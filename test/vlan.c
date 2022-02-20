// Copyright (c) 2022 Cesanta Software Limited
// All rights reserved

#include <pcap.h>
#include <termios.h>

#include "mip.h"
#include "mongoose.h"

struct ctx {
  int sock;                // UDP socket
  struct sockaddr_in sin;  // Peer socket address
};

static int s_signo;
static pcap_t *s_ph = NULL;

void signal_handler(int signo) {
  s_signo = signo;
}

static int fail(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  exit(EXIT_FAILURE);
}

static inline void dump(const char *label, const uint8_t *buf, size_t len) {
  char *s = mg_hexdump(buf, len);
  printf("%s [%d bytes]\n%s\n", label, (int) len, s);
  free(s);
}

static void tx(struct mip_if *ifp) {
  struct ctx *ctx = ifp->userdata;
  // dump("DEV > NET", ifp->frame, ifp->frame_len);
  int n = sendto(ctx->sock, ifp->frame, ifp->frame_len, 0,
                 (struct sockaddr *) &ctx->sin, sizeof(ctx->sin));
  printf("-> %d/%lu\n", n, ifp->frame_len);
  pcap_inject(s_ph, ifp->frame, ifp->frame_len);
}

int main(int argc, char **argv) {
  const char *udp = "127.0.0.1:1999";  // UDP destination for frames
  const char *iface = NULL;            // Network iface
  const char *bpf = NULL;  // "host x.x.x.x or ether host ff:ff:ff:ff:ff:ff";
  const char *mac = "aa:bb:cc:dd:ee:ff";

  // Parse options
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
      iface = argv[++i];
    } else if (strcmp(argv[i], "-bpf") == 0 && i + 1 < argc) {
      bpf = argv[++i];
    } else if (strcmp(argv[i], "-mac") == 0 && i + 1 < argc) {
      mac = argv[++i];
    } else if (strcmp(argv[i], "-udp") == 0 && i + 1 < argc) {
      udp = argv[++i];
    } else {
      return fail("unknown option %s", argv[i]);
    }
  }

  // Open network interface
  if (iface == NULL) fail("No iface set");
  char errbuf[PCAP_ERRBUF_SIZE] = "";
  s_ph = pcap_open_live(iface, 0xffff, 1, 1, errbuf);
  if (s_ph == NULL) fail("pcap_open_live: %s\n", errbuf);
  // pcap_setnonblock(s_ph, 1, errbuf);
  // Apply BPF to reduce noise. Let in only broadcasts and our own traffic
  if (bpf != NULL) {
    struct bpf_program bpfp;
    if (pcap_compile(s_ph, &bpfp, bpf, 1, 0)) fail("compile \n");
    pcap_setfilter(s_ph, &bpfp);
    pcap_freecode(&bpfp);
  }
  printf("Opened %s in live mode fd=%d\n", iface, pcap_get_selectable_fd(s_ph));

  struct ctx ctx = {};
  struct mg_addr a;
  if (!mg_aton(mg_url_host(udp), &a)) fail("Invalid udp spec: [%s]\n", udp);
  ctx.sin.sin_port = mg_htons(mg_url_port(udp));
  ctx.sin.sin_addr.s_addr = a.ip;
  ctx.sock = socket(AF_INET, SOCK_DGRAM, 17);
  printf("Opened %s sock=%d\n", udp, ctx.sock);

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  uint8_t frame[2048];
  struct mip_if mif = {.tx = tx,
                       .userdata = &ctx,
                       .frame = frame,
                       .frame_max_size = sizeof(frame)};
  sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mif.mac[0], &mif.mac[1],
         &mif.mac[2], &mif.mac[3], &mif.mac[4], &mif.mac[5]);

  // Main loop. Listen for input from UART, PCAP, and STDIN.
  while (s_signo == 0) {
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(ctx.sock, &rset);

    // See if there is something for us..
    struct timeval tv = {.tv_sec = 0, .tv_usec = 10000};
    if (select(ctx.sock + 1, &rset, 0, 0, &tv) >= 0 &&
        FD_ISSET(ctx.sock, &rset)) {
      struct sockaddr_in sa;
      uint8_t buf[BUFSIZ];
      unsigned sl = sizeof(sa);
      int len =
          recvfrom(ctx.sock, buf, sizeof(buf), 0, (struct sockaddr *) &sa, &sl);
      MG_INFO(("Got %d", len));
      if (len <= 0) fail("Socket closed\n");
      if (len > (int) mif.frame_max_size) continue;
      mif.frame_len = len;
      pcap_inject(s_ph, buf, len);  // Forward to iface for wireshark
      memcpy(mif.frame, buf, len);  // Feed MIP
      mip_rx(&mif);
    }
    mip_poll(&mif, mg_millis());
  }
  pcap_close(s_ph);
  close(ctx.sock);
  printf("Exiting on signal %d\n", s_signo);
  return 0;
}
