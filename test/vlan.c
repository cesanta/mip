// Copyright (c) 2022 Cesanta Software Limited
// All rights reserved

#include <pcap.h>

#include "mip.h"
#include "mongoose.h"

static int s_signo;

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
  // dump("DEV > NET", ifp->frame, ifp->frame_len);
  pcap_inject(ifp->userdata, ifp->frame, ifp->frame_len);
  // printf("-> %lu\n", ifp->frame_len);
}

int main(int argc, char **argv) {
  const char *iface = NULL;  // Network iface
  const char *bpf = NULL;    // "host x.x.x.x or ether host ff:ff:ff:ff:ff:ff";
  const char *mac = "aa:bb:cc:dd:ee:ff";
  bool verbose = false;

  // Parse options
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
      iface = argv[++i];
    } else if (strcmp(argv[i], "-bpf") == 0 && i + 1 < argc) {
      bpf = argv[++i];
    } else if (strcmp(argv[i], "-mac") == 0 && i + 1 < argc) {
      mac = argv[++i];
    } else if (strcmp(argv[i], "-v") == 0) {
      verbose = true;
    } else {
      return fail("unknown option %s", argv[i]);
    }
  }

  if (iface == NULL) fail("No iface set");

  // Open network interface
  pcap_t *ph = NULL;
  if (iface != NULL) {
    char errbuf[PCAP_ERRBUF_SIZE] = "";
    ph = pcap_open_live(iface, 0xffff, 1, 1, errbuf);
    if (ph == NULL) fail("pcap_open_live: %s\n", errbuf);
    // pcap_setnonblock(ph, 1, errbuf);

    // Apply BPF to reduce noise. Let in only broadcasts and our own traffic
    if (bpf != NULL) {
      struct bpf_program bpfp;
      if (pcap_compile(ph, &bpfp, bpf, 1, 0)) fail("compile \n");
      pcap_setfilter(ph, &bpfp);
      pcap_freecode(&bpfp);
    }

    printf("Opened %s in live mode fd=%d\n", iface, pcap_get_selectable_fd(ph));
  }
  int pcap_fd = pcap_get_selectable_fd(ph);

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  uint8_t frame[2048];
  struct mip_if mif = {.tx = tx,
                       .userdata = ph,
                       .frame = frame,
                       .frame_max_size = sizeof(frame)};
  sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mif.mac[0], &mif.mac[1],
         &mif.mac[2], &mif.mac[3], &mif.mac[4], &mif.mac[5]);

  // Main loop. Listen for input from UART, PCAP, and STDIN.
  while (s_signo == 0) {
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(pcap_fd, &rset);

    // See if there is something for us..
    struct timeval tv = {.tv_sec = 0, .tv_usec = 10000};
    if (select(pcap_fd + 1, &rset, 0, 0, &tv) < 0) continue;

    // Maybe there is something on the network?
    if (pcap_fd >= 0 && FD_ISSET(pcap_fd, &rset)) {
      struct pcap_pkthdr *hdr = NULL;
      const unsigned char *pkt = NULL;
      if (pcap_next_ex(ph, &hdr, &pkt) != 1) continue;  // Yea, fetch packet
      if (hdr->len > mif.frame_max_size) hdr->len = mif.frame_max_size;
      mif.frame_len = hdr->len;
      memcpy(mif.frame, pkt, mif.frame_len);
      if (verbose) dump("NET > DEV", mif.frame, mif.frame_len);
      mip_rx(&mif);
    }

    mip_poll(&mif, mg_millis());
  }
  pcap_close(ph);
  printf("Exiting on signal %d\n", s_signo);
  return 0;
}
