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

static void dump(const char *label, const uint8_t *buf, size_t len) {
  char *s = mg_hexdump(buf, len);
  printf("%s [%d bytes]\n%s\n", label, (int) len, s);
  free(s);
}

static void dbg(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
}

static void snd(struct mip_if *ifp, void *buf, size_t len) {
  LOG(LL_INFO, ("%p %p %d", ifp, buf, (int) len));
}

int main(int argc, char **argv) {
  const char *iface = NULL;  // Network iface
  const char *bpf = NULL;    // "host x.x.x.x or ether host ff:ff:ff:ff:ff:ff";
  bool verbose = false;

  // Parse options
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
      iface = argv[++i];
    } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
      bpf = argv[++i];
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

  uint8_t obuf[2048];
  struct mip_if mif = {.dbg = dbg,
                       .snd = snd,
                       .userdata = ph,
                       .obuf = obuf,
                       .olen = sizeof(obuf)};

  // Main loop. Listen for input from UART, PCAP, and STDIN.
  while (s_signo == 0) {
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(pcap_fd, &rset);

    // See if there is something for us..
    struct timeval tv = {.tv_sec = 0, .tv_usec = 50000};
    if (select(pcap_fd + 1, &rset, 0, 0, &tv) <= 0) continue;

    // Maybe there is something on the network?
    if (pcap_fd >= 0 && FD_ISSET(pcap_fd, &rset)) {
      struct pcap_pkthdr *hdr = NULL;
      const unsigned char *pkt = NULL;
      if (pcap_next_ex(ph, &hdr, &pkt) != 1) continue;  // Yea, fetch packet
      if (verbose) dump("NET > DEV", pkt, hdr->len);
      mip_rcv(&mif, pkt, hdr->len);
    }

    mip_poll(&mif, mg_millis());
  }
  pcap_close(ph);
  printf("Exiting on signal %d\n", s_signo);
  return 0;
}
