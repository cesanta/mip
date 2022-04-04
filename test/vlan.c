// Copyright (c) 2022 Cesanta Software Limited
// All rights reserved

#include "mip.h"
#include "mongoose.h"

#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int s_signo;
union {
  struct sockaddr sa;
  struct sockaddr_ll ll;
} s_usa = {.ll = {.sll_family = PF_PACKET, .sll_pkttype = PACKET_HOST}};

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

static int faile(const char *name) {
  return fail("%s(): %d (%s)\n", name, errno, strerror(errno));
}

static void tx(struct mip_if *ifp) {
  int sock = *(int *) ifp->txdata;
  int n =
      sendto(sock, ifp->frame, ifp->frame_len, 0, &s_usa.sa, sizeof(s_usa.ll));
  printf("-> %d/%lu\n", n, ifp->frame_len);
}

static void fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
  if (ev == MG_EV_POLL) return;
  MG_INFO(("%lu %d %p %p", c->id, ev, ev_data, fn_data));
  if (ev == MG_EV_OPEN) {
    c->is_hexdumping = 1;
  }
}

static void timer_fn(void *arg) {
  struct mg_mgr *mgr = (struct mg_mgr *) arg;
  mg_http_connect(mgr, "http://cesanta.com", fn, NULL);
}

int main(void) {
  int sock = socket(PF_PACKET, SOCK_RAW, 768);
  if (sock < 0) faile("socket");

  struct ifreq ifr = {.ifr_name = "vlan1"};
  ioctl(sock, SIOCGIFINDEX, &ifr);
  s_usa.ll.sll_ifindex = ifr.ifr_ifindex;

  if (bind(sock, &s_usa.sa, sizeof(s_usa.ll)) != 0) faile("bind");
  printf("Opened raw socket %d\n", sock);

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  uint8_t frame[2048];
  struct mip_if mif = {.tx = tx,
                       .txdata = &sock,
                       .frame = frame,
                       .mac = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
                       .frame_max_size = sizeof(frame)};

  struct mg_mgr mgr;
  struct mg_timer t;
  mg_mgr_init(&mgr);
  mg_log_set("3");
  mg_attach_mip(&mgr, &mif);
  mg_timer_init(&t, 300, MG_TIMER_REPEAT, timer_fn, &mgr);
  mg_listen(&mgr, "udp://0.0.0.0:1234", fn, NULL);

  // Main loop. Listen for input from UART, PCAP, and STDIN.
  while (s_signo == 0) {
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(sock, &rset);

    // See if there is something for us..
    struct timeval tv = {.tv_sec = 0, .tv_usec = 10000};
    if (select(sock + 1, &rset, 0, 0, &tv) < 0) continue;
    if (FD_ISSET(sock, &rset)) {
      uint8_t buf[BUFSIZ];
      unsigned sl = sizeof(s_usa.ll);
      int len = recvfrom(sock, buf, sizeof(buf), 0, &s_usa.sa, &sl);
      MG_INFO(("Got %d", len));
      if (len <= 0) fail("Socket closed\n");
      if (len > (int) mif.frame_max_size) continue;
      mif.frame_len = len;
      memcpy(mif.frame, buf, len);  // Feed MIP
      mip_rx(&mif);
    }
    mip_poll(&mif, mg_millis());
  }

  close(sock);
  printf("Exiting on signal %d\n", s_signo);
  return 0;
}
