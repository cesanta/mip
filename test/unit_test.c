// Copyright (c) 2022 Cesanta Software Limited
// All rights reserved

#include <assert.h>
#include "../mip.c"
#define BIT(n) (1U << (n))

static void ev_ip6(struct mip_ev *ev) {
  ((int *) ev->ifp->evdata)[0] |= BIT(ev->event);
}

static void test_ip6(void) {
  uint8_t pkt[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x98, 0x5a, 0xeb,
                   0xd9, 0xbf, 0x34, 0x86, 0xdd, 0x60, 0x08, 0x6e, 0xf9,
                   0x00, 0x08, 0x3a, 0xff, 0xfe, 0x80, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x18, 0x47, 0xc5, 0xc9, 0x5e, 0xc7,
                   0x3b, 0x8a, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                   0x85, 0x00, 0x04, 0xd5, 0x00, 0x00, 0x00, 0x00};
  int done = 0;
  struct mip_if mif = {
      .ev = ev_ip6, .evdata = &done, .mac = {1, 2, 3, 4, 5, 6}};
  mip_rx(&mif, pkt, sizeof(pkt));
  // printf("%s %d\n", __func__, done);
  assert(done == (BIT(MIP_IP) | BIT(MIP_ICMP)));
}

static void test_arp_cache(void) {
  struct mip_if mif = {.evdata = NULL};
  uint8_t mac1[] = {1, 2, 3, 4, 5, 6}, mac2[] = {11, 22, 33, 44, 55, 66};
  arp_cache_add(&mif, 1, mac1);
  assert(arp_cache_find(&mif, 1) != NULL);
  arp_cache_add(&mif, 2, mac2);
  assert(arp_cache_find(&mif, 1) != NULL);
  assert(arp_cache_find(&mif, 2) != NULL);
  arp_cache_add(&mif, 3, mac1);
  arp_cache_add(&mif, 4, mac1);
  arp_cache_add(&mif, 5, mac1);
  arp_cache_add(&mif, 6, mac1);
  assert(arp_cache_find(&mif, 1) == NULL);
  assert(arp_cache_find(&mif, 2) != NULL);
}

int main(void) {
  test_arp_cache();
  test_ip6();
  return 0;
}
