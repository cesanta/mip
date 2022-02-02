// Copyright (c) 2022 Cesanta Software Limited
// All rights reserved

#include "../mip.c"

#include <assert.h>

static void test_arp_cache(void) {
  struct mip_if mif = {.userdata = NULL};
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
  return 0;
}
