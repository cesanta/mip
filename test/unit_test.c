// Copyright (c) 2022 Cesanta Software Limited
// All rights reserved

#include <assert.h>
#include <pthread.h>
#include "../mip.c"
#define BIT(n) (1U << (n))

static void test_queue(void) {
  uint8_t buf[11 + 2 * sizeof(size_t) + 1], tmp[100];
  struct queue q = {.buf = buf, .len = sizeof(buf)};
  assert(q_write(&q, "hi", 2) == true);
  assert(q_write(&q, "there:,-+", 9) == true);
  assert(q_write(&q, "hi", 2) == false);
  assert(q_read(&q, tmp) == 2);
  assert(memcmp(tmp, "hi", 2) == 0);
  assert(q_write(&q, "hi", 2) == true);
  assert(q_read(&q, tmp) == 9);
  assert(memcmp(tmp, "there:,-+", 9) == 0);
  assert(q_read(&q, tmp) == 2);
  assert(memcmp(tmp, "hi", 2) == 0);
  assert(q_read(&q, tmp) == 0);
}

static void test_arp_cache(void) {
  struct mip_if mif = {.ip = 0};
  uint8_t mac1[] = {1, 2, 3, 4, 5, 6}, mac2[] = {11, 22, 33, 44, 55, 66};
  assert(arp_cache_find(&mif, 1) == NULL);
  arp_cache_add(&mif, 1, mac1);
  assert(arp_cache_find(&mif, 1) != NULL);
  assert(arp_cache_find(&mif, 2) == NULL);
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
  test_queue();
  return 0;
}
