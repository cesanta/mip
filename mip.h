// Copyright (c) 2022 Cesanta
// All rights reserved

#ifndef MIP_H
#define MIP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#ifndef MIP_ARP_ENTRIES
#define MIP_ARP_ENTRIES 5  // Number of ARP cache entries. Maximum 21
#endif

// Network interface descriptor
struct mip_if {
  // These settings must be initialised by the user
  void *userdata;               // Custom data for this iface
  void (*tx)(struct mip_if *);  // Transmit frame (set frame_len!)
  uint8_t mac[6];               // MAC address
  uint32_t ip, mask, gw;        // Leave zeros to use DCHP
  uint8_t *frame;               // Frame (input and output)
  size_t frame_max_size;        // Frame max size

  // These settings are used internally
  size_t frame_len;                             // Frame length
  uint64_t timer;                               // Timer
  uint8_t arp_cache[2 + 12 * MIP_ARP_ENTRIES];  // Each entry is 12 bytes
};

void mip_rx(struct mip_if *);                 // Receive frame (set frame_len!)
void mip_poll(struct mip_if *, uint64_t ms);  // Call periodically

#ifdef __cplusplus
}
#endif
#endif
