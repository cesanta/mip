// Copyright (c) 2021 Cesanta
// All rights reserved

#pragma once

#include <stddef.h>
#include <stdint.h>

// Network interface descriptor
struct mip_if {
  void *userdata;                  // Custom data for this iface
  void (*snd)(struct mip_if *);    // Send frame, flen
  void (*dbg)(const char *, ...);  // Debug print
  uint8_t mac[6];                  // MAC address
  uint32_t ip, mask, gw;           // Leave zeros to use DCHP
  uint8_t *frame;                  // Frame (input and output)
  size_t frame_max_size;           // Frame max size
  size_t frame_len;                // Frame length
  uint64_t timer;
};

void mip_rcv(struct mip_if *);                // Receive into frame, flen
void mip_poll(struct mip_if *, uint64_t ms);  // Call periodically
