// Copyright (c) 2021 Cesanta
// All rights reserved

#pragma once

#include <stddef.h>
#include <stdint.h>

// Low level (hardware) API
struct mip_if {
  void *userdata;
  void (*snd)(struct mip_if *, void *, size_t);  // Send frame
  void (*dbg)(const char *, ...);                // Debug print
  uint8_t mac[6];                                // MAC address
  uint32_t ip, mask, gw;                         // Leave zeros to use DCHP
  uint8_t *obuf;                                 // Output frame buffer
  size_t olen;                                   // Output frame buffer max size
};

void mip_rcv(struct mip_if *, const void *, size_t);  // Receive frame
void mip_poll(struct mip_if *, uint64_t ms);          // Call periodically
