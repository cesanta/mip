// Copyright (c) 2022 Cesanta Software Limited
// All rights reserved
//
// This software is dual-licensed: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3 as
// published by the Free Software Foundation. For the terms of this
// license, see http://www.fsf.org/licensing/licenses/agpl-3.0.html
//
// You are free to use this software under the terms of the GNU General
// Public License, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// Alternatively, you can license this software under a commercial
// license, please contact us at https://cesanta.com/contact.html

#ifndef MIP_H
#define MIP_H

#include "mongoose.h"

#ifdef __cplusplus
extern "C" {
#endif

struct mip_driver {
  void *data;                                      // Driver-specific data
  void (*init)(void *data);                        // Initialise driver
  size_t (*tx)(const void *, size_t, void *data);  // Transmit frame
  void (*rx)(void *buf, size_t len, void *data);   // Receive frame (polling)
  bool (*status)(void *data);                      // Up/down status
  // Set receive callback for interrupt-driven drivers
  void (*rxcb)(void (*fn)(void *buf, size_t len, void *rxdata), void *rxdata);
};

struct mip_ipcfg {
  uint8_t mac[6];         // MAC address. Must not be 0
  uint32_t ip, mask, gw;  // IP, netmask, GW. If IP is 0, DHCP is used
};

void mip_init(struct mg_mgr *, struct mip_ipcfg *, struct mip_driver *);

#ifdef __cplusplus
}
#endif
#endif
