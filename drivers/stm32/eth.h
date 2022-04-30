// Copyright (c) 2022 Cesanta Software Limited
// All rights reserved

// This is an Ethernet driver for the STM32 MAC. Usage:
//    1. Initialise Ethernet clocks and GPIO pins
//    2. Call eth_driver_init()

#pragma once

#include <stdbool.h>
#include <stddef.h>

void eth_driver_init(void *userdata,
                     void (*receive_frame)(void *userdata, void *, size_t));
bool eth_driver_has_carrier(void);
size_t eth_driver_transmit_frame(const void *buf, size_t len);
