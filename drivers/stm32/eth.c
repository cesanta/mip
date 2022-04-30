// Copyright (c) 2022 Cesanta Software Limited
// All rights reserved

#include "eth.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct eth {
  uint32_t MACCR, MACFFR, MACHTHR, MACHTLR, MACMIIAR, MACMIIDR, MACFCR,
      MACVLANTR, RESERVED0[2], MACRWUFFR, MACPMTCSR, RESERVED1, MACDBGR, MACSR,
      MACIMR, MACA0HR, MACA0LR, MACA1HR, MACA1LR, MACA2HR, MACA2LR, MACA3HR,
      MACA3LR, RESERVED2[40], MMCCR, MMCRIR, MMCTIR, MMCRIMR, MMCTIMR,
      RESERVED3[14], MMCTGFSCCR, MMCTGFMSCCR, RESERVED4[5], MMCTGFCR,
      RESERVED5[10], MMCRFCECR, MMCRFAECR, RESERVED6[10], MMCRGUFCR,
      RESERVED7[334], PTPTSCR, PTPSSIR, PTPTSHR, PTPTSLR, PTPTSHUR, PTPTSLUR,
      PTPTSAR, PTPTTHR, PTPTTLR, RESERVED8, PTPTSSR, PTPPPSCR, RESERVED9[564],
      DMABMR, DMATPDR, DMARPDR, DMARDLAR, DMATDLAR, DMASR, DMAOMR, DMAIER,
      DMAMFBOCR, DMARSWTR, RESERVED10[8], DMACHTDR, DMACHRDR, DMACHTBAR,
      DMACHRBAR;
};
#define ETH ((struct eth *) 0x40028000)

#define BIT(x) (1UL << (x))
#define ETH_PKT_SIZE 1540  // Max frame size
#define ETH_DESC_CNT 2     // Descriptors count
#define ETH_DS 4           // Descriptor size (words)

static uint32_t s_rxdesc[ETH_DESC_CNT][ETH_DS];      // RX descriptors
static uint32_t s_txdesc[ETH_DESC_CNT][ETH_DS];      // TX descriptors
static uint8_t s_rxbuf[ETH_DESC_CNT][ETH_PKT_SIZE];  // RX ethernet buffers
static uint8_t s_txbuf[ETH_DESC_CNT][ETH_PKT_SIZE];  // TX ethernet buffers
static void (*s_rx)(void *, void *, size_t);         // Recv callback
static void *s_rxdata;                               // Recv callback data
static volatile uint32_t s_nirq, s_nrcv, s_nsnt;     // Counters
enum { PHY_ADDR = 0, PHY_BCR = 0, PHY_BSR = 1 };     // PHY constants

static inline void spin(volatile uint32_t count) {
  while (count--) asm("nop");
}

uint32_t eth_read_phy(uint8_t addr, uint8_t reg) {
  ETH->MACMIIAR &= (7 << 2);
  ETH->MACMIIAR |= ((uint32_t) addr << 11) | ((uint32_t) reg << 6);
  ETH->MACMIIAR |= BIT(0);
  while (ETH->MACMIIAR & BIT(0)) spin(1);
  return ETH->MACMIIDR;
}

void eth_write_phy(uint8_t addr, uint8_t reg, uint32_t val) {
  ETH->MACMIIDR = val;
  ETH->MACMIIAR &= (7 << 2);
  ETH->MACMIIAR |= ((uint32_t) addr << 11) | ((uint32_t) reg << 6) | BIT(1);
  ETH->MACMIIAR |= BIT(0);
  while (ETH->MACMIIAR & BIT(0)) spin(1);
}

void eth_driver_init(void *rxdata, void (*rx)(void *, void *, size_t)) {
  s_rx = rx;
  s_rxdata = rxdata;

  // Init RX descriptors
  for (int i = 0; i < ETH_DESC_CNT; i++) {
    s_rxdesc[i][0] = BIT(31);                       // Own
    s_rxdesc[i][1] = sizeof(s_rxbuf[i]) | BIT(14);  // 2nd address chained
    s_rxdesc[i][2] = (uint32_t) s_rxbuf[i];         // Point to data buffer
    s_rxdesc[i][3] = (uint32_t) s_rxdesc[(i + 1) % ETH_DESC_CNT];  // Next desc
  }

  // Init TX descriptors
  for (int i = 0; i < ETH_DESC_CNT; i++) {
    s_txdesc[i][0] = BIT(20) | BIT(28) | BIT(29) | BIT(30);  // Chain, FS, LS
    s_txdesc[i][2] = (uint32_t) s_txbuf[i];                  // Buf pointer
    s_txdesc[i][3] = (uint32_t) s_txdesc[(i + 1) % ETH_DESC_CNT];  // Next desc
  }

  ETH->DMABMR |= BIT(0);                        // Software reset
  while ((ETH->DMABMR & BIT(0)) != 0) spin(1);  // Wait until done
  // NOTE(cpq): we do not use extended descriptor bit 7, and do not use
  // hardware checksum. Therefore, descriptor size is 4, not 8
  // ETH->DMABMR = BIT(13) | BIT(16) | BIT(22) | BIT(23) | BIT(25);
  ETH->MACIMR = BIT(3) | BIT(9);              // Mask timestamp & PMT IT
  ETH->MACMIIAR = 4 << 2;                     // MDC clock 150-216 MHz, 38.8.1
  ETH->MACFCR = BIT(7);                       // Disable zero quarta pause
  ETH->MACFFR = BIT(31);                      // Receive all
  eth_write_phy(PHY_ADDR, PHY_BCR, BIT(15));  // Reset PHY
  eth_write_phy(PHY_ADDR, PHY_BCR, BIT(12));  // Set autonegotiation
  ETH->DMARDLAR = (uint32_t) s_rxdesc;        // RX descriptors
  ETH->DMATDLAR = (uint32_t) s_txdesc;        // RX descriptors
  ETH->DMAIER = BIT(6) | BIT(16);             // RIE, NISE
  ETH->MACCR = BIT(2) | BIT(3) | BIT(11) | BIT(14);    // RE, TE, Duplex, Fast
  ETH->DMAOMR = BIT(1) | BIT(13) | BIT(21) | BIT(25);  // SR, ST, TSF, RSF
}

size_t eth_driver_transmit_frame(const void *buf, size_t len) {
  uint32_t no = s_nsnt % ETH_DESC_CNT;  // Descriptor number
  if (len > sizeof(s_txbuf[0])) {
    len = 0;  // Frame is too big
  } else if (s_txdesc[no][0] & BIT(31)) {
    len = 0;  // Busy, fail
  } else {
    memcpy(s_txbuf[no], buf, len);                            // Copy data
    s_txdesc[no][1] = (uint32_t) len;                         // Set data len
    s_txdesc[no][0] = BIT(20) | BIT(28) | BIT(29) | BIT(30);  // Chain, FS, LS
    s_txdesc[no][0] |= BIT(31);  // Set OWN bit - let DMA take over
    s_nsnt++;
  }
  if (ETH->DMASR & BIT(2)) ETH->DMASR = BIT(2), ETH->DMATPDR = 0;  // Un-busy
  if (ETH->DMASR & BIT(5)) ETH->DMASR = BIT(5), ETH->DMATPDR = 0;  // Un-busy
  return len;
}

bool eth_driver_has_carrier(void) {
  return eth_read_phy(PHY_ADDR, PHY_BSR) & BIT(2) ? 1 : 0;
}

void irq_eth(void) {  // Ethernet IRQ handler
  volatile uint32_t sr = ETH->DMASR;
  s_nirq++;
  while (sr & BIT(6)) {                   // Frame received, loop
    uint32_t no = s_nrcv % ETH_DESC_CNT;  // Descriptor number
    uint32_t len = ((s_rxdesc[no][0] >> 16) & (BIT(14) - 1));
    if (s_rxdesc[no][0] & BIT(31)) break;
    if (s_rx != NULL) s_rx(s_rxdata, s_rxbuf[no], len > 4 ? len - 4 : len);
    s_rxdesc[no][0] = BIT(31);
    s_nrcv++;
  }
  // printf("  %lx %lx %lx %lx %lx\n", s_nirq, s_nrcv, s_nsnt, sr,
  //       s_txdesc[s_nsnt % ETH_DESC_CNT][0]);
  ETH->DMASR = ~0UL;                                     // Clear status
  if ((sr & BIT(2)) || (sr & BIT(5))) ETH->DMATPDR = 0;  // Resume TX
  if (sr & BIT(7)) ETH->DMARPDR = 0;                     // Resume RX
}
