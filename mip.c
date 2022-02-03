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

#include "mip.h"
#include <stdio.h>
#include <string.h>

#ifdef MIP_ENABLE_DEBUG
#define DBG(x) printf("%s:%-4d %-10s ", __FILE__, __LINE__, __func__), printf x
#else
#define DBG(x)
#endif

struct lcp {
  uint8_t addr, ctrl, proto[2], code, id, len[2];
} __attribute__((packed));

struct eth {
  uint8_t dst[6];  // Destination MAC address
  uint8_t src[6];  // Source MAC address
  uint16_t type;   // Ethernet type
} __attribute__((packed));

struct ip {
  uint8_t ver;    // Version
  uint8_t tos;    // Unused
  uint16_t len;   // Length
  uint16_t id;    // Unused
  uint16_t frag;  // Fragmentation
  uint8_t ttl;    // Time to live
  uint8_t proto;  // Upper level protocol
  uint16_t csum;  // Checksum
  uint32_t src;   // Source IP
  uint32_t dst;   // Destination IP
} __attribute__((packed));

struct icmp {
  uint8_t type;
  uint8_t code;
  uint16_t csum;
} __attribute__((packed));

struct arp {
  uint16_t fmt;    // Format of hardware address
  uint16_t pro;    // Format of protocol address
  uint8_t hlen;    // Length of hardware address
  uint8_t plen;    // Length of protocol address
  uint16_t op;     // Operation
  uint8_t sha[6];  // Sender hardware address
  uint32_t spa;    // Sender protocol address
  uint8_t tha[6];  // Target hardware address
  uint32_t tpa;    // Target protocol address
} __attribute__((packed));

struct tcp {
  uint16_t sport;  // Source port
  uint16_t dport;  // Destination port
  uint32_t seq;    // Sequence number
  uint32_t ack;    // Acknowledgement number
  uint8_t off;     // Data offset
  uint8_t flags;   // TCP flags
  uint16_t win;    // Window
  uint16_t csum;   // Checksum
  uint16_t surp;   // Urgent pointer
} __attribute__((packed));
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)

struct udp {
  uint16_t sport;  // Source port
  uint16_t dport;  // Destination port
  uint16_t len;    // UDP length
  uint16_t csum;   // UDP checksum
} __attribute__((packed));

struct dhcp {
  uint8_t op, htype, hlen, hops;
  uint32_t xid;
  uint16_t secs, flags;
  uint32_t ciaddr, yiaddr, siaddr, giaddr;
  uint8_t hwaddr[208];
  uint32_t magic;
  uint8_t options[32];
} __attribute__((packed));

#define U16(ptr) ((((uint16_t) (ptr)[0]) << 8) | (ptr)[1])
#define NET16(x) __builtin_bswap16(x)
#define NET32(x) __builtin_bswap32(x)

static uint32_t csumup(uint32_t sum, const void *buf, size_t len) {
  const uint8_t *p = (const uint8_t *) buf;
  for (size_t i = 0; i < len; i++) sum += i & 1 ? p[i] : (p[i] << 8);
  return sum;
}

static uint16_t csumfin(uint32_t sum) {
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return NET16(~sum & 0xffff);
}

static uint16_t ipcsum(const void *buf, size_t len) {
  uint32_t sum = csumup(0, buf, len);
  return csumfin(sum);
}

// ARP cache is organised as a doubly linked list. A successful cache lookup
// moves an entry to the head of the list. New entries are added by replacing
// the last entry in the list with a new IP/MAC.
// ARP cache format: | prev | next | Entry0 | Entry1 | .... | EntryN |
// ARP entry format: | prev | next | IP (4bytes) | MAC (6bytes) |
// prev and next are 1-byte offsets in the cache, so cache size is max 256 bytes
// ARP entry size is 12 bytes
static void arp_cache_init(uint8_t *p, int n, int size) {
  for (int i = 0; i < n; i++) p[2 + i * size] = (uint8_t) (2 + (i - 1) * size);
  for (int i = 0; i < n; i++) p[3 + i * size] = (uint8_t) (2 + (i + 1) * size);
  p[0] = p[2] = (uint8_t) (2 + (n - 1) * size);
  p[1] = p[3 + (n - 1) * size] = 2;
}

static uint8_t *arp_cache_find(struct mip_if *ifp, uint32_t ip) {
  uint8_t *p = ifp->arp_cache;
  if (p[0] == 0 || p[1] == 0) arp_cache_init(p, MIP_ARP_ENTRIES, 12);
  for (uint8_t i = 0, j = p[1]; i < MIP_ARP_ENTRIES; i++, j = p[j + 1]) {
    if (memcmp(p + j + 2, &ip, sizeof(ip)) == 0) {
      p[1] = j, p[0] = p[j];  // Found entry! Point list head to us
      return p + j + 6;       // And return MAC address
    }
  }
  return NULL;
}

static void arp_cache_add(struct mip_if *ifp, uint32_t ip, uint8_t mac[6]) {
  uint8_t *p = ifp->arp_cache;
  if (arp_cache_find(ifp, ip) != NULL) return;  // Already exists, do nothing
  memcpy(p + p[0] + 2, &ip, sizeof(ip));  // Replace last entry: IP address
  memcpy(p + p[0] + 6, mac, 6);           // And MAC address
  p[1] = p[0], p[0] = p[p[1]];            // Point list head to us
  DBG(("ARP cache: added %#x\n", ip));
}

static struct ip *tx_ip(struct mip_if *ifp, uint8_t proto, uint32_t ip_src,
                        uint32_t ip_dst, size_t plen) {
  struct eth *eth = (struct eth *) ifp->frame;
  struct ip *ip = (struct ip *) (eth + 1);
  uint8_t *mac = arp_cache_find(ifp, ip_dst);
  if (mac) memcpy(eth->dst, mac, sizeof(eth->dst));
  if (!mac) memset(eth->dst, 255, sizeof(eth->dst));
  memcpy(eth->src, ifp->mac, sizeof(eth->src));
  eth->type = NET16(0x800);
  ip->ver = 0x45;
  ip->tos = 0x0;
  ip->len = NET16((uint16_t) (sizeof(*ip) + plen));
  ip->id = 0;
  ip->frag = 0;
  ip->ttl = 255;
  ip->proto = proto;
  ip->src = ip_src;
  ip->dst = ip_dst;
  ip->csum = 0;
  ip->csum = ipcsum(ip, sizeof(*ip));
  return ip;
}

static void tx_udp(struct mip_if *ifp, uint32_t ip_src, uint32_t ip_dst,
                   uint16_t sport, uint16_t dport, void *buf, size_t len) {
  struct ip *ip = tx_ip(ifp, 17, ip_src, ip_dst, len + sizeof(struct udp));
  struct udp *udp = (struct udp *) (ip + 1);
  udp->sport = NET16(sport);
  udp->dport = NET16(dport);
  udp->len = NET16((uint16_t) (sizeof(*udp) + len));
  udp->csum = 0;
  uint32_t cs = csumup(0, udp, sizeof(*udp));
  cs = csumup(cs, buf, len);
  cs = csumup(cs, &ip->src, sizeof(ip->src));
  cs = csumup(cs, &ip->dst, sizeof(ip->dst));
  cs += ip->proto + sizeof(*udp) + len;
  udp->csum = csumfin(cs);
  memmove(udp + 1, buf, len);
  ifp->frame_len = sizeof(struct eth) + sizeof(*ip) + sizeof(*udp) + len;
  // DBG(("UDP LEN %d %d\n", (int) len, (int) ifp->frame_len));
  ifp->tx(ifp);
}

static void tx_dhcp(struct mip_if *ifp, uint32_t src, uint32_t dst,
                    uint8_t *opts, size_t optslen) {
  struct dhcp *dhcp = (struct dhcp *) (ifp->frame + sizeof(struct eth) +
                                       sizeof(struct ip) + sizeof(struct udp));
  memset(dhcp, 0, sizeof(*dhcp));
  dhcp->op = 1;
  dhcp->htype = 1;
  dhcp->hlen = 6;
  dhcp->magic = NET32(0x63825363);
  dhcp->ciaddr = src;
  memcpy(dhcp->hwaddr, ifp->mac, sizeof(ifp->mac));
  memcpy(&dhcp->xid, ifp->mac + 2, sizeof(dhcp->xid));
  memcpy(dhcp->options, opts, optslen);
  tx_udp(ifp, src, dst, 68, 67, dhcp, sizeof(*dhcp));
}

static void tx_dhcp_request(struct mip_if *ifp, uint32_t src, uint32_t dst) {
  uint8_t opts[] = {
      53, 1, 3,                 // Type: DHCP request
      55, 2, 1,   3,            // GW and mask
      12, 3, 'm', 'i', 'p',     // Host name: "mip"
      54, 4, 0,   0,   0,   0,  // DHCP server ID
      50, 4, 0,   0,   0,   0,  // Requested IP
      255                       // End of options
  };
  memcpy(opts + 14, &dst, sizeof(dst));
  memcpy(opts + 20, &src, sizeof(src));
  tx_dhcp(ifp, 0, 0xffffffff, opts, sizeof(opts));
}

static void tx_dhcp_discover(struct mip_if *ifp) {
  uint8_t opts[] = {
      53, 1, 1,     // Type: DHCP discover
      55, 3, 1, 3,  // Parameters: ip, mask
      255           // End of options
  };
  tx_dhcp(ifp, 0, 0xffffffff, opts, sizeof(opts));
}

static void rx_arp(struct mip_if *ifp, struct eth *eth, struct arp *arp) {
  // DBG(("ARP op %d %#x %#x\n", NET16(arp->op), arp->spa, arp->tpa));
  if (arp->op == NET16(1) && arp->tpa == ifp->ip) {
    // ARP request. Edit packet in-place. Make a response, then send
    memcpy(eth->dst, eth->src, sizeof(eth->dst));
    memcpy(eth->src, ifp->mac, sizeof(eth->src));
    arp->op = NET16(2);
    memcpy(arp->tha, arp->sha, sizeof(arp->tha));
    memcpy(arp->sha, ifp->mac, sizeof(arp->sha));
    arp->tpa = arp->spa;
    arp->spa = ifp->ip;
    DBG(("ARP response: we're %#x\n", ifp->ip));
    ifp->frame_len = sizeof(*eth) + sizeof(*arp);
    ifp->tx(ifp);
  } else if (arp->op == NET16(2)) {
    if (memcmp(arp->tha, ifp->mac, sizeof(arp->tha)) != 0) return;
    arp_cache_add(ifp, arp->tpa, arp->tha);
  }
}

static void rx_icmp(struct mip_if *ifp, struct eth *eth, struct ip *ip,
                    struct icmp *icmp, size_t len) {
  DBG(("ICMP %d\n", (int) len));
  if (icmp->type == 8 && ip->dst == ifp->ip) {
    memcpy(eth->dst, eth->src, sizeof(eth->dst));
    memcpy(eth->src, ifp->mac, sizeof(eth->src));
    ip->dst = ip->src;
    ip->src = ifp->ip;
    ip->csum = 0;  // Important - clear csum before recomputing
    ip->csum = ipcsum(ip, sizeof(*ip));
    icmp->type = 0;
    icmp->csum = 0;  // Important - clear csum before recomputing
    icmp->csum = ipcsum(icmp, sizeof(*icmp) + len);
    ifp->frame_len = sizeof(*eth) + sizeof(*ip) + sizeof(*icmp) + len;
    DBG(("ICMP response %d\n", (int) ifp->frame_len));
    ifp->tx(ifp);
  }
}

static void rx_dhcp(struct mip_if *ifp, struct dhcp *dhcp, size_t len) {
  uint32_t ip = 0, gw = 0, mask = 0;
  uint8_t *p = dhcp->options, *end = ((uint8_t *) dhcp) + len;
  if (len < sizeof(*dhcp)) return;
  while (p < end && p[0] != 255) {
    if (p[0] == 1 && p[1] == sizeof(ifp->mask)) {
      memcpy(&mask, p + 2, sizeof(mask));
      // DBG(("MASK %x\n", mask));
    } else if (p[0] == 3 && p[1] == sizeof(ifp->gw)) {
      memcpy(&gw, p + 2, sizeof(gw));
      ip = dhcp->yiaddr;
      // DBG(("IP %x GW %x\n", ip, gw));
    }
    p += p[1] + 2;
  }
  if (ip && mask && gw && ifp->ip == 0) {
    DBG(("DHCP request ip %#x mask %#x gw %#x\n", ip, mask, gw));
    arp_cache_add(ifp, dhcp->siaddr, ((struct eth *) ifp->frame)->src);
    ifp->ip = ip, ifp->gw = gw, ifp->mask = mask;
    tx_dhcp_request(ifp, ip, dhcp->siaddr);
  }
}

static void rx_ip(struct mip_if *ifp, struct eth *eth, struct ip *ip,
                  size_t len) {
  // DBG(("IP %d\n", (int) len));
  if (ip->proto == 1) {
    struct icmp *icmp = (struct icmp *) (ip + 1);
    if (len < sizeof(*icmp)) return;
    rx_icmp(ifp, eth, ip, icmp, len - sizeof(*icmp));
  } else if (ip->proto == 17) {
    struct udp *udp = (struct udp *) (ip + 1);
    if (len < sizeof(*udp)) return;
    if (udp->dport == NET16(68))
      rx_dhcp(ifp, (struct dhcp *) (udp + 1), len - sizeof(*udp));
  }
}

void mip_rx(struct mip_if *ifp) {
  // DBG(("gt frame %u bytes\n", len));
  size_t len = ifp->frame_len;
  struct eth *eth = (struct eth *) ifp->frame;
  if (len < sizeof(*eth)) return;  // Truncated packet - runt?
  if (eth->type == NET16(0x806)) {
    struct arp *arp = (struct arp *) (eth + 1);
    if (sizeof(*eth) + sizeof(*arp) > len) return;  // Truncated
    rx_arp(ifp, eth, arp);
  } else if (eth->type == NET16(0x800)) {
    struct ip *ip = (struct ip *) (eth + 1);
    if (len < sizeof(*eth) + sizeof(*ip)) return;  // Truncated packed
    if (ip->ver != 0x45) return;                   // Not IP
    rx_ip(ifp, eth, ip, len - sizeof(*eth) - sizeof(*ip));
  }
}

void mip_poll(struct mip_if *ifp, uint64_t uptime_ms) {
  // DBG(("poll: %p %lld\n", ifp, uptime_ms));
  if (ifp->ip == 0 && uptime_ms > ifp->timer) {
    tx_dhcp_discover(ifp);
    ifp->timer = uptime_ms + 3000;
  }
}
