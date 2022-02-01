// Copyright (c) 2021 Cesanta
// All rights reserved

#include "mip.h"
#include <string.h>

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

struct arp_entry {
  uint8_t mac[6];
  uint32_t ip;
} __attribute__((packed));

#define U16(ptr) ((((uint16_t) (ptr)[0]) << 8) | (ptr)[1])
#define NET16(x) __builtin_bswap16(x)
#define NET32(x) __builtin_bswap32(x)

#define CNIP_ARP_CACHE_SIZE 10
static struct arp_entry s_arp_cache[CNIP_ARP_CACHE_SIZE];  // ARP cache
static size_t s_arp_idx;                                   // Current ARP index

static void mip_arp(struct mip_if *ifp, struct eth *eth, struct arp *arp) {
  if (arp->op == NET16(1) && arp->tpa == ifp->ip) {
    // ARP request. Edit packet in-place. Make a response, then send
    memcpy(eth->dst, eth->src, sizeof(eth->dst));
    memcpy(eth->src, ifp->mac, sizeof(eth->src));
    arp->op = NET16(2);
    memcpy(arp->tha, arp->sha, sizeof(arp->tha));
    memcpy(arp->sha, ifp->mac, sizeof(arp->sha));
    arp->tpa = arp->spa;
    arp->spa = ifp->ip;
    ifp->dbg("%s", "ARP response\n");
    ifp->frame_len = sizeof(*eth) + sizeof(*arp);
    ifp->snd(ifp);
  } else if (arp->op == NET16(2)) {
    // ARP response
    if (memcmp(arp->tha, ifp->mac, sizeof(arp->tha)) != 0) return;
    // s_arp_cache[s_arp_idx++] = *(struct arp_entry *) (void *) &arp->sha;
    (void) s_arp_cache;
    if (s_arp_idx >= CNIP_ARP_CACHE_SIZE) s_arp_idx = 0;
  }
}

static uint32_t csumup(uint32_t sum, const void *buf, size_t len) {
  const uint8_t *p = buf;
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

static void mip_icmp(struct mip_if *ifp, struct eth *eth, struct ip *ip,
                     struct icmp *icmp, size_t len) {
  if (icmp->type == 8) {
    memcpy(eth->dst, eth->src, sizeof(eth->dst));
    memcpy(eth->src, ifp->mac, sizeof(eth->src));
    ip->dst = ip->src;
    ip->src = ifp->ip;
    ip->csum = 0;  // Important - clear csum before recomputing
    ip->csum = ipcsum(ip, sizeof(*ip));
    icmp->type = 0;
    icmp->csum = 0;  // Important - clear csum before recomputing
    icmp->csum = ipcsum(icmp, sizeof(*icmp) + len);
    ifp->frame_len = (size_t) ((char *) (icmp + 1) - (char *) eth) + len;
    // ifp->dbg("ICMP response %d\n", ifp->frame_len);
    ifp->snd(ifp);
  }
}

static void mip_dhcp(struct mip_if *ifp, struct dhcp *dhcp, size_t len) {
  uint32_t ip = ifp->ip;
  uint8_t *p = dhcp->options, *end = ((uint8_t *) dhcp) + len;
  if (len < sizeof(*dhcp)) return;
  while (p < end && p[0] != 255) {
    if (p[0] == 1 && p[1] == sizeof(ifp->mask)) {
      memcpy(&ifp->mask, p + 2, sizeof(ifp->mask));
      ifp->dbg("MASK %x\n", ifp->mask);
    } else if (p[0] == 3 && p[1] == sizeof(ifp->gw)) {
      memcpy(&ifp->gw, p + 2, sizeof(ifp->gw));
      ifp->ip = dhcp->yiaddr;
      ifp->dbg("IP %x GW %x\n", ifp->ip, ifp->gw);
    }
    p += p[1] + 2;
  }
  ifp->dbg("DHCP!!!!!");
  if (ip == 0 && ifp->ip) {
  }
}

static void mip_ip(struct mip_if *ifp, struct eth *eth, struct ip *ip,
                   size_t len) {
  if (ip->proto == 1) {
    struct icmp *icmp = (struct icmp *) (ip + 1);
    if (len < sizeof(*icmp)) return;
    ifp->dbg("ICMP %d\n", len);
    mip_icmp(ifp, eth, ip, icmp, len - sizeof(*icmp));
  } else if (ip->proto == 17) {
    struct udp *udp = (struct udp *) (ip + 1);
    if (len < sizeof(*udp)) return;
    if (udp->dport == NET16(68))
      mip_dhcp(ifp, (struct dhcp *) (udp + 1), len - sizeof(*udp));
  }
}

void mip_rcv(struct mip_if *ifp) {
  // ifp->dbg("got frame %u bytes\n", len);
  size_t len = ifp->frame_len;
  struct eth *eth = (struct eth *) ifp->frame;
  if (len < sizeof(*eth)) return;  // Truncated packet - runt?
  if (eth->type == NET16(0x806)) {
    struct arp *arp = (struct arp *) (eth + 1);
    if (sizeof(*eth) + sizeof(*arp) > len) return;  // Truncated
    ifp->dbg("ARP %d\n", len);
    mip_arp(ifp, eth, arp);
  } else if (eth->type == NET16(0x800)) {
    struct ip *ip = (struct ip *) (eth + 1);
    if (len < sizeof(*eth) + sizeof(*ip)) return;  // Truncated packed
    if (ip->ver != 0x45) return;                   // Not IP
    ifp->dbg("IP %d\n", len);
    mip_ip(ifp, eth, ip, len - sizeof(*eth) - sizeof(*ip));
  }
}

static struct ip *tx_ip(struct mip_if *ifp, uint8_t proto, uint32_t ip_src,
                        uint32_t ip_dst, size_t plen) {
  struct eth *eth = (struct eth *) ifp->frame;
  struct ip *ip = (struct ip *) (eth + 1);
  if (ip_dst == 0xffffffff) memset(eth->dst, 255, sizeof(eth->dst));
  memcpy(eth->src, ifp->mac, sizeof(eth->src));
  eth->type = NET16(0x800);
  ip->ver = 0x45;
  ip->tos = 0x0;
  ip->len = NET16(plen);
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
  udp->len = NET16(sizeof(*udp) + len);
  udp->csum = 0;
  uint32_t cs = csumup(0, udp, sizeof(*udp));
  cs = csumup(cs, buf, len);
  cs = csumup(cs, &ip->src, sizeof(ip->src));
  cs = csumup(cs, &ip->dst, sizeof(ip->dst));
  cs += ip->proto + sizeof(*udp) + len;
  udp->csum = csumfin(cs);
  memcpy(udp + 1, buf, len);
  ifp->frame_len = sizeof(struct eth) + sizeof(*ip) + sizeof(*udp) + len;
  ifp->snd(ifp);
}

static void tx_dhcp(struct mip_if *ifp, uint8_t *opts, size_t optslen) {
  struct dhcp dhcp = {
      .op = 1, .htype = 1, .hlen = 6, .magic = NET32(0x63825363)};
  memcpy(dhcp.hwaddr, ifp->mac, sizeof(ifp->mac));
  memcpy(&dhcp.xid, ifp->mac + 2, sizeof(dhcp.xid));
  memcpy(dhcp.options, opts, optslen);
  tx_udp(ifp, 0, 0xffffffff, 68, 67, &dhcp, sizeof(dhcp));
}

static void tx_dhcp_discover(struct mip_if *ifp) {
  uint8_t opts[] = {
      53, 1, 1,                      // Type: DHCP discover
      55, 3, 1, 3,   6,              // Parameters: ip, mask, DNS server
      61, 7, 1, 0,   0, 0, 0, 0, 0,  // Client ID: ether + mac addr
      57, 2, 5, 220,                 // Max message size: 1500
      255                            // End of options
  };
  memcpy(opts + 11, ifp->mac, sizeof(ifp->mac));
  tx_dhcp(ifp, opts, sizeof(opts));
}

void mip_poll(struct mip_if *ifp, uint64_t uptime_ms) {
  // ifp->dbg("poll: %p %lld\n", ifp, uptime_ms);
  if (ifp->ip == 0 && uptime_ms > ifp->timer) {
    tx_dhcp_discover(ifp);
    ifp->timer = uptime_ms + 3000;
  }
}
