#include "mip.h"
#include "mongoose.h"

#define MIP_ETHEMERAL_PORT 49152
static uint16_t s_next_ethemeral_port = MIP_ETHEMERAL_PORT;

static void mg_mip_ev_handler(struct mip_ev *mev) {
  struct mg_mgr *mgr = mev->ifp->evdata;
  if (mev->event == MIP_POLL) {
    mg_mgr_poll(mgr, 0);
  } else {
    MG_INFO(("%d %p %u", mev->event, mev->buf, mev->len));
  }
}

void mg_attach_mip(struct mg_mgr *mgr, struct mip_if *ifp) {
  mgr->userdata = ifp;
  ifp->ev = mg_mip_ev_handler;
  ifp->evdata = mgr;
}

void mg_connect_resolved(struct mg_connection *c) {
  struct mip_if *ifp = (struct mip_if *) c->mgr->userdata;
  if (c->is_udp) {
    c->loc.ip = ifp->ip;
    c->loc.port = mg_htons(s_next_ethemeral_port++);
    MG_INFO(("%08x.%hu->%08x.%hu", mg_ntohl(c->loc.ip), mg_ntohs(c->loc.port),
             mg_ntohl(c->rem.ip), mg_ntohs(c->rem.port)));
    if (s_next_ethemeral_port == 0) s_next_ethemeral_port = MIP_ETHEMERAL_PORT;
  } else {
    mg_error(c, "Not implemented");
  }
}

bool mg_open_listener(struct mg_connection *c, const char *url) {
  (void) c, (void) url;
  return false;
}

void mg_mgr_poll(struct mg_mgr *mgr, int ms) {
  // struct mip_if *ifp = (struct mip_if *) mgr->userdata;
  struct mg_connection *c, *tmp;
  int64_t now = mg_millis();
  mg_timer_poll(now);
  for (c = mgr->conns; c != NULL; c = tmp) {
    tmp = c->next;
    mg_call(c, MG_EV_POLL, &now);
#if 0
    if (c->is_resolving || c->is_closing) {
      // Do nothing
    } else if (c->is_listening && c->is_udp == 0) {
      if (c->is_readable) accept_conn(mgr, c);
    } else if (c->is_connecting) {
      if (c->is_readable || c->is_writable) connect_conn(c);
    } else if (c->is_tls_hs) {
      if ((c->is_readable || c->is_writable)) mg_tls_handshake(c);
    } else {
      if (c->is_readable) read_conn(c);
      if (c->is_writable) write_conn(c);
      while (c->is_tls && read_conn(c) > 0) (void) 0;  // Read buffered TLS data
    }
#endif
    if (c->is_draining && c->send.len == 0) c->is_closing = 1;
    if (c->is_closing) mg_close_conn(c);
  }
  (void) ms;
}

bool mg_send(struct mg_connection *c, const void *buf, size_t len) {
  struct mip_if *ifp = (struct mip_if *) c->mgr->userdata;
  bool res = false;
  if (ifp->ip == 0) {
    mg_error(c, "net down");
  } else if (c->is_udp) {
    mip_tx_udp(ifp, c->loc.ip, c->loc.port, c->rem.ip, c->rem.port, buf, len);
    res = true;
  } else {
    mg_error(c, "TCP Not implemented");
  }
  return res;
}

void mg_mgr_wakeup(struct mg_connection *c, const void *buf, size_t len) {
  (void) c, (void) buf, (void) len;
}

struct mg_connection *mg_mkpipe(struct mg_mgr *mgr, mg_event_handler_t fn,
                                void *fn_data) {
  (void) mgr, (void) fn, (void) fn_data;
  return NULL;
}
