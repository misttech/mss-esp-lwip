/* Copyright 2026 Mist Tecnologia LTDA. All rights reserved. */

/* The hooks lwipopts.h names. ip4_route_src_hook is ESP-IDF's default; the ISN hook
 * counts as lwIP's own tcp_next_iss() does, since ESP-IDF's hashes a secret.
 *
 * And esp_random(), ESP-IDF's LWIP_RAND(), which the Rust modules call by that name:
 * here it is this port's LWIP_RAND(), which the C files call, so both draw from the
 * same generator in the same order. */

#include "lwip_rust_hooks.h"

#include "lwip/netif.h"
#include "lwip/priv/tcp_priv.h"

struct netif *ip4_route_src_hook(const ip4_addr_t *src, const ip4_addr_t *dest) {
  struct netif *netif = NULL;

  LWIP_UNUSED_ARG(dest);
  if ((src != NULL) && !ip4_addr_isany(src)) {
    for (netif = netif_list; netif != NULL; netif = netif->next) {
      if (netif_is_up(netif) && netif_is_link_up(netif) &&
          !ip4_addr_isany_val(*netif_ip4_addr(netif))) {
        if (ip4_addr_cmp(src, netif_ip4_addr(netif))) {
          return netif;
        }
      }
    }
  }
  return netif;
}

u32_t lwip_hook_tcp_isn(const ip_addr_t *local_ip, u16_t local_port,
                        const ip_addr_t *remote_ip, u16_t remote_port) {
  static u32_t iss = 6510;

  LWIP_UNUSED_ARG(local_ip);
  LWIP_UNUSED_ARG(local_port);
  LWIP_UNUSED_ARG(remote_ip);
  LWIP_UNUSED_ARG(remote_port);
  iss += tcp_ticks;
  return iss;
}

u32_t esp_random(void) {
  return LWIP_RAND();
}
