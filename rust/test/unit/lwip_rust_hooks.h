/* Copyright 2026 Mist Tecnologia LTDA. All rights reserved. */

/* The hooks lwipopts.h names, declared as ESP-IDF's lwip_default_hooks.h declares them. */

#ifndef LWIP_RUST_HOOKS_H
#define LWIP_RUST_HOOKS_H

#include "lwip/arch.h"
#include "lwip/ip_addr.h"

struct netif;

struct netif *ip4_route_src_hook(const ip4_addr_t *src, const ip4_addr_t *dest);
u32_t lwip_hook_tcp_isn(const ip_addr_t *local_ip, u16_t local_port,
                        const ip_addr_t *remote_ip, u16_t remote_port);
u32_t esp_random(void);

#endif /* LWIP_RUST_HOOKS_H */
