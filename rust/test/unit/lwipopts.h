/* Copyright 2026 Mist Tecnologia LTDA. All rights reserved. */

/* lwIP's unit-test options (test/unit/lwipopts.h, built with ESP_LWIP=1 as its CI does),
 * with every option the Rust modules port only one way set the way ESP-IDF sets it.
 *
 * Both builds of the unit tests, the all-C one and the one with the Rust modules, use
 * this file, so they run the same tests against the same configuration. */

#ifndef LWIP_RUST_UNITTEST_LWIPOPTS_H
#define LWIP_RUST_UNITTEST_LWIPOPTS_H

#include "../../../test/unit/lwipopts.h"

/* The port's hooks, as ESP-IDF's lwipopts.h names them (hooks.c defines them). */
#define LWIP_HOOK_FILENAME "lwip_rust_hooks.h"
#define LWIP_HOOK_IP4_ROUTE_SRC ip4_route_src_hook
#define LWIP_HOOK_TCP_ISN lwip_hook_tcp_isn

/* lwIP's heap and pools are the C library's allocator. */
#define MEM_LIBC_MALLOC 1
#define MEMP_MEM_MALLOC 1

/* The tests find leaks through the heap and pool statistics, which mem and memp keep;
 * lwip_check_ensure_no_alloc() prints each pool's name. The Rust modules count no
 * other statistic. */
#define LWIP_STATS 1
#define LWIP_STATS_DISPLAY 1
#define MEM_STATS 1
#define MEMP_STATS 1
#define LINK_STATS 0
#define ETHARP_STATS 0
#define IP_STATS 0
#define IPFRAG_STATS 0
#define ICMP_STATS 0
#define UDP_STATS 0
#define TCP_STATS 0
#undef MIB2_STATS
#define MIB2_STATS 0

/* No checksum on copy and no window scaling. */
#undef LWIP_CHECKSUM_ON_COPY
#define LWIP_CHECKSUM_ON_COPY 0
#undef TCP_CHECKSUM_ON_COPY_SANITY_CHECK
#undef TCP_CHECKSUM_ON_COPY_SANITY_CHECK_FAIL
#undef LWIP_WND_SCALE
#define LWIP_WND_SCALE 0
#undef TCP_RCV_SCALE

/* What ESP-IDF turns on. */
#define LWIP_RAW 1
#define LWIP_ACD 1
#define LWIP_NETIF_HOSTNAME 1
#define LWIP_NETIF_TX_SINGLE_PBUF 1
#define LWIP_NETIF_LOOPBACK 1
#define LWIP_LOOPBACK_MAX_PBUFS 8
#define LWIP_TCP_KEEPALIVE 1
#define ARP_QUEUEING 1
#define ESP_LWIP_ARP 1
#define TCP_LISTEN_BACKLOG 1
#define SO_REUSE 1
#define SO_REUSE_RXTOALL 1
#define LWIP_DNS_SUPPORT_MDNS_QUERIES 1
#define LWIP_DHCP_DISCOVER_ADD_HOSTNAME 1
#define DHCP_TIMEOUT_SIZE_T u32_t
#undef LWIP_DNS_SECURE
#define LWIP_DNS_SECURE \
  (LWIP_DNS_SECURE_RAND_XID | LWIP_DNS_SECURE_NO_MULTIPLE_OUTSTANDING | LWIP_DNS_SECURE_RAND_SRC_PORT)

/* What ESP-IDF leaves off. */
#define IP_REASSEMBLY 0
#define CHECKSUM_CHECK_IP 0
#define CHECKSUM_CHECK_UDP 0
#undef DHCP_ADD_EXTRA_REQUEST_OPTIONS

#endif /* LWIP_RUST_UNITTEST_LWIPOPTS_H */
