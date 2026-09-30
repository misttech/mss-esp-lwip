// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

// The lwIP configuration the Rust modules are built for, read from the same headers and
// flags as the C stack.
//
// This file is compiled to assembly, never linked. Each ENTRY becomes a line
//   @@lwip NAME VALUE
// in the output, which the lwip crate's build script turns into `cfg`s and constants.
// Every `#[repr(C)]` mirror in the crate is checked against the offsets and sizes listed
// here, so a configuration the mirrors do not match fails the build instead of the
// firmware.

#include <stddef.h>

#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/ip_addr.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/sys.h"
#include "lwip/stats.h"
/* What memp.c includes, for the structs its pools hold. */
#include "lwip/raw.h"
#include "lwip/udp.h"
#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/altcp.h"
#include "lwip/ip4_frag.h"
#include "lwip/netbuf.h"
#include "lwip/api.h"
#include "lwip/priv/tcpip_priv.h"
#include "lwip/priv/api_msg.h"
#include "lwip/priv/sockets_priv.h"
#include "lwip/etharp.h"
#include "lwip/igmp.h"
#include "lwip/timeouts.h"
#include "netif/ppp/ppp_opts.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "lwip/priv/nd6_priv.h"
#include "lwip/ip6_frag.h"
#include "lwip/mld6.h"
#include "netif/ethernet.h"
#include "lwip/prot/etharp.h"
#include "lwip/prot/ethernet.h"
#include "lwip/ip.h"
#include "lwip/icmp.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/icmp.h"
#include "lwip/prot/udp.h"
#include "lwip/priv/raw_priv.h"
#include "lwip/prot/dns.h"
#include "lwip/dhcp.h"
#include "lwip/prot/dhcp.h"
#include "lwip/acd.h"
/* The port's hooks, as the lwIP sources include them. */
#ifdef LWIP_HOOK_FILENAME
#include LWIP_HOOK_FILENAME
#endif

#define ENTRY(name, value) \
  __asm__ volatile("\n.ascii \"@@lwip " #name " %0\\n\"" : : "i"((long)(value)))

#define DEFINED(name, macro_defined) ENTRY(name, macro_defined)

/* A string: a line
 *   @@lwipstr NAME TEXT
 * where TEXT, a C string literal's contents, runs to the end of the line. */
#define STRING(name, text) __asm__ volatile("\n.ascii \"@@lwipstr " #name " " text "\\n\"")

void lwip_rust_config(void);

void lwip_rust_config(void)
{
  /* Features. */
  ENTRY(LWIP_IPV4, LWIP_IPV4);
  ENTRY(LWIP_IPV6, LWIP_IPV6);
#if LWIP_IPV6
  ENTRY(LWIP_IPV6_SCOPES, LWIP_IPV6_SCOPES);
  ENTRY(LWIP_IPV6_NUM_ADDRESSES, LWIP_IPV6_NUM_ADDRESSES);
  ENTRY(LWIP_IPV6_ADDRESS_LIFETIMES, LWIP_IPV6_ADDRESS_LIFETIMES);
  ENTRY(LWIP_ND6_ALLOW_RA_UPDATES, LWIP_ND6_ALLOW_RA_UPDATES);
#endif
  ENTRY(LWIP_SINGLE_NETIF, LWIP_SINGLE_NETIF);
  ENTRY(LWIP_NETIF_STATUS_CALLBACK, LWIP_NETIF_STATUS_CALLBACK);
  ENTRY(LWIP_NETIF_LINK_CALLBACK, LWIP_NETIF_LINK_CALLBACK);
  ENTRY(LWIP_NETIF_REMOVE_CALLBACK, LWIP_NETIF_REMOVE_CALLBACK);
#ifdef netif_get_client_data
  ENTRY(LWIP_NETIF_CLIENT_DATA, LWIP_NETIF_CLIENT_DATA_INDEX_MAX + LWIP_NUM_NETIF_CLIENT_DATA);
#else
  ENTRY(LWIP_NETIF_CLIENT_DATA, 0);
#endif
  ENTRY(LWIP_NETIF_HOSTNAME, LWIP_NETIF_HOSTNAME);
  ENTRY(LWIP_CHECKSUM_CTRL_PER_NETIF, LWIP_CHECKSUM_CTRL_PER_NETIF);
  ENTRY(NETIF_MAX_HWADDR_LEN, NETIF_MAX_HWADDR_LEN);
  ENTRY(IP4ADDR_STRLEN_MAX, IP4ADDR_STRLEN_MAX);

  /* Assertions: LWIP_ASSERT compiled out, or abort() without a message. */
#ifdef LWIP_NOASSERT
  ENTRY(LWIP_NOASSERT, 1);
#else
  ENTRY(LWIP_NOASSERT, 0);
#endif
#if defined(CONFIG_OPTIMIZATION_ASSERTIONS_SILENT) && CONFIG_OPTIMIZATION_ASSERTIONS_SILENT
  ENTRY(LWIP_ASSERT_SILENT, 1);
#else
  ENTRY(LWIP_ASSERT_SILENT, 0);
#endif

  /* The functions def.c builds: a port may map each to its own in arch/cc.h. */
#if BYTE_ORDER == LITTLE_ENDIAN && !defined(lwip_htons)
  ENTRY(LWIP_HTONS_FN, 1);
#else
  ENTRY(LWIP_HTONS_FN, 0);
#endif
#if BYTE_ORDER == LITTLE_ENDIAN && !defined(lwip_htonl)
  ENTRY(LWIP_HTONL_FN, 1);
#else
  ENTRY(LWIP_HTONL_FN, 0);
#endif
#ifndef lwip_strnstr
  ENTRY(LWIP_STRNSTR_FN, 1);
#else
  ENTRY(LWIP_STRNSTR_FN, 0);
#endif
#ifndef lwip_strnistr
  ENTRY(LWIP_STRNISTR_FN, 1);
#else
  ENTRY(LWIP_STRNISTR_FN, 0);
#endif
#ifndef lwip_stricmp
  ENTRY(LWIP_STRICMP_FN, 1);
#else
  ENTRY(LWIP_STRICMP_FN, 0);
#endif
#ifndef lwip_strnicmp
  ENTRY(LWIP_STRNICMP_FN, 1);
#else
  ENTRY(LWIP_STRNICMP_FN, 0);
#endif
#ifndef lwip_itoa
  ENTRY(LWIP_ITOA_FN, 1);
#else
  ENTRY(LWIP_ITOA_FN, 0);
#endif
#if LWIP_NO_CTYPE_H
  ENTRY(LWIP_NO_CTYPE_H, 1);
#else
  ENTRY(LWIP_NO_CTYPE_H, 0);
#endif

  /* Checksums: inet_chksum.c builds lwip_standard_chksum only when the port does not
   * name its own LWIP_CHKSUM. */
#ifdef LWIP_CHKSUM
  ENTRY(LWIP_STANDARD_CHKSUM, 0);
  ENTRY(LWIP_CHKSUM_ALGORITHM, 0);
#else
  ENTRY(LWIP_STANDARD_CHKSUM, 1);
#ifdef LWIP_CHKSUM_ALGORITHM
  ENTRY(LWIP_CHKSUM_ALGORITHM, LWIP_CHKSUM_ALGORITHM);
#else
  ENTRY(LWIP_CHKSUM_ALGORITHM, 2);
#endif
#endif
#ifdef LWIP_CHKSUM_COPY_ALGORITHM
  ENTRY(LWIP_CHKSUM_COPY_ALGORITHM, LWIP_CHKSUM_COPY_ALGORITHM);
#else
  ENTRY(LWIP_CHKSUM_COPY_ALGORITHM, 0);
#endif

  /* Memory: mem.c and memp.c are ported for the C library's allocator only. */
  ENTRY(MEM_LIBC_MALLOC, MEM_LIBC_MALLOC);
  ENTRY(MEMP_MEM_MALLOC, MEMP_MEM_MALLOC);
  ENTRY(MEM_USE_POOLS, MEM_USE_POOLS);
  ENTRY(MEM_ALIGNMENT, MEM_ALIGNMENT);
  ENTRY(MEM_OVERFLOW_CHECK, MEM_OVERFLOW_CHECK);
  ENTRY(MEM_SANITY_CHECK, MEM_SANITY_CHECK);
  ENTRY(MEMP_OVERFLOW_CHECK, MEMP_OVERFLOW_CHECK);
  ENTRY(MEM_STATS, LWIP_STATS && MEM_STATS);
  ENTRY(MEMP_STATS, LWIP_STATS && MEMP_STATS);
#if defined(CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP) && CONFIG_SPIRAM_TRY_ALLOCATE_WIFI_LWIP
  ENTRY(LWIP_MEM_CLIB_HEAP_CAPS, 1);
#else
  ENTRY(LWIP_MEM_CLIB_HEAP_CAPS, 0);
#endif
  ENTRY(SIZEOF_MEM_SIZE_T, sizeof(mem_size_t));
  ENTRY(SIZEOF_MEMP_T, sizeof(memp_t));
  ENTRY(SIZEOF_MEMP_DESC, sizeof(struct memp_desc));
  ENTRY(MEMP_DESC_SIZE, offsetof(struct memp_desc, size));
  ENTRY(MEMP_MAX, MEMP_MAX);
  /* Each pool: its memp_t value and its descriptor's size, as memp.c declares them. */
#define LWIP_MEMPOOL(name, num, size, desc) \
  ENTRY(MEMP_POOL_##name, MEMP_##name); \
  ENTRY(MEMP_SIZE_##name, LWIP_MEM_ALIGN_SIZE(size)); \
  STRING(MEMP_DESC_##name, desc);
#include "lwip/priv/memp_std.h"
  /* Statistics: the heap's and each pool's, which mem.c and memp.c keep; the protocols'
   * counters are not ported. A pool descriptor names its pool for the statistics. */
  ENTRY(LWIP_STATS, LWIP_STATS);
  ENTRY(LWIP_STATS_DISPLAY, LWIP_STATS_DISPLAY);
#if defined(LWIP_DEBUG) || MEMP_OVERFLOW_CHECK || LWIP_STATS_DISPLAY
  ENTRY(MEMP_DESC_DESC, offsetof(struct memp_desc, desc));
#endif
#if LWIP_STATS
  ENTRY(SIZEOF_STAT_COUNTER, sizeof(STAT_COUNTER));
  ENTRY(SIZEOF_STATS_MEM, sizeof(struct stats_mem));
#if defined(LWIP_DEBUG) || LWIP_STATS_DISPLAY
  ENTRY(STATS_MEM_NAME, offsetof(struct stats_mem, name));
#endif
  ENTRY(STATS_MEM_ERR, offsetof(struct stats_mem, err));
  ENTRY(STATS_MEM_USED, offsetof(struct stats_mem, used));
  ENTRY(STATS_MEM_MAX, offsetof(struct stats_mem, max));
#if MEM_STATS
  ENTRY(LWIP_STATS_MEM, offsetof(struct stats_, mem));
#endif
#if MEMP_STATS
  ENTRY(MEMP_DESC_STATS, offsetof(struct memp_desc, stats));
  ENTRY(LWIP_STATS_MEMP, offsetof(struct stats_, memp));
#endif
#endif
  ENTRY(LINK_STATS, LWIP_STATS && LINK_STATS);
  ENTRY(ETHARP_STATS, LWIP_STATS && ETHARP_STATS);
  ENTRY(IP_STATS, LWIP_STATS && IP_STATS);
  ENTRY(IPFRAG_STATS, LWIP_STATS && IPFRAG_STATS);
  ENTRY(ICMP_STATS, LWIP_STATS && ICMP_STATS);
  ENTRY(UDP_STATS, LWIP_STATS && UDP_STATS);
  ENTRY(TCP_STATS, LWIP_STATS && TCP_STATS);
#if defined(ESP_LWIP) && ESP_LWIP
  ENTRY(ESP_LWIP, 1);
#else
  ENTRY(ESP_LWIP, 0);
#endif
  ENTRY(LWIP_TCP, LWIP_TCP);
  ENTRY(MEMP_NUM_TCP_PCB, MEMP_NUM_TCP_PCB);

  /* Pbufs. */
  ENTRY(PBUF_POOL_BUFSIZE, PBUF_POOL_BUFSIZE);
  ENTRY(LWIP_SUPPORT_CUSTOM_PBUF, LWIP_SUPPORT_CUSTOM_PBUF);
  ENTRY(PBUF_POOL_FREE_OOSEQ, LWIP_TCP && TCP_QUEUE_OOSEQ && PBUF_POOL_FREE_OOSEQ);
  ENTRY(NO_SYS, NO_SYS);
  ENTRY(SYS_LIGHTWEIGHT_PROT, SYS_LIGHTWEIGHT_PROT);
  ENTRY(LWIP_TESTMODE, LWIP_TESTMODE);
  ENTRY(LWIP_CHECKSUM_ON_COPY, LWIP_CHECKSUM_ON_COPY);
  ENTRY(PBUF_SPLIT_64K, LWIP_TCP && TCP_QUEUE_OOSEQ && LWIP_WND_SCALE);
#ifdef LWIP_DEBUG
  ENTRY(LWIP_DEBUG, 1);
#else
  ENTRY(LWIP_DEBUG, 0);
#endif

  /* netif.c, ethernet.c, and etharp.c. */
  /* ESP-IDF's ARP queue drops the new packet, not the oldest, when it is full. */
#if defined(ESP_LWIP_ARP) && ESP_LWIP_ARP
  ENTRY(ESP_LWIP_ARP, 1);
#else
  ENTRY(ESP_LWIP_ARP, 0);
#endif
/* An option under its own name: stringified here, before the argument expands. */
#define SWITCH(name) \
  __asm__ volatile("\n.ascii \"@@lwip " #name " %0\\n\"" : : "i"((long)(name)))
  SWITCH(ENABLE_LOOPBACK);
  SWITCH(LWIP_HAVE_LOOPIF);
  SWITCH(LWIP_NETIF_LOOPBACK_MULTITHREADING);
  SWITCH(LWIP_LOOPBACK_MAX_PBUFS);
  SWITCH(LWIP_NETIF_EXT_STATUS_CALLBACK);
  SWITCH(LWIP_IGMP);
  SWITCH(LWIP_ACD);
  SWITCH(LWIP_DHCP);
  SWITCH(LWIP_UDP);
  SWITCH(LWIP_RAW);
  SWITCH(MIB2_STATS);
  SWITCH(LWIP_NETIF_USE_HINTS);
  SWITCH(IP_NAPT);
  SWITCH(LWIP_ARP);
  SWITCH(LWIP_ETHERNET);
  SWITCH(ETH_PAD_SIZE);
  SWITCH(ARP_TABLE_SIZE);
  SWITCH(ARP_MAXAGE);
  SWITCH(ARP_QUEUEING);
  SWITCH(ARP_QUEUE_LEN);
  SWITCH(ETHARP_SUPPORT_STATIC_ENTRIES);
  SWITCH(ETHARP_TABLE_MATCH_NETIF);
  SWITCH(ETHARP_SUPPORT_VLAN);
  SWITCH(LWIP_AUTOIP);
  SWITCH(NETIF_NAMESIZE);
  ENTRY(PBUF_LINK_LAYER, PBUF_LINK);
  ENTRY(LWIP_NETIF_STATS_DEBUG, LWIP_STATS && (ETHARP_STATS || LINK_STATS || IP_STATS));
#if LWIP_IPV6
  SWITCH(LWIP_IPV6_MLD);
  SWITCH(LWIP_IPV6_AUTOCONFIG);
  SWITCH(LWIP_IPV6_SEND_ROUTER_SOLICIT);
  SWITCH(LWIP_IPV6_DHCP6);
#endif
  /* Hooks into the ported files, which are not ported: each must be undefined (or 0). */
#if defined(LWIP_HOOK_UNKNOWN_ETH_PROTOCOL) || defined(LWIP_HOOK_VLAN_CHECK) || \
    defined(LWIP_HOOK_VLAN_SET) || defined(LWIP_HOOK_ETHARP_GET_GW) || \
    defined(LWIP_HOOK_NETIF_ADD) || LWIP_ARP_FILTER_NETIF
  ENTRY(LWIP_NETIF_HOOKS, 1);
#else
  ENTRY(LWIP_NETIF_HOOKS, 0);
#endif

  /* ip4.c, ip4_frag.c, and icmp.c. */
  SWITCH(LWIP_ICMP);
  SWITCH(IP_FORWARD);
  SWITCH(IP_REASSEMBLY);
  SWITCH(IP_FRAG);
  SWITCH(IP_OPTIONS_ALLOWED);
  SWITCH(IP_OPTIONS_SEND);
  /* ip4.c's own derived switches, computed as it computes them. */
#if LWIP_DHCP || defined(LWIP_IP_ACCEPT_UDP_PORT)
  ENTRY(IP_ACCEPT_LINK_LAYER_ADDRESSING, 1);
#else
  ENTRY(IP_ACCEPT_LINK_LAYER_ADDRESSING, 0);
#endif
#ifdef LWIP_INLINE_IP_CHKSUM
  ENTRY(CHECKSUM_GEN_IP_INLINE, LWIP_INLINE_IP_CHKSUM && CHECKSUM_GEN_IP);
#else
  ENTRY(CHECKSUM_GEN_IP_INLINE, !LWIP_CHECKSUM_CTRL_PER_NETIF && CHECKSUM_GEN_IP);
#endif
  SWITCH(CHECKSUM_GEN_IP);
  SWITCH(CHECKSUM_CHECK_IP);
  SWITCH(CHECKSUM_GEN_ICMP);
  SWITCH(CHECKSUM_CHECK_ICMP);
  SWITCH(LWIP_BROADCAST_PING);
  SWITCH(LWIP_MULTICAST_PING);
  SWITCH(LWIP_MULTICAST_TX_OPTIONS);
  SWITCH(LWIP_NETIF_LOOPBACK);
  SWITCH(LWIP_NETIF_TX_SINGLE_PBUF);
  SWITCH(LWIP_UDPLITE);
  SWITCH(ICMP_TTL);
  ENTRY(PBUF_IP_LAYER, PBUF_IP);
  ENTRY(PBUF_TRANSPORT_LAYER, PBUF_TRANSPORT);
#ifdef LWIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN
  ENTRY(LWIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN_DEFINED, 1);
#else
  ENTRY(LWIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN_DEFINED, 0);
#endif
  /* ESP-IDF routes by source through LWIP_HOOK_IP4_ROUTE_SRC; the other IPv4 hooks are
   * not ported. */
#ifdef LWIP_HOOK_IP4_ROUTE_SRC
  ENTRY(LWIP_HOOK_IP4_ROUTE_SRC_DEFINED, 1);
#else
  ENTRY(LWIP_HOOK_IP4_ROUTE_SRC_DEFINED, 0);
#endif
#if defined(LWIP_HOOK_IP4_ROUTE) || defined(LWIP_HOOK_IP4_INPUT) || \
    defined(LWIP_HOOK_IP4_CANFORWARD) || defined(LWIP_IP_ACCEPT_UDP_PORT)
  ENTRY(LWIP_IP4_HOOKS, 1);
#else
  ENTRY(LWIP_IP4_HOOKS, 0);
#endif

  /* udp.c. */
  SWITCH(CHECKSUM_GEN_UDP);
  SWITCH(CHECKSUM_CHECK_UDP);
  SWITCH(IP_SOF_BROADCAST);
  SWITCH(IP_SOF_BROADCAST_RECV);
  SWITCH(LWIP_ICMP6);
  SWITCH(SO_REUSE);
  SWITCH(SO_REUSE_RXTOALL);
  SWITCH(UDP_TTL);
  /* udp.c's own defaults unless the port sets the range. */
#ifdef UDP_LOCAL_PORT_RANGE_START
  ENTRY(UDP_LOCAL_PORT_RANGE_START_, UDP_LOCAL_PORT_RANGE_START);
  ENTRY(UDP_LOCAL_PORT_RANGE_END_, UDP_LOCAL_PORT_RANGE_END);
#else
  ENTRY(UDP_LOCAL_PORT_RANGE_START_, 0xc000);
  ENTRY(UDP_LOCAL_PORT_RANGE_END_, 0xffff);
#endif
#ifdef LWIP_RAND
  ENTRY(LWIP_RAND_DEFINED, 1);
#else
  ENTRY(LWIP_RAND_DEFINED, 0);
#endif

  /* dns.c. */
  SWITCH(LWIP_DNS);
  SWITCH(ESP_DNS);
  SWITCH(ESP_LWIP_DNS_TIMERS_ONDEMAND);
  SWITCH(LWIP_DNS_SETSERVER_WITH_NETIF);
  SWITCH(LWIP_DNS_SUPPORT_MDNS_QUERIES);
  SWITCH(DNS_LOCAL_HOSTLIST);
  SWITCH(DNS_DOES_NAME_CHECK);
  ENTRY(LWIP_DNS_SECURE, LWIP_DNS_SECURE);
  ENTRY(DNS_TABLE_SIZE, DNS_TABLE_SIZE);
  ENTRY(DNS_MAX_NAME_LENGTH, DNS_MAX_NAME_LENGTH);
  ENTRY(DNS_MAX_SERVERS, DNS_MAX_SERVERS);
  ENTRY(DNS_MAX_RETRIES, DNS_MAX_RETRIES);
  ENTRY(DNS_MAX_HOST_IP, DNS_MAX_HOST_IP);
  ENTRY(DNS_TMR_INTERVAL, DNS_TMR_INTERVAL);
  ENTRY(LWIP_DNS_ADDRTYPE_DEFAULT, LWIP_DNS_ADDRTYPE_DEFAULT);
  /* dns.c's own defaults and derived sizes, computed as it computes them. */
#ifdef DNS_MAX_TTL
  ENTRY(DNS_MAX_TTL_, DNS_MAX_TTL);
#else
  ENTRY(DNS_MAX_TTL_, 604800);
#endif
#if ((LWIP_DNS_SECURE & LWIP_DNS_SECURE_NO_MULTIPLE_OUTSTANDING) != 0) && defined(DNS_MAX_REQUESTS)
  ENTRY(DNS_MAX_REQUESTS_, DNS_MAX_REQUESTS);
#else
  ENTRY(DNS_MAX_REQUESTS_, DNS_TABLE_SIZE);
#endif
#if ((LWIP_DNS_SECURE & LWIP_DNS_SECURE_RAND_SRC_PORT) != 0) && defined(DNS_MAX_SOURCE_PORTS)
  ENTRY(DNS_MAX_SOURCE_PORTS_, DNS_MAX_SOURCE_PORTS);
#elif ((LWIP_DNS_SECURE & LWIP_DNS_SECURE_RAND_SRC_PORT) != 0) && \
    ((LWIP_DNS_SECURE & LWIP_DNS_SECURE_NO_MULTIPLE_OUTSTANDING) != 0) && defined(DNS_MAX_REQUESTS)
  ENTRY(DNS_MAX_SOURCE_PORTS_, DNS_MAX_REQUESTS);
#elif ((LWIP_DNS_SECURE & LWIP_DNS_SECURE_RAND_SRC_PORT) != 0)
  ENTRY(DNS_MAX_SOURCE_PORTS_, DNS_TABLE_SIZE);
#else
  ENTRY(DNS_MAX_SOURCE_PORTS_, 1);
#endif
  /* Hooks and overrides dns.rs does not port. */
#if defined(DNS_RAND_TXID) || defined(DNS_PORT_ALLOWED) || defined(DNS_SERVER_ADDRESS) || \
    defined(FALLBACK_DNS_SERVER_ADDRESS) || defined(LWIP_HOOK_DNS_EXTERNAL_RESOLVE) || \
    defined(DNS_LOOKUP_LOCAL_EXTERN)
  ENTRY(DNS_HOOKS, 1);
#else
  ENTRY(DNS_HOOKS, 0);
#endif

  /* dhcp.c. */
  SWITCH(ESP_LWIP_DHCP_FINE_TIMERS_ONDEMAND);
  SWITCH(LWIP_DHCP_DOES_ACD_CHECK);
  SWITCH(LWIP_DHCP_GET_NTP_SRV);
  SWITCH(LWIP_DHCP_BOOTP_FILE);
  SWITCH(LWIP_DHCP_DISCOVER_ADD_HOSTNAME);
  SWITCH(LWIP_DHCP_AUTOIP_COOP);
  SWITCH(DHCP_DEFINE_CUSTOM_TIMEOUTS);
  ENTRY(DHCP_OPTIONS_LEN, DHCP_OPTIONS_LEN);
  ENTRY(DHCP_COARSE_TIMER_SECS, DHCP_COARSE_TIMER_SECS);
  ENTRY(DHCP_FINE_TIMER_MSECS, DHCP_FINE_TIMER_MSECS);
  ENTRY(SIZEOF_DHCP_TIMEOUT_T, sizeof(dhcp_timeout_t));
  ENTRY(LWIP_NETIF_CLIENT_DATA_INDEX_DHCP_, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP);
#ifdef DNS_FALLBACK_SERVER_INDEX
  ENTRY(DNS_FALLBACK_SERVER_INDEX, DNS_FALLBACK_SERVER_INDEX);
#endif
  /* dhcp.c's own derived values, computed as it computes them. */
#if LWIP_DNS && LWIP_DHCP_MAX_DNS_SERVERS
#if DNS_MAX_SERVERS > LWIP_DHCP_MAX_DNS_SERVERS
  ENTRY(LWIP_DHCP_PROVIDE_DNS_SERVERS_, LWIP_DHCP_MAX_DNS_SERVERS);
#else
  ENTRY(LWIP_DHCP_PROVIDE_DNS_SERVERS_, DNS_MAX_SERVERS);
#endif
#else
  ENTRY(LWIP_DHCP_PROVIDE_DNS_SERVERS_, 0);
#endif
#if DHCP_DEFINE_CUSTOM_TIMEOUTS
  ENTRY(DHCP_NEXT_TIMEOUT_THRESHOLD_, DHCP_NEXT_TIMEOUT_THRESHOLD);
  /* dhcp.rs computes the back-off as ESP-IDF defines it; these are checked against it. */
  ENTRY(DHCP_BACKOFF_1, DHCP_REQUEST_BACKOFF_SEQUENCE(0, 1));
  ENTRY(DHCP_BACKOFF_4, DHCP_REQUEST_BACKOFF_SEQUENCE(0, 4));
  ENTRY(DHCP_BACKOFF_5, DHCP_REQUEST_BACKOFF_SEQUENCE(0, 5));
  ENTRY(DHCP_BACKOFF_255, DHCP_REQUEST_BACKOFF_SEQUENCE(0, 255));
#endif
  /* Hooks and overrides dhcp.rs does not port; ESP-IDF's option hooks it does. */
#if defined(LWIP_HOOK_DHCP_POST_INIT) || defined(DHCP_GLOBAL_XID) || defined(DHCP_GLOBAL_XID_HEADER) || \
    defined(DHCP_ADD_EXTRA_REQUEST_OPTIONS) || defined(LWIP_DHCP_INPUT_ERROR) || \
    (defined(DHCP_CREATE_RAND_XID) && !DHCP_CREATE_RAND_XID)
  ENTRY(DHCP_HOOKS, 1);
#else
  ENTRY(DHCP_HOOKS, 0);
#endif
#if defined(LWIP_HOOK_DHCP_PARSE_OPTION) && defined(LWIP_HOOK_DHCP_APPEND_OPTIONS)
  ENTRY(DHCP_ESP_OPTION_HOOKS, 1);
#else
  ENTRY(DHCP_ESP_OPTION_HOOKS, 0);
#endif

  /* tcp.c, tcp_in.c, and tcp_out.c. */
  SWITCH(LWIP_TCP_TIMESTAMPS);
  SWITCH(LWIP_WND_SCALE);
  SWITCH(LWIP_TCP_SACK_OUT);
  SWITCH(TCP_CHECKSUM_ON_COPY);
  SWITCH(CHECKSUM_GEN_TCP);
  SWITCH(CHECKSUM_CHECK_TCP);
  SWITCH(TCP_OVERSIZE_DBGCHECK);
  SWITCH(LWIP_TCP_KEEPALIVE);
  SWITCH(TCP_QUEUE_OOSEQ);
  SWITCH(LWIP_TCP_PCB_NUM_EXT_ARGS);
  SWITCH(LWIP_CALLBACK_API);
  SWITCH(LWIP_EVENT_API);
  ENTRY(TCP_MSS, TCP_MSS);
  ENTRY(TCP_SND_BUF, TCP_SND_BUF);
  ENTRY(TCP_WND, TCP_WND);
  ENTRY(TCP_SND_QUEUELEN, TCP_SND_QUEUELEN);
  ENTRY(TCP_SNDQUEUELEN_OVERFLOW, TCP_SNDQUEUELEN_OVERFLOW);
  ENTRY(TCP_TTL, TCP_TTL);
  ENTRY(TCP_OVERSIZE, TCP_OVERSIZE);
  SWITCH(TCP_LISTEN_BACKLOG);
  ENTRY(TCP_DEFAULT_LISTEN_BACKLOG, TCP_DEFAULT_LISTEN_BACKLOG);
  SWITCH(TCP_CALCULATE_EFF_SEND_MSS);
  SWITCH(LWIP_ND6);
  ENTRY(TCP_MAXRTX, TCP_MAXRTX);
  ENTRY(TCP_SYNMAXRTX, TCP_SYNMAXRTX);
  ENTRY(TCP_PRIO_NORMAL, TCP_PRIO_NORMAL);
  ENTRY(TCP_PRIO_MAX, TCP_PRIO_MAX);
  ENTRY(TCP_WND_UPDATE_THRESHOLD, TCP_WND_UPDATE_THRESHOLD);
  ENTRY(TCP_SLOW_INTERVAL, TCP_SLOW_INTERVAL);
  ENTRY(TCP_FIN_WAIT_TIMEOUT, TCP_FIN_WAIT_TIMEOUT);
  ENTRY(TCP_SYN_RCVD_TIMEOUT, TCP_SYN_RCVD_TIMEOUT);
  ENTRY(TCP_OOSEQ_TIMEOUT, TCP_OOSEQ_TIMEOUT);
  ENTRY(TCP_MSL, TCP_MSL);
  ENTRY(TCP_KEEPIDLE_DEFAULT, TCP_KEEPIDLE_DEFAULT);
  ENTRY(TCP_KEEPINTVL_DEFAULT, TCP_KEEPINTVL_DEFAULT);
  ENTRY(TCP_KEEPCNT_DEFAULT, TCP_KEEPCNT_DEFAULT);
  ENTRY(LWIP_TCP_RTO_TIME, LWIP_TCP_RTO_TIME);
  SWITCH(LWIP_SO_LINGER);
  SWITCH(LWIP_ND6_TCP_REACHABILITY_HINTS);
#ifdef TCP_OOSEQ_PBUFS_LIMIT
  ENTRY(TCP_OOSEQ_PBUFS_LIMIT_, TCP_OOSEQ_PBUFS_LIMIT(0));
#else
  ENTRY(TCP_OOSEQ_PBUFS_LIMIT_, 0);
#endif
#ifdef TCP_OOSEQ_BYTES_LIMIT
  ENTRY(TCP_OOSEQ_BYTES_LIMITED, 1);
#else
  ENTRY(TCP_OOSEQ_BYTES_LIMITED, 0);
#endif
#ifdef LWIP_HOOK_TCP_ISN
  ENTRY(TCP_ISN_HOOK, 1);
#else
  ENTRY(TCP_ISN_HOOK, 0);
#endif
#if defined(TCP_LOCAL_PORT_RANGE_START) || LWIP_VLAN_PCP
  ENTRY(TCP_C_OVERRIDES, 1);
#else
  ENTRY(TCP_C_OVERRIDES, 0);
#endif
#if defined(LWIP_HOOK_TCP_OUT_TCPOPT_LENGTH) || defined(LWIP_HOOK_TCP_OUT_ADD_TCPOPTS) || \
    defined(LWIP_HOOK_TCP_INPACKET_PCB) || defined(LWIP_HOOK_TCP_PARSE_OPTION)
  ENTRY(TCP_HOOKS, 1);
#else
  ENTRY(TCP_HOOKS, 0);
#endif

  /* Layouts. */
  ENTRY(SIZEOF_POINTER, sizeof(void *));
  ENTRY(SIZEOF_PBUF, sizeof(struct pbuf));
  ENTRY(ALIGNOF_PBUF, __alignof__(struct pbuf));
  ENTRY(SIZEOF_PBUF_REF, sizeof(LWIP_PBUF_REF_T));
  ENTRY(PBUF_NEXT, offsetof(struct pbuf, next));
  ENTRY(PBUF_PAYLOAD, offsetof(struct pbuf, payload));
  ENTRY(PBUF_TOT_LEN, offsetof(struct pbuf, tot_len));
  ENTRY(PBUF_LEN, offsetof(struct pbuf, len));
  ENTRY(PBUF_TYPE_INTERNAL, offsetof(struct pbuf, type_internal));
  ENTRY(PBUF_FLAGS, offsetof(struct pbuf, flags));
  ENTRY(PBUF_REF_COUNT, offsetof(struct pbuf, ref));
  ENTRY(PBUF_IF_IDX, offsetof(struct pbuf, if_idx));
#if LWIP_SUPPORT_CUSTOM_PBUF
  ENTRY(SIZEOF_PBUF_CUSTOM, sizeof(struct pbuf_custom));
  ENTRY(PBUF_CUSTOM_FREE_FUNCTION, offsetof(struct pbuf_custom, custom_free_function));
#endif
#if LWIP_TCP
  ENTRY(SIZEOF_TCPWND_SIZE_T, sizeof(tcpwnd_size_t));
  ENTRY(SIZEOF_TCP_PCB, sizeof(struct tcp_pcb));
  ENTRY(TCP_PCB_NEXT, offsetof(struct tcp_pcb, next));
  ENTRY(TCP_PCB_STATE, offsetof(struct tcp_pcb, state));
  ENTRY(TCP_PCB_FLAGS, offsetof(struct tcp_pcb, flags));
  ENTRY(TCP_PCB_TMR, offsetof(struct tcp_pcb, tmr));
  ENTRY(TCP_PCB_RCV_ANN_RIGHT_EDGE, offsetof(struct tcp_pcb, rcv_ann_right_edge));
  ENTRY(TCP_PCB_RTTEST, offsetof(struct tcp_pcb, rttest));
  ENTRY(TCP_PCB_LASTACK, offsetof(struct tcp_pcb, lastack));
  ENTRY(TCP_PCB_SND_NXT, offsetof(struct tcp_pcb, snd_nxt));
  ENTRY(TCP_PCB_SND_BUF, offsetof(struct tcp_pcb, snd_buf));
  ENTRY(TCP_PCB_BYTES_ACKED, offsetof(struct tcp_pcb, bytes_acked));
#if TCP_QUEUE_OOSEQ
  ENTRY(TCP_PCB_OOSEQ, offsetof(struct tcp_pcb, ooseq));
#endif
  ENTRY(TCP_PCB_LISTENER, offsetof(struct tcp_pcb, listener));
  ENTRY(TCP_PCB_ERRF, offsetof(struct tcp_pcb, errf));
  ENTRY(TCP_PCB_KEEP_IDLE, offsetof(struct tcp_pcb, keep_idle));
  ENTRY(TCP_PCB_KEEP_CNT_SENT, offsetof(struct tcp_pcb, keep_cnt_sent));
  ENTRY(SIZEOF_TCP_PCB_LISTEN, sizeof(struct tcp_pcb_listen));
  ENTRY(TCP_PCB_LISTEN_ACCEPT, offsetof(struct tcp_pcb_listen, accept));
  ENTRY(TCP_PCB_LISTEN_ACCEPTS_PENDING, offsetof(struct tcp_pcb_listen, accepts_pending));
  ENTRY(SIZEOF_TCP_SEG, sizeof(struct tcp_seg));
  ENTRY(TCP_SEG_TCPHDR, offsetof(struct tcp_seg, tcphdr));
  ENTRY(SIZEOF_TCP_HDR, sizeof(struct tcp_hdr));
#endif

  ENTRY(SIZEOF_IP4_ADDR, sizeof(ip4_addr_t));
#if LWIP_IPV6
  ENTRY(SIZEOF_IP6_ADDR, sizeof(ip6_addr_t));
#endif
  ENTRY(SIZEOF_IP_ADDR, sizeof(ip_addr_t));
  ENTRY(ALIGNOF_IP_ADDR, __alignof__(ip_addr_t));
#if LWIP_IPV4 && LWIP_IPV6
  ENTRY(IP_ADDR_TYPE, offsetof(ip_addr_t, type));
#endif

#if !LWIP_SINGLE_NETIF
  ENTRY(NETIF_NEXT, offsetof(struct netif, next));
#endif
#if LWIP_IPV4
  ENTRY(NETIF_IP_ADDR, offsetof(struct netif, ip_addr));
  ENTRY(NETIF_NETMASK, offsetof(struct netif, netmask));
  ENTRY(NETIF_GW, offsetof(struct netif, gw));
#endif
  ENTRY(NETIF_STATE, offsetof(struct netif, state));
  ENTRY(NETIF_MTU, offsetof(struct netif, mtu));
  ENTRY(NETIF_HWADDR, offsetof(struct netif, hwaddr));
  ENTRY(NETIF_FLAGS, offsetof(struct netif, flags));
  ENTRY(NETIF_NUM, offsetof(struct netif, num));
  ENTRY(SIZEOF_NETIF, sizeof(struct netif));
  ENTRY(ALIGNOF_NETIF, __alignof__(struct netif));
  ENTRY(NETIF_INPUT, offsetof(struct netif, input));
  ENTRY(NETIF_LINKOUTPUT, offsetof(struct netif, linkoutput));
  ENTRY(NETIF_CLIENT_DATA, offsetof(struct netif, client_data));
#if LWIP_IPV6
  ENTRY(NETIF_IP6_ADDR, offsetof(struct netif, ip6_addr));
  ENTRY(NETIF_IP6_ADDR_STATE, offsetof(struct netif, ip6_addr_state));
  ENTRY(NETIF_OUTPUT_IP6, offsetof(struct netif, output_ip6));
#if LWIP_IPV6_AUTOCONFIG
  ENTRY(NETIF_IP6_AUTOCONFIG_ENABLED, offsetof(struct netif, ip6_autoconfig_enabled));
#endif
#if LWIP_IPV6_MLD
  ENTRY(NETIF_MLD_MAC_FILTER, offsetof(struct netif, mld_mac_filter));
#endif
#endif
#if LWIP_IGMP
  ENTRY(NETIF_IGMP_MAC_FILTER, offsetof(struct netif, igmp_mac_filter));
#endif
#if LWIP_ACD
  ENTRY(NETIF_ACD_LIST, offsetof(struct netif, acd_list));
#endif
#if ENABLE_LOOPBACK
  ENTRY(NETIF_LOOP_FIRST, offsetof(struct netif, loop_first));
  ENTRY(NETIF_LOOP_LAST, offsetof(struct netif, loop_last));
#if LWIP_LOOPBACK_MAX_PBUFS
  ENTRY(NETIF_LOOP_CNT_CURRENT, offsetof(struct netif, loop_cnt_current));
#endif
#if LWIP_NETIF_LOOPBACK_MULTITHREADING
  ENTRY(NETIF_RESCHEDULE_POLL, offsetof(struct netif, reschedule_poll));
#endif
#endif
#if IP_NAPT
  ENTRY(NETIF_NAPT, offsetof(struct netif, napt));
#endif
#if LWIP_NETIF_EXT_STATUS_CALLBACK
  ENTRY(SIZEOF_NETIF_EXT_CALLBACK, sizeof(netif_ext_callback_t));
  ENTRY(NETIF_EXT_CALLBACK_NEXT, offsetof(netif_ext_callback_t, next));
  ENTRY(SIZEOF_NETIF_EXT_CALLBACK_ARGS, sizeof(netif_ext_callback_args_t));
  ENTRY(SIZEOF_NETIF_NSC_REASON, sizeof(netif_nsc_reason_t));
#endif
#if LWIP_ARP && ARP_QUEUEING
  ENTRY(SIZEOF_ETHARP_Q_ENTRY, sizeof(struct etharp_q_entry));
  ENTRY(ETHARP_Q_ENTRY_P, offsetof(struct etharp_q_entry, p));
#endif
  ENTRY(SIZEOF_IP_GLOBALS, sizeof(struct ip_globals));
  ENTRY(IP_GLOBALS_CURRENT_INPUT_NETIF, offsetof(struct ip_globals, current_input_netif));
  ENTRY(IP_GLOBALS_CURRENT_IP4_HEADER, offsetof(struct ip_globals, current_ip4_header));
  ENTRY(IP_GLOBALS_CURRENT_IP6_HEADER, offsetof(struct ip_globals, current_ip6_header));
  ENTRY(IP_GLOBALS_CURRENT_IP_HEADER_TOT_LEN, offsetof(struct ip_globals, current_ip_header_tot_len));
  ENTRY(IP_GLOBALS_CURRENT_IPHDR_SRC, offsetof(struct ip_globals, current_iphdr_src));
  ENTRY(IP_GLOBALS_CURRENT_IPHDR_DEST, offsetof(struct ip_globals, current_iphdr_dest));
  ENTRY(SIZEOF_STRUCT_IP_HDR, sizeof(struct ip_hdr));
  ENTRY(SIZEOF_STRUCT_ICMP_ECHO_HDR, sizeof(struct icmp_echo_hdr));
  ENTRY(SIZEOF_STRUCT_ICMP_HDR, sizeof(struct icmp_hdr));
  ENTRY(SIZEOF_STRUCT_UDP_HDR, sizeof(struct udp_hdr));
  ENTRY(UDP_HDR_DEST, offsetof(struct udp_hdr, dest));
  ENTRY(SIZEOF_RAW_INPUT_STATE, sizeof(raw_input_state_t));
  ENTRY(SIZEOF_STRUCT_DHCP, sizeof(struct dhcp));
  ENTRY(DHCP_REQUEST_TIMEOUT, offsetof(struct dhcp, request_timeout));
  ENTRY(DHCP_T0_TIMEOUT, offsetof(struct dhcp, t0_timeout));
  ENTRY(DHCP_SERVER_IP_ADDR, offsetof(struct dhcp, server_ip_addr));
  ENTRY(DHCP_OFFERED_IP_ADDR, offsetof(struct dhcp, offered_ip_addr));
  ENTRY(DHCP_OFFERED_T2_REBIND, offsetof(struct dhcp, offered_t2_rebind));
  ENTRY(DHCP_ACD, offsetof(struct dhcp, acd));
  ENTRY(SIZEOF_STRUCT_ACD, sizeof(struct acd));
  ENTRY(ACD_STATE, offsetof(struct acd, state));
  ENTRY(ACD_TTW, offsetof(struct acd, ttw));
  ENTRY(ACD_CONFLICT_CALLBACK, offsetof(struct acd, acd_conflict_callback));
  ENTRY(SIZEOF_STRUCT_DHCP_MSG, sizeof(struct dhcp_msg));
  ENTRY(DHCP_MSG_OPTIONS, offsetof(struct dhcp_msg, options));
  ENTRY(SIZEOF_UDP_PCB, sizeof(struct udp_pcb));
  ENTRY(UDP_PCB_REMOTE_IP, offsetof(struct udp_pcb, remote_ip));
  ENTRY(UDP_PCB_NETIF_IDX, offsetof(struct udp_pcb, netif_idx));
  ENTRY(UDP_PCB_TTL, offsetof(struct udp_pcb, ttl));
  ENTRY(UDP_PCB_NEXT, offsetof(struct udp_pcb, next));
  ENTRY(UDP_PCB_FLAGS, offsetof(struct udp_pcb, flags));
  ENTRY(UDP_PCB_LOCAL_PORT, offsetof(struct udp_pcb, local_port));
  ENTRY(UDP_PCB_REMOTE_PORT, offsetof(struct udp_pcb, remote_port));
#if LWIP_MULTICAST_TX_OPTIONS
  ENTRY(UDP_PCB_MCAST_IP4, offsetof(struct udp_pcb, mcast_ip4));
  ENTRY(UDP_PCB_MCAST_TTL, offsetof(struct udp_pcb, mcast_ttl));
#endif
  ENTRY(UDP_PCB_RECV, offsetof(struct udp_pcb, recv));
  ENTRY(UDP_PCB_RECV_ARG, offsetof(struct udp_pcb, recv_arg));
  ENTRY(SIZEOF_ETH_ADDR, sizeof(struct eth_addr));
  ENTRY(SIZEOF_STRUCT_ETH_HDR, sizeof(struct eth_hdr));
  ENTRY(ETH_HDR_TYPE, offsetof(struct eth_hdr, type));
  ENTRY(SIZEOF_STRUCT_ETHARP_HDR, sizeof(struct etharp_hdr));
  ENTRY(ETHARP_HDR_OPCODE, offsetof(struct etharp_hdr, opcode));
  ENTRY(ETHARP_HDR_SIPADDR, offsetof(struct etharp_hdr, sipaddr));
  ENTRY(ETHARP_HDR_DIPADDR, offsetof(struct etharp_hdr, dipaddr));
}
