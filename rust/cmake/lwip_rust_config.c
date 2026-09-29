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

#define ENTRY(name, value) \
  __asm__ volatile("\n.ascii \"@@lwip " #name " %0\\n\"" : : "i"((long)(value)))

#define DEFINED(name, macro_defined) ENTRY(name, macro_defined)

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
  ENTRY(MEMP_SIZE_##name, LWIP_MEM_ALIGN_SIZE(size));
#include "lwip/priv/memp_std.h"
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
  ENTRY(LWIP_CHECKSUM_ON_COPY, LWIP_CHECKSUM_ON_COPY);
  ENTRY(PBUF_STATS, LWIP_STATS && (MEMP_STATS || MEM_STATS));
  ENTRY(PBUF_SPLIT_64K, LWIP_TCP && TCP_QUEUE_OOSEQ && LWIP_WND_SCALE);
#ifdef LWIP_DEBUG
  ENTRY(LWIP_DEBUG, 1);
#else
  ENTRY(LWIP_DEBUG, 0);
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
  ENTRY(TCP_PCB_NEXT, offsetof(struct tcp_pcb, next));
#if TCP_QUEUE_OOSEQ
  ENTRY(TCP_PCB_OOSEQ, offsetof(struct tcp_pcb, ooseq));
#endif
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
}
