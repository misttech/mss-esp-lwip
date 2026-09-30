// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! Configures the crate for the lwIP options it is built against.
//!
//! The firmware build compiles `../cmake/lwip_rust_config.c` to assembly with the C
//! stack's own flags and passes it in `LWIP_RUST_CONFIG`. Each `@@lwip NAME VALUE` line
//! there becomes a constant in `config.rs`, a `cfg` named `name` in lower case when
//! `NAME` is a feature switch and its value is not 0, and, for the layout entries, a
//! compile-time check of the matching `#[repr(C)]` mirror (the `lwip_layout` cfg).
//!
//! The memory pools lwIP declares in `memp_std.h` (the `MEMP_POOL_<name>` and
//! `MEMP_SIZE_<name>` entries) also become `memp_pools.rs`: `memp.c`'s pool descriptors.
//!
//! Without `LWIP_RUST_CONFIG`, as in host tests, the options are ESP-IDF v6.1's defaults
//! below, and no layout is checked: host pointers are wider than the target's.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

/// Feature switches: each becomes a `cfg` when not 0. ESP-IDF v6.1 defaults.
const SWITCHES: &[(&str, u64)] = &[
    ("LWIP_IPV4", 1),
    ("LWIP_IPV6", 1),
    ("LWIP_IPV6_SCOPES", 1),
    ("LWIP_IPV6_ADDRESS_LIFETIMES", 1),
    ("LWIP_ND6_ALLOW_RA_UPDATES", 1),
    ("LWIP_SINGLE_NETIF", 0),
    ("LWIP_NETIF_STATUS_CALLBACK", 0),
    ("LWIP_NETIF_LINK_CALLBACK", 0),
    ("LWIP_NETIF_REMOVE_CALLBACK", 0),
    ("LWIP_NETIF_HOSTNAME", 1),
    ("LWIP_CHECKSUM_CTRL_PER_NETIF", 0),
    ("LWIP_NOASSERT", 0),
    ("LWIP_ASSERT_SILENT", 0),
    ("LWIP_HTONS_FN", 1),
    ("LWIP_HTONL_FN", 1),
    ("LWIP_STRNSTR_FN", 1),
    ("LWIP_STRNISTR_FN", 1),
    ("LWIP_STRICMP_FN", 1),
    ("LWIP_STRNICMP_FN", 1),
    ("LWIP_ITOA_FN", 1),
    ("LWIP_NO_CTYPE_H", 0),
    ("LWIP_STANDARD_CHKSUM", 1),
    ("MEM_LIBC_MALLOC", 1),
    ("MEMP_MEM_MALLOC", 1),
    ("ESP_LWIP", 1),
    ("LWIP_TCP", 1),
    ("LWIP_SUPPORT_CUSTOM_PBUF", 1),
    ("PBUF_POOL_FREE_OOSEQ", 1),
    ("PBUF_SPLIT_64K", 0),
    ("ENABLE_LOOPBACK", 1),
    ("LWIP_HAVE_LOOPIF", 1),
    ("LWIP_NETIF_LOOPBACK_MULTITHREADING", 1),
    ("LWIP_LOOPBACK_MAX_PBUFS", 8),
    ("LWIP_NETIF_EXT_STATUS_CALLBACK", 1),
    ("LWIP_IGMP", 1),
    ("LWIP_ACD", 1),
    ("LWIP_DHCP", 1),
    ("LWIP_UDP", 1),
    ("LWIP_RAW", 1),
    ("MIB2_STATS", 0),
    ("LWIP_NETIF_USE_HINTS", 0),
    ("IP_NAPT", 0),
    ("LWIP_ARP", 1),
    ("LWIP_ETHERNET", 1),
    ("ARP_QUEUEING", 1),
    ("ETHARP_SUPPORT_STATIC_ENTRIES", 1),
    ("ETHARP_TABLE_MATCH_NETIF", 1),
    ("ETHARP_SUPPORT_VLAN", 0),
    ("LWIP_AUTOIP", 0),
    ("LWIP_IPV6_MLD", 1),
    ("LWIP_IPV6_AUTOCONFIG", 1),
    ("LWIP_IPV6_SEND_ROUTER_SOLICIT", 1),
    ("LWIP_IPV6_DHCP6", 0),
    ("LWIP_NETIF_HOOKS", 0),
    ("LWIP_NETIF_STATS_DEBUG", 0),
    ("LWIP_ICMP", 1),
    ("IP_FORWARD", 0),
    ("IP_REASSEMBLY", 0),
    ("IP_FRAG", 1),
    ("IP_OPTIONS_ALLOWED", 1),
    ("IP_OPTIONS_SEND", 1),
    ("IP_ACCEPT_LINK_LAYER_ADDRESSING", 1),
    ("CHECKSUM_GEN_IP", 1),
    ("CHECKSUM_CHECK_IP", 0),
    ("CHECKSUM_GEN_ICMP", 1),
    ("CHECKSUM_CHECK_ICMP", 1),
    ("CHECKSUM_GEN_IP_INLINE", 1),
    ("LWIP_BROADCAST_PING", 0),
    ("LWIP_MULTICAST_PING", 0),
    ("LWIP_MULTICAST_TX_OPTIONS", 1),
    ("LWIP_NETIF_LOOPBACK", 1),
    ("LWIP_NETIF_TX_SINGLE_PBUF", 1),
    ("LWIP_UDPLITE", 0),
    ("LWIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN_DEFINED", 0),
    ("LWIP_HOOK_IP4_ROUTE_SRC_DEFINED", 1),
    ("LWIP_IP4_HOOKS", 0),
    ("CHECKSUM_GEN_UDP", 1),
    ("CHECKSUM_CHECK_UDP", 0),
    ("IP_SOF_BROADCAST", 0),
    ("IP_SOF_BROADCAST_RECV", 0),
    ("LWIP_ICMP6", 1),
    ("SO_REUSE", 1),
    ("SO_REUSE_RXTOALL", 1),
    ("LWIP_RAND_DEFINED", 1),
    ("LWIP_DNS", 1),
    ("ESP_DNS", 1),
    ("ESP_LWIP_DNS_TIMERS_ONDEMAND", 1),
    ("LWIP_DNS_SETSERVER_WITH_NETIF", 0),
    ("LWIP_DNS_SUPPORT_MDNS_QUERIES", 1),
    ("DNS_LOCAL_HOSTLIST", 0),
    ("DNS_DOES_NAME_CHECK", 1),
    ("ESP_LWIP_DHCP_FINE_TIMERS_ONDEMAND", 1),
    ("LWIP_DHCP_DOES_ACD_CHECK", 1),
    ("LWIP_DHCP_GET_NTP_SRV", 0),
    ("LWIP_DHCP_BOOTP_FILE", 0),
    ("LWIP_DHCP_DISCOVER_ADD_HOSTNAME", 1),
    ("LWIP_DHCP_AUTOIP_COOP", 0),
    ("DHCP_DEFINE_CUSTOM_TIMEOUTS", 1),
    ("LWIP_TCP_TIMESTAMPS", 0),
    ("LWIP_WND_SCALE", 0),
    ("LWIP_TCP_SACK_OUT", 0),
    ("TCP_CHECKSUM_ON_COPY", 0),
    ("CHECKSUM_GEN_TCP", 1),
    ("CHECKSUM_CHECK_TCP", 1),
    ("TCP_OVERSIZE_DBGCHECK", 0),
    ("LWIP_TCP_KEEPALIVE", 1),
    ("TCP_QUEUE_OOSEQ", 1),
    ("LWIP_TCP_PCB_NUM_EXT_ARGS", 0),
    ("LWIP_CALLBACK_API", 1),
    ("LWIP_EVENT_API", 0),
    ("TCP_LISTEN_BACKLOG", 1),
    ("TCP_CALCULATE_EFF_SEND_MSS", 1),
    ("LWIP_ND6", 1),
];

/// Values. ESP-IDF v6.1 defaults.
const VALUES: &[(&str, u64)] = &[
    ("LWIP_IPV6_NUM_ADDRESSES", 3),
    ("LWIP_NETIF_CLIENT_DATA", 4),
    ("NETIF_MAX_HWADDR_LEN", 6),
    ("IP4ADDR_STRLEN_MAX", 16),
    ("LWIP_CHKSUM_ALGORITHM", 2),
    ("LWIP_CHKSUM_COPY_ALGORITHM", 0),
    ("MEM_USE_POOLS", 0),
    ("MEM_ALIGNMENT", 4),
    ("MEM_OVERFLOW_CHECK", 0),
    ("MEM_SANITY_CHECK", 0),
    ("MEMP_OVERFLOW_CHECK", 0),
    ("MEM_STATS", 0),
    ("MEMP_STATS", 0),
    ("PBUF_STATS", 0),
    ("LWIP_MEM_CLIB_HEAP_CAPS", 0),
    ("NO_SYS", 0),
    ("LWIP_DEBUG", 0),
    ("LWIP_CHECKSUM_ON_COPY", 0),
    ("MEMP_NUM_TCP_PCB", 16),
    ("PBUF_POOL_BUFSIZE", 1516),
    ("ETH_PAD_SIZE", 0),
    ("ARP_TABLE_SIZE", 10),
    ("ARP_MAXAGE", 300),
    ("ARP_QUEUE_LEN", 3),
    ("NETIF_NAMESIZE", 6),
    ("PBUF_LINK_LAYER", 14),
    ("PBUF_IP_LAYER", 54),
    ("PBUF_TRANSPORT_LAYER", 74),
    ("ICMP_TTL", 64),
    ("UDP_TTL", 64),
    ("UDP_LOCAL_PORT_RANGE_START_", 0xc000),
    ("UDP_LOCAL_PORT_RANGE_END_", 0xffff),
    ("LWIP_DNS_SECURE", 7),
    ("DNS_TABLE_SIZE", 4),
    ("DNS_MAX_NAME_LENGTH", 256),
    ("DNS_MAX_SERVERS", 3),
    ("DNS_MAX_RETRIES", 4),
    ("DNS_MAX_HOST_IP", 1),
    ("DNS_TMR_INTERVAL", 1000),
    ("LWIP_DNS_ADDRTYPE_DEFAULT", 2),
    ("DNS_MAX_TTL_", 604800),
    ("DNS_MAX_REQUESTS_", 4),
    ("DNS_MAX_SOURCE_PORTS_", 4),
    ("DNS_HOOKS", 0),
    ("DHCP_OPTIONS_LEN", 69),
    ("DHCP_COARSE_TIMER_SECS", 1),
    ("DHCP_FINE_TIMER_MSECS", 500),
    ("SIZEOF_DHCP_TIMEOUT_T", 4),
    ("LWIP_NETIF_CLIENT_DATA_INDEX_DHCP_", 0),
    ("DNS_FALLBACK_SERVER_INDEX", 2),
    ("LWIP_DHCP_PROVIDE_DNS_SERVERS_", 3),
    ("DHCP_NEXT_TIMEOUT_THRESHOLD_", 3),
    ("DHCP_BACKOFF_1", 500),
    ("DHCP_BACKOFF_4", 4000),
    ("DHCP_BACKOFF_5", 4000),
    ("DHCP_BACKOFF_255", 4000),
    ("DHCP_HOOKS", 0),
    ("DHCP_ESP_OPTION_HOOKS", 1),
    ("TCP_MSS", 1440),
    ("TCP_SND_BUF", 5760),
    ("TCP_WND", 5760),
    ("TCP_SND_QUEUELEN", 16),
    ("TCP_SNDQUEUELEN_OVERFLOW", 0xfffc),
    ("TCP_TTL", 64),
    ("TCP_OVERSIZE", 1440),
    ("TCP_HOOKS", 0),
    ("TCP_MAXRTX", 12),
    ("TCP_SYNMAXRTX", 12),
    ("TCP_PRIO_NORMAL", 64),
    ("TCP_PRIO_MAX", 127),
    ("TCP_WND_UPDATE_THRESHOLD", 1440),
    ("TCP_SLOW_INTERVAL", 500),
    ("TCP_FIN_WAIT_TIMEOUT", 20000),
    ("TCP_SYN_RCVD_TIMEOUT", 20000),
    ("TCP_OOSEQ_TIMEOUT", 6),
    ("TCP_MSL", 60000),
    ("TCP_KEEPIDLE_DEFAULT", 7200000),
    ("TCP_KEEPINTVL_DEFAULT", 75000),
    ("TCP_KEEPCNT_DEFAULT", 9),
    ("LWIP_TCP_RTO_TIME", 1500),
    ("TCP_ISN_HOOK", 1),
    ("TCP_C_OVERRIDES", 0),
    // Read only when a tcp_pcb exists; host tests have none.
    ("TCP_PCB_NEXT", 0),
    ("TCP_PCB_OOSEQ", 0),
];

/// The memory pools, as `memp_std.h` declares them: name and descriptor size, in memp_t
/// order. ESP-IDF v6.1 defaults.
const POOLS: &[(&str, u64)] = &[
    ("RAW_PCB", 72),
    ("UDP_PCB", 80),
    ("TCP_PCB", 208),
    ("TCP_PCB_LISTEN", 76),
    ("TCP_SEG", 16),
    ("FRAG_PBUF", 24),
    ("NETBUF", 36),
    ("NETCONN", 52),
    ("TCPIP_MSG_API", 16),
    ("TCPIP_MSG_INPKT", 16),
    ("ARP_QUEUE", 8),
    ("IGMP_GROUP", 16),
    ("SYS_TIMEOUT", 16),
    ("NETDB", 320),
    ("ND6_QUEUE", 8),
    ("MLD6_GROUP", 32),
    ("PBUF", 16),
    ("PBUF_POOL", 1532),
];

fn main() {
    println!("cargo::rerun-if-env-changed=LWIP_RUST_CONFIG");
    println!("cargo::rustc-check-cfg=cfg(lwip_layout)");
    for (name, _) in SWITCHES {
        println!("cargo::rustc-check-cfg=cfg({})", name.to_lowercase());
    }

    let mut entries: Vec<(String, u64)> = SWITCHES
        .iter()
        .chain(VALUES)
        .map(|&(name, value)| (name.to_string(), value))
        .collect();
    // A host's struct pbuf and the PCBs and segments are wider than the target's: size
    // their pools for them.
    let pointer =
        env::var("CARGO_CFG_TARGET_POINTER_WIDTH").map_or(4, |w| w.parse::<u64>().unwrap() / 8);
    let host_pbuf = (2 * pointer + 8).next_multiple_of(pointer);
    let mut pools: Vec<(String, u64, u64)> = POOLS
        .iter()
        .enumerate()
        .map(|(index, &(name, size))| {
            let size = match name {
                "PBUF" => host_pbuf,
                "PBUF_POOL" => host_pbuf + 1516,
                // Three pointers: next, recv, and recv_arg.
                "UDP_PCB" => (size + 3 * (pointer - 4)).next_multiple_of(pointer),
                // Wider pointers at most double a struct.
                "TCP_PCB" | "TCP_PCB_LISTEN" | "TCP_SEG" => size * pointer / 4,
                _ => size,
            };
            (name.to_string(), index as u64, size)
        })
        .collect();
    if let Some(path) = env::var_os("LWIP_RUST_CONFIG") {
        println!("cargo::rerun-if-changed={}", PathBuf::from(&path).display());
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
        let generated = parse(&text);
        assert!(
            !generated.is_empty(),
            "{} has no @@lwip entries",
            path.display()
        );
        // A switch or value the configuration does not list (an IPv6 option with IPv6
        // off) is 0; everything it lists replaces the default, and the layout entries are
        // added.
        for (name, value) in &mut entries {
            *value = generated
                .iter()
                .find(|(n, _)| n == name)
                .map_or(0, |&(_, v)| v);
        }
        pools.clear();
        let mut memp_max = None;
        for (name, value) in &generated {
            if let Some(pool) = name.strip_prefix("MEMP_POOL_") {
                let size = generated
                    .iter()
                    .find(|(n, _)| *n == format!("MEMP_SIZE_{pool}"))
                    .map(|&(_, v)| v)
                    .unwrap_or_else(|| panic!("no MEMP_SIZE_{pool}"));
                pools.push((pool.to_string(), *value, size));
            } else if name == "MEMP_MAX" {
                memp_max = Some(*value);
            } else if !name.starts_with("MEMP_SIZE_") && !entries.iter().any(|(n, _)| n == name) {
                entries.push((name.clone(), *value));
            }
        }
        pools.sort_by_key(|&(_, index, _)| index);
        assert_eq!(
            memp_max,
            Some(pools.len() as u64),
            "MEMP_MAX does not count the pools"
        );
        println!("cargo::rustc-cfg=lwip_layout");
    }
    for (position, (name, index, _)) in pools.iter().enumerate() {
        assert_eq!(
            *index, position as u64,
            "memp_t values are not consecutive at {name}"
        );
    }

    let value = |name: &str| entries.iter().find(|(n, _)| n == name).map(|&(_, v)| v);
    let require = |feature: &str, name: &str, expected: u64, what: &str| {
        let feature_on = env::var_os(format!("CARGO_FEATURE_{}", feature.to_uppercase()));
        if feature_on.is_some() {
            assert_eq!(value(name), Some(expected), "{feature}: {what}");
        }
    };
    // LWIP_DEBUGF and LWIP_ERROR's messages are not ported: they print only with LWIP_DEBUG.
    assert_eq!(value("LWIP_DEBUG"), Some(0), "LWIP_DEBUG is not ported");
    // inet_chksum.rs translates algorithm 2, the default, which ESP-IDF uses.
    if value("LWIP_STANDARD_CHKSUM") == Some(1) {
        require(
            "inet_chksum",
            "LWIP_CHKSUM_ALGORITHM",
            2,
            "only LWIP_CHKSUM_ALGORITHM 2 is ported",
        );
    }
    require(
        "inet_chksum",
        "LWIP_CHKSUM_COPY_ALGORITHM",
        0,
        "LWIP_CHKSUM_COPY is not ported",
    );
    // mem.rs and memp.rs translate the C library allocator configuration ESP-IDF uses, not
    // lwIP's own heap and pools.
    require(
        "mem",
        "MEM_LIBC_MALLOC",
        1,
        "only MEM_LIBC_MALLOC is ported",
    );
    require("mem", "MEM_USE_POOLS", 0, "MEM_USE_POOLS is not ported");
    require(
        "mem",
        "MEM_OVERFLOW_CHECK",
        0,
        "MEM_OVERFLOW_CHECK is not ported",
    );
    require(
        "mem",
        "MEM_SANITY_CHECK",
        0,
        "MEM_SANITY_CHECK is not ported",
    );
    require("mem", "MEM_STATS", 0, "MEM_STATS is not ported");
    require(
        "mem",
        "LWIP_MEM_CLIB_HEAP_CAPS",
        0,
        "heap_caps_malloc_prefer is not ported",
    );
    require(
        "memp",
        "MEMP_MEM_MALLOC",
        1,
        "only MEMP_MEM_MALLOC is ported",
    );
    require(
        "memp",
        "MEMP_OVERFLOW_CHECK",
        0,
        "MEMP_OVERFLOW_CHECK is not ported",
    );
    require("memp", "MEMP_STATS", 0, "MEMP_STATS is not ported");
    require("pbuf", "NO_SYS", 0, "only the !NO_SYS ooseq path is ported");
    require(
        "pbuf",
        "LWIP_CHECKSUM_ON_COPY",
        0,
        "LWIP_CHECKSUM_ON_COPY is not ported",
    );
    require("pbuf", "PBUF_STATS", 0, "pbuf statistics are not ported");
    // netif.rs, ethernet.rs, and etharp.rs translate the files as ESP-IDF configures them:
    // each option below selects code they do not port.
    let requires = |feature: &str, options: &[(&str, u64)]| {
        for &(name, expected) in options {
            require(
                feature,
                name,
                expected,
                &format!("only {name} = {expected} is ported"),
            );
        }
    };
    let common = [
        ("LWIP_IPV4", 1),
        ("LWIP_IPV6", 1),
        ("LWIP_NETIF_HOOKS", 0),
        ("LWIP_NETIF_STATS_DEBUG", 0),
        ("LWIP_NETIF_USE_HINTS", 0),
        ("LWIP_AUTOIP", 0),
        ("ETHARP_SUPPORT_VLAN", 0),
        ("ETH_PAD_SIZE", 0),
        ("LWIP_ARP", 1),
    ];
    requires("netif", &common);
    requires(
        "netif",
        &[
            ("LWIP_SINGLE_NETIF", 0),
            ("LWIP_IPV6_SCOPES", 1),
            ("LWIP_IPV6_ADDRESS_LIFETIMES", 1),
            ("LWIP_ND6_ALLOW_RA_UPDATES", 1),
            ("ENABLE_LOOPBACK", 1),
            ("LWIP_HAVE_LOOPIF", 1),
            ("LWIP_NETIF_LOOPBACK_MULTITHREADING", 1),
            ("LWIP_NETIF_EXT_STATUS_CALLBACK", 1),
            ("LWIP_IGMP", 1),
            ("LWIP_IPV6_MLD", 1),
            ("LWIP_ACD", 1),
            ("LWIP_DHCP", 1),
            ("LWIP_IPV6_AUTOCONFIG", 1),
            ("LWIP_IPV6_DHCP6", 0),
            ("LWIP_TCP", 1),
            ("LWIP_UDP", 1),
            ("LWIP_RAW", 1),
            ("LWIP_NETIF_STATUS_CALLBACK", 0),
            ("LWIP_NETIF_LINK_CALLBACK", 0),
            ("LWIP_NETIF_REMOVE_CALLBACK", 0),
            ("MIB2_STATS", 0),
            ("LWIP_ETHERNET", 1),
            ("NO_SYS", 0),
        ],
    );
    // ip4.rs, ip4_frag.rs, and icmp.rs translate the IPv4 files as ESP-IDF configures them.
    let ip4_common = [
        ("LWIP_IPV4", 1),
        ("IP_FORWARD", 0),
        ("IP_REASSEMBLY", 0),
        ("LWIP_IP4_HOOKS", 0),
        ("LWIP_CHECKSUM_CTRL_PER_NETIF", 0),
        ("LWIP_NETIF_USE_HINTS", 0),
        ("LWIP_SINGLE_NETIF", 0),
        ("IP_NAPT", 0),
    ];
    requires("ip4", &ip4_common);
    requires(
        "ip4",
        &[
            ("IP_OPTIONS_ALLOWED", 1),
            ("IP_OPTIONS_SEND", 1),
            ("IP_ACCEPT_LINK_LAYER_ADDRESSING", 1),
            ("CHECKSUM_GEN_IP", 1),
            ("CHECKSUM_CHECK_IP", 0),
            ("CHECKSUM_GEN_IP_INLINE", 1),
            ("LWIP_MULTICAST_TX_OPTIONS", 1),
            ("ENABLE_LOOPBACK", 1),
            ("LWIP_NETIF_LOOPBACK", 1),
            ("LWIP_HAVE_LOOPIF", 1),
            ("LWIP_HOOK_IP4_ROUTE_SRC_DEFINED", 1),
            ("IP_FRAG", 1),
            ("LWIP_IGMP", 1),
            ("LWIP_RAW", 1),
            ("LWIP_UDP", 1),
            ("LWIP_UDPLITE", 0),
            ("LWIP_TCP", 1),
            ("LWIP_ICMP", 1),
            ("LWIP_DHCP", 1),
            ("LWIP_AUTOIP", 0),
        ],
    );
    requires("ip4_frag", &ip4_common);
    requires(
        "ip4_frag",
        &[
            ("IP_FRAG", 1),
            ("LWIP_NETIF_TX_SINGLE_PBUF", 1),
            ("CHECKSUM_GEN_IP", 1),
        ],
    );
    requires("icmp", &ip4_common);
    requires(
        "icmp",
        &[
            ("LWIP_ICMP", 1),
            ("CHECKSUM_GEN_ICMP", 1),
            ("CHECKSUM_CHECK_ICMP", 1),
            ("CHECKSUM_GEN_IP", 1),
            ("LWIP_BROADCAST_PING", 0),
            ("LWIP_MULTICAST_PING", 0),
            ("LWIP_ICMP_ECHO_CHECK_INPUT_PBUF_LEN_DEFINED", 0),
        ],
    );
    // udp.rs translates udp.c as ESP-IDF configures it.
    requires(
        "udp",
        &[
            ("LWIP_IPV4", 1),
            ("LWIP_IPV6", 1),
            ("LWIP_IPV6_SCOPES", 1),
            ("LWIP_UDP", 1),
            ("LWIP_UDPLITE", 0),
            ("CHECKSUM_GEN_UDP", 1),
            ("CHECKSUM_CHECK_UDP", 0),
            ("LWIP_CHECKSUM_ON_COPY", 0),
            ("IP_SOF_BROADCAST", 0),
            ("IP_SOF_BROADCAST_RECV", 0),
            ("LWIP_ICMP", 1),
            ("LWIP_ICMP6", 1),
            ("LWIP_MULTICAST_TX_OPTIONS", 1),
            ("SO_REUSE", 1),
            ("SO_REUSE_RXTOALL", 1),
            ("LWIP_RAND_DEFINED", 1),
            ("ESP_LWIP", 1),
            ("LWIP_NETIF_USE_HINTS", 0),
        ],
    );
    // tcp.rs, tcp_in.rs, and tcp_out.rs translate the files as ESP-IDF configures them.
    let tcp_common = [
        ("LWIP_IPV4", 1),
        ("LWIP_IPV6", 1),
        ("LWIP_IPV6_SCOPES", 1),
        ("LWIP_TCP", 1),
        ("LWIP_TCP_TIMESTAMPS", 0),
        ("LWIP_WND_SCALE", 0),
        ("LWIP_TCP_SACK_OUT", 0),
        ("TCP_CHECKSUM_ON_COPY", 0),
        ("LWIP_CHECKSUM_ON_COPY", 0),
        ("CHECKSUM_GEN_TCP", 1),
        ("CHECKSUM_CHECK_TCP", 1),
        ("LWIP_CHECKSUM_CTRL_PER_NETIF", 0),
        ("TCP_OVERSIZE_DBGCHECK", 0),
        ("LWIP_TCP_KEEPALIVE", 1),
        ("TCP_QUEUE_OOSEQ", 1),
        ("LWIP_TCP_PCB_NUM_EXT_ARGS", 0),
        ("LWIP_CALLBACK_API", 1),
        ("LWIP_EVENT_API", 0),
        ("LWIP_NETIF_TX_SINGLE_PBUF", 1),
        ("TCP_HOOKS", 0),
        ("ESP_LWIP", 1),
    ];
    requires("tcp_out", &tcp_common);
    requires("tcp", &tcp_common);
    requires(
        "tcp",
        &[
            ("TCP_LISTEN_BACKLOG", 1),
            ("TCP_CALCULATE_EFF_SEND_MSS", 1),
            ("LWIP_ND6", 1),
            ("LWIP_AUTOIP", 0),
            ("SO_REUSE", 1),
            ("LWIP_RAND_DEFINED", 1),
            ("TCP_ISN_HOOK", 1),
            ("TCP_C_OVERRIDES", 0),
        ],
    );
    if env::var_os("CARGO_FEATURE_TCP_OUT").is_some() {
        assert_eq!(
            value("TCP_OVERSIZE"),
            value("TCP_MSS"),
            "tcp_out: only TCP_OVERSIZE == TCP_MSS is ported"
        );
    }
    // dhcp.rs translates dhcp.c as ESP-IDF configures it: the back-off it computes is
    // ESP-IDF's DHCP_REQUEST_BACKOFF_SEQUENCE, checked at a few points.
    requires(
        "dhcp",
        &[
            ("LWIP_IPV4", 1),
            ("LWIP_IPV6", 1),
            ("LWIP_DHCP", 1),
            ("LWIP_UDP", 1),
            ("ESP_LWIP", 1),
            ("ESP_DNS", 1),
            ("LWIP_DNS", 1),
            ("LWIP_DNS_SETSERVER_WITH_NETIF", 0),
            ("ESP_LWIP_DHCP_FINE_TIMERS_ONDEMAND", 1),
            ("LWIP_DHCP_DOES_ACD_CHECK", 1),
            ("LWIP_ACD", 1),
            ("LWIP_DHCP_GET_NTP_SRV", 0),
            ("LWIP_DHCP_BOOTP_FILE", 0),
            ("LWIP_NETIF_HOSTNAME", 1),
            ("LWIP_DHCP_DISCOVER_ADD_HOSTNAME", 1),
            ("LWIP_DHCP_AUTOIP_COOP", 0),
            ("LWIP_AUTOIP", 0),
            ("DHCP_DEFINE_CUSTOM_TIMEOUTS", 1),
            ("SIZEOF_DHCP_TIMEOUT_T", 4),
            ("DHCP_BACKOFF_1", 500),
            ("DHCP_BACKOFF_4", 4000),
            ("DHCP_BACKOFF_5", 4000),
            ("DHCP_BACKOFF_255", 4000),
            ("DHCP_HOOKS", 0),
            ("DHCP_ESP_OPTION_HOOKS", 1),
            ("LWIP_RAND_DEFINED", 1),
        ],
    );
    // dns.rs translates dns.c as ESP-IDF configures it.
    requires(
        "dns",
        &[
            ("LWIP_IPV4", 1),
            ("LWIP_IPV6", 1),
            ("LWIP_IPV6_SCOPES", 1),
            ("LWIP_DNS", 1),
            ("ESP_DNS", 1),
            ("ESP_LWIP_DNS_TIMERS_ONDEMAND", 1),
            ("LWIP_DNS_SETSERVER_WITH_NETIF", 0),
            ("LWIP_DNS_SUPPORT_MDNS_QUERIES", 1),
            ("DNS_LOCAL_HOSTLIST", 0),
            ("DNS_DOES_NAME_CHECK", 1),
            ("LWIP_HAVE_LOOPIF", 1),
            ("LWIP_DNS_SECURE", 7),
            ("LWIP_RAND_DEFINED", 1),
            ("LWIP_STRNICMP_FN", 1),
            ("DNS_HOOKS", 0),
        ],
    );
    if env::var_os("CARGO_FEATURE_NETIF").is_some() {
        assert_ne!(
            value("LWIP_LOOPBACK_MAX_PBUFS"),
            Some(0),
            "netif: LWIP_LOOPBACK_MAX_PBUFS 0 is not ported"
        );
    }
    requires("ethernet", &common);
    requires("etharp", &common);
    requires(
        "etharp",
        &[
            ("ARP_QUEUEING", 1),
            ("ETHARP_SUPPORT_STATIC_ENTRIES", 1),
            ("ETHARP_TABLE_MATCH_NETIF", 1),
            ("LWIP_ACD", 1),
        ],
    );

    let mut out = String::from("// Generated by build.rs from the lwIP configuration.\n");
    for (name, value) in &entries {
        writeln!(out, "pub const {name}: usize = {value};").unwrap();
        if value != &0 && SWITCHES.iter().any(|(n, _)| n == name) {
            println!("cargo::rustc-cfg={}", name.to_lowercase());
        }
    }
    writeln!(out, "pub const MEMP_MAX: usize = {};", pools.len()).unwrap();
    for (name, index, _) in &pools {
        writeln!(out, "pub const MEMP_{name}: u32 = {index};").unwrap();
    }
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    fs::write(out_dir.join("config.rs"), out).expect("writing config.rs");

    let mut out = String::from("// Generated by build.rs from lwIP's memp_std.h.\n");
    for (name, _, size) in &pools {
        writeln!(
            out,
            "/// `memp_{name}`: the {name} pool.\n\
             #[cfg_attr(target_os = \"none\", unsafe(no_mangle))]\n\
             pub static memp_{name}: MempDesc = MempDesc {{ size: {size} }};"
        )
        .unwrap();
    }
    writeln!(
        out,
        "/// `memp_pools`: every pool's descriptor, by `memp_t`."
    )
    .unwrap();
    writeln!(out, "#[cfg_attr(target_os = \"none\", unsafe(no_mangle))]").unwrap();
    writeln!(
        out,
        "pub static memp_pools: [&MempDesc; config::MEMP_MAX] = ["
    )
    .unwrap();
    for (name, _, _) in &pools {
        writeln!(out, "    &memp_{name},").unwrap();
    }
    writeln!(out, "];").unwrap();
    fs::write(out_dir.join("memp_pools.rs"), out).expect("writing memp_pools.rs");
}

/// The `@@lwip NAME VALUE` entries in `text`.
fn parse(text: &str) -> Vec<(String, u64)> {
    text.lines()
        .filter_map(|line| {
            let rest = &line[line.find("@@lwip ")? + "@@lwip ".len()..];
            let mut words = rest.split(|c: char| c.is_whitespace() || c == '\\' || c == '"');
            let name = words.next()?;
            let value = words.next()?.parse().ok()?;
            Some((name.to_string(), value))
        })
        .collect()
}
