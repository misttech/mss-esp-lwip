// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! The lwIP functions one module calls in another file: the Rust translation when that
//! module is built in this crate, the C function otherwise. Either way the call has the C
//! signature and contract, so a module does not depend on which of its neighbors are
//! ported. Functions of files not ported yet are always the C ones.

#![allow(clippy::missing_safety_doc, unused_unsafe)]

use core::ffi::{c_char, c_int, c_void};

use crate::mem::MemSize;
use crate::memp::MempT;
use crate::types::*;

/// For each function: a wrapper under its C name that calls `crate::<module>::<name>`
/// when the module's feature is on and the C symbol otherwise.
macro_rules! ported {
    ($($module:ident $feature:literal: fn $name:ident($($arg:ident: $ty:ty),* $(,)?) $(-> $ret:ty)?;)*) => {
        mod c_ported {
            #[allow(unused_imports)]
            use super::*;

            unsafe extern "C" {
                $(
                    #[cfg(not(feature = $feature))]
                    pub(super) fn $name($($arg: $ty),*) $(-> $ret)?;
                )*
            }
        }

        $(
            #[doc = concat!("`", stringify!($name), "()`, with the C function's contract.")]
            pub(crate) unsafe fn $name($($arg: $ty),*) $(-> $ret)? {
                #[cfg(feature = $feature)]
                // SAFETY: forwarded from the caller.
                let result = unsafe { crate::$module::$name($($arg),*) };
                #[cfg(not(feature = $feature))]
                // SAFETY: forwarded from the caller.
                let result = unsafe { c_ported::$name($($arg),*) };
                result
            }
        )*
    };
}

/// For each function of a file not ported yet: a wrapper under its C name.
macro_rules! c_only {
    ($(fn $name:ident($($arg:ident: $ty:ty),* $(,)?) $(-> $ret:ty)?;)*) => {
        mod c_only {
            #[allow(unused_imports)]
            use super::*;

            unsafe extern "C" {
                $(pub(super) fn $name($($arg: $ty),*) $(-> $ret)?;)*
            }
        }

        $(
            #[doc = concat!("`", stringify!($name), "()`, with the C function's contract.")]
            #[allow(dead_code)]
            pub(crate) unsafe fn $name($($arg: $ty),*) $(-> $ret)? {
                // SAFETY: forwarded from the caller.
                unsafe { c_only::$name($($arg),*) }
            }
        )*
    };
}

ported! {
    mem "mem": fn mem_malloc(size: MemSize) -> *mut c_void;
    mem "mem": fn mem_free(rmem: *mut c_void);
    mem "mem": fn mem_trim(mem: *mut c_void, size: MemSize) -> *mut c_void;
    memp "memp": fn memp_malloc(type_: MempT) -> *mut c_void;
    memp "memp": fn memp_free(type_: MempT, mem: *mut c_void);
    pbuf "pbuf": fn pbuf_alloc(layer: PbufLayer, length: u16, type_: PbufType) -> *mut Pbuf;
    pbuf "pbuf": fn pbuf_free(p: *mut Pbuf) -> u8;
    pbuf "pbuf": fn pbuf_clen(p: *const Pbuf) -> u16;
    pbuf "pbuf": fn pbuf_copy(p_to: *mut Pbuf, p_from: *const Pbuf) -> ErrT;
    pbuf "pbuf": fn pbuf_ref(p: *mut Pbuf);
    pbuf "pbuf": fn pbuf_clone(layer: PbufLayer, type_: PbufType, p: *mut Pbuf) -> *mut Pbuf;
    pbuf "pbuf": fn pbuf_add_header(p: *mut Pbuf, header_size_increment: usize) -> u8;
    pbuf "pbuf": fn pbuf_remove_header(p: *mut Pbuf, header_size_decrement: usize) -> u8;
    pbuf "pbuf": fn pbuf_realloc(p: *mut Pbuf, new_len: u16);
    pbuf "pbuf": fn pbuf_header_force(p: *mut Pbuf, header_size_increment: i16) -> u8;
    pbuf "pbuf": fn pbuf_copy_partial(buf: *const Pbuf, dataptr: *mut c_void, len: u16, offset: u16) -> u16;
    pbuf "pbuf": fn pbuf_copy_partial_pbuf(p_to: *mut Pbuf, p_from: *const Pbuf, copy_len: u16, offset: u16) -> ErrT;
    inet_chksum "inet_chksum": fn inet_chksum(dataptr: *const c_void, len: u16) -> u16;
    inet_chksum "inet_chksum": fn inet_chksum_pbuf(p: *mut Pbuf) -> u16;
    netif "netif": fn netif_loop_output(netif: *mut Netif, p: *mut Pbuf) -> ErrT;
    ip4 "ip4": fn ip4_input(p: *mut Pbuf, inp: *mut Netif) -> ErrT;
    ip4 "ip4": fn ip4_route(dest: *const Ip4Addr) -> *mut Netif;
    ip4 "ip4": fn ip4_route_src(src: *const Ip4Addr, dest: *const Ip4Addr) -> *mut Netif;
    ip4 "ip4": fn ip4_output_if(
        p: *mut Pbuf,
        src: *const Ip4Addr,
        dest: *const Ip4Addr,
        ttl: u8,
        tos: u8,
        proto: u8,
        netif: *mut Netif,
    ) -> ErrT;
    ip4_frag "ip4_frag": fn ip4_frag(p: *mut Pbuf, netif: *mut Netif, dest: *const Ip4Addr) -> ErrT;
    icmp "icmp": fn icmp_input(p: *mut Pbuf, inp: *mut Netif);
    icmp "icmp": fn icmp_dest_unreach(p: *mut Pbuf, t: IcmpDurType);
    ip4 "ip4": fn ip4_output_if_src(
        p: *mut Pbuf,
        src: *const Ip4Addr,
        dest: *const Ip4Addr,
        ttl: u8,
        tos: u8,
        proto: u8,
        netif: *mut Netif,
    ) -> ErrT;
    inet_chksum "inet_chksum": fn ip_chksum_pseudo(
        p: *mut Pbuf,
        proto: u8,
        proto_len: u16,
        src: *const IpAddr,
        dest: *const IpAddr,
    ) -> u16;
    pbuf "pbuf": fn pbuf_chain(h: *mut Pbuf, t: *mut Pbuf);
    netif "netif": fn netif_get_by_index(idx: u8) -> *mut Netif;
    netif "netif": fn netif_get_ip6_addr_match(netif: *mut Netif, ip6addr: *const Ip6Addr) -> i8;
    udp "udp": fn udp_input(p: *mut Pbuf, inp: *mut Netif);
    udp "udp": fn udp_netif_ip_addr_changed(old_addr: *const IpAddr, new_addr: *const IpAddr);
    udp "udp": fn udp_new_ip_type(type_: u8) -> *mut UdpPcb;
    udp "udp": fn udp_new() -> *mut UdpPcb;
    udp "udp": fn udp_connect(pcb: *mut UdpPcb, ipaddr: *const IpAddr, port: u16) -> ErrT;
    udp "udp": fn udp_sendto_if(
        pcb: *mut UdpPcb,
        p: *mut Pbuf,
        dst_ip: *const IpAddr,
        dst_port: u16,
        netif: *mut Netif,
    ) -> ErrT;
    udp "udp": fn udp_sendto_if_src(
        pcb: *mut UdpPcb,
        p: *mut Pbuf,
        dst_ip: *const IpAddr,
        dst_port: u16,
        netif: *mut Netif,
        src_ip: *const IpAddr,
    ) -> ErrT;
    netif "netif": fn netif_set_addr(
        netif: *mut Netif,
        ipaddr: *const Ip4Addr,
        netmask: *const Ip4Addr,
        gw: *const Ip4Addr,
    );
    dns "dns": fn dns_setserver(numdns: u8, dnsserver: *const IpAddr);
    dhcp "dhcp": fn dhcp_network_changed_link_up(netif: *mut Netif);
    pbuf "pbuf": fn pbuf_cat(head: *mut Pbuf, tail: *mut Pbuf);
    tcp "tcp": fn tcp_eff_send_mss_netif(sendmss: u16, outif: *mut Netif, dest: *const IpAddr) -> u16;
    tcp "tcp": fn tcp_seg_free(seg: *mut TcpSeg);
    tcp "tcp": fn tcp_segs_free(seg: *mut TcpSeg);
    tcp "tcp": fn tcp_netif_ip_addr_changed(old_addr: *const IpAddr, new_addr: *const IpAddr);
    tcp "tcp": fn tcp_free_ooseq(pcb: *mut TcpPcb);
    tcp "tcp": fn tcp_process_refused_data(pcb: *mut TcpPcb) -> ErrT;
    tcp "tcp": fn tcp_pcb_remove(pcblist: *mut *mut TcpPcb, pcb: *mut TcpPcb);
    tcp "tcp": fn tcp_free(pcb: *mut TcpPcb);
    tcp "tcp": fn tcp_abort(pcb: *mut TcpPcb);
    tcp "tcp": fn tcp_abandon(pcb: *mut TcpPcb, reset: c_int);
    tcp "tcp": fn tcp_alloc(prio: u8) -> *mut TcpPcb;
    tcp "tcp": fn tcp_next_iss(pcb: *mut TcpPcb) -> u32;
    tcp "tcp": fn tcp_backlog_accepted(pcb: *mut TcpPcb);
    tcp "tcp": fn tcp_pcb_purge(pcb: *mut TcpPcb);
    tcp "tcp": fn tcp_update_rcv_ann_wnd(pcb: *mut TcpPcb) -> u32;
    tcp "tcp": fn tcp_recv_null(arg: *mut c_void, pcb: *mut TcpPcb, p: *mut Pbuf, err: ErrT) -> ErrT;
    tcp "tcp": fn tcp_seg_copy(seg: *mut TcpSeg) -> *mut TcpSeg;
    tcp_in "tcp_in": fn tcp_trigger_input_pcb_close();
    tcp_in "tcp_in": fn tcp_input(p: *mut Pbuf, inp: *mut Netif);
    tcp_out "tcp_out": fn tcp_send_empty_ack(pcb: *mut TcpPcb) -> ErrT;
    tcp_out "tcp_out": fn tcp_rst_netif(
        netif: *mut Netif,
        seqno: u32,
        ackno: u32,
        local_ip: *const IpAddr,
        remote_ip: *const IpAddr,
        local_port: u16,
        remote_port: u16,
    );
    tcp_out "tcp_out": fn tcp_rexmit(pcb: *mut TcpPcb) -> ErrT;
    tcp_out "tcp_out": fn tcp_rexmit_fast(pcb: *mut TcpPcb);
    tcp_out "tcp_out": fn tcp_rexmit_rto(pcb: *mut TcpPcb);
    tcp_out "tcp_out": fn tcp_rst(
        pcb: *const TcpPcb,
        seqno: u32,
        ackno: u32,
        local_ip: *const IpAddr,
        remote_ip: *const IpAddr,
        local_port: u16,
        remote_port: u16,
    );
    tcp_out "tcp_out": fn tcp_send_fin(pcb: *mut TcpPcb) -> ErrT;
    tcp_out "tcp_out": fn tcp_output(pcb: *mut TcpPcb) -> ErrT;
    tcp_out "tcp_out": fn tcp_enqueue_flags(pcb: *mut TcpPcb, flags: u8) -> ErrT;
    tcp_out "tcp_out": fn tcp_zero_window_probe(pcb: *mut TcpPcb) -> ErrT;
    tcp_out "tcp_out": fn tcp_split_unsent_seg(pcb: *mut TcpPcb, split: u16) -> ErrT;
    tcp_out "tcp_out": fn tcp_rexmit_rto_prepare(pcb: *mut TcpPcb) -> ErrT;
    tcp_out "tcp_out": fn tcp_rexmit_rto_commit(pcb: *mut TcpPcb);
    tcp_out "tcp_out": fn tcp_keepalive(pcb: *mut TcpPcb) -> ErrT;
    udp "udp": fn udp_bind(pcb: *mut UdpPcb, ipaddr: *const IpAddr, port: u16) -> ErrT;
    udp "udp": fn udp_recv(pcb: *mut UdpPcb, recv: UdpRecvFn, recv_arg: *mut c_void);
    udp "udp": fn udp_remove(pcb: *mut UdpPcb);
    udp "udp": fn udp_sendto(pcb: *mut UdpPcb, p: *mut Pbuf, dst_ip: *const IpAddr, dst_port: u16) -> ErrT;
    pbuf "pbuf": fn pbuf_take(buf: *mut Pbuf, dataptr: *const c_void, len: u16) -> ErrT;
    pbuf "pbuf": fn pbuf_take_at(buf: *mut Pbuf, dataptr: *const c_void, len: u16, offset: u16) -> ErrT;
    pbuf "pbuf": fn pbuf_try_get_at(p: *const Pbuf, offset: u16) -> c_int;
    pbuf "pbuf": fn pbuf_put_at(p: *mut Pbuf, offset: u16, data: u8);
    def "def": fn lwip_itoa(result: *mut c_char, bufsize: usize, number: c_int);
    ip4_addr "ip4_addr": fn ip4_addr_isbroadcast_u32(addr: u32, netif: *const Netif) -> u8;
    ethernet "ethernet": fn ethernet_input(p: *mut Pbuf, netif: *mut Netif) -> ErrT;
    ethernet "ethernet": fn ethernet_output(
        netif: *mut Netif,
        p: *mut Pbuf,
        src: *const EthAddr,
        dst: *const EthAddr,
        eth_type: u16,
    ) -> ErrT;
    etharp "etharp": fn etharp_input(p: *mut Pbuf, netif: *mut Netif);
    etharp "etharp": fn etharp_cleanup_netif(netif: *mut Netif);
    tcp "tcp": fn tcp_tmr();
    timeouts "timeouts": fn sys_timeout(msecs: u32, handler: SysTimeoutHandler, arg: *mut c_void);
    timeouts "timeouts": fn sys_untimeout(handler: SysTimeoutHandler, arg: *mut c_void);
    timeouts "timeouts": fn tcp_timer_needed();
}

c_only! {
    fn ip_input(p: *mut Pbuf, inp: *mut Netif) -> ErrT;
    fn ip6_input(p: *mut Pbuf, inp: *mut Netif) -> ErrT;
    fn ip4_route_src_hook(src: *const Ip4Addr, dest: *const Ip4Addr) -> *mut Netif;
    fn raw_input(p: *mut Pbuf, inp: *mut Netif) -> RawInputState;
    fn esp_random() -> u32;
    fn ipaddr_aton(cp: *const c_char, addr: *mut IpAddr) -> c_int;
    fn ip6_route(src: *const Ip6Addr, dest: *const Ip6Addr) -> *mut Netif;
    fn ip6_select_source_address(netif: *mut Netif, dest: *const Ip6Addr) -> *const IpAddr;
    fn ip6_output_if_src(
        p: *mut Pbuf,
        src: *const Ip6Addr,
        dest: *const Ip6Addr,
        hl: u8,
        tc: u8,
        nexth: u8,
        netif: *mut Netif,
    ) -> ErrT;
    fn icmp6_dest_unreach(p: *mut Pbuf, c: core::ffi::c_uint);
    fn nd6_reachability_hint(ip6addr: *const Ip6Addr);
    fn lwip_hook_tcp_isn(local_ip: *const IpAddr, local_port: u16, remote_ip: *const IpAddr, remote_port: u16) -> u32;
    fn nd6_get_destination_mtu(ip6addr: *const Ip6Addr, netif: *mut Netif) -> u16;
    fn ip6_output_if(
        p: *mut Pbuf,
        src: *const Ip6Addr,
        dest: *const Ip6Addr,
        hl: u8,
        tc: u8,
        nexth: u8,
        netif: *mut Netif,
    ) -> ErrT;
    fn igmp_input(p: *mut Pbuf, inp: *mut Netif, dest: *const Ip4Addr);
    fn igmp_lookfor_group(ifp: *mut Netif, addr: *const Ip4Addr) -> *mut c_void;
    fn tcpip_try_callback(function: Option<unsafe extern "C" fn(ctx: *mut c_void)>, ctx: *mut c_void) -> ErrT;
    fn acd_arp_reply(netif: *mut Netif, hdr: *mut EtharpHdr);
    fn acd_netif_ip_addr_changed(netif: *mut Netif, old_addr: *const IpAddr, new_addr: *const IpAddr);
    fn acd_network_changed_link_down(netif: *mut Netif);
    fn acd_add(netif: *mut Netif, acd: *mut Acd, acd_conflict_callback: AcdConflictCallback) -> ErrT;
    fn acd_remove(netif: *mut Netif, acd: *mut Acd);
    fn acd_start(netif: *mut Netif, acd: *mut Acd, ipaddr: Ip4Addr) -> ErrT;
    fn dhcp_parse_extra_opts(dhcp: *mut Dhcp, state: u8, option: u8, len: u8, p: *mut Pbuf, offset: u16);
    fn dhcp_append_extra_opts(netif: *mut Netif, state: u8, msg_out: *mut c_void, options_out_len: *mut u16);
    fn igmp_start(netif: *mut Netif) -> ErrT;
    fn igmp_stop(netif: *mut Netif) -> ErrT;
    fn igmp_report_groups(netif: *mut Netif);
    fn mld6_stop(netif: *mut Netif) -> ErrT;
    fn mld6_report_groups(netif: *mut Netif);
    fn nd6_restart_netif(netif: *mut Netif);
    fn nd6_cleanup_netif(netif: *mut Netif);
    fn nd6_adjust_mld_membership(netif: *mut Netif, addr_idx: i8, new_state: u8);
    fn raw_netif_ip_addr_changed(old_addr: *const IpAddr, new_addr: *const IpAddr);
}

unsafe extern "C" {
    /// `tcpip_input`: the input function `netif_init` gives the loopback netif.
    pub(crate) fn tcpip_input(p: *mut Pbuf, inp: *mut Netif) -> ErrT;
}

#[cfg(not(feature = "ethernet"))]
mod c_ethernet {
    use super::EthAddr;

    unsafe extern "C" {
        pub(super) static ethbroadcast: EthAddr;
        pub(super) static ethzero: EthAddr;
    }
}

/// `&ethbroadcast`: ethernet.c's broadcast address, Rust or C.
pub(crate) fn ethbroadcast() -> *const EthAddr {
    #[cfg(feature = "ethernet")]
    let address = &raw const crate::ethernet::ethbroadcast;
    #[cfg(not(feature = "ethernet"))]
    // SAFETY: only the address of the C constant is taken.
    let address = unsafe { &raw const c_ethernet::ethbroadcast };
    address
}

/// `&ethzero`: ethernet.c's all-zero address, Rust or C.
pub(crate) fn ethzero() -> *const EthAddr {
    #[cfg(feature = "ethernet")]
    let address = &raw const crate::ethernet::ethzero;
    #[cfg(not(feature = "ethernet"))]
    // SAFETY: only the address of the C constant is taken.
    let address = unsafe { &raw const c_ethernet::ethzero };
    address
}

#[cfg(not(feature = "netif"))]
mod c_netif {
    use super::Netif;

    unsafe extern "C" {
        pub(super) static mut netif_list: *mut Netif;
        pub(super) static mut netif_default: *mut Netif;
    }
}

/// `netif_list`: the first netif, Rust or C.
pub(crate) fn netif_list() -> *mut Netif {
    #[cfg(feature = "netif")]
    let netif = crate::netif::netif_list.get();
    #[cfg(not(feature = "netif"))]
    // SAFETY: the stack serializes access to its globals.
    let netif = unsafe { (&raw const c_netif::netif_list).read() };
    netif
}

/// `netif_default`: the default netif, Rust or C.
pub(crate) fn netif_default() -> *mut Netif {
    #[cfg(feature = "netif")]
    let netif = crate::netif::netif_default.get();
    #[cfg(not(feature = "netif"))]
    // SAFETY: the stack serializes access to its globals.
    let netif = unsafe { (&raw const c_netif::netif_default).read() };
    netif
}

mod c_ip {
    use super::IpGlobals;

    unsafe extern "C" {
        pub(super) static mut ip_data: IpGlobals;
    }
}

/// `&ip_data`: ip.c's state of the packet being delivered (ip.c is C).
pub(crate) fn ip_data() -> *mut IpGlobals {
    // SAFETY: only the address is taken.
    unsafe { &raw mut c_ip::ip_data }
}

#[cfg(not(all(feature = "ip4_addr", lwip_ipv4)))]
mod c_ip4_addr {
    use super::IpAddr;

    unsafe extern "C" {
        pub(super) static ip_addr_any: IpAddr;
        pub(super) static ip_addr_broadcast: IpAddr;
    }
}

/// `IP_ADDR_ANY`: ip4_addr.c's 0.0.0.0, Rust or C.
pub(crate) fn ip_addr_any() -> *const IpAddr {
    #[cfg(all(feature = "ip4_addr", lwip_ipv4))]
    let address = &raw const crate::ip4_addr::ip_addr_any;
    #[cfg(not(all(feature = "ip4_addr", lwip_ipv4)))]
    // SAFETY: only the address of the C constant is taken.
    let address = unsafe { &raw const c_ip4_addr::ip_addr_any };
    address
}

/// `IP_ADDR_BROADCAST`: ip4_addr.c's 255.255.255.255, Rust or C.
pub(crate) fn ip_addr_broadcast() -> *const IpAddr {
    #[cfg(all(feature = "ip4_addr", lwip_ipv4))]
    let address = &raw const crate::ip4_addr::ip_addr_broadcast;
    #[cfg(not(all(feature = "ip4_addr", lwip_ipv4)))]
    // SAFETY: only the address of the C constant is taken.
    let address = unsafe { &raw const c_ip4_addr::ip_addr_broadcast };
    address
}

mod c_ip_any_type {
    use super::IpAddr;

    unsafe extern "C" {
        pub(super) static ip_addr_any_type: IpAddr;
    }
}

/// `IP_ANY_TYPE`: ip.c's dual-stack any address (ip.c is C).
pub(crate) fn ip_addr_any_type() -> *const IpAddr {
    // SAFETY: only the address of the C constant is taken.
    unsafe { &raw const c_ip_any_type::ip_addr_any_type }
}

#[cfg(all(lwip_strnicmp_fn, not(feature = "def")))]
mod c_def {
    use core::ffi::{c_char, c_int};

    unsafe extern "C" {
        pub(super) fn lwip_strnicmp(str1: *const c_char, str2: *const c_char, len: usize) -> c_int;
    }
}

/// `lwip_strnicmp()`, def.c's, Rust or C.
#[cfg(lwip_strnicmp_fn)]
pub(crate) unsafe fn lwip_strnicmp(str1: *const c_char, str2: *const c_char, len: usize) -> c_int {
    #[cfg(feature = "def")]
    // SAFETY: forwarded from the caller.
    let result = unsafe { crate::def::lwip_strnicmp(str1, str2, len) };
    #[cfg(not(feature = "def"))]
    // SAFETY: forwarded from the caller.
    let result = unsafe { c_def::lwip_strnicmp(str1, str2, len) };
    result
}

#[cfg(not(feature = "tcp"))]
mod c_tcp {
    use super::TcpPcb;

    unsafe extern "C" {
        pub(super) static mut tcp_ticks: u32;
        pub(super) static mut tcp_active_pcbs: *mut TcpPcb;
        pub(super) static mut tcp_tw_pcbs: *mut TcpPcb;
        pub(super) static mut tcp_listen_pcbs: *mut TcpPcb;
        pub(super) static mut tcp_active_pcbs_changed: u8;
    }
}

#[cfg(not(feature = "tcp_in"))]
mod c_tcp_in {
    use super::TcpPcb;

    unsafe extern "C" {
        pub(super) static mut tcp_input_pcb: *mut TcpPcb;
    }
}

/// `tcp_ticks`: tcp.c's slow-timer tick count, Rust or C.
pub(crate) fn tcp_ticks() -> u32 {
    #[cfg(feature = "tcp")]
    let ticks = crate::tcp::tcp_ticks.get();
    #[cfg(not(feature = "tcp"))]
    // SAFETY: the stack serializes access to its globals.
    let ticks = unsafe { (&raw const c_tcp::tcp_ticks).read() };
    ticks
}

/// `&tcp_active_pcbs`: tcp.c's list of active connections, Rust or C.
pub(crate) fn tcp_active_pcbs_head() -> *mut *mut TcpPcb {
    #[cfg(feature = "tcp")]
    let head = crate::tcp::tcp_active_pcbs.as_ptr();
    #[cfg(not(feature = "tcp"))]
    // SAFETY: only the address is taken.
    let head = unsafe { &raw mut c_tcp::tcp_active_pcbs };
    head
}

/// `&tcp_tw_pcbs`: tcp.c's list of connections in TIME-WAIT, Rust or C.
pub(crate) fn tcp_tw_pcbs_head() -> *mut *mut TcpPcb {
    #[cfg(feature = "tcp")]
    let head = crate::tcp::tcp_tw_pcbs.as_ptr();
    #[cfg(not(feature = "tcp"))]
    // SAFETY: only the address is taken.
    let head = unsafe { &raw mut c_tcp::tcp_tw_pcbs };
    head
}

/// `&tcp_listen_pcbs`: tcp.c's list of listening PCBs, Rust or C.
pub(crate) fn tcp_listen_pcbs_head() -> *mut *mut TcpPcb {
    #[cfg(feature = "tcp")]
    let head = crate::tcp::tcp_listen_pcbs.as_ptr();
    #[cfg(not(feature = "tcp"))]
    // SAFETY: only the address is taken.
    let head = unsafe { &raw mut c_tcp::tcp_listen_pcbs };
    head
}

/// `&tcp_active_pcbs_changed`, Rust or C.
pub(crate) fn tcp_active_pcbs_changed() -> *mut u8 {
    #[cfg(feature = "tcp")]
    let flag = crate::tcp::tcp_active_pcbs_changed.as_ptr();
    #[cfg(not(feature = "tcp"))]
    // SAFETY: only the address is taken.
    let flag = unsafe { &raw mut c_tcp::tcp_active_pcbs_changed };
    flag
}

/// `tcp_active_pcbs`: tcp.c's active connections, Rust or C.
pub(crate) fn tcp_active_pcbs() -> *mut TcpPcb {
    // SAFETY: the stack serializes access to its globals.
    unsafe { *tcp_active_pcbs_head() }
}

/// `tcp_input_pcb`: the PCB tcp_in.c is processing input for, Rust or C.
pub(crate) fn tcp_input_pcb() -> *mut TcpPcb {
    #[cfg(feature = "tcp_in")]
    let pcb = crate::tcp_in::tcp_input_pcb.get();
    #[cfg(not(feature = "tcp_in"))]
    // SAFETY: the stack serializes access to its globals.
    let pcb = unsafe { (&raw const c_tcp_in::tcp_input_pcb).read() };
    pcb
}
