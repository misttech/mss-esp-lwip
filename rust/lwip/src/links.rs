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
}

c_only! {
    fn ip_input(p: *mut Pbuf, inp: *mut Netif) -> ErrT;
    fn ip4_input(p: *mut Pbuf, inp: *mut Netif) -> ErrT;
    fn ip6_input(p: *mut Pbuf, inp: *mut Netif) -> ErrT;
    fn ip4_route(dest: *const Ip4Addr) -> *mut Netif;
    fn tcpip_try_callback(function: Option<unsafe extern "C" fn(ctx: *mut c_void)>, ctx: *mut c_void) -> ErrT;
    fn acd_arp_reply(netif: *mut Netif, hdr: *mut EtharpHdr);
    fn acd_netif_ip_addr_changed(netif: *mut Netif, old_addr: *const IpAddr, new_addr: *const IpAddr);
    fn acd_network_changed_link_down(netif: *mut Netif);
    fn dhcp_network_changed_link_up(netif: *mut Netif);
    fn igmp_start(netif: *mut Netif) -> ErrT;
    fn igmp_stop(netif: *mut Netif) -> ErrT;
    fn igmp_report_groups(netif: *mut Netif);
    fn mld6_stop(netif: *mut Netif) -> ErrT;
    fn mld6_report_groups(netif: *mut Netif);
    fn nd6_restart_netif(netif: *mut Netif);
    fn nd6_cleanup_netif(netif: *mut Netif);
    fn nd6_adjust_mld_membership(netif: *mut Netif, addr_idx: i8, new_state: u8);
    fn tcp_netif_ip_addr_changed(old_addr: *const IpAddr, new_addr: *const IpAddr);
    fn udp_netif_ip_addr_changed(old_addr: *const IpAddr, new_addr: *const IpAddr);
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
