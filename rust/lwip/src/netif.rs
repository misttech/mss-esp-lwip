// Copyright (c) 2001-2004 Swedish Institute of Computer Science.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
// SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
// OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
// OF SUCH DAMAGE.
//
// This file is part of the lwIP TCP/IP stack.
//
// Author: Adam Dunkels <adam@sics.se>
//
// Translated to Rust for mss-esp-lwip by Mist Tecnologia LTDA.

//! lwIP network interface abstraction, from `src/core/netif.c`, as ESP-IDF configures
//! it: IPv4 and IPv6 with scopes, address lifetimes, and autoconfiguration; a loopback
//! netif fed from the tcpip thread; extended status callbacks; IGMP, MLD, ACD, and DHCP;
//! no MIB2 statistics, address hints, or plain status callbacks (`build.rs` refuses the
//! rest).
//!
//! # Safety
//!
//! Like the C module, this one runs in the tcpip thread (or with the core locked), which
//! serializes every call, and keeps its state in statics. Netif, pbuf, and address
//! pointers are as each function's C contract has them: live where the C code
//! dereferences them. The loopback queue is also touched from `netif_loop_output`, under
//! `SYS_ARCH_PROTECT`, as in C.

#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_void};
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};

use crate::config;
use crate::global::Global;
use crate::links::*;
use crate::sys::locked;
use crate::types::*;

/// The list of network interfaces.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub static netif_list: Global<*mut Netif> = Global::new(ptr::null_mut());

/// The default network interface.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub static netif_default: Global<*mut Netif> = Global::new(ptr::null_mut());

/// The number the next added netif gets, unless it is taken.
static NETIF_NUM: Global<u8> = Global::new(0);

/// The loopback netif (`loop_netif`), zeroed as a C static is.
static LOOP_NETIF: Global<MaybeUninit<Netif>> = Global::new(MaybeUninit::zeroed());

/// The loopback netif, for lwIP's unit tests.
#[cfg(lwip_testmode)]
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn netif_get_loopif() -> *mut Netif {
    LOOP_NETIF.as_ptr().cast()
}

/// The registered extended status callbacks.
static EXT_CALLBACK: Global<*mut NetifExtCallback> = Global::new(ptr::null_mut());

const NETIF_REPORT_TYPE_IPV4: u8 = 0x01;
const NETIF_REPORT_TYPE_IPV6: u8 = 0x02;

/// `LWIP_NSC_*`: why an extended status callback is called.
pub const LWIP_NSC_NONE: NetifNscReason = 0x0000;
/// netif was added. arg: NULL. Called AFTER netif was added.
pub const LWIP_NSC_NETIF_ADDED: NetifNscReason = 0x0001;
/// netif was removed. arg: NULL. Called BEFORE netif is removed.
pub const LWIP_NSC_NETIF_REMOVED: NetifNscReason = 0x0002;
/// link changed.
pub const LWIP_NSC_LINK_CHANGED: NetifNscReason = 0x0004;
/// netif administrative status changed.
pub const LWIP_NSC_STATUS_CHANGED: NetifNscReason = 0x0008;
/// IPv4 address has changed.
pub const LWIP_NSC_IPV4_ADDRESS_CHANGED: NetifNscReason = 0x0010;
/// IPv4 gateway has changed.
pub const LWIP_NSC_IPV4_GATEWAY_CHANGED: NetifNscReason = 0x0020;
/// IPv4 netmask has changed.
pub const LWIP_NSC_IPV4_NETMASK_CHANGED: NetifNscReason = 0x0040;
/// Called AFTER IPv4 address/gateway/netmask changes have been applied.
pub const LWIP_NSC_IPV4_SETTINGS_CHANGED: NetifNscReason = 0x0080;
/// IPv6 address was added.
pub const LWIP_NSC_IPV6_SET: NetifNscReason = 0x0100;
/// IPv6 address state has changed.
pub const LWIP_NSC_IPV6_ADDR_STATE_CHANGED: NetifNscReason = 0x0200;
/// IPv4 settings: valid address set, application may start to communicate.
pub const LWIP_NSC_IPV4_ADDR_VALID: NetifNscReason = 0x0400;

/// Callback arguments with no field set, where C leaves them uninitialized.
fn empty_args() -> NetifExtCallbackArgs {
    NetifExtCallbackArgs {
        ipv4_changed: Ipv4Changed {
            old_address: ptr::null(),
            old_netmask: ptr::null(),
            old_gw: ptr::null(),
        },
    }
}

/// An IPv4 address in network byte order from its four bytes, as `IP4_ADDR` sets it.
const fn ip4(a: u8, b: u8, c: u8, d: u8) -> Ip4Addr {
    Ip4Addr {
        addr: u32::from_be_bytes([a, b, c, d]).to_be(),
    }
}

/// `ip6_addr_assign_zone(ip6addr, IP6_UNICAST, netif)`: a link-local unicast address is
/// in the zone of the netif whose index is `netif_index`; any other has none.
fn ip6_addr_assign_zone(ip6addr: &mut Ip6Addr, netif_index: u8) {
    ip6addr.zone = if ip6addr.is_link_local() {
        netif_index
    } else {
        0
    };
}

/// Initialize a lwIP network interface structure for a loopback interface.
unsafe extern "C" fn netif_loopif_init(netif: *mut Netif) -> ErrT {
    lwip_assert!("netif_loopif_init: invalid netif", !netif.is_null());
    // SAFETY: the netif netif_add is initializing.
    unsafe {
        (*netif).name = [b'l' as c_char, b'o' as c_char];
        (*netif).output = Some(netif_loop_output_ipv4);
        (*netif).output_ip6 = Some(netif_loop_output_ipv6);
    }
    ERR_OK
}

/// Initializes the network interface module: adds the loopback netif, 127.0.0.1 and ::1,
/// and sets its link and itself up.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn netif_init() {
    let loop_gw = ip4(127, 0, 0, 1);
    let loop_ipaddr = ip4(127, 0, 0, 1);
    let loop_netmask = ip4(255, 0, 0, 0);
    let loop_netif = LOOP_NETIF.as_ptr().cast::<Netif>();

    // SAFETY: the loopback netif is a static that only this module adds, and tcpip_input
    // is the stack's input function.
    unsafe {
        netif_add(
            loop_netif,
            &loop_ipaddr,
            &loop_netmask,
            &loop_gw,
            ptr::null_mut(),
            Some(netif_loopif_init),
            Some(tcpip_input),
        );

        // IP_ADDR6_HOST(loop_netif.ip6_addr, 0, 0, 0, 0x00000001UL).
        let addr = &mut (*loop_netif).ip6_addr[0];
        *addr.ip6_mut() = Ip6Addr {
            addr: [0, 0, 0, 1_u32.to_be()],
            zone: 0,
        };
        addr.type_ = IPADDR_TYPE_V6;
        (*loop_netif).ip6_addr_state[0] = IP6_ADDR_VALID;

        netif_set_link_up(loop_netif);
        netif_set_up(loop_netif);
    }
}

/// Forwards a received packet for input processing with `ethernet_input()` or
/// `ip_input()` depending on netif flags. Don't call directly, pass to `netif_add()` and
/// call `netif->input()`. Only works if the netif driver correctly sets
/// NETIF_FLAG_ETHARP and/or NETIF_FLAG_ETHERNET flag!
///
/// # Safety
///
/// `p` and `inp` are live; the caller gives up `p`.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_input(p: *mut Pbuf, inp: *mut Netif) -> ErrT {
    lwip_assert!("netif_input: invalid pbuf", !p.is_null());
    lwip_assert!("netif_input: invalid netif", !inp.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        if (*inp).flags & (NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET) != 0 {
            ethernet_input(p, inp)
        } else {
            ip_input(p, inp)
        }
    }
}

/// Add a network interface to the list of lwIP netifs, without addresses. Same as
/// `netif_add` but without IPv4 addresses.
///
/// # Safety
///
/// As `netif_add`'s.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_add_noaddr(
    netif: *mut Netif,
    state: *mut c_void,
    init: NetifInitFn,
    input: NetifInputFn,
) -> *mut Netif {
    // SAFETY: forwarded from the caller.
    unsafe {
        netif_add(
            netif,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            state,
            init,
            input,
        )
    }
}

/// Add a network interface to the list of lwIP netifs.
///
/// `netif` is a pre-allocated netif structure; `ipaddr`, `netmask`, and `gw` are its IPv4
/// configuration (null for 0.0.0.0); `state` is opaque data passed to the new netif;
/// `init` is the callback that initializes the interface; `input` the callback that is
/// called to pass ingress packets up in the protocol layer stack.
///
/// Returns `netif`, or null if `init` failed.
///
/// # Safety
///
/// `netif` is writable and not on the list, the addresses null or valid.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_add(
    netif: *mut Netif,
    ipaddr: *const Ip4Addr,
    netmask: *const Ip4Addr,
    gw: *const Ip4Addr,
    state: *mut c_void,
    init: NetifInitFn,
    input: NetifInputFn,
) -> *mut Netif {
    // LWIP_ERROR("netif_add: invalid netif", netif != NULL, return NULL);
    // LWIP_ERROR("netif_add: No init function given", init != NULL, return NULL);
    let Some(init) = init else {
        return ptr::null_mut();
    };
    if netif.is_null() {
        return ptr::null_mut();
    }

    let ipaddr = if ipaddr.is_null() {
        &raw const IP4_ADDR_ANY4
    } else {
        ipaddr
    };
    let netmask = if netmask.is_null() {
        &raw const IP4_ADDR_ANY4
    } else {
        netmask
    };
    let gw = if gw.is_null() {
        &raw const IP4_ADDR_ANY4
    } else {
        gw
    };

    // SAFETY: as the caller guarantees.
    unsafe {
        // Reset new interface configuration state.
        let n = &mut *netif;
        n.ip_addr.set_zero_ip4();
        n.netmask.set_zero_ip4();
        n.gw.set_zero_ip4();
        n.output = Some(netif_null_output_ip4);
        for i in 0..config::LWIP_IPV6_NUM_ADDRESSES {
            n.ip6_addr[i].set_zero_ip6();
            n.ip6_addr_state[i] = IP6_ADDR_INVALID;
            n.ip6_addr_valid_life[i] = 0; // IP6_ADDR_LIFE_STATIC
            n.ip6_addr_pref_life[i] = 0; // IP6_ADDR_LIFE_STATIC
        }
        n.output_ip6 = Some(netif_null_output_ip6);
        n.mtu = 0;
        n.flags = 0;
        n.client_data = [ptr::null_mut(); config::LWIP_NETIF_CLIENT_DATA];
        // IPv6 address autoconfiguration should be enabled by default.
        n.ip6_autoconfig_enabled = 1;
        nd6_restart_netif(netif);
        let n = &mut *netif;
        n.igmp_mac_filter = None;
        n.mld_mac_filter = None;

        // Remember netif specific state information data.
        n.state = state;
        n.num = NETIF_NUM.get();
        n.input = input;
        n.acd_list = ptr::null_mut();
        n.loop_first = None;
        n.loop_last = None;
        n.loop_cnt_current = 0;
        n.reschedule_poll = 0;

        netif_set_addr(netif, ipaddr, netmask, gw);

        // Call user specified initialization function for netif.
        if init(netif) != ERR_OK {
            return ptr::null_mut();
        }
        (*netif).mtu6 = (*netif).mtu;

        // Assign a unique netif number in the range [0..254], so that (num+1) can serve as
        // an interface index that fits into an u8_t. We assume that the new netif has not
        // yet been added to the list here. This algorithm is O(n^2), but that should be
        // OK for lwIP.
        loop {
            if (*netif).num == 255 {
                (*netif).num = 0;
            }
            let mut num_netifs = 0;
            let mut netif2 = netif_list.get();
            let mut collided = false;
            while !netif2.is_null() {
                lwip_assert!("netif already added", netif2 != netif);
                num_netifs += 1;
                lwip_assert!(
                    "too many netifs, max. supported number is 255",
                    num_netifs <= 255
                );
                if (*netif2).num == (*netif).num {
                    (*netif).num = (*netif).num.wrapping_add(1);
                    collided = true;
                    break;
                }
                netif2 = next(netif2);
            }
            if !collided {
                break;
            }
        }
        if (*netif).num == 254 {
            NETIF_NUM.set(0);
        } else {
            NETIF_NUM.set((*netif).num + 1);
        }

        // Add this netif to the list.
        (*netif).next = NonNull::new(netif_list.get());
        netif_list.set(netif);

        // Start IGMP processing.
        if (*netif).flags & NETIF_FLAG_IGMP != 0 {
            igmp_start(netif);
        }

        netif_invoke_ext_callback(netif, LWIP_NSC_NETIF_ADDED, ptr::null());
    }
    netif
}

/// The netif after `netif` on the list.
///
/// # Safety
///
/// `netif` is live.
unsafe fn next(netif: *mut Netif) -> *mut Netif {
    // SAFETY: live, per the caller.
    unsafe { (*netif).next.map_or(ptr::null_mut(), NonNull::as_ptr) }
}

/// Tell the protocols with bound PCBs that an address changed.
///
/// # Safety
///
/// `old_addr` is valid and `new_addr` null or valid.
unsafe fn netif_do_ip_addr_changed(old_addr: *const IpAddr, new_addr: *const IpAddr) {
    // SAFETY: forwarded from the caller.
    unsafe {
        tcp_netif_ip_addr_changed(old_addr, new_addr);
        udp_netif_ip_addr_changed(old_addr, new_addr);
        raw_netif_ip_addr_changed(old_addr, new_addr);
    }
}

/// Set the IPv4 address if it changed, saving the old one in `old_addr`.
///
/// # Safety
///
/// `netif` is live, `ipaddr` valid, and `old_addr` writable.
unsafe fn netif_do_set_ipaddr(
    netif: *mut Netif,
    ipaddr: *const Ip4Addr,
    old_addr: *mut IpAddr,
) -> bool {
    lwip_assert!("invalid pointer", !ipaddr.is_null());
    lwip_assert!("invalid pointer", !old_addr.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        // Address is actually being changed?
        if (*ipaddr).addr != (*netif).ip4_addr().addr {
            let mut new_addr = IpAddr::v4((*ipaddr).addr);
            new_addr.ip4_mut().addr = (*ipaddr).addr;
            new_addr.type_ = IPADDR_TYPE_V4;

            (*old_addr).copy_from(&(*netif).ip_addr);

            netif_do_ip_addr_changed(old_addr, &new_addr);

            acd_netif_ip_addr_changed(netif, old_addr, &new_addr);

            (*netif).ip_addr.ip4_mut().addr = (*ipaddr).addr;
            (*netif).ip_addr.type_ = IPADDR_TYPE_V4;

            netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV4);

            return true; // address changed
        }
    }
    false // address unchanged
}

/// Change the IP address of a network interface.
///
/// # Safety
///
/// `netif` is null or live, and `ipaddr` null or valid.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_set_ipaddr(netif: *mut Netif, ipaddr: *const Ip4Addr) {
    // LWIP_ERROR("netif_set_ipaddr: invalid netif", netif != NULL, return);
    if netif.is_null() {
        return;
    }

    // Set ipaddr to 0.0.0.0 if NULL.
    let ipaddr = if ipaddr.is_null() {
        &raw const IP4_ADDR_ANY4
    } else {
        ipaddr
    };

    let mut old_addr = IpAddr::v4(0);
    // SAFETY: as the caller guarantees.
    unsafe {
        if netif_do_set_ipaddr(netif, ipaddr, &mut old_addr) {
            let mut args = empty_args();
            args.ipv4_changed.old_address = &old_addr;
            netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_ADDRESS_CHANGED, &args);
        }
    }
}

/// Set the netmask if it changed, saving the old one in `old_nm`.
///
/// # Safety
///
/// `netif` is live, `netmask` valid, and `old_nm` writable.
unsafe fn netif_do_set_netmask(
    netif: *mut Netif,
    netmask: *const Ip4Addr,
    old_nm: *mut IpAddr,
) -> bool {
    // SAFETY: as the caller guarantees.
    unsafe {
        // Address is actually being changed?
        if (*netmask).addr != (*netif).ip4_netmask().addr {
            lwip_assert!("invalid pointer", !old_nm.is_null());
            (*old_nm).copy_from(&(*netif).netmask);
            // Set new netmask to netif.
            (*netif).netmask.ip4_mut().addr = (*netmask).addr;
            (*netif).netmask.type_ = IPADDR_TYPE_V4;
            return true; // netmask changed
        }
    }
    false // netmask unchanged
}

/// Change the netmask of a network interface.
///
/// # Safety
///
/// `netif` is null or live, and `netmask` null or valid.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_set_netmask(netif: *mut Netif, netmask: *const Ip4Addr) {
    // LWIP_ERROR("netif_set_netmask: invalid netif", netif != NULL, return);
    if netif.is_null() {
        return;
    }

    // Set netmask to 0.0.0.0 if NULL.
    let netmask = if netmask.is_null() {
        &raw const IP4_ADDR_ANY4
    } else {
        netmask
    };

    let mut old_nm = IpAddr::v4(0);
    // SAFETY: as the caller guarantees.
    unsafe {
        if netif_do_set_netmask(netif, netmask, &mut old_nm) {
            let mut args = empty_args();
            args.ipv4_changed.old_netmask = &old_nm;
            netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_NETMASK_CHANGED, &args);
        }
    }
}

/// Set the gateway if it changed, saving the old one in `old_gw`.
///
/// # Safety
///
/// `netif` is live, `gw` valid, and `old_gw` writable.
unsafe fn netif_do_set_gw(netif: *mut Netif, gw: *const Ip4Addr, old_gw: *mut IpAddr) -> bool {
    // SAFETY: as the caller guarantees.
    unsafe {
        if (*gw).addr != (*netif).ip4_gw().addr {
            lwip_assert!("invalid pointer", !old_gw.is_null());
            (*old_gw).copy_from(&(*netif).gw);
            (*netif).gw.ip4_mut().addr = (*gw).addr;
            (*netif).gw.type_ = IPADDR_TYPE_V4;
            return true; // gateway changed
        }
    }
    false // gateway unchanged
}

/// Change the default gateway for a network interface.
///
/// # Safety
///
/// `netif` is null or live, and `gw` null or valid.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_set_gw(netif: *mut Netif, gw: *const Ip4Addr) {
    // LWIP_ERROR("netif_set_gw: invalid netif", netif != NULL, return);
    if netif.is_null() {
        return;
    }

    // Set gw to 0.0.0.0 if NULL.
    let gw = if gw.is_null() {
        &raw const IP4_ADDR_ANY4
    } else {
        gw
    };

    let mut old_gw = IpAddr::v4(0);
    // SAFETY: as the caller guarantees.
    unsafe {
        if netif_do_set_gw(netif, gw, &mut old_gw) {
            let mut args = empty_args();
            args.ipv4_changed.old_gw = &old_gw;
            netif_invoke_ext_callback(netif, LWIP_NSC_IPV4_GATEWAY_CHANGED, &args);
        }
    }
}

/// Change IP address configuration for a network interface (including netmask and
/// default gateway).
///
/// # Safety
///
/// `netif` is live, and the addresses null or valid.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_set_addr(
    netif: *mut Netif,
    ipaddr: *const Ip4Addr,
    netmask: *const Ip4Addr,
    gw: *const Ip4Addr,
) {
    let mut change_reason = LWIP_NSC_NONE;
    let mut cb_args = empty_args();
    let mut old_nm = IpAddr::v4(0);
    let mut old_gw = IpAddr::v4(0);
    let mut old_addr = IpAddr::v4(0);

    // Set ipaddr to 0.0.0.0 if NULL.
    let ipaddr = if ipaddr.is_null() {
        &raw const IP4_ADDR_ANY4
    } else {
        ipaddr
    };
    let netmask = if netmask.is_null() {
        &raw const IP4_ADDR_ANY4
    } else {
        netmask
    };
    let gw = if gw.is_null() {
        &raw const IP4_ADDR_ANY4
    } else {
        gw
    };

    // SAFETY: as the caller guarantees.
    unsafe {
        let remove = (*ipaddr).addr == IPADDR_ANY;
        if remove {
            // When removing an address, we have to remove it *before* changing netmask/gw
            // to ensure that tcp RST segment can be sent correctly.
            if netif_do_set_ipaddr(netif, ipaddr, &mut old_addr) {
                change_reason |= LWIP_NSC_IPV4_ADDRESS_CHANGED;
                cb_args.ipv4_changed.old_address = &old_addr;
            }
        }
        if netif_do_set_netmask(netif, netmask, &mut old_nm) {
            change_reason |= LWIP_NSC_IPV4_NETMASK_CHANGED;
            cb_args.ipv4_changed.old_netmask = &old_nm;
        }
        if netif_do_set_gw(netif, gw, &mut old_gw) {
            change_reason |= LWIP_NSC_IPV4_GATEWAY_CHANGED;
            cb_args.ipv4_changed.old_gw = &old_gw;
        }
        if !remove {
            // Set ipaddr last to ensure netmask/gw have been set when status callback is
            // called.
            if netif_do_set_ipaddr(netif, ipaddr, &mut old_addr) {
                change_reason |= LWIP_NSC_IPV4_ADDRESS_CHANGED;
                cb_args.ipv4_changed.old_address = &old_addr;
            }
        }

        if change_reason != LWIP_NSC_NONE {
            change_reason |= LWIP_NSC_IPV4_SETTINGS_CHANGED;
        }
        if !remove {
            // Issue a callback even if the address hasn't changed.
            change_reason |= LWIP_NSC_IPV4_ADDR_VALID;
        }
        if change_reason != LWIP_NSC_NONE {
            netif_invoke_ext_callback(netif, change_reason, &cb_args);
        }
    }
}

/// Remove a network interface from the list of lwIP netifs.
///
/// # Safety
///
/// `netif` is null or live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_remove(netif: *mut Netif) {
    if netif.is_null() {
        return;
    }

    // SAFETY: as the caller guarantees.
    unsafe {
        netif_invoke_ext_callback(netif, LWIP_NSC_NETIF_REMOVED, ptr::null());

        if (*netif).ip4_addr().addr != IPADDR_ANY {
            netif_do_ip_addr_changed(&(*netif).ip_addr, ptr::null());
        }

        // Stop IGMP processing.
        if (*netif).flags & NETIF_FLAG_IGMP != 0 {
            igmp_stop(netif);
        }

        for i in 0..config::LWIP_IPV6_NUM_ADDRESSES {
            if (*netif).ip6_addr_state[i] & IP6_ADDR_VALID != 0 {
                netif_do_ip_addr_changed(&(*netif).ip6_addr[i], ptr::null());
            }
        }
        // Stop MLD processing.
        mld6_stop(netif);

        if (*netif).flags & NETIF_FLAG_UP != 0 {
            // Set netif down before removing (call callback function).
            netif_set_down(netif);
        }

        // This netif is default?
        if netif_default.get() == netif {
            // Reset default netif.
            netif_set_default(ptr::null_mut());
        }
        // Is it the first netif?
        if netif_list.get() == netif {
            netif_list.set(next(netif));
        } else {
            // Look for netif further down the list.
            let mut tmp_netif = netif_list.get();
            while !tmp_netif.is_null() {
                if next(tmp_netif) == netif {
                    (*tmp_netif).next = (*netif).next;
                    break;
                }
                tmp_netif = next(tmp_netif);
            }
            // If tmp_netif is null, the netif is not on the list: C returns here, before
            // debug output that this configuration does not compile.
        }
    }
}

/// Set a network interface as the default network interface (used to output all packets
/// for which no specific route is found).
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn netif_set_default(netif: *mut Netif) {
    netif_default.set(netif);
}

/// Bring an interface up, available for processing traffic.
///
/// # Safety
///
/// `netif` is null or live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_set_up(netif: *mut Netif) {
    // LWIP_ERROR("netif_set_up: invalid netif", netif != NULL, return);
    if netif.is_null() {
        return;
    }

    // SAFETY: as the caller guarantees.
    unsafe {
        if (*netif).flags & NETIF_FLAG_UP == 0 {
            (*netif).flags |= NETIF_FLAG_UP;

            let mut args = empty_args();
            args.status_changed = StateChanged { state: 1 };
            netif_invoke_ext_callback(netif, LWIP_NSC_STATUS_CHANGED, &args);

            netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV4 | NETIF_REPORT_TYPE_IPV6);
            nd6_restart_netif(netif);
        }
    }
}

/// Send ARP/IGMP/MLD/RS events, e.g. on link-up/netif-up or addr-change.
///
/// # Safety
///
/// `netif` is live.
unsafe fn netif_issue_reports(netif: *mut Netif, report_type: u8) {
    lwip_assert!("netif_issue_reports: invalid netif", !netif.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        // Only send reports when both link and admin states are up.
        if (*netif).flags & NETIF_FLAG_LINK_UP == 0 || (*netif).flags & NETIF_FLAG_UP == 0 {
            return;
        }

        if report_type & NETIF_REPORT_TYPE_IPV4 != 0 && (*netif).ip4_addr().addr != IPADDR_ANY {
            // Resend IGMP memberships.
            if (*netif).flags & NETIF_FLAG_IGMP != 0 {
                igmp_report_groups(netif);
            }
        }

        if report_type & NETIF_REPORT_TYPE_IPV6 != 0 {
            // Send mld memberships.
            mld6_report_groups(netif);
        }
    }
}

/// Bring an interface down, disabling any traffic processing.
///
/// # Safety
///
/// `netif` is null or live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_set_down(netif: *mut Netif) {
    // LWIP_ERROR("netif_set_down: invalid netif", netif != NULL, return);
    if netif.is_null() {
        return;
    }

    // SAFETY: as the caller guarantees.
    unsafe {
        if (*netif).flags & NETIF_FLAG_UP != 0 {
            let mut args = empty_args();
            args.status_changed = StateChanged { state: 0 };
            netif_invoke_ext_callback(netif, LWIP_NSC_STATUS_CHANGED, &args);

            (*netif).flags &= !NETIF_FLAG_UP;

            if (*netif).flags & NETIF_FLAG_ETHARP != 0 {
                etharp_cleanup_netif(netif);
            }

            nd6_cleanup_netif(netif);
        }
    }
}

/// Called by a driver when its link goes up.
///
/// # Safety
///
/// `netif` is null or live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_set_link_up(netif: *mut Netif) {
    // LWIP_ERROR("netif_set_link_up: invalid netif", netif != NULL, return);
    if netif.is_null() {
        return;
    }

    // SAFETY: as the caller guarantees.
    unsafe {
        if (*netif).flags & NETIF_FLAG_LINK_UP == 0 {
            (*netif).flags |= NETIF_FLAG_LINK_UP;

            dhcp_network_changed_link_up(netif);

            netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV4 | NETIF_REPORT_TYPE_IPV6);
            nd6_restart_netif(netif);

            let mut args = empty_args();
            args.link_changed = StateChanged { state: 1 };
            netif_invoke_ext_callback(netif, LWIP_NSC_LINK_CHANGED, &args);
        }
    }
}

/// Called by a driver when its link goes down.
///
/// # Safety
///
/// `netif` is null or live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_set_link_down(netif: *mut Netif) {
    // LWIP_ERROR("netif_set_link_down: invalid netif", netif != NULL, return);
    if netif.is_null() {
        return;
    }

    // SAFETY: as the caller guarantees.
    unsafe {
        if (*netif).flags & NETIF_FLAG_LINK_UP != 0 {
            (*netif).flags &= !NETIF_FLAG_LINK_UP;

            acd_network_changed_link_down(netif);

            (*netif).mtu6 = (*netif).mtu;

            let mut args = empty_args();
            args.link_changed = StateChanged { state: 0 };
            netif_invoke_ext_callback(netif, LWIP_NSC_LINK_CHANGED, &args);
        }
    }
}

/// `tcpip_try_callback`'s view of `netif_poll`, whose argument is the netif.
unsafe extern "C" fn netif_poll_callback(ctx: *mut c_void) {
    // SAFETY: queued by netif_loop_output with a live netif.
    unsafe { netif_poll(ctx.cast()) };
}

/// Send an IP packet to be received on the same netif (loopif-like). The pbuf is copied
/// and added to an internal queue which is fed to `netif->input` by `netif_poll()`. In
/// multithreaded mode, the call to `netif_poll()` is queued to be done on the TCP/IP
/// thread.
///
/// Returns `ERR_OK` if the packet has been sent, `ERR_MEM` if the pbuf used to copy the
/// packet couldn't be allocated.
///
/// # Safety
///
/// `netif` and `p` are live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_loop_output(netif: *mut Netif, p: *mut Pbuf) -> ErrT {
    let mut schedule_poll = false;

    lwip_assert!("netif_loop_output: invalid netif", !netif.is_null());
    lwip_assert!("netif_loop_output: invalid pbuf", !p.is_null());

    // SAFETY: as the caller guarantees; the queue is changed under SYS_ARCH_PROTECT.
    unsafe {
        // Allocate a new pbuf.
        let r = pbuf_alloc(config::PBUF_LINK_LAYER as PbufLayer, (*p).tot_len, PBUF_RAM);
        if r.is_null() {
            return ERR_MEM;
        }
        let clen = pbuf_clen(r);
        // Check for overflow or too many pbuf on queue.
        let queued = i32::from((*netif).loop_cnt_current) + i32::from(clen);
        if queued < i32::from((*netif).loop_cnt_current)
            || queued > config::LWIP_LOOPBACK_MAX_PBUFS.min(0xFFFF) as i32
        {
            pbuf_free(r);
            return ERR_MEM;
        }
        (*netif).loop_cnt_current = (*netif).loop_cnt_current.wrapping_add(clen);

        // Copy the whole pbuf queue p into the single pbuf r.
        let err = pbuf_copy(r, p);
        if err != ERR_OK {
            pbuf_free(r);
            return err;
        }

        // Put the packet on a linked list which gets emptied through calling
        // netif_poll().

        // Let last point to the last pbuf in chain r.
        let mut last = r;
        while let Some(n) = (*last).next {
            last = n.as_ptr();
        }

        locked(|| {
            if (*netif).loop_first.is_some() {
                lwip_assert!(
                    "if first != NULL, last must also be != NULL",
                    (*netif).loop_last.is_some()
                );
                let loop_last = (*netif).loop_last.map_or(ptr::null_mut(), NonNull::as_ptr);
                (*loop_last).next = NonNull::new(r);
                (*netif).loop_last = NonNull::new(last);
                if (*netif).reschedule_poll != 0 {
                    schedule_poll = true;
                    (*netif).reschedule_poll = 0;
                }
            } else {
                (*netif).loop_first = NonNull::new(r);
                (*netif).loop_last = NonNull::new(last);
                schedule_poll = true;
            }
        });

        // For multithreading environment, schedule a call to netif_poll.
        if schedule_poll && tcpip_try_callback(Some(netif_poll_callback), netif.cast()) != ERR_OK {
            locked(|| (*netif).reschedule_poll = 1);
        }
    }
    ERR_OK
}

unsafe extern "C" fn netif_loop_output_ipv4(
    netif: *mut Netif,
    p: *mut Pbuf,
    addr: *const Ip4Addr,
) -> ErrT {
    let _ = addr;
    // SAFETY: the netif's output function, called with a live netif and pbuf.
    unsafe { netif_loop_output(netif, p) }
}

unsafe extern "C" fn netif_loop_output_ipv6(
    netif: *mut Netif,
    p: *mut Pbuf,
    addr: *const Ip6Addr,
) -> ErrT {
    let _ = addr;
    // SAFETY: the netif's output function, called with a live netif and pbuf.
    unsafe { netif_loop_output(netif, p) }
}

/// Call `netif_poll()` in the main loop of your application. This is to prevent reentering
/// non-reentrant functions like `tcp_input()`. Packets passed to `netif_loop_output()` are
/// put on a list that is passed to `netif->input()` by `netif_poll()`.
///
/// # Safety
///
/// `netif` is live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_poll(netif: *mut Netif) {
    lwip_assert!("netif_poll: invalid netif", !netif.is_null());

    // SAFETY: as the caller guarantees; the queue is taken under SYS_ARCH_PROTECT.
    unsafe {
        // Get a packet from the list. With SYS_LIGHTWEIGHT_PROT=1, this is protected.
        while let Some(in_) = locked(|| {
            let first = (*netif).loop_first?;
            let in_ = first.as_ptr();
            let mut in_end = in_;
            let mut clen: u8 = 1;
            // Adjust the count.
            while (*in_end).len != (*in_end).tot_len {
                lwip_assert!(
                    "bogus pbuf: len != tot_len but next == NULL!",
                    (*in_end).next.is_some()
                );
                in_end = (*in_end).next.map_or(ptr::null_mut(), NonNull::as_ptr);
                clen = clen.wrapping_add(1);
            }
            // Adjust the count.
            lwip_assert!(
                "netif->loop_cnt_current underflow",
                i32::from((*netif).loop_cnt_current) - i32::from(clen)
                    < i32::from((*netif).loop_cnt_current)
            );
            (*netif).loop_cnt_current = (*netif).loop_cnt_current.wrapping_sub(clen.into());

            // 'in_end' now points to the last pbuf from 'in'.
            if Some(in_end) == (*netif).loop_last.map(NonNull::as_ptr) {
                // This was the last pbuf in the list.
                (*netif).loop_first = None;
                (*netif).loop_last = None;
            } else {
                // Pop the pbuf off the list.
                (*netif).loop_first = (*in_end).next;
                lwip_assert!(
                    "should not be null since first != last!",
                    (*netif).loop_first.is_some()
                );
            }
            // De-queue the pbuf from its successors on the 'loop_' list.
            (*in_end).next = None;
            Some(in_)
        }) {
            (*in_).if_idx = (*netif).index();

            // Loopback packets are always IP packets!
            if ip_input(in_, netif) != ERR_OK {
                pbuf_free(in_);
            }
        }
    }
}

/// Change an IPv6 address of a network interface.
///
/// # Safety
///
/// `netif` is live and `addr6` valid.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_ip6_addr_set(
    netif: *mut Netif,
    addr_idx: i8,
    addr6: *const Ip6Addr,
) {
    lwip_assert!("netif_ip6_addr_set: invalid netif", !netif.is_null());
    lwip_assert!("netif_ip6_addr_set: invalid addr6", !addr6.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        let a = (*addr6).addr;
        netif_ip6_addr_set_parts(netif, addr_idx, a[0], a[1], a[2], a[3]);
    }
}

/// Change an IPv6 address of a network interface (internal version taking 4 * u32_t).
///
/// # Safety
///
/// `netif` is live and `addr_idx` an address index.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_ip6_addr_set_parts(
    netif: *mut Netif,
    addr_idx: i8,
    i0: u32,
    i1: u32,
    i2: u32,
    i3: u32,
) {
    lwip_assert!("netif != NULL", !netif.is_null());
    lwip_assert!(
        "invalid index",
        (addr_idx as i32) < config::LWIP_IPV6_NUM_ADDRESSES as i32
    );
    let idx = addr_idx as usize;

    // SAFETY: as the caller guarantees.
    unsafe {
        let mut old_addr = IpAddr::v4(0);
        old_addr.copy_from_ip6((*netif).ip6_addr[idx].ip6());

        // Address is actually being changed?
        if old_addr.ip6().addr != [i0, i1, i2, i3] {
            let mut new_ipaddr = IpAddr::v4(0);
            new_ipaddr.copy_from_ip6(&Ip6Addr {
                addr: [i0, i1, i2, i3],
                zone: 0,
            });
            ip6_addr_assign_zone(new_ipaddr.ip6_mut(), (*netif).index());

            if (*netif).ip6_addr_state[idx] & IP6_ADDR_VALID != 0 {
                netif_do_ip_addr_changed(&(*netif).ip6_addr[idx], &new_ipaddr);
            }
            // @todo: remove/readd mib2 ip6 entries?

            (*netif).ip6_addr[idx].copy_from(&new_ipaddr);

            if (*netif).ip6_addr_state[idx] & IP6_ADDR_VALID != 0 {
                netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV6);
            }

            let mut args = empty_args();
            args.ipv6_set = Ipv6Set {
                addr_index: addr_idx,
                old_address: &old_addr,
            };
            netif_invoke_ext_callback(netif, LWIP_NSC_IPV6_SET, &args);
        }
    }
}

/// Change the state of an IPv6 address of a network interface (INVALID, TEMPTATIVE,
/// PREFERRED, DEPRECATED, where TEMPTATIVE includes the number of checks done, see
/// ip6_addr.h).
///
/// # Safety
///
/// `netif` is live and `addr_idx` an address index.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_ip6_addr_set_state(netif: *mut Netif, addr_idx: i8, state: u8) {
    lwip_assert!("netif != NULL", !netif.is_null());
    lwip_assert!(
        "invalid index",
        (addr_idx as i32) < config::LWIP_IPV6_NUM_ADDRESSES as i32
    );
    let idx = addr_idx as usize;

    // SAFETY: as the caller guarantees.
    unsafe {
        let old_state = (*netif).ip6_addr_state[idx];
        // State is actually being changed?
        if old_state != state {
            let old_valid = old_state & IP6_ADDR_VALID;
            let new_valid = state & IP6_ADDR_VALID;

            if (*netif).flags & NETIF_FLAG_MLD6 != 0 {
                nd6_adjust_mld_membership(netif, addr_idx, state);
            }
            // Reflect changes in the ip6 addresses, if needed.
            if old_valid != 0 && new_valid == 0 {
                // Address about to be removed by setting invalid.
                netif_do_ip_addr_changed(&(*netif).ip6_addr[idx], ptr::null());
                // @todo: remove mib2 ip6 entries?
            }
            (*netif).ip6_addr_state[idx] = state;

            if old_valid == 0 && new_valid != 0 {
                // @todo: add mib2 ip6 entries?
                netif_issue_reports(netif, NETIF_REPORT_TYPE_IPV6);
            }

            let mut args = empty_args();
            args.ipv6_addr_state_changed = Ipv6AddrStateChanged {
                addr_index: addr_idx,
                old_state,
                address: &(*netif).ip6_addr[idx],
            };
            netif_invoke_ext_callback(netif, LWIP_NSC_IPV6_ADDR_STATE_CHANGED, &args);
        }
    }
}

/// Checks if a specific local address is present on the netif and returns its index.
/// Depending on its state, it may or may not be assigned to the interface (as per RFC
/// terminology).
///
/// The given address may or may not be zoned (i.e., have a zone index other than
/// IP6_NO_ZONE). If the address is zoned, it must have the correct zone for the given
/// netif, or no match will be found.
///
/// Returns >= 0: address found, this is its index; -1: address not found on this netif.
///
/// # Safety
///
/// `netif` is live and `ip6addr` valid.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_get_ip6_addr_match(
    netif: *mut Netif,
    ip6addr: *const Ip6Addr,
) -> i8 {
    lwip_assert!("netif_get_ip6_addr_match: invalid netif", !netif.is_null());
    lwip_assert!(
        "netif_get_ip6_addr_match: invalid ip6addr",
        !ip6addr.is_null()
    );

    // SAFETY: as the caller guarantees.
    unsafe {
        let ip6addr = &*ip6addr;
        if ip6addr.zone != 0 && ip6addr.zone != (*netif).index() {
            return -1; // wrong zone, no match
        }
        for i in 0..config::LWIP_IPV6_NUM_ADDRESSES {
            if (*netif).ip6_addr_state[i] != IP6_ADDR_INVALID
                && (*netif).ip6_addr[i].ip6().zoneless_eq(ip6addr)
            {
                return i as i8;
            }
        }
    }
    -1
}

/// Create a link-local IPv6 address on a netif (stored in slot 0).
///
/// `from_mac_48bit`: if 1, the interface ID is derived from the 48-bit MAC address
/// (EUI-64); if 0, it is copied from the (up to 8-byte) hardware address.
///
/// # Safety
///
/// `netif` is live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_create_ip6_linklocal_address(netif: *mut Netif, from_mac_48bit: u8) {
    lwip_assert!(
        "netif_create_ip6_linklocal_address: invalid netif",
        !netif.is_null()
    );

    // SAFETY: as the caller guarantees.
    unsafe {
        let hw = (*netif).hwaddr;
        let hwaddr_len = usize::from((*netif).hwaddr_len);
        let addr = &mut (*netif).ip6_addr[0].ip6_mut().addr;
        // Link-local prefix.
        addr[0] = 0xfe80_0000_u32.to_be();
        addr[1] = 0;

        // Generate interface ID.
        if from_mac_48bit != 0 {
            // Assume hwaddr is a 48-bit IEEE 802 MAC. Convert to EUI-64 address. Complement
            // Group bit.
            addr[2] = ((u32::from(hw[0] ^ 0x02) << 24)
                | (u32::from(hw[1]) << 16)
                | (u32::from(hw[2]) << 8)
                | 0xff)
                .to_be();
            addr[3] = ((0xfe_u32 << 24)
                | (u32::from(hw[3]) << 16)
                | (u32::from(hw[4]) << 8)
                | u32::from(hw[5]))
            .to_be();
        } else {
            // Use hwaddr directly as interface ID.
            addr[2] = 0;
            addr[3] = 0;

            let mut addr_index = 3;
            let mut i = 0;
            while i < 8 && i < hwaddr_len {
                if i == 4 {
                    addr_index -= 1;
                }
                addr[addr_index] |= (u32::from(hw[hwaddr_len - i - 1]) << (8 * (i & 0x03))).to_be();
                i += 1;
            }
        }

        // Set a link-local zone. Even though the zone is implied by the owning netif,
        // setting the zone anyway has two important conceptual advantages: 1) it avoids
        // the need for a ton of exceptions in internal code, allowing e.g. ip6_addr_eq()
        // to be used for local address comparisons; and 2) the user can safely pass
        // any address to external code, which is then fully zone-aware.
        let index = (*netif).index();
        ip6_addr_assign_zone((*netif).ip6_addr[0].ip6_mut(), index);

        // Set address state.
        // Will perform duplicate address detection (DAD).
        netif_ip6_addr_set_state(netif, 0, IP6_ADDR_TENTATIVE);
    }
}

/// This function allows for the easy addition of a new IPv6 address to an interface. It
/// takes care of finding an empty slot and then sets the address tentative (to make sure
/// that all the subsequent processing happens).
///
/// Returns `ERR_OK` if there was an address slot available, and it was set (its index in
/// `chosen_idx`, when not null); `ERR_VAL` otherwise.
///
/// # Safety
///
/// `netif` is live, `ip6addr` valid, and `chosen_idx` null or writable.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_add_ip6_address(
    netif: *mut Netif,
    ip6addr: *const Ip6Addr,
    chosen_idx: *mut i8,
) -> ErrT {
    lwip_assert!("netif_add_ip6_address: invalid netif", !netif.is_null());
    lwip_assert!("netif_add_ip6_address: invalid ip6addr", !ip6addr.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        let i = netif_get_ip6_addr_match(netif, ip6addr);
        if i >= 0 {
            // Address already added.
            if !chosen_idx.is_null() {
                *chosen_idx = i;
            }
            return ERR_OK;
        }

        // Find a free slot. The first one is reserved for link-local addresses.
        let first = if (*ip6addr).is_link_local() { 0 } else { 1 };
        for i in first..config::LWIP_IPV6_NUM_ADDRESSES {
            if (*netif).ip6_addr_state[i] == IP6_ADDR_INVALID {
                (*netif).ip6_addr[i].copy_from_ip6(&*ip6addr);
                let index = (*netif).index();
                ip6_addr_assign_zone((*netif).ip6_addr[i].ip6_mut(), index);
                netif_ip6_addr_set_state(netif, i as i8, IP6_ADDR_TENTATIVE);
                if !chosen_idx.is_null() {
                    *chosen_idx = i as i8;
                }
                return ERR_OK;
            }
        }

        if !chosen_idx.is_null() {
            *chosen_idx = -1;
        }
    }
    ERR_VAL
}

/// Dummy IPv6 output function for netifs not supporting IPv6.
unsafe extern "C" fn netif_null_output_ip6(
    netif: *mut Netif,
    p: *mut Pbuf,
    ipaddr: *const Ip6Addr,
) -> ErrT {
    let _ = (netif, p, ipaddr);
    ERR_IF
}

/// Dummy IPv4 output function for netifs not supporting IPv4.
unsafe extern "C" fn netif_null_output_ip4(
    netif: *mut Netif,
    p: *mut Pbuf,
    ipaddr: *const Ip4Addr,
) -> ErrT {
    let _ = (netif, p, ipaddr);
    ERR_IF
}

/// Return the interface index for the netif with name or `NETIF_NO_INDEX` if not found.
///
/// # Safety
///
/// `name` is null or a NUL-terminated string.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_name_to_index(name: *const c_char) -> u8 {
    // SAFETY: forwarded from the caller.
    let netif = unsafe { netif_find(name) };
    if netif.is_null() {
        return NETIF_NO_INDEX;
    }
    // SAFETY: a netif on the list.
    unsafe { (*netif).index() }
}

/// Return the interface name for the netif matching index or NULL if not found.
///
/// `name` is a char buffer of at least NETIF_NAMESIZE bytes.
///
/// # Safety
///
/// `name` is writable for `NETIF_NAMESIZE` bytes.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_index_to_name(idx: u8, name: *mut c_char) -> *mut c_char {
    let netif = netif_get_by_index(idx);

    if netif.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: a netif on the list, and a buffer of NETIF_NAMESIZE bytes.
    unsafe {
        *name = (*netif).name[0];
        *name.add(1) = (*netif).name[1];
        lwip_itoa(
            name.add(2),
            config::NETIF_NAMESIZE - 2,
            c_int::from(idx) - 1,
        );
    }
    name
}

/// Return the interface for the netif index.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn netif_get_by_index(idx: u8) -> *mut Netif {
    if idx != NETIF_NO_INDEX {
        let mut netif = netif_list.get();
        while !netif.is_null() {
            // SAFETY: netifs on the list are live.
            unsafe {
                if idx == (*netif).index() {
                    return netif; // found!
                }
                netif = next(netif);
            }
        }
    }
    ptr::null_mut()
}

/// Find a network interface by searching for its name.
///
/// The name is of the form "et0", where the first two letters are the "name" field in
/// the netif structure, and the digit is in the num field in the same structure.
///
/// # Safety
///
/// `name` is null or a NUL-terminated string.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_find(name: *const c_char) -> *mut Netif {
    if name.is_null() {
        return ptr::null_mut();
    }

    // SAFETY: NUL-terminated, per the caller; C reads name[2] too, so the string has at
    // least that many bytes or a NUL before.
    unsafe {
        let num = rivet_libc::atoi(name.add(2)) as u8;
        if num == 0 && *name.add(2) != b'0' as c_char {
            // Treat "et" as "et0" is not supported.
            return ptr::null_mut();
        }

        let mut netif = netif_list.get();
        while !netif.is_null() {
            if num == (*netif).num && *name == (*netif).name[0] && *name.add(1) == (*netif).name[1]
            {
                return netif;
            }
            netif = next(netif);
        }
    }
    ptr::null_mut()
}

/// Add extended netif events listener.
///
/// # Safety
///
/// `callback` is writable and stays live while registered.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_add_ext_callback(
    callback: *mut NetifExtCallback,
    fn_: NetifExtCallbackFn,
) {
    lwip_assert!("callback must be != NULL", !callback.is_null());
    lwip_assert!("fn must be != NULL", fn_.is_some());

    // SAFETY: as the caller guarantees.
    unsafe {
        (*callback).callback_fn = fn_;
        (*callback).next = EXT_CALLBACK.get();
    }
    EXT_CALLBACK.set(callback);
}

/// Remove extended netif events listener.
///
/// # Safety
///
/// `callback` is live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_remove_ext_callback(callback: *mut NetifExtCallback) {
    lwip_assert!("callback must be != NULL", !callback.is_null());

    let head = EXT_CALLBACK.get();
    if head.is_null() {
        return;
    }

    // SAFETY: registered callbacks stay live, per netif_add_ext_callback's contract.
    unsafe {
        if callback == head {
            EXT_CALLBACK.set((*head).next);
        } else {
            let mut last = head;
            let mut iter = (*head).next;
            while !iter.is_null() {
                if iter == callback {
                    lwip_assert!("last != NULL", !last.is_null());
                    (*last).next = (*callback).next;
                    break;
                }
                last = iter;
                iter = (*iter).next;
            }
        }
        (*callback).next = ptr::null_mut();
    }
}

/// Invoke extended netif status event.
///
/// # Safety
///
/// `netif` is live and `args` null or valid for the reason.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn netif_invoke_ext_callback(
    netif: *mut Netif,
    reason: NetifNscReason,
    args: *const NetifExtCallbackArgs,
) {
    lwip_assert!("netif must be != NULL", !netif.is_null());

    let mut callback = EXT_CALLBACK.get();
    // SAFETY: registered callbacks stay live; each may remove itself, so its successor
    // is read first.
    unsafe {
        while !callback.is_null() {
            // Allow callback to remove itself.
            let next = (*callback).next;
            if let Some(callback_fn) = (*callback).callback_fn {
                callback_fn(netif, reason, args);
            }
            callback = next;
        }
    }
}

#[cfg(test)]
mod tests;
