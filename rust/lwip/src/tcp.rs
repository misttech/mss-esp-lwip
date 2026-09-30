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

//! Transmission Control Protocol for IP, from `src/core/tcp.c`, as ESP-IDF configures
//! it: IPv4 and IPv6 with scopes, the callback API, the listen backlog, `SO_REUSE`,
//! keepalive with per-PCB settings, out-of-sequence queueing, ESP-IDF's ISN hook, its
//! RTO backoff (not doubled in SYN_RCVD), and its extra PCB reclaiming (`build.rs`
//! refuses the rest).
//!
//! This file contains common functions for the TCP implementation, such as functions
//! for manipulating the data structures and the TCP timer functions. TCP functions
//! related to input and output is found in tcp_in.c and tcp_out.c respectively.
//!
//! Transmission Control Protocol for IP. See also the raw API for TCP and the
//! netconn/socket APIs built on it.

#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::config;
use crate::global::Global;
use crate::links::*;
use crate::types::*;

const TCP_LOCAL_PORT_RANGE_START: u16 = 0xc000;
const TCP_LOCAL_PORT_RANGE_END: u16 = 0xffff;

/// `TCP_ENSURE_LOCAL_PORT_RANGE(port)`.
fn tcp_ensure_local_port_range(port: u32) -> u16 {
    ((port as u16) & !TCP_LOCAL_PORT_RANGE_START).wrapping_add(TCP_LOCAL_PORT_RANGE_START)
}

const TCP_MSS: u16 = config::TCP_MSS as u16;
const TCP_WND: TcpWnd = config::TCP_WND as TcpWnd;
const TCP_SND_BUF: TcpWnd = config::TCP_SND_BUF as TcpWnd;
const TCP_TTL: u8 = config::TCP_TTL as u8;
const TCP_MAXRTX: u8 = config::TCP_MAXRTX as u8;
const TCP_SYNMAXRTX: u8 = config::TCP_SYNMAXRTX as u8;
const TCP_PRIO_NORMAL: u8 = config::TCP_PRIO_NORMAL as u8;
const TCP_PRIO_MAX: u8 = config::TCP_PRIO_MAX as u8;
const TCP_WND_UPDATE_THRESHOLD: u32 = config::TCP_WND_UPDATE_THRESHOLD as u32;
const TCP_SLOW_INTERVAL: u32 = config::TCP_SLOW_INTERVAL as u32;
const TCP_FIN_WAIT_TIMEOUT: u32 = config::TCP_FIN_WAIT_TIMEOUT as u32;
const TCP_SYN_RCVD_TIMEOUT: u32 = config::TCP_SYN_RCVD_TIMEOUT as u32;
const TCP_OOSEQ_TIMEOUT: u32 = config::TCP_OOSEQ_TIMEOUT as u32;
const TCP_MSL: u32 = config::TCP_MSL as u32;
const TCP_KEEPIDLE_DEFAULT: u32 = config::TCP_KEEPIDLE_DEFAULT as u32;
const TCP_KEEPINTVL_DEFAULT: u32 = config::TCP_KEEPINTVL_DEFAULT as u32;
const TCP_KEEPCNT_DEFAULT: u32 = config::TCP_KEEPCNT_DEFAULT as u32;
const LWIP_TCP_RTO_TIME: u32 = config::LWIP_TCP_RTO_TIME as u32;

/// As initial send MSS, we use TCP_MSS but limit it to 536.
const INITIAL_MSS: u16 = if TCP_MSS > 536 { 536 } else { TCP_MSS };

/// `SOF_KEEPALIVE`: keep connections alive.
const SOF_KEEPALIVE: u8 = 0x08;

/// `NUM_TCP_PCB_LISTS` and `NUM_TCP_PCB_LISTS_NO_TIME_WAIT`.
const NUM_TCP_PCB_LISTS: usize = 4;
const NUM_TCP_PCB_LISTS_NO_TIME_WAIT: usize = 3;

/// `IP6_HLEN`.
const IP6_HLEN: u16 = 40;

static TCP_STATE_STR: [&core::ffi::CStr; 11] = [
    c"CLOSED",
    c"LISTEN",
    c"SYN_SENT",
    c"SYN_RCVD",
    c"ESTABLISHED",
    c"FIN_WAIT_1",
    c"FIN_WAIT_2",
    c"CLOSE_WAIT",
    c"CLOSING",
    c"LAST_ACK",
    c"TIME_WAIT",
];

/// Last local TCP port.
static TCP_PORT: Global<u16> = Global::new(TCP_LOCAL_PORT_RANGE_START);

/// Incremented every coarse grained timer shot (typically every 500 ms).
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub static tcp_ticks: Global<u32> = Global::new(0);

static TCP_BACKOFF: [u8; 13] = [1, 2, 3, 4, 5, 6, 7, 7, 7, 7, 7, 7, 7];
/// Times per slowtmr hits.
static TCP_PERSIST_BACKOFF: [u8; 7] = [3, 6, 12, 24, 48, 96, 120];

// The TCP PCB lists.

/// List of all TCP PCBs bound but not yet (connected || listening).
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub static tcp_bound_pcbs: Global<*mut TcpPcb> = Global::new(ptr::null_mut());
/// List of all TCP PCBs in LISTEN state (`union tcp_listen_pcbs_t`: both members are the
/// list's head).
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub static tcp_listen_pcbs: Global<*mut TcpPcb> = Global::new(ptr::null_mut());
/// List of all TCP PCBs that are in a state in which they accept or send data.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub static tcp_active_pcbs: Global<*mut TcpPcb> = Global::new(ptr::null_mut());
/// List of all TCP PCBs in TIME-WAIT state.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub static tcp_tw_pcbs: Global<*mut TcpPcb> = Global::new(ptr::null_mut());

/// `struct tcp_pcb **const tcp_pcb_lists[]`: the lists' heads.
#[repr(transparent)]
pub struct TcpPcbLists(pub [*mut *mut TcpPcb; NUM_TCP_PCB_LISTS]);

// SAFETY: the array is constant; the heads it points at are only used by the stack,
// which serializes access to them.
unsafe impl Sync for TcpPcbLists {}

/// An array with all (non-temporary) PCB lists, mainly used for smaller code size.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub static tcp_pcb_lists: TcpPcbLists = TcpPcbLists([
    tcp_listen_pcbs.as_ptr(),
    tcp_bound_pcbs.as_ptr(),
    tcp_active_pcbs.as_ptr(),
    tcp_tw_pcbs.as_ptr(),
]);

/// Set when a callback may have changed the active list.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub static tcp_active_pcbs_changed: Global<u8> = Global::new(0);

/// Timer counter to handle calling slow-timer from tcp_tmr().
static TCP_TIMER: Global<u8> = Global::new(0);
static TCP_TIMER_CTR: Global<u8> = Global::new(0);

/// `tcp_set_flags(pcb, set_flags)`.
///
/// # Safety
///
/// `pcb` is live.
unsafe fn tcp_set_flags(pcb: *mut TcpPcb, set_flags: TcpFlags) {
    // SAFETY: as the caller guarantees.
    unsafe { (*pcb).flags |= set_flags };
}

/// `tcp_clear_flags(pcb, clr_flags)`.
///
/// # Safety
///
/// `pcb` is live.
unsafe fn tcp_clear_flags(pcb: *mut TcpPcb, clr_flags: TcpFlags) {
    // SAFETY: as the caller guarantees.
    unsafe { (*pcb).flags &= !clr_flags };
}

/// `tcp_ack_now(pcb)`.
///
/// # Safety
///
/// `pcb` is live.
unsafe fn tcp_ack_now(pcb: *mut TcpPcb) {
    // SAFETY: as the caller guarantees.
    unsafe { tcp_set_flags(pcb, TF_ACK_NOW) };
}

/// `TCP_SEQ_LT(a, b)` and the comparisons built on it.
fn tcp_seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn tcp_seq_gt(a: u32, b: u32) -> bool {
    tcp_seq_lt(b, a)
}

fn tcp_seq_geq(a: u32, b: u32) -> bool {
    !tcp_seq_lt(a, b)
}

/// `TCP_REG(pcbs, npcb)`: put a PCB at the head of a list, and have the timer run.
///
/// # Safety
///
/// `pcbs` is a list head and `npcb` a live PCB on no list.
pub(crate) unsafe fn tcp_reg(pcbs: *mut *mut TcpPcb, npcb: *mut TcpPcb) {
    // SAFETY: as the caller guarantees.
    unsafe {
        (*npcb).next = *pcbs;
        *pcbs = npcb;
        tcp_timer_needed();
    }
}

/// `TCP_RMV(pcbs, npcb)`: take a PCB off a list.
///
/// # Safety
///
/// `pcbs` is a list head and `npcb` a live PCB.
pub(crate) unsafe fn tcp_rmv(pcbs: *mut *mut TcpPcb, npcb: *mut TcpPcb) {
    // SAFETY: as the caller guarantees; PCBs on the list are live.
    unsafe {
        if *pcbs == npcb {
            *pcbs = (**pcbs).next;
        } else {
            let mut tcp_tmp_pcb = *pcbs;
            while !tcp_tmp_pcb.is_null() {
                if (*tcp_tmp_pcb).next == npcb {
                    (*tcp_tmp_pcb).next = (*npcb).next;
                    break;
                }
                tcp_tmp_pcb = (*tcp_tmp_pcb).next;
            }
        }
        (*npcb).next = ptr::null_mut();
    }
}

/// `TCP_REG_ACTIVE(npcb)`.
///
/// # Safety
///
/// `npcb` is a live PCB on no list.
pub(crate) unsafe fn tcp_reg_active(npcb: *mut TcpPcb) {
    // SAFETY: as the caller guarantees.
    unsafe { tcp_reg(tcp_active_pcbs.as_ptr(), npcb) };
    tcp_active_pcbs_changed.set(1);
}

/// `TCP_RMV_ACTIVE(npcb)`.
///
/// # Safety
///
/// `npcb` is a live PCB.
pub(crate) unsafe fn tcp_rmv_active(npcb: *mut TcpPcb) {
    // SAFETY: as the caller guarantees.
    unsafe { tcp_rmv(tcp_active_pcbs.as_ptr(), npcb) };
    tcp_active_pcbs_changed.set(1);
}

/// `TCP_PCB_REMOVE_ACTIVE(pcb)`.
///
/// # Safety
///
/// `pcb` is a live PCB on the active list.
pub(crate) unsafe fn tcp_pcb_remove_active(pcb: *mut TcpPcb) {
    // SAFETY: as the caller guarantees.
    unsafe { tcp_pcb_remove(tcp_active_pcbs.as_ptr(), pcb) };
    tcp_active_pcbs_changed.set(1);
}

/// `TCP_EVENT_ERR(last_state, errf, arg, err)`.
///
/// # Safety
///
/// `errf` is null or the PCB's error callback, and `arg` its argument.
unsafe fn tcp_event_err(errf: TcpErrFn, arg: *mut c_void, err: ErrT) {
    if let Some(errf) = errf {
        // SAFETY: as the caller guarantees.
        unsafe { errf(arg, err) };
    }
}

/// `ip_route(src, dest)`.
///
/// # Safety
///
/// `src` and `dest` are valid.
unsafe fn ip_route(src: *const IpAddr, dest: *const IpAddr) -> *mut Netif {
    // SAFETY: as the caller guarantees.
    unsafe {
        if (*dest).is_v6() {
            ip6_route((*src).ip6(), (*dest).ip6())
        } else {
            ip4_route_src((*src).ip4(), (*dest).ip4())
        }
    }
}

/// `ip_netif_get_local_ip(netif, dest)`.
///
/// # Safety
///
/// `netif` is live and `dest` valid.
unsafe fn ip_netif_get_local_ip(netif: *mut Netif, dest: *const IpAddr) -> *const IpAddr {
    // SAFETY: as the caller guarantees.
    unsafe {
        if (*dest).is_v6() {
            ip6_select_source_address(netif, (*dest).ip6())
        } else {
            &(*netif).ip_addr
        }
    }
}

/// `ip6_addr_has_scope(addr, IP6_UNKNOWN)`: a link-local address, or an interface- or
/// link-local multicast address.
fn ip6_has_scope_unknown(addr: &Ip6Addr) -> bool {
    let a0 = addr.addr[0];
    a0 & 0xffc0_0000_u32.to_be() == 0xfe80_0000_u32.to_be()
        || a0 & 0xff8f_0000_u32.to_be() == 0xff01_0000_u32.to_be()
        || a0 & 0xff8f_0000_u32.to_be() == 0xff02_0000_u32.to_be()
}

/// `ip6_addr_lacks_zone(addr, IP6_UNICAST)`: a link-local address without a zone.
fn ip6_lacks_unicast_zone(addr: &Ip6Addr) -> bool {
    addr.zone == 0 && addr.is_link_local()
}

/// Initialize this module.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tcp_init() {
    // SAFETY: the port's random source takes nothing.
    TCP_PORT.set(tcp_ensure_local_port_range(unsafe { esp_random() }));
}

/// Free a tcp pcb.
///
/// # Safety
///
/// `pcb` is a live PCB from MEMP_TCP_PCB, not used afterwards.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_free(pcb: *mut TcpPcb) {
    // SAFETY: as the caller guarantees.
    unsafe {
        lwip_assert!("tcp_free: LISTEN", (*pcb).state != LISTEN);
        memp_free(config::MEMP_TCP_PCB, pcb.cast());
    }
}

/// Free a tcp listen pcb.
///
/// # Safety
///
/// `pcb` is a live listen PCB, not used afterwards.
unsafe fn tcp_free_listen(pcb: *mut TcpPcb) {
    // SAFETY: as the caller guarantees.
    unsafe {
        // As in tcp.c, the check is inverted: callers have already set the state.
        lwip_assert!("tcp_free_listen: !LISTEN", (*pcb).state != LISTEN);
        memp_free(config::MEMP_TCP_PCB_LISTEN, pcb.cast());
    }
}

/// Called periodically to dispatch TCP timers.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tcp_tmr() {
    // Call tcp_fasttmr() every 250 ms.
    tcp_fasttmr();

    TCP_TIMER.set(TCP_TIMER.get().wrapping_add(1));
    if TCP_TIMER.get() & 1 != 0 {
        // Call tcp_slowtmr() every 500 ms, i.e., every other timer tcp_tmr() is called.
        tcp_slowtmr();
    }
}

/// Called when a listen pcb is closed. Iterates one pcb list and removes the closed
/// listener pcb from pcb->listener if matching.
///
/// # Safety
///
/// `list` is a list of live PCBs.
unsafe fn tcp_remove_listener(list: *mut TcpPcb, lpcb: *mut TcpPcbListen) {
    lwip_assert!("tcp_remove_listener: invalid listener", !lpcb.is_null());

    let mut pcb = list;
    while !pcb.is_null() {
        // SAFETY: as the caller guarantees.
        unsafe {
            if (*pcb).listener == lpcb {
                (*pcb).listener = ptr::null_mut();
            }
            pcb = (*pcb).next;
        }
    }
}

/// Called when a listen pcb is closed. Iterates all pcb lists and removes the closed
/// listener pcb from pcb->listener if matching.
///
/// # Safety
///
/// `pcb` is a live listen PCB.
unsafe fn tcp_listen_closed(pcb: *mut TcpPcb) {
    lwip_assert!("pcb != NULL", !pcb.is_null());
    // SAFETY: as the caller guarantees; the lists hold live PCBs.
    unsafe {
        lwip_assert!("pcb->state == LISTEN", (*pcb).state == LISTEN);
        for &list in &tcp_pcb_lists.0[1..] {
            tcp_remove_listener(*list, pcb.cast());
        }
    }
}

/// Delay accepting a connection in respect to the listen backlog: the number of
/// outstanding connections is increased until `tcp_backlog_accepted()` is called.
///
/// ATTENTION: the caller is responsible for calling `tcp_backlog_accepted()` or else
/// the backlog feature will get out of sync!
///
/// # Safety
///
/// `pcb` is a live connection PCB.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_backlog_delayed(pcb: *mut TcpPcb) {
    lwip_assert!("pcb != NULL", !pcb.is_null());
    // SAFETY: as the caller guarantees; its listener is live.
    unsafe {
        if (*pcb).flags & TF_BACKLOGPEND == 0 && !(*pcb).listener.is_null() {
            let listener = (*pcb).listener;
            (*listener).accepts_pending = (*listener).accepts_pending.wrapping_add(1);
            lwip_assert!("accepts_pending != 0", (*listener).accepts_pending != 0);
            tcp_set_flags(pcb, TF_BACKLOGPEND);
        }
    }
}

/// A delayed-accept a connection is accepted (or closed/aborted): decreases the number
/// of outstanding connections after calling `tcp_backlog_delayed()`.
///
/// ATTENTION: the caller is responsible for calling `tcp_backlog_accepted()` or else
/// the backlog feature will get out of sync!
///
/// # Safety
///
/// `pcb` is a live connection PCB.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_backlog_accepted(pcb: *mut TcpPcb) {
    lwip_assert!("pcb != NULL", !pcb.is_null());
    // SAFETY: as the caller guarantees; its listener is live.
    unsafe {
        if (*pcb).flags & TF_BACKLOGPEND != 0 && !(*pcb).listener.is_null() {
            let listener = (*pcb).listener;
            lwip_assert!("accepts_pending != 0", (*listener).accepts_pending != 0);
            (*listener).accepts_pending -= 1;
            tcp_clear_flags(pcb, TF_BACKLOGPEND);
        }
    }
}

/// Closes the TX side of a connection held by the PCB. For `tcp_close()`, a RST is sent
/// if the application didn't receive all data (`tcp_recved()` not called for all data
/// passed to recv callback).
///
/// Listening pcbs are freed and may not be referenced any more. Connection pcbs are
/// freed if not yet connected and may not be referenced any more. If a connection is
/// established (at least SYN received or in a closing state), the connection is closed,
/// and put in a closing state. The pcb is then automatically freed in `tcp_slowtmr()`.
/// It is therefore unsafe to reference it.
///
/// Returns `ERR_OK` if connection has been closed, another `err_t` if closing failed
/// and pcb is not freed.
///
/// # Safety
///
/// `pcb` is live.
unsafe fn tcp_close_shutdown(pcb: *mut TcpPcb, rst_on_unacked_data: u8) -> ErrT {
    lwip_assert!("tcp_close_shutdown: invalid pcb", !pcb.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        if rst_on_unacked_data != 0
            && ((*pcb).state == ESTABLISHED || (*pcb).state == CLOSE_WAIT)
            && (!(*pcb).refused_data.is_null() || (*pcb).rcv_wnd != TCP_WND)
        {
            // Not all data received by application, send RST to tell the remote side
            // about this.
            lwip_assert!("pcb->flags & TF_RXCLOSED", (*pcb).flags & TF_RXCLOSED != 0);

            // Don't call tcp_abort here: we must not deallocate the pcb since that might
            // not be expected when calling tcp_close.
            tcp_rst(
                pcb,
                (*pcb).snd_nxt,
                (*pcb).rcv_nxt,
                &(*pcb).local_ip,
                &(*pcb).remote_ip,
                (*pcb).local_port,
                (*pcb).remote_port,
            );

            tcp_pcb_purge(pcb);
            tcp_rmv_active(pcb);
            // Deallocate the pcb since we already sent a RST for it.
            if tcp_input_pcb() == pcb {
                // Prevent using a deallocated pcb: free it from tcp_input later.
                tcp_trigger_input_pcb_close();
            } else {
                tcp_free(pcb);
            }
            return ERR_OK;
        }

        // - states which free the pcb are handled here,
        // - states which send FIN and change state are handled in
        //   tcp_close_shutdown_fin().
        match (*pcb).state {
            CLOSED => {
                // Closing a pcb in the CLOSED state might seem erroneous, however, it is
                // in this state once allocated and as yet unused and the user needs some
                // way to free it should the need arise. Calling tcp_close() with a pcb
                // that has already been closed, (i.e. twice) or for a pcb that has been
                // used and then entered the CLOSED state is erroneous, but this should
                // never happen as the pcb has in those cases been freed, and so any
                // remaining handles are bogus.
                if (*pcb).local_port != 0 {
                    tcp_rmv(tcp_bound_pcbs.as_ptr(), pcb);
                }
                tcp_free(pcb);
            }
            LISTEN => {
                tcp_listen_closed(pcb);
                tcp_pcb_remove(tcp_listen_pcbs.as_ptr(), pcb);
                tcp_free_listen(pcb);
            }
            SYN_SENT => {
                tcp_pcb_remove_active(pcb);
                tcp_free(pcb);
            }
            _ => return tcp_close_shutdown_fin(pcb),
        }
    }
    ERR_OK
}

/// Sends the FIN of a connection being closed and moves it to its closing state.
///
/// # Safety
///
/// `pcb` is live.
unsafe fn tcp_close_shutdown_fin(pcb: *mut TcpPcb) -> ErrT {
    lwip_assert!("pcb != NULL", !pcb.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        let err = match (*pcb).state {
            SYN_RCVD => {
                let err = tcp_send_fin(pcb);
                if err == ERR_OK {
                    tcp_backlog_accepted(pcb);
                    (*pcb).state = FIN_WAIT_1;
                }
                err
            }
            ESTABLISHED => {
                let err = tcp_send_fin(pcb);
                if err == ERR_OK {
                    (*pcb).state = FIN_WAIT_1;
                }
                err
            }
            CLOSE_WAIT => {
                let err = tcp_send_fin(pcb);
                if err == ERR_OK {
                    (*pcb).state = LAST_ACK;
                }
                err
            }
            // Has already been closed, do nothing.
            _ => return ERR_OK,
        };

        if err == ERR_OK {
            // To ensure all data has been sent when tcp_close returns, we have to make
            // sure tcp_output doesn't fail. Since we don't really have to ensure all
            // data has been sent when tcp_close returns (unsent data is sent from tcp
            // timer functions, also), we don't care for the return value of tcp_output
            // for now.
            tcp_output(pcb);
        } else if err == ERR_MEM {
            // Mark this pcb for closing. Closing is retried from tcp_tmr.
            tcp_set_flags(pcb, TF_CLOSEPEND);
            // We have to return ERR_OK from here to indicate to the callers that this
            // pcb should not be used any more as it will be freed soon via tcp_tmr.
            // This is OK here since sending FIN does not guarantee a time frime for
            // actually freeing the pcb, either (it is left in closure states for remote
            // ACK or timeout).
            return ERR_OK;
        }
        err
    }
}

/// Closes the connection held by the PCB.
///
/// Listening pcbs are freed and may not be referenced any more. Connection pcbs are
/// freed if not yet connected and may not be referenced any more. If a connection is
/// established (at least SYN received or in a closing state), the connection is closed,
/// and put in a closing state. The pcb is then automatically freed in `tcp_slowtmr()`.
/// It is therefore unsafe to reference it (unless an error is returned).
///
/// The function may return `ERR_MEM` if no memory was available for closing the
/// connection. If so, the application should wait and try again either by using the
/// acknowledgment callback or the polling functionality. If the close succeeds, the
/// function returns `ERR_OK`.
///
/// # Safety
///
/// `pcb` is null or live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_close(pcb: *mut TcpPcb) -> ErrT {
    // SAFETY: forwarded from the caller.
    unsafe { tcp_close_ext(pcb, 1) }
}

/// `tcp_close`, choosing whether unreceived data makes it send a RST.
///
/// # Safety
///
/// `pcb` is null or live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_close_ext(pcb: *mut TcpPcb, rst_on_unacked_data: u8) -> ErrT {
    // LWIP_ERROR("tcp_close: invalid pcb", pcb != NULL, return ERR_ARG);
    if pcb.is_null() {
        return ERR_ARG;
    }
    // SAFETY: as the caller guarantees.
    unsafe {
        if (*pcb).state != LISTEN {
            // Set a flag not to receive any more data...
            tcp_set_flags(pcb, TF_RXCLOSED);
        }
        // ... and close.
        tcp_close_shutdown(pcb, rst_on_unacked_data)
    }
}

/// Causes all or part of a full-duplex connection of this PCB to be shut down. This
/// doesn't deallocate the PCB unless shutting down both sides! Shutting down both sides
/// is the same as calling `tcp_close`, so if it succeeds (i.e. returns `ERR_OK`), the
/// PCB must not be referenced any more!
///
/// # Safety
///
/// `pcb` is null or live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_shutdown(pcb: *mut TcpPcb, shut_rx: c_int, shut_tx: c_int) -> ErrT {
    // LWIP_ERROR("tcp_shutdown: invalid pcb", pcb != NULL, return ERR_ARG);
    if pcb.is_null() {
        return ERR_ARG;
    }

    // SAFETY: as the caller guarantees.
    unsafe {
        if (*pcb).state == LISTEN {
            return ERR_CONN;
        }
        if shut_rx != 0 {
            // Shut down the receive side: set a flag not to receive any more data...
            tcp_set_flags(pcb, TF_RXCLOSED);
            if shut_tx != 0 {
                // Shutting down the tx AND rx side is the same as closing for the raw
                // API.
                return tcp_close_shutdown(pcb, 1);
            }
            // ... and free buffered data.
            if !(*pcb).refused_data.is_null() {
                pbuf_free((*pcb).refused_data);
                (*pcb).refused_data = ptr::null_mut();
            }
        }
        if shut_tx != 0 {
            // This can't happen twice since if it succeeds, the pcb's state is changed.
            // Only close in these states as the others directly deallocate the PCB.
            return match (*pcb).state {
                SYN_RCVD | ESTABLISHED | CLOSE_WAIT => tcp_close_shutdown(pcb, shut_rx as u8),
                // Not (yet?) connected, cannot shutdown the TX side as that would bring
                // us into CLOSED state, where the PCB is deallocated.
                _ => ERR_CONN,
            };
        }
    }
    ERR_OK
}

/// Abandons a connection and optionally sends a RST to the remote host. Deletes the
/// local protocol control block. This is done when a connection is killed because of
/// shortage of memory.
///
/// # Safety
///
/// `pcb` is null or live, and not used afterwards.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_abandon(pcb: *mut TcpPcb, reset: c_int) {
    // LWIP_ERROR("tcp_abandon: invalid pcb", pcb != NULL, return);
    if pcb.is_null() {
        return;
    }

    // SAFETY: as the caller guarantees.
    unsafe {
        // pcb->state LISTEN not allowed here.
        lwip_assert!(
            "don't call tcp_abort/tcp_abandon for listen-pcbs",
            (*pcb).state != LISTEN
        );
        // Figure out on which TCP PCB list we are, and remove us. If we are in an active
        // state, call the receive function associated with the PCB with a NULL
        // argument, and send an RST to the remote end.
        if (*pcb).state == TIME_WAIT {
            tcp_pcb_remove(tcp_tw_pcbs.as_ptr(), pcb);
            tcp_free(pcb);
        } else {
            let mut send_rst = 0;
            let mut local_port: u16 = 0;
            let seqno = (*pcb).snd_nxt;
            let ackno = (*pcb).rcv_nxt;
            let errf = (*pcb).errf;
            let errf_arg = (*pcb).callback_arg;
            if (*pcb).state == CLOSED {
                if (*pcb).local_port != 0 {
                    // Bound, not yet opened.
                    tcp_rmv(tcp_bound_pcbs.as_ptr(), pcb);
                }
            } else {
                send_rst = reset;
                local_port = (*pcb).local_port;
                tcp_pcb_remove_active(pcb);
            }
            if !(*pcb).unacked.is_null() {
                tcp_segs_free((*pcb).unacked);
            }
            if !(*pcb).unsent.is_null() {
                tcp_segs_free((*pcb).unsent);
            }
            if !(*pcb).ooseq.is_null() {
                tcp_segs_free((*pcb).ooseq);
            }
            tcp_backlog_accepted(pcb);
            if send_rst != 0 {
                tcp_rst(
                    pcb,
                    seqno,
                    ackno,
                    &(*pcb).local_ip,
                    &(*pcb).remote_ip,
                    local_port,
                    (*pcb).remote_port,
                );
            }
            tcp_free(pcb);
            tcp_event_err(errf, errf_arg, ERR_ABRT);
        }
    }
}

/// Aborts the connection by sending a RST (reset) segment to the remote host. The pcb
/// is deallocated. This function never fails.
///
/// ATTENTION: When calling this from one of the TCP callbacks, make sure you always
/// return `ERR_ABRT` (and never return `ERR_ABRT` otherwise or you will risk accessing
/// deallocated memory or memory leaks!
///
/// # Safety
///
/// `pcb` is null or live, and not used afterwards.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_abort(pcb: *mut TcpPcb) {
    // SAFETY: forwarded from the caller.
    unsafe { tcp_abandon(pcb, 1) };
}

/// Binds the connection to a local port number and IP address. If the IP address is not
/// given (i.e., ipaddr == IP_ANY_TYPE), the connection is bound to all local IP
/// addresses. If another connection is bound to the same port, the function will
/// return `ERR_USE`, otherwise `ERR_OK` is returned.
///
/// # Safety
///
/// `pcb` is null or live, and `ipaddr` null or valid.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_bind(pcb: *mut TcpPcb, ipaddr: *const IpAddr, mut port: u16) -> ErrT {
    // Don't propagate NULL pointer (IPv4 ANY) to subsequent functions.
    let mut ipaddr = if ipaddr.is_null() {
        ip_addr_any()
    } else {
        ipaddr
    };

    // LWIP_ERROR("tcp_bind: invalid pcb", pcb != NULL, return ERR_ARG);
    if pcb.is_null() {
        return ERR_ARG;
    }

    // SAFETY: as the caller guarantees; PCBs on the lists are live.
    unsafe {
        // LWIP_ERROR("tcp_bind: can only bind in state CLOSED", pcb->state == CLOSED, return ERR_VAL);
        if (*pcb).state != CLOSED {
            return ERR_VAL;
        }

        let mut max_pcb_list = NUM_TCP_PCB_LISTS;
        // Unless the REUSEADDR flag is set, we have to check the pcbs in TIME-WAIT
        // state, also. We do not dump TIME_WAIT pcb's; they can still be matched by
        // incoming packets using both local and remote IP addresses and ports to
        // distinguish.
        if (*pcb).so_options & SOF_REUSEADDR != 0 {
            max_pcb_list = NUM_TCP_PCB_LISTS_NO_TIME_WAIT;
        }

        // If the given IP address should have a zone but doesn't, assign one now. This
        // is legacy support: scope-aware callers should always provide properly zoned
        // source addresses. Do the zone selection before the address-in-use check
        // below; as such we have to make a temporary copy of the address.
        let mut zoned_ipaddr = IpAddr::v4(0);
        if (*ipaddr).is_v6() && ip6_lacks_unicast_zone((*ipaddr).ip6()) {
            zoned_ipaddr.copy_from(&*ipaddr);
            // ip6_addr_select_zone(dest, src).
            let selected_netif = ip6_route(zoned_ipaddr.ip6(), zoned_ipaddr.ip6());
            if !selected_netif.is_null() {
                let zone = if ip6_has_scope_unknown(zoned_ipaddr.ip6()) {
                    (*selected_netif).index()
                } else {
                    0
                };
                zoned_ipaddr.ip6_mut().zone = zone;
            }
            ipaddr = &zoned_ipaddr;
        }

        if port == 0 {
            port = tcp_new_port();
            if port == 0 {
                return ERR_BUF;
            }
        } else {
            // Check if the address already is in use (on all lists).
            for &list in &tcp_pcb_lists.0[..max_pcb_list] {
                let mut cpcb = *list;
                while !cpcb.is_null() {
                    // Omit checking for the same port if both pcbs have REUSEADDR set.
                    // For SO_REUSEADDR, the duplicate-check for a 5-tuple is done in
                    // tcp_connect.
                    if (*cpcb).local_port == port
                        && ((*pcb).so_options & SOF_REUSEADDR == 0
                            || (*cpcb).so_options & SOF_REUSEADDR == 0)
                        && (*ipaddr).is_v6() == (*cpcb).local_ip.is_v6()
                        && ((*cpcb).local_ip.is_any()
                            || (*ipaddr).is_any()
                            || (*cpcb).local_ip.eq_addr(&*ipaddr))
                    {
                        return ERR_USE;
                    }
                    cpcb = (*cpcb).next;
                }
            }
        }

        if !(*ipaddr).is_any() || (*ipaddr).type_ != (*pcb).local_ip.type_ {
            (*pcb).local_ip.copy_from(&*ipaddr);
        }
        (*pcb).local_port = port;
        tcp_reg(tcp_bound_pcbs.as_ptr(), pcb);
    }
    ERR_OK
}

/// Binds the connection to a netif and IP address. After calling this function, all
/// packets received via this PCB are guaranteed to have come in via the specified
/// netif, and all outgoing packets will go out via the specified netif.
///
/// # Safety
///
/// `pcb` is live and `netif` null or live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_bind_netif(pcb: *mut TcpPcb, netif: *const Netif) {
    // SAFETY: as the caller guarantees.
    unsafe {
        (*pcb).netif_idx = if netif.is_null() {
            NETIF_NO_INDEX
        } else {
            (*netif).index()
        };
    }
}

/// Default accept callback if no accept callback is specified by the user.
unsafe extern "C" fn tcp_accept_null(_arg: *mut c_void, pcb: *mut TcpPcb, _err: ErrT) -> ErrT {
    lwip_assert!("tcp_accept_null: invalid pcb", !pcb.is_null());

    // SAFETY: tcp_in.c hands the callback the new, live connection.
    unsafe { tcp_abort(pcb) };

    ERR_ABRT
}

/// Set the state of the connection to be LISTEN, which means that it is able to accept
/// incoming connections. The protocol control block is reallocated in order to consume
/// less memory. Setting the connection to LISTEN is an irreversible process. When an
/// incoming connection is accepted, the function specified with the `tcp_accept()`
/// function will be called. The pcb has to be bound to a local port with the
/// `tcp_bind()` function.
///
/// # Safety
///
/// `pcb` is null or live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_listen_with_backlog(pcb: *mut TcpPcb, backlog: u8) -> *mut TcpPcb {
    // SAFETY: forwarded from the caller.
    unsafe { tcp_listen_with_backlog_and_err(pcb, backlog, ptr::null_mut()) }
}

/// Set the state of the connection to be LISTEN, which means that it is able to accept
/// incoming connections. The protocol control block is reallocated in order to consume
/// less memory. Setting the connection to LISTEN is an irreversible process.
///
/// Returns the tcp_pcb which is now in the LISTEN state (the original is freed), or
/// null if it could not be; `err`, when not null, says why.
///
/// # Safety
///
/// `pcb` is null or live, and `err` null or writable.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_listen_with_backlog_and_err(
    pcb: *mut TcpPcb,
    backlog: u8,
    err: *mut ErrT,
) -> *mut TcpPcb {
    let mut lpcb: *mut TcpPcbListen = ptr::null_mut();

    // SAFETY: as the caller guarantees; a MEMP_TCP_PCB_LISTEN element holds a struct
    // tcp_pcb_listen.
    let res = unsafe {
        'done: {
            // LWIP_ERROR("tcp_listen_with_backlog_and_err: invalid pcb", pcb != NULL, res = ERR_ARG; goto done);
            if pcb.is_null() {
                break 'done ERR_ARG;
            }
            // LWIP_ERROR("...: pcb already connected", pcb->state == CLOSED, res = ERR_CLSD; goto done);
            if (*pcb).state != CLOSED {
                break 'done ERR_CLSD;
            }

            // Already listening? (Unreachable after the check above, as in tcp.c.)
            if (*pcb).state == LISTEN {
                lpcb = pcb.cast();
                break 'done ERR_ALREADY;
            }
            if (*pcb).so_options & SOF_REUSEADDR != 0 {
                // Since SOF_REUSEADDR allows reusing a local address before the pcb's
                // usage is declared (listen-/connection-pcb), we have to make sure now
                // that this port is only used once for every local IP.
                lpcb = tcp_listen_pcbs.get().cast();
                while !lpcb.is_null() {
                    if (*lpcb).local_port == (*pcb).local_port
                        && (*lpcb).local_ip.eq_addr(&(*pcb).local_ip)
                    {
                        // This address/port is already used.
                        lpcb = ptr::null_mut();
                        break 'done ERR_USE;
                    }
                    lpcb = (*lpcb).next;
                }
            }
            lpcb = memp_malloc(config::MEMP_TCP_PCB_LISTEN).cast();
            if lpcb.is_null() {
                break 'done ERR_MEM;
            }
            (*lpcb).callback_arg = (*pcb).callback_arg;
            (*lpcb).local_port = (*pcb).local_port;
            (*lpcb).state = LISTEN;
            (*lpcb).prio = (*pcb).prio;
            (*lpcb).so_options = (*pcb).so_options;
            (*lpcb).netif_idx = (*pcb).netif_idx;
            (*lpcb).ttl = (*pcb).ttl;
            (*lpcb).tos = (*pcb).tos;
            (*lpcb).remote_ip.type_ = (*pcb).local_ip.type_;
            (*lpcb).local_ip.copy_from(&(*pcb).local_ip);
            if (*pcb).local_port != 0 {
                tcp_rmv(tcp_bound_pcbs.as_ptr(), pcb);
            }
            tcp_free(pcb);
            (*lpcb).accept = Some(tcp_accept_null);
            (*lpcb).accepts_pending = 0;
            // tcp_backlog_set(lpcb, backlog).
            lwip_assert!(
                "pcb->state == LISTEN (called for wrong pcb?)",
                (*lpcb).state == LISTEN
            );
            (*lpcb).backlog = if backlog != 0 { backlog } else { 1 };
            tcp_reg(tcp_listen_pcbs.as_ptr(), lpcb.cast());
            ERR_OK
        }
    };
    if !err.is_null() {
        // SAFETY: as the caller guarantees.
        unsafe { *err = res };
    }
    lpcb.cast()
}

/// Update the state that tracks the available window space to advertise.
///
/// Returns how much extra window would be advertised if we sent an update now.
///
/// # Safety
///
/// `pcb` is live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_update_rcv_ann_wnd(pcb: *mut TcpPcb) -> u32 {
    lwip_assert!("tcp_update_rcv_ann_wnd: invalid pcb", !pcb.is_null());
    // SAFETY: as the caller guarantees.
    unsafe {
        let new_right_edge = (*pcb).rcv_nxt.wrapping_add(u32::from((*pcb).rcv_wnd));

        if tcp_seq_geq(
            new_right_edge,
            (*pcb)
                .rcv_ann_right_edge
                .wrapping_add(u32::from((TCP_WND / 2).min((*pcb).mss))),
        ) {
            // We can advertise more window.
            (*pcb).rcv_ann_wnd = (*pcb).rcv_wnd;
            new_right_edge.wrapping_sub((*pcb).rcv_ann_right_edge)
        } else {
            if tcp_seq_gt((*pcb).rcv_nxt, (*pcb).rcv_ann_right_edge) {
                // Can happen due to other end sending out of advertised window, but
                // within actual available (but not yet advertised) window.
                (*pcb).rcv_ann_wnd = 0;
            } else {
                // Keep the right edge of window constant.
                let new_rcv_ann_wnd = (*pcb).rcv_ann_right_edge.wrapping_sub((*pcb).rcv_nxt);
                lwip_assert!("new_rcv_ann_wnd <= 0xffff", new_rcv_ann_wnd <= 0xffff);
                (*pcb).rcv_ann_wnd = new_rcv_ann_wnd as TcpWnd;
            }
            0
        }
    }
}

/// This function should be called by the application when it has processed the data.
/// The purpose is to advertise a larger window when the data has been processed.
///
/// # Safety
///
/// `pcb` is null or live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_recved(pcb: *mut TcpPcb, len: u16) {
    // LWIP_ERROR("tcp_recved: invalid pcb", pcb != NULL, return);
    if pcb.is_null() {
        return;
    }

    // SAFETY: as the caller guarantees.
    unsafe {
        // pcb->state LISTEN not allowed here.
        lwip_assert!(
            "don't call tcp_recved for listen-pcbs",
            (*pcb).state != LISTEN
        );

        let rcv_wnd = (*pcb).rcv_wnd.wrapping_add(len);
        if rcv_wnd > TCP_WND || rcv_wnd < (*pcb).rcv_wnd {
            // Window got too big or tcpwnd_size_t overflow.
            (*pcb).rcv_wnd = TCP_WND;
        } else {
            (*pcb).rcv_wnd = rcv_wnd;
        }

        let wnd_inflation = tcp_update_rcv_ann_wnd(pcb);

        // If the change in the right edge of window is significant (default watermark
        // is TCP_WND/4), then send an explicit update now. Otherwise wait for a packet
        // to be sent in the normal course of events (or more window to be available
        // later).
        if wnd_inflation >= TCP_WND_UPDATE_THRESHOLD {
            tcp_ack_now(pcb);
            tcp_output(pcb);
        }
    }
}

/// Allocate a new local TCP port.
///
/// Returns a new (free) local TCP port number, or 0 if none is free.
fn tcp_new_port() -> u16 {
    let mut n: u16 = 0;

    'again: loop {
        TCP_PORT.set(TCP_PORT.get().wrapping_add(1));
        if TCP_PORT.get() == TCP_LOCAL_PORT_RANGE_END {
            TCP_PORT.set(TCP_LOCAL_PORT_RANGE_START);
        }
        // Check all PCB lists.
        for &list in &tcp_pcb_lists.0 {
            // SAFETY: the lists hold live PCBs.
            unsafe {
                let mut pcb = *list;
                while !pcb.is_null() {
                    if (*pcb).local_port == TCP_PORT.get() {
                        n += 1;
                        if n > TCP_LOCAL_PORT_RANGE_END - TCP_LOCAL_PORT_RANGE_START {
                            return 0;
                        }
                        continue 'again;
                    }
                    pcb = (*pcb).next;
                }
            }
        }
        return TCP_PORT.get();
    }
}

/// Connects to another host. The function given as the "connected" argument will be
/// called when the connection has been established. Sets up the pcb to connect to the
/// remote host and sends the initial SYN segment which opens the connection.
///
/// The `tcp_connect()` function returns immediately; it does not wait for the
/// connection to be properly setup. Instead, it will call the function specified as the
/// fourth argument (the "connected" argument) when the connection is established. If
/// the connection could not be properly established, either because the other host
/// refused the connection or because the other host didn't answer, the "err" callback
/// function of this pcb (registered with `tcp_err`, see below) will be called.
///
/// Returns `ERR_VAL` if invalid arguments are given, `ERR_OK` if connect request has
/// been sent, and other `err_t` values if connect request couldn't be sent.
///
/// # Safety
///
/// `pcb` is null or live, and `ipaddr` null or valid.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_connect(
    pcb: *mut TcpPcb,
    ipaddr: *const IpAddr,
    port: u16,
    connected: TcpConnectedFn,
) -> ErrT {
    // LWIP_ERROR("tcp_connect: invalid pcb", pcb != NULL, return ERR_ARG);
    // LWIP_ERROR("tcp_connect: invalid ipaddr", ipaddr != NULL, return ERR_ARG);
    if pcb.is_null() || ipaddr.is_null() {
        return ERR_ARG;
    }

    // SAFETY: as the caller guarantees; PCBs on the lists are live.
    unsafe {
        // LWIP_ERROR("tcp_connect: can only connect from state CLOSED", pcb->state == CLOSED, return ERR_ISCONN);
        if (*pcb).state != CLOSED {
            return ERR_ISCONN;
        }

        (*pcb).remote_ip.copy_from(&*ipaddr);
        (*pcb).remote_port = port;

        let netif = if (*pcb).netif_idx != NETIF_NO_INDEX {
            netif_get_by_index((*pcb).netif_idx)
        } else {
            // Check if we have a route to the remote host.
            ip_route(&(*pcb).local_ip, &(*pcb).remote_ip)
        };
        if netif.is_null() {
            // Don't even try to send a SYN packet if we have no route since that will
            // fail.
            return ERR_RTE;
        }

        // Check if local IP has been assigned to pcb, if not, get one.
        if (*pcb).local_ip.is_any() {
            let local_ip = ip_netif_get_local_ip(netif, ipaddr);
            if local_ip.is_null() {
                return ERR_RTE;
            }
            (*pcb).local_ip.copy_from(&*local_ip);
        }

        // If the given IP address should have a zone but doesn't, assign one now. Given
        // that we already have the target netif, this is easy and cheap.
        if (*pcb).remote_ip.is_v6() && ip6_lacks_unicast_zone((*pcb).remote_ip.ip6()) {
            // ip6_addr_assign_zone(addr, IP6_UNICAST, netif).
            let zone = if (*pcb).remote_ip.ip6().is_link_local() {
                (*netif).index()
            } else {
                0
            };
            (*pcb).remote_ip.ip6_mut().zone = zone;
        }

        let old_local_port = (*pcb).local_port;
        if (*pcb).local_port == 0 {
            (*pcb).local_port = tcp_new_port();
            if (*pcb).local_port == 0 {
                return ERR_BUF;
            }
        } else if (*pcb).so_options & SOF_REUSEADDR != 0 {
            // Since SOF_REUSEADDR allows reusing a local address, we have to make sure
            // now that the 5-tuple is unique. Don't check listen- and bound-PCBs, check
            // active- and TIME-WAIT PCBs.
            for &list in &tcp_pcb_lists.0[2..] {
                let mut cpcb = *list;
                while !cpcb.is_null() {
                    if (*cpcb).local_port == (*pcb).local_port
                        && (*cpcb).remote_port == port
                        && (*cpcb).local_ip.eq_addr(&(*pcb).local_ip)
                        && (*cpcb).remote_ip.eq_addr(&*ipaddr)
                    {
                        // Linux returns EISCONN here, but ERR_USE should be OK for us.
                        return ERR_USE;
                    }
                    cpcb = (*cpcb).next;
                }
            }
        }

        let iss = tcp_next_iss(pcb);
        (*pcb).rcv_nxt = 0;
        (*pcb).snd_nxt = iss;
        (*pcb).lastack = iss.wrapping_sub(1);
        (*pcb).snd_wl2 = iss.wrapping_sub(1);
        (*pcb).snd_lbb = iss.wrapping_sub(1);
        // Start with a window that does not need scaling. When window scaling is
        // enabled and used, the window is enlarged when both sides agree on scaling.
        (*pcb).rcv_wnd = TCP_WND;
        (*pcb).rcv_ann_wnd = TCP_WND;
        (*pcb).rcv_ann_right_edge = (*pcb).rcv_nxt;
        (*pcb).snd_wnd = TCP_WND;
        // As initial send MSS, we use TCP_MSS but limit it to 536. The send MSS is
        // updated when an MSS option is received.
        (*pcb).mss = INITIAL_MSS;
        (*pcb).mss = tcp_eff_send_mss_netif((*pcb).mss, netif, &(*pcb).remote_ip);
        (*pcb).cwnd = 1;
        (*pcb).connected = connected;

        // Send a SYN together with the MSS option.
        let ret = tcp_enqueue_flags(pcb, TCP_SYN);
        if ret == ERR_OK {
            // SYN segment was enqueued, changed the pcbs state now.
            (*pcb).state = SYN_SENT;
            if old_local_port != 0 {
                tcp_rmv(tcp_bound_pcbs.as_ptr(), pcb);
            }
            tcp_reg_active(pcb);

            tcp_output(pcb);
        }
        ret
    }
}

/// Called every 500 ms and implements the retransmission timer and the timer that
/// removes PCBs that have been in TIME-WAIT for enough time. It also increments various
/// timers such as the inactivity timer in each PCB.
///
/// Automatically called from `tcp_tmr()`.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tcp_slowtmr() {
    let mut err = ERR_OK;

    tcp_ticks.set(tcp_ticks.get().wrapping_add(1));
    TCP_TIMER_CTR.set(TCP_TIMER_CTR.get().wrapping_add(1));

    // SAFETY: the PCBs on the lists are live; callbacks that change the lists are
    // detected through tcp_active_pcbs_changed.
    unsafe {
        'tcp_slowtmr_start: loop {
            // Steps through all of the active PCBs.
            let mut prev: *mut TcpPcb = ptr::null_mut();
            let mut pcb = tcp_active_pcbs.get();
            while !pcb.is_null() {
                lwip_assert!(
                    "tcp_slowtmr: active pcb->state != CLOSED",
                    (*pcb).state != CLOSED
                );
                lwip_assert!(
                    "tcp_slowtmr: active pcb->state != LISTEN",
                    (*pcb).state != LISTEN
                );
                lwip_assert!(
                    "tcp_slowtmr: active pcb->state != TIME-WAIT",
                    (*pcb).state != TIME_WAIT
                );
                if (*pcb).last_timer == TCP_TIMER_CTR.get() {
                    // Skip this pcb, we have already processed it.
                    prev = pcb;
                    pcb = (*pcb).next;
                    continue;
                }
                (*pcb).last_timer = TCP_TIMER_CTR.get();

                let mut pcb_remove: u8 = 0;
                let mut pcb_reset: u8 = 0;

                if ((*pcb).state == SYN_SENT && (*pcb).nrtx >= TCP_SYNMAXRTX)
                    || (*pcb).nrtx >= TCP_MAXRTX
                {
                    // Max SYN retries, or max DATA retries, reached.
                    pcb_remove += 1;
                } else if (*pcb).persist_backoff > 0 {
                    lwip_assert!(
                        "tcp_slowtimr: persist ticking with in-flight data",
                        (*pcb).unacked.is_null()
                    );
                    lwip_assert!(
                        "tcp_slowtimr: persist ticking with empty send buffer",
                        !(*pcb).unsent.is_null()
                    );
                    if (*pcb).persist_probe >= TCP_MAXRTX {
                        pcb_remove += 1; // Max probes reached.
                    } else {
                        let backoff_cnt =
                            TCP_PERSIST_BACKOFF[usize::from((*pcb).persist_backoff - 1)];
                        if (*pcb).persist_cnt < backoff_cnt {
                            (*pcb).persist_cnt += 1;
                        }
                        if (*pcb).persist_cnt >= backoff_cnt {
                            let mut next_slot = true; // Increment timer to next slot.
                            // If snd_wnd is zero, send 1 byte probes.
                            if (*pcb).snd_wnd == 0 {
                                if tcp_zero_window_probe(pcb) != ERR_OK {
                                    next_slot = false; // Try probe again with current slot.
                                }
                            // snd_wnd not fully closed, split unsent head and fill window.
                            } else if tcp_split_unsent_seg(pcb, (*pcb).snd_wnd) == ERR_OK
                                && tcp_output(pcb) == ERR_OK
                            {
                                // Sending will cancel persist timer, else retry with
                                // current slot.
                                next_slot = false;
                            }
                            if next_slot {
                                (*pcb).persist_cnt = 0;
                                if usize::from((*pcb).persist_backoff) < TCP_PERSIST_BACKOFF.len() {
                                    (*pcb).persist_backoff += 1;
                                }
                            }
                        }
                    }
                } else {
                    // Increase the retransmission timer if it is running.
                    if (*pcb).rtime >= 0 && (*pcb).rtime < 0x7FFF {
                        (*pcb).rtime += 1;
                    }

                    if (*pcb).rtime >= (*pcb).rto {
                        // Time for a retransmission. If prepare phase fails but we have
                        // unsent data but no unacked data, still execute the backoff
                        // calculations below, as this means we somehow failed to send
                        // segment.
                        if tcp_rexmit_rto_prepare(pcb) == ERR_OK
                            || ((*pcb).unacked.is_null() && !(*pcb).unsent.is_null())
                        {
                            // Double retransmission time-out unless we are trying to
                            // connect to somebody (i.e., we are in SYN_SENT): ESP-IDF
                            // also leaves SYN_RCVD alone.
                            if (*pcb).state != SYN_SENT && (*pcb).state != SYN_RCVD {
                                let backoff_idx =
                                    usize::from((*pcb).nrtx).min(TCP_BACKOFF.len() - 1);
                                let calc_rto = ((i32::from((*pcb).sa) >> 3) + i32::from((*pcb).sv))
                                    << TCP_BACKOFF[backoff_idx];
                                (*pcb).rto = calc_rto.min(0x7FFF) as i16;
                            }

                            // Reset the retransmission timer.
                            (*pcb).rtime = 0;

                            // Reduce congestion window and ssthresh.
                            let eff_wnd = (*pcb).cwnd.min((*pcb).snd_wnd);
                            (*pcb).ssthresh = eff_wnd >> 1;
                            if (*pcb).ssthresh < ((*pcb).mss << 1) {
                                (*pcb).ssthresh = (*pcb).mss << 1;
                            }
                            (*pcb).cwnd = (*pcb).mss;
                            (*pcb).bytes_acked = 0;

                            // The following needs to be called AFTER cwnd is set to one
                            // mss - STJ.
                            tcp_rexmit_rto_commit(pcb);
                        }
                    }
                }
                // Check if this PCB has stayed too long in FIN-WAIT-2. If this PCB is in
                // FIN_WAIT_2 because of SHUT_WR don't let it time out.
                // PCB was fully closed (either through close() or SHUT_RDWR): normal
                // FIN-WAIT timeout handling.
                if (*pcb).state == FIN_WAIT_2
                    && (*pcb).flags & TF_RXCLOSED != 0
                    && tcp_ticks.get().wrapping_sub((*pcb).tmr)
                        > TCP_FIN_WAIT_TIMEOUT / TCP_SLOW_INTERVAL
                {
                    pcb_remove += 1;
                }

                // Check if KEEPALIVE should be sent.
                if (*pcb).so_options & SOF_KEEPALIVE != 0
                    && ((*pcb).state == ESTABLISHED || (*pcb).state == CLOSE_WAIT)
                {
                    let idle = tcp_ticks.get().wrapping_sub((*pcb).tmr);
                    let keep_dur = (*pcb).keep_cnt.wrapping_mul((*pcb).keep_intvl);
                    if idle > (*pcb).keep_idle.wrapping_add(keep_dur) / TCP_SLOW_INTERVAL {
                        pcb_remove += 1;
                        pcb_reset += 1;
                    } else if idle
                        > (*pcb).keep_idle.wrapping_add(
                            u32::from((*pcb).keep_cnt_sent).wrapping_mul((*pcb).keep_intvl),
                        ) / TCP_SLOW_INTERVAL
                    {
                        err = tcp_keepalive(pcb);
                        if err == ERR_OK {
                            (*pcb).keep_cnt_sent = (*pcb).keep_cnt_sent.wrapping_add(1);
                        }
                    }
                }

                // If this PCB has queued out of sequence data, but has been inactive for
                // too long, will drop the data (it will eventually be retransmitted).
                if !(*pcb).ooseq.is_null()
                    && tcp_ticks.get().wrapping_sub((*pcb).tmr)
                        >= ((*pcb).rto as u32).wrapping_mul(TCP_OOSEQ_TIMEOUT)
                {
                    tcp_free_ooseq(pcb);
                }

                // Check if this PCB has stayed too long in SYN-RCVD.
                if (*pcb).state == SYN_RCVD
                    && tcp_ticks.get().wrapping_sub((*pcb).tmr)
                        > TCP_SYN_RCVD_TIMEOUT / TCP_SLOW_INTERVAL
                {
                    pcb_remove += 1;
                }

                // Check if this PCB has stayed too long in LAST-ACK.
                if (*pcb).state == LAST_ACK
                    && tcp_ticks.get().wrapping_sub((*pcb).tmr) > 2 * TCP_MSL / TCP_SLOW_INTERVAL
                {
                    pcb_remove += 1;
                }

                // If the PCB should be removed, do it.
                if pcb_remove != 0 {
                    let err_fn = (*pcb).errf;
                    tcp_pcb_purge(pcb);
                    // Remove PCB from tcp_active_pcbs list.
                    if !prev.is_null() {
                        lwip_assert!(
                            "tcp_slowtmr: middle tcp != tcp_active_pcbs",
                            pcb != tcp_active_pcbs.get()
                        );
                        (*prev).next = (*pcb).next;
                    } else {
                        // This PCB was the first.
                        lwip_assert!(
                            "tcp_slowtmr: first pcb == tcp_active_pcbs",
                            tcp_active_pcbs.get() == pcb
                        );
                        tcp_active_pcbs.set((*pcb).next);
                    }

                    if pcb_reset != 0 {
                        tcp_rst(
                            pcb,
                            (*pcb).snd_nxt,
                            (*pcb).rcv_nxt,
                            &(*pcb).local_ip,
                            &(*pcb).remote_ip,
                            (*pcb).local_port,
                            (*pcb).remote_port,
                        );
                    }

                    let err_arg = (*pcb).callback_arg;
                    let pcb2 = pcb;
                    pcb = (*pcb).next;
                    tcp_free(pcb2);

                    tcp_active_pcbs_changed.set(0);
                    tcp_event_err(err_fn, err_arg, ERR_ABRT);
                    if tcp_active_pcbs_changed.get() != 0 {
                        continue 'tcp_slowtmr_start;
                    }
                } else {
                    // Get the 'next' element now and work with 'prev' below (in case of
                    // abort).
                    prev = pcb;
                    pcb = (*pcb).next;

                    // We check if we should poll the connection.
                    (*prev).polltmr = (*prev).polltmr.wrapping_add(1);
                    if (*prev).polltmr >= (*prev).pollinterval {
                        (*prev).polltmr = 0;
                        tcp_active_pcbs_changed.set(0);
                        // TCP_EVENT_POLL(prev, err).
                        err = match (*prev).poll {
                            Some(poll) => poll((*prev).callback_arg, prev),
                            None => ERR_OK,
                        };
                        if tcp_active_pcbs_changed.get() != 0 {
                            continue 'tcp_slowtmr_start;
                        }
                        // If err == ERR_ABRT, 'prev' is already deallocated.
                        if err == ERR_OK {
                            tcp_output(prev);
                        }
                    }
                }
            }
            break;
        }

        // Steps through all of the TIME-WAIT PCBs.
        let mut prev: *mut TcpPcb = ptr::null_mut();
        let mut pcb = tcp_tw_pcbs.get();
        while !pcb.is_null() {
            lwip_assert!(
                "tcp_slowtmr: TIME-WAIT pcb->state == TIME-WAIT",
                (*pcb).state == TIME_WAIT
            );

            // Check if this PCB has stayed long enough in TIME-WAIT.
            if tcp_ticks.get().wrapping_sub((*pcb).tmr) > 2 * TCP_MSL / TCP_SLOW_INTERVAL {
                // If the PCB should be removed, do it.
                tcp_pcb_purge(pcb);
                // Remove PCB from tcp_tw_pcbs list.
                if !prev.is_null() {
                    lwip_assert!(
                        "tcp_slowtmr: middle tcp != tcp_tw_pcbs",
                        pcb != tcp_tw_pcbs.get()
                    );
                    (*prev).next = (*pcb).next;
                } else {
                    // This PCB was the first.
                    lwip_assert!(
                        "tcp_slowtmr: first pcb == tcp_tw_pcbs",
                        tcp_tw_pcbs.get() == pcb
                    );
                    tcp_tw_pcbs.set((*pcb).next);
                }
                let pcb2 = pcb;
                pcb = (*pcb).next;
                tcp_free(pcb2);
            } else {
                prev = pcb;
                pcb = (*pcb).next;
            }
        }
    }
    let _ = err;
}

/// Is called every TCP_FAST_INTERVAL (250 ms) and process data previously "refused" by
/// upper layer (application) and sends delayed ACKs or pending FINs.
///
/// Automatically called from `tcp_tmr()`.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tcp_fasttmr() {
    TCP_TIMER_CTR.set(TCP_TIMER_CTR.get().wrapping_add(1));

    // SAFETY: the PCBs on the list are live; callbacks that change the list are
    // detected through tcp_active_pcbs_changed.
    unsafe {
        'tcp_fasttmr_start: loop {
            let mut pcb = tcp_active_pcbs.get();

            while !pcb.is_null() {
                if (*pcb).last_timer != TCP_TIMER_CTR.get() {
                    (*pcb).last_timer = TCP_TIMER_CTR.get();
                    // Send delayed ACKs.
                    if (*pcb).flags & TF_ACK_DELAY != 0 {
                        tcp_ack_now(pcb);
                        tcp_output(pcb);
                        tcp_clear_flags(pcb, TF_ACK_DELAY | TF_ACK_NOW);
                    }
                    // Send pending FIN.
                    if (*pcb).flags & TF_CLOSEPEND != 0 {
                        tcp_clear_flags(pcb, TF_CLOSEPEND);
                        tcp_close_shutdown_fin(pcb);
                    }

                    let next = (*pcb).next;

                    // If there is data which was previously "refused" by upper layer.
                    if !(*pcb).refused_data.is_null() {
                        tcp_active_pcbs_changed.set(0);
                        tcp_process_refused_data(pcb);
                        if tcp_active_pcbs_changed.get() != 0 {
                            // Application callback has changed the pcb list: restart the
                            // loop.
                            continue 'tcp_fasttmr_start;
                        }
                    }
                    pcb = next;
                } else {
                    pcb = (*pcb).next;
                }
            }
            break;
        }
    }
}

/// Call `tcp_output` for all active pcbs that have TF_NAGLEMEMERR set.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tcp_txnow() {
    let mut pcb = tcp_active_pcbs.get();
    while !pcb.is_null() {
        // SAFETY: the PCBs on the list are live.
        unsafe {
            if (*pcb).flags & TF_NAGLEMEMERR != 0 {
                tcp_output(pcb);
            }
            pcb = (*pcb).next;
        }
    }
}

/// Pass pcb->refused_data to the recv callback.
///
/// # Safety
///
/// `pcb` is null or live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_process_refused_data(pcb: *mut TcpPcb) -> ErrT {
    // LWIP_ERROR("tcp_process_refused_data: invalid pcb", pcb != NULL, return ERR_ARG);
    if pcb.is_null() {
        return ERR_ARG;
    }

    // SAFETY: as the caller guarantees; the refused data is a live pbuf the PCB owns.
    unsafe {
        let refused_flags = (*(*pcb).refused_data).flags;
        // Set pcb->refused_data to NULL in case the callback frees it and then closes
        // the pcb.
        let refused_data = (*pcb).refused_data;
        (*pcb).refused_data = ptr::null_mut();
        // Notify again application with data previously received.
        let mut err = tcp_event_recv(pcb, refused_data, ERR_OK);
        if err == ERR_OK {
            // Did refused_data include a FIN?
            if refused_flags & PBUF_FLAG_TCP_FIN != 0 {
                // Correct rcv_wnd as the application won't call tcp_recved() for the
                // FIN's seqno.
                if (*pcb).rcv_wnd != TCP_WND {
                    (*pcb).rcv_wnd += 1;
                }
                err = tcp_event_closed(pcb);
                if err == ERR_ABRT {
                    return ERR_ABRT;
                }
            }
        } else if err == ERR_ABRT {
            // If err == ERR_ABRT, 'pcb' is already deallocated. Drop incoming packets
            // because pcb is "full" (only if the incoming segment contains data).
            return ERR_ABRT;
        } else {
            // Data is still refused, pbuf is still valid (go on for ACK-only packets).
            (*pcb).refused_data = refused_data;
            return ERR_INPROGRESS;
        }
    }
    ERR_OK
}

/// `TCP_EVENT_RECV(pcb, p, err, ret)`.
///
/// # Safety
///
/// `pcb` is live and `p` null or a pbuf the callback takes.
pub(crate) unsafe fn tcp_event_recv(pcb: *mut TcpPcb, p: *mut Pbuf, err: ErrT) -> ErrT {
    // SAFETY: as the caller guarantees.
    unsafe {
        match (*pcb).recv {
            Some(recv) => recv((*pcb).callback_arg, pcb, p, err),
            None => tcp_recv_null(ptr::null_mut(), pcb, p, err),
        }
    }
}

/// `TCP_EVENT_CLOSED(pcb, ret)`.
///
/// # Safety
///
/// `pcb` is live.
pub(crate) unsafe fn tcp_event_closed(pcb: *mut TcpPcb) -> ErrT {
    // SAFETY: as the caller guarantees.
    unsafe {
        match (*pcb).recv {
            Some(recv) => recv((*pcb).callback_arg, pcb, ptr::null_mut(), ERR_OK),
            None => ERR_OK,
        }
    }
}

/// Deallocates a list of TCP segments (tcp_seg structures).
///
/// # Safety
///
/// `seg` is null or a list of live segments, not used afterwards.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_segs_free(mut seg: *mut TcpSeg) {
    while !seg.is_null() {
        // SAFETY: as the caller guarantees.
        unsafe {
            let next = (*seg).next;
            tcp_seg_free(seg);
            seg = next;
        }
    }
}

/// Frees a TCP segment (tcp_seg structure).
///
/// # Safety
///
/// `seg` is null or a live segment, not used afterwards.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_seg_free(seg: *mut TcpSeg) {
    if !seg.is_null() {
        // SAFETY: as the caller guarantees.
        unsafe {
            if !(*seg).p.is_null() {
                pbuf_free((*seg).p);
            }
            memp_free(config::MEMP_TCP_SEG, seg.cast());
        }
    }
}

/// Sets the priority of a connection.
///
/// # Safety
///
/// `pcb` is null or live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_setprio(pcb: *mut TcpPcb, prio: u8) {
    // LWIP_ERROR("tcp_setprio: invalid pcb", pcb != NULL, return);
    if !pcb.is_null() {
        // SAFETY: as the caller guarantees.
        unsafe { (*pcb).prio = prio };
    }
}

/// Returns a copy of the given TCP segment. The pbuf and data are not copied, only the
/// pointers.
///
/// # Safety
///
/// `seg` is a live segment.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_seg_copy(seg: *mut TcpSeg) -> *mut TcpSeg {
    lwip_assert!("tcp_seg_copy: invalid seg", !seg.is_null());

    // SAFETY: as the caller guarantees; a MEMP_TCP_SEG element holds a struct tcp_seg.
    unsafe {
        let cseg = memp_malloc(config::MEMP_TCP_SEG).cast::<TcpSeg>();
        if cseg.is_null() {
            return ptr::null_mut();
        }
        ptr::copy_nonoverlapping(seg, cseg, 1);
        pbuf_ref((*cseg).p);
        cseg
    }
}

/// Default receive callback that is called if the user didn't register a recv
/// callback for the pcb.
///
/// # Safety
///
/// `pcb` is null or live, and `p` null or a pbuf this takes.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_recv_null(
    _arg: *mut c_void,
    pcb: *mut TcpPcb,
    p: *mut Pbuf,
    err: ErrT,
) -> ErrT {
    // LWIP_ERROR("tcp_recv_null: invalid pcb", pcb != NULL, return ERR_ARG);
    if pcb.is_null() {
        return ERR_ARG;
    }

    // SAFETY: as the caller guarantees.
    unsafe {
        if !p.is_null() {
            tcp_recved(pcb, (*p).tot_len);
            pbuf_free(p);
        } else if err == ERR_OK {
            return tcp_close(pcb);
        }
    }
    ERR_OK
}

/// Kills the oldest active connection that has the same or lower priority than `prio`.
fn tcp_kill_prio(prio: u8) {
    let mut mprio = TCP_PRIO_MAX.min(prio);

    // We want to kill connections with a lower prio, so bail out if supplied prio is 0
    // - there can never be a lower prio.
    if mprio == 0 {
        return;
    }

    // We only want kill connections with a lower prio, so decrement prio by one and
    // start searching for oldest connection with same or lower priority than mprio. We
    // want to find the connections with the lowest possible prio, and among these the
    // one with the longest inactivity time.
    mprio -= 1;

    let mut inactivity: u32 = 0;
    let mut inactive: *mut TcpPcb = ptr::null_mut();
    let mut pcb = tcp_active_pcbs.get();
    // SAFETY: the PCBs on the list are live.
    unsafe {
        while !pcb.is_null() {
            // Lower prio is always a kill candidate; longer inactivity is also a kill
            // candidate.
            if (*pcb).prio < mprio
                || ((*pcb).prio == mprio && tcp_ticks.get().wrapping_sub((*pcb).tmr) >= inactivity)
            {
                inactivity = tcp_ticks.get().wrapping_sub((*pcb).tmr);
                inactive = pcb;
                mprio = (*pcb).prio;
            }
            pcb = (*pcb).next;
        }
        if !inactive.is_null() {
            tcp_abort(inactive);
        }
    }
}

/// Kills the oldest connection that is in specific `state`. Called from `tcp_alloc()`
/// for LAST_ACK and CLOSING (and, on ESP-IDF, the FIN_WAIT states) if no more
/// connections are available.
fn tcp_kill_state(state: TcpState) {
    let mut inactivity: u32 = 0;
    let mut inactive: *mut TcpPcb = ptr::null_mut();
    // Go through the list of active pcbs and get the oldest pcb that is in state
    // CLOSING/LAST_ACK.
    let mut pcb = tcp_active_pcbs.get();
    // SAFETY: the PCBs on the list are live.
    unsafe {
        while !pcb.is_null() {
            if (*pcb).state == state && tcp_ticks.get().wrapping_sub((*pcb).tmr) >= inactivity {
                inactivity = tcp_ticks.get().wrapping_sub((*pcb).tmr);
                inactive = pcb;
            }
            pcb = (*pcb).next;
        }
        if !inactive.is_null() {
            // Don't send a RST, since no data is lost.
            tcp_abandon(inactive, 0);
        }
    }
}

/// Kills the oldest connection that is in TIME_WAIT state. Called from `tcp_alloc()` if
/// no more connections are available.
fn tcp_kill_timewait() {
    let mut inactivity: u32 = 0;
    let mut inactive: *mut TcpPcb = ptr::null_mut();
    // Go through the list of TIME_WAIT pcbs and get the oldest pcb.
    let mut pcb = tcp_tw_pcbs.get();
    // SAFETY: the PCBs on the list are live.
    unsafe {
        while !pcb.is_null() {
            if tcp_ticks.get().wrapping_sub((*pcb).tmr) >= inactivity {
                inactivity = tcp_ticks.get().wrapping_sub((*pcb).tmr);
                inactive = pcb;
            }
            pcb = (*pcb).next;
        }
        if !inactive.is_null() {
            tcp_abort(inactive);
        }
    }
}

/// Called when allocating a pcb fails. In this case, we want to handle all pcbs that
/// want to close first: if we can now send the FIN (which failed before), the pcb
/// might be in a state that is OK for us to now free it.
fn tcp_handle_closepend() {
    let mut pcb = tcp_active_pcbs.get();

    while !pcb.is_null() {
        // SAFETY: the PCBs on the list are live.
        unsafe {
            let next = (*pcb).next;
            // Send pending FIN.
            if (*pcb).flags & TF_CLOSEPEND != 0 {
                tcp_clear_flags(pcb, TF_CLOSEPEND);
                tcp_close_shutdown_fin(pcb);
            }
            pcb = next;
        }
    }
}

/// Allocate a new tcp_pcb structure.
///
/// Returns a new tcp_pcb that initially is in state CLOSED.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tcp_alloc(prio: u8) -> *mut TcpPcb {
    // SAFETY: a MEMP_TCP_PCB element holds a struct tcp_pcb, zeroed before use.
    unsafe {
        let mut pcb = memp_malloc(config::MEMP_TCP_PCB).cast::<TcpPcb>();
        if pcb.is_null() {
            // Try to send FIN for all pcbs stuck in TF_CLOSEPEND first.
            tcp_handle_closepend();

            // Try killing oldest connection in TIME-WAIT.
            tcp_kill_timewait();
            // Try to allocate a tcp_pcb again.
            pcb = memp_malloc(config::MEMP_TCP_PCB).cast();
            if pcb.is_null() {
                // Try killing oldest connection in LAST-ACK (these wouldn't go to
                // TIME-WAIT).
                tcp_kill_state(LAST_ACK);
                pcb = memp_malloc(config::MEMP_TCP_PCB).cast();
                if pcb.is_null() {
                    // Try killing oldest connection in CLOSING.
                    tcp_kill_state(CLOSING);
                    pcb = memp_malloc(config::MEMP_TCP_PCB).cast();
                    if pcb.is_null() {
                        // ESP-IDF: try killing oldest connection in FIN_WAIT_2, then in
                        // FIN_WAIT_1.
                        tcp_kill_state(FIN_WAIT_2);
                        pcb = memp_malloc(config::MEMP_TCP_PCB).cast();
                        if pcb.is_null() {
                            tcp_kill_state(FIN_WAIT_1);
                            pcb = memp_malloc(config::MEMP_TCP_PCB).cast();
                            if pcb.is_null() {
                                // Try killing oldest active connection with lower
                                // priority than the new one.
                                tcp_kill_prio(prio);
                                pcb = memp_malloc(config::MEMP_TCP_PCB).cast();
                            }
                        }
                    }
                }
            }
        }
        if !pcb.is_null() {
            // Zero out the whole pcb, so there is no need to initialize members to zero.
            ptr::write_bytes(pcb, 0, 1);
            (*pcb).prio = prio;
            (*pcb).snd_buf = TCP_SND_BUF;
            // Start with a window that does not need scaling. When window scaling is
            // enabled and used, the window is enlarged when both sides agree on scaling.
            (*pcb).rcv_wnd = TCP_WND;
            (*pcb).rcv_ann_wnd = TCP_WND;
            (*pcb).ttl = TCP_TTL;
            // As initial send MSS, we use TCP_MSS but limit it to 536. The send MSS is
            // updated when an MSS option is received.
            (*pcb).mss = INITIAL_MSS;
            // Set initial TCP's retransmission timeout to 3000 ms by default. This value
            // could be configured in lwipopts.
            (*pcb).rto = (LWIP_TCP_RTO_TIME / TCP_SLOW_INTERVAL) as i16;
            (*pcb).sv = (LWIP_TCP_RTO_TIME / TCP_SLOW_INTERVAL) as i16;
            (*pcb).rtime = -1;
            (*pcb).cwnd = 1;
            (*pcb).tmr = tcp_ticks.get();
            (*pcb).last_timer = TCP_TIMER_CTR.get();

            // RFC 5681 recommends setting ssthresh arbitrarily high and gives an example
            // of using the largest advertised receive window. We've seen complications
            // with receiving TCPs that use window scaling and/or window auto-tuning where
            // the initial advertised window is very small and then grows rapidly once the
            // connection is established. To avoid these complications, we set ssthresh
            // to the largest effective cwnd (amount of in-flight data) that the sender
            // can have.
            (*pcb).ssthresh = TCP_SND_BUF;

            (*pcb).recv = Some(tcp_recv_null);

            // Init KEEPALIVE timer.
            (*pcb).keep_idle = TCP_KEEPIDLE_DEFAULT;
            (*pcb).keep_intvl = TCP_KEEPINTVL_DEFAULT;
            (*pcb).keep_cnt = TCP_KEEPCNT_DEFAULT;
        }
        pcb
    }
}

/// Creates a new TCP protocol control block but doesn't place it on any of the TCP PCB
/// lists. The pcb is not put on any list until binding using `tcp_bind()`. If memory is
/// not available for creating the new pcb, NULL is returned.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tcp_new() -> *mut TcpPcb {
    tcp_alloc(TCP_PRIO_NORMAL)
}

/// Creates a new TCP protocol control block but doesn't place it on any of the TCP PCB
/// lists, for the given IP type (`IPADDR_TYPE_V4`, `IPADDR_TYPE_V6`, or
/// `IPADDR_TYPE_ANY`).
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tcp_new_ip_type(type_: u8) -> *mut TcpPcb {
    let pcb = tcp_alloc(TCP_PRIO_NORMAL);
    if !pcb.is_null() {
        // SAFETY: a fresh PCB.
        unsafe {
            (*pcb).local_ip.type_ = type_;
            (*pcb).remote_ip.type_ = type_;
        }
    }
    pcb
}

/// Specifies the program specific state that should be passed to all other callback
/// functions. The "pcb" argument is the current TCP connection control block, and the
/// "arg" argument is the argument that will be passed to the callbacks.
///
/// # Safety
///
/// `pcb` is null or live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_arg(pcb: *mut TcpPcb, arg: *mut c_void) {
    // This function is allowed to be called for both listen pcbs and connection pcbs.
    if !pcb.is_null() {
        // SAFETY: as the caller guarantees.
        unsafe { (*pcb).callback_arg = arg };
    }
}

/// Sets the callback function that will be called when new data arrives. The callback
/// function will be passed a NULL pbuf to indicate that the remote host has closed the
/// connection. If the callback function returns `ERR_OK` or `ERR_ABRT` it must have
/// freed the pbuf, otherwise it must not have freed it.
///
/// # Safety
///
/// `pcb` is null or live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_recv(pcb: *mut TcpPcb, recv: TcpRecvFn) {
    if !pcb.is_null() {
        // SAFETY: as the caller guarantees.
        unsafe {
            lwip_assert!(
                "invalid socket state for recv callback",
                (*pcb).state != LISTEN
            );
            (*pcb).recv = recv;
        }
    }
}

/// Specifies the callback function that should be called when data has successfully
/// been received (i.e., acknowledged) by the remote host.
///
/// # Safety
///
/// `pcb` is null or live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_sent(pcb: *mut TcpPcb, sent: TcpSentFn) {
    if !pcb.is_null() {
        // SAFETY: as the caller guarantees.
        unsafe {
            lwip_assert!(
                "invalid socket state for sent callback",
                (*pcb).state != LISTEN
            );
            (*pcb).sent = sent;
        }
    }
}

/// Used to specify the function that should be called when a fatal error has occurred
/// on the connection.
///
/// If a connection is aborted because of an error, the application is alerted of this
/// event by the err callback. Errors that might abort a connection are when there is a
/// shortage of memory. The corresponding pcb is already freed when this callback is
/// called!
///
/// # Safety
///
/// `pcb` is null or live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_err(pcb: *mut TcpPcb, err: TcpErrFn) {
    if !pcb.is_null() {
        // SAFETY: as the caller guarantees.
        unsafe {
            lwip_assert!(
                "invalid socket state for err callback",
                (*pcb).state != LISTEN
            );
            (*pcb).errf = err;
        }
    }
}

/// Used for specifying the function that should be called when a LISTENing connection
/// has been connected to another host.
///
/// # Safety
///
/// `pcb` is null or live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_accept(pcb: *mut TcpPcb, accept: TcpAcceptFn) {
    // SAFETY: as the caller guarantees; a LISTEN PCB is a struct tcp_pcb_listen.
    unsafe {
        if !pcb.is_null() && (*pcb).state == LISTEN {
            let lpcb = pcb.cast::<TcpPcbListen>();
            (*lpcb).accept = accept;
        }
    }
}

/// Specifies the polling interval and the callback function that should be called to
/// poll the application. The interval is specified in number of TCP coarse grained
/// timer shots, which typically occurs twice a second. An interval of 10 means that the
/// application would be polled every 5 seconds.
///
/// # Safety
///
/// `pcb` is null or live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_poll(pcb: *mut TcpPcb, poll: TcpPollFn, interval: u8) {
    // LWIP_ERROR("tcp_poll: invalid pcb", pcb != NULL, return);
    if pcb.is_null() {
        return;
    }
    // SAFETY: as the caller guarantees.
    unsafe {
        lwip_assert!("invalid socket state for poll", (*pcb).state != LISTEN);

        (*pcb).poll = poll;
        (*pcb).pollinterval = interval;
    }
}

/// Purges a TCP PCB. Removes any buffered data and frees the buffer memory
/// (pcb->ooseq, pcb->unsent and pcb->unacked are freed).
///
/// # Safety
///
/// `pcb` is null or live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_pcb_purge(pcb: *mut TcpPcb) {
    // LWIP_ERROR("tcp_pcb_purge: invalid pcb", pcb != NULL, return);
    if pcb.is_null() {
        return;
    }

    // SAFETY: as the caller guarantees.
    unsafe {
        if (*pcb).state != CLOSED && (*pcb).state != TIME_WAIT && (*pcb).state != LISTEN {
            tcp_backlog_accepted(pcb);

            if !(*pcb).refused_data.is_null() {
                pbuf_free((*pcb).refused_data);
                (*pcb).refused_data = ptr::null_mut();
            }
            if !(*pcb).ooseq.is_null() {
                tcp_free_ooseq(pcb);
            }

            // Stop the retransmission timer as it will expect data on unacked queue if
            // it fires.
            (*pcb).rtime = -1;

            tcp_segs_free((*pcb).unsent);
            tcp_segs_free((*pcb).unacked);
            (*pcb).unacked = ptr::null_mut();
            (*pcb).unsent = ptr::null_mut();
            (*pcb).unsent_oversize = 0;
        }
    }
}

/// Purges the PCB and removes it from a PCB list. Any delayed ACKs are sent first.
///
/// # Safety
///
/// `pcblist` is a list head and `pcb` a live PCB.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_pcb_remove(pcblist: *mut *mut TcpPcb, pcb: *mut TcpPcb) {
    lwip_assert!("tcp_pcb_remove: invalid pcb", !pcb.is_null());
    lwip_assert!("tcp_pcb_remove: invalid pcblist", !pcblist.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        tcp_rmv(pcblist, pcb);

        tcp_pcb_purge(pcb);

        // If there is an outstanding delayed ACKs, send it.
        if (*pcb).state != TIME_WAIT && (*pcb).state != LISTEN && (*pcb).flags & TF_ACK_DELAY != 0 {
            tcp_ack_now(pcb);
            tcp_output(pcb);
        }

        if (*pcb).state != LISTEN {
            lwip_assert!("unsent segments leaking", (*pcb).unsent.is_null());
            lwip_assert!("unacked segments leaking", (*pcb).unacked.is_null());
            lwip_assert!("ooseq segments leaking", (*pcb).ooseq.is_null());
        }

        (*pcb).state = CLOSED;
        // Reset the local port to prevent the pcb from being 'bound'.
        (*pcb).local_port = 0;
    }
}

/// Calculates a new initial sequence number for new connections: ESP-IDF's
/// `LWIP_HOOK_TCP_ISN`.
///
/// # Safety
///
/// `pcb` is live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_next_iss(pcb: *mut TcpPcb) -> u32 {
    lwip_assert!("tcp_next_iss: invalid pcb", !pcb.is_null());
    // SAFETY: as the caller guarantees.
    unsafe {
        lwip_hook_tcp_isn(
            &(*pcb).local_ip,
            (*pcb).local_port,
            &(*pcb).remote_ip,
            (*pcb).remote_port,
        )
    }
}

/// Calculates the effective send mss that can be used for a specific IP address by
/// calculating the minimum of TCP_MSS and the mtu (if set) of the target netif (if not
/// NULL).
///
/// # Safety
///
/// `outif` is null or live, and `dest` valid.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_eff_send_mss_netif(
    mut sendmss: u16,
    outif: *mut Netif,
    dest: *const IpAddr,
) -> u16 {
    lwip_assert!("tcp_eff_send_mss_netif: invalid dst_ip", !dest.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        let mtu = if (*dest).is_v6() {
            // First look in destination cache, to see if there is a Path MTU.
            nd6_get_destination_mtu((*dest).ip6(), outif)
        } else {
            if outif.is_null() {
                return sendmss;
            }
            (*outif).mtu
        };

        if mtu != 0 {
            let offset = if (*dest).is_v6() {
                IP6_HLEN + TCP_HLEN
            } else {
                IP_HLEN + TCP_HLEN
            };
            let mss_s = mtu.saturating_sub(offset);
            // RFC 1122, chap 4.2.2.6: Eff.snd.MSS = min(SendMSS+20, MMS_S) - TCPhdrsize
            // - IPoptionsize. We correct for TCP options in tcp_write(), and don't
            // support IP options.
            sendmss = sendmss.min(mss_s);
        }
    }
    sendmss
}

/// Helper function for `tcp_netif_ip_addr_changed()` that iterates a pcb list.
///
/// # Safety
///
/// `old_addr` is valid and `pcb_list` a list of live PCBs.
unsafe fn tcp_netif_ip_addr_changed_pcblist(old_addr: *const IpAddr, pcb_list: *mut TcpPcb) {
    lwip_assert!(
        "tcp_netif_ip_addr_changed_pcblist: invalid old_addr",
        !old_addr.is_null()
    );

    let mut pcb = pcb_list;
    // SAFETY: as the caller guarantees.
    unsafe {
        while !pcb.is_null() {
            // PCB bound to current local interface address?
            if (*pcb).local_ip.eq_addr(&*old_addr) {
                // This connection must be aborted.
                let next = (*pcb).next;
                tcp_abort(pcb);
                pcb = next;
            } else {
                pcb = (*pcb).next;
            }
        }
    }
}

/// This function is called from netif.c when address is changed or netif is removed.
///
/// # Safety
///
/// `old_addr` is valid, and `new_addr` null or valid.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_netif_ip_addr_changed(
    old_addr: *const IpAddr,
    new_addr: *const IpAddr,
) {
    // SAFETY: as the caller guarantees; the lists hold live PCBs.
    unsafe {
        if !old_addr.as_ref().is_none_or(IpAddr::is_any) {
            tcp_netif_ip_addr_changed_pcblist(old_addr, tcp_active_pcbs.get());
            tcp_netif_ip_addr_changed_pcblist(old_addr, tcp_bound_pcbs.get());

            if !new_addr.as_ref().is_none_or(IpAddr::is_any) {
                // PCB bound to current local interface address?
                let mut lpcb = tcp_listen_pcbs.get().cast::<TcpPcbListen>();
                while !lpcb.is_null() {
                    // PCB bound to current local interface address?
                    if (*lpcb).local_ip.eq_addr(&*old_addr) {
                        // The PCB is listening to the old ipaddr and is set to listen to
                        // the new one instead.
                        (*lpcb).local_ip.copy_from(&*new_addr);
                    }
                    lpcb = (*lpcb).next;
                }
            }
        }
    }
}

/// The name of a TCP state, for debug output.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tcp_debug_state_str(s: TcpState) -> *const c_char {
    TCP_STATE_STR[s as usize].as_ptr()
}

/// Returns the local or remote address and port of a connection.
///
/// # Safety
///
/// `pcb` is null or live, and `addr` and `port` null or writable.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_tcp_get_tcp_addrinfo(
    pcb: *mut TcpPcb,
    local: c_int,
    addr: *mut IpAddr,
    port: *mut u16,
) -> ErrT {
    if pcb.is_null() {
        return ERR_VAL;
    }
    // SAFETY: as the caller guarantees.
    unsafe {
        let (ip, p) = if local != 0 {
            ((*pcb).local_ip, (*pcb).local_port)
        } else {
            ((*pcb).remote_ip, (*pcb).remote_port)
        };
        if !addr.is_null() {
            *addr = ip;
        }
        if !port.is_null() {
            *port = p;
        }
    }
    ERR_OK
}

/// Free all ooseq pbufs (and possibly reset SACK state).
///
/// # Safety
///
/// `pcb` is live.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_free_ooseq(pcb: *mut TcpPcb) {
    // SAFETY: as the caller guarantees.
    unsafe {
        if !(*pcb).ooseq.is_null() {
            tcp_segs_free((*pcb).ooseq);
            (*pcb).ooseq = ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests;
