// Copyright (c) 2001-2004 Leon Woestenberg <leon.woestenberg@gmx.net>
// Copyright (c) 2001-2004 Axon Digital Design B.V., The Netherlands.
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
// The Swedish Institute of Computer Science and Adam Dunkels
// are specifically granted permission to redistribute this
// source code.
//
// Author: Leon Woestenberg <leon.woestenberg@gmx.net>
//
// Translated to Rust for mss-esp-lwip by Mist Tecnologia LTDA.

//! Dynamic Host Configuration Protocol client, from `src/core/ipv4/dhcp.c`, as ESP-IDF
//! configures it: address conflict detection of the offered address, DNS servers from
//! the lease (but not into the fallback slot), the host name in its messages, ESP-IDF's
//! timeouts, back-off, on-demand fine timer and option hooks, and no NTP servers, BOOTP
//! file, or AutoIP cooperation (`build.rs` refuses the rest).
//!
//! DHCP (IPv4) is a stateful protocol: the client obtains a lease from a server,
//! renews it, and gives it back. To use it, call `dhcp_start()` on a netif that is up;
//! `dhcp_coarse_tmr()` must be called every `DHCP_COARSE_TIMER_SECS` seconds, and the
//! fine timer schedules itself while a request is outstanding.

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr;

use crate::config;
use crate::global::Global;
use crate::links::*;
use crate::types::*;

// DHCP message types.
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_DECLINE: u8 = 4;
const DHCP_ACK: u8 = 5;
const DHCP_NAK: u8 = 6;
const DHCP_RELEASE: u8 = 7;
const DHCP_INFORM: u8 = 8;

// DHCP options.
const DHCP_OPTION_PAD: u8 = 0;
const DHCP_OPTION_SUBNET_MASK: u8 = 1;
const DHCP_OPTION_ROUTER: u8 = 3;
const DHCP_OPTION_DNS_SERVER: u8 = 6;
const DHCP_OPTION_HOSTNAME: u8 = 12;
const DHCP_OPTION_BROADCAST: u8 = 28;
const DHCP_OPTION_REQUESTED_IP: u8 = 50;
const DHCP_OPTION_LEASE_TIME: u8 = 51;
const DHCP_OPTION_OVERLOAD: u8 = 52;
const DHCP_OPTION_MESSAGE_TYPE: u8 = 53;
const DHCP_OPTION_SERVER_ID: u8 = 54;
const DHCP_OPTION_PARAMETER_REQUEST_LIST: u8 = 55;
const DHCP_OPTION_MAX_MSG_SIZE: u8 = 57;
const DHCP_OPTION_T1: u8 = 58;
const DHCP_OPTION_T2: u8 = 59;
const DHCP_OPTION_END: u8 = 255;

// Possible combinations of overloading the file and sname fields with options.
const DHCP_OVERLOAD_FILE: u32 = 1;
const DHCP_OVERLOAD_SNAME: u32 = 2;
const DHCP_OVERLOAD_SNAME_FILE: u32 = 3;

const DHCP_BOOTREQUEST: u8 = 1;
const DHCP_BOOTREPLY: u8 = 2;
const DHCP_MAGIC_COOKIE: u32 = 0x6382_5363;
const LWIP_IANA_HWTYPE_ETHERNET: u8 = 1;
const LWIP_IANA_PORT_DHCP_SERVER: u16 = 67;
const LWIP_IANA_PORT_DHCP_CLIENT: u16 = 68;

// DHCP client states.
const DHCP_STATE_OFF: u8 = 0;
const DHCP_STATE_REQUESTING: u8 = 1;
const DHCP_STATE_INIT: u8 = 2;
const DHCP_STATE_REBOOTING: u8 = 3;
const DHCP_STATE_REBINDING: u8 = 4;
const DHCP_STATE_RENEWING: u8 = 5;
const DHCP_STATE_SELECTING: u8 = 6;
const DHCP_STATE_INFORMING: u8 = 7;
const DHCP_STATE_CHECKING: u8 = 8;
const DHCP_STATE_BOUND: u8 = 10;
const DHCP_STATE_BACKING_OFF: u8 = 12;

const DHCP_FLAG_SUBNET_MASK_GIVEN: u8 = 0x01;
const DHCP_FLAG_EXTERNAL_MEM: u8 = 0x02;

// struct dhcp_msg, as offsets into the packed message.
const DHCP_OP: usize = 0;
const DHCP_HTYPE: usize = 1;
const DHCP_HLEN: usize = 2;
const DHCP_XID: usize = 4;
const DHCP_CIADDR: usize = 12;
const DHCP_YIADDR: usize = 16;
const DHCP_CHADDR: usize = 28;
const DHCP_CHADDR_LEN: usize = 16;
const DHCP_SNAME_OFS: u16 = 44;
const DHCP_SNAME_LEN: u16 = 64;
const DHCP_FILE_OFS: u16 = 108;
const DHCP_FILE_LEN: u16 = 128;
const DHCP_MSG_LEN: u16 = 236;
const DHCP_COOKIE: usize = DHCP_MSG_LEN as usize;
/// Offset of the options: the fixed fields and the magic cookie.
const DHCP_OPTIONS_OFS: u16 = DHCP_MSG_LEN + 4;
const DHCP_OPTIONS_LEN: usize = config::DHCP_OPTIONS_LEN;
const DHCP_MIN_OPTIONS_LEN: u16 = 68;
/// `sizeof(struct dhcp_msg)`.
const SIZEOF_DHCP_MSG: usize = DHCP_OPTIONS_OFS as usize + DHCP_OPTIONS_LEN;

/// Minimum length for reply before packet is parsed.
const DHCP_MIN_REPLY_LEN: u16 = 44;
const DHCP_MAX_MSG_LEN_MIN_REQUIRED: u16 = 576;
const REBOOT_TRIES: u8 = 2;

const DHCP_COARSE_TIMER_SECS: u32 = config::DHCP_COARSE_TIMER_SECS as u32;
const DHCP_FINE_TIMER_MSECS: u32 = config::DHCP_FINE_TIMER_MSECS as u32;
const DHCP_NEXT_TIMEOUT_THRESHOLD: u32 = config::DHCP_NEXT_TIMEOUT_THRESHOLD_ as u32;
const LWIP_DHCP_PROVIDE_DNS_SERVERS: usize = config::LWIP_DHCP_PROVIDE_DNS_SERVERS_;
const DNS_FALLBACK_SERVER_INDEX: usize = config::DNS_FALLBACK_SERVER_INDEX;
const LWIP_NETIF_CLIENT_DATA_INDEX_DHCP: usize = config::LWIP_NETIF_CLIENT_DATA_INDEX_DHCP_;

// Option handling: the options are parsed in dhcp_parse_reply and saved in an array
// where other functions can load them from. This might be moved into the struct dhcp
// (not necessarily since lwIP is single-threaded and the array is only used while in
// recv callback).
const DHCP_OPTION_IDX_OVERLOAD: usize = 0;
const DHCP_OPTION_IDX_MSG_TYPE: usize = 1;
const DHCP_OPTION_IDX_SERVER_ID: usize = 2;
const DHCP_OPTION_IDX_LEASE_TIME: usize = 3;
const DHCP_OPTION_IDX_T1: usize = 4;
const DHCP_OPTION_IDX_T2: usize = 5;
const DHCP_OPTION_IDX_SUBNET_MASK: usize = 6;
const DHCP_OPTION_IDX_ROUTER: usize = 7;
const DHCP_OPTION_IDX_DNS_SERVER: usize = 8;
const DHCP_OPTION_IDX_MAX: usize = DHCP_OPTION_IDX_DNS_SERVER + LWIP_DHCP_PROVIDE_DNS_SERVERS;

/// Holds the decoded option values, only valid while in dhcp_recv.
static DHCP_RX_OPTIONS_VAL: Global<[u32; DHCP_OPTION_IDX_MAX]> =
    Global::new([0; DHCP_OPTION_IDX_MAX]);
/// Holds a flag which option was received and is contained in dhcp_rx_options_val, only
/// valid while in dhcp_recv.
static DHCP_RX_OPTIONS_GIVEN: Global<[u8; DHCP_OPTION_IDX_MAX]> =
    Global::new([0; DHCP_OPTION_IDX_MAX]);

static DHCP_DISCOVER_REQUEST_OPTIONS: [u8; 4] = [
    DHCP_OPTION_SUBNET_MASK,
    DHCP_OPTION_ROUTER,
    DHCP_OPTION_BROADCAST,
    DHCP_OPTION_DNS_SERVER,
];

static DHCP_PCB: Global<*mut UdpPcb> = Global::new(ptr::null_mut());
static DHCP_PCB_REFCOUNT: Global<u8> = Global::new(0);
/// `dhcp_create_msg`'s `static u32_t xid`.
static XID: Global<u32> = Global::new(0);

/// `dhcp_option_given(dhcp, idx)`.
fn option_given(idx: usize) -> bool {
    DHCP_RX_OPTIONS_GIVEN.get()[idx] != 0
}

/// `dhcp_got_option(dhcp, idx)` and `dhcp_clear_option(dhcp, idx)`.
fn set_option_given(idx: usize, given: bool) {
    // SAFETY: the stack serializes access to its globals.
    unsafe { (*DHCP_RX_OPTIONS_GIVEN.as_ptr())[idx] = u8::from(given) };
}

/// `dhcp_get_option_value(dhcp, idx)`.
fn option_value(idx: usize) -> u32 {
    DHCP_RX_OPTIONS_VAL.get()[idx]
}

/// `dhcp_set_option_value(dhcp, idx, val)`.
fn set_option_value(idx: usize, val: u32) {
    // SAFETY: the stack serializes access to its globals.
    unsafe { (*DHCP_RX_OPTIONS_VAL.as_ptr())[idx] = val };
}

/// `netif_dhcp_data(netif)`.
///
/// # Safety
///
/// `netif` is live.
unsafe fn netif_dhcp_data(netif: *const Netif) -> *mut Dhcp {
    // SAFETY: as the caller guarantees.
    unsafe { (*netif).client_data[LWIP_NETIF_CLIENT_DATA_INDEX_DHCP].cast() }
}

/// `netif_set_client_data(netif, LWIP_NETIF_CLIENT_DATA_INDEX_DHCP, dhcp)`.
///
/// # Safety
///
/// `netif` is live.
unsafe fn set_netif_dhcp_data(netif: *mut Netif, dhcp: *mut Dhcp) {
    // SAFETY: as the caller guarantees.
    unsafe { (*netif).client_data[LWIP_NETIF_CLIENT_DATA_INDEX_DHCP] = dhcp.cast() };
}

/// `IP4_ADDR_ANY4`, ip4_addr.c's.
fn ip4_addr_any() -> *const Ip4Addr {
    // SAFETY: the address of the constant's IPv4 part.
    unsafe { (*ip_addr_any()).ip4() }
}

/// ESP-IDF's `DHCP_REQUEST_BACKOFF_SEQUENCE(state, tries)`: 500 ms, then 1, 2, 4 s and
/// 4 s from then on (`build.rs` checks it against the configuration).
fn request_backoff_sequence(tries: u8) -> u16 {
    ((if tries < 5 { 1 << tries } else { 16 }) * 250) as u16
}

/// ESP-IDF's `timeout_from_offered`: the offered time in coarse ticks, or `min` if none
/// was offered.
fn timeout_from_offered(lease: u32, min: u32) -> u32 {
    let timeout = if lease == 0 { min } else { lease };
    timeout.wrapping_add(DHCP_COARSE_TIMER_SECS - 1) / DHCP_COARSE_TIMER_SECS
}

/// `(u16_t)((msecs + DHCP_FINE_TIMER_MSECS - 1) / DHCP_FINE_TIMER_MSECS)`: a request
/// timeout in fine-timer ticks.
fn fine_ticks(msecs: u16) -> DhcpTimeout {
    u32::from(msecs).div_ceil(DHCP_FINE_TIMER_MSECS) as u16 as DhcpTimeout
}

/// `ESP_LWIP_DHCP_FINE_TIMER_START_ONCE(netif, dhcp)`.
///
/// # Safety
///
/// `dhcp` is `netif`'s, and both are live.
unsafe fn fine_timer_start_once(netif: *mut Netif, dhcp: *mut Dhcp) {
    // SAFETY: as the caller guarantees.
    unsafe {
        if (*dhcp).fine_timer_enabled == 0 {
            sys_timeout(
                DHCP_FINE_TIMER_MSECS,
                Some(dhcp_fine_timeout_cb),
                netif.cast(),
            );
            (*dhcp).fine_timer_enabled = 1;
        }
    }
}

/// `ESP_LWIP_DHCP_FINE_CLOSE(netif, dhcp)`.
///
/// # Safety
///
/// `dhcp` is `netif`'s, and both are live.
unsafe fn fine_timer_close(netif: *mut Netif, dhcp: *mut Dhcp) {
    // SAFETY: as the caller guarantees.
    unsafe {
        if (*dhcp).fine_timer_enabled != 0 {
            sys_untimeout(Some(dhcp_fine_timeout_cb), netif.cast());
            (*dhcp).fine_timer_enabled = 0;
        }
    }
}

/// Ensure DHCP PCB is allocated and bound.
unsafe fn dhcp_inc_pcb_refcount() -> ErrT {
    // SAFETY: the stack serializes access to its globals; the PCB is fresh.
    unsafe {
        if DHCP_PCB_REFCOUNT.get() == 0 {
            lwip_assert!(
                "dhcp_inc_pcb_refcount(): memory leak",
                DHCP_PCB.get().is_null()
            );

            // Allocate UDP PCB.
            let pcb = udp_new();
            DHCP_PCB.set(pcb);
            if pcb.is_null() {
                return ERR_MEM;
            }

            (*pcb).so_options |= SOF_BROADCAST;

            // Set up local and remote port for the pcb -> listen on all interfaces on
            // all src/dest IPs.
            udp_bind(pcb, ip_addr_any(), LWIP_IANA_PORT_DHCP_CLIENT);
            udp_connect(pcb, ip_addr_any(), LWIP_IANA_PORT_DHCP_SERVER);
            udp_recv(pcb, Some(dhcp_recv), ptr::null_mut());
        }

        DHCP_PCB_REFCOUNT.set(DHCP_PCB_REFCOUNT.get() + 1);
    }
    ERR_OK
}

/// Free DHCP PCB if the last netif stops using it.
unsafe fn dhcp_dec_pcb_refcount() {
    lwip_assert!(
        "dhcp_pcb_refcount(): refcount error",
        DHCP_PCB_REFCOUNT.get() > 0
    );
    DHCP_PCB_REFCOUNT.set(DHCP_PCB_REFCOUNT.get() - 1);

    if DHCP_PCB_REFCOUNT.get() == 0 {
        // SAFETY: the PCB from dhcp_inc_pcb_refcount.
        unsafe { udp_remove(DHCP_PCB.get()) };
        DHCP_PCB.set(ptr::null_mut());
    }
}

/// ESP-IDF: the fine timer's handler, with the netif as its argument.
///
/// # Safety
///
/// `arg` is null or a live netif.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn dhcp_fine_timeout_cb(arg: *mut c_void) {
    // SAFETY: as the caller guarantees.
    unsafe { dhcp_fine_tmr(arg.cast()) };
}

/// Back-off the DHCP client (because of a received NAK response).
///
/// Back-off the DHCP client because of a received NAK. Receiving a NAK means the client
/// asked for something non-sensible, for example when it tries to renew a lease obtained
/// on another network.
///
/// We clear any existing set IP address and restart DHCP negotiation afresh (as per RFC2131
/// 3.2.3).
///
/// # Safety
///
/// `netif` is a live netif with DHCP.
unsafe fn dhcp_handle_nak(netif: *mut Netif) {
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);
        // Change to a defined state - set this before assigning the address to ensure
        // the callback can use dhcp_supplied_address().
        dhcp_set_state(dhcp, DHCP_STATE_BACKING_OFF);
        // Remove IP address from interface (must no longer be used, as per RFC2131).
        netif_set_addr(netif, ip4_addr_any(), ip4_addr_any(), ip4_addr_any());
        // We can immediately restart discovery.
        dhcp_discover(netif);
    }
}

/// Handle conflict information from ACD module.
///
/// `state` is `ACD_IP_OK` for an address that can be used, `ACD_RESTART_CLIENT` to back
/// off after too many conflicts, and `ACD_DECLINE` for an address in use.
unsafe extern "C" fn dhcp_conflict_callback(netif: *mut Netif, state: AcdCallback) {
    // SAFETY: acd.c calls back with the netif whose DHCP added the client.
    unsafe {
        let dhcp = netif_dhcp_data(netif);
        lwip_assert!(
            "DHCP should be enabled at this point, but it is not!",
            !dhcp.is_null() && (*dhcp).state != DHCP_STATE_OFF
        );

        match state {
            ACD_IP_OK => dhcp_bind(netif),
            ACD_RESTART_CLIENT => {
                // Wait 10s before restarting. According to RFC2131 section 3.1 point 5:
                // If the client detects that the address is already in use (e.g., through
                // the use of ARP), the client MUST send a DHCPDECLINE message to the server
                // and restarts the configuration process. The client SHOULD wait a minimum
                // of ten seconds before restarting the configuration process to avoid
                // excessive network traffic in case of looping.
                dhcp_set_state(dhcp, DHCP_STATE_BACKING_OFF);
                let msecs: u16 = 10 * 1000;
                (*dhcp).request_timeout = fine_ticks(msecs);
                fine_timer_start_once(netif, dhcp);
            }
            ACD_DECLINE => {
                // Remove IP address from interface (prevents routing from selecting this
                // interface).
                netif_set_addr(netif, ip4_addr_any(), ip4_addr_any(), ip4_addr_any());
                // Let the DHCP server know we will not use the address.
                dhcp_decline(netif);
            }
            _ => {}
        }
    }
}

/// Checks if the offered IP address is already in use.
///
/// It does this according to the address conflict detection method described in
/// RFC5227.
///
/// # Safety
///
/// `netif` is a live netif with DHCP.
unsafe fn dhcp_check(netif: *mut Netif) {
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);
        dhcp_set_state(dhcp, DHCP_STATE_CHECKING);
        // Start ACD module.
        acd_start(netif, &raw mut (*dhcp).acd, (*dhcp).offered_ip_addr);
    }
}

/// Remember the configuration offered by a DHCP server.
///
/// # Safety
///
/// `netif` is a live netif with DHCP, and `msg_in` the offer.
unsafe fn dhcp_handle_offer(netif: *mut Netif, msg_in: *const u8) {
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);
        // Obtain the server address.
        if option_given(DHCP_OPTION_IDX_SERVER_ID) {
            (*dhcp).request_timeout = 0; // Stop timer.

            (*dhcp)
                .server_ip_addr
                .copy_from_ip4(u32::from_be(option_value(DHCP_OPTION_IDX_SERVER_ID)));
            // Remember offered address.
            (*dhcp).offered_ip_addr.addr = msg_in.add(DHCP_YIADDR).cast::<u32>().read_unaligned();

            dhcp_select(netif);
        }
    }
}

/// Select a DHCP server offer out of all offers.
///
/// Simply select the first offer received.
///
/// Returns the lwIP specific error (see error.h).
///
/// # Safety
///
/// `netif` is null or a live netif.
unsafe fn dhcp_select(netif: *mut Netif) -> ErrT {
    // LWIP_ERROR("dhcp_select: netif != NULL", (netif != NULL), return ERR_ARG;);
    if netif.is_null() {
        return ERR_ARG;
    }
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);
        // LWIP_ERROR("dhcp_select: dhcp != NULL", (dhcp != NULL), return ERR_VAL;);
        if dhcp.is_null() {
            return ERR_VAL;
        }

        dhcp_set_state(dhcp, DHCP_STATE_REQUESTING);

        // Create and initialize the DHCP message header.
        let mut options_out_len = 0;
        let p_out = dhcp_create_msg(netif, dhcp, DHCP_REQUEST, &mut options_out_len);
        let result = if !p_out.is_null() {
            let msg_out = (*p_out).payload.cast::<u8>();
            let mut len = options_out_len;
            len = dhcp_option(len, msg_out, DHCP_OPTION_MAX_MSG_SIZE, 2);
            len = dhcp_option_short(len, msg_out, (*netif).mtu);

            // MUST request the offered IP address.
            len = dhcp_option(len, msg_out, DHCP_OPTION_REQUESTED_IP, 4);
            len = dhcp_option_long(len, msg_out, u32::from_be((*dhcp).offered_ip_addr.addr));

            len = dhcp_option(len, msg_out, DHCP_OPTION_SERVER_ID, 4);
            len = dhcp_option_long(
                len,
                msg_out,
                u32::from_be((*dhcp).server_ip_addr.ip4().addr),
            );

            len = dhcp_option(
                len,
                msg_out,
                DHCP_OPTION_PARAMETER_REQUEST_LIST,
                DHCP_DISCOVER_REQUEST_OPTIONS.len() as u8,
            );
            for &option in &DHCP_DISCOVER_REQUEST_OPTIONS {
                len = dhcp_option_byte(len, msg_out, option);
            }

            len = dhcp_option_hostname(len, msg_out, netif);

            dhcp_append_extra_opts(netif, DHCP_STATE_REQUESTING, msg_out.cast(), &mut len);
            dhcp_option_trailer(len, msg_out, p_out);

            // Send broadcast to any DHCP server.
            let result = udp_sendto_if_src(
                DHCP_PCB.get(),
                p_out,
                ip_addr_broadcast(),
                LWIP_IANA_PORT_DHCP_SERVER,
                netif,
                ip_addr_any(),
            );
            pbuf_free(p_out);
            result
        } else {
            ERR_MEM
        };
        (*dhcp).tries = (*dhcp).tries.saturating_add(1);
        let msecs = request_backoff_sequence((*dhcp).tries);
        (*dhcp).request_timeout = fine_ticks(msecs);
        fine_timer_start_once(netif, dhcp);
        result
    }
}

/// The DHCP timer that checks for lease renewal/rebind timeouts. Must be called once a
/// minute (see `DHCP_COARSE_TIMER_SECS`).
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn dhcp_coarse_tmr() {
    // SAFETY: netifs on the list are live, and so is their DHCP state.
    unsafe {
        // Iterate through all network interfaces.
        let mut netif = netif_list();
        while !netif.is_null() {
            // Only act on DHCP configured interfaces.
            let dhcp = netif_dhcp_data(netif);
            if !dhcp.is_null() && (*dhcp).state != DHCP_STATE_OFF {
                // Compare lease time to expire timeout.
                if (*dhcp).t0_timeout != 0 && {
                    (*dhcp).lease_used = (*dhcp).lease_used.wrapping_add(1);
                    (*dhcp).lease_used == (*dhcp).t0_timeout
                } {
                    // This clients' lease time has expired.
                    dhcp_release_and_stop(netif);
                    dhcp_start(netif);
                // Timer is active (non zero), and triggers (zeroes) now?
                } else if (*dhcp).t2_rebind_time != 0 && {
                    let t = (*dhcp).t2_rebind_time;
                    (*dhcp).t2_rebind_time = t.wrapping_sub(1);
                    t == 1
                } {
                    // This clients' rebind timeout triggered.
                    dhcp_t2_timeout(netif);
                // Timer is active (non zero), and triggers (zeroes) now.
                } else if (*dhcp).t1_renew_time != 0 && {
                    let t = (*dhcp).t1_renew_time;
                    (*dhcp).t1_renew_time = t.wrapping_sub(1);
                    t == 1
                } {
                    // This clients' renewal timeout triggered.
                    dhcp_t1_timeout(netif);
                }
            }
            netif = (*netif).next.map_or(ptr::null_mut(), |n| n.as_ptr());
        }
    }
}

/// DHCP transaction timeout handling (this function must be called every 500ms, see
/// `DHCP_FINE_TIMER_MSECS`).
///
/// A DHCP server is expected to respond within a short period of time. This timer checks
/// whether an outstanding DHCP request is timed out. ESP-IDF runs it for one netif, and
/// only while a request is outstanding.
///
/// # Safety
///
/// `netif` is null or a live netif.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn dhcp_fine_tmr(netif: *mut Netif) {
    if netif.is_null() {
        return;
    }
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);
        // Only act on DHCP configured interfaces.
        if !dhcp.is_null() {
            let mut tmr_restart = false;
            // Timer is active (non zero), and is about to trigger now.
            if (*dhcp).request_timeout > 1 {
                (*dhcp).request_timeout -= 1;
                tmr_restart = true;
            } else if (*dhcp).request_timeout == 1 {
                (*dhcp).request_timeout -= 1;
                // This client's request timeout triggered.
                dhcp_timeout(netif);
                tmr_restart = true;
            }
            if tmr_restart {
                if (*dhcp).fine_timer_enabled == 1 {
                    sys_timeout(
                        DHCP_FINE_TIMER_MSECS,
                        Some(dhcp_fine_timeout_cb),
                        netif.cast(),
                    );
                }
            } else {
                sys_untimeout(Some(dhcp_fine_timeout_cb), netif.cast());
                (*dhcp).fine_timer_enabled = 0;
            }
        }
    }
}

/// A DHCP negotiation transaction, or ARP request, has timed out.
///
/// The timer that was started with the DHCP or ARP request has timed out, indicating no
/// response was received in time.
///
/// # Safety
///
/// `netif` is a live netif with DHCP.
unsafe fn dhcp_timeout(netif: *mut Netif) {
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);
        let state = (*dhcp).state;
        // Back-off period has passed, or server selection timed out.
        if state == DHCP_STATE_BACKING_OFF || state == DHCP_STATE_SELECTING {
            dhcp_discover(netif);
        // Receiving the requested lease timed out.
        } else if state == DHCP_STATE_REQUESTING {
            if (*dhcp).tries <= 5 {
                dhcp_select(netif);
            } else {
                dhcp_release_and_stop(netif);
                dhcp_start(netif);
            }
        } else if state == DHCP_STATE_REBOOTING {
            if (*dhcp).tries < REBOOT_TRIES {
                dhcp_reboot(netif);
            } else {
                dhcp_discover(netif);
            }
        } else if state == DHCP_STATE_REBINDING {
            // ESP-IDF: rebind again at the next coarse tick.
            (*dhcp).t2_rebind_time = 1;
        }
    }
}

/// The renewal period has timed out.
///
/// # Safety
///
/// `netif` is a live netif with DHCP.
unsafe fn dhcp_t1_timeout(netif: *mut Netif) {
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);
        let state = (*dhcp).state;
        if state == DHCP_STATE_REQUESTING
            || state == DHCP_STATE_BOUND
            || state == DHCP_STATE_RENEWING
        {
            // Just retry to renew - note that the rebind timer (t2) will eventually time-out
            // if renew tries fail.
            dhcp_renew(netif);
            // Calculate next timeout.
            let next = (*dhcp).t2_timeout.wrapping_sub((*dhcp).lease_used) / 2;
            if next >= DHCP_NEXT_TIMEOUT_THRESHOLD {
                (*dhcp).t1_renew_time = next;
            }
        }
    }
}

/// The rebind period has timed out.
///
/// # Safety
///
/// `netif` is a live netif with DHCP.
unsafe fn dhcp_t2_timeout(netif: *mut Netif) {
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);
        let state = (*dhcp).state;
        if state == DHCP_STATE_REQUESTING
            || state == DHCP_STATE_BOUND
            || state == DHCP_STATE_RENEWING
            || state == DHCP_STATE_REBINDING
        {
            // Just retry to rebind.
            dhcp_rebind(netif);
            // Calculate next timeout.
            let next = (*dhcp).t0_timeout.wrapping_sub((*dhcp).lease_used) / 2;
            if next >= DHCP_NEXT_TIMEOUT_THRESHOLD {
                (*dhcp).t2_rebind_time = next;
            }
        }
    }
}

/// Handle a DHCP ACK packet.
///
/// # Safety
///
/// `netif` is a live netif with DHCP, and `msg_in` the ACK.
unsafe fn dhcp_handle_ack(netif: *mut Netif, msg_in: *const u8) {
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);

        // Clear options we might not get from the ACK.
        (*dhcp).offered_sn_mask.addr = 0;
        (*dhcp).offered_gw_addr.addr = 0;

        // Lease time given?
        if option_given(DHCP_OPTION_IDX_LEASE_TIME) {
            // Remember offered lease time.
            (*dhcp).offered_t0_lease = option_value(DHCP_OPTION_IDX_LEASE_TIME);
        }
        // Renewal period given?
        if option_given(DHCP_OPTION_IDX_T1) {
            // Remember given renewal period.
            (*dhcp).offered_t1_renew = option_value(DHCP_OPTION_IDX_T1);
        } else {
            // Calculate safe periods for renewal.
            (*dhcp).offered_t1_renew = (*dhcp).offered_t0_lease / 2;
        }

        // Renewal period given?
        if option_given(DHCP_OPTION_IDX_T2) {
            // Remember given rebind period.
            (*dhcp).offered_t2_rebind = option_value(DHCP_OPTION_IDX_T2);
        } else {
            // Calculate safe periods for rebinding (offered_t0_lease * 0.875 -> 87.5%).
            (*dhcp).offered_t2_rebind = (*dhcp).offered_t0_lease.wrapping_mul(7) / 8;
        }

        // (y)our internet address.
        (*dhcp).offered_ip_addr.addr = msg_in.add(DHCP_YIADDR).cast::<u32>().read_unaligned();

        // Subnet mask given?
        if option_given(DHCP_OPTION_IDX_SUBNET_MASK) {
            // Remember given subnet mask.
            (*dhcp).offered_sn_mask.addr = u32::from_be(option_value(DHCP_OPTION_IDX_SUBNET_MASK));
            (*dhcp).flags |= DHCP_FLAG_SUBNET_MASK_GIVEN;
        } else {
            (*dhcp).flags &= !DHCP_FLAG_SUBNET_MASK_GIVEN;
        }

        // Gateway router.
        if option_given(DHCP_OPTION_IDX_ROUTER) {
            (*dhcp).offered_gw_addr.addr = u32::from_be(option_value(DHCP_OPTION_IDX_ROUTER));
        }

        // DNS servers.
        let mut n = 0;
        while n < LWIP_DHCP_PROVIDE_DNS_SERVERS && option_given(DHCP_OPTION_IDX_DNS_SERVER + n) {
            // ESP-IDF keeps the fallback server's slot.
            if n != DNS_FALLBACK_SERVER_INDEX {
                let mut dns_addr = IpAddr::v4(0);
                dns_addr.copy_from_ip4(u32::from_be(option_value(DHCP_OPTION_IDX_DNS_SERVER + n)));
                dns_setserver(n as u8, &dns_addr);
            }
            n += 1;
        }
    }
}

/// Set a statically allocated struct dhcp to work with. Using this prevents
/// `dhcp_start` to allocate it using `mem_malloc`.
///
/// # Safety
///
/// `netif` is a live netif without DHCP, and `dhcp` writable and outlives its use.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn dhcp_set_struct(netif: *mut Netif, dhcp: *mut Dhcp) {
    lwip_assert!("netif != NULL", !netif.is_null());
    lwip_assert!("dhcp != NULL", !dhcp.is_null());
    // SAFETY: as the caller guarantees; every field of the struct is valid zeroed.
    unsafe {
        lwip_assert!(
            "netif already has a struct dhcp set",
            netif_dhcp_data(netif).is_null()
        );

        // Clear data structure.
        ptr::write_bytes(dhcp, 0, 1);
        (*dhcp).flags |= DHCP_FLAG_EXTERNAL_MEM;
        set_netif_dhcp_data(netif, dhcp);
    }
}

/// Removes a struct dhcp from a netif.
///
/// ATTENTION: Only use this when not using `dhcp_set_struct()` to allocate the struct
/// dhcp since the memory is passed back to the heap.
///
/// # Safety
///
/// `netif` is a live netif.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn dhcp_cleanup(netif: *mut Netif) {
    lwip_assert!("netif != NULL", !netif.is_null());
    // SAFETY: as the caller guarantees; a struct dhcp without the external flag came
    // from mem_malloc.
    unsafe {
        let dhcp = netif_dhcp_data(netif);
        if !dhcp.is_null() {
            if (*dhcp).flags & DHCP_FLAG_EXTERNAL_MEM == 0 {
                mem_free(dhcp.cast());
            }
            set_netif_dhcp_data(netif, ptr::null_mut());
        }
    }
}

/// Start DHCP negotiation for a network interface.
///
/// If no DHCP client instance was attached to this interface, a new client is created
/// first. If a DHCP client instance was already present, it restarts negotiation.
///
/// Returns lwIP error code:
/// - `ERR_OK` - No error
/// - `ERR_MEM` - Out of memory
///
/// # Safety
///
/// `netif` is null or a live netif.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn dhcp_start(netif: *mut Netif) -> ErrT {
    // LWIP_ERROR("netif != NULL", (netif != NULL), return ERR_ARG;);
    if netif.is_null() {
        return ERR_ARG;
    }
    // SAFETY: as the caller guarantees; the struct dhcp is the netif's or fresh.
    unsafe {
        // LWIP_ERROR("netif is not up, old style port?", netif_is_up(netif), return ERR_ARG;);
        if (*netif).flags & NETIF_FLAG_UP == 0 {
            return ERR_ARG;
        }
        let mut dhcp = netif_dhcp_data(netif);

        // Check MTU of the netif.
        if (*netif).mtu < DHCP_MAX_MSG_LEN_MIN_REQUIRED {
            return ERR_MEM;
        }

        // No DHCP client attached yet?
        if dhcp.is_null() {
            // Allocate memory for DHCP.
            dhcp = mem_malloc(size_of::<Dhcp>() as _).cast();
            if dhcp.is_null() {
                return ERR_MEM;
            }

            // Store this DHCP client in the netif.
            set_netif_dhcp_data(netif, dhcp);
        // Already has DHCP client attached.
        } else if (*dhcp).pcb_allocated != 0 {
            dhcp_dec_pcb_refcount(); // Free DHCP PCB if not needed any more.
        }
        // dhcp is cleared below, no need to reset flag.

        // Clear data structure.
        ptr::write_bytes(dhcp, 0, 1);

        // Add acd struct to list.
        acd_add(netif, &raw mut (*dhcp).acd, Some(dhcp_conflict_callback));

        if dhcp_inc_pcb_refcount() != ERR_OK {
            // Ensure DHCP PCB is allocated.
            return ERR_MEM;
        }
        (*dhcp).pcb_allocated = 1;

        if (*netif).flags & NETIF_FLAG_LINK_UP == 0 {
            // Set state INIT and wait for dhcp_network_changed() to call dhcp_discover().
            dhcp_set_state(dhcp, DHCP_STATE_INIT);
            return ERR_OK;
        }

        fine_timer_close(netif, dhcp);
        // (Re)start the DHCP negotiation.
        let result = dhcp_discover(netif);
        if result != ERR_OK {
            // Free resources allocated above.
            dhcp_release_and_stop(netif);
            return ERR_MEM;
        }
        result
    }
}

/// Inform a DHCP server of our manual configuration.
///
/// This informs DHCP servers of our fixed IP address configuration by sending an INFORM
/// message. It does not involve DHCP address configuration, it is just here to be nice
/// to the network.
///
/// # Safety
///
/// `netif` is null or a live netif.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn dhcp_inform(netif: *mut Netif) {
    // LWIP_ERROR("netif != NULL", (netif != NULL), return;);
    if netif.is_null() {
        return;
    }
    // SAFETY: as the caller guarantees; every field of a struct dhcp is valid zeroed.
    unsafe {
        if dhcp_inc_pcb_refcount() != ERR_OK {
            // Ensure DHCP PCB is allocated.
            return;
        }

        let mut dhcp: Dhcp = MaybeUninit::zeroed().assume_init();
        dhcp_set_state(&mut dhcp, DHCP_STATE_INFORMING);

        // Create and initialize the DHCP message header.
        let mut options_out_len = 0;
        let p_out = dhcp_create_msg(netif, &mut dhcp, DHCP_INFORM, &mut options_out_len);
        if !p_out.is_null() {
            let msg_out = (*p_out).payload.cast::<u8>();
            let mut len = options_out_len;
            len = dhcp_option(len, msg_out, DHCP_OPTION_MAX_MSG_SIZE, 2);
            len = dhcp_option_short(len, msg_out, (*netif).mtu);

            dhcp_append_extra_opts(netif, DHCP_STATE_INFORMING, msg_out.cast(), &mut len);
            dhcp_option_trailer(len, msg_out, p_out);

            udp_sendto_if(
                DHCP_PCB.get(),
                p_out,
                ip_addr_broadcast(),
                LWIP_IANA_PORT_DHCP_SERVER,
                netif,
            );

            pbuf_free(p_out);
        }

        dhcp_dec_pcb_refcount(); // Delete DHCP PCB if not needed any more.
    }
}

/// Handle a possible change in the network configuration.
///
/// This enters the REBOOTING state to verify that the currently bound address is still
/// valid.
///
/// # Safety
///
/// `netif` is a live netif.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn dhcp_network_changed_link_up(netif: *mut Netif) {
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);

        if dhcp.is_null() {
            return;
        }
        match (*dhcp).state {
            DHCP_STATE_REBINDING | DHCP_STATE_RENEWING | DHCP_STATE_BOUND
            | DHCP_STATE_REBOOTING => {
                (*dhcp).tries = 0;
                dhcp_reboot(netif);
            }
            DHCP_STATE_OFF => {
                // Stay off.
            }
            _ => {
                lwip_assert!(
                    "invalid dhcp->state",
                    (*dhcp).state <= DHCP_STATE_BACKING_OFF
                );
                // INIT/REQUESTING/CHECKING/BACKING_OFF restart with new 'rid' because the
                // state changes, SELECTING: continue with current 'rid' as we stay in the
                // same state.
                // Ensure we start with short timeouts, even if already discovering.
                (*dhcp).tries = 0;
                dhcp_discover(netif);
            }
        }
    }
}

/// Decline an offered lease.
///
/// Tell the DHCP server we do not accept the offered address. One reason to decline the
/// lease is when we find out the address is already in use by another host (through
/// ARP).
///
/// # Safety
///
/// `netif` is a live netif with DHCP.
unsafe fn dhcp_decline(netif: *mut Netif) -> ErrT {
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);

        // Set the state before assigning the address, as in dhcp_handle_nak.
        dhcp_set_state(dhcp, DHCP_STATE_BACKING_OFF);
        // Create and initialize the DHCP message header.
        let mut options_out_len = 0;
        let p_out = dhcp_create_msg(netif, dhcp, DHCP_DECLINE, &mut options_out_len);
        if !p_out.is_null() {
            let msg_out = (*p_out).payload.cast::<u8>();
            let mut len = options_out_len;
            len = dhcp_option(len, msg_out, DHCP_OPTION_REQUESTED_IP, 4);
            len = dhcp_option_long(len, msg_out, u32::from_be((*dhcp).offered_ip_addr.addr));

            dhcp_append_extra_opts(netif, DHCP_STATE_BACKING_OFF, msg_out.cast(), &mut len);
            dhcp_option_trailer(len, msg_out, p_out);

            // Per section 4.4.4, broadcast DECLINE messages.
            let result = udp_sendto_if_src(
                DHCP_PCB.get(),
                p_out,
                ip_addr_broadcast(),
                LWIP_IANA_PORT_DHCP_SERVER,
                netif,
                ip_addr_any(),
            );
            pbuf_free(p_out);
            result
        } else {
            ERR_MEM
        }
    }
}

/// Start the DHCP process, discover a DHCP server.
///
/// # Safety
///
/// `netif` is a live netif with DHCP.
unsafe fn dhcp_discover(netif: *mut Netif) -> ErrT {
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);

        (*dhcp).offered_ip_addr.addr = IPADDR_ANY;
        dhcp_set_state(dhcp, DHCP_STATE_SELECTING);
        // Create and initialize the DHCP message header.
        let mut options_out_len = 0;
        let p_out = dhcp_create_msg(netif, dhcp, DHCP_DISCOVER, &mut options_out_len);
        if !p_out.is_null() {
            let msg_out = (*p_out).payload.cast::<u8>();
            let mut len = options_out_len;
            len = dhcp_option(len, msg_out, DHCP_OPTION_MAX_MSG_SIZE, 2);
            len = dhcp_option_short(len, msg_out, (*netif).mtu);

            len = dhcp_option_hostname(len, msg_out, netif);

            len = dhcp_option(
                len,
                msg_out,
                DHCP_OPTION_PARAMETER_REQUEST_LIST,
                DHCP_DISCOVER_REQUEST_OPTIONS.len() as u8,
            );
            for &option in &DHCP_DISCOVER_REQUEST_OPTIONS {
                len = dhcp_option_byte(len, msg_out, option);
            }
            dhcp_append_extra_opts(netif, DHCP_STATE_SELECTING, msg_out.cast(), &mut len);
            dhcp_option_trailer(len, msg_out, p_out);

            udp_sendto_if_src(
                DHCP_PCB.get(),
                p_out,
                ip_addr_broadcast(),
                LWIP_IANA_PORT_DHCP_SERVER,
                netif,
                ip_addr_any(),
            );
            pbuf_free(p_out);
        }
        (*dhcp).tries = (*dhcp).tries.saturating_add(1);
        let msecs = request_backoff_sequence((*dhcp).tries);
        (*dhcp).request_timeout = fine_ticks(msecs);
        fine_timer_start_once(netif, dhcp);
    }
    ERR_OK
}

/// Bind the interface to the offered IP address.
///
/// # Safety
///
/// `netif` is null or a live netif.
unsafe fn dhcp_bind(netif: *mut Netif) {
    // LWIP_ERROR("dhcp_bind: netif != NULL", (netif != NULL), return;);
    if netif.is_null() {
        return;
    }
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);
        // LWIP_ERROR("dhcp_bind: dhcp != NULL", (dhcp != NULL), return;);
        if dhcp.is_null() {
            return;
        }

        // Reset time used of lease.
        (*dhcp).lease_used = 0;

        if (*dhcp).offered_t0_lease != 0xffff_ffff {
            // Set renewal period timer.
            (*dhcp).t0_timeout = timeout_from_offered((*dhcp).offered_t0_lease, 120);
        }

        // Temporary DHCP lease?
        if (*dhcp).offered_t1_renew != 0xffff_ffff {
            // Set renewal period timer.
            (*dhcp).t1_timeout =
                timeout_from_offered((*dhcp).offered_t1_renew, (*dhcp).t0_timeout >> 1);
            (*dhcp).t1_renew_time = (*dhcp).t1_timeout;
        }
        // Set renewal period timer.
        if (*dhcp).offered_t2_rebind != 0xffff_ffff {
            (*dhcp).t2_timeout =
                timeout_from_offered((*dhcp).offered_t2_rebind, ((*dhcp).t0_timeout / 8) * 7);
            (*dhcp).t2_rebind_time = (*dhcp).t2_timeout;
        }

        // If we have sub-1 minute lease, t2 and t1 will kick in at the same time.
        if (*dhcp).t1_timeout >= (*dhcp).t2_timeout && (*dhcp).t2_timeout > 0 {
            (*dhcp).t1_timeout = 0;
        }

        let sn_mask = if (*dhcp).flags & DHCP_FLAG_SUBNET_MASK_GIVEN != 0 {
            // Copy offered network mask.
            (*dhcp).offered_sn_mask
        } else {
            // Subnet mask not given, choose a safe subnet mask given the network class.
            let first_octet = (*dhcp).offered_ip_addr.addr.to_ne_bytes()[0];
            let mask: u32 = if first_octet <= 127 {
                0xff00_0000
            } else if first_octet >= 192 {
                0xffff_ff00
            } else {
                0xffff_0000
            };
            Ip4Addr { addr: mask.to_be() }
        };

        let gw_addr = (*dhcp).offered_gw_addr;

        dhcp_set_state(dhcp, DHCP_STATE_BOUND);

        fine_timer_close(netif, dhcp);
        netif_set_addr(netif, &(*dhcp).offered_ip_addr, &sn_mask, &gw_addr);
        // Interface is used by routing now that an address is set.
    }
}

/// Renew an existing DHCP lease at the involved DHCP server.
///
/// # Safety
///
/// `netif` is a live netif with DHCP.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn dhcp_renew(netif: *mut Netif) -> ErrT {
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);
        dhcp_set_state(dhcp, DHCP_STATE_RENEWING);

        // Create and initialize the DHCP message header.
        let mut options_out_len = 0;
        let p_out = dhcp_create_msg(netif, dhcp, DHCP_REQUEST, &mut options_out_len);
        let result = if !p_out.is_null() {
            let msg_out = (*p_out).payload.cast::<u8>();
            let mut len = options_out_len;
            len = dhcp_option(len, msg_out, DHCP_OPTION_MAX_MSG_SIZE, 2);
            len = dhcp_option_short(len, msg_out, (*netif).mtu);

            len = dhcp_option(
                len,
                msg_out,
                DHCP_OPTION_PARAMETER_REQUEST_LIST,
                DHCP_DISCOVER_REQUEST_OPTIONS.len() as u8,
            );
            for &option in &DHCP_DISCOVER_REQUEST_OPTIONS {
                len = dhcp_option_byte(len, msg_out, option);
            }

            len = dhcp_option_hostname(len, msg_out, netif);

            dhcp_append_extra_opts(netif, DHCP_STATE_RENEWING, msg_out.cast(), &mut len);
            dhcp_option_trailer(len, msg_out, p_out);

            let result = udp_sendto_if(
                DHCP_PCB.get(),
                p_out,
                &(*dhcp).server_ip_addr,
                LWIP_IANA_PORT_DHCP_SERVER,
                netif,
            );
            pbuf_free(p_out);
            result
        } else {
            ERR_MEM
        };
        (*dhcp).tries = (*dhcp).tries.saturating_add(1);
        // Back-off on retries, but to a maximum of 20 seconds.
        let tries = u32::from((*dhcp).tries);
        let msecs = (if tries < 10 { tries * 2000 } else { 20 * 1000 }) as u16;
        (*dhcp).request_timeout = fine_ticks(msecs);
        fine_timer_start_once(netif, dhcp);
        result
    }
}

/// Rebind with a DHCP server for an existing DHCP lease.
///
/// # Safety
///
/// `netif` is a live netif with DHCP.
unsafe fn dhcp_rebind(netif: *mut Netif) -> ErrT {
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);
        dhcp_set_state(dhcp, DHCP_STATE_REBINDING);

        // Create and initialize the DHCP message header.
        let mut options_out_len = 0;
        let p_out = dhcp_create_msg(netif, dhcp, DHCP_REQUEST, &mut options_out_len);
        let result = if !p_out.is_null() {
            let msg_out = (*p_out).payload.cast::<u8>();
            let mut len = options_out_len;
            len = dhcp_option(len, msg_out, DHCP_OPTION_MAX_MSG_SIZE, 2);
            len = dhcp_option_short(len, msg_out, (*netif).mtu);

            len = dhcp_option(
                len,
                msg_out,
                DHCP_OPTION_PARAMETER_REQUEST_LIST,
                DHCP_DISCOVER_REQUEST_OPTIONS.len() as u8,
            );
            for &option in &DHCP_DISCOVER_REQUEST_OPTIONS {
                len = dhcp_option_byte(len, msg_out, option);
            }

            len = dhcp_option_hostname(len, msg_out, netif);

            dhcp_append_extra_opts(netif, DHCP_STATE_REBINDING, msg_out.cast(), &mut len);
            dhcp_option_trailer(len, msg_out, p_out);

            // Broadcast to server.
            let result = udp_sendto_if(
                DHCP_PCB.get(),
                p_out,
                ip_addr_broadcast(),
                LWIP_IANA_PORT_DHCP_SERVER,
                netif,
            );
            pbuf_free(p_out);
            result
        } else {
            ERR_MEM
        };
        (*dhcp).tries = (*dhcp).tries.saturating_add(1);
        let tries = u32::from((*dhcp).tries);
        let msecs = (if tries < 10 { tries * 1000 } else { 10 * 1000 }) as u16;
        (*dhcp).request_timeout = fine_ticks(msecs);
        fine_timer_start_once(netif, dhcp);
        result
    }
}

/// Enter REBOOTING state to verify an existing lease.
///
/// # Safety
///
/// `netif` is a live netif with DHCP.
unsafe fn dhcp_reboot(netif: *mut Netif) -> ErrT {
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);
        dhcp_set_state(dhcp, DHCP_STATE_REBOOTING);

        // Create and initialize the DHCP message header.
        let mut options_out_len = 0;
        let p_out = dhcp_create_msg(netif, dhcp, DHCP_REQUEST, &mut options_out_len);
        let result = if !p_out.is_null() {
            let msg_out = (*p_out).payload.cast::<u8>();
            let mut len = options_out_len;
            len = dhcp_option(len, msg_out, DHCP_OPTION_MAX_MSG_SIZE, 2);
            len = dhcp_option_short(len, msg_out, DHCP_MAX_MSG_LEN_MIN_REQUIRED);

            len = dhcp_option(len, msg_out, DHCP_OPTION_REQUESTED_IP, 4);
            len = dhcp_option_long(len, msg_out, u32::from_be((*dhcp).offered_ip_addr.addr));

            len = dhcp_option(
                len,
                msg_out,
                DHCP_OPTION_PARAMETER_REQUEST_LIST,
                DHCP_DISCOVER_REQUEST_OPTIONS.len() as u8,
            );
            for &option in &DHCP_DISCOVER_REQUEST_OPTIONS {
                len = dhcp_option_byte(len, msg_out, option);
            }

            len = dhcp_option_hostname(len, msg_out, netif);

            dhcp_append_extra_opts(netif, DHCP_STATE_REBOOTING, msg_out.cast(), &mut len);
            dhcp_option_trailer(len, msg_out, p_out);

            // Broadcast to server.
            let result = udp_sendto_if(
                DHCP_PCB.get(),
                p_out,
                ip_addr_broadcast(),
                LWIP_IANA_PORT_DHCP_SERVER,
                netif,
            );
            pbuf_free(p_out);
            result
        } else {
            ERR_MEM
        };
        (*dhcp).tries = (*dhcp).tries.saturating_add(1);
        let tries = u32::from((*dhcp).tries);
        let msecs = (if tries < 10 { tries * 1000 } else { 10 * 1000 }) as u16;
        (*dhcp).request_timeout = fine_ticks(msecs);
        fine_timer_start_once(netif, dhcp);
        result
    }
}

/// Release a DHCP lease and stop DHCP statemachine (and AUTOIP if LWIP_DHCP_AUTOIP_COOP).
///
/// # Safety
///
/// `netif` is a live netif.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn dhcp_release_and_stop(netif: *mut Netif) {
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);

        if dhcp.is_null() {
            return;
        }

        // Already off? -> nothing to do.
        if (*dhcp).state == DHCP_STATE_OFF {
            return;
        }

        let mut server_ip_addr = IpAddr::v4(0);
        server_ip_addr.copy_from(&(*dhcp).server_ip_addr);

        // Clean old DHCP offer.
        (*dhcp).server_ip_addr.set_zero_ip4();
        (*dhcp).offered_ip_addr.addr = 0;
        (*dhcp).offered_sn_mask.addr = 0;
        (*dhcp).offered_gw_addr.addr = 0;
        (*dhcp).offered_t0_lease = 0;
        (*dhcp).offered_t1_renew = 0;
        (*dhcp).offered_t2_rebind = 0;
        (*dhcp).t1_renew_time = 0;
        (*dhcp).t2_rebind_time = 0;
        (*dhcp).lease_used = 0;
        (*dhcp).t0_timeout = 0;

        // Send release message when current IP was assigned via DHCP.
        if dhcp_supplied_address(netif) != 0 {
            // Create and initialize the DHCP message header.
            dhcp_set_state(dhcp, DHCP_STATE_OFF);
            let mut options_out_len = 0;
            let p_out = dhcp_create_msg(netif, dhcp, DHCP_RELEASE, &mut options_out_len);
            if !p_out.is_null() {
                let msg_out = (*p_out).payload.cast::<u8>();
                let mut len = options_out_len;
                len = dhcp_option(len, msg_out, DHCP_OPTION_SERVER_ID, 4);
                len = dhcp_option_long(len, msg_out, u32::from_be(server_ip_addr.ip4().addr));

                dhcp_append_extra_opts(netif, (*dhcp).state, msg_out.cast(), &mut len);
                dhcp_option_trailer(len, msg_out, p_out);

                udp_sendto_if(
                    DHCP_PCB.get(),
                    p_out,
                    &server_ip_addr,
                    LWIP_IANA_PORT_DHCP_SERVER,
                    netif,
                );
                pbuf_free(p_out);
            }

            // Remove IP address from interface (prevents routing from selecting this
            // interface).
            netif_set_addr(netif, ip4_addr_any(), ip4_addr_any(), ip4_addr_any());
        } else {
            dhcp_set_state(dhcp, DHCP_STATE_OFF);
        }

        acd_remove(netif, &raw mut (*dhcp).acd);

        fine_timer_close(netif, dhcp);
        if (*dhcp).pcb_allocated != 0 {
            dhcp_dec_pcb_refcount(); // Free DHCP PCB if not needed any more.
            (*dhcp).pcb_allocated = 0;
        }
    }
}

/// This function calls `dhcp_release_and_stop()` internally. @deprecated Use
/// `dhcp_release_and_stop()` instead.
///
/// # Safety
///
/// `netif` is a live netif.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn dhcp_release(netif: *mut Netif) -> ErrT {
    // SAFETY: forwarded from the caller.
    unsafe { dhcp_release_and_stop(netif) };
    ERR_OK
}

/// This function calls `dhcp_release_and_stop()` internally. @deprecated Use
/// `dhcp_release_and_stop()` instead.
///
/// # Safety
///
/// `netif` is a live netif.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn dhcp_stop(netif: *mut Netif) {
    // SAFETY: forwarded from the caller.
    unsafe { dhcp_release_and_stop(netif) };
}

/// Set the DHCP state of a DHCP client.
///
/// If the state changed, reset the number of tries.
///
/// # Safety
///
/// `dhcp` is writable.
unsafe fn dhcp_set_state(dhcp: *mut Dhcp, new_state: u8) {
    // SAFETY: as the caller guarantees.
    unsafe {
        if new_state != (*dhcp).state {
            (*dhcp).state = new_state;
            (*dhcp).tries = 0;
            (*dhcp).request_timeout = 0;
        }
    }
}

/// The options area of the message at `msg`.
///
/// # Safety
///
/// `msg` points at a whole `struct dhcp_msg`, not otherwise borrowed while the slice
/// lives.
unsafe fn options<'a>(msg: *mut u8) -> &'a mut [u8] {
    // SAFETY: as the caller guarantees.
    unsafe {
        core::slice::from_raw_parts_mut(msg.add(usize::from(DHCP_OPTIONS_OFS)), DHCP_OPTIONS_LEN)
    }
}

/// Concatenate an option type and length field to the outgoing DHCP message.
///
/// # Safety
///
/// `msg` points at a whole `struct dhcp_msg`.
unsafe fn dhcp_option(options_out_len: u16, msg: *mut u8, option_type: u8, option_len: u8) -> u16 {
    lwip_assert!(
        "dhcp_option: options_out_len + 2 + option_len <= DHCP_OPTIONS_LEN",
        usize::from(options_out_len) + 2 + usize::from(option_len) <= DHCP_OPTIONS_LEN
    );
    // SAFETY: as the caller guarantees.
    let options = unsafe { options(msg) };
    let i = usize::from(options_out_len);
    options[i] = option_type;
    options[i + 1] = option_len;
    options_out_len + 2
}

/// Concatenate a single byte to the outgoing DHCP message.
///
/// # Safety
///
/// `msg` points at a whole `struct dhcp_msg`.
unsafe fn dhcp_option_byte(options_out_len: u16, msg: *mut u8, value: u8) -> u16 {
    lwip_assert!(
        "dhcp_option_byte: options_out_len < DHCP_OPTIONS_LEN",
        usize::from(options_out_len) < DHCP_OPTIONS_LEN
    );
    // SAFETY: as the caller guarantees.
    let options = unsafe { options(msg) };
    options[usize::from(options_out_len)] = value;
    options_out_len + 1
}

/// Concatenate a two-byte value, most significant byte first.
///
/// # Safety
///
/// `msg` points at a whole `struct dhcp_msg`.
unsafe fn dhcp_option_short(options_out_len: u16, msg: *mut u8, value: u16) -> u16 {
    lwip_assert!(
        "dhcp_option_short: options_out_len + 2 <= DHCP_OPTIONS_LEN",
        usize::from(options_out_len) + 2 <= DHCP_OPTIONS_LEN
    );
    let i = usize::from(options_out_len);
    // SAFETY: as the caller guarantees.
    let options = unsafe { options(msg) };
    options[i..i + 2].copy_from_slice(&value.to_be_bytes());
    options_out_len + 2
}

/// Concatenate a four-byte value, most significant byte first.
///
/// # Safety
///
/// `msg` points at a whole `struct dhcp_msg`.
unsafe fn dhcp_option_long(options_out_len: u16, msg: *mut u8, value: u32) -> u16 {
    lwip_assert!(
        "dhcp_option_long: options_out_len + 4 <= DHCP_OPTIONS_LEN",
        usize::from(options_out_len) + 4 <= DHCP_OPTIONS_LEN
    );
    let i = usize::from(options_out_len);
    // SAFETY: as the caller guarantees.
    let options = unsafe { options(msg) };
    options[i..i + 4].copy_from_slice(&value.to_be_bytes());
    options_out_len + 4
}

/// Add the netif's host name, if it has one.
///
/// # Safety
///
/// `msg` points at a whole `struct dhcp_msg`, and `netif` is live.
unsafe fn dhcp_option_hostname(mut options_out_len: u16, msg: *mut u8, netif: *mut Netif) -> u16 {
    // SAFETY: as the caller guarantees; the host name is a C string.
    unsafe {
        let hostname = (*netif).hostname;
        if !hostname.is_null() {
            let namelen = forkpoint_libc::strlen(hostname);
            if namelen > 0 {
                // Shrink len to available bytes (need 2 bytes for OPTION_HOSTNAME and 1
                // byte for trailer).
                let available = DHCP_OPTIONS_LEN
                    .wrapping_sub(usize::from(options_out_len))
                    .wrapping_sub(3);
                lwip_assert!("DHCP: hostname is too long!", namelen <= available);
                let len = namelen.min(available);
                lwip_assert!("DHCP: hostname is too long!", len <= 0xff);
                options_out_len =
                    dhcp_option(options_out_len, msg, DHCP_OPTION_HOSTNAME, len as u8);
                for i in 0..len {
                    options_out_len =
                        dhcp_option_byte(options_out_len, msg, *hostname.add(i) as u8);
                }
            }
        }
    }
    options_out_len
}

/// Extract the DHCP message and the DHCP options.
///
/// Extract the DHCP message and the DHCP options, each into a contiguous piece of
/// memory. As a DHCP message is variable sized by its options, and also allows
/// overriding some fields for options, the easy approach is to first unfold the options
/// into a contiguous piece of memory, and use that further on.
///
/// # Safety
///
/// `p` is a live pbuf chain and `dhcp` a live client.
unsafe fn dhcp_parse_reply(p: *mut Pbuf, dhcp: *mut Dhcp) -> ErrT {
    // Clear received options.
    // SAFETY: the stack serializes access to its globals.
    unsafe { ptr::write_bytes(DHCP_RX_OPTIONS_GIVEN.as_ptr(), 0, 1) };

    // SAFETY: as the caller guarantees; `options` indexes a pbuf's payload below its
    // length, which each step checks.
    unsafe {
        // Check that beginning of dhcp_msg (up to and including chaddr) is in the first pbuf.
        if (*p).len < DHCP_SNAME_OFS {
            return ERR_BUF;
        }

        // Parse options.

        // Start with options field.
        let mut options_idx = DHCP_OPTIONS_OFS;
        // Parse options to the end of the received packet.
        let mut options_idx_max = (*p).tot_len;
        let mut parse_file_as_options = false;
        let mut parse_sname_as_options = false;
        loop {
            // 'again:'
            let mut q = p;
            let options_offset = options_idx;
            while !q.is_null() && options_idx >= (*q).len {
                options_idx -= (*q).len;
                options_idx_max = options_idx_max.wrapping_sub((*q).len);
                q = (*q).next.map_or(ptr::null_mut(), |n| n.as_ptr());
            }
            if q.is_null() {
                return ERR_BUF;
            }
            let mut offset = options_idx;
            let mut offset_max = options_idx_max;
            let mut options = (*q).payload.cast::<u8>();
            // At least 1 byte to read and no end marker, then at least 3 bytes to read?
            while !q.is_null()
                && offset < offset_max
                && *options.add(usize::from(offset)) != DHCP_OPTION_END
            {
                let op = *options.add(usize::from(offset));
                let mut len: u8;
                let mut decode_len: u8;
                let mut decode_idx: isize = -1;
                let mut val_offset = offset.wrapping_add(2);
                if val_offset < offset {
                    // Overflow.
                    return ERR_BUF;
                }
                // len byte might be in the next pbuf.
                if offset + 1 < (*q).len {
                    len = *options.add(usize::from(offset) + 1);
                } else {
                    len = match (*q).next {
                        Some(next) => *(*next.as_ptr()).payload.cast::<u8>(),
                        None => 0,
                    };
                }
                decode_len = len;
                match op {
                    // Case DHCP_OPTION_END: handled above.
                    DHCP_OPTION_PAD => {
                        // Special option: no len encoded.
                        len = 0;
                        decode_len = 0;
                    }
                    DHCP_OPTION_SUBNET_MASK => {
                        if len != 4 {
                            return ERR_VAL;
                        }
                        decode_idx = DHCP_OPTION_IDX_SUBNET_MASK as isize;
                    }
                    DHCP_OPTION_ROUTER => {
                        decode_len = 4; // Only copy the first given router.
                        if len < decode_len {
                            return ERR_VAL;
                        }
                        decode_idx = DHCP_OPTION_IDX_ROUTER as isize;
                    }
                    DHCP_OPTION_DNS_SERVER => {
                        // Special case: there might be more than one server.
                        if !len.is_multiple_of(4) {
                            return ERR_VAL;
                        }
                        // Limit number of DNS servers.
                        decode_len = len.min((4 * LWIP_DHCP_PROVIDE_DNS_SERVERS) as u8);
                        if len < decode_len {
                            return ERR_VAL;
                        }
                        decode_idx = DHCP_OPTION_IDX_DNS_SERVER as isize;
                    }
                    DHCP_OPTION_LEASE_TIME => {
                        if len != 4 {
                            return ERR_VAL;
                        }
                        decode_idx = DHCP_OPTION_IDX_LEASE_TIME as isize;
                    }
                    DHCP_OPTION_OVERLOAD => {
                        if len != 1 {
                            return ERR_VAL;
                        }
                        // Backup the overload option: it is only allowed in the options
                        // field.
                        if options_offset != DHCP_OPTIONS_OFS {
                            return ERR_VAL;
                        }
                        decode_idx = DHCP_OPTION_IDX_OVERLOAD as isize;
                    }
                    DHCP_OPTION_MESSAGE_TYPE => {
                        if len != 1 {
                            return ERR_VAL;
                        }
                        decode_idx = DHCP_OPTION_IDX_MSG_TYPE as isize;
                    }
                    DHCP_OPTION_SERVER_ID => {
                        if len != 4 {
                            return ERR_VAL;
                        }
                        decode_idx = DHCP_OPTION_IDX_SERVER_ID as isize;
                    }
                    DHCP_OPTION_T1 => {
                        if len != 4 {
                            return ERR_VAL;
                        }
                        decode_idx = DHCP_OPTION_IDX_T1 as isize;
                    }
                    DHCP_OPTION_T2 => {
                        if len != 4 {
                            return ERR_VAL;
                        }
                        decode_idx = DHCP_OPTION_IDX_T2 as isize;
                    }
                    _ => {
                        decode_len = 0;
                        // ESP-IDF's LWIP_HOOK_DHCP_PARSE_OPTION.
                        dhcp_parse_extra_opts(dhcp, (*dhcp).state, op, len, q, val_offset);
                    }
                }
                if op == DHCP_OPTION_PAD {
                    offset += 1;
                } else {
                    if u32::from(offset) + u32::from(len) + 2 > 0xFFFF {
                        // Overflow.
                        return ERR_BUF;
                    }
                    offset = offset + u16::from(len) + 2;
                    if decode_len > 0 {
                        // 'decode_next:'
                        loop {
                            lwip_assert!(
                                "check decode_idx",
                                decode_idx >= 0 && (decode_idx as usize) < DHCP_OPTION_IDX_MAX
                            );
                            let idx = decode_idx as usize;
                            if option_given(idx) {
                                break;
                            }
                            let copy_len = u16::from(decode_len.min(4));
                            let mut value = [0_u8; 4];
                            if pbuf_copy_partial(q, value.as_mut_ptr().cast(), copy_len, val_offset)
                                != copy_len
                            {
                                return ERR_BUF;
                            }
                            let value = if decode_len > 4 {
                                // Decode more than one u32_t.
                                if !decode_len.is_multiple_of(4) {
                                    return ERR_VAL;
                                }
                                set_option_given(idx, true);
                                set_option_value(idx, u32::from_be_bytes(value));
                                decode_len -= 4;
                                let next_val_offset = val_offset.wrapping_add(4);
                                if next_val_offset < val_offset {
                                    // Overflow.
                                    return ERR_BUF;
                                }
                                val_offset = next_val_offset;
                                decode_idx += 1;
                                continue;
                            } else if decode_len == 4 {
                                u32::from_be_bytes(value)
                            } else {
                                if decode_len != 1 {
                                    return ERR_VAL;
                                }
                                u32::from(value[0])
                            };
                            set_option_given(idx, true);
                            set_option_value(idx, value);
                            break;
                        }
                    }
                }
                if offset >= (*q).len {
                    offset -= (*q).len;
                    offset_max = offset_max.wrapping_sub((*q).len);
                    if offset < offset_max {
                        q = (*q).next.map_or(ptr::null_mut(), |n| n.as_ptr());
                        if q.is_null() {
                            return ERR_VAL;
                        }
                        options = (*q).payload.cast::<u8>();
                    } else {
                        // Hit the end of options.
                        return ERR_BUF;
                    }
                }
            }
            // Is this an overloaded message?
            if option_given(DHCP_OPTION_IDX_OVERLOAD) {
                let overload = option_value(DHCP_OPTION_IDX_OVERLOAD);
                set_option_given(DHCP_OPTION_IDX_OVERLOAD, false);
                if overload == DHCP_OVERLOAD_FILE {
                    parse_file_as_options = true;
                } else if overload == DHCP_OVERLOAD_SNAME {
                    parse_sname_as_options = true;
                } else if overload == DHCP_OVERLOAD_SNAME_FILE {
                    parse_sname_as_options = true;
                    parse_file_as_options = true;
                }
                // Else: invalid overload option.
            }
            if parse_file_as_options {
                // If both are overloaded, parse file first and then sname (RFC 2131 ch.
                // 4.1).
                parse_file_as_options = false;
                options_idx = DHCP_FILE_OFS;
                options_idx_max = DHCP_FILE_OFS + DHCP_FILE_LEN;
            } else if parse_sname_as_options {
                parse_sname_as_options = false;
                options_idx = DHCP_SNAME_OFS;
                options_idx_max = DHCP_SNAME_OFS + DHCP_SNAME_LEN;
            } else {
                break;
            }
        }
    }
    ERR_OK
}

/// If an incoming DHCP message is in response to us, then trigger the state machine.
unsafe extern "C" fn dhcp_recv(
    _arg: *mut c_void,
    _pcb: *mut UdpPcb,
    p: *mut Pbuf,
    addr: *const IpAddr,
    _port: u16,
) {
    // SAFETY: udp.c hands the callback a live pbuf it gives up, and ip_data names the
    // live netif it arrived on.
    unsafe {
        dhcp_recv_reply(p, addr);
        pbuf_free(p);
    }
}

/// `dhcp_recv` up to its `free_pbuf_and_return` label.
///
/// # Safety
///
/// `p` is a live pbuf chain, and ip_data names the live netif it arrived on.
unsafe fn dhcp_recv_reply(p: *mut Pbuf, addr: *const IpAddr) {
    // SAFETY: as the caller guarantees; the first pbuf holds the fixed fields
    // (DHCP_MIN_REPLY_LEN, checked before they are read).
    unsafe {
        let netif = (*ip_data()).current_input_netif;
        let dhcp = netif_dhcp_data(netif);
        let reply_msg = (*p).payload.cast::<u8>();

        // Caught DHCP message from netif that does not have DHCP enabled? -> not
        // interested.
        if dhcp.is_null() || (*dhcp).pcb_allocated == 0 {
            return;
        }

        lwip_assert!(
            "invalid server address type",
            addr.is_null() || (*addr).type_ == IPADDR_TYPE_V4
        );

        if (*p).len < DHCP_MIN_REPLY_LEN {
            return;
        }

        if *reply_msg.add(DHCP_OP) != DHCP_BOOTREPLY {
            return;
        }
        // Iterate through hardware address and match against DHCP message.
        let hwlen = usize::from((*netif).hwaddr_len);
        for i in 0..hwlen.min(DHCP_CHADDR_LEN.min(config::NETIF_MAX_HWADDR_LEN)) {
            if (*netif).hwaddr[i] != *reply_msg.add(DHCP_CHADDR + i) {
                return;
            }
        }
        // Match transaction ID against what we expected.
        if u32::from_be(reply_msg.add(DHCP_XID).cast::<u32>().read_unaligned()) != (*dhcp).xid {
            return;
        }
        // Option fields could be unfold?
        if dhcp_parse_reply(p, dhcp) != ERR_OK {
            return;
        }

        // Obtain pointer to DHCP message type.
        if !option_given(DHCP_OPTION_IDX_MSG_TYPE) {
            return;
        }

        let msg_in = (*p).payload.cast::<u8>().cast_const();
        // Read DHCP message type.
        let msg_type = option_value(DHCP_OPTION_IDX_MSG_TYPE) as u8;
        let state = (*dhcp).state;
        // Message type is DHCP ACK?
        if msg_type == DHCP_ACK {
            // In requesting state or just reconnected to the network?
            if state == DHCP_STATE_REQUESTING || state == DHCP_STATE_REBOOTING {
                dhcp_handle_ack(netif, msg_in);
                if (*netif).flags & NETIF_FLAG_ETHARP != 0 {
                    // Check if the acknowledged lease address is already in use.
                    dhcp_check(netif);
                } else {
                    // Bind interface to the acknowledged lease address.
                    dhcp_bind(netif);
                }
            // Already bound to the given lease address and using it?
            } else if state == DHCP_STATE_REBINDING || state == DHCP_STATE_RENEWING {
                dhcp_handle_ack(netif, msg_in);
                dhcp_bind(netif);
            }
        // Received a DHCP_NAK in appropriate state?
        } else if msg_type == DHCP_NAK
            && (state == DHCP_STATE_REBOOTING
                || state == DHCP_STATE_REQUESTING
                || state == DHCP_STATE_REBINDING
                || state == DHCP_STATE_RENEWING)
        {
            dhcp_handle_nak(netif);
        // Received a DHCP_OFFER in DHCP_STATE_SELECTING state?
        } else if msg_type == DHCP_OFFER && state == DHCP_STATE_SELECTING {
            // Remember offered lease.
            dhcp_handle_offer(netif, msg_in);
        }
    }
}

/// Create a DHCP request, fill in common headers.
///
/// Returns a pbuf for the message, with the message type option written and its length
/// in `options_out_len`, or null.
///
/// # Safety
///
/// `netif` is null or live, and `dhcp` null or writable.
unsafe fn dhcp_create_msg(
    netif: *mut Netif,
    dhcp: *mut Dhcp,
    message_type: u8,
    options_out_len: *mut u16,
) -> *mut Pbuf {
    // LWIP_ERROR("dhcp_create_msg: netif != NULL", (netif != NULL), return NULL;);
    // LWIP_ERROR("dhcp_create_msg: dhcp != NULL", (dhcp != NULL), return NULL;);
    if netif.is_null() || dhcp.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: as the caller guarantees; the message is a fresh pbuf in one piece.
    unsafe {
        let p_out = pbuf_alloc(
            config::PBUF_TRANSPORT_LAYER as PbufLayer,
            SIZEOF_DHCP_MSG as u16,
            PBUF_RAM,
        );
        if p_out.is_null() {
            return ptr::null_mut();
        }
        lwip_assert!(
            "dhcp_create_msg: check that first pbuf can hold struct dhcp_msg",
            usize::from((*p_out).len) >= SIZEOF_DHCP_MSG
        );

        // DHCP_REQUEST should reuse 'xid' from DHCPOFFER.
        if message_type != DHCP_REQUEST || (*dhcp).state == DHCP_STATE_REBOOTING {
            // Reuse transaction identifier in retransmissions.
            if (*dhcp).tries == 0 {
                XID.set(esp_random());
            }
            (*dhcp).xid = XID.get();
        }

        let msg_out = (*p_out).payload.cast::<u8>();
        ptr::write_bytes(msg_out, 0, SIZEOF_DHCP_MSG);

        *msg_out.add(DHCP_OP) = DHCP_BOOTREQUEST;
        // @todo: make link layer independent.
        *msg_out.add(DHCP_HTYPE) = LWIP_IANA_HWTYPE_ETHERNET;
        *msg_out.add(DHCP_HLEN) = (*netif).hwaddr_len;
        msg_out
            .add(DHCP_XID)
            .cast::<u32>()
            .write_unaligned((*dhcp).xid.to_be());
        // We don't need the broadcast flag since we can receive unicast traffic before
        // being fully configured!
        // Set ciaddr to netif->ip_addr based on message_type and state.
        let state = (*dhcp).state;
        if message_type == DHCP_INFORM
            || message_type == DHCP_DECLINE
            || message_type == DHCP_RELEASE
            || (message_type == DHCP_REQUEST
                && (state == DHCP_STATE_RENEWING || state == DHCP_STATE_REBINDING))
        {
            msg_out
                .add(DHCP_CIADDR)
                .cast::<u32>()
                .write_unaligned((*netif).ip4_addr().addr);
        }
        for i in 0..DHCP_CHADDR_LEN.min(config::NETIF_MAX_HWADDR_LEN) {
            // Copy netif hardware address (padded with zeroes through memset already).
            *msg_out.add(DHCP_CHADDR + i) = (*netif).hwaddr[i];
        }
        msg_out
            .add(DHCP_COOKIE)
            .cast::<u32>()
            .write_unaligned(DHCP_MAGIC_COOKIE.to_be());
        // Add option MESSAGE_TYPE.
        let mut len = dhcp_option(0, msg_out, DHCP_OPTION_MESSAGE_TYPE, 1);
        len = dhcp_option_byte(len, msg_out, message_type);
        if !options_out_len.is_null() {
            *options_out_len = len;
        }
        p_out
    }
}

/// Add a DHCP message trailer.
///
/// Adds the END option to the DHCP message, and if necessary, up to three padding bytes.
///
/// # Safety
///
/// `msg` is `p_out`'s whole `struct dhcp_msg`.
unsafe fn dhcp_option_trailer(mut options_out_len: u16, msg: *mut u8, p_out: *mut Pbuf) {
    // SAFETY: as the caller guarantees.
    unsafe {
        let options = options(msg);
        // The options can fill the message: ESP-IDF's vendor class option leaves no room
        // for the end marker. C then writes the marker one byte past the message,
        // outside the pbuf, and sends the message without it, as pbuf_realloc below does
        // not grow a pbuf. The same bytes go out here, without that write.
        if let Some(end) = options.get_mut(usize::from(options_out_len)) {
            *end = DHCP_OPTION_END;
        }
        options_out_len += 1;
        // Packet is too small, or not 4 byte aligned?
        while (options_out_len < DHCP_MIN_OPTIONS_LEN || options_out_len & 3 != 0)
            && usize::from(options_out_len) < DHCP_OPTIONS_LEN
        {
            // Add a fill/padding byte.
            options[usize::from(options_out_len)] = 0;
            options_out_len += 1;
        }
        // Shrink the pbuf to the actual content length.
        pbuf_realloc(
            p_out,
            (SIZEOF_DHCP_MSG - DHCP_OPTIONS_LEN + usize::from(options_out_len)) as u16,
        );
    }
}

/// Check DHCP negotiation is done for a network interface.
///
/// Returns 1 if DHCP supplied the netif's address (states BOUND, RENEWING or
/// REBINDING), 0 otherwise.
///
/// # Safety
///
/// `netif` is null or a live netif.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn dhcp_supplied_address(netif: *const Netif) -> u8 {
    if netif.is_null() {
        return 0;
    }
    // SAFETY: as the caller guarantees.
    unsafe {
        let dhcp = netif_dhcp_data(netif);
        if dhcp.is_null() {
            return 0;
        }
        let state = (*dhcp).state;
        u8::from(
            state == DHCP_STATE_BOUND
                || state == DHCP_STATE_RENEWING
                || state == DHCP_STATE_REBINDING,
        )
    }
}

#[cfg(test)]
mod tests;
