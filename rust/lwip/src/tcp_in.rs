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

//! Transmission Control Protocol, incoming traffic, from `src/core/tcp_in.c`, as ESP-IDF
//! configures it: IPv4 and IPv6, checksums checked, the MSS option only, `SO_REUSE`, the
//! listen backlog, out-of-sequence queueing capped at `TCP_OOSEQ_MAX_PBUFS`, ND6
//! reachability hints, and ESP-IDF's changes to trimming segments against the window and
//! the out-of-sequence queue (`build.rs` refuses the rest).
//!
//! The input processing functions of the TCP layer.
//!
//! These functions are generally called in the order (`ip_input()` ->) `tcp_input()`
//! -> `tcp_process()` -> `tcp_receive()` (-> application).

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::ptr;

use crate::config;
use crate::global::Global;
use crate::links::*;
use crate::types::*;

const TCP_MSS: u16 = config::TCP_MSS as u16;
const TCP_WND: TcpWnd = config::TCP_WND as TcpWnd;
const TCP_SYNMAXRTX: u8 = config::TCP_SYNMAXRTX as u8;
const TCP_OOSEQ_PBUFS_LIMIT: u16 = config::TCP_OOSEQ_PBUFS_LIMIT_ as u16;

/// `SOF_INHERITED`: socket options inherited by a connection from its listener.
const SOF_INHERITED: u8 = SOF_REUSEADDR | 0x08;

// `recv_flags` bits.
/// Connection was reset.
const TF_RESET: u8 = 0x08;
/// Connection was successfully closed.
const TF_CLOSED: u8 = 0x10;
/// Connection was closed by the remote end.
const TF_GOT_FIN: u8 = 0x20;

/// `PBUF_FLAG_PUSH`: the pbuf holds data the sender pushed.
const PBUF_FLAG_PUSH: u8 = 0x01;

// TCP options.
const LWIP_TCP_OPT_EOL: u8 = 0;
const LWIP_TCP_OPT_NOP: u8 = 1;
const LWIP_TCP_OPT_MSS: u8 = 2;
const LWIP_TCP_OPT_LEN_MSS: u8 = 4;

/// `LWIP_TCP_CALC_INITIAL_CWND(mss)`: RFC 3390's initial window.
fn lwip_tcp_calc_initial_cwnd(mss: u16) -> TcpWnd {
    (4 * u32::from(mss)).min((2 * u32::from(mss)).max(4380)) as TcpWnd
}

// These variables are global to all functions involved in the input processing of TCP
// segments. They are set by the tcp_input() function.
static INSEG: Global<TcpSeg> = Global::new(TcpSeg {
    next: ptr::null_mut(),
    p: ptr::null_mut(),
    len: 0,
    flags: 0,
    tcphdr: ptr::null_mut(),
});
static TCPHDR: Global<*mut TcpHdr> = Global::new(ptr::null_mut());
static TCPHDR_OPTLEN: Global<u16> = Global::new(0);
static TCPHDR_OPT1LEN: Global<u16> = Global::new(0);
static TCPHDR_OPT2: Global<*mut u8> = Global::new(ptr::null_mut());
static TCP_OPTIDX: Global<u16> = Global::new(0);
static SEQNO: Global<u32> = Global::new(0);
static ACKNO: Global<u32> = Global::new(0);
static RECV_ACKED: Global<TcpWnd> = Global::new(0);
static TCPLEN: Global<u16> = Global::new(0);
static FLAGS: Global<u8> = Global::new(0);

static RECV_FLAGS: Global<u8> = Global::new(0);
static RECV_DATA: Global<*mut Pbuf> = Global::new(ptr::null_mut());

/// The PCB whose input is being processed.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub static tcp_input_pcb: Global<*mut TcpPcb> = Global::new(ptr::null_mut());

/// `&inseg`.
fn inseg() -> *mut TcpSeg {
    INSEG.as_ptr()
}

fn seqno() -> u32 {
    SEQNO.get()
}

fn ackno() -> u32 {
    ACKNO.get()
}

fn tcplen() -> u16 {
    TCPLEN.get()
}

fn flags() -> u8 {
    FLAGS.get()
}

fn recv_flags_set(f: u8) {
    RECV_FLAGS.set(RECV_FLAGS.get() | f);
}

/// `tcp_pcbs_sane()`, which `tcp_priv.h` defines as 1 without `TCP_DEBUG`,
/// `TCP_INPUT_DEBUG`, or `TCP_OUTPUT_DEBUG`; `build.rs` requires all three off.
const fn tcp_pcbs_sane() -> bool {
    true
}

/// `TCP_SEQ_LT(a, b)` and the comparisons built on it.
fn tcp_seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn tcp_seq_leq(a: u32, b: u32) -> bool {
    !tcp_seq_lt(b, a)
}

fn tcp_seq_gt(a: u32, b: u32) -> bool {
    tcp_seq_lt(b, a)
}

fn tcp_seq_geq(a: u32, b: u32) -> bool {
    tcp_seq_leq(b, a)
}

fn tcp_seq_between(a: u32, b: u32, c: u32) -> bool {
    tcp_seq_geq(a, b) && tcp_seq_leq(a, c)
}

/// `TCPH_FLAGS(phdr)`.
///
/// # Safety
///
/// `h` is a live header.
unsafe fn tcph_flags(h: *const TcpHdr) -> u8 {
    // SAFETY: as the caller guarantees.
    let v = unsafe { ptr::addr_of!((*h)._hdrlen_rsvd_flags).read_unaligned() };
    (u16::from_be(v) & u16::from(TCP_FLAGS)) as u8
}

/// `TCPH_SET_FLAG(phdr, flags)`.
///
/// # Safety
///
/// `h` is a live header.
unsafe fn tcph_set_flag(h: *mut TcpHdr, flags: u8) {
    // SAFETY: as the caller guarantees.
    unsafe {
        let field = ptr::addr_of_mut!((*h)._hdrlen_rsvd_flags);
        field.write_unaligned(field.read_unaligned() | u16::from(flags).to_be());
    }
}

/// `TCPH_FLAGS_SET(phdr, flags)`.
///
/// # Safety
///
/// `h` is a live header.
unsafe fn tcph_flags_set(h: *mut TcpHdr, flags: u8) {
    // SAFETY: as the caller guarantees.
    unsafe {
        let field = ptr::addr_of_mut!((*h)._hdrlen_rsvd_flags);
        field.write_unaligned(
            (field.read_unaligned() & (!u16::from(TCP_FLAGS)).to_be()) | u16::from(flags).to_be(),
        );
    }
}

/// An input segment's sequence number, which `tcp_input` converted to host order in its
/// header.
///
/// # Safety
///
/// `seg` is a live segment with its header.
unsafe fn in_seqno(seg: *const TcpSeg) -> u32 {
    // SAFETY: as the caller guarantees.
    unsafe { ptr::addr_of!((*(*seg).tcphdr).seqno).read_unaligned() }
}

/// An output segment's sequence number, in network order in its header.
///
/// # Safety
///
/// `seg` is a live segment with its header.
unsafe fn out_seqno(seg: *const TcpSeg) -> u32 {
    // SAFETY: as the caller guarantees.
    unsafe { u32::from_be(in_seqno(seg)) }
}

/// `TCP_TCPLEN(seg)`.
///
/// # Safety
///
/// `seg` is a live segment with its header.
unsafe fn tcp_tcplen(seg: *const TcpSeg) -> u32 {
    // SAFETY: as the caller guarantees.
    unsafe {
        u32::from((*seg).len) + u32::from(tcph_flags((*seg).tcphdr) & (TCP_FIN | TCP_SYN) != 0)
    }
}

/// The header of the segment being processed, whose ports and window `tcp_input`
/// converted to host order.
///
/// # Safety
///
/// Only during input processing.
unsafe fn hdr_src() -> u16 {
    // SAFETY: as the caller guarantees.
    unsafe { ptr::addr_of!((*TCPHDR.get()).src).read_unaligned() }
}

/// As `hdr_src`.
///
/// # Safety
///
/// Only during input processing.
unsafe fn hdr_dest() -> u16 {
    // SAFETY: as the caller guarantees.
    unsafe { ptr::addr_of!((*TCPHDR.get()).dest).read_unaligned() }
}

/// As `hdr_src`.
///
/// # Safety
///
/// Only during input processing.
unsafe fn hdr_wnd() -> u16 {
    // SAFETY: as the caller guarantees.
    unsafe { ptr::addr_of!((*TCPHDR.get()).wnd).read_unaligned() }
}

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

/// `tcp_ack(pcb)`: delay the ACK, unless one is already delayed.
///
/// # Safety
///
/// `pcb` is live.
unsafe fn tcp_ack(pcb: *mut TcpPcb) {
    // SAFETY: as the caller guarantees.
    unsafe {
        if (*pcb).flags & TF_ACK_DELAY != 0 {
            tcp_clear_flags(pcb, TF_ACK_DELAY);
            tcp_ack_now(pcb);
        } else {
            tcp_set_flags(pcb, TF_ACK_DELAY);
        }
    }
}

/// `TCP_WND_INC(wnd, inc)`: increments and holds at max value rather than rollover.
fn tcp_wnd_inc(wnd: &mut TcpWnd, inc: TcpWnd) {
    *wnd = wnd.saturating_add(inc);
}

/// `TCP_REG(pcbs, npcb)`.
///
/// # Safety
///
/// `pcbs` is a list head and `npcb` a live PCB on no list.
unsafe fn tcp_reg(pcbs: *mut *mut TcpPcb, npcb: *mut TcpPcb) {
    // SAFETY: as the caller guarantees.
    unsafe {
        (*npcb).next = *pcbs;
        *pcbs = npcb;
        tcp_timer_needed();
    }
}

/// `TCP_RMV(pcbs, npcb)`.
///
/// # Safety
///
/// `pcbs` is a list head and `npcb` a live PCB.
unsafe fn tcp_rmv(pcbs: *mut *mut TcpPcb, npcb: *mut TcpPcb) {
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
unsafe fn tcp_reg_active(npcb: *mut TcpPcb) {
    // SAFETY: as the caller guarantees.
    unsafe {
        tcp_reg(tcp_active_pcbs_head(), npcb);
        *tcp_active_pcbs_changed() = 1;
    }
}

/// `TCP_RMV_ACTIVE(npcb)`.
///
/// # Safety
///
/// `npcb` is a live PCB.
unsafe fn tcp_rmv_active(npcb: *mut TcpPcb) {
    // SAFETY: as the caller guarantees.
    unsafe {
        tcp_rmv(tcp_active_pcbs_head(), npcb);
        *tcp_active_pcbs_changed() = 1;
    }
}

/// `TCP_EVENT_ERR(last_state, errf, arg, err)`.
///
/// # Safety
///
/// `errf` is null or a PCB's error callback, and `arg` its argument.
unsafe fn tcp_event_err(errf: TcpErrFn, arg: *mut c_void, err: ErrT) {
    if let Some(errf) = errf {
        // SAFETY: as the caller guarantees.
        unsafe { errf(arg, err) };
    }
}

/// `TCP_EVENT_RECV(pcb, p, err, ret)`.
///
/// # Safety
///
/// `pcb` is live and `p` null or a pbuf the callback takes.
unsafe fn tcp_event_recv(pcb: *mut TcpPcb, p: *mut Pbuf, err: ErrT) -> ErrT {
    // SAFETY: as the caller guarantees.
    unsafe {
        match (*pcb).recv {
            Some(recv) => recv((*pcb).callback_arg, pcb, p, err),
            None => tcp_recv_null(ptr::null_mut(), pcb, p, err),
        }
    }
}

/// `ip_current_dest_addr()` and `ip_current_src_addr()`.
fn ip_current_dest_addr() -> *const IpAddr {
    // SAFETY: only the field's address is taken.
    unsafe { &raw const (*ip_data()).current_iphdr_dest }
}

fn ip_current_src_addr() -> *const IpAddr {
    // SAFETY: only the field's address is taken.
    unsafe { &raw const (*ip_data()).current_iphdr_src }
}

/// `tcp_eff_send_mss(sendmss, src, dest)`: through the route to `dest`.
///
/// # Safety
///
/// `src` and `dest` are valid.
unsafe fn tcp_eff_send_mss(sendmss: u16, src: *const IpAddr, dest: *const IpAddr) -> u16 {
    // SAFETY: as the caller guarantees.
    unsafe {
        let netif = if (*dest).is_v6() {
            ip6_route((*src).ip6(), (*dest).ip6())
        } else {
            ip4_route_src((*src).ip4(), (*dest).ip4())
        };
        tcp_eff_send_mss_netif(sendmss, netif, dest)
    }
}

/// The initial input processing of TCP. It verifies the TCP header, demultiplexes the
/// segment between the PCBs and passes it on to `tcp_process()`, which implements the
/// TCP finite state machine. This function is called by the IP layer (in
/// `ip_input()`).
///
/// # Safety
///
/// `p` is a live pbuf chain at the TCP header, which this takes; `inp` the netif it
/// arrived on; and `ip_data` describes the packet.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_input(p: *mut Pbuf, inp: *mut Netif) {
    lwip_assert!("tcp_input: invalid pbuf", !p.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        if !tcp_input_packet(p, inp) {
            // dropped:
            pbuf_free(p);
        }
    }
}

/// `tcp_input` up to its `dropped` label: returns false to drop `p`, true once `p` has
/// been handed on or freed.
///
/// # Safety
///
/// As `tcp_input`.
unsafe fn tcp_input_packet(p: *mut Pbuf, _inp: *mut Netif) -> bool {
    // SAFETY: as the caller guarantees; PCBs on the lists are live.
    unsafe {
        let ipd = ip_data();
        let tcphdr = (*p).payload.cast::<TcpHdr>();
        TCPHDR.set(tcphdr);

        // Check that TCP header fits in payload.
        if (*p).len < TCP_HLEN {
            // Drop short packets.
            return false;
        }

        // Don't even process incoming broadcasts/multicasts.
        let dest = &*ip_current_dest_addr();
        if (!dest.is_v6() && ip4_addr_isbroadcast_u32(dest.ip4().addr, (*ipd).current_netif) != 0)
            || dest.is_multicast()
        {
            return false;
        }

        // Verify TCP checksum.
        let chksum = ip_chksum_pseudo(
            p,
            IP_PROTO_TCP,
            (*p).tot_len,
            ip_current_src_addr(),
            ip_current_dest_addr(),
        );
        if chksum != 0 {
            return false;
        }

        // Sanity-check header length.
        let hdrlen_bytes =
            ((u16::from_be(ptr::addr_of!((*tcphdr)._hdrlen_rsvd_flags).read_unaligned()) >> 12)
                << 2) as u8;
        if u16::from(hdrlen_bytes) < TCP_HLEN || u16::from(hdrlen_bytes) > (*p).tot_len {
            return false;
        }

        // Move the payload pointer in the pbuf so that it points to the TCP data instead
        // of the TCP header.
        TCPHDR_OPTLEN.set(u16::from(hdrlen_bytes) - TCP_HLEN);
        TCPHDR_OPT2.set(ptr::null_mut());
        if (*p).len >= u16::from(hdrlen_bytes) {
            // All options are in the first pbuf.
            TCPHDR_OPT1LEN.set(TCPHDR_OPTLEN.get());
            pbuf_remove_header(p, usize::from(hdrlen_bytes)); // Cannot fail.
        } else {
            // TCP header fits into first pbuf, options don't - data is in the next pbuf.
            // There must be a next pbuf, due to hdrlen_bytes sanity check above.
            let next = (*p).next.map_or(ptr::null_mut(), |n| n.as_ptr());
            lwip_assert!("p->next != NULL", !next.is_null());

            // Advance over the TCP header (cannot fail).
            pbuf_remove_header(p, usize::from(TCP_HLEN));

            // Determine how long the first and second parts of the options are.
            TCPHDR_OPT1LEN.set((*p).len);
            let opt2len = TCPHDR_OPTLEN.get().wrapping_sub(TCPHDR_OPT1LEN.get());

            // Options continue in the next pbuf: set p to zero length and hide the
            // options in the next pbuf (adjusting p->tot_len).
            pbuf_remove_header(p, usize::from(TCPHDR_OPT1LEN.get()));

            // Check that the options fit in the second pbuf.
            if opt2len > (*next).len {
                // Drop short packets.
                return false;
            }

            // Remember the pointer to the second part of the options.
            TCPHDR_OPT2.set((*next).payload.cast());

            // Advance p->next to point after the options, and manually adjust p->tot_len
            // to keep it consistent with the changed p->next.
            pbuf_remove_header(next, usize::from(opt2len));
            (*p).tot_len = (*p).tot_len.wrapping_sub(opt2len);

            lwip_assert!("p->len == 0", (*p).len == 0);
            lwip_assert!(
                "p->tot_len == p->next->tot_len",
                (*p).tot_len == (*next).tot_len
            );
        }

        // Convert fields in TCP header to host byte order.
        let src = ptr::addr_of_mut!((*tcphdr).src);
        src.write_unaligned(u16::from_be(src.read_unaligned()));
        let dst = ptr::addr_of_mut!((*tcphdr).dest);
        dst.write_unaligned(u16::from_be(dst.read_unaligned()));
        let sq = ptr::addr_of_mut!((*tcphdr).seqno);
        sq.write_unaligned(u32::from_be(sq.read_unaligned()));
        SEQNO.set(sq.read_unaligned());
        let ak = ptr::addr_of_mut!((*tcphdr).ackno);
        ak.write_unaligned(u32::from_be(ak.read_unaligned()));
        ACKNO.set(ak.read_unaligned());
        let wnd = ptr::addr_of_mut!((*tcphdr).wnd);
        wnd.write_unaligned(u16::from_be(wnd.read_unaligned()));

        FLAGS.set(tcph_flags(tcphdr));
        TCPLEN.set((*p).tot_len);
        if flags() & (TCP_FIN | TCP_SYN) != 0 {
            TCPLEN.set(tcplen().wrapping_add(1));
            if tcplen() < (*p).tot_len {
                // u16_t overflow, cannot handle this.
                return false;
            }
        }

        let input_idx = (*(*ipd).current_input_netif).index();

        // Demultiplex an incoming segment. First, we check if it is destined for an
        // active connection.
        let mut prev: *mut TcpPcb = ptr::null_mut();
        let mut pcb = *tcp_active_pcbs_head();
        while !pcb.is_null() {
            lwip_assert!(
                "tcp_input: active pcb->state != CLOSED",
                (*pcb).state != CLOSED
            );
            lwip_assert!(
                "tcp_input: active pcb->state != TIME-WAIT",
                (*pcb).state != TIME_WAIT
            );
            lwip_assert!(
                "tcp_input: active pcb->state != LISTEN",
                (*pcb).state != LISTEN
            );

            // Check if PCB is bound to specific netif.
            if (*pcb).netif_idx != NETIF_NO_INDEX && (*pcb).netif_idx != input_idx {
                prev = pcb;
                pcb = (*pcb).next;
                continue;
            }

            if (*pcb).remote_port == hdr_src()
                && (*pcb).local_port == hdr_dest()
                && (*pcb).remote_ip.eq_addr(&*ip_current_src_addr())
                && (*pcb).local_ip.eq_addr(&*ip_current_dest_addr())
            {
                // Move this PCB to the front of the list so that subsequent lookups will
                // be faster (we exploit locality in TCP segment arrivals).
                lwip_assert!(
                    "tcp_input: pcb->next != pcb (before cache)",
                    (*pcb).next != pcb
                );
                if !prev.is_null() {
                    (*prev).next = (*pcb).next;
                    (*pcb).next = *tcp_active_pcbs_head();
                    *tcp_active_pcbs_head() = pcb;
                }
                lwip_assert!(
                    "tcp_input: pcb->next != pcb (after cache)",
                    (*pcb).next != pcb
                );
                break;
            }
            prev = pcb;
            pcb = (*pcb).next;
        }

        if pcb.is_null() {
            // If it did not go to an active connection, we check the connections in the
            // TIME-WAIT state.
            let mut twpcb = *tcp_tw_pcbs_head();
            while !twpcb.is_null() {
                lwip_assert!(
                    "tcp_input: TIME-WAIT pcb->state == TIME-WAIT",
                    (*twpcb).state == TIME_WAIT
                );

                // Check if PCB is bound to specific netif.
                if ((*twpcb).netif_idx == NETIF_NO_INDEX || (*twpcb).netif_idx == input_idx)
                    && (*twpcb).remote_port == hdr_src()
                    && (*twpcb).local_port == hdr_dest()
                    && (*twpcb).remote_ip.eq_addr(&*ip_current_src_addr())
                    && (*twpcb).local_ip.eq_addr(&*ip_current_dest_addr())
                {
                    // We don't really care enough to move this PCB to the front of the
                    // list since we are not very likely to receive that many segments
                    // for connections in TIME-WAIT.
                    tcp_timewait_input(twpcb);
                    pbuf_free(p);
                    return true;
                }
                twpcb = (*twpcb).next;
            }

            // Finally, if we still did not get a match, we check all PCBs that are
            // LISTENing for incoming connections.
            let mut prev: *mut TcpPcb = ptr::null_mut();
            let mut lpcb_prev: *mut TcpPcb = ptr::null_mut();
            let mut lpcb_any: *mut TcpPcbListen = ptr::null_mut();
            let mut lpcb = (*tcp_listen_pcbs_head()).cast::<TcpPcbListen>();
            while !lpcb.is_null() {
                // Check if PCB is bound to specific netif.
                if (*lpcb).netif_idx != NETIF_NO_INDEX && (*lpcb).netif_idx != input_idx {
                    prev = lpcb.cast();
                    lpcb = (*lpcb).next;
                    continue;
                }

                if (*lpcb).local_port == hdr_dest() {
                    if (*lpcb).local_ip.type_ == IPADDR_TYPE_ANY {
                        // Found an ANY TYPE (IPv4/IPv6) match.
                        lpcb_any = lpcb;
                        lpcb_prev = prev;
                    } else if (*lpcb).local_ip.type_ == (*ip_current_dest_addr()).type_ {
                        if (*lpcb).local_ip.eq_addr(&*ip_current_dest_addr()) {
                            // Found an exact match.
                            break;
                        } else if (*lpcb).local_ip.is_any() {
                            // Found an ANY-match.
                            lpcb_any = lpcb;
                            lpcb_prev = prev;
                        }
                    }
                }
                prev = lpcb.cast();
                lpcb = (*lpcb).next;
            }
            // First try specific local IP.
            if lpcb.is_null() {
                // Only pass to ANY if no specific local IP has been found.
                lpcb = lpcb_any;
                prev = lpcb_prev;
            }
            if !lpcb.is_null() {
                // Move this PCB to the front of the list so that subsequent lookups will be
                // faster (we exploit locality in TCP segment arrivals).
                if !prev.is_null() {
                    (*prev.cast::<TcpPcbListen>()).next = (*lpcb).next;
                    // Our successor is the remainder of the listening list.
                    (*lpcb).next = (*tcp_listen_pcbs_head()).cast();
                    // Put this listening pcb at the head of the listening list.
                    *tcp_listen_pcbs_head() = lpcb.cast();
                }

                tcp_listen_input(lpcb);
                pbuf_free(p);
                return true;
            }
        }

        if !pcb.is_null() {
            // The incoming segment belongs to a connection.
            tcp_input_connection(pcb, p);
        } else {
            // If no matching PCB was found, send a TCP RST (reset) to the sender.
            if tcph_flags(tcphdr) & TCP_RST == 0 {
                tcp_rst_netif(
                    (*ipd).current_input_netif,
                    ackno(),
                    seqno().wrapping_add(u32::from(tcplen())),
                    ip_current_dest_addr(),
                    ip_current_src_addr(),
                    hdr_dest(),
                    hdr_src(),
                );
            }
            pbuf_free(p);
        }
    }

    lwip_assert!("tcp_input: tcp_pcbs_sane()", tcp_pcbs_sane());
    true
}

/// The part of `tcp_input` for a segment that belongs to connection `pcb`.
///
/// # Safety
///
/// As `tcp_input`, with `pcb` the live connection.
unsafe fn tcp_input_connection(pcb: *mut TcpPcb, p: *mut Pbuf) {
    // SAFETY: as the caller guarantees; callbacks may free the PCB, which each step
    // checks for as tcp_in.c does.
    unsafe {
        // Set up a tcp_seg structure.
        let seg = inseg();
        (*seg).next = ptr::null_mut();
        (*seg).len = (*p).tot_len;
        (*seg).p = p;
        (*seg).tcphdr = TCPHDR.get();

        RECV_DATA.set(ptr::null_mut());
        RECV_FLAGS.set(0);
        RECV_ACKED.set(0);

        if flags() & TCP_PSH != 0 {
            (*p).flags |= PBUF_FLAG_PUSH;
        }

        'aborted: {
            // If there is data which was previously "refused" by upper layer.
            // Pcb has been aborted or refused data is still refused and the new segment
            // contains data.
            if !(*pcb).refused_data.is_null()
                && (tcp_process_refused_data(pcb) == ERR_ABRT
                    || (!(*pcb).refused_data.is_null() && tcplen() > 0))
            {
                if (*pcb).rcv_ann_wnd == 0 {
                    // This is a zero-window probe, we respond to it with current RCV.NXT
                    // and drop the data segment.
                    tcp_send_empty_ack(pcb);
                }
                break 'aborted;
            }
            tcp_input_pcb.set(pcb);
            let err = tcp_process(pcb);
            // A return value of ERR_ABRT means that tcp_abort() was called and that the
            // pcb has been freed. If so, we don't do anything.
            if err != ERR_ABRT {
                if RECV_FLAGS.get() & TF_RESET != 0 {
                    // TF_RESET means that the connection was reset by the other end. We
                    // then call the error callback to inform the application that the
                    // connection is dead before we deallocate the PCB.
                    tcp_event_err((*pcb).errf, (*pcb).callback_arg, ERR_RST);
                    tcp_pcb_remove(tcp_active_pcbs_head(), pcb);
                    tcp_free(pcb);
                } else {
                    // If the application has registered a "sent" function to be called
                    // when new send buffer space is available, we call it now.
                    if RECV_ACKED.get() > 0 {
                        let acked16 = RECV_ACKED.get();
                        // TCP_EVENT_SENT(pcb, acked16, err).
                        let err = match (*pcb).sent {
                            Some(sent) => sent((*pcb).callback_arg, pcb, acked16),
                            None => ERR_OK,
                        };
                        if err == ERR_ABRT {
                            break 'aborted;
                        }
                        RECV_ACKED.set(0);
                    }
                    if tcp_input_delayed_close(pcb) {
                        break 'aborted;
                    }
                    let recv_data = RECV_DATA.get();
                    if !recv_data.is_null() {
                        lwip_assert!("pcb->refused_data == NULL", (*pcb).refused_data.is_null());
                        if (*pcb).flags & TF_RXCLOSED != 0 {
                            // Received data although already closed -> abort (send RST) to
                            // notify the remote host that not all data has been processed.
                            pbuf_free(recv_data);
                            tcp_abort(pcb);
                            break 'aborted;
                        }

                        // Notify application that data has been received.
                        let err = tcp_event_recv(pcb, recv_data, ERR_OK);
                        if err == ERR_ABRT {
                            break 'aborted;
                        }

                        // If the upper layer can't receive this data, store it.
                        if err != ERR_OK {
                            (*pcb).refused_data = recv_data;
                        }
                    }

                    // If a FIN segment was received, we call the callback function with a
                    // NULL buffer to indicate EOF.
                    if RECV_FLAGS.get() & TF_GOT_FIN != 0 {
                        if !(*pcb).refused_data.is_null() {
                            // Delay this if we have refused data.
                            (*(*pcb).refused_data).flags |= PBUF_FLAG_TCP_FIN;
                        } else {
                            // Correct rcv_wnd as the application won't call tcp_recved()
                            // for the FIN's seqno.
                            if (*pcb).rcv_wnd != TCP_WND {
                                (*pcb).rcv_wnd += 1;
                            }
                            // TCP_EVENT_CLOSED(pcb, err).
                            let err = match (*pcb).recv {
                                Some(recv) => {
                                    recv((*pcb).callback_arg, pcb, ptr::null_mut(), ERR_OK)
                                }
                                None => ERR_OK,
                            };
                            if err == ERR_ABRT {
                                break 'aborted;
                            } else if err == ERR_MEM {
                                tcp_set_flags(pcb, TF_CLOSEPEND);
                            }
                        }
                    }

                    tcp_input_pcb.set(ptr::null_mut());
                    if tcp_input_delayed_close(pcb) {
                        break 'aborted;
                    }
                    // Try to send something out.
                    tcp_output(pcb);
                }
            }
        }
        // Jump target if pcb has been aborted in a callback (by calling tcp_abort()).
        // Below this line, 'pcb' may not be dereferenced!
        tcp_input_pcb.set(ptr::null_mut());
        RECV_DATA.set(ptr::null_mut());

        // Give up our reference to inseg.p.
        if !(*seg).p.is_null() {
            pbuf_free((*seg).p);
            (*seg).p = ptr::null_mut();
        }
    }
}

/// Called from tcp_input to check for TF_CLOSED flag. This results in closing and
/// deallocating a pcb at the correct time. Returns true if the pcb has been closed and
/// deallocated.
///
/// # Safety
///
/// `pcb` is live.
unsafe fn tcp_input_delayed_close(pcb: *mut TcpPcb) -> bool {
    lwip_assert!("tcp_input_delayed_close: invalid pcb", !pcb.is_null());

    if RECV_FLAGS.get() & TF_CLOSED != 0 {
        // SAFETY: as the caller guarantees.
        unsafe {
            // The connection has been closed and we will deallocate the PCB.
            if (*pcb).flags & TF_RXCLOSED == 0 {
                // Connection closed although the application has only shut down the tx
                // side: call the PCB's err callback and indicate the closure to ensure the
                // application doesn't continue using the PCB.
                tcp_event_err((*pcb).errf, (*pcb).callback_arg, ERR_CLSD);
            }
            tcp_pcb_remove(tcp_active_pcbs_head(), pcb);
            tcp_free(pcb);
        }
        return true;
    }
    false
}

/// Called by `tcp_input()` when a segment arrives for a listening connection (from
/// `tcp_input()`).
///
/// # Safety
///
/// `pcb` is a live listen PCB, during input processing.
unsafe fn tcp_listen_input(pcb: *mut TcpPcbListen) {
    if flags() & TCP_RST != 0 {
        // An incoming RST should be ignored. Return.
        return;
    }

    lwip_assert!("tcp_listen_input: invalid pcb", !pcb.is_null());

    // SAFETY: as the caller guarantees; the new PCB is fresh.
    unsafe {
        // In the LISTEN state, we check for incoming SYN segments, creates a new PCB, and
        // responds with a SYN|ACK.
        if flags() & TCP_ACK != 0 {
            // For incoming segments with the ACK flag set, respond with a RST.
            tcp_rst_netif(
                (*ip_data()).current_input_netif,
                ackno(),
                seqno().wrapping_add(u32::from(tcplen())),
                ip_current_dest_addr(),
                ip_current_src_addr(),
                hdr_dest(),
                hdr_src(),
            );
        } else if flags() & TCP_SYN != 0 {
            if (*pcb).accepts_pending >= (*pcb).backlog {
                return;
            }
            let npcb = tcp_alloc((*pcb).prio);
            // If a new PCB could not be created (probably due to lack of memory), we don't
            // do anything, but rely on the sender will retransmit the SYN at a time when
            // we have more memory available.
            if npcb.is_null() {
                // TCP_EVENT_ACCEPT(pcb, NULL, pcb->callback_arg, ERR_MEM, err): err not
                // useful here.
                if let Some(accept) = (*pcb).accept {
                    accept((*pcb).callback_arg, ptr::null_mut(), ERR_MEM);
                }
                return;
            }
            (*pcb).accepts_pending = (*pcb).accepts_pending.wrapping_add(1);
            tcp_set_flags(npcb, TF_BACKLOGPEND);
            // Set up the new PCB.
            (*npcb).local_ip.copy_from(&*ip_current_dest_addr());
            (*npcb).remote_ip.copy_from(&*ip_current_src_addr());
            (*npcb).local_port = (*pcb).local_port;
            (*npcb).remote_port = hdr_src();
            (*npcb).state = SYN_RCVD;
            (*npcb).rcv_nxt = seqno().wrapping_add(1);
            (*npcb).rcv_ann_right_edge = (*npcb).rcv_nxt;
            let iss = tcp_next_iss(npcb);
            (*npcb).snd_wl2 = iss;
            (*npcb).snd_nxt = iss;
            (*npcb).lastack = iss;
            (*npcb).snd_lbb = iss;
            (*npcb).snd_wl1 = seqno().wrapping_sub(1); // Initialise to seqno-1 to force window update.
            (*npcb).callback_arg = (*pcb).callback_arg;
            (*npcb).listener = pcb;
            // Inherit socket options.
            (*npcb).so_options = (*pcb).so_options & SOF_INHERITED;
            (*npcb).netif_idx = (*pcb).netif_idx;
            // Register the new PCB so that we can begin receiving segments for it.
            tcp_reg_active(npcb);

            // Parse any options in the SYN.
            tcp_parseopt(npcb);
            (*npcb).snd_wnd = hdr_wnd();
            (*npcb).snd_wnd_max = (*npcb).snd_wnd;

            (*npcb).mss = tcp_eff_send_mss((*npcb).mss, &(*npcb).local_ip, &(*npcb).remote_ip);

            // Send a SYN|ACK together with the MSS option.
            let rc = tcp_enqueue_flags(npcb, TCP_SYN | TCP_ACK);
            if rc != ERR_OK {
                tcp_abandon(npcb, 0);
                return;
            }
            tcp_output(npcb);
        }
    }
}

/// Called by `tcp_input()` when a segment arrives for a connection in TIME_WAIT.
///
/// # Safety
///
/// `pcb` is a live PCB in TIME-WAIT, during input processing.
unsafe fn tcp_timewait_input(pcb: *mut TcpPcb) {
    // RFC 1337: in TIME_WAIT, ignore RST and ACK FINs + any 'acceptable' segments. RFC
    // 793 3.9 Event Processing - Segment Arrives:
    // - first check sequence number - we skip that one in TIME_WAIT (always acceptable
    //   since we only send ACKs)
    // - second check the RST bit (... return)
    if flags() & TCP_RST != 0 {
        return;
    }

    lwip_assert!("tcp_timewait_input: invalid pcb", !pcb.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        // - fourth, check the SYN bit,
        if flags() & TCP_SYN != 0 {
            // If an incoming segment is not acceptable, an acknowledgment should be sent in
            // reply.
            if tcp_seq_between(
                seqno(),
                (*pcb).rcv_nxt,
                (*pcb).rcv_nxt.wrapping_add(u32::from((*pcb).rcv_wnd)),
            ) {
                // If the SYN is in the window it is an error, send a reset.
                tcp_rst(
                    pcb,
                    ackno(),
                    seqno().wrapping_add(u32::from(tcplen())),
                    ip_current_dest_addr(),
                    ip_current_src_addr(),
                    hdr_dest(),
                    hdr_src(),
                );
                return;
            }
        } else if flags() & TCP_FIN != 0 {
            // - eighth, check the FIN bit: Remain in the TIME-WAIT state. Restart the 2
            //   MSL time-wait timeout.
            (*pcb).tmr = tcp_ticks();
        }

        if tcplen() > 0 {
            // Acknowledge data, FIN or out-of-window SYN.
            tcp_ack_now(pcb);
            tcp_output(pcb);
        }
    }
}

/// Implements the TCP state machine. Called by `tcp_input`. In some states
/// `tcp_receive()` is called to receive data. The `tcp_seg` argument will be freed by
/// the caller (`tcp_input()`) unless the `recv_data` pointer in the pcb is set.
///
/// Returns `ERR_OK`, or `ERR_ABRT` if the pcb has been aborted and freed.
///
/// # Safety
///
/// `pcb` is live, during input processing.
unsafe fn tcp_process(pcb: *mut TcpPcb) -> ErrT {
    let mut acceptable = false;

    lwip_assert!("tcp_process: invalid pcb", !pcb.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        // Process incoming RST segments.
        if flags() & TCP_RST != 0 {
            // First, determine if the reset is acceptable.
            if (*pcb).state == SYN_SENT {
                // "In the SYN-SENT state (a RST received in response to an initial SYN),
                // the RST is acceptable if the ACK field acknowledges the SYN."
                if ackno() == (*pcb).snd_nxt {
                    acceptable = true;
                }
            } else {
                // "In all states except SYN-SENT, all reset (RST) segments are validated
                // by checking their SEQ-fields."
                if seqno() == (*pcb).rcv_nxt {
                    acceptable = true;
                } else if tcp_seq_between(
                    seqno(),
                    (*pcb).rcv_nxt,
                    (*pcb).rcv_nxt.wrapping_add(u32::from((*pcb).rcv_wnd)),
                ) {
                    // If the sequence number is inside the window, we send a challenge ACK
                    // and wait for a re-send with matching sequence number. This follows
                    // RFC 5961 section 3.2 and addresses CVE-2004-0230 (RST spoofing
                    // attack), which is present in RFC 793 RST handling.
                    tcp_ack_now(pcb);
                }
            }

            if acceptable {
                lwip_assert!("tcp_input: pcb->state != CLOSED", (*pcb).state != CLOSED);
                recv_flags_set(TF_RESET);
                tcp_clear_flags(pcb, TF_ACK_DELAY);
                return ERR_RST;
            } else {
                return ERR_OK;
            }
        }

        if flags() & TCP_SYN != 0 && (*pcb).state != SYN_SENT && (*pcb).state != SYN_RCVD {
            // Cope with new connection attempt after remote end crashed.
            tcp_ack_now(pcb);
            return ERR_OK;
        }

        if (*pcb).flags & TF_RXCLOSED == 0 {
            // Update the PCB (in)activity timer unless rx is closed (see tcp_shutdown).
            (*pcb).tmr = tcp_ticks();
        }
        (*pcb).keep_cnt_sent = 0;
        (*pcb).persist_probe = 0;

        tcp_parseopt(pcb);

        // Accept SYN only in 2 states:
        if flags() & TCP_SYN != 0 && (*pcb).state != SYN_SENT && (*pcb).state != SYN_RCVD {
            return ERR_OK;
        }

        // Do different things depending on the TCP state.
        match (*pcb).state {
            SYN_SENT => {
                // Received SYN ACK with expected sequence number?
                if flags() & TCP_ACK != 0
                    && flags() & TCP_SYN != 0
                    && ackno() == (*pcb).lastack.wrapping_add(1)
                {
                    (*pcb).rcv_nxt = seqno().wrapping_add(1);
                    (*pcb).rcv_ann_right_edge = (*pcb).rcv_nxt;
                    (*pcb).lastack = ackno();
                    (*pcb).snd_wnd = hdr_wnd();
                    (*pcb).snd_wnd_max = (*pcb).snd_wnd;
                    (*pcb).snd_wl1 = seqno().wrapping_sub(1); // Initialise to seqno - 1 to force window update.
                    (*pcb).state = ESTABLISHED;

                    (*pcb).mss = tcp_eff_send_mss((*pcb).mss, &(*pcb).local_ip, &(*pcb).remote_ip);

                    (*pcb).cwnd = lwip_tcp_calc_initial_cwnd((*pcb).mss);
                    lwip_assert!("pcb->snd_queuelen > 0", (*pcb).snd_queuelen > 0);
                    (*pcb).snd_queuelen -= 1;
                    let mut rseg = (*pcb).unacked;
                    if rseg.is_null() {
                        // Might happen if tcp_output fails in tcp_rexmit_rto() in which case
                        // the segment is on the unsent list.
                        rseg = (*pcb).unsent;
                        lwip_assert!("no segment to free", !rseg.is_null());
                        (*pcb).unsent = (*rseg).next;
                    } else {
                        (*pcb).unacked = (*rseg).next;
                    }
                    tcp_seg_free(rseg);

                    // If there's nothing left to acknowledge, stop the retransmit timer,
                    // otherwise reset it to start again.
                    if (*pcb).unacked.is_null() {
                        (*pcb).rtime = -1;
                    } else {
                        (*pcb).rtime = 0;
                        (*pcb).nrtx = 0;
                    }

                    // Call the user specified function to call when successfully connected.
                    // TCP_EVENT_CONNECTED(pcb, ERR_OK, err).
                    let err = match (*pcb).connected {
                        Some(connected) => connected((*pcb).callback_arg, pcb, ERR_OK),
                        None => ERR_OK,
                    };
                    if err == ERR_ABRT {
                        return ERR_ABRT;
                    }
                    tcp_ack_now(pcb);
                }
                // Received ACK? possibly a half-open connection.
                else if flags() & TCP_ACK != 0 {
                    // Send a RST to bring the other side in a non-synchronized state.
                    tcp_rst(
                        pcb,
                        ackno(),
                        seqno().wrapping_add(u32::from(tcplen())),
                        ip_current_dest_addr(),
                        ip_current_src_addr(),
                        hdr_dest(),
                        hdr_src(),
                    );
                    // Resend SYN immediately (don't wait for rto timeout) to establish
                    // connection faster, but do not send more SYNs than we otherwise would
                    // have, or we might get caught in a loop on loopback interfaces.
                    if (*pcb).nrtx < TCP_SYNMAXRTX {
                        (*pcb).rtime = 0;
                        tcp_rexmit_rto(pcb);
                    }
                }
            }
            SYN_RCVD => {
                if flags() & TCP_SYN != 0 {
                    if seqno() == (*pcb).rcv_nxt.wrapping_sub(1) {
                        // Looks like another copy of the SYN - retransmit our SYN-ACK.
                        tcp_rexmit(pcb);
                    }
                } else if flags() & TCP_ACK != 0 {
                    // Expected ACK number?
                    if tcp_seq_between(ackno(), (*pcb).lastack.wrapping_add(1), (*pcb).snd_nxt) {
                        (*pcb).state = ESTABLISHED;
                        let err = if (*pcb).listener.is_null() {
                            // Listen pcb might be closed by now.
                            ERR_VAL
                        } else {
                            lwip_assert!(
                                "pcb->listener->accept != NULL",
                                (*(*pcb).listener).accept.is_some()
                            );
                            tcp_backlog_accepted(pcb);
                            // Call the accept function.
                            // TCP_EVENT_ACCEPT(pcb->listener, pcb, pcb->callback_arg, ERR_OK, err).
                            match (*(*pcb).listener).accept {
                                Some(accept) => accept((*pcb).callback_arg, pcb, ERR_OK),
                                None => ERR_ARG,
                            }
                        };
                        if err != ERR_OK {
                            // If the accept function returns with an error, we abort the
                            // connection. Already aborted?
                            if err != ERR_ABRT {
                                tcp_abort(pcb);
                            }
                            return ERR_ABRT;
                        }
                        // If there was any data contained within this ACK, we'd better pass
                        // it on to the application as well.
                        tcp_receive(pcb);

                        // Prevent ACK for SYN to generate a sent event.
                        if RECV_ACKED.get() != 0 {
                            RECV_ACKED.set(RECV_ACKED.get() - 1);
                        }

                        (*pcb).cwnd = lwip_tcp_calc_initial_cwnd((*pcb).mss);

                        if RECV_FLAGS.get() & TF_GOT_FIN != 0 {
                            tcp_ack_now(pcb);
                            (*pcb).state = CLOSE_WAIT;
                        }
                    } else {
                        // Incorrect ACK number, send RST.
                        tcp_rst(
                            pcb,
                            ackno(),
                            seqno().wrapping_add(u32::from(tcplen())),
                            ip_current_dest_addr(),
                            ip_current_src_addr(),
                            hdr_dest(),
                            hdr_src(),
                        );
                    }
                }
            }
            CLOSE_WAIT | ESTABLISHED => {
                tcp_receive(pcb);
                if RECV_FLAGS.get() & TF_GOT_FIN != 0 {
                    // Passive close.
                    tcp_ack_now(pcb);
                    (*pcb).state = CLOSE_WAIT;
                }
            }
            FIN_WAIT_1 => {
                tcp_receive(pcb);
                if RECV_FLAGS.get() & TF_GOT_FIN != 0 {
                    if flags() & TCP_ACK != 0
                        && ackno() == (*pcb).snd_nxt
                        && (*pcb).unsent.is_null()
                    {
                        tcp_ack_now(pcb);
                        tcp_pcb_purge(pcb);
                        tcp_rmv_active(pcb);
                        (*pcb).state = TIME_WAIT;
                        tcp_reg(tcp_tw_pcbs_head(), pcb);
                    } else {
                        tcp_ack_now(pcb);
                        (*pcb).state = CLOSING;
                    }
                } else if flags() & TCP_ACK != 0
                    && ackno() == (*pcb).snd_nxt
                    && (*pcb).unsent.is_null()
                {
                    (*pcb).state = FIN_WAIT_2;
                }
            }
            FIN_WAIT_2 => {
                tcp_receive(pcb);
                if RECV_FLAGS.get() & TF_GOT_FIN != 0 {
                    tcp_ack_now(pcb);
                    tcp_pcb_purge(pcb);
                    tcp_rmv_active(pcb);
                    (*pcb).state = TIME_WAIT;
                    tcp_reg(tcp_tw_pcbs_head(), pcb);
                }
            }
            CLOSING => {
                tcp_receive(pcb);
                if flags() & TCP_ACK != 0 && ackno() == (*pcb).snd_nxt && (*pcb).unsent.is_null() {
                    tcp_pcb_purge(pcb);
                    tcp_rmv_active(pcb);
                    (*pcb).state = TIME_WAIT;
                    tcp_reg(tcp_tw_pcbs_head(), pcb);
                }
            }
            LAST_ACK => {
                tcp_receive(pcb);
                if flags() & TCP_ACK != 0 && ackno() == (*pcb).snd_nxt && (*pcb).unsent.is_null() {
                    // Bugfix #21699: don't set pcb->state to CLOSED here or we risk leaking
                    // segments.
                    recv_flags_set(TF_CLOSED);
                }
            }
            _ => {}
        }
    }
    ERR_OK
}

/// Insert segment into the list (segments covered with new one will be deleted).
///
/// Called from `tcp_receive()`.
///
/// # Safety
///
/// `cseg` is a live segment and `next` null or a list of live segments.
unsafe fn tcp_oos_insert_segment(cseg: *mut TcpSeg, mut next: *mut TcpSeg) {
    lwip_assert!("tcp_oos_insert_segment: invalid cseg", !cseg.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        if tcph_flags((*cseg).tcphdr) & TCP_FIN != 0 {
            // Received segment overlaps all following segments.
            tcp_segs_free(next);
            next = ptr::null_mut();
        } else {
            // Delete some following segments; oos queue may have segments with FIN flag.
            while !next.is_null()
                && tcp_seq_geq(
                    seqno().wrapping_add(u32::from((*cseg).len)),
                    in_seqno(next).wrapping_add(u32::from((*next).len)),
                )
            {
                // cseg with FIN already processed.
                if tcph_flags((*next).tcphdr) & TCP_FIN != 0 {
                    tcph_set_flag((*cseg).tcphdr, TCP_FIN);
                }
                let old_seg = next;
                next = (*next).next;
                tcp_seg_free(old_seg);
            }
            if !next.is_null()
                && tcp_seq_gt(seqno().wrapping_add(u32::from((*cseg).len)), in_seqno(next))
            {
                // We need to trim the incoming segment.
                (*cseg).len = in_seqno(next).wrapping_sub(seqno()) as u16;
                pbuf_realloc((*cseg).p, (*cseg).len);
            }
        }
        (*cseg).next = next;
    }
}

/// Remove segments from a list if the incoming ACK acknowledges them.
///
/// # Safety
///
/// `pcb` is live and `seg_list` null or a list of its live output segments.
unsafe fn tcp_free_acked_segments(
    pcb: *mut TcpPcb,
    mut seg_list: *mut TcpSeg,
    dbg_other_seg_list: *mut TcpSeg,
) -> *mut TcpSeg {
    // SAFETY: as the caller guarantees.
    unsafe {
        while !seg_list.is_null()
            && tcp_seq_leq(
                out_seqno(seg_list).wrapping_add(tcp_tcplen(seg_list)),
                ackno(),
            )
        {
            let next = seg_list;
            seg_list = (*seg_list).next;

            let clen = pbuf_clen((*next).p);
            lwip_assert!(
                "pcb->snd_queuelen >= pbuf_clen(next->p)",
                (*pcb).snd_queuelen >= clen
            );

            (*pcb).snd_queuelen -= clen;
            RECV_ACKED.set(RECV_ACKED.get().wrapping_add((*next).len));
            tcp_seg_free(next);

            if (*pcb).snd_queuelen != 0 {
                lwip_assert!(
                    "tcp_receive: valid queue length",
                    !seg_list.is_null() || !dbg_other_seg_list.is_null()
                );
            }
        }
        seg_list
    }
}

/// Called by `tcp_process`. Checks if the given segment is an ACK for outstanding data,
/// and if so frees the memory of the buffered data. Next, it places the segment on any
/// of the receive queues (pcb->recved or pcb->ooseq). If the segment is buffered, the
/// pbuf is referenced by pbuf_ref so that it will not be freed until it has been
/// removed from the buffer.
///
/// If the incoming segment constitutes an ACK for a segment that was used for RTT
/// estimation, the RTT is estimated here as well.
///
/// Called from `tcp_process()`.
///
/// # Safety
///
/// `pcb` is live, during input processing.
unsafe fn tcp_receive(pcb: *mut TcpPcb) {
    lwip_assert!("tcp_receive: invalid pcb", !pcb.is_null());

    // SAFETY: as the caller guarantees; the segments on the PCB's queues are live, and
    // inseg holds the segment being processed.
    unsafe {
        lwip_assert!("tcp_receive: wrong state", (*pcb).state >= ESTABLISHED);
        let inseg = inseg();

        if flags() & TCP_ACK != 0 {
            let right_wnd_edge = u32::from((*pcb).snd_wnd).wrapping_add((*pcb).snd_wl2);

            // Update window.
            if tcp_seq_lt((*pcb).snd_wl1, seqno())
                || ((*pcb).snd_wl1 == seqno() && tcp_seq_lt((*pcb).snd_wl2, ackno()))
                || ((*pcb).snd_wl2 == ackno() && hdr_wnd() > (*pcb).snd_wnd)
            {
                (*pcb).snd_wnd = hdr_wnd();
                // Keep track of the biggest window announced by the remote host to
                // calculate the maximum segment size.
                if (*pcb).snd_wnd_max < (*pcb).snd_wnd {
                    (*pcb).snd_wnd_max = (*pcb).snd_wnd;
                }
                (*pcb).snd_wl1 = seqno();
                (*pcb).snd_wl2 = ackno();
            }

            // (From Stevens TCP/IP Illustrated Vol II, p970.) Its only a duplicate ack if:
            // 1) It doesn't ACK new data
            // 2) length of received packet is zero (i.e. no payload)
            // 3) the advertised window hasn't changed
            // 4) There is outstanding unacknowledged data (retransmission timer running)
            // 5) The ACK is == biggest ACK sequence number so far seen (snd_una)
            //
            // If it passes all five, should process as a dupack:
            // a) dupacks < 3: do nothing
            // b) dupacks == 3: fast retransmit
            // c) dupacks > 3: increase cwnd
            //
            // If it only passes 1-3, should reset dupack counter (and add to stats, which
            // we don't do in lwIP)
            //
            // If it only passes 1, should reset dupack counter

            // Clause 1.
            if tcp_seq_leq(ackno(), (*pcb).lastack) {
                // Clause 2, clause 3, clause 4, and clause 5.
                if tcplen() == 0
                    && (*pcb).snd_wl2.wrapping_add(u32::from((*pcb).snd_wnd)) == right_wnd_edge
                    && (*pcb).rtime >= 0
                    && (*pcb).lastack == ackno()
                {
                    if (*pcb).dupacks.wrapping_add(1) > (*pcb).dupacks {
                        (*pcb).dupacks += 1;
                    }
                    if (*pcb).dupacks > 3 {
                        // Inflate the congestion window.
                        tcp_wnd_inc(&mut (*pcb).cwnd, (*pcb).mss);
                    }
                    if (*pcb).dupacks >= 3 {
                        // Do fast retransmit (checked via TF_INFR, not via dupacks count).
                        tcp_rexmit_fast(pcb);
                    }
                }
            } else if tcp_seq_between(ackno(), (*pcb).lastack.wrapping_add(1), (*pcb).snd_nxt) {
                // We come here when the ACK acknowledges new data.

                // Reset the "IN Fast Retransmit" flag, since we are no longer in fast
                // retransmit. Also reset the congestion window to the slow start
                // threshold.
                if (*pcb).flags & TF_INFR != 0 {
                    tcp_clear_flags(pcb, TF_INFR);
                    (*pcb).cwnd = (*pcb).ssthresh;
                    (*pcb).bytes_acked = 0;
                }

                // Reset the number of retransmissions.
                (*pcb).nrtx = 0;

                // Reset the retransmission time-out.
                (*pcb).rto = ((*pcb).sa >> 3).wrapping_add((*pcb).sv);

                // Record how much data this ACK acks.
                let acked = ackno().wrapping_sub((*pcb).lastack) as TcpWnd;

                // Reset the fast retransmit variables.
                (*pcb).dupacks = 0;
                (*pcb).lastack = ackno();

                // Update the congestion control variables (cwnd and ssthresh).
                if (*pcb).state >= ESTABLISHED {
                    if (*pcb).cwnd < (*pcb).ssthresh {
                        // Limit to 1 SMSS segment during period following RTO.
                        let num_seg: u16 = if (*pcb).flags & TF_RTO != 0 { 1 } else { 2 };
                        // RFC 3465, section 2.2 Slow Start.
                        let increase = acked.min(num_seg.wrapping_mul((*pcb).mss));
                        tcp_wnd_inc(&mut (*pcb).cwnd, increase);
                    } else {
                        // RFC 3465, section 2.1 Congestion Avoidance.
                        tcp_wnd_inc(&mut (*pcb).bytes_acked, acked);
                        if (*pcb).bytes_acked >= (*pcb).cwnd {
                            (*pcb).bytes_acked -= (*pcb).cwnd;
                            tcp_wnd_inc(&mut (*pcb).cwnd, (*pcb).mss);
                        }
                    }
                }

                // Remove segment from the unacknowledged list if the incoming ACK
                // acknowledges them.
                (*pcb).unacked = tcp_free_acked_segments(pcb, (*pcb).unacked, (*pcb).unsent);
                // We go through the ->unsent list to see if any of the segments on the list
                // are acknowledged by the ACK. This may seem strange since an "unsent"
                // segment shouldn't be acked. The rationale is that lwIP puts all
                // outstanding segments on the ->unsent list after a retransmission, so
                // these segments may in fact have been sent once.
                (*pcb).unsent = tcp_free_acked_segments(pcb, (*pcb).unsent, (*pcb).unacked);

                // If there's nothing left to acknowledge, stop the retransmit timer,
                // otherwise reset it to start again.
                (*pcb).rtime = if (*pcb).unacked.is_null() { -1 } else { 0 };

                (*pcb).polltmr = 0;

                if (*pcb).unsent.is_null() {
                    (*pcb).unsent_oversize = 0;
                }

                if !(*ip_data()).current_ip6_header.is_null() {
                    // Inform neighbor reachability of forward progress.
                    nd6_reachability_hint((*ip_current_src_addr()).ip6());
                }

                (*pcb).snd_buf = (*pcb).snd_buf.wrapping_add(RECV_ACKED.get());
                // Check if this ACK ends our retransmission of in-flight data.
                if (*pcb).flags & TF_RTO != 0 {
                    // RTO is done if
                    // 1) both queues are empty or
                    // 2) unacked is empty and unsent head contains data not part of RTO or
                    // 3) unacked head contains data not part of RTO
                    if (*pcb).unacked.is_null() {
                        if (*pcb).unsent.is_null()
                            || tcp_seq_leq((*pcb).rto_end, out_seqno((*pcb).unsent))
                        {
                            tcp_clear_flags(pcb, TF_RTO);
                        }
                    } else if tcp_seq_leq((*pcb).rto_end, out_seqno((*pcb).unacked)) {
                        tcp_clear_flags(pcb, TF_RTO);
                    }
                }
                // End of ACK for new data processing.
            } else {
                // Out of sequence ACK, didn't really ack anything.
                tcp_send_empty_ack(pcb);
            }

            // RTT estimation calculations. This is done by checking if the incoming
            // segment acknowledges the segment we use to take a round-trip time
            // measurement.
            if (*pcb).rttest != 0 && tcp_seq_lt((*pcb).rtseq, ackno()) {
                // Diff between this shouldn't exceed 32K since this are tcp timer ticks and
                // a round-trip shouldn't be that long...
                let mut m = tcp_ticks().wrapping_sub((*pcb).rttest) as i16;

                // This is taken directly from VJs original code in his paper.
                m = m.wrapping_sub((*pcb).sa >> 3);
                (*pcb).sa = (*pcb).sa.wrapping_add(m);
                if m < 0 {
                    m = m.wrapping_neg();
                }
                m = m.wrapping_sub((*pcb).sv >> 2);
                (*pcb).sv = (*pcb).sv.wrapping_add(m);
                (*pcb).rto = ((*pcb).sa >> 3).wrapping_add((*pcb).sv);

                (*pcb).rttest = 0;
            }
        }

        // If the incoming segment contains data, we must process it further unless the pcb
        // already received a FIN. (RFC 793, chapter 3.9, "SEGMENT ARRIVES" in states
        // CLOSE-WAIT, CLOSING, LAST-ACK and TIME-WAIT: "Ignore the segment text.")
        if tcplen() > 0 && (*pcb).state < CLOSE_WAIT {
            // This code basically does three things:
            //
            // +) If the incoming segment contains data that is the next in-sequence data,
            // this data is passed to the application. This might involve trimming the first
            // edge of the data. The rcv_nxt variable and the advertised window are
            // adjusted.
            //
            // +) If the incoming segment has data that is above the next sequence number
            // expected (->rcv_nxt), the segment is placed on the ->ooseq queue. This is done
            // by finding the appropriate place in the ->ooseq queue (which is ordered by
            // sequence number) and trim the segment in both ends if needed. An immediate
            // ACK is sent to indicate that we received an out-of-sequence segment.
            //
            // +) Finally, we check if the first segment on the ->ooseq queue now is in
            // sequence (i.e., if rcv_nxt >= ooseq->seqno). If rcv_nxt > ooseq->seqno, we
            // must trim the first edge of the segment on ->ooseq before we adjust rcv_nxt.
            // The data in the segments that are now on sequence are chained onto the
            // incoming segment so that we only need to call the application once.

            // First, we check if we must trim the first edge. We have to do this if the
            // sequence number of the incoming segment is less than rcv_nxt, and the
            // sequence number plus the length of the segment is larger than rcv_nxt.
            if tcp_seq_between(
                (*pcb).rcv_nxt,
                seqno().wrapping_add(1),
                seqno().wrapping_add(u32::from(tcplen())).wrapping_sub(1),
            ) {
                // Trimming the first edge is done by pushing the payload pointer in the pbuf
                // downwards. This is somewhat tricky since we do not want to discard the
                // full contents of the pbuf up to the new starting point of the data since
                // we have to keep the TCP header which is present in the first pbuf in the
                // chain.
                //
                // What is done is really quite a nasty hack: the first pbuf in the pbuf
                // chain is pointed to by inseg.p. Since we need to be able to deallocate the
                // whole pbuf, we cannot change this inseg.p pointer to point to any of the
                // later pbufs in the chain. Instead, we point the ->payload pointer in the
                // first pbuf to data in one of the later pbufs. We also set the inseg.data
                // pointer to point to the right place. This way, the ->p pointer will still
                // point to the first pbuf, but the ->p->payload pointer will point to data
                // in another pbuf.
                //
                // After we are done with adjusting the pbuf pointers we must adjust the
                // ->data pointer in the seg and the segment length.
                let mut p = (*inseg).p;
                let off32 = (*pcb).rcv_nxt.wrapping_sub(seqno());
                lwip_assert!("inseg.p != NULL", !(*inseg).p.is_null());
                lwip_assert!("insane offset!", off32 < 0xffff);
                let mut off = off32 as u16;
                lwip_assert!(
                    "pbuf too short!",
                    i32::from((*(*inseg).p).tot_len) >= i32::from(off)
                );
                (*inseg).len -= off;
                let new_tot_len = (*(*inseg).p).tot_len - off;
                while (*p).len < off {
                    off -= (*p).len;
                    // All pbufs up to and including this one have len==0, so tot_len is
                    // equal.
                    (*p).tot_len = new_tot_len;
                    (*p).len = 0;
                    p = (*p).next.map_or(ptr::null_mut(), |n| n.as_ptr());
                }
                // Cannot fail...
                pbuf_remove_header(p, usize::from(off));
                SEQNO.set((*pcb).rcv_nxt);
                ptr::addr_of_mut!((*(*inseg).tcphdr).seqno).write_unaligned(seqno());
            } else if tcp_seq_lt(seqno(), (*pcb).rcv_nxt) {
                // The whole segment is < rcv_nxt: must be a duplicate of a packet that has
                // already been correctly handled.
                tcp_ack_now(pcb);
            }

            // The sequence number must be within the window (above rcv_nxt and below
            // rcv_nxt + rcv_wnd) in order to be further processed.
            if tcp_seq_between(
                seqno(),
                (*pcb).rcv_nxt,
                (*pcb)
                    .rcv_nxt
                    .wrapping_add(u32::from((*pcb).rcv_wnd))
                    .wrapping_sub(1),
            ) {
                if (*pcb).rcv_nxt == seqno() {
                    tcp_receive_in_sequence(pcb);
                } else {
                    // We get here if the incoming segment is out-of-sequence.
                    tcp_receive_out_of_sequence(pcb);

                    // We send the ACK packet after we've (potentially) dealt with SACKs, so
                    // they can be included in the acknowledgment.
                    tcp_send_empty_ack(pcb);
                }
            } else {
                // The incoming segment is not within the window.
                tcp_send_empty_ack(pcb);
            }
        } else {
            // Segments with length 0 is taken care of here. Segments that fall out of the
            // window are ACKed.
            if !tcp_seq_between(
                seqno(),
                (*pcb).rcv_nxt,
                (*pcb)
                    .rcv_nxt
                    .wrapping_add(u32::from((*pcb).rcv_wnd))
                    .wrapping_sub(1),
            ) {
                tcp_ack_now(pcb);
            }
        }
    }
}

/// The part of `tcp_receive` for a segment that is the next in sequence: we check if we
/// have to trim the end of the segment and update rcv_nxt and pass the data to the
/// application.
///
/// # Safety
///
/// As `tcp_receive`.
unsafe fn tcp_receive_in_sequence(pcb: *mut TcpPcb) {
    // SAFETY: as the caller guarantees.
    unsafe {
        let inseg = inseg();
        TCPLEN.set(tcp_tcplen(inseg) as u16);

        if tcplen() > (*pcb).rcv_wnd {
            if tcph_flags((*inseg).tcphdr) & TCP_FIN != 0 {
                // Must remove the FIN from the header as we're trimming that byte of
                // sequence-space from the packet.
                tcph_flags_set((*inseg).tcphdr, tcph_flags((*inseg).tcphdr) & !TCP_FIN);
            }
            // Adjust length of segment to fit in the window.
            (*inseg).len = (*pcb).rcv_wnd;
            if tcph_flags((*inseg).tcphdr) & TCP_SYN != 0 {
                (*inseg).len = (*inseg).len.wrapping_sub(1);
            }
            pbuf_realloc((*inseg).p, (*inseg).len);
            TCPLEN.set(tcp_tcplen(inseg) as u16);
            lwip_assert!(
                "tcp_receive: segment not trimmed correctly to rcv_wnd",
                seqno().wrapping_add(u32::from(tcplen()))
                    == (*pcb).rcv_nxt.wrapping_add(u32::from((*pcb).rcv_wnd))
            );
        }
        // Received in-sequence data, adjust ooseq data if:
        // - FIN has been received or
        // - inseq overlaps with ooseq
        if !(*pcb).ooseq.is_null() {
            if tcph_flags((*inseg).tcphdr) & TCP_FIN != 0 {
                // Received in-order FIN means anything that was received out of order must
                // now have been received in-order, so bin the ooseq queue.
                while !(*pcb).ooseq.is_null() {
                    let old_ooseq = (*pcb).ooseq;
                    (*pcb).ooseq = (*(*pcb).ooseq).next;
                    tcp_seg_free(old_ooseq);
                }
            } else {
                let mut next = (*pcb).ooseq;
                // Remove all segments on ooseq that are covered by inseg already. FIN is
                // copied from ooseq to inseg if present.
                while !next.is_null()
                    && tcp_seq_geq(
                        seqno().wrapping_add(u32::from(tcplen())),
                        in_seqno(next).wrapping_add(u32::from((*next).len)),
                    )
                {
                    // inseg cannot have FIN here (already processed above).
                    if tcph_flags((*next).tcphdr) & TCP_FIN != 0
                        && tcph_flags((*inseg).tcphdr) & TCP_SYN == 0
                    {
                        tcph_set_flag((*inseg).tcphdr, TCP_FIN);
                        TCPLEN.set(tcp_tcplen(inseg) as u16);
                    }
                    let tmp = next;
                    next = (*next).next;
                    tcp_seg_free(tmp);
                }
                // Now trim right side of inseg if it overlaps with the first segment on
                // ooseq.
                if !next.is_null()
                    && tcp_seq_gt(seqno().wrapping_add(u32::from(tcplen())), in_seqno(next))
                {
                    (*inseg).len = in_seqno(next).wrapping_sub(seqno()) as u16;
                    // ESP-IDF: FIN takes a sequence number too.
                    if tcph_flags((*inseg).tcphdr) & TCP_SYN != 0
                        || tcph_flags((*inseg).tcphdr) & TCP_FIN != 0
                    {
                        (*inseg).len = (*inseg).len.wrapping_sub(1);
                    }
                    pbuf_realloc((*inseg).p, (*inseg).len);
                    TCPLEN.set(tcp_tcplen(inseg) as u16);
                    lwip_assert!(
                        "tcp_receive: segment not trimmed correctly to ooseq queue",
                        seqno().wrapping_add(u32::from(tcplen())) == in_seqno(next)
                    );
                }
                (*pcb).ooseq = next;
            }
        }

        (*pcb).rcv_nxt = seqno().wrapping_add(u32::from(tcplen()));

        // Update the receiver's (our) window.
        lwip_assert!("tcp_receive: tcplen > rcv_wnd", (*pcb).rcv_wnd >= tcplen());
        (*pcb).rcv_wnd -= tcplen();

        tcp_update_rcv_ann_wnd(pcb);

        // If there is data in the segment, we make preparations to pass this up to the
        // application. The ->recv_data variable is used for holding the pbuf that goes to
        // the application. The code for reassembling out-of-sequence data chains its data
        // on this pbuf as well.
        //
        // If the segment was a FIN, we set the TF_GOT_FIN flag that will be used to
        // indicate to the application that the remote side has closed its end of the
        // connection.
        if (*(*inseg).p).tot_len > 0 {
            RECV_DATA.set((*inseg).p);
            // Since this pbuf now is the responsibility of the application, we delete our
            // reference to it so that we won't (mistakingly) deallocate it.
            (*inseg).p = ptr::null_mut();
        }
        if tcph_flags((*inseg).tcphdr) & TCP_FIN != 0 {
            recv_flags_set(TF_GOT_FIN);
        }

        // We now check if we have segments on the ->ooseq queue that are now in
        // sequence.
        while !(*pcb).ooseq.is_null() && in_seqno((*pcb).ooseq) == (*pcb).rcv_nxt {
            let cseg = (*pcb).ooseq;
            SEQNO.set(in_seqno(cseg));
            // ESP-IDF: trim a segment the window cannot hold yet.
            if u32::from((*pcb).rcv_wnd) < tcp_tcplen(cseg) {
                let mut trimmed_len = (*pcb).rcv_wnd;
                let syn_or_fin = tcph_flags((*cseg).tcphdr) & (TCP_SYN | TCP_FIN) != 0;
                if syn_or_fin && trimmed_len > 0 {
                    trimmed_len -= 1;
                }
                // TCP_TCPLEN(&trimmed): the trimmed copy has the same header.
                let trimmed_tcplen = u32::from(trimmed_len) + u32::from(syn_or_fin);
                if u32::from((*pcb).rcv_wnd) < trimmed_tcplen {
                    // Cannot accept this segment yet (e.g. FIN/SYN with zero window).
                    break;
                }
                (*cseg).len = trimmed_len;
                pbuf_realloc((*cseg).p, (*cseg).len);
                tcp_segs_free((*cseg).next);
                (*cseg).next = ptr::null_mut();
            }
            (*pcb).rcv_nxt = (*pcb).rcv_nxt.wrapping_add(tcp_tcplen(cseg));
            lwip_assert!(
                "tcp_receive: ooseq tcplen > rcv_wnd",
                u32::from((*pcb).rcv_wnd) >= tcp_tcplen(cseg)
            );
            (*pcb).rcv_wnd -= tcp_tcplen(cseg) as TcpWnd;

            tcp_update_rcv_ann_wnd(pcb);

            if (*(*cseg).p).tot_len > 0 {
                // Chain this pbuf onto the pbuf that we will pass to the application.
                if !RECV_DATA.get().is_null() {
                    pbuf_cat(RECV_DATA.get(), (*cseg).p);
                } else {
                    RECV_DATA.set((*cseg).p);
                }
                (*cseg).p = ptr::null_mut();
            }
            if tcph_flags((*cseg).tcphdr) & TCP_FIN != 0 {
                recv_flags_set(TF_GOT_FIN);
                if (*pcb).state == ESTABLISHED {
                    // Force passive close or we can move to active close.
                    (*pcb).state = CLOSE_WAIT;
                }
            }

            (*pcb).ooseq = (*cseg).next;
            tcp_seg_free(cseg);
        }

        // Acknowledge the segment(s).
        tcp_ack(pcb);

        if !(*ip_data()).current_ip6_header.is_null() {
            // Inform neighbor reachability of forward progress.
            nd6_reachability_hint((*ip_current_src_addr()).ip6());
        }
    }
}

/// The part of `tcp_receive` for a segment that is out of sequence: we queue it on the
/// ->ooseq queue.
///
/// # Safety
///
/// As `tcp_receive`.
unsafe fn tcp_receive_out_of_sequence(pcb: *mut TcpPcb) {
    // SAFETY: as the caller guarantees.
    unsafe {
        let inseg = inseg();
        if (*pcb).ooseq.is_null() {
            (*pcb).ooseq = tcp_seg_copy(inseg);
        } else {
            // If the queue is not empty, we walk through the queue and try to find a place
            // where the sequence number of the incoming segment is between the sequence
            // numbers of the previous and the next segment on the ->ooseq queue. That is
            // the place where we put the incoming segment. If needed, we trim the second
            // edges of the previous and the incoming segment so that it will fit into the
            // sequence.
            //
            // If the incoming segment has the same sequence number as a segment on the
            // ->ooseq queue, we discard the segment that contains less data.
            let mut prev: *mut TcpSeg = ptr::null_mut();
            let mut next = (*pcb).ooseq;
            while !next.is_null() {
                if seqno() == in_seqno(next) {
                    // The sequence number of the incoming segment is the same as the
                    // sequence number of the segment on ->ooseq. We check the lengths to
                    // see which one to discard.
                    if (*inseg).len > (*next).len {
                        // The incoming segment is larger than the old segment. We replace
                        // some segments with the new one.
                        let cseg = tcp_seg_copy(inseg);
                        if !cseg.is_null() {
                            if !prev.is_null() {
                                (*prev).next = cseg;
                            } else {
                                (*pcb).ooseq = cseg;
                            }
                            tcp_oos_insert_segment(cseg, next);
                        }
                    }
                    // Either the lengths are the same or the incoming segment was smaller
                    // than the old one; in either case, we ditch the incoming segment.
                    break;
                } else {
                    if prev.is_null() {
                        if tcp_seq_lt(seqno(), in_seqno(next)) {
                            // The sequence number of the incoming segment is lower than the
                            // sequence number of the first segment on the queue. We put the
                            // incoming segment first on the queue.
                            let cseg = tcp_seg_copy(inseg);
                            if !cseg.is_null() {
                                (*pcb).ooseq = cseg;
                                tcp_oos_insert_segment(cseg, next);
                            }
                            break;
                        }
                    } else if tcp_seq_between(
                        seqno(),
                        in_seqno(prev).wrapping_add(1),
                        in_seqno(next).wrapping_sub(1),
                    ) {
                        // The sequence number of the incoming segment is in between the
                        // sequence numbers of the previous and the next segment on ->ooseq.
                        // We trim trim the previous segment, delete next segments that
                        // included in received segment and trim received, if needed.
                        let cseg = tcp_seg_copy(inseg);
                        if !cseg.is_null() {
                            if tcp_seq_gt(
                                in_seqno(prev).wrapping_add(u32::from((*prev).len)),
                                seqno(),
                            ) {
                                // We need to trim the prev segment.
                                (*prev).len = seqno().wrapping_sub(in_seqno(prev)) as u16;
                                pbuf_realloc((*prev).p, (*prev).len);
                            }
                            (*prev).next = cseg;
                            tcp_oos_insert_segment(cseg, next);
                        }
                        break;
                    }

                    // We don't use 'prev' below, so let's set it to current 'next'. This
                    // way even if we break the loop below, 'prev' will be pointing at the
                    // segment right in front of the newly added one.
                    prev = next;

                    // If the "next" segment is the last segment on the ooseq queue, we add
                    // the incoming segment to the end of the list.
                    if (*next).next.is_null() && tcp_seq_gt(seqno(), in_seqno(next)) {
                        if tcph_flags((*next).tcphdr) & TCP_FIN != 0 {
                            // Segment "next" already contains all data.
                            break;
                        }
                        (*next).next = tcp_seg_copy(inseg);
                        if !(*next).next.is_null() {
                            if tcp_seq_gt(
                                in_seqno(next).wrapping_add(u32::from((*next).len)),
                                seqno(),
                            ) {
                                // We need to trim the last segment.
                                (*next).len = seqno().wrapping_sub(in_seqno(next)) as u16;
                                pbuf_realloc((*next).p, (*next).len);
                            }
                            // Check if the remote side overruns our receive window.
                            if tcp_seq_gt(
                                u32::from(tcplen()).wrapping_add(seqno()),
                                (*pcb).rcv_nxt.wrapping_add(u32::from((*pcb).rcv_wnd)),
                            ) {
                                let last = (*next).next;
                                if tcph_flags((*last).tcphdr) & TCP_FIN != 0 {
                                    // Must remove the FIN from the header as we're trimming
                                    // that byte of sequence-space from the packet.
                                    tcph_flags_set(
                                        (*last).tcphdr,
                                        tcph_flags((*last).tcphdr) & !TCP_FIN,
                                    );
                                }
                                // Adjust length of segment to fit in the window.
                                (*last).len = (*pcb)
                                    .rcv_nxt
                                    .wrapping_add(u32::from((*pcb).rcv_wnd))
                                    .wrapping_sub(seqno())
                                    as u16;
                                // ESP-IDF: a SYN takes a sequence number too.
                                if tcph_flags((*last).tcphdr) & TCP_SYN != 0 && (*last).len > 0 {
                                    (*last).len -= 1;
                                }
                                pbuf_realloc((*last).p, (*last).len);
                                TCPLEN.set(tcp_tcplen(last) as u16);
                                lwip_assert!(
                                    "tcp_receive: segment not trimmed correctly to rcv_wnd",
                                    seqno().wrapping_add(u32::from(tcplen()))
                                        == (*pcb).rcv_nxt.wrapping_add(u32::from((*pcb).rcv_wnd))
                                );
                            }
                        }
                        break;
                    }
                }
                next = (*next).next;
            }
        }

        // Check that the data on ooseq doesn't exceed one of the limits and throw away
        // everything above that limit.
        let mut ooseq_qlen: u16 = 0;
        let mut prev: *mut TcpSeg = ptr::null_mut();
        let mut next = (*pcb).ooseq;
        while !next.is_null() {
            let p = (*next).p;
            ooseq_qlen = ooseq_qlen.wrapping_add(pbuf_clen(p));
            if ooseq_qlen > TCP_OOSEQ_PBUFS_LIMIT {
                // Too much ooseq data, dump this and everything after it.
                tcp_segs_free(next);
                if prev.is_null() {
                    // First ooseq segment is too much, dump the whole queue.
                    (*pcb).ooseq = ptr::null_mut();
                } else {
                    // Just dump 'next' and everything after it.
                    (*prev).next = ptr::null_mut();
                }
                break;
            }
            prev = next;
            next = (*next).next;
        }
    }
}

/// The next option byte, from the first or the second part of the options.
///
/// # Safety
///
/// Only during option parsing, within the options' length.
unsafe fn tcp_get_next_optbyte() -> u8 {
    let optidx = TCP_OPTIDX.get();
    TCP_OPTIDX.set(optidx.wrapping_add(1));
    // SAFETY: as the caller guarantees; the options follow the header or are at opt2.
    unsafe {
        if TCPHDR_OPT2.get().is_null() || optidx < TCPHDR_OPT1LEN.get() {
            let opts = TCPHDR.get().cast::<u8>().add(usize::from(TCP_HLEN));
            *opts.add(usize::from(optidx))
        } else {
            let idx = optidx.wrapping_sub(TCPHDR_OPT1LEN.get()) as u8;
            *TCPHDR_OPT2.get().add(usize::from(idx))
        }
    }
}

/// Parses the options contained in the incoming segment.
///
/// Called from `tcp_listen_input()` and `tcp_process()`. Currently, only the MSS option
/// is supported!
///
/// # Safety
///
/// `pcb` is live, during input processing.
unsafe fn tcp_parseopt(pcb: *mut TcpPcb) {
    lwip_assert!("tcp_parseopt: invalid pcb", !pcb.is_null());

    let optlen = TCPHDR_OPTLEN.get();
    // Parse the TCP MSS option, if present.
    if optlen != 0 {
        TCP_OPTIDX.set(0);
        // SAFETY: as the caller guarantees; each byte read is below the options' length.
        unsafe {
            while TCP_OPTIDX.get() < optlen {
                let opt = tcp_get_next_optbyte();
                match opt {
                    // End of options.
                    LWIP_TCP_OPT_EOL => return,
                    // NOP option.
                    LWIP_TCP_OPT_NOP => {}
                    LWIP_TCP_OPT_MSS => {
                        if tcp_get_next_optbyte() != LWIP_TCP_OPT_LEN_MSS
                            || TCP_OPTIDX
                                .get()
                                .wrapping_sub(2)
                                .wrapping_add(u16::from(LWIP_TCP_OPT_LEN_MSS))
                                > optlen
                        {
                            // Bad length.
                            return;
                        }
                        // An MSS option with the right option length.
                        let mut mss = u16::from(tcp_get_next_optbyte()) << 8;
                        mss |= u16::from(tcp_get_next_optbyte());
                        // Limit the mss to the configured TCP_MSS and prevent division by
                        // zero.
                        (*pcb).mss = if mss > TCP_MSS || mss == 0 {
                            TCP_MSS
                        } else {
                            mss
                        };
                    }
                    _ => {
                        let data = tcp_get_next_optbyte();
                        if data < 2 {
                            // If the length field is zero, the options are malformed and we
                            // don't process them further.
                            return;
                        }
                        // All other options have a length field, so that we easily can skip
                        // past them.
                        TCP_OPTIDX.set(TCP_OPTIDX.get().wrapping_add(u16::from(data) - 2));
                    }
                }
            }
        }
    }
}

/// Makes `tcp_input` free the PCB it is processing once it is done with it.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn tcp_trigger_input_pcb_close() {
    recv_flags_set(TF_CLOSED);
}

#[cfg(test)]
mod tests;
