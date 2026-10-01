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

//! Transmission Control Protocol, outgoing traffic, from `src/core/tcp_out.c`, as
//! ESP-IDF configures it: IPv4 and IPv6, the MSS option only (no timestamps, window
//! scaling, or SACK), `TCP_OVERSIZE` of one MSS with each segment in one pbuf
//! (`LWIP_NETIF_TX_SINGLE_PBUF`), checksums generated, and no option hooks (`build.rs`
//! refuses the rest).
//!
//! The output functions of TCP.
//!
//! There are two distinct ways for TCP segments to get sent:
//! - queued data: these are segments transferring data or segments containing SYN or
//!   FIN (which both count as one sequence number). They are created as struct
//!   `pbuf` together with a struct `tcp_seg` and enqueue to the unsent list of the pcb.
//!   They are sent by `tcp_output`:
//!   - `tcp_write`: creates data segments
//!   - `tcp_split_unsent_seg`: splits a data segment
//!   - `tcp_enqueue_flags`: creates SYN-only or FIN-only segments
//!   - `tcp_output` / `tcp_output_segment`: finalize the tcp header (e.g. sequence
//!     numbers, options, checksum) and output to IP
//!   - the various `tcp_rexmit` functions shuffle around segments between the unsent an
//!     unacked lists to retransmit them
//!   - `tcp_create_segment` and `tcp_pbuf_prealloc` allocate pbuf and segment for these
//!     functions
//! - direct send: these segments don't contain data but control the connection
//!   behaviour. They are created as pbuf only and sent directly without enqueueing
//!   them:
//!   - `tcp_send_empty_ack`: send an ACK-only segment
//!   - `tcp_rst`: send a RST segment
//!   - `tcp_keepalive`: send a keepalive segment
//!   - `tcp_zero_window_probe`: send a window probe segment
//!   - `tcp_output_alloc_header` allocates a header-only pbuf for these functions

use core::ffi::c_void;
use core::ptr;

use crate::config;
use crate::links::*;
use crate::types::*;

const TCP_MSS: u16 = config::TCP_MSS as u16;
const TCP_WND: u16 = config::TCP_WND as u16;
const TCP_SND_QUEUELEN: u16 = config::TCP_SND_QUEUELEN as u16;
const TCP_SNDQUEUELEN_OVERFLOW: u16 = config::TCP_SNDQUEUELEN_OVERFLOW as u16;
const TCP_TTL: u8 = config::TCP_TTL as u8;
const IP_PROTO_TCP_: u8 = IP_PROTO_TCP;
const PBUF_TRANSPORT: PbufLayer = config::PBUF_TRANSPORT_LAYER as PbufLayer;
const PBUF_IP: PbufLayer = config::PBUF_IP_LAYER as PbufLayer;

/// `LWIP_TCP_OPT_LENGTH(flags)`: only the MSS option is configured.
fn lwip_tcp_opt_length(flags: u8) -> u8 {
    if flags & TF_SEG_OPTS_MSS != 0 { 4 } else { 0 }
}

/// `TCPH_FLAGS(phdr)`.
///
/// # Safety
///
/// `h` is a live header.
pub(crate) unsafe fn tcph_flags(h: *const TcpHdr) -> u8 {
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

/// `TCPH_HDRLEN_FLAGS_SET(phdr, len, flags)`.
///
/// # Safety
///
/// `h` is a live header.
unsafe fn tcph_hdrlen_flags_set(h: *mut TcpHdr, len: u16, flags: u8) {
    // SAFETY: as the caller guarantees.
    unsafe {
        ptr::addr_of_mut!((*h)._hdrlen_rsvd_flags)
            .write_unaligned(((len << 12) | u16::from(flags)).to_be())
    };
}

/// The segment's sequence number, in host order.
///
/// # Safety
///
/// `seg` is a live segment with its header.
pub(crate) unsafe fn seg_seqno(seg: *const TcpSeg) -> u32 {
    // SAFETY: as the caller guarantees.
    unsafe { u32::from_be(ptr::addr_of!((*(*seg).tcphdr).seqno).read_unaligned()) }
}

/// `TCP_TCPLEN(seg)`: the sequence space the segment takes, SYN and FIN included.
///
/// # Safety
///
/// `seg` is a live segment with its header.
pub(crate) unsafe fn tcp_tcplen(seg: *const TcpSeg) -> u32 {
    // SAFETY: as the caller guarantees.
    unsafe {
        u32::from((*seg).len) + u32::from(tcph_flags((*seg).tcphdr) & (TCP_FIN | TCP_SYN) != 0)
    }
}

/// `TCP_SEQ_LT(a, b)`.
pub(crate) fn tcp_seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
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

/// `tcp_do_output_nagle(tpcb)`: whether Nagle's algorithm lets the PCB send now.
///
/// # Safety
///
/// `pcb` is live.
unsafe fn tcp_do_output_nagle(pcb: *const TcpPcb) -> bool {
    // SAFETY: as the caller guarantees.
    unsafe {
        (*pcb).unacked.is_null()
            || (*pcb).flags & (TF_NODELAY | TF_INFR) != 0
            || (!(*pcb).unsent.is_null()
                && (!(*(*pcb).unsent).next.is_null() || (*(*pcb).unsent).len >= (*pcb).mss))
            || (*pcb).snd_buf == 0
            || (*pcb).snd_queuelen >= TCP_SND_QUEUELEN
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

/// `ip_output_if(p, src, dest, ttl, tos, proto, netif)`.
///
/// # Safety
///
/// As the IP output functions require.
unsafe fn ip_output_if(
    p: *mut Pbuf,
    src: *const IpAddr,
    dest: *const IpAddr,
    ttl: u8,
    tos: u8,
    proto: u8,
    netif: *mut Netif,
) -> ErrT {
    // SAFETY: as the caller guarantees.
    unsafe {
        if (*dest).is_v6() {
            ip6_output_if(p, (*src).ip6(), (*dest).ip6(), ttl, tos, proto, netif)
        } else {
            ip4_output_if(p, (*src).ip4(), (*dest).ip4(), ttl, tos, proto, netif)
        }
    }
}

/// The netif for the PCB's traffic: the one it is bound to, or a route.
///
/// # Safety
///
/// `pcb` is null or live, and `src` and `dst` valid.
unsafe fn tcp_route(pcb: *const TcpPcb, src: *const IpAddr, dst: *const IpAddr) -> *mut Netif {
    // SAFETY: as the caller guarantees.
    unsafe {
        if !pcb.is_null() && (*pcb).netif_idx != NETIF_NO_INDEX {
            netif_get_by_index((*pcb).netif_idx)
        } else if (*dst).is_v6() {
            ip6_route((*src).ip6(), (*dst).ip6())
        } else {
            ip4_route_src((*src).ip4(), (*dst).ip4())
        }
    }
}

/// Create a TCP segment with prefilled header.
///
/// Called by `tcp_write`, `tcp_enqueue_flags` and `tcp_split_unsent_seg`.
///
/// `p` is the pbuf that is used to hold the TCP header (it is freed on error),
/// `hdrflags` the TCP flags for the header, `seqno` the sequence number of the new
/// segment, and `optflags` the options to include in the segment (`TF_SEG_OPTS_*`).
///
/// # Safety
///
/// `pcb` is live and `p` a pbuf the segment takes.
unsafe fn tcp_create_segment(
    pcb: *const TcpPcb,
    p: *mut Pbuf,
    hdrflags: u8,
    seqno: u32,
    optflags: u8,
) -> *mut TcpSeg {
    lwip_assert!("tcp_create_segment: invalid pcb", !pcb.is_null());
    lwip_assert!("tcp_create_segment: invalid pbuf", !p.is_null());

    let optlen = lwip_tcp_opt_length(optflags);

    // SAFETY: as the caller guarantees; a MEMP_TCP_SEG element holds a struct tcp_seg,
    // and the header goes into the room pbuf_add_header made.
    unsafe {
        let seg = memp_malloc(config::MEMP_TCP_SEG).cast::<TcpSeg>();
        if seg.is_null() {
            pbuf_free(p);
            return ptr::null_mut();
        }
        (*seg).flags = optflags;
        (*seg).next = ptr::null_mut();
        (*seg).p = p;
        lwip_assert!("p->tot_len >= optlen", (*p).tot_len >= u16::from(optlen));
        (*seg).len = (*p).tot_len - u16::from(optlen);

        // Build TCP header.
        if pbuf_add_header(p, usize::from(TCP_HLEN)) != 0 {
            tcp_seg_free(seg);
            return ptr::null_mut();
        }
        let tcphdr = (*(*seg).p).payload.cast::<TcpHdr>();
        (*seg).tcphdr = tcphdr;
        ptr::addr_of_mut!((*tcphdr).src).write_unaligned((*pcb).local_port.to_be());
        ptr::addr_of_mut!((*tcphdr).dest).write_unaligned((*pcb).remote_port.to_be());
        ptr::addr_of_mut!((*tcphdr).seqno).write_unaligned(seqno.to_be());
        // ackno is set in tcp_output.
        tcph_hdrlen_flags_set(tcphdr, 5 + u16::from(optlen) / 4, hdrflags);
        // wnd and chksum are set in tcp_output.
        ptr::addr_of_mut!((*tcphdr).urgp).write_unaligned(0);
        seg
    }
}

/// Allocate a PBUF_RAM pbuf, perhaps with extra space at the end.
///
/// This function is like `pbuf_alloc(layer, length, PBUF_RAM)` except there may be
/// extra bytes available at the end: with `LWIP_NETIF_TX_SINGLE_PBUF`, always the
/// maximum size.
///
/// # Safety
///
/// `oversize` is writable and `pcb` live.
unsafe fn tcp_pbuf_prealloc(
    layer: PbufLayer,
    length: u16,
    max_length: u16,
    oversize: *mut u16,
    pcb: *const TcpPcb,
    _apiflags: u8,
    _first_seg: bool,
) -> *mut Pbuf {
    lwip_assert!("tcp_pbuf_prealloc: invalid oversize", !oversize.is_null());
    lwip_assert!("tcp_pbuf_prealloc: invalid pcb", !pcb.is_null());

    // Always allocate maximum size.
    let alloc = max_length;
    // SAFETY: as the caller guarantees; a fresh pbuf.
    unsafe {
        let p = pbuf_alloc(layer, alloc, PBUF_RAM);
        if p.is_null() {
            return ptr::null_mut();
        }
        lwip_assert!("need unchained pbuf", (*p).next.is_none());
        *oversize = (*p).len - length;
        // Trim p->len to the currently used size.
        (*p).len = length;
        (*p).tot_len = length;
        p
    }
}

/// Checks if tcp_write is allowed or not (checks state, snd_buf and snd_queuelen).
///
/// Returns `ERR_OK` if tcp_write is allowed to proceed, another `err_t` otherwise.
///
/// # Safety
///
/// `pcb` is live.
unsafe fn tcp_write_checks(pcb: *mut TcpPcb, len: u16) -> ErrT {
    lwip_assert!("tcp_write_checks: invalid pcb", !pcb.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        // Connection is in invalid state for data transmission?
        let state = (*pcb).state;
        if state != ESTABLISHED && state != CLOSE_WAIT && state != SYN_SENT && state != SYN_RCVD {
            return ERR_CONN;
        } else if len == 0 {
            return ERR_OK;
        }

        // Fail on too much data.
        if len > (*pcb).snd_buf {
            tcp_set_flags(pcb, TF_NAGLEMEMERR);
            return ERR_MEM;
        }

        // If total number of pbufs on the unsent/unacked queues exceeds the configured
        // maximum, return an error. Check for configured max queuelen and possible
        // overflow.
        if (*pcb).snd_queuelen >= TCP_SND_QUEUELEN.min(TCP_SNDQUEUELEN_OVERFLOW + 1) {
            tcp_set_flags(pcb, TF_NAGLEMEMERR);
            return ERR_MEM;
        }
        if (*pcb).snd_queuelen != 0 {
            lwip_assert!(
                "tcp_write: pbufs on queue => at least one queue non-empty",
                !(*pcb).unacked.is_null() || !(*pcb).unsent.is_null()
            );
        } else {
            lwip_assert!(
                "tcp_write: no pbufs on queue => both queues empty",
                (*pcb).unacked.is_null() && (*pcb).unsent.is_null()
            );
        }
    }
    ERR_OK
}

/// Write data for sending (but does not send it immediately).
///
/// It waits in the expectation of more data being sent soon (as it can send them more
/// efficiently by combining them together). To prompt the system to send data now,
/// call `tcp_output()` after calling `tcp_write()`.
///
/// `arg` points to the data to be enqueued for sending, `len` is its length, and
/// `apiflags` is a combination of `TCP_WRITE_FLAG_COPY` (1: data will be copied into
/// memory belonging to the stack) and `TCP_WRITE_FLAG_MORE` (1: for TCP connection, PSH
/// flag will not be set on last segment sent).
///
/// Returns `ERR_OK` if enqueued, another `err_t` on error.
///
/// # Safety
///
/// `pcb` is null or live, and `arg` readable for `len` bytes (for as long as the stack
/// references it without `TCP_WRITE_FLAG_COPY`).
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_write(
    pcb: *mut TcpPcb,
    arg: *const c_void,
    len: u16,
    mut apiflags: u8,
) -> ErrT {
    // LWIP_ERROR("tcp_write: invalid pcb", pcb != NULL, return ERR_ARG);
    if pcb.is_null() {
        return ERR_ARG;
    }

    // SAFETY: as the caller guarantees; segments and pbufs on the PCB's queues are live.
    unsafe {
        // Phase 2 is not configured, so nothing is ever concatenated.
        let concat_p: *mut Pbuf = ptr::null_mut();
        let mut last_unsent: *mut TcpSeg = ptr::null_mut();
        let mut seg: *mut TcpSeg = ptr::null_mut();
        let mut prev_seg: *mut TcpSeg = ptr::null_mut();
        let mut queue: *mut TcpSeg = ptr::null_mut();
        let mut pos: u16 = 0;
        let optflags: u8 = 0;
        let mut oversize: u16 = 0;
        let mut oversize_used: u16 = 0;
        let extendlen: u16 = 0;

        // Don't allocate segments bigger than half the maximum window we ever received.
        let mut mss_local = (*pcb).mss.min((*pcb).snd_wnd_max / 2);
        mss_local = if mss_local != 0 {
            mss_local
        } else {
            (*pcb).mss
        };

        // Always copy to try to create single pbufs for TX.
        apiflags |= TCP_WRITE_FLAG_COPY;

        // LWIP_ERROR("tcp_write: arg == NULL (programmer violates API)", arg != NULL, return ERR_ARG;);
        if arg.is_null() {
            return ERR_ARG;
        }

        let err = tcp_write_checks(pcb, len);
        if err != ERR_OK {
            return err;
        }
        let mut queuelen = (*pcb).snd_queuelen;

        let optlen = lwip_tcp_opt_length(0);

        // TCP segmentation is done in three phases with increasing complexity:
        //
        // 1. Copy data directly into an oversized pbuf.
        // 2. Chain a new pbuf to the end of pcb->unsent.
        // 3. Create new segments.
        //
        // We may run out of memory at any point. In that case we must return ERR_MEM and
        // not change anything in pcb. Therefore, all changes are recorded in local
        // variables and committed at the end of the function. Some pcb fields are
        // maintained in local copies:
        //
        // queuelen = pcb->snd_queuelen
        // oversize = pcb->unsent_oversize
        //
        // These variables are set consistently by the phases:
        //
        // seg points to the last segment tampered with.
        //
        // pos records progress as data is segmented.

        // Find the tail of the unsent queue.
        if !(*pcb).unsent.is_null() {
            last_unsent = (*pcb).unsent;
            while !(*last_unsent).next.is_null() {
                last_unsent = (*last_unsent).next;
            }

            // Usable space at the end of the last unsent segment.
            let unsent_optlen = u16::from(lwip_tcp_opt_length((*last_unsent).flags));
            lwip_assert!(
                "mss_local is too small",
                mss_local >= (*last_unsent).len + unsent_optlen
            );
            let mut space = mss_local - ((*last_unsent).len + unsent_optlen);

            // Phase 1: Copy data directly into an oversized pbuf.
            //
            // The number of bytes copied is recorded in the oversize_used variable. The
            // actual copying is done at the bottom of the function.
            oversize = (*pcb).unsent_oversize;
            if oversize > 0 {
                lwip_assert!("inconsistent oversize vs. space", oversize <= space);
                lwip_sometimes!(
                    "tcp_write: data fills the spare room of the last unsent segment",
                    true
                );
                seg = last_unsent;
                oversize_used = space.min(oversize.min(len));
                pos += oversize_used;
                oversize -= oversize_used;
                space -= oversize_used;
            }
            let _ = space;
            // Now we are either done or oversize is zero.
            lwip_assert!("inconsistent oversize vs. len", oversize == 0 || pos == len);

            // Phase 2: Chain a new pbuf to the end of pcb->unsent: not done with
            // LWIP_NETIF_TX_SINGLE_PBUF.
        } else {
            lwip_assert!(
                "unsent_oversize mismatch (pcb->unsent is NULL)",
                (*pcb).unsent_oversize == 0
            );
        }

        // Phase 3: Create new segments.
        //
        // The new segments are chained together in the local 'queue' variable, ready to
        // be appended to pcb->unsent.
        'memerr: {
            while pos < len {
                let left = len - pos;
                let max_len = mss_local - u16::from(optlen);
                let seglen = left.min(max_len);

                let p;
                if apiflags & TCP_WRITE_FLAG_COPY != 0 {
                    // If copy is set, memory should be allocated and data copied into
                    // pbuf.
                    p = tcp_pbuf_prealloc(
                        PBUF_TRANSPORT,
                        seglen + u16::from(optlen),
                        mss_local,
                        &mut oversize,
                        pcb,
                        apiflags,
                        queue.is_null(),
                    );
                    if p.is_null() {
                        break 'memerr;
                    }
                    lwip_assert!(
                        "tcp_write: check that first pbuf can hold the complete seglen",
                        (*p).len >= seglen
                    );
                    ptr::copy_nonoverlapping(
                        arg.cast::<u8>().add(usize::from(pos)),
                        (*p).payload.cast::<u8>().add(usize::from(optlen)),
                        usize::from(seglen),
                    );
                } else {
                    // Copy is not set: first allocate a pbuf for holding the data. Since
                    // the referenced data is available at least until it is sent out on
                    // the link (as it has to be ACKed by the remote party) we can safely
                    // use PBUF_ROM instead of PBUF_REF here.
                    lwip_assert!("oversize == 0", oversize == 0);
                    let p2 = pbuf_alloc(PBUF_TRANSPORT, seglen, PBUF_ROM);
                    if p2.is_null() {
                        break 'memerr;
                    }
                    (*p2).payload = arg.cast::<u8>().add(usize::from(pos)).cast_mut().cast();

                    // Second, allocate a pbuf for the headers.
                    p = pbuf_alloc(PBUF_TRANSPORT, u16::from(optlen), PBUF_RAM);
                    if p.is_null() {
                        // If allocation fails, we have to deallocate the data pbuf as
                        // well.
                        pbuf_free(p2);
                        break 'memerr;
                    }
                    // Concatenate the headers and data pbufs together.
                    pbuf_cat(p, p2);
                }

                queuelen = queuelen.wrapping_add(pbuf_clen(p));

                // Now that there are more segments queued, we check again if the length
                // of the queue exceeds the configured maximum or overflows.
                if queuelen > TCP_SND_QUEUELEN.min(TCP_SNDQUEUELEN_OVERFLOW) {
                    pbuf_free(p);
                    break 'memerr;
                }

                seg = tcp_create_segment(
                    pcb,
                    p,
                    0,
                    (*pcb).snd_lbb.wrapping_add(u32::from(pos)),
                    optflags,
                );
                if seg.is_null() {
                    break 'memerr;
                }

                // First segment of to-be-queued data?
                if queue.is_null() {
                    queue = seg;
                } else {
                    // Attach the segment to the end of the queued segments.
                    lwip_assert!("prev_seg != NULL", !prev_seg.is_null());
                    (*prev_seg).next = seg;
                }
                // Remember last segment of to-be-queued data for next iteration.
                prev_seg = seg;

                pos += seglen;
            }

            // All three segmentation phases were successful. We can commit the
            // transaction.

            // Phase 1: If data has been added to the preallocated tail of last_unsent,
            // we update the length fields of the pbuf chain.
            if oversize_used > 0 {
                // Bump tot_len of whole chain, len of tail.
                let mut p = (*last_unsent).p;
                while !p.is_null() {
                    (*p).tot_len += oversize_used;
                    if (*p).next.is_none() {
                        ptr::copy_nonoverlapping(
                            arg.cast::<u8>(),
                            (*p).payload.cast::<u8>().add(usize::from((*p).len)),
                            usize::from(oversize_used),
                        );
                        (*p).len += oversize_used;
                    }
                    p = (*p).next.map_or(ptr::null_mut(), |n| n.as_ptr());
                }
                (*last_unsent).len += oversize_used;
            }
            (*pcb).unsent_oversize = oversize;

            // Phase 2: concat_p can be concatenated onto last_unsent->p, unless we
            // are doing a checksum on copy.
            if !concat_p.is_null() {
                lwip_assert!(
                    "tcp_write: cannot concatenate when pcb->unsent is empty",
                    !last_unsent.is_null()
                );
                pbuf_cat((*last_unsent).p, concat_p);
                (*last_unsent).len += (*concat_p).tot_len;
            } else if extendlen > 0 {
                lwip_assert!(
                    "tcp_write: extension of reference requires reference",
                    !last_unsent.is_null() && !(*last_unsent).p.is_null()
                );
                let mut p = (*last_unsent).p;
                while let Some(next) = (*p).next {
                    (*p).tot_len += extendlen;
                    p = next.as_ptr();
                }
                (*p).tot_len += extendlen;
                (*p).len += extendlen;
                (*last_unsent).len += extendlen;
            }

            // Phase 3: Append queue to pcb->unsent. Queue may be NULL, but that does no
            // harm.
            if last_unsent.is_null() {
                (*pcb).unsent = queue;
            } else {
                (*last_unsent).next = queue;
            }

            // Finally update the pcb state.
            (*pcb).snd_lbb = (*pcb).snd_lbb.wrapping_add(u32::from(len));
            (*pcb).snd_buf -= len;
            (*pcb).snd_queuelen = queuelen;

            if (*pcb).snd_queuelen != 0 {
                lwip_assert!(
                    "tcp_write: valid queue length",
                    !(*pcb).unacked.is_null() || !(*pcb).unsent.is_null()
                );
            }

            // Set the PSH flag in the last segment that we enqueued.
            if !seg.is_null() && !(*seg).tcphdr.is_null() && apiflags & TCP_WRITE_FLAG_MORE == 0 {
                tcph_set_flag((*seg).tcphdr, TCP_PSH);
            }

            return ERR_OK;
        }

        // memerr:
        tcp_set_flags(pcb, TF_NAGLEMEMERR);

        if !concat_p.is_null() {
            pbuf_free(concat_p);
        }
        if !queue.is_null() {
            tcp_segs_free(queue);
        }
        if (*pcb).snd_queuelen != 0 {
            lwip_assert!(
                "tcp_write: valid queue length",
                !(*pcb).unacked.is_null() || !(*pcb).unsent.is_null()
            );
        }
        ERR_MEM
    }
}

/// Split segment on the head of the unsent queue. If return is not ERR_OK, existing
/// head remains intact.
///
/// The split is accomplished by creating a new TCP segment and pbuf which holds the
/// remainder payload after the split. The original pbuf is trimmed to new length. This
/// allows splitting of read-only pbufs.
///
/// `split` is the amount of payload to remain in the head.
///
/// # Safety
///
/// `pcb` is live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_split_unsent_seg(pcb: *mut TcpPcb, split: u16) -> ErrT {
    lwip_assert!("tcp_split_unsent_seg: invalid pcb", !pcb.is_null());

    // SAFETY: as the caller guarantees; the head segment and its pbuf are live.
    unsafe {
        let useg = (*pcb).unsent;
        if useg.is_null() {
            return ERR_MEM;
        }

        if split == 0 {
            lwip_assert!("Can't split segment into length 0", false);
            return ERR_VAL;
        }

        if (*useg).len <= split {
            return ERR_OK;
        }

        lwip_assert!("split <= mss", split <= (*pcb).mss);
        lwip_assert!("useg->len > 0", (*useg).len > 0);

        // We should check that we don't exceed TCP_SND_QUEUELEN but we need to split the
        // segment regardless. Here we set the flags to indicate that the connection is
        // ready to transmit.
        let optflags = (*useg).flags;
        let optlen = u16::from(lwip_tcp_opt_length(optflags));
        let remainder = (*useg).len - split;

        // Create new pbuf for the remainder of the split.
        let p = pbuf_alloc(PBUF_TRANSPORT, remainder + optlen, PBUF_RAM);
        if p.is_null() {
            return split_memerr(ptr::null_mut(), ptr::null_mut());
        }

        // Offset into the original pbuf is past TCP/IP headers, options, and split
        // amount.
        let offset = (*(*useg).p).tot_len - (*useg).len + split;
        // Copy remainder into new pbuf, headers and options will not be filled out.
        if pbuf_copy_partial(
            (*useg).p,
            (*p).payload.cast::<u8>().add(usize::from(optlen)).cast(),
            remainder,
            offset,
        ) != remainder
        {
            return split_memerr(ptr::null_mut(), p);
        }

        // Options are created when calling tcp_output().

        // Migrate flags from original segment.
        let mut split_flags = tcph_flags((*useg).tcphdr);
        let mut remainder_flags: u8 = 0;

        if split_flags & TCP_PSH != 0 {
            split_flags &= !TCP_PSH;
            remainder_flags |= TCP_PSH;
        }
        if split_flags & TCP_FIN != 0 {
            split_flags &= !TCP_FIN;
            remainder_flags |= TCP_FIN;
        }
        // URG, ACK, and RST are not present.

        let seg = tcp_create_segment(
            pcb,
            p,
            remainder_flags,
            seg_seqno(useg).wrapping_add(u32::from(split)),
            optflags,
        );
        if seg.is_null() {
            // The pbuf was freed by tcp_create_segment.
            return split_memerr(seg, ptr::null_mut());
        }

        // Remove this segment from the queue since trimming it may free pbufs.
        (*pcb).snd_queuelen = (*pcb).snd_queuelen.wrapping_sub(pbuf_clen((*useg).p));

        // Trim the original pbuf into our split size. At this point our remainder bytes
        // have been copied to the new pbuf.
        pbuf_realloc((*useg).p, (*(*useg).p).tot_len - remainder);
        (*useg).len -= remainder;
        tcph_set_flag((*useg).tcphdr, split_flags);

        // Add back to the queue with new trimmed pbuf.
        (*pcb).snd_queuelen = (*pcb).snd_queuelen.wrapping_add(pbuf_clen((*useg).p));

        // Update number of segments on the queues. Note that length now may exceed
        // TCP_SND_QUEUELEN, but that is not an issue as the TCP layer will send out
        // these segments shortly.
        (*pcb).snd_queuelen = (*pcb).snd_queuelen.wrapping_add(pbuf_clen((*seg).p));
        lwip_sometimes!("tcp_split_unsent_seg: segment split", true);

        // Finally insert remainder into queue after split (which stays head).
        (*seg).next = (*useg).next;
        (*useg).next = seg;

        // If remainder is last segment on the unsent, ensure we clear the oversize
        // amount because the remainder is always sized to the exact remaining amount.
        if (*seg).next.is_null() {
            (*pcb).unsent_oversize = 0;
        }
    }
    ERR_OK
}

/// `tcp_split_unsent_seg`'s `memerr` label: frees the remainder pbuf `p`, if any, and
/// fails. No segment was created.
///
/// # Safety
///
/// `p` is null or a pbuf the caller owns.
unsafe fn split_memerr(seg: *mut TcpSeg, p: *mut Pbuf) -> ErrT {
    lwip_assert!("seg == NULL", seg.is_null());
    if !p.is_null() {
        // SAFETY: as the caller guarantees.
        unsafe { pbuf_free(p) };
    }
    ERR_MEM
}

/// Called by `tcp_close()` to send a segment including FIN flag but not data. This
/// FIN may be added to an existing segment or a new, otherwise empty segment is
/// enqueued.
///
/// Returns `ERR_OK` if sent, another `err_t` otherwise.
///
/// # Safety
///
/// `pcb` is live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_send_fin(pcb: *mut TcpPcb) -> ErrT {
    lwip_assert!("tcp_send_fin: invalid pcb", !pcb.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        // First, try to add the fin to the last unsent segment.
        if !(*pcb).unsent.is_null() {
            let mut last_unsent = (*pcb).unsent;
            while !(*last_unsent).next.is_null() {
                last_unsent = (*last_unsent).next;
            }

            if tcph_flags((*last_unsent).tcphdr) & (TCP_SYN | TCP_FIN | TCP_RST) == 0 {
                // No SYN/FIN/RST flag in the header, we can add the FIN flag.
                tcph_set_flag((*last_unsent).tcphdr, TCP_FIN);
                tcp_set_flags(pcb, TF_FIN);
                return ERR_OK;
            }
        }
        // No data, no length, flags, copy=1, no optdata.
        tcp_enqueue_flags(pcb, TCP_FIN)
    }
}

/// Enqueue SYN or FIN for transmission.
///
/// Called by `tcp_connect`, `tcp_listen_input`, and `tcp_close` (via `tcp_send_fin`).
///
/// `flags` is `TCP_SYN` or `TCP_FIN` (or both).
///
/// # Safety
///
/// `pcb` is live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_enqueue_flags(pcb: *mut TcpPcb, flags: u8) -> ErrT {
    lwip_assert!(
        "tcp_enqueue_flags: need either TCP_SYN or TCP_FIN in flags (programmer violates API)",
        flags & (TCP_SYN | TCP_FIN) != 0
    );
    lwip_assert!("tcp_enqueue_flags: invalid pcb", !pcb.is_null());

    // SAFETY: as the caller guarantees; a fresh pbuf and segment.
    unsafe {
        // No need to check pcb->snd_queuelen if only SYN or FIN are allowed!

        // Get options for this segment. This is a special case since this is the only
        // place where a SYN can be sent.
        let optflags = if flags & TCP_SYN != 0 {
            TF_SEG_OPTS_MSS
        } else {
            0
        };
        let optlen = lwip_tcp_opt_length(optflags);

        // Allocate pbuf with room for TCP header + options.
        let p = pbuf_alloc(PBUF_TRANSPORT, u16::from(optlen), PBUF_RAM);
        if p.is_null() {
            tcp_set_flags(pcb, TF_NAGLEMEMERR);
            return ERR_MEM;
        }
        lwip_assert!(
            "tcp_enqueue_flags: check that first pbuf can hold optlen",
            (*p).len >= u16::from(optlen)
        );

        // Allocate memory for tcp_seg, and fill in fields.
        let seg = tcp_create_segment(pcb, p, flags, (*pcb).snd_lbb, optflags);
        if seg.is_null() {
            tcp_set_flags(pcb, TF_NAGLEMEMERR);
            return ERR_MEM;
        }
        lwip_assert!(
            "seg->tcphdr not aligned",
            ((*seg).tcphdr as usize).is_multiple_of(config::MEM_ALIGNMENT.min(4))
        );
        lwip_assert!("tcp_enqueue_flags: invalid segment length", (*seg).len == 0);

        // Now append seg to pcb->unsent queue.
        if (*pcb).unsent.is_null() {
            (*pcb).unsent = seg;
        } else {
            let mut useg = (*pcb).unsent;
            while !(*useg).next.is_null() {
                useg = (*useg).next;
            }
            (*useg).next = seg;
        }
        // The new unsent tail has no space.
        (*pcb).unsent_oversize = 0;

        // SYN and FIN bump the sequence number.
        if flags & TCP_SYN != 0 || flags & TCP_FIN != 0 {
            (*pcb).snd_lbb = (*pcb).snd_lbb.wrapping_add(1);
            // Optlen does not influence snd_buf.
        }
        if flags & TCP_FIN != 0 {
            tcp_set_flags(pcb, TF_FIN);
        }

        // Update number of segments on the queues.
        (*pcb).snd_queuelen = (*pcb).snd_queuelen.wrapping_add(pbuf_clen((*seg).p));
        if (*pcb).snd_queuelen != 0 {
            lwip_assert!(
                "tcp_enqueue_flags: invalid queue length",
                !(*pcb).unacked.is_null() || !(*pcb).unsent.is_null()
            );
        }
    }
    ERR_OK
}

/// Find out what we can send and send it.
///
/// Returns `ERR_OK` if data has been sent or nothing to send, another `err_t` on error.
///
/// # Safety
///
/// `pcb` is live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_output(pcb: *mut TcpPcb) -> ErrT {
    lwip_assert!("tcp_output: invalid pcb", !pcb.is_null());
    // SAFETY: as the caller guarantees; segments on the PCB's queues are live.
    unsafe {
        // pcb->state LISTEN not allowed here.
        lwip_assert!(
            "don't call tcp_output for listen-pcbs",
            (*pcb).state != LISTEN
        );

        // First, check if we are invoked by the TCP input processing code. If so, we do
        // not output anything. Instead, we rely on the input processing code to call us
        // when input processing is done with.
        if tcp_input_pcb() == pcb {
            return ERR_OK;
        }

        let wnd = u32::from((*pcb).snd_wnd.min((*pcb).cwnd));

        let mut seg = (*pcb).unsent;

        'output_done: {
            if seg.is_null() {
                // If the TF_ACK_NOW flag is set and the ->unsent queue is empty, construct
                // an empty ACK segment and send it.
                if (*pcb).flags & TF_ACK_NOW != 0 {
                    return tcp_send_empty_ack(pcb);
                }
                // Nothing to send: shortcut out of here.
                break 'output_done;
            }

            let netif = tcp_route(pcb, &(*pcb).local_ip, &(*pcb).remote_ip);
            if netif.is_null() {
                return ERR_RTE;
            }

            // If we don't have a local IP address, we get one from netif.
            if (*pcb).local_ip.is_any() {
                let local_ip = ip_netif_get_local_ip(netif, &(*pcb).remote_ip);
                if local_ip.is_null() {
                    return ERR_RTE;
                }
                (*pcb).local_ip.copy_from(&*local_ip);
            }

            // Handle the current segment not fitting within the window.
            if seg_seqno(seg)
                .wrapping_sub((*pcb).lastack)
                .wrapping_add(u32::from((*seg).len))
                > wnd
            {
                // We need to start the persistent timer when the next unsent segment does
                // not fit within the remaining (could be 0) send window and RTO timer is
                // not running (we have no in-flight data). If window is still too small
                // after persist timer fires, then we split the segment. We don't consider
                // the congestion window since a cwnd smaller than 1 SMSS implies in-flight
                // data.
                if wnd == u32::from((*pcb).snd_wnd)
                    && (*pcb).unacked.is_null()
                    && (*pcb).persist_backoff == 0
                {
                    lwip_sometimes!(
                        "tcp_output: persist timer started for a closed window",
                        true
                    );
                    (*pcb).persist_cnt = 0;
                    (*pcb).persist_backoff = 1;
                    (*pcb).persist_probe = 0;
                }
                // We need an ACK, but can't send data now, so send an empty ACK.
                if (*pcb).flags & TF_ACK_NOW != 0 {
                    return tcp_send_empty_ack(pcb);
                }
                break 'output_done;
            }
            // Stop persist timer, above conditions are not active.
            (*pcb).persist_backoff = 0;

            // useg should point to last segment on unacked queue.
            let mut useg = (*pcb).unacked;
            if !useg.is_null() {
                while !(*useg).next.is_null() {
                    useg = (*useg).next;
                }
            }
            // Data available and window allows it to be sent?
            while !seg.is_null()
                && seg_seqno(seg)
                    .wrapping_sub((*pcb).lastack)
                    .wrapping_add(u32::from((*seg).len))
                    <= wnd
            {
                lwip_assert!(
                    "RST not expected here!",
                    tcph_flags((*seg).tcphdr) & TCP_RST == 0
                );
                // Stop sending if the nagle algorithm would prevent it. Don't stop:
                // - if tcp_write had a memory error before (prevent delayed ACK timeout)
                //   or
                // - if FIN was already enqueued for this PCB (SYN is always alone in a
                //   segment - either seg->next != NULL or pcb->unacked == NULL; RST is
                //   no sent using tcp_write/tcp_output.
                if !tcp_do_output_nagle(pcb) && (*pcb).flags & (TF_NAGLEMEMERR | TF_FIN) == 0 {
                    break;
                }

                if (*pcb).state != SYN_SENT {
                    tcph_set_flag((*seg).tcphdr, TCP_ACK);
                }

                let err = tcp_output_segment(seg, pcb, netif);
                if err != ERR_OK {
                    // Segment could not be sent, for whatever reason.
                    tcp_set_flags(pcb, TF_NAGLEMEMERR);
                    return err;
                }
                (*pcb).unsent = (*seg).next;
                if (*pcb).state != SYN_SENT {
                    tcp_clear_flags(pcb, TF_ACK_DELAY | TF_ACK_NOW);
                }
                let snd_nxt = seg_seqno(seg).wrapping_add(tcp_tcplen(seg));
                if tcp_seq_lt((*pcb).snd_nxt, snd_nxt) {
                    (*pcb).snd_nxt = snd_nxt;
                }
                // Put segment on unacknowledged list if length > 0.
                if tcp_tcplen(seg) > 0 {
                    (*seg).next = ptr::null_mut();
                    // Unacked list is empty?
                    if (*pcb).unacked.is_null() {
                        (*pcb).unacked = seg;
                        useg = seg;
                    // Unacked list is not empty?
                    } else {
                        // In the case of fast retransmit, the packet should not go to the
                        // tail of the unacked queue, but rather somewhere before it. We
                        // need to check for this case. -STJ Jul 27, 2004
                        if tcp_seq_lt(seg_seqno(seg), seg_seqno(useg)) {
                            // Add segment to before tail of unacked list, keeping the list
                            // sorted.
                            let mut cur_seg: *mut *mut TcpSeg = &raw mut (*pcb).unacked;
                            while !(*cur_seg).is_null()
                                && tcp_seq_lt(seg_seqno(*cur_seg), seg_seqno(seg))
                            {
                                cur_seg = &raw mut (**cur_seg).next;
                            }
                            (*seg).next = *cur_seg;
                            *cur_seg = seg;
                        } else {
                            // Add segment to tail of unacked list.
                            (*useg).next = seg;
                            useg = (*useg).next;
                        }
                    }
                // Do not queue empty segments on the unacked list.
                } else {
                    tcp_seg_free(seg);
                }
                seg = (*pcb).unsent;
            }
            if (*pcb).unsent.is_null() {
                // Last unsent has been removed, reset unsent_oversize.
                (*pcb).unsent_oversize = 0;
            }
        }

        // output_done:
        tcp_clear_flags(pcb, TF_NAGLEMEMERR);
    }
    ERR_OK
}

/// Check if a segment's pbufs are used by someone else than TCP. This can happen on
/// retransmission if the pbuf of this segment is still referenced by the netif driver
/// due to deferred transmission. This is the case (only!) if someone down the TX call
/// path called pbuf_ref() on one of the pbufs!
///
/// # Safety
///
/// `seg` is a live segment.
unsafe fn tcp_output_segment_busy(seg: *const TcpSeg) -> bool {
    lwip_assert!("tcp_output_segment_busy: invalid seg", !seg.is_null());

    // We only need to check the first pbuf here: If a pbuf is queued for transmission, a
    // driver calls pbuf_ref(), which only changes the ref count of the first pbuf.
    // SAFETY: as the caller guarantees.
    unsafe { (*(*seg).p).ref_ != 1 }
}

/// Called by `tcp_output()` to actually send a TCP segment over IP.
///
/// # Safety
///
/// `seg`, `pcb`, and `netif` are live.
unsafe fn tcp_output_segment(seg: *mut TcpSeg, pcb: *mut TcpPcb, netif: *mut Netif) -> ErrT {
    lwip_assert!("tcp_output_segment: invalid seg", !seg.is_null());
    lwip_assert!("tcp_output_segment: invalid pcb", !pcb.is_null());
    lwip_assert!("tcp_output_segment: invalid netif", !netif.is_null());

    // SAFETY: as the caller guarantees; the header and options are in the segment's
    // first pbuf.
    unsafe {
        if tcp_output_segment_busy(seg) {
            // This should not happen: rexmit functions should have checked this.
            // However, since this function modifies p->len, we must not continue in
            // this case.
            return ERR_OK;
        }

        let tcphdr = (*seg).tcphdr;
        // The TCP header has already been constructed, but the ackno and wnd fields
        // remain.
        ptr::addr_of_mut!((*tcphdr).ackno).write_unaligned((*pcb).rcv_nxt.to_be());

        // Advertise our receive window size in this TCP segment.
        ptr::addr_of_mut!((*tcphdr).wnd).write_unaligned((*pcb).rcv_ann_wnd.to_be());

        (*pcb).rcv_ann_right_edge = (*pcb).rcv_nxt.wrapping_add(u32::from((*pcb).rcv_ann_wnd));

        // Add any requested options. NB MSS option is only set on SYN packets, so ignore
        // it here.
        let mut opts = tcphdr.add(1).cast::<u8>();
        if (*seg).flags & TF_SEG_OPTS_MSS != 0 {
            let mss = tcp_eff_send_mss_netif(TCP_MSS, netif, &(*pcb).remote_ip);
            opts.cast::<u32>()
                .write_unaligned((0x0204_0000_u32 | u32::from(mss)).to_be());
            opts = opts.add(4);
        }

        // Set retransmission timer running if it is not currently enabled. This must be
        // set before checking the route.
        if (*pcb).rtime < 0 {
            (*pcb).rtime = 0;
        }

        if (*pcb).rttest == 0 {
            (*pcb).rttest = tcp_ticks();
            (*pcb).rtseq = seg_seqno(seg);
        }

        let p = (*seg).p;
        let len = tcphdr.cast::<u8>().offset_from((*p).payload.cast::<u8>()) as u16;
        (*p).len -= len;
        (*p).tot_len -= len;

        (*p).payload = tcphdr.cast();

        ptr::addr_of_mut!((*tcphdr).chksum).write_unaligned(0);

        lwip_assert!(
            "options not filled",
            opts == tcphdr
                .add(1)
                .cast::<u8>()
                .add(usize::from(lwip_tcp_opt_length((*seg).flags)))
        );

        let chksum = ip_chksum_pseudo(
            p,
            IP_PROTO_TCP_,
            (*p).tot_len,
            &(*pcb).local_ip,
            &(*pcb).remote_ip,
        );
        ptr::addr_of_mut!((*tcphdr).chksum).write_unaligned(chksum);

        ip_output_if(
            p,
            &(*pcb).local_ip,
            &(*pcb).remote_ip,
            (*pcb).ttl,
            (*pcb).tos,
            IP_PROTO_TCP_,
            netif,
        )
    }
}

/// Requeue all unacked segments for retransmission.
///
/// Called by `tcp_slowtmr()` for slow retransmission.
///
/// # Safety
///
/// `pcb` is live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_rexmit_rto_prepare(pcb: *mut TcpPcb) -> ErrT {
    lwip_assert!("tcp_rexmit_rto_prepare: invalid pcb", !pcb.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        if (*pcb).unacked.is_null() {
            return ERR_VAL;
        }

        lwip_sometimes!(
            "tcp_rexmit_rto_prepare: retransmission timeout with unacked data",
            true
        );
        // Move all unacked segments to the head of the unsent queue. However, give up if
        // any of the unsent pbufs are still referenced by the netif driver due to
        // deferred transmission. No point loading the link further if it is struggling to
        // flush its buffered writes.
        let mut seg = (*pcb).unacked;
        while !(*seg).next.is_null() {
            if tcp_output_segment_busy(seg) {
                return ERR_VAL;
            }
            seg = (*seg).next;
        }
        if tcp_output_segment_busy(seg) {
            return ERR_VAL;
        }
        // Concatenate unsent queue after unacked queue.
        (*seg).next = (*pcb).unsent;
        // Unsent queue is the concatenated queue (of unacked, unsent).
        (*pcb).unsent = (*pcb).unacked;
        // Unacked queue is now empty.
        (*pcb).unacked = ptr::null_mut();

        // Mark RTO in-progress.
        tcp_set_flags(pcb, TF_RTO);
        // Record the next byte following retransmit.
        (*pcb).rto_end = seg_seqno(seg).wrapping_add(tcp_tcplen(seg));
        // Don't take any RTT measurements after retransmitting.
        (*pcb).rttest = 0;
    }
    ERR_OK
}

/// Requeue all unacked segments for retransmission.
///
/// Called by `tcp_slowtmr()` for slow retransmission.
///
/// # Safety
///
/// `pcb` is live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_rexmit_rto_commit(pcb: *mut TcpPcb) {
    lwip_assert!("tcp_rexmit_rto_commit: invalid pcb", !pcb.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        // Increment number of retransmissions.
        (*pcb).nrtx = (*pcb).nrtx.saturating_add(1);
        // Do the actual retransmission.
        tcp_output(pcb);
    }
}

/// Requeue all unacked segments for retransmission.
///
/// Called by `tcp_process()` only, `tcp_slowtmr()` needs to do some things between
/// "prepare" and "commit".
///
/// # Safety
///
/// `pcb` is live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_rexmit_rto(pcb: *mut TcpPcb) {
    lwip_assert!("tcp_rexmit_rto: invalid pcb", !pcb.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        if tcp_rexmit_rto_prepare(pcb) == ERR_OK {
            tcp_rexmit_rto_commit(pcb);
        }
    }
}

/// Requeue the first unacked segment for retransmission.
///
/// Called by `tcp_receive()` for fast retransmit.
///
/// # Safety
///
/// `pcb` is live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_rexmit(pcb: *mut TcpPcb) -> ErrT {
    lwip_assert!("tcp_rexmit: invalid pcb", !pcb.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        if (*pcb).unacked.is_null() {
            return ERR_VAL;
        }

        let seg = (*pcb).unacked;

        // Give up if the segment is still referenced by the netif driver due to deferred
        // transmission.
        if tcp_output_segment_busy(seg) {
            return ERR_VAL;
        }

        // Move the first unacked segment to the unsent queue. Keep the unsent queue
        // sorted.
        (*pcb).unacked = (*seg).next;

        let mut cur_seg: *mut *mut TcpSeg = &raw mut (*pcb).unsent;
        while !(*cur_seg).is_null() && tcp_seq_lt(seg_seqno(*cur_seg), seg_seqno(seg)) {
            cur_seg = &raw mut (**cur_seg).next;
        }
        (*seg).next = *cur_seg;
        *cur_seg = seg;
        if (*seg).next.is_null() {
            // The retransmitted segment is the last in the unsent queue.
            (*pcb).unsent_oversize = 0;
        }

        (*pcb).nrtx = (*pcb).nrtx.saturating_add(1);

        // Don't take any rtt measurements after retransmitting.
        (*pcb).rttest = 0;
    }

    // Do the actual retransmission: done by tcp_output.
    ERR_OK
}

/// Handle retransmission after three dupacks received.
///
/// # Safety
///
/// `pcb` is live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_rexmit_fast(pcb: *mut TcpPcb) {
    lwip_assert!("tcp_rexmit_fast: invalid pcb", !pcb.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        if !(*pcb).unacked.is_null() && (*pcb).flags & TF_INFR == 0 {
            lwip_sometimes!("tcp_rexmit_fast: fast retransmit", true);
            // This is fast retransmit. Retransmit the first unacked segment.
            if tcp_rexmit(pcb) == ERR_OK {
                // Set ssthresh to half of the minimum of the current cwnd and the
                // advertised window.
                (*pcb).ssthresh = (*pcb).cwnd.min((*pcb).snd_wnd) / 2;

                // The minimum value for ssthresh should be 2 MSS.
                if u32::from((*pcb).ssthresh) < 2 * u32::from((*pcb).mss) {
                    (*pcb).ssthresh = (2 * u32::from((*pcb).mss)) as TcpWnd;
                }

                (*pcb).cwnd = (u32::from((*pcb).ssthresh) + 3 * u32::from((*pcb).mss)) as TcpWnd;
                tcp_set_flags(pcb, TF_INFR);

                // Reset the retransmission timer to prevent immediate rto retransmissions.
                (*pcb).rtime = 0;
            }
        }
    }
}

/// Allocate a header-only pbuf for a segment sent directly.
///
/// # Safety
///
/// None beyond the allocator's; the result is null or a fresh pbuf.
#[allow(clippy::too_many_arguments)]
unsafe fn tcp_output_alloc_header_common(
    ackno: u32,
    optlen: u16,
    datalen: u16,
    seqno_be: u32,
    src_port: u16,
    dst_port: u16,
    flags: u8,
    wnd: u16,
) -> *mut Pbuf {
    // SAFETY: a fresh pbuf, the header in its first TCP_HLEN + optlen bytes.
    unsafe {
        let p = pbuf_alloc(PBUF_IP, TCP_HLEN + optlen + datalen, PBUF_RAM);
        if !p.is_null() {
            lwip_assert!(
                "check that first pbuf can hold struct tcp_hdr",
                (*p).len >= TCP_HLEN + optlen
            );
            let tcphdr = (*p).payload.cast::<TcpHdr>();
            ptr::addr_of_mut!((*tcphdr).src).write_unaligned(src_port.to_be());
            ptr::addr_of_mut!((*tcphdr).dest).write_unaligned(dst_port.to_be());
            ptr::addr_of_mut!((*tcphdr).seqno).write_unaligned(seqno_be);
            ptr::addr_of_mut!((*tcphdr).ackno).write_unaligned(ackno.to_be());
            tcph_hdrlen_flags_set(tcphdr, 5 + optlen / 4, flags);
            ptr::addr_of_mut!((*tcphdr).wnd).write_unaligned(wnd.to_be());
            ptr::addr_of_mut!((*tcphdr).chksum).write_unaligned(0);
            ptr::addr_of_mut!((*tcphdr).urgp).write_unaligned(0);
        }
        p
    }
}

/// Create a TCP segment usable for passing to `tcp_output_control_segment`.
///
/// # Safety
///
/// `pcb` is live.
unsafe fn tcp_output_alloc_header(
    pcb: *mut TcpPcb,
    optlen: u16,
    datalen: u16,
    seqno_be: u32,
) -> *mut Pbuf {
    lwip_assert!("tcp_output_alloc_header: invalid pcb", !pcb.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        let p = tcp_output_alloc_header_common(
            (*pcb).rcv_nxt,
            optlen,
            datalen,
            seqno_be,
            (*pcb).local_port,
            (*pcb).remote_port,
            TCP_ACK,
            (*pcb).rcv_ann_wnd,
        );
        if !p.is_null() {
            // If we're sending a packet, update the announced right window edge.
            (*pcb).rcv_ann_right_edge = (*pcb).rcv_nxt.wrapping_add(u32::from((*pcb).rcv_ann_wnd));
        }
        p
    }
}

/// Fill in options for control segments: none are configured.
fn tcp_output_fill_options(_pcb: *const TcpPcb, p: *mut Pbuf, optflags: u8, _num_sacks: u8) {
    lwip_assert!("tcp_output_fill_options: invalid pbuf", !p.is_null());
    // No option is configured, so the options end where they start.
    lwip_assert!("options not filled", lwip_tcp_opt_length(optflags) == 0);
}

/// Output a control segment pbuf to IP.
///
/// Called from `tcp_rst`, `tcp_send_empty_ack`, `tcp_keepalive` and
/// `tcp_zero_window_probe`, this function combines selecting a netif for transmission,
/// generating the tcp header checksum and calling ip_output_if while handling netif
/// hints and stats.
///
/// # Safety
///
/// `pcb` is null or live, `p` a pbuf this takes, and `src` and `dst` valid.
unsafe fn tcp_output_control_segment(
    pcb: *const TcpPcb,
    p: *mut Pbuf,
    src: *const IpAddr,
    dst: *const IpAddr,
) -> ErrT {
    lwip_assert!("tcp_output_control_segment: invalid pbuf", !p.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        let netif = tcp_route(pcb, src, dst);
        if netif.is_null() {
            pbuf_free(p);
            return ERR_RTE;
        }
        tcp_output_control_segment_netif(pcb, p, src, dst, netif)
    }
}

/// Output a control segment pbuf to IP, through `netif`.
///
/// # Safety
///
/// As `tcp_output_control_segment`, and `netif` live.
unsafe fn tcp_output_control_segment_netif(
    pcb: *const TcpPcb,
    p: *mut Pbuf,
    src: *const IpAddr,
    dst: *const IpAddr,
    netif: *mut Netif,
) -> ErrT {
    lwip_assert!(
        "tcp_output_control_segment_netif: no netif given",
        !netif.is_null()
    );

    // SAFETY: as the caller guarantees; the header is at the pbuf's payload.
    unsafe {
        let tcphdr = (*p).payload.cast::<TcpHdr>();
        let chksum = ip_chksum_pseudo(p, IP_PROTO_TCP_, (*p).tot_len, src, dst);
        ptr::addr_of_mut!((*tcphdr).chksum).write_unaligned(chksum);

        let (ttl, tos) = if pcb.is_null() {
            (TCP_TTL, 0)
        } else {
            ((*pcb).ttl, (*pcb).tos)
        };
        let err = ip_output_if(p, src, dst, ttl, tos, IP_PROTO_TCP_, netif);
        pbuf_free(p);
        err
    }
}

/// A RST segment's pbuf.
///
/// # Safety
///
/// `local_ip` and `remote_ip` are valid.
unsafe fn tcp_rst_common(
    pcb: *const TcpPcb,
    seqno: u32,
    ackno: u32,
    local_ip: *const IpAddr,
    remote_ip: *const IpAddr,
    local_port: u16,
    remote_port: u16,
) -> *mut Pbuf {
    lwip_assert!("tcp_rst: invalid local_ip", !local_ip.is_null());
    lwip_assert!("tcp_rst: invalid remote_ip", !remote_ip.is_null());

    let optlen = u16::from(lwip_tcp_opt_length(0));

    // As in tcp_out.c, the window is swapped to network order here and again when the
    // header is written.
    let wnd = TCP_WND.swap_bytes();

    // SAFETY: a fresh pbuf.
    unsafe {
        let p = tcp_output_alloc_header_common(
            ackno,
            optlen,
            0,
            seqno.to_be(),
            local_port,
            remote_port,
            TCP_RST | TCP_ACK,
            wnd,
        );
        if p.is_null() {
            return ptr::null_mut();
        }
        tcp_output_fill_options(pcb, p, 0, 0);
        p
    }
}

/// Send a TCP RESET packet (empty segment with RST flag set) to abort a connection.
///
/// Called by `tcp_abort()` (to abort a local connection), `tcp_closen()` (if not all
/// data has been received by the application), `tcp_timewait_input()` (if a SYN is
/// received) and `tcp_process()` (received segment in the wrong state).
///
/// Since a RST segment is in most cases not sent for an active connection,
/// `tcp_rst()` has a number of arguments that are taken from a tcp_pcb for most other
/// segment output functions.
///
/// # Safety
///
/// `pcb` is null or live, and `local_ip` and `remote_ip` valid.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_rst(
    pcb: *const TcpPcb,
    seqno: u32,
    ackno: u32,
    local_ip: *const IpAddr,
    remote_ip: *const IpAddr,
    local_port: u16,
    remote_port: u16,
) {
    // SAFETY: as the caller guarantees.
    unsafe {
        let p = tcp_rst_common(
            pcb,
            seqno,
            ackno,
            local_ip,
            remote_ip,
            local_port,
            remote_port,
        );
        if !p.is_null() {
            tcp_output_control_segment(pcb, p, local_ip, remote_ip);
        }
    }
}

/// Send a TCP RESET packet (empty segment with RST flag set) to show that there is no
/// matching local connection for a received segment.
///
/// Called by `tcp_input()` (if no matching local pcb was found) and
/// `tcp_listen_input()` (if incoming segment has ACK flag set).
///
/// # Safety
///
/// `netif` is null or live, and `local_ip` and `remote_ip` valid.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_rst_netif(
    netif: *mut Netif,
    seqno: u32,
    ackno: u32,
    local_ip: *const IpAddr,
    remote_ip: *const IpAddr,
    local_port: u16,
    remote_port: u16,
) {
    if !netif.is_null() {
        // SAFETY: as the caller guarantees.
        unsafe {
            let p = tcp_rst_common(
                ptr::null(),
                seqno,
                ackno,
                local_ip,
                remote_ip,
                local_port,
                remote_port,
            );
            if !p.is_null() {
                tcp_output_control_segment_netif(ptr::null(), p, local_ip, remote_ip, netif);
            }
        }
    }
}

/// Send an ACK without data.
///
/// # Safety
///
/// `pcb` is live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_send_empty_ack(pcb: *mut TcpPcb) -> ErrT {
    lwip_assert!("tcp_send_empty_ack: invalid pcb", !pcb.is_null());

    let optflags: u8 = 0;
    let num_sacks: u8 = 0;
    let optlen = u16::from(lwip_tcp_opt_length(optflags));

    // SAFETY: as the caller guarantees.
    unsafe {
        let p = tcp_output_alloc_header(pcb, optlen, 0, (*pcb).snd_nxt.to_be());
        if p.is_null() {
            // Let tcp_fasttmr retry sending this ACK.
            tcp_set_flags(pcb, TF_ACK_DELAY | TF_ACK_NOW);
            return ERR_BUF;
        }
        tcp_output_fill_options(pcb, p, optflags, num_sacks);

        let err = tcp_output_control_segment(pcb, p, &(*pcb).local_ip, &(*pcb).remote_ip);
        if err != ERR_OK {
            // Let tcp_fasttmr retry sending this ACK.
            tcp_set_flags(pcb, TF_ACK_DELAY | TF_ACK_NOW);
        } else {
            // Remove ACK flags from the PCB, as we sent an empty ACK now.
            tcp_clear_flags(pcb, TF_ACK_DELAY | TF_ACK_NOW);
        }
        err
    }
}

/// Send keepalive packets to keep a connection active although no data is sent over
/// it.
///
/// Called by `tcp_slowtmr()`.
///
/// # Safety
///
/// `pcb` is live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_keepalive(pcb: *mut TcpPcb) -> ErrT {
    let optlen = u16::from(lwip_tcp_opt_length(0));

    lwip_assert!("tcp_keepalive: invalid pcb", !pcb.is_null());
    lwip_sometimes!("tcp_keepalive: keepalive probe sent", true);

    // SAFETY: as the caller guarantees.
    unsafe {
        let p = tcp_output_alloc_header(pcb, optlen, 0, (*pcb).snd_nxt.wrapping_sub(1).to_be());
        if p.is_null() {
            return ERR_MEM;
        }
        tcp_output_fill_options(pcb, p, 0, 0);
        tcp_output_control_segment(pcb, p, &(*pcb).local_ip, &(*pcb).remote_ip)
    }
}

/// Send persist timer zero-window probes to keep a connection active when a window
/// update is lost.
///
/// Called by `tcp_slowtmr()`.
///
/// # Safety
///
/// `pcb` is live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn tcp_zero_window_probe(pcb: *mut TcpPcb) -> ErrT {
    let optlen = u16::from(lwip_tcp_opt_length(0));

    lwip_assert!("tcp_zero_window_probe: invalid pcb", !pcb.is_null());
    lwip_sometimes!("tcp_zero_window_probe: zero window probe sent", true);

    // SAFETY: as the caller guarantees; the unsent head segment is live.
    unsafe {
        // Only consider unsent, persist timer should be off when there is data in-flight.
        let seg = (*pcb).unsent;
        if seg.is_null() {
            // Not expected, persist timer should be off when the send buffer is empty.
            return ERR_OK;
        }

        // Increment probe count. NOTE: we record probe even if it fails to actually
        // transmit due to an error. This ensures memory exhaustion/routing problem
        // doesn't leave a zero-window pcb as an indefinite zombie. RTO mechanism has
        // similar behavior, see pcb->nrtx.
        (*pcb).persist_probe = (*pcb).persist_probe.saturating_add(1);

        let is_fin = tcph_flags((*seg).tcphdr) & TCP_FIN != 0 && (*seg).len == 0;
        // We want to send one seqno: either FIN or data (no options).
        let len: u16 = if is_fin { 0 } else { 1 };

        let p = tcp_output_alloc_header(
            pcb,
            optlen,
            len,
            ptr::addr_of!((*(*seg).tcphdr).seqno).read_unaligned(),
        );
        if p.is_null() {
            return ERR_MEM;
        }
        let tcphdr = (*p).payload.cast::<TcpHdr>();

        if is_fin {
            // FIN segment, no data.
            let field = ptr::addr_of_mut!((*tcphdr)._hdrlen_rsvd_flags);
            field.write_unaligned(
                (field.read_unaligned() & (!u16::from(TCP_FLAGS)).to_be())
                    | u16::from(TCP_ACK | TCP_FIN).to_be(),
            );
        } else {
            // Data segment, copy in one byte from the head of the unacked queue.
            let d = (*p).payload.cast::<u8>().add(usize::from(TCP_HLEN));
            // Depending on whether the segment has already been sent (unacked) or not
            // (unsent), seg->p->payload points to the IP header or TCP header. Ensure we
            // copy the first TCP data byte:
            pbuf_copy_partial((*seg).p, d.cast(), 1, (*(*seg).p).tot_len - (*seg).len);
        }

        // The byte may be acknowledged without the window being opened.
        let snd_nxt = seg_seqno(seg).wrapping_add(1);
        if tcp_seq_lt((*pcb).snd_nxt, snd_nxt) {
            (*pcb).snd_nxt = snd_nxt;
        }
        tcp_output_fill_options(pcb, p, 0, 0);

        tcp_output_control_segment(pcb, p, &(*pcb).local_ip, &(*pcb).remote_ip)
    }
}

#[cfg(test)]
mod tests;
