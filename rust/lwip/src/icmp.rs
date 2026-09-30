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

//! ICMP - Internet Control Message Protocol, from `src/core/ipv4/icmp.c`, as ESP-IDF
//! configures it: echo requests answered (not to broadcast or multicast addresses),
//! checksums checked and generated, and destination-unreachable messages sent
//! (`build.rs` refuses the rest). Some ICMP messages should be passed to the transport
//! protocols; this is not implemented.
//!
//! # Safety
//!
//! Like the C module, this one runs in the tcpip thread from `ip4_input`, whose
//! `ip_data` describes the packet. Headers are read and written unaligned, as the packed
//! C structs are.

use core::ptr;

use crate::config;
use crate::links::*;
use crate::types::*;

/// `ICMP_ER`: echo reply.
const ICMP_ER: u8 = 0;
/// `ICMP_DUR`: destination unreachable.
const ICMP_DUR: u8 = 3;
/// `ICMP_ECHO`: echo.
const ICMP_ECHO: u8 = 8;

/// The amount of data from the original packet to return in a dest-unreachable.
const ICMP_DEST_UNREACH_DATASIZE: u16 = 8;

/// `ip4_addr_ismulticast()`: 224.0.0.0/4.
fn ismulticast(addr: u32) -> bool {
    addr & 0xf000_0000_u32.to_be() == 0xe000_0000_u32.to_be()
}

/// Processes ICMP input packets, called from `ip4_input()`.
///
/// Currently only processes icmp echo requests and sends out the echo response.
///
/// # Safety
///
/// `p` is a live pbuf chain at the ICMP header, `inp` the live netif it arrived on, and
/// `ip_data` describes the packet; the caller gives up `p`.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn icmp_input(p: *mut Pbuf, inp: *mut Netif) {
    let mut p = p;

    // SAFETY: as the caller guarantees.
    unsafe {
        let ipd = ip_data();
        let iphdr_in = (*ipd).current_ip4_header;
        let hlen = u16::from((iphdr_in.read_unaligned().v_hl & 0x0f) * 4);
        if hlen < IP_HLEN {
            // lenerr
            pbuf_free(p);
            return;
        }
        if usize::from((*p).len) < core::mem::size_of::<u16>() * 2 {
            // lenerr
            pbuf_free(p);
            return;
        }

        let type_ = (*p).payload.cast::<u8>().read();
        match type_ {
            ICMP_ER => {
                // This is OK, echo reply might have been parsed by a raw PCB (as
                // obviously, an echo request has been sent, too).
            }
            ICMP_ECHO => {
                let src = (*ipd).current_iphdr_dest.ip4();
                // Multicast destination address?
                if ismulticast(src.addr) {
                    // For multicast, use address of receiving interface as source address.
                    // (LWIP_MULTICAST_PING is 0: drop.)
                    pbuf_free(p);
                    return;
                }
                // Broadcast destination address?
                if ip4_addr_isbroadcast_u32(src.addr, (*ipd).current_netif) != 0 {
                    // For broadcast, use address of receiving interface as source address.
                    // (LWIP_BROADCAST_PING is 0: drop.)
                    pbuf_free(p);
                    return;
                }
                if usize::from((*p).tot_len) < core::mem::size_of::<IcmpEchoHdr>() {
                    // lenerr
                    pbuf_free(p);
                    return;
                }
                if inet_chksum_pbuf(p) != 0 {
                    pbuf_free(p);
                    return;
                }
                let link = config::PBUF_LINK_LAYER as u16;
                if pbuf_add_header(p, usize::from(hlen + link)) != 0 {
                    // Not enough space in the pbuf for the IP and link headers: allocate
                    // a new one and copy p into it.
                    let alloc_len = (*p).tot_len.wrapping_add(hlen);
                    if alloc_len < (*p).tot_len {
                        // icmperr
                        pbuf_free(p);
                        return;
                    }
                    // Allocate new packet buffer with space for link headers.
                    let r = pbuf_alloc(config::PBUF_LINK_LAYER as PbufLayer, alloc_len, PBUF_RAM);
                    if r.is_null() {
                        pbuf_free(p);
                        return;
                    }
                    if usize::from((*r).len)
                        < usize::from(hlen) + core::mem::size_of::<IcmpEchoHdr>()
                    {
                        pbuf_free(r);
                        pbuf_free(p);
                        return;
                    }
                    // Copy the ip header.
                    ptr::copy(
                        iphdr_in.cast::<u8>(),
                        (*r).payload.cast::<u8>(),
                        usize::from(hlen),
                    );
                    // Switch r->payload back to icmp header (cannot fail).
                    if pbuf_remove_header(r, usize::from(hlen)) != 0 {
                        lwip_assert!("icmp_input: moving r->payload to icmp header failed", false);
                        pbuf_free(r);
                        pbuf_free(p);
                        return;
                    }
                    // Copy the rest of the packet without ip header.
                    if pbuf_copy(r, p) != ERR_OK {
                        pbuf_free(r);
                        pbuf_free(p);
                        return;
                    }
                    // Free the original p.
                    pbuf_free(p);
                    // We now have an identical copy of p that has room for link headers.
                    p = r;
                } else if pbuf_remove_header(p, usize::from(hlen + link)) != 0 {
                    // Restore p->payload to point to icmp header (cannot fail).
                    lwip_assert!("icmp_input: restoring original p->payload failed", false);
                    pbuf_free(p);
                    return;
                }
                // At this point, all checks are OK. We generate an answer by switching
                // the dest and src ip addresses, setting the icmp type to ECHO_RESPONSE
                // and updating the checksum.
                let iecho = (*p).payload.cast::<IcmpEchoHdr>();
                if pbuf_add_header(p, usize::from(hlen)) == 0 {
                    let iphdr = (*p).payload.cast::<IpHdr>();
                    ptr::addr_of_mut!((*iphdr).src).write_unaligned(src.addr);
                    ptr::addr_of_mut!((*iphdr).dest)
                        .write_unaligned((*ipd).current_iphdr_src.ip4().addr);
                    ptr::addr_of_mut!((*iecho).type_).write(ICMP_ER);
                    // Adjust the checksum.
                    let chksum_ptr = ptr::addr_of_mut!((*iecho).chksum);
                    let chksum = chksum_ptr.read_unaligned();
                    let echo = u16::from(ICMP_ECHO) << 8;
                    if chksum > (0xffff - echo).to_be() {
                        chksum_ptr
                            .write_unaligned(chksum.wrapping_add(echo.to_be()).wrapping_add(1));
                    } else {
                        chksum_ptr.write_unaligned(chksum.wrapping_add(echo.to_be()));
                    }

                    // Set the TTL in the IP header.
                    ptr::addr_of_mut!((*iphdr).ttl).write(config::ICMP_TTL as u8);
                    ptr::addr_of_mut!((*iphdr).chksum).write_unaligned(0);
                    ptr::addr_of_mut!((*iphdr).chksum)
                        .write_unaligned(inet_chksum(iphdr.cast(), hlen));

                    // Send an ICMP packet; the IP header is included (LWIP_IP_HDRINCL).
                    ip4_output_if(
                        p,
                        src,
                        ptr::null(),
                        config::ICMP_TTL as u8,
                        0,
                        IP_PROTO_ICMP,
                        inp,
                    );
                }
            }
            _ => {
                // ICMP type not supported.
            }
        }
        pbuf_free(p);
    }
}

/// Send an icmp 'destination unreachable' packet, called from `ip4_input()` if the
/// transport layer protocol is unknown and from `udp_input()` if the local port is not
/// bound.
///
/// `p` is the input packet for which the 'unreachable' should be sent, with its payload
/// pointing to the IP header; it is not freed.
///
/// # Safety
///
/// `p` is a live pbuf chain at an IPv4 header.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn icmp_dest_unreach(p: *mut Pbuf, t: IcmpDurType) {
    // SAFETY: forwarded from the caller.
    unsafe { icmp_send_response(p, ICMP_DUR, t as u8) };
}

/// Send an ICMP packet (to be called from `icmp_dest_unreach` and, with IP forwarding or
/// reassembly, `icmp_time_exceeded`), quoting the start of `p`.
///
/// # Safety
///
/// `p` is a live pbuf chain at an IPv4 header.
unsafe fn icmp_send_response(p: *mut Pbuf, type_: u8, code: u8) {
    // SAFETY: as the caller guarantees; the ICMP header is written into q's payload,
    // which holds it and the quoted bytes.
    unsafe {
        // Increase number of messages attempted to send.
        let mut response_pkt_len = IP_HLEN + ICMP_DEST_UNREACH_DATASIZE;
        if (*p).tot_len < response_pkt_len {
            response_pkt_len = (*p).tot_len;
        }

        // ICMP header + IP header + 8 bytes of data.
        let icmp_hdr_len = core::mem::size_of::<IcmpHdr>() as u16;
        let q = pbuf_alloc(
            config::PBUF_IP_LAYER as PbufLayer,
            icmp_hdr_len + response_pkt_len,
            PBUF_RAM,
        );
        if q.is_null() {
            return;
        }
        lwip_assert!(
            "check that first pbuf can hold icmp message",
            (*q).len >= icmp_hdr_len + response_pkt_len
        );

        let iphdr = (*p).payload.cast::<IpHdr>();

        let icmphdr = (*q).payload.cast::<IcmpHdr>();
        ptr::addr_of_mut!((*icmphdr).type_).write(type_);
        ptr::addr_of_mut!((*icmphdr).code).write(code);
        ptr::addr_of_mut!((*icmphdr).data).write_unaligned(0);

        // Copy fields from original packet.
        pbuf_copy_partial_pbuf(q, p, response_pkt_len, icmp_hdr_len);

        let iphdr_src = Ip4Addr {
            addr: ptr::addr_of!((*iphdr).src).read_unaligned(),
        };
        let iphdr_dst = Ip4Addr {
            addr: ptr::addr_of!((*iphdr).dest).read_unaligned(),
        };
        let netif = ip4_route_src(&iphdr_dst, &iphdr_src);
        if !netif.is_null() {
            // Calculate checksum.
            ptr::addr_of_mut!((*icmphdr).chksum).write_unaligned(0);
            ptr::addr_of_mut!((*icmphdr).chksum)
                .write_unaligned(inet_chksum(icmphdr.cast(), (*q).len));
            ip4_output_if(
                q,
                ptr::null(),
                &iphdr_src,
                config::ICMP_TTL as u8,
                0,
                IP_PROTO_ICMP,
                netif,
            );
        }
        pbuf_free(q);
    }
}

#[cfg(test)]
mod tests;
