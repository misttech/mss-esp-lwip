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
// Author: Jani Monoses <jani@iv.ro>
//         Simon Goldschmidt
// original reassembly code by Adam Dunkels <adam@sics.se>
//
// Translated to Rust for mss-esp-lwip by Mist Tecnologia LTDA.

//! This is the IPv4 packet segmentation implementation, from `src/core/ipv4/ip4_frag.c`,
//! as ESP-IDF configures it: fragmentation by copying each fragment into its own pbuf
//! (`LWIP_NETIF_TX_SINGLE_PBUF`), and no reassembly (`build.rs` refuses the rest).

use core::ptr;

use crate::config;
use crate::links::{inet_chksum, pbuf_add_header, pbuf_alloc, pbuf_copy_partial, pbuf_free};
use crate::types::*;

/// Fragment an IP datagram if too large for the netif.
///
/// Chop the datagram in MTU sized chunks and send them in order by pointing PBUF_REFs
/// into p (or, as here, copying each chunk into its own pbuf).
///
/// Returns `ERR_OK` if sent successfully, `err_t` otherwise.
///
/// # Safety
///
/// `p` is a live pbuf chain starting with an IPv4 header, `netif` a live netif with an
/// `output`, and `dest` valid.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ip4_frag(p: *mut Pbuf, netif: *mut Netif, dest: *const Ip4Addr) -> ErrT {
    // SAFETY: as the caller guarantees; each fragment is a fresh pbuf in one piece.
    unsafe {
        let nfb = ((i32::from((*netif).mtu) - i32::from(IP_HLEN)) / 8) as u16;
        let mut poff = IP_HLEN;

        let original_iphdr = (*p).payload.cast::<IpHdr>();
        let orig = original_iphdr.read_unaligned();

        // Save original offset.
        if u16::from((orig.v_hl & 0x0f) * 4) != IP_HLEN {
            // ip4_frag() does not support IP options.
            return ERR_VAL;
        }
        // LWIP_ERROR("ip4_frag(): pbuf too short", p->len >= IP_HLEN, return ERR_VAL);
        if (*p).len < IP_HLEN {
            return ERR_VAL;
        }

        let tmp = u16::from_be(orig.offset);
        let mut ofo = tmp & IP_OFFMASK;
        // Is the IP header of the input packet already a fragment?
        let mf_set = tmp & IP_MF != 0;

        let mut left = (*p).tot_len.wrapping_sub(IP_HLEN);

        while left != 0 {
            // Fill this fragment.
            let fragsize = left.min(nfb.wrapping_mul(8));

            // When not using a static buffer, create a buffer for the fragment and copy
            // the data into it.
            let rambuf = pbuf_alloc(config::PBUF_IP_LAYER as PbufLayer, fragsize, PBUF_RAM);
            if rambuf.is_null() {
                return ERR_MEM;
            }
            lwip_assert!(
                "this needs a pbuf in one piece!",
                (*rambuf).len == (*rambuf).tot_len && (*rambuf).next.is_none()
            );
            poff = poff.wrapping_add(pbuf_copy_partial(p, (*rambuf).payload, fragsize, poff));
            // Make room for the IP header.
            if pbuf_add_header(rambuf, IP_HLEN.into()) != 0 {
                pbuf_free(rambuf);
                return ERR_MEM;
            }
            // Fill in the IP header.
            ptr::copy(
                original_iphdr.cast::<u8>(),
                (*rambuf).payload.cast::<u8>(),
                usize::from(IP_HLEN),
            );
            let iphdr = (*rambuf).payload.cast::<IpHdr>();

            let last = i32::from(left) <= i32::from((*netif).mtu) - i32::from(IP_HLEN);

            // Set new offset and MF flag.
            let mut tmp = IP_OFFMASK & ofo;
            if !last || mf_set {
                // The last fragment has MF set if the input frame had it.
                tmp |= IP_MF;
            }
            ptr::addr_of_mut!((*iphdr).offset).write_unaligned(tmp.to_be());
            ptr::addr_of_mut!((*iphdr).len).write_unaligned((fragsize + IP_HLEN).to_be());
            ptr::addr_of_mut!((*iphdr).chksum).write_unaligned(0);
            ptr::addr_of_mut!((*iphdr).chksum).write_unaligned(inet_chksum(iphdr.cast(), IP_HLEN));

            // No need for separate header pbuf - we allowed room for it in rambuf when
            // allocated.
            if let Some(output) = (*netif).output {
                output(netif, rambuf, dest);
            }

            // Unfortunately we can't reuse rambuf - the hardware may still be using the
            // buffer. Instead we free it (and the ensuing chain) and recreate it next
            // time round the loop. If we're lucky the hardware will have finished with
            // it by now and the buffer will be freed.
            pbuf_free(rambuf);
            left = left.wrapping_sub(fragsize);
            ofo = ofo.wrapping_add(nfb);
        }
    }
    ERR_OK
}

#[cfg(test)]
mod tests;
