// Copyright (c) 2001-2003 Swedish Institute of Computer Science.
// Copyright (c) 2003-2004 Leon Woestenberg <leon.woestenberg@axon.tv>
// Copyright (c) 2003-2004 Axon Digital Design B.V., The Netherlands.
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
// Translated to Rust for mss-esp-lwip by Mist Tecnologia LTDA.

//! Ethernet common functions, from `src/netif/ethernet.c`, as ESP-IDF configures them:
//! IPv4 with ARP and IPv6, no VLAN or link-layer hooks, `ETH_PAD_SIZE` 0 (`build.rs`
//! refuses the rest).

#![allow(non_upper_case_globals)]

use core::ptr;

use crate::links::{
    etharp_input, ip4_input, ip6_input, pbuf_add_header, pbuf_free, pbuf_remove_header,
};
use crate::types::*;

/// The broadcast Ethernet address.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub static ethbroadcast: EthAddr = EthAddr {
    addr: [0xff; ETH_HWADDR_LEN],
};

/// The all-zero Ethernet address.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub static ethzero: EthAddr = EthAddr {
    addr: [0; ETH_HWADDR_LEN],
};

/// Receives an Ethernet frame from the network interface and passes it to the protocol
/// its type names: IPv4 and ARP when the netif does ARP, and IPv6. Frames too short to
/// hold a header, and frames of any other type, are dropped.
///
/// The pbuf is always consumed: passed on or freed. Returns `ERR_OK`.
///
/// # Safety
///
/// `p` is a live pbuf chain whose first pbuf's payload is at least `len` bytes, and
/// `netif` is a live netif; the caller gives up `p`.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn ethernet_input(p: *mut Pbuf, netif: *mut Netif) -> ErrT {
    let next_hdr_offset = SIZEOF_ETH_HDR;

    // SAFETY: `p` and `netif` are live, per the caller; the header is read only once the
    // first pbuf is known to hold more than it.
    unsafe {
        if (*p).len <= SIZEOF_ETH_HDR {
            // A packet with only an ethernet header (or less) is not valid for us.
            pbuf_free(p);
            return ERR_OK;
        }

        // Points to packet payload, which starts with an Ethernet header.
        let ethhdr = (*p).payload.cast::<EthHdr>().read_unaligned();
        let type_ = ethhdr.type_;

        if (*p).if_idx == NETIF_NO_INDEX {
            (*p).if_idx = (*netif).index();
        }

        let dest = ethhdr.dest.addr;
        if dest[0] & 1 != 0 {
            // This might be a multicast or broadcast packet.
            if dest[0] == 0x01 {
                if dest[1] == 0x00 && dest[2] == 0x5e {
                    // Mark the pbuf as link-layer multicast.
                    (*p).flags |= PBUF_FLAG_LLMCAST;
                }
            } else if dest[0] == 0x33 && dest[1] == 0x33 {
                // Mark the pbuf as link-layer multicast.
                (*p).flags |= PBUF_FLAG_LLMCAST;
            } else if ethhdr.dest == ethbroadcast {
                // Mark the pbuf as link-layer broadcast.
                (*p).flags |= PBUF_FLAG_LLBCAST;
            }
        }

        match u16::from_be(type_) {
            // IP packet?
            ETHTYPE_IP => {
                if (*netif).flags & NETIF_FLAG_ETHARP == 0 {
                    pbuf_free(p);
                    return ERR_OK;
                }
                // Skip Ethernet header (min. size checked above).
                if pbuf_remove_header(p, next_hdr_offset.into()) != 0 {
                    pbuf_free(p);
                    return ERR_OK;
                }
                // Pass to IP layer.
                ip4_input(p, netif);
            }
            ETHTYPE_ARP => {
                if (*netif).flags & NETIF_FLAG_ETHARP == 0 {
                    pbuf_free(p);
                    return ERR_OK;
                }
                // Skip Ethernet header (min. size checked above).
                if pbuf_remove_header(p, next_hdr_offset.into()) != 0 {
                    pbuf_free(p);
                    return ERR_OK;
                }
                // Pass p to ARP module.
                etharp_input(p, netif);
            }
            ETHTYPE_IPV6 => {
                // Skip Ethernet header.
                if (*p).len < next_hdr_offset || pbuf_remove_header(p, next_hdr_offset.into()) != 0
                {
                    pbuf_free(p);
                    return ERR_OK;
                }
                // Pass to IPv6 layer.
                ip6_input(p, netif);
            }
            _ => {
                pbuf_free(p);
                return ERR_OK;
            }
        }
    }

    // This means the pbuf is freed or consumed, so the caller doesn't have to free it
    // again.
    ERR_OK
}

/// Sends an Ethernet frame on the network interface: prepends the Ethernet header, with
/// `src`, `dst`, and `eth_type` (in host byte order), and passes the pbuf to the netif's
/// `linkoutput`.
///
/// Returns `ERR_OK` if the packet was sent, any other `err_t` on failure (`ERR_BUF` if
/// there is no room for the header).
///
/// # Safety
///
/// `netif` is a live netif with a `linkoutput`, `p` a live pbuf chain, and `src` and `dst`
/// valid Ethernet addresses.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn ethernet_output(
    netif: *mut Netif,
    p: *mut Pbuf,
    src: *const EthAddr,
    dst: *const EthAddr,
    eth_type: u16,
) -> ErrT {
    let eth_type_be = eth_type.to_be();

    // SAFETY: live netif and pbuf, per the caller; the header is written only once
    // `pbuf_add_header` has made room for it at the payload.
    unsafe {
        if pbuf_add_header(p, SIZEOF_ETH_HDR.into()) != 0 {
            return ERR_BUF;
        }

        let ethhdr = (*p).payload.cast::<EthHdr>();
        ptr::addr_of_mut!((*ethhdr).type_).write_unaligned(eth_type_be);
        ptr::addr_of_mut!((*ethhdr).dest).write_unaligned(dst.read_unaligned());
        ptr::addr_of_mut!((*ethhdr).src).write_unaligned(src.read_unaligned());

        lwip_assert!(
            "netif->hwaddr_len must be 6 for ethernet_output!",
            usize::from((*netif).hwaddr_len) == ETH_HWADDR_LEN
        );

        // Send the packet.
        match (*netif).linkoutput {
            Some(linkoutput) => linkoutput(netif, p),
            None => ERR_IF,
        }
    }
}

#[cfg(test)]
mod tests;
