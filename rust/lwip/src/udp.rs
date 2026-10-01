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

//! User Datagram Protocol module, from `src/core/udp.c`, as ESP-IDF configures it:
//! IPv4 and IPv6 with scopes, `SO_REUSE` with delivery of broadcasts and multicasts to
//! every matching PCB, multicast TX options, checksums generated but not checked on
//! input, no UDP-Lite, ports from `LWIP_RAND` (`esp_random`), and ESP-IDF's sending of
//! IPv4-mapped IPv6 destinations as IPv4 (`build.rs` refuses the rest).
//!
//! The code for the User Datagram Protocol UDP & UDPLite (RFC 3828). See also udp_raw.
//!
//! # Safety
//!
//! Like the C module, this one runs in the tcpip thread, which serializes every call.
//! PCBs are allocated from `MEMP_UDP_PCB` and linked on `udp_pcbs`; each PCB pointer a
//! function takes is live, as are pbufs, netifs, and addresses where the C code
//! dereferences them.

#![allow(non_upper_case_globals)]

use core::ffi::c_void;
use core::ptr;

use crate::config;
use crate::global::Global;
use crate::links::*;
use crate::types::*;

/// Last local UDP port.
static UDP_PORT: Global<u16> = Global::new(config::UDP_LOCAL_PORT_RANGE_START_ as u16);

/// The list of UDP PCBs.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub static udp_pcbs: Global<*mut UdpPcb> = Global::new(ptr::null_mut());

const START: u16 = config::UDP_LOCAL_PORT_RANGE_START_ as u16;
const END: u16 = config::UDP_LOCAL_PORT_RANGE_END_ as u16;

/// `UDP_ENSURE_LOCAL_PORT_RANGE(port)`.
fn ensure_local_port_range(port: u32) -> u16 {
    ((port as u16) & !START).wrapping_add(START)
}

/// `ICMP_DUR_PORT` and `ICMP6_DUR_PORT`.
const ICMP_DUR_PORT: IcmpDurType = 3;
const ICMP6_DUR_PORT: core::ffi::c_uint = 4;

/// `PBUF_FLAG_MCASTLOOP`.
const PBUF_FLAG_MCASTLOOP: u8 = 0x04;

/// Initialize this module.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn udp_init() {
    // SAFETY: the port's random source takes nothing.
    UDP_PORT.set(ensure_local_port_range(unsafe { esp_random() }));
}

/// Allocate a new local UDP port.
///
/// Returns a new (free) local UDP port number, or 0 if none is free.
fn udp_new_port() -> u16 {
    let mut n: u16 = 0;
    'again: loop {
        let port = UDP_PORT.get();
        UDP_PORT.set(port.wrapping_add(1));
        if port == END {
            UDP_PORT.set(START);
        }
        // Check all PCBs.
        let mut pcb = udp_pcbs.get();
        while !pcb.is_null() {
            // SAFETY: PCBs on the list are live.
            unsafe {
                if (*pcb).local_port == UDP_PORT.get() {
                    n = n.wrapping_add(1);
                    if n > END - START {
                        return 0;
                    }
                    continue 'again;
                }
                pcb = (*pcb).next;
            }
        }
        return UDP_PORT.get();
    }
}

/// `ip6_addr_has_scope(addr, IP6_UNKNOWN)`: a link-local address, or an interface- or
/// link-local multicast address.
fn ip6_has_scope(addr: &Ip6Addr) -> bool {
    let a0 = addr.addr[0];
    a0 & 0xffc0_0000_u32.to_be() == 0xfe80_0000_u32.to_be()
        || a0 & 0xff8f_0000_u32.to_be() == 0xff01_0000_u32.to_be()
        || a0 & 0xff8f_0000_u32.to_be() == 0xff02_0000_u32.to_be()
}

/// `ip6_addr_lacks_zone(addr, IP6_UNKNOWN)`: an address with a scope but no zone yet.
fn ip6_lacks_zone(addr: &Ip6Addr) -> bool {
    addr.zone == 0 && ip6_has_scope(addr)
}

/// `ip6_addr_select_zone(dest, src)`: give `dest` the zone of the netif `src` routes
/// through (`ip6_addr_assign_zone(dest, IP6_UNKNOWN, netif)`).
///
/// # Safety
///
/// `src` is valid.
unsafe fn ip6_addr_select_zone(dest: &mut Ip6Addr, src: *const Ip6Addr) {
    // SAFETY: valid addresses; a routed netif is live.
    unsafe {
        let selected_netif = ip6_route(src, dest);
        if !selected_netif.is_null() {
            dest.zone = if ip6_has_scope(dest) {
                (*selected_netif).index()
            } else {
                0
            };
        }
    }
}

/// Common code to see if the current input packet matches the pcb (current input packet
/// is accessed via ip(4/6)_current_* macros).
///
/// Returns true if the packet is for this pcb.
///
/// # Safety
///
/// `pcb` and `inp` are live, and `ip_data` describes the packet.
unsafe fn udp_input_local_match(pcb: *mut UdpPcb, inp: *mut Netif, broadcast: bool) -> bool {
    lwip_assert!("udp_input_local_match: invalid pcb", !pcb.is_null());
    lwip_assert!("udp_input_local_match: invalid netif", !inp.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        let ipd = ip_data();
        // Check if PCB is bound to specific netif.
        if (*pcb).netif_idx != NETIF_NO_INDEX
            && (*pcb).netif_idx != (*(*ipd).current_input_netif).index()
        {
            return false;
        }

        // Dual-stack: PCBs listening to any IP type also listen to any IP address.
        if (*pcb).local_ip.type_ == IPADDR_TYPE_ANY {
            return true;
        }

        // Only need to check PCB if incoming IP version matches PCB IP version.
        if (*pcb).local_ip.type_ == (*ipd).current_iphdr_dest.type_ {
            // Special case: IPv4 broadcast: all or broadcasts in my subnet. Note: broadcast
            // variable can only be 1 if it is an IPv4 broadcast.
            if broadcast {
                let local = (*pcb).local_ip.ip4().addr;
                let dest = (*ipd).current_iphdr_dest.ip4().addr;
                let mask = (*inp).ip4_netmask().addr;
                if local == IPADDR_ANY || dest == IPADDR_BROADCAST || local & mask == dest & mask {
                    return true;
                }
            } else if (*pcb).local_ip.is_any()
                || (*pcb).local_ip.eq_addr(&(*ipd).current_iphdr_dest)
            {
                // Handle IPv4 and IPv6: all or exact match.
                return true;
            }
        }
    }
    false
}

/// Process an incoming UDP datagram.
///
/// Given an incoming UDP datagram (as a chain of pbufs) this function finds a
/// corresponding UDP PCB and hands over the pbuf to the pcbs recv function. If no pcb is
/// found for the datagram, it is discarded (with an ICMP port unreachable unless it was a
/// broadcast or multicast).
///
/// # Safety
///
/// `p` is a live pbuf chain at the UDP header, `inp` the live netif it arrived on, and
/// `ip_data` describes the packet; the caller gives up `p`.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn udp_input(p: *mut Pbuf, inp: *mut Netif) {
    lwip_assert!("udp_input: invalid pbuf", !p.is_null());
    lwip_assert!("udp_input: invalid netif", !inp.is_null());

    // SAFETY: as the caller guarantees; PCBs on the list are live.
    unsafe {
        // Check minimum length (UDP header).
        if (*p).len < UDP_HLEN {
            // Drop short packets.
            pbuf_free(p);
            return;
        }

        let ipd = ip_data();
        let udphdr = (*p).payload.cast::<UdpHdr>().read_unaligned();

        // Is broadcast packet?
        let broadcast = !(*ipd).current_iphdr_dest.is_v6()
            && ip4_addr_isbroadcast_u32((*ipd).current_iphdr_dest.ip4().addr, (*ipd).current_netif)
                != 0;

        // Convert src and dest ports to host byte order.
        let src = u16::from_be(udphdr.src);
        let dest = u16::from_be(udphdr.dest);

        let mut pcb: *mut UdpPcb;
        let mut prev: *mut UdpPcb = ptr::null_mut();
        let mut uncon_pcb: *mut UdpPcb = ptr::null_mut();
        // Iterate through the UDP pcb list for a matching pcb. 'Perfect match' pcbs
        // (connected to the remote port and ip address) are preferred. If no perfect
        // match is found, the first unconnected pcb that matches the local address and
        // port gets the datagram.
        pcb = udp_pcbs.get();
        while !pcb.is_null() {
            // Compare PCB local addr+port to UDP destination addr+port.
            if (*pcb).local_port == dest && udp_input_local_match(pcb, inp, broadcast) {
                if (*pcb).flags & UDP_FLAGS_CONNECTED == 0 {
                    if uncon_pcb.is_null() {
                        // The first unconnected matching PCB.
                        uncon_pcb = pcb;
                    } else if broadcast && (*ipd).current_iphdr_dest.ip4().addr == IPADDR_BROADCAST
                    {
                        // Global broadcast address (only valid for IPv4; match was
                        // checked before).
                        let ours = (*inp).ip4_addr().addr;
                        if (*uncon_pcb).local_ip.type_ != IPADDR_TYPE_V4
                            || (*uncon_pcb).local_ip.ip4().addr != ours
                        {
                            // Uncon_pcb does not match the input netif, check this pcb.
                            if (*pcb).local_ip.type_ == IPADDR_TYPE_V4
                                && (*pcb).local_ip.ip4().addr == ours
                            {
                                // Better match.
                                uncon_pcb = pcb;
                            }
                        }
                    } else if !(*pcb).local_ip.is_any() {
                        // SO_REUSE: prefer specific IPs over catch-all.
                        uncon_pcb = pcb;
                    }
                }

                // Compare PCB remote addr+port to UDP source addr+port.
                if (*pcb).remote_port == src
                    && ((*pcb).remote_ip.is_any()
                        || (*pcb).remote_ip.eq_addr(&(*ipd).current_iphdr_src))
                {
                    // The first fully matching PCB.
                    if !prev.is_null() {
                        // Move the pcb to the front of udp_pcbs so that is found faster
                        // next time.
                        (*prev).next = (*pcb).next;
                        (*pcb).next = udp_pcbs.get();
                        udp_pcbs.set(pcb);
                    }
                    break;
                }
            }

            prev = pcb;
            pcb = (*pcb).next;
        }
        // No fully matching pcb found? Then look for an unconnected pcb.
        if pcb.is_null() {
            pcb = uncon_pcb;
        }

        // Check checksum if this is a match or if it was directed at us.
        let for_us = if !pcb.is_null() {
            true
        } else if !(*ipd).current_ip6_header.is_null() {
            netif_get_ip6_addr_match(inp, (*ipd).current_iphdr_dest.ip6()) >= 0
        } else {
            (*inp).ip4_addr().addr == (*ipd).current_iphdr_dest.ip4().addr
        };

        if !for_us {
            pbuf_free(p);
            return;
        }

        // CHECKSUM_CHECK_UDP is 0: the checksum is not checked.
        if pbuf_remove_header(p, UDP_HLEN.into()) != 0 {
            // Can we cope with this failing? Just assert for now.
            lwip_assert!("pbuf_remove_header failed", false);
            pbuf_free(p);
            return;
        }

        if !pcb.is_null() {
            if (*pcb).so_options & SOF_REUSEADDR != 0
                && (broadcast || (*ipd).current_iphdr_dest.is_multicast())
            {
                // Pass broadcast- or multicast packets to all multicast pcbs if
                // SOF_REUSEADDR is set on the first match.
                let mut mpcb = udp_pcbs.get();
                while !mpcb.is_null() {
                    if mpcb != pcb
                        // Compare PCB local addr+port to UDP destination addr+port.
                        && (*mpcb).local_port == dest
                        && udp_input_local_match(mpcb, inp, broadcast)
                    {
                        // Pass a copy of the packet to all local matches.
                        if let Some(recv) = (*mpcb).recv {
                            let q = pbuf_clone(PBUF_RAW, PBUF_POOL, p);
                            if !q.is_null() {
                                recv((*mpcb).recv_arg, mpcb, q, &(*ipd).current_iphdr_src, src);
                            }
                        }
                    }
                    mpcb = (*mpcb).next;
                }
            }
            // Callback.
            match (*pcb).recv {
                // Now the recv function is responsible for freeing p.
                Some(recv) => recv((*pcb).recv_arg, pcb, p, &(*ipd).current_iphdr_src, src),
                // No recv function registered? Then we have to free the pbuf!
                None => {
                    pbuf_free(p);
                }
            }
        } else {
            // No match was found, send ICMP destination port unreachable unless
            // destination address was broadcast/multicast.
            if !broadcast && !(*ipd).current_iphdr_dest.is_multicast() {
                lwip_sometimes!("udp_input: port unreachable sent", true);
                // Move payload pointer back to ip header.
                pbuf_header_force(p, ((*ipd).current_ip_header_tot_len + UDP_HLEN) as i16);
                if !(*ipd).current_ip6_header.is_null() {
                    icmp6_dest_unreach(p, ICMP6_DUR_PORT);
                } else {
                    icmp_dest_unreach(p, ICMP_DUR_PORT);
                }
            }
            pbuf_free(p);
        }
    }
}

/// Sends the pbuf p using UDP. The pbuf is not deallocated.
///
/// The datagram will be sent to the current remote_ip & remote_port stored in pcb. If the
/// pcb is not bound to a port, it will automatically be bound to a random port.
///
/// Returns `ERR_OK` if data was sent, another `err_t` otherwise.
///
/// # Safety
///
/// `pcb` is null or live, and `p` null or a live pbuf chain.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn udp_send(pcb: *mut UdpPcb, p: *mut Pbuf) -> ErrT {
    if pcb.is_null() || p.is_null() {
        return ERR_ARG;
    }
    // SAFETY: as the caller guarantees.
    unsafe {
        if (*pcb).remote_ip.type_ == IPADDR_TYPE_ANY {
            return ERR_VAL;
        }
        // Send to the packet using remote ip and port stored in the pcb.
        udp_sendto(pcb, p, &(*pcb).remote_ip, (*pcb).remote_port)
    }
}

/// Send data to a specified address using UDP.
///
/// dst_ip & dst_port are expected to be in the same byte order as in the pcb. If the PCB
/// already has a remote address association, it will be restored after the data is sent.
///
/// # Safety
///
/// `pcb` null or live, `p` null or a live pbuf chain, and `dst_ip` null or valid.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn udp_sendto(
    pcb: *mut UdpPcb,
    p: *mut Pbuf,
    dst_ip: *const IpAddr,
    dst_port: u16,
) -> ErrT {
    if pcb.is_null() || p.is_null() || dst_ip.is_null() {
        return ERR_ARG;
    }

    // SAFETY: as the caller guarantees; netifs found are live.
    unsafe {
        let dst = &*dst_ip;
        if !((*pcb).local_ip.type_ == IPADDR_TYPE_ANY || (*pcb).local_ip.type_ == dst.type_) {
            return ERR_VAL;
        }

        // ESP-IDF: an IPv4-mapped IPv6 destination is sent as IPv4.
        if dst.is_v6()
            && dst.ip6().addr[0] == 0
            && dst.ip6().addr[1] == 0
            && dst.ip6().addr[2] == 0x0000_ffff_u32.to_be()
        {
            let mut dest_ipv4 = IpAddr::v4(0);
            dest_ipv4.ip4_mut().addr = dst.ip6().addr[3];
            dest_ipv4.type_ = IPADDR_TYPE_V4;
            return udp_sendto(pcb, p, &dest_ipv4, dst_port);
        }

        let mut netif: *mut Netif;
        if (*pcb).netif_idx != NETIF_NO_INDEX {
            netif = netif_get_by_index((*pcb).netif_idx);
        } else {
            netif = ptr::null_mut();
            if dst.is_multicast() {
                // For IPv6, the interface to use for packets with a multicast destination
                // is specified using an interface index. The same approach may be used
                // for IPv4 as well, in which case it overrides the IPv4 multicast
                // override address below.
                if (*pcb).mcast_ifindex != NETIF_NO_INDEX {
                    netif = netif_get_by_index((*pcb).mcast_ifindex);
                } else if dst.type_ == IPADDR_TYPE_V4 {
                    // IPv4 does not use source-based routing by default, so we use an
                    // administratively selected interface for multicast by default.
                    // However, this can be overridden by setting an interface address in
                    // pcb->mcast_ip4 that is used for routing. If this routing lookup
                    // fails, we try regular routing as though no override was set.
                    let mcast = (*pcb).mcast_ip4.addr;
                    if mcast != IPADDR_ANY && mcast != (*ip_addr_broadcast()).ip4().addr {
                        netif = ip4_route_src((*pcb).local_ip.ip4(), &(*pcb).mcast_ip4);
                    }
                }
            }

            if netif.is_null() {
                // Find the outgoing network interface for this packet.
                netif = if dst.is_v6() {
                    ip6_route((*pcb).local_ip.ip6(), dst.ip6())
                } else {
                    ip4_route_src((*pcb).local_ip.ip4(), dst.ip4())
                };
            }
        }

        // No outgoing network interface could be found?
        if netif.is_null() {
            return ERR_RTE;
        }
        udp_sendto_if(pcb, p, dst_ip, dst_port, netif)
    }
}

/// Send data to a specified address using UDP. The netif used for sending can be
/// specified.
///
/// # Safety
///
/// `pcb` null or live, `p` null or a live pbuf chain, `dst_ip` null or valid, and
/// `netif` null or live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn udp_sendto_if(
    pcb: *mut UdpPcb,
    p: *mut Pbuf,
    dst_ip: *const IpAddr,
    dst_port: u16,
    netif: *mut Netif,
) -> ErrT {
    if pcb.is_null() || p.is_null() || dst_ip.is_null() || netif.is_null() {
        return ERR_ARG;
    }

    // SAFETY: as the caller guarantees.
    unsafe {
        let dst = &*dst_ip;
        let local = &(*pcb).local_ip;
        if !(local.type_ == IPADDR_TYPE_ANY || local.type_ == dst.type_) {
            return ERR_VAL;
        }

        let src_ip: *const IpAddr;
        // PCB local address is IP_ANY_ADDR or multicast?
        if dst.is_v6() {
            if local.ip6().addr == [0; 4]
                || local.ip6().addr[0] & 0xff00_0000_u32.to_be() == 0xff00_0000_u32.to_be()
            {
                src_ip = ip6_select_source_address(netif, dst.ip6());
                if src_ip.is_null() {
                    // No outgoing network interface could be found?
                    return ERR_RTE;
                }
            } else {
                // Use UDP PCB local IPv6 address as source address, if still valid.
                if netif_get_ip6_addr_match(netif, local.ip6()) < 0 {
                    // Address isn't valid anymore.
                    return ERR_RTE;
                }
                src_ip = local;
            }
        } else if local.ip4().addr == IPADDR_ANY
            || local.ip4().addr & 0xf000_0000_u32.to_be() == 0xe000_0000_u32.to_be()
        {
            // If the local_ip is any or multicast use the outgoing network interface IP
            // address as source address.
            src_ip = &(*netif).ip_addr;
        } else {
            // Check if UDP PCB local IP address is correct. This could be an old address
            // if netif->ip_addr has changed.
            if local.ip4().addr != (*netif).ip4_addr().addr {
                // Local_ip doesn't match, drop the packet.
                return ERR_RTE;
            }
            // Use UDP PCB local IP address as source address.
            src_ip = local;
        }
        udp_sendto_if_src(pcb, p, dst_ip, dst_port, netif, src_ip)
    }
}

/// Same as `udp_sendto_if`, but with source address.
///
/// # Safety
///
/// `pcb` null or live, `p` null or a live pbuf chain, `dst_ip` and `src_ip` null or
/// valid, and `netif` null or live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn udp_sendto_if_src(
    pcb: *mut UdpPcb,
    p: *mut Pbuf,
    dst_ip: *const IpAddr,
    dst_port: u16,
    netif: *mut Netif,
    src_ip: *const IpAddr,
) -> ErrT {
    if pcb.is_null() || p.is_null() || dst_ip.is_null() || src_ip.is_null() || netif.is_null() {
        return ERR_ARG;
    }

    // SAFETY: as the caller guarantees; the header is written into the room
    // pbuf_add_header made, or into a fresh pbuf.
    unsafe {
        let (dst, src) = (&*dst_ip, &*src_ip);
        let local_type = (*pcb).local_ip.type_;
        if !(local_type == IPADDR_TYPE_ANY || local_type == src.type_)
            || !(local_type == IPADDR_TYPE_ANY || local_type == dst.type_)
        {
            return ERR_VAL;
        }

        // If the PCB is not yet bound to a port, bind it here.
        if (*pcb).local_port == 0 {
            let err = udp_bind(pcb, &(*pcb).local_ip, (*pcb).local_port);
            if err != ERR_OK {
                return err;
            }
        }

        // Packet too large to add a UDP header without causing an overflow?
        if (*p).tot_len.wrapping_add(UDP_HLEN) < (*p).tot_len {
            return ERR_MEM;
        }
        let q: *mut Pbuf;
        // Not enough space to add an UDP header to first pbuf in given p chain?
        if pbuf_add_header(p, UDP_HLEN.into()) != 0 {
            // Allocate header in a separate new pbuf.
            q = pbuf_alloc(config::PBUF_IP_LAYER as PbufLayer, UDP_HLEN, PBUF_RAM);
            // New header pbuf could not be allocated?
            if q.is_null() {
                return ERR_MEM;
            }
            if (*p).tot_len != 0 {
                // Chain header q in front of given pbuf p (only if p contains data).
                pbuf_chain(q, p);
            }
            // First pbuf q points to header pbuf.
        } else {
            // Adding space for header within p succeeded; first pbuf q equals given pbuf.
            q = p;
        }
        lwip_assert!(
            "check that first pbuf can hold struct udp_hdr",
            (*q).len >= UDP_HLEN
        );
        // q now represents the packet to be sent.
        let udphdr = (*q).payload.cast::<UdpHdr>();
        ptr::addr_of_mut!((*udphdr).src).write_unaligned((*pcb).local_port.to_be());
        ptr::addr_of_mut!((*udphdr).dest).write_unaligned(dst_port.to_be());
        // In UDP, 0 checksum means 'no checksum'.
        ptr::addr_of_mut!((*udphdr).chksum).write_unaligned(0);

        if (*pcb).flags & UDP_FLAGS_MULTICAST_LOOP != 0 && dst.is_multicast() {
            (*q).flags |= PBUF_FLAG_MCASTLOOP;
        }

        // UDP.
        ptr::addr_of_mut!((*udphdr).len).write_unaligned((*q).tot_len.to_be());
        // Calculate checksum.
        if dst.is_v6() || (*pcb).flags & UDP_FLAGS_NOCHKSUM == 0 {
            let mut udpchksum = ip_chksum_pseudo(q, IP_PROTO_UDP, (*q).tot_len, src_ip, dst_ip);
            // Chksum zero must become 0xffff, as zero means 'no checksum'.
            if udpchksum == 0x0000 {
                udpchksum = 0xffff;
            }
            ptr::addr_of_mut!((*udphdr).chksum).write_unaligned(udpchksum);
        }
        let ip_proto = IP_PROTO_UDP;

        // Determine TTL to use.
        let ttl = if dst.is_multicast() {
            (*pcb).mcast_ttl
        } else {
            (*pcb).ttl
        };

        // Output to IP.
        let err = if dst.is_v6() {
            ip6_output_if_src(q, src.ip6(), dst.ip6(), ttl, (*pcb).tos, ip_proto, netif)
        } else {
            ip4_output_if_src(q, src.ip4(), dst.ip4(), ttl, (*pcb).tos, ip_proto, netif)
        };

        // Did we chain a separate header pbuf earlier?
        if q != p {
            // Free the header pbuf.
            pbuf_free(q);
        }
        err
    }
}

/// Bind an UDP PCB.
///
/// `ipaddr` is the local IP address to bind with (null or `IP_ANY_TYPE` for any local
/// address); `port` the local UDP port (0 to have one chosen).
///
/// Returns `ERR_USE` if the port is already in use, `ERR_OK` otherwise.
///
/// # Safety
///
/// `pcb` null or live, and `ipaddr` null or valid.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn udp_bind(pcb: *mut UdpPcb, ipaddr: *const IpAddr, port: u16) -> ErrT {
    let mut ipaddr = if ipaddr.is_null() {
        ip_addr_any()
    } else {
        ipaddr
    };
    let mut port = port;

    // LWIP_ERROR("udp_bind: invalid pcb", pcb != NULL, return ERR_ARG);
    if pcb.is_null() {
        return ERR_ARG;
    }

    // SAFETY: as the caller guarantees; PCBs on the list are live.
    unsafe {
        let mut rebind = false;
        // Check for double bind and rebind of the same pcb.
        let mut ipcb = udp_pcbs.get();
        while !ipcb.is_null() {
            // Is this UDP PCB already on active list?
            if pcb == ipcb {
                rebind = true;
                break;
            }
            ipcb = (*ipcb).next;
        }

        // If the given IP address should have a zone but doesn't, assign one now. This
        // is legacy support: scope-aware callers should always provide properly zoned
        // source addresses. Do the zone selection as early as possible so that
        // duplicate address checking works.
        let mut zoned_ipaddr = IpAddr::v4(0);
        if (*ipaddr).is_v6() && ip6_lacks_zone((*ipaddr).ip6()) {
            zoned_ipaddr.copy_from(&*ipaddr);
            let src = *zoned_ipaddr.ip6();
            ip6_addr_select_zone(zoned_ipaddr.ip6_mut(), &src);
            ipaddr = &zoned_ipaddr;
        }

        // No port specified?
        if port == 0 {
            port = udp_new_port();
            if port == 0 {
                // No more ports available in local range.
                return ERR_USE;
            }
        } else {
            let addr = &*ipaddr;
            let mut ipcb = udp_pcbs.get();
            while !ipcb.is_null() {
                if pcb != ipcb
                    // Omit if both pcbs have REUSEADDR set.
                    && ((*pcb).so_options & SOF_REUSEADDR == 0 || (*ipcb).so_options & SOF_REUSEADDR == 0)
                    // By default, we don't allow to bind to a port that any other udp PCB
                    // is already bound to, unless *all* PCBs with that port have the
                    // REUSEADDR flag set (checked for above).
                    && (*ipcb).local_port == port
                    && (((*ipcb).local_ip.type_ == addr.type_
                        // IP address matches or any IP used?
                        && ((*ipcb).local_ip.eq_addr(addr) || addr.is_any() || (*ipcb).local_ip.is_any()))
                        || (*ipcb).local_ip.type_ == IPADDR_TYPE_ANY
                        || addr.type_ == IPADDR_TYPE_ANY)
                {
                    // Other PCB already binds to this local IP and port.
                    return ERR_USE;
                }
                ipcb = (*ipcb).next;
            }
        }

        (*pcb).local_ip.copy_from(&*ipaddr);
        (*pcb).local_port = port;
        // PCB not yet on the list?
        if !rebind {
            // Place the PCB on the active list if not already there.
            (*pcb).next = udp_pcbs.get();
            udp_pcbs.set(pcb);
        }
    }
    ERR_OK
}

/// Bind an UDP PCB to a specific netif. After calling this function, all packets
/// received via this PCB are guaranteed to have come in via the specified netif, and all
/// outgoing packets will go out via the specified netif.
///
/// # Safety
///
/// `pcb` is live and `netif` null or live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn udp_bind_netif(pcb: *mut UdpPcb, netif: *const Netif) {
    // SAFETY: as the caller guarantees.
    unsafe {
        (*pcb).netif_idx = if netif.is_null() {
            NETIF_NO_INDEX
        } else {
            (*netif).index()
        };
    }
}

/// Sets the remote end of the pcb. This function does not generate any network traffic,
/// but only sets the remote address of the pcb.
///
/// # Safety
///
/// `pcb` null or live, and `ipaddr` null or valid.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn udp_connect(pcb: *mut UdpPcb, ipaddr: *const IpAddr, port: u16) -> ErrT {
    if pcb.is_null() || ipaddr.is_null() {
        return ERR_ARG;
    }

    // SAFETY: as the caller guarantees; PCBs on the list are live.
    unsafe {
        if (*pcb).local_port == 0 {
            let err = udp_bind(pcb, &(*pcb).local_ip, (*pcb).local_port);
            if err != ERR_OK {
                return err;
            }
        }

        (*pcb).remote_ip.copy_from(&*ipaddr);
        // If the given IP address should have a zone but doesn't, assign one now, using
        // the bound address to make a more informed decision when possible.
        if (*pcb).remote_ip.is_v6() && ip6_lacks_zone((*pcb).remote_ip.ip6()) {
            let src = *(*pcb).local_ip.ip6();
            ip6_addr_select_zone((*pcb).remote_ip.ip6_mut(), &src);
        }

        (*pcb).remote_port = port;
        (*pcb).flags |= UDP_FLAGS_CONNECTED;

        // Insert UDP PCB into the list of active UDP PCBs.
        let mut ipcb = udp_pcbs.get();
        while !ipcb.is_null() {
            if pcb == ipcb {
                // Already on the list, just return.
                return ERR_OK;
            }
            ipcb = (*ipcb).next;
        }
        // PCB not yet on the list, add PCB now.
        (*pcb).next = udp_pcbs.get();
        udp_pcbs.set(pcb);
    }
    ERR_OK
}

/// Remove the remote end of the pcb. This function does not generate any network
/// traffic, but only removes the remote address of the pcb.
///
/// # Safety
///
/// `pcb` is null or live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn udp_disconnect(pcb: *mut UdpPcb) {
    if pcb.is_null() {
        return;
    }
    // SAFETY: as the caller guarantees.
    unsafe {
        // Reset remote address association.
        if (*pcb).local_ip.type_ == IPADDR_TYPE_ANY {
            (*pcb).remote_ip.copy_from(&*ip_addr_any_type());
        } else if (*pcb).remote_ip.is_v6() {
            (*pcb).remote_ip.set_zero_ip6();
        } else {
            (*pcb).remote_ip.set_zero_ip4();
        }
        (*pcb).remote_port = 0;
        (*pcb).netif_idx = NETIF_NO_INDEX;
        // Mark PCB as unconnected.
        (*pcb).flags &= !UDP_FLAGS_CONNECTED;
    }
}

/// Set a receive callback for a UDP PCB. This callback will be called when receiving a
/// datagram for the pcb.
///
/// # Safety
///
/// `pcb` is null or live.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn udp_recv(pcb: *mut UdpPcb, recv: UdpRecvFn, recv_arg: *mut c_void) {
    if pcb.is_null() {
        return;
    }
    // SAFETY: as the caller guarantees.
    unsafe {
        // Remember recv() callback and user data.
        (*pcb).recv = recv;
        (*pcb).recv_arg = recv_arg;
    }
}

/// Removes and deallocates the pcb.
///
/// # Safety
///
/// `pcb` is null or a live PCB from `udp_new`, not used afterwards.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn udp_remove(pcb: *mut UdpPcb) {
    if pcb.is_null() {
        return;
    }
    // SAFETY: as the caller guarantees; PCBs on the list are live.
    unsafe {
        // PCB to be removed is first in list?
        if udp_pcbs.get() == pcb {
            // Make list start at 2nd pcb.
            udp_pcbs.set((*pcb).next);
        } else {
            // PCB not 1st in list.
            let mut pcb2 = udp_pcbs.get();
            while !pcb2.is_null() {
                // Find pcb in udp_pcbs list.
                if !(*pcb2).next.is_null() && (*pcb2).next == pcb {
                    // Remove pcb from list.
                    (*pcb2).next = (*pcb).next;
                    break;
                }
                pcb2 = (*pcb2).next;
            }
        }
        memp_free(config::MEMP_UDP_PCB, pcb.cast());
    }
}

/// Creates a new UDP pcb which can be used for UDP communication. The pcb is not active
/// until it has either been bound to a local address or connected to a remote address.
///
/// Returns the UDP PCB which was created, or null if the PCB data structure could not be
/// allocated.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn udp_new() -> *mut UdpPcb {
    // SAFETY: a MEMP_UDP_PCB element holds a struct udp_pcb, zeroed before use.
    unsafe {
        let pcb = memp_malloc(config::MEMP_UDP_PCB).cast::<UdpPcb>();
        // Could allocate UDP PCB?
        if !pcb.is_null() {
            // UDP Lite: by initializing to all zeroes, chksum_len is set to 0 which means
            // checksum is generated over the whole datagram per default (recommended as
            // default by RFC 3828).
            // Initialize PCB to all zeroes.
            ptr::write_bytes(pcb, 0, 1);
            (*pcb).ttl = config::UDP_TTL as u8;
            (*pcb).mcast_ttl = config::UDP_TTL as u8;
        }
        pcb
    }
}

/// Create a UDP PCB for specific IP type.
///
/// `type_` is one of `IPADDR_TYPE_*`.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn udp_new_ip_type(type_: u8) -> *mut UdpPcb {
    let pcb = udp_new();
    if !pcb.is_null() {
        // SAFETY: a fresh PCB.
        unsafe {
            (*pcb).local_ip.type_ = type_;
            (*pcb).remote_ip.type_ = type_;
        }
    }
    pcb
}

/// This function is called from netif.c when address is changed.
///
/// # Safety
///
/// `old_addr` and `new_addr` are null or valid.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn udp_netif_ip_addr_changed(
    old_addr: *const IpAddr,
    new_addr: *const IpAddr,
) {
    // SAFETY: as the caller guarantees; PCBs on the list are live.
    unsafe {
        let old_any = old_addr.as_ref().is_none_or(IpAddr::is_any);
        let new_any = new_addr.as_ref().is_none_or(IpAddr::is_any);
        if !old_any && !new_any {
            let mut upcb = udp_pcbs.get();
            while !upcb.is_null() {
                // PCB bound to current local interface address?
                if (*upcb).local_ip.eq_addr(&*old_addr) {
                    // The PCB is bound to the old ipaddr and is set to bound to the new
                    // one instead.
                    (*upcb).local_ip.copy_from(&*new_addr);
                }
                upcb = (*upcb).next;
            }
        }
    }
}

#[cfg(test)]
mod tests;
