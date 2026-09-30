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

//! This is the IPv4 layer implementation for incoming and outgoing IP traffic, from
//! `src/core/ipv4/ip4.c`, as ESP-IDF configures it: no forwarding or reassembly, IP
//! options accepted and sent, link-layer-addressed DHCP accepted, the header checksum
//! generated inline and not checked on input, loopback, a default multicast netif, and
//! ESP-IDF's source-routing hook (`build.rs` refuses the rest).
//!
//! # Safety
//!
//! Like the C module, this one runs in the tcpip thread, which serializes every call.
//! Pbuf, netif, and address pointers are as each function's C contract has them: live
//! where the C code dereferences them. IP headers are read and written unaligned, as the
//! packed C struct is.

use core::ffi::c_void;
use core::ptr;

use crate::global::Global;
use crate::links::*;
use crate::types::*;

/// The IP header ID of the next outgoing IP packet.
static IP_ID: Global<u16> = Global::new(0);

/// The default netif used for multicast.
static IP4_DEFAULT_MULTICAST_NETIF: Global<*mut Netif> = Global::new(ptr::null_mut());

/// `LWIP_IANA_PORT_DHCP_CLIENT`.
const LWIP_IANA_PORT_DHCP_CLIENT: u16 = 68;

/// `PBUF_FLAG_MCASTLOOP`: this pbuf should be looped back when sent to a multicast group.
const PBUF_FLAG_MCASTLOOP: u8 = 0x04;

/// `ip4_addr_ismulticast()`: 224.0.0.0/4.
fn ismulticast(addr: u32) -> bool {
    addr & 0xf000_0000_u32.to_be() == 0xe000_0000_u32.to_be()
}

/// `ip4_addr_isloopback()`: 127.0.0.0/8.
fn isloopback(addr: u32) -> bool {
    addr & 0xff00_0000_u32.to_be() == (127_u32 << 24).to_be()
}

/// `IPH_HL_BYTES()`: the header length in bytes.
fn hl_bytes(v_hl: u8) -> u16 {
    u16::from((v_hl & 0x0f) * 4)
}

/// `SWAP_BYTES_IN_WORD`-style `PP_NTOHS` of a value built in an `int`.
fn swap16(x: u32) -> u32 {
    ((x & 0x00ff) << 8) | ((x & 0xff00) >> 8)
}

/// The IPv4 header at `p`'s payload.
///
/// # Safety
///
/// `p` is live and its payload holds an IPv4 header.
unsafe fn header(p: *const Pbuf) -> *mut IpHdr {
    // SAFETY: as the caller guarantees.
    unsafe { (*p).payload.cast() }
}

/// Is the netif up, its link up, and does it have an address?
///
/// # Safety
///
/// `netif` is live.
unsafe fn is_routable(netif: *const Netif) -> bool {
    // SAFETY: as the caller guarantees.
    unsafe {
        (*netif).flags & NETIF_FLAG_UP != 0
            && (*netif).flags & NETIF_FLAG_LINK_UP != 0
            && (*netif).ip4_addr().addr != IPADDR_ANY
    }
}

/// Set a default netif for IPv4 multicast.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn ip4_set_default_multicast_netif(default_multicast_netif: *mut Netif) {
    IP4_DEFAULT_MULTICAST_NETIF.set(default_multicast_netif);
}

/// Source based IPv4 routing must be fully implemented in LWIP_HOOK_IP4_ROUTE_SRC(). This
/// function only provides the parameters.
///
/// # Safety
///
/// `src` is null or valid, and `dest` valid.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ip4_route_src(src: *const Ip4Addr, dest: *const Ip4Addr) -> *mut Netif {
    // SAFETY: forwarded from the caller.
    unsafe {
        if !src.is_null() {
            // When src==NULL, the hook is called from ip4_route(dest).
            let netif = ip4_route_src_hook(src, dest);
            if !netif.is_null() {
                return netif;
            }
        }
        ip4_route(dest)
    }
}

/// Finds the appropriate network interface for a given IP address. It searches the list
/// of network interfaces linearly. A match is found if the masked IP address of the
/// network interface equals the masked IP address given to the function.
///
/// Returns the netif on which to send to reach dest, or null if none.
///
/// # Safety
///
/// `dest` is valid.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ip4_route(dest: *const Ip4Addr) -> *mut Netif {
    // SAFETY: as the caller guarantees; netifs on the list are live.
    unsafe {
        let dest_addr = (*dest).addr;

        // Use administratively selected interface for multicast by default.
        let multicast_netif = IP4_DEFAULT_MULTICAST_NETIF.get();
        if ismulticast(dest_addr) && !multicast_netif.is_null() {
            return multicast_netif;
        }

        // Iterate through netifs.
        let mut netif = netif_list();
        while !netif.is_null() {
            // Is the netif up, does it have a link and a valid address?
            if is_routable(netif) {
                // Network mask matches?
                let mask = (*netif).ip4_netmask().addr;
                if dest_addr & mask == (*netif).ip4_addr().addr & mask {
                    // Return netif on which to forward IP packet.
                    return netif;
                }
                // Gateway matches on a non broadcast interface? (i.e. peer in a
                // point to point interface)
                if (*netif).flags & NETIF_FLAG_BROADCAST == 0 && dest_addr == (*netif).ip4_gw().addr
                {
                    // Return netif on which to forward IP packet.
                    return netif;
                }
            }
            netif = (*netif).next.map_or(ptr::null_mut(), ptr::NonNull::as_ptr);
        }

        let netif = ip4_route_src_hook(ptr::null(), dest);
        if !netif.is_null() {
            return netif;
        }

        let default = netif_default();
        if default.is_null() || !is_routable(default) || isloopback(dest_addr) {
            // No matching netif found and default netif is not usable. If this is not
            // good enough for you, use LWIP_HOOK_IP4_ROUTE().
            return ptr::null_mut();
        }
        default
    }
}

/// Determine whether an IP address is in a subnet (or a broadcast) of a network
/// interface the packet was sent to.
///
/// # Safety
///
/// `netif` is live.
unsafe fn ip4_input_accept(netif: *mut Netif) -> bool {
    // SAFETY: as the caller guarantees; ip_data is the packet being delivered.
    unsafe {
        // Interface is up and configured?
        if (*netif).flags & NETIF_FLAG_UP != 0 && (*netif).ip4_addr().addr != IPADDR_ANY {
            let dest = (*ip_data()).current_iphdr_dest.ip4().addr;
            // Unicast to this interface address? Or broadcast on this interface?
            if dest == (*netif).ip4_addr().addr || ip4_addr_isbroadcast_u32(dest, netif) != 0 {
                // Accept on this netif.
                return true;
            }
        }
    }
    false
}

/// This function is called by the network interface device driver when an IP packet is
/// received. The function does the basic checks of the IP header such as packet size
/// being at least larger than the header size etc. If the packet was not destined for
/// us, the packet is dropped (no forwarding in this configuration).
///
/// Finally, the packet is sent to the upper layer protocol input function.
///
/// Returns `ERR_OK` if the packet was processed or dropped (the pbuf is consumed either
/// way).
///
/// # Safety
///
/// `p` is a live pbuf chain holding an IPv4 packet and `inp` a live netif; the caller
/// gives up `p`.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ip4_input(p: *mut Pbuf, inp: *mut Netif) -> ErrT {
    let mut check_ip_src = true;

    // SAFETY: as the caller guarantees; the header is read unaligned from the payload,
    // which ip4_input checks holds it before using its length.
    unsafe {
        // Identify the IP header.
        let iphdr = header(p);
        let hdr = || iphdr.read_unaligned();
        if hdr().v_hl >> 4 != 4 {
            pbuf_free(p);
            return ERR_OK;
        }

        // Obtain IP header length in bytes.
        let iphdr_hlen = hl_bytes(hdr().v_hl);
        // Obtain ip length in bytes.
        let iphdr_len = u16::from_be(hdr().len);

        // Trim pbuf. This is especially required for packets < 60 bytes.
        if iphdr_len < (*p).tot_len {
            pbuf_realloc(p, iphdr_len);
        }

        // Header length exceeds first pbuf length, or ip length exceeds total pbuf
        // length?
        if iphdr_hlen > (*p).len || iphdr_len > (*p).tot_len || iphdr_hlen < IP_HLEN {
            // Free (drop) packet pbufs.
            pbuf_free(p);
            return ERR_OK;
        }

        // Copy IP addresses to aligned ip_addr_t.
        let ipd = ip_data();
        (*ipd).current_iphdr_dest.copy_from_ip4(hdr().dest);
        (*ipd).current_iphdr_src.copy_from_ip4(hdr().src);
        let dest = (*ipd).current_iphdr_dest.ip4().addr;
        let src = (*ipd).current_iphdr_src.ip4().addr;

        let mut netif: *mut Netif;
        // Match packet against an interface, i.e. is this packet for us?
        if ismulticast(dest) {
            if (*inp).flags & NETIF_FLAG_IGMP != 0
                && !igmp_lookfor_group(inp, (*ipd).current_iphdr_dest.ip4()).is_null()
            {
                // IGMP snooping switches need 0.0.0.0 to be allowed as source address
                // (RFC 4541).
                let allsystems = u32::from_be_bytes([224, 0, 0, 1]).to_be();
                if dest == allsystems && src == IPADDR_ANY {
                    check_ip_src = false;
                }
                netif = inp;
            } else {
                netif = ptr::null_mut();
            }
        } else {
            // Start trying with inp. if that's not acceptable, start walking the list of
            // configured netifs.
            if ip4_input_accept(inp) {
                netif = inp;
            } else {
                netif = ptr::null_mut();
                // Packets sent to the loopback address must not be accepted on an
                // interface that does not have the loopback address assigned to it,
                // unless a non-loopback interface is used for loopback traffic.
                if !isloopback(dest) {
                    netif = netif_list();
                    while !netif.is_null() {
                        if netif != inp && ip4_input_accept(netif) {
                            break;
                        }
                        netif = (*netif).next.map_or(ptr::null_mut(), ptr::NonNull::as_ptr);
                    }
                }
            }
        }

        // Pass DHCP messages regardless of destination address. DHCP traffic is addressed
        // using link layer addressing (such as Ethernet MAC) so we must not filter on IP.
        // According to RFC 1542 section 3.1.1, referred by RFC 2131).
        //
        // If you want to accept private broadcast communication while a netif is down,
        // define LWIP_IP_ACCEPT_UDP_PORT(dst_port).
        if netif.is_null() {
            // Remote port is DHCP server?
            if hdr().proto == IP_PROTO_UDP {
                let udp_dest = iphdr
                    .cast::<u8>()
                    .add(usize::from(iphdr_hlen) + UDP_HDR_DEST)
                    .cast::<u16>()
                    .read_unaligned();
                if udp_dest == LWIP_IANA_PORT_DHCP_CLIENT.to_be() {
                    netif = inp;
                    check_ip_src = false;
                }
            }
        }

        // Broadcast or multicast packet source address? Compliant with RFC 1122: 3.2.1.3
        if check_ip_src
            && src != IPADDR_ANY
            && (ip4_addr_isbroadcast_u32(src, inp) != 0 || ismulticast(src))
        {
            // Packet source is not valid; free (drop) packet pbufs.
            pbuf_free(p);
            return ERR_OK;
        }

        // Packet not for us?
        if netif.is_null() {
            // Packet not for us, route or discard.
            pbuf_free(p);
            return ERR_OK;
        }
        // Packet consists of multiple fragments?
        if hdr().offset & (IP_OFFMASK | IP_MF).to_be() != 0 {
            // IP_REASSEMBLY == 0: no packet fragment reassembly code present.
            pbuf_free(p);
            return ERR_OK;
        }

        // Send to upper layers.
        (*ipd).current_netif = netif;
        (*ipd).current_input_netif = inp;
        (*ipd).current_ip4_header = iphdr;
        (*ipd).current_ip_header_tot_len = hl_bytes(hdr().v_hl);

        // Raw input did not eat the packet?
        let raw_status = raw_input(p, inp);
        if raw_status != RAW_INPUT_EATEN {
            pbuf_remove_header(p, usize::from(iphdr_hlen)); // Move to payload, no check necessary.

            match hdr().proto {
                IP_PROTO_UDP => udp_input(p, inp),
                IP_PROTO_TCP => tcp_input(p, inp),
                IP_PROTO_ICMP => icmp_input(p, inp),
                IP_PROTO_IGMP => igmp_input(p, inp, (*ipd).current_iphdr_dest.ip4()),
                _ => {
                    if raw_status != RAW_INPUT_DELIVERED {
                        // Send ICMP destination protocol unreachable unless is was a
                        // broadcast.
                        let dest = (*ipd).current_iphdr_dest.ip4().addr;
                        if ip4_addr_isbroadcast_u32(dest, netif) == 0 && !ismulticast(dest) {
                            pbuf_header_force(p, iphdr_hlen as i16); // Move to ip header, no check necessary.
                            icmp_dest_unreach(p, ICMP_DUR_PROTO);
                        }
                    }
                    pbuf_free(p);
                }
            }
        }

        // @todo: this is not really necessary...
        (*ipd).current_netif = ptr::null_mut();
        (*ipd).current_input_netif = ptr::null_mut();
        (*ipd).current_ip4_header = ptr::null();
        (*ipd).current_ip_header_tot_len = 0;
        (*ipd).current_iphdr_src.ip4_mut().addr = IPADDR_ANY;
        (*ipd).current_iphdr_dest.ip4_mut().addr = IPADDR_ANY;
    }
    ERR_OK
}

/// Sends an IP packet on a network interface. This function constructs the IP header and
/// calculates the IP header checksum. If the source IP address is NULL, the IP address
/// of the outgoing network interface is filled in as source address. If the destination
/// IP address is LWIP_IP_HDRINCL, p is assumed to already include an IP header and
/// p->payload points to it instead of the data.
///
/// # Safety
///
/// See `ip4_output_if_opt_src`.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ip4_output_if(
    p: *mut Pbuf,
    src: *const Ip4Addr,
    dest: *const Ip4Addr,
    ttl: u8,
    tos: u8,
    proto: u8,
    netif: *mut Netif,
) -> ErrT {
    // SAFETY: forwarded from the caller.
    unsafe { ip4_output_if_opt(p, src, dest, ttl, tos, proto, netif, ptr::null_mut(), 0) }
}

/// Same as `ip4_output_if()` but with the possibility to include IP options.
///
/// # Safety
///
/// See `ip4_output_if_opt_src`.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ip4_output_if_opt(
    p: *mut Pbuf,
    src: *const Ip4Addr,
    dest: *const Ip4Addr,
    ttl: u8,
    tos: u8,
    proto: u8,
    netif: *mut Netif,
    ip_options: *mut c_void,
    optlen: u16,
) -> ErrT {
    let mut src_used = src;
    // SAFETY: forwarded from the caller.
    unsafe {
        if !dest.is_null() && (src.is_null() || (*src).addr == IPADDR_ANY) {
            src_used = (*netif).ip4_addr();
        }
        ip4_output_if_opt_src(
            p, src_used, dest, ttl, tos, proto, netif, ip_options, optlen,
        )
    }
}

/// Same as `ip4_output_if()` but 'src' address is not replaced by netif address when it
/// is 'any'.
///
/// # Safety
///
/// See `ip4_output_if_opt_src`.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ip4_output_if_src(
    p: *mut Pbuf,
    src: *const Ip4Addr,
    dest: *const Ip4Addr,
    ttl: u8,
    tos: u8,
    proto: u8,
    netif: *mut Netif,
) -> ErrT {
    // SAFETY: forwarded from the caller.
    unsafe { ip4_output_if_opt_src(p, src, dest, ttl, tos, proto, netif, ptr::null_mut(), 0) }
}

/// Same as `ip4_output_if_opt()` but 'src' address is not replaced by netif address when
/// it is 'any'.
///
/// # Safety
///
/// `p` is a live pbuf chain with a single reference, `netif` a live netif with an
/// `output`, `src` null or valid, `dest` null (the header is included) or valid, and
/// `ip_options` readable for `optlen` bytes.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn ip4_output_if_opt_src(
    p: *mut Pbuf,
    src: *const Ip4Addr,
    dest: *const Ip4Addr,
    ttl: u8,
    tos: u8,
    proto: u8,
    netif: *mut Netif,
    ip_options: *mut c_void,
    optlen: u16,
) -> ErrT {
    let mut chk_sum: u32 = 0;
    let dest_addr;
    let mut dest = dest;

    // SAFETY: as the caller guarantees; the header is written unaligned into the room
    // pbuf_add_header made at the payload.
    unsafe {
        lwip_assert!("p->ref == 1", (*p).ref_ == 1);

        // Should the IP header be generated or is it already included in p?
        if !dest.is_null() {
            let mut ip_hlen = IP_HLEN;
            if optlen != 0 {
                if optlen > IP_HLEN_MAX - IP_HLEN {
                    // Optlen too long.
                    return ERR_VAL;
                }
                // Round up to a multiple of 4.
                let optlen_aligned = (optlen + 3) & !3;
                ip_hlen += optlen_aligned;
                // First write in the IP options.
                if pbuf_add_header(p, optlen_aligned.into()) != 0 {
                    return ERR_BUF;
                }
                ptr::copy(
                    ip_options.cast::<u8>(),
                    (*p).payload.cast::<u8>(),
                    optlen.into(),
                );
                if optlen < optlen_aligned {
                    // Zero the remaining bytes.
                    ptr::write_bytes(
                        (*p).payload.cast::<u8>().add(optlen.into()),
                        0,
                        usize::from(optlen_aligned - optlen),
                    );
                }
                for i in 0..usize::from(optlen_aligned / 2) {
                    chk_sum += u32::from((*p).payload.cast::<u16>().add(i).read_unaligned());
                }
            }
            // Generate IP header.
            if pbuf_add_header(p, IP_HLEN.into()) != 0 {
                return ERR_BUF;
            }

            let iphdr = header(p);
            lwip_assert!(
                "check that first pbuf can hold struct ip_hdr",
                usize::from((*p).len) >= core::mem::size_of::<IpHdr>()
            );

            ptr::addr_of_mut!((*iphdr).ttl).write(ttl);
            ptr::addr_of_mut!((*iphdr).proto).write(proto);
            chk_sum += swap16(u32::from(proto) | (u32::from(ttl) << 8));

            // dest cannot be NULL here.
            let dest_value = (*dest).addr;
            ptr::addr_of_mut!((*iphdr).dest).write_unaligned(dest_value);
            chk_sum += dest_value & 0xFFFF;
            chk_sum += dest_value >> 16;

            let v_hl = (4 << 4) | (ip_hlen / 4) as u8;
            ptr::addr_of_mut!((*iphdr).v_hl).write(v_hl);
            ptr::addr_of_mut!((*iphdr).tos).write(tos);
            chk_sum += swap16(u32::from(tos) | (u32::from(v_hl) << 8));
            let len = (*p).tot_len.to_be();
            ptr::addr_of_mut!((*iphdr).len).write_unaligned(len);
            chk_sum += u32::from(len);
            ptr::addr_of_mut!((*iphdr).offset).write_unaligned(0);
            let id = IP_ID.get().to_be();
            ptr::addr_of_mut!((*iphdr).id).write_unaligned(id);
            chk_sum += u32::from(id);
            IP_ID.set(IP_ID.get().wrapping_add(1));

            let src_value = if src.is_null() {
                IPADDR_ANY
            } else {
                (*src).addr
            };
            ptr::addr_of_mut!((*iphdr).src).write_unaligned(src_value);

            chk_sum += src_value & 0xFFFF;
            chk_sum += src_value >> 16;
            chk_sum = (chk_sum >> 16) + (chk_sum & 0xFFFF);
            chk_sum = (chk_sum >> 16).wrapping_add(chk_sum);
            chk_sum = !chk_sum;
            ptr::addr_of_mut!((*iphdr).chksum).write_unaligned(chk_sum as u16);
        } else {
            // IP header already included in p.
            if (*p).len < IP_HLEN {
                return ERR_BUF;
            }
            let iphdr = header(p);
            dest_addr = Ip4Addr {
                addr: ptr::addr_of!((*iphdr).dest).read_unaligned(),
            };
            dest = &dest_addr;
        }

        if (*dest).addr == (*netif).ip4_addr().addr {
            // Packet to self, enqueue it for loopback.
            return netif_loop_output(netif, p);
        }
        if (*p).flags & PBUF_FLAG_MCASTLOOP != 0 {
            netif_loop_output(netif, p);
        }
        // Don't fragment if interface has mtu set to 0 [loopif].
        if (*netif).mtu != 0 && (*p).tot_len > (*netif).mtu {
            return ip4_frag(p, netif, dest);
        }

        match (*netif).output {
            Some(output) => output(netif, p, dest),
            None => ERR_IF,
        }
    }
}

/// Simple interface to ip_output_if. It finds the outgoing network interface and calls
/// upon ip_output_if to do the actual work.
///
/// Returns `ERR_RTE` if no route is found, see `ip4_output_if()` for more return values.
///
/// # Safety
///
/// See `ip4_output_if_opt_src`; `dest` is valid.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn ip4_output(
    p: *mut Pbuf,
    src: *const Ip4Addr,
    dest: *const Ip4Addr,
    ttl: u8,
    tos: u8,
    proto: u8,
) -> ErrT {
    // SAFETY: forwarded from the caller.
    unsafe {
        lwip_assert!("p->ref == 1", (*p).ref_ == 1);

        let netif = ip4_route_src(src, dest);
        if netif.is_null() {
            return ERR_RTE;
        }
        ip4_output_if(p, src, dest, ttl, tos, proto, netif)
    }
}

#[cfg(test)]
pub(crate) mod tests;
