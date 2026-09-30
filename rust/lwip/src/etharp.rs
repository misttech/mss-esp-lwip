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

//! Address Resolution Protocol module for IP over Ethernet, from `src/core/ipv4/etharp.c`,
//! as ESP-IDF configures it: packets queued while an address resolves, static entries,
//! entries matched by netif, address conflict detection, and no VLANs or address hints
//! (`build.rs` refuses the rest).
//!
//! Functionally, ARP is divided into two parts. The first maps IP addresses to physical
//! addresses when sending a packet, and the second part answers requests from other
//! machines for our physical address.
//!
//! This implementation complies with RFC 826 (Ethernet ARP). It supports Gratuitous ARP
//! from RFC3220 (IP Mobility Support for IPv4) section 4.6 and RFC 5227 (IPv4 Address
//! Conflict Detection).
//!
//! # Safety
//!
//! Like the C module, this one keeps its table in a static and runs only in the tcpip
//! thread, which serializes every call. Netif, pbuf, and address pointers are as each
//! function's C contract has them: live where the C code dereferences them.

use core::ffi::c_int;
use core::ptr;

use crate::config;
use crate::global::Global;
use crate::links::{
    acd_arp_reply, ethbroadcast, ethernet_output, ethzero, ip4_addr_isbroadcast_u32, ip4_route,
    memp_free, memp_malloc, pbuf_alloc, pbuf_clone, pbuf_free, pbuf_ref,
};
use crate::types::*;

/// Re-request a used ARP entry 1 minute before it would expire to prevent breaking a
/// steadily used connection because the ARP entry timed out.
const ARP_AGE_REREQUEST_USED_UNICAST: u16 = config::ARP_MAXAGE as u16 - 30;
const ARP_AGE_REREQUEST_USED_BROADCAST: u16 = config::ARP_MAXAGE as u16 - 15;

/// The time an ARP entry stays pending after first request, for ARP_TMR_INTERVAL = 1000,
/// this is 10 seconds.
///
/// @internal Keep this number at least 2, otherwise it might run out instantly if the
/// timeout occurs directly after a request.
const ARP_MAXPENDING: u16 = 5;

/// ARP states.
const ETHARP_STATE_EMPTY: u8 = 0;
const ETHARP_STATE_PENDING: u8 = 1;
const ETHARP_STATE_STABLE: u8 = 2;
const ETHARP_STATE_STABLE_REREQUESTING_1: u8 = 3;
const ETHARP_STATE_STABLE_REREQUESTING_2: u8 = 4;
const ETHARP_STATE_STATIC: u8 = 5;

/// Try hard to create a new entry - we want the IP address to appear in the cache (even
/// if this means removing an active entry or so).
const ETHARP_FLAG_TRY_HARD: u8 = 1;
const ETHARP_FLAG_FIND_ONLY: u8 = 2;
const ETHARP_FLAG_STATIC_ENTRY: u8 = 4;

/// ARP message types (opcodes).
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;

/// `LWIP_IANA_HWTYPE_ETHERNET`.
const LWIP_IANA_HWTYPE_ETHERNET: u16 = 1;

const ARP_TABLE_SIZE: usize = config::ARP_TABLE_SIZE;

/// An entry of the ARP table (`struct etharp_entry`). Private to this module.
#[derive(Clone, Copy)]
struct EtharpEntry {
    /// Pointer to queue of pending outgoing packets on this ARP entry.
    q: *mut EtharpQEntry,
    ipaddr: Ip4Addr,
    netif: *mut Netif,
    ethaddr: EthAddr,
    ctime: u16,
    state: u8,
}

const EMPTY_ENTRY: EtharpEntry = EtharpEntry {
    q: ptr::null_mut(),
    ipaddr: Ip4Addr { addr: 0 },
    netif: ptr::null_mut(),
    ethaddr: EthAddr {
        addr: [0; ETH_HWADDR_LEN],
    },
    ctime: 0,
    state: ETHARP_STATE_EMPTY,
};

static ARP_TABLE: Global<[EtharpEntry; ARP_TABLE_SIZE]> =
    Global::new([EMPTY_ENTRY; ARP_TABLE_SIZE]);

/// `netif_addr_idx_t` of the entry last used for output.
static ETHARP_CACHED_ENTRY: Global<u8> = Global::new(0);

/// Entry `i` of the ARP table.
///
/// # Safety
///
/// `i < ARP_TABLE_SIZE`, called from the tcpip thread; the reference is not held across
/// a call that may use the table.
unsafe fn entry<'a>(i: usize) -> &'a mut EtharpEntry {
    // SAFETY: in bounds and serialized, per the caller.
    unsafe { &mut (*ARP_TABLE.as_ptr())[i] }
}

/// `ip4_addr_isany()`: null or 0.0.0.0.
fn ip4_addr_isany(addr: *const Ip4Addr) -> bool {
    // SAFETY: null or a valid address, per the callers' contracts.
    unsafe { addr.as_ref() }.is_none_or(|addr| addr.addr == IPADDR_ANY)
}

/// `ip4_addr_ismulticast()`: 224.0.0.0/4.
fn ip4_addr_ismulticast(addr: &Ip4Addr) -> bool {
    addr.addr & 0xf000_0000_u32.to_be() == 0xe000_0000_u32.to_be()
}

/// `ip4_addr_islinklocal()`: 169.254.0.0/16.
fn ip4_addr_islinklocal(addr: &Ip4Addr) -> bool {
    addr.addr & 0xffff_0000_u32.to_be() == 0xa9fe_0000_u32.to_be()
}

/// `ip4_addr_net_eq(addr1, addr2, mask)`.
fn ip4_addr_net_eq(addr1: &Ip4Addr, addr2: &Ip4Addr, mask: &Ip4Addr) -> bool {
    addr1.addr & mask.addr == addr2.addr & mask.addr
}

/// Free a complete queue of etharp entries.
///
/// # Safety
///
/// `q` is a queue of `MEMP_ARP_QUEUE` elements, each holding a pbuf reference.
unsafe fn free_etharp_q(mut q: *mut EtharpQEntry) {
    lwip_assert!("q != NULL", !q.is_null());
    // SAFETY: each element is live until freed, per the caller.
    unsafe {
        while !q.is_null() {
            let r = q;
            q = (*q).next;
            lwip_assert!("r->p != NULL", !(*r).p.is_null());
            pbuf_free((*r).p);
            memp_free(config::MEMP_ARP_QUEUE, r.cast());
        }
    }
}

/// Clean up ARP table entries.
fn etharp_free_entry(i: usize) {
    // SAFETY: `i` is a table index; the queue is this entry's.
    unsafe {
        // And empty packet queue.
        let q = entry(i).q;
        if !q.is_null() {
            // Remove all queued packets.
            free_etharp_q(q);
            entry(i).q = ptr::null_mut();
        }
        // Recycle entry for re-use.
        entry(i).state = ETHARP_STATE_EMPTY;
    }
}

/// Clears expired entries in the ARP table.
///
/// This function should be called every `ARP_TMR_INTERVAL` milliseconds (1 second), in
/// order to expire entries in the ARP table.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn etharp_tmr() {
    // Remove expired entries from the ARP table.
    for i in 0..ARP_TABLE_SIZE {
        // SAFETY: a table index; the reference is re-taken after each call below.
        let e = unsafe { entry(i) };
        let state = e.state;
        if state != ETHARP_STATE_EMPTY && state != ETHARP_STATE_STATIC {
            e.ctime = e.ctime.wrapping_add(1);
            if e.ctime >= config::ARP_MAXAGE as u16
                || (e.state == ETHARP_STATE_PENDING && e.ctime >= ARP_MAXPENDING)
            {
                // Pending or stable entry has become old!
                // Clean up entries that have just been expired.
                etharp_free_entry(i);
            } else if e.state == ETHARP_STATE_STABLE_REREQUESTING_1 {
                // Don't send more than one request every 2 seconds.
                e.state = ETHARP_STATE_STABLE_REREQUESTING_2;
            } else if e.state == ETHARP_STATE_STABLE_REREQUESTING_2 {
                // Reset state to stable, so that the next transmitted packet will
                // re-send an ARP request.
                e.state = ETHARP_STATE_STABLE;
            } else if e.state == ETHARP_STATE_PENDING {
                // Still pending, resend an ARP query.
                let (netif, ipaddr) = (e.netif, ptr::addr_of!(e.ipaddr));
                // SAFETY: a pending entry's netif is live.
                unsafe { etharp_request(netif, ipaddr) };
            }
        }
    }
}

/// Search the ARP table for a matching or new entry.
///
/// If an IP address is given, return a pending or stable ARP entry that matches the
/// address. If no match is found, create a new entry with this address set, but in state
/// ETHARP_EMPTY. The caller must check and possibly change the state of the returned
/// entry.
///
/// If ipaddr is NULL, return an empty entry.
///
/// In all cases, attempt to create new entries from an empty entry. If no empty entries
/// are available and `ETHARP_FLAG_TRY_HARD` flag is set, recycle old entries. Heuristic
/// choose the least important entry for recycling.
///
/// Returns the ARP entry index that matched or is created, `ERR_MEM` if no entry is found
/// or could be recycled.
///
/// # Safety
///
/// `ipaddr` is null or valid.
unsafe fn etharp_find_entry(ipaddr: *const Ip4Addr, flags: u8, netif: *mut Netif) -> i16 {
    const NONE: i16 = ARP_TABLE_SIZE as i16;
    let (mut old_pending, mut old_stable) = (NONE, NONE);
    let mut empty = NONE;
    let mut old_queue = NONE;
    // Its age.
    let (mut age_queue, mut age_pending, mut age_stable): (u16, u16, u16) = (0, 0, 0);

    // SAFETY: null or valid, per the caller.
    let ipaddr_ref = unsafe { ipaddr.as_ref() };

    // a) do a search through the cache, remember candidates
    // b) select candidate entry
    // c) create new entry

    // a) in a single search sweep, do all of this
    // 1) remember the first empty entry (if any)
    // 2) remember the oldest stable entry (if any)
    // 3) remember the oldest pending entry without queued packets (if any)
    // 4) remember the oldest pending entry with queued packets (if any)
    // 5) search for a matching IP entry, either pending or stable until 5 matches, or all
    //    entries are searched for.
    for i in 0..NONE {
        // SAFETY: a table index.
        let e = unsafe { entry(i as usize) };
        let state = e.state;
        // No empty entry found yet and now we do find one?
        if empty == NONE && state == ETHARP_STATE_EMPTY {
            // Remember first empty entry.
            empty = i;
        } else if state != ETHARP_STATE_EMPTY {
            lwip_assert!(
                "state == ETHARP_STATE_PENDING || state >= ETHARP_STATE_STABLE",
                state == ETHARP_STATE_PENDING || state >= ETHARP_STATE_STABLE
            );
            // If given, does IP address match IP address in ARP entry?
            if ipaddr_ref.is_some_and(|ipaddr| ipaddr.addr == e.ipaddr.addr)
                && (netif.is_null() || netif == e.netif)
            {
                // Found exact IP address match, simply bail out.
                return i;
            }
            // Pending entry?
            if state == ETHARP_STATE_PENDING {
                // Pending with queued packets?
                if !e.q.is_null() {
                    if e.ctime >= age_queue {
                        old_queue = i;
                        age_queue = e.ctime;
                    }
                } else if e.ctime >= age_pending {
                    // Pending without queued packets: remember entry pending time.
                    old_pending = i;
                    age_pending = e.ctime;
                }
            // Stable entry?
            } else if state >= ETHARP_STATE_STABLE {
                // Don't record old_stable for static entries since they never expire.
                if state < ETHARP_STATE_STATIC {
                    // Remember entry and time.
                    if e.ctime >= age_stable {
                        old_stable = i;
                        age_stable = e.ctime;
                    }
                }
            }
        }
    }
    // { we have no match }
    // => no entry found, or IP address was not found in the entries.

    // Don't create new entry, only search?
    if flags & ETHARP_FLAG_FIND_ONLY != 0
        // Or no empty entry found and not allowed to recycle?
        || (empty == NONE && flags & ETHARP_FLAG_TRY_HARD == 0)
    {
        return i16::from(ERR_MEM);
    }

    // b) choose the least destructive entry to recycle:
    // 1) empty entry
    // 2) oldest stable entry
    // 3) oldest pending entry without queued packets
    // 4) oldest pending entry with queued packets
    //
    // { ETHARP_FLAG_TRY_HARD is set at this point }

    let i;
    // 1) empty entry available?
    if empty < NONE {
        i = empty;
    } else {
        // 2) found recyclable stable entry?
        if old_stable < NONE {
            // Recycle oldest stable.
            i = old_stable;
            // No queued packets should exist on stable entries.
            // SAFETY: a table index.
            lwip_assert!(
                "arp_table[i].q == NULL",
                unsafe { entry(i as usize) }.q.is_null()
            );
        // 3) found recyclable pending entry without queued packets?
        } else if old_pending < NONE {
            // Recycle oldest pending.
            i = old_pending;
        // 4) found recyclable pending entry with queued packets?
        } else if old_queue < NONE {
            // Recycle oldest pending (queued packets are free in etharp_free_entry).
            i = old_queue;
        // No empty or recyclable entries found.
        } else {
            return i16::from(ERR_MEM);
        }

        // { empty or recyclable entry found }
        lwip_assert!("i < ARP_TABLE_SIZE", i < NONE);
        etharp_free_entry(i as usize);
    }

    lwip_assert!("i < ARP_TABLE_SIZE", i < NONE);
    // SAFETY: a table index.
    let e = unsafe { entry(i as usize) };
    lwip_assert!(
        "arp_table[i].state == ETHARP_STATE_EMPTY",
        e.state == ETHARP_STATE_EMPTY
    );

    // IP address given?
    if let Some(ipaddr) = ipaddr_ref {
        // Set IP address.
        e.ipaddr = *ipaddr;
    }
    e.ctime = 0;
    e.netif = netif;
    i
}

/// Update (or insert) an IP/MAC address pair in the ARP cache.
///
/// If a pending entry is resolved, any queued packets will be sent at this point.
///
/// Returns `ERR_OK` on success, `ERR_ARG` for a non-unicast address, `ERR_MEM` if the
/// cache is full, `ERR_VAL` to refuse overwriting a static entry.
///
/// # Safety
///
/// `netif` is live, `ipaddr` null or valid, and `ethaddr` a valid Ethernet address.
unsafe fn etharp_update_arp_entry(
    netif: *mut Netif,
    ipaddr: *const Ip4Addr,
    ethaddr: *const EthAddr,
    flags: u8,
) -> ErrT {
    // SAFETY: as the caller guarantees.
    unsafe {
        lwip_assert!(
            "netif->hwaddr_len == ETH_HWADDR_LEN",
            usize::from((*netif).hwaddr_len) == ETH_HWADDR_LEN
        );
        // Non-unicast address?
        if ip4_addr_isany(ipaddr)
            || ip4_addr_isbroadcast_u32((*ipaddr).addr, netif) != 0
            || ip4_addr_ismulticast(&*ipaddr)
        {
            return ERR_ARG;
        }
        // Find or create ARP entry.
        let i = etharp_find_entry(ipaddr, flags, netif);
        // Bail out if no entry could be found.
        if i < 0 {
            return i as ErrT;
        }
        let i = i as usize;

        if flags & ETHARP_FLAG_STATIC_ENTRY != 0 {
            // Record static type.
            entry(i).state = ETHARP_STATE_STATIC;
        } else if entry(i).state == ETHARP_STATE_STATIC {
            // Found entry is a static type, don't overwrite it.
            return ERR_VAL;
        } else {
            // Mark it stable.
            entry(i).state = ETHARP_STATE_STABLE;
        }

        // Record network interface.
        entry(i).netif = netif;
        // Update address.
        entry(i).ethaddr = ethaddr.read_unaligned();
        // Reset time stamp.
        entry(i).ctime = 0;
        // This is where we will send out queued packets!
        while !entry(i).q.is_null() {
            let q = entry(i).q;
            // Remember remainder of queue.
            entry(i).q = (*q).next;
            // Get the packet pointer.
            let p = (*q).p;
            // Now queue entry can be freed.
            memp_free(config::MEMP_ARP_QUEUE, q.cast());
            // Send the queued IP packet.
            ethernet_output(
                netif,
                p,
                ptr::addr_of!((*netif).hwaddr).cast(),
                ethaddr,
                ETHTYPE_IP,
            );
            // Free the queued IP packet.
            pbuf_free(p);
        }
    }
    ERR_OK
}

/// Add a new static entry to the ARP table. If an entry exists for the specified IP
/// address, this entry is overwritten. If packets are queued for the specified IP
/// address, they are sent out.
///
/// # Safety
///
/// `ipaddr` and `ethaddr` are valid.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn etharp_add_static_entry(
    ipaddr: *const Ip4Addr,
    ethaddr: *mut EthAddr,
) -> ErrT {
    // SAFETY: valid, per the caller; a routed netif is live.
    unsafe {
        let netif = ip4_route(ipaddr);
        if netif.is_null() {
            return ERR_RTE;
        }
        etharp_update_arp_entry(
            netif,
            ipaddr,
            ethaddr,
            ETHARP_FLAG_TRY_HARD | ETHARP_FLAG_STATIC_ENTRY,
        )
    }
}

/// Remove a static entry from the ARP table previously added with a call to
/// `etharp_add_static_entry`.
///
/// Returns `ERR_OK` if the entry was removed, `ERR_MEM` if the entry wasn't found,
/// `ERR_ARG` if the entry wasn't a static entry but a dynamic one.
///
/// # Safety
///
/// `ipaddr` is valid.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn etharp_remove_static_entry(ipaddr: *const Ip4Addr) -> ErrT {
    // Find or create ARP entry.
    // SAFETY: valid, per the caller.
    let i = unsafe { etharp_find_entry(ipaddr, ETHARP_FLAG_FIND_ONLY, ptr::null_mut()) };
    // Bail out if no entry could be found.
    if i < 0 {
        return i as ErrT;
    }
    // SAFETY: a table index.
    if unsafe { entry(i as usize) }.state != ETHARP_STATE_STATIC {
        // Entry wasn't a static entry, cannot remove it.
        return ERR_ARG;
    }
    // Entry found, free it.
    etharp_free_entry(i as usize);
    ERR_OK
}

/// Remove all ARP table entries of the specified netif.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn etharp_cleanup_netif(netif: *mut Netif) {
    for i in 0..ARP_TABLE_SIZE {
        // SAFETY: a table index.
        let e = unsafe { entry(i) };
        if e.state != ETHARP_STATE_EMPTY && e.netif == netif {
            etharp_free_entry(i);
        }
    }
}

/// Finds (stable) ethernet/IP address pair from ARP table using interface and IP address
/// index.
///
/// Returns the table index if found, -1 otherwise.
///
/// # Safety
///
/// `ipaddr` is valid, and `eth_ret` and `ip_ret` are writable.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn etharp_find_addr(
    netif: *mut Netif,
    ipaddr: *const Ip4Addr,
    eth_ret: *mut *mut EthAddr,
    ip_ret: *mut *const Ip4Addr,
) -> isize {
    lwip_assert!(
        "eth_ret != NULL && ip_ret != NULL",
        !eth_ret.is_null() && !ip_ret.is_null()
    );
    // SAFETY: as the caller guarantees; the returned pointers point into the static table.
    unsafe {
        let i = etharp_find_entry(ipaddr, ETHARP_FLAG_FIND_ONLY, netif);
        if i >= 0 && entry(i as usize).state >= ETHARP_STATE_STABLE {
            let e = (*ARP_TABLE.as_ptr()).as_mut_ptr().add(i as usize);
            *eth_ret = ptr::addr_of_mut!((*e).ethaddr);
            *ip_ret = ptr::addr_of!((*e).ipaddr);
            return i as isize;
        }
    }
    -1
}

/// Possibility to iterate over stable ARP table entries.
///
/// Returns 1 on valid index, 0 otherwise.
///
/// # Safety
///
/// `ipaddr`, `netif`, and `eth_ret` are writable.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn etharp_get_entry(
    i: usize,
    ipaddr: *mut *mut Ip4Addr,
    netif: *mut *mut Netif,
    eth_ret: *mut *mut EthAddr,
) -> c_int {
    lwip_assert!("ipaddr != NULL", !ipaddr.is_null());
    lwip_assert!("netif != NULL", !netif.is_null());
    lwip_assert!("eth_ret != NULL", !eth_ret.is_null());

    // SAFETY: writable, per the caller; the returned pointers point into the static table.
    unsafe {
        if i < ARP_TABLE_SIZE && entry(i).state >= ETHARP_STATE_STABLE {
            let e = (*ARP_TABLE.as_ptr()).as_mut_ptr().add(i);
            *ipaddr = ptr::addr_of_mut!((*e).ipaddr);
            *netif = (*e).netif;
            *eth_ret = ptr::addr_of_mut!((*e).ethaddr);
            1
        } else {
            0
        }
    }
}

/// Responds to ARP requests to us. Upon ARP replies to us, add entry to cache send out
/// queued IP packets. Updates cache with snooped address pairs.
///
/// Should be called for incoming ARP packets. The pbuf in the argument is freed by this
/// function.
///
/// # Safety
///
/// `p` is a live pbuf whose payload holds an ARP message and `netif` is null or live; the
/// caller gives up `p`.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn etharp_input(p: *mut Pbuf, netif: *mut Netif) {
    // LWIP_ERROR("netif != NULL", (netif != NULL), return;)
    if netif.is_null() {
        return;
    }

    // SAFETY: as the caller guarantees. ethernet_input checked the pbuf holds more than
    // an Ethernet header; the ARP header fields are read unaligned, as the packed C
    // struct is.
    unsafe {
        let hdr = (*p).payload.cast::<EtharpHdr>();
        let h = hdr.read_unaligned();

        // RFC 826 "Packet Reception":
        if h.hwtype != LWIP_IANA_HWTYPE_ETHERNET.to_be()
            || usize::from(h.hwlen) != ETH_HWADDR_LEN
            || usize::from(h.protolen) != core::mem::size_of::<Ip4Addr>()
            || h.proto != ETHTYPE_IP.to_be()
        {
            pbuf_free(p);
            return;
        }

        // We have to check if a host already has configured our random created link
        // local address and continuously check if there is a host with this IP-address
        // so we can detect collisions.
        acd_arp_reply(netif, hdr);

        // Copy struct ip4_addr_wordaligned to aligned ip4_addr, to support compilers
        // without structure packing (not using structure copy which breaks
        // strict-aliasing rules).
        let sipaddr = Ip4Addr {
            addr: u32::from_ne_bytes(ptr::addr_of!((*hdr).sipaddr).cast::<[u8; 4]>().read()),
        };
        let dipaddr = Ip4Addr {
            addr: u32::from_ne_bytes(ptr::addr_of!((*hdr).dipaddr).cast::<[u8; 4]>().read()),
        };

        let ours = (*netif).ip4_addr().addr;
        // This interface is not configured?
        let (for_us, from_us) = if ours == IPADDR_ANY {
            (false, false)
        } else {
            // ARP packet directed to us?
            // ARP packet from us?
            (dipaddr.addr == ours, sipaddr.addr == ours)
        };

        // ARP message directed to us?
        //   -> add IP address in ARP cache; assume requester wants to talk to us, can
        //      result in directly sending the queued packets for this host.
        // ARP message not directed to us?
        //   -> update the source IP address in the cache, if present
        etharp_update_arp_entry(
            netif,
            &sipaddr,
            ptr::addr_of!((*hdr).shwaddr),
            if for_us {
                ETHARP_FLAG_TRY_HARD
            } else {
                ETHARP_FLAG_FIND_ONLY
            },
        );

        // Now act on the message itself.
        match u16::from_be(h.opcode) {
            // ARP request?
            ARP_REQUEST => {
                // ARP request. If it asked for our address, we send out a reply. In any
                // case, we time-stamp any existing ARP entry, and possibly send out an IP
                // packet that was queued on it.
                // ARP request for our address?
                if for_us && !from_us {
                    // Send ARP response.
                    let hwaddr = ptr::addr_of!((*netif).hwaddr).cast::<EthAddr>();
                    etharp_raw(
                        netif,
                        hwaddr,
                        ptr::addr_of!((*hdr).shwaddr),
                        hwaddr,
                        (*netif).ip4_addr(),
                        ptr::addr_of!((*hdr).shwaddr),
                        &sipaddr,
                        ARP_REPLY,
                    );
                }
                // Otherwise the request is for someone else, or we are not configured
                // yet: nothing to answer.
            }
            // ARP reply. We already updated the ARP cache earlier.
            // DHCP wants to know about ARP replies from any host with an IP address
            // also used by us, but that is handled by ACD above.
            ARP_REPLY => {}
            _ => {}
        }
        // Free ARP packet.
        pbuf_free(p);
    }
}

/// Just a small helper function that sends a pbuf to an ethernet address in the
/// `arp_table` specified by the index `arp_idx`.
///
/// # Safety
///
/// `netif` and `q` are live, and `arp_idx` names a stable entry.
unsafe fn etharp_output_to_arp_index(netif: *mut Netif, q: *mut Pbuf, arp_idx: u8) -> ErrT {
    let idx = usize::from(arp_idx);
    // SAFETY: as the caller guarantees.
    unsafe {
        lwip_assert!(
            "arp_table[arp_idx].state >= ETHARP_STATE_STABLE",
            entry(idx).state >= ETHARP_STATE_STABLE
        );
        let e = (*ARP_TABLE.as_ptr()).as_mut_ptr().add(idx);
        // If arp table entry is about to expire: re-request it, but only if its state is
        // ETHARP_STATE_STABLE to prevent flooding the network with ARP requests if this
        // address is used frequently.
        if (*e).state == ETHARP_STATE_STABLE {
            if (*e).ctime >= ARP_AGE_REREQUEST_USED_BROADCAST {
                // Issue a standard request using broadcast.
                if etharp_request(netif, ptr::addr_of!((*e).ipaddr)) == ERR_OK {
                    (*e).state = ETHARP_STATE_STABLE_REREQUESTING_1;
                }
            } else if (*e).ctime >= ARP_AGE_REREQUEST_USED_UNICAST {
                // Issue a unicast request (for 15 seconds) to prevent unnecessary
                // broadcast.
                if etharp_request_dst(
                    netif,
                    ptr::addr_of!((*e).ipaddr),
                    ptr::addr_of!((*e).ethaddr),
                ) == ERR_OK
                {
                    (*e).state = ETHARP_STATE_STABLE_REREQUESTING_1;
                }
            }
        }

        ethernet_output(
            netif,
            q,
            ptr::addr_of!((*netif).hwaddr).cast(),
            ptr::addr_of!((*e).ethaddr),
            ETHTYPE_IP,
        )
    }
}

/// Resolve and fill-in Ethernet address header for outgoing IP packet.
///
/// For IP multicast and broadcast, corresponding Ethernet addresses are selected and the
/// packet is transmitted on the link.
///
/// For unicast addresses, the packet is submitted to `etharp_query()`. In case the IP
/// address is outside the local network, the IP address of the gateway is used.
///
/// Returns `ERR_RTE` if no route to destination (no gateway to external networks), or the
/// return type of either `etharp_query()` or `ethernet_output()`.
///
/// # Safety
///
/// `netif` and `q` are live and `ipaddr` valid.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn etharp_output(
    netif: *mut Netif,
    q: *mut Pbuf,
    ipaddr: *const Ip4Addr,
) -> ErrT {
    let mut dst_addr = ipaddr;

    lwip_assert!("netif != NULL", !netif.is_null());
    lwip_assert!("q != NULL", !q.is_null());
    lwip_assert!("ipaddr != NULL", !ipaddr.is_null());

    // SAFETY: as the caller guarantees.
    unsafe {
        let ip = &*ipaddr;
        let mcastaddr;
        let dest: *const EthAddr;
        // Determine on destination hardware address. Broadcasts and multicasts are
        // special, other IP addresses are looked up in the ARP table.

        // Broadcast destination IP address?
        if ip4_addr_isbroadcast_u32(ip.addr, netif) != 0 {
            // Broadcast on Ethernet also.
            dest = ethbroadcast();
        // Multicast destination IP address?
        } else if ip4_addr_ismulticast(ip) {
            // Hash IP multicast address to MAC address.
            let bytes = ip.addr.to_ne_bytes();
            mcastaddr = EthAddr {
                addr: [0x01, 0x00, 0x5e, bytes[1] & 0x7f, bytes[2], bytes[3]],
            };
            // Destination Ethernet address is multicast.
            dest = &mcastaddr;
        // Unicast destination IP address?
        } else {
            // Outside local network? If so, this can neither be a global broadcast nor a
            // subnet broadcast.
            if !ip4_addr_net_eq(ip, (*netif).ip4_addr(), (*netif).ip4_netmask())
                && !ip4_addr_islinklocal(ip)
            {
                // Interface has default gateway?
                if (*netif).ip4_gw().addr != IPADDR_ANY {
                    // Send to hardware address of default gateway IP address.
                    dst_addr = (*netif).ip4_gw();
                // No default gateway available.
                } else {
                    // No route to destination error (default gateway missing).
                    return ERR_RTE;
                }
            }

            // Find stable entry: do this first since this is the most common case.
            let cached = ETHARP_CACHED_ENTRY.get();
            let c = entry(usize::from(cached));
            if c.state >= ETHARP_STATE_STABLE
                && c.netif == netif
                && (*dst_addr).addr == c.ipaddr.addr
            {
                // The per-pcb-cached entry is stable and matches the destination: use it.
                return etharp_output_to_arp_index(netif, q, cached);
            }
            // Find stable entry: do this first since this is the most common case.
            for i in 0..ARP_TABLE_SIZE as u8 {
                let e = entry(usize::from(i));
                if e.state >= ETHARP_STATE_STABLE
                    && e.netif == netif
                    && (*dst_addr).addr == e.ipaddr.addr
                {
                    // Found an existing, stable entry.
                    ETHARP_CACHED_ENTRY.set(i);
                    return etharp_output_to_arp_index(netif, q, i);
                }
            }
            // No stable entry found, use the (slower) query function: queue on
            // destination Ethernet address belonging to ipaddr.
            return etharp_query(netif, dst_addr, q);
        }

        // Continuation for multicast/broadcast destinations; obtain source Ethernet
        // address of the interface and send the packet.
        ethernet_output(
            netif,
            q,
            ptr::addr_of!((*netif).hwaddr).cast(),
            dest,
            ETHTYPE_IP,
        )
    }
}

/// Send an ARP request for the given IP address and/or queue a packet.
///
/// If the IP address was not yet in the cache, a pending ARP cache entry is added and an
/// ARP request is sent for the given address. The packet is queued on this entry.
///
/// If the IP address was already pending in the cache, a new ARP request is sent for the
/// given address. The packet is queued on this entry.
///
/// If the IP address was already stable in the cache, and a packet is given, it is
/// directly sent and no ARP request is sent out.
///
/// If the IP address was already stable in the cache, and no packet is given, an ARP
/// request is sent out.
///
/// Returns `ERR_BUF` if the ARP request couldn't be sent, `ERR_MEM` if the packet couldn't
/// be queued, `ERR_ARG` for a non-unicast address, `ERR_OK` otherwise.
///
/// # Safety
///
/// `netif` is live, `ipaddr` valid, and `q` null or a live pbuf chain.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn etharp_query(
    netif: *mut Netif,
    ipaddr: *const Ip4Addr,
    q: *mut Pbuf,
) -> ErrT {
    let mut result = ERR_MEM;
    let mut is_new_entry = false;

    // SAFETY: as the caller guarantees.
    unsafe {
        let srcaddr = ptr::addr_of!((*netif).hwaddr).cast::<EthAddr>();

        // Non-unicast address? (The C macros read the address first, so it is never
        // null here.)
        if ip4_addr_isbroadcast_u32((*ipaddr).addr, netif) != 0
            || ip4_addr_ismulticast(&*ipaddr)
            || ip4_addr_isany(ipaddr)
        {
            return ERR_ARG;
        }

        // Find entry in ARP cache, ask to create entry if queueing packet.
        let i_err = etharp_find_entry(ipaddr, ETHARP_FLAG_TRY_HARD, netif);

        // Could not find or create entry?
        if i_err < 0 {
            return i_err as ErrT;
        }
        lwip_assert!("type overflow", (i_err as usize) < 0x7F);
        let i = i_err as u8;
        let idx = usize::from(i);

        // Mark a fresh entry as pending (we just sent a request).
        if entry(idx).state == ETHARP_STATE_EMPTY {
            is_new_entry = true;
            entry(idx).state = ETHARP_STATE_PENDING;
            // Record network interface for re-sending arp request in etharp_tmr.
            entry(idx).netif = netif;
        }

        // { i is either a STABLE or (new or existing) PENDING entry }
        lwip_assert!(
            "arp_table[i].state == PENDING or STABLE",
            entry(idx).state == ETHARP_STATE_PENDING || entry(idx).state >= ETHARP_STATE_STABLE
        );

        // Do we have a new entry? or an implicit query request?
        if is_new_entry || q.is_null() {
            // Try to resolve it; send out ARP request.
            result = etharp_request(netif, ipaddr);
            if result == ERR_OK && entry(idx).state == ETHARP_STATE_PENDING && !is_new_entry {
                // Reset time stamp to prevent a too early timeout for requests that are
                // re-sent.
                entry(idx).ctime = 0;
            }
            if q.is_null() {
                return result;
            }
        }

        // Packet given?
        lwip_assert!("q != NULL", !q.is_null());
        // Stable entry?
        if entry(idx).state >= ETHARP_STATE_STABLE {
            // We have a valid IP->Ethernet address mapping.
            ETHARP_CACHED_ENTRY.set(i);
            // Send the packet.
            let e = (*ARP_TABLE.as_ptr()).as_mut_ptr().add(idx);
            result = ethernet_output(netif, q, srcaddr, ptr::addr_of!((*e).ethaddr), ETHTYPE_IP);
        // Pending entry? (either just created or already pending)
        } else if entry(idx).state == ETHARP_STATE_PENDING {
            // Entry is still pending, queue the given packet 'q'.
            let mut copy_needed = false;
            // IF q includes a pbuf that must be copied, copy the whole chain into a new
            // PBUF_RAM. See the definition of PBUF_NEEDS_COPY for details.
            let mut p = q;
            while !p.is_null() {
                lwip_assert!(
                    "no packet queues allowed!",
                    (*p).len != (*p).tot_len || (*p).next.is_none()
                );
                if (*p).type_internal & PBUF_TYPE_FLAG_DATA_VOLATILE != 0 {
                    copy_needed = true;
                    break;
                }
                p = (*p).next.map_or(ptr::null_mut(), ptr::NonNull::as_ptr);
            }
            if copy_needed {
                // Copy the whole packet into new pbufs.
                p = pbuf_clone(config::PBUF_LINK_LAYER as PbufLayer, PBUF_RAM, q);
            } else {
                // Referencing the old pbuf is enough.
                p = q;
                pbuf_ref(p);
            }
            // Packet could be taken over?
            if !p.is_null() {
                // Queue packet ...
                let new_entry = memp_malloc(config::MEMP_ARP_QUEUE).cast::<EtharpQEntry>();
                if !new_entry.is_null() {
                    let mut qlen: u32 = 0;
                    new_entry.write(EtharpQEntry {
                        next: ptr::null_mut(),
                        p,
                    });
                    let mut r = entry(idx).q;
                    if !r.is_null() {
                        // Queue was already existent, append the new entry to the end.
                        qlen += 1;
                        while !(*r).next.is_null() {
                            r = (*r).next;
                            qlen += 1;
                        }
                        (*r).next = new_entry;
                    } else {
                        // Queue did not exist, first item in queue.
                        entry(idx).q = new_entry;
                    }
                    if qlen >= config::ARP_QUEUE_LEN as u32 {
                        (*r).next = ptr::null_mut();
                        pbuf_free((*new_entry).p);
                        memp_free(config::MEMP_ARP_QUEUE, new_entry.cast());
                        return ERR_MEM;
                    }
                    result = ERR_OK;
                } else {
                    // The pool MEMP_ARP_QUEUE is empty.
                    pbuf_free(p);
                    result = ERR_MEM;
                }
            } else {
                result = ERR_MEM;
            }
        }
    }
    result
}

/// Send a raw ARP packet (opcode and all addresses can be modified).
///
/// Returns `ERR_OK` if the ARP packet has been sent, `ERR_MEM` if the ARP packet couldn't
/// be allocated.
///
/// # Safety
///
/// `netif` is live and every address valid.
#[allow(clippy::too_many_arguments)]
unsafe fn etharp_raw(
    netif: *mut Netif,
    ethsrc_addr: *const EthAddr,
    ethdst_addr: *const EthAddr,
    hwsrc_addr: *const EthAddr,
    ipsrc_addr: *const Ip4Addr,
    hwdst_addr: *const EthAddr,
    ipdst_addr: *const Ip4Addr,
    opcode: u16,
) -> ErrT {
    let result = ERR_OK;

    lwip_assert!("netif != NULL", !netif.is_null());

    // SAFETY: as the caller guarantees; the header is written into the pbuf's payload,
    // which is at least SIZEOF_ETHARP_HDR bytes.
    unsafe {
        // Allocate a pbuf for the outgoing ARP request packet.
        let p = pbuf_alloc(
            config::PBUF_LINK_LAYER as PbufLayer,
            SIZEOF_ETHARP_HDR,
            PBUF_RAM,
        );
        // Could allocate a pbuf for an ARP request?
        if p.is_null() {
            return ERR_MEM;
        }
        lwip_assert!(
            "check that first pbuf can hold struct etharp_hdr",
            (*p).len >= SIZEOF_ETHARP_HDR
        );

        let hdr = (*p).payload.cast::<EtharpHdr>();
        ptr::addr_of_mut!((*hdr).opcode).write_unaligned(opcode.to_be());

        lwip_assert!(
            "netif->hwaddr_len must be the same as ETH_HWADDR_LEN for etharp!",
            usize::from((*netif).hwaddr_len) == ETH_HWADDR_LEN
        );

        // Write the ARP MAC-Addresses.
        ptr::addr_of_mut!((*hdr).shwaddr).write_unaligned(hwsrc_addr.read_unaligned());
        ptr::addr_of_mut!((*hdr).dhwaddr).write_unaligned(hwdst_addr.read_unaligned());
        // Copy struct ip4_addr_wordaligned to aligned ip4_addr, to support compilers
        // without structure packing.
        ptr::addr_of_mut!((*hdr).sipaddr)
            .cast::<[u8; 4]>()
            .write((*ipsrc_addr).addr.to_ne_bytes());
        ptr::addr_of_mut!((*hdr).dipaddr)
            .cast::<[u8; 4]>()
            .write((*ipdst_addr).addr.to_ne_bytes());

        ptr::addr_of_mut!((*hdr).hwtype).write_unaligned(LWIP_IANA_HWTYPE_ETHERNET.to_be());
        ptr::addr_of_mut!((*hdr).proto).write_unaligned(ETHTYPE_IP.to_be());
        // Set hwlen and protolen.
        ptr::addr_of_mut!((*hdr).hwlen).write(ETH_HWADDR_LEN as u8);
        ptr::addr_of_mut!((*hdr).protolen).write(core::mem::size_of::<Ip4Addr>() as u8);

        // Send ARP query.
        ethernet_output(netif, p, ethsrc_addr, ethdst_addr, ETHTYPE_ARP);
        // Free ARP query packet.
        pbuf_free(p);
    }
    // Could not allocate pbuf for ARP request.
    result
}

/// Send an ARP request packet asking for ipaddr to a specific eth address. Used to send
/// unicast request to refresh the ARP table just before an entry times out.
///
/// # Safety
///
/// `netif` is live and the addresses valid.
unsafe fn etharp_request_dst(
    netif: *mut Netif,
    ipaddr: *const Ip4Addr,
    hw_dst_addr: *const EthAddr,
) -> ErrT {
    // SAFETY: as the caller guarantees.
    unsafe {
        let hwaddr = ptr::addr_of!((*netif).hwaddr).cast::<EthAddr>();
        etharp_raw(
            netif,
            hwaddr,
            hw_dst_addr,
            hwaddr,
            (*netif).ip4_addr(),
            ethzero(),
            ipaddr,
            ARP_REQUEST,
        )
    }
}

/// Send an ARP request packet asking for ipaddr.
///
/// Returns `ERR_OK` if the request has been sent, `ERR_MEM` if the ARP packet couldn't be
/// allocated.
///
/// # Safety
///
/// `netif` is live and `ipaddr` valid.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn etharp_request(netif: *mut Netif, ipaddr: *const Ip4Addr) -> ErrT {
    // SAFETY: forwarded from the caller.
    unsafe { etharp_request_dst(netif, ipaddr, ethbroadcast()) }
}

/// Send an ARP request packet probing for an ipaddr. Used to send probe messages for
/// address conflict detection.
///
/// # Safety
///
/// `netif` is live and `ipaddr` valid.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn etharp_acd_probe(netif: *mut Netif, ipaddr: *const Ip4Addr) -> ErrT {
    // SAFETY: as the caller guarantees.
    unsafe {
        let hwaddr = ptr::addr_of!((*netif).hwaddr).cast::<EthAddr>();
        let any = Ip4Addr { addr: IPADDR_ANY };
        etharp_raw(
            netif,
            hwaddr,
            ethbroadcast(),
            hwaddr,
            &any,
            ethzero(),
            ipaddr,
            ARP_REQUEST,
        )
    }
}

/// Send an ARP request packet announcing an ipaddr. Used to send announce messages for
/// address conflict detection.
///
/// # Safety
///
/// `netif` is live and `ipaddr` valid.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn etharp_acd_announce(netif: *mut Netif, ipaddr: *const Ip4Addr) -> ErrT {
    // SAFETY: as the caller guarantees.
    unsafe {
        let hwaddr = ptr::addr_of!((*netif).hwaddr).cast::<EthAddr>();
        etharp_raw(
            netif,
            hwaddr,
            ethbroadcast(),
            hwaddr,
            ipaddr,
            ethzero(),
            ipaddr,
            ARP_REQUEST,
        )
    }
}

#[cfg(test)]
mod tests;
