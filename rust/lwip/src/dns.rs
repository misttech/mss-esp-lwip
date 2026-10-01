// Port to lwIP from uIP
// by Jim Pettinato April 2007
//
// security fixes and more by Simon Goldschmidt
//
// uIP version Copyright (c) 2002-2003, Adam Dunkels.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote
//    products derived from this software without specific prior
//    written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
// OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
// GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Translated to Rust for mss-esp-lwip by Mist Tecnologia LTDA.

//! DNS - host name to IP address resolver, from `src/core/dns.c`, as ESP-IDF configures
//! it: IPv4 and IPv6 answers, random transaction IDs and source ports
//! (`LWIP_DNS_SECURE`), mDNS queries for `.local` names, ESP-IDF's skipping of unset
//! servers and its on-demand timer, and no local host list (`build.rs` refuses the
//! rest).
//!
//! The lwIP DNS resolver functions are used to lookup a host name and map it to a
//! numerical IP address. It maintains a list of resolved hostnames that can be queried
//! with the [`dns_lookup`] function. New hostnames can be resolved using the
//! [`dns_query`] function.
//!
//! The lwIP version of the resolver also adds a non-blocking version of
//! `gethostbyname()` that will work with a raw API application. This function checks for
//! an IP address string first and converts it if it is valid. [`dns_gethostbyname`] then
//! does a [`dns_lookup`] to see if the name is already in the table. If so, the IP is
//! returned. If not, a query is issued and the function returns with an
//! `ERR_INPROGRESS` status. The app using the `dns` client must then go into a waiting
//! state.
//!
//! Once a hostname has been resolved (or found to be non-existent), the resolver code
//! calls a specified callback function (which must be implemented by the module that
//! uses the resolver).
//!
//! Multicast DNS queries are supported for names ending on ".local". However, only
//! "One-Shot Multicast DNS Queries" are supported (RFC 6762 chapter 5.1), this is not a
//! fully compliant implementation of continuous mDNS querying!
//!
//! All functions must be called from TCPIP thread.
//!
//! [`dns_lookup`]: dns_lookup
//! [`dns_query`]: dns_enqueue

#![allow(non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::config;
use crate::global::Global;
use crate::links::*;
use crate::types::*;

const DNS_TABLE_SIZE: usize = config::DNS_TABLE_SIZE;
const DNS_MAX_NAME_LENGTH: usize = config::DNS_MAX_NAME_LENGTH;
const DNS_MAX_SERVERS: usize = config::DNS_MAX_SERVERS;
const DNS_MAX_REQUESTS: usize = config::DNS_MAX_REQUESTS_;
const DNS_MAX_SOURCE_PORTS: usize = config::DNS_MAX_SOURCE_PORTS_;
const DNS_MAX_HOST_IP: usize = config::DNS_MAX_HOST_IP;
const DNS_MAX_RETRIES: u8 = config::DNS_MAX_RETRIES as u8;
/// DNS resource record max. TTL (one week as default).
const DNS_MAX_TTL: u32 = config::DNS_MAX_TTL_ as u32;

/// `LWIP_DNS_ADDRTYPE_IPV4`: try to resolve IPv4 only.
pub const LWIP_DNS_ADDRTYPE_IPV4: u8 = 0;
/// `LWIP_DNS_ADDRTYPE_IPV6`: try to resolve IPv6 only.
pub const LWIP_DNS_ADDRTYPE_IPV6: u8 = 1;
/// `LWIP_DNS_ADDRTYPE_IPV4_IPV6`: try to resolve IPv4 first, try IPv6 if IPv4 fails.
pub const LWIP_DNS_ADDRTYPE_IPV4_IPV6: u8 = 2;
/// `LWIP_DNS_ADDRTYPE_IPV6_IPV4`: try to resolve IPv6 first, try IPv4 if IPv6 fails.
pub const LWIP_DNS_ADDRTYPE_IPV6_IPV4: u8 = 3;

/// DNS server port address.
const DNS_SERVER_PORT: u16 = 53;
/// UDP port for multicast DNS queries.
const DNS_MQUERY_PORT: u16 = 5353;

/// DNS field TYPE used for "Resource Records": a host address.
const DNS_RRTYPE_A: u16 = 1;
/// DNS field TYPE used for "Resource Records": IPv6 address.
const DNS_RRTYPE_AAAA: u16 = 28;
/// DNS field CLASS used for "Resource Records": the internet.
const DNS_RRCLASS_IN: u16 = 1;

const DNS_FLAG1_RESPONSE: u8 = 0x80;
const DNS_FLAG1_RD: u8 = 0x01;
const DNS_FLAG2_ERR_MASK: u8 = 0x0f;

/// `SIZEOF_DNS_HDR`: the DNS message header.
const SIZEOF_DNS_HDR: u16 = 12;
/// `SIZEOF_DNS_QUERY`: DNS query message structure. No packing needed: only used
/// locally on the stack.
const SIZEOF_DNS_QUERY: u16 = 4;
/// `SIZEOF_DNS_ANSWER`: DNS answer message structure, as it is on the wire.
const SIZEOF_DNS_ANSWER: u16 = 10;
/// `SIZEOF_DNS_ANSWER_ASSERT`: the most `struct dns_answer` may take in C, padding
/// included.
const SIZEOF_DNS_ANSWER_ASSERT: u16 = 12;

/// DNS table entry states.
const DNS_STATE_UNUSED: u8 = 0;
const DNS_STATE_NEW: u8 = 1;
const DNS_STATE_ASKING: u8 = 2;
const DNS_STATE_DONE: u8 = 3;

/// `dns_found_callback`: called when a host name is found or can't be found.
///
/// `name` is the host name that was looked up, `ipaddr` the IP address of the host
/// name, or null if the name could not be found (or on any other error), and
/// `callback_arg` a user-specified callback argument passed to `dns_gethostbyname`.
pub type DnsFoundCallback = Option<
    unsafe extern "C" fn(name: *const c_char, ipaddr: *const IpAddr, callback_arg: *mut c_void),
>;

/// `LWIP_DNS_ADDRTYPE_IS_IPV6(t)`.
fn addrtype_is_ipv6(t: u8) -> bool {
    t == LWIP_DNS_ADDRTYPE_IPV6_IPV4 || t == LWIP_DNS_ADDRTYPE_IPV6
}

/// `LWIP_DNS_ADDRTYPE_MATCH_IP(t, ip)`.
fn addrtype_match_ip(t: u8, ip: &IpAddr) -> bool {
    if ip.is_v6() {
        addrtype_is_ipv6(t)
    } else {
        !addrtype_is_ipv6(t)
    }
}

/// DNS table entry.
#[derive(Clone, Copy)]
struct DnsTableEntry {
    ttl: [u32; DNS_MAX_HOST_IP],
    ipaddr: [IpAddr; DNS_MAX_HOST_IP],
    ipaddr_cnt: u8,
    txid: u16,
    state: u8,
    server_idx: u8,
    tmr: u8,
    retries: u8,
    seqno: u8,
    pcb_idx: u8,
    name: [c_char; DNS_MAX_NAME_LENGTH],
    reqaddrtype: u8,
    is_mdns: u8,
}

/// A table entry as C zero-initializes it.
const DNS_TABLE_ENTRY_ZERO: DnsTableEntry = DnsTableEntry {
    ttl: [0; DNS_MAX_HOST_IP],
    ipaddr: [IpAddr::v4(0); DNS_MAX_HOST_IP],
    ipaddr_cnt: 0,
    txid: 0,
    state: DNS_STATE_UNUSED,
    server_idx: 0,
    tmr: 0,
    retries: 0,
    seqno: 0,
    pcb_idx: 0,
    name: [0; DNS_MAX_NAME_LENGTH],
    reqaddrtype: 0,
    is_mdns: 0,
};

/// DNS request table entry: used when dns_gethostbyname cannot answer the request from
/// the DNS table.
#[derive(Clone, Copy)]
struct DnsReqEntry {
    /// Pointer to callback on DNS query done.
    found: DnsFoundCallback,
    /// Argument passed to the callback function.
    arg: *mut c_void,
    dns_table_idx: u8,
    reqaddrtype: u8,
}

const DNS_REQ_ENTRY_ZERO: DnsReqEntry = DnsReqEntry {
    found: None,
    arg: ptr::null_mut(),
    dns_table_idx: 0,
    reqaddrtype: 0,
};

/// Whether ESP-IDF's on-demand DNS timer is running.
static S_IS_TMR_START: Global<bool> = Global::new(false);
static DNS_PCBS: Global<[*mut UdpPcb; DNS_MAX_SOURCE_PORTS]> =
    Global::new([ptr::null_mut(); DNS_MAX_SOURCE_PORTS]);
static DNS_LAST_PCB_IDX: Global<u8> = Global::new(0);
static DNS_SEQNO: Global<u8> = Global::new(0);
static DNS_TABLE: Global<[DnsTableEntry; DNS_TABLE_SIZE]> =
    Global::new([DNS_TABLE_ENTRY_ZERO; DNS_TABLE_SIZE]);
static DNS_REQUESTS: Global<[DnsReqEntry; DNS_MAX_REQUESTS]> =
    Global::new([DNS_REQ_ENTRY_ZERO; DNS_MAX_REQUESTS]);
static DNS_SERVERS: Global<[IpAddr; DNS_MAX_SERVERS]> =
    Global::new([IpAddr::v4(0); DNS_MAX_SERVERS]);

/// `dns_mquery_v4group`: 224.0.0.251, the mDNS IPv4 group.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub static dns_mquery_v4group: IpAddr = IpAddr::v4(u32::from_be_bytes([224, 0, 0, 251]).to_be());

/// `dns_mquery_v6group`: FF02::FB, the mDNS IPv6 group.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub static dns_mquery_v6group: IpAddr = IpAddr {
    u_addr: IpAddrUnion {
        ip6: Ip6Addr {
            addr: [0xff02_0000_u32.to_be(), 0, 0, 0xfb_u32.to_be()],
            #[cfg(lwip_ipv6_scopes)]
            zone: 0,
        },
    },
    type_: IPADDR_TYPE_V6,
};

/// `&dns_table[idx]`.
fn entry(idx: u8) -> *mut DnsTableEntry {
    // SAFETY: only the element's address is taken, in bounds.
    unsafe { &raw mut (*DNS_TABLE.as_ptr())[usize::from(idx)] }
}

/// `&dns_requests[idx]`.
fn request(idx: u8) -> *mut DnsReqEntry {
    // SAFETY: as in `entry`.
    unsafe { &raw mut (*DNS_REQUESTS.as_ptr())[usize::from(idx)] }
}

/// `&dns_servers[idx]`.
fn server(idx: usize) -> *mut IpAddr {
    // SAFETY: as in `entry`.
    unsafe { &raw mut (*DNS_SERVERS.as_ptr())[idx] }
}

/// `&dns_pcbs[idx]`.
fn pcb_slot(idx: u8) -> *mut *mut UdpPcb {
    // SAFETY: as in `entry`.
    unsafe { &raw mut (*DNS_PCBS.as_ptr())[usize::from(idx)] }
}

/// `ip_addr_isany_val(dns_servers[idx])`.
fn server_is_any(idx: usize) -> bool {
    // SAFETY: the stack serializes access to its globals.
    unsafe { (*server(idx)).is_any() }
}

/// Initialize the resolver: set up the UDP pcb and configure the default server (if
/// DNS_SERVER_ADDRESS is set).
///
/// With random source ports, the PCBs are allocated per query, and ESP-IDF sets no
/// fallback server here: there is nothing to do but dns.c's sanity checks. Its records
/// are byte arrays of these sizes, so they hold by construction.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn dns_init() {
    lwip_assert!("sanity check SIZEOF_DNS_QUERY", SIZEOF_DNS_QUERY == 4);
    lwip_assert!(
        "sanity check SIZEOF_DNS_ANSWER",
        SIZEOF_DNS_ANSWER <= SIZEOF_DNS_ANSWER_ASSERT
    );
}

/// Initialize one of the DNS servers.
///
/// `numdns` is the index of the DNS server to set, which must be <
/// `DNS_MAX_SERVERS`, and `dnsserver` the IP address of the DNS server to set, or null
/// for any.
///
/// # Safety
///
/// `dnsserver` is null or valid.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn dns_setserver(numdns: u8, dnsserver: *const IpAddr) {
    if usize::from(numdns) < DNS_MAX_SERVERS {
        // SAFETY: as the caller guarantees; the server is in the table.
        unsafe {
            *server(usize::from(numdns)) = if dnsserver.is_null() {
                *ip_addr_any()
            } else {
                *dnsserver
            };
        }
    }
}

/// Remove all entries from the local host-list, calling their callbacks with a null
/// address.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn dns_clear_cache() {
    for i in 0..DNS_TABLE_SIZE as u8 {
        // SAFETY: an entry of the table; the stack serializes access to it.
        if unsafe { (*entry(i)).state } != DNS_STATE_UNUSED {
            // SAFETY: `i` is an index of the table.
            unsafe { dns_call_found(i, ptr::null_mut()) };
        }
    }
    // SAFETY: every field of an entry is valid zeroed.
    unsafe { ptr::write_bytes(DNS_TABLE.as_ptr(), 0, 1) };
}

/// Obtain one of the currently configured DNS server.
///
/// Returns the IP address of DNS server `numdns`, or `IP_ADDR_ANY` if the index is out
/// of range.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn dns_getserver(numdns: u8) -> *const IpAddr {
    if usize::from(numdns) < DNS_MAX_SERVERS {
        server(usize::from(numdns))
    } else {
        ip_addr_any()
    }
}

/// The on-demand timer's handler.
unsafe extern "C" fn dns_timeout_cb(_arg: *mut c_void) {
    dns_tmr();
}

/// The DNS resolver client timer - handle retries and timeouts and should be called
/// every `DNS_TMR_INTERVAL` milliseconds (every second by default).
///
/// ESP-IDF runs it only while an entry is in use: it re-arms itself until the table is
/// empty.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn dns_tmr() {
    // SAFETY: the stack's timer calls, serialized with the other entry points.
    unsafe {
        dns_check_entries();
        let tmr_restart = (0..DNS_TABLE_SIZE as u8).any(|i| (*entry(i)).state != DNS_STATE_UNUSED);
        if tmr_restart {
            sys_timeout(
                config::DNS_TMR_INTERVAL as u32,
                Some(dns_timeout_cb),
                ptr::null_mut(),
            );
        } else {
            sys_untimeout(Some(dns_timeout_cb), ptr::null_mut());
            S_IS_TMR_START.set(false);
        }
    }
}

/// Look up a hostname in the array of known hostnames.
///
/// `name` is the hostname to look for, `hostnamelen` its length, `addr` the buffer of
/// `addr_cnt` addresses the addresses found go to, and `dns_addrtype` the address type
/// wanted.
///
/// Returns `ERR_OK` if found, `ERR_ARG` if not found.
///
/// # Safety
///
/// `name` is readable for `hostnamelen` bytes or up to a NUL, and `addr` null or
/// writable for `addr_cnt` addresses.
unsafe fn dns_lookup(
    name: *const c_char,
    hostnamelen: usize,
    addr: *mut IpAddr,
    dns_addrtype: u8,
    addr_cnt: u8,
) -> ErrT {
    let namelen = hostnamelen.min(DNS_MAX_NAME_LENGTH - 1);
    let mut out_idx: u8 = 0;
    // Walk through name list, return entry if found. If not, return NULL.
    for i in 0..DNS_TABLE_SIZE as u8 {
        let e = entry(i);
        // SAFETY: as the caller guarantees; the entry is in the table.
        unsafe {
            if (*e).state == DNS_STATE_DONE
                && lwip_strnicmp(name, (&raw const (*e).name).cast(), namelen) == 0
                && (*e).name[namelen] == 0
            {
                for j in 0..usize::from((*e).ipaddr_cnt) {
                    if addrtype_match_ip(dns_addrtype, &(*e).ipaddr[j])
                        && !addr.is_null()
                        && out_idx < addr_cnt
                    {
                        (*addr.add(usize::from(out_idx))).copy_from(&(*e).ipaddr[j]);
                        out_idx += 1;
                    }
                }
                if out_idx != 0 {
                    return ERR_OK;
                }
            }
        }
    }
    ERR_ARG
}

/// Compare the "dotted" name "query" with the encoded name "response" to make sure an
/// answer from the DNS server matches the current dns_table entry (otherwise, answers
/// might arrive late for hostname not on the list any more).
///
/// For now, this function compares case-insensitive to cope with all kinds of servers.
/// This also means that "dns 0x20 bit encoding" must be checked externally, if
/// implemented. Returns the offset past the name, or 0xFFFF if it does not match.
///
/// # Safety
///
/// `query` is a NUL-terminated string and `p` a live pbuf chain.
unsafe fn dns_compare_name(mut query: *const c_char, p: *mut Pbuf, start_offset: u16) -> u16 {
    let mut response_offset = start_offset;
    // SAFETY: as the caller guarantees; `query` is read only up to its NUL.
    unsafe {
        loop {
            let mut n = pbuf_try_get_at(p, response_offset);
            if n < 0 || response_offset == 0xFFFF {
                // Error or overflow.
                return 0xFFFF;
            }
            response_offset += 1;
            // Check for a compressed name: the name is not compressed in the query.
            if n & 0xc0 == 0xc0 {
                // Compressed name: cannot be equal since we don't send them.
                return 0xFFFF;
            } else {
                // Not compressed name.
                while n > 0 {
                    let c = pbuf_try_get_at(p, response_offset);
                    if c < 0 {
                        return 0xFFFF;
                    }
                    if rivet_libc::tolower(c_int::from(*query as u8))
                        != rivet_libc::tolower(c_int::from(c as u8))
                    {
                        return 0xFFFF;
                    }
                    if response_offset == 0xFFFF {
                        // Would overflow.
                        return 0xFFFF;
                    }
                    response_offset += 1;
                    query = query.add(1);
                    n -= 1;
                }
                query = query.add(1);
            }
            n = pbuf_try_get_at(p, response_offset);
            if n < 0 {
                return 0xFFFF;
            }
            if n == 0 {
                break;
            }
        }
    }

    if response_offset == 0xFFFF {
        // Would overflow.
        return 0xFFFF;
    }
    response_offset + 1
}

/// Walk through a compact encoded DNS name and return the end of the name.
///
/// Returns the index to the query/answer after the name, or 0xFFFF on error.
///
/// # Safety
///
/// `p` is a live pbuf chain.
unsafe fn dns_skip_name(p: *mut Pbuf, query_idx: u16) -> u16 {
    let mut offset = query_idx;
    // SAFETY: as the caller guarantees.
    unsafe {
        loop {
            let mut n = pbuf_try_get_at(p, offset);
            offset = offset.wrapping_add(1);
            if n < 0 || offset == 0 {
                return 0xFFFF;
            }
            // Check for a compressed name.
            if n & 0xc0 == 0xc0 {
                // Compressed name: since we only want to skip it (not check it), stop
                // here.
                break;
            } else {
                // Not compressed name.
                if i32::from(offset) + n >= i32::from((*p).tot_len) {
                    return 0xFFFF;
                }
                offset = (i32::from(offset) + n) as u16;
            }
            n = pbuf_try_get_at(p, offset);
            if n < 0 {
                return 0xFFFF;
            }
            if n == 0 {
                break;
            }
        }
    }

    if offset == 0xFFFF {
        return 0xFFFF;
    }
    offset + 1
}

/// Send a DNS query packet.
///
/// Returns `ERR_OK` if packet is sent; an `err_t` indicating the problem otherwise.
///
/// # Safety
///
/// `idx` is an index of the table whose entry has a PCB.
unsafe fn dns_send(idx: u8) -> ErrT {
    let e = entry(idx);
    // SAFETY: an entry of the table; the stack serializes access to it.
    unsafe {
        lwip_assert!(
            "dns server out of array",
            usize::from((*e).server_idx) < DNS_MAX_SERVERS
        );

        if server_is_any(usize::from((*e).server_idx)) && (*e).is_mdns == 0 {
            // DNS server not valid anymore, e.g. PPP netif has been shut down.
            // Call specified callback function if provided.
            dns_call_found(idx, ptr::null_mut());
            // Flush this entry.
            (*e).state = DNS_STATE_UNUSED;
            return ERR_OK;
        }

        let name = (&raw const (*e).name).cast::<c_char>();
        // If here, we have either a new query or a retry on a previous query to process.
        let length = usize::from(SIZEOF_DNS_HDR)
            + rivet_libc::strlen(name)
            + 2
            + usize::from(SIZEOF_DNS_QUERY);
        let p = pbuf_alloc(
            config::PBUF_TRANSPORT_LAYER as PbufLayer,
            length as u16,
            PBUF_RAM,
        );
        if p.is_null() {
            return ERR_MEM;
        }

        // Fill dns header.
        let mut hdr = [0_u8; SIZEOF_DNS_HDR as usize];
        hdr[0..2].copy_from_slice(&(*e).txid.to_be_bytes());
        hdr[2] = DNS_FLAG1_RD;
        hdr[4..6].copy_from_slice(&1_u16.to_be_bytes());
        pbuf_take(p, hdr.as_ptr().cast(), SIZEOF_DNS_HDR);
        let mut hostname = name.sub(1);

        // Convert hostname into suitable query format.
        let mut query_idx = SIZEOF_DNS_HDR;
        loop {
            hostname = hostname.add(1);
            let hostname_part = hostname;
            let mut n: u8 = 0;
            while *hostname != b'.' as c_char && *hostname != 0 {
                n = n.wrapping_add(1);
                hostname = hostname.add(1);
            }
            let copy_len = hostname.offset_from(hostname_part) as u16;
            if u32::from(query_idx) + u32::from(n) + 1 > 0xFFFF {
                // u16_t overflow.
                pbuf_free(p);
                return ERR_VAL;
            }
            pbuf_put_at(p, query_idx, n);
            pbuf_take_at(p, hostname_part.cast(), copy_len, query_idx.wrapping_add(1));
            query_idx = query_idx.wrapping_add(u16::from(n) + 1);
            if *hostname == 0 {
                break;
            }
        }
        pbuf_put_at(p, query_idx, 0);
        query_idx = query_idx.wrapping_add(1);

        // Fill dns query.
        let qtype = if addrtype_is_ipv6((*e).reqaddrtype) {
            DNS_RRTYPE_AAAA
        } else {
            DNS_RRTYPE_A
        };
        let mut qry = [0_u8; SIZEOF_DNS_QUERY as usize];
        qry[0..2].copy_from_slice(&qtype.to_be_bytes());
        qry[2..4].copy_from_slice(&DNS_RRCLASS_IN.to_be_bytes());
        pbuf_take_at(p, qry.as_ptr().cast(), SIZEOF_DNS_QUERY, query_idx);

        let pcb_idx = (*e).pcb_idx;
        let (dst, dst_port): (*const IpAddr, u16) = if (*e).is_mdns != 0 {
            let group = if addrtype_is_ipv6((*e).reqaddrtype) {
                &dns_mquery_v6group
            } else {
                &dns_mquery_v4group
            };
            (group, DNS_MQUERY_PORT)
        } else {
            (server(usize::from((*e).server_idx)), DNS_SERVER_PORT)
        };
        let err = udp_sendto(*pcb_slot(pcb_idx), p, dst, dst_port);

        // Free pbuf.
        pbuf_free(p);
        err
    }
}

/// A UDP PCB bound to a random port of 1024 or above that `dns_recv` receives on, or
/// null if none can be made.
unsafe fn dns_alloc_random_port() -> *mut UdpPcb {
    // SAFETY: a fresh PCB, bound and given the receive callback, or removed.
    unsafe {
        let pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
        if pcb.is_null() {
            return ptr::null_mut();
        }
        let mut err;
        loop {
            let port = esp_random() as u16;
            err = if port >= 1024 {
                udp_bind(pcb, ip_addr_any_type(), port)
            } else {
                ERR_USE
            };
            if err != ERR_USE {
                break;
            }
        }
        if err != ERR_OK {
            udp_remove(pcb);
            return ptr::null_mut();
        }
        udp_recv(pcb, Some(dns_recv), ptr::null_mut());
        pcb
    }
}

/// dns_alloc_pcb() - allocates a new pcb (or reuses an existing one) to be used for
/// sending a request.
///
/// Returns an index into `dns_pcbs`, or `DNS_MAX_SOURCE_PORTS` if none is available.
unsafe fn dns_alloc_pcb() -> u8 {
    // SAFETY: the stack serializes access to its globals.
    unsafe {
        let free = (0..DNS_MAX_SOURCE_PORTS as u8).find(|&i| (*pcb_slot(i)).is_null());
        if let Some(i) = free {
            // Found an unused entry, allocate a new pcb.
            *pcb_slot(i) = dns_alloc_random_port();
            if !(*pcb_slot(i)).is_null() {
                // Succeeded.
                DNS_LAST_PCB_IDX.set(i);
                return i;
            }
        }
        // If we come here, creating a new UDP pcb failed, so we have to use an already
        // existing one (so overflow is no issue).
        let mut idx = DNS_LAST_PCB_IDX.get().wrapping_add(1);
        for _ in 0..DNS_MAX_SOURCE_PORTS {
            if usize::from(idx) >= DNS_MAX_SOURCE_PORTS {
                idx = 0;
            }
            if !(*pcb_slot(idx)).is_null() {
                DNS_LAST_PCB_IDX.set(idx);
                return idx;
            }
            idx = idx.wrapping_add(1);
        }
    }
    DNS_MAX_SOURCE_PORTS as u8
}

/// dns_call_found() - call the found callback and check if there are duplicate entries
/// for the given hostname. If there are any, their found callback will be called and
/// they will be removed.
///
/// # Safety
///
/// `idx` is an index of the table, and `addr` null or its entry's addresses.
unsafe fn dns_call_found(idx: u8, addr: *mut IpAddr) {
    let e = entry(idx);
    // SAFETY: an entry of the table; callbacks may re-enter the resolver, so its state is
    // read and written through the tables each time.
    unsafe {
        if !addr.is_null() {
            // Check that address type matches the request and adapt the table entry.
            if (*addr).is_v6() {
                lwip_assert!("invalid response", addrtype_is_ipv6((*e).reqaddrtype));
                (*e).reqaddrtype = LWIP_DNS_ADDRTYPE_IPV6;
            } else {
                lwip_assert!("invalid response", !addrtype_is_ipv6((*e).reqaddrtype));
                (*e).reqaddrtype = LWIP_DNS_ADDRTYPE_IPV4;
            }
        }

        for i in 0..DNS_MAX_REQUESTS as u8 {
            let r = request(i);
            if let Some(found) = (*r).found
                && (*r).dns_table_idx == idx
            {
                found((&raw const (*e).name).cast(), addr, (*r).arg);
                // Flush this entry.
                (*request(i)).found = None;
            }
        }

        // Close the pcb used unless other request are using it.
        for i in 0..DNS_TABLE_SIZE as u8 {
            if i == idx {
                continue; // Only check other requests.
            }
            if (*entry(i)).state == DNS_STATE_ASKING && (*entry(i)).pcb_idx == (*e).pcb_idx {
                // Another request is still using the same pcb.
                (*e).pcb_idx = DNS_MAX_SOURCE_PORTS as u8;
                break;
            }
        }
        if usize::from((*e).pcb_idx) < DNS_MAX_SOURCE_PORTS {
            // If we come here, the pcb is not used any more and can be removed.
            udp_remove(*pcb_slot((*e).pcb_idx));
            *pcb_slot((*e).pcb_idx) = ptr::null_mut();
            (*e).pcb_idx = DNS_MAX_SOURCE_PORTS as u8;
        }
    }
}

/// Create a query transmission ID that is unique for all outstanding queries.
unsafe fn dns_create_txid() -> u16 {
    'again: loop {
        // SAFETY: the port's random number generator.
        let txid = unsafe { esp_random() } as u16;

        // Check whether the ID is unique.
        for i in 0..DNS_TABLE_SIZE as u8 {
            // SAFETY: an entry of the table.
            let (state, entry_txid) = unsafe { ((*entry(i)).state, (*entry(i)).txid) };
            if state == DNS_STATE_ASKING && entry_txid == txid {
                // ID already used by another pending query.
                continue 'again;
            }
        }
        return txid;
    }
}

/// Check whether there are other backup DNS servers available to try.
///
/// # Safety
///
/// `pentry` is null or an entry of the table.
unsafe fn dns_backupserver_available(pentry: *const DnsTableEntry) -> bool {
    // SAFETY: as the caller guarantees.
    unsafe {
        !pentry.is_null() && {
            let next = usize::from((*pentry).server_idx) + 1;
            next < DNS_MAX_SERVERS && !server_is_any(next)
        }
    }
}

/// dns_check_entry() - see if entry has not yet been queried and, if so, sends out a
/// query. Check an entry in the dns_table:
/// - send out query for new entries
/// - retry old pending entries on timeout (also with different servers)
/// - remove completed entries from the table if their TTL has expired
///
/// # Safety
///
/// `idx` is an index of the table.
unsafe fn dns_check_entry(idx: u8) {
    lwip_assert!(
        "array index out of bounds",
        usize::from(idx) < DNS_TABLE_SIZE
    );
    let e = entry(idx);
    // SAFETY: an entry of the table.
    unsafe {
        match (*e).state {
            DNS_STATE_NEW => {
                // Initialize new entry.
                (*e).txid = dns_create_txid();
                (*e).state = DNS_STATE_ASKING;
                (*e).server_idx = 0;
                (*e).tmr = 1;
                (*e).retries = 0;
                while usize::from((*e).server_idx) + 1 < DNS_MAX_SERVERS
                    && server_is_any(usize::from((*e).server_idx))
                {
                    (*e).server_idx += 1;
                }
                // Send DNS packet for this entry.
                let _ = dns_send(idx);
            }
            DNS_STATE_ASKING => {
                (*e).tmr = (*e).tmr.wrapping_sub(1);
                if (*e).tmr == 0 {
                    (*e).retries = (*e).retries.wrapping_add(1);
                    if (*e).retries == DNS_MAX_RETRIES {
                        // Skip DNS servers with zero address.
                        while usize::from((*e).server_idx) + 1 < DNS_MAX_SERVERS
                            && server_is_any(usize::from((*e).server_idx) + 1)
                        {
                            (*e).server_idx += 1;
                        }
                        if dns_backupserver_available(e) && (*e).is_mdns == 0 {
                            // Change of server.
                            (*e).server_idx += 1;
                            (*e).tmr = 1;
                            (*e).retries = 0;
                        } else {
                            // Call specified callback function if provided.
                            dns_call_found(idx, ptr::null_mut());
                            // Flush this entry.
                            (*e).state = DNS_STATE_UNUSED;
                            return;
                        }
                    } else {
                        // Wait longer for the next retry.
                        (*e).tmr = (*e).retries;
                    }

                    // Send DNS packet for this entry.
                    let _ = dns_send(idx);
                }
            }
            DNS_STATE_DONE => {
                let initial_ipaddr_cnt = usize::from((*e).ipaddr_cnt);
                for i in 0..initial_ipaddr_cnt {
                    // If the time to live is nul.
                    let expired = (*e).ttl[i] == 0 || {
                        (*e).ttl[i] -= 1;
                        (*e).ttl[i] == 0
                    };
                    if expired {
                        (*e).ipaddr[i] = IpAddr::v4(0);
                        (*e).ipaddr_cnt -= 1;
                    }
                }
                if (*e).ipaddr_cnt == 0 {
                    // Flush this entry, there cannot be any related pending entries in
                    // this state.
                    (*e).state = DNS_STATE_UNUSED;
                }
            }
            DNS_STATE_UNUSED => {
                // Nothing to do.
            }
            _ => {
                lwip_assert!("unknown dns_table entry state:", false);
            }
        }
    }
}

/// Call dns_check_entry for each entry in dns_table - check all entries.
unsafe fn dns_check_entries() {
    for i in 0..DNS_TABLE_SIZE as u8 {
        // SAFETY: an index of the table.
        unsafe { dns_check_entry(i) };
    }
}

/// Save TTL and call dns_call_found for correct response.
///
/// # Safety
///
/// `idx` is an index of the table.
unsafe fn dns_correct_response(idx: u8) {
    let e = entry(idx);
    // SAFETY: an entry of the table.
    unsafe {
        // Change the state of the entry.
        (*e).state = DNS_STATE_DONE;

        dns_call_found(idx, (&raw mut (*e).ipaddr).cast());

        let initial_ipaddr_cnt = usize::from((*e).ipaddr_cnt);
        for i in 0..initial_ipaddr_cnt {
            if (*e).ttl[i] == 0 {
                // RFC 883, page 29: "Zero values are interpreted to mean that the RR can
                // only be used for the transaction in progress, and should not be
                // cached." -> flush this entry now.
                (*e).ipaddr[i] = IpAddr::v4(0);
                (*e).ipaddr_cnt -= 1;
            }
        }
        if (*e).ipaddr_cnt == 0 && (*e).state == DNS_STATE_DONE {
            // Flush this entry.
            (*e).state = DNS_STATE_UNUSED;
        }
    }
}

/// Receive input function for DNS response packets arriving for the dns UDP pcb.
unsafe extern "C" fn dns_recv(
    _arg: *mut c_void,
    _pcb: *mut UdpPcb,
    p: *mut Pbuf,
    addr: *const IpAddr,
    _port: u16,
) {
    // SAFETY: udp.c hands the callback a live pbuf it gives up and the sender's address.
    unsafe {
        if !dns_recv_response(p, addr) {
            // Deallocate memory and return.
            pbuf_free(p);
        }
    }
}

/// `dns_recv` up to its `ignore_packet` label: handles a response to a query in the
/// table, freeing `p`, and returns true; returns false to ignore the packet.
///
/// # Safety
///
/// `p` is a live pbuf chain the resolver owns and `addr` valid.
unsafe fn dns_recv_response(p: *mut Pbuf, addr: *const IpAddr) -> bool {
    // SAFETY: as the caller guarantees; entries are in the table.
    unsafe {
        // Is the dns message big enough?
        if (*p).tot_len < SIZEOF_DNS_HDR + SIZEOF_DNS_QUERY {
            // Free pbuf and return.
            return false;
        }

        // Copy dns payload inside static buffer for processing.
        let mut hdr = [0_u8; SIZEOF_DNS_HDR as usize];
        if pbuf_copy_partial(p, hdr.as_mut_ptr().cast(), SIZEOF_DNS_HDR, 0) != SIZEOF_DNS_HDR {
            return false;
        }
        // Match the ID in the DNS header with the name table.
        let txid = u16::from_be_bytes([hdr[0], hdr[1]]);
        let (flags1, flags2) = (hdr[2], hdr[3]);
        for i in 0..DNS_TABLE_SIZE as u8 {
            let e = entry(i);
            if (*e).state != DNS_STATE_ASKING || (*e).txid != txid {
                continue;
            }
            // We only care about the question(s) and the answers. The authrr and the
            // extrarr are simply discarded.
            let nquestions = u16::from_be_bytes([hdr[4], hdr[5]]);
            let mut nanswers = u16::from_be_bytes([hdr[6], hdr[7]]);

            // Check for correct response.
            if flags1 & DNS_FLAG1_RESPONSE == 0 {
                return false;
            }
            if nquestions != 1 {
                return false;
            }

            if (*e).is_mdns == 0 {
                // Check whether response comes from the same network address to which
                // the question was sent. (RFC 5452)
                if !(*addr).eq_addr(&*server(usize::from((*e).server_idx))) {
                    return false;
                }
            }

            // Check if the name in the "question" part match with the name in the
            // entry and skip it if equal.
            let mut res_idx = dns_compare_name((&raw const (*e).name).cast(), p, SIZEOF_DNS_HDR);
            if res_idx == 0xFFFF {
                return false;
            }

            // Check if "question" part matches the request.
            let mut qry = [0_u8; SIZEOF_DNS_QUERY as usize];
            if pbuf_copy_partial(p, qry.as_mut_ptr().cast(), SIZEOF_DNS_QUERY, res_idx)
                != SIZEOF_DNS_QUERY
            {
                return false;
            }
            let qtype = u16::from_be_bytes([qry[0], qry[1]]);
            let qcls = u16::from_be_bytes([qry[2], qry[3]]);
            if qcls != DNS_RRCLASS_IN
                || (addrtype_is_ipv6((*e).reqaddrtype) && qtype != DNS_RRTYPE_AAAA)
                || (!addrtype_is_ipv6((*e).reqaddrtype) && qtype != DNS_RRTYPE_A)
            {
                return false;
            }
            // Skip the rest of the "question" part.
            if u32::from(res_idx) + u32::from(SIZEOF_DNS_QUERY) > 0xFFFF {
                return false;
            }
            res_idx += SIZEOF_DNS_QUERY;

            // Check for error. If so, call callback to inform.
            if flags2 & DNS_FLAG2_ERR_MASK != 0 {
                if dns_backupserver_available(e) {
                    // Try the next server.
                    (*e).retries = DNS_MAX_RETRIES - 1;
                    (*e).tmr = 1;
                    dns_check_entry(i);
                    return false;
                }
            } else {
                let initial_ipaddr_cnt = (*e).ipaddr_cnt;
                while nanswers > 0 && res_idx < (*p).tot_len {
                    // Skip answer resource record's host name.
                    res_idx = dns_skip_name(p, res_idx);
                    if res_idx == 0xFFFF {
                        return false;
                    }

                    // Check for IP address type and Internet class. Others are discarded.
                    let mut ans = [0_u8; SIZEOF_DNS_ANSWER as usize];
                    if pbuf_copy_partial(p, ans.as_mut_ptr().cast(), SIZEOF_DNS_ANSWER, res_idx)
                        != SIZEOF_DNS_ANSWER
                    {
                        return false;
                    }
                    if u32::from(res_idx) + u32::from(SIZEOF_DNS_ANSWER) > 0xFFFF {
                        return false;
                    }
                    res_idx += SIZEOF_DNS_ANSWER;
                    let atype = u16::from_be_bytes([ans[0], ans[1]]);
                    let acls = u16::from_be_bytes([ans[2], ans[3]]);
                    let attl = u32::from_be_bytes([ans[4], ans[5], ans[6], ans[7]]);
                    let alen = u16::from_be_bytes([ans[8], ans[9]]);

                    if acls == DNS_RRCLASS_IN && usize::from((*e).ipaddr_cnt) < DNS_MAX_HOST_IP {
                        if atype == DNS_RRTYPE_A
                            && usize::from(alen) == size_of::<Ip4Addr>()
                            && !addrtype_is_ipv6((*e).reqaddrtype)
                        {
                            let mut ip4addr = [0_u8; 4];
                            // Read the IP address after answer resource record's header.
                            if pbuf_copy_partial(p, ip4addr.as_mut_ptr().cast(), 4, res_idx) != 4 {
                                return false;
                            }
                            let n = usize::from((*e).ipaddr_cnt);
                            (*e).ipaddr[n].copy_from_ip4(u32::from_ne_bytes(ip4addr));
                            (*e).ttl[n] = attl.min(DNS_MAX_TTL);
                            (*e).ipaddr_cnt += 1;
                        }
                        if atype == DNS_RRTYPE_AAAA
                            && usize::from(alen) == 16
                            && addrtype_is_ipv6((*e).reqaddrtype)
                        {
                            let mut ip6addr = [0_u8; 16];
                            // Read the IP address after answer resource record's header.
                            if pbuf_copy_partial(p, ip6addr.as_mut_ptr().cast(), 16, res_idx) != 16
                            {
                                return false;
                            }
                            let (words, _) = ip6addr.as_chunks::<4>();
                            let n = usize::from((*e).ipaddr_cnt);
                            (*e).ipaddr[n].copy_from_ip6(&Ip6Addr {
                                addr: [
                                    u32::from_ne_bytes(words[0]),
                                    u32::from_ne_bytes(words[1]),
                                    u32::from_ne_bytes(words[2]),
                                    u32::from_ne_bytes(words[3]),
                                ],
                                #[cfg(lwip_ipv6_scopes)]
                                zone: 0,
                            });
                            (*e).ttl[n] = attl.min(DNS_MAX_TTL);
                            (*e).ipaddr_cnt += 1;
                        }
                    }
                    // Skip this answer.
                    if u32::from(res_idx) + u32::from(alen) > 0xFFFF {
                        return false;
                    }
                    res_idx += alen;
                    nanswers -= 1;
                }
                if initial_ipaddr_cnt < (*e).ipaddr_cnt {
                    // At least one address was found.
                    pbuf_free(p);
                    dns_correct_response(i);
                    return true;
                }
                if (*e).reqaddrtype == LWIP_DNS_ADDRTYPE_IPV4_IPV6
                    || (*e).reqaddrtype == LWIP_DNS_ADDRTYPE_IPV6_IPV4
                {
                    // IPv4 failed, try IPv6, or IPv6 failed, try IPv4.
                    (*e).reqaddrtype = if (*e).reqaddrtype == LWIP_DNS_ADDRTYPE_IPV4_IPV6 {
                        LWIP_DNS_ADDRTYPE_IPV6
                    } else {
                        LWIP_DNS_ADDRTYPE_IPV4
                    };
                    pbuf_free(p);
                    (*e).state = DNS_STATE_NEW;
                    dns_check_entry(i);
                    return true;
                }
            }
            // Call callback to indicate error, clean up memory and return.
            pbuf_free(p);
            dns_call_found(i, ptr::null_mut());
            (*e).state = DNS_STATE_UNUSED;
            (*e).ipaddr_cnt = 0;
            return true;
        }
    }
    false
}

/// Queues a new hostname to resolve and sends out a DNS query for that hostname.
///
/// Returns `ERR_INPROGRESS` if the query was queued, `ERR_MEM` if the table or the
/// requests are full.
///
/// # Safety
///
/// `name` is readable for `hostnamelen` bytes.
unsafe fn dns_enqueue(
    name: *const c_char,
    hostnamelen: usize,
    found: DnsFoundCallback,
    callback_arg: *mut c_void,
    dns_addrtype: u8,
    is_mdns: u8,
) -> ErrT {
    let namelen = hostnamelen.min(DNS_MAX_NAME_LENGTH - 1);
    // SAFETY: as the caller guarantees; entries and requests are in their tables.
    unsafe {
        // Check for duplicate entries.
        for i in 0..DNS_TABLE_SIZE as u8 {
            let e = entry(i);
            if (*e).state == DNS_STATE_ASKING
                && lwip_strnicmp(name, (&raw const (*e).name).cast(), namelen) == 0
                && (*e).name[namelen] == 0
            {
                if (*e).reqaddrtype != dns_addrtype {
                    // Requested address types don't match; this can lead to 2 concurrent
                    // requests, but mixing the address types for the same host should
                    // not be that common.
                    continue;
                }
                // This is a duplicate entry, find a free request entry.
                for r in 0..DNS_MAX_REQUESTS as u8 {
                    let req = request(r);
                    if (*req).found.is_none() {
                        (*req).found = found;
                        (*req).arg = callback_arg;
                        (*req).dns_table_idx = i;
                        (*req).reqaddrtype = dns_addrtype;
                        return ERR_INPROGRESS;
                    }
                }
            }
        }
        // No duplicate entries found.

        // Search an unused entry, or the oldest one.
        let mut lseq: u8 = 0;
        let mut lseqi = DNS_TABLE_SIZE as u8;
        let mut i = 0;
        while usize::from(i) < DNS_TABLE_SIZE {
            let e = entry(i);
            // Is it an unused entry?
            if (*e).state == DNS_STATE_UNUSED {
                break;
            }
            // Check if this is the oldest completed entry.
            if (*e).state == DNS_STATE_DONE {
                let age = DNS_SEQNO.get().wrapping_sub((*e).seqno);
                if age > lseq {
                    lseq = age;
                    lseqi = i;
                }
            }
            i += 1;
        }

        // If we don't have found an unused entry, use the oldest completed one.
        if usize::from(i) == DNS_TABLE_SIZE {
            if usize::from(lseqi) >= DNS_TABLE_SIZE || (*entry(lseqi)).state != DNS_STATE_DONE {
                // No entry can be used now, table is full.
                return ERR_MEM;
            }
            // Use the oldest completed one.
            i = lseqi;
        }
        let e = entry(i);

        // Find a free request entry.
        let Some(r) = (0..DNS_MAX_REQUESTS as u8).find(|&r| (*request(r)).found.is_none()) else {
            // No request entry can be used now, table is full.
            return ERR_MEM;
        };
        let req = request(r);
        (*req).dns_table_idx = i;

        // Use this entry.
        // Fill the entry.
        (*e).state = DNS_STATE_NEW;
        (*e).seqno = DNS_SEQNO.get();
        (*e).ipaddr_cnt = 0;
        for j in 0..DNS_MAX_HOST_IP {
            (*e).ipaddr[j] = IpAddr::v4(0);
        }
        (*e).reqaddrtype = dns_addrtype;
        (*req).reqaddrtype = dns_addrtype;
        (*req).found = found;
        (*req).arg = callback_arg;
        ptr::copy(name, (&raw mut (*e).name).cast::<c_char>(), namelen);
        (*e).name[namelen] = 0;

        (*e).pcb_idx = dns_alloc_pcb();
        if usize::from((*e).pcb_idx) >= DNS_MAX_SOURCE_PORTS {
            // Failed to get a UDP pcb.
            (*e).state = DNS_STATE_UNUSED;
            (*e).ipaddr_cnt = 0;
            (*req).found = None;
            return ERR_MEM;
        }

        (*e).is_mdns = is_mdns;

        DNS_SEQNO.set(DNS_SEQNO.get().wrapping_add(1));

        // Force to send query without waiting timer.
        dns_check_entry(i);

        if !S_IS_TMR_START.get() {
            sys_timeout(
                config::DNS_TMR_INTERVAL as u32,
                Some(dns_timeout_cb),
                ptr::null_mut(),
            );
            S_IS_TMR_START.set(true);
        }
    }

    // DNS query in progress.
    ERR_INPROGRESS
}

/// Resolve a hostname (string) into an IP address. NON-BLOCKING callback version for
/// use with raw API!!!
///
/// Returns immediately with one of the `err_t` return codes:
/// - `ERR_OK` if hostname is a valid IP address string or the host name is already in
///   the local names table.
/// - `ERR_INPROGRESS` enqueue a request to be sent to the DNS server for resolution if
///   no errors are present.
/// - `ERR_ARG`: dns client not initialized or invalid hostname
///
/// `hostname` is the hostname that is to be queried, `addr` a pointer to a `ip_addr_t`
/// where to store the address if it is already cached in the dns_table (only valid if
/// `ERR_OK` is returned!), `found` a callback function to be called on success,
/// failure or timeout (only if `ERR_INPROGRESS` is returned!), and `callback_arg`
/// argument to pass to the callback function.
///
/// # Safety
///
/// `hostname` is null or a C string, and `addr` null or writable.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn dns_gethostbyname(
    hostname: *const c_char,
    addr: *mut IpAddr,
    found: DnsFoundCallback,
    callback_arg: *mut c_void,
) -> ErrT {
    // SAFETY: forwarded from the caller.
    unsafe {
        dns_gethostbyname_addrtype(
            hostname,
            addr,
            found,
            callback_arg,
            config::LWIP_DNS_ADDRTYPE_DEFAULT as u8,
        )
    }
}

/// ESP-IDF: whether any DNS server is set.
fn dns_server_is_set() -> bool {
    (0..DNS_MAX_SERVERS).any(|i| !server_is_any(i))
}

/// Like `dns_gethostbyname`, but returned address type can be controlled.
///
/// `dns_addrtype` is `LWIP_DNS_ADDRTYPE_IPV4_IPV6` (0) try to resolve IPv4 first, try
/// IPv6 if IPv4 fails only; `LWIP_DNS_ADDRTYPE_IPV6_IPV4` (1) try to resolve IPv6
/// first, try IPv4 if IPv6 fails only; `LWIP_DNS_ADDRTYPE_IPV4` (2) try to resolve
/// IPv4 only; `LWIP_DNS_ADDRTYPE_IPV6` (3) try to resolve IPv6 only.
///
/// # Safety
///
/// As `dns_gethostbyname`.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn dns_gethostbyname_addrtype(
    hostname: *const c_char,
    addr: *mut IpAddr,
    found: DnsFoundCallback,
    callback_arg: *mut c_void,
    dns_addrtype: u8,
) -> ErrT {
    // SAFETY: forwarded from the caller; one address.
    unsafe { dns_gethostbyname_addrtype_n(hostname, addr, 1, found, callback_arg, dns_addrtype) }
}

/// Like `dns_gethostbyname_addrtype`, for up to `addr_cnt` addresses.
///
/// `addr_cnt` is the number of addresses requested; must be > 0 and <=
/// `DNS_MAX_HOST_IP`. Returns `ERR_ARG` if `addr_cnt` is 0 or greater than
/// `DNS_MAX_HOST_IP` (among other invalid parameters).
///
/// # Safety
///
/// `hostname` is null or a C string, and `addr` null or writable for `addr_cnt`
/// addresses.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn dns_gethostbyname_addrtype_n(
    hostname: *const c_char,
    addr: *mut IpAddr,
    addr_cnt: u8,
    found: DnsFoundCallback,
    callback_arg: *mut c_void,
    dns_addrtype: u8,
) -> ErrT {
    // Not initialized or no valid server yet, or invalid addr pointer or invalid
    // hostname or invalid hostname length.
    // SAFETY: as the caller guarantees.
    unsafe {
        if addr.is_null() || hostname.is_null() || *hostname == 0 {
            return ERR_ARG;
        }
        if addr_cnt == 0 || usize::from(addr_cnt) > DNS_MAX_HOST_IP {
            return ERR_ARG;
        }
        let mut hostnamelen = rivet_libc::strlen(hostname);
        if *hostname.add(hostnamelen - 1) == b'.' as c_char {
            hostnamelen -= 1;
        }
        if hostnamelen >= DNS_MAX_NAME_LENGTH {
            return ERR_ARG;
        }

        if rivet_libc::strcmp(hostname, c"localhost".as_ptr()) == 0 {
            if addrtype_is_ipv6(dns_addrtype) {
                (*addr).copy_from_ip6(&Ip6Addr {
                    addr: [0, 0, 0, 1_u32.to_be()],
                    #[cfg(lwip_ipv6_scopes)]
                    zone: 0,
                });
            } else {
                (*addr).copy_from_ip4(0x7f00_0001_u32.to_be());
            }
            return ERR_OK;
        }

        // Host name already in octet notation? Set ip addr and return ERR_OK.
        if ipaddr_aton(hostname, addr) != 0
            && (((*addr).is_v6() && dns_addrtype != LWIP_DNS_ADDRTYPE_IPV4)
                || ((*addr).type_ == IPADDR_TYPE_V4 && dns_addrtype != LWIP_DNS_ADDRTYPE_IPV6))
        {
            return ERR_OK;
        }
        // Already have this address cached?
        if dns_lookup(hostname, hostnamelen, addr, dns_addrtype, addr_cnt) == ERR_OK {
            return ERR_OK;
        }
        if dns_addrtype == LWIP_DNS_ADDRTYPE_IPV4_IPV6
            || dns_addrtype == LWIP_DNS_ADDRTYPE_IPV6_IPV4
        {
            // Fallback to 2nd IP type and try again to lookup.
            let fallback = if dns_addrtype == LWIP_DNS_ADDRTYPE_IPV4_IPV6 {
                LWIP_DNS_ADDRTYPE_IPV6
            } else {
                LWIP_DNS_ADDRTYPE_IPV4
            };
            if dns_lookup(hostname, hostnamelen, addr, fallback, addr_cnt) == ERR_OK {
                return ERR_OK;
            }
        }

        let local = rivet_libc::strstr(hostname, c".local".as_ptr());
        let is_mdns =
            u8::from(local.cast_const() == hostname.wrapping_add(hostnamelen).wrapping_sub(6));

        if is_mdns == 0 && !dns_server_is_set() {
            // Prevent calling found callback if no server is set, return error instead.
            return ERR_VAL;
        }

        // Queue query with specified callback.
        dns_enqueue(
            hostname,
            hostnamelen,
            found,
            callback_arg,
            dns_addrtype,
            is_mdns,
        )
    }
}

#[cfg(test)]
mod tests;
