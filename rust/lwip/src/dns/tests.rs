// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! test/unit/core/test_dns.c, and beyond it the resolver against a scripted server on
//! the IPv4 test netif: queries on the wire, answers, the cache and its TTL, retries,
//! server fallback, the IPv4-then-IPv6 fallback, mDNS, and the input checks.

extern crate std;

use core::ffi::CStr;
use core::sync::atomic::Ordering::Relaxed;
use std::string::String;
use std::sync::Mutex;
use std::vec::Vec;

use super::*;
use crate::ip4::ip4_input;
use crate::ip4::tests::{
    LINKOUTPUT_CTR, LINKOUTPUT_PKT, TEST_IPADDR, arpless_output, ip_header, ip4, packet,
    with_test_netif,
};
use crate::test_support::{clear_timeouts, timeouts};

const SERVER: Ip4Addr = ip4(192, 168, 0, 2);
const BACKUP: Ip4Addr = ip4(192, 168, 0, 3);
const EXAMPLE: Ip4Addr = ip4(93, 184, 215, 14);

/// An address as its type, the words of the union, and the zone: comparable and
/// printable.
type Key = (u8, [u32; 4], u8);

fn key(addr: &IpAddr) -> Key {
    (addr.type_, addr.ip6().addr, addr.ip6().zone)
}

/// What the found callback was called with: the name, and the address if any.
static FOUND: Mutex<Vec<(String, Option<Key>)>> = Mutex::new(Vec::new());

unsafe extern "C" fn record_found(name: *const c_char, ipaddr: *const IpAddr, _arg: *mut c_void) {
    // SAFETY: the resolver passes its entry's name and null or its address.
    let (name, ipaddr) = unsafe {
        (
            CStr::from_ptr(name).to_str().unwrap().into(),
            ipaddr.as_ref().map(key),
        )
    };
    FOUND.lock().unwrap().push((name, ipaddr));
}

fn found() -> Vec<(String, Option<Key>)> {
    core::mem::take(&mut *FOUND.lock().unwrap())
}

/// The resolver back to its state at boot: no servers, entries, requests, or timer.
fn reset() {
    dns_clear_cache();
    for i in 0..DNS_MAX_SERVERS as u8 {
        // SAFETY: null sets any.
        unsafe { dns_setserver(i, ptr::null()) };
    }
    for i in 0..DNS_MAX_SOURCE_PORTS as u8 {
        // SAFETY: a slot of the table; its PCB came from udp_new.
        unsafe {
            if !(*pcb_slot(i)).is_null() {
                crate::udp::udp_remove(*pcb_slot(i));
                *pcb_slot(i) = ptr::null_mut();
            }
        }
    }
    // SAFETY: every field of a request is valid zeroed.
    unsafe { ptr::write_bytes(DNS_REQUESTS.as_ptr(), 0, 1) };
    S_IS_TMR_START.set(false);
    clear_timeouts();
    found();
}

/// Fire the resolver's timer as its timeout expiring would: the pending timeout goes,
/// then the timer runs.
fn tick() {
    // SAFETY: the resolver's own timeout, with its null argument.
    unsafe {
        sys_untimeout(Some(dns_timeout_cb), ptr::null_mut());
        dns_timeout_cb(ptr::null_mut());
    }
}

/// The resolver with `SERVER` set, on the test netif, which sends straight to its driver.
fn with_resolver(test: impl FnOnce(*mut Netif)) {
    with_test_netif(|netif| {
        reset();
        // SAFETY: a live netif; a valid address.
        unsafe {
            (*netif).output = Some(arpless_output);
            dns_setserver(0, &IpAddr::v4(SERVER.addr));
        }
        test(netif);
        reset();
        assert!(
            crate::udp::udp_pcbs.get().is_null(),
            "the resolver's PCBs are removed"
        );
    });
}

/// `dns_gethostbyname_addrtype` with the recording callback.
fn resolve(name: &CStr, addr: &mut IpAddr, addrtype: u8) -> ErrT {
    // SAFETY: a C string and an address to fill.
    unsafe {
        dns_gethostbyname_addrtype(
            name.as_ptr(),
            addr,
            Some(record_found),
            ptr::null_mut(),
            addrtype,
        )
    }
}

/// A query the resolver sent: destination, source port, and DNS message.
struct Query {
    dest: [u8; 4],
    dest_port: u16,
    src_port: u16,
    txid: u16,
    name: Vec<u8>,
    qtype: u16,
}

/// The last packet sent, as a DNS query.
fn last_query() -> Query {
    let pkt = LINKOUTPUT_PKT.lock().unwrap().clone();
    assert_eq!(pkt[9], IP_PROTO_UDP);
    let udp = &pkt[20..];
    let dns = &udp[8..];
    assert_eq!(dns[2] & DNS_FLAG1_RD, DNS_FLAG1_RD, "recursion desired");
    assert_eq!(u16::from_be_bytes([dns[4], dns[5]]), 1, "one question");
    assert_eq!(dns[6..12], [0; 6]);
    let end = 12 + dns[12..].iter().position(|&b| b == 0).unwrap() + 1;
    let question = &dns[end..end + 4];
    assert_eq!(
        u16::from_be_bytes([question[2], question[3]]),
        DNS_RRCLASS_IN
    );
    Query {
        dest: pkt[16..20].try_into().unwrap(),
        dest_port: u16::from_be_bytes([udp[2], udp[3]]),
        src_port: u16::from_be_bytes([udp[0], udp[1]]),
        txid: u16::from_be_bytes([dns[0], dns[1]]),
        name: dns[12..end].to_vec(),
        qtype: u16::from_be_bytes([question[0], question[1]]),
    }
}

/// A response to `query` from `from` with rcode `rcode` and `answers` (type, TTL, and
/// data), each named by a pointer to the question's name.
fn respond(
    netif: *mut Netif,
    from: Ip4Addr,
    query: &Query,
    rcode: u8,
    answers: &[(u16, u32, &[u8])],
) {
    let mut dns = Vec::new();
    dns.extend(query.txid.to_be_bytes());
    dns.extend([DNS_FLAG1_RESPONSE | DNS_FLAG1_RD, 0x80 | rcode]);
    dns.extend(1_u16.to_be_bytes());
    dns.extend((answers.len() as u16).to_be_bytes());
    dns.extend([0, 0, 0, 0]);
    dns.extend(&query.name);
    dns.extend(query.qtype.to_be_bytes());
    dns.extend(DNS_RRCLASS_IN.to_be_bytes());
    for &(rrtype, ttl, data) in answers {
        dns.extend([0xc0, 12]);
        dns.extend(rrtype.to_be_bytes());
        dns.extend(DNS_RRCLASS_IN.to_be_bytes());
        dns.extend(ttl.to_be_bytes());
        dns.extend((data.len() as u16).to_be_bytes());
        dns.extend(data);
    }
    let len = UDP_HLEN + dns.len() as u16;
    let mut bytes = ip_header(from, TEST_IPADDR, IP_PROTO_UDP, len, 0);
    bytes.extend(query.dest_port.to_be_bytes());
    bytes.extend(query.src_port.to_be_bytes());
    bytes.extend(len.to_be_bytes());
    bytes.extend([0, 0]);
    bytes.extend(dns);
    // SAFETY: a live netif; the packet is given up.
    unsafe { ip4_input(packet(&bytes), netif) };
}

/// The encoded form of `name`.
fn encoded(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend(label.as_bytes());
    }
    out.push(0);
    out
}

fn v4(addr: Ip4Addr) -> IpAddr {
    IpAddr::v4(addr.addr)
}

fn same(a: &IpAddr, b: &IpAddr) -> bool {
    a.eq_addr(b)
}

/// test_dns.c: test_dns_set_get_server.
#[test]
fn test_dns_set_get_server() {
    let _serial = crate::test_support::serial();
    reset();
    for n in 0..256 {
        let i = n as u8;
        // SAFETY: a valid address; dns_getserver returns one.
        unsafe {
            // Should return a zeroed address for any index.
            assert!(!dns_getserver(i).is_null());
            assert!((*dns_getserver(i)).is_any());

            // Should accept setting address for any index, and ignore if out of range.
            let server = IpAddr::v4(ip4(10, 0, 0, i).addr);
            dns_setserver(i, &server);
            assert!(!dns_getserver(i).is_null());
            if usize::from(i) < DNS_MAX_SERVERS {
                assert!(same(&*dns_getserver(i), &server));
            } else {
                assert!((*dns_getserver(i)).is_any());
            }
        }
    }
    reset();
}

#[test]
fn a_query_goes_out_and_its_answer_is_reported_and_cached() {
    with_resolver(|netif| {
        let mut addr = IpAddr::v4(0);
        let sent = LINKOUTPUT_CTR.load(Relaxed);
        assert_eq!(
            resolve(c"Example.com.", &mut addr, LWIP_DNS_ADDRTYPE_IPV4_IPV6),
            ERR_INPROGRESS
        );
        assert_eq!(
            LINKOUTPUT_CTR.load(Relaxed),
            sent + 1,
            "sent without waiting for the timer"
        );
        let query = last_query();
        assert_eq!(query.dest, SERVER.addr.to_ne_bytes());
        assert_eq!(query.dest_port, DNS_SERVER_PORT);
        assert!(query.src_port >= 1024, "a random source port");
        assert_eq!(
            query.name,
            encoded("Example.com"),
            "without the trailing dot"
        );
        assert_eq!(query.qtype, DNS_RRTYPE_A, "IPv4 first");
        assert!(found().is_empty());
        // The on-demand timer runs while the query is pending.
        assert_eq!(timeouts().len(), 1);

        respond(
            netif,
            SERVER,
            &query,
            0,
            &[(DNS_RRTYPE_A, 300, &EXAMPLE.addr.to_ne_bytes())],
        );
        assert_eq!(found(), [("Example.com".into(), Some(key(&v4(EXAMPLE))))]);

        // Cached, in any letter case: answered at once and not asked again.
        let mut cached = IpAddr::v4(0);
        assert_eq!(
            resolve(c"example.COM", &mut cached, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_OK
        );
        assert!(same(&cached, &v4(EXAMPLE)));
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), sent + 1);
        // But not for another address type.
        assert_eq!(
            resolve(c"example.com", &mut cached, LWIP_DNS_ADDRTYPE_IPV6),
            ERR_INPROGRESS
        );
    });
}

#[test]
fn an_answer_lives_for_its_ttl() {
    with_resolver(|netif| {
        let mut addr = IpAddr::v4(0);
        assert_eq!(
            resolve(c"short.example", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_INPROGRESS
        );
        respond(
            netif,
            SERVER,
            &last_query(),
            0,
            &[(DNS_RRTYPE_A, 2, &EXAMPLE.addr.to_ne_bytes())],
        );
        assert_eq!(found().len(), 1);
        tick();
        assert_eq!(
            resolve(c"short.example", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_OK
        );
        tick();
        // Expired: the timer stopped with the table empty, and the name is asked again.
        assert!(timeouts().is_empty());
        assert!(!S_IS_TMR_START.get());
        assert_eq!(
            resolve(c"short.example", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_INPROGRESS
        );

        // A TTL of 0 is reported but not cached.
        respond(
            netif,
            SERVER,
            &last_query(),
            0,
            &[(DNS_RRTYPE_A, 0, &EXAMPLE.addr.to_ne_bytes())],
        );
        assert_eq!(found().len(), 1);
        assert_eq!(
            resolve(c"short.example", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_INPROGRESS
        );
    });
}

#[test]
fn an_ipv6_answer_and_the_fallback_between_families() {
    with_resolver(|netif| {
        let mut addr = IpAddr::v4(0);
        assert_eq!(
            resolve(c"v6.example", &mut addr, LWIP_DNS_ADDRTYPE_IPV4_IPV6),
            ERR_INPROGRESS
        );
        let query = last_query();
        assert_eq!(query.qtype, DNS_RRTYPE_A);
        // No A record: the resolver asks for AAAA.
        let sent = LINKOUTPUT_CTR.load(Relaxed);
        respond(netif, SERVER, &query, 0, &[]);
        assert!(found().is_empty());
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), sent + 1);
        let query = last_query();
        assert_eq!(query.qtype, DNS_RRTYPE_AAAA);

        let v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        respond(netif, SERVER, &query, 0, &[(DNS_RRTYPE_AAAA, 60, &v6)]);
        let address = [
            u32::from_ne_bytes([0x20, 0x01, 0x0d, 0xb8]),
            0,
            0,
            1_u32.to_be(),
        ];
        assert_eq!(
            found(),
            [("v6.example".into(), Some((IPADDR_TYPE_V6, address, 0)))]
        );
        // Cached as IPv6: an IPv6-first lookup finds it, an IPv4-only one does not.
        assert_eq!(
            resolve(c"v6.example", &mut addr, LWIP_DNS_ADDRTYPE_IPV6_IPV4),
            ERR_OK
        );
        assert!(addr.is_v6());
        assert_eq!(
            resolve(c"v6.example", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_INPROGRESS
        );
        // Neither family: an IPv4-only query that is not answered reports no address.
        respond(netif, SERVER, &last_query(), 0, &[]);
        assert_eq!(found(), [("v6.example".into(), None)]);
    });
}

#[test]
fn responses_that_do_not_match_the_query_are_ignored() {
    with_resolver(|netif| {
        let mut addr = IpAddr::v4(0);
        assert_eq!(
            resolve(c"example.com", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_INPROGRESS
        );
        let query = last_query();
        let answer: &[(u16, u32, &[u8])] = &[(DNS_RRTYPE_A, 300, &EXAMPLE.addr.to_ne_bytes())];

        // From another address than the server asked (RFC 5452).
        respond(netif, BACKUP, &query, 0, answer);
        // Another transaction ID.
        respond(
            netif,
            SERVER,
            &Query {
                txid: query.txid.wrapping_add(1),
                ..last_query()
            },
            0,
            answer,
        );
        // Another name.
        respond(
            netif,
            SERVER,
            &Query {
                name: encoded("example.org"),
                ..last_query()
            },
            0,
            answer,
        );
        // Another question type.
        respond(
            netif,
            SERVER,
            &Query {
                qtype: DNS_RRTYPE_AAAA,
                ..last_query()
            },
            0,
            answer,
        );
        assert!(found().is_empty());

        respond(netif, SERVER, &query, 0, answer);
        assert_eq!(found(), [("example.com".into(), Some(key(&v4(EXAMPLE))))]);
    });
}

#[test]
fn retries_back_off_then_give_up() {
    with_resolver(|_| {
        let mut addr = IpAddr::v4(0);
        let sent = LINKOUTPUT_CTR.load(Relaxed);
        assert_eq!(
            resolve(c"silent.example", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_INPROGRESS
        );
        // Resent after 1, 1, 2, and 3 more ticks; given up at the 4th retry.
        let mut sends = Vec::new();
        for n in 1..=7 {
            tick();
            sends.push((n, LINKOUTPUT_CTR.load(Relaxed) - sent));
        }
        assert_eq!(
            sends,
            [(1, 2), (2, 3), (3, 3), (4, 4), (5, 4), (6, 4), (7, 4)]
        );
        assert_eq!(found(), [("silent.example".into(), None)]);
        assert!(timeouts().is_empty());
    });
}

#[test]
fn an_error_or_silence_moves_to_the_next_server() {
    with_resolver(|netif| {
        // SAFETY: a valid address.
        unsafe { dns_setserver(1, &v4(BACKUP)) };
        let mut addr = IpAddr::v4(0);
        assert_eq!(
            resolve(c"example.com", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_INPROGRESS
        );
        let query = last_query();
        assert_eq!(query.dest, SERVER.addr.to_ne_bytes());
        // SERVFAIL: asked again of the backup server.
        respond(netif, SERVER, &query, 2, &[]);
        assert!(found().is_empty());
        let query = last_query();
        assert_eq!(query.dest, BACKUP.addr.to_ne_bytes());
        // An error from the last server is final.
        respond(netif, BACKUP, &query, 3, &[]);
        assert_eq!(found(), [("example.com".into(), None)]);

        // With server 1 unset, an error does not look past it...
        // SAFETY: null sets any; a valid address.
        unsafe {
            dns_setserver(1, ptr::null());
            dns_setserver(2, &v4(BACKUP));
        }
        assert_eq!(
            resolve(c"example.org", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_INPROGRESS
        );
        respond(netif, SERVER, &last_query(), 2, &[]);
        assert_eq!(found(), [("example.org".into(), None)]);

        // ...but ESP-IDF skips it when the retries run out: after 1, 1, 2, and 3 ticks.
        assert_eq!(
            resolve(c"example.net", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_INPROGRESS
        );
        for _ in 0..6 {
            tick();
        }
        assert_eq!(last_query().dest, SERVER.addr.to_ne_bytes());
        tick();
        assert_eq!(last_query().dest, BACKUP.addr.to_ne_bytes());
        assert!(found().is_empty());
    });
}

#[test]
fn names_that_need_no_query() {
    with_resolver(|_| {
        let mut addr = IpAddr::v4(0);
        let sent = LINKOUTPUT_CTR.load(Relaxed);
        assert_eq!(
            resolve(c"localhost", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_OK
        );
        assert!(same(&addr, &v4(ip4(127, 0, 0, 1))));
        assert_eq!(
            resolve(c"localhost", &mut addr, LWIP_DNS_ADDRTYPE_IPV6),
            ERR_OK
        );
        assert!(addr.is_v6() && addr.ip6().addr == [0, 0, 0, 1_u32.to_be()]);
        assert_eq!(
            resolve(c"10.1.2.3", &mut addr, LWIP_DNS_ADDRTYPE_IPV4_IPV6),
            ERR_OK
        );
        assert!(same(&addr, &v4(ip4(10, 1, 2, 3))));
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), sent);
        // An IPv4 literal is not an answer to an IPv6-only lookup.
        assert_eq!(
            resolve(c"10.1.2.3", &mut addr, LWIP_DNS_ADDRTYPE_IPV6),
            ERR_INPROGRESS
        );
    });
}

#[test]
fn invalid_arguments_and_no_server() {
    with_resolver(|_| {
        let mut addr = IpAddr::v4(0);
        // SAFETY: null arguments are refused.
        unsafe {
            assert_eq!(
                dns_gethostbyname(ptr::null(), &mut addr, None, ptr::null_mut()),
                ERR_ARG
            );
            assert_eq!(
                dns_gethostbyname(c"a".as_ptr(), ptr::null_mut(), None, ptr::null_mut()),
                ERR_ARG
            );
            assert_eq!(
                dns_gethostbyname_addrtype_n(c"a".as_ptr(), &mut addr, 0, None, ptr::null_mut(), 0),
                ERR_ARG
            );
            assert_eq!(
                dns_gethostbyname_addrtype_n(c"a".as_ptr(), &mut addr, 2, None, ptr::null_mut(), 0),
                ERR_ARG
            );
        }
        assert_eq!(resolve(c"", &mut addr, LWIP_DNS_ADDRTYPE_IPV4), ERR_ARG);
        let long = std::ffi::CString::new("a".repeat(DNS_MAX_NAME_LENGTH)).unwrap();
        assert_eq!(resolve(&long, &mut addr, LWIP_DNS_ADDRTYPE_IPV4), ERR_ARG);

        // No server: refused rather than reported through the callback.
        // SAFETY: null sets any.
        unsafe { dns_setserver(0, ptr::null()) };
        assert_eq!(
            resolve(c"example.com", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_VAL
        );
        // Only the last server set is enough.
        // SAFETY: a valid address.
        unsafe { dns_setserver(2, &v4(BACKUP)) };
        assert_eq!(
            resolve(c"example.com", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_INPROGRESS
        );
        assert_eq!(last_query().dest, BACKUP.addr.to_ne_bytes());
    });
}

#[test]
fn a_local_name_is_asked_by_multicast_without_a_server() {
    with_resolver(|netif| {
        // SAFETY: null sets any.
        unsafe { dns_setserver(0, ptr::null()) };
        let mut addr = IpAddr::v4(0);
        assert_eq!(
            resolve(c"printer.local", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_INPROGRESS
        );
        let query = last_query();
        assert_eq!(query.dest, [224, 0, 0, 251]);
        assert_eq!(query.dest_port, DNS_MQUERY_PORT);
        // Any responder may answer.
        let printer = ip4(192, 168, 0, 40);
        respond(
            netif,
            printer,
            &query,
            0,
            &[(DNS_RRTYPE_A, 120, &printer.addr.to_ne_bytes())],
        );
        assert_eq!(found(), [("printer.local".into(), Some(key(&v4(printer))))]);
        // ".local" elsewhere in the name is not mDNS.
        assert_eq!(
            resolve(c"a.local.example", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_VAL
        );
    });
}

#[test]
fn duplicate_lookups_share_one_query_and_clear_cache_reports_them() {
    with_resolver(|_| {
        let mut addr = IpAddr::v4(0);
        let sent = LINKOUTPUT_CTR.load(Relaxed);
        assert_eq!(
            resolve(c"example.com", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_INPROGRESS
        );
        assert_eq!(
            resolve(c"EXAMPLE.com", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_INPROGRESS
        );
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), sent + 1, "one query for both");
        dns_clear_cache();
        assert_eq!(
            found(),
            [("example.com".into(), None), ("example.com".into(), None)]
        );
    });
}

#[test]
fn the_table_fills_up_and_the_oldest_answer_is_evicted() {
    with_resolver(|netif| {
        let mut addr = IpAddr::v4(0);
        let answer: &[(u16, u32, &[u8])] = &[(DNS_RRTYPE_A, 300, &EXAMPLE.addr.to_ne_bytes())];
        let mut queries = Vec::new();
        for name in [c"a.example", c"b.example", c"c.example", c"d.example"] {
            assert_eq!(
                resolve(name, &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
                ERR_INPROGRESS
            );
            queries.push(last_query());
        }
        // Every entry is pending: no room.
        assert_eq!(
            resolve(c"e.example", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_MEM
        );
        // b and d complete; a new name takes b's entry, the older one.
        respond(netif, SERVER, &queries[3], 0, answer);
        respond(netif, SERVER, &queries[1], 0, answer);
        assert_eq!(found().len(), 2);
        assert_eq!(
            resolve(c"e.example", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_INPROGRESS
        );
        assert_eq!(
            resolve(c"d.example", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_OK
        );
        assert_eq!(
            resolve(c"b.example", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_INPROGRESS
        );
        // Now d is gone too, and nothing is left to evict.
        assert_eq!(
            resolve(c"d.example", &mut addr, LWIP_DNS_ADDRTYPE_IPV4),
            ERR_MEM
        );
    });
}

#[test]
fn the_multicast_groups() {
    assert!(same(&dns_mquery_v4group, &v4(ip4(224, 0, 0, 251))));
    assert!(dns_mquery_v6group.is_v6());
    assert_eq!(
        dns_mquery_v6group.ip6().addr,
        [0xff02_0000_u32.to_be(), 0, 0, 0xfb_u32.to_be()]
    );
}
