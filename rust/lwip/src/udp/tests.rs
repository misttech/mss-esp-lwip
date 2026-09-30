// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! test/unit/udp/test_udp.c, and beyond it udp.c's documented behavior: binding and port
//! allocation, sending, receiving and demultiplexing, connect and disconnect, the ICMP
//! port-unreachable reply, and address changes.

extern crate std;

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering::Relaxed};
use std::boxed::Box;
use std::vec::Vec;

use super::*;
use crate::ip4::ip4_input;
use crate::ip4::tests::{
    LINKOUTPUT_CTR, LINKOUTPUT_PKT, TEST_IPADDR, arpless_output, ip_header, ip4, packet,
    with_test_netif,
};

const PEER: Ip4Addr = ip4(192, 168, 0, 9);
const PBUF_TRANSPORT: PbufLayer = config::PBUF_TRANSPORT_LAYER as PbufLayer;

unsafe extern "C" fn count_recv(
    arg: *mut c_void,
    _pcb: *mut UdpPcb,
    p: *mut Pbuf,
    _addr: *const IpAddr,
    _port: u16,
) {
    // SAFETY: `arg` is the counter the test gave udp_recv; the callback owns the pbuf.
    unsafe {
        (*arg.cast::<AtomicUsize>()).fetch_add(1, Relaxed);
        pbuf_free(p);
    }
}

/// A PCB bound to `addr` (any if null) and `port` that counts into `counter`.
fn listener(addr: *const IpAddr, port: u16, reuse: bool, counter: &AtomicUsize) -> *mut UdpPcb {
    let pcb = udp_new();
    assert!(!pcb.is_null());
    // SAFETY: a fresh PCB; the counter outlives it.
    unsafe {
        if reuse {
            (*pcb).so_options |= SOF_REUSEADDR;
        }
        assert_eq!(udp_bind(pcb, addr, port), ERR_OK);
        udp_recv(
            pcb,
            Some(count_recv),
            ptr::from_ref(counter).cast_mut().cast(),
        );
    }
    pcb
}

/// The PCBs on `udp_pcbs`, in order.
fn pcbs() -> Vec<*mut UdpPcb> {
    let mut all = Vec::new();
    let mut pcb = udp_pcbs.get();
    while !pcb.is_null() {
        all.push(pcb);
        // SAFETY: PCBs on the list are live.
        pcb = unsafe { (*pcb).next };
    }
    all
}

/// Removes every PCB left on the list.
fn remove_all() {
    for pcb in pcbs() {
        // SAFETY: PCBs on the list come from udp_new.
        unsafe { udp_remove(pcb) };
    }
}

/// A UDP datagram from `src:sport` to `dest:dport` through `ip4_input`.
fn deliver(netif: *mut Netif, src: Ip4Addr, sport: u16, dest: Ip4Addr, dport: u16, len: u16) {
    let mut bytes = ip_header(src, dest, IP_PROTO_UDP, UDP_HLEN + len, 0);
    bytes.extend(sport.to_be_bytes());
    bytes.extend(dport.to_be_bytes());
    bytes.extend((UDP_HLEN + len).to_be_bytes());
    bytes.extend([0, 0]);
    bytes.extend((0..len).map(|i| i as u8));
    // SAFETY: a live netif; the packet is given up.
    unsafe { ip4_input(packet(&bytes), netif) };
}

/// The one's-complement sum of `bytes` as 16-bit big-endian words.
fn ones_sum(bytes: &[u8], mut sum: u32) -> u32 {
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

// test_udp.c.

/// test_udp.c's `struct test_udp_rxdata`.
struct RxData {
    rx_cnt: AtomicU32,
    rx_bytes: AtomicU32,
    pcb: *mut UdpPcb,
}

impl RxData {
    fn new(pcb: *mut UdpPcb) -> Self {
        Self {
            rx_cnt: AtomicU32::new(0),
            rx_bytes: AtomicU32::new(0),
            pcb,
        }
    }

    /// The count and bytes received since the last call.
    fn take(&self) -> (u32, u32) {
        (self.rx_cnt.swap(0, Relaxed), self.rx_bytes.swap(0, Relaxed))
    }
}

unsafe extern "C" fn test_recv(
    arg: *mut c_void,
    pcb: *mut UdpPcb,
    p: *mut Pbuf,
    _addr: *const IpAddr,
    _port: u16,
) {
    assert!(!arg.is_null());
    // SAFETY: `arg` is the test's RxData; the callback owns the pbuf.
    unsafe {
        let ctr = &*arg.cast::<RxData>();
        assert_eq!(ctr.pcb, pcb);
        ctr.rx_cnt.fetch_add(1, Relaxed);
        ctr.rx_bytes.fetch_add(u32::from((*p).tot_len), Relaxed);
        pbuf_free(p);
    }
}

unsafe extern "C" fn default_netif_output(
    _netif: *mut Netif,
    p: *mut Pbuf,
    ipaddr: *const Ip4Addr,
) -> ErrT {
    assert!(!p.is_null() && !ipaddr.is_null());
    ERR_OK
}

unsafe extern "C" fn default_netif_linkoutput(_netif: *mut Netif, p: *mut Pbuf) -> ErrT {
    assert!(!p.is_null());
    ERR_OK
}

unsafe extern "C" fn default_netif_init(netif: *mut Netif) -> ErrT {
    // SAFETY: the netif being added.
    unsafe {
        (*netif).output = Some(default_netif_output);
        (*netif).linkoutput = Some(default_netif_linkoutput);
        (*netif).mtu = 1500;
        (*netif).flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
        (*netif).hwaddr_len = 6;
    }
    ERR_OK
}

/// test_udp.c's default_netif_add and default_netif_remove around `test`: 192.168.0.1/24
/// (the default) and 192.168.1.1/24.
fn with_two_netifs(test: impl FnOnce(*mut Netif, *mut Netif)) {
    let _serial = crate::test_support::serial();
    assert!(pcbs().is_empty());
    assert!(crate::netif::netif_default.get().is_null());
    // SAFETY: every field of the mirror is valid zeroed.
    let mut netifs: [Box<Netif>; 2] =
        core::array::from_fn(|_| Box::new(unsafe { MaybeUninit::zeroed().assume_init() }));
    let [n1, n2] = netifs.each_mut().map(|n| &mut **n as *mut Netif);
    let netmask = ip4(255, 255, 255, 0);
    // SAFETY: the netifs outlive their time on the list.
    unsafe {
        for (n, ip, gw) in [
            (n1, ip4(192, 168, 0, 1), ip4(192, 168, 0, 254)),
            (n2, ip4(192, 168, 1, 1), ip4(192, 168, 1, 254)),
        ] {
            let added = crate::netif::netif_add(
                n,
                &ip,
                &netmask,
                &gw,
                ptr::null_mut(),
                Some(default_netif_init),
                None,
            );
            assert_eq!(added, n);
        }
        crate::netif::netif_set_default(n1);
        crate::netif::netif_set_up(n1);
        crate::netif::netif_set_up(n2);
    }

    test(n1, n2);

    remove_all();
    // SAFETY: on the list.
    unsafe {
        crate::netif::netif_remove(n1);
        crate::netif::netif_remove(n2);
    }
    assert!(crate::netif::netif_default.get().is_null());
}

/// test_udp_create_test_packet: `length` bytes from `port` to `port` at `dst_addr`, in an
/// IPv4 header from 0.0.0.0.
fn test_packet(length: u16, port: u16, dst_addr: u32) -> *mut Pbuf {
    let mut bytes = ip_header(
        ip4(0, 0, 0, 0),
        Ip4Addr { addr: dst_addr },
        IP_PROTO_UDP,
        UDP_HLEN + length,
        0,
    );
    bytes.extend(port.to_be_bytes());
    bytes.extend(port.to_be_bytes());
    bytes.extend((UDP_HLEN + length).to_be_bytes());
    bytes.extend([0, 0]);
    bytes.extend((0..length).map(|i| i as u8));
    packet(&bytes)
}

#[test]
fn test_udp_new_remove() {
    with_two_netifs(|_, _| {
        let pcb = udp_new();
        assert!(!pcb.is_null());
        // SAFETY: a PCB from udp_new, not on the list.
        unsafe { udp_remove(pcb) };
        assert!(pcbs().is_empty());
    });
}

/// Bind 2 pcbs to specific netif IP and test which one gets broadcasts.
#[test]
fn test_udp_broadcast_rx_with_2_netifs() {
    with_two_netifs(|n1, n2| {
        const PORT: u16 = 12345;
        let (pcb1, pcb2, pcb_any) = (udp_new(), udp_new(), udp_new());
        let (ctr1, ctr2, ctr_any) = (RxData::new(pcb1), RxData::new(pcb2), RxData::new(pcb_any));
        // SAFETY: live PCBs and netifs; the counters outlive the PCBs.
        unsafe {
            for pcb in [pcb1, pcb2, pcb_any] {
                (*pcb).so_options |= SOF_REUSEADDR;
            }
            assert_eq!(udp_bind(pcb_any, ptr::null(), PORT), ERR_OK);
            udp_recv(
                pcb_any,
                Some(test_recv),
                ptr::from_ref(&ctr_any).cast_mut().cast(),
            );
            assert_eq!(udp_bind(pcb1, &(*n1).ip_addr, PORT), ERR_OK);
            assert_eq!(udp_bind(pcb2, &(*n2).ip_addr, PORT), ERR_OK);
            udp_recv(
                pcb1,
                Some(test_recv),
                ptr::from_ref(&ctr1).cast_mut().cast(),
            );
            udp_recv(
                pcb2,
                Some(test_recv),
                ptr::from_ref(&ctr2).cast_mut().cast(),
            );

            let (ip1, ip2) = ((*n1).ip4_addr().addr, (*n2).ip4_addr().addr);
            let (mask1, mask2) = ((*n1).ip4_netmask().addr, (*n2).ip4_netmask().addr);
            // (destination, input netif, and datagrams pcb1, pcb2, and pcb_any receive).
            // test_udp.c's configuration has no SO_REUSE, so it expects pcb_any to get
            // nothing; ESP-IDF's SO_REUSE_RXTOALL also hands a copy of each broadcast to
            // every other PCB that matches it.
            let cases = [
                // Unicast to netif1.
                (ip1, n1, (1, 0, 0)),
                // Unicast to netif2.
                (ip2, n2, (0, 1, 0)),
                // Broadcast to netif1-broadcast, input to netif2.
                (ip1 | !mask1, n2, (1, 0, 1)),
                // Broadcast to netif2-broadcast, input to netif1.
                (ip2 | !mask2, n1, (0, 1, 1)),
                // Broadcast to global-broadcast, input to netif1: pcb1 first.
                (0xffff_ffff, n1, (1, 1, 1)),
                // Broadcast to global-broadcast, input to netif2: pcb2 first.
                (0xffff_ffff, n2, (1, 1, 1)),
            ];
            for (dst, inp, (to1, to2, to_any)) in cases {
                assert_eq!(ip4_input(test_packet(16, PORT, dst), inp), ERR_OK);
                assert_eq!(ctr1.take(), (to1, 16 * to1));
                assert_eq!(ctr2.take(), (to2, 16 * to2));
                assert_eq!(ctr_any.take(), (to_any, 16 * to_any));
            }
        }
    });
}

#[test]
fn test_udp_bind() {
    with_two_netifs(|_, _| {
        let any4 = IpAddr::v4(0);
        let mut any6 = IpAddr::v4(0);
        any6.set_zero_ip6();
        let (a1234, a4321) = (
            IpAddr::v4(ip4(1, 2, 3, 4).addr),
            IpAddr::v4(ip4(4, 3, 2, 1).addr),
        );
        // SAFETY: the address of ip.c's constant.
        let any_type = unsafe { *ip_addr_any_type() };
        // (PCB types, addresses, and the second bind's result)
        let cases = [
            // Bind on same port using different IP address types.
            ((IPADDR_TYPE_V4, IPADDR_TYPE_V6), (any4, any6), ERR_OK),
            // Bind on same port using SAME IPv4 address type.
            ((IPADDR_TYPE_V4, IPADDR_TYPE_V4), (any4, any4), ERR_USE),
            // Bind on same port using SAME IPv6 address type.
            ((IPADDR_TYPE_V6, IPADDR_TYPE_V6), (any6, any6), ERR_USE),
            // Bind with different IP address type.
            ((IPADDR_TYPE_V6, IPADDR_TYPE_V4), (any4, any6), ERR_OK),
            // Bind with different IP numbers.
            ((IPADDR_TYPE_V6, IPADDR_TYPE_V4), (a1234, a4321), ERR_OK),
            // Bind with same IP numbers.
            ((IPADDR_TYPE_V6, IPADDR_TYPE_V4), (a1234, a1234), ERR_USE),
            // Bind on same port using ANY + IPv4.
            (
                (IPADDR_TYPE_ANY, IPADDR_TYPE_V4),
                (any_type, a1234),
                ERR_USE,
            ),
        ];
        for ((type1, type2), (ip1, ip2), second) in cases {
            let (pcb1, pcb2) = (udp_new_ip_type(type1), udp_new_ip_type(type2));
            // SAFETY: fresh PCBs, removed after.
            unsafe {
                assert_eq!(udp_bind(pcb1, &ip1, 2105), ERR_OK);
                assert_eq!(udp_bind(pcb2, &ip2, 2105), second);
                udp_remove(pcb1);
                udp_remove(pcb2);
            }
        }
    });
}

// Beyond test_udp.c.

#[test]
fn port_zero_takes_the_next_local_port_and_duplicates_are_refused() {
    with_test_netif(|_| {
        assert!(pcbs().is_empty());
        let counter = AtomicUsize::new(0);
        let a = listener(ptr::null(), 0, false, &counter);
        let b = listener(ptr::null(), 0, false, &counter);
        // SAFETY: live PCBs.
        unsafe {
            let (pa, pb) = ((*a).local_port, (*b).local_port);
            let range = config::UDP_LOCAL_PORT_RANGE_START_ as u16
                ..=config::UDP_LOCAL_PORT_RANGE_END_ as u16;
            assert!(range.contains(&pa) && range.contains(&pb));
            assert_ne!(pa, pb);

            // Another PCB on a port in use, on any address or on ours.
            let c = udp_new();
            assert_eq!(udp_bind(c, ptr::null(), pa), ERR_USE);
            let ours = IpAddr::v4(TEST_IPADDR.addr);
            assert_eq!(udp_bind(c, &ours, pa), ERR_USE);
            assert_eq!(udp_bind(c, &ours, 9999), ERR_OK);
            // A rebind moves the PCB without listing it twice.
            assert_eq!(udp_bind(c, &ours, 9998), ERR_OK);
            assert_eq!(pcbs(), [c, b, a]);
            assert_eq!((*c).local_port, 9998);

            // Two PCBs that both set SO_REUSEADDR may share a port.
            let d = listener(ptr::null(), 7000, true, &counter);
            let e = udp_new();
            (*e).so_options |= SOF_REUSEADDR;
            assert_eq!(udp_bind(e, ptr::null(), 7000), ERR_OK);
            assert_eq!(pcbs(), [e, d, c, b, a]);

            // A null PCB is refused.
            assert_eq!(udp_bind(ptr::null_mut(), ptr::null(), 1), ERR_ARG);
        }
        remove_all();
    });
}

#[test]
fn remove_unlinks_from_any_position() {
    with_test_netif(|_| {
        let counter = AtomicUsize::new(0);
        let a = listener(ptr::null(), 1001, false, &counter);
        let b = listener(ptr::null(), 1002, false, &counter);
        let c = listener(ptr::null(), 1003, false, &counter);
        assert_eq!(pcbs(), [c, b, a]);
        // SAFETY: live PCBs from udp_new; null is ignored.
        unsafe {
            udp_remove(b);
            assert_eq!(pcbs(), [c, a]);
            udp_remove(c);
            assert_eq!(pcbs(), [a]);
            udp_remove(ptr::null_mut());
            udp_remove(a);
        }
        assert!(pcbs().is_empty());
    });
}

#[test]
fn new_ip_type_sets_both_address_types_and_ttl() {
    with_test_netif(|_| {
        let pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
        // SAFETY: a fresh PCB, not on the list.
        unsafe {
            assert_eq!((*pcb).local_ip.type_, IPADDR_TYPE_ANY);
            assert_eq!((*pcb).remote_ip.type_, IPADDR_TYPE_ANY);
            assert_eq!((*pcb).ttl, config::UDP_TTL as u8);
            assert!((*pcb).next.is_null());
            udp_remove(pcb);
        }
    });
}

#[test]
fn sendto_writes_the_header_and_a_valid_checksum() {
    with_test_netif(|netif| {
        // SAFETY: a live netif and PCB; the pbuf stays ours.
        unsafe {
            (*netif).output = Some(arpless_output);
            let pcb = udp_new();
            assert_eq!(udp_bind(pcb, ptr::null(), 5000), ERR_OK);
            let payload = b"hello";
            let p = pbuf_alloc(PBUF_TRANSPORT, payload.len() as u16, PBUF_RAM);
            assert_eq!(
                crate::pbuf::pbuf_take(p, payload.as_ptr().cast(), 5),
                ERR_OK
            );
            let before = LINKOUTPUT_CTR.load(Relaxed);
            let dest = IpAddr::v4(PEER.addr);
            assert_eq!(udp_sendto(pcb, p, &dest, 53), ERR_OK);
            assert_eq!(LINKOUTPUT_CTR.load(Relaxed), before + 1);
            // The headers went in front of the payload, in place, and stay there.
            assert_eq!((*p).tot_len, 20 + 8 + 5);
            pbuf_free(p);

            let pkt = LINKOUTPUT_PKT.lock().unwrap().clone();
            assert_eq!(pkt.len(), 20 + 8 + 5);
            assert_eq!(pkt[8], config::UDP_TTL as u8);
            assert_eq!(pkt[9], IP_PROTO_UDP);
            assert_eq!(pkt[12..16], TEST_IPADDR.addr.to_ne_bytes());
            assert_eq!(pkt[16..20], PEER.addr.to_ne_bytes());
            let udp = &pkt[20..];
            assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), 5000);
            assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), 53);
            assert_eq!(u16::from_be_bytes([udp[4], udp[5]]), 13);
            assert_eq!(&udp[8..], payload);
            // Pseudo-header and datagram sum to all ones.
            let mut pseudo = Vec::new();
            pseudo.extend(&pkt[12..20]);
            pseudo.extend([0, IP_PROTO_UDP, 0, 13]);
            assert_eq!(ones_sum(udp, ones_sum(&pseudo, 0)), 0xffff);
            assert_ne!(u16::from_be_bytes([udp[6], udp[7]]), 0);

            udp_remove(pcb);
        }
    });
}

#[test]
fn send_binds_an_unbound_pcb_and_needs_a_route() {
    with_test_netif(|netif| {
        // SAFETY: a live netif and PCB; the pbufs stay ours.
        unsafe {
            (*netif).output = Some(arpless_output);
            let pcb = udp_new();
            let peer = IpAddr::v4(PEER.addr);
            assert_eq!(udp_connect(pcb, &peer, 7), ERR_OK);
            assert_ne!((*pcb).flags & UDP_FLAGS_CONNECTED, 0);
            assert_eq!(pcbs(), [pcb]);
            let port = (*pcb).local_port;
            assert_ne!(port, 0, "connect binds a port");

            let p = pbuf_alloc(PBUF_TRANSPORT, 4, PBUF_RAM);
            assert_eq!(udp_send(pcb, p), ERR_OK);
            let pkt = LINKOUTPUT_PKT.lock().unwrap().clone();
            assert_eq!(u16::from_be_bytes([pkt[20], pkt[21]]), port);
            assert_eq!(u16::from_be_bytes([pkt[22], pkt[23]]), 7);

            // Nothing routes 10.0.0.1: the netif is on 192.168/16 and not the default.
            crate::netif::netif_set_default(ptr::null_mut());
            let far = IpAddr::v4(ip4(10, 0, 0, 1).addr);
            assert_eq!(udp_sendto(pcb, p, &far, 7), ERR_RTE);
            crate::netif::netif_set_default(netif);
            pbuf_free(p);

            udp_disconnect(pcb);
            assert_eq!((*pcb).flags & UDP_FLAGS_CONNECTED, 0);
            assert_eq!((*pcb).remote_port, 0);
            assert!((*pcb).remote_ip.is_any());
            udp_remove(pcb);
        }
    });
}

#[test]
fn a_connected_pcb_wins_over_an_unconnected_one() {
    with_test_netif(|netif| {
        let (connected, unconnected) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let any = listener(ptr::null(), 7000, true, &unconnected);
        let conn = listener(ptr::null(), 7000, true, &connected);
        let peer = IpAddr::v4(PEER.addr);
        // SAFETY: a live PCB.
        unsafe { assert_eq!(udp_connect(conn, &peer, 1234), ERR_OK) };

        deliver(netif, PEER, 1234, TEST_IPADDR, 7000, 4);
        assert_eq!((connected.load(Relaxed), unconnected.load(Relaxed)), (1, 0));
        // Another source port or host goes to the unconnected PCB.
        deliver(netif, PEER, 1235, TEST_IPADDR, 7000, 4);
        deliver(netif, ip4(192, 168, 0, 10), 1234, TEST_IPADDR, 7000, 4);
        assert_eq!((connected.load(Relaxed), unconnected.load(Relaxed)), (1, 2));

        // The connected PCB moved to the front of the list when it matched.
        // SAFETY: a live PCB.
        unsafe { udp_disconnect(conn) };
        assert_eq!(pcbs()[0], conn);
        let _ = any;
        remove_all();
    });
}

#[test]
fn a_specific_address_wins_over_any() {
    with_test_netif(|netif| {
        let (specific, wildcard) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let ours = IpAddr::v4(TEST_IPADDR.addr);
        listener(ptr::null(), 7000, true, &wildcard);
        listener(&ours, 7000, true, &specific);
        listener(ptr::null(), 7000, true, &wildcard);
        deliver(netif, PEER, 1, TEST_IPADDR, 7000, 0);
        assert_eq!((specific.load(Relaxed), wildcard.load(Relaxed)), (1, 0));
        remove_all();
    });
}

#[test]
fn broadcast_reaches_every_reuseaddr_listener() {
    with_test_netif(|netif| {
        let (a, b, other) = (
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
        );
        listener(ptr::null(), 68, true, &a);
        listener(ptr::null(), 68, true, &b);
        listener(ptr::null(), 69, false, &other);
        let before = LINKOUTPUT_CTR.load(Relaxed);
        for dest in [ip4(255, 255, 255, 255), ip4(192, 168, 255, 255)] {
            deliver(netif, PEER, 67, dest, 68, 10);
        }
        assert_eq!(
            (a.load(Relaxed), b.load(Relaxed), other.load(Relaxed)),
            (2, 2, 0)
        );
        // An unmatched broadcast is dropped without an ICMP reply.
        deliver(netif, PEER, 67, ip4(255, 255, 255, 255), 70, 10);
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), before);
        remove_all();
    });
}

#[test]
fn an_unmatched_unicast_datagram_gets_port_unreachable() {
    with_test_netif(|netif| {
        // SAFETY: a live netif.
        unsafe { (*netif).output = Some(arpless_output) };
        let before = LINKOUTPUT_CTR.load(Relaxed);
        deliver(netif, PEER, 1234, TEST_IPADDR, 4321, 16);
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), before + 1);
        let pkt = LINKOUTPUT_PKT.lock().unwrap().clone();
        assert_eq!(pkt[9], IP_PROTO_ICMP);
        assert_eq!(pkt[16..20], PEER.addr.to_ne_bytes());
        assert_eq!((pkt[20], pkt[21]), (3, 3), "destination unreachable: port");
        // It quotes the original IP header and the start of its UDP header.
        assert_eq!(pkt[28 + 9], IP_PROTO_UDP);
        assert_eq!(u16::from_be_bytes([pkt[28 + 22], pkt[28 + 23]]), 4321);

        // A datagram for another host is dropped silently.
        deliver(netif, PEER, 1234, ip4(192, 168, 0, 77), 4321, 16);
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), before + 1);
    });
}

#[test]
fn a_datagram_shorter_than_the_header_is_dropped() {
    with_test_netif(|netif| {
        let counter = AtomicUsize::new(0);
        listener(ptr::null(), 7000, false, &counter);
        let mut bytes = ip_header(PEER, TEST_IPADDR, IP_PROTO_UDP, 4, 0);
        bytes.extend([0, 1, 0x1b, 0x58]);
        // SAFETY: a live netif; the packet is given up.
        unsafe { ip4_input(packet(&bytes), netif) };
        deliver(netif, PEER, 1, TEST_IPADDR, 7000, 0);
        assert_eq!(counter.load(Relaxed), 1);
        remove_all();
    });
}

#[test]
fn a_pcb_bound_to_a_netif_only_hears_that_netif() {
    with_test_netif(|netif| {
        let counter = AtomicUsize::new(0);
        let pcb = listener(ptr::null(), 7000, false, &counter);
        // SAFETY: a live PCB and netif.
        unsafe {
            udp_bind_netif(pcb, netif);
            assert_eq!((*pcb).netif_idx, (*netif).index());
            deliver(netif, PEER, 1, TEST_IPADDR, 7000, 0);
            assert_eq!(counter.load(Relaxed), 1);
            (*pcb).netif_idx = (*netif).index().wrapping_add(1);
            deliver(netif, PEER, 1, TEST_IPADDR, 7000, 0);
            assert_eq!(counter.load(Relaxed), 1);
            udp_bind_netif(pcb, ptr::null());
            assert_eq!((*pcb).netif_idx, NETIF_NO_INDEX);
        }
        remove_all();
    });
}

#[test]
fn an_address_change_rebinds_pcbs_on_the_old_address() {
    with_test_netif(|netif| {
        let counter = AtomicUsize::new(0);
        let ours = IpAddr::v4(TEST_IPADDR.addr);
        let bound = listener(&ours, 7000, false, &counter);
        let wildcard = listener(ptr::null(), 7001, false, &counter);
        let new = ip4(192, 168, 0, 2);
        // SAFETY: live PCBs and netif.
        unsafe {
            crate::netif::netif_set_ipaddr(netif, &new);
            assert_eq!((*bound).local_ip.ip4().addr, new.addr);
            assert!((*wildcard).local_ip.is_any());
            // A change to or from any leaves the PCBs alone.
            udp_netif_ip_addr_changed(&IpAddr::v4(new.addr), &IpAddr::v4(0));
            udp_netif_ip_addr_changed(ptr::null(), &IpAddr::v4(new.addr));
            assert_eq!((*bound).local_ip.ip4().addr, new.addr);
            crate::netif::netif_set_ipaddr(netif, &TEST_IPADDR);
            assert_eq!((*bound).local_ip.ip4().addr, TEST_IPADDR.addr);
        }
        remove_all();
    });
}
