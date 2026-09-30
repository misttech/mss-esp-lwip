// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! test/unit/ip4/test_ip4.c, with the test netif its cases share (also used by the ICMP
//! and fragmentation tests), plus IPv4 input and output behavior beyond it.
//!
//! test_ip4_reass needs IP_REASSEMBLY, which ESP-IDF turns off; here fragments are
//! dropped, and a test checks that instead. test_ip4addr_aton is with ip4_addr's tests.

extern crate std;

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering::Relaxed};
use std::boxed::Box;
use std::sync::Mutex;
use std::vec::Vec;

use super::*;
use crate::netif::{netif_add, netif_default, netif_remove, netif_set_default, netif_set_up};
use crate::test_support::serial;

pub(crate) static LINKOUTPUT_CTR: AtomicUsize = AtomicUsize::new(0);
pub(crate) static LINKOUTPUT_BYTE_CTR: AtomicUsize = AtomicUsize::new(0);
/// The start of the last packet sent (100 bytes at most), as test_ip4.c keeps it.
pub(crate) static LINKOUTPUT_PKT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static TEST_NETIF: AtomicPtr<Netif> = AtomicPtr::new(ptr::null_mut());

pub(crate) const fn ip4(a: u8, b: u8, c: u8, d: u8) -> Ip4Addr {
    Ip4Addr {
        addr: u32::from_be_bytes([a, b, c, d]).to_be(),
    }
}

pub(crate) const TEST_IPADDR: Ip4Addr = ip4(192, 168, 0, 1);

unsafe extern "C" fn test_netif_linkoutput(netif: *mut Netif, p: *mut Pbuf) -> ErrT {
    assert_eq!(netif, TEST_NETIF.load(Relaxed));
    assert!(!p.is_null());
    LINKOUTPUT_CTR.fetch_add(1, Relaxed);
    // SAFETY: the stack hands the driver a live pbuf chain.
    unsafe {
        LINKOUTPUT_BYTE_CTR.fetch_add(usize::from((*p).tot_len), Relaxed);
        // Copy start of packet into buffer.
        let mut pkt = std::vec![0_u8; 100];
        let len = pbuf_copy_partial(p, pkt.as_mut_ptr().cast(), 100, 0);
        pkt.truncate(usize::from(len));
        *LINKOUTPUT_PKT.lock().unwrap() = pkt;
    }
    ERR_OK
}

unsafe extern "C" fn test_netif_init(netif: *mut Netif) -> ErrT {
    assert!(!netif.is_null());
    // SAFETY: the netif being added.
    unsafe {
        (*netif).linkoutput = Some(test_netif_linkoutput);
        (*netif).output = Some(crate::etharp::etharp_output);
        (*netif).mtu = 1500;
        (*netif).flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
        (*netif).hwaddr_len = ETH_HWADDR_LEN as u8;
    }
    ERR_OK
}

/// `arpless_output`: straight to the driver, without ARP.
pub(crate) unsafe extern "C" fn arpless_output(
    netif: *mut Netif,
    p: *mut Pbuf,
    _ipaddr: *const Ip4Addr,
) -> ErrT {
    // SAFETY: the netif's own output, with its own driver.
    unsafe { (*netif).linkoutput.unwrap()(netif, p) }
}

/// test_netif_add and test_netif_remove around `test`, serialized with the other tests
/// that use the stack's globals.
pub(crate) fn with_test_netif(test: impl FnOnce(*mut Netif)) {
    let _serial = serial();
    // SAFETY: every field of the mirror is valid zeroed.
    let mut netif: Box<Netif> = Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
    let n = &mut *netif as *mut Netif;
    TEST_NETIF.store(n, Relaxed);
    LINKOUTPUT_CTR.store(0, Relaxed);
    LINKOUTPUT_BYTE_CTR.store(0, Relaxed);
    let (test_gw, test_netmask) = (ip4(192, 168, 0, 1), ip4(255, 255, 0, 0));
    assert!(netif_default.get().is_null());
    // SAFETY: the netif outlives its time on the list.
    unsafe {
        netif_add(
            n,
            &TEST_IPADDR,
            &test_netmask,
            &test_gw,
            ptr::null_mut(),
            Some(test_netif_init),
            None,
        );
        netif_set_default(n);
        netif_set_up(n);
    }

    test(n);

    // SAFETY: on the list.
    unsafe { netif_remove(n) };
}

/// A packet `bytes` long in a PBUF_IP pbuf.
pub(crate) fn packet(bytes: &[u8]) -> *mut Pbuf {
    // SAFETY: a fresh pbuf of the packet's size.
    unsafe {
        let p = pbuf_alloc(
            crate::config::PBUF_IP_LAYER as PbufLayer,
            bytes.len() as u16,
            PBUF_RAM,
        );
        assert!(!p.is_null());
        assert_eq!(
            crate::pbuf::pbuf_take(p, bytes.as_ptr().cast(), bytes.len() as u16),
            ERR_OK
        );
        p
    }
}

/// An IPv4 header of `proto` from `src` to `dest` with `payload_len` bytes after it, its
/// checksum filled in.
pub(crate) fn ip_header(
    src: Ip4Addr,
    dest: Ip4Addr,
    proto: u8,
    payload_len: u16,
    offset: u16,
) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend([0x45, 0x00]);
    h.extend((IP_HLEN + payload_len).to_be_bytes());
    h.extend([0x12, 0x34]);
    h.extend(offset.to_be_bytes());
    h.extend([64, proto, 0, 0]);
    h.extend(src.addr.to_ne_bytes());
    h.extend(dest.addr.to_ne_bytes());
    // SAFETY: a 20-byte buffer.
    let sum = unsafe { inet_chksum(h.as_ptr().cast(), IP_HLEN) };
    h[10..12].copy_from_slice(&sum.to_ne_bytes());
    h
}

#[test]
fn test_ip4_frag() {
    with_test_netif(|netif| {
        // SAFETY: a live netif and pbuf, and valid addresses.
        unsafe {
            let data = pbuf_alloc(crate::config::PBUF_IP_LAYER as PbufLayer, 8000, PBUF_RAM);
            let peer_ip = ip4(192, 168, 0, 5);

            // Verify that 8000 byte payload is split into six packets.
            assert!(!data.is_null());
            (*netif).output = Some(arpless_output);
            let err = ip4_output_if_src(data, &TEST_IPADDR, &peer_ip, 16, 0, IP_PROTO_UDP, netif);
            assert_eq!(err, ERR_OK);
            assert_eq!(LINKOUTPUT_CTR.load(Relaxed), 6);
            assert_eq!(
                LINKOUTPUT_BYTE_CTR.load(Relaxed),
                8000 + 6 * usize::from(IP_HLEN)
            );
            pbuf_free(data);
        }
    });
}

#[test]
fn test_127_0_0_1() {
    with_test_netif(|_netif| {
        // Without a loopback netif up, 127.0.0.1 has no route and nothing is sent.
        let localhost = ip4(127, 0, 0, 1);
        // SAFETY: a fresh pbuf; valid addresses.
        unsafe {
            let p = pbuf_alloc(crate::config::PBUF_IP_LAYER as PbufLayer, 10, PBUF_POOL);
            if ip4_output(
                p,
                (*netif_default.get()).ip4_addr(),
                &localhost,
                0,
                0,
                IP_PROTO_UDP,
            ) != ERR_OK
            {
                pbuf_free(p);
            }
        }
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), 0);
    });
}

#[test]
fn test_ip4_icmp_replylen_short() {
    // IP packet to 192.168.0.1 using proto 0x22 and 1 byte payload.
    let unknown_proto: [u8; 21] = [
        0x45, 0x00, 0x00, 0x15, 0xd4, 0x31, 0x00, 0x00, 0xff, 0x22, 0x66, 0x41, 0xc0, 0xa8, 0x00,
        0x02, 0xc0, 0xa8, 0x00, 0x01, 0xaa,
    ];
    let icmp_len = usize::from(IP_HLEN) + core::mem::size_of::<IcmpHdr>();
    with_test_netif(|netif| {
        // SAFETY: a live netif; the packet is given up to ip4_input.
        unsafe {
            (*netif).output = Some(arpless_output);
            assert_eq!(ip4_input(packet(&unknown_proto), netif), ERR_OK);
        }
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), 1);
        // Verify outgoing ICMP packet has no extra data.
        let pkt = LINKOUTPUT_PKT.lock().unwrap();
        assert_eq!(pkt.len(), icmp_len + unknown_proto.len());
        assert_eq!(&pkt[icmp_len..], &unknown_proto);
    });
}

#[test]
fn test_ip4_icmp_replylen_first_8() {
    // IP packet to 192.168.0.1 using proto 0x22 and 11 bytes payload.
    let unknown_proto: [u8; 31] = [
        0x45, 0x00, 0x00, 0x1f, 0xd4, 0x31, 0x00, 0x00, 0xff, 0x22, 0x66, 0x37, 0xc0, 0xa8, 0x00,
        0x02, 0xc0, 0xa8, 0x00, 0x01, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
        0xaa,
    ];
    let icmp_len = usize::from(IP_HLEN) + core::mem::size_of::<IcmpHdr>();
    let unreach_len = usize::from(IP_HLEN) + 8;
    with_test_netif(|netif| {
        // SAFETY: a live netif; the packet is given up to ip4_input.
        unsafe {
            (*netif).output = Some(arpless_output);
            assert_eq!(ip4_input(packet(&unknown_proto), netif), ERR_OK);
        }
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), 1);
        let pkt = LINKOUTPUT_PKT.lock().unwrap();
        assert_eq!(pkt.len(), icmp_len + unreach_len);
        assert_eq!(&pkt[icmp_len..], &unknown_proto[..unreach_len]);
    });
}

// Beyond test_ip4.c.

/// Datagrams the listeners below received.
static UDP_RECEIVED: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn count_recv(
    _arg: *mut core::ffi::c_void,
    _pcb: *mut UdpPcb,
    p: *mut Pbuf,
    _addr: *const IpAddr,
    _port: u16,
) {
    UDP_RECEIVED.fetch_add(1, Relaxed);
    // SAFETY: the receive callback owns the pbuf.
    unsafe { pbuf_free(p) };
}

/// A UDP PCB on `port` of any local address that counts what it receives.
pub(crate) fn udp_listener(port: u16) -> *mut UdpPcb {
    let pcb = crate::udp::udp_new();
    assert!(!pcb.is_null());
    // SAFETY: a fresh PCB; a null address binds to any.
    unsafe {
        assert_eq!(crate::udp::udp_bind(pcb, ptr::null(), port), ERR_OK);
        crate::udp::udp_recv(pcb, Some(count_recv), ptr::null_mut());
    }
    pcb
}

#[test]
fn fragments_are_dropped_without_reassembly() {
    with_test_netif(|netif| {
        let listener = udp_listener(9);
        let before = UDP_RECEIVED.load(Relaxed);
        for (offset, more) in [(0, true), (25, false)] {
            let mut bytes = ip_header(
                ip4(192, 168, 0, 2),
                TEST_IPADDR,
                IP_PROTO_UDP,
                200,
                offset | if more { IP_MF } else { 0 },
            );
            // The first fragment starts with a UDP header to the listener's port.
            bytes.extend([0, 67, 0, 9]);
            bytes.extend([0_u8; 196]);
            // SAFETY: a live netif; the packet is given up.
            assert_eq!(unsafe { ip4_input(packet(&bytes), netif) }, ERR_OK);
        }
        assert_eq!(
            UDP_RECEIVED.load(Relaxed),
            before,
            "no fragment reaches UDP"
        );
        // SAFETY: a PCB from udp_new.
        unsafe { crate::udp::udp_remove(listener) };
    });
}

#[test]
fn input_accepts_ours_and_dhcp_and_drops_the_rest() {
    with_test_netif(|netif| {
        let listeners = [udp_listener(9), udp_listener(68)];
        let deliver = |src: Ip4Addr, dest: Ip4Addr, udp_dest: u16| {
            let mut bytes = ip_header(src, dest, IP_PROTO_UDP, 8, 0);
            bytes.extend(67_u16.to_be_bytes());
            bytes.extend(udp_dest.to_be_bytes());
            bytes.extend([0, 8, 0, 0]);
            let before = UDP_RECEIVED.load(Relaxed);
            // SAFETY: a live netif; the packet is given up.
            unsafe { ip4_input(packet(&bytes), netif) };
            UDP_RECEIVED.load(Relaxed) - before
        };
        // To us, and to the subnet broadcast.
        assert_eq!(deliver(ip4(192, 168, 0, 2), TEST_IPADDR, 9), 1);
        assert_eq!(deliver(ip4(192, 168, 0, 2), ip4(192, 168, 255, 255), 9), 1);
        // To someone else: dropped, unless it is a DHCP reply.
        assert_eq!(deliver(ip4(10, 0, 0, 1), ip4(10, 0, 0, 9), 9), 0);
        assert_eq!(deliver(ip4(10, 0, 0, 1), ip4(10, 0, 0, 9), 68), 1);
        // From a broadcast or multicast source: dropped.
        assert_eq!(deliver(ip4(255, 255, 255, 255), TEST_IPADDR, 9), 0);
        assert_eq!(deliver(ip4(224, 0, 0, 1), TEST_IPADDR, 9), 0);
        // Not IPv4, or a length longer than the pbuf: dropped.
        let mut v6 = ip_header(ip4(192, 168, 0, 2), TEST_IPADDR, IP_PROTO_UDP, 8, 0);
        v6[0] = 0x65;
        v6.extend([0; 8]);
        // SAFETY: a live netif; the packets are given up.
        unsafe {
            assert_eq!(ip4_input(packet(&v6), netif), ERR_OK);
            let mut long = ip_header(ip4(192, 168, 0, 2), TEST_IPADDR, IP_PROTO_UDP, 100, 0);
            long.extend([0; 8]);
            assert_eq!(ip4_input(packet(&long), netif), ERR_OK);
            for pcb in listeners {
                crate::udp::udp_remove(pcb);
            }
        }
    });
}

#[test]
fn output_builds_the_header_and_its_checksum() {
    with_test_netif(|netif| {
        // SAFETY: a live netif, fresh pbufs, and valid addresses.
        unsafe {
            (*netif).output = Some(arpless_output);
            let p = pbuf_alloc(crate::config::PBUF_IP_LAYER as PbufLayer, 4, PBUF_RAM);
            let dest = ip4(192, 168, 0, 9);
            // A null source is replaced by the netif's address.
            assert_eq!(
                ip4_output_if(p, ptr::null(), &dest, 32, 0x10, IP_PROTO_UDP, netif),
                ERR_OK
            );
            pbuf_free(p);
            let pkt = LINKOUTPUT_PKT.lock().unwrap().clone();
            assert_eq!(pkt.len(), 24);
            assert_eq!(pkt[0], 0x45);
            assert_eq!(pkt[1], 0x10);
            assert_eq!(&pkt[2..4], &24_u16.to_be_bytes());
            assert_eq!(pkt[8], 32);
            assert_eq!(pkt[9], IP_PROTO_UDP);
            assert_eq!(&pkt[12..16], &TEST_IPADDR.addr.to_ne_bytes());
            assert_eq!(&pkt[16..20], &dest.addr.to_ne_bytes());
            // The inline checksum verifies.
            assert_eq!(inet_chksum(pkt.as_ptr().cast(), IP_HLEN), 0);

            // Options are padded to 4 bytes and counted in the header length.
            let p = pbuf_alloc(crate::config::PBUF_IP_LAYER as PbufLayer, 4, PBUF_RAM);
            let mut options = [0x94_u8, 0x04, 0x00];
            assert_eq!(
                ip4_output_if_opt(
                    p,
                    ptr::null(),
                    &dest,
                    32,
                    0,
                    IP_PROTO_UDP,
                    netif,
                    options.as_mut_ptr().cast(),
                    3
                ),
                ERR_OK
            );
            pbuf_free(p);
            let pkt = LINKOUTPUT_PKT.lock().unwrap().clone();
            assert_eq!(pkt[0], 0x46);
            assert_eq!(&pkt[20..24], &[0x94, 0x04, 0x00, 0x00]);
            assert_eq!(inet_chksum(pkt.as_ptr().cast(), 24), 0);

            // Too many options.
            let p = pbuf_alloc(crate::config::PBUF_IP_LAYER as PbufLayer, 4, PBUF_RAM);
            let mut big = [0_u8; 44];
            assert_eq!(
                ip4_output_if_opt(
                    p,
                    ptr::null(),
                    &dest,
                    32,
                    0,
                    IP_PROTO_UDP,
                    netif,
                    big.as_mut_ptr().cast(),
                    44
                ),
                ERR_VAL
            );
            pbuf_free(p);

            // No route: ERR_RTE.
            let p = pbuf_alloc(crate::config::PBUF_IP_LAYER as PbufLayer, 4, PBUF_RAM);
            assert_eq!(
                ip4_output(p, ptr::null(), &ip4(127, 0, 0, 1), 32, 0, IP_PROTO_UDP),
                ERR_RTE
            );
            pbuf_free(p);
        }
    });
}

#[test]
fn route_prefers_the_subnet_then_the_default() {
    with_test_netif(|netif| {
        // SAFETY: valid addresses.
        unsafe {
            assert_eq!(ip4_route(&ip4(192, 168, 7, 7)), netif);
            assert_eq!(ip4_route(&ip4(8, 8, 8, 8)), netif, "the default netif");
            assert!(ip4_route(&ip4(127, 0, 0, 1)).is_null());
            assert_eq!(ip4_route_src(&TEST_IPADDR, &ip4(8, 8, 8, 8)), netif);
            // A default multicast netif takes multicast destinations.
            ip4_set_default_multicast_netif(netif);
            assert_eq!(ip4_route(&ip4(239, 1, 2, 3)), netif);
            ip4_set_default_multicast_netif(ptr::null_mut());
        }
    });
}
