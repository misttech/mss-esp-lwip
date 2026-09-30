// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! ICMP echo through ip4_input; destination-unreachable replies are in the ip4 tests
//! (test_ip4.c's reply-length cases).

extern crate std;

use core::sync::atomic::Ordering::Relaxed;

use crate::ip4::ip4_input;
use crate::ip4::tests::{
    LINKOUTPUT_CTR, LINKOUTPUT_PKT, TEST_IPADDR, arpless_output, ip_header, ip4, packet,
    with_test_netif,
};
use crate::links::inet_chksum;
use crate::types::*;

/// An echo request to `dest` with `data`, its ICMP checksum filled in.
fn echo_request(dest: Ip4Addr, data: &[u8]) -> std::vec::Vec<u8> {
    let mut icmp = std::vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
    icmp.extend(data);
    // SAFETY: a live buffer.
    let sum = unsafe { inet_chksum(icmp.as_ptr().cast(), icmp.len() as u16) };
    icmp[2..4].copy_from_slice(&sum.to_ne_bytes());
    let mut bytes = ip_header(
        ip4(192, 168, 0, 2),
        dest,
        IP_PROTO_ICMP,
        icmp.len() as u16,
        0,
    );
    bytes.extend(icmp);
    bytes
}

#[test]
fn an_echo_request_is_answered_with_a_valid_reply() {
    with_test_netif(|netif| {
        // SAFETY: a live netif; the packet is given up to ip4_input.
        unsafe {
            (*netif).output = Some(arpless_output);
            ip4_input(packet(&echo_request(TEST_IPADDR, b"ping")), netif);
        }
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), 1);
        let pkt = LINKOUTPUT_PKT.lock().unwrap().clone();
        // Addresses swapped, TTL reset, header checksum valid.
        assert_eq!(&pkt[12..16], &TEST_IPADDR.addr.to_ne_bytes());
        assert_eq!(&pkt[16..20], &ip4(192, 168, 0, 2).addr.to_ne_bytes());
        assert_eq!(pkt[8], crate::config::ICMP_TTL as u8);
        // SAFETY: live buffers.
        unsafe {
            assert_eq!(inet_chksum(pkt.as_ptr().cast(), IP_HLEN), 0);
            // An echo reply, same id, sequence, and data, and the adjusted checksum
            // verifies.
            assert_eq!(pkt[20], 0);
            assert_eq!(&pkt[24..], &[0x12, 0x34, 0, 1, b'p', b'i', b'n', b'g']);
            assert_eq!(
                inet_chksum(pkt[20..].as_ptr().cast(), (pkt.len() - 20) as u16),
                0
            );
        }
    });
}

#[test]
fn bad_checksums_broadcasts_and_replies_are_not_answered() {
    with_test_netif(|netif| {
        // SAFETY: a live netif; the packets are given up to ip4_input.
        unsafe {
            (*netif).output = Some(arpless_output);
            let mut bad = echo_request(TEST_IPADDR, b"ping");
            bad[22] ^= 0xff;
            ip4_input(packet(&bad), netif);
            ip4_input(
                packet(&echo_request(ip4(192, 168, 255, 255), b"ping")),
                netif,
            );
            let mut reply = echo_request(TEST_IPADDR, b"pong");
            reply[20] = 0;
            ip4_input(packet(&reply), netif);
        }
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), 0);
    });
}
