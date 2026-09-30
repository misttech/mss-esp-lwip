// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! Fragment headers: offsets, the more-fragments flag, lengths, and checksums.
//! test_ip4.c's test_ip4_frag counts the fragments; it is with the ip4 tests.

extern crate std;

use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::Mutex;
use std::vec::Vec;

use super::*;
use crate::ip4::tests::{TEST_IPADDR, ip_header, ip4, packet, with_test_netif};

static FRAGMENTS: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());
static SENT: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn record_output(
    _netif: *mut Netif,
    p: *mut Pbuf,
    _dest: *const Ip4Addr,
) -> ErrT {
    SENT.fetch_add(1, Relaxed);
    // SAFETY: a live pbuf in one piece.
    let bytes =
        unsafe { core::slice::from_raw_parts((*p).payload.cast::<u8>(), usize::from((*p).len)) };
    FRAGMENTS.lock().unwrap().push(bytes.to_vec());
    ERR_OK
}

#[test]
fn a_datagram_is_cut_on_8_byte_boundaries_with_valid_headers() {
    with_test_netif(|netif| {
        FRAGMENTS.lock().unwrap().clear();
        let dest = ip4(192, 168, 0, 9);
        let mut bytes = ip_header(TEST_IPADDR, dest, IP_PROTO_TCP, 1000, 0);
        bytes.extend((0..1000).map(|i| i as u8));
        // SAFETY: a live netif and packet, and a valid address.
        unsafe {
            (*netif).mtu = 420;
            (*netif).output = Some(record_output);
            let p = packet(&bytes);
            assert_eq!(ip4_frag(p, netif, &dest), ERR_OK);
            crate::links::pbuf_free(p);
        }
        let fragments = FRAGMENTS.lock().unwrap().clone();
        // (420 - 20) / 8 * 8 = 400 bytes each: 400, 400, 200.
        assert_eq!(
            fragments.iter().map(|f| f.len()).collect::<Vec<_>>(),
            [420, 420, 220]
        );
        let mut payload: Vec<u8> = Vec::new();
        for (i, f) in fragments.iter().enumerate() {
            let offset = u16::from_be_bytes([f[6], f[7]]);
            assert_eq!(offset & IP_OFFMASK, i as u16 * 50);
            assert_eq!(offset & IP_MF != 0, i < 2, "MF on all but the last");
            assert_eq!(u16::from_be_bytes([f[2], f[3]]) as usize, f.len());
            // SAFETY: a live buffer.
            assert_eq!(unsafe { inet_chksum(f.as_ptr().cast(), IP_HLEN) }, 0);
            payload.extend(&f[20..]);
        }
        assert_eq!(payload, &bytes[20..]);
    });
}

#[test]
fn a_fragment_keeps_its_more_fragments_flag_and_options_are_refused() {
    with_test_netif(|netif| {
        FRAGMENTS.lock().unwrap().clear();
        let dest = ip4(192, 168, 0, 9);
        // SAFETY: live netif and packets.
        unsafe {
            (*netif).mtu = 420;
            (*netif).output = Some(record_output);
            let mut bytes = ip_header(TEST_IPADDR, dest, IP_PROTO_TCP, 500, IP_MF | 10);
            bytes.extend([0_u8; 500]);
            let p = packet(&bytes);
            assert_eq!(ip4_frag(p, netif, &dest), ERR_OK);
            crate::links::pbuf_free(p);
            let fragments = FRAGMENTS.lock().unwrap().clone();
            let last = fragments.last().unwrap();
            let offset = u16::from_be_bytes([last[6], last[7]]);
            assert_ne!(offset & IP_MF, 0, "the input already had MF");
            assert_eq!(offset & IP_OFFMASK, 10 + 50);

            // A header with options is not fragmented.
            let mut with_options = ip_header(TEST_IPADDR, dest, IP_PROTO_TCP, 500, 0);
            with_options[0] = 0x46;
            with_options.extend([0_u8; 504]);
            let p = packet(&with_options);
            assert_eq!(ip4_frag(p, netif, ptr::addr_of!(dest)), ERR_VAL);
            crate::links::pbuf_free(p);
        }
    });
}
