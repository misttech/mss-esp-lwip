// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! ethernet.c has no lwIP unit test; these check its documented behavior: dispatch by
//! ethertype, link-layer broadcast and multicast flags, the input netif's index, and the
//! header ethernet_output builds.

extern crate std;

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering::Relaxed};
use std::boxed::Box;
use std::vec::Vec;

use super::*;
use crate::config;
use crate::test_support::{IP4_INPUTS, IP6_INPUTS, serial};

fn new_netif(flags: u8) -> Box<Netif> {
    // SAFETY: every field of the mirror is valid zeroed.
    let mut netif: Box<Netif> = Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
    netif.flags = flags;
    netif.num = 3;
    netif.hwaddr_len = ETH_HWADDR_LEN as u8;
    netif.hwaddr[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    netif
}

/// A frame to `dest` of `ethertype`, with `payload_len` bytes after the header.
fn frame(dest: [u8; 6], ethertype: u16, payload_len: u16) -> *mut Pbuf {
    // SAFETY: the test owns the fresh pbuf.
    let p = unsafe { pbuf_alloc_for_test(SIZEOF_ETH_HDR + payload_len) };
    let mut bytes = Vec::from(dest);
    bytes.extend([2, 0, 0, 0, 0, 2]);
    bytes.extend(ethertype.to_be_bytes());
    // SAFETY: the pbuf's payload is at least the header.
    unsafe { ptr::copy(bytes.as_ptr(), (*p).payload.cast::<u8>(), bytes.len()) };
    p
}

/// `pbuf_alloc(PBUF_RAW, len, PBUF_RAM)`.
///
/// # Safety
///
/// None; the caller owns the result.
unsafe fn pbuf_alloc_for_test(len: u16) -> *mut Pbuf {
    // SAFETY: pbuf_alloc takes any length.
    let p = unsafe { crate::links::pbuf_alloc(PBUF_RAW, len, PBUF_RAM) };
    assert!(!p.is_null());
    p
}

#[test]
fn frames_are_dispatched_by_ethertype_and_flagged_by_destination() {
    let _serial = serial();
    let mut netif = new_netif(NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET);
    let n = &mut *netif as *mut Netif;
    let (ip4_before, ip6_before) = (IP4_INPUTS.load(Relaxed), IP6_INPUTS.load(Relaxed));

    // SAFETY: fresh frames, given up to ethernet_input, and a live netif.
    unsafe {
        let p = frame([0xff; 6], ETHTYPE_IP, 20);
        // Keep the pbuf alive past the stand-in's free, to look at its flags.
        crate::links::pbuf_ref(p);
        assert_eq!(ethernet_input(p, n), ERR_OK);
        assert_eq!((*p).flags & PBUF_FLAG_LLBCAST, PBUF_FLAG_LLBCAST);
        assert_eq!((*p).if_idx, 4, "the netif's index");
        assert_eq!((*p).len, 20, "the Ethernet header is hidden");
        crate::links::pbuf_free(p);

        let p = frame([0x01, 0x00, 0x5e, 1, 2, 3], ETHTYPE_IP, 20);
        crate::links::pbuf_ref(p);
        ethernet_input(p, n);
        assert_eq!((*p).flags & PBUF_FLAG_LLMCAST, PBUF_FLAG_LLMCAST);
        crate::links::pbuf_free(p);

        let p = frame([0x33, 0x33, 0, 0, 0, 1], ETHTYPE_IPV6, 40);
        crate::links::pbuf_ref(p);
        ethernet_input(p, n);
        assert_eq!((*p).flags & PBUF_FLAG_LLMCAST, PBUF_FLAG_LLMCAST);
        crate::links::pbuf_free(p);

        assert_eq!(IP4_INPUTS.load(Relaxed) - ip4_before, 2);
        assert_eq!(IP6_INPUTS.load(Relaxed) - ip6_before, 1);
    }
}

#[test]
fn short_unknown_and_unrouted_frames_are_dropped() {
    let _serial = serial();
    let ip4_before = IP4_INPUTS.load(Relaxed);
    let mut plain = new_netif(NETIF_FLAG_ETHERNET);
    let mut etharp = new_netif(NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET);
    // SAFETY: fresh frames, given up to ethernet_input, and live netifs.
    unsafe {
        // Only a header (or less).
        assert_eq!(
            ethernet_input(frame([2; 6], ETHTYPE_IP, 0), &mut *etharp),
            ERR_OK
        );
        // An ethertype nobody handles.
        assert_eq!(
            ethernet_input(frame([2; 6], 0x88cc, 20), &mut *etharp),
            ERR_OK
        );
        // IPv4 and ARP need a netif that does ARP.
        assert_eq!(
            ethernet_input(frame([2; 6], ETHTYPE_IP, 20), &mut *plain),
            ERR_OK
        );
        assert_eq!(
            ethernet_input(frame([2; 6], ETHTYPE_ARP, 28), &mut *plain),
            ERR_OK
        );
    }
    assert_eq!(IP4_INPUTS.load(Relaxed), ip4_before);
}

static SENT: AtomicPtr<Pbuf> = AtomicPtr::new(ptr::null_mut());
static SENDS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn record_linkoutput(_netif: *mut Netif, p: *mut Pbuf) -> ErrT {
    SENDS.fetch_add(1, Relaxed);
    SENT.store(p, Relaxed);
    ERR_OK
}

#[test]
fn output_prepends_the_header_and_hands_the_frame_to_the_driver() {
    let _serial = serial();
    let mut netif = new_netif(NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET);
    netif.linkoutput = Some(record_linkoutput);
    let src = EthAddr {
        addr: [2, 0, 0, 0, 0, 1],
    };
    let dst = EthAddr {
        addr: [2, 0, 0, 0, 0, 9],
    };
    // SAFETY: a live netif and pbufs, and valid addresses.
    unsafe {
        let p = crate::links::pbuf_alloc(config::PBUF_LINK_LAYER as PbufLayer, 10, PBUF_RAM);
        assert_eq!(
            ethernet_output(&mut *netif, p, &src, &dst, ETHTYPE_ARP),
            ERR_OK
        );
        assert_eq!(SENT.load(Relaxed), p);
        assert_eq!((*p).len, 24);
        let header = core::slice::from_raw_parts((*p).payload.cast::<u8>(), 14);
        assert_eq!(&header[..6], &dst.addr);
        assert_eq!(&header[6..12], &src.addr);
        assert_eq!(&header[12..], &[0x08, 0x06]);
        crate::links::pbuf_free(p);

        // No room in front of the payload: ERR_BUF, and the driver is not called.
        let sends = SENDS.load(Relaxed);
        let p = crate::links::pbuf_alloc(PBUF_RAW, 10, PBUF_RAM);
        assert_eq!(
            ethernet_output(&mut *netif, p, &src, &dst, ETHTYPE_IP),
            ERR_BUF
        );
        assert_eq!(SENDS.load(Relaxed), sends);
        crate::links::pbuf_free(p);
    }
    assert_eq!(ethbroadcast.addr, [0xff; 6]);
    assert_eq!(ethzero.addr, [0; 6]);
}
