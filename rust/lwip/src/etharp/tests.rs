// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! test/unit/etharp/test_etharp.c. The C test sends through `udp_sendto`, which reaches
//! ARP through the netif's `output`, `etharp_output`; UDP is not ported, so this one
//! calls `etharp_output` itself, with the same destinations and checks.

extern crate std;

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering::Relaxed};
use std::boxed::Box;
use std::vec::Vec;

use super::*;
use crate::netif::{netif_add, netif_default, netif_remove, netif_set_default, netif_set_up};
use crate::test_support::serial;

static LINKOUTPUT_CTR: AtomicI32 = AtomicI32::new(0);
static TEST_NETIF: AtomicPtr<Netif> = AtomicPtr::new(ptr::null_mut());

const TEST_ETHADDR: EthAddr = EthAddr {
    addr: [1, 1, 1, 1, 1, 1],
};
const TEST_ETHADDR2: EthAddr = EthAddr {
    addr: [1, 1, 1, 1, 1, 2],
};
const TEST_ETHADDR3: EthAddr = EthAddr {
    addr: [1, 1, 1, 1, 1, 3],
};
const TEST_ETHADDR4: EthAddr = EthAddr {
    addr: [1, 1, 1, 1, 1, 4],
};

const fn ip4(a: u8, b: u8, c: u8, d: u8) -> Ip4Addr {
    Ip4Addr {
        addr: u32::from_be_bytes([a, b, c, d]).to_be(),
    }
}

const TEST_IPADDR: Ip4Addr = ip4(192, 168, 0, 1);

/// Call etharp_tmr often enough to have all entries cleaned.
fn etharp_remove_all() {
    for _ in 0..0xff {
        etharp_tmr();
    }
}

unsafe extern "C" fn default_netif_linkoutput(netif: *mut Netif, p: *mut Pbuf) -> ErrT {
    assert_eq!(netif, TEST_NETIF.load(Relaxed));
    assert!(!p.is_null());
    LINKOUTPUT_CTR.fetch_add(1, Relaxed);
    ERR_OK
}

unsafe extern "C" fn default_netif_init(netif: *mut Netif) -> ErrT {
    assert!(!netif.is_null());
    // SAFETY: the netif being added.
    unsafe {
        (*netif).linkoutput = Some(default_netif_linkoutput);
        (*netif).output = Some(etharp_output);
        (*netif).mtu = 1500;
        (*netif).flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_LINK_UP;
        (*netif).hwaddr_len = ETH_HWADDR_LEN as u8;
    }
    ERR_OK
}

/// etharp_setup and etharp_teardown around `test`, with the test netif.
fn with_default_netif(test: impl FnOnce(*mut Netif)) {
    let _serial = serial();
    etharp_remove_all();
    // SAFETY: every field of the mirror is valid zeroed.
    let mut netif: Box<Netif> = Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
    let n = &mut *netif as *mut Netif;
    TEST_NETIF.store(n, Relaxed);
    let (test_gw, test_netmask) = (ip4(192, 168, 0, 1), ip4(255, 255, 0, 0));
    assert!(netif_default.get().is_null());
    // SAFETY: the netif outlives its time on the list.
    unsafe {
        netif_set_default(netif_add(
            n,
            &TEST_IPADDR,
            &test_netmask,
            &test_gw,
            ptr::null_mut(),
            Some(default_netif_init),
            None,
        ));
        netif_set_up(n);
    }

    test(n);

    etharp_remove_all();
    assert_eq!(netif_default.get(), n);
    // SAFETY: on the list.
    unsafe { netif_remove(n) };
}

/// An ARP reply from TEST_ETHADDR2 for `adr`, through ethernet_input.
fn create_arp_response(netif: *mut Netif, adr: &Ip4Addr) {
    let mut frame = Vec::new();
    frame.extend(TEST_ETHADDR.addr);
    frame.extend(TEST_ETHADDR2.addr);
    frame.extend(ETHTYPE_ARP.to_be_bytes());
    frame.extend(LWIP_IANA_HWTYPE_ETHERNET.to_be_bytes());
    frame.extend(ETHTYPE_IP.to_be_bytes());
    frame.extend([ETH_HWADDR_LEN as u8, 4]);
    frame.extend(ARP_REPLY.to_be_bytes());
    frame.extend(TEST_ETHADDR2.addr);
    frame.extend(adr.addr.to_ne_bytes());
    frame.extend(TEST_ETHADDR.addr);
    frame.extend(TEST_IPADDR.addr.to_ne_bytes());
    // SAFETY: a fresh pbuf of the frame's size, given up to ethernet_input.
    unsafe {
        let p = pbuf_alloc(PBUF_RAW, frame.len() as u16, PBUF_RAM);
        assert!(!p.is_null());
        ptr::copy(frame.as_ptr(), (*p).payload.cast::<u8>(), frame.len());
        crate::links::ethernet_input(p, netif);
    }
}

/// `udp_sendto(pcb, p, dst, 123)`'s way into ARP: a 10-byte packet with room for the
/// link header, to `dst` through the netif's output.
fn send_to(netif: *mut Netif, dst: &Ip4Addr) -> ErrT {
    // SAFETY: a fresh pbuf; the sender keeps its reference and frees it, as udp_sendto's
    // caller does.
    unsafe {
        let p = pbuf_alloc(config::PBUF_LINK_LAYER as PbufLayer, 10, PBUF_RAM);
        assert!(!p.is_null());
        let err = etharp_output(netif, p, dst);
        pbuf_free(p);
        err
    }
}

fn find(adr: &Ip4Addr) -> isize {
    let mut eth: *mut EthAddr = ptr::null_mut();
    let mut ip: *const Ip4Addr = ptr::null();
    // SAFETY: valid address and out-pointers.
    unsafe { etharp_find_addr(ptr::null_mut(), adr, &mut eth, &mut ip) }
}

#[test]
fn test_etharp_table() {
    with_default_netif(|netif| {
        assert_eq!(
            netif_default.get(),
            netif,
            "This test needs a default netif"
        );
        LINKOUTPUT_CTR.store(0, Relaxed);

        let adrs: Vec<Ip4Addr> = (0..ARP_TABLE_SIZE + 2)
            .map(|i| ip4(192, 168, 0, i as u8 + 2))
            .collect();
        // Fill ARP-table with dynamic entries.
        for (i, adr) in adrs.iter().enumerate().take(ARP_TABLE_SIZE) {
            assert_eq!(send_to(netif, adr), ERR_OK);
            // etharp request sent?
            assert_eq!(LINKOUTPUT_CTR.load(Relaxed), 2 * i as i32 + 1);
            // Create an ARP response.
            create_arp_response(netif, adr);
            // Queued UDP packet sent?
            assert_eq!(LINKOUTPUT_CTR.load(Relaxed), 2 * i as i32 + 2);
            assert_eq!(find(adr), i as isize);
            etharp_tmr();
        }
        LINKOUTPUT_CTR.store(0, Relaxed);
        // Create one static entry.
        let mut ethaddr3 = TEST_ETHADDR3;
        // SAFETY: valid addresses; ip4_route's stand-in routes to the default netif.
        assert_eq!(
            unsafe { etharp_add_static_entry(&adrs[ARP_TABLE_SIZE], &mut ethaddr3) },
            ERR_OK
        );
        assert_eq!(find(&adrs[ARP_TABLE_SIZE]), 0);
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), 0);

        LINKOUTPUT_CTR.store(0, Relaxed);
        // Fill ARP-table with dynamic entries.
        for (i, adr) in adrs.iter().enumerate().take(ARP_TABLE_SIZE) {
            assert_eq!(send_to(netif, adr), ERR_OK);
            // etharp request sent?
            assert_eq!(LINKOUTPUT_CTR.load(Relaxed), 2 * i as i32 + 1);
            // Create an ARP response.
            create_arp_response(netif, adr);
            // Queued UDP packet sent?
            assert_eq!(LINKOUTPUT_CTR.load(Relaxed), 2 * i as i32 + 2);
            let idx = find(adr);
            if i < ARP_TABLE_SIZE - 1 {
                assert_eq!(idx, i as isize + 1);
            } else {
                // The last entry must not overwrite the static entry!
                assert_eq!(idx, 1);
            }
            etharp_tmr();
        }
        // Create a second static entry.
        let mut ethaddr4 = TEST_ETHADDR4;
        // SAFETY: as above.
        unsafe {
            assert_eq!(
                etharp_add_static_entry(&adrs[ARP_TABLE_SIZE + 1], &mut ethaddr4),
                ERR_OK
            );
            assert_eq!(find(&adrs[ARP_TABLE_SIZE]), 0);
            assert_eq!(find(&adrs[ARP_TABLE_SIZE + 1]), 2);
            // And remove it again.
            assert_eq!(
                etharp_remove_static_entry(&adrs[ARP_TABLE_SIZE + 1]),
                ERR_OK
            );
            assert_eq!(find(&adrs[ARP_TABLE_SIZE]), 0);
            assert_eq!(find(&adrs[ARP_TABLE_SIZE + 1]), -1);
        }

        // Check that static entries don't time out.
        etharp_remove_all();
        assert_eq!(find(&adrs[ARP_TABLE_SIZE]), 0);

        // Remove the first static entry.
        // SAFETY: a valid address.
        assert_eq!(
            unsafe { etharp_remove_static_entry(&adrs[ARP_TABLE_SIZE]) },
            ERR_OK
        );
        assert_eq!(find(&adrs[ARP_TABLE_SIZE]), -1);
        assert_eq!(find(&adrs[ARP_TABLE_SIZE + 1]), -1);
    });
}

// Beyond test_etharp.c.

#[test]
fn a_pending_entry_queues_at_most_arp_queue_len_packets() {
    with_default_netif(|netif| {
        LINKOUTPUT_CTR.store(0, Relaxed);
        let dst = ip4(192, 168, 7, 7);
        assert_eq!(send_to(netif, &dst), ERR_OK);
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), 1, "one request");
        for _ in 1..config::ARP_QUEUE_LEN {
            assert_eq!(send_to(netif, &dst), ERR_OK);
        }
        // The queue is full: the next packet is refused.
        assert_eq!(send_to(netif, &dst), ERR_MEM);
        // The reply sends everything queued.
        create_arp_response(netif, &dst);
        assert_eq!(
            LINKOUTPUT_CTR.load(Relaxed),
            1 + config::ARP_QUEUE_LEN as i32
        );
        // Now stable: a packet goes straight out, without a request.
        assert_eq!(send_to(netif, &dst), ERR_OK);
        assert_eq!(
            LINKOUTPUT_CTR.load(Relaxed),
            2 + config::ARP_QUEUE_LEN as i32
        );
    });
}

#[test]
fn broadcast_multicast_and_offlink_destinations() {
    with_default_netif(|netif| {
        LINKOUTPUT_CTR.store(0, Relaxed);
        // Broadcast and multicast go out directly.
        assert_eq!(send_to(netif, &ip4(255, 255, 255, 255)), ERR_OK);
        assert_eq!(send_to(netif, &ip4(224, 0, 0, 251)), ERR_OK);
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), 2);
        // Off the subnet: resolved through the gateway, which is this host here, so a
        // request goes out for it.
        assert_eq!(send_to(netif, &ip4(10, 0, 0, 1)), ERR_OK);
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), 3);
        // Non-unicast addresses are refused by etharp_query.
        // SAFETY: a live netif and valid address.
        unsafe {
            assert_eq!(
                etharp_query(netif, &ip4(0, 0, 0, 0), ptr::null_mut()),
                ERR_ARG
            );
            assert_eq!(
                etharp_query(netif, &ip4(224, 1, 2, 3), ptr::null_mut()),
                ERR_ARG
            );
            // An implicit query (no packet) only sends a request.
            assert_eq!(
                etharp_query(netif, &ip4(192, 168, 9, 9), ptr::null_mut()),
                ERR_OK
            );
        }
        assert_eq!(LINKOUTPUT_CTR.load(Relaxed), 4);
    });
}

#[test]
fn a_request_for_us_is_answered_and_entries_can_be_listed() {
    with_default_netif(|netif| {
        LINKOUTPUT_CTR.store(0, Relaxed);
        // A request from 192.168.0.9 for our address.
        let peer = ip4(192, 168, 0, 9);
        let mut frame = Vec::new();
        frame.extend([0xff; 6]);
        frame.extend(TEST_ETHADDR2.addr);
        frame.extend(ETHTYPE_ARP.to_be_bytes());
        frame.extend(LWIP_IANA_HWTYPE_ETHERNET.to_be_bytes());
        frame.extend(ETHTYPE_IP.to_be_bytes());
        frame.extend([ETH_HWADDR_LEN as u8, 4]);
        frame.extend(ARP_REQUEST.to_be_bytes());
        frame.extend(TEST_ETHADDR2.addr);
        frame.extend(peer.addr.to_ne_bytes());
        frame.extend([0; 6]);
        frame.extend(TEST_IPADDR.addr.to_ne_bytes());
        // SAFETY: a fresh pbuf given up to ethernet_input; live out-pointers.
        unsafe {
            let p = pbuf_alloc(PBUF_RAW, frame.len() as u16, PBUF_RAM);
            ptr::copy(frame.as_ptr(), (*p).payload.cast::<u8>(), frame.len());
            crate::links::ethernet_input(p, netif);
            assert_eq!(LINKOUTPUT_CTR.load(Relaxed), 1, "a reply");
            // The requester is now in the table.
            let (mut ip, mut owner, mut eth) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
            let i = find(&peer);
            assert!(i >= 0);
            assert_eq!(
                etharp_get_entry(i as usize, &mut ip, &mut owner, &mut eth),
                1
            );
            assert_eq!((*ip).addr, peer.addr);
            assert_eq!(owner, netif);
            assert_eq!((*eth).addr, TEST_ETHADDR2.addr);
            assert_eq!(
                etharp_get_entry(ARP_TABLE_SIZE, &mut ip, &mut owner, &mut eth),
                0
            );
            // A netif going down forgets its entries.
            etharp_cleanup_netif(netif);
            assert_eq!(find(&peer), -1);
        }
    });
}
