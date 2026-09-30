// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! test/unit/core/test_netif.c, plus the loopback queue, IPv6 addresses, and indexes.

extern crate std;

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, AtomicU16, Ordering::Relaxed};
use std::boxed::Box;

use super::*;
use crate::ethernet::ethernet_input;
use crate::test_support::{IP_INPUTS, serial};

/// A netif as a C caller allocates one: zeroed storage at a stable address.
fn new_netif() -> Box<Netif> {
    // SAFETY: every field of the mirror is valid zeroed: integers, null pointers, and
    // `None` callbacks.
    Box::new(unsafe { MaybeUninit::zeroed().assume_init() })
}

unsafe extern "C" fn testif_tx_func(_netif: *mut Netif, _p: *mut Pbuf) -> ErrT {
    ERR_OK
}

/// test_netif.c's testif_init. `output` stays netif_add's null output: ARP is not part
/// of these tests.
unsafe extern "C" fn testif_init(netif: *mut Netif) -> ErrT {
    // SAFETY: the netif being added.
    unsafe {
        (*netif).name = [b'c' as c_char, b'h' as c_char];
        (*netif).linkoutput = Some(testif_tx_func);
        (*netif).mtu = 1500;
        (*netif).hwaddr_len = 6;
        (*netif).flags = NETIF_FLAG_BROADCAST
            | NETIF_FLAG_ETHARP
            | NETIF_FLAG_ETHERNET
            | NETIF_FLAG_IGMP
            | NETIF_FLAG_MLD6;
        (*netif).hwaddr = [0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    }
    ERR_OK
}

static EXPECTED_REASONS: AtomicU16 = AtomicU16::new(0);
static CALLBACK_CTR: AtomicI32 = AtomicI32::new(0);
static DUMMY_ACTIVE: AtomicBool = AtomicBool::new(false);
static NET_TEST: AtomicPtr<Netif> = AtomicPtr::new(ptr::null_mut());

unsafe extern "C" fn test_netif_ext_callback_dummy(
    _netif: *mut Netif,
    _reason: NetifNscReason,
    _args: *const NetifExtCallbackArgs,
) {
    assert!(DUMMY_ACTIVE.load(Relaxed));
}

unsafe extern "C" fn test_netif_ext_callback(
    netif: *mut Netif,
    reason: NetifNscReason,
    _args: *const NetifExtCallbackArgs,
) {
    CALLBACK_CTR.fetch_add(1, Relaxed);
    assert_eq!(netif, NET_TEST.load(Relaxed));
    assert_eq!(EXPECTED_REASONS.load(Relaxed), reason);
}

fn new_callback() -> Box<NetifExtCallback> {
    Box::new(NetifExtCallback {
        callback_fn: None,
        next: ptr::null_mut(),
    })
}

/// Expect one callback for `reason` from `action`.
fn expect(reason: NetifNscReason, count: i32, action: impl FnOnce()) {
    EXPECTED_REASONS.store(reason, Relaxed);
    CALLBACK_CTR.store(0, Relaxed);
    action();
    assert_eq!(CALLBACK_CTR.load(Relaxed), count, "reason {reason:#x}");
}

#[test]
fn test_netif_extcallbacks() {
    let _serial = serial();
    let mut net_test = new_netif();
    let net = &mut *net_test as *mut Netif;
    NET_TEST.store(net, Relaxed);
    let mut addr = ip4(0, 0, 0, 0);
    let mut netmask = ip4(0, 0, 0, 0);
    let mut gw = ip4(0, 0, 0, 0);
    let (mut cb1, mut cb2, mut cb3) = (new_callback(), new_callback(), new_callback());

    // SAFETY: the netif and callbacks outlive their registration.
    unsafe {
        netif_add_ext_callback(&mut *cb3, Some(test_netif_ext_callback_dummy));
        netif_add_ext_callback(&mut *cb2, Some(test_netif_ext_callback));
        netif_add_ext_callback(&mut *cb1, Some(test_netif_ext_callback_dummy));

        DUMMY_ACTIVE.store(true, Relaxed);

        // Positive tests: check that single events come as expected.
        expect(LWIP_NSC_NETIF_ADDED, 1, || {
            netif_add(
                net,
                &addr,
                &netmask,
                &gw,
                net.cast(),
                Some(testif_init),
                Some(ethernet_input),
            );
        });
        expect(LWIP_NSC_LINK_CHANGED, 1, || netif_set_link_up(net));
        expect(LWIP_NSC_STATUS_CHANGED, 1, || netif_set_up(net));

        addr = ip4(1, 2, 3, 4);
        expect(LWIP_NSC_IPV4_ADDRESS_CHANGED, 1, || {
            netif_set_ipaddr(net, &addr)
        });
        netmask = ip4(255, 255, 255, 0);
        expect(LWIP_NSC_IPV4_NETMASK_CHANGED, 1, || {
            netif_set_netmask(net, &netmask)
        });
        gw = ip4(1, 2, 3, 254);
        expect(LWIP_NSC_IPV4_GATEWAY_CHANGED, 1, || netif_set_gw(net, &gw));
        addr = ip4(0, 0, 0, 0);
        expect(LWIP_NSC_IPV4_ADDRESS_CHANGED, 1, || {
            netif_set_ipaddr(net, &addr)
        });
        netmask = ip4(0, 0, 0, 0);
        expect(LWIP_NSC_IPV4_NETMASK_CHANGED, 1, || {
            netif_set_netmask(net, &netmask)
        });
        gw = ip4(0, 0, 0, 0);
        expect(LWIP_NSC_IPV4_GATEWAY_CHANGED, 1, || netif_set_gw(net, &gw));

        // Check for multi-events (only one combined callback expected).
        addr = ip4(1, 2, 3, 4);
        netmask = ip4(255, 255, 255, 0);
        gw = ip4(1, 2, 3, 254);
        expect(
            LWIP_NSC_IPV4_ADDRESS_CHANGED
                | LWIP_NSC_IPV4_NETMASK_CHANGED
                | LWIP_NSC_IPV4_GATEWAY_CHANGED
                | LWIP_NSC_IPV4_SETTINGS_CHANGED
                | LWIP_NSC_IPV4_ADDR_VALID,
            1,
            || netif_set_addr(net, &addr, &netmask, &gw),
        );

        // Check that for no-change, no callback is expected.
        expect(LWIP_NSC_NONE, 0, || netif_set_ipaddr(net, &addr));
        expect(LWIP_NSC_NONE, 0, || netif_set_netmask(net, &netmask));
        expect(LWIP_NSC_NONE, 0, || netif_set_gw(net, &gw));

        // netif_set_addr() always issues at least LWIP_NSC_IPV4_ADDR_VALID.
        expect(LWIP_NSC_IPV4_ADDR_VALID, 1, || {
            netif_set_addr(net, &addr, &netmask, &gw)
        });

        // Check for single-events.
        addr = ip4(1, 2, 3, 5);
        expect(
            LWIP_NSC_IPV4_ADDRESS_CHANGED
                | LWIP_NSC_IPV4_SETTINGS_CHANGED
                | LWIP_NSC_IPV4_ADDR_VALID,
            1,
            || netif_set_addr(net, &addr, &netmask, &gw),
        );

        expect(LWIP_NSC_STATUS_CHANGED, 1, || netif_set_down(net));
        expect(LWIP_NSC_NETIF_REMOVED, 1, || netif_remove(net));

        EXPECTED_REASONS.store(LWIP_NSC_NONE, Relaxed);

        netif_remove_ext_callback(&mut *cb2);
        netif_remove_ext_callback(&mut *cb3);
        netif_remove_ext_callback(&mut *cb1);
        DUMMY_ACTIVE.store(false, Relaxed);
        assert!(EXT_CALLBACK.get().is_null());
    }
}

#[test]
fn test_netif_flag_set() {
    let _serial = serial();
    let mut net_test = new_netif();
    let net = &mut *net_test as *mut Netif;
    let any = ip4(0, 0, 0, 0);
    // SAFETY: the netif outlives its time on the list.
    unsafe {
        netif_add(
            net,
            &any,
            &any,
            &any,
            net.cast(),
            Some(testif_init),
            Some(ethernet_input),
        );
        let flags = (*net).flags;
        assert_eq!(flags & NETIF_FLAG_UP, 0);
        assert_ne!(flags & NETIF_FLAG_BROADCAST, 0);
        assert_eq!(flags & NETIF_FLAG_LINK_UP, 0);
        assert_ne!(flags & NETIF_FLAG_ETHARP, 0);
        assert_ne!(flags & NETIF_FLAG_ETHERNET, 0);
        assert_ne!(flags & NETIF_FLAG_IGMP, 0);
        assert_ne!(flags & NETIF_FLAG_MLD6, 0);
        netif_remove(net);
    }
}

#[test]
fn test_netif_find() {
    let _serial = serial();
    let (mut net0, mut net1) = (new_netif(), new_netif());
    let (n0, n1) = (&mut *net0 as *mut Netif, &mut *net1 as *mut Netif);
    // SAFETY: the netifs outlive their time on the list; the names are NUL-terminated.
    unsafe {
        // No netifs available.
        assert!(netif_find(c"ch0".as_ptr()).is_null());

        // Add netifs with known names.
        assert_eq!(
            netif_add_noaddr(n0, ptr::null_mut(), Some(testif_init), Some(ethernet_input)),
            n0
        );
        (*n0).num = 0;
        assert_eq!(
            netif_add_noaddr(n1, ptr::null_mut(), Some(testif_init), Some(ethernet_input)),
            n1
        );
        (*n1).num = 1;

        assert_eq!(netif_find(c"ch0".as_ptr()), n0);
        assert!(netif_find(c"CH0".as_ptr()).is_null());
        assert_eq!(netif_find(c"ch1".as_ptr()), n1);
        assert!(netif_find(c"ch3".as_ptr()).is_null());
        // atoi failure is not treated as zero.
        assert!(netif_find(c"chX".as_ptr()).is_null());
        assert!(netif_find(c"ab0".as_ptr()).is_null());

        // Beyond test_netif.c: indexes and names.
        assert_eq!(netif_name_to_index(c"ch1".as_ptr()), 2);
        assert_eq!(netif_get_by_index(1), n0);
        assert!(netif_get_by_index(NETIF_NO_INDEX).is_null());
        let mut name = [0 as c_char; config::NETIF_NAMESIZE];
        assert_eq!(netif_index_to_name(2, name.as_mut_ptr()), name.as_mut_ptr());
        assert_eq!(core::ffi::CStr::from_ptr(name.as_ptr()), c"ch1");
        assert!(netif_index_to_name(9, name.as_mut_ptr()).is_null());

        netif_remove(n0);
        netif_remove(n1);
        assert!(netif_list.get().is_null());
    }
}

#[test]
fn numbers_are_unique_and_the_default_is_cleared_on_remove() {
    let _serial = serial();
    let (mut a, mut b) = (new_netif(), new_netif());
    let (a, b) = (&mut *a as *mut Netif, &mut *b as *mut Netif);
    // SAFETY: the netifs outlive their time on the list.
    unsafe {
        netif_add_noaddr(a, ptr::null_mut(), Some(testif_init), Some(ethernet_input));
        netif_add_noaddr(b, ptr::null_mut(), Some(testif_init), Some(ethernet_input));
        assert_ne!((*a).num, (*b).num);
        assert_eq!(netif_list.get(), b, "added at the head");
        netif_set_default(a);
        netif_remove(a);
        assert!(netif_default.get().is_null());
        assert_eq!(netif_list.get(), b);
        netif_remove(b);
        // Nothing to add without an init function.
        assert!(netif_add_noaddr(a, ptr::null_mut(), None, None).is_null());
    }
}

#[test]
fn loopback_output_queues_copies_and_poll_delivers_them() {
    let _serial = serial();
    let mut net = new_netif();
    let n = &mut *net as *mut Netif;
    let before = IP_INPUTS.load(Relaxed);
    // SAFETY: the netif and pbufs are live; the queue is drained before the netif goes.
    unsafe {
        netif_add_noaddr(n, ptr::null_mut(), Some(testif_init), Some(ethernet_input));
        let p = pbuf_alloc(PBUF_RAW, 100, PBUF_RAM);
        assert_eq!(netif_loop_output(n, p), ERR_OK);
        assert_eq!(netif_loop_output(n, p), ERR_OK);
        pbuf_free(p);
        assert_eq!((*n).loop_cnt_current, 2);
        // The tcpip queue stand-in refuses the poll, so it is rescheduled.
        assert_eq!((*n).reschedule_poll, 1);
        // The queue is bounded by LWIP_LOOPBACK_MAX_PBUFS.
        let q = pbuf_alloc(PBUF_RAW, 10, PBUF_RAM);
        for _ in 2..config::LWIP_LOOPBACK_MAX_PBUFS {
            assert_eq!(netif_loop_output(n, q), ERR_OK);
        }
        assert_eq!(netif_loop_output(n, q), ERR_MEM);
        pbuf_free(q);

        netif_poll(n);
        assert_eq!(
            IP_INPUTS.load(Relaxed) - before,
            config::LWIP_LOOPBACK_MAX_PBUFS
        );
        assert_eq!((*n).loop_cnt_current, 0);
        assert!((*n).loop_first.is_none() && (*n).loop_last.is_none());
        netif_remove(n);
    }
}

#[test]
fn ipv6_addresses_are_matched_added_and_zoned() {
    let _serial = serial();
    let mut net = new_netif();
    let n = &mut *net as *mut Netif;
    // SAFETY: the netif is live while on the list.
    unsafe {
        netif_add_noaddr(n, ptr::null_mut(), Some(testif_init), Some(ethernet_input));

        // The link-local address from the MAC, EUI-64, tentative, in the netif's zone.
        netif_create_ip6_linklocal_address(n, 1);
        let ll = *(*n).ip6_addr[0].ip6();
        assert_eq!(
            ll.addr,
            [
                0xfe80_0000_u32.to_be(),
                0,
                0x0003_04ff_u32.to_be(),
                0xfe05_0607_u32.to_be()
            ]
        );
        assert_eq!(ll.zone, (*n).index());
        assert_eq!((*n).ip6_addr_state[0], IP6_ADDR_TENTATIVE);

        // Matching respects zones.
        assert_eq!(netif_get_ip6_addr_match(n, &ll), 0);
        let mut other_zone = ll;
        other_zone.zone = (*n).index() + 1;
        assert_eq!(netif_get_ip6_addr_match(n, &other_zone), -1);

        // A global address takes the first free slot after the link-local one.
        let global = Ip6Addr {
            addr: [0x2001_0db8_u32.to_be(), 0, 0, 1_u32.to_be()],
            zone: 0,
        };
        let mut chosen = -2;
        assert_eq!(netif_add_ip6_address(n, &global, &mut chosen), ERR_OK);
        assert_eq!(chosen, 1);
        assert_eq!(
            (*n).ip6_addr[1].ip6().zone,
            0,
            "a global address has no zone"
        );
        // Adding it again finds it.
        assert_eq!(netif_add_ip6_address(n, &global, &mut chosen), ERR_OK);
        assert_eq!(chosen, 1);

        // Set by parts, and invalidate.
        netif_ip6_addr_set_parts(n, 2, 1, 2, 3, 4);
        assert_eq!((*n).ip6_addr[2].ip6().addr, [1, 2, 3, 4]);
        netif_ip6_addr_set_state(n, 1, IP6_ADDR_VALID);
        netif_ip6_addr_set_state(n, 1, IP6_ADDR_INVALID);
        assert_eq!((*n).ip6_addr_state[1], IP6_ADDR_INVALID);

        // With every slot taken, there is no room.
        netif_ip6_addr_set_state(n, 1, IP6_ADDR_VALID);
        netif_ip6_addr_set_state(n, 2, IP6_ADDR_VALID);
        let third = Ip6Addr {
            addr: [0x2001_0db8_u32.to_be(), 0, 0, 2_u32.to_be()],
            zone: 0,
        };
        assert_eq!(netif_add_ip6_address(n, &third, &mut chosen), ERR_VAL);
        assert_eq!(chosen, -1);

        netif_remove(n);
    }
}

#[test]
fn input_dispatches_by_flags() {
    let _serial = serial();
    let mut net = new_netif();
    let n = &mut *net as *mut Netif;
    let before = IP_INPUTS.load(Relaxed);
    // SAFETY: a live netif and freshly allocated pbufs, given up to the stack.
    unsafe {
        (*n).flags = 0;
        // Not Ethernet: straight to IP.
        assert_eq!(netif_input(pbuf_alloc(PBUF_RAW, 20, PBUF_RAM), n), 0);
        assert_eq!(IP_INPUTS.load(Relaxed) - before, 1);
    }
}
