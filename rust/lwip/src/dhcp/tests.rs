// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! test/unit/dhcp/test_dhcp.c, on a netif with the Rust Ethernet, ARP, IPv4, and UDP
//! layers under it. acd.c is C, so address conflict detection is the stand-in: it sends
//! no probes, and a test reports its outcome through the client's callback where
//! test_dhcp.c lets acd.c's probes run (ESP-IDF's DHCP_TEST_NUM_ARP_FRAMES of 5 is 0
//! here). test_dhcp_mtu_validation tests ESP-IDF's option hook, which is C.

extern crate std;

use core::mem::MaybeUninit;
use std::boxed::Box;
use std::sync::Mutex;
use std::vec::Vec;

use super::*;
use crate::test_support::{ACD, DHCP_EXTRA_OPTS, clear_timeouts, serial};

mod packets;

const BROADCAST: [u8; 6] = [0xff; 6];
const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
const HWADDR: [u8; 6] = [0x00, 0x23, 0xC1, 0xDE, 0xD0, 0x0D];
const DHCP_OPTION_MTU: u8 = 26;

/// The frames the netif sent, whole.
static TX: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

unsafe extern "C" fn lwip_tx_func(_netif: *mut Netif, p: *mut Pbuf) -> ErrT {
    // SAFETY: the stack hands the driver a live pbuf chain.
    unsafe {
        let mut frame = std::vec![0_u8; usize::from((*p).tot_len)];
        pbuf_copy_partial(p, frame.as_mut_ptr().cast(), (*p).tot_len, 0);
        TX.lock().unwrap().push(frame);
    }
    ERR_OK
}

unsafe extern "C" fn testif_init(netif: *mut Netif) -> ErrT {
    // SAFETY: the netif being added.
    unsafe {
        (*netif).name = [b'c' as _, b'h' as _];
        (*netif).output = Some(crate::etharp::etharp_output);
        (*netif).linkoutput = Some(lwip_tx_func);
        (*netif).mtu = 1500;
        (*netif).hwaddr_len = 6;
        (*netif).flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP;
        (&mut (*netif).hwaddr)[..6].copy_from_slice(&HWADDR);
    }
    ERR_OK
}

/// test_dhcp.c's net_test, added with no address, linked, and up, around `test`; DHCP is
/// stopped and cleaned up after.
fn with_net_test(test: impl FnOnce(*mut Netif)) {
    let _serial = serial();
    TX.lock().unwrap().clear();
    DHCP_EXTRA_OPTS.lock().unwrap().clear();
    clear_timeouts();
    // SAFETY: every field of the mirror is valid zeroed.
    let mut netif: Box<Netif> = Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
    let n = &mut *netif as *mut Netif;
    let any = Ip4Addr { addr: 0 };
    // SAFETY: the netif outlives its time on the list.
    unsafe {
        crate::netif::netif_add(
            n,
            &any,
            &any,
            &any,
            n.cast(),
            Some(testif_init),
            Some(crate::ethernet::ethernet_input),
        );
        crate::netif::netif_set_link_up(n);
        crate::netif::netif_set_up(n);
    }

    test(n);

    // SAFETY: on the list.
    unsafe {
        dhcp_stop(n);
        dhcp_cleanup(n);
        crate::netif::netif_remove(n);
    }
    assert!(
        DHCP_PCB.get().is_null(),
        "the PCB goes with the last client"
    );
    assert!(ACD.lock().unwrap().is_none(), "the ACD client is removed");
}

/// `send_pkt`: `data` into the netif's input, in a pool pbuf.
fn send_pkt(netif: *mut Netif, data: &[u8]) {
    // SAFETY: a fresh pbuf chain of the frame's size; the input takes it.
    unsafe {
        let p = pbuf_alloc(0 /* PBUF_RAW */, data.len() as u16, PBUF_POOL);
        assert!(!p.is_null());
        assert_eq!(
            pbuf_take(p, data.as_ptr().cast(), data.len() as u16),
            ERR_OK
        );
        (*netif).input.unwrap()(p, netif);
    }
}

/// `data` with the transaction ID `xid` written at the bootp header's, in memory order.
fn with_xid(data: &[u8], xid: u32) -> Vec<u8> {
    let mut frame = data.to_vec();
    frame[46..50].copy_from_slice(&xid.to_ne_bytes());
    frame
}

fn dhcp(netif: *mut Netif) -> *mut Dhcp {
    // SAFETY: a live netif.
    unsafe { netif_dhcp_data(netif) }
}

/// `htonl(netif_dhcp_data(netif)->xid)`.
fn xid(netif: *mut Netif) -> u32 {
    // SAFETY: the netif's live client.
    unsafe { (*dhcp(netif)).xid.to_be() }
}

/// test_dhcp.c's `tick_lwip`, 100 ms: the fine timer every 5 ticks, the coarse one
/// every `DHCP_COARSE_TIMER_SECS` seconds.
struct Ticker(u32);

impl Ticker {
    fn tick(&mut self, netif: *mut Netif) {
        self.0 += 1;
        if self.0.is_multiple_of(5) {
            // SAFETY: the timer's own netif.
            unsafe {
                sys_untimeout(Some(dhcp_fine_timeout_cb), netif.cast());
                dhcp_fine_tmr(netif);
            }
        }
        if self.0.is_multiple_of(DHCP_COARSE_TIMER_SECS * 10) {
            dhcp_coarse_tmr();
        }
    }
}

/// Reports `outcome` for the address the client asked ACD to check, as acd.c would.
fn acd_reports(netif: *mut Netif, outcome: AcdCallback) {
    let (_, callback, _) = ACD.lock().unwrap().expect("an ACD client");
    // SAFETY: the client's callback, for its netif.
    unsafe { callback.unwrap()(netif, outcome) };
}

fn addresses(netif: *mut Netif) -> [[u8; 4]; 3] {
    // SAFETY: a live netif.
    unsafe {
        [
            (*netif).ip4_addr().addr.to_ne_bytes(),
            (*netif).ip4_netmask().addr.to_ne_bytes(),
            (*netif).ip4_gw().addr.to_ne_bytes(),
        ]
    }
}

/// `check_pkt`.
fn check_pkt(frame: &[u8], pos: usize, mem: &[u8]) {
    assert_eq!(&frame[pos..pos + mem.len()], mem, "data at pos {pos}");
}

/// `check_pkt_fuzzy`: `mem` somewhere from `startpos` on.
fn check_pkt_fuzzy(frame: &[u8], startpos: usize, mem: &[u8]) {
    assert!(
        frame[startpos..].windows(mem.len()).any(|w| w == mem),
        "{mem:02x?} not found"
    );
}

/// `get_opt`: option `opt`'s value in a DHCP frame, bug for bug (a pad skips a byte).
fn get_opt(opt: u8, frame: &[u8]) -> Option<Vec<u8>> {
    let magic_cookie_pos = 278;
    check_pkt(frame, magic_cookie_pos, &MAGIC_COOKIE);
    let mut i = magic_cookie_pos + 4;
    while i < frame.len() {
        let op = frame[i];
        i += 1;
        if op == DHCP_OPTION_PAD {
            i += 1;
            continue;
        }
        let len = usize::from(frame[i]);
        i += 1;
        if op == opt {
            return Some(frame[i..i + len].to_vec());
        }
        i += len;
    }
    None
}

/// The checks test_dhcp.c's `lwip_tx_func` makes of a broadcast request from the unit.
fn check_bootp_request(frame: &[u8], ipaddrs: &[u8; 16]) {
    check_pkt(frame, 6, &HWADDR); // Eth level src: unit mac.
    check_pkt(frame, 12, &[0x08, 0x00]); // Eth level proto: ip.
    check_pkt(frame, 42, &[0x01, 0x01, 0x06, 0x00]); // Bootp request, eth, hwaddr len 6, 0 hops.
    check_pkt(frame, 53, ipaddrs);
    check_pkt(frame, 70, &HWADDR); // Mac addr inside bootp.
    check_pkt(frame, 278, &MAGIC_COOKIE);
}

fn tx() -> Vec<Vec<u8>> {
    TX.lock().unwrap().clone()
}

/// Test basic happy flow DHCP session. Validate that xid is checked.
#[test]
fn test_dhcp() {
    with_net_test(|netif| {
        // SAFETY: a live netif.
        assert_eq!(unsafe { dhcp_start(netif) }, ERR_OK);
        assert_eq!(tx().len(), 1); // DHCP discover sent.
        // SAFETY: the netif's live client.
        let bad = unsafe { (*dhcp(netif)).xid }; // Write bad xid, not using htonl!
        send_pkt(netif, &with_xid(&packets::DHCP_OFFER, bad));

        // IP addresses should be zero.
        assert_eq!(addresses(netif), [[0; 4]; 3]);

        assert_eq!(tx().len(), 1); // Nothing more sent.
        send_pkt(netif, &with_xid(&packets::DHCP_OFFER, xid(netif))); // Insert correct transaction id.

        assert_eq!(tx().len(), 2); // DHCP request sent.
        // SAFETY: as above.
        let bad = unsafe { (*dhcp(netif)).xid };
        send_pkt(netif, &with_xid(&packets::DHCP_ACK, bad));

        assert_eq!(tx().len(), 2); // No more sent.
        send_pkt(netif, &with_xid(&packets::DHCP_ACK, xid(netif)));
        assert_eq!(tx().len(), 2);

        // The acknowledged address is checked before it is used.
        assert_eq!(
            ACD.lock().unwrap().unwrap().2.to_ne_bytes(),
            [195, 170, 189, 200]
        );
        assert_eq!(addresses(netif), [[0; 4]; 3]);
        acd_reports(netif, ACD_IP_OK);

        let mut ticker = Ticker(0);
        for _ in 0..200 {
            ticker.tick(netif);
        }
        let frames = tx();
        assert_eq!(frames.len(), 2);
        for (i, frame) in frames.iter().enumerate() {
            check_pkt(frame, 0, &BROADCAST); // Eth level dest: broadcast.
            check_bootp_request(frame, &[0; 16]);
            // Check dhcp message type, can be at different positions.
            if i == 0 {
                check_pkt_fuzzy(frame, 282, &[0x35, 0x01, 0x01]);
            } else {
                check_pkt_fuzzy(frame, 282, &[0x35, 0x01, 0x03]);
                check_pkt_fuzzy(frame, 282, &[0x32, 0x04, 0xc3, 0xaa, 0xbd, 0xc8]); // Ask for offered IP.
            }
        }

        // Interface up.
        // SAFETY: a live netif.
        assert_ne!(unsafe { (*netif).flags } & NETIF_FLAG_UP, 0);
        // Now it should have taken the IP.
        assert_eq!(
            addresses(netif),
            [
                [195, 170, 189, 200],
                [255, 255, 255, 0],
                [195, 170, 189, 171]
            ]
        );
        // SAFETY: a live netif.
        assert_eq!(unsafe { dhcp_supplied_address(netif) }, 1);
    });
}

/// Test that IP address is not taken and a DECLINE is sent if someone replies to ARP
/// requests for the offered address.
#[test]
fn test_dhcp_nak() {
    with_net_test(|netif| {
        // SAFETY: a live netif.
        unsafe { dhcp_start(netif) };
        assert_eq!(tx().len(), 1); // DHCP discover sent.
        send_pkt(netif, &with_xid(&packets::DHCP_OFFER, xid(netif)));
        assert_eq!(tx().len(), 2); // DHCP request sent.
        send_pkt(netif, &with_xid(&packets::DHCP_ACK, xid(netif)));
        assert_eq!(tx().len(), 2);

        // The offered IP is taken: acd.c tells the client after an ARP reply.
        acd_reports(netif, ACD_DECLINE);

        let frames = tx();
        assert_eq!(frames.len(), 3); // DHCP decline sent.
        let frame = &frames[2];
        check_pkt(frame, 0, &BROADCAST);
        check_bootp_request(frame, &[0; 16]);
        check_pkt_fuzzy(frame, 282, &[0x35, 0x01, 0x04]); // Decline the ack.
        check_pkt_fuzzy(frame, 282, &[0x32, 0x04, 0xc3, 0xaa, 0xbd, 0xc8]);
        assert_eq!(addresses(netif), [[0; 4]; 3]);
        // SAFETY: the netif's live client.
        assert_eq!(unsafe { (*dhcp(netif)).state }, DHCP_STATE_BACKING_OFF);
    });
}

/// Test case based on captured data where replies are sent from a different IP than the
/// one the client unicasted to.
#[test]
fn test_dhcp_relayed() {
    with_net_test(|netif| {
        // SAFETY: a live netif.
        unsafe { dhcp_start(netif) };
        assert_eq!(tx().len(), 1); // DHCP discover sent.
        // IP addresses should be zero.
        assert_eq!(addresses(netif), [[0; 4]; 3]);

        send_pkt(netif, &with_xid(&packets::RELAY_OFFER, xid(netif)));
        // Request sent?
        assert_eq!(tx().len(), 2);
        send_pkt(netif, &with_xid(&packets::RELAY_ACK1, xid(netif)));
        acd_reports(netif, ACD_IP_OK);

        let mut ticker = Ticker(0);
        for _ in 0..200 {
            ticker.tick(netif);
        }
        assert_eq!(tx().len(), 2);

        // Interface up.
        // SAFETY: a live netif.
        assert_ne!(unsafe { (*netif).flags } & NETIF_FLAG_UP, 0);

        // Now it should have taken the IP.
        assert_eq!(
            addresses(netif),
            [[79, 138, 51, 5], [255, 255, 254, 0], [79, 138, 50, 1]]
        );

        for _ in 0..108000 - 25 {
            ticker.tick(netif);
        }

        // The renewal goes to the server by unicast: ARP asks for it first.
        let frames = tx();
        assert_eq!(frames.len(), 3);
        check_pkt(&frames[2], 0, &BROADCAST);
        check_pkt(&frames[2], 6, &HWADDR);
        check_pkt(&frames[2], 12, &[0x08, 0x06]); // Eth level proto: arp.

        // We need to send arp response here..
        send_pkt(netif, &packets::ARP_RESP);

        let frames = tx();
        assert_eq!(frames.len(), 4);
        let frame = &frames[3];
        check_pkt(frame, 0, &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xab]); // Eth level dest: the server.
        check_bootp_request(
            frame,
            &[
                0x00, 0x4f, 0x8a, 0x33, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        );
        check_pkt_fuzzy(frame, 282, &[0x35, 0x01, 0x03]);

        send_pkt(netif, &with_xid(&packets::RELAY_ACK2, xid(netif)));

        for _ in 0..100000 {
            ticker.tick(netif);
        }

        assert_eq!(tx().len(), 4);
        // SAFETY: a live netif.
        assert_eq!(unsafe { dhcp_supplied_address(netif) }, 1);
    });
}

#[test]
fn test_dhcp_nak_no_endmarker() {
    with_net_test(|netif| {
        // SAFETY: a live netif and its client.
        unsafe {
            dhcp_start(netif);
            let dhcp = dhcp(netif);

            assert_eq!(tx().len(), 1); // DHCP discover sent.
            send_pkt(netif, &with_xid(&packets::DHCP_OFFER, (*dhcp).xid)); // Bad xid.
            // IP addresses should be zero.
            assert_eq!(addresses(netif), [[0; 4]; 3]);

            assert_eq!(tx().len(), 1); // Nothing more sent.
            send_pkt(netif, &with_xid(&packets::DHCP_OFFER, xid(netif)));

            assert_eq!((*dhcp).state, DHCP_STATE_REQUESTING);

            assert_eq!(tx().len(), 2);
            let xid = xid(netif);
            let (tries, request_timeout) = ((*dhcp).tries, (*dhcp).request_timeout);
            send_pkt(netif, &with_xid(&packets::DHCP_NACK_NO_ENDMARKER, xid));

            // NAK should be ignored.
            assert_eq!((*dhcp).state, DHCP_STATE_REQUESTING);
            assert_eq!(tx().len(), 2); // No more sent.
            assert_eq!(xid, (*dhcp).xid.to_be());
            assert_eq!(tries, (*dhcp).tries);
            assert_eq!(request_timeout, (*dhcp).request_timeout);
        }
    });
}

#[test]
fn test_dhcp_invalid_overload() {
    with_net_test(|netif| {
        // SAFETY: a live netif.
        unsafe { dhcp_start(netif) };

        assert_eq!(tx().len(), 1); // DHCP discover sent.
        let mut offer = with_xid(&packets::DHCP_OFFER_INVALID_OVERLOAD, xid(netif));
        for overload in [3, 2, 1] {
            offer[311] = overload;
            send_pkt(netif, &offer);
            // IP addresses should be zero.
            assert_eq!(addresses(netif), [[0; 4]; 3]);
            assert_eq!(tx().len(), 1); // Nothing more sent.
        }

        offer[311] = 0;
        send_pkt(netif, &offer[..packets::DHCP_OFFER.len()]);

        // SAFETY: the netif's live client.
        assert_eq!(unsafe { (*dhcp(netif)).state }, DHCP_STATE_REQUESTING);
        assert_eq!(tx().len(), 2);
    });
}

#[test]
fn test_options() {
    with_net_test(|netif| {
        // SAFETY: a live netif.
        unsafe { dhcp_start(netif) };

        assert_eq!(tx().len(), 1); // DHCP discover sent.
        let mut dhcp_with_opts = [0_u8; 512];
        dhcp_with_opts[..packets::DHCP_OFFER.len()]
            .copy_from_slice(&with_xid(&packets::DHCP_OFFER, xid(netif)));
        // Replace the END marker of the original packet: MTU 512, VSI info, new END.
        dhcp_with_opts[309..320].copy_from_slice(&[
            DHCP_OPTION_MTU,
            2,
            0x02,
            0x00,
            43,
            4,
            1,
            2,
            3,
            4,
            0xff,
        ]);

        send_pkt(netif, &dhcp_with_opts);
        // MTU should not be updated in selection state (ESP-IDF's hook does that).
        // SAFETY: a live netif.
        assert_eq!(unsafe { (*netif).mtu }, 1500);
        // The options dhcp.c does not know go to ESP-IDF's hook.
        assert_eq!(
            *DHCP_EXTRA_OPTS.lock().unwrap(),
            [(DHCP_OPTION_MTU, 2), (43, 4)]
        );

        let frames = tx();
        assert_eq!(frames.len(), 2); // DHCP request sent.
        assert_eq!(
            get_opt(DHCP_OPTION_MESSAGE_TYPE, &frames[1]),
            Some(std::vec![DHCP_REQUEST])
        );
        let requested = get_opt(DHCP_OPTION_PARAMETER_REQUEST_LIST, &frames[1]).unwrap();
        assert!(!requested.contains(&43)); // VSI mustn't be in the requested opts.
        assert_eq!(requested, DHCP_DISCOVER_REQUEST_OPTIONS);

        dhcp_with_opts = [0; 512];
        dhcp_with_opts[..packets::DHCP_ACK.len()]
            .copy_from_slice(&with_xid(&packets::DHCP_ACK, xid(netif)));
        dhcp_with_opts[309..314].copy_from_slice(&[DHCP_OPTION_MTU, 2, 0x02, 0x00, 0xff]);
        send_pkt(netif, &dhcp_with_opts);
        acd_reports(netif, ACD_IP_OK);
        // SAFETY: a live netif.
        assert_eq!(unsafe { (*netif).mtu }, 1500);

        // Wait after the rebinding period to expect several ARP packets (counted) and 1
        // DHCP request packet with renewal.
        let mut ticker = Ticker(0);
        let mut last_message_type = 0;
        let mut tx_arp = 0;
        for _ in 0..1200 {
            ticker.tick(netif);
            let frames = tx();
            let last = frames.last().unwrap();
            if frames.len() > 2 && last.len() <= packets::ARPREPLY.len() && last[..6] == BROADCAST {
                tx_arp = frames.len() - 2;
            } else if frames.len() > 2 {
                last_message_type = get_opt(DHCP_OPTION_MESSAGE_TYPE, last).unwrap()[0];
            }
            if last_message_type == DHCP_REQUEST {
                break;
            }
        }
        assert_eq!(last_message_type, DHCP_REQUEST);
        assert_eq!(tx().len(), 3 + tx_arp); // DHCP renewal.
    });
}

// Beyond test_dhcp.c.

#[test]
fn a_nak_while_requesting_restarts_discovery_and_link_changes_reboot() {
    with_net_test(|netif| {
        // SAFETY: a live netif and its client.
        unsafe {
            dhcp_start(netif);
            send_pkt(netif, &with_xid(&packets::DHCP_OFFER, xid(netif)));
            assert_eq!((*dhcp(netif)).state, DHCP_STATE_REQUESTING);
            // The ACK's message type made a NAK.
            let mut nak = with_xid(&packets::DHCP_ACK, xid(netif));
            nak[284] = DHCP_NAK;
            send_pkt(netif, &nak);
            assert_eq!((*dhcp(netif)).state, DHCP_STATE_SELECTING);
            let frames = tx();
            assert_eq!(frames.len(), 3);
            check_pkt_fuzzy(&frames[2], 282, &[0x35, 0x01, 0x01]); // A new discover.

            // Bound, then the link comes back: the client verifies its lease.
            send_pkt(netif, &with_xid(&packets::DHCP_OFFER, xid(netif)));
            send_pkt(netif, &with_xid(&packets::DHCP_ACK, xid(netif)));
            acd_reports(netif, ACD_IP_OK);
            assert_eq!((*dhcp(netif)).state, DHCP_STATE_BOUND);
            dhcp_network_changed_link_up(netif);
            assert_eq!((*dhcp(netif)).state, DHCP_STATE_REBOOTING);
            let frames = tx();
            let frame = frames.last().unwrap();
            check_pkt_fuzzy(frame, 282, &[0x35, 0x01, 0x03]);
            check_pkt_fuzzy(frame, 282, &[0x32, 0x04, 0xc3, 0xaa, 0xbd, 0xc8]);
            check_pkt_fuzzy(frame, 282, &[DHCP_OPTION_MAX_MSG_SIZE, 2, 0x02, 0x40]); // 576.
        }
    });
}

#[test]
fn the_host_name_goes_in_and_release_tells_the_server() {
    with_net_test(|netif| {
        // SAFETY: a live netif and its client; the host name outlives them.
        unsafe {
            (*netif).hostname = c"espressif".as_ptr();
            dhcp_start(netif);
            check_pkt_fuzzy(&tx()[0], 282, b"\x0c\x09espressif");
            send_pkt(netif, &with_xid(&packets::DHCP_OFFER, xid(netif)));
            send_pkt(netif, &with_xid(&packets::DHCP_ACK, xid(netif)));
            acd_reports(netif, ACD_IP_OK);
            let sent = tx().len();

            // Releasing a bound lease tells the server, by unicast (ARP first), and
            // drops the address.
            assert_eq!(dhcp_release(netif), ERR_OK);
            assert_eq!(addresses(netif), [[0; 4]; 3]);
            assert_eq!(tx().len(), sent + 1);
            check_pkt(&tx()[sent], 12, &[0x08, 0x06]);
            assert_eq!(dhcp_supplied_address(netif), 0);
            (*netif).hostname = ptr::null();
        }
    });
}

#[test]
fn a_client_without_link_waits_for_it_in_a_static_struct() {
    with_net_test(|netif| {
        // SAFETY: a live netif; the client struct outlives its use.
        unsafe {
            let mut client: Dhcp = MaybeUninit::zeroed().assume_init();
            dhcp_set_struct(netif, &mut client);
            assert_eq!(dhcp(netif), &raw mut client);
            crate::netif::netif_set_link_down(netif);
            assert_eq!(dhcp_start(netif), ERR_OK);
            assert_eq!(client.state, DHCP_STATE_INIT);
            assert!(tx().is_empty());
            crate::netif::netif_set_link_up(netif);
            assert_eq!(client.state, DHCP_STATE_SELECTING);
            assert_eq!(tx().len(), 1);
            dhcp_stop(netif);
            // As in dhcp.c, dhcp_start cleared the whole struct, the flag that keeps
            // dhcp_cleanup from freeing it included: detach it by hand.
            assert_eq!(client.flags & DHCP_FLAG_EXTERNAL_MEM, 0);
            set_netif_dhcp_data(netif, ptr::null_mut());
        }
    });
}

#[test]
fn inform_sends_the_address_and_starts_no_client() {
    with_net_test(|netif| {
        // SAFETY: a live netif.
        unsafe {
            let (ip, mask, gw) = (
                Ip4Addr {
                    addr: u32::from_ne_bytes([10, 0, 0, 5]),
                },
                Ip4Addr {
                    addr: u32::from_ne_bytes([255, 0, 0, 0]),
                },
                Ip4Addr { addr: 0 },
            );
            crate::netif::netif_set_addr(netif, &ip, &mask, &gw);
            dhcp_inform(netif);
            let frames = tx();
            assert_eq!(frames.len(), 1);
            check_pkt(&frames[0], 0, &BROADCAST);
            check_bootp_request(
                &frames[0],
                &[0, 10, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            );
            check_pkt_fuzzy(&frames[0], 282, &[0x35, 0x01, 0x08]);
            assert!(dhcp(netif).is_null());
            assert!(DHCP_PCB.get().is_null());
        }
    });
}

#[test]
fn the_backoff_and_timeouts_follow_esp_idf() {
    assert_eq!(
        (0..7).map(request_backoff_sequence).collect::<Vec<_>>(),
        [250, 500, 1000, 2000, 4000, 4000, 4000]
    );
    assert_eq!(timeout_from_offered(0, 120), 120);
    assert_eq!(timeout_from_offered(3600, 120), 3600);
    assert_eq!(fine_ticks(500), 1);
    assert_eq!(fine_ticks(501), 2);
}

#[test]
fn a_message_the_options_fill_goes_out_without_the_end_marker() {
    let _serial = serial();
    // SAFETY: a fresh pbuf the size of a message, freed below.
    unsafe {
        let p = pbuf_alloc(
            config::PBUF_TRANSPORT_LAYER as PbufLayer,
            SIZEOF_DHCP_MSG as u16,
            PBUF_RAM,
        );
        assert!(!p.is_null());
        let msg = (*p).payload.cast::<u8>();
        options(msg).fill(0xaa);
        // No room is left for DHCP_OPTION_END: C writes it past the message, which the
        // port does not, and the message keeps its length.
        dhcp_option_trailer(DHCP_OPTIONS_LEN as u16, msg, p);
        assert!(options(msg).iter().all(|&b| b == 0xaa));
        assert_eq!(usize::from((*p).tot_len), SIZEOF_DHCP_MSG);

        // With room, the marker ends the options and the message shrinks to them, padded
        // to DHCP_MIN_OPTIONS_LEN.
        dhcp_option_trailer(3, msg, p);
        assert_eq!(options(msg)[3], DHCP_OPTION_END);
        assert!(
            options(msg)[4..usize::from(DHCP_MIN_OPTIONS_LEN)]
                .iter()
                .all(|&b| b == 0)
        );
        assert_eq!(
            usize::from((*p).tot_len),
            SIZEOF_DHCP_MSG - DHCP_OPTIONS_LEN + usize::from(DHCP_MIN_OPTIONS_LEN)
        );
        pbuf_free(p);
    }
}
