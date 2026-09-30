// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! tcp.c on the IPv4 test netif: PCB allocation and its defaults, binding and port
//! allocation, listening, connecting, closing, shutdown and abort, the slow and fast
//! timers (retransmission and its backoff, SYN retries, keepalive, TIME-WAIT, polling,
//! delayed ACKs, pending FINs, refused data), window updates, and address changes.
//! test_tcp.c's cases drive TCP through tcp_input; they come with tcp_in.c. Until then,
//! the tests stand in for input by setting a connection's state as tcp_in.c would.

extern crate std;

use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::Mutex;
use std::vec::Vec;

use super::*;
use crate::ip4::tests::{TEST_IPADDR, ip4, with_test_netif};
use crate::tcp_out::tcp_write;

const PEER: Ip4Addr = ip4(192, 168, 0, 9);

/// The IPv4 packets the netif sent.
static FRAMES: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

unsafe extern "C" fn record(_netif: *mut Netif, p: *mut Pbuf) -> ErrT {
    // SAFETY: the stack hands the driver a live pbuf chain.
    unsafe {
        let mut frame = std::vec![0_u8; usize::from((*p).tot_len)];
        pbuf_copy_partial(p, frame.as_mut_ptr().cast(), (*p).tot_len, 0);
        FRAMES.lock().unwrap().push(frame);
    }
    ERR_OK
}

unsafe extern "C" fn arpless(netif: *mut Netif, p: *mut Pbuf, _ipaddr: *const Ip4Addr) -> ErrT {
    // SAFETY: the netif's own driver.
    unsafe { record(netif, p) }
}

/// The TCP flags of the segments sent since the last call.
fn sent_flags() -> Vec<u8> {
    core::mem::take(&mut *FRAMES.lock().unwrap())
        .iter()
        .map(|f| f[20 + 13])
        .collect()
}

/// Every PCB on the four lists.
fn all_pcbs() -> Vec<*mut TcpPcb> {
    let mut all = Vec::new();
    for &list in &tcp_pcb_lists.0 {
        // SAFETY: the lists hold live PCBs.
        unsafe {
            let mut pcb = *list;
            while !pcb.is_null() {
                all.push(pcb);
                pcb = (*pcb).next;
            }
        }
    }
    all
}

/// Aborts, closes, or frees whatever the test left on the lists.
fn clean_up() {
    // SAFETY: the lists hold live PCBs; each is taken off before it is freed.
    unsafe {
        let mut pcb = tcp_listen_pcbs.get();
        while !pcb.is_null() {
            let next = (*pcb).next;
            tcp_close(pcb);
            pcb = next;
        }
        for list in [tcp_active_pcbs.as_ptr(), tcp_tw_pcbs.as_ptr()] {
            while !(*list).is_null() {
                tcp_abandon(*list, 0);
            }
        }
        while !tcp_bound_pcbs.get().is_null() {
            tcp_close(tcp_bound_pcbs.get());
        }
    }
    assert!(all_pcbs().is_empty());
}

/// TCP on the test netif, whose output skips ARP.
fn with_tcp(test: impl FnOnce(*mut Netif)) {
    with_test_netif(|netif| {
        // SAFETY: a live netif.
        unsafe {
            (*netif).output = Some(arpless);
            (*netif).linkoutput = Some(record);
        }
        clean_up();
        FRAMES.lock().unwrap().clear();
        test(netif);
        clean_up();
    });
}

/// A PCB connected to PEER:80 and made ESTABLISHED as tcp_in.c would on the SYN-ACK.
fn established() -> *mut TcpPcb {
    let pcb = tcp_new();
    let peer = IpAddr::v4(PEER.addr);
    // SAFETY: a fresh PCB.
    unsafe {
        assert_eq!(tcp_connect(pcb, &peer, 80, None), ERR_OK);
        assert_eq!(sent_flags(), [TCP_SYN]);
        // The SYN-ACK: SYN acknowledged, the peer's ISN 5000, its window 5760.
        tcp_segs_free((*pcb).unacked);
        (*pcb).unacked = ptr::null_mut();
        (*pcb).snd_queuelen = 0;
        (*pcb).lastack = (*pcb).snd_nxt;
        (*pcb).rcv_nxt = 5001;
        (*pcb).rcv_ann_right_edge = 5001;
        (*pcb).snd_wnd = 5760;
        (*pcb).snd_wnd_max = 5760;
        (*pcb).cwnd = (*pcb).mss;
        (*pcb).rtime = -1;
        (*pcb).nrtx = 0;
        (*pcb).state = ESTABLISHED;
    }
    pcb
}

static ERRS: Mutex<Vec<ErrT>> = Mutex::new(Vec::new());

unsafe extern "C" fn record_err(_arg: *mut c_void, err: ErrT) {
    ERRS.lock().unwrap().push(err);
}

fn errs() -> Vec<ErrT> {
    core::mem::take(&mut *ERRS.lock().unwrap())
}

#[test]
fn a_new_pcb_starts_closed_with_the_configured_defaults() {
    with_tcp(|_| {
        let pcb = tcp_new();
        // SAFETY: a fresh PCB, on no list.
        unsafe {
            assert_eq!((*pcb).state, CLOSED);
            assert_eq!((*pcb).prio, TCP_PRIO_NORMAL);
            assert_eq!(
                ((*pcb).snd_buf, (*pcb).ssthresh),
                (TCP_SND_BUF, TCP_SND_BUF)
            );
            assert_eq!(((*pcb).rcv_wnd, (*pcb).rcv_ann_wnd), (TCP_WND, TCP_WND));
            assert_eq!((*pcb).mss, 536);
            assert_eq!(
                ((*pcb).rto, (*pcb).sv),
                (3, 3),
                "LWIP_TCP_RTO_TIME is 1500 ms"
            );
            assert_eq!(((*pcb).rtime, (*pcb).cwnd), (-1, 1));
            assert_eq!((*pcb).ttl, TCP_TTL);
            assert_eq!(
                ((*pcb).keep_idle, (*pcb).keep_intvl, (*pcb).keep_cnt),
                (7_200_000, 75_000, 9)
            );
            let recv_null: unsafe extern "C" fn(*mut c_void, *mut TcpPcb, *mut Pbuf, ErrT) -> ErrT =
                tcp_recv_null;
            assert_eq!((*pcb).recv.map(|f| f as usize), Some(recv_null as usize));
            assert!(all_pcbs().is_empty(), "on no list until bound");
            tcp_close(pcb);

            let pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
            assert_eq!(
                ((*pcb).local_ip.type_, (*pcb).remote_ip.type_),
                (IPADDR_TYPE_ANY, IPADDR_TYPE_ANY)
            );
            tcp_close(pcb);
        }
        assert_eq!(CStr::from_ptr_state(ESTABLISHED), "ESTABLISHED");
    });
}

/// `tcp_debug_state_str` as a string.
struct CStr;

impl CStr {
    fn from_ptr_state(state: TcpState) -> &'static str {
        // SAFETY: the state names are static C strings.
        unsafe { core::ffi::CStr::from_ptr(tcp_debug_state_str(state)) }
            .to_str()
            .unwrap()
    }
}

#[test]
fn bind_allocates_ports_and_refuses_one_in_use() {
    with_tcp(|_| {
        // SAFETY: fresh PCBs; the addresses are valid.
        unsafe {
            let a = tcp_new();
            assert_eq!(tcp_bind(a, ptr::null(), 0), ERR_OK);
            let port = (*a).local_port;
            assert!(port >= TCP_LOCAL_PORT_RANGE_START);
            assert_eq!(tcp_bound_pcbs.get(), a);
            assert!(
                crate::test_support::TCP_TIMER_NEEDED.load(Relaxed) > 0,
                "a bound PCB needs the timer"
            );

            // The same port on any address or on ours is taken; another is not.
            let b = tcp_new();
            assert_eq!(tcp_bind(b, ptr::null(), port), ERR_USE);
            let ours = IpAddr::v4(TEST_IPADDR.addr);
            assert_eq!(tcp_bind(b, &ours, port), ERR_USE);
            // IPv6 does not collide with IPv4.
            let mut any6 = IpAddr::v4(0);
            any6.set_zero_ip6();
            assert_eq!(tcp_bind(b, &any6, port), ERR_OK);
            assert!((*b).local_ip.is_v6());

            // Only a CLOSED PCB binds (a bound one still is: bind does not check).
            let conn = established();
            assert_eq!(tcp_bind(conn, ptr::null(), 9), ERR_VAL);
            sent_flags();

            // With SO_REUSEADDR on both, the port is shared.
            let (c, d) = (tcp_new(), tcp_new());
            (*c).so_options |= SOF_REUSEADDR;
            (*d).so_options |= SOF_REUSEADDR;
            assert_eq!(tcp_bind(c, &ours, 7000), ERR_OK);
            assert_eq!(tcp_bind(d, &ours, 7000), ERR_OK);
            assert_eq!(all_pcbs().len(), 5);
        }
    });
}

#[test]
fn listen_replaces_the_pcb_and_closing_it_forgets_its_connections() {
    with_tcp(|_| {
        // SAFETY: fresh PCBs.
        unsafe {
            let pcb = tcp_new();
            assert_eq!(tcp_bind(pcb, ptr::null(), 80), ERR_OK);
            let mut err = ERR_VAL;
            let lpcb = tcp_listen_with_backlog_and_err(pcb, 0, &mut err);
            assert_eq!(err, ERR_OK);
            assert_eq!((*lpcb).state, LISTEN);
            assert!(tcp_bound_pcbs.get().is_null());
            assert_eq!(tcp_listen_pcbs.get(), lpcb);
            let listen = lpcb.cast::<TcpPcbListen>();
            assert_eq!(
                (
                    (*listen).local_port,
                    (*listen).backlog,
                    (*listen).accepts_pending
                ),
                (80, 1, 0)
            );
            assert!(
                (*listen).accept.is_some(),
                "tcp_accept_null until the application sets one"
            );
            tcp_accept(lpcb, None);
            assert!((*listen).accept.is_none());

            // A second listener on the port: refused with SO_REUSEADDR, as its bind
            // allowed it.
            let other = tcp_new();
            (*other).so_options |= SOF_REUSEADDR;
            (*listen).so_options |= SOF_REUSEADDR;
            assert_eq!(tcp_bind(other, ptr::null(), 80), ERR_OK);
            assert!(tcp_listen_with_backlog_and_err(other, 2, &mut err).is_null());
            assert_eq!(err, ERR_USE);
            tcp_close(other);

            // Only a CLOSED PCB listens.
            assert!(tcp_listen_with_backlog_and_err(lpcb, 1, &mut err).is_null());
            assert_eq!(err, ERR_CLSD);

            // A connection accepted from it forgets it when it closes, and its backlog
            // counts pending accepts.
            let conn = established();
            (*conn).listener = listen;
            tcp_backlog_delayed(conn);
            tcp_backlog_delayed(conn);
            assert_eq!((*listen).accepts_pending, 1);
            tcp_backlog_accepted(conn);
            assert_eq!((*listen).accepts_pending, 0);
            tcp_backlog_delayed(conn);
            assert_eq!(tcp_close(lpcb), ERR_OK);
            assert!((*conn).listener.is_null());
            assert!(tcp_listen_pcbs.get().is_null());
        }
    });
}

#[test]
fn connect_sends_a_syn_with_the_hook_isn() {
    with_tcp(|netif| {
        let pcb = tcp_new();
        let peer = IpAddr::v4(PEER.addr);
        // SAFETY: a fresh PCB; valid addresses.
        unsafe {
            assert_eq!(tcp_connect(pcb, &peer, 80, None), ERR_OK);
            assert_eq!((*pcb).state, SYN_SENT);
            assert_eq!(tcp_active_pcbs.get(), pcb);
            assert_eq!(
                (*pcb).local_ip.ip4().addr,
                TEST_IPADDR.addr,
                "the netif's address"
            );
            assert!((*pcb).local_port >= TCP_LOCAL_PORT_RANGE_START);
            assert_eq!((*pcb).mss, 536, "INITIAL_MSS fits the netif");
            assert_eq!((*pcb).lastack, (*pcb).snd_nxt - 1);
            assert_eq!((*pcb).snd_lbb, (*pcb).snd_nxt);
            let frames = core::mem::take(&mut *FRAMES.lock().unwrap());
            let tcp = &frames[0][20..];
            assert_eq!(tcp[13], TCP_SYN);
            assert_eq!(
                u32::from_be_bytes(tcp[4..8].try_into().unwrap()),
                (*pcb).snd_nxt - 1
            );
            assert_eq!(tcp[20..24], [2, 4, 0x05, 0xa0], "MSS option: TCP_MSS");
            assert_eq!(tcp_connect(pcb, &peer, 80, None), ERR_ISCONN);

            // No route: nothing is sent.
            crate::netif::netif_set_default(ptr::null_mut());
            let far = IpAddr::v4(ip4(10, 0, 0, 1).addr);
            let other = tcp_new();
            assert_eq!(tcp_connect(other, &far, 80, None), ERR_RTE);
            tcp_close(other);
            crate::netif::netif_set_default(netif);
        }
        assert!(sent_flags().is_empty());
    });
}

#[test]
fn close_frees_unconnected_pcbs_and_sends_fin_on_connections() {
    with_tcp(|_| {
        // SAFETY: live PCBs.
        unsafe {
            // A SYN_SENT PCB goes away without a FIN.
            let peer = IpAddr::v4(PEER.addr);
            let pcb = tcp_new();
            assert_eq!(tcp_connect(pcb, &peer, 80, None), ERR_OK);
            sent_flags();
            assert_eq!(tcp_close(pcb), ERR_OK);
            assert!(all_pcbs().is_empty());
            assert!(sent_flags().is_empty());

            // An ESTABLISHED one sends FIN and waits in FIN_WAIT_1.
            let pcb = established();
            assert_eq!(tcp_close(pcb), ERR_OK);
            assert_eq!((*pcb).state, FIN_WAIT_1);
            assert_ne!((*pcb).flags & TF_RXCLOSED, 0);
            assert_eq!(sent_flags(), [TCP_ACK | TCP_FIN]);

            // From CLOSE_WAIT, a FIN leads to LAST_ACK.
            let pcb = established();
            (*pcb).state = CLOSE_WAIT;
            assert_eq!(tcp_close(pcb), ERR_OK);
            assert_eq!((*pcb).state, LAST_ACK);
            sent_flags();

            // Data the application never took: a RST, and the PCB is gone.
            let pcb = established();
            (*pcb).rcv_wnd = TCP_WND - 10;
            let before = all_pcbs().len();
            assert_eq!(tcp_close(pcb), ERR_OK);
            assert_eq!(sent_flags(), [TCP_RST | TCP_ACK]);
            assert_eq!(all_pcbs().len(), before - 1);
        }
    });
}

#[test]
fn shutdown_closes_one_side_or_both() {
    with_tcp(|_| {
        // SAFETY: live PCBs.
        unsafe {
            let pcb = established();
            assert_eq!(tcp_shutdown(pcb, 1, 0), ERR_OK);
            assert_ne!((*pcb).flags & TF_RXCLOSED, 0);
            assert_eq!((*pcb).state, ESTABLISHED);
            assert_eq!(tcp_shutdown(pcb, 0, 1), ERR_OK);
            assert_eq!((*pcb).state, FIN_WAIT_1);
            assert_eq!(tcp_shutdown(pcb, 0, 1), ERR_CONN, "already shut");
            sent_flags();

            let lpcb = tcp_new();
            tcp_bind(lpcb, ptr::null(), 81);
            let lpcb = tcp_listen_with_backlog(lpcb, 1);
            assert_eq!(tcp_shutdown(lpcb, 1, 1), ERR_CONN);
        }
    });
}

#[test]
fn abort_sends_rst_and_reports_the_error() {
    with_tcp(|_| {
        // SAFETY: a live PCB.
        unsafe {
            let pcb = established();
            tcp_err(pcb, Some(record_err));
            tcp_abort(pcb);
            assert_eq!(sent_flags(), [TCP_RST | TCP_ACK]);
            assert_eq!(errs(), [ERR_ABRT]);
            assert!(all_pcbs().is_empty());

            // A bound, unconnected PCB just goes, without a RST.
            let pcb = tcp_new();
            tcp_bind(pcb, ptr::null(), 0);
            tcp_err(pcb, Some(record_err));
            tcp_abort(pcb);
            assert!(sent_flags().is_empty());
            assert_eq!(errs(), [ERR_ABRT]);
        }
    });
}

#[test]
fn the_retransmission_timer_backs_off_and_resends() {
    with_tcp(|_| {
        // SAFETY: a live PCB and data that outlives the call.
        unsafe {
            let pcb = established();
            let data = [7_u8; 100];
            assert_eq!(tcp_write(pcb, data.as_ptr().cast(), 100, 0), ERR_OK);
            assert_eq!(tcp_output(pcb), ERR_OK);
            assert_eq!(sent_flags(), [TCP_ACK | TCP_PSH]);
            assert_eq!(((*pcb).rtime, (*pcb).rto), (0, 3));

            // rto ticks of the slow timer later, the segment goes again.
            for _ in 0..3 {
                tcp_slowtmr();
            }
            assert_eq!(sent_flags(), [TCP_ACK | TCP_PSH]);
            assert_eq!((*pcb).nrtx, 1);
            assert_eq!((*pcb).rtime, 0);
            assert_eq!((*pcb).cwnd, (*pcb).mss);
            assert_eq!((*pcb).ssthresh, 2 * (*pcb).mss);
            // ((sa >> 3) + sv) << backoff[0]: (0 + 3) << 1.
            assert_eq!((*pcb).rto, 6);
        }
    });
}

#[test]
fn too_many_syn_retries_remove_the_pcb() {
    with_tcp(|_| {
        let pcb = tcp_new();
        let peer = IpAddr::v4(PEER.addr);
        // SAFETY: a live PCB until the timer removes it.
        unsafe {
            tcp_err(pcb, Some(record_err));
            assert_eq!(tcp_connect(pcb, &peer, 80, None), ERR_OK);
            let mut ticks = 0;
            while !tcp_active_pcbs.get().is_null() {
                tcp_slowtmr();
                ticks += 1;
                assert!(ticks < 10_000);
            }
        }
        // The first SYN and TCP_SYNMAXRTX retries; the SYN's RTO is not doubled.
        assert_eq!(sent_flags().len(), 1 + usize::from(TCP_SYNMAXRTX));
        assert_eq!(errs(), [ERR_ABRT]);
    });
}

#[test]
fn keepalive_probes_then_resets_an_idle_connection() {
    with_tcp(|_| {
        // SAFETY: a live PCB until the timer removes it.
        unsafe {
            let pcb = established();
            tcp_err(pcb, Some(record_err));
            (*pcb).so_options |= SOF_KEEPALIVE;
            (*pcb).keep_idle = 1000;
            (*pcb).keep_intvl = 1000;
            (*pcb).keep_cnt = 2;
            (*pcb).tmr = tcp_ticks.get();
            let mut ticks = 0;
            while !tcp_active_pcbs.get().is_null() {
                tcp_slowtmr();
                ticks += 1;
                assert!(ticks < 100);
            }
            // Probes past keep_idle, then a RST past keep_idle + keep_cnt * keep_intvl.
            let flags = sent_flags();
            assert_eq!(flags.last(), Some(&(TCP_RST | TCP_ACK)));
            assert!(flags[..flags.len() - 1].iter().all(|&f| f == TCP_ACK));
            assert_eq!(flags.len() - 1, 2);
            assert_eq!(errs(), [ERR_ABRT]);
        }
    });
}

#[test]
fn time_wait_ends_after_twice_the_msl() {
    with_tcp(|_| {
        // SAFETY: a live PCB, moved to TIME-WAIT as tcp_in.c would.
        unsafe {
            let pcb = established();
            tcp_rmv_active(pcb);
            (*pcb).state = TIME_WAIT;
            (*pcb).tmr = tcp_ticks.get();
            tcp_reg(tcp_tw_pcbs.as_ptr(), pcb);
            for _ in 0..2 * TCP_MSL / TCP_SLOW_INTERVAL {
                tcp_slowtmr();
            }
            assert_eq!(tcp_tw_pcbs.get(), pcb);
            tcp_slowtmr();
            assert!(tcp_tw_pcbs.get().is_null());
        }
    });
}

static POLLS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn count_poll(_arg: *mut c_void, _pcb: *mut TcpPcb) -> ErrT {
    POLLS.fetch_add(1, Relaxed);
    ERR_OK
}

#[test]
fn the_application_is_polled_at_its_interval() {
    with_tcp(|_| {
        // SAFETY: a live PCB.
        unsafe {
            let pcb = established();
            tcp_poll(pcb, Some(count_poll), 4);
            POLLS.store(0, Relaxed);
            for _ in 0..12 {
                tcp_slowtmr();
            }
            assert_eq!(POLLS.load(Relaxed), 3);
        }
    });
}

static RECEIVED: Mutex<Vec<(usize, ErrT)>> = Mutex::new(Vec::new());
static REFUSE: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn recv(_arg: *mut c_void, _pcb: *mut TcpPcb, p: *mut Pbuf, err: ErrT) -> ErrT {
    if REFUSE.load(Relaxed) != 0 {
        return ERR_MEM;
    }
    // SAFETY: the callback owns a pbuf it accepts.
    let len = unsafe { p.as_ref() }.map_or(0, |p| usize::from(p.tot_len));
    RECEIVED.lock().unwrap().push((len, err));
    if !p.is_null() {
        // SAFETY: as above.
        unsafe { pbuf_free(p) };
    }
    ERR_OK
}

#[test]
fn the_fast_timer_sends_delayed_acks_pending_fins_and_refused_data() {
    with_tcp(|_| {
        // SAFETY: a live PCB and pbufs it takes.
        unsafe {
            let pcb = established();
            (*pcb).flags |= TF_ACK_DELAY;
            tcp_fasttmr();
            assert_eq!(sent_flags(), [TCP_ACK]);
            assert_eq!((*pcb).flags & (TF_ACK_DELAY | TF_ACK_NOW), 0);

            (*pcb).flags |= TF_CLOSEPEND;
            tcp_fasttmr();
            assert_eq!((*pcb).state, FIN_WAIT_1);
            assert_eq!(sent_flags(), [TCP_ACK | TCP_FIN]);

            let pcb = established();
            tcp_recv(pcb, Some(recv));
            RECEIVED.lock().unwrap().clear();
            let data = crate::ip4::tests::packet(&[1; 30]);
            (*data).flags |= PBUF_FLAG_TCP_FIN;
            (*pcb).refused_data = data;
            (*pcb).rcv_wnd = TCP_WND - 1;
            // Still refused: the data stays.
            REFUSE.store(1, Relaxed);
            assert_eq!(tcp_process_refused_data(pcb), ERR_INPROGRESS);
            assert_eq!((*pcb).refused_data, data);
            // Taken: the data, then the FIN as an empty receive, and the FIN's window
            // byte back.
            REFUSE.store(0, Relaxed);
            tcp_fasttmr();
            assert!((*pcb).refused_data.is_null());
            assert_eq!(*RECEIVED.lock().unwrap(), [(30, ERR_OK), (0, ERR_OK)]);
            assert_eq!((*pcb).rcv_wnd, TCP_WND);
        }
    });
}

#[test]
fn recved_opens_the_window_and_announces_a_large_update() {
    with_tcp(|_| {
        // SAFETY: a live PCB.
        unsafe {
            let pcb = established();
            // The application holds 3000 bytes it received.
            (*pcb).rcv_wnd = TCP_WND - 3000;
            (*pcb).rcv_ann_wnd = TCP_WND - 3000;
            (*pcb).rcv_ann_right_edge = (*pcb).rcv_nxt + u32::from(TCP_WND - 3000);
            tcp_recved(pcb, 1000);
            assert_eq!((*pcb).rcv_wnd, TCP_WND - 2000);
            assert!(sent_flags().is_empty(), "below TCP_WND_UPDATE_THRESHOLD");
            tcp_recved(pcb, 2000);
            assert_eq!((*pcb).rcv_wnd, TCP_WND);
            assert_eq!(sent_flags(), [TCP_ACK], "the window update");
            assert_eq!((*pcb).rcv_ann_wnd, TCP_WND);
            tcp_recved(pcb, 100);
            assert_eq!((*pcb).rcv_wnd, TCP_WND, "never beyond TCP_WND");
        }
    });
}

#[test]
fn an_address_change_aborts_connections_and_moves_listeners() {
    with_tcp(|_| {
        // SAFETY: live PCBs.
        unsafe {
            let conn = established();
            tcp_err(conn, Some(record_err));
            let lpcb = tcp_new();
            let ours = IpAddr::v4(TEST_IPADDR.addr);
            tcp_bind(lpcb, &ours, 80);
            let lpcb = tcp_listen_with_backlog(lpcb, 1);
            sent_flags();

            let new = IpAddr::v4(ip4(192, 168, 0, 2).addr);
            tcp_netif_ip_addr_changed(&ours, &new);
            assert_eq!(errs(), [ERR_ABRT]);
            assert_eq!(sent_flags(), [TCP_RST | TCP_ACK]);
            assert!(tcp_active_pcbs.get().is_null());
            assert_eq!((*lpcb).local_ip.ip4().addr, new.ip4().addr);
        }
    });
}

#[test]
fn a_segment_copy_shares_the_pbuf() {
    with_tcp(|_| {
        // SAFETY: a live PCB and segment.
        unsafe {
            let pcb = established();
            let data = [1_u8; 10];
            tcp_write(pcb, data.as_ptr().cast(), 10, 0);
            let seg = (*pcb).unsent;
            let copy = tcp_seg_copy(seg);
            assert_eq!(((*copy).p, (*copy).len), ((*seg).p, 10));
            assert_eq!((*(*seg).p).ref_, 2);
            tcp_seg_free(copy);
            assert_eq!((*(*seg).p).ref_, 1);
        }
    });
}

#[test]
fn the_effective_mss_follows_the_mtu() {
    with_tcp(|netif| {
        let v4 = IpAddr::v4(PEER.addr);
        let mut v6 = IpAddr::v4(0);
        v6.set_zero_ip6();
        // SAFETY: a live netif and valid addresses.
        unsafe {
            assert_eq!(tcp_eff_send_mss_netif(1440, netif, &v4), 1440);
            (*netif).mtu = 576;
            assert_eq!(tcp_eff_send_mss_netif(1440, netif, &v4), 536);
            (*netif).mtu = 1500;
            assert_eq!(tcp_eff_send_mss_netif(1440, ptr::null_mut(), &v4), 1440);
            // IPv6: the stand-in path MTU of 1280, less 60 bytes of headers.
            assert_eq!(tcp_eff_send_mss_netif(1440, netif, &v6), 1220);
        }
    });
}
