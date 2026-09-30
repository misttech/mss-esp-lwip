// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! test/unit/tcp/test_tcp.c.

extern crate std;

use core::ptr;
use std::vec::Vec;

use super::helper::*;
use crate::links::*;
use crate::tcp::{
    tcp_abort, tcp_close, tcp_fasttmr, tcp_listen_with_backlog, tcp_new, tcp_recv, tcp_slowtmr,
};
use crate::tcp_out::{tcp_output, tcp_write};
use crate::types::*;

/// Used with `check_seqnos()`.
const SEQNO1: u32 = 0xFFFF_FF00 - TEST_MSS as u32;

fn seqnos() -> [u32; 6] {
    core::array::from_fn(|i| SEQNO1.wrapping_add(i as u32 * u32::from(TEST_MSS)))
}

/// Our own version of tcp_tmr so we can reset fast/slow timer state.
struct Tmr(u8);

impl Tmr {
    fn tick(&mut self) {
        tcp_fasttmr();
        self.0 = self.0.wrapping_add(1);
        if self.0 & 1 != 0 {
            tcp_slowtmr();
        }
    }
}

fn check_seqnos(segs: *mut TcpSeg, expected: &[u32]) {
    let mut s = segs;
    for &seqno in expected {
        assert!(!s.is_null());
        // SAFETY: a list of live output segments.
        unsafe {
            assert_eq!(
                u32::from_be(ptr::addr_of!((*(*s).tcphdr).seqno).read_unaligned()),
                seqno
            );
            s = (*s).next;
        }
    }
    assert!(s.is_null());
}

fn write(pcb: *mut TcpPcb, data: &[u8]) -> ErrT {
    // SAFETY: a live PCB; the data is copied.
    unsafe {
        tcp_write(
            pcb,
            data.as_ptr().cast(),
            data.len() as u16,
            TCP_WRITE_FLAG_COPY,
        )
    }
}

fn output(pcb: *mut TcpPcb) -> ErrT {
    // SAFETY: a live PCB.
    unsafe { tcp_output(pcb) }
}

fn abort(pcb: *mut TcpPcb) {
    assert_eq!(pcbs_in_use(), 1);
    // SAFETY: a live PCB.
    unsafe { tcp_abort(pcb) };
    assert_eq!(pcbs_in_use(), 0);
}

/// An ESTABLISHED connection with the counters' callbacks and test_tcp.c's MSS.
fn established(counters: &mut Counters) -> *mut TcpPcb {
    let pcb = test_tcp_new_counters_pcb(counters);
    assert!(!pcb.is_null());
    tcp_set_state(
        pcb,
        ESTABLISHED,
        &TEST_LOCAL_IP,
        &TEST_REMOTE_IP,
        TEST_LOCAL_PORT,
        TEST_REMOTE_PORT,
    );
    // SAFETY: a live PCB.
    unsafe { (*pcb).mss = TEST_MSS };
    pcb
}

fn tx_data() -> Vec<u8> {
    (0..usize::from(TCP_WND) * 2).map(|i| i as u8).collect()
}

/// Call tcp_new() and tcp_abort() and test memp stats.
#[test]
fn test_tcp_new_abort() {
    let _f = Fixture::new();
    let pcb = tcp_new();
    assert!(!pcb.is_null());
    // A new PCB is on no list: memp counts it, the lists do not.
    // SAFETY: a fresh PCB.
    unsafe { tcp_abort(pcb) };
    assert_eq!(pcbs_in_use(), 0);
}

/// A SYN to a listener gets a SYN-ACK; a short one does not.
#[test]
fn test_tcp_listen_passive_open() {
    let mut f = Fixture::new();
    let netif = f.netif();
    let pcb = tcp_new();
    // SAFETY: live PCBs and netif.
    unsafe {
        assert_eq!(crate::tcp::tcp_bind(pcb, &(*netif).ip_addr, 1234), ERR_OK);
        let pcbl = tcp_listen_with_backlog(pcb, crate::config::TCP_DEFAULT_LISTEN_BACKLOG as u8);
        assert!(!pcbl.is_null() && pcbl != pcb);
        let lpcb = pcbl.cast::<TcpPcbListen>();
        let src_addr = IpAddr::v4((u32::from_be((*lpcb).local_ip.ip4().addr) + 1).to_be());

        // Check correct syn packet.
        let p = tcp_create_segment(
            &src_addr,
            &(*lpcb).local_ip,
            12345,
            (*lpcb).local_port,
            &[],
            12345,
            54321,
            TCP_SYN,
        );
        test_tcp_input(p, netif);
        assert_eq!(f.tx.num_tx_calls, 1);

        // Check syn packet with short length.
        let p = tcp_create_segment(
            &src_addr,
            &(*lpcb).local_ip,
            12345,
            (*lpcb).local_port,
            &[],
            12345,
            54321,
            TCP_SYN,
        );
        assert!((*p).next.is_none());
        (*p).len -= 2;
        (*p).tot_len -= 2;
        test_tcp_input(p, netif);
        assert_eq!(f.tx.num_tx_calls, 1);

        tcp_close(pcbl);
        // The connection the first SYN opened.
        crate::tcp::tcp_abort(crate::tcp::tcp_active_pcbs.get());
    }
}

/// Create an ESTABLISHED pcb and check if receive callback is called.
#[test]
fn test_tcp_recv_inseq() {
    let mut f = Fixture::new();
    let netif = f.netif();
    let data = [1, 2, 3, 4];
    let mut counters = Counters {
        expected_data: data.to_vec(),
        ..Default::default()
    };
    let pcb = established(&mut counters);
    let p = tcp_create_rx_segment(pcb, &data, 0, 0, 0);
    test_tcp_input(p, netif);
    assert_eq!(
        (
            counters.close_calls,
            counters.recv_calls,
            counters.recved_bytes,
            counters.err_calls
        ),
        (0, 1, 4, 0)
    );
    abort(pcb);
}

/// Create an ESTABLISHED pcb and check if receive callback is called if a segment
/// overlapping rcv_nxt is received.
#[test]
fn test_tcp_recv_inseq_trim() {
    let mut f = Fixture::new();
    let netif = f.netif();
    let data = std::vec![0_u8; crate::config::PBUF_POOL_BUFSIZE * 2];
    let data_len = data.len() as u32;
    let new_data_len = 40;
    let mut counters = Counters {
        expected_data: data.clone(),
        ..Default::default()
    };
    let pcb = established(&mut counters);
    // Create a segment (with an overlapping/old seqno so that the new data begins in the
    // 2nd pbuf).
    let p = tcp_create_rx_segment(
        pcb,
        &data,
        0_u32.wrapping_sub(data_len - new_data_len),
        0,
        0,
    );
    // SAFETY: a live pbuf chain.
    unsafe {
        let next = (*p).next.unwrap().as_ptr();
        assert!((*next).next.is_some());
    }
    test_tcp_input(p, netif);
    assert_eq!(
        (
            counters.close_calls,
            counters.recv_calls,
            counters.recved_bytes,
            counters.err_calls
        ),
        (0, 1, new_data_len, 0)
    );
    abort(pcb);
}

unsafe extern "C" fn test_tcp_recv_expectclose(
    _arg: *mut core::ffi::c_void,
    pcb: *mut TcpPcb,
    p: *mut Pbuf,
    err: ErrT,
) -> ErrT {
    assert!(!pcb.is_null());
    assert_eq!(err, ERR_OK);
    assert!(p.is_null(), "only the FIN is expected");
    // Correct: FIN received; close our end, too.
    // SAFETY: the callback's live PCB.
    unsafe {
        assert_eq!(tcp_close(pcb), ERR_OK);
        // Set back to some other rx function, just to not get here again.
        tcp_recv(pcb, Some(test_tcp_recv_expect1byte));
    }
    ERR_OK
}

unsafe extern "C" fn test_tcp_recv_expect1byte(
    _arg: *mut core::ffi::c_void,
    pcb: *mut TcpPcb,
    p: *mut Pbuf,
    err: ErrT,
) -> ErrT {
    assert!(!pcb.is_null());
    assert_eq!(err, ERR_OK);
    assert!(!p.is_null(), "no FIN expected here");
    // SAFETY: the callback's live PCB and pbuf.
    unsafe {
        assert_eq!(((*p).len, (*p).tot_len), (1, 1));
        tcp_recv(pcb, Some(test_tcp_recv_expectclose));
        pbuf_free(p);
    }
    ERR_OK
}

#[test]
fn test_tcp_passive_close() {
    let mut f = Fixture::new();
    let netif = f.netif();
    let data = [0x0f];
    let mut counters = Counters {
        expected_data: data.to_vec(),
        ..Default::default()
    };
    let pcb = established(&mut counters);
    // Create a segment with one byte and FIN.
    let p = tcp_create_rx_segment(pcb, &data, 0, 0, TCP_FIN);
    // SAFETY: a live PCB.
    unsafe { tcp_recv(pcb, Some(test_tcp_recv_expect1byte)) };
    test_tcp_input(p, netif);
    // Don't free the pcb here (part of the test!): the callbacks closed it. The byte was
    // never passed to tcp_recved, so tcp_close reset the connection and freed the PCB,
    // as C's does; test_tcp.c checks nothing further.
    assert_eq!(pcbs_in_use(), 0);
}

#[test]
fn test_tcp_active_abort() {
    let mut f = Fixture::new();
    let mut counters = Counters {
        expected_data: std::vec![0x0f],
        ..Default::default()
    };
    let pcb = established(&mut counters);
    // Abort the pcb.
    assert_eq!(f.tx.num_tx_calls, 0);
    f.tx.copy_tx_packets = true;
    // SAFETY: a live PCB.
    unsafe { tcp_abort(pcb) };
    f.tx.copy_tx_packets = false;
    assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (1, 40));
    let tcphdr = &f.tx.tx_packets[0][20..40];
    assert_eq!(u16::from_be_bytes([tcphdr[2], tcphdr[3]]), TEST_REMOTE_PORT);
    assert_eq!(u16::from_be_bytes([tcphdr[0], tcphdr[1]]), TEST_LOCAL_PORT);
}

/// Check that we handle malformed tcp headers, and discard the pbuf(s).
#[test]
fn test_tcp_malformed_header() {
    let mut f = Fixture::new();
    let netif = f.netif();
    let data = [1, 2, 3, 4];
    let mut counters = Counters {
        expected_data: data.to_vec(),
        ..Default::default()
    };
    let pcb = established(&mut counters);
    let p = tcp_create_rx_segment(pcb, &data, 0, 0, 0);
    // SAFETY: a live pbuf in one piece.
    unsafe {
        pbuf_remove_header(p, usize::from(IP_HLEN));
        let hdr = (*p).payload.cast::<u8>();
        // TCPH_HDRLEN_FLAGS_SET(hdr, 15, 0x3d1).
        hdr.add(12)
            .cast::<u16>()
            .write_unaligned(((15_u16 << 12) | 0x3d1).to_be());
        hdr.add(16).cast::<u16>().write_unaligned(0);
        let chksum = ip_chksum_pseudo(
            p,
            IP_PROTO_TCP,
            (*p).tot_len,
            &TEST_REMOTE_IP,
            &TEST_LOCAL_IP,
        );
        hdr.add(16).cast::<u16>().write_unaligned(chksum);
        pbuf_add_header(p, usize::from(IP_HLEN));
        assert!((*p).next.is_none());
    }
    test_tcp_input(p, netif);
    assert_eq!(
        (
            counters.close_calls,
            counters.recv_calls,
            counters.recved_bytes,
            counters.err_calls
        ),
        (0, 0, 0, 0)
    );
    abort(pcb);
}

/// Provoke fast retransmission by duplicate ACKs and then recover by ACKing all sent
/// data. At the end, send more data.
#[test]
fn test_tcp_fast_retx_recover() {
    let mut f = Fixture::new();
    let netif = f.netif();
    let mut counters = Counters::default();
    let (data1, data2, data3, data4, data5) = (
        [1, 2, 3, 4],
        [5, 6, 7, 8],
        [9, 10, 11, 12],
        [13, 14, 15, 16],
        [17, 18, 19, 20],
    );
    let mut data6 = std::vec![0_u8; usize::from(TEST_MSS)];
    data6[..4].copy_from_slice(&[21, 22, 23, 24]);
    let pcb = established(&mut counters);
    // Disable initial congestion window (we don't send a SYN here...).
    // SAFETY: a live PCB.
    unsafe { (*pcb).cwnd = (*pcb).snd_wnd };

    // Send data1.
    assert_eq!(write(pcb, &data1), ERR_OK);
    assert_eq!(output(pcb), ERR_OK);
    assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (1, 4 + 40));
    f.tx.reset();
    // "recv" ACK for data1.
    test_tcp_input(tcp_create_rx_segment(pcb, &[], 0, 4, TCP_ACK), netif);
    assert_eq!(f.tx.num_tx_calls, 0);
    // SAFETY: a live PCB.
    assert!(unsafe { (*pcb).unacked.is_null() });
    // Send data2.
    assert_eq!(write(pcb, &data2), ERR_OK);
    assert_eq!(output(pcb), ERR_OK);
    assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (1, 4 + 40));
    f.tx.reset();
    // Duplicate ACK for data1 (data2 is lost).
    test_tcp_input(tcp_create_rx_segment(pcb, &[], 0, 0, TCP_ACK), netif);
    assert_eq!(f.tx.num_tx_calls, 0);
    // SAFETY: a live PCB.
    assert_eq!(unsafe { (*pcb).dupacks }, 1);
    // Send data3.
    assert_eq!(write(pcb, &data3), ERR_OK);
    assert_eq!(output(pcb), ERR_OK);
    // Nagle enabled, no tx calls.
    assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (0, 0));
    f.tx.reset();
    // 2nd duplicate ACK for data1 (data2 and data3 are lost).
    test_tcp_input(tcp_create_rx_segment(pcb, &[], 0, 0, TCP_ACK), netif);
    assert_eq!(f.tx.num_tx_calls, 0);
    // SAFETY: a live PCB.
    assert_eq!(unsafe { (*pcb).dupacks }, 2);
    // Queue data4, don't send it (unsent-oversize is != 0).
    assert_eq!(write(pcb, &data4), ERR_OK);
    // 3nd duplicate ACK for data1 (data2 and data3 are lost) -> fast retransmission.
    test_tcp_input(tcp_create_rx_segment(pcb, &[], 0, 0, TCP_ACK), netif);
    // SAFETY: a live PCB.
    assert_eq!(unsafe { (*pcb).dupacks }, 3);
    f.tx.reset();
    // Send data5, not output yet.
    assert_eq!(write(pcb, &data5), ERR_OK);
    assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (0, 0));
    f.tx.reset();
    loop {
        if write(pcb, &data6) != ERR_OK {
            break;
        }
    }
    assert_eq!(output(pcb), ERR_OK);
    f.tx.reset();
    // Send even more data.
    for _ in 0..4 {
        assert_eq!(write(pcb, &data5), ERR_OK);
        assert_eq!(output(pcb), ERR_OK);
    }
    // Send ACKs for data2 and data3.
    test_tcp_input(tcp_create_rx_segment(pcb, &[], 0, 12, TCP_ACK), netif);
    // ...and even more data.
    for _ in 0..2 {
        assert_eq!(write(pcb, &data5), ERR_OK);
        assert_eq!(output(pcb), ERR_OK);
    }
    abort(pcb);
}

/// Send data with sequence numbers that wrap around the u32_t range. Then, provoke fast
/// retransmission by duplicate ACKs and check that all segment lists are still properly
/// sorted.
#[test]
fn test_tcp_fast_rexmit_wraparound() {
    let mut f = Fixture::new();
    let netif = f.netif();
    let tx_data = tx_data();
    let seqnos = seqnos();
    let mss = usize::from(TEST_MSS);
    let mut counters = Counters::default();
    crate::test_support::TCP_ISS.store(SEQNO1, core::sync::atomic::Ordering::Relaxed);
    let pcb = established(&mut counters);
    // SAFETY: a live PCB.
    unsafe {
        // Disable initial congestion window (we don't send a SYN here...).
        (*pcb).cwnd = 2 * TEST_MSS;
        // Start in congestion advoidance.
        (*pcb).ssthresh = (*pcb).cwnd;
    }
    // Send 6 mss-sized segments.
    for i in 0..6 {
        assert_eq!(write(pcb, &tx_data[i * mss..(i + 1) * mss]), ERR_OK);
    }
    // SAFETY: a live PCB.
    unsafe {
        check_seqnos((*pcb).unsent, &seqnos);
        assert!((*pcb).unacked.is_null());
        assert_eq!(output(pcb), ERR_OK);
        assert_eq!(
            (f.tx.num_tx_calls, f.tx.num_tx_bytes),
            (2, 2 * (u32::from(TEST_MSS) + 40))
        );
        f.tx.reset();
        check_seqnos((*pcb).unacked, &seqnos[..2]);
        check_seqnos((*pcb).unsent, &seqnos[2..]);

        // ACK the first segment.
        test_tcp_input(
            tcp_create_rx_segment(pcb, &[], 0, u32::from(TEST_MSS), TCP_ACK),
            netif,
        );
        // Ensure this didn't trigger a retransmission. Only one segment should be
        // transmitted because cwnd opened up by TCP_MSS and a fraction since we are in
        // congestion avoidance.
        assert_eq!(
            (f.tx.num_tx_calls, f.tx.num_tx_bytes),
            (1, u32::from(TEST_MSS) + 40)
        );
        f.tx.reset();
        check_seqnos((*pcb).unacked, &seqnos[1..3]);
        check_seqnos((*pcb).unsent, &seqnos[3..]);

        // 3 dupacks.
        assert_eq!((*pcb).dupacks, 0);
        test_tcp_input(tcp_create_rx_segment(pcb, &[], 0, 0, TCP_ACK), netif);
        assert_eq!(f.tx.num_tx_calls, 0);
        assert_eq!((*pcb).dupacks, 1);
        test_tcp_input(tcp_create_rx_segment(pcb, &[], 0, 0, TCP_ACK), netif);
        assert_eq!(f.tx.num_tx_calls, 0);
        assert_eq!((*pcb).dupacks, 2);
        // 3rd dupack -> fast rexmit.
        test_tcp_input(tcp_create_rx_segment(pcb, &[], 0, 0, TCP_ACK), netif);
        assert_eq!((*pcb).dupacks, 3);
        assert_eq!(f.tx.num_tx_calls, 4);
        f.tx.reset();
        assert!((*pcb).unsent.is_null());
        check_seqnos((*pcb).unacked, &seqnos[1..]);
    }
    abort(pcb);
}

/// Send data with sequence numbers that wrap around the u32_t range. Then, provoke RTO
/// retransmission and check that all segment lists are still properly sorted.
#[test]
fn test_tcp_rto_rexmit_wraparound() {
    let mut f = Fixture::new();
    let tx_data = tx_data();
    let seqnos = seqnos();
    let mss = usize::from(TEST_MSS);
    let mut counters = Counters::default();
    let mut tmr = Tmr(0);
    crate::test_support::TCP_ISS.store(SEQNO1, core::sync::atomic::Ordering::Relaxed);
    let pcb = established(&mut counters);
    // SAFETY: a live PCB.
    unsafe {
        // Disable initial congestion window (we don't send a SYN here...).
        (*pcb).cwnd = 2 * TEST_MSS;
    }
    // Send 6 mss-sized segments.
    for i in 0..6 {
        assert_eq!(write(pcb, &tx_data[i * mss..(i + 1) * mss]), ERR_OK);
    }
    // SAFETY: a live PCB.
    unsafe {
        check_seqnos((*pcb).unsent, &seqnos);
        assert!((*pcb).unacked.is_null());
        assert_eq!(output(pcb), ERR_OK);
        assert_eq!(
            (f.tx.num_tx_calls, f.tx.num_tx_bytes),
            (2, 2 * (u32::from(TEST_MSS) + 40))
        );
        f.tx.reset();
        check_seqnos((*pcb).unacked, &seqnos[..2]);
        check_seqnos((*pcb).unsent, &seqnos[2..]);

        // Call the tcp timer some times: the slow timer runs on every other call, so the
        // RTO fires on call 2 * rto - 1 (test_tcp.c's 11th, at its 3 s RTO).
        let fire = 2 * (*pcb).rto as usize - 1;
        for _ in 0..fire - 1 {
            tmr.tick();
            assert_eq!(f.tx.num_tx_calls, 0);
        }
        tmr.tick();
        assert_eq!(f.tx.num_tx_calls, 1);
        check_seqnos((*pcb).unacked, &seqnos[..1]);
        check_seqnos((*pcb).unsent, &seqnos[1..]);

        // Fake greater cwnd.
        (*pcb).cwnd = (*pcb).snd_wnd;
        // Send more data.
        assert_eq!(output(pcb), ERR_OK);
        // Check queues are sorted.
        assert!((*pcb).unsent.is_null());
        check_seqnos((*pcb).unacked, &seqnos);
    }
    abort(pcb);
}

/// Send a full window, lose it, and check the persist timer and the window probe it
/// sends.
fn test_tcp_tx_full_window_lost(zero_window_probe_from_unsent: bool) {
    let mut f = Fixture::new();
    let netif = f.netif();
    let mss = usize::from(TEST_MSS);
    let wnd = usize::from(TCP_WND);
    let expected: u8 = 0xFE;
    let mut tx_data: Vec<u8> = (0..wnd * 2)
        .map(|i| if i as u8 == 0xFE { 0xF0 } else { i as u8 })
        .collect();
    if zero_window_probe_from_unsent {
        tx_data[wnd] = expected;
    } else {
        tx_data[0] = expected;
    }
    let mut counters = Counters::default();
    let mut tmr = Tmr(0);
    let pcb = established(&mut counters);
    // SAFETY: a live PCB.
    unsafe {
        // Disable initial congestion window (we don't send a SYN here...).
        (*pcb).cwnd = (*pcb).snd_wnd;
    }
    // Send a full window (minus 1 packets) of TCP data in MSS-sized chunks.
    let mut sent_total = 0;
    if (wnd - mss) % mss != 0 {
        let initial_data_len = (wnd - mss) % mss;
        assert_eq!(write(pcb, &tx_data[..initial_data_len]), ERR_OK);
        assert_eq!(output(pcb), ERR_OK);
        assert_eq!(
            (f.tx.num_tx_calls, f.tx.num_tx_bytes),
            (1, initial_data_len as u32 + 40)
        );
        f.tx.reset();
        sent_total += initial_data_len;
    }
    while sent_total < wnd - mss {
        assert_eq!(write(pcb, &tx_data[sent_total..sent_total + mss]), ERR_OK);
        assert_eq!(output(pcb), ERR_OK);
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (1, mss as u32 + 40));
        f.tx.reset();
        sent_total += mss;
    }
    assert_eq!(sent_total, wnd - mss);
    // SAFETY: a live PCB.
    unsafe {
        // Now ACK the packet before the first.
        test_tcp_input(tcp_create_rx_segment(pcb, &[], 0, 0, TCP_ACK), netif);
        // Ensure this didn't trigger a retransmission.
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (0, 0));
        assert_eq!((*pcb).persist_backoff, 0);
        // Send the last packet, now a complete window has been sent.
        assert_eq!(write(pcb, &tx_data[sent_total..sent_total + mss]), ERR_OK);
        sent_total += mss;
        assert_eq!(output(pcb), ERR_OK);
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (1, mss as u32 + 40));
        f.tx.reset();
        assert_eq!((*pcb).persist_backoff, 0);

        if zero_window_probe_from_unsent {
            // ACK all data but close the TX window.
            test_tcp_input(
                tcp_create_rx_segment_wnd(pcb, &[], 0, u32::from(TCP_WND), TCP_ACK, 0),
                netif,
            );
            // Ensure this didn't trigger any transmission.
            assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (0, 0));
            // Window is completely full, but persist timer is off since send buffer is
            // empty.
            assert_eq!((*pcb).snd_wnd, 0);
            assert_eq!((*pcb).persist_backoff, 0);
        }

        // Send one byte more (out of window) -> persist timer starts.
        assert_eq!(write(pcb, &tx_data[sent_total..sent_total + 1]), ERR_OK);
        assert_eq!(output(pcb), ERR_OK);
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (0, 0));
        f.tx.reset();
        if !zero_window_probe_from_unsent {
            // No persist timer unless a zero window announcement has been received.
            assert_eq!((*pcb).persist_backoff, 0);
        } else {
            assert_eq!((*pcb).persist_backoff, 1);
            // Call tcp_timer some more times to let persist timer count up.
            for _ in 0..4 {
                tmr.tick();
                assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (0, 0));
            }
            // This should trigger the zero-window-probe.
            f.tx.copy_tx_packets = true;
            tmr.tick();
            f.tx.copy_tx_packets = false;
            assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (1, 1 + 40));
            assert_eq!(f.tx.tx_packets[0][40], expected);
        }
    }
    abort(pcb);
}

#[test]
fn test_tcp_tx_full_window_lost_from_unsent() {
    test_tcp_tx_full_window_lost(true);
}

#[test]
fn test_tcp_tx_full_window_lost_from_unacked() {
    test_tcp_tx_full_window_lost(false);
}

/// Send data, provoke retransmission and then add data to a segment that already has
/// been sent before.
#[test]
fn test_tcp_retx_add_to_sent() {
    let mut f = Fixture::new();
    let netif = f.netif();
    let (data1a, data1b, data2a, data2b) = ([1, 2, 3], [4], [5, 6, 7, 8], [5, 6, 7]);
    let (data3, data4) = ([9, 10, 11, 12, 12], [13, 14, 15, 16, 17]);
    let mut counters = Counters::default();
    let mut tmr = Tmr(0);
    let pcb = established(&mut counters);
    // SAFETY: a live PCB.
    unsafe {
        // Disable initial congestion window (we don't send a SYN here...).
        (*pcb).cwnd = (*pcb).snd_wnd;

        // Send data1.
        assert_eq!(write(pcb, &data1a), ERR_OK);
        assert_eq!(write(pcb, &data1b), ERR_OK);
        assert_eq!(output(pcb), ERR_OK);
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (1, 4 + 40));
        f.tx.reset();
        // "recv" ACK for data1.
        test_tcp_input(tcp_create_rx_segment(pcb, &[], 0, 4, TCP_ACK), netif);
        assert_eq!(f.tx.num_tx_calls, 0);
        assert!((*pcb).unacked.is_null());
        // Send data2.
        assert_eq!(write(pcb, &data2a), ERR_OK);
        assert_eq!(write(pcb, &data2b), ERR_OK);
        assert_eq!(output(pcb), ERR_OK);
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (1, 7 + 40));
        f.tx.reset();
        // Send data3.
        assert_eq!(write(pcb, &data3), ERR_OK);
        assert_eq!(output(pcb), ERR_OK);
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (0, 0));
        f.tx.reset();
        // data3 not sent yet (nagle).
        assert!(!(*pcb).unacked.is_null());
        assert!(!(*pcb).unsent.is_null());

        // Disable nagle for this test so data to sent segment can be added below...
        (*pcb).flags |= TF_NODELAY;
        // Call the tcp timer some times.
        for _ in 0..20 {
            tmr.tick();
            if f.tx.num_tx_calls != 0 {
                break;
            }
        }
        // data3 sent.
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (1, 5 + 40));
        assert!(!(*pcb).unacked.is_null());
        assert!((*pcb).unsent.is_null());
        f.tx.reset();

        (*pcb).flags &= !TF_NODELAY;
        // Call the tcp timer some times.
        for _ in 0..20 {
            tmr.tick();
            if f.tx.num_tx_calls != 0 {
                break;
            }
        }
        // RTO: rexmit of data2.
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (1, 7 + 40));
        assert!(!(*pcb).unacked.is_null());
        assert!(!(*pcb).unsent.is_null());
        f.tx.reset();

        // Send data4.
        assert_eq!(write(pcb, &data4), ERR_OK);
        // Disable nagle for this test so data to transmit without further ACKs...
        (*pcb).flags |= TF_NODELAY;
        assert_eq!(output(pcb), ERR_OK);
        // test_tcp.c expects data3 and data4 in one segment; ESP-IDF's
        // LWIP_NETIF_TX_SINGLE_PBUF sends them apart, as the C files do (see
        // rust/test/unit/expected-failures.txt).
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (2, 5 + 40 + 5 + 40));
        f.tx.reset();
    }
    abort(pcb);
}

#[test]
fn test_tcp_rto_tracking() {
    let mut f = Fixture::new();
    let netif = f.netif();
    let tx_data = tx_data();
    let seqnos = seqnos();
    let mss = usize::from(TEST_MSS);
    let mss32 = u32::from(TEST_MSS);
    let mut counters = Counters::default();
    let mut tmr = Tmr(0);
    crate::test_support::TCP_ISS.store(SEQNO1, core::sync::atomic::Ordering::Relaxed);
    let pcb = established(&mut counters);
    // SAFETY: a live PCB.
    unsafe {
        // Set congestion window large enough to send all our segments.
        (*pcb).cwnd = 5 * TEST_MSS;
        // Send 5 mss-sized segments.
        for i in 0..5 {
            assert_eq!(write(pcb, &tx_data[i * mss..(i + 1) * mss]), ERR_OK);
        }
        check_seqnos((*pcb).unsent, &seqnos[..5]);
        assert!((*pcb).unacked.is_null());
        assert_eq!(output(pcb), ERR_OK);
        assert_eq!(
            (f.tx.num_tx_calls, f.tx.num_tx_bytes),
            (5, 5 * (mss32 + 40))
        );
        f.tx.reset();
        // Check all 5 are in-flight.
        assert!((*pcb).unsent.is_null());
        check_seqnos((*pcb).unacked, &seqnos[..5]);

        // Force us into retransmisson timeout.
        // The timer changes the PCB through C.
        loop {
            if !((*pcb).flags & TF_RTO == 0) {
                break;
            }
            tmr.tick();
        }
        // Ensure 4 remaining segments are back on unsent, ready for retransmission.
        check_seqnos((*pcb).unsent, &seqnos[1..5]);
        // Ensure 1st segment is on unacked (already retransmitted).
        check_seqnos((*pcb).unacked, &seqnos[..1]);
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (1, mss32 + 40));
        f.tx.reset();
        // Ensure rto_end points to next byte.
        assert_eq!((*pcb).rto_end, seqnos[5]);
        assert_eq!((*pcb).rto_end, (*pcb).snd_nxt);
        // Check cwnd was reset.
        assert_eq!((*pcb).cwnd, (*pcb).mss);

        // Add another segment to send buffer which is outside of RTO.
        assert_eq!(write(pcb, &tx_data[5 * mss..6 * mss]), ERR_OK);
        check_seqnos((*pcb).unsent, &seqnos[1..]);
        // Ensure no new data was sent.
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (0, 0));
        assert_eq!((*pcb).rto_end, (*pcb).snd_nxt);

        // ACK first segment.
        test_tcp_input(tcp_create_rx_segment(pcb, &[], 0, mss32, TCP_ACK), netif);
        // Next two retranmissions should go out, due to cwnd in slow start.
        assert_eq!(
            (f.tx.num_tx_calls, f.tx.num_tx_bytes),
            (2, 2 * (mss32 + 40))
        );
        f.tx.reset();
        check_seqnos((*pcb).unacked, &seqnos[1..3]);
        check_seqnos((*pcb).unsent, &seqnos[3..]);
        // RTO should still be marked.
        assert_ne!((*pcb).flags & TF_RTO, 0);
        // cwnd should have only grown by 1 MSS.
        assert_eq!((*pcb).cwnd, 2 * (*pcb).mss);
        // Ensure no new data was sent.
        assert_eq!((*pcb).rto_end, (*pcb).snd_nxt);

        // ACK the next two segments.
        test_tcp_input(
            tcp_create_rx_segment(pcb, &[], 0, 2 * mss32, TCP_ACK),
            netif,
        );
        // Final 2 retransmissions and 1 new data should go out.
        assert_eq!(
            (f.tx.num_tx_calls, f.tx.num_tx_bytes),
            (3, 3 * (mss32 + 40))
        );
        f.tx.reset();
        check_seqnos((*pcb).unacked, &seqnos[3..]);
        assert!((*pcb).unsent.is_null());
        // RTO should still be marked.
        assert_ne!((*pcb).flags & TF_RTO, 0);
        // cwnd should have only grown by 1 MSS.
        assert_eq!((*pcb).cwnd, 3 * (*pcb).mss);
        // snd_nxt should have been advanced past rto_end.
        assert!(((*pcb).snd_nxt.wrapping_sub((*pcb).rto_end) as i32) > 0);

        // ACK the next two segments, finishing our RTO, leaving new segment unacked.
        test_tcp_input(
            tcp_create_rx_segment(pcb, &[], 0, 2 * mss32, TCP_ACK),
            netif,
        );
        assert_eq!((*pcb).flags & TF_RTO, 0);
        check_seqnos((*pcb).unacked, &seqnos[5..]);
        // We should be in ABC congestion avoidance, so no change in cwnd.
        assert_eq!((*pcb).cwnd, 3 * (*pcb).mss);
        assert!((*pcb).cwnd >= (*pcb).ssthresh);
        // Ensure ABC congestion avoidance is tracking bytes acked.
        assert_eq!((*pcb).bytes_acked, 2 * (*pcb).mss);
    }
    abort(pcb);
}

fn test_tcp_rto_timeout_impl(link_down: bool) {
    let mut f = Fixture::new();
    let netif = f.netif();
    let tx_data = tx_data();
    let mss32 = u32::from(TEST_MSS);
    let max_wait_ctr = 1024 * 1024;
    let mut counters = Counters::default();
    let mut tmr = Tmr(0);
    crate::test_support::TCP_ISS.store(SEQNO1, core::sync::atomic::Ordering::Relaxed);
    let pcb = established(&mut counters);
    // SAFETY: a live PCB until the timer aborts it.
    unsafe {
        (*pcb).cwnd = TEST_MSS;
        // Send our segment.
        assert_eq!(write(pcb, &tx_data[..usize::from(TEST_MSS)]), ERR_OK);
        assert_eq!(output(pcb), ERR_OK);
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (1, mss32 + 40));
        f.tx.reset();
        // Ensure no errors have been recorded.
        assert_eq!((counters.err_calls, counters.last_err), (0, ERR_OK));

        // Force us into retransmisson timeout.
        let mut i = 0;
        while (*pcb).flags & TF_RTO == 0 && i < max_wait_ctr {
            tmr.tick();
            i += 1;
        }
        assert!(i < max_wait_ctr);
        // Check first rexmit.
        assert_eq!((*pcb).nrtx, 1);
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (1, mss32 + 40));
        // Still no error expected.
        assert_eq!((counters.err_calls, counters.last_err), (0, ERR_OK));

        if link_down {
            crate::netif::netif_set_link_down(netif);
        }
    }

    // Keep running the timer till we hit our maximum RTO.
    let mut i = 0;
    while counters.last_err == ERR_OK && i < max_wait_ctr {
        tmr.tick();
        i += 1;
    }
    assert!(i < max_wait_ctr);

    // Check number of retransmissions.
    let maxrtx = crate::config::TCP_MAXRTX as u32;
    if link_down {
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (1, mss32 + 40));
    } else {
        assert_eq!(
            (f.tx.num_tx_calls, f.tx.num_tx_bytes),
            (maxrtx, maxrtx * (mss32 + 40))
        );
    }
    // Check the connection (pcb) has been aborted.
    assert_eq!((counters.err_calls, counters.last_err), (1, ERR_ABRT));
    // Check our pcb is no longer active.
    assert_eq!(pcbs_in_use(), 0);
}

#[test]
fn test_tcp_rto_timeout() {
    test_tcp_rto_timeout_impl(false);
}

#[test]
fn test_tcp_rto_timeout_link_down() {
    test_tcp_rto_timeout_impl(true);
}

fn test_tcp_rto_timeout_syn_sent_impl(link_down: bool) {
    let mut f = Fixture::new();
    let netif = f.netif();
    let max_wait_ctr = 1024 * 1024;
    // LWIP_TCP_OPT_LENGTH of every SYN option: only the MSS option is configured.
    let tcp_syn_opts_len = 4_u32;
    let mut counters = Counters::default();
    let mut tmr = Tmr(0);
    crate::test_support::TCP_ISS.store(SEQNO1, core::sync::atomic::Ordering::Relaxed);
    let pcb = test_tcp_new_counters_pcb(&mut counters);
    // SAFETY: a live PCB until the timer aborts it, and a live netif.
    unsafe {
        assert_eq!(
            crate::tcp::tcp_connect(pcb, &(*netif).gw, 123, None),
            ERR_OK
        );
        assert_eq!((*pcb).state, SYN_SENT);
        assert_eq!(
            (f.tx.num_tx_calls, f.tx.num_tx_bytes),
            (1, 40 + tcp_syn_opts_len)
        );
        // Ensure no errors have been recorded.
        assert_eq!((counters.err_calls, counters.last_err), (0, ERR_OK));
        f.tx.reset();

        // Force us into retransmisson timeout.
        let mut i = 0;
        while (*pcb).flags & TF_RTO == 0 && i < max_wait_ctr {
            tmr.tick();
            i += 1;
        }
        assert!(i < max_wait_ctr);
        // Check first rexmit.
        assert_eq!((*pcb).nrtx, 1);
        assert_eq!(
            (f.tx.num_tx_calls, f.tx.num_tx_bytes),
            (1, 40 + tcp_syn_opts_len)
        );
        // Still no error expected.
        assert_eq!((counters.err_calls, counters.last_err), (0, ERR_OK));

        if link_down {
            // Set link down and check what happens to the RTO counter.
            crate::netif::netif_set_link_down(netif);
        }
    }

    // Keep running the timer till we hit our maximum RTO.
    let mut i = 0;
    while counters.last_err == ERR_OK && i < max_wait_ctr {
        tmr.tick();
        i += 1;
    }
    assert!(i < max_wait_ctr);

    // Check number of retransmissions.
    let synmaxrtx = crate::config::TCP_SYNMAXRTX as u32;
    if link_down {
        assert_eq!(
            (f.tx.num_tx_calls, f.tx.num_tx_bytes),
            (1, 40 + tcp_syn_opts_len)
        );
    } else {
        assert_eq!(
            (f.tx.num_tx_calls, f.tx.num_tx_bytes),
            (synmaxrtx, synmaxrtx * (tcp_syn_opts_len + 40))
        );
    }
    // Check the connection (pcb) has been aborted.
    assert_eq!((counters.err_calls, counters.last_err), (1, ERR_ABRT));
    // Check our pcb is no longer active.
    assert_eq!(pcbs_in_use(), 0);
}

#[test]
fn test_tcp_rto_timeout_syn_sent() {
    test_tcp_rto_timeout_syn_sent_impl(false);
}

#[test]
fn test_tcp_rto_timeout_syn_sent_link_down() {
    test_tcp_rto_timeout_syn_sent_impl(true);
}

fn test_tcp_zwp_timeout_impl(link_down: bool) {
    let mut f = Fixture::new();
    let netif = f.netif();
    let tx_data = tx_data();
    let seqnos = seqnos();
    let mss = usize::from(TEST_MSS);
    let mss32 = u32::from(TEST_MSS);
    let mut counters = Counters::default();
    let mut tmr = Tmr(0);
    crate::test_support::TCP_ISS.store(SEQNO1, core::sync::atomic::Ordering::Relaxed);
    let pcb = established(&mut counters);
    // SAFETY: a live PCB until the timer aborts it.
    unsafe {
        (*pcb).cwnd = TEST_MSS;
        // Send first segment.
        assert_eq!(write(pcb, &tx_data[..mss]), ERR_OK);
        assert_eq!(output(pcb), ERR_OK);
        // Verify segment is in-flight.
        assert!((*pcb).unsent.is_null());
        check_seqnos((*pcb).unacked, &seqnos[..1]);
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (1, mss32 + 40));
        f.tx.reset();

        // ACK the segment and close the TX window.
        test_tcp_input(
            tcp_create_rx_segment_wnd(pcb, &[], 0, mss32, TCP_ACK, 0),
            netif,
        );
        assert!((*pcb).unacked.is_null());
        assert!((*pcb).unsent.is_null());
        // Send buffer empty, persist should be off.
        assert_eq!((*pcb).persist_backoff, 0);
        assert_eq!((*pcb).snd_wnd, 0);

        // Send second segment, should be buffered.
        assert_eq!(write(pcb, &tx_data[mss..2 * mss]), ERR_OK);
        assert_eq!(output(pcb), ERR_OK);
        // Ensure it is buffered and persist timer started.
        assert!((*pcb).unacked.is_null());
        check_seqnos((*pcb).unsent, &seqnos[1..2]);
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (0, 0));
        assert_eq!((*pcb).persist_backoff, 1);
        // Ensure no errors have been recorded.
        assert_eq!((counters.err_calls, counters.last_err), (0, ERR_OK));

        // Run timer till first probe.
        assert_eq!((*pcb).persist_probe, 0);
        // The timer changes the PCB through C.
        loop {
            if !((*pcb).persist_probe == 0) {
                break;
            }
            tmr.tick();
        }
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (1, 1 + 40));
        f.tx.reset();

        // Respond to probe with remote's current SEQ, ACK, and zero-window.
        test_tcp_input(tcp_create_rx_segment_wnd(pcb, &[], 0, 0, TCP_ACK, 0), netif);
        // Ensure zero-window is still active, but probe count reset.
        assert!((*pcb).persist_backoff > 1);
        assert_eq!((*pcb).persist_probe, 0);
        assert_eq!((*pcb).snd_wnd, 0);
        // Ensure no errors have been recorded.
        assert_eq!((counters.err_calls, counters.last_err), (0, ERR_OK));

        if link_down {
            crate::netif::netif_set_link_down(netif);
        }
    }

    // Now run the timer till we hit our maximum probe count. The error callback sets
    // the counters through the PCB's argument.
    loop {
        if counters.last_err != ERR_OK {
            break;
        }
        tmr.tick();
    }

    let maxrtx = crate::config::TCP_MAXRTX as u32;
    if link_down {
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (0, 0));
    } else {
        // Check maximum number of 1 byte probes were sent.
        assert_eq!(
            (f.tx.num_tx_calls, f.tx.num_tx_bytes),
            (maxrtx, maxrtx * (1 + 40))
        );
    }
    // Check the connection (pcb) has been aborted.
    assert_eq!((counters.err_calls, counters.last_err), (1, ERR_ABRT));
    // Check our pcb is no longer active.
    assert_eq!(pcbs_in_use(), 0);
}

#[test]
fn test_tcp_zwp_timeout() {
    test_tcp_zwp_timeout_impl(false);
}

#[test]
fn test_tcp_zwp_timeout_link_down() {
    test_tcp_zwp_timeout_impl(true);
}

#[test]
fn test_tcp_persist_split() {
    let mut f = Fixture::new();
    let netif = f.netif();
    let tx_data = tx_data();
    let seqnos = seqnos();
    let mss = TEST_MSS;
    let mut counters = Counters::default();
    let mut tmr = Tmr(0);
    crate::test_support::TCP_ISS.store(SEQNO1, core::sync::atomic::Ordering::Relaxed);
    let pcb = established(&mut counters);
    // SAFETY: a live PCB.
    unsafe {
        // Set window to three segments.
        (*pcb).cwnd = 3 * mss;
        (*pcb).snd_wnd = 3 * mss;
        (*pcb).snd_wnd_max = 3 * mss;
        // Send four segments. Fourth should stay buffered and is a 3/4 MSS segment to get
        // coverage on the oversized segment case.
        let len = usize::from((3 * mss) + (mss - (mss / 4)));
        assert_eq!(write(pcb, &tx_data[..len]), ERR_OK);
        assert_eq!(output(pcb), ERR_OK);
        // Verify 3 segments are in-flight.
        assert!(!(*pcb).unacked.is_null());
        check_seqnos((*pcb).unacked, &seqnos[..3]);
        assert_eq!(
            (f.tx.num_tx_calls, f.tx.num_tx_bytes),
            (3, 3 * (u32::from(mss) + 40))
        );
        f.tx.reset();
        // Verify 4th segment is on unsent.
        assert!(!(*pcb).unsent.is_null());
        assert_eq!((*(*pcb).unsent).len, mss - (mss / 4));
        check_seqnos((*pcb).unsent, &seqnos[3..4]);
        assert_eq!((*pcb).unsent_oversize, mss / 4);

        // ACK the 3 segments and update the window to only 1/2 TCP_MSS. 4th segment
        // should stay on unsent because it's bigger than 1/2 MSS.
        test_tcp_input(
            tcp_create_rx_segment_wnd(pcb, &[], 0, 3 * u32::from(mss), TCP_ACK, mss / 2),
            netif,
        );
        assert!((*pcb).unacked.is_null());
        assert_eq!((*pcb).snd_wnd, mss / 2);
        assert!(!(*pcb).unsent.is_null());
        check_seqnos((*pcb).unsent, &seqnos[3..4]);
        assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (0, 0));
        // Persist timer should be started since 4th segment is stuck waiting on snd_wnd.
        assert_eq!((*pcb).persist_backoff, 1);
        // Ensure no errors have been recorded.
        assert_eq!((counters.err_calls, counters.last_err), (0, ERR_OK));

        // Call tcp_timer some more times to let persist timer count up.
        for _ in 0..4 {
            tmr.tick();
            assert_eq!((f.tx.num_tx_calls, f.tx.num_tx_bytes), (0, 0));
        }

        // This should be the first timer shot, which should split the segment and send a
        // runt (of the remaining window size).
        f.tx.copy_tx_packets = true;
        tmr.tick();
        f.tx.copy_tx_packets = false;
        // Persist will be disabled as RTO timer takes over.
        assert_eq!((*pcb).persist_backoff, 0);
        assert_eq!(
            (f.tx.num_tx_calls, f.tx.num_tx_bytes),
            (1, u32::from(mss / 2) + 40)
        );
        // Verify 1/2 MSS segment sent, 1/4 MSS still buffered.
        assert!(!(*pcb).unsent.is_null());
        assert_eq!((*(*pcb).unsent).len, mss / 4);
        assert!(!(*pcb).unacked.is_null());
        assert_eq!((*(*pcb).unacked).len, mss / 2);
        // Verify there is no oversized remaining since during the segment split, the
        // remainder pbuf is always the exact length.
        assert_eq!((*pcb).unsent_oversize, 0);
        // Verify first half segment.
        let at = usize::from(3 * mss);
        assert_eq!(
            f.tx.tx_packets[0][40..40 + usize::from(mss / 2)],
            tx_data[at..at + usize::from(mss / 2)]
        );
        f.tx.reset();

        // ACK the half segment, leave window at half segment.
        let p = tcp_create_rx_segment_wnd(pcb, &[], 0, u32::from(mss / 2), TCP_ACK, mss / 2);
        f.tx.copy_tx_packets = true;
        test_tcp_input(p, netif);
        f.tx.copy_tx_packets = false;
        // Ensure remaining segment was sent.
        assert_eq!(
            (f.tx.num_tx_calls, f.tx.num_tx_bytes),
            (1, u32::from(mss / 4) + 40)
        );
        assert!((*pcb).unsent.is_null());
        assert!(!(*pcb).unacked.is_null());
        assert_eq!((*(*pcb).unacked).len, mss / 4);
        assert_eq!((*pcb).snd_wnd, mss / 2);
        // Verify remainder segment.
        let at = usize::from(3 * mss + mss / 2);
        assert_eq!(
            f.tx.tx_packets[0][40..40 + usize::from(mss / 4)],
            tx_data[at..at + usize::from(mss / 4)]
        );
        // Ensure no errors have been recorded.
        assert_eq!((counters.err_calls, counters.last_err), (0, ERR_OK));
    }
    abort(pcb);
}
