// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! tcp_out.c's output paths on the IPv4 test netif: segmentation and the oversized
//! tail, Nagle's algorithm, SYN and FIN, splitting, retransmission, and the segments
//! sent directly (RST, empty ACK, keepalive, window probe), each checked on the wire.
//! test_tcp.c's cases drive TCP through tcp_input and tcp.c; they come with those
//! files. Until tcp.c is ported, the tests build the PCB themselves.

extern crate std;

use core::mem::MaybeUninit;
use std::boxed::Box;
use std::sync::Mutex;
use std::vec::Vec;

use super::*;
use crate::ip4::tests::{TEST_IPADDR, ip4, with_test_netif};

const PEER: Ip4Addr = ip4(192, 168, 0, 9);
const ISS: u32 = 1000;
const RCV_NXT: u32 = 5000;

/// The frames the netif sent, whole (IPv4 packets: the output skips ARP).
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

fn frames() -> Vec<Vec<u8>> {
    core::mem::take(&mut *FRAMES.lock().unwrap())
}

/// An ESTABLISHED connection from TEST_IPADDR:1234 to PEER:80 with a 536-byte MSS, as
/// tcp.c and tcp_in.c would leave it.
fn with_pcb(test: impl FnOnce(*mut TcpPcb)) {
    with_test_netif(|netif| {
        // SAFETY: a live netif.
        unsafe {
            (*netif).output = Some(arpless);
            (*netif).linkoutput = Some(record);
        }
        frames();
        // SAFETY: every field of the mirror is valid zeroed.
        let mut pcb: Box<TcpPcb> = Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
        pcb.local_ip = IpAddr::v4(TEST_IPADDR.addr);
        pcb.remote_ip = IpAddr::v4(PEER.addr);
        pcb.local_port = 1234;
        pcb.remote_port = 80;
        pcb.state = ESTABLISHED;
        pcb.mss = 536;
        pcb.snd_wnd = 5760;
        pcb.snd_wnd_max = 5760;
        pcb.cwnd = 5760;
        pcb.snd_buf = 5760;
        pcb.snd_lbb = ISS;
        pcb.snd_nxt = ISS;
        pcb.lastack = ISS;
        pcb.rcv_nxt = RCV_NXT;
        pcb.rcv_wnd = 5760;
        pcb.rcv_ann_wnd = 5760;
        pcb.ttl = 64;
        pcb.rtime = -1;
        let p = &mut *pcb as *mut TcpPcb;

        test(p);

        // SAFETY: the PCB's queues hold live segments.
        unsafe {
            tcp_segs_free((*p).unsent);
            tcp_segs_free((*p).unacked);
        }
    });
}

/// A segment as it went on the wire.
#[derive(Debug)]
struct Seg {
    seqno: u32,
    ackno: u32,
    hdrlen: usize,
    flags: u8,
    wnd: u16,
    options: Vec<u8>,
    payload: Vec<u8>,
}

/// Parses an IPv4/TCP packet and checks both checksums.
fn parse(frame: &[u8]) -> Seg {
    assert_eq!(frame[0], 0x45);
    assert_eq!(frame[9], IP_PROTO_TCP);
    assert_eq!(frame[12..16], TEST_IPADDR.addr.to_ne_bytes());
    assert_eq!(frame[16..20], PEER.addr.to_ne_bytes());
    let tcp = &frame[20..];
    let mut pseudo = Vec::new();
    pseudo.extend(&frame[12..20]);
    pseudo.extend([0, IP_PROTO_TCP]);
    pseudo.extend((tcp.len() as u16).to_be_bytes());
    assert_eq!(ones_sum(tcp, ones_sum(&pseudo, 0)), 0xffff, "TCP checksum");
    assert_eq!(u16::from_be_bytes([tcp[0], tcp[1]]), 1234);
    assert_eq!(u16::from_be_bytes([tcp[2], tcp[3]]), 80);
    let hdrlen = usize::from(tcp[12] >> 4) * 4;
    Seg {
        seqno: u32::from_be_bytes(tcp[4..8].try_into().unwrap()),
        ackno: u32::from_be_bytes(tcp[8..12].try_into().unwrap()),
        hdrlen,
        flags: tcp[13],
        wnd: u16::from_be_bytes([tcp[14], tcp[15]]),
        options: tcp[20..hdrlen].to_vec(),
        payload: tcp[hdrlen..].to_vec(),
    }
}

fn ones_sum(bytes: &[u8], mut sum: u32) -> u32 {
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

fn data(len: usize) -> Vec<u8> {
    (0..len).map(|i| i as u8).collect()
}

fn write(pcb: *mut TcpPcb, bytes: &[u8], flags: u8) -> ErrT {
    // SAFETY: a live PCB; the data outlives the call (it is copied).
    unsafe { tcp_write(pcb, bytes.as_ptr().cast(), bytes.len() as u16, flags) }
}

/// The lengths of the segments on a queue.
fn lens(mut seg: *mut TcpSeg) -> Vec<u16> {
    let mut all = Vec::new();
    while !seg.is_null() {
        // SAFETY: a list of live segments.
        unsafe {
            all.push((*seg).len);
            seg = (*seg).next;
        }
    }
    all
}

#[test]
fn write_segments_by_mss_and_output_honours_nagle() {
    with_pcb(|pcb| {
        let bytes = data(1000);
        assert_eq!(write(pcb, &bytes, 0), ERR_OK);
        // SAFETY: a live PCB.
        unsafe {
            assert_eq!(lens((*pcb).unsent), [536, 464]);
            assert_eq!((*pcb).snd_queuelen, 2);
            assert_eq!((*pcb).snd_buf, 5760 - 1000);
            assert_eq!((*pcb).snd_lbb, ISS + 1000);
            // The tail pbuf was allocated a whole MSS: the rest is the oversize.
            assert_eq!((*pcb).unsent_oversize, 536 - 464);

            assert_eq!(tcp_output(pcb), ERR_OK);
        }
        // Nagle: the full segment goes, the short tail waits for the ACK.
        let sent = frames();
        assert_eq!(sent.len(), 1);
        let first = parse(&sent[0]);
        assert_eq!(
            (first.seqno, first.ackno, first.flags),
            (ISS, RCV_NXT, TCP_ACK)
        );
        assert_eq!(first.wnd, 5760);
        assert_eq!(first.payload, bytes[..536]);
        // SAFETY: a live PCB.
        unsafe {
            assert_eq!(lens((*pcb).unacked), [536]);
            assert_eq!(lens((*pcb).unsent), [464]);
            assert_eq!((*pcb).snd_nxt, ISS + 536);
            assert_eq!((*pcb).rtime, 0, "the retransmission timer runs");
            assert_eq!((*pcb).rcv_ann_right_edge, RCV_NXT + 5760);

            // Without Nagle, the tail goes too, with PSH as the end of the write.
            (*pcb).flags |= TF_NODELAY;
            assert_eq!(tcp_output(pcb), ERR_OK);
        }
        let second = parse(&frames()[0]);
        assert_eq!((second.seqno, second.flags), (ISS + 536, TCP_ACK | TCP_PSH));
        assert_eq!(second.payload, bytes[536..]);
        // SAFETY: a live PCB.
        unsafe {
            assert_eq!(lens((*pcb).unacked), [536, 464]);
            assert!((*pcb).unsent.is_null());
            assert_eq!((*pcb).unsent_oversize, 0);
        }
    });
}

#[test]
fn a_small_write_fills_the_oversized_tail() {
    with_pcb(|pcb| {
        assert_eq!(write(pcb, &data(100), TCP_WRITE_FLAG_MORE), ERR_OK);
        assert_eq!(write(pcb, &[0xaa; 50], 0), ERR_OK);
        // SAFETY: a live PCB.
        unsafe {
            assert_eq!(lens((*pcb).unsent), [150]);
            assert_eq!((*pcb).unsent_oversize, 536 - 150);
            assert_eq!((*pcb).snd_queuelen, 1);
            (*pcb).flags |= TF_NODELAY;
            tcp_output(pcb);
        }
        let seg = parse(&frames()[0]);
        assert_eq!(seg.payload[..100], data(100)[..]);
        assert_eq!(seg.payload[100..], [0xaa; 50]);
        // The first write asked for no PSH; the one filling its tail did, on that same
        // segment.
        assert_eq!(seg.flags, TCP_ACK | TCP_PSH);
    });
}

#[test]
fn write_checks_state_buffer_and_queue() {
    with_pcb(|pcb| {
        // SAFETY: a live PCB.
        unsafe {
            (*pcb).state = CLOSED;
            assert_eq!(write(pcb, &[1], 0), ERR_CONN);
            (*pcb).state = CLOSE_WAIT;
            assert_eq!(write(pcb, &[], 0), ERR_OK);
            assert_eq!(write(pcb, &data(5761), 0), ERR_MEM);
            assert_ne!((*pcb).flags & TF_NAGLEMEMERR, 0);
        }
    });
}

#[test]
fn a_full_queue_is_refused() {
    with_pcb(|pcb| {
        // SAFETY: a live PCB.
        unsafe {
            (*pcb).mss = 100;
            for _ in 0..16 {
                assert_eq!(write(pcb, &data(100), 0), ERR_OK);
            }
            assert_eq!((*pcb).snd_queuelen, 16);
            assert_eq!(write(pcb, &data(1), 0), ERR_MEM);
            assert_ne!((*pcb).flags & TF_NAGLEMEMERR, 0);
            assert_eq!(lens((*pcb).unsent).len(), 16, "nothing was queued");
        }
    });
}

#[test]
fn a_syn_carries_the_mss_option_and_no_ack() {
    with_pcb(|pcb| {
        // SAFETY: a live PCB.
        unsafe {
            (*pcb).state = SYN_SENT;
            assert_eq!(tcp_enqueue_flags(pcb, TCP_SYN), ERR_OK);
            assert_eq!((*pcb).snd_lbb, ISS + 1);
            assert_eq!(tcp_output(pcb), ERR_OK);
            assert_eq!((*pcb).snd_nxt, ISS + 1, "SYN takes a sequence number");
        }
        let syn = parse(&frames()[0]);
        assert_eq!((syn.flags, syn.hdrlen), (TCP_SYN, 24));
        // The stand-in tcp_eff_send_mss_netif allows TCP_MSS on a 1500-byte MTU.
        assert_eq!(syn.options, [2, 4, 0x05, 0xa0]);
        assert!(syn.payload.is_empty());
    });
}

#[test]
fn fin_joins_the_last_segment_or_goes_alone() {
    with_pcb(|pcb| {
        // SAFETY: a live PCB.
        unsafe {
            assert_eq!(write(pcb, &data(10), 0), ERR_OK);
            assert_eq!(tcp_send_fin(pcb), ERR_OK);
            assert_eq!(lens((*pcb).unsent), [10], "the FIN rides on the data");
            assert_ne!((*pcb).flags & TF_FIN, 0);
            assert_eq!(
                (*pcb).snd_lbb,
                ISS + 10,
                "no sequence number of its own yet"
            );
            // A second FIN cannot join a segment that already has one.
            assert_eq!(tcp_send_fin(pcb), ERR_OK);
            assert_eq!(lens((*pcb).unsent), [10, 0]);
            assert_eq!((*pcb).snd_lbb, ISS + 11);
            // FIN is sent despite Nagle.
            tcp_output(pcb);
        }
        let sent = frames();
        assert_eq!(parse(&sent[0]).flags, TCP_ACK | TCP_PSH | TCP_FIN);
        assert_eq!(parse(&sent[1]).flags, TCP_ACK | TCP_FIN);
    });
}

#[test]
fn split_copies_psh_and_fin_to_the_remainder() {
    with_pcb(|pcb| {
        let bytes = data(500);
        assert_eq!(write(pcb, &bytes, 0), ERR_OK);
        // SAFETY: a live PCB.
        unsafe {
            tcp_send_fin(pcb);
            assert_eq!(tcp_split_unsent_seg(pcb, 600), ERR_OK, "nothing to split");
            assert_eq!(tcp_split_unsent_seg(pcb, 200), ERR_OK);
            assert_eq!(lens((*pcb).unsent), [200, 300]);
            assert_eq!((*pcb).snd_queuelen, 2);
            assert_eq!((*pcb).unsent_oversize, 0);
            (*pcb).flags |= TF_NODELAY;
            tcp_output(pcb);
        }
        let sent = frames();
        let (head, rest) = (parse(&sent[0]), parse(&sent[1]));
        // As in tcp_out.c, the head's flags are ORed with what it keeps rather than set to
        // it, so it keeps PSH and FIN too.
        assert_eq!((head.seqno, head.flags), (ISS, TCP_ACK | TCP_PSH | TCP_FIN));
        assert_eq!(
            (rest.seqno, rest.flags),
            (ISS + 200, TCP_ACK | TCP_PSH | TCP_FIN)
        );
        assert_eq!([head.payload, rest.payload].concat(), bytes);
    });
}

#[test]
fn retransmission_requeues_in_sequence_order() {
    with_pcb(|pcb| {
        // SAFETY: a live PCB and its segments.
        unsafe {
            (*pcb).flags |= TF_NODELAY;
            (*pcb).mss = 100;
            assert_eq!(write(pcb, &data(300), 0), ERR_OK);
            tcp_output(pcb);
            frames();
            assert_eq!(lens((*pcb).unacked), [100, 100, 100]);
            assert_eq!(write(pcb, &data(50), 0), ERR_OK);

            // Fast retransmit: the first unacked segment goes before the new data.
            (*pcb).cwnd = 1000;
            (*pcb).snd_wnd = 3000;
            tcp_rexmit_fast(pcb);
            assert_eq!(lens((*pcb).unacked), [100, 100]);
            assert_eq!(lens((*pcb).unsent), [100, 50]);
            assert_eq!((*pcb).ssthresh, 500);
            assert_eq!((*pcb).cwnd, 800);
            assert_ne!((*pcb).flags & TF_INFR, 0);
            assert_eq!((*pcb).nrtx, 1);
            // Once in fast recovery, it does not retransmit again.
            tcp_rexmit_fast(pcb);
            assert_eq!(lens((*pcb).unsent), [100, 50]);

            // The RTO moves everything unacked to the front of unsent.
            assert_eq!(tcp_rexmit_rto_prepare(pcb), ERR_OK);
            assert!((*pcb).unacked.is_null());
            let seqnos = {
                let mut all = Vec::new();
                let mut seg = (*pcb).unsent;
                while !seg.is_null() {
                    all.push(seg_seqno(seg));
                    seg = (*seg).next;
                }
                all
            };
            assert_eq!(seqnos, [ISS + 100, ISS + 200, ISS, ISS + 300]);
            assert_ne!((*pcb).flags & TF_RTO, 0);
            assert_eq!((*pcb).rto_end, ISS + 300);
            assert_eq!(tcp_rexmit_rto_prepare(pcb), ERR_VAL, "nothing unacked");
        }
    });
}

#[test]
fn a_segment_still_held_by_the_driver_is_not_retransmitted() {
    with_pcb(|pcb| {
        // SAFETY: a live PCB and its segments.
        unsafe {
            (*pcb).flags |= TF_NODELAY;
            assert_eq!(write(pcb, &data(10), 0), ERR_OK);
            tcp_output(pcb);
            let seg = (*pcb).unacked;
            pbuf_ref((*seg).p);
            assert_eq!(tcp_rexmit(pcb), ERR_VAL);
            assert_eq!(tcp_rexmit_rto_prepare(pcb), ERR_VAL);
            pbuf_free((*seg).p);
            assert_eq!(tcp_rexmit(pcb), ERR_OK);
            assert_eq!(lens((*pcb).unsent), [10]);
        }
    });
}

#[test]
fn a_window_too_small_starts_the_persist_timer_and_a_probe_sends_one_byte() {
    with_pcb(|pcb| {
        // SAFETY: a live PCB.
        unsafe {
            (*pcb).snd_wnd = 0;
            assert_eq!(write(pcb, &data(10), 0), ERR_OK);
            tcp_output(pcb);
            assert!(frames().is_empty());
            assert_eq!(
                (
                    (*pcb).persist_backoff,
                    (*pcb).persist_cnt,
                    (*pcb).persist_probe
                ),
                (1, 0, 0)
            );

            assert_eq!(tcp_zero_window_probe(pcb), ERR_OK);
            assert_eq!((*pcb).persist_probe, 1);
            assert_eq!((*pcb).snd_nxt, ISS + 1);
        }
        let probe = parse(&frames()[0]);
        assert_eq!(
            (probe.seqno, probe.flags, probe.payload),
            (ISS, TCP_ACK, std::vec![0])
        );
    });
}

#[test]
fn empty_ack_keepalive_and_rst() {
    with_pcb(|pcb| {
        // SAFETY: a live PCB and valid addresses.
        unsafe {
            (*pcb).snd_nxt = ISS + 7;
            (*pcb).flags |= TF_ACK_DELAY | TF_ACK_NOW;
            // Nothing to send but an ACK due: tcp_output sends it empty.
            assert_eq!(tcp_output(pcb), ERR_OK);
            assert_eq!((*pcb).flags & (TF_ACK_DELAY | TF_ACK_NOW), 0);
            assert_eq!(tcp_keepalive(pcb), ERR_OK);
            tcp_rst(pcb, 77, 88, &(*pcb).local_ip, &(*pcb).remote_ip, 1234, 80);
        }
        let sent = frames();
        let ack = parse(&sent[0]);
        assert_eq!(
            (ack.seqno, ack.ackno, ack.flags),
            (ISS + 7, RCV_NXT, TCP_ACK)
        );
        assert!(ack.payload.is_empty());
        let keepalive = parse(&sent[1]);
        assert_eq!((keepalive.seqno, keepalive.flags), (ISS + 6, TCP_ACK));
        let rst = parse(&sent[2]);
        assert_eq!(
            (rst.seqno, rst.ackno, rst.flags),
            (77, 88, TCP_RST | TCP_ACK)
        );
        // As in tcp_out.c, the RST's window is byte-swapped twice over: TCP_WND
        // (0x1680) goes out as 0x8016.
        assert_eq!(rst.wnd, 0x8016);
    });
}

#[test]
fn nothing_is_sent_while_input_processes_the_pcb_or_without_a_route() {
    with_pcb(|pcb| {
        // SAFETY: a live PCB; the stand-in global is restored.
        unsafe {
            (*pcb).flags |= TF_NODELAY;
            assert_eq!(write(pcb, &data(10), 0), ERR_OK);
            crate::tcp_in::tcp_input_pcb.set(pcb);
            assert_eq!(tcp_output(pcb), ERR_OK);
            crate::tcp_in::tcp_input_pcb.set(ptr::null_mut());
            assert!(frames().is_empty());

            (*pcb).remote_ip = IpAddr::v4(ip4(10, 0, 0, 1).addr);
            crate::netif::netif_set_default(ptr::null_mut());
            assert_eq!(tcp_output(pcb), ERR_RTE);
            assert_eq!(lens((*pcb).unsent), [10]);
        }
    });
}
