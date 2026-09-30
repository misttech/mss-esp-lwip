// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! test/unit/tcp/tcp_helper.c.

extern crate std;

use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::ptr;
use std::boxed::Box;
use std::sync::MutexGuard;
use std::vec::Vec;

use crate::inet_chksum::inet_chksum;
use crate::links::*;
use crate::tcp::{
    tcp_abort, tcp_active_pcbs, tcp_bound_pcbs, tcp_close, tcp_listen_pcbs, tcp_new, tcp_reg,
    tcp_tw_pcbs,
};
use crate::types::*;

/// test_tcp.c's configuration's TCP_MSS.
pub(super) const TEST_MSS: u16 = 536;
/// test_tcp.c's configuration's TCP_SND_BUF.
pub(super) const TEST_SND_BUF: TcpWnd = 12 * TEST_MSS;
pub(super) const TCP_WND: TcpWnd = crate::config::TCP_WND as TcpWnd;

pub(super) const TEST_REMOTE_PORT: u16 = 0x100;
pub(super) const TEST_LOCAL_PORT: u16 = 0x101;

const fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::v4(u32::from_be_bytes([a, b, c, d]).to_be())
}

pub(super) const TEST_LOCAL_IP: IpAddr = ip(192, 168, 1, 1);
pub(super) const TEST_REMOTE_IP: IpAddr = ip(192, 168, 1, 2);
pub(super) const TEST_NETMASK: IpAddr = ip(255, 255, 255, 0);

/// Counters used for `test_tcp_counters_*` callback functions.
#[derive(Default)]
pub(super) struct Counters {
    pub recv_calls: u32,
    pub recved_bytes: u32,
    pub recv_calls_after_close: u32,
    pub recved_bytes_after_close: u32,
    pub close_calls: u32,
    pub err_calls: u32,
    pub last_err: ErrT,
    pub expected_data: Vec<u8>,
}

/// What the test netif sent.
#[derive(Default)]
pub(super) struct TxCounters {
    pub num_tx_calls: u32,
    pub num_tx_bytes: u32,
    pub copy_tx_packets: bool,
    pub tx_packets: Vec<Vec<u8>>,
}

impl TxCounters {
    pub fn reset(&mut self) {
        *self = TxCounters::default();
    }
}

/// Remove all pcbs on the given list.
fn tcp_remove(pcb_list: *mut TcpPcb) {
    let mut pcb = pcb_list;
    while !pcb.is_null() {
        // SAFETY: the list holds live PCBs; each is read before it goes.
        unsafe {
            let pcb2 = pcb;
            pcb = (*pcb).next;
            if (*pcb2).state == LISTEN {
                tcp_close(pcb2);
            } else {
                tcp_abort(pcb2);
            }
        }
    }
}

/// Remove all pcbs on listen-, active- and time-wait-list (bound- isn't exported).
pub(super) fn tcp_remove_all() {
    tcp_remove(tcp_listen_pcbs.get());
    tcp_remove(tcp_bound_pcbs.get());
    tcp_remove(tcp_active_pcbs.get());
    tcp_remove(tcp_tw_pcbs.get());
    assert_eq!(pcbs_in_use(), 0);
}

/// The PCBs on the lists: memp statistics' count of used PCBs, which the tests check.
pub(super) fn pcbs_in_use() -> usize {
    let mut n = 0;
    for head in [
        tcp_listen_pcbs.get(),
        tcp_bound_pcbs.get(),
        tcp_active_pcbs.get(),
        tcp_tw_pcbs.get(),
    ] {
        let mut pcb = head;
        while !pcb.is_null() {
            n += 1;
            // SAFETY: the lists hold live PCBs.
            pcb = unsafe { (*pcb).next };
        }
    }
    n
}

/// Create a TCP segment usable for passing to tcp_input.
#[allow(clippy::too_many_arguments)]
pub(super) fn tcp_create_segment_wnd(
    src_ip: &IpAddr,
    dst_ip: &IpAddr,
    src_port: u16,
    dst_port: u16,
    data: &[u8],
    seqno: u32,
    ackno: u32,
    headerflags: u8,
    wnd: u16,
) -> *mut Pbuf {
    let pbuf_len = (usize::from(IP_HLEN) + usize::from(TCP_HLEN) + data.len()) as u16;
    // SAFETY: a fresh pool pbuf chain, the headers in its first pbuf.
    unsafe {
        let p = pbuf_alloc(0 /* PBUF_RAW */, pbuf_len, PBUF_POOL);
        assert!(!p.is_null());
        // First pbuf must be big enough to hold the headers.
        assert!((*p).len >= IP_HLEN + TCP_HLEN);
        if !data.is_empty() {
            // First pbuf must be big enough to hold at least 1 data byte, too.
            assert!((*p).len > IP_HLEN + TCP_HLEN);
        }
        let mut q = p;
        while !q.is_null() {
            ptr::write_bytes((*q).payload.cast::<u8>(), 0, usize::from((*q).len));
            q = (*q).next.map_or(ptr::null_mut(), |n| n.as_ptr());
        }

        // Fill IP header.
        let iphdr = (*p).payload.cast::<u8>();
        iphdr
            .add(16)
            .cast::<u32>()
            .write_unaligned(dst_ip.ip4().addr);
        iphdr
            .add(12)
            .cast::<u32>()
            .write_unaligned(src_ip.ip4().addr);
        *iphdr = 0x45;
        iphdr
            .add(2)
            .cast::<u16>()
            .write_unaligned((*p).tot_len.to_be());
        let chksum = inet_chksum(iphdr.cast(), IP_HLEN);
        iphdr.add(10).cast::<u16>().write_unaligned(chksum);

        // Let p point to TCP header.
        pbuf_remove_header(p, usize::from(IP_HLEN));
        let tcphdr = (*p).payload.cast::<u8>();
        tcphdr.cast::<u16>().write_unaligned(src_port.to_be());
        tcphdr
            .add(2)
            .cast::<u16>()
            .write_unaligned(dst_port.to_be());
        tcphdr.add(4).cast::<u32>().write_unaligned(seqno.to_be());
        tcphdr.add(8).cast::<u32>().write_unaligned(ackno.to_be());
        tcphdr
            .add(12)
            .cast::<u16>()
            .write_unaligned(((5 << 12) | u16::from(headerflags)).to_be());
        tcphdr.add(14).cast::<u16>().write_unaligned(wnd.to_be());

        if !data.is_empty() {
            // Let p point to TCP data, copy data, and let p point to TCP header again.
            pbuf_remove_header(p, usize::from(TCP_HLEN));
            crate::pbuf::pbuf_take(p, data.as_ptr().cast(), data.len() as u16);
            pbuf_add_header(p, usize::from(TCP_HLEN));
        }

        // Calculate checksum.
        let chksum = ip_chksum_pseudo(p, IP_PROTO_TCP, (*p).tot_len, src_ip, dst_ip);
        tcphdr.add(16).cast::<u16>().write_unaligned(chksum);

        pbuf_add_header(p, usize::from(IP_HLEN));
        p
    }
}

/// Create a TCP segment usable for passing to tcp_input.
#[expect(clippy::too_many_arguments, reason = "tcp_helper.c's signature")]
pub(super) fn tcp_create_segment(
    src_ip: &IpAddr,
    dst_ip: &IpAddr,
    src_port: u16,
    dst_port: u16,
    data: &[u8],
    seqno: u32,
    ackno: u32,
    headerflags: u8,
) -> *mut Pbuf {
    tcp_create_segment_wnd(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        data,
        seqno,
        ackno,
        headerflags,
        TCP_WND,
    )
}

/// Create a TCP segment usable for passing to tcp_input: IP-addresses, ports, seqno and
/// ackno are taken from pcb; seqno and ackno can be altered with an offset.
pub(super) fn tcp_create_rx_segment(
    pcb: *mut TcpPcb,
    data: &[u8],
    seqno_offset: u32,
    ackno_offset: u32,
    headerflags: u8,
) -> *mut Pbuf {
    tcp_create_rx_segment_wnd(pcb, data, seqno_offset, ackno_offset, headerflags, TCP_WND)
}

/// As `tcp_create_rx_segment`, with the TCP window given.
pub(super) fn tcp_create_rx_segment_wnd(
    pcb: *mut TcpPcb,
    data: &[u8],
    seqno_offset: u32,
    ackno_offset: u32,
    headerflags: u8,
    wnd: u16,
) -> *mut Pbuf {
    // SAFETY: a live PCB.
    unsafe {
        tcp_create_segment_wnd(
            &(*pcb).remote_ip,
            &(*pcb).local_ip,
            (*pcb).remote_port,
            (*pcb).local_port,
            data,
            (*pcb).rcv_nxt.wrapping_add(seqno_offset),
            (*pcb).lastack.wrapping_add(ackno_offset),
            headerflags,
            wnd,
        )
    }
}

/// Safely bring a tcp_pcb into the requested state.
pub(super) fn tcp_set_state(
    pcb: *mut TcpPcb,
    state: TcpState,
    local_ip: &IpAddr,
    remote_ip: &IpAddr,
    local_port: u16,
    remote_port: u16,
) {
    // SAFETY: a live PCB on no list.
    unsafe {
        (*pcb).state = state;
        let iss = crate::tcp::tcp_next_iss(pcb);
        (*pcb).snd_wl2 = iss;
        (*pcb).snd_nxt = iss;
        (*pcb).lastack = iss;
        (*pcb).snd_lbb = iss;
        match state {
            ESTABLISHED | TIME_WAIT => {
                tcp_reg(
                    if state == ESTABLISHED {
                        tcp_active_pcbs.as_ptr()
                    } else {
                        tcp_tw_pcbs.as_ptr()
                    },
                    pcb,
                );
                (*pcb).local_ip.copy_from(local_ip);
                (*pcb).local_port = local_port;
                (*pcb).remote_ip.copy_from(remote_ip);
                (*pcb).remote_port = remote_port;
            }
            LISTEN => {
                tcp_reg(tcp_listen_pcbs.as_ptr(), pcb);
                (*pcb).local_ip.copy_from(local_ip);
                (*pcb).local_port = local_port;
            }
            _ => panic!("tcp_set_state: {state}"),
        }
    }
}

pub(super) unsafe extern "C" fn test_tcp_counters_err(arg: *mut c_void, err: ErrT) {
    assert!(!arg.is_null());
    // SAFETY: the counters the test gave tcp_arg.
    let counters = unsafe { &mut *arg.cast::<Counters>() };
    counters.err_calls += 1;
    counters.last_err = err;
}

fn test_tcp_counters_check_rxdata(counters: &Counters, p: *mut Pbuf) {
    if counters.expected_data.is_empty() {
        // No data to compare.
        return;
    }
    // SAFETY: a live pbuf chain.
    unsafe {
        assert!(
            counters.recved_bytes as usize + usize::from((*p).tot_len)
                <= counters.expected_data.len()
        );
        let mut received = counters.recved_bytes as usize;
        let mut q = p;
        while !q.is_null() {
            let data =
                core::slice::from_raw_parts((*q).payload.cast::<u8>(), usize::from((*q).len));
            for &byte in data {
                assert_eq!(byte, counters.expected_data[received]);
                received += 1;
            }
            q = (*q).next.map_or(ptr::null_mut(), |n| n.as_ptr());
        }
        assert_eq!(
            received,
            counters.recved_bytes as usize + usize::from((*p).tot_len)
        );
    }
}

pub(super) unsafe extern "C" fn test_tcp_counters_recv(
    arg: *mut c_void,
    pcb: *mut TcpPcb,
    p: *mut Pbuf,
    err: ErrT,
) -> ErrT {
    assert!(!arg.is_null() && !pcb.is_null());
    assert_eq!(err, ERR_OK);
    // SAFETY: the counters the test gave tcp_arg; the callback owns the pbuf.
    unsafe {
        let counters = &mut *arg.cast::<Counters>();
        if !p.is_null() {
            if counters.close_calls == 0 {
                counters.recv_calls += 1;
                test_tcp_counters_check_rxdata(counters, p);
                counters.recved_bytes += u32::from((*p).tot_len);
            } else {
                counters.recv_calls_after_close += 1;
                counters.recved_bytes_after_close += u32::from((*p).tot_len);
            }
            pbuf_free(p);
        } else {
            counters.close_calls += 1;
        }
        assert!(counters.recv_calls_after_close == 0 && counters.recved_bytes_after_close == 0);
    }
    ERR_OK
}

/// Allocate a pcb and set up the `test_tcp_counters_*` callbacks, with test_tcp.c's
/// send buffer.
pub(super) fn test_tcp_new_counters_pcb(counters: &mut Counters) -> *mut TcpPcb {
    let pcb = tcp_new();
    if !pcb.is_null() {
        // SAFETY: a fresh PCB; the counters outlive it.
        unsafe {
            // Set up args and callbacks.
            crate::tcp::tcp_arg(pcb, ptr::from_mut(counters).cast());
            crate::tcp::tcp_recv(pcb, Some(test_tcp_counters_recv));
            crate::tcp::tcp_err(pcb, Some(test_tcp_counters_err));
            (*pcb).snd_wnd = TCP_WND;
            (*pcb).snd_wnd_max = TCP_WND;
            (*pcb).snd_buf = TEST_SND_BUF;
        }
    }
    pcb
}

/// Calls tcp_input() after adjusting current_iphdr_dest.
pub(super) fn test_tcp_input(p: *mut Pbuf, inp: *mut Netif) {
    // SAFETY: a live pbuf holding an IPv4 header and a live netif; ip_data is the
    // stack's.
    unsafe {
        let ipd = ip_data();
        let iphdr = (*p).payload.cast::<u8>();
        // These lines are a hack, don't use them as an example :-)
        (*ipd)
            .current_iphdr_dest
            .copy_from_ip4(iphdr.add(16).cast::<u32>().read_unaligned());
        (*ipd)
            .current_iphdr_src
            .copy_from_ip4(iphdr.add(12).cast::<u32>().read_unaligned());
        (*ipd).current_netif = inp;
        (*ipd).current_ip4_header = iphdr.cast();
        (*ipd).current_input_netif = inp;
        // Since adding IPv6, p->payload must point to tcp header, not ip header.
        pbuf_remove_header(p, usize::from(IP_HLEN));
        tcp_input(p, inp);
        (*ipd).current_iphdr_dest = IpAddr::v4(0);
        (*ipd).current_iphdr_src = IpAddr::v4(0);
        (*ipd).current_netif = ptr::null_mut();
        (*ipd).current_ip4_header = ptr::null();
    }
}

unsafe extern "C" fn test_tcp_netif_output(
    netif: *mut Netif,
    p: *mut Pbuf,
    _ipaddr: *const Ip4Addr,
) -> ErrT {
    // SAFETY: the netif's state is the test's counters; the pbuf is live.
    unsafe {
        let txcounters = (*netif).state.cast::<TxCounters>();
        if let Some(txcounters) = txcounters.as_mut() {
            txcounters.num_tx_calls += 1;
            txcounters.num_tx_bytes += u32::from((*p).tot_len);
            if txcounters.copy_tx_packets {
                let mut copy = std::vec![0_u8; usize::from((*p).tot_len)];
                pbuf_copy_partial(p, copy.as_mut_ptr().cast(), (*p).tot_len, 0);
                txcounters.tx_packets.push(copy);
            }
        }
    }
    ERR_OK
}

/// test_tcp.c's setup and teardown around a test: a netif on its own on the list, as
/// test_tcp_init_netif leaves it, with its counters; no TCP PCBs; and the ISS 6510.
pub(super) struct Fixture {
    pub netif: Box<Netif>,
    pub tx: Box<TxCounters>,
    old_list: *mut Netif,
    old_default: *mut Netif,
    _serial: MutexGuard<'static, ()>,
}

impl Fixture {
    pub fn new() -> Self {
        let serial = crate::test_support::serial();
        crate::test_support::TCP_ISS.store(6510, core::sync::atomic::Ordering::Relaxed);
        crate::tcp::tcp_ticks.set(0);
        tcp_remove_all();
        // SAFETY: every field of the mirror is valid zeroed.
        let mut netif: Box<Netif> = Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
        let mut tx = Box::new(TxCounters::default());
        netif.state = ptr::from_mut(&mut *tx).cast();
        netif.output = Some(test_tcp_netif_output);
        netif.flags |= NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
        netif.netmask.copy_from_ip4(TEST_NETMASK.ip4().addr);
        netif.ip_addr.copy_from_ip4(TEST_LOCAL_IP.ip4().addr);
        let old_list = crate::netif::netif_list.get();
        let old_default = crate::netif::netif_default.get();
        crate::netif::netif_list.set(&mut *netif);
        crate::netif::netif_default.set(ptr::null_mut());
        Fixture {
            netif,
            tx,
            old_list,
            old_default,
            _serial: serial,
        }
    }

    pub fn netif(&mut self) -> *mut Netif {
        &mut *self.netif
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        crate::netif::netif_list.set(ptr::null_mut());
        crate::netif::netif_default.set(ptr::null_mut());
        if !std::thread::panicking() {
            tcp_remove_all();
        }
        // Restore netif_list for next tests (e.g. loopif).
        crate::netif::netif_list.set(self.old_list);
        crate::netif::netif_default.set(self.old_default);
    }
}
