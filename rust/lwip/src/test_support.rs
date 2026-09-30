// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! What the C stack and its port provide to the modules in firmware, stood in for host
//! tests.

extern crate std;

use core::ffi::c_void;
use std::sync::{Mutex, MutexGuard};

use crate::sys::SysProt;

/// Serializes tests that share the modules' global state, such as the TCP PCB count.
pub(crate) fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The port's critical section: tests run the stack from one thread at a time.
#[unsafe(no_mangle)]
extern "C" fn sys_arch_protect() -> SysProt {
    0
}

#[unsafe(no_mangle)]
extern "C" fn sys_arch_unprotect(_pval: SysProt) {}

/// `tcp_active_pcbs`: no TCP connections in host tests.
#[unsafe(no_mangle)]
static mut tcp_active_pcbs: *mut c_void = core::ptr::null_mut();

#[unsafe(no_mangle)]
extern "C" fn tcp_free_ooseq(_pcb: *mut c_void) {}

/// `tcpip_try_callback`: the TCP/IP thread's queue, which the tests do not run. Report it
/// full, as `ERR_MEM`.
#[unsafe(no_mangle)]
extern "C" fn tcpip_try_callback(
    _function: Option<unsafe extern "C" fn(*mut c_void)>,
    _ctx: *mut c_void,
) -> i8 {
    -1
}

use core::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use core::mem::MaybeUninit;

use crate::types::{ErrT, Ip4Addr, IpAddr, IpGlobals, Netif, Pbuf, RAW_INPUT_NONE, RawInputState};

/// Packets the IP layer stand-ins received, by protocol.
pub(crate) static IP6_INPUTS: AtomicUsize = AtomicUsize::new(0);
pub(crate) static IP_INPUTS: AtomicUsize = AtomicUsize::new(0);

/// Consume a packet a stand-in received, as the real layer would.
fn consume(p: *mut Pbuf) {
    // SAFETY: the stack hands the stand-in a live pbuf it gives up.
    unsafe { crate::links::pbuf_free(p) };
}

#[unsafe(no_mangle)]
extern "C" fn ip_input(p: *mut Pbuf, _inp: *mut Netif) -> ErrT {
    IP_INPUTS.fetch_add(1, Relaxed);
    consume(p);
    0
}

#[unsafe(no_mangle)]
extern "C" fn ip6_input(p: *mut Pbuf, _inp: *mut Netif) -> ErrT {
    IP6_INPUTS.fetch_add(1, Relaxed);
    consume(p);
    0
}

#[unsafe(no_mangle)]
extern "C" fn tcpip_input(p: *mut Pbuf, _inp: *mut Netif) -> ErrT {
    consume(p);
    0
}

/// `ip_data`, ip.c's state of the packet being delivered: zeroed, as a C global is.
#[unsafe(no_mangle)]
static mut ip_data: MaybeUninit<IpGlobals> = MaybeUninit::zeroed();

/// Packets the protocol stand-ins received.
pub(crate) static TCP_INPUTS: AtomicUsize = AtomicUsize::new(0);

/// ip.c's `ip_addr_any_type`: the dual-stack any address.
#[unsafe(no_mangle)]
static ip_addr_any_type: IpAddr = IpAddr {
    u_addr: crate::types::IpAddrUnion {
        ip4: Ip4Addr { addr: 0 },
    },
    type_: crate::types::IPADDR_TYPE_ANY,
};

/// `esp_random`: a fixed sequence, so tests are repeatable.
#[unsafe(no_mangle)]
extern "C" fn esp_random() -> u32 {
    static STATE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0x1234_5678);
    STATE.fetch_add(0x9e37_79b9, Relaxed)
}

/// Packets the IPv6 output stand-in was handed (it does not consume them).
pub(crate) static IP6_OUTPUTS: AtomicUsize = AtomicUsize::new(0);

#[unsafe(no_mangle)]
extern "C" fn ip6_output_if_src(
    _p: *mut Pbuf,
    _src: *const c_void,
    _dest: *const c_void,
    _hl: u8,
    _tc: u8,
    _nexth: u8,
    _netif: *mut Netif,
) -> ErrT {
    IP6_OUTPUTS.fetch_add(1, Relaxed);
    0
}

#[unsafe(no_mangle)]
extern "C" fn tcp_input(p: *mut Pbuf, _inp: *mut Netif) {
    TCP_INPUTS.fetch_add(1, Relaxed);
    consume(p);
}

#[unsafe(no_mangle)]
extern "C" fn igmp_input(p: *mut Pbuf, _inp: *mut Netif, _dest: *const Ip4Addr) {
    consume(p);
}

/// The protocols a netif change reaches, which host tests do not run.
macro_rules! no_ops {
    ($(fn $name:ident($($arg:ident: $ty:ty),*) $(-> $ret:ty = $value:expr)?;)*) => {
        $(
            #[unsafe(no_mangle)]
            extern "C" fn $name($($arg: $ty),*) $(-> $ret)? {
                let _ = ($($arg,)*);
                $($value)?
            }
        )*
    };
}

no_ops! {
    fn acd_arp_reply(netif: *mut Netif, hdr: *mut c_void);
    fn acd_netif_ip_addr_changed(netif: *mut Netif, old: *const IpAddr, new: *const IpAddr);
    fn acd_network_changed_link_down(netif: *mut Netif);
    fn igmp_start(netif: *mut Netif) -> ErrT = 0;
    fn igmp_stop(netif: *mut Netif) -> ErrT = 0;
    fn igmp_report_groups(netif: *mut Netif);
    fn mld6_stop(netif: *mut Netif) -> ErrT = 0;
    fn mld6_report_groups(netif: *mut Netif);
    fn nd6_restart_netif(netif: *mut Netif);
    fn nd6_cleanup_netif(netif: *mut Netif);
    fn nd6_adjust_mld_membership(netif: *mut Netif, addr_idx: i8, state: u8);
    fn tcp_netif_ip_addr_changed(old: *const IpAddr, new: *const IpAddr);
    fn raw_netif_ip_addr_changed(old: *const IpAddr, new: *const IpAddr);
    fn raw_input(p: *mut Pbuf, inp: *mut Netif) -> RawInputState = RAW_INPUT_NONE;
    fn igmp_lookfor_group(ifp: *mut Netif, addr: *const Ip4Addr) -> *mut c_void = core::ptr::null_mut();
    fn ip4_route_src_hook(src: *const Ip4Addr, dest: *const Ip4Addr) -> *mut Netif = core::ptr::null_mut();
    fn ip6_route(src: *const c_void, dest: *const c_void) -> *mut Netif = core::ptr::null_mut();
    fn ip6_select_source_address(netif: *mut Netif, dest: *const c_void) -> *const IpAddr = core::ptr::null();
    fn icmp6_dest_unreach(p: *mut Pbuf, c: core::ffi::c_uint);
}

/// The timeouts `sys_timeout` set and `sys_untimeout` has not cleared: handler and
/// argument, as addresses.
pub(crate) static TIMEOUTS: Mutex<std::vec::Vec<(usize, usize)>> = Mutex::new(std::vec::Vec::new());

/// `sys_timeout`: recorded, not run; a test fires a timer by calling its function.
#[unsafe(no_mangle)]
extern "C" fn sys_timeout(_msecs: u32, handler: crate::types::SysTimeoutHandler, arg: *mut c_void) {
    let entry = (handler.map_or(0, |h| h as usize), arg as usize);
    TIMEOUTS.lock().unwrap().push(entry);
}

#[unsafe(no_mangle)]
extern "C" fn sys_untimeout(handler: crate::types::SysTimeoutHandler, arg: *mut c_void) {
    let entry = (handler.map_or(0, |h| h as usize), arg as usize);
    TIMEOUTS.lock().unwrap().retain(|&e| e != entry);
}

/// `ipaddr_aton`: ip.c's, for IPv4 dotted addresses, which is all the tests pass it.
#[unsafe(no_mangle)]
extern "C" fn ipaddr_aton(cp: *const core::ffi::c_char, addr: *mut IpAddr) -> core::ffi::c_int {
    let mut ip4 = Ip4Addr { addr: 0 };
    // SAFETY: a C string and an address to fill, as ip.c's contract.
    unsafe {
        if crate::ip4_addr::ip4addr_aton(cp, &mut ip4) == 0 {
            return 0;
        }
        if !addr.is_null() {
            (*addr).copy_from_ip4(ip4.addr);
        }
    }
    1
}

/// The ACD client the stand-ins last saw: its state (as an address), its callback, and
/// the address `acd_start` was last asked to check.
pub(crate) static ACD: Mutex<Option<(usize, crate::types::AcdConflictCallback, u32)>> =
    Mutex::new(None);

/// `acd_add`: remembers the client, for a test to report to through its callback.
#[unsafe(no_mangle)]
extern "C" fn acd_add(
    _netif: *mut Netif,
    acd: *mut crate::types::Acd,
    callback: crate::types::AcdConflictCallback,
) -> ErrT {
    *ACD.lock().unwrap() = Some((acd as usize, callback, 0));
    0
}

#[unsafe(no_mangle)]
extern "C" fn acd_remove(_netif: *mut Netif, acd: *mut crate::types::Acd) {
    let mut client = ACD.lock().unwrap();
    if client.is_some_and(|(a, _, _)| a == acd as usize) {
        *client = None;
    }
}

/// `acd_start`: records the address; the test decides the outcome, without probes.
#[unsafe(no_mangle)]
extern "C" fn acd_start(_netif: *mut Netif, _acd: *mut crate::types::Acd, ipaddr: Ip4Addr) -> ErrT {
    if let Some(client) = ACD.lock().unwrap().as_mut() {
        client.2 = ipaddr.addr;
    }
    0
}

/// The options ESP-IDF's parse hook was handed: option and length.
pub(crate) static DHCP_EXTRA_OPTS: Mutex<std::vec::Vec<(u8, u8)>> =
    Mutex::new(std::vec::Vec::new());

/// ESP-IDF's DHCP option hooks: parsing records the option; there is nothing to add.
#[unsafe(no_mangle)]
extern "C" fn dhcp_parse_extra_opts(
    _dhcp: *mut crate::types::Dhcp,
    _state: u8,
    option: u8,
    len: u8,
    _p: *mut Pbuf,
    _offset: u16,
) {
    DHCP_EXTRA_OPTS.lock().unwrap().push((option, len));
}

#[unsafe(no_mangle)]
extern "C" fn dhcp_append_extra_opts(
    _netif: *mut Netif,
    _state: u8,
    _msg_out: *mut c_void,
    _options_out_len: *mut u16,
) {
}

/// tcp.c's `tcp_ticks` and tcp_in.c's `tcp_input_pcb`, until they are ported.
#[unsafe(no_mangle)]
pub(crate) static mut tcp_ticks: u32 = 0;
#[unsafe(no_mangle)]
pub(crate) static mut tcp_input_pcb: *mut crate::types::TcpPcb = core::ptr::null_mut();

/// tcp.c's `tcp_eff_send_mss_netif`: the MSS the netif's MTU allows for IPv4.
#[unsafe(no_mangle)]
extern "C" fn tcp_eff_send_mss_netif(sendmss: u16, outif: *mut Netif, _dest: *const IpAddr) -> u16 {
    // SAFETY: tcp_out.c passes the netif it routes through, or null.
    let mtu = unsafe { outif.as_ref() }.map_or(0, |n| n.mtu);
    if mtu == 0 {
        sendmss
    } else {
        sendmss.min(mtu - 40)
    }
}

/// tcp.c's `tcp_seg_free` and `tcp_segs_free`.
#[unsafe(no_mangle)]
extern "C" fn tcp_seg_free(seg: *mut crate::types::TcpSeg) {
    if !seg.is_null() {
        // SAFETY: a segment from memp with its pbuf.
        unsafe {
            if !(*seg).p.is_null() {
                crate::links::pbuf_free((*seg).p);
            }
            crate::links::memp_free(crate::config::MEMP_TCP_SEG, seg.cast());
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn tcp_segs_free(mut seg: *mut crate::types::TcpSeg) {
    while !seg.is_null() {
        // SAFETY: a list of live segments.
        let next = unsafe { (*seg).next };
        tcp_seg_free(seg);
        seg = next;
    }
}

/// Packets the IPv6 output stand-in `ip6_output_if` was handed.
pub(crate) static IP6_IF_OUTPUTS: AtomicUsize = AtomicUsize::new(0);

#[unsafe(no_mangle)]
extern "C" fn ip6_output_if(
    _p: *mut Pbuf,
    _src: *const c_void,
    _dest: *const c_void,
    _hl: u8,
    _tc: u8,
    _nexth: u8,
    _netif: *mut Netif,
) -> ErrT {
    IP6_IF_OUTPUTS.fetch_add(1, Relaxed);
    0
}
