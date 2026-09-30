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
    fn dhcp_network_changed_link_up(netif: *mut Netif);
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
