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

use crate::types::{ErrT, Ip4Addr, IpAddr, Netif, Pbuf};

/// Packets the IP layer stand-ins received, by protocol.
pub(crate) static IP4_INPUTS: AtomicUsize = AtomicUsize::new(0);
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
extern "C" fn ip4_input(p: *mut Pbuf, _inp: *mut Netif) -> ErrT {
    IP4_INPUTS.fetch_add(1, Relaxed);
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

/// `ip4_route`: every destination goes through the default netif.
#[unsafe(no_mangle)]
extern "C" fn ip4_route(_dest: *const Ip4Addr) -> *mut Netif {
    #[cfg(feature = "netif")]
    return crate::netif::netif_default.get();
    #[cfg(not(feature = "netif"))]
    core::ptr::null_mut()
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
    fn udp_netif_ip_addr_changed(old: *const IpAddr, new: *const IpAddr);
    fn raw_netif_ip_addr_changed(old: *const IpAddr, new: *const IpAddr);
}
