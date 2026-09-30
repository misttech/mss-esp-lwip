// Copyright (c) 2001-2004 Swedish Institute of Computer Science.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
// SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
// OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
// OF SUCH DAMAGE.
//
// This file is part of the lwIP TCP/IP stack.
//
// Author: Adam Dunkels <adam@sics.se>
//         Simon Goldschmidt
//
// Translated to Rust for mss-esp-lwip by Mist Tecnologia LTDA.

//! Stack-internal timers, from `src/core/timeouts.c`, as ESP-IDF configures it: lwIP's
//! own timeout list, without timer names (`build.rs` refuses the rest).
//!
//! This module includes timer callbacks for stack-internal timers as well as functions to
//! set up or stop timers and check for expired timers.
//!
//! # Safety
//!
//! Like the C module, this one keeps its list in a static and runs only in the tcpip
//! thread, which serializes every call. A handler may set or clear timeouts, so the list
//! is only read through the head, never held across a handler.

#[cfg(test)]
extern crate std;

use core::ffi::{c_int, c_void};
use core::ptr;

use crate::config;
use crate::global::Global;
use crate::links::{memp_free, memp_malloc};
use crate::types::SysTimeoutHandler;

/// `lwip_cyclic_timer_handler`: a cyclic timer's function.
pub type LwipCyclicTimerHandler = Option<unsafe extern "C" fn()>;

/// `struct lwip_cyclic_timer`: a stack-internal timer that runs every `interval_ms`.
#[repr(C)]
pub struct LwipCyclicTimer {
    pub interval_ms: u32,
    pub handler: LwipCyclicTimerHandler,
}

/// `struct sys_timeo`: one pending timeout, on the list sorted by expiry.
#[repr(C)]
pub struct SysTimeo {
    pub next: *mut SysTimeo,
    pub time: u32,
    pub h: SysTimeoutHandler,
    pub arg: *mut c_void,
}

#[cfg(lwip_layout)]
mod layout {
    use core::mem::{offset_of, size_of};

    use super::*;
    use crate::config::*;

    fp::static_assert!(size_of::<SysTimeo>() == SIZEOF_SYS_TIMEO);
    fp::static_assert!(offset_of!(SysTimeo, next) == SYS_TIMEO_NEXT);
    fp::static_assert!(offset_of!(SysTimeo, time) == SYS_TIMEO_TIME);
    fp::static_assert!(offset_of!(SysTimeo, h) == SYS_TIMEO_H);
    fp::static_assert!(offset_of!(SysTimeo, arg) == SYS_TIMEO_ARG);
    fp::static_assert!(size_of::<LwipCyclicTimer>() == SIZEOF_LWIP_CYCLIC_TIMER);
    fp::static_assert!(offset_of!(LwipCyclicTimer, interval_ms) == LWIP_CYCLIC_TIMER_INTERVAL_MS);
    fp::static_assert!(offset_of!(LwipCyclicTimer, handler) == LWIP_CYCLIC_TIMER_HANDLER);
}

mod cyclic {
    #![allow(non_upper_case_globals)]

    use super::LwipCyclicTimer;

    include!(concat!(env!("OUT_DIR"), "/timeouts_cyclic.rs"));
}

pub use cyclic::{lwip_cyclic_timers, lwip_num_cyclic_timers};

const LWIP_MAX_TIMEOUT: u32 = 0x7fff_ffff;

/// `SYS_TIMEOUTS_SLEEPTIME_INFINITE`: no timeout is pending.
pub const SYS_TIMEOUTS_SLEEPTIME_INFINITE: u32 = 0xffff_ffff;

/// `TIME_LESS_THAN(t, compare_to)`: whether timer's expiry time `t` is before
/// `compare_to`, caring about u32_t wraparounds.
fn time_less_than(t: u32, compare_to: u32) -> bool {
    t.wrapping_sub(compare_to) > LWIP_MAX_TIMEOUT
}

unsafe extern "C" {
    /// The port's millisecond clock.
    fn sys_now() -> u32;
}

/// The one and only timeout list.
static NEXT_TIMEOUT: Global<*mut SysTimeo> = Global::new(ptr::null_mut());

/// The due time of the timeout `sys_check_timeouts` is running.
static CURRENT_TIMEOUT_DUE_TIME: Global<u32> = Global::new(0);

/// `&next_timeout`, for lwIP's unit tests.
#[cfg(lwip_testmode)]
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn sys_timeouts_get_next_timeout() -> *mut *mut SysTimeo {
    NEXT_TIMEOUT.as_ptr()
}

/// Global variable that shows if the tcp timer is currently scheduled or not.
#[cfg(lwip_tcp)]
static TCPIP_TCP_TIMER_ACTIVE: Global<c_int> = Global::new(0);

/// Timer callback function that calls `tcp_tmr()` and reschedules itself.
#[cfg(lwip_tcp)]
unsafe extern "C" fn tcpip_tcp_timer(arg: *mut c_void) {
    let _ = arg;

    // Call TCP timer handler.
    // SAFETY: the tcpip thread runs the timers.
    unsafe { crate::links::tcp_tmr() };
    // Timer still needed?
    if tcp_pcbs_pending() {
        // Restart timer.
        sys_timeout(
            config::TCP_TMR_INTERVAL as u32,
            Some(tcpip_tcp_timer),
            ptr::null_mut(),
        );
    } else {
        // Disable timer.
        TCPIP_TCP_TIMER_ACTIVE.set(0);
    }
}

/// `tcp_active_pcbs || tcp_tw_pcbs`.
#[cfg(lwip_tcp)]
fn tcp_pcbs_pending() -> bool {
    // SAFETY: the list heads are tcp.c's globals, read in the tcpip thread.
    unsafe {
        !(*crate::links::tcp_active_pcbs_head()).is_null()
            || !(*crate::links::tcp_tw_pcbs_head()).is_null()
    }
}

/// Called from `TCP_REG` when registering a new PCB: the reason is to have the TCP timer
/// only running when there are active (or time-wait) PCBs.
#[cfg(lwip_tcp)]
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn tcp_timer_needed() {
    #[cfg(test)]
    crate::test_support::TCP_TIMER_NEEDED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    // Timer is off but needed again?
    if TCPIP_TCP_TIMER_ACTIVE.get() == 0 && tcp_pcbs_pending() {
        // Enable and start timer.
        TCPIP_TCP_TIMER_ACTIVE.set(1);
        sys_timeout(
            config::TCP_TMR_INTERVAL as u32,
            Some(tcpip_tcp_timer),
            ptr::null_mut(),
        );
    }
}

/// Insert a timeout due at `abs_time` into the list, after those due at the same time.
fn sys_timeout_abs(abs_time: u32, handler: SysTimeoutHandler, arg: *mut c_void) {
    // SAFETY: MEMP_SYS_TIMEOUT elements hold a struct sys_timeo.
    let timeout = unsafe { memp_malloc(config::MEMP_SYS_TIMEOUT) }.cast::<SysTimeo>();
    if timeout.is_null() {
        lwip_assert!(
            "sys_timeout: timeout != NULL, pool MEMP_SYS_TIMEOUT is empty",
            false
        );
        return;
    }

    // SAFETY: `timeout` is a fresh element; every timeout on the list is live.
    unsafe {
        timeout.write(SysTimeo {
            next: ptr::null_mut(),
            time: abs_time,
            h: handler,
            arg,
        });

        let next_timeout = NEXT_TIMEOUT.get();
        if next_timeout.is_null() {
            NEXT_TIMEOUT.set(timeout);
            return;
        }
        if time_less_than((*timeout).time, (*next_timeout).time) {
            (*timeout).next = next_timeout;
            NEXT_TIMEOUT.set(timeout);
        } else {
            let mut t = next_timeout;
            while !t.is_null() {
                if (*t).next.is_null() || time_less_than((*timeout).time, (*(*t).next).time) {
                    (*timeout).next = (*t).next;
                    (*t).next = timeout;
                    break;
                }
                t = (*t).next;
            }
        }
    }
}

/// Timer callback function that calls `cyclic->handler()` and reschedules itself.
///
/// # Safety
///
/// `arg` is one of the `lwip_cyclic_timer`s.
#[cfg_attr(all(lwip_testmode, lwip_export), unsafe(no_mangle))]
pub unsafe extern "C" fn lwip_cyclic_timer(arg: *mut c_void) {
    let cyclic = arg.cast_const().cast::<LwipCyclicTimer>();

    // SAFETY: a cyclic timer, per the caller.
    let (handler, interval_ms) = unsafe { ((*cyclic).handler, (*cyclic).interval_ms) };
    if let Some(handler) = handler {
        // SAFETY: the stack's timer handler, run in the tcpip thread.
        unsafe { handler() };
    }

    // SAFETY: the port's clock.
    let now = unsafe { sys_now() };
    // Overflow handled by TIME_LESS_THAN.
    let next_timeout_time = CURRENT_TIMEOUT_DUE_TIME.get().wrapping_add(interval_ms);
    if time_less_than(next_timeout_time, now) {
        // Timer would immediately expire again -> "overload" -> restart without any
        // correction.
        sys_timeout_abs(now.wrapping_add(interval_ms), Some(lwip_cyclic_timer), arg);
    } else {
        // Correct cyclic interval with handler execution delay and sys_check_timeouts
        // jitter.
        sys_timeout_abs(next_timeout_time, Some(lwip_cyclic_timer), arg);
    }
}

/// The first cyclic timer `sys_timeouts_init` starts: `tcp_tmr()` at index 0 is started
/// on demand.
const FIRST_STARTED: usize = if cfg!(lwip_tcp) { 1 } else { 0 };

/// Initialize this module.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn sys_timeouts_init() {
    for cyclic in &lwip_cyclic_timers[FIRST_STARTED..] {
        sys_timeout(
            cyclic.interval_ms,
            Some(lwip_cyclic_timer),
            ptr::from_ref(cyclic).cast_mut().cast(),
        );
    }
}

/// Deinitialize this module.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn sys_timeouts_deinit() {
    for cyclic in &lwip_cyclic_timers[FIRST_STARTED..] {
        sys_untimeout(
            Some(lwip_cyclic_timer),
            ptr::from_ref(cyclic).cast_mut().cast(),
        );
    }
}

/// Create a one-shot timer (aka timeout). Timeouts are processed in the following cases:
/// - while waiting for a message using `sys_timeouts_mbox_fetch()`
/// - by calling `sys_check_timeouts()` (NO_SYS==1 only)
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn sys_timeout(msecs: u32, handler: SysTimeoutHandler, arg: *mut c_void) {
    lwip_assert!(
        "Timeout time too long, max is LWIP_UINT32_MAX/4 msecs",
        msecs <= u32::MAX / 4
    );

    // SAFETY: the port's clock.
    let next_timeout_time = unsafe { sys_now() }.wrapping_add(msecs);

    sys_timeout_abs(next_timeout_time, handler, arg);
}

/// Go through timeout list (for this task only) and remove the first matching entry
/// (subsequent entries remain untouched), even though the timeout has not triggered yet.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn sys_untimeout(handler: SysTimeoutHandler, arg: *mut c_void) {
    let handler = handler.map(|h| h as usize);
    let mut prev_t: *mut SysTimeo = ptr::null_mut();
    let mut t = NEXT_TIMEOUT.get();
    // SAFETY: every timeout on the list is live, and was allocated from MEMP_SYS_TIMEOUT.
    unsafe {
        while !t.is_null() {
            if (*t).h.map(|h| h as usize) == handler && (*t).arg == arg {
                // We have a match. Unlink from previous in list.
                if prev_t.is_null() {
                    NEXT_TIMEOUT.set((*t).next);
                } else {
                    (*prev_t).next = (*t).next;
                }
                memp_free(config::MEMP_SYS_TIMEOUT, t.cast());
                return;
            }
            prev_t = t;
            t = (*t).next;
        }
    }
}

/// Handle timeouts for NO_SYS==1 (i.e. without using tcpip_thread/
/// `sys_timeouts_mbox_fetch()`). Uses `sys_now()` to call timeout handler functions when
/// timeouts expire.
///
/// Must be called periodically from your main loop.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn sys_check_timeouts() {
    // Process only timers expired at the start of the function.
    // SAFETY: the port's clock.
    let now = unsafe { sys_now() };

    // PBUF_CHECK_FREE_OOSEQ() and LWIP_TCPIP_THREAD_ALIVE() are empty (see build.rs).
    loop {
        let tmptimeout = NEXT_TIMEOUT.get();
        if tmptimeout.is_null() {
            return;
        }

        // SAFETY: the head is live until it is freed below, after it is read.
        let (time, next, handler, arg) = unsafe {
            (
                (*tmptimeout).time,
                (*tmptimeout).next,
                (*tmptimeout).h,
                (*tmptimeout).arg,
            )
        };
        if time_less_than(now, time) {
            return;
        }

        // Timeout has expired.
        NEXT_TIMEOUT.set(next);
        CURRENT_TIMEOUT_DUE_TIME.set(time);
        // SAFETY: unlinked, and allocated from MEMP_SYS_TIMEOUT.
        unsafe { memp_free(config::MEMP_SYS_TIMEOUT, tmptimeout.cast()) };
        if let Some(handler) = handler {
            // SAFETY: the handler and argument its timeout was set with.
            unsafe { handler(arg) };
        }

        // Repeat until all expired timers have been called.
    }
}

/// Rebase the timeout times to the current time. This is necessary if
/// `sys_check_timeouts()` hasn't been called for a long time (e.g. while saving energy)
/// to prevent all timer functions of that period being called.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn sys_restart_timeouts() {
    let next_timeout = NEXT_TIMEOUT.get();
    if next_timeout.is_null() {
        return;
    }

    // SAFETY: the port's clock; every timeout on the list is live.
    unsafe {
        let now = sys_now();
        let base = (*next_timeout).time;

        let mut t = next_timeout;
        while !t.is_null() {
            (*t).time = (*t).time.wrapping_sub(base).wrapping_add(now);
            t = (*t).next;
        }
    }
}

/// Return the time left before the next timeout is due. If no timeouts are enqueued,
/// returns 0xffffffff.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn sys_timeouts_sleeptime() -> u32 {
    let next_timeout = NEXT_TIMEOUT.get();
    if next_timeout.is_null() {
        return SYS_TIMEOUTS_SLEEPTIME_INFINITE;
    }
    // SAFETY: the port's clock; the head is live.
    unsafe {
        let now = sys_now();
        if time_less_than((*next_timeout).time, now) {
            0
        } else {
            let ret = (*next_timeout).time.wrapping_sub(now);
            lwip_assert!("invalid sleeptime", ret <= LWIP_MAX_TIMEOUT);
            ret
        }
    }
}

/// The pending timeouts, in the order they are due: handler and argument, as addresses.
#[cfg(test)]
pub(crate) fn pending() -> std::vec::Vec<(usize, usize)> {
    let mut pending = std::vec::Vec::new();
    let mut t = NEXT_TIMEOUT.get();
    // SAFETY: every timeout on the list is live.
    unsafe {
        while !t.is_null() {
            pending.push(((*t).h.map_or(0, |h| h as usize), (*t).arg as usize));
            t = (*t).next;
        }
    }
    pending
}

/// Free every pending timeout and stop the TCP timer, as a fresh stack has neither.
#[cfg(test)]
pub(crate) fn reset() {
    loop {
        let t = NEXT_TIMEOUT.get();
        if t.is_null() {
            break;
        }
        // SAFETY: the head is live and was allocated from MEMP_SYS_TIMEOUT.
        unsafe {
            NEXT_TIMEOUT.set((*t).next);
            memp_free(config::MEMP_SYS_TIMEOUT, t.cast());
        }
    }
    #[cfg(lwip_tcp)]
    TCPIP_TCP_TIMER_ACTIVE.set(0);
}

#[cfg(test)]
mod tests;
