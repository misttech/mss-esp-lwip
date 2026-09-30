// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! lwIP's test/unit/core/test_timers.c on the Rust timeouts, and the cyclic timers and the
//! TCP timer, which it does not cover.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering::Relaxed};
use std::sync::MutexGuard;

use super::*;
use crate::test_support::{NOW, serial};

/// test_timers.c's setup and teardown: an empty timeout list, and the clock at 0 after.
struct Fixture {
    _serial: MutexGuard<'static, ()>,
}

impl Fixture {
    fn new() -> Self {
        let serial = serial();
        reset();
        Self { _serial: serial }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        reset();
        NOW.store(0, Relaxed);
    }
}

fn now() -> u32 {
    NOW.load(Relaxed)
}

fn set_now(now: u32) {
    NOW.store(now, Relaxed);
}

fn advance(msecs: u32) {
    NOW.store(now().wrapping_add(msecs), Relaxed);
}

/// The due time of each pending timeout, in list order.
fn due_times() -> std::vec::Vec<u32> {
    let mut times = std::vec::Vec::new();
    let mut t = NEXT_TIMEOUT.get();
    // SAFETY: every timeout on the list is live.
    unsafe {
        while !t.is_null() {
            times.push((*t).time);
            t = (*t).next;
        }
    }
    times
}

static FIRED: [AtomicBool; 3] = [
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
];

fn fired() -> [bool; 3] {
    FIRED.each_ref().map(|f| f.load(Relaxed))
}

fn clear_fired() {
    for f in &FIRED {
        f.store(false, Relaxed);
    }
}

unsafe extern "C" fn dummy_handler(arg: *mut c_void) {
    FIRED[arg as usize].store(true, Relaxed);
}

fn timeout(msecs: u32, index: usize) {
    sys_timeout(msecs, Some(dummy_handler), index as *mut c_void);
}

fn untimeout(index: usize) {
    sys_untimeout(Some(dummy_handler), index as *mut c_void);
}

const HANDLER_EXECUTION_TIME: u32 = 5;
static CYCLIC_FIRED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" fn dummy_cyclic_handler() {
    CYCLIC_FIRED.store(true, Relaxed);
    advance(HANDLER_EXECUTION_TIME);
}

static TEST_CYCLIC: LwipCyclicTimer = LwipCyclicTimer {
    interval_ms: 10,
    handler: Some(dummy_cyclic_handler),
};

fn test_cyclic() -> *mut c_void {
    ptr::from_ref(&TEST_CYCLIC).cast_mut().cast()
}

fn do_test_cyclic_timers(offset: u32) {
    let interval = TEST_CYCLIC.interval_ms;

    // Verify normal timer expiration.
    set_now(offset);
    sys_timeout(interval, Some(lwip_cyclic_timer), test_cyclic());

    CYCLIC_FIRED.store(false, Relaxed);
    sys_check_timeouts();
    assert!(!CYCLIC_FIRED.load(Relaxed));

    set_now(offset.wrapping_add(interval));
    sys_check_timeouts();
    assert!(CYCLIC_FIRED.load(Relaxed));

    assert_eq!(
        due_times()[0],
        now()
            .wrapping_add(interval)
            .wrapping_sub(HANDLER_EXECUTION_TIME)
    );

    sys_untimeout(Some(lwip_cyclic_timer), test_cyclic());

    // Verify "overload" - next cyclic timer execution is already overdue twice.
    set_now(offset);
    sys_timeout(interval, Some(lwip_cyclic_timer), test_cyclic());

    CYCLIC_FIRED.store(false, Relaxed);
    sys_check_timeouts();
    assert!(!CYCLIC_FIRED.load(Relaxed));

    set_now(offset.wrapping_add(2 * interval));
    sys_check_timeouts();
    assert!(CYCLIC_FIRED.load(Relaxed));

    assert_eq!(due_times()[0], now().wrapping_add(interval));
}

#[cfg(feature = "memp")]
#[test]
fn a_timeout_fits_its_pool() {
    assert!(usize::from(crate::memp::memp_SYS_TIMEOUT.size) >= core::mem::size_of::<SysTimeo>());
}

#[test]
fn test_cyclic_timers() {
    let _f = Fixture::new();
    // Check without u32_t wraparound.
    do_test_cyclic_timers(0);
    // Check with u32_t wraparound.
    do_test_cyclic_timers(0xffff_fff0);
}

/// Reproduce bug #52748: the bug in timeouts.c.
#[test]
fn test_bug52748() {
    let _f = Fixture::new();
    clear_fired();

    set_now(50);
    timeout(20, 0);
    timeout(5, 2);

    set_now(55);
    sys_check_timeouts();
    assert_eq!(fired(), [false, false, true]);

    set_now(60);
    timeout(10, 1);
    sys_check_timeouts();
    assert_eq!(fired(), [false, false, true]);

    set_now(70);
    sys_check_timeouts();
    assert_eq!(fired(), [true, true, true]);
}

fn do_test_timers(offset: u32) {
    set_now(offset);

    timeout(10, 0);
    assert_eq!(sys_timeouts_sleeptime(), 10);
    timeout(20, 1);
    assert_eq!(sys_timeouts_sleeptime(), 10);
    timeout(5, 2);
    assert_eq!(sys_timeouts_sleeptime(), 5);

    // Linked list correctly sorted?
    assert_eq!(
        due_times(),
        [5, 10, 20].map(|d| now().wrapping_add(d)).to_vec()
    );

    // Check timers expire in correct order.
    clear_fired();

    advance(4);
    sys_check_timeouts();
    assert!(!fired()[2]);

    advance(1);
    sys_check_timeouts();
    assert!(fired()[2]);

    advance(4);
    sys_check_timeouts();
    assert!(!fired()[0]);

    advance(1);
    sys_check_timeouts();
    assert!(fired()[0]);

    advance(9);
    sys_check_timeouts();
    assert!(!fired()[1]);

    advance(1);
    sys_check_timeouts();
    assert!(fired()[1]);

    untimeout(0);
    untimeout(1);
    untimeout(2);
}

#[test]
fn test_timers() {
    let _f = Fixture::new();
    // Check without u32_t wraparound.
    do_test_timers(0);
    // Check with u32_t wraparound.
    do_test_timers(0xffff_fff0);
}

#[test]
fn test_long_timer() {
    let _f = Fixture::new();
    clear_fired();
    set_now(0);

    timeout(u32::MAX / 4, 0);
    assert_eq!(sys_timeouts_sleeptime(), u32::MAX / 4);

    sys_check_timeouts();
    assert!(!fired()[0]);

    advance(u32::MAX / 8);
    sys_check_timeouts();
    assert!(!fired()[0]);

    advance(u32::MAX / 8);
    sys_check_timeouts();
    assert!(!fired()[0]);

    advance(1);
    sys_check_timeouts();
    assert!(fired()[0]);

    untimeout(0);
}

#[test]
fn equal_due_times_keep_their_order_and_untimeout_takes_the_first_match() {
    let _f = Fixture::new();
    set_now(100);
    timeout(10, 0);
    timeout(10, 1);
    timeout(10, 0);
    let first = |i: usize| (dummy_handler as *const () as usize, i);
    assert_eq!(crate::timeouts::pending(), [first(0), first(1), first(0)]);

    // Only the first of the two matching timeouts goes.
    untimeout(0);
    assert_eq!(crate::timeouts::pending(), [first(1), first(0)]);
    // An unknown timeout is ignored.
    untimeout(2);
    assert_eq!(crate::timeouts::pending().len(), 2);
}

#[test]
fn an_empty_list_sleeps_forever_and_an_overdue_timeout_not_at_all() {
    let _f = Fixture::new();
    assert_eq!(sys_timeouts_sleeptime(), SYS_TIMEOUTS_SLEEPTIME_INFINITE);
    set_now(1000);
    timeout(10, 0);
    set_now(1020);
    assert_eq!(sys_timeouts_sleeptime(), 0);
}

#[test]
fn restart_rebases_every_timeout_on_now() {
    let _f = Fixture::new();
    set_now(0);
    timeout(10, 0);
    timeout(30, 1);
    set_now(5000);
    sys_restart_timeouts();
    // The first is due now, the others as far after it as they were.
    assert_eq!(due_times(), [5000, 5020]);
}

static COUNTED: AtomicU32 = AtomicU32::new(0);

unsafe extern "C" fn counting_handler() {
    COUNTED.fetch_add(1, Relaxed);
}

#[test]
fn init_starts_every_cyclic_timer_but_tcp_and_deinit_stops_them() {
    let _f = Fixture::new();
    set_now(0);
    sys_timeouts_init();
    let started = lwip_cyclic_timers.len() - 1;
    let pending = crate::timeouts::pending();
    assert_eq!(pending.len(), started);
    assert!(
        pending
            .iter()
            .all(|&(h, _)| h == lwip_cyclic_timer as *const () as usize)
    );
    // The table is ESP-IDF's: TCP first, started on demand.
    assert_eq!(lwip_num_cyclic_timers as usize, lwip_cyclic_timers.len());
    assert_eq!(
        lwip_cyclic_timers[0].interval_ms,
        config::TCP_TMR_INTERVAL as u32
    );
    sys_timeouts_deinit();
    assert!(crate::timeouts::pending().is_empty());
}

#[test]
fn a_cyclic_timer_runs_every_interval() {
    let _f = Fixture::new();
    static TIMER: LwipCyclicTimer = LwipCyclicTimer {
        interval_ms: 100,
        handler: Some(counting_handler),
    };
    let arg = ptr::from_ref(&TIMER).cast_mut().cast();
    COUNTED.store(0, Relaxed);
    set_now(0);
    sys_timeout(100, Some(lwip_cyclic_timer), arg);
    for tick in 1..=10 {
        set_now(tick * 50);
        sys_check_timeouts();
    }
    assert_eq!(COUNTED.load(Relaxed), 5);
    assert_eq!(due_times(), [600]);
}

#[test]
fn the_tcp_timer_runs_while_a_pcb_needs_it() {
    let _f = Fixture::new();
    set_now(0);
    // No PCB: nothing to time.
    tcp_timer_needed();
    assert!(crate::timeouts::pending().is_empty());

    // A PCB in TIME-WAIT keeps the timer going.
    let pcb = crate::tcp::tcp_new();
    assert!(!pcb.is_null());
    // SAFETY: a fresh PCB, put on tcp.c's TIME-WAIT list as TCP_REG would.
    unsafe {
        (*pcb).state = crate::types::TIME_WAIT;
        (*pcb).next = crate::tcp::tcp_tw_pcbs.get();
        crate::tcp::tcp_tw_pcbs.set(pcb);
    }
    tcp_timer_needed();
    let tcp_timer = (tcpip_tcp_timer as *const () as usize, 0);
    assert_eq!(crate::timeouts::pending(), [tcp_timer]);
    // Asking again does not start a second one.
    tcp_timer_needed();
    assert_eq!(crate::timeouts::pending().len(), 1);

    set_now(config::TCP_TMR_INTERVAL as u32);
    sys_check_timeouts();
    assert_eq!(crate::timeouts::pending(), [tcp_timer], "restarted");

    // With the PCB gone, the next run stops the timer.
    // SAFETY: the PCB is on the TIME-WAIT list, which tcp_abort takes it off.
    unsafe { crate::tcp::tcp_abort(pcb) };
    set_now(2 * config::TCP_TMR_INTERVAL as u32);
    sys_check_timeouts();
    assert!(crate::timeouts::pending().is_empty());
    assert_eq!(TCPIP_TCP_TIMER_ACTIVE.get(), 0);
}
