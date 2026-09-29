// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! What the modules use of the port's `sys_arch`: its critical section.

use core::ffi::c_int;

/// `sys_prot_t`: the state `sys_arch_protect` saves (`int` in ESP-IDF's `arch/cc.h`).
pub type SysProt = c_int;

unsafe extern "C" {
    fn sys_arch_protect() -> SysProt;
    fn sys_arch_unprotect(pval: SysProt);
}

/// `SYS_ARCH_PROTECT(old_level); f(); SYS_ARCH_UNPROTECT(old_level);`: run `f` in the
/// port's critical section, which masks what could reenter the stack.
pub(crate) fn locked<R>(f: impl FnOnce() -> R) -> R {
    // SAFETY: the port's critical section takes and returns only its saved state, and
    // every protect is paired with the unprotect below.
    let old_level = unsafe { sys_arch_protect() };
    let result = f();
    // SAFETY: as above.
    unsafe { sys_arch_unprotect(old_level) };
    result
}
