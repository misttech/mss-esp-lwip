// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! The lwIP functions one module calls in another file: the Rust translation when that
//! module is built in this crate, the C function otherwise. Either way the call has the C
//! signature and contract, so a module does not depend on which of its neighbors are
//! ported.

use core::ffi::c_void;

use crate::mem::MemSize;
use crate::memp::MempT;

#[cfg(not(feature = "mem"))]
mod c_mem {
    use super::*;

    unsafe extern "C" {
        pub(super) fn mem_malloc(size: MemSize) -> *mut c_void;
        pub(super) fn mem_free(rmem: *mut c_void);
        pub(super) fn mem_trim(mem: *mut c_void, size: MemSize) -> *mut c_void;
    }
}

#[cfg(not(feature = "memp"))]
mod c_memp {
    use super::*;

    unsafe extern "C" {
        pub(super) fn memp_malloc(type_: MempT) -> *mut c_void;
        pub(super) fn memp_free(type_: MempT, mem: *mut c_void);
    }
}

/// `mem_malloc()`.
///
/// # Safety
///
/// As the C function's.
pub(crate) unsafe fn mem_malloc(size: MemSize) -> *mut c_void {
    #[cfg(feature = "mem")]
    // SAFETY: forwarded from the caller.
    let p = unsafe { crate::mem::mem_malloc(size) };
    #[cfg(not(feature = "mem"))]
    // SAFETY: forwarded from the caller.
    let p = unsafe { c_mem::mem_malloc(size) };
    p
}

/// `mem_free()`.
///
/// # Safety
///
/// `rmem` was returned by `mem_malloc` and not freed since.
pub(crate) unsafe fn mem_free(rmem: *mut c_void) {
    #[cfg(feature = "mem")]
    // SAFETY: forwarded from the caller.
    unsafe {
        crate::mem::mem_free(rmem)
    };
    #[cfg(not(feature = "mem"))]
    // SAFETY: forwarded from the caller.
    unsafe {
        c_mem::mem_free(rmem)
    };
}

/// `mem_trim()`.
///
/// # Safety
///
/// `mem` was returned by `mem_malloc` and is at least `size` bytes.
pub(crate) unsafe fn mem_trim(mem: *mut c_void, size: MemSize) -> *mut c_void {
    #[cfg(feature = "mem")]
    let p = crate::mem::mem_trim(mem, size);
    #[cfg(not(feature = "mem"))]
    // SAFETY: forwarded from the caller.
    let p = unsafe { c_mem::mem_trim(mem, size) };
    p
}

/// `memp_malloc()`.
///
/// # Safety
///
/// As the C function's.
pub(crate) unsafe fn memp_malloc(type_: MempT) -> *mut c_void {
    #[cfg(feature = "memp")]
    let p = crate::memp::memp_malloc(type_);
    #[cfg(not(feature = "memp"))]
    // SAFETY: forwarded from the caller.
    let p = unsafe { c_memp::memp_malloc(type_) };
    p
}

/// `memp_free()`.
///
/// # Safety
///
/// `mem` is null or was allocated from the pool `type_` and not freed since.
pub(crate) unsafe fn memp_free(type_: MempT, mem: *mut c_void) {
    #[cfg(feature = "memp")]
    // SAFETY: forwarded from the caller.
    unsafe {
        crate::memp::memp_free(type_, mem)
    };
    #[cfg(not(feature = "memp"))]
    // SAFETY: forwarded from the caller.
    unsafe {
        c_memp::memp_free(type_, mem)
    };
}
