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

//! Dynamic memory manager, from `src/core/mem.c`, for `MEM_LIBC_MALLOC`: lwIP's heap is
//! the C library's `malloc`, `calloc`, and `free`. That is the configuration ESP-IDF uses
//! and the only one ported; `build.rs` refuses the others (lwIP's own heap, `MEM_USE_POOLS`,
//! overflow and sanity checks, statistics, and ESP-IDF's SPIRAM-first allocation).
//!
//! The allocator is the firmware's, as it is for the C stack: forkpoint-libc leaves
//! allocation to the platform, and ESP-IDF's heap serves both.
//!
//! The types and alignment helpers are always built; the functions only with the `mem`
//! feature, when this module replaces `mem.c`.

use core::ffi::c_void;

use crate::config;

/// `mem_size_t`: a heap size. `size_t` under `MEM_LIBC_MALLOC`.
pub type MemSize = usize;

/// `LWIP_MEM_ALIGN_SIZE(size)`: `size` rounded up to `MEM_ALIGNMENT`, in unsigned
/// arithmetic that wraps as C's does.
pub const fn mem_align_size(size: usize) -> usize {
    size.wrapping_add(config::MEM_ALIGNMENT - 1) & !(config::MEM_ALIGNMENT - 1)
}

/// `LWIP_MEM_ALIGN(addr)`: `addr` rounded up to `MEM_ALIGNMENT`.
pub fn mem_align<T>(addr: *mut T) -> *mut T {
    addr.map_addr(mem_align_size)
}

#[cfg(feature = "mem")]
unsafe extern "C" {
    /// `mem_clib_malloc`: the firmware's allocator.
    fn malloc(size: usize) -> *mut c_void;
    /// `mem_clib_calloc`.
    fn calloc(count: usize, size: usize) -> *mut c_void;
    /// `mem_clib_free`.
    fn free(ptr: *mut c_void);
}

/// Zero. With `MEM_LIBC_MALLOC`, there is no heap to initialize.
#[cfg(feature = "mem")]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn mem_init() {}

/// Shrink memory returned by `mem_malloc()`. The C library's heap is not trimmed: `mem`
/// itself is returned.
#[cfg(feature = "mem")]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn mem_trim(mem: *mut c_void, size: MemSize) -> *mut c_void {
    let _ = size;
    mem
}

/// Allocate `size` bytes, aligned to `MEM_ALIGNMENT`, from the C library's heap.
///
/// Returns null if the heap is exhausted.
///
/// # Safety
///
/// None beyond the C library's `malloc`.
#[cfg(feature = "mem")]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn mem_malloc(size: MemSize) -> *mut c_void {
    // MEM_LIBC_STATSHELPER_SIZE is 0 without statistics.
    // SAFETY: `malloc` takes any size.
    let ret = unsafe { malloc(size) };
    if ret.is_null() {
        // MEM_STATS_INC_LOCKED(err): the critical section is entered even though there is
        // no statistic to count.
        crate::sys::locked(|| {});
    } else {
        lwip_assert!("malloc() must return aligned memory", mem_align(ret) == ret);
    }
    ret
}

/// Put memory back on the heap.
///
/// # Safety
///
/// `rmem` was returned by `mem_malloc` or `mem_calloc` and not freed since.
#[cfg(feature = "mem")]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn mem_free(rmem: *mut c_void) {
    lwip_assert!("rmem != NULL", !rmem.is_null());
    lwip_assert!("rmem == MEM_ALIGN(rmem)", rmem == mem_align(rmem));
    // SAFETY: `rmem` came from the C library's heap, per the caller.
    unsafe { free(rmem) };
}

/// Contiguously allocates enough space for `count` objects that are `size` bytes of
/// memory each, all zeroed.
///
/// # Safety
///
/// None beyond the C library's `calloc`.
#[cfg(feature = "mem")]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn mem_calloc(count: MemSize, size: MemSize) -> *mut c_void {
    // SAFETY: `calloc` takes any count and size.
    unsafe { calloc(count, size) }
}

#[cfg(all(test, feature = "mem"))]
mod tests {
    use super::*;

    // test/unit/core/test_mem.c exercises lwIP's own heap: its MEM_STATS counters and its
    // detection of illegal and double frees (test_mem_invalid_free,
    // test_mem_double_free, test_mem_reallocate) exist only without MEM_LIBC_MALLOC. The
    // allocation patterns carry over.

    /// test_mem_one, without the heap statistics.
    #[test]
    fn test_mem_one() {
        const SIZE1: usize = 16;
        const SIZE1_2: usize = 12;
        const SIZE2: usize = 16;
        // SAFETY: allocations freed once each.
        unsafe {
            let p1 = mem_malloc(SIZE1);
            assert!(!p1.is_null());
            let p2 = mem_malloc(SIZE2);
            assert!(!p2.is_null());
            assert_eq!(mem_trim(p1, SIZE1_2), p1);
            mem_free(p2);
            mem_free(p1);
        }
    }

    /// malloc_keep_x from test_mem.c: allocate `num`, free every `freestep`th but `x`,
    /// free the rest, and `x` last.
    fn malloc_keep_x(x: usize, num: usize, size: usize, freestep: usize) {
        let mut p = [core::ptr::null_mut::<c_void>(); 16];
        // SAFETY: each pointer is freed once.
        unsafe {
            for slot in p.iter_mut().take(num) {
                *slot = mem_malloc(size);
                assert!(!slot.is_null());
                assert_eq!(slot.addr() % config::MEM_ALIGNMENT, 0);
            }
            for i in (0..num.min(16)).step_by(freestep) {
                if i != x {
                    mem_free(p[i]);
                    p[i] = core::ptr::null_mut();
                }
            }
            for (i, slot) in p.iter_mut().enumerate().take(num) {
                if i != x && !slot.is_null() {
                    mem_free(*slot);
                    *slot = core::ptr::null_mut();
                }
            }
            assert!(!p[x].is_null());
            mem_free(p[x]);
        }
    }

    /// test_mem_random.
    #[test]
    fn test_mem_random() {
        let num = 16;
        for x in 0..num {
            for size in 1..32 {
                for freestep in 1..=3 {
                    malloc_keep_x(x, num, size, freestep);
                }
            }
        }
    }

    #[test]
    fn calloc_zeroes_and_align_rounds_up() {
        // SAFETY: freed once.
        unsafe {
            let p = mem_calloc(3, 5).cast::<u8>();
            assert!(!p.is_null());
            assert!(core::slice::from_raw_parts(p, 15).iter().all(|&b| b == 0));
            mem_free(p.cast());
        }
        assert_eq!(mem_align_size(0), 0);
        assert_eq!(mem_align_size(1), config::MEM_ALIGNMENT);
        assert_eq!(mem_align_size(config::MEM_ALIGNMENT), config::MEM_ALIGNMENT);
        assert_eq!(
            mem_align_size(usize::MAX),
            0,
            "wraps as C's unsigned arithmetic"
        );
    }
}
