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
//
// Translated to Rust for mss-esp-lwip by Mist Tecnologia LTDA.

//! Dynamic pool memory manager, from `src/core/memp.c`, for `MEMP_MEM_MALLOC`: each pool
//! allocates its elements with `mem_malloc`, so a pool is only its element size. That is
//! the configuration ESP-IDF uses and the only one ported; `build.rs` refuses lwIP's
//! static pools, overflow checks, and statistics.
//!
//! The pools are those `lwip/priv/memp_std.h` declares for the configuration, and
//! `build.rs` generates their descriptors from it. ESP-IDF's lwIP also caps the TCP PCBs
//! allocated at once at `MEMP_NUM_TCP_PCB`, which lwIP's own pools would do by their size.
//!
//! The types are always built; the functions and descriptors only with the `memp`
//! feature, when this module replaces `memp.c`.

#[cfg(feature = "memp")]
use core::ffi::c_void;

#[cfg(feature = "memp")]
use crate::config;
#[cfg(feature = "memp")]
use crate::links::{mem_free, mem_malloc};
#[cfg(feature = "memp")]
use crate::mem::mem_align_size;

/// `memp_t`: a pool, by its index in `memp_pools` (a C enum, so an `int` in size).
pub type MempT = core::ffi::c_uint;

/// `struct memp_desc`: a memory pool descriptor. Under `MEMP_MEM_MALLOC`, without overflow
/// checks or statistics, only the element size.
#[repr(C)]
pub struct MempDesc {
    /// Element size.
    pub size: u16,
}

#[cfg(lwip_layout)]
mod layout {
    use core::mem::{offset_of, size_of};

    use super::*;
    use crate::config::*;

    fp::static_assert!(size_of::<MempDesc>() == SIZEOF_MEMP_DESC);
    fp::static_assert!(offset_of!(MempDesc, size) == MEMP_DESC_SIZE);
    fp::static_assert!(size_of::<MempT>() == SIZEOF_MEMP_T);
}

#[cfg(feature = "memp")]
mod pools {
    #![allow(non_upper_case_globals)]

    use super::MempDesc;
    use crate::config;

    include!(concat!(env!("OUT_DIR"), "/memp_pools.rs"));
}

#[cfg(feature = "memp")]
pub use pools::*;

/// The TCP PCBs allocated and not yet freed, for ESP-IDF's cap.
#[cfg(all(feature = "memp", esp_lwip, lwip_tcp))]
static NUM_TCP_PCB: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Whether `desc` is the TCP PCB pool's.
#[cfg(all(feature = "memp", esp_lwip, lwip_tcp))]
fn is_tcp_pcb_pool(desc: &MempDesc) -> bool {
    core::ptr::eq(desc, memp_pools[config::MEMP_TCP_PCB as usize])
}

/// Initialize a custom memory pool. Nothing to do: elements come from `mem_malloc`.
#[cfg(feature = "memp")]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn memp_init_pool(desc: *const MempDesc) {
    let _ = desc;
}

/// Initializes lwIP built-in pools.
#[cfg(feature = "memp")]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn memp_init() {
    // For every pool:
    for desc in memp_pools {
        memp_init_pool(desc);
    }
}

/// An element of the pool `desc`, or null if the heap is exhausted or ESP-IDF's TCP PCB
/// cap is reached.
#[cfg(feature = "memp")]
fn do_memp_malloc_pool(desc: &MempDesc) -> *mut c_void {
    use core::sync::atomic::Ordering::Relaxed;

    #[cfg(all(esp_lwip, lwip_tcp))]
    if is_tcp_pcb_pool(desc) && NUM_TCP_PCB.load(Relaxed) >= config::MEMP_NUM_TCP_PCB as u32 {
        return core::ptr::null_mut();
    }

    // MEMP_SIZE is 0 without overflow checks.
    // SAFETY: `mem_malloc` takes any size.
    let memp = unsafe { mem_malloc(mem_align_size(usize::from(desc.size))) };
    crate::sys::locked(|| {
        if memp.is_null() {
            // MEMP_STATS_INC(err): no statistics.
            return core::ptr::null_mut();
        }
        #[cfg(all(esp_lwip, lwip_tcp))]
        if is_tcp_pcb_pool(desc) {
            NUM_TCP_PCB.store(NUM_TCP_PCB.load(Relaxed) + 1, Relaxed);
        }
        lwip_assert!(
            "memp_malloc: memp properly aligned",
            memp.addr().is_multiple_of(config::MEM_ALIGNMENT)
        );
        memp
    })
}

/// Get an element from a custom pool.
///
/// # Safety
///
/// `desc` is null or one of the pool descriptors.
#[cfg(feature = "memp")]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn memp_malloc_pool(desc: *const MempDesc) -> *mut c_void {
    lwip_assert!("invalid pool desc", !desc.is_null());
    // SAFETY: null or a pool descriptor, per the caller.
    match unsafe { desc.as_ref() } {
        Some(desc) => do_memp_malloc_pool(desc),
        None => core::ptr::null_mut(),
    }
}

/// Get an element from a specific pool.
///
/// Returns a pointer to the allocated memory or null on error.
#[cfg(feature = "memp")]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn memp_malloc(type_: MempT) -> *mut c_void {
    // LWIP_ERROR("memp_malloc: type < MEMP_MAX", (type < MEMP_MAX), return NULL;)
    match memp_pools.get(type_ as usize) {
        Some(desc) => do_memp_malloc_pool(desc),
        None => core::ptr::null_mut(),
    }
}

/// Put `mem` back into the pool `desc`.
///
/// # Safety
///
/// `mem` was allocated from `desc` and not freed since.
#[cfg(feature = "memp")]
unsafe fn do_memp_free_pool(desc: &MempDesc, mem: *mut c_void) {
    lwip_assert!(
        "memp_free: mem properly aligned",
        mem.addr().is_multiple_of(config::MEM_ALIGNMENT)
    );
    // MEMP_SIZE is 0 without overflow checks.
    let memp = mem;
    crate::sys::locked(|| {
        #[cfg(all(esp_lwip, lwip_tcp))]
        if is_tcp_pcb_pool(desc) {
            use core::sync::atomic::Ordering::Relaxed;
            NUM_TCP_PCB.store(NUM_TCP_PCB.load(Relaxed).wrapping_sub(1), Relaxed);
        }
        let _ = desc;
    });
    // SAFETY: `memp` came from `mem_malloc`, per the caller.
    unsafe { mem_free(memp) };
}

/// Free an element from a custom pool.
///
/// # Safety
///
/// `desc` is null or one of the pool descriptors; `mem` is null or was allocated from it
/// and not freed since.
#[cfg(feature = "memp")]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn memp_free_pool(desc: *const MempDesc, mem: *mut c_void) {
    lwip_assert!("invalid pool desc", !desc.is_null());
    // SAFETY: null or a pool descriptor, per the caller.
    let Some(desc) = (unsafe { desc.as_ref() }) else {
        return;
    };
    if mem.is_null() {
        return;
    }
    // SAFETY: allocated from `desc`, per the caller.
    unsafe { do_memp_free_pool(desc, mem) };
}

/// Put an element back into its pool.
///
/// # Safety
///
/// `mem` is null or was allocated from the pool `type_` and not freed since.
#[cfg(feature = "memp")]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn memp_free(type_: MempT, mem: *mut c_void) {
    // LWIP_ERROR("memp_free: type < MEMP_MAX", (type < MEMP_MAX), return;)
    let Some(desc) = memp_pools.get(type_ as usize) else {
        return;
    };
    if mem.is_null() {
        return;
    }
    // SAFETY: allocated from this pool, per the caller.
    unsafe { do_memp_free_pool(desc, mem) };
}

#[cfg(all(test, feature = "memp", feature = "mem"))]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn every_pool_allocates_aligned_elements_of_its_size() {
        let _serial = crate::test_support::serial();
        memp_init();
        for type_ in 0..config::MEMP_MAX as MempT {
            let p = memp_malloc(type_);
            assert!(!p.is_null(), "pool {type_}");
            assert_eq!(p.addr() % config::MEM_ALIGNMENT, 0);
            let size = usize::from(memp_pools[type_ as usize].size);
            // SAFETY: the element is `size` bytes.
            unsafe {
                core::ptr::write_bytes(p.cast::<u8>(), 0xa5, size);
                memp_free(type_, p);
            }
        }
    }

    #[test]
    fn an_unknown_pool_or_a_null_element_is_refused() {
        assert!(memp_malloc(config::MEMP_MAX as MempT).is_null());
        // SAFETY: nothing is freed.
        unsafe {
            memp_free(
                config::MEMP_MAX as MempT,
                core::ptr::NonNull::<u8>::dangling().as_ptr().cast(),
            );
            memp_free(config::MEMP_PBUF, core::ptr::null_mut());
        }
    }

    #[cfg(all(esp_lwip, lwip_tcp))]
    #[test]
    fn tcp_pcbs_are_capped_at_memp_num_tcp_pcb() {
        let _serial = crate::test_support::serial();
        let pcbs: std::vec::Vec<_> = (0..config::MEMP_NUM_TCP_PCB)
            .map(|_| memp_malloc(config::MEMP_TCP_PCB))
            .collect();
        assert!(pcbs.iter().all(|p| !p.is_null()));
        assert!(
            memp_malloc(config::MEMP_TCP_PCB).is_null(),
            "the cap is reached"
        );
        // Other pools are not capped.
        let udp = memp_malloc(config::MEMP_UDP_PCB);
        assert!(!udp.is_null());
        // SAFETY: each element is freed once, to its own pool.
        unsafe {
            memp_free(config::MEMP_UDP_PCB, udp);
            memp_free(config::MEMP_TCP_PCB, pcbs[0]);
        }
        let again = memp_malloc(config::MEMP_TCP_PCB);
        assert!(!again.is_null(), "a freed PCB makes room");
        // SAFETY: as above.
        unsafe {
            memp_free(config::MEMP_TCP_PCB, again);
            for &p in &pcbs[1..] {
                memp_free(config::MEMP_TCP_PCB, p);
            }
        }
    }
}
