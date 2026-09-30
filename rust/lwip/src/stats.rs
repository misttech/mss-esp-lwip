// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! The statistics the ported modules keep: the heap's (`MEM_STATS`) and each pool's
//! (`MEMP_STATS`), in `lwip_stats`, which stats.c defines. The protocols' counters are not
//! ported; `build.rs` refuses a configuration that counts them in a ported module.

#[cfg(lwip_stats_display)]
use core::ffi::c_char;

#[cfg(any(mem_stats, memp_stats))]
use crate::config;
use crate::config::StatCounter;
use crate::mem::MemSize;

/// `struct stats_mem`.
#[repr(C)]
pub struct StatsMem {
    #[cfg(lwip_stats_display)]
    pub name: *const c_char,
    pub err: StatCounter,
    pub avail: MemSize,
    pub used: MemSize,
    pub max: MemSize,
    pub illegal: StatCounter,
}

impl StatsMem {
    /// All counters 0, and no name, as a C static starts.
    pub const ZERO: Self = Self {
        #[cfg(lwip_stats_display)]
        name: core::ptr::null(),
        err: 0,
        avail: 0,
        used: 0,
        max: 0,
        illegal: 0,
    };

    /// `STATS_INC_USED`: count `size` more in use, and the most ever in use.
    pub fn inc_used(&mut self, size: MemSize) {
        self.used = self.used.wrapping_add(size);
        if self.max < self.used {
            self.max = self.used;
        }
    }
}

#[cfg(lwip_layout)]
mod layout {
    use core::mem::{offset_of, size_of};

    use super::*;
    use crate::config::*;

    #[cfg(lwip_stats)]
    fp::static_assert!(size_of::<StatCounter>() == SIZEOF_STAT_COUNTER);
    #[cfg(lwip_stats)]
    fp::static_assert!(size_of::<StatsMem>() == SIZEOF_STATS_MEM);
    #[cfg(all(lwip_stats, lwip_stats_display))]
    fp::static_assert!(offset_of!(StatsMem, name) == STATS_MEM_NAME);
    #[cfg(lwip_stats)]
    fp::static_assert!(offset_of!(StatsMem, err) == STATS_MEM_ERR);
    #[cfg(lwip_stats)]
    fp::static_assert!(offset_of!(StatsMem, used) == STATS_MEM_USED);
    #[cfg(lwip_stats)]
    fp::static_assert!(offset_of!(StatsMem, max) == STATS_MEM_MAX);
}

#[cfg(any(mem_stats, memp_stats))]
unsafe extern "C" {
    /// stats.c's `struct stats_ lwip_stats`, reached at the offsets the configuration
    /// lists.
    static mut lwip_stats: u8;
}

/// `&lwip_stats.mem`.
#[cfg(mem_stats)]
pub fn mem() -> *mut StatsMem {
    // SAFETY: `mem` lies within `lwip_stats` at this offset.
    unsafe {
        (&raw mut lwip_stats)
            .add(config::LWIP_STATS_MEM)
            .cast::<StatsMem>()
    }
}

/// `&lwip_stats.memp[type_]`: the slot `memp_init` points at a pool's statistics.
///
/// # Safety
///
/// `type_` is below `MEMP_MAX`.
#[cfg(memp_stats)]
pub unsafe fn memp_slot(type_: usize) -> *mut *mut StatsMem {
    // SAFETY: `memp` is an array of MEMP_MAX pointers within `lwip_stats` at this offset,
    // and `type_` indexes it, as the caller guarantees.
    unsafe {
        (&raw mut lwip_stats)
            .add(config::LWIP_STATS_MEMP)
            .cast::<*mut StatsMem>()
            .add(type_)
    }
}
