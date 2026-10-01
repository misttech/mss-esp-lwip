// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! Firmware SDK for the Forkpoint hostcall device: property assertions ([`assert`], and
//! [`prelude`] for the macros) reported as probes through the device ([`hostcall`]).
//!
//! A probe is five aligned 32-bit stores into a window that exists only in the
//! virtual machine. The last store reports the probe. The layout matches
//! `src/dvmc/devices/src/hostcall.rs` and `sdk/c/include/forkpoint/hostcall.h`.
//!
//! Nothing in this crate touches that window unless the `enabled` feature is
//! on. A production build leaves the feature off, so the calls compile out and
//! real silicon never sees them. With the feature on, set `FPT_HOSTCALL_BASE`
//! to the address the board's Device Tree gives the `forkpoint,hostcall` node
//! (`0xa0000000` on the boards that carry one). The crate then supports
//! Cortex-M, which masks with `PRIMASK`, and RISC-V, which clears `mstatus.MIE`
//! and restores only that bit. The RISC-V translation unit needs the Zicsr
//! extension. Both run in the mode their Forkpoint CPU model
//! implements, so the CSR or special-register access is permitted.

#![no_std]

pub mod assert;
pub mod catalog;
pub mod hostcall;
pub mod lifecycle;
pub mod prelude;
pub mod random;

pub use assert::{KIND_ALWAYS, KIND_REACHABLE, KIND_SOMETIMES, KIND_UNREACHABLE, message_id};
pub use hostcall::{
    ID_HI, ID_LO, KIND, MAGIC, MAGIC_OFFSET, RANDOM, RANDOM_HI, RANDOM_LO, VALUE_HI, VALUE_LO,
    VERSION, VERSION_OFFSET, hostcall_present, hostcall_random, hostcall_version, parse_base,
    probe, probe_stores,
};
