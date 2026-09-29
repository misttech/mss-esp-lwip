// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! lwIP core modules in Rust.
//!
//! Each module is a direct translation of one lwIP C file and exports the same C symbols,
//! so the firmware build drops that file and links this crate in its place (see
//! `../../README.md`). A module is built when its Cargo feature, named after the C file,
//! is on; the shared struct mirrors in [`types`] always are.

#![no_std]

pub mod config {
    //! The lwIP options the crate is built for; see `build.rs`.
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}

mod cstr;
pub mod types;

#[macro_use]
mod platform;

#[cfg(feature = "def")]
pub mod def;
#[cfg(feature = "inet_chksum")]
pub mod inet_chksum;
#[cfg(all(feature = "ip4_addr", lwip_ipv4))]
pub mod ip4_addr;
