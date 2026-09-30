// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! lwIP core modules in Rust.
//!
//! Each module is a direct translation of one lwIP C file and exports the same C symbols,
//! so the firmware build drops that file and links this crate in its place (see
//! `../../README.md`). A module is built when its Cargo feature, named after the C file,
//! is on; the shared struct mirrors in [`types`] always are.

#![no_std]
// A firmware that ports only some modules builds only some of them, and the shared
// helpers (C strings, assertions, calls between modules) serve modules that may be off.
#![cfg_attr(
    not(all(
        feature = "def",
        feature = "inet_chksum",
        feature = "ip4_addr",
        feature = "mem",
        feature = "memp",
        feature = "pbuf",
        feature = "netif",
        feature = "ethernet",
        feature = "etharp",
        feature = "ip4",
        feature = "ip4_frag",
        feature = "icmp"
    )),
    allow(dead_code, unused_imports, unused_macros)
)]

pub mod config {
    //! The lwIP options the crate is built for; see `build.rs`.
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}

mod cstr;
pub mod types;

#[macro_use]
mod platform;

mod global;
mod links;
pub mod mem;
pub mod memp;
mod sys;
#[cfg(test)]
mod test_support;

#[cfg(feature = "def")]
pub mod def;
#[cfg(feature = "etharp")]
pub mod etharp;
#[cfg(feature = "ethernet")]
pub mod ethernet;
#[cfg(feature = "icmp")]
pub mod icmp;
#[cfg(feature = "inet_chksum")]
pub mod inet_chksum;
#[cfg(feature = "ip4")]
pub mod ip4;
#[cfg(all(feature = "ip4_addr", lwip_ipv4))]
pub mod ip4_addr;
#[cfg(feature = "ip4_frag")]
pub mod ip4_frag;
#[cfg(feature = "netif")]
pub mod netif;
#[cfg(feature = "pbuf")]
pub mod pbuf;
