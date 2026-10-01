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

//! Functions for handling IPv4 addresses, from `src/core/ipv4/ip4_addr.c`.

#![allow(non_upper_case_globals)]

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int};

use crate::config::IP4ADDR_STRLEN_MAX;
use crate::cstr::Cursor;
use crate::types::{
    IPADDR_ANY, IPADDR_BROADCAST, IPADDR_NONE, Ip4Addr, IpAddr, NETIF_FLAG_BROADCAST, Netif,
};

/// Used by `IP4_ADDR_ANY` and `IP_ADDR_BROADCAST` in `ip_addr.h`.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub static ip_addr_any: IpAddr = IpAddr::v4(IPADDR_ANY);

/// Used by `IP_ADDR_BROADCAST` in `ip_addr.h`.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub static ip_addr_broadcast: IpAddr = IpAddr::v4(IPADDR_BROADCAST);

/// `ip4_addr_net_eq(addr1, addr2, mask)`: whether `addr1` and `addr2` are on the same
/// network under `mask`.
fn net_eq(addr1: &Ip4Addr, addr2: &Ip4Addr, mask: &Ip4Addr) -> bool {
    addr1.addr & mask.addr == addr2.addr & mask.addr
}

/// Determine if an address is a broadcast address on a network interface.
pub fn is_broadcast(addr: u32, netif: &Netif) -> bool {
    let ipaddr = Ip4Addr { addr };
    let netmask = netif.ip4_netmask().addr;

    // All ones (broadcast) or all zeroes (old skool broadcast).
    if !addr == IPADDR_ANY || addr == IPADDR_ANY {
        true
    // No broadcast support on this network interface?
    } else if netif.flags & NETIF_FLAG_BROADCAST == 0 {
        // The given address cannot be a broadcast address nor can we check against any
        // broadcast addresses.
        false
    // Address matches network interface address exactly? => no broadcast.
    } else if addr == netif.ip4_addr().addr {
        false
    // On the same (sub) network...
    } else {
        net_eq(&ipaddr, netif.ip4_addr(), netif.ip4_netmask())
            // ...and host identifier bits are all ones? => network broadcast address.
            && addr & !netmask == IPADDR_BROADCAST & !netmask
    }
}

/// Determine if an address is a broadcast address on a network interface.
///
/// Returns non-zero if the address is a broadcast address.
///
/// # Safety
///
/// `netif` is a valid network interface.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn ip4_addr_isbroadcast_u32(addr: u32, netif: *const Netif) -> u8 {
    // SAFETY: valid, per the caller.
    u8::from(is_broadcast(addr, unsafe { &*netif }))
}

/// Checks if a netmask (in network byte order!) is valid: starting with ones, then only
/// zeros.
pub fn netmask_valid(netmask: u32) -> bool {
    let nm_hostorder = u32::from_be(netmask);
    // First, check for the first zero; then check that there is no one after it.
    let ones = nm_hostorder.leading_ones();
    ones == 32 || nm_hostorder << ones == 0
}

/// Checks if a netmask (in network byte order!) is valid.
///
/// Returns 1 if the netmask is valid, 0 if it is not.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub extern "C" fn ip4_addr_netmask_valid(netmask: u32) -> u8 {
    u8::from(netmask_valid(netmask))
}

/// `lwip_isdigit()`: the C library's `isdigit((unsigned char)c)`.
fn isdigit(c: u8) -> bool {
    rivet_libc::isdigit(c_int::from(c)) != 0
}

/// `lwip_isxdigit()`.
fn isxdigit(c: u8) -> bool {
    rivet_libc::isxdigit(c_int::from(c)) != 0
}

/// `lwip_islower()`.
fn islower(c: u8) -> bool {
    rivet_libc::islower(c_int::from(c)) != 0
}

/// `lwip_isspace()`: space, `\f`, `\n`, `\r`, `\t`, and `\v`.
fn isspace(c: u8) -> bool {
    rivet_libc::isspace(c_int::from(c)) != 0
}

/// Ascii internet address interpretation routine. Check whether `cp` is a valid ascii
/// representation of an Internet address and convert to a binary address in network
/// order. This replaces `inet_addr`, the return value from which cannot distinguish
/// between failure and a local broadcast address.
///
/// Reads `cp` only up to the first byte that ends the address, as the C code does.
///
/// # Safety
///
/// `cp` is a NUL-terminated string.
pub unsafe fn aton(cp: *const c_char) -> Option<Ip4Addr> {
    // SAFETY: NUL-terminated, per the caller; each read below follows a non-NUL byte.
    let cp = unsafe { Cursor::new(cp) };
    let mut at = 0;
    // SAFETY: reads stop at the NUL, which ends every loop below.
    let next = |at: &mut usize| -> u8 {
        *at += 1;
        unsafe { cp.at(*at) }
    };
    let mut parts = [0_u32; 4];
    let mut pp = 0;
    let mut val: u32;

    // SAFETY: the first byte of a NUL-terminated string.
    let mut c = unsafe { cp.at(0) };
    loop {
        // Collect number up to ``.''. Values are specified as for C: 0x=hex, 0=octal,
        // 1-9=decimal.
        if !isdigit(c) {
            return None;
        }
        val = 0;
        let mut base: u32 = 10;
        if c == b'0' {
            c = next(&mut at);
            if c == b'x' || c == b'X' {
                base = 16;
                c = next(&mut at);
            } else {
                base = 8;
            }
        }
        loop {
            if isdigit(c) {
                if base == 8 && u32::from(c - b'0') >= 8 {
                    break;
                }
                val = val.wrapping_mul(base).wrapping_add(u32::from(c - b'0'));
                c = next(&mut at);
            } else if base == 16 && isxdigit(c) {
                let digit = u32::from(c) + 10 - u32::from(if islower(c) { b'a' } else { b'A' });
                val = (val << 4) | digit;
                c = next(&mut at);
            } else {
                break;
            }
        }
        if c == b'.' {
            // Internet format:
            //  a.b.c.d
            //  a.b.c   (with c treated as 16 bits)
            //  a.b     (with b treated as 24 bits)
            if pp >= 3 {
                return None;
            }
            parts[pp] = val;
            pp += 1;
            c = next(&mut at);
        } else {
            break;
        }
    }
    // Check for trailing characters.
    if c != 0 && !isspace(c) {
        return None;
    }
    // Concoct the address according to the number of parts specified.
    match pp + 1 {
        // a -- 32 bits
        1 => {}
        // a.b -- 8.24 bits
        2 => {
            if val > 0xff_ffff || parts[0] > 0xff {
                return None;
            }
            val |= parts[0] << 24;
        }
        // a.b.c -- 8.8.16 bits
        3 => {
            if val > 0xffff || parts[0] > 0xff || parts[1] > 0xff {
                return None;
            }
            val |= (parts[0] << 24) | (parts[1] << 16);
        }
        // a.b.c.d -- 8.8.8.8 bits
        4 => {
            if val > 0xff || parts[0] > 0xff || parts[1] > 0xff || parts[2] > 0xff {
                return None;
            }
            val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
        }
        _ => {
            lwip_assert!("unhandled", false);
        }
    }
    Some(Ip4Addr { addr: val.to_be() })
}

/// Ascii internet address interpretation routine.
///
/// Returns the ip address in network order, or `IPADDR_NONE`.
///
/// # Safety
///
/// `cp` is a NUL-terminated string.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn ipaddr_addr(cp: *const c_char) -> u32 {
    // SAFETY: forwarded from the caller.
    unsafe { aton(cp) }.map_or(IPADDR_NONE, |val| val.addr)
}

/// Check whether `cp` is a valid ascii representation of an Internet address and convert
/// to a binary address, stored in `addr` in network order unless `addr` is null.
///
/// Returns 1 if `cp` could be converted to `addr`, 0 on failure.
///
/// # Safety
///
/// `cp` is a NUL-terminated string; `addr` is null or writable.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn ip4addr_aton(cp: *const c_char, addr: *mut Ip4Addr) -> c_int {
    // SAFETY: forwarded from the caller.
    let Some(val) = (unsafe { aton(cp) }) else {
        return 0;
    };
    // SAFETY: null or writable, per the caller.
    if let Some(addr) = unsafe { addr.as_mut() } {
        *addr = val;
    }
    1
}

/// Convert numeric IP address into decimal dotted ASCII representation in `buf`,
/// NUL-terminated. Returns `None`, with `buf` partly written, if `buf` was too small.
pub fn ntoa(addr: &Ip4Addr, buf: &mut [u8]) -> Option<()> {
    let mut len = 0;
    for mut byte in addr.addr.to_ne_bytes() {
        let mut inv = [0_u8; 3];
        let mut i = 0;
        loop {
            inv[i] = b'0' + byte % 10;
            i += 1;
            byte /= 10;
            if byte == 0 {
                break;
            }
        }
        for &digit in inv[..i].iter().rev() {
            *buf.get_mut(len)? = digit;
            len += 1;
        }
        *buf.get_mut(len)? = b'.';
        len += 1;
    }
    // Replace the last '.' with the NUL.
    buf[len - 1] = 0;
    Some(())
}

/// Same as `ip4addr_ntoa`, but reentrant since a user-supplied buffer is used.
///
/// Returns either pointer to `buf` which now holds the ASCII representation of `addr` or
/// NULL if `buf` was too small.
///
/// # Safety
///
/// `addr` is valid; `buf` is writable for `buflen` bytes.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn ip4addr_ntoa_r(
    addr: *const Ip4Addr,
    buf: *mut c_char,
    buflen: c_int,
) -> *mut c_char {
    let Ok(len) = usize::try_from(buflen) else {
        return core::ptr::null_mut();
    };
    let out: &mut [u8] = if len == 0 {
        &mut []
    } else {
        // SAFETY: writable for `buflen` bytes, per the caller.
        unsafe { core::slice::from_raw_parts_mut(buf.cast(), len) }
    };
    // SAFETY: valid, per the caller.
    match ntoa(unsafe { &*addr }, out) {
        Some(()) => buf,
        None => core::ptr::null_mut(),
    }
}

/// `ip4addr_ntoa`'s buffer: static, so the function is not reentrant, as in C.
struct NtoaBuffer(UnsafeCell<[c_char; IP4ADDR_STRLEN_MAX]>);

// SAFETY: lwIP calls ip4addr_ntoa from one thread at a time; that the result is shared
// is its documented contract.
unsafe impl Sync for NtoaBuffer {}

static NTOA_BUFFER: NtoaBuffer = NtoaBuffer(UnsafeCell::new([0; IP4ADDR_STRLEN_MAX]));

/// Convert numeric IP address into decimal dotted ASCII representation. Returns ptr to
/// static buffer; not reentrant!
///
/// # Safety
///
/// `addr` is valid, and no other call uses the static buffer at the same time.
#[cfg_attr(lwip_export, unsafe(no_mangle))]
pub unsafe extern "C" fn ip4addr_ntoa(addr: *const Ip4Addr) -> *mut c_char {
    // SAFETY: forwarded from the caller; the buffer is IP4ADDR_STRLEN_MAX bytes.
    unsafe {
        ip4addr_ntoa_r(
            addr,
            NTOA_BUFFER.0.get().cast(),
            IP4ADDR_STRLEN_MAX as c_int,
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ffi::CStr;
    use core::mem::MaybeUninit;

    use super::*;

    fn aton_str(s: &CStr) -> Option<u32> {
        // SAFETY: NUL-terminated.
        unsafe { aton(s.as_ptr()) }.map(|addr| u32::from_be(addr.addr))
    }

    #[test]
    fn aton_accepts_every_c_form() {
        assert_eq!(aton_str(c"192.168.0.1"), Some(0xc0a8_0001));
        assert_eq!(aton_str(c"10.1"), Some(0x0a00_0001));
        assert_eq!(aton_str(c"10.1.2"), Some(0x0a01_0002));
        assert_eq!(aton_str(c"3232235521"), Some(0xc0a8_0001));
        assert_eq!(aton_str(c"0xc0.0250.0.1"), Some(0xc0a8_0001));
        assert_eq!(aton_str(c"0XC0.0xa8.0.1"), Some(0xc0a8_0001));
        assert_eq!(aton_str(c"1.2.3.4 trailing"), Some(0x0102_0304));
        assert_eq!(aton_str(c"1.2.3.4\x0b"), Some(0x0102_0304));
        assert_eq!(aton_str(c"0"), Some(0));
    }

    #[test]
    fn aton_rejects_what_c_rejects() {
        for bad in [
            c"",
            c"a.b.c.d",
            c"1.2.3.4.5",
            c"256.1.1.1",
            c"1.2.3.256",
            c"1.2.65536",
            c"1.16777216",
            c"1.2.3.4x",
            c".1.2.3",
            c"1..2",
            c"1.2.3.",
            c"08",
            c"1.2.3.4\x01",
        ] {
            assert_eq!(aton_str(bad), None, "{bad:?}");
        }
    }

    /// test/unit/ip4/test_ip4.c: test_ip4addr_aton.
    #[test]
    fn test_ip4addr_aton() {
        let mut ip_addr = Ip4Addr::default();
        let aton = |s: &CStr, addr: &mut Ip4Addr| {
            // SAFETY: NUL-terminated; a live address.
            unsafe { ip4addr_aton(s.as_ptr(), addr) }
        };
        assert_eq!(aton(c"192.168.0.1", &mut ip_addr), 1);
        assert_eq!(aton(c"192.168.0.0001", &mut ip_addr), 1);
        assert_eq!(aton(c"192.168.0.zzz", &mut ip_addr), 0);
        assert_eq!(aton(c"192.168.1", &mut ip_addr), 1);
        assert_eq!(aton(c"192.168.0xd3", &mut ip_addr), 1);
        assert_eq!(aton(c"192.168.0xz5", &mut ip_addr), 0);
        assert_eq!(aton(c"192.168.095", &mut ip_addr), 0);
    }

    #[test]
    fn octal_parsing_stops_at_an_eight() {
        // The fix in upstream 2e175a23: "08" is "0" with a trailing "8", not 8.
        assert_eq!(aton_str(c"010.0.0.1"), Some(0x0800_0001));
        assert_eq!(aton_str(c"09.0.0.1"), None);
    }

    #[test]
    fn a_32_bit_value_wraps_as_in_c() {
        // 4294967296 overflows u32_t and wraps to 0.
        assert_eq!(aton_str(c"4294967296"), Some(0));
    }

    #[test]
    fn ipaddr_addr_and_ip4addr_aton_report_failure_their_own_way() {
        // SAFETY: NUL-terminated strings; a null or live `addr`.
        unsafe {
            assert_eq!(ipaddr_addr(c"bogus".as_ptr()), IPADDR_NONE);
            assert_eq!(ipaddr_addr(c"1.2.3.4".as_ptr()), 0x0102_0304_u32.to_be());
            assert_eq!(ip4addr_aton(c"1.2.3.4".as_ptr(), core::ptr::null_mut()), 1);
            let mut addr = Ip4Addr { addr: 7 };
            assert_eq!(ip4addr_aton(c"x".as_ptr(), &mut addr), 0);
            assert_eq!(addr.addr, 7, "unchanged on failure");
        }
    }

    fn ntoa_str(addr: u32, buflen: usize) -> Option<std::string::String> {
        let mut buf = std::vec![0xaa_u8; buflen];
        ntoa(&Ip4Addr { addr: addr.to_be() }, &mut buf)?;
        Some(
            CStr::from_bytes_until_nul(&buf)
                .unwrap()
                .to_str()
                .unwrap()
                .into(),
        )
    }

    #[test]
    fn ntoa_writes_dotted_decimal_and_needs_room_for_the_nul() {
        assert_eq!(ntoa_str(0xc0a8_0001, 16).as_deref(), Some("192.168.0.1"));
        assert_eq!(
            ntoa_str(0xffff_ffff, 16).as_deref(),
            Some("255.255.255.255")
        );
        assert_eq!(ntoa_str(0, 8).as_deref(), Some("0.0.0.0"));
        assert_eq!(ntoa_str(0, 7), None);
        assert_eq!(ntoa_str(0xffff_ffff, 15), None);
        assert_eq!(ntoa_str(0, 0), None);
    }

    #[test]
    fn ntoa_r_returns_null_for_a_short_or_negative_buffer() {
        let addr = Ip4Addr { addr: 0x0100_000a };
        let mut buf = [0 as c_char; 16];
        // SAFETY: a live address and buffer of the lengths given.
        unsafe {
            assert!(ip4addr_ntoa_r(&addr, buf.as_mut_ptr(), -1).is_null());
            assert!(ip4addr_ntoa_r(&addr, buf.as_mut_ptr(), 8).is_null());
            assert_eq!(ip4addr_ntoa_r(&addr, buf.as_mut_ptr(), 9), buf.as_mut_ptr());
            assert_eq!(CStr::from_ptr(buf.as_ptr()), c"10.0.0.1");
            assert_eq!(CStr::from_ptr(ip4addr_ntoa(&addr)), c"10.0.0.1");
        }
    }

    #[test]
    fn netmask_valid_needs_contiguous_ones() {
        for (mask, valid) in [
            (0xffff_ff00_u32, true),
            (0xffff_ffff, true),
            (0, true),
            (0x8000_0000, true),
            (0xffff_00ff, false),
            (0x0000_00ff, false),
            (0xfffe_ff00, false),
        ] {
            assert_eq!(
                ip4_addr_netmask_valid(mask.to_be()),
                u8::from(valid),
                "{mask:#x}"
            );
        }
    }

    fn netif(ip: u32, mask: u32, flags: u8) -> Netif {
        // SAFETY: every field of the mirror is valid when zeroed: integers, null
        // pointers, and `None` callbacks.
        let mut netif: Netif = unsafe { MaybeUninit::zeroed().assume_init() };
        netif.ip_addr = IpAddr::v4(ip.to_be());
        netif.netmask = IpAddr::v4(mask.to_be());
        netif.flags = flags;
        netif
    }

    #[test]
    fn isbroadcast_follows_the_c_decision_order() {
        let n = netif(0xc0a8_0105, 0xffff_ff00, NETIF_FLAG_BROADCAST);
        let is = |addr: u32| is_broadcast(addr.to_be(), &n);
        assert!(is(0xffff_ffff));
        assert!(is(0));
        assert!(is(0xc0a8_01ff));
        assert!(!is(0xc0a8_0105), "the interface's own address");
        assert!(!is(0xc0a8_0106));
        assert!(!is(0xc0a8_02ff), "another subnet");
        let no_broadcast = netif(0xc0a8_0105, 0xffff_ff00, 0);
        assert!(!is_broadcast(0xc0a8_01ff_u32.to_be(), &no_broadcast));
        assert!(is_broadcast(0xffff_ffff, &no_broadcast));
        // SAFETY: a live netif.
        assert_eq!(unsafe { ip4_addr_isbroadcast_u32(0xffff_ffff, &n) }, 1);
    }

    #[test]
    fn ip_addr_any_and_broadcast_are_ipv4() {
        assert_eq!(ip_addr_any.ip4().addr, IPADDR_ANY);
        assert_eq!(ip_addr_broadcast.ip4().addr, IPADDR_BROADCAST);
    }
}
