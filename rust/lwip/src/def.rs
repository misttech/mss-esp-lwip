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
// Author: Simon Goldschmidt
//
// Translated to Rust for mss-esp-lwip by Mist Tecnologia LTDA.

//! Common functions used throughout the stack, from `src/core/def.c`.
//!
//! These are reference implementations of the byte swapping functions. Byte swapping is
//! the second thing you would want to optimize; a port can `#define lwip_htons(x)
//! your_htons` and `lwip_htonl(x) your_htonl` in its `cc.h`, and then these are not
//! built (`LWIP_HTONS_FN`, `LWIP_HTONL_FN` in `config`). `lwip_ntohs()` and
//! `lwip_ntohl()` are merely references to the htonx counterparts.
//!
//! lwIP also provides default implementations for non-standard functions (the
//! `sys_nonstandard` group). A port can map them to OS functions in `arch/cc.h` to reduce
//! code footprint; the ones it maps are not built here either.

use core::ffi::{c_char, c_int};
use core::ptr;

use crate::cstr::{self, Cursor};

/// Convert an `u16_t` from host to network byte order.
pub fn htons(n: u16) -> u16 {
    n.to_be()
}

/// Convert an `u32_t` from host to network byte order.
pub fn htonl(n: u32) -> u32 {
    n.to_be()
}

/// `lwip_htons`: [`htons`] for C.
#[cfg(all(target_endian = "little", lwip_htons_fn))]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn lwip_htons(n: u16) -> u16 {
    htons(n)
}

/// `lwip_htonl`: [`htonl`] for C.
#[cfg(all(target_endian = "little", lwip_htonl_fn))]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn lwip_htonl(n: u32) -> u32 {
    htonl(n)
}

/// Whether the `len` bytes at `p` equal the first `len` bytes of `token`, compared the
/// way `strncmp(p, token, len) == 0` does when `token` has no NUL in its first `len`
/// bytes: stop at the first difference.
///
/// # Safety
///
/// `p` and `token` are readable up to their first difference, and `token` up to `len`.
unsafe fn prefix_eq(p: Cursor, token: Cursor, len: usize) -> bool {
    // SAFETY: each read stops at the first difference or at `len`, per the caller.
    (0..len).all(|i| unsafe { p.at(i) == token.at(i) })
}

/// `strnstr()` and `strnistr()`: the first place in the first `n` bytes of `buffer`
/// (or before its NUL) where `token` starts, as `matches(p, token, tokenlen)` decides.
///
/// # Safety
///
/// `buffer` and `token` are NUL-terminated strings, and `matches` reads no further than
/// [`prefix_eq`].
unsafe fn find(
    buffer: *const c_char,
    token: *const c_char,
    n: usize,
    matches: unsafe fn(Cursor, Cursor, usize) -> bool,
) -> *mut c_char {
    // SAFETY: `token` is NUL-terminated, per the caller.
    let tokenlen = unsafe { cstr::strlen(token) };
    if tokenlen == 0 {
        return buffer.cast_mut();
    }
    // SAFETY: both are NUL-terminated strings, per the caller.
    let (buffer, token) = unsafe { (Cursor::new(buffer), Cursor::new(token)) };
    let end = buffer.ptr().wrapping_add(n);
    let mut p = buffer;
    // SAFETY: the loop reads `p` only after the previous byte was not NUL.
    while unsafe { p.at(0) } != 0 && p.ptr().wrapping_add(tokenlen) <= end {
        // SAFETY: `matches` stops at the first difference, so at `p`'s NUL at the latest.
        if unsafe { matches(p, token, tokenlen) } {
            return p.ptr().cast_mut().cast();
        }
        p = p.advance(1);
    }
    ptr::null_mut()
}

/// lwIP default implementation for the non-standard `strnstr()`.
///
/// # Safety
///
/// `buffer` and `token` are NUL-terminated strings.
#[cfg(lwip_strnstr_fn)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn lwip_strnstr(
    buffer: *const c_char,
    token: *const c_char,
    n: usize,
) -> *mut c_char {
    // SAFETY: forwarded from the caller; `prefix_eq` stops at the first difference.
    unsafe { find(buffer, token, n, prefix_eq) }
}

/// lwIP default implementation for the non-standard `strnistr()`.
///
/// # Safety
///
/// `buffer` and `token` are NUL-terminated strings.
#[cfg(lwip_strnistr_fn)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn lwip_strnistr(
    buffer: *const c_char,
    token: *const c_char,
    n: usize,
) -> *mut c_char {
    unsafe fn matches(p: Cursor, token: Cursor, len: usize) -> bool {
        // SAFETY: `strnicmp` stops at the first difference or NUL.
        unsafe { strnicmp(p, token, len) == 0 }
    }
    // SAFETY: forwarded from the caller; `matches` stops at the first difference.
    unsafe { find(buffer, token, n, matches) }
}

/// Whether `c1` and `c2`, known to differ, are the same letter in different case.
fn same_letter(c1: u8, c2: u8) -> bool {
    let c1_upc = c1 | 0x20;
    // Characters are not equal and one is in the alphabet range: downcase both chars and
    // check again. Otherwise they are not equal, and none is in the alphabet range.
    c1_upc.is_ascii_lowercase() && c1_upc == c2 | 0x20
}

/// Compare `str1` and `str2` ignoring case, for at most `len` bytes, the first always.
/// Returns 0 if equal and 1 otherwise: callers don't care for < or >.
///
/// # Safety
///
/// Both are readable up to their first NUL or difference.
unsafe fn strnicmp(str1: Cursor, str2: Cursor, mut len: usize) -> c_int {
    let mut i = 0;
    loop {
        // SAFETY: the previous bytes were equal and not NUL, per the loop condition.
        let (c1, c2) = unsafe { (str1.at(i), str2.at(i)) };
        i += 1;
        if c1 != c2 && !same_letter(c1, c2) {
            return 1;
        }
        // As in C, a `len` of 0 still compares the first byte and then wraps, so the
        // comparison runs to the NUL.
        len = len.wrapping_sub(1);
        if len == 0 || c1 == 0 {
            return 0;
        }
    }
}

/// lwIP default implementation for the non-standard `stricmp()`.
///
/// # Safety
///
/// `str1` and `str2` are NUL-terminated strings.
#[cfg(lwip_stricmp_fn)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn lwip_stricmp(str1: *const c_char, str2: *const c_char) -> c_int {
    // SAFETY: both are NUL-terminated, per the caller, and a `len` of 0 never ends the
    // comparison before a NUL or a difference.
    unsafe { strnicmp(Cursor::new(str1), Cursor::new(str2), 0) }
}

/// lwIP default implementation for the non-standard `strnicmp()`.
///
/// # Safety
///
/// `str1` and `str2` are NUL-terminated strings, or readable for `len` bytes.
#[cfg(lwip_strnicmp_fn)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn lwip_strnicmp(
    str1: *const c_char,
    str2: *const c_char,
    len: usize,
) -> c_int {
    // SAFETY: forwarded from the caller.
    unsafe { strnicmp(Cursor::new(str1), Cursor::new(str2), len) }
}

/// Write `number` in decimal into `result`, NUL-terminated. A buffer too small for the
/// number and its NUL gets an empty string; an empty buffer is left alone.
pub fn itoa(result: &mut [u8], number: c_int) {
    let bufsize = result.len();
    // Handle invalid bufsize.
    if bufsize < 2 {
        if let Some(first) = result.first_mut() {
            *first = 0;
        }
        return;
    }
    // C negates `number` in `int`; the one value that overflows, INT_MIN, stays negative,
    // and the digits it then yields are what the C code writes.
    let mut n = if number >= 0 {
        number
    } else {
        number.wrapping_neg()
    };
    let mut res = 0;
    // First, add sign.
    if number < 0 {
        result[res] = b'-';
        res += 1;
    }
    // Then create the string from the end and stop if buffer full, and ensure output
    // string is zero terminated.
    let mut tmp = bufsize - 1;
    result[tmp] = 0;
    while n != 0 && tmp > res {
        let val = (c_int::from(b'0') + n % 10) as u8;
        tmp -= 1;
        result[tmp] = val;
        n /= 10;
    }
    if n != 0 {
        // Buffer is too small.
        result[0] = 0;
        return;
    }
    if result[tmp] == 0 {
        // Nothing added?
        result[res] = b'0';
        result[res + 1] = 0;
        return;
    }
    // Move from temporary buffer to output buffer (sign is not moved).
    result.copy_within(tmp..bufsize, res);
}

/// lwIP default implementation for the non-standard `itoa()`.
///
/// # Safety
///
/// `result` is writable for `bufsize` bytes.
#[cfg(lwip_itoa_fn)]
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn lwip_itoa(result: *mut c_char, bufsize: usize, number: c_int) {
    if bufsize == 0 {
        return;
    }
    // SAFETY: `result` is writable for `bufsize` bytes, per the caller.
    let result = unsafe { core::slice::from_raw_parts_mut(result.cast::<u8>(), bufsize) };
    itoa(result, number);
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::ffi::CStr;

    use super::*;

    const MAGIC_UNTOUCHED_BYTE: u8 = 0x7a;
    const TEST_BUFSIZE: usize = 32;
    const GUARD_SIZE: usize = 4;

    fn check_range_untouched(buf: &[u8]) {
        assert!(buf.iter().all(|&byte| byte == MAGIC_UNTOUCHED_BYTE));
    }

    /// test/unit/core/test_def.c: test_def_itoa.
    fn test_def_itoa(number: c_int, expected: &str) {
        let expected = expected.as_bytes();
        let exp_len = expected.len();
        assert!(exp_len + 4 < TEST_BUFSIZE - 2 * GUARD_SIZE);

        let mut buf = [MAGIC_UNTOUCHED_BYTE; TEST_BUFSIZE];
        itoa(&mut buf[GUARD_SIZE..GUARD_SIZE + exp_len + 1], number);
        let (guard, test_buf) = buf.split_at(GUARD_SIZE);
        check_range_untouched(guard);
        assert_eq!(test_buf[exp_len], 0);
        assert_eq!(&test_buf[..exp_len], expected);
        check_range_untouched(&test_buf[exp_len + 1..]);

        // Check with too small buffer.
        let mut buf = [MAGIC_UNTOUCHED_BYTE; TEST_BUFSIZE];
        itoa(&mut buf[GUARD_SIZE..GUARD_SIZE + exp_len], number);
        let (guard, test_buf) = buf.split_at(GUARD_SIZE);
        check_range_untouched(guard);
        check_range_untouched(&test_buf[exp_len + 1..]);

        // Check with too large buffer.
        let mut buf = [MAGIC_UNTOUCHED_BYTE; TEST_BUFSIZE];
        itoa(&mut buf[GUARD_SIZE..GUARD_SIZE + exp_len + 4], number);
        let (guard, test_buf) = buf.split_at(GUARD_SIZE);
        check_range_untouched(guard);
        assert_eq!(test_buf[exp_len], 0);
        assert_eq!(&test_buf[..exp_len], expected);
        check_range_untouched(&test_buf[exp_len + 4..]);
    }

    #[test]
    fn test_def_lwip_itoa() {
        test_def_itoa(0, "0");
        test_def_itoa(1, "1");
        test_def_itoa(-1, "-1");
        test_def_itoa(15, "15");
        test_def_itoa(-15, "-15");
        test_def_itoa(156, "156");
        test_def_itoa(1192, "1192");
        test_def_itoa(-156, "-156");
    }

    #[test]
    fn itoa_edge_cases() {
        let mut empty = [MAGIC_UNTOUCHED_BYTE; 0];
        itoa(&mut empty, 7);
        let mut one = [MAGIC_UNTOUCHED_BYTE; 1];
        itoa(&mut one, 7);
        assert_eq!(one, [0]);
        let mut two = [MAGIC_UNTOUCHED_BYTE; 2];
        itoa(&mut two, -7);
        assert_eq!(two[0], 0, "no room for the sign and a digit");
        let mut max = [MAGIC_UNTOUCHED_BYTE; 11];
        itoa(&mut max, c_int::MAX);
        assert_eq!(&max, b"2147483647\0");
    }

    #[test]
    fn itoa_of_int_min_writes_what_the_c_code_does() {
        // -INT_MIN overflows back to INT_MIN; its remainders are negative, so each
        // "digit" d is written as '0' - d. C writes the same bytes.
        let mut buf = [MAGIC_UNTOUCHED_BYTE; 12];
        itoa(&mut buf, c_int::MIN);
        assert_eq!(&buf, b"-./,),(-*,(\0");
    }

    #[test]
    fn htons_and_htonl_swap_on_little_endian() {
        assert_eq!(htons(0x1234), 0x1234_u16.to_be());
        assert_eq!(htonl(0x1234_5678), 0x1234_5678_u32.to_be());
    }

    fn ci(a: &CStr, b: &CStr, len: usize) -> c_int {
        // SAFETY: both are NUL-terminated.
        unsafe { strnicmp(Cursor::new(a.as_ptr()), Cursor::new(b.as_ptr()), len) }
    }

    #[test]
    fn strnicmp_ignores_case_only_for_letters() {
        assert_eq!(ci(c"Host", c"hOST", 0), 0);
        assert_eq!(ci(c"Host", c"Hosts", 0), 1);
        assert_eq!(ci(c"Host", c"Hosts", 4), 0);
        // '@' | 0x20 is '`', not a letter.
        assert_eq!(ci(c"@", c"`", 0), 1);
        assert_eq!(ci(c"[", c"{", 0), 1);
        assert_eq!(ci(c"", c"", 0), 0);
        assert_eq!(ci(c"a", c"b", 1), 1);
    }

    fn find_in(buffer: &CStr, token: &CStr, n: usize, ignore_case: bool) -> Option<usize> {
        unsafe fn insensitive(p: Cursor, token: Cursor, len: usize) -> bool {
            // SAFETY: forwarded.
            unsafe { strnicmp(p, token, len) == 0 }
        }
        let matches = if ignore_case { insensitive } else { prefix_eq };
        // SAFETY: both are NUL-terminated.
        let found = unsafe { find(buffer.as_ptr(), token.as_ptr(), n, matches) };
        (!found.is_null()).then(|| found as usize - buffer.as_ptr() as usize)
    }

    #[test]
    fn strnstr_finds_a_token_inside_the_bound() {
        let buffer = c"HTTP/1.0 200 OK\r\n\r\nbody";
        assert_eq!(find_in(buffer, c"\r\n\r\n", 64, false), Some(15));
        assert_eq!(find_in(buffer, c"\r\n\r\n", 19, false), Some(15));
        // The token must end inside the first `n` bytes.
        assert_eq!(find_in(buffer, c"\r\n\r\n", 18, false), None);
        assert_eq!(find_in(buffer, c"", 0, false), Some(0));
        assert_eq!(find_in(buffer, c"ok", 64, false), None);
        assert_eq!(find_in(buffer, c"ok", 64, true), Some(13));
        assert_eq!(find_in(c"", c"a", 8, false), None);
    }
}
