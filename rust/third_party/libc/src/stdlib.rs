// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! `stdlib.h`: `abort` and `atoi`. `free` is the firmware allocator's.

use core::ffi::{c_char, c_int, c_long};

use crate::ctype::isspace;
use crate::unistd::{self, Console};

/// The status `abort` exits with: 128 plus `SIGABRT`, as a shell reports it.
const ABORT_STATUS: core::ffi::c_int = 134;

/// Writes `abort()` to standard error and ends the program.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn abort() -> ! {
    // The program is ending: a failed write has nowhere to be reported.
    let _ = Console::STDERR.write_bytes(b"abort()\n");
    unistd::exit(ABORT_STATUS)
}

/// Converts the initial decimal number in `s` to an `int`, as `(int)strtol(s, NULL, 10)`
/// does: leading white space is skipped, one `+` or `-` sign is taken, and the digits run
/// to the first non-digit. A number too large for `long` is clamped to `LONG_MAX` or
/// `LONG_MIN` before the conversion to `int`, as newlib's `atoi` does; no digits give 0.
///
/// # Safety
///
/// `s` is a NUL-terminated string.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn atoi(s: *const c_char) -> c_int {
    let s = s.cast::<u8>();
    let mut i = 0;
    // SAFETY: each read is at or before the string's NUL, which ends every loop.
    let at = |i: usize| unsafe { *s.add(i) };
    while isspace(c_int::from(at(i))) != 0 {
        i += 1;
    }
    let negative = at(i) == b'-';
    if at(i) == b'-' || at(i) == b'+' {
        i += 1;
    }
    let mut value: c_long = 0;
    while at(i).is_ascii_digit() {
        let digit = c_long::from(at(i) - b'0');
        value = if negative {
            value.saturating_mul(10).saturating_sub(digit)
        } else {
            value.saturating_mul(10).saturating_add(digit)
        };
        i += 1;
    }
    value as c_int
}

#[cfg(test)]
mod tests {
    use core::ffi::CStr;

    use super::*;

    fn a(s: &CStr) -> c_int {
        // SAFETY: NUL-terminated.
        unsafe { atoi(s.as_ptr()) }
    }

    #[test]
    fn atoi_reads_the_leading_decimal_number() {
        assert_eq!(a(c"0"), 0);
        assert_eq!(a(c"42"), 42);
        assert_eq!(a(c"  \t\n\x0b\x0c\r-17abc"), -17);
        assert_eq!(a(c"+8"), 8);
        assert_eq!(a(c"007"), 7);
        assert_eq!(a(c""), 0);
        assert_eq!(a(c"x1"), 0);
        assert_eq!(a(c"- 1"), 0);
        assert_eq!(a(c"+-1"), 0);
        assert_eq!(a(c"2147483647"), 2_147_483_647);
        assert_eq!(a(c"-2147483648"), -2_147_483_648);
    }

    #[test]
    fn atoi_clamps_to_long_before_converting_to_int() {
        // strtol clamps to LONG_MAX; the conversion to int keeps the low bits, as C's does.
        assert_eq!(a(c"99999999999999999999999"), c_long::MAX as c_int);
        assert_eq!(a(c"-99999999999999999999999"), c_long::MIN as c_int);
    }
}
