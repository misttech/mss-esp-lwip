// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! `string.h`.
//!
//! Each function walks raw pointers one byte at a time. They cannot use slices,
//! `CStr`, or `core::ptr::copy` and its relatives: those lower to calls to
//! `memcpy`, `memmove`, `memset`, `memcmp`, or `strlen`, which are the
//! functions being defined here.

use core::ffi::{c_char, c_int, c_void};

// Comparisons read `c_char` through `u8` pointers: C compares strings as
// `unsigned char`, and `c_char` is signed on some targets.

/// Copies `n` bytes from `src` to `dst`. Returns `dst`.
///
/// # Safety
///
/// `src` is readable and `dst` writable for `n` bytes, and the two do not
/// overlap.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let d = dst.cast::<u8>();
    let s = src.cast::<u8>();
    for i in 0..n {
        // SAFETY: `i < n`, and both ranges are valid for `n` bytes.
        unsafe { *d.add(i) = *s.add(i) };
    }
    dst
}

/// Copies `n` bytes from `src` to `dst`, which may overlap. Returns `dst`.
///
/// # Safety
///
/// `src` is readable and `dst` writable for `n` bytes.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    let d = dst.cast::<u8>();
    let s = src.cast::<u8>();
    if d.cast_const() < s {
        // Copy forward: each byte is read before a lower write can reach it.
        for i in 0..n {
            // SAFETY: `i < n`, and both ranges are valid for `n` bytes.
            unsafe { *d.add(i) = *s.add(i) };
        }
    } else {
        // Copy backward: each byte is read before a higher write can reach it.
        for i in (0..n).rev() {
            // SAFETY: `i < n`, and both ranges are valid for `n` bytes.
            unsafe { *d.add(i) = *s.add(i) };
        }
    }
    dst
}

/// Fills `n` bytes at `dst` with `c` converted to `unsigned char`. Returns `dst`.
///
/// # Safety
///
/// `dst` is writable for `n` bytes.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn memset(dst: *mut c_void, c: c_int, n: usize) -> *mut c_void {
    let d = dst.cast::<u8>();
    for i in 0..n {
        // SAFETY: `i < n`, and `dst` is writable for `n` bytes.
        unsafe { *d.add(i) = c as u8 };
    }
    dst
}

/// Compares `n` bytes as `unsigned char`. Returns the difference of the first
/// pair that differs, or 0.
///
/// # Safety
///
/// `a` and `b` are readable for `n` bytes.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int {
    let x = a.cast::<u8>();
    let y = b.cast::<u8>();
    for i in 0..n {
        // SAFETY: `i < n`, and both ranges are readable for `n` bytes.
        let (p, q) = unsafe { (*x.add(i), *y.add(i)) };
        if p != q {
            return c_int::from(p) - c_int::from(q);
        }
    }
    0
}

/// Returns the number of bytes before the NUL that ends `s`.
///
/// # Safety
///
/// `s` is a NUL-terminated string.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strlen(s: *const c_char) -> usize {
    let mut len = 0;
    // SAFETY: every byte up to and including the NUL is readable.
    while unsafe { *s.add(len) } != 0 {
        len += 1;
    }
    len
}

/// Compares two strings as `unsigned char`.
///
/// # Safety
///
/// `a` and `b` are NUL-terminated strings.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strcmp(a: *const c_char, b: *const c_char) -> c_int {
    let mut i = 0;
    loop {
        // SAFETY: neither string has ended before `i`, so byte `i` is readable.
        let (p, q) = unsafe { (*a.cast::<u8>().add(i), *b.cast::<u8>().add(i)) };
        if p != q || p == 0 {
            return c_int::from(p) - c_int::from(q);
        }
        i += 1;
    }
}

/// Compares at most `n` bytes of two strings as `unsigned char`.
///
/// # Safety
///
/// `a` and `b` are each NUL-terminated or readable for `n` bytes.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strncmp(a: *const c_char, b: *const c_char, n: usize) -> c_int {
    for i in 0..n {
        // SAFETY: `i < n` and neither string has ended before `i`.
        let (p, q) = unsafe { (*a.cast::<u8>().add(i), *b.cast::<u8>().add(i)) };
        if p != q || p == 0 {
            return c_int::from(p) - c_int::from(q);
        }
    }
    0
}

/// Copies `src`, with its NUL, to `dst`. Returns `dst`.
///
/// # Safety
///
/// `src` is a NUL-terminated string, `dst` is writable for `strlen(src) + 1`
/// bytes, and the two do not overlap.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    let mut i = 0;
    loop {
        // SAFETY: `src` has not ended before `i`, and `dst` has room through its NUL.
        let byte = unsafe { *src.add(i) };
        // SAFETY: as above.
        unsafe { *dst.add(i) = byte };
        if byte == 0 {
            return dst;
        }
        i += 1;
    }
}

/// Copies at most `n` bytes of `src` to `dst`, then pads `dst` with NULs to `n`
/// bytes. `dst` is not NUL-terminated when `src` is `n` bytes or longer.
/// Returns `dst`.
///
/// # Safety
///
/// `src` is NUL-terminated or readable for `n` bytes, `dst` is writable for `n`
/// bytes, and the two do not overlap.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strncpy(dst: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    let mut i = 0;
    // SAFETY: `i < n` and `src` has not ended before `i`.
    while i < n && unsafe { *src.add(i) } != 0 {
        // SAFETY: as above, and `dst` is writable for `n` bytes.
        unsafe { *dst.add(i) = *src.add(i) };
        i += 1;
    }
    while i < n {
        // SAFETY: `i < n`, and `dst` is writable for `n` bytes.
        unsafe { *dst.add(i) = 0 };
        i += 1;
    }
    dst
}

/// Appends `src`, with its NUL, to the string in `dst`. Returns `dst`.
///
/// # Safety
///
/// `dst` and `src` are NUL-terminated strings, `dst` is writable for
/// `strlen(dst) + strlen(src) + 1` bytes, and the two do not overlap.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strcat(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    // SAFETY: the caller's contract covers both calls.
    unsafe { strcpy(dst.add(strlen(dst)), src) };
    dst
}

/// Returns a pointer to the first `c`, converted to `char`, in `s`, or null. The
/// NUL that ends `s` is part of the string, so `c == 0` finds it.
///
/// # Safety
///
/// `s` is a NUL-terminated string.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strchr(s: *const c_char, c: c_int) -> *mut c_char {
    let wanted = c as c_char;
    let mut i = 0;
    loop {
        // SAFETY: `s` has not ended before `i`.
        let byte = unsafe { *s.add(i) };
        if byte == wanted {
            // SAFETY: `i` is within `s`, through its NUL.
            return unsafe { s.add(i) }.cast_mut();
        }
        if byte == 0 {
            return core::ptr::null_mut();
        }
        i += 1;
    }
}

/// Finds the first occurrence of `needle` in `haystack`. Returns a pointer to it,
/// `haystack` itself when `needle` is empty, or null when there is none.
///
/// # Safety
///
/// `haystack` and `needle` are NUL-terminated strings.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn strstr(haystack: *const c_char, needle: *const c_char) -> *mut c_char {
    let mut start = 0;
    loop {
        let mut i = 0;
        loop {
            // SAFETY: `needle` has not ended before `i`.
            let wanted = unsafe { *needle.add(i) };
            if wanted == 0 {
                // SAFETY: `start` is within `haystack`, through its NUL.
                return unsafe { haystack.add(start) }.cast_mut();
            }
            // SAFETY: `haystack` has not ended before `start + i`: every byte
            // before it matched a byte of `needle`, which is not NUL.
            if unsafe { *haystack.add(start + i) } != wanted {
                break;
            }
            i += 1;
        }
        // SAFETY: `haystack` has not ended before `start`.
        if unsafe { *haystack.add(start) } == 0 {
            return core::ptr::null_mut();
        }
        start += 1;
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::CStr;

    use super::*;

    fn bytes(buf: &[u8]) -> *const c_char {
        buf.as_ptr().cast()
    }

    #[test]
    fn memcpy_copies_n_bytes_and_returns_dst() {
        let src = *b"abcdef";
        let mut dst = [0_u8; 6];
        let ret = unsafe { memcpy(dst.as_mut_ptr().cast(), src.as_ptr().cast(), 4) };
        assert_eq!(ret, dst.as_mut_ptr().cast());
        assert_eq!(&dst, b"abcd\0\0");
    }

    #[test]
    fn memmove_handles_overlap_in_both_directions() {
        let mut buf = *b"123456";
        let base = buf.as_mut_ptr();
        unsafe { memmove(base.add(2).cast(), base.cast(), 4) };
        assert_eq!(&buf, b"121234");
        let mut buf = *b"123456";
        let base = buf.as_mut_ptr();
        unsafe { memmove(base.cast(), base.add(2).cast(), 4) };
        assert_eq!(&buf, b"345656");
    }

    #[test]
    fn memset_stores_the_low_byte_of_c() {
        let mut buf = [0_u8; 4];
        unsafe { memset(buf.as_mut_ptr().cast(), 0x1ab, 3) };
        assert_eq!(buf, [0xab, 0xab, 0xab, 0]);
    }

    #[test]
    fn memcmp_compares_as_unsigned_char() {
        let a = [0x01_u8, 0x80];
        let b = [0x01_u8, 0x7f];
        assert!(unsafe { memcmp(a.as_ptr().cast(), b.as_ptr().cast(), 2) } > 0);
        assert_eq!(
            unsafe { memcmp(a.as_ptr().cast(), b.as_ptr().cast(), 1) },
            0
        );
        assert_eq!(
            unsafe { memcmp(a.as_ptr().cast(), b.as_ptr().cast(), 0) },
            0
        );
    }

    #[test]
    fn strlen_counts_bytes_before_the_nul() {
        assert_eq!(unsafe { strlen(c"".as_ptr()) }, 0);
        assert_eq!(unsafe { strlen(c"LVGL".as_ptr()) }, 4);
    }

    #[test]
    fn strcmp_orders_by_first_difference_as_unsigned_char() {
        assert_eq!(unsafe { strcmp(c"abc".as_ptr(), c"abc".as_ptr()) }, 0);
        assert!(unsafe { strcmp(c"abc".as_ptr(), c"abd".as_ptr()) } < 0);
        assert!(unsafe { strcmp(c"ab".as_ptr(), c"abc".as_ptr()) } < 0);
        assert!(unsafe { strcmp(bytes(b"\x80\0"), bytes(b"\x7f\0")) } > 0);
    }

    #[test]
    fn strncmp_stops_after_n_bytes_or_at_the_nul() {
        assert_eq!(unsafe { strncmp(c"abcX".as_ptr(), c"abcY".as_ptr(), 3) }, 0);
        assert!(unsafe { strncmp(c"abcX".as_ptr(), c"abcY".as_ptr(), 4) } < 0);
        assert_eq!(unsafe { strncmp(c"ab".as_ptr(), c"ab".as_ptr(), 10) }, 0);
        assert_eq!(unsafe { strncmp(c"a".as_ptr(), c"b".as_ptr(), 0) }, 0);
    }

    #[test]
    fn strcpy_copies_through_the_nul() {
        let mut dst = [0x55_u8; 6];
        unsafe { strcpy(dst.as_mut_ptr().cast(), c"abc".as_ptr()) };
        assert_eq!(&dst, b"abc\0\x55\x55");
    }

    #[test]
    fn strncpy_pads_short_sources_and_truncates_long_ones() {
        let mut dst = [0x55_u8; 6];
        unsafe { strncpy(dst.as_mut_ptr().cast(), c"ab".as_ptr(), 5) };
        assert_eq!(&dst, b"ab\0\0\0\x55");
        let mut dst = [0x55_u8; 4];
        unsafe { strncpy(dst.as_mut_ptr().cast(), c"abcdef".as_ptr(), 3) };
        assert_eq!(&dst, b"abc\x55");
    }

    #[test]
    fn strcat_appends_after_the_existing_string() {
        let mut dst = *b"ab\0\0\0\0";
        unsafe { strcat(dst.as_mut_ptr().cast(), c"\n".as_ptr()) };
        let joined = unsafe { CStr::from_ptr(dst.as_ptr().cast()) };
        assert_eq!(joined, c"ab\n");
    }

    #[test]
    fn strchr_finds_the_first_match_or_the_terminator() {
        let s = c"a\nb\n";
        let base = s.as_ptr();
        assert_eq!(
            unsafe { strchr(base, i32::from(b'\n')) },
            unsafe { base.add(1) }.cast_mut()
        );
        assert_eq!(
            unsafe { strchr(base, 0) },
            unsafe { base.add(4) }.cast_mut()
        );
        assert!(unsafe { strchr(base, i32::from(b'z')) }.is_null());
    }

    #[test]
    fn strstr_finds_the_first_occurrence() {
        let s = c"host.local.local";
        let base = s.as_ptr();
        assert_eq!(
            unsafe { strstr(base, c".local".as_ptr()) },
            unsafe { base.add(4) }.cast_mut()
        );
        assert_eq!(unsafe { strstr(base, c"host".as_ptr()) }, base.cast_mut());
        assert_eq!(
            unsafe { strstr(base, c"l.local".as_ptr()) },
            unsafe { base.add(9) }.cast_mut()
        );
        // A partial match that fails restarts one byte on.
        let aab = c"aab".as_ptr();
        assert_eq!(
            unsafe { strstr(aab, c"ab".as_ptr()) },
            unsafe { aab.add(1) }.cast_mut()
        );
    }

    #[test]
    fn strstr_misses_and_an_empty_needle() {
        let s = c"example.com";
        let base = s.as_ptr();
        assert!(unsafe { strstr(base, c".local".as_ptr()) }.is_null());
        assert!(unsafe { strstr(base, c"example.commerce".as_ptr()) }.is_null());
        assert!(unsafe { strstr(c"".as_ptr(), c"a".as_ptr()) }.is_null());
        assert_eq!(unsafe { strstr(base, c"".as_ptr()) }, base.cast_mut());
        let empty = c"".as_ptr();
        assert_eq!(unsafe { strstr(empty, c"".as_ptr()) }, empty.cast_mut());
    }
}
