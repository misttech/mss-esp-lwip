// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! `ctype.h`: character classification and case mapping in the "C" locale.
//!
//! Each function takes a character as an `int` holding an `unsigned char` value or
//! `EOF`, as C does. Only ASCII letters, digits, and the six white-space characters
//! (`' '`, `\t`, `\n`, `\v`, `\f`, `\r`) classify; every other value, including `EOF` and
//! bytes above 0x7f, does not. The predicates return 1 or 0.

use core::ffi::c_int;

/// `c` as a byte, or `None` if it is `EOF` or outside `unsigned char`.
fn byte(c: c_int) -> Option<u8> {
    u8::try_from(c).ok()
}

/// Whether `c` is a decimal digit.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn isdigit(c: c_int) -> c_int {
    c_int::from(byte(c).is_some_and(|b| b.is_ascii_digit()))
}

/// Whether `c` is a hexadecimal digit.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn isxdigit(c: c_int) -> c_int {
    c_int::from(byte(c).is_some_and(|b| b.is_ascii_hexdigit()))
}

/// Whether `c` is a lowercase letter.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn islower(c: c_int) -> c_int {
    c_int::from(byte(c).is_some_and(|b| b.is_ascii_lowercase()))
}

/// Whether `c` is an uppercase letter.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn isupper(c: c_int) -> c_int {
    c_int::from(byte(c).is_some_and(|b| b.is_ascii_uppercase()))
}

/// Whether `c` is white space: space, `\t`, `\n`, `\v`, `\f`, or `\r`. Unlike
/// `u8::is_ascii_whitespace`, this includes `\v`.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn isspace(c: c_int) -> c_int {
    c_int::from(byte(c).is_some_and(|b| b == b' ' || (b'\t'..=b'\r').contains(&b)))
}

/// `c` in lowercase if it is an uppercase letter, else `c` unchanged.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn tolower(c: c_int) -> c_int {
    match byte(c) {
        Some(b) => c_int::from(b.to_ascii_lowercase()),
        None => c,
    }
}

/// `c` in uppercase if it is a lowercase letter, else `c` unchanged.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn toupper(c: c_int) -> c_int {
    match byte(c) {
        Some(b) => c_int::from(b.to_ascii_uppercase()),
        None => c,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EOF: c_int = -1;

    /// Every value a predicate accepts, from EOF through 255.
    fn accepted(predicate: extern "C" fn(c_int) -> c_int) -> [bool; 257] {
        core::array::from_fn(|i| {
            let result = predicate(i as c_int - 1);
            assert!(result == 0 || result == 1, "predicates return 0 or 1");
            result == 1
        })
    }

    fn only(chars: &[u8]) -> [bool; 257] {
        core::array::from_fn(|i| i > 0 && chars.contains(&((i - 1) as u8)))
    }

    #[test]
    fn classification_matches_the_c_locale_for_every_value() {
        let digits = b"0123456789";
        let lower = b"abcdefghijklmnopqrstuvwxyz";
        let upper = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        assert_eq!(accepted(isdigit), only(digits));
        assert_eq!(accepted(isxdigit), only(b"0123456789abcdefABCDEF"));
        assert_eq!(accepted(islower), only(lower));
        assert_eq!(accepted(isupper), only(upper));
        assert_eq!(accepted(isspace), only(b" \t\n\x0b\x0c\r"));
    }

    #[test]
    fn case_mapping_changes_only_letters() {
        assert_eq!(tolower(c_int::from(b'Q')), c_int::from(b'q'));
        assert_eq!(toupper(c_int::from(b'q')), c_int::from(b'Q'));
        for c in [
            EOF,
            0,
            c_int::from(b'5'),
            c_int::from(b'@'),
            c_int::from(b'['),
            0xc4,
        ] {
            assert_eq!(tolower(c), c);
            assert_eq!(toupper(c), c);
        }
    }
}
