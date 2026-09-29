// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! Zero-dependency `no_std` building blocks for the lwIP Rust port. See `README.md`.

#![no_std]

mod lossy_utf8;
mod static_assert;

pub use lossy_utf8::{LossyUtf8, from_utf8_lossy};

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::from_utf8_lossy;

    crate::static_assert!(core::mem::size_of::<u32>() == 4);
    crate::static_assert_size_and_align!(u64, 8, core::mem::align_of::<u64>());

    #[test]
    fn valid_utf8_formats_unchanged() {
        assert_eq!(format!("{}", from_utf8_lossy(b"GT1151")), "GT1151");
    }

    #[test]
    fn each_invalid_sequence_becomes_one_replacement_character() {
        assert_eq!(
            format!("{}", from_utf8_lossy(b"a\xffb\xc3")),
            "a\u{FFFD}b\u{FFFD}"
        );
    }
}
