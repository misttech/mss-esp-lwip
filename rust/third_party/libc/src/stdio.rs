// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! `stdio.h`: `putchar`. `printf` is the firmware's, since stable Rust cannot
//! define a C variadic function.

use core::ffi::c_int;

use crate::unistd::Console;

/// C `EOF`.
const EOF: c_int = -1;

/// Writes `c`, converted to `unsigned char`, to standard output.
///
/// Returns the byte written, or `EOF` if the write failed.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub extern "C" fn putchar(c: c_int) -> c_int {
    let byte = c as u8;
    match Console::STDOUT.write_bytes(&[byte]) {
        Ok(()) => c_int::from(byte),
        Err(()) => EOF,
    }
}
