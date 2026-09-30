// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! A minimal freestanding C library for firmware run under Forkpoint.
//!
//! It provides what LVGL, the lwIP Rust port, and compiler-generated code call:
//! the `string.h` and `ctype.h` functions, `putchar`, `abort`, `atoi`, and the `assert`
//! failure path. The firmware
//! supplies the two calls a C library makes into its platform, POSIX `write`
//! and `_exit` (declared in `include/unistd.h`), and its own `printf` and
//! `free`. The C declarations are in `include/`.
//!
//! The C symbols are exported only for a bare-metal target (`target_os =
//! "none"`). A host build, such as `cargo test`, keeps them as ordinary Rust
//! functions so they do not replace the host's C library.

#![no_std]
// memcpy, memmove, memset, and memcmp are defined here: LLVM must not lower
// their loops back into calls to themselves.
#![no_builtins]

mod assert;
pub(crate) mod ctype;
mod stdio;
mod stdlib;
mod string;
mod unistd;

pub use assert::__assert_func;
pub use ctype::{isdigit, islower, isspace, isupper, isxdigit, tolower, toupper};
pub use stdio::putchar;
pub use stdlib::{abort, atoi};
pub use string::{
    memcmp, memcpy, memmove, memset, strcat, strchr, strcmp, strcpy, strlen, strncmp, strncpy,
    strstr,
};

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use core::fmt::Write;

    let mut stderr = unistd::Console::STDERR;
    // The program is ending: a failed write has nowhere to be reported.
    let _ = writeln!(stderr, "libc panic: {info}");
    unistd::exit(134)
}
