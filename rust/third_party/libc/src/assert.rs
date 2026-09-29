// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! `assert.h`: the failure path of `assert`, named as newlib names it.

use core::ffi::{CStr, c_char, c_int};
use core::fmt::{self, Write};

use crate::stdlib::abort;
use crate::unistd::Console;

/// Reports a failed `assert` on standard error and aborts.
///
/// # Safety
///
/// `file`, `function`, and `expression` are each null or a NUL-terminated
/// string, as the `assert` macro in `include/assert.h` passes them.
#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub unsafe extern "C" fn __assert_func(
    file: *const c_char,
    line: c_int,
    function: *const c_char,
    expression: *const c_char,
) -> ! {
    // SAFETY: the caller passes null or NUL-terminated strings.
    let (file, function, expression) =
        unsafe { (c_bytes(file), c_bytes(function), c_bytes(expression)) };
    // The program is ending: a failed write has nowhere to be reported.
    let mut stderr = Console::STDERR;
    let _ = write_failure(&mut stderr, file, line, function, expression);
    abort()
}

/// # Safety
///
/// `s` is null or a NUL-terminated string that outlives the returned slice.
unsafe fn c_bytes<'a>(s: *const c_char) -> &'a [u8] {
    if s.is_null() {
        return b"?";
    }
    // SAFETY: `s` is non-null and NUL-terminated, per the caller.
    unsafe { CStr::from_ptr(s) }.to_bytes()
}

fn write_failure(
    out: &mut impl Write,
    file: &[u8],
    line: c_int,
    function: &[u8],
    expression: &[u8],
) -> fmt::Result {
    writeln!(
        out,
        "assert failed: {} {}:{} ({})",
        fp::from_utf8_lossy(function),
        fp::from_utf8_lossy(file),
        line,
        fp::from_utf8_lossy(expression)
    )
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::string::String;

    use super::*;

    #[test]
    fn a_failure_names_function_file_line_and_expression() {
        let mut out = String::new();
        write_failure(&mut out, b"main/main.c", 94, b"guiTask", b"buf1 != NULL").unwrap();
        assert_eq!(
            out,
            "assert failed: guiTask main/main.c:94 (buf1 != NULL)\n"
        );
    }

    #[test]
    fn a_null_string_prints_as_a_question_mark() {
        // SAFETY: null is allowed.
        assert_eq!(unsafe { c_bytes(core::ptr::null()) }, b"?");
        // SAFETY: the literal is NUL-terminated and static.
        assert_eq!(unsafe { c_bytes(c"expr".as_ptr()) }, b"expr");
    }
}
