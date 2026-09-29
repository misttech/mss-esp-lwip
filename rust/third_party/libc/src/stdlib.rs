// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! `stdlib.h`: `abort`. `free` is the firmware allocator's.

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
