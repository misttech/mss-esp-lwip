// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! The firmware's side of the library: POSIX `write` and `_exit`.

use core::ffi::{c_int, c_long, c_void};
use core::fmt;

pub(crate) const STDOUT_FILENO: c_int = 1;
pub(crate) const STDERR_FILENO: c_int = 2;

unsafe extern "C" {
    fn write(fd: c_int, buf: *const c_void, count: usize) -> c_long;
    fn _exit(status: c_int) -> !;
}

/// A file descriptor the firmware's `write` accepts, as a `fmt::Write` sink.
#[derive(Clone, Copy)]
pub(crate) struct Console(c_int);

impl Console {
    pub(crate) const STDOUT: Self = Self(STDOUT_FILENO);
    pub(crate) const STDERR: Self = Self(STDERR_FILENO);

    /// Writes every byte of `bytes`, retrying short writes, and stops at the first
    /// error.
    pub(crate) fn write_bytes(self, mut bytes: &[u8]) -> Result<(), ()> {
        while !bytes.is_empty() {
            // SAFETY: `bytes` is a live slice of `bytes.len()` readable bytes.
            let written = unsafe { write(self.0, bytes.as_ptr().cast(), bytes.len()) };
            let Ok(written) = usize::try_from(written) else {
                return Err(());
            };
            if written == 0 {
                return Err(());
            }
            bytes = bytes.get(written..).unwrap_or_default();
        }
        Ok(())
    }
}

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s.as_bytes()).map_err(|()| fmt::Error)
    }
}

/// Ends the program through the firmware's `_exit`.
pub(crate) fn exit(status: c_int) -> ! {
    // SAFETY: `_exit` takes any status and does not return.
    unsafe { _exit(status) }
}
