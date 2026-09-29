// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! Byte-at-a-time reads of C strings whose length is not known up front.
//!
//! lwIP's string helpers read their arguments lazily: they stop at the first NUL, the
//! first mismatch, or a caller-given bound, whichever comes first, and never look past
//! it. Forming a slice first (`CStr::from_ptr`, which calls `strlen`) would read further
//! than the C code does, so these helpers keep the C access pattern.

use core::ffi::c_char;

/// A read cursor over a C string.
#[derive(Clone, Copy)]
pub(crate) struct Cursor {
    ptr: *const u8,
}

impl Cursor {
    /// # Safety
    ///
    /// `ptr` points to a byte sequence that stays readable up to and including its first
    /// NUL, or up to whatever bound every later read respects.
    pub(crate) unsafe fn new(ptr: *const c_char) -> Self {
        Self { ptr: ptr.cast() }
    }

    /// The byte `index` bytes past the cursor.
    ///
    /// # Safety
    ///
    /// No NUL lies before `index` in the string the cursor was made from, or the caller's
    /// bound covers `index`.
    pub(crate) unsafe fn at(self, index: usize) -> u8 {
        // SAFETY: the caller guarantees the byte is inside the readable string.
        unsafe { self.ptr.add(index).read() }
    }

    /// The cursor `count` bytes further on.
    pub(crate) fn advance(self, count: usize) -> Self {
        Self {
            ptr: self.ptr.wrapping_add(count),
        }
    }

    /// The pointer the cursor is at.
    pub(crate) fn ptr(self) -> *const u8 {
        self.ptr
    }
}

/// The length of the C string `s`, from the C library's `strlen`.
///
/// # Safety
///
/// `s` is a NUL-terminated string.
pub(crate) unsafe fn strlen(s: *const c_char) -> usize {
    // SAFETY: `s` is NUL-terminated, per the caller.
    unsafe { forkpoint_libc::strlen(s) }
}
