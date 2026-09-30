// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! lwIP's global variables.

use core::cell::UnsafeCell;

/// A global variable of the stack, laid out as the plain C variable it replaces, so C
/// code that declares it `extern` reads and writes it directly.
///
/// lwIP's core is not reentrant: it runs in the tcpip thread (or under
/// `LOCK_TCPIP_CORE`), and state that interrupts share is guarded by
/// `SYS_ARCH_PROTECT`. That discipline, not this type, keeps accesses from overlapping.
#[repr(transparent)]
pub struct Global<T>(UnsafeCell<T>);

// SAFETY: the stack serializes every access, as described above.
unsafe impl<T> Sync for Global<T> {}

impl<T> Global<T> {
    /// A global initialized to `value`.
    pub const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    /// The variable's address, for C and for fields of a struct global.
    pub const fn as_ptr(&self) -> *mut T {
        self.0.get()
    }
}

impl<T: Copy> Global<T> {
    /// The variable's value.
    pub fn get(&self) -> T {
        // SAFETY: accesses are serialized by the stack; the value is Copy.
        unsafe { self.0.get().read() }
    }

    /// Sets the variable.
    pub fn set(&self, value: T) {
        // SAFETY: accesses are serialized by the stack.
        unsafe { self.0.get().write(value) }
    }
}
