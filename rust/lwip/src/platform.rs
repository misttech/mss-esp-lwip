// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! What the C stack gets from `arch/cc.h`: assertions. They fail through the C library,
//! `rivet-libc`, whose panic handler also serves this crate in firmware.

/// `LWIP_ASSERT(message, assertion)`: when `assertion` is false, report `message` the way
/// the port's `LWIP_PLATFORM_ASSERT` does. Compiled out with `LWIP_NOASSERT`.
macro_rules! lwip_assert {
    ($message:literal, $assertion:expr) => {
        #[cfg(not(lwip_noassert))]
        if !($assertion) {
            $crate::platform::platform_assert(
                concat!(file!(), "\0"),
                line!(),
                concat!(module_path!(), "\0"),
                concat!($message, "\0"),
            );
        }
    };
}

/// `LWIP_PLATFORM_ASSERT(message)` in ESP-IDF: the C library's `__assert_func`, or
/// `abort()` when assertions are silent. Each string ends in a NUL. A host test panics
/// instead, since the C library's failure path ends the process.
#[cfg(not(lwip_noassert))]
#[cold]
pub(crate) fn platform_assert(file: &str, line: u32, func: &str, message: &str) -> ! {
    #[cfg(all(target_os = "none", not(lwip_assert_silent)))]
    // SAFETY: each string is NUL-terminated and static.
    unsafe {
        rivet_libc::__assert_func(
            file.as_ptr().cast(),
            line as core::ffi::c_int,
            func.as_ptr().cast(),
            message.as_ptr().cast(),
        )
    }
    #[cfg(all(target_os = "none", lwip_assert_silent))]
    {
        let _ = (file, line, func, message);
        rivet_libc::abort()
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = func;
        panic!(
            "assertion \"{}\" failed: file \"{}\", line {line}",
            message.trim_end_matches('\0'),
            file.trim_end_matches('\0')
        )
    }
}

/// The panic handler of a host build linked into a C program, such as lwIP's own unit
/// tests: a failed assertion panics (see `platform_assert`), which reports the message
/// on standard error and aborts, as the Unix port's `LWIP_PLATFORM_ASSERT` does. A
/// firmware's is rivet-libc's; a host test's is the standard library's.
#[cfg(all(lwip_export, not(target_os = "none"), not(test)))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use core::fmt::Write;

    unsafe extern "C" {
        fn write(fd: core::ffi::c_int, buf: *const u8, count: usize) -> isize;
        fn abort() -> !;
    }

    struct Stderr;

    impl Write for Stderr {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            // SAFETY: `s` is `s.len()` readable bytes.
            let written = unsafe { write(2, s.as_ptr(), s.len()) };
            if written < 0 {
                Err(core::fmt::Error)
            } else {
                Ok(())
            }
        }
    }

    // The program is ending: a failed write has nowhere to be reported.
    let _ = writeln!(Stderr, "{}", info.message());
    // SAFETY: `abort` takes no arguments and does not return.
    unsafe { abort() }
}

/// The unwinding personality the host's prebuilt `core` refers to. This crate is built
/// with `panic = "abort"`, so nothing unwinds and it is never called.
#[cfg(all(lwip_export, not(target_os = "none"), not(test)))]
#[unsafe(no_mangle)]
extern "C" fn rust_eh_personality() {}
