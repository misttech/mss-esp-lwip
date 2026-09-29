// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! What the C stack gets from `arch/cc.h`: assertions. They fail through the C library,
//! `forkpoint-libc`, whose panic handler also serves this crate in firmware.

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
        forkpoint_libc::__assert_func(
            file.as_ptr().cast(),
            line as core::ffi::c_int,
            func.as_ptr().cast(),
            message.as_ptr().cast(),
        )
    }
    #[cfg(all(target_os = "none", lwip_assert_silent))]
    {
        let _ = (file, line, func, message);
        forkpoint_libc::abort()
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
