# forkpoint-libc

Forkpoint's freestanding C library, which the lwIP Rust modules take everything
they need from a C library from (`strlen`, `memmove`, `atoi`, the `ctype.h`
classification, `abort`, and the `assert` failure path) instead of the
firmware's newlib.

- Source: Forkpoint `src/lib/libc`, revision `0a5c82e92716f84167c363f4e331c9517856a14a`.
- Local change: the `zr` building blocks are `fp` here (`../fp`).

This copy lasts until the library moves to its own repository; until then,
change it in Forkpoint first and copy it here.
