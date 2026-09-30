# forkpoint-libc

Forkpoint's freestanding C library, which the lwIP Rust modules take everything
they need from a C library from (`strlen`, `memmove`, `atoi`, the `ctype.h`
classification, `abort`, and the `assert` failure path) instead of the
firmware's newlib.

- Source: Forkpoint `src/lib/libc`, revision `5a7883c760055016ee1f9ce091368844bf0fa09b`.
- Local change: the `zr` building blocks are `fp` here (`../fp`).

This copy lasts until the library moves to its own repository; until then,
change it in Forkpoint first and copy it here.
