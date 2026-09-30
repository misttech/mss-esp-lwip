# rivet-libc

Rivet's freestanding C library, which the lwIP Rust modules take everything
they need from a C library from (`strlen`, `memmove`, `atoi`, the `ctype.h`
classification, `abort`, and the `assert` failure path) instead of the
firmware's newlib.

- Source: https://github.com/misttech/rivet, `src/lib/libc`, revision
  `b5b21b3e4be01828220429bf693811f2f281f59b`.
- Local change: rivet's `zr` building blocks are `fp` here (`../fp`), and
  the files are formatted with this tree's rustfmt settings.

Change the library in rivet first, with its tests, then copy it here and update
the revision above.
