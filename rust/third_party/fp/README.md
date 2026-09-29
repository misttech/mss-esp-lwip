# fp

Zero-dependency `no_std` building blocks for the lwIP Rust port, the same set
Forkpoint's firmware-facing Rust crates use.

- License: BSD-3-Clause, see `LICENSE`. The module files keep their original
  copyright headers.

| File | Provides |
|---|---|
| `src/static_assert.rs` | `static_assert!`, `static_assert_size_and_align!` |
| `src/lossy_utf8.rs` | `from_utf8_lossy` |

Add a module only when a port needs it, and list it here.
