# Porting a module

Ports follow Forkpoint's C-to-Rust rubric. In short:

1. **One C file, one module.** Translate with the same data structures and
   algorithms. Every function the C file defines has a Rust counterpart that
   exports the same symbol with the same signature and semantics, corner cases
   included (a zero length, a too-small buffer, an `INT_MIN`). Keep the
   configuration switches the C file has, as `cfg`s from `build.rs`.
2. **Exact layout.** A struct shared with C is `#[repr(C)]` in `lwip/src/types.rs`,
   field for field under the same options, and each offset and size is added to
   `cmake/lwip_rust_config.c` and checked in `types.rs`'s `layout` module.
3. **Test parity.** Every lwIP `test/unit` case that covers the file becomes a
   Rust test; code without C tests gains tests for its documented behavior and
   edge cases.
4. **No new failure modes.** No allocation beyond lwIP's own pools, no panics on
   paths the C code could not fail on, no overflow the C code did not have.
   `LWIP_ASSERT` becomes `lwip_assert!`, which fails the way the port's
   `LWIP_PLATFORM_ASSERT` does, and `LWIP_SOMETIMES` becomes `lwip_sometimes!`
   on the same path, with the same message.
5. **Safety at the edge.** Raw pointers stay in the `extern "C"` functions, which
   turn them into references and slices once. Every `unsafe` block has a
   `// SAFETY:` comment and every `unsafe fn` a `# Safety` section. Update
   `UNSAFE.md`.
6. **The C library.** Anything a module needs from a C library comes from
   `third_party/rivet`, a copy of rivet's C library. Add what is missing to
   rivet (https://github.com/misttech/rivet) first, with its tests, then copy
   it here.
7. **Documentation.** Keep the C file's comments that document behavior, and its
   license header.
8. **Wiring.** Add the module's feature to `lwip/Cargo.toml` and its C file to
   `LWIP_RUST_FILES` in `cmake/lwip-rust.cmake`.
9. **Equivalence.** In Forkpoint, `make test-esp32-s31-korvo-1-http-request`
   builds the example with the Rust modules and checks it with `fpt equiv`
   against the C build.
