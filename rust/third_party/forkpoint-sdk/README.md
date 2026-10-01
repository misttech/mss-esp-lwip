# Forkpoint SDK

The Forkpoint firmware SDK, through which lwIP reports its assertions to
Forkpoint's emulator as properties: the Rust crate `forkpoint` for the
`lwip` crate's `forkpoint` feature, and the C header
`include/forkpoint/hostcall.h` for the C files built with `LWIP_FORKPOINT`
(see `../../README.md`). Without them neither is used.

- Source: https://github.com/misttech/forkpoint, `sdk/rust/forkpoint`
  (`src/`, `Cargo.toml`) and `sdk/c/include/forkpoint/hostcall.h`, revision
  `4b0cd8ca4a56d0402cd78864893eb489252ecf94`.
- License: Mist Tecnologia LTDA.
- Local changes: `Cargo.toml` calls the package `lwip-forkpoint-sdk`, so
  firmware that also depends on Forkpoint's own copy has two distinct packages
  rather than two named `forkpoint`, and sets the edition, version, and
  `publish` itself: it is kept out of this tree's workspace, whose
  `--all-features` would turn on probes for the host. The Rust files are
  formatted with this tree's rustfmt settings.

To refresh it, copy those files from one Forkpoint revision, keep the local
changes, and update the revision above.
