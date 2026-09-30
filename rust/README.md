# lwIP in Rust

A memory-safe port of this lwIP tree, module by module. Each ported C file
becomes a Rust module that exports the same C symbols, so a firmware build drops
the C file and links the module in its place; the rest of the stack stays C and
does not change. Forkpoint runs the same firmware with C and with Rust modules
and checks, with `fpt equiv`, that what an observer sees (the console and every
Ethernet frame) is identical.

| Directory | Contents |
|---|---|
| `lwip/` | The `lwip` crate: one module per ported C file, and the `#[repr(C)]` mirrors of the structs they share with C |
| `cmake/` | `lwip_rust_apply()`, which swaps modules into a CMake lwIP target, and the configuration probe |
| `esp-idf/lwip/` | ESP-IDF's `lwip` component, built from this tree with Rust modules |
| `third_party/fp/` | Zero-dependency `no_std` building blocks (`static_assert!`) |
| `third_party/libc/` | Forkpoint's C library, which the Rust modules take everything they need from a C library from |

See `PORTING.md` for how a module is ported and `UNSAFE.md` for the `unsafe`
count per module.

## Ported modules

| Module | C file | Feature |
|---|---|---|
| `def` | `src/core/def.c` | `def` |
| `inet_chksum` | `src/core/inet_chksum.c` | `inet_chksum` |
| `ip4_addr` | `src/core/ipv4/ip4_addr.c` | `ip4_addr` |
| `mem` | `src/core/mem.c` (`MEM_LIBC_MALLOC`) | `mem` |
| `memp` | `src/core/memp.c` (`MEMP_MEM_MALLOC`) | `memp` |
| `pbuf` | `src/core/pbuf.c` | `pbuf` |
| `netif` | `src/core/netif.c` | `netif` |
| `ethernet` | `src/netif/ethernet.c` | `ethernet` |
| `etharp` | `src/core/ipv4/etharp.c` | `etharp` |
| `ip4` | `src/core/ipv4/ip4.c` | `ip4` |
| `ip4_frag` | `src/core/ipv4/ip4_frag.c` (fragmentation; no reassembly) | `ip4_frag` |
| `icmp` | `src/core/ipv4/icmp.c` | `icmp` |
| `udp` | `src/core/udp.c` | `udp` |
| `dns` | `src/core/dns.c` | `dns` |

`mem` and `memp` are ported for the configuration ESP-IDF uses, where lwIP's heap
is the C library's allocator and each pool allocates from it; `build.rs`
refuses lwIP's own heap and static pools. `memp.rs`'s pool descriptors are
generated from the configuration's `memp_std.h`, as `memp.c` declares them.
`netif`, `ethernet`, `etharp`, `ip4`, `ip4_frag`, `icmp`, `udp`, and `dns` are
ported as ESP-IDF configures them; `build.rs` lists the options each requires
and refuses a configuration that selects code they do not port. A module calls a
neighbor that is still C through the C symbol (`lwip/src/links.rs`), so any
subset can be built.

## Configuration

The crate is built for one lwIP configuration: the one the C stack it joins is
compiled with. The firmware build compiles `cmake/lwip_rust_config.c` to
assembly with the C stack's own compiler and flags, and `lwip/build.rs` reads
the options, offsets, and sizes it lists. Every mirrored struct is checked
against them at compile time, so a configuration the mirrors do not match fails
the build, not the firmware. Without it, as in host tests, the options are
ESP-IDF v6.1's defaults.

## Building into ESP-IDF

Make a component directory named `lwip` that overrides ESP-IDF's (through
`EXTRA_COMPONENT_DIRS`, for instance) and holds:

- `CMakeLists.txt`, a link to `esp-idf/lwip/CMakeLists.txt`;
- `lwip`, a link to this tree;
- `apps`, `include`, `port`, `Kconfig`, `linker.lf`, and `sdkconfig.rename`,
  links to ESP-IDF's `components/lwip` entries.

Then configure the project with
`-DLWIP_RUST_MODULES="def;inet_chksum;ip4_addr;mem;memp;pbuf;netif;ethernet;etharp;ip4;ip4_frag;icmp;udp;dns"`
and, if cargo is not on `PATH`, `-DLWIP_RUST_CARGO=<cargo>`. The Rust target is
`riscv32imafc-unknown-none-elf` (`rv32imafc`, `ilp32f`); set `LWIP_RUST_TARGET`
for another.

The build hands the C stack one relocatable object whose only global symbols
are the lwIP C symbols the modules define. The Rust runtime, compiler builtins,
and C library inside it are local, so the C stack keeps binding to its own C
library and libgcc.

## Host checks

```bash
cargo fmt --all --check
cargo clippy --all-features --all-targets -- -D warnings
cargo test --all-features
cargo build -p lwip --all-features --target riscv32imafc-unknown-none-elf --release
```
