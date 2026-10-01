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
| `cmake/` | `lwip_rust_apply()`, which swaps modules into a CMake lwIP target, the configuration probe, and `lwip_forkpoint_apply()`, which reports assertions to Forkpoint |
| `esp-idf/lwip/` | ESP-IDF's `lwip` component, built from this tree with Rust modules |
| `third_party/forkpoint-sdk/` | Forkpoint's firmware SDK, through which C and Rust report assertions as properties |
| `third_party/fp/` | Zero-dependency `no_std` building blocks (`static_assert!`) |
| `third_party/rivet/` | Rivet's C library, which the Rust modules take everything they need from a C library from |
| `test/unit/` | lwIP's own unit tests, run against the Rust modules |

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
| `dhcp` | `src/core/ipv4/dhcp.c` | `dhcp` |
| `dns` | `src/core/dns.c` | `dns` |
| `tcp` | `src/core/tcp.c` | `tcp` |
| `tcp_out` | `src/core/tcp_out.c` | `tcp_out` |
| `tcp_in` | `src/core/tcp_in.c` | `tcp_in` |
| `timeouts` | `src/core/timeouts.c` | `timeouts` |

`mem` and `memp` are ported for the configuration ESP-IDF uses, where lwIP's heap
is the C library's allocator and each pool allocates from it; `build.rs`
refuses lwIP's own heap and static pools. `memp.rs`'s pool descriptors are
generated from the configuration's `memp_std.h`, as `memp.c` declares them.
With `MEM_STATS` and `MEMP_STATS`, both keep their statistics in `lwip_stats`
as the C files do; no module counts the protocols' statistics, and `build.rs`
refuses a configuration that has a ported module count them.
`netif`, `ethernet`, `etharp`, `ip4`, `ip4_frag`, `icmp`, `udp`, `dns`, `dhcp`,
`tcp`, `tcp_out`, `tcp_in`, and `timeouts` are ported as ESP-IDF configures
them; `build.rs` lists the options each requires and refuses a configuration
that selects code they do not port. A module calls a neighbor that is still C through the C symbol
(`lwip/src/links.rs`), so any subset can be built.

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
`-DLWIP_RUST_MODULES="def;inet_chksum;ip4_addr;mem;memp;pbuf;netif;ethernet;etharp;ip4;ip4_frag;icmp;udp;dns;dhcp;tcp;tcp_out;tcp_in;timeouts"`
and, if cargo is not on `PATH`, `-DLWIP_RUST_CARGO=<cargo>`. The Rust target is
`riscv32imafc-unknown-none-elf` (`rv32imafc`, `ilp32f`); set `LWIP_RUST_TARGET`
for another.

The build hands the C stack one relocatable object whose only global symbols
are the lwIP C symbols the modules define. The Rust runtime, compiler builtins,
and C library inside it are local, so the C stack keeps binding to its own C
library and libgcc.

## Forkpoint properties

Configure the project with `-DLWIP_FORKPOINT_HOSTCALL_BASE=<address>`, the
address of the board's Forkpoint hostcall device (`0xa0000000` on the boards
that carry one), and every lwIP assertion becomes a
[Forkpoint](https://github.com/misttech/forkpoint) property as well: a claim
that the assertion never fails, which Forkpoint judges after each run. The C
files are compiled with `LWIP_FORKPOINT` (`src/include/lwip/debug.h`), and the
Rust modules with their `forkpoint` feature (`lwip_assert!` in
`lwip/src/platform.rs`). Both report through the Forkpoint SDK in
`third_party/forkpoint-sdk`. A property is named by the assertion's message,
so a C file and the Rust module that replaces it report the same properties: a
run of the all-C build and a run with the Rust modules must reach the same
properties, the same number of times. Since every `LWIP_ASSERT` becomes an
`lwip_assert!`, the two images also carry the same messages.

With `-DLWIP_FORKPOINT_COVERAGE=ON` as well, edge paths are properties too:
each claims that some run takes it, such as a retransmission timeout, an
out-of-sequence segment, a packet queued on an unresolved ARP entry, or a DHCP
lease renewal. The C files mark them with `LWIP_SOMETIMES(message, condition)`
(`LWIP_FORKPOINT_COVERAGE`), and the Rust modules with `lwip_sometimes!` (the
`forkpoint-coverage` feature), on the same paths with the same messages, so the
two also report the same coverage. A single run takes only some of these paths;
the rest are for exploring many runs. Without the option the markers compile to
nothing, their conditions included.

The SDK also records each assertion in the image's `.fpt_catalog` section,
which `cmake/lwip-forkpoint-catalog.ld` keeps in the ELF and out of target
memory; `fpt catalog` lists it. The properties follow `LWIP_ASSERT`: a build
with `LWIP_NOASSERT` reports none. Without the option nothing changes.

## Host checks

```bash
cargo fmt --all --check
cargo clippy --all-features --all-targets -- -D warnings
cargo test --all-features
FPT_HOSTCALL_BASE=0xa0000000 \
  cargo build -p lwip --all-features --target riscv32imafc-unknown-none-elf --release
```

`--all-features` includes `forkpoint`, whose firmware build needs the hostcall
device's address. A host build only writes the catalog.

## lwIP's unit tests

`test/unit/run.sh` runs lwIP's own C unit tests (`../test/unit`) against the
Rust modules. It builds them twice, as `contrib/ports/unix/check` does, once all
C and once with every ported module (or those in `LWIP_RUST_MODULES`) in place
of its C file, and fails unless each test has the same result in both: the same
pass, or the same failure with the same message.

```bash
test/unit/run.sh                 # builds under target/unittests
```

Both builds use `test/unit/lwipopts.h`: the tests' own options, with every
option the modules port only one way set as ESP-IDF sets it (the C library's
allocator, source routing, single-pbuf transmission, and so on), and with the
heap and pool statistics the tests check for leaks. A few tests expect lwIP's
defaults for those options instead, and fail in the all-C build too;
`test/unit/expected-failures.txt` lists each with the option it expects
otherwise, and `run.sh` also fails if the all-C build fails any other test.
The upstream tests are adapted where these options kept them from building or
checking: `test_pbuf.c`'s 64 KiB split tests are left out without window
scaling, and `test_ip4.c`'s reassembly test without reassembly; files that
required protocol statistics they never read no longer do; the leak check
leaves out the heap that skipped pools hold when pools allocate from the heap;
`esp_platform_hooks.c` builds with `LWIP_NETIF_HOSTNAME`; and `test_tcp_oos.c`'s
out-of-sequence pbuf limit test, which lwIP's own test options leave out, builds
again.

The script needs cmake, ninja, a C compiler, cargo, and the check library
(`apt install check`, or `CMAKE_PREFIX_PATH` naming where it is installed).

