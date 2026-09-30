# Unsafe budget

`unsafe` in the firmware code of each module, tests excluded: `unsafe` blocks,
and `unsafe fn` items, which include `unsafe extern "C"` declarations and
function-pointer types. It is the safety metric of this port: each count should
stay at the FFI edge, where a C caller hands over raw pointers, and fall as more
of the stack moves to Rust and those pointers become references.

| Module | `unsafe` blocks | `unsafe fn` | `unsafe impl` | What it covers |
|---|---:|---:|---:|---|
| `cstr` | 2 | 3 | 0 | Reading C strings of unknown length |
| `types` | 7 | 12 | 0 | Pbuf payloads and chains; the `ip_addr_t` union; C callback types |
| `platform` | 1 | 0 | 0 | Calling the C library's `__assert_func` |
| `sys` | 2 | 0 | 0 | The port's critical section |
| `global` | 2 | 0 | 1 | lwIP's global variables, laid out as C's |
| `links` | 5 | 3 | 0 | Calls between modules, Rust or C (the macros expand to one wrapper per function) |
| `def` | 12 | 10 | 0 | The C string functions' pointer arguments |
| `inet_chksum` | 19 | 12 | 0 | Buffers and pbuf chains from C callers |
| `ip4_addr` | 10 | 6 | 1 | C strings and buffers; `ip4addr_ntoa`'s static buffer |
| `mem` | 6 | 3 | 0 | The C library's allocator |
| `memp` | 10 | 4 | 0 | Pool descriptors and elements from C callers |
| `pbuf` | 48 | 37 | 0 | Pbuf chains the C stack allocates, links, and frees; `tcp_pcb` until tcp.c is ported |
| `netif` | 39 | 38 | 0 | Netifs, addresses, and callbacks C registers; the loopback queue |
| `ethernet` | 2 | 2 | 0 | Frames in C pbufs; the driver's `linkoutput` |
| `etharp` | 26 | 17 | 0 | The ARP table C holds pointers into; packed ARP headers in C pbufs |

`pbuf` and `netif` are the largest: every pbuf and netif is shared with C, which holds raw pointers to
it, so each field access is a raw place access under the module's one safety
contract (see its documentation). It shrinks as the modules that hold pbufs
(`netif`, `ip4`, `udp`, `tcp`) are ported and can pass references instead.
