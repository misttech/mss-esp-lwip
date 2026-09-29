# Unsafe budget

`unsafe` in the firmware code of each module, tests excluded: `unsafe` blocks,
and `unsafe fn` items, which include `unsafe extern "C"` declarations and
function-pointer types. It is the safety metric of this port: each count should
stay at the FFI edge, where a C caller hands over raw pointers, and fall as more
of the stack moves to Rust and those pointers become references.

| Module | `unsafe` blocks | `unsafe fn` | `unsafe impl` | What it covers |
|---|---:|---:|---:|---|
| `cstr` | 2 | 3 | 0 | Reading C strings of unknown length |
| `types` | 5 | 4 | 0 | Pbuf payloads and chains; the `ip_addr_t` union |
| `platform` | 1 | 0 | 0 | Calling the C library's `__assert_func` |
| `sys` | 2 | 0 | 0 | The port's critical section |
| `links` | 8 | 5 | 0 | Calls between modules, Rust or C |
| `def` | 12 | 10 | 0 | The C string functions' pointer arguments |
| `inet_chksum` | 19 | 12 | 0 | Buffers and pbuf chains from C callers |
| `ip4_addr` | 10 | 6 | 1 | C strings and buffers; `ip4addr_ntoa`'s static buffer |
| `mem` | 6 | 3 | 0 | The C library's allocator |
| `memp` | 10 | 4 | 0 | Pool descriptors and elements from C callers |
| `pbuf` | 48 | 37 | 0 | Pbuf chains the C stack allocates, links, and frees; `tcp_pcb` until tcp.c is ported |

`pbuf` is the largest: every pbuf is shared with C, which holds raw pointers to
it, so each field access is a raw place access under the module's one safety
contract (see its documentation). It shrinks as the modules that hold pbufs
(`netif`, `ip4`, `udp`, `tcp`) are ported and can pass references instead.
