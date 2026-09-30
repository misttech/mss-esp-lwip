# Unsafe budget

`unsafe` in the firmware code of each module, tests excluded: `unsafe` blocks,
and `unsafe fn` items, which include `unsafe extern "C"` declarations and
function-pointer types. It is the safety metric of this port: each count should
stay at the FFI edge, where a C caller hands over raw pointers, and fall as more
of the stack moves to Rust and those pointers become references.

| Module | `unsafe` blocks | `unsafe fn` | `unsafe impl` | What it covers |
|---|---:|---:|---:|---|
| `cstr` | 2 | 3 | 0 | Reading C strings of unknown length |
| `types` | 7 | 21 | 0 | Pbuf payloads and chains; the `ip_addr_t` union; C callback types |
| `platform` | 3 | 0 | 0 | Calling the C library's `__assert_func`; a host build's panic handler writing to standard error |
| `sys` | 2 | 0 | 0 | The port's critical section |
| `global` | 2 | 0 | 1 | lwIP's global variables, laid out as C's |
| `stats` | 2 | 1 | 0 | `lwip_stats`, which stats.c defines, at the offsets the configuration lists |
| `links` | 16 | 4 | 0 | Calls between modules, Rust or C (the macros expand to one wrapper per function) |
| `def` | 12 | 10 | 0 | The C string functions' pointer arguments |
| `inet_chksum` | 19 | 12 | 0 | Buffers and pbuf chains from C callers |
| `ip4_addr` | 10 | 6 | 1 | C strings and buffers; `ip4addr_ntoa`'s static buffer |
| `mem` | 8 | 3 | 0 | The C library's allocator; the size header the statistics keep before each block |
| `memp` | 13 | 6 | 1 | Pool descriptors and elements from C callers; each pool's statistics |
| `pbuf` | 48 | 37 | 0 | Pbuf chains the C stack allocates, links, and frees |
| `netif` | 39 | 38 | 0 | Netifs, addresses, and callbacks C registers; the loopback queue |
| `ethernet` | 2 | 2 | 0 | Frames in C pbufs; the driver's `linkoutput` |
| `etharp` | 26 | 17 | 0 | The ARP table C holds pointers into; packed ARP headers in C pbufs |
| `ip4` | 11 | 11 | 0 | Packets and netifs from C; `ip_data`, which ip.c owns; packed IP headers |
| `ip4_frag` | 1 | 1 | 0 | The datagram and its fragments' headers |
| `icmp` | 3 | 3 | 0 | Echo and unreachable messages built in C pbufs |
| `udp` | 18 | 14 | 0 | PCBs on the list C holds; datagrams in C pbufs; receive callbacks |
| `dhcp` | 49 | 44 | 0 | Netifs and their `struct dhcp`, which C reads; messages built and parsed in C pbufs |
| `tcp` | 67 | 54 | 1 | PCB lists and callbacks C shares; timers walking lists callbacks may change; the list-head array |
| `tcp_out` | 36 | 36 | 0 | PCBs and segment queues C shares; headers built in C pbufs |
| `tcp_in` | 36 | 34 | 0 | Segments in C pbufs and their headers; PCB lists and callbacks C shares; the out-of-sequence queue |
| `timeouts` | 15 | 3 | 0 | The timeout list's elements, from the pool C shares; handlers and cyclic timers called through C function pointers |
| `dns` | 29 | 21 | 0 | Host names and addresses from C callers; the tables found callbacks may re-enter; responses in C pbufs |

`pbuf` and `netif` are the largest: every pbuf and netif is shared with C, which holds raw pointers to
it, so each field access is a raw place access under the module's one safety
contract (see its documentation). It shrinks as the modules that hold pbufs
(`netif`, `ip4`, `udp`, `tcp`) are ported and can pass references instead.
