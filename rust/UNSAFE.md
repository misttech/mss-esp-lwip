# Unsafe budget

`unsafe` in the firmware code of each module, tests excluded. It is the safety
metric of this port: each count should stay at the FFI edge, where a C caller
hands over raw pointers, and fall as more of the stack moves to Rust and those
pointers become references.

| Module | `unsafe` blocks | `unsafe fn` | `unsafe impl` | What it covers |
|---|---:|---:|---:|---|
| `cstr` | 2 | 3 | 0 | Reading C strings of unknown length |
| `types` | 5 | 3 | 0 | Pbuf payloads and chains; the `ip_addr_t` union |
| `platform` | 1 | 0 | 0 | Calling the C library's `__assert_func` |
| `def` | 12 | 10 | 0 | The C string functions' pointer arguments |
| `inet_chksum` | 19 | 12 | 0 | Buffers and pbuf chains from C callers |
| `ip4_addr` | 10 | 6 | 1 | C strings and buffers; `ip4addr_ntoa`'s static buffer |
