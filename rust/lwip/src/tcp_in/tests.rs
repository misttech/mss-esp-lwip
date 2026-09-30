// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! lwIP's TCP unit tests, test/unit/tcp, on the Rust TCP: `helper` is tcp_helper.c, and
//! each module one test file.
//!
//! The tests were written for lwIP's unit-test configuration, not ESP-IDF's. Where the
//! difference matters they run as that configuration would: segments are that
//! configuration's TCP_MSS of 536 bytes (set on each PCB, as the tests already do), and
//! each PCB gets its 12 * 536-byte send buffer, since test_tcp.c requires one larger
//! than the window. Counts that follow from the RTO or the out-of-sequence limits are
//! computed from ESP-IDF's values.

mod helper;
mod test_tcp;
