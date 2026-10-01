// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! Telling the host where the firmware is in its life. Each call is one probe, compiled
//! out without the `enabled` feature.

use crate::assert::message_id;
use crate::hostcall::probe;

/// The probe [`setup_complete`] reports.
pub const KIND_SETUP_COMPLETE: u32 = 0x4650_5408;
/// The probe [`send_event`] reports.
pub const KIND_EVENT: u32 = 0x4650_5409;

/// Setup is over: what runs from here is what is worth exploring. `fpt explore
/// --fork-after-setup` runs to the first call and forks from that state, so exploration
/// skips the boot every branch would share. Only the first call counts.
pub fn setup_complete(details: u64) {
    probe(KIND_SETUP_COMPLETE, 0, details);
}

/// Something happened that a reader of the trace should see, named by a constant `name`
/// (its FNV-1a hash is the probe id, as an assertion's message is) with `details`.
pub fn send_event(name: &'static str, details: u64) {
    probe(KIND_EVENT, message_id(name), details);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disabled_build_reports_nothing_and_does_not_panic() {
        setup_complete(1);
        setup_complete(2);
        send_event("boot", 3);
    }
}
