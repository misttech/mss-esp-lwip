// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! Randomness for firmware. In the Forkpoint machine a value comes from its seeded
//! source through the hostcall device
//! (layout version 2): the run's `--seed` decides it, and a replay or a branch from a
//! snapshot draws it again, so a run that uses randomness still replays exactly.
//!
//! Without such a device, and always without the `enabled` feature, values come from a
//! deterministic xorshift64* fallback, since bare metal has no universal entropy source.
//! Its state is two 32-bit words updated with plain loads and stores, which every target
//! has: concurrent callers may draw the same value, which a fallback can afford.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::hostcall::hostcall_random;

static FALLBACK_LO: AtomicU32 = AtomicU32::new(0x7f4a_7c15);
static FALLBACK_HI: AtomicU32 = AtomicU32::new(0x9e37_79b9);

fn fallback() -> u64 {
    let mut x = u64::from(FALLBACK_HI.load(Ordering::Relaxed)) << 32
        | u64::from(FALLBACK_LO.load(Ordering::Relaxed));
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    FALLBACK_LO.store(x as u32, Ordering::Relaxed);
    FALLBACK_HI.store((x >> 32) as u32, Ordering::Relaxed);
    x.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

/// A random value: from the machine's seeded source when the hostcall device has one,
/// otherwise from the deterministic fallback.
pub fn get_random() -> u64 {
    hostcall_random().unwrap_or_else(fallback)
}

/// A random element of `slice`, or `None` when it is empty.
pub fn random_choice<T>(slice: &[T]) -> Option<&T> {
    if slice.is_empty() {
        return None;
    }
    slice.get((get_random() % slice.len() as u64) as usize)
}

/// A generator over [`get_random`], for code that wants one to hold.
#[derive(Clone, Copy, Debug, Default)]
pub struct ForkpointRng;

impl ForkpointRng {
    pub fn next_u32(&mut self) -> u32 {
        get_random() as u32
    }

    pub fn next_u64(&mut self) -> u64 {
        get_random()
    }

    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            chunk.copy_from_slice(&get_random().to_le_bytes()[..chunk.len()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_a_device_values_come_from_the_fallback_and_vary() {
        let values = [get_random(), get_random(), get_random()];
        assert!(
            values[0] != values[1] && values[1] != values[2],
            "{values:?}"
        );
    }

    #[test]
    fn a_choice_is_an_element_and_an_empty_slice_has_none() {
        let items = [3, 5, 8];
        for _ in 0..16 {
            assert!(items.contains(random_choice(&items).unwrap()));
        }
        assert_eq!(random_choice::<u8>(&[]), None);
    }

    #[test]
    fn fill_bytes_fills_a_length_that_is_not_a_multiple_of_eight() {
        let mut bytes = [0u8; 13];
        ForkpointRng.fill_bytes(&mut bytes);
        assert!(bytes.iter().any(|byte| *byte != 0));
    }
}
