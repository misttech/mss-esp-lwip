// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! Property assertions. Each reports one probe to the hostcall device, whose id is the
//! FNV-1a hash of the assertion's message; the explorer records it and does not steer on it
//! yet.
//!
//! Every call site is also recorded in the image's assertion [catalog](crate::catalog),
//! with the `catalog` feature, which `enabled` implies. Without the `enabled` feature an
//! assertion still evaluates its condition, so side effects and lints do not differ
//! between builds, but it reports nothing: [`probe`] compiles out.

use crate::hostcall::probe;

/// Property probe kinds. Firmware that picks its own kinds should stay below
/// this range.
pub const KIND_ALWAYS: u32 = 0x4650_5401;
pub const KIND_SOMETIMES: u32 = 0x4650_5402;
pub const KIND_UNREACHABLE: u32 = 0x4650_5403;
pub const KIND_REACHABLE: u32 = 0x4650_5404;
/// Guidance, reported after a numeric assertion's own probe with the same id: `left -
/// right` as an `i64`'s bits, saturated. The explorer records it; steering on it is later
/// work.
pub const KIND_GUIDANCE_NUMERIC: u32 = 0x4650_5405;
/// Guidance, reported after `assert_sometimes_all!` or `assert_always_some!`: a bitmask of
/// which named propositions held, the first in bit 0.
pub const KIND_GUIDANCE_BOOLEAN: u32 = 0x4650_5406;
/// An assertion's `details`, reported after its own probe with the same id.
pub const KIND_DETAILS: u32 = 0x4650_5407;

/// FNV-1a 64 of `message`. The C SDK's `fpt_message_id` computes the same value,
/// so a property's probe id does not depend on where the string was placed.
pub const fn message_id(message: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let bytes = message.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        index += 1;
    }
    hash
}

/// What an assertion claims. With `must_hit`, the assertion must also be reached at
/// least once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssertType {
    /// The condition holds every time the assertion is reached.
    Always,
    /// The condition holds at least once.
    Sometimes,
    /// Reaching the assertion is what matters: it must be (`must_hit`), or must not be.
    Reachability,
}

/// The probe an assertion reports, as `(kind, value)`.
pub const fn assertion_probe(
    assert_type: AssertType,
    must_hit: bool,
    condition: bool,
) -> (u32, u64) {
    match (assert_type, must_hit) {
        (AssertType::Always, true) => (KIND_ALWAYS, condition as u64),
        // Always or unreachable: a false condition is reported as a reach of a place
        // that must not be reached.
        (AssertType::Always, false) if condition => (KIND_ALWAYS, 1),
        (AssertType::Always, false) => (KIND_UNREACHABLE, 0),
        (AssertType::Sometimes, _) => (KIND_SOMETIMES, condition as u64),
        (AssertType::Reachability, true) => (KIND_REACHABLE, 1),
        (AssertType::Reachability, false) => (KIND_UNREACHABLE, 1),
    }
}

/// Report an assertion a framework builds at run time, whose message need not be a
/// constant. The macros are the usual way to assert.
pub fn assert_raw(condition: bool, message: &str, assert_type: AssertType, must_hit: bool) {
    report(message_id(message), assert_type, must_hit, condition);
}

#[doc(hidden)]
#[inline]
pub fn report(id: u64, assert_type: AssertType, must_hit: bool, condition: bool) {
    let (kind, value) = assertion_probe(assert_type, must_hit, condition);
    probe(kind, id, value);
}

#[doc(hidden)]
#[inline]
pub fn report_details(id: u64, details: u64) {
    probe(KIND_DETAILS, id, details);
}

#[doc(hidden)]
#[inline]
pub fn report_numeric(id: u64, difference: i64) {
    probe(KIND_GUIDANCE_NUMERIC, id, difference as u64);
}

#[doc(hidden)]
#[inline]
pub fn report_boolean(id: u64, held: &[bool]) {
    probe(KIND_GUIDANCE_BOOLEAN, id, held_mask(held));
}

/// Which of `held` are true, the first in bit 0. Only the first 64 fit.
pub const fn held_mask(held: &[bool]) -> u64 {
    let mut mask = 0u64;
    let mut index = 0;
    while index < held.len() && index < 64 {
        if held[index] {
            mask |= 1 << index;
        }
        index += 1;
    }
    mask
}

/// A value a numeric assertion compares, and how far apart two are, for guidance.
pub trait Guidance: Copy + PartialOrd {
    /// `self - other`, saturated to an `i64`.
    fn difference(self, other: Self) -> i64;
}

macro_rules! integer_guidance {
    ($($t:ty),*) => {$(
        impl Guidance for $t {
            fn difference(self, other: Self) -> i64 {
                let wide = self as i128 - other as i128;
                wide.clamp(i64::MIN as i128, i64::MAX as i128) as i64
            }
        }
    )*};
}
integer_guidance!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

impl Guidance for f32 {
    fn difference(self, other: Self) -> i64 {
        f64::from(self).difference(f64::from(other))
    }
}

impl Guidance for f64 {
    fn difference(self, other: Self) -> i64 {
        // A float cast saturates, and NaN becomes 0.
        (self - other) as i64
    }
}

/// A value an assertion's `details` can carry: an integer or a `bool`, as its bits. There
/// is no serializer on an MCU; the rest of the context comes from replaying the trace.
pub trait IntoDetails {
    fn into_details(self) -> u64;
}

macro_rules! integer_details {
    ($($t:ty),*) => {$(
        impl IntoDetails for $t {
            fn into_details(self) -> u64 {
                self as u64
            }
        }
    )*};
}
integer_details!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

impl IntoDetails for bool {
    fn into_details(self) -> u64 {
        u64::from(self)
    }
}

/// The condition holds every time this is reached, and it is reached at least once.
#[macro_export]
macro_rules! assert_always {
    ($condition:expr, $message:expr $(, $details:expr)? $(,)?) => {{
        $crate::__catalog!(Always, $message);
        const ID: u64 = $crate::message_id($message);
        let condition: bool = $condition;
        $crate::assert::report(ID, $crate::assert::AssertType::Always, true, condition);
        $($crate::assert::report_details(ID, $crate::assert::IntoDetails::into_details($details));)?
    }};
}

/// The condition holds every time this is reached, which it need not be.
#[macro_export]
macro_rules! assert_always_or_unreachable {
    ($condition:expr, $message:expr $(, $details:expr)? $(,)?) => {{
        $crate::__catalog!(AlwaysOrUnreachable, $message);
        const ID: u64 = $crate::message_id($message);
        let condition: bool = $condition;
        $crate::assert::report(ID, $crate::assert::AssertType::Always, false, condition);
        $($crate::assert::report_details(ID, $crate::assert::IntoDetails::into_details($details));)?
    }};
}

/// The condition holds at least once when this is reached.
#[macro_export]
macro_rules! assert_sometimes {
    ($condition:expr, $message:expr $(, $details:expr)? $(,)?) => {{
        $crate::__catalog!(Sometimes, $message);
        const ID: u64 = $crate::message_id($message);
        let condition: bool = $condition;
        $crate::assert::report(ID, $crate::assert::AssertType::Sometimes, true, condition);
        $($crate::assert::report_details(ID, $crate::assert::IntoDetails::into_details($details));)?
    }};
}

/// This is reached at least once.
#[macro_export]
macro_rules! assert_reachable {
    ($message:expr $(, $details:expr)? $(,)?) => {{
        $crate::__catalog!(Reachable, $message);
        const ID: u64 = $crate::message_id($message);
        $crate::assert::report(ID, $crate::assert::AssertType::Reachability, true, true);
        $($crate::assert::report_details(ID, $crate::assert::IntoDetails::into_details($details));)?
    }};
}

/// This is never reached.
#[macro_export]
macro_rules! assert_unreachable {
    ($message:expr $(, $details:expr)? $(,)?) => {{
        $crate::__catalog!(Unreachable, $message);
        const ID: u64 = $crate::message_id($message);
        $crate::assert::report(ID, $crate::assert::AssertType::Reachability, false, false);
        $($crate::assert::report_details(ID, $crate::assert::IntoDetails::into_details($details));)?
    }};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __assert_numeric {
    ($catalog:ident, $assert_type:ident, $op:tt, $left:expr, $right:expr, $message:expr $(, $details:expr)?) => {{
        $crate::__catalog!($catalog, $message);
        const ID: u64 = $crate::message_id($message);
        let (left, right) = ($left, $right);
        let condition: bool = left $op right;
        $crate::assert::report(ID, $crate::assert::AssertType::$assert_type, true, condition);
        $crate::assert::report_numeric(ID, $crate::assert::Guidance::difference(left, right));
        $($crate::assert::report_details(ID, $crate::assert::IntoDetails::into_details($details));)?
    }};
}

/// `left` is greater than `right` every time this is reached, and it is reached at least once. Also reports `left - right` as
/// guidance ([`KIND_GUIDANCE_NUMERIC`]).
#[macro_export]
macro_rules! assert_always_greater_than {
    ($left:expr, $right:expr, $message:expr $(, $details:expr)? $(,)?) => {
        $crate::__assert_numeric!(Always, Always, >, $left, $right, $message $(, $details)?)
    };
}

/// `left` is at least `right` every time this is reached, and it is reached at least once. Also reports `left - right` as
/// guidance ([`KIND_GUIDANCE_NUMERIC`]).
#[macro_export]
macro_rules! assert_always_greater_than_or_equal_to {
    ($left:expr, $right:expr, $message:expr $(, $details:expr)? $(,)?) => {
        $crate::__assert_numeric!(Always, Always, >=, $left, $right, $message $(, $details)?)
    };
}

/// `left` is less than `right` every time this is reached, and it is reached at least once. Also reports `left - right` as
/// guidance ([`KIND_GUIDANCE_NUMERIC`]).
#[macro_export]
macro_rules! assert_always_less_than {
    ($left:expr, $right:expr, $message:expr $(, $details:expr)? $(,)?) => {
        $crate::__assert_numeric!(Always, Always, <, $left, $right, $message $(, $details)?)
    };
}

/// `left` is at most `right` every time this is reached, and it is reached at least once. Also reports `left - right` as
/// guidance ([`KIND_GUIDANCE_NUMERIC`]).
#[macro_export]
macro_rules! assert_always_less_than_or_equal_to {
    ($left:expr, $right:expr, $message:expr $(, $details:expr)? $(,)?) => {
        $crate::__assert_numeric!(Always, Always, <=, $left, $right, $message $(, $details)?)
    };
}

/// `left` is greater than `right` at least once when this is reached. Also reports `left - right` as
/// guidance ([`KIND_GUIDANCE_NUMERIC`]).
#[macro_export]
macro_rules! assert_sometimes_greater_than {
    ($left:expr, $right:expr, $message:expr $(, $details:expr)? $(,)?) => {
        $crate::__assert_numeric!(Sometimes, Sometimes, >, $left, $right, $message $(, $details)?)
    };
}

/// `left` is at least `right` at least once when this is reached. Also reports `left - right` as
/// guidance ([`KIND_GUIDANCE_NUMERIC`]).
#[macro_export]
macro_rules! assert_sometimes_greater_than_or_equal_to {
    ($left:expr, $right:expr, $message:expr $(, $details:expr)? $(,)?) => {
        $crate::__assert_numeric!(Sometimes, Sometimes, >=, $left, $right, $message $(, $details)?)
    };
}

/// `left` is less than `right` at least once when this is reached. Also reports `left - right` as
/// guidance ([`KIND_GUIDANCE_NUMERIC`]).
#[macro_export]
macro_rules! assert_sometimes_less_than {
    ($left:expr, $right:expr, $message:expr $(, $details:expr)? $(,)?) => {
        $crate::__assert_numeric!(Sometimes, Sometimes, <, $left, $right, $message $(, $details)?)
    };
}

/// `left` is at most `right` at least once when this is reached. Also reports `left - right` as
/// guidance ([`KIND_GUIDANCE_NUMERIC`]).
#[macro_export]
macro_rules! assert_sometimes_less_than_or_equal_to {
    ($left:expr, $right:expr, $message:expr $(, $details:expr)? $(,)?) => {
        $crate::__assert_numeric!(Sometimes, Sometimes, <=, $left, $right, $message $(, $details)?)
    };
}

/// Every named proposition holds at least once, together, when this is reached. Each is
/// evaluated, none short-circuits, and which held is reported as guidance
/// ([`KIND_GUIDANCE_BOOLEAN`]). The names document the propositions; the catalog does not
/// record them.
#[macro_export]
macro_rules! assert_sometimes_all {
    ({ $($name:ident : $value:expr),+ $(,)? }, $message:expr $(, $details:expr)? $(,)?) => {{
        $crate::__catalog!(Sometimes, $message);
        const ID: u64 = $crate::message_id($message);
        let held = [$({ let $name: bool = $value; $name }),+];
        $crate::assert::report(ID, $crate::assert::AssertType::Sometimes, true, held.iter().all(|held| *held));
        $crate::assert::report_boolean(ID, &held);
        $($crate::assert::report_details(ID, $crate::assert::IntoDetails::into_details($details));)?
    }};
}

/// At least one named proposition holds every time this is reached, and it is reached at
/// least once. Each is evaluated, and which held is reported as guidance.
#[macro_export]
macro_rules! assert_always_some {
    ({ $($name:ident : $value:expr),+ $(,)? }, $message:expr $(, $details:expr)? $(,)?) => {{
        $crate::__catalog!(Always, $message);
        const ID: u64 = $crate::message_id($message);
        let held = [$({ let $name: bool = $value; $name }),+];
        $crate::assert::report(ID, $crate::assert::AssertType::Always, true, held.iter().any(|held| *held));
        $crate::assert::report_boolean(ID, &held);
        $($crate::assert::report_details(ID, $crate::assert::IntoDetails::into_details($details));)?
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn message_id_matches_the_c_sdk() {
        assert_eq!(message_id("hello"), 0xa430_d846_80aa_bd0b);
        assert_eq!(message_id("mie-kept"), 0xc5fd_b2f4_b511_0731);
        assert_eq!(message_id(""), 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn each_assertion_reports_the_probe_the_c_sdk_does() {
        use AssertType::*;
        assert_eq!(assertion_probe(Always, true, false), (KIND_ALWAYS, 0));
        assert_eq!(assertion_probe(Always, true, true), (KIND_ALWAYS, 1));
        assert_eq!(assertion_probe(Always, false, true), (KIND_ALWAYS, 1));
        assert_eq!(assertion_probe(Always, false, false), (KIND_UNREACHABLE, 0));
        assert_eq!(assertion_probe(Sometimes, true, true), (KIND_SOMETIMES, 1));
        assert_eq!(
            assertion_probe(Reachability, true, true),
            (KIND_REACHABLE, 1)
        );
        assert_eq!(
            assertion_probe(Reachability, false, false),
            (KIND_UNREACHABLE, 1)
        );
    }

    #[test]
    fn guidance_is_the_saturated_difference() {
        assert_eq!(7u8.difference(9), -2);
        assert_eq!(u64::MAX.difference(0), i64::MAX);
        assert_eq!(i64::MIN.difference(1), i64::MIN);
        assert_eq!(2.5f32.difference(0.5), 2);
        assert_eq!(f64::NAN.difference(1.0), 0);
        assert_eq!(held_mask(&[true, false, true]), 0b101);
        assert_eq!((-1i8).into_details(), u64::MAX);
        assert_eq!(true.into_details(), 1);
    }

    #[test]
    fn numeric_and_named_assertions_evaluate_each_operand_once() {
        let evaluated = Cell::new(0);
        let value = |v: u32| {
            evaluated.set(evaluated.get() + 1);
            v
        };
        crate::assert_always_greater_than!(value(3), value(2), "gt");
        crate::assert_always_greater_than_or_equal_to!(value(3), value(3), "ge", 7u8);
        crate::assert_always_less_than!(value(1), value(2), "lt");
        crate::assert_always_less_than_or_equal_to!(value(2), value(2), "le");
        crate::assert_sometimes_greater_than!(value(1), value(2), "sgt");
        crate::assert_sometimes_greater_than_or_equal_to!(value(1), value(2), "sge");
        crate::assert_sometimes_less_than!(value(1), value(2), "slt");
        crate::assert_sometimes_less_than_or_equal_to!(value(1), value(2), "sle", -1i32);
        assert_eq!(evaluated.get(), 16);
        crate::assert_sometimes_all!({ small: value(1) < 2, even: value(4) % 2 == 0 }, "all");
        crate::assert_always_some!({ a: value(1) == 0, b: value(1) == 1 }, "some", true);
        assert_eq!(evaluated.get(), 20, "no proposition short-circuits");
        crate::assert_always!(value(1) == 1, "with details", 42u64);
        crate::assert_reachable!("reached", 1u8);
    }

    #[test]
    fn a_disabled_build_still_evaluates_every_condition() {
        let evaluated = Cell::new(0);
        let condition = |value| {
            evaluated.set(evaluated.get() + 1);
            value
        };
        crate::assert_always!(condition(false), "always");
        crate::assert_always_or_unreachable!(condition(false), "always or unreachable");
        crate::assert_sometimes!(condition(true), "sometimes");
        crate::assert_reachable!("reachable");
        crate::assert_unreachable!("unreachable");
        assert_raw(condition(true), "raw", AssertType::Sometimes, true);
        assert_eq!(evaluated.get(), 4);
    }
}
