// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! Everything firmware usually needs: `use forkpoint::prelude::*;`.

pub use crate::assert::{AssertType, assert_raw};
pub use crate::lifecycle::{send_event, setup_complete};
pub use crate::random::{ForkpointRng, get_random, random_choice};
pub use crate::{
    assert_always, assert_always_greater_than, assert_always_greater_than_or_equal_to,
    assert_always_less_than, assert_always_less_than_or_equal_to, assert_always_or_unreachable,
    assert_always_some, assert_reachable, assert_sometimes, assert_sometimes_all,
    assert_sometimes_greater_than, assert_sometimes_greater_than_or_equal_to,
    assert_sometimes_less_than, assert_sometimes_less_than_or_equal_to, assert_unreachable,
};
