// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! The hostcall device's register window: its layout, the stores that report a probe,
//! and the interrupt masking that keeps a probe's five stores together.

/// `MAGIC` reads as "FPHC" in memory order.
pub const MAGIC: u32 = u32::from_le_bytes(*b"FPHC");
/// The register layout this crate knows. Version 1 has the probe registers; version 2
/// adds `RANDOM`.
pub const VERSION: u32 = 2;

pub const MAGIC_OFFSET: u32 = 0x00;
pub const VERSION_OFFSET: u32 = 0x04;
pub const ID_LO: u32 = 0x08;
pub const ID_HI: u32 = 0x0c;
pub const VALUE_LO: u32 = 0x10;
pub const VALUE_HI: u32 = 0x14;
pub const KIND: u32 = 0x18;
/// A write draws a value from the machine's seeded source into `RANDOM_LO`/`RANDOM_HI`.
pub const RANDOM: u32 = 0x1c;
pub const RANDOM_LO: u32 = 0x20;
pub const RANDOM_HI: u32 = 0x24;

/// The five stores of one probe, in order: `(offset, value)`.
pub const fn probe_stores(kind: u32, id: u64, value: u64) -> [(u32, u32); 5] {
    [
        (ID_LO, id as u32),
        (ID_HI, (id >> 32) as u32),
        (VALUE_LO, value as u32),
        (VALUE_HI, (value >> 32) as u32),
        (KIND, kind),
    ]
}

/// The layout version of the hostcall device at `FPT_HOSTCALL_BASE`, or 0 when none
/// answers. Always 0 when the `enabled` feature is off.
#[inline]
pub fn hostcall_version() -> u32 {
    #[cfg(feature = "enabled")]
    {
        if load(MAGIC_OFFSET) == MAGIC {
            load(VERSION_OFFSET)
        } else {
            0
        }
    }
    #[cfg(not(feature = "enabled"))]
    {
        0
    }
}

/// Whether the hostcall device answers at `FPT_HOSTCALL_BASE` with probe registers:
/// layout version 1 or later, each of which keeps version 1's registers. Always false
/// when the `enabled` feature is off.
#[inline]
pub fn hostcall_present() -> bool {
    hostcall_version() >= 1
}

/// Draw a value from the machine's seeded source, which needs layout version 2. `None`
/// without one, and always without the `enabled` feature.
#[inline]
pub fn hostcall_random() -> Option<u64> {
    #[cfg(feature = "enabled")]
    {
        if hostcall_version() < 2 {
            return None;
        }
        let mask = mask_interrupts();
        store(RANDOM, 0);
        let value = u64::from(load(RANDOM_HI)) << 32 | u64::from(load(RANDOM_LO));
        unmask_interrupts(mask);
        Some(value)
    }
    #[cfg(not(feature = "enabled"))]
    {
        None
    }
}

/// Report probe `id` with `value`. The host records it in the trace, and
/// `fpt explore --stop-at-probe ID` stops right after the call. What `kind`
/// means is agreed between the firmware and whatever reads the trace.
///
/// A no-op when the `enabled` feature is off.
#[inline]
pub fn probe(kind: u32, id: u64, value: u64) {
    #[cfg(feature = "enabled")]
    {
        let mask = mask_interrupts();
        for (offset, word) in probe_stores(kind, id, value) {
            store(offset, word);
        }
        unmask_interrupts(mask);
    }
    #[cfg(not(feature = "enabled"))]
    {
        let _ = (kind, id, value);
    }
}

#[cfg(feature = "enabled")]
const HOSTCALL_BASE: u32 = match option_env!("FPT_HOSTCALL_BASE") {
    Some(text) => parse_base(text),
    None => panic!("the enabled feature needs FPT_HOSTCALL_BASE, the hostcall device's address"),
};

/// `FPT_HOSTCALL_BASE` as a `u32`: `0x` hex or decimal.
pub const fn parse_base(text: &str) -> u32 {
    let bytes = text.as_bytes();
    let hex = bytes.len() > 2 && bytes[0] == b'0' && (bytes[1] == b'x' || bytes[1] == b'X');
    let radix: u32 = if hex { 16 } else { 10 };
    let mut index = if hex { 2 } else { 0 };
    if index >= bytes.len() {
        panic!("FPT_HOSTCALL_BASE is empty");
    }
    let mut value = 0u32;
    while index < bytes.len() {
        let byte = bytes[index];
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' if radix == 16 => byte - b'a' + 10,
            b'A'..=b'F' if radix == 16 => byte - b'A' + 10,
            _ => panic!("FPT_HOSTCALL_BASE is not an integer"),
        };
        let Some(wide) = value.checked_mul(radix) else {
            panic!("FPT_HOSTCALL_BASE does not fit in 32 bits");
        };
        let Some(next) = wide.checked_add(digit as u32) else {
            panic!("FPT_HOSTCALL_BASE does not fit in 32 bits");
        };
        value = next;
        index += 1;
    }
    value
}

#[cfg(feature = "enabled")]
fn load(offset: u32) -> u32 {
    let address = HOSTCALL_BASE.wrapping_add(offset);
    // SAFETY: `HOSTCALL_BASE` is the hostcall window the board maps for this
    // firmware. The device defines an aligned 32-bit read at `offset`, and the
    // caller passes one of the register offsets in this module.
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

#[cfg(feature = "enabled")]
fn store(offset: u32, value: u32) {
    let address = HOSTCALL_BASE.wrapping_add(offset);
    // SAFETY: same window as `load`. The device defines an aligned 32-bit write
    // at each staged register and at `KIND`.
    unsafe { core::ptr::write_volatile(address as *mut u32, value) }
}

#[cfg(all(feature = "enabled", target_arch = "riscv32"))]
fn mask_interrupts() -> u32 {
    let old: u32;
    // SAFETY: firmware on this hart runs in machine mode, which may clear
    // `mstatus.MIE`. The instruction returns the previous `mstatus`.
    unsafe {
        core::arch::asm!("csrrci {old}, mstatus, 8", old = out(reg) old, options(nostack, preserves_flags));
    }
    old
}

#[cfg(all(feature = "enabled", target_arch = "riscv32"))]
fn unmask_interrupts(mstatus: u32) {
    let mie = mstatus & 8;
    // SAFETY: sets `mstatus.MIE` only when it was set before `mask_interrupts`.
    // A zero register leaves the bit clear.
    unsafe {
        core::arch::asm!("csrs mstatus, {mie}", mie = in(reg) mie, options(nostack, preserves_flags));
    }
}

#[cfg(all(feature = "enabled", target_arch = "arm"))]
fn mask_interrupts() -> u32 {
    let primask: u32;
    // SAFETY: Cortex-M firmware may read and set PRIMASK. `cpsid i` masks
    // interrupts and the previous PRIMASK is returned for `unmask_interrupts`.
    unsafe {
        core::arch::asm!("mrs {primask}, primask", "cpsid i", primask = out(reg) primask, options(nostack, preserves_flags));
    }
    primask
}

#[cfg(all(feature = "enabled", target_arch = "arm"))]
fn unmask_interrupts(primask: u32) {
    // SAFETY: restores the PRIMASK `mask_interrupts` saved, including a mask
    // that was already set.
    unsafe {
        core::arch::asm!("msr primask, {primask}", primask = in(reg) primask, options(nostack, preserves_flags));
    }
}

#[cfg(all(
    feature = "enabled",
    not(any(target_arch = "riscv32", target_arch = "arm"))
))]
compile_error!("the hostcall SDK supports only RISC-V and Cortex-M");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_stores_stage_the_halves_and_finish_with_the_kind() {
        assert_eq!(
            probe_stores(0x4650_5401, 0x1122_3344_5566_7788, u64::MAX),
            [
                (ID_LO, 0x5566_7788),
                (ID_HI, 0x1122_3344),
                (VALUE_LO, 0xffff_ffff),
                (VALUE_HI, 0xffff_ffff),
                (KIND, 0x4650_5401),
            ]
        );
    }

    #[test]
    fn parse_base_accepts_hex_and_decimal() {
        assert_eq!(parse_base("0xa0000000"), 0xa000_0000);
        assert_eq!(parse_base("0xA0000000"), 0xa000_0000);
        assert_eq!(parse_base("16"), 16);
    }

    #[test]
    fn a_disabled_build_finds_no_hostcall_device_and_reports_nothing() {
        assert!(!hostcall_present());
        probe(1, 2, 3);
    }
}
