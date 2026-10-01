// Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

//! The assertion catalog: one record per assertion call site, kept in the firmware
//! image's `.fpt_catalog` section, so the host knows every assertion before a run, the
//! ones no run reaches included. The host reads the section from the ELF (`fpt catalog`)
//! and [`parse`]s it with this module, so writer and reader share one format.
//!
//! A record holds no pointers, so nothing in it is relocated, and firmware linker scripts
//! keep the section out of target memory:
//!
//! ```text
//! .fpt_catalog (INFO) : { KEEP(*(.fpt_catalog)) }
//! ```
//!
//! The macros emit records only with the `catalog` feature, which `enabled` implies. A
//! record is little-endian and 4-byte aligned:
//!
//! ```text
//! 0   magic "FPTA"
//! 4   u32  record length, a multiple of 4
//! 8   u8   AssertionKind, then 3 zero bytes
//! 12  u64  id: the message's FNV-1a hash, the probe id; 0 when the writer could not
//!          hash at compile time (the C SDK), and the reader derives it from the message
//! 20  u32  line
//! 24  u32  column
//! 28  u16  file length, u16 module path length, u16 message length, u16 zero
//! 36  file, module path, and message, as UTF-8, then zeros to the record length
//! ```

use crate::assert::message_id;

/// The section records go to.
pub const SECTION: &str = ".fpt_catalog";
/// The first bytes of every record.
pub const MAGIC: [u8; 4] = *b"FPTA";
const HEADER_LEN: usize = 36;

/// What an assertion claims, as the catalog classifies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssertionKind {
    Always = 0,
    AlwaysOrUnreachable = 1,
    Sometimes = 2,
    Reachable = 3,
    Unreachable = 4,
}

impl AssertionKind {
    const fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Always,
            1 => Self::AlwaysOrUnreachable,
            2 => Self::Sometimes,
            3 => Self::Reachable,
            4 => Self::Unreachable,
            _ => return None,
        })
    }

    /// The name of the macro that makes this kind of assertion, without the `!`.
    pub const fn display_type(self) -> &'static str {
        match self {
            Self::Always => "assert_always",
            Self::AlwaysOrUnreachable => "assert_always_or_unreachable",
            Self::Sometimes => "assert_sometimes",
            Self::Reachable => "assert_reachable",
            Self::Unreachable => "assert_unreachable",
        }
    }
}

/// Where an assertion is in the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceLocation<'a> {
    pub file: &'a str,
    pub begin_line: u32,
    pub begin_column: u32,
    /// The module path.
    pub class: &'a str,
}

/// One cataloged assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Assertion<'a> {
    /// The probe id it reports with.
    pub id: u64,
    pub message: &'a str,
    pub kind: AssertionKind,
    pub location: SourceLocation<'a>,
}

/// One record, as a static the macros place in [`SECTION`].
#[doc(hidden)]
#[repr(C, align(4))]
pub struct Record<const N: usize>([u8; N]);

/// The length of the record for these strings.
#[doc(hidden)]
pub const fn record_len(file: &str, module: &str, message: &str) -> usize {
    (HEADER_LEN + file.len() + module.len() + message.len()).next_multiple_of(4)
}

impl<const N: usize> Record<N> {
    /// Encode a record. `N` must be [`record_len`] of the same strings.
    #[doc(hidden)]
    pub const fn new(
        kind: AssertionKind,
        file: &str,
        line: u32,
        column: u32,
        module: &str,
        message: &str,
    ) -> Self {
        assert!(
            N == record_len(file, module, message),
            "record length mismatch"
        );
        assert!(
            file.len() <= u16::MAX as usize,
            "file name too long for the catalog"
        );
        assert!(
            module.len() <= u16::MAX as usize,
            "module path too long for the catalog"
        );
        assert!(
            message.len() <= u16::MAX as usize,
            "message too long for the catalog"
        );
        let mut bytes = [0u8; N];
        let mut at = put(&mut bytes, 0, &MAGIC);
        at = put(&mut bytes, at, &(N as u32).to_le_bytes());
        at = put(&mut bytes, at, &[kind as u8, 0, 0, 0]);
        at = put(&mut bytes, at, &message_id(message).to_le_bytes());
        at = put(&mut bytes, at, &line.to_le_bytes());
        at = put(&mut bytes, at, &column.to_le_bytes());
        at = put(&mut bytes, at, &(file.len() as u16).to_le_bytes());
        at = put(&mut bytes, at, &(module.len() as u16).to_le_bytes());
        at = put(&mut bytes, at, &(message.len() as u16).to_le_bytes());
        at = put(&mut bytes, at, &[0, 0]);
        at = put(&mut bytes, at, file.as_bytes());
        at = put(&mut bytes, at, module.as_bytes());
        put(&mut bytes, at, message.as_bytes());
        Self(bytes)
    }

    /// The encoded bytes.
    pub const fn bytes(&self) -> &[u8; N] {
        &self.0
    }
}

const fn put<const N: usize>(bytes: &mut [u8; N], at: usize, from: &[u8]) -> usize {
    let mut index = 0;
    while index < from.len() {
        bytes[at + index] = from[index];
        index += 1;
    }
    at + from.len()
}

/// Why a catalog section did not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CatalogError {
    /// The bytes at `offset` are not a record.
    BadRecord { offset: usize },
}

impl core::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadRecord { offset } => write!(f, "no valid catalog record at offset {offset}"),
        }
    }
}

/// The assertions in a catalog section's contents, in section order. A linker may pad
/// between records with zero words, which are skipped.
pub fn parse(section: &[u8]) -> Parse<'_> {
    Parse { section, offset: 0 }
}

/// The iterator [`parse`] returns. It stops after the first error.
pub struct Parse<'a> {
    section: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for Parse<'a> {
    type Item = Result<Assertion<'a>, CatalogError>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.section[self.offset..].starts_with(&[0; 4]) {
            self.offset += 4;
        }
        if self.offset >= self.section.len() {
            return None;
        }
        let at = self.offset;
        match record(&self.section[at..]) {
            Some((assertion, len)) => {
                self.offset += len;
                Some(Ok(assertion))
            }
            None => {
                self.offset = self.section.len();
                Some(Err(CatalogError::BadRecord { offset: at }))
            }
        }
    }
}

fn record(bytes: &[u8]) -> Option<(Assertion<'_>, usize)> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?));
    if bytes.get(..4)? != MAGIC {
        return None;
    }
    let len = u32_at(4)? as usize;
    if len < HEADER_LEN || !len.is_multiple_of(4) || len > bytes.len() {
        return None;
    }
    let kind = AssertionKind::from_u8(bytes[8])?;
    let id = u64::from_le_bytes(bytes.get(12..20)?.try_into().ok()?);
    let (file_len, module_len, message_len) = (
        usize::from(u16_at(28)?),
        usize::from(u16_at(30)?),
        usize::from(u16_at(32)?),
    );
    let text = |start: usize, len: usize| core::str::from_utf8(bytes.get(start..start + len)?).ok();
    let file = text(HEADER_LEN, file_len)?;
    let class = text(HEADER_LEN + file_len, module_len)?;
    let message = text(HEADER_LEN + file_len + module_len, message_len)?;
    if HEADER_LEN + file_len + module_len + message_len > len {
        return None;
    }
    let location = SourceLocation {
        file,
        begin_line: u32_at(20)?,
        begin_column: u32_at(24)?,
        class,
    };
    let id = if id == 0 { message_id(message) } else { id };
    Some((
        Assertion {
            id,
            message,
            kind,
            location,
        },
        len,
    ))
}

/// Emit a catalog record for an assertion at the call site, with the `catalog` feature.
#[cfg(feature = "catalog")]
#[doc(hidden)]
#[macro_export]
macro_rules! __catalog {
    ($kind:ident, $message:expr) => {
        #[used]
        #[unsafe(link_section = ".fpt_catalog")]
        static RECORD: $crate::catalog::Record<
            { $crate::catalog::record_len(file!(), module_path!(), $message) },
        > = $crate::catalog::Record::new(
            $crate::catalog::AssertionKind::$kind,
            file!(),
            line!(),
            column!(),
            module_path!(),
            $message,
        );
    };
}

#[cfg(not(feature = "catalog"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __catalog {
    ($kind:ident, $message:expr) => {};
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &str = "the queue never overflows";

    fn encoded() -> Record<{ record_len("src/q.rs", "fw::q", MESSAGE) }> {
        Record::new(AssertionKind::Always, "src/q.rs", 42, 9, "fw::q", MESSAGE)
    }

    #[test]
    fn a_record_parses_back_to_its_assertion() {
        let record = encoded();
        let bytes = record.bytes();
        assert_eq!(bytes.len() % 4, 0);
        let mut parsed = parse(bytes);
        let assertion = parsed.next().unwrap().unwrap();
        assert_eq!(assertion.id, message_id(MESSAGE));
        assert_eq!(assertion.message, MESSAGE);
        assert_eq!(assertion.kind, AssertionKind::Always);
        assert_eq!(assertion.kind.display_type(), "assert_always");
        assert_eq!(
            assertion.location,
            SourceLocation {
                file: "src/q.rs",
                begin_line: 42,
                begin_column: 9,
                class: "fw::q"
            }
        );
        assert!(parsed.next().is_none());
    }

    #[test]
    fn a_record_without_an_id_takes_its_message_hash() {
        let mut record = *encoded().bytes();
        record[12..20].fill(0);
        let assertion = parse(&record).next().unwrap().unwrap();
        assert_eq!(assertion.id, message_id(MESSAGE));
    }

    #[test]
    fn zero_padding_between_records_is_skipped_and_garbage_is_an_error() {
        let one = encoded();
        let mut section = [0u8; 256];
        let len = one.bytes().len();
        section[..len].copy_from_slice(one.bytes());
        section[len + 8..2 * len + 8].copy_from_slice(one.bytes());
        let section = &section[..2 * len + 8];
        assert_eq!(parse(section).filter(|r| r.is_ok()).count(), 2);

        let mut bad = [0u8; 64];
        bad[..len.min(64)].copy_from_slice(&one.bytes()[..len.min(64)]);
        bad[0] = b'X';
        let results: [_; 1] = [parse(&bad).next().unwrap()];
        assert_eq!(results[0], Err(CatalogError::BadRecord { offset: 0 }));
        let mut short = *one.bytes();
        short[4] = 200; // a length past the end
        assert!(parse(&short).next().unwrap().is_err());
    }
}
