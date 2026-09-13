//! HID report-descriptor parsing.
//!
//! A HID report descriptor is a byte stream of items describing what a
//! device's reports contain. It comes from the far end of a cable, and
//! parsing it is a well-known minefield — the format nests, the item sizes
//! are encoded in a way that admits a zero-length walk, and the usage stack
//! is unbounded in the specification but not in any implementation.
//!
//! # The failure modes, which are the same shape as descriptor parsing
//!
//! - **An item's size field encodes 0, 1, 2 or 4 bytes** — the value 3 means
//!   *four*, not three. Reading it as three walks the stream misaligned from
//!   that point on, and every item after it is garbage that still parses.
//! - **A long item** (tag 0xFE) carries its own length byte and must be
//!   skipped wholesale. Treating it as a short item reads its payload as
//!   items.
//! - **Nesting is unbounded on the wire.** `PUSH` without `POP` repeated
//!   enough times exhausts any stack, and a device can send as many as it
//!   likes.
//!
//! This parses the structure and the fields a HID consumer needs —
//! report sizes and counts — and refuses anything malformed rather than
//! guessing.

/// Item type, from bits 2..3 of the prefix.
pub mod item_type {
    /// Main items: INPUT, OUTPUT, FEATURE, COLLECTION.
    pub const MAIN: u8 = 0;
    /// Global items: USAGE_PAGE, REPORT_SIZE, REPORT_COUNT, REPORT_ID.
    pub const GLOBAL: u8 = 1;
    /// Local items: USAGE, USAGE_MINIMUM, USAGE_MAXIMUM.
    pub const LOCAL: u8 = 2;
}

/// Item tags this core acts on, from bits 4..7 of the prefix.
pub mod tag {
    /// `INPUT` — a report the device sends.
    pub const INPUT: u8 = 0x8;
    /// `OUTPUT`.
    pub const OUTPUT: u8 = 0x9;
    /// `FEATURE`.
    pub const FEATURE: u8 = 0xB;
    /// `COLLECTION`.
    pub const COLLECTION: u8 = 0xA;
    /// `END_COLLECTION`.
    pub const END_COLLECTION: u8 = 0xC;
    /// `USAGE_PAGE`.
    pub const USAGE_PAGE: u8 = 0x0;
    /// `REPORT_SIZE` — bits per field.
    pub const REPORT_SIZE: u8 = 0x7;
    /// `REPORT_ID`.
    pub const REPORT_ID: u8 = 0x8;
    /// `REPORT_COUNT` — how many fields.
    pub const REPORT_COUNT: u8 = 0x9;
    /// `PUSH`.
    pub const PUSH: u8 = 0xA;
    /// `POP`.
    pub const POP: u8 = 0xB;
}

/// The prefix byte of a long item. Its length lives in the next byte.
pub const LONG_ITEM_PREFIX: u8 = 0xFE;

/// Nesting depth the parser will follow.
///
/// The specification places no bound on PUSH/POP or collection nesting, and a
/// device can send as many as it likes. Sixteen is far beyond any real
/// descriptor and finite, which is the property that matters.
pub const MAX_NESTING: usize = 16;

/// Items the parser will walk.
///
/// A descriptor may legitimately be long; an endless one is a device holding
/// enumeration open, and enumeration must be able to give up.
pub const MAX_ITEMS: usize = 256;

/// Why a descriptor was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HidError {
    /// An item's payload runs past the end of the descriptor.
    Truncated,
    /// More items than the parser will walk.
    TooManyItems,
    /// Nesting deeper than [`MAX_NESTING`].
    TooDeep,
    /// `POP` with nothing pushed, or `END_COLLECTION` with none open.
    UnbalancedNesting,
    /// A field the workload needs is missing or impossible.
    InvalidField,
}

/// One parsed item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Item {
    /// Item type.
    pub kind: u8,
    /// Item tag.
    pub tag: u8,
    /// The item's data, zero-extended. Items carry at most four bytes.
    pub data: u32,
}

/// Bytes of payload an item's size field encodes.
///
/// **The value 3 means four bytes, not three.** That is the single most
/// common HID parsing bug: reading it as three leaves the walk misaligned
/// from that item onward, and every subsequent item parses into something
/// plausible and wrong.
#[inline]
pub const fn payload_len(size_field: u8) -> usize {
    match size_field & 0x3 {
        0 => 0,
        1 => 1,
        2 => 2,
        _ => 4,
    }
}

/// Walk a report descriptor, calling `visit` for each short item.
///
/// Long items are skipped wholesale rather than descended into: they carry
/// their own length and their payload is not items.
///
/// Terminates. Every step advances by at least one byte, and the item count
/// is capped.
pub fn walk(
    descriptor: &[u8],
    mut visit: impl FnMut(Item) -> Result<(), HidError>,
) -> Result<usize, HidError> {
    let mut cursor = 0usize;
    let mut seen = 0usize;

    while cursor < descriptor.len() {
        if seen == MAX_ITEMS {
            return Err(HidError::TooManyItems);
        }
        let prefix = descriptor[cursor];

        if prefix == LONG_ITEM_PREFIX {
            // bDataSize, bLongItemTag, then the data.
            if cursor + 2 >= descriptor.len() {
                return Err(HidError::Truncated);
            }
            let data_len = descriptor[cursor + 1] as usize;
            let total = 3 + data_len;
            if cursor + total > descriptor.len() {
                return Err(HidError::Truncated);
            }
            cursor += total;
            seen += 1;
            continue;
        }

        let len = payload_len(prefix);
        if cursor + 1 + len > descriptor.len() {
            return Err(HidError::Truncated);
        }

        let mut data = 0u32;
        for i in 0..len {
            data |= (descriptor[cursor + 1 + i] as u32) << (8 * i);
        }

        visit(Item {
            kind: (prefix >> 2) & 0x3,
            tag: (prefix >> 4) & 0xf,
            data,
        })?;

        // At least one byte, always — a zero-length payload still consumes
        // its prefix, so the walk cannot stand still.
        cursor += 1 + len;
        seen += 1;
    }

    Ok(seen)
}

/// What a proving workload needs to know about a device's reports.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReportShape {
    /// Bits in one input report's fields.
    pub input_bits: u32,
    /// Whether the descriptor declares report IDs, which prefix every report
    /// with an extra byte — getting this wrong shifts every field by eight
    /// bits.
    pub has_report_id: bool,
}

/// Parse the report shape, tracking nesting.
///
/// Rejects unbalanced `PUSH`/`POP` and `COLLECTION`/`END_COLLECTION` rather
/// than carrying on with a corrupted global state — a descriptor that pops
/// more than it pushed is telling the parser something it cannot satisfy, and
/// continuing means reporting field sizes from the wrong scope.
pub fn report_shape(descriptor: &[u8]) -> Result<ReportShape, HidError> {
    let mut shape = ReportShape::default();
    let mut report_size = 0u32;
    let mut report_count = 0u32;
    let mut pushes = 0usize;
    let mut collections = 0usize;
    let mut error = None;

    walk(descriptor, |item| {
        match (item.kind, item.tag) {
            (item_type::GLOBAL, tag::REPORT_SIZE) => report_size = item.data,
            (item_type::GLOBAL, tag::REPORT_COUNT) => report_count = item.data,
            (item_type::GLOBAL, tag::REPORT_ID) => shape.has_report_id = true,
            (item_type::GLOBAL, tag::PUSH) => {
                pushes += 1;
                if pushes > MAX_NESTING {
                    error = Some(HidError::TooDeep);
                    return Err(HidError::TooDeep);
                }
            }
            (item_type::GLOBAL, tag::POP) => {
                if pushes == 0 {
                    error = Some(HidError::UnbalancedNesting);
                    return Err(HidError::UnbalancedNesting);
                }
                pushes -= 1;
            }
            (item_type::MAIN, tag::COLLECTION) => {
                collections += 1;
                if collections > MAX_NESTING {
                    error = Some(HidError::TooDeep);
                    return Err(HidError::TooDeep);
                }
            }
            (item_type::MAIN, tag::END_COLLECTION) => {
                if collections == 0 {
                    error = Some(HidError::UnbalancedNesting);
                    return Err(HidError::UnbalancedNesting);
                }
                collections -= 1;
            }
            (item_type::MAIN, tag::INPUT) => {
                // Saturating: a descriptor declaring enormous sizes should
                // not wrap into a small, plausible total.
                shape.input_bits = shape
                    .input_bits
                    .saturating_add(report_size.saturating_mul(report_count));
            }
            _ => {}
        }
        Ok(())
    })?;

    if let Some(e) = error {
        return Err(e);
    }
    if collections != 0 || pushes != 0 {
        return Err(HidError::UnbalancedNesting);
    }
    Ok(shape)
}
