//! Env binds: a graph's module params that take their value from an
//! environment, written out before the graph is created.
//!
//! A module param the graph binds to a name travels as an **env bind
//! record** in the module's params TLV, under the reserved entry tag
//! [`BIND_TAG`] in the basic section. Whoever holds the environment — a node
//! agent creating a workload, the tools building a static graph — copies the
//! graph through [`bind`], which writes every record out as the param's
//! entries. A bind record never reaches a module: the kernel refuses an add
//! that still carries one.
//!
//! The record's value:
//! ```text
//! off  size  field
//!   0    1   target    the param's own TLV tag (below BIND_TAG)
//!   1    1   kind      KIND_U8 | KIND_U16 | KIND_U32 | KIND_STR | KIND_STR_CHUNKED
//!   2    1   flags     FLAG_REQUIRED | FLAG_DEFAULT (at most one)
//!   3    1   name_len  1..=MAX_NAME
//!   4    4   min       u32 LE, inclusive
//!   8    4   max       u32 LE, inclusive
//!  12    n   name
//! 12+n  ..   default   with FLAG_DEFAULT: an integer kind's value LE in its
//!                      width, a string kind's bytes
//! ```
//! `min`/`max` are the param's schema bounds: an integer kind's value, a
//! string kind's bytes. A value or default outside them fails `Invalid`.
//! The value a name has is written as the param's packer writes it: an
//! integer (decimal, `0x` hex, `true`/`false`) LE in the kind's width, out
//! of range [`BindError::Invalid`]; a string as one entry (`KIND_STR`, at
//! most 255 bytes, longer `Invalid`) or 255-byte chunks under the one tag
//! (`KIND_STR_CHUNKED`); an empty string as no entry. A name with no value
//! takes the default; with none and `FLAG_REQUIRED` the binding fails
//! `Invalid`, and an optional one leaves the param out (the module's own
//! default). A graph the values do not fit (a module's params past a `u16`,
//! or the output buffer) fails [`BindError::TooBig`].

use super::{decode, HEADER_LEN, MODULE_HEAD_LEN, RECORD_ALIGN};

/// The params TLV tag of an env bind record: reserved, below the kernel's
/// metadata tags (0xEE..=0xFF) and above every module param's.
pub const BIND_TAG: u8 = 0xED;
/// Longest name a bind record carries.
pub const MAX_NAME: usize = 128;
/// Bytes of a bind record before its name.
pub const HEAD: usize = 12;
/// Offset of the record's `min` bound.
pub const MIN_AT: usize = 4;
/// Offset of the record's `max` bound.
pub const MAX_AT: usize = 8;
pub const KIND_U8: u8 = 0;
pub const KIND_U16: u8 = 1;
pub const KIND_U32: u8 = 2;
pub const KIND_STR: u8 = 3;
pub const KIND_STR_CHUNKED: u8 = 6;
/// No value for the name fails the binding.
pub const FLAG_REQUIRED: u8 = 0x01;
/// The record carries a default after its name.
pub const FLAG_DEFAULT: u8 = 0x02;

/// Why a graph could not be bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindError {
    /// A graph the codec refuses, a malformed record, a value its kind
    /// cannot hold, or a required name with no value (`EINVAL`).
    Invalid,
    /// The bound graph does not fit (`E2BIG`).
    TooBig,
}

/// TLV header byte and terminator of a module's params.
const TLV_MAGIC: u8 = 0xFE;
const TLV_END: u8 = 0xFF;

/// An `env` options entry's `(name, value)`: the name up to the first `=`,
/// never empty, at most [`MAX_NAME`]; `None` for anything else.
#[must_use]
pub fn entry(val: &[u8]) -> Option<(&[u8], &[u8])> {
    let eq = val.iter().position(|&b| b == b'=')?;
    (eq > 0 && eq <= MAX_NAME).then(|| (&val[..eq], &val[eq + 1..]))
}

/// An integer as an env value writes it: decimal, `0x` hex, `true`/`false`.
fn parse_int(v: &[u8]) -> Option<u64> {
    match v {
        b"true" => return Some(1),
        b"false" => return Some(0),
        _ => {}
    }
    let (digits, radix) = match v.strip_prefix(b"0x").or_else(|| v.strip_prefix(b"0X")) {
        Some(h) => (h, 16u32),
        None => (v, 10u32),
    };
    if digits.is_empty() {
        return None;
    }
    let mut n: u64 = 0;
    for &c in digits {
        let d = u64::from((c as char).to_digit(radix)?);
        n = n.checked_mul(u64::from(radix))?.checked_add(d)?;
    }
    Some(n)
}

/// A bounded writer over the bound graph.
struct Out<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl Out<'_> {
    fn put(&mut self, b: &[u8]) -> Result<(), BindError> {
        let end = self.at.checked_add(b.len()).ok_or(BindError::TooBig)?;
        self.buf
            .get_mut(self.at..end)
            .ok_or(BindError::TooBig)?
            .copy_from_slice(b);
        self.at = end;
        Ok(())
    }

    /// One params entry, or several 255-byte ones under `tag` for a value
    /// longer than one entry carries.
    fn entries(&mut self, tag: u8, v: &[u8]) -> Result<(), BindError> {
        for chunk in v.chunks(usize::from(u8::MAX)) {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "a chunk is at most 255 bytes"
            )]
            self.put(&[tag, chunk.len() as u8])?;
            self.put(chunk)?;
        }
        Ok(())
    }
}

/// Write one env bind record out as its param's entries.
fn emit<'v>(
    rec: &[u8],
    value: &impl Fn(&[u8]) -> Option<&'v [u8]>,
    out: &mut Out<'_>,
) -> Result<(), BindError> {
    use BindError::Invalid;
    if rec.len() < HEAD {
        return Err(Invalid);
    }
    let (target, kind, flags, name_len) = (rec[0], rec[1], rec[2], usize::from(rec[3]));
    let bound = |at: usize| u32::from_le_bytes([rec[at], rec[at + 1], rec[at + 2], rec[at + 3]]);
    let (min, max) = (u64::from(bound(MIN_AT)), u64::from(bound(MAX_AT)));
    let both = FLAG_REQUIRED | FLAG_DEFAULT;
    if target >= BIND_TAG
        || name_len == 0
        || name_len > MAX_NAME
        || flags & !both != 0
        || flags == both
        || min > max
    {
        return Err(Invalid);
    }
    let within = |n: u64| -> Result<(), BindError> {
        if n < min || n > max {
            Err(Invalid)
        } else {
            Ok(())
        }
    };
    let name = rec.get(HEAD..HEAD + name_len).ok_or(Invalid)?;
    let default = &rec[HEAD + name_len..];
    if flags & FLAG_DEFAULT == 0 && !default.is_empty() {
        return Err(Invalid);
    }
    let width = match kind {
        KIND_U8 => Some(1),
        KIND_U16 => Some(2),
        KIND_U32 => Some(4),
        KIND_STR | KIND_STR_CHUNKED => None,
        _ => return Err(Invalid),
    };
    let text = |v: &[u8], out: &mut Out<'_>| -> Result<(), BindError> {
        if kind == KIND_STR && v.len() > usize::from(u8::MAX) {
            return Err(Invalid);
        }
        within(v.len() as u64)?;
        out.entries(target, v)
    };
    match (value(name), width) {
        (Some(v), Some(w)) => {
            let n = parse_int(v).ok_or(Invalid)?;
            if n >> (8 * w) != 0 {
                return Err(Invalid);
            }
            within(n)?;
            out.entries(target, &n.to_le_bytes()[..w])
        }
        (Some(v), None) => text(v, out),
        (None, Some(w)) if flags & FLAG_DEFAULT != 0 => {
            if default.len() != w {
                return Err(Invalid);
            }
            let mut b = [0u8; 8];
            b[..w].copy_from_slice(default);
            within(u64::from_le_bytes(b))?;
            out.entries(target, default)
        }
        (None, None) if flags & FLAG_DEFAULT != 0 => text(default, out),
        (None, _) if flags & FLAG_REQUIRED != 0 => Err(Invalid),
        (None, _) => Ok(()),
    }
}

/// Write a module's params out with every env bind record replaced by its
/// param's entries; params with none are copied as they are.
fn bind_params<'v>(
    p: &[u8],
    value: &impl Fn(&[u8]) -> Option<&'v [u8]>,
    out: &mut Out<'_>,
) -> Result<(), BindError> {
    let start = if p.len() >= 4 && p[0] == TLV_MAGIC {
        4
    } else {
        0
    };
    // Is there a record at all? Walked as the kernel walks params.
    let mut pos = start;
    let mut binds = false;
    while pos + 2 <= p.len() && p[pos] != TLV_END {
        binds |= p[pos] == BIND_TAG;
        pos += 2 + usize::from(p[pos + 1]);
    }
    if !binds {
        return out.put(p);
    }
    let head_at = out.at;
    out.put(&p[..start])?;
    let payload_at = out.at;
    let mut pos = start;
    loop {
        if pos + 2 > p.len() {
            return Err(BindError::Invalid); // a record in params with no terminator
        }
        let (tag, len) = (p[pos], usize::from(p[pos + 1]));
        if tag == TLV_END {
            // The terminator, and whatever follows it, as they are; the
            // header's advisory length runs through the terminator.
            let end_at = out.at + 2;
            out.put(&p[pos..])?;
            if start == 4 {
                let n = u16::try_from(end_at - payload_at).unwrap_or(u16::MAX);
                out.buf[head_at + 2..head_at + 4].copy_from_slice(&n.to_le_bytes());
            }
            return Ok(());
        }
        let val = p.get(pos + 2..pos + 2 + len).ok_or(BindError::Invalid)?;
        if tag == BIND_TAG {
            emit(val, value, out)?;
        } else {
            out.put(&p[pos..pos + 2 + len])?;
        }
        pos += 2 + len;
    }
}

/// Copy the composed graph `src` into `out` with each module's env bind
/// records written out from `value`, which answers a name's value (`None`:
/// the environment does not give it). The length written.
///
/// # Errors
/// [`BindError`].
pub fn bind<'v>(
    src: &[u8],
    out: &mut [u8],
    value: impl Fn(&[u8]) -> Option<&'v [u8]>,
) -> Result<usize, BindError> {
    let g = decode(src).map_err(|_| BindError::Invalid)?;
    let mut o = Out { buf: out, at: 0 };
    let order_end = (HEADER_LEN + 2 * usize::from(g.module_count())).next_multiple_of(RECORD_ALIGN);
    o.put(&src[..order_end])?;
    let mut at = order_end;
    for _ in 0..g.module_count() {
        let len = usize::from(u16::from_le_bytes([src[at], src[at + 1]]));
        let record_at = o.at;
        o.put(&src[at..at + MODULE_HEAD_LEN])?;
        bind_params(&src[at + MODULE_HEAD_LEN..at + len], &value, &mut o)?;
        let written = u16::try_from(o.at - record_at).map_err(|_| BindError::TooBig)?;
        o.buf[record_at..record_at + 2].copy_from_slice(&written.to_le_bytes());
        while !o.at.is_multiple_of(RECORD_ALIGN) {
            o.put(&[0])?;
        }
        at += len.next_multiple_of(RECORD_ALIGN);
    }
    o.put(&src[at..])?;
    Ok(o.at)
}
