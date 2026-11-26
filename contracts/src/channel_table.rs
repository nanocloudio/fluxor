//! The channel table: one declaration of the channels a carrier moves, the
//! same whether the peer is another node (`remote_channel`) or a host
//! process (`host_lane`).
//!
//! A table is written `content_type:framing:max_record;…`, channel index =
//! position. Each entry names the channel's content type, how its records
//! are delimited on the local edge, and its largest record. Both ends of a
//! carrier state their tables and refuse a difference.
//!
//! The parser fills a caller's slice of [`Entry`]s, so each carrier keeps
//! its own capacity and appends its own entries after the parsed ones
//! (`remote_channel`'s exchange endpoint, `host_lane`'s per-contract call
//! and answer channels). No allocation, and nothing here panics: a module
//! that links it carries no panic location.

/// Longest content-type name a table entry carries — longer than any name
/// in the content-type registry.
pub const CT_NAME_MAX: usize = 32;

/// The longest local header a length framing names: the field's offset and
/// width together.
pub const HDR_MAX: usize = 64;

/// How records are delimited on a channel's local edge. Local only: a
/// carrier moves the record's bytes verbatim, so the two ends agree on
/// content type and maximum, not on how each delimits locally.
pub mod framing {
    /// A length field in a header of the record's own: `len16@<off>+<add>`
    /// or `len32@<off>+<add>` — a little-endian 16- or 32-bit field at byte
    /// `off` of the record, and the whole record is the field's value plus
    /// `add` bytes ([`super::Entry::len_off`], `len_width`, `len_add`).
    /// `tlv16` is `len16@1+3` (`[type:1][len:2 LE][payload]`, the header the
    /// net contracts share) and `len32` is `len32@0+4` (`[len:4 LE][payload]`).
    pub const LEN: u8 = 0;
    /// A mailbox edge (`buffer_group`): one buffer is one record.
    pub const MAILBOX: u8 = 2;
    /// A byte stream with no records in it — a connection's payload. It
    /// crosses in order and lossless; `max_record` bounds one piece of it.
    pub const BYTES: u8 = 3;
}

/// One channel's table entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub content_type: [u8; CT_NAME_MAX],
    pub ct_len: u8,
    pub framing: u8,
    /// [`framing::LEN`]: the length field's offset in the record, its width
    /// in bytes (2 or 4), and what the whole record adds to its value.
    pub len_off: u8,
    pub len_width: u8,
    pub len_add: u32,
    pub max_record: u32,
}

impl Entry {
    pub const EMPTY: Entry = Entry {
        content_type: [0; CT_NAME_MAX],
        ct_len: 0,
        framing: framing::LEN,
        len_off: 1,
        len_width: 2,
        len_add: 3,
        max_record: 0,
    };

    /// A `mailbox` entry named `ct` of `max_record`: the shape a carrier's
    /// own channels take (an exchange endpoint's, a contract's calls and
    /// answers). `None` for a name [`parse_into`] would refuse.
    pub fn mailbox(ct: &[u8], max_record: u32) -> Option<Entry> {
        if !content_type_ok(ct) || max_record == 0 {
            return None;
        }
        let mut e = Entry::EMPTY;
        for (d, s) in e.content_type.iter_mut().zip(ct) {
            *d = *s;
        }
        e.ct_len = ct.len() as u8;
        e.framing = framing::MAILBOX;
        e.max_record = max_record;
        Some(e)
    }

    pub fn content_type(&self) -> &[u8] {
        let n = (self.ct_len as usize).min(CT_NAME_MAX);
        self.content_type.get(..n).unwrap_or(&[])
    }

    /// Bytes of local header that announce a record's length — through the
    /// end of its length field — or 0 for a mailbox or a byte stream.
    pub fn header_len(&self) -> usize {
        match self.framing {
            framing::LEN => self.len_off as usize + self.len_width as usize,
            _ => 0,
        }
    }

    /// The whole record's length from its local header (`header_len`
    /// bytes); 0 when `hdr` is shorter than that.
    pub fn record_len(&self, hdr: &[u8]) -> u64 {
        let at = self.len_off as usize;
        let field = if self.len_width == 2 {
            match hdr.get(at..at + 2) {
                Some(&[a, b]) => u64::from(u16::from_le_bytes([a, b])),
                _ => return 0,
            }
        } else {
            match hdr.get(at..at + 4) {
                Some(&[a, b, c, d]) => u64::from(u32::from_le_bytes([a, b, c, d])),
                _ => return 0,
            }
        };
        field + u64::from(self.len_add)
    }
}

/// Why a table was refused. The discriminants are stable: a carrier indexes
/// its refusal texts by them.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableError {
    Empty = 0,
    TooManyChannels,
    Syntax,
    ContentType,
    Framing,
    /// Not a number, zero, under the local header, over the framing's own
    /// ceiling, or over `limit`.
    MaxRecord,
}

/// A length framing's text: `tlv16`, `len32`, or `len16@<off>+<add>` /
/// `len32@<off>+<add>` (decimal). `(offset, width, add)`, or `None` for a
/// spec that is malformed or whose header passes [`HDR_MAX`].
pub fn parse_len_framing(text: &[u8]) -> Option<(u8, u8, u32)> {
    match text {
        b"tlv16" => return Some((1, 2, 3)),
        b"len32" => return Some((0, 4, 4)),
        _ => {}
    }
    let (width, rest) = if let Some(r) = text.strip_prefix(b"len16@") {
        (2u8, r)
    } else if let Some(r) = text.strip_prefix(b"len32@") {
        (4u8, r)
    } else {
        return None;
    };
    let plus = rest.iter().position(|&b| b == b'+')?;
    let off = parse_u32(rest.get(..plus)?)?;
    let add = parse_u32(rest.get(plus + 1..)?)?;
    if off as usize + width as usize > HDR_MAX {
        return None;
    }
    Some((off as u8, width, add))
}

/// Parse `content_type:framing:max_record;…` into `out`, from index 0.
/// Returns how many entries it filled. Each ceiling refuses — a record
/// maximum over `limit`, more entries than `out` holds — and none is
/// clamped; an empty table is [`TableError::Empty`].
pub fn parse_into(text: &[u8], limit: u32, out: &mut [Entry]) -> Result<usize, TableError> {
    let text = trim(text);
    if text.is_empty() {
        return Err(TableError::Empty);
    }
    let mut n = 0usize;
    for item in text.split(|&b| b == b';') {
        let item = trim(item);
        if item.is_empty() {
            continue;
        }
        let Some(slot) = out.get_mut(n) else {
            return Err(TableError::TooManyChannels);
        };
        *slot = parse_entry(item, limit)?;
        n += 1;
    }
    if n == 0 {
        return Err(TableError::Empty);
    }
    Ok(n)
}

/// One `content_type:framing:max_record` item.
fn parse_entry(item: &[u8], limit: u32) -> Result<Entry, TableError> {
    let mut parts = item.split(|&b| b == b':');
    let (Some(ct), Some(fr), Some(mx), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(TableError::Syntax);
    };
    let ct = trim(ct);
    if !content_type_ok(ct) {
        return Err(TableError::ContentType);
    }
    let fr = trim(fr);
    let (framing_kind, len) = match fr {
        b"mailbox" => (framing::MAILBOX, None),
        b"bytes" => (framing::BYTES, None),
        _ => (
            framing::LEN,
            Some(parse_len_framing(fr).ok_or(TableError::Framing)?),
        ),
    };
    let max = parse_u32(trim(mx)).ok_or(TableError::MaxRecord)?;
    // A record holds at least its own header and at least what its
    // length adds; a 16-bit field reaches `add + 0xFFFF` and no further.
    let (ceiling, floor) = match len {
        Some((off, width, add)) => {
            let field_max = if width == 2 {
                u64::from(u16::MAX)
            } else {
                u64::from(u32::MAX)
            };
            (
                u64::from(limit).min(u64::from(add) + field_max) as u32,
                (u32::from(off) + u32::from(width)).max(add).max(1),
            )
        }
        None => (limit, 1),
    };
    if max < floor || max > ceiling {
        return Err(TableError::MaxRecord);
    }
    let mut e = Entry::EMPTY;
    for (d, s) in e.content_type.iter_mut().zip(ct) {
        *d = *s;
    }
    e.ct_len = ct.len() as u8;
    e.framing = framing_kind;
    if let Some((off, width, add)) = len {
        e.len_off = off;
        e.len_width = width;
        e.len_add = add;
    }
    e.max_record = max;
    Ok(e)
}

/// A content-type name a table carries: 1 to [`CT_NAME_MAX`] ASCII
/// alphanumerics.
pub fn content_type_ok(ct: &[u8]) -> bool {
    !ct.is_empty() && ct.len() <= CT_NAME_MAX && ct.iter().all(|b| b.is_ascii_alphanumeric())
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if first.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = s {
        if last.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 10 {
        return None;
    }
    let mut v: u64 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u64::from(b - b'0');
    }
    u32::try_from(v).ok()
}
