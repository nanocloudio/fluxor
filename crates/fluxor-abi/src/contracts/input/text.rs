// Contract: input::text — text and composition records (the `TextEvents`
// content type).
//
// Layer: contracts/input (public, stable).
//
// What a platform's text machinery did, for an application that draws its
// own text fields: text committed, a composition in progress (an input
// method's preedit), a deletion, a moved selection. Key records
// (`input::key`) carry keys; these carry text. A key whose effect arrived
// here is flagged `KEY_TEXT` there, so nothing is applied twice.
//
// Every record, little-endian:
//
//   [0]     msg     MSG_*
//   [1]     flags   per message; other bits zero
//   [2..4]  len     u16  payload bytes, `target` onward; at most MAX_LEN
//   [4..8]  target  u32  the accessibility node being edited
//                        (`contracts::accessibility`), or NO_TARGET: the
//                        application's own focused text field
//
//   COMMIT   [text: 1..=TEXT_MAX bytes of UTF-8]
//            Insert at the target's selection, replacing it. `CONTINUES`:
//            the next COMMIT continues this insert (one undo step).
//   COMPOSE  [hl_start u16][hl_end u16][preedit: 0..=TEXT_MAX bytes of UTF-8]
//            The composition in progress; replaces the previous preedit.
//            `START` on a composition's first record. `END` when it is
//            over: the preedit is removed, the record carries an empty
//            preedit and zero `hl_*`, and a COMMIT follows if the
//            composition produced text. `hl_start..hl_end` is the input
//            method's highlighted range in the preedit (the clause being
//            converted); equal values mark the caret.
//   DELETE   [before u32][after u32]
//            Delete the selection if it is non-empty, else `before` scalar
//            values before the caret and `after` after it.
//   SELECT   [anchor u32][focus u32]
//            The user moved the selection in the platform's field; offsets
//            into the node's value; `focus` is the caret end.
//
// OFFSETS AND COUNTS ARE UNICODE SCALAR VALUES: not UTF-16 code units, not
// bytes, not grapheme clusters. A consumer with no segmentation tables can
// apply scalar counts, and a producer that knows clusters expresses them in
// scalars.
//
// LONG TEXT. Text longer than TEXT_MAX bytes is split at scalar boundaries
// into COMMITs with `CONTINUES` on all but the last. A longer preedit is
// truncated at a scalar boundary and `hl_*` clamped to it: a preedit is
// display only, and the committed text comes whole in COMMITs.
//
// READING. The content type is `Streamed`: a consumer keeps a carry buffer
// of `MAX_RECORD` bytes, appends what it reads, and calls `parse` until it
// answers `NeedMore`. A faulted record is dropped whole (its `skip` says how
// many bytes) together with the composition in progress, and counted;
// `Sequence` holds the composition rule.

use crate::wire::utf8_text;

/// Bytes before the payload's message-specific part: the record header and
/// the target.
pub const HEADER: usize = 8;
/// Bytes of the record header (`msg`, `flags`, `len`).
pub const PREFIX: usize = 4;

/// Byte offsets of the fixed fields.
pub const OFF_MSG: usize = 0;
pub const OFF_FLAGS: usize = 1;
pub const OFF_LEN: usize = 2;
pub const OFF_TARGET: usize = 4;

/// The longest text or preedit one record carries, in bytes.
pub const TEXT_MAX: usize = 1024;
/// The largest `len`: target, a COMPOSE's highlight, and `TEXT_MAX` bytes.
pub const MAX_LEN: usize = 4 + 4 + TEXT_MAX;
/// The largest whole record, which is what a consumer's carry buffer holds.
pub const MAX_RECORD: usize = PREFIX + MAX_LEN;

/// Messages.
pub const MSG_COMMIT: u8 = 0x01;
pub const MSG_COMPOSE: u8 = 0x02;
pub const MSG_DELETE: u8 = 0x03;
pub const MSG_SELECT: u8 = 0x04;

/// `COMMIT` flag: the next COMMIT continues this insert.
pub const COMMIT_CONTINUES: u8 = 0x01;
/// `COMPOSE` flags.
pub const COMPOSE_START: u8 = 0x01;
pub const COMPOSE_END: u8 = 0x02;

/// `target` for the application's own focused text field.
pub const NO_TARGET: u32 = u32::MAX;

/// `len` of the fixed-size records.
pub const DELETE_LEN: usize = 12;
pub const SELECT_LEN: usize = 12;
/// `len` of a COMPOSE with an empty preedit.
pub const COMPOSE_MIN_LEN: usize = 8;

/// One text record, borrowing its text from the read buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record<'a> {
    Commit {
        target: u32,
        /// The next COMMIT continues this insert.
        continues: bool,
        text: &'a str,
    },
    Compose {
        target: u32,
        start: bool,
        end: bool,
        hl_start: u16,
        hl_end: u16,
        preedit: &'a str,
    },
    Delete {
        target: u32,
        before: u32,
        after: u32,
    },
    Select {
        target: u32,
        anchor: u32,
        focus: u32,
    },
}

/// Why a record is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// A `msg` byte outside `MSG_*`.
    UnknownMsg,
    /// A flag bit the message does not allocate.
    BadFlags,
    /// A `len` past `MAX_LEN`: the record boundary is lost.
    Oversize,
    /// A `len` the message cannot have: a fixed record of another size, an
    /// empty COMMIT, text past `TEXT_MAX`, a payload shorter than its fields.
    BadLen,
    /// Text that is not UTF-8.
    BadText,
    /// A COMPOSE highlight that is reversed or reaches past its preedit, or
    /// an `END` carrying a preedit or a highlight.
    BadCompose,
    /// A COMPOSE with no `START` before it.
    NotComposing,
}

/// The outcome of `parse`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parse<'a> {
    /// A whole record, and how many bytes of the buffer it occupied.
    Record { record: Record<'a>, consumed: usize },
    /// The buffer ends inside a record; read more and call again.
    NeedMore,
    /// A refused record. `skip` is its whole length, to drop it and read
    /// on; zero when the boundary is lost (`Oversize`) and the reader must
    /// discard what it holds.
    Fault { fault: Fault, skip: usize },
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// The number of Unicode scalar values in `s`.
pub fn scalars(s: &str) -> usize {
    utf8_text::scalars(s)
}

/// The longest prefix of `s` that is at most `max` bytes and ends on a
/// scalar boundary: how a producer splits long text across COMMITs and
/// truncates a long preedit.
pub fn prefix_within(s: &str, max: usize) -> &str {
    utf8_text::prefix_within(s, max)
}

/// Parse the record at the front of `buf`.
pub fn parse(buf: &[u8]) -> Parse<'_> {
    if buf.len() < PREFIX {
        return Parse::NeedMore;
    }
    let len = u16_at(buf, OFF_LEN) as usize;
    if len > MAX_LEN {
        return Parse::Fault {
            fault: Fault::Oversize,
            skip: 0,
        };
    }
    let total = PREFIX + len;
    if buf.len() < total {
        return Parse::NeedMore;
    }
    let refuse = |fault| Parse::Fault { fault, skip: total };
    if len < 4 {
        return refuse(Fault::BadLen);
    }
    let flags = buf[OFF_FLAGS];
    let target = u32_at(buf, OFF_TARGET);
    let body = &buf[HEADER..total];
    let record = match buf[OFF_MSG] {
        MSG_COMMIT => {
            if flags & !COMMIT_CONTINUES != 0 {
                return refuse(Fault::BadFlags);
            }
            if body.is_empty() || body.len() > TEXT_MAX {
                return refuse(Fault::BadLen);
            }
            let Some(text) = utf8_text::text(body) else {
                return refuse(Fault::BadText);
            };
            Record::Commit {
                target,
                continues: flags & COMMIT_CONTINUES != 0,
                text,
            }
        }
        MSG_COMPOSE => {
            if flags & !(COMPOSE_START | COMPOSE_END) != 0 {
                return refuse(Fault::BadFlags);
            }
            if body.len() < 4 || body.len() - 4 > TEXT_MAX {
                return refuse(Fault::BadLen);
            }
            let hl_start = u16_at(body, 0);
            let hl_end = u16_at(body, 2);
            let Some(preedit) = utf8_text::text(&body[4..]) else {
                return refuse(Fault::BadText);
            };
            let end = flags & COMPOSE_END != 0;
            if hl_start > hl_end || hl_end as usize > scalars(preedit) || end && !preedit.is_empty()
            {
                return refuse(Fault::BadCompose);
            }
            Record::Compose {
                target,
                start: flags & COMPOSE_START != 0,
                end,
                hl_start,
                hl_end,
                preedit,
            }
        }
        MSG_DELETE | MSG_SELECT => {
            if flags != 0 {
                return refuse(Fault::BadFlags);
            }
            if len != DELETE_LEN {
                return refuse(Fault::BadLen);
            }
            let (a, b) = (u32_at(body, 0), u32_at(body, 4));
            if buf[OFF_MSG] == MSG_DELETE {
                Record::Delete {
                    target,
                    before: a,
                    after: b,
                }
            } else {
                Record::Select {
                    target,
                    anchor: a,
                    focus: b,
                }
            }
        }
        _ => return refuse(Fault::UnknownMsg),
    };
    Parse::Record {
        record,
        consumed: total,
    }
}

fn header(out: &mut [u8], msg: u8, flags: u8, len: usize, target: u32) {
    out[OFF_MSG] = msg;
    out[OFF_FLAGS] = flags;
    out[OFF_LEN..OFF_LEN + 2].copy_from_slice(&(len as u16).to_le_bytes());
    out[OFF_TARGET..OFF_TARGET + 4].copy_from_slice(&target.to_le_bytes());
}

/// Write a COMMIT. `None` when `out` is too small, or `text` is empty or
/// longer than `TEXT_MAX` (split it with `prefix_within`); never a partial
/// record.
pub fn write_commit(out: &mut [u8], target: u32, continues: bool, text: &str) -> Option<usize> {
    if text.is_empty() || text.len() > TEXT_MAX {
        return None;
    }
    let total = HEADER + text.len();
    let out = out.get_mut(..total)?;
    let flags = if continues { COMMIT_CONTINUES } else { 0 };
    header(out, MSG_COMMIT, flags, 4 + text.len(), target);
    out[HEADER..].copy_from_slice(text.as_bytes());
    Some(total)
}

/// Write a COMPOSE. `None` when `out` is too small or the record is one
/// `parse` refuses: a preedit past `TEXT_MAX`, a highlight reversed or past
/// the preedit, an `end` carrying a preedit.
pub fn write_compose(
    out: &mut [u8],
    target: u32,
    start: bool,
    end: bool,
    hl_start: u16,
    hl_end: u16,
    preedit: &str,
) -> Option<usize> {
    if preedit.len() > TEXT_MAX
        || hl_start > hl_end
        || hl_end as usize > scalars(preedit)
        || end && !preedit.is_empty()
    {
        return None;
    }
    let total = HEADER + 4 + preedit.len();
    let out = out.get_mut(..total)?;
    let mut flags = 0;
    if start {
        flags |= COMPOSE_START;
    }
    if end {
        flags |= COMPOSE_END;
    }
    header(out, MSG_COMPOSE, flags, 8 + preedit.len(), target);
    out[HEADER..HEADER + 2].copy_from_slice(&hl_start.to_le_bytes());
    out[HEADER + 2..HEADER + 4].copy_from_slice(&hl_end.to_le_bytes());
    out[HEADER + 4..].copy_from_slice(preedit.as_bytes());
    Some(total)
}

fn write_pair(out: &mut [u8], msg: u8, target: u32, a: u32, b: u32) -> Option<usize> {
    let total = PREFIX + DELETE_LEN;
    let out = out.get_mut(..total)?;
    header(out, msg, 0, DELETE_LEN, target);
    out[HEADER..HEADER + 4].copy_from_slice(&a.to_le_bytes());
    out[HEADER + 4..].copy_from_slice(&b.to_le_bytes());
    Some(total)
}

/// Write a DELETE.
pub fn write_delete(out: &mut [u8], target: u32, before: u32, after: u32) -> Option<usize> {
    write_pair(out, MSG_DELETE, target, before, after)
}

/// Write a SELECT.
pub fn write_select(out: &mut [u8], target: u32, anchor: u32, focus: u32) -> Option<usize> {
    write_pair(out, MSG_SELECT, target, anchor, focus)
}

/// The composition rule, enforced: a COMPOSE belongs to a composition its
/// `START` opened. A consumer admits every parsed record through one of
/// these; on any fault (here or from `parse`) it drops the record and the
/// composition in progress, which `reset` records.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sequence {
    composing: bool,
}

impl Sequence {
    pub const fn new() -> Self {
        Self { composing: false }
    }

    /// Whether a composition is in progress.
    pub const fn is_composing(&self) -> bool {
        self.composing
    }

    /// Forget the composition in progress, after a fault.
    pub fn reset(&mut self) {
        self.composing = false;
    }

    /// Admit `record`, or refuse a COMPOSE outside a composition.
    pub fn admit(&mut self, record: &Record<'_>) -> Result<(), Fault> {
        if let Record::Compose { start, end, .. } = *record {
            if !start && !self.composing {
                return Err(Fault::NotComposing);
            }
            self.composing = !end;
        }
        Ok(())
    }
}

const _: () = assert!(OFF_MSG == 0);
const _: () = assert!(OFF_MSG + 1 == OFF_FLAGS);
const _: () = assert!(OFF_FLAGS + 1 == OFF_LEN);
const _: () = assert!(OFF_LEN + 2 == OFF_TARGET);
const _: () = assert!(OFF_LEN + 2 == PREFIX);
const _: () = assert!(OFF_TARGET + 4 == HEADER);
const _: () = assert!(MAX_LEN == 1032);
const _: () = assert!(MAX_RECORD == 1036);
const _: () = assert!(DELETE_LEN == SELECT_LEN);
