//! The remote-channel wire: the channel table, the frames both carriers
//! share, and an incremental parser over one carrier byte stream.
//!
//! Pure: no syscalls, no state beyond what a caller hands in, so the codec is
//! exercised on the host exactly as the module runs it.
//!
//! ## Frames
//!
//! ```text
//! [kind:1][channel:1][len:2 LE][body:len]
//! ```
//!
//! | kind | body | meaning |
//! |---|---|---|
//! | `HELLO` | `"FXRC"[count:1]` then per channel `[ct_len:1][content_type][max_record:4 LE]` | the sender's whole channel table |
//! | `REFUSE` | `[reason:1]` | the sender is ending the session, and why |
//! | `CREDIT` | `[bytes:4 LE]` | the receiver can take `bytes` more record bytes on `channel` |
//! | `BEGIN` | `[record_len:4 LE][first bytes]` | a record starts on `channel` |
//! | `MORE` | `[bytes]` | the record in progress on `channel` continues |
//!
//! A record's bytes, and a fixed charge of four bytes per record (the length
//! the receiver files it under), are counted against the credit the receiver
//! granted; frame headers are not. A record ends when `record_len` bytes
//! have arrived, so no end marker exists and none can be forged.
//!
//! On the `net` carrier one byte stream carries every channel and `HELLO` /
//! `REFUSE` name [`CONTROL`]. On the `mux` carrier each channel has a stream
//! of its own, every frame on it names that stream's channel, and `HELLO`
//! opens every stream in both directions — it is how the accepting side
//! learns which channel a stream carries.

/// Frame header bytes.
pub const FRAME_HDR: usize = 4;
/// `BEGIN`'s record-length prefix.
pub const BEGIN_PREFIX: usize = 4;

pub const KIND_HELLO: u8 = 1;
pub const KIND_REFUSE: u8 = 2;
pub const KIND_CREDIT: u8 = 3;
pub const KIND_BEGIN: u8 = 4;
pub const KIND_MORE: u8 = 5;

/// The channel byte of a `net` carrier's `HELLO` and `REFUSE`.
pub const CONTROL: u8 = 0xFF;

/// `HELLO`'s leading magic.
pub const HELLO_MAGIC: [u8; 4] = *b"FXRC";

/// Most channels one instance carries. Each is a port pair, a reassembly
/// region and a send state, and on `quic` a stream; the manifest declares
/// this many port pairs.
pub const MAX_CHANNELS: usize = 8;

/// Longest content-type name a channel table carries — longer than any
/// name in the content-type registry.
pub const CT_NAME_MAX: usize = 32;

/// Largest `HELLO` body.
pub const HELLO_MAX: usize = 4 + 1 + MAX_CHANNELS * HELLO_ENTRY_LEN;
/// One `HELLO` table entry at its longest.
pub const HELLO_ENTRY_LEN: usize = 1 + CT_NAME_MAX + 4;

/// `REFUSE` reasons.
pub mod refuse {
    /// The two channel tables differ.
    pub const TABLE_MISMATCH: u8 = 1;
    /// A frame the protocol does not allow at that point.
    pub const PROTOCOL: u8 = 2;
    /// More record bytes than the receiver granted.
    pub const CREDIT: u8 = 3;
    /// A record longer than its channel's maximum.
    pub const OVERSIZE: u8 = 4;
}

/// How records are delimited on a channel's local ports. Local only: the
/// wire carries the record's bytes verbatim, so the two ends agree on
/// content type and maximum, not on how each delimits locally.
pub mod framing {
    /// `[type:1][len:2 LE][payload]` — the header the net contracts share
    /// (net_proto, session_ctrl, mux, peer_identity).
    pub const TLV16: u8 = 0;
    /// `[len:4 LE][payload]`.
    pub const LEN32: u8 = 1;
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
    pub max_record: u32,
}

impl Entry {
    pub const EMPTY: Entry = Entry {
        content_type: [0; CT_NAME_MAX],
        ct_len: 0,
        framing: framing::TLV16,
        max_record: 0,
    };

    pub fn content_type(&self) -> &[u8] {
        &self.content_type[..self.ct_len as usize]
    }

    /// Bytes of local header that announce a record's length, or 0 for a
    /// mailbox.
    pub fn header_len(&self) -> usize {
        match self.framing {
            framing::TLV16 => 3,
            framing::LEN32 => 4,
            _ => 0,
        }
    }

    /// The whole record's length from its local header.
    pub fn record_len(&self, hdr: &[u8]) -> u64 {
        match self.framing {
            framing::TLV16 => 3 + u16::from_le_bytes([hdr[1], hdr[2]]) as u64,
            _ => 4 + u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as u64,
        }
    }
}

/// The channel table: `channels` entries, index = position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Table {
    pub channels: u8,
    pub entries: [Entry; MAX_CHANNELS],
}

/// Why a `channels` parameter was refused.
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

/// Parse `content_type:framing:max_record;…`. Each ceiling refuses; none
/// is clamped.
pub fn parse_table(text: &[u8], limit: u32) -> Result<Table, TableError> {
    let mut t = Table {
        channels: 0,
        entries: [Entry::EMPTY; MAX_CHANNELS],
    };
    let text = trim(text);
    if text.is_empty() {
        return Err(TableError::Empty);
    }
    for item in text.split(|&b| b == b';') {
        let item = trim(item);
        if item.is_empty() {
            continue;
        }
        if t.channels as usize == MAX_CHANNELS {
            return Err(TableError::TooManyChannels);
        }
        let mut parts = item.split(|&b| b == b':');
        let (Some(ct), Some(fr), Some(mx), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(TableError::Syntax);
        };
        let ct = trim(ct);
        if ct.is_empty() || ct.len() > CT_NAME_MAX || !ct.iter().all(|b| b.is_ascii_alphanumeric())
        {
            return Err(TableError::ContentType);
        }
        let framing = match trim(fr) {
            b"tlv16" => framing::TLV16,
            b"len32" => framing::LEN32,
            b"mailbox" => framing::MAILBOX,
            b"bytes" => framing::BYTES,
            _ => return Err(TableError::Framing),
        };
        let max = parse_u32(trim(mx)).ok_or(TableError::MaxRecord)?;
        let ceiling = match framing {
            framing::TLV16 => limit.min(3 + u16::MAX as u32),
            _ => limit,
        };
        let floor = match framing {
            framing::TLV16 => 3,
            framing::LEN32 => 4,
            _ => 1,
        };
        if max < floor || max > ceiling {
            return Err(TableError::MaxRecord);
        }
        let e = &mut t.entries[t.channels as usize];
        e.content_type[..ct.len()].copy_from_slice(ct);
        e.ct_len = ct.len() as u8;
        e.framing = framing;
        e.max_record = max;
        t.channels += 1;
    }
    if t.channels == 0 {
        return Err(TableError::Empty);
    }
    Ok(t)
}

/// Encode a `HELLO` body. Returns its length.
pub fn encode_hello(t: &Table, out: &mut [u8; HELLO_MAX]) -> usize {
    out[..4].copy_from_slice(&HELLO_MAGIC);
    out[4] = t.channels;
    let mut at = 5;
    for e in &t.entries[..t.channels as usize] {
        out[at] = e.ct_len;
        at += 1;
        out[at..at + e.ct_len as usize].copy_from_slice(e.content_type());
        at += e.ct_len as usize;
        out[at..at + 4].copy_from_slice(&e.max_record.to_le_bytes());
        at += 4;
    }
    at
}

/// Does a peer's `HELLO` body state exactly this table? Same channel count,
/// and per index the same content type and maximum record.
pub fn hello_matches(t: &Table, body: &[u8]) -> bool {
    let mut own = [0u8; HELLO_MAX];
    let n = encode_hello(t, &mut own);
    body == &own[..n]
}

/// Write a frame header.
pub fn header(kind: u8, channel: u8, len: usize, out: &mut [u8]) {
    out[0] = kind;
    out[1] = channel;
    out[2..4].copy_from_slice(&(len as u16).to_le_bytes());
}

/// What one [`Parser::next`] call found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// The input was consumed with nothing complete yet.
    None,
    /// A whole `HELLO`: the channel byte and the body.
    Hello(u8, &'a [u8]),
    Refuse(u8),
    Credit(u8, u32),
    /// A record of `len` bytes starts on the channel.
    Begin(u8, u32),
    /// Record bytes on the channel.
    Data(u8, &'a [u8]),
    /// Not a frame this protocol has; the stream cannot be resynchronised.
    Error,
}

/// Incremental parser over one carrier stream. A carrier is reliable and
/// ordered and authenticated beneath this protocol, so there is no resync:
/// a frame that does not parse ends the session.
pub struct Parser {
    hdr: [u8; FRAME_HDR + BEGIN_PREFIX],
    have: u8,
    in_body: bool,
    kind: u8,
    channel: u8,
    /// Body bytes still to come in the current frame.
    remaining: u16,
    ctrl: [u8; HELLO_MAX],
    ctrl_len: u16,
}

impl Parser {
    pub const fn new() -> Self {
        Self {
            hdr: [0; FRAME_HDR + BEGIN_PREFIX],
            have: 0,
            in_body: false,
            kind: 0,
            channel: 0,
            remaining: 0,
            ctrl: [0; HELLO_MAX],
            ctrl_len: 0,
        }
    }

    pub fn reset(&mut self) {
        self.have = 0;
        self.in_body = false;
        self.remaining = 0;
        self.ctrl_len = 0;
    }

    fn header_len(kind: u8) -> usize {
        if kind == KIND_BEGIN {
            FRAME_HDR + BEGIN_PREFIX
        } else {
            FRAME_HDR
        }
    }

    /// Take bytes from `input`; returns how many were consumed and what
    /// completed. Call again with the rest until it consumes nothing.
    pub fn next<'a>(&'a mut self, input: &'a [u8]) -> (usize, Event<'a>) {
        let mut used = 0;
        if !self.in_body {
            loop {
                let need = if self.have == 0 {
                    FRAME_HDR
                } else {
                    Self::header_len(self.hdr[0]).max(FRAME_HDR)
                };
                if self.have as usize >= need {
                    break;
                }
                if used == input.len() {
                    return (used, Event::None);
                }
                self.hdr[self.have as usize] = input[used];
                self.have += 1;
                used += 1;
            }
            let len = u16::from_le_bytes([self.hdr[2], self.hdr[3]]) as usize;
            self.kind = self.hdr[0];
            self.channel = self.hdr[1];
            self.have = 0;
            self.ctrl_len = 0;
            match self.kind {
                KIND_HELLO if (1..=HELLO_MAX).contains(&len) => {}
                KIND_REFUSE if len == 1 => {}
                KIND_CREDIT if len == 4 => {}
                KIND_MORE if len > 0 => {}
                KIND_BEGIN if len >= BEGIN_PREFIX => {
                    let rl =
                        u32::from_le_bytes([self.hdr[4], self.hdr[5], self.hdr[6], self.hdr[7]]);
                    self.remaining = (len - BEGIN_PREFIX) as u16;
                    self.in_body = self.remaining > 0;
                    return (used, Event::Begin(self.channel, rl));
                }
                _ => return (used, Event::Error),
            }
            self.remaining = len as u16;
            self.in_body = true;
        }
        let take = (input.len() - used).min(self.remaining as usize);
        let bytes = &input[used..used + take];
        used += take;
        self.remaining -= take as u16;
        if self.remaining == 0 {
            self.in_body = false;
        }
        if self.kind == KIND_BEGIN || self.kind == KIND_MORE {
            return if take == 0 {
                (used, Event::None)
            } else {
                (used, Event::Data(self.channel, bytes))
            };
        }
        let at = self.ctrl_len as usize;
        self.ctrl[at..at + take].copy_from_slice(bytes);
        self.ctrl_len += take as u16;
        if self.in_body {
            return (used, Event::None);
        }
        let body = &self.ctrl[..self.ctrl_len as usize];
        let ev = match self.kind {
            KIND_HELLO => Event::Hello(self.channel, body),
            KIND_REFUSE => Event::Refuse(body[0]),
            _ => Event::Credit(
                self.channel,
                u32::from_le_bytes([body[0], body[1], body[2], body[3]]),
            ),
        };
        (used, ev)
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
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
        v = v * 10 + (b - b'0') as u64;
    }
    u32::try_from(v).ok()
}
