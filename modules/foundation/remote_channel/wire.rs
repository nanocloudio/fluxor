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
//! | `HELLO` | `"FXRC"[count:1]` then per channel `[ct_len:1][content_type][max_record:4 LE]`, then `[side:1]` when the table carries an exchange endpoint | the sender's whole channel table |
//! | `REFUSE` | `[reason:1]` | the sender is ending the session, and why |
//! | `CREDIT` | `[bytes:4 LE]` | the receiver can take `bytes` more record bytes on `channel` |
//! | `BEGIN` | `[record_len:4 LE][first bytes]` | a record starts on `channel` |
//! | `MORE` | `[bytes]` | the record in progress on `channel` continues |
//! | `ACK` | `[seq:8 LE]` | (resume) every record on `channel` through `seq` has arrived whole |
//! | `RBEGIN` | `[record_len:4 LE][seq:8 LE][first bytes]` | (resume) record `seq` starts on `channel` |
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
//!
//! ## Resume
//!
//! A table with `resume` set numbers every record on every channel from 1,
//! per direction, within the sender's incarnation (16 random bytes drawn at
//! construction). The sender keeps each record in a retained window until
//! the receiver acknowledges it (`ACK`), so a session that ends takes
//! nothing with it: the `HELLO` trailer
//!
//! ```text
//! ['R'][incarnation:16][held:16][next:8 LE × resumed channels]
//! ```
//!
//! names the sender's incarnation, the peer incarnation whose streams the
//! sender holds (`held`, zero for none) and, per channel, the next record
//! it expects of that stream. A peer whose `held` is this side's
//! incarnation is resumed exactly: every record before `next` is released
//! and the rest are sent again from `next` — unless this side gave the
//! peer's streams up (a listener releasing a peer slot after `retain_ms`,
//! or to make room for another peer) and holds none of them: then it
//! numbers what it sends next from `next`, so the peer takes it as the next
//! record, and names no incarnation as `held`. A peer that names another
//! incarnation never saw this stream (its first session, or it restarted
//! and lost it): the retained records are renumbered from 1 and sent to
//! it. Within a session every `RBEGIN` must carry exactly the next number
//! the receiver expects — a record it already has (a replay) or one past
//! it (a gap) is refused with `SEQUENCE` — and an `ACK` may not name a
//! record that was never sent, nor go behind one already released.
//!
//! An exchange endpoint is two more table entries, `ExchangeRequest` and
//! `ExchangeResponse`, both `mailbox` at the exchange contract's record
//! maximum, after the `channels` entries. Requests cross on the first from
//! the near side to the far side and answers on the second the other way;
//! the `HELLO` trailer names the sender's side, and a peer's table matches
//! only when its side is the other one. Under `resume` the endpoint's two
//! channels are the ones not resumed: their records are `BEGIN`, never
//! `RBEGIN`, nothing on them is acknowledged, and the trailer's `next` list
//! covers only the `channels` entries — an exchange a session leaves open
//! is ended with it and issued again by its requester (the exchange
//! contract's LINK), whatever the channels beside it resume.

/// Frame header bytes.
pub const FRAME_HDR: usize = 4;
/// `BEGIN`'s record-length prefix.
pub const BEGIN_PREFIX: usize = 4;
/// `RBEGIN`'s record-length and sequence prefix.
pub const RBEGIN_PREFIX: usize = 12;

pub const KIND_HELLO: u8 = 1;
pub const KIND_REFUSE: u8 = 2;
pub const KIND_CREDIT: u8 = 3;
pub const KIND_BEGIN: u8 = 4;
pub const KIND_MORE: u8 = 5;
/// Resume sessions only: an acknowledgement of whole records.
pub const KIND_ACK: u8 = 6;
/// Resume sessions only: a numbered record starts.
pub const KIND_RBEGIN: u8 = 7;

/// The channel byte of a `net` carrier's `HELLO` and `REFUSE`.
pub const CONTROL: u8 = 0xFF;

/// `HELLO`'s leading magic.
pub const HELLO_MAGIC: [u8; 4] = *b"FXRC";

/// Most `channels` entries one instance carries: one per port pair
/// (`chN`/`chN_rx`), and the manifest declares this many.
pub const PORT_CHANNELS: usize = 8;

/// Most channels one table carries: every `channels` entry, and the
/// exchange endpoint's two after them, which have ports of their own
/// (`request_in` …) and so take no port pair. Each is a reassembly region
/// and a send state, and on `quic` a stream.
pub const MAX_CHANNELS: usize = PORT_CHANNELS + 2;

/// Longest content-type name a channel table carries — longer than any
/// name in the content-type registry.
pub const CT_NAME_MAX: usize = 32;

/// Largest `HELLO` body: every entry at its longest, the side byte, and a
/// resume trailer.
pub const HELLO_MAX: usize = 4 + 1 + MAX_CHANNELS * HELLO_ENTRY_LEN + 1 + RESUME_TRAILER_MAX;
/// The resume trailer's marker byte.
pub const RESUME_MARK: u8 = b'R';
/// An incarnation: 16 random bytes an instance draws at construction.
pub const INCARNATION_LEN: usize = 16;
/// The longest resume trailer: the marker, two incarnations, a `next` per
/// channel.
pub const RESUME_TRAILER_MAX: usize = 1 + 2 * INCARNATION_LEN + 8 * MAX_CHANNELS;
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
    /// Resume: a record out of sequence — one the receiver already has (a
    /// replay) or one past the next it expects (a gap) — or an
    /// acknowledgement or resume point the sender cannot honour.
    pub const SEQUENCE: u8 = 5;
}

/// How records are delimited on a channel's local ports. Local only: the
/// wire carries the record's bytes verbatim, so the two ends agree on
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

/// The longest local header a length framing names: the field's offset and
/// width together.
pub const HDR_MAX: usize = 64;

/// Which side of an exchange endpoint an instance is.
pub mod side {
    /// The instance carries no exchange endpoint.
    pub const NONE: u8 = 0;
    /// Stands in for the remote provider: a local requester's requests in,
    /// the provider's answers out.
    pub const NEAR: u8 = 1;
    /// Stands in for the remote requester: its requests out to the local
    /// provider, the provider's answers in.
    pub const FAR: u8 = 2;

    /// The side a peer must be for the endpoint to pair.
    pub const fn other(side: u8) -> u8 {
        match side {
            NEAR => FAR,
            FAR => NEAR,
            s => s,
        }
    }
}

/// The content types of an exchange endpoint's two channels.
pub const EXCHANGE_REQUEST: &[u8] = b"ExchangeRequest";
pub const EXCHANGE_RESPONSE: &[u8] = b"ExchangeResponse";

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

    pub fn content_type(&self) -> &[u8] {
        &self.content_type[..self.ct_len as usize]
    }

    /// Bytes of local header that announce a record's length — through the
    /// end of its length field — or 0 for a mailbox or a byte stream.
    pub fn header_len(&self) -> usize {
        match self.framing {
            framing::LEN => self.len_off as usize + self.len_width as usize,
            _ => 0,
        }
    }

    /// The whole record's length from its local header (`header_len` bytes).
    pub fn record_len(&self, hdr: &[u8]) -> u64 {
        let at = self.len_off as usize;
        let field = if self.len_width == 2 {
            u16::from_le_bytes([hdr[at], hdr[at + 1]]) as u64
        } else {
            u32::from_le_bytes([hdr[at], hdr[at + 1], hdr[at + 2], hdr[at + 3]]) as u64
        };
        field + self.len_add as u64
    }
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
    let off = parse_u32(&rest[..plus])?;
    let add = parse_u32(&rest[plus + 1..])?;
    if off as usize + width as usize > HDR_MAX {
        return None;
    }
    Some((off as u8, width, add))
}

/// The channel table: `channels` entries, index = position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Table {
    pub channels: u8,
    pub entries: [Entry; MAX_CHANNELS],
    /// This instance's side of the exchange endpoint ([`side`]).
    pub side: u8,
    /// The endpoint's request channel; its response channel is the next.
    pub exchange_at: u8,
    /// Records are numbered and retained until acknowledged, and a session
    /// resumes where the last left off (see the module docs, Resume).
    pub resume: bool,
}

impl Table {
    /// The channels `resume` numbers, retains and resumes: the `channels`
    /// entries, never an exchange endpoint's two, which its requester
    /// issues again when a session ends (they are the table's last).
    pub const fn resumed(&self) -> usize {
        if self.side == side::NONE {
            self.channels as usize
        } else {
            (self.channels as usize).saturating_sub(2)
        }
    }

    pub const EMPTY: Table = Table {
        channels: 0,
        entries: [Entry::EMPTY; MAX_CHANNELS],
        side: side::NONE,
        exchange_at: 0,
        resume: false,
    };

    /// Append an exchange endpoint's two channels, `max_record` each, as
    /// `side`. Refused when the table has no room for both.
    pub fn add_exchange(&mut self, side: u8, max_record: u32) -> Result<(), TableError> {
        let at = self.channels as usize;
        if at + 2 > MAX_CHANNELS {
            return Err(TableError::TooManyChannels);
        }
        for (k, ct) in [EXCHANGE_REQUEST, EXCHANGE_RESPONSE].iter().enumerate() {
            let e = &mut self.entries[at + k];
            e.content_type = [0; CT_NAME_MAX];
            e.content_type[..ct.len()].copy_from_slice(ct);
            e.ct_len = ct.len() as u8;
            e.framing = framing::MAILBOX;
            e.max_record = max_record;
        }
        self.channels += 2;
        self.side = side;
        self.exchange_at = at as u8;
        Ok(())
    }
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
    let mut t = Table::EMPTY;
    let text = trim(text);
    if text.is_empty() {
        return Err(TableError::Empty);
    }
    for item in text.split(|&b| b == b';') {
        let item = trim(item);
        if item.is_empty() {
            continue;
        }
        if t.channels as usize == PORT_CHANNELS {
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
        let fr = trim(fr);
        let (framing, len) = match fr {
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
                    u16::MAX as u64
                } else {
                    u32::MAX as u64
                };
                (
                    (limit as u64).min(add as u64 + field_max) as u32,
                    (off as u32 + width as u32).max(add).max(1),
                )
            }
            None => (limit, 1),
        };
        if max < floor || max > ceiling {
            return Err(TableError::MaxRecord);
        }
        let e = &mut t.entries[t.channels as usize];
        e.content_type[..ct.len()].copy_from_slice(ct);
        e.ct_len = ct.len() as u8;
        e.framing = framing;
        if let Some((off, width, add)) = len {
            e.len_off = off;
            e.len_width = width;
            e.len_add = add;
        }
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
    if t.side != side::NONE {
        out[at] = t.side;
        at += 1;
    }
    at
}

/// The resume trailer's length for this table (0 without `resume`).
pub fn resume_trailer_len(t: &Table) -> usize {
    if t.resume {
        1 + 2 * INCARNATION_LEN + 8 * t.resumed()
    } else {
        0
    }
}

/// Append the resume trailer to a `HELLO` body of `at` bytes: this side's
/// incarnation, the peer incarnation whose streams it holds, and the next
/// record it expects on each resumed channel ([`Table::resumed`]). Returns
/// the new length.
pub fn encode_resume(
    t: &Table,
    incarnation: &[u8; INCARNATION_LEN],
    held: &[u8; INCARNATION_LEN],
    next: &[u64; MAX_CHANNELS],
    out: &mut [u8; HELLO_MAX],
    at: usize,
) -> usize {
    if !t.resume {
        return at;
    }
    let mut at = at;
    out[at] = RESUME_MARK;
    at += 1;
    out[at..at + INCARNATION_LEN].copy_from_slice(incarnation);
    at += INCARNATION_LEN;
    out[at..at + INCARNATION_LEN].copy_from_slice(held);
    at += INCARNATION_LEN;
    for n in &next[..t.resumed()] {
        out[at..at + 8].copy_from_slice(&n.to_le_bytes());
        at += 8;
    }
    at
}

/// A peer's resume trailer: its incarnation, the incarnation whose streams
/// it holds, and the next record it expects per resumed channel (the
/// exchange endpoint's two entries are not resumed and stay 0 here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resume {
    pub incarnation: [u8; INCARNATION_LEN],
    pub held: [u8; INCARNATION_LEN],
    pub next: [u64; MAX_CHANNELS],
}

/// Does a peer's `HELLO` body state exactly this table? Same channel count,
/// per index the same content type and maximum record, an exchange
/// endpoint on the other side of the one this table carries, and a resume
/// trailer exactly when this table resumes.
pub fn hello_matches(t: &Table, body: &[u8]) -> bool {
    hello_parse(t, body).is_some()
}

/// [`hello_matches`], returning the peer's resume trailer (`None` inside
/// when the table does not resume).
pub fn hello_parse(t: &Table, body: &[u8]) -> Option<Option<Resume>> {
    let mut peer = *t;
    peer.side = side::other(t.side);
    let mut want = [0u8; HELLO_MAX];
    let n = encode_hello(&peer, &mut want);
    let tl = resume_trailer_len(t);
    if body.len() != n + tl || body[..n] != want[..n] {
        return None;
    }
    if !t.resume {
        return Some(None);
    }
    let r = &body[n..];
    if r[0] != RESUME_MARK {
        return None;
    }
    let mut out = Resume {
        incarnation: [0; INCARNATION_LEN],
        held: [0; INCARNATION_LEN],
        next: [0; MAX_CHANNELS],
    };
    out.incarnation.copy_from_slice(&r[1..1 + INCARNATION_LEN]);
    out.held
        .copy_from_slice(&r[1 + INCARNATION_LEN..1 + 2 * INCARNATION_LEN]);
    let mut at = 1 + 2 * INCARNATION_LEN;
    for k in 0..t.resumed() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&r[at..at + 8]);
        out.next[k] = u64::from_le_bytes(b);
        if out.next[k] == 0 {
            return None;
        }
        at += 8;
    }
    if out.incarnation == [0; INCARNATION_LEN] {
        return None;
    }
    Some(Some(out))
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
    /// Resume: record `seq`, of `len` bytes, starts on the channel.
    RBegin(u8, u32, u64),
    /// Resume: every record through `seq` arrived whole.
    Ack(u8, u64),
    /// Record bytes on the channel.
    Data(u8, &'a [u8]),
    /// Not a frame this protocol has; the stream cannot be resynchronised.
    Error,
}

/// Incremental parser over one carrier stream. A carrier is reliable and
/// ordered and authenticated beneath this protocol, so there is no resync:
/// a frame that does not parse ends the session.
pub struct Parser {
    hdr: [u8; FRAME_HDR + RBEGIN_PREFIX],
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
            hdr: [0; FRAME_HDR + RBEGIN_PREFIX],
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
        match kind {
            KIND_BEGIN => FRAME_HDR + BEGIN_PREFIX,
            KIND_RBEGIN => FRAME_HDR + RBEGIN_PREFIX,
            _ => FRAME_HDR,
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
                KIND_ACK if len == 8 => {}
                KIND_MORE if len > 0 => {}
                KIND_RBEGIN if len >= RBEGIN_PREFIX => {
                    let h = &self.hdr;
                    let rl = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
                    let seq =
                        u64::from_le_bytes([h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]]);
                    self.remaining = (len - RBEGIN_PREFIX) as u16;
                    self.in_body = self.remaining > 0;
                    return (used, Event::RBegin(self.channel, rl, seq));
                }
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
        if matches!(self.kind, KIND_BEGIN | KIND_RBEGIN | KIND_MORE) {
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
            KIND_ACK => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&body[..8]);
                Event::Ack(self.channel, u64::from_le_bytes(b))
            }
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
