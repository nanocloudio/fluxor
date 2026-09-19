// Contract: dns_wire — the DNS message codec shared by the `dns` server and
// the `ip` stub resolver.
//
// Layer: contracts/net (public, stable).
//
// RFC 1035 message framing: the 12-byte header, names in label form with
// backward-only compression pointers, the question, and the resource-record
// envelope. Nothing here decides what a message means — `dns` serves and
// forwards with it, `ip` asks one question and reads one address out of the
// answer — so both speak the same bytes and neither carries a private copy.
//
// Two shapes of API live here. The pointer-and-length functions are what a
// module driving a raw packet buffer calls; the slice functions
// (`read_header` / `write_header`, and `build_query` / `parse_answer_a`,
// which compose the rest for the stub-resolver case) are for a caller that
// already holds the message as a slice.
//
// Names cross the boundary in dotted presentation form. Every decoder here
// (`extract_qname`, `read_name`, `copy_name_lower`) lowercases as it goes,
// so a name that came off the wire is lowercase; the encoders send the case
// they are handed, and a comparison that may meet either case uses
// `name_eq_fold`.

// ── Message constants ────────────────────────────────────────────────────

/// Bytes of the fixed header: ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT.
pub const DNS_HEADER_LEN: usize = 12;
/// Largest UDP DNS message without EDNS (RFC 1035 §4.2.1).
pub const DNS_MAX_PACKET: usize = 512;

/// Record types.
pub const QTYPE_A: u16 = 1;
pub const QTYPE_NS: u16 = 2;
pub const QTYPE_CNAME: u16 = 5;
pub const QTYPE_SOA: u16 = 6;
pub const QTYPE_PTR: u16 = 12;
pub const QTYPE_MX: u16 = 15;
pub const QTYPE_TXT: u16 = 16;
pub const QTYPE_AAAA: u16 = 28;
pub const QTYPE_DNAME: u16 = 39;
pub const QTYPE_OPT: u16 = 41;
pub const QTYPE_TSIG: u16 = 250;
pub const QTYPE_ANY: u16 = 255;
/// Record classes.
pub const QCLASS_IN: u16 = 1;
pub const QCLASS_NONE: u16 = 254;
pub const QCLASS_ANY: u16 = 255;

/// Header flag bits.
pub const FLAG_QR: u16 = 0x8000; // Response
pub const FLAG_AA: u16 = 0x0400; // Authoritative
pub const FLAG_TC: u16 = 0x0200; // Truncated
pub const FLAG_RA: u16 = 0x0080; // Recursion available
pub const FLAG_RD: u16 = 0x0100; // Recursion desired
pub const FLAG_AD: u16 = 0x0020; // Authentic data
pub const FLAG_CD: u16 = 0x0010; // Checking disabled
pub const RCODE_MASK: u16 = 0x000F;
pub const RCODE_NOERROR: u16 = 0x0000;
pub const RCODE_FORMERR: u16 = 0x0001;
pub const RCODE_SERVFAIL: u16 = 0x0002;
pub const RCODE_NXDOMAIN: u16 = 0x0003;
pub const RCODE_NOTIMP: u16 = 0x0004;
pub const RCODE_REFUSED: u16 = 0x0005;
pub const RCODE_YXDOMAIN: u16 = 0x0006;
pub const RCODE_YXRRSET: u16 = 0x0007;
pub const RCODE_NXRRSET: u16 = 0x0008;
pub const RCODE_NOTAUTH: u16 = 0x0009;
pub const RCODE_NOTZONE: u16 = 0x000A;

/// The DO bit in an OPT record's extended flags (RFC 6891 §6.1.4).
pub const EDNS_DO: u16 = 0x8000;

/// Opcode field of the header flags word (bits 11..14).
pub const FLAG_OPCODE_MASK: u16 = 0x7800;
pub const FLAG_OPCODE_SHIFT: u32 = 11;

/// Opcode 0 is a standard query; opcode 5 is UPDATE (RFC 2136).
pub const OPCODE_QUERY: u8 = 0;
pub const OPCODE_UPDATE: u8 = 5;

/// Maximum dotted domain name length, in bytes. This is the DNS full-name
/// ceiling (RFC 1035 §2.3.4), not the 63-byte per-label ceiling — a name of
/// several ordinary labels must fit.
pub const MAX_NAME_LEN: usize = 255;

/// Maximum length of one wire-format label (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// Compression-pointer hops followed while decoding one name before the
/// packet is refused as malformed. A legal name needs far fewer; a pointer
/// cycle needs the bound.
pub const MAX_NAME_PTR_HOPS: usize = 16;

/// Resource records examined in any one section of a message; a section
/// claiming more is refused rather than walked.
pub const MAX_SECTION_RRS: usize = 32;

/// Port a DNS server listens on.
pub const DNS_PORT: u16 = 53;

// ── Header ───────────────────────────────────────────────────────────────

/// The fixed header, decoded.
#[derive(Clone, Copy)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

/// Decode the header at the front of `pkt`; `None` when the packet is
/// shorter than a header.
pub fn read_header(pkt: &[u8]) -> Option<Header> {
    if pkt.len() < DNS_HEADER_LEN {
        return None;
    }
    let w = |i: usize| u16::from_be_bytes([pkt[i], pkt[i + 1]]);
    Some(Header {
        id: w(0),
        flags: w(2),
        qdcount: w(4),
        ancount: w(6),
        nscount: w(8),
        arcount: w(10),
    })
}

/// Write `h` at the front of `out`, which holds at least `DNS_HEADER_LEN`
/// bytes.
pub fn write_header(out: &mut [u8], h: &Header) {
    out[0..2].copy_from_slice(&h.id.to_be_bytes());
    out[2..4].copy_from_slice(&h.flags.to_be_bytes());
    out[4..6].copy_from_slice(&h.qdcount.to_be_bytes());
    out[6..8].copy_from_slice(&h.ancount.to_be_bytes());
    out[8..10].copy_from_slice(&h.nscount.to_be_bytes());
    out[10..12].copy_from_slice(&h.arcount.to_be_bytes());
}

// ── Names ────────────────────────────────────────────────────────────────

/// Extract QNAME from the question section. Converts wire-format labels to a
/// dotted lowercase name. Returns the name length, or 0 on error, and
/// advances `*offset` past the QNAME. Questions carry no compression
/// pointers; one is refused as malformed.
///
/// # Safety
/// `pkt` is valid for `pkt_len` bytes; `name_buf` for `MAX_NAME_LEN`.
pub unsafe fn extract_qname(
    pkt: *const u8,
    pkt_len: usize,
    offset: &mut usize,
    name_buf: *mut u8,
) -> usize {
    let mut name_pos = 0usize;
    let mut off = *offset;

    loop {
        if off >= pkt_len {
            return 0;
        }
        let label_len = *pkt.add(off) as usize;
        off += 1;

        if label_len == 0 {
            break; // root label
        }

        if label_len > MAX_LABEL_LEN || off + label_len > pkt_len {
            return 0;
        }

        // Dot separator (not before the first label).
        if name_pos > 0 {
            if name_pos >= MAX_NAME_LEN {
                return 0;
            }
            *name_buf.add(name_pos) = b'.';
            name_pos += 1;
        }

        // Copy label bytes, lowercased.
        let mut i = 0;
        while i < label_len {
            if name_pos >= MAX_NAME_LEN {
                return 0;
            }
            let mut b = *pkt.add(off + i);
            if b.is_ascii_uppercase() {
                b += 32;
            }
            *name_buf.add(name_pos) = b;
            name_pos += 1;
            i += 1;
        }
        off += label_len;
    }

    *offset = off;
    name_pos
}

/// Encode a dotted name into wire-format labels at `dst`. Returns the bytes
/// written, or 0 when a label is empty or over `MAX_LABEL_LEN`.
///
/// # Safety
/// `name` is valid for `name_len` bytes; `dst` for `name_len + 2`.
pub unsafe fn encode_name(name: *const u8, name_len: usize, dst: *mut u8) -> usize {
    let mut pos = 0usize;
    let mut label_start = 0usize;

    let mut i = 0;
    while i <= name_len {
        if i == name_len || *name.add(i) == b'.' {
            let label_len = i - label_start;
            if label_len == 0 || label_len > MAX_LABEL_LEN {
                return 0;
            }
            *dst.add(pos) = label_len as u8;
            pos += 1;
            let mut j = label_start;
            while j < i {
                *dst.add(pos) = *name.add(j);
                pos += 1;
                j += 1;
            }
            label_start = i + 1;
        }
        i += 1;
    }

    // Root label terminator.
    *dst.add(pos) = 0;
    pos += 1;
    pos
}

/// Decode the name at `off`, following compression pointers under
/// `MAX_NAME_PTR_HOPS`, into dotted lowercase `out` (at least
/// `MAX_NAME_LEN + 1` bytes). Returns the dotted length and the offset just
/// past the name's in-place bytes, or `None` when malformed. The root name
/// decodes to length 0.
///
/// # Safety
/// `pkt` is valid for `pkt_len` bytes; `out` for `MAX_NAME_LEN + 1`.
pub unsafe fn read_name(
    pkt: *const u8,
    pkt_len: usize,
    off: usize,
    out: *mut u8,
) -> Option<(usize, usize)> {
    let mut pos = off;
    let mut name_pos = 0usize;
    let mut next: Option<usize> = None;
    let mut hops = 0usize;
    loop {
        if pos >= pkt_len {
            return None;
        }
        let b = *pkt.add(pos) as usize;
        if b == 0 {
            pos += 1;
            break;
        }
        if b & 0xC0 == 0xC0 {
            if pos + 1 >= pkt_len {
                return None;
            }
            let target = ((b & 0x3F) << 8) | *pkt.add(pos + 1) as usize;
            // A pointer only ever refers backwards, so a cycle needs the hop
            // bound only as a second line.
            if target >= pos || target < DNS_HEADER_LEN {
                return None;
            }
            hops += 1;
            if hops > MAX_NAME_PTR_HOPS {
                return None;
            }
            if next.is_none() {
                next = Some(pos + 2);
            }
            pos = target;
            continue;
        }
        if b & 0xC0 != 0 || b > MAX_LABEL_LEN || pos + 1 + b > pkt_len {
            return None;
        }
        if name_pos > 0 {
            if name_pos >= MAX_NAME_LEN {
                return None;
            }
            *out.add(name_pos) = b'.';
            name_pos += 1;
        }
        let mut i = 0;
        while i < b {
            if name_pos >= MAX_NAME_LEN {
                return None;
            }
            let mut c = *pkt.add(pos + 1 + i);
            if c.is_ascii_uppercase() {
                c += 32;
            }
            *out.add(name_pos) = c;
            name_pos += 1;
            i += 1;
        }
        pos += 1 + b;
    }
    Some((name_pos, next.unwrap_or(pos)))
}

/// Byte equality of two dotted lowercase names.
///
/// # Safety
/// `a` and `b` are valid for `a_len` and `b_len` bytes.
pub unsafe fn names_equal(a: *const u8, a_len: usize, b: *const u8, b_len: usize) -> bool {
    if a_len != b_len {
        return false;
    }
    let mut i = 0;
    while i < a_len {
        if *a.add(i) != *b.add(i) {
            return false;
        }
        i += 1;
    }
    true
}

/// Lowercase ASCII copy of `len` bytes, dropping one trailing dot. Returns
/// the bytes written, or 0 when the name is empty or does not fit `cap`.
///
/// # Safety
/// `src` is valid for `len` bytes; `dst` for `cap`.
pub unsafe fn copy_name_lower(dst: *mut u8, cap: usize, src: *const u8, len: usize) -> usize {
    let mut n = len;
    if n > 0 && *src.add(n - 1) == b'.' {
        n -= 1;
    }
    if n == 0 || n > cap {
        return 0;
    }
    let mut i = 0;
    while i < n {
        let mut c = *src.add(i);
        if c.is_ascii_uppercase() {
            c += 32;
        }
        *dst.add(i) = c;
        i += 1;
    }
    n
}

// ── Resource records ─────────────────────────────────────────────────────

/// One parsed resource record; `owner` was written to the caller's buffer.
#[derive(Clone, Copy)]
pub struct RrView {
    pub owner_len: usize,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdlen: usize,
    /// Offset of the first RDATA byte.
    pub rdata_off: usize,
    /// Offset of the record's first byte.
    pub start: usize,
    /// Offset just past the record.
    pub next: usize,
}

/// Parse the record at `off`; the owner goes to `name_buf`.
///
/// # Safety
/// `pkt` is valid for `pkt_len` bytes; `name_buf` for `MAX_NAME_LEN + 1`.
pub unsafe fn parse_rr(
    pkt: *const u8,
    pkt_len: usize,
    off: usize,
    name_buf: *mut u8,
) -> Option<RrView> {
    let (owner_len, p) = read_name(pkt, pkt_len, off, name_buf)?;
    if p + 10 > pkt_len {
        return None;
    }
    let rtype = u16::from_be_bytes([*pkt.add(p), *pkt.add(p + 1)]);
    let rclass = u16::from_be_bytes([*pkt.add(p + 2), *pkt.add(p + 3)]);
    let ttl = u32::from_be_bytes([
        *pkt.add(p + 4),
        *pkt.add(p + 5),
        *pkt.add(p + 6),
        *pkt.add(p + 7),
    ]);
    let rdlen = u16::from_be_bytes([*pkt.add(p + 8), *pkt.add(p + 9)]) as usize;
    if p + 10 + rdlen > pkt_len {
        return None;
    }
    Some(RrView {
        owner_len,
        rtype,
        rclass,
        ttl,
        rdlen,
        rdata_off: p + 10,
        start: off,
        next: p + 10 + rdlen,
    })
}

/// Skip `count` records starting at `off`, returning the offset past them.
///
/// # Safety
/// `pkt` is valid for `pkt_len` bytes.
pub unsafe fn skip_rrs(pkt: *const u8, pkt_len: usize, off: usize, count: usize) -> Option<usize> {
    if count > MAX_SECTION_RRS {
        return None;
    }
    let mut scratch = [0u8; MAX_NAME_LEN + 1];
    let mut pos = off;
    let mut i = 0;
    while i < count {
        let rr = parse_rr(pkt, pkt_len, pos, scratch.as_mut_ptr())?;
        pos = rr.next;
        i += 1;
    }
    Some(pos)
}

// ── Byte helpers ─────────────────────────────────────────────────────────

/// Copy `n` bytes.
///
/// # Safety
/// `src` is valid for `n` bytes of reads and `dst` for `n` bytes of writes;
/// the ranges do not overlap.
#[inline(always)]
pub unsafe fn copy_bytes(dst: *mut u8, src: *const u8, n: usize) {
    let mut i = 0;
    while i < n {
        *dst.add(i) = *src.add(i);
        i += 1;
    }
}

/// Write a big-endian u16.
///
/// # Safety
/// `dst` is valid for 2 bytes of writes.
#[inline(always)]
pub unsafe fn put_u16(dst: *mut u8, v: u16) {
    let b = v.to_be_bytes();
    *dst = b[0];
    *dst.add(1) = b[1];
}

/// Write a big-endian u32.
///
/// # Safety
/// `dst` is valid for 4 bytes of writes.
#[inline(always)]
pub unsafe fn put_u32(dst: *mut u8, v: u32) {
    let b = v.to_be_bytes();
    copy_bytes(dst, b.as_ptr(), 4);
}

// ── Stub-resolver composition ────────────────────────────────────────────

/// Compose a recursion-desired query for `(qname, qtype, IN)` into `out`,
/// answering its length, or 0 when the name does not encode or `out` cannot
/// hold it. `qname` is dotted presentation form; case is sent as given.
pub fn build_query(id: u16, qname: &[u8], qtype: u16, out: &mut [u8]) -> usize {
    // Header, labels (one length byte per label plus the root), QTYPE, QCLASS.
    let need = DNS_HEADER_LEN + qname.len() + 2 + 4;
    if qname.is_empty() || qname.len() > MAX_NAME_LEN || out.len() < need {
        return 0;
    }
    write_header(
        out,
        &Header {
            id,
            flags: FLAG_RD,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        },
    );
    // SAFETY: `out` holds `need` bytes and `encode_name` writes at most
    // `qname.len() + 2` from `DNS_HEADER_LEN`.
    let n = unsafe {
        encode_name(
            qname.as_ptr(),
            qname.len(),
            out.as_mut_ptr().add(DNS_HEADER_LEN),
        )
    };
    if n == 0 {
        return 0;
    }
    let p = DNS_HEADER_LEN + n;
    out[p..p + 2].copy_from_slice(&qtype.to_be_bytes());
    out[p + 2..p + 4].copy_from_slice(&QCLASS_IN.to_be_bytes());
    p + 4
}

/// What an A answer said about the name it was asked for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AnswerA {
    /// An address for the name, with the record's TTL in seconds.
    Address([u8; 4], u32),
    /// A correlated answer with no address: NXDOMAIN, another error code,
    /// or NOERROR whose answer section held no A record as far as it could
    /// be read.
    Negative,
    /// Not an answer to this question — wrong id, not a response, a
    /// different question, or malformed — and to be ignored.
    Unrelated,
}

/// Read the answer to the query `build_query(id_expected, qname, QTYPE_A, …)`
/// composed. The message must be a response carrying that id and repeating
/// that question (name compared case-insensitively). The first IN A record
/// in the answer section is taken; an answer section that resolves a CNAME
/// chain lists the chain's terminal A after the CNAMEs, so the first A is
/// the one the name reaches. A truncated response is read as far as it goes.
pub fn parse_answer_a(pkt: &[u8], id_expected: u16, qname: &[u8]) -> AnswerA {
    let Some(h) = read_header(pkt) else {
        return AnswerA::Unrelated;
    };
    if h.id != id_expected || h.flags & FLAG_QR == 0 || h.qdcount != 1 {
        return AnswerA::Unrelated;
    }
    let mut name = [0u8; MAX_NAME_LEN + 1];
    let mut off = DNS_HEADER_LEN;
    // SAFETY: `pkt` is a live slice; `name` holds `MAX_NAME_LEN + 1`.
    let qlen = unsafe { extract_qname(pkt.as_ptr(), pkt.len(), &mut off, name.as_mut_ptr()) };
    if qlen == 0 || off + 4 > pkt.len() {
        return AnswerA::Unrelated;
    }
    let qtype = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
    let qclass = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
    if qtype != QTYPE_A || qclass != QCLASS_IN || !name_eq_fold(&name[..qlen], qname) {
        return AnswerA::Unrelated;
    }
    if h.flags & RCODE_MASK != RCODE_NOERROR {
        return AnswerA::Negative;
    }
    let mut pos = off + 4;
    let count = usize::from(h.ancount).min(MAX_SECTION_RRS);
    let mut i = 0;
    while i < count {
        // SAFETY: as above.
        let Some(rr) = (unsafe { parse_rr(pkt.as_ptr(), pkt.len(), pos, name.as_mut_ptr()) })
        else {
            break;
        };
        if rr.rtype == QTYPE_A && rr.rclass == QCLASS_IN && rr.rdlen == 4 {
            let a = &pkt[rr.rdata_off..rr.rdata_off + 4];
            return AnswerA::Address([a[0], a[1], a[2], a[3]], rr.ttl);
        }
        pos = rr.next;
        i += 1;
    }
    AnswerA::Negative
}

/// Case-insensitive ASCII equality of two dotted names, ignoring one
/// trailing dot on either side.
pub fn name_eq_fold(a: &[u8], b: &[u8]) -> bool {
    let a = match a.split_last() {
        Some((b'.', rest)) => rest,
        _ => a,
    };
    let b = match b.split_last() {
        Some((b'.', rest)) => rest,
        _ => b,
    };
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}
