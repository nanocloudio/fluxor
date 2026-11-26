// A module's parameter schema: what the `.fmod` says about each param the
// module takes, so the composer packs, bounds and names them without
// module-specific code. `define_params!` writes it (at compile time, sized
// exactly), the packer finds its end and the composer reads it, all through
// this one codec.
//
// ```text
// [b'S'][b'P'][VERSION][count u8]
// per param:
//   [tag u8][type u8][default u32][min u32][max u32]
//   [name_len u8][name]
//   [enum_count u8] then per enum value: [value u8][name_len u8][name]
// ```
//
// Integers are little-endian. `min` and `max` are always present, inclusive,
// and mean by type: an integer's value; a `str`'s bytes (at most 255, one
// TLV entry); a `u16_array`'s elements; a `blob`'s or `str_chunked`'s total
// bytes. A param declaring none takes its type's ceiling ([`type_ceiling`]).

/// The schema's first two bytes.
pub const MAGIC: [u8; 2] = *b"SP";
/// Its layout.
pub const VERSION: u8 = 1;
/// Bytes before the first param.
pub const HEADER: usize = 4;
/// Bytes of a param before its name.
pub const PARAM_FIXED: usize = 14;

/// Param type ids.
pub mod ty {
    pub const U8: u8 = 0;
    pub const U16: u8 = 1;
    pub const U32: u8 = 2;
    /// One TLV entry of bytes.
    pub const STR: u8 = 3;
    pub const U16_ARRAY: u8 = 4;
    /// Bytes carried in 255-byte entries, the first opening with the
    /// blob's `u16` length.
    pub const BLOB: u8 = 5;
    /// A `str` the packer splits across entries under one tag, for a
    /// handler that appends each chunk.
    pub const STR_CHUNKED: u8 = 6;
    /// The largest type id.
    pub const MAX: u8 = STR_CHUNKED;
}

/// The largest bound a param of type `ptype` can state: an integer's
/// largest value, a `str`'s one-entry 255 bytes, a `blob`'s `u16` length,
/// any other's `u32`.
pub const fn type_ceiling(ptype: u8) -> u32 {
    match ptype {
        ty::U8 | ty::STR => u8::MAX as u32,
        ty::U16 | ty::BLOB => u16::MAX as u32,
        _ => u32::MAX,
    }
}

/// Whether a param of type `ptype` is an integer, whose bounds are its
/// value's.
pub const fn is_integer(ptype: u8) -> bool {
    matches!(ptype, ty::U8 | ty::U16 | ty::U32)
}

/// One param as `define_params!` declares it.
#[derive(Clone, Copy)]
pub struct Entry<'a> {
    pub tag: u8,
    pub ptype: u8,
    pub default: u32,
    pub min: u32,
    pub max: u32,
    pub name: &'a str,
    pub enums: &'a [(&'a str, u8)],
}

/// The bytes [`encode`] writes for `entries`.
pub const fn encoded_len(entries: &[Entry<'_>]) -> usize {
    let mut n = HEADER;
    let mut i = 0;
    while i < entries.len() {
        let e = &entries[i];
        n += PARAM_FIXED + 1 + e.name.len() + 1;
        let mut j = 0;
        while j < e.enums.len() {
            n += 2 + e.enums[j].0.len();
            j += 1;
        }
        i += 1;
    }
    n
}

// `check` and the encoders are `#[inline]`: their refusals are messages, and
// a message is a table of pointers a module may not carry, so they are
// generated only where they are called — at compile time in a module
// (`define_params!`), at run time only in a host tool.

/// Refuse, at compile time, a declaration the schema cannot state: two
/// params on one tag, a bound past the type's ceiling, `min` above `max`,
/// an integer default outside its bounds, a name or enum list longer than a
/// byte counts.
#[inline]
pub const fn check(entries: &[Entry<'_>]) {
    assert!(entries.len() <= 255, "define_params!: more than 255 params");
    let mut i = 0;
    while i < entries.len() {
        let e = &entries[i];
        assert!(e.ptype <= ty::MAX, "define_params!: unknown param type");
        assert!(e.tag != 0xFF, "define_params!: tag 0xFF ends a params TLV");
        assert!(
            e.min <= e.max,
            "define_params!: a param's min is above its max"
        );
        assert!(
            e.max <= type_ceiling(e.ptype),
            "define_params!: a param's bound is past its type's ceiling"
        );
        assert!(
            !is_integer(e.ptype) || (e.default >= e.min && e.default <= e.max),
            "define_params!: an integer param's default is outside its bounds"
        );
        assert!(
            e.name.len() <= 255,
            "define_params!: a param name past 255 bytes"
        );
        assert!(
            e.enums.len() <= 255,
            "define_params!: more than 255 enum values"
        );
        let mut j = i + 1;
        while j < entries.len() {
            assert!(
                entries[j].tag != e.tag,
                "define_params!: two params declare the same tag"
            );
            j += 1;
        }
        i += 1;
    }
}

/// Write `entries` as a schema of exactly `N` bytes ([`encoded_len`]).
#[inline]
pub const fn encode<const N: usize>(entries: &[Entry<'_>]) -> [u8; N] {
    let mut b = [0u8; N];
    let n = encode_into(entries, &mut b);
    assert!(n == N, "param_schema::encode: N is not encoded_len");
    b
}

/// Write `entries` into `b`, which holds at least [`encoded_len`] bytes;
/// the bytes written.
#[inline]
pub const fn encode_into(entries: &[Entry<'_>], b: &mut [u8]) -> usize {
    check(entries);
    assert!(
        b.len() >= encoded_len(entries),
        "param_schema::encode_into: short buffer"
    );
    b[0] = MAGIC[0];
    b[1] = MAGIC[1];
    b[2] = VERSION;
    b[3] = entries.len() as u8;
    let mut at = HEADER;
    let mut i = 0;
    while i < entries.len() {
        let e = &entries[i];
        b[at] = e.tag;
        b[at + 1] = e.ptype;
        at = put_u32(b, at + 2, e.default);
        at = put_u32(b, at, e.min);
        at = put_u32(b, at, e.max);
        at = put_str(b, at, e.name.as_bytes());
        b[at] = e.enums.len() as u8;
        at += 1;
        let mut j = 0;
        while j < e.enums.len() {
            b[at] = e.enums[j].1;
            at = put_str(b, at + 1, e.enums[j].0.as_bytes());
            j += 1;
        }
        i += 1;
    }
    at
}

const fn put_u32(b: &mut [u8], at: usize, v: u32) -> usize {
    let v = v.to_le_bytes();
    b[at] = v[0];
    b[at + 1] = v[1];
    b[at + 2] = v[2];
    b[at + 3] = v[3];
    at + 4
}

const fn put_str(b: &mut [u8], at: usize, s: &[u8]) -> usize {
    b[at] = s.len() as u8;
    let mut k = 0;
    while k < s.len() {
        b[at + 1 + k] = s[k];
        k += 1;
    }
    at + 1 + s.len()
}

/// One param of a schema, as [`for_each_param`] reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Param<'a> {
    pub tag: u8,
    pub ptype: u8,
    pub default: u32,
    pub min: u32,
    pub max: u32,
    pub name: &'a [u8],
    /// The param's enum list: `[value u8][name_len u8][name]` each.
    pub enums: &'a [u8],
    pub enum_count: u8,
}

impl<'a> Param<'a> {
    /// Each enum value as `(name, value)`.
    pub fn for_each_enum(&self, mut f: impl FnMut(&'a [u8], u8)) {
        let mut at = 0;
        for _ in 0..self.enum_count {
            let (Some(&v), Some(&n)) = (self.enums.get(at), self.enums.get(at + 1)) else {
                return;
            };
            let Some(name) = self.enums.get(at + 2..at + 2 + n as usize) else {
                return;
            };
            f(name, v);
            at += 2 + n as usize;
        }
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Read the param at `at`: it and the offset past it, or `None` when it is
/// malformed or runs past `b`.
fn read_param(b: &[u8], at: usize) -> Option<(Param<'_>, usize)> {
    let fixed = b.get(at..at + PARAM_FIXED)?;
    let (ptype, default, min, max) = (
        fixed[1],
        u32_at(fixed, 2),
        u32_at(fixed, 6),
        u32_at(fixed, 10),
    );
    if ptype > ty::MAX || min > max || max > type_ceiling(ptype) {
        return None;
    }
    let name_at = at + PARAM_FIXED + 1;
    let name = b.get(name_at..name_at + *b.get(at + PARAM_FIXED)? as usize)?;
    let mut e = name_at + name.len();
    let enum_count = *b.get(e)?;
    e += 1;
    let enums_at = e;
    for _ in 0..enum_count {
        let n = *b.get(e + 1)? as usize;
        e += 2 + n;
        if e > b.len() {
            return None;
        }
    }
    Some((
        Param {
            tag: fixed[0],
            ptype,
            default,
            min,
            max,
            name,
            enums: &b[enums_at..e],
            enum_count,
        },
        e,
    ))
}

/// The schema's exact length, walked from its header; `None` when it is not
/// a schema or a param is malformed.
pub fn schema_len(b: &[u8]) -> Option<usize> {
    if b.len() < HEADER || b[..2] != MAGIC || b[2] != VERSION {
        return None;
    }
    let mut at = HEADER;
    for _ in 0..b[3] {
        at = read_param(b, at)?.1;
    }
    Some(at)
}

/// Call `f` for each param of schema `b`. Nothing for a malformed schema:
/// [`schema_len`] says which.
pub fn for_each_param<'a>(b: &'a [u8], mut f: impl FnMut(Param<'a>)) {
    if schema_len(b).is_none() {
        return;
    }
    let mut at = HEADER;
    for _ in 0..b[3] {
        let Some((p, next)) = read_param(b, at) else {
            return;
        };
        f(p);
        at = next;
    }
}
