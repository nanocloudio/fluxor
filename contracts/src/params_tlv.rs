//! The params TLV a module is instantiated with, as the kernel side reads and
//! amends it.
//!
//! Layout (v1, the only version): `[0xFE][0x01][len u16 LE]`, then the basic
//! section of `[tag][len u8][value]` entries ended by `0xFF 0x00`, then any
//! extended entries (`[tag][0x00][len u16 BE][payload]`: certificates, keys,
//! trust bundles) up to the blob's own length. The header's `len` is advisory
//! and saturates past 64 KiB, so the basic section's end is always found by
//! walking to the terminator.

/// The params TLV's magic byte.
pub const TLV_MAGIC: u8 = 0xFE;
/// The params TLV's version byte. There is one version.
pub const TLV_VERSION: u8 = 0x01;
/// The tag that ends the basic section.
pub const TLV_END: u8 = 0xFF;
/// Tags at and above this are kernel metadata, never a module's declared
/// params.
pub const FIRST_RESERVED_TAG: u8 = 0xF0;

/// Where the basic section's terminator sits in the first `len` bytes of
/// `blob`, walking entries from offset 4. `None` when no terminator lies
/// inside them.
pub fn terminator_at(blob: &[u8], len: usize) -> Option<usize> {
    let len = len.min(blob.len());
    let mut p = 4usize;
    while p + 2 <= len {
        let tag = *blob.get(p)?;
        if tag == TLV_END {
            return Some(p);
        }
        p += 2 + usize::from(*blob.get(p + 1)?);
    }
    None
}

/// Call `f(tag, value)` for each declared param (tag below
/// [`FIRST_RESERVED_TAG`]) of a v1 params blob, in order, up to the
/// terminator. No-op on a blob that is not one.
pub fn walk_declared<F: FnMut(u8, &[u8])>(blob: &[u8], mut f: F) {
    if blob.get(..2) != Some(&[TLV_MAGIC, TLV_VERSION][..]) || blob.len() < 4 {
        return;
    }
    let mut off = 4usize;
    while let (Some(&tag), Some(&elen)) = (blob.get(off), blob.get(off + 1)) {
        let start = off + 2;
        let Some(value) = blob.get(start..start + usize::from(elen)) else {
            break;
        };
        if tag == TLV_END {
            break;
        }
        if tag < FIRST_RESERVED_TAG {
            f(tag, value);
        }
        off = start + value.len();
    }
}

/// What [`merge_overrides`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Merged {
    /// The merged blob's length.
    pub len: usize,
    /// Overrides left out because `buf` had no room for them. The compiled
    /// value stands for each.
    pub dropped: usize,
}

/// The bytes `n` overrides of `value_bytes` total value bytes may add to a
/// compiled params blob: their entries, plus a header and terminator when
/// the blob has none. What a merge buffer reserves past the compiled params.
pub const fn merge_room(n: usize, value_bytes: usize) -> usize {
    2 * n + value_bytes + 4 + 2
}

/// Merge runtime `overrides` into the params blob in `buf[..len]`, in place.
///
/// Each override becomes a `[tag][len][value]` entry inserted just before the
/// basic section's terminator, so `parse_tlv`'s last-writer-wins gives it
/// precedence. Everything from the terminator on — the terminator itself and
/// every extended entry after it — is moved up whole, byte for byte. A blob
/// with no params gets a v1 header and a terminator. Overrides are taken in
/// order while they fit in `buf`; the rest are counted in
/// [`Merged::dropped`]. The header's advisory length is rewritten to the new
/// basic section, saturating.
///
/// Nothing is merged into a blob that is not a v1 params blob (a module's
/// params in some other encoding): every override is dropped and the blob is
/// left as it was. An override tagged [`TLV_END`] is dropped too, with every
/// override after it: as an entry it would end the basic section early and
/// turn the entries behind it into garbage.
pub fn merge_overrides<'a, I>(buf: &mut [u8], len: usize, overrides: I) -> Merged
where
    I: Iterator<Item = (u8, &'a [u8])> + Clone,
{
    // Every access below is checked (`get`, `get_mut`), never indexed: a
    // module links this, and an indexing panic would carry a panic location
    // into it.
    let mut len = len.min(buf.len());
    let refuse = |len: usize, overrides: I| Merged {
        len,
        dropped: overrides.count(),
    };
    match buf.get_mut(..4) {
        None => return refuse(len, overrides),
        Some([magic, version, lo, hi]) if len < 4 => {
            *magic = TLV_MAGIC;
            *version = TLV_VERSION;
            *lo = 0;
            *hi = 0;
            len = 4;
        }
        Some([magic, version, ..]) if *magic == TLV_MAGIC && *version == TLV_VERSION => {}
        Some(_) => return refuse(len, overrides),
    }
    // Insert before the terminator; with none, append and terminate.
    let (at, need_end) = match terminator_at(buf, len) {
        Some(t) => (t, 0usize),
        None => (len, 2usize),
    };
    let room = buf.len().saturating_sub(len + need_end);
    let mut add = 0usize;
    let mut taken = 0usize;
    let mut dropped = 0usize;
    for (tag, v) in overrides.clone() {
        let entry = 2 + v.len();
        if dropped == 0 && tag != TLV_END && v.len() <= usize::from(u8::MAX) && add + entry <= room
        {
            add += entry;
            taken += 1;
        } else {
            dropped += 1;
        }
    }
    // Move the terminator and everything after it up by `add`, from the end.
    for i in (at..len).rev() {
        if let Some(b) = buf.get(i).copied() {
            if let Some(d) = buf.get_mut(i + add) {
                *d = b;
            }
        }
    }
    let mut w = at;
    for (tag, v) in overrides.take(taken) {
        put(buf, w, tag);
        put(buf, w + 1, v.len() as u8);
        for (k, b) in v.iter().enumerate() {
            put(buf, w + 2 + k, *b);
        }
        w += 2 + v.len();
    }
    let mut new_len = len + add;
    if need_end != 0 {
        put(buf, new_len, TLV_END);
        put(buf, new_len + 1, 0x00);
        new_len += 2;
    }
    // Advisory: the basic section runs to the byte after its terminator.
    let basic = (at + add + 2).saturating_sub(4);
    let [lo, hi] = u16::try_from(basic).unwrap_or(u16::MAX).to_le_bytes();
    put(buf, 2, lo);
    put(buf, 3, hi);
    Merged {
        len: new_len,
        dropped,
    }
}

/// `buf[at] = b`, where `at` lies inside `buf` (the merge sized every
/// write against `buf.len()` first).
fn put(buf: &mut [u8], at: usize, b: u8) {
    if let Some(d) = buf.get_mut(at) {
        *d = b;
    }
}
