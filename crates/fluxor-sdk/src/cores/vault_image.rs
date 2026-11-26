//! `FXVS` v1, the key vault's record image: one buffer of named records with
//! a sequence and a digest, which the vault keeps in two A/B slots on a
//! block source and the tools write off the device. Pure: no I/O, no state
//! beyond the caller's buffers.
//!
//! ```text
//! [0..4]   "FXVS"            [4]      version 1
//! [8..16]  seq (u64)         [16..18] record count (u16)
//! [20..24] body length (u32) [56..88] SHA-256 over [0..56] ‖ body
//! [96..]   body: per record [name_len:u8][name][blob_len:u16][blob]
//! ```
//!
//! Bytes between the fields, and after the body, are zero. All integers are
//! little-endian.

use crate::crypto::sha256::Sha256;

/// The image's magic, `"FXVS"`, as an integer read little-endian.
const MAGIC: [u8; 4] = *b"FXVS";
pub const VERSION: u8 = 1;
const SEQ: usize = 8;
const COUNT: usize = 16;
const BODY_LEN: usize = 20;
const DIGEST: usize = 56;
/// Bytes of the header; the body starts here.
pub const HEADER: usize = 96;
/// Smallest image: a header and room for one small record.
pub const MIN_IMAGE: usize = 512;
/// Slots an image alternates between: A (0) and B (1).
pub const SLOTS: u8 = 2;

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut s = [0u8; 8];
    s.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(s)
}

/// Whether `len` is an image size: a multiple of 512 of at least
/// [`MIN_IMAGE`].
pub fn valid_len(len: usize) -> bool {
    len >= MIN_IMAGE && len.is_multiple_of(512)
}

/// The sequence `img` carries.
pub fn seq(img: &[u8]) -> u64 {
    u64_at(img, SEQ)
}

/// The record count `img` carries.
pub fn count(img: &[u8]) -> u16 {
    u16::from_le_bytes([img[COUNT], img[COUNT + 1]])
}

/// Make `img` an empty image at sequence `seq`.
pub fn format(img: &mut [u8], seq: u64) {
    img.fill(0);
    img[0..4].copy_from_slice(&MAGIC);
    img[4] = VERSION;
    img[SEQ..SEQ + 8].copy_from_slice(&seq.to_le_bytes());
    seal_digest(img);
}

/// Whether `img` is a whole, valid image.
pub fn valid(img: &[u8]) -> bool {
    if img.len() < HEADER || img[0..4] != MAGIC || img[4] != VERSION {
        return false;
    }
    let body = u32_at(img, BODY_LEN) as usize;
    if body > img.len() - HEADER {
        return false;
    }
    digest_of(img)[..] == img[DIGEST..DIGEST + 32]
}

fn digest_of(img: &[u8]) -> [u8; 32] {
    let body = (u32_at(img, BODY_LEN) as usize).min(img.len() - HEADER);
    let mut h = Sha256::new();
    h.update(&img[..DIGEST]);
    h.update(&img[HEADER..HEADER + body]);
    h.finalize()
}

/// Write the image's digest over its header and body.
pub fn seal_digest(img: &mut [u8]) {
    let d = digest_of(img);
    img[DIGEST..DIGEST + 32].copy_from_slice(&d);
}

/// Walk `img`'s records: `(offset, name, blob)`; `f` returns false to stop.
pub fn records(img: &[u8], mut f: impl FnMut(usize, &[u8], &[u8]) -> bool) {
    let count = count(img) as usize;
    let end = HEADER + (u32_at(img, BODY_LEN) as usize).min(img.len() - HEADER);
    let mut at = HEADER;
    for _ in 0..count {
        let Some(&nl) = img.get(at) else { return };
        let nl = nl as usize;
        if at + 3 + nl > end {
            return;
        }
        let name = &img[at + 1..at + 1 + nl];
        let bl = u16::from_le_bytes([img[at + 1 + nl], img[at + 2 + nl]]) as usize;
        if at + 3 + nl + bl > end {
            return;
        }
        let blob = &img[at + 3 + nl..at + 3 + nl + bl];
        if !f(at, name, blob) {
            return;
        }
        at += 3 + nl + bl;
    }
}

/// The record filed under `name`, copied to `out`: its length, `None` when
/// absent or larger than `out`.
pub fn read(img: &[u8], name: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut got = None;
    records(img, |_, n, b| {
        if n == name {
            if b.len() <= out.len() {
                out[..b.len()].copy_from_slice(b);
                got = Some(b.len());
            }
            return false;
        }
        true
    });
    got
}

/// What [`change`] did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Change {
    /// The image changed and now carries this sequence.
    Changed(u64),
    /// Nothing to remove: the image is as it was.
    Unchanged,
    /// The result would not fit (or a name or blob is too long): the image
    /// is as it was.
    Full,
}

/// Put `blob` under `name` (`Some`) or remove `name` (`None`) in `img`,
/// moving its sequence on by one and resealing its digest. The image only
/// changes when the result fits.
pub fn change(img: &mut [u8], name: &[u8], put: Option<&[u8]>) -> Change {
    let len = img.len();
    let body = (u32_at(img, BODY_LEN) as usize).min(len - HEADER);
    let mut old: Option<(usize, usize)> = None;
    records(img, |at, n, b| {
        if n == name {
            old = Some((at, 3 + n.len() + b.len()));
            return false;
        }
        true
    });
    if old.is_none() && put.is_none() {
        return Change::Unchanged;
    }
    if name.len() > u8::MAX as usize || put.is_some_and(|b| b.len() > u16::MAX as usize) {
        return Change::Full;
    }
    let add = put.map_or(0, |b| 3 + name.len() + b.len());
    let new_body = body - old.map_or(0, |(_, l)| l) + add;
    if HEADER + new_body > len {
        return Change::Full;
    }
    let mut count = count(img);
    if let Some((at, l)) = old {
        // Close the gap, front to back (`copy_within` would carry a panic
        // message table no position-independent module may hold).
        for i in at..HEADER + body - l {
            img[i] = img[i + l];
        }
        count -= 1;
    }
    let mut at = HEADER + body - old.map_or(0, |(_, l)| l);
    if let Some(b) = put {
        img[at] = name.len() as u8;
        img[at + 1..at + 1 + name.len()].copy_from_slice(name);
        img[at + 1 + name.len()..at + 3 + name.len()]
            .copy_from_slice(&(b.len() as u16).to_le_bytes());
        img[at + 3 + name.len()..at + add].copy_from_slice(b);
        at += add;
        count += 1;
    }
    img[at..].fill(0);
    let seq = seq(img).wrapping_add(1);
    img[SEQ..SEQ + 8].copy_from_slice(&seq.to_le_bytes());
    img[COUNT..COUNT + 2].copy_from_slice(&count.to_le_bytes());
    img[BODY_LEN..BODY_LEN + 4].copy_from_slice(&(new_body as u32).to_le_bytes());
    seal_digest(img);
    Change::Changed(seq)
}

/// A streaming check of one slot read in order, keeping only its header and
/// a running digest: one image of RAM serves a load, never two.
#[derive(Clone)]
pub struct Scan {
    sha: Sha256,
    header: [u8; HEADER],
    /// Bytes of the slot seen so far.
    pub got: usize,
    /// `Some(seq)` once the slot proved a valid image.
    pub seq: Option<u64>,
    pub digest: [u8; 32],
}

impl Default for Scan {
    fn default() -> Self {
        Self::new()
    }
}

impl Scan {
    pub const fn new() -> Self {
        Scan {
            sha: Sha256::new(),
            header: [0; HEADER],
            got: 0,
            seq: None,
            digest: [0; 32],
        }
    }

    /// Feed `data`, at `offset` of a slot of `image_len` bytes. False when
    /// out of order or past the end.
    pub fn feed(&mut self, image_len: usize, offset: usize, data: &[u8]) -> bool {
        if offset != self.got || offset + data.len() > image_len {
            return false;
        }
        for (i, &b) in data.iter().enumerate() {
            let p = offset + i;
            if p < HEADER {
                self.header[p] = b;
            }
        }
        // The digest covers [0..DIGEST) and the body after the header.
        let end = offset + data.len();
        if offset < DIGEST {
            let to = end.min(DIGEST);
            self.sha.update(&data[..to - offset]);
        }
        if end > HEADER {
            // The header is whole by now: it came first.
            let body = (u32_at(&self.header, BODY_LEN) as usize).min(image_len - HEADER);
            let from = offset.max(HEADER);
            let to = end.min(HEADER + body);
            if to > from {
                self.sha.update(&data[from - offset..to - offset]);
            }
        }
        self.got = end;
        if self.got == image_len {
            let h = &self.header;
            let body = u32_at(h, BODY_LEN) as usize;
            let digest = self.sha.clone().finalize();
            self.digest = digest;
            if h[0..4] == MAGIC
                && h[4] == VERSION
                && body <= image_len - HEADER
                && digest[..] == h[DIGEST..DIGEST + 32]
            {
                self.seq = Some(u64_at(h, SEQ));
            }
        }
        true
    }
}

/// The slot a load trusts: the valid one with the higher sequence; `None`
/// when neither is valid (a store never written).
pub fn choose(a: &Scan, b: &Scan) -> Option<u8> {
    match (a.seq, b.seq) {
        (Some(x), Some(y)) => Some(u8::from(y > x)),
        (Some(_), None) => Some(0),
        (None, Some(_)) => Some(1),
        (None, None) => None,
    }
}
