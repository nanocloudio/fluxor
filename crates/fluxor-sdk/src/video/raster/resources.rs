//! A consumer's resource store: the bytes RES_DEF and RES_DATA deliver, the
//! SHA-256 check that makes them usable, and the byte strings the consumer
//! already holds that RES_REF names by digest.

use super::source::{Resources, Strike, Texels};
use crate::crypto::sha256::Sha256;
use fluxor_abi::contracts::glyph_pack as gp;
use fluxor_abi::contracts::video_draw::{
    ResDef, ResRef, RES_GLYPH_PACK, RES_GLYPH_STRIKE, RES_PIXMAP,
};

/// A byte string the consumer holds in place (a glyph pack or a strike in
/// its program image), with the digest RES_REF finds it by. The digest is
/// computed by `Store::prepare`, a slice at a time.
pub struct Held<'m> {
    bytes: &'m [u8],
    hasher: Sha256,
    hashed: usize,
    digest: Option<[u8; 32]>,
}

impl<'m> Held<'m> {
    pub fn new(bytes: &'m [u8]) -> Self {
        Held {
            bytes,
            hasher: Sha256::new(),
            hashed: 0,
            digest: None,
        }
    }

    /// The digest, once `Store::prepare` has finished it.
    pub fn digest(&self) -> Option<&[u8; 32]> {
        self.digest.as_ref()
    }
}

/// Where a resource's bytes are.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    Free,
    /// In the store's arena.
    Arena,
    /// In held byte string `held`.
    Held(u8),
}

/// One resource slot of a `Store`.
#[derive(Clone, Copy)]
pub struct Slot {
    place: Place,
    kind: u8,
    format: u8,
    width: u16,
    height: u16,
    offset: u32,
    len: u32,
    digest: [u8; 32],
}

impl Slot {
    /// An empty slot, to build the table a `Store` borrows.
    pub const FREE: Slot = Slot {
        place: Place::Free,
        kind: 0,
        format: 0,
        width: 0,
        height: 0,
        offset: 0,
        len: 0,
        digest: [0; 32],
    };
}

/// The resources of one stream: a slot per id, an arena for defined bytes
/// (`resource_bytes` of it), and the held byte strings references resolve
/// against.
pub struct Store<'m> {
    slots: &'m mut [Slot],
    arena: &'m mut [u8],
    used: usize,
    held: &'m mut [Held<'m>],
}

impl<'m> Store<'m> {
    /// A store of `slots.len()` ids over `arena`.
    pub fn new(slots: &'m mut [Slot], arena: &'m mut [u8], held: &'m mut [Held<'m>]) -> Self {
        slots.fill(Slot::FREE);
        Store {
            slots,
            arena,
            used: 0,
            held,
        }
    }

    /// Ids the store holds.
    pub fn ids(&self) -> usize {
        self.slots.len()
    }

    /// Bytes the arena holds.
    pub fn capacity(&self) -> usize {
        self.arena.len()
    }

    /// Hash up to `budget` bytes of the held byte strings: whether every
    /// digest is known. A consumer calls this each step until it answers
    /// `true`, and takes no stream before then.
    pub fn prepare(&mut self, mut budget: usize) -> bool {
        for held in self.held.iter_mut() {
            if held.digest.is_some() {
                continue;
            }
            let take = (held.bytes.len() - held.hashed).min(budget);
            held.hasher
                .update(&held.bytes[held.hashed..held.hashed + take]);
            held.hashed += take;
            budget -= take;
            if held.hashed < held.bytes.len() {
                return false;
            }
            let hasher = core::mem::take(&mut held.hasher);
            held.digest = Some(hasher.finalize());
        }
        true
    }

    /// Whether every held byte string's digest is known.
    pub fn prepared(&self) -> bool {
        self.held.iter().all(|h| h.digest.is_some())
    }

    /// Release every resource: a stream opened.
    pub fn clear(&mut self) {
        self.slots.fill(Slot::FREE);
        self.used = 0;
    }

    /// Release resource `id`.
    pub fn release(&mut self, id: u16) {
        if let Some(slot) = self.slots.get_mut(usize::from(id)) {
            *slot = Slot::FREE;
        }
    }

    /// Close the gaps released resources left in the arena.
    fn compact(&mut self) {
        let mut floor = 0u32;
        let mut end = 0usize;
        loop {
            // The lowest resource at or above the floor.
            let mut next: Option<usize> = None;
            for (i, s) in self.slots.iter().enumerate() {
                if s.place == Place::Arena
                    && s.offset >= floor
                    && next.is_none_or(|n| s.offset < self.slots[n].offset)
                {
                    next = Some(i);
                }
            }
            let Some(i) = next else { break };
            let (from, len) = (self.slots[i].offset as usize, self.slots[i].len as usize);
            super::shift_down(self.arena, from, len, end);
            // A moved resource lands below where it was, so below the floor.
            floor = self.slots[i].offset + 1;
            self.slots[i].offset = end as u32;
            end += len;
        }
        self.used = end;
    }

    /// Reserve a defined resource's bytes: whether the id is free and the
    /// arena has room.
    pub fn define(&mut self, def: &ResDef) -> bool {
        let len = def.total_len as usize;
        match self.slots.get(usize::from(def.id)) {
            Some(slot) if slot.place == Place::Free => {}
            _ => return false,
        }
        if self.arena.len() - self.used < len {
            self.compact();
            if self.arena.len() - self.used < len {
                return false;
            }
        }
        self.slots[usize::from(def.id)] = Slot {
            place: Place::Arena,
            kind: def.kind,
            format: def.format,
            width: def.width,
            height: def.height,
            offset: self.used as u32,
            len: def.total_len,
            digest: def.digest,
        };
        self.used += len;
        true
    }

    /// Store a RES_DATA chunk: whether it lies inside the resource.
    pub fn data(&mut self, id: u16, offset: u32, bytes: &[u8]) -> bool {
        let Some(slot) = self.slots.get(usize::from(id)) else {
            return false;
        };
        if slot.place != Place::Arena {
            return false;
        }
        let Some(end) = (offset as usize).checked_add(bytes.len()) else {
            return false;
        };
        if end > slot.len as usize {
            return false;
        }
        let at = slot.offset as usize + offset as usize;
        match self.arena.get_mut(at..at + bytes.len()) {
            Some(dst) => {
                dst.copy_from_slice(bytes);
                true
            }
            None => false,
        }
    }

    fn bytes(&self, slot: &Slot) -> Option<&[u8]> {
        let (at, len) = (slot.offset as usize, slot.len as usize);
        match slot.place {
            Place::Free => None,
            Place::Arena => self.arena.get(at..at.checked_add(len)?),
            Place::Held(i) => self
                .held
                .get(usize::from(i))?
                .bytes
                .get(at..at.checked_add(len)?),
        }
    }

    /// The verdict on a defined resource whose last byte has arrived, for
    /// `Sequence::resolve`: `Some(glyphs)` when its bytes hash to the
    /// digest its definition stated and, for a strike, parse as one
    /// covering exactly its length.
    pub fn complete(&self, id: u16) -> Option<u32> {
        let slot = self.slots.get(usize::from(id))?;
        let bytes = self.bytes(slot)?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        if hasher.finalize() != slot.digest {
            return None;
        }
        match slot.kind {
            RES_PIXMAP => Some(0),
            RES_GLYPH_STRIKE => {
                let strike = gp::Strike::parse(bytes)?;
                if !strike.covers(slot.format) {
                    return None;
                }
                u32::try_from(strike.len()).ok()
            }
            _ => None,
        }
    }

    /// Resolve a RES_REF against the held byte strings, for
    /// `Sequence::resolve`: `Some(glyphs)` when one hashes to its digest
    /// and is a strike (kind GLYPH_STRIKE) or a pack in the named format
    /// with a strike at the selected ppem (kind GLYPH_PACK).
    pub fn reference(&mut self, r: &ResRef) -> Option<u32> {
        let index = self
            .held
            .iter()
            .position(|h| h.digest.as_ref() == Some(&r.digest))?;
        let bytes = self.held[index].bytes;
        let (offset, len, glyphs) = match r.kind {
            RES_GLYPH_STRIKE => {
                let strike = gp::Strike::parse(bytes)?;
                if !strike.covers(r.format) {
                    return None;
                }
                (0, bytes.len(), strike.len())
            }
            RES_GLYPH_PACK => {
                let pack = gp::Pack::parse(bytes)?;
                if pack.format != r.format {
                    return None;
                }
                let ppem = u16::try_from(r.selector).ok()?;
                let strike = pack.strike_bytes(ppem)?;
                let offset = (strike.as_ptr() as usize).checked_sub(bytes.as_ptr() as usize)?;
                let len = strike.len();
                let strike = gp::Strike::parse(strike)?;
                (offset, len, strike.len())
            }
            _ => return None,
        };
        let slot = self.slots.get_mut(usize::from(r.id))?;
        if slot.place != Place::Free {
            return None;
        }
        *slot = Slot {
            place: Place::Held(u8::try_from(index).ok()?),
            kind: RES_GLYPH_STRIKE,
            format: r.format,
            width: 0,
            height: 0,
            offset: u32::try_from(offset).ok()?,
            len: u32::try_from(len).ok()?,
            digest: r.digest,
        };
        u32::try_from(glyphs).ok()
    }
}

impl Resources for Store<'_> {
    fn strike(&self, id: u16) -> Option<Strike<'_>> {
        let slot = self.slots.get(usize::from(id))?;
        if slot.kind != RES_GLYPH_STRIKE {
            return None;
        }
        Strike::parse(self.bytes(slot)?, slot.format)
    }

    fn pixmap(&self, id: u16) -> Option<Texels<'_>> {
        let slot = self.slots.get(usize::from(id))?;
        if slot.kind != RES_PIXMAP {
            return None;
        }
        Texels::pixmap(self.bytes(slot)?, slot.width, slot.height, slot.format)
    }
}
