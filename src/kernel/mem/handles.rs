//! `HandleTable`: a boot-sized table of values named by kernel handles.
//!
//! A slot is `{ live, generation, value }`. Claiming a slot bumps its
//! generation, so a handle kept past its release names nothing: the slot's
//! generation has moved on (`abi::kernel_abi::handle`, the 9-bit field).
//! Claims are next-fit — each starts after the slot the last one took — so a
//! slot just released is the last one reused, and a stale handle has as many
//! claims as the table has slots to go before its slot comes round again.
//!
//! The table is sized from a resource pool like every other boot table
//! (`boot_table!`); a claim past its ceiling is `None`, and the caller
//! refuses with `ENOSPC`.

use portable_atomic::{AtomicUsize, Ordering};

use crate::abi::kernel_abi::handle;
use crate::kernel::mem::table::{Table, TableError};

/// One slot.
#[derive(Clone, Copy)]
pub struct Slot<T: Copy> {
    pub live: bool,
    /// The generation a handle to this slot carries; moved on every claim.
    pub generation: u16,
    pub value: T,
}

impl<T: Copy> Slot<T> {
    /// A free slot holding `value` (its empty value).
    pub const fn free(value: T) -> Self {
        Self {
            live: false,
            generation: 0,
            value,
        }
    }
}

/// A table of `Slot<T>`, at most `N` slots on a static profile.
pub struct HandleTable<T: Copy, const N: usize> {
    slots: Table<Slot<T>, N>,
    /// Where the next claim starts looking.
    next: AtomicUsize,
}

impl<T: Copy, const N: usize> HandleTable<T, N> {
    /// A handle table over `slots` (built with `boot_table!`).
    pub const fn new(slots: Table<Slot<T>, N>) -> Self {
        Self {
            slots,
            next: AtomicUsize::new(0),
        }
    }

    /// Reserve and commit `n` slots: the pool's ceiling. Past the handle
    /// word's index field is refused: a handle could not name the slot.
    ///
    /// # Safety
    /// Graph-preparation context: no reference into the table is live.
    pub unsafe fn size(&self, n: usize) -> Result<(), TableError> {
        if n > handle::INDEX_LIMIT {
            return Err(TableError::Ceiling);
        }
        // SAFETY: the caller's contract.
        unsafe { self.slots.reserve(n)? };
        self.slots.grow(n)
    }

    /// Size a table no plan has sized to `n()` slots.
    pub fn size_unplanned(&self, n: impl FnOnce() -> usize) {
        self.slots.size_unplanned(n);
    }

    /// Slots the table holds.
    pub fn capacity(&self) -> usize {
        self.slots.len().min(handle::INDEX_LIMIT)
    }

    /// Claim a free slot for `value`: `(index, generation)`, or `None` when
    /// every slot is live. Next-fit: the search starts after the last claim.
    pub fn claim(&mut self, value: T) -> Option<(u32, u16)> {
        let len = self.capacity();
        if len == 0 {
            return None;
        }
        let start = self.next.load(Ordering::Relaxed) % len;
        for k in 0..len {
            let i = (start + k) % len;
            let s = &mut self.slots[i];
            if s.live {
                continue;
            }
            s.live = true;
            s.generation = s.generation.wrapping_add(1) & handle::GEN_MASK;
            s.value = value;
            self.next.store(i + 1, Ordering::Relaxed);
            return Some((i as u32, s.generation));
        }
        None
    }

    /// The live slot `index` at `generation`.
    pub fn get(&self, index: u32, generation: u16) -> Option<&T> {
        self.slots
            .get(index as usize)
            .filter(|s| s.live && s.generation == generation)
            .map(|s| &s.value)
    }

    /// As [`get`](Self::get), mutably.
    pub fn get_mut(&mut self, index: u32, generation: u16) -> Option<&mut T> {
        self.slots
            .get_mut(index as usize)
            .filter(|s| s.live && s.generation == generation)
            .map(|s| &mut s.value)
    }

    /// Free slot `index` if it is still live at `generation`; its value.
    pub fn release(&mut self, index: u32, generation: u16) -> Option<T> {
        let s = self.slots.get_mut(index as usize)?;
        if !s.live || s.generation != generation {
            return None;
        }
        s.live = false;
        Some(s.value)
    }

    /// Every live slot: `(index, generation, value)`.
    pub fn live(&self) -> impl Iterator<Item = (u32, u16, &T)> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.live)
            .map(|(i, s)| (i as u32, s.generation, &s.value))
    }

    /// Live slots now.
    pub fn in_use(&self) -> usize {
        self.slots.iter().filter(|s| s.live).count()
    }

    /// Free every slot. Generations stay, so no handle minted before names a
    /// slot after.
    pub fn clear(&mut self) {
        for s in self.slots.iter_mut() {
            s.live = false;
        }
    }
}
