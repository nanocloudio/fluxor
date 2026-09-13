//! xHCI transfer/command ring arithmetic.
//!
//! An xHCI ring is a circular array of 16-byte Transfer Request Blocks whose
//! last entry is a **Link TRB** pointing back to the start. Producer and
//! consumer share it with no lock and no doorbell per entry, so the only
//! thing telling the consumer which entries are new is a single bit.
//!
//! # The cycle bit
//!
//! Each TRB carries a cycle bit. The consumer owns a "cycle state" and
//! processes a TRB only when the TRB's bit matches it. The producer writes
//! the current state into each TRB and **toggles its own state every time it
//! wraps**. So on the first pass through the ring the valid TRBs have cycle
//! 1, on the second pass 0, and so on.
//!
//! Get this wrong and nothing errors. Forget to toggle and the consumer stops
//! after one lap, because every subsequent TRB looks stale — the symptom is a
//! device that works until exactly one ring's worth of traffic has passed.
//! Toggle too early and the consumer runs ahead into entries the producer has
//! not written, executing whatever was left there from the previous lap.
//!
//! # Full is not "enqueue met dequeue"
//!
//! The ring must never be filled completely: a ring whose enqueue pointer has
//! caught its dequeue pointer is indistinguishable from an empty one, because
//! both mean the two pointers are equal. One slot is always left free, and
//! the Link TRB's slot is not usable either.
//!
//! This is pure arithmetic over indices. It touches no registers and no
//! memory-mapped ring, because the failure modes above are far easier to
//! provoke here than on a Pi 5.

/// Bytes in a TRB.
pub const TRB_LEN: usize = 16;

/// TRB types this core names (xHCI 1.2 Table 6-91).
pub mod trb_type {
    /// Normal — a bulk or interrupt data block.
    pub const NORMAL: u32 = 1;
    /// Setup stage of a control transfer.
    pub const SETUP_STAGE: u32 = 2;
    /// Data stage of a control transfer.
    pub const DATA_STAGE: u32 = 3;
    /// Status stage of a control transfer.
    pub const STATUS_STAGE: u32 = 4;
    /// Link — points at another ring segment, or back to the start.
    pub const LINK: u32 = 6;
    /// Where the type field sits in the TRB's control word.
    pub const SHIFT: u32 = 10;
}

/// Control-word flags.
pub mod flags {
    /// Cycle bit. The only thing distinguishing a fresh TRB from a stale one.
    pub const CYCLE: u32 = 1 << 0;
    /// Toggle Cycle, on a Link TRB: tells the consumer to flip its cycle
    /// state when it follows this link.
    pub const TOGGLE_CYCLE: u32 = 1 << 1;
    /// Chain — this TRB is part of a multi-TRB transfer.
    pub const CHAIN: u32 = 1 << 4;
    /// Interrupt On Completion.
    pub const IOC: u32 = 1 << 5;
}

/// A ring's producer-side state.
///
/// Holds indices, not pointers: the ring's memory belongs to a controller
/// backend, and every mistake this type exists to prevent is an indexing one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ring {
    /// TRBs in the ring, including the Link TRB.
    size: usize,
    /// Where the next TRB will be written.
    enqueue: usize,
    /// Where the consumer has reached.
    dequeue: usize,
    /// The cycle bit the producer is currently writing.
    cycle: bool,
}

/// Why a ring operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingError {
    /// Fewer than two TRBs: one for the Link and at least one usable.
    TooSmall,
    /// No usable slot. See the module docs on why "full" leaves one free.
    Full,
}

impl Ring {
    /// A ring of `size` TRBs, the last of which is the Link TRB.
    ///
    /// The producer starts at cycle 1 because the ring is zeroed at
    /// allocation, so every TRB initially reads cycle 0 — which is what makes
    /// an untouched ring look entirely stale to the consumer, correctly.
    pub const fn new(size: usize) -> Result<Self, RingError> {
        if size < 2 {
            return Err(RingError::TooSmall);
        }
        Ok(Self {
            size,
            enqueue: 0,
            dequeue: 0,
            cycle: true,
        })
    }

    /// The index of the Link TRB: always the last entry.
    pub const fn link_index(&self) -> usize {
        self.size - 1
    }

    /// The cycle bit the producer is writing.
    pub const fn cycle(&self) -> bool {
        self.cycle
    }

    /// Where the next TRB goes.
    pub const fn enqueue_index(&self) -> usize {
        self.enqueue
    }

    /// Where the consumer has reached.
    pub const fn dequeue_index(&self) -> usize {
        self.dequeue
    }

    /// Usable slots, excluding the Link TRB and the one that must stay free.
    pub const fn capacity(&self) -> usize {
        self.size - 2
    }

    /// Whether another TRB can be enqueued.
    ///
    /// The check looks one past the enqueue point, skipping the Link TRB,
    /// because filling the last slot would make enqueue equal dequeue — which
    /// is how an empty ring looks.
    pub const fn has_room(&self) -> bool {
        let mut next = self.enqueue + 1;
        if next == self.link_index() {
            next = 0;
        }
        next != self.dequeue
    }

    /// Reserve the next slot, returning its index and the cycle bit to write
    /// into it.
    ///
    /// The caller writes the TRB at that index with that cycle bit. Writing a
    /// different one is the bug this signature exists to make awkward.
    pub fn enqueue(&mut self) -> Result<(usize, bool), RingError> {
        if !self.has_room() {
            return Err(RingError::Full);
        }
        let index = self.enqueue;
        let cycle = self.cycle;

        self.enqueue += 1;
        if self.enqueue == self.link_index() {
            // Following the Link TRB wraps to the start and flips the cycle
            // state. Forgetting the flip stops the consumer after one lap;
            // flipping early runs it into TRBs not yet written.
            self.enqueue = 0;
            self.cycle = !self.cycle;
        }
        Ok((index, cycle))
    }

    /// Record that the consumer has processed through `index`.
    pub fn set_dequeue(&mut self, index: usize) {
        if index < self.size {
            self.dequeue = index;
        }
    }

    /// Whether the ring holds nothing the consumer has yet to see.
    pub const fn is_empty(&self) -> bool {
        self.enqueue == self.dequeue
    }
}

/// Build a TRB control word.
///
/// The cycle bit is a separate argument rather than folded into `flags`
/// because it is not a flag the caller chooses — it comes from
/// [`Ring::enqueue`], and mixing it in with the others invites writing a
/// literal.
pub const fn control_word(trb_type: u32, flags: u32, cycle: bool) -> u32 {
    let mut w = (trb_type << trb_type::SHIFT) | flags;
    // Clear any cycle bit the caller passed in `flags`: the ring owns it.
    w &= !flags::CYCLE;
    if cycle {
        w |= flags::CYCLE;
    }
    w
}

/// Extract a TRB's type from its control word.
pub const fn control_word_type(w: u32) -> u32 {
    (w >> trb_type::SHIFT) & 0x3f
}

/// Whether a TRB is one the consumer should process, given its cycle state.
#[inline]
pub const fn is_owned_by_consumer(control: u32, consumer_cycle: bool) -> bool {
    (control & flags::CYCLE != 0) == consumer_cycle
}

/// The Link TRB's control word, which must carry Toggle Cycle.
///
/// Without it the consumer never flips its cycle state and stops after one
/// lap — the producer and consumer then disagree about every TRB forever.
pub const fn link_control_word(cycle: bool) -> u32 {
    control_word(trb_type::LINK, flags::TOGGLE_CYCLE, cycle)
}
