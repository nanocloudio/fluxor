// nonce_reservation_core — windowed egress-counter reservation with
// epoch fencing ( §13.7.6 R2).
//
// Shared by any datagram anchor doing platform-replicated-state
// `transport_migratable` migration, and by the session directory that
// grants the reservations. The core is the *ordering and fencing*
// logic only: making a grant quorum-durable is the caller's job (the
// directory's Raft group). The invariants this core enforces:
//
//   - **No emission outside a granted block.** `next_value` yields
//     values only from blocks previously installed via `grant`.
//   - **Epoch monotonicity across all paths (R2).** A grant carrying a
//     lower epoch than the current one is rejected (`StaleEpoch`); a
//     grant with a higher epoch fences: any outstanding blocks from
//     the older epoch are dropped before the new block installs.
//   - **Identity space never re-handed out.** A grant must start at or
//     above the high-water mark of every block ever installed here.
//     The unused tail of an abandoned block is *wasted, not reused* —
//     that waste is the price of takeover safety (§13.7.2).
//   - **Unsafe recovery voids outstanding blocks (R2).** After
//     `void_outstanding` (forced/unsafe quorum recovery), emission
//     stops and only a grant with a *strictly higher* epoch is
//     accepted.
//   - **Refill-ahead (double-buffer, §13.7.7).** One pending block may
//     be installed while the current block drains, so block
//     exhaustion mid-stream (`Exhausted` from `next_value` — the
//     `reservation_exhausted_stall` telemetry event) is rare rather
//     than periodic.
//
// The same reserve-ahead discipline covers all three §13.7.1 tier-3
// counters (egress AEAD nonce, reliable-ordered send index, outbound
// datagram sequence): instantiate one `NonceReservation` per counter.
//
// `no_std`, zero-alloc, `Copy`-free plain state — embeddable directly
// in a module's `#[repr(C)]` state struct.

/// Why a grant or emission was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationError {
    /// Grant epoch is below the current epoch (stale writer, R2).
    StaleEpoch,
    /// Grant range overlaps identity space already handed out.
    Overlap,
    /// Grant block length is zero.
    ZeroLen,
    /// Current and pending block slots are both occupied.
    Busy,
    /// Outstanding blocks were voided by unsafe recovery; a grant must
    /// carry a strictly higher epoch before emission may resume (R2).
    EpochNotBumped,
    /// Arithmetic overflow on `start + len` (identity space exhausted).
    SpaceExhausted,
}

/// Windowed counter reservation state for ONE monotonic egress counter.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct NonceReservation {
    /// Current session epoch the installed blocks are fenced by.
    epoch: u32,
    /// Set by `void_outstanding`; cleared by an epoch-bumping grant.
    voided: bool,
    _pad: [u8; 3],
    /// Active block: next value to emit and its exclusive end.
    /// `cur_next == cur_end` means no active block.
    cur_next: u64,
    cur_end: u64,
    /// Pre-granted next block (refill-ahead). `next_start == next_end`
    /// means no pending block.
    next_start: u64,
    next_end: u64,
    /// Highest exclusive end of any block ever installed. New grants
    /// must start at or above this so identity space is never reused.
    high_water: u64,
}

impl Default for NonceReservation {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceReservation {
    /// Fresh reservation state (attach path): no blocks, epoch 0.
    pub const fn new() -> Self {
        NonceReservation {
            epoch: 0,
            voided: false,
            _pad: [0; 3],
            cur_next: 0,
            cur_end: 0,
            next_start: 0,
            next_end: 0,
            high_water: 0,
        }
    }

    /// Takeover path (§13.7.4 step 3): resume on a new host strictly
    /// ahead of anything the dead host could have emitted. `floor` is
    /// the exclusive end of the last quorum-committed grant for this
    /// counter — the dead host cannot have emitted at or beyond it.
    /// The partially-used tail below `floor` is abandoned. `epoch` is
    /// the post-bump session epoch.
    pub const fn resume(epoch: u32, floor: u64) -> Self {
        NonceReservation {
            epoch,
            voided: false,
            _pad: [0; 3],
            cur_next: 0,
            cur_end: 0,
            next_start: 0,
            next_end: 0,
            high_water: floor,
        }
    }

    /// Current fencing epoch.
    #[inline]
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Values still emittable from installed blocks (current + pending).
    pub fn remaining(&self) -> u64 {
        (self.cur_end - self.cur_next) + (self.next_end - self.next_start)
    }

    /// True when the caller should request the next block from the
    /// reservation authority: no pending block is staged and the
    /// active block has fewer than `low_water` values left. Refilling
    /// ahead of exhaustion keeps the quorum round-trip off the emit
    /// path (§13.7.7).
    pub fn needs_refill(&self, low_water: u64) -> bool {
        !self.voided
            && self.next_start == self.next_end
            && (self.cur_end - self.cur_next) < low_water
    }

    /// Install a quorum-committed grant `[start, start+len)` fenced by
    /// `epoch`. The caller MUST NOT call this before the grant is
    /// quorum-durable (R2): a grant that has only been *sent* by the
    /// leader can be re-handed-out by an unsafe recovery that loses
    /// the log tail.
    pub fn grant(&mut self, epoch: u32, start: u64, len: u64) -> Result<(), ReservationError> {
        if len == 0 {
            return Err(ReservationError::ZeroLen);
        }
        let end = start
            .checked_add(len)
            .ok_or(ReservationError::SpaceExhausted)?;
        if epoch < self.epoch {
            return Err(ReservationError::StaleEpoch);
        }
        if self.voided && epoch == self.epoch {
            return Err(ReservationError::EpochNotBumped);
        }
        if start < self.high_water {
            return Err(ReservationError::Overlap);
        }
        if epoch > self.epoch {
            // Epoch fence: outstanding blocks from the older epoch are
            // dropped — a stale-epoch block must never emit again.
            self.cur_next = 0;
            self.cur_end = 0;
            self.next_start = 0;
            self.next_end = 0;
            self.epoch = epoch;
            self.voided = false;
        }
        if self.cur_next == self.cur_end {
            self.cur_next = start;
            self.cur_end = end;
        } else if self.next_start == self.next_end {
            self.next_start = start;
            self.next_end = end;
        } else {
            return Err(ReservationError::Busy);
        }
        self.high_water = end;
        Ok(())
    }

    /// Take the next emittable counter value, advancing within the
    /// active block at line rate (no durable I/O here). Returns `None`
    /// when no granted value is available — the emit-path stall the
    /// `reservation_exhausted_stall` telemetry event reports. The
    /// caller must hold the packet, not emit an unreserved value.
    pub fn next_value(&mut self) -> Option<u64> {
        if self.voided {
            return None;
        }
        if self.cur_next == self.cur_end {
            // Promote the pending block, if staged.
            if self.next_start == self.next_end {
                return None;
            }
            self.cur_next = self.next_start;
            self.cur_end = self.next_end;
            self.next_start = 0;
            self.next_end = 0;
        }
        let v = self.cur_next;
        self.cur_next += 1;
        Some(v)
    }

    /// Unsafe-recovery invalidation (R2): the reservation authority
    /// went through forced/unsafe recovery (force-new-cluster, quorum
    /// reduction), so any outstanding grant may have been re-handed
    /// out. Drop all installed blocks and refuse emission until a
    /// grant with a strictly higher epoch arrives.
    pub fn void_outstanding(&mut self) {
        self.cur_next = 0;
        self.cur_end = 0;
        self.next_start = 0;
        self.next_end = 0;
        self.voided = true;
    }

    /// True after `void_outstanding` until an epoch-bumping grant.
    #[inline]
    pub fn is_voided(&self) -> bool {
        self.voided
    }
}
