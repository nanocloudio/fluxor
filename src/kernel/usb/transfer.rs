//! Transfer identity, cancellation and exactly-once completion.
//!
//! A controller reports completions asynchronously, by an identifier the core
//! handed it earlier. Two things then have to be true, and neither is free:
//!
//! - a completion must be delivered **exactly once**, even if the controller
//!   reports it twice (a retried IRQ, a ring read that wrapped);
//! - an identifier for a transfer that has been cancelled, or whose device
//!   has detached, must **not** resolve to whatever now occupies its slot.
//!
//! The second is the dangerous one. Slots are reused, so a bare index is a
//! use-after-free with a friendly name: a stale completion lands on the new
//! owner's transfer and the data goes to the wrong module. A generation
//! counter in the handle makes that detectable instead of silent.

/// Slots this core will track concurrently.
///
/// Bounded, like every other queue in the kernel. A
/// device that submits without bound must be refused, not allowed to consume
/// the table that every other device shares.
pub const MAX_TRANSFERS: usize = 32;

/// A transfer identifier: a slot index plus the generation that slot held
/// when the handle was issued.
///
/// The generation is what makes a stale handle detectable. Without it two
/// transfers that happen to use the same slot are indistinguishable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferToken {
    slot: u16,
    generation: u16,
}

impl TransferToken {
    /// The slot this token refers to. For controller backends that key their
    /// rings by slot; never for resolving ownership, which must go through
    /// [`TransferTable::get`].
    #[inline]
    pub const fn slot(&self) -> u16 {
        self.slot
    }

    /// The generation this token was issued against.
    #[inline]
    pub const fn generation(&self) -> u16 {
        self.generation
    }
}

/// How a transfer ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    /// Completed, transferring this many bytes.
    Ok(u32),
    /// The endpoint returned STALL.
    Stalled,
    /// The device detached before the transfer completed.
    Disconnected,
    /// The transfer exceeded its deadline.
    TimedOut,
    /// A bus-level error: CRC, bit-stuffing, or a transaction error.
    BusError,
    /// The device sent more data than the transfer allowed.
    Babble,
    /// Cancelled by the submitter.
    Cancelled,
}

/// State of one slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotState {
    /// Nothing here; the generation is the next one to issue.
    Free,
    /// Submitted to the controller, not yet completed.
    Pending,
    /// Cancellation requested; the controller has not yet acknowledged.
    ///
    /// A distinct state, not an immediate free. The controller may already
    /// have the transfer in flight and will still report it, so the slot must
    /// stay reserved until that report arrives — releasing it early is how a
    /// late completion lands on the next occupant.
    Cancelling,
    /// Completed; the result is waiting to be taken.
    Complete(Completion),
}

#[derive(Clone, Copy)]
struct Slot {
    state: SlotState,
    generation: u16,
    owner: u8,
}

/// Why a submission or completion was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferError {
    /// Every slot is in use.
    TableFull,
    /// The token's generation does not match the slot's: the transfer it
    /// referred to is over and the slot has been reused.
    StaleToken,
    /// The slot is not in a state where this operation makes sense.
    WrongState,
}

/// The transfer table: slot allocation, generation tracking and
/// exactly-once completion.
pub struct TransferTable {
    slots: [Slot; MAX_TRANSFERS],
}

impl Default for TransferTable {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferTable {
    /// An empty table.
    pub const fn new() -> Self {
        Self {
            slots: [Slot {
                state: SlotState::Free,
                generation: 0,
                owner: 0,
            }; MAX_TRANSFERS],
        }
    }

    /// Reserve a slot for `owner`, returning its token.
    pub fn submit(&mut self, owner: u8) -> Result<TransferToken, TransferError> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.state == SlotState::Free {
                slot.state = SlotState::Pending;
                slot.owner = owner;
                return Ok(TransferToken {
                    slot: i as u16,
                    generation: slot.generation,
                });
            }
        }
        Err(TransferError::TableFull)
    }

    /// Resolve a token to its owner, or report why it does not resolve.
    ///
    /// This is the only way to get from a token to an owner. A backend that
    /// indexed `slots` directly would bypass the generation check, which is
    /// the entire protection.
    pub fn get(&self, token: TransferToken) -> Result<u8, TransferError> {
        let slot = self
            .slots
            .get(token.slot as usize)
            .ok_or(TransferError::StaleToken)?;
        if slot.generation != token.generation || slot.state == SlotState::Free {
            return Err(TransferError::StaleToken);
        }
        Ok(slot.owner)
    }

    /// Request cancellation. The slot stays reserved until the controller
    /// reports the transfer, because it may already be in flight.
    pub fn cancel(&mut self, token: TransferToken) -> Result<(), TransferError> {
        let slot = self
            .slots
            .get_mut(token.slot as usize)
            .ok_or(TransferError::StaleToken)?;
        if slot.generation != token.generation {
            return Err(TransferError::StaleToken);
        }
        match slot.state {
            SlotState::Pending => {
                slot.state = SlotState::Cancelling;
                Ok(())
            }
            // Cancelling twice is not an error: the caller's intent is
            // already recorded and repeating it changes nothing.
            SlotState::Cancelling => Ok(()),
            SlotState::Complete(_) | SlotState::Free => Err(TransferError::WrongState),
        }
    }

    /// Record a completion reported by the controller.
    ///
    /// **Exactly once.** A second report for the same transfer is refused
    /// rather than overwriting the first: controllers do re-report, and the
    /// second report is the one carrying the wrong answer once the slot has
    /// been reused.
    ///
    /// A transfer being cancelled completes as [`Completion::Cancelled`]
    /// whatever the controller says, so the submitter sees the outcome it
    /// asked for rather than a race.
    pub fn complete(
        &mut self,
        token: TransferToken,
        result: Completion,
    ) -> Result<(), TransferError> {
        let slot = self
            .slots
            .get_mut(token.slot as usize)
            .ok_or(TransferError::StaleToken)?;
        if slot.generation != token.generation {
            return Err(TransferError::StaleToken);
        }
        match slot.state {
            SlotState::Pending => {
                slot.state = SlotState::Complete(result);
                Ok(())
            }
            SlotState::Cancelling => {
                slot.state = SlotState::Complete(Completion::Cancelled);
                Ok(())
            }
            SlotState::Complete(_) | SlotState::Free => Err(TransferError::WrongState),
        }
    }

    /// Take a completed result, freeing the slot and advancing its
    /// generation so every outstanding token for it becomes stale.
    pub fn take(&mut self, token: TransferToken) -> Result<Completion, TransferError> {
        let slot = self
            .slots
            .get_mut(token.slot as usize)
            .ok_or(TransferError::StaleToken)?;
        if slot.generation != token.generation {
            return Err(TransferError::StaleToken);
        }
        match slot.state {
            SlotState::Complete(result) => {
                slot.state = SlotState::Free;
                // Wrapping is correct and safe: a collision needs 65536
                // reuses of one slot while a single token from the first is
                // still held, which no transfer lifetime spans.
                slot.generation = slot.generation.wrapping_add(1);
                Ok(result)
            }
            _ => Err(TransferError::WrongState),
        }
    }

    /// Complete every outstanding transfer for `owner` as disconnected.
    ///
    /// Called when a device detaches. Every transfer must reach a terminal
    /// state — a submitter blocked on one that never completes is a leak the
    /// device can trigger by being unplugged.
    ///
    /// Returns how many were affected.
    pub fn disconnect_owner(&mut self, owner: u8) -> usize {
        let mut n = 0;
        for slot in self.slots.iter_mut() {
            if slot.owner != owner {
                continue;
            }
            if matches!(slot.state, SlotState::Pending | SlotState::Cancelling) {
                slot.state = SlotState::Complete(Completion::Disconnected);
                n += 1;
            }
        }
        n
    }

    /// Slots currently in use.
    pub fn in_flight(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.state != SlotState::Free)
            .count()
    }
}
