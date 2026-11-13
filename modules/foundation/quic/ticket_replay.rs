// ticket_replay_core — single-use enforcement for resumption tickets
// (RFC 8446 §8, RFC 9001 §9.2).
//
// A resumption ticket is accepted at most once, and the server's record
// that it was already spent is the only thing enforcing that. The sharpest
// reason is early data: 0-RTT bytes are replayable by anyone who captured
// them, so a second acceptance is a second execution. A ticket accepted
// twice also correlates two connections as one client. Either way the
// record is server-side state, which makes the shape of this store a
// security property rather than a memory-budget decision.
//
// Two rules make a bounded store sound, and both are easy to get wrong:
//
//   - **A claim is retained for the ticket's whole acceptance window.**
//     Reclaiming a slot early re-opens exactly the window a replay lands
//     in. Slots are reclaimed by the claim EXPIRING, never by pressure.
//   - **A full store refuses the resumption.** The tempting alternative
//     — evict the oldest claim to make room — silently converts the
//     store's depth into an attacker's waiting time: capture a ticket,
//     wait for `N` further resumptions, replay it. Refusing costs a full
//     handshake, which is a latency cost. Evicting costs the guarantee,
//     which is not a cost the caller can see.
//
// A flat scan, deliberately: the store is sized by the resumptions that
// may be in flight inside one ticket lifetime, and the caller sizes that
// against the lifetime it issues.
//
// Pure logic over caller-owned state: no allocation, no clock, no syscall.
// The caller supplies the current reading, so the same core serves a
// module reading `dev_millis` and a test driving time by hand — which is
// what lets the dangerous half be tested at all.
//
// `no_std`, zero-alloc.

/// One accepted ticket, held until its acceptance window closes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TicketClaim {
    /// Ticket identity — a digest, not the ticket itself.
    pub digest: [u8; 16],
    /// Reading past which this claim protects nothing and the slot is
    /// free. Zero is a free slot.
    pub expiry: u64,
}

impl TicketClaim {
    pub const EMPTY: Self = Self {
        digest: [0u8; 16],
        expiry: 0,
    };
}

/// Whether `digest` names a ticket already accepted and still inside its
/// acceptance window.
///
/// A claim whose window has closed is not a match: the ticket it named is
/// no longer acceptable on its own lifetime, so the claim has nothing left
/// to protect.
#[must_use]
pub fn ticket_claim_held(store: &[TicketClaim], digest: &[u8; 16], now: u64) -> bool {
    let mut i = 0;
    while i < store.len() {
        if store[i].expiry > now && store[i].digest == *digest {
            return true;
        }
        i += 1;
    }
    false
}

/// Claim `digest` until `expiry`. Answers false when the ticket is already
/// claimed, when the window has already closed, or when every slot holds a
/// live claim.
///
/// The caller must treat false as "do not accept this resumption". It is
/// one answer on purpose: a caller that could distinguish "already
/// claimed" from "no room" would be tempted to treat the second as
/// recoverable, and it is not — both mean this acceptance would be
/// unprotected.
#[must_use]
pub fn ticket_claim(store: &mut [TicketClaim], digest: [u8; 16], expiry: u64, now: u64) -> bool {
    if expiry <= now {
        return false;
    }
    let mut free = store.len();
    let mut i = 0;
    while i < store.len() {
        if store[i].expiry <= now {
            if free == store.len() {
                free = i;
            }
        } else if store[i].digest == digest {
            return false;
        }
        i += 1;
    }
    if free == store.len() {
        return false;
    }
    store[free] = TicketClaim { digest, expiry };
    true
}
