// Core: table_consumer — the normative "subscribe, don't invent a
// push contract" state machine.
//
// Layer: cores (reusable SDK implementation, `include!`d by consumers —
// NOT a wire contract, so it lives under `cores/` with `session_handoff`
// rather than `contracts/`: outside the `abi::contracts` namespace and
// the numeric ABI-surface walk, though still covered by the whole-tree
// `modules/sdk` source pin like every core).
// Arena-agnostic: the caller owns the concrete table and supplies
// scratch; this file owns only the SUBSCRIBE / TAKE_RUNG / CHANGES /
// shadow-relist protocol so every table consumer (http edge,
// dns-records-in-graph, …) shares one audited implementation instead of
// re-deriving it.
//
// Includer contract: this file references `SyscallTable` and `abi`
// unqualified; each `include!` site must bring both into scope first —
// `abi` is the SDK root, so `abi::contracts::storage::namespace` and
// `abi::kernel_abi` resolve (module crates via `use crate::abi;
// use crate::abi::SyscallTable;`, the harness via `use fluxor::abi;
// use fluxor::abi::SyscallTable;`).
//
// ## The pattern
//
//   1. One kernel event — the module creates it once
//      (`kernel_abi::event::CREATE`, [`create_event`]) and names it in
//      every subscription it opens. The store signals it; it never writes
//      a byte into any channel of the module, so no self-wired port and
//      no sink exist.
//   2. Subscribe — `SUBSCRIBE (0x1305)` on the prefix with that event.
//      `EAGAIN`/`ENOMEM` is asked again next step; the subscription is
//      opened *before* the first read, so every change after it rings.
//      Cold start marks the consumer *pending* with an empty token: its
//      first read is the relist (§5: cold start == recovery).
//   3. Take — each step `event::POLL`s, and when the event fired asks
//      `TAKE_RUNG (0x1309)` which subscriptions rang, marking each one
//      named *pending* ([`take_rung`]).
//   4. Read — a pending consumer reads `CHANGES (0x1307)` from its token,
//      one bounded page per call, applying each page by key as it lands.
//      *Pending* is cleared only by a page whose `more` is clear; that
//      page carries the 8-byte revision token kept at rest. Any failure
//      (`EAGAIN`, `ENOMEM`, …) leaves the token where it was and the
//      consumer pending, so the next step asks again — an `EAGAIN` also
//      re-rings the subscription, named in the read, once the store can
//      answer.
//   5. Loss recovery with shadow swap — a LOST answer (the token is older
//      than the store can answer) or a cold start relists: `CHANGES` with
//      the empty token, paged by key, into a SHADOW table, swapped in only
//      when the last page lands — never in place, because a table swapped
//      in place is a torn table for any reader mid-scan. The relist's last
//      page carries the token the consumer resumes from.
//   6. Bounded admission — the arena is the caller's; overflow is the
//      caller's to surface (a reader holds no write grant, §6).
//   7. Single-writer prefix discipline — a compiler owns the prefix;
//      the consumer treats it as read-only.
//
// ## Several tables on one event
//
// A module with several table consumers creates ONE event for all of
// them. `TAKE_RUNG` answers every rung subscription the caller holds on
// the event, so the module takes once per step for all of them —
// [`take_rung`] over the whole set — and then [`TableConsumer::advance`]s
// each. [`TableConsumer::step`] is the one-table shorthand that does both.

// `SyscallTable` and `abi` are provided by the `include!` site (see the
// header).

use abi::contracts::storage::namespace::{self as ns, changes, subscribe, take};

/// Steps until a `SUBSCRIBE` refused for a reason other than "not now"
/// is asked again. Rare by construction (a malformed prefix, a store
/// that offers no subscriptions), and cheap to repeat, but not worth a
/// provider call on every step.
const RESUBSCRIBE_BACKOFF_STEPS: u32 = 1024;

/// `CHANGES` pages read in one step at most. A relist of a large prefix
/// spans steps; the step stays bounded whatever the prefix holds.
const PAGES_PER_STEP: usize = 4;

/// Rung handles taken in one `TAKE_RUNG`. More are taken on the next
/// wake: the store signals the event again when they did not fit.
const TAKE_MAX: usize = 16;

/// Errnos the consumer tells apart.
const ERR_AGAIN: i32 = -11;
const ERR_NOMEM: i32 = -12;
const ERR_INVAL: i32 = -22;

/// The caller's table, driven by the consumer. Implementors keep a live
/// table and a shadow table; the helper fills the shadow during a
/// relist and calls [`swap_shadow`](TableSink::swap_shadow) to promote
/// it atomically. `Added`/`Modified` both map to `upsert`; `Deleted`
/// maps to `remove`.
///
/// Records are applied by key and are idempotent: a key reported twice
/// carries its latest value both times, and a `Deleted` for a key the
/// table does not hold is a no-op — the store reports a key created and
/// deleted inside one window rather than omit it.
pub trait TableSink {
    /// Insert or replace `key`'s row. `shadow` selects the rebuild
    /// shadow (`true`) or the live table (`false`).
    fn upsert(&mut self, key: &[u8], value: &[u8], shadow: bool);
    /// Remove `key`'s row from the shadow or live table; a key the
    /// table does not hold is a no-op.
    fn remove(&mut self, key: &[u8], shadow: bool);
    /// Empty the shadow table at the start of a relist (§2 rule 4).
    fn clear_shadow(&mut self);
    /// Atomically promote the shadow table to live.
    fn swap_shadow(&mut self);
}

/// [`TableConsumer::sub`]: no subscription yet (the zero state).
pub const SUB_NONE: u8 = 0;
/// [`TableConsumer::sub`]: subscribed; `handle` names it.
pub const SUB_OPEN: u8 = 1;
/// [`TableConsumer::sub`]: refused; asked again after a backoff.
pub const SUB_REFUSED: u8 = 2;

/// The subscription's persistent bookkeeping. Embed one per consumed
/// prefix in the module's `#[repr(C)]` state. All-zero is
/// [`TableConsumer::new`], so a kernel-zeroed state needs no init. The
/// table itself lives in the caller's arena; this holds the subscription
/// handle and the resume token, which an opaque provider continuation
/// may make as long as `changes::TOKEN_MAX`.
#[repr(C)]
pub struct TableConsumer {
    /// The store's subscription handle while `sub == SUB_OPEN`.
    pub handle: i32,
    /// [`SUB_NONE`], [`SUB_OPEN`] or [`SUB_REFUSED`].
    pub sub: u8,
    /// A read is owed: set by a rung take and at cold start, cleared only
    /// by a `CHANGES` page with `more` clear.
    pub pending: u8,
    /// A relist is in flight: pages land in the shadow table, which is
    /// swapped in when the last one does.
    pub relisting: u8,
    _pad: u8,
    /// Steps left before a refused `SUBSCRIBE` is asked again.
    pub backoff: u32,
    /// Length of `token`. 0: nothing listed yet — the next read relists.
    pub token_len: u16,
    _pad2: [u8; 6],
    /// Where the next read resumes: at rest the 8-byte revision of the
    /// last completed read; mid-read the store's continuation.
    pub token: [u8; changes::TOKEN_MAX],
}

impl TableConsumer {
    pub const fn new() -> Self {
        Self {
            handle: 0,
            sub: SUB_NONE,
            pending: 0,
            relisting: 0,
            _pad: 0,
            backoff: 0,
            token_len: 0,
            _pad2: [0; 6],
            token: [0; changes::TOKEN_MAX],
        }
    }

    /// The revision the live table reflects, once a read has completed:
    /// the at-rest token. `None` before the first completed read, and
    /// while one is mid-way.
    pub fn revision(&self) -> Option<u64> {
        if self.pending != 0 {
            return None;
        }
        changes::token_revision(&self.token[..self.token_len as usize])
    }

    /// Mark this consumer pending when `handle` is its subscription.
    pub fn ring(&mut self, handle: i32) -> bool {
        if self.sub == SUB_OPEN && self.handle == handle {
            self.pending = 1;
            return true;
        }
        false
    }

    /// Drive one step of a module's ONLY table consumer: take the
    /// event's rung subscriptions, then [`advance`](Self::advance).
    /// A module with several consumers on one event calls [`take_rung`]
    /// once over all of them and `advance`s each instead.
    ///
    /// # Safety
    /// As [`advance`](Self::advance).
    pub unsafe fn step<T: TableSink>(
        &mut self,
        sys: &SyscallTable,
        event: i32,
        prefix: &[u8],
        scratch: &mut [u8],
        table: &mut T,
    ) {
        if event < 0 {
            return;
        }
        take_rung(sys, event, &mut [&mut *self]);
        self.advance(sys, event, prefix, scratch, table);
    }

    /// Subscribe if not yet subscribed, then, while a read is owed, read
    /// and apply up to [`PAGES_PER_STEP`] `CHANGES` pages. `scratch` is
    /// a caller-owned buffer for one page: it must hold the page head,
    /// the largest record (key and value) and the trailer
    /// (`changes::min_out_cap`); a smaller one answers `ENOMEM` and the
    /// read waits, keeping the prior table. It is transient — consumers
    /// stepped in turn may share one.
    ///
    /// # Safety
    /// `sys` must be a live syscall table; `event >= 0` an event the
    /// calling module created.
    pub unsafe fn advance<T: TableSink>(
        &mut self,
        sys: &SyscallTable,
        event: i32,
        prefix: &[u8],
        scratch: &mut [u8],
        table: &mut T,
    ) {
        if event < 0 {
            return;
        }
        if self.sub != SUB_OPEN && !self.subscribe(sys, event, prefix) {
            return;
        }
        let mut fence = [0u8; abi::fence::WIRE_MAX_LEN];
        let mut pages = 0;
        while self.pending != 0 && pages < PAGES_PER_STEP {
            pages += 1;
            if self.token_len == 0 && self.relisting == 0 {
                // A relist starts from an empty shadow (§2 rule 4).
                table.clear_shadow();
                self.relisting = 1;
            }
            let token_len = self.token_len as usize;
            let n = read_changes(
                sys,
                prefix,
                self.handle,
                &self.token[..token_len],
                scratch,
                &mut fence,
            );
            if n < 0 {
                if n == ERR_INVAL && token_len != 0 && token_len != changes::REVISION_TOKEN_LEN {
                    // A continuation the store no longer recognises (it
                    // restarted mid-read): start the read over as a relist.
                    self.restart_relist();
                    continue;
                }
                // EAGAIN (the store re-rings us when it can answer),
                // ENOMEM or anything else: keep the token and stay
                // pending; the next step asks again.
                return;
            }
            let Some(page) = changes::decode_page(&scratch[..n as usize]) else {
                return;
            };
            if page.lost {
                // The token precedes what the store can answer: relist.
                self.restart_relist();
                continue;
            }
            if page.more && page.token.is_empty() {
                return; // no way to continue; ask again from where we were
            }
            let shadow = self.relisting != 0;
            for rec in page.records() {
                match rec.kind {
                    changes::KIND_ADDED | changes::KIND_MODIFIED => {
                        table.upsert(rec.key, rec.val, shadow)
                    }
                    changes::KIND_DELETED => table.remove(rec.key, shadow),
                    _ => {}
                }
            }
            self.token[..page.token.len()].copy_from_slice(page.token);
            self.token_len = page.token.len() as u16;
            if !page.more {
                if self.relisting != 0 {
                    table.swap_shadow();
                    self.relisting = 0;
                }
                self.pending = 0;
            }
        }
    }

    /// Open the subscription. `true` once open (and the first read owed).
    unsafe fn subscribe(&mut self, sys: &SyscallTable, event: i32, prefix: &[u8]) -> bool {
        if self.sub == SUB_REFUSED {
            if self.backoff > 0 {
                self.backoff -= 1;
                return false;
            }
            self.sub = SUB_NONE;
        }
        let rc = subscribe(sys, prefix, event, 0);
        if rc >= 0 {
            self.handle = rc;
            self.sub = SUB_OPEN;
            // Cold start == recovery: the first read is the relist, from
            // an empty token, unless a token is already held.
            self.pending = 1;
            return true;
        }
        if rc != ERR_AGAIN && rc != ERR_NOMEM {
            self.sub = SUB_REFUSED;
            self.backoff = RESUBSCRIBE_BACKOFF_STEPS;
        }
        false
    }

    /// Drop the token and any half-built shadow; the next read relists.
    fn restart_relist(&mut self) {
        self.token_len = 0;
        self.relisting = 0;
    }
}

impl Default for TableConsumer {
    fn default() -> Self {
        Self::new()
    }
}

/// Create the module's subscription event (`kernel_abi::event::CREATE`).
/// Returns the event fd, or a negative errno.
///
/// # Safety
/// `sys` must be a live syscall table.
pub unsafe fn create_event(sys: &SyscallTable) -> i32 {
    (sys.provider_call)(-1, abi::kernel_abi::event::CREATE, core::ptr::null_mut(), 0)
}

/// `event::POLL` the module's event and, when it fired, `TAKE_RUNG` once,
/// marking every consumer whose subscription is named pending. A take
/// whose handles did not all fit has the store signal the event again,
/// so the rest are taken on the next step. Returns how many handles the
/// take named.
///
/// # Safety
/// `sys` must be a live syscall table; `event` an event the calling
/// module created.
pub unsafe fn take_rung(
    sys: &SyscallTable,
    event: i32,
    consumers: &mut [&mut TableConsumer],
) -> usize {
    if event < 0 {
        return 0;
    }
    let fired = (sys.provider_call)(
        event,
        abi::kernel_abi::event::POLL,
        core::ptr::null_mut(),
        0,
    );
    if fired <= 0 {
        return 0;
    }
    let mut out = [0u8; take::HEAD_LEN + 4 * TAKE_MAX];
    let req = take::Request {
        event,
        out_ptr: out.as_mut_ptr() as u64,
        out_cap: out.len() as u32,
    };
    let mut arg = [0u8; take::REQUEST_LEN];
    let Some(len) = take::encode(&mut arg, &req) else {
        return 0;
    };
    let n = (sys.provider_call)(-1, ns::TAKE_RUNG, arg.as_mut_ptr(), len);
    if n < 0 {
        return 0;
    }
    let Some((_more, handles)) = take::decode(&out[..(n as usize).min(out.len())]) else {
        return 0;
    };
    let mut named = 0;
    for h in handles {
        named += 1;
        for c in consumers.iter_mut() {
            if c.ring(h) {
                break;
            }
        }
    }
    named
}

/// Encode + issue `SUBSCRIBE (0x1305)` on `prefix` with the caller's
/// `event` (`namespace::subscribe`). Returns the subscription handle or a
/// negative errno.
///
/// # Safety
/// `sys` must be a live syscall table; `event` an event the calling
/// module created.
pub unsafe fn subscribe(sys: &SyscallTable, prefix: &[u8], event: i32, flags: u8) -> i32 {
    let mut arg = [0u8; ARG_MAX];
    let req = subscribe::Request {
        prefix,
        event,
        flags,
    };
    let Some(len) = subscribe::encode(&mut arg, &req) else {
        return ERR_INVAL; // prefix too long for the scratch
    };
    (sys.provider_call)(-1, ns::SUBSCRIBE, arg.as_mut_ptr(), len)
}

/// Encode + issue one `CHANGES (0x1307)` page read into `out`
/// (`namespace::changes`), writing the encoded fence into `fence`
/// (>= `fence::WIRE_MAX_LEN`). `sub` is the subscription the read serves
/// (or -1). Returns the byte count written to `out`, or a negative errno.
///
/// # Safety
/// `sys` must be a live syscall table; `out` and `fence` must remain
/// valid for the duration of the call — the store writes the page into
/// `out` and the covered fence into `fence`.
pub unsafe fn read_changes(
    sys: &SyscallTable,
    prefix: &[u8],
    sub: i32,
    token: &[u8],
    out: &mut [u8],
    fence: &mut [u8],
) -> i32 {
    let mut arg = [0u8; ARG_MAX];
    let req = changes::Request {
        prefix,
        sub,
        token,
        out_ptr: out.as_mut_ptr() as u64,
        out_cap: out.len().min(u32::MAX as usize) as u32,
        fence_out_ptr: fence.as_mut_ptr() as u64,
        fence_out_cap: fence.len().min(u16::MAX as usize) as u16,
    };
    let Some(len) = changes::encode_request(&mut arg, &req) else {
        return ERR_INVAL;
    };
    (sys.provider_call)(-1, ns::CHANGES, arg.as_mut_ptr(), len)
}

/// Scratch for the SUBSCRIBE / CHANGES arg encodings: a consumer's prefix
/// (well under this), the longest token and the fixed fields.
const ARG_MAX: usize = 256 + changes::TOKEN_MAX + changes::REQUEST_FIXED_LEN;
