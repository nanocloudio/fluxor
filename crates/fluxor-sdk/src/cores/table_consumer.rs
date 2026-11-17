// Core: table_consumer — the consumer side of a `storage.namespace`
// subscription: a table kept equal to what a store holds under a prefix.
//
// Layer: cores (library code in `fluxor-sdk`, linked by its consumers —
// NOT a wire contract, so it is not ABI and not hashed into the
// ABI-surface digest).
// Arena-agnostic: the caller owns the concrete table and supplies
// scratch; this file owns only the SUBSCRIBE / poll / CHANGES /
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
//   1. Subscribe — `SUBSCRIBE` on the prefix. `EAGAIN` is asked again
//      next step, any other refusal after a backoff; the subscription is
//      opened *before* the first read, so every change after it rings. A
//      new subscription is *pending* with the token it holds — empty on a
//      cold start, so its first read is the relist: a cold start is a
//      recovery. The subscription is a signalling handle: the store rings
//      its doorbell on a change, and the kernel wakes the module. The store
//      never writes a byte into any channel of the module, so no self-wired
//      port and no sink exist.
//   2. Poll — each step `HANDLE_POLL`s the subscription; `POLL_IN` (once
//      per ring: the poll takes it) marks the consumer *pending*.
//   3. Read — a pending consumer reads `CHANGES` from its token through
//      its subscription's handle, one bounded page per call, applying each
//      page by key as it lands.
//      *Pending* is cleared only by a page whose `more` is clear; that
//      page carries the 8-byte revision token kept at rest. Any failure
//      (`EAGAIN`, `ENOMEM`, …) leaves the token where it was and the
//      consumer pending, so the next step asks again — an `EAGAIN` also
//      re-rings the subscription the read came through, once the store can
//      answer.
//   4. Loss recovery with shadow swap — a LOST answer (the token is older
//      than the store can answer), a continuation the store no longer
//      recognises, or a cold start relists: `CHANGES` with the empty token,
//      paged by key, into a SHADOW table, swapped in only when the last
//      page lands — never in place, because a table swapped in place is a
//      torn table for any reader mid-scan. The relist's last page carries
//      the token the consumer resumes from.
//   5. Bounded admission — the arena is the caller's; overflow is the
//      caller's to surface (a reader holds no write grant).
//   6. Single-writer prefix discipline — a compiler owns the prefix;
//      the consumer treats it as read-only.
//
// ## Which store
//
// Every store op goes to the provider `store` names: empty, the contract's
// default (`handle == -1`); otherwise a keyed volume, or `platform` for the
// platform's own store beneath a graph-local default, which the consumer
// binds by name once (`kernel_abi::bind`) and keeps the bound handle of. A
// module names its store by a `str` param it declares as its
// `storage.namespace` claim's `selector_param`, so the composer checks the
// store a table reads from as it checks every claim. A subscription opened
// through the bound handle comes back routed to the same store, and its
// `CHANGES` reads go through it, so the consumer is the same machine
// whichever store it follows.
//
// ## Several tables
//
// Each consumer holds its own subscription handle and polls it, so a module
// with several table consumers keeps them in its state side by side — the
// consumer *is* the module's map from a subscription to the table it feeds —
// and [`TableConsumer::step`]s each.

// `SyscallTable` and `abi` are provided by the `include!` site (see the
// header).

use fluxor_abi as abi;
use fluxor_abi::kernel_abi::SyscallTable;

use abi::contracts::storage::namespace::{self as ns, changes, subscribe};

/// Steps until a `SUBSCRIBE` refused for a reason other than "not now"
/// is asked again. Rare by construction (a malformed prefix, a store
/// that offers no subscriptions, a subscription table at its ceiling),
/// and not worth a provider call on every step: a store counts and logs
/// every refusal at capacity, so asking each step would turn one full
/// table into a refusal per step.
pub const RESUBSCRIBE_BACKOFF_STEPS: u32 = 1024;

/// `CHANGES` pages read in one step at most. A relist of a large prefix
/// spans steps; the step stays bounded whatever the prefix holds.
pub const PAGES_PER_STEP: usize = 4;

/// Errnos the consumer tells apart.
pub const ERR_AGAIN: i32 = -11;
pub const ERR_INVAL: i32 = -22;

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
    /// Empty the shadow table at the start of a relist.
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
/// table itself lives in the caller's arena; this holds the store binding,
/// the subscription handle and the resume token, which an opaque provider
/// continuation may make as long as `changes::TOKEN_MAX`.
#[repr(C)]
pub struct TableConsumer {
    /// The store's subscription handle while `sub == SUB_OPEN`.
    pub handle: i32,
    /// The handle bound to a named store while `store_bound` is set.
    pub store: i32,
    /// [`SUB_NONE`], [`SUB_OPEN`] or [`SUB_REFUSED`].
    pub sub: u8,
    /// A read is owed: set by a ring and at cold start, cleared only by a
    /// `CHANGES` page with `more` clear.
    pub pending: u8,
    /// A relist is in flight: pages land in the shadow table, which is
    /// swapped in when the last one does.
    pub relisting: u8,
    pub _pad1: u8,
    /// Steps left before a refused `SUBSCRIBE` is asked again.
    pub backoff: u32,
    /// Length of `token`. 0: nothing listed yet — the next read relists.
    pub token_len: u16,
    /// `store` holds the binding of the named store, opened once.
    pub store_bound: u8,
    pub _pad2: [u8; 5],
    /// Where the next read resumes: at rest the 8-byte revision of the
    /// last completed read; mid-read the store's continuation.
    pub token: [u8; changes::TOKEN_MAX],
}

impl TableConsumer {
    pub const fn new() -> Self {
        Self {
            handle: 0,
            store: 0,
            sub: SUB_NONE,
            pending: 0,
            relisting: 0,
            _pad1: 0,
            backoff: 0,
            token_len: 0,
            store_bound: 0,
            _pad2: [0; 5],
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

    /// Drive one step: subscribe if not yet subscribed, mark the consumer
    /// pending when its subscription rang, then read what is owed (see
    /// [`advance`](Self::advance)).
    ///
    /// # Safety
    /// As [`advance`](Self::advance).
    pub unsafe fn step<T: TableSink>(
        &mut self,
        sys: &SyscallTable,
        store: &[u8],
        prefix: &[u8],
        scratch: &mut [u8],
        table: &mut T,
    ) {
        if self.sub == SUB_OPEN && rang(sys, self.handle) {
            self.pending = 1;
        }
        self.advance(sys, store, prefix, scratch, table);
    }

    /// Subscribe if not yet subscribed, then, while a read is owed, read
    /// and apply up to [`PAGES_PER_STEP`] `CHANGES` pages, all from the
    /// store `store` names (empty: the default; see "Which store"). `scratch` is
    /// a caller-owned buffer for one page: it must hold the page head,
    /// the largest record (key and value) and the trailer
    /// (`changes::min_out_cap`); a smaller one answers `ENOMEM` and the
    /// read waits, keeping the prior table. It is transient — consumers
    /// stepped in turn may share one.
    ///
    /// # Safety
    /// `sys` must be a live syscall table.
    pub unsafe fn advance<T: TableSink>(
        &mut self,
        sys: &SyscallTable,
        store: &[u8],
        prefix: &[u8],
        scratch: &mut [u8],
        table: &mut T,
    ) {
        if self.sub != SUB_OPEN && !self.subscribe(sys, store, prefix) {
            return;
        }
        let mut pages = 0;
        while self.pending != 0 && pages < PAGES_PER_STEP {
            pages += 1;
            if self.token_len == 0 && self.relisting == 0 {
                // A relist starts from an empty shadow.
                table.clear_shadow();
                self.relisting = 1;
            }
            let token_len = self.token_len as usize;
            let n = read_changes(
                sys,
                self.handle,
                prefix,
                &self.token[..token_len],
                scratch,
                None,
            );
            if n < 0 {
                if n == ERR_INVAL && token_len != 0 && token_len != changes::REVISION_TOKEN_LEN {
                    // A continuation the store does not recognise (it
                    // restarted mid-read): start the read over as a relist.
                    self.restart_relist();
                    continue;
                }
                // EAGAIN (the store rings again when it can answer),
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

    /// Open the subscription. `true` once open (and a read owed from the
    /// token held: the relist when there is none).
    unsafe fn subscribe(&mut self, sys: &SyscallTable, store: &[u8], prefix: &[u8]) -> bool {
        if self.sub == SUB_REFUSED {
            if self.backoff > 0 {
                self.backoff -= 1;
                return false;
            }
            self.sub = SUB_NONE;
        }
        let h = match self.store_handle(sys, store) {
            Ok(h) => h,
            Err(e) => {
                self.refuse(e);
                return false;
            }
        };
        let rc = subscribe(sys, h, prefix, 0);
        if rc >= 0 {
            self.handle = rc;
            self.sub = SUB_OPEN;
            // Whatever changed before the subscription existed rang no one:
            // read from the token held, which is the relist on a cold start.
            self.pending = 1;
            return true;
        }
        self.refuse(rc);
        false
    }

    /// A refused subscribe: asked again next step on `EAGAIN`, else after
    /// the backoff.
    fn refuse(&mut self, rc: i32) {
        if rc != ERR_AGAIN {
            self.sub = SUB_REFUSED;
            self.backoff = RESUBSCRIBE_BACKOFF_STEPS;
        }
    }

    /// The handle ops on the store `store` names go through: `-1` for the
    /// default, else the binding of the named store, opened on first use and
    /// kept. A negative errno when the store cannot be bound.
    ///
    /// # Safety
    /// `sys` must be a live syscall table.
    pub unsafe fn store_handle(&mut self, sys: &SyscallTable, store: &[u8]) -> Result<i32, i32> {
        if store.is_empty() {
            return Ok(-1);
        }
        if self.store_bound == 0 {
            let h = bind_store(sys, store);
            if h < 0 {
                return Err(h);
            }
            self.store = h;
            self.store_bound = 1;
        }
        Ok(self.store)
    }

    /// Drop the token and any half-built shadow; the next read relists.
    pub fn restart_relist(&mut self) {
        self.token_len = 0;
        self.relisting = 0;
    }
}

impl Default for TableConsumer {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether subscription `handle` rang since the last poll: `HANDLE_POLL`
/// for `POLL_IN`, which takes the ring.
///
/// # Safety
/// `sys` must be a live syscall table.
pub unsafe fn rang(sys: &SyscallTable, handle: i32) -> bool {
    let mut events = [abi::kernel_abi::poll::IN as u8];
    let rc = (sys.provider_call)(
        handle,
        abi::kernel_abi::HANDLE_POLL,
        events.as_mut_ptr(),
        events.len(),
        core::ptr::null_mut(),
        0,
    );
    rc > 0 && rc as u32 & abi::kernel_abi::poll::IN != 0
}

/// Encode + issue `SUBSCRIBE` on `prefix` (`namespace::subscribe`) through
/// `handle` (`-1`, or a handle bound to the store). Returns the subscription
/// handle (routed to the bound store), which polls ready when it rings, or a
/// negative errno.
///
/// # Safety
/// `sys` must be a live syscall table.
pub unsafe fn subscribe(sys: &SyscallTable, handle: i32, prefix: &[u8], flags: u8) -> i32 {
    let mut arg = [0u8; subscribe::ARG_MAX];
    let req = subscribe::Request { prefix, flags };
    let Some(len) = subscribe::encode(&mut arg, &req) else {
        return ERR_INVAL;
    };
    (sys.provider_call)(
        handle,
        ns::SUBSCRIBE,
        arg.as_mut_ptr(),
        len,
        core::ptr::null_mut(),
        0,
    )
}

/// Encode + issue one `CHANGES` page read into `out` (`namespace::changes`)
/// through `handle`: the subscription the read serves, or `-1` (or a handle
/// bound to the store) for a read none serves. The fence of the page, when
/// `fence` asks for it, is decoded from the trailer. Returns the byte count
/// written to `out`, or a negative errno.
///
/// # Safety
/// `sys` must be a live syscall table.
pub unsafe fn read_changes(
    sys: &SyscallTable,
    handle: i32,
    prefix: &[u8],
    token: &[u8],
    out: &mut [u8],
    fence: Option<&mut Option<abi::fence::Fence>>,
) -> i32 {
    let mut arg = [0u8; changes::ARG_MAX];
    let req = changes::Request { prefix, token };
    let Some(len) = changes::encode_request(&mut arg, &req) else {
        return ERR_INVAL;
    };
    let rc = (sys.provider_call)(
        handle,
        ns::CHANGES,
        arg.as_mut_ptr(),
        len,
        out.as_mut_ptr(),
        out.len(),
    );
    if let Some(f) = fence {
        *f = if rc >= 0 {
            abi::fence::trailer::get(&arg[..len])
        } else {
            None
        };
    }
    rc
}

/// Bind the store registered under `name` (`kernel_abi::bind`, `NAME`): the
/// bound handle, or a negative errno.
///
/// # Safety
/// `sys` must be a live syscall table.
pub unsafe fn bind_store(sys: &SyscallTable, name: &[u8]) -> i32 {
    let mut b = [0u8; abi::kernel_abi::bind::ARG_MAX];
    let Some(n) = abi::kernel_abi::bind::name(name, &mut b) else {
        return ERR_INVAL;
    };
    (sys.provider_open)(
        u32::from(abi::registry::storage_namespace::ID),
        abi::kernel_abi::bind::BIND,
        b.as_ptr(),
        n,
    )
}
