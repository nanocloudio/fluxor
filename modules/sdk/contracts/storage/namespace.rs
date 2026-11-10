// Contract: namespace — directory-like storage surface.
//
// Layer: contracts/storage (public, stable).
//
// One of four canonical storage surfaces (`storage.block`,
// `file.data`, `storage.namespace`, `storage.object`) — see
// `docs/architecture/storage_capability_surface.md`. The namespace
// surface describes name-keyed addressing — entries living under a
// prefix — without claiming anything about the bytes those names
// address. A provider that publishes `storage.namespace` typically
// also publishes `storage.object` or `file.data` so consumers can
// fetch entry contents; the two are kept separate so pure index
// providers (HTTP listings, S3 ListBucket, object-store directories,
// cluster metadata) need not hold byte data themselves.
//
// ## Handle identity
//
// `LOOKUP` and `SUBSCRIBE` return a tagged FD: providers encode the
// returned slot via `kernel_abi::fd::tag_fd(FD_TAG_STORAGE_NAMESPACE,
// slot)`. The kernel vtable wrapper strips the tag before
// re-entering the provider, so inbound ops see a raw slot. Tagging
// is what lets `provider_query(handle, query_key::LAST_FENCE, …)`
// resolve the contract from the handle and prevents handle
// collisions when a graph hosts multiple storage providers issuing
// identical raw slot numbers.
//
// ## Fence advertisement per op shape
//
//   - `LOOKUP` advertises its handle's fence via
//     `provider_query(handle, query_key::LAST_FENCE, …)`, and `STAT`
//     answers against that same handle and view.
//   - A `SUBSCRIBE` handle names a doorbell, not a view, and carries no
//     fence: `LAST_FENCE` on it is `ENOSYS`. The `CHANGES` read it asks
//     for carries its own.
//   - Handle=-1 one-shot ops (`LIST`, `RENAME`, `DELETE`, `BIND`,
//     `CHANGES`) carry a `[fence_out_ptr: u64 LE, fence_out_cap: u16 LE]`
//     pair in their arg layout. The provider writes the encoded `Fence`
//     (up to `fence::WIRE_MAX_LEN` bytes) into that buffer atomically
//     with the op return; callers decode via `Fence::decode`. A null
//     `fence_out_ptr`, or a `fence_out_cap` below `fence::WIRE_MAX_LEN`,
//     is `EINVAL`, refused before the op acts.
//
// Typical advertisements: `ViewConsistent { source, revision }` for
// snapshot reads, `LocalDurable { device_id }` for committed
// renames/deletes, `ReplicatedDurable { source, .. }` when a
// quorum-replicated provider acks, `Volatile` from a provider that keeps
// nothing across a reset. See `contracts::fence` for the dominance rules.
//
// ## Operations
//
//   LOOKUP    — resolve a path under this namespace to its entry
//               kind and storage handle.
//   STAT      — read a resolved entry's metadata (size, mtime, kind,
//               etag) through its LOOKUP handle.
//   LIST      — enumerate entries under a prefix; results paged via
//               an opaque cursor so partial scans compose.
//   BIND      — create a binding `name → {kind, target}`: the one op
//               that mints a name, so a provider needs no private
//               creation vocabulary of its own.
//   RENAME    — rename or move an entry within the namespace.
//               Atomic within a single provider; cross-provider
//               renames are out of scope for this surface.
//   DELETE    — remove an entry. Recursive delete on directories is
//               opt-in via a flag.
//   SUBSCRIBE — watch a prefix: the provider signals the caller's own
//               kernel event when something under it changes
//               (level-triggered; no bytes are delivered).
//   TAKE_RUNG — which of the caller's subscriptions on an event have
//               changed since it last asked; the caller then reads
//               them with CHANGES.
//   CHANGES   — what changed under a prefix since a revision, one
//               bounded page per call.
//   CLOSE     — release a LOOKUP or SUBSCRIBE handle.
//   CAPS      — capability bits: which optional/mutation ops this
//               provider implements (mirrors `fs::CAPS`).
//
// ## Opcode class
//
// Opcodes occupy the 0x13__ range — class byte 0x13 maps to
// `kernel::module::provider::contract::STORAGE_NAMESPACE`. A dedicated
// class id lets kernel routing dispatch namespace ops to a
// namespace provider without colliding with FS (0x09__) or BUFFER
// (0x0A__).
//
// A subscription is a doorbell, not a stream: the provider never writes
// a consumer's channel. It signals the consumer's own kernel event
// (`kernel_abi::event`), and the consumer asks TAKE_RUNG which of its
// subscriptions rang and reads each with CHANGES. The section
// "Subscriptions" of `docs/architecture/storage_capability_surface.md`
// describes the protocol end to end.

/// A write's answer here is classified as `storage.object`'s is.
pub use super::object::{write_answer, WriteAnswer};

/// Look up a name under this namespace.
///
/// `handle = -1`; `arg` points at the UTF-8 path (no null
/// terminator), `arg_len` is its length. On success returns a
/// non-negative handle into the namespace's resolved-entry table
/// (passed to `STAT` and `CLOSE`); on failure returns a negative
/// errno (`-2 ENOENT`, `-22 EINVAL`, …).
///
/// Resolution is snapshot-relative: the provider records the
/// revision it observed and any subsequent `STAT` against this
/// handle answers against the same view. Callers wanting freshness
/// re-`LOOKUP`. The fence on this handle (via
/// `provider_query(handle, query_key::LAST_FENCE, …)`) is
/// `ViewConsistent { source, revision }`.
pub use super::super::super::registry::storage_namespace::LOOKUP;

/// Read metadata for a resolved entry.
///
/// `handle` is a LOOKUP-returned handle; `arg` points at an output
/// buffer of layout:
///
/// ```text
///   [size: u64 LE]                — bytes (0 for directories)
///   [mtime: u64 LE]               — provider-clock seconds
///   [kind: u8]                    — 0=object, 1=namespace, 2=stream
///   [etag_len: u8]                — 0..=32
///   [etag: etag_len bytes]        — opaque provider tag
/// ```
///
/// Returns the number of bytes written, or negative errno.
pub use super::super::super::registry::storage_namespace::STAT;

/// List entries under a prefix, in ascending bytewise name order, one page
/// per call, resumed by a cursor.
///
/// `handle = -1`; `arg` points at a request:
///
/// ```text
///   [prefix_len: u16 LE]
///   [prefix: prefix_len bytes UTF-8]
///   [cursor_len: u16 LE]          — 0 for the first page
///   [cursor: cursor_len bytes]    — otherwise exactly the cursor a previous
///                                   page returned
///   [out_buf: ptr u64 LE]
///   [out_cap: u32 LE]
///   [fence_out_ptr: u64 LE]       — receives Fence::encode bytes
///   [fence_out_cap: u16 LE]       — must be >= `fence::WIRE_MAX_LEN`
/// ```
///
/// On success the provider writes batched entries into `out_buf`
/// and the encoded fence into `fence_out_ptr`; the return value is
/// the byte count written to `out_buf`. Each entry is:
///
/// ```text
///   [name_len: u8]
///   [kind: u8]                    — 0=object, 1=namespace, 2=stream
///   [name: name_len bytes UTF-8]
/// ```
///
/// followed by a trailing cursor record:
///
/// ```text
///   [0xFF]
///   [0xFF]                        — not a valid `kind`; see below
///   [cursor_len: u8]              — 0 means END OF LISTING
///   [cursor: cursor_len bytes]    — echo to fetch the next page
/// ```
///
/// [`list`] is the codec for both sides; providers and consumers use it
/// rather than spelling the offsets themselves.
///
/// ## Names: two shapes
///
/// A provider lists in one of two shapes, and says which in [`CAPS`]:
///
///   - **key-shaped** ([`caps::CHILD_NAMES`] clear): every entry is a whole
///     key that starts with the prefix, at any depth below it. A flat key
///     store is this shape.
///   - **directory-shaped** ([`caps::CHILD_NAMES`] set): every entry is an
///     immediate child of the prefix, named relative to it, so a name never
///     contains `/`. The entry's full path is the prefix joined to the name
///     with one `/` (none when the prefix is empty or already ends in `/`).
///     A filesystem tree is this shape.
///
/// A consumer that turns a name into a key for `storage.object` or `fs`
/// reads the bit; a provider that does not implement `CAPS` is key-shaped.
///
/// ## Cursor
///
/// The cursor is the last name the page returned, and the next page resumes
/// strictly after it in name order. A name written or deleted between pages
/// is seen or not according to whether it sorts after the cursor, a write
/// behind the cursor never shifts, skips or repeats an entry, and a name
/// present for the whole listing is seen exactly once. Each page carries its
/// own fence, so a listing is a sequence of views, not a snapshot.
///
/// A cursor is a name of this provider's shape or it was not issued here:
/// `EINVAL` when it is not UTF-8, and, by shape, when it does not start with
/// the prefix (key-shaped) or contains `/` (directory-shaped).
///
/// The empty cursor means "first page" in a request and "end of listing"
/// in a page, so the empty name is never an entry.
///
/// A name is at most [`STORAGE_KEY_MAX`](super::handle::STORAGE_KEY_MAX)
/// bytes, which is also the longest cursor. The prefix is a path, bounded by
/// [`PATH_MAX`]: a directory-shaped provider's prefix names a directory
/// however deep it sits, and a key-shaped provider holds no key under a
/// prefix longer than a key.
///
/// `cursor_len` in the trailing record is **u8**, narrower than the `u16` the
/// request carries. It is stated here because a consumer parses one shape,
/// and a provider that guesses the other width corrupts every page but the
/// last.
///
/// ## Why the trailer is two bytes
///
/// A consumer tells an entry from the trailer by reading the record's first
/// byte, so that byte has to mean one thing. An entry leads with `name_len`,
/// and a name of exactly 255 bytes makes `name_len` equal the `0xFF` marker;
/// read by its first byte alone, such an entry looks like the end of the page
/// and every entry after it is lost with no error.
///
/// The second `0xFF` is what disambiguates, and it is free: the byte in that
/// position is an entry's [`kind`], which has three valid values, so `0xFF`
/// there can never begin an entry. A consumer MUST check both bytes
/// ([`is_trailer`]).
///
/// A provider that meets a name longer than `STORAGE_KEY_MAX` MUST refuse the listing
/// with `EOVERFLOW` rather than skip the entry: a short page a caller
/// believes is complete is a silent loss.
///
/// ## Paging
///
/// A provider MUST page rather than refuse: fill whole entries while keeping
/// room for the trailing record, emit a cursor, and let the caller ask
/// again. Answering ENOMEM because a whole listing does not fit turns the
/// caller's buffer into a ceiling on how many entries a prefix may hold. A
/// page MUST make progress: when not even one entry plus the trailer fits,
/// the provider refuses with `ENOMEM` rather than return an empty page that
/// is not the last ([`list::min_out_cap`] is what one entry needs).
///
/// ## Errors
///
///   - `EINVAL` — malformed request, a prefix longer than [`PATH_MAX`], a
///     null output or fence pointer, `fence_out_cap` below
///     `fence::WIRE_MAX_LEN`, or a cursor this provider did not issue for
///     this prefix.
///   - `ENOMEM` — `out_cap` cannot hold one entry plus the trailer.
///   - `EOVERFLOW` — a name in range exceeds `STORAGE_KEY_MAX`.
pub use super::super::super::registry::storage_namespace::LIST;

/// Rename or move an entry. Atomic within a single namespace
/// provider.
///
/// `handle = -1`; `arg` is:
///
/// ```text
///   [src_len: u16 LE]
///   [src: src_len bytes]
///   [dst_len: u16 LE]
///   [dst: dst_len bytes]
///   [flags: u8]                   — bit 0: replace-existing
///   [fence_out_ptr: u64 LE]       — receives Fence::encode bytes
///   [fence_out_cap: u16 LE]       — must be >= `fence::WIRE_MAX_LEN`
/// ```
///
/// Returns 0 or negative errno. The provider writes the achieved
/// fence — `LocalDurable { device_id }` for local providers,
/// `ReplicatedDurable { source, .. }` once a quorum acks,
/// `Volatile` for in-memory namespaces — into `fence_out_ptr`
/// atomically with returning success.
///
/// `RENAME`, `DELETE` and `BIND` MAY answer `EINPROGRESS` when the
/// provider cannot decide the write inside the call (a replicated
/// provider decides it at its log position). The caller asks again later
/// with byte-identical arguments; the answer to a later ask is the
/// decision and its fence. The provider keys an undecided write by the
/// calling module and the request's bytes, so asking again is never a
/// second write. This is the same rule as `storage.object`'s writes.
pub use super::super::super::registry::storage_namespace::RENAME;

/// Delete an entry.
///
/// `handle = -1`; `arg` is:
///
/// ```text
///   [path_len: u16 LE]
///   [path: path_len bytes]
///   [flags: u8]                   — bit 0: recursive
///   [fence_out_ptr: u64 LE]       — receives Fence::encode bytes
///   [fence_out_cap: u16 LE]       — must be >= `fence::WIRE_MAX_LEN`
/// ```
///
/// Returns 0 or negative errno, or `EINPROGRESS` as for `RENAME`. Same
/// fence-advertisement rules as `RENAME` — the encoded fence is written
/// into `fence_out_ptr` atomically with the op return.
pub use super::super::super::registry::storage_namespace::DELETE;

/// Watch a prefix: the provider signals the caller's kernel event whenever
/// something under the prefix changes. Level-triggered — a doorbell, never a
/// stream: no key, value or record is pushed anywhere.
///
/// `handle = -1`; `arg` is ([`subscribe`] is the codec):
///
/// ```text
///   [prefix_len: u16 LE]
///   [prefix: prefix_len bytes]
///   [event: i32 LE]               — a tagged event fd the CALLER owns
///                                   (`kernel_abi::event::CREATE`)
///   [flags: u8]                   — bit 0: ring once now
/// ```
///
/// Returns a non-negative subscription handle (passed to `CLOSE`, named by
/// [`TAKE_RUNG`] and [`CHANGES`]) or a negative errno. The handle carries no
/// fence.
///
/// ## Delivery
///
/// The provider keeps one *rung* bit per subscription. A change under the
/// prefix that finds the bit clear sets it and signals the event; one that
/// finds it set does nothing. [`TAKE_RUNG`] returns and clears the bits. A
/// consumer's step is therefore: `event::POLL`, then `TAKE_RUNG` when the
/// event fired, marking each returned subscription *pending*, then a
/// [`CHANGES`] read of each pending one, clearing *pending* only when a read
/// completes (a page with `more` clear). Whatever the interleaving, a change
/// is followed by a completed read that observes it: if the bit was clear
/// the signal follows the change; if set, the take that clears it is still
/// to come, and the read follows the take.
///
/// Two obligations make that hold. `POLL` consumes the signal while a set
/// bit sends no other, so a `TAKE_RUNG` that fails, or answers `more`, is
/// owed and asked again on the next step whether or not the event fires
/// again. And a read that fails leaves the subscription *pending*: its next
/// step reads again, since no further signal may come. A consumer holding
/// several subscriptions uses one event for all of them and takes once per
/// step for the whole set.
///
/// ## Ownership and lifetime
///
///   - The event must belong to the calling module (`query_key::EVENT_OWNER`).
///     Before every signal the provider checks that the subscribing module
///     occupancy still stands (`query_key::MODULE_LIVE`) and still owns the
///     event; a subscription whose module is gone, or whose event slot
///     another module now holds, is dropped, never signalled. A module that
///     destroys its event closes the subscriptions naming it first: until a
///     change finds the slot free or another module's they stay open, and
///     they ring the slot if the module's own next `CREATE` takes it.
///   - Idempotent: a repeat with the same owner, module occupancy, event and
///     prefix returns the existing handle (and rings once again when bit 0
///     is set), so a module re-running its subscribe path cannot leak.
///   - A handle answers its opener alone — its owner and its module
///     occupancy; to anyone else it is as if not open.
///   - A subscription ends with its subscriber. Once the owner that opened
///     it is released, or the module occupancy that opened it ends
///     (finished, restarted, its slot reassigned), it is never signalled
///     again, and the provider frees it: at once on the owner-release
///     notification, or at its next change or the sweep a refusal at
///     capacity makes first.
///
/// ## Errors
///
///   - `EINVAL` — malformed request, a prefix longer than this provider can
///     hold, an `event` that is not a tagged event fd the calling module
///     owns, or a call from outside any module.
///   - `ENOMEM` — the provider's subscription table is full after its dead
///     subscriptions are swept, or the calling owner holds the provider's
///     per-owner quota where it keeps one. A provider whose table is a
///     resource-ledger pool counts the refusal against that pool.
pub use super::super::super::registry::storage_namespace::SUBSCRIBE;

/// Which of the caller's subscriptions on an event have rung since it last
/// asked; returns and clears their rung bits.
///
/// `handle = -1`; `arg` is ([`take`] is the codec):
///
/// ```text
///   [event: i32 LE]               — the event the subscriptions name
///   [out_buf: ptr u64 LE]
///   [out_cap: u32 LE]
/// ```
///
/// On success the provider writes into `out_buf`:
///
/// ```text
///   [more: u8]                    — 1: further rung subscriptions did not
///                                   fit; the provider has signalled the
///                                   event again
///   [count: u16 LE]
///   count × [handle: i32 LE]      — subscription handles
/// ```
///
/// and returns the byte count. Only subscriptions the caller opened on that
/// event are named; a handle that is not the caller's is never named or
/// cleared. A failed take (`EINVAL` for a malformed request, `ENOMEM` when
/// `out_cap` cannot hold the header and one handle) clears no bit, so the
/// subscriptions it would have named stay rung for the take that follows.
pub use super::super::super::registry::storage_namespace::TAKE_RUNG;

/// Close a LOOKUP or SUBSCRIBE handle. A subscription closed by its opener
/// is gone with its rung bit; its handle may name a later subscription.
pub use super::super::super::registry::storage_namespace::CLOSE;

/// What changed under a prefix since a point — one bounded page per call. The
/// read a [`SUBSCRIBE`] doorbell asks for, and the primitive a long-poll watch
/// server (a watch resumed from a revision) is a direct projection of.
///
/// `handle = -1`; `arg` is ([`changes`] is the codec):
///
/// ```text
///   [prefix_len: u16 LE]
///   [prefix: prefix_len bytes]
///   [sub: i32 LE]                 — the subscription this read serves, or -1
///   [token_len: u16 LE]
///   [token: token_len bytes]      — where to resume (below)
///   [out_buf: ptr u64 LE]
///   [out_cap: u32 LE]
///   [fence_out_ptr: u64 LE]       — receives Fence::encode bytes
///   [fence_out_cap: u16 LE]       — must be >= `fence::WIRE_MAX_LEN`
/// ```
///
/// ## Tokens
///
///   - empty: a **relist** — every current entry under the prefix, `Added`,
///     with its value, paged by key;
///   - exactly 8 bytes: a bare revision `since` (u64 LE) — the changes after
///     it. Any consumer may build one ([`changes::revision_token`]);
///   - anything else: a provider-issued continuation, echoed back verbatim.
///     A provider never issues one of exactly 8 bytes. A continuation it did
///     not issue, or no longer recognises (it restarted), is `EINVAL` or
///     `LOST`, and the consumer relists on either.
///
/// A page whose `more` is clear carries an 8-byte token: the revision the
/// consumer keeps at rest and resumes from. A relist pins the revision its
/// first page reads at and its last page hands that revision back; an entry
/// changed after it is left out of the relist and reported by the read that
/// resumes from it.
///
/// ## Answer
///
/// ```text
///   [status: u8]                  — 0 = records follow; 1 = LOST (the point
///                                   precedes what the provider can answer —
///                                   relist)
///   [more: u8]                    — 1: ask again with `token` for the rest
///   [safe_rev: u64 LE]            — the highest revision this read has
///                                   delivered whole: a consumer that hands
///                                   resume points to its own clients stamps
///                                   them at most this; 0 on a relist page
///                                   with `more` set (nothing is whole until
///                                   the relist ends)
///   [count: u32 LE]
///   count × record:
///     [mod_rev: u64 LE][kind: u8][key_len: u16 LE][val_len: u32 LE][key][val]
///   [token_len: u16 LE]
///   [token: token_len bytes]      — where the next read resumes
/// ```
///
/// One record per changed key, read at the provider's current state: present
/// → `Added` (absent before the window, when known) or `Modified`, with its
/// current value and `mod_rev`; absent → `Deleted` (no value). A key is never
/// omitted because it was created and deleted inside the window — `Deleted`
/// is always reported, and applying by key is idempotent. Intermediate
/// versions collapse. A record whose current `mod_rev` lies past the page's
/// cut is left to the later page that holds it, so no `mod_rev` a consumer
/// sees is ahead of what the read has delivered.
///
/// The return value is the byte count written to `out_buf`; the encoded
/// fence of the state the records were read at is written to
/// `fence_out_ptr` — `ViewConsistent { source, revision }` from a versioned
/// store, `Volatile` from one that keeps nothing across a reset.
///
/// ## Bounds and waits
///
/// A provider pages rather than refuses, within a per-call budget it states;
/// `ENOMEM` only when `out_cap` cannot hold the header, the next record and
/// the trailer ([`changes::min_out_cap`]). `EAGAIN` means "not now" (a busy
/// device, a spent walk budget); when `sub` names one of the caller's
/// subscriptions the provider rings it again once the cause clears, so a
/// consumer woken only by its event never stalls on a wait.
pub use super::super::super::registry::storage_namespace::CHANGES;

/// Create a binding: `path → {kind, target}` — the one op that mints
/// a name. Fails with `-17 EEXIST` when the path is already bound and
/// the replace flag is clear; RENAME covers moves, so BIND never
/// implies one.
///
/// `handle = -1`; `arg` is:
///
/// ```text
///   [path_len: u16 LE]
///   [path: path_len bytes UTF-8]
///   [kind: u8]                    — 0=object, 1=namespace, 2=stream
///   [flags: u8]                   — bit 0: replace-existing
///   [target_len: u16 LE]          — 0 permitted (kind=namespace needs no target)
///   [target: target_len bytes]    — provider-interpreted target key (an
///                                   object id, a volume key, a stream name);
///                                   opaque to this surface
///   [fence_out_ptr: u64 LE]       — receives Fence::encode bytes
///   [fence_out_cap: u16 LE]       — must be >= `fence::WIRE_MAX_LEN`
/// ```
///
/// Returns 0 or negative errno, or `EINPROGRESS` as for `RENAME`. Same
/// fence-advertisement rules as `RENAME`/`DELETE`: the achieved fence —
/// `Volatile` for in-memory namespaces, `LocalDurable { device_id }` once
/// locally committed, `ReplicatedDurable { source, .. }` once a quorum acks —
/// is written into `fence_out_ptr` atomically with the op return.
///
/// ## Relation to `fs::OPEN_CREATE` and `fs::MKDIR`
///
/// `fs::OPEN_CREATE` is normatively `BIND(kind=object) + file.data::OPEN`
/// fused into one round trip, and `fs::MKDIR` is `BIND(kind=namespace)`;
/// a filesystem provider whose directory entries live inside the byte
/// tier keeps the fused forms, a split provider (index without bytes)
/// implements BIND alone. The fused and split paths are the same
/// operation, with the same outcome and the same fence.
pub use super::super::super::registry::storage_namespace::BIND;

/// Capability bits: which optional ops this provider implements.
///
/// `handle = -1`; `arg`/`arg_len` unused. Returns the `caps` bitmap
/// (non-negative, so the bitmap is confined to bits 0..=30) or a
/// negative errno. A provider that does not implement `CAPS` itself
/// returns `ENOSYS`, which callers treat as "mandatory read surface
/// only" (LOOKUP/STAT/LIST/CLOSE per its own errnos, no mutation ops).
pub use super::super::super::registry::storage_namespace::CAPS;

/// Capability bits returned by [`CAPS`]. A provider sets bit B iff
/// calling the corresponding opcode would succeed for valid input
/// (rather than returning `ENOSYS`). Mirrors `fs::caps`: a bit names an
/// opcode, a provider that does not implement the opcode reads it 0, and
/// bit positions are stable — never renumbered.
/// [`caps::CHILD_NAMES`] is the one bit that names no opcode: it states the
/// shape of the provider's `LIST` names.
pub mod caps {
    /// [`super::BIND`] (`storage_namespace::BIND`) — provider can mint a binding.
    pub const BIND: u32 = 1 << 0;
    /// [`super::RENAME`].
    pub const RENAME: u32 = 1 << 1;
    /// [`super::DELETE`].
    pub const DELETE: u32 = 1 << 2;
    /// [`super::SUBSCRIBE`] and [`super::TAKE_RUNG`] —
    /// change doorbells.
    pub const SUBSCRIBE: u32 = 1 << 3;
    /// [`super::CHANGES`] — windowed change reads.
    pub const CHANGES: u32 = 1 << 4;
    /// Not an opcode: `LIST` is directory-shaped, its entries the immediate
    /// children of the prefix named relative to it. Clear: key-shaped,
    /// every entry a whole key under the prefix (see [`super::LIST`]).
    pub const CHILD_NAMES: u32 = 1 << 5;
}

/// The longest namespace path: a `LIST` prefix or a `LOOKUP` path. A path is
/// not a name — a directory-shaped provider's prefix walks its tree to any
/// depth — so it has its own bound, sized for a host directory path. Names
/// and cursors stay within `STORAGE_KEY_MAX`.
pub const PATH_MAX: usize = 1024;

// ── Entry kind tags returned in STAT / LIST ─────────────────────────

pub const KIND_OBJECT: u8 = 0;
pub const KIND_NAMESPACE: u8 = 1;
pub const KIND_STREAM: u8 = 2;

// ── LIST page framing ───────────────────────────────────────────────
//
// The one place the page framing is spelled out. A producer or consumer
// that writes the trailer check by hand has to get a two-byte marker and
// a reserved length right from prose, and both halves are easy to read
// past.

/// The byte that opens the trailing cursor record, in both of its
/// positions. Not a valid [`KIND_OBJECT`] / [`KIND_NAMESPACE`] /
/// [`KIND_STREAM`], which is what lets the second occurrence
/// disambiguate a 255-byte name from the end of the page.
pub const TRAILER_MARK: u8 = 0xFF;

/// Bytes the trailing cursor record occupies before its cursor bytes:
/// `[0xFF][0xFF][cursor_len]`.
pub const TRAILER_HEADER_LEN: usize = 3;

/// True when the record starting at `pos` is the trailing cursor
/// record rather than an entry.
///
/// Both bytes are checked. An entry whose name is exactly 255 bytes
/// carries `TRAILER_MARK` in its `name_len` position, so a consumer
/// testing only the first byte reads that entry as the end of the
/// page and silently loses every entry behind it.
#[inline]
pub fn is_trailer(page: &[u8], pos: usize) -> bool {
    pos + 1 < page.len() && page[pos] == TRAILER_MARK && page[pos + 1] == TRAILER_MARK
}

/// The [`LIST`] wire codec — request parsing, page writing with the
/// trailer reservation, and page decoding. No `std`, no allocation, so the
/// kernel providers, bare-metal providers and PIC modules share one
/// implementation of the layout.
pub mod list {
    use super::super::handle::STORAGE_KEY_MAX;
    use super::{is_trailer, PATH_MAX, TRAILER_HEADER_LEN, TRAILER_MARK};

    const _: () = assert!(STORAGE_KEY_MAX <= u8::MAX as usize);

    /// Request bytes besides the prefix and cursor: the two length
    /// prefixes, `out_buf`, `out_cap`, `fence_out_ptr` and `fence_out_cap`.
    pub const REQUEST_FIXED_LEN: usize = 2 + 2 + 8 + 4 + 8 + 2;

    /// An entry's bytes besides its name: `[name_len: u8][kind: u8]`.
    pub const ENTRY_FIXED_LEN: usize = 2;

    /// Smallest `out_cap` that holds one entry with a name of this length
    /// and the trailer that resumes after it: what a provider needs to make
    /// progress past it.
    pub const fn min_out_cap(name_len: usize) -> usize {
        ENTRY_FIXED_LEN + name_len + TRAILER_HEADER_LEN + name_len
    }

    /// A decoded [`super::LIST`] request.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Request<'a> {
        pub prefix: &'a [u8],
        /// Empty for the first page.
        pub cursor: &'a [u8],
        pub out_ptr: u64,
        pub out_cap: u32,
        pub fence_out_ptr: u64,
        pub fence_out_cap: u16,
    }

    fn u16_at(b: &[u8], at: usize) -> Option<u16> {
        let s = b.get(at..at.checked_add(2)?)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }

    fn u32_at(b: &[u8], at: usize) -> Option<u32> {
        let s = b.get(at..at.checked_add(4)?)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn u64_at(b: &[u8], at: usize) -> Option<u64> {
        let s = b.get(at..at.checked_add(8)?)?;
        Some(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    /// Parse and validate a request. `None` — the provider answers
    /// `EINVAL` — when the bytes are not exactly one request, the prefix is
    /// longer than `PATH_MAX` or the cursor longer than `STORAGE_KEY_MAX`,
    /// either output pointer is null, or the fence buffer is smaller than
    /// `fence::WIRE_MAX_LEN`.
    ///
    /// The length is exact: a `cursor_len` that disagrees with the bytes
    /// supplied shifts the fixed tail, and reading a shifted tail yields a
    /// plausible pointer to write into.
    pub fn parse_request(arg: &[u8]) -> Option<Request<'_>> {
        let prefix_len = u16_at(arg, 0)? as usize;
        if prefix_len > PATH_MAX {
            return None;
        }
        let prefix = arg.get(2..2 + prefix_len)?;
        let p = 2 + prefix_len;
        let cursor_len = u16_at(arg, p)? as usize;
        if cursor_len > STORAGE_KEY_MAX {
            return None;
        }
        let cursor = arg.get(p + 2..p + 2 + cursor_len)?;
        let p = p + 2 + cursor_len;
        if arg.len() != p + REQUEST_FIXED_LEN - 4 {
            return None;
        }
        let req = Request {
            prefix,
            cursor,
            out_ptr: u64_at(arg, p)?,
            out_cap: u32_at(arg, p + 8)?,
            fence_out_ptr: u64_at(arg, p + 12)?,
            fence_out_cap: u16_at(arg, p + 20)?,
        };
        if req.out_ptr == 0
            || req.fence_out_ptr == 0
            || (req.fence_out_cap as usize) < super::super::super::super::fence::WIRE_MAX_LEN
        {
            return None;
        }
        Some(req)
    }

    /// Encode `req` into `out`. Returns the bytes written, or `None` when
    /// `out` is too small or a field exceeds its bound.
    pub fn encode_request(out: &mut [u8], req: &Request<'_>) -> Option<usize> {
        if req.prefix.len() > PATH_MAX || req.cursor.len() > STORAGE_KEY_MAX {
            return None;
        }
        let total = REQUEST_FIXED_LEN + req.prefix.len() + req.cursor.len();
        let out = out.get_mut(..total)?;
        let mut p = 0;
        let mut put = |bytes: &[u8]| {
            out[p..p + bytes.len()].copy_from_slice(bytes);
            p += bytes.len();
        };
        put(&(req.prefix.len() as u16).to_le_bytes());
        put(req.prefix);
        put(&(req.cursor.len() as u16).to_le_bytes());
        put(req.cursor);
        put(&req.out_ptr.to_le_bytes());
        put(&req.out_cap.to_le_bytes());
        put(&req.fence_out_ptr.to_le_bytes());
        put(&req.fence_out_cap.to_le_bytes());
        Some(total)
    }

    /// Writes one page into a caller buffer, keeping the trailer's room in
    /// reserve so the page can always be finished.
    pub struct PageWriter<'a> {
        out: &'a mut [u8],
        pos: usize,
        count: usize,
    }

    impl<'a> PageWriter<'a> {
        /// A writer over `out`.
        pub fn new(out: &'a mut [u8]) -> Self {
            PageWriter {
                out,
                pos: 0,
                count: 0,
            }
        }

        /// Entries written so far.
        pub fn count(&self) -> usize {
            self.count
        }

        /// Append one entry. `false` when the entry and the trailer that
        /// resumes after it (the cursor is this name) do not both fit, or
        /// when the name is empty or exceeds `STORAGE_KEY_MAX` — the caller tells
        /// those apart before pushing. Nothing is written on `false`.
        pub fn push(&mut self, name: &[u8], kind: u8) -> bool {
            if name.is_empty() || name.len() > STORAGE_KEY_MAX {
                return false;
            }
            let end = self.pos + ENTRY_FIXED_LEN + name.len();
            if end + TRAILER_HEADER_LEN + name.len() > self.out.len() {
                return false;
            }
            self.out[self.pos] = name.len() as u8;
            self.out[self.pos + 1] = kind;
            self.out[self.pos + 2..end].copy_from_slice(name);
            self.pos = end;
            self.count += 1;
            true
        }

        /// Write the trailing record (empty cursor = end of listing).
        /// Returns the page length, or `None` when the buffer cannot hold
        /// it — the provider answers `ENOMEM`.
        pub fn finish(self, cursor: &[u8]) -> Option<usize> {
            if cursor.len() > STORAGE_KEY_MAX {
                return None;
            }
            let end = self.pos + TRAILER_HEADER_LEN + cursor.len();
            if end > self.out.len() {
                return None;
            }
            self.out[self.pos] = TRAILER_MARK;
            self.out[self.pos + 1] = TRAILER_MARK;
            self.out[self.pos + 2] = cursor.len() as u8;
            self.out[self.pos + TRAILER_HEADER_LEN..end].copy_from_slice(cursor);
            Some(end)
        }
    }

    /// One listed name.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Entry<'a> {
        pub name: &'a [u8],
        pub kind: u8,
    }

    /// A decoded page: its entries and the cursor that continues it.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Page<'a> {
        entries: &'a [u8],
        cursor: &'a [u8],
    }

    fn entry_at(b: &[u8], at: usize) -> Option<(Entry<'_>, usize)> {
        let len = *b.get(at)? as usize;
        let kind = *b.get(at + 1)?;
        let name = b.get(at + 2..at + 2 + len)?;
        Some((Entry { name, kind }, at + 2 + len))
    }

    /// Decode exactly one page — the `n` bytes a successful call reported.
    /// `None` when the bytes are not one well-formed page: no trailing
    /// record, a cursor longer than its bytes or than `STORAGE_KEY_MAX`, or bytes
    /// after the trailer.
    pub fn decode_page(page: &[u8]) -> Option<Page<'_>> {
        let mut p = 0;
        while !is_trailer(page, p) {
            p = entry_at(page, p)?.1;
        }
        let cursor_len = *page.get(p + 2)? as usize;
        if cursor_len > STORAGE_KEY_MAX || page.len() != p + TRAILER_HEADER_LEN + cursor_len {
            return None;
        }
        Some(Page {
            entries: &page[..p],
            cursor: &page[p + TRAILER_HEADER_LEN..],
        })
    }

    impl<'a> Page<'a> {
        /// The cursor to send for the next page; empty at the end of the
        /// listing.
        pub fn cursor(&self) -> &'a [u8] {
            self.cursor
        }

        /// This page is the last of the listing.
        pub fn is_last(&self) -> bool {
            self.cursor.is_empty()
        }

        pub fn entries(&self) -> Entries<'a> {
            Entries {
                buf: self.entries,
                pos: 0,
            }
        }
    }

    /// The entries of a decoded [`Page`], in name order.
    pub struct Entries<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> Iterator for Entries<'a> {
        type Item = Entry<'a>;

        fn next(&mut self) -> Option<Entry<'a>> {
            let (entry, next) = entry_at(self.buf, self.pos)?;
            self.pos = next;
            Some(entry)
        }
    }
}

// ── SUBSCRIBE / TAKE_RUNG / CHANGES wire codecs ──────────────────────
//
// One implementation of each layout for providers and consumers alike: no
// `std`, no allocation, so kernel providers, bare-metal providers and PIC
// modules share it.

fn le_u16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn le_u32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn le_u64(b: &[u8], at: usize) -> Option<u64> {
    let s = b.get(at..at.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

/// Appends fields to a bounded buffer; `None` once one does not fit.
struct Put<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Put<'_> {
    fn bytes(&mut self, b: &[u8]) -> Option<()> {
        let end = self.at.checked_add(b.len())?;
        self.out.get_mut(self.at..end)?.copy_from_slice(b);
        self.at = end;
        Some(())
    }
}

/// The [`SUBSCRIBE`] request.
pub mod subscribe {
    use super::{le_u16, Put, PATH_MAX};

    /// `flags` bit 0: ring once now.
    pub const FLAG_RING_NOW: u8 = 1 << 0;

    /// A decoded request.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Request<'a> {
        pub prefix: &'a [u8],
        /// The caller's tagged event fd.
        pub event: i32,
        pub flags: u8,
    }

    /// Parse exactly one request; `None` — `EINVAL` — otherwise.
    pub fn parse(arg: &[u8]) -> Option<Request<'_>> {
        let plen = le_u16(arg, 0)? as usize;
        if plen > PATH_MAX || arg.len() != 2 + plen + 5 {
            return None;
        }
        let prefix = arg.get(2..2 + plen)?;
        let e = arg.get(2 + plen..2 + plen + 4)?;
        Some(Request {
            prefix,
            event: i32::from_le_bytes([e[0], e[1], e[2], e[3]]),
            flags: *arg.get(2 + plen + 4)?,
        })
    }

    /// Encode a request into `out`: its length, or `None` when it does not fit.
    pub fn encode(out: &mut [u8], req: &Request<'_>) -> Option<usize> {
        if req.prefix.len() > PATH_MAX {
            return None;
        }
        let mut p = Put { out, at: 0 };
        p.bytes(&(req.prefix.len() as u16).to_le_bytes())?;
        p.bytes(req.prefix)?;
        p.bytes(&req.event.to_le_bytes())?;
        p.bytes(&[req.flags])?;
        Some(p.at)
    }
}

/// The [`TAKE_RUNG`] request and answer.
pub mod take {
    use super::{le_u16, le_u32, le_u64, Put};

    /// Request bytes: `[event i32][out_ptr u64][out_cap u32]`.
    pub const REQUEST_LEN: usize = 16;
    /// Answer bytes before the handles: `[more u8][count u16]`.
    pub const HEAD_LEN: usize = 3;
    /// The smallest `out_cap` that makes progress: the head and one handle.
    pub const MIN_OUT_CAP: usize = HEAD_LEN + 4;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Request {
        pub event: i32,
        pub out_ptr: u64,
        pub out_cap: u32,
    }

    /// Parse exactly one request; `None` — `EINVAL` — otherwise, or when the
    /// output pointer is null.
    pub fn parse(arg: &[u8]) -> Option<Request> {
        if arg.len() != REQUEST_LEN {
            return None;
        }
        let r = Request {
            event: le_u32(arg, 0)? as i32,
            out_ptr: le_u64(arg, 4)?,
            out_cap: le_u32(arg, 12)?,
        };
        (r.out_ptr != 0).then_some(r)
    }

    pub fn encode(out: &mut [u8], req: &Request) -> Option<usize> {
        let mut p = Put { out, at: 0 };
        p.bytes(&req.event.to_le_bytes())?;
        p.bytes(&req.out_ptr.to_le_bytes())?;
        p.bytes(&req.out_cap.to_le_bytes())?;
        Some(p.at)
    }

    /// Writes one answer, the head last.
    pub struct Writer<'a> {
        out: &'a mut [u8],
        count: u16,
    }

    impl<'a> Writer<'a> {
        /// `None` when `out` cannot hold [`MIN_OUT_CAP`] (`ENOMEM`).
        pub fn new(out: &'a mut [u8]) -> Option<Self> {
            (out.len() >= MIN_OUT_CAP).then_some(Writer { out, count: 0 })
        }

        /// Append a handle; `false` when it does not fit (nothing written).
        pub fn push(&mut self, handle: i32) -> bool {
            let at = HEAD_LEN + self.count as usize * 4;
            match self.out.get_mut(at..at + 4) {
                Some(d) if self.count < u16::MAX => {
                    d.copy_from_slice(&handle.to_le_bytes());
                    self.count += 1;
                    true
                }
                _ => false,
            }
        }

        /// Write the head; the answer's length.
        pub fn finish(self, more: bool) -> usize {
            self.out[0] = u8::from(more);
            self.out[1..3].copy_from_slice(&self.count.to_le_bytes());
            HEAD_LEN + self.count as usize * 4
        }
    }

    /// A decoded answer: `(more, handles)`.
    pub fn decode(ans: &[u8]) -> Option<(bool, impl Iterator<Item = i32> + '_)> {
        let more = *ans.first()? != 0;
        let count = le_u16(ans, 1)? as usize;
        let body = ans.get(HEAD_LEN..HEAD_LEN + count * 4)?;
        if ans.len() != HEAD_LEN + count * 4 {
            return None;
        }
        Some((
            more,
            body.chunks_exact(4)
                .map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]])),
        ))
    }
}

/// The [`CHANGES`] request, page and tokens.
pub mod changes {
    use super::super::handle::STORAGE_KEY_MAX;
    use super::{le_u16, le_u32, le_u64, Put, PATH_MAX};

    /// The longest token: a provider's continuation (a kind byte, revisions
    /// and a key cursor) fits in it.
    pub const TOKEN_MAX: usize = 320;
    /// A bare revision token's length.
    pub const REVISION_TOKEN_LEN: usize = 8;

    pub const STATUS_OK: u8 = 0;
    pub const STATUS_LOST: u8 = 1;

    pub const KIND_ADDED: u8 = 0;
    pub const KIND_MODIFIED: u8 = 1;
    pub const KIND_DELETED: u8 = 2;

    /// Page bytes before the records: `[status][more][safe_rev u64][count u32]`.
    pub const HEAD_LEN: usize = 14;
    /// A record's bytes besides its key and value.
    pub const RECORD_FIXED_LEN: usize = 15;
    /// The trailer's bytes besides its token: `[token_len u16]`.
    pub const TRAILER_FIXED_LEN: usize = 2;
    /// Request bytes besides the prefix and token.
    pub const REQUEST_FIXED_LEN: usize = 2 + 4 + 2 + 8 + 4 + 8 + 2;

    /// A bare revision token: "the changes after `since`".
    pub const fn revision_token(since: u64) -> [u8; REVISION_TOKEN_LEN] {
        since.to_le_bytes()
    }

    /// The revision a bare revision token names; `None` for any other token.
    pub fn token_revision(token: &[u8]) -> Option<u64> {
        (token.len() == REVISION_TOKEN_LEN)
            .then(|| le_u64(token, 0))
            .flatten()
    }

    /// The smallest `out_cap` that makes progress past a record with a key
    /// of `key_len` and a value of `val_len`, with a token of `token_len`.
    pub const fn min_out_cap(key_len: usize, val_len: usize, token_len: usize) -> usize {
        HEAD_LEN + RECORD_FIXED_LEN + key_len + val_len + TRAILER_FIXED_LEN + token_len
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Request<'a> {
        pub prefix: &'a [u8],
        /// The subscription this read serves, or -1.
        pub sub: i32,
        pub token: &'a [u8],
        pub out_ptr: u64,
        pub out_cap: u32,
        pub fence_out_ptr: u64,
        pub fence_out_cap: u16,
    }

    /// Parse exactly one request; `None` — `EINVAL` — when the bytes are not
    /// one request, a field exceeds its bound, an output pointer is null or
    /// the fence buffer is short.
    pub fn parse_request(arg: &[u8]) -> Option<Request<'_>> {
        let plen = le_u16(arg, 0)? as usize;
        if plen > PATH_MAX {
            return None;
        }
        let prefix = arg.get(2..2 + plen)?;
        let mut p = 2 + plen;
        let sub = le_u32(arg, p)? as i32;
        p += 4;
        let tlen = le_u16(arg, p)? as usize;
        if tlen > TOKEN_MAX {
            return None;
        }
        let token = arg.get(p + 2..p + 2 + tlen)?;
        p += 2 + tlen;
        if arg.len() != p + 22 {
            return None;
        }
        let req = Request {
            prefix,
            sub,
            token,
            out_ptr: le_u64(arg, p)?,
            out_cap: le_u32(arg, p + 8)?,
            fence_out_ptr: le_u64(arg, p + 12)?,
            fence_out_cap: le_u16(arg, p + 20)?,
        };
        if req.out_ptr == 0
            || req.fence_out_ptr == 0
            || (req.fence_out_cap as usize) < super::super::super::super::fence::WIRE_MAX_LEN
        {
            return None;
        }
        Some(req)
    }

    pub fn encode_request(out: &mut [u8], req: &Request<'_>) -> Option<usize> {
        if req.prefix.len() > PATH_MAX || req.token.len() > TOKEN_MAX {
            return None;
        }
        let mut p = Put { out, at: 0 };
        p.bytes(&(req.prefix.len() as u16).to_le_bytes())?;
        p.bytes(req.prefix)?;
        p.bytes(&req.sub.to_le_bytes())?;
        p.bytes(&(req.token.len() as u16).to_le_bytes())?;
        p.bytes(req.token)?;
        p.bytes(&req.out_ptr.to_le_bytes())?;
        p.bytes(&req.out_cap.to_le_bytes())?;
        p.bytes(&req.fence_out_ptr.to_le_bytes())?;
        p.bytes(&req.fence_out_cap.to_le_bytes())?;
        Some(p.at)
    }

    /// Writes one page into a caller buffer, keeping room for the trailer
    /// (a token of up to `token_reserve` bytes) so the page can always be
    /// finished.
    pub struct PageWriter<'a> {
        out: &'a mut [u8],
        pos: usize,
        count: u32,
        reserve: usize,
    }

    impl<'a> PageWriter<'a> {
        /// `None` when `out` cannot hold the head and a trailer of
        /// `token_reserve` bytes.
        pub fn new(out: &'a mut [u8], token_reserve: usize) -> Option<Self> {
            let reserve = TRAILER_FIXED_LEN + token_reserve.min(TOKEN_MAX);
            (out.len() >= HEAD_LEN + reserve).then_some(PageWriter {
                out,
                pos: HEAD_LEN,
                count: 0,
                reserve,
            })
        }

        pub fn count(&self) -> u32 {
            self.count
        }

        /// Append one record; `false` when it and the trailer do not both
        /// fit, or the key exceeds `STORAGE_KEY_MAX` (nothing written).
        pub fn push(&mut self, mod_rev: u64, kind: u8, key: &[u8], val: &[u8]) -> bool {
            if key.len() > STORAGE_KEY_MAX || val.len() > u32::MAX as usize {
                return false;
            }
            let end = self.pos + RECORD_FIXED_LEN + key.len() + val.len();
            if end + self.reserve > self.out.len() {
                return false;
            }
            let o = &mut self.out[self.pos..end];
            o[..8].copy_from_slice(&mod_rev.to_le_bytes());
            o[8] = kind;
            o[9..11].copy_from_slice(&(key.len() as u16).to_le_bytes());
            o[11..15].copy_from_slice(&(val.len() as u32).to_le_bytes());
            o[15..15 + key.len()].copy_from_slice(key);
            o[15 + key.len()..].copy_from_slice(val);
            self.pos = end;
            self.count += 1;
            true
        }

        /// Write the head and the trailer; the page's length, or `None` when
        /// the token is longer than the reserve.
        pub fn finish(self, more: bool, safe_rev: u64, token: &[u8]) -> Option<usize> {
            if TRAILER_FIXED_LEN + token.len() > self.reserve {
                return None;
            }
            let o = self.out;
            o[0] = STATUS_OK;
            o[1] = u8::from(more);
            o[2..10].copy_from_slice(&safe_rev.to_le_bytes());
            o[10..14].copy_from_slice(&self.count.to_le_bytes());
            let mut p = Put {
                out: o,
                at: self.pos,
            };
            p.bytes(&(token.len() as u16).to_le_bytes())?;
            p.bytes(token)?;
            Some(p.at)
        }
    }

    /// Write a LOST page into `out`: its length, or `None` when it does not
    /// fit.
    pub fn write_lost(out: &mut [u8]) -> Option<usize> {
        let o = out.get_mut(..HEAD_LEN + TRAILER_FIXED_LEN)?;
        o.fill(0);
        o[0] = STATUS_LOST;
        Some(HEAD_LEN + TRAILER_FIXED_LEN)
    }

    /// One record.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Record<'a> {
        pub mod_rev: u64,
        pub kind: u8,
        pub key: &'a [u8],
        pub val: &'a [u8],
    }

    /// A decoded page.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Page<'a> {
        pub lost: bool,
        pub more: bool,
        pub safe_rev: u64,
        pub count: u32,
        records: &'a [u8],
        pub token: &'a [u8],
    }

    fn record_at(b: &[u8], at: usize) -> Option<(Record<'_>, usize)> {
        let mod_rev = le_u64(b, at)?;
        let kind = *b.get(at + 8)?;
        let kl = le_u16(b, at + 9)? as usize;
        let vl = le_u32(b, at + 11)? as usize;
        let key = b.get(at + 15..at + 15 + kl)?;
        let val = b.get(at + 15 + kl..at + 15 + kl + vl)?;
        Some((
            Record {
                mod_rev,
                kind,
                key,
                val,
            },
            at + 15 + kl + vl,
        ))
    }

    /// Decode exactly one page — the bytes a successful call reported.
    pub fn decode_page(page: &[u8]) -> Option<Page<'_>> {
        let status = *page.first()?;
        let more = *page.get(1)? != 0;
        let safe_rev = le_u64(page, 2)?;
        let count = le_u32(page, 10)?;
        let mut p = HEAD_LEN;
        for _ in 0..count {
            p = record_at(page, p)?.1;
        }
        let tlen = le_u16(page, p)? as usize;
        let token = page.get(p + 2..p + 2 + tlen)?;
        if page.len() != p + 2 + tlen || tlen > TOKEN_MAX {
            return None;
        }
        Some(Page {
            lost: status == STATUS_LOST,
            more,
            safe_rev,
            count,
            records: &page[HEAD_LEN..p],
            token,
        })
    }

    impl<'a> Page<'a> {
        pub fn records(&self) -> Records<'a> {
            Records {
                buf: self.records,
                pos: 0,
            }
        }
    }

    pub struct Records<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> Iterator for Records<'a> {
        type Item = Record<'a>;

        fn next(&mut self) -> Option<Record<'a>> {
            let (r, next) = record_at(self.buf, self.pos)?;
            self.pos = next;
            Some(r)
        }
    }
}
