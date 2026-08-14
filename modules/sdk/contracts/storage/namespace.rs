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
// providers (HTTP listings, S3 ListBucket, Loam directory, Clustor
// metadata) need not hold byte data themselves.
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
//   - Open-returning ops (`LOOKUP`, `SUBSCRIBE`) advertise per-handle
//     fence via `provider_query(handle, query_key::LAST_FENCE, …)`.
//   - Handle-bound ops (`STAT`) advertise per-handle via the same path.
//   - Handle=-1 one-shot ops (`LIST`, `RENAME`, `DELETE`) carry a
//     `[fence_out_ptr: u64 LE, fence_out_cap: u16 LE]` pair in their
//     arg layout. The provider writes the encoded `Fence` (up to
//     `fence::WIRE_MAX_LEN` bytes) into that buffer atomically with
//     the op return; callers decode via `Fence::decode`.
//
// Typical advertisements: `ViewConsistent { source, revision }` for
// snapshot reads, `LocalDurable { device_id }` for committed
// renames/deletes, `ReplicatedDurable { source, .. }` when a
// quorum-replicated provider acks. See `contracts::fence` for the
// dominance rules.
//
// ## Operations
//
//   LOOKUP    — resolve a path under this namespace to its entry
//               kind and storage handle.
//   STAT      — read entry metadata (size, mtime, kind, etag)
//               without opening a handle.
//   LIST      — enumerate entries under a prefix; results paged via
//               an opaque cursor so partial scans compose.
//   BIND      — create a binding `name → {kind, target}`. The one
//               op that MINTS a name; without it the surface is
//               read-mostly by construction and every provider
//               invents a private creation vocabulary (fat32's
//               naming ops welded into `fs` 0x09__, loam's
//               project-local OP_BIND).
//   RENAME    — rename or move an entry within the namespace.
//               Atomic within a single provider; cross-provider
//               renames are out of scope for this surface.
//   DELETE    — remove an entry. Recursive delete on directories is
//               opt-in via a flag.
//   SUBSCRIBE — open an `Event<namespace.change>` stream rooted at
//               a prefix; events flow through the mesh Event
//               primitive (see mesh.md §5).
//   CAPS      — capability bits: which optional/mutation ops this
//               provider actually implements (mirrors `fs::CAPS`).
//
// ## Opcode class
//
// Opcodes occupy the 0x13__ range — class byte 0x13 maps to
// `kernel::module::provider::contract::STORAGE_NAMESPACE`. A dedicated
// class id lets kernel routing dispatch namespace ops to a
// namespace provider without colliding with FS (0x09__) or BUFFER
// (0x0A__).
//
// Subscribe events ride the mesh Event primitive — this contract
// owns the opcode that opens the subscription; the payload format
// on the returned event stream is documented under
// `docs/architecture/storage_capability_surface.md` §"namespace.change".

/// Look up a name under this namespace.
///
/// `handle = -1`; `arg` points at the UTF-8 path (no null
/// terminator), `arg_len` is its length. On success returns a
/// non-negative handle into the namespace's resolved-entry table
/// (passed to `STAT` or `SUBSCRIBE`); on failure returns a negative
/// errno (`-2 ENOENT`, `-22 EINVAL`, …).
///
/// Resolution is snapshot-relative: the provider records the
/// revision it observed and any subsequent `STAT` against this
/// handle answers against the same view. Callers wanting freshness
/// re-`LOOKUP`. The fence on this handle (via
/// `provider_query(handle, query_key::LAST_FENCE, …)`) is
/// `ViewConsistent { source, revision }`.
pub const LOOKUP: u32 = 0x1300;

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
pub const STAT: u32 = 0x1301;

/// List entries under a prefix.
///
/// `handle = -1`; `arg` points at a request:
///
/// ```text
///   [prefix_len: u16 LE]
///   [prefix: prefix_len bytes UTF-8]
///   [cursor_len: u16 LE]          — 0 for first page
///   [cursor: cursor_len bytes]    — opaque, echoed from prior LIST
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
/// followed by a trailing cursor record (`[0xFF, cursor_len, cursor…]`)
/// when more pages remain. A trailing record with `cursor_len = 0`
/// means "end of listing".
pub const LIST: u32 = 0x1302;

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
pub const RENAME: u32 = 0x1303;

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
/// Returns 0 or negative errno. Same fence-advertisement rules as
/// `RENAME` — the encoded fence is written into `fence_out_ptr`
/// atomically with the op return.
pub const DELETE: u32 = 0x1304;

/// Open an `Event<namespace.change>` subscription rooted at a
/// prefix.
///
/// `handle = -1`; `arg` is:
///
/// ```text
///   [prefix_len: u16 LE]
///   [prefix: prefix_len bytes]
///   [sink_chan: u32 LE]           — channel to deliver Events onto
///   [flags: u8]                   — bit 0: include-initial-listing
/// ```
///
/// Returns a non-negative subscription handle (passed to `CLOSE`)
/// or a negative errno. Events delivered on `sink_chan` follow the
/// mesh Event header (see `mesh.md`); the payload format for
/// `namespace.change` is documented in
/// `docs/architecture/storage_capability_surface.md`.
pub const SUBSCRIBE: u32 = 0x1305;

/// Close a LOOKUP or SUBSCRIBE handle.
pub const CLOSE: u32 = 0x1306;

/// Synchronous windowed change-read — the request/response dual of the
/// push-based `SUBSCRIBE`. Where `SUBSCRIBE` streams live events onto a channel,
/// `CHANGES` answers "what changed under `prefix` since revision `since`?" in one
/// call, into a caller buffer. This is the primitive a long-poll watch server
/// (k8s `?watch`/resourceVersion) is a direct projection of: LIST-at-a-fence
/// then the changes since it, both synchronous.
///
/// `handle = -1`; `arg` is:
///
/// ```text
///   [prefix_len: u16 LE]
///   [prefix: prefix_len bytes]
///   [since: u64 LE]               — 0 = full current snapshot; N = changes after rev N
///   [out_buf: ptr u64 LE]
///   [out_cap: u32 LE]
///   [fence_out_ptr: u64 LE]       — receives Fence::encode bytes
///   [fence_out_cap: u16 LE]       — must be >= `fence::WIRE_MAX_LEN`
/// ```
///
/// On success the provider writes into `out_buf`:
///
/// ```text
///   [status: u8]                  — 0 = events follow; 1 = LOST (window preceded
///                                   retained history — the client must relist)
///   [count: u32 LE]               — number of event records (0 when status=LOST)
///   count × event:
///     [rev: u64 LE][kind: u8][key_len: u16 LE][val_len: u32 LE][key][val]
/// ```
///
/// `kind` is `0=Added`, `1=Modified`, `2=Deleted` (value absent for Deleted).
/// `since = 0` returns every current entry as `Added` at its revision (the
/// snapshot a client relists into). The return value is the byte count written
/// to `out_buf`; the encoded fence (`ViewConsistent { revision }`, the highest
/// revision covered — the client's next `since`) is written to `fence_out_ptr`.
pub const CHANGES: u32 = 0x1307;

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
/// Returns 0 or negative errno. Same fence-advertisement rules as
/// `RENAME`/`DELETE`: the achieved fence — `Volatile` for in-memory
/// namespaces, `LocalDurable { device_id }` once locally committed,
/// `ReplicatedDurable { source, .. }` once a quorum acks — is written
/// into `fence_out_ptr` atomically with the op return.
///
/// ## Relation to `fs::OPEN_CREATE` and `fs::MKDIR`
///
/// `fs::OPEN_CREATE` is normatively `BIND(kind=object) + file.data::OPEN`
/// fused into one round trip, and `fs::MKDIR` is `BIND(kind=namespace)`;
/// a filesystem provider whose directory entries live inside the byte
/// tier keeps the fused forms, a split provider (index without bytes)
/// implements BIND alone. The fused and split paths are the same
/// operation — a future dedup of the `fs` naming opcodes against this
/// range must preserve that equivalence.
pub const BIND: u32 = 0x1308;

/// Capability bits: which optional ops this provider implements.
///
/// `handle = -1`; `arg`/`arg_len` unused. Returns the `caps` bitmap
/// (non-negative, so the bitmap is confined to bits 0..=30) or a
/// negative errno. A provider that does not implement `CAPS` itself
/// returns `ENOSYS`, which callers treat as "mandatory read surface
/// only" (LOOKUP/STAT/LIST/CLOSE per its own errnos, no mutation ops).
pub const CAPS: u32 = 0x13FF;

/// Capability bits returned by [`CAPS`]. A provider sets bit B iff
/// calling the corresponding opcode would succeed for valid input
/// (rather than returning `ENOSYS`). Mirrors `fs::caps`: adding an
/// opcode is a two-step ABI change — reserve the bit here (providers
/// MUST return 0 for it until they implement), then flip it on per
/// backend. Bit positions are stable forever — never renumber.
pub mod caps {
    /// [`super::BIND`] (0x1308) — provider can mint a binding.
    pub const BIND: u32 = 1 << 0;
    /// [`super::RENAME`] (0x1303).
    pub const RENAME: u32 = 1 << 1;
    /// [`super::DELETE`] (0x1304).
    pub const DELETE: u32 = 1 << 2;
    /// [`super::SUBSCRIBE`] (0x1305) — live change events.
    pub const SUBSCRIBE: u32 = 1 << 3;
    /// [`super::CHANGES`] (0x1307) — windowed change reads.
    pub const CHANGES: u32 = 1 << 4;
}

// ── Entry kind tags returned in STAT / LIST ─────────────────────────

pub const KIND_OBJECT: u8 = 0;
pub const KIND_NAMESPACE: u8 = 1;
pub const KIND_STREAM: u8 = 2;
