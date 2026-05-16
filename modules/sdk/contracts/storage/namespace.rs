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
//   RENAME    — rename or move an entry within the namespace.
//               Atomic within a single provider; cross-provider
//               renames are out of scope for this surface.
//   DELETE    — remove an entry. Recursive delete on directories is
//               opt-in via a flag.
//   SUBSCRIBE — open an `Event<namespace.change>` stream rooted at
//               a prefix; events flow through the mesh Event
//               primitive (see mesh.md §5).
//
// ## Opcode class
//
// Opcodes occupy the 0x13__ range — class byte 0x13 maps to
// `kernel::provider::contract::STORAGE_NAMESPACE`. A dedicated
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

// ── Entry kind tags returned in STAT / LIST ─────────────────────────

pub const KIND_OBJECT: u8 = 0;
pub const KIND_NAMESPACE: u8 = 1;
pub const KIND_STREAM: u8 = 2;
