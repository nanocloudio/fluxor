// Contract: object — content-addressable byte-blob surface.
//
// Layer: contracts/storage (public, stable).
//
// One of four canonical storage surfaces (`storage.block`,
// `file.data`, `storage.namespace`, `storage.object`) — see
// `docs/architecture/storage_capability_surface.md`. The object
// surface addresses whole byte blobs by name and supports
// range-read, HEAD-style metadata, and single-shot put. Large
// writes compose via the `PUT_STREAMED_*` sequence below (the
// concrete shape of the event.log pattern). An S3 adapter that
// needs multipart synthesises it on top of this surface; the
// surface itself stays narrow so substitutability holds.
//
// ## Handle identity
//
// `GET` and `PUT_STREAMED_OPEN` return a tagged FD: providers
// encode the returned slot via `kernel_abi::fd::tag_fd(
// FD_TAG_STORAGE_OBJECT, slot)`. The kernel vtable wrapper strips
// the tag before re-entering the provider; inbound ops see a raw
// slot. Tagging is what lets `provider_query(handle,
// query_key::LAST_FENCE, …)` resolve the contract from the handle.
//
// ## Fence advertisement
//
//   - Handle-bound ops (`RANGE_GET`, `CLOSE`) and open-returning
//     ops (`GET`, `PUT_STREAMED_OPEN`) advertise the per-handle
//     fence via `provider_query(handle, query_key::LAST_FENCE, …)`.
//   - Handle=-1 one-shot ops (`PUT`, `HEAD`, `DELETE`) carry an
//     explicit `[fence_out_ptr, fence_out_cap]` pair in their arg
//     layout. The provider writes up to `fence::WIRE_MAX_LEN` bytes
//     of `Fence::encode` output into `fence_out_ptr` atomically
//     with returning the op's i32 result; callers decode via
//     `Fence::decode`.
//
// Typical advertisements:
//   - `GET` / `RANGE_GET` / `HEAD` → `ViewConsistent { source,
//     revision }` for snapshot-based providers, or
//     `ContentHashed { algorithm, digest }` for CAS providers.
//   - `PUT` → the strongest fence the commit achieved:
//     `LocalDurable` on a single-node store,
//     `ReplicatedDurable { source, .. }` once a replicating
//     provider is in the path, `ContentHashed` for CAS.
//   - `DELETE` → `LocalDurable` / `ReplicatedDurable` once the
//     tombstone is committed.
//
// ## Opcode class
//
// Opcodes occupy 0x14__ — class byte 0x14 maps to
// `kernel::provider::contract::STORAGE_OBJECT`. Distinct from FS
// (0x09__), BUFFER (0x0A__), and namespace (0x13__).

/// Single-shot put of a complete blob.
///
/// `handle = -1`; `arg` points at:
///
/// ```text
///   [key_len: u16 LE]
///   [key: key_len bytes UTF-8]
///   [content_type_len: u8]
///   [content_type: content_type_len bytes]    — MIME-style tag
///   [body_ptr: u64 LE]
///   [body_len: u64 LE]
///   [if_match_len: u8]                        — 0 or 32; etag guard
///   [if_match: if_match_len bytes]
///   [fence_out_ptr: u64 LE]                   — receives Fence::encode bytes
///   [fence_out_cap: u16 LE]                   — must be >= `fence::WIRE_MAX_LEN`
/// ```
///
/// Returns 0 or negative errno. On success the provider writes the
/// encoded fence (up to `fence::WIRE_MAX_LEN` bytes) into the
/// buffer at `fence_out_ptr`. `body_len` must fit a single
/// in-memory blob; large bodies use the `PUT_STREAMED_*` sequence
/// below.
pub const PUT: u32 = 0x1420;

/// Open a blob for streaming reads.
///
/// `handle = -1`; `arg` is the UTF-8 key, `arg_len` its length.
/// Returns a non-negative handle (used with `RANGE_GET` / `CLOSE`)
/// or negative errno. The handle's fence is read via
/// `provider_query(handle, query_key::LAST_FENCE, …)`.
pub const GET: u32 = 0x1421;

/// Read metadata for a blob without opening a handle.
///
/// `handle = -1`; `arg` points at:
///
/// ```text
///   [key_len: u16 LE]
///   [key: key_len bytes]
///   [out_ptr: u64 LE]
///   [out_cap: u32 LE]
///   [fence_out_ptr: u64 LE]                   — receives Fence::encode bytes
///   [fence_out_cap: u16 LE]                   — must be >= `fence::WIRE_MAX_LEN`
/// ```
///
/// On success writes a HEAD record into the output buffer:
///
/// ```text
///   [size: u64 LE]
///   [mtime: u64 LE]
///   [content_type_len: u8]
///   [content_type: content_type_len bytes]
///   [etag_len: u8]
///   [etag: etag_len bytes]
/// ```
///
/// and writes the encoded fence into `fence_out_ptr`. Returns the
/// number of bytes written to `out_ptr`, or negative errno.
pub const HEAD: u32 = 0x1422;

/// Read a byte range from an open object handle.
///
/// `handle` is a GET-returned handle; `arg` is:
///
/// ```text
///   [offset: u64 LE]
///   [length: u32 LE]
///   [out_ptr: u64 LE]
/// ```
///
/// Reads up to `length` bytes starting at `offset` into the output
/// buffer. Returns the number of bytes actually read (which may be
/// less than `length` near the tail) or negative errno. Fence is
/// advertised per-handle via `query_key::LAST_FENCE`.
pub const RANGE_GET: u32 = 0x1423;

/// Delete a blob.
///
/// `handle = -1`; `arg` is:
///
/// ```text
///   [key_len: u16 LE]
///   [key: key_len bytes]
///   [if_match_len: u8]                        — 0 or 32; etag guard
///   [if_match: if_match_len bytes]
///   [fence_out_ptr: u64 LE]                   — receives Fence::encode bytes
///   [fence_out_cap: u16 LE]                   — must be >= `fence::WIRE_MAX_LEN`
/// ```
///
/// Returns 0 or negative errno. The provider writes the encoded
/// fence into `fence_out_ptr` atomically with returning success.
pub const DELETE: u32 = 0x1424;

/// Close a GET or PUT_STREAMED_OPEN handle.
pub const CLOSE: u32 = 0x1425;

// ── Large-blob streaming write (event.log composition) ──────────────
//
// `PUT_STREAMED_OPEN` produces a stream handle; the caller writes
// body chunks through `PUT_STREAMED_WRITE`; `PUT_STREAMED_COMMIT`
// atomically promotes the staged content into an object and
// surfaces the strongest fence achieved. `PUT_STREAMED_ABORT`
// discards the staging area.
//
// Providers map this to whatever their backing store prefers — a
// replicating provider opens an `event.log` stream at
// `_staging/<key>`, appends each `PUT_STREAMED_WRITE` as one Event,
// and on `COMMIT` atomically links the finalised event sequence
// into the object namespace under `<key>` advertising
// `ReplicatedDurable`. Single-node providers buffer chunks in a
// temp file and rename on commit, advertising `LocalDurable`.

/// Open a streaming-write handle for `key`.
///
/// `handle = -1`; `arg` is:
///
/// ```text
///   [key_len: u16 LE]
///   [key: key_len bytes UTF-8]
///   [content_type_len: u8]
///   [content_type: content_type_len bytes]
///   [expected_size: u64 LE]                   — best-effort hint; 0 = unknown
///   [if_match_len: u8]                        — 0 or 32; pre-existence etag guard
///   [if_match: if_match_len bytes]
/// ```
///
/// Returns a non-negative streaming-write handle or negative errno.
/// The handle's fence is `Fence::Volatile` until
/// `PUT_STREAMED_COMMIT` succeeds.
pub const PUT_STREAMED_OPEN: u32 = 0x1426;

/// Append a chunk of body bytes to a streaming-write handle.
///
/// `handle` is a `PUT_STREAMED_OPEN`-returned handle; `arg` points
/// at the chunk bytes, `arg_len` is the chunk size. Returns 0 or
/// negative errno. Each successful WRITE corresponds to one Event
/// appended on the provider's staging event-log stream. Fence on
/// the handle remains `Volatile`.
pub const PUT_STREAMED_WRITE: u32 = 0x1427;

/// Atomically finalise a streaming write into an object PUT.
///
/// `handle` is a `PUT_STREAMED_OPEN`-returned handle; `arg` points
/// at:
///
/// ```text
///   [fence_out_ptr: u64 LE]                   — receives Fence::encode bytes
///   [fence_out_cap: u16 LE]                   — must be >= `fence::WIRE_MAX_LEN`
/// ```
///
/// Returns 0 or negative errno. On success the staged event-log
/// stream is committed under the object key, the handle's
/// per-handle fence is updated to the strongest fence the commit
/// achieved, and the encoded fence is also written into
/// `fence_out_ptr`. After COMMIT the handle is no longer writable;
/// callers MUST call `CLOSE`.
pub const PUT_STREAMED_COMMIT: u32 = 0x1428;

/// Discard a streaming-write handle without committing.
///
/// `handle` is a `PUT_STREAMED_OPEN`-returned handle; `arg = null`,
/// `arg_len = 0`. Returns 0 or negative errno. The provider drops
/// the staged event-log stream; subsequent reads under `key` do
/// not observe any appended chunks. After ABORT the handle is
/// released — callers do not need to `CLOSE`.
pub const PUT_STREAMED_ABORT: u32 = 0x1429;
