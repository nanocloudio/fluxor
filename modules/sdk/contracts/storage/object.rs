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

// ── Embedded-image decode (cover art) ───────────────────────────────
//
// Range-fetch an image embedded in a served object (e.g. the `covr`
// payload inside an `.m4a`) and decode it straight to RGB565 at a target
// size — host-side on wasm (browser `createImageBitmap` + downscale), so
// a PIC UI module renders album art without an in-wasm image decoder or
// multi-MB encoded buffers.
//
// `IMG_DECODE` (handle = -1) — `arg` is
//   `[offset:u64 LE][length:u64 LE][width:u16 LE][height:u16 LE][url…]`
// returns a non-negative handle. `IMG_RECV(handle)` drains the
// `width*height*2`-byte RGB565 buffer (EAGAIN while the async decode is
// pending). `IMG_CLOSE(handle)` releases it.
pub const IMG_DECODE: u32 = 0x1430;
pub const IMG_RECV: u32 = 0x1431;
pub const IMG_CLOSE: u32 = 0x1432;

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

/// Host-neutral helpers shared by the platform `storage.object`
/// adapters that back `HEAD` / `RANGE_GET` with browser `fetch()`
/// (wasm) and `Range:` requests (linux). The four browser host
/// bindings named by the Playload RFC §12.3 — `host_object_head`,
/// `host_object_range_open`, `host_object_recv`, `host_object_close`
/// — and their Linux peers all reduce to the same three concerns:
/// clamping a requested window against the object size, encoding the
/// `HEAD` metadata record, and formatting an HTTP byte-range. Keeping
/// that logic here (no_std, no alloc, no host calls) is what lets it
/// be unit-tested off-target; the per-platform providers are thin
/// transport wrappers over these functions.
pub mod range {
    /// A requested byte window resolved against a known object size.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Resolved {
        /// First byte to read. Clamped to `object_size` when the
        /// request starts at or past the end (yields `count == 0`).
        pub start: u64,
        /// Number of bytes actually available in the window — `length`
        /// for a fully-in-bounds request, `object_size - start` for a
        /// tail request that runs off the end, `0` for an empty
        /// (`length == 0`) or wholly out-of-bounds request.
        pub count: u64,
        /// `true` when this window reaches the end of the object, so a
        /// reader knows no further range follows.
        pub eof_after: bool,
    }

    /// Clamp a `[offset, offset+length)` request against `object_size`.
    ///
    /// Three shapes matter to callers and tests:
    /// - **empty** — `length == 0` → `count == 0` (a HEAD-style probe).
    /// - **partial** — fully in bounds → `count == length`.
    /// - **tail** — starts in bounds but runs off the end → `count`
    ///   trimmed to `object_size - offset`.
    ///
    /// A request whose `offset >= object_size` is wholly out of bounds:
    /// `start` is pinned to `object_size` and `count` is `0` (the
    /// provider surfaces this as a zero-byte read / `416`-style state,
    /// not an error here).
    pub fn resolve(offset: u64, length: u64, object_size: u64) -> Resolved {
        if offset >= object_size {
            return Resolved {
                start: object_size,
                count: 0,
                eof_after: true,
            };
        }
        // `offset < object_size`, so the subtraction can't underflow.
        let max_avail = object_size - offset;
        let count = if length > max_avail { max_avail } else { length };
        Resolved {
            start: offset,
            count,
            eof_after: offset + count >= object_size,
        }
    }

    /// Tracks how many bytes of a resolved window remain to be drained
    /// across repeated `host_object_recv` calls. The provider owns the
    /// actual byte transport; this only does the bounded accounting so
    /// a recv never over-reads its window and EOF is reported exactly
    /// once the window is exhausted.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Cursor {
        remaining: u64,
    }

    impl Cursor {
        /// A cursor over a freshly-resolved window.
        pub fn new(resolved: Resolved) -> Self {
            Cursor {
                remaining: resolved.count,
            }
        }

        /// Bytes still owed on this window.
        pub fn remaining(&self) -> u64 {
            self.remaining
        }

        /// Whether the window is fully drained.
        pub fn is_eof(&self) -> bool {
            self.remaining == 0
        }

        /// Reserve up to `want` bytes for the next recv, never more
        /// than the window has left. Decrements the cursor by the
        /// granted amount and returns it. A `want` of `0`, or a call
        /// after EOF, grants `0`.
        pub fn take(&mut self, want: usize) -> usize {
            let want = want as u64;
            let grant = if want > self.remaining {
                self.remaining
            } else {
                want
            };
            self.remaining -= grant;
            grant as usize
        }
    }

    /// Minimum encoded size of a `HEAD` record: `size` + `mtime` + the
    /// two length prefixes, with empty content-type and etag.
    pub const HEAD_MIN_LEN: usize = 8 + 8 + 1 + 1;

    /// Encode a `HEAD` record into `out` per the `object::HEAD` layout
    /// (`[size:u64][mtime:u64][ct_len:u8][ct][etag_len:u8][etag]`).
    /// Returns the number of bytes written, or `None` if `out` is too
    /// small or a field exceeds its `u8` length prefix.
    pub fn encode_head(
        out: &mut [u8],
        size: u64,
        mtime: u64,
        content_type: &[u8],
        etag: &[u8],
    ) -> Option<usize> {
        if content_type.len() > u8::MAX as usize || etag.len() > u8::MAX as usize {
            return None;
        }
        let total = HEAD_MIN_LEN + content_type.len() + etag.len();
        if out.len() < total {
            return None;
        }
        out[0..8].copy_from_slice(&size.to_le_bytes());
        out[8..16].copy_from_slice(&mtime.to_le_bytes());
        let mut p = 16;
        out[p] = content_type.len() as u8;
        p += 1;
        out[p..p + content_type.len()].copy_from_slice(content_type);
        p += content_type.len();
        out[p] = etag.len() as u8;
        p += 1;
        out[p..p + etag.len()].copy_from_slice(etag);
        p += etag.len();
        Some(p)
    }

    /// The fixed-width prefix of a decoded `HEAD` record.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Head {
        pub size: u64,
        pub mtime: u64,
    }

    /// Decode a `HEAD` record, returning its fixed fields plus borrowed
    /// `content_type` and `etag` slices. Returns `None` on truncation.
    pub fn decode_head(buf: &[u8]) -> Option<(Head, &[u8], &[u8])> {
        if buf.len() < HEAD_MIN_LEN {
            return None;
        }
        let mut size = [0u8; 8];
        size.copy_from_slice(&buf[0..8]);
        let mut mtime = [0u8; 8];
        mtime.copy_from_slice(&buf[8..16]);
        let ct_len = buf[16] as usize;
        let ct_start: usize = 17;
        let ct_end = ct_start.checked_add(ct_len)?;
        if buf.len() < ct_end + 1 {
            return None;
        }
        let content_type = &buf[ct_start..ct_end];
        let etag_len = buf[ct_end] as usize;
        let etag_start = ct_end + 1;
        let etag_end = etag_start.checked_add(etag_len)?;
        if buf.len() < etag_end {
            return None;
        }
        let etag = &buf[etag_start..etag_end];
        Some((
            Head {
                size: u64::from_le_bytes(size),
                mtime: u64::from_le_bytes(mtime),
            },
            content_type,
            etag,
        ))
    }

    /// Format an HTTP `Range` header *value* for a resolved window into
    /// `out` (e.g. `bytes=100-199`). Used by the Linux adapter to issue
    /// a ranged `GET` through `linux_net`. Returns the byte length
    /// written, or `None` if `out` is too small or `count == 0` (an
    /// empty window has no range to request — the caller issues a HEAD
    /// instead). The end byte is inclusive per RFC 9110 §14.1.
    pub fn write_range_header_value(out: &mut [u8], start: u64, count: u64) -> Option<usize> {
        if count == 0 {
            return None;
        }
        let end = start + count - 1;
        let mut p = 0;
        for b in b"bytes=" {
            *out.get_mut(p)? = *b;
            p += 1;
        }
        p += write_u64(out.get_mut(p..)?, start)?;
        *out.get_mut(p)? = b'-';
        p += 1;
        p += write_u64(out.get_mut(p..)?, end)?;
        Some(p)
    }

    /// Write a `u64` as decimal ASCII into `out`, returning its length.
    /// `None` if `out` can't hold the digits.
    fn write_u64(out: &mut [u8], mut v: u64) -> Option<usize> {
        // Render into a scratch buffer (max 20 digits for u64) then
        // copy in order — avoids alloc in this no_std path.
        let mut scratch = [0u8; 20];
        let mut n = 0;
        if v == 0 {
            *out.get_mut(0)? = b'0';
            return Some(1);
        }
        while v > 0 {
            scratch[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
        if out.len() < n {
            return None;
        }
        for i in 0..n {
            out[i] = scratch[n - 1 - i];
        }
        Some(n)
    }
}
