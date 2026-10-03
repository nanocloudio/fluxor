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
//   - Handle=-1 one-shot ops (`PUT`, `HEAD`, `DELETE`, `LIST`) carry an
//     explicit `[fence_out_ptr, fence_out_cap]` pair in their arg
//     layout. The provider writes up to `fence::WIRE_MAX_LEN` bytes
//     of `Fence::encode` output into `fence_out_ptr` atomically
//     with returning the op's i32 result; callers decode via
//     `Fence::decode`. A null `fence_out_ptr`, or a `fence_out_cap`
//     below `fence::WIRE_MAX_LEN`, is `EINVAL`, refused before the op
//     acts: an answer whose fence cannot be delivered is not an answer.
//
// Typical advertisements:
//   - `LIST` → `ViewConsistent { source, revision }` per page; a
//     listing spans pages and is not a snapshot (see `LIST`).
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
// `kernel::module::provider::contract::STORAGE_OBJECT`. Distinct from FS
// (0x09__), BUFFER (0x0A__), and namespace (0x13__).
//
// ## "Not yet" — the pending rule
//
// A dispatch has to RETURN now; it does not have to ANSWER now. A
// provider whose backing fetch is still in flight has no answer to
// give, and the two halves of this surface say so differently — the
// read path has a code for it, the write path deliberately does not.
//
// ### Reads: `EAGAIN` means ask again
//
// `GET`, `HEAD` and `RANGE_GET` MAY return `EAGAIN` while the backing
// fetch has not landed. Consumers accordingly MUST treat `EAGAIN` from
// a read as "ask again", never as "capability absent" or "object
// absent", and MUST hold the handle and the request that produced it
// rather than re-issuing a new one — a retry that opens a second
// request abandons the fetch already in flight and, against a provider
// that serves one fetch per handle, never terminates.
//
// This mirrors `storage.fs`, which states the same MUST for the same
// reason, and it is what the wasm provider does.
//
// ### Writes: `EINPROGRESS` means ask again with the same request
//
// `PUT`, `PUT_STREAMED_COMMIT` and `DELETE` MAY return `EINPROGRESS` when
// the provider cannot decide the write inside the call. A replicated
// provider is the case: a write and its precondition are decided where
// the entry lands in the group's log, which is the linearization point
// `precondition` requires, and that takes a consensus round.
//
// `EINPROGRESS` means the write is taken and not yet decided. The caller
// MUST ask again later with byte-identical arguments, and MUST NOT change
// them; the answer to a later ask is the decision (0, `EEXIST`, `EAGAIN`
// for a lost etag, …) with its fence. The provider keys an undecided write
// by the calling module and the request's bytes, so asking again is a
// second look at the same write, never a second write. The request names
// its buffers by address, so the buffers it names (key, value, fence out)
// stay where they are and keep their contents until the write is decided:
// the provider reads the value and writes the fence on a later ask, not
// only on the first. A caller that stops asking does not undo the write:
// it was decided in the log, and only the answer is uncollected.
//
// `EAGAIN` keeps its single meaning on the write path: `precondition::ETAG`
// answers it when the etag moved, and the caller re-reads and retries with
// the new etag. "Not yet" has its own code, so a lost update and a pending
// write are never confused.
//
// A provider that decides inside the call never answers `EINPROGRESS`.
// "Taken but not yet durable" is a success carrying `Fence::Volatile`.

/// What a storage write answered: decided, or not yet.
///
/// Every write `provider_call` (`PUT`, `PUT_STREAMED_COMMIT`, `DELETE`, and
/// `storage.namespace`'s `RENAME`, `DELETE`, `BIND`) hands its return code
/// to [`write_answer`]; the hygiene scan holds every call site to that. A
/// `match` on the answer then has to say what the caller does with
/// [`WriteAnswer::Pending`], which is the point: a pending write is not a
/// failure, and the caller asks again with the same request.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteAnswer {
    /// The provider's decision: 0, or a negative errno (`EEXIST` for a
    /// lost `ABSENT`, `EAGAIN` for a lost `ETAG`, …).
    Decided(i32),
    /// `EINPROGRESS`: taken, not yet decided. Ask again later with
    /// byte-identical arguments.
    Pending,
}

/// Classify a write's return code.
pub const fn write_answer(rc: i32) -> WriteAnswer {
    if rc == super::super::super::kernel_abi::errno::EINPROGRESS {
        WriteAnswer::Pending
    } else {
        WriteAnswer::Decided(rc)
    }
}

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
///   [precondition: u8]                        — see `precondition` below
///   [etag_len: u8]                            — 0 unless precondition = ETAG
///   [etag: etag_len bytes]
///   [fence_out_ptr: u64 LE]                   — receives Fence::encode bytes
///   [fence_out_cap: u16 LE]                   — must be >= `fence::WIRE_MAX_LEN`
/// ```
///
/// Returns 0 or negative errno. On success the provider writes the
/// encoded fence (up to `fence::WIRE_MAX_LEN` bytes) into the
/// buffer at `fence_out_ptr`. `body_len` must fit a single
/// in-memory blob; large bodies use the `PUT_STREAMED_*` sequence
/// below. A provider that enumerates its keys refuses (`EINVAL`) a key it
/// could not list: the empty key, and one longer than the listing surfaces
/// it serves can carry.
pub const PUT: u32 = 0x1420;

/// Conditions a mutating op may be made subject to.
///
/// Three named conditions rather than a bare etag guard. An etag field
/// alone expresses only "none" and "this etag"; the third meaning, "only
/// if absent", then has to ride a *convention* — that an all-zero 32-byte
/// etag means revision zero. A convention held by one provider and no
/// contract is one a second provider cannot reproduce and a caller cannot
/// discover.
///
/// The three are genuinely three, and not an `Option`: "must not
/// exist" and "must be at revision 0" are different requests, and
/// collapsing them answers one of the two wrongly.
///
/// Carried by [`PUT`], [`DELETE`] and [`PUT_STREAMED_OPEN`]. The streamed
/// path takes the same three because body size is not a reason to lose a
/// guarantee: a create-if-absent of a large body is the same request as a
/// small one, and a caller that could not express it would have to fall
/// back to the `HEAD`-then-write race this contract forbids.
///
/// ## Atomicity
///
/// A provider MUST evaluate the precondition and apply the mutation
/// at a single linearization point, at the replicated state-machine
/// position the returned `Fence` represents. A `HEAD` followed by an
/// unconditional `PUT` is NOT equivalent and does not satisfy this
/// contract: two callers doing that both observe absence and both
/// write, which is the race conditional writes exist to prevent.
///
/// A provider that cannot offer a condition MUST refuse it with
/// `ENOSYS` rather than ignore it. Silently downgrading a conditional
/// write to an unconditional one turns a refusal into a lost update.
pub mod precondition {
    /// Apply unconditionally.
    pub const ANY: u8 = 0;
    /// Apply only if the key does not exist. `EEXIST` if it does.
    pub const ABSENT: u8 = 1;
    /// Apply only if the key's current etag equals the supplied one.
    /// `EAGAIN` if it does not — re-read and retry.
    pub const ETAG: u8 = 2;
}

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
/// number of bytes written to `out_ptr`, or negative errno: `ENXIO` for
/// an absent key, `ENOMEM` when `out_cap` cannot hold the record,
/// `EINVAL` for a null `out_ptr`.
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
///   [precondition: u8]                        — see `precondition` below
///   [etag_len: u8]                            — 0 unless precondition = ETAG
///   [etag: etag_len bytes]
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
///   [precondition: u8]                        — see `precondition`
///   [etag_len: u8]                            — 0 unless precondition = ETAG
///   [etag: etag_len bytes]
/// ```
///
/// Returns a non-negative streaming-write handle or negative errno.
/// The handle's fence is `Fence::Volatile` until
/// `PUT_STREAMED_COMMIT` succeeds.
///
/// The condition is stated at OPEN and evaluated at
/// [`PUT_STREAMED_COMMIT`], not here: a streamed write is open across many
/// calls, and a key that satisfied the condition when the handle opened may
/// not when the bytes land. Evaluating at open would make the guard a
/// statement about a moment that has passed by the time it matters — which
/// is the same race a `HEAD` followed by an unconditional write loses, and
/// the reason [`precondition`] insists on a single linearization point.
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

// ── Enumeration ─────────────────────────────────────────────────────

/// Enumerate the objects whose key starts with a prefix, in ascending
/// bytewise key order, one bounded page per call, resumed by an opaque
/// cursor.
///
/// `handle = -1`; `arg` is:
///
/// ```text
///   [prefix_len: u16 LE]
///   [prefix: prefix_len bytes]
///   [cursor_len: u16 LE]                      — 0 for the first page
///   [cursor: cursor_len bytes]                — otherwise exactly the cursor
///                                               a previous page returned
///   [max_keys: u16 LE]                        — 1..=`LIST_PAGE_MAX`
///   [out_ptr: u64 LE]
///   [out_cap: u32 LE]
///   [fence_out_ptr: u64 LE]                   — receives Fence::encode bytes
///   [fence_out_cap: u16 LE]                   — must be >= `fence::WIRE_MAX_LEN`
/// ```
///
/// On success the provider writes one page into `out_ptr`:
///
/// ```text
///   [count: u16 LE]
///   count × entry:
///     [key_len: u16 LE][key][size: u64 LE][mtime: u64 LE]
///     [etag_len: u8][etag]
///   [cursor_len: u16 LE]                      — 0 means END OF LISTING
///   [cursor: cursor_len bytes]                — opaque, echo to fetch the next page
/// ```
///
/// and the encoded fence into `fence_out_ptr`. Returns the number of
/// bytes written to `out_ptr`, or negative errno. [`list`] is the codec
/// for both sides; providers and consumers use it rather than spelling
/// the offsets themselves.
///
/// An entry names an object by the key `GET`, `HEAD` and `DELETE` take,
/// and carries what `HEAD` would report for it — its size, mtime and etag —
/// so a listing needs no `GET` to learn them. Listing opens nothing and
/// returns no handle; a caller reads an object by opening its key.
///
/// ## Paging
///
/// A page holds at most `max_keys` entries. The provider fills as many
/// whole entries as fit `out_cap` while keeping room for the trailing
/// cursor, which is the last key returned, so a page can always be
/// terminated. A page MUST make progress: when
/// not even one entry plus the trailer fits, the provider refuses with
/// `ENOMEM` rather than return an empty page that is not the last. A
/// prefix with nothing under it answers `count = 0, cursor_len = 0`.
///
/// ## Cursor
///
/// The cursor names a position in key order: the next page resumes
/// strictly after the last key the previous page returned. Keys inserted
/// or deleted between pages are therefore seen or not according to
/// whether they sort after the cursor, and a key present for the whole
/// listing is never skipped or repeated. Each page writes its own fence —
/// `ViewConsistent { source, revision }` from a store — so a listing is
/// a sequence of views, not a snapshot.
///
/// The empty cursor means "first page" in a request and "end of listing"
/// in a page, so the empty key is never a key (see [`PUT`]).
///
/// A key is at most [`STORAGE_KEY_MAX`](super::handle::STORAGE_KEY_MAX) bytes, which is also the
/// longest prefix and cursor, so a provider that enumerates its keys refuses
/// to create a longer one ([`PUT`]). A provider that meets one anyway in the
/// range it is listing refuses the call with `EOVERFLOW` rather than skip it:
/// a listing a caller believes is complete and is not is a silent loss.
///
/// A module that reaches the provider through the kernel's gateway sends the
/// request through the gateway's argument copy, which is sized to carry a
/// prefix and a cursor of `STORAGE_KEY_MAX` bytes each, so such a caller can resume
/// at any key a provider holds.
///
/// ## Errors
///
///   - `EINVAL` — malformed request, `max_keys` of 0 or above
///     [`LIST_PAGE_MAX`], `fence_out_cap` below `fence::WIRE_MAX_LEN`, or
///     a cursor this provider did not issue for this prefix.
///   - `ENOMEM` — `out_cap` cannot hold one entry plus the trailer.
///   - `EOVERFLOW` — a key in range exceeds `STORAGE_KEY_MAX`.
///   - `ENOSYS` — the provider cannot enumerate its keys (an HTTP origin
///     offers no listing).
pub const LIST: u32 = 0x142A;

/// Most entries one [`LIST`] page may carry. S3's `MaxKeys` ceiling;
/// bounds the work one call does.
pub const LIST_PAGE_MAX: u16 = 1000;

/// The [`LIST`] wire codec — request parsing, page writing with the
/// trailer reservation, and page decoding. No `std`, no allocation, so
/// the kernel providers, bare-metal providers and PIC consumers share
/// one implementation of the layout.
pub mod list {
    use super::super::handle::STORAGE_KEY_MAX;
    use super::LIST_PAGE_MAX;

    /// `[count: u16]` at the head of a page.
    pub const PAGE_HEADER_LEN: usize = 2;

    /// `[cursor_len: u16]`, the trailing record's bytes besides its cursor.
    pub const TRAILER_HEADER_LEN: usize = 2;

    /// An entry's bytes besides its key and etag:
    /// `[key_len: u16][size: u64][mtime: u64][etag_len: u8]`.
    pub const ENTRY_FIXED_LEN: usize = 2 + 8 + 8 + 1;

    /// Request bytes besides the prefix and cursor:
    /// the two length prefixes, `max_keys`, `out_ptr`, `out_cap`,
    /// `fence_out_ptr` and `fence_out_cap`.
    pub const REQUEST_FIXED_LEN: usize = 2 + 2 + 2 + 8 + 4 + 8 + 2;

    /// Encoded size of one entry.
    pub const fn entry_len(key_len: usize, etag_len: usize) -> usize {
        ENTRY_FIXED_LEN + key_len + etag_len
    }

    /// Smallest `out_cap` that holds one entry of this shape and the trailer
    /// that resumes after it (the cursor is this key): what a provider needs
    /// to make progress past it.
    pub const fn min_out_cap(key_len: usize, etag_len: usize) -> usize {
        PAGE_HEADER_LEN + entry_len(key_len, etag_len) + TRAILER_HEADER_LEN + key_len
    }

    /// A decoded [`super::LIST`] request.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Request<'a> {
        pub prefix: &'a [u8],
        /// Empty for the first page.
        pub cursor: &'a [u8],
        pub max_keys: u16,
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
    /// `EINVAL` — when the bytes are not exactly one request, `max_keys`
    /// is outside `1..=LIST_PAGE_MAX`, the prefix or cursor is longer than
    /// `STORAGE_KEY_MAX`, either output pointer is null, or the fence buffer is
    /// smaller than `fence::WIRE_MAX_LEN`.
    ///
    /// The length is exact: a `cursor_len` that disagrees with the bytes
    /// supplied shifts the fixed tail, and reading a shifted tail yields a
    /// plausible pointer to write into.
    pub fn parse_request(arg: &[u8]) -> Option<Request<'_>> {
        let prefix_len = u16_at(arg, 0)? as usize;
        if prefix_len > STORAGE_KEY_MAX {
            return None;
        }
        let prefix = arg.get(2..2 + prefix_len)?;
        let mut p = 2 + prefix_len;
        let cursor_len = u16_at(arg, p)? as usize;
        if cursor_len > STORAGE_KEY_MAX {
            return None;
        }
        let cursor = arg.get(p + 2..p + 2 + cursor_len)?;
        p += 2 + cursor_len;
        if arg.len() != p + REQUEST_FIXED_LEN - 4 {
            return None;
        }
        let req = Request {
            prefix,
            cursor,
            max_keys: u16_at(arg, p)?,
            out_ptr: u64_at(arg, p + 2)?,
            out_cap: u32_at(arg, p + 10)?,
            fence_out_ptr: u64_at(arg, p + 14)?,
            fence_out_cap: u16_at(arg, p + 22)?,
        };
        if req.max_keys == 0 || req.max_keys > LIST_PAGE_MAX {
            return None;
        }
        if req.out_ptr == 0
            || req.fence_out_ptr == 0
            || (req.fence_out_cap as usize) < super::super::super::super::fence::WIRE_MAX_LEN
        {
            return None;
        }
        Some(req)
    }

    /// Encode `req` into `out`. Returns the bytes written, or `None` when
    /// `out` is too small or a field exceeds its length prefix.
    pub fn encode_request(out: &mut [u8], req: &Request<'_>) -> Option<usize> {
        if req.prefix.len() > STORAGE_KEY_MAX || req.cursor.len() > STORAGE_KEY_MAX {
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
        put(&req.max_keys.to_le_bytes());
        put(&req.out_ptr.to_le_bytes());
        put(&req.out_cap.to_le_bytes());
        put(&req.fence_out_ptr.to_le_bytes());
        put(&req.fence_out_cap.to_le_bytes());
        Some(total)
    }

    /// Writes one page into a caller buffer, keeping the trailer's room
    /// in reserve so the page can always be finished.
    pub struct PageWriter<'a> {
        out: &'a mut [u8],
        pos: usize,
        count: u16,
        max_keys: u16,
    }

    impl<'a> PageWriter<'a> {
        /// A writer over `out` that accepts at most `max_keys` entries.
        pub fn new(out: &'a mut [u8], max_keys: u16) -> Self {
            PageWriter {
                out,
                pos: PAGE_HEADER_LEN,
                count: 0,
                max_keys,
            }
        }

        /// Entries written so far.
        pub fn count(&self) -> u16 {
            self.count
        }

        /// The page holds `max_keys` entries and takes no more.
        pub fn is_full(&self) -> bool {
            self.count >= self.max_keys
        }

        /// Append one entry. `false` when the page is full, when the entry
        /// and the trailer that resumes after it (the cursor is this key) do
        /// not both fit, or when the key is empty or exceeds `STORAGE_KEY_MAX`, or the
        /// etag its `u8` length prefix — the caller tells those apart before
        /// pushing. Nothing is written on `false`.
        pub fn push(&mut self, key: &[u8], size: u64, mtime: u64, etag: &[u8]) -> bool {
            if self.is_full()
                || key.is_empty()
                || key.len() > STORAGE_KEY_MAX
                || etag.len() > u8::MAX as usize
            {
                return false;
            }
            let need = entry_len(key.len(), etag.len());
            let end = self.pos + need;
            if end + TRAILER_HEADER_LEN + key.len() > self.out.len() {
                return false;
            }
            let o = &mut self.out[self.pos..end];
            o[0..2].copy_from_slice(&(key.len() as u16).to_le_bytes());
            let mut p = 2 + key.len();
            o[2..p].copy_from_slice(key);
            o[p..p + 8].copy_from_slice(&size.to_le_bytes());
            o[p + 8..p + 16].copy_from_slice(&mtime.to_le_bytes());
            o[p + 16] = etag.len() as u8;
            p += 17;
            o[p..p + etag.len()].copy_from_slice(etag);
            self.pos = end;
            self.count += 1;
            true
        }

        /// Write the header and the trailing cursor (empty = end of
        /// listing). Returns the page length, or `None` when the buffer
        /// cannot hold the page — the provider answers `ENOMEM`.
        pub fn finish(self, cursor: &[u8]) -> Option<usize> {
            if cursor.len() > STORAGE_KEY_MAX {
                return None;
            }
            let end = self.pos + TRAILER_HEADER_LEN + cursor.len();
            if end > self.out.len() {
                return None;
            }
            self.out[0..2].copy_from_slice(&self.count.to_le_bytes());
            self.out[self.pos..self.pos + 2].copy_from_slice(&(cursor.len() as u16).to_le_bytes());
            self.out[self.pos + 2..end].copy_from_slice(cursor);
            Some(end)
        }
    }

    /// One listed object.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Entry<'a> {
        pub key: &'a [u8],
        pub size: u64,
        pub mtime: u64,
        pub etag: &'a [u8],
    }

    /// A decoded page: its entries and the cursor that continues it.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Page<'a> {
        count: u16,
        entries: &'a [u8],
        cursor: &'a [u8],
    }

    fn entry_at(b: &[u8], at: usize) -> Option<(Entry<'_>, usize)> {
        let key_len = u16_at(b, at)? as usize;
        let key = b.get(at + 2..at + 2 + key_len)?;
        let p = at + 2 + key_len;
        let size = u64_at(b, p)?;
        let mtime = u64_at(b, p + 8)?;
        let etag_len = *b.get(p + 16)? as usize;
        let etag = b.get(p + 17..p + 17 + etag_len)?;
        Some((
            Entry {
                key,
                size,
                mtime,
                etag,
            },
            p + 17 + etag_len,
        ))
    }

    /// Decode exactly one page — the `n` bytes a successful call reported.
    /// `None` when the bytes are not one well-formed page.
    pub fn decode_page(page: &[u8]) -> Option<Page<'_>> {
        let count = u16_at(page, 0)?;
        let mut p = PAGE_HEADER_LEN;
        for _ in 0..count {
            p = entry_at(page, p)?.1;
        }
        let cursor_len = u16_at(page, p)? as usize;
        if cursor_len > STORAGE_KEY_MAX || page.len() != p + TRAILER_HEADER_LEN + cursor_len {
            return None;
        }
        Some(Page {
            count,
            entries: &page[PAGE_HEADER_LEN..p],
            cursor: &page[p + 2..],
        })
    }

    impl<'a> Page<'a> {
        pub fn count(&self) -> u16 {
            self.count
        }

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

    /// The entries of a decoded [`Page`], in key order.
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

// ── Authority: presenting a capability ─────────────────────────────
//
// A provider configured with mesh roots admits nothing on its say-so alone:
// every op runs under a GRANT the caller presented. `PRESENT` takes a scope
// (a key prefix — a bucket, say `photos/`) and a capability chain whose
// leaf names that scope's object ([`grant::scope_object`]); the provider
// verifies the chain against its roots and its trusted clock and answers a
// grant handle. Every later op passes the grant as its `handle` — `PUT`,
// `GET`, `HEAD`, `DELETE`, `LIST` and `PUT_STREAMED_OPEN`, which otherwise
// take `-1` — and is admitted only when:
//
//   - the key (or, for `LIST`, the prefix) lies inside the scope;
//   - the grant carries the permission the op's class needs
//     ([`grant::access_of`] → `StorageAccess::permission`);
//   - the grant's window has not closed, by the provider's trusted clock.
//
// A refusal is `EACCES`. A handle minted under a grant (a `GET`'s read
// handle) dies with it. `CLOSE` on a grant drops it. The grant belongs to the
// module occupancy that presented it; another module, or a later occupancy
// of the same scheduler slot, is refused `EACCES`.
//
// A provider with no roots is an unguarded local store: it answers
// `PRESENT` with `ENOSYS` and serves `handle = -1` ops as before. A provider
// with roots answers every `handle = -1` op with `EACCES`, and refuses its
// namespace surface the same way, because that surface has no way to carry a
// grant and would otherwise list what the scope hides.

/// Present a capability chain for a scope; answers a grant handle.
///
/// `handle = -1`; `arg` is:
///
/// ```text
///   [refusal: u8]                                 — written: the `Refusal`
///                                                   byte on EACCES, else 0
///   [scope_len: u16 LE][scope: scope_len bytes]   — a key prefix ending `/`
///   [chain_len: u16 LE][chain: chain_len bytes]   — mesh::capability chain
/// ```
///
/// The answer's reason travels in the request rather than behind a pointer,
/// so the request carries no pointer at all and an isolated module can
/// present the longest chain.
///
/// Returns a grant handle (tagged like a `GET` handle), `EACCES` when the
/// chain is refused (its reason in byte 0), `EINVAL` when the request or
/// scope is malformed, `ENOSYS` from a provider with no roots, or `ENOMEM`
/// when no grant slot is free.
pub const PRESENT: u32 = 0x142B;

/// Grants, scopes, and which permission each op needs. Shared so a
/// provider, a consumer and an issuer compute the same object for the same
/// scope.
pub mod grant {
    use super::super::super::mesh::capability::{CapCrypto, ObjectId};
    use super::super::handle::{StorageAccess, STORAGE_KEY_MAX};

    /// Longest scope a grant names: a scope is a key prefix, so it is
    /// bounded as keys are.
    pub const SCOPE_MAX: usize = 255;
    const _: () = assert!(SCOPE_MAX == STORAGE_KEY_MAX);

    /// Domain separation for [`scope_object`], so a scope's object can never
    /// equal a delegated key's (`capability::key_object`).
    pub const SCOPE_DOMAIN: &[u8] = b"fluxor.storage.scope\0";

    /// The object a capability over `scope` names: the first 16 bytes of
    /// SHA-256 of [`SCOPE_DOMAIN`] followed by the scope. `None` for a scope
    /// that is not [`valid_scope`].
    pub fn scope_object<C: CapCrypto>(crypto: &C, scope: &[u8]) -> Option<ObjectId> {
        if !valid_scope(scope) {
            return None;
        }
        let mut buf = [0u8; SCOPE_DOMAIN.len() + SCOPE_MAX];
        let n = SCOPE_DOMAIN.len();
        buf[..n].copy_from_slice(SCOPE_DOMAIN);
        buf[n..n + scope.len()].copy_from_slice(scope);
        let h = crypto.sha256(&buf[..n + scope.len()]);
        let mut o = [0u8; 16];
        o.copy_from_slice(&h[..16]);
        Some(o)
    }

    /// A scope is non-empty, at most [`SCOPE_MAX`] bytes, and ends `/`, so
    /// `photos/` never admits `photos2/…`.
    pub fn valid_scope(scope: &[u8]) -> bool {
        !scope.is_empty() && scope.len() <= SCOPE_MAX && scope.last() == Some(&b'/')
    }

    /// Whether `key` (or a `LIST` prefix) lies inside `scope`.
    pub fn in_scope(scope: &[u8], key: &[u8]) -> bool {
        key.starts_with(scope)
    }

    /// The access class an op needs; `None` for an op no grant covers.
    pub fn access_of(op: u32) -> Option<StorageAccess> {
        match op {
            super::GET | super::HEAD | super::RANGE_GET | super::LIST => Some(StorageAccess::Read),
            super::PUT
            | super::DELETE
            | super::PUT_STREAMED_OPEN
            | super::PUT_STREAMED_WRITE
            | super::PUT_STREAMED_COMMIT
            | super::PUT_STREAMED_ABORT => Some(StorageAccess::Write),
            _ => None,
        }
    }

    /// A parsed `PRESENT` request.
    pub struct Present<'a> {
        pub scope: &'a [u8],
        pub chain: &'a [u8],
    }

    /// Offset of the refusal byte the provider writes.
    pub const REFUSAL_AT: usize = 0;

    /// Parse a `PRESENT` argument; `None` unless it is exactly one request.
    pub fn parse_present(arg: &[u8]) -> Option<Present<'_>> {
        let sl = u16::from_le_bytes([*arg.get(1)?, *arg.get(2)?]) as usize;
        let scope = arg.get(3..3 + sl)?;
        let at = 3 + sl;
        let cl = u16::from_le_bytes([*arg.get(at)?, *arg.get(at + 1)?]) as usize;
        let chain = arg.get(at + 2..at + 2 + cl)?;
        if arg.len() != at + 2 + cl {
            return None;
        }
        Some(Present { scope, chain })
    }

    /// Encode a `PRESENT` argument into `out`; its length, or `None` when it
    /// does not fit.
    pub fn encode_present(out: &mut [u8], scope: &[u8], chain: &[u8]) -> Option<usize> {
        let n = 1 + 2 + scope.len() + 2 + chain.len();
        if out.len() < n || scope.len() > u16::MAX as usize || chain.len() > u16::MAX as usize {
            return None;
        }
        out[0] = 0;
        out[1..3].copy_from_slice(&(scope.len() as u16).to_le_bytes());
        out[3..3 + scope.len()].copy_from_slice(scope);
        let at = 3 + scope.len();
        out[at..at + 2].copy_from_slice(&(chain.len() as u16).to_le_bytes());
        out[at + 2..at + 2 + chain.len()].copy_from_slice(chain);
        Some(n)
    }
}

/// Host-neutral helpers shared by the platform `storage.object`
/// adapters that back `HEAD` / `RANGE_GET` with browser `fetch()`
/// (wasm) and `Range:` requests (linux). The four browser host
/// bindings — `host_object_head`,
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
        let count = if length > max_avail {
            max_avail
        } else {
            length
        };
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
