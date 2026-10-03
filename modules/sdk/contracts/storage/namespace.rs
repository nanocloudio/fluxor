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
//   - Open-returning ops (`LOOKUP`, `SUBSCRIBE`) advertise per-handle
//     fence via `provider_query(handle, query_key::LAST_FENCE, …)`.
//   - Handle-bound ops (`STAT`) advertise per-handle via the same path.
//   - Handle=-1 one-shot ops (`LIST`, `RENAME`, `DELETE`) carry a
//     `[fence_out_ptr: u64 LE, fence_out_cap: u16 LE]` pair in their
//     arg layout. The provider writes the encoded `Fence` (up to
//     `fence::WIRE_MAX_LEN` bytes) into that buffer atomically with
//     the op return; callers decode via `Fence::decode`. A null
//     `fence_out_ptr`, or a `fence_out_cap` below `fence::WIRE_MAX_LEN`,
//     is `EINVAL`, refused before the op acts.
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
//               naming ops welded into `fs` 0x09__, a log-structured
//               store's project-local bind op).
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

/// A write's answer here is classified as `storage.object`'s is.
pub use super::object::{write_answer, WriteAnswer};

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
/// A name is at most [`STORAGE_KEY_MAX`](super::handle::STORAGE_KEY_MAX) bytes, which is
/// also the longest cursor. The prefix is a path, bounded by [`PATH_MAX`]: a
/// directory-shaped provider's prefix names a directory however deep it sits,
/// and a key-shaped provider holds no key under a prefix longer than a key; `cursor_len` in the trailing record is **u8**,
/// narrower than the `u16` the request carries, and stated here because a
/// consumer parses one shape and a provider that guesses the other width
/// corrupts every page but the last.
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
///
/// `RENAME`, `DELETE` and `BIND` MAY answer `EINPROGRESS` when the
/// provider cannot decide the write inside the call (a replicated
/// provider decides it at its log position). The caller asks again later
/// with byte-identical arguments; the answer to a later ask is the
/// decision and its fence. The provider keys an undecided write by the
/// calling module and the request's bytes, so asking again is never a
/// second write. This is the same rule as `storage.object`'s writes.
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
/// Returns 0 or negative errno, or `EINPROGRESS` as for `RENAME`. Same
/// fence-advertisement rules as `RENAME` — the encoded fence is written
/// into `fence_out_ptr` atomically with the op return.
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
/// [`caps::CHILD_NAMES`] is the one bit that names no opcode: it states the
/// shape of the provider's `LIST` names.
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
