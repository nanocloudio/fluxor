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
// `GET` and `PUT_STREAMED_OPEN` answer the provider's own index; the kernel
// wraps it in a handle (`kernel_abi::handle`) routed to that provider, and
// every later op on the handle (`provider_query(handle,
// query_key::LAST_FENCE, …)` included) reaches the provider with its index.
//
// A consumer that names its store reaches it through a handle bound to it
// (`kernel_abi::bind`, `NAME`); every op below that takes `handle = -1`
// takes that bound handle in its place, and the provider sees `-1`. A
// handle such an op mints comes back routed to the same provider.
//
// ## Call shape
//
// Every op is one flat `arg` record and at most one bulk `data` span. No
// field of any record is an address. A key, prefix, etag or scope is inline
// in `arg`; a body, a range and a listing page travel in `data`. Each
// layout below has one codec in this module, which providers and consumers
// share, with `const fn` lengths a caller sizes its `arg` with.
//
// ## Fence advertisement
//
//   - Handle-bound ops (`RANGE_GET`, `CLOSE`) and open-returning
//     ops (`GET`, `PUT_STREAMED_OPEN`) advertise the per-handle
//     fence via `provider_query(handle, query_key::LAST_FENCE, …)`.
//   - One-shot ops (`PUT`, `HEAD`, `DELETE`, `LIST`, `RETAIN`,
//     `PUT_STREAMED_COMMIT`) end their `arg` with the fence trailer
//     (`fence::trailer`): the last `fence::trailer::LEN` bytes, which the
//     provider writes as `[fence_len u16][Fence::encode bytes]` atomically
//     with returning the op's i32 result. An `arg` too short to hold its
//     record and the trailer is `EINVAL`, refused before the op acts: an
//     answer whose fence cannot be delivered is not an answer.
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
//   - `RETAIN` → the strongest fence the change achieved, as for `PUT`.
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
// `PUT`, `PUT_STREAMED_COMMIT`, `DELETE` and `RETAIN` MAY return `EINPROGRESS` when
// the provider cannot decide the write inside the call. A replicated
// provider is the case: a write and its precondition are decided where
// the entry lands in the group's log, which is the linearization point
// `precondition` requires, and that takes a consensus round.
//
// `EINPROGRESS` means the write is taken and not yet decided. The caller
// MUST ask again later with byte-identical arguments, and MUST NOT change
// them; the answer to a later ask is the decision (0, `EEXIST`, `EAGAIN`
// for a lost etag, …) with its fence. The provider keys an undecided write
// by the calling module and the request's record (the `arg` bytes before
// the fence trailer), so asking again is a second look at the same write,
// never a second write. A `PUT` asks again with the same body in `data`:
// the provider may read it on a later ask, not only on the first, and it
// writes the fence trailer of the ask that carries the decision. A caller
// that stops asking does not undo the write: it was decided in the log, and
// only the answer is uncollected.
//
// `EAGAIN` keeps its single meaning on the write path: `precondition::ETAG`
// answers it when the etag moved, and the caller re-reads and retries with
// the new etag. "Not yet" has its own code, so a lost update and a pending
// write are never confused.
//
// A provider that decides inside the call never answers `EINPROGRESS`.
// "Taken but not yet durable" is a success carrying `Fence::Volatile`.
//
// ### Streamed writes: `EAGAIN` is backpressure
//
// `PUT_STREAMED_OPEN` and `PUT_STREAMED_WRITE` MAY return `EAGAIN` when the
// provider cannot take the request now without waiting: no stream slot is
// free yet (one is still being released), or the chunk fits neither the
// staging area nor the provider's bounded spill. `EAGAIN` here means
// nothing was taken and no state moved: no handle was opened, and no byte
// of the chunk was consumed, so the stream's length, its digest and its
// order are as they were before the call.
//
// The caller MUST keep the chunk and send the same chunk again on a later
// step, ahead of any byte that follows it in the body, and MUST NOT treat
// `EAGAIN` as a failure, an end of stream or a reason to abort. It MUST
// NOT re-send within the same step: the provider frees room only between
// steps, so asking again inside a step spins. A caller fed by a flow (an
// HTTP body, a socket) holds the flow while the chunk waits — it stops
// reading more until the chunk is taken — rather than drop or buffer
// without bound. A `PUT_STREAMED_WRITE` is all or nothing: 0 means the
// whole chunk was taken, and there is no short count.
//
// `PUT_STREAMED_COMMIT` keeps the write path's meanings: `EINPROGRESS` is
// "taken, ask again byte-identical" and `EAGAIN` is the decision that a
// `precondition::ETAG` lost. `PUT_STREAMED_ABORT` and `CLOSE` decide inside
// the call and release the handle whatever they answer.

/// What a storage write answered: decided, or not yet.
///
/// Every write `provider_call` (`PUT`, `PUT_STREAMED_COMMIT`, `DELETE`, `RETAIN`, and
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
/// `handle = -1` (or a grant); `arg` (in/out, [`put`] is the codec) is:
///
/// ```text
///   [key_len: u16 LE]
///   [key: key_len bytes UTF-8]
///   [content_type_len: u8]
///   [content_type: content_type_len bytes]    — MIME-style tag
///   [precondition: u8]                        — see `precondition` below
///   [etag_len: u8]                            — 0 unless precondition = ETAG
///   [etag: etag_len bytes]
///   [key_ref_len: u8]                         — see [`Kept`]
///   [key_ref: key_ref_len bytes]
///   [retain_until_ms: u64 LE]                 — 0 = none
///   [legal_hold: u8]                          — 0 or 1
///   [fence trailer: fence::trailer::LEN]      — written by the provider
/// ```
///
/// `data` (in) is the body, the whole blob.
///
/// Returns 0 or negative errno, `ERETAINED` over a retained or held object
/// (see [`Kept`]). On success the provider writes the encoded fence into the
/// trailer. The body must fit a single in-memory blob; large bodies use the
/// `PUT_STREAMED_*` sequence below. A provider that enumerates its keys
/// refuses (`EINVAL`) a key it could not list: the empty key, and one longer
/// than the listing surfaces it serves can carry.
pub use super::super::super::registry::storage_object::PUT;

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
///
/// The same rule holds for [`Kept`]: a provider that cannot keep a field MUST
/// refuse a non-empty `key_ref`, a non-zero `retain_until_ms`, a `legal_hold`
/// and [`RETAIN`] with `ENOSYS`. Ignoring one turns a write the caller asked
/// to be immutable into a deletable one, and the caller is told it succeeded.
pub mod precondition {
    /// Apply unconditionally.
    pub const ANY: u8 = 0;
    /// Apply only if the key does not exist. `EEXIST` if it does.
    pub const ABSENT: u8 = 1;
    /// Apply only if the key's current etag equals the supplied one.
    /// `EAGAIN` if it does not — re-read and retry.
    pub const ETAG: u8 = 2;
}

/// Longest `key_ref` a write may name, in bytes.
pub const KEY_REF_MAX: usize = 64;

/// [`Kept`]'s wire bytes besides its `key_ref`:
/// `[key_ref_len: u8][retain_until_ms: u64][legal_hold: u8]`.
pub const KEPT_FIXED_LEN: usize = 1 + 8 + 1;

/// What the store keeps with an object besides its bytes: the block
/// `[key_ref_len: u8][key_ref][retain_until_ms: u64 LE][legal_hold: u8]`,
/// carried by [`PUT`], [`PUT_STREAMED_OPEN`] and the [`HEAD`] record.
///
/// `key_ref` is an opaque name of the key that sealed the object, at most
/// [`KEY_REF_MAX`] bytes. The store keeps it and returns it and never
/// interprets it; the object's bytes are sealed before they reach the store.
///
/// `retain_until_ms` is a time in milliseconds since the Unix epoch, 0 for
/// none. Until it passes, by the store's own clock, the object is retained.
/// `legal_hold` holds the object until the hold is cleared ([`RETAIN`]).
///
/// ## Retained and held objects
///
/// While an object is retained or held, a `DELETE` of it and a `PUT` or
/// `PUT_STREAMED_COMMIT` over it are refused with `ERETAINED`. The decision
/// is the store's, at the write's linearization point, in the same log order
/// as every other write ([`precondition`]'s atomicity rule), so a write and a
/// [`RETAIN`] are ordered one way for every observer. A streamed write states
/// the block at `PUT_STREAMED_OPEN` and is judged at its commit. A
/// precondition that does not hold answers its own code first.
///
/// A write that lands replaces all three: the new object has what its own
/// write stated, and nothing of the object it replaced.
///
/// A provider that cannot keep these refuses them ([`precondition`]) and
/// reports [`Kept::none`] in every `HEAD` record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Kept<'a> {
    pub key_ref: &'a [u8],
    pub retain_until_ms: u64,
    pub legal_hold: bool,
}

impl<'a> Kept<'a> {
    /// Nothing kept.
    pub const fn none() -> Self {
        Kept {
            key_ref: &[],
            retain_until_ms: 0,
            legal_hold: false,
        }
    }

    /// Whether this asks the store to keep nothing.
    pub const fn is_none(&self) -> bool {
        self.key_ref.is_empty() && self.retain_until_ms == 0 && !self.legal_hold
    }

    /// Encoded size.
    pub const fn wire_len(&self) -> usize {
        KEPT_FIXED_LEN + self.key_ref.len()
    }

    /// Parse the block at `at` in `a`, with the offset just past it. `None`,
    /// which a provider answers `EINVAL`, when it is cut short, its `key_ref`
    /// is past [`KEY_REF_MAX`], or `legal_hold` is neither 0 nor 1.
    pub fn parse(a: &'a [u8], at: usize) -> Option<(Self, usize)> {
        let len = *a.get(at)? as usize;
        if len > KEY_REF_MAX {
            return None;
        }
        let key_ref = a.get(at + 1..at + 1 + len)?;
        let p = at + 1 + len;
        let until = a.get(p..p + 8)?;
        let retain_until_ms = u64::from_le_bytes([
            until[0], until[1], until[2], until[3], until[4], until[5], until[6], until[7],
        ]);
        let legal_hold = match *a.get(p + 8)? {
            0 => false,
            1 => true,
            _ => return None,
        };
        Some((
            Kept {
                key_ref,
                retain_until_ms,
                legal_hold,
            },
            p + 9,
        ))
    }

    /// Encode into `out`; the bytes written, or `None` when `out` is too small
    /// or `key_ref` is past [`KEY_REF_MAX`].
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let len = self.key_ref.len();
        if len > KEY_REF_MAX {
            return None;
        }
        let o = out.get_mut(..KEPT_FIXED_LEN + len)?;
        o[0] = len as u8;
        o[1..1 + len].copy_from_slice(self.key_ref);
        o[1 + len..1 + len + 8].copy_from_slice(&self.retain_until_ms.to_le_bytes());
        o[1 + len + 8] = self.legal_hold as u8;
        Some(KEPT_FIXED_LEN + len)
    }
}

/// Open a blob for streaming reads.
///
/// `handle = -1` (or a grant); `arg` (in, [`key`] is the codec) is
/// `[key_len: u16 LE][key]`.
/// Returns a non-negative handle (used with `RANGE_GET` / `CLOSE`)
/// or negative errno. The handle's fence is read via
/// `provider_query(handle, query_key::LAST_FENCE, …)`.
pub use super::super::super::registry::storage_object::GET;

/// Read metadata for a blob without opening a handle.
///
/// `handle = -1` (or a grant); `arg` is in/out ([`head`] is the codec). In,
/// it opens with the key and ends with the fence trailer:
///
/// ```text
///   [key_len: u16 LE]
///   [key: key_len bytes]
///   …                                         — room for the answer
///   [fence trailer: fence::trailer::LEN]
/// ```
///
/// On success the provider writes the HEAD record over `arg` from byte 0,
/// having taken the key first:
///
/// ```text
///   [size: u64 LE]
///   [mtime: u64 LE]
///   [content_type_len: u8]
///   [content_type: content_type_len bytes]
///   [etag_len: u8]
///   [etag: etag_len bytes]
///   [key_ref_len: u8]                         — see [`Kept`]
///   [key_ref: key_ref_len bytes]
///   [retain_until_ms: u64 LE]                 — 0 = none
///   [legal_hold: u8]                          — 0 or 1
/// ```
///
/// and the encoded fence into the trailer. Returns the record's length, or
/// negative errno: `ENXIO` for an absent key, `ENOMEM` when the bytes before
/// the trailer cannot hold the record ([`head::ARG_LEN`] always can),
/// `EINVAL` for a malformed request.
pub use super::super::super::registry::storage_object::HEAD;

/// Read a byte range from an open object handle.
///
/// `handle` is a GET-returned handle; `arg` (in, [`range_get`] is the codec)
/// is `[offset: u64 LE]`, and `data` (out) receives the range.
///
/// Reads up to `data`'s length starting at `offset` into `data`. Returns the
/// number of bytes actually read (which may be less near the tail, 0 at or
/// past the end) or negative errno. Fence is advertised per-handle via
/// `query_key::LAST_FENCE`.
pub use super::super::super::registry::storage_object::RANGE_GET;

/// Delete a blob.
///
/// `handle = -1` (or a grant); `arg` (in/out, [`delete`] is the codec) is:
///
/// ```text
///   [key_len: u16 LE]
///   [key: key_len bytes]
///   [precondition: u8]                        — see `precondition` below
///   [etag_len: u8]                            — 0 unless precondition = ETAG
///   [etag: etag_len bytes]
///   [fence trailer: fence::trailer::LEN]      — written by the provider
/// ```
///
/// Returns 0 or negative errno, `ERETAINED` for a retained or held object
/// (see [`Kept`]). The provider writes the encoded fence into the trailer
/// atomically with returning success.
pub use super::super::super::registry::storage_object::DELETE;

/// Close a GET or PUT_STREAMED_OPEN handle.
pub use super::super::super::registry::storage_object::CLOSE;

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
/// `handle = -1` (or a grant); `arg` (in) is [`PUT`]'s record without its
/// fence trailer, and there is no `data` ([`put::encode_record`] /
/// [`put::parse_record`]):
///
/// ```text
///   [key_len: u16 LE]
///   [key: key_len bytes UTF-8]
///   [content_type_len: u8]
///   [content_type: content_type_len bytes]
///   [precondition: u8]                        — see `precondition`
///   [etag_len: u8]                            — 0 unless precondition = ETAG
///   [etag: etag_len bytes]
///   [key_ref_len: u8]                         — see [`Kept`]
///   [key_ref: key_ref_len bytes]
///   [retain_until_ms: u64 LE]                 — 0 = none
///   [legal_hold: u8]                          — 0 or 1
/// ```
///
/// Returns a non-negative streaming-write handle or negative errno.
/// `EAGAIN` means no handle was opened yet — ask again on a later step
/// (see "Streamed writes: `EAGAIN` is backpressure" above); `ENOMEM` means
/// every stream slot is open. The handle's fence is `Fence::Volatile`
/// until `PUT_STREAMED_COMMIT` succeeds.
///
/// The condition is stated at OPEN and evaluated at
/// [`PUT_STREAMED_COMMIT`], not here: a streamed write is open across many
/// calls, and a key that satisfied the condition when the handle opened may
/// not when the bytes land. Evaluating at open would make the guard a
/// statement about a moment that has passed by the time it matters — which
/// is the same race a `HEAD` followed by an unconditional write loses, and
/// the reason [`precondition`] insists on a single linearization point.
pub use super::super::super::registry::storage_object::PUT_STREAMED_OPEN;

/// Append a chunk of body bytes to a streaming-write handle.
///
/// `handle` is a `PUT_STREAMED_OPEN`-returned handle; there is no `arg`, and
/// `data` (in) is the chunk. Returns 0 (the whole
/// chunk was taken) or negative errno. Each successful WRITE corresponds
/// to one Event appended on the provider's staging event-log stream. Fence
/// on the handle remains `Volatile`.
///
/// `EAGAIN` is backpressure: nothing of this chunk was consumed, and the
/// caller sends the same chunk again on a later step, before any later
/// byte, never within the same step (see "Streamed writes: `EAGAIN` is
/// backpressure" above). Any other negative answer is a failure of the
/// stream, which the caller aborts.
pub use super::super::super::registry::storage_object::PUT_STREAMED_WRITE;

/// Atomically finalise a streaming write into an object PUT.
///
/// `handle` is a `PUT_STREAMED_OPEN`-returned handle; `arg` (out) is the
/// fence trailer alone, [`COMMIT_ARG_LEN`] bytes.
///
/// Returns 0 or negative errno, `ERETAINED` over a retained or held object
/// (see [`Kept`]). On success the staged event-log
/// stream is committed under the object key, the handle's
/// per-handle fence is updated to the strongest fence the commit
/// achieved, and the encoded fence is also written into the trailer.
/// After COMMIT the handle is no longer writable; callers MUST call `CLOSE`.
pub use super::super::super::registry::storage_object::PUT_STREAMED_COMMIT;

/// [`PUT_STREAMED_COMMIT`]'s `arg`: the fence trailer and nothing else.
pub const COMMIT_ARG_LEN: usize = super::super::super::fence::trailer::LEN;

/// Discard a streaming-write handle without committing.
///
/// `handle` is a `PUT_STREAMED_OPEN`-returned handle; no `arg`, no `data`.
/// Returns 0 or negative errno. The provider drops
/// the staged event-log stream; subsequent reads under `key` do
/// not observe any appended chunks. After ABORT the handle is
/// released — callers do not need to `CLOSE`.
pub use super::super::super::registry::storage_object::PUT_STREAMED_ABORT;

// ── Retention and legal hold ────────────────────────────────────────

/// Change a live object's retention or legal hold.
///
/// `handle = -1`, or a grant; `arg` (in/out) is:
///
/// ```text
///   [key_len: u16 LE]
///   [key: key_len bytes]
///   [retain_until_ms: u64 LE]                 — 0 = leave unchanged
///   [hold: u8]                                — see `hold`
///   [fence trailer: fence::trailer::LEN]      — written by the provider
/// ```
///
/// [`retain`] is the codec for both sides.
///
/// `retain_until_ms` only extends: a value earlier than the one held is
/// refused `ERETAINED` and changes nothing, the hold included, and the value
/// already held is a success that moves nothing. A hold can be set and cleared
/// ([`hold`]), and clearing one leaves any retention standing. The object's
/// bytes, etag, mtime and `key_ref` do not change.
///
/// The store decides at its linearization point, in the same log order as
/// writes ([`Kept`]), so a `RETAIN` is a write: it MAY answer `EINPROGRESS`,
/// and a caller passes its answer to [`write_answer`].
///
/// Returns 0 or negative errno: `ENXIO` for an absent key, `EINVAL` for a
/// malformed request or one that changes neither field, `ENOSYS` from a
/// provider that cannot keep these. On success the provider writes the encoded
/// fence into the trailer. A grant authorizes it with the store's write
/// permission ([`grant::access_of`]): it changes what later writes may do, as
/// a write does, and a scope that may write its objects may protect them.
pub use super::super::super::registry::storage_object::RETAIN;

/// [`RETAIN`]'s `hold` byte.
pub mod hold {
    /// Leave the hold as it is.
    pub const LEAVE: u8 = 0;
    /// Set the hold.
    pub const SET: u8 = 1;
    /// Clear the hold.
    pub const CLEAR: u8 = 2;
}

/// The [`RETAIN`] wire codec. No `std`, no allocation.
pub mod retain {
    use super::super::super::super::fence::trailer;
    use super::super::handle::STORAGE_KEY_MAX;

    /// Record bytes besides the key: `key_len`, `retain_until_ms`, `hold`.
    pub const REQUEST_FIXED_LEN: usize = 2 + 8 + 1;

    /// The `arg` a request for a key of `key_len` bytes takes, trailer
    /// included.
    pub const fn arg_len(key_len: usize) -> usize {
        REQUEST_FIXED_LEN + key_len + trailer::LEN
    }

    /// The longest `arg`.
    pub const ARG_MAX: usize = arg_len(STORAGE_KEY_MAX);

    /// A decoded [`super::RETAIN`] request.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Request<'a> {
        pub key: &'a [u8],
        pub retain_until_ms: u64,
        pub hold: u8,
    }

    /// Parse and validate the request in `arg` (trailer included). `None`,
    /// which the provider answers `EINVAL`, when the bytes before the
    /// trailer are not exactly one request, the key is empty or past
    /// `STORAGE_KEY_MAX`, `hold` is not one of [`super::hold`], or the
    /// request changes neither field.
    pub fn parse_request(arg: &[u8]) -> Option<Request<'_>> {
        let rec = trailer::record(arg)?;
        let key_len = u16::from_le_bytes([*rec.first()?, *rec.get(1)?]) as usize;
        if key_len == 0 || key_len > STORAGE_KEY_MAX || rec.len() != REQUEST_FIXED_LEN + key_len {
            return None;
        }
        let key = rec.get(2..2 + key_len)?;
        let t = rec.get(2 + key_len..)?;
        let req = Request {
            key,
            retain_until_ms: u64::from_le_bytes([t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]]),
            hold: t[8],
        };
        if req.hold > super::hold::CLEAR
            || (req.retain_until_ms == 0 && req.hold == super::hold::LEAVE)
        {
            return None;
        }
        Some(req)
    }

    /// Encode `req` into `out` with an empty trailer; the `arg` length, or
    /// `None` when `out` is too small or the key is past `STORAGE_KEY_MAX`.
    pub fn encode_request(out: &mut [u8], req: &Request<'_>) -> Option<usize> {
        let n = req.key.len();
        if n > STORAGE_KEY_MAX {
            return None;
        }
        let o = out.get_mut(..arg_len(n))?;
        o[0..2].copy_from_slice(&(n as u16).to_le_bytes());
        o[2..2 + n].copy_from_slice(req.key);
        let t = 2 + n;
        o[t..t + 8].copy_from_slice(&req.retain_until_ms.to_le_bytes());
        o[t + 8] = req.hold;
        o[t + 9..].fill(0);
        Some(o.len())
    }
}

/// The `[key_len: u16 LE][key]` record [`GET`] takes, and that opens
/// [`HEAD`]'s request.
pub mod key {
    use super::super::handle::STORAGE_KEY_MAX;

    /// The record for a key of `key_len` bytes.
    pub const fn arg_len(key_len: usize) -> usize {
        2 + key_len
    }

    /// The longest record.
    pub const ARG_MAX: usize = arg_len(STORAGE_KEY_MAX);

    /// The key a record opens with, and the offset just past it. `None`
    /// when the bytes are short or the key is past `STORAGE_KEY_MAX`.
    pub fn parse_prefix(arg: &[u8]) -> Option<(&[u8], usize)> {
        let n = u16::from_le_bytes([*arg.first()?, *arg.get(1)?]) as usize;
        if n > STORAGE_KEY_MAX {
            return None;
        }
        Some((arg.get(2..2 + n)?, 2 + n))
    }

    /// The key when `arg` is exactly one record.
    pub fn parse(arg: &[u8]) -> Option<&[u8]> {
        match parse_prefix(arg)? {
            (k, end) if end == arg.len() => Some(k),
            _ => None,
        }
    }

    /// Encode `key` into `out`; the record's length, or `None` when it does
    /// not fit or the key is past `STORAGE_KEY_MAX`.
    pub fn encode(out: &mut [u8], key: &[u8]) -> Option<usize> {
        if key.len() > STORAGE_KEY_MAX {
            return None;
        }
        let o = out.get_mut(..arg_len(key.len()))?;
        o[..2].copy_from_slice(&(key.len() as u16).to_le_bytes());
        o[2..].copy_from_slice(key);
        Some(o.len())
    }
}

/// The [`PUT`] request, whose record is also [`PUT_STREAMED_OPEN`]'s.
pub mod put {
    use super::super::super::super::fence::trailer;
    use super::super::handle::STORAGE_KEY_MAX;
    use super::{Kept, KEPT_FIXED_LEN, KEY_REF_MAX};

    /// Record bytes besides the key, content type, etag and `key_ref`: the
    /// three length prefixes, `precondition` and the `Kept` block's fixed
    /// part.
    pub const RECORD_FIXED_LEN: usize = 2 + 1 + 1 + 1 + KEPT_FIXED_LEN;

    /// The record (no trailer) for fields of these lengths.
    pub const fn record_len(key: usize, content_type: usize, etag: usize, key_ref: usize) -> usize {
        RECORD_FIXED_LEN + key + content_type + etag + key_ref
    }

    /// The longest record.
    pub const RECORD_MAX: usize = record_len(STORAGE_KEY_MAX, 255, 255, KEY_REF_MAX);

    /// A `PUT`'s `arg` for fields of these lengths: the record and the
    /// fence trailer.
    pub const fn arg_len(key: usize, content_type: usize, etag: usize, key_ref: usize) -> usize {
        record_len(key, content_type, etag, key_ref) + trailer::LEN
    }

    /// The longest `PUT` `arg`.
    pub const ARG_MAX: usize = RECORD_MAX + trailer::LEN;

    /// A decoded request.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Request<'a> {
        pub key: &'a [u8],
        pub content_type: &'a [u8],
        /// One of [`super::precondition`].
        pub precondition: u8,
        /// Empty unless `precondition` is `ETAG`.
        pub etag: &'a [u8],
        pub kept: Kept<'a>,
    }

    impl Request<'_> {
        pub const fn record_len(&self) -> usize {
            record_len(
                self.key.len(),
                self.content_type.len(),
                self.etag.len(),
                self.kept.key_ref.len(),
            )
        }
    }

    /// Parse exactly one record. `None` — `EINVAL` — when the bytes are not
    /// one record, the key is past `STORAGE_KEY_MAX`, or the `Kept` block is
    /// malformed. Key and precondition checks beyond the shape are the
    /// provider's.
    pub fn parse_record(rec: &[u8]) -> Option<Request<'_>> {
        let (key, mut p) = super::key::parse_prefix(rec)?;
        let ct_len = *rec.get(p)? as usize;
        let content_type = rec.get(p + 1..p + 1 + ct_len)?;
        p += 1 + ct_len;
        let precondition = *rec.get(p)?;
        let etag_len = *rec.get(p + 1)? as usize;
        let etag = rec.get(p + 2..p + 2 + etag_len)?;
        p += 2 + etag_len;
        let (kept, end) = Kept::parse(rec, p)?;
        (end == rec.len()).then_some(Request {
            key,
            content_type,
            precondition,
            etag,
            kept,
        })
    }

    /// Parse a `PUT` `arg`: the record before the fence trailer.
    pub fn parse(arg: &[u8]) -> Option<Request<'_>> {
        parse_record(trailer::record(arg)?)
    }

    /// Encode the record alone (a `PUT_STREAMED_OPEN` `arg`); its length,
    /// or `None` when `out` is too small or a field exceeds its prefix.
    pub fn encode_record(out: &mut [u8], req: &Request<'_>) -> Option<usize> {
        if req.key.len() > STORAGE_KEY_MAX
            || req.content_type.len() > u8::MAX as usize
            || req.etag.len() > u8::MAX as usize
        {
            return None;
        }
        let o = out.get_mut(..req.record_len())?;
        let mut p = super::key::encode(o, req.key)?;
        o[p] = req.content_type.len() as u8;
        o[p + 1..p + 1 + req.content_type.len()].copy_from_slice(req.content_type);
        p += 1 + req.content_type.len();
        o[p] = req.precondition;
        o[p + 1] = req.etag.len() as u8;
        o[p + 2..p + 2 + req.etag.len()].copy_from_slice(req.etag);
        p += 2 + req.etag.len();
        p += req.kept.encode(o.get_mut(p..)?)?;
        Some(p)
    }

    /// Encode a `PUT` `arg`: the record and an empty fence trailer. Its
    /// length, or `None` when it does not fit.
    pub fn encode(out: &mut [u8], req: &Request<'_>) -> Option<usize> {
        let n = encode_record(out, req)?;
        out.get_mut(n..n + trailer::LEN)?.fill(0);
        Some(n + trailer::LEN)
    }
}

/// The [`HEAD`] request and its in-place answer.
pub mod head {
    use super::super::super::super::fence::trailer;
    use super::super::handle::STORAGE_KEY_MAX;

    /// The longest HEAD record: a content type and etag of 255 bytes each
    /// and a `key_ref` of `KEY_REF_MAX`.
    pub const RECORD_MAX: usize = super::range::HEAD_MIN_LEN + 255 + 255 + super::KEY_REF_MAX;

    /// An `arg` that always holds the answer: the longest record (which is
    /// longer than any key's request) and the trailer.
    pub const ARG_LEN: usize = RECORD_MAX + trailer::LEN;

    const _: () = assert!(RECORD_MAX >= super::key::arg_len(STORAGE_KEY_MAX));

    /// Encode a request for `key` into `out`, zeroing the rest of it; the
    /// whole of `out` is the `arg`. `None` when `out` cannot hold the key and
    /// the trailer.
    pub fn encode_request(out: &mut [u8], key: &[u8]) -> Option<usize> {
        if out.len() < super::key::arg_len(key.len()) + trailer::LEN {
            return None;
        }
        let n = super::key::encode(out, key)?;
        out[n..].fill(0);
        Some(out.len())
    }

    /// The key a request names. The bytes after it, up to the trailer, are
    /// room for the answer and are not read.
    pub fn parse_request(arg: &[u8]) -> Option<&[u8]> {
        let rec = trailer::record(arg)?;
        let (k, _) = super::key::parse_prefix(rec)?;
        (!k.is_empty()).then_some(k)
    }

    /// The record part of a HEAD `arg`, for the provider to write the answer
    /// into once it has taken the key (`range::encode_head`).
    pub fn answer_area(arg: &mut [u8]) -> Option<&mut [u8]> {
        trailer::split(arg).map(|(rec, _)| rec)
    }
}

/// The [`RANGE_GET`] request: `[offset: u64 LE]`.
pub mod range_get {
    pub const ARG_LEN: usize = 8;

    pub const fn encode(offset: u64) -> [u8; ARG_LEN] {
        offset.to_le_bytes()
    }

    /// The offset, when `arg` is exactly one request.
    pub fn parse(arg: &[u8]) -> Option<u64> {
        let a: [u8; ARG_LEN] = arg.try_into().ok()?;
        Some(u64::from_le_bytes(a))
    }
}

/// The [`DELETE`] request.
pub mod delete {
    use super::super::super::super::fence::trailer;
    use super::super::handle::STORAGE_KEY_MAX;

    /// Record bytes besides the key and etag.
    pub const REQUEST_FIXED_LEN: usize = 2 + 1 + 1;

    pub const fn arg_len(key_len: usize, etag_len: usize) -> usize {
        REQUEST_FIXED_LEN + key_len + etag_len + trailer::LEN
    }

    pub const ARG_MAX: usize = arg_len(STORAGE_KEY_MAX, 255);

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Request<'a> {
        pub key: &'a [u8],
        pub precondition: u8,
        pub etag: &'a [u8],
    }

    /// Parse the request in `arg` (trailer included); `None` — `EINVAL` —
    /// unless the bytes before the trailer are exactly one request.
    pub fn parse_request(arg: &[u8]) -> Option<Request<'_>> {
        let rec = trailer::record(arg)?;
        let (key, p) = super::key::parse_prefix(rec)?;
        let precondition = *rec.get(p)?;
        let etag_len = *rec.get(p + 1)? as usize;
        let etag = rec.get(p + 2..p + 2 + etag_len)?;
        (p + 2 + etag_len == rec.len()).then_some(Request {
            key,
            precondition,
            etag,
        })
    }

    /// Encode with an empty trailer; the `arg` length.
    pub fn encode_request(out: &mut [u8], req: &Request<'_>) -> Option<usize> {
        if req.etag.len() > u8::MAX as usize {
            return None;
        }
        let total = arg_len(req.key.len(), req.etag.len());
        let o = out.get_mut(..total)?;
        let p = super::key::encode(o, req.key)?;
        o[p] = req.precondition;
        o[p + 1] = req.etag.len() as u8;
        o[p + 2..p + 2 + req.etag.len()].copy_from_slice(req.etag);
        o[p + 2 + req.etag.len()..].fill(0);
        Some(total)
    }
}

// ── Enumeration ─────────────────────────────────────────────────────

/// Enumerate the objects whose key starts with a prefix, in ascending
/// bytewise key order, one bounded page per call, resumed by an opaque
/// cursor.
///
/// `handle = -1` (or a grant); `arg` (in/out) is:
///
/// ```text
///   [prefix_len: u16 LE]
///   [prefix: prefix_len bytes]
///   [cursor_len: u16 LE]                      — 0 for the first page
///   [cursor: cursor_len bytes]                — otherwise exactly the cursor
///                                               a previous page returned
///   [max_keys: u16 LE]                        — 1..=`LIST_PAGE_MAX`
///   [fence trailer: fence::trailer::LEN]      — written by the provider
/// ```
///
/// On success the provider writes one page into `data` (out):
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
/// and the encoded fence into the trailer. Returns the number of bytes
/// written to `data`, or negative errno. [`list`] is the codec
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
/// whole entries as fit `data` while keeping room for the trailing
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
/// [`list::ARG_MAX`] carries a prefix and a cursor of `STORAGE_KEY_MAX` bytes
/// each, so any caller, gated or not, can resume at any key a provider holds.
///
/// ## Errors
///
///   - `EINVAL` — malformed request (one with no room for the fence
///     trailer included), `max_keys` of 0 or above [`LIST_PAGE_MAX`], or
///     a cursor this provider did not issue for this prefix.
///   - `ENOMEM` — `data` cannot hold one entry plus the page trailer.
///   - `EOVERFLOW` — a key in range exceeds `STORAGE_KEY_MAX`.
///   - `ENOSYS` — the provider cannot enumerate its keys (an HTTP origin
///     offers no listing).
pub use super::super::super::registry::storage_object::LIST;

/// Most entries one [`LIST`] page may carry. S3's `MaxKeys` ceiling;
/// bounds the work one call does.
pub const LIST_PAGE_MAX: u16 = 1000;

/// The [`LIST`] wire codec — request parsing, page writing with the
/// trailer reservation, and page decoding. No `std`, no allocation, so
/// the kernel providers, bare-metal providers and PIC consumers share
/// one implementation of the layout.
pub mod list {
    use super::super::super::super::fence::trailer;
    use super::super::handle::STORAGE_KEY_MAX;
    use super::LIST_PAGE_MAX;

    /// `[count: u16]` at the head of a page.
    pub const PAGE_HEADER_LEN: usize = 2;

    /// `[cursor_len: u16]`, the trailing record's bytes besides its cursor.
    pub const TRAILER_HEADER_LEN: usize = 2;

    /// An entry's bytes besides its key and etag:
    /// `[key_len: u16][size: u64][mtime: u64][etag_len: u8]`.
    pub const ENTRY_FIXED_LEN: usize = 2 + 8 + 8 + 1;

    /// Record bytes besides the prefix and cursor: the two length prefixes
    /// and `max_keys`.
    pub const REQUEST_FIXED_LEN: usize = 2 + 2 + 2;

    /// The `arg` for a prefix and cursor of these lengths, trailer included.
    pub const fn arg_len(prefix_len: usize, cursor_len: usize) -> usize {
        REQUEST_FIXED_LEN + prefix_len + cursor_len + trailer::LEN
    }

    /// The longest `arg`.
    pub const ARG_MAX: usize = arg_len(STORAGE_KEY_MAX, STORAGE_KEY_MAX);

    /// Encoded size of one entry.
    pub const fn entry_len(key_len: usize, etag_len: usize) -> usize {
        ENTRY_FIXED_LEN + key_len + etag_len
    }

    /// Smallest `data` that holds one entry of this shape and the trailer
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
    }

    fn u16_at(b: &[u8], at: usize) -> Option<u16> {
        let s = b.get(at..at.checked_add(2)?)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }

    fn u64_at(b: &[u8], at: usize) -> Option<u64> {
        let s = b.get(at..at.checked_add(8)?)?;
        Some(u64::from_le_bytes([
            s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
        ]))
    }

    /// Parse and validate the request in `arg` (trailer included). `None` —
    /// the provider answers `EINVAL` — when the bytes before the trailer are
    /// not exactly one request, `max_keys` is outside `1..=LIST_PAGE_MAX`,
    /// or the prefix or cursor is longer than `STORAGE_KEY_MAX`.
    pub fn parse_request(arg: &[u8]) -> Option<Request<'_>> {
        let arg = trailer::record(arg)?;
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
        if arg.len() != p + 2 {
            return None;
        }
        let req = Request {
            prefix,
            cursor,
            max_keys: u16_at(arg, p)?,
        };
        if req.max_keys == 0 || req.max_keys > LIST_PAGE_MAX {
            return None;
        }
        Some(req)
    }

    /// Encode `req` into `out` with an empty fence trailer. Returns the
    /// `arg` length, or `None` when `out` is too small or a field exceeds
    /// its length prefix.
    pub fn encode_request(out: &mut [u8], req: &Request<'_>) -> Option<usize> {
        if req.prefix.len() > STORAGE_KEY_MAX || req.cursor.len() > STORAGE_KEY_MAX {
            return None;
        }
        let total = arg_len(req.prefix.len(), req.cursor.len());
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
        put(&[0u8; trailer::LEN]);
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
// `GET`, `HEAD`, `DELETE`, `LIST`, `RETAIN` and `PUT_STREAMED_OPEN`, which
// otherwise take `-1` — and is admitted only when:
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
/// `handle = -1`; `arg` (in/out, [`grant::parse_present`] /
/// [`grant::encode_present`]) is:
///
/// ```text
///   [refusal: u8]                                 — written: the `Refusal`
///                                                   byte on EACCES, else 0
///   [scope_len: u16 LE][scope: scope_len bytes]   — a key prefix ending `/`
/// ```
///
/// and `data` (in) is the `mesh::capability` chain, so a chain of any
/// length is presented without growing the record.
///
/// Returns a grant handle (tagged like a `GET` handle), `EACCES` when the
/// chain is refused (its reason in byte 0), `EINVAL` when the request or
/// scope is malformed, `ENOSYS` from a provider with no roots, or `ENOMEM`
/// when no grant slot is free.
pub use super::super::super::registry::storage_object::PRESENT;

/// Capability bits: which optional parts of this contract the provider
/// serves. `handle = -1` (or a bound handle); `arg` out is exactly 4 bytes,
/// the `u32` LE [`caps`] word; no `data`. Returns 0. Every provider
/// implements it; `ENOSYS` from `CAPS` means there is no provider.
///
/// A consumer that needs a part reads the word once and fails closed when
/// its bit is clear, before it writes anything. The ops keep their own
/// refusals: a provider still answers `ENOSYS` to a request whose part its
/// word does not carry, so a consumer that skipped `CAPS` is refused, never
/// silently served less. `GET`, `HEAD`, `RANGE_GET` and `CLOSE` are the
/// mandatory surface and have no bit.
pub use super::super::super::registry::storage_object::CAPS;

/// [`CAPS`] bits. A bit is set only where the provider serves that part for
/// valid input; bits not listed are reserved and read 0.
pub mod caps {
    /// [`super::PUT`] and [`super::DELETE`] (unconditional). Clear on a
    /// read-only origin.
    pub const WRITE: u32 = 1 << 0;
    /// [`super::precondition::ABSENT`] on a `PUT`.
    pub const IF_ABSENT: u32 = 1 << 1;
    /// [`super::precondition::ETAG`] on a `PUT` and a `DELETE`.
    pub const IF_ETAG: u32 = 1 << 2;
    /// The `PUT_STREAMED_*` sequence.
    pub const STREAMED: u32 = 1 << 3;
    /// [`super::LIST`].
    pub const LIST: u32 = 1 << 4;
    /// [`super::Kept`] fields on a write, in the `HEAD` record, and
    /// [`super::RETAIN`].
    pub const KEEP: u32 = 1 << 5;
    /// [`super::PRESENT`]: the store has roots, and every `handle = -1` op
    /// but `CAPS` is refused `EACCES`.
    pub const GRANTS: u32 = 1 << 6;
}

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
            | super::PUT_STREAMED_ABORT
            | super::RETAIN => Some(StorageAccess::Write),
            _ => None,
        }
    }

    /// Offset of the refusal byte the provider writes.
    pub const REFUSAL_AT: usize = 0;

    /// A `PRESENT` `arg` for a scope of `scope_len` bytes.
    pub const fn present_arg_len(scope_len: usize) -> usize {
        3 + scope_len
    }

    /// The longest `PRESENT` `arg`.
    pub const PRESENT_ARG_MAX: usize = present_arg_len(SCOPE_MAX);

    /// The scope a `PRESENT` `arg` names; `None` unless it is exactly one
    /// request with a scope of at most [`SCOPE_MAX`] bytes.
    pub fn parse_present(arg: &[u8]) -> Option<&[u8]> {
        let sl = u16::from_le_bytes([*arg.get(1)?, *arg.get(2)?]) as usize;
        if sl > SCOPE_MAX || arg.len() != present_arg_len(sl) {
            return None;
        }
        arg.get(3..)
    }

    /// Encode a `PRESENT` `arg` into `out`; its length, or `None` when it
    /// does not fit or the scope is past [`SCOPE_MAX`]. The chain goes in
    /// `data`.
    pub fn encode_present(out: &mut [u8], scope: &[u8]) -> Option<usize> {
        if scope.len() > SCOPE_MAX {
            return None;
        }
        let o = out.get_mut(..present_arg_len(scope.len()))?;
        o[0] = 0;
        o[1..3].copy_from_slice(&(scope.len() as u16).to_le_bytes());
        o[3..].copy_from_slice(scope);
        Some(o.len())
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
    /// two length prefixes + the `Kept` block, with empty content-type, etag
    /// and `key_ref`.
    pub const HEAD_MIN_LEN: usize = 8 + 8 + 1 + 1 + super::KEPT_FIXED_LEN;

    /// Encode a `HEAD` record into `out` per the `object::HEAD` layout
    /// (`[size:u64][mtime:u64][ct_len:u8][ct][etag_len:u8][etag]`, then the
    /// `Kept` block). Returns the number of bytes written, or `None` if `out`
    /// is too small or a field exceeds its length bound.
    pub fn encode_head(
        out: &mut [u8],
        size: u64,
        mtime: u64,
        content_type: &[u8],
        etag: &[u8],
        kept: super::Kept<'_>,
    ) -> Option<usize> {
        if content_type.len() > u8::MAX as usize || etag.len() > u8::MAX as usize {
            return None;
        }
        let total = HEAD_MIN_LEN + content_type.len() + etag.len() + kept.key_ref.len();
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
        p += kept.encode(out.get_mut(p..)?)?;
        Some(p)
    }

    /// The fixed-width prefix of a decoded `HEAD` record.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Head {
        pub size: u64,
        pub mtime: u64,
    }

    /// Decode a `HEAD` record, returning its fixed fields plus borrowed
    /// `content_type` and `etag` slices and its `Kept` block. Returns `None`
    /// on truncation or a malformed `Kept` block.
    pub fn decode_head(buf: &[u8]) -> Option<(Head, &[u8], &[u8], super::Kept<'_>)> {
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
        let (kept, _) = super::Kept::parse(buf, etag_end)?;
        Some((
            Head {
                size: u64::from_le_bytes(size),
                mtime: u64::from_le_bytes(mtime),
            },
            content_type,
            etag,
            kept,
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
