// Generic GPU wire contract — the ONE definition of the request envelope,
// operation numbers, opaque handles, outcome records, capability facts and
// reject reasons that a GPU producer, the driver that decodes the stream, and
// every backend (WebGPU, native wgpu/Vulkan, the replay provider) must agree
// on.
//
// There is one contract and it is this one. No version field, no negotiation,
// no compatibility layer: a stream that does not decode here is not this
// contract, and the answer is a framing fault rather than a fallback.
//
// Path-mounted by each side so the numbers cannot drift. The JS backend cannot
// include Rust, so `tests/harness/tests/gpu_backend_wire.rs` reads
// `host_shims.js` and checks its literals against these constants.
//
// ## What this contract is not
//
// It carries no application meaning. Tensor shapes, model operators,
// quantisation, pixel semantics, scene graphs and numerical tolerance belong
// to the consumer. This file frames *generic executable work over generic
// resources*: a program pack, buffers and views, a dependency-ordered
// submission, a fence, and a structured outcome.
//
// ## Mounting
//
// No inner attributes, so the file is `include!`-able flat alongside
// `cores/gpu_pack.rs` and `cores/gpu_device.rs`, which read its constants
// from the same namespace. A consumer that only needs the numbers can
// `#[path]`-mount it as a module instead; both reaches see one definition.
// Includers carry the usual module-scope `#![allow(dead_code)]` — no side
// of this contract uses every constant.
//
// ## Envelope
//
// Every record — request and outcome alike — is a 16-byte header followed by
// `len` payload bytes, little-endian throughout:
//
// ```text
//   [0..2]   magic   u16  = MAGIC
//   [2..4]   op      u16  request op (< 0x8000) or outcome kind (>= 0x8000)
//   [4..8]   len     u32  payload byte length, <= MAX_PAYLOAD
//   [8..16]  corr    u64  caller-chosen correlation, echoed on every outcome
// ```
//
// `magic` is a framing check, not a version and not a sniffing mechanism: a
// port carries this contract because the graph typed it `GpuCommand`, and a
// header that fails the check is a framing fault. The decoder rejects with
// [`REASON_MALFORMED`] and the caller must resynchronise by reconnecting,
// because a byte FIFO cannot be resynced by searching for the next plausible
// header.
//
// There is deliberately **no owner field**. Authority comes from the granted
// channel/provider context the record arrived on. A caller-supplied owner
// number would be a claim, not a grant.
//
// ## Correlation and outcomes
//
// `corr` is opaque to the provider and echoed on every outcome for the
// request. Exactly one of these is emitted per request:
//
// - [`OUT_REJECTED`] — terminal. Nothing was admitted; **no caller-visible
//   output changed**, no fence was allocated, no resource was mutated.
// - [`OUT_ACCEPTED`] — the request was admitted and a fence allocated. Every
//   admitted request, including ones that finish at admission, gets a fence,
//   so there is one completion rule rather than a fast path and a slow path.
//
// An accepted request then reaches exactly one terminal fence outcome inside
// the live device epoch: [`OUT_COMPLETED`], [`OUT_FAILED`], [`OUT_CANCELLED`]
// or [`OUT_DEVICE_LOST`]. That is a per-epoch guarantee over one channel, not
// a distributed exactly-once claim: a device epoch bump terminates every
// outstanding fence with `OUT_DEVICE_LOST` and invalidates all handles.
//
// Terminal outcomes are **retained** until the consumer acknowledges them
// with [`OP_RELEASE_FENCE`]. When the fence/result pool fills, new work is
// refused at admission ([`REASON_FENCE_EXHAUSTED`]) — results are never
// dropped to make room, because a dropped result is indistinguishable from
// work that never ran.
//
// ## Bulk data
//
// `MAX_PAYLOAD` bounds one record at 64 KiB. Larger transfers are a run of
// [`OP_UPLOAD`] / [`OP_READBACK`] chunks against explicit offsets, which is
// what makes a step's work bounded. It is a chunked bulk path, not a
// per-element call.

// ── Envelope ────────────────────────────────────────────────────────────

/// First two bytes of every record, little-endian.
///
/// A framing check, not a version. A stream that does not start with these
/// bytes is not this contract, and there is no other contract to fall back to.
pub const MAGIC: u16 = 0x47F9;
/// Bytes before the payload.
pub const HEADER_LEN: usize = 16;
/// Largest payload one record may carry. An R2 width ceiling, published as a
/// capability fact so a producer sizes its chunking against the contract
/// rather than against a backend's incidental buffer size.
pub const MAX_PAYLOAD: u32 = 64 * 1024;
/// Largest whole record: header plus a maximal payload.
pub const MAX_RECORD: usize = HEADER_LEN + MAX_PAYLOAD as usize;

/// A decoded record header. Produced only by [`Header::decode`], which
/// validates the magic and the payload length before it exists, so holding one
/// is evidence the framing was sound.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    pub op: u16,
    pub len: u32,
    pub corr: u64,
}

impl Header {
    #[must_use]
    pub const fn new(op: u16, len: u32, corr: u64) -> Self {
        Self { op, len, corr }
    }

    /// Encode into a 16-byte header.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..2].copy_from_slice(&MAGIC.to_le_bytes());
        buf[2..4].copy_from_slice(&self.op.to_le_bytes());
        buf[4..8].copy_from_slice(&self.len.to_le_bytes());
        buf[8..16].copy_from_slice(&self.corr.to_le_bytes());
        buf
    }

    /// Decode a header from the front of `bytes`.
    ///
    /// `Err` carries the reject reason to answer with. `Ok(None)` means the
    /// 16 header bytes have not all arrived yet — the caller keeps buffering.
    /// A short *payload* is likewise not an error; [`Self::total_len`] says
    /// how many bytes the whole record needs.
    pub fn decode(bytes: &[u8]) -> Result<Option<Header>, u16> {
        let magic = MAGIC.to_le_bytes();
        if bytes.len() < HEADER_LEN {
            // A wrong leading byte is detectable before the rest arrives, and
            // saying so immediately beats buffering 15 more bytes of garbage.
            if bytes.first().is_some_and(|b| *b != magic[0])
                || bytes.get(1).is_some_and(|b| *b != magic[1])
            {
                return Err(REASON_MALFORMED);
            }
            return Ok(None);
        }
        if bytes[0] != magic[0] || bytes[1] != magic[1] {
            return Err(REASON_MALFORMED);
        }
        let op = u16::from_le_bytes([bytes[2], bytes[3]]);
        let len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if len > MAX_PAYLOAD {
            return Err(REASON_OVERSIZE);
        }
        let corr = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        Ok(Some(Header { op, len, corr }))
    }

    /// Whole-record byte length. Cannot overflow: `len <= MAX_PAYLOAD`.
    #[must_use]
    pub const fn total_len(&self) -> usize {
        HEADER_LEN + self.len as usize
    }
}

// ── Request operations (op < 0x8000) ────────────────────────────────────
//
// Grouped by family, one family per high nibble of the low byte, so a reader
// can tell a resource op from a submission op at a glance and an unallocated
// number in a family is visibly free.

/// Ask the provider for its capability record. Answered with [`OUT_CAPS`].
/// Payload: empty.
pub const OP_QUERY_CAPS: u16 = 0x0001;

/// Create a buffer. Payload:
/// `[size u64][usage u32][rights u32][residency u8][pad u8×3]`.
pub const OP_CREATE_BUFFER: u16 = 0x0010;
/// Create a texture. Payload:
/// `[width u32][height u32][layers u32][format u32][usage u32][rights u32]`.
pub const OP_CREATE_TEXTURE: u16 = 0x0011;
/// Retire a resource handle. Payload: `[handle u64]`. The handle is invalid
/// immediately; storage is freed only once nothing in flight references it.
pub const OP_DESTROY_RESOURCE: u16 = 0x0012;
/// Create a bounded aligned view over a resource subrange. Payload:
/// `[resource u64][offset u64][length u64][usage u32][rights u32]`.
pub const OP_CREATE_VIEW: u16 = 0x0013;
/// Release a view handle. Payload: `[handle u64]`.
pub const OP_RELEASE_VIEW: u16 = 0x0014;
/// Seal a buffer: no further writes through this handle or any alias.
/// Payload: `[handle u64]`.
pub const OP_SEAL_RESOURCE: u16 = 0x0015;
/// Move a resource between residency states. Payload: `[handle u64][state u8]`.
/// An in-flight resource is never evicted; the request is refused instead.
pub const OP_SET_RESIDENCY: u16 = 0x0016;
/// Create a sampler. Payload: `[filter u32][address u32][rights u32]`.
pub const OP_CREATE_SAMPLER: u16 = 0x0017;

/// Load a program pack (see `gpu_pack.rs` for the manifest layout). Payload:
/// `[program u64][chunk_offset u32][total_len u32][pack bytes…]`.
///
/// Chunked, because a pack is routinely larger than [`MAX_PAYLOAD`].
/// `program` is [`HANDLE_NONE`] on the first chunk and the handle the
/// provider answered with on every later one — the handle is what ties the
/// chunks together, so two interleaved loads cannot splice into one artifact.
/// `chunk_offset` must equal the bytes already received. Identity is checked
/// once the artifact is whole: no partial pack is ever reported as having
/// passed a digest check.
pub const OP_LOAD_PROGRAM: u16 = 0x0020;
/// Release a program handle. Payload: `[handle u64]`.
pub const OP_RELEASE_PROGRAM: u16 = 0x0021;
/// Create a pipeline from a loaded program. Payload:
/// `[program u64][kind u8][pad u8×3][state_len u32][backend state…]`.
/// Compilation is asynchronous: the fence completes when the pipeline is
/// ready, or fails with the compiler's structured error. Work dispatched
/// against a pipeline whose fence has not completed is refused with
/// [`REASON_NOT_READY`] — never silently skipped.
pub const OP_CREATE_PIPELINE: u16 = 0x0022;
/// Release a pipeline handle. Payload: `[handle u64]`.
pub const OP_RELEASE_PIPELINE: u16 = 0x0023;

/// Write CPU bytes into a resource. Payload:
/// `[view u64][offset u64][byte_len u32][pad u32][bytes…]`.
pub const OP_UPLOAD: u16 = 0x0030;
/// Read resource bytes back to the CPU. Payload:
/// `[view u64][offset u64][byte_len u32][pad u32]`. The bytes arrive as one
/// or more [`OUT_RESULT`] records before the fence's terminal outcome.
pub const OP_READBACK: u16 = 0x0031;

/// Distinct resources one submission may reference.
///
/// A fence remembers every resource its submission touched — to hold them
/// against destruction while the work is in flight, to know which candidate
/// outputs it publishes, and to refuse a read of something still uncommitted.
/// That table is fixed, so the count is bounded, and a submission that
/// exceeds it is refused with [`REASON_OVERSIZE`] and this number as its
/// detail.
///
/// Published here because it is a **producer's** constraint, not only a
/// provider's: a consumer with more resident geometry than this has to draw
/// it in several submissions, and it cannot work out how to batch without
/// knowing the ceiling. Bindings, vertex and index buffers, pass targets and
/// copy endpoints all count, and each distinct resource counts once however
/// many times it appears.
pub const MAX_SUBMISSION_RESOURCES: usize = 16;

/// Submit dependency-ordered work. Payload:
/// `[queue u8][wait_count u8][flags u16][item_len u32]`
/// `[wait fences u64 × wait_count][items…]`.
/// Items are the `ITEM_*` sub-records below.
pub const OP_SUBMIT: u16 = 0x0040;

/// Poll a fence without blocking. Payload: `[fence u64]`. Answered with the
/// fence's current terminal outcome, or [`REASON_NOT_READY`] if it has none
/// yet. Polling is optional — outcomes are pushed as they occur.
pub const OP_POLL_FENCE: u16 = 0x0050;
/// Acknowledge and release a fence and its retained result. Payload:
/// `[fence u64]`. This is the ack that bounds result retention.
pub const OP_RELEASE_FENCE: u16 = 0x0051;

/// Ask to cancel accepted work. Payload: `[fence u64]`. Before dispatch this
/// releases the reservation; after dispatch it can only suppress publication
/// until the device finishes. The disposition says which happened.
pub const OP_CANCEL: u16 = 0x0060;
/// Wait for physical quiescence of this owner's work. Payload: empty. The
/// fence completes only when the device has actually finished — channel
/// drainage alone does not prove a GPU is idle.
pub const OP_DRAIN: u16 = 0x0061;
/// Reset the device. Payload: `[scope u8][pad u8×3]`. Terminates every
/// affected accepted request, bumps the device epoch and invalidates all
/// handles, fences, surfaces and pipeline-cache references.
pub const OP_RESET: u16 = 0x0062;

/// Export a resource as a presentable surface lease. Payload:
/// `[view u64][width u32][height u32][format u32][colour_space u32]`.
/// Answered with an [`OUT_SURFACE`] descriptor.
pub const OP_EXPORT_SURFACE: u16 = 0x0070;
/// Release a surface lease. Payload: `[surface u64]`.
pub const OP_RELEASE_SURFACE: u16 = 0x0071;

// ── Submission items (u8 sub-opcode inside OP_SUBMIT) ───────────────────

/// `[pipeline u64][bind_count u16][pad u16][(slot u16, pad u16, view u64) × n]`
/// `[groups_x u32][groups_y u32][groups_z u32]`
pub const ITEM_DISPATCH: u8 = 0x01;
/// `[src view u64][dst view u64][length u64]` — device-to-device copy.
pub const ITEM_COPY: u8 = 0x02;
/// `[target u64][flags u32][clear_rgba u32]` — begin a render pass.
/// `flags` is the `PASS_*` mask below; `clear_rgba` is one texel of the
/// target's format, used only when `PASS_CLEAR_COLOUR` is set.
pub const ITEM_BEGIN_PASS: u8 = 0x03;
// ── Render pass flags ───────────────────────────────────────────────────
//
// The `flags` word of `ITEM_BEGIN_PASS`.

/// Clear the colour attachment to the item's `clear_rgba` before drawing.
/// Without it the pass loads what the target already held.
pub const PASS_CLEAR_COLOUR: u32 = 1 << 0;
/// The pass has a depth attachment, in the format the pipeline declared.
///
/// A depth attachment is pass-local: no consumer names it, binds it, copies
/// it or reads it back, so it is the provider's to allocate against the
/// target's extent rather than a resource the handle table carries. A
/// provider that allocates one reports its bytes; one that cannot refuses the
/// flag rather than drawing without a depth test.
pub const PASS_DEPTH: u32 = 1 << 1;
/// Clear that depth attachment to its far value before drawing. Requires
/// [`PASS_DEPTH`].
pub const PASS_CLEAR_DEPTH: u32 = 1 << 2;

/// Every pass flag this contract allocates.
pub const PASS_ALL: u32 = PASS_CLEAR_COLOUR | PASS_DEPTH | PASS_CLEAR_DEPTH;

/// `[pipeline u64][bind_count u16][pad u16][(slot u16, pad u16, view u64) × n]`
/// `[vertex u64][index u64][first u32][count u32][instances u32]`
pub const ITEM_DRAW: u8 = 0x04;
/// No payload — end the open render pass.
pub const ITEM_END_PASS: u8 = 0x05;

/// Byte length of one binding entry inside a DISPATCH/DRAW item.
pub const BIND_ENTRY_LEN: usize = 12;

// ── Outcome records (op >= 0x8000) ──────────────────────────────────────

/// Discriminator bit separating outcome kinds from request ops, so a record
/// captured off either direction of a channel is unambiguous.
pub const OUTCOME_BIT: u16 = 0x8000;

/// Terminal. Nothing was admitted. Payload: `[reason u16][pad u16][detail u32]`.
/// `detail` is reason-specific and diagnostic only — never a second contract.
pub const OUT_REJECTED: u16 = 0x8001;
/// Admitted; a fence was allocated. Payload: `[fence u64]`.
pub const OUT_ACCEPTED: u16 = 0x8002;
/// The fence's work finished successfully and any candidate output is now
/// published. Payload: `[fence u64][flags u32][pad u32][gpu_nanos u64]`.
/// `gpu_nanos` is `0` unless [`FEATURE_TIMESTAMP`] is advertised — a CPU
/// submit/poll reading is never reported in this field.
pub const OUT_COMPLETED: u16 = 0x8003;
/// The fence's work failed. No candidate output is published. Payload:
/// `[fence u64][reason u16][pad u16][detail u32]`.
pub const OUT_FAILED: u16 = 0x8004;
/// The fence's work was cancelled. Payload: `[fence u64][disposition u8][pad u8×7]`.
pub const OUT_CANCELLED: u16 = 0x8005;
/// The device epoch was lost or reset; every outstanding fence terminates
/// here and every handle of the old epoch is invalid. Payload:
/// `[old_epoch u32][new_epoch u32][reason u16][pad u16][blast u32]`.
pub const OUT_DEVICE_LOST: u16 = 0x8006;
/// Capability record — see [`CAPS_LEN`] and the `caps_*` offsets below.
pub const OUT_CAPS: u16 = 0x8007;
/// One chunk of readback bytes. Payload:
/// `[fence u64][offset u64][byte_len u32][pad u32][bytes…]`. Emitted before
/// the fence's terminal outcome; a fence whose result bytes could not all be
/// written to the output channel stays retained rather than losing bytes.
pub const OUT_RESULT: u16 = 0x8008;
/// A handle was issued. Payload: `[handle u64]`. Follows [`OUT_ACCEPTED`] for
/// every create/load op, so the caller never has to guess a handle value.
pub const OUT_HANDLE: u16 = 0x8009;
/// A surface lease descriptor — see `VideoScanout` in the sink contract.
/// Payload: [`SURFACE_LEN`] bytes, offsets `surface_*` below.
pub const OUT_SURFACE: u16 = 0x800A;

/// `OUT_COMPLETED` flags.
/// The candidate output was published to its public resource.
pub const COMPLETED_PUBLISHED: u32 = 1 << 0;
/// Timing came from conservative queue completion, not a per-submit GPU
/// timestamp. Set whenever `gpu_nanos` is absent or approximate.
pub const COMPLETED_QUEUE_TIMED: u32 = 1 << 1;

/// `OUT_CANCELLED` dispositions — what cancellation actually achieved.
/// Cancelled before dispatch; reservations released, nothing ran.
pub const CANCEL_PRE_DISPATCH: u8 = 1;
/// The device had already started; the work ran to completion and only its
/// publication was suppressed. Cancellation cannot un-run a dispatch.
pub const CANCEL_SUPPRESSED: u8 = 2;
/// A dependency of this work was cancelled, so it never became runnable.
pub const CANCEL_DEPENDENCY: u8 = 3;

// ── Reject / failure reasons ────────────────────────────────────────────

/// Framing fault: bad magic, truncated fixed field, or a payload whose
/// declared shape does not fit its length.
pub const REASON_MALFORMED: u16 = 1;
/// Operation number is not allocated in this contract.
pub const REASON_UNKNOWN_OP: u16 = 2;
/// Declared length exceeds [`MAX_PAYLOAD`] or an advertised limit.
pub const REASON_OVERSIZE: u16 = 3;
/// Handle is unknown, retired, of a stale generation, or from a dead epoch.
pub const REASON_BAD_HANDLE: u16 = 4;
/// Handle names the wrong kind of object for this operation.
pub const REASON_BAD_KIND: u16 = 5;
/// `offset + length` overflows or leaves the resource's bounds.
pub const REASON_BAD_RANGE: u16 = 6;
/// Offset, length or a binding does not meet the device's alignment fact.
pub const REASON_BAD_ALIGNMENT: u16 = 7;
/// The resource was not created with the usage this operation needs.
pub const REASON_USAGE_DENIED: u16 = 8;
/// The granted rights on this handle do not permit the operation, or the
/// handle belongs to another owner and no lease was granted.
pub const REASON_ACCESS_DENIED: u16 = 9;
/// The buffer is sealed; writes through it or any alias are refused.
pub const REASON_SEALED: u16 = 10;
/// A pipeline is still compiling, or a dependency has not completed within
/// the admitted budget. Retry; nothing was skipped.
pub const REASON_NOT_READY: u16 = 11;
/// R1: device memory or staging bytes exhausted.
pub const REASON_RESOURCE_EXHAUSTED: u16 = 12;
/// R2: a handle table is full.
pub const REASON_HANDLE_EXHAUSTED: u16 = 13;
/// Fence/result pool full — retained results must be released first. Refused
/// at admission, before any dispatch.
pub const REASON_FENCE_EXHAUSTED: u16 = 14;
/// Queue depth reached.
pub const REASON_QUEUE_FULL: u16 = 15;
/// The declared waits would make the dependency graph cyclic.
pub const REASON_DEPENDENCY_CYCLE: u16 = 16;
/// A fence this work waited on failed or was cancelled.
pub const REASON_DEPENDENCY_FAILED: u16 = 17;
/// The object is referenced by in-flight work and cannot be mutated or
/// evicted now.
pub const REASON_IN_FLIGHT: u16 = 18;
/// The device epoch ended.
pub const REASON_DEVICE_LOST: u16 = 19;
/// The request needs a feature, format or arithmetic fact this device does
/// not advertise. Refused with the fact, never emulated silently.
pub const REASON_UNSUPPORTED_FEATURE: u16 = 20;
/// Program-pack identity, target, toolchain or binding layout is not
/// acceptable to this provider.
pub const REASON_BAD_PROGRAM: u16 = 21;
/// A candidate output would alias a public or input resource. Refused until
/// aliasing is supported safely.
pub const REASON_ALIASED_OUTPUT: u16 = 22;
/// The resource is not resident (or is still uploading) and this provider
/// does not page it in transparently.
pub const REASON_RESIDENCY: u16 = 23;
/// The device timed out waiting for this work; the memory it could reach is
/// retained until a verified reset, not reused.
pub const REASON_TIMEOUT: u16 = 24;

/// Human-readable name for a reason code. Diagnostics only — the number is
/// the contract.
#[must_use]
pub const fn reason_name(reason: u16) -> &'static str {
    match reason {
        REASON_MALFORMED => "malformed",
        REASON_UNKNOWN_OP => "unknown-op",
        REASON_OVERSIZE => "oversize",
        REASON_BAD_HANDLE => "bad-handle",
        REASON_BAD_KIND => "bad-kind",
        REASON_BAD_RANGE => "bad-range",
        REASON_BAD_ALIGNMENT => "bad-alignment",
        REASON_USAGE_DENIED => "usage-denied",
        REASON_ACCESS_DENIED => "access-denied",
        REASON_SEALED => "sealed",
        REASON_NOT_READY => "not-ready",
        REASON_RESOURCE_EXHAUSTED => "resource-exhausted",
        REASON_HANDLE_EXHAUSTED => "handle-exhausted",
        REASON_FENCE_EXHAUSTED => "fence-exhausted",
        REASON_QUEUE_FULL => "queue-full",
        REASON_DEPENDENCY_CYCLE => "dependency-cycle",
        REASON_DEPENDENCY_FAILED => "dependency-failed",
        REASON_IN_FLIGHT => "in-flight",
        REASON_DEVICE_LOST => "device-lost",
        REASON_UNSUPPORTED_FEATURE => "unsupported-feature",
        REASON_BAD_PROGRAM => "bad-program",
        REASON_ALIASED_OUTPUT => "aliased-output",
        REASON_RESIDENCY => "residency",
        REASON_TIMEOUT => "timeout",
        _ => "unknown",
    }
}

// ── Handles ─────────────────────────────────────────────────────────────
//
// A handle is opaque to the caller and meaningful only to the provider that
// issued it. It is scoped to a device epoch, carries a generation so a retired
// slot cannot be reached by a stale copy, and names a kind so a buffer handle
// cannot be passed where a pipeline is expected. Copying the number to another
// process, worker or host is not access: the receiving side has no grant.
//
//   bits  0..16  index      (u16) — slot in the provider's table
//   bits 16..32  generation (u16) — bumped on retirement; never 0 when live
//   bits 32..40  kind       (u8)  — KIND_* below
//   bits 40..56  epoch      (u16) — device epoch the handle belongs to
//   bits 56..64  reserved   (u8)  — must be zero

/// The null handle. Never issued; every field zero, so a zeroed struct is
/// unambiguously "no handle" rather than "slot 0, generation 0".
pub const HANDLE_NONE: u64 = 0;

pub const KIND_BUFFER: u8 = 1;
pub const KIND_TEXTURE: u8 = 2;
pub const KIND_SAMPLER: u8 = 3;
pub const KIND_VIEW: u8 = 4;
pub const KIND_PROGRAM: u8 = 5;
pub const KIND_PIPELINE: u8 = 6;
pub const KIND_FENCE: u8 = 7;
pub const KIND_SURFACE: u8 = 8;

/// Pack a handle. `generation` must be non-zero for a live handle.
#[must_use]
pub const fn handle_pack(index: u16, generation: u16, kind: u8, epoch: u16) -> u64 {
    (index as u64) | ((generation as u64) << 16) | ((kind as u64) << 32) | ((epoch as u64) << 40)
}

#[must_use]
pub const fn handle_index(h: u64) -> u16 {
    (h & 0xFFFF) as u16
}
#[must_use]
pub const fn handle_generation(h: u64) -> u16 {
    ((h >> 16) & 0xFFFF) as u16
}
#[must_use]
pub const fn handle_kind(h: u64) -> u8 {
    ((h >> 32) & 0xFF) as u8
}
#[must_use]
pub const fn handle_epoch(h: u64) -> u16 {
    ((h >> 40) & 0xFFFF) as u16
}
/// Whether the reserved high byte is clear. A handle with reserved bits set
/// was fabricated or corrupted, never issued.
#[must_use]
pub const fn handle_reserved_clear(h: u64) -> bool {
    (h >> 56) == 0
}

// ── Resource usage and access rights ────────────────────────────────────
//
// Two independent masks, because they answer different questions.
//
// `usage` is a property of the RESOURCE, fixed at creation: what the device
// was told to make it capable of. Widening it later would mean reallocating.
//
// `rights` is a property of the HANDLE: what this holder may do with a
// resource that is already capable. A lease to another owner is a handle with
// narrower rights over the same resource — which is why merging the two masks
// into one would be wrong.

pub const USAGE_STORAGE: u32 = 1 << 0;
pub const USAGE_UNIFORM: u32 = 1 << 1;
pub const USAGE_VERTEX: u32 = 1 << 2;
pub const USAGE_INDEX: u32 = 1 << 3;
pub const USAGE_INDIRECT: u32 = 1 << 4;
pub const USAGE_COPY_SRC: u32 = 1 << 5;
pub const USAGE_COPY_DST: u32 = 1 << 6;
pub const USAGE_MAP_READ: u32 = 1 << 7;
pub const USAGE_TEXTURE_SAMPLE: u32 = 1 << 8;
pub const USAGE_RENDER_TARGET: u32 = 1 << 9;
/// Eligible to back a presentable surface lease.
pub const USAGE_SCANOUT: u32 = 1 << 10;
/// Private candidate storage for an accepted request's output. Exclusive:
/// a candidate resource may not alias public or input data.
pub const USAGE_CANDIDATE: u32 = 1 << 11;

/// Every usage bit this contract allocates. A request naming a bit outside
/// this mask is malformed rather than merely unsupported.
pub const USAGE_ALL: u32 = USAGE_STORAGE
    | USAGE_UNIFORM
    | USAGE_VERTEX
    | USAGE_INDEX
    | USAGE_INDIRECT
    | USAGE_COPY_SRC
    | USAGE_COPY_DST
    | USAGE_MAP_READ
    | USAGE_TEXTURE_SAMPLE
    | USAGE_RENDER_TARGET
    | USAGE_SCANOUT
    | USAGE_CANDIDATE;

/// May be read by the device or copied from.
pub const RIGHT_READ: u32 = 1 << 0;
/// May be written by the device, uploaded into, or copied to.
pub const RIGHT_WRITE: u32 = 1 << 1;
/// May be named in a submission's bindings.
pub const RIGHT_BIND: u32 = 1 << 2;
/// May be read back to the CPU.
pub const RIGHT_MAP: u32 = 1 << 3;
/// May be granted onward to another owner as a narrower lease.
pub const RIGHT_GRANT: u32 = 1 << 4;
/// May be destroyed or sealed by this holder.
pub const RIGHT_OWN: u32 = 1 << 5;

pub const RIGHT_ALL: u32 =
    RIGHT_READ | RIGHT_WRITE | RIGHT_BIND | RIGHT_MAP | RIGHT_GRANT | RIGHT_OWN;

// ── Texture formats ─────────────────────────────────────────────────────
//
// `format` on a texture, a view and a surface descriptor is one enumeration,
// allocated here rather than left to each backend. It would otherwise be an
// opaque u32 that a native provider and a browser provider each numbered for
// themselves, and a consumer targeting both would have to know which one
// answered — which is exactly the portability this contract exists to give.
//
// Deliberately small. These are the formats a provider here implements, not
// every format a GPU API can spell; one more is a commit, and a request
// naming a number outside this set is refused with the fact rather than
// guessed at.

/// No format. A buffer has none, and a zeroed descriptor is unambiguous.
pub const FORMAT_NONE: u32 = 0;
/// Eight bits per channel, RGBA order, unsigned normalised.
pub const FORMAT_RGBA8_UNORM: u32 = 1;
/// The same, sampled and blended as sRGB.
pub const FORMAT_RGBA8_UNORM_SRGB: u32 = 2;
/// Eight bits per channel, BGRA order — what most swapchains want.
pub const FORMAT_BGRA8_UNORM: u32 = 3;
/// The same, sRGB.
pub const FORMAT_BGRA8_UNORM_SRGB: u32 = 4;
/// 32-bit float depth. Depth only: no stencil, because no provider here
/// implements stencil test and advertising one would be a claim.
pub const FORMAT_DEPTH32_FLOAT: u32 = 5;
/// One unsigned 32-bit integer per texel.
pub const FORMAT_R32_UINT: u32 = 6;

/// Highest format id this contract allocates.
pub const FORMAT_MAX: u32 = FORMAT_R32_UINT;

/// Bytes one texel of `format` occupies, or `None` for an unallocated id.
///
/// Separate from the resource-accounting assumption in the device core, which
/// reserves four bytes per texel for every format. That over-reserves a
/// narrower format and never under-reserves; this answers what a provider
/// actually has to allocate and copy.
#[must_use]
pub const fn format_texel_bytes(format: u32) -> Option<u32> {
    match format {
        FORMAT_RGBA8_UNORM
        | FORMAT_RGBA8_UNORM_SRGB
        | FORMAT_BGRA8_UNORM
        | FORMAT_BGRA8_UNORM_SRGB
        | FORMAT_DEPTH32_FLOAT
        | FORMAT_R32_UINT => Some(4),
        _ => None,
    }
}

/// Whether `format` is a depth format, and so belongs on a pass's depth
/// attachment rather than its colour attachment.
#[must_use]
pub const fn format_is_depth(format: u32) -> bool {
    matches!(format, FORMAT_DEPTH32_FLOAT)
}

// ── Residency ───────────────────────────────────────────────────────────
//
// Explicit, five states, no transparent paging. A workload that does not fit
// is refused so the consumer can choose another declared program or profile —
// silently evicting an in-flight weight would turn a memory shortfall into a
// wrong answer.

/// Backing storage is committed and the device may reach it.
pub const RESIDENCY_RESIDENT: u8 = 1;
/// An upload is in progress; the contents are not yet defined.
pub const RESIDENCY_UPLOADING: u8 = 2;
/// Committed but unpinned: the provider may reclaim its storage when nothing
/// in flight references it. Never while in flight.
pub const RESIDENCY_EVICTABLE: u8 = 3;
/// The handle is retired. Storage may still be held until quiescence.
pub const RESIDENCY_RETIRED: u8 = 4;
/// Contents were lost with the device epoch. Recreate, do not reuse.
pub const RESIDENCY_LOST: u8 = 5;

// ── Queues ──────────────────────────────────────────────────────────────

/// Compute queue. Every provider that advertises [`FEATURE_COMPUTE`] has one.
pub const QUEUE_COMPUTE: u8 = 0;
/// Raster queue. Present only with [`FEATURE_RASTER`]; may be the same
/// hardware queue, which is why cross-queue visibility is a declared fact
/// rather than an assumption.
pub const QUEUE_RASTER: u8 = 1;
/// Transfer queue for uploads, copies and readbacks.
pub const QUEUE_TRANSFER: u8 = 2;
/// Number of queue ids this contract allocates.
pub const QUEUE_COUNT: usize = 3;

// ── Backends ────────────────────────────────────────────────────────────
//
// Which implementation answered. Reported, never requested: a consumer that
// needs a property asks for the property, and provider selection is explicit
// graph composition.

pub const BACKEND_REPLAY: u32 = 1;
pub const BACKEND_WEBGPU: u32 = 2;
pub const BACKEND_WGPU_NATIVE: u32 = 3;

// ── Capability features ─────────────────────────────────────────────────
//
// Independently composed: a compute image advertises COMPUTE and nothing
// about presentation, and the omission is checked in the built artifact, not
// merely disabled at runtime.

pub const FEATURE_COMPUTE: u32 = 1 << 0;
pub const FEATURE_RASTER: u32 = 1 << 1;
pub const FEATURE_READBACK: u32 = 1 << 2;
/// Can hand a device-resident resource to a sink without a CPU round trip.
pub const FEATURE_SHARED_SURFACE: u32 = 1 << 3;
/// Reports true GPU timestamps, distinct from CPU submit/poll readings.
pub const FEATURE_TIMESTAMP: u32 = 1 << 4;
pub const FEATURE_INDIRECT: u32 = 1 << 5;
pub const FEATURE_SUBGROUP: u32 = 1 << 6;
/// A compute output can be bound as raster geometry without a CPU detour.
pub const FEATURE_COMPUTE_TO_RASTER: u32 = 1 << 7;
/// A device reset has been demonstrated to reach verified quiescence, so
/// recovery is advertised rather than hoped for.
pub const FEATURE_DEVICE_RESET: u32 = 1 << 8;
/// Work can be preempted. An advertised fact, not a promise made on behalf
/// of a driver that has not demonstrated it.
pub const FEATURE_PREEMPTION: u32 = 1 << 9;

// ── Arithmetic and storage facts ────────────────────────────────────────
//
// Four independent questions about a numeric type, because conflating them is
// the specific mistake this table exists to prevent: a u8-packed buffer says
// nothing about whether the device can do i8 arithmetic, and "supported" says
// nothing about whether the support is silicon or a shader emulating it.

/// The type can be stored in and loaded from a buffer.
pub const ARITH_STORAGE: u8 = 1 << 0;
/// Arithmetic on the type is available in a program.
pub const ARITH_COMPUTE: u8 = 1 << 1;
/// The type can serve as an accumulator without a widening detour.
pub const ARITH_ACCUM: u8 = 1 << 2;
/// Execution is native. Clear means an explicitly implemented emulation
/// path — never "unknown", and never a way to answer a request the device
/// cannot actually serve.
pub const ARITH_NATIVE: u8 = 1 << 3;

/// Index of each numeric type in the capability record's arithmetic table.
/// A type with a zero byte is unsupported: not stored, not computed, not
/// emulated. BF16, INT4 and ternary are listed so they can be *declared
/// absent* — which is the honest answer until a path exists.
pub const ARITH_I8: usize = 0;
pub const ARITH_U8: usize = 1;
pub const ARITH_I16: usize = 2;
pub const ARITH_U16: usize = 3;
pub const ARITH_I32: usize = 4;
pub const ARITH_U32: usize = 5;
pub const ARITH_F16: usize = 6;
pub const ARITH_F32: usize = 7;
pub const ARITH_BF16: usize = 8;
pub const ARITH_I4: usize = 9;
pub const ARITH_U4: usize = 10;
pub const ARITH_TERNARY: usize = 11;
pub const ARITH_F64: usize = 12;
/// Entries in the arithmetic table.
pub const ARITH_TYPE_COUNT: usize = 13;

/// Composite operations, separate from per-type facts because a device can
/// have F16 arithmetic without a packed F16 multiply.
pub const AOP_DOT4_I8: u32 = 1 << 0;
pub const AOP_DOT2_I16: u32 = 1 << 1;
pub const AOP_PACKED_MUL_F16: u32 = 1 << 2;
pub const AOP_FMA_F32: u32 = 1 << 3;
pub const AOP_ATOMIC_I32: u32 = 1 << 4;
pub const AOP_ATOMIC_F32: u32 = 1 << 5;

// ── Capability record (OUT_CAPS payload) ────────────────────────────────
//
// A flat fixed record with named offsets rather than a self-describing TLV:
// the fields are the contract, so a reader that cannot find one has a version
// problem, not a parsing problem.

/// Reserved head word; zero. Not a version — there is one contract.
pub const CAPS_RESERVED: usize = 0; // u32
pub const CAPS_BACKEND: usize = 4; // u32
pub const CAPS_PROVIDER_EPOCH: usize = 8; // u32
pub const CAPS_DEVICE_EPOCH: usize = 12; // u32
pub const CAPS_FEATURES: usize = 16; // u32
pub const CAPS_ARITH_OPS: usize = 20; // u32
pub const CAPS_MAX_RESOURCES: usize = 24; // u32  R2
pub const CAPS_MAX_VIEWS: usize = 28; // u32  R2
pub const CAPS_MAX_PROGRAMS: usize = 32; // u32  R2
pub const CAPS_MAX_PIPELINES: usize = 36; // u32  R2
pub const CAPS_MAX_FENCES: usize = 40; // u32  R2
pub const CAPS_MAX_QUEUE_DEPTH: usize = 44; // u32  R2
pub const CAPS_MAX_BINDINGS: usize = 48; // u32  R3
pub const CAPS_MIN_ALIGN: usize = 52; // u32  R3
pub const CAPS_MAX_WORKGROUP_X: usize = 56; // u32  R3
pub const CAPS_MAX_WORKGROUP_Y: usize = 60; // u32  R3
pub const CAPS_MAX_WORKGROUP_Z: usize = 64; // u32  R3
pub const CAPS_MAX_WORKGROUP_INVOCATIONS: usize = 68; // u32  R3
pub const CAPS_MAX_GRID_X: usize = 72; // u32  R3
pub const CAPS_MAX_GRID_Y: usize = 76; // u32  R3
pub const CAPS_MAX_GRID_Z: usize = 80; // u32  R3
pub const CAPS_MAX_RECORD_PAYLOAD: usize = 84; // u32  R2 (== MAX_PAYLOAD)
pub const CAPS_MAX_ALLOC_BYTES: usize = 88; // u64  R3
pub const CAPS_MAX_RESIDENT_BYTES: usize = 96; // u64  R1
pub const CAPS_MAX_STAGING_BYTES: usize = 104; // u64  R1
pub const CAPS_MAX_SCRATCH_BYTES: usize = 112; // u64  R1
/// Accepted program-pack target ISAs, one `u32` each, `TARGET_NONE`-padded.
pub const CAPS_TARGETS: usize = 120; // u32 × CAPS_TARGET_SLOTS
pub const CAPS_TARGET_SLOTS: usize = 4;
/// Per-type arithmetic facts, `ARITH_TYPE_COUNT` bytes.
pub const CAPS_ARITH_TABLE: usize = 136;
/// Total capability-record length, padded to 8.
pub const CAPS_LEN: usize = 152;

const _: () = assert!(CAPS_ARITH_TABLE + ARITH_TYPE_COUNT <= CAPS_LEN);
const _: () = assert!(CAPS_TARGETS + CAPS_TARGET_SLOTS * 4 == CAPS_ARITH_TABLE);

// ── Program-pack target ISAs ────────────────────────────────────────────
//
// Named here (not in `gpu_pack.rs`) because a provider advertises the set it
// accepts in its capability record, and the pack declares one of the same
// numbers. WGSL is the portable browser/Linux source path; direct V3D accepts
// only a precompiled kernel pack and never shader text.

pub const TARGET_NONE: u32 = 0;
pub const TARGET_WGSL: u32 = 1;
pub const TARGET_SPIRV: u32 = 2;
pub const TARGET_V3D_QPU: u32 = 3;
/// A fixture artifact the replay provider interprets. Deterministic and
/// hardware-free; it is a validation oracle, not evidence any GPU ran.
pub const TARGET_REPLAY: u32 = 4;

// ── Surface lease descriptor (OUT_SURFACE payload) ──────────────────────
//
// The `VideoScanout` descriptor: what a sink needs in order to
// consume a device-resident frame safely and to say honestly when it was
// displayed. GPU completion, output publication, present-queued and actual
// scanout are four different events, and only the first two are facts this
// provider owns.

pub const SURFACE_HANDLE: usize = 0; // u64
pub const SURFACE_PROVIDER_EPOCH: usize = 8; // u32
pub const SURFACE_DEVICE_EPOCH: usize = 12; // u32
pub const SURFACE_RESOURCE: usize = 16; // u64  the leased view
pub const SURFACE_PRODUCER_FENCE: usize = 24; // u64  wait before reading
pub const SURFACE_WIDTH: usize = 32; // u32
pub const SURFACE_HEIGHT: usize = 36; // u32
pub const SURFACE_STRIDE: usize = 40; // u32
pub const SURFACE_FORMAT: usize = 44; // u32
pub const SURFACE_COLOUR_SPACE: usize = 48; // u32
pub const SURFACE_DAMAGE_X: usize = 52; // u32
pub const SURFACE_DAMAGE_Y: usize = 56; // u32
pub const SURFACE_DAMAGE_W: usize = 60; // u32
pub const SURFACE_DAMAGE_H: usize = 64; // u32
/// Presentation sequence number, monotonic per surface generation.
pub const SURFACE_SEQUENCE: usize = 68; // u32
/// Presentation-group time context in the sink clock's units, or 0 when the
/// producer has no timing intent. Never a fabricated scanout time.
pub const SURFACE_TIME: usize = 72; // u64
pub const SURFACE_FLAGS: usize = 80; // u32
pub const SURFACE_LEN: usize = 88;

/// The lease is device-resident and can be imported without a CPU copy.
pub const SURFACE_ZERO_COPY: u32 = 1 << 0;
/// The bytes were read back to CPU-visible memory; the copy cost is real and
/// is reported rather than hidden.
pub const SURFACE_READBACK_COPY: u32 = 1 << 1;

// ── Encoding helpers ────────────────────────────────────────────────────
//
// Checked readers over a caller-owned payload slice. Every one answers
// `Option`, so a truncated or mis-shaped payload becomes a rejection at the
// decode site instead of a panic or a silently zero field.

#[must_use]
pub fn get_u8(p: &[u8], off: usize) -> Option<u8> {
    p.get(off).copied()
}

#[must_use]
pub fn get_u16(p: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let s = p.get(off..end)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

#[must_use]
pub fn get_u32(p: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let s = p.get(off..end)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

#[must_use]
pub fn get_u64(p: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let s = p.get(off..end)?;
    Some(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

pub fn put_u16(p: &mut [u8], off: usize, v: u16) {
    p[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

pub fn put_u32(p: &mut [u8], off: usize, v: u32) {
    p[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

pub fn put_u64(p: &mut [u8], off: usize, v: u64) {
    p[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Write a whole record (header + payload) into `out`, answering its length.
/// `None` when `out` is too small or `payload` exceeds [`MAX_PAYLOAD`] — a
/// caller that cannot fit a record must apply backpressure, never truncate.
#[must_use]
pub fn encode_record(out: &mut [u8], op: u16, corr: u64, payload: &[u8]) -> Option<usize> {
    if payload.len() > MAX_PAYLOAD as usize {
        return None;
    }
    let total = HEADER_LEN + payload.len();
    if out.len() < total {
        return None;
    }
    out[..HEADER_LEN].copy_from_slice(&Header::new(op, payload.len() as u32, corr).encode());
    out[HEADER_LEN..total].copy_from_slice(payload);
    Some(total)
}

/// Payload bytes of an [`OUT_REJECTED`] record: `[reason u16][_ u16][detail
/// u32]`. Named so a caller can size a stack buffer for the one outcome it
/// must always be able to emit.
pub const REJECT_PAYLOAD_LEN: usize = 8;

/// Encode an [`OUT_REJECTED`] record. The one outcome every decoder must be
/// able to emit, including from a state where nothing else is known.
#[must_use]
pub fn encode_reject(out: &mut [u8], corr: u64, reason: u16, detail: u32) -> Option<usize> {
    let mut payload = [0u8; REJECT_PAYLOAD_LEN];
    put_u16(&mut payload, 0, reason);
    put_u32(&mut payload, 4, detail);
    encode_record(out, OUT_REJECTED, corr, &payload)
}

/// Whether `op` is an allocated request operation.
#[must_use]
pub const fn is_known_op(op: u16) -> bool {
    matches!(
        op,
        OP_QUERY_CAPS
            | OP_CREATE_BUFFER
            | OP_CREATE_TEXTURE
            | OP_DESTROY_RESOURCE
            | OP_CREATE_VIEW
            | OP_RELEASE_VIEW
            | OP_SEAL_RESOURCE
            | OP_SET_RESIDENCY
            | OP_CREATE_SAMPLER
            | OP_LOAD_PROGRAM
            | OP_RELEASE_PROGRAM
            | OP_CREATE_PIPELINE
            | OP_RELEASE_PIPELINE
            | OP_UPLOAD
            | OP_READBACK
            | OP_SUBMIT
            | OP_POLL_FENCE
            | OP_RELEASE_FENCE
            | OP_CANCEL
            | OP_DRAIN
            | OP_RESET
            | OP_EXPORT_SURFACE
            | OP_RELEASE_SURFACE
    )
}

/// Whether `kind` is an allocated outcome record.
#[must_use]
pub const fn is_known_outcome(kind: u16) -> bool {
    matches!(
        kind,
        OUT_REJECTED
            | OUT_ACCEPTED
            | OUT_COMPLETED
            | OUT_FAILED
            | OUT_CANCELLED
            | OUT_DEVICE_LOST
            | OUT_CAPS
            | OUT_RESULT
            | OUT_HANDLE
            | OUT_SURFACE
    )
}

/// Whether an outcome kind ends a request's life. `OUT_ACCEPTED`,
/// `OUT_HANDLE`, `OUT_RESULT`, `OUT_CAPS` and `OUT_SURFACE` are progress
/// records; exactly one terminal outcome follows them.
#[must_use]
pub const fn is_terminal_outcome(kind: u16) -> bool {
    matches!(
        kind,
        OUT_REJECTED | OUT_COMPLETED | OUT_FAILED | OUT_CANCELLED | OUT_DEVICE_LOST
    )
}

// ── Request encoders ────────────────────────────────────────────────────
//
// The producer half of the contract. A consumer that had to lay these bytes
// out by hand would be reimplementing the payload layouts once per repo, and
// the first field anyone got wrong would look like a provider bug. They live
// here, beside the offsets the decoder reads, so the two cannot drift.
//
// Each answers the record length written, or `None` when `out` is too small —
// never a truncated record.

/// Scratch large enough for any fixed-shape request. Requests carrying bulk
/// bytes (upload, program chunks, submissions) are sized by their caller.
pub const MAX_FIXED_REQUEST: usize = HEADER_LEN + 64;

/// `OP_QUERY_CAPS` — no payload.
pub fn req_query_caps(out: &mut [u8], corr: u64) -> Option<usize> {
    encode_record(out, OP_QUERY_CAPS, corr, &[])
}

/// `OP_CREATE_BUFFER` — `[size u64][usage u32][rights u32][residency u8][pad u8×3]`.
pub fn req_create_buffer(
    out: &mut [u8],
    corr: u64,
    size: u64,
    usage: u32,
    rights: u32,
    residency: u8,
) -> Option<usize> {
    let mut p = [0u8; 20];
    put_u64(&mut p, 0, size);
    put_u32(&mut p, 8, usage);
    put_u32(&mut p, 12, rights);
    p[16] = residency;
    encode_record(out, OP_CREATE_BUFFER, corr, &p)
}

/// The six fields of an `OP_CREATE_TEXTURE` payload, in payload order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TextureSpec {
    pub width: u32,
    pub height: u32,
    pub layers: u32,
    pub format: u32,
    pub usage: u32,
    pub rights: u32,
}

/// `OP_CREATE_TEXTURE` —
/// `[width u32][height u32][layers u32][format u32][usage u32][rights u32]`.
pub fn req_create_texture(out: &mut [u8], corr: u64, spec: &TextureSpec) -> Option<usize> {
    let mut p = [0u8; 24];
    put_u32(&mut p, 0, spec.width);
    put_u32(&mut p, 4, spec.height);
    put_u32(&mut p, 8, spec.layers);
    put_u32(&mut p, 12, spec.format);
    put_u32(&mut p, 16, spec.usage);
    put_u32(&mut p, 20, spec.rights);
    encode_record(out, OP_CREATE_TEXTURE, corr, &p)
}

/// `OP_CREATE_SAMPLER` — `[filter u32][address u32][rights u32]`.
pub fn req_create_sampler(
    out: &mut [u8],
    corr: u64,
    filter: u32,
    address: u32,
    rights: u32,
) -> Option<usize> {
    let mut p = [0u8; 12];
    put_u32(&mut p, 0, filter);
    put_u32(&mut p, 4, address);
    put_u32(&mut p, 8, rights);
    encode_record(out, OP_CREATE_SAMPLER, corr, &p)
}

/// `OP_CREATE_VIEW` —
/// `[resource u64][offset u64][length u64][usage u32][rights u32]`.
pub fn req_create_view(
    out: &mut [u8],
    corr: u64,
    resource: u64,
    offset: u64,
    length: u64,
    usage: u32,
    rights: u32,
) -> Option<usize> {
    let mut p = [0u8; 32];
    put_u64(&mut p, 0, resource);
    put_u64(&mut p, 8, offset);
    put_u64(&mut p, 16, length);
    put_u32(&mut p, 24, usage);
    put_u32(&mut p, 28, rights);
    encode_record(out, OP_CREATE_VIEW, corr, &p)
}

/// Any op whose whole payload is one handle: destroy, release, seal, poll,
/// cancel. One encoder, because one shape.
pub fn req_handle_op(out: &mut [u8], corr: u64, op: u16, handle: u64) -> Option<usize> {
    let mut p = [0u8; 8];
    put_u64(&mut p, 0, handle);
    encode_record(out, op, corr, &p)
}

/// `OP_SET_RESIDENCY` — `[handle u64][state u8]`.
pub fn req_set_residency(out: &mut [u8], corr: u64, handle: u64, state: u8) -> Option<usize> {
    let mut p = [0u8; 12];
    put_u64(&mut p, 0, handle);
    p[8] = state;
    encode_record(out, OP_SET_RESIDENCY, corr, &p)
}

/// `OP_LOAD_PROGRAM` — `[program u64][chunk_offset u32][total_len u32][bytes…]`.
/// Pass [`HANDLE_NONE`] as `program` for the first chunk.
pub fn req_load_program(
    out: &mut [u8],
    corr: u64,
    program: u64,
    chunk_offset: u32,
    total_len: u32,
    bytes: &[u8],
) -> Option<usize> {
    let n = HEADER_LEN + 16 + bytes.len();
    if out.len() < n || 16 + bytes.len() > MAX_PAYLOAD as usize {
        return None;
    }
    out[..HEADER_LEN]
        .copy_from_slice(&Header::new(OP_LOAD_PROGRAM, (16 + bytes.len()) as u32, corr).encode());
    let p = &mut out[HEADER_LEN..n];
    put_u64(p, 0, program);
    put_u32(p, 8, chunk_offset);
    put_u32(p, 12, total_len);
    p[16..].copy_from_slice(bytes);
    Some(n)
}

// ── Raster pipeline state ───────────────────────────────────────────────
//
// The `[backend state…]` tail of `OP_CREATE_PIPELINE` for a `QUEUE_RASTER`
// pipeline. A compute pipeline carries no state and its tail is empty.
//
// Allocated here, in the contract, for the same reason the formats above are:
// state that each backend defined for itself would make the raster half
// unportable, and a consumer would need one encoding per provider to draw the
// same scene twice. Everything a draw needs that is not in the program pack
// or the submission is here, and nothing else is.
//
// ```text
//   [0..4]   colour_format  u32  FORMAT_* of the pass's colour attachment
//   [4..8]   depth_format   u32  FORMAT_* of its depth attachment, or NONE
//   [8..12]  vertex_stride  u32  bytes between consecutive vertices
//   [12]     topology       u8   TOPOLOGY_*
//   [13]     cull           u8   CULL_*
//   [14]     front_face     u8   FRONT_FACE_*
//   [15]     blend          u8   BLEND_*
//   [16]     depth_compare  u8   DEPTH_*
//   [17]     depth_write    u8   0 or 1
//   [18..20] attr_count     u16  vertex attributes that follow
//   [20..24] reserved       u32  must be zero
//   then attr_count × [location u16][format u16][offset u32]
// ```

/// Bytes of the fixed head of a raster pipeline state blob.
pub const RASTER_STATE_HEAD: usize = 24;
/// Bytes of one vertex attribute entry.
pub const RASTER_ATTR_LEN: usize = 8;
/// Most vertex attributes one pipeline may declare.
pub const MAX_VERTEX_ATTRS: usize = 16;

pub const TOPOLOGY_TRIANGLE_LIST: u8 = 1;
pub const TOPOLOGY_TRIANGLE_STRIP: u8 = 2;
pub const TOPOLOGY_LINE_LIST: u8 = 3;
pub const TOPOLOGY_POINT_LIST: u8 = 4;

pub const CULL_NONE: u8 = 0;
pub const CULL_BACK: u8 = 1;
pub const CULL_FRONT: u8 = 2;

/// Counter-clockwise winding seen from outside is the front face.
pub const FRONT_FACE_CCW: u8 = 0;
pub const FRONT_FACE_CW: u8 = 1;

/// Source replaces destination; no blending.
pub const BLEND_REPLACE: u8 = 0;
/// Straight (non-premultiplied) source-alpha over destination.
pub const BLEND_ALPHA: u8 = 1;

/// Depth test always passes. With `depth_write` clear this is "no depth".
pub const DEPTH_ALWAYS: u8 = 0;
pub const DEPTH_LESS: u8 = 1;
pub const DEPTH_LESS_EQUAL: u8 = 2;
pub const DEPTH_GREATER: u8 = 3;

/// Vertex attribute component formats.
pub const VATTR_F32: u16 = 1;
pub const VATTR_F32X2: u16 = 2;
pub const VATTR_F32X3: u16 = 3;
pub const VATTR_F32X4: u16 = 4;
pub const VATTR_U32: u16 = 5;
pub const VATTR_U32X2: u16 = 6;
pub const VATTR_U32X4: u16 = 7;
/// Four unsigned bytes, normalised to 0.0..=1.0.
pub const VATTR_U8X4_UNORM: u16 = 8;

/// Bytes one attribute of `format` occupies, or `None` for an unallocated id.
#[must_use]
pub const fn vattr_bytes(format: u16) -> Option<u32> {
    match format {
        VATTR_F32 | VATTR_U32 | VATTR_U8X4_UNORM => Some(4),
        VATTR_F32X2 | VATTR_U32X2 => Some(8),
        VATTR_F32X3 => Some(12),
        VATTR_F32X4 | VATTR_U32X4 => Some(16),
        _ => None,
    }
}

/// One vertex attribute: where the shader reads it, how it is encoded, and
/// where it sits inside a vertex.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VertexAttr {
    /// The shader's `@location`.
    pub location: u16,
    /// `VATTR_*`.
    pub format: u16,
    /// Byte offset from the start of the vertex.
    pub offset: u32,
}

/// Everything a raster pipeline needs that the program pack and the
/// submission do not carry.
#[derive(Clone, Copy, Debug)]
pub struct RasterState {
    pub colour_format: u32,
    /// `FORMAT_NONE` for a pass with no depth attachment.
    pub depth_format: u32,
    pub vertex_stride: u32,
    pub topology: u8,
    pub cull: u8,
    pub front_face: u8,
    pub blend: u8,
    pub depth_compare: u8,
    pub depth_write: bool,
    pub attr_count: u16,
    pub attrs: [VertexAttr; MAX_VERTEX_ATTRS],
}

impl Default for RasterState {
    fn default() -> Self {
        Self {
            colour_format: FORMAT_RGBA8_UNORM,
            depth_format: FORMAT_NONE,
            vertex_stride: 0,
            topology: TOPOLOGY_TRIANGLE_LIST,
            cull: CULL_NONE,
            front_face: FRONT_FACE_CCW,
            blend: BLEND_REPLACE,
            depth_compare: DEPTH_ALWAYS,
            depth_write: false,
            attr_count: 0,
            attrs: [VertexAttr {
                location: 0,
                format: 0,
                offset: 0,
            }; MAX_VERTEX_ATTRS],
        }
    }
}

impl RasterState {
    /// The attributes actually declared.
    #[must_use]
    pub fn attrs(&self) -> &[VertexAttr] {
        &self.attrs[..(self.attr_count as usize).min(MAX_VERTEX_ATTRS)]
    }

    /// Encoded length of this state.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        RASTER_STATE_HEAD + self.attrs().len() * RASTER_ATTR_LEN
    }

    /// Write the state into `out`, answering its length, or `None` when `out`
    /// is too small — never a truncated blob.
    pub fn encode(&self, out: &mut [u8]) -> Option<usize> {
        let n = self.encoded_len();
        if out.len() < n {
            return None;
        }
        let p = &mut out[..n];
        p.fill(0);
        put_u32(p, 0, self.colour_format);
        put_u32(p, 4, self.depth_format);
        put_u32(p, 8, self.vertex_stride);
        p[12] = self.topology;
        p[13] = self.cull;
        p[14] = self.front_face;
        p[15] = self.blend;
        p[16] = self.depth_compare;
        p[17] = u8::from(self.depth_write);
        put_u16(p, 18, self.attrs().len() as u16);
        for (i, a) in self.attrs().iter().enumerate() {
            let at = RASTER_STATE_HEAD + i * RASTER_ATTR_LEN;
            put_u16(p, at, a.location);
            put_u16(p, at + 2, a.format);
            put_u32(p, at + 4, a.offset);
        }
        Some(n)
    }

    /// Decode a state blob, validating every field against what this contract
    /// allocates.
    ///
    /// A provider that decoded leniently would accept a pipeline it cannot
    /// build and fail later at draw time, where the caller has already been
    /// told its pipeline is ready. Everything checkable is checked here.
    pub fn decode(p: &[u8]) -> Result<Self, u16> {
        if p.len() < RASTER_STATE_HEAD {
            return Err(REASON_MALFORMED);
        }
        let colour_format = get_u32(p, 0).ok_or(REASON_MALFORMED)?;
        let depth_format = get_u32(p, 4).ok_or(REASON_MALFORMED)?;
        let vertex_stride = get_u32(p, 8).ok_or(REASON_MALFORMED)?;
        let topology = p[12];
        let cull = p[13];
        let front_face = p[14];
        let blend = p[15];
        let depth_compare = p[16];
        let depth_write = p[17];
        let attr_count = get_u16(p, 18).ok_or(REASON_MALFORMED)?;
        if get_u32(p, 20) != Some(0) {
            return Err(REASON_MALFORMED);
        }
        if format_texel_bytes(colour_format).is_none() || format_is_depth(colour_format) {
            return Err(REASON_UNSUPPORTED_FEATURE);
        }
        if depth_format != FORMAT_NONE && !format_is_depth(depth_format) {
            return Err(REASON_UNSUPPORTED_FEATURE);
        }
        if !matches!(
            topology,
            TOPOLOGY_TRIANGLE_LIST | TOPOLOGY_TRIANGLE_STRIP | TOPOLOGY_LINE_LIST
                | TOPOLOGY_POINT_LIST
        ) || !matches!(cull, CULL_NONE | CULL_BACK | CULL_FRONT)
            || !matches!(front_face, FRONT_FACE_CCW | FRONT_FACE_CW)
            || !matches!(blend, BLEND_REPLACE | BLEND_ALPHA)
            || !matches!(
                depth_compare,
                DEPTH_ALWAYS | DEPTH_LESS | DEPTH_LESS_EQUAL | DEPTH_GREATER
            )
            || depth_write > 1
        {
            return Err(REASON_MALFORMED);
        }
        // Depth state that names no attachment cannot be honoured, and a
        // pipeline whose depth test silently did nothing is worse than one
        // that was refused.
        if depth_format == FORMAT_NONE && (depth_write == 1 || depth_compare != DEPTH_ALWAYS) {
            return Err(REASON_MALFORMED);
        }
        if attr_count as usize > MAX_VERTEX_ATTRS {
            return Err(REASON_OVERSIZE);
        }
        let want = RASTER_STATE_HEAD + attr_count as usize * RASTER_ATTR_LEN;
        if p.len() < want {
            return Err(REASON_MALFORMED);
        }
        let mut st = Self {
            colour_format,
            depth_format,
            vertex_stride,
            topology,
            cull,
            front_face,
            blend,
            depth_compare,
            depth_write: depth_write == 1,
            attr_count,
            ..Self::default()
        };
        for i in 0..attr_count as usize {
            let at = RASTER_STATE_HEAD + i * RASTER_ATTR_LEN;
            let location = get_u16(p, at).ok_or(REASON_MALFORMED)?;
            let format = get_u16(p, at + 2).ok_or(REASON_MALFORMED)?;
            let offset = get_u32(p, at + 4).ok_or(REASON_MALFORMED)?;
            let width = vattr_bytes(format).ok_or(REASON_UNSUPPORTED_FEATURE)?;
            // An attribute that runs past the stride reads the next vertex.
            // The device would not fault; it would draw the wrong thing.
            if offset.checked_add(width).is_none_or(|end| end > vertex_stride) {
                return Err(REASON_BAD_RANGE);
            }
            if st.attrs()[..i].iter().any(|a| a.location == location) {
                return Err(REASON_MALFORMED);
            }
            st.attrs[i] = VertexAttr {
                location,
                format,
                offset,
            };
        }
        Ok(st)
    }
}

/// `OP_CREATE_PIPELINE` —
/// `[program u64][kind u8][pad u8×3][state_len u32][backend state…]`.
pub fn req_create_pipeline(
    out: &mut [u8],
    corr: u64,
    program: u64,
    kind: u8,
    state: &[u8],
) -> Option<usize> {
    let n = HEADER_LEN + 16 + state.len();
    if out.len() < n || 16 + state.len() > MAX_PAYLOAD as usize {
        return None;
    }
    out[..HEADER_LEN].copy_from_slice(
        &Header::new(OP_CREATE_PIPELINE, (16 + state.len()) as u32, corr).encode(),
    );
    let p = &mut out[HEADER_LEN..n];
    put_u64(p, 0, program);
    p[8] = kind;
    // Padding is written, not left as whatever the caller's buffer held. The
    // same request must encode to the same bytes every time, or a record can
    // neither be compared nor attested.
    p[9..12].fill(0);
    put_u32(p, 12, state.len() as u32);
    p[16..].copy_from_slice(state);
    Some(n)
}

/// `OP_UPLOAD` — `[view u64][offset u64][byte_len u32][pad u32][bytes…]`.
pub fn req_upload(
    out: &mut [u8],
    corr: u64,
    view: u64,
    offset: u64,
    bytes: &[u8],
) -> Option<usize> {
    let n = HEADER_LEN + 24 + bytes.len();
    if out.len() < n || 24 + bytes.len() > MAX_PAYLOAD as usize {
        return None;
    }
    out[..HEADER_LEN]
        .copy_from_slice(&Header::new(OP_UPLOAD, (24 + bytes.len()) as u32, corr).encode());
    let p = &mut out[HEADER_LEN..n];
    put_u64(p, 0, view);
    put_u64(p, 8, offset);
    put_u32(p, 16, bytes.len() as u32);
    // As above: the declared padding is part of the record, so it is written.
    p[20..24].fill(0);
    p[24..].copy_from_slice(bytes);
    Some(n)
}

/// `OP_READBACK` — `[view u64][offset u64][byte_len u32][pad u32]`.
pub fn req_readback(
    out: &mut [u8],
    corr: u64,
    view: u64,
    offset: u64,
    byte_len: u32,
) -> Option<usize> {
    let mut p = [0u8; 24];
    put_u64(&mut p, 0, view);
    put_u64(&mut p, 8, offset);
    put_u32(&mut p, 16, byte_len);
    encode_record(out, OP_READBACK, corr, &p)
}

/// `OP_SUBMIT` —
/// `[queue u8][wait_count u8][flags u16][item_len u32][waits u64×n][items…]`.
pub fn req_submit(
    out: &mut [u8],
    corr: u64,
    queue: u8,
    waits: &[u64],
    items: &[u8],
) -> Option<usize> {
    let body = 8 + waits.len() * 8 + items.len();
    let n = HEADER_LEN + body;
    if out.len() < n || body > MAX_PAYLOAD as usize || waits.len() > u8::MAX as usize {
        return None;
    }
    out[..HEADER_LEN].copy_from_slice(&Header::new(OP_SUBMIT, body as u32, corr).encode());
    let p = &mut out[HEADER_LEN..n];
    // Every byte of the fixed head is written, reserved fields included.
    // `out` is the caller's buffer and is routinely reused, so a field left
    // alone is not zero — it is the previous request's bytes, put on the
    // wire and read as meaning by the first reader that consults it.
    p[0] = queue;
    p[1] = waits.len() as u8;
    put_u16(p, 2, 0);
    put_u32(p, 4, items.len() as u32);
    for (i, w) in waits.iter().enumerate() {
        put_u64(p, 8 + i * 8, *w);
    }
    p[8 + waits.len() * 8..].copy_from_slice(items);
    Some(n)
}

/// `OP_DRAIN` — no payload.
pub fn req_drain(out: &mut [u8], corr: u64) -> Option<usize> {
    encode_record(out, OP_DRAIN, corr, &[])
}

/// `OP_RESET` — `[scope u8][pad u8×3]`.
pub fn req_reset(out: &mut [u8], corr: u64, scope: u8) -> Option<usize> {
    let mut p = [0u8; 4];
    p[0] = scope;
    encode_record(out, OP_RESET, corr, &p)
}

/// `OP_EXPORT_SURFACE` —
/// `[view u64][width u32][height u32][format u32][colour_space u32]`.
pub fn req_export_surface(
    out: &mut [u8],
    corr: u64,
    view: u64,
    width: u32,
    height: u32,
    format: u32,
    colour_space: u32,
) -> Option<usize> {
    let mut p = [0u8; 24];
    put_u64(&mut p, 0, view);
    put_u32(&mut p, 8, width);
    put_u32(&mut p, 12, height);
    put_u32(&mut p, 16, format);
    put_u32(&mut p, 20, colour_space);
    encode_record(out, OP_EXPORT_SURFACE, corr, &p)
}

// ── Submission item encoders ────────────────────────────────────────────
//
// Items are appended to a caller-owned list buffer, so a frame with many
// primitives is one submission carrying data rather than many calls. Each
// answers the bytes written.

/// `[slot u16][pad u16][view u64]`.
pub fn item_binding(out: &mut [u8], slot: u16, view: u64) -> Option<usize> {
    if out.len() < BIND_ENTRY_LEN {
        return None;
    }
    put_u16(out, 0, slot);
    put_u16(out, 2, 0);
    put_u64(out, 4, view);
    Some(BIND_ENTRY_LEN)
}

/// `[0x01][pipeline u64][bind_count u16][pad u16][bindings…][gx][gy][gz]`.
pub fn item_dispatch(
    out: &mut [u8],
    pipeline: u64,
    bindings: &[(u16, u64)],
    groups: [u32; 3],
) -> Option<usize> {
    let n = 13 + bindings.len() * BIND_ENTRY_LEN + 12;
    if out.len() < n || bindings.len() > u16::MAX as usize {
        return None;
    }
    out[0] = ITEM_DISPATCH;
    put_u64(out, 1, pipeline);
    put_u16(out, 9, bindings.len() as u16);
    put_u16(out, 11, 0);
    let mut off = 13;
    for (slot, view) in bindings {
        item_binding(&mut out[off..], *slot, *view)?;
        off += BIND_ENTRY_LEN;
    }
    put_u32(out, off, groups[0]);
    put_u32(out, off + 4, groups[1]);
    put_u32(out, off + 8, groups[2]);
    Some(n)
}

/// `[0x02][src u64][dst u64][len u64]`.
pub fn item_copy(out: &mut [u8], src: u64, dst: u64, len: u64) -> Option<usize> {
    if out.len() < 25 {
        return None;
    }
    out[0] = ITEM_COPY;
    put_u64(out, 1, src);
    put_u64(out, 9, dst);
    put_u64(out, 17, len);
    Some(25)
}

/// `[0x03][target u64][flags u32][clear u32]`.
pub fn item_begin_pass(out: &mut [u8], target: u64, flags: u32, clear: u32) -> Option<usize> {
    if out.len() < 17 {
        return None;
    }
    out[0] = ITEM_BEGIN_PASS;
    put_u64(out, 1, target);
    put_u32(out, 9, flags);
    put_u32(out, 13, clear);
    Some(17)
}

/// `[0x04][pipeline u64][bind_count u16][pad u16][bindings…]`
/// `[vertex u64][index u64][first u32][count u32][instances u32]`.
#[allow(
    clippy::too_many_arguments,
    reason = "a draw call's parameters are the draw call; grouping them into a \
              struct would add a type whose only job is to be destructured here"
)]
pub fn item_draw(
    out: &mut [u8],
    pipeline: u64,
    bindings: &[(u16, u64)],
    vertex: u64,
    index: u64,
    first: u32,
    count: u32,
    instances: u32,
) -> Option<usize> {
    let n = 13 + bindings.len() * BIND_ENTRY_LEN + 28;
    if out.len() < n || bindings.len() > u16::MAX as usize {
        return None;
    }
    out[0] = ITEM_DRAW;
    put_u64(out, 1, pipeline);
    put_u16(out, 9, bindings.len() as u16);
    put_u16(out, 11, 0);
    let mut off = 13;
    for (slot, view) in bindings {
        item_binding(&mut out[off..], *slot, *view)?;
        off += BIND_ENTRY_LEN;
    }
    put_u64(out, off, vertex);
    put_u64(out, off + 8, index);
    put_u32(out, off + 16, first);
    put_u32(out, off + 20, count);
    put_u32(out, off + 24, instances);
    Some(n)
}

/// `[0x05]` — end the open render pass.
pub fn item_end_pass(out: &mut [u8]) -> Option<usize> {
    if out.is_empty() {
        return None;
    }
    out[0] = ITEM_END_PASS;
    Some(1)
}

// ── Outcome decoding ────────────────────────────────────────────────────

/// A decoded outcome record, as a consumer sees it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome<'a> {
    Rejected {
        corr: u64,
        reason: u16,
        detail: u32,
    },
    Accepted {
        corr: u64,
        fence: u64,
    },
    Handle {
        corr: u64,
        handle: u64,
    },
    Completed {
        corr: u64,
        fence: u64,
        flags: u32,
        gpu_nanos: u64,
    },
    Failed {
        corr: u64,
        fence: u64,
        reason: u16,
        detail: u32,
    },
    Cancelled {
        corr: u64,
        fence: u64,
        disposition: u8,
    },
    DeviceLost {
        corr: u64,
        old_epoch: u32,
        new_epoch: u32,
        reason: u16,
        blast: u32,
    },
    Caps {
        corr: u64,
        caps: &'a [u8],
    },
    Result {
        corr: u64,
        fence: u64,
        offset: u64,
        bytes: &'a [u8],
    },
    Surface {
        corr: u64,
        descriptor: &'a [u8],
    },
}

/// Decode one outcome record from the front of `bytes`.
///
/// `Ok(None)` means the record has not fully arrived. `Err` carries the
/// reason a consumer should treat the stream as broken.
pub fn decode_outcome(bytes: &[u8]) -> Result<Option<(Outcome<'_>, usize)>, u16> {
    let Some(h) = Header::decode(bytes)? else {
        return Ok(None);
    };
    let total = h.total_len();
    if bytes.len() < total {
        return Ok(None);
    }
    let p = &bytes[HEADER_LEN..total];
    let corr = h.corr;
    let out = match h.op {
        OUT_REJECTED => Outcome::Rejected {
            corr,
            reason: get_u16(p, 0).ok_or(REASON_MALFORMED)?,
            detail: get_u32(p, 4).ok_or(REASON_MALFORMED)?,
        },
        OUT_ACCEPTED => Outcome::Accepted {
            corr,
            fence: get_u64(p, 0).ok_or(REASON_MALFORMED)?,
        },
        OUT_HANDLE => Outcome::Handle {
            corr,
            handle: get_u64(p, 0).ok_or(REASON_MALFORMED)?,
        },
        OUT_COMPLETED => Outcome::Completed {
            corr,
            fence: get_u64(p, 0).ok_or(REASON_MALFORMED)?,
            flags: get_u32(p, 8).ok_or(REASON_MALFORMED)?,
            gpu_nanos: get_u64(p, 16).ok_or(REASON_MALFORMED)?,
        },
        OUT_FAILED => Outcome::Failed {
            corr,
            fence: get_u64(p, 0).ok_or(REASON_MALFORMED)?,
            reason: get_u16(p, 8).ok_or(REASON_MALFORMED)?,
            detail: get_u32(p, 12).ok_or(REASON_MALFORMED)?,
        },
        OUT_CANCELLED => Outcome::Cancelled {
            corr,
            fence: get_u64(p, 0).ok_or(REASON_MALFORMED)?,
            disposition: get_u8(p, 8).ok_or(REASON_MALFORMED)?,
        },
        OUT_DEVICE_LOST => Outcome::DeviceLost {
            corr,
            old_epoch: get_u32(p, 0).ok_or(REASON_MALFORMED)?,
            new_epoch: get_u32(p, 4).ok_or(REASON_MALFORMED)?,
            reason: get_u16(p, 8).ok_or(REASON_MALFORMED)?,
            blast: get_u32(p, 12).ok_or(REASON_MALFORMED)?,
        },
        OUT_CAPS => {
            if p.len() < CAPS_LEN {
                return Err(REASON_MALFORMED);
            }
            Outcome::Caps { corr, caps: p }
        }
        OUT_SURFACE => {
            if p.len() < SURFACE_LEN {
                return Err(REASON_MALFORMED);
            }
            Outcome::Surface {
                corr,
                descriptor: p,
            }
        }
        OUT_RESULT => {
            let len = get_u32(p, 16).ok_or(REASON_MALFORMED)? as usize;
            let bytes = p.get(24..24 + len).ok_or(REASON_MALFORMED)?;
            Outcome::Result {
                corr,
                fence: get_u64(p, 0).ok_or(REASON_MALFORMED)?,
                offset: get_u64(p, 8).ok_or(REASON_MALFORMED)?,
                bytes,
            }
        }
        _ => return Err(REASON_UNKNOWN_OP),
    };
    Ok(Some((out, total)))
}
