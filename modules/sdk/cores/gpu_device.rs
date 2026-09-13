// gpu_device_core — the portable half of a GPU provider.
//
// Every GPU backend has two halves. One owns OS or browser objects: adapters,
// queues, command encoders, shader modules, mapped memory. The other decides
// whether a request is allowed at all, what a handle means, when an output
// becomes observable, what a fence is worth and what a failure did to the
// caller's data. The second half is identical on WebGPU, on native
// wgpu/Vulkan, on a direct V3D driver and on a provider with no hardware — so
// it lives here, once, and every backend gets the same answers.
//
// That split is the point. The rules that are easy to get subtly wrong —
// stale handles from a dead epoch, a destroy racing work in flight, a
// candidate output published after a failure, a result dropped under
// backpressure and mistaken for work that never ran — are exactly the rules
// that are cheapest to test with no GPU present and most expensive to debug
// with one.
//
// Pure logic over caller-owned slices: no allocation, no clock, no syscall,
// no I/O. The caller supplies the tables, supplies the bytes, and executes the
// [`Work`] this core hands back. `no_std`.
//
// Mount alongside `sdk/wire/gpu_wire.rs`, `sdk/cores/gpu_pack.rs` and
// `sdk/crypto/sha256.rs`; this core reads their items from the flat namespace
// the `include!` chain produces.
//
// ## The admission rule
//
// Nothing observable changes until a request is fully validated. `admit`
// decodes, resolves every handle, checks every range, alignment, usage,
// right, residency and budget, and reserves queue, fence and outcome-ring
// capacity — and only then allocates anything. A rejection therefore leaves
// the caller's resources bit-identical, which is what makes "rejection is
// safe to retry" true rather than hopeful.
//
// ## Why dependency cycles cannot arise
//
// A submission may only wait on fences that are already live, and its own
// fence is allocated after its waits are validated. The wait graph is
// therefore a DAG by construction, not by a cycle detector that has to be
// right. `REASON_DEPENDENCY_CYCLE` stays allocated in the wire contract for a
// provider that later hands out fence names before their work exists; this
// core cannot reach it, and a test asserts the structural property instead of
// pretending to exercise a detector.

// ── Capacities ──────────────────────────────────────────────────────────
//
// Fixed per-slot array bounds. These are R2 identifier-width ceilings, not
// memory budgets: they bound the core's own work per request so a step's cost
// is knowable, and the caller sizes the tables themselves.

/// Waits one submission may declare.
pub const MAX_WAITS: usize = 8;
/// Resources one accepted request may hold references on. Bounds both the
/// retain/release bookkeeping and the candidate-publication list.
pub const MAX_FENCE_REFS: usize = 16;
/// Bindings a loaded program may declare. Copied out of the pack at load so
/// the program stays self-describing after the producer's bytes are gone.
pub const MAX_PROGRAM_BINDINGS: usize = 16;

/// "No slot". Never a valid table index because a table larger than this
/// would exceed the handle's 16-bit index field anyway.
pub const NO_SLOT: u16 = u16::MAX;

// ── Fence lifecycle ─────────────────────────────────────────────────────

/// Slot is unallocated.
pub const FENCE_FREE: u8 = 0;
/// Admitted; at least one wait has not completed.
pub const FENCE_WAITING: u8 = 1;
/// Dependencies met; not yet handed to the backend.
pub const FENCE_READY: u8 = 2;
/// Handed to the backend and physically in flight.
pub const FENCE_RUNNING: u8 = 3;
/// Outcome decided. Retained — with its result bytes — until the consumer
/// acknowledges it with `OP_RELEASE_FENCE`.
pub const FENCE_TERMINAL: u8 = 4;

// ── Tables ──────────────────────────────────────────────────────────────

/// A buffer, texture or sampler. One table, because compute and raster share
/// one resource service; the `kind` field is what keeps a sampler from being
/// dispatched as a storage buffer.
#[derive(Clone, Copy, Debug)]
pub struct ResourceSlot {
    pub generation: u16,
    pub kind: u8,
    pub residency: u8,
    pub live: bool,
    /// Handle retired but storage still held because work in flight can
    /// reach it. Freed at quiescence, never at the retirement request.
    pub retiring: bool,
    pub sealed: bool,
    /// A candidate output that has completed and been committed. Until this
    /// is set, the contents are not a valid output and cannot be read.
    pub published: bool,
    pub usage: u32,
    pub rights: u32,
    pub owner: u16,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    pub format: u32,
    /// Accepted-but-not-terminal requests that can reach this resource.
    pub in_flight: u16,
}

impl ResourceSlot {
    pub const EMPTY: Self = Self {
        generation: 0,
        kind: 0,
        residency: 0,
        live: false,
        retiring: false,
        sealed: false,
        published: false,
        usage: 0,
        rights: 0,
        owner: 0,
        size: 0,
        width: 0,
        height: 0,
        format: 0,
        in_flight: 0,
    };
}

/// A bounded, aligned subrange of a resource with its own rights.
///
/// A view is the unit of binding, transfer and lease — never the resource
/// itself. That is what makes "narrow this grant" expressible: a lease is a
/// view with fewer rights over the same bytes, and revoking it retires one
/// view rather than the resource everything else is using.
#[derive(Clone, Copy, Debug)]
pub struct ViewSlot {
    pub generation: u16,
    pub live: bool,
    pub resource: u16,
    pub resource_gen: u16,
    pub offset: u64,
    pub length: u64,
    pub usage: u32,
    pub rights: u32,
    pub owner: u16,
}

impl ViewSlot {
    pub const EMPTY: Self = Self {
        generation: 0,
        live: false,
        resource: NO_SLOT,
        resource_gen: 0,
        offset: 0,
        length: 0,
        usage: 0,
        rights: 0,
        owner: 0,
    };
}

/// A loaded program pack. The binding table is copied in at load so the
/// program keeps describing itself after the producer's buffer is reused.
#[derive(Clone, Copy, Debug)]
pub struct ProgramSlot {
    pub generation: u16,
    pub live: bool,
    /// The whole pack arrived and passed validation. Until this is set the
    /// slot names a load in progress, and no pipeline can be built from it —
    /// a partially received artifact has no digest anyone has checked.
    pub ready: bool,
    pub owner: u16,
    pub target_isa: u32,
    pub target_rev: u32,
    pub workgroup: [u32; 3],
    pub binding_count: u8,
    pub bindings: [PackBinding; MAX_PROGRAM_BINDINGS],
    /// Full-manifest identity — the pipeline-cache key.
    pub identity: [u8; 32],
    pub artifact_len: u32,
    /// Bytes of a chunked pack received so far; the load fence completes only
    /// when this reaches the declared total.
    pub received: u32,
    pub declared: u32,
}

impl ProgramSlot {
    pub const EMPTY: Self = Self {
        generation: 0,
        live: false,
        ready: false,
        owner: 0,
        target_isa: 0,
        target_rev: 0,
        workgroup: [0; 3],
        binding_count: 0,
        bindings: [PackBinding {
            slot: 0,
            kind: 0,
            access: 0,
            min_size: 0,
            align: 0,
        }; MAX_PROGRAM_BINDINGS],
        identity: [0u8; 32],
        artifact_len: 0,
        received: 0,
        declared: 0,
    };
}

/// A pipeline built from a program. Readiness is explicit: a dispatch against
/// a pipeline whose compilation has not completed is refused with
/// `REASON_NOT_READY`, never skipped and reported as success.
#[derive(Clone, Copy, Debug)]
pub struct PipelineSlot {
    pub generation: u16,
    pub live: bool,
    pub owner: u16,
    pub program: u16,
    pub program_gen: u16,
    pub kind: u8,
    pub ready: bool,
    /// Fence whose completion makes this pipeline ready.
    pub build_fence: u16,
}

impl PipelineSlot {
    pub const EMPTY: Self = Self {
        generation: 0,
        live: false,
        owner: 0,
        program: NO_SLOT,
        program_gen: 0,
        kind: 0,
        ready: false,
        build_fence: NO_SLOT,
    };
}

/// One accepted request's completion record.
#[derive(Clone, Copy, Debug)]
pub struct FenceSlot {
    pub generation: u16,
    pub state: u8,
    pub owner: u16,
    pub queue: u8,
    /// The op that produced this fence — read by drain and by diagnostics.
    pub op: u16,
    pub corr: u64,
    /// Terminal outcome kind, once `state == FENCE_TERMINAL`.
    pub outcome: u16,
    pub reason: u16,
    pub detail: u32,
    pub disposition: u8,
    pub gpu_nanos: u64,
    /// Whether the terminal record has been written to the outcome ring. The
    /// slot is not reusable until it has been, and until the consumer acks.
    pub delivered: bool,
    pub cancel_requested: bool,
    pub waits: [u16; MAX_WAITS],
    pub wait_gens: [u16; MAX_WAITS],
    pub wait_count: u8,
    /// Resources this request holds a reference on, released at terminal.
    pub refs: [u16; MAX_FENCE_REFS],
    pub ref_gens: [u16; MAX_FENCE_REFS],
    pub ref_count: u8,
    /// Candidate outputs published on success and left unpublished on any
    /// other outcome. A subset of `refs`.
    pub candidates: [u16; MAX_FENCE_REFS],
    pub candidate_count: u8,
    /// Readback bytes owed to the consumer, and how many have been sent. The
    /// fence stays non-terminal until they are all delivered, so a full
    /// output ring stalls rather than loses bytes.
    pub result_len: u64,
    pub result_sent: u64,
    /// Staging bytes reserved for this request, returned at terminal.
    pub staging_bytes: u64,
    /// Outcome-ring bytes reserved at admission, released as records are
    /// written. Reserving up front is what makes "results are never dropped"
    /// enforceable rather than aspirational.
    pub ring_reserved: u32,
}

impl FenceSlot {
    pub const EMPTY: Self = Self {
        generation: 0,
        state: FENCE_FREE,
        owner: 0,
        queue: 0,
        op: 0,
        corr: 0,
        outcome: 0,
        reason: 0,
        detail: 0,
        disposition: 0,
        gpu_nanos: 0,
        delivered: false,
        cancel_requested: false,
        waits: [NO_SLOT; MAX_WAITS],
        wait_gens: [0; MAX_WAITS],
        wait_count: 0,
        refs: [NO_SLOT; MAX_FENCE_REFS],
        ref_gens: [0; MAX_FENCE_REFS],
        ref_count: 0,
        candidates: [NO_SLOT; MAX_FENCE_REFS],
        candidate_count: 0,
        result_len: 0,
        result_sent: 0,
        staging_bytes: 0,
        ring_reserved: 0,
    };
}

/// A presentable surface lease over a view.
#[derive(Clone, Copy, Debug)]
pub struct SurfaceSlot {
    pub generation: u16,
    pub live: bool,
    pub owner: u16,
    pub view: u16,
    pub view_gen: u16,
    pub producer_fence: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: u32,
    pub colour_space: u32,
    pub sequence: u32,
    pub flags: u32,
}

impl SurfaceSlot {
    pub const EMPTY: Self = Self {
        generation: 0,
        live: false,
        owner: 0,
        view: NO_SLOT,
        view_gen: 0,
        producer_fence: 0,
        width: 0,
        height: 0,
        stride: 0,
        format: 0,
        colour_space: 0,
        sequence: 0,
        flags: 0,
    };
}

// ── Device facts ────────────────────────────────────────────────────────

/// The numeric facts a provider advertises and this core enforces.
///
/// Four classes, kept apart because they bind for different reasons and a
/// single `MAX_GPU_*` number would hide which one a workload actually hit:
/// R1 is memory bytes, R2 is identifier and table widths, R3 is what the
/// hardware can do, and rate/deadline budgets (R4) belong to the caller's
/// step budget rather than to a ledger this core keeps.
#[derive(Clone, Copy, Debug)]
pub struct DeviceLimits {
    pub features: u32,
    pub arith_ops: u32,
    pub arith_types: [u8; ARITH_TYPE_COUNT],
    /// Accepted program-pack targets and the minimum revision of each.
    pub targets: [u32; CAPS_TARGET_SLOTS],
    pub target_min_rev: [u32; CAPS_TARGET_SLOTS],
    // R3 — hardware.
    pub max_bindings: u32,
    pub min_align: u32,
    pub max_workgroup: [u32; 3],
    pub max_workgroup_invocations: u32,
    pub max_grid: [u32; 3],
    pub max_alloc_bytes: u64,
    // R1 — memory.
    pub max_resident_bytes: u64,
    pub max_staging_bytes: u64,
    pub max_scratch_bytes: u64,
    // R2 — widths.
    pub max_queue_depth: u16,
}

impl DeviceLimits {
    /// A conservative baseline: compute and readback only, F32/I32/U32
    /// arithmetic, 64-byte alignment, modest ceilings.
    ///
    /// Deliberately not a union of what some backend might manage. A provider
    /// starts here and widens each fact it has actually demonstrated, so an
    /// unset field can only ever under-promise.
    #[must_use]
    pub const fn baseline() -> Self {
        let mut arith = [0u8; ARITH_TYPE_COUNT];
        let native = ARITH_STORAGE | ARITH_COMPUTE | ARITH_ACCUM | ARITH_NATIVE;
        arith[ARITH_I32] = native;
        arith[ARITH_U32] = native;
        arith[ARITH_F32] = native;
        // Byte and half-word types are storable in a buffer everywhere; that
        // says nothing about arithmetic, and this table is the one place the
        // difference is recorded rather than assumed.
        arith[ARITH_I8] = ARITH_STORAGE;
        arith[ARITH_U8] = ARITH_STORAGE;
        arith[ARITH_I16] = ARITH_STORAGE;
        arith[ARITH_U16] = ARITH_STORAGE;
        Self {
            features: FEATURE_COMPUTE | FEATURE_READBACK,
            arith_ops: AOP_FMA_F32,
            arith_types: arith,
            targets: [TARGET_NONE; CAPS_TARGET_SLOTS],
            target_min_rev: [0; CAPS_TARGET_SLOTS],
            max_bindings: MAX_PROGRAM_BINDINGS as u32,
            min_align: 64,
            max_workgroup: [256, 256, 64],
            max_workgroup_invocations: 256,
            max_grid: [65535, 65535, 65535],
            max_alloc_bytes: 64 * 1024 * 1024,
            max_resident_bytes: 256 * 1024 * 1024,
            max_staging_bytes: 8 * 1024 * 1024,
            max_scratch_bytes: 16 * 1024 * 1024,
            max_queue_depth: 64,
        }
    }

    /// The pack validator's view of these facts.
    #[must_use]
    pub fn pack_limits(&self) -> PackLimits {
        PackLimits {
            targets: self.targets,
            target_min_rev: self.target_min_rev,
            features: self.features,
            arith_ops: self.arith_ops,
            arith_types: self.arith_types,
            max_bindings: self.max_bindings,
            min_align: self.min_align,
            max_workgroup: self.max_workgroup,
            max_workgroup_invocations: self.max_workgroup_invocations,
            max_resident_bytes: self.max_resident_bytes,
            max_scratch_bytes: self.max_scratch_bytes,
        }
    }
}

/// Counters and high-water marks. Reported through the ordinary telemetry
/// surface by the provider that owns this core — this file records the facts
/// and emits nothing itself, so one core serves a module with a metric ring
/// and a host test with neither.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeviceStats {
    pub admitted: u64,
    pub rejected: u64,
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub device_losses: u64,
    pub upload_bytes: u64,
    pub readback_bytes: u64,
    /// Times the outcome ring lacked room and the caller was asked to drain
    /// before more input was read. Backpressure, not loss.
    pub output_stalls: u64,
    /// Terminal records re-attempted because the ring could not take them
    /// when their fence finished. Every accepted request reserves room for
    /// its own terminal record, so this stays zero unless that reservation
    /// has been undermined — a non-zero value is a defect signal, not load.
    pub terminal_retries: u64,
    pub peak_resident_bytes: u64,
    pub peak_staging_bytes: u64,
    pub peak_fences: u16,
    pub peak_queue_depth: [u16; QUEUE_COUNT],
    pub peak_resources: u16,
    /// Last rejection reason, for the diagnostic path that wants one number.
    pub last_reason: u16,
}

// ── Work handed back to the backend ─────────────────────────────────────

/// What the caller's backend must physically do for an admitted request.
///
/// Payload-bearing variants carry offsets into the record payload the caller
/// already holds rather than copies of it: this core never owns bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Work {
    /// Fully handled here. The fence is already terminal; the backend has
    /// nothing to do.
    None,
    CreateBuffer {
        fence: u16,
        slot: u16,
    },
    CreateTexture {
        fence: u16,
        slot: u16,
    },
    /// The handle is retired already. Free the backing object only once
    /// `resource_free_pending` reports the slot quiescent.
    DestroyResource {
        fence: u16,
        slot: u16,
    },
    LoadProgram {
        fence: u16,
        slot: u16,
        /// Byte offset of this chunk within the whole pack.
        chunk_offset: u32,
        /// Offset of the chunk bytes within the record payload.
        payload_offset: usize,
        chunk_len: usize,
    },
    CreatePipeline {
        fence: u16,
        slot: u16,
        program: u16,
    },
    /// The handle is retired. Free the backend's shader module.
    ///
    /// A release that settled in the core alone would leave the backend
    /// holding a compiled module for a program nothing can name — a leak that
    /// grows for the life of a long-running graph.
    ReleaseProgram {
        fence: u16,
        slot: u16,
    },
    /// The handle is retired. Free the backend's pipeline.
    ReleasePipeline {
        fence: u16,
        slot: u16,
    },
    Upload {
        fence: u16,
        resource: u16,
        offset: u64,
        payload_offset: usize,
        len: u32,
    },
    Readback {
        fence: u16,
        resource: u16,
        offset: u64,
        len: u32,
    },
    /// A validated submission. Walk its items with [`GpuDevice::items`].
    Submit {
        fence: u16,
        queue: u8,
        items_offset: usize,
        items_len: usize,
    },
    /// Ask the backend to stop `target` if it can. The disposition was
    /// already decided here and reported; this is the hardware hint.
    Cancel {
        fence: u16,
        target: u16,
    },
    /// Complete `fence` only once the device is physically quiescent.
    Drain {
        fence: u16,
    },
    /// Every handle of the old epoch is already invalid and every
    /// outstanding request already terminated. Reset the hardware, then
    /// complete `fence`.
    Reset {
        fence: u16,
        old_epoch: u16,
        new_epoch: u16,
    },
    ExportSurface {
        fence: u16,
        slot: u16,
    },
}
impl Work {
    /// The fence this work settles, or `None` for [`Work::None`], which
    /// names no outstanding fence because the request is already terminal.
    ///
    /// Every other variant carries one, and a provider holding state
    /// alongside a fence needs it without matching all fourteen — a match
    /// each provider writes for itself is a match each provider can miss a
    /// variant in.
    #[must_use]
    pub fn fence(&self) -> Option<u16> {
        match *self {
            Work::None => None,
            Work::CreateBuffer { fence, .. }
            | Work::CreateTexture { fence, .. }
            | Work::DestroyResource { fence, .. }
            | Work::LoadProgram { fence, .. }
            | Work::CreatePipeline { fence, .. }
            | Work::ReleaseProgram { fence, .. }
            | Work::ReleasePipeline { fence, .. }
            | Work::Upload { fence, .. }
            | Work::Readback { fence, .. }
            | Work::Submit { fence, .. }
            | Work::Cancel { fence, .. }
            | Work::Drain { fence, .. }
            | Work::Reset { fence, .. }
            | Work::ExportSurface { fence, .. } => Some(fence),
        }
    }
}

/// The result of offering bytes to [`GpuDevice::admit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    /// The record has not fully arrived. Buffer more input.
    NeedMore,
    /// The outcome ring cannot hold this request's answers. Drain outcomes
    /// and offer the same bytes again — nothing was consumed and nothing
    /// changed.
    Backpressure,
    /// One record was consumed.
    Consumed { bytes: usize, work: Work },
    /// Framing is broken. A rejection was emitted if there was room; the
    /// caller must tear the stream down, because a byte FIFO cannot be
    /// resynchronised by hunting for the next plausible header.
    Fault { bytes: usize },
}

// ── The device ──────────────────────────────────────────────────────────

/// Caller-owned tables. Their lengths are the device's R2 ceilings; a table
/// longer than `u16::MAX - 1` is refused at construction because a handle
/// cannot name past it.
pub struct GpuTables<'a> {
    pub resources: &'a mut [ResourceSlot],
    pub views: &'a mut [ViewSlot],
    pub programs: &'a mut [ProgramSlot],
    pub pipelines: &'a mut [PipelineSlot],
    pub fences: &'a mut [FenceSlot],
    pub surfaces: &'a mut [SurfaceSlot],
    /// Outcome ring: whole encoded records, oldest first.
    pub outcomes: &'a mut [u8],
}

pub struct GpuDevice<'a> {
    t: GpuTables<'a>,
    pub limits: DeviceLimits,
    pub stats: DeviceStats,
    backend: u32,
    provider_epoch: u32,
    epoch: u16,
    resident_bytes: u64,
    staging_bytes: u64,
    queue_depth: [u16; QUEUE_COUNT],
    /// Live bytes in the outcome ring.
    out_len: usize,
    /// Bytes promised to admitted requests that have not yet been written.
    out_reserved: usize,
    surface_sequence: u32,
}

/// Ring bytes an admitted request may still need to write: the acceptance
/// ack, an optional handle record, and the largest terminal record.
const RESERVE_ACCEPTED: usize = HEADER_LEN + 8;
const RESERVE_HANDLE: usize = HEADER_LEN + 8;
const RESERVE_TERMINAL: usize = HEADER_LEN + 24;
pub const RESERVE_BASE: usize = RESERVE_ACCEPTED + RESERVE_HANDLE + RESERVE_TERMINAL;
/// A rejection must always be affordable, or the caller cannot be told why.
const RESERVE_REJECT: usize = HEADER_LEN + 8;

/// Smallest outcome ring a device can be built over: enough for a capability
/// record plus one request's full set of answers. A smaller ring could not
/// answer `QUERY_CAPS` at all.
pub const MIN_RING_BYTES: usize = HEADER_LEN + CAPS_LEN + RESERVE_BASE;

/// Fixed fields ahead of the bytes in an `OUT_RESULT` record: fence handle,
/// offset, length.
const RESULT_PREFIX: usize = 24;

/// The device state that does not live in the caller's tables.
///
/// A provider whose device is rebuilt each step — a PIC module reconstituting
/// borrowed slices from raw pointers, say — saves this between steps.
/// Everything else (which handle is live, what a fence is waiting on, how far
/// a readback got) is table state the caller already owns; these are the
/// scalars, and losing them would silently reset the epoch, the budgets and
/// the outcome ring's cursors.
#[derive(Clone, Copy, Debug)]
pub struct DeviceScalars {
    pub epoch: u16,
    pub resident_bytes: u64,
    pub staging_bytes: u64,
    pub queue_depth: [u16; QUEUE_COUNT],
    pub out_len: usize,
    pub out_reserved: usize,
    pub surface_sequence: u32,
    pub stats: DeviceStats,
}

impl DeviceScalars {
    /// The state of a device that has never run: epoch 1 (never 0, so a
    /// zeroed handle cannot look current), nothing committed, nothing owed.
    #[must_use]
    pub fn initial() -> Self {
        Self {
            epoch: 1,
            resident_bytes: 0,
            staging_bytes: 0,
            queue_depth: [0; QUEUE_COUNT],
            out_len: 0,
            out_reserved: 0,
            surface_sequence: 0,
            stats: DeviceStats::default(),
        }
    }
}

impl<'a> GpuDevice<'a> {
    /// Build a device over caller-owned tables.
    ///
    /// `None` when a table is longer than the handle index field can name, or
    /// when the outcome ring is too small to hold the largest single record —
    /// both are composition errors, and discovering them at construction beats
    /// discovering them when a capability query cannot be answered.
    #[must_use]
    pub fn new(
        t: GpuTables<'a>,
        limits: DeviceLimits,
        backend: u32,
        provider_epoch: u32,
    ) -> Option<Self> {
        let cap = NO_SLOT as usize;
        if t.resources.len() >= cap
            || t.views.len() >= cap
            || t.programs.len() >= cap
            || t.pipelines.len() >= cap
            || t.fences.len() >= cap
            || t.surfaces.len() >= cap
        {
            return None;
        }
        if t.outcomes.len() < MIN_RING_BYTES {
            return None;
        }
        t.resources.fill(ResourceSlot::EMPTY);
        t.views.fill(ViewSlot::EMPTY);
        t.programs.fill(ProgramSlot::EMPTY);
        t.pipelines.fill(PipelineSlot::EMPTY);
        t.fences.fill(FenceSlot::EMPTY);
        t.surfaces.fill(SurfaceSlot::EMPTY);
        Some(Self {
            t,
            limits,
            stats: DeviceStats::default(),
            backend,
            provider_epoch,
            epoch: 1,
            resident_bytes: 0,
            staging_bytes: 0,
            queue_depth: [0; QUEUE_COUNT],
            out_len: 0,
            out_reserved: 0,
            surface_sequence: 0,
        })
    }

    /// Rebuild a device over tables that already hold live state.
    ///
    /// Unlike [`Self::new`] this clears nothing and validates nothing: the
    /// tables came from a previous step of the same provider, and the widths
    /// were checked when they were first built. A caller that constructs
    /// tables only through `restore` asserts those widths at its mount site,
    /// where they are compile-time constants.
    #[must_use]
    pub fn restore(
        t: GpuTables<'a>,
        limits: DeviceLimits,
        backend: u32,
        provider_epoch: u32,
        saved: DeviceScalars,
    ) -> Self {
        Self {
            t,
            limits,
            stats: saved.stats,
            backend,
            provider_epoch,
            epoch: saved.epoch,
            resident_bytes: saved.resident_bytes,
            staging_bytes: saved.staging_bytes,
            queue_depth: saved.queue_depth,
            out_len: saved.out_len,
            out_reserved: saved.out_reserved,
            surface_sequence: saved.surface_sequence,
        }
    }

    /// The scalars to carry to the next [`Self::restore`].
    #[must_use]
    pub fn save(&self) -> DeviceScalars {
        DeviceScalars {
            epoch: self.epoch,
            resident_bytes: self.resident_bytes,
            staging_bytes: self.staging_bytes,
            queue_depth: self.queue_depth,
            out_len: self.out_len,
            out_reserved: self.out_reserved,
            surface_sequence: self.surface_sequence,
            stats: self.stats,
        }
    }

    #[must_use]
    pub const fn epoch(&self) -> u16 {
        self.epoch
    }
    #[must_use]
    pub const fn resident_bytes(&self) -> u64 {
        self.resident_bytes
    }
    #[must_use]
    pub const fn staging_bytes(&self) -> u64 {
        self.staging_bytes
    }

    // ── Handle resolution ───────────────────────────────────────────────
    //
    // One check, used everywhere. Epoch first: a handle from a dead epoch is
    // the case a per-table generation counter alone would miss, because the
    // slot may legitimately have been reallocated to the same generation in
    // the new epoch.

    fn check_handle(&self, h: u64, kind: u8, owner: u16) -> Result<u16, u16> {
        if h == HANDLE_NONE || !handle_reserved_clear(h) {
            return Err(REASON_BAD_HANDLE);
        }
        if handle_epoch(h) != self.epoch {
            return Err(REASON_DEVICE_LOST);
        }
        if handle_kind(h) != kind {
            return Err(REASON_BAD_KIND);
        }
        let idx = handle_index(h);
        let gen = handle_generation(h);
        let (live, slot_gen, slot_owner) = match kind {
            KIND_BUFFER | KIND_TEXTURE | KIND_SAMPLER => {
                let s = self
                    .t
                    .resources
                    .get(idx as usize)
                    .ok_or(REASON_BAD_HANDLE)?;
                // A retired-but-retained slot is not reachable: the handle is
                // dead the moment destroy is accepted, even though the bytes
                // survive until quiescence.
                (
                    s.live && !s.retiring && s.kind == kind,
                    s.generation,
                    s.owner,
                )
            }
            KIND_VIEW => {
                let s = self.t.views.get(idx as usize).ok_or(REASON_BAD_HANDLE)?;
                (s.live, s.generation, s.owner)
            }
            KIND_PROGRAM => {
                let s = self.t.programs.get(idx as usize).ok_or(REASON_BAD_HANDLE)?;
                (s.live, s.generation, s.owner)
            }
            KIND_PIPELINE => {
                let s = self
                    .t
                    .pipelines
                    .get(idx as usize)
                    .ok_or(REASON_BAD_HANDLE)?;
                (s.live, s.generation, s.owner)
            }
            KIND_FENCE => {
                let s = self.t.fences.get(idx as usize).ok_or(REASON_BAD_HANDLE)?;
                (s.state != FENCE_FREE, s.generation, s.owner)
            }
            KIND_SURFACE => {
                let s = self.t.surfaces.get(idx as usize).ok_or(REASON_BAD_HANDLE)?;
                (s.live, s.generation, s.owner)
            }
            _ => return Err(REASON_BAD_KIND),
        };
        if !live || slot_gen != gen {
            return Err(REASON_BAD_HANDLE);
        }
        // Ownership is checked here and nowhere else. A handle number that
        // reached another owner by any route is refused: possession of the
        // number was never the grant.
        if slot_owner != owner {
            return Err(REASON_ACCESS_DENIED);
        }
        Ok(idx)
    }

    /// Resolve a resource handle of any resource kind.
    ///
    /// The epoch is checked first, exactly as in [`Self::check_handle`]: a
    /// handle left over from a dead epoch should report the loss, not a kind
    /// mismatch. The caller did nothing wrong, and telling it the wrong thing
    /// sends it looking for a bug it does not have.
    fn check_resource(&self, h: u64, owner: u16) -> Result<u16, u16> {
        if h == HANDLE_NONE || !handle_reserved_clear(h) {
            return Err(REASON_BAD_HANDLE);
        }
        if handle_epoch(h) != self.epoch {
            return Err(REASON_DEVICE_LOST);
        }
        for kind in [KIND_BUFFER, KIND_TEXTURE, KIND_SAMPLER] {
            if handle_kind(h) == kind {
                return self.check_handle(h, kind, owner);
            }
        }
        Err(REASON_BAD_KIND)
    }

    fn handle_for(&self, kind: u8, idx: u16, generation: u16) -> u64 {
        handle_pack(idx, generation, kind, self.epoch)
    }

    // ── Slot allocation ─────────────────────────────────────────────────

    fn alloc_resource(&mut self) -> Option<u16> {
        let idx = self.t.resources.iter().position(|s| !s.live)? as u16;
        let s = &mut self.t.resources[idx as usize];
        s.generation = next_gen(s.generation);
        s.live = true;
        s.retiring = false;
        s.sealed = false;
        s.published = false;
        s.in_flight = 0;
        Some(idx)
    }

    fn alloc_view(&mut self) -> Option<u16> {
        let idx = self.t.views.iter().position(|s| !s.live)? as u16;
        let s = &mut self.t.views[idx as usize];
        s.generation = next_gen(s.generation);
        s.live = true;
        Some(idx)
    }

    fn alloc_program(&mut self) -> Option<u16> {
        let idx = self.t.programs.iter().position(|s| !s.live)? as u16;
        let s = &mut self.t.programs[idx as usize];
        let g = next_gen(s.generation);
        *s = ProgramSlot::EMPTY;
        s.generation = g;
        s.live = true;
        Some(idx)
    }

    fn alloc_pipeline(&mut self) -> Option<u16> {
        let idx = self.t.pipelines.iter().position(|s| !s.live)? as u16;
        let s = &mut self.t.pipelines[idx as usize];
        let g = next_gen(s.generation);
        *s = PipelineSlot::EMPTY;
        s.generation = g;
        s.live = true;
        Some(idx)
    }

    fn alloc_surface(&mut self) -> Option<u16> {
        let idx = self.t.surfaces.iter().position(|s| !s.live)? as u16;
        let s = &mut self.t.surfaces[idx as usize];
        let g = next_gen(s.generation);
        *s = SurfaceSlot::EMPTY;
        s.generation = g;
        s.live = true;
        Some(idx)
    }

    /// A fence slot is free only when it has never been used, or its terminal
    /// record was both delivered and acknowledged. Reclaiming one earlier is
    /// how a completed result silently disappears.
    fn alloc_fence(&mut self, owner: u16, op: u16, corr: u64, queue: u8) -> Option<u16> {
        let idx = self.t.fences.iter().position(|s| s.state == FENCE_FREE)? as u16;
        let s = &mut self.t.fences[idx as usize];
        let g = next_gen(s.generation);
        *s = FenceSlot::EMPTY;
        s.generation = g;
        s.state = FENCE_WAITING;
        s.owner = owner;
        s.op = op;
        s.corr = corr;
        s.queue = queue;
        let live = self.live_fences();
        if live > self.stats.peak_fences {
            self.stats.peak_fences = live;
        }
        Some(idx)
    }

    fn live_fences(&self) -> u16 {
        self.t
            .fences
            .iter()
            .filter(|f| f.state != FENCE_FREE)
            .count() as u16
    }

    // ── Outcome ring ────────────────────────────────────────────────────
    //
    // A linear buffer compacted on drain, not a wrapping ring: records are
    // variable-length and a wrap that splits one would need either a second
    // copy path or a reserved gap. Compaction costs a memmove per drain and
    // buys a decoder that never sees a torn record.

    fn ring_free(&self) -> usize {
        self.t
            .outcomes
            .len()
            .saturating_sub(self.out_len)
            .saturating_sub(self.out_reserved)
    }

    /// Append a record, consuming `from_reserved` bytes of a prior
    /// reservation. Answers false only when the caller failed to reserve —
    /// a programming error this core makes visible rather than silently
    /// dropping the record.
    fn emit(&mut self, op: u16, corr: u64, payload: &[u8], from_reserved: usize) -> bool {
        let need = HEADER_LEN + payload.len();
        let released = from_reserved.min(self.out_reserved);
        self.out_reserved -= released;
        if self.t.outcomes.len() - self.out_len < need {
            // Put the reservation back: the record still has to be written.
            self.out_reserved += released;
            return false;
        }
        let start = self.out_len;
        match encode_record(&mut self.t.outcomes[start..], op, corr, payload) {
            Some(n) => {
                self.out_len += n;
                true
            }
            None => {
                self.out_reserved += released;
                false
            }
        }
    }

    /// Copy whole records out and compact. Answers the byte count written.
    ///
    /// Partial records are never emitted: a caller with a small buffer gets
    /// fewer records, not a truncated one, because the consumer decodes a
    /// byte FIFO and half a header is indistinguishable from corruption.
    pub fn drain_outcomes(&mut self, out: &mut [u8]) -> usize {
        let mut taken = 0usize;
        while taken < self.out_len {
            let rec = &self.t.outcomes[taken..self.out_len];
            let hdr = match Header::decode(rec) {
                Ok(Some(h)) => h,
                _ => break,
            };
            let total = hdr.total_len();
            if taken + total > self.out_len || out.len() - taken < total {
                break;
            }
            out[taken..taken + total].copy_from_slice(&self.t.outcomes[taken..taken + total]);
            taken += total;
        }
        if taken > 0 {
            self.t.outcomes.copy_within(taken..self.out_len, 0);
            self.out_len -= taken;
        }
        taken
    }

    /// Bytes of encoded outcome waiting to be drained.
    #[must_use]
    pub const fn pending_outcome_bytes(&self) -> usize {
        self.out_len
    }

    fn reject(&mut self, corr: u64, reason: u16, detail: u32) {
        self.stats.rejected += 1;
        self.stats.last_reason = reason;
        let mut payload = [0u8; 8];
        put_u16(&mut payload, 0, reason);
        put_u32(&mut payload, 4, detail);
        self.emit(OUT_REJECTED, corr, &payload, 0);
    }

    // ── Admission ───────────────────────────────────────────────────────

    /// Decode and admit one record from the front of `buf`.
    ///
    /// `owner` is the graph owner the channel context grants — supplied by
    /// the caller, never read from the record, because a record is a claim
    /// and the channel is the grant.
    pub fn admit(&mut self, owner: u16, buf: &[u8]) -> Admit {
        let hdr = match Header::decode(buf) {
            Ok(Some(h)) => h,
            Ok(None) => return Admit::NeedMore,
            Err(reason) => {
                if self.ring_free() < RESERVE_REJECT {
                    self.stats.output_stalls += 1;
                    return Admit::Backpressure;
                }
                // `corr` is unknown when framing failed — the header it would
                // have come from is the thing that did not parse.
                self.reject(0, reason, 0);
                return Admit::Fault { bytes: buf.len() };
            }
        };
        let total = hdr.total_len();
        if buf.len() < total {
            return Admit::NeedMore;
        }
        let payload = &buf[HEADER_LEN..total];

        // Reserve before anything can change. An op whose answers do not fit
        // is not admitted at all, and the caller is told to drain.
        let extra = match hdr.op {
            OP_QUERY_CAPS => HEADER_LEN + CAPS_LEN,
            OP_EXPORT_SURFACE => HEADER_LEN + SURFACE_LEN,
            _ => 0,
        };
        let need = RESERVE_BASE + extra;
        if self.ring_free() < need {
            self.stats.output_stalls += 1;
            return Admit::Backpressure;
        }

        match self.dispatch(owner, &hdr, payload, need) {
            Ok(work) => Admit::Consumed { bytes: total, work },
            Err((reason, detail)) => {
                self.reject(hdr.corr, reason, detail);
                Admit::Consumed {
                    bytes: total,
                    work: Work::None,
                }
            }
        }
    }

    fn dispatch(
        &mut self,
        owner: u16,
        hdr: &Header,
        payload: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        match hdr.op {
            OP_QUERY_CAPS => self.op_query_caps(owner, hdr, reserve),
            OP_CREATE_BUFFER => self.op_create_buffer(owner, hdr, payload, reserve),
            OP_CREATE_TEXTURE => self.op_create_texture(owner, hdr, payload, reserve),
            OP_CREATE_SAMPLER => self.op_create_sampler(owner, hdr, payload, reserve),
            OP_DESTROY_RESOURCE => self.op_destroy_resource(owner, hdr, payload, reserve),
            OP_CREATE_VIEW => self.op_create_view(owner, hdr, payload, reserve),
            OP_RELEASE_VIEW => self.op_release_view(owner, hdr, payload, reserve),
            OP_SEAL_RESOURCE => self.op_seal(owner, hdr, payload, reserve),
            OP_SET_RESIDENCY => self.op_set_residency(owner, hdr, payload, reserve),
            OP_LOAD_PROGRAM => self.op_load_program(owner, hdr, payload, reserve),
            OP_RELEASE_PROGRAM => self.op_release_program(owner, hdr, payload, reserve),
            OP_CREATE_PIPELINE => self.op_create_pipeline(owner, hdr, payload, reserve),
            OP_RELEASE_PIPELINE => self.op_release_pipeline(owner, hdr, payload, reserve),
            OP_UPLOAD => self.op_upload(owner, hdr, payload, reserve),
            OP_READBACK => self.op_readback(owner, hdr, payload, reserve),
            OP_SUBMIT => self.op_submit(owner, hdr, payload, reserve),
            OP_POLL_FENCE => self.op_poll_fence(owner, hdr, payload),
            OP_RELEASE_FENCE => self.op_release_fence(owner, hdr, payload, reserve),
            OP_CANCEL => self.op_cancel(owner, hdr, payload, reserve),
            OP_DRAIN => self.op_drain(owner, hdr, reserve),
            OP_RESET => self.op_reset(owner, hdr, payload, reserve),
            OP_EXPORT_SURFACE => self.op_export_surface(owner, hdr, payload, reserve),
            OP_RELEASE_SURFACE => self.op_release_surface(owner, hdr, payload, reserve),
            _ => Err((REASON_UNKNOWN_OP, hdr.op as u32)),
        }
    }

    /// Emit `OUT_ACCEPTED` for a freshly allocated fence and record what the
    /// request still owes the ring.
    fn accept(&mut self, fence: u16, reserve: usize) -> u64 {
        self.stats.admitted += 1;
        let gen = self.t.fences[fence as usize].generation;
        let corr = self.t.fences[fence as usize].corr;
        let h = self.handle_for(KIND_FENCE, fence, gen);
        // The whole reservation transfers to the fence; each record written
        // for it draws that reservation down.
        self.out_reserved += reserve;
        self.t.fences[fence as usize].ring_reserved = reserve as u32;
        let mut p = [0u8; 8];
        put_u64(&mut p, 0, h);
        self.emit(OUT_ACCEPTED, corr, &p, RESERVE_ACCEPTED);
        self.t.fences[fence as usize].ring_reserved -= RESERVE_ACCEPTED as u32;
        h
    }

    fn emit_handle(&mut self, fence: u16, handle: u64) {
        let corr = self.t.fences[fence as usize].corr;
        let mut p = [0u8; 8];
        put_u64(&mut p, 0, handle);
        self.emit(OUT_HANDLE, corr, &p, RESERVE_HANDLE);
        let f = &mut self.t.fences[fence as usize];
        f.ring_reserved = f.ring_reserved.saturating_sub(RESERVE_HANDLE as u32);
    }

    /// Mark a fence complete without any backend round trip — the answer for
    /// every operation whose whole effect is bookkeeping this core already did.
    fn settle_now(&mut self, fence: u16) {
        self.finish(fence, OUT_COMPLETED, 0, 0, 0, 0);
    }

    // ── Operations ──────────────────────────────────────────────────────

    fn op_query_caps(
        &mut self,
        owner: u16,
        hdr: &Header,
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_COMPUTE)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        self.accept(fence, reserve);
        let caps = self.encode_caps();
        self.emit(OUT_CAPS, hdr.corr, &caps, HEADER_LEN + CAPS_LEN);
        let f = &mut self.t.fences[fence as usize];
        f.ring_reserved = f
            .ring_reserved
            .saturating_sub((HEADER_LEN + CAPS_LEN) as u32);
        self.settle_now(fence);
        Ok(Work::None)
    }

    /// The capability record. Every number here is a fact this provider has
    /// been configured to stand behind — a union of what some backend might
    /// support would make the whole record worthless.
    #[must_use]
    pub fn encode_caps(&self) -> [u8; CAPS_LEN] {
        let mut c = [0u8; CAPS_LEN];
        put_u32(&mut c, CAPS_BACKEND, self.backend);
        put_u32(&mut c, CAPS_PROVIDER_EPOCH, self.provider_epoch);
        put_u32(&mut c, CAPS_DEVICE_EPOCH, self.epoch as u32);
        put_u32(&mut c, CAPS_FEATURES, self.limits.features);
        put_u32(&mut c, CAPS_ARITH_OPS, self.limits.arith_ops);
        put_u32(&mut c, CAPS_MAX_RESOURCES, self.t.resources.len() as u32);
        put_u32(&mut c, CAPS_MAX_VIEWS, self.t.views.len() as u32);
        put_u32(&mut c, CAPS_MAX_PROGRAMS, self.t.programs.len() as u32);
        put_u32(&mut c, CAPS_MAX_PIPELINES, self.t.pipelines.len() as u32);
        put_u32(&mut c, CAPS_MAX_FENCES, self.t.fences.len() as u32);
        put_u32(
            &mut c,
            CAPS_MAX_QUEUE_DEPTH,
            self.limits.max_queue_depth as u32,
        );
        put_u32(&mut c, CAPS_MAX_BINDINGS, self.limits.max_bindings);
        put_u32(&mut c, CAPS_MIN_ALIGN, self.limits.min_align);
        put_u32(&mut c, CAPS_MAX_WORKGROUP_X, self.limits.max_workgroup[0]);
        put_u32(&mut c, CAPS_MAX_WORKGROUP_Y, self.limits.max_workgroup[1]);
        put_u32(&mut c, CAPS_MAX_WORKGROUP_Z, self.limits.max_workgroup[2]);
        put_u32(
            &mut c,
            CAPS_MAX_WORKGROUP_INVOCATIONS,
            self.limits.max_workgroup_invocations,
        );
        put_u32(&mut c, CAPS_MAX_GRID_X, self.limits.max_grid[0]);
        put_u32(&mut c, CAPS_MAX_GRID_Y, self.limits.max_grid[1]);
        put_u32(&mut c, CAPS_MAX_GRID_Z, self.limits.max_grid[2]);
        put_u32(&mut c, CAPS_MAX_RECORD_PAYLOAD, MAX_PAYLOAD);
        put_u64(&mut c, CAPS_MAX_ALLOC_BYTES, self.limits.max_alloc_bytes);
        put_u64(
            &mut c,
            CAPS_MAX_RESIDENT_BYTES,
            self.limits.max_resident_bytes,
        );
        put_u64(
            &mut c,
            CAPS_MAX_STAGING_BYTES,
            self.limits.max_staging_bytes,
        );
        put_u64(
            &mut c,
            CAPS_MAX_SCRATCH_BYTES,
            self.limits.max_scratch_bytes,
        );
        for (i, t) in self.limits.targets.iter().enumerate() {
            put_u32(&mut c, CAPS_TARGETS + i * 4, *t);
        }
        c[CAPS_ARITH_TABLE..CAPS_ARITH_TABLE + ARITH_TYPE_COUNT]
            .copy_from_slice(&self.limits.arith_types);
        c
    }

    fn op_create_buffer(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let size = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let usage = get_u32(p, 8).ok_or((REASON_MALFORMED, 0))?;
        let rights = get_u32(p, 12).ok_or((REASON_MALFORMED, 0))?;
        let residency = get_u8(p, 16).ok_or((REASON_MALFORMED, 0))?;
        self.validate_new_resource(size, usage, rights, residency)?;
        // Candidate storage that cannot be written could never be produced.
        // Being mappable or presentable is fine and expected — reading a
        // candidate is gated on publication, not on how it was created.
        if usage & USAGE_CANDIDATE != 0 && rights & RIGHT_WRITE == 0 {
            return Err((REASON_MALFORMED, USAGE_CANDIDATE));
        }
        self.reserve_resident(size)?;
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        let slot = match self.alloc_resource() {
            Some(s) => s,
            None => {
                self.release_fence_slot(fence);
                self.resident_bytes -= size;
                return Err((REASON_HANDLE_EXHAUSTED, 0));
            }
        };
        {
            let s = &mut self.t.resources[slot as usize];
            s.kind = KIND_BUFFER;
            s.residency = residency;
            s.usage = usage;
            s.rights = rights;
            s.owner = owner;
            s.size = size;
        }
        self.note_resource_peak();
        self.accept(fence, reserve);
        let handle = self.handle_for(
            KIND_BUFFER,
            slot,
            self.t.resources[slot as usize].generation,
        );
        self.emit_handle(fence, handle);
        Ok(Work::CreateBuffer { fence, slot })
    }

    fn op_create_texture(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let width = get_u32(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let height = get_u32(p, 4).ok_or((REASON_MALFORMED, 0))?;
        let layers = get_u32(p, 8).ok_or((REASON_MALFORMED, 0))?;
        let format = get_u32(p, 12).ok_or((REASON_MALFORMED, 0))?;
        let usage = get_u32(p, 16).ok_or((REASON_MALFORMED, 0))?;
        let rights = get_u32(p, 20).ok_or((REASON_MALFORMED, 0))?;
        if self.limits.features & FEATURE_RASTER == 0 && usage & USAGE_RENDER_TARGET != 0 {
            return Err((REASON_UNSUPPORTED_FEATURE, FEATURE_RASTER));
        }
        if width == 0 || height == 0 || layers == 0 {
            return Err((REASON_MALFORMED, 0));
        }
        // Four bytes per texel is the accounting assumption, stated rather
        // than hidden: a provider with a narrower format still reserves this,
        // which over-reserves but never under-reserves.
        let size = (width as u64)
            .checked_mul(height as u64)
            .and_then(|v| v.checked_mul(layers as u64))
            .and_then(|v| v.checked_mul(4))
            .ok_or((REASON_BAD_RANGE, 0))?;
        self.validate_new_resource(size, usage, rights, RESIDENCY_RESIDENT)?;
        self.reserve_resident(size)?;
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        let slot = match self.alloc_resource() {
            Some(s) => s,
            None => {
                self.release_fence_slot(fence);
                self.resident_bytes -= size;
                return Err((REASON_HANDLE_EXHAUSTED, 0));
            }
        };
        {
            let s = &mut self.t.resources[slot as usize];
            s.kind = KIND_TEXTURE;
            s.residency = RESIDENCY_RESIDENT;
            s.usage = usage;
            s.rights = rights;
            s.owner = owner;
            s.size = size;
            s.width = width;
            s.height = height;
            s.format = format;
        }
        self.note_resource_peak();
        self.accept(fence, reserve);
        let handle = self.handle_for(
            KIND_TEXTURE,
            slot,
            self.t.resources[slot as usize].generation,
        );
        self.emit_handle(fence, handle);
        Ok(Work::CreateTexture { fence, slot })
    }

    fn op_create_sampler(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let filter = get_u32(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let address = get_u32(p, 4).ok_or((REASON_MALFORMED, 0))?;
        let rights = get_u32(p, 8).ok_or((REASON_MALFORMED, 0))?;
        if rights & !RIGHT_ALL != 0 {
            return Err((REASON_MALFORMED, rights));
        }
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        let slot = match self.alloc_resource() {
            Some(s) => s,
            None => {
                self.release_fence_slot(fence);
                return Err((REASON_HANDLE_EXHAUSTED, 0));
            }
        };
        {
            let s = &mut self.t.resources[slot as usize];
            s.kind = KIND_SAMPLER;
            s.residency = RESIDENCY_RESIDENT;
            s.usage = USAGE_TEXTURE_SAMPLE;
            s.rights = rights;
            s.owner = owner;
            s.size = 0;
            s.width = filter;
            s.height = address;
        }
        self.note_resource_peak();
        self.accept(fence, reserve);
        let handle = self.handle_for(
            KIND_SAMPLER,
            slot,
            self.t.resources[slot as usize].generation,
        );
        self.emit_handle(fence, handle);
        // A sampler has no device-side creation cost worth a round trip in
        // this contract; the backend materialises it lazily at first bind.
        self.settle_now(fence);
        Ok(Work::None)
    }

    fn validate_new_resource(
        &self,
        size: u64,
        usage: u32,
        rights: u32,
        residency: u8,
    ) -> Result<(), (u16, u32)> {
        if usage & !USAGE_ALL != 0 {
            return Err((REASON_MALFORMED, usage));
        }
        if rights & !RIGHT_ALL != 0 {
            return Err((REASON_MALFORMED, rights));
        }
        if usage == 0 || rights == 0 {
            return Err((REASON_MALFORMED, 0));
        }
        if !matches!(
            residency,
            RESIDENCY_RESIDENT | RESIDENCY_UPLOADING | RESIDENCY_EVICTABLE
        ) {
            return Err((REASON_MALFORMED, residency as u32));
        }
        if size == 0 || size > self.limits.max_alloc_bytes {
            return Err((REASON_OVERSIZE, 0));
        }
        Ok(())
    }

    fn reserve_resident(&mut self, size: u64) -> Result<(), (u16, u32)> {
        let next = self
            .resident_bytes
            .checked_add(size)
            .ok_or((REASON_RESOURCE_EXHAUSTED, 0))?;
        if next > self.limits.max_resident_bytes {
            return Err((REASON_RESOURCE_EXHAUSTED, 0));
        }
        self.resident_bytes = next;
        if next > self.stats.peak_resident_bytes {
            self.stats.peak_resident_bytes = next;
        }
        Ok(())
    }

    fn note_resource_peak(&mut self) {
        let live = self.t.resources.iter().filter(|s| s.live).count() as u16;
        if live > self.stats.peak_resources {
            self.stats.peak_resources = live;
        }
    }

    fn op_destroy_resource(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let h = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let idx = self.check_resource(h, owner).map_err(|r| (r, 0))?;
        if self.t.resources[idx as usize].rights & RIGHT_OWN == 0 {
            return Err((REASON_ACCESS_DENIED, 0));
        }
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        // Retire the handle immediately — every later use of it is a stale
        // handle, which is the point — but keep the storage until nothing in
        // flight can reach it.
        self.t.resources[idx as usize].retiring = true;
        self.t.resources[idx as usize].residency = RESIDENCY_RETIRED;
        self.accept(fence, reserve);
        if self.t.resources[idx as usize].in_flight == 0 {
            self.free_resource(idx);
            self.settle_now(fence);
            return Ok(Work::DestroyResource { fence, slot: idx });
        }
        // Still referenced: the destroy fence completes when the last
        // referencing request terminates.
        Ok(Work::DestroyResource { fence, slot: idx })
    }

    fn free_resource(&mut self, idx: u16) {
        let s = &mut self.t.resources[idx as usize];
        if !s.live {
            return;
        }
        let size = s.size;
        s.live = false;
        s.retiring = false;
        s.residency = RESIDENCY_RETIRED;
        s.usage = 0;
        s.rights = 0;
        s.published = false;
        s.sealed = false;
        self.resident_bytes = self.resident_bytes.saturating_sub(size);
        // Any view onto it dies with it: a view outliving its resource would
        // be a handle whose bounds check has nothing to check against.
        for v in self.t.views.iter_mut() {
            if v.live && v.resource == idx {
                v.live = false;
            }
        }
    }

    fn op_create_view(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let rh = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let offset = get_u64(p, 8).ok_or((REASON_MALFORMED, 0))?;
        let length = get_u64(p, 16).ok_or((REASON_MALFORMED, 0))?;
        let usage = get_u32(p, 24).ok_or((REASON_MALFORMED, 0))?;
        let rights = get_u32(p, 28).ok_or((REASON_MALFORMED, 0))?;
        let idx = self.check_resource(rh, owner).map_err(|r| (r, 0))?;
        let res = self.t.resources[idx as usize];
        if length == 0 {
            return Err((REASON_MALFORMED, 0));
        }
        // Checked arithmetic, not `offset + length <= size`: the wrapping
        // form accepts an offset near u64::MAX with any length at all.
        let end = offset.checked_add(length).ok_or((REASON_BAD_RANGE, 0))?;
        if end > res.size {
            return Err((REASON_BAD_RANGE, 0));
        }
        // `max(1)` reads as "0 and 1 both mean unconstrained", and it is also
        // what keeps the remainder total: `restore` validates nothing, so the
        // check site is the only place a device with no stated alignment can
        // be made safe.
        if !offset.is_multiple_of(u64::from(self.limits.min_align.max(1))) {
            return Err((REASON_BAD_ALIGNMENT, self.limits.min_align));
        }
        // A view can only narrow: it may not add a usage the resource was
        // not created with, nor a right the parent handle does not hold.
        if usage & !res.usage != 0 {
            return Err((REASON_USAGE_DENIED, usage & !res.usage));
        }
        if rights & !res.rights != 0 {
            return Err((REASON_ACCESS_DENIED, rights & !res.rights));
        }
        if usage == 0 || rights == 0 {
            return Err((REASON_MALFORMED, 0));
        }
        if res.sealed && rights & RIGHT_WRITE != 0 {
            return Err((REASON_SEALED, 0));
        }
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        let vslot = match self.alloc_view() {
            Some(v) => v,
            None => {
                self.release_fence_slot(fence);
                return Err((REASON_HANDLE_EXHAUSTED, 0));
            }
        };
        {
            let v = &mut self.t.views[vslot as usize];
            v.resource = idx;
            v.resource_gen = res.generation;
            v.offset = offset;
            v.length = length;
            v.usage = usage;
            v.rights = rights;
            v.owner = owner;
        }
        self.accept(fence, reserve);
        let handle = self.handle_for(KIND_VIEW, vslot, self.t.views[vslot as usize].generation);
        self.emit_handle(fence, handle);
        self.settle_now(fence);
        Ok(Work::None)
    }

    fn op_release_view(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let h = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let idx = self.check_handle(h, KIND_VIEW, owner).map_err(|r| (r, 0))?;
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        self.t.views[idx as usize].live = false;
        self.accept(fence, reserve);
        self.settle_now(fence);
        Ok(Work::None)
    }

    fn op_seal(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let h = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let idx = self.check_resource(h, owner).map_err(|r| (r, 0))?;
        if self.t.resources[idx as usize].rights & RIGHT_OWN == 0 {
            return Err((REASON_ACCESS_DENIED, 0));
        }
        if self.t.resources[idx as usize].in_flight != 0 {
            return Err((REASON_IN_FLIGHT, 0));
        }
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        self.t.resources[idx as usize].sealed = true;
        // Sealing is not a promise about one handle: every alias loses write
        // rights, or the seal would be defeated by a view made a moment
        // earlier.
        for v in self.t.views.iter_mut() {
            if v.live && v.resource == idx {
                v.rights &= !RIGHT_WRITE;
            }
        }
        self.accept(fence, reserve);
        self.settle_now(fence);
        Ok(Work::None)
    }

    fn op_set_residency(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let h = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let state = get_u8(p, 8).ok_or((REASON_MALFORMED, 0))?;
        let idx = self.check_resource(h, owner).map_err(|r| (r, 0))?;
        if !matches!(
            state,
            RESIDENCY_RESIDENT | RESIDENCY_UPLOADING | RESIDENCY_EVICTABLE
        ) {
            return Err((REASON_MALFORMED, state as u32));
        }
        // Unpinning something the device may currently be reading is the one
        // transition that can corrupt a result rather than merely fail one.
        if state == RESIDENCY_EVICTABLE && self.t.resources[idx as usize].in_flight != 0 {
            return Err((REASON_IN_FLIGHT, 0));
        }
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        self.t.resources[idx as usize].residency = state;
        self.accept(fence, reserve);
        self.settle_now(fence);
        Ok(Work::None)
    }

    fn op_load_program(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let program = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let chunk_offset = get_u32(p, 8).ok_or((REASON_MALFORMED, 0))?;
        let total_len = get_u32(p, 12).ok_or((REASON_MALFORMED, 0))?;
        let body = p.get(16..).ok_or((REASON_MALFORMED, 0))?;
        if body.is_empty() || total_len as usize > MAX_PACK_BYTES {
            return Err((REASON_OVERSIZE, total_len));
        }

        // Continuation of a load already in progress. The handle is what ties
        // the chunks together; a stream position is not an identity, and two
        // interleaved loads would otherwise silently splice into one pack.
        if program != HANDLE_NONE {
            let slot = self
                .check_handle(program, KIND_PROGRAM, owner)
                .map_err(|r| (r, 0))?;
            let s = self.t.programs[slot as usize];
            if s.ready {
                return Err((REASON_BAD_PROGRAM, PACK_MALFORMED as u32));
            }
            if total_len != s.declared || chunk_offset != s.received {
                return Err((REASON_BAD_RANGE, s.received));
            }
            let end = (chunk_offset as u64) + body.len() as u64;
            if end > s.declared as u64 {
                return Err((REASON_BAD_RANGE, s.declared));
            }
            let fence = self
                .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
                .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
            self.t.programs[slot as usize].received = end as u32;
            self.accept(fence, reserve);
            return Ok(Work::LoadProgram {
                fence,
                slot,
                chunk_offset,
                payload_offset: HEADER_LEN + 16,
                chunk_len: body.len(),
            });
        }

        // A new load. Nothing about the pack is validated here — not even the
        // magic — because the first chunk may be shorter than the header. The
        // single validation path is `finish_program`, run once the artifact is
        // whole, so a partial pack can never be reported as one that passed a
        // digest check.
        if chunk_offset != 0 || body.len() > total_len as usize {
            return Err((REASON_BAD_RANGE, 0));
        }
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        let slot = match self.alloc_program() {
            Some(s) => s,
            None => {
                self.release_fence_slot(fence);
                return Err((REASON_HANDLE_EXHAUSTED, 0));
            }
        };
        {
            let s = &mut self.t.programs[slot as usize];
            s.owner = owner;
            s.declared = total_len;
            s.received = body.len() as u32;
        }
        self.accept(fence, reserve);
        let handle = self.handle_for(
            KIND_PROGRAM,
            slot,
            self.t.programs[slot as usize].generation,
        );
        self.emit_handle(fence, handle);
        Ok(Work::LoadProgram {
            fence,
            slot,
            chunk_offset,
            payload_offset: HEADER_LEN + 16,
            chunk_len: body.len(),
        })
    }

    /// Validate an assembled pack and make its program usable.
    ///
    /// The backend calls this once it holds every declared byte — it owns the
    /// assembly buffer, because this core owns no storage. Validation is the
    /// same `decode_and_validate` a single-chunk load runs, so a chunked pack
    /// and a whole one are held to one standard.
    ///
    /// On failure the program slot is retired: a pack that did not validate
    /// leaves nothing behind for a later request to reach.
    pub fn finish_program(&mut self, slot: u16, assembled: &[u8]) -> Result<(), u16> {
        let limits = self.limits.pack_limits();
        let Some(s) = self.t.programs.get(slot as usize) else {
            return Err(PACK_MALFORMED);
        };
        if !s.live || s.ready {
            return Err(PACK_MALFORMED);
        }
        if s.received != s.declared || assembled.len() != s.declared as usize {
            self.t.programs[slot as usize].live = false;
            return Err(PACK_MALFORMED);
        }
        let pack = match decode_and_validate(assembled, &limits) {
            Ok(p) => p,
            Err(e) => {
                self.t.programs[slot as usize].live = false;
                return Err(e);
            }
        };
        if pack.binding_count > MAX_PROGRAM_BINDINGS {
            self.t.programs[slot as usize].live = false;
            return Err(PACK_BAD_BINDING);
        }
        let identity = pack.identity();
        let s = &mut self.t.programs[slot as usize];
        s.target_isa = pack.target_isa;
        s.target_rev = pack.target_rev;
        s.workgroup = pack.workgroup;
        s.binding_count = pack.binding_count as u8;
        for i in 0..pack.binding_count {
            if let Some(b) = pack.binding(i) {
                s.bindings[i] = b;
            }
        }
        s.identity = identity;
        s.artifact_len = pack.artifact().len() as u32;
        s.ready = true;
        Ok(())
    }

    /// Bytes of a chunked pack still owed for `slot`.
    #[must_use]
    pub fn program_outstanding(&self, slot: u16) -> u32 {
        self.t
            .programs
            .get(slot as usize)
            .map_or(0, |s| s.declared.saturating_sub(s.received))
    }

    fn op_release_program(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let h = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let idx = self
            .check_handle(h, KIND_PROGRAM, owner)
            .map_err(|r| (r, 0))?;
        // A pipeline built from it keeps it alive: releasing the program out
        // from under a live pipeline would leave the pipeline's binding
        // contract unverifiable.
        if self
            .t
            .pipelines
            .iter()
            .any(|pl| pl.live && pl.program == idx)
        {
            return Err((REASON_IN_FLIGHT, 0));
        }
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        self.t.programs[idx as usize].live = false;
        self.accept(fence, reserve);
        Ok(Work::ReleaseProgram { fence, slot: idx })
    }

    fn op_create_pipeline(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let ph = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let kind = get_u8(p, 8).ok_or((REASON_MALFORMED, 0))?;
        let state_len = get_u32(p, 12).ok_or((REASON_MALFORMED, 0))?;
        if p.len() < 16 + state_len as usize {
            return Err((REASON_MALFORMED, 0));
        }
        let prog = self
            .check_handle(ph, KIND_PROGRAM, owner)
            .map_err(|r| (r, 0))?;
        if !self.t.programs[prog as usize].ready {
            return Err((REASON_NOT_READY, 0));
        }
        if !matches!(kind, QUEUE_COMPUTE | QUEUE_RASTER) {
            return Err((REASON_MALFORMED, kind as u32));
        }
        if kind == QUEUE_RASTER && self.limits.features & FEATURE_RASTER == 0 {
            return Err((REASON_UNSUPPORTED_FEATURE, FEATURE_RASTER));
        }
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        let slot = match self.alloc_pipeline() {
            Some(s) => s,
            None => {
                self.release_fence_slot(fence);
                return Err((REASON_HANDLE_EXHAUSTED, 0));
            }
        };
        {
            let s = &mut self.t.pipelines[slot as usize];
            s.owner = owner;
            s.program = prog;
            s.program_gen = self.t.programs[prog as usize].generation;
            s.kind = kind;
            // Not ready until the build fence completes. Everything about
            // readiness hangs off that one flag; nothing else may set it.
            s.ready = false;
            s.build_fence = fence;
        }
        self.accept(fence, reserve);
        let handle = self.handle_for(
            KIND_PIPELINE,
            slot,
            self.t.pipelines[slot as usize].generation,
        );
        self.emit_handle(fence, handle);
        Ok(Work::CreatePipeline {
            fence,
            slot,
            program: prog,
        })
    }

    fn op_release_pipeline(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let h = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let idx = self
            .check_handle(h, KIND_PIPELINE, owner)
            .map_err(|r| (r, 0))?;
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        self.t.pipelines[idx as usize].live = false;
        self.accept(fence, reserve);
        Ok(Work::ReleasePipeline { fence, slot: idx })
    }

    fn op_upload(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let vh = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let offset = get_u64(p, 8).ok_or((REASON_MALFORMED, 0))?;
        let byte_len = get_u32(p, 16).ok_or((REASON_MALFORMED, 0))?;
        let bytes = p.get(24..).ok_or((REASON_MALFORMED, 0))?;
        if bytes.len() != byte_len as usize || byte_len == 0 {
            return Err((REASON_MALFORMED, byte_len));
        }
        let (res_idx, abs_off) = self.resolve_write_range(vh, owner, offset, byte_len as u64)?;
        self.reserve_staging(byte_len as u64)?;
        let fence = match self.alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER) {
            Some(f) => f,
            None => {
                self.staging_bytes -= byte_len as u64;
                return Err((REASON_FENCE_EXHAUSTED, 0));
            }
        };
        self.t.fences[fence as usize].staging_bytes = byte_len as u64;
        self.retain(fence, res_idx);
        self.stats.upload_bytes += byte_len as u64;
        self.accept(fence, reserve);
        Ok(Work::Upload {
            fence,
            resource: res_idx,
            offset: abs_off,
            payload_offset: HEADER_LEN + 24,
            len: byte_len,
        })
    }

    fn op_readback(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        if self.limits.features & FEATURE_READBACK == 0 {
            return Err((REASON_UNSUPPORTED_FEATURE, FEATURE_READBACK));
        }
        let vh = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let offset = get_u64(p, 8).ok_or((REASON_MALFORMED, 0))?;
        let byte_len = get_u32(p, 16).ok_or((REASON_MALFORMED, 0))?;
        if byte_len == 0 {
            return Err((REASON_MALFORMED, 0));
        }
        let (res_idx, abs_off) = self.resolve_read_range(vh, owner, offset, byte_len as u64)?;
        // Reading uncommitted scratch back to the CPU is exactly the leak
        // this contract exists to prevent.
        if self.candidate_pending(res_idx) {
            return Err((REASON_NOT_READY, 0));
        }
        if self.t.views[handle_index(vh) as usize].rights & RIGHT_MAP == 0 {
            return Err((REASON_ACCESS_DENIED, RIGHT_MAP));
        }
        if self.t.resources[res_idx as usize].usage & USAGE_MAP_READ == 0 {
            return Err((REASON_USAGE_DENIED, USAGE_MAP_READ));
        }
        self.reserve_staging(byte_len as u64)?;
        let fence = match self.alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER) {
            Some(f) => f,
            None => {
                self.staging_bytes -= byte_len as u64;
                return Err((REASON_FENCE_EXHAUSTED, 0));
            }
        };
        {
            let f = &mut self.t.fences[fence as usize];
            f.staging_bytes = byte_len as u64;
            f.result_len = byte_len as u64;
        }
        self.retain(fence, res_idx);
        self.accept(fence, reserve);
        Ok(Work::Readback {
            fence,
            resource: res_idx,
            offset: abs_off,
            len: byte_len,
        })
    }

    /// Resolve a view + relative range for writing, answering the backing
    /// resource and the absolute offset within it.
    fn resolve_write_range(
        &self,
        vh: u64,
        owner: u16,
        offset: u64,
        len: u64,
    ) -> Result<(u16, u64), (u16, u32)> {
        let vidx = self
            .check_handle(vh, KIND_VIEW, owner)
            .map_err(|r| (r, 0))?;
        let v = self.t.views[vidx as usize];
        if v.rights & RIGHT_WRITE == 0 {
            return Err((REASON_ACCESS_DENIED, RIGHT_WRITE));
        }
        let res = &self.t.resources[v.resource as usize];
        if !res.live || res.generation != v.resource_gen {
            return Err((REASON_BAD_HANDLE, 0));
        }
        if res.sealed {
            return Err((REASON_SEALED, 0));
        }
        if res.residency != RESIDENCY_RESIDENT && res.residency != RESIDENCY_UPLOADING {
            return Err((REASON_RESIDENCY, res.residency as u32));
        }
        let end = offset.checked_add(len).ok_or((REASON_BAD_RANGE, 0))?;
        if end > v.length {
            return Err((REASON_BAD_RANGE, 0));
        }
        Ok((v.resource, v.offset + offset))
    }

    fn resolve_read_range(
        &self,
        vh: u64,
        owner: u16,
        offset: u64,
        len: u64,
    ) -> Result<(u16, u64), (u16, u32)> {
        let vidx = self
            .check_handle(vh, KIND_VIEW, owner)
            .map_err(|r| (r, 0))?;
        let v = self.t.views[vidx as usize];
        if v.rights & RIGHT_READ == 0 {
            return Err((REASON_ACCESS_DENIED, RIGHT_READ));
        }
        let res = &self.t.resources[v.resource as usize];
        if !res.live || res.generation != v.resource_gen {
            return Err((REASON_BAD_HANDLE, 0));
        }
        if res.residency != RESIDENCY_RESIDENT {
            return Err((REASON_RESIDENCY, res.residency as u32));
        }
        let end = offset.checked_add(len).ok_or((REASON_BAD_RANGE, 0))?;
        if end > v.length {
            return Err((REASON_BAD_RANGE, 0));
        }
        Ok((v.resource, v.offset + offset))
    }

    /// Whether `res` is private candidate storage whose contents have not been
    /// committed by a successful completion.
    ///
    /// The distinction the whole candidate mechanism turns on: an uncommitted
    /// candidate is unreadable *to the consumer* — no readback, no present, no
    /// unrelated submission. It is readable to work that explicitly waits on
    /// the fence which will publish it, because that wait is precisely how a
    /// two-stage pipeline is expressed. Collapsing those two cases would
    /// either leak uncommitted bytes or make dependent kernels impossible.
    fn candidate_pending(&self, res: u16) -> bool {
        self.t
            .resources
            .get(res as usize)
            .is_some_and(|r| r.usage & USAGE_CANDIDATE != 0 && !r.published)
    }

    fn reserve_staging(&mut self, n: u64) -> Result<(), (u16, u32)> {
        let next = self
            .staging_bytes
            .checked_add(n)
            .ok_or((REASON_RESOURCE_EXHAUSTED, 0))?;
        if next > self.limits.max_staging_bytes {
            return Err((REASON_RESOURCE_EXHAUSTED, 0));
        }
        self.staging_bytes = next;
        if next > self.stats.peak_staging_bytes {
            self.stats.peak_staging_bytes = next;
        }
        Ok(())
    }

    fn retain(&mut self, fence: u16, res: u16) {
        let f = &mut self.t.fences[fence as usize];
        for i in 0..f.ref_count as usize {
            if f.refs[i] == res {
                return;
            }
        }
        if (f.ref_count as usize) < MAX_FENCE_REFS {
            let i = f.ref_count as usize;
            f.refs[i] = res;
            f.ref_gens[i] = self.t.resources[res as usize].generation;
            f.ref_count += 1;
            self.t.resources[res as usize].in_flight += 1;
        }
    }

    fn note_candidate(&mut self, fence: u16, res: u16) {
        let f = &mut self.t.fences[fence as usize];
        for i in 0..f.candidate_count as usize {
            if f.candidates[i] == res {
                return;
            }
        }
        if (f.candidate_count as usize) < MAX_FENCE_REFS {
            f.candidates[f.candidate_count as usize] = res;
            f.candidate_count += 1;
        }
    }

    // ── Submission ──────────────────────────────────────────────────────

    fn op_submit(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let queue = get_u8(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let wait_count = get_u8(p, 1).ok_or((REASON_MALFORMED, 0))? as usize;
        let _flags = get_u16(p, 2).ok_or((REASON_MALFORMED, 0))?;
        let item_len = get_u32(p, 4).ok_or((REASON_MALFORMED, 0))? as usize;
        if queue as usize >= QUEUE_COUNT {
            return Err((REASON_MALFORMED, queue as u32));
        }
        if queue == QUEUE_RASTER && self.limits.features & FEATURE_RASTER == 0 {
            return Err((REASON_UNSUPPORTED_FEATURE, FEATURE_RASTER));
        }
        if wait_count > MAX_WAITS {
            return Err((REASON_OVERSIZE, wait_count as u32));
        }
        let waits_off = 8;
        let items_off = waits_off + wait_count * 8;
        if p.len() < items_off + item_len {
            return Err((REASON_MALFORMED, 0));
        }
        if self.queue_depth[queue as usize] >= self.limits.max_queue_depth {
            return Err((REASON_QUEUE_FULL, queue as u32));
        }

        // Resolve waits first: every one must name a live fence of this
        // owner. A submission cannot wait on its own fence because that fence
        // does not exist until this validation passes — which is why the
        // wait graph is acyclic by construction.
        let mut waits = [NO_SLOT; MAX_WAITS];
        let mut wait_gens = [0u16; MAX_WAITS];
        for i in 0..wait_count {
            let h = get_u64(p, waits_off + i * 8).ok_or((REASON_MALFORMED, 0))?;
            let idx = self
                .check_handle(h, KIND_FENCE, owner)
                .map_err(|r| (r, 0))?;
            waits[i] = idx;
            wait_gens[i] = handle_generation(h);
        }

        // Walk the item list twice: once to validate everything, once (in the
        // caller's backend) to execute it. The validating walk is the only
        // one that decides anything, so an item the backend re-reads has
        // already been proven safe.
        let items = &p[items_off..items_off + item_len];
        let plan = self.validate_items(owner, queue, items)?;

        // Any uncommitted candidate this work reads must be published by a
        // fence it actually waits on. Without that check a submission could
        // read another's scratch mid-flight; with a blanket refusal instead,
        // a two-stage pipeline could never be admitted at all.
        for i in 0..plan.pending_count {
            let res = plan.pending[i];
            let covered = (0..wait_count).any(|w| {
                let wf = &self.t.fences[waits[w] as usize];
                wf.candidates[..wf.candidate_count as usize].contains(&res)
            });
            if !covered {
                return Err((REASON_NOT_READY, res as u32));
            }
        }

        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, queue)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        {
            let f = &mut self.t.fences[fence as usize];
            f.waits = waits;
            f.wait_gens = wait_gens;
            f.wait_count = wait_count as u8;
        }
        for i in 0..plan.ref_count {
            self.retain(fence, plan.refs[i]);
        }
        for i in 0..plan.candidate_count {
            self.note_candidate(fence, plan.candidates[i]);
        }
        self.queue_depth[queue as usize] += 1;
        if self.queue_depth[queue as usize] > self.stats.peak_queue_depth[queue as usize] {
            self.stats.peak_queue_depth[queue as usize] = self.queue_depth[queue as usize];
        }
        self.accept(fence, reserve);
        Ok(Work::Submit {
            fence,
            queue,
            items_offset: HEADER_LEN + items_off,
            items_len: item_len,
        })
    }

    /// Everything one submission touches, gathered by the validating walk.
    fn validate_items(&self, owner: u16, queue: u8, items: &[u8]) -> Result<ItemPlan, (u16, u32)> {
        let mut plan = ItemPlan::EMPTY;
        let mut off = 0usize;
        let mut in_pass = false;
        while off < items.len() {
            let op = items[off];
            off += 1;
            match op {
                ITEM_DISPATCH => {
                    if queue != QUEUE_COMPUTE {
                        return Err((REASON_MALFORMED, op as u32));
                    }
                    let binds = self.parse_binds(items, off, owner)?;
                    let next = binds.next;
                    let gx = get_u32(items, next).ok_or((REASON_MALFORMED, 0))?;
                    let gy = get_u32(items, next + 4).ok_or((REASON_MALFORMED, 0))?;
                    let gz = get_u32(items, next + 8).ok_or((REASON_MALFORMED, 0))?;
                    if gx == 0 || gy == 0 || gz == 0 {
                        return Err((REASON_MALFORMED, 0));
                    }
                    if gx > self.limits.max_grid[0]
                        || gy > self.limits.max_grid[1]
                        || gz > self.limits.max_grid[2]
                    {
                        return Err((REASON_OVERSIZE, gx));
                    }
                    self.check_bindings(items, &binds, owner, &mut plan)?;
                    off = next + 12;
                }
                ITEM_COPY => {
                    let src = get_u64(items, off).ok_or((REASON_MALFORMED, 0))?;
                    let dst = get_u64(items, off + 8).ok_or((REASON_MALFORMED, 0))?;
                    let len = get_u64(items, off + 16).ok_or((REASON_MALFORMED, 0))?;
                    if len == 0 {
                        return Err((REASON_MALFORMED, 0));
                    }
                    let (s_res, _) = self.resolve_read_range(src, owner, 0, len)?;
                    let (d_res, _) = self.resolve_write_range(dst, owner, 0, len)?;
                    if s_res == d_res {
                        return Err((REASON_ALIASED_OUTPUT, 0));
                    }
                    if self.candidate_pending(s_res) {
                        plan.add_pending(s_res)?;
                    }
                    plan.add_read(s_res)?;
                    plan.add_write(d_res, self.t.resources[d_res as usize].usage)?;
                    off += 24;
                }
                ITEM_BEGIN_PASS => {
                    if queue != QUEUE_RASTER || in_pass {
                        return Err((REASON_MALFORMED, op as u32));
                    }
                    let target = get_u64(items, off).ok_or((REASON_MALFORMED, 0))?;
                    let _flags = get_u32(items, off + 8).ok_or((REASON_MALFORMED, 0))?;
                    let _clear = get_u32(items, off + 12).ok_or((REASON_MALFORMED, 0))?;
                    let tidx = self.check_resource(target, owner).map_err(|r| (r, 0))?;
                    if self.t.resources[tidx as usize].usage & USAGE_RENDER_TARGET == 0 {
                        return Err((REASON_USAGE_DENIED, USAGE_RENDER_TARGET));
                    }
                    plan.add_write(tidx, self.t.resources[tidx as usize].usage)?;
                    in_pass = true;
                    off += 16;
                }
                ITEM_DRAW => {
                    if queue != QUEUE_RASTER || !in_pass {
                        return Err((REASON_MALFORMED, op as u32));
                    }
                    let binds = self.parse_binds(items, off, owner)?;
                    let next = binds.next;
                    let vertex = get_u64(items, next).ok_or((REASON_MALFORMED, 0))?;
                    let index = get_u64(items, next + 8).ok_or((REASON_MALFORMED, 0))?;
                    let _first = get_u32(items, next + 16).ok_or((REASON_MALFORMED, 0))?;
                    let count = get_u32(items, next + 20).ok_or((REASON_MALFORMED, 0))?;
                    let instances = get_u32(items, next + 24).ok_or((REASON_MALFORMED, 0))?;
                    if count == 0 || instances == 0 {
                        return Err((REASON_MALFORMED, 0));
                    }
                    self.check_bindings(items, &binds, owner, &mut plan)?;
                    // Geometry produced by a compute dispatch is read here
                    // directly — the compute→CPU→raster detour this contract
                    // exists to remove.
                    let vres = self.check_geometry(vertex, owner, USAGE_VERTEX)?;
                    if self.candidate_pending(vres) {
                        plan.add_pending(vres)?;
                    }
                    plan.add_read(vres)?;
                    if index != HANDLE_NONE {
                        let ires = self.check_geometry(index, owner, USAGE_INDEX)?;
                        if self.candidate_pending(ires) {
                            plan.add_pending(ires)?;
                        }
                        plan.add_read(ires)?;
                    }
                    off = next + 28;
                }
                ITEM_END_PASS => {
                    if !in_pass {
                        return Err((REASON_MALFORMED, op as u32));
                    }
                    in_pass = false;
                }
                _ => return Err((REASON_MALFORMED, op as u32)),
            }
        }
        if in_pass {
            return Err((REASON_MALFORMED, ITEM_BEGIN_PASS as u32));
        }
        // Aliasing check across the whole submission: a resource written by
        // this work may not also be read by it. Until in-place aliasing is
        // supported safely, the honest answer is a refusal rather than a
        // result whose correctness depends on execution order.
        for i in 0..plan.write_count {
            for j in 0..plan.read_count {
                if plan.writes[i] == plan.reads[j] {
                    return Err((REASON_ALIASED_OUTPUT, plan.writes[i] as u32));
                }
            }
        }
        Ok(plan)
    }

    /// `[pipeline u64][bind_count u16][pad u16][entries…]` — answers the
    /// pipeline slot, the byte range of the binding entries, and the offset
    /// just past them.
    fn parse_binds(&self, items: &[u8], off: usize, owner: u16) -> Result<Binds, (u16, u32)> {
        let ph = get_u64(items, off).ok_or((REASON_MALFORMED, 0))?;
        let n = get_u16(items, off + 8).ok_or((REASON_MALFORMED, 0))? as usize;
        if n > self.limits.max_bindings as usize {
            return Err((REASON_OVERSIZE, n as u32));
        }
        let start = off + 12;
        let end = start
            .checked_add(n * BIND_ENTRY_LEN)
            .ok_or((REASON_MALFORMED, 0))?;
        if end > items.len() {
            return Err((REASON_MALFORMED, 0));
        }
        let pipe = self
            .check_handle(ph, KIND_PIPELINE, owner)
            .map_err(|r| (r, 0))?;
        if !self.t.pipelines[pipe as usize].ready {
            // Never "skip the dispatch and report success". The caller is
            // told the pipeline is still compiling and can retry.
            return Err((REASON_NOT_READY, 0));
        }
        Ok(Binds {
            pipeline: pipe,
            start,
            count: n,
            next: end,
        })
    }

    /// Check every binding against the program's declared layout, in both
    /// directions: no binding the program did not declare, and none of the
    /// program's declared bindings left unsupplied.
    fn check_bindings(
        &self,
        items: &[u8],
        binds: &Binds,
        owner: u16,
        plan: &mut ItemPlan,
    ) -> Result<(), (u16, u32)> {
        let Binds {
            pipeline: pipe,
            start,
            count: n,
            ..
        } = *binds;
        let pl = self.t.pipelines[pipe as usize];
        let prog = &self.t.programs[pl.program as usize];
        if !prog.live || prog.generation != pl.program_gen {
            return Err((REASON_BAD_HANDLE, 0));
        }
        let mut supplied = 0usize;
        for i in 0..n {
            let e = start + i * BIND_ENTRY_LEN;
            let slot = get_u16(items, e).ok_or((REASON_MALFORMED, 0))?;
            let vh = get_u64(items, e + 4).ok_or((REASON_MALFORMED, 0))?;
            let decl = (0..prog.binding_count as usize)
                .map(|k| prog.bindings[k])
                .find(|b| b.slot == slot)
                .ok_or((REASON_MALFORMED, slot as u32))?;
            let vidx = self
                .check_handle(vh, KIND_VIEW, owner)
                .map_err(|r| (r, 0))?;
            let v = self.t.views[vidx as usize];
            let res = &self.t.resources[v.resource as usize];
            if !res.live || res.generation != v.resource_gen {
                return Err((REASON_BAD_HANDLE, 0));
            }
            if v.rights & RIGHT_BIND == 0 {
                return Err((REASON_ACCESS_DENIED, RIGHT_BIND));
            }
            if res.residency != RESIDENCY_RESIDENT {
                return Err((REASON_RESIDENCY, res.residency as u32));
            }
            // The usage the program's binding kind needs must be one the
            // resource was actually created with.
            let need_usage = match decl.kind {
                BIND_STORAGE => USAGE_STORAGE,
                BIND_UNIFORM => USAGE_UNIFORM,
                BIND_TEXTURE => USAGE_TEXTURE_SAMPLE,
                BIND_SAMPLER => USAGE_TEXTURE_SAMPLE,
                BIND_VERTEX => USAGE_VERTEX,
                BIND_INDEX => USAGE_INDEX,
                _ => return Err((REASON_BAD_KIND, decl.kind as u32)),
            };
            if v.usage & need_usage == 0 {
                return Err((REASON_USAGE_DENIED, need_usage));
            }
            if v.length < decl.min_size as u64 {
                return Err((REASON_BAD_RANGE, decl.min_size));
            }
            if decl.align == 0 || !v.offset.is_multiple_of(u64::from(decl.align)) {
                return Err((REASON_BAD_ALIGNMENT, decl.align));
            }
            // Rights are checked for each access the binding declares…
            if decl.access & BIND_ACCESS_READ != 0 && v.rights & RIGHT_READ == 0 {
                return Err((REASON_ACCESS_DENIED, RIGHT_READ));
            }
            if decl.access & BIND_ACCESS_WRITE != 0 {
                if v.rights & RIGHT_WRITE == 0 {
                    return Err((REASON_ACCESS_DENIED, RIGHT_WRITE));
                }
                if res.sealed {
                    return Err((REASON_SEALED, 0));
                }
            }
            // …but the aliasing plan records ONE role per binding. A binding
            // declared read-write is an in-place update: one binding, one
            // range, and the program's own declaration that the input is the
            // output. Recording it as both would make every in-place kernel
            // alias itself and be refused, while the aliasing this check
            // exists for — two DIFFERENT bindings naming one resource, one
            // reading and one writing — is still caught.
            if decl.access & BIND_ACCESS_WRITE != 0 {
                plan.add_write(v.resource, res.usage)?;
            } else {
                if res.usage & USAGE_CANDIDATE != 0 && !res.published {
                    plan.add_pending(v.resource)?;
                }
                plan.add_read(v.resource)?;
            }
            supplied += 1;
        }
        // A program whose binding was left unbound would read whatever the
        // backend happened to leave in that slot.
        if supplied != prog.binding_count as usize {
            return Err((REASON_MALFORMED, prog.binding_count as u32));
        }
        Ok(())
    }

    fn check_geometry(&self, vh: u64, owner: u16, usage: u32) -> Result<u16, (u16, u32)> {
        let vidx = self
            .check_handle(vh, KIND_VIEW, owner)
            .map_err(|r| (r, 0))?;
        let v = self.t.views[vidx as usize];
        if v.usage & usage == 0 {
            return Err((REASON_USAGE_DENIED, usage));
        }
        if v.rights & (RIGHT_READ | RIGHT_BIND) != (RIGHT_READ | RIGHT_BIND) {
            return Err((REASON_ACCESS_DENIED, RIGHT_READ | RIGHT_BIND));
        }
        let res = &self.t.resources[v.resource as usize];
        if !res.live || res.generation != v.resource_gen {
            return Err((REASON_BAD_HANDLE, 0));
        }
        if res.residency != RESIDENCY_RESIDENT {
            return Err((REASON_RESIDENCY, res.residency as u32));
        }
        Ok(v.resource)
    }

    // ── Fence operations ────────────────────────────────────────────────

    fn op_poll_fence(&mut self, owner: u16, hdr: &Header, p: &[u8]) -> Result<Work, (u16, u32)> {
        let h = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let idx = self
            .check_handle(h, KIND_FENCE, owner)
            .map_err(|r| (r, 0))?;
        let f = self.t.fences[idx as usize];
        if f.state != FENCE_TERMINAL {
            return Err((REASON_NOT_READY, 0));
        }
        // Re-emit the terminal record against THIS poll's correlation. The
        // fence's own record still stands against the original correlation;
        // polling is a read, not an acknowledgement.
        let corr = hdr.corr;
        self.emit_terminal_record(idx, corr);
        Ok(Work::None)
    }

    fn op_release_fence(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let h = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let idx = self
            .check_handle(h, KIND_FENCE, owner)
            .map_err(|r| (r, 0))?;
        let f = self.t.fences[idx as usize];
        if f.state != FENCE_TERMINAL {
            return Err((REASON_IN_FLIGHT, 0));
        }
        if !f.delivered {
            // The result has not left the ring yet; releasing now is exactly
            // the "drop bytes to make room" this contract refuses.
            return Err((REASON_NOT_READY, 0));
        }
        // Release BEFORE allocating the acknowledgement's own fence. The other
        // order deadlocks a full table: the one operation that frees a slot
        // would itself be refused for want of one.
        self.release_fence_slot(idx);
        let ack = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        self.accept(ack, reserve);
        self.settle_now(ack);
        Ok(Work::None)
    }

    fn op_cancel(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let h = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let target = self
            .check_handle(h, KIND_FENCE, owner)
            .map_err(|r| (r, 0))?;
        let ack = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        self.accept(ack, reserve);
        let state = self.t.fences[target as usize].state;
        match state {
            FENCE_WAITING | FENCE_READY => {
                // Not yet handed to the device: the reservation really can be
                // released and nothing ran.
                self.finish(target, OUT_CANCELLED, 0, 0, CANCEL_PRE_DISPATCH, 0);
                self.settle_now(ack);
                Ok(Work::None)
            }
            FENCE_RUNNING => {
                // The device has it. Publication is suppressed; the hardware
                // finishes on its own schedule. Saying otherwise would be a
                // promise no driver here can keep.
                self.t.fences[target as usize].cancel_requested = true;
                self.settle_now(ack);
                Ok(Work::Cancel { fence: ack, target })
            }
            _ => {
                self.settle_now(ack);
                Ok(Work::None)
            }
        }
    }

    fn op_drain(&mut self, owner: u16, hdr: &Header, reserve: usize) -> Result<Work, (u16, u32)> {
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        self.accept(fence, reserve);
        // Completed by `advance` once nothing else is in flight — and by the
        // backend only when the device is physically quiescent, which is why
        // this returns work rather than settling here.
        Ok(Work::Drain { fence })
    }

    fn op_reset(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let _scope = get_u8(p, 0).ok_or((REASON_MALFORMED, 0))?;
        if self.limits.features & FEATURE_DEVICE_RESET == 0 {
            return Err((REASON_UNSUPPORTED_FEATURE, FEATURE_DEVICE_RESET));
        }
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        self.accept(fence, reserve);
        let old = self.epoch;
        let new = self.bump_epoch(fence);
        Ok(Work::Reset {
            fence,
            old_epoch: old,
            new_epoch: new,
        })
    }

    fn op_export_surface(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        if self.limits.features & FEATURE_SHARED_SURFACE == 0 {
            return Err((REASON_UNSUPPORTED_FEATURE, FEATURE_SHARED_SURFACE));
        }
        let vh = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let width = get_u32(p, 8).ok_or((REASON_MALFORMED, 0))?;
        let height = get_u32(p, 12).ok_or((REASON_MALFORMED, 0))?;
        let format = get_u32(p, 16).ok_or((REASON_MALFORMED, 0))?;
        let colour = get_u32(p, 20).ok_or((REASON_MALFORMED, 0))?;
        if width == 0 || height == 0 {
            return Err((REASON_MALFORMED, 0));
        }
        let vidx = self
            .check_handle(vh, KIND_VIEW, owner)
            .map_err(|r| (r, 0))?;
        let v = self.t.views[vidx as usize];
        if v.usage & USAGE_SCANOUT == 0 {
            return Err((REASON_USAGE_DENIED, USAGE_SCANOUT));
        }
        if v.rights & RIGHT_GRANT == 0 {
            return Err((REASON_ACCESS_DENIED, RIGHT_GRANT));
        }
        let res = self.t.resources[v.resource as usize];
        if !res.live || res.generation != v.resource_gen {
            return Err((REASON_BAD_HANDLE, 0));
        }
        // A sink scans out of this memory directly, so it must actually be
        // there. Every other path that hands a resource to hardware checks
        // this; leaving it out here would let a lease name storage the device
        // has evicted, and the sink would read whatever now occupies it.
        if res.residency != RESIDENCY_RESIDENT {
            return Err((REASON_RESIDENCY, res.residency as u32));
        }
        // A frame that has not been committed is not presentable, for the
        // same reason it is not readable.
        if res.usage & USAGE_CANDIDATE != 0 && !res.published {
            return Err((REASON_NOT_READY, 0));
        }
        // The whole span stays in `u64`. Narrowing the stride first would
        // put the overflow in the cast rather than the multiply, where no
        // `checked_` can see it: a width of 0x4000_0000 gives a stride of
        // zero, and a zero stride passes every length check there is.
        let stride = (width as u64).checked_mul(4).ok_or((REASON_BAD_RANGE, 0))?;
        let need = stride
            .checked_mul(height as u64)
            .ok_or((REASON_BAD_RANGE, 0))?;
        // Narrowed only once the span is known to fit, and refused rather
        // than truncated if it does not.
        let stride_u32 = u32::try_from(stride).map_err(|_| (REASON_BAD_RANGE, 0))?;
        if need > v.length {
            return Err((REASON_BAD_RANGE, 0));
        }
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_RASTER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        let slot = match self.alloc_surface() {
            Some(s) => s,
            None => {
                self.release_fence_slot(fence);
                return Err((REASON_HANDLE_EXHAUSTED, 0));
            }
        };
        self.surface_sequence = self.surface_sequence.wrapping_add(1);
        let sequence = self.surface_sequence;
        let fence_handle =
            self.handle_for(KIND_FENCE, fence, self.t.fences[fence as usize].generation);
        {
            let s = &mut self.t.surfaces[slot as usize];
            s.owner = owner;
            s.view = vidx;
            s.view_gen = v.generation;
            s.producer_fence = fence_handle;
            s.width = width;
            s.height = height;
            s.stride = stride_u32;
            s.format = format;
            s.colour_space = colour;
            s.sequence = sequence;
            // Whether the import is genuinely zero-copy is the backend's fact
            // to set once it knows; claiming it here would be the unmeasured
            // claim this contract refuses.
            s.flags = 0;
        }
        self.retain(fence, v.resource);
        self.accept(fence, reserve);
        let handle = self.handle_for(
            KIND_SURFACE,
            slot,
            self.t.surfaces[slot as usize].generation,
        );
        self.emit_handle(fence, handle);
        let desc = self.encode_surface(slot);
        self.emit(OUT_SURFACE, hdr.corr, &desc, HEADER_LEN + SURFACE_LEN);
        let f = &mut self.t.fences[fence as usize];
        f.ring_reserved = f
            .ring_reserved
            .saturating_sub((HEADER_LEN + SURFACE_LEN) as u32);
        Ok(Work::ExportSurface { fence, slot })
    }

    /// Encode a surface lease descriptor.
    #[must_use]
    pub fn encode_surface(&self, slot: u16) -> [u8; SURFACE_LEN] {
        let mut d = [0u8; SURFACE_LEN];
        let s = self.t.surfaces[slot as usize];
        put_u64(
            &mut d,
            SURFACE_HANDLE,
            self.handle_for(KIND_SURFACE, slot, s.generation),
        );
        put_u32(&mut d, SURFACE_PROVIDER_EPOCH, self.provider_epoch);
        put_u32(&mut d, SURFACE_DEVICE_EPOCH, self.epoch as u32);
        put_u64(
            &mut d,
            SURFACE_RESOURCE,
            self.handle_for(KIND_VIEW, s.view, s.view_gen),
        );
        put_u64(&mut d, SURFACE_PRODUCER_FENCE, s.producer_fence);
        put_u32(&mut d, SURFACE_WIDTH, s.width);
        put_u32(&mut d, SURFACE_HEIGHT, s.height);
        put_u32(&mut d, SURFACE_STRIDE, s.stride);
        put_u32(&mut d, SURFACE_FORMAT, s.format);
        put_u32(&mut d, SURFACE_COLOUR_SPACE, s.colour_space);
        put_u32(&mut d, SURFACE_DAMAGE_W, s.width);
        put_u32(&mut d, SURFACE_DAMAGE_H, s.height);
        put_u32(&mut d, SURFACE_SEQUENCE, s.sequence);
        put_u32(&mut d, SURFACE_FLAGS, s.flags);
        d
    }

    fn op_release_surface(
        &mut self,
        owner: u16,
        hdr: &Header,
        p: &[u8],
        reserve: usize,
    ) -> Result<Work, (u16, u32)> {
        let h = get_u64(p, 0).ok_or((REASON_MALFORMED, 0))?;
        let idx = self
            .check_handle(h, KIND_SURFACE, owner)
            .map_err(|r| (r, 0))?;
        let fence = self
            .alloc_fence(owner, hdr.op, hdr.corr, QUEUE_TRANSFER)
            .ok_or((REASON_FENCE_EXHAUSTED, 0))?;
        self.t.surfaces[idx as usize].live = false;
        self.accept(fence, reserve);
        self.settle_now(fence);
        Ok(Work::None)
    }

    // ── Backend callbacks ───────────────────────────────────────────────

    /// The backend has handed `fence` to the device.
    pub fn mark_running(&mut self, fence: u16) {
        if let Some(f) = self.t.fences.get_mut(fence as usize) {
            if f.state == FENCE_READY || f.state == FENCE_WAITING {
                f.state = FENCE_RUNNING;
            }
        }
    }

    /// The backend finished `fence` successfully.
    ///
    /// `gpu_nanos` is a real GPU timestamp or `0`. A CPU submit-to-poll
    /// interval is not one, and passing it here would make every latency
    /// number downstream wrong in a way nobody could see.
    pub fn complete(&mut self, fence: u16, gpu_nanos: u64) {
        let flags = if self.limits.features & FEATURE_TIMESTAMP != 0 && gpu_nanos != 0 {
            0
        } else {
            COMPLETED_QUEUE_TIMED
        };
        if self
            .t
            .fences
            .get(fence as usize)
            .is_some_and(|f| f.cancel_requested)
        {
            // The work ran; only its publication was suppressed. That is the
            // honest disposition, not "cancelled before it started".
            self.finish(fence, OUT_CANCELLED, 0, 0, CANCEL_SUPPRESSED, gpu_nanos);
            return;
        }
        self.finish(fence, OUT_COMPLETED, 0, flags, 0, gpu_nanos);
    }

    /// The backend failed `fence`. No candidate output is published.
    pub fn fail(&mut self, fence: u16, reason: u16, detail: u32) {
        self.finish(fence, OUT_FAILED, reason, detail, 0, 0);
    }

    /// Deliver readback bytes for `fence`.
    ///
    /// Answers false when the outcome ring is full: the bytes stay owed and
    /// the fence stays non-terminal. Retry after draining. Nothing is ever
    /// dropped, because a lost result and work that never ran look identical
    /// to a consumer.
    pub fn push_result(&mut self, fence: u16, offset: u64, bytes: &[u8]) -> bool {
        let Some(f) = self.t.fences.get(fence as usize) else {
            return false;
        };
        if f.state == FENCE_FREE || f.state == FENCE_TERMINAL {
            return false;
        }
        let corr = f.corr;
        let need = HEADER_LEN + RESULT_PREFIX + bytes.len();
        if bytes.len() > (MAX_PAYLOAD as usize - RESULT_PREFIX) {
            return false;
        }
        // Result bytes are unreserved, so they draw on free space only —
        // never on the room another fence is holding for its terminal record.
        // Spending that would trade a stall this caller retries for an
        // outcome some other request could never deliver.
        if self.ring_free() < need {
            self.stats.output_stalls += 1;
            return false;
        }
        let fh = self.handle_for(KIND_FENCE, fence, self.t.fences[fence as usize].generation);
        // Build the record in place: header, then the fixed fields, then the
        // bytes — no intermediate copy of a payload that may be 64 KiB.
        let start = self.out_len;
        let total = HEADER_LEN + RESULT_PREFIX + bytes.len();
        let out = &mut self.t.outcomes[start..start + total];
        out[..HEADER_LEN].copy_from_slice(
            &Header::new(OUT_RESULT, (RESULT_PREFIX + bytes.len()) as u32, corr).encode(),
        );
        let body = &mut out[HEADER_LEN..];
        put_u64(body, 0, fh);
        put_u64(body, 8, offset);
        put_u32(body, 16, bytes.len() as u32);
        body[24..].copy_from_slice(bytes);
        self.out_len += total;
        self.stats.readback_bytes += bytes.len() as u64;
        let f = &mut self.t.fences[fence as usize];
        f.result_sent = f.result_sent.saturating_add(bytes.len() as u64);
        true
    }

    /// The largest result payload [`Self::push_result`] would accept now.
    ///
    /// A backend sizes its chunk from this rather than from a constant. The
    /// ring's free space is the device's to know, and it moves: a fixed chunk
    /// is either smaller than the ring could have taken, or refused outright
    /// and re-offered at the same size next step, which is how a readback
    /// stops making progress rather than merely slowing down. Zero means the
    /// ring has no room at all right now; drain and ask again.
    #[must_use]
    pub fn max_result_chunk(&self) -> usize {
        self.ring_free()
            .saturating_sub(HEADER_LEN + RESULT_PREFIX)
            .min(MAX_PAYLOAD as usize - RESULT_PREFIX)
    }

    /// Whether `fence` still owes result bytes.
    #[must_use]
    pub fn result_outstanding(&self, fence: u16) -> u64 {
        self.t
            .fences
            .get(fence as usize)
            .map_or(0, |f| f.result_len.saturating_sub(f.result_sent))
    }

    /// The backend built a pipeline. Readiness is set here and only here.
    pub fn mark_pipeline_ready(&mut self, slot: u16, ok: bool) {
        let Some(p) = self.t.pipelines.get_mut(slot as usize) else {
            return;
        };
        p.ready = ok;
        if !ok {
            p.live = false;
        }
    }

    /// Whether a resource's storage may now be released — the handle was
    /// retired and nothing in flight can still reach it.
    #[must_use]
    pub fn resource_free_pending(&self, slot: u16) -> bool {
        self.t
            .resources
            .get(slot as usize)
            .is_some_and(|s| s.live && s.retiring && s.in_flight == 0)
    }

    fn finish(
        &mut self,
        fence: u16,
        outcome: u16,
        reason: u16,
        detail: u32,
        disposition: u8,
        gpu_nanos: u64,
    ) {
        let Some(f) = self.t.fences.get(fence as usize) else {
            return;
        };
        if f.state == FENCE_TERMINAL || f.state == FENCE_FREE {
            // Exactly one terminal outcome per accepted request. A backend
            // that reports twice — a late callback, a double release — is
            // ignored rather than allowed to emit a second record.
            return;
        }
        // A readback that still owes bytes is not finished. Deliver the rest
        // first; the caller retries once the ring drains.
        if outcome == OUT_COMPLETED && f.result_len > f.result_sent {
            return;
        }
        let queue = f.queue as usize;
        let staging = f.staging_bytes;
        let ref_count = f.ref_count as usize;
        let cand_count = f.candidate_count as usize;
        let refs = f.refs;
        let ref_gens = f.ref_gens;
        let candidates = f.candidates;
        let op = f.op;

        {
            let f = &mut self.t.fences[fence as usize];
            f.state = FENCE_TERMINAL;
            f.outcome = outcome;
            f.reason = reason;
            f.detail = detail;
            f.disposition = disposition;
            f.gpu_nanos = gpu_nanos;
        }
        if op == OP_SUBMIT && queue < QUEUE_COUNT {
            self.queue_depth[queue] = self.queue_depth[queue].saturating_sub(1);
        }
        self.staging_bytes = self.staging_bytes.saturating_sub(staging);

        // Output commit. This is the ONLY place a candidate becomes readable,
        // and it happens only on success — a failed or cancelled request
        // leaves its scratch exactly as unreadable as before it ran.
        if outcome == OUT_COMPLETED {
            for &cand in &candidates[..cand_count] {
                if let Some(r) = self.t.resources.get_mut(cand as usize) {
                    r.published = true;
                }
            }
        }

        // Release resource references, and free anything whose destroy was
        // waiting on exactly this.
        for i in 0..ref_count {
            let idx = refs[i];
            let Some(r) = self.t.resources.get_mut(idx as usize) else {
                continue;
            };
            if r.generation == ref_gens[i] {
                r.in_flight = r.in_flight.saturating_sub(1);
            }
            if r.live && r.retiring && r.in_flight == 0 {
                self.free_resource(idx);
            }
        }

        match outcome {
            OUT_COMPLETED => self.stats.completed += 1,
            OUT_FAILED => self.stats.failed += 1,
            OUT_CANCELLED => self.stats.cancelled += 1,
            OUT_DEVICE_LOST => self.stats.device_losses += 1,
            _ => {}
        }

        let corr = self.t.fences[fence as usize].corr;
        self.emit_terminal_record(fence, corr);
    }

    /// Write the fence's terminal record against `corr`.
    ///
    /// The draw on the outcome ring is decided here rather than by the
    /// caller, because only one of the two callers is delivering: `finish`
    /// spends the reservation taken for this record at admission, while a
    /// poll re-reads an outcome already delivered and draws on the free
    /// space admission proved was there. A caller that passed the wrong one
    /// would either double-spend the reservation or strand it forever.
    fn emit_terminal_record(&mut self, fence: u16, corr: u64) {
        let f = self.t.fences[fence as usize];
        let fh = self.handle_for(KIND_FENCE, fence, f.generation);
        let mut payload = [0u8; 24];
        put_u64(&mut payload, 0, fh);
        let len = match f.outcome {
            OUT_COMPLETED => {
                put_u32(&mut payload, 8, COMPLETED_PUBLISHED | f.detail);
                put_u64(&mut payload, 16, f.gpu_nanos);
                24
            }
            OUT_FAILED => {
                put_u16(&mut payload, 8, f.reason);
                put_u32(&mut payload, 12, f.detail);
                16
            }
            OUT_CANCELLED => {
                payload[8] = f.disposition;
                16
            }
            OUT_DEVICE_LOST => {
                put_u16(&mut payload, 8, f.reason);
                put_u32(&mut payload, 12, f.detail);
                16
            }
            _ => return,
        };
        let from_reserved = if f.delivered {
            0
        } else {
            f.ring_reserved as usize
        };
        if self.emit(f.outcome, corr, &payload[..len], from_reserved) {
            self.t.fences[fence as usize].delivered = true;
            self.t.fences[fence as usize].ring_reserved = 0;
        }
    }

    fn release_fence_slot(&mut self, idx: u16) {
        let f = &mut self.t.fences[idx as usize];
        let reserved = f.ring_reserved as usize;
        // Cleared, not merely marked free. Every other field is still read by
        // passes that scan the whole table, and `op` in particular decides
        // whether a slot is treated as a drain — so a freed slot that kept its
        // last life's `op` would be picked up as live work it never was.
        // The generation survives: it is what makes a handle to the old fence
        // refusable rather than a handle to whatever lands here next.
        let generation = f.generation;
        *f = FenceSlot::EMPTY;
        f.generation = generation;
        self.out_reserved = self.out_reserved.saturating_sub(reserved);
    }

    // ── Scheduling ──────────────────────────────────────────────────────

    /// Advance dependency state. Call once per step, before asking for
    /// runnable work.
    ///
    /// Does three things and nothing else: propagates dependency outcomes,
    /// promotes satisfied waits to `READY`, and completes a drain once the
    /// device has nothing left in flight.
    pub fn advance(&mut self) {
        // A terminal record the ring could not take is owed, not lost. The
        // fence stays unreleasable until its outcome reaches the consumer, so
        // without a retry it would never be released at all — the slot, and
        // the reservation with it, would be gone for the life of the device.
        for idx in 0..self.t.fences.len() {
            let f = self.t.fences[idx];
            if f.state == FENCE_TERMINAL && !f.delivered {
                self.stats.terminal_retries += 1;
                let corr = f.corr;
                self.emit_terminal_record(idx as u16, corr);
            }
        }

        // Propagate failures and cancellations down the wait graph. Bounded:
        // one pass per call, and a chain of N fences resolves in N calls,
        // which keeps a step's work independent of graph depth.
        for idx in 0..self.t.fences.len() {
            let f = self.t.fences[idx];
            if f.state != FENCE_WAITING {
                continue;
            }
            // A drain declares no waits, so the general rule ("no unmet waits
            // means runnable") would promote it immediately and defeat the
            // quiescence pass below, which is the only thing that makes a
            // drain mean anything.
            if f.op == OP_DRAIN {
                continue;
            }
            let mut all_done = true;
            let mut poisoned: Option<(u16, u8)> = None;
            for i in 0..f.wait_count as usize {
                let w = f.waits[i] as usize;
                let Some(wf) = self.t.fences.get(w) else {
                    poisoned = Some((OUT_FAILED, 0));
                    break;
                };
                if wf.generation != f.wait_gens[i] || wf.state == FENCE_FREE {
                    // The dependency was released out from under this work.
                    poisoned = Some((OUT_FAILED, 0));
                    break;
                }
                if wf.state != FENCE_TERMINAL {
                    all_done = false;
                    continue;
                }
                match wf.outcome {
                    OUT_COMPLETED => {}
                    OUT_CANCELLED => {
                        poisoned = Some((OUT_CANCELLED, CANCEL_DEPENDENCY));
                        break;
                    }
                    _ => {
                        poisoned = Some((OUT_FAILED, 0));
                        break;
                    }
                }
            }
            if let Some((outcome, disp)) = poisoned {
                if outcome == OUT_FAILED {
                    self.finish(idx as u16, OUT_FAILED, REASON_DEPENDENCY_FAILED, 0, 0, 0);
                } else {
                    self.finish(idx as u16, OUT_CANCELLED, 0, 0, disp, 0);
                }
                continue;
            }
            if all_done {
                self.t.fences[idx].state = FENCE_READY;
            }
        }

        // A drain completes only when nothing else of any owner is still in
        // flight. Channel drainage does not prove a device is idle; the
        // absence of non-terminal fences is the closest fact this core owns,
        // and the backend still gates on physical quiescence before calling
        // `complete`.
        for idx in 0..self.t.fences.len() {
            // `op` means nothing on a slot that holds no request, so state is
            // read first: a free slot is not a drain, whatever it last was.
            if !matches!(
                self.t.fences[idx].state,
                FENCE_WAITING | FENCE_READY | FENCE_RUNNING
            ) || self.t.fences[idx].op != OP_DRAIN
            {
                continue;
            }
            let busy = self.t.fences.iter().enumerate().any(|(j, f)| {
                j != idx
                    && matches!(f.state, FENCE_WAITING | FENCE_READY | FENCE_RUNNING)
                    && f.op != OP_DRAIN
            });
            if !busy {
                self.t.fences[idx].state = FENCE_READY;
            }
        }
    }

    /// The next fence whose dependencies are met and that the backend has not
    /// been handed yet. Answers `None` when there is nothing to start.
    pub fn next_ready(&mut self) -> Option<u16> {
        (0..self.t.fences.len())
            .find(|&i| self.t.fences[i].state == FENCE_READY)
            .map(|i| i as u16)
    }

    /// Whether anything is still in flight.
    #[must_use]
    pub fn quiescent(&self) -> bool {
        !self
            .t
            .fences
            .iter()
            .any(|f| matches!(f.state, FENCE_WAITING | FENCE_READY | FENCE_RUNNING))
    }

    /// End the current device epoch, terminating everything outstanding.
    ///
    /// `keep` names a fence that survives — the reset request's own, which
    /// must still be able to report that the reset happened. Every other
    /// accepted request terminates with `OUT_DEVICE_LOST`, every handle of
    /// the old epoch stops resolving, and every resource is marked lost
    /// rather than silently reused: the consumer rebuilds derived state, and
    /// nothing it held before the reset can be mistaken for something valid
    /// after it.
    ///
    /// Answers the new epoch.
    pub fn bump_epoch(&mut self, keep: u16) -> u16 {
        let old = self.epoch;
        let mut blast = 0u32;
        for idx in 0..self.t.fences.len() {
            if idx as u16 == keep {
                continue;
            }
            if matches!(
                self.t.fences[idx].state,
                FENCE_WAITING | FENCE_READY | FENCE_RUNNING
            ) {
                blast += 1;
                self.finish(idx as u16, OUT_DEVICE_LOST, REASON_DEVICE_LOST, 0, 0, 0);
            }
        }
        for r in self.t.resources.iter_mut() {
            if r.live {
                r.residency = RESIDENCY_LOST;
                r.live = false;
                r.retiring = false;
                r.published = false;
                r.in_flight = 0;
            }
        }
        for v in self.t.views.iter_mut() {
            v.live = false;
        }
        for p in self.t.programs.iter_mut() {
            p.live = false;
        }
        for p in self.t.pipelines.iter_mut() {
            p.live = false;
            p.ready = false;
        }
        for s in self.t.surfaces.iter_mut() {
            s.live = false;
        }
        // The reset IS the verified quiescence, so the memory the old epoch
        // held is genuinely reclaimable now — which is exactly why a timeout
        // alone, with no reset, does not free anything.
        self.resident_bytes = 0;
        self.staging_bytes = 0;
        self.queue_depth = [0; QUEUE_COUNT];
        self.epoch = self.epoch.wrapping_add(1);
        if self.epoch == 0 {
            self.epoch = 1;
        }
        self.stats.device_losses += 1;
        // Announce the epoch change once, so a consumer that was not waiting
        // on any fence still learns its handles are gone.
        let mut p = [0u8; 16];
        put_u32(&mut p, 0, old as u32);
        put_u32(&mut p, 4, self.epoch as u32);
        put_u16(&mut p, 8, REASON_DEVICE_LOST);
        put_u32(&mut p, 12, blast);
        self.emit(OUT_DEVICE_LOST, 0, &p, 0);
        self.epoch
    }

    /// Walk a validated submission's items. The backend uses this to execute
    /// what admission already proved safe, so there is one item decoder
    /// rather than a validating one and an executing one that can disagree.
    #[must_use]
    pub fn items<'p>(&self, payload: &'p [u8], offset: usize, len: usize) -> ItemWalk<'p> {
        let end = offset.saturating_add(len).min(payload.len());
        ItemWalk {
            bytes: &payload[offset.min(end)..end],
            off: 0,
        }
    }

    /// Resolve a handle the backend received in an item to its table slot.
    /// Answers `None` for a handle that no longer resolves — which, after a
    /// mid-walk epoch bump, is the correct answer rather than a panic.
    #[must_use]
    pub fn slot_of(&self, handle: u64, kind: u8, owner: u16) -> Option<u16> {
        self.check_handle(handle, kind, owner).ok()
    }

    /// The resource a view names, and the absolute byte range it covers.
    #[must_use]
    pub fn view_range(&self, view_slot: u16) -> Option<(u16, u64, u64)> {
        let v = self.t.views.get(view_slot as usize)?;
        if !v.live {
            return None;
        }
        Some((v.resource, v.offset, v.length))
    }

    /// Read-only access to a resource slot, for a backend that keeps its own
    /// parallel table of device objects.
    #[must_use]
    pub fn resource(&self, slot: u16) -> Option<&ResourceSlot> {
        self.t.resources.get(slot as usize)
    }

    #[must_use]
    pub fn program(&self, slot: u16) -> Option<&ProgramSlot> {
        self.t.programs.get(slot as usize)
    }

    #[must_use]
    pub fn pipeline(&self, slot: u16) -> Option<&PipelineSlot> {
        self.t.pipelines.get(slot as usize)
    }

    #[must_use]
    pub fn fence(&self, slot: u16) -> Option<&FenceSlot> {
        self.t.fences.get(slot as usize)
    }

    #[must_use]
    pub fn surface(&self, slot: u16) -> Option<&SurfaceSlot> {
        self.t.surfaces.get(slot as usize)
    }

    /// Record how a surface lease is actually satisfied. Set by the sink once
    /// it knows, because whether an import was zero-copy is a measurement,
    /// not a hope.
    pub fn set_surface_flags(&mut self, slot: u16, flags: u32) {
        if let Some(s) = self.t.surfaces.get_mut(slot as usize) {
            s.flags = flags;
        }
    }
}

/// Generations skip zero so a handle's generation field is never zero on a
/// live slot, which makes the all-zero handle unambiguously "none".
fn next_gen(g: u16) -> u16 {
    let n = g.wrapping_add(1);
    if n == 0 {
        1
    } else {
        n
    }
}

/// One item's binding table, located but not yet checked.
///
/// `next` is where the item's own fields begin, immediately after the table —
/// the caller reads its grid or its geometry from there.
#[derive(Clone, Copy)]
struct Binds {
    pipeline: u16,
    start: usize,
    count: usize,
    next: usize,
}

/// What a submission reads and writes, gathered during validation.
#[derive(Clone, Copy)]
struct ItemPlan {
    reads: [u16; MAX_FENCE_REFS],
    read_count: usize,
    writes: [u16; MAX_FENCE_REFS],
    write_count: usize,
    refs: [u16; MAX_FENCE_REFS],
    ref_count: usize,
    candidates: [u16; MAX_FENCE_REFS],
    candidate_count: usize,
    /// Uncommitted candidates this work reads. Each must be covered by a
    /// declared wait on the fence that publishes it.
    pending: [u16; MAX_FENCE_REFS],
    pending_count: usize,
}

impl ItemPlan {
    const EMPTY: Self = Self {
        reads: [NO_SLOT; MAX_FENCE_REFS],
        read_count: 0,
        writes: [NO_SLOT; MAX_FENCE_REFS],
        write_count: 0,
        refs: [NO_SLOT; MAX_FENCE_REFS],
        ref_count: 0,
        candidates: [NO_SLOT; MAX_FENCE_REFS],
        candidate_count: 0,
        pending: [NO_SLOT; MAX_FENCE_REFS],
        pending_count: 0,
    };

    fn add_pending(&mut self, res: u16) -> Result<(), (u16, u32)> {
        if self.pending[..self.pending_count].contains(&res) {
            return Ok(());
        }
        if self.pending_count == MAX_FENCE_REFS {
            return Err((REASON_OVERSIZE, MAX_FENCE_REFS as u32));
        }
        self.pending[self.pending_count] = res;
        self.pending_count += 1;
        Ok(())
    }

    fn add_ref(&mut self, res: u16) -> Result<(), (u16, u32)> {
        if self.refs[..self.ref_count].contains(&res) {
            return Ok(());
        }
        if self.ref_count == MAX_FENCE_REFS {
            return Err((REASON_OVERSIZE, MAX_FENCE_REFS as u32));
        }
        self.refs[self.ref_count] = res;
        self.ref_count += 1;
        Ok(())
    }

    fn add_read(&mut self, res: u16) -> Result<(), (u16, u32)> {
        self.add_ref(res)?;
        if !self.reads[..self.read_count].contains(&res) {
            if self.read_count == MAX_FENCE_REFS {
                return Err((REASON_OVERSIZE, MAX_FENCE_REFS as u32));
            }
            self.reads[self.read_count] = res;
            self.read_count += 1;
        }
        Ok(())
    }

    fn add_write(&mut self, res: u16, usage: u32) -> Result<(), (u16, u32)> {
        self.add_ref(res)?;
        if !self.writes[..self.write_count].contains(&res) {
            if self.write_count == MAX_FENCE_REFS {
                return Err((REASON_OVERSIZE, MAX_FENCE_REFS as u32));
            }
            self.writes[self.write_count] = res;
            self.write_count += 1;
        }
        if usage & USAGE_CANDIDATE != 0 && !self.candidates[..self.candidate_count].contains(&res) {
            if self.candidate_count == MAX_FENCE_REFS {
                return Err((REASON_OVERSIZE, MAX_FENCE_REFS as u32));
            }
            self.candidates[self.candidate_count] = res;
            self.candidate_count += 1;
        }
        Ok(())
    }
}

/// One item of a validated submission, as the backend sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitItem {
    Dispatch {
        pipeline: u64,
        binds_offset: usize,
        bind_count: usize,
        groups: [u32; 3],
    },
    Copy {
        src: u64,
        dst: u64,
        len: u64,
    },
    BeginPass {
        target: u64,
        flags: u32,
        clear: u32,
    },
    Draw {
        pipeline: u64,
        binds_offset: usize,
        bind_count: usize,
        vertex: u64,
        index: u64,
        first: u32,
        count: u32,
        instances: u32,
    },
    EndPass,
}

/// Iterator over a validated item list. Offsets in the yielded items are
/// relative to the slice this walk was built from.
pub struct ItemWalk<'p> {
    bytes: &'p [u8],
    off: usize,
}

impl<'p> ItemWalk<'p> {
    /// The bytes being walked, so a caller can read binding entries at the
    /// offsets an item reports.
    #[must_use]
    pub const fn bytes(&self) -> &'p [u8] {
        self.bytes
    }

    /// Read binding entry `i` of an item that reported `binds_offset`.
    #[must_use]
    pub fn binding(&self, binds_offset: usize, i: usize) -> Option<(u16, u64)> {
        let e = binds_offset + i * BIND_ENTRY_LEN;
        Some((get_u16(self.bytes, e)?, get_u64(self.bytes, e + 4)?))
    }
}

impl Iterator for ItemWalk<'_> {
    type Item = SubmitItem;

    fn next(&mut self) -> Option<SubmitItem> {
        if self.off >= self.bytes.len() {
            return None;
        }
        let b = self.bytes;
        let op = b[self.off];
        let o = self.off + 1;
        let item = match op {
            ITEM_DISPATCH => {
                let pipeline = get_u64(b, o)?;
                let n = get_u16(b, o + 8)? as usize;
                let binds_offset = o + 12;
                let next = binds_offset + n * BIND_ENTRY_LEN;
                let groups = [
                    get_u32(b, next)?,
                    get_u32(b, next + 4)?,
                    get_u32(b, next + 8)?,
                ];
                self.off = next + 12;
                SubmitItem::Dispatch {
                    pipeline,
                    binds_offset,
                    bind_count: n,
                    groups,
                }
            }
            ITEM_COPY => {
                let item = SubmitItem::Copy {
                    src: get_u64(b, o)?,
                    dst: get_u64(b, o + 8)?,
                    len: get_u64(b, o + 16)?,
                };
                self.off = o + 24;
                item
            }
            ITEM_BEGIN_PASS => {
                let item = SubmitItem::BeginPass {
                    target: get_u64(b, o)?,
                    flags: get_u32(b, o + 8)?,
                    clear: get_u32(b, o + 12)?,
                };
                self.off = o + 16;
                item
            }
            ITEM_DRAW => {
                let pipeline = get_u64(b, o)?;
                let n = get_u16(b, o + 8)? as usize;
                let binds_offset = o + 12;
                let next = binds_offset + n * BIND_ENTRY_LEN;
                let item = SubmitItem::Draw {
                    pipeline,
                    binds_offset,
                    bind_count: n,
                    vertex: get_u64(b, next)?,
                    index: get_u64(b, next + 8)?,
                    first: get_u32(b, next + 16)?,
                    count: get_u32(b, next + 20)?,
                    instances: get_u32(b, next + 24)?,
                };
                self.off = next + 28;
                item
            }
            ITEM_END_PASS => {
                self.off = o;
                SubmitItem::EndPass
            }
            _ => return None,
        };
        Some(item)
    }
}
