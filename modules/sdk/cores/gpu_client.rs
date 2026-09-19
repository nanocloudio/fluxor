// gpu_client_core — the producer half of the GPU contract.
//
// A provider issues handles; a consumer thinks in its own names. Something has
// to hold the map between them, and every consumer would otherwise write it
// again: correlate a request with the outcome that answers it, remember which
// handle came back for which name, and know when a pipeline is usable.
//
// That is all this is. It emits requests, applies outcomes, and answers
// "what is the handle for the thing I called `PIX`". It decides nothing about
// the contract — the provider does that, and refuses whatever this got wrong.
//
// ## Why names rather than handles
//
// A consumer's resources are structural: the colour plane, the coverage
// plane, the output. Those are compile-time facts about its pipeline, so it
// names them with constants. Handles are runtime facts about a device that
// may not exist yet, and that change wholesale when a device is lost. Keeping
// the two apart is what lets a consumer be written once and survive an epoch
// change without threading handles through its own logic.
//
// ## Pipelining
//
// Several requests may be outstanding at once; each is remembered by its
// correlation. A consumer that had to wait for every answer before sending
// the next request would spend a frame's worth of steps setting up.
//
// Pure logic over caller-owned state: no allocation, no clock, no syscall, no
// I/O. `no_std`.
//
// Mount alongside `sdk/wire/gpu_wire.rs`.

/// A named resource and the handles the provider issued for it.
///
/// Both a buffer and a view, because the contract binds views and a consumer
/// almost always wants the whole buffer: minting the obvious view here saves
/// every consumer the same two-step dance.
#[derive(Clone, Copy, Debug)]
pub struct ClientResource {
    pub name: u32,
    pub live: bool,
    pub size: u64,
    pub buffer: u64,
    pub view: u64,
}

impl ClientResource {
    pub const EMPTY: Self = Self {
        name: 0,
        live: false,
        size: 0,
        buffer: HANDLE_NONE,
        view: HANDLE_NONE,
    };

    /// Whether the resource is usable: created, and with a view to bind.
    #[must_use]
    pub const fn usable(&self) -> bool {
        self.live && self.view != HANDLE_NONE
    }
}

/// A named program and the pipeline built from it.
#[derive(Clone, Copy, Debug)]
pub struct ClientProgram {
    pub name: u32,
    pub live: bool,
    pub program: u64,
    pub pipeline: u64,
    /// The provider completed the pipeline's build fence.
    pub ready: bool,
    /// The program or its pipeline failed. Nothing is retried automatically:
    /// a shader that does not compile will not compile on the next frame
    /// either, and a consumer that kept resubmitting would hide the fault.
    pub failed: bool,
    /// The consumer asked for this name back. Its handles are released in the
    /// order the provider requires — the pipeline first, because a program a
    /// live pipeline still names cannot be released.
    pub retiring: bool,
}

impl ClientProgram {
    pub const EMPTY: Self = Self {
        name: 0,
        live: false,
        program: HANDLE_NONE,
        pipeline: HANDLE_NONE,
        ready: false,
        failed: false,
        retiring: false,
    };
}

/// "No slot" for a pending entry that answers for no table row.
///
/// The client's own sentinel, not the device model's: a consumer mounts this
/// core beside the wire contract alone, and borrowing a constant from the
/// provider half would drag the whole device model in with it.
pub const CLIENT_NO_SLOT: u16 = u16::MAX;

/// What an outstanding request will produce.
pub const PEND_FREE: u8 = 0;
/// A buffer handle for the resource in this slot.
pub const PEND_BUFFER: u8 = 1;
/// A view over the buffer just created.
pub const PEND_VIEW: u8 = 2;
/// A program handle.
pub const PEND_PROGRAM: u8 = 3;
/// A pipeline handle, and the completion that makes it ready.
pub const PEND_PIPELINE: u8 = 4;
/// A completion with no handle: an upload, a submission, a drain.
pub const PEND_WORK: u8 = 5;
/// A readback, whose result bytes the caller collects.
pub const PEND_READ: u8 = 6;
/// One of a retiring program's two handle releases. One kind, not two: the
/// slot's own handles say which record is still owed.
pub const PEND_RETIRE: u8 = 7;

/// One outstanding request.
#[derive(Clone, Copy, Debug)]
pub struct Pending {
    pub corr: u64,
    pub kind: u8,
    /// The resource or program slot this answers for, or [`CLIENT_NO_SLOT`].
    pub slot: u16,
    /// The caller's own tag, echoed back when the request settles. Whatever a
    /// consumer needs to recognise its own work — a frame number, a stage id.
    pub tag: u32,
}

impl Pending {
    pub const EMPTY: Self = Self {
        corr: 0,
        kind: PEND_FREE,
        slot: CLIENT_NO_SLOT,
        tag: 0,
    };
}

/// What applying an outcome meant to the consumer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ClientEvent<'a> {
    /// Nothing the consumer needs to act on.
    Quiet,
    /// A named resource is now usable.
    ResourceReady { name: u32 },
    /// A named program's pipeline is now usable.
    ProgramReady { name: u32 },
    /// Work the consumer tagged finished.
    Finished { tag: u32 },
    /// Readback bytes for tagged work, at `offset` within the request.
    Bytes {
        tag: u32,
        offset: u64,
        bytes: &'a [u8],
    },
    /// A request was refused or failed. `reason` is the contract's code.
    Failed { tag: u32, reason: u16 },
    /// The device epoch ended. Every handle this client holds is gone and its
    /// tables have been cleared; the consumer rebuilds from its own names.
    DeviceLost,
    /// The provider answered a capability query. `min_align` and the rest are
    /// now readable from [`GpuClient`].
    Capabilities,
}

/// The producer's side of a GPU conversation.
pub struct GpuClient<'a> {
    pub resources: &'a mut [ClientResource],
    pub programs: &'a mut [ClientProgram],
    pub pending: &'a mut [Pending],
    /// The next correlation this client will use. Monotonic, so an answer to
    /// a request abandoned by a device loss can never settle a current one.
    pub next_corr: u64,
    /// Facts read from the provider's capability record. Zero until a
    /// [`ClientEvent::Capabilities`] arrives — a consumer that builds a pack
    /// before then is guessing the device's alignment.
    pub min_align: u32,
    pub max_bindings: u32,
    pub features: u32,
    pub max_workgroup: [u32; 3],
    /// Set when the device epoch ended. The consumer's own names survive;
    /// nothing else does.
    pub lost: bool,
}

impl GpuClient<'_> {
    /// Whether the provider's facts have arrived.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.min_align != 0
    }

    /// The view handle for a named resource, or `None` if it is not usable
    /// yet.
    #[must_use]
    pub fn view(&self, name: u32) -> Option<u64> {
        self.resources
            .iter()
            .find(|r| r.live && r.name == name && r.view != HANDLE_NONE)
            .map(|r| r.view)
    }

    /// The buffer handle for a named resource.
    #[must_use]
    pub fn buffer(&self, name: u32) -> Option<u64> {
        self.resources
            .iter()
            .find(|r| r.live && r.name == name && r.buffer != HANDLE_NONE)
            .map(|r| r.buffer)
    }

    /// The pipeline handle for a named program, or `None` until it is ready.
    /// A dispatch against a pipeline that is not ready is refused by the
    /// provider, so asking here is how a consumer avoids the round trip.
    #[must_use]
    pub fn pipeline(&self, name: u32) -> Option<u64> {
        self.programs
            .iter()
            .find(|p| p.live && p.name == name && p.ready)
            .map(|p| p.pipeline)
    }

    /// The size a named resource was created at, or `None` if it does not
    /// exist. A consumer whose geometry changed compares against this to know
    /// whether the buffer it has is still the buffer it needs.
    #[must_use]
    pub fn resource_size(&self, name: u32) -> Option<u64> {
        self.resources
            .iter()
            .find(|r| r.live && r.name == name)
            .map(|r| r.size)
    }

    /// Whether a named resource is created, or at least asked for. A consumer
    /// setting several up at once uses this to avoid asking twice.
    #[must_use]
    pub fn claimed(&self, name: u32) -> bool {
        self.resources.iter().any(|r| r.live && r.name == name)
    }

    /// Whether a named program still holds provider handles.
    ///
    /// A load under this name is refused until [`Self::release_program`] has
    /// retired it. That refusal is permanent, which a bare `None` would
    /// otherwise read as the backpressure every other refusal here means — so
    /// a consumer that could spin asks this instead.
    #[must_use]
    pub fn program_claimed(&self, name: u32) -> bool {
        self.programs.iter().any(|p| {
            p.live
                && p.name == name
                && (p.retiring || p.program != HANDLE_NONE || p.pipeline != HANDLE_NONE)
        })
    }

    /// Whether a named program failed to build.
    #[must_use]
    pub fn program_failed(&self, name: u32) -> bool {
        self.programs
            .iter()
            .any(|p| p.live && p.name == name && p.failed)
    }

    /// Outstanding requests.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.pending.iter().filter(|p| p.kind != PEND_FREE).count()
    }

    fn corr(&mut self) -> u64 {
        self.next_corr = self.next_corr.wrapping_add(1);
        self.next_corr
    }

    fn arm(&mut self, corr: u64, kind: u8, slot: u16, tag: u32) -> bool {
        let Some(p) = self.pending.iter_mut().find(|p| p.kind == PEND_FREE) else {
            return false;
        };
        *p = Pending {
            corr,
            kind,
            slot,
            tag,
        };
        true
    }

    fn resource_slot(&mut self, name: u32) -> Option<usize> {
        if let Some(i) = self.resources.iter().position(|r| r.live && r.name == name) {
            return Some(i);
        }
        let i = self.resources.iter().position(|r| !r.live)?;
        self.resources[i] = ClientResource {
            name,
            live: true,
            ..ClientResource::EMPTY
        };
        Some(i)
    }

    fn program_slot(&mut self, name: u32) -> Option<usize> {
        if let Some(i) = self.programs.iter().position(|p| p.live && p.name == name) {
            // A slot still holding provider handles is not free to reuse.
            // Overwriting it in place would strand a program and a pipeline
            // that nothing can name again, and the provider's tables would
            // fill one reload at a time until every load is refused. The
            // consumer retires the name first; `program_claimed` says so.
            let p = self.programs[i];
            if p.retiring || p.program != HANDLE_NONE || p.pipeline != HANDLE_NONE {
                return None;
            }
            // A load still in flight, or one whose pack was refused, holds
            // nothing — reusing that slot is how a fixed pack is retried.
            self.programs[i] = ClientProgram {
                name,
                live: true,
                ..ClientProgram::EMPTY
            };
            return Some(i);
        }
        let i = self.programs.iter().position(|p| !p.live)?;
        self.programs[i] = ClientProgram {
            name,
            live: true,
            ..ClientProgram::EMPTY
        };
        Some(i)
    }

    // ── Requests ────────────────────────────────────────────────────────
    //
    // Each writes one record and answers its length, or `None` when `out` is
    // too small or the client has no room to track another outstanding
    // request. `None` is backpressure: the caller retries next step.
    //
    // Two refusals are permanent rather than backpressure, and each has a
    // predicate that says so: `load_program` refuses a name whose provider
    // handles are still held (`program_claimed`), and `create_pipeline`
    // refuses a program that already has one or that failed
    // (`program_failed`). A consumer that would otherwise spin asks.

    /// Ask for the device's facts. A consumer sends this once, first: a pack
    /// built before the answer arrives is built against a guessed alignment.
    pub fn ask_capabilities(&mut self, out: &mut [u8]) -> Option<usize> {
        let corr = self.corr();
        let n = req_query_caps(out, corr)?;
        self.arm(corr, PEND_WORK, CLIENT_NO_SLOT, 0).then_some(n)
    }

    /// Create a named buffer. The matching whole-buffer view is minted
    /// automatically once the buffer's handle arrives.
    pub fn create_buffer(
        &mut self,
        out: &mut [u8],
        name: u32,
        size: u64,
        usage: u32,
        rights: u32,
    ) -> Option<usize> {
        let slot = self.resource_slot(name)?;
        self.resources[slot].size = size;
        // The view needs the same usage and rights, so they are remembered
        // rather than asked for twice.
        self.resources[slot].buffer = HANDLE_NONE;
        self.resources[slot].view = HANDLE_NONE;
        let corr = self.corr();
        let n = req_create_buffer(out, corr, size, usage, rights, RESIDENCY_RESIDENT)?;
        self.arm(corr, PEND_BUFFER, slot as u16, usage).then_some(n)
    }

    /// Create a named texture. The matching whole-texture view is minted
    /// automatically once the handle arrives, exactly as for a buffer.
    ///
    /// The bytes the view spans are the contract's own accounting — four per
    /// texel, whatever the format's actual width — so a view over a narrower
    /// format covers more bytes than its texels occupy. That is the device
    /// model's assumption, restated here rather than a second one invented.
    pub fn create_texture(
        &mut self,
        out: &mut [u8],
        name: u32,
        spec: &TextureSpec,
    ) -> Option<usize> {
        let size = u64::from(spec.width)
            .checked_mul(u64::from(spec.height))?
            .checked_mul(u64::from(spec.layers))?
            .checked_mul(4)?;
        let slot = self.resource_slot(name)?;
        self.resources[slot].size = size;
        self.resources[slot].buffer = HANDLE_NONE;
        self.resources[slot].view = HANDLE_NONE;
        let corr = self.corr();
        let n = req_create_texture(out, corr, spec)?;
        self.arm(corr, PEND_BUFFER, slot as u16, spec.usage)
            .then_some(n)
    }

    /// Retire a named resource.
    ///
    /// The name is free immediately, so a consumer can recreate it at a new
    /// size in the same step — which is what a geometry change is. The
    /// provider keeps the storage until nothing in flight can reach it; that
    /// is its business, not the consumer's.
    pub fn destroy(&mut self, out: &mut [u8], name: u32) -> Option<usize> {
        let slot = self
            .resources
            .iter()
            .position(|r| r.live && r.name == name)?;
        let buffer = self.resources[slot].buffer;
        if buffer == HANDLE_NONE {
            // Never created, or its handle never arrived. Dropping the slot is
            // the whole of the work.
            self.resources[slot] = ClientResource::EMPTY;
            return Some(0);
        }
        let corr = self.corr();
        let n = req_handle_op(out, corr, OP_DESTROY_RESOURCE, buffer)?;
        if !self.arm(corr, PEND_WORK, CLIENT_NO_SLOT, name) {
            return None;
        }
        self.resources[slot] = ClientResource::EMPTY;
        Some(n)
    }

    /// Load a named program from a pack. Chunked by the caller when the pack
    /// exceeds one record; pass the handle back as `program` for later chunks.
    pub fn load_program(
        &mut self,
        out: &mut [u8],
        name: u32,
        total_len: u32,
        chunk_offset: u32,
        bytes: &[u8],
    ) -> Option<usize> {
        let slot = if chunk_offset == 0 {
            self.program_slot(name)?
        } else {
            self.programs
                .iter()
                .position(|p| p.live && p.name == name)?
        };
        let program = self.programs[slot].program;
        let corr = self.corr();
        let n = req_load_program(out, corr, program, chunk_offset, total_len, bytes)?;
        self.arm(corr, PEND_PROGRAM, slot as u16, name).then_some(n)
    }

    /// Retire a named program and the pipeline built from it.
    ///
    /// Two provider handles, so two records, in the order the provider
    /// requires: releasing a program is refused while a live pipeline still
    /// names it. This writes the first; the second follows from its
    /// completion, so a consumer asks once and the ordering is not its
    /// problem.
    ///
    /// `Some(0)` means the name held nothing and is free already.
    pub fn release_program(&mut self, out: &mut [u8], name: u32) -> Option<usize> {
        let slot = self
            .programs
            .iter()
            .position(|p| p.live && p.name == name)?;
        let p = self.programs[slot];
        let (op, handle) = if p.pipeline != HANDLE_NONE {
            (OP_RELEASE_PIPELINE, p.pipeline)
        } else if p.program != HANDLE_NONE {
            (OP_RELEASE_PROGRAM, p.program)
        } else {
            self.programs[slot] = ClientProgram::EMPTY;
            return Some(0);
        };
        let corr = self.corr();
        let n = req_handle_op(out, corr, op, handle)?;
        if !self.arm(corr, PEND_RETIRE, slot as u16, name) {
            return None;
        }
        self.programs[slot].retiring = true;
        self.programs[slot].ready = false;
        Some(n)
    }

    /// Build a raster pipeline for a named program whose load completed.
    ///
    /// Separate from [`Self::create_pipeline`] rather than an argument on it:
    /// a raster pipeline needs state a compute pipeline has no place for, and
    /// a parameter that is meaningless in one of the two cases is a worse
    /// interface than two calls.
    pub fn create_raster_pipeline(
        &mut self,
        out: &mut [u8],
        name: u32,
        state: &RasterState,
    ) -> Option<usize> {
        let mut blob = [0u8; RASTER_STATE_HEAD + MAX_VERTEX_ATTRS * RASTER_ATTR_LEN];
        let len = state.encode(&mut blob)?;
        self.pipeline_for(out, name, QUEUE_RASTER, &blob[..len])
    }

    /// Build the pipeline for a named program whose load completed.
    pub fn create_pipeline(&mut self, out: &mut [u8], name: u32) -> Option<usize> {
        self.pipeline_for(out, name, QUEUE_COMPUTE, &[])
    }

    fn pipeline_for(&mut self, out: &mut [u8], name: u32, kind: u8, state: &[u8]) -> Option<usize> {
        // A program that failed is not buildable. Its handle may well have
        // arrived before the failure did, so the handle alone is not the
        // question — and a client that kept offering pipelines for a shader
        // that will not compile would hide the fault behind a graph that
        // merely produces nothing.
        // A program that already has a pipeline is not built twice: the second
        // build allocates another provider slot and overwrites the handle to
        // the first, which then pins its program against release forever.
        let slot = self.programs.iter().position(|p| {
            p.live
                && p.name == name
                && p.program != HANDLE_NONE
                && p.pipeline == HANDLE_NONE
                && !p.failed
                && !p.retiring
        })?;
        let program = self.programs[slot].program;
        let corr = self.corr();
        let n = req_create_pipeline(out, corr, program, kind, state)?;
        self.arm(corr, PEND_PIPELINE, slot as u16, name)
            .then_some(n)
    }

    /// Write bytes into a named resource. `bytes` must fit one record; a
    /// caller with more chunks it against explicit offsets.
    pub fn upload(
        &mut self,
        out: &mut [u8],
        name: u32,
        offset: u64,
        bytes: &[u8],
        tag: u32,
    ) -> Option<usize> {
        let view = self.view(name)?;
        let corr = self.corr();
        let n = req_upload(out, corr, view, offset, bytes)?;
        self.arm(corr, PEND_WORK, CLIENT_NO_SLOT, tag).then_some(n)
    }

    /// Write bytes into a view the caller already holds.
    ///
    /// The named form is the usual one; this exists for a caller that resolved
    /// the handle once and is now writing many chunks against it, where
    /// looking the name up per chunk is pure overhead.
    pub fn upload_to(
        &mut self,
        out: &mut [u8],
        view: u64,
        offset: u64,
        bytes: &[u8],
        tag: u32,
    ) -> Option<usize> {
        let corr = self.corr();
        let n = req_upload(out, corr, view, offset, bytes)?;
        self.arm(corr, PEND_WORK, CLIENT_NO_SLOT, tag).then_some(n)
    }

    /// Claim a correlation for an upload the caller will frame itself,
    /// answering the correlation to put in its header.
    ///
    /// For a payload large enough that staging it twice matters: a 64 KiB
    /// chunk built in the caller's own buffer and then copied through this
    /// one's is 64 KiB of a cooperative step spent for nothing. The caller
    /// writes the record; this tracks the request so its outcome still finds
    /// the tag.
    ///
    /// `None` when there is no room to track another outstanding request —
    /// the caller must not frame the record.
    pub fn reserve_upload(&mut self, tag: u32) -> Option<u64> {
        let corr = self.corr();
        self.arm(corr, PEND_WORK, CLIENT_NO_SLOT, tag)
            .then_some(corr)
    }

    /// Submit an item list the caller built with the wire encoders.
    pub fn submit(
        &mut self,
        out: &mut [u8],
        waits: &[u64],
        items: &[u8],
        tag: u32,
    ) -> Option<usize> {
        self.submit_on(out, QUEUE_COMPUTE, waits, items, tag)
    }

    /// Submit on a named queue.
    ///
    /// Dispatches and draws cannot share a submission — the device model
    /// refuses a draw on the compute queue and a dispatch on the raster one —
    /// so a consumer that does both says which each time, and the two are
    /// ordered by a fence rather than by their position in one list.
    pub fn submit_on(
        &mut self,
        out: &mut [u8],
        queue: u8,
        waits: &[u64],
        items: &[u8],
        tag: u32,
    ) -> Option<usize> {
        let corr = self.corr();
        let n = req_submit(out, corr, queue, waits, items)?;
        self.arm(corr, PEND_WORK, CLIENT_NO_SLOT, tag).then_some(n)
    }

    /// Read a named resource back to the CPU.
    pub fn readback(
        &mut self,
        out: &mut [u8],
        name: u32,
        offset: u64,
        len: u32,
        tag: u32,
    ) -> Option<usize> {
        let view = self.view(name)?;
        let corr = self.corr();
        let n = req_readback(out, corr, view, offset, len)?;
        self.arm(corr, PEND_READ, CLIENT_NO_SLOT, tag).then_some(n)
    }

    /// Acknowledge a fence, releasing the provider's retained result.
    ///
    /// A consumer that never does this eventually exhausts the fence pool and
    /// is refused at admission — which is the contract working, not a fault.
    pub fn release_fence(&mut self, out: &mut [u8], fence: u64) -> Option<usize> {
        let corr = self.corr();
        let n = req_handle_op(out, corr, OP_RELEASE_FENCE, fence)?;
        self.arm(corr, PEND_WORK, CLIENT_NO_SLOT, 0).then_some(n)
    }

    // ── Outcomes ────────────────────────────────────────────────────────

    /// Apply one outcome, answering what it meant.
    ///
    /// An outcome whose correlation this client is not waiting on is quiet:
    /// an answer to a request abandoned by a device loss must not settle a
    /// current one.
    pub fn apply<'o>(&mut self, rec: &Outcome<'o>, out: &mut [u8]) -> (ClientEvent<'o>, usize) {
        match *rec {
            Outcome::Caps { caps, .. } => {
                self.min_align = get_u32(caps, CAPS_MIN_ALIGN).unwrap_or(0);
                self.max_bindings = get_u32(caps, CAPS_MAX_BINDINGS).unwrap_or(0);
                self.features = get_u32(caps, CAPS_FEATURES).unwrap_or(0);
                self.max_workgroup = [
                    get_u32(caps, CAPS_MAX_WORKGROUP_X).unwrap_or(0),
                    get_u32(caps, CAPS_MAX_WORKGROUP_Y).unwrap_or(0),
                    get_u32(caps, CAPS_MAX_WORKGROUP_Z).unwrap_or(0),
                ];
                (ClientEvent::Capabilities, 0)
            }

            Outcome::DeviceLost { .. } => {
                // Every handle is gone. The consumer's names survive, so it
                // rebuilds from those rather than from anything it held.
                for r in self.resources.iter_mut() {
                    *r = ClientResource::EMPTY;
                }
                for p in self.programs.iter_mut() {
                    *p = ClientProgram::EMPTY;
                }
                for p in self.pending.iter_mut() {
                    *p = Pending::EMPTY;
                }
                self.lost = true;
                (ClientEvent::DeviceLost, 0)
            }

            Outcome::Handle { corr, handle } => {
                let Some(i) = self.find(corr) else {
                    return (ClientEvent::Quiet, 0);
                };
                let p = self.pending[i];
                match p.kind {
                    PEND_BUFFER => {
                        let slot = p.slot as usize;
                        self.resources[slot].buffer = handle;
                        // Mint the whole-buffer view straight away: the
                        // contract binds views, and this is the one every
                        // consumer wants.
                        let size = self.resources[slot].size;
                        let usage = p.tag;
                        self.pending[i] = Pending::EMPTY;
                        let corr = self.corr();
                        if let Some(n) =
                            req_create_view(out, corr, handle, 0, size, usage, RIGHT_ALL)
                        {
                            if self.arm(corr, PEND_VIEW, slot as u16, usage) {
                                return (ClientEvent::Quiet, n);
                            }
                        }
                        // No room to track the view request. The resource
                        // stays unusable and the caller retries by asking for
                        // it again — nothing was half-created.
                        self.resources[slot].live = false;
                        (ClientEvent::Quiet, 0)
                    }
                    PEND_VIEW => {
                        let slot = p.slot as usize;
                        self.resources[slot].view = handle;
                        self.pending[i] = Pending::EMPTY;
                        (
                            ClientEvent::ResourceReady {
                                name: self.resources[slot].name,
                            },
                            0,
                        )
                    }
                    PEND_PROGRAM => {
                        self.programs[p.slot as usize].program = handle;
                        (ClientEvent::Quiet, 0)
                    }
                    PEND_PIPELINE => {
                        self.programs[p.slot as usize].pipeline = handle;
                        (ClientEvent::Quiet, 0)
                    }
                    _ => (ClientEvent::Quiet, 0),
                }
            }

            Outcome::Completed { corr, .. } => {
                let Some(i) = self.find(corr) else {
                    return (ClientEvent::Quiet, 0);
                };
                let p = self.pending[i];
                self.pending[i] = Pending::EMPTY;
                match p.kind {
                    PEND_PROGRAM => (ClientEvent::Quiet, 0),
                    PEND_PIPELINE => {
                        let slot = p.slot as usize;
                        self.programs[slot].ready = true;
                        (
                            ClientEvent::ProgramReady {
                                name: self.programs[slot].name,
                            },
                            0,
                        )
                    }
                    PEND_VIEW | PEND_BUFFER => (ClientEvent::Quiet, 0),
                    PEND_RETIRE => {
                        let slot = p.slot as usize;
                        // Clear the handle this release just returned, then
                        // owe the next one. The provider refuses to release a
                        // program while a pipeline names it, so the pipeline
                        // is always the one that went first.
                        if self.programs[slot].pipeline != HANDLE_NONE {
                            self.programs[slot].pipeline = HANDLE_NONE;
                        } else {
                            self.programs[slot].program = HANDLE_NONE;
                        }
                        let program = self.programs[slot].program;
                        if program == HANDLE_NONE {
                            self.programs[slot] = ClientProgram::EMPTY;
                            return (ClientEvent::Finished { tag: p.tag }, 0);
                        }
                        let corr = self.corr();
                        if let Some(n) = req_handle_op(out, corr, OP_RELEASE_PROGRAM, program) {
                            if self.arm(corr, PEND_RETIRE, slot as u16, p.tag) {
                                return (ClientEvent::Quiet, n);
                            }
                        }
                        // No room to track the second release. The slot stays
                        // retiring and keeps the program handle, so asking
                        // again resumes from exactly here.
                        (ClientEvent::Quiet, 0)
                    }
                    _ => (ClientEvent::Finished { tag: p.tag }, 0),
                }
            }

            Outcome::Result {
                corr,
                offset,
                bytes,
                ..
            } => {
                let Some(i) = self.find(corr) else {
                    return (ClientEvent::Quiet, 0);
                };
                // The read is not finished until its completion arrives; the
                // pending entry stays.
                let tag = self.pending[i].tag;
                (ClientEvent::Bytes { tag, offset, bytes }, 0)
            }

            Outcome::Rejected { corr, reason, .. } | Outcome::Failed { corr, reason, .. } => {
                let Some(i) = self.find(corr) else {
                    return (ClientEvent::Quiet, 0);
                };
                let p = self.pending[i];
                self.pending[i] = Pending::EMPTY;
                match p.kind {
                    PEND_BUFFER | PEND_VIEW => {
                        // Half a resource is no resource. Retiring the slot
                        // lets the consumer ask again from its own name.
                        self.resources[p.slot as usize] = ClientResource::EMPTY;
                    }
                    PEND_PROGRAM | PEND_PIPELINE => {
                        // Nothing is retried automatically: a shader that did
                        // not compile will not compile next frame either, and
                        // a consumer that kept resubmitting would hide it.
                        self.programs[p.slot as usize].failed = true;
                        self.programs[p.slot as usize].ready = false;
                    }
                    PEND_RETIRE => {
                        // The handle is still the provider's, so the slot
                        // keeps it and stays retiring. Forgetting it here
                        // would drop the one number that can still reach the
                        // thing this call exists to release.
                    }
                    _ => {}
                }
                (ClientEvent::Failed { tag: p.tag, reason }, 0)
            }

            Outcome::Cancelled { corr, .. } => {
                let Some(i) = self.find(corr) else {
                    return (ClientEvent::Quiet, 0);
                };
                let tag = self.pending[i].tag;
                self.pending[i] = Pending::EMPTY;
                (
                    ClientEvent::Failed {
                        tag,
                        reason: REASON_NOT_READY,
                    },
                    0,
                )
            }

            Outcome::Accepted { .. } | Outcome::Surface { .. } => (ClientEvent::Quiet, 0),
        }
    }

    fn find(&self, corr: u64) -> Option<usize> {
        self.pending
            .iter()
            .position(|p| p.kind != PEND_FREE && p.corr == corr)
    }
}
