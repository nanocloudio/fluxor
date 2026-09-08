// gpu_replay_core — a GPU provider with no GPU.
//
// It executes the whole contract — admission, handles, views, sealing,
// residency, dependencies, fences, candidate commit, cancellation, epochs —
// against a plain byte arena, and it does not pretend to run shaders. That is
// the point twice over:
//
//   - **As an oracle.** Every backend is held to the same lifetime corpus.
//     Running that corpus somewhere with no driver, no adapter and no
//     asynchronous callbacks means a failure is a contract bug, not a
//     hardware one.
//   - **As a composition.** A graph wired to this provider builds and runs on
//     every target, including ones with no GPU at all, so a consumer can
//     develop and regression-test its request/result lifecycle before any
//     silicon exists.
//
// ## What a replay kernel computes
//
// A fixture transformation, declared as such: each dispatch adds a per-program
// constant — the first byte of the pack's identity digest — to every byte it
// copies from its read binding to its write binding.
//
// Chosen because it is the weakest thing that still proves the data path.
// It is deterministic, it is order-sensitive (two chained kernels give
// `input + k1 + k2`, so a dependency honoured out of order produces a
// different answer), and a CPU oracle for it is one line. What it is NOT is
// evidence that any GPU computed anything: `TARGET_REPLAY` artifacts run
// nowhere else, and computational evidence comes from native kernels on real
// devices.
//
// Pure logic over caller-owned storage: no allocation, no clock, no syscall.
// `no_std`.
//
// Mount alongside `sdk/wire/gpu_wire.rs`, `sdk/cores/gpu_pack.rs`,
// `sdk/cores/gpu_device.rs` and `sdk/crypto/sha256.rs`.

/// Arena granularity. A resource takes a contiguous run of whole blocks, so
/// the allocator is a bitmap first-fit rather than a bump pointer — a bump
/// arena cannot honour `destroy`, and a provider that never reclaims turns
/// every long-running graph into a leak.
pub const BLOCK_BYTES: usize = 4096;

/// Byte storage behind the device's resources.
///
/// Split from [`GpuDevice`] rather than folded into it because it is the one
/// part a real backend replaces: wgpu owns `wgpu::Buffer`s, WebGPU owns
/// `GPUBuffer`s, a direct driver owns arena offsets. Everything else in this
/// file is the same work those backends do around their own storage.
pub struct ReplayStore<'a> {
    bytes: &'a mut [u8],
    /// One entry per device resource slot: first block, or `NO_BLOCK`.
    first_block: &'a mut [u32],
    block_count: &'a mut [u32],
    /// One bit per block; `true` is allocated.
    used: &'a mut [bool],
}

/// "No allocation" for a resource slot.
pub const NO_BLOCK: u32 = u32::MAX;

impl<'a> ReplayStore<'a> {
    /// Build a store over caller-owned storage.
    ///
    /// `bytes` is truncated to a whole number of blocks; `used` must have one
    /// entry per block, and `first_block`/`block_count` one per resource slot.
    #[must_use]
    pub fn new(
        bytes: &'a mut [u8],
        first_block: &'a mut [u32],
        block_count: &'a mut [u32],
        used: &'a mut [bool],
    ) -> Option<Self> {
        if bytes.len() / BLOCK_BYTES != used.len() || first_block.len() != block_count.len() {
            return None;
        }
        first_block.fill(NO_BLOCK);
        block_count.fill(0);
        used.fill(false);
        Some(Self {
            bytes,
            first_block,
            block_count,
            used,
        })
    }

    /// Rebuild a store over bookkeeping that already describes live
    /// allocations — the counterpart to [`Self::new`] for a provider whose
    /// borrowed slices are reconstituted each step. Clears nothing.
    #[must_use]
    pub fn restore(
        bytes: &'a mut [u8],
        first_block: &'a mut [u32],
        block_count: &'a mut [u32],
        used: &'a mut [bool],
    ) -> Option<Self> {
        if bytes.len() / BLOCK_BYTES != used.len() || first_block.len() != block_count.len() {
            return None;
        }
        Some(Self {
            bytes,
            first_block,
            block_count,
            used,
        })
    }

    /// Total bytes the store can hold. A provider publishes this as its
    /// resident-memory fact so admission refuses before allocation can fail.
    #[must_use]
    pub fn capacity(&self) -> u64 {
        (self.used.len() * BLOCK_BYTES) as u64
    }

    /// Bytes currently committed.
    #[must_use]
    pub fn committed(&self) -> u64 {
        (self.used.iter().filter(|u| **u).count() * BLOCK_BYTES) as u64
    }

    /// Reserve contiguous storage for `slot`.
    ///
    /// Answers false when no run of blocks is long enough. That can happen
    /// with bytes still free — fragmentation is a real failure mode, and the
    /// provider reports it as a failed fence rather than hiding it, because a
    /// consumer that cannot fit needs to choose another profile.
    pub fn alloc(&mut self, slot: u16, size: u64) -> bool {
        let idx = slot as usize;
        if idx >= self.first_block.len() || self.first_block[idx] != NO_BLOCK {
            return false;
        }
        if size == 0 {
            // A zero-length allocation is legal to record and impossible to
            // address; keep it out of the arena entirely.
            self.first_block[idx] = NO_BLOCK;
            self.block_count[idx] = 0;
            return true;
        }
        let need = size.div_ceil(BLOCK_BYTES as u64) as usize;
        let total = self.used.len();
        if need > total {
            return false;
        }
        let mut start = 0usize;
        while start + need <= total {
            if let Some(busy) = (start..start + need).find(|b| self.used[*b]) {
                start = busy + 1;
                continue;
            }
            for b in start..start + need {
                self.used[b] = true;
            }
            // Zero on allocation: a fresh buffer must not expose whatever the
            // previous owner left behind.
            let base = start * BLOCK_BYTES;
            self.bytes[base..base + need * BLOCK_BYTES].fill(0);
            self.first_block[idx] = start as u32;
            self.block_count[idx] = need as u32;
            return true;
        }
        false
    }

    /// Release a slot's storage.
    pub fn free(&mut self, slot: u16) {
        let idx = slot as usize;
        if idx >= self.first_block.len() || self.first_block[idx] == NO_BLOCK {
            return;
        }
        let start = self.first_block[idx] as usize;
        for b in start..start + self.block_count[idx] as usize {
            self.used[b] = false;
        }
        self.first_block[idx] = NO_BLOCK;
        self.block_count[idx] = 0;
    }

    /// Release everything — what a device reset does, and the only moment at
    /// which wholesale reclamation is sound.
    pub fn reset(&mut self) {
        self.first_block.fill(NO_BLOCK);
        self.block_count.fill(0);
        self.used.fill(false);
    }

    /// The byte range `[offset, offset + len)` of `slot`, if it is inside the
    /// slot's allocation.
    fn range(&self, slot: u16, offset: u64, len: u64) -> Option<(usize, usize)> {
        let idx = slot as usize;
        let first = *self.first_block.get(idx)?;
        if first == NO_BLOCK {
            return None;
        }
        let cap = self.block_count[idx] as u64 * BLOCK_BYTES as u64;
        let end = offset.checked_add(len)?;
        if end > cap {
            return None;
        }
        let base = first as usize * BLOCK_BYTES;
        Some((base + offset as usize, len as usize))
    }

    /// Read a slot's bytes.
    #[must_use]
    pub fn read(&self, slot: u16, offset: u64, len: u64) -> Option<&[u8]> {
        let (at, n) = self.range(slot, offset, len)?;
        self.bytes.get(at..at + n)
    }

    /// Write into a slot.
    pub fn write(&mut self, slot: u16, offset: u64, src: &[u8]) -> bool {
        let Some((at, n)) = self.range(slot, offset, src.len() as u64) else {
            return false;
        };
        self.bytes[at..at + n].copy_from_slice(src);
        true
    }

    /// The fixture transformation: `dst[i] = src[i] + k`, over ranges that may
    /// belong to the same allocation.
    ///
    /// Copies through a small stack window rather than borrowing both ranges,
    /// because Rust will not hand out two mutable views into one slice and the
    /// alternative — a second buffer sized to the transfer — would put a
    /// megabyte on a cooperative step's stack.
    fn transform(
        &mut self,
        src: (u16, u64),
        dst: (u16, u64),
        len: u64,
        k: u8,
    ) -> bool {
        let Some((sat, _)) = self.range(src.0, src.1, len) else {
            return false;
        };
        let Some((dat, _)) = self.range(dst.0, dst.1, len) else {
            return false;
        };
        let mut window = [0u8; 256];
        let mut done = 0usize;
        let n = len as usize;
        while done < n {
            let chunk = window.len().min(n - done);
            window[..chunk].copy_from_slice(&self.bytes[sat + done..sat + done + chunk]);
            for b in &mut window[..chunk] {
                *b = b.wrapping_add(k);
            }
            self.bytes[dat + done..dat + done + chunk].copy_from_slice(&window[..chunk]);
            done += chunk;
        }
        true
    }
}

// ── The replay provider's profile ───────────────────────────────────────
//
// Table widths and arena size of the provider built on this backend. They
// live beside the backend rather than only inside the module that mounts it
// because the offline packer validates a pack against the device a graph
// would actually get: one definition, so a pack the tooling accepts is a pack
// the provider accepts.
//
// Chosen for a conformance and development provider rather than a production
// device — wide enough to run the whole lifetime corpus and a two-stage
// consumer pipeline, narrow enough that the state fits a module slot on every
// target the provider names.

pub const REPLAY_MAX_RESOURCES: usize = 16;
pub const REPLAY_MAX_VIEWS: usize = 32;
pub const REPLAY_MAX_PROGRAMS: usize = 4;
pub const REPLAY_MAX_PIPELINES: usize = 8;
pub const REPLAY_MAX_FENCES: usize = 32;
pub const REPLAY_MAX_SURFACES: usize = 2;

/// Blocks in the byte arena behind resources. The provider's resident-memory
/// fact, so admission refuses before the block allocator can be asked for
/// bytes that do not exist.
pub const REPLAY_ARENA_BLOCKS: usize = 64;
/// Bytes in that arena.
pub const REPLAY_ARENA_BYTES: usize = REPLAY_ARENA_BLOCKS * BLOCK_BYTES;

/// The device facts a replay provider stands behind.
///
/// Compute and readback, no raster, no presentation, no timestamps — and it
/// says so, rather than advertising what some other backend could do. Reset
/// IS supported, because clearing a byte arena is a verified quiescence in a
/// way a real device reset has to earn.
#[must_use]
pub fn replay_limits(store_bytes: u64) -> DeviceLimits {
    let mut l = DeviceLimits::baseline();
    l.features = FEATURE_COMPUTE | FEATURE_READBACK | FEATURE_DEVICE_RESET;
    l.targets = [TARGET_REPLAY, TARGET_NONE, TARGET_NONE, TARGET_NONE];
    l.max_resident_bytes = store_bytes;
    l.max_alloc_bytes = store_bytes;
    l.max_staging_bytes = 256 * 1024;
    l.max_scratch_bytes = store_bytes;
    l
}

/// What executing one unit of work did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Executed {
    /// Nothing to do, or the fence was already settled by the device.
    Idle,
    /// The work finished; its fence is terminal.
    Done,
    /// The work could not be carried out and its fence failed with `reason`.
    Failed(u16),
    /// The work is not finished — a readback with bytes still owed. Call
    /// again after draining outcomes.
    Pending,
}

/// Carry out one [`Work`] item against the store.
///
/// `record` is the whole request record the work came from, because upload
/// bytes and submission items live in it; this core copies out of it and
/// never retains it.
pub fn execute(
    dev: &mut GpuDevice<'_>,
    store: &mut ReplayStore<'_>,
    owner: u16,
    record: &[u8],
    work: Work,
) -> Executed {
    match work {
        Work::None => Executed::Idle,

        Work::CreateBuffer { fence, slot } | Work::CreateTexture { fence, slot } => {
            let size = dev.resource(slot).map_or(0, |r| r.size);
            if store.alloc(slot, size) {
                dev.complete(fence, 0);
                Executed::Done
            } else {
                // Fragmentation, not a budget overrun: the device admitted
                // this because the bytes were free, and the honest answer is
                // that they were not contiguous.
                dev.fail(fence, REASON_RESOURCE_EXHAUSTED, size as u32);
                Executed::Failed(REASON_RESOURCE_EXHAUSTED)
            }
        }

        Work::DestroyResource { fence, slot } => {
            // The handle is already retired. The bytes go only once nothing
            // in flight can still reach them.
            if dev.resource_free_pending(slot) || dev.resource(slot).is_none_or(|r| !r.live) {
                store.free(slot);
            }
            if dev.fence(fence).is_some_and(|f| f.state != FENCE_TERMINAL) {
                dev.complete(fence, 0);
            }
            Executed::Done
        }

        Work::LoadProgram { fence, .. } => {
            // Chunk assembly belongs to the caller, which owns the buffer the
            // bytes accumulate in; it calls `finish_program` and settles this
            // fence. Reporting `Idle` keeps that responsibility visible
            // instead of quietly completing a load that has not validated.
            let _ = fence;
            Executed::Idle
        }

        Work::ReleaseProgram { fence, .. } | Work::ReleasePipeline { fence, .. } => {
            // Nothing to free — a replay program is its manifest — but the
            // fence still has to finish, or a release would never complete.
            dev.complete(fence, 0);
            Executed::Done
        }

        Work::CreatePipeline { fence, slot, .. } => {
            // Compilation is instantaneous here, but it still goes through the
            // readiness flag rather than around it, so the corpus exercises
            // the same path a real asynchronous compiler takes.
            dev.mark_pipeline_ready(slot, true);
            dev.complete(fence, 0);
            Executed::Done
        }

        Work::Upload {
            fence,
            resource,
            offset,
            payload_offset,
            len,
        } => {
            let Some(src) = record.get(payload_offset..payload_offset + len as usize) else {
                dev.fail(fence, REASON_MALFORMED, 0);
                return Executed::Failed(REASON_MALFORMED);
            };
            if store.write(resource, offset, src) {
                dev.complete(fence, 0);
                Executed::Done
            } else {
                dev.fail(fence, REASON_BAD_RANGE, 0);
                Executed::Failed(REASON_BAD_RANGE)
            }
        }

        Work::Readback {
            fence,
            resource,
            offset,
            len,
        } => push_readback(dev, store, fence, resource, offset, len),

        Work::Submit {
            fence,
            queue,
            items_offset,
            items_len,
        } => run_submission(dev, store, owner, record, fence, queue, items_offset, items_len),

        Work::Cancel { fence, .. } => {
            // The device already decided and reported the disposition; there
            // is no hardware here to hint at.
            let _ = fence;
            Executed::Idle
        }

        Work::Drain { fence } => {
            // Quiescence is exactly "nothing in flight" for a provider whose
            // work is synchronous. A real driver waits on the device.
            if dev.quiescent() || dev.fence(fence).is_some_and(|f| f.state == FENCE_READY) {
                dev.complete(fence, 0);
                Executed::Done
            } else {
                Executed::Pending
            }
        }

        Work::Reset { fence, .. } => {
            store.reset();
            dev.complete(fence, 0);
            Executed::Done
        }

        Work::ExportSurface { fence, .. } => {
            // No shared surface is advertised, so admission never reaches
            // here; failing loudly beats a lease nothing can honour.
            dev.fail(fence, REASON_UNSUPPORTED_FEATURE, FEATURE_SHARED_SURFACE);
            Executed::Failed(REASON_UNSUPPORTED_FEATURE)
        }
    }
}

/// Deliver as much of a readback as the outcome ring will take.
///
/// Answers `Pending` while bytes are still owed, so the caller drains and
/// calls again. Nothing is dropped to make room, which is the whole reason
/// this is a loop rather than one write.
pub fn push_readback(
    dev: &mut GpuDevice<'_>,
    store: &ReplayStore<'_>,
    fence: u16,
    resource: u16,
    offset: u64,
    len: u32,
) -> Executed {
    let mut sent = len as u64 - dev.result_outstanding(fence);
    while sent < len as u64 {
        let remaining = len as u64 - sent;
        // Sized to what the ring will take now. A chunk it cannot hold is
        // re-offered unchanged next step, so guessing here would stall the
        // readback rather than pace it.
        let room = dev.max_result_chunk();
        if room == 0 {
            return Executed::Pending;
        }
        let chunk = remaining.min(room as u64);
        let Some(bytes) = store.read(resource, offset + sent, chunk) else {
            dev.fail(fence, REASON_BAD_RANGE, 0);
            return Executed::Failed(REASON_BAD_RANGE);
        };
        // Copy through a window so the store is not borrowed across the
        // device's mutable call.
        let mut window = [0u8; 4096];
        let n = bytes.len().min(window.len());
        window[..n].copy_from_slice(&bytes[..n]);
        if !dev.push_result(fence, offset + sent, &window[..n]) {
            return Executed::Pending;
        }
        sent += n as u64;
    }
    dev.complete(fence, 0);
    Executed::Done
}

#[allow(
    clippy::too_many_arguments,
    reason = "the parameters are the Work::Submit variant destructured; \
              re-boxing them into a struct would add a type to unpack twice"
)]
fn run_submission(
    dev: &mut GpuDevice<'_>,
    store: &mut ReplayStore<'_>,
    owner: u16,
    record: &[u8],
    fence: u16,
    queue: u8,
    items_offset: usize,
    items_len: usize,
) -> Executed {
    if queue == QUEUE_RASTER {
        dev.fail(fence, REASON_UNSUPPORTED_FEATURE, FEATURE_RASTER);
        return Executed::Failed(REASON_UNSUPPORTED_FEATURE);
    }
    // Binding offsets an item reports are relative to the item list, not to
    // the record it arrived in.
    let end = items_offset.saturating_add(items_len).min(record.len());
    let items = &record[items_offset.min(end)..end];
    let walk = dev.items(record, items_offset, items_len);
    // Collect first: the walk borrows `dev`, and executing an item needs it
    // mutably. Bounded by the submission's own item budget.
    let mut plan = [None::<PlannedItem>; MAX_FENCE_REFS];
    let mut n = 0usize;
    for item in walk {
        let planned = match item {
            SubmitItem::Dispatch {
                pipeline,
                binds_offset,
                bind_count,
                ..
            } => {
                let Some(p) = plan_dispatch(dev, items, owner, pipeline, binds_offset, bind_count)
                else {
                    dev.fail(fence, REASON_BAD_HANDLE, 0);
                    return Executed::Failed(REASON_BAD_HANDLE);
                };
                p
            }
            SubmitItem::Copy { src, dst, len } => {
                let Some((s, so)) = view_target(dev, src, owner) else {
                    dev.fail(fence, REASON_BAD_HANDLE, 0);
                    return Executed::Failed(REASON_BAD_HANDLE);
                };
                let Some((d, dof)) = view_target(dev, dst, owner) else {
                    dev.fail(fence, REASON_BAD_HANDLE, 0);
                    return Executed::Failed(REASON_BAD_HANDLE);
                };
                PlannedItem {
                    src: (s, so),
                    dst: (d, dof),
                    len,
                    k: 0,
                }
            }
            // Raster items cannot reach here: the queue check above refused
            // them, and admission refuses a raster item on the compute queue.
            _ => {
                dev.fail(fence, REASON_UNSUPPORTED_FEATURE, FEATURE_RASTER);
                return Executed::Failed(REASON_UNSUPPORTED_FEATURE);
            }
        };
        if n == plan.len() {
            dev.fail(fence, REASON_OVERSIZE, plan.len() as u32);
            return Executed::Failed(REASON_OVERSIZE);
        }
        plan[n] = Some(planned);
        n += 1;
    }

    for item in plan.iter().take(n).flatten() {
        if !store.transform(item.src, item.dst, item.len, item.k) {
            dev.fail(fence, REASON_BAD_RANGE, 0);
            return Executed::Failed(REASON_BAD_RANGE);
        }
    }
    dev.complete(fence, 0);
    Executed::Done
}

#[derive(Clone, Copy)]
struct PlannedItem {
    src: (u16, u64),
    dst: (u16, u64),
    len: u64,
    k: u8,
}

/// Resolve a dispatch to the byte move it stands for: the first binding the
/// program reads, the first it writes, and the program's replay constant.
fn plan_dispatch(
    dev: &GpuDevice<'_>,
    items: &[u8],
    owner: u16,
    pipeline: u64,
    binds_offset: usize,
    bind_count: usize,
) -> Option<PlannedItem> {
    let pslot = dev.slot_of(pipeline, KIND_PIPELINE, owner)?;
    let pipe = dev.pipeline(pslot)?;
    let prog = dev.program(pipe.program)?;
    let k = prog.identity[0];

    let mut src = None;
    let mut dst = None;
    let mut len = u64::MAX;
    for i in 0..bind_count {
        let e = binds_offset + i * BIND_ENTRY_LEN;
        let slot = get_u16(items, e)?;
        let view = get_u64(items, e + 4)?;
        let decl = (0..prog.binding_count as usize)
            .map(|j| prog.bindings[j])
            .find(|b| b.slot == slot)?;
        let (res, off) = view_target(dev, view, owner)?;
        let (_, _, view_len) = dev.view_range(dev.slot_of(view, KIND_VIEW, owner)?)?;
        len = len.min(view_len);
        if decl.access & BIND_ACCESS_WRITE != 0 {
            dst = Some((res, off));
        } else if src.is_none() {
            src = Some((res, off));
        }
    }
    Some(PlannedItem {
        src: src?,
        dst: dst?,
        len: if len == u64::MAX { 0 } else { len },
        k,
    })
}

/// The resource slot and absolute offset a view names.
fn view_target(dev: &GpuDevice<'_>, view: u64, owner: u16) -> Option<(u16, u64)> {
    let vslot = dev.slot_of(view, KIND_VIEW, owner)?;
    let (res, offset, _) = dev.view_range(vslot)?;
    Some((res, offset))
}

/// The CPU oracle for the fixture transformation.
///
/// One line, on purpose: a fixture whose expected answer needs a second
/// implementation to compute is a fixture that can agree with a bug.
#[must_use]
pub fn replay_expected(input: u8, constants: &[u8]) -> u8 {
    constants.iter().fold(input, |acc, k| acc.wrapping_add(*k))
}
