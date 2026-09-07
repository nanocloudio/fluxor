//! Native GPU compute over wgpu/Vulkan, headless — the provider behind the
//! `linux_gpu` built-in.
//!
//! The generic GPU contract on a real device, with no display, no swapchain
//! and no window: a compute graph builds and runs here on a Pi 5's V3D exactly
//! as it does on a workstation's discrete card, because nothing in the path
//! touches presentation.
//!
//! ## The split
//!
//! Validation, handles, views, sealing, residency, fences, dependency order,
//! candidate-output commit and epochs are the shared cores
//! (`modules/sdk/cores/gpu_*.rs`) — the same code the `gpu_null` provider runs,
//! so both are held to one lifetime corpus. This file owns exactly what wgpu
//! owns: adapters, buffers, shader modules, pipelines, encoders and mapped
//! memory.
//!
//! ## Why a worker thread
//!
//! A cooperative step must not block. Adapter and device creation are
//! asynchronous; shader compilation can take tens of milliseconds; `map_async`
//! completes on a poll. Doing any of that inline would blow a step budget the
//! whole scheduler depends on.
//!
//! So the device lives on a dedicated thread. A step translates admitted work
//! into owned jobs, hands them over, and applies whatever results have come
//! back. The translation is where bytes are copied — an upload leaves the
//! record it arrived in, because the record is gone by the time the queue
//! writes it — and that copy is a real cost, counted rather than hidden.
//!
//! ## Bytes in, bytes out
//!
//! [`GpuProvider`] takes command bytes and produces outcome bytes. It touches
//! no channel, which is what lets the same provider be driven by the built-in
//! wrapper in a live graph and by a test against a real adapter. I/O belongs at
//! the edge; this is not the edge.
//!
//! ## What it advertises
//!
//! Only what has been demonstrated on the adapter it actually opened. WGSL is
//! the one accepted program target: SPIR-V passthrough needs an exact-version
//! validation story this provider does not have, so it is refused rather than
//! half-supported. Raster, shared surfaces and device reset are not advertised,
//! because none of them is implemented here — a union of what wgpu could do
//! would make the capability record worthless.

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};

use crate::abi::contracts::gpu as gpu_wire;

// ── Sizing ──────────────────────────────────────────────────────────────

const MAX_RESOURCES: usize = 256;
const MAX_VIEWS: usize = 512;
const MAX_PROGRAMS: usize = 64;
const MAX_PIPELINES: usize = 64;
const MAX_FENCES: usize = 256;
const MAX_SURFACES: usize = 4;
/// Command bytes buffered from the input channel; one whole record must fit.
const CMD_BUF: usize = gpu_wire::MAX_RECORD + 64 * 1024;
/// Outcome ring, sized to hold several maximal readback chunks so a consumer
/// draining once per step never stalls the device on one large result.
const RING_BYTES: usize = 512 * 1024;
/// Assembly buffer for one chunked program pack at a time.
const PACK_BUF: usize = 1024 * 1024;

const OWNER: u16 = 0;

// ── Worker protocol ─────────────────────────────────────────────────────
//
// Everything crossing the thread boundary is owned. Nothing borrows a record,
// a table or a device object, so neither side can be blocked by the other's
// lifetimes.

/// One validated dispatch or copy, in terms of table slots.
#[cfg_attr(
    not(feature = "host-gpu"),
    allow(
        dead_code,
        reason = "without the backend the worker that reads these is compiled \
                  out, but the protocol stays so the module still frames the \
                  contract and refuses with a reason"
    )
)]
enum ExecItem {
    Dispatch {
        pipeline: u16,
        /// `(binding index, buffer slot, byte offset, byte size)`.
        binds: Vec<(u32, u16, u64, u64)>,
        groups: [u32; 3],
    },
    Copy {
        src: u16,
        src_offset: u64,
        dst: u16,
        dst_offset: u64,
        len: u64,
    },
}

#[cfg_attr(
    not(feature = "host-gpu"),
    allow(
        dead_code,
        reason = "without the backend the worker that reads these is compiled \
                  out, but the protocol stays so the module still frames the \
                  contract and refuses with a reason"
    )
)]
enum Job {
    CreateBuffer {
        fence: u16,
        slot: u16,
        size: u64,
        usage: u32,
    },
    DestroyBuffer {
        fence: u16,
        slot: u16,
    },
    LoadProgram {
        fence: u16,
        slot: u16,
        wgsl: String,
        entry: String,
    },
    CreatePipeline {
        fence: u16,
        slot: u16,
        program: u16,
    },
    ReleaseProgram {
        fence: u16,
        slot: u16,
    },
    ReleasePipeline {
        fence: u16,
        slot: u16,
    },
    Upload {
        fence: u16,
        slot: u16,
        offset: u64,
        bytes: Vec<u8>,
    },
    Submit {
        fence: u16,
        items: Vec<ExecItem>,
    },
    Readback {
        fence: u16,
        slot: u16,
        offset: u64,
        len: u32,
    },
    Drain {
        fence: u16,
    },
}

#[cfg_attr(
    not(feature = "host-gpu"),
    allow(
        dead_code,
        reason = "without the backend the worker that reads these is compiled \
                  out, but the protocol stays so the module still frames the \
                  contract and refuses with a reason"
    )
)]
enum Done {
    /// The adapter opened; these are the facts it published.
    Ready(Box<AdapterFacts>),
    /// The adapter could not be opened. The provider stays refusing.
    Unavailable(String),
    Completed {
        fence: u16,
        gpu_nanos: u64,
    },
    Failed {
        fence: u16,
        reason: u16,
        detail: u32,
    },
    PipelineReady {
        slot: u16,
        ok: bool,
    },
    Bytes {
        fence: u16,
        offset: u64,
        bytes: Vec<u8>,
    },
}

/// What the opened adapter can actually do, read off the adapter rather than
/// assumed from the backend's name.
#[cfg_attr(
    not(feature = "host-gpu"),
    allow(
        dead_code,
        reason = "without the backend the worker that reads these is compiled \
                  out, but the protocol stays so the module still frames the \
                  contract and refuses with a reason"
    )
)]
struct AdapterFacts {
    name: String,
    driver: String,
    limits: gpu_wire::DeviceLimits,
}

// ── Module state ────────────────────────────────────────────────────────

/// A GPU provider: command bytes in, outcome bytes out.
pub struct GpuProvider {
    /// Set once the worker answers with an adapter's facts. Nothing is
    /// admitted before then, because there is no device to admit against.
    live: bool,
    /// The adapter could not be opened and never will be in this process.
    unavailable: bool,

    to_worker: Sender<Job>,
    from_worker: Receiver<Done>,

    limits: gpu_wire::DeviceLimits,

    cmd: Vec<u8>,
    cmd_len: u32,
    ring: Vec<u8>,
    pack_buf: Vec<u8>,
    out_buf: Vec<u8>,

    resources: Vec<gpu_wire::ResourceSlot>,
    views: Vec<gpu_wire::ViewSlot>,
    programs: Vec<gpu_wire::ProgramSlot>,
    pipelines: Vec<gpu_wire::PipelineSlot>,
    fences: Vec<gpu_wire::FenceSlot>,
    surfaces: Vec<gpu_wire::SurfaceSlot>,
    saved: gpu_wire::DeviceScalars,

    pack: gpu_wire::PackCursor,
    out: gpu_wire::OutCursor,
    faulted: bool,

    /// The artifact bytes of a program the worker has not been told about yet
    /// — a pack is validated by the core before its WGSL is handed over.
    program_source: HashMap<u16, (String, String)>,
    /// Submissions admitted but not yet runnable, keyed by fence slot. Held
    /// here because the record they were decoded from is gone by the time
    /// their dependencies settle.
    deferred: HashMap<u16, Vec<ExecItem>>,
    /// Readbacks the worker has answered but whose bytes have not all reached
    /// the outcome ring: `(fence, offset, bytes, sent)`.
    pending_bytes: Vec<(u16, u64, Vec<u8>, usize)>,
}

// ── The worker ──────────────────────────────────────────────────────────

#[cfg(feature = "host-gpu")]
mod worker {
    use super::{AdapterFacts, Done, ExecItem, Job};
    use std::collections::HashMap;
    use std::sync::mpsc::{Receiver, Sender};

    use crate::abi::contracts::gpu as w;

    /// Open an adapter and serve jobs until the channel closes.
    ///
    /// Every error here becomes a structured outcome rather than a panic: a
    /// GPU that will not open is a capability the graph must be told about,
    /// not a reason to take the process down.
    pub fn run(jobs: Receiver<Job>, out: Sender<Done>, resident_bytes: u64, staging_bytes: u64) {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: wgpu::Backends::VULKAN,
            ..Default::default()
        });
        // Headless: no compatible surface is requested, and none is needed.
        // A compute graph must build where no display server exists.
        let adapter =
            match pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                force_fallback_adapter: false,
                compatible_surface: None,
            })) {
                Ok(a) => a,
                Err(e) => {
                    let _ = out.send(Done::Unavailable(format!("no Vulkan adapter: {e}")));
                    return;
                }
            };
        let info = adapter.get_info();
        let adapter_limits = adapter.limits();
        let features = adapter.features();

        // Request only what a compute profile needs. Asking for the adapter's
        // full limit set is how a device creation fails on the one machine
        // that has a smaller ceiling for something nothing uses.
        let mut wanted =
            wgpu::Limits::downlevel_defaults().using_resolution(adapter_limits.clone());
        wanted.max_storage_buffer_binding_size = adapter_limits.max_storage_buffer_binding_size;
        wanted.max_buffer_size = adapter_limits.max_buffer_size;
        wanted.max_compute_workgroup_size_x = adapter_limits.max_compute_workgroup_size_x;
        wanted.max_compute_workgroup_size_y = adapter_limits.max_compute_workgroup_size_y;
        wanted.max_compute_workgroup_size_z = adapter_limits.max_compute_workgroup_size_z;
        wanted.max_compute_invocations_per_workgroup =
            adapter_limits.max_compute_invocations_per_workgroup;
        wanted.max_compute_workgroups_per_dimension =
            adapter_limits.max_compute_workgroups_per_dimension;
        let timestamps = features.contains(wgpu::Features::TIMESTAMP_QUERY);
        let (device, queue) =
            match pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
                label: Some("fluxor-gpu"),
                required_features: wgpu::Features::empty(),
                required_limits: wanted,
                memory_hints: Default::default(),
                trace: wgpu::Trace::Off,
            })) {
                Ok(pair) => pair,
                Err(e) => {
                    let _ = out.send(Done::Unavailable(format!("device: {e}")));
                    return;
                }
            };

        // Validation errors arrive asynchronously. Logging them is the whole
        // reason a wgpu failure is debuggable at all; the fence that caused
        // one still fails through the normal path.
        device.on_uncaptured_error(Box::new(|e| {
            log::error!("[linux_gpu] wgpu: {e}");
        }));

        let limits = facts_from(&adapter_limits, features, resident_bytes, staging_bytes);
        let _ = out.send(Done::Ready(Box::new(AdapterFacts {
            name: info.name.clone(),
            driver: format!("{} ({})", info.driver, info.driver_info),
            limits,
        })));

        let mut buffers: HashMap<u16, wgpu::Buffer> = HashMap::new();
        let mut modules: HashMap<u16, (wgpu::ShaderModule, String)> = HashMap::new();
        let mut pipelines: HashMap<u16, wgpu::ComputePipeline> = HashMap::new();

        while let Ok(job) = jobs.recv() {
            match job {
                Job::CreateBuffer {
                    fence,
                    slot,
                    size,
                    usage,
                } => {
                    let buf = device.create_buffer(&wgpu::BufferDescriptor {
                        label: None,
                        size: size.max(4),
                        usage: buffer_usage(usage),
                        mapped_at_creation: false,
                    });
                    buffers.insert(slot, buf);
                    let _ = out.send(Done::Completed {
                        fence,
                        gpu_nanos: 0,
                    });
                }

                Job::DestroyBuffer { fence, slot } => {
                    if let Some(b) = buffers.remove(&slot) {
                        b.destroy();
                    }
                    let _ = out.send(Done::Completed {
                        fence,
                        gpu_nanos: 0,
                    });
                }

                Job::LoadProgram {
                    fence,
                    slot,
                    wgsl,
                    entry,
                } => {
                    // Parsing happens here, off the cooperative step, and its
                    // errors become the fence's failure rather than a log line
                    // nobody correlates.
                    let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
                        label: None,
                        source: wgpu::ShaderSource::Wgsl(wgsl.into()),
                    });
                    modules.insert(slot, (module, entry));
                    let _ = out.send(Done::Completed {
                        fence,
                        gpu_nanos: 0,
                    });
                }

                Job::CreatePipeline {
                    fence,
                    slot,
                    program,
                } => {
                    let Some((module, entry)) = modules.get(&program) else {
                        let _ = out.send(Done::Failed {
                            fence,
                            reason: w::REASON_BAD_HANDLE,
                            detail: program as u32,
                        });
                        let _ = out.send(Done::PipelineReady { slot, ok: false });
                        continue;
                    };
                    device.push_error_scope(wgpu::ErrorFilter::Validation);
                    let pipeline =
                        device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                            label: None,
                            layout: None,
                            module,
                            entry_point: Some(entry.as_str()),
                            compilation_options: Default::default(),
                            cache: None,
                        });
                    let err = pollster::block_on(device.pop_error_scope());
                    if let Some(e) = err {
                        // A shader that does not compile is a graph-visible
                        // outcome, never a silently skipped dispatch.
                        log::error!("[linux_gpu] pipeline {slot}: {e}");
                        let _ = out.send(Done::Failed {
                            fence,
                            reason: w::REASON_BAD_PROGRAM,
                            detail: 0,
                        });
                        let _ = out.send(Done::PipelineReady { slot, ok: false });
                        continue;
                    }
                    pipelines.insert(slot, pipeline);
                    let _ = out.send(Done::PipelineReady { slot, ok: true });
                    let _ = out.send(Done::Completed {
                        fence,
                        gpu_nanos: 0,
                    });
                }

                Job::ReleaseProgram { fence, slot } => {
                    // A shader module the graph can no longer name is a leak
                    // that grows for the life of the process.
                    modules.remove(&slot);
                    let _ = out.send(Done::Completed {
                        fence,
                        gpu_nanos: 0,
                    });
                }

                Job::ReleasePipeline { fence, slot } => {
                    pipelines.remove(&slot);
                    let _ = out.send(Done::Completed {
                        fence,
                        gpu_nanos: 0,
                    });
                }

                Job::Upload {
                    fence,
                    slot,
                    offset,
                    bytes,
                } => {
                    let Some(buf) = buffers.get(&slot) else {
                        let _ = out.send(Done::Failed {
                            fence,
                            reason: w::REASON_BAD_HANDLE,
                            detail: slot as u32,
                        });
                        continue;
                    };
                    queue.write_buffer(buf, offset, &bytes);
                    // Flush it. A queued write sits in a staging belt until
                    // some submission carries it, and a belt entry is not what
                    // this fence promises: the empty submit hands the copy to
                    // the queue now, so the completion reported below is true
                    // of the device and not just of the staging buffer.
                    queue.submit([]);
                    let _ = out.send(Done::Completed {
                        fence,
                        gpu_nanos: 0,
                    });
                }

                Job::Submit { fence, items } => {
                    match record_and_submit(&device, &queue, &buffers, &pipelines, &items) {
                        Ok(()) => {
                            // Conservative queue completion: the whole queue
                            // is drained before the fence is reported. Not a
                            // per-submit GPU timestamp, and the outcome says
                            // so rather than reporting a CPU reading as one.
                            let _ = device.poll(wgpu::PollType::Wait);
                            let _ = out.send(Done::Completed {
                                fence,
                                gpu_nanos: 0,
                            });
                        }
                        Err((reason, detail)) => {
                            let _ = out.send(Done::Failed {
                                fence,
                                reason,
                                detail,
                            });
                        }
                    }
                }

                Job::Readback {
                    fence,
                    slot,
                    offset,
                    len,
                } => {
                    match readback(&device, &queue, &buffers, slot, offset, len) {
                        // Bytes only. The fence completes when they have all
                        // reached the outcome ring, which the step decides —
                        // completing here would report a result the consumer
                        // has no way to read.
                        Ok(bytes) => {
                            let _ = out.send(Done::Bytes {
                                fence,
                                offset,
                                bytes,
                            });
                        }
                        Err((reason, detail)) => {
                            let _ = out.send(Done::Failed {
                                fence,
                                reason,
                                detail,
                            });
                        }
                    }
                }

                Job::Drain { fence } => {
                    // Physical quiescence, not "the channel is empty": the
                    // device is polled to completion before the fence answers.
                    let _ = device.poll(wgpu::PollType::Wait);
                    let _ = out.send(Done::Completed {
                        fence,
                        gpu_nanos: 0,
                    });
                }
            }
        }
        let _ = timestamps;
    }

    /// Translate the contract's usage mask into wgpu's.
    ///
    /// `COPY_DST` is added unconditionally: an upload is a queue write, which
    /// wgpu requires the flag for, and a buffer nobody can put bytes into is
    /// not a resource any graph wants.
    fn buffer_usage(usage: u32) -> wgpu::BufferUsages {
        let mut u = wgpu::BufferUsages::COPY_DST;
        if usage & w::USAGE_STORAGE != 0 {
            u |= wgpu::BufferUsages::STORAGE;
        }
        if usage & w::USAGE_UNIFORM != 0 {
            u |= wgpu::BufferUsages::UNIFORM;
        }
        if usage & w::USAGE_VERTEX != 0 {
            u |= wgpu::BufferUsages::VERTEX;
        }
        if usage & w::USAGE_INDEX != 0 {
            u |= wgpu::BufferUsages::INDEX;
        }
        if usage & w::USAGE_INDIRECT != 0 {
            u |= wgpu::BufferUsages::INDIRECT;
        }
        if usage & (w::USAGE_COPY_SRC | w::USAGE_MAP_READ) != 0 {
            u |= wgpu::BufferUsages::COPY_SRC;
        }
        u
    }

    fn record_and_submit(
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        buffers: &HashMap<u16, wgpu::Buffer>,
        pipelines: &HashMap<u16, wgpu::ComputePipeline>,
        items: &[ExecItem],
    ) -> Result<(), (u16, u32)> {
        let mut enc = device.create_command_encoder(&Default::default());
        // Bind groups must outlive the pass that references them.
        let mut groups = Vec::new();
        for item in items {
            if let ExecItem::Dispatch {
                pipeline, binds, ..
            } = item
            {
                let p = pipelines
                    .get(pipeline)
                    .ok_or((w::REASON_BAD_HANDLE, *pipeline as u32))?;
                let layout = p.get_bind_group_layout(0);
                let mut entries = Vec::with_capacity(binds.len());
                for (binding, slot, offset, size) in binds {
                    let b = buffers
                        .get(slot)
                        .ok_or((w::REASON_BAD_HANDLE, *slot as u32))?;
                    entries.push(wgpu::BindGroupEntry {
                        binding: *binding,
                        resource: wgpu::BindingResource::Buffer(wgpu::BufferBinding {
                            buffer: b,
                            offset: *offset,
                            size: std::num::NonZeroU64::new(*size),
                        }),
                    });
                }
                groups.push(Some(device.create_bind_group(&wgpu::BindGroupDescriptor {
                    label: None,
                    layout: &layout,
                    entries: &entries,
                })));
            } else {
                groups.push(None);
            }
        }
        // Walk the items in order, opening a compute pass for each run of
        // dispatches and closing it before a copy. Order inside a submission
        // is the caller's declared order — a provider that hoisted every copy
        // to the end would silently change what the work computes.
        let mut i = 0usize;
        while i < items.len() {
            match &items[i] {
                ExecItem::Dispatch { .. } => {
                    let mut pass = enc.begin_compute_pass(&Default::default());
                    while let Some(ExecItem::Dispatch {
                        pipeline,
                        groups: g,
                        ..
                    }) = items.get(i)
                    {
                        let p = pipelines
                            .get(pipeline)
                            .ok_or((w::REASON_BAD_HANDLE, *pipeline as u32))?;
                        let bg = groups[i].as_ref().ok_or((w::REASON_BAD_HANDLE, 0))?;
                        pass.set_pipeline(p);
                        pass.set_bind_group(0, bg, &[]);
                        pass.dispatch_workgroups(g[0], g[1], g[2]);
                        i += 1;
                    }
                }
                ExecItem::Copy {
                    src,
                    src_offset,
                    dst,
                    dst_offset,
                    len,
                } => {
                    let s = buffers
                        .get(src)
                        .ok_or((w::REASON_BAD_HANDLE, *src as u32))?;
                    let d = buffers
                        .get(dst)
                        .ok_or((w::REASON_BAD_HANDLE, *dst as u32))?;
                    enc.copy_buffer_to_buffer(s, *src_offset, d, *dst_offset, *len);
                    i += 1;
                }
            }
        }
        queue.submit([enc.finish()]);
        Ok(())
    }

    fn readback(
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        buffers: &HashMap<u16, wgpu::Buffer>,
        slot: u16,
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, (u16, u32)> {
        let src = buffers
            .get(&slot)
            .ok_or((w::REASON_BAD_HANDLE, slot as u32))?;
        // Copy sizes and offsets must be 4-aligned for wgpu; round the window
        // out and trim, so a caller's byte-granular request still works.
        let start = offset & !3;
        let lead = (offset - start) as usize;
        let span = ((lead + len as usize) as u64).div_ceil(4) * 4;
        let staging = device.create_buffer(&wgpu::BufferDescriptor {
            label: None,
            size: span,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let mut enc = device.create_command_encoder(&Default::default());
        enc.copy_buffer_to_buffer(src, start, &staging, 0, span);
        queue.submit([enc.finish()]);

        let slice = staging.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |r| {
            let _ = tx.send(r);
        });
        if device.poll(wgpu::PollType::Wait).is_err() {
            return Err((w::REASON_DEVICE_LOST, 0));
        }
        match rx.recv() {
            Ok(Ok(())) => {}
            _ => return Err((w::REASON_TIMEOUT, 0)),
        }
        let view = slice.get_mapped_range();
        let bytes = view[lead..lead + len as usize].to_vec();
        drop(view);
        staging.unmap();
        staging.destroy();
        Ok(bytes)
    }

    /// Build the contract's device facts from the adapter's own limits.
    ///
    /// Every entry is either read off the adapter or is a decision this
    /// provider stands behind. Nothing is inherited from what another backend
    /// can do, and the arithmetic table in particular is filled from the
    /// adapter's declared features rather than from what WGSL can spell.
    fn facts_from(
        limits: &wgpu::Limits,
        features: wgpu::Features,
        resident_bytes: u64,
        staging_bytes: u64,
    ) -> w::DeviceLimits {
        let mut l = w::DeviceLimits::baseline();

        let mut arith = [0u8; w::ARITH_TYPE_COUNT];
        let native = w::ARITH_STORAGE | w::ARITH_COMPUTE | w::ARITH_ACCUM | w::ARITH_NATIVE;
        // WGSL's scalar types on any conformant device.
        arith[w::ARITH_I32] = native;
        arith[w::ARITH_U32] = native;
        arith[w::ARITH_F32] = native;
        // Storable in a buffer, not computable as a type: a packed i8 tensor
        // is bytes, and calling that "i8 arithmetic" is the exact confusion
        // the four independent fact bits exist to prevent.
        arith[w::ARITH_I8] = w::ARITH_STORAGE;
        arith[w::ARITH_U8] = w::ARITH_STORAGE;
        arith[w::ARITH_I16] = w::ARITH_STORAGE;
        arith[w::ARITH_U16] = w::ARITH_STORAGE;
        // f16 only where the adapter says so. On a Pi 5's V3D it does not,
        // and advertising it because "some Vulkan device has it" would be the
        // union-of-backends claim this contract forbids.
        if features.contains(wgpu::Features::SHADER_F16) {
            arith[w::ARITH_F16] = native;
        }
        // BF16, packed INT4 and ternary have no path here — native or
        // emulated — so they stay declared absent.
        l.arith_types = arith;
        l.arith_ops = w::AOP_FMA_F32 | w::AOP_ATOMIC_I32;

        let mut features_out = w::FEATURE_COMPUTE | w::FEATURE_READBACK;
        if features.contains(wgpu::Features::TIMESTAMP_QUERY) {
            // The adapter can time work. This provider does not yet place
            // timestamp queries, so the fact is advertised and every
            // completion still flags itself queue-timed until it does.
            features_out |= w::FEATURE_TIMESTAMP;
        }
        // Not advertised, because not implemented here: raster, shared
        // surfaces, indirect dispatch, subgroups, preemption — and device
        // reset, which needs demonstrated quiescence rather than a hope that
        // recreating an adapter is enough.
        l.features = features_out;

        l.targets = [
            w::TARGET_WGSL,
            w::TARGET_NONE,
            w::TARGET_NONE,
            w::TARGET_NONE,
        ];
        l.min_align = limits
            .min_storage_buffer_offset_alignment
            .max(limits.min_uniform_buffer_offset_alignment);
        l.max_bindings = (w::MAX_PROGRAM_BINDINGS as u32).min(limits.max_bindings_per_bind_group);
        l.max_workgroup = [
            limits.max_compute_workgroup_size_x,
            limits.max_compute_workgroup_size_y,
            limits.max_compute_workgroup_size_z,
        ];
        l.max_workgroup_invocations = limits.max_compute_invocations_per_workgroup;
        let grid = limits.max_compute_workgroups_per_dimension;
        l.max_grid = [grid, grid, grid];
        l.max_alloc_bytes = limits
            .max_buffer_size
            .min(limits.max_storage_buffer_binding_size as u64);
        // Memory budgets are a deployment decision, not an adapter fact: the
        // adapter will happily let a graph allocate until the system dies.
        l.max_resident_bytes = resident_bytes.min(l.max_alloc_bytes.saturating_mul(64));
        l.max_staging_bytes = staging_bytes;
        l.max_scratch_bytes = l.max_resident_bytes;
        l.max_queue_depth = 64;
        l
    }
}

// ── Driving the provider ────────────────────────────────────────────────

impl GpuProvider {
    /// Open an adapter on a dedicated thread and build the provider around it.
    ///
    /// Returns immediately: the adapter is not open yet, and [`Self::live`]
    /// answers when it is. A constructor that blocked here would put hundreds
    /// of milliseconds of driver initialisation inside whatever called it.
    #[must_use]
    pub fn new(resident_bytes: u64, staging_bytes: u64) -> Self {
        let (to_worker, jobs) = std::sync::mpsc::channel::<Job>();
        let (results, from_worker) = std::sync::mpsc::channel::<Done>();

        #[cfg(feature = "host-gpu")]
        {
            if let Err(e) = std::thread::Builder::new()
                .name("fluxor-gpu".into())
                .spawn(move || worker::run(jobs, results, resident_bytes, staging_bytes))
            {
                log::error!("[linux_gpu] cannot spawn the device thread: {e}");
            }
        }
        #[cfg(not(feature = "host-gpu"))]
        {
            // Built without the backend. Say so once, and refuse every request
            // with a reason rather than accepting work nothing will run.
            let _ = (resident_bytes, staging_bytes);
            drop(jobs);
            let _ = results.send(Done::Unavailable(
                "built without --features host-gpu".into(),
            ));
        }

        Self {
            live: false,
            unavailable: false,
            to_worker,
            from_worker,
            // Until the adapter answers, these size nothing that runs: no
            // request is admitted before `live`.
            limits: gpu_wire::DeviceLimits::baseline(),
            cmd: vec![0u8; CMD_BUF],
            cmd_len: 0,
            ring: vec![0u8; RING_BYTES],
            pack_buf: vec![0u8; PACK_BUF],
            out_buf: vec![0u8; gpu_wire::MAX_RECORD],
            resources: vec![gpu_wire::ResourceSlot::EMPTY; MAX_RESOURCES],
            views: vec![gpu_wire::ViewSlot::EMPTY; MAX_VIEWS],
            programs: vec![gpu_wire::ProgramSlot::EMPTY; MAX_PROGRAMS],
            pipelines: vec![gpu_wire::PipelineSlot::EMPTY; MAX_PIPELINES],
            fences: vec![gpu_wire::FenceSlot::EMPTY; MAX_FENCES],
            surfaces: vec![gpu_wire::SurfaceSlot::EMPTY; MAX_SURFACES],
            saved: gpu_wire::DeviceScalars::initial(),
            pack: gpu_wire::PackCursor::idle(),
            out: gpu_wire::OutCursor::default(),
            faulted: false,
            program_source: HashMap::new(),
            deferred: HashMap::new(),
            pending_bytes: Vec::new(),
        }
    }

    /// Whether an adapter is open and requests can be admitted.
    #[must_use]
    pub fn live(&self) -> bool {
        self.live
    }

    /// Whether no adapter will ever open in this process — the build has no
    /// backend, or the driver refused. A graph is better told this than left
    /// waiting for outcomes that cannot come.
    #[must_use]
    pub fn unavailable(&self) -> bool {
        self.unavailable
    }

    /// The adapter's published facts, once it is live.
    #[must_use]
    pub fn limits(&self) -> &gpu_wire::DeviceLimits {
        &self.limits
    }

    /// Room left in the command buffer.
    #[must_use]
    pub fn command_space(&self) -> usize {
        self.cmd.len() - self.cmd_len as usize
    }

    /// Buffer command bytes, answering how many were taken.
    ///
    /// A short answer is backpressure, not loss: the caller keeps the rest and
    /// offers it again. A faulted stream takes nothing at all.
    pub fn feed(&mut self, bytes: &[u8]) -> usize {
        if self.faulted {
            return 0;
        }
        let room = self.command_space();
        let n = room.min(bytes.len());
        let at = self.cmd_len as usize;
        self.cmd[at..at + n].copy_from_slice(&bytes[..n]);
        self.cmd_len += n as u32;
        n
    }

    /// One cooperative step: apply the worker's answers, admit what is
    /// buffered, dispatch what has become runnable, and append outcome records
    /// to `out`.
    ///
    /// `out` grows by whole records only. A consumer decoding a byte FIFO
    /// cannot recover from half a header.
    pub fn step(&mut self, out: &mut Vec<u8>) {
        self.apply_worker_results();
        if self.unavailable {
            self.refuse_buffered(out);
            return;
        }
        if !self.live {
            return;
        }
        self.pump(out);
    }

    /// Answer every buffered request with a rejection, because no device will
    /// ever open here.
    fn refuse_buffered(&mut self, out: &mut Vec<u8>) {
        gpu_wire::refuse_records(
            &mut self.cmd,
            &mut self.cmd_len,
            &mut self.faulted,
            gpu_wire::REASON_DEVICE_LOST,
            |bytes| {
                out.extend_from_slice(bytes);
                bytes.len() as i32
            },
        );
    }
}

impl GpuProvider {
    /// Drain the worker's answers and apply them to the device.
    fn apply_worker_results(&mut self) {
        let st = self;
        let mut batch: Vec<Done> = Vec::new();
        loop {
            match st.from_worker.try_recv() {
                Ok(Done::Ready(facts)) => {
                    log::info!(
                        "[linux_gpu] {} via {} — align {} B, workgroup {}x{}x{}, {} bindings, \
                     f16 {}, timestamps {}",
                        facts.name,
                        facts.driver,
                        facts.limits.min_align,
                        facts.limits.max_workgroup[0],
                        facts.limits.max_workgroup[1],
                        facts.limits.max_workgroup[2],
                        facts.limits.max_bindings,
                        facts.limits.arith_types[gpu_wire::ARITH_F16] & gpu_wire::ARITH_NATIVE != 0,
                        facts.limits.features & gpu_wire::FEATURE_TIMESTAMP != 0,
                    );
                    st.limits = facts.limits;
                    st.live = true;
                }
                Ok(Done::Unavailable(why)) => {
                    log::warn!("[linux_gpu] no GPU: {why}");
                    st.unavailable = true;
                    return;
                }
                Ok(msg) => batch.push(msg),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    if !st.unavailable && !st.live {
                        log::error!(
                            "[linux_gpu] the device thread ended before opening an adapter"
                        );
                        st.unavailable = true;
                    }
                    break;
                }
            }
        }
        if batch.is_empty() {
            return;
        }

        let Self {
            limits,
            ring,
            resources,
            views,
            programs,
            pipelines,
            fences,
            surfaces,
            saved,
            pending_bytes,
            ..
        } = st;
        let mut dev = gpu_wire::GpuDevice::restore(
            gpu_wire::GpuTables {
                resources,
                views,
                programs,
                pipelines,
                fences,
                surfaces,
                outcomes: ring,
            },
            *limits,
            gpu_wire::BACKEND_WGPU_NATIVE,
            1,
            *saved,
        );
        for msg in batch {
            match msg {
                Done::Completed { fence, gpu_nanos } => dev.complete(fence, gpu_nanos),
                Done::Failed {
                    fence,
                    reason,
                    detail,
                } => dev.fail(fence, reason, detail),
                Done::PipelineReady { slot, ok } => dev.mark_pipeline_ready(slot, ok),
                // The bytes exist; getting them into the ring may take several
                // steps, and until they are all there the fence is not finished.
                Done::Bytes {
                    fence,
                    offset,
                    bytes,
                } => pending_bytes.push((fence, offset, bytes, 0)),
                Done::Ready(_) | Done::Unavailable(_) => {}
            }
        }
        *saved = dev.save();
    }

    /// Admit what is buffered, dispatch what has become runnable, and append
    /// outcome records.
    ///
    /// The state is destructured once: the device borrows the tables for the whole
    /// step, so the command buffer, the pack assembly, the worker handle and the
    /// pending results all have to be disjoint borrows taken at the same moment.
    fn pump(&mut self, sink: &mut Vec<u8>) {
        let Self {
            to_worker,
            limits,
            cmd,
            cmd_len,
            ring,
            pack_buf,
            out_buf,
            resources,
            views,
            programs,
            pipelines,
            fences,
            surfaces,
            saved,
            pack,
            out,
            faulted,
            program_source,
            deferred,
            pending_bytes,
            ..
        } = self;

        let mut dev = gpu_wire::GpuDevice::restore(
            gpu_wire::GpuTables {
                resources,
                views,
                programs,
                pipelines,
                fences,
                surfaces,
                outcomes: ring,
            },
            *limits,
            gpu_wire::BACKEND_WGPU_NATIVE,
            1,
            *saved,
        );
        // The caller owns the transport; whole records are appended and always
        // accepted, so the staging cursor never has to hold a partial run.
        let mut write = |bytes: &[u8]| -> i32 {
            sink.extend_from_slice(bytes);
            bytes.len() as i32
        };

        // Results the device already has must reach the ring before more work is
        // taken on, or a large readback would be starved by fresh submissions.
        drain_pending_bytes(&mut dev, pending_bytes);
        gpu_wire::flush_outcomes(&mut dev, out_buf, out, &mut write);

        gpu_wire::pump_admit(
            &mut dev,
            OWNER,
            cmd,
            cmd_len,
            faulted,
            |dev, record, work| {
                translate(
                    dev,
                    to_worker,
                    program_source,
                    deferred,
                    pack,
                    pack_buf,
                    record,
                    work,
                )
            },
        );

        // Dependencies settle, then anything now runnable goes to the device.
        dev.advance();
        while let Some(fence) = dev.next_ready() {
            dev.mark_running(fence);
            let op = dev.fence(fence).map_or(0, |f| f.op);
            let sent = if let Some(items) = deferred.remove(&fence) {
                to_worker.send(Job::Submit { fence, items }).is_ok()
            } else if op == gpu_wire::OP_DRAIN {
                to_worker.send(Job::Drain { fence }).is_ok()
            } else if op == gpu_wire::OP_SUBMIT {
                // A submission whose plan is gone cannot be reported as done: the
                // work never reached the queue, and completing it here would be
                // the one failure mode a caller has no way to detect. The provider
                // has lost the ability to run it, which is what device-lost means
                // to a caller that is holding the fence.
                dev.fail(fence, gpu_wire::REASON_DEVICE_LOST, 0);
                true
            } else {
                // Nothing to run: the request was handled at admission and the
                // device is waiting for a completion that will never come.
                dev.complete(fence, 0);
                true
            };
            if !sent {
                dev.fail(fence, gpu_wire::REASON_DEVICE_LOST, 0);
            }
        }

        drain_pending_bytes(&mut dev, pending_bytes);
        gpu_wire::flush_outcomes(&mut dev, out_buf, out, &mut write);
        // Saved last: draining is what advances the ring's cursor, and a save
        // taken before it would roll that cursor back and re-emit every record.
        *saved = dev.save();
    }
}

/// Move readback bytes into the outcome ring in bounded chunks, completing a
/// fence only once every byte it owes has landed there.
fn drain_pending_bytes(
    dev: &mut gpu_wire::GpuDevice<'_>,
    pending: &mut Vec<(u16, u64, Vec<u8>, usize)>,
) {
    let mut i = 0;
    while i < pending.len() {
        let (fence, offset, bytes, sent) = &mut pending[i];
        let mut progressed = true;
        while *sent < bytes.len() && progressed {
            let chunk = (bytes.len() - *sent).min(gpu_wire::MAX_PAYLOAD as usize - 24);
            progressed =
                dev.push_result(*fence, *offset + *sent as u64, &bytes[*sent..*sent + chunk]);
            if progressed {
                *sent += chunk;
            }
        }
        if *sent >= bytes.len() {
            // Every owed byte is in the ring, so the fence can finish. Doing
            // this earlier would report a result the consumer cannot read.
            dev.complete(*fence, 0);
            pending.remove(i);
        } else {
            // The ring is full. Leave the rest here and retry next step —
            // dropping it would be indistinguishable from work that never ran.
            i += 1;
        }
    }
}

/// Turn one admitted request into an owned job for the worker.
///
/// Everything crossing the thread boundary is copied here, because the record
/// it came from is gone by the time the queue writes it. That copy is the
/// explicit transfer cost this contract insists on reporting rather than
/// hiding.
#[allow(
    clippy::too_many_arguments,
    reason = "the disjoint borrows the step split out of one state struct; \
              re-boxing them would only move the destructuring"
)]
fn translate(
    dev: &mut gpu_wire::GpuDevice<'_>,
    to_worker: &Sender<Job>,
    program_source: &mut HashMap<u16, (String, String)>,
    deferred: &mut HashMap<u16, Vec<ExecItem>>,
    pack: &mut gpu_wire::PackCursor,
    pack_buf: &mut [u8],
    record: &[u8],
    work: gpu_wire::Work,
) -> bool {
    use gpu_wire::Work;
    let send = |dev: &mut gpu_wire::GpuDevice<'_>, fence: u16, job: Job| {
        dev.mark_running(fence);
        if to_worker.send(job).is_err() {
            dev.fail(fence, gpu_wire::REASON_DEVICE_LOST, 0);
        }
    };

    match work {
        Work::None => true,

        Work::CreateBuffer { fence, slot } | Work::CreateTexture { fence, slot } => {
            let (size, usage) = dev.resource(slot).map_or((0, 0), |r| (r.size, r.usage));
            send(
                dev,
                fence,
                Job::CreateBuffer {
                    fence,
                    slot,
                    size,
                    usage,
                },
            );
            true
        }

        Work::DestroyResource { fence, slot } => {
            // The handle is retired already; the object goes only once nothing
            // in flight can still reach it.
            if dev.resource_free_pending(slot) || dev.resource(slot).is_none_or(|r| !r.live) {
                send(dev, fence, Job::DestroyBuffer { fence, slot });
            } else {
                dev.mark_running(fence);
                dev.complete(fence, 0);
            }
            true
        }

        Work::LoadProgram {
            fence,
            slot,
            chunk_offset,
            payload_offset,
            chunk_len,
        } => {
            let Some(bytes) = record.get(payload_offset..payload_offset + chunk_len) else {
                dev.fail(fence, gpu_wire::REASON_MALFORMED, 0);
                return true;
            };
            // How many bytes the whole pack is, read before absorbing: the
            // cursor is cleared the moment the last chunk validates.
            let declared = dev.program(slot).map_or(0, |p| p.declared) as usize;
            // The pack is validated by the shared core before a single byte of
            // it reaches a shader compiler.
            if gpu_wire::absorb_pack_chunk(dev, pack, pack_buf, fence, slot, chunk_offset, bytes)
                != gpu_wire::PackChunk::Loaded
            {
                return true;
            }
            // Re-decode the assembled pack for its artifact bytes and entry
            // point: the program slot keeps the validated manifest, not the
            // source. It decoded once already, so this cannot fail — and the
            // arm below says so rather than inventing a reason.
            match gpu_wire::decode(&pack_buf[..declared.min(pack_buf.len())]) {
                Ok(p) => match (
                    core::str::from_utf8(p.artifact()),
                    core::str::from_utf8(p.entry()),
                ) {
                    (Ok(wgsl), Ok(entry)) => {
                        program_source.insert(slot, (wgsl.to_string(), entry.to_string()));
                        send(
                            dev,
                            fence,
                            Job::LoadProgram {
                                fence,
                                slot,
                                wgsl: wgsl.to_string(),
                                entry: entry.to_string(),
                            },
                        );
                    }
                    _ => {
                        // WGSL is text. Bytes that are not text are not WGSL,
                        // whatever the manifest declared.
                        dev.fail(fence, gpu_wire::REASON_BAD_PROGRAM, 0);
                    }
                },
                Err(e) => dev.fail(fence, gpu_wire::REASON_BAD_PROGRAM, e as u32),
            }
            true
        }

        Work::CreatePipeline {
            fence,
            slot,
            program,
        } => {
            if program_source.contains_key(&program) {
                send(
                    dev,
                    fence,
                    Job::CreatePipeline {
                        fence,
                        slot,
                        program,
                    },
                );
            } else {
                dev.fail(fence, gpu_wire::REASON_BAD_HANDLE, program as u32);
            }
            true
        }

        Work::ReleaseProgram { fence, slot } => {
            program_source.remove(&slot);
            send(dev, fence, Job::ReleaseProgram { fence, slot });
            true
        }

        Work::ReleasePipeline { fence, slot } => {
            send(dev, fence, Job::ReleasePipeline { fence, slot });
            true
        }

        Work::Upload {
            fence,
            resource,
            offset,
            payload_offset,
            len,
        } => {
            let Some(bytes) = record.get(payload_offset..payload_offset + len as usize) else {
                dev.fail(fence, gpu_wire::REASON_MALFORMED, 0);
                return true;
            };
            send(
                dev,
                fence,
                Job::Upload {
                    fence,
                    slot: resource,
                    offset,
                    bytes: bytes.to_vec(),
                },
            );
            true
        }

        Work::Readback {
            fence,
            resource,
            offset,
            len,
        } => {
            send(
                dev,
                fence,
                Job::Readback {
                    fence,
                    slot: resource,
                    offset,
                    len,
                },
            );
            true
        }

        Work::Submit {
            fence,
            items_offset,
            items_len,
            ..
        } => {
            match plan_submission(dev, record, items_offset, items_len) {
                Some(items) => {
                    // Held until its dependencies settle: the record it was
                    // decoded from is gone by then, so the plan has to outlive
                    // it.
                    deferred.insert(fence, items);
                }
                None => dev.fail(fence, gpu_wire::REASON_BAD_HANDLE, 0),
            }
            true
        }

        Work::Drain { .. } => true,

        Work::Cancel { fence, .. } => {
            // No preemption is advertised, so there is nothing to ask the
            // device for. The disposition the core already reported is the
            // truth: the work runs, only its publication is suppressed.
            dev.mark_running(fence);
            dev.complete(fence, 0);
            true
        }

        Work::Reset { fence, .. } => {
            // Reset is not advertised and admission refuses it; reaching here
            // would mean the capability record and this file disagree.
            dev.fail(
                fence,
                gpu_wire::REASON_UNSUPPORTED_FEATURE,
                gpu_wire::FEATURE_DEVICE_RESET,
            );
            true
        }

        Work::ExportSurface { fence, .. } => {
            dev.fail(
                fence,
                gpu_wire::REASON_UNSUPPORTED_FEATURE,
                gpu_wire::FEATURE_SHARED_SURFACE,
            );
            true
        }
    }
}

/// Resolve a validated submission into slot-addressed work.
///
/// Admission already proved every handle, range, alignment, usage and right;
/// this only translates. A `None` here means a handle stopped resolving
/// between admission and now, which is a device-epoch change rather than a
/// caller error.
fn plan_submission(
    dev: &gpu_wire::GpuDevice<'_>,
    record: &[u8],
    items_offset: usize,
    items_len: usize,
) -> Option<Vec<ExecItem>> {
    let walk = dev.items(record, items_offset, items_len);
    let bytes = walk.bytes();
    let mut out = Vec::new();
    for item in dev.items(record, items_offset, items_len) {
        match item {
            gpu_wire::SubmitItem::Dispatch {
                pipeline,
                binds_offset,
                bind_count,
                groups,
            } => {
                let pslot = dev.slot_of(pipeline, gpu_wire::KIND_PIPELINE, OWNER)?;
                let mut binds = Vec::with_capacity(bind_count);
                for i in 0..bind_count {
                    let e = binds_offset + i * gpu_wire::BIND_ENTRY_LEN;
                    let slot = gpu_wire::get_u16(bytes, e)?;
                    let view = gpu_wire::get_u64(bytes, e + 4)?;
                    let vslot = dev.slot_of(view, gpu_wire::KIND_VIEW, OWNER)?;
                    let (res, offset, len) = dev.view_range(vslot)?;
                    // The pack's binding slot IS the shader's `@binding`
                    // index: one number, declared once in the manifest and
                    // used unchanged here.
                    binds.push((slot as u32, res, offset, len));
                }
                out.push(ExecItem::Dispatch {
                    pipeline: pslot,
                    binds,
                    groups,
                });
            }
            gpu_wire::SubmitItem::Copy { src, dst, len } => {
                let s = dev.slot_of(src, gpu_wire::KIND_VIEW, OWNER)?;
                let d = dev.slot_of(dst, gpu_wire::KIND_VIEW, OWNER)?;
                let (src_slot, src_offset, _) = dev.view_range(s)?;
                let (dst_slot, dst_offset, _) = dev.view_range(d)?;
                out.push(ExecItem::Copy {
                    src: src_slot,
                    src_offset,
                    dst: dst_slot,
                    dst_offset,
                    len,
                });
            }
            // Raster items cannot be admitted: this provider does not
            // advertise `FEATURE_RASTER`, so the queue check refuses them.
            _ => return None,
        }
    }
    Some(out)
}
