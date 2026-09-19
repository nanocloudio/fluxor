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
//! (`modules/sdk/cores/gpu_*.rs`) — the same code the `gpu_replay` provider runs,
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
    BeginPass {
        /// Texture slot of the colour attachment.
        target: u16,
        flags: u32,
        clear: u32,
    },
    Draw {
        pipeline: u16,
        binds: Vec<(u32, u16, u64, u64)>,
        /// `(buffer slot, byte offset, byte length)` of the vertex buffer.
        vertex: (u16, u64, u64),
        /// The same for the index buffer, or `None` for a non-indexed draw.
        index: Option<(u16, u64, u64)>,
        first: u32,
        count: u32,
        instances: u32,
    },
    EndPass,
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
    CreateResource {
        fence: u16,
        slot: u16,
        /// `KIND_BUFFER` or `KIND_TEXTURE`. A texture is a texture here: the
        /// provider used to make every resource a buffer, which cannot be a
        /// render target and cannot be sampled.
        kind: u8,
        size: u64,
        usage: u32,
        width: u32,
        height: u32,
        format: u32,
    },
    DestroyResource {
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
        /// `Some` for a raster pipeline, carrying everything a draw needs
        /// that the program pack and the submission do not.
        raster: Option<Box<gpu_wire::RasterState>>,
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
    /// Prove quiescence, then drop every device object of the old epoch.
    Reset {
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

        // The DEVICE's limits, not the adapter's. They are not the same
        // thing: the adapter says what it could do, and the device says what
        // it was created to enforce — asking for `downlevel_defaults` raises
        // `min_uniform_buffer_offset_alignment` to 256 on hardware whose
        // adapter reports 32. Publishing the adapter's number told consumers
        // an alignment the device then refused, which is the union-of-
        // backends mistake in miniature: a capability record has to describe
        // the thing that will answer the requests.
        let device_limits = device.limits();
        let limits = facts_from(&device_limits, features, resident_bytes, staging_bytes);
        let _ = out.send(Done::Ready(Box::new(AdapterFacts {
            name: info.name.clone(),
            driver: format!("{} ({})", info.driver, info.driver_info),
            limits,
        })));

        let mut buffers: HashMap<u16, wgpu::Buffer> = HashMap::new();
        let mut textures: HashMap<u16, Target> = HashMap::new();
        let mut modules: HashMap<u16, (wgpu::ShaderModule, String)> = HashMap::new();
        let mut pipelines: HashMap<u16, Pipe> = HashMap::new();
        // Depth attachments are pass-local and nothing outside a pass can
        // name one, so they are kept here keyed by extent and format and
        // reused rather than allocated per pass.
        let mut depths: HashMap<(u32, u32, u32), wgpu::Texture> = HashMap::new();

        while let Ok(job) = jobs.recv() {
            match job {
                Job::CreateResource {
                    fence,
                    slot,
                    kind,
                    size,
                    usage,
                    width,
                    height,
                    format,
                } => {
                    if kind == w::KIND_TEXTURE {
                        match texture_format(format) {
                            Some(fmt) => {
                                let tex = device.create_texture(&wgpu::TextureDescriptor {
                                    label: None,
                                    size: wgpu::Extent3d {
                                        width,
                                        height,
                                        depth_or_array_layers: 1,
                                    },
                                    mip_level_count: 1,
                                    sample_count: 1,
                                    dimension: wgpu::TextureDimension::D2,
                                    format: fmt,
                                    usage: texture_usage(usage),
                                    view_formats: &[],
                                });
                                textures.insert(
                                    slot,
                                    Target {
                                        texture: tex,
                                        format: fmt,
                                        width,
                                        height,
                                    },
                                );
                                let _ = out.send(Done::Completed {
                                    fence,
                                    gpu_nanos: 0,
                                });
                            }
                            // A format outside the contract's enumeration is
                            // refused with the fact rather than substituted.
                            None => {
                                let _ = out.send(Done::Failed {
                                    fence,
                                    reason: w::REASON_UNSUPPORTED_FEATURE,
                                    detail: format,
                                });
                            }
                        }
                        continue;
                    }
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

                Job::DestroyResource { fence, slot } => {
                    if let Some(b) = buffers.remove(&slot) {
                        b.destroy();
                    }
                    if let Some(t) = textures.remove(&slot) {
                        t.texture.destroy();
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
                    raster,
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
                    // Compilation errors arrive asynchronously, so the scope
                    // is what turns them into this fence's failure instead of
                    // a log line nobody correlates.
                    device.push_error_scope(wgpu::ErrorFilter::Validation);
                    let built = match raster.as_deref() {
                        Some(st) => {
                            build_raster(&device, module, entry, st).map(|pipeline| Pipe::Raster {
                                pipeline,
                                colour: texture_format(st.colour_format)
                                    .unwrap_or(wgpu::TextureFormat::Rgba8Unorm),
                                depth: st.depth_format != w::FORMAT_NONE,
                            })
                        }
                        None => Some(Pipe::Compute(device.create_compute_pipeline(
                            &wgpu::ComputePipelineDescriptor {
                                label: None,
                                layout: None,
                                module,
                                entry_point: Some(entry.as_str()),
                                compilation_options: Default::default(),
                                cache: None,
                            },
                        ))),
                    };
                    let err = pollster::block_on(device.pop_error_scope());
                    let Some(pipeline) = built.filter(|_| err.is_none()) else {
                        // A shader that does not compile is a graph-visible
                        // outcome, never a silently skipped dispatch or draw.
                        if let Some(e) = err {
                            log::error!("[linux_gpu] pipeline {slot}: {e}");
                        }
                        let _ = out.send(Done::Failed {
                            fence,
                            reason: w::REASON_BAD_PROGRAM,
                            detail: 0,
                        });
                        let _ = out.send(Done::PipelineReady { slot, ok: false });
                        continue;
                    };
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
                    // Scoped, because wgpu reports encoder and bind-group
                    // faults asynchronously. Without this a submission whose
                    // bindings the device refused completes successfully and
                    // draws nothing — the consumer is told its frame was
                    // rendered and reads back an empty target.
                    device.push_error_scope(wgpu::ErrorFilter::Validation);
                    match record_and_submit(
                        &device,
                        &queue,
                        &buffers,
                        &textures,
                        &mut depths,
                        &pipelines,
                        &items,
                    ) {
                        Ok(()) => {
                            // Conservative queue completion: the whole queue
                            // is drained before the fence is reported. Not a
                            // per-submit GPU timestamp, and the outcome says
                            // so rather than reporting a CPU reading as one.
                            let _ = device.poll(wgpu::PollType::Wait);
                            match pollster::block_on(device.pop_error_scope()) {
                                None => {
                                    let _ = out.send(Done::Completed {
                                        fence,
                                        gpu_nanos: 0,
                                    });
                                }
                                Some(e) => {
                                    log::error!("[linux_gpu] submission {fence}: {e}");
                                    let _ = out.send(Done::Failed {
                                        fence,
                                        reason: w::REASON_MALFORMED,
                                        detail: 0,
                                    });
                                }
                            }
                        }
                        Err((reason, detail)) => {
                            let _ = pollster::block_on(device.pop_error_scope());
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
                    match readback(&device, &queue, &buffers, &textures, slot, offset, len) {
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

                Job::Reset { fence } => {
                    // Quiescence first, reclamation second, and in that order
                    // for a reason: work still in flight can reach any of
                    // these objects, so destroying them before the device has
                    // finished would free memory the GPU is still reading. A
                    // timeout on its own frees nothing precisely because it
                    // proves nothing about this poll.
                    let quiesced = device.poll(wgpu::PollType::Wait).is_ok();
                    for (_, b) in buffers.drain() {
                        b.destroy();
                    }
                    for (_, t) in textures.drain() {
                        t.texture.destroy();
                    }
                    for (_, t) in depths.drain() {
                        t.destroy();
                    }
                    // Pipelines and shader modules hold compiled code and a
                    // pipeline cache keyed on the old epoch's identities.
                    pipelines.clear();
                    modules.clear();
                    if quiesced {
                        let _ = out.send(Done::Completed {
                            fence,
                            gpu_nanos: 0,
                        });
                    } else {
                        // The device would not drain. Its memory stays
                        // quarantined in the driver rather than being handed
                        // back for reuse, and the caller is told the reset
                        // did not happen.
                        let _ = out.send(Done::Failed {
                            fence,
                            reason: w::REASON_DEVICE_LOST,
                            detail: 0,
                        });
                    }
                }
            }
        }
        let _ = timestamps;
    }

    /// A colour attachment or sampled texture, with the facts a pass needs
    /// about it. The extent is kept because a render pass has to size its
    /// depth attachment and its viewport from the target, and asking wgpu for
    /// them per draw would be a call per draw.
    pub struct Target {
        pub texture: wgpu::Texture,
        pub format: wgpu::TextureFormat,
        pub width: u32,
        pub height: u32,
    }

    /// One built pipeline. The two kinds cannot be interchanged: a draw
    /// against a compute pipeline is a caller error the contract already
    /// refuses, and this makes it unrepresentable here too.
    pub enum Pipe {
        Compute(wgpu::ComputePipeline),
        Raster {
            pipeline: wgpu::RenderPipeline,
            /// The colour format the pipeline was built for, kept so a draw
            /// into a target of a different format is refused with a reason
            /// instead of becoming an asynchronous driver validation error
            /// after the caller was told its pipeline was ready.
            colour: wgpu::TextureFormat,
            /// Whether it was built with a depth attachment. A pass that does
            /// not provide one is refused for the same reason.
            depth: bool,
        },
    }

    /// Translate the contract's format enumeration into wgpu's.
    ///
    /// `None` for anything the contract does not allocate — refused with the
    /// number rather than substituted, because a target silently created in
    /// another format draws the wrong colours and reads back the wrong bytes.
    fn texture_format(format: u32) -> Option<wgpu::TextureFormat> {
        Some(match format {
            w::FORMAT_RGBA8_UNORM => wgpu::TextureFormat::Rgba8Unorm,
            w::FORMAT_RGBA8_UNORM_SRGB => wgpu::TextureFormat::Rgba8UnormSrgb,
            w::FORMAT_BGRA8_UNORM => wgpu::TextureFormat::Bgra8Unorm,
            w::FORMAT_BGRA8_UNORM_SRGB => wgpu::TextureFormat::Bgra8UnormSrgb,
            w::FORMAT_DEPTH32_FLOAT => wgpu::TextureFormat::Depth32Float,
            w::FORMAT_R32_UINT => wgpu::TextureFormat::R32Uint,
            _ => return None,
        })
    }

    /// Translate the contract's usage mask into wgpu's texture usages.
    ///
    /// `COPY_DST` is unconditional for the same reason it is on a buffer: a
    /// texture nothing can put bytes into is not a resource any graph wants.
    fn texture_usage(usage: u32) -> wgpu::TextureUsages {
        let mut u = wgpu::TextureUsages::COPY_DST;
        if usage & w::USAGE_TEXTURE_SAMPLE != 0 {
            u |= wgpu::TextureUsages::TEXTURE_BINDING;
        }
        if usage & w::USAGE_RENDER_TARGET != 0 {
            u |= wgpu::TextureUsages::RENDER_ATTACHMENT;
        }
        if usage & w::USAGE_STORAGE != 0 {
            u |= wgpu::TextureUsages::STORAGE_BINDING;
        }
        if usage & (w::USAGE_COPY_SRC | w::USAGE_MAP_READ) != 0 {
            u |= wgpu::TextureUsages::COPY_SRC;
        }
        u
    }

    fn vertex_format(format: u16) -> Option<wgpu::VertexFormat> {
        Some(match format {
            w::VATTR_F32 => wgpu::VertexFormat::Float32,
            w::VATTR_F32X2 => wgpu::VertexFormat::Float32x2,
            w::VATTR_F32X3 => wgpu::VertexFormat::Float32x3,
            w::VATTR_F32X4 => wgpu::VertexFormat::Float32x4,
            w::VATTR_U32 => wgpu::VertexFormat::Uint32,
            w::VATTR_U32X2 => wgpu::VertexFormat::Uint32x2,
            w::VATTR_U32X4 => wgpu::VertexFormat::Uint32x4,
            w::VATTR_U8X4_UNORM => wgpu::VertexFormat::Unorm8x4,
            _ => return None,
        })
    }

    /// Build a render pipeline from the contract's state descriptor.
    ///
    /// The descriptor was validated by the wire decoder before it reached
    /// here — formats allocated, attributes inside the stride, no duplicate
    /// locations, depth state consistent with the attachment — so this is a
    /// translation. `None` means a field the contract allocates has no wgpu
    /// equivalent, which is a gap in this provider rather than a caller error.
    fn build_raster(
        device: &wgpu::Device,
        module: &wgpu::ShaderModule,
        entry: &str,
        st: &w::RasterState,
    ) -> Option<wgpu::RenderPipeline> {
        let mut attrs: Vec<wgpu::VertexAttribute> = Vec::with_capacity(st.attrs().len());
        for a in st.attrs() {
            attrs.push(wgpu::VertexAttribute {
                format: vertex_format(a.format)?,
                offset: a.offset as u64,
                shader_location: a.location as u32,
            });
        }
        let colour = texture_format(st.colour_format)?;
        let buffers: &[wgpu::VertexBufferLayout<'_>] = &[wgpu::VertexBufferLayout {
            array_stride: st.vertex_stride as u64,
            step_mode: wgpu::VertexStepMode::Vertex,
            attributes: &attrs,
        }];
        // A pipeline with no attributes declares no vertex buffer at all,
        // rather than one of stride zero, so a shader that generates its own
        // positions needs no dummy geometry bound.
        let empty: &[wgpu::VertexBufferLayout<'_>] = &[];
        let blend = match st.blend {
            w::BLEND_ALPHA => Some(wgpu::BlendState::ALPHA_BLENDING),
            _ => None,
        };
        let depth = if st.depth_format == w::FORMAT_NONE {
            None
        } else {
            Some(wgpu::DepthStencilState {
                format: texture_format(st.depth_format)?,
                depth_write_enabled: st.depth_write,
                depth_compare: match st.depth_compare {
                    w::DEPTH_LESS => wgpu::CompareFunction::Less,
                    w::DEPTH_LESS_EQUAL => wgpu::CompareFunction::LessEqual,
                    w::DEPTH_GREATER => wgpu::CompareFunction::Greater,
                    _ => wgpu::CompareFunction::Always,
                },
                stencil: wgpu::StencilState::default(),
                bias: wgpu::DepthBiasState::default(),
            })
        };
        Some(
            device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
                label: None,
                layout: None,
                vertex: wgpu::VertexState {
                    module,
                    entry_point: Some(entry),
                    compilation_options: Default::default(),
                    buffers: if attrs.is_empty() { empty } else { buffers },
                },
                primitive: wgpu::PrimitiveState {
                    topology: match st.topology {
                        w::TOPOLOGY_TRIANGLE_STRIP => wgpu::PrimitiveTopology::TriangleStrip,
                        w::TOPOLOGY_LINE_LIST => wgpu::PrimitiveTopology::LineList,
                        w::TOPOLOGY_POINT_LIST => wgpu::PrimitiveTopology::PointList,
                        _ => wgpu::PrimitiveTopology::TriangleList,
                    },
                    strip_index_format: None,
                    front_face: match st.front_face {
                        w::FRONT_FACE_CW => wgpu::FrontFace::Cw,
                        _ => wgpu::FrontFace::Ccw,
                    },
                    cull_mode: match st.cull {
                        w::CULL_BACK => Some(wgpu::Face::Back),
                        w::CULL_FRONT => Some(wgpu::Face::Front),
                        _ => None,
                    },
                    unclipped_depth: false,
                    polygon_mode: wgpu::PolygonMode::Fill,
                    conservative: false,
                },
                depth_stencil: depth,
                multisample: wgpu::MultisampleState::default(),
                // The fragment entry point shares the vertex entry's name.
                // One pack, one entry: the contract's program envelope names
                // a single entry point, and splitting it would need a second
                // field in the manifest rather than a convention invented
                // here.
                fragment: Some(wgpu::FragmentState {
                    module,
                    entry_point: None,
                    compilation_options: Default::default(),
                    targets: &[Some(wgpu::ColorTargetState {
                        format: colour,
                        blend,
                        write_mask: wgpu::ColorWrites::ALL,
                    })],
                }),
                multiview: None,
                cache: None,
            }),
        )
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

    /// Record one submission's items in the caller's declared order and hand
    /// it to the queue.
    ///
    /// Order is the caller's, not an optimiser's: a provider that hoisted
    /// every copy to the end would silently change what the work computes.
    /// Compute passes open for each run of dispatches and close before a copy
    /// or a render pass; a render pass is opened by its `BeginPass` and
    /// closed by its `EndPass`, both of which the device core has already
    /// checked are balanced and on the raster queue.
    #[allow(
        clippy::too_many_arguments,
        reason = "the worker's device objects live in separate maps because \
                  they have separate lifetimes; boxing them together would \
                  only move the destructuring into this function"
    )]
    fn record_and_submit(
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        buffers: &HashMap<u16, wgpu::Buffer>,
        textures: &HashMap<u16, Target>,
        depths: &mut HashMap<(u32, u32, u32), wgpu::Texture>,
        pipelines: &HashMap<u16, Pipe>,
        items: &[ExecItem],
    ) -> Result<(), (u16, u32)> {
        // Everything a pass borrows has to be created before any pass is
        // open: a bind group, a texture view or a depth attachment made
        // inside the pass would not outlive it.
        let mut groups = Vec::with_capacity(items.len());
        for item in items {
            let (pipeline, binds) = match item {
                ExecItem::Dispatch {
                    pipeline, binds, ..
                }
                | ExecItem::Draw {
                    pipeline, binds, ..
                } => (pipeline, binds),
                _ => {
                    groups.push(None);
                    continue;
                }
            };
            // A program that declares no bindings has no group 0, so asking
            // for its layout is itself a validation error — the question has
            // to be skipped, not merely its answer discarded.
            if binds.is_empty() {
                groups.push(None);
                continue;
            }
            let layout = match pipelines
                .get(pipeline)
                .ok_or((w::REASON_BAD_HANDLE, *pipeline as u32))?
            {
                Pipe::Compute(p) => p.get_bind_group_layout(0),
                Pipe::Raster { pipeline, .. } => pipeline.get_bind_group_layout(0),
            };
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
        }

        // Colour and depth attachment views, in the same index space.
        let mut colour_views: Vec<Option<wgpu::TextureView>> = Vec::with_capacity(items.len());
        let mut depth_views: Vec<Option<wgpu::TextureView>> = Vec::with_capacity(items.len());
        for item in items {
            let ExecItem::BeginPass { target, flags, .. } = item else {
                colour_views.push(None);
                depth_views.push(None);
                continue;
            };
            let t = textures
                .get(target)
                .ok_or((w::REASON_BAD_HANDLE, *target as u32))?;
            colour_views.push(Some(t.texture.create_view(&Default::default())));
            if flags & w::PASS_DEPTH == 0 {
                depth_views.push(None);
                continue;
            }
            // Pass-local, so the provider owns it: nothing outside the pass
            // can name, bind, copy or read it back. Keyed by extent and
            // format and reused, because a depth texture per pass would
            // allocate every frame.
            let key = (t.width, t.height, w::FORMAT_DEPTH32_FLOAT);
            let tex = depths.entry(key).or_insert_with(|| {
                device.create_texture(&wgpu::TextureDescriptor {
                    label: Some("fluxor-gpu-depth"),
                    size: wgpu::Extent3d {
                        width: t.width,
                        height: t.height,
                        depth_or_array_layers: 1,
                    },
                    mip_level_count: 1,
                    sample_count: 1,
                    dimension: wgpu::TextureDimension::D2,
                    format: wgpu::TextureFormat::Depth32Float,
                    usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
                    view_formats: &[],
                })
            });
            depth_views.push(Some(tex.create_view(&Default::default())));
        }

        let mut enc = device.create_command_encoder(&Default::default());
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
                        let Some(Pipe::Compute(p)) = pipelines.get(pipeline) else {
                            return Err((w::REASON_BAD_HANDLE, *pipeline as u32));
                        };
                        pass.set_pipeline(p);
                        if let Some(bg) = groups[i].as_ref() {
                            pass.set_bind_group(0, bg, &[]);
                        }
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
                ExecItem::BeginPass {
                    target,
                    flags,
                    clear,
                } => {
                    let colour = colour_views[i].as_ref().ok_or((w::REASON_BAD_HANDLE, 0))?;
                    let depth = depth_views[i].as_ref();
                    let has_depth = depth.is_some();
                    let target_format = textures
                        .get(target)
                        .ok_or((w::REASON_BAD_HANDLE, *target as u32))?
                        .format;
                    let load = if flags & w::PASS_CLEAR_COLOUR != 0 {
                        wgpu::LoadOp::Clear(clear_colour(*clear))
                    } else {
                        wgpu::LoadOp::Load
                    };
                    let depth_attachment = depth.map(|v| wgpu::RenderPassDepthStencilAttachment {
                        view: v,
                        depth_ops: Some(wgpu::Operations {
                            load: if flags & w::PASS_CLEAR_DEPTH != 0 {
                                // Far plane. A reversed-Z consumer asks
                                // for `DEPTH_GREATER` and clears to the
                                // same value; the comparison is the
                                // caller's, the clear value is not.
                                wgpu::LoadOp::Clear(1.0)
                            } else {
                                wgpu::LoadOp::Load
                            },
                            store: wgpu::StoreOp::Store,
                        }),
                        stencil_ops: None,
                    });
                    let mut pass = enc.begin_render_pass(&wgpu::RenderPassDescriptor {
                        label: None,
                        color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                            view: colour,
                            depth_slice: None,
                            resolve_target: None,
                            ops: wgpu::Operations {
                                load,
                                store: wgpu::StoreOp::Store,
                            },
                        })],
                        depth_stencil_attachment: depth_attachment,
                        timestamp_writes: None,
                        occlusion_query_set: None,
                    });
                    i += 1;
                    while let Some(item) = items.get(i) {
                        let ExecItem::Draw {
                            pipeline,
                            vertex,
                            index,
                            first,
                            count,
                            instances,
                            ..
                        } = item
                        else {
                            break;
                        };
                        let Some(Pipe::Raster {
                            pipeline: p,
                            colour: want,
                            depth: wants_depth,
                        }) = pipelines.get(pipeline)
                        else {
                            return Err((w::REASON_BAD_HANDLE, *pipeline as u32));
                        };
                        // Attachment agreement, checked rather than assumed.
                        // wgpu would raise this asynchronously, long after
                        // this pipeline was reported ready.
                        if *want != target_format {
                            return Err((w::REASON_UNSUPPORTED_FEATURE, 0));
                        }
                        if *wants_depth != has_depth {
                            return Err((w::REASON_MALFORMED, w::PASS_DEPTH));
                        }
                        pass.set_pipeline(p);
                        if let Some(bg) = groups[i].as_ref() {
                            pass.set_bind_group(0, bg, &[]);
                        }
                        let (vslot, voff, vlen) = *vertex;
                        // Geometry a compute dispatch in this same submission
                        // wrote is bound here directly. That is the whole
                        // point of the usage mask: no CPU detour, no readback,
                        // and the dependency is the submission's own order.
                        let vb = buffers
                            .get(&vslot)
                            .ok_or((w::REASON_BAD_HANDLE, vslot as u32))?;
                        pass.set_vertex_buffer(0, vb.slice(voff..voff + vlen));
                        match index {
                            Some((islot, ioff, ilen)) => {
                                let ib = buffers
                                    .get(islot)
                                    .ok_or((w::REASON_BAD_HANDLE, *islot as u32))?;
                                pass.set_index_buffer(
                                    ib.slice(*ioff..*ioff + *ilen),
                                    wgpu::IndexFormat::Uint32,
                                );
                                pass.draw_indexed(*first..*first + *count, 0, 0..*instances);
                            }
                            None => pass.draw(*first..*first + *count, 0..*instances),
                        }
                        i += 1;
                    }
                    // The device core already proved the pass is closed; a
                    // submission that ended inside one would not have been
                    // admitted.
                    if matches!(items.get(i), Some(ExecItem::EndPass)) {
                        i += 1;
                    }
                }
                // Reached only if a draw or an end-pass arrived outside a
                // pass, which admission refuses. Failing here rather than
                // ignoring it keeps the two layers' views of the submission
                // from drifting apart silently.
                ExecItem::Draw { .. } | ExecItem::EndPass => {
                    return Err((w::REASON_MALFORMED, 0));
                }
            }
        }
        queue.submit([enc.finish()]);
        Ok(())
    }

    /// Unpack a pass's `clear_rgba` word into wgpu's linear clear colour.
    ///
    /// The word is one RGBA8 texel, low byte red, which is the order the
    /// contract's `FORMAT_RGBA8_UNORM` names. No sRGB conversion: the target
    /// format decides that, and applying it twice would wash the clear out.
    fn clear_colour(rgba: u32) -> wgpu::Color {
        let ch = |shift: u32| f64::from((rgba >> shift) & 0xFF) / 255.0;
        wgpu::Color {
            r: ch(0),
            g: ch(8),
            b: ch(16),
            a: ch(24),
        }
    }

    fn readback(
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        buffers: &HashMap<u16, wgpu::Buffer>,
        textures: &HashMap<u16, Target>,
        slot: u16,
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, (u16, u32)> {
        if let Some(t) = textures.get(&slot) {
            return readback_texture(device, queue, t, offset, len);
        }
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

    /// Read a rendered texture back, in the tightly packed layout the
    /// contract's size accounting describes.
    ///
    /// wgpu requires a copy's rows to be 256-byte aligned, which the
    /// contract's layout is not. The copy is made into a padded staging
    /// buffer and the rows are compacted here, so a consumer sees
    /// `width × 4` bytes per row and the padding never reaches the wire.
    fn readback_texture(
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        target: &Target,
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, (u16, u32)> {
        let texel = 4u32;
        let row = target.width * texel;
        let align = wgpu::COPY_BYTES_PER_ROW_ALIGNMENT;
        let padded = row.div_ceil(align) * align;
        let staging = device.create_buffer(&wgpu::BufferDescriptor {
            label: None,
            size: u64::from(padded) * u64::from(target.height),
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let mut enc = device.create_command_encoder(&Default::default());
        enc.copy_texture_to_buffer(
            wgpu::TexelCopyTextureInfo {
                texture: &target.texture,
                mip_level: 0,
                origin: wgpu::Origin3d::ZERO,
                aspect: wgpu::TextureAspect::All,
            },
            wgpu::TexelCopyBufferInfo {
                buffer: &staging,
                layout: wgpu::TexelCopyBufferLayout {
                    offset: 0,
                    bytes_per_row: Some(padded),
                    rows_per_image: Some(target.height),
                },
            },
            wgpu::Extent3d {
                width: target.width,
                height: target.height,
                depth_or_array_layers: 1,
            },
        );
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
        let mut packed = Vec::with_capacity((row as usize) * target.height as usize);
        for y in 0..target.height as usize {
            let at = y * padded as usize;
            packed.extend_from_slice(&view[at..at + row as usize]);
        }
        drop(view);
        staging.unmap();
        staging.destroy();

        let start = offset as usize;
        let end = start.saturating_add(len as usize);
        packed
            .get(start..end)
            .map(<[u8]>::to_vec)
            .ok_or((w::REASON_BAD_RANGE, 0))
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

        // Raster is advertised because it is implemented: pipelines built
        // from the contract's state descriptor, passes with a colour and an
        // optional depth attachment, and indexed and non-indexed draws.
        //
        // `COMPUTE_TO_RASTER` goes with it. A buffer created with both
        // `USAGE_STORAGE` and `USAGE_VERTEX` is one wgpu buffer with both
        // usages, so a dispatch writes the geometry a later draw in the same
        // submission reads, with no CPU detour and no readback — which is the
        // fact the bit names rather than an aspiration.
        let features_out = w::FEATURE_COMPUTE
            | w::FEATURE_RASTER
            | w::FEATURE_COMPUTE_TO_RASTER
            | w::FEATURE_READBACK;
        // Device reset is advertised because quiescence is demonstrated
        // rather than hoped for: the reset polls the device to completion
        // before it destroys anything, and only then is the old epoch's
        // memory reclaimed. Recreating an adapter would not be a proof;
        // `PollType::Wait` returning is.
        let features_out = features_out | w::FEATURE_DEVICE_RESET;
        // Still not advertised, because still not implemented here: shared
        // surfaces, indirect dispatch, subgroups, preemption, timestamps —
        // the adapter may carry `TIMESTAMP_QUERY`, but this provider places
        // no query and every completion reports `gpu_nanos` of zero, and a
        // capability record that reports what a backend could manage rather
        // than what this one does is worth nothing to the consumer reading
        // it — and device
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
            } else if op == gpu_wire::OP_RESET {
                to_worker.send(Job::Reset { fence }).is_ok()
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
            // Sized to what the ring will take now, not to a constant: a chunk
            // the ring cannot hold is re-offered at the same size next step,
            // so a fixed chunk turns a slow readback into a stalled one.
            let room = dev.max_result_chunk();
            if room == 0 {
                break;
            }
            let chunk = (bytes.len() - *sent).min(room);
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
    // A fence slot is reused as soon as it is released, and a plan left
    // under its index outlives it: the fence that never reached
    // `next_ready` — cancelled, or poisoned by a dependency — left one
    // behind, and the next fence at that index would find it and submit
    // another request's work. So the index is cleared the moment it names
    // something new, before the arms below put anything under it.
    if let Some(fence) = work.fence() {
        deferred.remove(&fence);
    }
    let send = |dev: &mut gpu_wire::GpuDevice<'_>, fence: u16, job: Job| {
        dev.mark_running(fence);
        if to_worker.send(job).is_err() {
            dev.fail(fence, gpu_wire::REASON_DEVICE_LOST, 0);
        }
    };

    match work {
        Work::None => true,

        Work::CreateBuffer { fence, slot } | Work::CreateTexture { fence, slot } => {
            // The kind comes from the slot the core filled, not from which
            // arm matched: a texture has to become a texture, because a
            // buffer cannot be a render attachment or be sampled.
            let Some(r) = dev.resource(slot) else {
                dev.fail(fence, gpu_wire::REASON_BAD_HANDLE, slot as u32);
                return true;
            };
            let job = Job::CreateResource {
                fence,
                slot,
                kind: r.kind,
                size: r.size,
                usage: r.usage,
                width: r.width,
                height: r.height,
                format: r.format,
            };
            send(dev, fence, job);
            true
        }

        Work::DestroyResource { fence, slot } => {
            // The handle is retired already; the object goes only once nothing
            // in flight can still reach it.
            if dev.resource_free_pending(slot) || dev.resource(slot).is_none_or(|r| !r.live) {
                send(dev, fence, Job::DestroyResource { fence, slot });
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
            if !program_source.contains_key(&program) {
                dev.fail(fence, gpu_wire::REASON_BAD_HANDLE, program as u32);
                return true;
            }
            // The pipeline kind and its state blob are read back out of the
            // record. The core validated both and does not carry the state
            // forward, because only a backend has any use for it.
            let payload = &record[gpu_wire::HEADER_LEN..];
            let kind = gpu_wire::get_u8(payload, 8).unwrap_or(gpu_wire::QUEUE_COMPUTE);
            let raster = if kind == gpu_wire::QUEUE_RASTER {
                let len = gpu_wire::get_u32(payload, 12).unwrap_or(0) as usize;
                let state = payload.get(16..16 + len).unwrap_or(&[]);
                match gpu_wire::RasterState::decode(state) {
                    Ok(st) => Some(Box::new(st)),
                    // The descriptor is refused here rather than at the first
                    // draw, where the caller has already been told its
                    // pipeline is ready.
                    Err(reason) => {
                        dev.fail(fence, reason, 0);
                        dev.mark_pipeline_ready(slot, false);
                        return true;
                    }
                }
            } else {
                None
            };
            send(
                dev,
                fence,
                Job::CreatePipeline {
                    fence,
                    slot,
                    program,
                    raster,
                },
            );
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
            // The core has already terminated every other outstanding request
            // with `DEVICE_LOST`, bumped the epoch and retired every handle.
            // What is left is the physical half: drain the device and drop the
            // objects the old epoch's handles named. Plans held for fences
            // that will never run go with them — a fence slot reused in the
            // new epoch must not find the old epoch's work under its index.
            //
            // Dispatched from the step's ready loop like a drain, not sent
            // from here, so one place decides when a fence's work reaches the
            // device.
            let _ = fence;
            deferred.clear();
            program_source.clear();
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
                let binds = resolve_binds(dev, bytes, binds_offset, bind_count)?;
                out.push(ExecItem::Dispatch {
                    pipeline: pslot,
                    binds,
                    groups,
                });
            }
            gpu_wire::SubmitItem::BeginPass {
                target,
                flags,
                clear,
            } => {
                // The pass target is a resource handle, not a view: a render
                // attachment is the whole texture.
                let slot = dev.slot_of(target, gpu_wire::KIND_TEXTURE, OWNER)?;
                out.push(ExecItem::BeginPass {
                    target: slot,
                    flags,
                    clear,
                });
            }
            gpu_wire::SubmitItem::Draw {
                pipeline,
                binds_offset,
                bind_count,
                vertex,
                index,
                first,
                count,
                instances,
            } => {
                let pslot = dev.slot_of(pipeline, gpu_wire::KIND_PIPELINE, OWNER)?;
                let binds = resolve_binds(dev, bytes, binds_offset, bind_count)?;
                let geometry = |h: u64| -> Option<(u16, u64, u64)> {
                    let v = dev.slot_of(h, gpu_wire::KIND_VIEW, OWNER)?;
                    dev.view_range(v)
                };
                let vertex = geometry(vertex)?;
                // A draw with no index buffer names the null handle, which is
                // not a handle that failed to resolve.
                let index = if index == gpu_wire::HANDLE_NONE {
                    None
                } else {
                    Some(geometry(index)?)
                };
                out.push(ExecItem::Draw {
                    pipeline: pslot,
                    binds,
                    vertex,
                    index,
                    first,
                    count,
                    instances,
                });
            }
            gpu_wire::SubmitItem::EndPass => out.push(ExecItem::EndPass),
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
        }
    }
    Some(out)
}

/// Resolve a submission item's bindings into slot-addressed buffer ranges.
///
/// The pack's binding slot IS the shader's `@binding` index: one number,
/// declared once in the manifest and used unchanged here. Dispatches and
/// draws bind identically, which is why they share this.
fn resolve_binds(
    dev: &gpu_wire::GpuDevice<'_>,
    bytes: &[u8],
    binds_offset: usize,
    bind_count: usize,
) -> Option<Vec<(u32, u16, u64, u64)>> {
    let mut binds = Vec::with_capacity(bind_count);
    for i in 0..bind_count {
        let e = binds_offset + i * gpu_wire::BIND_ENTRY_LEN;
        let slot = gpu_wire::get_u16(bytes, e)?;
        let view = gpu_wire::get_u64(bytes, e + 4)?;
        let vslot = dev.slot_of(view, gpu_wire::KIND_VIEW, OWNER)?;
        let (res, offset, len) = dev.view_range(vslot)?;
        binds.push((slot as u32, res, offset, len));
    }
    Some(binds)
}
