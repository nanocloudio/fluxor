//! `wasm_browser_gpu` built-in: generic GPU raster driver (browser/WebGPU backend)
//!
//! Backend-agnostic 3D raster capability surface. The module holds ZERO
//! application knowledge: no shaders, no vertex formats, no uniform layouts.
//! Applications supply all of those as data via `CMD_SET_PIPELINE`; this
//! driver only frames the command stream and forwards it to the host backend
//! (`host_gpu_raster_*` in host_shims.js today; a Vulkan or bare-metal driver
//! implements the same imports unchanged — WGSL compiles to SPIR-V via naga).
//!
//! ## Command stream (channel input, little-endian)
//!
//! Pipelines and vertex buffers are SLOTTED (ids 0..=7): an app creates any
//! number of pipelines (e.g. 0 = world, 1 = highlight overlay) and uploads
//! into independent vertex-buffer slots; DRAW names the (pipeline, buffer)
//! pair. Uniform buffers are per-pipeline.
//!
//! - SET_PIPELINE [0x03] [pipeline_id:u32] [desc_len:u32] [descriptor…]
//!   Creates/replaces render pipeline `pipeline_id` from an app-supplied
//!   descriptor:
//!     vertex_stride: u32
//!     attr_count:    u32                 (≤ 16)
//!     attrs:         attr_count × { format:u32, offset:u32, location:u32 }
//!     uniform_size:  u32                 (bytes; bound at @group(0) @binding(0))
//!     flags:         u32                 (bit0 = depth test, bit1 = cull back,
//!                                         bit2 = line-list topology,
//!                                         bit3 = suppress depth WRITE — for
//!                                         overlays that test against the scene
//!                                         but must not occlude it)
//!     shader_format: u32                 (0 = WGSL utf8, 1 = SPIR-V,
//!                                         2+ = reserved for native blobs;
//!                                         a driver REJECTS formats it cannot
//!                                         consume — apps ship the variant their
//!                                         hardware target needs, translated at
//!                                         build time from the canonical WGSL)
//!     shader_len:    u32
//!     shader:        one module, entry points `vs_main` / `fs_main`
//!   Attribute format codes: 0=float32 1=float32x2 2=float32x3 3=float32x4
//!                           4=uint32  5=unorm8x4
//!   Applied outside frame gating (device state, not frame content).
//!
//! - FRAME_BEGIN [0x01] [frame_tick:u32, clear_r:f32, clear_g:f32, clear_b:f32]
//!   (`frame_tick` gates frames generated before the GPU was ready; a producer
//!   may pass u32::MAX to always pass the gate.)
//! - SET_UNIFORMS [0x02] [pipeline_id:u32] [byte_len:u32] [bytes…] — written
//!   verbatim into that pipeline's uniform buffer; layout is a contract
//!   between the app's shader and the app's producer module, opaque here.
//! - UPLOAD_VERTICES [0x10] [slot:u32] [byte_len:u32] [vertex_data…]
//!   (small, single-shot; replaces the slot's buffer)
//! - UPLOAD_INDICES  [0x11] [slot:u32] [byte_len:u32] [index_data…] (u32)
//! - UPLOAD_VERTICES_BEGIN [0x12] [slot:u32] [total_len:u32]
//!   Starts a streamed vertex upload into `slot`: the backend allocates a
//!   staging buffer of `total_len` bytes. Draws keep using the slot's
//!   previous geometry until the stream completes.
//! - UPLOAD_VERTICES_CHUNK [0x13] [slot:u32] [byte_len:u32] [data…]
//!   Appends to the slot's staging buffer. When the accumulated bytes reach
//!   `total_len`, the staging buffer atomically becomes the slot's active
//!   buffer. `byte_len` must be a multiple of 4 (backend writeBuffer rule).
//!   Like SET_PIPELINE, upload commands are device state: they are processed
//!   even while a stale frame is being discarded.
//! - UPLOAD_INDICES_BEGIN [0x14] [slot:u32] [total_len:u32]
//! - UPLOAD_INDICES_CHUNK [0x15] [slot:u32] [byte_len:u32] [data…]
//!   Streamed u32 index upload, same staging semantics as the vertex pair.
//!   An app replacing a slot's mesh should complete the vertex stream first,
//!   then the index stream: draws are indexed once indices exist, and an
//!   out-of-bounds index fetch is safe (zeroed) but visible for a frame.
//! - DRAW [0x20] [pipeline_id:u32] [slot:u32]
//!   Draws the slot's whole buffer with the pipeline (vertex count =
//!   slot bytes / pipeline stride; indexed if the slot has indices).
//! - FRAME_END [0xFF]

use crate::kernel::{channel, scheduler, syscalls};

// Command opcodes
const CMD_FRAME_BEGIN: u8 = 0x01;
const CMD_SET_UNIFORMS: u8 = 0x02;
const CMD_SET_PIPELINE: u8 = 0x03;
const CMD_UPLOAD_VERTICES: u8 = 0x10;
const CMD_UPLOAD_INDICES: u8 = 0x11;
const CMD_UPLOAD_VERTICES_BEGIN: u8 = 0x12;
const CMD_UPLOAD_VERTICES_CHUNK: u8 = 0x13;
const CMD_UPLOAD_INDICES_BEGIN: u8 = 0x14;
const CMD_UPLOAD_INDICES_CHUNK: u8 = 0x15;
const CMD_DRAW: u8 = 0x20;
const CMD_FRAME_END: u8 = 0xFF;

// Init status constants (match host_shims.js)
const GPU_INIT_READY: i32 = 0;
const GPU_INIT_PENDING: i32 = 1;
const GPU_INIT_NOT_STARTED: i32 = 2;

// Not every host_gpu_raster_* import is called yet (resize / get_size are part of the
// host ABI surface the JS driver implements but the module does not drive today).
#[allow(dead_code)]
extern "C" {
    /// Initialize the GPU backend. Returns 0=ready, 1=pending, <0=error
    fn host_gpu_raster_init() -> i32;

    /// Poll init status
    fn host_gpu_raster_poll_init() -> i32;

    /// Resize the output surface
    fn host_gpu_raster_resize(width: u32, height: u32) -> i32;

    /// Create/replace render pipeline `id` from an app-supplied descriptor
    /// (see module docs for the wire layout). Returns 0 or <0 on error.
    fn host_gpu_raster_pipeline(id: u32, desc_ptr: *const u8, desc_len: u32) -> i32;

    /// Replace vertex-buffer `slot`. Returns 0 or <0 on error
    fn host_gpu_raster_upload_vertices(slot: u32, ptr: *const u8, byte_len: u32) -> i32;

    /// Begin a streamed vertex upload of `total_len` bytes into `slot`
    fn host_gpu_raster_vertices_begin(slot: u32, total_len: u32) -> i32;

    /// Append a chunk to the slot's streamed upload; swaps in when complete
    fn host_gpu_raster_vertices_chunk(slot: u32, ptr: *const u8, byte_len: u32) -> i32;

    /// Upload indices (u32) for `slot`. Returns index count or <0 on error
    fn host_gpu_raster_upload_indices(slot: u32, ptr: *const u8, byte_len: u32) -> i32;

    /// Begin a streamed index upload of `total_len` bytes into `slot`
    fn host_gpu_raster_indices_begin(slot: u32, total_len: u32) -> i32;

    /// Append a chunk to the slot's streamed index upload
    fn host_gpu_raster_indices_chunk(slot: u32, ptr: *const u8, byte_len: u32) -> i32;

    /// Write `byte_len` bytes verbatim into pipeline `id`'s uniform buffer
    fn host_gpu_raster_set_uniforms(id: u32, ptr: *const u8, byte_len: u32) -> i32;

    /// Begin frame with clear color
    fn host_gpu_raster_begin_frame(r: f32, g: f32, b: f32) -> i32;

    /// Draw vertex-buffer `slot` with pipeline `id`
    fn host_gpu_raster_draw(id: u32, slot: u32) -> i32;

    /// End frame and present
    fn host_gpu_raster_end_frame() -> i32;

    /// Get surface size
    fn host_gpu_raster_get_size(out_ptr: *mut u32) -> i32;
}

#[repr(C)]
pub(crate) struct GpuState {
    pub in_chan: i32,
    pub width: u16,
    pub height: u16,
    pub init_status: i32,
    pub in_frame: bool,
    pub frames: u32,
    pub ready_tick: u32, // Tick when GPU became ready - discard older frames
    // True while discarding a stale frame: commands are still parsed by their
    // encoded length (so the stream stays framed), but their host effects are
    // suppressed until the matching CMD_FRAME_END. Avoids byte-scanning for
    // CMD_FRAME_END, which could match vertex/uniform/float payload bytes and
    // resume parsing mid-command.
    pub skip_frame: bool,
    // Command buffer for parsing
    pub cmd_buf: *mut u8,
    pub cmd_len: u32,
    pub cmd_cap: u32,
    pub cmd_offset: u32,
}

const CMD_BUF_SIZE: u32 = 64 * 1024; // 64KB command buffer

pub(crate) fn heap_size_for(_width: u16, _height: u16) -> usize {
    core::mem::size_of::<GpuState>() + CMD_BUF_SIZE as usize + 256
}

unsafe fn alloc_state(in_chan: i32, width: u16, height: u16) -> *mut GpuState {
    let table = syscalls::get_syscall_table();
    let state_size = core::mem::size_of::<GpuState>() as u32;
    let raw = (table.heap_alloc)(state_size) as *mut GpuState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }

    let cmd_buf = (table.heap_alloc)(CMD_BUF_SIZE);
    if cmd_buf.is_null() {
        return core::ptr::null_mut();
    }

    core::ptr::write(
        raw,
        GpuState {
            in_chan,
            width,
            height,
            init_status: GPU_INIT_NOT_STARTED,
            in_frame: false,
            frames: 0,
            ready_tick: 0,
            skip_frame: false,
            cmd_buf,
            cmd_len: 0,
            cmd_cap: CMD_BUF_SIZE,
            cmd_offset: 0,
        },
    );
    raw
}

fn read_u32(buf: *const u8, offset: usize) -> u32 {
    unsafe {
        let ptr = buf.add(offset) as *const u32;
        core::ptr::read_unaligned(ptr)
    }
}

fn read_f32(buf: *const u8, offset: usize) -> f32 {
    unsafe {
        let ptr = buf.add(offset) as *const f32;
        core::ptr::read_unaligned(ptr)
    }
}

extern "C" {
    fn host_log(level: u32, ptr: *const u8, len: usize);
}

fn log_msg(msg: &[u8]) {
    unsafe {
        host_log(2, msg.as_ptr(), msg.len());
    }
}

fn gpu_step(state: *mut u8) -> i32 {
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut GpuState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;

        // Initialize the backend if not started
        if st.init_status == GPU_INIT_NOT_STARTED {
            st.init_status = host_gpu_raster_init();
        }

        // Poll init if pending
        if st.init_status == GPU_INIT_PENDING {
            st.init_status = host_gpu_raster_poll_init();
        }

        // Don't process commands until initialized
        if st.init_status != GPU_INIT_READY {
            return 0;
        }

        // Record ready_tick on first ready (used to discard stale frames)
        if st.ready_tick == 0 {
            st.ready_tick = scheduler::tick_count();
            log_msg(b"[gpu] backend ready");
        }

        // Read commands from channel
        loop {
            let available = st.cmd_cap - st.cmd_len;
            if available == 0 {
                break;
            }
            let n = channel::channel_read(
                st.in_chan,
                st.cmd_buf.add(st.cmd_len as usize),
                available as usize,
            );
            if n <= 0 {
                break;
            }
            st.cmd_len += n as u32;
        }

        // Process commands. Payload-carrying commands rewind to the opcode and
        // break when the payload has not fully arrived yet; the tail is
        // compacted below and completed on a later tick.
        while st.cmd_offset < st.cmd_len {
            let cmd = *st.cmd_buf.add(st.cmd_offset as usize);
            st.cmd_offset += 1;

            match cmd {
                CMD_SET_PIPELINE => {
                    if st.cmd_offset + 8 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let id = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    let desc_len = read_u32(st.cmd_buf, st.cmd_offset as usize + 4);
                    if st.cmd_offset + 8 + desc_len > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    st.cmd_offset += 8;
                    let ptr = st.cmd_buf.add(st.cmd_offset as usize);
                    // Device state, not frame content: applied even while a
                    // stale frame is being discarded.
                    let rc = host_gpu_raster_pipeline(id, ptr, desc_len);
                    if rc < 0 {
                        log_msg(b"[gpu] pipeline create failed");
                    } else {
                        log_msg(b"[gpu] pipeline created");
                    }
                    st.cmd_offset += desc_len;
                }

                CMD_FRAME_BEGIN => {
                    // 16 bytes: frame_tick (u32) + clear color (3 floats)
                    if st.cmd_offset + 16 > st.cmd_len {
                        st.cmd_offset -= 1; // Rewind
                        break;
                    }
                    let frame_tick = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    st.cmd_offset += 4;
                    let r = read_f32(st.cmd_buf, st.cmd_offset as usize);
                    let g = read_f32(st.cmd_buf, st.cmd_offset as usize + 4);
                    let b = read_f32(st.cmd_buf, st.cmd_offset as usize + 8);
                    st.cmd_offset += 12;

                    // Skip frames generated before the GPU was ready. Rather than
                    // byte-scanning for CMD_FRAME_END (which could match payload
                    // bytes), mark the frame as skipped: the loop keeps decoding
                    // each command by its encoded length so the stream stays
                    // framed, and host effects are suppressed until FRAME_END.
                    if frame_tick < st.ready_tick {
                        st.skip_frame = true;
                        continue;
                    }

                    // The driver may refuse the frame (e.g. vsync throttle:
                    // one submitted frame per display refresh). Treat exactly
                    // like a stale frame: keep parsing, suppress host effects.
                    if host_gpu_raster_begin_frame(r, g, b) < 0 {
                        st.skip_frame = true;
                        continue;
                    }
                    st.in_frame = true;
                }

                CMD_SET_UNIFORMS => {
                    if st.cmd_offset + 8 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let id = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    let byte_len = read_u32(st.cmd_buf, st.cmd_offset as usize + 4);
                    if st.cmd_offset + 8 + byte_len > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    st.cmd_offset += 8;
                    let ptr = st.cmd_buf.add(st.cmd_offset as usize);
                    if !st.skip_frame {
                        host_gpu_raster_set_uniforms(id, ptr, byte_len);
                    }
                    st.cmd_offset += byte_len;
                }

                CMD_UPLOAD_VERTICES => {
                    if st.cmd_offset + 8 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let slot = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    let byte_len = read_u32(st.cmd_buf, st.cmd_offset as usize + 4);
                    if st.cmd_offset + 8 + byte_len > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    st.cmd_offset += 8;
                    let ptr = st.cmd_buf.add(st.cmd_offset as usize);
                    if !st.skip_frame {
                        host_gpu_raster_upload_vertices(slot, ptr, byte_len);
                    }
                    st.cmd_offset += byte_len;
                }

                CMD_UPLOAD_VERTICES_BEGIN => {
                    if st.cmd_offset + 8 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let slot = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    let total = read_u32(st.cmd_buf, st.cmd_offset as usize + 4);
                    st.cmd_offset += 8;
                    // Device state: processed regardless of skip_frame.
                    host_gpu_raster_vertices_begin(slot, total);
                }

                CMD_UPLOAD_VERTICES_CHUNK => {
                    if st.cmd_offset + 8 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let slot = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    let byte_len = read_u32(st.cmd_buf, st.cmd_offset as usize + 4);
                    if st.cmd_offset + 8 + byte_len > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    st.cmd_offset += 8;
                    let ptr = st.cmd_buf.add(st.cmd_offset as usize);
                    host_gpu_raster_vertices_chunk(slot, ptr, byte_len);
                    st.cmd_offset += byte_len;
                }

                CMD_UPLOAD_INDICES => {
                    if st.cmd_offset + 8 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let slot = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    let byte_len = read_u32(st.cmd_buf, st.cmd_offset as usize + 4);
                    if st.cmd_offset + 8 + byte_len > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    st.cmd_offset += 8;
                    let ptr = st.cmd_buf.add(st.cmd_offset as usize);
                    if !st.skip_frame {
                        host_gpu_raster_upload_indices(slot, ptr, byte_len);
                    }
                    st.cmd_offset += byte_len;
                }

                CMD_UPLOAD_INDICES_BEGIN => {
                    if st.cmd_offset + 8 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let slot = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    let total = read_u32(st.cmd_buf, st.cmd_offset as usize + 4);
                    st.cmd_offset += 8;
                    // Device state: processed regardless of skip_frame.
                    host_gpu_raster_indices_begin(slot, total);
                }

                CMD_UPLOAD_INDICES_CHUNK => {
                    if st.cmd_offset + 8 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let slot = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    let byte_len = read_u32(st.cmd_buf, st.cmd_offset as usize + 4);
                    if st.cmd_offset + 8 + byte_len > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    st.cmd_offset += 8;
                    let ptr = st.cmd_buf.add(st.cmd_offset as usize);
                    host_gpu_raster_indices_chunk(slot, ptr, byte_len);
                    st.cmd_offset += byte_len;
                }

                CMD_DRAW => {
                    if st.cmd_offset + 8 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let id = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    let slot = read_u32(st.cmd_buf, st.cmd_offset as usize + 4);
                    st.cmd_offset += 8;
                    if !st.skip_frame {
                        host_gpu_raster_draw(id, slot);
                    }
                }

                CMD_FRAME_END => {
                    if st.skip_frame {
                        st.skip_frame = false;
                    } else {
                        host_gpu_raster_end_frame();
                        st.in_frame = false;
                        st.frames = st.frames.wrapping_add(1);
                    }
                }

                _ => {
                    // Unknown opcode: the stream should never contain one — it
                    // means framing desynced. Log byte+offset for diagnosis.
                    let mut dbg = *b"[gpu] BAD op=00 at 00000";
                    let hi = (cmd >> 4) & 0xF;
                    let lo = cmd & 0xF;
                    dbg[14] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
                    dbg[15] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
                    let off = st.cmd_offset - 1;
                    for i in 0..5 {
                        dbg[23 - i] = b'0' + ((off / 10u32.pow(i as u32)) % 10) as u8;
                    }
                    log_msg(&dbg);
                }
            }
        }

        // Compact processed commands
        if st.cmd_offset > 0 {
            let remaining = st.cmd_len - st.cmd_offset;
            if remaining > 0 {
                core::ptr::copy(
                    st.cmd_buf.add(st.cmd_offset as usize),
                    st.cmd_buf,
                    remaining as usize,
                );
            }
            st.cmd_len = remaining;
            st.cmd_offset = 0;
        }

        0
    }
}

pub(crate) unsafe fn build(width: u16, height: u16, in_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_gpu", gpu_step);
    let raw = alloc_state(in_chan, width, height);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut GpuState, raw);
    m
}
