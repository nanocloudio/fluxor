//! `wasm_browser_gpu` built-in: WebGPU rendering backend
//!
//! Provides GPU rendering via WebGPU in the browser.
//! Uses the host_webgpu_* shims defined in host_shims.js.
//!
//! ## API for modules
//!
//! Modules send draw commands via channel. The GPU module processes
//! them and renders each frame using WebGPU.
//!
//! ## Command Format (channel input)
//!
//! Commands are binary-encoded:
//! - FRAME_BEGIN [0x01] [frame_tick:u32, clear_r:f32, clear_g:f32, clear_b:f32] = 16 bytes
//!   (`frame_tick` gates frames generated before the GPU was ready — see the
//!   CMD_FRAME_BEGIN parser; a producer omitting it shifts every field and its
//!   frames are dropped as stale.)
//! - SET_UNIFORMS [0x02] [viewProj:mat4(64), camPos:vec4(16), time:f32(4), fogDist:f32(4), _pad:vec2(8)] = 96 bytes
//!   (camPos is a vec4 by WGSL 16-byte alignment — only xyz is used; the host
//!   writes these bytes verbatim into the uniform buffer, so the wire layout IS
//!   the WGSL std140 layout. See the CMD_SET_UNIFORMS parser for offsets.)
//! - UPLOAD_VERTICES [0x10] [byte_len:u32] [vertex_data...]
//! - UPLOAD_INDICES [0x11] [byte_len:u32] [index_data...]
//! - DRAW [0x20]
//! - FRAME_END [0xFF]
//!
//! Vertex format: position (3xf32) + color (3xf32) + normal (3xf32) = 36 bytes

use crate::kernel::{channel, scheduler, syscalls};

// Command opcodes
const CMD_FRAME_BEGIN: u8 = 0x01;
const CMD_SET_UNIFORMS: u8 = 0x02;
const CMD_UPLOAD_VERTICES: u8 = 0x10;
const CMD_UPLOAD_INDICES: u8 = 0x11;
const CMD_DRAW: u8 = 0x20;
const CMD_FRAME_END: u8 = 0xFF;

// Init status constants (match host_shims.js)
const GPU_INIT_READY: i32 = 0;
const GPU_INIT_PENDING: i32 = 1;
const GPU_INIT_NOT_STARTED: i32 = 2;

// Not every host_webgpu_* import is called yet (resize / get_size are part of the
// host ABI surface the JS driver implements but the module does not drive today).
#[allow(dead_code)]
extern "C" {
    /// Initialize WebGPU. Returns 0=ready, 1=pending, <0=error
    fn host_webgpu_init() -> i32;

    /// Poll init status
    fn host_webgpu_poll_init() -> i32;

    /// Resize canvas
    fn host_webgpu_resize(width: u32, height: u32) -> i32;

    /// Upload vertices. Returns vertex count or <0 on error
    fn host_webgpu_upload_vertices(ptr: *const u8, byte_len: u32) -> i32;

    /// Upload indices (u32). Returns index count or <0 on error
    fn host_webgpu_upload_indices(ptr: *const u8, byte_len: u32) -> i32;

    /// Set uniforms (viewProj + camPos + time + fogDist)
    fn host_webgpu_set_uniforms(ptr: *const u8, byte_len: u32) -> i32;

    /// Begin frame with clear color
    fn host_webgpu_begin_frame(r: f32, g: f32, b: f32) -> i32;

    /// Draw current geometry
    fn host_webgpu_draw() -> i32;

    /// End frame and present
    fn host_webgpu_end_frame() -> i32;

    /// Get canvas size
    fn host_webgpu_get_size(out_ptr: *mut u32) -> i32;
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

static mut STEP_COUNT: u32 = 0;

fn gpu_step(state: *mut u8) -> i32 {
    unsafe {
        STEP_COUNT += 1;

        let st_ptr = core::ptr::read(state as *const *mut GpuState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;

        // Initialize WebGPU if not started
        if st.init_status == GPU_INIT_NOT_STARTED {
            log_msg(b"[gpu] init starting");
            st.init_status = host_webgpu_init();
        }

        // Poll init if pending
        if st.init_status == GPU_INIT_PENDING {
            st.init_status = host_webgpu_poll_init();
        }

        // Don't process commands until initialized
        if st.init_status != GPU_INIT_READY {
            return 0;
        }

        // Record ready_tick on first ready (used to discard stale frames)
        if st.ready_tick == 0 {
            st.ready_tick = scheduler::tick_count();
            log_msg(b"[gpu] ready, will discard stale frames");
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

        // Process commands
        while st.cmd_offset < st.cmd_len {
            let cmd = *st.cmd_buf.add(st.cmd_offset as usize);
            st.cmd_offset += 1;

            match cmd {
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

                    if st.frames == 0 {
                        log_msg(b"[gpu] FRAME_BEGIN (synced)");
                    }
                    host_webgpu_begin_frame(r, g, b);
                    st.in_frame = true;
                }

                CMD_SET_UNIFORMS => {
                    // 96 bytes in WGSL std140 layout, written verbatim into the
                    // uniform buffer by the host (`host_webgpu_set_uniforms`):
                    //   viewProj mat4x4 : offset  0, 64 bytes
                    //   camPos   vec4   : offset 64, 16 bytes (only xyz used;
                    //                     16-byte aligned per WGSL)
                    //   time     f32    : offset 80,  4 bytes
                    //   fogDist  f32    : offset 84,  4 bytes
                    //   _pad     vec2   : offset 88,  8 bytes
                    let uniform_size = 96u32;
                    if st.cmd_offset + uniform_size > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let ptr = st.cmd_buf.add(st.cmd_offset as usize);
                    if !st.skip_frame {
                        host_webgpu_set_uniforms(ptr, uniform_size);
                    }
                    st.cmd_offset += uniform_size;
                }

                CMD_UPLOAD_VERTICES => {
                    // 4 bytes: byte_len, then vertex data
                    if st.cmd_offset + 4 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let byte_len = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    st.cmd_offset += 4;

                    if st.cmd_offset + byte_len > st.cmd_len {
                        st.cmd_offset -= 5;
                        break;
                    }
                    let ptr = st.cmd_buf.add(st.cmd_offset as usize);
                    if !st.skip_frame {
                        host_webgpu_upload_vertices(ptr, byte_len);
                    }
                    st.cmd_offset += byte_len;
                }

                CMD_UPLOAD_INDICES => {
                    // 4 bytes: byte_len, then index data
                    if st.cmd_offset + 4 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let byte_len = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    st.cmd_offset += 4;

                    if st.cmd_offset + byte_len > st.cmd_len {
                        st.cmd_offset -= 5;
                        break;
                    }
                    let ptr = st.cmd_buf.add(st.cmd_offset as usize);
                    if !st.skip_frame {
                        host_webgpu_upload_indices(ptr, byte_len);
                    }
                    st.cmd_offset += byte_len;
                }

                CMD_DRAW => {
                    if !st.skip_frame {
                        host_webgpu_draw();
                    }
                }

                CMD_FRAME_END => {
                    if st.skip_frame {
                        // End of a discarded stale frame — resume normal effects.
                        st.skip_frame = false;
                    } else {
                        host_webgpu_end_frame();
                        st.in_frame = false;
                        st.frames = st.frames.wrapping_add(1);
                    }
                }

                _ => {
                    // Unknown command, skip
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
    log_msg(b"[gpu] build() called");
    let mut m = scheduler::BuiltInModule::new("wasm_browser_gpu", gpu_step);
    let raw = alloc_state(in_chan, width, height);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut GpuState, raw);
    log_msg(b"[gpu] module built");
    m
}
