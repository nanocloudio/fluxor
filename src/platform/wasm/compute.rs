//! `wasm_browser_compute` built-in: generic GPU compute driver (browser/WebGPU backend)
//!
//! Backend-agnostic GPGPU capability surface, the compute sibling of the raster
//! driver in `gpu.rs`. The module holds ZERO application knowledge: no shaders,
//! no buffer semantics, no pixel formats. Applications supply the compute
//! shaders and describe the work as data on the input channel; this driver only
//! frames the command stream and forwards it to the host backend
//! (`host_gpu_compute_*` in host_shims.js today; a Vulkan or bare-metal driver
//! implements the same imports unchanged — WGSL compiles to SPIR-V via naga).
//!
//! A consumer (e.g. an emulator's pixel-pipeline rasteriser, owned by the
//! app repo) ships its compute shaders via `CREATE_PIPELINE`, uploads its work
//! buffers, expresses per-frame dispatches as a `SUBMIT` command list, and
//! blits a result buffer to the display with `PRESENT`. Present *timing* is the
//! app's decision (pace it on the `STREAM_TIME` audio clock for A/V sync).
//!
//! ## Command stream (channel input, little-endian)
//!
//! Pipelines and buffers are identified by app-chosen u32 ids (create replaces).
//!
//! - CREATE_PIPELINE [0x01] [id:u32][shader_fmt:u32][entry_len:u32][entry:utf8]
//!   [shader_len:u32][shader] — creates/replaces compute pipeline `id` from an
//!   app-supplied shader with entry point `entry`. `shader_fmt`: 0 = WGSL utf8,
//!   1 = SPIR-V, 2+ reserved for native blobs; a backend REJECTS formats it
//!   cannot consume (the browser backend takes WGSL only — apps ship the variant
//!   their target needs, translated at build time from the canonical WGSL).
//!   Bind-group layout is derived from the shader (`layout: 'auto'`, group 0).
//! - CREATE_BUFFER [0x10] [id:u32][size:u32][usage:u32] — allocates GPU buffer
//!   `id` of `size` bytes. `usage` bitmask: bit0 = storage, bit1 = uniform,
//!   bit2 = copy-src, bit4 = map-read (readback staging). copy-dst is always
//!   implied so UPLOAD_BUFFER works.
//! - UPLOAD_BUFFER [0x11] [id:u32][offset:u32][byte_len:u32][bytes…] — writes
//!   `bytes` verbatim into buffer `id` at `offset`. Opaque payload; the layout
//!   is a contract between the app's shader and the app's producer.
//! - SUBMIT [0x30] [list_len:u32][command list…] — records ONE compute
//!   submission (a single backend command encoder) from a sub-command list, then
//!   submits it (submit-then-signal; never blocks). Each list item starts with a
//!   sub-opcode byte. DISPATCH [0x01] [pipeline_id:u32][n_bind:u32][n_bind ×
//!   (binding:u32, buffer_id:u32)][groups_x:u32][groups_y:u32][groups_z:u32]
//!   binds the named buffers into group 0 at the given binding indices and
//!   dispatches `pipeline_id` — a frame with many primitives is many DISPATCH
//!   items in one SUBMIT, so the heavy per-primitive loop is DATA, not host code.
//!   COPY [0x02] [src_id:u32][src_off:u32][dst_id:u32][dst_off:u32][len:u32] is a
//!   buffer-to-buffer copy within the same encoder.
//! - PRESENT [0x40] [buffer_id:u32][width:u32][height:u32] — blits buffer `id`
//!   (interpreted as `width*height` little-endian u32 pixels, `r | g<<8 | b<<16`)
//!   to the display sink. The buffer must have been written by a prior SUBMIT.
//!   Present timing is the app's decision.
//! - READBACK [0x50] [buffer_id:u32][src_offset:u32][byte_len:u32] — reads
//!   `byte_len` bytes from buffer `id` back to the CPU and writes them to the
//!   module's OUTPUT channel (wire an output port to use it). Async: one
//!   readback outstanding at a time; requests larger than the staging buffer,
//!   or with no output port wired, are dropped.

use crate::kernel::exec::scheduler;
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

/// Command opcodes — the shared producer↔consumer wire contract. Included from
/// the same file a producer includes, so the two cannot drift.
#[path = "../../../modules/sdk/wire/gpu_compute_wire.rs"]
mod wire;
use wire::{
    CMD_CREATE_BUFFER, CMD_CREATE_PIPELINE, CMD_PRESENT, CMD_READBACK, CMD_SUBMIT,
    CMD_UPLOAD_BUFFER,
};

// Init status constants (match host_shims.js)
const GPU_INIT_READY: i32 = 0;
const GPU_INIT_PENDING: i32 = 1;
const GPU_INIT_NOT_STARTED: i32 = 2;

extern "C" {
    /// Initialize the compute backend. Returns 0=ready, 1=pending, <0=error.
    fn host_gpu_compute_init() -> i32;
    /// Poll init status (0=ready, 1=pending, <0=error).
    fn host_gpu_compute_poll_init() -> i32;
    /// Create/replace compute pipeline `id` from an app shader + entry point.
    /// Returns 0 or <0 on error (incl. an unconsumable `shader_fmt`).
    fn host_gpu_compute_pipeline(
        id: u32,
        shader_fmt: u32,
        entry_ptr: *const u8,
        entry_len: u32,
        shader_ptr: *const u8,
        shader_len: u32,
    ) -> i32;
    /// Allocate buffer `id` of `size` bytes with the given usage bitmask.
    fn host_gpu_compute_buffer(id: u32, size: u32, usage: u32) -> i32;
    /// Write `byte_len` bytes verbatim into buffer `id` at `offset`.
    fn host_gpu_compute_upload(id: u32, offset: u32, ptr: *const u8, byte_len: u32) -> i32;
    /// Record + submit one compute pass from a sub-command list. Returns 0 or <0.
    fn host_gpu_compute_submit(list_ptr: *const u8, list_len: u32) -> i32;
    /// Blit buffer `id` (width*height u32 pixels) to the display. Returns 0 or <0.
    fn host_gpu_compute_present(buffer_id: u32, width: u32, height: u32) -> i32;
    /// Read `byte_len` bytes from buffer `id` at `offset` into `out_ptr`. Async:
    /// the first call for a (buffer,offset,len) kicks off the copy+map and
    /// returns -1 (pending); a later poll returns the byte count (>=0) once the
    /// data is copied, or <0 on error. Single outstanding readback.
    fn host_gpu_compute_readback(
        buffer_id: u32,
        offset: u32,
        out_ptr: *mut u8,
        byte_len: u32,
    ) -> i32;

    fn host_log(level: u32, ptr: *const u8, len: usize);
}

fn log_msg(msg: &[u8]) {
    // SAFETY: host_log reads exactly `len` bytes from `ptr`; `msg` is a live slice.
    unsafe { host_log(2, msg.as_ptr(), msg.len()) }
}

#[repr(C)]
pub(crate) struct ComputeState {
    pub in_chan: i32,
    // Output channel for READBACK results (-1 if the module has no output port
    // wired — READBACK is then a no-op).
    pub out_chan: i32,
    pub init_status: i32,
    pub submits: u32,
    pub cmd_buf: *mut u8,
    pub cmd_len: u32,
    pub cmd_cap: u32,
    pub cmd_offset: u32,
    // Pending readback: poll the backend each step until the bytes are ready,
    // then write them to `out_chan`. One outstanding at a time (drop-if-busy).
    pub rb_active: bool,
    pub rb_buffer: u32,
    pub rb_offset: u32,
    pub rb_len: u32,
    pub rb_buf: *mut u8,
}

const CMD_BUF_SIZE: u32 = 256 * 1024; // 256KB command buffer
const RB_BUF_SIZE: u32 = 256 * 1024; // 256KB readback staging; larger requests are dropped

pub(crate) fn heap_size_for() -> usize {
    core::mem::size_of::<ComputeState>() + CMD_BUF_SIZE as usize + RB_BUF_SIZE as usize + 256
}

unsafe fn alloc_state(in_chan: i32, out_chan: i32) -> *mut ComputeState {
    let table = syscalls::get_syscall_table();
    let raw = (table.heap_alloc)(core::mem::size_of::<ComputeState>() as u32) as *mut ComputeState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    let cmd_buf = (table.heap_alloc)(CMD_BUF_SIZE);
    if cmd_buf.is_null() {
        return core::ptr::null_mut();
    }
    let rb_buf = (table.heap_alloc)(RB_BUF_SIZE);
    if rb_buf.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        ComputeState {
            in_chan,
            out_chan,
            init_status: GPU_INIT_NOT_STARTED,
            submits: 0,
            cmd_buf,
            cmd_len: 0,
            cmd_cap: CMD_BUF_SIZE,
            cmd_offset: 0,
            rb_active: false,
            rb_buffer: 0,
            rb_offset: 0,
            rb_len: 0,
            rb_buf,
        },
    );
    raw
}

fn read_u32(buf: *const u8, offset: usize) -> u32 {
    // SAFETY: callers bounds-check `offset + 4 <= cmd_len` before reading; the
    // read is unaligned-safe.
    unsafe { core::ptr::read_unaligned(buf.add(offset) as *const u32) }
}

fn compute_step(state: *mut u8) -> i32 {
    // SAFETY: single-threaded module step. `state` holds a live `*mut ComputeState`
    // written in `build()`; `cmd_buf` is a heap_alloc'd `CMD_BUF_SIZE` buffer, and
    // every payload read is bounds-checked against `cmd_len` before deref.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut ComputeState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;

        if st.init_status == GPU_INIT_NOT_STARTED {
            st.init_status = host_gpu_compute_init();
        }
        if st.init_status == GPU_INIT_PENDING {
            st.init_status = host_gpu_compute_poll_init();
        }
        if st.init_status != GPU_INIT_READY {
            return 0;
        }

        // Fill the command buffer from the channel.
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
        // break when the payload has not fully arrived; the tail is compacted
        // below and completed on a later tick (identical framing to gpu.rs).
        while st.cmd_offset < st.cmd_len {
            let cmd = *st.cmd_buf.add(st.cmd_offset as usize);
            st.cmd_offset += 1;

            match cmd {
                CMD_CREATE_PIPELINE => {
                    // [id][fmt][entry_len][entry][shader_len][shader]
                    if st.cmd_offset + 12 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let id = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    let fmt = read_u32(st.cmd_buf, st.cmd_offset as usize + 4);
                    let entry_len = read_u32(st.cmd_buf, st.cmd_offset as usize + 8);
                    // Need entry bytes + the shader_len word that follows them.
                    if st.cmd_offset + 12 + entry_len + 4 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let entry_off = st.cmd_offset + 12;
                    let shader_len = read_u32(st.cmd_buf, (entry_off + entry_len) as usize);
                    let total = 12 + entry_len + 4 + shader_len;
                    if st.cmd_offset + total > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let entry_ptr = st.cmd_buf.add(entry_off as usize);
                    let shader_ptr = st.cmd_buf.add((entry_off + entry_len + 4) as usize);
                    let rc = host_gpu_compute_pipeline(
                        id, fmt, entry_ptr, entry_len, shader_ptr, shader_len,
                    );
                    if rc < 0 {
                        log_msg(b"[compute] pipeline create failed");
                    }
                    st.cmd_offset += total;
                }

                CMD_CREATE_BUFFER => {
                    if st.cmd_offset + 12 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let id = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    let size = read_u32(st.cmd_buf, st.cmd_offset as usize + 4);
                    let usage = read_u32(st.cmd_buf, st.cmd_offset as usize + 8);
                    host_gpu_compute_buffer(id, size, usage);
                    st.cmd_offset += 12;
                }

                CMD_UPLOAD_BUFFER => {
                    if st.cmd_offset + 12 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let id = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    let offset = read_u32(st.cmd_buf, st.cmd_offset as usize + 4);
                    let byte_len = read_u32(st.cmd_buf, st.cmd_offset as usize + 8);
                    if st.cmd_offset + 12 + byte_len > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let ptr = st.cmd_buf.add((st.cmd_offset + 12) as usize);
                    host_gpu_compute_upload(id, offset, ptr, byte_len);
                    st.cmd_offset += 12 + byte_len;
                }

                CMD_SUBMIT => {
                    if st.cmd_offset + 4 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let list_len = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    if st.cmd_offset + 4 + list_len > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let ptr = st.cmd_buf.add((st.cmd_offset + 4) as usize);
                    host_gpu_compute_submit(ptr, list_len);
                    st.submits = st.submits.wrapping_add(1);
                    st.cmd_offset += 4 + list_len;
                }

                CMD_PRESENT => {
                    if st.cmd_offset + 12 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let buffer_id = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    let w = read_u32(st.cmd_buf, st.cmd_offset as usize + 4);
                    let h = read_u32(st.cmd_buf, st.cmd_offset as usize + 8);
                    host_gpu_compute_present(buffer_id, w, h);
                    st.cmd_offset += 12;
                }

                CMD_READBACK => {
                    // [buffer_id][src_offset][byte_len]. Arms a pending readback
                    // drained to the output channel below. Requests larger than
                    // the staging buffer, or with no output port wired, are
                    // dropped; a new request while one is in flight is ignored.
                    if st.cmd_offset + 12 > st.cmd_len {
                        st.cmd_offset -= 1;
                        break;
                    }
                    let buffer_id = read_u32(st.cmd_buf, st.cmd_offset as usize);
                    let offset = read_u32(st.cmd_buf, st.cmd_offset as usize + 4);
                    let len = read_u32(st.cmd_buf, st.cmd_offset as usize + 8);
                    if !st.rb_active && st.out_chan >= 0 && len > 0 && len <= RB_BUF_SIZE {
                        st.rb_active = true;
                        st.rb_buffer = buffer_id;
                        st.rb_offset = offset;
                        st.rb_len = len;
                    }
                    st.cmd_offset += 12;
                }

                _ => {
                    // Unknown opcode: framing desynced. Log byte + offset.
                    let mut dbg = *b"[compute] BAD op=00 at 00000";
                    let hi = (cmd >> 4) & 0xF;
                    let lo = cmd & 0xF;
                    dbg[18] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
                    dbg[19] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
                    let off = st.cmd_offset - 1;
                    for i in 0..5 {
                        dbg[27 - i] = b'0' + ((off / 10u32.pow(i as u32)) % 10) as u8;
                    }
                    log_msg(&dbg);
                    // Can't safely resync a byte stream; drop the rest of the buffer.
                    st.cmd_offset = st.cmd_len;
                }
            }
        }

        // Compact processed commands.
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

        // Drain a pending readback: poll the backend; when the bytes are ready,
        // forward them to the output channel. The backend kicks off the async
        // copy+map on the first poll and returns them on a later one.
        if st.rb_active {
            let got = host_gpu_compute_readback(st.rb_buffer, st.rb_offset, st.rb_buf, st.rb_len);
            if got >= 0 {
                if st.out_chan >= 0 && got > 0 {
                    channel::channel_write(st.out_chan, st.rb_buf, got as usize);
                }
                st.rb_active = false;
            }
        }

        0
    }
}

pub(crate) unsafe fn build(in_chan: i32, out_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_compute", compute_step);
    let raw = alloc_state(in_chan, out_chan);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut ComputeState, raw);
    m
}
