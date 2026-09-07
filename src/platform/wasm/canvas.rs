//! `wasm_browser_canvas` built-in: VideoRaster sink that presents
//! frames to an HTML `<canvas>` through the host shim's
//! `host_canvas_present` import.
//!
//! Pixel format is RGB565 little-endian by default. A self-describing
//! (`header`) frame may declare [`RASTER_RGBA8`] instead, for producers whose
//! source is already 8 bits per channel — a GPU readback, say. Narrowing
//! those to RGB565 on the way to a canvas that will widen them again throws
//! away three bits of red and blue for nothing.
//!
//! State is heap-allocated (the 154 KiB QVGA RGB565 frame buffer
//! does not fit in BuiltInModule's 64-byte inline state). The kernel
//! state holds a `*mut CanvasState` pointer in bytes 0..4.

use crate::kernel::exec::scheduler;
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

extern "C" {
    /// Present a frame to the host canvas. `ptr`/`len` is in the kernel's
    /// linear memory; the shim copies the bytes into a `Uint8ClampedArray`
    /// and blits via Canvas 2D. `format` is one of the `RASTER_*` values.
    fn host_canvas_present(ptr: *const u8, len: usize, width: u32, height: u32, format: u32);
}

// The SRF1 `fmt` byte. Mirrored by the `host_canvas_present` shim in
// `src/platform/wasm/host/host_shims.js`, which is the only other reader:
// JavaScript cannot include Rust, and the wasm-only build of this file is
// unreachable from a host test, so the two sides are held together by naming
// each other rather than by a drift guard.

/// RGB565, little-endian, two bytes per pixel. The default, and what a frame
/// carrying no self-describing header is.
pub(crate) const RASTER_RGB565: u8 = 0;
/// RGBA8888, four bytes per pixel in R, G, B, A byte order. The alpha byte is
/// carried and ignored — the canvas is presented opaque — because dropping it
/// would make the row stride disagree with every producer that already has
/// its pixels in this shape, a GPU readback among them.
pub(crate) const RASTER_RGBA8: u8 = 1;

/// Bytes per pixel for a raster format. An unrecognised byte reads as RGB565,
/// which is what a producer that declares no format emits.
const fn bytes_per_pixel(format: u8) -> usize {
    match format {
        RASTER_RGBA8 => 4,
        _ => 2,
    }
}

// CanvasState's frame buffer is heap-allocated separately (sized
// to `width * height * 2`) so the State struct stays small. A
// 1080p RGB565 frame is 4 MiB — far too big to inline, and even
// a 540p frame (~1 MiB) would push the per-module heap past
// arena-friendly sizes when more than one canvas instance exists.
// Self-describing-frame header: `[magic "SRF1"][w:u16 LE][h:u16 LE][fmt:u8][flags:u8]`.
// Matches sector/modules/common/sector_raster.rs and linux_display's `header` mode.
const SRF1_MAGIC: &[u8; 4] = b"SRF1";
const SRF1_HDR_LEN: usize = 10;

#[repr(C)]
pub(crate) struct CanvasState {
    pub in_chan: i32,
    pub width: u16,
    pub height: u16,
    pub frames: u32,
    pub buf_len: u32,
    pub buf_cap: u32,
    pub buf_ptr: *mut u8,
    // When set, each frame is prefixed with an SRF1 header and `width`/`height` are
    // taken from the STREAM (bounded by `buf_cap`), not the config. `hdr_pos` tracks
    // how much of the current frame's header has been read.
    pub header_mode: bool,
    pub hdr: [u8; SRF1_HDR_LEN],
    pub hdr_pos: u8,
    /// The current frame's pixel format, from the SRF1 header's `fmt` byte.
    /// Without a header there is nothing to declare it, so it stays RGB565.
    pub format: u8,
}

/// Public — used by `wasm.rs` to size the per-module heap.
///
/// Sized for the widest format, because a self-describing stream chooses its
/// format per frame and a buffer that only fits RGB565 would refuse an RGBA8
/// frame at runtime rather than at composition.
pub(crate) fn heap_size_for(width: u16, height: u16) -> usize {
    core::mem::size_of::<CanvasState>()
        + (width as usize) * (height as usize) * bytes_per_pixel(RASTER_RGBA8)
        + 256
}

/// Allocate a `CanvasState` on the kernel heap and return its raw
/// pointer. Caller stashes the pointer in the BuiltInModule's state
/// buffer; `step` recovers it via pointer-deref.
unsafe fn alloc_state(
    in_chan: i32,
    width: u16,
    height: u16,
    header_mode: bool,
) -> *mut CanvasState {
    let table = syscalls::get_syscall_table();
    let state_size = core::mem::size_of::<CanvasState>() as u32;
    let raw = (table.heap_alloc)(state_size) as *mut CanvasState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    let buf_cap = (width as u32) * (height as u32) * bytes_per_pixel(RASTER_RGBA8) as u32;
    let buf_ptr = (table.heap_alloc)(buf_cap);
    if buf_ptr.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        CanvasState {
            in_chan,
            width,
            height,
            frames: 0,
            buf_len: 0,
            buf_cap,
            buf_ptr,
            header_mode,
            hdr: [0u8; SRF1_HDR_LEN],
            hdr_pos: 0,
            format: RASTER_RGB565,
        },
    );
    raw
}

/// BuiltInModule step function. Reads any pending bytes from the
/// input channel into the frame buffer; once the buffer holds a full
/// frame's worth (`width * height * 2`), presents it and resets.
fn canvas_step(state: *mut u8) -> i32 {
    // SAFETY: state is the kernel-provided opaque state pointer for
    // this module instance; we cast it back to the module-private state
    // type allocated by the new_fn and operate within that allocation.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut CanvasState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.in_chan < 0 || st.buf_ptr.is_null() {
            return 0;
        }

        loop {
            // Header phase (opt-in): collect the SRF1 header, then take geometry from
            // the STREAM (bounded by buf_cap) rather than the config.
            if st.header_mode && (st.hdr_pos as usize) < SRF1_HDR_LEN {
                let pos = st.hdr_pos as usize;
                let n = channel::channel_read(
                    st.in_chan,
                    st.hdr.as_mut_ptr().add(pos),
                    SRF1_HDR_LEN - pos,
                );
                if n <= 0 {
                    break;
                }
                st.hdr_pos += n as u8;
                if (st.hdr_pos as usize) < SRF1_HDR_LEN {
                    continue; // header still partial — wait for more bytes
                }
                if &st.hdr[0..4] == SRF1_MAGIC {
                    let w = u16::from_le_bytes([st.hdr[4], st.hdr[5]]);
                    let h = u16::from_le_bytes([st.hdr[6], st.hdr[7]]);
                    let fmt = st.hdr[8];
                    let need = (w as usize) * (h as usize) * bytes_per_pixel(fmt);
                    if w > 0 && h > 0 && need <= st.buf_cap as usize {
                        st.width = w;
                        st.height = h;
                        st.format = fmt;
                    }
                } else {
                    st.header_mode = false; // not SRF1 — stop parsing to avoid desync
                }
                st.buf_len = 0;
            }

            let frame_size =
                (st.width as usize) * (st.height as usize) * bytes_per_pixel(st.format);
            if frame_size == 0 || frame_size > st.buf_cap as usize {
                return -1;
            }
            let cur = st.buf_len as usize;
            if cur >= frame_size {
                host_canvas_present(
                    st.buf_ptr,
                    frame_size,
                    st.width as u32,
                    st.height as u32,
                    u32::from(st.format),
                );
                st.frames = st.frames.wrapping_add(1);
                if st.header_mode {
                    // Exact-frame reads (below) leave no residual; expect the next header.
                    st.buf_len = 0;
                    st.hdr_pos = 0;
                } else {
                    let residual = cur - frame_size;
                    if residual > 0 {
                        core::ptr::copy(st.buf_ptr.add(frame_size), st.buf_ptr, residual);
                    }
                    st.buf_len = residual as u32;
                }
                continue;
            }
            // In header mode read no further than this frame, so the next frame's
            // header stays in the channel for the header phase; else fill the buffer.
            let want = if st.header_mode {
                frame_size - cur
            } else {
                st.buf_cap as usize - cur
            };
            let n = channel::channel_read(st.in_chan, st.buf_ptr.add(cur), want);
            if n <= 0 {
                break;
            }
            st.buf_len = (cur + n as usize) as u32;
        }
        0
    }
}

/// Construct a `wasm_browser_canvas` BuiltInModule. The kernel-side
/// loader calls this when a module table entry's name matches
/// `wasm_browser_canvas`.
pub(crate) unsafe fn build(
    width: u16,
    height: u16,
    header_mode: bool,
    in_chan: i32,
) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_canvas", canvas_step);
    let raw = alloc_state(in_chan, width, height, header_mode);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut CanvasState, raw);
    m
}
