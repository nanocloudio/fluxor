//! `wasm_browser_canvas` built-in: VideoRaster sink that presents
//! frames to an HTML `<canvas>` through the host shim's
//! `host_canvas_present` import.
//!
//! Pixel format is RGB565 little-endian. Other formats are added by
//! extending the host import.
//!
//! State is heap-allocated (the 154 KiB QVGA RGB565 frame buffer
//! does not fit in BuiltInModule's 64-byte inline state). The kernel
//! state holds a `*mut CanvasState` pointer in bytes 0..4.

use crate::kernel::{channel, scheduler, syscalls};

extern "C" {
    /// Present an RGB565-little-endian frame to the host canvas.
    /// `ptr`/`len` is in the kernel's linear memory; the shim copies
    /// the bytes into a `Uint8ClampedArray` and blits via Canvas 2D.
    fn host_canvas_present(ptr: *const u8, len: usize, width: u32, height: u32);
}

/// QVGA RGB565: 320 × 240 × 2 bytes = 153.6 KiB. Sized to fit ZX
/// Spectrum (256 × 192) plus headroom; larger frames need a bigger
/// buffer (or producer-side downscale).
const FRAME_BUF_BYTES: usize = 320 * 240 * 2;

#[repr(C)]
pub(crate) struct CanvasState {
    pub in_chan: i32,
    pub width: u16,
    pub height: u16,
    pub frames: u32,
    pub buf_len: u32,
    pub buf: [u8; FRAME_BUF_BYTES],
}

/// Allocate a `CanvasState` on the kernel heap and return its raw
/// pointer. Caller stashes the pointer in the BuiltInModule's state
/// buffer; `step` recovers it via pointer-deref.
unsafe fn alloc_state(in_chan: i32, width: u16, height: u16) -> *mut CanvasState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<CanvasState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut CanvasState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    // Initialise fields explicitly — heap_alloc returns uninitialised memory.
    core::ptr::write(
        raw,
        CanvasState {
            in_chan,
            width,
            height,
            frames: 0,
            buf_len: 0,
            buf: [0u8; FRAME_BUF_BYTES],
        },
    );
    raw
}

/// BuiltInModule step function. Reads any pending bytes from the
/// input channel into the frame buffer; once the buffer holds a full
/// frame's worth (`width * height * 2`), presents it and resets.
fn canvas_step(state: *mut u8) -> i32 {
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut CanvasState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.in_chan < 0 {
            return 0;
        }
        let frame_size = (st.width as usize) * (st.height as usize) * 2;
        if frame_size == 0 || frame_size > st.buf.len() {
            return -1;
        }

        loop {
            let cur = st.buf_len as usize;
            if cur >= frame_size {
                host_canvas_present(
                    st.buf.as_ptr(),
                    frame_size,
                    st.width as u32,
                    st.height as u32,
                );
                st.frames = st.frames.wrapping_add(1);
                let residual = cur - frame_size;
                if residual > 0 {
                    let src = st.buf.as_ptr();
                    let dst = st.buf.as_mut_ptr();
                    core::ptr::copy(src.add(frame_size), dst, residual);
                }
                st.buf_len = residual as u32;
                continue;
            }
            let n = channel::channel_read(
                st.in_chan,
                st.buf.as_mut_ptr().add(cur),
                st.buf.len() - cur,
            );
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
pub(crate) unsafe fn build(width: u16, height: u16, in_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_canvas", canvas_step);
    let raw = alloc_state(in_chan, width, height);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut CanvasState, raw);
    m
}
