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

// CanvasState's frame buffer is heap-allocated separately (sized
// to `width * height * 2`) so the State struct stays small. A
// 1080p RGB565 frame is 4 MiB — far too big to inline, and even
// a 540p frame (~1 MiB) would push the per-module heap past
// arena-friendly sizes when more than one canvas instance exists.
#[repr(C)]
pub(crate) struct CanvasState {
    pub in_chan: i32,
    pub width: u16,
    pub height: u16,
    pub frames: u32,
    pub buf_len: u32,
    pub buf_cap: u32,
    pub buf_ptr: *mut u8,
}

/// Public — used by `wasm.rs` to size the per-module heap.
pub(crate) fn heap_size_for(width: u16, height: u16) -> usize {
    core::mem::size_of::<CanvasState>() + (width as usize) * (height as usize) * 2 + 256
}

/// Allocate a `CanvasState` on the kernel heap and return its raw
/// pointer. Caller stashes the pointer in the BuiltInModule's state
/// buffer; `step` recovers it via pointer-deref.
unsafe fn alloc_state(in_chan: i32, width: u16, height: u16) -> *mut CanvasState {
    let table = syscalls::get_syscall_table();
    let state_size = core::mem::size_of::<CanvasState>() as u32;
    let raw = (table.heap_alloc)(state_size) as *mut CanvasState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    let buf_cap = (width as u32) * (height as u32) * 2;
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
        if st.in_chan < 0 || st.buf_ptr.is_null() {
            return 0;
        }
        let frame_size = (st.width as usize) * (st.height as usize) * 2;
        if frame_size == 0 || frame_size > st.buf_cap as usize {
            return -1;
        }

        loop {
            let cur = st.buf_len as usize;
            if cur >= frame_size {
                host_canvas_present(st.buf_ptr, frame_size, st.width as u32, st.height as u32);
                st.frames = st.frames.wrapping_add(1);
                let residual = cur - frame_size;
                if residual > 0 {
                    core::ptr::copy(st.buf_ptr.add(frame_size), st.buf_ptr, residual);
                }
                st.buf_len = residual as u32;
                continue;
            }
            let n =
                channel::channel_read(st.in_chan, st.buf_ptr.add(cur), st.buf_cap as usize - cur);
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
