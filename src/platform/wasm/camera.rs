//! `wasm_browser_camera` built-in: camera-frame source. Pulls the latest
//! grayscale frame from the host shim's `getUserMedia` capture loop and forwards
//! it on the output channel as `[w:u16 LE][h:u16 LE][luma w*h]` — the frame format
//! the `qr_scan` module reassembles. The shim owns the `<video>` + offscreen
//! canvas + getImageData→luma; this leaf is the graph-side pump.
//!
//! Wire shape on `camera.frames`: one length-prefixed luma frame per capture. A
//! frame larger than the channel buffer is written across steps (position kept in
//! state); a new frame is pulled only once the previous is fully drained, so the
//! downstream sees whole frames back-to-back with natural back-pressure.
//!
//! Host shim contract: `host_camera_frame(buf, len)` writes one framed luma image
//! into kernel memory and returns its total byte length (header + pixels), or 0
//! when no frame is ready (camera still starting / permission pending).

use crate::kernel::exec::scheduler;
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

extern "C" {
    /// Fill `buf` (kernel pointer) with `[w:u16 LE][h:u16 LE][luma w*h]` for the
    /// most recent camera frame. Returns the total length written, 0 if no frame
    /// is available yet, or negative on error. The shim starts getUserMedia lazily
    /// on the first call.
    fn host_camera_frame(buf: *mut u8, len: usize) -> i32;
}

/// Largest frame the leaf buffers — matches qr_scan's MAX (200×200 luma + 4-byte
/// header). The shim captures at or below this.
const MAX_FRAME: usize = 4 + 200 * 200;

#[repr(C)]
pub(crate) struct CameraState {
    pub out_chan: i32,
    pub buf_ptr: *mut u8,
    pub len: u32, // total bytes in the current frame (0 = none in flight)
    pub pos: u32, // bytes of the current frame already written to the channel
}

/// Heap footprint: the State struct + the frame buffer.
pub(crate) fn heap_size_for() -> usize {
    core::mem::size_of::<CameraState>() + MAX_FRAME + 64
}

unsafe fn alloc_state(out_chan: i32) -> *mut CameraState {
    let table = syscalls::get_syscall_table();
    let raw = (table.heap_alloc)(core::mem::size_of::<CameraState>() as u32) as *mut CameraState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    let buf_ptr = (table.heap_alloc)(MAX_FRAME as u32);
    if buf_ptr.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        CameraState {
            out_chan,
            buf_ptr,
            len: 0,
            pos: 0,
        },
    );
    raw
}

fn camera_step(state: *mut u8) -> i32 {
    // SAFETY: `state` is the kernel-provided opaque state pointer for this module
    // instance; cast back to the module-private type allocated by `build`.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut CameraState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.out_chan < 0 || st.buf_ptr.is_null() {
            return 0;
        }
        loop {
            // Pull a fresh frame only when the previous is fully drained.
            if st.pos >= st.len {
                let n = host_camera_frame(st.buf_ptr, MAX_FRAME);
                if n <= 0 {
                    break; // no frame ready
                }
                st.len = (n as usize).min(MAX_FRAME) as u32;
                st.pos = 0;
            }
            let remaining = (st.len - st.pos) as usize;
            let w = channel::channel_write(st.out_chan, st.buf_ptr.add(st.pos as usize), remaining);
            if w <= 0 {
                break; // channel full — try again next step (back-pressure)
            }
            st.pos += w as u32;
        }
        0
    }
}

pub(crate) unsafe fn build(out_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_camera", camera_step);
    let raw = alloc_state(out_chan);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut CameraState, raw);
    m
}
