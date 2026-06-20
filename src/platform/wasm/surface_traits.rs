//! `wasm_browser_surface_traits` built-in: runtime environment-plane
//! source backed by the browser. The host shim listens to DOM `resize`,
//! `visualViewport`, `matchMedia('(pointer: coarse)')`, gamepad
//! connect/disconnect, and AudioContext state, coalesces them to at most
//! one record per animation frame, and pushes a snapshot into a per-handle
//! queue; this module drains that queue into the configured output channel.
//!
//! Wire shape on the output port:
//!   `modules/sdk/contracts/input/surface_traits.rs::MSG_TRAITS` —
//!   24-byte records (content type `SurfaceTraits`).
//!
//! Host shim contract: `host_surface_traits_pop(buf, len)` returns one
//! 24-byte record per call, or 0 when the queue is empty.

use crate::kernel::{channel, scheduler, syscalls};

extern "C" {
    /// Pop the next pending surface-traits record into `buf` (kernel-side
    /// pointer, written by the shim). Returns the number of bytes written,
    /// 0 if the queue is empty, or negative on error. Record format
    /// matches `EVENT_RECORD` below.
    fn host_surface_traits_pop(buf: *mut u8, len: usize) -> i32;
}

/// Wire size of one record (matches input::surface_traits::EVENT_SIZE).
const EVENT_RECORD: usize = 24;

#[repr(C)]
pub(crate) struct SurfaceTraitsState {
    pub out_chan: i32,
    pub buf: [u8; EVENT_RECORD],
    /// Bytes of a popped-but-not-yet-delivered record held in `buf`. A record
    /// is removed from the host queue by `host_surface_traits_pop` *before* it
    /// can be written downstream; if the write is refused (full channel) the
    /// record would be lost. We instead retain it here and retry the write on
    /// the next step, popping the next record only once `buf` has drained.
    pub pending: usize,
}

unsafe fn alloc_state(out_chan: i32) -> *mut SurfaceTraitsState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<SurfaceTraitsState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut SurfaceTraitsState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        SurfaceTraitsState {
            out_chan,
            buf: [0u8; EVENT_RECORD],
            pending: 0,
        },
    );
    raw
}

fn surface_traits_step(state: *mut u8) -> i32 {
    // SAFETY: state is the kernel-provided opaque state pointer for this
    // module instance; we cast it back to the module-private state type
    // allocated by the new_fn and operate within that allocation.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut SurfaceTraitsState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.out_chan < 0 {
            return 0;
        }

        loop {
            // Retry a previously-popped record first; only pop a fresh one once
            // the held record has been delivered.
            if st.pending == 0 {
                let n = host_surface_traits_pop(st.buf.as_mut_ptr(), st.buf.len());
                if n <= 0 {
                    break;
                }
                st.pending = (n as usize).min(st.buf.len());
            }
            let written = channel::channel_write(st.out_chan, st.buf.as_ptr(), st.pending);
            if written <= 0 {
                // Channel full — keep the record and retry next step. Records
                // are last-write-wins snapshots, so a brief delay is harmless;
                // dropping one is not.
                break;
            }
            st.pending = 0;
        }
        0
    }
}

pub(crate) unsafe fn build(out_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_surface_traits", surface_traits_step);
    let raw = alloc_state(out_chan);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut SurfaceTraitsState, raw);
    m
}
