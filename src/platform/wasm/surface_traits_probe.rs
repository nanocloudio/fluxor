//! `wasm_browser_surface_traits_probe` built-in: a demo consumer of the
//! Surface Traits surface. It reads `input::surface_traits::MSG_TRAITS`
//! records from its input channel and logs the decoded fields to the
//! kernel log ring (visible in the DOM terminal), proving the full
//! round-trip: browser publisher → host queue → wasm_browser_surface_traits
//! → channel → consumer. Not a production module — it is the live
//! acceptance check for `.context/rfc_surface_traits.md` (criterion 1).

use crate::kernel::{channel, scheduler, syscalls};

/// Wire size of one record (matches input::surface_traits::EVENT_SIZE).
const EVENT_RECORD: usize = 24;

#[repr(C)]
pub(crate) struct ProbeState {
    pub in_chan: i32,
    pub buf: [u8; EVENT_RECORD],
}

unsafe fn alloc_state(in_chan: i32) -> *mut ProbeState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<ProbeState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut ProbeState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        ProbeState {
            in_chan,
            buf: [0u8; EVENT_RECORD],
        },
    );
    raw
}

#[inline]
fn u16le(b: &[u8], off: usize) -> u64 {
    (b[off] as u64) | ((b[off + 1] as u64) << 8)
}

#[inline]
fn u32le(b: &[u8], off: usize) -> u64 {
    (b[off] as u64)
        | ((b[off + 1] as u64) << 8)
        | ((b[off + 2] as u64) << 16)
        | ((b[off + 3] as u64) << 24)
}

fn probe_step(state: *mut u8) -> i32 {
    // SAFETY: state is the kernel-provided opaque state pointer for this
    // module instance; we cast it back to the module-private state type
    // allocated by the new_fn and operate within that allocation.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut ProbeState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.in_chan < 0 {
            return 0;
        }

        loop {
            let n = channel::channel_read(st.in_chan, st.buf.as_mut_ptr(), st.buf.len());
            if n < EVENT_RECORD as i32 {
                break;
            }
            let b = &st.buf;
            // Decode per input::surface_traits.rs MSG_TRAITS layout.
            let orientation = b[1] as u64;
            let size_w = b[2] as u64;
            let size_h = b[3] as u64;
            let view_w = u16le(b, 4);
            let view_h = u16le(b, 6);
            let modalities = u16le(b, 8);
            let epoch = u32le(b, 16);
            let display_count = b[21] as u64;
            super::log_fmt2(2, "[surface_traits] epoch=", epoch, " w=", view_w);
            super::log_fmt2(2, "[surface_traits]   h=", view_h, " orient=", orientation);
            super::log_fmt2(2, "[surface_traits]   sizeW=", size_w, " sizeH=", size_h);
            super::log_fmt2(
                2,
                "[surface_traits]   modalities=",
                modalities,
                " displays=",
                display_count,
            );
        }
        0
    }
}

pub(crate) unsafe fn build(in_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_surface_traits_probe", probe_step);
    let raw = alloc_state(in_chan);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut ProbeState, raw);
    m
}
