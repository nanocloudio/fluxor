//! `wasm_browser_display_capture` built-in: frames of a surface the user chose
//! to share. Pulls the newest frame from the host shim's `getDisplayMedia`
//! capture loop and forwards it on the output channel as an `SRF1`-headered
//! RGB565-LE raster — the format `linux_display`, `st7701s`, and
//! `wasm_browser_canvas` all already consume.
//!
//! Wire shape on `capture.pixels`: one self-describing frame per capture,
//! `[magic "SRF1"][w:u16 LE][h:u16 LE][fmt:u8][flags:u8][rgb565 w*h*2]`. A
//! frame larger than the channel buffer is written across steps (position kept
//! in state), and a new frame is pulled only once the previous one is fully
//! drained, so a consumer sees whole frames back-to-back with natural
//! back-pressure and never a half-frame followed by a fresh header.
//!
//! Host shim contract: `host_display_frame(buf, len)` writes one framed raster
//! into kernel memory and returns its total byte length, 0 when no frame is
//! ready (the share dialog is still open, or permission is pending), or a
//! negative — `ENDED` once the person stopped sharing, and nothing else that
//! this leaf keeps waiting on.
//!
//! **Stopping is final here.** When the shim reports `ENDED` this leaf latches
//! and never pulls again. Re-asking would re-open the browser's share dialog —
//! a graph that quietly re-acquired someone's screen after they stopped
//! sharing it would be doing the one thing this whole surface exists to keep
//! under the person's control. A new capture is a new module instance, which
//! means a new decision.

use crate::kernel::exec::scheduler;
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

extern "C" {
    /// Fill `buf` (kernel pointer) with one `SRF1` RGB565 frame of the shared
    /// surface. Returns the total length written, 0 if no frame is available
    /// yet, or a negative to end the capture — `ENDED` when the person ended
    /// it, any other when the shim cannot serve one at all. The shim starts
    /// `getDisplayMedia` lazily on the first call, and never writes more than
    /// `len` bytes: it scales the shared surface down to the room it is given
    /// and says so in the header.
    fn host_display_frame(buf: *mut u8, len: usize) -> i32;
}

/// Self-describing frame header: `magic(4) + w(2) + h(2) + format(1) + flags(1)`.
/// Matches `sector/modules/common/sector_raster.rs` and `linux_display`'s
/// `header` mode.
const SRF1_HDR_LEN: usize = 10;

/// The shim's "the person stopped sharing" return.
///
/// Mirrored as `DISPLAY_ENDED` in `host/host_shims.js`; the two sides of one
/// value, so a change here is a change there. Everything else the shim can
/// answer is a length or 0 — see [`display_capture_step`] for why anything
/// outside that set ends the capture rather than being waited on.
const ENDED: i32 = -2;

/// Bytes one frame at `width` x `height` occupies: the self-describing header
/// plus RGB565 pixels.
///
/// One expression, because [`heap_size_for`] sizes the arena from it and
/// [`alloc_state`] allocates from it. Two copies that disagree would size the
/// arena below the allocation, which surfaces as a module that faults on its
/// first step rather than as anything that names the real cause.
fn frame_bytes(width: u16, height: u16) -> usize {
    SRF1_HDR_LEN + (width as usize) * (height as usize) * 2
}

#[repr(C)]
pub(crate) struct DisplayCaptureState {
    pub out_chan: i32,
    pub buf_ptr: *mut u8,
    pub buf_cap: u32,
    /// Total bytes in the frame currently being written (0 = none in flight).
    pub len: u32,
    /// How much of it has reached the channel.
    pub pos: u32,
    /// Set once the capture ended. Never cleared: see the module docs.
    pub ended: bool,
    /// Whether the `SRF1` header is forwarded. When it is not, the header the
    /// shim writes is skipped rather than not written: the shim always
    /// describes the frame, and this leaf decides whether the consumer is one
    /// that reads the description.
    pub header: bool,
}

/// Heap footprint: the State struct plus one full frame at the configured
/// backing geometry. Sized from the params because the buffer *is* the bound
/// on what a stream-supplied header may claim.
pub(crate) fn heap_size_for(width: u16, height: u16) -> usize {
    core::mem::size_of::<DisplayCaptureState>() + frame_bytes(width, height) + 256
}

unsafe fn alloc_state(
    out_chan: i32,
    width: u16,
    height: u16,
    header: bool,
) -> *mut DisplayCaptureState {
    let table = syscalls::get_syscall_table();
    let raw = (table.heap_alloc)(core::mem::size_of::<DisplayCaptureState>() as u32)
        as *mut DisplayCaptureState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    let cap = frame_bytes(width, height);
    let buf_ptr = (table.heap_alloc)(cap as u32);
    if buf_ptr.is_null() {
        // Hand the state block back before giving up. Nothing else holds a
        // pointer to it, and a leak on the out-of-memory path is the one that
        // makes a retry less likely to succeed than the attempt that failed.
        (table.heap_free)(raw.cast::<u8>());
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        DisplayCaptureState {
            out_chan,
            buf_ptr,
            buf_cap: cap as u32,
            len: 0,
            pos: 0,
            ended: false,
            header,
        },
    );
    raw
}

fn display_capture_step(state: *mut u8) -> i32 {
    // SAFETY: `state` is the kernel-provided opaque state pointer for this
    // module instance; cast back to the module-private type allocated by
    // `build`.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut DisplayCaptureState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.out_chan < 0 || st.buf_ptr.is_null() {
            return 0;
        }
        loop {
            if st.pos >= st.len {
                // The frame in hand is drained. Finish before honouring the
                // stop, so the last frame the person did share arrives whole
                // rather than being cut mid-raster.
                if st.ended {
                    break;
                }
                let n = host_display_frame(st.buf_ptr, st.buf_cap as usize);
                if n == 0 {
                    break; // no frame ready
                }
                if n < 0 {
                    // `ENDED` is the person stopping. Any other negative is a
                    // shim that cannot serve this capture at all — a different
                    // reason with the same honest answer, that the stream is
                    // over. Waiting on the second instead would be
                    // indistinguishable from a share dialog nobody has
                    // answered yet: a leaf producing nothing, forever, for a
                    // reason no one can see.
                    debug_assert!(n == ENDED, "host_display_frame returned an undeclared rc");
                    st.ended = true;
                    break;
                }
                st.len = (n as usize).min(st.buf_cap as usize) as u32;
                if st.len as usize <= SRF1_HDR_LEN {
                    // A frame that is header and nothing else describes no
                    // pixels; dropping it is better than writing a header a
                    // consumer would then wait behind.
                    st.len = 0;
                    break;
                }
                st.pos = if st.header { 0 } else { SRF1_HDR_LEN as u32 };
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

pub(crate) unsafe fn build(
    width: u16,
    height: u16,
    header: bool,
    out_chan: i32,
) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_display_capture", display_capture_step);
    let raw = alloc_state(out_chan, width, height, header);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut DisplayCaptureState, raw);
    m
}
