//! `wasm_browser_display_capture` native module: frames of a surface the user chose
//! to share. Pulls the newest frame from the host shim's `getDisplayMedia`
//! capture loop and forwards it on the output channel as a `VideoRaster`
//! record: one region header (`abi::contracts::video_raster`) covering the
//! whole surface, then its RGB565 pixels.
//!
//! The shim hands over pixels and their extent; the header is written here.
//! The shared surface's extent is the person's choice and may change between
//! frames, which the header of each frame states. A frame is written to the
//! channel in pieces across steps (position kept in state), and a new frame
//! is pulled only once the previous one is fully written, so a consumer sees
//! whole frames back to back with natural back-pressure.
//!
//! **Stopping is final here.** When the shim reports `ENDED` this leaf latches
//! and never pulls again. Re-asking would re-open the browser's share dialog —
//! a graph that quietly re-acquired someone's screen after they stopped
//! sharing it would be doing the one thing this whole surface exists to keep
//! under the person's control. A new capture is a new module instance, which
//! means a new decision.

use crate::abi::contracts::video_raster::{self, Header};
use crate::abi::platform::native::wasm::wasm_browser_display_capture as tags;
use crate::kernel::exec::scheduler;
use crate::kernel::exec::scheduler::{NativeInit, NativeVtable};
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

extern "C" {
    /// Fill `buf` (kernel pointer, `len` bytes of room) with one frame of the
    /// shared surface as RGB565 little-endian pixels, rows top to bottom,
    /// and write the frame's width and height to `extent` (two `u32`s).
    /// Returns the pixel bytes written, 0 if no frame is available yet, or a
    /// negative to end the capture — `ENDED` when the person ended it, any
    /// other when the shim cannot serve one at all. The shim starts
    /// `getDisplayMedia` lazily on the first call, and never writes more
    /// than `len` bytes: it scales the shared surface down to the room it is
    /// given and reports the extent it produced.
    fn host_display_frame(buf: *mut u8, len: usize, extent: *mut u32) -> i32;
}

/// The shim's "the person stopped sharing" return.
///
/// Mirrored as `DISPLAY_ENDED` in `host/host_shims.js`; the two sides of one
/// value, so a change here is a change there. Everything else the shim can
/// answer is a length or 0 — see [`display_capture_step`] for why anything
/// outside that set ends the capture rather than being waited on.
const ENDED: i32 = -2;

/// The format this source produces.
const FORMAT: u8 = video_raster::FORMAT_RGB565;
const PIXEL: usize = match video_raster::bytes_per_pixel(FORMAT) {
    Some(n) => n,
    None => panic!("the capture format is a raster format"),
};

/// The most one channel write carries. A write lands whole or not at all,
/// so a frame goes out in pieces a ring of the default size takes.
const WRITE_CHUNK_BYTES: usize = 1024;

/// Bytes one frame at `width` x `height` occupies: the region header plus
/// its pixels.
///
/// One expression, because the heap seat is asserted against it and
/// [`alloc_state`] allocates from it. Two copies that disagree would size the
/// arena below the allocation, which surfaces as a module that faults on its
/// first step rather than as anything that names the real cause.
const fn frame_bytes(width: u16, height: u16) -> usize {
    video_raster::HEADER + (width as usize) * (height as usize) * PIXEL
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
}

/// Heap footprint, the manifest's `HEAP_SEAT`: the instance plus one full
/// frame at the configured backing extent. Sized from the params because
/// the buffer *is* the bound on the surface the shim may hand over.
const SEAT: [u32; 6] = crate::abi::platform::native::wasm::wasm_browser_display_capture::HEAP_SEAT;
const _: () = assert!(
    SEAT[0] as usize >= super::heap_for::<DisplayCaptureState>() + 32 + frame_bytes(0, 0)
        && SEAT[1] as usize == frame_bytes(1, 1) - frame_bytes(0, 0),
    "the declared heap seat holds the instance and one frame"
);

unsafe fn alloc_state(out_chan: i32, width: u16, height: u16) -> *mut DisplayCaptureState {
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
        },
    );
    raw
}

/// The header of a whole-surface frame of `pixel_bytes` bytes at the extent
/// the shim reported, or `None` when the two do not describe one frame the
/// contract admits.
fn frame_header(extent: [u32; 2], pixel_bytes: usize) -> Option<Header> {
    let w = u16::try_from(extent[0]).ok()?;
    let h = u16::try_from(extent[1]).ok()?;
    let header = Header::whole(w, h, FORMAT);
    header.validate().ok()?;
    (header.pixel_len() == pixel_bytes as u64).then_some(header)
}

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn display_capture_step(state: *mut u8) -> i32 {
    // SAFETY: `state` is the kernel-provided opaque state pointer for this
    // module instance; cast back to the module-private type allocated by
    // the constructor.
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
                st.len = 0;
                st.pos = 0;
                let room = st.buf_cap as usize - video_raster::HEADER;
                let mut extent = [0u32; 2];
                let n = host_display_frame(
                    st.buf_ptr.add(video_raster::HEADER),
                    room,
                    extent.as_mut_ptr(),
                );
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
                let pixel_bytes = n as usize;
                let header = if pixel_bytes <= room {
                    frame_header(extent, pixel_bytes)
                } else {
                    None
                };
                let head = core::slice::from_raw_parts_mut(st.buf_ptr, video_raster::HEADER);
                let Some(_) = header.and_then(|h| h.write(head)) else {
                    // Pixels that do not make the frame their extent names
                    // describe nothing a consumer could present.
                    log::warn!(
                        "[display-capture] dropped a {pixel_bytes}-byte frame reported as {}x{}",
                        extent[0],
                        extent[1]
                    );
                    break;
                };
                st.len = (video_raster::HEADER + pixel_bytes) as u32;
            }
            let remaining = (st.len - st.pos) as usize;
            let w = channel::channel_write(
                st.out_chan,
                st.buf_ptr.add(st.pos as usize),
                remaining.min(WRITE_CHUNK_BYTES),
            );
            if w <= 0 {
                break; // channel full — try again next step (back-pressure)
            }
            st.pos += w as u32;
        }
        0
    }
}

/// The `wasm_browser_display_capture` native module.
pub static WASM_BROWSER_DISPLAY_CAPTURE: NativeVtable = super::heap_native(
    new,
    display_capture_step,
    crate::abi::platform::native::wasm::wasm_browser_display_capture::STATE_BYTES,
);

/// # Safety
/// `state` is the instance's zeroed arena state; the current module is
/// `init.slot`.
unsafe fn new(state: *mut u8, init: &NativeInit<'_>) -> i32 {
    let mut width = 0u16;
    let mut height = 0u16;
    super::walk_tlv(init.params, |tag, value| match tag {
        tags::TAG_WIDTH => width = super::tlv_u32(value) as u16,
        tags::TAG_HEIGHT => height = super::tlv_u32(value) as u16,
        _ => {}
    });
    let out_chan = scheduler::module_port(init.slot, tags::PORT_PIXELS);
    // SAFETY: the constructor's own contract; the instance is built on
    // the slot's heap, which the current module allocates through.
    unsafe {
        super::seat_heap_instance(
            state,
            init.slot,
            &crate::abi::platform::native::wasm::wasm_browser_display_capture::HEAP_SEAT,
            init.params,
            || alloc_state(out_chan, width, height).cast(),
        )
    }
}
