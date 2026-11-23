//! `wasm_browser_canvas` native module: `VideoRaster` sink that presents
//! region rasters on an HTML `<canvas>` through the host shim's
//! `host_canvas_present` import.
//!
//! Every record on the input is a region header
//! (`abi::contracts::video_raster`) and that region's pixels. The header is
//! read and checked here; the shim is handed plain pixels and a rectangle.
//! A frame's regions are staged by the shim and shown together at the
//! frame's last region, so a frame of several regions appears whole. A
//! damage frame changes only its regions; the rest of the canvas keeps its
//! picture.
//!
//! A record the contract refuses is counted and skipped, the frame it
//! belonged to is abandoned, the canvas keeps what it last showed, and the
//! stream is scanned forward for the next header of the surface in use.
//!
//! The instance lives on the module's own heap with one region buffer sized
//! for a whole surface of `width` x `height` in the widest format; its
//! arena state holds the `*mut CanvasState` pointer.

use crate::abi::contracts::video_raster::{self, Frames, Header};
use crate::abi::platform::native::wasm::wasm_browser_canvas as tags;
use crate::kernel::exec::scheduler;
use crate::kernel::exec::scheduler::{NativeInit, NativeVtable};
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

extern "C" {
    /// Stage one region of a frame, and show the frame when it is complete.
    /// `ptr`/`len` are the region's pixels in the kernel's linear memory,
    /// `width` x `height` of them in `format` (a `video_raster::FORMAT_*`
    /// value), rows top to bottom; `x`, `y` place the region on a surface of
    /// `surface_w` x `surface_h`. `flags` are `PRESENT_*`.
    fn host_canvas_present(
        ptr: *const u8,
        len: usize,
        width: u32,
        height: u32,
        format: u32,
        x: u32,
        y: u32,
        surface_w: u32,
        surface_h: u32,
        flags: u32,
    );
}

/// `host_canvas_present` flag: the region opens a frame; regions the shim
/// staged for a frame that never completed are dropped.
const PRESENT_FIRST: u32 = 1;
/// `host_canvas_present` flag: the region completes its frame; the shim
/// shows every staged region.
const PRESENT_LAST: u32 = 2;

/// Bytes per pixel of the widest raster format, which sizes the region
/// buffer: a stream chooses its format per surface.
const WIDEST_PIXEL: usize = 4;
const _: () = assert!(matches!(
    video_raster::bytes_per_pixel(video_raster::FORMAT_RGBA8),
    Some(WIDEST_PIXEL)
));
const _: () = assert!(video_raster::FORMAT_COUNT == 2);

/// Bytes of a header that name its surface: the magic, the surface's extent
/// and the format. A resynchronising scan looks for these.
const SURFACE_KEY: usize = video_raster::OFF_FLAGS;

#[repr(C)]
pub(crate) struct CanvasState {
    pub in_chan: i32,
    /// The largest surface this canvas accepts: its `width` and `height`.
    pub max_w: u16,
    pub max_h: u16,
    /// The frame rules for surfaces up to that extent.
    pub frames: Frames,
    /// Header bytes read so far, and how many.
    pub carry: [u8; video_raster::HEADER],
    pub carry_len: u8,
    /// Whether `region` is admitted and its pixels are being read.
    pub in_region: bool,
    pub region: Header,
    /// `PRESENT_*` for the region being read.
    pub region_flags: u32,
    /// Pixel bytes of the region read so far.
    pub got: u32,
    /// The surface of the last admitted region, as the leading bytes of its
    /// headers; `surface_known` once one was admitted.
    pub surface_key: [u8; SURFACE_KEY],
    pub surface_known: bool,
    /// Frames shown.
    pub frames_shown: u32,
    /// Records refused.
    pub refused: u32,
    pub buf_cap: u32,
    pub buf_ptr: *mut u8,
}

/// The per-module heap the constructor seats is its manifest's `HEAP_SEAT`:
/// the instance, and a region buffer at `width` x `height` in the widest
/// format, so a stream's choice of format is never refused for room.
const SEAT: [u32; 6] = crate::abi::platform::native::wasm::wasm_browser_canvas::HEAP_SEAT;
const _: () = assert!(
    SEAT[0] as usize >= super::heap_for::<CanvasState>() + 32 && SEAT[1] as usize == WIDEST_PIXEL,
    "the declared heap seat holds the instance and a region buffer in the widest format"
);

/// Allocate a `CanvasState` on the module heap and return its raw pointer.
/// The constructor stashes the pointer in the arena state; `step` recovers
/// it by pointer-deref.
unsafe fn alloc_state(in_chan: i32, width: u16, height: u16) -> *mut CanvasState {
    let table = syscalls::get_syscall_table();
    let state_size = core::mem::size_of::<CanvasState>() as u32;
    let raw = (table.heap_alloc)(state_size) as *mut CanvasState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    let buf_cap = (width as u32) * (height as u32) * WIDEST_PIXEL as u32;
    let buf_ptr = (table.heap_alloc)(buf_cap);
    if buf_ptr.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        CanvasState {
            in_chan,
            max_w: width,
            max_h: height,
            frames: Frames::new(width, height),
            carry: [0u8; video_raster::HEADER],
            carry_len: 0,
            in_region: false,
            region: Header::whole(1, 1, video_raster::FORMAT_RGB565),
            region_flags: 0,
            got: 0,
            surface_key: [0u8; SURFACE_KEY],
            surface_known: false,
            frames_shown: 0,
            refused: 0,
            buf_cap,
            buf_ptr,
        },
    );
    raw
}

/// How many bytes to drop from the front of a refused header so that what
/// remains could still open a header worth decoding: the smallest shift, at
/// least one, after which the kept bytes agree with `want` as far as either
/// reaches. The whole carry when no such shift exists.
fn resync_shift(carry: &[u8], want: &[u8]) -> usize {
    (1..carry.len())
        .find(|&k| {
            let rest = &carry[k..];
            let n = rest.len().min(want.len());
            rest[..n] == want[..n]
        })
        .unwrap_or(carry.len())
}

impl CanvasState {
    /// Count a refused record, abandon the frame it belonged to, and keep
    /// only the carry bytes that could open the next header.
    fn refuse(&mut self, fault: video_raster::Fault) {
        if self.refused == 0 || self.refused.is_power_of_two() {
            log::warn!(
                "[canvas] raster record refused ({fault:?}); {} refused so far",
                self.refused + 1
            );
        }
        self.refused = self.refused.wrapping_add(1);
        // The frame in progress is abandoned: the next admitted region
        // starts one.
        self.frames.abandon();
        let shift = if self.surface_known {
            resync_shift(&self.carry, &self.surface_key)
        } else {
            resync_shift(&self.carry, &video_raster::MAGIC)
        };
        self.carry.copy_within(shift.., 0);
        self.carry_len = (self.carry.len() - shift) as u8;
    }
}

/// Step function. Reads region records from the input channel: a header,
/// checked against the frame rules, then that region's pixels, handed to
/// the shim once whole.
///
/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn canvas_step(state: *mut u8) -> i32 {
    // SAFETY: state is the kernel-provided opaque state pointer for
    // this module instance; we cast it back to the module-private state
    // type allocated by the constructor and operate within that allocation.
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
            if !st.in_region {
                let have = st.carry_len as usize;
                if have < video_raster::HEADER {
                    let n = channel::channel_read(
                        st.in_chan,
                        st.carry.as_mut_ptr().add(have),
                        video_raster::HEADER - have,
                    );
                    if n <= 0 {
                        break;
                    }
                    st.carry_len += n as u8;
                    continue;
                }
                let admitted = Header::decode(&st.carry)
                    .and_then(|header| st.frames.admit(&header).map(|a| (header, a)));
                let (header, admitted) = match admitted {
                    Ok(pair) => pair,
                    Err(fault) => {
                        st.refuse(fault);
                        continue;
                    }
                };
                // A surface within the configured extent in any format fits
                // the buffer, and a region is no larger than its surface.
                debug_assert!(header.pixel_len() <= u64::from(st.buf_cap));
                st.surface_key.copy_from_slice(&st.carry[..SURFACE_KEY]);
                st.surface_known = true;
                st.region = header;
                st.region_flags = if admitted.frame_start {
                    PRESENT_FIRST
                } else {
                    0
                } | if admitted.last { PRESENT_LAST } else { 0 };
                st.got = 0;
                st.carry_len = 0;
                st.in_region = true;
            }

            let need = st.region.pixel_len() as usize;
            let got = st.got as usize;
            if got < need {
                let n = channel::channel_read(st.in_chan, st.buf_ptr.add(got), need - got);
                if n <= 0 {
                    break;
                }
                st.got = (got + n as usize) as u32;
                continue;
            }
            let r = st.region;
            host_canvas_present(
                st.buf_ptr,
                need,
                u32::from(r.w),
                u32::from(r.h),
                u32::from(r.format),
                u32::from(r.x),
                u32::from(r.y),
                u32::from(r.surface_w),
                u32::from(r.surface_h),
                st.region_flags,
            );
            if r.is_last() {
                st.frames_shown = st.frames_shown.wrapping_add(1);
            }
            st.in_region = false;
        }
        0
    }
}

/// The `wasm_browser_canvas` native module.
pub static WASM_BROWSER_CANVAS: NativeVtable = super::heap_native(
    new,
    canvas_step,
    crate::abi::platform::native::wasm::wasm_browser_canvas::STATE_BYTES,
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
    let in_chan = scheduler::module_port(init.slot, tags::PORT_PIXELS);
    // SAFETY: the constructor's own contract; the instance is built on
    // the slot's heap, which the current module allocates through.
    unsafe {
        super::seat_heap_instance(
            state,
            init.slot,
            &crate::abi::platform::native::wasm::wasm_browser_canvas::HEAP_SEAT,
            init.params,
            || alloc_state(in_chan, width, height).cast(),
        )
    }
}
