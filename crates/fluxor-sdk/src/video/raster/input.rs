//! One raster input of a consumer: the regions of a `VideoRaster` stream
//! read from a channel into a back buffer, and the last frame that
//! committed held in a front buffer for SURFACE records to sample.

use super::source::Texels;
use fluxor_abi::contracts::video_raster as vr;
use fluxor_abi::kernel_abi::SyscallTable;

/// Reading a header.
const HEADER: u8 = 0;
/// Reading a region's pixels into the back buffer.
const PIXELS: u8 = 1;
/// Dropping a refused region's pixels.
const SKIP: u8 = 2;
/// Sliding over the stream for the next header after an unreadable one.
const SCAN: u8 = 3;

/// A surface's extent and format.
type Geometry = (u16, u16, u8);

/// A raster input: a channel, two buffers of the consumer's, and where the
/// stream stands.
pub struct Input {
    chan: i32,
    /// Two buffers of `cap` bytes; null when the graph gives the input no
    /// storage.
    buffers: [*mut u8; 2],
    cap: usize,
    front: usize,
    /// What the front buffer holds: the last committed frame.
    shown: Option<Geometry>,
    /// What the back buffer is receiving.
    arriving: Option<Geometry>,
    frames: vr::Frames,
    phase: u8,
    head: [u8; vr::HEADER],
    head_len: usize,
    region: vr::Header,
    /// Pixel bytes of the region read so far.
    done: u64,
    skip: u64,
    /// A whole frame is in the back buffer, waiting for `commit`.
    pub ready: bool,
    /// Regions refused.
    pub refused: u32,
}

impl Input {
    /// An input reading channel `chan` (negative: not wired) into two
    /// buffers of `cap` bytes each (null: the input holds nothing and
    /// refuses every region).
    ///
    /// # Safety
    /// Each non-null buffer is `cap` writable bytes that outlive the input
    /// and that nothing else reads or writes.
    pub unsafe fn new(chan: i32, buffers: [*mut u8; 2], cap: usize) -> Self {
        Input {
            chan,
            buffers,
            cap,
            front: 0,
            shown: None,
            arriving: None,
            frames: vr::Frames::new(u16::MAX, u16::MAX),
            phase: HEADER,
            head: [0; vr::HEADER],
            head_len: 0,
            region: vr::Header::whole(1, 1, vr::FORMAT_RGB565),
            done: 0,
            skip: 0,
            ready: false,
            refused: 0,
        }
    }

    /// The committed frame, for a SURFACE record.
    pub fn texels(&self) -> Option<Texels<'_>> {
        let (w, h, format) = self.shown?;
        let len = vr::Header::whole(w, h, format).surface_len() as usize;
        if len > self.cap || self.buffers[self.front].is_null() {
            return None;
        }
        // SAFETY: the front buffer is `cap` bytes of this instance's heap
        // block, written only by `pump` into the other buffer.
        let pixels = unsafe { core::slice::from_raw_parts(self.buffers[self.front], len) };
        Texels::raster(pixels, w, h, format)
    }

    /// Show the frame that is ready: whether there was one, so what
    /// `texels` answers changed.
    pub fn commit(&mut self) -> bool {
        if !self.ready {
            return false;
        }
        self.front = 1 - self.front;
        self.shown = self.arriving;
        self.ready = false;
        true
    }

    /// Decide what the 20 bytes in `head` start.
    unsafe fn accept(&mut self) {
        let current = self.frames.surface();
        let header = match vr::Header::decode(&self.head) {
            // After a lost boundary only a header of the surface in hand is
            // believed.
            Ok(h)
                if self.phase != SCAN
                    || current.is_none_or(|s| s == (h.surface_w, h.surface_h, h.format)) =>
            {
                h
            }
            _ => {
                if self.phase != SCAN {
                    self.refused = self.refused.wrapping_add(1);
                }
                self.phase = SCAN;
                let mut i = 1;
                while i < vr::HEADER {
                    self.head[i - 1] = self.head[i];
                    i += 1;
                }
                self.head_len = vr::HEADER - 1;
                return;
            }
        };
        self.head_len = 0;
        let fits = header.surface_len() <= self.cap as u64 && !self.buffers[0].is_null();
        let admitted = if fits {
            self.frames.admit(&header).ok()
        } else {
            None
        };
        let Some(admitted) = admitted else {
            self.refused = self.refused.wrapping_add(1);
            self.skip = header.pixel_len();
            self.phase = SKIP;
            return;
        };
        if admitted.frame_start {
            let geometry = (header.surface_w, header.surface_h, header.format);
            if header.is_damage() {
                // The regions update what is shown: start from it.
                let len = header.surface_len() as usize;
                let back = self.buffers[1 - self.front];
                if self.shown == Some(geometry) {
                    core::ptr::copy_nonoverlapping(self.buffers[self.front], back, len);
                } else {
                    core::ptr::write_bytes(back, 0, len);
                }
            }
            self.arriving = Some(geometry);
        }
        self.region = header;
        self.done = 0;
        self.phase = PIXELS;
    }

    /// Read up to `budget` bytes of the stream. Stops when a frame is
    /// ready: nothing more is read until `commit`.
    ///
    /// # Safety
    /// `sys` is the kernel's syscall table, as the module was given it.
    pub unsafe fn pump(&mut self, sys: &SyscallTable, mut budget: usize) {
        if self.chan < 0 {
            return;
        }
        while budget > 0 && !self.ready {
            let read = match self.phase {
                PIXELS => {
                    let h = &self.region;
                    let bpp = vr::bytes_per_pixel(h.format).unwrap_or(2) as u64;
                    let row_bytes = u64::from(h.w) * bpp;
                    let row = self.done.checked_div(row_bytes).unwrap_or(0);
                    let col = self.done - row * row_bytes;
                    let at = ((u64::from(h.y) + row) * u64::from(h.surface_w) + u64::from(h.x))
                        * bpp
                        + col;
                    // A full-width region is one run; otherwise a row is.
                    let run = if h.w == h.surface_w {
                        h.pixel_len() - self.done
                    } else {
                        row_bytes - col
                    };
                    let want = run.min(budget as u64) as usize;
                    if at as usize + want > self.cap {
                        // Unreachable for an admitted region; never write
                        // outside the buffer.
                        self.phase = SCAN;
                        continue;
                    }
                    let dst = self.buffers[1 - self.front].add(at as usize);
                    let n = (sys.channel_read)(self.chan, dst, want);
                    if n <= 0 {
                        return;
                    }
                    self.done += n as u64;
                    if self.done == h.pixel_len() {
                        self.ready = h.is_last();
                        self.phase = HEADER;
                    }
                    n as usize
                }
                SKIP => {
                    let want = self.skip.min(budget as u64) as usize;
                    let n = (sys.channel_discard)(self.chan, want);
                    if n <= 0 {
                        return;
                    }
                    self.skip -= n as u64;
                    if self.skip == 0 {
                        self.phase = HEADER;
                    }
                    n as usize
                }
                _ => {
                    let want = vr::HEADER - self.head_len;
                    let dst = self.head.as_mut_ptr().add(self.head_len);
                    let n = (sys.channel_read)(self.chan, dst, want);
                    if n <= 0 {
                        return;
                    }
                    self.head_len += n as usize;
                    if self.head_len == vr::HEADER {
                        self.accept();
                    }
                    n as usize
                }
            };
            budget = budget.saturating_sub(read);
        }
    }
}
