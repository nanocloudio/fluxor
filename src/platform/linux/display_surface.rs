//! The picture a Linux display sink holds: `VideoRaster` records in, a
//! retained surface out.
//!
//! Every record on a `VideoRaster` edge is a region header
//! (`abi::contracts::video_raster`) and that region's pixels. `RasterSink`
//! takes the stream a chunk at a time, checks each header against the frame
//! rules, converts the region's pixels as they arrive and places them on a
//! working surface. At a frame's last region the working surface becomes
//! the presented one, so a frame of several regions appears whole. A damage
//! frame changes only its regions; the rest of the picture stays.
//!
//! A record the contract refuses is counted, the frame it belonged to is
//! abandoned and the working surface returns to the presented picture. The
//! stream is then scanned forward for the next header of the surface in
//! use (any header, before a surface was admitted).
//!
//! Pixels are held as `0x00RRGGBB`, the form a host window presents. An
//! RGBA8 region's alpha is not kept: a display sink has nothing behind its
//! picture.

use crate::abi::contracts::video_raster::{self, Fault, Frames, Header};

/// Bytes of a header that name its surface: the magic, the surface's extent
/// and the format. A resynchronising scan looks for these.
const SURFACE_KEY: usize = video_raster::OFF_FLAGS;

/// A presented picture: `width` x `height` pixels of `0x00RRGGBB`, rows top
/// to bottom.
#[derive(Clone, Copy)]
pub struct Picture<'a> {
    pub width: u16,
    pub height: u16,
    pub pixels: &'a [u32],
}

impl Picture<'_> {
    /// The picture as a binary PPM (`P6`) file.
    pub fn to_ppm(&self) -> Vec<u8> {
        let mut out = format!("P6\n{} {}\n255\n", self.width, self.height).into_bytes();
        out.reserve(self.pixels.len() * 3);
        for p in self.pixels {
            out.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, *p as u8]);
        }
        out
    }
}

/// One surface's pixels and extent.
#[derive(Default)]
struct Plane {
    width: u16,
    height: u16,
    pixels: Vec<u32>,
}

impl Plane {
    fn is(&self, width: u16, height: u16) -> bool {
        self.width == width && self.height == height && !self.pixels.is_empty()
    }

    fn copy_from(&mut self, other: &Plane) {
        self.width = other.width;
        self.height = other.height;
        self.pixels.clear();
        self.pixels.extend_from_slice(&other.pixels);
    }
}

/// `0x00RRGGBB` for a little-endian RGB565 pixel, low bits replicated.
pub fn rgb565_to_xrgb(lo: u8, hi: u8) -> u32 {
    let v = u16::from_le_bytes([lo, hi]) as u32;
    let (r5, g6, b5) = ((v >> 11) & 0x1F, (v >> 5) & 0x3F, v & 0x1F);
    let r = (r5 << 3) | (r5 >> 2);
    let g = (g6 << 2) | (g6 >> 4);
    let b = (b5 << 3) | (b5 >> 2);
    (r << 16) | (g << 8) | b
}

/// How many bytes to drop from the front of a refused header so that what
/// remains could still open a header: the smallest shift, at least one,
/// after which the kept bytes agree with `want` as far as either reaches.
/// The whole carry when no such shift exists.
fn resync_shift(carry: &[u8], want: &[u8]) -> usize {
    (1..carry.len())
        .find(|&k| {
            let rest = &carry[k..];
            let n = rest.len().min(want.len());
            rest[..n] == want[..n]
        })
        .unwrap_or(carry.len())
}

/// A `VideoRaster` consumer with frame memory.
pub struct RasterSink {
    frames: Frames,
    /// Header bytes read so far.
    carry: [u8; video_raster::HEADER],
    carry_len: usize,
    /// The admitted region whose pixels are being read.
    region: Option<Header>,
    /// Pixels of the region placed so far.
    placed: u64,
    /// Bytes of the pixel being read.
    part: [u8; 4],
    part_len: usize,
    /// The surface of the last admitted region, as the leading bytes of its
    /// headers.
    surface_key: Option<[u8; SURFACE_KEY]>,
    /// The frame being received, and the picture last presented.
    work: Plane,
    shown: Plane,
    /// Whether `work` holds regions `shown` does not.
    dirty: bool,
    /// Whether the last header read was admitted: a refusal while scanning
    /// for the next header is the same loss, counted once.
    in_sync: bool,
    presented: u32,
    refused: u32,
}

impl RasterSink {
    /// A sink accepting surfaces up to `max_w` x `max_h`.
    pub fn new(max_w: u16, max_h: u16) -> Self {
        Self {
            frames: Frames::new(max_w, max_h),
            carry: [0; video_raster::HEADER],
            carry_len: 0,
            region: None,
            placed: 0,
            part: [0; 4],
            part_len: 0,
            surface_key: None,
            work: Plane::default(),
            shown: Plane::default(),
            dirty: false,
            in_sync: true,
            presented: 0,
            refused: 0,
        }
    }

    /// Frames presented.
    pub fn presented(&self) -> u32 {
        self.presented
    }

    /// Records refused.
    pub fn refused(&self) -> u32 {
        self.refused
    }

    /// The picture last presented, once there is one.
    pub fn picture(&self) -> Option<Picture<'_>> {
        (!self.shown.pixels.is_empty()).then_some(Picture {
            width: self.shown.width,
            height: self.shown.height,
            pixels: &self.shown.pixels,
        })
    }

    /// Take the next bytes of the stream. `present` is called with the
    /// picture each time a frame completes. Returns the fault of each
    /// record refused in these bytes through `refusal`.
    pub fn feed(
        &mut self,
        mut bytes: &[u8],
        mut present: impl FnMut(Picture<'_>),
        mut refusal: impl FnMut(Fault, u32),
    ) {
        while !bytes.is_empty() {
            let Some(region) = self.region else {
                bytes = self.read_header(bytes, &mut refusal);
                continue;
            };
            bytes = self.place(&region, bytes);
            if self.placed == u64::from(region.w) * u64::from(region.h) {
                self.region = None;
                if region.is_last() {
                    self.shown.copy_from(&self.work);
                    self.dirty = false;
                    self.presented = self.presented.wrapping_add(1);
                    present(Picture {
                        width: self.shown.width,
                        height: self.shown.height,
                        pixels: &self.shown.pixels,
                    });
                }
            }
        }
    }

    /// Read header bytes from the front of `bytes`; admit the header once
    /// whole. Returns what is left of `bytes`.
    fn read_header<'b>(
        &mut self,
        mut bytes: &'b [u8],
        refusal: &mut impl FnMut(Fault, u32),
    ) -> &'b [u8] {
        if self.carry_len == 0 {
            // No header starts before the magic's first byte.
            let skip = bytes
                .iter()
                .position(|&b| b == video_raster::MAGIC[0])
                .unwrap_or(bytes.len());
            if skip > 0 {
                self.lose(Fault::BadMagic, refusal);
                bytes = &bytes[skip..];
            }
        }
        let take = (video_raster::HEADER - self.carry_len).min(bytes.len());
        self.carry[self.carry_len..self.carry_len + take].copy_from_slice(&bytes[..take]);
        self.carry_len += take;
        bytes = &bytes[take..];
        if self.carry_len < video_raster::HEADER {
            return bytes;
        }
        let admitted = Header::decode(&self.carry).and_then(|h| {
            let admitted = self.frames.admit(&h)?;
            Ok((h, admitted))
        });
        match admitted {
            Ok((header, admitted)) => {
                let mut key = [0u8; SURFACE_KEY];
                key.copy_from_slice(&self.carry[..SURFACE_KEY]);
                self.surface_key = Some(key);
                self.carry_len = 0;
                self.in_sync = true;
                if admitted.frame_start && !self.work.is(header.surface_w, header.surface_h) {
                    self.work.width = header.surface_w;
                    self.work.height = header.surface_h;
                    self.work.pixels.clear();
                    self.work.pixels.resize(
                        usize::from(header.surface_w) * usize::from(header.surface_h),
                        0,
                    );
                }
                self.dirty = true;
                self.region = Some(header);
                self.placed = 0;
                self.part_len = 0;
            }
            Err(fault) => {
                self.lose(fault, refusal);
                let shift = match &self.surface_key {
                    Some(key) => resync_shift(&self.carry, key),
                    None => resync_shift(&self.carry, &video_raster::MAGIC),
                };
                self.carry.copy_within(shift.., 0);
                self.carry_len = video_raster::HEADER - shift;
            }
        }
        bytes
    }

    /// Count a refused record once, abandon its frame and return the
    /// working surface to the presented picture.
    fn lose(&mut self, fault: Fault, refusal: &mut impl FnMut(Fault, u32)) {
        self.frames.abandon();
        if self.dirty {
            self.work.copy_from(&self.shown);
            self.dirty = false;
        }
        if self.in_sync {
            self.in_sync = false;
            self.refused = self.refused.wrapping_add(1);
            refusal(fault, self.refused);
        }
    }

    /// Convert pixel bytes from the front of `bytes` onto the working
    /// surface. Returns what is left of `bytes` once the region is whole.
    fn place<'b>(&mut self, region: &Header, mut bytes: &'b [u8]) -> &'b [u8] {
        let bpp = video_raster::bytes_per_pixel(region.format).unwrap_or(4);
        let total = u64::from(region.w) * u64::from(region.h);
        let stride = usize::from(self.work.width);
        let (x0, y0, w) = (
            usize::from(region.x),
            usize::from(region.y),
            u64::from(region.w),
        );
        while self.placed < total && !bytes.is_empty() {
            let take = (bpp - self.part_len).min(bytes.len());
            self.part[self.part_len..self.part_len + take].copy_from_slice(&bytes[..take]);
            self.part_len += take;
            bytes = &bytes[take..];
            if self.part_len < bpp {
                break;
            }
            self.part_len = 0;
            let pixel = if region.format == video_raster::FORMAT_RGB565 {
                rgb565_to_xrgb(self.part[0], self.part[1])
            } else {
                (u32::from(self.part[0]) << 16)
                    | (u32::from(self.part[1]) << 8)
                    | u32::from(self.part[2])
            };
            let (col, row) = ((self.placed % w) as usize, (self.placed / w) as usize);
            // An admitted region lies inside its surface, which is the
            // working surface's extent.
            if let Some(slot) = self.work.pixels.get_mut((y0 + row) * stride + x0 + col) {
                *slot = pixel;
            }
            self.placed += 1;
        }
        bytes
    }
}
