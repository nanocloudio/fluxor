// Contract: video_raster — the region header every record on a
// `VideoRaster` edge carries.
//
// Layer: contracts (public, stable).
//
// A raster producer sends pixels a region at a time. Every record is this
// header and then the region's pixels; there is no headerless form. The
// header is the stream's truth about its own format and geometry; the
// `video.raster` port facts are the build-time check on top of it.
//
//   [0..4]    magic      MAGIC
//   [4..6]    surface_w  u16  the whole surface's extent
//   [6..8]    surface_h  u16
//   [8]       format     u8   FORMAT_*: position in
//                             `vocabulary::RASTER_FORMATS`
//   [9]       flags      u8   FLAG_LAST | FLAG_DAMAGE; other bits zero
//   [10..12]  x          u16  the region's top-left
//   [12..14]  y          u16
//   [14..16]  w          u16  the region's extent, at least 1
//   [16..18]  h          u16
//   [18..20]  0          u16
//   [20..]    pixels     w × h × bytes-per-pixel, rows top to bottom,
//                        stride w × bytes-per-pixel
//
// Little-endian. The header is 20 bytes so RGBA8 pixels start 4-byte
// aligned.
//
// FRAMES. `FLAG_LAST` ends a frame; a consumer with frame memory presents
// at it, so a frame of several regions presents atomically. A frame is one
// of two kinds, never a mixture:
//
//   - `FLAG_DAMAGE` set on every region: each updates a retained surface,
//     and pixels outside the frame's regions keep their content.
//   - `FLAG_DAMAGE` clear on every region: the regions tile the whole
//     surface top to bottom (bands; a whole frame is one region). Each has
//     `x = 0` and `w = surface_w`, the first starts at `y = 0`, each next
//     one starts where the last ended, and the `FLAG_LAST` one ends at
//     `surface_h`.
//
// A change of `surface_w`, `surface_h` or `format` at a frame start is a
// new surface; inside a frame it is a fault.
//
// FAULTS. A consumer discards a faulted record, counts it, keeps its last
// presented picture, and resynchronises by scanning forward for a header
// whose magic, surface and format equal the current surface's
// (`find_header`). `Frames` holds the frame rules.
//
// The content type is `Streamed`: a region of a large frame is bigger than
// a small target's ring, and the header states the record's length.

/// The first four bytes of every record.
pub const MAGIC: [u8; 4] = *b"SRF1";

/// Bytes before the pixels.
pub const HEADER: usize = 20;

/// Byte offsets of the header's fields.
pub const OFF_MAGIC: usize = 0;
pub const OFF_SURFACE_W: usize = 4;
pub const OFF_SURFACE_H: usize = 6;
pub const OFF_FORMAT: usize = 8;
pub const OFF_FLAGS: usize = 9;
pub const OFF_X: usize = 10;
pub const OFF_Y: usize = 12;
pub const OFF_W: usize = 14;
pub const OFF_H: usize = 16;
pub const OFF_RESERVED: usize = 18;

/// Format bytes: positions in `vocabulary::RASTER_FORMATS`.
/// `FORMAT_RGB565`: a little-endian `u16` a pixel. `FORMAT_RGBA8`: bytes
/// red, green, blue, alpha.
pub const FORMAT_RGB565: u8 = 0;
pub const FORMAT_RGBA8: u8 = 1;
/// Number of allocated format bytes.
pub const FORMAT_COUNT: u8 = 2;

/// The frame's last region.
pub const FLAG_LAST: u8 = 0x01;
/// The region updates a retained surface.
pub const FLAG_DAMAGE: u8 = 0x02;
const FLAGS_KNOWN: u8 = FLAG_LAST | FLAG_DAMAGE;

/// Bytes in one pixel of `format`, or `None` for an unallocated byte.
pub const fn bytes_per_pixel(format: u8) -> Option<usize> {
    match format {
        FORMAT_RGB565 => Some(2),
        FORMAT_RGBA8 => Some(4),
        _ => None,
    }
}

/// Why a record is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Fewer than `HEADER` bytes.
    Truncated,
    /// The first four bytes are not `MAGIC`.
    BadMagic,
    /// A format byte past `FORMAT_COUNT`.
    UnknownFormat,
    /// A flag bit this contract does not allocate.
    BadFlags,
    /// A non-zero reserved word.
    Reserved,
    /// A region with `w` or `h` 0.
    EmptyRegion,
    /// A region reaching outside its surface.
    OutsideSurface,
    /// A surface larger than the consumer accepts.
    SurfaceTooLarge,
    /// A change of surface extent or format inside a frame.
    SurfaceChanged,
    /// A frame mixing damage regions with tiling regions.
    MixedFrame,
    /// A tiling region that is not full width, leaves a gap or an overlap,
    /// or a last one that stops short of the surface's bottom edge.
    BrokenTiling,
}

/// One region header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub surface_w: u16,
    pub surface_h: u16,
    pub format: u8,
    pub flags: u8,
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

const fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

impl Header {
    /// The header of a whole-surface frame in one region.
    pub const fn whole(surface_w: u16, surface_h: u16, format: u8) -> Header {
        Header {
            surface_w,
            surface_h,
            format,
            flags: FLAG_LAST,
            x: 0,
            y: 0,
            w: surface_w,
            h: surface_h,
        }
    }

    /// Check the header alone: a known format and flags, a non-empty region
    /// inside its surface.
    pub const fn validate(&self) -> Result<(), Fault> {
        if self.format >= FORMAT_COUNT {
            return Err(Fault::UnknownFormat);
        }
        if self.flags & !FLAGS_KNOWN != 0 {
            return Err(Fault::BadFlags);
        }
        if self.w == 0 || self.h == 0 {
            return Err(Fault::EmptyRegion);
        }
        if self.x as u32 + self.w as u32 > self.surface_w as u32
            || self.y as u32 + self.h as u32 > self.surface_h as u32
        {
            return Err(Fault::OutsideSurface);
        }
        Ok(())
    }

    /// Whether this is the frame's last region.
    pub const fn is_last(&self) -> bool {
        self.flags & FLAG_LAST != 0
    }

    /// Whether the region updates a retained surface.
    pub const fn is_damage(&self) -> bool {
        self.flags & FLAG_DAMAGE != 0
    }

    /// Bytes of pixels that follow the header; 0 for an unallocated format.
    pub const fn pixel_len(&self) -> u64 {
        let bpp = match bytes_per_pixel(self.format) {
            Some(b) => b as u64,
            None => 0,
        };
        self.w as u64 * self.h as u64 * bpp
    }

    /// Bytes of the whole record: the header and its pixels.
    pub const fn record_len(&self) -> u64 {
        HEADER as u64 + self.pixel_len()
    }

    /// Bytes of the whole surface in this format; 0 for an unallocated
    /// format.
    pub const fn surface_len(&self) -> u64 {
        let bpp = match bytes_per_pixel(self.format) {
            Some(b) => b as u64,
            None => 0,
        };
        self.surface_w as u64 * self.surface_h as u64 * bpp
    }

    /// The 20 header bytes, or the fault `validate` finds; never the bytes
    /// of a header a consumer would refuse.
    pub const fn encode(&self) -> Result<[u8; HEADER], Fault> {
        if let Err(fault) = self.validate() {
            return Err(fault);
        }
        let sw = self.surface_w.to_le_bytes();
        let sh = self.surface_h.to_le_bytes();
        let x = self.x.to_le_bytes();
        let y = self.y.to_le_bytes();
        let w = self.w.to_le_bytes();
        let h = self.h.to_le_bytes();
        Ok([
            MAGIC[0],
            MAGIC[1],
            MAGIC[2],
            MAGIC[3],
            sw[0],
            sw[1],
            sh[0],
            sh[1],
            self.format,
            self.flags,
            x[0],
            x[1],
            y[0],
            y[1],
            w[0],
            w[1],
            h[0],
            h[1],
            0,
            0,
        ])
    }

    /// Write the header at the front of `out`, returning `HEADER`. `None`
    /// when `out` is too small or the header is not valid.
    pub fn write(&self, out: &mut [u8]) -> Option<usize> {
        let bytes = self.encode().ok()?;
        out.get_mut(..HEADER)?.copy_from_slice(&bytes);
        Some(HEADER)
    }

    /// Read and check the header at the front of `buf`.
    pub const fn decode(buf: &[u8]) -> Result<Header, Fault> {
        if buf.len() < HEADER {
            return Err(Fault::Truncated);
        }
        if buf[0] != MAGIC[0] || buf[1] != MAGIC[1] || buf[2] != MAGIC[2] || buf[3] != MAGIC[3] {
            return Err(Fault::BadMagic);
        }
        if u16_at(buf, OFF_RESERVED) != 0 {
            return Err(Fault::Reserved);
        }
        let header = Header {
            surface_w: u16_at(buf, OFF_SURFACE_W),
            surface_h: u16_at(buf, OFF_SURFACE_H),
            format: buf[OFF_FORMAT],
            flags: buf[OFF_FLAGS],
            x: u16_at(buf, OFF_X),
            y: u16_at(buf, OFF_Y),
            w: u16_at(buf, OFF_W),
            h: u16_at(buf, OFF_H),
        };
        match header.validate() {
            Ok(()) => Ok(header),
            Err(fault) => Err(fault),
        }
    }
}

/// The offset of the first place in `buf` where a header of the surface
/// `surface_w × surface_h` in `format` could start: the scan a consumer
/// makes to resynchronise after a fault. The bytes there still go through
/// `Header::decode` and `Frames::admit`.
pub fn find_header(buf: &[u8], surface_w: u16, surface_h: u16, format: u8) -> Option<usize> {
    let sw = surface_w.to_le_bytes();
    let sh = surface_h.to_le_bytes();
    let want = [
        MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], sw[0], sw[1], sh[0], sh[1], format,
    ];
    buf.windows(want.len()).position(|w| w == want)
}

/// What `Frames::admit` learned about an admitted region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admitted {
    /// The region is its frame's first.
    pub frame_start: bool,
    /// The region opens a surface of another extent or format than the
    /// last (or the first surface): the consumer reallocates.
    pub new_surface: bool,
    /// The region ends its frame: a consumer with frame memory presents.
    pub last: bool,
}

/// The frame rules, enforced. A consumer admits every decoded header
/// through one of these, built with the largest surface it accepts; after a
/// fault the frame in progress is abandoned and the next admitted region
/// starts one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frames {
    max_w: u16,
    max_h: u16,
    surface: Option<(u16, u16, u8)>,
    in_frame: bool,
    damage: bool,
    next_y: u16,
}

impl Frames {
    /// Rules for a consumer accepting surfaces up to `max_w × max_h`.
    pub const fn new(max_w: u16, max_h: u16) -> Self {
        Self {
            max_w,
            max_h,
            surface: None,
            in_frame: false,
            damage: false,
            next_y: 0,
        }
    }

    /// The surface the last admitted region belonged to: extent and format.
    pub const fn surface(&self) -> Option<(u16, u16, u8)> {
        self.surface
    }

    /// Whether a frame is in progress.
    pub const fn in_frame(&self) -> bool {
        self.in_frame
    }

    /// Abandon the frame in progress: the next admitted region starts one.
    /// For a consumer that refused a record before it reached `admit` (a
    /// header `Header::decode` faulted). The surface stays the last
    /// admitted one, which a resynchronising scan looks for.
    pub const fn abandon(&mut self) {
        self.in_frame = false;
    }

    /// Admit a header `Header::decode` returned, or refuse it.
    pub fn admit(&mut self, header: &Header) -> Result<Admitted, Fault> {
        let result = self.check(header);
        if result.is_err() {
            self.in_frame = false;
        }
        result
    }

    fn check(&mut self, h: &Header) -> Result<Admitted, Fault> {
        h.validate()?;
        if h.surface_w > self.max_w || h.surface_h > self.max_h {
            return Err(Fault::SurfaceTooLarge);
        }
        let surface = (h.surface_w, h.surface_h, h.format);
        let frame_start = !self.in_frame;
        let new_surface = self.surface != Some(surface);
        if frame_start {
            self.damage = h.is_damage();
            self.next_y = 0;
        } else if new_surface {
            return Err(Fault::SurfaceChanged);
        } else if self.damage != h.is_damage() {
            return Err(Fault::MixedFrame);
        }
        if !self.damage {
            let end = h.y as u32 + h.h as u32;
            if h.x != 0
                || h.w != h.surface_w
                || h.y != self.next_y
                || h.is_last() && end != h.surface_h as u32
            {
                return Err(Fault::BrokenTiling);
            }
            self.next_y = end as u16;
        }
        self.surface = Some(surface);
        self.in_frame = !h.is_last();
        Ok(Admitted {
            frame_start,
            new_surface,
            last: h.is_last(),
        })
    }
}

const _: () = assert!(OFF_MAGIC == 0);
const _: () = assert!(OFF_MAGIC + 4 == OFF_SURFACE_W);
const _: () = assert!(OFF_SURFACE_W + 2 == OFF_SURFACE_H);
const _: () = assert!(OFF_SURFACE_H + 2 == OFF_FORMAT);
const _: () = assert!(OFF_FORMAT + 1 == OFF_FLAGS);
const _: () = assert!(OFF_FLAGS + 1 == OFF_X);
const _: () = assert!(OFF_X + 2 == OFF_Y);
const _: () = assert!(OFF_Y + 2 == OFF_W);
const _: () = assert!(OFF_W + 2 == OFF_H);
const _: () = assert!(OFF_H + 2 == OFF_RESERVED);
const _: () = assert!(OFF_RESERVED + 2 == HEADER);
const _: () = assert!(HEADER.is_multiple_of(4));
