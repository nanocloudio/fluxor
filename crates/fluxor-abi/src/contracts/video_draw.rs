// Contract: video_draw — the record stream on the `VideoDraw` content type.
//
// Layer: contracts (public, stable).
//
// A draw list: resources (glyph strikes, pixmaps), frames, optional bands,
// a small paint state, and drawing operations, composited in stream order.
// A consumer rasterises it, or retains the last committed frame's records
// and replays them — a few kilobytes of records standing in for a
// framebuffer. The rasteriser itself (`fluxor_sdk::video::raster`) is
// library code; this file is the wire and the rules every consumer refuses
// the same streams by.
//
// CONVENTIONS. Little-endian throughout; fields are read byte-wise, so no
// record needs alignment.
//
//   fx      i32 fixed point, 1/64 device pixel. Device space: origin
//           top-left, x right, y down.
//   rect    [x fx][y fx][w fx][h fx], 16 bytes; w, h >= 0.
//   radii   four corners (top-left, top-right, bottom-right, bottom-left),
//           each [rx fx][ry fx], 32 bytes; every value >= 0.
//   colour  [r][g][b][a], sRGB-encoded, not premultiplied.
//   prect   [x u16][y u16][w u16][h u16], whole device pixels.
//
// EVERY RECORD is a 4-byte header and then `len` payload bytes:
//
//   [0]     kind   u8
//   [1]     flags  u8   zero
//   [2..4]  len    u16  payload bytes; a fixed-size kind has exactly its
//                       stated len
//
// STREAM CONTROL
//
//   0x01 STREAM  len 18  [width u16][height u16][band_rows u16]
//                        [max_depth u8][0 u8][max_resources u16]
//                        [resource_bytes u32][generation u32]
//   0x02 END     len 0
//
// STREAM opens a stream: the surface extent, the band height (0 =
// unbanded), the deepest SAVE nesting, the resource limits, and the
// producer's session `generation`, which advances whenever the producer
// restarts. A consumer refuses a STREAM that exceeds its own limits. A
// STREAM after frames starts a new stream: all resources and state are
// released first. END closes the stream.
//
// RESOURCES
//
//   0x10 RES_DEF   [id u16][kind u8][format u8][total_len u32][digest 32]
//                  [kind header]
//   0x11 RES_DATA  [id u16][offset u32][bytes...], at least one byte
//   0x12 RES_DROP  len 2   [id u16]
//   0x13 RES_REF   len 40  [id u16][kind u8][format u8][selector u32]
//                          [digest 32]
//
//   kind 1 GLYPH_STRIKE  format: a `glyph_pack` FORMAT_* byte. No kind
//          header (RES_DEF len 40). Data: one strike, byte for byte as
//          `glyph_pack` lays a strike out; it must parse as a
//          `glyph_pack::Strike` covering exactly `total_len` bytes.
//   kind 2 PIXMAP        format: PIXMAP_RGBA8 | PIXMAP_RGB565. Kind header
//          [width u16][height u16] (RES_DEF len 44). Data: rows top to
//          bottom, tightly packed; `total_len` is width × height × bytes
//          per pixel.
//   kind 3 GLYPH_PACK    RES_REF only: a whole glyph pack the consumer
//          holds; `selector` is the ppem of the strike used.
//
// A defined resource is filled by RES_DATA chunks at explicit offsets and
// becomes usable only when all `total_len` bytes have arrived and their
// SHA-256 equals `digest`. RES_REF names bytes the consumer already holds
// in place, found by `digest`; one it cannot resolve is a fault. A RES_REF
// names a GLYPH_STRIKE (`selector` 0) or a GLYPH_PACK; a pixmap has no
// place for its extent in the record and is always defined. `id` is below
// the stream's `max_resources`; the sum of live `total_len` of defined
// resources stays within `resource_bytes` (a referenced resource costs
// nothing against it); redefining a live id is a fault. RES_DROP takes
// effect at the next COMMIT of a frame that does not name the resource,
// and its bytes count until then: a consumer replaying a retained frame
// keeps what that frame draws with. A glyph's id in a run is its index in
// the strike's entry table, not the font's glyph id, so lookup is a bounds
// check.
//
// FRAMES AND BANDS
//
//   0x20 FRAME   len 16  [generation u32][revision u32][damage prect]
//   0x21 BAND    len 4   [y u16][rows u16]
//   0x22 COMMIT  len 4   [revision u32]
//
// FRAME's `generation` equals the stream's; `revision` increases strictly
// within a stream; `damage` is the region the frame repaints, non-empty
// and inside the surface. COMMIT's `revision` matches its FRAME. Before a
// frame's (or a band's) first operation, damage pixels hold their previous
// content on a consumer that retains pixels, and opaque black on one that
// does not.
//
// A stream with `band_rows > 0` is banded: inside a frame every paint-state
// and drawing record sits in a BAND; bands cover only damage rows, in
// strictly increasing `y`, without overlap, each no taller than
// `band_rows`; at every BAND the paint state resets and the producer
// re-emits what the band needs. Unbanded, operations follow FRAME and the
// state resets there.
//
// PAINT STATE
//
//   0x30 SAVE        len 0
//   0x31 RESTORE     len 0
//   0x32 CLIP_RECT   len 16  [rect]
//   0x33 CLIP_RRECT  len 48  [rect][radii]
//   0x34 TRANSLATE   len 8   [dx fx][dy fx]
//
// The state is a translation (initially zero) and a clip: one rectangle
// (initially the damage region, intersected with the band in a banded
// stream; each CLIP_RECT intersects it exactly) and an ordered list of
// rounded rectangles (each CLIP_RRECT appends one; at most `max_depth`
// live). Clips take their shape in current coordinates; TRANSLATE adds;
// SAVE pushes the whole state and RESTORE pops it. Every fx sum is computed
// in i64 and is a fault if it leaves i32.
//
// DRAWING
//
//   0x40 FILL_RECT   len 20  [rect][colour]
//   0x41 FILL_RRECT  len 52  [rect][radii][colour]
//   0x42 BORDER      len 80  [rect][radii][widths 4 × fx][colours 4 × 4]
//   0x43 PIXMAP      len 28  [id u16][filter u8][0 u8][src prect][dst rect]
//   0x44 GLYPHS      len 16 + 6n  [res u16][count u16][colour][x fx][y fx]
//                            then n × [glyph u16][dx i16][dy i16]
//   0x45 SURFACE     len 28  [input u8][filter u8][0 u16][src prect]
//                            [dst rect]
//
// BORDER: widths and colours run top, right, bottom, left; `rect` is the
// border box. PIXMAP scales `src` of resource `id` into `dst`; `filter` is
// FILTER_NEAREST or FILTER_BILINEAR; `src` has w, h >= 1 and lies inside
// the pixmap; a `dst` with w or h 0 draws nothing. GLYPHS: `(x, y)` is the
// run's origin on the baseline; glyph i's origin is `x + dx_0 + … + dx_i`
// (the first entry's `dx` is normally 0), and `dy` offsets that glyph alone
// from the baseline; `res` is a GLYPH_STRIKE or a GLYPH_PACK reference; a
// run too long for one record is split, each record with its own origin.
// SURFACE places the latest committed frame of the consumer's raster input
// `input`, `src` of it scaled into `dst`; a surface that has committed no
// frame paints nothing.
//
// Every drawing operation is translated, then clipped, then composited.
//
// RESERVED. Kinds 0x35 (a current colour), 0x50–0x52 (paths) and flag 0x01
// on the colour-carrying kinds are held for path drawing; until then each
// is an unknown kind or a non-zero flag, and so a fault.
//
// FAULTS. On any fault the consumer discards the current frame, keeps its
// last committed output, counts the fault, and skips records by their
// `len` until the next STREAM (`resync`). Faults are never repaired.
// `parse` checks a record alone; `Sequence` checks positions, limits and
// byte accounting. The SHA-256 that makes a resource usable is the
// caller's to compute: this crate carries no hash.
//
// READING. The content type is `Streamed`: a write is whole, a read is any
// split. A consumer keeps a carry buffer, appends what it reads, and calls
// `parse` until it answers `NeedMore`.

/// Bytes of every record's header.
pub const HEADER: usize = 4;

/// One device pixel in fx units.
pub const FX_ONE: i32 = 64;

/// Record kinds.
pub const KIND_STREAM: u8 = 0x01;
pub const KIND_END: u8 = 0x02;
pub const KIND_RES_DEF: u8 = 0x10;
pub const KIND_RES_DATA: u8 = 0x11;
pub const KIND_RES_DROP: u8 = 0x12;
pub const KIND_RES_REF: u8 = 0x13;
pub const KIND_FRAME: u8 = 0x20;
pub const KIND_BAND: u8 = 0x21;
pub const KIND_COMMIT: u8 = 0x22;
pub const KIND_SAVE: u8 = 0x30;
pub const KIND_RESTORE: u8 = 0x31;
pub const KIND_CLIP_RECT: u8 = 0x32;
pub const KIND_CLIP_RRECT: u8 = 0x33;
pub const KIND_TRANSLATE: u8 = 0x34;
pub const KIND_FILL_RECT: u8 = 0x40;
pub const KIND_FILL_RRECT: u8 = 0x41;
pub const KIND_BORDER: u8 = 0x42;
pub const KIND_PIXMAP: u8 = 0x43;
pub const KIND_GLYPHS: u8 = 0x44;
pub const KIND_SURFACE: u8 = 0x45;

/// Payload lengths of the fixed-size kinds, and the fixed parts of the
/// others.
pub const STREAM_LEN: usize = 18;
pub const RES_DEF_FIXED: usize = 40;
pub const RES_DEF_PIXMAP_LEN: usize = RES_DEF_FIXED + 4;
pub const RES_DATA_FIXED: usize = 6;
pub const RES_DROP_LEN: usize = 2;
pub const RES_REF_LEN: usize = 40;
pub const FRAME_LEN: usize = 16;
pub const BAND_LEN: usize = 4;
pub const COMMIT_LEN: usize = 4;
pub const CLIP_RECT_LEN: usize = 16;
pub const CLIP_RRECT_LEN: usize = 48;
pub const TRANSLATE_LEN: usize = 8;
pub const FILL_RECT_LEN: usize = 20;
pub const FILL_RRECT_LEN: usize = 52;
pub const BORDER_LEN: usize = 80;
pub const PIXMAP_LEN: usize = 28;
pub const GLYPHS_FIXED: usize = 16;
pub const GLYPH_ENTRY: usize = 6;
pub const SURFACE_LEN: usize = 28;

/// The most glyphs one GLYPHS record carries.
pub const GLYPHS_MAX: usize = (u16::MAX as usize - GLYPHS_FIXED) / GLYPH_ENTRY;
/// The most bytes one RES_DATA record carries.
pub const RES_DATA_MAX: usize = u16::MAX as usize - RES_DATA_FIXED;
/// The largest whole record.
pub const MAX_RECORD: usize = HEADER + u16::MAX as usize;

/// Payload offsets, per record.
pub mod off {
    pub const STREAM_WIDTH: usize = 0;
    pub const STREAM_HEIGHT: usize = 2;
    pub const STREAM_BAND_ROWS: usize = 4;
    pub const STREAM_MAX_DEPTH: usize = 6;
    pub const STREAM_RESERVED: usize = 7;
    pub const STREAM_MAX_RESOURCES: usize = 8;
    pub const STREAM_RESOURCE_BYTES: usize = 10;
    pub const STREAM_GENERATION: usize = 14;

    pub const RES_ID: usize = 0;
    pub const RES_KIND: usize = 2;
    pub const RES_FORMAT: usize = 3;
    /// RES_DEF: `total_len`; RES_REF: `selector`.
    pub const RES_TOTAL_LEN: usize = 4;
    pub const RES_SELECTOR: usize = 4;
    pub const RES_DIGEST: usize = 8;
    /// RES_DEF of a pixmap: the kind header.
    pub const RES_PIXMAP_WIDTH: usize = 40;
    pub const RES_PIXMAP_HEIGHT: usize = 42;

    pub const RES_DATA_ID: usize = 0;
    pub const RES_DATA_OFFSET: usize = 2;
    pub const RES_DATA_BYTES: usize = 6;

    pub const FRAME_GENERATION: usize = 0;
    pub const FRAME_REVISION: usize = 4;
    pub const FRAME_DAMAGE: usize = 8;

    pub const BAND_Y: usize = 0;
    pub const BAND_ROWS: usize = 2;

    /// The rect that opens CLIP_RECT, CLIP_RRECT, FILL_RECT, FILL_RRECT and
    /// BORDER; the radii that follow it in the rounded kinds.
    pub const RECT: usize = 0;
    pub const RADII: usize = 16;
    pub const FILL_RECT_COLOUR: usize = 16;
    pub const FILL_RRECT_COLOUR: usize = 48;
    pub const BORDER_WIDTHS: usize = 48;
    pub const BORDER_COLOURS: usize = 64;

    pub const PIXMAP_ID: usize = 0;
    pub const PIXMAP_FILTER: usize = 2;
    pub const PIXMAP_RESERVED: usize = 3;
    pub const PIXMAP_SRC: usize = 4;
    pub const PIXMAP_DST: usize = 12;

    pub const GLYPHS_RES: usize = 0;
    pub const GLYPHS_COUNT: usize = 2;
    pub const GLYPHS_COLOUR: usize = 4;
    pub const GLYPHS_X: usize = 8;
    pub const GLYPHS_Y: usize = 12;
    pub const GLYPHS_ENTRIES: usize = 16;

    pub const SURFACE_INPUT: usize = 0;
    pub const SURFACE_FILTER: usize = 1;
    pub const SURFACE_RESERVED: usize = 2;
    pub const SURFACE_SRC: usize = 4;
    pub const SURFACE_DST: usize = 12;
}

/// Resource kinds.
pub const RES_GLYPH_STRIKE: u8 = 1;
pub const RES_PIXMAP: u8 = 2;
pub const RES_GLYPH_PACK: u8 = 3;

/// Pixmap format bytes: positions in `vocabulary::PIXMAP_FORMATS`.
/// `PIXMAP_RGBA8`: bytes red, green, blue, alpha, not premultiplied.
/// `PIXMAP_RGB565`: a little-endian `u16` a pixel, opaque.
pub const PIXMAP_RGBA8: u8 = 0;
pub const PIXMAP_RGB565: u8 = 1;
/// Number of allocated pixmap format bytes.
pub const PIXMAP_FORMAT_COUNT: u8 = 2;

/// Glyph format bytes are `glyph_pack`'s.
pub use super::glyph_pack::{
    FORMAT_A1 as GLYPH_A1, FORMAT_A8 as GLYPH_A8, FORMAT_COUNT as GLYPH_FORMAT_COUNT,
};

/// Sampling filters.
pub const FILTER_NEAREST: u8 = 0;
pub const FILTER_BILINEAR: u8 = 1;

/// Operation bits, for a consumer's `Limits::ops`: bit positions in
/// `vocabulary::DRAW_OPS`. SAVE and RESTORE are always admitted.
pub const OP_FILL_RECT: u16 = 1 << 0;
pub const OP_FILL_RRECT: u16 = 1 << 1;
pub const OP_BORDER: u16 = 1 << 2;
pub const OP_PIXMAP: u16 = 1 << 3;
pub const OP_GLYPHS: u16 = 1 << 4;
pub const OP_CLIP_RECT: u16 = 1 << 5;
pub const OP_CLIP_RRECT: u16 = 1 << 6;
pub const OP_TRANSLATE: u16 = 1 << 7;
pub const OP_SURFACE: u16 = 1 << 8;
pub const OP_RES_REF: u16 = 1 << 9;
/// Number of allocated operation bits.
pub const OP_COUNT: u8 = 10;
/// Every allocated operation bit.
pub const OPS_ALL: u16 = (1 << OP_COUNT) - 1;

/// Bytes in one pixel of a pixmap `format`, or `None` for an unallocated
/// byte.
pub const fn pixmap_bytes_per_pixel(format: u8) -> Option<u32> {
    match format {
        PIXMAP_RGBA8 => Some(4),
        PIXMAP_RGB565 => Some(2),
        _ => None,
    }
}

/// A rectangle in fx.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// Corner radii in fx: `[rx, ry]` for the top-left, top-right, bottom-right
/// and bottom-left corners.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Radii(pub [[i32; 2]; 4]);

/// A rectangle in whole device pixels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PRect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

/// `[r, g, b, a]`, sRGB-encoded, not premultiplied.
pub type Colour = [u8; 4];

/// A STREAM record's fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stream {
    pub width: u16,
    pub height: u16,
    /// Band height in rows; 0 for an unbanded stream.
    pub band_rows: u16,
    pub max_depth: u8,
    pub max_resources: u16,
    pub resource_bytes: u32,
    pub generation: u32,
}

/// A RES_DEF record's fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResDef {
    pub id: u16,
    /// `RES_GLYPH_STRIKE` or `RES_PIXMAP`.
    pub kind: u8,
    pub format: u8,
    pub total_len: u32,
    pub digest: [u8; 32],
    /// A pixmap's extent; zero for a strike.
    pub width: u16,
    pub height: u16,
}

/// A RES_REF record's fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResRef {
    pub id: u16,
    /// `RES_GLYPH_STRIKE` or `RES_GLYPH_PACK`.
    pub kind: u8,
    pub format: u8,
    /// A pack's strike, by ppem; zero for a strike.
    pub selector: u32,
    pub digest: [u8; 32],
}

/// A GLYPHS record, borrowing its entries from the read buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Glyphs<'a> {
    pub res: u16,
    pub colour: Colour,
    pub x: i32,
    pub y: i32,
    /// `GLYPH_ENTRY` bytes a glyph.
    entries: &'a [u8],
}

impl<'a> Glyphs<'a> {
    /// A run over `entries`, which is `GLYPH_ENTRY` bytes a glyph (written
    /// with `glyph_entry`). `None` when it is not a whole number of
    /// entries or holds more than `GLYPHS_MAX`.
    pub fn new(res: u16, colour: Colour, x: i32, y: i32, entries: &'a [u8]) -> Option<Self> {
        if !entries.len().is_multiple_of(GLYPH_ENTRY) || entries.len() / GLYPH_ENTRY > GLYPHS_MAX {
            return None;
        }
        Some(Self {
            res,
            colour,
            x,
            y,
            entries,
        })
    }

    /// Glyphs in the run.
    pub fn count(&self) -> usize {
        self.entries.len() / GLYPH_ENTRY
    }

    /// Glyph `i` as `(index in the strike, dx, dy)`.
    pub fn glyph(&self, i: usize) -> Option<(u16, i16, i16)> {
        let e = self.entries.get(i * GLYPH_ENTRY..(i + 1) * GLYPH_ENTRY)?;
        Some((
            u16::from_le_bytes([e[0], e[1]]),
            i16::from_le_bytes([e[2], e[3]]),
            i16::from_le_bytes([e[4], e[5]]),
        ))
    }

    /// The run's glyphs, in order.
    pub fn iter(&self) -> impl Iterator<Item = (u16, i16, i16)> + 'a {
        self.entries.chunks_exact(GLYPH_ENTRY).map(|e| {
            (
                u16::from_le_bytes([e[0], e[1]]),
                i16::from_le_bytes([e[2], e[3]]),
                i16::from_le_bytes([e[4], e[5]]),
            )
        })
    }

    /// The entries as they sit in the record.
    pub fn entries(&self) -> &'a [u8] {
        self.entries
    }
}

/// The six bytes of one GLYPHS entry.
pub const fn glyph_entry(glyph: u16, dx: i16, dy: i16) -> [u8; GLYPH_ENTRY] {
    let g = glyph.to_le_bytes();
    let x = dx.to_le_bytes();
    let y = dy.to_le_bytes();
    [g[0], g[1], x[0], x[1], y[0], y[1]]
}

/// One record. Borrowed fields point into the read buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record<'a> {
    Stream(Stream),
    End,
    ResDef(ResDef),
    ResData {
        id: u16,
        offset: u32,
        bytes: &'a [u8],
    },
    ResDrop {
        id: u16,
    },
    ResRef(ResRef),
    Frame {
        generation: u32,
        revision: u32,
        damage: PRect,
    },
    Band {
        y: u16,
        rows: u16,
    },
    Commit {
        revision: u32,
    },
    Save,
    Restore,
    ClipRect(Rect),
    ClipRRect {
        rect: Rect,
        radii: Radii,
    },
    Translate {
        dx: i32,
        dy: i32,
    },
    FillRect {
        rect: Rect,
        colour: Colour,
    },
    FillRRect {
        rect: Rect,
        radii: Radii,
        colour: Colour,
    },
    Border {
        rect: Rect,
        radii: Radii,
        /// Top, right, bottom, left.
        widths: [i32; 4],
        colours: [Colour; 4],
    },
    Pixmap {
        id: u16,
        filter: u8,
        src: PRect,
        dst: Rect,
    },
    Glyphs(Glyphs<'a>),
    Surface {
        input: u8,
        filter: u8,
        src: PRect,
        dst: Rect,
    },
}

/// Why a stream is refused. Every fault ends the frame in progress; the
/// consumer skips to the next STREAM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// A kind byte this contract does not allocate.
    UnknownKind,
    /// A non-zero flags byte.
    BadFlags,
    /// A fixed-size kind with another `len`, or a variable one whose `len`
    /// its fields cannot fill.
    BadLen,
    /// A non-zero reserved byte.
    Reserved,
    /// A record that cannot fit the reader's carry buffer.
    Oversize,
    /// An enumerated byte outside its values: a filter, a resource kind or
    /// format, a selector on a kind that takes none.
    BadValue,
    /// A negative extent, radius or width; an empty surface; a pixmap
    /// source with `w` or `h` 0.
    BadGeometry,
    /// A resource definition whose `total_len` its kind and extent do not
    /// give.
    BadResource,
    /// A record out of position: anything but STREAM outside a stream, a
    /// FRAME inside a frame, drawing or paint state outside a frame (or
    /// outside a band in a banded stream), a BAND in an unbanded stream,
    /// COMMIT or END where no frame or stream is open to close.
    OutOfPosition,
    /// A STREAM past the consumer's limits, or unbanded (or banded too
    /// tall) for a consumer that retains nothing.
    StreamLimit,
    /// A FRAME whose generation is not the stream's.
    Generation,
    /// A FRAME whose revision does not increase, or a COMMIT whose revision
    /// is not its FRAME's.
    Revision,
    /// A damage region empty or outside the surface.
    BadDamage,
    /// Damage that is not the whole surface, on a consumer that retains
    /// records.
    PartialDamage,
    /// A band out of order, overlapping, outside the damage rows, empty or
    /// taller than `band_rows`.
    BadBand,
    /// RESTORE on an empty stack.
    StackUnderflow,
    /// SAVE nesting past `max_depth`.
    StackOverflow,
    /// More than `max_depth` live rounded clips.
    ClipOverflow,
    /// An fx sum leaving i32.
    FxOverflow,
    /// An operation, pixmap format or glyph format the consumer does not
    /// admit.
    NotAdmitted,
    /// A resource id past `max_resources`, a definition past
    /// `resource_bytes`, or a redefinition of a live id.
    ResourceLimit,
    /// RES_DATA for a resource that is not being filled, or reaching past
    /// its `total_len`.
    ResourceData,
    /// A record naming a resource that is not live, not usable, or of the
    /// wrong kind; a resource whose bytes failed their digest or a
    /// reference the consumer could not resolve.
    ResourceUnusable,
    /// A glyph index past its strike.
    GlyphIndex,
    /// A pixmap source reaching outside its pixmap.
    PixmapSource,
    /// A SURFACE input past the consumer's surfaces.
    SurfaceInput,
    /// A frame larger than the consumer retains.
    FrameTooLarge,
}

/// The outcome of `parse`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parse<'a> {
    /// A whole record, and how many bytes of the buffer it occupied.
    Record {
        record: Record<'a>,
        consumed: usize,
    },
    /// The buffer ends inside a record; read more and call again.
    NeedMore,
    Fault(Fault),
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn i32_at(b: &[u8], at: usize) -> i32 {
    u32_at(b, at) as i32
}

fn rect_at(b: &[u8], at: usize) -> Result<Rect, Fault> {
    let r = Rect {
        x: i32_at(b, at),
        y: i32_at(b, at + 4),
        w: i32_at(b, at + 8),
        h: i32_at(b, at + 12),
    };
    if r.w < 0 || r.h < 0 {
        return Err(Fault::BadGeometry);
    }
    Ok(r)
}

fn radii_at(b: &[u8], at: usize) -> Result<Radii, Fault> {
    let mut radii = [[0i32; 2]; 4];
    for (i, corner) in radii.iter_mut().enumerate() {
        for (j, v) in corner.iter_mut().enumerate() {
            *v = i32_at(b, at + 8 * i + 4 * j);
            if *v < 0 {
                return Err(Fault::BadGeometry);
            }
        }
    }
    Ok(Radii(radii))
}

fn prect_at(b: &[u8], at: usize) -> PRect {
    PRect {
        x: u16_at(b, at),
        y: u16_at(b, at + 2),
        w: u16_at(b, at + 4),
        h: u16_at(b, at + 6),
    }
}

fn colour_at(b: &[u8], at: usize) -> Colour {
    [b[at], b[at + 1], b[at + 2], b[at + 3]]
}

fn digest_at(b: &[u8], at: usize) -> [u8; 32] {
    let mut d = [0u8; 32];
    d.copy_from_slice(&b[at..at + 32]);
    d
}

/// The payload length a fixed-size `kind` has, `None` for a variable or
/// unknown one.
const fn fixed_len(kind: u8) -> Option<usize> {
    Some(match kind {
        KIND_STREAM => STREAM_LEN,
        KIND_END | KIND_SAVE | KIND_RESTORE => 0,
        KIND_RES_DROP => RES_DROP_LEN,
        KIND_RES_REF => RES_REF_LEN,
        KIND_FRAME => FRAME_LEN,
        KIND_BAND => BAND_LEN,
        KIND_COMMIT => COMMIT_LEN,
        KIND_CLIP_RECT => CLIP_RECT_LEN,
        KIND_CLIP_RRECT => CLIP_RRECT_LEN,
        KIND_TRANSLATE => TRANSLATE_LEN,
        KIND_FILL_RECT => FILL_RECT_LEN,
        KIND_FILL_RRECT => FILL_RRECT_LEN,
        KIND_BORDER => BORDER_LEN,
        KIND_PIXMAP => PIXMAP_LEN,
        KIND_SURFACE => SURFACE_LEN,
        _ => return None,
    })
}

fn sample_at(p: &[u8], filter: usize, src: usize, dst: usize) -> Result<(u8, PRect, Rect), Fault> {
    if p[filter] > FILTER_BILINEAR {
        return Err(Fault::BadValue);
    }
    let s = prect_at(p, src);
    if s.w == 0 || s.h == 0 {
        return Err(Fault::BadGeometry);
    }
    Ok((p[filter], s, rect_at(p, dst)?))
}

fn parse_payload(kind: u8, p: &[u8]) -> Result<Record<'_>, Fault> {
    Ok(match kind {
        KIND_STREAM => {
            if p[off::STREAM_RESERVED] != 0 {
                return Err(Fault::Reserved);
            }
            let s = Stream {
                width: u16_at(p, off::STREAM_WIDTH),
                height: u16_at(p, off::STREAM_HEIGHT),
                band_rows: u16_at(p, off::STREAM_BAND_ROWS),
                max_depth: p[off::STREAM_MAX_DEPTH],
                max_resources: u16_at(p, off::STREAM_MAX_RESOURCES),
                resource_bytes: u32_at(p, off::STREAM_RESOURCE_BYTES),
                generation: u32_at(p, off::STREAM_GENERATION),
            };
            if s.width == 0 || s.height == 0 {
                return Err(Fault::BadGeometry);
            }
            Record::Stream(s)
        }
        KIND_END => Record::End,
        KIND_RES_DEF => {
            if p.len() < RES_DEF_FIXED {
                return Err(Fault::BadLen);
            }
            let mut d = ResDef {
                id: u16_at(p, off::RES_ID),
                kind: p[off::RES_KIND],
                format: p[off::RES_FORMAT],
                total_len: u32_at(p, off::RES_TOTAL_LEN),
                digest: digest_at(p, off::RES_DIGEST),
                width: 0,
                height: 0,
            };
            match d.kind {
                RES_GLYPH_STRIKE => {
                    if d.format >= GLYPH_FORMAT_COUNT {
                        return Err(Fault::BadValue);
                    }
                    if p.len() != RES_DEF_FIXED {
                        return Err(Fault::BadLen);
                    }
                    if d.total_len == 0 {
                        return Err(Fault::BadResource);
                    }
                }
                RES_PIXMAP => {
                    let Some(bpp) = pixmap_bytes_per_pixel(d.format) else {
                        return Err(Fault::BadValue);
                    };
                    if p.len() != RES_DEF_PIXMAP_LEN {
                        return Err(Fault::BadLen);
                    }
                    d.width = u16_at(p, off::RES_PIXMAP_WIDTH);
                    d.height = u16_at(p, off::RES_PIXMAP_HEIGHT);
                    if d.width == 0 || d.height == 0 {
                        return Err(Fault::BadGeometry);
                    }
                    let want = u64::from(d.width) * u64::from(d.height) * u64::from(bpp);
                    if u64::from(d.total_len) != want {
                        return Err(Fault::BadResource);
                    }
                }
                _ => return Err(Fault::BadValue),
            }
            Record::ResDef(d)
        }
        KIND_RES_DATA => {
            if p.len() <= RES_DATA_FIXED {
                return Err(Fault::BadLen);
            }
            Record::ResData {
                id: u16_at(p, off::RES_DATA_ID),
                offset: u32_at(p, off::RES_DATA_OFFSET),
                bytes: &p[off::RES_DATA_BYTES..],
            }
        }
        KIND_RES_DROP => Record::ResDrop {
            id: u16_at(p, off::RES_ID),
        },
        KIND_RES_REF => {
            let r = ResRef {
                id: u16_at(p, off::RES_ID),
                kind: p[off::RES_KIND],
                format: p[off::RES_FORMAT],
                selector: u32_at(p, off::RES_SELECTOR),
                digest: digest_at(p, off::RES_DIGEST),
            };
            let selector_ok = match r.kind {
                RES_GLYPH_STRIKE => r.selector == 0,
                RES_GLYPH_PACK => r.selector >= 1 && r.selector <= u16::MAX as u32,
                _ => return Err(Fault::BadValue),
            };
            if !selector_ok || r.format >= GLYPH_FORMAT_COUNT {
                return Err(Fault::BadValue);
            }
            Record::ResRef(r)
        }
        KIND_FRAME => Record::Frame {
            generation: u32_at(p, off::FRAME_GENERATION),
            revision: u32_at(p, off::FRAME_REVISION),
            damage: prect_at(p, off::FRAME_DAMAGE),
        },
        KIND_BAND => Record::Band {
            y: u16_at(p, off::BAND_Y),
            rows: u16_at(p, off::BAND_ROWS),
        },
        KIND_COMMIT => Record::Commit {
            revision: u32_at(p, 0),
        },
        KIND_SAVE => Record::Save,
        KIND_RESTORE => Record::Restore,
        KIND_CLIP_RECT => Record::ClipRect(rect_at(p, off::RECT)?),
        KIND_CLIP_RRECT => Record::ClipRRect {
            rect: rect_at(p, off::RECT)?,
            radii: radii_at(p, off::RADII)?,
        },
        KIND_TRANSLATE => Record::Translate {
            dx: i32_at(p, 0),
            dy: i32_at(p, 4),
        },
        KIND_FILL_RECT => Record::FillRect {
            rect: rect_at(p, off::RECT)?,
            colour: colour_at(p, off::FILL_RECT_COLOUR),
        },
        KIND_FILL_RRECT => Record::FillRRect {
            rect: rect_at(p, off::RECT)?,
            radii: radii_at(p, off::RADII)?,
            colour: colour_at(p, off::FILL_RRECT_COLOUR),
        },
        KIND_BORDER => {
            let mut widths = [0i32; 4];
            let mut colours = [[0u8; 4]; 4];
            for i in 0..4 {
                widths[i] = i32_at(p, off::BORDER_WIDTHS + 4 * i);
                if widths[i] < 0 {
                    return Err(Fault::BadGeometry);
                }
                colours[i] = colour_at(p, off::BORDER_COLOURS + 4 * i);
            }
            Record::Border {
                rect: rect_at(p, off::RECT)?,
                radii: radii_at(p, off::RADII)?,
                widths,
                colours,
            }
        }
        KIND_PIXMAP => {
            if p[off::PIXMAP_RESERVED] != 0 {
                return Err(Fault::Reserved);
            }
            let (filter, src, dst) =
                sample_at(p, off::PIXMAP_FILTER, off::PIXMAP_SRC, off::PIXMAP_DST)?;
            Record::Pixmap {
                id: u16_at(p, off::PIXMAP_ID),
                filter,
                src,
                dst,
            }
        }
        KIND_GLYPHS => {
            if p.len() < GLYPHS_FIXED {
                return Err(Fault::BadLen);
            }
            let count = u16_at(p, off::GLYPHS_COUNT) as usize;
            if p.len() != GLYPHS_FIXED + count * GLYPH_ENTRY {
                return Err(Fault::BadLen);
            }
            Record::Glyphs(Glyphs {
                res: u16_at(p, off::GLYPHS_RES),
                colour: colour_at(p, off::GLYPHS_COLOUR),
                x: i32_at(p, off::GLYPHS_X),
                y: i32_at(p, off::GLYPHS_Y),
                entries: &p[off::GLYPHS_ENTRIES..],
            })
        }
        KIND_SURFACE => {
            if u16_at(p, off::SURFACE_RESERVED) != 0 {
                return Err(Fault::Reserved);
            }
            let (filter, src, dst) =
                sample_at(p, off::SURFACE_FILTER, off::SURFACE_SRC, off::SURFACE_DST)?;
            Record::Surface {
                input: p[off::SURFACE_INPUT],
                filter,
                src,
                dst,
            }
        }
        _ => return Err(Fault::UnknownKind),
    })
}

/// Parse the record at the front of `buf`.
///
/// `capacity` is the size of the caller's carry buffer: a record whose
/// declared length cannot fit it would leave the reader waiting forever, so
/// it is refused as `Oversize` as soon as its header is readable. A fault a
/// record's header shows (an unknown kind, a flag, a wrong fixed length) is
/// answered before its payload has arrived.
pub fn parse(buf: &[u8], capacity: usize) -> Parse<'_> {
    if buf.len() < HEADER {
        return Parse::NeedMore;
    }
    let kind = buf[0];
    let len = u16_at(buf, 2) as usize;
    match (kind, fixed_len(kind)) {
        (_, Some(want)) if want != len => return Parse::Fault(Fault::BadLen),
        (KIND_RES_DEF | KIND_RES_DATA | KIND_GLYPHS, None) | (_, Some(_)) => {}
        _ => return Parse::Fault(Fault::UnknownKind),
    }
    if buf[1] != 0 {
        return Parse::Fault(Fault::BadFlags);
    }
    let total = HEADER + len;
    if total > capacity {
        return Parse::Fault(Fault::Oversize);
    }
    if buf.len() < total {
        return Parse::NeedMore;
    }
    match parse_payload(kind, &buf[HEADER..total]) {
        Ok(record) => Parse::Record {
            record,
            consumed: total,
        },
        Err(fault) => Parse::Fault(fault),
    }
}

/// How to drop a faulted stream's bytes: see `resync`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resync {
    /// Bytes to drop from the front of the buffer.
    pub discard: usize,
    /// Bytes of the record being skipped that have not been read yet: the
    /// reader drops that many more as they arrive before calling again.
    pub skip_more: usize,
    /// The buffer, after `discard`, starts at a STREAM record.
    pub at_stream: bool,
}

/// After a fault, skip whole records by their `len` to the next STREAM.
pub fn resync(buf: &[u8]) -> Resync {
    let mut at = 0;
    loop {
        let rest = &buf[at..];
        if rest.len() < HEADER {
            return Resync {
                discard: at,
                skip_more: 0,
                at_stream: false,
            };
        }
        if rest[0] == KIND_STREAM {
            return Resync {
                discard: at,
                skip_more: 0,
                at_stream: true,
            };
        }
        let total = HEADER + u16_at(rest, 2) as usize;
        if rest.len() < total {
            return Resync {
                discard: buf.len(),
                skip_more: total - rest.len(),
                at_stream: false,
            };
        }
        at += total;
    }
}

fn put_header(out: &mut [u8], kind: u8, len: usize) {
    out[0] = kind;
    out[1] = 0;
    out[2..4].copy_from_slice(&(len as u16).to_le_bytes());
}

fn put_rect(p: &mut [u8], at: usize, r: &Rect) {
    for (i, v) in [r.x, r.y, r.w, r.h].into_iter().enumerate() {
        p[at + 4 * i..at + 4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
}

fn put_radii(p: &mut [u8], at: usize, r: &Radii) {
    for (i, corner) in r.0.iter().enumerate() {
        for (j, v) in corner.iter().enumerate() {
            let o = at + 8 * i + 4 * j;
            p[o..o + 4].copy_from_slice(&v.to_le_bytes());
        }
    }
}

fn put_prect(p: &mut [u8], at: usize, r: &PRect) {
    for (i, v) in [r.x, r.y, r.w, r.h].into_iter().enumerate() {
        p[at + 2 * i..at + 2 * i + 2].copy_from_slice(&v.to_le_bytes());
    }
}

fn put_u16(p: &mut [u8], at: usize, v: u16) {
    p[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(p: &mut [u8], at: usize, v: u32) {
    p[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// The payload length `record` encodes to.
fn payload_len(record: &Record<'_>) -> usize {
    match record {
        Record::Stream(_) => STREAM_LEN,
        Record::End | Record::Save | Record::Restore => 0,
        Record::ResDef(d) if d.kind == RES_PIXMAP => RES_DEF_PIXMAP_LEN,
        Record::ResDef(_) => RES_DEF_FIXED,
        Record::ResData { bytes, .. } => RES_DATA_FIXED + bytes.len(),
        Record::ResDrop { .. } => RES_DROP_LEN,
        Record::ResRef(_) => RES_REF_LEN,
        Record::Frame { .. } => FRAME_LEN,
        Record::Band { .. } => BAND_LEN,
        Record::Commit { .. } => COMMIT_LEN,
        Record::ClipRect(_) => CLIP_RECT_LEN,
        Record::ClipRRect { .. } => CLIP_RRECT_LEN,
        Record::Translate { .. } => TRANSLATE_LEN,
        Record::FillRect { .. } => FILL_RECT_LEN,
        Record::FillRRect { .. } => FILL_RRECT_LEN,
        Record::Border { .. } => BORDER_LEN,
        Record::Pixmap { .. } => PIXMAP_LEN,
        Record::Glyphs(g) => GLYPHS_FIXED + g.entries.len(),
        Record::Surface { .. } => SURFACE_LEN,
    }
}

/// Write `record` at the front of `out`, returning its length.
///
/// `None` when `out` is too small or the record is one `parse` refuses (a
/// negative extent, an unallocated format, a payload past what `len` can
/// state); `out` then holds no record a reader may be handed.
pub fn write(out: &mut [u8], record: &Record<'_>) -> Option<usize> {
    let len = payload_len(record);
    if len > u16::MAX as usize {
        return None;
    }
    let total = HEADER + len;
    let out = out.get_mut(..total)?;
    out.fill(0);
    let (head, p) = out.split_at_mut(HEADER);
    match record {
        Record::Stream(s) => {
            put_header(head, KIND_STREAM, len);
            put_u16(p, off::STREAM_WIDTH, s.width);
            put_u16(p, off::STREAM_HEIGHT, s.height);
            put_u16(p, off::STREAM_BAND_ROWS, s.band_rows);
            p[off::STREAM_MAX_DEPTH] = s.max_depth;
            put_u16(p, off::STREAM_MAX_RESOURCES, s.max_resources);
            put_u32(p, off::STREAM_RESOURCE_BYTES, s.resource_bytes);
            put_u32(p, off::STREAM_GENERATION, s.generation);
        }
        Record::End => put_header(head, KIND_END, len),
        Record::ResDef(d) => {
            put_header(head, KIND_RES_DEF, len);
            put_u16(p, off::RES_ID, d.id);
            p[off::RES_KIND] = d.kind;
            p[off::RES_FORMAT] = d.format;
            put_u32(p, off::RES_TOTAL_LEN, d.total_len);
            p[off::RES_DIGEST..off::RES_DIGEST + 32].copy_from_slice(&d.digest);
            if d.kind == RES_PIXMAP {
                put_u16(p, off::RES_PIXMAP_WIDTH, d.width);
                put_u16(p, off::RES_PIXMAP_HEIGHT, d.height);
            } else if d.width != 0 || d.height != 0 {
                return None;
            }
        }
        Record::ResData { id, offset, bytes } => {
            put_header(head, KIND_RES_DATA, len);
            put_u16(p, off::RES_DATA_ID, *id);
            put_u32(p, off::RES_DATA_OFFSET, *offset);
            p[off::RES_DATA_BYTES..].copy_from_slice(bytes);
        }
        Record::ResDrop { id } => {
            put_header(head, KIND_RES_DROP, len);
            put_u16(p, off::RES_ID, *id);
        }
        Record::ResRef(r) => {
            put_header(head, KIND_RES_REF, len);
            put_u16(p, off::RES_ID, r.id);
            p[off::RES_KIND] = r.kind;
            p[off::RES_FORMAT] = r.format;
            put_u32(p, off::RES_SELECTOR, r.selector);
            p[off::RES_DIGEST..off::RES_DIGEST + 32].copy_from_slice(&r.digest);
        }
        Record::Frame {
            generation,
            revision,
            damage,
        } => {
            put_header(head, KIND_FRAME, len);
            put_u32(p, off::FRAME_GENERATION, *generation);
            put_u32(p, off::FRAME_REVISION, *revision);
            put_prect(p, off::FRAME_DAMAGE, damage);
        }
        Record::Band { y, rows } => {
            put_header(head, KIND_BAND, len);
            put_u16(p, off::BAND_Y, *y);
            put_u16(p, off::BAND_ROWS, *rows);
        }
        Record::Commit { revision } => {
            put_header(head, KIND_COMMIT, len);
            put_u32(p, 0, *revision);
        }
        Record::Save => put_header(head, KIND_SAVE, len),
        Record::Restore => put_header(head, KIND_RESTORE, len),
        Record::ClipRect(rect) => {
            put_header(head, KIND_CLIP_RECT, len);
            put_rect(p, off::RECT, rect);
        }
        Record::ClipRRect { rect, radii } => {
            put_header(head, KIND_CLIP_RRECT, len);
            put_rect(p, off::RECT, rect);
            put_radii(p, off::RADII, radii);
        }
        Record::Translate { dx, dy } => {
            put_header(head, KIND_TRANSLATE, len);
            put_u32(p, 0, *dx as u32);
            put_u32(p, 4, *dy as u32);
        }
        Record::FillRect { rect, colour } => {
            put_header(head, KIND_FILL_RECT, len);
            put_rect(p, off::RECT, rect);
            p[off::FILL_RECT_COLOUR..].copy_from_slice(colour);
        }
        Record::FillRRect {
            rect,
            radii,
            colour,
        } => {
            put_header(head, KIND_FILL_RRECT, len);
            put_rect(p, off::RECT, rect);
            put_radii(p, off::RADII, radii);
            p[off::FILL_RRECT_COLOUR..].copy_from_slice(colour);
        }
        Record::Border {
            rect,
            radii,
            widths,
            colours,
        } => {
            put_header(head, KIND_BORDER, len);
            put_rect(p, off::RECT, rect);
            put_radii(p, off::RADII, radii);
            for i in 0..4 {
                put_u32(p, off::BORDER_WIDTHS + 4 * i, widths[i] as u32);
                let c = off::BORDER_COLOURS + 4 * i;
                p[c..c + 4].copy_from_slice(&colours[i]);
            }
        }
        Record::Pixmap {
            id,
            filter,
            src,
            dst,
        } => {
            put_header(head, KIND_PIXMAP, len);
            put_u16(p, off::PIXMAP_ID, *id);
            p[off::PIXMAP_FILTER] = *filter;
            put_prect(p, off::PIXMAP_SRC, src);
            put_rect(p, off::PIXMAP_DST, dst);
        }
        Record::Glyphs(g) => {
            put_header(head, KIND_GLYPHS, len);
            put_u16(p, off::GLYPHS_RES, g.res);
            put_u16(p, off::GLYPHS_COUNT, g.count() as u16);
            p[off::GLYPHS_COLOUR..off::GLYPHS_COLOUR + 4].copy_from_slice(&g.colour);
            put_u32(p, off::GLYPHS_X, g.x as u32);
            put_u32(p, off::GLYPHS_Y, g.y as u32);
            p[off::GLYPHS_ENTRIES..].copy_from_slice(g.entries);
        }
        Record::Surface {
            input,
            filter,
            src,
            dst,
        } => {
            put_header(head, KIND_SURFACE, len);
            p[off::SURFACE_INPUT] = *input;
            p[off::SURFACE_FILTER] = *filter;
            put_prect(p, off::SURFACE_SRC, src);
            put_rect(p, off::SURFACE_DST, dst);
        }
    }
    match parse(out, total) {
        Parse::Record { consumed, .. } if consumed == total => Some(total),
        _ => {
            out.fill(0);
            None
        }
    }
}

/// Write just a RES_DATA record's header and fixed fields
/// (`HEADER + RES_DATA_FIXED` bytes), for a producer that sends them and
/// the `len` resource bytes as separate writes of one record. The two
/// writes go to the channel back to back. `None` when `out` is too small
/// or `len` is 0 or past `RES_DATA_MAX`.
pub fn write_res_data_header(out: &mut [u8], id: u16, offset: u32, len: usize) -> Option<usize> {
    if len == 0 || len > RES_DATA_MAX {
        return None;
    }
    let total = HEADER + RES_DATA_FIXED;
    let out = out.get_mut(..total)?;
    put_header(out, KIND_RES_DATA, RES_DATA_FIXED + len);
    put_u16(out, HEADER + off::RES_DATA_ID, id);
    put_u32(out, HEADER + off::RES_DATA_OFFSET, offset);
    Some(total)
}

/// What a consumer takes: its `video.draw` facts and the storage it built
/// its `Sequence` over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// `OP_*` bits of the operations it draws.
    pub ops: u16,
    /// A bit per `PIXMAP_*` format byte it takes.
    pub pixmap_formats: u8,
    /// A bit per `GLYPH_*` format byte it takes.
    pub glyph_formats: u8,
    /// The largest surface it draws.
    pub max_width: u16,
    pub max_height: u16,
    pub max_depth: u8,
    pub max_resources: u16,
    pub resource_bytes: u32,
    /// The largest frame it retains, FRAME through COMMIT, resource records
    /// excluded; 0 when it retains nothing, which requires a banded stream.
    pub frame_bytes: u32,
    /// The tallest band it takes when it retains nothing.
    pub band_rows: u16,
    /// It replays retained records, so every frame's damage must be the
    /// whole surface.
    pub damage_full: bool,
    /// Raster inputs a SURFACE may name.
    pub surfaces: u8,
}

/// One resource slot of a `Sequence`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resource {
    state: ResourceState,
    kind: u8,
    format: u8,
    referenced: bool,
    dropped: bool,
    named: bool,
    width: u16,
    height: u16,
    total_len: u32,
    received: u32,
    selector: u32,
    glyphs: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResourceState {
    Free,
    /// Defined; RES_DATA still arriving.
    Filling,
    /// Every byte has arrived, or the resource is a reference: the caller
    /// owes `Sequence::resolve`.
    Unresolved,
    Usable,
}

impl Resource {
    /// An empty slot, to build the table a `Sequence` borrows.
    pub const FREE: Resource = Resource {
        state: ResourceState::Free,
        kind: 0,
        format: 0,
        referenced: false,
        dropped: false,
        named: false,
        width: 0,
        height: 0,
        total_len: 0,
        received: 0,
        selector: 0,
        glyphs: 0,
    };

    /// `RES_*`.
    pub const fn kind(&self) -> u8 {
        self.kind
    }

    pub const fn format(&self) -> u8 {
        self.format
    }

    /// Named by RES_REF: its bytes are the consumer's own.
    pub const fn is_referenced(&self) -> bool {
        self.referenced
    }

    /// May be drawn with.
    pub const fn is_usable(&self) -> bool {
        matches!(self.state, ResourceState::Usable)
    }

    /// A pixmap's extent.
    pub const fn extent(&self) -> (u16, u16) {
        (self.width, self.height)
    }

    /// A defined resource's length in bytes.
    pub const fn total_len(&self) -> u32 {
        self.total_len
    }

    /// A referenced pack's strike, by ppem.
    pub const fn selector(&self) -> u32 {
        self.selector
    }

    /// Glyphs in a usable strike.
    pub const fn glyphs(&self) -> u32 {
        self.glyphs
    }
}

/// One saved paint state of a `Sequence`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Saved {
    tx: i32,
    ty: i32,
    rounded_clips: u8,
}

impl Saved {
    /// An empty slot, to build the stack a `Sequence` borrows.
    pub const EMPTY: Saved = Saved {
        tx: 0,
        ty: 0,
        rounded_clips: 0,
    };
}

/// What `Sequence::admit` learned about an admitted record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admitted {
    /// Nothing the caller must act on beyond the record itself.
    Record,
    /// A stream opened: every resource and all state of the last are
    /// released.
    Stream,
    /// The last byte of resource `id` arrived. The caller checks the
    /// bytes' SHA-256 against the definition's digest (and that a strike
    /// parses) and answers with `Sequence::resolve`.
    ResourceComplete { id: u16 },
    /// Resource `id` names bytes the consumer holds. The caller finds them
    /// by digest and answers with `Sequence::resolve`.
    ResourceReferenced { id: u16 },
    /// A frame committed. Dropped resources the frame does not name are
    /// released: `Sequence::resource` answers `None` for them.
    Commit,
    /// The stream closed.
    End,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Position {
    /// No stream is open, or the stream faulted.
    Closed,
    /// A stream is open, between frames.
    Open,
    /// Inside a frame; in a banded stream, before its first band.
    Frame,
    /// Inside a band.
    Band,
}

/// The stream rules, enforced: positions, limits and byte accounting. A
/// consumer admits every parsed record through one of these, built over a
/// resource table and a paint-state stack it owns; after a fault only a
/// STREAM is admitted.
#[derive(Debug)]
pub struct Sequence<'t> {
    limits: Limits,
    resources: &'t mut [Resource],
    stack: &'t mut [Saved],
    at: Position,
    stream: Stream,
    last_revision: Option<u32>,
    frame_revision: u32,
    damage: PRect,
    frame_used: u32,
    band_floor: u32,
    live_bytes: u32,
    depth: usize,
    tx: i32,
    ty: i32,
    rounded_clips: u8,
}

const NO_STREAM: Stream = Stream {
    width: 0,
    height: 0,
    band_rows: 0,
    max_depth: 0,
    max_resources: 0,
    resource_bytes: 0,
    generation: 0,
};

fn fx_sum(a: i64, b: i64) -> Result<i32, Fault> {
    i32::try_from(a + b).map_err(|_| Fault::FxOverflow)
}

impl<'t> Sequence<'t> {
    /// Rules for a consumer with `limits`, over its resource table and
    /// paint-state stack. `limits.max_resources` and `limits.max_depth` are
    /// lowered to what the two slices hold.
    pub fn new(mut limits: Limits, resources: &'t mut [Resource], stack: &'t mut [Saved]) -> Self {
        limits.max_resources = limits
            .max_resources
            .min(resources.len().min(u16::MAX as usize) as u16);
        limits.max_depth = limits
            .max_depth
            .min(stack.len().min(u8::MAX as usize) as u8);
        resources.fill(Resource::FREE);
        Self {
            limits,
            resources,
            stack,
            at: Position::Closed,
            stream: NO_STREAM,
            last_revision: None,
            frame_revision: 0,
            damage: PRect {
                x: 0,
                y: 0,
                w: 0,
                h: 0,
            },
            frame_used: 0,
            band_floor: 0,
            live_bytes: 0,
            depth: 0,
            tx: 0,
            ty: 0,
            rounded_clips: 0,
        }
    }

    /// The limits in force.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Whether a stream is open.
    pub fn is_open(&self) -> bool {
        self.at != Position::Closed
    }

    /// Whether a frame is in progress.
    pub fn in_frame(&self) -> bool {
        matches!(self.at, Position::Frame | Position::Band)
    }

    /// The open stream's description.
    pub fn stream(&self) -> Option<&Stream> {
        if self.is_open() {
            Some(&self.stream)
        } else {
            None
        }
    }

    /// The frame in progress: its damage.
    pub fn damage(&self) -> Option<PRect> {
        if self.in_frame() {
            Some(self.damage)
        } else {
            None
        }
    }

    /// The current translation, fx.
    pub fn translation(&self) -> (i32, i32) {
        (self.tx, self.ty)
    }

    /// Live resource `id`.
    pub fn resource(&self, id: u16) -> Option<&Resource> {
        self.resources
            .get(id as usize)
            .filter(|r| r.state != ResourceState::Free)
    }

    /// Bytes of live defined resources.
    pub fn resource_bytes(&self) -> u32 {
        self.live_bytes
    }

    /// The caller's verdict on a resource `admit` reported complete or
    /// referenced. `Some(glyphs)`: its bytes are the ones its digest names
    /// (and a strike parses), with `glyphs` entries in the strike drawn
    /// from, 0 for a pixmap. `None`: they are not, or the reference could
    /// not be resolved, which faults the stream.
    pub fn resolve(&mut self, id: u16, verdict: Option<u32>) -> Result<(), Fault> {
        let result = match (self.resources.get_mut(id as usize), verdict) {
            (Some(r), Some(glyphs)) if r.state == ResourceState::Unresolved => {
                r.state = ResourceState::Usable;
                r.glyphs = glyphs;
                Ok(())
            }
            _ => Err(Fault::ResourceUnusable),
        };
        if result.is_err() {
            self.at = Position::Closed;
        }
        result
    }

    /// Admit a record `parse` returned, with the bytes it occupied
    /// (`consumed`), or refuse it. A refusal closes the stream.
    pub fn admit(&mut self, record: &Record<'_>, consumed: usize) -> Result<Admitted, Fault> {
        let result = self.check(record, consumed);
        if result.is_err() {
            self.at = Position::Closed;
        }
        result
    }

    fn reset_state(&mut self) {
        self.depth = 0;
        self.tx = 0;
        self.ty = 0;
        self.rounded_clips = 0;
    }

    fn op(&self, bit: u16) -> Result<(), Fault> {
        if self.limits.ops & bit == 0 {
            return Err(Fault::NotAdmitted);
        }
        Ok(())
    }

    /// A paint-state or drawing record is in position.
    fn drawing(&mut self, consumed: usize) -> Result<(), Fault> {
        let want = if self.stream.band_rows == 0 {
            Position::Frame
        } else {
            Position::Band
        };
        if self.at != want {
            return Err(Fault::OutOfPosition);
        }
        self.count(consumed)
    }

    /// Count a frame record against what the consumer retains.
    fn count(&mut self, consumed: usize) -> Result<(), Fault> {
        let used = u64::from(self.frame_used) + consumed as u64;
        if self.limits.frame_bytes != 0 && used > u64::from(self.limits.frame_bytes) {
            return Err(Fault::FrameTooLarge);
        }
        self.frame_used = used.min(u64::from(u32::MAX)) as u32;
        Ok(())
    }

    /// `rect`, translated, stays inside i32 at both corners.
    fn placed(&self, r: &Rect) -> Result<(), Fault> {
        let x = fx_sum(i64::from(r.x), i64::from(self.tx))?;
        let y = fx_sum(i64::from(r.y), i64::from(self.ty))?;
        fx_sum(i64::from(x), i64::from(r.w))?;
        fx_sum(i64::from(y), i64::from(r.h))?;
        Ok(())
    }

    /// Live, usable resource `id`, marked as named by the frame.
    fn named(&mut self, id: u16) -> Result<Resource, Fault> {
        match self.resources.get_mut(id as usize) {
            Some(r) if r.state == ResourceState::Usable => {
                r.named = true;
                Ok(*r)
            }
            _ => Err(Fault::ResourceUnusable),
        }
    }

    /// A free slot for a definition or reference of `id`.
    fn free_slot(&mut self, id: u16) -> Result<&mut Resource, Fault> {
        if id >= self.stream.max_resources {
            return Err(Fault::ResourceLimit);
        }
        match self.resources.get_mut(id as usize) {
            Some(r) if r.state == ResourceState::Free => Ok(r),
            _ => Err(Fault::ResourceLimit),
        }
    }

    fn check(&mut self, record: &Record<'_>, consumed: usize) -> Result<Admitted, Fault> {
        if let Record::Stream(s) = record {
            let l = &self.limits;
            let unbanded_ok = l.frame_bytes != 0;
            let banded_ok = l.frame_bytes != 0 || s.band_rows <= l.band_rows;
            if s.width > l.max_width
                || s.height > l.max_height
                || s.max_depth > l.max_depth
                || s.max_resources > l.max_resources
                || s.resource_bytes > l.resource_bytes
                || s.band_rows == 0 && !unbanded_ok
                || s.band_rows != 0 && !banded_ok
            {
                return Err(Fault::StreamLimit);
            }
            self.resources.fill(Resource::FREE);
            self.live_bytes = 0;
            self.stream = *s;
            self.last_revision = None;
            self.reset_state();
            self.at = Position::Open;
            return Ok(Admitted::Stream);
        }
        if self.at == Position::Closed {
            return Err(Fault::OutOfPosition);
        }
        match record {
            Record::Stream(_) => {}
            Record::End => {
                if self.at != Position::Open {
                    return Err(Fault::OutOfPosition);
                }
                self.at = Position::Closed;
                return Ok(Admitted::End);
            }
            Record::ResDef(d) => {
                let formats = if d.kind == RES_PIXMAP {
                    self.limits.pixmap_formats
                } else {
                    self.limits.glyph_formats
                };
                if d.format >= 8 || formats & (1 << d.format) == 0 {
                    return Err(Fault::NotAdmitted);
                }
                let live = u64::from(self.live_bytes) + u64::from(d.total_len);
                if live > u64::from(self.stream.resource_bytes) {
                    return Err(Fault::ResourceLimit);
                }
                let slot = self.free_slot(d.id)?;
                *slot = Resource {
                    state: ResourceState::Filling,
                    kind: d.kind,
                    format: d.format,
                    width: d.width,
                    height: d.height,
                    total_len: d.total_len,
                    ..Resource::FREE
                };
                self.live_bytes = live as u32;
            }
            Record::ResData { id, offset, bytes } => {
                let Some(r) = self
                    .resources
                    .get_mut(*id as usize)
                    .filter(|r| r.state == ResourceState::Filling)
                else {
                    return Err(Fault::ResourceData);
                };
                let len = bytes.len() as u64;
                if u64::from(*offset) + len > u64::from(r.total_len)
                    || u64::from(r.received) + len > u64::from(r.total_len)
                {
                    return Err(Fault::ResourceData);
                }
                r.received += len as u32;
                if r.received == r.total_len {
                    r.state = ResourceState::Unresolved;
                    return Ok(Admitted::ResourceComplete { id: *id });
                }
            }
            Record::ResDrop { id } => match self.resources.get_mut(*id as usize) {
                Some(r) if r.state != ResourceState::Free && !r.dropped => r.dropped = true,
                _ => return Err(Fault::ResourceUnusable),
            },
            Record::ResRef(r) => {
                self.op(OP_RES_REF)?;
                if self.limits.glyph_formats & (1 << r.format) == 0 {
                    return Err(Fault::NotAdmitted);
                }
                let slot = self.free_slot(r.id)?;
                *slot = Resource {
                    state: ResourceState::Unresolved,
                    kind: r.kind,
                    format: r.format,
                    referenced: true,
                    selector: r.selector,
                    ..Resource::FREE
                };
                return Ok(Admitted::ResourceReferenced { id: r.id });
            }
            Record::Frame {
                generation,
                revision,
                damage,
            } => {
                if self.at != Position::Open {
                    return Err(Fault::OutOfPosition);
                }
                if *generation != self.stream.generation {
                    return Err(Fault::Generation);
                }
                if self.last_revision.is_some_and(|last| *revision <= last) {
                    return Err(Fault::Revision);
                }
                let s = &self.stream;
                if damage.w == 0
                    || damage.h == 0
                    || u32::from(damage.x) + u32::from(damage.w) > u32::from(s.width)
                    || u32::from(damage.y) + u32::from(damage.h) > u32::from(s.height)
                {
                    return Err(Fault::BadDamage);
                }
                if self.limits.damage_full && (damage.w != s.width || damage.h != s.height) {
                    return Err(Fault::PartialDamage);
                }
                for r in self.resources.iter_mut() {
                    r.named = false;
                }
                self.frame_revision = *revision;
                self.damage = *damage;
                self.band_floor = u32::from(damage.y);
                self.frame_used = 0;
                self.reset_state();
                self.at = Position::Frame;
                self.count(consumed)?;
            }
            Record::Band { y, rows } => {
                if self.stream.band_rows == 0 || !self.in_frame() {
                    return Err(Fault::OutOfPosition);
                }
                let end = u32::from(*y) + u32::from(*rows);
                if *rows == 0
                    || *rows > self.stream.band_rows
                    || u32::from(*y) < self.band_floor
                    || end > u32::from(self.damage.y) + u32::from(self.damage.h)
                {
                    return Err(Fault::BadBand);
                }
                self.band_floor = end;
                self.reset_state();
                self.at = Position::Band;
                self.count(consumed)?;
            }
            Record::Commit { revision } => {
                if !self.in_frame() {
                    return Err(Fault::OutOfPosition);
                }
                if *revision != self.frame_revision {
                    return Err(Fault::Revision);
                }
                self.count(consumed)?;
                for r in self.resources.iter_mut() {
                    if r.state != ResourceState::Free && r.dropped && !r.named {
                        if !r.referenced {
                            self.live_bytes -= r.total_len;
                        }
                        *r = Resource::FREE;
                    }
                }
                self.last_revision = Some(*revision);
                self.reset_state();
                self.at = Position::Open;
                return Ok(Admitted::Commit);
            }
            Record::Save => {
                self.drawing(consumed)?;
                if self.depth >= usize::from(self.stream.max_depth) {
                    return Err(Fault::StackOverflow);
                }
                self.stack[self.depth] = Saved {
                    tx: self.tx,
                    ty: self.ty,
                    rounded_clips: self.rounded_clips,
                };
                self.depth += 1;
            }
            Record::Restore => {
                self.drawing(consumed)?;
                if self.depth == 0 {
                    return Err(Fault::StackUnderflow);
                }
                self.depth -= 1;
                let s = self.stack[self.depth];
                self.tx = s.tx;
                self.ty = s.ty;
                self.rounded_clips = s.rounded_clips;
            }
            Record::ClipRect(rect) => {
                self.drawing(consumed)?;
                self.op(OP_CLIP_RECT)?;
                self.placed(rect)?;
            }
            Record::ClipRRect { rect, .. } => {
                self.drawing(consumed)?;
                self.op(OP_CLIP_RRECT)?;
                self.placed(rect)?;
                if self.rounded_clips >= self.stream.max_depth {
                    return Err(Fault::ClipOverflow);
                }
                self.rounded_clips += 1;
            }
            Record::Translate { dx, dy } => {
                self.drawing(consumed)?;
                self.op(OP_TRANSLATE)?;
                let tx = fx_sum(i64::from(self.tx), i64::from(*dx))?;
                let ty = fx_sum(i64::from(self.ty), i64::from(*dy))?;
                self.tx = tx;
                self.ty = ty;
            }
            Record::FillRect { rect, .. } => {
                self.drawing(consumed)?;
                self.op(OP_FILL_RECT)?;
                self.placed(rect)?;
            }
            Record::FillRRect { rect, .. } => {
                self.drawing(consumed)?;
                self.op(OP_FILL_RRECT)?;
                self.placed(rect)?;
            }
            Record::Border { rect, .. } => {
                self.drawing(consumed)?;
                self.op(OP_BORDER)?;
                self.placed(rect)?;
            }
            Record::Pixmap { id, src, dst, .. } => {
                self.drawing(consumed)?;
                self.op(OP_PIXMAP)?;
                self.placed(dst)?;
                let r = self.named(*id)?;
                if r.kind != RES_PIXMAP {
                    return Err(Fault::ResourceUnusable);
                }
                if u32::from(src.x) + u32::from(src.w) > u32::from(r.width)
                    || u32::from(src.y) + u32::from(src.h) > u32::from(r.height)
                {
                    return Err(Fault::PixmapSource);
                }
            }
            Record::Glyphs(g) => {
                self.drawing(consumed)?;
                self.op(OP_GLYPHS)?;
                let r = self.named(g.res)?;
                if r.kind == RES_PIXMAP {
                    return Err(Fault::ResourceUnusable);
                }
                let mut x = i64::from(fx_sum(i64::from(g.x), i64::from(self.tx))?);
                let y = i64::from(fx_sum(i64::from(g.y), i64::from(self.ty))?);
                for (glyph, dx, dy) in g.iter() {
                    if u32::from(glyph) >= r.glyphs {
                        return Err(Fault::GlyphIndex);
                    }
                    x = i64::from(fx_sum(x, i64::from(dx))?);
                    fx_sum(y, i64::from(dy))?;
                }
            }
            Record::Surface { input, dst, .. } => {
                self.drawing(consumed)?;
                self.op(OP_SURFACE)?;
                self.placed(dst)?;
                if *input >= self.limits.surfaces {
                    return Err(Fault::SurfaceInput);
                }
            }
        }
        Ok(Admitted::Record)
    }
}

/// The conformance vector file: one stream, what it draws with, and the
/// SHA-256 of what a conforming rasteriser produces from it.
///
/// ```text
///   [0..4]    magic     MAGIC
///   [4]       surfaces  u8   raster inputs that follow
///   [5]       blobs     u8   held byte strings that follow
///   [6..8]    0         u16
///   [8..12]   stream    u32  bytes of the draw stream
///   [12..44]  rgb565    the SHA-256 of the output as RGB565
///   [44..76]  rgba8     the SHA-256 of the output as RGBA8
///   then, per surface, one `video_raster` record: a whole-surface region
///   (its committed frame; input `i` is the `i`th)
///   then, per blob, [len u32][bytes]: what RES_REF digests resolve
///   against
///   then the stream
/// ```
///
/// The output is the whole surface after the stream's last COMMIT, drawn
/// from opaque black, rows top to bottom: RGB565 as little-endian `u16`s,
/// RGBA8 as bytes red, green, blue, alpha.
pub mod vector {
    use super::super::video_raster;

    /// The first four bytes of a vector file.
    pub const MAGIC: [u8; 4] = *b"VDV1";
    /// Bytes before the surfaces.
    pub const HEADER: usize = 76;

    pub const OFF_SURFACES: usize = 4;
    pub const OFF_BLOBS: usize = 5;
    pub const OFF_RESERVED: usize = 6;
    pub const OFF_STREAM_LEN: usize = 8;
    pub const OFF_RGB565: usize = 12;
    pub const OFF_RGBA8: usize = 44;

    /// A decoded vector, borrowing from the file's bytes.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Vector<'a> {
        pub surfaces: u8,
        pub blobs: u8,
        pub rgb565: [u8; 32],
        pub rgba8: [u8; 32],
        /// The draw stream.
        pub stream: &'a [u8],
        /// The surfaces, then the blobs.
        inputs: &'a [u8],
    }

    fn u32_at(b: &[u8], at: usize) -> Option<u32> {
        let s = b.get(at..at + 4)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// The length of the surface record at the front of `b`.
    fn surface_len(b: &[u8]) -> Option<usize> {
        let h = video_raster::Header::decode(b).ok()?;
        if h.x != 0 || h.y != 0 || h.w != h.surface_w || h.h != h.surface_h || !h.is_last() {
            return None;
        }
        usize::try_from(h.record_len()).ok()
    }

    impl<'a> Vector<'a> {
        /// Read a vector file. `None` unless every part is whole and the
        /// parts fill the file exactly.
        pub fn decode(file: &'a [u8]) -> Option<Vector<'a>> {
            if file.get(..4)? != MAGIC || file.get(OFF_RESERVED..OFF_RESERVED + 2)? != [0, 0] {
                return None;
            }
            let surfaces = *file.get(OFF_SURFACES)?;
            let blobs = *file.get(OFF_BLOBS)?;
            let stream_len = u32_at(file, OFF_STREAM_LEN)? as usize;
            let mut rgb565 = [0u8; 32];
            let mut rgba8 = [0u8; 32];
            rgb565.copy_from_slice(file.get(OFF_RGB565..OFF_RGB565 + 32)?);
            rgba8.copy_from_slice(file.get(OFF_RGBA8..OFF_RGBA8 + 32)?);
            let body = file.get(HEADER..)?;
            let mut at = 0usize;
            for _ in 0..surfaces {
                at = at.checked_add(surface_len(body.get(at..)?)?)?;
            }
            for _ in 0..blobs {
                let len = u32_at(body, at)? as usize;
                at = at.checked_add(4)?.checked_add(len)?;
            }
            let inputs = body.get(..at)?;
            let stream = body.get(at..)?;
            if stream.len() != stream_len {
                return None;
            }
            Some(Vector {
                surfaces,
                blobs,
                rgb565,
                rgba8,
                stream,
                inputs,
            })
        }

        /// Surface input `i`: its header and its pixels.
        pub fn surface(&self, i: u8) -> Option<(video_raster::Header, &'a [u8])> {
            if i >= self.surfaces {
                return None;
            }
            let mut at = 0usize;
            for _ in 0..i {
                at += surface_len(&self.inputs[at..])?;
            }
            let rest = &self.inputs[at..];
            let header = video_raster::Header::decode(rest).ok()?;
            let len = surface_len(rest)?;
            Some((header, &rest[video_raster::HEADER..len]))
        }

        /// Blob `i`.
        pub fn blob(&self, i: u8) -> Option<&'a [u8]> {
            if i >= self.blobs {
                return None;
            }
            let mut at = 0usize;
            for _ in 0..self.surfaces {
                at += surface_len(&self.inputs[at..])?;
            }
            for _ in 0..i {
                at += 4 + u32_at(self.inputs, at)? as usize;
            }
            let len = u32_at(self.inputs, at)? as usize;
            self.inputs.get(at + 4..at + 4 + len)
        }
    }

    /// Write a vector file's header. The caller appends each surface (a
    /// `video_raster` header from `Header::whole` and its pixels), each
    /// blob behind its `u32` length, and the stream. `None` when `out` is
    /// too small.
    pub fn write_header(
        out: &mut [u8],
        surfaces: u8,
        blobs: u8,
        stream_len: u32,
        rgb565: &[u8; 32],
        rgba8: &[u8; 32],
    ) -> Option<usize> {
        let out = out.get_mut(..HEADER)?;
        out[..4].copy_from_slice(&MAGIC);
        out[OFF_SURFACES] = surfaces;
        out[OFF_BLOBS] = blobs;
        out[OFF_RESERVED] = 0;
        out[OFF_RESERVED + 1] = 0;
        out[OFF_STREAM_LEN..OFF_STREAM_LEN + 4].copy_from_slice(&stream_len.to_le_bytes());
        out[OFF_RGB565..OFF_RGB565 + 32].copy_from_slice(rgb565);
        out[OFF_RGBA8..OFF_RGBA8 + 32].copy_from_slice(rgba8);
        Some(HEADER)
    }

    const _: () = assert!(OFF_SURFACES == 4);
    const _: () = assert!(OFF_SURFACES + 1 == OFF_BLOBS);
    const _: () = assert!(OFF_BLOBS + 1 == OFF_RESERVED);
    const _: () = assert!(OFF_RESERVED + 2 == OFF_STREAM_LEN);
    const _: () = assert!(OFF_STREAM_LEN + 4 == OFF_RGB565);
    const _: () = assert!(OFF_RGB565 + 32 == OFF_RGBA8);
    const _: () = assert!(OFF_RGBA8 + 32 == HEADER);
}

// Every fixed length is the sum of its fields, and every offset follows the
// field before it.
const _: () = assert!(off::STREAM_WIDTH == 0);
const _: () = assert!(off::STREAM_WIDTH + 2 == off::STREAM_HEIGHT);
const _: () = assert!(off::STREAM_HEIGHT + 2 == off::STREAM_BAND_ROWS);
const _: () = assert!(off::STREAM_BAND_ROWS + 2 == off::STREAM_MAX_DEPTH);
const _: () = assert!(off::STREAM_MAX_DEPTH + 1 == off::STREAM_RESERVED);
const _: () = assert!(off::STREAM_RESERVED + 1 == off::STREAM_MAX_RESOURCES);
const _: () = assert!(off::STREAM_MAX_RESOURCES + 2 == off::STREAM_RESOURCE_BYTES);
const _: () = assert!(off::STREAM_RESOURCE_BYTES + 4 == off::STREAM_GENERATION);
const _: () = assert!(off::STREAM_GENERATION + 4 == STREAM_LEN);
const _: () = assert!(off::RES_ID == 0);
const _: () = assert!(off::RES_ID + 2 == off::RES_KIND);
const _: () = assert!(off::RES_KIND + 1 == off::RES_FORMAT);
const _: () = assert!(off::RES_FORMAT + 1 == off::RES_TOTAL_LEN);
const _: () = assert!(off::RES_TOTAL_LEN == off::RES_SELECTOR);
const _: () = assert!(off::RES_TOTAL_LEN + 4 == off::RES_DIGEST);
const _: () = assert!(off::RES_DIGEST + 32 == RES_DEF_FIXED);
const _: () = assert!(off::RES_DIGEST + 32 == RES_REF_LEN);
const _: () = assert!(off::RES_PIXMAP_WIDTH == RES_DEF_FIXED);
const _: () = assert!(off::RES_PIXMAP_WIDTH + 2 == off::RES_PIXMAP_HEIGHT);
const _: () = assert!(off::RES_PIXMAP_HEIGHT + 2 == RES_DEF_PIXMAP_LEN);
const _: () = assert!(off::RES_ID + 2 == RES_DROP_LEN);
const _: () = assert!(off::RES_DATA_ID == 0);
const _: () = assert!(off::RES_DATA_ID + 2 == off::RES_DATA_OFFSET);
const _: () = assert!(off::RES_DATA_OFFSET + 4 == off::RES_DATA_BYTES);
const _: () = assert!(off::RES_DATA_BYTES == RES_DATA_FIXED);
const _: () = assert!(off::FRAME_GENERATION == 0);
const _: () = assert!(off::FRAME_GENERATION + 4 == off::FRAME_REVISION);
const _: () = assert!(off::FRAME_REVISION + 4 == off::FRAME_DAMAGE);
const _: () = assert!(off::FRAME_DAMAGE + 8 == FRAME_LEN);
const _: () = assert!(off::BAND_Y == 0);
const _: () = assert!(off::BAND_Y + 2 == off::BAND_ROWS);
const _: () = assert!(off::BAND_ROWS + 2 == BAND_LEN);
const _: () = assert!(off::RECT == 0);
const _: () = assert!(off::RECT + 16 == CLIP_RECT_LEN);
const _: () = assert!(off::RECT + 16 == off::RADII);
const _: () = assert!(off::RADII + 32 == CLIP_RRECT_LEN);
const _: () = assert!(off::RECT + 16 == off::FILL_RECT_COLOUR);
const _: () = assert!(off::FILL_RECT_COLOUR + 4 == FILL_RECT_LEN);
const _: () = assert!(off::RADII + 32 == off::FILL_RRECT_COLOUR);
const _: () = assert!(off::FILL_RRECT_COLOUR + 4 == FILL_RRECT_LEN);
const _: () = assert!(off::RADII + 32 == off::BORDER_WIDTHS);
const _: () = assert!(off::BORDER_WIDTHS + 16 == off::BORDER_COLOURS);
const _: () = assert!(off::BORDER_COLOURS + 16 == BORDER_LEN);
const _: () = assert!(off::PIXMAP_ID == 0);
const _: () = assert!(off::PIXMAP_ID + 2 == off::PIXMAP_FILTER);
const _: () = assert!(off::PIXMAP_FILTER + 1 == off::PIXMAP_RESERVED);
const _: () = assert!(off::PIXMAP_RESERVED + 1 == off::PIXMAP_SRC);
const _: () = assert!(off::PIXMAP_SRC + 8 == off::PIXMAP_DST);
const _: () = assert!(off::PIXMAP_DST + 16 == PIXMAP_LEN);
const _: () = assert!(off::GLYPHS_RES == 0);
const _: () = assert!(off::GLYPHS_RES + 2 == off::GLYPHS_COUNT);
const _: () = assert!(off::GLYPHS_COUNT + 2 == off::GLYPHS_COLOUR);
const _: () = assert!(off::GLYPHS_COLOUR + 4 == off::GLYPHS_X);
const _: () = assert!(off::GLYPHS_X + 4 == off::GLYPHS_Y);
const _: () = assert!(off::GLYPHS_Y + 4 == off::GLYPHS_ENTRIES);
const _: () = assert!(off::GLYPHS_ENTRIES == GLYPHS_FIXED);
const _: () = assert!(off::SURFACE_INPUT == 0);
const _: () = assert!(off::SURFACE_INPUT + 1 == off::SURFACE_FILTER);
const _: () = assert!(off::SURFACE_FILTER + 1 == off::SURFACE_RESERVED);
const _: () = assert!(off::SURFACE_RESERVED + 2 == off::SURFACE_SRC);
const _: () = assert!(off::SURFACE_SRC + 8 == off::SURFACE_DST);
const _: () = assert!(off::SURFACE_DST + 16 == SURFACE_LEN);
const _: () = assert!(TRANSLATE_LEN == 8 && COMMIT_LEN == 4);
const _: () = assert!(GLYPHS_FIXED + GLYPHS_MAX * GLYPH_ENTRY <= u16::MAX as usize);
const _: () = assert!(GLYPH_FORMAT_COUNT <= 8 && PIXMAP_FORMAT_COUNT <= 8);
