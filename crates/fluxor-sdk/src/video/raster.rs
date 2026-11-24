//! The reference rasteriser of the `VideoDraw` contract
//! (`fluxor_abi::contracts::video_draw`): the code whose output defines what
//! a draw list looks like. Any other rasteriser conforms by producing the
//! same bytes for the conformance vectors.
//!
//! A consumer links what it needs:
//!
//! - `Ingest` reads the stream: it admits every record through the
//!   contract's `Sequence`, files resource bytes in a `Store` (computing
//!   the SHA-256 that makes a resource usable) and retains the last
//!   committed frame's records.
//! - `replay` draws a retained frame into a `Band`, a few rows at a time,
//!   through a `Painter` that holds the paint state, visiting only the
//!   records the frame's `Index` says reach those rows. A band is 8-bit red,
//!   green and blue; `Band::row_rgb565` and `Band::row_rgba8` convert a
//!   finished row to an output format.
//! - `Input` holds one raster input a SURFACE record places: the regions
//!   of a `VideoRaster` stream read into the consumer's two buffers.
//! - `BandCache` keeps finished RGB565 bands of a picture shown for many
//!   refreshes, encoded as runs and literals, and writes them back byte for
//!   byte.
//! - `coverage::corner` and `coverage::join` are the contract's reference
//!   functions for rounded corners and border joins.
//!
//! Compositing is source-over onto an opaque destination in 8-bit
//! sRGB-encoded colour with exact integer rounding (`round`). The same
//! stream gives the same bytes on every target: all arithmetic is integer,
//! of explicit width, and no input can make it overflow or panic.
//! Nothing here allocates; every table is the caller's.

#![deny(clippy::float_arithmetic)]

pub mod band;
pub mod band_cache;
pub mod coverage;
pub mod ingest;
pub mod input;
pub mod paint;
pub mod replay;
pub mod resources;
pub mod round;
pub mod source;

/// Move `len` bytes of `buf` from `from` down to `to` (`to <= from`).
/// Nothing moves when either range leaves the buffer.
fn shift_down(buf: &mut [u8], from: usize, len: usize, to: usize) {
    let fits = from.checked_add(len).is_some_and(|end| end <= buf.len());
    if !fits || to > from || to == from || len == 0 {
        return;
    }
    // SAFETY: both ranges lie inside `buf` (`to <= from` and `from + len`
    // is within it); `copy` allows them to overlap.
    unsafe {
        let base = buf.as_mut_ptr();
        core::ptr::copy(base.add(from), base.add(to), len);
    }
}

pub use band::{Band, BAND_BPP};
pub use band_cache::BandCache;
pub use coverage::Shape;
pub use ingest::{fault_text, Event, Ingest};
pub use input::Input;
pub use paint::{Painter, Saved};
pub use replay::{intersect, replay, surface_reach, Entry, Index};
pub use resources::{Held, Slot, Store};
pub use source::{NoSurfaces, Resources, Strike, Surfaces, TexelFormat, Texels};
