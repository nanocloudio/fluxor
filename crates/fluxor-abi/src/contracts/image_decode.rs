// Contract: image_decode — decode an encoded image held in a store to raw
// pixels at a size the caller names.
//
// Layer: contracts (public, stable).
//
// The source is a byte range of a `storage.object` object, named by its key:
// an image file, or an image embedded at a known offset in another object
// (cover art inside a media file, box art inside a package). The provider
// reads exactly that range with its own reach into the object store and
// decodes it, so the encoded bytes never pass through the caller and a caller
// needs no decoder and no room for the encoded image. A caller holding this
// contract therefore sees, as pixels, any object the provider can read.
//
// One decode is one job: `DECODE` opens it and mints its handle, `RECV`
// drains the pixels, `CLOSE` releases it. The decode runs behind the call:
// `RECV` answers `EAGAIN` until the pixels exist.
//
// A consumer that names its decoder reaches it through a handle bound to it
// (`kernel_abi::bind`, `NAME`); `DECODE` takes that bound handle in place of
// `handle = -1`, and the job handle it mints is routed to the same provider.
//
// Every op is one flat `arg` record and at most one bulk `data` span; no
// field is an address. Little-endian, tightly packed.

use super::storage::handle::STORAGE_KEY_MAX;

/// Contract id and opcode class.
pub const CLASS: u16 = super::super::registry::image_decode::ID;

/// Open a decode job. `handle = -1` (or a bound handle); `arg` in, one
/// [`decode`] record:
///
/// ```text
///   [key_len: u16][key: key_len bytes]   — the storage.object key
///   [offset: u64]                        — first byte of the encoded image
///   [length: u32]                        — its length in bytes
///   [width: u16][height: u16]            — the output size, in pixels
///   [format: u8]                         — the output pixel format (`format`)
/// ```
///
/// The image is scaled to exactly `width` x `height` (its aspect is not
/// kept). Returns the job handle, `EINVAL` for a malformed record, `ENOTSUP`
/// for a format the provider does not produce, `ENOMEM` when it holds no
/// room for another job, or `ENODEV` when it cannot start the decode.
pub use super::super::registry::image_decode::DECODE;

/// Drain decoded pixels. `handle` = the job; no `arg`; `data` out receives
/// the next pixels in row order, top-left first, `width * height *
/// format::bytes_per_pixel(format)` bytes in all ([`pixels_len`]).
///
/// Returns the bytes written, `EAGAIN` while the decode is still running,
/// 0 once every pixel has been delivered, `EIO` when the decode failed (the
/// source is missing, short, or not an image the provider reads), or
/// `EINVAL` for a handle that names no job or an empty `data`.
pub use super::super::registry::image_decode::RECV;

/// Release a job, running or finished. `handle` = the job; no `arg`.
pub use super::super::registry::image_decode::CLOSE;

/// Output pixel formats.
pub mod format {
    /// 16-bit RGB 5-6-5, little-endian per pixel.
    pub const RGB565: u8 = 1;

    /// Bytes one pixel of `format` takes; `None` for an unknown format.
    pub const fn bytes_per_pixel(format: u8) -> Option<usize> {
        match format {
            RGB565 => Some(2),
            _ => None,
        }
    }
}

/// The bytes a decoded `width` x `height` image of `format` takes; `None`
/// for an unknown format.
pub const fn pixels_len(width: u16, height: u16, format: u8) -> Option<usize> {
    match format::bytes_per_pixel(format) {
        Some(bpp) => Some(width as usize * height as usize * bpp),
        None => None,
    }
}

/// The [`DECODE`] record codec. No `std`, no allocation.
pub mod decode {
    use super::STORAGE_KEY_MAX;

    /// Record bytes besides the key: `key_len`, `offset`, `length`, `width`,
    /// `height`, `format`.
    pub const FIXED_LEN: usize = 2 + 8 + 4 + 2 + 2 + 1;

    /// The `arg` a request for a key of `key_len` bytes takes.
    pub const fn arg_len(key_len: usize) -> usize {
        FIXED_LEN + key_len
    }

    /// The longest `arg`: a key at the storage bound.
    pub const ARG_MAX: usize = arg_len(STORAGE_KEY_MAX);

    /// One decode request.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Request<'a> {
        pub key: &'a [u8],
        pub offset: u64,
        pub length: u32,
        pub width: u16,
        pub height: u16,
        pub format: u8,
    }

    /// Write `req` at the head of `out`; the bytes written, or `None` when
    /// `out` is too short or the key is empty or past [`STORAGE_KEY_MAX`].
    pub fn encode(out: &mut [u8], req: &Request<'_>) -> Option<usize> {
        let kl = req.key.len();
        if kl == 0 || kl > STORAGE_KEY_MAX {
            return None;
        }
        let n = arg_len(kl);
        let out = out.get_mut(..n)?;
        out[..2].copy_from_slice(&(kl as u16).to_le_bytes());
        out[2..2 + kl].copy_from_slice(req.key);
        let t = &mut out[2 + kl..];
        t[..8].copy_from_slice(&req.offset.to_le_bytes());
        t[8..12].copy_from_slice(&req.length.to_le_bytes());
        t[12..14].copy_from_slice(&req.width.to_le_bytes());
        t[14..16].copy_from_slice(&req.height.to_le_bytes());
        t[16] = req.format;
        Some(n)
    }

    /// The request `arg` holds; `None` unless it is exactly one record with
    /// a key of 1..=[`STORAGE_KEY_MAX`] bytes, a non-empty range that does
    /// not wrap, and a non-empty output size. The format is not judged here:
    /// a provider refuses one it does not produce.
    pub fn parse(arg: &[u8]) -> Option<Request<'_>> {
        let kl = u16::from_le_bytes([*arg.first()?, *arg.get(1)?]) as usize;
        if kl == 0 || kl > STORAGE_KEY_MAX || arg.len() != arg_len(kl) {
            return None;
        }
        let key = &arg[2..2 + kl];
        let t = &arg[2 + kl..];
        let offset = u64::from_le_bytes([t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]]);
        let length = u32::from_le_bytes([t[8], t[9], t[10], t[11]]);
        let width = u16::from_le_bytes([t[12], t[13]]);
        let height = u16::from_le_bytes([t[14], t[15]]);
        let format = t[16];
        if length == 0 || offset.checked_add(u64::from(length)).is_none() {
            return None;
        }
        if width == 0 || height == 0 {
            return None;
        }
        Some(Request {
            key,
            offset,
            length,
            width,
            height,
            format,
        })
    }
}
