//! OTA RAM staging surface — the Pi 5 / hosted-Linux counterpart of the
//! RP flash graph-slot A/B path.
//!
//! A module (normally `ota_registry`) streams a GRAPH IMAGE (`fluxor
//! build --emit=image`: FXSL header + modules blob + config blob) into
//! the inactive one of two RAM staging buffers via `OTA_STAGE_WRITE`,
//! then commits it with `OTA_STAGE_CTRL`. Commit validates the image —
//! header shape, SHA-256 over the payload, ABI-surface pin against the
//! running kernel, epoch monotonicity — flips the region executable
//! (cache maintenance / page permissions via `hal::ota_stage_protect`),
//! re-points the static loader + config at the staged blobs
//! (`populate_static_state_with_len`, the same population boot uses)
//! and requests a graph rebuild through the proven rebuild bridge.
//!
//! Two buffers alternate (A/B in RAM): after a commit the staged buffer
//! IS the live modules region, so the next update stages into the other
//! one. Everything runs on the scheduler thread (provider-call context
//! and rebuild consumption are the same thread), so the statics need no
//! synchronization — the same discipline as the scheduler's own state.
//!
//! Failure posture mirrors the rebuild bridge: a validation failure
//! leaves the running graph untouched; a populate/rebuild failure
//! leaves the graph idle (fail-safe), recoverable by power cycle into
//! the netboot image.

use crate::kernel::exec::scheduler;
use crate::kernel::sys::errno;
use crate::kernel::sys::hal;

/// Staging capacity per buffer. Mirrors the loader's
/// `MAX_MODULES_BLOB_SIZE` reasoning (loader.rs): comfortably above any
/// realistic graph bundle.
pub const STAGE_CAPACITY: usize = 8 * 1024 * 1024;

// FXSL graph-image header layout. Format-pinned to the header the
// pack tool emits (`fluxor build --emit=image`, tools/src/cli/
// commands_a.rs::cmd_graph_image) and the RP boot slot selector reads
// (`modules/sdk/platform/rp/flash_layout.rs` — an RP flash A/B slot
// holds exactly this image format; "FXSL" is a fixed on-disk constant
// and its mnemonic does not describe the format). The constants are
// restated here because this surface
// compiles on targets that do not mount the RP platform tables.
const IMAGE_MAGIC: u32 = 0x4C53_5846; // "FXSL"
const IMAGE_VERSION: u8 = 1;
const IMAGE_HEADER_SIZE: usize = 256;
const IMAGE_ABI_SURFACE_OFFSET: usize = 64;

/// Page-aligned staging buffer. 16 KiB covers the largest page size a
/// hosted kernel uses (Raspberry Pi OS aarch64 runs 16 KiB pages, and
/// `mprotect` demands page-aligned addresses); bare-metal targets need
/// only cache-line alignment, which this satisfies trivially.
#[repr(C, align(16384))]
struct StageBuf {
    bytes: [u8; STAGE_CAPACITY],
}

static mut STAGE_A: StageBuf = StageBuf {
    bytes: [0; STAGE_CAPACITY],
};
static mut STAGE_B: StageBuf = StageBuf {
    bytes: [0; STAGE_CAPACITY],
};

/// Which buffer holds the LIVE (committed) image: 0 = A, 1 = B,
/// 0xFF = none (booted from the platform's own image; both free).
static mut LIVE_BUF: u8 = 0xFF;
/// Bytes staged so far into the inactive buffer.
static mut STAGED_LEN: usize = 0;
/// Epoch of the live committed image (0 = the boot image; a staged
/// image's epoch must exceed it).
static mut LIVE_EPOCH: u64 = 0;

fn staging_buf() -> &'static mut StageBuf {
    // SAFETY: scheduler-thread access (provider-call context); the
    // inactive buffer is never read by running code.
    unsafe {
        let live = LIVE_BUF;
        if live == 0 {
            let p = &raw mut STAGE_B;
            &mut *p
        } else {
            let p = &raw mut STAGE_A;
            &mut *p
        }
    }
}

/// `OTA_STAGE_WRITE`: append `data` at `offset` into the staging buffer.
/// `offset == 0` begins a fresh stage (unlocks the region for writing);
/// writes advance monotonically — an offset below the staged length is
/// refused (a dropped chunk is caught immediately), and a forward gap
/// is zero-filled (layered-pull alignment padding).
pub fn stage_write(offset: usize, data: &[u8]) -> i32 {
    let buf = staging_buf();
    // SAFETY: scheduler-thread statics, single writer.
    unsafe {
        if offset == 0 {
            if !hal::ota_stage_protect(buf.bytes.as_mut_ptr(), STAGE_CAPACITY, false) {
                return errno::ENOSYS; // no staging surface on this target
            }
            STAGED_LEN = 0;
        }
        // A layered pull places blobs at publisher-annotated offsets;
        // the deterministic alignment gaps between layers are
        // zero-filled here (matching the pack tool's zero padding, so
        // the reassembled image is byte-exact over the hashed
        // regions). Rewinds other than a full restart stay refused.
        if offset < STAGED_LEN {
            return errno::EINVAL;
        }
        if offset + data.len() > STAGE_CAPACITY {
            return errno::ENOSPC;
        }
        if offset > STAGED_LEN {
            buf.bytes[STAGED_LEN..offset].fill(0);
        }
        buf.bytes[offset..offset + data.len()].copy_from_slice(data);
        STAGED_LEN = offset + data.len();
    }
    0
}

/// `OTA_STAGE_CTRL` command byte.
pub const CTRL_COMMIT: u8 = 0;
pub const CTRL_ABORT: u8 = 1;
pub const CTRL_EPOCH: u8 = 2;

/// `OTA_STAGE_CTRL`: commit / abort the staged image, or query the live
/// epoch (returned as a non-negative i32, saturated).
pub fn stage_ctrl(cmd: u8) -> i32 {
    match cmd {
        CTRL_COMMIT => commit(),
        CTRL_ABORT => {
            // SAFETY: scheduler-thread static.
            unsafe { STAGED_LEN = 0 };
            0
        }
        CTRL_EPOCH => {
            // SAFETY: scheduler-thread static.
            let e = unsafe { LIVE_EPOCH };
            e.min(i32::MAX as u64) as i32
        }
        _ => errno::EINVAL,
    }
}

fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn read_u64(b: &[u8], off: usize) -> u64 {
    let lo = read_u32(b, off) as u64;
    let hi = read_u32(b, off + 4) as u64;
    lo | (hi << 32)
}

fn commit() -> i32 {
    let buf = staging_buf();
    // SAFETY: scheduler-thread statics; validation reads the staged
    // bytes this thread wrote.
    let staged_len = unsafe { STAGED_LEN };
    if staged_len < IMAGE_HEADER_SIZE {
        return errno::EINVAL;
    }
    let image = &buf.bytes[..staged_len];

    // Header shape.
    if read_u32(image, 0) != IMAGE_MAGIC || image[4] != IMAGE_VERSION {
        log::error!("[ota] commit: bad image magic/version");
        return errno::EINVAL;
    }
    let epoch = read_u64(image, 8);
    let modules_offset = read_u32(image, 16) as usize;
    let modules_size = read_u32(image, 20) as usize;
    let config_offset = read_u32(image, 24) as usize;
    let config_size = read_u32(image, 28) as usize;
    // The smallest real module table is its 16-byte header; region
    // bounds are checked against what was actually staged.
    if modules_size < 16
        || config_size == 0
        || modules_offset < IMAGE_HEADER_SIZE
        || modules_offset.saturating_add(modules_size) > staged_len
        || config_offset < modules_offset + modules_size
        || config_offset.saturating_add(config_size) > staged_len
    {
        log::error!("[ota] commit: image regions out of bounds");
        return errno::EINVAL;
    }

    // Payload integrity: SHA-256 over modules ++ config, as the pack
    // tool computed it.
    let mut h = crate::kernel::security::crypto::sha256::Sha256::new();
    h.update(&image[modules_offset..modules_offset + modules_size]);
    h.update(&image[config_offset..config_offset + config_size]);
    let digest = h.finalize();
    if digest[..] != image[32..64] {
        log::error!("[ota] commit: payload sha256 mismatch");
        return errno::EINVAL;
    }

    // ABI-surface pin: strict equality with the running kernel's own
    // surface digest — an incompatible graph is refused, not loaded.
    let own = kernel_abi_surface_digest();
    if image[IMAGE_ABI_SURFACE_OFFSET..IMAGE_ABI_SURFACE_OFFSET + 32] != own[..] {
        log::error!(
            "[ota] commit: ABI-surface pin mismatch (rebuild the image against this kernel)"
        );
        return errno::EACCES;
    }

    // Epoch monotonicity: a replayed or stale image is refused.
    // SAFETY: scheduler-thread static.
    let live_epoch = unsafe { LIVE_EPOCH };
    if epoch <= live_epoch {
        log::warn!("[ota] commit: epoch {epoch} <= live {live_epoch}; refused");
        return errno::EBUSY;
    }

    // Make the staged region executable (cache maintenance / RX flip).
    if !hal::ota_stage_protect(buf.bytes.as_mut_ptr(), staged_len, true) {
        log::error!("[ota] commit: stage protect failed");
        return errno::ERROR;
    }

    // Re-point loader + config at the staged blobs — the exact
    // population boot performs — then fire the rebuild bridge. From
    // here failure leaves the graph idle (the rebuild bridge's
    // documented fail-safe posture).
    let modules_ptr = buf.bytes[modules_offset..].as_ptr();
    let config_blob = &buf.bytes[config_offset..config_offset + config_size];
    // SAFETY: single-threaded scheduler context; the staged region is
    // stable for the life of the committed generation (the buffers
    // alternate, so the next stage targets the other buffer).
    let populated = unsafe {
        scheduler::populate_static_state_with_len(config_blob, modules_ptr, modules_size)
    };
    if let Err(e) = populated {
        log::error!("[ota] commit: populate failed: {e}");
        return errno::EINVAL;
    }
    // SAFETY: null/0 = "reload current STATIC_CONFIG", which populate
    // just swapped to the staged config.
    unsafe { scheduler::request_rebuild(core::ptr::null(), 0) };

    // SAFETY: scheduler-thread statics.
    unsafe {
        LIVE_EPOCH = epoch;
        LIVE_BUF = if LIVE_BUF == 0 { 1 } else { 0 };
        STAGED_LEN = 0;
    }
    log::warn!("[ota] committed image epoch {epoch} ({staged_len} bytes); rebuild requested");
    0
}

/// The running kernel's own ABI-surface digest — sha256 over the
/// canonical `abi_surface` stream (the same computation the RP slot
/// selector uses at boot).
fn kernel_abi_surface_digest() -> [u8; 32] {
    let mut h = crate::kernel::security::crypto::sha256::Sha256::new();
    crate::abi::abi_surface::write_surface(&mut |bytes| h.update(bytes));
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}
