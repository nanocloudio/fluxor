//! OTA RAM staging surface — the Pi 5 / hosted-Linux counterpart of the
//! RP flash graph-slot A/B path.
//!
//! A module (normally `ota_registry`) streams a NODE IMAGE (`fluxor
//! build --emit=node`: the `wire::node_image` header, the module table
//! and the config) into the inactive one of two RAM staging buffers via
//! `OTA_STAGE_WRITE`, then commits it with `OTA_STAGE_CTRL`. Commit admits
//! the image as boot admits one (`boot::node_image::admit`: header shape,
//! ABI-surface pin, on a kernel image with a signing root its signature,
//! SHA-256 over the payload) and requires an epoch above the live one — flips
//! the region executable (cache maintenance / page permissions via
//! `hal::ota_stage_protect`), re-points the static loader + config at the
//! staged blobs (`populate_static_state_with_len`, the same population
//! boot uses) and requests a graph rebuild through the rebuild bridge.
//!
//! The live epoch is RAM state that starts at 0 each boot: an image must
//! beat the last one committed since boot, so refusing an older epoch holds
//! within a boot, not across one.
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
/// realistic node image.
pub const STAGE_CAPACITY: usize = 8 * 1024 * 1024;

/// Page-aligned staging buffer. 64 KiB is the largest page an aarch64 Linux
/// kernel uses (`mprotect` works on whole pages, and the buffer's capacity
/// is a multiple of it, so a protection change never reaches past the
/// buffer); bare-metal targets need only cache-line alignment, which this
/// satisfies trivially.
#[repr(C, align(65536))]
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
/// Epoch of the live committed image (0 = the firmware image; a staged
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
            if !hal::ota_stage_protect(&mut buf.bytes, false) {
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

fn commit() -> i32 {
    let buf = staging_buf();
    // SAFETY: scheduler-thread statics; validation reads the staged
    // bytes this thread wrote.
    let staged_len = unsafe { STAGED_LEN };
    let image = &buf.bytes[..staged_len];
    let own = crate::kernel::boot::node_image::own_abi_pin();
    let header = match crate::kernel::boot::node_image::admit(image, &own) {
        Ok(header) => header,
        Err(why) => {
            use crate::kernel::boot::node_image::Refusal;
            log::error!("[ota] commit: image refused: {}", why.reason());
            return match why {
                Refusal::Pin | Refusal::Signature(_) => errno::EACCES,
                Refusal::Malformed(_) | Refusal::Digest => errno::EINVAL,
            };
        }
    };
    let epoch = header.epoch;
    let modules_offset = header.modules_offset as usize;
    let modules_size = header.modules_size as usize;
    let config_offset = header.config_offset as usize;
    let config_size = header.config_size as usize;

    // Epoch monotonicity: a replayed or stale image is refused.
    // SAFETY: scheduler-thread static.
    let live_epoch = unsafe { LIVE_EPOCH };
    if epoch <= live_epoch {
        log::warn!("[ota] commit: epoch {epoch} <= live {live_epoch}; refused");
        return errno::EBUSY;
    }

    // Make the staged region executable (cache maintenance / RX flip).
    if !hal::ota_stage_protect(&mut buf.bytes[..staged_len], true) {
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
    // The rebuild reloads STATIC_CONFIG, which populate just swapped to the
    // staged config.
    scheduler::request_rebuild();

    // SAFETY: scheduler-thread statics.
    unsafe {
        LIVE_EPOCH = epoch;
        LIVE_BUF = if LIVE_BUF == 0 { 1 } else { 0 };
        STAGED_LEN = 0;
    }
    log::warn!("[ota] committed image epoch {epoch} ({staged_len} bytes); rebuild requested");
    0
}
