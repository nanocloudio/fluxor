//! `SEAL_KEY_DERIVE`: a module's own sealing key, derived from the
//! platform's (`hal::seal_key`) by HKDF-SHA256 with salt `fluxor/seal` and
//! info = the caller's module type hash ‖ a context it names
//! (`fluxor_sdk::crypto::seal::derive`). The platform key never leaves the
//! kernel; a module gets a key only its own type can derive again. The
//! `seal_key` grant is checked by the gateway before this runs.

use crate::abi::errno::{EINVAL, ENOSYS};
use crate::abi::kernel_abi::seal::{KEY_LEN, MAX_CTX, OUT_LEN};
use crate::kernel::sys::hal::{self, SealProvenance};

/// The wire byte of a provenance (`kernel_abi::seal::provenance`).
pub fn provenance_byte(p: SealProvenance) -> u8 {
    use crate::abi::kernel_abi::seal::provenance;
    match p {
        SealProvenance::None => provenance::NONE,
        SealProvenance::HostReadable => provenance::HOST_READABLE,
        SealProvenance::DeviceUnique => provenance::DEVICE_UNIQUE,
    }
}

/// Serve `SEAL_KEY_DERIVE` for a module of type `module_type`: `arg` =
/// `[ctx_len u8][ctx]` in, `[provenance u8][key 32]` out. Returns
/// [`OUT_LEN`], `EINVAL` for a malformed argument, `ENOSYS` when the
/// platform has no sealing key.
pub fn derive_for(module_type: u32, arg: &mut [u8]) -> i32 {
    let Some(&ctx_len) = arg.first() else {
        return EINVAL;
    };
    let ctx_len = usize::from(ctx_len);
    if ctx_len > MAX_CTX || arg.len() < OUT_LEN || arg.len() < 1 + ctx_len {
        return EINVAL;
    }
    let Some(mut platform) = hal::seal_key() else {
        return ENOSYS;
    };
    let mut ctx = [0u8; MAX_CTX];
    ctx[..ctx_len].copy_from_slice(&arg[1..1 + ctx_len]);
    let derived = fluxor_sdk::crypto::seal::derive(&platform, module_type, &ctx[..ctx_len]);
    fluxor_sdk::crypto::zeroize::zeroize(&mut platform);
    let Some(mut key) = derived else {
        return EINVAL;
    };
    arg[0] = provenance_byte(hal::seal_provenance());
    arg[1..1 + KEY_LEN].copy_from_slice(&key);
    fluxor_sdk::crypto::zeroize::zeroize(&mut key);
    OUT_LEN as i32
}
