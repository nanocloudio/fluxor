//! The sealing-key derivation `SEAL_KEY_DERIVE` answers with
//! (`kernel_abi::seal`): HKDF-SHA256 with salt `fluxor/seal` over the
//! platform's sealing key, info = the caller's module type hash (u32 LE)
//! then a context the caller names. The kernel serves it and the tools that
//! provision sealed records off the device call it, one function for both.

use crate::crypto::sha256::Sha256;
use crate::crypto::zeroize::zeroize;
use fluxor_abi::kernel_abi::seal::{info, KEY_LEN, MAX_CTX, SALT};

/// The key `module_type` derives for `ctx` from `platform_key`; `None` when
/// `ctx` is longer than `MAX_CTX`.
pub fn derive(platform_key: &[u8; KEY_LEN], module_type: u32, ctx: &[u8]) -> Option<[u8; KEY_LEN]> {
    let mut inf = [0u8; 4 + MAX_CTX];
    let n = info(module_type, ctx, &mut inf)?;
    Some(hkdf32(&SALT, platform_key, &inf[..n]))
}

/// HMAC-SHA256 over the concatenation of `parts`. SHA-256 alone and no
/// message buffer: the kernel serves the derivation on whichever core the
/// caller runs, inside that core's small stack reserve.
fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut pad = [0x36u8; 64];
    for (p, k) in pad.iter_mut().zip(key) {
        *p ^= k;
    }
    let mut inner = Sha256::new();
    inner.update(&pad);
    for part in parts {
        inner.update(part);
    }
    let mut ih = inner.finalize();
    for p in &mut pad {
        *p ^= 0x36 ^ 0x5c;
    }
    let mut outer = Sha256::new();
    outer.update(&pad);
    outer.update(&ih);
    zeroize(&mut pad);
    zeroize(&mut ih);
    outer.finalize()
}

/// RFC 5869 HKDF-SHA256 for one 32-byte output block; `salt` at most 32
/// bytes (zero-padded to the key, as HMAC does for a short key).
fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..salt.len()].copy_from_slice(salt);
    let mut prk = hmac(&k, &[ikm]);
    let out = hmac(&prk, &[info, &[1u8]]);
    zeroize(&mut prk);
    out
}

/// Salt of the record key a vault kept under its owner's key derives.
const OWNER_SALT: [u8; 17] = *b"fluxor/seal/owner";

/// The record key a vault kept under an owner's key (the 32 bytes its
/// `seal_in` port receives) derives from it: HKDF-SHA256 with salt `fluxor/seal/owner`, info `ctx`.
/// The owner's key is the whole of the secret; no platform key takes part,
/// so the records follow that key and the medium, not the node.
pub fn derive_owner(owner_key: &[u8; KEY_LEN], ctx: &[u8]) -> [u8; KEY_LEN] {
    hkdf32(&OWNER_SALT, owner_key, ctx)
}
