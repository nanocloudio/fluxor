//! The running-composition record: what this kernel is executing, stated
//! from what it holds — never from what it was told.
//!
//! A deployment stages a closure and activates it; what a peer can check
//! afterwards is that THIS host runs EXACTLY that closure, and the only
//! thing that can say so honestly is the kernel, over the bytes it loaded
//! and the graph it wired. The record is:
//!
//! ```text
//! [magic "FXAT"][version u8 = 1]
//! [boot_incarnation 16][challenge 32][kernel_abi_surface 32]
//! [blob_count u16]     per loaded module blob, loader-table order:
//!                      [name_hash u32][size u32][sha256 32]
//! [instance_count u16] per instantiated module, config order:
//!                      [name_hash u32][domain u8][params_sha256 32]
//! [edge_count u16]     per graph edge, config order:
//!                      [from_id u8][from_port u8][to_id u8][to_port_kind u8][to_port u8]
//! [vault_tier u8]
//! ```
//!
//! The vault signs it (`KEY_VAULT::ATTEST_COMPOSITION`) and reports the
//! tier its key is held at, so the signature's meaning travels with it:
//! `DEVICE_HW` says this hardware runs this closure; `SOFTWARE` says a
//! process that could be read runs it. The **composition digest** is the
//! SHA-256 of the record with the challenge zeroed — the stable identity a
//! key-wrap binds to, independent of who asked.
//!
//! What the record proves is bytes and wiring. It does not prove that the
//! closure is correct, authorised or intended; that is a statement about
//! policy, made above this surface.

use super::static_storage::{static_config, static_loader};
use crate::kernel::security::crypto::sha256::Sha256;

/// Record magic.
pub const MAGIC: [u8; 4] = *b"FXAT";
/// Record version.
pub const VERSION: u8 = 1;
/// Offset of the challenge within the record.
pub const CHALLENGE_OFF: usize = 4 + 1 + 16;
/// Fixed prefix length: magic, version, incarnation, challenge, ABI digest.
pub const PREFIX_LEN: usize = CHALLENGE_OFF + 32 + 32;

/// Append `bytes` to `out` at `pos`, or report that they did not fit.
fn put(out: &mut [u8], pos: &mut usize, bytes: &[u8]) -> bool {
    if *pos + bytes.len() > out.len() {
        return false;
    }
    out[*pos..*pos + bytes.len()].copy_from_slice(bytes);
    *pos += bytes.len();
    true
}

/// Write the record for `challenge` into `out`, returning its length;
/// `None` when `out` is too small. `tier` is the vault's answer for the
/// key that will sign it.
///
/// Costs one SHA-256 pass over every loaded module blob, so it is made at
/// activation, not per request.
pub fn write_record(challenge: &[u8; 32], tier: u8, out: &mut [u8]) -> Option<usize> {
    let mut pos = 0usize;
    if !put(out, &mut pos, &MAGIC) || !put(out, &mut pos, &[VERSION]) {
        return None;
    }
    let incarnation = crate::kernel::sys::incarnation::get();
    if !put(out, &mut pos, &incarnation) || !put(out, &mut pos, challenge) {
        return None;
    }
    // The kernel's own ABI-surface digest, over the canonical stream the
    // loader checks every module against.
    let abi = {
        let mut h = Sha256::new();
        crate::abi::abi_surface::write_surface(&mut |bytes| h.update(bytes));
        h.finalize()
    };
    if !put(out, &mut pos, &abi) {
        return None;
    }

    // SAFETY: attestation runs on the scheduler thread with no concurrent
    // `static_loader_mut` / `static_config_mut` borrow — those are init-time
    // and reconfigure-time only.
    let (loader, config) = unsafe { (static_loader(), static_config()) };

    // Every blob the loader holds, hashed in place. The blob is what was
    // admitted: header, code, data, exports, manifest.
    let blob_count = loader.module_count();
    if !put(out, &mut pos, &(blob_count as u16).to_le_bytes()) {
        return None;
    }
    let mut i = 0;
    while i < blob_count {
        let entry = loader.get_entry(i)?;
        let m = loader.find_by_name_hash(entry.name_hash).ok()?;
        let mut h = Sha256::new();
        // SAFETY: `base` is the loaded blob the loader admitted and `size`
        // its length from the module table; both were validated at load.
        let bytes = unsafe { core::slice::from_raw_parts(m.base, entry.size as usize) };
        h.update(bytes);
        let digest = h.finalize();
        if !put(out, &mut pos, &entry.name_hash.to_le_bytes())
            || !put(out, &mut pos, &entry.size.to_le_bytes())
            || !put(out, &mut pos, &digest)
        {
            return None;
        }
        i += 1;
    }

    // Every instantiated module with its parameters as composed.
    let instance_count = config.module_count as usize;
    if !put(out, &mut pos, &(instance_count as u16).to_le_bytes()) {
        return None;
    }
    let mut n = 0;
    let mut i = 0;
    while i < config.modules.len() && n < instance_count {
        if let Some(entry) = &config.modules[i] {
            let mut h = Sha256::new();
            if !entry.params_ptr.is_null() && entry.params_len > 0 {
                // SAFETY: the config parser set `params_ptr`/`params_len` to a
                // slice inside the config arena it owns.
                let p = unsafe { core::slice::from_raw_parts(entry.params_ptr, entry.params_len) };
                h.update(p);
            }
            let digest = h.finalize();
            if !put(out, &mut pos, &entry.name_hash.to_le_bytes())
                || !put(out, &mut pos, &[entry.domain_id])
                || !put(out, &mut pos, &digest)
            {
                return None;
            }
            n += 1;
        }
        i += 1;
    }

    // Every edge as composed.
    let edge_count = config.edge_count as usize;
    if !put(out, &mut pos, &(edge_count as u16).to_le_bytes()) {
        return None;
    }
    let mut n = 0;
    let mut i = 0;
    while i < config.graph_edges.len() && n < edge_count {
        if let Some(e) = &config.graph_edges[i] {
            if !put(
                out,
                &mut pos,
                &[
                    e.from_id,
                    e.from_port_index,
                    e.to_id,
                    e.to_port,
                    e.to_port_index,
                ],
            ) {
                return None;
            }
            n += 1;
        }
        i += 1;
    }

    if !put(out, &mut pos, &[tier]) {
        return None;
    }
    Some(pos)
}

/// The composition digest of a record: SHA-256 with the challenge zeroed.
/// The identity a key-wrap binds to.
pub fn composition_digest_of(record: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    if record.len() >= PREFIX_LEN {
        h.update(&record[..CHALLENGE_OFF]);
        h.update(&[0u8; 32]);
        h.update(&record[CHALLENGE_OFF + 32..]);
    } else {
        h.update(record);
    }
    h.finalize()
}

/// This composition's digest, as a peer's attestation of it would carry.
/// `None` when the record cannot be built.
pub fn composition_digest(tier: u8, scratch: &mut [u8]) -> Option<[u8; 32]> {
    let len = write_record(&[0u8; 32], tier, scratch)?;
    Some(composition_digest_of(&scratch[..len]))
}
