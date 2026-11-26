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
//!                      [from_id u16][from_port u8][to_id u16][to_port_kind u8][to_port u8]
//! [vault_custody u8]
//! ```
//!
//! The `key_vault` module reads it through `COMPOSITION_RECORD`, signs it
//! (`ATTEST_COMPOSITION`) and reports the
//! custody its key is held at, so the signature's meaning travels with it:
//! `DEVICE_HW` says this hardware runs this closure; `SOFTWARE` says a
//! process that could be read runs it. The **composition digest** is the
//! SHA-256 of the record with the challenge zeroed — the stable identity a
//! key-wrap binds to, independent of who asked.
//!
//! What the record proves is bytes and wiring. It does not prove that the
//! closure is correct, authorised or intended; that is a statement about
//! policy, made above this surface.
//!
//! **Listed blobs.** The blob list is every blob the loader table holds, an
//! instance running it or not, and only a blob an instance runs has passed
//! `loader::validate_module` (integrity, signature where present, and an
//! ABI-surface attestation equal to this kernel's). Listing an unvalidated
//! blob exposes nothing, because no path runs a listed blob's code without
//! that validation:
//!
//! - Every instantiation from the node's loader, at boot and in a live add
//!   (`live::instantiate_pic`), goes through `instantiate_one_module`, which
//!   validates before any export of the module runs, and `start_new`
//!   validates again before its init.
//! - A workload's code pack is admitted through `code_pack::admitted_with`,
//!   which validates every pack module before its region is sealed
//!   executable.
//! - What else reads a listed blob reads bytes, never code: this record and
//!   the node's module digests (`code_pack::node_digests`) hash the table
//!   entry; the hints pass (`collect_one_module_hints`) validates before it
//!   reads the manifest; an add's grant pre-check (`live::module_grants`)
//!   reads manifest fields only. Those reads stay inside the entry's footprint, which the table's
//!   load bounded (`validate_table_layout` covers the header, code, data,
//!   exports, schema and manifest of every entry), and what they decide is
//!   advisory: the instantiation that follows validates the blob, so a forged
//!   manifest can only make an add fail later, never run.
//!
//! So the list states what the table holds, and the instance list below it
//! states what runs; a verifier that needs every held blob checked reads the
//! digests against its own pins.

use super::static_storage::{static_config, static_loader};
use crate::abi::kernel_abi::composition::{MAGIC, VERSION};
use crate::kernel::security::crypto::sha256::Sha256;

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
/// `None` when `out` is too small. `custody` is the vault's answer for the
/// key that will sign it.
///
/// Each loaded blob is hashed once per loaded table and cached
/// ([`forget_blob_digests`]).
pub fn write_record(challenge: &[u8; 32], custody: u8, out: &mut [u8]) -> Option<usize> {
    let mut pos = 0usize;
    write_record_into(challenge, custody, &mut |b| put(out, &mut pos, b)).then_some(pos)
}

/// [`write_record`] into any sink: `e` takes each piece and answers false to
/// stop (out of room).
fn write_record_into(challenge: &[u8; 32], custody: u8, e: &mut dyn FnMut(&[u8]) -> bool) -> bool {
    if !e(&MAGIC) || !e(&[VERSION]) {
        return false;
    }
    let incarnation = crate::kernel::sys::incarnation::get();
    if !e(&incarnation) || !e(challenge) {
        return false;
    }
    // The kernel's own ABI-surface digest, over the canonical stream. Every
    // module the loader instantiates attests this same digest, signed or not
    // (`loader::validate_module` refuses one that is unattested or attests
    // another), so each instance listed below runs a blob built for it. A
    // blob the table holds that no instance runs is listed by its bytes and
    // has not been checked; no path runs it unchecked (see the module
    // documentation).
    let abi = {
        let mut h = Sha256::new();
        crate::abi::abi_surface::write_surface(&mut |bytes| h.update(bytes));
        h.finalize()
    };
    if !e(&abi) {
        return false;
    }

    // SAFETY: attestation runs on the scheduler thread with no concurrent
    // `static_loader_mut` / `static_config_mut` borrow — those are init-time
    // and reconfigure-time only.
    let (loader, config) = unsafe { (static_loader(), static_config()) };

    // Every blob the loader holds, hashed in place: the table entry's bytes,
    // header, code, data, exports and manifest.
    let blob_count = loader.module_count();
    if !e(&(blob_count as u16).to_le_bytes()) {
        return false;
    }
    let mut i = 0;
    while i < blob_count {
        let Some(entry) = loader.get_entry(i) else {
            return false;
        };
        let Some(digest) = blob_digest(loader, i) else {
            return false;
        };
        if !e(&entry.name_hash.to_le_bytes()) || !e(&entry.size.to_le_bytes()) || !e(&digest) {
            return false;
        }
        i += 1;
    }

    // Every instantiated module with its parameters as composed.
    let instance_count = config.module_count as usize;
    if !e(&(instance_count as u16).to_le_bytes()) {
        return false;
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
            if !e(&entry.name_hash.to_le_bytes()) || !e(&[entry.domain_id]) || !e(&digest) {
                return false;
            }
            n += 1;
        }
        i += 1;
    }

    // Every edge as composed, a lane end by its side, key and target.
    let edge_count = config.edge_count as usize;
    if !e(&(edge_count as u16).to_le_bytes()) {
        return false;
    }
    let mut n = 0;
    let mut i = 0;
    while i < config.graph_edges.len() && n < edge_count {
        if let Some(g) = &config.graph_edges[i] {
            if !e(&g.from_id.to_le_bytes())
                || !e(&[g.from_port_index])
                || !e(&g.to_id.to_le_bytes())
                || !e(&[g.to_port, g.to_port_index])
            {
                return false;
            }
            // A lane end, by its side, key and target.
            if let Some(l) = g.lane {
                if !e(&[1 + u8::from(l.to), l.key]) || !e(&l.target.to_le_bytes()) {
                    return false;
                }
            }
            n += 1;
        }
        i += 1;
    }

    if !e(&[custody]) {
        return false;
    }
    true
}

/// Blob digests cached per loader-table index: a blob is hashed once per
/// loaded table, not inside every caller's step that asks for the record.
#[cfg(any(target_arch = "aarch64", feature = "host-linux"))]
const DIGEST_CACHE: usize = 128;
#[cfg(not(any(target_arch = "aarch64", feature = "host-linux")))]
const DIGEST_CACHE: usize = 32;

struct DigestCache {
    /// The table the cached digests describe: its base address.
    table: usize,
    known: [bool; DIGEST_CACHE],
    digest: [[u8; 32]; DIGEST_CACHE],
}

static mut DIGESTS: DigestCache = DigestCache {
    table: 0,
    known: [false; DIGEST_CACHE],
    digest: [[0; 32]; DIGEST_CACHE],
};

/// Forget every cached blob digest: the loader's table is about to change.
pub fn forget_blob_digests() {
    // SAFETY: scheduler thread, outside any record build.
    unsafe {
        let c = &mut *core::ptr::addr_of_mut!(DIGESTS);
        c.table = 0;
        c.known = [false; DIGEST_CACHE];
    }
}

/// The SHA-256 of loader-table blob `i`: its header, code, data, exports
/// and manifest, as the table holds them.
fn blob_digest(loader: &crate::kernel::module::loader::ModuleLoader, i: usize) -> Option<[u8; 32]> {
    let entry = loader.get_entry(i)?;
    let m = loader.find_by_name_hash(entry.name_hash).ok()?;
    // SAFETY: scheduler thread, the cache's only user.
    let c = unsafe { &mut *core::ptr::addr_of_mut!(DIGESTS) };
    let table = loader.table_base() as usize;
    if c.table != table {
        c.table = table;
        c.known = [false; DIGEST_CACHE];
    }
    if i < DIGEST_CACHE && c.known[i] {
        return Some(c.digest[i]);
    }
    let mut h = Sha256::new();
    // SAFETY: `base` is the loaded blob the loader admitted and `size` its
    // length from the module table; both were validated at load.
    let bytes = unsafe { core::slice::from_raw_parts(m.base, entry.size as usize) };
    h.update(bytes);
    let d = h.finalize();
    if i < DIGEST_CACHE {
        c.digest[i] = d;
        c.known[i] = true;
    }
    Some(d)
}

/// Serve `COMPOSITION_RECORD`: `arg` = `[challenge 32][custody u8]`, the
/// record into `out`; with `composition::DIGEST` in the custody byte, the
/// composition digest (32 bytes) instead. `ERANGE` with the length needed
/// in `arg[..4]` when `out` is short.
pub fn serve_record(arg: &mut [u8], out: &mut [u8]) -> i32 {
    use crate::abi::errno::{EINVAL, ERANGE};
    use crate::abi::kernel_abi::composition::{DIGEST, DIGEST_LEN};
    if arg.len() < 33 {
        return EINVAL;
    }
    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(&arg[..32]);
    let custody = arg[32];
    let need = |arg: &mut [u8], n: usize| {
        arg[..4].copy_from_slice(&(n as u32).to_le_bytes());
        ERANGE
    };
    if custody & DIGEST != 0 {
        if out.len() < DIGEST_LEN {
            return need(arg, DIGEST_LEN);
        }
        let mut h = Sha256::new();
        if !stream_record(&[0u8; 32], custody & !DIGEST, &mut |b| h.update(b)) {
            return EINVAL;
        }
        out[..DIGEST_LEN].copy_from_slice(&h.finalize());
        return DIGEST_LEN as i32;
    }
    let n = record_len();
    if n == 0 {
        return EINVAL;
    }
    if out.len() < n {
        return need(arg, n);
    }
    match write_record(&challenge, custody, out) {
        Some(len) => len as i32,
        None => EINVAL,
    }
}

/// The length the record has now.
fn record_len() -> usize {
    let mut n = 0usize;
    if stream_record(&[0u8; 32], 0, &mut |b| n += b.len()) {
        n
    } else {
        0
    }
}

/// Emit the record piecewise into `sink`, with no buffer. False when a blob
/// cannot be read.
fn stream_record(challenge: &[u8; 32], custody: u8, sink: &mut dyn FnMut(&[u8])) -> bool {
    write_record_into(challenge, custody, &mut |b| {
        sink(b);
        true
    })
}
