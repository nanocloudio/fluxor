//! The key vault's persisted record: one labelled key, filed in a
//! [`super::vault_image`] under a name built from its scope and label.
//! Shared by the `key_vault` module and the tools that provision records off
//! the device, so the two cannot disagree about a byte of it.
//!
//! A record is its header then the key: sealed (`[nonce 12][ct][tag 16]`,
//! ChaCha20-Poly1305 under the vault's record key with the header as
//! associated data) or, in a vault kept readable, the key itself.
//!
//! ```text
//! header: magic(4) ‖ namespace:u32 ‖ suite:u16 ‖ usage:u32 ‖ label_len:u8
//!         ‖ label ‖ [realm:16]
//! name:   namespace:u32 (big-endian) ‖ [realm:16] ‖ label
//! ```
//!
//! The header is the AEAD's associated data, so every fact a key is filed
//! under is authenticated with it: a header altered at rest makes the
//! record not open, rather than open as something else. A workload's record
//! in a vault that serves several realms is realm-bound (`FXVW`, `FXVR`):
//! its realm is in the header and the name, so no other realm's record
//! opens as it. A record in a vault kept under one owner's key names no
//! realm (`FXVK`, `FXVC`).

use crate::crypto::chacha20::{chacha20_poly1305_decrypt, chacha20_poly1305_encrypt};
use crate::crypto::zeroize::zeroize;

/// Longest label.
pub const MAX_LABEL: usize = 64;
/// Largest key a record carries.
pub const MAX_KEY: usize = 64;
/// Nonce and tag a sealed key carries beside its bytes.
pub const SEAL_OVERHEAD: usize = 12 + 16;
/// Longest sealed key.
pub const MAX_SEALED: usize = MAX_KEY + SEAL_OVERHEAD;
/// Longest header.
pub const MAX_HEADER: usize = 4 + 4 + 2 + 4 + 1 + MAX_LABEL + 16;
/// Longest record.
pub const MAX_RECORD: usize = MAX_HEADER + MAX_SEALED;
/// Longest name.
pub const MAX_NAME: usize = 4 + 16 + MAX_LABEL;
/// Shortest header: no label, no realm.
pub const MIN_HEADER: usize = 15;

/// A sealed record, no realm.
pub const SEALED: [u8; 4] = *b"FXVK";
/// A sealed record bound to a workload's realm.
pub const SEALED_REALM: [u8; 4] = *b"FXVW";
/// A readable record, no realm.
pub const CLEAR: [u8; 4] = *b"FXVC";
/// A readable record bound to a workload's realm.
pub const CLEAR_REALM: [u8; 4] = *b"FXVR";

/// What a record is filed under.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Filing<'a> {
    /// The owning module type's hash: labels are unique within it.
    pub namespace: u32,
    /// The workload realm the record is bound to, `None` for an unbound one
    /// (the node's own, or any record of a vault kept under an owner's key).
    pub realm: Option<&'a [u8; 16]>,
    pub label: &'a [u8],
}

/// The header for a key filed as `f`, written into `out`; returns its
/// length, `None` for a label longer than [`MAX_LABEL`].
pub fn header(
    f: &Filing<'_>,
    suite: u16,
    usage: u32,
    clear: bool,
    out: &mut [u8; MAX_HEADER],
) -> Option<usize> {
    if f.label.len() > MAX_LABEL {
        return None;
    }
    out[0..4].copy_from_slice(match (f.realm.is_some(), clear) {
        (true, false) => &SEALED_REALM,
        (false, false) => &SEALED,
        (true, true) => &CLEAR_REALM,
        (false, true) => &CLEAR,
    });
    out[4..8].copy_from_slice(&f.namespace.to_le_bytes());
    out[8..10].copy_from_slice(&suite.to_le_bytes());
    out[10..14].copy_from_slice(&usage.to_le_bytes());
    out[14] = f.label.len() as u8;
    out[15..15 + f.label.len()].copy_from_slice(f.label);
    let mut n = 15 + f.label.len();
    if let Some(realm) = f.realm {
        out[n..n + 16].copy_from_slice(realm);
        n += 16;
    }
    Some(n)
}

/// The image name a key filed as `f` is kept under; returns its length.
pub fn name(f: &Filing<'_>, out: &mut [u8; MAX_NAME]) -> Option<usize> {
    if f.label.len() > MAX_LABEL {
        return None;
    }
    out[0..4].copy_from_slice(&f.namespace.to_be_bytes());
    let mut at = 4;
    if let Some(realm) = f.realm {
        out[4..20].copy_from_slice(realm);
        at = 20;
    }
    out[at..at + f.label.len()].copy_from_slice(f.label);
    Some(at + f.label.len())
}

/// The suite and usage a record's header names, and whether it is a
/// readable one: `None` when it is too short to be a header.
pub fn facts(record: &[u8]) -> Option<(u16, u32, bool)> {
    if record.len() < MIN_HEADER {
        return None;
    }
    let suite = u16::from_le_bytes([record[8], record[9]]);
    let usage = u32::from_le_bytes([record[10], record[11], record[12], record[13]]);
    let clear = record[0..4] == CLEAR || record[0..4] == CLEAR_REALM;
    Some((suite, usage, clear))
}

/// Seal `plain` under `key` with `aad`: `[nonce][ct][tag]` into `out`,
/// returning its length; `None` when `out` is short.
pub fn seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plain: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = plain.len() + SEAL_OVERHEAD;
    if out.len() < total {
        return None;
    }
    out[..12].copy_from_slice(nonce);
    out[12..12 + plain.len()].copy_from_slice(plain);
    let tag = chacha20_poly1305_encrypt(key, nonce, aad, &mut out[12..12 + plain.len()]);
    out[12 + plain.len()..total].copy_from_slice(&tag);
    Some(total)
}

/// Open what [`seal`] sealed: the key's length in `out`; `None` (and `out`
/// wiped) when it does not open under `key` and `aad`.
pub fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8], out: &mut [u8]) -> Option<usize> {
    if sealed.len() < SEAL_OVERHEAD || out.len() < sealed.len() - SEAL_OVERHEAD {
        return None;
    }
    let body = sealed.len() - SEAL_OVERHEAD;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sealed[..12]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&sealed[12 + body..]);
    out[..body].copy_from_slice(&sealed[12..12 + body]);
    if chacha20_poly1305_decrypt(key, &nonce, aad, &mut out[..body], &tag) {
        Some(body)
    } else {
        zeroize(&mut out[..body]);
        None
    }
}

/// Build the whole record for `key` filed as `f` into `out`: its header,
/// then the key sealed under `record_key` (or, `record_key` `None`, the key
/// readable). Returns its length.
pub fn encode(
    f: &Filing<'_>,
    suite: u16,
    usage: u32,
    key: &[u8],
    record_key: Option<&[u8; 32]>,
    nonce: &[u8; 12],
    out: &mut [u8; MAX_RECORD],
) -> Option<usize> {
    if key.len() > MAX_KEY {
        return None;
    }
    let mut h = [0u8; MAX_HEADER];
    let hl = header(f, suite, usage, record_key.is_none(), &mut h)?;
    out[..hl].copy_from_slice(&h[..hl]);
    let n = match record_key {
        Some(k) => seal(k, nonce, &h[..hl], key, &mut out[hl..])?,
        None => {
            out[hl..hl + key.len()].copy_from_slice(key);
            key.len()
        }
    };
    Some(hl + n)
}
