//! Hash helpers used across the tools surface.
//!
//! - FNV-1a 32-bit: re-exported from the wire SDK so host tools and
//!   the kernel agree byte-for-byte on name hashes.
//! - SHA-256 of a file: one core implementation, three output shapes
//!   used by different callers (cargo index = bare hex, lockfile =
//!   `sha256:`-prefixed hex, publish-local = 12-char short hex).

use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::Result;

pub use crate::wire::fnv1a32 as fnv1a_hash;

/// SHA-256 of a file as 64 lowercase hex characters.
pub fn file_sha256_full(path: &Path) -> Result<String> {
    let bytes = fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

/// `sha256:<full-hex>` — lockfile and index `hash` field convention.
pub fn file_sha256_prefixed(path: &Path) -> Result<String> {
    Ok(format!("sha256:{}", file_sha256_full(path)?))
}

/// First 12 hex characters of SHA-256(content). Used for the
/// `-local.<sha>` content-hash suffix on local-publish artefacts —
/// 48 bits of distinguisher is enough for any registry that holds
/// thousands of snapshots.
pub fn file_sha256_short(path: &Path) -> Result<String> {
    let bytes = fs::read(path)?;
    let digest = Sha256::digest(&bytes);
    Ok(digest.iter().take(6).map(|b| format!("{b:02x}")).collect())
}
