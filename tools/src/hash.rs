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

/// sha256 of the canonical ABI wire-surface stream (`abi_surface`): the
/// digest that pins a graph generation / slot image to the kernel surface
/// it was built against. Equality = wire-compatible; no version windows.
pub fn abi_surface_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    crate::abi_surface::write_surface(&mut |bytes| h.update(bytes));
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    // The SDK embeds `ABI_SURFACE_DIGEST` — a checked-in copy of this digest
    // — into every module. Assert the copy still equals the freshly computed
    // surface, so a stale const is caught in any debug build of the tools,
    // not only under `cargo test`.
    debug_assert_eq!(
        out,
        crate::abi_surface::ABI_SURFACE_DIGEST,
        "checked-in ABI_SURFACE_DIGEST is stale vs the computed surface — regenerate it"
    );
    out
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

/// Recompute the canonical source hash over ALL of `modules/sdk` — the
/// full SDK a module compiles against: kernel_abi (incl. SyscallTable
/// layout and helper signatures), wire, config profiles, internal
/// layers, contracts, platform. Only the generated pin file itself is
/// excluded (self-reference).
///
/// Canonicalization is intentionally light: it drops blank lines and
/// whole-line `//` comments (so pure doc churn on `///` lines is
/// digest-neutral) and trims trailing whitespace. It does NOT strip
/// block comments, inline trailing comments, or indentation, and it
/// includes the relative path — so a rename, a reformat, or an inline
/// comment DOES move the digest. That is the deliberate, safe direction
/// (a false-positive rebuild self-heals; a false-negative acceptance is
/// a field failure), but it means the pin tracks more than strictly the
/// wire-bearing tokens.
///
/// Used by the drift test; the checked-in const is what ships (no
/// build.rs in no_std consumers).
#[allow(
    dead_code,
    reason = "consumed by the lib-side drift test; the bin mounts this file too"
)]
pub fn compute_contracts_platform_src_hash(repo_root: &Path) -> Result<[u8; 32]> {
    fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> std::io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let p = entry.path();
            if entry.file_type()?.is_dir() {
                // Build artifacts never participate.
                if p.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                walk(&p, out)?;
            } else if p.extension().is_some_and(|e| e == "rs")
                && p.file_name().is_none_or(|n| n != "abi_surface_srcpin.rs")
            {
                out.push(p);
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    walk(&repo_root.join("modules/sdk"), &mut files)?;
    let mut rels: Vec<(String, std::path::PathBuf)> = files
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(repo_root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            (rel, p)
        })
        .collect();
    rels.sort();
    let mut h = Sha256::new();
    for (rel, path) in rels {
        h.update(rel.as_bytes());
        h.update([0u8]);
        let text = fs::read_to_string(&path)?;
        let mut canon = String::new();
        let mut first = true;
        for line in text.split('\n') {
            let t = line.trim();
            if t.is_empty() || t.starts_with("//") {
                continue;
            }
            if !first {
                canon.push('\n');
            }
            first = false;
            canon.push_str(line.trim_end());
        }
        h.update(canon.as_bytes());
        h.update([0u8]);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drift guard for the ABI-surface digest itself. This locks the
    /// current wire surface: if it fails, an ABI numeric allocation (or
    /// the canonical field list in `modules/sdk/abi_surface.rs`) changed.
    /// That must be a conscious decision — already-built `.fmod`s hardcode
    /// these values, and every staged generation/slot pinned to the old
    /// digest will (correctly) stop matching. Update the constant here
    /// only as part of that deliberate change.
    #[test]
    fn abi_surface_digest_is_locked() {
        let digest = abi_surface_digest();
        // The embedded const modules carry MUST equal the computed digest,
        // or every module would embed a stale value and fail packing. This
        // is the regeneration gate for `ABI_SURFACE_DIGEST`.
        assert_eq!(
            digest,
            crate::abi_surface::ABI_SURFACE_DIGEST,
            "ABI_SURFACE_DIGEST const in modules/sdk/abi_surface_srcpin.rs is \
             stale — replace it with the computed digest below"
        );
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, "7dd8fe542b62705a9264c752116a605a7d53d28b76e65029e37111f1be96bb74",
            "ABI wire-surface changed — see this test's doc comment"
        );
    }

    /// The canonical stream must be deterministic and non-trivial.
    #[test]
    fn abi_surface_stream_is_deterministic() {
        assert_eq!(abi_surface_digest(), abi_surface_digest());
        let mut len = 0usize;
        crate::abi_surface::write_surface(&mut |b| len += b.len());
        assert!(len > 500, "surface stream suspiciously small: {len} bytes");
    }

    /// Drift guard for the checked-in contracts/platform source pin. When
    /// this fails, a contract or platform SDK file changed: paste the
    /// printed array into `modules/sdk/abi_surface_srcpin.rs`, then update
    /// the two locked surface digests (here and in the harness) — the
    /// full restage/rebuild that implies is the point.
    #[test]
    fn contracts_platform_srcpin_is_current() {
        let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let computed = compute_contracts_platform_src_hash(&repo).expect("hashable");
        let stored = crate::abi_surface::srcpin_for_test();
        if computed != stored {
            let arr: Vec<String> = computed.iter().map(|b| format!("0x{b:02x}")).collect();
            panic!(
                "contracts/platform source pin is stale.\nReplace the const in \
                 modules/sdk/abi_surface_srcpin.rs with:\n[{}]",
                arr.join(", ")
            );
        }
    }
}
