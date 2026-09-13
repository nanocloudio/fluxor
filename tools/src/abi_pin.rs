//! Shared ABI-surface pin computation — the single source of the checked-in
//! pin values, used by both `fluxor abi-regen` (the writer) and the `fluxor ci`
//! gate (the read-only `--check`). The pin is the digest of the ABI wire
//! surface folded with the hash of the contracts/platform sources; every
//! checked-in copy of it must agree, or a graph could be admitted onto a
//! substrate whose ABI it does not match. See the `abi_surface_srcpin.rs`
//! header for the constants this writes.

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

/// The recomputed pin plus the content each checked-in site SHOULD have.
pub struct PinPlan {
    pub digest_hex: String,
    /// `(path, expected_content)` for each of the three checked-in sites.
    pub edits: Vec<(PathBuf, String)>,
}

impl PinPlan {
    /// Sites whose on-disk content differs from what the plan expects.
    pub fn stale_sites(&self) -> Result<Vec<PathBuf>> {
        let mut stale = Vec::new();
        for (path, expected) in &self.edits {
            if std::fs::read_to_string(path)? != *expected {
                stale.push(path.clone());
            }
        }
        Ok(stale)
    }

    /// Write every site to its expected content.
    pub fn write(&self) -> Result<()> {
        for (path, expected) in &self.edits {
            std::fs::write(path, expected)?;
        }
        Ok(())
    }
}

/// Walk up from `start` to the repo root (the dir holding
/// `modules/sdk/abi_surface.rs`).
pub fn repo_root_from(start: &Path) -> Result<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        if dir.join("modules/sdk/abi_surface.rs").is_file() {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err(Error::Config(
                "repo root not found — run from within the fluxor tree (no \
                 modules/sdk/abi_surface.rs above the start path)"
                    .into(),
            ));
        }
    }
}

/// True if `repo` carries the ABI-surface sources this pin governs (the fluxor
/// kernel tree). Downstream projects don't, and skip the gate.
pub fn has_abi_surface(repo: &Path) -> bool {
    repo.join("modules/sdk/abi_surface_srcpin.rs").is_file()
}

/// Recompute the pin from source and build the expected content of all sites.
/// The digest folds the FRESHLY computed source hash — not the compiled-in
/// const — so this is correct in one invocation with no rebuild.
pub fn compute(repo: &Path) -> Result<PinPlan> {
    use sha2::{Digest, Sha256};

    let srcpin = crate::hash::compute_contracts_platform_src_hash(repo)?;

    // Mirror `abi_surface::write_surface`: numeric walk ‖ "contracts_platform_src"\0 ‖ srcpin.
    let mut h = Sha256::new();
    crate::abi_surface::for_each_field(&mut |name, value| {
        h.update(name.as_bytes());
        h.update([0u8]);
        h.update(value.to_le_bytes());
    });
    h.update(b"contracts_platform_src");
    h.update([0u8]);
    h.update(srcpin);
    let digest: [u8; 32] = h.finalize().into();
    let digest_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();

    // Two sites, not three: the harness lock asserts the kernel mount against
    // `ABI_SURFACE_DIGEST` rather than restating the digest, so the only
    // spelled-out copy in the tree is the tools-side tripwire below.
    let srcpin_file = repo.join("modules/sdk/abi_surface_srcpin.rs");
    let hash_file = repo.join("tools/src/hash.rs");

    let mut sp = std::fs::read_to_string(&srcpin_file)?;
    sp = replace_u8_array(&sp, "CONTRACTS_PLATFORM_SRC_HASH", &srcpin)?;
    sp = replace_u8_array(&sp, "ABI_SURFACE_DIGEST", &digest)?;
    let hs = replace_hex(&std::fs::read_to_string(&hash_file)?, "hex, ", &digest_hex)?;

    Ok(PinPlan {
        digest_hex,
        edits: vec![(srcpin_file, sp), (hash_file, hs)],
    })
}

/// Format 32 bytes as a `[u8; 32]` literal body in the checked-in 15/15/2
/// layout (4-space indent).
fn fmt_u8_array(bytes: &[u8; 32]) -> String {
    let hexes: Vec<String> = bytes.iter().map(|b| format!("0x{b:02x}")).collect();
    let mut out = String::from("[\n");
    for chunk in [&hexes[0..15], &hexes[15..30], &hexes[30..32]] {
        out.push_str("    ");
        out.push_str(&chunk.join(", "));
        out.push_str(",\n");
    }
    out.push(']');
    out
}

fn replace_u8_array(src: &str, const_name: &str, bytes: &[u8; 32]) -> Result<String> {
    let re = regex::Regex::new(&format!(
        r"(?s)({}: \[u8; 32\] = )\[.*?\]",
        regex::escape(const_name)
    ))
    .unwrap();
    if !re.is_match(src) {
        return Err(Error::Config(format!(
            "const {const_name} not found for abi pin"
        )));
    }
    let arr = fmt_u8_array(bytes);
    Ok(re
        .replace(src, |c: &regex::Captures<'_>| format!("{}{}", &c[1], arr))
        .into_owned())
}

fn replace_hex(src: &str, anchor: &str, new_hex: &str) -> Result<String> {
    let re =
        regex::Regex::new(&format!(r#"({}")[0-9a-f]{{64}}(")"#, regex::escape(anchor))).unwrap();
    if !re.is_match(src) {
        return Err(Error::Config(format!(
            "digest anchor `{anchor}` not found for abi pin"
        )));
    }
    Ok(re
        .replace(src, |c: &regex::Captures<'_>| {
            format!("{}{}{}", &c[1], new_hex, &c[2])
        })
        .into_owned())
}
