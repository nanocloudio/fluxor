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
    // NB: this returns the freshly COMPUTED digest and deliberately does not
    // assert it against the checked-in `ABI_SURFACE_DIGEST` const. A stale
    // const is caught by the `abi_surface_digest_is_locked` /
    // `contracts_platform_srcpin_is_current` tests and by pack-time
    // attestation (`verify_module_abi_surface`), and is *fixed* by
    // `fluxor abi-regen`. A `debug_assert` here would panic the whole tool —
    // including the regen command — whenever the pin is stale, i.e. it would
    // block its own fix path.
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
/// Canonicalization is **token-based** (`canonicalize_source`): each file is
/// tokenized and the token stream is hashed structurally. Comments and
/// formatting are not tokens, so a doc/inline/block comment edit or a `cargo
/// fmt` is digest-neutral, without introducing a false negative:
/// every identifier, punctuation, and literal —
/// including a string literal's exact spelling and internal whitespace — is a
/// token, so any change to an opcode number, const value, struct field, or
/// signature still moves the digest. The relative path is still folded in, so a
/// rename moves it. A file that fails to tokenize (should not happen for valid
/// Rust) falls back to line-canonicalization (drop blank + whole-line comments)
/// — the safe over-approximation.
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
        h.update(canonicalize_source(&text).as_bytes());
        h.update([0u8]);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    Ok(out)
}

/// Canonicalize one Rust source file to its wire-relevant essence for the pin.
/// Tokenizes and renders the token stream structurally — dropping comments and
/// formatting (not tokens) while preserving every identifier, punct, and
/// literal (so literal values, including string contents, are exact). Falls
/// back to line-canonicalization if the file does not tokenize.
fn canonicalize_source(text: &str) -> String {
    use std::str::FromStr;
    match proc_macro2::TokenStream::from_str(text) {
        Ok(ts) => {
            let mut out = String::new();
            render_tokens(ts, &mut out);
            out
        }
        Err(_) => {
            let mut canon = String::new();
            for line in text.split('\n') {
                let t = line.trim();
                if t.is_empty() || t.starts_with("//") {
                    continue;
                }
                canon.push_str(line.trim_end());
                canon.push('\n');
            }
            canon
        }
    }
}

/// Render a token stream to a stable, delimiter-separated string. Each token is
/// tagged by kind so distinct token sequences can never collide (`0x1f` = unit
/// separator). Does not use `TokenStream::to_string` (its inter-token spacing
/// is not guaranteed stable across proc-macro2 versions).
///
/// Doc comments (`///`, `//!`, `/** */`) are lexed into `#[doc = "…"]` /
/// `#![doc = "…"]` attribute tokens; those are DROPPED here (documentation
/// carries no wire meaning). Real attributes — `#[repr(C)]`, `#[cfg(...)]` —
/// are kept, since they DO affect the surface.
fn render_tokens(ts: proc_macro2::TokenStream, out: &mut String) {
    use proc_macro2::{Delimiter, TokenTree};
    let toks: Vec<TokenTree> = ts.into_iter().collect();
    let mut i = 0;
    while i < toks.len() {
        // Attribute shape: `#` `!`? `[ … ]`. Skip the whole thing iff it is a
        // `doc` attribute.
        if matches!(&toks[i], TokenTree::Punct(p) if p.as_char() == '#') {
            let mut j = i + 1;
            if matches!(toks.get(j), Some(TokenTree::Punct(q)) if q.as_char() == '!') {
                j += 1;
            }
            if let Some(TokenTree::Group(g)) = toks.get(j) {
                if g.delimiter() == Delimiter::Bracket && group_is_doc(g) {
                    i = j + 1;
                    continue;
                }
            }
        }
        render_one(&toks[i], out);
        i += 1;
    }
}

/// True if a bracket group is a `doc = "…"` attribute body.
fn group_is_doc(g: &proc_macro2::Group) -> bool {
    matches!(
        g.stream().into_iter().next(),
        Some(proc_macro2::TokenTree::Ident(id)) if id == "doc"
    )
}

fn render_one(tt: &proc_macro2::TokenTree, out: &mut String) {
    use proc_macro2::{Delimiter, TokenTree};
    match tt {
        TokenTree::Group(g) => {
            out.push('g');
            out.push(match g.delimiter() {
                Delimiter::Parenthesis => '(',
                Delimiter::Brace => '{',
                Delimiter::Bracket => '[',
                Delimiter::None => 'N',
            });
            out.push('\x1f');
            render_tokens(g.stream(), out);
            out.push('G');
            out.push('\x1f');
        }
        TokenTree::Ident(i) => {
            out.push('i');
            out.push_str(&i.to_string());
            out.push('\x1f');
        }
        TokenTree::Punct(p) => {
            out.push('p');
            out.push(p.as_char());
            out.push('\x1f');
        }
        TokenTree::Literal(l) => {
            out.push('l');
            out.push_str(&l.to_string());
            out.push('\x1f');
        }
    }
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
            hex, "5aa15398e7917e24bbef200b8217314330c3fdb051792781a1a8320e9b8af201",
            "ABI wire-surface changed — see this test's doc comment"
        );
    }

    /// The source-pin canonicalizer must be neutral to comments and formatting
    /// (false-positive churn) yet sensitive to every wire token — including a
    /// string literal's internal whitespace, the exact case a naive text strip
    /// would silently miss (a false negative in a compatibility guard).
    #[test]
    fn source_canon_drops_noise_keeps_wire_tokens() {
        let base = "pub const OP: u32 = 0x1A00; // opcode\n";
        // Comment edits, block comments, reformatting, blank lines: all neutral.
        let comment = "pub const OP: u32 = 0x1A00; // a completely different note\n";
        let block = "/* banner */\npub const OP: u32 = 0x1A00;\n";
        let reformat = "pub  const OP:u32   =0x1A00;\n\n\n";
        // `///` doc comments lex to `#[doc=...]` attrs — must be dropped too.
        let docced = "/// This opcode does a thing.\npub const OP: u32 = 0x1A00;\n";
        assert_eq!(canonicalize_source(base), canonicalize_source(comment));
        assert_eq!(canonicalize_source(base), canonicalize_source(block));
        assert_eq!(canonicalize_source(base), canonicalize_source(reformat));
        assert_eq!(
            canonicalize_source(base),
            canonicalize_source(docced),
            "/// doc comments must be digest-neutral"
        );
        // But a REAL attribute is wire-relevant and must be kept.
        assert_ne!(
            canonicalize_source("pub struct W { a: u32 }\n"),
            canonicalize_source("#[repr(C)]\npub struct W { a: u32 }\n"),
            "#[repr(C)] changes layout — must move the digest"
        );

        // Any wire change moves it: opcode value, and — critically — whitespace
        // INSIDE a string literal (no false-negative).
        let value = "pub const OP: u32 = 0x1A01;\n";
        assert_ne!(canonicalize_source(base), canonicalize_source(value));
        assert_ne!(
            canonicalize_source("pub const S: &str = \"a  b\";\n"),
            canonicalize_source("pub const S: &str = \"a b\";\n"),
            "string-literal internal whitespace must be preserved"
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
                "contracts/platform source pin is stale (a modules/sdk source \
                 changed).\nRun `fluxor abi-regen` to rewrite all pin sites, \
                 then `fluxor modules build --all` so .fmods re-attest.\n(Manual fallback — \
                 replace the const in modules/sdk/abi_surface_srcpin.rs \
                 with:\n[{}])",
                arr.join(", ")
            );
        }
    }
}
