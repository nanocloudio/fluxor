//! Asset bank: build a `fluxor.assets` WebAssembly custom section
//! that bakes a graph's declared assets into the `.wasm` bundle.
//!
//! ### Why a custom section?
//!
//! The WebAssembly binary format allows arbitrary "custom" sections
//! (section_id = 0, named, opaque payload) that the JS host can read
//! via `WebAssembly.Module.customSections(module, name)` *before*
//! instantiation. This is the standard way to ship sidecar data with
//! a `.wasm` and is supported by every major browser engine.
//!
//! The alternative was a fixed-size zero-initialised placeholder in
//! the kernel `.rodata` — same magic-blob pattern as `modules.bin` /
//! `config.bin` — but that forces every wasm scenario (audio_player,
//! input_only_demos, …) to ship a multi-megabyte zero block even when it
//! has no assets. A custom section is zero-cost when absent and sized
//! exactly to the declared asset payload otherwise.
//!
//! ### TOC format
//!
//! The section's *body* (the bytes after the standard wasm custom-
//! section header — see `append_custom_section` below) is:
//!
//! ```text
//! [4]   magic = b"FXAB"      (Fluxor X-section Asset Bank)
//! [4]   u32 LE format_version = 1
//! [4]   u32 LE asset_count
//! per entry:
//!   [4]              u32 LE name_len
//!   [4]              u32 LE byte_len
//!   [name_len]       UTF-8 name (no nul, lowercase recommended)
//!   [byte_len]       asset bytes verbatim
//! ```
//!
//! Variable-length, interleaved entries — the shell walks the section
//! once at boot, builds a `Map<name, Uint8Array>`, and is done. No
//! padding, no fixed name length, no indirection.
//!
//! The shell's parser is the source of truth for the runtime contract;
//! see `src/platform/wasm/host/host_shims.js::parseAssetBank()`.

use crate::error::{Error, Result};

/// Magic bytes at the start of the TOC body. The JS shell sanity-checks
/// this before reading any counts.
pub const ASSET_BANK_MAGIC: &[u8; 4] = b"FXAB";

/// Format version. Bump when the TOC layout changes incompatibly.
pub const ASSET_BANK_VERSION: u32 = 1;

/// Custom-section name. Browsers expose this via `customSections(m, NAME)`.
pub const ASSET_BANK_SECTION_NAME: &str = "fluxor.assets";

/// One asset entry to bake into the bank.
#[derive(Debug, Clone)]
pub struct AssetEntry {
    /// Logical name the wasm runtime fetches via `asset://<name>`.
    /// UTF-8, no nul bytes. Path separators (`/`) are allowed and
    /// match the wire URL byte-for-byte.
    pub name: String,
    /// Raw asset bytes (image, audio, font, anything).
    pub bytes: Vec<u8>,
}

/// Encode a u32 as LEB128 unsigned varint, the wasm spec's integer
/// format. Used for custom-section length + name-length fields.
fn write_leb128_u32(out: &mut Vec<u8>, mut v: u32) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

/// Build the TOC body (the payload that goes *inside* the custom
/// section). Caller is responsible for appending it via
/// `append_custom_section`.
fn build_toc(entries: &[AssetEntry]) -> Result<Vec<u8>> {
    let mut toc = Vec::new();
    toc.extend_from_slice(ASSET_BANK_MAGIC);
    toc.extend_from_slice(&ASSET_BANK_VERSION.to_le_bytes());
    toc.extend_from_slice(&(entries.len() as u32).to_le_bytes());

    for e in entries {
        if e.name.is_empty() {
            return Err(Error::Config(
                "asset bank: empty asset name is not allowed".into(),
            ));
        }
        if e.name.as_bytes().contains(&0) {
            return Err(Error::Config(format!(
                "asset bank: asset name `{}` contains nul byte — \
                 names must be UTF-8 text",
                e.name
            )));
        }
        if e.name.len() > u32::MAX as usize {
            return Err(Error::Config(format!(
                "asset bank: asset name length {} exceeds u32::MAX",
                e.name.len()
            )));
        }
        if e.bytes.len() > u32::MAX as usize {
            return Err(Error::Config(format!(
                "asset bank: asset `{}` byte length {} exceeds u32::MAX",
                e.name,
                e.bytes.len()
            )));
        }
        toc.extend_from_slice(&(e.name.len() as u32).to_le_bytes());
        toc.extend_from_slice(&(e.bytes.len() as u32).to_le_bytes());
        toc.extend_from_slice(e.name.as_bytes());
        toc.extend_from_slice(&e.bytes);
    }

    Ok(toc)
}

/// Append a wasm custom section to `wasm_bytes` carrying the given
/// asset bank. The result is a valid wasm binary that any compliant
/// engine can instantiate; the asset bytes are reachable via
/// `WebAssembly.Module.customSections(module, "fluxor.assets")`.
///
/// If `entries` is empty, this is a no-op (the bundle stays byte-
/// identical) — calling code is free to invoke unconditionally.
pub fn append_asset_bank(wasm_bytes: &mut Vec<u8>, entries: &[AssetEntry]) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }

    // Sanity-check that the input *is* a wasm binary so we don't
    // silently corrupt arbitrary bytes if a caller mis-wires the path.
    if wasm_bytes.len() < 8 || &wasm_bytes[..4] != b"\0asm" {
        return Err(Error::Config(
            "asset bank: input does not start with wasm magic (\\0asm); \
             cannot append custom section"
                .into(),
        ));
    }

    let toc = build_toc(entries)?;
    let name = ASSET_BANK_SECTION_NAME.as_bytes();

    // Custom section format (wasm 1.0 spec §5.5):
    //   [u8 section_id = 0]
    //   [varuint32 section_size]   ← bytes after this varint
    //   [varuint32 name_len]
    //   [name_len bytes name]
    //   [section_size - (name_len_bytes + name_len) bytes payload]

    // Build the inner part (name_len + name + payload) first so we
    // know section_size.
    let mut inner = Vec::with_capacity(5 + name.len() + toc.len());
    write_leb128_u32(&mut inner, name.len() as u32);
    inner.extend_from_slice(name);
    inner.extend_from_slice(&toc);

    wasm_bytes.push(0x00); // custom section id
    write_leb128_u32(wasm_bytes, inner.len() as u32);
    wasm_bytes.extend_from_slice(&inner);

    Ok(())
}

/// Read an asset list from disk. Resolves relative paths against
/// `scenario_dir`. The asset's logical name is the basename of the
/// path; passing the same basename twice is an error (would create
/// shadowed entries in the runtime map).
///
/// Paths may be plain strings (`"assets/foo.png"`) or per-entry maps
/// with explicit `name:` overrides (`{path: ..., name: foo.png}`).
/// The mapping is interpreted by the caller; this helper only deals
/// with `(name, path)` pairs.
pub fn load_assets(pairs: &[(String, std::path::PathBuf)]) -> Result<Vec<AssetEntry>> {
    use std::collections::HashSet;
    // Dedup-check up-front so a duplicate fails fast (and
    // deterministically) without depending on which file the OS
    // happens to surface first.
    let mut seen: HashSet<&str> = HashSet::with_capacity(pairs.len());
    for (name, _) in pairs {
        if !seen.insert(name) {
            return Err(Error::Config(format!(
                "asset bank: duplicate asset name `{name}` — names must be \
                 unique within a bundle"
            )));
        }
    }

    let mut out = Vec::with_capacity(pairs.len());
    for (name, path) in pairs {
        let bytes = std::fs::read(path).map_err(|e| {
            Error::Config(format!(
                "asset bank: cannot read `{}` (resolved to {}): {}",
                name,
                path.display(),
                e
            ))
        })?;
        out.push(AssetEntry {
            name: name.clone(),
            bytes,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid wasm: magic + version, no sections.
    fn empty_wasm() -> Vec<u8> {
        vec![
            0x00, 0x61, 0x73, 0x6d, // \0asm
            0x01, 0x00, 0x00, 0x00, // version 1
        ]
    }

    #[test]
    fn leb128_round_trip_small_values() {
        let cases: &[(u32, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (300, &[0xac, 0x02]),
            (16384, &[0x80, 0x80, 0x01]),
        ];
        for (v, expected) in cases {
            let mut buf = Vec::new();
            write_leb128_u32(&mut buf, *v);
            assert_eq!(&buf[..], *expected, "LEB128 mismatch for {v}");
        }
    }

    #[test]
    fn empty_entries_is_noop() {
        let mut w = empty_wasm();
        let before = w.clone();
        append_asset_bank(&mut w, &[]).unwrap();
        assert_eq!(w, before, "empty entries must not mutate the wasm");
    }

    #[test]
    fn appends_well_formed_custom_section() {
        let mut w = empty_wasm();
        let entries = vec![
            AssetEntry {
                name: "a.bin".into(),
                bytes: b"hello".to_vec(),
            },
            AssetEntry {
                name: "b.bin".into(),
                bytes: b"world!".to_vec(),
            },
        ];
        append_asset_bank(&mut w, &entries).unwrap();

        // Wasm prelude is unchanged.
        assert_eq!(&w[..8], &empty_wasm()[..8]);

        // Custom section id = 0 follows.
        assert_eq!(w[8], 0x00, "custom section id should be 0");

        // The section name is somewhere inside the trailing bytes.
        let trailing = &w[9..];
        let name = ASSET_BANK_SECTION_NAME.as_bytes();
        assert!(
            trailing.windows(name.len()).any(|win| win == name),
            "expected custom section name `{ASSET_BANK_SECTION_NAME}` in appended bytes",
        );

        // TOC magic + entry bytes are reachable somewhere in the trailing region.
        assert!(
            trailing.windows(4).any(|w| w == ASSET_BANK_MAGIC),
            "expected TOC magic FXAB in appended bytes"
        );
        assert!(
            trailing.windows(5).any(|w| w == b"hello"),
            "expected entry payload `hello`"
        );
        assert!(
            trailing.windows(6).any(|w| w == b"world!"),
            "expected entry payload `world!`"
        );
    }

    #[test]
    fn rejects_duplicate_names() {
        let pairs = vec![
            (
                "dup.png".to_string(),
                std::path::PathBuf::from("/tmp/nonexistent_a"),
            ),
            (
                "dup.png".to_string(),
                std::path::PathBuf::from("/tmp/nonexistent_b"),
            ),
        ];
        // load_assets fails on the duplicate before it tries to read the file.
        let err = load_assets(&pairs).unwrap_err();
        assert!(
            err.to_string().contains("duplicate asset name"),
            "wanted duplicate-name error, got: {err}"
        );
    }

    #[test]
    fn rejects_non_wasm_input() {
        let mut not_wasm = b"this is not wasm".to_vec();
        let entries = vec![AssetEntry {
            name: "x".into(),
            bytes: vec![1, 2, 3],
        }];
        let err = append_asset_bank(&mut not_wasm, &entries).unwrap_err();
        assert!(err.to_string().contains("wasm magic"), "got: {err}");
    }

    #[test]
    fn rejects_empty_name() {
        let mut w = empty_wasm();
        let entries = vec![AssetEntry {
            name: "".into(),
            bytes: b"x".to_vec(),
        }];
        let err = append_asset_bank(&mut w, &entries).unwrap_err();
        assert!(err.to_string().contains("empty asset name"), "got: {err}");
    }

    #[test]
    fn rejects_nul_in_name() {
        let mut w = empty_wasm();
        let entries = vec![AssetEntry {
            name: "ev\0il".into(),
            bytes: b"x".to_vec(),
        }];
        let err = append_asset_bank(&mut w, &entries).unwrap_err();
        assert!(err.to_string().contains("nul"), "got: {err}");
    }
}
