//! WASM bundle: rewrite the kernel `.wasm`'s embedded modules-blob and
//! config-blob placeholders with the real `modules.bin` / `config.bin`
//! bytes.
//!
//! See `docs/architecture/wasm_platform.md` §5 for the platform-level
//! description. The kernel emits two `#[no_mangle] pub static` blob
//! structs at compile time, each carrying:
//!
//! ```text
//! [0..16]   magic — 16-byte ASCII sentinel
//! [16..20]  capacity — u32 LE; bytes available in `data`
//! [20..24]  used_len — u32 LE; 0 in the placeholder
//! [24..32]  reserved
//! [32..N]   data — capacity bytes of payload
//! ```
//!
//! This tool greps the kernel `.wasm` file for the two magic
//! sentinels, validates each header, and overwrites `used_len` plus
//! the first `used_len` bytes of `data` with the real blob. Output is
//! a self-contained `.wasm` file the host instantiates without further
//! processing.

use crate::error::{Error, Result};

const MODULES_MAGIC: &[u8; 16] = b"FLUXOR_MOD_BLOB\0";
const CONFIG_MAGIC: &[u8; 16] = b"FLUXOR_CFG_BLOB\0";

/// Size of the per-blob header (magic + capacity + used_len + reserved).
const BLOB_HEADER_SIZE: usize = 32;

/// One blob the bundle tool needs to rewrite.
struct BlobSlot<'a> {
    name: &'a str,
    magic: &'a [u8; 16],
    payload: &'a [u8],
}

/// Locate the unique occurrence of `magic` in `kernel`. Errors if the
/// magic appears zero times or more than once. The placeholder header
/// is unique enough (16-byte ASCII sentinel) that exactly one match is
/// the expected case; multiple matches indicate either a corrupt
/// kernel build or accidental aliasing in another data segment, both
/// of which should fail loudly.
fn find_magic_offset(kernel: &[u8], magic: &[u8; 16], name: &str) -> Result<usize> {
    let mut found: Option<usize> = None;
    let mut i = 0usize;
    while i + 16 <= kernel.len() {
        if &kernel[i..i + 16] == magic {
            if found.is_some() {
                return Err(Error::Config(format!(
                    "wasm bundle: {} magic appears more than once in kernel.wasm \
                     (corrupt build or magic collision); aborting",
                    name
                )));
            }
            found = Some(i);
            // Skip past this match to detect duplicates without rescan.
            i += 16;
        } else {
            i += 1;
        }
    }
    found.ok_or_else(|| {
        Error::Config(format!(
            "wasm bundle: {} magic not found in kernel.wasm — was the kernel \
             built without the host-wasm feature, or is this not a Fluxor \
             kernel?",
            name
        ))
    })
}

/// Rewrite one blob slot in `kernel`. Verifies capacity ≥ payload, then
/// overwrites `used_len` and the first `payload.len()` bytes of `data`.
fn rewrite_one(kernel: &mut [u8], slot: &BlobSlot) -> Result<()> {
    let header_off = find_magic_offset(kernel, slot.magic, slot.name)?;

    // Header layout: [16 magic][u32 capacity][u32 used_len][8 reserved]
    let cap_off = header_off + 16;
    let used_off = header_off + 20;
    let data_off = header_off + BLOB_HEADER_SIZE;

    let capacity = u32::from_le_bytes(
        kernel[cap_off..cap_off + 4]
            .try_into()
            .expect("4-byte slice"),
    ) as usize;

    if slot.payload.len() > capacity {
        return Err(Error::Config(format!(
            "wasm bundle: {} blob is {} bytes but kernel placeholder \
             capacity is {} bytes — rebuild kernel with a larger \
             placeholder (see src/platform/wasm.rs)",
            slot.name,
            slot.payload.len(),
            capacity,
        )));
    }

    // Write used_len (LE u32).
    let used_len = slot.payload.len() as u32;
    kernel[used_off..used_off + 4].copy_from_slice(&used_len.to_le_bytes());

    // Write payload bytes. Bytes beyond payload.len() within the
    // placeholder are left as their pre-bundle value (zero, on a fresh
    // kernel build); the kernel reads exactly `used_len` bytes so the
    // tail is irrelevant.
    if !slot.payload.is_empty() {
        kernel[data_off..data_off + slot.payload.len()].copy_from_slice(slot.payload);
    }

    Ok(())
}

/// Public entry point: take kernel WASM bytes plus the modules and
/// config blobs, return the rewritten WASM bytes ready to write out.
pub fn bundle(kernel: &[u8], modules_bin: &[u8], config_bin: &[u8]) -> Result<Vec<u8>> {
    // Quick sanity check that this looks like a wasm binary.
    if kernel.len() < 8 || &kernel[..4] != b"\0asm" {
        return Err(Error::Config(
            "wasm bundle: kernel file does not start with the wasm magic \
             (\\0asm); not a wasm binary"
                .into(),
        ));
    }

    let mut out = kernel.to_vec();

    rewrite_one(
        &mut out,
        &BlobSlot {
            name: "modules",
            magic: MODULES_MAGIC,
            payload: modules_bin,
        },
    )?;

    rewrite_one(
        &mut out,
        &BlobSlot {
            name: "config",
            magic: CONFIG_MAGIC,
            payload: config_bin,
        },
    )?;

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthesize a fake "kernel" containing both magics + headers, so
    /// the bundle round-trip can be tested without a real kernel build.
    fn fake_kernel(modules_cap: usize, config_cap: usize) -> Vec<u8> {
        let mut k = Vec::new();
        // wasm magic + version
        k.extend_from_slice(b"\0asm\x01\x00\x00\x00");
        // pad
        k.extend_from_slice(&[0u8; 64]);
        // modules slot
        k.extend_from_slice(MODULES_MAGIC);
        k.extend_from_slice(&(modules_cap as u32).to_le_bytes());
        k.extend_from_slice(&0u32.to_le_bytes());
        k.extend_from_slice(&[0u8; 8]);
        k.extend_from_slice(&vec![0u8; modules_cap]);
        // pad
        k.extend_from_slice(&[0u8; 32]);
        // config slot
        k.extend_from_slice(CONFIG_MAGIC);
        k.extend_from_slice(&(config_cap as u32).to_le_bytes());
        k.extend_from_slice(&0u32.to_le_bytes());
        k.extend_from_slice(&[0u8; 8]);
        k.extend_from_slice(&vec![0u8; config_cap]);
        k
    }

    #[test]
    fn round_trip_basic() {
        let k = fake_kernel(1024, 256);
        let modules = b"hello modules.bin";
        let config = b"hello config.bin";
        let out = bundle(&k, modules, config).unwrap();
        // Find the modules header in the output and check used_len + data.
        let m_off = find_magic_offset(&out, MODULES_MAGIC, "modules").unwrap();
        let m_used = u32::from_le_bytes(out[m_off + 20..m_off + 24].try_into().unwrap());
        assert_eq!(m_used, modules.len() as u32);
        assert_eq!(&out[m_off + 32..m_off + 32 + modules.len()], modules);
        let c_off = find_magic_offset(&out, CONFIG_MAGIC, "config").unwrap();
        let c_used = u32::from_le_bytes(out[c_off + 20..c_off + 24].try_into().unwrap());
        assert_eq!(c_used, config.len() as u32);
        assert_eq!(&out[c_off + 32..c_off + 32 + config.len()], config);
    }

    #[test]
    fn rejects_oversize_payload() {
        let k = fake_kernel(8, 256);
        let too_big = vec![0u8; 16];
        let err = bundle(&k, &too_big, b"").unwrap_err();
        assert!(err.to_string().contains("modules"));
    }

    #[test]
    fn rejects_non_wasm() {
        let err = bundle(b"not-a-wasm-file-blah", b"", b"").unwrap_err();
        assert!(err.to_string().contains("wasm magic"));
    }
}
