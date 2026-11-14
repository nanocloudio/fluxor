//! The workspace's signing key, and the signing root it makes.
//!
//! One key gives a matched pair: `fluxor modules build` signs every module
//! with it, and `fluxor build` writes its public key into the kernel image as
//! the signing root, so the image admits exactly the modules this workspace
//! signed. The key is a 32-byte Ed25519 seed file (`fluxor modules keygen`),
//! named by, in order:
//!
//! 1. the command's own flag (`--sign-key`);
//! 2. `$FLUXOR_SIGNING_KEY`, for a script or rig whose seed is machine-local;
//! 3. `[signing] key = "${file:<path>}"` in the workspace `fluxor.toml`,
//!    relative to the project root.
//!
//! Without any, modules are built unsigned and images carry no root.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// The environment variable naming the signing key's seed file.
pub const ENV_KEY: &str = "FLUXOR_SIGNING_KEY";

/// The seed file this workspace signs with, if any.
pub fn key_path(flag: Option<&Path>, project_root: &Path) -> Result<Option<PathBuf>> {
    if let Some(p) = flag {
        return Ok(Some(p.to_path_buf()));
    }
    if let Some(p) = std::env::var_os(ENV_KEY).filter(|v| !v.is_empty()) {
        return Ok(Some(PathBuf::from(p)));
    }
    configured_key(project_root)
}

/// `fluxor.toml`'s `[signing] key`, resolved against the project root.
fn configured_key(project_root: &Path) -> Result<Option<PathBuf>> {
    let path = project_root.join("fluxor.toml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(None);
    };
    let doc: toml::Value =
        toml::from_str(&text).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
    let Some(spec) = doc.get("signing").and_then(|s| s.get("key")) else {
        return Ok(None);
    };
    let file = spec.as_str().and_then(file_source).ok_or_else(|| {
        Error::Config(format!(
            "{}: [signing] key is `\"${{file:<path>}}\"`, the seed file `fluxor modules \
                 keygen` makes",
            path.display()
        ))
    })?;
    Ok(Some(project_root.join(file)))
}

/// The path a `${file:<path>}` spec names.
pub fn file_source(spec: &str) -> Option<&str> {
    spec.strip_prefix("${file:")?
        .strip_suffix('}')
        .filter(|p| !p.is_empty())
}

/// The 32-byte seed in `path`.
pub fn read_seed(path: &Path) -> Result<[u8; 32]> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::Config(format!("signing key {}: {e}", path.display())))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        Error::Config(format!(
            "signing key {} is {} bytes, not a 32-byte Ed25519 seed",
            path.display(),
            bytes.len()
        ))
    })
}

/// The seed this workspace signs with, if any.
pub fn seed(flag: Option<&Path>, project_root: &Path) -> Result<Option<[u8; 32]>> {
    key_path(flag, project_root)?
        .map(|p| read_seed(&p))
        .transpose()
}

/// The public key of `seed`: the root a key's modules verify against.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    fluxor_sdk::crypto::ed25519::ed25519_public_key(seed)
}

/// The fingerprint a module signed by `seed` carries (`signer_fp`).
pub fn fingerprint(seed: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(public_key(seed)).into()
}

/// A root given as 64 hex digits.
pub fn parse_root(hex: &str) -> Result<[u8; 32]> {
    let bad = || {
        Error::Config(format!(
            "--root `{hex}` is not 64 hex digits (a 32-byte public key)"
        ))
    };
    if hex.len() != 64 {
        return Err(bad());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(out)
}

/// `fluxor build --root`, recorded once at dispatch for every image the
/// build packs.
static ROOT_FLAG: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Record `--root` for this invocation.
pub fn set_root_flag(hex: String) {
    let _ = ROOT_FLAG.set(hex);
}

/// The root a kernel image gets: `--root`, else the public key of this
/// workspace's signing key, else none.
pub fn root(project_root: &Path) -> Result<Option<[u8; 32]>> {
    if let Some(hex) = ROOT_FLAG.get() {
        return parse_root(hex).map(Some);
    }
    Ok(seed(None, project_root)?.map(|s| public_key(&s)))
}

/// Write `root` into a kernel image's root item and read it back, so an
/// image whose item the packager cannot find, or finds twice, is refused
/// rather than emitted rootless.
pub fn write_root(image: &mut [u8], root: Option<[u8; 32]>, what: &str) -> Result<()> {
    use fluxor_abi::wire::image_root::{self, ItemError};
    let explain = |e: ItemError| {
        Error::Config(match e {
            ItemError::Missing => format!(
                "{what} carries no signing-root item: it is not a kernel built from this tree"
            ),
            ItemError::Ambiguous => {
                format!("{what} carries more than one signing-root item")
            }
        })
    };
    image_root::write(image, root).map_err(explain)?;
    if image_root::read(image).map_err(explain)? != root {
        return Err(Error::Config(format!(
            "{what}: the signing root did not read back as written"
        )));
    }
    Ok(())
}

/// The root as the boot log names it: its first four bytes.
pub fn root_id(root: &[u8; 32]) -> String {
    root[..4].iter().map(|b| format!("{b:02x}")).collect()
}
