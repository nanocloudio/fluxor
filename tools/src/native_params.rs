//! The native modules' wire facts, generated from their manifests into the
//! ABI crate: `crates/fluxor-abi/src/platform/native.rs`, one module per
//! native module under its platform (`linux`, `wasm`), each with its name
//! hash, a `TAG_<PARAM>` per `[[params]]` entry and a `PORT_<NAME>: (u8, u8)`
//! per `[[ports]]` entry at the `(direction, index)` the packer binds it.
//!
//! `fluxor abi-regen` writes it with the registry and the pin (so the pin
//! covers it); `fluxor abi-regen --check` fails when it is stale. The
//! manifest is the one place each number is written.

use crate::error::{Error, Result};
use serde::Deserialize;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Where the generated file is written, relative to the repo root.
pub const NATIVE_GEN: &str = "crates/fluxor-abi/src/platform/native.rs";

/// The platforms whose native modules' manifests live under
/// `modules/platform/<platform>/`.
const PLATFORMS: [&str; 2] = ["linux", "wasm"];

#[derive(Deserialize)]
struct Manifest {
    #[serde(default)]
    builtin: bool,
    #[serde(default)]
    params: Vec<Param>,
    #[serde(default)]
    ports: Vec<Port>,
}

#[derive(Deserialize)]
struct Param {
    name: String,
    tag: u8,
}

#[derive(Deserialize)]
struct Port {
    name: String,
    direction: String,
    #[serde(default)]
    index: Option<u8>,
}

/// The port-type byte a direction resolves to, as the packer resolves it.
fn port_type(direction: &str, manifest: &Path) -> Result<u8> {
    match direction {
        "input" | "in" => Ok(0),
        "output" | "out" => Ok(1),
        "ctrl" | "ctrl_input" => Ok(2),
        other => Err(Error::Config(format!(
            "{}: port direction '{other}' is not one a native module binds",
            manifest.display()
        ))),
    }
}

/// One native module's block: its name hash, tags and ports, each port at
/// the index the packer gives it (one counter per direction; an explicit
/// `index` advances its counter past itself).
fn emit_module(out: &mut String, name: &str, m: &Manifest, path: &Path) -> Result<()> {
    let _ = writeln!(out, "pub mod {name} {{");
    let _ = writeln!(
        out,
        "pub const NAME_HASH: u32 = {:#010x};",
        fluxor_abi::wire::fnv1a32(name.as_bytes())
    );
    for p in &m.params {
        let _ = writeln!(
            out,
            "pub const TAG_{}: u8 = {};",
            p.name.to_uppercase(),
            p.tag
        );
    }
    let mut next = [0u8; 3];
    for p in &m.ports {
        let dir = port_type(&p.direction, path)?;
        let counter = &mut next[dir as usize];
        let index = match p.index {
            Some(i) => {
                *counter = (*counter).max(i + 1);
                i
            }
            None => {
                let i = *counter;
                *counter += 1;
                i
            }
        };
        let _ = writeln!(
            out,
            "pub const PORT_{}: (u8, u8) = ({dir}, {index});",
            p.name.to_uppercase()
        );
    }
    let _ = writeln!(out, "}}");
    Ok(())
}

/// The generated source for `repo`'s native-module manifests.
pub fn generate(repo: &Path) -> Result<String> {
    let mut out = String::from(
        "//! Native modules' name hashes, params tags and port bindings, generated\n\
         //! by `fluxor abi-regen` from `modules/platform/<platform>/*/manifest.toml`.\n\
         //! Do not edit: change the manifest and regenerate.\n\n",
    );
    for platform in PLATFORMS {
        let dir = repo.join("modules/platform").join(platform);
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map_err(|e| Error::Config(format!("{}: {e}", dir.display())))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.join("manifest.toml").is_file())
            .collect();
        paths.sort();
        let _ = writeln!(out, "pub mod {platform} {{");
        for p in paths {
            let path = p.join("manifest.toml");
            let text = std::fs::read_to_string(&path)
                .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
            let m: Manifest = toml::from_str(&text)
                .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
            if !m.builtin {
                continue;
            }
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            emit_module(&mut out, &name, &m, &path)?;
        }
        let _ = writeln!(out, "}}");
    }
    crate::abi_registry::rustfmt(&out)
}

/// The generated file's path under `repo`.
pub fn gen_path(repo: &Path) -> PathBuf {
    repo.join(NATIVE_GEN)
}
