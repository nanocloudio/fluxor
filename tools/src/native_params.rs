//! The native modules' wire facts, generated from their manifests into the
//! ABI crate (a built-in a host provider serves is none: its instances are
//! `host_lane`s): `crates/fluxor-abi/src/platform/native.rs`, one module per
//! native module under its platform (`linux`, `wasm`), each with its name
//! hash, a `TAG_<PARAM>` per `[[params]]` entry, a `PORT_<NAME>: (u8, u8)`
//! per `[[ports]]` entry at the `(direction, index)` the packer binds it, and
//! — for a native the kernel instantiates — `STATE_BYTES`, the state its
//! vtable takes from the state arena (`state_bytes_64` × 64). Each platform
//! also gets `STATE_BYTES_BY_HASH`, every such native's `(NAME_HASH,
//! STATE_BYTES)`, which the build charges a graph's natives from. A native
//! that seats a module heap for its instance (`[capacities] heap_seat`) gets
//! `HEAP_SEAT`, the rule `fluxor_contracts::state_arena::heap_seat_bytes`
//! sizes that heap by, and its platform `HEAP_SEAT_BY_HASH`.
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
    /// A built-in a host provider serves: the kernel instantiates a
    /// `host_lane` for it, so it has no native of its own.
    #[serde(default)]
    host_provider: Option<toml::Value>,
    #[serde(default)]
    state_bytes_64: Option<u32>,
    #[serde(default)]
    params: Vec<Param>,
    #[serde(default)]
    ports: Vec<Port>,
    #[serde(default)]
    capacities: Capacities,
}

/// The `[capacities]` a native's heap seat is stated by.
#[derive(Deserialize, Default)]
struct Capacities {
    /// Bytes of module heap the kernel seats for an instance before scaling.
    heap_seat: Option<u32>,
    /// Bytes per pixel of the instance's `width` × `height` params.
    heap_seat_per_pixel: Option<u32>,
    /// The tag of a param whose value is bytes the seat adds.
    heap_seat_param: Option<u8>,
}

#[derive(Deserialize)]
struct Param {
    name: String,
    tag: u8,
    #[serde(default)]
    default: Option<toml::Value>,
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

/// One native module's block: its name hash, its state, tags and ports,
/// each port at the index the packer gives it (one counter per direction; an
/// explicit `index` advances its counter past itself).
fn emit_module(out: &mut String, name: &str, m: &Manifest, path: &Path) -> Result<()> {
    let _ = writeln!(out, "pub mod {name} {{");
    let _ = writeln!(
        out,
        "pub const NAME_HASH: u32 = {:#010x};",
        fluxor_abi::wire::fnv1a32(name.as_bytes())
    );
    if let Some(units) = state_units(m, path)? {
        let _ = writeln!(out, "pub const STATE_BYTES: u32 = {};", units * 64);
    }
    if let Some(seat) = heap_seat(m, path)? {
        let words: Vec<String> = seat.iter().map(u32::to_string).collect();
        let _ = writeln!(
            out,
            "pub const HEAP_SEAT: [u32; 6] = [{}];",
            words.join(", ")
        );
    }
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

/// A native's declared state, in 64-byte units: `None` for a manifest that
/// declares none (a native the kernel does not instantiate). A declared zero
/// is refused: the kernel's vtable would carve nothing to hand the
/// constructor.
fn state_units(m: &Manifest, path: &Path) -> Result<Option<u32>> {
    match m.state_bytes_64 {
        Some(0) => Err(Error::Config(format!(
            "{}: `state_bytes_64 = 0` — a native the kernel instantiates states the \
             64-byte units its instance holds; one it does not instantiates states none",
            path.display()
        ))),
        Some(n) => n.checked_mul(64).map(|_| Some(n)).ok_or_else(|| {
            Error::Config(format!("{}: `state_bytes_64` overflows", path.display()))
        }),
        None => Ok(None),
    }
}

/// A heap native's seat rule as `fluxor_contracts::state_arena::heap_seat_bytes`
/// reads it: `[base, per_pixel, width tag, height tag, param tag, param
/// default]`. `None` for a native that seats no heap.
fn heap_seat(m: &Manifest, path: &Path) -> Result<Option<[u32; 6]>> {
    let c = &m.capacities;
    let Some(base) = c.heap_seat else {
        if c.heap_seat_per_pixel.is_some() || c.heap_seat_param.is_some() {
            return Err(Error::Config(format!(
                "{}: a heap seat that scales states its `heap_seat` base",
                path.display()
            )));
        }
        return Ok(None);
    };
    let tag_of = |name: &str| m.params.iter().find(|p| p.name == name).map(|p| p.tag);
    let (per_pixel, width, height) = match c.heap_seat_per_pixel {
        Some(px) => match (tag_of("width"), tag_of("height")) {
            (Some(w), Some(h)) => (px, w, h),
            _ => {
                return Err(Error::Config(format!(
                    "{}: `heap_seat_per_pixel` scales by the `width` and `height` params, \
                     which the manifest does not declare",
                    path.display()
                )))
            }
        },
        None => (0, 0, 0),
    };
    let (param, default) = match c.heap_seat_param {
        Some(tag) => {
            let Some(p) = m.params.iter().find(|p| p.tag == tag) else {
                return Err(Error::Config(format!(
                    "{}: `heap_seat_param = {tag}` names no declared param",
                    path.display()
                )));
            };
            let default = match &p.default {
                Some(toml::Value::Integer(v)) => u32::try_from(*v).map_err(|_| {
                    Error::Config(format!(
                        "{}: `{}`'s default is not a u32",
                        path.display(),
                        p.name
                    ))
                })?,
                Some(_) => {
                    return Err(Error::Config(format!(
                        "{}: `{}`'s default is not an integer",
                        path.display(),
                        p.name
                    )))
                }
                None => 0,
            };
            (tag, default)
        }
        None => (0, 0),
    };
    Ok(Some([
        base,
        per_pixel,
        width as u32,
        height as u32,
        param as u32,
        default,
    ]))
}

/// The generated source for `repo`'s native-module manifests.
pub fn generate(repo: &Path) -> Result<String> {
    let mut out = String::from(
        "//! Native modules' name hashes, states, params tags and port bindings,\n\
         //! generated by `fluxor abi-regen` from\n\
         //! `modules/platform/<platform>/*/manifest.toml`.\n\
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
        let mut stated: Vec<String> = Vec::new();
        let mut seated: Vec<String> = Vec::new();
        for p in paths {
            let path = p.join("manifest.toml");
            let text = std::fs::read_to_string(&path)
                .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
            let m: Manifest = toml::from_str(&text)
                .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
            if !m.builtin || m.host_provider.is_some() {
                continue;
            }
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if state_units(&m, &path)?.is_some() {
                stated.push(name.clone());
            }
            if heap_seat(&m, &path)?.is_some() {
                seated.push(name.clone());
            }
            emit_module(&mut out, &name, &m, &path)?;
        }
        let _ = writeln!(
            out,
            "/// Every native this platform's kernel instantiates, as `(NAME_HASH, STATE_BYTES)`."
        );
        let _ = writeln!(out, "pub const STATE_BYTES_BY_HASH: &[(u32, u32)] = &[");
        for name in &stated {
            let _ = writeln!(out, "({name}::NAME_HASH, {name}::STATE_BYTES),");
        }
        let _ = writeln!(out, "];");
        let _ = writeln!(
            out,
            "/// Every native this platform's kernel seats a module heap for, as `(NAME_HASH, HEAP_SEAT)`."
        );
        let _ = writeln!(out, "pub const HEAP_SEAT_BY_HASH: &[(u32, [u32; 6])] = &[");
        for name in &seated {
            let _ = writeln!(out, "({name}::NAME_HASH, {name}::HEAP_SEAT),");
        }
        let _ = writeln!(out, "];");
        let _ = writeln!(out, "}}");
    }
    crate::abi_registry::rustfmt(&out)
}

/// The generated file's path under `repo`.
pub fn gen_path(repo: &Path) -> PathBuf {
    repo.join(NATIVE_GEN)
}
