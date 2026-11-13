//! The three crates every module links — `fluxor_abi`, `fluxor_sdk`,
//! `fluxor_rt` — built once per module ABI as rlibs.
//!
//! Each is compiled with the module build's own flags, one codegen unit (so
//! a crate is one object and its `#[used]` statics travel with whatever the
//! module pulls from it), a fixed `-C metadata` (so the mangled names a
//! module's assembly calls are the names the rlib's assembly defines) and its
//! source path remapped to the crate name (so panic locations carry a short
//! path, not this machine's). The source comes from `crates/<name>` in
//! fluxor and from the synced `target/fluxor/<name>` everywhere else.
//!
//! A built rlib is held to what a module is held to: every object passes
//! `relocation_refusals`, and the three together leave no symbol undefined —
//! as a set, since `fluxor_abi` and `fluxor_sdk` call the `memcpy` and
//! `__aeabi_*` helpers only `fluxor_rt` defines. A stamp over the crate
//! sources, the compiler and the flags skips a rebuild that would produce the
//! same bytes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use super::{cfg_abi_args, relocation_refusals, run_step, AbiSpec, PIC_RELOCATION_MODEL};
use crate::error::{Error, Result};

/// The crates, in dependency order: each may use only those before it.
const CRATES: [(&str, &str); 3] = [
    ("fluxor-abi", "fluxor_abi"),
    ("fluxor-sdk", "fluxor_sdk"),
    ("fluxor-rt", "fluxor_rt"),
];

/// The rlibs for one module ABI, and the assembly each was compiled to.
pub struct SdkLibs {
    dir: PathBuf,
    rlibs: Vec<PathBuf>,
    asm: Vec<PathBuf>,
}

impl SdkLibs {
    /// The rustc arguments that make the crates available to a module.
    pub fn extern_args(&self) -> Vec<String> {
        let mut args = vec![
            "-L".to_string(),
            format!("dependency={}", self.dir.display()),
        ];
        for ((_, name), rlib) in CRATES.iter().zip(&self.rlibs) {
            args.push("--extern".into());
            args.push(format!("{name}={}", rlib.display()));
        }
        args
    }

    /// The rlibs, for the module link.
    pub fn rlibs(&self) -> &[PathBuf] {
        &self.rlibs
    }

    /// The assembly of all three, for the module's stack walk.
    pub fn asm(&self) -> &[PathBuf] {
        &self.asm
    }
}

/// Where crate `dir_name` (`fluxor-abi`, …) is compiled from: this tree's
/// `crates/`, or the source tree `fluxor sync` staged.
pub fn crate_dir(project_root: &Path, dir_name: &str) -> Option<PathBuf> {
    [
        project_root.join("crates").join(dir_name),
        project_root.join("target/fluxor").join(dir_name),
    ]
    .into_iter()
    .find(|d| d.join("src/lib.rs").is_file())
}

/// The module link script, which ships with `fluxor-rt`.
pub fn module_ld(project_root: &Path) -> Option<PathBuf> {
    crate_dir(project_root, "fluxor-rt")
        .map(|d| d.join("module.ld"))
        .filter(|p| p.is_file())
}

/// Every file of crate tree `dir`, in a stable order.
fn crate_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(walkdir::DirEntry::into_path)
        .collect();
    files.sort();
    files
}

/// The newest modification time among the crates' sources: a module built
/// before it may have linked other code.
pub fn newest_source(project_root: &Path) -> Option<std::time::SystemTime> {
    CRATES
        .iter()
        .filter_map(|(dir, _)| crate_dir(project_root, dir))
        .flat_map(|d| crate_files(&d))
        .filter_map(|f| f.metadata().ok()?.modified().ok())
        .max()
}

fn rustc_version() -> Result<String> {
    let out = Command::new("rustc")
        .arg("-vV")
        .output()
        .map_err(|e| Error::Module(format!("rustc -vV: {e}")))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The rustc flags an rlib for `spec` compiles under, after the crate's own.
fn rlib_flags(spec: &AbiSpec, strict: bool) -> Vec<String> {
    let mut f: Vec<String> = Vec::new();
    let pic = spec.linker.is_some();
    // wasm modules compile for size, so their crates do too.
    f.extend([
        "-C".into(),
        format!("opt-level={}", if pic { "2" } else { "z" }),
    ]);
    if pic {
        f.extend([
            "-C".into(),
            format!("relocation-model={PIC_RELOCATION_MODEL}"),
        ]);
    }
    // One object per crate; no LLVM bitcode in it, which nothing here
    // reads (the module link is not LTO) and which would ride along in the
    // rlib and its assembly.
    f.extend(["-C".into(), "codegen-units=1".into()]);
    f.extend(["-C".into(), "embed-bitcode=no".into()]);
    f.extend(spec.extra_rustflags.iter().map(|s| (*s).to_string()));
    f.extend(cfg_abi_args(spec));
    f.extend(["--check-cfg".into(), "cfg(feature, values())".into()]);
    f.extend([
        "-D".into(),
        if strict {
            "warnings"
        } else {
            "unfulfilled_lint_expectations"
        }
        .into(),
    ]);
    f
}

/// Build (or find current) the three rlibs for `spec` under
/// `<out_root>/<abi>/sdk/`.
pub fn ensure(
    project_root: &Path,
    out_root: &Path,
    spec: &AbiSpec,
    strict: bool,
    verbose: bool,
) -> Result<SdkLibs> {
    let dir = out_root.join(spec.abi_id).join("sdk");
    std::fs::create_dir_all(&dir)?;
    let flags = rlib_flags(spec, strict);
    let rustc = rustc_version()?;
    let mut libs = SdkLibs {
        dir: dir.clone(),
        rlibs: Vec::new(),
        asm: Vec::new(),
    };
    // Each crate's stamp folds in the ones before it: a changed dependency
    // is a changed compile.
    let mut chain = Sha256::new();
    for (dir_name, name) in CRATES {
        let src = crate_dir(project_root, dir_name).ok_or_else(|| {
            Error::Module(format!(
                "crate `{dir_name}` not found under crates/ or target/fluxor/ (run `fluxor sync`)"
            ))
        })?;
        chain.update(name.as_bytes());
        chain.update(spec.module_target.as_bytes());
        chain.update(rustc.as_bytes());
        for f in &flags {
            chain.update(f.as_bytes());
            chain.update([0]);
        }
        for file in crate_files(&src) {
            chain.update(
                file.strip_prefix(&src)
                    .unwrap_or(&file)
                    .to_string_lossy()
                    .as_bytes(),
            );
            chain.update(std::fs::read(&file)?);
        }
        let stamp: String = chain
            .clone()
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let rlib = dir.join(format!("lib{name}.rlib"));
        let asm = dir.join(format!("{name}.s"));
        let stamp_path = dir.join(format!("{name}.stamp"));
        let current = rlib.is_file()
            && asm.is_file()
            && std::fs::read_to_string(&stamp_path).ok().as_deref() == Some(stamp.as_str());
        if !current {
            if verbose {
                eprintln!("[modules] rlib  {name} ({})", spec.abi_id);
            }
            let _ = std::fs::remove_file(&stamp_path);
            let scratch = dir.join(format!("{name}.rustc"));
            std::fs::create_dir_all(&scratch)?;
            let mut cmd = Command::new("rustc");
            cmd.arg("--crate-type=rlib")
                .arg("--crate-name")
                .arg(name)
                .arg("--edition")
                .arg("2021")
                .arg("--target")
                .arg(spec.module_target)
                .arg("-C")
                .arg(format!("metadata={name}"))
                .arg(format!("--remap-path-prefix={}={dir_name}", src.display()))
                .args(&flags)
                .args(libs.extern_args())
                .arg("--out-dir")
                .arg(&scratch)
                .arg(format!(
                    "--emit=link={},asm={}",
                    rlib.display(),
                    asm.display()
                ))
                .arg(src.join("src/lib.rs"));
            let built = run_step(cmd, "rustc");
            let _ = std::fs::remove_dir_all(&scratch);
            built.map_err(|e| Error::Module(format!("{name}: {e}")))?;
            if spec.linker.is_some() {
                for (member, obj) in ar_objects(&std::fs::read(&rlib)?)? {
                    relocation_refusals(&obj)?.into_result(&format!("{name} ({member})"))?;
                }
            }
            std::fs::write(&stamp_path, &stamp)?;
        }
        libs.rlibs.push(rlib);
        libs.asm.push(asm);
    }
    // Checked on every build, not only a rebuild: a failed check must not be
    // forgotten by the next run because the stamps say current.
    if spec.linker.is_some() {
        closed_as_a_set(&libs)?;
    }
    Ok(libs)
}

/// Refuse when the three rlibs, together, call a symbol none of them
/// defines: a module linking them would fail at `--no-undefined`, every one
/// of them, for a reason no module could fix.
fn closed_as_a_set(libs: &SdkLibs) -> Result<()> {
    let mut defined = BTreeSet::new();
    let mut undefined = BTreeSet::new();
    for rlib in &libs.rlibs {
        for (_, obj) in ar_objects(&std::fs::read(rlib)?)? {
            let (d, u) = elf_symbols(&obj)?;
            defined.extend(d);
            undefined.extend(u);
        }
    }
    let open: Vec<String> = undefined.difference(&defined).cloned().collect();
    if open.is_empty() {
        return Ok(());
    }
    Err(Error::Module(format!(
        "the fluxor_abi/fluxor_sdk/fluxor_rt rlibs call {} symbol(s) none of them defines: {} \
         (a libcore entry point the runtime does not shim, or code that needs a crate it does not depend on)",
        open.len(),
        open.join(", ")
    )))
}

/// The object members of an `ar` archive (an rlib): `(name, bytes)`, skipping
/// the symbol tables, the long-name table and rustc's metadata.
fn ar_objects(ar: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let bad = || Error::Module("rlib: malformed ar archive".into());
    if ar.get(0..8) != Some(b"!<arch>\n") {
        return Err(bad());
    }
    let mut longnames: &[u8] = &[];
    let mut out = Vec::new();
    let mut at = 8usize;
    while at + 60 <= ar.len() {
        let h = &ar[at..at + 60];
        let raw_name = std::str::from_utf8(&h[0..16])
            .map_err(|_| bad())?
            .trim_end();
        let size: usize = std::str::from_utf8(&h[48..58])
            .map_err(|_| bad())?
            .trim()
            .parse()
            .map_err(|_| bad())?;
        let body = ar.get(at + 60..at + 60 + size).ok_or_else(bad)?;
        let name = if raw_name == "//" {
            longnames = body;
            String::new()
        } else if let Some(off) = raw_name.strip_prefix('/').filter(|r| !r.is_empty()) {
            let off: usize = off.parse().map_err(|_| bad())?;
            let rest = longnames.get(off..).ok_or_else(bad)?;
            let end = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
            String::from_utf8_lossy(&rest[..end])
                .trim_end_matches('/')
                .to_string()
        } else {
            raw_name.trim_end_matches('/').to_string()
        };
        if name.ends_with(".o") && body.starts_with(b"\x7fELF") {
            out.push((name, body.to_vec()));
        }
        at += 60 + size + (size & 1);
    }
    Ok(out)
}

/// The global and weak symbols an ELF object defines, and those it uses
/// without defining.
fn elf_symbols(obj: &[u8]) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let bad = || Error::Module("object: malformed ELF".into());
    let get = |o: usize, n: usize| obj.get(o..o.checked_add(n)?);
    let u16_at = |o: usize| -> Result<usize> {
        let b = get(o, 2).ok_or_else(bad)?;
        Ok(usize::from(u16::from_le_bytes([b[0], b[1]])))
    };
    let u32_at = |o: usize| -> Result<usize> {
        let b = get(o, 4).ok_or_else(bad)?;
        usize::try_from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])).map_err(|_| bad())
    };
    let u64_at = |o: usize| -> Result<usize> {
        let b = get(o, 8).ok_or_else(bad)?;
        usize::try_from(u64::from_le_bytes(b.try_into().map_err(|_| bad())?)).map_err(|_| bad())
    };
    if obj.get(0..4) != Some(b"\x7fELF") || obj.get(5) != Some(&1) {
        return Err(bad());
    }
    let elf64 = obj.get(4) == Some(&2);
    let (shoff, shentsize, shnum) = if elf64 {
        (u64_at(40)?, u16_at(58)?, u16_at(60)?)
    } else {
        (u32_at(32)?, u16_at(46)?, u16_at(48)?)
    };
    // (type, offset, size, link, entsize) of section `i`.
    let section = |i: usize| -> Result<(usize, usize, usize, usize, usize)> {
        let h = shoff + i * shentsize;
        Ok(if elf64 {
            (
                u32_at(h + 4)?,
                u64_at(h + 24)?,
                u64_at(h + 32)?,
                u32_at(h + 40)?,
                u64_at(h + 56)?,
            )
        } else {
            (
                u32_at(h + 4)?,
                u32_at(h + 16)?,
                u32_at(h + 20)?,
                u32_at(h + 24)?,
                u32_at(h + 36)?,
            )
        })
    };
    let mut defined = BTreeSet::new();
    let mut undefined = BTreeSet::new();
    for i in 0..shnum {
        let (ty, off, size, link, entsize) = section(i)?;
        if ty != 2 || entsize == 0 {
            continue; // SHT_SYMTAB only
        }
        let (_, stroff, strsize, _, _) = section(link)?;
        let strtab = get(stroff, strsize).ok_or_else(bad)?;
        for e in 1..size / entsize {
            let s = off + e * entsize;
            let (name, info, shndx) = if elf64 {
                (u32_at(s)?, *obj.get(s + 4).ok_or_else(bad)?, u16_at(s + 6)?)
            } else {
                (
                    u32_at(s)?,
                    *obj.get(s + 12).ok_or_else(bad)?,
                    u16_at(s + 14)?,
                )
            };
            let bind = info >> 4;
            if bind != 1 && bind != 2 {
                continue; // locals are the object's own business
            }
            let tail = strtab.get(name..).ok_or_else(bad)?;
            let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
            let sym = String::from_utf8_lossy(&tail[..end]).into_owned();
            if sym.is_empty() {
                continue;
            }
            if shndx == 0 {
                // A weak reference may stay unresolved; a global one may not.
                if bind == 1 {
                    undefined.insert(sym);
                }
            } else {
                defined.insert(sym);
            }
        }
    }
    Ok((defined, undefined))
}
