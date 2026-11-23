//! The four crates every module links — `fluxor_abi`, `fluxor_sdk`,
//! `fluxor_rt` and `fluxor_contracts` — built once per module ABI as rlibs.
//!
//! Each is compiled with the module build's own flags, one codegen unit (so
//! a crate is one object and its `#[used]` statics travel with whatever the
//! module pulls from it), a fixed `-C metadata` (so the mangled names a
//! module's assembly calls are the names the rlib's assembly defines) and its
//! source path remapped to the crate name (so panic locations carry a short
//! path, not this machine's). The source comes from the crate's own tree in
//! fluxor and from the synced `target/fluxor/<name>` everywhere else.
//!
//! A crate's features are the module build's choice, not the crate's
//! defaults: a module has no global allocator, so `fluxor_contracts` is
//! compiled with `alloc` off and its heap-owning items (`graph::encode`,
//! `graph::plan::compose`, the owner-log records) do not exist for a module.
//! The allocation-free codec and composition passes do.
//!
//! A built rlib is held to what a module is held to. A crate whose every
//! item a module may carry ([`PicCheck::Whole`]) has every object pass
//! `relocation_refusals` when it is built; a crate that also serves the
//! kernel and the tools ([`PicCheck::AsLinked`]) has what each module's link
//! keeps of it pass, judged from the linker's garbage-collection report. The
//! four together leave no symbol undefined —
//! as a set, since `fluxor_abi`, `fluxor_sdk` and `fluxor_contracts` call the
//! `memcpy` and `__aeabi_*` helpers only `fluxor_rt` defines. A stamp over the crate
//! sources, the compiler and the flags skips a rebuild that would produce the
//! same bytes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use super::{
    cfg_abi_args, relocation_refusals, relocation_refusals_in, run_step, AbiSpec,
    PIC_RELOCATION_MODEL,
};
use crate::error::{Error, Result};

/// How a crate's objects are held to the position-independence rules.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PicCheck {
    /// Every object, when the rlib is built: nothing in the crate is
    /// anything a module may not carry.
    Whole,
    /// What each module's link keeps: the crate also holds code the kernel
    /// and the tools use (formatting, tables of names), which a module that
    /// never reaches it does not carry.
    AsLinked,
}

/// One crate a module links.
struct ModuleCrate {
    /// The published and synced name: `target/fluxor/<dir_name>`.
    dir_name: &'static str,
    /// The crate name a module imports.
    name: &'static str,
    /// The crate's tree in the fluxor checkout, relative to its root.
    in_tree: &'static str,
    /// The features the crate declares, for `--check-cfg`.
    declared: &'static [&'static str],
    pic: PicCheck,
}

/// The crates, in dependency order: each may use only those before it. No
/// declared feature is enabled for a module.
const CRATES: [ModuleCrate; 4] = [
    ModuleCrate {
        dir_name: "fluxor-abi",
        name: "fluxor_abi",
        in_tree: "crates/fluxor-abi",
        declared: &[],
        pic: PicCheck::Whole,
    },
    ModuleCrate {
        dir_name: "fluxor-sdk",
        name: "fluxor_sdk",
        in_tree: "crates/fluxor-sdk",
        declared: &[],
        pic: PicCheck::Whole,
    },
    ModuleCrate {
        dir_name: "fluxor-rt",
        name: "fluxor_rt",
        in_tree: "crates/fluxor-rt",
        declared: &[],
        pic: PicCheck::Whole,
    },
    ModuleCrate {
        dir_name: "fluxor-contracts",
        name: "fluxor_contracts",
        in_tree: "contracts",
        declared: &["alloc"],
        pic: PicCheck::AsLinked,
    },
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
        for (c, rlib) in CRATES.iter().zip(&self.rlibs) {
            args.push("--extern".into());
            args.push(format!("{}={}", c.name, rlib.display()));
        }
        args
    }

    /// The rlibs, for the module link.
    pub fn rlibs(&self) -> &[PathBuf] {
        &self.rlibs
    }

    /// The assembly of all four, for the module's stack walk.
    pub fn asm(&self) -> &[PathBuf] {
        &self.asm
    }

    /// Hold what module `module`'s link kept of each [`PicCheck::AsLinked`]
    /// crate to the position-independence rules. `report` is the link's
    /// `--trace --trace` and `--print-gc-sections` output: of each member the
    /// link loaded, every section it does not name as removed is in the
    /// module.
    pub fn check_as_linked(&self, report: &str, module: &str) -> Result<()> {
        let removed = gc_removed(report)?;
        let none = BTreeSet::new();
        for (c, rlib) in CRATES.iter().zip(&self.rlibs) {
            if c.pic != PicCheck::AsLinked {
                continue;
            }
            for (member, obj) in ar_objects(&std::fs::read(rlib)?)? {
                let file = format!("{}({member})", rlib.display());
                // `--trace --trace` names each archive member the link loaded
                // on a line of its own, `<archive>(<member>)` from lld and
                // `(<archive>)<member>` from GNU ld; a member never loaded is
                // not in the module.
                let gnu = format!("({}){member}", rlib.display());
                if !report
                    .lines()
                    .any(|l| l.trim_end() == file || l.trim_end() == gnu)
                {
                    continue;
                }
                let gone = removed.get(&file).unwrap_or(&none);
                relocation_refusals_in(&obj, &|sec| !gone.contains(sec))?
                    .into_result(&format!("{module} (through {})", c.name))?;
            }
        }
        Ok(())
    }
}

/// The sections a link removed, by input file (`<archive>(<member>)` for an
/// archive member), from its `--print-gc-sections` report. GNU ld writes
/// `removing unused section '<section>' in file '<file>'`, lld
/// `removing unused section <file>:(<section>)`. A removal line in neither
/// shape is an error: an unread line would count a removed section as kept,
/// and that refuses a module for code it does not carry.
fn gc_removed(report: &str) -> Result<std::collections::BTreeMap<String, BTreeSet<String>>> {
    const MARK: &str = "removing unused section ";
    let mut out: std::collections::BTreeMap<String, BTreeSet<String>> = Default::default();
    for line in report.lines() {
        let Some(at) = line.find(MARK) else {
            continue;
        };
        let rest = &line[at + MARK.len()..];
        let parsed = if let Some(r) = rest.strip_prefix('\'') {
            r.split_once("' in file '")
                .and_then(|(sec, file)| Some((file.strip_suffix('\'')?, sec)))
        } else {
            rest.rfind(":(")
                .and_then(|k| Some((&rest[..k], rest[k + 2..].strip_suffix(')')?)))
        };
        let (file, section) = parsed.ok_or_else(|| {
            Error::Module(format!(
                "linker garbage-collection report: unread line `{line}`"
            ))
        })?;
        out.entry(file.to_string())
            .or_default()
            .insert(section.to_string());
    }
    Ok(out)
}

/// Where crate `c` is compiled from: its tree in this checkout (a tree whose
/// manifest names the package, so another project's `contracts/` is never
/// taken for it), or the source tree `fluxor sync` staged.
fn crate_dir(project_root: &Path, c: &ModuleCrate) -> Option<PathBuf> {
    let in_tree = project_root.join(c.in_tree);
    let package = format!("name = \"{}\"", c.dir_name);
    let ours = std::fs::read_to_string(in_tree.join("Cargo.toml")).is_ok_and(|m| {
        m.lines()
            .any(|l| l.split_whitespace().collect::<Vec<_>>().join(" ") == package)
    });
    let staged = project_root.join("target/fluxor").join(c.dir_name);
    [ours.then_some(in_tree), Some(staged)]
        .into_iter()
        .flatten()
        .find(|d| d.join("src/lib.rs").is_file())
}

/// The module link script, which ships with `fluxor-rt`.
pub fn module_ld(project_root: &Path) -> Option<PathBuf> {
    CRATES
        .iter()
        .find(|c| c.dir_name == "fluxor-rt")
        .and_then(|c| crate_dir(project_root, c))
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
        .filter_map(|c| crate_dir(project_root, c))
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

/// The `--check-cfg` that declares crate `c`'s features: a `cfg(feature)`
/// the crate does not declare stays an error.
fn check_cfg(c: &ModuleCrate) -> [String; 2] {
    let values: Vec<String> = c.declared.iter().map(|f| format!("\"{f}\"")).collect();
    [
        "--check-cfg".into(),
        format!("cfg(feature, values({}))", values.join(", ")),
    ]
}

/// Build (or find current) the four rlibs for `spec` under
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
    for c in &CRATES {
        let (dir_name, name) = (c.dir_name, c.name);
        let check_cfg = check_cfg(c);
        let src = crate_dir(project_root, c).ok_or_else(|| {
            Error::Module(format!(
                "crate `{dir_name}` not found at {} or under target/fluxor/ (run `fluxor sync`)",
                c.in_tree
            ))
        })?;
        chain.update(name.as_bytes());
        chain.update(spec.module_target.as_bytes());
        chain.update(rustc.as_bytes());
        for f in flags.iter().chain(&check_cfg) {
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
                .args(&check_cfg)
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
            if spec.linker.is_some() && c.pic == PicCheck::Whole {
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

/// Refuse when the [`PicCheck::Whole`] rlibs call a symbol none of the four
/// defines: a module linking them would fail at `--no-undefined`, every one
/// of them, for a reason no module could fix. What a [`PicCheck::AsLinked`]
/// crate calls is the module's link's to answer: its `--no-undefined` judges
/// the sections the module keeps, so a module that never reaches the crate's
/// formatting does not need what that formatting calls.
fn closed_as_a_set(libs: &SdkLibs) -> Result<()> {
    let mut defined = BTreeSet::new();
    let mut undefined = BTreeSet::new();
    for (c, rlib) in CRATES.iter().zip(&libs.rlibs) {
        for (_, obj) in ar_objects(&std::fs::read(rlib)?)? {
            let (d, u) = elf_symbols(&obj)?;
            defined.extend(d);
            if c.pic == PicCheck::Whole {
                undefined.extend(u);
            }
        }
    }
    let open: Vec<String> = undefined.difference(&defined).cloned().collect();
    if open.is_empty() {
        return Ok(());
    }
    Err(Error::Module(format!(
        "the fluxor_abi/fluxor_sdk/fluxor_rt rlibs call {} symbol(s) none of the module crates defines: {} \
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
    let mut defined = BTreeSet::new();
    let mut undefined = BTreeSet::new();
    each_symbol(obj, |sym, info, shndx| {
        let bind = info >> 4;
        if bind != 1 && bind != 2 {
            return; // locals are the object's own business
        }
        if shndx == 0 {
            // A weak reference may stay unresolved; a global one may not.
            if bind == 1 {
                undefined.insert(sym.to_string());
            }
        } else {
            defined.insert(sym.to_string());
        }
    })?;
    Ok((defined, undefined))
}

/// Every function an ELF file defines, local or not: of a linked module,
/// the functions its link kept.
pub(super) fn elf_functions(elf: &[u8]) -> Result<BTreeSet<String>> {
    const STT_FUNC: u8 = 2;
    let mut out = BTreeSet::new();
    each_symbol(elf, |sym, info, shndx| {
        if info & 0xf == STT_FUNC && shndx != 0 {
            out.insert(sym.to_string());
        }
    })?;
    Ok(out)
}

/// Call `f(name, st_info, st_shndx)` for every named symbol of an ELF
/// file's symbol tables.
fn each_symbol(obj: &[u8], mut f: impl FnMut(&str, u8, usize)) -> Result<()> {
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
            let tail = strtab.get(name..).ok_or_else(bad)?;
            let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
            let sym = String::from_utf8_lossy(&tail[..end]);
            if !sym.is_empty() {
                f(&sym, info, shndx);
            }
        }
    }
    Ok(())
}
