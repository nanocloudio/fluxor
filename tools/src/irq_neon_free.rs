//! `fluxor ci` phase `irq-neon-free`: the AArch64 kernel's own interrupt path
//! touches no FP/SIMD register.
//!
//! The EL1 IRQ vector saves general registers only, so any vector register,
//! FPSR or FPCR the kernel's IRQ path writes is a value of the interrupted
//! code lost. Module code runs from IRQ context only through
//! `fluxor_tier2_isr_frame`, which keeps the whole FP/SIMD state around it;
//! everything else on the path must be scalar. The compiler is free to emit
//! SIMD anywhere on a `+neon` target, its `memset`/`memcpy` included, so
//! this is checked on the linked image, not the source.
//!
//! For every kernel target built for `aarch64-unknown-none` (each such
//! board, and the UEFI host), the phase links the kernel
//! (`tools/firmware.sh`), disassembles it, and walks every direct
//! branch from the IRQ entry points. It fails when a reached function names
//! a vector register (`v`, `q`, `d`, `s`, `h`, `b`) or FPSR/FPCR, when a
//! reached function branches through a register without being declared in
//! [`INDIRECT`], or when an entry point or declared target names nothing.
//! The walk stops at the frame (the one function allowed vector registers)
//! and at the panic path, which never returns to the interrupted code.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

/// Where the IRQ path starts: the vector's handler, and the two kernel
/// functions it reaches that the build keeps out of line for this walk.
pub const ROOTS: &[&str] = &[
    "irq_handler",
    "fluxor::kernel::exec::isr_tier::isr_tier2_trampoline",
    "fluxor::kernel::ipc::event::event_signal_from_isr",
];

/// The functions allowed FP/SIMD registers. The walk does not enter them.
pub const ALLOWED: &[&str] = &["fluxor_tier2_isr_frame"];

/// Functions on the IRQ path that branch through a register, with every
/// function the register can hold. A target that is not in a given image
/// belongs to another platform; each must be in at least one.
pub const INDIRECT: &[IndirectSite] = &[
    IndirectSite {
        function: "irq_handler",
        what: "the registered IRQ multiplexer (`gic::irq_mux`)",
        targets: &["fluxor::pcie1_msi_mux"],
    },
    IndirectSite {
        function: "fluxor::kernel::exec::isr_tier::isr_tier2_trampoline",
        what: "HAL `core_id` and `read_cycle_count`",
        targets: &[
            "fluxor::bcm_core_id",
            "fluxor::bcm_read_cycle_count",
            "fluxor::hal::core_id",
            "fluxor::hal::read_cycle_count",
        ],
    },
    IndirectSite {
        function: "fluxor::kernel::ipc::event::event_signal_from_isr",
        what: "HAL `wake_scheduler`",
        targets: &["fluxor::bcm_wake_scheduler", "fluxor::hal::wake_scheduler"],
    },
];

/// The panic path: it never returns to the interrupted code, so what it
/// does to the vector registers is not observable there.
const DIVERGING_PREFIXES: &[&str] = &[
    "core::panicking::",
    "core::slice::index::slice_",
    "core::option::unwrap_failed",
    "core::option::expect_failed",
    "core::result::unwrap_failed",
    "core::cell::panic_already",
];

/// A function on the IRQ path that calls through a pointer.
#[derive(Debug, Clone, Copy)]
pub struct IndirectSite {
    /// The function holding the indirect branch.
    pub function: &'static str,
    /// What the pointer is.
    pub what: &'static str,
    /// Every function the pointer can hold, across platforms.
    pub targets: &'static [&'static str],
}

/// The walk's rules: entry points, the functions allowed vector registers,
/// and the declared indirect branches.
#[derive(Debug, Clone, Copy)]
pub struct Spec<'a> {
    pub roots: &'a [&'a str],
    pub allowed: &'a [&'a str],
    pub indirect: &'a [IndirectSite],
}

impl Spec<'static> {
    /// The kernel's rules.
    pub const KERNEL: Spec<'static> = Spec {
        roots: ROOTS,
        allowed: ALLOWED,
        indirect: INDIRECT,
    };
}

/// One instruction: mnemonic and operands, comments removed.
struct Insn {
    addr: String,
    mnemonic: String,
    operands: String,
}

/// What one image's walk found.
#[derive(Debug, Default)]
pub struct Walk {
    /// Problems, one line each.
    pub problems: Vec<String>,
    /// Declared indirect targets found in this image.
    pub targets_found: BTreeSet<&'static str>,
    /// Functions reached.
    pub reached: usize,
}

/// `name` as source spells it: without the ` (.llvm.<n>)` suffix of a
/// symbol LTO promoted, and without the `::h<16 hex>` hash `--demangle`
/// leaves on legacy Rust symbols.
fn strip_hash(name: &str) -> &str {
    let name = match name.find(" (.llvm.") {
        Some(pos) => &name[..pos],
        None => name,
    };
    if let Some(pos) = name.rfind("::h") {
        let tail = &name[pos + 3..];
        if tail.len() == 16 && tail.bytes().all(|b| b.is_ascii_hexdigit()) {
            return &name[..pos];
        }
    }
    name
}

/// Parse `objdump -d --demangle --no-show-raw-insn` output into functions.
fn parse(disasm: &str) -> BTreeMap<String, Vec<Insn>> {
    let mut funcs: BTreeMap<String, Vec<Insn>> = BTreeMap::new();
    let mut cur: Option<String> = None;
    for line in disasm.lines() {
        let trimmed = line.trim_end();
        // Function header: `<hex> <name>:`
        if let Some(rest) = trimmed.strip_suffix(">:") {
            if let Some((addr, name)) = rest.split_once(" <") {
                if !addr.is_empty() && addr.bytes().all(|b| b.is_ascii_hexdigit()) {
                    let name = strip_hash(name).to_string();
                    funcs.entry(name.clone()).or_default();
                    cur = Some(name);
                    continue;
                }
            }
        }
        // Instruction: `  <hex>:  <mnemonic>\t<operands>`
        let Some(name) = cur.as_ref() else { continue };
        let Some((addr, body)) = line.trim_start().split_once(':') else {
            continue;
        };
        if addr.is_empty() || !addr.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let body = body.trim();
        let (mnemonic, operands) = match body.split_once(char::is_whitespace) {
            Some((m, o)) => (m, o.trim()),
            None => (body, ""),
        };
        if mnemonic.is_empty() {
            continue;
        }
        let operands = operands.split("//").next().unwrap_or("").trim();
        if let Some(insns) = funcs.get_mut(name) {
            insns.push(Insn {
                addr: addr.to_string(),
                mnemonic: mnemonic.to_string(),
                operands: operands.to_string(),
            });
        }
    }
    funcs
}

/// The branch target an operand list names (`0x1234 <sym+0x10>` → `sym`),
/// or `None` when it names a position inside a function.
fn direct_target(operands: &str) -> Option<String> {
    let start = operands.find('<')?;
    let end = operands[start..].find('>')? + start;
    let sym = &operands[start + 1..end];
    if sym.contains('+') {
        return None;
    }
    Some(strip_hash(sym).to_string())
}

fn is_branch(mnemonic: &str) -> bool {
    matches!(mnemonic, "b" | "bl" | "cbz" | "cbnz" | "tbz" | "tbnz") || mnemonic.starts_with("b.")
}

fn is_indirect(mnemonic: &str) -> bool {
    matches!(mnemonic, "blr" | "br" | "blraa" | "blrab" | "braa" | "brab")
}

/// The FP/SIMD register an instruction names, if any. A system-register
/// move names one only as FPSR or FPCR; its other operands are system
/// register encodings (`S3_3_C9_C13_0`), not vector registers.
fn simd_register(mnemonic: &str, operands: &str) -> Option<String> {
    if matches!(mnemonic, "mrs" | "msr") {
        let lower = operands.to_ascii_lowercase();
        return ["fpcr", "fpsr"]
            .into_iter()
            .find(|r| {
                lower
                    .split(|c: char| !c.is_ascii_alphanumeric())
                    .any(|t| t == *r)
            })
            .map(str::to_string);
    }
    // Symbol names in `<...>` are not operands.
    let mut text = String::with_capacity(operands.len());
    let mut depth = 0usize;
    for c in operands.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => text.push(c),
            _ => {}
        }
    }
    for token in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        let lower = token.to_ascii_lowercase();
        if lower == "fpcr" || lower == "fpsr" {
            return Some(lower);
        }
        let mut chars = lower.chars();
        let Some(class) = chars.next() else { continue };
        if !matches!(class, 'v' | 'q' | 'd' | 's' | 'h' | 'b') {
            continue;
        }
        let digits = chars.as_str();
        if digits.is_empty() || digits.len() > 2 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if digits.parse::<u32>().is_ok_and(|n| n < 32) {
            return Some(lower);
        }
    }
    None
}

fn diverges(name: &str) -> bool {
    name.contains("rust_begin_unwind") || DIVERGING_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Walk one image's disassembly under `spec`.
pub fn walk(disasm: &str, spec: &Spec<'_>) -> Walk {
    let funcs = parse(disasm);
    let mut out = Walk::default();
    let indirect: BTreeMap<&str, &IndirectSite> =
        spec.indirect.iter().map(|s| (s.function, s)).collect();

    // (function, the function that reached it)
    let mut stack: Vec<(String, Option<String>)> = Vec::new();
    for root in spec.roots {
        if funcs.contains_key(*root) {
            stack.push((root.to_string(), None));
        } else {
            out.problems.push(format!(
                "entry point `{root}` is not in the image (inlined or renamed): the walk \
                 would not cover it"
            ));
        }
    }
    for site in spec.indirect {
        for t in site.targets {
            if funcs.contains_key(*t) {
                out.targets_found.insert(t);
            }
        }
    }

    let mut parent: BTreeMap<String, Option<String>> = BTreeMap::new();
    let path_to = |parent: &BTreeMap<String, Option<String>>, f: &str| -> String {
        let mut chain = vec![f.to_string()];
        let mut at = parent.get(f).cloned().flatten();
        while let Some(p) = at {
            at = parent.get(&p).cloned().flatten();
            chain.push(p);
        }
        chain.reverse();
        chain.join(" -> ")
    };

    while let Some((f, from)) = stack.pop() {
        if parent.contains_key(&f) {
            continue;
        }
        let Some(insns) = funcs.get(&f) else { continue };
        parent.insert(f.clone(), from);
        if spec.allowed.contains(&f.as_str()) || diverges(&f) {
            continue;
        }
        if let Some(insn) = insns
            .iter()
            .find(|i| !is_branch(&i.mnemonic) && simd_register(&i.mnemonic, &i.operands).is_some())
        {
            out.problems.push(format!(
                "`{}` uses {} (`{} {}` at 0x{}), reached by {}",
                f,
                simd_register(&insn.mnemonic, &insn.operands).unwrap_or_default(),
                insn.mnemonic,
                insn.operands,
                insn.addr,
                path_to(&parent, &f)
            ));
        }
        let mut undeclared = false;
        for insn in insns {
            if is_branch(&insn.mnemonic) {
                if let Some(t) = direct_target(&insn.operands) {
                    if t != f {
                        stack.push((t, Some(f.clone())));
                    }
                }
            } else if is_indirect(&insn.mnemonic) {
                match indirect.get(f.as_str()) {
                    Some(site) => {
                        for t in site.targets {
                            if funcs.contains_key(*t) {
                                stack.push((t.to_string(), Some(f.clone())));
                            }
                        }
                    }
                    None => undeclared = true,
                }
            }
        }
        if undeclared {
            out.problems.push(format!(
                "`{}` branches through a register and is not declared in \
                 irq_neon_free::INDIRECT, so the walk cannot follow it; reached by {}",
                f,
                path_to(&parent, &f)
            ));
        }
    }
    out.reached = parent.len();
    out
}

/// Every kernel target built for `aarch64-unknown-none`, by the id
/// `tools/firmware.sh` takes: each board, and each host that is a kernel of
/// its own (UEFI). Each platform's IRQ path is in exactly one of them.
fn aarch64_kernels(project_root: &Path) -> Vec<String> {
    use crate::target::TargetKind;
    let mut ids: Vec<String> = crate::target::list_targets(project_root)
        .into_iter()
        .filter_map(|name| crate::target::load_target(&name, project_root).ok())
        .filter(|t| {
            t.build
                .as_ref()
                .is_some_and(|b| b.rust_target == "aarch64-unknown-none")
        })
        .filter_map(|t| match t.kind {
            TargetKind::Board => t.board_id,
            TargetKind::Host => Some(t.id),
            TargetKind::Silicon => None,
        })
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// Disassemble `elf` with the toolchain's `rust-objdump`, which reads AArch64
/// on any host.
pub fn disassemble(elf: &Path) -> Result<String, String> {
    let out = Command::new("rust-objdump")
        .args(["-d", "--demangle", "--no-show-raw-insn"])
        .arg(elf)
        .output()
        .map_err(|e| format!("rust-objdump: {e} (cargo install cargo-binutils)"))?;
    if !out.status.success() {
        return Err(format!(
            "rust-objdump {}: {}",
            elf.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("rust-objdump output: {e}"))
}

/// Check already-built images under the kernel's rules: `(label, elf)`.
pub fn check_images(images: &[(String, std::path::PathBuf)]) -> Result<String, String> {
    let mut failures = Vec::new();
    let mut found: BTreeSet<&'static str> = BTreeSet::new();
    let mut summary = Vec::new();
    for (label, elf) in images {
        let disasm = match disassemble(elf) {
            Ok(d) => d,
            Err(e) => {
                failures.push(format!("{label}: {e}"));
                continue;
            }
        };
        let w = walk(&disasm, &Spec::KERNEL);
        found.extend(w.targets_found.iter().copied());
        summary.push(format!("{label}: {} functions", w.reached));
        failures.extend(w.problems.into_iter().map(|p| format!("{label}: {p}")));
    }
    if failures.is_empty() && !images.is_empty() {
        for site in INDIRECT {
            for t in site.targets {
                if !found.contains(t) {
                    failures.push(format!(
                        "declared target `{t}` of {} in `{}` is in no image: rename or remove it",
                        site.what, site.function
                    ));
                }
            }
        }
    }
    if failures.is_empty() {
        Ok(summary.join(", "))
    } else {
        Err(failures.join("\n  "))
    }
}

/// The phase: link every `aarch64-unknown-none` kernel and check its IRQ
/// path.
pub fn run(project_root: &Path, verbose: bool) -> Result<(), String> {
    let kernels = aarch64_kernels(project_root);
    if kernels.is_empty() {
        return Err("no aarch64-unknown-none kernel targets in the target registry".into());
    }
    let mut images = Vec::new();
    let mut failures = Vec::new();
    for id in &kernels {
        let mut cmd = Command::new(crate::ci::KERNEL_LINK_SCRIPT);
        cmd.arg(id).current_dir(project_root);
        let out = crate::ci::with_running_cli(&mut cmd)
            .output()
            .map_err(|e| format!("firmware.sh {id}: {e}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let tail: Vec<&str> = err.lines().rev().take(12).collect();
            failures.push(format!(
                "{id}: kernel image build failed\n    {}",
                tail.into_iter().rev().collect::<Vec<_>>().join("\n    ")
            ));
            continue;
        }
        // The target-scoped copy: targets sharing a triple overwrite cargo's.
        images.push((
            id.clone(),
            project_root.join(format!("target/{id}/firmware.elf")),
        ));
    }
    if !failures.is_empty() {
        return Err(failures.join("; "));
    }
    let summary = check_images(&images)?;
    if verbose {
        println!("  irq-neon-free: {summary}");
    }
    Ok(())
}
