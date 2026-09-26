//! Worst-case stack depth of a PIC module, read from the compiler's own
//! assembly.
//!
//! A module steps on a stack it does not own, so the composer admits the
//! deepest it can go before a device runs it. The figure comes from the same
//! compile that produces the object: `rustc --emit=obj,asm` writes both from
//! one code generation, and the assembly carries what the object has lost —
//! each function's frame and each call by name.
//!
//! - **Frames.** On 32-bit Arm the unwind directives LLVM writes beside every
//!   prologue (`.save`, `.vsave`, `.pad`) are the frame, exactly. The aarch64
//!   bare-metal target writes no unwind information, so there the frame is the
//!   sum of the function's stack-pointer decrements (`sub sp, sp, #n`,
//!   pre-indexed `stp`/`str` to `[sp, #-n]!`).
//! - **Calls.** `bl` is a call: the callee's depth stacks on the caller's
//!   frame. A branch to a function is a tail call: the caller's frame is gone
//!   before it, so the callee's depth stands alone.
//! - **Indirect calls** (`blx rN`, `blr xN`, and their tail forms) reach
//!   either the kernel — syscalls, whose frames are the kernel's stack
//!   reserve, not the module's — or a function whose address the module
//!   takes. Each is charged the deepest such function, one level deep. Stored
//!   pointer tables are refused by the module build, so an address a module
//!   takes appears in its code, where this reads it. A taken function is also
//!   an entry point, since the kernel may call it back.
//!
//! What has no bound here is refused rather than guessed — recursion, a frame
//! sized at run time, a call to a function the module does not contain — and
//! such a module declares its depth instead. A callback reached through
//! another callback is the one path this does not follow; the scheduler's
//! stack fence reports it on the device.

use std::collections::{HashMap, HashSet};

/// The instruction set the assembly is written in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Isa {
    /// Thumb-2 / Thumb-1 (rp2350, rp2040).
    Thumb,
    /// AArch64 (bcm2712).
    Aarch64,
}

impl Isa {
    /// The instruction set a module target triple compiles to, or `None` for
    /// one this module does not read (wasm).
    pub fn for_target(triple: &str) -> Option<Self> {
        if triple.starts_with("thumb") {
            Some(Isa::Thumb)
        } else if triple.starts_with("aarch64") {
            Some(Isa::Aarch64)
        } else {
            None
        }
    }
}

/// The deepest path through a module, from one of its entry points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Depth {
    /// Bytes of stack the path uses, entry frame included.
    pub bytes: u32,
    /// The functions along it, entry first.
    pub path: Vec<String>,
}

#[derive(Default)]
struct Function {
    frame: u32,
    calls: Vec<String>,
    tail_calls: Vec<String>,
    indirect: bool,
    indirect_tail: bool,
    /// Why this function's frame cannot be bounded, if it cannot.
    unbounded: Option<String>,
}

/// The module's entry points: every `module_*` function it defines, which is
/// every function the kernel calls into.
pub fn entry_points(asm: &str) -> Vec<String> {
    let mut out: Vec<String> = asm
        .lines()
        .filter_map(|l| {
            let rest = l.trim().strip_prefix(".type")?.trim();
            let (sym, kind) = rest.split_once(',')?;
            let kind = kind.trim();
            let sym = sym.trim();
            ((kind == "%function" || kind == "@function") && sym.starts_with("module_"))
                .then(|| sym.to_string())
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The deepest any entry point in `roots` reaches, over the module in `asm`.
///
/// `roots` are the functions the kernel calls: every exported `module_*`
/// symbol. A function whose address the module takes is a root as well, since
/// the usual reason to take one is to hand it to the kernel as a callback.
pub fn worst_case(asm: &str, isa: Isa, roots: &[&str]) -> Result<Depth, String> {
    let functions = parse(asm, isa);
    let mut taken: Vec<String> = address_taken(asm, isa, &functions).into_iter().collect();
    taken.sort();
    let none = Depth {
        bytes: 0,
        path: Vec::new(),
    };

    // One level of indirection: an indirect call is charged the deepest
    // address-taken function, measured with its own indirect calls charged
    // nothing. A callback that calls a callback is deeper than this, and is
    // what the scheduler's stack fence reports on the bench.
    let mut local = HashMap::new();
    let mut indirect = none.clone();
    for t in &taken {
        let d = walk(t, &functions, &none, &mut local, &mut Vec::new())?;
        if d.bytes > indirect.bytes {
            indirect = d;
        }
    }

    let mut memo = HashMap::new();
    let mut deepest = none;
    for root in roots
        .iter()
        .copied()
        .chain(taken.iter().map(String::as_str))
    {
        if !functions.contains_key(root) {
            continue;
        }
        let d = walk(root, &functions, &indirect, &mut memo, &mut Vec::new())?;
        if d.bytes > deepest.bytes {
            deepest = d;
        }
    }
    Ok(deepest)
}

fn walk(
    name: &str,
    functions: &HashMap<String, Function>,
    indirect: &Depth,
    memo: &mut HashMap<String, Depth>,
    stack: &mut Vec<String>,
) -> Result<Depth, String> {
    if let Some(d) = memo.get(name) {
        return Ok(d.clone());
    }
    if let Some(at) = stack.iter().position(|s| s == name) {
        let mut cycle: Vec<String> = stack[at..].iter().map(|s| demangle(s)).collect();
        cycle.push(demangle(name));
        return Err(format!("recursion: {}", cycle.join(" -> ")));
    }
    let Some(f) = functions.get(name) else {
        return Err(format!(
            "calls {}, which the module does not contain",
            demangle(name)
        ));
    };
    if let Some(why) = &f.unbounded {
        return Err(format!("{}: {why}", demangle(name)));
    }
    stack.push(name.to_string());
    let mut under = Depth {
        bytes: 0,
        path: Vec::new(),
    };
    let mut beside = under.clone();
    for callee in &f.calls {
        let d = walk(callee, functions, indirect, memo, stack)?;
        if d.bytes > under.bytes {
            under = d;
        }
    }
    for callee in &f.tail_calls {
        let d = walk(callee, functions, indirect, memo, stack)?;
        if d.bytes > beside.bytes {
            beside = d;
        }
    }
    stack.pop();
    if f.indirect && indirect.bytes > under.bytes {
        under = indirect.clone();
    }
    if f.indirect_tail && indirect.bytes > beside.bytes {
        beside = indirect.clone();
    }

    let mut path = vec![name.to_string()];
    let result = if beside.bytes > f.frame + under.bytes {
        path.extend(beside.path);
        Depth {
            bytes: beside.bytes,
            path,
        }
    } else {
        path.extend(under.path);
        Depth {
            bytes: f.frame + under.bytes,
            path,
        }
    };
    memo.insert(name.to_string(), result.clone());
    Ok(result)
}

/// Split the assembly into functions: every symbol typed `%function` /
/// `@function`, from its label to the next function's.
fn parse(asm: &str, isa: Isa) -> HashMap<String, Function> {
    let names: HashSet<&str> = asm
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix(".type")?.trim();
            let (sym, kind) = rest.split_once(',')?;
            let kind = kind.trim();
            (kind == "%function" || kind == "@function").then_some(sym.trim())
        })
        .collect();

    let mut out: HashMap<String, Function> = HashMap::new();
    let mut current: Option<String> = None;
    let mut directives = false;
    let mut jump_table = false;
    let mut pending_register_branch = false;
    for raw in asm.lines() {
        let line = raw.split(['@', ';']).next().unwrap_or("");
        let line = if isa == Isa::Aarch64 {
            raw.split("//").next().unwrap_or("")
        } else {
            line
        };
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(label) = t.strip_suffix(':') {
            if names.contains(label) {
                if let (Some(prev), true) = (current.take(), pending_register_branch) {
                    mark_register_branch(&mut out, &prev, jump_table);
                }
                current = Some(label.to_string());
                out.entry(label.to_string()).or_default();
                directives = false;
                jump_table = false;
                pending_register_branch = false;
            }
            continue;
        }
        // `alias = target` (or `.set alias, target`): one function under two
        // names, as the linker sees it.
        let alias = t.split_once(" = ").or_else(|| {
            t.strip_prefix(".set")
                .and_then(|r| r.trim().split_once(','))
        });
        if let Some((a, b)) = alias {
            let (a, b) = (a.trim(), b.trim());
            if names.contains(a) {
                out.entry(a.to_string())
                    .or_default()
                    .tail_calls
                    .push(b.to_string());
                continue;
            }
        }
        let Some(name) = current.clone() else {
            continue;
        };
        if t.contains(".LJTI") || t.starts_with("tbb") || t.starts_with("tbh") {
            jump_table = true;
        }
        let f = out.get_mut(&name).expect("current function exists");
        let mut words = t.split_whitespace();
        let op = branch_base(words.next().unwrap_or(""), isa);
        let operands: String = words.collect::<Vec<_>>().join(" ");

        match isa {
            Isa::Thumb => match op {
                ".save" | ".vsave" => {
                    if !directives {
                        directives = true;
                        f.frame = 0;
                    }
                    let each = if op == ".save" { 4 } else { 8 };
                    f.frame += each * register_count(&operands);
                }
                ".pad" => {
                    if !directives {
                        directives = true;
                        f.frame = 0;
                    }
                    match immediate(&operands) {
                        Some(n) => f.frame += n,
                        None => f.unbounded = Some(format!("frame padding `{t}`")),
                    }
                }
                "push" | "push.w" | "stmdb" if !directives => {
                    f.frame += 4 * register_count(&operands);
                }
                "vpush" if !directives => {
                    f.frame += 8 * register_count(&operands);
                }
                "sub" | "sub.w" | "subw" if !directives && operands.starts_with("sp,") => {
                    let rest = operands.trim_start_matches("sp,").trim();
                    let rest = rest.strip_prefix("sp,").map(str::trim).unwrap_or(rest);
                    match immediate(rest) {
                        Some(n) => f.frame += n,
                        None => f.unbounded = Some(format!("stack adjusted by a register: `{t}`")),
                    }
                }
                "bl" => call(f, &operands),
                "blx" => {
                    if is_register(&operands, isa) {
                        f.indirect = true;
                    } else {
                        call(f, &operands);
                    }
                }
                "bx" => {
                    if operands.trim() != "lr" {
                        pending_register_branch = true;
                    }
                }
                "mov" if operands.starts_with("pc,") => pending_register_branch = true,
                "b" | "cbz" | "cbnz" => {
                    let tgt = target(&operands);
                    if names.contains(tgt.as_str()) {
                        f.tail_calls.push(tgt);
                    }
                }
                _ => {}
            },
            Isa::Aarch64 => match op {
                "sub" if operands.starts_with("sp, sp,") => {
                    let rest = operands["sp, sp,".len()..].trim();
                    match aarch64_immediate(rest) {
                        Some(n) => f.frame += n,
                        None => f.unbounded = Some(format!("stack adjusted by a register: `{t}`")),
                    }
                }
                "stp" | "str" | "stur" | "stp.q" if operands.contains("[sp, #-") => {
                    if operands.trim_end().ends_with("]!") {
                        let at = operands.find("[sp, #-").expect("checked") + "[sp, #-".len();
                        let n: String = operands[at..]
                            .chars()
                            .take_while(|c| c.is_ascii_digit())
                            .collect();
                        f.frame += n.parse::<u32>().unwrap_or(0);
                    }
                }
                "bl" => call(f, &operands),
                "blr" => f.indirect = true,
                "br" => pending_register_branch = true,
                "b" | "cbz" | "cbnz" | "tbz" | "tbnz" => {
                    let tgt = target(&operands);
                    if names.contains(tgt.as_str()) {
                        f.tail_calls.push(tgt);
                    }
                }
                _ => {}
            },
        }
    }
    if let (Some(prev), true) = (current, pending_register_branch) {
        mark_register_branch(&mut out, &prev, jump_table);
    }
    out
}

/// A direct call. Thumb-1 also uses `bl` as a long branch within a
/// function, to a local `.L` label; that is not a call.
fn call(f: &mut Function, operands: &str) {
    let tgt = target(operands);
    if !tgt.starts_with(".L") {
        f.calls.push(tgt);
    }
}

/// A branch through a register leaves the function unless it is the
/// function's own jump table.
fn mark_register_branch(out: &mut HashMap<String, Function>, name: &str, jump_table: bool) {
    if !jump_table {
        if let Some(f) = out.get_mut(name) {
            f.indirect_tail = true;
        }
    }
}

/// Functions whose address the module takes: any mention of a function's
/// name that is neither its own label, a symbol directive, nor the target of
/// a direct call or branch.
fn address_taken(asm: &str, isa: Isa, functions: &HashMap<String, Function>) -> HashSet<String> {
    let mut out = HashSet::new();
    for raw in asm.lines() {
        let t = raw.trim();
        if t.is_empty() || t.ends_with(':') {
            continue;
        }
        let mut words = t.split_whitespace();
        let first = words.next().unwrap_or("");
        let op = branch_base(first, isa);
        if matches!(
            op,
            ".type"
                | ".size"
                | ".globl"
                | ".global"
                | ".hidden"
                | ".weak"
                | ".section"
                | ".file"
                | ".protected"
                | ".local"
                | ".set"
        ) || matches!(
            op,
            "bl" | "blx" | "blr" | "b" | "cbz" | "cbnz" | "tbz" | "tbnz"
        ) {
            continue;
        }
        for token in
            t.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '$'))
        {
            if !token.is_empty() && functions.contains_key(token) {
                out.insert(token.to_string());
            }
        }
    }
    out
}

/// A branch or call mnemonic without its condition and width suffix
/// (`bleq` → `bl`, `bne.w` → `b`, `b.ne` → `b`); any other mnemonic as is.
fn branch_base(op: &str, isa: Isa) -> &str {
    match isa {
        Isa::Thumb => {
            let bare = op
                .strip_suffix(".w")
                .or_else(|| op.strip_suffix(".n"))
                .unwrap_or(op);
            for base in ["blx", "bl", "bx", "b"] {
                if let Some(rest) = bare.strip_prefix(base) {
                    if rest.is_empty() || CONDITIONS.contains(&rest) {
                        return base;
                    }
                }
            }
            op
        }
        Isa::Aarch64 => {
            if op.starts_with("b.") {
                "b"
            } else {
                op
            }
        }
    }
}

const CONDITIONS: [&str; 17] = [
    "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
    "al",
];

/// The branch target: the last operand, which is the label for every form
/// read here (`cbz r0, label`, `tbz w0, #3, label`).
fn target(operands: &str) -> String {
    let last = operands.rsplit(',').next().unwrap_or("").trim();
    let last = last.split('(').next().unwrap_or(last);
    last.trim_start_matches('#').to_string()
}

fn is_register(operands: &str, isa: Isa) -> bool {
    let o = operands.trim();
    match isa {
        Isa::Thumb => {
            (o.starts_with('r') && o[1..].chars().all(|c| c.is_ascii_digit()))
                || matches!(o, "ip" | "lr" | "sb" | "sl" | "fp")
        }
        Isa::Aarch64 => o.starts_with('x'),
    }
}

/// Registers in a `{r4, r5, r6}` or `{r4-r7}` list.
fn register_count(list: &str) -> u32 {
    let inner = list.trim().trim_start_matches('{').trim_end_matches('}');
    inner
        .split(',')
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(|r| match r.split_once('-') {
            Some((a, b)) => {
                let n = |s: &str| {
                    s.trim_start_matches(|c: char| c.is_ascii_alphabetic())
                        .parse::<u32>()
                        .unwrap_or(0)
                };
                n(b).saturating_sub(n(a)) + 1
            }
            None => 1,
        })
        .sum()
}

/// A `#n` immediate, decimal or hex.
fn immediate(s: &str) -> Option<u32> {
    let s = s.trim().strip_prefix('#')?;
    let s = s.split_whitespace().next()?;
    match s.strip_prefix("0x") {
        Some(h) => u32::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// An aarch64 `#n` or `#n, lsl #12` immediate.
fn aarch64_immediate(s: &str) -> Option<u32> {
    let (imm, shift) = match s.split_once(',') {
        Some((a, b)) => (a, Some(b.trim())),
        None => (s, None),
    };
    let n = immediate(imm)?;
    match shift {
        None => Some(n),
        Some("lsl #12") => Some(n << 12),
        Some(_) => None,
    }
}

/// A readable name for a report: the Rust path of a legacy-mangled symbol,
/// without its hash, or the symbol itself.
pub fn demangle(sym: &str) -> String {
    let Some(mut rest) = sym.strip_prefix("_ZN") else {
        return sym.to_string();
    };
    let mut parts = Vec::new();
    while let Some(c) = rest.chars().next() {
        if !c.is_ascii_digit() {
            break;
        }
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        let Ok(n) = digits.parse::<usize>() else {
            break;
        };
        rest = &rest[digits.len()..];
        if rest.len() < n {
            break;
        }
        let part = &rest[..n];
        rest = &rest[n..];
        if !(part.starts_with('h') && part.len() == 17) {
            parts.push(
                part.replace("$LT$", "<")
                    .replace("$GT$", ">")
                    .replace("..", "::"),
            );
        }
    }
    if parts.is_empty() {
        sym.to_string()
    } else {
        parts.join("::")
    }
}
