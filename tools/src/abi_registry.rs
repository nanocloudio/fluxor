//! The ABI number registry: `crates/fluxor-abi/registry/registry.toml` parsed,
//! validated and emitted as `crates/fluxor-abi/src/registry.rs`.
//!
//! The TOML is the one place an ABI number is written: contract ids,
//! opcode classes and opcodes, grants, errno values, poll bits and
//! the handle word's bit split. The generated file holds only scalar constants and `match`-based
//! lookups, so it mounts into the kernel, the tools, the SDK runtime and
//! every PIC module without putting an absolute address in anyone's
//! `.rodata`. `fluxor abi-regen` writes it; `fluxor abi-regen --check`
//! fails when it is stale.

use crate::error::{Error, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Where the registry lives, relative to the repo root.
pub const REGISTRY_TOML: &str = "crates/fluxor-abi/registry/registry.toml";
/// Where the generated file is written, relative to the repo root.
pub const REGISTRY_GEN: &str = "crates/fluxor-abi/src/registry.rs";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub registry: Header,
    #[serde(default)]
    pub grant: Vec<Grant>,
    #[serde(default)]
    pub errno: Vec<Errno>,
    #[serde(default)]
    pub poll: Vec<Poll>,
    #[serde(default)]
    pub contract: Vec<Contract>,
    #[serde(default)]
    pub msgset: Vec<Msgset>,
    #[serde(default)]
    pub entry_point: Vec<EntryPoint>,
}

/// A function the kernel calls in a module, found by the FNV-1a hash of its
/// name in the `.fmod` export table. These are a module's only exports: every
/// static fact about a module is in its manifest.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryPoint {
    pub name: String,
    /// Every module defines it.
    #[serde(default)]
    pub required: bool,
    pub doc: Option<String>,
}

/// Channel message types that share one TLV header: every value is unique
/// across the set's members, so a fan-in or a mis-wire cannot misparse.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Msgset {
    pub name: String,
    pub members: Vec<String>,
    #[serde(default)]
    pub msg: Vec<Msg>,
    /// The value ranges a member owns. A member that declares any holds
    /// every one of its values inside them and fills each one densely, and
    /// no other member's value falls inside them.
    #[serde(default)]
    pub range: Vec<MsgRange>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MsgRange {
    pub surface: String,
    pub first: u8,
    pub last: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Msg {
    pub surface: String,
    pub name: String,
    pub value: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub semantic_epoch: u32,
    pub max_contracts: u16,
    /// Bit ORed onto an opcode to reach the provider below the caller.
    pub chain_next: u32,
    /// The handle word's fields, high to low below the clear sign bit:
    /// contract, generation, index. They fill the 31 bits.
    pub handle_contract_bits: u32,
    pub handle_generation_bits: u32,
    pub handle_index_bits: u32,
}

/// An op-level grant: a privileged family of ops inside a contract, held by
/// naming it in a manifest's `grants`. Its bit is in the second grant word.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub name: String,
    pub bit: u8,
    /// `"kernel"`: a gated module may not hold it. Absent: it may.
    pub reach: Option<String>,
    /// What holding the grant lets a module do.
    pub doc: Option<String>,
}

/// Most op-level grants: the width of the second grant word.
pub const MAX_GRANTS: u8 = 64;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Errno {
    pub name: String,
    pub value: i32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Poll {
    pub name: String,
    pub bit: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    /// Registry module name; also the manifest spelling when `manifest`.
    pub name: String,
    /// Contract id: the opcode class byte, the vtable index, the bit in
    /// the first grant word and the contract field of its handles.
    pub id: u8,
    /// A module manifest may name it (`requires_contract`, `provides`).
    #[serde(default)]
    pub manifest: bool,
    /// A module may serve it as a provider (`provider_contracts`): the
    /// kernel registers a module for no other contract.
    #[serde(default)]
    pub module_provided: bool,
    /// The grant the contract's ops need unless an op says otherwise:
    /// `"none"`, or a `[[grant]]` name. Absent: the contract's own bit.
    pub grant: Option<String>,
    /// `"kernel"`: a gated module may not hold the contract's own bit.
    pub reach: Option<String>,
    /// `"class"`: routed to the kernel by its opcode class ahead of any
    /// handle. `"edge"`: served by the module at the other end of a graph
    /// edge, reached only through a handle bound to that edge
    /// (`kernel::BIND` with a port). Absent: routed by the handle's
    /// contract.
    pub route: Option<String>,
    #[serde(default)]
    pub op: Vec<Op>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Op {
    pub name: String,
    /// Low byte of the opcode.
    pub op: u8,
    /// Overrides the contract's grant: `"none"`, or a `[[grant]]` name.
    pub grant: Option<String>,
    /// Creates work or a held resource: subject to the owner admission gate.
    #[serde(default)]
    pub admission: bool,
    /// Served to gated modules through the gateway, under this rule.
    pub gate: Option<Gate>,
    /// The op answers an address the kernel granted the caller (an arena,
    /// a resolved lend): never served to a gated module, whose mapping the
    /// answer need not lie in.
    #[serde(default)]
    pub addr_answer: bool,
    /// The op releases the handle it names.
    #[serde(default)]
    pub closes: bool,
    /// The handle the op mints signals its minter: the kernel claims a
    /// doorbell for it and hands the provider the doorbell to ring.
    #[serde(default)]
    pub signals: bool,
    /// Served to gated modules as a `provider_query` key writing at most
    /// this many bytes.
    pub query: Option<usize>,
    /// `"handle"`: on a class-routed contract, this op goes to the handle's
    /// own provider instead (an op every provider answers for its handles).
    pub route: Option<String>,
}

/// The shape of one call: what the handle slot may name, the flat `arg`
/// record (copied in and out for a gated caller, so always bounded) and the
/// one bulk `data` span (checked in place, never copied).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    pub handle: String,
    /// Which way `arg` moves.
    pub arg: String,
    /// Most bytes `arg` may hold: at most [`ARG_MAX`].
    pub max: usize,
    /// Which way `data` moves; absent: no `data` span.
    pub data: Option<String>,
    /// Most bytes `data` may hold: a count, or `"any"` (the caller's own
    /// region bounds it). Required with `data`.
    pub data_max: Option<GateMax>,
}

/// Longest `arg` record any op takes: the gateway's copy for a gated caller.
pub const ARG_MAX: usize = 1024;

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum GateMax {
    Bytes(usize),
    Word(String),
}

const HANDLES: &[(&str, &str)] = &[
    ("global", "Global"),
    ("value", "Value"),
    ("channel", "Channel"),
    ("minted", "Minted"),
    ("mints", "Mints"),
    ("scoped", "Scoped"),
    ("scoped_mints", "ScopedMints"),
    ("minted_mints", "MintedMints"),
];
const ARGS: &[(&str, &str)] = &[
    ("none", "None"),
    ("in", "In"),
    ("out", "Out"),
    ("inout", "InOut"),
];

impl Contract {
    fn module(&self) -> String {
        self.name.replace(['.', '-'], "_")
    }
    fn opcode(&self, op: &Op) -> u32 {
        (u32::from(self.id) << 8) | u32::from(op.op)
    }
    /// The grant `op` needs: `None` for the contract's own bit,
    /// `Some("none")` for nothing, else a `[[grant]]` name.
    fn op_grant<'a>(&'a self, op: &'a Op) -> Option<&'a str> {
        op.grant.as_deref().or(self.grant.as_deref())
    }
}

fn shout(s: &str) -> String {
    s.to_ascii_uppercase().replace(['.', '-'], "_")
}

/// Parse `registry.toml`.
pub fn parse(text: &str) -> Result<Registry> {
    toml::from_str(text).map_err(|e| Error::Config(format!("{REGISTRY_TOML}: {e}")))
}

/// Every rule the registry must satisfy; all violations, not the first.
pub fn validate(r: &Registry) -> Result<()> {
    let mut bad: Vec<String> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    for e in &r.entry_point {
        if !seen.insert(e.name.as_str()) {
            bad.push(format!("entry point `{}` declared twice", e.name));
        }
        if !e.name.starts_with("module_") {
            bad.push(format!("entry point `{}`: names start `module_`", e.name));
        }
        if !hashes.insert(fluxor_abi::wire::fnv1a32(e.name.as_bytes())) {
            bad.push(format!(
                "entry point `{}`: its hash collides with another's",
                e.name
            ));
        }
    }
    let grants: BTreeSet<&str> = r.grant.iter().map(|g| g.name.as_str()).collect();
    let mut seen = BTreeSet::new();
    let mut bits = BTreeSet::new();
    for g in &r.grant {
        if !seen.insert(g.name.as_str()) {
            bad.push(format!("grant `{}` declared twice", g.name));
        }
        if g.bit >= MAX_GRANTS || !bits.insert(g.bit) {
            bad.push(format!(
                "grant `{}`: bit {} is taken or past {}",
                g.name,
                g.bit,
                MAX_GRANTS - 1
            ));
        }
        if g.reach.as_deref().is_some_and(|r| r != "kernel") {
            bad.push(format!("grant `{}`: reach is \"kernel\" or absent", g.name));
        }
        if r.contract.iter().any(|c| c.name == g.name) {
            bad.push(format!("grant `{}` is also a contract's name", g.name));
        }
    }
    let mut granted = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for e in &r.errno {
        if !seen.insert(e.name.as_str()) {
            bad.push(format!("errno `{}` declared twice", e.name));
        }
    }
    if r.registry.chain_next.count_ones() != 1 || r.registry.chain_next <= 0xFFFF {
        bad.push("chain_next is one bit above the 16-bit opcode".to_string());
    }
    let mut seen = BTreeSet::new();
    let mut pbits = BTreeSet::new();
    for p in &r.poll {
        if !seen.insert(p.name.as_str()) || !pbits.insert(p.bit) {
            bad.push(format!(
                "poll `{}`: name or bit {:#x} declared twice",
                p.name, p.bit
            ));
        }
        if p.bit.count_ones() != 1 {
            bad.push(format!("poll `{}`: {:#x} is not one bit", p.name, p.bit));
        }
    }
    let mc = r.registry.max_contracts;
    if !mc.is_power_of_two() || !(2..=128).contains(&mc) {
        bad.push(format!(
            "max_contracts {mc} is not a power of two in 2..=128"
        ));
    }
    let h = &r.registry;
    if h.handle_contract_bits + h.handle_generation_bits + h.handle_index_bits != 31
        || h.handle_generation_bits == 0
        || h.handle_index_bits == 0
    {
        bad.push("the handle word's contract, generation and index bits fill 31".to_string());
    }
    if u32::from(mc) > 1u32 << h.handle_contract_bits.min(16) {
        bad.push(format!(
            "max_contracts {mc} does not fit the handle's {} contract bits",
            h.handle_contract_bits
        ));
    }
    let mut names = BTreeSet::new();
    let mut ids = BTreeMap::new();
    let mut opcodes: BTreeMap<u32, String> = BTreeMap::new();
    for c in &r.contract {
        if !names.insert(c.module()) {
            bad.push(format!("contract `{}` declared twice", c.name));
        }
        if u16::from(c.id) >= mc {
            bad.push(format!(
                "contract `{}`: id {:#x} is not below max_contracts {mc}",
                c.name, c.id
            ));
        }
        if let Some(o) = ids.insert(c.id, c.name.as_str()) {
            bad.push(format!("contract `{}`: id {:#x} is `{o}`'s", c.name, c.id));
        }
        if let Some(g) = c.grant.as_deref() {
            if g != "none" && !grants.contains(g) {
                bad.push(format!("contract `{}`: unknown grant `{g}`", c.name));
            }
        }
        if c.reach.as_deref().is_some_and(|r| r != "kernel") {
            bad.push(format!(
                "contract `{}`: reach is \"kernel\" or absent",
                c.name
            ));
        }
        match c.route.as_deref() {
            None | Some("class") => {}
            Some("edge") => {
                if !c.module_provided || !c.manifest {
                    bad.push(format!(
                        "contract `{}`: an edge contract is module-provided and named in manifests",
                        c.name
                    ));
                }
            }
            Some(_) => bad.push(format!(
                "contract `{}`: route is \"class\", \"edge\" or absent",
                c.name
            )),
        }
        let mut op_names = BTreeSet::new();
        for op in &c.op {
            if !op_names.insert(op.name.as_str()) {
                bad.push(format!("{}::{} declared twice", c.name, op.name));
            }
            if let Some(r) = op.route.as_deref() {
                if r != "handle" || c.route.as_deref() != Some("class") {
                    bad.push(format!(
                        "{}::{}: an op's route is \"handle\", on a class-routed contract",
                        c.name, op.name
                    ));
                }
            }
            let code = c.opcode(op);
            if let Some(o) = opcodes.insert(code, format!("{}::{}", c.name, op.name)) {
                bad.push(format!(
                    "{}::{}: opcode {code:#06x} is {o}'s",
                    c.name, op.name
                ));
            }
            if let Some(g) = op.grant.as_deref() {
                if g != "none" && !grants.contains(g) {
                    bad.push(format!("{}::{}: unknown grant `{g}`", c.name, op.name));
                }
            }
            if let Some(g) = c.op_grant(op) {
                granted.insert(g);
            }
            if let Some(g) = &op.gate {
                if !HANDLES.iter().any(|(k, _)| *k == g.handle) {
                    bad.push(format!(
                        "{}::{}: unknown gate handle `{}`",
                        c.name, op.name, g.handle
                    ));
                }
                if !ARGS.iter().any(|(k, _)| *k == g.arg) {
                    bad.push(format!(
                        "{}::{}: unknown gate arg `{}`",
                        c.name, op.name, g.arg
                    ));
                }
                if g.max > ARG_MAX {
                    bad.push(format!(
                        "{}::{}: arg max {} is past ARG_MAX {ARG_MAX}; bulk bytes go in `data`",
                        c.name, op.name, g.max
                    ));
                }
                if (g.arg == "none") != (g.max == 0) {
                    bad.push(format!(
                        "{}::{}: an op with no arg has max 0, and only it",
                        c.name, op.name
                    ));
                }
                match (g.data.as_deref(), &g.data_max) {
                    (None | Some("none"), None) => {}
                    (Some(d), Some(m)) if d != "none" && ARGS.iter().any(|(k, _)| *k == d) => {
                        if matches!(m, GateMax::Word(w) if w != "any")
                            || matches!(m, GateMax::Bytes(0))
                        {
                            bad.push(format!(
                                "{}::{}: data max is a non-zero count or \"any\"",
                                c.name, op.name
                            ));
                        }
                    }
                    _ => bad.push(format!(
                        "{}::{}: data is in/out/inout with a data_max, or absent without one",
                        c.name, op.name
                    )),
                }
            } else if op.closes {
                bad.push(format!("{}::{}: closes without a gate", c.name, op.name));
            }
            if op.addr_answer && op.gate.is_none() {
                bad.push(format!(
                    "{}::{}: an address answer still declares its shape",
                    c.name, op.name
                ));
            }
            if op.signals
                && !op
                    .gate
                    .as_ref()
                    .is_some_and(|g| g.handle.ends_with("mints"))
            {
                bad.push(format!(
                    "{}::{}: a signalling op mints the handle it signals",
                    c.name, op.name
                ));
            }
            if op.closes && op.gate.as_ref().is_some_and(|g| g.handle != "minted") {
                bad.push(format!(
                    "{}::{}: a closing op names a minted handle",
                    c.name, op.name
                ));
            }
        }
    }
    for g in &r.grant {
        if !granted.contains(g.name.as_str()) {
            bad.push(format!("grant `{}` is needed by no op", g.name));
        }
    }
    for (i, id) in ids.keys().enumerate() {
        if usize::from(*id) != i {
            bad.push(format!(
                "contract ids are not dense: {i:#x} is unassigned below {id:#x}"
            ));
            break;
        }
    }
    let mut sets = BTreeSet::new();
    for m in &r.msgset {
        if !sets.insert(m.name.as_str()) {
            bad.push(format!("msgset `{}` declared twice", m.name));
        }
        let members: BTreeSet<&str> = m.members.iter().map(String::as_str).collect();
        let mut values: BTreeMap<u8, String> = BTreeMap::new();
        let mut msg_names = BTreeSet::new();
        for msg in &m.msg {
            if !members.contains(msg.surface.as_str()) {
                bad.push(format!(
                    "msgset `{}`: `{}` is not a member",
                    m.name, msg.surface
                ));
            }
            if !msg_names.insert((msg.surface.as_str(), msg.name.as_str())) {
                bad.push(format!("{}::{} declared twice", msg.surface, msg.name));
            }
            if let Some(o) = values.insert(msg.value, format!("{}::{}", msg.surface, msg.name)) {
                bad.push(format!(
                    "msgset `{}`: {}::{} takes {:#04x}, which is {o}'s",
                    m.name, msg.surface, msg.name, msg.value
                ));
            }
        }
        for rg in &m.range {
            if !members.contains(rg.surface.as_str()) {
                bad.push(format!(
                    "msgset `{}`: range for `{}`, which is not a member",
                    m.name, rg.surface
                ));
            }
            if rg.first > rg.last {
                bad.push(format!(
                    "msgset `{}`: `{}` range {:#04x}..={:#04x} is empty",
                    m.name, rg.surface, rg.first, rg.last
                ));
                continue;
            }
            for v in rg.first..=rg.last {
                match m.msg.iter().find(|x| x.value == v) {
                    None => bad.push(format!(
                        "msgset `{}`: `{}` range {:#04x}..={:#04x} is not dense: {v:#04x} is unassigned",
                        m.name, rg.surface, rg.first, rg.last
                    )),
                    Some(x) if x.surface != rg.surface => bad.push(format!(
                        "msgset `{}`: {}::{} takes {v:#04x}, inside `{}`'s range",
                        m.name, x.surface, x.name, rg.surface
                    )),
                    Some(_) => {}
                }
            }
        }
        for msg in &m.msg {
            let owned: Vec<&MsgRange> = m
                .range
                .iter()
                .filter(|rg| rg.surface == msg.surface)
                .collect();
            if !owned.is_empty()
                && !owned
                    .iter()
                    .any(|rg| (rg.first..=rg.last).contains(&msg.value))
            {
                bad.push(format!(
                    "msgset `{}`: {}::{} takes {:#04x}, outside every range `{}` declares",
                    m.name, msg.surface, msg.name, msg.value, msg.surface
                ));
            }
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(Error::Config(format!(
            "{REGISTRY_TOML} is invalid:\n  {}",
            bad.join("\n  ")
        )))
    }
}

/// The generated file for a valid registry.
pub fn emit(r: &Registry) -> String {
    let mut o = String::new();
    let w = &mut o;
    let _ = writeln!(
        w,
        "// @generated\n\
         // By `fluxor abi-regen` from `registry.toml`. Edit that file and\n\
         // regenerate; never edit this one.\n\
         //\n\
         // Scalars and `match` lookups only: nothing here places an address in\n\
         // a module's `.rodata`.\n"
    );
    let _ = writeln!(
        w,
        "/// Bumped by hand when a meaning changes without a number changing.\n\
         pub const SEMANTIC_EPOCH: u32 = {};",
        r.registry.semantic_epoch
    );
    let _ = writeln!(
        w,
        "/// Contract ids are below this: the width of the first grant word.\n\
         pub const MAX_CONTRACTS: usize = {};",
        r.registry.max_contracts
    );
    let _ = writeln!(
        w,
        "/// ORed onto an opcode: dispatch to the provider below the caller.\n\
         pub const CHAIN_NEXT: u32 = {:#x};",
        r.registry.chain_next
    );
    let assigned = r.contract.len();
    let _ = writeln!(
        w,
        "/// Contract ids the registry assigns.\npub const CONTRACTS_ASSIGNED: usize = {assigned};\n"
    );

    // Grants.
    let _ = writeln!(
        w,
        "/// Op-level grants (`grants = [..]` in a manifest): the bits of the\n\
         /// second grant word. A contract's own grant is its id's bit in the first.\n\
         pub mod grant {{"
    );
    let mut by_bit: Vec<&Grant> = r.grant.iter().collect();
    by_bit.sort_by_key(|g| g.bit);
    for g in &by_bit {
        if let Some(d) = &g.doc {
            let _ = writeln!(w, "    /// {d}");
        }
        let _ = writeln!(w, "    pub const {}: u8 = {};", shout(&g.name), g.bit);
    }
    let reach: u64 = r
        .grant
        .iter()
        .filter(|g| g.reach.as_deref() == Some("kernel"))
        .fold(0, |m, g| m | (1u64 << g.bit));
    let _ = writeln!(
        w,
        "\n    /// The op-level grants a gated module may not hold.\n\
         \x20   pub const REACH_KERNEL: u64 = {reach:#x};\n"
    );
    let _ = writeln!(
        w,
        "    /// The bit an op-level grant's name stands for.\n\
         \x20   pub fn of_name(name: &str) -> Option<u8> {{\n        match name {{"
    );
    for g in &by_bit {
        let _ = writeln!(w, "            \"{}\" => Some({}),", g.name, shout(&g.name));
    }
    let _ = writeln!(w, "            _ => None,\n        }}\n    }}\n");
    let _ = writeln!(
        w,
        "    /// The name of an op-level grant's bit.\n\
         \x20   pub fn name(bit: u8) -> Option<&'static str> {{\n        match bit {{"
    );
    for g in &by_bit {
        let _ = writeln!(w, "            {} => Some(\"{}\"),", shout(&g.name), g.name);
    }
    let _ = writeln!(w, "            _ => None,\n        }}\n    }}\n}}\n");
    let creach: u64 = r
        .contract
        .iter()
        .filter(|c| c.reach.as_deref() == Some("kernel"))
        .fold(0, |m, c| m | (1u64 << c.id));
    let _ = writeln!(
        w,
        "/// The contracts whose own grant a gated module may not hold.\n\
         pub const CONTRACT_REACH_KERNEL: u64 = {creach:#x};\n"
    );

    // Entry points.
    let _ = writeln!(
        w,
        "/// The functions the kernel calls in a module, by the FNV-1a hash of\n\
         /// their names: a module exports these and nothing else.\npub mod entry_point {{"
    );
    for e in &r.entry_point {
        if let Some(d) = &e.doc {
            let _ = writeln!(w, "    /// {d}");
        }
        let _ = writeln!(
            w,
            "    pub const {}: u32 = {:#010x};",
            shout(&e.name),
            fluxor_abi::wire::fnv1a32(e.name.as_bytes())
        );
    }
    let _ = writeln!(w, "\n    /// Every entry point, by name.");
    let _ = writeln!(
        w,
        "    pub const NAMES: [&str; {}] = [",
        r.entry_point.len()
    );
    for e in &r.entry_point {
        let _ = writeln!(w, "        \"{}\",", e.name);
    }
    let _ = writeln!(w, "    ];");
    let _ = writeln!(w, "    /// The entry points every module defines.");
    let req: Vec<&EntryPoint> = r.entry_point.iter().filter(|e| e.required).collect();
    let _ = writeln!(w, "    pub const REQUIRED: [&str; {}] = [", req.len());
    for e in req {
        let _ = writeln!(w, "        \"{}\",", e.name);
    }
    let _ = writeln!(w, "    ];\n}}\n");

    // Errno and poll.
    let _ = writeln!(w, "/// Negative return values.\npub mod errno {{");
    for e in &r.errno {
        let _ = writeln!(w, "    pub const {}: i32 = {};", e.name, e.value);
    }
    let _ = writeln!(
        w,
        "}}\n\n/// Readiness bits `HANDLE_POLL` answers.\npub mod poll {{"
    );
    for p in &r.poll {
        let _ = writeln!(w, "    pub const {}: u32 = {:#04x};", p.name, p.bit);
    }
    let _ = writeln!(w, "}}\n");

    // One module per contract.
    for c in &r.contract {
        let _ = writeln!(w, "pub mod {} {{", c.module());
        let _ = writeln!(w, "    pub const ID: u16 = {:#06x};", c.id);
        for op in &c.op {
            let _ = writeln!(w, "    pub const {}: u32 = {:#06x};", op.name, c.opcode(op));
        }
        let _ = writeln!(w, "}}\n");
    }

    // Contract lookups.
    let _ = writeln!(
        w,
        "/// The contract a manifest names (`requires_contract`, `provides`).\n\
         pub fn contract_of_name(name: &str) -> Option<u16> {{\n    match name {{"
    );
    for c in r.contract.iter().filter(|c| c.manifest) {
        let _ = writeln!(w, "        \"{}\" => Some({:#06x}),", c.name, c.id);
    }
    let _ = writeln!(w, "        _ => None,\n    }}\n}}\n");
    let _ = writeln!(
        w,
        "/// The contract a registry name stands for, whether or not a manifest\n\
         /// may claim it: a manifest's `grants` may name any contract.\n\
         pub fn contract_id(name: &str) -> Option<u16> {{\n    match name {{"
    );
    for c in &r.contract {
        let _ = writeln!(w, "        \"{}\" => Some({:#06x}),", c.name, c.id);
    }
    let _ = writeln!(w, "        _ => None,\n    }}\n}}\n");
    let _ = writeln!(
        w,
        "/// The registry name of a contract id.\n\
         pub fn contract_name(id: u16) -> Option<&'static str> {{\n    match id {{"
    );
    let mut by_id: Vec<&Contract> = r.contract.iter().collect();
    by_id.sort_by_key(|c| c.id);
    for c in &by_id {
        let _ = writeln!(w, "        {:#06x} => Some(\"{}\"),", c.id, c.name);
    }
    let _ = writeln!(w, "        _ => None,\n    }}\n}}\n");
    let _ = writeln!(
        w,
        "/// Whether a module may serve the contract as a provider\n\
         /// (`provider_contracts`); the kernel registers a module for no other.\n\
         pub fn module_providable(id: u16) -> bool {{\n    matches!(\n        id,"
    );
    let providable: Vec<String> = by_id
        .iter()
        .filter(|c| c.module_provided)
        .map(|c| format!("{:#06x}", c.id))
        .collect();
    let _ = writeln!(
        w,
        "        {}\n    )\n}}\n",
        if providable.is_empty() {
            "_ if false".to_string()
        } else {
            providable.join(" | ")
        }
    );
    let manifest: Vec<&Contract> = r.contract.iter().filter(|c| c.manifest).collect();
    let _ = writeln!(
        w,
        "/// How many contracts a manifest may name.\npub const MANIFEST_CONTRACTS: usize = {};\n",
        manifest.len()
    );
    let _ = writeln!(
        w,
        "/// The `i`th contract a manifest may name, in registry order.\n\
         pub fn manifest_contract(i: usize) -> Option<&'static str> {{\n    match i {{"
    );
    for (i, c) in manifest.iter().enumerate() {
        let _ = writeln!(w, "        {i} => Some(\"{}\"),", c.name);
    }
    let _ = writeln!(w, "        _ => None,\n    }}\n}}\n");

    let classes: Vec<String> = r
        .contract
        .iter()
        .filter(|c| c.route.as_deref() == Some("class"))
        .map(|c| format!("{:#04x}", c.id))
        .collect();
    let by_handle: Vec<String> = r
        .contract
        .iter()
        .flat_map(|c| c.op.iter().map(move |o| (c, o)))
        .filter(|(_, o)| o.route.as_deref() == Some("handle"))
        .map(|(c, o)| format!("{:#06x}", c.opcode(o)))
        .collect();
    let _ = writeln!(
        w,
        "/// Whether an opcode goes to the kernel by its class ahead of any\n\
         /// handle: every op of a class-routed contract except those the\n\
         /// registry routes to the handle's own provider.\n\
         pub fn op_routes_to_kernel(op: u32) -> bool {{\n    \
         matches!((op >> 8) & 0xff, {}){}\n}}\n",
        classes.join(" | "),
        if by_handle.is_empty() {
            String::new()
        } else {
            format!(" && !matches!(op, {})", by_handle.join(" | "))
        }
    );

    let _ = writeln!(
        w,
        "/// Whether an opcode class byte belongs to the registry: ids are dense.\n\
         pub fn class_registered(class: u32) -> bool {{\n    (class as usize) < CONTRACTS_ASSIGNED\n}}\n"
    );
    let edge: Vec<String> = r
        .contract
        .iter()
        .filter(|c| c.route.as_deref() == Some("edge"))
        .map(|c| format!("{:#06x}", c.id))
        .collect();
    let _ = writeln!(
        w,
        "/// Whether a contract is served across a graph edge: by the module at\n\
         /// the other end of the caller's port, through a handle bound to it.\n\
         pub fn contract_is_edge(id: u16) -> bool {{\n    matches!(id, {})\n}}\n",
        if edge.is_empty() {
            "_ if false".to_string()
        } else {
            edge.join(" | ")
        }
    );

    // The handle word.
    let (cb, gb, ib) = (
        r.registry.handle_contract_bits,
        r.registry.handle_generation_bits,
        r.registry.handle_index_bits,
    );
    let _ = writeln!(
        w,
        "/// The handle word: bit 31 clear (a negative value is an errno), then\n\
         /// the contract, the generation and the index. The kernel mints every\n\
         /// handle a module holds; a provider sees only its own index.\n\
         pub mod handle {{\n\
         \x20   pub const CONTRACT_BITS: u32 = {cb};\n\
         \x20   pub const GEN_BITS: u32 = {gb};\n\
         \x20   pub const INDEX_BITS: u32 = {ib};\n\
         \x20   pub const GEN_SHIFT: u32 = INDEX_BITS;\n\
         \x20   pub const CONTRACT_SHIFT: u32 = INDEX_BITS + GEN_BITS;\n\
         \x20   pub const CONTRACT_MASK: u16 = (1 << CONTRACT_BITS) - 1;\n\
         \x20   pub const GEN_MASK: u16 = (1 << GEN_BITS) - 1;\n\
         \x20   pub const INDEX_MASK: u32 = (1 << INDEX_BITS) - 1;\n\
         \x20   /// Slots a table whose index a handle names may hold.\n\
         \x20   pub const INDEX_LIMIT: usize = 1 << INDEX_BITS;\n\n\
         \x20   /// The handle naming slot `index` of `contract`'s table at `generation`;\n\
         \x20   /// fields wider than theirs are truncated.\n\
         \x20   pub const fn encode(contract: u16, generation: u16, index: u32) -> i32 {{\n\
         \x20       ((((contract & CONTRACT_MASK) as u32) << CONTRACT_SHIFT)\n\
         \x20           | (((generation & GEN_MASK) as u32) << GEN_SHIFT)\n\
         \x20           | (index & INDEX_MASK)) as i32\n    }}\n\n\
         \x20   /// `(contract, generation, index)` of a handle; `None` for a negative\n\
         \x20   /// value, which is an errno.\n\
         \x20   pub const fn decode(h: i32) -> Option<(u16, u16, u32)> {{\n\
         \x20       if h < 0 {{\n            return None;\n        }}\n\
         \x20       let h = h as u32;\n\
         \x20       Some((\n\
         \x20           ((h >> CONTRACT_SHIFT) as u16) & CONTRACT_MASK,\n\
         \x20           ((h >> GEN_SHIFT) as u16) & GEN_MASK,\n\
         \x20           h & INDEX_MASK,\n\
         \x20       ))\n    }}\n\n\
         \x20   /// The contract a handle names, if it is one.\n\
         \x20   pub const fn contract_of(h: i32) -> Option<u16> {{\n\
         \x20       match decode(h) {{\n            Some((c, _, _)) => Some(c),\n            None => None,\n        }}\n    }}\n}}\n"
    );

    // Channel message types.
    if !r.msgset.is_empty() {
        let _ = writeln!(
            w,
            "/// Channel message types, one module per surface.\npub mod msg {{"
        );
        let mut surfaces: BTreeMap<&str, Vec<&Msg>> = BTreeMap::new();
        for m in &r.msgset {
            for s in &m.members {
                surfaces.entry(s.as_str()).or_default();
            }
            for msg in &m.msg {
                surfaces.entry(msg.surface.as_str()).or_default().push(msg);
            }
        }
        for (surface, msgs) in &surfaces {
            let _ = writeln!(w, "    pub mod {surface} {{");
            for m in msgs {
                let _ = writeln!(w, "        pub const {}: u8 = {:#04x};", m.name, m.value);
            }
            let ranges: Vec<(u8, u8)> = r
                .msgset
                .iter()
                .flat_map(|m| m.range.iter())
                .filter(|rg| rg.surface == *surface)
                .map(|rg| (rg.first, rg.last))
                .collect();
            if !ranges.is_empty() {
                // Lookups, never a slice: a table of tuples is data a PIC
                // module's `.rodata` would have to hold by address.
                let _ = writeln!(
                    w,
                    "        /// Value ranges this surface owns, each filled densely.\n        pub const RANGE_COUNT: usize = {};",
                    ranges.len()
                );
                let _ = writeln!(
                    w,
                    "        /// The `i`th range this surface owns, `(first, last)`.\n        pub const fn range(i: usize) -> Option<(u8, u8)> {{\n            match i {{"
                );
                for (i, (a, b)) in ranges.iter().enumerate() {
                    let _ = writeln!(w, "                {i} => Some(({a:#04x}, {b:#04x})),");
                }
                let _ = writeln!(w, "                _ => None,\n            }}\n        }}");
                let arms: Vec<String> = ranges
                    .iter()
                    .map(|(a, b)| format!("{a:#04x}..={b:#04x}"))
                    .collect();
                let _ = writeln!(
                    w,
                    "        /// Whether this surface owns message type `v`.\n        pub const fn owns(v: u8) -> bool {{\n            matches!(v, {})\n        }}",
                    arms.join(" | ")
                );
            }
            let _ = writeln!(w, "    }}");
        }
        let _ = writeln!(w, "}}\n");
    }

    // Grant and admission per opcode.
    let mut ops: Vec<(u32, &Contract, &Op)> = Vec::new();
    for c in &r.contract {
        for op in &c.op {
            ops.push((c.opcode(op), c, op));
        }
    }
    ops.sort_by_key(|(code, _, _)| *code);
    let _ = writeln!(
        w,
        "/// What calling an op needs.\n\
         #[derive(Clone, Copy, PartialEq, Eq, Debug)]\n\
         pub enum OpGrant {{\n\
         \x20   /// Nothing: every module may call it.\n    Free,\n\
         \x20   /// The contract's own grant: its id's bit in the first word.\n    Contract(u16),\n\
         \x20   /// An op-level grant: its bit in the second word.\n    Grant(u8),\n}}\n"
    );
    let _ = writeln!(
        w,
        "/// The grant `op` needs, or `None` when the registry does not list it:\n\
         /// an op the registry does not list does not exist.\n\
         pub fn op_grant(op: u32) -> Option<OpGrant> {{\n    match op {{"
    );
    for (code, c, op) in &ops {
        let g = match c.op_grant(op) {
            None => format!("OpGrant::Contract({:#06x})", c.id),
            Some("none") => "OpGrant::Free".to_string(),
            Some(g) => format!("OpGrant::Grant(grant::{})", shout(g)),
        };
        let _ = writeln!(w, "        {code:#06x} => Some({g}),");
    }
    let _ = writeln!(w, "        _ => None,\n    }}\n}}\n");
    let _ = writeln!(
        w,
        "/// What a contract's ops need unless an op says otherwise, or `None`\n\
         /// for an id the registry does not assign.\n\
         pub fn contract_grant(id: u16) -> Option<OpGrant> {{\n    match id {{"
    );
    for c in &by_id {
        let g = match c.grant.as_deref() {
            None => format!("OpGrant::Contract({:#06x})", c.id),
            Some("none") => "OpGrant::Free".to_string(),
            Some(g) => format!("OpGrant::Grant(grant::{})", shout(g)),
        };
        let _ = writeln!(w, "        {:#06x} => Some({g}),", c.id);
    }
    let _ = writeln!(w, "        _ => None,\n    }}\n}}\n");
    let _ = writeln!(
        w,
        "/// Whether an opcode creates work or a held resource, and so waits on\n\
         /// the owner admission gate.\n\
         pub fn op_admits(op: u32) -> bool {{\n    matches!(\n        op,"
    );
    let admits: Vec<String> = ops
        .iter()
        .filter(|(_, _, op)| op.admission)
        .map(|(code, _, _)| format!("{code:#06x}"))
        .collect();
    let _ = writeln!(w, "        {}\n    )\n}}\n", admits.join(" | "));

    // Gateway rules.
    let _ = writeln!(
        w,
        "/// The shape of every call a module may make, and what the gateway serves\n\
         /// a gated module.\npub mod gate {{\n\
         \x20   /// Longest `arg` record any op takes.\n\
         \x20   pub const ARG_MAX: usize = {ARG_MAX};\n\n\
         \x20   /// What a rule lets the caller name as the handle.\n\
         \x20   #[derive(Clone, Copy, PartialEq, Eq, Debug)]\n    pub enum HandleUse {{"
    );
    for (_, v) in HANDLES {
        let _ = writeln!(w, "        {v},");
    }
    let _ = writeln!(
        w,
        "    }}\n\n    /// Which way a buffer moves.\n\
         \x20   #[derive(Clone, Copy, PartialEq, Eq, Debug)]\n    pub enum Dir {{"
    );
    for (_, v) in ARGS {
        let _ = writeln!(w, "        {v},");
    }
    let _ = writeln!(
        w,
        "    }}\n\n    /// How long the `data` span may be.\n\
         \x20   #[derive(Clone, Copy, PartialEq, Eq, Debug)]\n    pub enum Bound {{\n\
         \x20       /// At most this many bytes.\n        Bytes(usize),\n\
         \x20       /// Bounded by the caller's own region alone.\n        Any,\n    }}\n"
    );
    let _ = writeln!(
        w,
        "    /// One opcode's shape.\n\
         \x20   #[derive(Clone, Copy, PartialEq, Eq, Debug)]\n    pub struct OpRule {{\n\
         \x20       pub handle: HandleUse,\n\
         \x20       /// Which way the flat `arg` record moves.\n        pub arg: Dir,\n\
         \x20       /// Most bytes `arg` holds (at most `ARG_MAX`).\n        pub arg_max: usize,\n\
         \x20       /// Which way the bulk `data` span moves.\n        pub data: Dir,\n\
         \x20       pub data_max: Bound,\n\
         \x20       /// The op releases the handle it names.\n        pub closes: bool,\n\
         \x20       /// The op answers a kernel-granted address: never served gated.\n\
         \x20       pub addr_answer: bool,\n\
         \x20       /// The handle the op mints signals its minter through a doorbell.\n\
         \x20       pub signals: bool,\n    }}\n"
    );
    let _ = writeln!(
        w,
        "    /// The shape of `op`, if the registry declares one.\n\
         \x20   pub fn op_rule(op: u32) -> Option<OpRule> {{\n        match op {{"
    );
    let dir_of = |k: &str| {
        ARGS.iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| *v)
            .unwrap_or("None")
    };
    for (code, _, op) in &ops {
        let Some(g) = &op.gate else { continue };
        let h = HANDLES
            .iter()
            .find(|(k, _)| *k == g.handle)
            .map(|(_, v)| *v)
            .unwrap_or("Global");
        let d = dir_of(&g.arg);
        let dd = dir_of(g.data.as_deref().unwrap_or("none"));
        let b = match &g.data_max {
            Some(GateMax::Bytes(n)) => format!("Bound::Bytes({n})"),
            Some(GateMax::Word(_)) => "Bound::Any".to_string(),
            None => "Bound::Bytes(0)".to_string(),
        };
        let _ = writeln!(
            w,
            "            {code:#06x} => Some(OpRule {{ handle: HandleUse::{h}, arg: Dir::{d}, arg_max: {}, data: Dir::{dd}, data_max: {b}, closes: {}, addr_answer: {}, signals: {} }}),",
            g.max, op.closes, op.addr_answer, op.signals
        );
    }
    let _ = writeln!(w, "            _ => None,\n        }}\n    }}\n");
    let _ = writeln!(
        w,
        "    /// The bytes a `provider_query` key served to gated modules writes.\n\
         \x20   pub fn query_max(key: u32) -> Option<usize> {{\n        match key {{"
    );
    for (code, _, op) in &ops {
        if let Some(q) = op.query {
            let _ = writeln!(w, "            {code:#06x} => Some({q}),");
        }
    }
    let _ = writeln!(w, "            _ => None,\n        }}\n    }}\n}}");
    o
}

/// Load, validate and emit the registry under `repo`.
pub fn generate(repo: &Path) -> Result<String> {
    let path = repo.join(REGISTRY_TOML);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
    let r = parse(&text)?;
    validate(&r)?;
    rustfmt(&emit(&r))
}

/// Generated source as `rustfmt` lays it out, so the file passes the module
/// fmt-check unchanged.
pub fn rustfmt(src: &str) -> Result<String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let mut child = Command::new("rustfmt")
        .args(["--edition", "2021", "--emit", "stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Config(format!("rustfmt: {e}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| Error::Config("rustfmt: no stdin".into()))?
        .write_all(src.as_bytes())
        .map_err(|e| Error::Config(format!("rustfmt: {e}")))?;
    let out = child
        .wait_with_output()
        .map_err(|e| Error::Config(format!("rustfmt: {e}")))?;
    if !out.status.success() {
        return Err(Error::Config(format!(
            "rustfmt refused the generated source: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    String::from_utf8(out.stdout).map_err(|e| Error::Config(format!("rustfmt: {e}")))
}

/// The generated file's path under `repo`.
pub fn gen_path(repo: &Path) -> PathBuf {
    repo.join(REGISTRY_GEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> String {
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join(REGISTRY_TOML),
        )
        .unwrap()
    }

    #[test]
    fn the_registry_is_valid() {
        validate(&parse(&registry()).unwrap()).unwrap();
    }

    /// A surface that declares ranges holds every value inside them, fills
    /// each one, and no other surface's value falls inside them.
    #[test]
    fn a_msgset_range_is_owned_and_dense() {
        let text = registry();
        let hole = text.replacen(
            "  [[msgset.msg]]\n  surface = \"stream_retx\"\n  name = \"MSG_RETX_REQUEST\"\n  value = 0xD1\n",
            "",
            1,
        );
        assert_ne!(hole, text);
        let e = validate(&parse(&hole).unwrap()).unwrap_err().to_string();
        assert!(e.contains("not dense") && e.contains("0xd1"), "{e}");

        let outside = text.replacen(
            "name = \"MSG_RETX_REQUEST\"\n  value = 0xD1",
            "name = \"MSG_RETX_REQUEST\"\n  value = 0xD7",
            1,
        );
        let e = validate(&parse(&outside).unwrap()).unwrap_err().to_string();
        assert!(e.contains("outside every range"), "{e}");

        let foreign = text.replacen(
            "  [[msgset.msg]]\n  surface = \"stream_trace\"",
            "  [[msgset.msg]]\n  surface = \"mux\"\n  name = \"MSG_INTRUDER\"\n  value = 0xD5\n\n  [[msgset.msg]]\n  surface = \"stream_trace\"",
            1,
        );
        let e = validate(&parse(&foreign).unwrap()).unwrap_err().to_string();
        assert!(e.contains("MSG_INTRUDER"), "{e}");
    }
}
