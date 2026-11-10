//! The ABI number registry: `modules/sdk/abi/registry.toml` parsed,
//! validated and emitted as `modules/sdk/abi/registry_gen.rs`.
//!
//! The TOML is the one place an ABI number is written: contract ids,
//! opcode classes and opcodes, permission bits, errno values, poll bits and
//! fd tags. The generated file holds only scalar constants and `match`-based
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
pub const REGISTRY_TOML: &str = "modules/sdk/abi/registry.toml";
/// Where the generated file is written, relative to the repo root.
pub const REGISTRY_GEN: &str = "modules/sdk/abi/registry_gen.rs";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub registry: Header,
    #[serde(default)]
    pub permission: Vec<Permission>,
    #[serde(default)]
    pub errno: Vec<Errno>,
    #[serde(default)]
    pub poll: Vec<Poll>,
    #[serde(default)]
    pub ioctl: Vec<Ioctl>,
    #[serde(default)]
    pub contract: Vec<Contract>,
    #[serde(default)]
    pub msgset: Vec<Msgset>,
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permission {
    pub name: String,
    pub bit: u8,
    /// What holding the permission lets a module do.
    pub doc: Option<String>,
}

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
pub struct Ioctl {
    pub name: String,
    pub value: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    /// Registry module name; also the manifest spelling when `manifest`.
    pub name: String,
    /// Contract id: the opcode class byte, the vtable index, the
    /// `required_caps` bit and, when it mints handles, their fd tag.
    pub id: u8,
    /// Hands out tagged handles: the id is also the handle's fd tag.
    #[serde(default)]
    pub mints: bool,
    /// A module manifest may name it (`requires_contract`, `provides`).
    #[serde(default)]
    pub manifest: bool,
    /// Permission every op of the entry requires unless the op says
    /// otherwise; absent, the ops require none.
    pub permission: Option<String>,
    /// Permission an op of this contract that the registry does not list
    /// requires before the kernel looks at it.
    pub unlisted: Option<String>,
    /// `"class"`: routed to the kernel by its opcode class ahead of any
    /// handle; absent, routed by the handle's contract.
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
    /// Overrides the entry's permission; `"none"` requires none.
    pub permission: Option<String>,
    /// Creates work or a held resource: subject to the owner admission gate.
    #[serde(default)]
    pub admission: bool,
    /// Served to gated modules through the gateway, under this rule.
    pub gate: Option<Gate>,
    /// The argument carries pointers the gateway finds with this walker.
    pub walker: Option<String>,
    /// The op releases the handle it names.
    #[serde(default)]
    pub closes: bool,
    /// Served to gated modules as a `provider_query` key writing at most
    /// this many bytes.
    pub query: Option<usize>,
    /// `"handle"`: on a class-routed contract, this op goes to the handle's
    /// own provider instead (an op every provider answers for its handles).
    pub route: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    pub handle: String,
    pub arg: String,
    pub max: GateMax,
}

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
    fn op_permission<'a>(&'a self, op: &'a Op) -> Option<&'a str> {
        match op.permission.as_deref() {
            Some("none") => None,
            Some(p) => Some(p),
            None => self.permission.as_deref(),
        }
    }
}

fn shout(s: &str) -> String {
    s.to_ascii_uppercase().replace(['.', '-'], "_")
}

fn camel(s: &str) -> String {
    s.split('_')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// Parse `registry.toml`.
pub fn parse(text: &str) -> Result<Registry> {
    toml::from_str(text).map_err(|e| Error::Config(format!("{REGISTRY_TOML}: {e}")))
}

/// Every rule the registry must satisfy; all violations, not the first.
pub fn validate(r: &Registry) -> Result<()> {
    let mut bad: Vec<String> = Vec::new();
    let perms: BTreeSet<&str> = r.permission.iter().map(|p| p.name.as_str()).collect();
    let mut seen = BTreeSet::new();
    let mut bits = BTreeSet::new();
    for p in &r.permission {
        if !seen.insert(p.name.as_str()) {
            bad.push(format!("permission `{}` declared twice", p.name));
        }
        if p.bit >= 16 || !bits.insert(p.bit) {
            bad.push(format!(
                "permission `{}`: bit {} is taken or past 15",
                p.name, p.bit
            ));
        }
    }
    let mut seen = BTreeSet::new();
    for e in &r.errno {
        if !seen.insert(e.name.as_str()) {
            bad.push(format!("errno `{}` declared twice", e.name));
        }
    }
    let mut seen = BTreeSet::new();
    let mut ivals = BTreeSet::new();
    for i in &r.ioctl {
        if !seen.insert(i.name.as_str()) || !ivals.insert(i.value) {
            bad.push(format!(
                "ioctl `{}`: name or value {} declared twice",
                i.name, i.value
            ));
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
        if c.mints && c.id == 0 {
            bad.push(format!(
                "contract `{}` mints handles at id 0, the untagged tag",
                c.name
            ));
        }
        for p in c.permission.iter().chain(c.unlisted.iter()) {
            if !perms.contains(p.as_str()) {
                bad.push(format!("contract `{}`: unknown permission `{p}`", c.name));
            }
        }
        if c.route.as_deref().is_some_and(|r| r != "class") {
            bad.push(format!(
                "contract `{}`: route is \"class\" or absent",
                c.name
            ));
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
            if let Some(p) = op.permission.as_deref() {
                if p != "none" && !perms.contains(p) {
                    bad.push(format!("{}::{}: unknown permission `{p}`", c.name, op.name));
                }
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
                match (&g.max, op.walker.is_some()) {
                    (GateMax::Word(w), true) if w == "walk" => {}
                    (GateMax::Word(w), false) if w == "any" => {}
                    (GateMax::Bytes(_), false) => {}
                    _ => bad.push(format!(
                        "{}::{}: gate max is a byte count, \"any\", or \"walk\" with a walker",
                        c.name, op.name
                    )),
                }
                if g.arg == "none" && !matches!(g.max, GateMax::Bytes(0)) {
                    bad.push(format!(
                        "{}::{}: a gate with no argument has max 0",
                        c.name, op.name
                    ));
                }
            } else if op.walker.is_some() || op.closes {
                bad.push(format!(
                    "{}::{}: walker/closes without a gate",
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
        "/// Contract ids are below this: the `required_caps` width.\n\
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

    // Permissions.
    let _ = writeln!(
        w,
        "/// Manifest permission bits (`permissions = [..]`).\npub mod permission {{"
    );
    for p in &r.permission {
        if let Some(d) = &p.doc {
            let _ = writeln!(w, "    /// {d}");
        }
        let _ = writeln!(w, "    pub const {}: u16 = 1 << {};", shout(&p.name), p.bit);
    }
    let _ = writeln!(
        w,
        "\n    /// The bit a manifest permission name stands for."
    );
    let _ = writeln!(
        w,
        "    pub fn of_name(name: &str) -> Option<u16> {{\n        match name {{"
    );
    for p in &r.permission {
        let _ = writeln!(w, "            \"{}\" => Some({}),", p.name, shout(&p.name));
    }
    let _ = writeln!(w, "            _ => None,\n        }}\n    }}\n");
    let _ = writeln!(w, "    /// The manifest name of one permission bit.");
    let _ = writeln!(
        w,
        "    pub fn name(bit: u16) -> Option<&'static str> {{\n        match bit {{"
    );
    for p in &r.permission {
        let _ = writeln!(w, "            {} => Some(\"{}\"),", shout(&p.name), p.name);
    }
    let _ = writeln!(w, "            _ => None,\n        }}\n    }}\n");
    let _ = writeln!(w, "    /// Every permission bit, in bit order.");
    let _ = writeln!(
        w,
        "    pub fn nth(i: usize) -> Option<u16> {{\n        match i {{"
    );
    let mut by_bit: Vec<&Permission> = r.permission.iter().collect();
    by_bit.sort_by_key(|p| p.bit);
    for (i, p) in by_bit.iter().enumerate() {
        let _ = writeln!(w, "            {i} => Some({}),", shout(&p.name));
    }
    let _ = writeln!(w, "            _ => None,\n        }}\n    }}\n}}\n");

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
    let _ = writeln!(
        w,
        "}}\n\n/// Channel ioctl commands the kernel serves (`channel_ioctl`'s `cmd`).\npub mod ioctl {{"
    );
    for i in &r.ioctl {
        let _ = writeln!(w, "    pub const {}: u32 = {};", i.name, i.value);
    }
    let _ = writeln!(w, "}}\n");

    // One module per contract.
    for c in &r.contract {
        let _ = writeln!(w, "pub mod {} {{", c.module());
        let _ = writeln!(w, "    pub const ID: u16 = {:#06x};", c.id);
        if c.mints {
            let _ = writeln!(w, "    pub const FD_TAG: i32 = {};", c.id);
        }
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
        "/// The registry name of a contract id.\n\
         pub fn contract_name(id: u16) -> Option<&'static str> {{\n    match id {{"
    );
    let mut by_id: Vec<&Contract> = r.contract.iter().collect();
    by_id.sort_by_key(|c| c.id);
    for c in &by_id {
        let _ = writeln!(w, "        {:#06x} => Some(\"{}\"),", c.id, c.name);
    }
    let _ = writeln!(w, "        _ => None,\n    }}\n}}\n");
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

    // Handles: a minting contract's tag is its id.
    let tag_bits = r.registry.max_contracts.trailing_zeros();
    let shift = 31 - tag_bits;
    let _ = writeln!(
        w,
        "/// Whether a contract hands out tagged handles (its id is their tag).\n\
         pub fn contract_mints(id: u16) -> bool {{\n    matches!(id, {})\n}}\n",
        {
            let v: Vec<String> = by_id
                .iter()
                .filter(|c| c.mints)
                .map(|c| format!("{:#06x}", c.id))
                .collect();
            v.join(" | ")
        }
    );
    let _ = writeln!(
        w,
        "/// Handle layout: bit 31 clear, a {tag_bits}-bit contract tag, then the slot.\n\
         pub mod fd {{\n\
         \x20   /// A handle with tag 0 is untagged (a channel port, a raw integer).\n\
         \x20   pub const UNTAGGED: i32 = 0;\n\
         \x20   pub const TAG_SHIFT: u32 = {shift};\n\
         \x20   pub const TAG_MASK: i32 = {:#x};\n\
         \x20   pub const SLOT_MASK: i32 = {:#x};\n\
         \x20   /// Slot bits a provider's own index may use; the kernel owns the\n\
         \x20   /// slot field's top bit (routed handles, the vault's hardware field).\n\
         \x20   pub const SLOT_FIELD_BITS: u32 = {};\n\n\
         \x20   /// Encode a tag and a slot; a negative slot (an errno) passes through,\n\
         \x20   /// and an unencodable tag is `EINVAL` rather than an alias.\n\
         \x20   pub const fn tag_fd(tag: i32, slot: i32) -> i32 {{\n\
         \x20       if slot < 0 {{\n            return slot;\n        }}\n\
         \x20       if tag < 0 || tag > TAG_MASK {{\n            return -22;\n        }}\n\
         \x20       (tag << TAG_SHIFT) | (slot & SLOT_MASK)\n    }}\n\n\
         \x20   /// Decode a handle into `(tag, slot)`.\n\
         \x20   pub const fn untag_fd(fd: i32) -> (i32, i32) {{\n\
         \x20       ((fd >> TAG_SHIFT) & TAG_MASK, fd & SLOT_MASK)\n    }}\n\n\
         \x20   /// The slot of a handle.\n\
         \x20   pub const fn slot_of(fd: i32) -> i32 {{\n        fd & SLOT_MASK\n    }}\n}}\n",
        (1u32 << tag_bits) - 1,
        (1u32 << shift) - 1,
        shift - 1
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
            let _ = writeln!(w, "    }}");
        }
        let _ = writeln!(w, "}}\n");
    }

    // Permission and admission per opcode.
    let mut ops: Vec<(u32, &Contract, &Op)> = Vec::new();
    for c in &r.contract {
        for op in &c.op {
            ops.push((c.opcode(op), c, op));
        }
    }
    ops.sort_by_key(|(code, _, _)| *code);
    let _ = writeln!(
        w,
        "/// The permission an opcode requires, if any. An opcode the registry\n\
         /// does not list requires its contract's `unlisted` permission.\n\
         pub fn op_permission(op: u32) -> Option<u16> {{\n    match op {{"
    );
    for (code, c, op) in &ops {
        if let Some(p) = c.op_permission(op) {
            let _ = writeln!(w, "        {code:#06x} => Some(permission::{}),", shout(p));
        } else {
            let _ = writeln!(w, "        {code:#06x} => None,");
        }
    }
    let mut unlisted: BTreeMap<u8, &str> = BTreeMap::new();
    for c in &r.contract {
        if let Some(u) = c.unlisted.as_deref() {
            unlisted.insert(c.id, u);
        }
    }
    let _ = writeln!(w, "        _ => match op >> 8 {{");
    for (class, p) in &unlisted {
        let _ = writeln!(
            w,
            "            {class:#04x} => Some(permission::{}),",
            shout(p)
        );
    }
    let _ = writeln!(w, "            _ => None,\n        }},\n    }}\n}}\n");
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
    let walkers: BTreeSet<&str> = ops
        .iter()
        .filter_map(|(_, _, op)| op.walker.as_deref())
        .collect();
    let _ = writeln!(
        w,
        "/// What the gateway serves a gated module.\npub mod gate {{\n\
         \x20   /// What a rule lets the caller name as the handle.\n\
         \x20   #[derive(Clone, Copy, PartialEq, Eq, Debug)]\n    pub enum HandleUse {{"
    );
    for (_, v) in HANDLES {
        let _ = writeln!(w, "        {v},");
    }
    let _ = writeln!(
        w,
        "    }}\n\n    /// Which way the argument buffer moves.\n\
         \x20   #[derive(Clone, Copy, PartialEq, Eq, Debug)]\n    pub enum ArgDir {{"
    );
    for (_, v) in ARGS {
        let _ = writeln!(w, "        {v},");
    }
    let _ = writeln!(
        w,
        "    }}\n\n    /// How long the argument buffer may be.\n\
         \x20   #[derive(Clone, Copy, PartialEq, Eq, Debug)]\n    pub enum Bound {{\n\
         \x20       /// At most this many bytes.\n        Bytes(usize),\n\
         \x20       /// Bounded by the caller's own region alone.\n        Any,\n\
         \x20       /// The walked-struct bound the gateway copies.\n        Walk,\n    }}\n"
    );
    let _ = writeln!(
        w,
        "    /// An argument struct that carries pointers, and how to find them.\n\
         \x20   #[derive(Clone, Copy, PartialEq, Eq, Debug)]\n    pub enum Walker {{"
    );
    for k in &walkers {
        let _ = writeln!(w, "        {},", camel(k));
    }
    let _ = writeln!(
        w,
        "    }}\n\n    /// One opcode a gated module may use.\n\
         \x20   #[derive(Clone, Copy, PartialEq, Eq, Debug)]\n    pub struct OpRule {{\n\
         \x20       pub handle: HandleUse,\n        pub dir: ArgDir,\n        pub bound: Bound,\n\
         \x20       pub walk: Option<Walker>,\n        /// The op releases the handle it names.\n\
         \x20       pub closes: bool,\n    }}\n"
    );
    let _ = writeln!(
        w,
        "    /// The rule for `op`, if gated modules may use it.\n\
         \x20   pub fn op_rule(op: u32) -> Option<OpRule> {{\n        match op {{"
    );
    for (code, _, op) in &ops {
        let Some(g) = &op.gate else { continue };
        let h = HANDLES
            .iter()
            .find(|(k, _)| *k == g.handle)
            .map(|(_, v)| *v)
            .unwrap_or("Global");
        let d = ARGS
            .iter()
            .find(|(k, _)| *k == g.arg)
            .map(|(_, v)| *v)
            .unwrap_or("None");
        let b = match &g.max {
            GateMax::Bytes(n) => format!("Bound::Bytes({n})"),
            GateMax::Word(s) if s == "walk" => "Bound::Walk".to_string(),
            GateMax::Word(_) => "Bound::Any".to_string(),
        };
        let wk = match op.walker.as_deref() {
            Some(k) => format!("Some(Walker::{})", camel(k)),
            None => "None".to_string(),
        };
        let _ = writeln!(
            w,
            "            {code:#06x} => Some(OpRule {{ handle: HandleUse::{h}, dir: ArgDir::{d}, bound: {b}, walk: {wk}, closes: {} }}),",
            op.closes
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

/// The generated source as `rustfmt` lays it out, so the file passes the
/// module fmt-check unchanged.
fn rustfmt(src: &str) -> Result<String> {
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
            "rustfmt refused the generated registry: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    String::from_utf8(out.stdout).map_err(|e| Error::Config(format!("rustfmt: {e}")))
}

/// The generated file's path under `repo`.
pub fn gen_path(repo: &Path) -> PathBuf {
    repo.join(REGISTRY_GEN)
}
