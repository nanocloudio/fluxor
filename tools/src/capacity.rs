//! Per-target kernel capacity facts shared by the boot-blob builder and the
//! composer, read as **profile data** from the kernel's own capacity seam,
//! `src/kernel/config.rs`, which this crate embeds at build time. Nothing here
//! restates a kernel figure: a profile's static pool sizes are its
//! `STATIC_POOLS` table, its default reserves its `DEFAULT_RESERVES`, and the
//! arenas and module domain the constants those tables name; the owner-slot
//! domain is read the same way from `src/kernel/workload/owner.rs`. A kernel
//! change is therefore a tools rebuild, never an edit here.
//!
//! With those figures the composer runs the kernel's boot plan
//! ([`check_boot_plan`]): each pool's ceiling is what the config derives for
//! it plus its reserve, exactly as `resource_ledger::plan` computes it, and a
//! ceiling past what the target's kernel can hold is refused at build, naming
//! the pool, rather than at boot.
//!
//! Kernel capacity is not ABI: changing a value in the kernel rebuilds the CLI
//! and the kernel, and moves no ABI epoch.

/// The kernel's capacity seam, embedded so the CLI carries the profiles of the
/// kernels it builds for.
const KERNEL_CONFIG: &str = include_str!("../../src/kernel/config.rs");

/// The kernel's owner table, embedded for its owner-slot domain
/// (`MAX_OWNERS`), which it states per platform.
const KERNEL_OWNER: &str = include_str!("../../src/kernel/workload/owner.rs");

/// Targets whose kernel compiles `profile_bcm2712` (`src/kernel/config.rs`).
fn is_bcm2712(target: &str) -> bool {
    matches!(target, "pi5" | "bcm2712" | "cm5" | "qemu-virt")
}

/// The kernel profile a target compiles. Unknown targets get the RP profile:
/// a graph that fits the smallest profile fits everywhere.
pub fn kernel_profile(target: &str) -> &'static str {
    match target {
        "linux" => "profile_linux",
        t if is_bcm2712(t) => "profile_bcm2712",
        "wasm" => "profile_wasm",
        _ => "profile_rp",
    }
}

/// The body of `mod <profile> { … }` in the kernel's capacity seam.
fn profile_body(profile: &str) -> &'static str {
    let Some(start) = KERNEL_CONFIG.find(&format!("mod {profile} {{")) else {
        return "";
    };
    let rest = &KERNEL_CONFIG[start..];
    let end = rest.find("\n}\n").unwrap_or(rest.len());
    &rest[..end]
}

/// Evaluate a profile's integer expression: a literal product (`16 * 1024`),
/// or the name of another constant of the same profile. `None` for anything
/// else (profile_rp's per-silicon `crate::platform::chip::…` sizes, which the
/// silicon TOML carries).
fn eval(body: &str, expr: &str) -> Option<u64> {
    let expr = expr.trim();
    if let Some(v) = expr
        .split('*')
        .map(|f| f.trim().replace('_', "").parse::<u64>().ok())
        .try_fold(1u64, |acc, f| f.map(|f| acc * f))
    {
        return Some(v);
    }
    if expr
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        let decl = format!("pub const {expr}: usize = ");
        // An unconditional declaration only: a cfg-guarded one names a
        // per-die figure the profile alone does not fix.
        let mut guarded = false;
        for line in body.lines() {
            let t = line.trim();
            if t.starts_with("#[cfg(") {
                guarded = true;
                continue;
            }
            if let Some(rest) = t.strip_prefix(&decl) {
                if !guarded {
                    return eval(body, rest.trim_end_matches(';'));
                }
            }
            if !t.is_empty() && !t.starts_with("//") {
                guarded = false;
            }
        }
    }
    None
}

/// `(pool name, value)` rows of a profile table (`STATIC_POOLS` or
/// `DEFAULT_RESERVES`); a value the profile does not fix is `None`.
fn profile_table(target: &str, table: &str) -> Vec<(String, Option<u64>)> {
    let body = profile_body(kernel_profile(target));
    let Some(start) = body.find(&format!("pub const {table}: &[(u16, usize)] = &[")) else {
        return Vec::new();
    };
    let rest = &body[start..];
    let end = rest.find("];").unwrap_or(rest.len());
    let mut rows = Vec::new();
    for line in rest[..end].lines() {
        let Some(row) = line.trim().strip_prefix("(res::POOL_") else {
            continue;
        };
        let Some((konst, value)) = row.trim_end_matches("),").split_once(',') else {
            continue;
        };
        rows.push((konst.to_ascii_lowercase(), eval(body, value)));
    }
    rows
}

/// `target`'s static size for `pool`, from its profile's `STATIC_POOLS`, in
/// the pool's own units (bytes for arenas, slots for tables). `None` where the
/// profile sizes the pool at boot (every pool on Linux, bcm2712 and RP).
pub fn kernel_pool_static_size(target: &str, pool: &str) -> Option<u64> {
    profile_table(target, "STATIC_POOLS")
        .into_iter()
        .find(|(name, _)| name == pool)
        .and_then(|(_, v)| v)
}

/// `target`'s default reserve for `pool` (`DEFAULT_RESERVES`): what its kernel
/// adds to the pool's derived size when the config carries no envelope entry,
/// or, for a pool the config cannot derive, the pool's default size. `None` on
/// a profile with static tables, for a pool the profile has no table for, and
/// for a per-silicon figure (the RP arenas, which the silicon TOML carries).
pub fn kernel_pool_default_reserve(target: &str, pool: &str) -> Option<u64> {
    profile_table(target, "DEFAULT_RESERVES")
        .into_iter()
        .find(|(name, _)| name == pool)
        .and_then(|(_, v)| v)
}

/// Whether `target`'s kernel has a table for `pool` at all: a row in its
/// profile's `STATIC_POOLS` or `DEFAULT_RESERVES`. The control-plane store's
/// tables, host-process sandboxes and TTY sessions exist only where their
/// platform does, and an envelope entry for a pool the kernel has no table
/// for would bound nothing.
pub fn kernel_has_pool(target: &str, pool: &str) -> bool {
    ["STATIC_POOLS", "DEFAULT_RESERVES"].iter().any(|t| {
        profile_table(target, t)
            .iter()
            .any(|(name, _)| name == pool)
    })
}

/// Whether `target`'s config blob lays its graph section out for the graph it
/// carries (Linux, bcm2712) rather than for the profile's compiled slot count
/// (`GRAPH_EDGES`, RP and wasm), which is then also its channel-id domain.
pub fn graph_section_per_graph(target: &str) -> bool {
    matches!(kernel_profile(target), "profile_linux" | "profile_bcm2712")
}

/// Kernel `MAX_MODULES` for the profile a target compiles: the module-index
/// domain (config ids carry 12 bits), within which Linux, bcm2712 and RP size
/// their module tables from the graph; wasm's static module table.
pub fn kernel_max_modules(target: &str) -> usize {
    eval(profile_body(kernel_profile(target)), "MAX_MODULES").unwrap_or(32) as usize
}

/// Graph-edge slots a target's config blob may carry, and so its channel-id
/// domain (`MAX_GRAPH_EDGES`, `MAX_CHANNELS`): the static profile's compiled
/// `GRAPH_EDGES`, or on Linux and bcm2712, whose graph section is laid out
/// for the graph, the format's bound.
pub fn kernel_max_edges(target: &str) -> usize {
    if graph_section_per_graph(target) {
        GRAPH_EDGES_FORMAT_BOUND
    } else {
        eval(profile_body(kernel_profile(target)), "GRAPH_EDGES").unwrap_or(128) as usize
    }
}

/// The format's bound on a per-graph section's edge slots: slot code 255, a
/// byte of 128-edge units.
pub const GRAPH_EDGES_FORMAT_BOUND: usize = 255 * 128;

/// Edge slots the graph section of a `target` blob carrying `edges` edges is
/// laid out for: the static profile's count, or on Linux and bcm2712 the
/// graph's own edges rounded up to whole 128-edge units.
pub fn graph_slots(target: &str, edges: usize) -> usize {
    if graph_section_per_graph(target) {
        edges.max(1).div_ceil(128) * 128
    } else {
        kernel_max_edges(target)
    }
}

/// A kernel pool's size where `target`'s profile fixes one: the static size,
/// else the default (for an arena, its size).
pub fn kernel_pool_size(target: &str, pool: &str) -> Option<u64> {
    kernel_pool_static_size(target, pool).or_else(|| kernel_pool_default_reserve(target, pool))
}

/// The channel buffer arena (`BUFFER_ARENA_SIZE`) of the kernel profile
/// `runtime` compiles. The RP kernels take theirs from the silicon TOML
/// (`[kernel] buffer_arena_kb`), which the target descriptor carries.
pub fn kernel_buffer_arena(runtime: &str) -> Option<u64> {
    match kernel_profile(runtime) {
        "profile_rp" => None,
        _ => kernel_pool_size(runtime, "buffer_arena"),
    }
}

/// Whether `runtime`'s kernel places its arenas per graph, at the sizes the
/// plan gives them (RP, splitting its static pool), so an arena envelope
/// entry is the arena's size, larger or smaller than the default. Elsewhere
/// the arenas are fixed (a `.bss` array, or on bcm2712 the device tree's
/// zone), and an entry only lowers the figure an allocation is admitted
/// against.
pub fn kernel_places_arenas(runtime: &str) -> bool {
    kernel_profile(runtime) == "profile_rp"
}

/// The module state arena a graph on `runtime` is admitted against, in bytes,
/// and whether the graph's `capacity:` envelope set it. `default_state` and
/// `default_buffer` are the target's planning figures (`state_arena_kb`,
/// `buffer_arena_kb`).
///
/// Where the kernel places its arenas per graph (RP), the state arena is what
/// the static pool holds beside the tables and the buffer arena. A
/// `state_arena` entry is then a size the kernel guarantees (a pool that
/// cannot seat it is refused at boot), so it is the figure, larger or smaller
/// than the default. Without one, the default split holds `default_state`
/// beside `default_buffer`, and a `buffer_arena` entry moves the difference
/// between the two arenas: a larger buffer arena takes it from the state
/// arena, a smaller one gives it back. Elsewhere the state arena is fixed, and
/// an entry only lowers the figure an allocation is admitted against.
pub fn planned_state_arena(
    runtime: &str,
    default_state: u64,
    default_buffer: Option<u64>,
    envelope: Option<&serde_json::Value>,
) -> (u64, bool) {
    let entry = |pool: &str| {
        envelope
            .and_then(|c| c.get(pool))
            .and_then(serde_json::Value::as_u64)
    };
    let state = entry("state_arena");
    if !kernel_places_arenas(runtime) {
        return match state {
            Some(n) if n < default_state => (n, true),
            _ => (default_state, false),
        };
    }
    if let Some(n) = state {
        return (n, true);
    }
    match (entry("buffer_arena"), default_buffer) {
        (Some(b), Some(d)) => ((default_state + d).saturating_sub(b), true),
        _ => (default_state, false),
    }
}

/// The value of `pub const <name>: usize` in `src`, taken from the
/// declaration whose `#[cfg(..)]` guard is exactly `cfg` (`None`: an
/// unguarded declaration). `None` when there is no such declaration or its
/// value is not a literal product.
fn cfg_const(src: &str, cfg: Option<&str>, name: &str) -> Option<u64> {
    let decl = format!("pub const {name}: usize = ");
    let mut guard: Option<&str> = None;
    for line in src.lines() {
        let t = line.trim();
        if let Some(pred) = t.strip_prefix("#[cfg(").and_then(|p| p.strip_suffix(")]")) {
            guard = Some(pred);
            continue;
        }
        if let Some(rest) = t.strip_prefix(&decl) {
            if guard == cfg {
                return eval("", rest.trim_end_matches(';'));
            }
        }
        if !t.is_empty() && !t.starts_with("//") {
            guard = None;
        }
    }
    None
}

/// The owner-slot domain (`MAX_OWNERS`, `src/kernel/workload/owner.rs`) of
/// the kernel `target` compiles, the system slot included: the hosted
/// multitenant figure on Linux, the bare-metal multitenant one on bcm2712,
/// and the system slot alone on the single-tenant profiles.
pub fn kernel_max_owners(target: &str) -> u64 {
    let cfg = match kernel_profile(target) {
        "profile_linux" => r#"all(feature = "multitenant", feature = "host-linux")"#,
        "profile_bcm2712" => r#"all(feature = "multitenant", not(feature = "host-linux"))"#,
        _ => r#"not(feature = "multitenant")"#,
    };
    cfg_const(KERNEL_OWNER, Some(cfg), "MAX_OWNERS").unwrap_or(1)
}

/// The Linux host-process backend, embedded for its sandbox and PTY-session
/// index domains.
const KERNEL_HOST_BACKEND: &str = include_str!("../../src/platform/linux/host_backend.rs");

/// The index domain the kernel holds `pool`'s table within on `target`, with
/// what the domain is: a boot plan whose ceiling passes it is refused at boot
/// naming the pool. `None` for a pool with no such domain (its table is bound
/// only by the memory the platform gives it).
pub fn kernel_pool_domain(target: &str, pool: &str) -> Option<(u64, &'static str)> {
    let linux = kernel_profile(target) == "profile_linux";
    match pool {
        "module_slots" => Some((
            kernel_max_modules(target) as u64,
            "module-index domain (MAX_MODULES)",
        )),
        "channels" => Some((
            kernel_max_edges(target) as u64,
            "channel-id domain (MAX_CHANNELS)",
        )),
        "owners" => Some((kernel_max_owners(target), "owner-slot domain (MAX_OWNERS)")),
        "events" | "timers" => {
            fd_slot_domain().map(|n| (n, "tagged-fd slot domain (fd::SLOT_MASK + 1)"))
        }
        "sandboxes" if linux => cfg_const(KERNEL_HOST_BACKEND, None, "MAX_SANDBOXES")
            .map(|n| (n, "sandbox-index domain (MAX_SANDBOXES)")),
        "tty_sessions" if linux => cfg_const(KERNEL_HOST_BACKEND, None, "MAX_TTY_SESSIONS")
            .map(|n| (n, "session-id domain (MAX_TTY_SESSIONS)")),
        _ => None,
    }
}

/// The module ABI's kernel surface, embedded for the tagged-fd slot field.
const KERNEL_ABI: &str = include_str!("../../modules/sdk/abi/kernel_abi.rs");

/// Slots a tagged fd's slot field can name (`kernel_abi::fd::SLOT_MASK` + 1):
/// the domain of the event and timer tables, whose handles carry their slot
/// there.
fn fd_slot_domain() -> Option<u64> {
    let decl = "pub const SLOT_MASK: i32 = ";
    let at = KERNEL_ABI.find(decl)? + decl.len();
    let rest = &KERNEL_ABI[at..];
    let lit = rest[..rest.find(';')?].trim().replace('_', "");
    let mask = match lit.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok()?,
        None => lit.parse().ok()?,
    };
    Some(mask + 1)
}

/// What a config gives the kernel's boot plan to derive pool sizes from
/// (`resource_ledger::plan`): its base graph and its resident workloads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GraphShape {
    /// Base-graph modules.
    pub modules: u64,
    /// Base-graph edges.
    pub edges: u64,
    /// Tees and merges graph preparation inserts ([`fan_count`]).
    pub fans: u64,
    /// Resident workloads (the FXPD section).
    pub workloads: u64,
    /// Their modules, summed.
    pub workload_modules: u64,
    /// Their edges, summed.
    pub workload_edges: u64,
    /// Base-graph edges that cross execution domains ([`crossing_count`]):
    /// on bcm2712 each takes a second channel, its consumer side.
    pub crossings: u64,
}

/// Base-graph edges that cross execution domains, as the bcm2712 plan counts
/// them (`resource_ledger::cross_domain_edges`): an edge whose two modules sit
/// in different domains, or whose edge class is cross-core. Each edge is
/// `(from domain, to domain, cross_core)`; a tee or merge takes the domain of
/// the module it fans on, so fanning adds none.
pub fn crossing_count(edges: impl IntoIterator<Item = (Option<u8>, Option<u8>, bool)>) -> u64 {
    edges
        .into_iter()
        .filter(|&(from, to, cross_core)| cross_core || from != to)
        .count() as u64
}

/// Tees and merges graph preparation inserts for `edges`, as the kernel's
/// plan counts them (`resource_ledger::fan_count`): one per port carrying two
/// or more edges in the same direction, an upper bound. Each edge is
/// `(from_id, to_id, to_port, from_port_index, to_port_index)`, the graph
/// section's fields.
pub fn fan_count(edges: &[(u16, u16, u8, u8, u8)]) -> u64 {
    let mut keys: Vec<u32> = Vec::with_capacity(2 * edges.len());
    for &(from_id, to_id, to_port, from_port_index, to_port_index) in edges {
        let to_key = (u32::from(to_port) << 4) | u32::from(to_port_index);
        keys.push((u32::from(from_id) << 5) | u32::from(from_port_index));
        keys.push((1 << 31) | (u32::from(to_id) << 5) | to_key);
    }
    keys.sort_unstable();
    let mut fans = 0;
    let mut i = 0;
    while i < keys.len() {
        let j = i + keys[i..].iter().take_while(|&&k| k == keys[i]).count();
        if j - i >= 2 {
            fans += 1;
        }
        i = j;
    }
    fans
}

/// `(workloads, modules, edges)` of an encoded resident-workload section, read
/// as the kernel's plan reads it (`resource_ledger::resident_demand`): the
/// count at bytes 10-11, then per workload `[blob_len u32][flags u8]` and the
/// FLXA blob, whose header holds its module count at byte 32 and its edge
/// count at 33.
pub fn resident_demand(section: &[u8]) -> (u64, u64, u64) {
    if section.len() < 12 {
        return (0, 0, 0);
    }
    let count = u16::from_le_bytes([section[10], section[11]]) as u64;
    let (mut modules, mut edges) = (0u64, 0u64);
    let mut off = 12usize;
    for _ in 0..count {
        let Some(b) = section.get(off..off + 4) else {
            break;
        };
        let blob_len = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if let Some(h) = section.get(off + 5..off + 5 + 34) {
            modules += u64::from(h[32]);
            edges += u64::from(h[33]);
        }
        off = off.saturating_add(5).saturating_add(blob_len);
    }
    (count, modules, edges)
}

/// One pool of a boot plan: what the config derives for it (and its modules
/// declare), the reserve on top, and where the reserve came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolPlan {
    pub derived: u64,
    pub reserve: u64,
    /// The reserve is the config's envelope entry, not the profile's default.
    pub from_envelope: bool,
}

impl PoolPlan {
    /// The pool's ceiling: what its table is sized to.
    pub fn ceiling(&self) -> u64 {
        self.derived.saturating_add(self.reserve)
    }
}

/// `(pool, n)` lists: an envelope's entries, or the graph's declared demand.
pub type PoolFigures = [(String, u64)];

fn figure(list: &PoolFigures, pool: &str) -> Option<u64> {
    list.iter().find(|(n, _)| n == pool).map(|&(_, v)| v)
}

/// `pool`'s boot plan on `target`, computed as `resource_ledger::plan`,
/// `plan_parts_wide` and `size_kernel_tables` compute it: the structural part
/// from `shape` (module slots, channels and owners from the graph and its
/// resident workloads, and on bcm2712 a channel per cross-domain edge; on
/// Linux the sandboxes from the owner table's workload slots; the state-arena
/// free list from the module slots), plus `declared` (FXDM), plus the reserve
/// — the envelope's entry in `entries`, never clamped (one past the pool's
/// domain is refused), else what a static table leaves, else the profile's
/// default clamped to what the pool's index domain leaves beside the derived
/// part.
pub fn plan_pool(
    target: &str,
    pool: &str,
    shape: &GraphShape,
    declared: &PoolFigures,
    entries: &PoolFigures,
) -> PoolPlan {
    let profile = kernel_profile(target);
    let static_size = kernel_pool_static_size(target, pool);
    let structural = match pool {
        "module_slots" => {
            shape.modules + shape.fans + shape.workload_modules + shape.workload_edges
        }
        "channels" if profile == "profile_bcm2712" => {
            shape.edges + shape.fans + 2 * shape.workload_edges + shape.crossings
        }
        "channels" => shape.edges + shape.fans + 2 * shape.workload_edges,
        "owners" if kernel_max_owners(target) > 1 => 1 + shape.workloads,
        "owners" => 1,
        "sandboxes" if profile == "profile_linux" => {
            plan_pool(target, "owners", shape, declared, entries)
                .ceiling()
                .saturating_sub(1)
        }
        "state_free_list" if static_size.is_none() => {
            let segments = eval(profile_body(profile), "HEAP_SEGMENTS").unwrap_or(1);
            plan_pool(target, "module_slots", shape, declared, entries).ceiling() * (2 + segments)
                + 1
        }
        _ => 0,
    };
    let derived = structural.saturating_add(figure(declared, pool).unwrap_or(0));
    let entry = figure(entries, pool);
    let reserve = match (entry, static_size) {
        (Some(n), _) => n,
        (None, Some(table)) => table.saturating_sub(derived),
        // The profile's default is headroom, not an ask: it takes what the
        // pool's index domain leaves beside the derived part.
        (None, None) => {
            let default = kernel_pool_default_reserve(target, pool).unwrap_or(0);
            match kernel_pool_domain(target, pool) {
                Some((domain, _)) => default.min(domain.saturating_sub(derived)),
                None => default,
            }
        }
    };
    PoolPlan {
        derived,
        reserve,
        from_envelope: entry.is_some(),
    }
}

/// The kernel's boot-plan checks for a config of `shape` on `target`, with
/// envelope `entries` and declared demand `declared`, run as
/// `size_kernel_tables` runs them: a static table must hold what an envelope
/// asks of it, and every pool with an index domain must keep its ceiling
/// within it. `Err` names the first pool the kernel would refuse, by how much
/// and why; `Ok` is a one-line summary of the structural pools. What a
/// platform's memory cannot hold (a host refusing an allocation, a carve
/// zone running out) only the kernel can know.
pub fn check_boot_plan(
    target: &str,
    shape: &GraphShape,
    entries: &PoolFigures,
    declared: &PoolFigures,
) -> Result<String, String> {
    let mut summary = Vec::new();
    for &(pool, _) in POOL_IDS {
        if !kernel_has_pool(target, pool) || is_arena_name(pool) {
            continue;
        }
        let plan = plan_pool(target, pool, shape, declared, entries);
        // A static table binds an envelope's ask; without one it keeps every
        // slot it has (`resource_ledger::check_static`).
        let static_bound = kernel_pool_static_size(target, pool)
            .filter(|_| plan.from_envelope)
            .map(|t| (t, "static table"));
        let bound = [static_bound, kernel_pool_domain(target, pool)]
            .into_iter()
            .flatten()
            .min_by_key(|&(n, _)| n);
        let Some((bound, what)) = bound else {
            continue;
        };
        let ceiling = plan.ceiling();
        if ceiling > bound {
            let reserve = if plan.from_envelope {
                format!("reserve {} from `capacity:`", plan.reserve)
            } else {
                format!("default reserve {}", plan.reserve)
            };
            let fix = if plan.derived < bound {
                format!(
                    "set `capacity: {{ {pool}: {} }}` or less, or shrink the graph",
                    bound - plan.derived
                )
            } else {
                "shrink the graph: what it derives alone is past the bound".to_string()
            };
            return Err(format!(
                "the {target} kernel's boot plan sizes pool '{pool}' to {ceiling} (derived \
                 {} + {reserve}), past its {what} of {bound} — over by {}; the kernel would \
                 refuse this config at boot. To fit, {fix}.",
                plan.derived,
                ceiling - bound
            ));
        }
        if matches!(pool, "module_slots" | "channels" | "owners") {
            summary.push(format!(
                "{pool} {} + {} of {bound}",
                plan.derived, plan.reserve
            ));
        }
    }
    Ok(format!("Boot plan ({target}): {}", summary.join(", ")))
}

/// Graph-section byte 3 for a section laid out for `slots` edges: the count
/// in units of 128, with 0 meaning 128 (see
/// `kernel::boot::config::GRAPH_SLOTS_CODE`).
pub fn graph_slots_code(slots: usize) -> u8 {
    if slots == 128 {
        0
    } else {
        (slots / 128) as u8
    }
}

/// Edge slots a finished config blob was laid out for, from its graph-section
/// byte 3 — so a tool re-reading a blob needs no target to find its sections.
pub fn edges_for_slots_code(code: u8) -> usize {
    if code == 0 {
        128
    } else {
        code as usize * 128
    }
}

/// Kernel resource-pool registry mirror: `(yaml name, pool id)` — the
/// composer-facing names for `modules/sdk/contracts/resource.rs` ids.
/// Pinned against the contract source by `capacity_pool_ids_match_contract`
/// in `tools/tests/limit_register.rs`.
pub const POOL_IDS: &[(&str, u16)] = &[
    ("state_arena", 0x0001),
    ("buffer_arena", 0x0002),
    ("config_arena", 0x0003),
    ("channels", 0x0004),
    ("events", 0x0005),
    ("timers", 0x0006),
    ("owners", 0x0007),
    ("module_slots", 0x0008),
    ("elastic_region", 0x0009),
    ("store_subs", 0x000A),
    ("store_reads", 0x000B),
    ("store_writes", 0x000C),
    ("store_grants", 0x000D),
    ("sandboxes", 0x000E),
    ("tty_sessions", 0x000F),
    ("tracked_handles", 0x0010),
    ("state_free_list", 0x0011),
    ("net_policy_tables", 0x0012),
    ("net_policy_table_bytes", 0x0013),
    ("owner_store_subs", 0x0014),
    ("owner_store_reads", 0x0015),
    ("owner_store_writes", 0x0016),
    ("net_route_segments", 0x0017),
    ("net_route_peers", 0x0018),
    ("net_route_held", 0x0019),
];

/// An arena entry with this bit set is in KiB — mirror of
/// `resource::ENTRY_KIB`, pinned by `capacity_pool_ids_match_contract` in
/// `tools/tests/limit_register.rs`.
pub const ENTRY_KIB: u32 = 1 << 31;

/// Whether pool `id` is an arena — mirror of `resource::is_arena`.
pub fn is_arena(id: u16) -> bool {
    POOL_IDS
        .iter()
        .any(|&(name, i)| i == id && is_arena_name(name))
}

/// Whether the pool named `name` is an arena (its envelope entry a size in
/// bytes, never derived).
pub fn is_arena_name(name: &str) -> bool {
    matches!(name, "state_arena" | "buffer_arena" | "elastic_region")
}

/// Encode figure `n` (bytes for an arena, slots otherwise) as an envelope
/// entry: exact bytes for an arena below 2 GiB, KiB rounded up with
/// [`ENTRY_KIB`] past it. `None` when it does not fit.
pub fn encode_entry(id: u16, n: u64) -> Option<u32> {
    if is_arena(id) {
        if n < u64::from(ENTRY_KIB) {
            return Some(n as u32);
        }
        let kib = n.div_ceil(1024);
        (kib < u64::from(ENTRY_KIB)).then_some(kib as u32 | ENTRY_KIB)
    } else {
        u32::try_from(n).ok()
    }
}

/// What a module's manifest may declare it will ask of a kernel pool at run
/// time, `([capacities] key, pool name)`. The composer sums the graph's
/// declarations per pool into the FXDM section, and the kernel adds them to
/// the pool's derived size.
pub const DECLARED_DEMAND: &[(&str, &str)] = &[("store_subscriptions", "store_subs")];

/// Envelope section magic "FXEV" — mirror of
/// `resource::ENVELOPE_SECTION_MAGIC`.
pub const ENVELOPE_SECTION_MAGIC: u32 = 0x4658_4556;
/// Declared-demand section magic "FXDM" — mirror of
/// `resource::DEMAND_SECTION_MAGIC`.
pub const DEMAND_SECTION_MAGIC: u32 = 0x4658_444D;

/// Encode a pool section (`abi::contracts::resource`): `[magic][section_len
/// u32][crc16][entry_count u16]` then `[pool u16][n u32]` entries; crc over
/// `section[10..]`. The FXEV envelope and the FXDM declared demand share it.
pub fn encode_pool_section(magic: u32, entries: &[(u16, u32)]) -> Vec<u8> {
    let section_len = 12 + entries.len() * 6;
    let mut s = Vec::with_capacity(section_len);
    s.extend_from_slice(&magic.to_le_bytes());
    s.extend_from_slice(&(section_len as u32).to_le_bytes());
    s.extend_from_slice(&[0, 0]); // crc placeholder
    s.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for (pool, n) in entries {
        s.extend_from_slice(&pool.to_le_bytes());
        s.extend_from_slice(&n.to_le_bytes());
    }
    let crc = crc16_ccitt(&s[10..]);
    s[8..10].copy_from_slice(&crc.to_le_bytes());
    s
}

/// Encode the FXEV capacity-envelope post-body section: each entry a pool's
/// live-add reserve (its size, for a pool the config cannot derive).
pub fn encode_envelope_section(entries: &[(u16, u32)]) -> Vec<u8> {
    encode_pool_section(ENVELOPE_SECTION_MAGIC, entries)
}

/// CRC16-CCITT (poly 0x1021, init 0xFFFF) — the config-blob section CRC.
fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}
