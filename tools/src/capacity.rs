//! Per-target kernel capacity facts shared by the boot-blob builder and the
//! composer. The single tools-side source for values the kernel defines per
//! platform in `src/kernel/config.rs` — every one pinned against that source
//! text by `compose::capacity_mirrors_kernel_sources`, so a kernel raise that
//! forgets this mirror fails the tools tests rather than admitting graphs the
//! kernel cannot hold (or refusing ones it can).
//!
//! Kernel capacity is not ABI: raising a value here and in the kernel
//! rebuilds the CLI and the kernel, and moves no ABI epoch.

/// Targets whose kernel compiles `profile_bcm2712` (`src/kernel/config.rs`).
fn is_bcm2712(target: &str) -> bool {
    matches!(target, "pi5" | "bcm2712" | "cm5" | "qemu-virt")
}

/// Kernel `MAX_MODULES` for the kernel platform a target compiles
/// (`src/kernel/config.rs`): the module-count ceiling the boot blob
/// builder enforces per target instead of one global constant. Unknown
/// targets get the RP floor — a graph that fits the smallest profile
/// fits everywhere.
pub fn kernel_max_modules(target: &str) -> usize {
    match target {
        // profile_linux.
        "linux" => LINUX_MAX_MODULES,
        // profile_bcm2712 (Pi 5, CM5, QEMU virt).
        t if is_bcm2712(t) => BCM2712_MAX_MODULES,
        // profile_wasm.
        "wasm" => WASM_MAX_MODULES,
        // Everything else (rp2040/rp2350 boards): profile_rp.
        _ => RP_MAX_MODULES,
    }
}

/// profile_linux `MAX_MODULES`.
pub const LINUX_MAX_MODULES: usize = 1024;
/// profile_bcm2712 `MAX_MODULES`.
pub const BCM2712_MAX_MODULES: usize = 1024;
/// profile_wasm `MAX_MODULES`.
pub const WASM_MAX_MODULES: usize = 48;
/// profile_rp `MAX_MODULES`.
pub const RP_MAX_MODULES: usize = 32;

/// Kernel `MAX_GRAPH_EDGES` for the arch profile a target compiles
/// (`src/kernel/boot/config.rs`): 1536 on the host profile, 128 elsewhere.
/// The config blob's graph section is laid out for exactly this many edge
/// slots.
pub fn kernel_max_edges(target: &str) -> usize {
    if kernel_max_modules(target) > 128 {
        1536
    } else {
        128
    }
}

/// profile_linux and profile_bcm2712 `STATE_ARENA_SIZE`
/// (`src/kernel/config.rs`): the two profiles state the same value, and the
/// mirror test pins each profile separately, so a divergence fails it.
pub const HOST_STATE_ARENA: u64 = 1024 * 1024 * 1024;
/// profile_linux and profile_bcm2712 `BUFFER_ARENA_SIZE`.
pub const HOST_BUFFER_ARENA: u64 = 16 * 1024 * 1024;
/// profile_linux and profile_bcm2712 `ELASTIC_REGION_SIZE`.
pub const HOST_ELASTIC_REGION: u64 = 16 * 1024 * 1024;
/// profile_wasm `STATE_ARENA_SIZE`.
pub const WASM_STATE_ARENA: u64 = 96 * 1024 * 1024;
/// profile_wasm `BUFFER_ARENA_SIZE`.
pub const WASM_BUFFER_ARENA: u64 = 8 * 1024 * 1024;
/// profile_wasm `ELASTIC_REGION_SIZE`.
pub const WASM_ELASTIC_REGION: u64 = 2 * 1024 * 1024;
/// profile_rp `ELASTIC_REGION_SIZE`: Tier B compiles out on the RP parts.
pub const RP_ELASTIC_REGION: u64 = 0;

/// The channel buffer arena (`BUFFER_ARENA_SIZE`) of the kernel profile
/// `runtime` compiles, where `src/kernel/config.rs` states it. The RP kernels
/// take theirs from the silicon TOML (`[kernel] buffer_arena_kb`), which the
/// target descriptor carries.
pub fn kernel_buffer_arena(runtime: &str) -> Option<u64> {
    match runtime {
        "linux" | "bcm2712" => Some(HOST_BUFFER_ARENA),
        "wasm" => Some(WASM_BUFFER_ARENA),
        _ => None,
    }
}

/// Graph-section byte 3 for a target: the edge-slot count in units of 128,
/// with 0 meaning 128 (see `kernel::boot::config::GRAPH_SLOTS_CODE`).
pub fn graph_slots_code(max_edges: usize) -> u8 {
    if max_edges == 128 {
        0
    } else {
        (max_edges / 128) as u8
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
];

/// Compiled static capacity of a kernel pool for `target`, in the pool's
/// own units (bytes for arenas, slots for tables) — the ceiling a
/// `capacity:` envelope entry may not exceed. `None` = not statically
/// known here (RP arena sizes live in the silicon TOML; the kernel clamps
/// an over-ask at boot and logs). Values are pinned against kernel source
/// by `compose::capacity_mirrors_kernel_sources`.
pub fn kernel_pool_static_cap(target: &str, pool: &str) -> Option<u64> {
    let host = target == "linux" || is_bcm2712(target);
    let wasm = target == "wasm";
    match pool {
        // Fixed across every profile.
        "events" => Some(32),
        "timers" => Some(16),
        "channels" => Some(kernel_max_edges(target) as u64), // MAX_GRAPH_EDGES
        "module_slots" => Some(kernel_max_modules(target) as u64),
        // Multitenant is an aarch64 feature; other targets have no
        // workload slots to enforce.
        "owners" => Some(if host { 64 } else { 1 }),
        // Platform arenas (src/kernel/config.rs). RP arenas come from the
        // silicon TOML — not mirrored here; kernel clamps at boot.
        "state_arena" if host => Some(HOST_STATE_ARENA),
        "state_arena" if wasm => Some(WASM_STATE_ARENA),
        "buffer_arena" if host => Some(HOST_BUFFER_ARENA),
        "buffer_arena" if wasm => Some(WASM_BUFFER_ARENA),
        // `config_arena` has no compiled size on any profile: module params
        // are borrowed from the config blob in place, so the pool is the
        // blob itself and the kernel reports it against the blob's length.
        // Tier B elastic region (kernel ELASTIC_REGION_SIZE).
        "elastic_region" if host => Some(HOST_ELASTIC_REGION),
        "elastic_region" if wasm => Some(WASM_ELASTIC_REGION),
        "elastic_region" => Some(RP_ELASTIC_REGION),
        _ => None,
    }
}

/// Encode the FXEV capacity-envelope post-body section
/// (`abi::contracts::resource`): `[FXEV][section_len u32][crc16][entry_count
/// u16]` then `[pool u16][n u32]` entries; crc over `section[10..]`.
pub fn encode_envelope_section(entries: &[(u16, u32)]) -> Vec<u8> {
    /// "FXEV" — mirror of `resource::ENVELOPE_SECTION_MAGIC`.
    const ENVELOPE_SECTION_MAGIC: u32 = 0x4658_4556;
    let section_len = 12 + entries.len() * 6;
    let mut s = Vec::with_capacity(section_len);
    s.extend_from_slice(&ENVELOPE_SECTION_MAGIC.to_le_bytes());
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
