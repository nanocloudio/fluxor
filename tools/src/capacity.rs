//! Per-target kernel capacity facts shared by the boot-blob builder and the
//! composer. The single tools-side source for values the kernel defines per
//! arch profile — pinned against kernel source text by
//! `compose::capacity_mirrors_kernel_sources`.

/// Kernel `MAX_MODULES` for the arch profile a target compiles
/// (`modules/sdk/abi/config.rs`): the module-count ceiling the boot blob
/// builder enforces per target instead of one global constant. Unknown
/// targets get the embedded floor — a graph that fits the smallest
/// profile fits everywhere.
pub fn kernel_max_modules(target: &str) -> usize {
    match target {
        // aarch64 profile_host (linux host + bcm2712-family boards).
        "linux" | "pi5" | "bcm2712" | "cm5" | "qemu-virt" => 192,
        // wasm32 profile_wasm.
        "wasm" => 48,
        // Everything else (rp2040/rp2350 boards): profile_embedded.
        _ => 32,
    }
}

/// Kernel resource-pool registry mirror: `(yaml name, pool id)` — the
/// composer-facing names for `modules/sdk/contracts/resource.rs` ids.
/// Pinned against the contract source by `tools/tests/limit_register.rs`'s
/// sibling `capacity_pool_ids_match_contract` gate.
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
    let host = matches!(target, "linux" | "pi5" | "bcm2712" | "cm5" | "qemu-virt");
    let wasm = target == "wasm";
    match pool {
        // Fixed across every profile.
        "events" => Some(32),
        "timers" => Some(16),
        "channels" => Some(128), // MAX_GRAPH_EDGES
        "module_slots" => Some(kernel_max_modules(target) as u64),
        // Multitenant is an aarch64 feature; other targets have no
        // workload slots to enforce.
        "owners" => Some(if host { 64 } else { 1 }),
        // Arch-profile arenas (abi/config.rs). RP arenas come from the
        // silicon TOML — not mirrored here; kernel clamps at boot.
        "state_arena" if host || wasm => Some(256 * 1024 * 1024),
        "buffer_arena" if host || wasm => Some(8 * 1024 * 1024),
        "config_arena" if host => Some(256 * 1024),
        "config_arena" if wasm => Some(32 * 1024),
        // Tier B elastic region (abi/config.rs ELASTIC_REGION_SIZE).
        "elastic_region" if host => Some(8 * 1024 * 1024),
        "elastic_region" if wasm => Some(2 * 1024 * 1024),
        "elastic_region" => Some(0),
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
