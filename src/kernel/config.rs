//! Kernel capacity: the sizes of the kernel's static arenas and tables, per
//! kernel platform.
//!
//! A no_std kernel sizes its static arenas at compile time, and the sizes are
//! platform-specific (rp2040's 264 KiB SRAM and a Pi 5's gigabytes cannot share
//! one figure). This module is where they are stated, and the one place the
//! kernel reaches into `platform::chip` for the per-silicon figures the RP
//! build generates from `targets/silicon/*.toml`. Every other kernel site
//! consumes the constants from here.
//!
//! **Kernel capacity is not ABI.** Nothing here is part of the module ABI, and
//! nothing under `modules/sdk` restates it: the SDK is hashed into the
//! ABI-surface digest, so a size stated there would turn raising it into an
//! ABI epoch and a workspace republish although no module reads it. A module
//! that needs one of these figures asks the kernel at runtime (the module slot
//! count is `internal::reconfigure::SLOT_CAPACITY`) or keys its own sizing on
//! the SDK's coarse `abi::config::TARGET_CLASS`. The `kernel_capacity_gate`
//! tools test fails if a kernel capacity constant reappears in the SDK or in
//! module source.
//!
//! One profile per kernel platform, selected by the platform feature:
//! `host-linux`, `chip-bcm2712`, `host-wasm` and `rp`. Linux and bcm2712 are
//! separate profiles even where their values agree, so a hosted Linux kernel
//! is not bound to what a Pi 5's linker regions can hold, nor the board to
//! what a Linux host can map.
//!
//! The composer reads these profiles as data (`tools/src/capacity.rs` embeds
//! this file) and runs the kernel's boot plan with them, so a value changed
//! here reaches it with a tools rebuild. Raising one means editing the limit
//! register row in the same change — and no ABI epoch.

#[cfg(feature = "host-linux")]
pub use self::profile_linux::*;

#[cfg(feature = "chip-bcm2712")]
pub use self::profile_bcm2712::*;

#[cfg(feature = "host-wasm")]
pub use self::profile_wasm::*;

#[cfg(feature = "rp")]
pub use self::profile_rp::*;

// ── Linux host ─────────────────────────────────────────────────────────────
//
// A hosted kernel on any Linux machine. Its figures match the bcm2712 profile's
// and are stated separately so they follow the host rather than the board.

#[cfg(feature = "host-linux")]
mod profile_linux {
    /// Pool used by `loader::alloc_state` to back every loaded module's
    /// `module_state` and `module_arena`. It must hold every module of the
    /// busiest graph at once. A node hosts workload subgraphs beside its own
    /// graph, and they draw on the same pool: a node's control plane seats
    /// ~253 MiB on its own, and one key-value workload's state worker asks
    /// 15-23 MiB. 1 GiB holds the node plane and several such workloads. It
    /// is never zeroed whole: it starts zero, and the loader returns each
    /// freed region to zero as it is freed.
    pub const STATE_ARENA_SIZE: usize = 1024 * 1024 * 1024;
    /// Per-channel buffer pool. A node's own graph and the workload
    /// subgraphs it hosts share it, and a stateful workload adds two
    /// 128 KiB block edges. `fluxor build` adds a graph's rings up and
    /// refuses one that does not fit, printing its share and the slack left
    /// for the workloads the node will admit.
    pub const BUFFER_ARENA_SIZE: usize = 16 * 1024 * 1024;
    /// The module-index DOMAIN, not a table size: the scheduler's per-module
    /// tables are sized at boot from the graph (`resource_ledger::plan`), its
    /// module count, fans and resident workloads plus the module-slot
    /// reserve. What this bounds is what a module index may be at all: a
    /// boot-config module id carries 12 bits (entry byte 8 plus four bits of
    /// byte 9), and a `ModuleMask` holds one bit per index in a fixed number
    /// of words. A plan past it is refused at boot naming `module_slots`.
    /// Modules read the live slot count at runtime through
    /// `internal::reconfigure::SLOT_CAPACITY`.
    pub const MAX_MODULES: usize = 4096;
    /// ISR-tier bridge slots: one per edge that crosses into an ISR-tier
    /// domain, each holding its ring inline (~2 KiB).
    pub const MAX_BRIDGES: usize = 16;
    /// Loader sanity ceiling for a single module's code segment. 1 MiB fits
    /// media modules (the unified codec's decoder plus its CAVLC/clip tables
    /// runs ~450 KiB) and protocol modules that bundle firmware blobs.
    pub const MAX_MODULE_CODE_SIZE: usize = 1024 * 1024;
    /// Capacity of the in-memory log ring (`kernel::sys::log_ring`). Sized
    /// for moderate trace volume.
    pub const LOG_RING_CAPACITY: usize = 65536;
    /// Kernel elastic region backing Tier B chunk grants
    /// (`resource::ELASTIC_ALLOC`). 16 MiB: room for TLS-session growth to
    /// its compiled maximum (~7.9 MiB at `tls::MAX_SESSIONS`, once 104 KiB
    /// chunks round up to the quantum below) plus several workloads' worth
    /// of headroom, and deliberately oversubscribable — Σ of pool maxima MAY
    /// exceed it; contention is a counted denial, mins are load-time.
    pub const ELASTIC_REGION_SIZE: usize = 16 * 1024 * 1024;
    /// Grant granularity: chunks are rounded up to this quantum (the 64 KiB
    /// platform quantum).
    pub const ELASTIC_QUANTUM: usize = 64 * 1024;
    /// Segments one module heap may carve (`kernel::mem::heap`). Above 1 a
    /// heap is elastic: it commits state-arena memory as the module
    /// allocates, up to its cap, rather than carving the cap at
    /// instantiation. Eight is derived, not tuned: the first segment is
    /// `cap >> 7` and each carve at least doubles what is committed, so
    /// eight carves reach any cap.
    pub const HEAP_SEGMENTS: usize = 8;

    /// Each kernel pool's DEFAULT reserve: what the boot plan adds to the
    /// pool's derived size when the boot config's capacity envelope (FXEV)
    /// carries no entry for it. A pool the graph cannot size (events,
    /// timers, TTY sessions, …) has no derived part, so its default is its
    /// size; the sandbox pool's derived part is the owner table's workload
    /// slots. A pool held within an index domain (module slots, channels,
    /// owners, events, timers, sandboxes, TTY sessions) takes only the part
    /// of its default the domain leaves beside the derived size
    /// (`resource_ledger::pool_domain`); an envelope entry is never clamped. Every table is sized at boot from derived + reserve
    /// (`resource_ledger::plan`); none of these is a ceiling, and a
    /// deployment that needs more says so in its `capacity:` block.
    ///
    /// The derived pools' reserves are live-add headroom: module slots and
    /// channels for the workload subgraphs a node admits after boot (a
    /// message broker is ~17 modules and ~50 edges), owners for the
    /// workloads themselves, store subscriptions for the store consumers
    /// those workloads bring.
    pub const DEFAULT_RESERVES: &[(u16, usize)] = &[
        (res::POOL_MODULE_SLOTS, 256),
        (res::POOL_CHANNELS, 512),
        (res::POOL_OWNERS, 63),
        (res::POOL_STORE_SUBS, 64),
        (res::POOL_STATE_FREE_LIST, 32),
        (res::POOL_EVENTS, 32),
        (res::POOL_TIMERS, 16),
        (res::POOL_STORE_READS, 32),
        (res::POOL_STORE_WRITES, 32),
        (res::POOL_STORE_GRANTS, 64),
        (res::POOL_SANDBOXES, 64),
        (res::POOL_TTY_SESSIONS, 8),
        (res::POOL_TRACKED_HANDLES, 128),
        (res::POOL_NET_POLICY_TABLES, 8),
        (res::POOL_NET_POLICY_TABLE_BYTES, 8192),
        (res::POOL_OWNER_STORE_SUBS, 16),
        (res::POOL_OWNER_STORE_READS, 8),
        (res::POOL_OWNER_STORE_WRITES, 4),
        (res::POOL_NET_ROUTE_SEGMENTS, 16),
        (res::POOL_NET_ROUTE_PEERS, 256),
        (res::POOL_NET_ROUTE_HELD, 256),
        (res::POOL_STATE_ARENA, STATE_ARENA_SIZE),
        (res::POOL_BUFFER_ARENA, BUFFER_ARENA_SIZE),
        (res::POOL_ELASTIC_REGION, ELASTIC_REGION_SIZE),
    ];
    /// No pool is a static table here.
    pub const STATIC_POOLS: &[(u16, usize)] = &[];
    use crate::abi::contracts::resource as res;
}

// ── BCM2712 bare metal (Raspberry Pi 5, QEMU virt) ─────────────────────────
//
// No heap on bare metal. The kernel's tables are sized at boot from the graph
// (`resource_ledger::plan`), as on Linux, and carved from the DRAM zone the
// device tree describes above the boot image (`kernel::mem::carve`,
// `platform/bcm2712/memmap.rs`); the module state arena takes what the carves
// leave of that zone. Kernel `.bss` holds the fixed arenas only, and must
// stay below the firmware's reservation (`linker/memory-bcm2712.x` asserts
// it).

#[cfg(feature = "chip-bcm2712")]
mod profile_bcm2712 {
    /// Module state pool the graph builder plans against: the smallest zone a
    /// supported board leaves (a 2 GB Pi 5's DRAM above 1 GB, QEMU virt's
    /// upper GB at `-m 2G`). The arena itself is sized at boot from the device
    /// tree — the zone above the boot image, less the tables carved from its
    /// top — and is never zeroed whole. `targets/silicon/bcm2712.toml` states
    /// the same figure (`state_arena_kb`) for the graph builder.
    pub const STATE_ARENA_SIZE: usize = 1024 * 1024 * 1024;
    /// Per-channel buffer pool (see the Linux profile); zero-initialised
    /// `.bss`.
    pub const BUFFER_ARENA_SIZE: usize = 16 * 1024 * 1024;
    /// The module-index DOMAIN (see the Linux profile), not a table size: the
    /// scheduler's per-module tables are sized at boot from the graph plus the
    /// module-slot reserve. A bare-metal node's control plane and image plane
    /// seat ~250 modules before any workload.
    pub const MAX_MODULES: usize = 1024;
    /// ISR-tier bridge slots (see the Linux profile).
    pub const MAX_BRIDGES: usize = 16;
    /// Loader sanity ceiling for a single module's code segment (see the
    /// Linux profile).
    pub const MAX_MODULE_CODE_SIZE: usize = 1024 * 1024;
    /// Early-boot log ring. Not raised past 64 KiB: the whole ring is
    /// replayed in one burst when a consumer attaches, and on the Pi 5 rig a
    /// 256 KiB ring outran the collector's socket buffer.
    pub const LOG_RING_CAPACITY: usize = 65536;
    /// Tier B elastic region (see the Linux profile). Zero-initialised, so
    /// the size costs kernel `.bss` rather than image.
    pub const ELASTIC_REGION_SIZE: usize = 16 * 1024 * 1024;
    /// Grant granularity: the 64 KiB platform quantum.
    pub const ELASTIC_QUANTUM: usize = 64 * 1024;
    /// Segments one module heap may carve (see the Linux profile): elastic
    /// heaps. Each carve comes from the state arena and takes memory the
    /// arena's zeroed frontier has already cleared.
    pub const HEAP_SEGMENTS: usize = 8;
    /// How far the state arena's zeroed frontier runs ahead of the memory the
    /// arena has handed out: the growth the domains' slack keeps cleared, so
    /// an allocation on a module's step finds zeroed memory waiting.
    pub const ZERO_AHEAD_BYTES: usize = 64 * 1024 * 1024;
    /// Bytes one slack claim zeroes: the unit of bounded work a domain does
    /// between checks of its remaining slack (~10 us on a Cortex-A76).
    pub const ZERO_CHUNK_BYTES: usize = 64 * 1024;

    /// Each kernel pool's DEFAULT reserve (see the Linux profile): what the
    /// boot plan adds to a pool's derived size when the boot config's
    /// capacity envelope (FXEV) carries no entry for it, or its size for a
    /// pool the graph cannot derive. Every table is sized at boot from
    /// derived + reserve and carved; none is a compiled ceiling.
    pub const DEFAULT_RESERVES: &[(u16, usize)] = &[
        (res::POOL_MODULE_SLOTS, 256),
        (res::POOL_CHANNELS, 512),
        (res::POOL_OWNERS, 63),
        (res::POOL_STORE_SUBS, 64),
        (res::POOL_STATE_FREE_LIST, 32),
        (res::POOL_EVENTS, 32),
        (res::POOL_TIMERS, 16),
        (res::POOL_STORE_READS, 32),
        (res::POOL_TRACKED_HANDLES, 128),
        (res::POOL_NET_POLICY_TABLES, 8),
        (res::POOL_NET_POLICY_TABLE_BYTES, 8192),
        (res::POOL_NET_ROUTE_SEGMENTS, 16),
        (res::POOL_NET_ROUTE_PEERS, 256),
        (res::POOL_NET_ROUTE_HELD, 256),
        (res::POOL_STATE_ARENA, STATE_ARENA_SIZE),
        (res::POOL_BUFFER_ARENA, BUFFER_ARENA_SIZE),
        (res::POOL_ELASTIC_REGION, ELASTIC_REGION_SIZE),
    ];
    /// No pool is a static table here.
    pub const STATIC_POOLS: &[(u16, usize)] = &[];
    use crate::abi::contracts::resource as res;
}

// ── wasm32 (browser, wasmtime, edge runtimes) ──────────────────────────────
//
// User-space-class memory but tighter budgets than Linux host — browser tabs
// are squeezed; edge runtimes have memory ceilings.

#[cfg(feature = "host-wasm")]
mod profile_wasm {
    /// Sized to hold a console-emulator graph at a 32 MiB cartridge ceiling:
    /// the core streams the ROM straight into its emulated bus (~32 MiB ROM +
    /// machine RAM, no second full-ROM copy) and a file loader stages one
    /// framed copy (~32 MiB) to emit the load command — ~72 MiB of live state
    /// at peak, plus the small video / audio / mapper modules. 96 MiB covers
    /// it with margin. The arena is paged in lazily by `memory.grow`.
    pub const STATE_ARENA_SIZE: usize = 96 * 1024 * 1024;
    /// Loader sanity ceiling for a single module's code segment (see the
    /// Linux profile).
    pub const MAX_MODULE_CODE_SIZE: usize = 1024 * 1024;
    /// Holds ALL channel ring buffers for the live graph. GPU-offload graphs
    /// wire multi-MiB frame channels (a whole serialized frame — up to
    /// ~1.57 MiB dense — must cross child->kernel in one ring fill) plus the
    /// small audio/input/command channels. 8 MiB is sized for chunk's GPU
    /// command ring, which wants a 4 MiB channel and alone fills a 4 MiB
    /// arena. Lazily paged by memory.grow, so it costs nothing until used.
    pub const BUFFER_ARENA_SIZE: usize = 8 * 1024 * 1024;
    /// 48: a multi-emulator browser graph (music + Game Boy + Spectrum
    /// chains) declares ~22 modules and the kernel inserts an internal
    /// tee/merge per fan, which 32 cannot hold.
    pub const MAX_MODULES: usize = 48;
    /// ISR-tier bridge slots (see the Linux profile).
    pub const MAX_BRIDGES: usize = 16;
    /// Early-boot log ring.
    pub const LOG_RING_CAPACITY: usize = 16384;
    /// Tier B elastic region. Browser tabs page lazily, but the region is
    /// still budgeted small.
    pub const ELASTIC_REGION_SIZE: usize = 2 * 1024 * 1024;
    /// Grant granularity: the wasm page.
    pub const ELASTIC_QUANTUM: usize = 64 * 1024;
    /// One segment per module heap: every heap is committed whole at
    /// instantiation.
    pub const HEAP_SEGMENTS: usize = 1;
    /// Graph edge slots: the config blob's graph section holds this many, and
    /// the channel table one per edge.
    pub const GRAPH_EDGES: usize = 128;

    /// The pools this profile holds as static tables, `(pool, size)`: the
    /// ceiling every boot plan must fit. The composer reads this table as the
    /// profile's data (`tools/src/capacity.rs`).
    pub const STATIC_POOLS: &[(u16, usize)] = &[
        (res::POOL_MODULE_SLOTS, MAX_MODULES),
        (res::POOL_CHANNELS, GRAPH_EDGES),
        (res::POOL_OWNERS, 1),
        (res::POOL_EVENTS, 32),
        (res::POOL_TIMERS, 16),
        (res::POOL_TRACKED_HANDLES, 128),
        (res::POOL_STATE_FREE_LIST, 32),
        (res::POOL_NET_POLICY_TABLES, 2),
        (res::POOL_NET_POLICY_TABLE_BYTES, 2048),
        (res::POOL_NET_ROUTE_SEGMENTS, 0),
        (res::POOL_NET_ROUTE_PEERS, 0),
        (res::POOL_NET_ROUTE_HELD, 0),
        (res::POOL_STATE_ARENA, STATE_ARENA_SIZE),
        (res::POOL_BUFFER_ARENA, BUFFER_ARENA_SIZE),
        (res::POOL_ELASTIC_REGION, ELASTIC_REGION_SIZE),
    ];
    /// Static tables have no reserve.
    pub const DEFAULT_RESERVES: &[(u16, usize)] = &[];
    use crate::abi::contracts::resource as res;
}

// ── RP (rp2040, rp2350) ────────────────────────────────────────────────────
//
// 256-512 KiB SRAM. The kernel's tables and its two arenas share one static
// pool (`kernel::mem::carve::POOL`, `KERNEL_POOL_SIZE`), which each graph's
// plan splits at boot: the tables are sized from what
// the graph derives plus the reserves below and carved off the pool's top,
// the channel buffer arena takes its ceiling below them, and the module state
// arena gets the rest. The pool, the default arena figures, the config sizes
// and the log ring are per-silicon facts that `build.rs` generates from
// `targets/silicon/*.toml` into `platform::chip`; the rest are stated here.
// What stays compile-time is the domains: module ids within `MAX_MODULES`,
// channel ids within the config blob's `GRAPH_EDGES` slots.

#[cfg(feature = "rp")]
mod profile_rp {
    /// The kernel's static pool, from `[kernel] kernel_pool_kb` in the silicon
    /// TOML: the silicon's static-RAM budget (`ram_static_max_kb`) less the
    /// kernel's fixed statics. Every table the plan sizes, the buffer arena
    /// and the state arena come from it.
    pub const KERNEL_POOL_SIZE: usize = crate::platform::chip::KERNEL_POOL_SIZE;
    /// The module state arena a graph that states no `state_arena` envelope
    /// entry is planned against, from `[kernel] state_arena_kb`: the composer
    /// admits a graph's module state against it. The arena itself is what the
    /// pool holds beside the graph's tables and buffer arena, at least this
    /// for any graph the composer admits.
    pub const STATE_ARENA_SIZE: usize = crate::platform::chip::STATE_ARENA_SIZE;
    /// Channel buffer arena a graph gets without a `buffer_arena` envelope
    /// entry, from `[kernel] buffer_arena_kb`.
    pub const BUFFER_ARENA_SIZE: usize = crate::platform::chip::BUFFER_ARENA_SIZE;
    /// The buffer a module's compiled params and its stored runtime
    /// overrides are merged in, from `[kernel] config_buffer_kb`. Only an
    /// instance the flash parameter store holds an override for is copied
    /// there; every other module borrows its params from flash in place, at
    /// any size. A merge that does not fit refuses the instance, loudly.
    pub const MAX_MODULE_CONFIG_SIZE: usize = crate::platform::chip::MAX_MODULE_CONFIG_SIZE;
    /// Early-boot log ring, from `[kernel] log_ring_kb`. Must be a power of
    /// two.
    pub const LOG_RING_CAPACITY: usize = crate::platform::chip::LOG_RING_CAPACITY;
    /// The module-index DOMAIN, not a table size: the module tables are sized
    /// from the plan within it. A `ModuleMask` holds one bit per index.
    pub const MAX_MODULES: usize = 32;
    /// ISR-tier bridge slots. Eight is the ISR edges a graph of this size
    /// has, at ~2 KiB of static RAM each.
    pub const MAX_BRIDGES: usize = 8;
    /// Loader sanity ceiling for a single module's code segment. Code
    /// executes in place from flash, so this costs no RAM and is set by the
    /// part's flash: 1 MiB on the 4 MiB RP2350, which a JavaScript engine
    /// (~440 KiB) fits; 384 KiB on the 2 MiB RP2040. `module_code_kb` in the
    /// silicon TOML mirrors it for the packer.
    #[cfg(not(fluxor_abi = "thumbv6m"))]
    pub const MAX_MODULE_CODE_SIZE: usize = 1024 * 1024;
    #[cfg(fluxor_abi = "thumbv6m")]
    pub const MAX_MODULE_CODE_SIZE: usize = 384 * 1024;
    /// No Tier B on MCU-class targets: elasticity compiles out —
    /// `ELASTIC_ALLOC` denies.
    pub const ELASTIC_REGION_SIZE: usize = 0;
    /// Grant granularity (unused while the region is empty).
    pub const ELASTIC_QUANTUM: usize = 1024;
    /// One segment per module heap: every heap is committed whole at
    /// instantiation, as the silicon TOML's state-arena budget plans it.
    pub const HEAP_SEGMENTS: usize = 1;
    /// Graph edge slots: the config blob's graph section holds this many, so
    /// it is the channel-id domain; the channel table is sized from the plan
    /// within it.
    pub const GRAPH_EDGES: usize = 128;

    /// Each kernel pool's DEFAULT reserve (see the Linux profile): what the
    /// boot plan adds to a pool's derived size when the boot config's
    /// capacity envelope (FXEV) carries no entry for it, or its size for a
    /// pool the graph cannot derive. The derived pools' reserves are slim —
    /// an MCU graph changes by a rebuild, which plans the pool again — and
    /// cover the channels a module opens for itself and the fan modules the
    /// plan's upper bound misses. The arenas' entries are the defaults the
    /// split starts from (the state arena takes what is left).
    pub const DEFAULT_RESERVES: &[(u16, usize)] = &[
        (res::POOL_MODULE_SLOTS, 4),
        (res::POOL_CHANNELS, 16),
        (res::POOL_OWNERS, 0),
        (res::POOL_STATE_FREE_LIST, 32),
        (res::POOL_EVENTS, 32),
        (res::POOL_TIMERS, 16),
        (res::POOL_TRACKED_HANDLES, 128),
        (res::POOL_NET_POLICY_TABLES, 0),
        (res::POOL_NET_POLICY_TABLE_BYTES, 2048),
        (res::POOL_NET_ROUTE_SEGMENTS, 0),
        (res::POOL_NET_ROUTE_PEERS, 0),
        (res::POOL_NET_ROUTE_HELD, 0),
        (res::POOL_STATE_ARENA, STATE_ARENA_SIZE),
        (res::POOL_BUFFER_ARENA, BUFFER_ARENA_SIZE),
        (res::POOL_ELASTIC_REGION, ELASTIC_REGION_SIZE),
    ];
    /// No pool is a static table here.
    pub const STATIC_POOLS: &[(u16, usize)] = &[];
    use crate::abi::contracts::resource as res;
}

const _: () = assert!(
    LOG_RING_CAPACITY.is_power_of_two(),
    "the log ring is indexed by mask"
);
const _: () = assert!(
    HEAP_SEGMENTS >= 1 && HEAP_SEGMENTS <= 32,
    "a heap's first segment is cap >> (HEAP_SEGMENTS - 1)"
);

/// `pool`'s entry in a profile table, or `None`.
const fn lookup(table: &[(u16, usize)], pool: u16) -> Option<usize> {
    let mut i = 0;
    while i < table.len() {
        if table[i].0 == pool {
            return Some(table[i].1);
        }
        i += 1;
    }
    None
}

/// The static size of `pool` on this profile, `None` where the profile sizes
/// the pool at boot (every pool on Linux, bcm2712 and RP).
pub const fn static_pool(pool: u16) -> Option<usize> {
    lookup(STATIC_POOLS, pool)
}

/// The compiled size of a static table, for its array type: the profile's
/// static size, or `0` on a profile that sizes the pool at boot (the table's
/// backend ignores it there).
pub const fn static_slots(pool: u16) -> usize {
    match static_pool(pool) {
        Some(n) => n,
        None => 0,
    }
}

/// The reserve the boot plan adds to `pool`'s derived size when the boot
/// config carries no envelope entry for it: the profile's default, `0` where
/// the pool is a static table (whose ceiling is the table).
pub const fn default_reserve(pool: u16) -> usize {
    match lookup(DEFAULT_RESERVES, pool) {
        Some(n) => n,
        None => 0,
    }
}

const _: () = assert!(
    MAX_MODULES <= 4096,
    "a boot-config module id carries 12 bits"
);
