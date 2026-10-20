//! Kernel capacity: the sizes of the kernel's static arenas and tables, per
//! kernel platform.
//!
//! A no_std kernel sizes its static arenas at compile time, and the sizes are
//! platform-specific (rp2040's 264 KiB SRAM and a Pi 5's gigabytes cannot share
//! one figure). This module is where they are stated, and the ONE place the
//! kernel reaches into `platform::chip` for the per-silicon figures the RP
//! build generates from `targets/silicon/*.toml` (the sanctioned
//! D-KERNEL-PLATFORM capacity seam). Every other kernel site consumes the
//! constants from here.
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
//! separate profiles even where their values agree today, so a hosted Linux
//! kernel is not bound to what a Pi 5's linker regions can hold, nor the board
//! to what a Linux host can map.
//!
//! The composer mirrors some of these figures (`tools/src/capacity.rs`), and
//! `compose::capacity_mirrors_kernel_sources` pins every mirrored value against
//! this file. Raising one here means editing that mirror and the limit
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
// A hosted kernel on any Linux machine. Today's figures are the Pi 5's; they
// are stated separately so they can follow the host rather than the board.

#[cfg(feature = "host-linux")]
mod profile_linux {
    /// Pool used by `loader::alloc_state` to back every loaded module's
    /// `module_state` and `module_arena`. It must hold every module of the
    /// busiest graph at once. A node hosts workload subgraphs beside its own
    /// graph, and they draw on the same pool: a node's control plane seats
    /// ~253 MiB on its own, and one key-value workload's state worker asks
    /// 15-23 MiB. 1 GiB holds the node plane and several such workloads. It
    /// is never zeroed whole (the loader zeroes each allocation).
    pub const STATE_ARENA_SIZE: usize = 1024 * 1024 * 1024;
    /// Per-channel buffer pool. A node's own graph and the workload
    /// subgraphs it hosts share it: a node's base graph alone holds ~8 MiB
    /// of channels, and a stateful workload adds two 128 KiB block edges.
    /// 16 MiB leaves room for several such workloads.
    pub const BUFFER_ARENA_SIZE: usize = 16 * 1024 * 1024;
    /// Module slots: a node's own graph plus the workload subgraphs it
    /// hosts, all in one scheduler. A node's control plane and image plane
    /// seat ~250 modules before any workload, and one message-broker
    /// workload is ~17 more. Module ids are u16 throughout the kernel and on
    /// the wire, with 0xFFFF the no-module sentinel, so the ceiling is a
    /// sizing choice: the scheduler's per-module tables, the `ModuleMask`
    /// bitmaps (MODULE_MASK_WORDS == 16 here) and the edge capacity
    /// (MAX_GRAPH_EDGES) scale with it. Modules read it at runtime through
    /// `internal::reconfigure::SLOT_CAPACITY`.
    pub const MAX_MODULES: usize = 1024;
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
}

// ── BCM2712 bare metal (Raspberry Pi 5, QEMU virt) ─────────────────────────
//
// Static arrays only: there is no heap on bare metal, and every byte here is
// either a linker region of its own (the state arena) or kernel `.bss`, which
// must stay below the firmware's reservation (`linker/memory-bcm2712.x`
// asserts it).

#[cfg(feature = "chip-bcm2712")]
mod profile_bcm2712 {
    /// Module state pool (see the Linux profile). The bcm2712 kernel gives it
    /// a linker region of its own above 1 GB, clear of the firmware's
    /// top-of-first-GB reservation, so a Pi 5 needs 2 GB of DRAM. It costs
    /// no image bytes and is never zeroed whole. `targets/silicon/bcm2712.toml`
    /// states the same figure (`state_arena_kb`) for the graph builder.
    pub const STATE_ARENA_SIZE: usize = 1024 * 1024 * 1024;
    /// Per-channel buffer pool (see the Linux profile); zero-initialised
    /// `.bss`.
    pub const BUFFER_ARENA_SIZE: usize = 16 * 1024 * 1024;
    /// Module slots (see the Linux profile). A bare-metal node's control
    /// plane and image plane seat ~250 modules before any workload.
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
    /// heaps. Each carve comes from the state arena above 1 GB and is zeroed
    /// as it is handed out, never a region wholesale.
    pub const HEAP_SEGMENTS: usize = 8;
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
}

// ── RP (rp2040, rp2350) ────────────────────────────────────────────────────
//
// 256-512 KiB SRAM. The arenas, the config sizes and the log ring are
// per-silicon facts that `build.rs` generates from `targets/silicon/*.toml`
// into `platform::chip`; the rest are stated here. `fluxor_abi` tells the two
// dies apart, as it does for the module build.

#[cfg(feature = "rp")]
mod profile_rp {
    /// Module state pool, from `[kernel] state_arena_kb` in the silicon TOML.
    pub const STATE_ARENA_SIZE: usize = crate::platform::chip::STATE_ARENA_SIZE;
    /// Channel buffer pool, from `[kernel] buffer_arena_kb`.
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
    /// Module slots.
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
}

const _: () = assert!(
    LOG_RING_CAPACITY.is_power_of_two(),
    "the log ring is indexed by mask"
);
const _: () = assert!(
    HEAP_SEGMENTS >= 1 && HEAP_SEGMENTS <= 32,
    "a heap's first segment is cap >> (HEAP_SEGMENTS - 1)"
);
