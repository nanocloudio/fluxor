// Canonical capacity / sizing tunables.
//
// One coherent envelope per board profile. Adding a new target
// means adding a `profile_*` module here, not editing 30 files.
//
// Why centralised: capacity knobs cross subsystem boundaries. The
// HTTP module's `MAX_CONCURRENT_CONNS` only makes sense if the IP
// module's `MAX_TCP_CONNS` is at least as large; the kernel's
// `STATE_ARENA_SIZE` has to fit every loaded module's
// `module_arena_size()`; `LOG_RING_CAPACITY` interacts with how
// much trace volume the system can absorb under load. When these
// lived in their owning modules, every change required a
// coordinated edit across the tree. Centralising them lets a
// reviewer see the full envelope on one screen and lets the
// compiler enforce cross-subsystem invariants.
//
// What lives here: cross-cutting capacity tunables. If a constant
// is referenced by more than one subsystem, or interacts with
// `STATE_ARENA_SIZE` or `module_arena_size()`, it belongs here.
//
// What does NOT live here: module-private opcodes, RFC values,
// internal struct offsets, per-chip register layouts. Those stay
// in the module that owns them.
//
// Adding a tunable:
// 1. Add it to all three profile modules below with values that
//    suit each target's memory budget.
// 2. (No extra step — the `pub use` is wildcarded.)
// 3. If it interacts with another subsystem, add a
//    `const _: () = assert!(...);` at the bottom.
// 4. `pub use abi::config::<subsystem>::*` in the consumer.

#[cfg(target_arch = "aarch64")]
pub use self::profile_host::*;

#[cfg(target_arch = "wasm32")]
pub use self::profile_wasm::*;

#[cfg(not(any(target_arch = "aarch64", target_arch = "wasm32")))]
pub use self::profile_embedded::*;

// The three `profile_*` modules below each define the FULL set of
// tunables for one target class. Only the cfg-selected one above is
// re-exported, so the others' constants would otherwise trip the
// `dead_code` lint (and the cross-subsystem invariants below would
// trigger duplicate-definition errors). Cfg-gating each module to
// its arch keeps the selection sharp: exactly one profile compiles
// for any given target, and adding a profile only means adding one
// more `mod profile_X` + matching `pub use` arm above.

// ── aarch64 host (Pi 5, Linux host) ────────────────────────────────────────
//
// 8 GiB physical RAM, no allocator pressure. Sized for genuinely
// concurrent serving — slot tables match what the IP layer exposes,
// arenas absorb peak working sets without heroics.

#[cfg(target_arch = "aarch64")]
mod profile_host {
    pub mod kernel {
        /// Pool used by `loader::alloc_state` to back every loaded
        /// module's `module_state` and `module_arena`. Sized to
        /// hold a busy graph: 64 modules × ~100 KiB state plus
        /// peak heap usage from the http module at full
        /// `ARENA_WORKING_SET_CONNS` activity.
        pub const STATE_ARENA_SIZE: usize = 32 * 1024 * 1024;
        /// Per-channel buffer pool. 8 MiB lets graphs size
        /// individual channels at 16-64 KiB without exhausting
        /// the arena under sustained gigabit-class loads.
        pub const BUFFER_ARENA_SIZE: usize = 8 * 1024 * 1024;
        pub const MAX_MODULES: usize = 64;
        pub const MAX_MODULE_CONFIG_SIZE: usize = 32 * 1024;
        pub const CONFIG_ARENA_SIZE: usize = 64 * 1024;
        /// Capacity of the in-memory log ring (`kernel::log_ring`).
        /// Sized for moderate trace volume.
        pub const LOG_RING_CAPACITY: usize = 65536;
    }

    pub mod http {
        /// Maximum simultaneous in-flight HTTP connections per
        /// server module instance. Slot table size on
        /// `ServerState`.
        ///
        /// Capped at 256 because the net-protocol wire format
        /// carries `conn_id` as a single byte (see
        /// `modules/foundation/ip/mod.rs` accept/data/close paths
        /// and `modules/foundation/http/server.rs::find_slot_by_conn_id`).
        /// Allowing >256 here would let slots 256..N wrap modulo
        /// 256 on the wire and collide with earlier slots' ids,
        /// silently misrouting traffic. Lifting this requires
        /// widening `conn_id` to `u16` end-to-end across IP +
        /// HTTP + ws_stream — tracked as future work.
        pub const MAX_CONCURRENT_CONNS: usize = 256;
        /// Peak active connections the heap arena is sized to
        /// support simultaneously. With `MAX_CONCURRENT_CONNS`
        /// pinned at the u8-conn-id ceiling, this matches it
        /// 1:1 — the slot table and the arena are co-bounded by
        /// the wire format.
        pub const ARENA_WORKING_SET_CONNS: usize = 256;
        /// Per-conn inbound buffer holding the HTTP request line,
        /// headers, and small request bodies. Heap-allocated on
        /// accept, freed on close.
        pub const RECV_BUF_SIZE: usize = 8192;
        /// Per-conn outbound buffer. Sized to hold one full WS
        /// frame plus protocol framing.
        pub const SEND_BUF_SIZE: usize = 4100;
        pub const MAX_ROUTES: usize = 4;
        pub const MAX_PATH: usize = 32;
        pub const MAX_CONTENT_TYPE: usize = 32;
        pub const MAX_FS_PATH: usize = 64;
        pub const MAX_VARS: usize = 16;
        pub const MAX_VAR_VALUE: usize = 16;
        pub const MAX_CACHE: usize = 4;
        pub const DEFAULT_BODY_POOL_SIZE: usize = 48 * 1024;
    }

    pub mod ip {
        /// IP module's TCP-conn slot table size. Must be at least
        /// `http::MAX_CONCURRENT_CONNS` (compile-time invariant).
        /// Pinned at 256 alongside http until `conn_id` widens
        /// past u8 on the wire.
        pub const MAX_TCP_CONNS: usize = 256;
    }

    pub mod h2 {
        /// Per-conn HTTP/2 stream slots.
        pub const MAX_STREAMS: usize = 4;
    }
}

// ── wasm32 (browser, wasmtime, edge runtimes) ──────────────────────────────
//
// User-space-class memory but tighter budgets than Linux host —
// browser tabs are squeezed; edge runtimes have memory ceilings.

#[cfg(target_arch = "wasm32")]
mod profile_wasm {
    pub mod kernel {
        pub const STATE_ARENA_SIZE: usize = 8 * 1024 * 1024;
        pub const BUFFER_ARENA_SIZE: usize = 2 * 1024 * 1024;
        pub const MAX_MODULES: usize = 32;
        pub const MAX_MODULE_CONFIG_SIZE: usize = 16 * 1024;
        pub const CONFIG_ARENA_SIZE: usize = 32 * 1024;
        pub const LOG_RING_CAPACITY: usize = 16384;
    }

    pub mod http {
        pub const MAX_CONCURRENT_CONNS: usize = 256;
        pub const ARENA_WORKING_SET_CONNS: usize = 64;
        pub const RECV_BUF_SIZE: usize = 4096;
        pub const SEND_BUF_SIZE: usize = 4100;
        pub const MAX_ROUTES: usize = 4;
        pub const MAX_PATH: usize = 32;
        pub const MAX_CONTENT_TYPE: usize = 32;
        pub const MAX_FS_PATH: usize = 64;
        pub const MAX_VARS: usize = 16;
        pub const MAX_VAR_VALUE: usize = 16;
        pub const MAX_CACHE: usize = 4;
        pub const DEFAULT_BODY_POOL_SIZE: usize = 32 * 1024;
    }

    pub mod ip {
        pub const MAX_TCP_CONNS: usize = 256;
    }

    pub mod h2 {
        pub const MAX_STREAMS: usize = 4;
    }
}

// ── Embedded (rp2350, rp2040) ──────────────────────────────────────────────
//
// 256-512 KiB SRAM. Single-conn HTTP, tight everything.

#[cfg(not(any(target_arch = "aarch64", target_arch = "wasm32")))]
mod profile_embedded {
    pub mod kernel {
        pub const STATE_ARENA_SIZE: usize = 256 * 1024;
        pub const BUFFER_ARENA_SIZE: usize = 64 * 1024;
        pub const MAX_MODULES: usize = 32;
        pub const MAX_MODULE_CONFIG_SIZE: usize = 4 * 1024;
        pub const CONFIG_ARENA_SIZE: usize = 16 * 1024;
        pub const LOG_RING_CAPACITY: usize = 4096;
    }

    pub mod http {
        pub const MAX_CONCURRENT_CONNS: usize = 1;
        pub const ARENA_WORKING_SET_CONNS: usize = 1;
        pub const RECV_BUF_SIZE: usize = 2048;
        pub const SEND_BUF_SIZE: usize = 4100;
        pub const MAX_ROUTES: usize = 4;
        pub const MAX_PATH: usize = 32;
        pub const MAX_CONTENT_TYPE: usize = 32;
        pub const MAX_FS_PATH: usize = 64;
        pub const MAX_VARS: usize = 16;
        pub const MAX_VAR_VALUE: usize = 16;
        pub const MAX_CACHE: usize = 4;
        pub const DEFAULT_BODY_POOL_SIZE: usize = 48 * 1024;
    }

    pub mod ip {
        pub const MAX_TCP_CONNS: usize = 16;
    }

    pub mod h2 {
        pub const MAX_STREAMS: usize = 4;
    }
}

// ── Cross-subsystem invariants ─────────────────────────────────────────────
//
// Caught at compile time. Adding a new invariant here is the right
// place when a tunable picks up a dependency on another subsystem.

const _: () = assert!(
    http::MAX_CONCURRENT_CONNS <= ip::MAX_TCP_CONNS,
    "http::MAX_CONCURRENT_CONNS must not exceed ip::MAX_TCP_CONNS"
);

const _: () = assert!(
    http::ARENA_WORKING_SET_CONNS <= http::MAX_CONCURRENT_CONNS,
    "http::ARENA_WORKING_SET_CONNS cannot exceed slot table size"
);

const _: () = assert!(
    http::ARENA_WORKING_SET_CONNS >= 1,
    "http::ARENA_WORKING_SET_CONNS must allow at least one active conn"
);
