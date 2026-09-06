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

/// The `handler` byte of a compiled route record.
///
/// One definition, because two independent ones cannot be checked
/// against each other. The config compiler derives this byte from a
/// graph's route keys and bakes it into the artefact; the serving
/// module switches on it. Neither repo can see the other's literals,
/// and a disagreement is invisible in a config dump — the route
/// simply serves the wrong thing, with every field that a reader
/// would check to notice looking exactly right.
///
/// Ids are wire values baked into shipped artefacts: a number may be
/// added, and never reused for a different meaning.
pub mod route_handler {
    /// Fixed body served verbatim.
    pub const STATIC: u8 = 0;
    /// Fixed body with `{{ }}` substitution.
    pub const TEMPLATE: u8 = 1;
    /// File fetched through the file channel and staged in the body
    /// pool.
    pub const FILE: u8 = 2;
    /// Forward to `proxy_ip` / `proxy_port`.
    pub const PROXY: u8 = 3;
    /// Accept the RFC 6455 upgrade and echo frames.
    pub const WEBSOCKET: u8 = 4;
    /// WebSocket fan-out; a new subscriber is replayed the retained
    /// frame.
    pub const WS_FANOUT_RETAIN: u8 = 5;
    /// Fixed-index fetch piped straight to the socket, never staged —
    /// for payloads past the body-pool cap.
    pub const STREAM: u8 = 6;
    /// One file from the filesystem surface.
    pub const FS_FILE: u8 = 7;
    /// Directory listing from the filesystem surface.
    pub const FS_LIST: u8 = 8;
    /// WebSocket fan-out with no replay: a subscriber sees only what
    /// arrives after it joins.
    pub const WS_FANOUT: u8 = 9;
    /// gRPC unary. The route path is the SERVICE prefix, because a
    /// method path is `/<service>/<Method>` and a trailing `/`
    /// matches as a prefix.
    pub const GRPC: u8 = 10;
    /// Hand the request to a downstream graph node as an
    /// `HttpRequest` and await its `HttpResponse`.
    pub const APP: u8 = 11;
    /// WebSocket fan-out gated on external admission: the 101 is
    /// composed only once the admission answer accepts. Distinct
    /// from [`WS_FANOUT_RETAIN`] because replaying an earlier
    /// connection's frames to a not-yet-admitted subscriber is
    /// exactly what admission exists to prevent.
    pub const WS_FANOUT_ADMIT: u8 = 12;
    /// Highest id this vocabulary defines.
    pub const MAX_ID: u8 = WS_FANOUT_ADMIT;
}

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
        /// module's `module_state` and `module_arena`. It must hold every
        /// module of the busiest graph at once. The `ip` module's
        /// connection table dominates: a `TcpConn` is ~2.2 KiB (its bounded
        /// reorder buffer is the bulk of that) and `MAX_TCP_CONNS` is
        /// 65,536 here, so `ip` alone asks for ~137 MiB. Beside it sit a
        /// 64-module graph at ~100 KiB of state each plus the http module's
        /// peak heap at full `ARENA_WORKING_SET_CONNS` activity, a
        /// console-emulator core's ~39 MiB working set, and a media-app host
        /// graph that peaks past 64 MiB. 256 MiB leaves ~117 MiB beside the
        /// connection table, above that peak. Zero-initialised, so it costs
        /// kernel `.bss` rather than image size.
        pub const STATE_ARENA_SIZE: usize = 256 * 1024 * 1024;
        /// Per-channel buffer pool. 8 MiB lets graphs size
        /// individual channels at 16-64 KiB without exhausting
        /// the arena under sustained gigabit-class loads.
        pub const BUFFER_ARENA_SIZE: usize = 8 * 1024 * 1024;
        // Multi-workload: the system substrate plus several workload subgraphs
        // co-resident on aarch64 (bcm2712 / linux). Every module index stays
        // within the scheduler's u8 index domain (`exec_order: [u8; _]`,
        // `module_idx as u8`), which is what bounds this at 256 — past that the
        // ids widen to u16. The `ModuleMask` bitmaps scale to match
        // (MODULE_MASK_WORDS == 3 here). Edge capacity is MAX_GRAPH_EDGES.
        //
        // 128 -> 192: a control plane whose controllers are PARAMS is counted
        // in decisions and connectors rather than in modules. nanocloud's
        // all-in-one graph is 100 nodes of control plane plus a 35-node node
        // plane, and the two cannot be split across processes — the linux store
        // is deliberately single-writer with no `flock`, so one runtime owns
        // the WAL. This is per-target (wasm32 48, Cortex-M 32 below), so the
        // scheduler's static tables grow on aarch64 only.
        pub const MAX_MODULES: usize = 192;
        /// Loader sanity ceiling for a single module's code segment.
        /// 1 MiB fits media modules (the unified codec's decoder plus
        /// its CAVLC/clip tables runs ~450 KiB) and protocol modules
        /// that bundle firmware blobs.
        pub const MAX_MODULE_CODE_SIZE: usize = 1024 * 1024;
        // 256 KiB so the synth host can carry the inlined wasm browser shell
        // (runtime.html ~83 KiB + host_shims.js ~56 KiB) as http `body:`
        // routes. Smaller values silently truncate the http module's params
        // blob (the kernel-side ParamBuffer copies up to this many bytes before
        // passing to module_new). Aligned with `MAX_CONFIG_SIZE`,
        // `MAX_MODULE_PARAMS_SIZE` (tools), and the http module section cap —
        // keep this whole set in lockstep.
        pub const MAX_MODULE_CONFIG_SIZE: usize = 256 * 1024;
        // 256 KiB so split scenarios where both halves' http modules
        // inline the canonical wasm shell as body routes
        // (~95 KiB per http module) leave enough headroom for the
        // other modules' params (codec, bank, ws_stream, ...).
        pub const CONFIG_ARENA_SIZE: usize = 256 * 1024;
        /// Capacity of the in-memory log ring (`kernel::sys::log_ring`).
        /// Sized for moderate trace volume.
        pub const LOG_RING_CAPACITY: usize = 65536;
        /// Kernel elastic region backing Tier B chunk grants
        /// (`resource::ELASTIC_ALLOC`).
        /// 8 MiB: room for TLS-session growth to its compiled maximum
        /// (~832 KiB) plus several workloads' worth of headroom, and
        /// deliberately oversubscribable — Σ of pool maxima MAY exceed
        /// it; contention is a counted denial, mins are load-time.
        pub const ELASTIC_REGION_SIZE: usize = 8 * 1024 * 1024;
        /// Grant granularity: chunks are rounded up to this quantum
        /// (the 64 KiB platform quantum, §3.1).
        pub const ELASTIC_QUANTUM: usize = 64 * 1024;
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
        /// Per-conn outbound buffer. Sized to hold one full WS wire
        /// frame for a ws_stream-produced envelope: ws_stream caps
        /// payloads at 4096 bytes/emit (see `modules/foundation/ws_stream`),
        /// so a 4096-byte payload + 4-byte WS server-to-client header
        /// fits exactly in 4100. Anything larger than this on `ws_in`
        /// — only reachable when something bypasses ws_stream — falls
        /// through to the RFC 6455 §5.4 fragmentation path in
        /// `ws_drain_fanout_input`.
        pub const SEND_BUF_SIZE: usize = 4100;
        // The http module's TLV parameter table in
        // `modules/foundation/http/mod.rs` declares 10 tags per route
        // (path, body, handler, proxy_ip, proxy_port, source,
        // content_type, fs_path, fs_list, fs_filter) at tag offsets
        // 10 + 10*i .. 10 + 10*(i+1). Bumping this ceiling REQUIRES
        // adding matching `define_params!` entries for the new
        // routes; tools/tests/http_route_tlv_coverage.rs locks the
        // invariant. The host profile is currently sized for 8
        // routes (tags 10..89) — enough for the scenario synth host
        // (runtime.html, fluxor.wasm, host_shims.js, /scenario.json,
        // /api/list, plus 3 spare for user/scenario route merges).
        pub const MAX_ROUTES: usize = 8;
        // Dynamic-route arena. A DEDICATED arena, deliberately separate
        // from the TLV-locked static `MAX_ROUTES` budget above: dyn
        // routes are programmed at runtime from `/dataplane/edge/` via
        // the table_consumer helper, carry a host axis + weighted backend
        // set, and are NOT wired through `define_params!` — so this
        // ceiling is free to size for route×backend fanout without
        // touching the TLV coverage lock. Host default 64; embedded/wasm
        // keep 8 (see the other profiles).
        pub const MAX_DYN_ROUTES: usize = 64;
        // Backends carried per dynamic route (the `be=` set). One PUT
        // replaces the whole set atomically (§3.1); the compiler
        // truncates oversized sets by weight order, and the edge counts
        // the overflow into `http.routes.dropped`.
        pub const MAX_ROUTE_BACKENDS: usize = 8;
        // Request-path budget. Serving a real library (`list:` over
        // `/tmp/music`) means request URLs like
        // `/music/Elbow/Asleep In the Back/01 Any Day Now.m4a`, and
        // percent-encoding (`%20` per space) inflates them further; 200 holds
        // them without a clipped path → 404. (`req_path_len` is a u8, so this
        // stays ≤ 255.)
        pub const MAX_PATH: usize = 200;
        pub const MAX_CONTENT_TYPE: usize = 32;
        /// Per-route absolute filesystem path budget on host targets. 256 fits
        /// realistic absolute paths like
        /// `/home/<user>/Development/<project>/examples/.../viewer.html` that
        /// the scenario synthesiser emits; a shorter budget truncates the path,
        /// so `linux_fs_dispatch` OPENs the wrong filename (creating an empty
        /// file via the `O_CREAT` fallback) and FS_STAT returns `st_size = 0` —
        /// surfacing as 200-OK-with-0-byte-body responses for `fs_path:`
        /// routes. Embedded/wasm profiles keep 64 — their fs_path values are
        /// short on-flash paths like `/web/INDEX.HTM`.
        pub const MAX_FS_PATH: usize = 256;
        pub const MAX_VARS: usize = 16;
        pub const MAX_VAR_VALUE: usize = 16;
        pub const MAX_CACHE: usize = 4;
        // Host profile (aarch64: linux orchestrator, pi5) serves
        // synthesised wasm-scenario hosts that inline the canonical browser
        // shell as `body:` routes — runtime.html (~83 KiB after scenario
        // substitution) + host_shims.js (~56 KiB) + scenario.json. 256 KiB
        // holds them without overflowing the pool (an overflow truncates bodies
        // into corrupt JS / empty scenario.json); the arena reserves 2× this
        // and these targets have GiBs of RAM, so it's a sanity bound, not a
        // memory constraint. profile_wasm / profile_embedded keep their small
        // pools.
        pub const DEFAULT_BODY_POOL_SIZE: usize = 256 * 1024;
    }

    pub mod ip {
        /// IP module's TCP-conn slot table size: the ceiling on locally
        /// terminated TCP connections. The net-proto `conn_id` is u16, so
        /// 65,536 slots is exactly the id space. A connection record is
        /// ~2.2 KiB — most of it the bounded reorder buffer — so the table
        /// is ~137 MiB and is what `kernel::STATE_ARENA_SIZE` is sized
        /// around. Lookup is by hash index (`ip/index.rs`), never a scan,
        /// and the timer sweep is sliced across the 50 ms window, so the
        /// size costs nothing per packet or per step.
        /// At least `http::MAX_CONCURRENT_CONNS` (compile-time invariant).
        pub const MAX_TCP_CONNS: usize = 65536;
        /// Datagram endpoints carry a u8 `ep_id` on the wire, so they are
        /// allocated only from the first `MAX_DG_ENDPOINTS` connection
        /// slots — the id space binds the endpoint count, not the table.
        pub const MAX_DG_ENDPOINTS: usize = 256;
        /// Multi-homing address-table size. Slot 0 is the primary
        /// (DHCP-managed); slots 1.. are secondaries added at runtime via
        /// the ip module's `addr_ctl` port. Demuxed through a hash index
        /// on the RX path, so the size costs nothing per frame.
        pub const MAX_LOCAL_ADDRS: usize = 4096;
        /// Packets the pre-transport decision seam may hold awaiting a
        /// director's disposition. One full frame each, so this is the
        /// seam's whole footprint (~48 KiB here); a packet arriving with
        /// every slot taken is refused and counted, never displaces one.
        pub const MAX_PACKET_HOLD: usize = 32;
    }

    pub mod tls {
        /// TLS session table. The ceiling on concurrent TLS connections — and
        /// so on HTTPS concurrency, which `http::MAX_CONCURRENT_CONNS` above
        /// does NOT bound on its own: an accept the tls module cannot seat is
        /// closed before http ever sees it. Published here so a consumer reads
        /// the envelope it actually has rather than inferring one from the
        /// HTTP number. Sixty-four sessions is ~830 KiB of elastic pool on
        /// aarch64; the module grows it in 8-session chunks.
        pub const MAX_SESSIONS: usize = 64;
    }

    pub mod quic {
        /// QUIC connection table. A connection carries ~58 KiB of state, so
        /// the table is ~464 KiB — the dominant term in this module's
        /// footprint, and why the ceiling is eight rather than a round
        /// number. One past it is refused with a stateless
        /// CONNECTION_REFUSED Initial.
        pub const MAX_CONNS: usize = 8;
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
        // Sized to hold a console-emulator graph at a 32 MiB cartridge
        // ceiling: the core streams the ROM straight into its emulated bus
        // (~32 MiB ROM + machine RAM, no second full-ROM copy) and a file
        // loader stages one framed copy (~32 MiB) to emit the load command —
        // ~72 MiB of live state at peak, plus the small video / audio /
        // mapper modules. 96 MiB covers it with margin; 64 MiB held only
        // ≤12 MB payloads. Browser tabs have ample memory headroom; the
        // arena is paged in lazily by `memory.grow`.
        pub const STATE_ARENA_SIZE: usize = 96 * 1024 * 1024;
        /// Loader sanity ceiling for a single module's code segment
        /// (see the host profile's rationale).
        pub const MAX_MODULE_CODE_SIZE: usize = 1024 * 1024;
        // Holds ALL channel ring buffers for the live graph. GPU-offload graphs
        // wire multi-MiB frame channels (a whole serialized frame — up to
        // ~1.57 MiB dense — must cross child->kernel in one ring fill)
        // PLUS the small audio/input/command channels (~24 KiB). At 2 MiB the arena
        // couldn't fit the 2 MiB channel alongside the others ("[buf] arena full
        // need=2097152 used=24576") -> channel open failed -> the emulator would not
        // start. Then 4 MiB for a 2 MiB channel + rest. Now 8 MiB: chunk's GPU
        // command ring wants a 4 MiB channel (a chunk mesh + the far-terrain LOD ring
        // in one step; channel sizes are powers of two, so 4 MiB is the next step
        // above 2 MiB), which alone fills a 4 MiB arena — 8 MiB holds it + the rest.
        // Lazily paged by memory.grow, so it costs nothing until used.
        pub const BUFFER_ARENA_SIZE: usize = 8 * 1024 * 1024;
        // 48: a multi-emulator browser graph (music + Game Boy +
        // Spectrum chains) declares ~22 modules and the kernel inserts
        // an internal tee/merge per fan — 32 left "No room for
        // internal module" at prepare_graph.
        pub const MAX_MODULES: usize = 48;
        pub const MAX_MODULE_CONFIG_SIZE: usize = 16 * 1024;
        pub const CONFIG_ARENA_SIZE: usize = 32 * 1024;
        pub const LOG_RING_CAPACITY: usize = 16384;
        /// Tier B elastic region (see the host profile). Browser tabs
        /// page lazily, but the region is still budgeted small.
        pub const ELASTIC_REGION_SIZE: usize = 2 * 1024 * 1024;
        /// Grant granularity: the wasm page.
        pub const ELASTIC_QUANTUM: usize = 64 * 1024;
    }

    pub mod http {
        pub const MAX_CONCURRENT_CONNS: usize = 256;
        pub const ARENA_WORKING_SET_CONNS: usize = 64;
        pub const RECV_BUF_SIZE: usize = 4096;
        pub const SEND_BUF_SIZE: usize = 4100;
        pub const MAX_ROUTES: usize = 4;
        // Dynamic-route arena; see profile_host.
        pub const MAX_DYN_ROUTES: usize = 8;
        pub const MAX_ROUTE_BACKENDS: usize = 4;
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
        /// Datagram endpoints; see profile_host.
        pub const MAX_DG_ENDPOINTS: usize = 256;
        /// Multi-homing address-table size.
        pub const MAX_LOCAL_ADDRS: usize = 8;
        /// Pre-transport decision hold slots; see profile_host.
        pub const MAX_PACKET_HOLD: usize = 8;
    }

    pub mod tls {
        /// TLS session table. The ceiling on concurrent TLS connections — and
        /// so on HTTPS concurrency, which `http::MAX_CONCURRENT_CONNS` above
        /// does NOT bound on its own: an accept the tls module cannot seat is
        /// closed before http ever sees it. Published here so a consumer reads
        /// the envelope it actually has rather than inferring one from the
        /// HTTP number. Sixty-four sessions is ~830 KiB of elastic pool on
        /// aarch64; the module grows it in 8-session chunks.
        pub const MAX_SESSIONS: usize = 64;
    }

    pub mod quic {
        /// QUIC connection table. A connection carries ~58 KiB of state, so
        /// the table is ~464 KiB — the dominant term in this module's
        /// footprint, and why the ceiling is eight rather than a round
        /// number. One past it is refused with a stateless
        /// CONNECTION_REFUSED Initial.
        pub const MAX_CONNS: usize = 8;
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
        /// Loader sanity ceiling for a single module's code segment.
        /// 384 KiB — an MCU profile can't host MiB-class media
        /// modules anyway.
        pub const MAX_MODULE_CODE_SIZE: usize = 384 * 1024;
        pub const BUFFER_ARENA_SIZE: usize = 64 * 1024;
        pub const MAX_MODULES: usize = 32;
        pub const MAX_MODULE_CONFIG_SIZE: usize = 4 * 1024;
        pub const CONFIG_ARENA_SIZE: usize = 16 * 1024;
        pub const LOG_RING_CAPACITY: usize = 4096;
        /// No Tier B on MCU-class targets: elasticity compiles out
        /// — `ELASTIC_ALLOC` denies.
        pub const ELASTIC_REGION_SIZE: usize = 0;
        pub const ELASTIC_QUANTUM: usize = 1024;
    }

    pub mod http {
        /// Four, not one: a browser opens several connections to a page in
        /// parallel, and a one-slot server closes all but the first, which
        /// presents as a page that half-loads. Four slots cost
        /// 4 × (2048 + 4100) ≈ 24 KiB of the 256 KiB arena, sized against the
        /// 4-session TLS table and the 16-slot TCP table in this profile.
        pub const MAX_CONCURRENT_CONNS: usize = 4;
        pub const ARENA_WORKING_SET_CONNS: usize = 4;
        pub const RECV_BUF_SIZE: usize = 2048;
        pub const SEND_BUF_SIZE: usize = 4100;
        pub const MAX_ROUTES: usize = 4;
        // Dynamic-route arena; see profile_host. Embedded default 8 —
        // small, and the feature is off (empty `routes_prefix`) on
        // any edge that doesn't run the compiler.
        pub const MAX_DYN_ROUTES: usize = 8;
        pub const MAX_ROUTE_BACKENDS: usize = 4;
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
        /// Datagram endpoints; see profile_host.
        pub const MAX_DG_ENDPOINTS: usize = 16;
        /// Multi-homing address-table size.
        pub const MAX_LOCAL_ADDRS: usize = 8;
        /// Pre-transport decision hold slots; see profile_host.
        pub const MAX_PACKET_HOLD: usize = 4;
    }

    pub mod tls {
        /// Whole pool inline (no elastic region on MCU-class targets).
        pub const MAX_SESSIONS: usize = 4;
    }

    pub mod quic {
        /// The quic module does not build for this profile; the value is
        /// published so a consumer reading the envelope sees a number rather
        /// than an absence.
        pub const MAX_CONNS: usize = 2;
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
    tls::MAX_SESSIONS <= ip::MAX_TCP_CONNS,
    "tls::MAX_SESSIONS cannot exceed ip::MAX_TCP_CONNS — a TLS session needs a TCP connection under it"
);
const _: () = assert!(
    http::MAX_CONCURRENT_CONNS <= ip::MAX_TCP_CONNS,
    "http::MAX_CONCURRENT_CONNS must not exceed ip::MAX_TCP_CONNS"
);
const _: () = assert!(
    ip::MAX_DG_ENDPOINTS <= ip::MAX_TCP_CONNS && ip::MAX_DG_ENDPOINTS <= 256,
    "ip::MAX_DG_ENDPOINTS is bounded by the connection table and by the u8 ep_id"
);
const _: () = assert!(
    ip::MAX_TCP_CONNS <= 65536 && ip::MAX_TCP_CONNS.is_power_of_two(),
    "ip::MAX_TCP_CONNS is bounded by the u16 conn_id and indexed by a power-of-two table"
);
const _: () = assert!(
    ip::MAX_LOCAL_ADDRS <= 4096 && ip::MAX_LOCAL_ADDRS.is_power_of_two(),
    "ip::MAX_LOCAL_ADDRS is bounded by the u16 slot (0xFFFF = wildcard) and indexed by a power-of-two table"
);

const _: () = assert!(
    http::ARENA_WORKING_SET_CONNS <= http::MAX_CONCURRENT_CONNS,
    "http::ARENA_WORKING_SET_CONNS cannot exceed slot table size"
);

const _: () = assert!(
    http::ARENA_WORKING_SET_CONNS >= 1,
    "http::ARENA_WORKING_SET_CONNS must allow at least one active conn"
);
