//! Shared ABI definitions for core and PIC modules.
//!
//! ## Layering
//!
//! The ABI is organised as four explicit layers; pick the right one up
//! front when adding a new API.
//!
//! | Layer | Files | What it contains |
//! |-------|-------|------------------|
//! | `kernel_abi` | `kernel_abi.rs` | Core primitives (channel, timer, buffer, event, log, random, arena) |
//! | `contracts` | `contracts/{hal,net,storage,key_vault}.rs` | Portable service contracts |
//! | `internal` | `internal/*.rs` | Kernel-private orchestration, monitor, bridge, flash |
//! | `platform` | `platform/{rp,bcm2712}/*.rs` | Chip-specific raw register bridges |
//!
//! The guardrails are described in `docs/architecture/abi_layers.md`.
//!
//! ## File layout
//!
//! This crate is the ABI and nothing else: `ABI_SURFACE_DIGEST` hashes its
//! source, `contracts/` (the host vocabulary) and the registry. Library code
//! modules link lives in `fluxor-sdk` and the module runtime in `fluxor-rt`;
//! neither is hashed. Every layer file is a module of its own; this file
//! composes the namespace and exposes a handful of top-level conveniences
//! (the syscall table and a few primitive constants).
//!
//! Call sites always use fully-qualified layer paths so the layer
//! boundary is visible at every use:
//!
//! - `abi::contracts::hal::gpio::CLAIM`
//! - `abi::platform::rp::pio::CMD_TRANSFER`
//! - `abi::contracts::net::net_proto::CMD_BIND`
//! - `abi::platform::rp::flash_layout::XIP_BASE`
//! - `abi::internal::reconfigure::CALL_DRAIN`
//! - `abi::platform::bcm2712::nic_ring::NIC_BAR_MAP`

#![no_std]
#![allow(
    unsafe_code,
    reason = "the syscall table is a table of `unsafe extern \"C\"` entry points taking raw pointers, and the wire views read records in place"
)]

// ─── Layered structure ───────────────────────────────────────────────

/// Wire-format constants — ABI version byte, channel-hint stride,
/// `fnv1a32` name hash. Imported by every consumer that needs to
/// agree on these bytes.
pub mod wire;

/// Capacity / sizing tunables — one coherent envelope per board
/// profile. Picked up by both the kernel and PIC modules so a
/// single edit moves the whole system in lockstep. See
/// `crates/fluxor-abi/src/config.rs` for the full layout and
/// cross-subsystem invariants.
pub mod config;

/// Every ABI number, generated from `abi/registry.toml` by `fluxor
/// abi-regen`: contract ids, opcodes, grants, errno, poll bits and the
/// handle word, with the lookups the kernel and tools derive from them.
pub mod registry;

pub mod kernel_abi;

/// A module's heap statistics, by offset and exact length.
pub mod heap_stats;

/// Canonical ABI wire-surface encoding (`abi_surface.rs`): the fixed
/// (name, value) walk over every numeric allocation above whose sha256
/// is the ABI-surface digest. Generations and slot images record the
/// digest they were built against; a selector accepts them only on
/// equality with the running kernel's own digest.
pub mod abi_surface;

pub mod contracts {
    pub mod hal {
        pub mod adc;
        pub mod gpio;
        pub mod i2c;
        /// Device registers, DMA memory and cache maintenance on a
        /// bare-metal aarch64 machine.
        pub mod metal_device;
        /// PCIe device capability — generic bus vocabulary (device handles,
        /// config space, BARs, interrupts, device info). Semantics are
        /// implementation-independent, so it lives in the portable HAL;
        /// root-complex mechanics stay under `platform` (D-HW-TAXONOMY).
        pub mod pcie_device;
        pub mod pwm;
        pub mod spi;
        pub mod uart;
    }
    pub mod net {
        pub mod datagram;
        /// DNS message wire shared by the resolver and `ip`'s name cache.
        pub mod dns_wire;
        pub mod identity;
        pub mod mux;
        pub mod net_proto;
        pub mod packet;
        /// What a TLS handshake established about the peer.
        pub mod peer_identity;
        /// Packet policy and service NAT, enforced by the platform: tables of
        /// neutral rules a provider realizes with the host's packet filter, a
        /// native filter, or nothing (and says so in its capabilities).
        pub mod policy;
        /// How the node's workloads reach each other and the outside world:
        /// segments, peer routes and held addresses, realized by the
        /// platform or a module provider and reported per entry.
        pub mod route;
        pub mod session_ctrl;
        /// The continuity cursors between a record layer and its consumer.
        pub mod stream_cursor;
        /// The retransmission hand-off between a transport and a consumer
        /// that keeps its own copy of what it sends.
        pub mod stream_retx;
        /// A stream's trace context, handed up its stages.
        pub mod stream_trace;
        /// The single-flow continuity surface's frames, magics and versions.
        pub mod transport_continuity;
        /// The records that drive a WebSocket connector from outside it:
        /// which resource to open on which link, and what became of it.
        pub mod ws_control;
        pub mod ws_frame;
    }
    /// The records a controller and a target's node agent exchange: desired
    /// workload package, descriptor revision, idempotency identity, observed activation
    /// and fenced status.
    pub mod agent;
    /// The `AudioSample` stream's records: PCM frames and the in-band format
    /// record that states their rate.
    pub mod audio_sample;
    /// The exchange records every request and its answer travel in, between
    /// any requester and any provider, and the collector a provider uses to
    /// take requests whole.
    pub mod exchange;
    /// HTTP as a binding of the exchange records: the method table, the
    /// status-to-outcome map, and header lines as meta.
    pub mod exchange_http;
    /// The GPU contract's wire: the pack envelope, the binding table, the
    /// device's capability words and the command records. The device model
    /// that runs it (`fluxor_sdk::gpu`) is library code, not ABI.
    pub mod gpu;
    /// Resource-ledger pool registry.
    pub mod resource;
    /// Generic stream-clock capability (audio/media clock query).
    pub mod stream_clock;
    /// A consumer restarts the stream its upstream producer writes at a
    /// position it names (an edge contract).
    pub mod stream_select;
    /// Observability telemetry envelope (metric / span signals).
    pub mod telemetry;
    /// The platform's own verdict on a certificate chain.
    pub mod trust;
    pub mod storage {
        /// Raw logical-block I/O over a `blocks` channel.
        pub mod block;
        /// Custody of a keyed volume's key: sealing, custodians, shares.
        pub mod custody;
        pub mod fs;
        pub mod graph_slot;
        /// Leased mesh Handle specialised for storage surfaces.
        pub mod handle;
        /// Directory-like name-keyed surface
        /// (see `storage_capability_surface.md`).
        pub mod namespace;
        /// Whole-blob byte-addressed surface.
        pub mod object;
        pub mod runtime_params;
    }
    pub mod key_vault;
    /// The mesh substrate's authority: capability tokens, delegation chains,
    /// local verification, and their presentation on a session.
    pub mod mesh {
        pub mod capability;
        /// A `remote_channel`'s session opening and ending.
        pub mod remote_session;
    }
    /// Encoded media stream — the `AudioEncoded` / `VideoEncoded` record
    /// stream: a self-describing `STREAM`, access-unit `UNIT` fragments, and
    /// `END`.
    pub mod encoded;
    /// Glyph pack — a font face baked by `font_bake`: metrics, character
    /// map, advances, OpenType layout tables, and strikes in a
    /// `GLYPH_FORMATS` variant. Read in place.
    pub mod glyph_pack;
    /// Decode an encoded image held in a store to raw pixels at a named
    /// size: the job's records and output formats.
    pub mod image_decode;
    /// Block-per-acquisition surface — the `MeasurementStream` content type's
    /// record. `sensor` carries one reading; this carries a block of samples
    /// whose individual readings are not separately meaningful.
    pub mod measurement;
    /// Measured-quantity surface — the `SensorSample` content type's record.
    pub mod sensor;
    /// Platform-neutral isolated-workload surface (contract class `0x1A`).
    pub mod workload;
    pub mod input {
        pub mod action;
        pub mod button;
        pub mod gamepad;
        pub mod key;
        pub mod midi;
        pub mod pointer;
        pub mod surface_traits;
    }
}

/// Per-op durability / ordering advertisement — the `Fence` wire value-type
/// every storage surface returns. A cross-cutting durability primitive rather
/// than a domain contract, so it sits at the `abi` root (not under `contracts`);
/// file at `crates/fluxor-abi/src/fence.rs`.
pub mod fence;

pub mod internal {
    pub mod bridge;
    pub mod diag;
    pub mod flash;
    pub mod monitor;
    pub mod reconfigure;
    pub mod vault_store;
}

pub mod platform {
    pub mod rp {
        pub mod adc_raw;
        pub mod dma_raw;
        pub mod flash_layout;
        pub mod i2c_raw;
        /// PIO capability contract — RP silicon only, so it lives here rather
        /// than the portable HAL (docs/architecture/hal_architecture.md
        /// D-HW-TAXONOMY). Numeric contract id unchanged (wire is stable).
        pub mod pio;
        pub mod pio_raw;
        pub mod pwm_raw;
        pub mod raw_claim;
        pub mod spi9_raw;
        pub mod spi_raw;
        pub mod uart_raw;
    }
    /// Linux host-platform mechanics (host-process ops; see the file header).
    pub mod linux {
        pub mod host_mount;
        pub mod host_process;
    }
    pub mod bcm2712 {
        pub mod nic_ring;
    }
    /// The native modules' name hashes, params tags and port bindings,
    /// generated from their manifests (`fluxor abi-regen`).
    pub mod native;
}

// ─── Top-level conveniences ──────────────────────────────────────────
//
// The handful of symbols that virtually every module references — the
// syscall table, the version byte, the standard channel buffer size,
// the ChannelAddr struct, and the poll / errno submodules — are
// re-exported at the top of `abi` for ergonomics. Everything else
// lives in its layer file and is accessed by its full path.

pub use self::kernel_abi::{
    errno, poll, ChannelAddr, StreamTime, SyscallTable, ABI_VERSION, CHANNEL_BUFFER_SIZE,
};
