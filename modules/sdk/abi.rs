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
//! | `contracts` | `contracts/{hal,net,storage,key_vault}.rs` | Portable domain contracts |
//! | `internal` | `internal/*.rs` | Kernel-private orchestration, monitor, bridge, flash |
//! | `platform` | `platform/{rp,bcm2712}/*.rs` | Chip-specific raw register bridges |
//!
//! The guardrails are described in `docs/architecture/abi_layers.md`.
//!
//! ## File layout
//!
//! This file is the *assembler*. Each layer file is `include!`'d into
//! a nested module below. The content lives in the layer file; this
//! file exists to compose the namespace and to expose a handful of
//! top-level conveniences (the syscall table and a few primitive
//! constants).
//!
//! Call sites always use fully-qualified layer paths so the layer
//! boundary is visible at every use:
//!
//! - `abi::contracts::hal::gpio::CLAIM`
//! - `abi::platform::rp::pio::CMD_TRANSFER`
//! - `abi::contracts::net::net_proto::CMD_BIND`
//! - `abi::platform::rp::flash_layout::GRAPH_SLOT_SIZE`
//! - `abi::internal::reconfigure::CALL_DRAIN`
//! - `abi::platform::bcm2712::nic_ring::NIC_BAR_MAP`

// ─── Layered structure ───────────────────────────────────────────────

/// Wire-format constants — ABI version byte, channel-hint stride,
/// `fnv1a32` name hash. Imported by every consumer that needs to
/// agree on these bytes.
pub mod wire {
    include!("wire/wire.rs");
}

/// Capacity / sizing tunables — one coherent envelope per board
/// profile. Picked up by both the kernel and PIC modules so a
/// single edit moves the whole system in lockstep. See
/// `modules/sdk/config.rs` for the full layout and
/// cross-subsystem invariants.
pub mod config {
    include!("abi/config.rs");
}

pub mod kernel_abi {
    include!("abi/kernel_abi.rs");
}

/// Canonical ABI wire-surface encoding (`abi_surface.rs`): the fixed
/// (name, value) walk over every numeric allocation above whose sha256
/// is the ABI-surface digest. Generations and slot images record the
/// digest they were built against; a selector accepts them only on
/// equality with the running kernel's own digest.
pub mod abi_surface {
    include!("abi_surface.rs");
}

pub mod contracts {
    pub mod hal {
        pub mod gpio {
            include!("contracts/hal/gpio.rs");
        }
        pub mod spi {
            include!("contracts/hal/spi.rs");
        }
        pub mod i2c {
            include!("contracts/hal/i2c.rs");
        }
        pub mod uart {
            include!("contracts/hal/uart.rs");
        }
        pub mod adc {
            include!("contracts/hal/adc.rs");
        }
        pub mod pwm {
            include!("contracts/hal/pwm.rs");
        }
        /// PCIe device capability — generic bus vocabulary (device handles,
        /// config space, BARs, interrupts, device info). Semantics are
        /// implementation-independent, so it lives in the portable HAL;
        /// root-complex mechanics stay under `platform` (D-HW-TAXONOMY).
        pub mod pcie_device {
            include!("contracts/hal/pcie.rs");
        }
    }
    pub mod net {
        pub mod net_proto {
            include!("contracts/net/net_proto.rs");
        }
        pub mod datagram {
            include!("contracts/net/datagram.rs");
        }
        pub mod packet {
            include!("contracts/net/packet.rs");
        }
        pub mod mux {
            include!("contracts/net/mux.rs");
        }
        pub mod session_ctrl {
            include!("contracts/net/session_ctrl.rs");
        }
        pub mod identity {
            include!("contracts/net/identity.rs");
        }
        /// What a TLS handshake established about the peer.
        pub mod peer_identity {
            include!("contracts/net/peer_identity.rs");
        }
        pub mod ws_frame {
            include!("contracts/net/ws_frame.rs");
        }
    }
    /// Observability telemetry envelope (metric / span signals).
    pub mod telemetry {
        include!("contracts/telemetry.rs");
    }
    /// Resource-ledger pool registry.
    pub mod resource {
        include!("contracts/resource.rs");
    }
    /// The generic GPU contract: the record envelope, the program-pack
    /// envelope, the portable device model every backend shares, the provider
    /// pump, the producer-side client and the deterministic null/replay
    /// backend.
    ///
    /// One namespace rather than six, because they are one contract — the pack
    /// validator reads the envelope's target and arithmetic facts, the device
    /// model reads the pack's bindings, and the pump drives the device. Mounted
    /// flat exactly as a PIC provider mounts them, so the kernel side and a
    /// module see the same items.
    #[allow(
        dead_code,
        reason = "one contract shared by producers, providers and tooling; \
                  no single consumer uses every constant"
    )]
    pub mod gpu {
        include!("crypto/sha256.rs");
        include!("wire/gpu_wire.rs");
        include!("cores/gpu_pack.rs");
        include!("cores/gpu_device.rs");
        include!("cores/gpu_pump.rs");
        include!("cores/gpu_client.rs");
        include!("cores/gpu_replay.rs");
    }
    /// Generic stream-clock capability (audio/media clock query).
    pub mod stream_clock {
        include!("contracts/stream_clock.rs");
    }
    /// Ordered-ack record exchange (`stream.ordered_ack`): publish frames in,
    /// durable acks out, and an optional reply carrying data back on the same
    /// correlation.
    pub mod exchange {
        include!("contracts/exchange.rs");
    }
    pub mod storage {
        pub mod graph_slot {
            include!("contracts/storage/graph_slot.rs");
        }
        pub mod runtime_params {
            include!("contracts/storage/runtime_params.rs");
        }
        pub mod paged_arena {
            include!("contracts/storage/paged_arena.rs");
        }
        pub mod fs {
            include!("contracts/storage/fs.rs");
        }
        /// Directory-like name-keyed surface
        /// (see `storage_capability_surface.md`).
        pub mod namespace {
            include!("contracts/storage/namespace.rs");
        }
        /// Whole-blob byte-addressed surface.
        pub mod object {
            include!("contracts/storage/object.rs");
        }
        /// Leased mesh Handle specialised for storage surfaces.
        pub mod handle {
            include!("contracts/storage/handle.rs");
        }
    }
    pub mod key_vault {
        include!("contracts/key_vault.rs");
    }
    /// Platform-neutral isolated-workload surface (contract class `0x1A`).
    pub mod workload {
        include!("contracts/workload.rs");
    }
    pub mod input {
        pub mod gamepad {
            include!("contracts/input/gamepad.rs");
        }
        pub mod pointer {
            include!("contracts/input/pointer.rs");
        }
        pub mod key {
            include!("contracts/input/key.rs");
        }
        pub mod midi {
            include!("contracts/input/midi.rs");
        }
        pub mod action {
            include!("contracts/input/action.rs");
        }
        pub mod surface_traits {
            include!("contracts/input/surface_traits.rs");
        }
    }
}

/// Per-op durability / ordering advertisement — the `Fence` wire value-type
/// every storage surface returns. A cross-cutting durability primitive rather
/// than a domain contract, so it sits at the `abi` root (not under `contracts`);
/// file at `modules/sdk/fence.rs`.
pub mod fence {
    include!("fence.rs");
}

pub mod internal {
    pub mod provider_registry {
        include!("internal/provider_registry.rs");
    }
    pub mod reconfigure {
        include!("internal/reconfigure.rs");
    }
    pub mod monitor {
        include!("internal/monitor.rs");
    }
    pub mod bridge {
        include!("internal/bridge.rs");
    }
    pub mod diag {
        include!("internal/diag.rs");
    }
    pub mod flash {
        include!("internal/flash.rs");
    }
}

pub mod platform {
    pub mod rp {
        pub mod pwm_raw {
            include!("platform/rp/pwm_raw.rs");
        }
        /// PIO capability contract — RP silicon only, so it lives here rather
        /// than the portable HAL (docs/architecture/hal_architecture.md
        /// D-HW-TAXONOMY). Numeric contract id unchanged (wire is stable).
        pub mod pio {
            include!("platform/rp/pio.rs");
        }
        pub mod pio_raw {
            include!("platform/rp/pio_raw.rs");
        }
        pub mod dma_raw {
            include!("platform/rp/dma_raw.rs");
        }
        pub mod spi9_raw {
            include!("platform/rp/spi9_raw.rs");
        }
        pub mod spi_raw {
            include!("platform/rp/spi_raw.rs");
        }
        pub mod i2c_raw {
            include!("platform/rp/i2c_raw.rs");
        }
        pub mod uart_raw {
            include!("platform/rp/uart_raw.rs");
        }
        pub mod adc_raw {
            include!("platform/rp/adc_raw.rs");
        }
        pub mod flash_layout {
            include!("platform/rp/flash_layout.rs");
        }
    }
    /// Linux host-platform mechanics (host-process ops; see the file header).
    pub mod linux {
        pub mod host_process {
            include!("platform/linux/host_process.rs");
        }
    }
    pub mod bcm2712 {
        pub mod mmio_dma {
            include!("platform/bcm2712/mmio_dma.rs");
        }
        pub mod pcie_config {
            include!("platform/bcm2712/pcie_config.rs");
        }
        pub mod nic_ring {
            include!("platform/bcm2712/nic_ring.rs");
        }
        pub mod smmu {
            include!("platform/bcm2712/smmu.rs");
        }
        pub mod msi {
            include!("platform/bcm2712/msi.rs");
        }
    }
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
