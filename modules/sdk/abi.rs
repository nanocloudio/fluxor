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
//! - `abi::contracts::hal::pio::CMD_TRANSFER`
//! - `abi::contracts::net::net_proto::CMD_BIND`
//! - `abi::platform::rp::flash_layout::GRAPH_SLOT_SIZE`
//! - `abi::internal::reconfigure::CALL_DRAIN`
//! - `abi::platform::bcm2712::pcie_nic::NIC_BAR_MAP`

// ─── Layered structure ───────────────────────────────────────────────

pub mod kernel_abi {
    include!("kernel_abi.rs");
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
        pub mod pio {
            include!("contracts/hal/pio.rs");
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
    }
    pub mod key_vault {
        include!("contracts/key_vault.rs");
    }
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
    pub mod bcm2712 {
        pub mod mmio_dma {
            include!("platform/bcm2712/mmio_dma.rs");
        }
        pub mod pcie_nic {
            include!("platform/bcm2712/pcie_nic.rs");
        }
        pub mod pcie_device {
            include!("platform/bcm2712/pcie_device.rs");
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
