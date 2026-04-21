// Platform: RP flash layout.
//
// Layer: platform/rp (chip-specific, unstable).
//
// The RP-family runtime uses a 4 MB XIP flash (0x1000_0000 base),
// partitioned end-to-end as:
//
//   0x000000 - 0x2FCFFF   firmware + modules + static config (~3 MB)
//   0x2FD000 - 0x37CFFF   graph slot A (512 KB)
//   0x37D000 - 0x3FCFFF   graph slot B (512 KB)
//   0x3FF000 - 0x3FFFFF   runtime parameter store (4 KB)
//
// These constants are RP-specific. Other chips (BCM2712, future ESP32)
// carry their own layout in their own `platform/<chip>` modules. The
// on-flash data formats (slot header, parameter store entries) are the
// property of this layer too — a second chip that happens to reuse the
// same format still pays its own constants here rather than reaching
// into another platform.

/// XIP mapping base on RP2040 / RP2350.
pub const XIP_BASE: u32 = 0x1000_0000;

// ── Graph slot A/B (OTA reconfigure) ──────────────────────────────────
//
// Two 512 KB regions at the top of flash. Each holds one version of the
// graph bundle (modules table + static config); the slot with a valid
// magic and higher epoch is live. Consumed by `src/kernel/config.rs`
// (boot-time read) and `modules/foundation/graph_slot/mod.rs` (writer).

pub const GRAPH_SLOT_A_OFFSET: u32 = 0x002F_D000;
pub const GRAPH_SLOT_B_OFFSET: u32 = 0x0037_D000;
pub const GRAPH_SLOT_SIZE: u32 = 0x0008_0000; // 512 KB
pub const GRAPH_SLOT_MAGIC: u32 = 0x4C53_5846; // "FXSL"
pub const GRAPH_SLOT_VERSION: u8 = 1;
/// Bytes reserved at the start of each slot for the slot header
/// (magic/epoch/sizes/sha256). See `contracts/storage/graph_slot.rs`
/// for the on-flash field layout.
pub const GRAPH_SLOT_HEADER_SIZE: usize = 256;

// ── Runtime parameter store ──────────────────────────────────────────
//
// Last 4 KB sector of flash; log-structured append of TLV entries
// scoped per (module_id, tag). Consumed by `src/platform/rp/flash.rs`
// (boot scan + merge) and `modules/drivers/flash_rp/mod.rs` (writer).

pub const PARAM_STORE_OFFSET: u32 = 0x003F_F000;
pub const PARAM_STORE_SIZE: usize = 4096;
pub const PARAM_STORE_MAGIC: u32 = 0x4650_5846; // "FXPS"
pub const PARAM_STORE_VERSION: u8 = 1;
