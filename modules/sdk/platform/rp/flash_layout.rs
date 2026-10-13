// Platform: RP flash layout.
//
// Layer: platform/rp (chip-specific, unstable).
//
// The RP-family runtime uses a 4 MB XIP flash (0x1000_0000 base),
// partitioned as:
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
// Two 512 KB regions near the top of flash. Each holds one graph image
// (`fluxor build --emit=image`): this header, the module table with its
// program section, and the static config. Of the slots the boot selector
// admits, the one with the higher epoch is live. Consumed by
// `src/kernel/boot/config.rs` (boot-time selection),
// `modules/foundation/graph_slot/mod.rs` (writer) and, for the same image
// staged in RAM, `src/kernel/module/ota_stage.rs`.
//
// Header (256 bytes, little-endian):
//
//   0..4     magic "FXSL"
//   4        version
//   5..8     unused (0xFF)
//   8..16    epoch (u64)
//   16..20   modules offset    20..24  modules size
//   24..28   config offset     28..32  config size
//   32..64   SHA-256 over the modules region then the config region
//   64..96   ABI-surface pin
//   96..168  signature record (below), or erased (0xFF) when unsigned
//   168..256 unused

pub const GRAPH_SLOT_A_OFFSET: u32 = 0x002F_D000;
pub const GRAPH_SLOT_B_OFFSET: u32 = 0x0037_D000;
pub const GRAPH_SLOT_SIZE: u32 = 0x0008_0000; // 512 KB
pub const GRAPH_SLOT_MAGIC: u32 = 0x4C53_5846; // "FXSL"
pub const GRAPH_SLOT_VERSION: u8 = 1;
/// Bytes reserved at the start of each slot for the header laid out above.
pub const GRAPH_SLOT_HEADER_SIZE: usize = 256;
/// Header offset of the 32-byte ABI-surface pin (`abi_surface.rs` digest
/// of the substrate the image was built against). `fluxor build
/// --emit=image` writes it; every reader accepts an image only when the
/// pin equals the running kernel's own surface digest.
pub const GRAPH_SLOT_ABI_SURFACE_OFFSET: usize = 64;
/// The header bytes a slot signature covers: magic through the ABI pin
/// (`[0..96]`) -- the epoch, both regions' offsets and sizes, the payload's
/// SHA-256 and the pin. The payload is bound through its digest, so one
/// signature over these bytes vouches for every module, the config and the
/// program section together.
pub const GRAPH_SLOT_SIGNED_LEN: usize = 96;
/// Header offset of the signature record: `[magic "SIG1"][key id: 4 bytes =
/// the first four of SHA-256(public key)][Ed25519 signature R ‖ S: 64
/// bytes]`, 72 bytes in all. An unsigned image leaves these bytes erased
/// (0xFF). A kernel built with a slot root (`FLUXOR_SLOT_ROOT_HEX`) accepts
/// only an image whose record verifies against it; one built without checks
/// no signature.
pub const GRAPH_SLOT_SIGNATURE_OFFSET: usize = 96;
pub const GRAPH_SLOT_SIGNATURE_MAGIC: u32 = 0x3147_4953; // "SIG1"
pub const GRAPH_SLOT_SIGNATURE_LEN: usize = 72;

// ── Runtime parameter store ──────────────────────────────────────────
//
// Last 4 KB sector of flash; log-structured append of TLV entries
// scoped per (module_id, tag). Consumed by `src/platform/rp/flash.rs`
// (boot scan + merge) and `modules/drivers/flash_rp/mod.rs` (writer).

pub const PARAM_STORE_OFFSET: u32 = 0x003F_F000;
pub const PARAM_STORE_SIZE: usize = 4096;
pub const PARAM_STORE_MAGIC: u32 = 0x4650_5846; // "FXPS"
pub const PARAM_STORE_VERSION: u8 = 1;
