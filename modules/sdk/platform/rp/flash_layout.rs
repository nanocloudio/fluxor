// Platform: RP flash layout.
//
// Layer: platform/rp (chip-specific, unstable).
//
// An RP board's XIP flash (0x1000_0000 base) is partitioned by
// [`graph_flash`] from two numbers: the board's flash size (a board fact,
// `[hardware.flash] size` in its TOML, defaulting to the silicon's) and the
// flash the kernel reserves for itself (a silicon fact). From the top:
//
//   last 4 KB sector          runtime parameter store
//   below it                  graph slot B
//   below that                graph slot A, the same size
//   from 0                    firmware + modules + static config
//
// The two slots are each a third of what the kernel leaves, so the region
// below them holds the kernel and a graph as large as a slot: any graph a
// board can be deployed with it can also be sent over the air, and the
// reverse. A 4 MB Pico 2 W gets two 1,148 KiB slots, a 2 MB Pico W two of
// 508 KiB, a 16 MB board two of some 5 MiB.
//
// The geometry is not a constant a module compiles in: the kernel is built
// for one board and answers it (`kernel_abi::FLASH_LAYOUT`), so one module
// build serves every board of its silicon. The kernel and the tool both
// compute it here.
//
// This layout is RP-specific. Other chips (BCM2712, future ESP32)
// carry their own layout in their own `platform/<chip>` modules. The
// on-flash data formats (slot header, parameter store entries) are the
// property of this layer too — a second chip that happens to reuse the
// same format still pays its own constants here rather than reaching
// into another platform.

/// XIP mapping base on RP2040 / RP2350.
pub const XIP_BASE: u32 = 0x1000_0000;

// ── Graph slot A/B (OTA reconfigure) ──────────────────────────────────
//
// Two equal regions below the parameter store. Each holds one graph image
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

pub const PARAM_STORE_SIZE: usize = 4096;
pub const PARAM_STORE_MAGIC: u32 = 0x4650_5846; // "FXPS"
pub const PARAM_STORE_VERSION: u8 = 1;

// ── The partition ────────────────────────────────────────────────────

/// The erase sector, and so the alignment of every region here.
pub const FLASH_SECTOR: u32 = 4096;

/// Where each region lies, as offsets from [`XIP_BASE`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GraphFlash {
    /// The board's flash, in bytes.
    pub flash_size: u32,
    /// Slot A's first byte; the firmware region ends here.
    pub slot_a: u32,
    pub slot_b: u32,
    /// Each slot's size: the largest image it holds, header included. 0 when
    /// the flash leaves no room for two after the kernel, and the board has
    /// no OTA.
    pub slot_size: u32,
    pub param_store: u32,
}

/// Bytes [`GraphFlash::encode`] writes and `FLASH_LAYOUT` answers:
/// `[flash_size][slot_a][slot_b][slot_size][param_store]`, each a u32 LE.
pub const GRAPH_FLASH_LEN: usize = 20;

/// The partition of a board with `flash_size` bytes of flash, of which the
/// kernel reserves `kernel_reserve` at the bottom: the parameter store in the
/// last sector, and two equal slots below it, each a third of what is left,
/// sector-aligned. A flash too small for that gets slots of size 0.
pub const fn graph_flash(flash_size: u32, kernel_reserve: u32) -> GraphFlash {
    let flash_size = flash_size - flash_size % FLASH_SECTOR;
    let param_store = flash_size.saturating_sub(FLASH_SECTOR);
    let usable = param_store.saturating_sub(kernel_reserve);
    let third = usable / 3;
    let slot_size = third - third % FLASH_SECTOR;
    let slot_b = param_store - slot_size;
    let slot_a = slot_b - slot_size;
    GraphFlash {
        flash_size,
        slot_a,
        slot_b,
        slot_size,
        param_store,
    }
}

impl GraphFlash {
    /// The `FLASH_LAYOUT` answer.
    pub const fn encode(&self) -> [u8; GRAPH_FLASH_LEN] {
        let words = [
            self.flash_size,
            self.slot_a,
            self.slot_b,
            self.slot_size,
            self.param_store,
        ];
        let mut out = [0u8; GRAPH_FLASH_LEN];
        let mut i = 0;
        while i < words.len() {
            let b = words[i].to_le_bytes();
            out[i * 4] = b[0];
            out[i * 4 + 1] = b[1];
            out[i * 4 + 2] = b[2];
            out[i * 4 + 3] = b[3];
            i += 1;
        }
        out
    }

    /// Read a `FLASH_LAYOUT` answer, refusing one whose regions do not fit
    /// the flash it names or overlap.
    pub fn decode(bytes: &[u8]) -> Option<GraphFlash> {
        if bytes.len() < GRAPH_FLASH_LEN {
            return None;
        }
        let w = |i: usize| {
            u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ])
        };
        let g = GraphFlash {
            flash_size: w(0),
            slot_a: w(1),
            slot_b: w(2),
            slot_size: w(3),
            param_store: w(4),
        };
        let fits = (g.param_store as u64) + (PARAM_STORE_SIZE as u64) <= g.flash_size as u64
            && (g.slot_a as u64) + (g.slot_size as u64) <= g.slot_b as u64
            && (g.slot_b as u64) + (g.slot_size as u64) <= g.param_store as u64;
        if fits {
            Some(g)
        } else {
            None
        }
    }

    /// The offset of slot 0 (A) or 1 (B).
    pub const fn slot(&self, index: u8) -> u32 {
        if index == 1 {
            self.slot_b
        } else {
            self.slot_a
        }
    }
}
