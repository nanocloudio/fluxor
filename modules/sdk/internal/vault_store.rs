// Internal: the key vault's durable store, kept by the `vault_store` module.
//
// Layer: internal (unstable, kernel-private).
//
// The vault keeps the node's persisted records as one image, `FXVS` v1, held
// in kernel RAM. The `vault_store` module carries that image to and from a
// `storage.block` source in two A/B slots, so a power cut at any point leaves
// the previous image whole. The kernel owns the format and every validity
// decision; the module owns the I/O, and so where the bytes live (a flash
// region, an SD card's file or partition, an NVMe window, a host file) is a
// graph's choice, with one implementation behind all of them.
//
// Every opcode takes handle=-1, rides the key-vault provider (class 0x10),
// and needs the `vault_store` permission; after `ATTACH` only the attaching
// instance is answered. All fields are little-endian.
//
// The cycle:
//
// 1. `ATTACH` once, with the image size and the seal mode.
// 2. Load: every slot's first `image_len` bytes through `LOAD` in phase
//    `SCAN` (slot 0, then slot 1), then `DECIDE`; when it names a slot, that
//    slot again through `LOAD` in phase `FILL`. The kernel needs one image of
//    RAM for this, never two: the scan keeps only a running digest.
// 3. Run: `PENDING` names an image to write and its slot; `READ` hands it
//    over in pieces; `DONE` reports it durable (or failed). A `READ` answered
//    `EAGAIN` means the image changed while it was written: ask `PENDING`
//    again, which names the same slot.

/// Become the vault's store. arg: `[image_len:u32][seal:u8][_pad:3]`.
/// Returns 0 (load next), or 1 when the image is already loaded — a new
/// instance after a graph rebuild — and the module goes straight to running;
/// `-EBUSY` when another live instance is the store; `-EINVAL` for an image
/// that is not a multiple of 512 bytes in `MIN_IMAGE..=` the kernel's
/// `MAX_IMAGE`, an unknown seal mode, or one that differs from the store
/// already loaded.
pub const ATTACH: u32 = 0x1040;

/// One piece of a slot as the medium holds it. arg:
/// `[phase:u8][slot:u8][_pad:2][offset:u32][ptr:u64][len:u32][_pad:4]`.
/// Pieces of one pass arrive in order from offset 0; the pass ends at
/// `image_len`. Returns 0; `-EINVAL` out of order or out of phase; `-EIO`
/// when a `FILL` ends with bytes that are not the image its `SCAN` chose
/// (the medium changed between the passes): load again from `SCAN`.
pub const LOAD: u32 = 0x1041;

/// After both slots were scanned: which slot to `FILL`. Returns 0 or 1, or
/// 2 when neither held an image and the store starts empty (and is ready).
pub const DECIDE: u32 = 0x1042;

/// The image waiting to be written, if any. arg: `[seq_out:u64][slot_out:u8]
/// [_pad:7]`. Returns 1 when one is waiting, 0 when the medium holds the
/// newest, `-EAGAIN` before the load finished.
pub const PENDING: u32 = 0x1043;

/// Copy part of image `seq`. arg: `[seq:u64][offset:u32][len:u32][ptr:u64]`.
/// Returns 0; `-EAGAIN` when the image is no longer `seq` (ask `PENDING`
/// again).
pub const READ: u32 = 0x1044;

/// Image `seq` reached its slot (status 0: written and flushed, so it
/// survives a power cut) or did not (a negative errno). arg:
/// `[seq:u64][status:i32][_pad:4]`. Returns 0.
pub const DONE: u32 = 0x1045;

/// Pass of a [`LOAD`].
pub mod phase {
    /// Digest a slot to learn whether it holds an image, and which.
    pub const SCAN: u8 = 0;
    /// Copy the slot [`super::DECIDE`] chose into the kernel.
    pub const FILL: u8 = 1;
}

/// The `seal` mode an [`ATTACH`] names.
pub mod seal {
    /// Sealed under the platform's key, which the medium never holds. A
    /// board with no such key persists nothing, and says so.
    pub const HARDWARE: u8 = 0;
    /// Kept readable on the medium: anyone holding it can copy the keys.
    /// Each record is marked so, and a key kept this way reports it.
    pub const NONE: u8 = 1;
}

/// Smallest image an [`ATTACH`] may name.
pub const MIN_IMAGE: u32 = 1024;
/// [`DECIDE`]: neither slot held an image.
pub const DECIDE_EMPTY: i32 = 2;

/// Argument sizes.
pub const ATTACH_LEN: usize = 8;
pub const LOAD_LEN: usize = 24;
pub const PENDING_LEN: usize = 16;
pub const READ_LEN: usize = 24;
pub const DONE_LEN: usize = 16;

/// Whether `op` is one of these opcodes.
pub const fn is_store_op(op: u32) -> bool {
    op >= ATTACH && op <= DONE
}
