//! crypt_block — authenticated encryption for a `storage.block` source.
//!
//! A block consumer on its `lower` input and a block source on its `blocks`
//! output. Every authentication unit (default 4 KiB) is sealed with an AEAD
//! under a volume data key held behind a KEY_VAULT handle; the key bytes
//! never enter this module. Each unit's nonce, tag and write generation live
//! in a metadata table on the lower device, and every write goes through a
//! write-ahead journal first, so a crash leaves each unit old or new —
//! never a unit whose data and metadata disagree.
//!
//! The on-device layout, the unit AEAD and the journal rules are the v1
//! container format: A/B superblocks (HMAC-authenticated), the journal, the
//! metadata table, then the data units the upper device addresses.
//!
//! Durability follows the lower device. A write completes `Volatile`; a
//! `FLUSH` makes the journal durable, writes the pending units home and
//! flushes again, and completes with the fence the lower source reported
//! for that last flush (on a source with no volatile cache, for its last
//! write): `LocalDurable` from a disk, `RevisionMonotone` from a Loam
//! volume. It is passed through as reported, never strengthened.
//! Encryption adds confidentiality and integrity, never durability.
//!
//! Lower I/O is asynchronous. One lower request is in flight at a time:
//! SUBMITted and REAPed on a source with `F_ASYNC`, otherwise an EXEC that
//! is asked again after a step while it answers `EAGAIN`. Every operation
//! — the mount, a unit read or write, a journal cycle, recovery, a rotation
//! phase, an erase — is a resumable state machine that yields while its
//! lower request is outstanding and resumes there, so a mount that waits
//! commits one superblock generation, not one per attempt. A source that
//! completes inline is one whose completions arrive at once. Each pump of
//! the engine is bounded by `STEP_BUDGET`.
//!
//! Upper requests complete when their lower work does. A `SUBMIT` queues
//! the request and `REAP` returns its completion later; its buffer is lent
//! until then (no `F_WRITE_COPIES`). An `EXEC` completes inside the call
//! when its lower work completes inside the call; otherwise it answers
//! `EAGAIN`, the request carries on in later steps, and the caller's next
//! `EXEC` of the same request (byte-identical, same tag) completes it. The
//! caller's buffer is touched only inside those calls. An `EXEC` of another
//! request, or a `SUBMIT`, drops an `EXEC` whose caller stopped asking.
//!
//! On a raw lower device the generations live in the same rollback domain
//! as the data: they make crash recovery exact and do not detect a hostile
//! restore of the whole device.
//!
//! The volume master comes one of two ways:
//! - **Local:** a persisted `KDF_KEY` under this module's `key` label.
//! - **Attach:** reconstructed from two share envelopes. The module makes a
//!   fresh recipient key, writes its public key to the `recipient` output,
//!   and waits for the attachment bundle on its `bundle` control input.
//!   The master it reconstructs is bound to the container's volume id and
//!   epoch, never persisted, and the recipient key is destroyed once used.
//!
//! **Data-key rotation** moves the volume to a new master and epoch without
//! taking it offline. A `"FXRT"` record on the control input starts it; the
//! superblock carries it through prepared, active, migrating and retiring,
//! so a crash at any point resumes where it was:
//! - **Prepared:** the next epoch's master is held: generated and
//!   persisted (local), or reconstructed from its bundle (attach).
//! - **Active:** new writes seal under the new epoch; reads take each
//!   unit's key from the epoch its metadata names.
//! - **Migrating:** each step re-seals a bounded batch of old-epoch units
//!   and commits the cursor once the batch is home and durable.
//! - **Retiring:** a scan proves no unit needs the old epoch; the steady
//!   superblock is committed, and only then is the old master destroyed
//!   (its label, local; its handle, attach).
//!
//! Attached, the next master comes from the custodians. The `"FXRT"` record
//! makes a fresh recipient and announces it on `recipient`; the pipeline
//! that sent the record knows it asked for the next epoch, and answers with
//! that epoch's bundle on the control input. The bundle is reconstructed
//! bound to the volume id and the next epoch, its recipient destroyed, and
//! only then is the prepared superblock committed. A bundle refused (another
//! epoch, volume or recipient) changes nothing: the volume stays steady and
//! a fresh recipient is announced for the next try. Attached masters are
//! never persisted, so a mount under a rotation needs both epochs' bundles
//! again: it announces a recipient, takes a bundle for either epoch it
//! needs (the one its superblock names, and the next while prepared or the
//! previous after), refuses one for any other epoch and announces afresh,
//! and mounts once it holds both. Each epoch a bundle is for is the one its
//! envelopes name.
//!
//! **Crypto-erase:** an `"FXER"` record on the control input destroys every
//! master the volume has, then zeroes both superblocks. Keys go first: a
//! crash after that already leaves nothing readable. The device goes offline
//! (`ENODEV`).
//!
//! **Status:** the optional `status` output carries one fixed record,
//! written whenever what it reports changes (and so once at ready), for
//! the pipeline that drives the control records to follow: `"FXST"`,
//! state (opening, awaiting a bundle, ready, rotating, failed, erased),
//! the superblock's rotation state, two reserved bytes, epoch, previous
//! epoch, the epoch a bundle is awaited for (0 for none or unknown), an
//! errno, and the volume id; little-endian. A full channel never holds the
//! module up: a record not yet written waits for the next step, and only
//! the latest is kept, so a slow reader loses intermediate states and never
//! the latest.
//!
//! Parameters:
//! - `key`: the vault label of the volume's master key (local), at most 64
//!   bytes. Epoch 1's master is filed under `key`, a later epoch's under
//!   `key#<epoch>`, which must fit the same bound.
//! - `attach`: 1 takes the master from an attachment bundle instead.
//! - `format`: 1 formats a lower device with no superblock in either slot.
//!   A device whose superblocks do not verify holds a container and is never
//!   formatted. In attach mode the new container takes the bundle's volume id
//!   and epoch.
//! - `block_size`: the upper logical block size, a power of two from 512 to
//!   the unit size (default 512).
//! - `unit_size`: the authentication unit, a power of two from 512 to 4096
//!   (default 4096).
//! - `journal_units`: journal size in units, even, 2 to 128; a record takes
//!   two units, a header and its ciphertext (default 64).

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    reason = "the PIC build mounts the whole of modules/sdk/* via include!, so every \
              module's compile sees the entire ABI surface while using a subset. This \
              allow is the SDK's textual mounting showing through"
)]
#![allow(
    unused_imports,
    reason = "same cause: the mounted SDK brings names this module does not reach for"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

use abi::contracts::key_vault as kv;
use abi::contracts::storage::block::{self as blk, Caps, Cpl, Req};
use abi::fence::Fence;

// ── Format constants ────────────────────────────────────────────────────

/// Largest authentication unit this build supports.
pub const MAX_UNIT: usize = 4096;
/// Largest lower logical block.
const MAX_LOWER_BLOCK: usize = 4096;
/// Requests whose completions wait for `REAP`.
pub const QUEUE_DEPTH: usize = 8;
/// Journal records this build indexes: half the largest journal.
pub const MAX_JOURNAL_RECORDS: usize = 64;
/// Journal records whose ciphertext stays in memory once written, so a
/// journal cycle writes it home without reading it back from the lower
/// device: over a remote volume that read is a round trip per unit. The
/// rp2350 keeps none; the cache is a quarter of a megabyte.
#[cfg(not(fluxor_silicon = "rp2350"))]
const JOURNAL_CACHE: usize = MAX_JOURNAL_RECORDS;
#[cfg(fluxor_silicon = "rp2350")]
const JOURNAL_CACHE: usize = 0;
/// Nonce sequences reserved per superblock write.
pub const NONCE_STRIDE: u64 = 1 << 20;
/// Bytes of a unit metadata record.
pub const META_LEN: usize = 48;
/// Longest master-key label.
const KEY_LABEL_CAP: usize = 64;

pub const SB_MAGIC: [u8; 8] = *b"FXCRYPTB";
pub const JOURNAL_MAGIC: [u8; 4] = *b"FXCJ";
pub const AAD_MAGIC: [u8; 4] = *b"FXCB";
/// Bytes of the superblock the MAC covers.
pub const SB_MAC_OFF: usize = 224;
pub const SB_LEN: usize = 256;
/// Bytes of the unit AAD.
pub const AAD_LEN: usize = 56;
/// Unit flag: discarded, reads as zeros.
pub const FLAG_DISCARDED: u32 = 1;

/// A bundle not for this volume, epoch or recipient.
const E_ACCES: i32 = -13;

pub const SUITE_CHACHA: u16 = 1;
pub const SUITE_AES: u16 = 2;

/// An attachment bundle on the `bundle` input: `"FXSB"`, the envelope
/// count (2) and three zero bytes, then the two share envelopes.
pub const BUNDLE_MAGIC: [u8; 4] = *b"FXSB";
pub const BUNDLE_LEN: usize = 8 + 2 * kv::share::P256_LEN;
/// The recipient announcement on the `recipient` output: `"FXRK"` then
/// the recipient's uncompressed P-256 public key.
pub const RECIPIENT_MAGIC: [u8; 4] = *b"FXRK";
pub const RECIPIENT_LEN: usize = 4 + kv::share::P256_PUB_LEN;

/// A control record that starts a data-key rotation: `"FXRT"` then four
/// zero bytes.
pub const ROTATE_MAGIC: [u8; 4] = *b"FXRT";
pub const ROTATE_LEN: usize = 8;
/// A control record that crypto-erases the volume: `"FXER"` then four zero
/// bytes. Control records are all this long.
pub const ERASE_MAGIC: [u8; 4] = *b"FXER";
/// The status record on the `status` output: `"FXST"`, state, rotation,
/// two reserved bytes, epoch, previous epoch, awaited epoch, errno, volume
/// id. Little-endian.
pub const STATUS_MAGIC: [u8; 4] = *b"FXST";
pub const STATUS_LEN: usize = 40;
/// Status states.
pub const ST_OPENING: u8 = 0;
pub const ST_AWAITING_BUNDLE: u8 = 1;
pub const ST_READY: u8 = 2;
pub const ST_ROTATING: u8 = 3;
pub const ST_FAILED: u8 = 4;
pub const ST_ERASED: u8 = 5;
/// Units a rotation step re-seals: bounds the work in one module step.
pub const MIGRATE_BATCH: u64 = 8;
/// Lower requests and operation resumptions one pump of the engine runs
/// before it yields. Above what any single upper request costs over a
/// source that completes inline (a full journal cycle at one lower block
/// per request), so EXEC over such a source still completes in its call.
pub const STEP_BUDGET: u32 = 4096;
/// Deepest nesting of operations under way: a request, the unit write it
/// makes, the journal cycle that write needs, the metadata write in it,
/// and one to spare. A deeper call fails `EIO` rather than overrunning.
pub const MAX_FRAMES: usize = 5;

/// Rotation states, as the superblock records them.
pub const ROT_STEADY: u8 = 0;
pub const ROT_PREPARED: u8 = 1;
pub const ROT_ACTIVE: u8 = 2;
pub const ROT_MIGRATING: u8 = 3;
pub const ROT_RETIRING: u8 = 4;

pub const LABEL_DATA: &[u8] = b"crypt_block/data";
pub const LABEL_SUPERBLOCK: &[u8] = b"crypt_block/superblock";

// ── Arithmetic ──────────────────────────────────────────────────────────
//
// A PIC module has no panic path to link, so no division here may be one
// the compiler cannot prove safe: every runtime divisor goes through these,
// and a zero divisor — which geometry validation rules out — yields 0.

fn div(a: u64, b: u64) -> u64 {
    a.checked_div(b).unwrap_or(0)
}

fn rem(a: u64, b: u64) -> u64 {
    a.checked_rem(b).unwrap_or(0)
}

fn div_ceil(a: u64, b: u64) -> u64 {
    div(a, b) + u64::from(rem(a, b) != 0)
}

// ── Pure record codecs ──────────────────────────────────────────────────

/// The container's geometry and state, as a superblock records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Superblock {
    pub generation: u64,
    pub volume_id: [u8; 16],
    pub suite: u16,
    pub flags: u16,
    pub unit_size: u32,
    pub lower_block: u32,
    pub journal_units: u32,
    pub data_units: u64,
    pub epoch: u32,
    pub prev_epoch: u32,
    pub rotation: u8,
    pub prefix: u32,
    pub prev_prefix: u32,
    pub reserved_seq: u64,
    pub rotation_cursor: u64,
    pub policy_digest: [u8; 32],
}

impl Superblock {
    /// The 224 bytes the MAC covers, in the v1 layout.
    pub fn encode_body(&self, out: &mut [u8; SB_MAC_OFF]) {
        out.fill(0);
        out[0..8].copy_from_slice(&SB_MAGIC);
        out[8..16].copy_from_slice(&self.generation.to_le_bytes());
        out[16..32].copy_from_slice(&self.volume_id);
        out[32..34].copy_from_slice(&self.suite.to_le_bytes());
        out[34..36].copy_from_slice(&self.flags.to_le_bytes());
        out[36..40].copy_from_slice(&self.unit_size.to_le_bytes());
        out[40..44].copy_from_slice(&self.lower_block.to_le_bytes());
        out[44..48].copy_from_slice(&self.journal_units.to_le_bytes());
        out[48..56].copy_from_slice(&self.data_units.to_le_bytes());
        out[56..60].copy_from_slice(&self.epoch.to_le_bytes());
        out[60..64].copy_from_slice(&self.prev_epoch.to_le_bytes());
        out[64] = self.rotation;
        out[68..72].copy_from_slice(&self.prefix.to_le_bytes());
        out[72..76].copy_from_slice(&self.prev_prefix.to_le_bytes());
        out[76..84].copy_from_slice(&self.reserved_seq.to_le_bytes());
        out[92..100].copy_from_slice(&self.rotation_cursor.to_le_bytes());
        out[100..132].copy_from_slice(&self.policy_digest);
    }

    /// Parse a superblock body, refusing one whose magic or geometry is not
    /// a container's. The MAC is the caller's to check.
    pub fn decode_body(b: &[u8]) -> Option<Superblock> {
        if b.len() < SB_MAC_OFF || b[0..8] != SB_MAGIC {
            return None;
        }
        let u16_at = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let u64_at = |o: usize| {
            let mut v = [0u8; 8];
            v.copy_from_slice(&b[o..o + 8]);
            u64::from_le_bytes(v)
        };
        let mut volume_id = [0u8; 16];
        volume_id.copy_from_slice(&b[16..32]);
        let mut policy_digest = [0u8; 32];
        policy_digest.copy_from_slice(&b[100..132]);
        let sb = Superblock {
            generation: u64_at(8),
            volume_id,
            suite: u16_at(32),
            flags: u16_at(34),
            unit_size: u32_at(36),
            lower_block: u32_at(40),
            journal_units: u32_at(44),
            data_units: u64_at(48),
            epoch: u32_at(56),
            prev_epoch: u32_at(60),
            rotation: b[64],
            prefix: u32_at(68),
            prev_prefix: u32_at(72),
            reserved_seq: u64_at(76),
            rotation_cursor: u64_at(92),
            policy_digest,
        };
        let unit = sb.unit_size;
        let lower = sb.lower_block;
        let geometry_ok = unit >= 512
            && unit as usize <= MAX_UNIT
            && unit.is_power_of_two()
            && lower >= 512
            && lower <= unit
            && lower.is_power_of_two()
            && sb.journal_units >= 2
            && sb.journal_units.is_multiple_of(2)
            && sb.journal_units as usize / 2 <= MAX_JOURNAL_RECORDS
            && sb.data_units > 0
            && (sb.suite == SUITE_CHACHA || sb.suite == SUITE_AES)
            && sb.epoch > 0;
        if geometry_ok {
            Some(sb)
        } else {
            None
        }
    }
}

/// Where each region starts, in lower blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Layout {
    pub blocks_per_unit: u64,
    pub journal_start: u64,
    pub meta_start: u64,
    pub meta_blocks: u64,
    pub data_start: u64,
    pub records_per_block: u64,
    /// Lower blocks the container occupies.
    pub total_blocks: u64,
}

impl Layout {
    /// The layout of a container with this geometry.
    pub fn of(unit_size: u32, lower_block: u32, journal_units: u32, data_units: u64) -> Layout {
        let bpu = div(u64::from(unit_size), u64::from(lower_block));
        let rpb = u64::from(lower_block) / META_LEN as u64;
        let meta_lower = div_ceil(data_units, rpb);
        let meta_units = div_ceil(meta_lower, bpu);
        let journal_start = 2 * bpu;
        let meta_start = journal_start + u64::from(journal_units) * bpu;
        let data_start = meta_start + meta_units * bpu;
        Layout {
            blocks_per_unit: bpu,
            journal_start,
            meta_start,
            meta_blocks: meta_units * bpu,
            data_start,
            records_per_block: rpb,
            total_blocks: data_start + data_units * bpu,
        }
    }

    /// The most data units a lower device of `lower_blocks` holds.
    pub fn data_units_for(
        unit_size: u32,
        lower_block: u32,
        journal_units: u32,
        lower_blocks: u64,
    ) -> u64 {
        let bpu = div(u64::from(unit_size), u64::from(lower_block));
        let rpb = u64::from(lower_block) / META_LEN as u64;
        let units = div(lower_blocks, bpu);
        let fixed = 2 + u64::from(journal_units);
        if units <= fixed + 1 {
            return 0;
        }
        // Each data unit costs one unit of data plus 1/(rpb*bpu) units of
        // metadata; solve, then back off until the layout fits.
        let mut n = div((units - fixed) * rpb * bpu, rpb * bpu + 1);
        while n > 0
            && Layout::of(unit_size, lower_block, journal_units, n).total_blocks > lower_blocks
        {
            n -= 1;
        }
        n
    }

    /// Lower block holding unit `u`'s metadata record, and the record's
    /// byte offset in it.
    pub fn meta_location(&self, u: u64) -> (u64, usize) {
        (
            self.meta_start + div(u, self.records_per_block),
            rem(u, self.records_per_block) as usize * META_LEN,
        )
    }

    pub fn data_block(&self, u: u64) -> u64 {
        self.data_start + u * self.blocks_per_unit
    }

    /// Lower block of journal slot `slot`'s header; its data unit follows.
    pub fn journal_block(&self, slot: u64) -> u64 {
        self.journal_start + 2 * slot * self.blocks_per_unit
    }
}

/// A unit's metadata record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Meta {
    pub generation: u64,
    pub epoch: u32,
    pub flags: u32,
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
}

impl Meta {
    pub fn encode(&self, out: &mut [u8]) {
        out[..META_LEN].fill(0);
        out[0..8].copy_from_slice(&self.generation.to_le_bytes());
        out[8..12].copy_from_slice(&self.epoch.to_le_bytes());
        out[12..16].copy_from_slice(&self.flags.to_le_bytes());
        out[16..28].copy_from_slice(&self.nonce);
        out[28..44].copy_from_slice(&self.tag);
    }

    pub fn decode(b: &[u8]) -> Meta {
        let mut g = [0u8; 8];
        g.copy_from_slice(&b[0..8]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&b[16..28]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&b[28..44]);
        Meta {
            generation: u64::from_le_bytes(g),
            epoch: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
            flags: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
            nonce,
            tag,
        }
    }
}

/// The unit AEAD's associated data: magic, volume id, unit index, unit size,
/// then the unit's epoch, generation and flags. `fence_token` fills the last
/// eight bytes and is zero in every container.
pub fn unit_aad(
    volume_id: &[u8; 16],
    unit: u64,
    unit_size: u32,
    meta: &Meta,
    fence_token: u64,
) -> [u8; AAD_LEN] {
    let mut a = [0u8; AAD_LEN];
    a[0..4].copy_from_slice(&AAD_MAGIC);
    a[4..20].copy_from_slice(volume_id);
    a[20..28].copy_from_slice(&unit.to_le_bytes());
    a[28..32].copy_from_slice(&unit_size.to_le_bytes());
    a[32..36].copy_from_slice(&meta.epoch.to_le_bytes());
    a[36..44].copy_from_slice(&meta.generation.to_le_bytes());
    a[44..48].copy_from_slice(&meta.flags.to_le_bytes());
    a[48..56].copy_from_slice(&fence_token.to_le_bytes());
    a
}

/// The nonce for sequence `seq` under `prefix`.
pub fn unit_nonce(prefix: u32, seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0..4].copy_from_slice(&prefix.to_le_bytes());
    n[4..12].copy_from_slice(&seq.to_le_bytes());
    n
}

/// Data-key derivation context: volume id, then epoch.
pub fn data_context(volume_id: &[u8; 16], epoch: u32) -> [u8; 20] {
    let mut c = [0u8; 20];
    c[..16].copy_from_slice(volume_id);
    c[16..].copy_from_slice(&epoch.to_le_bytes());
    c
}

// ── State ───────────────────────────────────────────────────────────────

const PHASE_OPENING: u8 = 0;
const PHASE_READY: u8 = 1;
const PHASE_FAILED: u8 = 2;

#[derive(Clone, Copy)]
#[repr(C)]
struct Pending {
    unit: u64,
    meta: Meta,
    slot: u16,
    live: bool,
    _pad: [u8; 5],
}

impl Pending {
    const EMPTY: Pending = Pending {
        unit: 0,
        meta: Meta {
            generation: 0,
            epoch: 0,
            flags: 0,
            nonce: [0; 12],
            tag: [0; 16],
        },
        slot: 0,
        live: false,
        _pad: [0; 5],
    };
}

#[repr(C)]
struct CryptState {
    syscalls: *const SyscallTable,
    /// The upper `blocks` output this source answers on.
    out_chan: i32,
    phase: u8,
    format: u8,
    key_len: u8,
    /// 1: the master comes from an attachment bundle.
    attach: u8,
    open_err: i32,
    upper_block: u32,
    unit_param: u32,
    journal_param: u32,
    /// The volume master (`KDF_KEY`) and the data key derived from it, for
    /// the current epoch; during a rotation, the previous epoch's too (the
    /// next epoch's while prepared).
    master: i32,
    data_key: i32,
    other_master: i32,
    other_data_key: i32,
    lower: BlockClient,
    sb: Superblock,
    /// Which slot holds the current superblock: 0 = A, 1 = B.
    sb_slot: u8,
    _pad2: [u8; 7],
    layout: Layout,
    /// Next nonce sequence; `sb.reserved_seq` bounds it.
    next_seq: u64,
    /// Next journal slot and record sequence.
    journal_head: u32,
    _pad3: u32,
    journal_seq: u64,
    pending: [Pending; MAX_JOURNAL_RECORDS],
    /// Completions waiting for `REAP`.
    head: u8,
    count: u8,
    _pad4: [u8; 6],
    done: [Cpl; QUEUE_DEPTH],
    key_label: [u8; KEY_LABEL_CAP],
    /// Attach mode: the `bundle` input, the `recipient` output, the fresh
    /// recipient key, and the bundle as it arrives.
    ctrl_chan: i32,
    recipient_out: i32,
    recipient: i32,
    bundle_len: u32,
    /// The volume id and epoch a container formatted in attach mode takes.
    attach_resource: [u8; 16],
    attach_epoch: u32,
    _pad5: u32,
    /// The bundle as it arrives while mounting; once the container is
    /// ready, each record on the control input (a control record, or a
    /// rotation's bundle) as it arrives.
    bundle: [u8; BUNDLE_LEN],
    /// Attach mode. `rot_want`: the epoch a rotation waits for a bundle of,
    /// 0 for none. `need_other`: the other epoch a mount under a rotation
    /// needs a bundle of, 0 for none. `other_epoch`: the epoch
    /// `other_master` was reconstructed for while mounting.
    rot_want: u32,
    need_other: u32,
    other_epoch: u32,
    /// The record in `bundle` is a bundle for the rotation to take.
    bundle_ready: u8,
    _pad7: [u8; 3],
    /// The last background step's result, logged when it changes.
    rotate_err: i32,
    /// The `status` output (-1 when unwired). `status_cur` is the latest
    /// record, `status_tx` the one being written, `status_off` bytes of it
    /// written; `status_dirty`: `status_cur` is newer than what was sent.
    status_out: i32,
    /// The last background job's result, as the status reports it.
    bg_err: i32,
    /// The erase's result, once `erase_state` is `ERASE_DONE`.
    erase_rc: i32,
    status_have: u8,
    status_dirty: u8,
    status_tx_live: u8,
    status_off: u8,
    erase_state: u8,
    /// The kind of the background frame running.
    bg_kind: u8,
    /// Attach mode: the superblocks were read, unverified, before the
    /// bundle was awaited; `probe_sb` is the newest of them. `probe_blank`:
    /// neither slot holds a superblock (the only device a mount formats).
    attach_probed: u8,
    probe_blank: u8,
    status_cur: [u8; STATUS_LEN],
    status_tx: [u8; STATUS_LEN],
    probe_sb: Superblock,
    /// The engine: the lower request in flight, the operations under way
    /// (innermost last), and what runs on it.
    io: LowerIo,
    frames: [Frame; MAX_FRAMES],
    depth: u8,
    job: u8,
    /// The running EXEC request waits for its caller's next ask.
    parked: u8,
    /// The mount finished (`mount_rc` holds its result).
    mount_done: u8,
    mount_rc: i32,
    /// The fence of the lower completion that last made data durable.
    lower_fence_len: u16,
    lower_fence: [u8; blk::cpl::FENCE_CAP],
    /// Results a nested operation hands its caller.
    ret_slot: i32,
    ret_seq: u64,
    ret_meta: Meta,
    /// The generation being committed, the superblock a failed rotation
    /// commit restores, and slot A's superblock while slot B is read.
    commit_sb: Superblock,
    revert_sb: Superblock,
    sb_a: Superblock,
    sb_a_ok: u8,
    /// The upper EXEC request's slot, and whether its caller is inside the
    /// call now (its buffer is lent only then).
    exec_state: u8,
    exec_live: u8,
    _pad6: [u8; 5],
    exec: Upper,
    exec_cpl: Cpl,
    /// Queued upper SUBMITs, and the arrival counter that orders them.
    reqs: [Upper; QUEUE_DEPTH],
    req_seq: u64,
    /// Scratch: a unit's plaintext, its ciphertext, a journal header, a
    /// lower block for metadata read-modify-write.
    plain: [u8; MAX_UNIT],
    cipher: [u8; MAX_UNIT],
    header: [u8; MAX_UNIT],
    meta_block: [u8; MAX_LOWER_BLOCK],
    /// The ciphertext of each journal slot written since the ring last
    /// restarted (`JOURNAL_CACHE`), and which slots hold it.
    jcache: [[u8; MAX_UNIT]; JOURNAL_CACHE],
    jcache_held: u64,
}

impl CryptState {
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
    fn unit(&self) -> usize {
        self.sb.unit_size as usize
    }
}

mod params_def {
    use super::CryptState;
    use super::SCHEMA_MAX;
    use super::{p_u32, p_u8};

    define_params! {
        CryptState;

        1, key, str, 0
            => |s, d, len| {
                // A label the vault cannot hold is no label: truncating it would
                // file the master under a name the operator never gave.
                let n = if len > s.key_label.len() { 0 } else { len };
                for i in 0..s.key_label.len() { s.key_label[i] = 0; }
                for i in 0..n { s.key_label[i] = *d.add(i); }
                s.key_len = n as u8;
            };

        2, format, u8, 0
            => |s, d, len| { s.format = p_u8(d, len, 0, 0); };

        3, block_size, u32, 512
            => |s, d, len| { s.upper_block = p_u32(d, len, 0, 512); };

        4, unit_size, u32, 4096
            => |s, d, len| { s.unit_param = p_u32(d, len, 0, 4096); };

        5, journal_units, u32, 64
            => |s, d, len| { s.journal_param = p_u32(d, len, 0, 64); };

        6, attach, u8, 0
            => |s, d, len| { s.attach = p_u8(d, len, 0, 0); };
    }
}

// ── Vault calls ─────────────────────────────────────────────────────────

/// The label epoch `epoch`'s master is filed under: `key` for the first
/// epoch, `key#<epoch>` after it. 0 when it would not fit.
fn epoch_label(s: &CryptState, epoch: u32, out: &mut [u8; KEY_LABEL_CAP]) -> usize {
    let key = &s.key_label[..s.key_len as usize];
    out[..key.len()].copy_from_slice(key);
    if epoch <= 1 {
        return key.len();
    }
    let mut digits = [0u8; 10];
    let mut n = 0;
    let mut e = epoch;
    while e > 0 && n < digits.len() {
        digits[n] = b'0' + (e % 10) as u8;
        e /= 10;
        n += 1;
    }
    let len = key.len() + 1 + n;
    if len > KEY_LABEL_CAP {
        return 0;
    }
    out[key.len()] = b'#';
    for i in 0..n {
        out[key.len() + 1 + i] = digits[n - 1 - i];
    }
    len
}

/// Open epoch `epoch`'s persisted master, generating it when `create`.
unsafe fn vault_open_epoch(s: &CryptState, epoch: u32, create: bool) -> i32 {
    let mut label = [0u8; KEY_LABEL_CAP];
    let len = epoch_label(s, epoch, &mut label);
    if len == 0 {
        return E_INVAL;
    }
    let mut arg = [0u8; 8 + KEY_LABEL_CAP + 12];
    arg[0..2].copy_from_slice(&kv::suite::KDF_KEY.to_le_bytes());
    let usage = kv::usage::DERIVE | kv::usage::PERSIST;
    arg[2..6].copy_from_slice(&usage.to_le_bytes());
    arg[7] = len as u8;
    arg[8..8 + len].copy_from_slice(&label[..len]);
    let n = 8 + len + 12;
    let op = if create {
        kv::OPEN_OR_GENERATE
    } else {
        kv::OPEN
    };
    (s.sys().provider_call)(-1, op, arg.as_mut_ptr(), n)
}

/// Destroy epoch `epoch`'s persisted master, record and all.
unsafe fn vault_destroy_epoch(s: &CryptState, epoch: u32) -> i32 {
    let mut label = [0u8; KEY_LABEL_CAP];
    let len = epoch_label(s, epoch, &mut label);
    if len == 0 {
        return E_INVAL;
    }
    let mut arg = [0u8; 1 + KEY_LABEL_CAP];
    arg[0] = len as u8;
    arg[1..1 + len].copy_from_slice(&label[..len]);
    (s.sys().provider_call)(-1, kv::DESTROY_BY_LABEL, arg.as_mut_ptr(), 1 + len)
}

/// `DERIVE` a purpose key from the current master.
unsafe fn vault_derive(
    s: &CryptState,
    suite: u16,
    usage: u32,
    label: &[u8],
    context: &[u8],
) -> i32 {
    vault_derive_from(s, s.master, suite, usage, label, context)
}

/// `DERIVE` a purpose key from `master`.
unsafe fn vault_derive_from(
    s: &CryptState,
    master: i32,
    suite: u16,
    usage: u32,
    label: &[u8],
    context: &[u8],
) -> i32 {
    use kv::derive as d;
    let mut arg = [0u8; d::LABEL + 32 + 32];
    arg[d::TARGET_SUITE..d::TARGET_SUITE + 2].copy_from_slice(&suite.to_le_bytes());
    arg[d::TARGET_USAGE..d::TARGET_USAGE + 4].copy_from_slice(&usage.to_le_bytes());
    arg[d::LABEL_LEN] = label.len() as u8;
    arg[d::CONTEXT_LEN..d::CONTEXT_LEN + 2].copy_from_slice(&(context.len() as u16).to_le_bytes());
    arg[d::LABEL..d::LABEL + label.len()].copy_from_slice(label);
    arg[d::LABEL + label.len()..d::LABEL + label.len() + context.len()].copy_from_slice(context);
    let n = d::LABEL + label.len() + context.len();
    (s.sys().provider_call)(master, kv::DERIVE, arg.as_mut_ptr(), n)
}

unsafe fn vault_destroy(s: &CryptState, handle: i32) {
    (s.sys().provider_call)(handle, kv::DESTROY, core::ptr::null_mut(), 0);
}

/// The superblock MAC: HMAC-SHA256 under the derived superblock key.
unsafe fn superblock_mac(
    s: &CryptState,
    volume_id: &[u8; 16],
    body: &[u8; SB_MAC_OFF],
) -> Option<[u8; 32]> {
    let k = vault_derive(
        s,
        kv::suite::HMAC_SHA256,
        kv::usage::SIGN,
        LABEL_SUPERBLOCK,
        volume_id,
    );
    if k < 0 {
        return None;
    }
    let mut tag = [0u8; 32];
    let mut arg = [0u8; 6 + SB_MAC_OFF + 12];
    arg[0] = kv::sign_mode::RAW;
    arg[2..6].copy_from_slice(&(SB_MAC_OFF as u32).to_le_bytes());
    arg[6..6 + SB_MAC_OFF].copy_from_slice(body);
    let t = 6 + SB_MAC_OFF;
    arg[t..t + 8].copy_from_slice(&(tag.as_mut_ptr() as u64).to_le_bytes());
    arg[t + 8..t + 10].copy_from_slice(&32u16.to_le_bytes());
    let rc = (s.sys().provider_call)(k, kv::SIGN, arg.as_mut_ptr(), arg.len());
    vault_destroy(s, k);
    if rc < 0 {
        None
    } else {
        Some(tag)
    }
}

/// The buffers of one unit handed to the vault: the nonce and associated data
/// it is bound to, the bytes sealed or opened in place, and the tag beside
/// them.
#[derive(Clone, Copy)]
struct SealedUnit<'a> {
    nonce: &'a [u8; 12],
    aad: &'a [u8],
    data: *mut u8,
    len: usize,
    tag: *mut u8,
}

/// Seal or open one buffer in place under the data key. Seal writes the tag;
/// open checks it and zeroes the buffer when it does not verify.
unsafe fn vault_unit(s: &CryptState, key: i32, seal: bool, unit: &SealedUnit) -> i32 {
    use kv::units as u;
    let SealedUnit {
        nonce,
        aad,
        data,
        len,
        tag,
    } = *unit;
    let mut arg = [0u8; u::HEADER_LEN + u::ENTRY_LEN];
    arg[u::COUNT..u::COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
    let e = u::HEADER_LEN;
    arg[e + u::NONCE..e + u::NONCE + 12].copy_from_slice(nonce);
    arg[e + u::AAD_LEN..e + u::AAD_LEN + 2].copy_from_slice(&(aad.len() as u16).to_le_bytes());
    arg[e + u::AAD_PTR..e + u::AAD_PTR + 8].copy_from_slice(&(aad.as_ptr() as u64).to_le_bytes());
    arg[e + u::DATA_PTR..e + u::DATA_PTR + 8].copy_from_slice(&(data as u64).to_le_bytes());
    arg[e + u::DATA_LEN..e + u::DATA_LEN + 4].copy_from_slice(&(len as u32).to_le_bytes());
    arg[e + u::TAG_PTR..e + u::TAG_PTR + 8].copy_from_slice(&(tag as u64).to_le_bytes());
    let op = if seal {
        kv::AEAD_SEAL_UNITS
    } else {
        kv::AEAD_OPEN_UNITS
    };
    let rc = (s.sys().provider_call)(key, op, arg.as_mut_ptr(), arg.len());
    match rc {
        0 => 0,
        rc if rc < 0 => rc,
        _ => E_IO,
    }
}

/// The data key for units sealed under `epoch`: the current epoch's, or
/// during a rotation the previous one's. `None` for any other epoch.
fn key_for_epoch(s: &CryptState, epoch: u32) -> Option<i32> {
    if epoch == s.sb.epoch && s.data_key >= 0 {
        Some(s.data_key)
    } else if s.sb.rotation >= ROT_ACTIVE && epoch == s.sb.prev_epoch && s.other_data_key >= 0 {
        Some(s.other_data_key)
    } else {
        None
    }
}

// ── Lower I/O engine ────────────────────────────────────────────────────
//
// Every lower read, write and flush goes through one engine that keeps one
// lower request in flight. On a source with `F_ASYNC` the request is
// SUBMITted and its completion REAPed, in the same step or a later one; on
// a source without it the request is an EXEC, and an EXEC answered `EAGAIN`
// is asked again, with the same tag, on a later pump. An EXEC that completes
// is a request whose completion arrived at once: nothing above the engine
// knows which kind of source it drives.
//
// One request at a time keeps the order the container format rests on — a
// journal record before the flush that covers it, homes only after it —
// without tracking dependencies between requests in flight, and it is the
// one unit in flight the format's budget allows the smallest targets.

const IO_IDLE: u8 = 0;
const IO_ISSUE: u8 = 1;
const IO_WAIT: u8 = 2;
const IO_DONE: u8 = 3;

/// The lower request in flight: `blocks` from `lba`, split to the source's
/// per-request limit, one piece at a time.
#[derive(Clone, Copy)]
#[repr(C)]
struct LowerIo {
    op: u8,
    state: u8,
    _pad: [u8; 2],
    status: i32,
    lba: u64,
    blocks: u64,
    /// Blocks already complete, and the blocks of the piece in flight.
    done: u64,
    chunk: u64,
    buf: usize,
    /// The piece in flight's tag; asking again reuses it.
    tag: u64,
}

unsafe fn io_start(s: &mut CryptState, op: u8, lba: u64, blocks: u64, buf: *mut u8) -> Act {
    s.io.op = op;
    s.io.lba = lba;
    s.io.blocks = blocks;
    s.io.done = 0;
    s.io.chunk = 0;
    s.io.buf = buf as usize;
    s.io.status = 0;
    s.io.tag = s.io.tag.wrapping_add(1);
    // A source with no volatile cache has nothing to flush: every write it
    // completed is already durable.
    let nothing = if op == blk::op::FLUSH {
        s.lower.flags() & blk::caps::F_FLUSH == 0
    } else {
        blocks == 0
    };
    s.io.state = if nothing { IO_DONE } else { IO_ISSUE };
    Act::Io
}

unsafe fn io_rw(s: &mut CryptState, write: bool, lba: u64, blocks: u64, buf: *mut u8) -> Act {
    let op = if write { blk::op::WRITE } else { blk::op::READ };
    io_start(s, op, lba, blocks, buf)
}

unsafe fn io_flush(s: &mut CryptState) -> Act {
    io_start(s, blk::op::FLUSH, 0, 0, core::ptr::null_mut())
}

/// Keep the fence of the lower completion that makes data durable: a
/// flush's, or on a source with no volatile cache, a write's. It is passed
/// up as it came, never strengthened; one that does not decode is dropped.
fn record_fence(s: &mut CryptState, c: &Cpl) {
    s.lower_fence_len = 0;
    if let Some((f, _)) = Fence::decode(c.fence_bytes()) {
        if let Some(n) = f.encode(&mut s.lower_fence) {
            s.lower_fence_len = n as u16;
        }
    }
}

/// A piece finished with `status`.
fn io_complete(s: &mut CryptState, status: i32, c: &Cpl) {
    if status == E_AGAIN {
        s.io.state = IO_ISSUE;
        return;
    }
    if status != 0 {
        s.io.status = status;
        s.io.state = IO_DONE;
        return;
    }
    let flush = s.io.op == blk::op::FLUSH;
    if flush || (s.io.op == blk::op::WRITE && s.lower.flags() & blk::caps::F_FLUSH == 0) {
        record_fence(s, c);
    }
    s.io.done += s.io.chunk;
    if flush || s.io.done >= s.io.blocks {
        s.io.state = IO_DONE;
    } else {
        s.io.tag = s.io.tag.wrapping_add(1);
        s.io.state = IO_ISSUE;
    }
}

/// Send the next piece. False when the source cannot take it now.
unsafe fn io_issue(s: &mut CryptState) -> bool {
    let lbs = u64::from(s.lower.block_size());
    let max = u64::from(s.lower.max_blocks().max(1));
    let n = if s.io.op == blk::op::FLUSH {
        0
    } else {
        (s.io.blocks - s.io.done).min(max)
    };
    s.io.chunk = n;
    let r = Req {
        op: s.io.op,
        flags: 0,
        nblocks: n as u32,
        lba: if n == 0 { 0 } else { s.io.lba + s.io.done },
        buf_ptr: if n == 0 {
            0
        } else {
            s.io.buf as u64 + s.io.done * lbs
        },
        buf_len: (n * lbs) as u32,
        tag: s.io.tag,
    };
    let mut b = [0u8; blk::req::LEN + blk::cpl::LEN];
    r.encode(&mut b);
    let sys = &*s.syscalls;
    if s.lower.flags() & blk::caps::F_ASYNC != 0 {
        let rc = dev_channel_ioctl(
            sys,
            s.lower.chan,
            blk::ioctl::SUBMIT,
            b.as_mut_ptr(),
            blk::req::LEN,
        );
        match rc {
            0 => s.io.state = IO_WAIT,
            E_AGAIN => return false,
            _ => {
                s.io.status = rc;
                s.io.state = IO_DONE;
            }
        }
        return true;
    }
    let rc = dev_channel_ioctl(sys, s.lower.chan, blk::ioctl::EXEC, b.as_mut_ptr(), b.len());
    if rc == E_AGAIN {
        return false;
    }
    let c = Cpl::decode(&b[blk::req::LEN..]).unwrap_or(Cpl::bare(r.tag, E_IO));
    io_complete(s, rc, &c);
    true
}

/// Drive the request in flight. True once it is done; false while it waits
/// on the source or the pump's budget is spent.
unsafe fn io_advance(s: &mut CryptState, work: &mut u32) -> bool {
    loop {
        match s.io.state {
            IO_ISSUE => {
                if *work >= STEP_BUDGET {
                    return false;
                }
                *work += 1;
                if !io_issue(s) {
                    return false;
                }
            }
            IO_WAIT => {
                if *work >= STEP_BUDGET {
                    return false;
                }
                *work += 1;
                let mut cb = [0u8; blk::cpl::LEN];
                let sys = &*s.syscalls;
                let rc = dev_channel_ioctl(
                    sys,
                    s.lower.chan,
                    blk::ioctl::REAP,
                    cb.as_mut_ptr(),
                    cb.len(),
                );
                if rc == 0 {
                    return false;
                }
                let decoded = if rc == 1 { Cpl::decode(&cb) } else { None };
                let Some(c) = decoded else {
                    s.io.status = if rc < 0 { rc } else { E_IO };
                    s.io.state = IO_DONE;
                    continue;
                };
                if c.tag != s.io.tag {
                    continue;
                }
                io_complete(s, c.status, &c);
                if s.io.state == IO_ISSUE && c.status == E_AGAIN {
                    return false;
                }
            }
            _ => return true,
        }
    }
}

// ── Resumable operations ────────────────────────────────────────────────
//
// Each operation on the container is a frame with a resume point. A frame
// runs until it starts a lower request, calls a nested operation, finishes,
// or — an upper EXEC's request only — needs the caller's buffer outside the
// caller's call. The pump runs the top frame, feeds it each lower result and
// each nested result, and stops when the lower source has nothing ready or
// the step's budget is spent. The next pump resumes exactly there: nothing
// is redone, so a mount that waits on its source never restarts.
//
// One operation runs at a time. Upper requests, the mount and a rotation
// phase never interleave: each sees the container as the one before it left
// it, so the journal, nonce and superblock rules hold per operation.

const K_READ_META: u8 = 1;
const K_WRITE_META: u8 = 2;
const K_CURRENT_META: u8 = 3;
const K_COMMIT_SB: u8 = 4;
const K_TAKE_SEQ: u8 = 5;
const K_READ_UNIT: u8 = 6;
const K_WRITE_UNIT: u8 = 7;
const K_JOURNAL_CYCLE: u8 = 8;
const K_RECOVER: u8 = 9;
const K_ZERO: u8 = 10;
const K_FORMAT: u8 = 11;
const K_MOUNT: u8 = 12;
const K_ROT_PREPARE: u8 = 13;
const K_ROT_ACTIVATE: u8 = 14;
const K_ROT_MIGRATE: u8 = 15;
const K_ROT_RETIRE: u8 = 16;
const K_ERASE: u8 = 17;
const K_REQUEST: u8 = 18;

/// What runs on the engine.
const JOB_NONE: u8 = 0;
const JOB_MOUNT: u8 = 1;
const JOB_REQUEST: u8 = 2;
const JOB_EXEC: u8 = 3;
/// A rotation phase or a control record's work.
const JOB_BACKGROUND: u8 = 4;

/// Where a crypto-erase is: none asked for, under way, finished.
const ERASE_NONE: u8 = 0;
const ERASE_RUNNING: u8 = 1;
const ERASE_DONE: u8 = 2;

/// The upper `EXEC` request's slot.
const EXEC_FREE: u8 = 0;
const EXEC_WAITING: u8 = 1;
const EXEC_RUNNING: u8 = 2;
const EXEC_DONE: u8 = 3;
/// `Frame::flag` of a request frame serving the EXEC slot.
const EXEC_SLOT: u8 = 0xFF;

/// One operation in progress: its kind, where it resumes, the result of
/// the last lower request or nested operation, and its locals.
#[derive(Clone, Copy)]
#[repr(C)]
struct Frame {
    kind: u8,
    pc: u8,
    flag: u8,
    _pad: u8,
    rc: i32,
    a: u64,
    b: u64,
    c: u64,
    meta: Meta,
}

impl Frame {
    fn new(kind: u8, a: u64, flag: u8) -> Frame {
        Frame {
            kind,
            pc: 0,
            flag,
            _pad: 0,
            rc: 0,
            a,
            b: 0,
            c: 0,
            meta: Meta::default(),
        }
    }
}

enum Act {
    /// A lower request started; its status arrives in `rc`.
    Io,
    /// Run this operation; its result arrives in `rc`.
    Call(Frame),
    Done(i32),
    /// An upper EXEC's request needs the caller's buffer: it waits for the
    /// caller to ask again.
    Park,
}

/// A queued upper `SUBMIT`.
#[derive(Clone, Copy)]
#[repr(C)]
struct Upper {
    req: Req,
    /// Arrival order: the oldest queued request runs first.
    seq: u64,
    used: u8,
    started: u8,
    _pad: [u8; 6],
}

fn push_frame(s: &mut CryptState, f: Frame) -> bool {
    let d = s.depth as usize;
    if d >= MAX_FRAMES {
        return false;
    }
    s.frames[d] = f;
    s.depth += 1;
    true
}

/// Run the engine as far as it goes now.
unsafe fn pump(s: &mut CryptState) {
    let mut work = 0u32;
    loop {
        if s.io.state != IO_IDLE {
            if !io_advance(s, &mut work) {
                return;
            }
            let rc = s.io.status;
            s.io.state = IO_IDLE;
            if s.depth > 0 {
                s.frames[s.depth as usize - 1].rc = rc;
            }
        }
        if s.depth == 0 && !start_next(s) {
            return;
        }
        if work >= STEP_BUDGET {
            return;
        }
        work += 1;
        let top = s.depth as usize - 1;
        let mut f = s.frames[top];
        s.parked = 0;
        match run_frame(s, &mut f) {
            Act::Io => s.frames[top] = f,
            Act::Call(child) => {
                s.frames[top] = f;
                if !push_frame(s, child) {
                    s.frames[top].rc = E_IO;
                }
            }
            Act::Done(rc) => {
                s.depth -= 1;
                if s.depth > 0 {
                    s.frames[s.depth as usize - 1].rc = rc;
                } else {
                    job_done(s, rc);
                }
            }
            Act::Park => {
                s.frames[top] = f;
                s.parked = 1;
                return;
            }
        }
    }
}

/// Start the next upper request: the EXEC slot's first, then the oldest
/// queued SUBMIT. Background work is started only by the module step.
fn start_next(s: &mut CryptState) -> bool {
    if s.phase == PHASE_OPENING {
        return false;
    }
    if s.exec_state == EXEC_WAITING && push_frame(s, Frame::new(K_REQUEST, 0, EXEC_SLOT)) {
        s.exec_state = EXEC_RUNNING;
        s.job = JOB_EXEC;
        return true;
    }
    let mut pick = QUEUE_DEPTH;
    for i in 0..QUEUE_DEPTH {
        let q = &s.reqs[i];
        if q.used != 0 && q.started == 0 && (pick == QUEUE_DEPTH || q.seq < s.reqs[pick].seq) {
            pick = i;
        }
    }
    if pick < QUEUE_DEPTH && push_frame(s, Frame::new(K_REQUEST, 0, pick as u8)) {
        s.reqs[pick].started = 1;
        s.job = JOB_REQUEST;
        return true;
    }
    false
}

/// Start background work now: nothing else may be running.
fn start_background(s: &mut CryptState, kind: u8) {
    if push_frame(s, Frame::new(kind, 0, 0)) {
        s.job = JOB_BACKGROUND;
        s.bg_kind = kind;
        if kind == K_ERASE {
            s.erase_state = ERASE_RUNNING;
        }
    }
}

fn upper_waiting(s: &CryptState) -> bool {
    s.exec_state == EXEC_WAITING || s.reqs.iter().any(|q| q.used != 0 && q.started == 0)
}

unsafe fn job_done(s: &mut CryptState, rc: i32) {
    match s.job {
        JOB_MOUNT => {
            s.mount_rc = rc;
            s.mount_done = 1;
        }
        JOB_BACKGROUND => {
            note_background(s, rc);
            s.bg_err = rc;
            if s.bg_kind == K_ERASE {
                s.erase_state = ERASE_DONE;
                s.erase_rc = rc;
            }
        }
        _ => {}
    }
    s.job = JOB_NONE;
    s.parked = 0;
}

/// A background step's result, logged when it changes. A failed rotation
/// step leaves the rotation where it was; the next step tries it again.
unsafe fn note_background(s: &mut CryptState, rc: i32) {
    if rc != s.rotate_err {
        s.rotate_err = rc;
        if rc != 0 {
            dev_log(
                s.sys(),
                1,
                b"[crypt_block] rotation step failed".as_ptr(),
                34,
            );
        }
    }
}

/// Drop an EXEC request its caller has given up on. Only one that owns no
/// lower request: waiting to start, parked for its buffer, or finished.
fn abandon_exec(s: &mut CryptState) {
    if s.job == JOB_EXEC && s.depth > 0 {
        s.depth = 0;
        s.job = JOB_NONE;
        s.parked = 0;
        s.plain.fill(0);
    }
    s.exec_state = EXEC_FREE;
}

unsafe fn run_frame(s: &mut CryptState, f: &mut Frame) -> Act {
    match f.kind {
        K_READ_META => run_read_meta(s, f),
        K_WRITE_META => run_write_meta(s, f),
        K_CURRENT_META => run_current_meta(s, f),
        K_COMMIT_SB => run_commit_sb(s, f),
        K_TAKE_SEQ => run_take_seq(s, f),
        K_READ_UNIT => run_read_unit(s, f),
        K_WRITE_UNIT => run_write_unit(s, f),
        K_JOURNAL_CYCLE => run_journal_cycle(s, f),
        K_RECOVER => run_recover(s, f),
        K_ZERO => run_zero(s, f),
        K_FORMAT => run_format(s, f),
        K_MOUNT => run_mount(s, f),
        K_ROT_PREPARE => run_rot_prepare(s, f),
        K_ROT_ACTIVATE => run_rot_activate(s, f),
        K_ROT_MIGRATE => run_rot_migrate(s, f),
        K_ROT_RETIRE => run_rot_retire(s, f),
        K_ERASE => run_erase(s, f),
        K_REQUEST => run_request(s, f),
        _ => Act::Done(E_INVAL),
    }
}

// ── Metadata and superblocks ────────────────────────────────────────────

/// Unit `a`'s home metadata into `ret_meta`.
unsafe fn run_read_meta(s: &mut CryptState, f: &mut Frame) -> Act {
    let (lba, off) = s.layout.meta_location(f.a);
    if f.pc == 0 {
        f.pc = 1;
        let p = s.meta_block.as_mut_ptr();
        return io_rw(s, false, lba, 1, p);
    }
    if f.rc != 0 {
        return Act::Done(f.rc);
    }
    s.ret_meta = Meta::decode(&s.meta_block[off..off + META_LEN]);
    Act::Done(0)
}

/// Write `meta` as unit `a`'s home metadata: read, modify, write its block.
unsafe fn run_write_meta(s: &mut CryptState, f: &mut Frame) -> Act {
    let (lba, off) = s.layout.meta_location(f.a);
    let p = s.meta_block.as_mut_ptr();
    match f.pc {
        0 => {
            f.pc = 1;
            io_rw(s, false, lba, 1, p)
        }
        1 => {
            if f.rc != 0 {
                return Act::Done(f.rc);
            }
            f.meta.encode(&mut s.meta_block[off..off + META_LEN]);
            f.pc = 2;
            io_rw(s, true, lba, 1, p)
        }
        _ => Act::Done(f.rc),
    }
}

/// The newest metadata for unit `a` into `ret_meta`: its pending journal
/// record (`ret_slot` names the slot), or its home (`ret_slot` is -1).
unsafe fn run_current_meta(s: &mut CryptState, f: &mut Frame) -> Act {
    if f.pc == 0 {
        for p in s.pending.iter() {
            if p.live && p.unit == f.a {
                s.ret_meta = p.meta;
                s.ret_slot = i32::from(p.slot);
                return Act::Done(0);
            }
        }
        f.pc = 1;
        return Act::Call(Frame::new(K_READ_META, f.a, 0));
    }
    s.ret_slot = -1;
    Act::Done(f.rc)
}

/// Write the next superblock generation to the other slot and flush it.
/// Memory takes the new generation only once it is durable.
unsafe fn run_commit_sb(s: &mut CryptState, f: &mut Frame) -> Act {
    match f.pc {
        0 => {
            let mut sb = s.sb;
            sb.generation += 1;
            let mut body = [0u8; SB_MAC_OFF];
            sb.encode_body(&mut body);
            let Some(mac) = superblock_mac(s, &sb.volume_id, &body) else {
                return Act::Done(E_IO);
            };
            let lbs = s.lower.block_size() as usize;
            s.header[..lbs].fill(0);
            s.header[..SB_MAC_OFF].copy_from_slice(&body);
            s.header[SB_MAC_OFF..SB_LEN].copy_from_slice(&mac);
            s.commit_sb = sb;
            let target = 1 - s.sb_slot;
            f.b = u64::from(target);
            f.pc = 1;
            let p = s.header.as_mut_ptr();
            let lba = u64::from(target) * s.layout.blocks_per_unit;
            io_rw(s, true, lba, 1, p)
        }
        1 => {
            if f.rc != 0 {
                return Act::Done(f.rc);
            }
            f.pc = 2;
            io_flush(s)
        }
        _ => {
            if f.rc != 0 {
                return Act::Done(f.rc);
            }
            s.sb = s.commit_sb;
            s.sb_slot = f.b as u8;
            Act::Done(0)
        }
    }
}

/// The next nonce sequence into `ret_seq`, reserving a new range first
/// when the current one is spent. A sequence is never issued before its
/// range is durable, and never wraps.
unsafe fn run_take_seq(s: &mut CryptState, f: &mut Frame) -> Act {
    if f.pc == 0 && s.next_seq >= s.sb.reserved_seq {
        let Some(next) = s.sb.reserved_seq.checked_add(NONCE_STRIDE) else {
            return Act::Done(E_IO);
        };
        // `b` keeps the durable bound: a commit that fails leaves memory
        // naming it again, so no later call issues from a range that is not
        // on the device.
        f.b = s.sb.reserved_seq;
        s.sb.reserved_seq = next;
        f.pc = 1;
        return Act::Call(Frame::new(K_COMMIT_SB, 0, 0));
    }
    if f.pc == 1 && f.rc != 0 {
        s.sb.reserved_seq = f.b;
        return Act::Done(f.rc);
    }
    s.ret_seq = s.next_seq;
    s.next_seq += 1;
    Act::Done(0)
}

// ── Units ───────────────────────────────────────────────────────────────

/// Decrypt unit `a` into `plain`.
unsafe fn run_read_unit(s: &mut CryptState, f: &mut Frame) -> Act {
    let unit = s.unit();
    match f.pc {
        0 => {
            f.pc = 1;
            Act::Call(Frame::new(K_CURRENT_META, f.a, 0))
        }
        1 => {
            if f.rc != 0 {
                return Act::Done(f.rc);
            }
            let meta = s.ret_meta;
            if meta.generation == 0 || meta.flags & FLAG_DISCARDED != 0 {
                s.plain[..unit].fill(0);
                return Act::Done(0);
            }
            f.meta = meta;
            let lba = if s.ret_slot >= 0 {
                s.layout.journal_block(s.ret_slot as u64) + s.layout.blocks_per_unit
            } else {
                s.layout.data_block(f.a)
            };
            f.pc = 2;
            let p = s.plain.as_mut_ptr();
            io_rw(s, false, lba, s.layout.blocks_per_unit, p)
        }
        _ => {
            if f.rc != 0 {
                return Act::Done(f.rc);
            }
            let meta = f.meta;
            let aad = unit_aad(&s.sb.volume_id, f.a, s.sb.unit_size, &meta, 0);
            let mut tag = meta.tag;
            let Some(key) = key_for_epoch(s, meta.epoch) else {
                s.plain[..unit].fill(0);
                return Act::Done(E_IO);
            };
            let sealed = SealedUnit {
                nonce: &meta.nonce,
                aad: &aad,
                data: s.plain.as_mut_ptr(),
                len: unit,
                tag: tag.as_mut_ptr(),
            };
            Act::Done(vault_unit(s, key, false, &sealed))
        }
    }
}

/// Seal `plain` as unit `a`'s next generation (or, with `flag`, a discard)
/// and append it to the journal.
unsafe fn run_write_unit(s: &mut CryptState, f: &mut Frame) -> Act {
    let discard = f.flag != 0;
    let bpu = s.layout.blocks_per_unit;
    loop {
        match f.pc {
            0 => {
                f.pc = 1;
                if s.journal_head as usize >= s.sb.journal_units as usize / 2 {
                    return Act::Call(Frame::new(K_JOURNAL_CYCLE, 0, 0));
                }
                f.rc = 0;
            }
            1 => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                f.pc = 2;
                return Act::Call(Frame::new(K_CURRENT_META, f.a, 0));
            }
            2 => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                f.b = s.ret_meta.generation;
                f.pc = 3;
                return Act::Call(Frame::new(K_TAKE_SEQ, 0, 0));
            }
            3 => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                let mut meta = Meta {
                    generation: f.b + 1,
                    epoch: s.sb.epoch,
                    flags: if discard { FLAG_DISCARDED } else { 0 },
                    nonce: unit_nonce(s.sb.prefix, s.ret_seq),
                    tag: [0; 16],
                };
                let unit = s.unit();
                let aad = unit_aad(&s.sb.volume_id, f.a, s.sb.unit_size, &meta, 0);
                let len = if discard { 0 } else { unit };
                if !discard {
                    s.cipher[..unit].copy_from_slice(&s.plain[..unit]);
                }
                let sealed = SealedUnit {
                    nonce: &meta.nonce,
                    aad: &aad,
                    data: s.cipher.as_mut_ptr(),
                    len,
                    tag: meta.tag.as_mut_ptr(),
                };
                let rc = vault_unit(s, s.data_key, true, &sealed);
                if rc != 0 {
                    return Act::Done(rc);
                }
                // Journal record: header unit, then the ciphertext unit.
                f.c = u64::from(s.journal_head);
                s.header[..unit].fill(0);
                s.header[0..4].copy_from_slice(&JOURNAL_MAGIC);
                s.header[8..16].copy_from_slice(&s.journal_seq.to_le_bytes());
                s.header[16..24].copy_from_slice(&f.a.to_le_bytes());
                meta.encode(&mut s.header[24..24 + META_LEN]);
                f.meta = meta;
                f.pc = 4;
                let p = s.header.as_mut_ptr();
                return io_rw(s, true, s.layout.journal_block(f.c), bpu, p);
            }
            4 => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                f.pc = 5;
                if !discard {
                    let slot = f.c as usize;
                    if slot < JOURNAL_CACHE {
                        let unit = s.unit();
                        s.jcache[slot][..unit].copy_from_slice(&s.cipher[..unit]);
                    }
                    let p = s.cipher.as_mut_ptr();
                    return io_rw(s, true, s.layout.journal_block(f.c) + bpu, bpu, p);
                }
                f.rc = 0;
            }
            _ => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                s.journal_seq += 1;
                s.journal_head += 1;
                if !discard && (f.c as usize) < JOURNAL_CACHE {
                    s.jcache_held |= 1u64 << f.c;
                }
                for p in s.pending.iter_mut() {
                    if p.live && p.unit == f.a {
                        p.live = false;
                    }
                }
                if let Some(p) = s.pending.iter_mut().find(|p| !p.live) {
                    *p = Pending {
                        unit: f.a,
                        meta: f.meta,
                        slot: f.c as u16,
                        live: true,
                        _pad: [0; 5],
                    };
                }
                return Act::Done(0);
            }
        }
    }
}

/// Make every journal record durable and home: flush, write the pending
/// homes, flush again, and restart the ring. The last flush's fence is the
/// one the records are durable under.
unsafe fn run_journal_cycle(s: &mut CryptState, f: &mut Frame) -> Act {
    let bpu = s.layout.blocks_per_unit;
    loop {
        let i = f.a as usize;
        let p = s.pending.get(i).copied().unwrap_or(Pending::EMPTY);
        match f.pc {
            0 => {
                f.pc = 1;
                return io_flush(s);
            }
            1 => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                f.a = 0;
                f.pc = 2;
            }
            2 => {
                if i >= MAX_JOURNAL_RECORDS {
                    f.pc = 6;
                    return io_flush(s);
                }
                if !p.live {
                    f.a += 1;
                    continue;
                }
                if p.meta.flags & FLAG_DISCARDED == 0 {
                    let slot = p.slot as usize;
                    if slot < JOURNAL_CACHE && s.jcache_held & (1u64 << slot) != 0 {
                        // Written this ring, still in hand: straight home.
                        let unit = s.unit();
                        s.cipher[..unit].copy_from_slice(&s.jcache[slot][..unit]);
                        f.pc = 4;
                        let buf = s.cipher.as_mut_ptr();
                        return io_rw(s, true, s.layout.data_block(p.unit), bpu, buf);
                    }
                    f.pc = 3;
                    let buf = s.cipher.as_mut_ptr();
                    let src = s.layout.journal_block(u64::from(p.slot)) + bpu;
                    return io_rw(s, false, src, bpu, buf);
                }
                f.pc = 5;
                let mut w = Frame::new(K_WRITE_META, p.unit, 0);
                w.meta = p.meta;
                return Act::Call(w);
            }
            3 => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                f.pc = 4;
                let buf = s.cipher.as_mut_ptr();
                return io_rw(s, true, s.layout.data_block(p.unit), bpu, buf);
            }
            4 => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                f.pc = 5;
                let mut w = Frame::new(K_WRITE_META, p.unit, 0);
                w.meta = p.meta;
                return Act::Call(w);
            }
            5 => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                f.a += 1;
                f.pc = 2;
            }
            _ => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                for p in s.pending.iter_mut() {
                    p.live = false;
                }
                s.journal_head = 0;
                s.jcache_held = 0;
                return Act::Done(0);
            }
        }
    }
}

/// Replay the journal after a restart: every record that opens and is
/// newer than its unit's home is written home. `a` is the slot, `b` the
/// record's unit, `flag` whether any record was applied.
unsafe fn run_recover(s: &mut CryptState, f: &mut Frame) -> Act {
    let bpu = s.layout.blocks_per_unit;
    let unit = s.unit();
    let records = u64::from(s.sb.journal_units / 2);
    loop {
        let hdr = s.layout.journal_block(f.a);
        let discard = f.meta.flags & FLAG_DISCARDED != 0;
        match f.pc {
            0 => {
                if f.a >= records {
                    f.pc = 7;
                    continue;
                }
                f.pc = 1;
                let p = s.header.as_mut_ptr();
                return io_rw(s, false, hdr, bpu, p);
            }
            1 => {
                f.pc = 0;
                if f.rc != 0 || s.header[0..4] != JOURNAL_MAGIC {
                    f.a += 1;
                    continue;
                }
                let mut idx = [0u8; 8];
                idx.copy_from_slice(&s.header[16..24]);
                let u = u64::from_le_bytes(idx);
                let mut jseq = [0u8; 8];
                jseq.copy_from_slice(&s.header[8..16]);
                let seq = u64::from_le_bytes(jseq);
                if seq >= s.journal_seq {
                    s.journal_seq = seq + 1;
                }
                if u >= s.sb.data_units {
                    f.a += 1;
                    continue;
                }
                f.meta = Meta::decode(&s.header[24..24 + META_LEN]);
                f.b = u;
                f.pc = 2;
                return Act::Call(Frame::new(K_READ_META, u, 0));
            }
            2 => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                if f.meta.generation <= s.ret_meta.generation {
                    f.a += 1;
                    f.pc = 0;
                    continue;
                }
                f.pc = 3;
                if !discard {
                    let p = s.cipher.as_mut_ptr();
                    return io_rw(s, false, hdr + bpu, bpu, p);
                }
                f.rc = 0;
            }
            3 => {
                if f.rc != 0 {
                    f.a += 1;
                    f.pc = 0;
                    continue;
                }
                // Opening proves the record whole and genuine; the
                // plaintext is discarded, the ciphertext goes home as it is.
                let meta = f.meta;
                let len = if discard { 0 } else { unit };
                s.plain[..len].copy_from_slice(&s.cipher[..len]);
                let aad = unit_aad(&s.sb.volume_id, f.b, s.sb.unit_size, &meta, 0);
                let mut tag = meta.tag;
                let opened = match key_for_epoch(s, meta.epoch) {
                    Some(key) => {
                        let sealed = SealedUnit {
                            nonce: &meta.nonce,
                            aad: &aad,
                            data: s.plain.as_mut_ptr(),
                            len,
                            tag: tag.as_mut_ptr(),
                        };
                        vault_unit(s, key, false, &sealed) == 0
                    }
                    None => false,
                };
                if !opened {
                    f.a += 1;
                    f.pc = 0;
                    continue;
                }
                f.pc = 4;
                if !discard {
                    let p = s.cipher.as_mut_ptr();
                    return io_rw(s, true, s.layout.data_block(f.b), bpu, p);
                }
                f.rc = 0;
            }
            4 => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                f.pc = 5;
                let mut w = Frame::new(K_WRITE_META, f.b, 0);
                w.meta = f.meta;
                return Act::Call(w);
            }
            5 => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                f.flag = 1;
                f.a += 1;
                f.pc = 0;
            }
            7 => {
                s.plain[..unit].fill(0);
                f.pc = 8;
                if f.flag != 0 {
                    return io_flush(s);
                }
                f.rc = 0;
            }
            _ => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                s.journal_head = 0;
                s.jcache_held = 0;
                return Act::Done(0);
            }
        }
    }
}

// ── Mount and format ────────────────────────────────────────────────────

/// Write zeros over `b` lower blocks from `a`, a unit at a time; `c` is
/// how far it has got.
unsafe fn run_zero(s: &mut CryptState, f: &mut Frame) -> Act {
    let bpu = s.layout.blocks_per_unit.max(1);
    loop {
        match f.pc {
            0 => {
                s.cipher.fill(0);
                f.c = 0;
                f.pc = 1;
            }
            1 => {
                if f.c >= f.b {
                    return Act::Done(0);
                }
                f.pc = 2;
                let n = (f.b - f.c).min(bpu);
                let p = s.cipher.as_mut_ptr();
                return io_rw(s, true, f.a + f.c, n, p);
            }
            _ => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                f.c += (f.b - f.c).min(bpu);
                f.pc = 1;
            }
        }
    }
}

fn zero_frame(lba: u64, blocks: u64) -> Frame {
    let mut z = Frame::new(K_ZERO, lba, 0);
    z.b = blocks;
    z
}

/// Lay a fresh container over the lower device.
unsafe fn run_format(s: &mut CryptState, f: &mut Frame) -> Act {
    match f.pc {
        0 => {
            let lbs = s.lower.block_size();
            let unit = s.unit_param;
            let journal = s.journal_param;
            let units = Layout::data_units_for(unit, lbs, journal, s.lower.block_count());
            if units == 0 {
                return Act::Done(E_INVAL);
            }
            let mut sb = Superblock {
                generation: 0,
                unit_size: unit,
                lower_block: lbs,
                journal_units: journal,
                data_units: units,
                epoch: 1,
                suite: SUITE_CHACHA,
                reserved_seq: NONCE_STRIDE,
                ..Superblock::default()
            };
            let mut rnd = [0u8; 20];
            if dev_csprng_fill(s.sys(), rnd.as_mut_ptr(), rnd.len()) != 0 {
                return Act::Done(E_IO);
            }
            if s.attach == 1 {
                // The grant names the volume and its epoch; the container is
                // theirs.
                sb.volume_id = s.attach_resource;
                sb.epoch = s.attach_epoch.max(1);
            } else {
                sb.volume_id.copy_from_slice(&rnd[..16]);
            }
            sb.prefix = u32::from_le_bytes([rnd[16], rnd[17], rnd[18], rnd[19]]);
            // AES-256-GCM where the vault offers it (constant-time AES),
            // otherwise ChaCha20-Poly1305. Fixed at format.
            let mut q = [0u8; 14];
            q[0..2].copy_from_slice(&kv::suite::AEAD_AES256_GCM.to_le_bytes());
            if (s.sys().provider_call)(-1, kv::SUITE_QUERY, q.as_mut_ptr(), q.len()) >= 0 {
                sb.suite = SUITE_AES;
            }
            s.sb = sb;
            s.layout = Layout::of(unit, lbs, journal, units);
            let jstart = s.layout.journal_start;
            f.pc = 1;
            Act::Call(zero_frame(jstart, s.layout.data_start - jstart))
        }
        1 => {
            if f.rc != 0 {
                return Act::Done(f.rc);
            }
            // Both slots: A at generation 1 below, B cleared so it never
            // outvotes.
            s.sb_slot = 1;
            f.pc = 2;
            let bpu = s.layout.blocks_per_unit;
            Act::Call(zero_frame(bpu, bpu))
        }
        2 => {
            if f.rc != 0 {
                return Act::Done(f.rc);
            }
            f.pc = 3;
            Act::Call(Frame::new(K_COMMIT_SB, 0, 0))
        }
        _ => Act::Done(f.rc),
    }
}

/// Read superblock slot `slot` into `header`, unverified. `None` when the
/// lower block cannot hold one: the slot then reads as empty.
unsafe fn sb_read(s: &mut CryptState, slot: u8) -> Option<Act> {
    let lbs = s.lower.block_size() as usize;
    if !(SB_LEN..=MAX_UNIT).contains(&lbs) {
        return None;
    }
    let bpu = div(u64::from(s.unit_param), u64::from(s.lower.block_size())).max(1);
    let p = s.header.as_mut_ptr();
    Some(io_rw(s, false, u64::from(slot) * bpu, 1, p))
}

/// The superblock `header` holds, when the read that filled it succeeded:
/// the parsed body, the body's bytes and the stored MAC. Nothing here is
/// trusted until the MAC checks.
fn sb_parse(s: &CryptState, rc: i32) -> Option<(Superblock, [u8; SB_MAC_OFF], [u8; 32])> {
    if rc != 0 {
        return None;
    }
    let mut body = [0u8; SB_MAC_OFF];
    body.copy_from_slice(&s.header[..SB_MAC_OFF]);
    let mut stored = [0u8; 32];
    stored.copy_from_slice(&s.header[SB_MAC_OFF..SB_LEN]);
    let sb = Superblock::decode_body(&body)?;
    Some((sb, body, stored))
}

/// As `sb_parse`, and verified under the current master.
unsafe fn sb_verified(s: &CryptState, rc: i32) -> Option<Superblock> {
    let (sb, body, stored) = sb_parse(s, rc)?;
    let mac = superblock_mac(s, &sb.volume_id, &body)?;
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= mac[i] ^ stored[i];
    }
    if diff != 0 {
        return None;
    }
    Some(sb)
}

/// Read one superblock slot, or go straight on to `next` with nothing read.
unsafe fn sb_read_or_skip(s: &mut CryptState, f: &mut Frame, slot: u8, next: u8) -> Option<Act> {
    f.pc = next;
    match sb_read(s, slot) {
        Some(act) => Some(act),
        None => {
            f.rc = E_IO;
            None
        }
    }
}

/// The newer of slot A (kept in `sb_a`) and slot B, by unverified fields.
fn newest_of(s: &CryptState, b: Option<Superblock>) -> Option<Superblock> {
    let a = if s.sb_a_ok != 0 { Some(s.sb_a) } else { None };
    match (a, b) {
        (Some(x), Some(y)) if y.generation > x.generation => Some(y),
        (Some(x), _) => Some(x),
        (None, y) => y,
    }
}

fn keep_a(s: &mut CryptState, a: Option<Superblock>) {
    s.sb_a_ok = u8::from(a.is_some());
    s.sb_a = a.unwrap_or_default();
}

/// Mount: find the master, verify the newest superblock (or format), open
/// the data keys, reserve a fresh nonce range in one committed generation,
/// then replay the journal. Only the wait for the lower source to attach and
/// the waits for attachment bundles answer `EAGAIN` and start again; all
/// come before anything is written. Everything after resumes where it waited.
///
/// An attached volume under a rotation needs two bundles: one for the epoch
/// its superblock names and one for the other epoch the rotation holds (the
/// next while prepared, the previous after). Each is announced a recipient
/// of its own, one after the other, and taken in whichever order it comes.
unsafe fn run_mount(s: &mut CryptState, f: &mut Frame) -> Act {
    const ATTACH: u8 = 10;
    const LOCAL: u8 = 20;
    const VERIFY: u8 = 30;
    const KEYS: u8 = 40;
    loop {
        match f.pc {
            0 => {
                let rc = s.lower.caps(s.sys());
                if rc != 0 {
                    return Act::Done(rc);
                }
                let lbs = s.lower.block_size();
                let unit = s.unit_param;
                if (s.key_len == 0 && s.attach == 0)
                    || !(512..=MAX_UNIT as u32).contains(&unit)
                    || !unit.is_power_of_two()
                    || lbs as usize > MAX_LOWER_BLOCK
                    || lbs > unit
                    || s.upper_block < 512
                    || !s.upper_block.is_power_of_two()
                    || s.upper_block > unit
                    || s.journal_param < 2
                    || !s.journal_param.is_multiple_of(2)
                    || s.journal_param as usize / 2 > MAX_JOURNAL_RECORDS
                    || s.lower.flags() & blk::caps::F_WRITE == 0
                {
                    return Act::Done(E_INVAL);
                }
                f.pc = if s.attach == 1 && attach_wanting(s) {
                    ATTACH
                } else if s.master >= 0 {
                    VERIFY
                } else {
                    LOCAL
                };
            }
            ATTACH => {
                // Bound to this container: the volume id and epoch its
                // superblock names, read here unverified — before the
                // bundle is awaited, so the status can name the epoch it
                // is awaited for — and verified with the key made. Nothing
                // is written while the mount waits, so they are read once.
                if s.attach_probed != 0 {
                    f.pc = ATTACH + 4;
                    continue;
                }
                if let Some(act) = sb_read_or_skip(s, f, 0, ATTACH + 1) {
                    return act;
                }
            }
            11 => {
                let a = sb_parse(s, f.rc).map(|x| x.0);
                keep_a(s, a);
                if let Some(act) = sb_read_or_skip(s, f, 1, ATTACH + 2) {
                    return act;
                }
            }
            12 => {
                let b = sb_parse(s, f.rc).map(|x| x.0);
                match newest_of(s, b) {
                    Some(sb) => {
                        s.attach_resource = sb.volume_id;
                        s.attach_epoch = sb.epoch;
                        s.need_other = other_epoch_of(&sb);
                        s.probe_sb = sb;
                        s.probe_blank = 0;
                    }
                    None => s.probe_blank = 1,
                }
                s.attach_probed = 1;
                f.pc = ATTACH + 4;
            }
            14 => {
                let rc = attach_gather(s);
                if rc != 0 {
                    return Act::Done(rc);
                }
                if s.bundle[..4] != BUNDLE_MAGIC || s.bundle[4] != 2 {
                    return Act::Done(attach_finish(s, E_INVAL));
                }
                if s.probe_blank != 0 && s.master < 0 {
                    let rc = attach_combine(s, None);
                    if rc != 0 {
                        return Act::Done(rc);
                    }
                    f.pc = VERIFY;
                    continue;
                }
                f.pc = ATTACH + 3;
            }
            13 => {
                // A bundle for an epoch this mount does not need is refused
                // and a fresh recipient announced; a bundle for one it needs
                // that does not open fails the mount.
                let rc = attach_take(s);
                if rc != 0 {
                    return Act::Done(rc);
                }
                if attach_wanting(s) {
                    return Act::Done(E_AGAIN);
                }
                f.pc = VERIFY;
            }
            LOCAL => {
                if let Some(act) = sb_read_or_skip(s, f, 0, LOCAL + 1) {
                    return act;
                }
            }
            21 => {
                let a = sb_parse(s, f.rc).map(|x| x.0);
                keep_a(s, a);
                if let Some(act) = sb_read_or_skip(s, f, 1, LOCAL + 2) {
                    return act;
                }
            }
            22 => {
                // The superblock names the epoch whose master verifies it.
                // A blank device is epoch 1, whose master is made only to
                // format.
                let b = sb_parse(s, f.rc).map(|x| x.0);
                let (epoch, create) = match newest_of(s, b) {
                    Some(sb) => (sb.epoch, false),
                    None => (1, s.format == 1),
                };
                s.probe_blank = u8::from(newest_of(s, b).is_none());
                let h = vault_open_epoch(s, epoch, create);
                if h < 0 {
                    return Act::Done(h);
                }
                s.master = h;
                f.pc = VERIFY;
            }
            VERIFY => {
                if let Some(act) = sb_read_or_skip(s, f, 0, VERIFY + 1) {
                    return act;
                }
            }
            31 => {
                let a = sb_verified(s, f.rc);
                keep_a(s, a);
                if let Some(act) = sb_read_or_skip(s, f, 1, VERIFY + 2) {
                    return act;
                }
            }
            32 => {
                let a = if s.sb_a_ok != 0 { Some(s.sb_a) } else { None };
                let b = sb_verified(s, f.rc);
                let chosen = match (a, b) {
                    (Some(x), Some(y)) if y.generation > x.generation => Some((y, 1)),
                    (Some(x), _) => Some((x, 0)),
                    (None, Some(y)) => Some((y, 1)),
                    (None, None) => None,
                };
                match chosen {
                    Some((sb, slot)) => {
                        if sb.lower_block != s.lower.block_size() || sb.unit_size != s.unit_param {
                            return Act::Done(E_INVAL);
                        }
                        s.sb = sb;
                        s.sb_slot = slot;
                        s.layout = Layout::of(
                            sb.unit_size,
                            sb.lower_block,
                            sb.journal_units,
                            sb.data_units,
                        );
                        if s.layout.total_blocks > s.lower.block_count() {
                            return Act::Done(E_INVAL);
                        }
                        f.pc = KEYS;
                    }
                    // Only a device with no superblock at all is formatted: one
                    // whose superblocks do not verify holds a container this
                    // key does not open, and is left as it is.
                    None if s.format == 1 && s.probe_blank != 0 => {
                        f.pc = 33;
                        return Act::Call(Frame::new(K_FORMAT, 0, 0));
                    }
                    None => return Act::Done(-19), // ENODEV: no container here
                }
            }
            33 => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                f.pc = KEYS;
            }
            KEYS => {
                // The other epoch's keys first: an attached volume whose
                // verified superblock needs one it does not hold yet goes
                // back to wait for its bundle, with nothing written.
                let rc = open_rotation_keys(s);
                if rc != 0 {
                    return Act::Done(rc);
                }
                let ctx = data_context(&s.sb.volume_id, s.sb.epoch);
                let k = vault_derive(
                    s,
                    data_suite(s),
                    kv::usage::SEAL | kv::usage::OPEN,
                    LABEL_DATA,
                    &ctx,
                );
                if k < 0 {
                    return Act::Done(k);
                }
                s.data_key = k;
                // Resume past everything the last run may have used, and
                // reserve anew.
                s.next_seq = s.sb.reserved_seq;
                s.sb.reserved_seq = s.next_seq.saturating_add(NONCE_STRIDE);
                f.pc = KEYS + 1;
                return Act::Call(Frame::new(K_COMMIT_SB, 0, 0));
            }
            41 => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                f.pc = KEYS + 2;
                return Act::Call(Frame::new(K_RECOVER, 0, 0));
            }
            _ => return Act::Done(f.rc),
        }
    }
}

// ── Attachment ──────────────────────────────────────────────────────────

/// Make the fresh recipient key and announce its public key.
unsafe fn attach_recipient(s: &mut CryptState) -> i32 {
    let mut public = [0u8; kv::share::P256_PUB_LEN];
    let mut arg = [0u8; 20];
    arg[0..2].copy_from_slice(&kv::suite::P256.to_le_bytes());
    arg[2..6].copy_from_slice(&(kv::usage::AGREE | kv::usage::EXPORT_PUBLIC).to_le_bytes());
    arg[8..16].copy_from_slice(&(public.as_mut_ptr() as u64).to_le_bytes());
    arg[16..18].copy_from_slice(&(public.len() as u16).to_le_bytes());
    let h = (s.sys().provider_call)(-1, kv::GENERATE, arg.as_mut_ptr(), arg.len());
    if h < 0 {
        return h;
    }
    s.recipient = h;
    if s.recipient_out >= 0 {
        let mut rec = [0u8; RECIPIENT_LEN];
        rec[..4].copy_from_slice(&RECIPIENT_MAGIC);
        rec[4..].copy_from_slice(&public);
        let n = (s.sys().channel_write)(s.recipient_out, rec.as_ptr(), RECIPIENT_LEN);
        if n != RECIPIENT_LEN as i32 {
            return E_IO;
        }
    }
    0
}

/// Announce the recipient and collect the attachment bundle: `E_AGAIN`
/// until the whole bundle has arrived.
unsafe fn attach_gather(s: &mut CryptState) -> i32 {
    if s.ctrl_chan < 0 {
        return E_INVAL;
    }
    if s.recipient < 0 {
        let rc = attach_recipient(s);
        if rc != 0 {
            return rc;
        }
    }
    while (s.bundle_len as usize) < BUNDLE_LEN {
        let have = s.bundle_len as usize;
        let p = s.bundle.as_mut_ptr().add(have);
        let n = (s.sys().channel_read)(s.ctrl_chan, p, BUNDLE_LEN - have);
        if n <= 0 {
            return E_AGAIN;
        }
        s.bundle_len += n as u32;
    }
    0
}

/// End an attach: the recipient key served it and is destroyed whatever
/// the outcome, and the bundle is forgotten.
unsafe fn attach_finish(s: &mut CryptState, rc: i32) -> i32 {
    if s.recipient >= 0 {
        vault_destroy(s, s.recipient);
    }
    s.recipient = -1;
    s.bundle.fill(0);
    s.bundle_len = 0;
    s.bundle_ready = 0;
    rc
}

/// The epoch the bundle's first envelope names. Unverified: it only picks
/// which epoch the bundle is offered for, and `SHARE_COMBINE` binds the
/// envelopes to that epoch.
fn bundle_epoch(s: &CryptState) -> u32 {
    let e = 8 + kv::share::EPOCH;
    u32::from_le_bytes([
        s.bundle[e],
        s.bundle[e + 1],
        s.bundle[e + 2],
        s.bundle[e + 3],
    ])
}

/// The epoch other than the superblock's own that a rotation holds keys
/// for: the next one while prepared, the previous one after; 0 when steady.
fn other_epoch_of(sb: &Superblock) -> u32 {
    match sb.rotation {
        ROT_STEADY => 0,
        ROT_PREPARED => sb.epoch.saturating_add(1),
        _ => sb.prev_epoch,
    }
}

/// A mount still waits for a bundle: the current epoch's, or the other
/// epoch's a rotation under way needs.
fn attach_wanting(s: &CryptState) -> bool {
    s.master < 0 || (s.need_other != 0 && s.other_master < 0)
}

/// Reconstruct the master the bundle holds, bound to `resource` and
/// `epoch`, into a new handle (or a negative errno). The recipient key and
/// the bundle are spent whatever the outcome.
unsafe fn share_combine(s: &mut CryptState, resource: &[u8; 16], epoch: u32) -> i32 {
    use kv::share::{self as sh, combine as a};
    let env_a = 8;
    let env_b = 8 + sh::P256_LEN;
    let mut arg = [0u8; a::ENVS + 2 * sh::P256_LEN];
    arg[a::TARGET_SUITE..a::TARGET_SUITE + 2].copy_from_slice(&kv::suite::KDF_KEY.to_le_bytes());
    arg[a::TARGET_USAGE..a::TARGET_USAGE + 4].copy_from_slice(&kv::usage::DERIVE.to_le_bytes());
    arg[a::OPENER_A..a::OPENER_A + 4].copy_from_slice(&s.recipient.to_le_bytes());
    arg[a::OPENER_B..a::OPENER_B + 4].copy_from_slice(&s.recipient.to_le_bytes());
    arg[a::RESOURCE..a::RESOURCE + 16].copy_from_slice(resource);
    arg[a::EPOCH..a::EPOCH + 4].copy_from_slice(&epoch.to_le_bytes());
    arg[a::ENV_A_LEN..a::ENV_A_LEN + 2].copy_from_slice(&(sh::P256_LEN as u16).to_le_bytes());
    arg[a::ENV_B_LEN..a::ENV_B_LEN + 2].copy_from_slice(&(sh::P256_LEN as u16).to_le_bytes());
    arg[a::ENVS..a::ENVS + 2 * sh::P256_LEN]
        .copy_from_slice(&s.bundle[env_a..env_b + sh::P256_LEN]);
    let h = if s.recipient >= 0 {
        (s.sys().provider_call)(-1, kv::SHARE_COMBINE, arg.as_mut_ptr(), arg.len())
    } else {
        E_INVAL
    };
    arg.fill(0);
    attach_finish(s, h)
}

/// On a device with no container: the master from the bundle, bound to the
/// bundle's own volume and epoch, to be formatted.
unsafe fn attach_combine(s: &mut CryptState, newest: Option<Superblock>) -> i32 {
    use kv::share as sh;
    if newest.is_some() || s.format != 1 {
        return attach_finish(s, -19); // ENODEV: no container, and none to make
    }
    let env_a = 8;
    s.attach_resource
        .copy_from_slice(&s.bundle[env_a + sh::RESOURCE..env_a + sh::RESOURCE + 16]);
    s.attach_epoch = bundle_epoch(s);
    let resource = s.attach_resource;
    let h = share_combine(s, &resource, s.attach_epoch);
    if h < 0 {
        return h;
    }
    s.master = h;
    0
}

/// Take a mount's bundle for the epoch it names: the superblock's own epoch
/// (the master that verifies it) or the other epoch a rotation holds. A
/// bundle for any other epoch, or one already held, is refused `EAGAIN`:
/// its recipient is destroyed, and the next attempt announces a fresh one.
unsafe fn attach_take(s: &mut CryptState) -> i32 {
    let epoch = bundle_epoch(s);
    let resource = s.attach_resource;
    if s.master < 0 && epoch == s.attach_epoch {
        let h = share_combine(s, &resource, epoch);
        if h < 0 {
            return h;
        }
        s.master = h;
        return 0;
    }
    if s.need_other != 0 && s.other_master < 0 && epoch == s.need_other {
        let h = share_combine(s, &resource, epoch);
        if h < 0 {
            return h;
        }
        s.other_master = h;
        s.other_epoch = epoch;
        return 0;
    }
    attach_finish(s, E_AGAIN)
}

// ── Data-key rotation ───────────────────────────────────────────────────

/// The AEAD suite a data key of this container takes.
fn data_suite(s: &CryptState) -> u16 {
    if s.sb.suite == SUITE_AES {
        kv::suite::AEAD_AES256_GCM
    } else {
        kv::suite::AEAD_KEY
    }
}

/// At mount: the other epoch's keys a rotation under way needs — the next
/// master while prepared, the previous master and data key after that. In
/// steady state, remove a previous master a crash left behind.
///
/// Attached, the other master is the one reconstructed from its own bundle
/// while mounting. When the verified superblock needs another epoch than
/// the one gathered — or one when none was — the mount answers `EAGAIN` and
/// goes back to wait for that epoch's bundle.
unsafe fn open_rotation_keys(s: &mut CryptState) -> i32 {
    if s.attach == 1 {
        if s.sb.rotation > ROT_RETIRING {
            return E_INVAL;
        }
        s.attach_resource = s.sb.volume_id;
        let want = other_epoch_of(&s.sb);
        if want == 0 || s.other_epoch != want {
            if s.other_master >= 0 {
                vault_destroy(s, s.other_master);
            }
            s.other_master = -1;
            s.other_epoch = 0;
        }
        s.need_other = want;
        if want == 0 {
            return 0;
        }
        if s.other_master < 0 {
            return E_AGAIN;
        }
        if s.sb.rotation == ROT_PREPARED {
            return 0;
        }
        let ctx = data_context(&s.sb.volume_id, s.sb.prev_epoch);
        let k = vault_derive_from(
            s,
            s.other_master,
            data_suite(s),
            kv::usage::OPEN,
            LABEL_DATA,
            &ctx,
        );
        if k < 0 {
            return k;
        }
        s.other_data_key = k;
        return 0;
    }
    match s.sb.rotation {
        ROT_STEADY => {
            if s.sb.epoch > 1 {
                // Retirement commits the steady superblock before it destroys
                // the old master; finish what a crash between them left.
                vault_destroy_epoch(s, s.sb.epoch - 1);
            }
            0
        }
        ROT_PREPARED => {
            let h = vault_open_epoch(s, s.sb.epoch + 1, false);
            if h < 0 {
                return h;
            }
            s.other_master = h;
            0
        }
        ROT_ACTIVE | ROT_MIGRATING | ROT_RETIRING => {
            let h = vault_open_epoch(s, s.sb.prev_epoch, false);
            if h < 0 {
                return h;
            }
            s.other_master = h;
            let ctx = data_context(&s.sb.volume_id, s.sb.prev_epoch);
            let k = vault_derive_from(s, h, data_suite(s), kv::usage::OPEN, LABEL_DATA, &ctx);
            if k < 0 {
                return k;
            }
            s.other_data_key = k;
            0
        }
        _ => E_INVAL,
    }
}

/// Commit the superblock as it now stands, remembering `s.sb` as it was so
/// a failed commit puts it back: memory then matches the device.
fn commit_reverting(s: &mut CryptState, old: Superblock) -> Act {
    s.revert_sb = old;
    Act::Call(Frame::new(K_COMMIT_SB, 0, 0))
}

/// Start a rotation: the next epoch's master, made and persisted, and the
/// superblock saying so. Nothing uses it yet.
unsafe fn run_rot_prepare(s: &mut CryptState, f: &mut Frame) -> Act {
    if s.attach == 1 {
        return rot_prepare_attached(s, f);
    }
    if f.pc == 0 {
        if s.sb.rotation != ROT_STEADY {
            return Act::Done(0);
        }
        let Some(next) = s.sb.epoch.checked_add(1) else {
            return Act::Done(E_INVAL);
        };
        let h = vault_open_epoch(s, next, true);
        if h < 0 {
            return Act::Done(h);
        }
        s.other_master = h;
        let old = s.sb;
        s.sb.rotation = ROT_PREPARED;
        s.sb.rotation_cursor = 0;
        f.pc = 1;
        return commit_reverting(s, old);
    }
    if f.rc != 0 {
        s.sb = s.revert_sb;
    }
    Act::Done(f.rc)
}

/// Ask for the next epoch's bundle: a fresh recipient key, announced on
/// `recipient`. The rotation then waits for the bundle; nothing is written.
unsafe fn rot_ask_bundle(s: &mut CryptState) -> i32 {
    let Some(next) = s.sb.epoch.checked_add(1) else {
        s.rot_want = 0;
        return E_INVAL;
    };
    let rc = attach_recipient(s);
    if rc != 0 {
        attach_finish(s, 0);
        s.rot_want = 0;
        return rc;
    }
    s.rot_want = next;
    0
}

/// An attached volume's rotation. The next epoch's master comes from its
/// custodians: a `"FXRT"` record asks for it with a fresh recipient; its
/// bundle, arriving on the control input, is reconstructed bound to the
/// volume and the next epoch, and the prepared superblock is committed.
/// A bundle refused — not for the next epoch, this volume or the recipient
/// — leaves the volume as it was, and a fresh recipient is announced for
/// the bundle to come.
unsafe fn rot_prepare_attached(s: &mut CryptState, f: &mut Frame) -> Act {
    if f.pc == 0 {
        let is_bundle = s.bundle_ready != 0;
        s.bundle_ready = 0;
        if !is_bundle {
            if s.sb.rotation != ROT_STEADY || s.rot_want != 0 {
                // Under way, or already asked: the recipient announced stands.
                return Act::Done(0);
            }
            return Act::Done(rot_ask_bundle(s));
        }
        if s.rot_want == 0 || s.sb.rotation != ROT_STEADY {
            // No rotation waits for a bundle.
            return Act::Done(attach_finish(s, E_INVAL));
        }
        let want = s.rot_want;
        let h = if s.bundle[4] == 2 && bundle_epoch(s) == want {
            let resource = s.sb.volume_id;
            share_combine(s, &resource, want)
        } else {
            attach_finish(s, E_ACCES)
        };
        if h < 0 {
            let rc = rot_ask_bundle(s);
            return Act::Done(if rc != 0 { rc } else { h });
        }
        s.rot_want = 0;
        s.other_master = h;
        let old = s.sb;
        s.sb.rotation = ROT_PREPARED;
        s.sb.rotation_cursor = 0;
        f.pc = 1;
        return commit_reverting(s, old);
    }
    if f.rc != 0 {
        // The master is not persisted: without the commit it is spent, and
        // the next epoch's bundle is asked for again.
        s.sb = s.revert_sb;
        vault_destroy(s, s.other_master);
        s.other_master = -1;
        rot_ask_bundle(s);
    }
    Act::Done(f.rc)
}

/// Switch new writes to the next epoch: one committed superblock names both
/// epochs, MAC'd under the new master. `a` holds the new data key, `b` the
/// old one, until the commit settles.
unsafe fn run_rot_activate(s: &mut CryptState, f: &mut Frame) -> Act {
    match f.pc {
        0 => {
            // Nothing sealed under the old epoch may wait in the journal.
            f.pc = 1;
            Act::Call(Frame::new(K_JOURNAL_CYCLE, 0, 0))
        }
        1 => {
            if f.rc != 0 {
                return Act::Done(f.rc);
            }
            let next = s.sb.epoch + 1;
            let ctx = data_context(&s.sb.volume_id, next);
            let dk = vault_derive_from(
                s,
                s.other_master,
                data_suite(s),
                kv::usage::SEAL | kv::usage::OPEN,
                LABEL_DATA,
                &ctx,
            );
            if dk < 0 {
                return Act::Done(dk);
            }
            let mut rnd = [0u8; 4];
            if dev_csprng_fill(s.sys(), rnd.as_mut_ptr(), rnd.len()) != 0 {
                vault_destroy(s, dk);
                return Act::Done(E_IO);
            }
            let old = s.sb;
            s.sb.prev_epoch = s.sb.epoch;
            s.sb.epoch = next;
            s.sb.prev_prefix = s.sb.prefix;
            s.sb.prefix = u32::from_le_bytes(rnd);
            s.sb.rotation = ROT_ACTIVE;
            s.sb.rotation_cursor = 0;
            core::mem::swap(&mut s.master, &mut s.other_master);
            f.a = u64::from(dk as u32);
            f.b = u64::from(s.data_key as u32);
            s.other_data_key = s.data_key;
            s.data_key = dk;
            f.pc = 2;
            commit_reverting(s, old)
        }
        _ => {
            if f.rc != 0 {
                s.sb = s.revert_sb;
                core::mem::swap(&mut s.master, &mut s.other_master);
                s.data_key = f.b as u32 as i32;
                s.other_data_key = -1;
                vault_destroy(s, f.a as u32 as i32);
            }
            Act::Done(f.rc)
        }
    }
}

/// Re-seal the next batch of old-epoch units under the current epoch, then
/// commit the cursor once the batch is home and durable. An application
/// write since activation is already current and is left alone. `a` is the
/// unit, `b` the batch's end.
unsafe fn run_rot_migrate(s: &mut CryptState, f: &mut Frame) -> Act {
    loop {
        match f.pc {
            0 => {
                f.a = s.sb.rotation_cursor;
                f.b = (f.a + MIGRATE_BATCH).min(s.sb.data_units);
                f.pc = 1;
            }
            1 => {
                if f.a >= f.b {
                    f.pc = 5;
                    return Act::Call(Frame::new(K_JOURNAL_CYCLE, 0, 0));
                }
                f.pc = 2;
                return Act::Call(Frame::new(K_CURRENT_META, f.a, 0));
            }
            2 => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                let meta = s.ret_meta;
                if meta.generation == 0
                    || meta.flags & FLAG_DISCARDED != 0
                    || meta.epoch == s.sb.epoch
                {
                    f.a += 1;
                    f.pc = 1;
                    continue;
                }
                f.pc = 3;
                return Act::Call(Frame::new(K_READ_UNIT, f.a, 0));
            }
            3 => {
                if f.rc != 0 {
                    s.plain.fill(0);
                    return Act::Done(f.rc);
                }
                f.pc = 4;
                return Act::Call(Frame::new(K_WRITE_UNIT, f.a, 0));
            }
            4 => {
                s.plain.fill(0);
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                f.a += 1;
                f.pc = 1;
            }
            5 => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                let old = s.sb;
                let end = f.b;
                s.sb.rotation_cursor = end;
                s.sb.rotation = if end >= s.sb.data_units {
                    ROT_RETIRING
                } else {
                    ROT_MIGRATING
                };
                if s.sb.rotation == ROT_RETIRING {
                    s.sb.rotation_cursor = 0;
                }
                f.pc = 6;
                return commit_reverting(s, old);
            }
            _ => {
                if f.rc != 0 {
                    s.sb = s.revert_sb;
                }
                return Act::Done(f.rc);
            }
        }
    }
}

/// Prove no unit needs the old epoch, a batch of metadata blocks per step;
/// then commit the steady superblock and, only after it is durable, destroy
/// the old master. A unit still under the old epoch sends the rotation back
/// to migrating. `a` is the metadata block, `b` the batch's end, `c` the
/// table's length in blocks.
unsafe fn run_rot_retire(s: &mut CryptState, f: &mut Frame) -> Act {
    let rpb = s.layout.records_per_block;
    loop {
        match f.pc {
            0 => {
                f.c = div_ceil(s.sb.data_units, rpb);
                f.a = s.sb.rotation_cursor;
                f.b = (f.a + MIGRATE_BATCH).min(f.c);
                f.pc = 1;
            }
            1 => {
                if f.a >= f.b {
                    f.pc = 4;
                    continue;
                }
                f.pc = 2;
                let p = s.meta_block.as_mut_ptr();
                return io_rw(s, false, s.layout.meta_start + f.a, 1, p);
            }
            2 => {
                if f.rc != 0 {
                    return Act::Done(f.rc);
                }
                for r in 0..rpb {
                    let u = f.a * rpb + r;
                    if u >= s.sb.data_units {
                        break;
                    }
                    let off = r as usize * META_LEN;
                    let m = Meta::decode(&s.meta_block[off..off + META_LEN]);
                    if m.generation != 0 && m.flags & FLAG_DISCARDED == 0 && m.epoch != s.sb.epoch {
                        let old = s.sb;
                        s.sb.rotation = ROT_MIGRATING;
                        s.sb.rotation_cursor = 0;
                        f.pc = 3;
                        return commit_reverting(s, old);
                    }
                }
                f.a += 1;
                f.pc = 1;
            }
            3 => {
                if f.rc != 0 {
                    s.sb = s.revert_sb;
                }
                return Act::Done(f.rc);
            }
            4 => {
                // Progress through the scan is not persisted: a restart
                // rescans.
                s.sb.rotation_cursor = f.b;
                if f.b < f.c {
                    return Act::Done(0);
                }
                let old = s.sb;
                f.a = u64::from(s.sb.prev_epoch);
                s.sb.rotation = ROT_STEADY;
                s.sb.prev_epoch = 0;
                s.sb.prev_prefix = 0;
                s.sb.rotation_cursor = 0;
                f.pc = 5;
                return commit_reverting(s, old);
            }
            _ => {
                if f.rc != 0 {
                    s.sb = s.revert_sb;
                    s.sb.rotation_cursor = 0;
                    return Act::Done(f.rc);
                }
                vault_destroy(s, s.other_data_key);
                vault_destroy(s, s.other_master);
                s.other_data_key = -1;
                s.other_master = -1;
                s.other_epoch = 0;
                s.need_other = 0;
                if s.attach == 0 {
                    // Attached, the old master was never persisted: its
                    // handle was all there was.
                    vault_destroy_epoch(s, f.a as u32);
                }
                return Act::Done(0);
            }
        }
    }
}

/// Crypto-erase: destroy every master the volume has, then zero both
/// superblocks and flush. The keys go first, so a crash part-way has
/// already made the data unreadable; the superblocks go so the device then
/// reads as holding no container.
unsafe fn run_erase(s: &mut CryptState, f: &mut Frame) -> Act {
    match f.pc {
        0 => {
            for h in [s.data_key, s.other_data_key, s.master, s.other_master] {
                if h >= 0 {
                    vault_destroy(s, h);
                }
            }
            s.data_key = -1;
            s.other_data_key = -1;
            s.master = -1;
            s.other_master = -1;
            // A rotation waiting for its bundle waits no more.
            attach_finish(s, 0);
            s.rot_want = 0;
            if s.attach == 0 {
                let epochs = [s.sb.epoch, s.sb.prev_epoch, s.sb.epoch.saturating_add(1)];
                for e in epochs {
                    if e != 0 {
                        let rc = vault_destroy_epoch(s, e);
                        // ENOENT: an epoch the volume never had a master for.
                        if rc != 0 && rc != -2 {
                            return Act::Done(rc);
                        }
                    }
                }
            }
            s.phase = PHASE_FAILED;
            s.open_err = -19;
            for p in s.pending.iter_mut() {
                p.live = false;
            }
            f.pc = 1;
            Act::Call(zero_frame(0, 2 * s.layout.blocks_per_unit))
        }
        1 => {
            if f.rc != 0 {
                return Act::Done(f.rc);
            }
            f.pc = 2;
            io_flush(s)
        }
        _ => Act::Done(f.rc),
    }
}

/// Read a record from the control input, if one has arrived, and start its
/// work: the kind of background frame to run, 0 when there was nothing to
/// do, or a negative errno for a record that is not one. Its magic says how
/// long it is: a bundle (`"FXSB"`, attach mode) is `BUNDLE_LEN` bytes,
/// every control record `ROTATE_LEN`.
unsafe fn poll_control(s: &mut CryptState) -> i32 {
    if s.ctrl_chan < 0 {
        return 0;
    }
    loop {
        let have = s.bundle_len as usize;
        let need = if have < 4 {
            4
        } else if s.bundle[..4] == BUNDLE_MAGIC {
            BUNDLE_LEN
        } else {
            ROTATE_LEN
        };
        if have >= need {
            break;
        }
        let p = s.bundle.as_mut_ptr().add(have);
        let n = (s.sys().channel_read)(s.ctrl_chan, p, need - have);
        if n <= 0 {
            return 0;
        }
        s.bundle_len += n as u32;
    }
    s.bundle_len = 0;
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&s.bundle[..4]);
    if magic == BUNDLE_MAGIC && s.attach == 1 {
        s.bundle_ready = 1;
        return i32::from(K_ROT_PREPARE);
    }
    s.bundle.fill(0);
    if magic == ERASE_MAGIC {
        return i32::from(K_ERASE);
    }
    if magic != ROTATE_MAGIC {
        return E_INVAL;
    }
    i32::from(K_ROT_PREPARE)
}

// ── Upper block surface ─────────────────────────────────────────────────

fn caps_of(s: &CryptState) -> Option<Caps> {
    if s.phase != PHASE_READY {
        return None;
    }
    let per_unit = div(u64::from(s.sb.unit_size), u64::from(s.upper_block)) as u32;
    // No `F_WRITE_COPIES`: a queued write reads its buffer when its turn
    // comes, which may be steps after `SUBMIT`, so the buffer is lent until
    // the completion is reaped.
    Some(Caps {
        logical_block_size: s.upper_block,
        block_count: s.sb.data_units * u64::from(per_unit),
        max_blocks: per_unit * 8,
        atomic_blocks: per_unit,
        queue_depth: QUEUE_DEPTH as u16,
        flags: blk::caps::F_WRITE
            | blk::caps::F_FLUSH
            | blk::caps::F_DISCARD
            | blk::caps::F_DISCARD_ZEROES
            | blk::caps::F_ASYNC,
        device_id: s.lower.device_id(),
    })
}

/// The request a request frame serves.
fn request_of(s: &CryptState, slot: u8) -> Req {
    if slot == EXEC_SLOT {
        s.exec.req
    } else {
        s.reqs[slot as usize % QUEUE_DEPTH].req
    }
}

/// Hand a finished request its completion: the EXEC slot keeps it for the
/// caller's next ask; a queued request's waits for `REAP`.
fn deliver(s: &mut CryptState, slot: u8, c: Cpl) {
    if slot == EXEC_SLOT {
        s.exec_cpl = c;
        s.exec_state = EXEC_DONE;
        return;
    }
    s.reqs[slot as usize % QUEUE_DEPTH].used = 0;
    if s.count as usize >= QUEUE_DEPTH {
        return;
    }
    let tail = (s.head as usize + s.count as usize) % QUEUE_DEPTH;
    s.done[tail] = c;
    s.count += 1;
}

/// Complete a request frame's request with `status`. A durable request
/// (`FLUSH`, `FUA`) carries the fence of the lower completion that made it
/// durable, as the lower source reported it; any other write is `Volatile`;
/// a read or a failure carries none.
fn finish(s: &mut CryptState, f: &Frame, status: i32, durable: bool) -> Act {
    s.plain.fill(0);
    let r = request_of(s, f.flag);
    let mut c = Cpl::bare(r.tag, status);
    if status == 0 && r.op != blk::op::READ {
        if durable {
            let n = s.lower_fence_len as usize;
            c.fence[..n].copy_from_slice(&s.lower_fence[..n]);
            c.fence_len = n as u16;
        } else if let Some(n) = Fence::Volatile.encode(&mut c.fence) {
            c.fence_len = n as u16;
        }
    }
    deliver(s, f.flag, c);
    Act::Done(0)
}

/// Run one upper request. `a` is how far into the request it has got.
///
/// A queued request's buffer is lent until it is reaped, so the request
/// reads and writes it whenever it runs. An EXEC request's buffer is lent
/// only for the call: where it needs the buffer outside one, it parks, and
/// the caller's next ask of the same request resumes it.
unsafe fn run_request(s: &mut CryptState, f: &mut Frame) -> Act {
    let r = request_of(s, f.flag);
    let unit = s.unit() as u64;
    let ub = u64::from(s.upper_block);
    let len = u64::from(r.nblocks) * ub;
    let buffer_ok = f.flag != EXEC_SLOT || s.exec_live != 0;
    loop {
        let pos = r.lba * ub + f.a;
        let u = div(pos, unit);
        let in_unit = rem(pos, unit);
        let n = (unit - in_unit).min(len.saturating_sub(f.a));
        let whole = in_unit == 0 && n == unit;
        match f.pc {
            0 => {
                if s.phase != PHASE_READY {
                    let err = if s.phase == PHASE_FAILED {
                        s.open_err
                    } else {
                        E_AGAIN
                    };
                    return finish(s, f, err, false);
                }
                f.pc = 1;
                if r.flags & blk::F_PREFLUSH != 0 {
                    return Act::Call(Frame::new(K_JOURNAL_CYCLE, 0, 0));
                }
                f.rc = 0;
            }
            1 => {
                if f.rc != 0 {
                    return finish(s, f, f.rc, false);
                }
                match r.op {
                    blk::op::FLUSH => {
                        f.pc = 9;
                        return Act::Call(Frame::new(K_JOURNAL_CYCLE, 0, 0));
                    }
                    blk::op::READ | blk::op::WRITE | blk::op::DISCARD => {
                        f.a = 0;
                        f.pc = 2;
                    }
                    _ => return finish(s, f, E_INVAL, false),
                }
            }
            2 => {
                if f.a >= len {
                    s.plain.fill(0);
                    if r.op != blk::op::READ && r.flags & blk::F_FUA != 0 {
                        f.pc = 9;
                        return Act::Call(Frame::new(K_JOURNAL_CYCLE, 0, 0));
                    }
                    return finish(s, f, 0, false);
                }
                match r.op {
                    blk::op::READ => {
                        f.pc = 3;
                        return Act::Call(Frame::new(K_READ_UNIT, u, 0));
                    }
                    blk::op::DISCARD if whole => {
                        f.pc = 6;
                        return Act::Call(Frame::new(K_WRITE_UNIT, u, 1));
                    }
                    _ => {
                        // A partial unit is read, modified and resealed; a
                        // discard of part of a unit writes zeros there.
                        f.pc = 5;
                        if !whole {
                            return Act::Call(Frame::new(K_READ_UNIT, u, 0));
                        }
                        f.rc = 0;
                    }
                }
            }
            3 => {
                if f.rc != 0 {
                    return finish(s, f, f.rc, false);
                }
                f.pc = 4;
            }
            4 => {
                if !buffer_ok {
                    return Act::Park;
                }
                core::ptr::copy_nonoverlapping(
                    s.plain.as_ptr().add(in_unit as usize),
                    (r.buf_ptr as *mut u8).add(f.a as usize),
                    n as usize,
                );
                f.a += n;
                f.pc = 2;
            }
            5 => {
                if f.rc != 0 {
                    return finish(s, f, f.rc, false);
                }
                let dst = s.plain.as_mut_ptr().add(in_unit as usize);
                if r.op == blk::op::WRITE {
                    if !buffer_ok {
                        return Act::Park;
                    }
                    core::ptr::copy_nonoverlapping(
                        (r.buf_ptr as *const u8).add(f.a as usize),
                        dst,
                        n as usize,
                    );
                } else {
                    core::ptr::write_bytes(dst, 0, n as usize);
                }
                f.pc = 6;
                return Act::Call(Frame::new(K_WRITE_UNIT, u, 0));
            }
            6 => {
                if f.rc != 0 {
                    return finish(s, f, f.rc, false);
                }
                f.a += n;
                f.pc = 2;
            }
            _ => {
                if f.rc != 0 {
                    return finish(s, f, f.rc, false);
                }
                return finish(s, f, 0, true);
            }
        }
    }
}

unsafe fn admitted(s: &mut CryptState, body: &[u8]) -> Result<Req, i32> {
    let Some(caps) = caps_of(s) else {
        return Err(if s.phase == PHASE_FAILED {
            s.open_err
        } else {
            E_AGAIN
        });
    };
    match Req::decode(body) {
        Some(r) if caps.admits(&r) => Ok(r),
        _ => Err(E_INVAL),
    }
}

/// Requests queued or finished and not yet reaped.
fn queued(s: &CryptState) -> usize {
    s.count as usize + s.reqs.iter().filter(|q| q.used != 0).count()
}

unsafe extern "C" fn crypt_block_ioctl(state: *mut c_void, cmd: u32, arg: *mut u8) -> i32 {
    if state.is_null() || arg.is_null() {
        return E_INVAL;
    }
    let s = &mut *(state as *mut CryptState);
    match cmd {
        blk::ioctl::CAPS => match caps_of(s) {
            Some(c) => {
                c.encode(core::slice::from_raw_parts_mut(arg, blk::caps::LEN));
                blk::caps::LEN as i32
            }
            None if s.phase == PHASE_FAILED => s.open_err,
            None => E_AGAIN,
        },
        blk::ioctl::EXEC => {
            let r = match admitted(s, core::slice::from_raw_parts(arg, blk::req::LEN)) {
                Ok(r) => r,
                Err(rc) => return rc,
            };
            if s.exec_state != EXEC_FREE && s.exec.req != r {
                // Another request holds the slot. Its caller has moved on;
                // it is dropped unless it owns a lower request in flight.
                let running = s.exec_state == EXEC_RUNNING && s.parked == 0;
                if running {
                    return E_AGAIN;
                }
                abandon_exec(s);
            }
            if s.exec_state == EXEC_FREE {
                s.exec.req = r;
                s.exec_state = EXEC_WAITING;
            }
            s.exec_live = 1;
            pump(s);
            s.exec_live = 0;
            if s.exec_state != EXEC_DONE {
                return E_AGAIN;
            }
            let c = s.exec_cpl;
            s.exec_state = EXEC_FREE;
            c.encode(core::slice::from_raw_parts_mut(
                arg.add(blk::req::LEN),
                blk::cpl::LEN,
            ));
            c.status
        }
        blk::ioctl::SUBMIT => {
            let r = match admitted(s, core::slice::from_raw_parts(arg, blk::req::LEN)) {
                Ok(r) => r,
                Err(rc) => return rc,
            };
            if s.job == JOB_EXEC && s.parked != 0 {
                // An EXEC waiting for its caller to ask again, when the
                // caller has gone on to queue: it would hold the device.
                abandon_exec(s);
            }
            if queued(s) >= QUEUE_DEPTH {
                return E_AGAIN;
            }
            let Some(i) = s.reqs.iter().position(|q| q.used == 0) else {
                return E_AGAIN;
            };
            s.req_seq += 1;
            s.reqs[i] = Upper {
                req: r,
                seq: s.req_seq,
                used: 1,
                started: 0,
                _pad: [0; 6],
            };
            pump(s);
            0
        }
        blk::ioctl::REAP => {
            pump(s);
            if s.count == 0 {
                return 0;
            }
            let c = s.done[s.head as usize];
            s.head = ((s.head as usize + 1) % QUEUE_DEPTH) as u8;
            s.count -= 1;
            c.encode(core::slice::from_raw_parts_mut(arg, blk::cpl::LEN));
            1
        }
        _ => E_NOSYS,
    }
}

// ── Status ──────────────────────────────────────────────────────────────

/// The status record for the module as it stands; `None` while an erase is
/// under way, so its half-done state is never reported.
fn status_record(s: &CryptState) -> Option<[u8; STATUS_LEN]> {
    let none = Superblock::default();
    let mut sb = &s.sb;
    let mut err = 0i32;
    let mut awaited = 0u32;
    let state = if s.erase_state == ERASE_RUNNING {
        return None;
    } else if s.erase_state == ERASE_DONE {
        if s.erase_rc == 0 {
            ST_ERASED
        } else {
            err = s.erase_rc;
            ST_FAILED
        }
    } else if s.phase == PHASE_FAILED {
        // An attach that failed before its superblock verified reports the
        // container it read.
        if s.sb.epoch == 0 && s.attach_probed != 0 {
            sb = &s.probe_sb;
        }
        err = s.open_err;
        ST_FAILED
    } else if s.phase == PHASE_OPENING {
        if s.attach == 1 && s.attach_probed != 0 {
            sb = &s.probe_sb;
            if attach_wanting(s) {
                // The superblock's own epoch first; then the other epoch a
                // rotation under way needs. 0 on a blank device, whose
                // epoch is the bundle's.
                awaited = if s.master < 0 {
                    s.attach_epoch
                } else {
                    s.need_other
                };
                ST_AWAITING_BUNDLE
            } else {
                ST_OPENING
            }
        } else {
            // A local mount names nothing until it is ready: its superblock
            // is not settled while it formats, verifies and recovers.
            sb = &none;
            ST_OPENING
        }
    } else {
        err = s.bg_err;
        if s.rot_want != 0 {
            awaited = s.rot_want;
            ST_AWAITING_BUNDLE
        } else if s.sb.rotation != ROT_STEADY {
            ST_ROTATING
        } else {
            ST_READY
        }
    };
    let mut r = [0u8; STATUS_LEN];
    r[0..4].copy_from_slice(&STATUS_MAGIC);
    r[4] = state;
    r[5] = sb.rotation;
    r[8..12].copy_from_slice(&sb.epoch.to_le_bytes());
    r[12..16].copy_from_slice(&sb.prev_epoch.to_le_bytes());
    r[16..20].copy_from_slice(&awaited.to_le_bytes());
    r[20..24].copy_from_slice(&err.to_le_bytes());
    r[24..40].copy_from_slice(&sb.volume_id);
    Some(r)
}

fn same_record(a: &[u8; STATUS_LEN], b: &[u8; STATUS_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..STATUS_LEN {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Write the status record when it changed. A record the channel takes
/// only part of is finished first, on later steps, so the stream stays
/// framed; a record not yet started is replaced by a newer one, so only
/// the latest waits. At most two writes per step.
unsafe fn status_publish(s: &mut CryptState) {
    if s.status_out < 0 {
        return;
    }
    if let Some(r) = status_record(s) {
        if s.status_have == 0 || !same_record(&r, &s.status_cur) {
            s.status_cur = r;
            s.status_have = 1;
            s.status_dirty = 1;
        }
    }
    for _ in 0..2 {
        // Only a record partly written must be finished as it was.
        if s.status_tx_live == 0 || (s.status_off == 0 && s.status_dirty != 0) {
            if s.status_dirty == 0 {
                return;
            }
            s.status_tx = s.status_cur;
            s.status_off = 0;
            s.status_tx_live = 1;
            s.status_dirty = 0;
        }
        let off = (s.status_off as usize).min(STATUS_LEN);
        let left = STATUS_LEN - off;
        let n = (s.sys().channel_write)(s.status_out, s.status_tx.as_ptr().add(off), left);
        if n <= 0 {
            return;
        }
        let done = off + (n as usize).min(left);
        s.status_off = done as u8;
        if done < STATUS_LEN {
            return;
        }
        s.status_tx_live = 0;
    }
}

// ── Module entry points ─────────────────────────────────────────────────

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<CryptState>()
}

/// Consumers wait for the container to mount: `Ready` gates them.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 {
    1
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<CryptState>() {
            return -2;
        }
        core::ptr::write_bytes(state, 0, core::mem::size_of::<CryptState>());
        let s = &mut *(state as *mut CryptState);
        s.syscalls = syscalls as *const SyscallTable;
        s.out_chan = out_chan;
        s.master = -1;
        s.data_key = -1;
        s.recipient = -1;
        s.other_master = -1;
        s.other_data_key = -1;
        s.ctrl_chan = ctrl_chan;
        s.lower.bind(in_chan);
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        // The `recipient` output, second of the outputs.
        s.recipient_out = if s.attach == 1 {
            dev_channel_port(&*s.syscalls, 1, 1)
        } else {
            -1
        };
        // The `status` output, third of the outputs; optional.
        s.status_out = dev_channel_port(&*s.syscalls, 1, 2);
        if out_chan >= 0 {
            dev_channel_register_ioctl(
                &*s.syscalls,
                out_chan,
                state as *mut c_void,
                Some(crypt_block_ioctl),
            );
        }
        0
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut CryptState);
        let rc = run_step(s);
        status_publish(s);
        rc
    }
}

/// A mount that failed serves nothing: drop every key handle it holds and
/// the scratch a replayed unit's plaintext may sit in. Persisted masters are
/// untouched: only the handles go.
unsafe fn release_keys(s: &mut CryptState) {
    for h in [s.data_key, s.other_data_key, s.master, s.other_master] {
        if h >= 0 {
            vault_destroy(s, h);
        }
    }
    s.data_key = -1;
    s.other_data_key = -1;
    s.master = -1;
    s.other_master = -1;
    attach_finish(s, 0);
    s.plain.fill(0);
    s.cipher.fill(0);
}

/// One module step: the mount while opening, then the engine and the
/// background work it may start.
unsafe fn run_step(s: &mut CryptState) -> i32 {
    if s.phase == PHASE_OPENING {
        if s.depth == 0 && push_frame(s, Frame::new(K_MOUNT, 0, 0)) {
            s.job = JOB_MOUNT;
            s.mount_done = 0;
        }
        pump(s);
        if s.mount_done == 0 {
            return 0;
        }
        s.mount_done = 0;
        return match s.mount_rc {
            0 => {
                s.phase = PHASE_READY;
                dev_log(s.sys(), 3, b"[crypt_block] ready".as_ptr(), 19);
                3
            }
            // Nothing read or written yet: the next step starts again.
            E_AGAIN => 0,
            rc => {
                s.phase = PHASE_FAILED;
                s.open_err = rc;
                release_keys(s);
                dev_log(s.sys(), 1, b"[crypt_block] mount failed".as_ptr(), 26);
                rc
            }
        };
    }
    pump(s);
    // Background work starts only on an idle engine with no upper
    // request waiting, one phase of a rotation per step: starting one
    // is a step.
    if s.phase == PHASE_READY && s.depth == 0 && !upper_waiting(s) {
        let kind = poll_control(s);
        if kind > 0 {
            start_background(s, kind as u8);
        } else if kind == 0 && s.sb.rotation != ROT_STEADY {
            let k = match s.sb.rotation {
                ROT_PREPARED => K_ROT_ACTIVATE,
                ROT_RETIRING => K_ROT_RETIRE,
                ROT_ACTIVE | ROT_MIGRATING => K_ROT_MIGRATE,
                _ => 0,
            };
            if k != 0 {
                start_background(s, k);
            }
        } else {
            note_background(s, kind);
            if kind < 0 {
                s.bg_err = kind;
            }
        }
        if s.depth != 0 {
            pump(s);
        }
    }
    0
}

/// Host-test surface: what a test needs to reach state no request can.
#[cfg(feature = "host-test")]
pub mod test_hooks {
    /// Spend the current nonce range: the next sealed unit must reserve a
    /// new one, committed to the device first.
    pub fn exhaust_nonce_range(state: *mut u8) {
        // SAFETY: `state` is the block `module_new` initialised.
        let s = unsafe { &mut *(state as *mut super::CryptState) };
        s.next_seq = s.sb.reserved_seq;
    }
}

include!("../../sdk/runtime/wasm_entry.rs");
