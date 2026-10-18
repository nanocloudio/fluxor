//! FAT32 PIC Module
//!
//! Reads raw blocks from input channel (SD module) and provides file-level
//! access to output channel. Supports seeking by file index.
//!
//! # Architecture
//!
//! ```text
//! SD -> [fat32] -> Bank
//!        |
//!        +-- Reads boot sector, FAT, directories
//!        +-- Enumerates files in configured path
//!        +-- On seek(index), streams that file's data
//! ```
//!
//! # Configuration
//!
//! Parameters (from YAML):
//!   path: Directory to enumerate (e.g., "/samples")
//!   pattern: Optional glob pattern (e.g., "*.raw")
//!
//! # Seek Protocol
//!
//! Downstream (bank) sends IOCTL_NOTIFY with file index (0, 1, 2, ...).
//! Fat32 starts streaming that file's data.

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
#![allow(
    unreachable_patterns,
    reason = "defensive `_ => Error` arms in enum state-machine matches. The match is \
              exhaustive, which is why the lint fires; the arm exists so that adding a \
              variant cannot silently bypass the error path. #[expect] is not the \
              alternative — it fails the build in the configurations where the lint \
              does not fire"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;

use abi::{errno, SyscallTable};

// ============================================================================
// Constants
// ============================================================================

/// Block size (always 512 for SD/FAT32)
const BLOCK_SIZE: usize = 512;

/// "This buffer holds no sector." Sector numbers in this state are offsets
/// within the volume, and FAT32 caps a volume well below `u32::MAX`, so this
/// can never collide with a real one.
const LBA_NONE: u32 = u32::MAX;

/// FAT sectors one `provider_call` will read looking for a free cluster
/// before yielding, matching [`DIR_SCAN_BUDGET_SECTORS`] for the same
/// reason: a synchronous device read inside a dispatch is charged to the
/// cooperative step budget, and the FAT of a large volume is far too big to
/// walk inside one.
const FAT_SCAN_BUDGET_SECTORS: u32 = 32;

/// Longest long name this provider will *generate* or match against, in
/// characters. The format allows 255; a buffer for that would be carried in
/// the cursor and in every wanted-name argument, on a board where the whole
/// module state is measured against a 256 KiB arena. 64 covers the names a
/// caller actually chooses, and a longer one is refused rather than clipped —
/// the same rule the 8.3 path already follows.
///
/// Names *longer* than this that were written elsewhere are still preserved
/// and retired correctly: preservation walks the companion run without
/// decoding it. Only matching and generation are bounded.
const LFN_MAX_CHARS: usize = 64;

/// Characters one companion entry carries.
const LFN_CHARS_PER_ENTRY: usize = 13;

/// Byte offsets of those 13 characters within a companion entry. They are
/// split into three runs around the attribute and checksum fields, which is
/// why this is a table rather than a stride.
const LFN_CHAR_OFFSETS: [usize; LFN_CHARS_PER_ENTRY] =
    [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];

/// Last-entry marker ORed into the ordinal of the final companion (the one
/// physically first, since the set is stored in reverse).
const LFN_LAST: u8 = 0x40;

/// The checksum every companion of a short entry carries, derived from the
/// 8.3 name itself.
///
/// This is what binds a name to the entry it names. A companion set whose
/// checksum does not match the short entry behind it belongs to a file that
/// is gone — which is precisely what a reused directory slot produces — so a
/// reader that trusts the companions without checking resolves the wrong
/// name to the right file.
fn fs_lfn_checksum(short: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    let mut i = 0usize;
    while i < 11 {
        sum = sum.rotate_right(1).wrapping_add(short[i]);
        i += 1;
    }
    sum
}

/// "No owner was on the provider stack." Distinct from any real owner slot,
/// so a handle opened outside a provider frame is never charged to one.
const OWNER_NONE: u16 = u16::MAX;

/// Scanning `[free_scan_cursor, max)` — the fast path, following the hint.
const FREE_SCAN_FORWARD: u8 = 0;
/// Scanning `[2, hint)` — the region the hint skipped past.
const FREE_SCAN_WRAPPED: u8 = 1;
/// Both ranges came up empty. Sticky until something is freed.
const FREE_SCAN_FULL: u8 = 2;

/// Outcome of one budgeted pass over a range of the FAT.
enum FreeScan {
    /// This cluster's entry is free; `free_scan_cursor` is parked after it.
    Found(u32),
    /// The range was examined to its end and holds nothing free.
    Exhausted,
    /// The sector budget ran out first; `free_scan_cursor` says where to
    /// resume.
    Yield,
}

/// Sectors held by an FD's write-back scratch. A full run is one submit, so
/// the ceiling is the block contract's per-request maximum
/// ([`MAX_WRITE_NLB`] — one 4 KiB DMA page of LBAs).
///
/// Split by target: the coalescing win is a multi-sector-device concern, and
/// the scratch is per-FD (`MAX_OPEN_FILES` of them) inside a state arena every
/// module shares — 256 KiB of it on rp2350, where 8 sectors would cost 28 KiB
/// more than 1. Embedded keeps a single sector, which degenerates to a plain
/// write-back cache: `scratch_accepts` can never extend a run, so `span` stays
/// 1 and every path behaves as the unbatched one.
#[cfg(target_arch = "aarch64")]
const SCRATCH_SECTORS: usize = 8;
#[cfg(not(target_arch = "aarch64"))]
const SCRATCH_SECTORS: usize = 1;

/// Max sectors per WRITE packet. Matches `nvme::MAX_NLB` (one 4 KB PRP1
/// page of LBAs). The batcher folds up to this many contiguous data
/// sectors into a single request so the nvme driver can issue one Write
/// SQE per packet instead of one per sector. The packet itself is
/// drained downstream in 512 B chunks (see `drain_packet`) so it fits
/// any reasonable channel capacity without requiring hints.
const MAX_WRITE_NLB: u16 = 8;

// A scratch run is flushed in one submit, so it can never exceed what one
// request carries. Both track `nvme::MAX_NLB`.
const _: () = assert!(SCRATCH_SECTORS <= MAX_WRITE_NLB as usize);

/// Maximum files to enumerate
const MAX_FILES: usize = 128;

/// FAT32 reserved value marking the tail of an allocated chain when
/// written into a FAT entry. Any read-back entry with its low 28 bits
/// >= `FAT32_EOC` is treated as end-of-chain.
const FAT32_TAIL: u32 = 0x0FFF_FFFF;

// FAT32 cluster values
const FAT32_EOC: u32 = 0x0FFFFFF8; // End of cluster chain (>= this value)
const FAT32_MASK: u32 = 0x0FFFFFFF; // Mask for 28-bit cluster number

// Directory entry constants
const DIR_ENTRY_SIZE: usize = 32;
const ATTR_LONG_NAME: u8 = 0x0F;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_ARCHIVE: u8 = 0x20;

// ============================================================================
// State Machine States
// ============================================================================

/// FAT32 initialization phases (SD Physical Layer Simplified Spec §7).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum Fat32InitPhase {
    Idle = 0,
    WaitBlock0 = 1,
    ReadBoot = 2,
    WaitBoot = 3,
    ReadRoot = 4,
    WaitRoot = 5,
    ReadDirFat = 6,
    WaitDirFat = 7,
    ReadGptHeader = 8,
    WaitGptHeader = 9,
    ReadGptEntry = 10,
    WaitGptEntry = 11,
    Done = 12,
    /// Laying a fresh volume down: zeroing the reserved region, both FATs
    /// and the root cluster, a bounded run of sectors per step.
    FormatZero = 13,
    /// Writing the FAT heads, FSINFO, the backup boot record and, last, the
    /// boot sector itself.
    FormatMeta = 14,
}

// Reads flow through the synchronous FS_CONTRACT dispatch
// (`fat32_fs_dispatch`) and the per-FD scratch in `OpenFile` — there
// is no per-step read state machine; the dispatch call walks the FAT
// chain in-line through `storage.block` `EXEC` reads.

// ============================================================================
/// FAT32 "clean shutdown" bit in cluster 1's FAT entry. When set the
/// filesystem was properly unmounted; when cleared Linux reports
/// "Dirty bit is set. Fs was not properly unmounted". See the FAT32
/// white paper and dosfstools `FAT32_CLN_SHUT_BIT_MASK`.
const CLN_SHUT_BIT: u32 = 0x0800_0000;

/// `ENODEV` — the device behind this provider is not the one the graph
/// asked for. Distinct from `ENOSYS`: the operation exists, the volume does
/// not, and no fallback is appropriate.
const E_NODEV: i32 = -19;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::p_u32;
    use super::Fat32State;
    use super::SCHEMA_MAX;

    define_params! {
        Fat32State;

        1, path, str, 0
            => |s, d, len| {
                if len > 0 && len < 64 {
                    let dst = s.path.as_mut_ptr();
                    let mut i = 0;
                    while i < len {
                        *dst.add(i) = *d.add(i);
                        i += 1;
                    }
                    *dst.add(len) = 0;
                }
            };

        2, pattern, str, 0
            => |s, d, len| {
                if len > 0 && len < 16 {
                    let dst = s.pattern.as_mut_ptr();
                    let mut i = 0;
                    while i < len {
                        *dst.add(i) = *d.add(i);
                        i += 1;
                    }
                    *dst.add(len) = 0;
                }
            };

        5, namespace, u32, 1
            => |s, d, len| { s.namespace = p_u32(d, len, 0, 1); };

        // When non-zero, on mount the synchronous write path's free-cluster
        // scan resumes from this cluster (and the value is persisted to the
        // FSINFO next-free hint). Operational override for a volume whose low
        // clusters are a long run of allocated/orphaned entries: seeding the
        // hint past that region keeps the first allocation O(1) instead of
        // scanning thousands of FAT entries. Clusters at/after the hint must
        // actually be free.
        8, init_free_hint, u32, 0
            => |s, d, len| { s.init_free_hint = p_u32(d, len, 0, 0); };

        // When non-zero (and `init_free_hint` set), the first create zeros the
        // FAT entries for `[init_free_hint, init_free_hint + clear_free_region)`
        // in every FAT copy, making that span free, before seeding the scan
        // there. Reclaims a span of a volume whose FAT region holds stale /
        // never-formatted (non-zero) entries the free-cluster scan would
        // otherwise treat as allocated. Keep small (a few hundred clusters) so
        // it fits one create's cooperative step budget; the span only needs to
        // cover the writer's working set. The region must not overlap real data
        // (pick a high, unused `init_free_hint`).
        9, clear_free_region, u32, 0
            => |s, d, len| { s.clear_free_region = p_u32(d, len, 0, 0); };

        // When non-zero, the first create truncates the root directory to one
        // empty cluster (zero cluster 2's sectors, set FAT[2]=EOC) before
        // scanning it. Reclaims a root dir bloated by orphaned entries: the dir
        // walk then touches one warm (just-written) cluster instead of many
        // cold ones — a cold first-touch read of a dir cluster can exceed the
        // cooperative step guard. CLEAN-SLATE ONLY: discards existing root-dir
        // entries; do not set where on-disk files must survive a remount.
        10, clean_root, u32, 0
            => |s, d, len| { s.clean_root = p_u32(d, len, 0, 0); };

        // Instance selector for multi-volume routing. When set (e.g.
        // `volume: "nvme0"`), this fat32 registers as a KEYED FS provider
        // the `mount` module binds by name via `provider_bind`, letting a
        // boot volume and a data volume coexist without shadowing. Absent →
        // selector 0 = the single default FS provider (unchanged). The hash
        // is the shared `provider_selector::hash` so the module's declared
        // key and the mount's `provider_bind("nvme0")` query agree.
        11, volume, str, 0
            => |s, d, len| {
                if len > 0 {
                    s.selector = super::hash_selector(d, len);
                }
            };

        // Volume serial number (`BS_VolID`, as `mkfs.vfat` reports it and
        // `blkid` prints it) that this graph expects to find. When set, the
        // destructive parameters above — `clean_root` and
        // `clear_free_region` — only take effect on a volume whose serial
        // matches, and every operation is refused on one that does not.
        //
        // This exists because a graph that says "wipe the root of the volume
        // on this channel" is one topology edit away from wiping a different
        // volume, and the two are indistinguishable to the module. Naming
        // the volume makes the destructive intent specific rather than
        // positional. Absent → no check, and the destructive parameters are
        // refused outright, which is the fail-closed default.
        12, expect_volume_id, u32, 0
            => |s, d, len| { s.expect_volume_id = p_u32(d, len, 0, 0); };

        // Handles one owner may hold at once. 0 = no per-owner ceiling, only
        // the provider-wide table. A shared table with no per-owner bound
        // means one workload leaking handles exhausts it for everybody, and
        // the `ENFILE` lands on whichever module asked next rather than on
        // the one at fault.
        13, max_open_per_owner, u32, 0
            => |s, d, len| { s.max_open_per_owner = p_u32(d, len, 0, 0); };

        // 1 = lay a fresh FAT32 volume on a source that holds none. Only a
        // source whose first sector is entirely zero is formatted: a blank
        // device, such as a fresh `crypt_block` container. A first sector
        // with any content — a FAT32 volume, a partition table, another
        // filesystem's data — is never overwritten, whatever this says. The volume spans the whole
        // source; the source must serve `storage.block` requests (the
        // streaming-only `sd` path cannot be written this way).
        14, format, u32, 0
            => |s, d, len| { s.format = p_u32(d, len, 0, 0) as u8; };

        // Sectors per cluster for a volume `format` lays: a power of two up
        // to 128, as `mkfs.vfat -s` takes it. 0 = the FAT32 specification's
        // table for the source's size. A size that leaves the volume outside
        // FAT32's cluster-count range is refused, and nothing is formatted.
        15, format_cluster_sectors, u32, 0
            => |s, d, len| { s.format_spc = p_u32(d, len, 0, 0).min(255) as u8; };
    }
}

// ============================================================================
// File Entry
// ============================================================================

/// Info about an enumerated file
#[repr(C)]
#[derive(Clone, Copy)]
struct FileEntry {
    /// Starting cluster
    start_cluster: u32,
    /// File size in bytes
    size: u32,
    /// Absolute LBA of the 512-byte sector holding this file's 32-byte
    /// directory entry. Captured during enumeration so the write path
    /// can re-read that exact sector for the size-field update without
    /// re-walking the directory.
    dir_lba: u32,
    /// Byte offset of the 32-byte entry inside `dir_lba`.
    dir_offset: u16,
    /// Short 8.3 name as stored in the directory entry: 8 name bytes
    /// padded with spaces, then 3 extension bytes. Used by the write
    /// path to locate a file by name.
    short_name: [u8; 11],
    _pad: u8,
}

impl FileEntry {
    const fn empty() -> Self {
        Self {
            start_cluster: 0,
            size: 0,
            dir_lba: 0,
            dir_offset: 0,
            short_name: [b' '; 11],
            _pad: 0,
        }
    }
}

/// Maximum concurrent FDs the FS_CONTRACT dispatch can hand out.
///
/// Split by target, because the pressure is not the same on both. A
/// multi-tenant node runs several independent consumers against one volume
/// at once — a consensus WAL, its snapshot writer, an object body store, a
/// firmware staging area — and each holds handles for as long as its own
/// work takes. Eight slots shared between them means one busy consumer
/// starves the rest, and the caller that loses gets `ENFILE` with nothing
/// to say which of its neighbours took the slots. On a microcontroller the
/// consumer set is fixed and small, and each slot costs a scratch buffer
/// out of a 256 KiB arena, so the tight bound is the right one there.
///
/// The table is provider-wide and shared between owners, which is why the
/// `max_open_per_owner` parameter exists: without a per-owner ceiling one
/// workload leaking handles takes the whole table down with it, and the
/// operator sees `ENFILE` on a module that did nothing wrong. The identity
/// comes from `query_key::CALLER_OWNER`, not from the dispatch arguments.
/// A replicated-state consumer is the demanding shape — it holds a
/// write-ahead log segment open per group plus a couple of metadata files,
/// so roughly three handles per group. Sixty-odd groups reach 192 before
/// any client workload opens a file of its own, which is why the aarch64
/// table is sized in hundreds rather than tens.
#[cfg(target_arch = "aarch64")]
const MAX_OPEN_FILES: usize = 256;
#[cfg(not(target_arch = "aarch64"))]
const MAX_OPEN_FILES: usize = 8;

/// Per-FD state for the FS_CONTRACT dispatch path. Scratch holds the
/// last 512 B sector served, so successive small `FS_READ` calls
/// don't re-fetch the same sector. The FAT walk fields (cluster +
/// sector_in_cluster) advance together with `offset`.
#[repr(C)]
#[derive(Clone, Copy)]
struct OpenFile {
    /// 1 = slot in use; 0 = free.
    in_use: u8,
    /// Owner that opened this handle — `(slot, generation)` from
    /// `query_key::CALLER_OWNER`, or `(u16::MAX, 0)` when the open happened
    /// outside a provider frame and there was nobody to charge.
    ///
    /// The generation is held with the slot deliberately: an owner slot is
    /// reused, and matching on the slot alone would charge a new workload for
    /// the handles of the dead one that preceded it.
    owner_slot: u16,
    owner_generation: u32,
    /// Sector index within current_cluster (0..sectors_per_cluster).
    sector_in_cluster: u8,
    /// 0 = regular file (FS_OPEN); 1 = directory (FS_OPENDIR).
    /// File slots use the OpenFile fields below for byte-level READ;
    /// dir slots reuse `current_cluster` + `sector_in_cluster` as the
    /// enumeration cursor and `offset` as the within-sector entry
    /// index. The shared slot pool means FS_CLOSE works uniformly.
    is_dir: u8,
    /// For dir slots only: 1 once the end-of-directory (0x00 entry)
    /// marker has been seen, so subsequent READDIR calls return 0
    /// without re-walking the FAT chain.
    dir_eof: u8,
    /// Cluster currently being read (FAT chain walk position).
    current_cluster: u32,
    /// Read offset within the file (bytes). 0..size.
    offset: u32,
    /// Total file size in bytes (cached at OPEN).
    size: u32,
    /// Starting cluster of the file (used for SEEK rewinds).
    start_cluster: u32,
    /// Bytes remaining in `scratch_block` from the most recent read.
    /// 0 means the next FS_READ must fetch a fresh sector.
    scratch_avail: u16,
    /// Read offset within `scratch_block` (= 512 - scratch_avail).
    scratch_pos: u16,

    // ── FS_CONTRACT write path (FS_OPEN_CREATE / FS_WRITE / FS_FSYNC) ──
    /// 1 = opened for append-writing via FS_OPEN_CREATE. Write ops
    /// reject FDs without this set. For a writable FD, `size` is the
    /// append cursor, `current_cluster` is the cluster holding byte
    /// `size`, and `start_cluster` is the chain head (0 = empty file).
    writable: u8,
    /// 1 = `size` / first-cluster grew since the last FS_FSYNC, so the
    /// directory entry needs writeback before the data is discoverable.
    dirty: u8,
    /// 1 once this handle's data + dir entry have been made device-durable
    /// by a successful FS_FSYNC; cleared on the next write. Drives the
    /// fence `QUERY_OP` so durability-aware callers observe `LocalDurable`
    /// after fsync rather than `Volatile`.
    durable: u8,
    /// 1 after FS_PREALLOCATE has made `size` a fixed physical capacity.
    /// Writes advance `offset` without growing `size`, so FS_FSYNC has no
    /// directory metadata to rewrite.
    fixed_capacity: u8,
    /// 1 when the complete preallocated chain is numerically contiguous.
    /// This lets the sequential writer advance clusters without a FAT read.
    fixed_contiguous: u8,
    /// 1 when `current_cluster` already points at the cluster holding byte
    /// `offset` (the READ/SEEK convention) rather than lagging one cluster
    /// behind it (the lazy append convention the write path assumes at a
    /// boundary). Set by FS_SEEK; consumed by the first FS_WRITE boundary so
    /// a seek onto a cluster boundary followed by a write does not advance the
    /// cursor twice and skip a cluster.
    cursor_positioned: u8,
    _pad_fixed: u16,
    /// Physical allocation bookkeeping used while PREALLOCATE extends the
    /// chain created by OPEN_CREATE.
    allocated_clusters: u32,
    allocation_tail: u32,
    /// Last-write time of the entry as Unix seconds when the handle was
    /// opened, reported by `FS_STAT`; 0 when the entry carries no stamp.
    mtime: u32,
    /// The 8.3 name this handle was opened under. Diagnostic only — the
    /// entry's location is what every operation actually addresses — but
    /// without it an exhausted handle table can only say that it is
    /// exhausted, never by what.
    name: [u8; 11],
    _pad_name: u8,
    /// Absolute LBA of the sector holding this file's 32-byte directory
    /// entry, and the byte offset of the entry within it. Captured at
    /// FS_OPEN_CREATE so FS_FSYNC/FS_CLOSE can patch the size + first
    /// cluster fields.
    dir_lba: u32,
    dir_off: u16,
    _pad_of: u16,
    /// Absolute LBA of the FIRST sector mirrored in `scratch_block`, or 0
    /// for none — LBA 0 is the MBR, never a file data sector. When a write
    /// or RMW targets a sector inside the mirrored run, the device read is
    /// skipped because `scratch_block` already mirrors it.
    /// Eliminates the read-after-write of a freshly-allocated cluster (a
    /// cold first-touch read can blow the cooperative step guard) on the
    /// append pattern where a length prefix and the payload share a sector,
    /// forcing an RMW of the sector just written.
    scratch_lba: u32,
    /// 1 when `scratch_block` holds appended data NOT yet written to the
    /// device at `scratch_lba`. Sequential small appends accumulate in
    /// `scratch_block` and the run is written once — when a write leaves it,
    /// at FS_FSYNC, or at FS_CLOSE. This
    /// collapses the per-append synchronous sector rewrite (a ~88-byte WAL
    /// entry would otherwise re-write its 512-byte sector ~6×) into one write
    /// per filled sector. Safe for the durability contract: un-fsynced bytes
    /// are not durable, so deferring their device write loses nothing a crash
    /// wouldn't already lose — FS_FSYNC flushes the pending sector first.
    scratch_dirty: u8,
    /// Sectors of `scratch_block` that mirror the device, starting at
    /// `scratch_lba`. 0 = nothing mirrored. Never exceeds `SCRATCH_SECTORS`.
    scratch_span: u8,
    /// Cluster the mirrored run belongs to, or 0 when the run came from the
    /// read path. A run only ever extends within one cluster, whose sectors
    /// are physically contiguous, so `scratch_lba .. +scratch_span` is a
    /// single device range and flushes in one submit.
    scratch_cluster: u32,
    /// What the block source is doing with `scratch_block` (`SIO_*`). While
    /// it is not `SIO_IDLE` the buffer is lent to the source — a read is
    /// landing in it, or a write is being taken from it on a source that
    /// does not copy at `SUBMIT` — and nothing may change it.
    scratch_io: u8,
    /// 1 when the run was written back from a buffer the source borrows, so
    /// collapsing it to its tail (`scratch_retain_tail`) waits for the write
    /// to complete.
    scratch_compact: u8,
    /// 1 while a background operation (`PREALLOCATE`) owns this FD's chain.
    op_busy: u8,
    /// 1 while this FD is being read sequentially: the step keeps its
    /// read-ahead going.
    ra_on: u8,
    /// Offset the last `READ` ended at, plus one (0 = none): a read starting
    /// there is sequential and earns read-ahead; one after a seek does not.
    ra_next: u32,
    /// Sectors, first sector and cluster of the read landing in
    /// `scratch_block`; they become the mirror when it completes.
    rd_span: u8,
    rd_lba: u32,
    rd_cluster: u32,
    /// Sequence of the last write submitted from `scratch_block`.
    scratch_seq: u64,
    /// A device failure on this FD's own data, reported by its next call.
    io_err: i32,
    /// Bumped by every `WRITE`, so an `FSYNC` decision is only handed back
    /// to a re-ask that covers the same bytes.
    write_gen: u32,
    /// The plain `FSYNC` taken on this FD: the epoch whose durability
    /// decides it (0 = none taken), the `write_gen` it covers, and the size
    /// and first cluster it publishes.
    fsync_epoch: u32,
    fsync_wgen: u32,
    fsync_size: u32,
    fsync_start: u32,
    /// Largest file size this FD has submitted into its directory entry on
    /// the device. The async metadata stage only rewrites the entry when a
    /// ticket's snapshot exceeds it, so out-of-order polls can never move
    /// the on-media size frontier backwards.
    dir_media_size: u32,
    /// Largest file size proven on non-volatile media in this FD's
    /// directory entry. A ticket whose snapshot is already covered by it
    /// needs no metadata stage at all — the preallocated fixed-capacity
    /// case, where the entry never changes.
    dir_durable_size: u32,
    /// First cluster proven on non-volatile media alongside
    /// `dir_durable_size`. Both fields must match a ticket's snapshot
    /// before its metadata stage can be skipped.
    dir_durable_start: u32,
    /// Write-back / read scratch for this FD. Holds `scratch_span`
    /// contiguous sectors starting at `scratch_lba`.
    ///
    /// Last, so the fields above it — everything a transaction may have to
    /// put back (see [`TxSave`]) — are one contiguous prefix.
    scratch_block: [u8; BLOCK_SIZE * SCRATCH_SECTORS],
}

/// `OpenFile::scratch_io`: the buffer is the provider's.
const SIO_IDLE: u8 = 0;
/// A read is landing in it.
const SIO_READ: u8 = 1;
/// A write is being taken from it by a source that borrows the buffer.
const SIO_WRITE: u8 = 2;

/// `OpenFile::in_use`: the slot is free.
const OF_FREE: u8 = 0;
/// The slot is an open handle.
const OF_OPEN: u8 = 1;
/// Closed by its caller, with write-back still to do or a device request
/// still holding its buffer. Not a handle any more — every operation on it
/// answers as for a closed one — and not free until the step finishes it.
const OF_DETACHED: u8 = 2;

impl OpenFile {
    const fn empty() -> Self {
        Self {
            in_use: 0,
            owner_slot: OWNER_NONE,
            owner_generation: 0,
            sector_in_cluster: 0,
            is_dir: 0,
            dir_eof: 0,
            current_cluster: 0,
            offset: 0,
            size: 0,
            start_cluster: 0,
            scratch_avail: 0,
            scratch_pos: 0,
            writable: 0,
            dirty: 0,
            durable: 0,
            fixed_capacity: 0,
            fixed_contiguous: 1,
            cursor_positioned: 0,
            _pad_fixed: 0,
            allocated_clusters: 0,
            allocation_tail: 0,
            mtime: 0,
            name: [b' '; 11],
            _pad_name: 0,
            dir_lba: 0,
            dir_off: 0,
            _pad_of: 0,
            scratch_lba: 0,
            scratch_dirty: 0,
            scratch_span: 0,
            scratch_cluster: 0,
            scratch_io: SIO_IDLE,
            scratch_compact: 0,
            op_busy: 0,
            ra_on: 0,
            ra_next: 0,
            rd_span: 0,
            rd_lba: 0,
            rd_cluster: 0,
            scratch_seq: 0,
            io_err: 0,
            write_gen: 0,
            fsync_epoch: 0,
            fsync_wgen: 0,
            fsync_size: 0,
            fsync_start: 0,
            dir_media_size: 0,
            dir_durable_size: 0,
            dir_durable_start: 0,
            scratch_block: [0u8; BLOCK_SIZE * SCRATCH_SECTORS],
        }
    }
}

// ============================================================================
// Module State
// ============================================================================

#[repr(C)]
struct Fat32State {
    syscalls: *const SyscallTable,
    /// Provider instance selector (FNV-1a hash of the `volume:` param).
    /// `0` when no `volume:` is given → this fat32 is the single unkeyed
    /// (default) FS provider. Non-zero → a keyed volume
    /// backend the `mount` module reaches via `provider_bind`. Exposed to
    /// the loader through the `module_provider_selector` export.
    selector: u32,
    /// Channel handle for the upstream block source (nvme.blocks /
    /// sd.blocks). Every sector read — init MBR/boot/dir, write-path
    /// FAT walks, FS_CONTRACT sync block reads — flows through this
    /// channel via ioctls on the producer side.
    in_chan: i32,
    /// `storage.block` requests on `in_chan`, and the pipelined writes and
    /// fences built from them.
    blk: BlockClient,

    // FAT32 geometry (from boot sector)
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    fat_size_32: u32,
    root_cluster: u32,
    fat_start_sector: u32,
    data_start_sector: u32,
    /// Count of addressable data clusters (`(total_sectors - metadata) /
    /// sectors_per_cluster`). Valid cluster numbers are `2 ..= count + 1`. 0
    /// if not derived from the BPB; the FAT's entry capacity is used as a
    /// fallback ceiling then. See `cluster_count_ceiling`.
    count_of_clusters: u32,
    /// Absolute LBA of this volume's first sector on the device.
    ///
    /// 64-bit while every other sector number in this state is a 32-bit
    /// offset *within* the volume. That split is deliberate: FAT32 caps a
    /// volume at 2 TiB, so in-volume arithmetic genuinely fits in 32 bits —
    /// but nothing caps where the volume sits, and a partition beyond 2 TiB
    /// on a large device is ordinary. Keeping the base wide and the offsets
    /// narrow puts the width exactly where the format does not bound it.
    partition_lba: u64,
    /// Sector number of the FSINFO sector relative to `partition_lba`,
    /// from BPB_FSInfo (boot-sector offset 48). `0` or `0xFFFF` means
    /// the volume has no FSINFO sector and the free-cluster bookkeeping
    /// is skipped on alloc.
    fsinfo_sector: u16,

    // State machine
    init_phase: Fat32InitPhase,

    // File enumeration — populated at init when `path:` is non-empty,
    // for the index-addressed streaming surface. The FS_CONTRACT path
    // walks the directory tree on demand and does not consult `files`.
    file_count: u16,
    files: [FileEntry; MAX_FILES],

    // Configuration
    path: [u8; 64],
    pattern: [u8; 16],

    // Directory enumeration state — read by `init_step` to populate
    // `s.files[]`. Idle in steady state.
    dir_cluster: u32,
    dir_sector_in_cluster: u8,
    dir_entry_in_sector: u8,
    dir_mode: u8,
    path_pos: u8,

    // Block I/O state. `block_buf` stages the metadata sector currently
    // being read or modified; `fat_buf` caches the FAT sector the chain
    // walk is reading. The FS dispatch maintains its own per-FD data
    // scratch in `OpenFile`.
    pending_block: u64,
    block_offset: u16,
    read_fill: u16,
    block_buf: [u8; BLOCK_SIZE],
    /// Absolute LBA whose contents `block_buf` currently holds, or
    /// [`LBA_NONE`].
    ///
    /// Two separate things depend on this tag. The obvious one is cost: a
    /// directory scan, a free-cluster scan and a read-modify-write of the
    /// same sector each re-read it, and every one of those reads is a
    /// synchronous device round trip inside a single `provider_call`.
    ///
    /// The less obvious one is that it makes the staging buffer's lifetime
    /// *stateable*. Without a tag, helpers can only hand the buffer to each
    /// other implicitly — "the free scan leaves the FAT sector here, so the
    /// caller may patch it" — which holds only while every operation runs to
    /// completion without yielding. With the tag, a caller that needs a
    /// sector asks for it, and the call costs nothing when the assumption
    /// held.
    block_buf_lba: u32,
    /// FAT sector cached for the cluster-chain walk, and the LBA it holds.
    ///
    /// Separate from `block_buf` because chain walking interleaves with
    /// directory reads — `fs_scan_dir` reads a directory sector, follows the
    /// FAT to the next directory cluster, reads a directory sector again. A
    /// single staging buffer thrashes on exactly that pattern, which is the
    /// one that matters for a directory large enough to span clusters.
    ///
    /// This is the *only* buffer through which a FAT sector is read or
    /// written. `block_buf` stages directory entries, FSINFO and the boot
    /// sector; nothing else may stage a FAT sector, which is what makes the
    /// write-back below safe to reason about.
    fat_buf: [u8; BLOCK_SIZE],
    fat_buf_lba: u32,
    /// Non-zero when `fat_buf` holds entries that are not yet on media.
    ///
    /// FAT sectors are written back, not through. A 512-byte sector holds
    /// 128 entries, so a sequential append crosses 128 cluster boundaries
    /// inside one sector; writing through costs `num_fats` sector writes at
    /// every one of them, and every write after the first is redundant.
    ///
    /// What makes deferral safe is the order it is flushed in, not the
    /// deferral itself. A dirty FAT sector is written before any directory
    /// sector is published ([`fs_write_staged`]), before any device flush or
    /// fence, and before the volume is marked clean. So the only state a
    /// crash can expose is *clusters linked in memory that never reached
    /// media* — and because the entry that would reference them has not been
    /// published either, the file is simply shorter. That is the same
    /// allocation-before-publish window the module already declares, made
    /// narrower rather than wider: links that never reached media cannot
    /// leak the clusters they described.
    fat_dirty: u8,

    /// Diagnostic step counter — the activity denominator in `[fat32] tlm`
    /// output. Timing is wall-clock.
    tick_count: u32,
    last_observe_ms: u64,

    /// NVMe namespace id used by the block ioctls. `0` forwards to the
    /// consumer's driver-wide default (nvme falls back to its own
    /// `namespace` param in that case).
    namespace: u32,

    /// Open-file slots backing the FS_CONTRACT dispatch path. Each
    /// slot is independent — multiple consumers can open multiple
    /// files concurrently (HTTP parallel range reads, etc.). Block
    /// I/O is shared (single nvme.blocks channel) but the FS_READ
    /// path uses `storage.block` `EXEC` reads, which are fully
    /// synchronous and serialize within each dispatch call.
    open_files: [OpenFile; MAX_OPEN_FILES],

    /// Linear free-cluster allocation hint for the synchronous FS write
    /// path. Starts at 2 and advances past every cluster handed out, so
    /// sequential appends don't rescan the FAT from the start each time.
    /// Only a hint — `fs_alloc_cluster` still verifies the entry is free.
    next_free_hint: u32,
    /// Next cluster the budgeted free-cluster scan will examine, and which
    /// of its two ranges it is in (`FREE_SCAN_*`). Persisting these across
    /// dispatches is what makes a bounded scan converge instead of restarting
    /// from the hint on every retry and never reaching the free space.
    free_scan_cursor: u32,
    free_scan_phase: u8,
    /// Handles one owner may hold at once (param `max_open_per_owner`);
    /// 0 disables the per-owner ceiling.
    max_open_per_owner: u32,
    /// Set by `fs_find_free_cluster` when it returned 0 because its sector
    /// budget ran out rather than because the volume is full. The two are
    /// `EAGAIN` and `ENOSPC` respectively, and a consumer that conflates
    /// them either spins on a full volume or gives up on a busy one.
    alloc_yield: u8,
    /// Mount-time override for `next_free_hint` (param `init_free_hint`);
    /// persisted to FSINFO once at init. 0 = unset.
    init_free_hint: u32,
    /// Clusters to zero in the FAT starting at `init_free_hint` on first
    /// create (param `clear_free_region`); reclaims a span of a garbage FAT.
    clear_free_region: u32,
    /// When non-zero (param `clean_root`), the FIRST OPERATION after mount
    /// truncates the root directory to one empty, warm cluster — avoids
    /// cold-read scans of a bloated root dir. Bench/clean-slate only.
    ///
    /// First operation, not first create: consumers that read at boot
    /// (replay, restore, recovery) open files before any create runs, so a
    /// wipe deferred to the first create would delete files those readers
    /// have already adopted and leave them serving state whose backing
    /// files no longer exist. Wiping ahead of the first read of any kind is
    /// what makes a clean-slate mount coherent: every reader sees the same
    /// empty root the first writer does.
    clean_root: u32,
    /// One-shot latch for the `clean_root` wipe (0 = not yet performed).
    root_cleaned: u32,

    /// One-shot latch for the rename-intent replay (0 = not yet performed).
    /// The replay runs at the dispatch chokepoint ahead of the first
    /// operation of any kind, so no reader can observe a directory still
    /// carrying an interrupted rename's intermediate state.
    rename_recovered: u32,

    /// Device rc recorded by the synchronous FS_CONTRACT helpers when a
    /// block read/write fails inside an Option/sentinel-returning
    /// function (`fs_dir_lookup`, `fs_scan_dir`, `fs_alloc_extent`, …)
    /// whose signature cannot carry an errno. Cleared at each
    /// FS_CONTRACT entry point; consulted by `fs_io_errno` so a device
    /// failure is not collapsed into a hard ENOENT/EIO/ENOSPC — which
    /// durability-grade callers rightly treat as fatal (quarantine), or
    /// worse, as "file missing" (truncate-create over a live file).
    io_rc: i32,

    /// Volume serial number (`BS_VolID`) read from the boot sector at mount.
    volume_id: u32,
    /// Serial the graph declared it expects (param `expect_volume_id`), or 0
    /// when it declared none.
    expect_volume_id: u32,
    /// Latch for the serial-mismatch report, so a refusal that repeats on
    /// every call is described once.
    volume_mismatch_logged: u8,
    /// Free clusters on the volume, and whether that number is trustworthy.
    /// Maintained incrementally; see [`fs_free_count_add`].
    free_count: u32,
    free_count_known: u8,
    /// 1 when FAT[1]'s ClnShutBit is set on media (the volume is recorded as
    /// cleanly shut down), 0 when it is clear. Mirrors media so the bit is
    /// written only on a transition.
    volume_clean: u8,
    /// Host-test measurement aid: when non-zero the sector tags never hit,
    /// so every read reaches the device. Always 0 in a firmware build.
    cache_defeated: u8,
    /// Set by any mutation; consumed by the background step once the volume
    /// falls quiet, which is when the free summary and the clean mark are
    /// published.
    fs_settle_pending: u8,
    _pad_settle: u8,

    /// Param `format`: 1 lays a fresh volume on a source holding none.
    format: u8,
    /// 1 when the block source serves `storage.block` requests, so the mount
    /// reads its sectors through them instead of the streaming channel.
    sync_src: u8,
    /// Param `format_cluster_sectors`: 0 = the specification's table.
    format_spc: u8,
    _pad_fmt: u8,
    /// Result of the mount's last synchronous sector read, reported by the
    /// phase that consumes it.
    sync_rc: i32,
    /// Format in progress: the geometry being laid down and how far it got.
    fmt: FormatPlan,

    /// Position of a directory walk that ran out of step budget, so the
    /// next call continues instead of starting over. See [`DirCursor`].
    dir_cursor: DirCursor,
    /// Parked walks (see [`DIR_CURSOR_POOL`]): a walk that yielded `Pending`
    /// is kept here so another name's lookup in between does not restart it.
    dir_cursor_pool: [DirCursor; DIR_CURSOR_POOL],

    /// Chain heads queued by `FS_UNLINK` for lazy freeing, drained by
    /// `fs_step_free_chains` one FAT-sector batch per step. Each slot is
    /// the next cluster to free in that chain (the cursor advances across
    /// steps for chains spanning FAT sectors); 0 = slot empty. A full ring
    /// orphans the chain instead (logged) — the same safe posture as
    /// create-truncate, namespace removal always wins over reclaim.
    unlink_free: [u32; UNLINK_FREE_SLOTS],
    /// When the current dispatch or step began (`dev_micros`), so a walk can
    /// stop on elapsed time as well as on sectors read (see
    /// [`CALL_BUDGET_US`]).
    call_t0: u64,
    /// How far the steps have settled the mount: 0 nothing, 1 FSINFO read,
    /// 2 clean bit read; the rename replay, which sets `rename_recovered`,
    /// ends it.
    settle_stage: u8,
    /// Recently resolved directory components (see [`DIR_CACHE`]).
    dir_cache: [DirCacheEntry; DIR_CACHE],
    dir_cache_next: u8,
    /// Reads served as whole-sector runs straight to the caller, and
    /// single-sector refills (telemetry).
    rd_runs: u32,
    rd_sectors: u32,

    /// Outstanding asynchronous durability fences (`FSYNC_SUBMIT` /
    /// `FSYNC_POLL`). One table for the whole provider: a ticket names a
    /// slot in it, so the poll path recovers the file-size frontier the
    /// submit snapshotted instead of reading the FD's mutable state.
    fences: [FenceSlot; MAX_FENCES],

    /// The sector cache every metadata read and write goes through (see
    /// "Sector cache, write-back and transactions"), its slots' data, and
    /// the counters that order versions and evictions.
    cache: [CacheSlot; CACHE_SLOTS],
    cache_data: [[u8; BLOCK_SIZE]; CACHE_SLOTS],
    cache_ver: u32,
    cache_stamp: u32,
    /// Bumped at every dispatch and step. A slot touched under the current
    /// value is not evicted, so what one call looked at stays for its own
    /// later steps.
    call_gen: u32,
    /// Set when this call needed a sector that was not in the cache (its
    /// read is now under way) or a resource that was momentarily full.
    miss: u8,
    /// 1 while a transaction is open (see [`fs_tx`]).
    tx_active: u8,
    /// Ask the write-back to close the open epoch on its next pass.
    wb_kick: u8,
    /// Boundaries the open transaction has closed, and whether it asked for
    /// more than `TX_BARRIER_MAX`.
    tx_barriers: u8,
    tx_overflow: u8,
    /// A queued FAT clear (param `clear_free_region`): next cluster, end.
    clear_next: u32,
    clear_end: u32,
    /// Sectors after the one asked for that a miss reads in the same
    /// request: the caller's read-ahead, set around one access.
    ra_hint: u32,
    /// The open epoch holds a FAT write, so a directory sector written now
    /// waits for it (FAT before the directory entry that references it).
    epoch_has_fat: u8,
    /// Write-back epochs. Every cache write carries `epoch`; the engine
    /// writes epoch `wb_epoch` and moves on only once all of it completed —
    /// and, across a durable boundary, once a flush covering it completed.
    /// `durable_through` is the last epoch known to be on media.
    epoch: u32,
    wb_epoch: u32,
    durable_through: u32,
    /// First write-back failure, latched: the cache then describes a state
    /// the media does not hold, and nothing may claim durability again.
    wb_err: i32,
    /// Bit `e % 64` set: the boundary after epoch `e` is durable.
    durable_bits: u64,
    /// The flush fence the engine is waiting on at a durable boundary.
    wb_ticket: u64,
    wb_ticket_live: u8,
    /// The mount's own sector read: 0 idle, 1 in flight, 2 landed.
    mount_rd: u8,
    _pad_wb: [u8; 2],
    mount_rc: i32,
    /// When the open epoch first took a write (`dev_millis`), 0 = clean.
    open_dirty_ms: u64,
    /// Sector ranges queued to be zeroed (a new directory cluster), and the
    /// zeroes they are written from.
    zero_runs: [ZeroRun; ZERO_RUN_SLOTS],
    zero_buf: [u8; ZERO_BUF_SECTORS * BLOCK_SIZE],
    /// Epoch whose writes retired the name of each `unlink_free` chain: the
    /// chain is freed only once that epoch has reached the device.
    unlink_epoch: [u32; UNLINK_FREE_SLOTS],
    /// Operations taken and not yet decided, or decided and not yet
    /// collected (`EINPROGRESS`).
    ops: [OpSlot; FS_OP_SLOTS],
    /// Each op slot's argument bytes, compared in full on a re-ask.
    op_args: [[u8; OP_ARG_MAX]; FS_OP_SLOTS],
    /// The epoch the operation that just committed waits on, set by it.
    op_wait_epoch: u32,
    /// Resumable position of a `TRUNCATE`'s walk to its new tail.
    trunc_walk: TruncWalk,
    /// What an open transaction puts back if it aborts.
    tx: TxSave,
    /// Format progress: the write the next record waits on, and the flush
    /// fence a commit point waits on.
    fmt_seq: u64,
    fmt_ticket: u64,
    fmt_ticket_live: u8,
    _pad_fmt2: [u8; 7],

    /// Hot-path counters emitted as `[fat32] tlm dt=… rx=… tx=… idle=… bp=…`
    /// every `FAT32_TLM_PERIOD` steps. `rx` is bytes consumed from
    /// the upstream blocks channel (init walks + write-path FAT/dir
    /// reads); `tx` and `bp` are unused on this path because reads
    /// flow through the synchronous FS_CONTRACT dispatch.
    tlm: TlmCounters,
    tlm_scratch: [u8; TLM_LINE_BUF_SIZE],
}

/// Shared wall-clock cadence for native telemetry, heartbeat, and the TLM line.
const FAT32_OBSERVE_INTERVAL_MS: u64 = 5_000;

/// Concurrent unlinked-chain frees in flight (see `Fat32State::unlink_free`).
/// Sized for the expected caller (WAL segment compaction retires a handful of
/// segments per snapshot); overflow degrades to orphaning, never to blocking.
const UNLINK_FREE_SLOTS: usize = 8;

/// Asynchronous durability fences outstanding across all open files. Bounds
/// the pipelining depth `FSYNC_SUBMIT` will admit; a submit that finds the
/// table full returns `E_AGAIN` (backpressure) rather than silently reusing
/// a live ticket.
///
/// Sized against [`MAX_OPEN_FILES`] rather than fixed: a fence table smaller
/// than the handle table means a consumer that opened a handle successfully
/// can still be unable to fence it, which reads as a durability failure
/// rather than as the resource limit it is.
const MAX_FENCES: usize = MAX_OPEN_FILES;

/// A fence whose covered data writes are still in flight.
const FENCE_STAGE_DATA: u8 = 1;
/// A fence whose data is durable and whose directory-entry write is in
/// flight behind a second device fence.
const FENCE_STAGE_META: u8 = 2;

/// One outstanding `FSYNC_SUBMIT` fence.
///
/// The size and first cluster are snapshotted at submit because an
/// asynchronous caller may issue further writes — growing the file — before
/// it polls this ticket. Publishing the FD's *current* directory state on
/// completion would attribute a newer size frontier to an older fence, and
/// that newer frontier's data is not covered by the device fence this ticket
/// represents.
#[derive(Clone, Copy)]
#[repr(C)]
struct FenceSlot {
    /// 0 = free, otherwise `FENCE_STAGE_DATA` / `FENCE_STAGE_META`.
    stage: u8,
    /// Owning `open_files` index.
    file: u8,
    /// Incremented every time the slot is allocated, so a ticket held across
    /// a close/reuse is rejected instead of resolving onto another file.
    generation: u16,
    /// File size at submit — the frontier this ticket is answerable for.
    size: u32,
    /// First cluster at submit; the other directory-entry field a growing
    /// file can change.
    start_cluster: u32,
    /// Block-source ticket for the stage currently in flight.
    device_ticket: u64,
}

impl FenceSlot {
    const fn empty() -> Self {
        Self {
            stage: 0,
            file: 0,
            generation: 0,
            size: 0,
            start_cluster: 0,
            device_ticket: 0,
        }
    }
}

/// Encode a fence slot index + generation into the opaque `u64` ticket the
/// contract hands the caller. Index is stored biased by one so a valid
/// ticket is never 0 — `FSYNC_SUBMIT` reserves 0 for "nothing to fence".
fn fence_ticket_encode(idx: usize, generation: u16) -> u64 {
    ((generation as u64) << 32) | (idx as u64 + 1)
}

/// Resolve a caller ticket back to a live fence slot owned by `file`.
/// Returns `None` for a malformed, stale, or foreign ticket.
fn fence_ticket_slot(s: &Fat32State, ticket: u64, file: usize) -> Option<usize> {
    let idx = (ticket & 0xFFFF_FFFF) as usize;
    if idx == 0 || idx > MAX_FENCES {
        return None;
    }
    let idx = idx - 1;
    let f = &s.fences[idx];
    if f.stage == 0 || f.file as usize != file {
        return None;
    }
    if f.generation as u64 != (ticket >> 32) {
        return None;
    }
    Some(idx)
}

impl Fat32State {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.selector = 0;
        self.in_chan = -1;
        self.bytes_per_sector = 512;
        self.sectors_per_cluster = 0;
        self.reserved_sectors = 0;
        self.num_fats = 0;
        self.fat_size_32 = 0;
        self.root_cluster = 0;
        self.fat_start_sector = 0;
        self.data_start_sector = 0;
        self.count_of_clusters = 0;
        self.partition_lba = 0;
        self.fsinfo_sector = 0;
        self.init_phase = Fat32InitPhase::Idle;
        self.next_free_hint = 2;
        self.free_scan_cursor = 0;
        self.free_scan_phase = FREE_SCAN_FORWARD;
        self.alloc_yield = 0;
        self.max_open_per_owner = 0;
        self.root_cleaned = 0;
        self.rename_recovered = 0;
        self.io_rc = 0;
        self.volume_id = 0;
        self.expect_volume_id = 0;
        self.volume_mismatch_logged = 0;
        self.free_count = 0;
        self.free_count_known = 0;
        // Unknown until the mount reads FAT[1]; treated as dirty so the
        // first mutation writes the mark rather than assuming it is there.
        self.volume_clean = 0;
        self.fs_settle_pending = 0;
        self.cache_defeated = 0;
        self.dir_cursor = DirCursor::empty();
        self.dir_cursor_pool = [DirCursor::empty(); DIR_CURSOR_POOL];
        self.format = 0;
        self.sync_src = 0;
        self.sync_rc = 0;
        self.fmt = FormatPlan::EMPTY;
        self.unlink_free = [0; UNLINK_FREE_SLOTS];
        self.call_t0 = 0;
        self.settle_stage = 0;
        self.dir_cache = [DirCacheEntry::EMPTY; DIR_CACHE];
        self.dir_cache_next = 0;
        self.rd_runs = 0;
        self.rd_sectors = 0;
        self.fences = [FenceSlot::empty(); MAX_FENCES];
        self.file_count = 0;
        self.dir_cluster = 0;
        self.dir_sector_in_cluster = 0;
        self.dir_entry_in_sector = 0;
        self.dir_mode = 0;
        self.path_pos = 0;
        self.pending_block = 0;
        self.block_offset = 0;
        self.read_fill = 0;
        self.block_buf_lba = LBA_NONE;
        self.fat_buf_lba = LBA_NONE;
        self.fat_dirty = 0;
        self.tick_count = 0;
        self.last_observe_ms = 0;
        self.namespace = 1;
        let mut i = 0usize;
        while i < MAX_OPEN_FILES {
            self.open_files[i] = OpenFile::empty();
            i += 1;
        }
        self.cache = [CacheSlot::EMPTY; CACHE_SLOTS];
        self.cache_ver = 0;
        self.cache_stamp = 0;
        self.call_gen = 0;
        self.miss = 0;
        self.tx_active = 0;
        self.wb_kick = 0;
        self.ra_hint = 0;
        self.epoch_has_fat = 0;
        self.epoch = 1;
        self.wb_epoch = 1;
        self.durable_through = 0;
        self.wb_err = 0;
        self.durable_bits = 0;
        self.wb_ticket = 0;
        self.wb_ticket_live = 0;
        self.mount_rd = 0;
        self.mount_rc = 0;
        self.open_dirty_ms = 0;
        self.zero_runs = [ZeroRun::EMPTY; ZERO_RUN_SLOTS];
        // The source of every zero run: it must read as zeroes for the life
        // of the module, and a reused state buffer need not.
        let mut z = 0usize;
        while z < ZERO_BUF_SECTORS * BLOCK_SIZE {
            self.zero_buf[z] = 0;
            z += 1;
        }
        self.unlink_epoch = [0; UNLINK_FREE_SLOTS];
        self.ops = [OpSlot::EMPTY; FS_OP_SLOTS];
        self.op_wait_epoch = 0;
        self.tx_barriers = 0;
        self.tx_overflow = 0;
        self.clear_next = 0;
        self.clear_end = 0;
        self.trunc_walk = TruncWalk::EMPTY;
        self.fmt_seq = 0;
        self.fmt_ticket = 0;
        self.fmt_ticket_live = 0;
        // path, pattern and files are zeroed by the kernel allocator.
    }

    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Read little-endian u16 from buffer (uses pointer arithmetic, no bounds check)
/// Caller must ensure offset+1 < buf.len()
#[inline(always)]
unsafe fn read_u16_le(buf: &[u8], offset: usize) -> u16 {
    let p = buf.as_ptr().add(offset);
    (*p as u16) | ((*p.add(1) as u16) << 8)
}

/// Read little-endian u32 from buffer (uses pointer arithmetic, no bounds check)
/// Caller must ensure offset+3 < buf.len()
#[inline(always)]
unsafe fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    let p = buf.as_ptr().add(offset);
    (*p as u32)
        | ((*p.add(1) as u32) << 8)
        | ((*p.add(2) as u32) << 16)
        | ((*p.add(3) as u32) << 24)
}

/// Write little-endian u32 into a buffer at `offset`.
#[inline(always)]
fn write_u32_le(buf: &mut [u8], offset: usize, value: u32) {
    let b = value.to_le_bytes();
    buf[offset] = b[0];
    buf[offset + 1] = b[1];
    buf[offset + 2] = b[2];
    buf[offset + 3] = b[3];
}

/// Convert cluster number to first sector number
#[inline(always)]
fn cluster_to_sector(s: &Fat32State, cluster: u32) -> u32 {
    s.data_start_sector + (cluster - 2) * (s.sectors_per_cluster as u32)
}

/// Exclusive upper bound for valid data-cluster numbers. Clusters are numbered
/// `2 ..= count_of_clusters + 1`, so the exclusive end is `count_of_clusters +
/// 2`, capped at the FAT's entry capacity. Falls back to FAT capacity when the
/// cluster count wasn't derived (non-standard BPB) so behaviour is never worse
/// than the old capacity-only bound. Allocators MUST scan below this so they
/// never hand out a FAT slack entry that maps past the end of the data area.
#[inline]
fn cluster_count_ceiling(s: &Fat32State) -> u32 {
    let eps = (s.bytes_per_sector as u32) / 4;
    let fat_cap = eps.saturating_mul(s.fat_size_32);
    if s.count_of_clusters == 0 {
        fat_cap
    } else {
        s.count_of_clusters.saturating_add(2).min(fat_cap)
    }
}

/// Get sector containing FAT entry for given cluster
/// Note: uses wrapping_div to avoid panic; bytes_per_sector is always valid after boot
#[inline(always)]
fn fat_sector_for_cluster(s: &Fat32State, cluster: u32) -> u32 {
    let bps = s.bytes_per_sector as u32;
    if bps == 0 {
        return s.fat_start_sector;
    }
    s.fat_start_sector
        .wrapping_add((cluster.wrapping_mul(4)).wrapping_div(bps))
}

/// Get offset within FAT sector for given cluster
/// Note: uses wrapping_rem to avoid panic; bytes_per_sector is always valid after boot
#[inline(always)]
fn fat_offset_for_cluster(s: &Fat32State, cluster: u32) -> usize {
    let bps = s.bytes_per_sector as u32;
    if bps == 0 {
        return 0;
    }
    ((cluster.wrapping_mul(4)).wrapping_rem(bps)) as usize
}

#[inline(always)]
unsafe fn log_info(s: &Fat32State, msg: &[u8]) {
    dev_log(s.sys(), 3, msg.as_ptr(), msg.len());
}

/// Seek the block source's stream to absolute `lba`.
///
/// Mount discovery over a source that is not a writable `storage.block`
/// source rides its streaming channel (see [`start_read`]). That seek is
/// `IOCTL_NOTIFY`, whose argument is four bytes, so this is the one place in
/// the provider that cannot express the full 64-bit address.
///
/// It refuses rather than truncates. A volume whose boot sector sits past
/// the 2 TiB a 32-bit seek can name is not mountable through a streaming
/// source, and saying so is the only honest answer; wrapping the address
/// would mount whatever happens to live at the aliased sector.
#[inline]
unsafe fn seek_block(s: &Fat32State, lba: u64) -> i32 {
    if lba > u64::from(u32::MAX) {
        return errno::EOVERFLOW;
    }
    let mut pos = lba as u32;
    let pos_ptr = &mut pos as *mut u32 as *mut u8;
    dev_channel_ioctl(s.sys(), s.in_chan, IOCTL_NOTIFY, pos_ptr, 4)
}

/// Flush SD's output buffer (our input)
#[inline]
unsafe fn flush_input(s: &Fat32State) -> i32 {
    dev_channel_ioctl(s.sys(), s.in_chan, IOCTL_FLUSH, core::ptr::null_mut(), 0)
}

/// Whether the block source is read through synchronous `storage.block`
/// requests rather than its stream.
///
/// A writable source with no read stream — a transform (`crypt_block`,
/// `loam_volume`) or a file-backed source (`file_block`) — has nothing to
/// answer a seek, so it is mounted and read through requests. A source that
/// offers `F_READ_STREAM` (`nvme`) is read through its stream: a directory
/// walk is many sectors, and one device round trip per sector in the
/// caller's step outlasts the step. A read-only source (`sd`) and one that
/// has not attached yet keep the streamed mount; [`init_step`] switches over
/// if it turns out to be a stream-less writable source.
unsafe fn writable_block_source(s: &Fat32State) -> bool {
    use abi::contracts::storage::block::caps as bc;
    s.blk.caps(&*s.syscalls) == 0
        && s.blk.flags() & bc::F_WRITE != 0
        && s.blk.flags() & bc::F_READ_STREAM == 0
}

/// Start the mount's read of absolute sector `lba` into `block_buf`; the
/// following `Wait*` phase collects it with [`try_read_block`].
///
/// A writable `storage.block` source (see [`writable_block_source`]) is read
/// through a submitted request, collected by a later step; anything else is
/// sought on the stream. Returns 0 when the read is under way (or done), 1
/// to retry next step, or a negative errno.
unsafe fn start_read(s: &mut Fat32State, lba: u64) -> i32 {
    if s.sync_src != 0 {
        if s.mount_rd == 1 {
            // The previous read is still landing in `block_buf`.
            return 1;
        }
        s.block_buf_lba = LBA_NONE;
        let buf = s.block_buf.as_mut_ptr();
        let rc = s.blk.submit_read(&*s.syscalls, lba, 1, buf, TAG_MOUNT);
        if rc == E_AGAIN {
            return 1;
        }
        if rc != 0 {
            s.sync_rc = rc;
            s.mount_rd = 2;
            s.read_fill = BLOCK_SIZE as u16;
            return 0;
        }
        s.mount_rd = 1;
        s.sync_rc = 0;
        s.read_fill = BLOCK_SIZE as u16;
        fs_route_reads(s);
        return 0;
    }
    flush_input(s);
    let rc = seek_block(s, lba);
    if rc < 0 {
        return rc;
    }
    s.read_fill = 0;
    0
}

// ============================================================================
// Boot Sector Parsing
// ============================================================================

/// Parse boot sector and extract FAT32 geometry
/// Note: uses pointer arithmetic to avoid bounds check panics.
unsafe fn parse_boot_sector(s: &mut Fat32State) -> bool {
    // Asked before the sector is borrowed; checked below with the format's
    // own sector size.
    let dev_bs = fs_device_block_size(s);
    let buf = &s.block_buf;

    // Check boot signature (use pointer arithmetic, no bounds check)
    let sig0 = *buf.as_ptr().add(510);
    let sig1 = *buf.as_ptr().add(511);
    if sig0 != 0x55 || sig1 != 0xAA {
        return false;
    }

    // Check for FAT32 (root_entry_count == 0 and fat_size_16 == 0)
    let root_entry_count = read_u16_le(buf, 17);
    let fat_size_16 = read_u16_le(buf, 22);
    if root_entry_count != 0 || fat_size_16 != 0 {
        return false; // Not FAT32
    }

    s.bytes_per_sector = read_u16_le(buf, 11);
    s.sectors_per_cluster = *buf.as_ptr().add(13);
    s.reserved_sectors = read_u16_le(buf, 14);
    s.num_fats = *buf.as_ptr().add(16);
    s.fat_size_32 = read_u32_le(buf, 36);
    s.root_cluster = read_u32_le(buf, 44);
    s.fsinfo_sector = read_u16_le(buf, 48);
    // Volume serial number (BS_VolID, offset 67). `mkfs` derives it from the
    // clock, so it is effectively unique per format and is the only
    // per-volume identity FAT32 carries. Used to bind the rename intent
    // record and the destructive mount parameters to the volume they were
    // meant for.
    s.volume_id = read_u32_le(buf, 67);

    // Derived sector numbers are relative to the start of the volume;
    // `partition_lba` is added once, at the point a device request is built.
    s.fat_start_sector = s.reserved_sectors as u32;
    s.data_start_sector = s.fat_start_sector + (s.num_fats as u32) * s.fat_size_32;

    // The volume's own sector size. This provider stages exactly one
    // 512-byte sector, and every failure-atomicity claim it makes — the
    // rename intent record, one directory entry per write — is a claim about
    // that unit.
    if s.bytes_per_sector as usize != BLOCK_SIZE {
        return false;
    }
    // And the device's. A 4Kn namespace turns a 512-byte sector write into a
    // read-modify-write of the enclosing 4 KiB block, which silently merges
    // eight sectors into one failure unit: two directory entries the format
    // placed in different sectors would stop being independent, and the
    // intent record's four-phase recovery would be reasoning about a unit
    // that no longer exists. Refusing is the honest answer — the alternative
    // is a volume that mounts and quietly stops providing the crash
    // semantics its consumers are built on. Zero means the source has not
    // attached yet; the mount is retried, not failed.
    if dev_bs != 0 && dev_bs as usize != BLOCK_SIZE {
        log_info(s, b"[fat32] device block size unsupported");
        return false;
    }
    if s.sectors_per_cluster == 0 {
        return false;
    }
    if s.root_cluster < 2 {
        return false;
    }

    // Real count of addressable data clusters (FAT32 §3.5). For FAT32 the
    // 16-bit total-sectors field is 0, so the 32-bit field at offset 32 holds
    // the count. The FAT can hold more entries than there are data clusters
    // (trailing slack), so the allocator must bound on this, not FAT capacity.
    let tot_sec_16 = read_u16_le(buf, 19) as u32;
    let tot_sec_32 = read_u32_le(buf, 32);
    let tot_sec = if tot_sec_16 != 0 {
        tot_sec_16
    } else {
        tot_sec_32
    };
    let meta_sectors =
        (s.reserved_sectors as u32).wrapping_add((s.num_fats as u32).wrapping_mul(s.fat_size_32));
    let data_sectors = tot_sec.saturating_sub(meta_sectors);
    s.count_of_clusters = data_sectors / (s.sectors_per_cluster as u32);

    true
}

/// Check if block 0 is an MBR and return LBA of first FAT32 partition, or 0.
unsafe fn parse_mbr(buf: &[u8]) -> u32 {
    let sig0 = *buf.as_ptr().add(510);
    let sig1 = *buf.as_ptr().add(511);
    if sig0 != 0x55 || sig1 != 0xAA {
        return 0;
    }

    // Scan 4 partition entries at offsets 446, 462, 478, 494
    let mut i = 0u32;
    while i < 4 {
        let entry = (446 + i * 16) as usize;
        let ptype = *buf.as_ptr().add(entry + 4);
        // 0x0B = FAT32 (CHS), 0x0C = FAT32 (LBA)
        if ptype == 0x0B || ptype == 0x0C {
            let lba = read_u32_le(buf, entry + 8);
            if lba > 0 {
                return lba;
            }
        }
        i += 1;
    }

    0
}

// ============================================================================
// Block Read / Name Matching Helpers
// ============================================================================

/// Try to fill block_buf from input channel, accumulating partial reads.
/// Returns 1 when full block ready, 0 when pending, -1 on error.
///
/// This is the asynchronous read path — the init walk and the one-shot
/// writer — and it fills `block_buf` without going through
/// [`fs_read_blockbuf`], so it drops the staging tag. Leaving the tag in
/// place would let a later FS-path read of that LBA hit a buffer holding
/// somebody else's sector.
#[inline]
unsafe fn try_read_block(s: &mut Fat32State) -> i32 {
    s.block_buf_lba = LBA_NONE;
    if s.sync_src != 0 {
        if s.mount_rd == 1 {
            s.blk.reap(&*s.syscalls);
            fs_route_reads(s);
        }
        if s.mount_rd == 1 {
            return 0;
        }
        s.mount_rd = 0;
        if s.sync_rc == 0 {
            s.sync_rc = s.mount_rc;
        }
        s.mount_rc = 0;
        return if s.sync_rc == 0 { 1 } else { -1 };
    }
    let poll = (s.sys().channel_poll)(s.in_chan, POLL_IN);
    if poll <= 0 || (poll as u32 & POLL_IN) == 0 {
        return 0;
    }
    let fill = s.read_fill as usize;
    let remaining = BLOCK_SIZE - fill;
    let buf = s.block_buf.as_mut_ptr().add(fill);
    let read = (s.sys().channel_read)(s.in_chan, buf, remaining);
    if read == E_AGAIN {
        return 0;
    }
    if read < 0 {
        return -1;
    }
    s.tlm.bytes_in = s.tlm.bytes_in.wrapping_add(read as u32);
    s.read_fill += read as u16;
    if (s.read_fill as usize) < BLOCK_SIZE {
        return 0;
    }
    1
}

#[inline(always)]
fn to_upper(c: u8) -> u8 {
    if c.is_ascii_lowercase() {
        c - 32
    } else {
        c
    }
}

/// Compare a name (with optional dot) against an 8.3 directory entry.
/// `name` points to name bytes, `name_len` is its length.
/// `entry` points to the 11-byte 8.3 filename field.
unsafe fn matches_83(name: *const u8, name_len: usize, entry: *const u8) -> bool {
    // Find dot position
    let mut dot = name_len;
    let mut i = 0;
    while i < name_len {
        if *name.add(i) == b'.' {
            dot = i;
            break;
        }
        i += 1;
    }

    // Name part (8 bytes, space-padded)
    i = 0;
    while i < 8 {
        let expected = if i < dot {
            to_upper(*name.add(i))
        } else {
            b' '
        };
        if *entry.add(i) != expected {
            return false;
        }
        i += 1;
    }

    // Extension part (3 bytes, space-padded)
    let ext_start = if dot < name_len { dot + 1 } else { name_len };
    let ext_len = name_len - ext_start;
    i = 0;
    while i < 3 {
        let expected = if i < ext_len {
            to_upper(*name.add(ext_start + i))
        } else {
            b' '
        };
        if *entry.add(8 + i) != expected {
            return false;
        }
        i += 1;
    }

    true
}

/// Check if entry extension matches a 3-byte uppercase extension at pp+offset.
/// Returns true if all 3 extension bytes match (space-padded).
#[inline(always)]
unsafe fn ext_matches(pp: *const u8, offset: usize, entry: *const u8) -> bool {
    let mut i = 0usize;
    let mut pi = offset;
    while i < 3 && *pp.add(pi) != 0 && *pp.add(pi) != b',' {
        if *entry.add(8 + i) != to_upper(*pp.add(pi)) {
            return false;
        }
        i += 1;
        pi += 1;
    }
    while i < 3 {
        if *entry.add(8 + i) != b' ' {
            return false;
        }
        i += 1;
    }
    true
}

/// Check if an 8.3 entry name matches a glob pattern.
/// Supports: empty (all), "*" (all), "*.ext" (by extension),
/// "*.ext,ext2,ext3" (comma-separated extensions), exact match.
unsafe fn pattern_matches(pattern: &[u8; 16], entry: *const u8) -> bool {
    let pp = pattern.as_ptr();
    let p0 = *pp;
    if p0 == 0 || (p0 == b'*' && *pp.add(1) == 0) {
        return true;
    }

    // "*.ext" or "*.ext,ext2,ext3" — match extension(s)
    if p0 == b'*' && *pp.add(1) == b'.' {
        // Try first extension at offset 2
        if ext_matches(pp, 2, entry) {
            return true;
        }
        // Scan for comma-separated alternatives
        let mut pi = 2usize;
        while pi < 15 && *pp.add(pi) != 0 {
            if *pp.add(pi) == b',' && ext_matches(pp, pi + 1, entry) {
                return true;
            }
            pi += 1;
        }
        return false;
    }

    // Exact 8.3 match
    let mut plen = 0usize;
    while plen < 15 && *pp.add(plen) != 0 {
        plen += 1;
    }
    matches_83(pp, plen, entry)
}

/// Prepare directory enumeration after boot sector parsed.
unsafe fn start_enumeration(s: &mut Fat32State) {
    s.dir_cluster = s.root_cluster;
    s.dir_sector_in_cluster = 0;
    s.dir_entry_in_sector = 0;
    s.file_count = 0;

    // Skip leading '/' in path
    let pp = s.path.as_ptr();
    s.path_pos = 0;
    while (s.path_pos as usize) < 63 && *pp.add(s.path_pos as usize) == b'/' {
        s.path_pos += 1;
    }

    s.dir_mode = if *pp.add(s.path_pos as usize) == 0 {
        1
    } else {
        0
    };
}

// ============================================================================
// Directory Parsing
// ============================================================================

/// Parse a directory entry from the buffer at given offset.
/// Returns true if it's a valid file entry (not LFN, not directory, not deleted).
/// Note: uses pointer arithmetic to avoid bounds check panics.
unsafe fn parse_dir_entry(s: &mut Fat32State, entry_offset: usize) -> bool {
    let buf = &s.block_buf;
    let buf_ptr = buf.as_ptr();

    // First byte: 0x00 = end of directory, 0xE5 = deleted
    let first = *buf_ptr.add(entry_offset);
    if first == 0x00 || first == 0xE5 {
        return false;
    }

    // Check attributes
    let attr = *buf_ptr.add(entry_offset + 11);
    if attr == ATTR_LONG_NAME {
        return false; // LFN entry, skip
    }
    if (attr & ATTR_DIRECTORY) != 0 {
        return false; // Directory, skip
    }
    if (attr & ATTR_VOLUME_ID) != 0 {
        return false; // Volume label, skip
    }

    // Apply pattern filter
    if !pattern_matches(&s.pattern, buf_ptr.add(entry_offset)) {
        return false;
    }

    // Extract cluster and size
    let cluster_hi = read_u16_le(buf, entry_offset + 20) as u32;
    let cluster_lo = read_u16_le(buf, entry_offset + 26) as u32;
    let cluster = (cluster_hi << 16) | cluster_lo;
    let size = read_u32_le(buf, entry_offset + 28);

    // Skip empty files
    if size == 0 || cluster < 2 {
        return false;
    }

    // Add to file list (use pointer arithmetic, no bounds check)
    let idx = s.file_count as usize;
    if idx < MAX_FILES {
        let file_ptr = s.files.as_mut_ptr().add(idx);
        (*file_ptr).start_cluster = cluster;
        (*file_ptr).size = size;
        // Capture the directory-sector LBA + entry offset so the
        // write path can re-read this exact sector when it needs to
        // patch the size field.
        (*file_ptr).dir_lba =
            cluster_to_sector(s, s.dir_cluster) + (s.dir_sector_in_cluster as u32);
        (*file_ptr).dir_offset = entry_offset as u16;
        // Copy the 11-byte short 8.3 name so the write-once path can
        // look the file up without re-parsing the directory.
        let mut i = 0usize;
        while i < 11 {
            (*file_ptr).short_name[i] = *buf_ptr.add(entry_offset + i);
            i += 1;
        }
        s.file_count += 1;
    }

    true
}

// ============================================================================
// FS_CONTRACT dispatch — fat32 as the bare-metal FS provider.
// ============================================================================
//
// Bare-metal counterpart to `linux_fs_dispatch`. Sector reads issue
// `storage.block` `EXEC` reads against whatever block source is
// wired to `s.in_chan` (nvme, sd, …). Up to MAX_OPEN_FILES concurrent
// opens; per-FD state lives in `OpenFile`. Random-access read latency
// is bounded by the producer's per-command device latency since the
// block read is fully synchronous inside the dispatch call.

// FS opcodes from the layered ABI.
/// Kernel → provider: the owner named in the 8-byte argument is being torn
/// down. Not an FS opcode — it reaches every provider that subscribed,
/// whatever contract it serves. See `abi::internal::reconfigure`.
const OWNER_RELEASED: u32 = abi::internal::reconfigure::OWNER_RELEASED;
const OWNER_RELEASED_ARG_LEN: usize = abi::internal::reconfigure::OWNER_RELEASED_ARG_LEN;
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_SEEK: u32 = 0x0902;
const FS_CLOSE: u32 = 0x0903;
const FS_STAT: u32 = 0x0904;
const FS_FSYNC: u32 = 0x0905;
const FS_WRITE: u32 = 0x0906;
const FS_WRITE_ASYNC: u32 = 0x090F;
const FS_FSYNC_SUBMIT: u32 = 0x0910;
const FS_FSYNC_POLL: u32 = 0x0911;
const FS_OPENDIR: u32 = 0x0907;
const FS_READDIR: u32 = 0x0908;
/// `OPEN_CREATE` (0x0909) is documented in
/// `modules/sdk/contracts/storage/fs.rs` and reserved at the
/// SDK level, but FAT32 doesn't implement file creation — no FAT
/// table writeback, no cluster allocator, no directory-entry
/// emit. We explicitly return ENOSYS rather than fall through to
/// the catch-all so the gap is obvious to readers of this file.
const FS_OPEN_CREATE: u32 = 0x0909;
/// `UNLINK` (0x090A) — remove a file by path. The synchronous part is
/// O(1): mark the 8.3 directory entry deleted (`0xE5`) and durably write
/// that one sector. The cluster chain is NOT walked inline — freeing an
/// N-cluster chain is O(N) device round-trips, which would blow the
/// cooperative step guard inside a single `provider_call` (the same
/// reason `fs_op_create` orphans on truncate). Instead the chain head is
/// queued on `unlink_free` and `step_inner` frees it one FAT-sector
/// batch per step (`fs_step_free_chains`). Crash ordering: entry first,
/// chain second — an interruption leaks clusters (safe, matches the
/// truncate posture) but can never leave a live entry pointing at freed
/// clusters.
const FS_UNLINK: u32 = 0x090A;
const FS_PREALLOCATE: u32 = 0x090E;

/// `RENAME` (0x090D) — move an 8.3 entry to another name, publishing the
/// new name durably. FAT32 has no directory-mutation primitive that spans
/// two sectors atomically, so the ordering is made recoverable instead: an
/// intent record in the volume's spare reserved sectors names both entries
/// and their exact expected images, and the replay at the next mount
/// resolves whichever intermediate state the interruption left. See
/// `fs_op_rename` for the phase sequence and `fs_rename_recover` for the
/// state discrimination.
const FS_RENAME: u32 = 0x090D;

/// `FSYNC_NAME` (0x0912) — durably publish the parent-directory entry
/// naming a path. FAT32 already writes every name-minting directory
/// sector synchronously (`fs_op_create`, `fs_op_unlink`), so the entry is
/// in the device's cache the moment the op returns; what is missing for
/// durability is the cache flush, which is exactly what this opcode adds.
const FS_FSYNC_NAME: u32 = 0x0912;

/// `CAPS` (0x09FF) — capability-discovery opcode. Returns a u32
/// LE bitmap of supported FS opcodes. Callers query this before
/// invoking write-tier ops (currently just `OPEN_CREATE`) so
/// they can branch on capability rather than catch `ENOSYS`.
const FS_CAPS: u32 = 0x09FF;

/// `MKDIR` (0x090B) — create one directory by path. The parent must
/// already exist; the new directory is minted with its `.` and `..`
/// entries and published like any other name (see `fs_op_mkdir`).
const FS_MKDIR: u32 = 0x090B;
const FS_RMDIR: u32 = 0x0915;

/// `TRUNCATE` (0x090C) — set an existing file's length, releasing the
/// clusters past the new end. Shrink only; growing a file is what
/// `PREALLOCATE` and `WRITE` are for.
const FS_TRUNCATE: u32 = 0x090C;

/// FS capability bits — must match
/// `modules/sdk/contracts/storage/fs.rs::caps`.
const FS_CAP_OPEN: u32 = 1 << 0;
const FS_CAP_OPENDIR: u32 = 1 << 1;
const FS_CAP_OPEN_CREATE: u32 = 1 << 2;
const FS_CAP_WRITE: u32 = 1 << 3;
const FS_CAP_FSYNC: u32 = 1 << 4;
const FS_CAP_UNLINK: u32 = 1 << 5;
const FS_CAP_TRUNCATE: u32 = 1 << 6;
const FS_CAP_MKDIR: u32 = 1 << 7;
const FS_CAP_RMDIR: u32 = 1 << 16;
const FS_CAP_RENAME: u32 = 1 << 8;
const FS_CAP_PREALLOCATE: u32 = 1 << 9;
const FS_CAP_FSYNC_ASYNC: u32 = 1 << 10;
const FS_CAP_FSYNC_NAME: u32 = 1 << 11;

/// `Fence::LocalDurable` device id reported by fat32 handles once their
/// data has been fsync'd. Opaque per `contracts::fence::DeviceId` (u64);
/// the ASCII tag just makes it legible in traces. Mirrors the linux FS
/// provider's `LINUX_FS_DEVICE_ID` convention.
const FAT32_FS_DEVICE_ID: u64 = 0x6661_7433_325f_6673; // "fat32_fs"

/// Ask the block source for its logical block size, or 0 when it has no
/// answer yet.
///
/// Returns 512 for a source that does not implement the query: that is the
/// answer for every block source predating it, and stating it in one place
/// beats each caller assuming it. Returns 0 for `EAGAIN` — a namespace that
/// has not attached has no geometry, and a guess latched at mount is exactly
/// the failure the `CAPS` probe rule exists to stop.
unsafe fn fs_device_block_size(s: &Fat32State) -> u32 {
    match s.blk.caps(&*s.syscalls) {
        0 => s.blk.block_size(),
        E_NOSYS => BLOCK_SIZE as u32,
        _ => 0,
    }
}

/// Absolute device LBA of a sector named relative to this volume.
#[inline]
fn fs_abs_lba(s: &Fat32State, lba: u32) -> u64 {
    s.partition_lba + u64::from(lba)
}

/// Host-test only: fetch a sector through `EXEC`, for the harness's mount
/// shortcut. Nothing the provider runs reads this way — `EXEC` may wait on
/// the device, and no fs operation does.
#[cfg(feature = "host-test")]
unsafe fn fs_sync_read_sector(s: &Fat32State, lba: u32, out: *mut u8) -> i32 {
    s.blk.read(&*s.syscalls, fs_abs_lba(s, lba), 1, out)
}

// ============================================================================
// Sector cache, write-back and transactions
// ============================================================================
//
// No fs operation waits on the device inside a call (the `fs` contract's
// rule). Three mechanisms make that hold without making every operation an
// explicit step machine.
//
// **The sector cache.** Every metadata sector this provider reads or writes —
// FAT, directory, FSINFO, the rename intent record — lives in a slot of
// `cache`. A read of a sector the cache does not hold submits its read
// (`storage.block` `SUBMIT`) and answers "not yet": the operation that needed
// it answers `EAGAIN` and finds it on a later ask. A write only changes the
// slot and marks it dirty; nothing reaches the device inside the call.
//
// **Epochs.** A dirty slot carries the epoch it was written in. The engine
// (`fs_pump`, run at every dispatch and every step) writes epoch `wb_epoch`
// and starts the next only once every write of it has completed — the
// completion-before-dependent-submit rule the block contract asks for — and,
// where the boundary was declared durable, once a `FLUSH` submitted after them
// has completed too. An operation states its ordering as boundaries
// (`fs_barrier`) instead of waiting: "zero the cluster, durable boundary,
// link it" is three statements in one call, and the engine puts them on the
// media in that order over as many steps as the device takes. A sector
// written again in a later epoch gets a new slot (copy on write), so the
// older image still reaches the device first.
//
// **Transactions.** An operation runs inside `fs_tx`. Its cache writes are
// tentative, and the in-memory state it may change is saved (`TxSave`). If
// any sector it needed was not cached — or the cache, the epoch window or a
// zero-run slot was momentarily full — the transaction aborts: tentative
// slots are dropped, the saved state is put back, and the operation answers
// `EAGAIN` with nothing consumed and no state moved, exactly as the contract
// requires. The read it missed is under way, so a later ask finds more of
// what it needs. Once everything it touches is cached, the whole operation
// runs inside one call against memory, and commits.
//
// What an operation promises to have made durable — FSYNC, RENAME, TRUNCATE,
// PREALLOCATE, FSYNC_NAME — is decided by its last durable boundary reaching
// the device. Until then it answers `EINPROGRESS`, and the caller asks again
// with the same request (see `fs_op_slotted`).
//
// Sizing. `CACHE_SLOTS` must hold one call's working set: a directory walk's
// budget of sectors, plus what the largest commit writes — a rename touches
// two directory sectors, their long-name companions, the intent record twice,
// two FAT sectors and their copies — with room to spare for the dirty slots
// the engine has not written yet. 128 slots is 64 KiB of the aarch64 state,
// beside the 1 MiB of per-handle scratch; 24 slots is 12 KiB on a
// microcontroller, whose walk budget is cut to match (`DIR_SCAN_BUDGET_SECTORS`).

#[cfg(target_arch = "aarch64")]
const CACHE_SLOTS: usize = 128;
#[cfg(not(target_arch = "aarch64"))]
const CACHE_SLOTS: usize = 24;

/// Slot states.
const CS_FREE: u8 = 0;
/// Its read is in flight; the data is the device's, not ours yet.
const CS_READING: u8 = 1;
/// Matches the device (or a zero run that is about to make it so).
const CS_CLEAN: u8 = 2;
/// Holds a write the engine has not submitted.
const CS_DIRTY: u8 = 3;
/// Its write is in flight. The data is lent to the source until it lands.
const CS_WRITING: u8 = 4;
/// Its read failed; the next access reports `err` and frees the slot.
const CS_FAILED: u8 = 5;

/// Written by the open transaction: dropped if it aborts.
const CF_TENTATIVE: u8 = 1;
/// An older image of its sector, kept only until it has been written.
const CF_SUPERSEDED: u8 = 2;
/// Free it when its read lands: the sector was overwritten meanwhile.
const CF_DISCARD: u8 = 4;

/// One cached sector.
#[derive(Clone, Copy)]
#[repr(C)]
struct CacheSlot {
    /// Write sequence while `CS_WRITING`.
    seq: u64,
    /// Volume-relative sector.
    lba: u32,
    /// Epoch of the write it holds.
    epoch: u32,
    /// Creation order among the versions of one sector: the highest live
    /// one is what a read sees.
    ver: u32,
    /// Last use, for eviction.
    stamp: u32,
    /// `call_gen` of the last use.
    gen: u32,
    /// The failed read's errno.
    err: i32,
    state: u8,
    flags: u8,
    _pad: [u8; 6],
}

impl CacheSlot {
    const EMPTY: Self = Self {
        seq: 0,
        lba: 0,
        epoch: 0,
        ver: 0,
        stamp: 0,
        gen: 0,
        err: 0,
        state: CS_FREE,
        flags: 0,
        _pad: [0; 6],
    };
}

/// Zero runs queued at once. A run is a new directory cluster (or a
/// preallocated file's first sector) whose sectors are written from
/// `zero_buf` instead of through cache slots, so a 64 KiB cluster does not
/// need 128 of them.
const ZERO_RUN_SLOTS: usize = 4;
/// Requests one zero run keeps in flight.
const ZERO_RUN_INFLIGHT: usize = 4;
/// Sectors one zero-run request writes, and the size of `zero_buf`: a full
/// request where state is plentiful, one sector on a microcontroller.
#[cfg(target_arch = "aarch64")]
const ZERO_BUF_SECTORS: usize = 8;
#[cfg(not(target_arch = "aarch64"))]
const ZERO_BUF_SECTORS: usize = 1;

#[derive(Clone, Copy)]
#[repr(C)]
struct ZeroRun {
    seq: [u64; ZERO_RUN_INFLIGHT],
    lba: u32,
    n: u32,
    /// Sectors submitted so far.
    next: u32,
    epoch: u32,
    live: u8,
    _pad: [u8; 7],
}

impl ZeroRun {
    const EMPTY: Self = Self {
        seq: [0; ZERO_RUN_INFLIGHT],
        lba: 0,
        n: 0,
        next: 0,
        epoch: 0,
        live: 0,
        _pad: [0; 7],
    };
}

/// Epochs written but not yet behind the engine at once. Past it a new
/// boundary waits (`EAGAIN`) for the device to catch up. Below 64, so the
/// durable-boundary bits never alias.
const EPOCH_WINDOW: usize = 56;

/// Boundaries one transaction may close. Well below `EPOCH_WINDOW`, so a
/// transaction that misses on a full window always fits once the engine has
/// drained: every transaction can commit. Work that would need more — a
/// large FAT clear — is split into transactions of its own.
const TX_BARRIER_MAX: usize = 24;

/// How long the open epoch may hold writes before the engine closes it and
/// writes them back, in milliseconds. Short: it exists so that repeated
/// writes of one FAT sector in a burst of appends coalesce, not to defer
/// write-back.
const WB_DELAY_MS: u64 = 20;

/// Sectors a directory walk asks for ahead of the one it missed.
const READAHEAD_SECTORS: u32 = 4;

/// Directory clusters one transaction can have changed and still have its
/// cached walks of them dropped precisely on abort; past it, all are.
const TX_DIRS: usize = 4;

/// Bytes of `OpenFile` a transaction can put back: everything but the
/// scratch buffer, which is last for this reason.
const OF_HEAD: usize = core::mem::offset_of!(OpenFile, scratch_block);

/// What an aborted transaction restores.
#[derive(Clone, Copy)]
#[repr(C)]
struct TxSave {
    zero_runs: [ZeroRun; ZERO_RUN_SLOTS],
    durable_bits: u64,
    open_dirty_ms: u64,
    epoch: u32,
    free_count: u32,
    unlink_free: [u32; UNLINK_FREE_SLOTS],
    unlink_epoch: [u32; UNLINK_FREE_SLOTS],
    root_cleaned: u32,
    clear_next: u32,
    clear_end: u32,
    /// The `open_files` slot saved in `file`, or `u32::MAX`.
    file_slot: u32,
    dirs: [u32; TX_DIRS],
    epoch_has_fat: u8,
    free_count_known: u8,
    fs_settle_pending: u8,
    volume_clean: u8,
    dirs_n: u8,
    _pad: [u8; 3],
    file: [u8; OF_HEAD],
}

/// Tag families of this provider's reads, above the slot index.
const TAG_CACHE: u64 = 1 << 48;
const TAG_FD: u64 = 2 << 48;
const TAG_MOUNT: u64 = 3 << 48;
const TAG_INDEX: u64 = 0xFFFF;
/// A cache read's sector count, above its first slot.
const TAG_COUNT_SHIFT: u32 = 16;
const TAG_LOW: u64 = 0xFF_FFFF;
/// Sectors one cache read carries at most.
const CACHE_RUN_SECTORS: u32 = 8;

/// Record a miss: the call needed something that is not here yet.
#[inline]
fn fs_miss(s: &mut Fat32State) {
    s.miss = 1;
    fs_note_io(s, E_AGAIN);
}

#[inline]
fn fs_touch(s: &mut Fat32State, i: usize) {
    s.cache_stamp = s.cache_stamp.wrapping_add(1);
    s.cache[i].stamp = s.cache_stamp;
    s.cache[i].gen = s.call_gen;
}

#[inline]
fn fs_next_ver(s: &mut Fat32State) -> u32 {
    s.cache_ver = s.cache_ver.wrapping_add(1);
    s.cache_ver
}

#[inline]
fn fs_slot_ptr(s: &mut Fat32State, i: usize) -> *mut u8 {
    s.cache_data[i].as_mut_ptr()
}

/// The slot a read of `lba` sees: the newest live version.
fn fs_cache_find(s: &Fat32State, lba: u32) -> Option<usize> {
    let mut best: Option<usize> = None;
    let mut best_ver = 0u32;
    let mut i = 0usize;
    while i < CACHE_SLOTS {
        let c = &s.cache[i];
        if c.state != CS_FREE
            && c.lba == lba
            && c.flags & (CF_SUPERSEDED | CF_DISCARD) == 0
            && (best.is_none() || c.ver.wrapping_sub(best_ver) as i32 > 0)
        {
            best = Some(i);
            best_ver = c.ver;
        }
        i += 1;
    }
    best
}

/// A free slot, evicting the least recently used clean one that this call
/// has not touched. `None` when every slot is dirty, in flight or in use by
/// this call: the engine is asked to write back, and the caller misses.
fn fs_cache_alloc(s: &mut Fat32State) -> Option<usize> {
    let mut victim: Option<usize> = None;
    let mut oldest = 0u32;
    let mut i = 0usize;
    while i < CACHE_SLOTS {
        let c = &s.cache[i];
        if c.state == CS_FREE {
            return Some(i);
        }
        if c.state == CS_CLEAN
            && c.flags == 0
            && c.gen != s.call_gen
            && (victim.is_none() || s.cache_stamp.wrapping_sub(c.stamp) > oldest)
        {
            victim = Some(i);
            oldest = s.cache_stamp.wrapping_sub(c.stamp);
        }
        i += 1;
    }
    if let Some(v) = victim {
        s.cache[v] = CacheSlot::EMPTY;
        return Some(v);
    }
    s.wb_kick = 1;
    None
}

/// Whether a live zero run covers `lba`: its sectors read as zero.
fn fs_zero_covers(s: &Fat32State, lba: u32) -> bool {
    let mut z = 0usize;
    while z < ZERO_RUN_SLOTS {
        let r = &s.zero_runs[z];
        if r.live != 0 && lba >= r.lba && lba - r.lba < r.n {
            return true;
        }
        z += 1;
    }
    false
}

/// Settle every read the source has finished: cache slots, an FD's scratch,
/// and the mount's own sector.
unsafe fn fs_route_reads(s: &mut Fat32State) {
    while let Some((tag, st)) = s.blk.take_read() {
        let idx = (tag & TAG_INDEX) as usize;
        match tag & !TAG_LOW {
            TAG_CACHE if idx < CACHE_SLOTS => {
                let n = (((tag >> TAG_COUNT_SHIFT) & 0xFF) as usize).max(1);
                let mut j = idx;
                while j < idx + n && j < CACHE_SLOTS {
                    let c = &mut s.cache[j];
                    if c.state == CS_READING {
                        if c.flags & CF_DISCARD != 0 {
                            *c = CacheSlot::EMPTY;
                        } else if st == 0 {
                            c.state = CS_CLEAN;
                        } else {
                            c.state = CS_FAILED;
                            c.err = st;
                        }
                    }
                    j += 1;
                }
            }
            TAG_FD if idx < MAX_OPEN_FILES => {
                let of = &mut s.open_files[idx];
                if of.scratch_io != SIO_READ {
                    continue;
                }
                of.scratch_io = SIO_IDLE;
                if st == 0 {
                    of.scratch_lba = of.rd_lba;
                    of.scratch_span = of.rd_span;
                    of.scratch_cluster = of.rd_cluster;
                } else {
                    of.scratch_span = 0;
                    of.io_err = st;
                }
            }
            TAG_MOUNT => {
                s.mount_rd = 2;
                s.mount_rc = st;
            }
            _ => {}
        }
    }
}

/// The cache slot holding `lba`, reading it when it is not there.
///
/// `Err(EAGAIN)` with the miss recorded when the sector is not cached yet:
/// its read has been submitted (or could not be, for want of a slot or of
/// queue room) and a later ask finds it.
unsafe fn fs_cache_get(s: &mut Fat32State, lba: u32) -> Result<usize, i32> {
    if let Some(i) = fs_cache_find(s, lba) {
        match s.cache[i].state {
            CS_READING => {
                fs_touch(s, i);
                fs_miss(s);
                return Err(E_AGAIN);
            }
            CS_FAILED => {
                let e = s.cache[i].err;
                s.cache[i] = CacheSlot::EMPTY;
                return Err(if e == 0 { -5 } else { e });
            }
            _ => {
                fs_touch(s, i);
                return Ok(i);
            }
        }
    }
    let Some(n) = fs_cache_alloc(s) else {
        fs_miss(s);
        return Err(E_AGAIN);
    };
    let ver = fs_next_ver(s);
    if fs_zero_covers(s, lba) {
        // About to be zero on the device; reading it now would return what
        // the zero run is there to replace.
        let p = fs_slot_ptr(s, n);
        core::ptr::write_bytes(p, 0, BLOCK_SIZE);
        s.cache[n] = CacheSlot {
            lba,
            ver,
            state: CS_CLEAN,
            flags: if s.tx_active != 0 { CF_TENTATIVE } else { 0 },
            ..CacheSlot::EMPTY
        };
        fs_touch(s, n);
        return Ok(n);
    }
    // Read ahead in the same request when the caller asked for it and a
    // run of adjacent slots is free for the sectors after this one.
    let (n, run) = fs_cache_run(s, n, lba);
    let mut k = 0u32;
    while k < run {
        let v = if k == 0 { ver } else { fs_next_ver(s) };
        s.cache[n + k as usize] = CacheSlot {
            lba: lba + k,
            ver: v,
            state: CS_READING,
            ..CacheSlot::EMPTY
        };
        fs_touch(s, n + k as usize);
        k += 1;
    }
    let p = fs_slot_ptr(s, n);
    let abs = fs_abs_lba(s, lba);
    let tag = TAG_CACHE | (u64::from(run) << TAG_COUNT_SHIFT) | n as u64;
    let rc = s.blk.submit_read(&*s.syscalls, abs, run, p, tag);
    if rc != 0 {
        let mut k = 0usize;
        while k < run as usize {
            s.cache[n + k] = CacheSlot::EMPTY;
            k += 1;
        }
        if rc == E_AGAIN {
            fs_miss(s);
        }
        return Err(rc);
    }
    // A completion already reaped by an earlier call may be waiting.
    fs_route_reads(s);
    match s.cache[n].state {
        CS_CLEAN => Ok(n),
        CS_FAILED => {
            let e = s.cache[n].err;
            s.cache[n] = CacheSlot::EMPTY;
            Err(if e == 0 { -5 } else { e })
        }
        _ => {
            fs_miss(s);
            Err(E_AGAIN)
        }
    }
}

/// Start reading `lba` and up to `max - 1` sectors after it into the cache,
/// in one request, without counting as a miss: read-ahead. Returns how many
/// sectors that covered (1 for one already cached or being zeroed), or 0
/// when nothing could be started — no slot, no queue room.
unsafe fn fs_cache_fetch_ahead(s: &mut Fat32State, lba: u32, max: u32) -> u32 {
    if fs_cache_find(s, lba).is_some() || fs_zero_covers(s, lba) {
        return 1;
    }
    let Some(one) = fs_cache_alloc(s) else {
        return 0;
    };
    let ver = fs_next_ver(s);
    s.ra_hint = max.saturating_sub(1);
    let (n, run) = fs_cache_run(s, one, lba);
    s.ra_hint = 0;
    let mut k = 0u32;
    while k < run {
        let v = if k == 0 { ver } else { fs_next_ver(s) };
        s.cache[n + k as usize] = CacheSlot {
            lba: lba + k,
            ver: v,
            state: CS_READING,
            ..CacheSlot::EMPTY
        };
        // Stamped, not pinned to this call: read-ahead must not keep the
        // cache from evicting it for the call's own needs.
        s.cache_stamp = s.cache_stamp.wrapping_add(1);
        s.cache[n + k as usize].stamp = s.cache_stamp;
        k += 1;
    }
    let p = fs_slot_ptr(s, n);
    let abs = fs_abs_lba(s, lba);
    let tag = TAG_CACHE | (u64::from(run) << TAG_COUNT_SHIFT) | n as u64;
    if s.blk.submit_read(&*s.syscalls, abs, run, p, tag) != 0 {
        let mut k = 0usize;
        while k < run as usize {
            s.cache[n + k] = CacheSlot::EMPTY;
            k += 1;
        }
        return 0;
    }
    run
}

/// Sectors a sequential reader keeps requested ahead of its cursor.
#[cfg(target_arch = "aarch64")]
const READ_AHEAD_SECTORS: u32 = 64;
#[cfg(not(target_arch = "aarch64"))]
const READ_AHEAD_SECTORS: u32 = 8;

/// Keep FD `slot`'s next sectors on their way: from its cursor forward, up
/// to `READ_AHEAD_SECTORS` or the end of the file, run by run, following the
/// chain where its FAT sector is cached (asking for it where not). Never
/// takes more than half the source's queue, so writes and metadata are not
/// starved, and never waits. Called by `READ` and by the step, so a
/// sequential read streams: the next runs are requested as the current
/// ones land, whether or not the reader is asking at that moment.
unsafe fn fs_read_ahead(s: &mut Fat32State, slot: usize) {
    let bps = u32::from(s.bytes_per_sector);
    let spc = u32::from(s.sectors_per_cluster);
    if bps == 0 || spc == 0 || s.tx_active != 0 {
        return;
    }
    let of = s.open_files[slot];
    if of.in_use != OF_OPEN || of.is_dir != 0 || of.writable != 0 || of.current_cluster < 2 {
        return;
    }
    let remaining = of.size.saturating_sub(of.offset);
    if remaining == 0 {
        return;
    }
    let left = (remaining + of.offset % bps).div_ceil(bps);
    let budget = left.min(READ_AHEAD_SECTORS);
    let cap = usize::from(s.blk.queue_depth().max(2) / 2);
    let mut cluster = of.current_cluster;
    let mut sic = u32::from(of.sector_in_cluster);
    let mut covered = 0u32;
    while covered < budget {
        if sic >= spc {
            let fsec = fat_sector_for_cluster(s, cluster);
            let cached = match fs_cache_find(s, fsec) {
                Some(i) => {
                    let st = s.cache[i].state;
                    st == CS_CLEAN || st == CS_DIRTY || st == CS_WRITING
                }
                None => false,
            };
            if !cached {
                if s.blk.reads_pending() < cap {
                    let fat_end = s.fat_start_sector.saturating_add(s.fat_size_32);
                    let _ = fs_cache_fetch_ahead(
                        s,
                        fsec,
                        (READAHEAD_SECTORS + 1).min(fat_end.saturating_sub(fsec)),
                    );
                }
                return;
            }
            match fs_fat_next(s, cluster) {
                Ok(n) if (2..FAT32_EOC).contains(&n) => {
                    cluster = n;
                    sic = 0;
                }
                _ => return,
            }
        }
        let lba = cluster_to_sector(s, cluster) + sic;
        if fs_cache_find(s, lba).is_some() || fs_zero_covers(s, lba) {
            sic += 1;
            covered += 1;
            continue;
        }
        if s.blk.reads_pending() >= cap {
            return;
        }
        let run = (spc - sic).min(budget - covered);
        let n = fs_cache_fetch_ahead(s, lba, run);
        if n == 0 {
            return;
        }
        sic += n;
        covered += n;
    }
}

/// The slots a miss of `lba` reads into: `one` alone, or — when the caller
/// set a read-ahead (`ra_hint`) — a run of adjacent free or evictable slots
/// for `lba` and the sectors after it that are not cached. Returns the first
/// slot and the run's length.
fn fs_cache_run(s: &mut Fat32State, one: usize, lba: u32) -> (usize, u32) {
    let maxb = s.blk.max_blocks().max(1);
    let mut want = 1 + s.ra_hint.min(CACHE_RUN_SECTORS - 1);
    want = want.min(maxb);
    // Stop at the first sector already cached or zeroed: it is not read
    // again.
    let mut k = 1u32;
    while k < want {
        if fs_cache_find(s, lba + k).is_some() || fs_zero_covers(s, lba + k) {
            break;
        }
        k += 1;
    }
    let want = k as usize;
    if want <= 1 {
        return (one, 1);
    }
    // Of the windows whose slots are all free or evictable, the one whose
    // most recently used slot is the oldest: read-ahead must not evict
    // what was just used, or a reader and a directory walk sharing the
    // cache would evict each other's sectors on every ask.
    let mut best: Option<usize> = None;
    let mut best_age = 0u32;
    let mut start = 0usize;
    while start + want <= CACHE_SLOTS {
        let mut ok = true;
        let mut youngest = u32::MAX;
        let mut j = 0usize;
        while j < want {
            let i = start + j;
            if i != one {
                let c = &s.cache[i];
                if c.state == CS_FREE {
                    // Free: as old as can be.
                } else if c.state == CS_CLEAN && c.flags == 0 && c.gen != s.call_gen {
                    youngest = youngest.min(s.cache_stamp.wrapping_sub(c.stamp));
                } else {
                    ok = false;
                    break;
                }
            }
            j += 1;
        }
        if ok && (best.is_none() || youngest > best_age) {
            best = Some(start);
            best_age = youngest;
        }
        start += 1;
    }
    let Some(start) = best else {
        return (one, 1);
    };
    let mut j = 0usize;
    while j < want {
        s.cache[start + j] = CacheSlot::EMPTY;
        j += 1;
    }
    if one < start || one >= start + want {
        // `one` was taken for this read and is not part of the run: give
        // it back.
        s.cache[one] = CacheSlot::EMPTY;
    }
    (start, want as u32)
}

/// Note that the open epoch now holds a write.
unsafe fn fs_note_open_dirty(s: &mut Fat32State) {
    if s.open_dirty_ms == 0 && !s.syscalls.is_null() {
        s.open_dirty_ms = dev_millis(&*s.syscalls).max(1);
    }
}

/// Settle the versions of `lba` once its newest one is final: every older
/// one is dropped, or — if it still has to reach the device in an earlier
/// epoch — kept as superseded until it has.
fn fs_cache_settle_versions(s: &mut Fat32State, lba: u32) {
    let Some(top) = fs_cache_find(s, lba) else {
        return;
    };
    let top_epoch = s.cache[top].epoch;
    let mut j = 0usize;
    while j < CACHE_SLOTS {
        if j != top {
            let c = &mut s.cache[j];
            if c.state != CS_FREE && c.lba == lba && c.flags & CF_TENTATIVE == 0 {
                match c.state {
                    CS_CLEAN | CS_FAILED => *c = CacheSlot::EMPTY,
                    CS_READING => c.flags |= CF_DISCARD,
                    CS_DIRTY => {
                        if c.epoch == top_epoch && c.flags & CF_SUPERSEDED == 0 {
                            *c = CacheSlot::EMPTY;
                        } else {
                            c.flags |= CF_SUPERSEDED;
                        }
                    }
                    _ => c.flags |= CF_SUPERSEDED,
                }
            }
        }
        j += 1;
    }
}

/// A slot for writing `lba` in the current epoch.
///
/// `preserve` asks for the sector's current contents (a read-modify-write);
/// without it the caller overwrites all 512 bytes. A slot is changed in
/// place only when doing so cannot lose anything: inside a transaction,
/// only a slot that transaction itself wrote in this same epoch; otherwise
/// a clean slot, or one dirty in this epoch. Anything else is copied to a
/// new slot, so an aborted transaction can drop it and an older epoch's
/// image still reaches the device first.
unsafe fn fs_cache_dirty(s: &mut Fat32State, lba: u32, preserve: bool) -> Result<usize, i32> {
    let mut vis = fs_cache_find(s, lba);
    if preserve {
        match vis {
            None => {
                let i = fs_cache_get(s, lba)?;
                vis = Some(i);
            }
            Some(i) => match s.cache[i].state {
                CS_READING | CS_FAILED => {
                    let i = fs_cache_get(s, lba)?;
                    vis = Some(i);
                }
                _ => {}
            },
        }
    }
    let tx = s.tx_active != 0;
    if let Some(i) = vis {
        let c = s.cache[i];
        let tentative = c.flags & CF_TENTATIVE != 0;
        let same_epoch = c.state == CS_CLEAN || (c.state == CS_DIRTY && c.epoch == s.epoch);
        let in_place = (c.state == CS_CLEAN || c.state == CS_DIRTY)
            && same_epoch
            && if tx { tentative } else { !tentative };
        if in_place {
            s.cache[i].state = CS_DIRTY;
            s.cache[i].epoch = s.epoch;
            fs_touch(s, i);
            fs_note_open_dirty(s);
            return Ok(i);
        }
    }
    let Some(n) = fs_cache_alloc(s) else {
        fs_miss(s);
        return Err(E_AGAIN);
    };
    if let Some(i) = vis {
        let st = s.cache[i].state;
        if st == CS_CLEAN || st == CS_DIRTY || st == CS_WRITING {
            let src = s.cache_data[i].as_ptr();
            let dst = s.cache_data[n].as_mut_ptr();
            core::ptr::copy_nonoverlapping(src, dst, BLOCK_SIZE);
        }
    }
    let ver = fs_next_ver(s);
    s.cache[n] = CacheSlot {
        lba,
        epoch: s.epoch,
        ver,
        state: CS_DIRTY,
        flags: if tx { CF_TENTATIVE } else { 0 },
        ..CacheSlot::EMPTY
    };
    fs_touch(s, n);
    if !tx {
        fs_cache_settle_versions(s, lba);
    }
    fs_note_open_dirty(s);
    Ok(n)
}

/// Close the current epoch: everything written so far reaches the device
/// before anything written after. With `durable`, a flush covering it
/// completes first as well. Returns the epoch closed, or 0 — with the miss
/// recorded — when the window of epochs not yet written back is full.
unsafe fn fs_barrier(s: &mut Fat32State, durable: bool) -> u32 {
    if s.tx_active != 0 {
        // A transaction needing more boundaries than the window can ever
        // hold would abort for ever. None does — the largest, a rename that
        // grows its directory, takes about a dozen — and one that did is
        // refused, deterministically, rather than retried.
        if usize::from(s.tx_barriers) >= TX_BARRIER_MAX {
            s.tx_overflow = 1;
            return 0;
        }
        s.tx_barriers += 1;
    }
    if s.epoch.wrapping_sub(s.wb_epoch) >= EPOCH_WINDOW as u32 {
        s.wb_kick = 1;
        fs_miss(s);
        return 0;
    }
    let e = s.epoch;
    if durable {
        s.durable_bits |= 1u64 << (e % 64);
    }
    s.epoch = e.wrapping_add(1);
    s.epoch_has_fat = 0;
    s.open_dirty_ms = 0;
    e
}

/// A durable boundary, as an errno: what `FLUSH` was in the synchronous
/// design. The operation that needs the boundary's durability waits on the
/// epoch it returned through `op_wait_epoch`.
unsafe fn fs_durable_point(s: &mut Fat32State) -> i32 {
    let e = fs_barrier(s, true);
    if e == 0 {
        return E_AGAIN;
    }
    s.op_wait_epoch = e;
    0
}

/// Whether every write of epoch `e` and before is on non-volatile media.
#[inline]
fn fs_durable(s: &Fat32State, e: u32) -> bool {
    s.durable_through.wrapping_sub(e) as i32 >= 0
}

/// Queue `n` sectors from `lba` to be zeroed in the current epoch, and make
/// the cache agree: a cached copy of any of them now reads as zeroes.
unsafe fn fs_zero_sectors(s: &mut Fat32State, lba: u32, n: u32) -> i32 {
    if n == 0 {
        return 0;
    }
    let mut z = 0usize;
    while z < ZERO_RUN_SLOTS && s.zero_runs[z].live != 0 {
        z += 1;
    }
    if z >= ZERO_RUN_SLOTS {
        s.wb_kick = 1;
        fs_miss(s);
        return E_AGAIN;
    }
    let mut k = 0u32;
    while k < n {
        if let Some(i) = fs_cache_find(s, lba + k) {
            if s.cache[i].state == CS_CLEAN && s.cache[i].flags == 0 {
                s.cache[i] = CacheSlot::EMPTY;
            } else {
                let j = match fs_cache_dirty(s, lba + k, false) {
                    Ok(j) => j,
                    Err(rc) => return rc,
                };
                let p = fs_slot_ptr(s, j);
                core::ptr::write_bytes(p, 0, BLOCK_SIZE);
            }
        }
        k += 1;
    }
    s.zero_runs[z] = ZeroRun {
        lba,
        n,
        epoch: s.epoch,
        live: 1,
        ..ZeroRun::EMPTY
    };
    fs_note_open_dirty(s);
    0
}

/// Make `[lba, lba + n)` safe for a file-data request: no zero run or
/// metadata write may still land on it afterwards, and no cached metadata
/// copy of it may be believed. A metadata slot for a data sector belongs to
/// a directory whose cluster has since been freed and handed to a file, so
/// it is dead and is dropped. `false` while one is still in flight: the
/// data request waits rather than racing it.
fn fs_data_claim(s: &mut Fat32State, lba: u32, n: u32) -> bool {
    let mut z = 0usize;
    while z < ZERO_RUN_SLOTS {
        let r = &s.zero_runs[z];
        if r.live != 0 && lba < r.lba.saturating_add(r.n) && r.lba < lba.saturating_add(n) {
            return false;
        }
        z += 1;
    }
    let mut i = 0usize;
    while i < CACHE_SLOTS {
        let c = &mut s.cache[i];
        if c.state != CS_FREE && c.lba >= lba && c.lba - lba < n {
            match c.state {
                CS_WRITING => return false,
                CS_READING => c.flags |= CF_DISCARD,
                _ => *c = CacheSlot::EMPTY,
            }
        }
        i += 1;
    }
    true
}

/// Whether epoch `e` holds anything the engine has to write.
fn fs_epoch_has_items(s: &Fat32State, e: u32) -> bool {
    let mut i = 0usize;
    while i < CACHE_SLOTS {
        let c = &s.cache[i];
        if c.flags & CF_TENTATIVE == 0
            && c.epoch == e
            && (c.state == CS_DIRTY || c.state == CS_WRITING)
        {
            return true;
        }
        i += 1;
    }
    let mut z = 0usize;
    while z < ZERO_RUN_SLOTS {
        if s.zero_runs[z].live != 0 && s.zero_runs[z].epoch == e {
            return true;
        }
        z += 1;
    }
    false
}

fn fs_dirty_count(s: &Fat32State) -> usize {
    let mut n = 0usize;
    let mut i = 0usize;
    while i < CACHE_SLOTS {
        if s.cache[i].state == CS_DIRTY {
            n += 1;
        }
        i += 1;
    }
    n
}

/// Whether nothing is waiting to be written: no dirty or in-flight slot, no
/// zero run, no epoch the engine has still to finish.
fn fs_wb_idle(s: &Fat32State) -> bool {
    if s.wb_epoch != s.epoch {
        return false;
    }
    let mut i = 0usize;
    while i < CACHE_SLOTS {
        let st = s.cache[i].state;
        if st == CS_DIRTY || st == CS_WRITING {
            return false;
        }
        i += 1;
    }
    let mut z = 0usize;
    while z < ZERO_RUN_SLOTS {
        if s.zero_runs[z].live != 0 {
            return false;
        }
        z += 1;
    }
    true
}

/// Collect the writes that have landed: cache slots, zero runs, and FD
/// scratch buffers a source was borrowing.
unsafe fn fs_wb_settle(s: &mut Fat32State) {
    let mut i = 0usize;
    while i < CACHE_SLOTS {
        if s.cache[i].state == CS_WRITING {
            let st = s.blk.write_state(s.cache[i].seq);
            if st != 1 {
                if st < 0 && s.wb_err == 0 {
                    s.wb_err = st;
                }
                if s.cache[i].flags & CF_SUPERSEDED != 0 {
                    s.cache[i] = CacheSlot::EMPTY;
                } else {
                    s.cache[i].state = CS_CLEAN;
                    s.cache[i].seq = 0;
                }
            }
        }
        i += 1;
    }
    let mut z = 0usize;
    while z < ZERO_RUN_SLOTS {
        if s.zero_runs[z].live != 0 {
            let mut busy = false;
            let mut k = 0usize;
            while k < ZERO_RUN_INFLIGHT {
                let q = s.zero_runs[z].seq[k];
                if q != 0 {
                    let st = s.blk.write_state(q);
                    if st == 1 {
                        busy = true;
                    } else {
                        if st < 0 && s.wb_err == 0 {
                            s.wb_err = st;
                        }
                        s.zero_runs[z].seq[k] = 0;
                    }
                }
                k += 1;
            }
            if !busy && s.zero_runs[z].next >= s.zero_runs[z].n {
                s.zero_runs[z].live = 0;
            }
        }
        z += 1;
    }
    let mut f = 0usize;
    while f < MAX_OPEN_FILES {
        if s.open_files[f].in_use != OF_FREE && s.open_files[f].scratch_io == SIO_WRITE {
            let st = s.blk.write_state(s.open_files[f].scratch_seq);
            if st != 1 {
                s.open_files[f].scratch_io = SIO_IDLE;
                if st < 0 {
                    s.open_files[f].io_err = st;
                }
            }
        }
        f += 1;
    }
}

/// Submit what remains of zero run `z`. True once all of it is in flight
/// or done.
unsafe fn fs_zero_submit(s: &mut Fat32State, z: usize) -> bool {
    let maxb = s.blk.max_blocks().max(1);
    while s.zero_runs[z].next < s.zero_runs[z].n {
        let mut k = 0usize;
        while k < ZERO_RUN_INFLIGHT && s.zero_runs[z].seq[k] != 0 {
            k += 1;
        }
        if k >= ZERO_RUN_INFLIGHT {
            return false;
        }
        let left = s.zero_runs[z].n - s.zero_runs[z].next;
        let chunk = left.min(ZERO_BUF_SECTORS as u32).min(maxb);
        let lba = s.zero_runs[z].lba + s.zero_runs[z].next;
        let abs = fs_abs_lba(s, lba);
        let src = s.zero_buf.as_ptr();
        let rc = s.blk.submit_write(&*s.syscalls, abs, chunk, src);
        if rc == E_AGAIN {
            return false;
        }
        if rc != 0 {
            if s.wb_err == 0 {
                s.wb_err = rc;
            }
            s.zero_runs[z].next = s.zero_runs[z].n;
            return true;
        }
        let q = s.blk.last_seq();
        if s.blk.write_state(q) == 1 {
            s.zero_runs[z].seq[k] = q;
        } else if s.blk.write_state(q) < 0 && s.wb_err == 0 {
            s.wb_err = -5;
        }
        s.zero_runs[z].next += chunk;
    }
    true
}

/// Move the write-back forward: submit the current epoch's writes, wait for
/// them (and for a flush at a durable boundary) without blocking, and step
/// to the next. Never waits; bounded by the queue it can fill.
unsafe fn fs_wb_advance(s: &mut Fat32State) {
    if s.tx_active != 0 || s.syscalls.is_null() {
        return;
    }
    let mut rounds = 0u32;
    while rounds < EPOCH_WINDOW as u32 + 2 {
        rounds += 1;
        let w = s.wb_epoch;
        if w == s.epoch {
            // The open epoch. Its writes coalesce until something needs
            // them out: a request, a filling cache, or a little time.
            let has = fs_epoch_has_items(s, w);
            let aged = s.open_dirty_ms != 0
                && dev_millis(&*s.syscalls).wrapping_sub(s.open_dirty_ms) >= WB_DELAY_MS;
            let full = fs_dirty_count(s) >= CACHE_SLOTS / 4;
            let kick = s.wb_kick != 0;
            s.wb_kick = 0;
            if has && (aged || full || kick) {
                fs_barrier(s, false);
                continue;
            }
            return;
        }
        let mut busy = false;
        let mut i = 0usize;
        while i < CACHE_SLOTS {
            let c = s.cache[i];
            if c.flags & CF_TENTATIVE == 0 && c.epoch == w {
                if c.state == CS_DIRTY {
                    let abs = fs_abs_lba(s, c.lba);
                    let p = s.cache_data[i].as_ptr();
                    let rc = s.blk.submit_write(&*s.syscalls, abs, 1, p);
                    if rc == 0 {
                        let q = s.blk.last_seq();
                        s.cache[i].state = CS_WRITING;
                        s.cache[i].seq = q;
                        let st = s.blk.write_state(q);
                        if st != 1 {
                            if st < 0 && s.wb_err == 0 {
                                s.wb_err = st;
                            }
                            if s.cache[i].flags & CF_SUPERSEDED != 0 {
                                s.cache[i] = CacheSlot::EMPTY;
                            } else {
                                s.cache[i].state = CS_CLEAN;
                                s.cache[i].seq = 0;
                            }
                        } else {
                            busy = true;
                        }
                    } else if rc == E_AGAIN {
                        busy = true;
                        break;
                    } else {
                        if s.wb_err == 0 {
                            s.wb_err = rc;
                        }
                        if c.flags & CF_SUPERSEDED != 0 {
                            s.cache[i] = CacheSlot::EMPTY;
                        } else {
                            s.cache[i].state = CS_CLEAN;
                        }
                    }
                } else if c.state == CS_WRITING {
                    busy = true;
                }
            }
            i += 1;
        }
        let mut z = 0usize;
        while z < ZERO_RUN_SLOTS {
            if s.zero_runs[z].live != 0 && s.zero_runs[z].epoch == w {
                if !fs_zero_submit(s, z) {
                    busy = true;
                }
                let mut k = 0usize;
                while k < ZERO_RUN_INFLIGHT {
                    if s.zero_runs[z].seq[k] != 0 {
                        busy = true;
                    }
                    k += 1;
                }
                if !busy && s.zero_runs[z].next >= s.zero_runs[z].n {
                    s.zero_runs[z].live = 0;
                }
            }
            z += 1;
        }
        if busy {
            return;
        }
        if s.durable_bits & (1u64 << (w % 64)) != 0 {
            if s.wb_ticket_live == 0 {
                s.wb_ticket = s.blk.flush_submit();
                s.wb_ticket_live = 1;
            }
            let r = s.blk.flush_poll(&*s.syscalls, s.wb_ticket);
            if r == 1 {
                return;
            }
            if r < 0 && s.wb_err == 0 {
                s.wb_err = r;
            }
            s.wb_ticket_live = 0;
            s.durable_bits &= !(1u64 << (w % 64));
            s.durable_through = w;
        }
        s.wb_epoch = w.wrapping_add(1);
    }
}

/// Everything the device has finished, and everything that can now be
/// started. Called at every dispatch and every step; never waits.
unsafe fn fs_pump(s: &mut Fat32State) {
    if s.syscalls.is_null() || s.in_chan < 0 {
        return;
    }
    if s.blk.caps(&*s.syscalls) != 0 {
        return;
    }
    s.blk.reap(&*s.syscalls);
    fs_route_reads(s);
    fs_wb_settle(s);
    fs_wb_advance(s);
}

// ── Transactions ───────────────────────────────────────────────────────────

unsafe fn tx_begin(s: &mut Fat32State) {
    s.tx_active = 1;
    s.miss = 0;
    s.op_wait_epoch = 0;
    s.tx.zero_runs = s.zero_runs;
    s.tx.durable_bits = s.durable_bits;
    s.tx.open_dirty_ms = s.open_dirty_ms;
    s.tx.epoch = s.epoch;
    s.tx.free_count = s.free_count;
    s.tx.unlink_free = s.unlink_free;
    s.tx.unlink_epoch = s.unlink_epoch;
    s.tx.root_cleaned = s.root_cleaned;
    s.tx.clear_next = s.clear_next;
    s.tx.clear_end = s.clear_end;
    s.tx_barriers = 0;
    s.tx_overflow = 0;
    s.tx.file_slot = u32::MAX;
    s.tx.dirs_n = 0;
    s.tx.epoch_has_fat = s.epoch_has_fat;
    s.tx.free_count_known = s.free_count_known;
    s.tx.fs_settle_pending = s.fs_settle_pending;
    s.tx.volume_clean = s.volume_clean;
    // The staging buffers carry nothing across a transaction boundary.
    s.fat_buf_lba = LBA_NONE;
    s.fat_dirty = 0;
    s.block_buf_lba = LBA_NONE;
}

/// Save `open_files[slot]` so an abort can put it back. One file per
/// transaction: no operation changes two.
unsafe fn tx_save_file(s: &mut Fat32State, slot: usize) {
    if s.tx_active == 0 || slot >= MAX_OPEN_FILES || s.tx.file_slot != u32::MAX {
        return;
    }
    s.tx.file_slot = slot as u32;
    let src = &s.open_files[slot] as *const OpenFile as *const u8;
    core::ptr::copy_nonoverlapping(src, s.tx.file.as_mut_ptr(), OF_HEAD);
}

/// Record that the transaction changed directory `dir`'s names, so an abort
/// drops whatever walks of it were cached over tentative bytes.
fn tx_note_dir(s: &mut Fat32State, dir: u32) {
    if s.tx_active == 0 {
        return;
    }
    let n = usize::from(s.tx.dirs_n);
    let mut i = 0usize;
    while i < n.min(TX_DIRS) {
        if s.tx.dirs[i] == dir {
            return;
        }
        i += 1;
    }
    if n < TX_DIRS {
        s.tx.dirs[n] = dir;
    }
    s.tx.dirs_n = s.tx.dirs_n.saturating_add(1);
}

unsafe fn tx_abort(s: &mut Fat32State) {
    let mut i = 0usize;
    while i < CACHE_SLOTS {
        if s.cache[i].flags & CF_TENTATIVE != 0 {
            s.cache[i] = CacheSlot::EMPTY;
        }
        i += 1;
    }
    s.zero_runs = s.tx.zero_runs;
    s.durable_bits = s.tx.durable_bits;
    s.open_dirty_ms = s.tx.open_dirty_ms;
    s.epoch = s.tx.epoch;
    s.free_count = s.tx.free_count;
    s.unlink_free = s.tx.unlink_free;
    s.unlink_epoch = s.tx.unlink_epoch;
    s.root_cleaned = s.tx.root_cleaned;
    s.clear_next = s.tx.clear_next;
    s.clear_end = s.tx.clear_end;
    s.epoch_has_fat = s.tx.epoch_has_fat;
    s.free_count_known = s.tx.free_count_known;
    s.fs_settle_pending = s.tx.fs_settle_pending;
    s.volume_clean = s.tx.volume_clean;
    let slot = s.tx.file_slot;
    if (slot as usize) < MAX_OPEN_FILES {
        let dst = &mut s.open_files[slot as usize] as *mut OpenFile as *mut u8;
        core::ptr::copy_nonoverlapping(s.tx.file.as_ptr(), dst, OF_HEAD);
    }
    s.tx_active = 0;
    let n = usize::from(s.tx.dirs_n);
    if n > TX_DIRS {
        s.dir_cursor.dir_cluster = 0;
        s.dir_cursor_pool = [DirCursor::empty(); DIR_CURSOR_POOL];
        s.dir_cache = [DirCacheEntry::EMPTY; DIR_CACHE];
    } else {
        let mut d = 0usize;
        while d < n {
            let dir = s.tx.dirs[d];
            fs_dir_changed(s, dir);
            d += 1;
        }
    }
    s.fat_buf_lba = LBA_NONE;
    s.fat_dirty = 0;
    s.block_buf_lba = LBA_NONE;
}

/// Make the transaction's writes final. False — the transaction aborted —
/// when landing the staged FAT sector needed a slot the cache did not have.
unsafe fn tx_commit(s: &mut Fat32State) -> bool {
    if fs_fat_flush(s) != 0 || s.miss != 0 {
        tx_abort(s);
        return false;
    }
    let mut lbas = [0u32; CACHE_SLOTS];
    let mut n = 0usize;
    let mut i = 0usize;
    while i < CACHE_SLOTS {
        if s.cache[i].flags & CF_TENTATIVE != 0 {
            s.cache[i].flags &= !CF_TENTATIVE;
            if n < CACHE_SLOTS {
                lbas[n] = s.cache[i].lba;
                n += 1;
            }
        }
        i += 1;
    }
    let mut k = 0usize;
    while k < n {
        fs_cache_settle_versions(s, lbas[k]);
        k += 1;
    }
    s.tx_active = 0;
    s.fat_buf_lba = LBA_NONE;
    s.block_buf_lba = LBA_NONE;
    true
}

/// Run `f` as one transaction. A miss, an `EAGAIN` or any failure aborts it
/// — leaving nothing changed — and is answered as such (a miss as
/// `EAGAIN`); success commits it.
unsafe fn fs_tx<F: FnOnce(&mut Fat32State) -> i32>(s: &mut Fat32State, f: F) -> i32 {
    tx_begin(s);
    let rc = f(s);
    if s.tx_overflow != 0 {
        tx_abort(s);
        return -7; // E2BIG: this transaction could never commit
    }
    if s.miss != 0 || rc == E_AGAIN {
        tx_abort(s);
        return E_AGAIN;
    }
    if rc < 0 {
        tx_abort(s);
        return rc;
    }
    if !tx_commit(s) {
        return E_AGAIN;
    }
    rc
}

// ── File data through an FD's scratch ──────────────────────────────────────

/// Collapse a run whose write-back borrowed the buffer, now that it is back.
unsafe fn fs_scratch_settle(s: &mut Fat32State, slot: usize) {
    let of = &mut s.open_files[slot];
    if of.scratch_compact != 0 && of.scratch_io == SIO_IDLE {
        of.scratch_compact = 0;
        scratch_retain_tail(of);
    }
}

/// Submit the FD's dirty run. 0 once it is submitted (or there was nothing
/// to submit), `EAGAIN` when it cannot be yet — the source's queue is full,
/// the buffer is still lent, or a metadata write to the same sectors is
/// still in flight — or the source's refusal.
unsafe fn fs_data_submit(s: &mut Fat32State, slot: usize) -> i32 {
    use abi::contracts::storage::block::caps as bc;
    if s.open_files[slot].scratch_dirty == 0 {
        return 0;
    }
    if s.open_files[slot].scratch_io != SIO_IDLE {
        return E_AGAIN;
    }
    let lba = s.open_files[slot].scratch_lba;
    let nlb = u32::from(s.open_files[slot].scratch_span);
    if nlb == 0 || nlb as usize > SCRATCH_SECTORS {
        return E_INVAL;
    }
    if !fs_data_claim(s, lba, nlb) {
        return E_AGAIN;
    }
    let abs = fs_abs_lba(s, lba);
    let p = s.open_files[slot].scratch_block.as_ptr();
    let rc = s.blk.submit_write(&*s.syscalls, abs, nlb, p);
    if rc != 0 {
        return rc;
    }
    let q = s.blk.last_seq();
    let copies = s.blk.flags() & bc::F_WRITE_COPIES != 0;
    let of = &mut s.open_files[slot];
    of.scratch_seq = q;
    of.scratch_dirty = 0;
    if s.blk.write_state(q) == 1 && !copies {
        // The source reads the buffer until the write completes; the run
        // stays exactly as submitted until then.
        of.scratch_io = SIO_WRITE;
        of.scratch_compact = 1;
    } else {
        scratch_retain_tail(of);
    }
    0
}

// ── Operations that answer `EINPROGRESS` ────────────────────────────────────

/// Taken operations held at once. A new one finds a free slot, or takes one
/// whose decision was never collected.
const FS_OP_SLOTS: usize = 4;

/// Longest argument a taken operation may carry: its bytes are kept whole
/// so a re-ask is recognised exactly. The longest is `RENAME`'s two
/// length-prefixed paths, 254 bytes each — longer than any path this
/// provider resolves usefully (each component is at most 64 characters, and
/// a FAT path of 260 is the format's own practical limit). A longer one is
/// refused `E2BIG`.
const OP_ARG_MAX: usize = 512;

const OPS_FREE: u8 = 0;
/// Committed; decided once `wait_epoch` is durable.
const OPS_WAIT: u8 = 1;
/// Decided: `result` is the answer to the next ask.
const OPS_DONE: u8 = 2;
/// A `PREALLOCATE` still allocating in the background.
const OPS_PREALLOC: u8 = 3;

#[derive(Clone, Copy)]
#[repr(C)]
struct OpSlot {
    /// FNV-1a over the argument bytes.
    hash: u64,
    opcode: u32,
    handle: i32,
    arg_len: u32,
    owner_gen: u32,
    wait_epoch: u32,
    result: i32,
    /// `PREALLOCATE`: the capacity asked for, and its clusters.
    capacity: u32,
    target: u32,
    owner_slot: u16,
    /// `PREALLOCATE`: the FD.
    fd: u16,
    state: u8,
    _pad: [u8; 7],
}

impl OpSlot {
    const EMPTY: Self = Self {
        hash: 0,
        opcode: 0,
        handle: 0,
        arg_len: 0,
        owner_gen: 0,
        wait_epoch: 0,
        result: 0,
        capacity: 0,
        target: 0,
        owner_slot: 0,
        fd: 0,
        state: OPS_FREE,
        _pad: [0; 7],
    };
}

/// Resumable position of a `TRUNCATE`'s walk to its new tail: cluster
/// number `n` (1-based) of the chain from `start` is `cur`. A cache over
/// the chain, not state: a walk of a different file starts over.
#[derive(Clone, Copy)]
#[repr(C)]
struct TruncWalk {
    start: u32,
    n: u32,
    cur: u32,
}

impl TruncWalk {
    const EMPTY: Self = Self {
        start: 0,
        n: 0,
        cur: 0,
    };
}

fn fs_fnv64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0usize;
    while i < bytes.len() {
        h ^= u64::from(bytes[i]);
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
        i += 1;
    }
    h
}

/// The identity of a request: who asked, and its byte-identical opcode,
/// handle and argument.
unsafe fn fs_op_key(
    s: &Fat32State,
    opcode: u32,
    handle: i32,
    arg: *const u8,
    arg_len: usize,
) -> OpSlot {
    let (owner_slot, owner_gen) = dev_caller_owner(s.sys()).unwrap_or((OWNER_NONE, 0));
    let hash = if arg.is_null() || arg_len == 0 {
        0
    } else {
        fs_fnv64(core::slice::from_raw_parts(arg, arg_len))
    };
    OpSlot {
        hash,
        opcode,
        handle,
        arg_len: arg_len as u32,
        owner_gen,
        owner_slot,
        ..OpSlot::EMPTY
    }
}

/// The slot holding the request `k` with argument `arg[..arg_len]`. The
/// hash only filters: the argument bytes the slot stored are compared in
/// full, so two requests can never share a decision.
unsafe fn fs_op_find(s: &Fat32State, k: &OpSlot, arg: *const u8, arg_len: usize) -> Option<usize> {
    let mut i = 0usize;
    while i < FS_OP_SLOTS {
        let o = &s.ops[i];
        if o.state != OPS_FREE
            && o.opcode == k.opcode
            && o.handle == k.handle
            && o.arg_len == k.arg_len
            && o.hash == k.hash
            && o.owner_slot == k.owner_slot
            && o.owner_gen == k.owner_gen
            && arg_len <= OP_ARG_MAX
        {
            let mut same = true;
            let mut j = 0usize;
            while j < arg_len {
                if s.op_args[i][j] != *arg.add(j) {
                    same = false;
                    break;
                }
                j += 1;
            }
            if same {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Keep request `i`'s argument bytes, for [`fs_op_find`] to compare.
unsafe fn fs_op_keep_arg(s: &mut Fat32State, i: usize, arg: *const u8, arg_len: usize) {
    let n = arg_len.min(OP_ARG_MAX);
    let mut j = 0usize;
    while j < n {
        s.op_args[i][j] = *arg.add(j);
        j += 1;
    }
}

/// A slot for a new operation: a free one, else one holding a decision
/// nobody collected. `None` while every slot holds an operation in
/// progress.
fn fs_op_slot(s: &mut Fat32State) -> Option<usize> {
    let mut i = 0usize;
    while i < FS_OP_SLOTS {
        if s.ops[i].state == OPS_FREE {
            return Some(i);
        }
        i += 1;
    }
    let mut j = 0usize;
    while j < FS_OP_SLOTS {
        if s.ops[j].state == OPS_DONE {
            s.ops[j] = OpSlot::EMPTY;
            return Some(j);
        }
        j += 1;
    }
    None
}

/// Move slot `i` towards its decision.
unsafe fn fs_op_progress(s: &mut Fat32State, i: usize) {
    if s.ops[i].state == OPS_PREALLOC {
        fs_prealloc_advance(s, i);
    }
    if s.ops[i].state == OPS_WAIT {
        if s.wb_err != 0 {
            s.ops[i].result = -5; // EIO
            s.ops[i].state = OPS_DONE;
            fs_op_finished(s, i);
        } else if fs_durable(s, s.ops[i].wait_epoch) {
            s.ops[i].state = OPS_DONE;
            fs_op_finished(s, i);
        }
    }
}

/// Bookkeeping when slot `i` is decided.
fn fs_op_finished(s: &mut Fat32State, i: usize) {
    if s.ops[i].opcode == FS_PREALLOCATE {
        let fd = usize::from(s.ops[i].fd);
        if fd < MAX_OPEN_FILES {
            let of = &mut s.open_files[fd];
            of.op_busy = 0;
            if s.ops[i].result == 0 {
                of.durable = 1;
                let covered = of.dir_media_size;
                let head = of.start_cluster;
                fs_note_dir_durable(s, fd, covered, head);
            }
        }
    }
}

/// The answer to an ask of slot `i`: its decision (and the slot is freed),
/// or `EINPROGRESS`.
unsafe fn fs_op_collect(s: &mut Fat32State, i: usize) -> i32 {
    fs_op_progress(s, i);
    if s.ops[i].state == OPS_DONE {
        let rc = s.ops[i].result;
        s.ops[i] = OpSlot::EMPTY;
        return rc;
    }
    E_INPROGRESS
}

/// Every operation in progress, one move each. Called from the step, so an
/// operation whose caller stopped asking still completes.
unsafe fn fs_ops_step(s: &mut Fat32State) -> bool {
    let mut busy = false;
    let mut i = 0usize;
    while i < FS_OP_SLOTS {
        if s.ops[i].state == OPS_WAIT || s.ops[i].state == OPS_PREALLOC {
            fs_op_progress(s, i);
            if s.ops[i].state != OPS_DONE {
                busy = true;
            }
        }
        i += 1;
    }
    busy
}

/// The FAT entry of `cluster`: the next cluster (28-bit), or `FAT32_EOC` at
/// the chain's end. `Err(EAGAIN)` when the FAT sector is not cached yet (its
/// read is under way), or the device's error.
unsafe fn fs_fat_next(s: &mut Fat32State, cluster: u32) -> Result<u32, i32> {
    let fat_lba = fat_sector_for_cluster(s, cluster);
    let rc = fs_fat_stage(s, fat_lba);
    if rc != 0 {
        fs_note_io(s, rc);
        return Err(rc);
    }
    let off = fat_offset_for_cluster(s, cluster);
    if off + 4 > BLOCK_SIZE {
        return Ok(FAT32_EOC);
    }
    let raw = read_u32_le(&s.fat_buf, off) & FAT32_MASK;
    if raw == 0 || raw >= FAT32_EOC {
        Ok(FAT32_EOC)
    } else {
        Ok(raw)
    }
}

/// Read one FAT entry; returns the next cluster number (28-bit) or
/// `FAT32_EOC` on chain end / error. A sector not cached yet is a miss
/// (`s.miss`), which aborts the transaction this runs in — so its `EOC`
/// never decides anything.
unsafe fn fs_read_fat_entry(s: &mut Fat32State, cluster: u32) -> u32 {
    let fat_lba = fat_sector_for_cluster(s, cluster);
    let rc = fs_fat_stage(s, fat_lba);
    if rc != 0 {
        fs_note_io(s, rc);
        return FAT32_EOC;
    }
    let off = fat_offset_for_cluster(s, cluster);
    if off + 4 > BLOCK_SIZE {
        return FAT32_EOC;
    }
    let buf = &s.fat_buf;
    let raw = u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) & FAT32_MASK;
    if raw == 0 || raw >= FAT32_EOC {
        FAT32_EOC
    } else {
        raw
    }
}

/// Record a device-I/O failure observed inside an Option/sentinel-
/// returning helper (see `Fat32State::io_rc`). First failure wins.
#[inline]
fn fs_note_io(s: &mut Fat32State, rc: i32) {
    if rc != 0 && s.io_rc == 0 {
        s.io_rc = rc;
    }
}

/// Errno for a device rc that reached the caller directly: `E_AGAIN`
/// stays `E_AGAIN` (transient — nvme busy or still initialising, the
/// caller retries next step), anything else is EIO. Collapsing a
/// transient into EIO makes durability-grade callers quarantine on a
/// hiccup.
#[inline]
fn fs_rc_errno(rc: i32) -> i32 {
    if rc == E_AGAIN {
        E_AGAIN
    } else {
        -5
    } // EIO
}

/// Errno for a failed resolve/scan/alloc at an FS_CONTRACT entry
/// point: a recorded device rc wins (see [`fs_rc_errno`]), otherwise
/// the semantic `default` (ENOENT, ENOSPC, …).
#[inline]
fn fs_io_errno(s: &Fat32State, default: i32) -> i32 {
    if s.io_rc == 0 {
        default
    } else {
        fs_rc_errno(s.io_rc)
    }
}

/// Errno for an allocation that could not be satisfied.
///
/// `ENOSPC` is a verdict about the volume and a consumer is right to act on
/// it — quarantine the write, fail the workload. The bounded free-cluster
/// scan can also come back empty-handed simply because it reached its sector
/// budget, and that is `EAGAIN`: the same request will succeed shortly. The
/// two must not be collapsed, in either direction.
fn fs_alloc_errno(s: &Fat32State) -> i32 {
    if s.alloc_yield != 0 {
        return E_AGAIN;
    }
    fs_io_errno(s, -28) // ENOSPC
}

/// Convert a path component to a FAT 8.3 short name (11 bytes,
/// space-padded, upper-cased). Returns false when the component is not a
/// legal 8.3 name.
///
/// Rejection, not truncation, is the whole point. Clipping a base longer
/// than 8 characters or an extension longer than 3 would give a caller that
/// asked for `datafile1.json` a file called `DATAFILE.JSO` — a different
/// name, silently, with no error. Two such requests can land on the same
/// entry, and every later lookup by the caller's own path goes through the
/// same clipping and therefore appears to work, right up until something
/// outside this provider reads the volume and finds a name nobody asked
/// for.
///
/// Generating `~1`-style names, the way a long-name-capable driver does,
/// would be the other answer, and needs long-name entries to record what
/// the name really was — see the module docs on what this provider does and
/// does not do with those. Until then a caller learns immediately, through
/// `EINVAL`, that the name it chose is not one this backend can carry.
fn fs_path_to_short_name(name: &[u8], out: &mut [u8; 11]) -> bool {
    *out = [b' '; 11];
    if name.is_empty() || name.len() > 12 {
        return false;
    }
    // `.` and `..` are directory-relative names this surface does not
    // resolve; accepting them as ordinary components would let a path escape
    // the tree it was resolved from.
    if name == b"." || name == b".." {
        return false;
    }
    // A trailing dot or space is dropped by the conversion, so accepting one
    // would hand the caller a file under a name it did not ask for — the same
    // silent substitution refusing an over-long base exists to prevent.
    let last = name[name.len() - 1];
    if last == b'.' || last == b' ' {
        return false;
    }
    let mut dot: usize = name.len();
    let mut i = 0usize;
    while i < name.len() {
        if name[i] == b'.' {
            if dot != name.len() {
                return false; // more than one separator is not an 8.3 name
            }
            dot = i;
        }
        i += 1;
    }
    let base = &name[..dot];
    let ext: &[u8] = if dot < name.len() {
        &name[dot + 1..]
    } else {
        &[]
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 {
        return false;
    }
    let mut j = 0usize;
    while j < base.len() {
        let c = fs_short_name_char(base[j]);
        if c == 0 {
            return false;
        }
        out[j] = c;
        j += 1;
    }
    let mut k = 0usize;
    while k < ext.len() {
        let c = fs_short_name_char(ext[k]);
        if c == 0 {
            return false;
        }
        out[8 + k] = c;
        k += 1;
    }
    // A first byte of 0xE5 is the deletion marker; the format reserves 0x05
    // to mean "this entry really does start with 0xE5". Nothing this
    // provider accepts can produce it, but encoding the rule here keeps the
    // guarantee local to the one function that decides what a name may be.
    if out[0] == 0xE5 {
        out[0] = 0x05;
    }
    true
}

/// Fold one character into its 8.3 form, or 0 when it is not legal in one.
///
/// The permitted set is the FAT specification's: ASCII above the control
/// range, minus the characters the format or its readers give other
/// meanings. Lower case folds to upper because a short name has no case;
/// storing it unfolded makes a name that only this provider can find again.
const fn fs_short_name_char(c: u8) -> u8 {
    if c <= 0x20 || c >= 0x7F {
        return 0;
    }
    match c {
        b'"' | b'*' | b'+' | b',' | b'.' | b'/' | b':' | b';' | b'<' | b'=' | b'>' | b'?'
        | b'[' | b'\\' | b']' | b'|' => 0,
        b'a'..=b'z' => c - 32,
        _ => c,
    }
}

/// Result of a successful path resolution.
#[derive(Clone, Copy)]
struct ResolvedFile {
    start_cluster: u32,
    size: u32,
    /// Last-write time as Unix seconds; 0 when the entry carries no stamp.
    mtime: u32,
    /// The 8.3 name of the terminal component, carried out of the walk that
    /// already computed it so callers do not re-derive it (and cannot
    /// disagree with it).
    name: [u8; 11],
    /// Where its directory entry lives.
    dir_lba: u32,
    dir_off: u16,
}

/// Whether a closed handle is still writing back the file whose entry is at
/// `(lba, off)`. Until it finishes, the entry on the volume does not yet say
/// what that handle wrote, so an open or a create of the file waits
/// (`EAGAIN`) rather than seeing — or truncating under — a stale entry.
fn fs_detached_writer_at(s: &Fat32State, lba: u32, off: u16) -> bool {
    let mut k = 0usize;
    while k < MAX_OPEN_FILES {
        let of = &s.open_files[k];
        if of.in_use == OF_DETACHED && of.writable != 0 && of.dir_lba == lba && of.dir_off == off {
            return true;
        }
        k += 1;
    }
    false
}

/// One path component, in both forms the directory can be searched by.
///
/// A name that fits 8.3 has `long_len == 0` and is matched against entries'
/// own name fields. A name that
/// does not is matched against the long-name companion run instead, and
/// carries its 8.3 form only as the synthesised `BASE~N.EXT` that will be
/// minted alongside it.
///
/// The two cannot be collapsed: a generated short name depends on what else
/// is already in the directory, so it is not derivable from the name the
/// caller asked for and cannot be used to find the entry again.
#[derive(Clone, Copy)]
struct PathName {
    short: [u8; 11],
    long: [u8; LFN_MAX_CHARS],
    long_len: u8,
}

impl PathName {
    const fn empty() -> Self {
        Self {
            short: [b' '; 11],
            long: [0; LFN_MAX_CHARS],
            long_len: 0,
        }
    }

    fn long_slice(&self) -> &[u8] {
        &self.long[..self.long_len as usize]
    }

    /// Companion entries a set for this name occupies. 0 for an 8.3 name.
    fn lfn_entries(&self) -> u8 {
        if self.long_len == 0 {
            return 0;
        }
        self.long_len.div_ceil(LFN_CHARS_PER_ENTRY as u8)
    }
}

/// Parse one path component into both forms, or `None` when it is not a name
/// this provider can carry.
///
/// 8.3 is tried first, so every name that worked before still takes the path
/// it took before and mints no companions — a volume this provider writes
/// stays as plain as the caller's names allow.
fn fs_path_component(comp: &[u8], out: &mut PathName) -> bool {
    *out = PathName::empty();
    if fs_path_to_short_name(comp, &mut out.short) {
        return true;
    }
    // Long form. ASCII only: decoding UTF-8 into the UTF-16 the format
    // stores means surrogate handling in a module that cannot afford to get
    // it subtly wrong, and a mangled name is worse than a refused one. Names
    // containing non-ASCII that were written elsewhere are still preserved
    // and still retired with their entries; they simply cannot be created or
    // looked up here.
    if comp.is_empty() || comp.len() > LFN_MAX_CHARS {
        return false;
    }
    if comp == b"." || comp == b".." {
        return false;
    }
    let mut i = 0usize;
    while i < comp.len() {
        let c = comp[i];
        if !(0x20..0x7F).contains(&c) {
            return false;
        }
        // The characters the format reserves for its own structure, plus the
        // separator this surface splits on.
        if matches!(
            c,
            b'/' | b'\\' | b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|'
        ) {
            return false;
        }
        i += 1;
    }
    // A trailing dot or space is not preserved by any FAT implementation, so
    // a caller that asked for one would get a different name back.
    let last = comp[comp.len() - 1];
    if last == b'.' || last == b' ' {
        return false;
    }
    out.long[..comp.len()].copy_from_slice(comp);
    out.long_len = comp.len() as u8;
    true
}

/// Fill `name.short` with an 8.3 alias for its long form, unique within
/// `parent`.
///
/// Every long-named entry still carries a short name, because that is the
/// field the format itself indexes by and the one any reader that ignores
/// companions will show. It has to be unique in the directory or two files
/// collide in the only name the format guarantees.
///
/// Four numeric tails are probed, then a hashed one. Probing indefinitely
/// would make a directory holding many similar long names quadratic in
/// device reads, inside a dispatch that is already budgeted; the hash makes
/// the fifth attempt as likely to be unique as the thousandth would be, and
/// bounds the work. Returns 0, `E_AGAIN` when a probe ran out of budget, or
/// a negative errno.
unsafe fn fs_assign_short_alias(s: &mut Fat32State, parent: u32, name: &mut PathName) -> i32 {
    let long = &name.long[..name.long_len as usize];

    // Extension: the run after the last dot, if it holds anything usable.
    let mut dot = long.len();
    let mut i = 0usize;
    while i < long.len() {
        if long[i] == b'.' {
            dot = i;
        }
        i += 1;
    }
    let mut ext = [b' '; 3];
    let mut ne = 0usize;
    let mut k = dot + 1;
    while k < long.len() && ne < 3 {
        let c = fs_short_name_char(long[k]);
        if c != 0 {
            ext[ne] = c;
            ne += 1;
        }
        k += 1;
    }

    // Stem: the first usable characters of the name before the extension.
    let mut stem = [b' '; 8];
    let mut ns = 0usize;
    let mut j = 0usize;
    while j < dot && ns < 8 {
        let c = fs_short_name_char(long[j]);
        if c != 0 {
            stem[ns] = c;
            ns += 1;
        }
        j += 1;
    }
    if ns == 0 {
        // Nothing in the name survives 8.3's character set. `_` keeps the
        // alias well-formed rather than leaving a blank name field, which no
        // reader treats as a name.
        stem[0] = b'_';
        ns = 1;
    }

    let mut attempt: u32 = 1;
    loop {
        let mut cand = [b' '; 11];
        let head = if attempt <= 4 {
            // `STEM~N`: keep as much of the name as the tail leaves room for.
            let keep = ns.min(8 - 2);
            cand[..keep].copy_from_slice(&stem[..keep]);
            let mut h = keep;
            cand[h] = b'~';
            h += 1;
            cand[h] = b'0' + attempt as u8;
            h + 1
        } else {
            // Four collisions in one directory means the names share a long
            // prefix, and more numbers will keep colliding. A checksum of the
            // whole long name does not.
            let sum = fs_name_hash(long);
            let keep = ns.min(2);
            cand[..keep].copy_from_slice(&stem[..keep]);
            let mut h = keep;
            let mut d = 0usize;
            while d < 4 {
                let nib = ((sum >> (12 - d * 4)) & 0xF) as u8;
                cand[h] = if nib < 10 {
                    b'0' + nib
                } else {
                    b'A' + nib - 10
                };
                h += 1;
                d += 1;
            }
            cand[h] = b'~';
            h += 1;
            cand[h] = b'0' + (attempt - 4) as u8;
            h + 1
        };
        let _ = head;
        cand[8..11].copy_from_slice(&ext);

        match fs_dir_walk(s, parent, &cand, 1) {
            DirScan::Found(_) => {}
            DirScan::Pending => return E_AGAIN,
            DirScan::Io => return fs_io_errno(s, -5),
            // Free or Full both mean the alias is not taken.
            _ => {
                name.short = cand;
                return 0;
            }
        }
        attempt += 1;
        if attempt > 8 {
            // Five hashed attempts all collided, which means five different
            // long names hash the same AND share a stem. Refusing beats
            // minting a duplicate short name.
            return -17; // EEXIST
        }
    }
}

/// 16-bit checksum of a long name, for the hashed short-name tail.
fn fs_name_hash(name: &[u8]) -> u16 {
    let mut h: u16 = 0;
    let mut i = 0usize;
    while i < name.len() {
        h = h.rotate_left(5) ^ u16::from(to_upper(name[i]));
        i += 1;
    }
    h
}

/// Read the 8.3 name field of the entry at `loc`.
///
/// Needed wherever an existing long-named entry is reused: its companions
/// carry the checksum of THAT alias, so the entry must keep it.
unsafe fn fs_dirent_short_name(s: &mut Fat32State, loc: &DirentLoc) -> Option<[u8; 11]> {
    if fs_read_blockbuf(s, loc.lba) != 0 {
        return None;
    }
    let e = loc.off as usize;
    let mut out = [b' '; 11];
    out.copy_from_slice(&s.block_buf[e..e + 11]);
    Some(out)
}

/// Walk `parent` for `name`, in whichever form it carries.
unsafe fn fs_name_walk(s: &mut Fat32State, parent: u32, name: &PathName, need: u8) -> DirScan {
    fs_dir_walk_long(s, parent, &name.short, need, name.long_slice())
}

/// Look up one path component: the matched entry's
/// `(start_cluster, size, attr)`, or `None`.
///
/// `None` covers three cases the Option cannot distinguish, so the two that
/// are not "absent" are recorded in `io_rc` for [`fs_io_errno`] to turn back
/// into the right errno: a device failure keeps its rc, and a walk that ran
/// out of step budget records `EAGAIN` so the caller retries rather than
/// concluding the name does not exist. Reporting ENOENT for a directory the
/// provider simply has not finished reading is the failure mode that makes a
/// consumer truncate-create over live data.
unsafe fn fs_dir_lookup(
    s: &mut Fat32State,
    dir_first_cluster: u32,
    want: &PathName,
) -> Option<DirentLoc> {
    match fs_name_walk(s, dir_first_cluster, want, 1) {
        DirScan::Found(loc) => Some(loc),
        DirScan::Pending => {
            fs_note_io(s, E_AGAIN);
            None
        }
        _ => None,
    }
}

/// Resolve an absolute FAT32 path (e.g. `/web/INDEX.HTM`) to its
/// `(start_cluster, size)`. Walks each path component synchronously
/// through `fs_dir_lookup`. Returns None on ENOENT or malformed
/// path. Path components must already be in 8.3-compatible form
/// (case-folded internally by `fs_path_to_short_name`).
unsafe fn fs_resolve_path(s: &mut Fat32State, path: &[u8]) -> Option<ResolvedFile> {
    if s.init_phase != Fat32InitPhase::Done {
        return None;
    }
    if s.root_cluster < 2 {
        return None;
    }
    if path.is_empty() {
        return None;
    }
    // Walk past leading slashes.
    let mut pos = 0usize;
    while pos < path.len() && path[pos] == b'/' {
        pos += 1;
    }
    if pos >= path.len() {
        return None;
    } // bare "/"

    let mut cur_cluster = s.root_cluster;
    loop {
        // Extract the next component up to the next '/' or end-of-string.
        let start = pos;
        while pos < path.len() && path[pos] != b'/' {
            pos += 1;
        }
        let comp = &path[start..pos];
        if comp.is_empty() {
            return None;
        }
        let mut want = PathName::empty();
        if !fs_path_component(comp, &mut want) {
            return None;
        }
        // Skip trailing slashes.
        while pos < path.len() && path[pos] == b'/' {
            pos += 1;
        }
        let is_final = pos >= path.len();
        if !is_final {
            // An intermediate component must be a directory.
            let (sc, attr) = fs_dir_component(s, cur_cluster, &want)?;
            if (attr & ATTR_DIRECTORY) == 0 {
                return None;
            }
            cur_cluster = sc;
            continue;
        }
        let found = fs_dir_lookup(s, cur_cluster, &want)?;
        // The terminal component must be a regular file — directories
        // aren't openable through FS_OPEN.
        if (found.attr & ATTR_DIRECTORY) != 0 {
            return None;
        }
        return Some(ResolvedFile {
            start_cluster: found.start_cluster,
            size: found.size,
            mtime: found.mtime,
            name: want.short,
            dir_lba: found.lba,
            dir_off: found.off,
        });
    }
}

/// Claim a free `open_files` slot, or report why there is none.
///
/// The diagnostic is the point. `ENFILE` on a provider-wide table tells the
/// caller only that somebody else is using it, and the caller cannot see who
/// — so an operator gets "storage stopped working" with nothing to act on.
/// Listing the names currently holding slots turns that into a question with
/// an answer.
unsafe fn fs_claim_slot(s: &mut Fat32State) -> Option<usize> {
    // Whoever is on the provider stack owns whatever this call opens. `None`
    // means the open did not arrive through a dispatch — there is nobody to
    // charge, and charging the last caller seen would bill a workload for
    // this provider's own housekeeping.
    let owner = dev_caller_owner(s.sys());
    let (owner_slot, owner_generation) = owner.unwrap_or((OWNER_NONE, 0));

    if s.max_open_per_owner > 0 && owner_slot != OWNER_NONE {
        let mut held: u32 = 0;
        let mut k = 0usize;
        while k < MAX_OPEN_FILES {
            if s.open_files[k].in_use == OF_OPEN
                && s.open_files[k].owner_slot == owner_slot
                && s.open_files[k].owner_generation == owner_generation
            {
                held += 1;
            }
            k += 1;
        }
        if held >= s.max_open_per_owner {
            // Refuse the owner that is over its share while the table still
            // has room, so the failure lands on the workload at fault rather
            // than on whoever asks next.
            let mut line = [0u8; 64];
            let head = b"[fat32] owner over handle quota: slot=";
            let mut n = head.len();
            line[..n].copy_from_slice(head);
            write_dec_u32(&mut line, &mut n, u32::from(owner_slot));
            let held_tag = b" held=";
            line[n..n + held_tag.len()].copy_from_slice(held_tag);
            n += held_tag.len();
            write_dec_u32(&mut line, &mut n, held);
            dev_log(s.sys(), 4, line.as_ptr(), n);
            return None;
        }
    }

    let mut k = 0usize;
    while k < MAX_OPEN_FILES {
        if s.open_files[k].in_use == 0 {
            s.open_files[k].owner_slot = owner_slot;
            s.open_files[k].owner_generation = owner_generation;
            return Some(k);
        }
        k += 1;
    }
    let mut line = [0u8; 128];
    let head = b"[fat32] no free handle; held by:";
    let mut n = head.len();
    line[..n].copy_from_slice(head);
    let mut i = 0usize;
    while i < MAX_OPEN_FILES && n + 12 < line.len() {
        line[n] = b' ';
        n += 1;
        let name = s.open_files[i].name;
        let mut j = 0usize;
        while j < 11 {
            line[n] = if name[j] == b' ' { b'_' } else { name[j] };
            n += 1;
            j += 1;
        }
        i += 1;
    }
    dev_log(s.sys(), 4, line.as_ptr(), n);
    None
}

/// Append `v` as decimal into `buf` at `n`, bounded by the buffer.
fn write_dec_u32(buf: &mut [u8], n: &mut usize, v: u32) {
    let mut digits = [0u8; 10];
    let mut d = 0usize;
    let mut x = v;
    loop {
        digits[d] = b'0' + (x % 10) as u8;
        d += 1;
        x /= 10;
        if x == 0 {
            break;
        }
    }
    while d > 0 && *n < buf.len() {
        d -= 1;
        buf[*n] = digits[d];
        *n += 1;
    }
}

/// FS_OPEN: resolve the absolute path through the FAT32 tree
/// (`fs_resolve_path` walks the dir chain synchronously through
/// `storage.block` `EXEC` reads), then allocate an `OpenFile` slot
/// populated with the file's `start_cluster` + `size`. Returns the
/// slot index as the FD, or a negative errno.
unsafe fn fs_op_open(s: &mut Fat32State, arg: *const u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len == 0 {
        return E_INVAL;
    }
    if s.init_phase != Fat32InitPhase::Done {
        return E_AGAIN;
    }
    s.io_rc = 0;
    let path = core::slice::from_raw_parts(arg, arg_len);
    let resolved = match fs_resolve_path(s, path) {
        Some(r) => r,
        // A resolve that failed on a device read is not "no such file" —
        // reporting ENOENT here makes callers truncate-create over a live
        // file. Surface the real errno.
        None => return fs_io_errno(s, -2), // ENOENT only when truly absent
    };
    if fs_detached_writer_at(s, resolved.dir_lba, resolved.dir_off) {
        return E_AGAIN;
    }
    // Allocate slot.
    let Some(slot) = fs_claim_slot(s) else {
        return -23; // ENFILE
    };
    let of = &mut s.open_files[slot];
    of.in_use = 1;
    of.name = resolved.name;
    of.mtime = resolved.mtime;
    of.start_cluster = resolved.start_cluster;
    of.current_cluster = resolved.start_cluster;
    of.size = resolved.size;
    of.offset = 0;
    of.sector_in_cluster = 0;
    of.scratch_avail = 0;
    of.scratch_pos = 0;
    of.scratch_lba = 0;
    of.scratch_span = 0;
    of.scratch_cluster = 0;
    of.scratch_dirty = 0;
    of.writable = 0;
    of.dirty = 0;
    of.dir_lba = 0;
    of.dir_off = 0;
    // FS handles carry their contract in the tag; the vtable
    // wrapper strips it on re-entry so inbound ops see the raw
    // slot.
    abi::kernel_abi::fd::tag_fd(abi::kernel_abi::fd::FD_TAG_FS, slot as i32)
}

/// FS_READ: copy what the FD's scratch already mirrors, and start fetching
/// the next run of sectors when it runs out. Never waits: answers the bytes
/// copied (possibly short), 0 at EOF, or `EAGAIN` when nothing could be
/// copied yet because the data is still on its way.
///
/// The cursor is `(current_cluster, sector_in_cluster)` alongside `offset`.
/// `sector_in_cluster == sectors_per_cluster` means the cursor has consumed
/// its cluster and the next one is not resolved yet: resolving it needs the
/// FAT, which may not be cached, so it happens on the next read rather than
/// as the last act of this one.
unsafe fn fs_op_read(s: &mut Fat32State, handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len == 0 {
        return E_INVAL;
    }
    if s.init_phase != Fat32InitPhase::Done {
        return E_AGAIN;
    }
    let slot = handle as usize;
    if slot >= MAX_OPEN_FILES || s.open_files[slot].in_use != OF_OPEN {
        return E_INVAL;
    }
    if s.open_files[slot].is_dir != 0 {
        return E_INVAL;
    }
    let err = s.open_files[slot].io_err;
    if err != 0 {
        s.open_files[slot].io_err = 0;
        return fs_rc_errno(err);
    }
    let bps = s.bytes_per_sector as u32;
    let spc = s.sectors_per_cluster as u32;
    if bps == 0 || spc == 0 {
        return E_AGAIN;
    }
    fs_scratch_settle(s, slot);
    // Sequential: at the start of the file, or where the last read ended.
    let start = s.open_files[slot].offset;
    let sequential = start == 0 || s.open_files[slot].ra_next == start.wrapping_add(1);
    let mut written: usize = 0;
    let mut waiting = false;
    while written < arg_len {
        let (offset, size) = (s.open_files[slot].offset, s.open_files[slot].size);
        let remaining = size.saturating_sub(offset);
        if remaining == 0 {
            break;
        }
        if u32::from(s.open_files[slot].sector_in_cluster) >= spc {
            // The cursor consumed its cluster; resolve the next one.
            let cur = s.open_files[slot].current_cluster;
            match fs_fat_next(s, cur) {
                Ok(next) if (2..FAT32_EOC).contains(&next) => {
                    let of = &mut s.open_files[slot];
                    of.current_cluster = next;
                    of.sector_in_cluster = 0;
                }
                Ok(_) => {
                    // No more clusters: the file ends here, whatever its
                    // size says.
                    let of = &mut s.open_files[slot];
                    of.offset = of.size;
                    break;
                }
                Err(E_AGAIN) => {
                    waiting = true;
                    break;
                }
                Err(rc) => {
                    if written > 0 {
                        break;
                    }
                    return fs_rc_errno(rc);
                }
            }
        }
        let of = &s.open_files[slot];
        let sector = cluster_to_sector(s, of.current_cluster) + u32::from(of.sector_in_cluster);
        let in_sec = offset % bps;
        let mirrored = of.scratch_io != SIO_READ
            && of.scratch_span > 0
            && sector >= of.scratch_lba
            && sector - of.scratch_lba < u32::from(of.scratch_span);
        if mirrored {
            let idx = (sector - of.scratch_lba) as usize;
            let take = (bps - in_sec)
                .min(remaining)
                .min((arg_len - written) as u32) as usize;
            let src = s.open_files[slot]
                .scratch_block
                .as_ptr()
                .add(idx * BLOCK_SIZE + in_sec as usize);
            core::ptr::copy_nonoverlapping(src, arg.add(written), take);
            written += take;
            let of = &mut s.open_files[slot];
            of.offset = of.offset.wrapping_add(take as u32);
            if in_sec as usize + take == bps as usize {
                of.sector_in_cluster = of.sector_in_cluster.wrapping_add(1);
            }
            continue;
        }
        // Not mirrored: read it through the sector cache, which outlives
        // the handle — a caller that closes and reopens on `EAGAIN` finds
        // the sector its first ask fetched. One of this FD's own writes
        // still in flight could land after a read of the same sectors, so
        // the read waits for it.
        let own = s.open_files[slot].scratch_seq;
        if own != 0 && s.blk.write_state(own) == 1 {
            waiting = true;
            break;
        }
        // On a miss, the rest of the cluster (as far as the file goes) is
        // read with it, in one request.
        let left_in_cluster = spc - u32::from(s.open_files[slot].sector_in_cluster);
        let left_in_file = (remaining + in_sec).div_ceil(bps);
        s.ra_hint = left_in_cluster.min(left_in_file).saturating_sub(1);
        let got = fs_cache_get(s, sector);
        s.ra_hint = 0;
        match got {
            Ok(i) => {
                let take = (bps - in_sec)
                    .min(remaining)
                    .min((arg_len - written) as u32) as usize;
                let src = s.cache_data[i].as_ptr().add(in_sec as usize);
                core::ptr::copy_nonoverlapping(src, arg.add(written), take);
                written += take;
                s.rd_sectors = s.rd_sectors.wrapping_add(1);
                let of = &mut s.open_files[slot];
                of.offset = of.offset.wrapping_add(take as u32);
                if in_sec as usize + take == bps as usize {
                    of.sector_in_cluster = of.sector_in_cluster.wrapping_add(1);
                }
            }
            Err(E_AGAIN) => {
                s.rd_runs = s.rd_runs.wrapping_add(1);
                waiting = true;
                break;
            }
            Err(rc) => {
                if written > 0 {
                    break;
                }
                return fs_rc_errno(rc);
            }
        }
    }
    // A sequential reader keeps what comes next on its way, here and from
    // the step. A reader that seeks about does not pay for read-ahead it
    // would skip past.
    let of = &mut s.open_files[slot];
    of.ra_next = of.offset.wrapping_add(1);
    of.ra_on = u8::from(sequential && of.offset < of.size);
    if of.ra_on != 0 {
        fs_read_ahead(s, slot);
    }
    if written > 0 {
        return written as i32;
    }
    if waiting {
        return E_AGAIN;
    }
    0
}

/// The step's half of streaming: every handle being read keeps its
/// read-ahead going as the runs before it land.
unsafe fn fs_step_read_ahead(s: &mut Fat32State) {
    let mut k = 0usize;
    while k < MAX_OPEN_FILES {
        if s.open_files[k].in_use == OF_OPEN && s.open_files[k].ra_on != 0 {
            fs_read_ahead(s, k);
        }
        k += 1;
    }
}

/// FS_SEEK: walk the cluster chain to the target cluster — from the
/// cursor's own cluster when a read-only cursor moves forward, from the
/// chain head otherwise. Answers the resulting offset, or `EAGAIN` with the
/// cursor where it was while a FAT sector of the walk is still on its way.
unsafe fn fs_op_seek(s: &mut Fat32State, handle: i32, arg: *const u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 4 {
        return E_INVAL;
    }
    let slot_idx = handle as usize;
    if slot_idx >= MAX_OPEN_FILES {
        return E_INVAL;
    }
    if s.open_files[slot_idx].in_use != OF_OPEN {
        return E_INVAL;
    }
    // The offset is 32 bits or 64, selected by the buffer the caller gave.
    // FAT32 cannot address past 4 GiB whichever form arrives, so a wide
    // offset that does not fit is refused rather than wrapped — a silently
    // truncated seek reads the wrong part of the file and looks like data
    // corruption to the caller.
    let wide = arg_len >= 8;
    let raw: u64 = if wide {
        let a = core::slice::from_raw_parts(arg, 8);
        u64::from_le_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]])
    } else {
        let v = i32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
        if v < 0 {
            return E_INVAL;
        }
        v as u64
    };
    if raw > u64::from(u32::MAX) {
        return E_INVAL;
    }
    let target = raw as u32;
    // A seek to the CURRENT offset is a positional no-op — the common WAL
    // "FS_SEEK to s.cursor before every append" pattern — so the pending run
    // stays intact and coalescing survives.
    if target == s.open_files[slot_idx].offset {
        return target as i32;
    }
    let bps = s.bytes_per_sector as u32;
    let spc = s.sectors_per_cluster as u32;
    if bps == 0 || spc == 0 {
        return E_AGAIN;
    }
    let cluster_bytes = bps * spc;
    // Fixed-capacity WAL batches write a four-byte terminator and immediately
    // rewind over it. Keep that same-cluster reposition O(1): the scratch
    // still mirrors the sector, and a full FAT walk from the chain head
    // would turn file age into latency. The mirror is matched by sector, so
    // a dirty run survives the move.
    let old_offset = s.open_files[slot_idx].offset;
    if s.open_files[slot_idx].writable != 0
        && old_offset > 0
        && (old_offset - 1) / cluster_bytes == target / cluster_bytes
    {
        let within_cluster = target % cluster_bytes;
        let of = &mut s.open_files[slot_idx];
        of.offset = target;
        of.sector_in_cluster = (within_cluster / bps) as u8;
        of.scratch_pos = (target % bps) as u16;
        of.scratch_avail = 0;
        of.cursor_positioned = 1;
        return target as i32;
    }
    if s.open_files[slot_idx].writable != 0
        && s.open_files[slot_idx].fixed_capacity != 0
        && s.open_files[slot_idx].fixed_contiguous != 0
        && old_offset > 0
        && (old_offset - 1) / cluster_bytes == target / cluster_bytes + 1
    {
        // The four-byte terminator straddled a cluster boundary. A physically
        // contiguous fixed chain can rewind one cluster arithmetically.
        let within_cluster = target % cluster_bytes;
        let of = &mut s.open_files[slot_idx];
        of.current_cluster = of.current_cluster.saturating_sub(1);
        of.offset = target;
        of.sector_in_cluster = (within_cluster / bps) as u8;
        of.scratch_pos = (target % bps) as u16;
        of.scratch_avail = 0;
        of.cursor_positioned = 1;
        return target as i32;
    }
    // A real reposition. A dirty run goes to the device first, so nothing
    // the walk below decides depends on bytes only this FD has seen; if it
    // cannot go yet, the cursor stays where it is.
    if s.open_files[slot_idx].scratch_dirty != 0 {
        let rc = fs_data_submit(s, slot_idx);
        if rc == E_AGAIN {
            return E_AGAIN;
        }
        if rc != 0 {
            return fs_rc_errno(rc);
        }
    }
    let target_cluster_idx = target / cluster_bytes;
    let target_sector = ((target % cluster_bytes) / bps) as u8;

    let start = s.open_files[slot_idx].start_cluster;
    let mut cluster = start;
    let mut walked = 0u32;
    // A reader moving forward walks on from where it stands, not from the
    // chain head: a read-only cursor inside the file holds the cluster
    // containing its offset (or, at `sector_in_cluster == spc`, the one
    // before it), so a file read block by block with a seek before each
    // walks the chain once in all, not once per block.
    {
        let of = &s.open_files[slot_idx];
        let here = if u32::from(of.sector_in_cluster) >= spc {
            (of.offset / cluster_bytes).saturating_sub(1)
        } else {
            of.offset / cluster_bytes
        };
        if of.writable == 0
            && of.offset < of.size
            && here <= target_cluster_idx
            && of.current_cluster >= 2
        {
            cluster = of.current_cluster;
            walked = here;
        }
    }
    while walked < target_cluster_idx {
        // On a miss, the FAT sectors the walk will want next come with it.
        let fsec = fat_sector_for_cluster(s, cluster);
        let fat_end = s.fat_start_sector.saturating_add(s.fat_size_32);
        s.ra_hint = READAHEAD_SECTORS.min(fat_end.saturating_sub(fsec + 1));
        let r = fs_fat_next(s, cluster);
        s.ra_hint = 0;
        let next = match r {
            Ok(n) => n,
            Err(E_AGAIN) => return E_AGAIN,
            Err(rc) => return fs_rc_errno(rc),
        };
        if next >= FAT32_EOC {
            // Seeking past EOF — clamp the offset to the file size.
            // POSIX lseek allows seeking past end, but the FS dispatch
            // contract caps reads at `size`, so this stays consistent.
            let size = s.open_files[slot_idx].size;
            let of = &mut s.open_files[slot_idx];
            of.offset = size;
            of.scratch_avail = 0;
            of.scratch_pos = 0;
            return size as i32;
        }
        cluster = next;
        walked += 1;
    }
    let within_sector = target % bps;
    let of = &mut s.open_files[slot_idx];
    of.current_cluster = cluster;
    of.sector_in_cluster = target_sector;
    of.offset = target;
    // `cluster` is the walked, existing cluster holding byte `target`, so the
    // cursor is positioned (not lagging). A subsequent boundary write must
    // reuse it rather than advance. The past-EOF branch above returns before
    // here, so appends at EOF keep the lazy convention and still allocate.
    of.cursor_positioned = 1;
    of.scratch_pos = within_sector as u16;
    of.scratch_avail = 0;
    target as i32
}

/// `OWNER_RELEASED`: close every handle this provider opened on behalf of an
/// owner that is being torn down.
///
/// The table is provider-wide and shared between owners, and nothing else ever
/// reclaims a slot a dead consumer left open: `max_open_per_owner` caps how
/// many a workload can hold but has no way to notice it is gone. Without this,
/// a workload that faults with files open costs those slots until the module is
/// reinstantiated, and the operator sees `ENFILE` on a module that did nothing
/// wrong.
///
/// The generation is compared along with the slot for the reason the stamp
/// carries it: an owner slot is reused, and matching on the slot alone would
/// close the live handles of the workload that replaced the dead one.
///
/// Each slot goes through `fs_op_close`, so a writable handle's tail is
/// written back and its directory entry patched exactly as an explicit close
/// would do it: in the background, after the slot has stopped being a
/// handle. Nothing here waits. Returns the number of slots released.
unsafe fn fs_op_owner_released(s: &mut Fat32State, arg: *const u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < OWNER_RELEASED_ARG_LEN {
        return E_INVAL;
    }
    let rec = core::slice::from_raw_parts(arg, OWNER_RELEASED_ARG_LEN);
    let slot = u16::from_le_bytes([rec[0], rec[1]]);
    let generation = u32::from_le_bytes([rec[4], rec[5], rec[6], rec[7]]);
    // An unstamped handle (opened outside a provider frame) belongs to nobody
    // and is never swept by an owner release.
    if slot == OWNER_NONE {
        return 0;
    }
    let mut released = 0i32;
    let mut k = 0usize;
    while k < MAX_OPEN_FILES {
        if s.open_files[k].in_use == OF_OPEN
            && s.open_files[k].owner_slot == slot
            && s.open_files[k].owner_generation == generation
        {
            let _ = fs_op_close(s, k as i32);
            released += 1;
        }
        k += 1;
    }
    released
}

/// Whether a closed handle still has work the step must finish before its
/// slot can be reused: data or a directory entry to write back, or a device
/// request still holding its buffer.
fn fs_close_needs_step(s: &Fat32State, of: &OpenFile) -> bool {
    of.scratch_io != SIO_IDLE
        || of.op_busy != 0
        || (of.writable != 0
            && (of.scratch_dirty != 0
                || of.dirty != 0
                || (of.scratch_seq != 0 && s.blk.write_state(of.scratch_seq) == 1)))
}

/// FS_CLOSE: release the handle. Never waits and always releases.
///
/// A writable handle's unwritten tail and its directory entry (size and
/// first cluster) are written back by the step after the handle is gone
/// (`fs_step_detached`), in the order a close has always used — the data
/// completes before the entry that publishes its size is written. Close does
/// not report how that goes: durability is what `FSYNC`, the async fence and
/// `FSYNC_NAME` are for, and a caller that needs it fences before closing.
/// Answers 0, or `EBADF` for a handle that is not open.
unsafe fn fs_op_close(s: &mut Fat32State, handle: i32) -> i32 {
    let slot_idx = handle as usize;
    if slot_idx >= MAX_OPEN_FILES || s.open_files[slot_idx].in_use != OF_OPEN {
        return -9; // EBADF
    }
    // Release any fence still naming this slot. `fs_op_fsync_poll` rejects
    // a ticket whose generation no longer matches, so a caller holding one
    // across close gets `EINVAL` rather than a fence over another file.
    let mut f = 0usize;
    while f < MAX_FENCES {
        if s.fences[f].stage != 0 && s.fences[f].file as usize == slot_idx {
            s.fences[f].stage = 0;
        }
        f += 1;
    }
    if s.open_files[slot_idx].writable != 0 {
        // Publish the free-cluster summary once the volume settles, so a
        // later mount resumes the scan past what this handle allocated.
        s.fs_settle_pending = 1;
    }
    if fs_close_needs_step(s, &s.open_files[slot_idx]) {
        s.open_files[slot_idx].in_use = OF_DETACHED;
        s.wb_kick = 1;
    } else {
        s.open_files[slot_idx] = OpenFile::empty();
    }
    0
}

/// Finish the closed handles: submit an unwritten tail, wait (without
/// blocking) for it and for any request still holding the buffer, then
/// patch the directory entry and free the slot. True while any remain.
unsafe fn fs_step_detached(s: &mut Fat32State) -> bool {
    let mut busy = false;
    let mut k = 0usize;
    while k < MAX_OPEN_FILES {
        if s.open_files[k].in_use != OF_DETACHED {
            k += 1;
            continue;
        }
        fs_scratch_settle(s, k);
        let of = &s.open_files[k];
        if of.op_busy != 0 || of.scratch_io != SIO_IDLE {
            busy = true;
            k += 1;
            continue;
        }
        if of.writable != 0 && of.scratch_dirty != 0 {
            let rc = fs_data_submit(s, k);
            if rc == E_AGAIN || s.open_files[k].scratch_io != SIO_IDLE {
                busy = true;
                k += 1;
                continue;
            }
            if rc != 0 && s.wb_err == 0 {
                s.wb_err = rc;
            }
        }
        // The data completes before the entry that publishes its size is
        // written.
        let seq = s.open_files[k].scratch_seq;
        if seq != 0 && s.blk.write_state(seq) == 1 {
            busy = true;
            k += 1;
            continue;
        }
        if s.open_files[k].writable != 0 && s.open_files[k].dirty != 0 {
            let rc = fs_tx(s, |s| {
                let b = fs_begin_mutation(s);
                if b != 0 {
                    return b;
                }
                fs_writeback_dir_entry(s, k)
            });
            if rc == E_AGAIN {
                busy = true;
                k += 1;
                continue;
            }
            if rc < 0 && s.wb_err == 0 {
                s.wb_err = rc;
            }
        }
        s.open_files[k] = OpenFile::empty();
        k += 1;
    }
    busy
}

/// FS_STAT: report a handle's size and modification time, in the width the
/// caller's buffer selects — `[size: u64, mtime: u64]` at 16 bytes or more,
/// `[size: u32, mtime: u32]` at 8.
///
/// `mtime` is 0: FAT32 stores a modification time in the directory entry,
/// but this provider does not maintain one, and returning a fabricated value
/// would be worse than returning none. Reporting 0 says "unknown"; the
/// alternative says "1980" and means the same thing while looking like data.
unsafe fn fs_op_stat(s: &Fat32State, handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 8 {
        return E_INVAL;
    }
    let slot_idx = handle as usize;
    if slot_idx >= MAX_OPEN_FILES {
        return E_INVAL;
    }
    if s.open_files[slot_idx].in_use != OF_OPEN {
        return E_INVAL;
    }
    let size = u64::from(s.open_files[slot_idx].size);
    let mtime = u64::from(s.open_files[slot_idx].mtime);
    if arg_len >= 16 {
        let out = core::slice::from_raw_parts_mut(arg, 16);
        out[..8].copy_from_slice(&size.to_le_bytes());
        out[8..].copy_from_slice(&mtime.to_le_bytes());
        return 16;
    }
    let out = core::slice::from_raw_parts_mut(arg, 8);
    // A FAT32 file cannot exceed 4 GiB, so the narrow form can always carry
    // it; the check states the invariant rather than trusting it.
    debug_assert!(size <= u64::from(u32::MAX));
    out[..4].copy_from_slice(&(size as u32).to_le_bytes());
    out[4..].copy_from_slice(&(mtime as u32).to_le_bytes());
    8
}

/// Same component walk as `fs_resolve_path`, but the terminal name
/// must be a *directory* (or the path may be the bare root `/`).
/// Returns the directory's first cluster on success, or `None` for
/// ENOENT / ENOTDIR. Used exclusively by `fs_op_opendir`.
unsafe fn fs_resolve_dir_path(s: &mut Fat32State, path: &[u8]) -> Option<u32> {
    if s.init_phase != Fat32InitPhase::Done {
        return None;
    }
    if s.root_cluster < 2 {
        return None;
    }
    // Strip leading + trailing slashes; bare "/" → root.
    let mut start = 0usize;
    while start < path.len() && path[start] == b'/' {
        start += 1;
    }
    let mut end = path.len();
    while end > start && path[end - 1] == b'/' {
        end -= 1;
    }
    if start >= end {
        return Some(s.root_cluster);
    }

    let mut cur_cluster = s.root_cluster;
    let mut pos = start;
    loop {
        let comp_start = pos;
        while pos < end && path[pos] != b'/' {
            pos += 1;
        }
        let comp = &path[comp_start..pos];
        if comp.is_empty() {
            return None;
        }
        let mut want = PathName::empty();
        if !fs_path_component(comp, &mut want) {
            return None;
        }
        let (sc, attr) = fs_dir_component(s, cur_cluster, &want)?;
        // Every intermediate AND the terminal component must be a dir.
        if (attr & ATTR_DIRECTORY) == 0 {
            return None;
        }
        cur_cluster = sc;
        while pos < end && path[pos] == b'/' {
            pos += 1;
        }
        if pos >= end {
            return Some(cur_cluster);
        }
    }
}

/// FS_OPENDIR: resolve the absolute path to a directory's first
/// cluster, then allocate a slot in `open_files` flagged as a dir.
/// The dir-cursor (`current_cluster`, `sector_in_cluster`, `offset` =
/// entry index within sector) starts at the first entry of the
/// first cluster.
unsafe fn fs_op_opendir(s: &mut Fat32State, arg: *const u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len == 0 {
        return E_INVAL;
    }
    if s.init_phase != Fat32InitPhase::Done {
        return E_AGAIN;
    }
    s.io_rc = 0;
    let path = core::slice::from_raw_parts(arg, arg_len);
    let dir_cluster = match fs_resolve_dir_path(s, path) {
        Some(c) => c,
        None => return fs_io_errno(s, -2), // ENOENT only when truly absent
    };
    let Some(slot) = fs_claim_slot(s) else {
        return -23; // ENFILE
    };
    let of = &mut s.open_files[slot];
    of.in_use = 1;
    of.is_dir = 1;
    of.dir_eof = 0;
    of.start_cluster = dir_cluster;
    of.current_cluster = dir_cluster;
    of.sector_in_cluster = 0;
    of.offset = 0; // entry index within current sector (0..entries_per_sector)
    of.size = 0;
    of.scratch_avail = 0;
    of.scratch_pos = 0;
    abi::kernel_abi::fd::tag_fd(abi::kernel_abi::fd::FD_TAG_FS, slot as i32)
}

/// FS_READDIR: walk dir entries from the cursor, emit one byte
/// stream of `[count:u16][name_len:u8][type:u8][name…]` records,
/// stop when the output buffer can't fit another entry. `.` and
/// `..` are skipped. LFN companion entries (attr == 0x0F), deleted
/// entries (first byte 0xE5), volume labels (attr & 0x08), hidden +
/// system entries (attr & 0x06) are all skipped at this layer so the
/// caller only sees user-visible files + directories.
///
/// On end-of-directory the function returns 0 and latches `dir_eof`
/// so subsequent calls keep returning 0 without re-walking the chain.
unsafe fn fs_op_readdir(s: &mut Fat32State, handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 2 {
        return E_INVAL;
    }
    if s.init_phase != Fat32InitPhase::Done {
        return E_AGAIN;
    }
    let slot_idx = handle as usize;
    if slot_idx >= MAX_OPEN_FILES {
        return E_INVAL;
    }
    if s.open_files[slot_idx].in_use != OF_OPEN {
        return E_INVAL;
    }
    if s.open_files[slot_idx].is_dir == 0 {
        return E_INVAL;
    }
    if s.open_files[slot_idx].dir_eof != 0 {
        return 0;
    }
    s.io_rc = 0;

    let spc = s.sectors_per_cluster as u32;
    if spc == 0 {
        return E_AGAIN;
    }
    let entries_per_sector = BLOCK_SIZE / DIR_ENTRY_SIZE;

    // Reserve 2 bytes for the count header; entries start at offset 2.
    let mut out_pos: usize = 2;
    let mut count: u16 = 0;
    let mut buf = [0u8; BLOCK_SIZE];

    loop {
        let cur_cluster = s.open_files[slot_idx].current_cluster;
        if cur_cluster < 2 {
            s.open_files[slot_idx].dir_eof = 1;
            break;
        }
        let cluster_first_sector = cluster_to_sector(s, cur_cluster);
        let sec = s.open_files[slot_idx].sector_in_cluster as u32;
        if sec >= spc {
            // Cluster exhausted — walk the FAT chain.
            let next = match fs_fat_next(s, cur_cluster) {
                Ok(n) => n,
                // A FAT read that has not landed or failed is not the end of
                // the directory. Latching dir_eof here would silently
                // truncate the listing (recovery would then treat missing
                // entries as deleted files). Hand back what this call has
                // gathered; the cursor resumes here.
                Err(rc) => {
                    if count > 0 {
                        break;
                    }
                    return fs_rc_errno(rc);
                }
            };
            if next >= FAT32_EOC {
                s.open_files[slot_idx].dir_eof = 1;
                break;
            }
            s.open_files[slot_idx].current_cluster = next;
            s.open_files[slot_idx].sector_in_cluster = 0;
            s.open_files[slot_idx].offset = 0;
            continue;
        }
        let lba = cluster_first_sector + sec;
        s.ra_hint = READAHEAD_SECTORS.min(spc - sec - 1);
        let got = fs_cache_get(s, lba);
        s.ra_hint = 0;
        match got {
            Ok(i) => {
                let src = s.cache_data[i].as_ptr();
                core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), BLOCK_SIZE);
            }
            Err(rrc) => {
                // Not cached yet, or a failed read — don't advance the
                // cursor. What this call already gathered is answered; the
                // next call resumes at this sector.
                if count > 0 {
                    break;
                }
                return fs_rc_errno(rrc);
            }
        }
        let mut e = s.open_files[slot_idx].offset as usize;
        while e < entries_per_sector {
            let off = e * DIR_ENTRY_SIZE;
            let first = buf[off];
            if first == 0x00 {
                // End-of-directory marker.
                s.open_files[slot_idx].dir_eof = 1;
                let cnt_le = count.to_le_bytes();
                *arg = cnt_le[0];
                *arg.add(1) = cnt_le[1];
                return out_pos as i32;
            }
            if first == 0xE5 {
                e += 1;
                continue;
            }
            let attr = buf[off + 11];
            // Skip LFN companion entries (attr == 0x0F), volume label
            // (0x08), hidden (0x02), system (0x04). Regular files +
            // dirs have neither of those four bits set in the lower
            // nibble combinations we filter.
            if attr == ATTR_LONG_NAME {
                e += 1;
                continue;
            }
            if (attr & (ATTR_VOLUME_ID | 0x02 | 0x04)) != 0 {
                e += 1;
                continue;
            }
            // Decode 8.3 short name back into "NAME.EXT" form.
            let raw = &buf[off..off + 11];
            // Skip "." and ".." pseudo-entries.
            if raw[0] == b'.' {
                let is_dot = raw[1] == b' ' && raw[2] == b' ';
                let is_dotdot = raw[1] == b'.' && raw[2] == b' ';
                if is_dot || is_dotdot {
                    e += 1;
                    continue;
                }
            }
            // Trim trailing spaces from name (0..8) and ext (8..11).
            let mut nlen = 8usize;
            while nlen > 0 && raw[nlen - 1] == b' ' {
                nlen -= 1;
            }
            let mut elen = 3usize;
            while elen > 0 && raw[8 + elen - 1] == b' ' {
                elen -= 1;
            }
            let total = nlen + if elen > 0 { 1 + elen } else { 0 };
            // Per-entry overhead: name_len(1) + type(1) + bytes.
            let need = 2 + total;
            if out_pos + need > arg_len {
                // Buffer full: stop here, don't advance cursor past
                // this entry. Next READDIR call will resume from `e`.
                if count == 0 {
                    // Even one entry didn't fit — caller's buffer is
                    // too small. Signal E2BIG without advancing.
                    return -7; // E2BIG
                }
                s.open_files[slot_idx].offset = e as u32;
                let cnt_le = count.to_le_bytes();
                *arg = cnt_le[0];
                *arg.add(1) = cnt_le[1];
                return out_pos as i32;
            }
            *arg.add(out_pos) = total as u8;
            *arg.add(out_pos + 1) = if (attr & ATTR_DIRECTORY) != 0 { 1 } else { 0 };
            let mut wp = out_pos + 2;
            // Copy name (lower-cased for cleaner display).
            let mut i = 0usize;
            while i < nlen {
                let c = raw[i];
                let lc = if c.is_ascii_uppercase() { c + 32 } else { c };
                *arg.add(wp) = lc;
                wp += 1;
                i += 1;
            }
            if elen > 0 {
                *arg.add(wp) = b'.';
                wp += 1;
                let mut k = 0usize;
                while k < elen {
                    let c = raw[8 + k];
                    let lc = if c.is_ascii_uppercase() { c + 32 } else { c };
                    *arg.add(wp) = lc;
                    wp += 1;
                    k += 1;
                }
            }
            out_pos = wp;
            count += 1;
            e += 1;
        }
        // Finished the sector — advance to the next one in this cluster
        // (or cluster boundary will be handled on the next loop iter).
        s.open_files[slot_idx].sector_in_cluster += 1;
        s.open_files[slot_idx].offset = 0;
    }

    let cnt_le = count.to_le_bytes();
    *arg = cnt_le[0];
    *arg.add(1) = cnt_le[1];
    out_pos as i32
}

// ============================================================================
// FS_CONTRACT write path (FS_OPEN_CREATE / FS_WRITE / FS_FSYNC)
// ============================================================================
//
// Append-only synchronous writer, the counterpart of the synchronous
// read path (`fs_op_open`/`fs_op_read`). Every block op is a
// `storage.block` `EXEC` request, or a pipelined write fenced later,
// because a `provider_call` must complete within the call. Targets the
// append-only workload:
// OPEN_CREATE → WRITE×N → FSYNC → CLOSE. All bookkeeping is sector-at-a-
// time read-modify-write; `block_buf` is the FAT/dir scratch and each
// FD's `scratch_block` is the data RMW buffer (nothing else runs during
// a synchronous dispatch on this cooperative single-core design).

/// Stage the sector at `lba` into `block_buf` from the cache. `EAGAIN` (and
/// the miss recorded) when it is not cached yet: its read is under way.
unsafe fn fs_read_blockbuf(s: &mut Fat32State, lba: u32) -> i32 {
    match fs_cache_get(s, lba) {
        Ok(i) => {
            let src = s.cache_data[i].as_ptr();
            core::ptr::copy_nonoverlapping(src, s.block_buf.as_mut_ptr(), BLOCK_SIZE);
            s.block_buf_lba = lba;
            0
        }
        Err(rc) => {
            // A failed read leaves the buffer holding whatever it held
            // before, and the tag must not claim otherwise — the next caller
            // would then patch and write back a stale sector under the new
            // LBA.
            s.block_buf_lba = LBA_NONE;
            rc
        }
    }
}

/// Write `block_buf` back to the sector it is staged for — into the cache,
/// for the write-back to put on the device.
///
/// The tag is what makes this safe to call: a caller that patched
/// `block_buf` after reading some *other* sector into it would otherwise
/// silently publish those bytes at the wrong LBA.
unsafe fn fs_write_staged(s: &mut Fat32State, lba: u32) -> i32 {
    debug_assert_eq!(
        s.block_buf_lba, lba,
        "write-back of a staging buffer holding a different sector"
    );
    // A directory sector is the thing that *references* clusters. Publishing
    // one while the links it depends on have not reached the device would
    // let a crash leave a size claiming bytes the chain cannot reach — the
    // one failure direction that is corruption rather than a shorter file.
    // So the staged FAT lands first, and a boundary puts it on the device
    // before this sector.
    let frc = fs_fat_flush(s);
    if frc != 0 {
        return frc;
    }
    if s.epoch_has_fat != 0 && fs_barrier(s, false) == 0 {
        return E_AGAIN;
    }
    let i = match fs_cache_dirty(s, lba, false) {
        Ok(i) => i,
        Err(rc) => {
            s.block_buf_lba = LBA_NONE;
            return rc;
        }
    };
    let dst = fs_slot_ptr(s, i);
    core::ptr::copy_nonoverlapping(s.block_buf.as_ptr(), dst, BLOCK_SIZE);
    s.block_buf_lba = lba;
    0
}

/// Write `nlb` whole sectors at `lba` from a buffer that is NOT `block_buf`,
/// through the cache.
unsafe fn fs_write_sector_from(s: &mut Fat32State, lba: u32, nlb: u16, buf: *const u8) -> i32 {
    let mut k = 0u32;
    while k < u32::from(nlb) {
        let i = match fs_cache_dirty(s, lba + k, false) {
            Ok(i) => i,
            Err(rc) => return rc,
        };
        let dst = fs_slot_ptr(s, i);
        core::ptr::copy_nonoverlapping(buf.add(k as usize * BLOCK_SIZE), dst, BLOCK_SIZE);
        if s.block_buf_lba == lba + k {
            s.block_buf_lba = LBA_NONE;
        }
        if s.fat_buf_lba == lba + k {
            debug_assert_eq!(s.fat_dirty, 0, "overwrote a dirty FAT sector");
            s.fat_buf_lba = LBA_NONE;
        }
        k += 1;
    }
    0
}

/// Stage the FAT sector at `fat1_lba` (a sector of the FIRST FAT) into
/// `fat_buf`, landing whatever it currently holds first if that is dirty and
/// for a different sector.
///
/// Every read and every write of a FAT entry goes through here. That is the
/// property the write-back depends on: there is no second path by which a
/// stale copy of a FAT sector can be observed or published.
unsafe fn fs_fat_stage(s: &mut Fat32State, fat1_lba: u32) -> i32 {
    if s.fat_buf_lba == fat1_lba {
        return 0;
    }
    let was_dirty = s.fat_dirty != 0;
    let rc = fs_fat_flush(s);
    if rc != 0 {
        return rc;
    }
    // Moving on from a FAT sector this operation changed: what it changed
    // there reaches the device before what it changes next. That is the
    // order the allocator's two-sector links are written in — the new
    // cluster's own entry before the link that reaches it — so an
    // interruption leaks a cluster rather than linking a chain into one the
    // FAT still calls free.
    if was_dirty && fs_barrier(s, false) == 0 {
        return E_AGAIN;
    }
    match fs_cache_get(s, fat1_lba) {
        Ok(i) => {
            let src = s.cache_data[i].as_ptr();
            core::ptr::copy_nonoverlapping(src, s.fat_buf.as_mut_ptr(), BLOCK_SIZE);
            s.fat_buf_lba = fat1_lba;
            0
        }
        Err(rc) => {
            // A failed read leaves whatever was there; the tag must not
            // claim otherwise, or the next patch writes back a stale sector
            // under the new LBA.
            s.fat_buf_lba = LBA_NONE;
            rc
        }
    }
}

/// Land `fat_buf` in the cache for every FAT copy and clear the dirty mark.
///
/// FAT32 keeps `num_fats` identical copies; a mutation that updates only one
/// leaves the volume inconsistent to any reader that prefers another copy,
/// and `fsck` repairs it by picking one arbitrarily. Every FAT mutation in
/// this provider funnels through here so that cannot be got wrong in one
/// place and right in the others.
unsafe fn fs_fat_flush(s: &mut Fat32State) -> i32 {
    if s.fat_dirty == 0 {
        return 0;
    }
    let fat1_lba = s.fat_buf_lba;
    if fat1_lba == LBA_NONE {
        s.fat_dirty = 0;
        return 0;
    }
    let rel = fat1_lba.wrapping_sub(s.fat_start_sector);
    let mut fi: u32 = 0;
    while fi < u32::from(s.num_fats) {
        let sec = s.fat_start_sector + fi * s.fat_size_32 + rel;
        let i = match fs_cache_dirty(s, sec, false) {
            Ok(i) => i,
            Err(rc) => return rc,
        };
        let dst = fs_slot_ptr(s, i);
        core::ptr::copy_nonoverlapping(s.fat_buf.as_ptr(), dst, BLOCK_SIZE);
        fi += 1;
    }
    s.epoch_has_fat = 1;
    s.fat_dirty = 0;
    0
}

/// Patch a FAT32 entry in the staged FAT sector, preserving the top 4
/// reserved bits. The caller has already staged the containing sector.
#[inline]
unsafe fn patch_fat_entry(s: &mut Fat32State, cluster: u32, value: u32) {
    let off = fat_offset_for_cluster(s, cluster);
    if off + 4 > BLOCK_SIZE {
        return;
    }
    let existing = read_u32_le(&s.fat_buf, off);
    let merged = (existing & !FAT32_MASK) | (value & FAT32_MASK);
    write_u32_le(&mut s.fat_buf, off, merged);
    s.fat_dirty = 1;
}

/// Write `value` (28-bit) into `cluster`'s FAT entry, preserving the top 4
/// reserved bits. The sector is staged and marked dirty; it reaches media at
/// the next flush point (see [`fs_fat_flush`]).
unsafe fn fs_write_fat_entry(s: &mut Fat32State, cluster: u32, value: u32) -> i32 {
    let fat1 = fat_sector_for_cluster(s, cluster);
    let rc = fs_fat_stage(s, fat1);
    if rc != 0 {
        return rc;
    }
    patch_fat_entry(s, cluster, value);
    0
}

/// Scan `[lo, hi)` for the first cluster whose FAT entry is free (== 0),
/// staged through `fat_buf`. Consumes `budget` sectors at most.
unsafe fn fs_scan_free_clusters(
    s: &mut Fat32State,
    lo: u32,
    hi: u32,
    budget: &mut u32,
) -> FreeScan {
    let bps = s.bytes_per_sector as u32;
    if bps == 0 {
        return FreeScan::Exhausted;
    }
    let eps = bps / 4;
    if eps == 0 {
        return FreeScan::Exhausted;
    }
    let mut c = if lo < 2 { 2 } else { lo };
    while c < hi {
        if *budget == 0 || (*budget < FAT_SCAN_BUDGET_SECTORS && fs_out_of_time(s)) {
            s.free_scan_cursor = c;
            return FreeScan::Yield;
        }
        let fat_sec = fat_sector_for_cluster(s, c);
        // A sector already staged costs nothing, and the common case — an
        // append walking forward through one sector's 128 entries — stages
        // it once. Only a genuine device read is charged to the budget.
        let charged = s.fat_buf_lba != fat_sec;
        // On a miss, the sectors the scan will want next come with it.
        let fat_end = s.fat_start_sector.saturating_add(s.fat_size_32);
        s.ra_hint = READAHEAD_SECTORS.min(fat_end.saturating_sub(fat_sec + 1));
        let rrc = fs_fat_stage(s, fat_sec);
        s.ra_hint = 0;
        if rrc == E_AGAIN {
            // Not cached yet: its read is under way. Resume here.
            s.free_scan_cursor = c;
            return FreeScan::Yield;
        }
        if rrc != 0 {
            fs_note_io(s, rrc);
            s.free_scan_cursor = c;
            return FreeScan::Exhausted;
        }
        if charged {
            *budget -= 1;
        }
        let first_in_sec = (fat_sec - s.fat_start_sector).wrapping_mul(eps);
        let end = first_in_sec + eps;
        let mut cc = c;
        while cc < end && cc < hi {
            if cc >= 2 {
                let off = ((cc - first_in_sec) * 4) as usize;
                if off + 4 <= BLOCK_SIZE && (read_u32_le(&s.fat_buf, off) & FAT32_MASK) == 0 {
                    s.free_scan_cursor = cc + 1;
                    return FreeScan::Found(cc);
                }
            }
            cc += 1;
        }
        c = end;
    }
    s.free_scan_cursor = hi;
    FreeScan::Exhausted
}

/// Find a free cluster, treating `next_free_hint` as a true HINT, not a
/// hard floor: scan `[hint, max)` first (the common fast path — the hint
/// points at fresh free space), then WRAP and scan `[2, hint)`. Without
/// the wrap a stale FSINFO hint or an `init_free_hint` set past the
/// actually-free region would return ENOSPC while free clusters sit below
/// it. Does not mutate the FAT — the caller links what it is given.
///
/// Returns 0 for two different situations, which the caller must tell
/// apart by `alloc_yield`: the volume is full, or this call reached its
/// sector budget and has more to look at. On a nearly-full or badly
/// fragmented volume the second is the common one — an exhaustive scan of a
/// 2 TiB volume's FAT is 512 MiB of reads, and running that inside one
/// `provider_call` stalls every other module sharing the lane. The scan
/// therefore resumes from `free_scan_cursor` on the next call, so a caller
/// that honours `EAGAIN` still converges.
unsafe fn fs_find_free_cluster(s: &mut Fat32State) -> u32 {
    s.alloc_yield = 0;
    // Real data-cluster ceiling, not raw FAT capacity — never return a slack
    // entry that maps past the data area.
    let max_clst = cluster_count_ceiling(s);
    if max_clst < 3 {
        return 0;
    }
    // A volume already scanned end-to-end without a hit stays full until
    // something is freed, which is the only event that can change the answer.
    // Re-scanning per request would turn every write against a full volume
    // into a full-FAT read.
    if s.free_scan_phase == FREE_SCAN_FULL {
        return 0;
    }
    let hint = if s.next_free_hint < 2 {
        2
    } else {
        s.next_free_hint.min(max_clst)
    };
    if s.free_scan_cursor < 2 {
        s.free_scan_cursor = if s.free_scan_phase == FREE_SCAN_FORWARD {
            hint
        } else {
            2
        };
    }
    let mut budget = FAT_SCAN_BUDGET_SECTORS;
    loop {
        let (lo, hi) = if s.free_scan_phase == FREE_SCAN_FORWARD {
            (s.free_scan_cursor, max_clst)
        } else {
            // Cap the upper bound at `max_clst` — a stale FSINFO hint or an
            // `init_free_hint` set beyond the data area would otherwise scan
            // past it and return a bogus (out-of-range) cluster.
            (s.free_scan_cursor, hint)
        };
        match fs_scan_free_clusters(s, lo, hi, &mut budget) {
            FreeScan::Found(c) => return c,
            FreeScan::Yield => {
                s.alloc_yield = 1;
                return 0;
            }
            FreeScan::Exhausted => {
                if s.free_scan_phase == FREE_SCAN_FORWARD && hint > 2 {
                    // Wrap: the region at/after the hint is spent; reclaim
                    // from the low region the hint skipped past.
                    s.free_scan_phase = FREE_SCAN_WRAPPED;
                    s.free_scan_cursor = 2;
                    continue;
                }
                s.free_scan_phase = FREE_SCAN_FULL;
                return 0;
            }
        }
    }
}

/// Reopen the free-cluster scan. Called wherever clusters are returned to
/// the volume: a `FREE_SCAN_FULL` verdict is only true until that happens.
#[inline]
fn fs_free_scan_reset(s: &mut Fat32State) {
    s.free_scan_phase = FREE_SCAN_FORWARD;
    s.free_scan_cursor = 0;
}

/// Link exactly one free cluster onto the chain ending at `prev` (or start a
/// chain when `prev < 2`), marking it end-of-chain.
///
/// The append path allocates one cluster at a time rather than reserving an
/// extent, and that is a correctness decision, not a performance oversight.
/// FAT32 describes a file's extent with nothing but its chain and its size,
/// so a reserved-but-unwritten cluster is indistinguishable from a file
/// whose size field is wrong: `fsck` reports "cluster chain length is >
/// file size" and offers to truncate. Reserving ahead therefore leaves every
/// growing file in a state a standard checker calls an error, for as long as
/// it is being written — and permanently if the writer dies.
///
/// The cost of not reserving is one FAT-sector read-modify-write per cluster
/// boundary. The read is served from `block_buf`'s tag on the common
/// sequential path (128 entries share a sector), so what remains is one
/// sector write per FAT copy per boundary — 4 KiB of writes per 4 MiB
/// appended at typical geometry. The throughput-critical caller, a WAL
/// segment, does not pay it at all: [`fs_op_preallocate`] links its whole
/// chain up front, where a reservation IS the file's size and no
/// inconsistency exists.
unsafe fn fs_alloc_one(s: &mut Fat32State, prev: u32) -> u32 {
    let cc = fs_find_free_cluster(s);
    if cc < 2 {
        return 0;
    }
    let rc = fs_write_fat_entry(s, cc, FAT32_TAIL);
    if rc != 0 {
        // The caller distinguishes "no space" from "the device refused", and
        // collapsing the second into the first makes a consumer quarantine
        // on a transient hiccup. Record the rc so `fs_io_errno` reports it.
        fs_note_io(s, rc);
        return 0;
    }
    let rc = if prev >= 2 {
        fs_write_fat_entry(s, prev, cc)
    } else {
        0
    };
    if rc != 0 {
        fs_note_io(s, rc);
        // The new cluster is marked EOC but nothing references it. It is a
        // leak, not a corruption, and it is bounded at one cluster per
        // failed link; the free-count is marked unknown so nothing trusts a
        // stale summary.
        fs_free_count_unknown(s);
        return 0;
    }
    if cc >= s.next_free_hint {
        s.next_free_hint = cc + 1;
    }
    fs_free_count_add(s, -1);
    cc
}

/// Maximum contiguous allocation made by one synchronous append boundary.
/// A FAT32 sector contains 128 entries with 512-byte sectors. Stay within one
/// sector and reserve as much of its contiguous free tail as fits; 127
/// clusters is just under 512 KiB with 4 KiB clusters. The device work remains
/// exactly one sector write per FAT copy regardless of the number reserved.
const FS_ALLOC_EXTENT_CLUSTERS: u8 = 127;

/// Allocate a small contiguous extent, mark its final cluster EOC, and (when
/// `prev >= 2`) link `prev` to its first cluster. The free scan leaves the FAT
/// sector containing `first` staged in `fat_buf`, so the common sequential
/// case patches the whole extent and the previous tail in one staged sector.
///
/// Returns `(first_cluster, cluster_count)` or `(0, 0)` on disk-full / I/O
/// failure. The extent never crosses a FAT-sector boundary; fragmentation
/// simply shortens it. Callers retain the unused contiguous count separately
/// from logical file size, so preallocation is invisible to STAT/replay.
unsafe fn fs_alloc_extent(s: &mut Fat32State, prev: u32) -> (u32, u8) {
    let cc = fs_find_free_cluster(s);
    if cc < 2 {
        return (0, 0);
    }

    let fat_lba = fat_sector_for_cluster(s, cc);
    let max_clst = cluster_count_ceiling(s);
    let mut count: u8 = 1;
    while count < FS_ALLOC_EXTENT_CLUSTERS {
        let candidate = cc + count as u32;
        if candidate >= max_clst || fat_sector_for_cluster(s, candidate) != fat_lba {
            break;
        }
        let off = fat_offset_for_cluster(s, candidate);
        if off + 4 > BLOCK_SIZE || (read_u32_le(&s.fat_buf, off) & FAT32_MASK) != 0 {
            break;
        }
        count += 1;
    }

    let last = cc + count as u32 - 1;
    let mut c = cc;
    while c < last {
        patch_fat_entry(s, c, c + 1);
        c += 1;
    }
    patch_fat_entry(s, last, FAT32_TAIL);

    let prev_inline = prev >= 2 && fat_sector_for_cluster(s, prev) == fat_lba;
    if prev_inline {
        patch_fat_entry(s, prev, cc);
    }

    fs_free_count_add(s, -i32::from(count));

    // If the old tail lives in another FAT sector, link it only after the new
    // extent is durable in the FAT — staging that sector flushes this one
    // first. An interruption can leak the new extent, but can never leave the
    // live file chain pointing into an uninitialised allocation.
    if prev >= 2 && !prev_inline {
        let lrc = fs_write_fat_entry(s, prev, cc);
        if lrc != 0 {
            fs_note_io(s, lrc);
            return (0, 0);
        }
    }

    s.next_free_hint = last + 1;
    s.free_scan_cursor = last + 1;
    (cc, count)
}

/// Free an entire cluster chain (set every entry to 0). Used to
/// truncate an existing file on FS_OPEN_CREATE.
unsafe fn fs_free_chain(s: &mut Fat32State, start: u32) {
    let mut c = start;
    let mut guard: u32 = 0;
    while (2..FAT32_EOC).contains(&c) && guard < 0x1000_0000 {
        let next = fs_read_fat_entry(s, c); // EOC on chain end / 0
        let _ = fs_write_fat_entry(s, c, 0);
        if !(2..FAT32_EOC).contains(&next) {
            break;
        }
        c = next;
        guard += 1;
    }
}

/// FS_UNLINK: remove `path`'s directory entry and queue its cluster chain
/// for lazy reclamation. See the `FS_UNLINK` opcode doc for the split
/// between the O(1) synchronous part and the per-step chain free.
///
/// Refuses (`EBUSY`) while any open FD references the entry — writable
/// FDs are matched by their directory-entry location, read FDs by start
/// cluster — because the read path walks the FAT chain the drain would
/// be zeroing underneath it.
unsafe fn fs_op_unlink(s: &mut Fat32State, arg: *const u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len == 0 {
        return E_INVAL;
    }
    if s.init_phase != Fat32InitPhase::Done {
        return E_AGAIN;
    }
    if s.root_cluster < 2 {
        return E_AGAIN;
    }
    s.io_rc = 0;
    let path = core::slice::from_raw_parts(arg, arg_len);
    let (parent, want) = match fs_split_parent(s, path) {
        Some(p) => p,
        None => return fs_io_errno(s, -2), // ENOENT only when truly absent
    };
    let loc = match fs_name_walk(s, parent, &want, 1) {
        DirScan::Found(l) => l,
        DirScan::Pending => return E_AGAIN,
        // Free slot / full dir both mean "no such file" — but a failed
        // device read during the scan must keep its own errno.
        _ => return fs_io_errno(s, -2), // ENOENT
    };
    if loc.is_dir {
        return -21;
    } // EISDIR — directory removal is not in the UNLINK surface
    let mut k = 0usize;
    while k < MAX_OPEN_FILES {
        let of = &s.open_files[k];
        if of.in_use != OF_FREE
            && ((of.writable != 0 && of.dir_lba == loc.lba && of.dir_off == loc.off)
                || (loc.start_cluster >= 2 && of.start_cluster == loc.start_cluster))
        {
            // A closed handle still writing back is not a user of the file:
            // it is finishing, and the caller only has to ask again.
            return if of.in_use == OF_DETACHED {
                E_AGAIN
            } else {
                -16
            }; // EBUSY
        }
        k += 1;
    }
    // Reserve reclamation capacity before touching the name. Once the entry
    // is `0xE5` the chain is unreachable, so discovering here that there is
    // nowhere to queue it would mean leaking it.
    if loc.start_cluster >= 2 && !fs_free_queue_has_room(s) {
        return E_AGAIN;
    }
    // Namespace removal first: durably mark the entry deleted, together
    // with the long-name companions that name it. After these sectors land,
    // OPEN/OPEN_CREATE no longer resolve the name; a crash before the chain
    // drain merely leaks clusters, which the scavenger reclaims.
    //
    // The companions are not optional tidying. They are what a real reader
    // resolves the name through: leaving them behind leaves a file visible
    // under its long name with its short entry gone, which `fsck` reports as
    // a checksum mismatch and a repair tool may act on.
    let rc = fs_dirent_retire(s, &loc);
    if rc != 0 {
        return fs_rc_errno(rc);
    }
    if loc.start_cluster >= 2 {
        fs_queue_free_chain(s, loc.start_cluster);
    }
    0
}

/// Whether the directory starting at `cluster` holds nothing but `.` and
/// `..`, or `None` when the walk hit its sector budget (caller yields) and
/// `Some(false)` the moment a live entry is found.
///
/// Bounded like every other directory walk here: `DIR_SCAN_BUDGET_SECTORS`
/// sectors, then `None`. An empty directory is one or two sectors, so the
/// budget is only reached by a directory that WAS large and has been emptied
/// — which is exactly the case where an unbounded scan would stall the lane.
unsafe fn fs_dir_is_empty(s: &mut Fat32State, cluster: u32) -> Option<bool> {
    let mut lba = cluster_to_sector(s, cluster);
    let mut budget = DIR_SCAN_BUDGET_SECTORS;
    loop {
        if budget == 0 || (budget < DIR_SCAN_BUDGET_SECTORS && fs_out_of_time(s)) {
            return None;
        }
        if fs_read_blockbuf(s, lba) != 0 {
            fs_note_io(s, -5);
            return Some(false);
        }
        budget -= 1;
        let mut off = 0usize;
        while off + DIR_ENTRY_SIZE <= BLOCK_SIZE {
            let first = s.block_buf[off];
            // 0x00 is end-of-directory: nothing live can follow it.
            if first == 0x00 {
                return Some(true);
            }
            if first != 0xE5 {
                let attr = s.block_buf[off + 11];
                // `.` and `..` are the directory's own links, not contents.
                let dot = s.block_buf[off] == b'.'
                    && (s.block_buf[off + 1] == b'.' || s.block_buf[off + 1] == b' ');
                if attr != ATTR_LONG_NAME && (attr & ATTR_VOLUME_ID) == 0 && !dot {
                    return Some(false);
                }
                // A long-name companion belongs to an entry further on. It
                // is not itself content, and treating it as content would
                // make every Linux-created directory permanently non-empty.
            }
            off += DIR_ENTRY_SIZE;
        }
        lba = fs_dir_next_lba(s, cluster, lba)?;
    }
}

/// FS_RMDIR: remove an empty directory.
///
/// Split from `UNLINK` rather than folded into it because the two differ in
/// the check that matters: a file's removal is unconditional, a directory's
/// is refused while it still holds anything. A single opcode that decided by
/// looking at the target would make "remove this name" mean two things, and
/// a caller that guessed wrong would delete a tree it meant to keep.
unsafe fn fs_op_rmdir(s: &mut Fat32State, arg: *const u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len == 0 {
        return E_INVAL;
    }
    if s.init_phase != Fat32InitPhase::Done {
        return E_AGAIN;
    }
    if s.root_cluster < 2 {
        return E_AGAIN;
    }
    s.io_rc = 0;
    let path = core::slice::from_raw_parts(arg, arg_len);
    let (parent, want) = match fs_split_parent(s, path) {
        Some(p) => p,
        None => return fs_io_errno(s, -2), // ENOENT
    };
    let loc = match fs_name_walk(s, parent, &want, 1) {
        DirScan::Found(l) => l,
        DirScan::Pending => return E_AGAIN,
        _ => return fs_io_errno(s, -2), // ENOENT
    };
    if !loc.is_dir {
        return -20; // ENOTDIR
    }
    if loc.start_cluster == s.root_cluster {
        // The root has no parent entry to retire, and a volume without a
        // root is not a volume.
        return -16; // EBUSY
    }
    let mut k = 0usize;
    while k < MAX_OPEN_FILES {
        let of = &s.open_files[k];
        if of.in_use != OF_FREE && loc.start_cluster >= 2 && of.start_cluster == loc.start_cluster {
            // EBUSY — an enumeration is walking it (or, closed, is finishing).
            return if of.in_use == OF_DETACHED {
                E_AGAIN
            } else {
                -16
            };
        }
        k += 1;
    }
    if loc.start_cluster >= 2 {
        match fs_dir_is_empty(s, loc.start_cluster) {
            Some(true) => {}
            Some(false) => {
                // Distinguish a genuine non-empty directory from a device
                // read that failed mid-scan; collapsing them would tell an
                // operator to go and delete files that are not there.
                if s.io_rc != 0 {
                    return fs_io_errno(s, -5);
                }
                return -39; // ENOTEMPTY
            }
            None => return E_AGAIN,
        }
        if !fs_free_queue_has_room(s) {
            return E_AGAIN;
        }
    }
    // Same order as UNLINK: retire the name first, so a crash leaks the
    // directory's cluster rather than leaving a name pointing at storage
    // that has been handed back.
    let rc = fs_dirent_retire(s, &loc);
    if rc != 0 {
        return fs_rc_errno(rc);
    }
    if loc.start_cluster >= 2 {
        fs_queue_free_chain(s, loc.start_cluster);
    }
    0
}

/// Mark a directory entry deleted, along with any long-name companions
/// attached to `loc`.
///
/// The short entry is retired FIRST. A companion set is only meaningful
/// while the entry it names is live, so clearing the short entry is the step
/// that makes the name stop resolving; a crash between the two leaves
/// stranded companions, which the next claim of that slot retires and which
/// no reader resolves a name through. The reverse order would leave a live
/// short entry with a half-cleared name in front of it, which a reader
/// resolves as a corrupt name rather than an absent one.
unsafe fn fs_dirent_retire(s: &mut Fat32State, loc: &DirentLoc) -> i32 {
    fs_dir_changed(s, loc.parent);
    let rc = fs_read_blockbuf(s, loc.lba);
    if rc != 0 {
        return rc;
    }
    s.block_buf[loc.off as usize] = 0xE5;
    let rc = fs_write_staged(s, loc.lba);
    if rc != 0 {
        return rc;
    }
    fs_lfn_retire(s, loc)
}

/// Mark `loc`'s long-name companion run deleted.
///
/// The run is contiguous and immediately precedes the short entry, but it
/// can straddle a sector boundary, so it is walked slot by slot from its
/// first entry rather than assumed to live in one sector.
unsafe fn fs_lfn_retire(s: &mut Fat32State, loc: &DirentLoc) -> i32 {
    if loc.lfn_run == 0 || loc.lfn_lba == 0 {
        return 0;
    }
    fs_dir_changed(s, loc.parent);
    let spc = u32::from(s.sectors_per_cluster);
    if spc == 0 {
        return 0;
    }
    let mut lba = loc.lfn_lba;
    let mut off = loc.lfn_off as usize;
    let mut left = loc.lfn_run;
    while left > 0 {
        let rc = fs_read_blockbuf(s, lba);
        if rc != 0 {
            return rc;
        }
        let mut dirty = false;
        while left > 0 && off < BLOCK_SIZE {
            // Only retire what is still a live companion: anything else in
            // this span belongs to another name.
            if s.block_buf[off + 11] == ATTR_LONG_NAME && s.block_buf[off] != 0xE5 {
                s.block_buf[off] = 0xE5;
                dirty = true;
            }
            off += DIR_ENTRY_SIZE;
            left -= 1;
        }
        if dirty {
            let rc = fs_write_staged(s, lba);
            if rc != 0 {
                return rc;
            }
        }
        if left == 0 {
            break;
        }
        // The run continues in the next directory sector, which is not
        // simply `lba + 1` when the set straddles a cluster boundary — the
        // next cluster can be anywhere. Follow the chain.
        match fs_dir_next_lba(s, loc.parent, lba) {
            Some(next) => lba = next,
            None => break,
        }
        off = 0;
    }
    let _ = spc;
    0
}

/// The directory sector following `lba` within the chain rooted at
/// `parent`, or `None` at the end of the chain.
///
/// Sectors inside one cluster are contiguous; the step from a cluster's last
/// sector to the next cluster's first is a FAT lookup. Walking the chain
/// from the head each time is O(chain) but a directory's chain is short and
/// the FAT sector is cached, so this stays cheap and stays correct — the
/// alternative, assuming `lba + 1`, writes into whatever file happens to own
/// the next cluster.
unsafe fn fs_dir_next_lba(s: &mut Fat32State, parent: u32, lba: u32) -> Option<u32> {
    let spc = u32::from(s.sectors_per_cluster);
    if spc == 0 || parent < 2 {
        return None;
    }
    let mut cur = parent;
    loop {
        let first = cluster_to_sector(s, cur);
        if lba >= first && lba < first + spc {
            if lba + 1 < first + spc {
                return Some(lba + 1);
            }
            let next = fs_read_fat_entry(s, cur);
            if !(2..FAT32_EOC).contains(&next) {
                return None;
            }
            return Some(cluster_to_sector(s, next));
        }
        let next = fs_read_fat_entry(s, cur);
        if !(2..FAT32_EOC).contains(&next) {
            return None;
        }
        cur = next;
    }
}

/// Queue a chain head for lazy reclamation by `fs_step_free_chains`.
///
/// Namespace removal always wins over reclaim: the entry is already gone by
/// the time this is called, so a full ring cannot be allowed to block or to
/// undo it.
///
/// The chain is freed only once the epoch that retired its name has reached
/// the device (`unlink_epoch`), and the boundary closed here keeps the
/// frees out of that epoch. Entry first, chain second: an interruption can
/// leak the clusters, never leave a live entry over freed — and perhaps
/// already reused — ones.
fn fs_queue_free_chain(s: &mut Fat32State, head: u32) {
    let mut q = 0usize;
    while q < UNLINK_FREE_SLOTS {
        if s.unlink_free[q] == 0 {
            s.unlink_free[q] = head;
            s.unlink_epoch[q] = s.epoch;
            fs_free_count_add(s, 0);
            // A full epoch window aborts the transaction (`fs_barrier`
            // records the miss), which un-queues this again.
            let _ = unsafe { fs_barrier(s, false) };
            return;
        }
        q += 1;
    }
    // The ring is full, so this chain is unreachable and its clusters are
    // stranded. That is a leak, and the only wrong response to a leak is a
    // silent one: the free-cluster summary is marked unknown so nothing
    // trusts a number that no longer describes the volume, and the dirty bit
    // the mutation already set tells the next host to check.
    fs_free_count_unknown(s);
    unsafe { dev_log(s.sys(), 4, b"[fat32] unlink orphan".as_ptr(), 21) };
}

/// One tick of every deferred, bounded piece of volume maintenance, in
/// priority order. Returns true while work remains, so a caller that needs a
/// settled volume knows when it has one.
///
/// Everything here is deferred out of the operation that caused it for the
/// same reason: the cooperative scheduler gives a `provider_call` a step
/// budget, and walking a cluster chain inside one call blows it. Deferring
/// is not laziness — it is what keeps a large unlink from stalling every
/// other module sharing the lane. Every piece runs as a transaction over the
/// cache: one that needs a sector still on its way stops for this tick and
/// resumes on a later one.
unsafe fn fs_background_step(s: &mut Fat32State) -> bool {
    s.call_gen = s.call_gen.wrapping_add(1);
    fs_pump(s);
    let mut busy = fs_ops_step(s);
    busy |= fs_step_detached(s);
    fs_step_free_chains(s);
    fs_pump(s);
    fs_step_read_ahead(s);
    if fs_has_pending_frees(s) || busy {
        return true;
    }
    // Nothing outstanding. Publish the free-cluster summary and, if no
    // writable handle is open, record the volume as cleanly shut down —
    // only on the edge into quiescence, so a busy volume never pays for
    // them, and only once every write before them has completed.
    if s.fs_settle_pending != 0 {
        if !fs_wb_idle(s) {
            s.wb_kick = 1;
            return true;
        }
        if fs_has_writable_handle(s) {
            // Still in use: record where the allocator got to, but do not
            // stand behind a count that the next write invalidates.
            if fs_tx(s, |s| fs_write_fsinfo(s, false)) != E_AGAIN {
                s.fs_settle_pending = 0;
            }
        } else if s.fs_settle_pending != SETTLE_MARK {
            // Quiescent. Publish the count first, then the clean mark on a
            // later tick: a reader that trusts the mark must find a count
            // that matches. A mutation in between retracts the count and
            // re-arms the settle (`fs_begin_mutation`).
            if fs_tx(s, |s| fs_write_fsinfo(s, true)) != E_AGAIN {
                s.fs_settle_pending = SETTLE_MARK;
            }
            fs_pump(s);
            return true;
        } else {
            // The clean mark is only honest once everything before it is
            // durable: a durable boundary ahead of it, and its own after.
            let rc = fs_tx(s, |s| {
                if fs_barrier(s, true) == 0 {
                    return E_AGAIN;
                }
                fs_mark_volume_clean(s, true)
            });
            if rc != E_AGAIN {
                s.fs_settle_pending = 0;
            }
        }
        fs_pump(s);
        return s.fs_settle_pending != 0 || !fs_wb_idle(s);
    }
    !fs_wb_idle(s)
}

/// True when the reclamation ring can accept another chain.
///
/// Checked BEFORE a name is removed, not after. An operation that retires a
/// name it cannot also queue the chain for has stranded those clusters
/// permanently — nothing on the volume distinguishes them from live data
/// afterwards. Declining with `EAGAIN` while the ring drains costs the
/// caller a retry and costs the volume nothing.
fn fs_free_queue_has_room(s: &Fat32State) -> bool {
    let mut q = 0usize;
    while q < UNLINK_FREE_SLOTS {
        if s.unlink_free[q] == 0 {
            return true;
        }
        q += 1;
    }
    false
}

/// True while any unlinked chain is still queued for reclamation.
fn fs_has_pending_frees(s: &Fat32State) -> bool {
    let mut q = 0usize;
    while q < UNLINK_FREE_SLOTS {
        if s.unlink_free[q] >= 2 {
            return true;
        }
        q += 1;
    }
    false
}

/// True while any handle that can mutate the volume is open.
fn fs_has_writable_handle(s: &Fat32State) -> bool {
    let mut k = 0usize;
    while k < MAX_OPEN_FILES {
        if s.open_files[k].in_use != 0 && s.open_files[k].writable != 0 {
            return true;
        }
        k += 1;
    }
    false
}

// ============================================================================
// Free-cluster accounting and the volume-dirty bit
// ============================================================================

/// FSINFO's "free cluster count" field (offset 0x1E8) and its next-free hint
/// (0x1EC). `0xFFFF_FFFF` means "unknown" in both, which the format defines
/// and every reader honours.
const FSINFO_FREE_COUNT: usize = 0x1E8;
const FSINFO_NEXT_FREE: usize = 0x1EC;
const FSINFO_UNKNOWN: u32 = 0xFFFF_FFFF;

/// Adjust the tracked free-cluster count by `delta`.
///
/// Maintained incrementally from a value read at mount rather than
/// recomputed, because recomputing means scanning the whole FAT and this
/// provider exists on machines where that is a visible stall. Incremental
/// accounting is exact as long as the starting value was, so any doubt about
/// the starting value — or about a mutation whose outcome is unknown —
/// collapses the whole thing to "unknown" rather than propagating a number
/// nobody should trust. A stale count is worse than no count: `fsck` reports
/// it as an error, and a consumer sizing a write against it gets a wrong
/// answer with no indication.
fn fs_free_count_add(s: &mut Fat32State, delta: i32) {
    s.fs_settle_pending = 1;
    if delta > 0 {
        // Clusters came back, so a "full" verdict from the bounded scan is no
        // longer true. This is the only event that can make it untrue, which
        // is what lets the verdict be sticky in the first place.
        fs_free_scan_reset(s);
    }
    if s.free_count_known == 0 {
        return;
    }
    let cur = i64::from(s.free_count);
    let next = cur + i64::from(delta);
    if next < 0 || next > i64::from(s.count_of_clusters) {
        // The count and the FAT disagree, so the count is the thing that is
        // wrong. Say so rather than clamping into a plausible-looking lie.
        s.free_count_known = 0;
        return;
    }
    s.free_count = next as u32;
}

/// Record that the free-cluster count can no longer be trusted.
fn fs_free_count_unknown(s: &mut Fat32State) {
    s.free_count_known = 0;
    s.fs_settle_pending = 1;
}

/// Write the FSINFO sector's free-count and next-free fields.
///
/// `publish_count` gates whether the tracked number is written or the
/// format's `0xFFFF_FFFF` "unknown". It is true in exactly one place: the
/// settle that also marks the volume cleanly shut down.
///
/// The reason is that an on-media count is a claim about a volume that is
/// not being written. The moment a mutation starts, the recorded number
/// describes the past, and a crash freezes that stale number in place —
/// which every FAT32 checker reports as an error, correctly, because
/// nothing distinguishes it from a count that was wrong all along. Writing
/// "unknown" at the start of activity and the real number only on the way
/// back to quiescence means the volume never carries a count it cannot
/// stand behind.
///
/// Best-effort: a volume without a valid FSINFO sector has nowhere to
/// record either, which the format permits.
unsafe fn fs_write_fsinfo(s: &mut Fat32State, publish_count: bool) -> i32 {
    if s.fsinfo_sector == 0 || s.fsinfo_sector == 0xFFFF {
        return 0;
    }
    let lba = u32::from(s.fsinfo_sector);
    if fs_read_blockbuf(s, lba) != 0 {
        return 0;
    }
    let count = if publish_count && s.free_count_known != 0 {
        s.free_count
    } else {
        FSINFO_UNKNOWN
    };
    write_u32_le(&mut s.block_buf, FSINFO_FREE_COUNT, count);
    write_u32_le(&mut s.block_buf, FSINFO_NEXT_FREE, s.next_free_hint);
    fs_write_staged(s, lba)
}

/// Read the free-cluster count and next-free hint FSINFO records, at mount.
/// False while the sector is still on its way.
unsafe fn fs_read_fsinfo(s: &mut Fat32State) -> bool {
    s.free_count_known = 0;
    if s.fsinfo_sector == 0 || s.fsinfo_sector == 0xFFFF {
        return true;
    }
    let lba = u32::from(s.fsinfo_sector);
    let rc = fs_read_blockbuf(s, lba);
    if rc == E_AGAIN {
        return false;
    }
    if rc != 0 {
        return true;
    }
    // Both signatures must be present, or this is not an FSINFO sector and
    // the numbers at those offsets are someone else's data.
    if read_u32_le(&s.block_buf, 0) != 0x4161_5252 || read_u32_le(&s.block_buf, 484) != 0x6141_7272
    {
        return true;
    }
    let hint = read_u32_le(&s.block_buf, FSINFO_NEXT_FREE);
    if (2..s.count_of_clusters).contains(&hint) {
        s.next_free_hint = hint;
    }
    let count = read_u32_le(&s.block_buf, FSINFO_FREE_COUNT);
    if count != FSINFO_UNKNOWN && count <= s.count_of_clusters {
        s.free_count = count;
        s.free_count_known = 1;
    }
    true
}

/// Set or clear FAT[1]'s ClnShutBit (bit 27), the flag every FAT32 reader
/// checks to decide whether the volume was shut down cleanly.
///
/// Marking the volume dirty on the first mutation of a mount is what makes a
/// crash *visible*. Without it, an interrupted write leaves a volume that
/// claims to be clean, so no host that later mounts it runs a check, and
/// whatever the interruption stranded stays stranded and unaccounted for.
/// The bit costs one sector write per transition — once on the way into
/// activity, once on the way back to quiescence — not one per operation.
///
/// Bit 26 (HrdErrBit) is never touched: this provider does not claim to have
/// found bad sectors.
unsafe fn fs_mark_volume_clean(s: &mut Fat32State, clean: bool) -> i32 {
    if s.volume_clean == u8::from(clean) {
        return 0;
    }
    if s.fat_start_sector == 0 {
        return 0;
    }
    let lba = s.fat_start_sector;
    let rc = fs_fat_stage(s, lba);
    if rc != 0 {
        return if rc == E_AGAIN { E_AGAIN } else { -5 }; // EIO
    }
    let entry1 = read_u32_le(&s.fat_buf, 4);
    let next = if clean {
        entry1 | CLN_SHUT_BIT
    } else {
        entry1 & !CLN_SHUT_BIT
    };
    if next != entry1 {
        write_u32_le(&mut s.fat_buf, 4, next);
        s.fat_dirty = 1;
        let rc = fs_fat_flush(s);
        if rc != 0 {
            return rc;
        }
        // The dirty mark is only useful if it reaches media BEFORE the
        // mutation it warns about: a durable boundary puts it there before
        // anything written after it. (The clean mark's caller puts one ahead
        // of it too: it is only honest once everything before it has.)
        let fl = fs_durable_point(s);
        if fl != 0 {
            return fl;
        }
    }
    s.volume_clean = u8::from(clean);
    0
}

/// Read FAT[1]'s ClnShutBit into `volume_clean`, so the first mutation
/// knows whether the mark actually needs writing.
///
/// A volume that comes up already dirty was not shut down cleanly. That is
/// worth saying out loud once: whatever the interruption stranded is still
/// stranded, and the free-cluster summary describes a volume that no longer
/// exists — so it is not trusted until something recomputes it.
/// False while the FAT sector is still on its way.
unsafe fn fs_read_clean_bit(s: &mut Fat32State) -> bool {
    if s.fat_start_sector == 0 {
        return true;
    }
    let lba = s.fat_start_sector;
    let rc = fs_fat_stage(s, lba);
    if rc == E_AGAIN {
        return false;
    }
    if rc != 0 {
        return true;
    }
    let entry1 = read_u32_le(&s.fat_buf, 4);
    let clean = (entry1 & CLN_SHUT_BIT) != 0;
    s.volume_clean = u8::from(clean);
    if !clean {
        s.free_count_known = 0;
        dev_log(s.sys(), 4, b"[fat32] volume not clean".as_ptr(), 24);
    }
    true
}

/// True for every opcode that can change what is on media.
///
/// `FSYNC` and `FSYNC_NAME` are mutations: both write a directory sector.
/// `OPEN`, `READ`, `SEEK`, `STAT`, `OPENDIR`, `READDIR`, `CLOSE` and `CAPS`
/// are not.
const fn fs_op_mutates(opcode: u32) -> bool {
    matches!(
        opcode,
        FS_OPEN_CREATE
            | FS_UNLINK
            | FS_PREALLOCATE
            | FS_WRITE
            | FS_WRITE_ASYNC
            | FS_FSYNC
            | FS_FSYNC_SUBMIT
            | FS_FSYNC_NAME
            | FS_RENAME
            | FS_MKDIR
            | FS_RMDIR
            | FS_TRUNCATE
            // An owner release closes that owner's handles, and closing a
            // writable handle writes its directory entry back.
            | OWNER_RELEASED
    )
}

/// Mark the volume dirty ahead of a mutation, once per mount. Runs inside
/// the mutation's own transaction, so the mark and the mutation are taken
/// together or not at all; the durable boundary after the mark puts it on
/// the device before anything the mutation writes.
unsafe fn fs_begin_mutation(s: &mut Fat32State) -> i32 {
    if s.volume_clean != 0 {
        // Transitioning out of quiescence. Retract the free-cluster summary
        // before anything invalidates it, so an interruption leaves
        // "unknown" rather than a number that no longer describes the FAT.
        let rc = fs_write_fsinfo(s, false);
        if rc != 0 {
            return rc;
        }
        let rc = fs_mark_volume_clean(s, false);
        if rc != 0 {
            return rc;
        }
    } else if s.fs_settle_pending == SETTLE_MARK {
        // The settle published the count and has not yet written the clean
        // mark: retract the count the same way.
        let rc = fs_write_fsinfo(s, false);
        if rc != 0 {
            return rc;
        }
    }
    s.fs_settle_pending = 1;
    0
}

/// Drain one queued unlinked chain by at most ONE FAT-sector batch: load
/// the FAT sector holding the cursor, zero every chain entry that lives in
/// that same sector (a sequential chain is up to 128 entries/sector), and
/// write the sector back through every FAT copy. Cost per step is bounded
/// at ~1 read + `num_fats` writes regardless of chain length; a chain
/// spanning S FAT sectors completes after S steps. Rewinds
/// `next_free_hint` so the allocator's forward scan can actually reuse the
/// reclaimed span within this mount.
unsafe fn fs_step_free_chains(s: &mut Fat32State) {
    // Only a chain whose name is already off the device's books: the epoch
    // that retired it has been written.
    let mut slot = 0usize;
    while slot < UNLINK_FREE_SLOTS
        && (s.unlink_free[slot] < 2 || s.wb_epoch.wrapping_sub(s.unlink_epoch[slot]) as i32 <= 0)
    {
        slot += 1;
    }
    if slot >= UNLINK_FREE_SLOTS {
        return;
    }
    let _ = fs_tx(s, |s| {
        let b = fs_begin_mutation(s);
        if b != 0 {
            return b;
        }
        fs_free_chain_batch(s, slot)
    });
}

/// One FAT sector's worth of chain `slot`, freed in the cache.
unsafe fn fs_free_chain_batch(s: &mut Fat32State, slot: usize) -> i32 {
    let bps = s.bytes_per_sector as u32;
    if bps == 0 {
        return 0;
    }
    let eps = bps / 4; // FAT entries per sector
    if eps == 0 {
        return 0;
    }
    let max_clst = cluster_count_ceiling(s);

    let mut c = s.unlink_free[slot];
    let fat_sec = fat_sector_for_cluster(s, c);
    let rc = fs_fat_stage(s, fat_sec);
    if rc != 0 {
        return rc;
    } // retry next step
    let first_in_sec = (fat_sec - s.fat_start_sector).wrapping_mul(eps);
    let mut freed_low: u32 = u32::MAX;
    let mut freed: i32 = 0;
    let mut guard: u32 = 0;
    // Zero every chain link that lives in the loaded sector. `guard`
    // bounds a corrupt/cyclic chain at one sector's entry count.
    while (2..FAT32_EOC).contains(&c) && c < max_clst && guard <= eps {
        if fat_sector_for_cluster(s, c) != fat_sec {
            break;
        }
        let off = ((c - first_in_sec) * 4) as usize;
        if off + 4 > BLOCK_SIZE {
            break;
        }
        let next = read_u32_le(&s.fat_buf, off) & FAT32_MASK;
        write_u32_le(&mut s.fat_buf, off, 0);
        s.fat_dirty = 1;
        if c < freed_low {
            freed_low = c;
        }
        freed += 1;
        c = next;
        guard += 1;
    }
    // Land the batch in the cache with the cursor's move: they commit
    // together, and the queue slot is the only record that this chain
    // still needs freeing.
    let rc = fs_fat_flush(s);
    if rc != 0 {
        return rc;
    }
    // Chain continues in another FAT sector → park the cursor there;
    // otherwise the chain is fully freed and the slot opens up.
    s.unlink_free[slot] = if (2..FAT32_EOC).contains(&c) && c < max_clst {
        c
    } else {
        0
    };
    if freed_low != u32::MAX && freed_low < s.next_free_hint {
        s.next_free_hint = freed_low;
    }
    if freed > 0 {
        fs_free_scan_reset(s);
    }
    fs_free_count_add(s, freed);
    0
}

/// Truncate the root directory to one empty cluster: write zeroed sectors over
/// the root cluster's data (every dir entry becomes 0x00 = end-of-directory)
/// and set its FAT entry to EOC, orphaning any further root-dir clusters. The
/// just-written cluster is warm, so the subsequent dir scan never cold-reads it
/// (a cold first-touch read can blow the cooperative step guard). Clean-slate
/// only — discards existing root-dir entries.
/// Write a volume serial as `XXXX-XXXX` — the form `blkid` and
/// `fatlabel -i` print, so a serial read off telemetry and one read off a
/// host tool compare directly. 9 bytes.
///
/// # Safety
/// `dst` must be valid for writes of 9 bytes. Bounds are not checked.
unsafe fn fmt_volume_id(dst: *mut u8, id: u32) -> usize {
    let mut i = 0usize;
    while i < 8 {
        let nib = ((id >> (28 - i * 4)) & 0x0F) as u8;
        let ch = if nib < 10 {
            b'0' + nib
        } else {
            b'A' + nib - 10
        };
        *dst.add(if i < 4 { i } else { i + 1 }) = ch;
        i += 1;
    }
    *dst.add(4) = b'-';
    9
}

unsafe fn fs_clean_root(s: &mut Fat32State) -> i32 {
    let spc = s.sectors_per_cluster as u32;
    if spc == 0 || s.root_cluster < 2 {
        return 0;
    }
    let base = cluster_to_sector(s, s.root_cluster);
    let rc = fs_zero_sectors(s, base, spc);
    if rc != 0 {
        return rc;
    }
    // One-cluster root: point its FAT entry at EOC, leaking any tail clusters.
    fs_write_fat_entry(s, s.root_cluster, FAT32_TAIL)
}

/// Queue the FAT entries for `[start, start + count)` clusters to be zeroed
/// in every FAT copy, marking that span free. The span is cleared one FAT
/// sector per transaction (`fs_clear_fat_step`), so its size bounds how many
/// calls it takes, never whether one can commit. Used to reclaim a usable
/// region of a volume whose FAT holds stale non-zero entries the free scan
/// would otherwise treat as allocated.
///
/// DESTRUCTIVE: blindly frees the whole span, so it MUST run only on a
/// fresh-format mount where the span holds nothing live. The mount path
/// gates the call on `clean_root` for exactly this reason — running it on a
/// remount severs any live chains that live in the operator's
/// `init_free_hint` region (FS_STAT still reports the full size, but the
/// chain past the first cluster — hence the data — is lost on read-back).
fn fs_clear_fat_region(s: &mut Fat32State, start: u32, count: u32) -> i32 {
    let max_clst = cluster_count_ceiling(s);
    // Never touch the reserved entries FAT[0]/FAT[1] (media byte / EOC marker).
    let start = start.max(2);
    let endc = start.saturating_add(count).min(max_clst);
    if start < endc {
        s.clear_next = start;
        s.clear_end = endc;
        // A blind zero of a FAT span cannot be reconciled with a running count.
        fs_free_count_unknown(s);
    }
    0
}

/// Clear the next FAT sector of the queued span. Runs inside a transaction
/// of its own: one FAT sector and its copies, and the boundary that moves
/// off it.
unsafe fn fs_clear_fat_step(s: &mut Fat32State) -> i32 {
    let bps = s.bytes_per_sector as u32;
    let eps = bps / 4; // FAT entries per sector
    if eps == 0 || s.clear_next >= s.clear_end {
        s.clear_next = s.clear_end;
        return 0;
    }
    let c = s.clear_next;
    let endc = s.clear_end;
    let fat_sec = fat_sector_for_cluster(s, c);
    let rc = fs_fat_stage(s, fat_sec);
    if rc != 0 {
        return rc;
    }
    let first_in_sec = (fat_sec - s.fat_start_sector).wrapping_mul(eps);
    let sec_end = first_in_sec.saturating_add(eps);
    let lo = c.max(first_in_sec);
    let hi = endc.min(sec_end);
    let mut cc = lo;
    while cc < hi {
        let off = ((cc - first_in_sec) * 4) as usize;
        if off + 4 <= BLOCK_SIZE {
            write_u32_le(&mut s.fat_buf, off, 0);
            s.fat_dirty = 1;
        }
        cc += 1;
    }
    let rc = fs_fat_flush(s);
    if rc != 0 {
        return rc;
    }
    s.clear_next = sec_end.min(endc);
    if s.clear_next >= endc {
        fs_free_scan_reset(s);
    }
    0
}

/// Location of a directory entry — an existing match, or a claimable slot.
#[derive(Clone, Copy)]
struct DirentLoc {
    lba: u32,
    off: u16,
    exists: bool,
    /// Set only when `exists` and the matched entry has `ATTR_DIRECTORY`.
    is_dir: bool,
    start_cluster: u32,
    size: u32,
    /// Raw attribute byte of a matched entry; 0 for a free slot.
    attr: u8,
    /// Last-write time as Unix seconds, or 0 when the entry carries no
    /// stamp (a volume written on a node with no real-time clock).
    mtime: u32,
    /// Chain head of the directory this location lives in. Needed to walk
    /// forward from a companion run that straddles a cluster boundary.
    parent: u32,
    /// The run of long-name companion entries attached to this location:
    /// the ones naming a matched entry, or the ones stranded immediately in
    /// front of a claimable slot. `lfn_run == 0` means there are none.
    ///
    /// A companion set can straddle a sector boundary, so the run is
    /// addressed by its first slot and walked forward from there.
    lfn_lba: u32,
    lfn_off: u16,
    lfn_run: u8,
}

/// One pass over a directory, bounded by [`DIR_SCAN_BUDGET_SECTORS`].
///
/// This is the module's only directory walker. Anything that needs to find
/// a name, claim a slot for one, or learn that a directory is full goes
/// through here — so every rule about what a directory entry means, long-name
/// companions included, has exactly one implementation to keep correct.
enum DirScan {
    /// `want` is present.
    Found(DirentLoc),
    /// `want` is absent; here is a slot to mint it in.
    Free(DirentLoc),
    /// `want` is absent and the directory has no room. The caller decides
    /// whether to grow the chain (`fs_dir_grow`) or fail.
    Full,
    /// The budget ran out. State is saved; call again with the same
    /// arguments to continue from where this stopped.
    Pending,
    /// A device read failed; `s.io_rc` carries the rc.
    Io,
}

/// Directory sectors one `provider_call` will walk before yielding.
///
/// A walk only ever reads cached sectors — one that is not cached is
/// fetched and the walk parks on it — so what this bounds is the CPU one
/// call spends and the cache slots it pins (a slot a call touched is not
/// evicted during that call). A directory with thousands of entries is not
/// exotic — a WAL that segments per snapshot fills one — so an unbounded
/// walk is a latent stall of every other module sharing the lane. When the
/// budget runs out the walk returns `Pending` and the opcode returns
/// `EAGAIN`, which the fs contract already defines as "ask again".
///
/// Split by target with `CACHE_SLOTS`: a walk may pin a quarter of the
/// cache at most, leaving the rest to the commit that follows it.
#[cfg(target_arch = "aarch64")]
const DIR_SCAN_BUDGET_SECTORS: u32 = 32;
#[cfg(not(target_arch = "aarch64"))]
const DIR_SCAN_BUDGET_SECTORS: u32 = 6;

/// `fs_settle_pending` once the settle has published the free count and the
/// clean mark is what remains (1 = a settle is due).
const SETTLE_MARK: u8 = 2;

/// Time one `provider_call` or step may spend walking before it yields, in
/// microseconds, alongside the sector budgets. A sector count alone assumes
/// a device speed, and a single-sector read costs anywhere from a few
/// microseconds to milliseconds depending on the device and its power state,
/// so 32 of them can pass a step's deadline several times over. A walk
/// always reads at least one sector per call, so a slow device still makes
/// progress; the budget is well under a step because the read that crosses
/// it still completes.
const CALL_BUDGET_US: u64 = 400;

/// Whether the current call has spent its time budget ([`CALL_BUDGET_US`]),
/// measured from `call_t0`; never before the first call has set it.
unsafe fn fs_out_of_time(s: &Fat32State) -> bool {
    if s.call_t0 == 0 || s.syscalls.is_null() {
        return false;
    }
    dev_micros(&*s.syscalls).wrapping_sub(s.call_t0) > CALL_BUDGET_US
}

/// Parked walks the working cursor spills into when it yields `Pending`.
///
/// One working cursor, and this many parked ones. With a single cursor, two
/// callers looking up different names in one directory larger than the
/// budget restart each other on every call and neither ever finishes; a
/// volume root that holds a store's runs and a log's segments is such a
/// directory. A parked walk resumes where it stopped when the same arguments
/// come back, whatever ran in between — unless the directory's names or
/// free slots changed meanwhile ([`fs_dir_changed`]).
const DIR_CURSOR_POOL: usize = 4;

/// Directory components resolved recently, so the paths of one operation --
/// a rename's source and destination share a parent -- do not each walk the
/// directories above it. Two lookups of one name in one call do not share a
/// walk: the first resumes the parked walk and finishes it, and the second
/// finds none and starts over. Under a directory too long to walk in one
/// call, every call would then resolve the first path and run out on the
/// second, and the operation would answer "not yet" for ever. A cached
/// component is dropped when its parent directory's names change
/// ([`fs_dir_changed`]), when a rename intent is replayed, and when the
/// volume is formatted.
const DIR_CACHE: usize = 2;

#[derive(Clone, Copy)]
struct DirCacheEntry {
    /// The directory the component was found in; 0 = empty.
    parent: u32,
    short: [u8; 11],
    long: [u8; LFN_MAX_CHARS],
    long_len: u8,
    start_cluster: u32,
    attr: u8,
}

impl DirCacheEntry {
    const EMPTY: Self = Self {
        parent: 0,
        short: [0; 11],
        long: [0; LFN_MAX_CHARS],
        long_len: 0,
        start_cluster: 0,
        attr: 0,
    };
}

/// Resolve one directory component of a path in `parent`: from the cache
/// when it holds it, else by a walk, cached when it names a directory. Only
/// directories are cached -- a file's size and time change without its
/// parent's names changing -- and a component is looked up through here only
/// where it must be a directory: one a path continues past, or the directory
/// `OPENDIR` names. A miss costs a walk, never a wrong answer: the cache
/// matches a name only in the spelling it was asked in.
unsafe fn fs_dir_component(s: &mut Fat32State, parent: u32, want: &PathName) -> Option<(u32, u8)> {
    if let Some(hit) = fs_dir_cache_get(s, parent, want) {
        return Some(hit);
    }
    let found = fs_dir_lookup(s, parent, want)?;
    if (found.attr & ATTR_DIRECTORY) != 0 {
        fs_dir_cache_put(s, parent, want, found.start_cluster, found.attr);
    }
    Some((found.start_cluster, found.attr))
}

fn fs_dir_cache_get(s: &Fat32State, parent: u32, want: &PathName) -> Option<(u32, u8)> {
    let mut c = 0usize;
    while c < DIR_CACHE {
        let e = &s.dir_cache[c];
        if e.parent != 0
            && e.parent == parent
            && e.short == want.short
            && e.long_len == want.long_len
            && e.long[..e.long_len as usize] == want.long[..want.long_len as usize]
        {
            return Some((e.start_cluster, e.attr));
        }
        c += 1;
    }
    None
}

fn fs_dir_cache_put(s: &mut Fat32State, parent: u32, want: &PathName, cluster: u32, attr: u8) {
    let slot = s.dir_cache_next as usize % DIR_CACHE;
    s.dir_cache_next = s.dir_cache_next.wrapping_add(1);
    s.dir_cache[slot] = DirCacheEntry {
        parent,
        short: want.short,
        long: want.long,
        long_len: want.long_len,
        start_cluster: cluster,
        attr,
    };
}

/// Drop every walk, working or parked, over `dir_cluster`, and every cached
/// component found in it.
///
/// A walk carries what it learned from the sectors behind it: where the
/// free run it would claim starts, where the long-name companions in front
/// of the current entry begin, and that the name was not among them. A
/// change to that directory's names or free slots — an entry minted,
/// retired or renamed, its companions written or retired — can make any of
/// that false, and a walk resumed across it could answer "absent" for a
/// name created behind it or hand a create a slot that is no longer free.
/// So those writes drop the directory's walks, and the next call starts
/// over. A size or first-cluster update to an existing entry changes
/// neither, and does not. A cached component goes with them: the entry it
/// was read from may be the one retired or renamed, and its cluster may be
/// handed to another directory.
fn fs_dir_changed(s: &mut Fat32State, dir_cluster: u32) {
    let mut c = 0usize;
    while c < DIR_CACHE {
        if s.dir_cache[c].parent == dir_cluster {
            s.dir_cache[c].parent = 0;
        }
        c += 1;
    }
    if s.dir_cursor.dir_cluster == dir_cluster {
        s.dir_cursor.dir_cluster = 0;
    }
    let mut i = 0usize;
    while i < DIR_CURSOR_POOL {
        if s.dir_cursor_pool[i].dir_cluster == dir_cluster {
            s.dir_cursor_pool[i].dir_cluster = 0;
        }
        i += 1;
    }
}

/// Resumable position of a bounded directory walk.
///
/// One working cursor for the whole provider, plus the parked ones above.
/// A walk that is neither the working cursor nor parked starts over, which
/// costs a rescan and never a wrong answer.
#[derive(Clone, Copy)]
#[repr(C)]
struct DirCursor {
    /// Chain head this cursor belongs to. 0 = idle.
    dir_cluster: u32,
    /// The 8.3 name being searched for.
    want: [u8; 11],
    /// Free slots the caller needs contiguously.
    need: u8,
    /// Cluster and sector-within-cluster reached.
    cluster: u32,
    sector: u32,
    /// Start of the free run seen so far, and its length.
    free_lba: u32,
    free_off: u16,
    free_run: u8,
    /// Start of the run of long-name companions immediately preceding the
    /// current position, and its length.
    lfn_lba: u32,
    lfn_off: u16,
    lfn_run: u8,
    /// The long name being searched for, upper-cased, when the caller's
    /// component is not expressible as 8.3. Length 0 means "match on the 8.3
    /// name", which is every lookup of a short name and is unchanged.
    want_long: [u8; LFN_MAX_CHARS],
    want_long_len: u8,
    /// Long name reconstructed from the companion run in front of the entry
    /// currently being considered, upper-cased for comparison.
    ///
    /// `lfn_acc_ok` is cleared the moment the run stops being well-formed —
    /// a gap in the ordinals, a name past `LFN_MAX_CHARS`, a character this
    /// provider does not decode. An ill-formed run must not match anything,
    /// because a partial decode of somebody else's name is a name.
    lfn_acc: [u8; LFN_MAX_CHARS],
    lfn_acc_len: u8,
    lfn_acc_ok: u8,
    /// Checksum the accumulated companions claim. Compared against the short
    /// entry behind them: a mismatch means they name a file that is gone.
    lfn_acc_sum: u8,
}

impl DirCursor {
    const fn empty() -> Self {
        Self {
            dir_cluster: 0,
            want: [b' '; 11],
            need: 1,
            cluster: 0,
            sector: 0,
            free_lba: 0,
            free_off: 0,
            free_run: 0,
            lfn_lba: 0,
            lfn_off: 0,
            lfn_run: 0,
            want_long: [0; LFN_MAX_CHARS],
            want_long_len: 0,
            lfn_acc: [0; LFN_MAX_CHARS],
            lfn_acc_len: 0,
            lfn_acc_ok: 0,
            lfn_acc_sum: 0,
        }
    }

    /// Does this cursor describe the walk the caller is asking for?
    /// Whether this cursor is the walk for these arguments. The long name is
    /// held upper-cased (FAT long names compare without case), so the
    /// caller's is folded the same way before comparing: compared as given,
    /// a name with a lowercase letter would never meet its own walk again,
    /// and in a directory longer than one call's budget it would restart on
    /// every call and never finish.
    fn matches(&self, dir_cluster: u32, want: &[u8; 11], need: u8, want_long: &[u8]) -> bool {
        if self.dir_cluster != dir_cluster
            || self.need != need
            || !name_eq(&self.want, want)
            || usize::from(self.want_long_len) != want_long.len()
        {
            return false;
        }
        let mut i = 0usize;
        while i < want_long.len() {
            if self.want_long[i] != to_upper(want_long[i]) {
                return false;
            }
            i += 1;
        }
        true
    }
}

/// Compare two 11-byte FAT 8.3 short names for equality.
#[inline]
fn name_eq(a: &[u8], b: &[u8; 11]) -> bool {
    let mut i = 0usize;
    while i < 11 {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Walk the directory at `dir_cluster` looking for `want`, remembering the
/// first run of `need` consecutive free slots along the way.
///
/// `need` is how many contiguous 32-byte slots the caller intends to claim:
/// one for a plain 8.3 entry. A run is counted over deleted (`0xE5`) and
/// never-used (`0x00`) slots alike.
///
/// Long-name companions are tracked, not skipped. A companion set is stored
/// immediately in front of the short entry it names, so:
///
///   - a `Found` result carries the span of companions belonging to the
///     match, which `UNLINK` and `RENAME` must retire with it — leaving them
///     behind makes a real reader show a name whose bytes are gone, and
///     makes `fsck` report a checksum mismatch;
///   - a `Free` result carries any companions stranded immediately in front
///     of the run, which the claim must retire before minting a new name
///     there — otherwise the new file inherits the old file's long name.
unsafe fn fs_dir_walk(s: &mut Fat32State, dir_cluster: u32, want: &[u8; 11], need: u8) -> DirScan {
    fs_dir_walk_long(s, dir_cluster, want, need, &[])
}

/// [`fs_dir_walk`], matching on a long name when one is given.
///
/// `want_long` is the caller's component, upper-cased, and empty for a name
/// that is expressible as 8.3. That distinction is the whole of the
/// difference: a short name is matched against the entry's own 8.3 field,
/// and a long name against the companion run reconstructed in front of it.
/// They cannot be unified, because a generated short name (`DATAFI~1.JSO`)
/// depends on what else is in the directory and is therefore not derivable
/// from the name the caller asked for.
unsafe fn fs_dir_walk_long(
    s: &mut Fat32State,
    dir_cluster: u32,
    want: &[u8; 11],
    need: u8,
    want_long: &[u8],
) -> DirScan {
    if dir_cluster < 2 || s.sectors_per_cluster == 0 {
        // Nothing to walk. Drop any cursor a previous walk parked, so it
        // cannot be resumed against a directory this call could not read.
        s.dir_cursor.dir_cluster = 0;
        return DirScan::Io;
    }
    if want_long.len() > LFN_MAX_CHARS {
        return DirScan::Io;
    }
    let spc = u32::from(s.sectors_per_cluster);
    let need = need.max(1);
    // A parked walk for these arguments resumes, and its slot is freed
    // either way: when the working cursor is still this walk (nothing ran
    // in between) the parked copy is stale, and a stale copy kept would fill
    // the pool with walks that already finished.
    let mut i = 0usize;
    while i < DIR_CURSOR_POOL {
        if s.dir_cursor_pool[i].dir_cluster != 0
            && s.dir_cursor_pool[i].matches(dir_cluster, want, need, want_long)
        {
            if !s.dir_cursor.matches(dir_cluster, want, need, want_long) {
                s.dir_cursor = s.dir_cursor_pool[i];
            }
            s.dir_cursor_pool[i].dir_cluster = 0;
            break;
        }
        i += 1;
    }
    if !s.dir_cursor.matches(dir_cluster, want, need, want_long) {
        let mut c = DirCursor {
            dir_cluster,
            want: *want,
            need,
            cluster: dir_cluster,
            sector: 0,
            ..DirCursor::empty()
        };
        // Upper-cased on the way in, because the accumulator that companion
        // entries are decoded into is upper-cased too. FAT long names are
        // case-preserving but case-insensitive, and comparing one folded
        // string against one unfolded one matches nothing.
        let mut i = 0usize;
        while i < want_long.len() {
            c.want_long[i] = to_upper(want_long[i]);
            i += 1;
        }
        c.want_long_len = want_long.len() as u8;
        s.dir_cursor = c;
    }
    let mut budget = DIR_SCAN_BUDGET_SECTORS;

    loop {
        if s.dir_cursor.sector >= spc {
            // Cluster exhausted — follow the chain.
            let next = match fs_fat_next(s, s.dir_cursor.cluster) {
                Ok(n) => n,
                Err(E_AGAIN) => {
                    // The FAT sector is on its way; this walk resumes here.
                    fs_dir_park(s);
                    return DirScan::Pending;
                }
                Err(_) => FAT32_EOC,
            };
            if !(2..FAT32_EOC).contains(&next) {
                let out = fs_dir_free_result(s);
                s.dir_cursor.dir_cluster = 0;
                return match out {
                    Some(loc) => DirScan::Free(loc),
                    None => DirScan::Full,
                };
            }
            s.dir_cursor.cluster = next;
            s.dir_cursor.sector = 0;
        }
        if budget == 0 || (budget < DIR_SCAN_BUDGET_SECTORS && fs_out_of_time(s)) {
            fs_dir_park(s);
            return DirScan::Pending;
        }
        budget -= 1;

        let lba = cluster_to_sector(s, s.dir_cursor.cluster) + s.dir_cursor.sector;
        // On a miss, the rest of this cluster is read with it.
        s.ra_hint = READAHEAD_SECTORS.min(spc - s.dir_cursor.sector - 1);
        let rrc = fs_read_blockbuf(s, lba);
        s.ra_hint = 0;
        if rrc == E_AGAIN {
            // Not cached yet: park the walk on this sector and resume here
            // when asked again.
            fs_dir_park(s);
            return DirScan::Pending;
        }
        if rrc != 0 {
            fs_note_io(s, rrc);
            s.dir_cursor.dir_cluster = 0;
            return DirScan::Io;
        }
        let mut e = 0usize;
        while e < BLOCK_SIZE {
            let b0 = s.block_buf[e];
            let attr = s.block_buf[e + 11];

            if b0 == 0x00 {
                // Never-used slot: the end of the directory, and also a
                // claimable slot. Everything past it is free too, so a run
                // that starts here is as long as the caller needs.
                fs_dir_note_free(s, lba, e as u16);
                s.dir_cursor.free_run = s.dir_cursor.free_run.max(need);
                let out = fs_dir_free_result(s);
                s.dir_cursor.dir_cluster = 0;
                return match out {
                    Some(loc) => DirScan::Free(loc),
                    None => DirScan::Full,
                };
            }

            if b0 == 0xE5 {
                fs_dir_note_free(s, lba, e as u16);
                // A deleted slot ends any live companion run in front of it.
                s.dir_cursor.lfn_run = 0;
                fs_lfn_acc_reset(s);
                e += DIR_ENTRY_SIZE;
                continue;
            }

            if attr == ATTR_LONG_NAME {
                // A live companion. Remember where the run starts so a match
                // or a claim can address the whole set.
                if s.dir_cursor.lfn_run == 0 {
                    s.dir_cursor.lfn_lba = lba;
                    s.dir_cursor.lfn_off = e as u16;
                }
                s.dir_cursor.lfn_run = s.dir_cursor.lfn_run.saturating_add(1);
                if s.dir_cursor.want_long_len > 0 {
                    fs_lfn_acc_take(s, e);
                }
                // Companions occupy slots, so they break a free run.
                s.dir_cursor.free_run = 0;
                e += DIR_ENTRY_SIZE;
                continue;
            }

            // A live short entry. It terminates both runs.
            s.dir_cursor.free_run = 0;
            let hit = if s.dir_cursor.want_long_len > 0 {
                let mut short = [0u8; 11];
                short.copy_from_slice(&s.block_buf[e..e + 11]);
                fs_lfn_acc_matches(s, &short)
            } else {
                name_eq(&s.block_buf[e..e + 11], want)
            };
            if (attr & ATTR_VOLUME_ID) == 0 && hit {
                let chi = u32::from(read_u16_le(&s.block_buf, e + 20));
                let clo = u32::from(read_u16_le(&s.block_buf, e + 26));
                let loc = DirentLoc {
                    lba,
                    off: e as u16,
                    exists: true,
                    is_dir: (attr & ATTR_DIRECTORY) != 0,
                    start_cluster: (chi << 16) | clo,
                    size: read_u32_le(&s.block_buf, e + 28),
                    attr,
                    mtime: fs_mtime_unix(&s.block_buf[e..e + DIR_ENTRY_SIZE]),
                    parent: dir_cluster,
                    lfn_lba: s.dir_cursor.lfn_lba,
                    lfn_off: s.dir_cursor.lfn_off,
                    lfn_run: s.dir_cursor.lfn_run,
                };
                s.dir_cursor.dir_cluster = 0;
                return DirScan::Found(loc);
            }
            s.dir_cursor.lfn_run = 0;
            fs_lfn_acc_reset(s);
            e += DIR_ENTRY_SIZE;
        }
        s.dir_cursor.sector += 1;
    }
}

/// Park the working walk in a free pool slot, so a later call with the same
/// arguments resumes it. With none free it is NOT parked and restarts when
/// asked again: evicting a parked walk instead lets more walkers than slots
/// evict each other every round and none ever finishes, while the parked
/// ones here finish, free their slots, and the rest take them.
fn fs_dir_park(s: &mut Fat32State) {
    let mut i = 0usize;
    while i < DIR_CURSOR_POOL {
        if s.dir_cursor_pool[i].dir_cluster == 0 {
            s.dir_cursor_pool[i] = s.dir_cursor;
            break;
        }
        i += 1;
    }
}

/// Forget the long name accumulated so far. Called wherever a companion run
/// ends without naming anything — a deleted slot, a short entry that did not
/// match — so the next run starts clean.
fn fs_lfn_acc_reset(s: &mut Fat32State) {
    s.dir_cursor.lfn_acc_len = 0;
    s.dir_cursor.lfn_acc_ok = 0;
    s.dir_cursor.lfn_acc_sum = 0;
}

/// Fold the companion entry at `off` in `block_buf` into the accumulated
/// long name.
///
/// The set is stored in reverse: the entry physically first carries the LAST
/// 13 characters and the `LFN_LAST` marker. Each entry's ordinal says where
/// its characters belong, so they are placed by ordinal rather than by
/// arrival order.
unsafe fn fs_lfn_acc_take(s: &mut Fat32State, off: usize) {
    let raw = s.block_buf[off];
    let last = (raw & LFN_LAST) != 0;
    let ord = usize::from(raw & 0x3F);
    let sum = s.block_buf[off + 13];
    if ord == 0 {
        s.dir_cursor.lfn_acc_ok = 0;
        return;
    }
    if last {
        // The physically-first entry starts a fresh name and fixes its
        // length; anything accumulated before it belonged to another run.
        s.dir_cursor.lfn_acc_len = 0;
        s.dir_cursor.lfn_acc_ok = 1;
        s.dir_cursor.lfn_acc_sum = sum;
    } else if s.dir_cursor.lfn_acc_ok == 0 || sum != s.dir_cursor.lfn_acc_sum {
        // A run that did not start with a marked last entry, or whose
        // members disagree about which short entry they name, is not a name.
        s.dir_cursor.lfn_acc_ok = 0;
        return;
    }

    let base = (ord - 1) * LFN_CHARS_PER_ENTRY;
    let mut i = 0usize;
    while i < LFN_CHARS_PER_ENTRY {
        let o = off + LFN_CHAR_OFFSETS[i];
        let unit = read_u16_le(&s.block_buf, o);
        // 0x0000 terminates, 0xFFFF pads past the terminator.
        if unit == 0x0000 || unit == 0xFFFF {
            break;
        }
        let pos = base + i;
        if pos >= LFN_MAX_CHARS {
            // Longer than this provider matches. Refusing to decode is not
            // the same as refusing to preserve: the run is still walked and
            // retired correctly, it simply never compares equal.
            s.dir_cursor.lfn_acc_ok = 0;
            return;
        }
        // Non-ASCII is not decoded, so a name containing it never matches
        // one this provider was asked for. It is still preserved on disk.
        if unit > 0x7F {
            s.dir_cursor.lfn_acc_ok = 0;
            return;
        }
        s.dir_cursor.lfn_acc[pos] = to_upper(unit as u8);
        if pos + 1 > usize::from(s.dir_cursor.lfn_acc_len) {
            s.dir_cursor.lfn_acc_len = (pos + 1) as u8;
        }
        i += 1;
    }
}

/// Does the accumulated companion run name `short`, and is that name the one
/// being looked for?
fn fs_lfn_acc_matches(s: &Fat32State, short: &[u8; 11]) -> bool {
    let c = &s.dir_cursor;
    if c.lfn_acc_ok == 0 || c.lfn_acc_len != c.want_long_len {
        return false;
    }
    // The checksum is what binds the companions to this entry. Without it a
    // stale run left in front of a reused slot would resolve the old name to
    // the new file.
    if c.lfn_acc_sum != fs_lfn_checksum(short) {
        return false;
    }
    let n = usize::from(c.want_long_len);
    c.lfn_acc[..n] == c.want_long[..n]
}

/// Extend the remembered free run with the slot at `(lba, off)`.
fn fs_dir_note_free(s: &mut Fat32State, lba: u32, off: u16) {
    if s.dir_cursor.free_run == 0 {
        s.dir_cursor.free_lba = lba;
        s.dir_cursor.free_off = off;
        // A run that starts here inherits whatever live companions sit
        // immediately in front of it: they are stranded, because the entry
        // they name is gone.
        if s.dir_cursor.lfn_run == 0 {
            s.dir_cursor.lfn_lba = 0;
            s.dir_cursor.lfn_off = 0;
        }
    }
    s.dir_cursor.free_run = s.dir_cursor.free_run.saturating_add(1);
}

/// The free-slot result for a walk that reached the end of the directory,
/// or `None` when no run long enough was seen.
fn fs_dir_free_result(s: &Fat32State) -> Option<DirentLoc> {
    let c = &s.dir_cursor;
    if c.free_run < c.need {
        return None;
    }
    Some(DirentLoc {
        lba: c.free_lba,
        off: c.free_off,
        exists: false,
        is_dir: false,
        start_cluster: 0,
        size: 0,
        attr: 0,
        mtime: 0,
        parent: c.dir_cluster,
        // Companions stranded in front of the claimable run: the claim
        // retires them, so a new name minted here cannot inherit an old
        // name's companions.
        lfn_lba: c.lfn_lba,
        lfn_off: c.lfn_off,
        lfn_run: if c.lfn_lba == 0 { 0 } else { c.lfn_run },
    })
}

/// Append one zeroed cluster to a full directory's chain and return the
/// first slot in it.
///
/// A FAT32 directory is an ordinary cluster chain; nothing in the format
/// caps its length. Refusing when the last cluster fills would turn a
/// directory that has accumulated enough names into a hard wall that no
/// amount of deleting elsewhere on the volume relieves.
///
/// The new cluster is zero-filled BEFORE it is linked. Zero bytes are the
/// end-of-directory marker, so a reader that reaches the new cluster over a
/// half-written link sees an empty tail rather than whatever the cluster
/// held when it was last used — which, on a volume that has recycled space,
/// is old directory entries naming clusters that now belong to something
/// else.
unsafe fn fs_dir_grow(s: &mut Fat32State, dir_cluster: u32) -> Option<DirentLoc> {
    if dir_cluster < 2 {
        return None;
    }
    // Walk to the chain's last cluster.
    let mut tail = dir_cluster;
    let mut guard: u32 = 0;
    loop {
        let next = fs_read_fat_entry(s, tail);
        if !(2..FAT32_EOC).contains(&next) {
            break;
        }
        tail = next;
        guard += 1;
        if guard > MAX_DIR_CLUSTERS {
            // A cyclic or absurdly long chain. Refusing to extend it is the
            // safe answer; growing it would compound the damage.
            return None;
        }
    }

    let spc = u32::from(s.sectors_per_cluster);
    if spc == 0 {
        return None;
    }
    // One cluster, not an extent: a directory grows by names, and reserving
    // 127 clusters for the next one would strand megabytes per directory.
    let cc = fs_find_free_cluster(s);
    if cc < 2 {
        return None;
    }

    let first = cluster_to_sector(s, cc);
    if fs_zero_sectors(s, first, spc) != 0 {
        return None;
    }
    // The zeroes are durable before the link, so the link can never publish
    // uninitialised bytes as directory entries.
    if fs_durable_point(s) != 0 {
        return None;
    }
    if fs_write_fat_entry(s, cc, FAT32_TAIL) != 0 {
        return None;
    }
    if fs_write_fat_entry(s, tail, cc) != 0 {
        return None;
    }
    if cc >= s.next_free_hint {
        s.next_free_hint = cc + 1;
    }
    fs_free_count_add(s, -1);
    // The walk that returned `Full` is stale now; the next one must see the
    // new cluster.
    s.dir_cursor.dir_cluster = 0;
    Some(DirentLoc {
        lba: first,
        off: 0,
        exists: false,
        is_dir: false,
        start_cluster: 0,
        size: 0,
        attr: 0,
        mtime: 0,
        parent: dir_cluster,
        lfn_lba: 0,
        lfn_off: 0,
        lfn_run: 0,
    })
}

/// Chain-length ceiling for a directory walk, as a corruption guard rather
/// than a policy limit: 65 536 clusters is far past any real directory and
/// far short of looping forever on a cyclic chain.
const MAX_DIR_CLUSTERS: u32 = 65_536;

/// Patch a directory entry's first-cluster (hi@20/lo@26) and size@28
/// fields in place. Read-modify-write of the entry's sector.
unsafe fn fs_patch_dirent(
    s: &mut Fat32State,
    lba: u32,
    off: u16,
    first_cluster: u32,
    size: u32,
) -> i32 {
    let rc = fs_read_blockbuf(s, lba);
    if rc != 0 {
        return rc;
    }
    let e = off as usize;
    if let Some(now) = fs_now_fat(s) {
        fs_stamp_written(&mut s.block_buf[e..e + DIR_ENTRY_SIZE], now);
    }
    s.block_buf[e + 20] = (first_cluster >> 16) as u8;
    s.block_buf[e + 21] = (first_cluster >> 24) as u8;
    s.block_buf[e + 26] = first_cluster as u8;
    s.block_buf[e + 27] = (first_cluster >> 8) as u8;
    let sz = size.to_le_bytes();
    s.block_buf[e + 28] = sz[0];
    s.block_buf[e + 29] = sz[1];
    s.block_buf[e + 30] = sz[2];
    s.block_buf[e + 31] = sz[3];
    fs_write_staged(s, lba)
}

/// Persist a writable FD's directory entry (first cluster + size) and
/// clear its dirty flag. The write lands in the sector cache; a caller
/// needing durability follows with a durable boundary and, once that is on
/// the device, `fs_note_dir_durable`.
unsafe fn fs_writeback_dir_entry(s: &mut Fat32State, slot: usize) -> i32 {
    let (lba, off, fc, sz) = {
        let of = &s.open_files[slot];
        (of.dir_lba, of.dir_off, of.start_cluster, of.size)
    };
    let rc = fs_patch_dirent(s, lba, off, fc, sz);
    if rc == 0 {
        s.open_files[slot].dirty = 0;
        if sz > s.open_files[slot].dir_media_size {
            s.open_files[slot].dir_media_size = sz;
        }
    }
    rc
}

/// Record that everything already submitted for `slot`'s directory entry is
/// now on non-volatile media. Called after a successful device flush or a
/// completed metadata fence; `covered` is the size frontier that flush
/// proves and `start_cluster` the chain head published with it.
fn fs_note_dir_durable(s: &mut Fat32State, slot: usize, covered: u32, start_cluster: u32) {
    if covered >= s.open_files[slot].dir_durable_size {
        s.open_files[slot].dir_durable_size = covered;
        s.open_files[slot].dir_durable_start = start_cluster;
    }
}

/// Resolve `path` into (parent directory cluster, final 8.3 name).
/// Intermediate components must be existing directories. Returns `None`
/// on a missing intermediate dir or a malformed component.
unsafe fn fs_split_parent(s: &mut Fat32State, path: &[u8]) -> Option<(u32, PathName)> {
    let mut cur = s.root_cluster;
    let mut i = 0usize;
    while i < path.len() && path[i] == b'/' {
        i += 1;
    }
    loop {
        let start = i;
        while i < path.len() && path[i] != b'/' {
            i += 1;
        }
        let comp = &path[start..i];
        if comp.is_empty() {
            return None;
        }
        let mut j = i;
        while j < path.len() && path[j] == b'/' {
            j += 1;
        }
        let is_final = j >= path.len();
        let mut want = PathName::empty();
        if !fs_path_component(comp, &mut want) {
            return None;
        }
        if is_final {
            return Some((cur, want));
        }
        let (sc, attr) = fs_dir_component(s, cur, &want)?;
        if (attr & ATTR_DIRECTORY) == 0 {
            return None;
        }
        cur = sc;
        i = j;
    }
}

/// FS_OPEN_CREATE: create (or truncate) `path` and return a writable FD
/// positioned for append at offset 0. The parent directory must already
/// exist (no mkdir). Append-only — an existing file is truncated to 0.
unsafe fn fs_op_create(s: &mut Fat32State, arg: *const u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len == 0 {
        return E_INVAL;
    }
    if s.init_phase != Fat32InitPhase::Done {
        return E_AGAIN;
    }
    if s.root_cluster < 2 {
        return E_AGAIN;
    }
    s.io_rc = 0;
    let path = core::slice::from_raw_parts(arg, arg_len);
    let (parent, want) = match fs_split_parent(s, path) {
        Some(p) => p,
        None => return fs_io_errno(s, -2), // ENOENT only when truly absent
    };
    // Resume the free-cluster scan past clusters consumed by earlier mounts
    // (and the orphaned chains of prior truncates) instead of rescanning the
    // allocated low region every time. Only when the in-memory hint is still
    // at its mount default (so we don't clobber progress within this mount).
    // An explicit `init_free_hint` param wins over the on-disk FSINFO hint —
    // it is the operator's override for a volume whose FSINFO hint is stale.
    if s.next_free_hint <= 2 {
        // The dispatch chokepoint wipes before the first operation of any
        // kind (`root_cleaned`), which is strictly earlier than any create,
        // so this arm is unreached on that path. It stands as the guard for
        // a caller that reaches creation without passing dispatch.
        if s.clean_root > 0 && s.root_cleaned == 0 && s.expect_volume_id != 0 {
            s.root_cleaned = 1;
            let _ = fs_clean_root(s);
            // `clear_free_region` blindly zeros the FAT span at
            // `init_free_hint` — DESTRUCTIVE. Run it ONLY on a fresh-format
            // mount (the same `clean_root` that just wiped the root). On a
            // remount (`clean_root` unset) any crash-durable files live in
            // that very region, and zeroing it would sever their multi-cluster
            // FAT chains past the first cluster — read-back then reconstructs
            // only ~1 cluster's worth (FS_STAT still shows the full size).
            // Gating the clear on `clean_root` preserves those chains; the
            // allocator simply scans past the existing data from
            // `next_free_hint`.
            if s.init_free_hint >= 2 && s.clear_free_region > 0 {
                let _ = fs_clear_fat_region(s, s.init_free_hint, s.clear_free_region);
            }
        }
        if s.init_free_hint >= 2 {
            s.next_free_hint = s.init_free_hint;
        }
    }
    // Find a free OpenFile slot up front.
    let Some(slot) = fs_claim_slot(s) else {
        return -23; // ENFILE
    };

    let mut want = want;
    // A long name needs its companion slots reserved contiguously with the
    // entry they name; an 8.3 name needs one slot.
    let mut loc = match fs_name_walk(s, parent, &want, want.lfn_entries() + 1) {
        DirScan::Found(l) => l,
        DirScan::Free(l) => l,
        DirScan::Pending => return E_AGAIN,
        // The directory has no free slot and no end marker. Grow its chain
        // rather than refusing: a root that fills up is otherwise a hard
        // wall, and FAT32 permits a directory to span as many clusters as
        // any other file.
        DirScan::Full => match fs_dir_grow(s, parent) {
            Some(l) => l,
            None => return fs_alloc_errno(s),
        },
        DirScan::Io => return fs_io_errno(s, -5), // EIO
    };

    // Never repurpose a directory entry as a regular file: truncating it would
    // orphan the directory's contents and leave a writable handle on an entry
    // still flagged ATTR_DIRECTORY.
    if loc.exists && loc.is_dir {
        return -21;
    } // EISDIR
    if loc.exists && fs_detached_writer_at(s, loc.lba, loc.off) {
        return E_AGAIN;
    }

    if loc.exists {
        // Truncate: zero the entry's cluster and size, then hand the old
        // chain to the background reclaimer.
        //
        // Walking the chain here instead would be O(N) device round-trips
        // inside one `provider_call`, which is why the release is deferred
        // rather than skipped. Skipping it strands the clusters: a node that
        // recycles the same names — a WAL segment, a snapshot, an object
        // body — would reach ENOSPC on a volume that is mostly free, with
        // nothing on the volume to say where the space went.
        if loc.start_cluster >= 2 && !fs_free_queue_has_room(s) {
            return E_AGAIN;
        }
        let prc = fs_patch_dirent(s, loc.lba, loc.off, 0, 0);
        if prc != 0 {
            return fs_rc_errno(prc);
        }
        if loc.start_cluster >= 2 {
            fs_queue_free_chain(s, loc.start_cluster);
        }
        // The entry keeps the 8.3 alias it was minted with — the companions
        // in front of it check against that one.
        if want.long_len > 0 {
            match fs_dirent_short_name(s, &loc) {
                Some(n) => want.short = n,
                None => return fs_io_errno(s, -5),
            }
        }
    } else {
        // A long name still needs the 8.3 alias the format indexes by, and
        // it has to be unique in this directory. Synthesised only for a NEW
        // entry: re-using a name keeps the alias the companions already
        // check against, and a fresh one would invalidate their checksum.
        // Chosen before anything is written, so the walks it takes see the
        // directory as it is.
        if want.long_len > 0 {
            let arc = fs_assign_short_alias(s, parent, &mut want);
            if arc != 0 {
                return arc;
            }
        }
        // Retire any long-name companions stranded in front of the slot
        // being claimed. They belong to a name whose short entry is already
        // gone; minting a new entry behind them makes a real reader resolve
        // the OLD long name onto the NEW file's bytes, which `fsck` reports
        // as a long-name checksum mismatch and declines to repair.
        let lrc = fs_lfn_retire(s, &loc);
        if lrc != 0 {
            return fs_rc_errno(lrc);
        }
        // A fresh entry: ATTR_ARCHIVE, no chain, no bytes.
        let run_start = loc;
        let wrc = fs_dirent_mint(s, &run_start, &want, ATTR_ARCHIVE, 0, 0, &mut loc);
        if wrc != 0 {
            return fs_rc_errno(wrc);
        }
    }

    // No cluster is reserved here. `OPEN_CREATE` mints a name; the chain
    // starts at the first byte written.
    //
    // Reserving an extent up front would move the cold FAT mutation onto the
    // boot path and out of the first client fsync, which is tempting and
    // wrong: a create that is then abandoned — closed without a write, or
    // interrupted — leaves a linked chain that the directory entry, still
    // reading `{cluster: 0, size: 0}`, does not reference, and nothing on
    // the volume can afterwards tell that chain from live data. A latency
    // optimisation is not worth a leak that only grows. The caller that
    // genuinely needs its capacity warmed asks for it with `PREALLOCATE`,
    // which is where the cold mutation belongs.
    tx_save_file(s, slot);
    let of = &mut s.open_files[slot];
    // `fs_claim_slot` has already stamped this slot with the owner on the
    // provider stack; carry that across the reset. Losing it would leave every
    // FS_OPEN_CREATE handle unowned — `max_open_per_owner` silently off on the
    // write path, and the handle unreclaimable when its owner is released.
    let (owner_slot, owner_generation) = (of.owner_slot, of.owner_generation);
    *of = OpenFile::empty();
    of.owner_slot = owner_slot;
    of.owner_generation = owner_generation;
    of.in_use = 1;
    of.writable = 1;
    of.name = want.short;
    of.dirty = 0;
    of.start_cluster = 0;
    of.current_cluster = 0;
    of.fixed_contiguous = 1;
    of.size = 0;
    of.offset = 0;
    of.dir_lba = loc.lba;
    of.dir_off = loc.off;
    abi::kernel_abi::fd::tag_fd(abi::kernel_abi::fd::FD_TAG_FS, slot as i32)
}

// ============================================================================
// Directory-entry timestamps
// ============================================================================

/// Byte offsets of the timestamp fields inside a 32-byte directory entry.
const DE_CRT_TENTH: usize = 13;
const DE_CRT_TIME: usize = 14;
const DE_CRT_DATE: usize = 16;
const DE_ACC_DATE: usize = 18;
const DE_WRT_TIME: usize = 22;
const DE_WRT_DATE: usize = 24;

/// FAT timestamps count from 1980; anything earlier cannot be represented.
const FAT_EPOCH_YEAR: u32 = 1980;

/// The current wall-clock time in FAT's `(date, time, tenths)` encoding, or
/// `None` when the platform has no real-time clock.
///
/// `None` is not a failure and is not padded with a plausible-looking
/// value. A bare-metal node with no RTC genuinely does not know what time it
/// is, and stamping every file it writes with 1980-01-01 — or with its own
/// uptime — produces a volume whose timestamps look like data and are not.
/// Leaving the fields zero is how the format spells "no timestamp", and a
/// reader shows it as blank rather than as a date that never happened.
unsafe fn fs_now_fat(s: &Fat32State) -> Option<(u16, u16, u8)> {
    let ms = dev_unix_millis(s.sys());
    if ms == 0 {
        return None;
    }
    let (secs, milli) = div_rem_u64_by_u32(ms, 1000);
    // Unix seconds fit a u32 until 2106, and every calculation below is
    // 32-bit from here on. That is not incidental: a PIC module has no
    // compiler intrinsics to call, so a 64-bit divide on a 32-bit target
    // emits a reference to `__aeabi_uldivmod` that the module linker cannot
    // resolve. One narrowing division, done explicitly, keeps the rest of
    // this ordinary arithmetic.
    if secs > u64::from(u32::MAX) {
        return None;
    }
    let secs = secs as u32;
    let days = secs / 86_400;
    let tod = secs % 86_400;
    let (y, m, d) = fs_civil_from_days(days);
    if y < FAT_EPOCH_YEAR {
        return None;
    }
    // Date: bits 15..9 year-since-1980, 8..5 month, 4..0 day.
    let date = (((y - FAT_EPOCH_YEAR) & 0x7F) << 9) | ((m & 0x0F) << 5) | (d & 0x1F);
    // Time: bits 15..11 hours, 10..5 minutes, 4..0 seconds/2.
    let hh = tod / 3600;
    let mm = (tod % 3600) / 60;
    let ss = tod % 60;
    let time = (hh << 11) | (mm << 5) | (ss / 2);
    // The creation stamp carries a tenths-of-a-second field that also holds
    // the odd second the two-second resolution above drops.
    let tenths = ((ss % 2) * 100 + milli / 10) as u8;
    Some((date as u16, time as u16, tenths))
}

/// Divide a `u64` by a `u32`, returning `(quotient, remainder)`, using only
/// 32-bit operations.
///
/// Restoring long division, 64 iterations. A PIC module links against
/// nothing, so on a 32-bit target the `/` operator on a `u64` is a call to
/// `__aeabi_uldivmod` that resolves to no symbol — the module builds and
/// then fails to link, which is a late and confusing place to discover it.
/// This is called once per directory-entry timestamp, so the loop costs
/// nothing that matters.
const fn div_rem_u64_by_u32(n: u64, d: u32) -> (u64, u32) {
    if d == 0 {
        return (0, 0);
    }
    let d64 = d as u64;
    let mut rem: u64 = 0;
    let mut quo: u64 = 0;
    let mut i = 64;
    while i > 0 {
        i -= 1;
        rem = (rem << 1) | ((n >> i) & 1);
        if rem >= d64 {
            rem -= d64;
            quo |= 1 << i;
        }
    }
    (quo, rem as u32)
}

/// Split days-since-the-Unix-epoch into `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days`, shifted to a March-based year so the
/// leap day falls at the end and month lengths become one expression.
/// Integer-only, 32-bit-only, and allocation-free — see
/// [`div_rem_u64_by_u32`] for why the width matters.
const fn fs_civil_from_days(days: u32) -> (u32, u32, u32) {
    // 719_468 = days from 0000-03-01 to 1970-01-01. `days` is bounded by the
    // u32 seconds ceiling (year 2106), so the sum cannot overflow.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March = 0
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Inverse of [`fs_civil_from_days`]: days since the Unix epoch.
const fn fs_days_from_civil(y: u32, m: u32, d: u32) -> u32 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Stamp an entry's creation, write and access fields with `now`.
fn fs_stamp_created(ent: &mut [u8], now: (u16, u16, u8)) {
    let (date, time, tenths) = now;
    ent[DE_CRT_TENTH] = tenths;
    ent[DE_CRT_TIME..DE_CRT_TIME + 2].copy_from_slice(&time.to_le_bytes());
    ent[DE_CRT_DATE..DE_CRT_DATE + 2].copy_from_slice(&date.to_le_bytes());
    ent[DE_ACC_DATE..DE_ACC_DATE + 2].copy_from_slice(&date.to_le_bytes());
    ent[DE_WRT_TIME..DE_WRT_TIME + 2].copy_from_slice(&time.to_le_bytes());
    ent[DE_WRT_DATE..DE_WRT_DATE + 2].copy_from_slice(&date.to_le_bytes());
}

/// Update only the last-write and last-access fields, leaving creation
/// alone — a file keeps the time it was made.
fn fs_stamp_written(ent: &mut [u8], now: (u16, u16, u8)) {
    let (date, time, _) = now;
    ent[DE_ACC_DATE..DE_ACC_DATE + 2].copy_from_slice(&date.to_le_bytes());
    ent[DE_WRT_TIME..DE_WRT_TIME + 2].copy_from_slice(&time.to_le_bytes());
    ent[DE_WRT_DATE..DE_WRT_DATE + 2].copy_from_slice(&date.to_le_bytes());
}

/// Decode an entry's last-write stamp into Unix seconds, or 0 when unset.
fn fs_mtime_unix(ent: &[u8]) -> u32 {
    let date = u16::from_le_bytes([ent[DE_WRT_DATE], ent[DE_WRT_DATE + 1]]);
    if date == 0 {
        return 0;
    }
    let time = u16::from_le_bytes([ent[DE_WRT_TIME], ent[DE_WRT_TIME + 1]]);
    let y = FAT_EPOCH_YEAR + u32::from(date >> 9);
    let m = u32::from((date >> 5) & 0x0F);
    let d = u32::from(date & 0x1F);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return 0;
    }
    if y < 1970 {
        return 0;
    }
    let days = fs_days_from_civil(y, m, d);
    let tod = u32::from(time >> 11) * 3600
        + u32::from((time >> 5) & 0x3F) * 60
        + u32::from(time & 0x1F) * 2;
    days.saturating_mul(86_400).saturating_add(tod)
}

/// Write a fresh 32-byte directory entry for `name` at `loc`, with the given
/// attribute byte, chain head and size.
///
/// One place mints entries, so one place decides what a new entry's bytes
/// are — the attribute byte, the zeroed timestamp fields, the cleared
/// reserved bytes. Two places doing it is how a directory ends up holding
/// entries that differ in fields nobody meant to vary.
unsafe fn fs_dirent_mint(
    s: &mut Fat32State,
    loc: &DirentLoc,
    name: &PathName,
    attr: u8,
    first_cluster: u32,
    size: u32,
    short_loc: &mut DirentLoc,
) -> i32 {
    // `loc` names the START of the reserved run. A long name puts its
    // companions there and the short entry behind them, so the caller's
    // record of "where this file's entry lives" is the slot computed here,
    // not the one it asked from.
    *short_loc = *loc;
    fs_dir_changed(s, loc.parent);
    let companions = name.lfn_entries();
    if companions > 0 {
        // The companion set comes first, because it is stored in front of
        // the entry it names. A crash between the two leaves companions with
        // no live entry behind them, which every reader — and the claim path
        // here — treats as stranded and ignores. The reverse order would
        // leave a live entry under its synthesised `~N` name with the
        // caller's name nowhere on the volume.
        let rc = fs_lfn_write(s, loc, name, companions);
        if rc != 0 {
            return rc;
        }
        match fs_dirent_advance(s, loc.parent, loc.lba, loc.off, companions) {
            Some((lba, off)) => {
                short_loc.lba = lba;
                short_loc.off = off;
            }
            None => return -5, // EIO — the run the walk reserved is gone
        }
        short_loc.lfn_lba = loc.lba;
        short_loc.lfn_off = loc.off;
        short_loc.lfn_run = companions;
    }
    let rc = fs_read_blockbuf(s, short_loc.lba);
    if rc != 0 {
        return rc;
    }
    let e = short_loc.off as usize;
    let mut i = 0usize;
    while i < DIR_ENTRY_SIZE {
        s.block_buf[e + i] = 0;
        i += 1;
    }
    let mut n = 0usize;
    while n < 11 {
        s.block_buf[e + n] = name.short[n];
        n += 1;
    }
    s.block_buf[e + 11] = attr;
    if let Some(now) = fs_now_fat(s) {
        fs_stamp_created(&mut s.block_buf[e..e + DIR_ENTRY_SIZE], now);
    }
    s.block_buf[e + 20] = (first_cluster >> 16) as u8;
    s.block_buf[e + 21] = (first_cluster >> 24) as u8;
    s.block_buf[e + 26] = first_cluster as u8;
    s.block_buf[e + 27] = (first_cluster >> 8) as u8;
    write_u32_le(&mut s.block_buf, e + 28, size);
    fs_write_staged(s, short_loc.lba)
}

/// Step `slots` directory entries forward from `(lba, off)`, following the
/// chain when the walk leaves the sector.
///
/// The next sector is not `lba + 1` once a directory spans more than one
/// cluster — the next cluster can be anywhere — which is the same reason
/// [`fs_lfn_retire`] walks rather than increments.
unsafe fn fs_dirent_advance(
    s: &mut Fat32State,
    parent: u32,
    lba: u32,
    off: u16,
    slots: u8,
) -> Option<(u32, u16)> {
    let mut lba = lba;
    let mut off = off as usize;
    let mut left = slots;
    while left > 0 {
        off += DIR_ENTRY_SIZE;
        if off >= BLOCK_SIZE {
            lba = fs_dir_next_lba(s, parent, lba)?;
            off = 0;
        }
        left -= 1;
    }
    Some((lba, off as u16))
}

/// Write `count` long-name companion entries for `name`, starting at `loc`.
///
/// The set is stored in REVERSE: the entry physically first carries the last
/// characters and the `LFN_LAST` marker, so a reader walking forward meets
/// the end of the name before it meets the entry the name belongs to. Every
/// companion carries the checksum of the 8.3 name behind it, which is what
/// stops a stale run being read as naming whatever entry later occupies the
/// slot after it.
unsafe fn fs_lfn_write(s: &mut Fat32State, loc: &DirentLoc, name: &PathName, count: u8) -> i32 {
    fs_dir_changed(s, loc.parent);
    let sum = fs_lfn_checksum(&name.short);
    let n = usize::from(name.long_len);
    let mut lba = loc.lba;
    let mut off = loc.off as usize;
    let mut written = 0u8;
    while written < count {
        // Physical slot `written` holds ordinal `count - written`.
        let ord = count - written;
        let rc = fs_read_blockbuf(s, lba);
        if rc != 0 {
            return rc;
        }
        let e = off;
        let mut z = 0usize;
        while z < DIR_ENTRY_SIZE {
            s.block_buf[e + z] = 0;
            z += 1;
        }
        s.block_buf[e] = if written == 0 { ord | LFN_LAST } else { ord };
        s.block_buf[e + 11] = ATTR_LONG_NAME;
        s.block_buf[e + 13] = sum;
        // Cluster field is zero in a companion: it names nothing itself.
        let base = usize::from(ord - 1) * LFN_CHARS_PER_ENTRY;
        let mut i = 0usize;
        while i < LFN_CHARS_PER_ENTRY {
            let o = e + LFN_CHAR_OFFSETS[i];
            let pos = base + i;
            let unit: u16 = if pos < n {
                u16::from(name.long[pos])
            } else if pos == n {
                0x0000 // terminator
            } else {
                0xFFFF // padding past it
            };
            let b = unit.to_le_bytes();
            s.block_buf[o] = b[0];
            s.block_buf[o + 1] = b[1];
            i += 1;
        }
        let rc = fs_write_staged(s, lba);
        if rc != 0 {
            return rc;
        }
        written += 1;
        if written == count {
            break;
        }
        off += DIR_ENTRY_SIZE;
        if off >= BLOCK_SIZE {
            match fs_dir_next_lba(s, loc.parent, lba) {
                Some(next) => {
                    lba = next;
                    off = 0;
                }
                None => return -5, // EIO
            }
        }
    }
    0
}

/// FS_MKDIR: create one directory by path.
///
/// The parent must already exist — this creates one directory, not a path.
/// The new directory is minted with its mandatory `.` and `..` entries, and
/// its cluster is zero-filled and committed BEFORE the name that reaches it
/// is published, so a crash can expose an empty directory but never one
/// whose remaining sectors hold whatever the cluster last contained.
///
/// `..` on a directory whose parent is the root carries cluster 0, which is
/// how the format spells "the root" — not the root's actual cluster number.
/// Writing the real number there is a classic FAT bug: `fsck` reports it,
/// and readers that compare against 0 to detect the root loop forever.
unsafe fn fs_op_mkdir(s: &mut Fat32State, arg: *const u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len == 0 {
        return E_INVAL;
    }
    if s.init_phase != Fat32InitPhase::Done || s.root_cluster < 2 {
        return E_AGAIN;
    }
    s.io_rc = 0;
    let path = core::slice::from_raw_parts(arg, arg_len);
    let (parent, want) = match fs_split_parent(s, path) {
        Some(p) => p,
        None => return fs_io_errno(s, -2), // ENOENT
    };
    let mut want = want;
    if want.long_len > 0 {
        let arc = fs_assign_short_alias(s, parent, &mut want);
        if arc != 0 {
            return arc;
        }
    }
    let loc = match fs_name_walk(s, parent, &want, want.lfn_entries() + 1) {
        DirScan::Found(l) => {
            // The contract makes an existing directory success, so a caller
            // creating each level of a path top-down can re-issue safely.
            return if l.is_dir { 0 } else { -17 }; // EEXIST — a file holds it
        }
        DirScan::Free(l) => l,
        DirScan::Pending => return E_AGAIN,
        DirScan::Full => match fs_dir_grow(s, parent) {
            Some(l) => l,
            None => return fs_alloc_errno(s),
        },
        DirScan::Io => return fs_io_errno(s, -5), // EIO
    };

    let cc = fs_alloc_one(s, 0);
    if cc < 2 {
        return fs_alloc_errno(s);
    }
    // Zero every sector of the new cluster: zero is the end-of-directory
    // marker, so an interrupted mkdir leaves an empty directory rather than
    // one that appears to contain whatever the cluster held before.
    let first = cluster_to_sector(s, cc);
    let spc = u32::from(s.sectors_per_cluster);
    if spc > 1 {
        let rc = fs_zero_sectors(s, first + 1, spc - 1);
        if rc != 0 {
            return fs_rc_errno(rc);
        }
    }
    // The first sector carries `.` and `..`, then end-of-directory.
    let mut head = [0u8; BLOCK_SIZE];
    fs_dot_entry(&mut head[..DIR_ENTRY_SIZE], b".          ", cc);
    let parent_link = if parent == s.root_cluster { 0 } else { parent };
    fs_dot_entry(
        &mut head[DIR_ENTRY_SIZE..2 * DIR_ENTRY_SIZE],
        b"..         ",
        parent_link,
    );
    let rc = fs_write_sector_from(s, first, 1, head.as_ptr());
    if rc != 0 {
        return fs_rc_errno(rc);
    }
    // The contents are durable before the name that reaches them is
    // published: a durable boundary, which the engine honours however many
    // steps the device takes. The name itself is published by `FSYNC_NAME`.
    let rc = fs_durable_point(s);
    if rc != 0 {
        return fs_rc_errno(rc);
    }

    let lrc = fs_lfn_retire(s, &loc);
    if lrc != 0 {
        return fs_rc_errno(lrc);
    }
    let mut short_loc = loc;
    let rc = fs_dirent_mint(s, &loc, &want, ATTR_DIRECTORY, cc, 0, &mut short_loc);
    if rc != 0 {
        return fs_rc_errno(rc);
    }
    0
}

/// Fill a `.` or `..` directory entry naming `cluster`.
fn fs_dot_entry(out: &mut [u8], name: &[u8; 11], cluster: u32) {
    out[..11].copy_from_slice(name);
    out[11] = ATTR_DIRECTORY;
    out[20] = (cluster >> 16) as u8;
    out[21] = (cluster >> 24) as u8;
    out[26] = cluster as u8;
    out[27] = (cluster >> 8) as u8;
}

/// FS_TRUNCATE: set an existing file's length to `len`, releasing the
/// clusters past the new end.
///
/// Shrink only. Growing a file by moving its size field would publish
/// clusters the file never wrote as its contents, which on a recycled
/// volume is whatever used to live there; a caller that wants capacity asks
/// for `PREALLOCATE`, which allocates it.
///
/// The size field is published FIRST, and only then are the clusters past it
/// queued for release. A crash between the two leaves a correct, shorter
/// file with some clusters still linked behind it — untidy, and reclaimed by
/// the next drain. The reverse order would leave a file whose size claims
/// bytes its chain no longer reaches.
unsafe fn fs_op_truncate(s: &mut Fat32State, arg: *const u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 9 {
        return E_INVAL;
    }
    if s.init_phase != Fat32InitPhase::Done || s.root_cluster < 2 {
        return E_AGAIN;
    }
    let a = core::slice::from_raw_parts(arg, arg_len);
    let wide = u64::from_le_bytes([a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]]);
    if wide > u64::from(u32::MAX) {
        return E_INVAL;
    }
    let len = wide as u32;
    let path = &a[8..];
    s.io_rc = 0;
    let (parent, want) = match fs_split_parent(s, path) {
        Some(p) => p,
        None => return fs_io_errno(s, -2), // ENOENT
    };
    let loc = match fs_name_walk(s, parent, &want, 1) {
        DirScan::Found(l) => l,
        DirScan::Pending => return E_AGAIN,
        _ => return fs_io_errno(s, -2), // ENOENT
    };
    if loc.is_dir {
        return -21; // EISDIR
    }
    // The busy check comes before the length check: a file with a live
    // writer has no settled size to compare against, so answering EINVAL
    // ("that length is bigger than the file") would be reporting on a number
    // that is still moving.
    let mut k = 0usize;
    while k < MAX_OPEN_FILES {
        let of = &s.open_files[k];
        if of.in_use != OF_FREE
            && of.writable != 0
            && (of.dir_lba == loc.lba && of.dir_off == loc.off
                || (loc.start_cluster >= 2 && of.start_cluster == loc.start_cluster))
        {
            return if of.in_use == OF_DETACHED {
                E_AGAIN
            } else {
                -16
            }; // EBUSY
        }
        k += 1;
    }
    if len > loc.size {
        return E_INVAL; // grow is not this opcode's job
    }
    if !fs_free_queue_has_room(s) {
        return E_AGAIN;
    }

    let cpb = u32::from(s.bytes_per_sector) * u32::from(s.sectors_per_cluster);
    if cpb == 0 {
        return E_AGAIN;
    }
    let keep = len.div_ceil(cpb);
    // Find the cluster that becomes the new tail, and the first one to drop.
    // The walk is resumable: a chain longer than the cache holds takes
    // several asks, each answered `EAGAIN` with nothing changed but how far
    // the walk has got (`trunc_walk`, a cache over the chain).
    let (new_head, drop_head, tail) = if keep == 0 {
        (0, loc.start_cluster, 0)
    } else {
        let w = s.trunc_walk;
        let (mut cur, mut n) = if w.start == loc.start_cluster && w.n >= 1 && w.n <= keep {
            (w.cur, w.n)
        } else {
            (loc.start_cluster, 1u32)
        };
        while n < keep {
            let next = match fs_fat_next(s, cur) {
                Ok(v) => v,
                Err(rc) => {
                    s.trunc_walk = TruncWalk {
                        start: loc.start_cluster,
                        n,
                        cur,
                    };
                    return rc;
                }
            };
            if !(2..FAT32_EOC).contains(&next) {
                // The chain is already shorter than the size claimed. Nothing
                // to release; publishing the smaller size is still correct
                // and makes the entry describe what is actually there.
                s.trunc_walk = TruncWalk::EMPTY;
                return fs_truncate_publish(s, &loc, len, loc.start_cluster);
            }
            cur = next;
            n += 1;
            if fs_out_of_time(s) && n < keep {
                s.trunc_walk = TruncWalk {
                    start: loc.start_cluster,
                    n,
                    cur,
                };
                return E_AGAIN;
            }
        }
        let drop = match fs_fat_next(s, cur) {
            Ok(v) => v,
            Err(rc) => {
                s.trunc_walk = TruncWalk {
                    start: loc.start_cluster,
                    n,
                    cur,
                };
                return rc;
            }
        };
        s.trunc_walk = TruncWalk::EMPTY;
        (
            loc.start_cluster,
            if (2..FAT32_EOC).contains(&drop) {
                drop
            } else {
                0
            },
            cur,
        )
    };

    let rc = fs_truncate_publish(s, &loc, len, new_head);
    if rc != 0 {
        return rc;
    }
    if tail >= 2 {
        // Terminate the retained chain before the dropped tail is freed, so
        // no window exists in which the file's last cluster points at a
        // cluster the reclaimer has already handed back.
        let rc = fs_write_fat_entry(s, tail, FAT32_TAIL);
        if rc != 0 {
            return fs_rc_errno(rc);
        }
        let rc = fs_durable_point(s);
        if rc != 0 {
            return rc;
        }
    }
    if drop_head >= 2 {
        let e = s.op_wait_epoch;
        fs_queue_free_chain(s, drop_head);
        s.op_wait_epoch = e;
    }
    0
}

/// Publish a truncated size (and possibly a cleared chain head), with a
/// durable boundary behind it: the call is decided when that reaches the
/// device.
unsafe fn fs_truncate_publish(s: &mut Fat32State, loc: &DirentLoc, len: u32, head: u32) -> i32 {
    let rc = fs_patch_dirent(s, loc.lba, loc.off, head, len);
    if rc != 0 {
        return fs_rc_errno(rc);
    }
    fs_durable_point(s)
}

/// FS_PREALLOCATE: physically back a fixed-capacity writable file, persist
/// its final directory size once, and leave the write cursor at byte zero.
///
/// The chain can be far larger than one call — or the cache — can allocate:
/// a 64 MiB log segment is 16 384 clusters over 128 FAT sectors. So the
/// first ask checks the request and takes it (`EINPROGRESS`); the chain is
/// then extended one FAT-sector extent per transaction, by the step and by
/// every re-ask (`fs_prealloc_advance`), and the size is published behind a
/// durable boundary. The decision is 0 once that reaches the device, or the
/// errno that stopped it (`ENOSPC` — with what was allocated given back).
///
/// Returns `Ok((capacity, clusters))` to take, or the decided errno.
unsafe fn fs_prealloc_check(
    s: &mut Fat32State,
    handle: i32,
    arg: *const u8,
    arg_len: usize,
) -> Result<(u32, u32), i32> {
    if arg.is_null() || arg_len < 4 {
        return Err(E_INVAL);
    }
    let slot = handle as usize;
    if slot >= MAX_OPEN_FILES || s.open_files[slot].in_use != OF_OPEN {
        return Err(E_INVAL);
    }
    if s.open_files[slot].writable == 0 {
        return Err(E_INVAL);
    }
    if s.open_files[slot].op_busy != 0 {
        return Err(E_AGAIN);
    }
    if s.open_files[slot].offset != 0 || s.open_files[slot].size != 0 {
        return Err(E_INVAL);
    }
    let capacity = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
    if capacity == 0 {
        return Err(E_INVAL);
    }
    let cpb = (s.bytes_per_sector as u32).saturating_mul(s.sectors_per_cluster as u32);
    if cpb == 0 {
        return Err(E_AGAIN);
    }
    Ok((capacity, capacity.saturating_add(cpb - 1) / cpb))
}

/// Extents one move of a `PREALLOCATE` allocates at most.
const PREALLOC_EXTENTS_PER_MOVE: u32 = 8;

/// One move of the `PREALLOCATE` in op slot `i`.
unsafe fn fs_prealloc_advance(s: &mut Fat32State, i: usize) {
    let fd = usize::from(s.ops[i].fd);
    if fd >= MAX_OPEN_FILES || s.open_files[fd].in_use == OF_FREE {
        s.ops[i].result = E_INVAL;
        s.ops[i].state = OPS_DONE;
        return;
    }
    let target = s.ops[i].target;
    let capacity = s.ops[i].capacity;
    let mut moves = 0u32;
    while s.open_files[fd].allocated_clusters < target {
        if moves >= PREALLOC_EXTENTS_PER_MOVE || (moves > 0 && fs_out_of_time(s)) {
            return;
        }
        moves += 1;
        s.io_rc = 0;
        let rc = fs_tx(s, |s| {
            let b = fs_begin_mutation(s);
            if b != 0 {
                return b;
            }
            tx_save_file(s, fd);
            let prev = s.open_files[fd].allocation_tail;
            let (first, count) = fs_alloc_extent(s, prev);
            if first < 2 || count == 0 {
                return fs_alloc_errno(s);
            }
            let of = &mut s.open_files[fd];
            if of.start_cluster < 2 {
                // First extent: this is where the file's chain begins. The
                // create left the entry chainless, so `PREALLOCATE` is what
                // mints the chain as well as sizing it.
                of.start_cluster = first;
                of.current_cluster = first;
            } else if first != prev.saturating_add(1) {
                of.fixed_contiguous = 0;
            }
            of.allocated_clusters = of.allocated_clusters.saturating_add(u32::from(count));
            of.allocation_tail = first + u32::from(count) - 1;
            0
        });
        if rc == E_AGAIN {
            return;
        }
        if rc < 0 {
            // Decided: the volume cannot back the capacity. What was linked
            // so far is referenced by nothing on the volume (the entry still
            // says empty), so it goes back rather than leaking.
            let head = s.open_files[fd].start_cluster;
            if head >= 2 {
                let _ = fs_tx(s, |s| {
                    tx_save_file(s, fd);
                    fs_queue_free_chain(s, head);
                    let of = &mut s.open_files[fd];
                    of.start_cluster = 0;
                    of.current_cluster = 0;
                    of.allocated_clusters = 0;
                    of.allocation_tail = 0;
                    of.fixed_contiguous = 1;
                    0
                });
            }
            s.ops[i].result = rc;
            s.ops[i].state = OPS_DONE;
            fs_op_finished(s, i);
            return;
        }
    }
    // Every cluster is linked: publish the size once, behind a durable
    // boundary that decides the call.
    let rc = fs_tx(s, |s| {
        let b = fs_begin_mutation(s);
        if b != 0 {
            return b;
        }
        tx_save_file(s, fd);
        // Warm the first data sector while PREALLOCATE is still on the
        // caller's setup path. Some consumer NVMe controllers pay a one-time
        // 100+ ms latency on the first write into a fresh data region even
        // after metadata I/O; a caller that asked for fixed capacity up front
        // is exactly the caller that does not want to pay it inside its
        // first durability fence.
        let head = s.open_files[fd].start_cluster;
        let zrc = fs_zero_sectors(s, cluster_to_sector(s, head), 1);
        if zrc != 0 {
            return zrc;
        }
        let of = &mut s.open_files[fd];
        of.size = capacity;
        of.offset = 0;
        of.current_cluster = of.start_cluster;
        of.sector_in_cluster = 0;
        of.fixed_capacity = 1;
        of.dirty = 1;
        let rc = fs_writeback_dir_entry(s, fd);
        if rc != 0 {
            return rc;
        }
        fs_durable_point(s)
    });
    if rc == E_AGAIN {
        return;
    }
    if rc < 0 {
        s.ops[i].result = rc;
        s.ops[i].state = OPS_DONE;
        fs_op_finished(s, i);
        return;
    }
    s.ops[i].wait_epoch = s.op_wait_epoch;
    s.ops[i].result = 0;
    s.ops[i].state = OPS_WAIT;
}

/// FS_WRITE / FS_WRITE_ASYNC: write `arg_len` bytes at the writable FD's
/// current offset, allocating and linking clusters when a normal append
/// grows the file. Answers the bytes taken, which may be short; `EAGAIN`
/// only when none were.
///
/// Bytes accumulate in the FD's scratch and are submitted to the block
/// source when a write leaves the run, at a fence, or after close — never
/// waited for here. A cluster boundary allocates through a transaction over
/// the cached FAT, so a FAT sector still on its way ends the call short with
/// nothing of that cluster taken. A write starting mid-sector into a sector
/// the scratch does not hold starts that sector's read and ends the call
/// short; the next call finds it. The directory-entry size is written at
/// `FSYNC` / the async fence / after close.
unsafe fn fs_op_write(s: &mut Fat32State, handle: i32, arg: *const u8, arg_len: usize) -> i32 {
    if arg.is_null() {
        return E_INVAL;
    }
    if arg_len == 0 {
        return 0;
    }
    let slot = handle as usize;
    if slot >= MAX_OPEN_FILES || s.open_files[slot].in_use != OF_OPEN {
        return E_INVAL;
    }
    if s.open_files[slot].writable == 0 {
        return E_INVAL;
    }
    if s.open_files[slot].op_busy != 0 {
        return E_AGAIN;
    }
    let err = s.open_files[slot].io_err;
    if err != 0 {
        s.open_files[slot].io_err = 0;
        return fs_rc_errno(err);
    }
    s.io_rc = 0;
    let bps = s.bytes_per_sector as u32;
    let spc = s.sectors_per_cluster as u32;
    if bps == 0 || spc == 0 {
        return E_AGAIN;
    }
    let cpb = bps * spc; // bytes per cluster

    let total = arg_len;
    let mut done = 0usize;
    // What stopped the loop short: 0 for nothing, else the errno a call
    // that moved no bytes answers.
    let mut stop = 0i32;
    while done < total {
        fs_scratch_settle(s, slot);
        let pos = s.open_files[slot].offset;
        // Fixed-capacity overrun aborts FIRST — before the submit and the
        // cluster-cursor work below — so an ENOSPC return leaves the FD
        // exactly as this iteration found it.
        if s.open_files[slot].fixed_capacity != 0 {
            let n = core::cmp::min(bps as usize - (pos % bps) as usize, total - done);
            if pos.saturating_add(n as u32) > s.open_files[slot].size {
                stop = -28; // ENOSPC within fixed capacity
                break;
            }
        }
        // The scratch is the source's while a request holds it.
        if s.open_files[slot].scratch_io != SIO_IDLE {
            stop = E_AGAIN;
            break;
        }
        // Submit the cached run BEFORE any cluster-cursor advancement below,
        // and only when this iteration's write leaves it (a cluster boundary
        // always starts a new sector; mid-cluster the target sector is
        // computable without advancing). Ordering matters: the submit can
        // answer EAGAIN (the queue is full), and the next call re-enters this
        // iteration from the top — if the cursor had already advanced (or a
        // cluster had been linked), it would advance the chain a second time.
        if s.open_files[slot].scratch_dirty != 0 {
            let leaving = if pos.is_multiple_of(cpb) {
                true
            } else {
                let cur = s.open_files[slot].current_cluster;
                let sec = cluster_to_sector(s, cur) + (pos / bps) % spc;
                !scratch_accepts(&s.open_files[slot], cur, sec)
            };
            if leaving {
                let wr = fs_data_submit(s, slot);
                if wr != 0 {
                    // EAGAIN is backpressure, not a failure: the bytes
                    // taken so far are answered and the caller writes the
                    // rest later.
                    stop = if wr == E_AGAIN { E_AGAIN } else { -5 };
                    break;
                }
                fs_scratch_settle(s, slot);
                if s.open_files[slot].scratch_io != SIO_IDLE {
                    // The source borrows the buffer until the run lands.
                    stop = E_AGAIN;
                    break;
                }
            }
        }
        // At a cluster boundary, select or allocate the cluster containing
        // byte `pos` — one transaction over the cached FAT.
        if pos.is_multiple_of(cpb) {
            let rc = fs_tx(s, |s| {
                tx_save_file(s, slot);
                fs_write_boundary(s, slot, pos)
            });
            if rc != 0 {
                stop = rc;
                break;
            }
        }
        let cur = s.open_files[slot].current_cluster;
        let sec_in_clu = (pos / bps) % spc;
        let sector = cluster_to_sector(s, cur) + sec_in_clu;
        let off_in_sec = (pos % bps) as usize;
        let n = core::cmp::min(bps as usize - off_in_sec, total - done);
        // Read-modify-write only when starting mid-sector (preserve the
        // existing prefix) in a sector the scratch does not mirror. A fresh
        // sector written from offset 0 needs no read — bytes past `size`
        // are never read (size-capped) — and neither does the common append
        // case where the length prefix and the payload share the sector the
        // previous write left in the scratch.
        if off_in_sec != 0 && !scratch_mirrors(&s.open_files[slot], sector) {
            if s.open_files[slot].scratch_dirty != 0 {
                let wr = fs_data_submit(s, slot);
                if wr != 0 {
                    stop = if wr == E_AGAIN { E_AGAIN } else { -5 };
                    break;
                }
                fs_scratch_settle(s, slot);
                if s.open_files[slot].scratch_io != SIO_IDLE {
                    stop = E_AGAIN;
                    break;
                }
            }
            // The prefix comes from the sector cache; a sector not cached
            // yet ends the call short with its read under way.
            let own = s.open_files[slot].scratch_seq;
            if own != 0 && s.blk.write_state(own) == 1 {
                stop = E_AGAIN;
                break;
            }
            match fs_cache_get(s, sector) {
                Ok(i) => {
                    let src = s.cache_data[i].as_ptr();
                    let of = &mut s.open_files[slot];
                    core::ptr::copy_nonoverlapping(src, of.scratch_block.as_mut_ptr(), BLOCK_SIZE);
                    of.scratch_lba = sector;
                    of.scratch_span = 1;
                    of.scratch_cluster = cur;
                    of.scratch_compact = 0;
                    continue;
                }
                Err(E_AGAIN) => {
                    stop = E_AGAIN;
                    break;
                }
                Err(rc) => {
                    stop = fs_rc_errno(rc);
                    break;
                }
            }
        }
        let (idx, _mirrored) = scratch_place(&mut s.open_files[slot], cur, sector);
        let sec_off = idx * BLOCK_SIZE;
        core::ptr::copy_nonoverlapping(
            arg.add(done),
            s.open_files[slot]
                .scratch_block
                .as_mut_ptr()
                .add(sec_off + off_in_sec),
            n,
        );
        // DEFER the device write: the scratch now mirrors `sector` with the
        // appended bytes; the run is submitted when a write leaves it, at a
        // fence, or after close — collapsing repeated same-sector appends
        // into one write, and a filled cluster's sectors into one submit.
        let of = &mut s.open_files[slot];
        of.scratch_dirty = 1;
        let new_offset = pos + n as u32;
        of.offset = new_offset;
        if new_offset > of.size {
            of.size = new_offset;
            of.dirty = 1;
        }
        // Fresh bytes are volatile until the next fence.
        of.durable = 0;
        of.write_gen = of.write_gen.wrapping_add(1);
        // The cursor is now genuinely lagging again: bytes have been written
        // into `current_cluster`, so the next boundary is a real crossing
        // that must advance. Clearing here also covers a seek that landed
        // mid-cluster (the boundary branch above was never entered).
        of.cursor_positioned = 0;
        done += n;
    }
    if done > 0 {
        return done as i32;
    }
    if stop != 0 {
        return stop;
    }
    0
}

/// The cluster-boundary step of a write at `pos`: select or allocate the
/// cluster holding that byte. Runs inside a transaction.
unsafe fn fs_write_boundary(s: &mut Fat32State, slot: usize, pos: u32) -> i32 {
    let start = s.open_files[slot].start_cluster;
    if s.open_files[slot].cursor_positioned != 0 {
        // A prior FS_SEEK already walked `current_cluster` to the cluster
        // holding `pos`; do not advance a second time. Consumed by the data
        // copy so the *next* boundary (a real crossing) advances again.
    } else if pos == 0 && start >= 2 {
        // PREALLOCATE linked the initial extent. Byte zero uses its first
        // cluster; advancement starts at the next boundary.
    } else if s.open_files[slot].fixed_capacity != 0 {
        let cur = s.open_files[slot].current_cluster;
        let next = if s.open_files[slot].fixed_contiguous != 0 {
            cur.saturating_add(1)
        } else {
            match fs_fat_next(s, cur) {
                Ok(v) => v,
                Err(rc) => return rc,
            }
        };
        if !(2..FAT32_EOC).contains(&next) {
            return fs_io_errno(s, -28);
        }
        s.open_files[slot].current_cluster = next;
    } else {
        let b = fs_begin_mutation(s);
        if b != 0 {
            return b;
        }
        if start == 0 {
            let nc = fs_alloc_one(s, 0);
            if nc < 2 {
                return fs_alloc_errno(s);
            }
            s.open_files[slot].start_cluster = nc;
            s.open_files[slot].current_cluster = nc;
        } else {
            // One cluster per boundary: the chain never describes more
            // capacity than the size field accounts for. See `fs_alloc_one`.
            let cur = s.open_files[slot].current_cluster;
            let nc = fs_alloc_one(s, cur);
            if nc < 2 {
                return fs_alloc_errno(s);
            }
            s.open_files[slot].current_cluster = nc;
        }
        s.open_files[slot].dirty = 1;
    }
    0
}

/// True when the scratch mirrors `sector` (holds its current bytes).
fn scratch_mirrors(of: &OpenFile, sector: u32) -> bool {
    of.scratch_io != SIO_READ
        && of.scratch_span > 0
        && sector >= of.scratch_lba
        && sector - of.scratch_lba < u32::from(of.scratch_span)
}

/// True when the mirrored run already covers `sector`, or can grow to cover
/// it. A run grows only within `cluster`, whose sectors are physically
/// contiguous, so the whole run stays one device range.
fn scratch_accepts(of: &OpenFile, cluster: u32, sector: u32) -> bool {
    let span = of.scratch_span as u32;
    if span == 0 {
        return false;
    }
    if sector >= of.scratch_lba && sector < of.scratch_lba + span {
        return true;
    }
    of.scratch_cluster == cluster
        && sector == of.scratch_lba + span
        && (span as usize) < SCRATCH_SECTORS
}

/// Position `sector` within the FD's scratch, returning its sector index and
/// whether `scratch_block` already mirrors it (in which case the caller skips
/// the read-modify-write fetch). Covers three cases: the sector is inside the
/// mirrored run; it extends the run by one; or it starts a fresh run — which
/// is only reached once the previous run has been flushed, since an
/// unflushable target is exactly what `scratch_accepts` rejects.
fn scratch_place(of: &mut OpenFile, cluster: u32, sector: u32) -> (usize, bool) {
    let span = of.scratch_span as u32;
    if span > 0 && sector >= of.scratch_lba && sector < of.scratch_lba + span {
        // A read-established mirror carries no cluster; adopt this one so
        // subsequent appends can extend the run.
        of.scratch_cluster = cluster;
        return ((sector - of.scratch_lba) as usize, true);
    }
    if of.scratch_dirty != 0 && scratch_accepts(of, cluster, sector) {
        of.scratch_span = (span + 1) as u8;
        return (span as usize, false);
    }
    of.scratch_lba = sector;
    of.scratch_span = 1;
    of.scratch_cluster = cluster;
    (0, false)
}

/// Collapse a just-flushed run to its final sector, which is the only one a
/// sequential append can still land in. The tail moves to index 0 and stays
/// mirrored, so the read-modify-write skip survives the flush while the next
/// run rebuilds from there — without a later flush re-writing sectors the
/// device already holds.
unsafe fn scratch_retain_tail(of: &mut OpenFile) {
    let span = of.scratch_span as usize;
    if span <= 1 {
        return;
    }
    let base = of.scratch_block.as_mut_ptr();
    core::ptr::copy(base.add((span - 1) * BLOCK_SIZE), base, BLOCK_SIZE);
    of.scratch_lba += (span - 1) as u32;
    of.scratch_span = 1;
}

/// FS_FSYNC: make this FD's bytes and the size metadata that covers them
/// durable. A no-op on a read-only FD.
///
/// Taken on the first ask, decided on a later one. The ask submits the
/// unwritten tail and commits, in one transaction, a durable boundary (the
/// data and every FAT link it needs), the directory entry carrying the size
/// and first cluster, and a durable boundary behind it — data reaches media
/// before the metadata that describes it, so a crash can never expose a size
/// pointing past durable bytes. It answers `EINPROGRESS`; a re-ask answers 0
/// once the last boundary is on the device (or `EIO` if a write failed).
///
/// The decision belongs to the bytes it covered: a re-ask after more writes
/// is a new `FSYNC`, taken afresh.
unsafe fn fs_op_fsync(s: &mut Fat32State, handle: i32) -> i32 {
    let slot = handle as usize;
    if slot >= MAX_OPEN_FILES || s.open_files[slot].in_use != OF_OPEN {
        return E_INVAL;
    }
    if s.open_files[slot].writable == 0 {
        return 0;
    }
    let err = s.open_files[slot].io_err;
    if err != 0 {
        s.open_files[slot].io_err = 0;
        s.open_files[slot].fsync_epoch = 0;
        return fs_rc_errno(err);
    }
    {
        let of = &s.open_files[slot];
        if of.fsync_epoch != 0 && of.fsync_wgen == of.write_gen && of.scratch_dirty == 0 {
            if s.wb_err != 0 {
                s.open_files[slot].fsync_epoch = 0;
                return -5; // EIO
            }
            if fs_durable(s, of.fsync_epoch) {
                let (size, start) = (of.fsync_size, of.fsync_start);
                let of = &mut s.open_files[slot];
                of.fsync_epoch = 0;
                if of.size == size {
                    of.durable = 1;
                }
                fs_note_dir_durable(s, slot, size, start);
                return 0;
            }
            return E_INPROGRESS;
        }
        if of.durable != 0 && of.scratch_dirty == 0 && of.dirty == 0 {
            return 0;
        }
    }
    if s.wb_err != 0 {
        return -5; // EIO
    }
    let sr = fs_data_submit(s, slot);
    if sr == E_AGAIN {
        return E_AGAIN;
    }
    if sr != 0 {
        return -5; // EIO
    }
    let rc = fs_tx(s, |s| {
        let b = fs_begin_mutation(s);
        if b != 0 {
            return b;
        }
        if fs_barrier(s, true) == 0 {
            return E_AGAIN;
        }
        if s.open_files[slot].dirty != 0 {
            tx_save_file(s, slot);
            let rc = fs_writeback_dir_entry(s, slot);
            if rc != 0 {
                return rc;
            }
        }
        fs_durable_point(s)
    });
    if rc != 0 {
        return rc;
    }
    let e = s.op_wait_epoch;
    let of = &mut s.open_files[slot];
    of.fsync_epoch = e;
    of.fsync_wgen = of.write_gen;
    of.fsync_size = of.size;
    of.fsync_start = of.start_cluster;
    E_INPROGRESS
}

/// FS_FSYNC_NAME: make the directory entry naming `path` durable.
///
/// Every op that mints or removes a name — `OPEN_CREATE`, `MKDIR`,
/// `UNLINK`, `RMDIR` — has written its directory sector into the cache by
/// the time it answers. What stands between it and stable storage is the
/// write-back and the device's volatile cache, so this op resolves the
/// parent (to reject a path that never named anything here) and commits a
/// durable boundary behind everything written so far. Decided — 0 — once
/// that is on the device.
///
/// The entry may be present or absent — a removal is as much a name
/// publication as a creation — so the entry itself is deliberately not
/// required to exist. What must resolve is the parent directory.
unsafe fn fs_op_fsync_name(s: &mut Fat32State, arg: *const u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len == 0 {
        return E_INVAL;
    }
    if s.init_phase != Fat32InitPhase::Done || s.root_cluster < 2 {
        return E_AGAIN;
    }
    s.io_rc = 0;
    let path = core::slice::from_raw_parts(arg, arg_len);
    if fs_split_parent(s, path).is_none() {
        return fs_io_errno(s, -2); // ENOENT
    }
    fs_durable_point(s)
}

/// Marker of a live rename-intent record (`"FRN1"` little-endian).
const RENAME_INTENT_MAGIC: u32 = 0x3146_524E;
/// `state` value of a record whose rename is in flight.
const RENAME_INTENT_ARMED: u32 = 1;
/// Sectors the FAT32 format itself defines inside the reserved region: the
/// boot sector (0), FSINFO (1), the third boot sector (2), and the backup
/// copies at 6, 7 and 8. The intent record takes the region's LAST sector,
/// which no FAT32 reader interprets, so a volume needs at least ten
/// reserved sectors to carry one. Below that, `RENAME` is unavailable and
/// its capability bit stays clear.
const RENAME_INTENT_MIN_RESERVED: u16 = 10;

// Field offsets inside the 512-byte intent record.
const RI_MAGIC: usize = 0;
const RI_STATE: usize = 4;
const RI_SRC_LBA: usize = 8;
const RI_DST_LBA: usize = 12;
const RI_SRC_OFF: usize = 16;
const RI_DST_OFF: usize = 18;
/// The exact 32 bytes that must appear at the destination.
const RI_ENT: usize = 20;
/// The exact 32 bytes the source entry held when the record was armed.
const RI_SRC_ENT: usize = 52;
/// The exact 32 bytes the destination slot held when the record was armed.
const RI_DST_PREV: usize = 84;
/// Volume serial number of the volume the record was armed on.
///
/// Without it, "is this record mine?" is answered by a checksum and a
/// range check on two LBAs — both of which a record left by an earlier
/// filesystem on the same device, with a similar geometry, can satisfy.
/// Replaying it would then write 32 bytes of a stranger's directory entry
/// into a live directory at an offset that happens to be in range. The
/// serial is written by `mkfs` and changes with every reformat, so a record
/// that does not carry this volume's is not about this volume.
const RI_VOL_ID: usize = 116;
const RI_CHECK: usize = 120;

/// Volume-relative sector of this volume's rename-intent record, or `None` when the
/// reserved region is too small to hold one.
fn fs_rename_intent_lba(s: &Fat32State) -> Option<u32> {
    if s.reserved_sectors < RENAME_INTENT_MIN_RESERVED {
        return None;
    }
    Some(s.reserved_sectors as u32 - 1)
}

/// FNV-1a over the record's fixed header. Rejects a torn or foreign sector
/// before any of its LBAs are used to address a directory write.
fn fs_intent_check(rec: &[u8; BLOCK_SIZE]) -> u32 {
    let mut h: u32 = 0x811C_9DC5;
    let mut i = 0usize;
    while i < RI_CHECK {
        h ^= rec[i] as u32;
        h = h.wrapping_mul(0x0100_0193);
        i += 1;
    }
    h
}

/// True when the 32 bytes at `off` in `block_buf` equal `rec[at..at + 32]`.
fn fs_entry_matches(buf: &[u8; BLOCK_SIZE], off: usize, rec: &[u8; BLOCK_SIZE], at: usize) -> bool {
    let mut i = 0usize;
    while i < DIR_ENTRY_SIZE {
        if buf[off + i] != rec[at + i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Return the intent record to its idle state, behind a durable boundary.
unsafe fn fs_rename_disarm(s: &mut Fat32State, intent_lba: u32) -> i32 {
    let idle = [0u8; BLOCK_SIZE];
    let rc = fs_write_sector_from(s, intent_lba, 1, idle.as_ptr());
    if rc != 0 {
        return rc;
    }
    fs_durable_point(s)
}

/// FS_RENAME: move an entry to another name, publishing the new name
/// durably.
///
/// A FAT32 directory entry is 32 bytes inside a 512-byte sector, so moving
/// a name means writing the destination sector and clearing the source
/// sector. One sector write is failure-atomic; two are not.
///
/// "One sector write is failure-atomic" is the load-bearing assumption
/// here and in every other single-sector metadata write this provider
/// makes, so it is not left as an assertion: the NVMe driver reads
/// AWUPF (Atomic Write Unit Power Fail, Identify Controller bytes
/// 42..43) and reports it on its acceptance line as `AWUPF=N` in
/// logical blocks. `AWUPF=1` is the guarantee this reasoning needs; a
/// device reporting it is a device on which a single-sector write
/// cannot be observed half-applied. Consumers building recovery on top
/// of this provider — two-slot Raft metadata, two-slot snapshot
/// pointers — inherit the same dependency, which is why the number is
/// visible rather than folded into a comment. When both
/// entries share a sector the whole mutation IS one write and needs
/// nothing else. When they do not, the ordering below makes every
/// intermediate state distinguishable, and `fs_rename_recover` — which
/// runs ahead of the first operation after any mount — resolves it:
///
///   1. arm — write the intent record (both LBAs/offsets and the exact
///      expected images of the source entry, the destination's previous
///      contents, and the entry to publish), flush;
///   2. publish — write the destination entry, flush;
///   3. retire — mark the source entry deleted (`0xE5`), flush;
///   4. disarm — return the intent record to idle, flush.
///
/// What a reader finds after an interruption:
///
///   - before 1, or after 1: the old name, alone. The destination slot
///     still holds its previous bytes, so the replay rolls back by simply
///     disarming.
///   - after 2: both names, naming one cluster chain. The replay reads the
///     armed record, sees the destination carrying the published image and
///     the source carrying its armed image, and completes step 3 — the
///     destination is authoritative.
///   - after 3: the new name, alone. The replay sees the source already
///     `0xE5` and only disarms.
///   - after 4: the new name, alone, with nothing outstanding.
///
/// So no interruption leaves the bytes reachable by no name, and no
/// interruption leaves the outcome ambiguous to the next mount. The "both
/// names" window between steps 2 and 3 is visible to a foreign FAT32
/// reader that mounts the volume before this provider replays the record;
/// such a reader sees two entries sharing a chain, and a repair tool run
/// at that moment may act on it.
///
/// The record is addressed only after its own checksum verifies, and each
/// phase is applied only when the on-media bytes still equal the image the
/// record recorded, so a directory mutated by anything else between the
/// interruption and the replay is left untouched.
unsafe fn fs_op_rename(s: &mut Fat32State, arg: *const u8, arg_len: usize) -> i32 {
    if s.init_phase != Fat32InitPhase::Done || s.root_cluster < 2 {
        return E_AGAIN;
    }
    // Fail closed BEFORE anything else, including argument validation. The
    // capability bit is derived from this volume's reserved region, and a
    // caller that asked for a rename on a volume that cannot carry the intent
    // record must learn that the operation is unavailable — not that its
    // source path happens not to exist, which is what path resolution would
    // report first and which reads as a transient, retryable condition.
    if fs_rename_intent_lba(s).is_none() {
        return E_NOSYS;
    }
    if arg.is_null() || arg_len < 4 {
        return E_INVAL;
    }
    let a = core::slice::from_raw_parts(arg, arg_len);
    let src_len = u16::from_le_bytes([a[0], a[1]]) as usize;
    if src_len == 0 || arg_len < 4 + src_len {
        return E_INVAL;
    }
    let dst_len = u16::from_le_bytes([a[2 + src_len], a[3 + src_len]]) as usize;
    if dst_len == 0 || arg_len < 4 + src_len + dst_len {
        return E_INVAL;
    }
    let src_path = &a[2..2 + src_len];
    let dst_path = &a[4 + src_len..4 + src_len + dst_len];

    s.io_rc = 0;
    let (src_parent, src_name) = match fs_split_parent(s, src_path) {
        Some(p) => p,
        None => return fs_io_errno(s, -2), // ENOENT
    };
    let (dst_parent, dst_name) = match fs_split_parent(s, dst_path) {
        Some(p) => p,
        None => return fs_io_errno(s, -2), // ENOENT
    };
    let src = match fs_name_walk(s, src_parent, &src_name, 1) {
        DirScan::Found(l) => l,
        DirScan::Pending => return E_AGAIN,
        _ => return fs_io_errno(s, -2), // ENOENT
    };
    if src.is_dir {
        return -21; // EISDIR — directory rename is not in this surface
    }
    // A destination that needs a long name needs its companion slots
    // reserved with the entry's, contiguously and in front of it.
    let mut dst_name = dst_name;
    let dst_need = dst_name.lfn_entries() + 1;
    let mut dst = match fs_name_walk(s, dst_parent, &dst_name, dst_need) {
        DirScan::Found(l) => l,
        DirScan::Free(l) => l,
        DirScan::Pending => return E_AGAIN,
        DirScan::Full => match fs_dir_grow(s, dst_parent) {
            Some(l) => l,
            None => return fs_alloc_errno(s),
        },
        DirScan::Io => return fs_io_errno(s, -5), // EIO
    };
    if dst.exists && dst.is_dir {
        return -21; // EISDIR
    }
    if dst.lba == src.lba && dst.off == src.off {
        return 0; // the same entry under the same 8.3 name
    }
    // A live writable handle records its entry's location; moving the entry
    // under it would leave the handle publishing size metadata into a slot
    // that no longer names its file. Refuse, exactly as `UNLINK` does.
    let mut k = 0usize;
    while k < MAX_OPEN_FILES {
        let of = &s.open_files[k];
        // Only a writable handle records where its entry lives; a read
        // handle leaves `dir_lba` at 0 and must not be matched by it.
        let holds_entry = of.writable != 0;
        let names_src = holds_entry && of.dir_lba == src.lba && of.dir_off == src.off;
        let names_dst = holds_entry && dst.exists && of.dir_lba == dst.lba && of.dir_off == dst.off;
        if of.in_use != OF_FREE
            && (names_src
                || names_dst
                || (dst.exists && dst.start_cluster >= 2 && of.start_cluster == dst.start_cluster))
        {
            return if of.in_use == OF_DETACHED {
                E_AGAIN
            } else {
                -16
            }; // EBUSY
        }
        k += 1;
    }

    // A new long-named destination gets its companions written BEFORE the
    // intent record is armed, and the intent then describes only the short
    // entry's slot. That ordering is what keeps the recovery argument the
    // one this module already makes: the publish step stays a single
    // failure-atomic sector write, and a crash before it leaves companions
    // naming nothing — which every reader ignores and the next claim of the
    // slot retires.
    if dst.exists && dst_name.long_len > 0 {
        // Overwriting an existing long name: keep the alias its companions
        // already check against. Minting a fresh one would leave them naming
        // a checksum that no longer matches the entry behind them, which
        // `fsck` reports and declines to repair.
        match fs_dirent_short_name(s, &dst) {
            Some(n) => dst_name.short = n,
            None => return fs_io_errno(s, -5),
        }
    }
    if !dst.exists && dst_name.long_len > 0 {
        let arc = fs_assign_short_alias(s, dst_parent, &mut dst_name);
        if arc != 0 {
            return arc;
        }
        let lrc = fs_lfn_retire(s, &dst);
        if lrc != 0 {
            return fs_rc_errno(lrc);
        }
        let run_start = dst;
        let companions = dst_name.lfn_entries();
        let wrc = fs_lfn_write(s, &run_start, &dst_name, companions);
        if wrc != 0 {
            return fs_rc_errno(wrc);
        }
        match fs_dirent_advance(s, dst_parent, run_start.lba, run_start.off, companions) {
            Some((lba, off)) => {
                dst.lba = lba;
                dst.off = off;
                dst.lfn_lba = run_start.lba;
                dst.lfn_off = run_start.off;
                dst.lfn_run = companions;
            }
            None => return fs_io_errno(s, -5), // EIO
        }
        if dst.lba == src.lba && dst.off == src.off {
            return 0;
        }
    }

    // The entry to publish: the source's own record — chain head, size,
    // attributes and timestamps — under the destination's 8.3 name.
    let rc = fs_read_blockbuf(s, src.lba);
    if rc != 0 {
        return fs_rc_errno(rc);
    }
    let mut src_ent = [0u8; DIR_ENTRY_SIZE];
    let mut i = 0usize;
    while i < DIR_ENTRY_SIZE {
        src_ent[i] = s.block_buf[src.off as usize + i];
        i += 1;
    }
    let mut ent = src_ent;
    let mut n = 0usize;
    while n < 11 {
        ent[n] = dst_name.short[n];
        n += 1;
    }

    fs_dir_changed(s, src.parent);
    fs_dir_changed(s, dst.parent);
    if src.lba == dst.lba {
        // Both entries live in the one sector, so publication and
        // retirement are a single failure-atomic write. No intent record
        // can add anything a reader could observe.
        let mut i = 0usize;
        while i < DIR_ENTRY_SIZE {
            s.block_buf[dst.off as usize + i] = ent[i];
            i += 1;
        }
        s.block_buf[src.off as usize] = 0xE5;
        let wrc = fs_write_staged(s, src.lba);
        if wrc != 0 {
            return fs_rc_errno(wrc);
        }
        // The source's long-name companions name an entry that is now gone.
        // Leaving them is not tidying debt: `fsck` reports an orphaned long
        // file name, and the next entry minted behind them inherits the old
        // name.
        let lrc = fs_lfn_retire(s, &src);
        if lrc != 0 {
            return fs_rc_errno(lrc);
        }
        let frc = fs_durable_point(s);
        if frc != 0 {
            return fs_rc_errno(frc);
        }
        let e = s.op_wait_epoch;
        fs_rename_reclaim_replaced(s, &src, &dst);
        s.op_wait_epoch = e;
        return 0;
    }

    let intent_lba = match fs_rename_intent_lba(s) {
        Some(l) => l,
        None => return -38, // ENOSYS — matches the cleared capability bit
    };

    let rc = fs_read_blockbuf(s, dst.lba);
    if rc != 0 {
        return fs_rc_errno(rc);
    }
    let mut rec = [0u8; BLOCK_SIZE];
    let mut i = 0usize;
    while i < DIR_ENTRY_SIZE {
        rec[RI_DST_PREV + i] = s.block_buf[dst.off as usize + i];
        rec[RI_ENT + i] = ent[i];
        rec[RI_SRC_ENT + i] = src_ent[i];
        i += 1;
    }
    write_u32_le(&mut rec, RI_VOL_ID, s.volume_id);
    write_u32_le(&mut rec, RI_MAGIC, RENAME_INTENT_MAGIC);
    write_u32_le(&mut rec, RI_STATE, RENAME_INTENT_ARMED);
    write_u32_le(&mut rec, RI_SRC_LBA, src.lba);
    write_u32_le(&mut rec, RI_DST_LBA, dst.lba);
    rec[RI_SRC_OFF] = src.off as u8;
    rec[RI_SRC_OFF + 1] = (src.off >> 8) as u8;
    rec[RI_DST_OFF] = dst.off as u8;
    rec[RI_DST_OFF + 1] = (dst.off >> 8) as u8;
    let check = fs_intent_check(&rec);
    write_u32_le(&mut rec, RI_CHECK, check);

    // The four phases are committed together, against the cache, and reach
    // the device in order: each ends in a durable boundary, and the engine
    // starts a phase's writes only once the one before it is on media. A
    // failure inside this call aborts the transaction with nothing written;
    // an interruption on the device lands between two phases, which is
    // exactly what the recovery below is built for.
    //
    // Phase 1 — arm. Nothing in either directory has changed yet.
    let wrc = fs_write_sector_from(s, intent_lba, 1, rec.as_ptr());
    if wrc != 0 {
        return fs_rc_errno(wrc);
    }
    let frc = fs_durable_point(s);
    if frc != 0 {
        return fs_rc_errno(frc);
    }

    // Phase 2 — publish the destination.
    let rc = fs_read_blockbuf(s, dst.lba);
    if rc != 0 {
        return fs_rc_errno(rc);
    }
    let mut i = 0usize;
    while i < DIR_ENTRY_SIZE {
        s.block_buf[dst.off as usize + i] = ent[i];
        i += 1;
    }
    let wrc = fs_write_staged(s, dst.lba);
    if wrc != 0 {
        return fs_rc_errno(wrc);
    }
    let frc = fs_durable_point(s);
    if frc != 0 {
        return fs_rc_errno(frc);
    }

    // Phase 3 — retire the source. From here the destination is
    // authoritative; a failure leaves the armed record to complete it.
    let rc = fs_read_blockbuf(s, src.lba);
    if rc != 0 {
        return fs_rc_errno(rc);
    }
    s.block_buf[src.off as usize] = 0xE5;
    let wrc = fs_write_staged(s, src.lba);
    if wrc != 0 {
        return fs_rc_errno(wrc);
    }
    // The source's long-name companions name an entry that is now gone.
    // Retired after the short entry, for the same reason `fs_dirent_retire`
    // orders them that way: the short entry is what makes the name stop
    // resolving, and stranded companions resolve to nothing.
    let lrc = fs_lfn_retire(s, &src);
    if lrc != 0 {
        return fs_rc_errno(lrc);
    }
    let frc = fs_durable_point(s);
    if frc != 0 {
        return fs_rc_errno(frc);
    }

    // Phase 4 — disarm. Both names are settled; the record has no work
    // left to describe. The call is decided when this boundary is durable.
    let drc = fs_rename_disarm(s, intent_lba);
    if drc != 0 {
        return fs_rc_errno(drc);
    }
    let e = s.op_wait_epoch;
    fs_rename_reclaim_replaced(s, &src, &dst);
    s.op_wait_epoch = e;
    0
}

/// Queue the chain a replaced destination entry used to name, once that
/// entry is gone from the directory. Ordering matches `UNLINK`: the name
/// is retired first, so an interruption before the drain leaks clusters
/// rather than leaving a live entry over freed ones.
fn fs_rename_reclaim_replaced(s: &mut Fat32State, src: &DirentLoc, dst: &DirentLoc) {
    if !dst.exists || dst.start_cluster < 2 || dst.start_cluster == src.start_cluster {
        return;
    }
    fs_queue_free_chain(s, dst.start_cluster);
}

/// Replay an interrupted rename before this mount's first operation.
///
/// Reads the intent record and, when it is armed and its checksum
/// verifies, classifies the directory by comparing the on-media entries
/// against the images the record captured. Only two states are actionable
/// — destination published with the source still live (complete the
/// retirement), and destination untouched (roll back by disarming). Any
/// other image means the directory moved under the record; the replay then
/// touches no entry.
///
/// Runs as a transaction like any operation: a sector still on its way
/// answers `EAGAIN` (the caller tries again), and what the replay writes
/// reaches the device behind durable boundaries in the order below. The
/// ops that follow it see the replayed cache at once.
unsafe fn fs_rename_recover(s: &mut Fat32State) -> i32 {
    let intent_lba = match fs_rename_intent_lba(s) {
        Some(l) => l,
        None => return 0,
    };
    // The intent record names sectors, not directories: drop every walk.
    s.dir_cursor.dir_cluster = 0;
    s.dir_cursor_pool = [DirCursor::empty(); DIR_CURSOR_POOL];
    s.dir_cache = [DirCacheEntry::EMPTY; DIR_CACHE];
    let rc = fs_read_blockbuf(s, intent_lba);
    if rc == E_AGAIN {
        return E_AGAIN;
    }
    if rc != 0 {
        return 0;
    }
    let rec: [u8; BLOCK_SIZE] = s.block_buf;
    if read_u32_le(&rec, RI_MAGIC) != RENAME_INTENT_MAGIC
        || read_u32_le(&rec, RI_STATE) != RENAME_INTENT_ARMED
        || read_u32_le(&rec, RI_VOL_ID) != s.volume_id
        || read_u32_le(&rec, RI_CHECK) != fs_intent_check(&rec)
    {
        return 0;
    }
    let src_lba = read_u32_le(&rec, RI_SRC_LBA);
    let dst_lba = read_u32_le(&rec, RI_DST_LBA);
    let src_off = u16::from_le_bytes([rec[RI_SRC_OFF], rec[RI_SRC_OFF + 1]]) as usize;
    let dst_off = u16::from_le_bytes([rec[RI_DST_OFF], rec[RI_DST_OFF + 1]]) as usize;
    if src_off + DIR_ENTRY_SIZE > BLOCK_SIZE || dst_off + DIR_ENTRY_SIZE > BLOCK_SIZE {
        return 0;
    }
    // Both LBAs must name directory sectors on THIS volume. A record
    // carried over from another volume checksums correctly and would
    // otherwise aim a write at whatever those numbers mean here.
    if src_lba < s.data_start_sector || dst_lba < s.data_start_sector {
        return 0;
    }
    let rc = fs_read_blockbuf(s, dst_lba);
    if rc != 0 {
        return if rc == E_AGAIN { E_AGAIN } else { 0 };
    }
    let published = fs_entry_matches(&s.block_buf, dst_off, &rec, RI_ENT);
    let untouched = fs_entry_matches(&s.block_buf, dst_off, &rec, RI_DST_PREV);
    if published {
        let rc = fs_read_blockbuf(s, src_lba);
        if rc != 0 {
            return if rc == E_AGAIN { E_AGAIN } else { 0 };
        }
        if fs_entry_matches(&s.block_buf, src_off, &rec, RI_SRC_ENT) {
            s.block_buf[src_off] = 0xE5;
            let rc = fs_write_staged(s, src_lba);
            if rc != 0 {
                return if rc == E_AGAIN { E_AGAIN } else { 0 };
            }
            let rc = fs_durable_point(s);
            if rc != 0 {
                return rc;
            }
        } else if s.block_buf[src_off] != 0xE5 {
            return 0; // neither armed image nor retired — leave it alone
        }
    } else if !untouched {
        return 0;
    }
    let rc = fs_rename_disarm(s, intent_lba);
    if rc == E_AGAIN {
        return E_AGAIN;
    }
    0
}

/// FSYNC_SUBMIT: open a non-blocking durability fence over this FD's
/// writes, returning its ticket (`u64` LE) in `arg` (≥8 bytes). Submits the
/// pending run so the fence covers it, closes a durable boundary behind
/// everything written so far — the data and every FAT link it needs — and
/// snapshots the file's size and first cluster.
///
/// The snapshot is what makes the ticket answerable for a fixed extent.
/// A caller may submit further writes, growing the file, before it polls
/// this ticket; the directory entry published on completion carries the
/// size recorded here, never the FD's later size, because only the bytes
/// below this frontier are covered by this ticket's boundary.
///
/// No device work is done or waited for here. `EAGAIN` — with nothing
/// consumed — when every fence slot is outstanding, the run cannot be
/// submitted yet, or the window of boundaries is full: real backpressure,
/// not a downgrade.
unsafe fn fs_op_fsync_submit(s: &mut Fat32State, handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    let slot = handle as usize;
    if slot >= MAX_OPEN_FILES || s.open_files[slot].in_use != OF_OPEN {
        return E_INVAL;
    }
    if arg.is_null() || arg_len < 8 {
        return E_INVAL;
    }
    if s.open_files[slot].writable == 0 {
        let mut i = 0usize;
        while i < 8 {
            *arg.add(i) = 0;
            i += 1;
        }
        return 0;
    }
    let mut idx = 0usize;
    while idx < MAX_FENCES && s.fences[idx].stage != 0 {
        idx += 1;
    }
    if idx >= MAX_FENCES {
        return E_AGAIN;
    }
    if s.epoch.wrapping_sub(s.wb_epoch) >= EPOCH_WINDOW as u32 - 1 {
        s.wb_kick = 1;
        return E_AGAIN;
    }
    let sr = fs_data_submit(s, slot);
    if sr == E_AGAIN {
        return E_AGAIN;
    }
    if sr != 0 {
        return -5; // EIO
    }
    let e = fs_barrier(s, true);
    if e == 0 {
        return E_AGAIN;
    }
    let generation = s.fences[idx].generation.wrapping_add(1);
    s.fences[idx] = FenceSlot {
        stage: FENCE_STAGE_DATA,
        file: slot as u8,
        generation,
        size: s.open_files[slot].size,
        start_cluster: s.open_files[slot].start_cluster,
        device_ticket: u64::from(e),
    };
    let tb = fence_ticket_encode(idx, generation).to_le_bytes();
    let mut i = 0usize;
    while i < 8 {
        *arg.add(i) = tb[i];
        i += 1;
    }
    0
}

/// FSYNC_POLL: non-blocking poll of a fence ticket (`u64` LE in `arg`).
/// Returns 0 = durable, 1 = pending, or a negative errno if a fenced write
/// failed or the ticket does not name a live fence on this FD.
///
/// ## What a 0 return means
///
/// Every byte written to this FD before the ticket's `FSYNC_SUBMIT`, and a
/// directory entry recording a size at least that frontier, are both on
/// non-volatile media. It is a LOWER bound: writes issued after the submit
/// may also have reached media, and a larger on-media size is a valid
/// result, not a failure.
///
/// ## Two stages
///
/// A ticket runs `FENCE_STAGE_DATA` then `FENCE_STAGE_META`. The data
/// stage waits for the durable boundary the submit closed. Only once that
/// is on the device does the metadata stage write the directory entry —
/// carrying the ticket's snapshotted size and first cluster — into the
/// cache, behind a second durable boundary. That second boundary is what
/// proves the entry itself is past the device's volatile cache, so the poll
/// never reports durable on the back of an unflushed metadata write.
///
/// A ticket whose snapshot is already covered by a durable directory entry
/// (the preallocated fixed-capacity file, whose size never changes) skips
/// the metadata stage entirely. The entry is only rewritten when a
/// ticket's frontier exceeds what has been written for this FD, so
/// polling tickets out of order can never move the on-media size
/// backwards.
unsafe fn fs_op_fsync_poll(s: &mut Fat32State, handle: i32, arg: *const u8, arg_len: usize) -> i32 {
    let slot = handle as usize;
    if slot >= MAX_OPEN_FILES || s.open_files[slot].in_use != OF_OPEN {
        return E_INVAL;
    }
    if arg.is_null() || arg_len < 8 {
        return E_INVAL;
    }
    let ticket = u64::from_le_bytes([
        *arg,
        *arg.add(1),
        *arg.add(2),
        *arg.add(3),
        *arg.add(4),
        *arg.add(5),
        *arg.add(6),
        *arg.add(7),
    ]);
    // Ticket 0 is the read-only FD's "nothing to fence" reply.
    if ticket == 0 {
        return 0;
    }
    let Some(idx) = fence_ticket_slot(s, ticket, slot) else {
        return E_INVAL;
    };
    if s.wb_err != 0 {
        s.fences[idx].stage = 0;
        return -5; // EIO
    }
    let wait = s.fences[idx].device_ticket as u32;
    if !fs_durable(s, wait) {
        return 1;
    }
    if s.fences[idx].stage == FENCE_STAGE_META {
        let covered = s.fences[idx].size;
        let head = s.fences[idx].start_cluster;
        s.fences[idx].stage = 0;
        fs_note_dir_durable(s, slot, covered, head);
        if s.open_files[slot].size == covered && s.open_files[slot].scratch_dirty == 0 {
            s.open_files[slot].durable = 1;
        }
        return 0;
    }
    // Data stage complete. Publish the snapshotted frontier if the
    // directory entry does not already carry it durably.
    let (size, start_cluster) = (s.fences[idx].size, s.fences[idx].start_cluster);
    if size <= s.open_files[slot].dir_durable_size
        && start_cluster == s.open_files[slot].dir_durable_start
    {
        s.fences[idx].stage = 0;
        if s.open_files[slot].size == size && s.open_files[slot].scratch_dirty == 0 {
            s.open_files[slot].durable = 1;
        }
        return 0;
    }
    let rc = fs_tx(s, |s| {
        let b = fs_begin_mutation(s);
        if b != 0 {
            return b;
        }
        if size > s.open_files[slot].dir_media_size {
            tx_save_file(s, slot);
            let (lba, off) = (s.open_files[slot].dir_lba, s.open_files[slot].dir_off);
            if lba == 0 {
                return E_INVAL;
            }
            let wr = fs_patch_dirent(s, lba, off, start_cluster, size);
            if wr != 0 {
                return wr;
            }
            let of = &mut s.open_files[slot];
            if of.size == size && of.start_cluster == start_cluster {
                of.dirty = 0;
            }
            if size > of.dir_media_size {
                of.dir_media_size = size;
            }
        }
        fs_durable_point(s)
    });
    if rc == E_AGAIN {
        // A sector on its way or a full window — retry on the next poll.
        // The ticket stays in the data stage with nothing consumed.
        return 1;
    }
    if rc != 0 {
        s.fences[idx].stage = 0;
        return rc;
    }
    s.fences[idx].stage = FENCE_STAGE_META;
    s.fences[idx].device_ticket = u64::from(s.op_wait_epoch);
    1
}

/// # Safety
/// Kernel provider-dispatch entry point: `state` is the instance block this
/// module's `module_new` initialised, and `arg` points to `arg_len` bytes
/// (may be null when `arg_len` is 0) valid for the call.
#[cfg_attr(
    not(feature = "host-test"),
    link_section = ".text.module_provider_dispatch"
)]
#[cfg_attr(not(feature = "host-test"), export_name = "module_provider_dispatch")]
pub unsafe extern "C" fn fat32_fs_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if state.is_null() {
        return E_INVAL;
    }
    let s = &mut *(state as *mut Fat32State);
    if !s.syscalls.is_null() {
        s.call_t0 = dev_micros(&*s.syscalls);
    }
    s.call_gen = s.call_gen.wrapping_add(1);
    s.miss = 0;
    // `contracts::fence::QUERY_OP` — fence introspection. A handle reports
    // `LocalDurable` ONLY after a writable handle's bytes have been committed
    // past the device's volatile cache by a successful FS_FSYNC (`durable`
    // flag, advertised via FS_CAP_FSYNC). Everything else — a writable handle
    // with unflushed writes, AND any read-only handle — is `Volatile`, per the
    // fence contract ("plain reads ... land [in Volatile]") and
    // `contracts/storage/fs.rs` (OPEN/READ report Volatile). The handle is
    // validated like every other op: `EINVAL` for a malformed buffer,
    // `ENOSYS` for handles this provider does not own.
    if opcode == abi::fence::QUERY_OP {
        if arg.is_null() || arg_len < abi::fence::WIRE_MAX_LEN {
            return E_INVAL;
        }
        let slot_idx = handle as usize;
        if slot_idx >= MAX_OPEN_FILES || s.open_files[slot_idx].in_use != OF_OPEN {
            return E_NOSYS;
        }
        let of = &s.open_files[slot_idx];
        let fence = if of.writable != 0 && of.durable != 0 {
            abi::fence::Fence::LocalDurable {
                device_id: FAT32_FS_DEVICE_ID,
            }
        } else {
            // Read-only handle, or writable bytes not yet through FS_FSYNC.
            abi::fence::Fence::Volatile
        };
        let buf = core::slice::from_raw_parts_mut(arg, arg_len);
        return match fence.encode(buf) {
            Some(n) => n as i32,
            None => E_INVAL,
        };
    }
    // FS capability bitmap (modules/sdk/contracts/storage/fs.rs::CAPS).
    // The CAPS query is the canonical way for callers to discover which
    // tiers this provider serves before they call an opcode and get
    // ENOSYS.
    //
    // `RENAME` is read from the MOUNTED volume's geometry: the intent
    // record needs a spare reserved sector, which is a property of this
    // volume, not of this provider. Before the boot sector is parsed
    // `reserved_sectors` is 0 and that bit would read clear — so CAPS
    // answers `E_AGAIN` until the mount resolves, exactly like every
    // other opcode. Returning a pessimistic bitmap instead would be
    // worse than useless: a consumer may latch the bitmap it reads, so a
    // boot-order probe would record as absent a capability the volume
    // does in fact have, and the consumer would run its degraded tier
    // forever with nothing to distinguish that from a volume that
    // genuinely cannot carry the record. A capability answer is only
    // meaningful once there is a volume to answer about.
    if opcode == FS_CAPS {
        if arg.is_null() || arg_len < 4 {
            return E_INVAL;
        }
        if s.init_phase != Fat32InitPhase::Done {
            return E_AGAIN;
        }
        let mut caps: u32 = FS_CAP_OPEN
            | FS_CAP_OPENDIR
            | FS_CAP_OPEN_CREATE
            | FS_CAP_WRITE
            | FS_CAP_FSYNC
            | FS_CAP_UNLINK
            | FS_CAP_PREALLOCATE
            | FS_CAP_FSYNC_ASYNC
            | FS_CAP_FSYNC_NAME
            | FS_CAP_MKDIR
            | FS_CAP_RMDIR
            | FS_CAP_TRUNCATE;
        if fs_rename_intent_lba(s).is_some() {
            caps |= FS_CAP_RENAME;
        }
        let bytes = caps.to_le_bytes();
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), arg, 4);
        return 4;
    }
    // CLOSE never waits and always releases, whatever the mount or the
    // device is doing; so does an owner release.
    if opcode == FS_CLOSE {
        let rc = fs_op_close(s, handle);
        fs_pump(s);
        return rc;
    }
    if opcode == OWNER_RELEASED {
        let rc = fs_op_owner_released(s, arg as *const u8, arg_len);
        fs_pump(s);
        return rc;
    }
    // Collect what the device finished since the last call, so this one
    // sees it; and after the call, start what it made ready.
    fs_pump(s);
    let rc = fs_dispatch_op(s, handle, opcode, arg, arg_len);
    fs_pump(s);
    // Closed handles finish as soon as what they wait for has landed, not
    // only on the next step: a caller that closes and reopens a file finds
    // it written back. Bounded, and never waits.
    if fs_step_detached(s) {
        fs_pump(s);
    }
    // A full reclamation ring refuses the next unlink (`EAGAIN`) until a
    // chain drains; drain one batch now rather than only on the next step,
    // so a caller re-asking inside one burst of calls still gets through.
    if !fs_free_queue_has_room(s) {
        fs_step_free_chains(s);
        fs_pump(s);
    }
    if s.cache_defeated != 0 && rc != E_AGAIN && rc != E_INPROGRESS {
        fs_cache_drop_clean(s);
    }
    rc
}

/// The mount's settling: the free summary, the clean bit, then the rename
/// replay. True once all three are done. Each step needs sectors that may
/// still be on their way, so this runs as far as the cache allows and is
/// resumed by the next call or step.
unsafe fn fs_settle_mount(s: &mut Fat32State) -> bool {
    if s.rename_recovered != 0 {
        return true;
    }
    if s.init_phase != Fat32InitPhase::Done {
        return false;
    }
    if s.settle_stage == 0 {
        if !fs_read_fsinfo(s) {
            return false;
        }
        s.settle_stage = 1;
    }
    if s.settle_stage == 1 {
        if !fs_read_clean_bit(s) {
            return false;
        }
        s.settle_stage = 2;
    }
    if fs_tx(s, |s| fs_rename_recover(s)) == E_AGAIN {
        return false;
    }
    s.settle_stage = 3;
    s.rename_recovered = 1;
    true
}

/// Drop every clean cached sector (the host-test measurement aid behind
/// `cache_defeated`): the next operation pays its reads again.
fn fs_cache_drop_clean(s: &mut Fat32State) {
    let mut i = 0usize;
    while i < CACHE_SLOTS {
        if s.cache[i].state == CS_CLEAN && s.cache[i].flags == 0 {
            s.cache[i] = CacheSlot::EMPTY;
        }
        i += 1;
    }
    s.fat_buf_lba = LBA_NONE;
    s.block_buf_lba = LBA_NONE;
}

/// A namespace-mutating operation that decides inside the call: one
/// transaction, the volume-dirty mark included.
///
/// Arming the mark here rather than inside each operation is deliberate: a
/// mutation added later cannot forget to mark, and the mark is what makes a
/// crash visible to whatever mounts the volume next. A write-back failure
/// does not stop it: what it cannot prove is reported by the fences that
/// would have proved it (`FSYNC`, the async fence, `FSYNC_NAME`), which
/// latch `EIO` from then on.
unsafe fn fs_mutate<F: FnOnce(&mut Fat32State) -> i32>(s: &mut Fat32State, f: F) -> i32 {
    fs_tx(s, |s| {
        let b = fs_begin_mutation(s);
        if b != 0 {
            return b;
        }
        f(s)
    })
}

/// An operation that may answer `EINPROGRESS`: `FSYNC_NAME`, `RENAME`,
/// `TRUNCATE`, `PREALLOCATE`.
///
/// A request is identified by who asked and its byte-identical (opcode,
/// handle, argument). The first ask commits the operation — or decides it,
/// when it fails or needs nothing durable — and takes a slot; asks with the
/// same identity answer `EINPROGRESS` until it is decided, then the
/// decision, which frees the slot. The step keeps the operation moving
/// whether or not anyone asks. With every slot holding an operation in
/// progress, a new request answers `EAGAIN`; an uncollected decision is
/// dropped when a new request needs its slot.
unsafe fn fs_op_slotted(
    s: &mut Fat32State,
    opcode: u32,
    handle: i32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    // A request is recognised on a re-ask by its bytes, kept in full. One
    // longer than the slot keeps is refused, deterministically, rather than
    // taken on a key that could match another request.
    if arg_len > OP_ARG_MAX {
        return -7; // E2BIG
    }
    let key = fs_op_key(s, opcode, handle, arg as *const u8, arg_len);
    if let Some(i) = fs_op_find(s, &key, arg as *const u8, arg_len) {
        return fs_op_collect(s, i);
    }
    // Look for room before doing anything: a request that cannot be held
    // must not be taken.
    let mut room = false;
    let mut i = 0usize;
    while i < FS_OP_SLOTS {
        if s.ops[i].state == OPS_FREE || s.ops[i].state == OPS_DONE {
            room = true;
        }
        i += 1;
    }
    if !room {
        return E_AGAIN;
    }
    if opcode == FS_PREALLOCATE {
        let (capacity, target) = match fs_prealloc_check(s, handle, arg as *const u8, arg_len) {
            Ok(v) => v,
            Err(rc) => return rc,
        };
        let Some(i) = fs_op_slot(s) else {
            return E_AGAIN;
        };
        s.ops[i] = OpSlot {
            state: OPS_PREALLOC,
            fd: handle as u16,
            capacity,
            target,
            ..key
        };
        fs_op_keep_arg(s, i, arg as *const u8, arg_len);
        s.open_files[handle as usize].op_busy = 1;
        s.io_rc = 0;
        return fs_op_collect(s, i);
    }
    let a = arg as *const u8;
    let rc = fs_tx(s, |s| {
        let b = fs_begin_mutation(s);
        if b != 0 {
            return b;
        }
        // The dirty mark's boundary is not what this operation waits on.
        s.op_wait_epoch = 0;
        let rc = match opcode {
            FS_FSYNC_NAME => fs_op_fsync_name(s, a, arg_len),
            FS_RENAME => fs_op_rename(s, a, arg_len),
            FS_TRUNCATE => fs_op_truncate(s, a, arg_len),
            _ => E_NOSYS,
        };
        if rc >= 0 && s.op_wait_epoch == 0 {
            // Nothing of its own to make durable (a rename onto itself,
            // say): what it promises is still that its directories are.
            let d = fs_durable_point(s);
            if d != 0 {
                return d;
            }
        }
        rc
    });
    if rc < 0 {
        return rc;
    }
    let Some(i) = fs_op_slot(s) else {
        return E_AGAIN;
    };
    s.ops[i] = OpSlot {
        state: OPS_WAIT,
        wait_epoch: s.op_wait_epoch,
        result: rc,
        ..key
    };
    fs_op_keep_arg(s, i, arg as *const u8, arg_len);
    fs_op_collect(s, i)
}

/// Every opcode but the ones that never wait for the mount.
unsafe fn fs_dispatch_op(
    s: &mut Fat32State,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    // Settle the mount before the first operation of any kind. A reader
    // that resolves a name across an un-replayed rename would adopt a
    // directory the replay is about to change under it, and an allocator
    // that runs before the free summary is read would start from a default
    // rather than from where the last mount left off.
    if s.rename_recovered == 0 && s.init_phase == Fat32InitPhase::Done && !fs_settle_mount(s) {
        return E_AGAIN;
    }
    // A graph that named a volume gets that volume or nothing. Refusing
    // every operation — rather than only the destructive ones — is the point:
    // if the device under this module is not the one the graph was written
    // for, reading from it is as wrong as writing to it, and failing loudly
    // at the first call is how an operator finds out before a consumer has
    // built state on the wrong data.
    if s.expect_volume_id != 0
        && s.init_phase == Fat32InitPhase::Done
        && s.volume_id != s.expect_volume_id
    {
        if s.volume_mismatch_logged == 0 {
            s.volume_mismatch_logged = 1;
            let mut msg = [0u8; 64];
            let mp = msg.as_mut_ptr();
            let head = b"[fat32] volume ";
            core::ptr::copy_nonoverlapping(head.as_ptr(), mp, head.len());
            let mut n = head.len();
            n += fmt_volume_id(mp.add(n), s.volume_id);
            let mid = b" is not the expected ";
            core::ptr::copy_nonoverlapping(mid.as_ptr(), mp.add(n), mid.len());
            n += mid.len();
            n += fmt_volume_id(mp.add(n), s.expect_volume_id);
            dev_log(s.sys(), 2, mp, n);
        }
        return E_NODEV;
    }
    // Clean-slate wipe BEFORE the first operation of any kind (see the
    // `clean_root` field doc): boot readers and the first writer must see
    // the same empty root, or a reader adopts files the wipe later removes
    // from under it.
    if s.clean_root > 0 && s.root_cleaned == 0 && s.init_phase == Fat32InitPhase::Done {
        if s.expect_volume_id == 0 {
            s.root_cleaned = 1;
            // The graph asked to wipe a volume it did not name. Refusing is
            // not pedantry: this is the one parameter whose effect cannot be
            // undone, and "whatever is on the blocks channel" is not a
            // specific enough answer to the question of which volume.
            let mut msg = [0u8; 64];
            let mp = msg.as_mut_ptr();
            let head = b"[fat32] clean_root needs expect_volume_id: ";
            core::ptr::copy_nonoverlapping(head.as_ptr(), mp, head.len());
            let mut n = head.len();
            n += fmt_volume_id(mp.add(n), s.volume_id);
            dev_log(s.sys(), 2, mp, n);
        } else {
            let rc = fs_tx(s, |s| {
                s.root_cleaned = 1;
                let b = fs_begin_mutation(s);
                if b != 0 {
                    return b;
                }
                let rc = fs_clean_root(s);
                if rc != 0 {
                    return rc;
                }
                if s.init_free_hint >= 2 && s.clear_free_region > 0 {
                    return fs_clear_fat_region(s, s.init_free_hint, s.clear_free_region);
                }
                0
            });
            if rc == E_AGAIN {
                return E_AGAIN;
            }
        }
    }
    // A queued FAT clear finishes before the first operation, one sector per
    // transaction: however large, every step of it can commit.
    while s.clear_next < s.clear_end {
        let rc = fs_tx(s, |s| fs_clear_fat_step(s));
        if rc == E_AGAIN {
            return E_AGAIN;
        }
        if rc < 0 {
            s.clear_next = s.clear_end;
        }
        fs_pump(s);
    }
    let a = arg as *const u8;
    match opcode {
        FS_OPEN => fs_op_open(s, a, arg_len),
        FS_READ => fs_op_read(s, handle, arg, arg_len),
        FS_SEEK => fs_op_seek(s, handle, a, arg_len),
        FS_STAT => fs_op_stat(s, handle, arg, arg_len),
        FS_OPENDIR => fs_op_opendir(s, a, arg_len),
        FS_READDIR => fs_op_readdir(s, handle, arg, arg_len),
        FS_OPEN_CREATE => fs_mutate(s, |s| fs_op_create(s, a, arg_len)),
        FS_UNLINK => fs_mutate(s, |s| fs_op_unlink(s, a, arg_len)),
        FS_MKDIR => fs_mutate(s, |s| fs_op_mkdir(s, a, arg_len)),
        FS_RMDIR => fs_mutate(s, |s| fs_op_rmdir(s, a, arg_len)),
        FS_WRITE | FS_WRITE_ASYNC => fs_op_write(s, handle, a, arg_len),
        FS_FSYNC => fs_op_fsync(s, handle),
        FS_FSYNC_SUBMIT => fs_op_fsync_submit(s, handle, arg, arg_len),
        FS_FSYNC_POLL => fs_op_fsync_poll(s, handle, a, arg_len),
        FS_FSYNC_NAME | FS_RENAME | FS_TRUNCATE | FS_PREALLOCATE => {
            fs_op_slotted(s, opcode, handle, arg, arg_len)
        }
        _ => -38, // ENOSYS
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(
    not(feature = "host-test"),
    link_section = ".text.module_provides_contract"
)]
pub extern "C" fn module_provides_contract() -> u32 {
    0x0009 // FS
}

/// FNV-1a hash of a `volume:` param string via the shared kernel/module
/// `provider_selector::hash`, so this fat32's declared selector matches a
/// `mount` module's `provider_bind("<volume>")` query byte-for-byte.
///
/// # Safety
/// `d` must point to `len` readable bytes.
unsafe fn hash_selector(d: *const u8, len: usize) -> u32 {
    abi::kernel_abi::provider_selector::hash(core::slice::from_raw_parts(d, len))
}

/// Instance selector for this fat32 volume (0 = unkeyed default provider).
/// The loader calls this after `module_new` so `state` holds the parsed
/// `volume:` param; a keyed volume is bound by the `mount` module.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(
    not(feature = "host-test"),
    link_section = ".text.module_provider_selector"
)]
pub extern "C" fn module_provider_selector(state: *mut u8) -> u32 {
    if state.is_null() {
        return 0;
    }
    // SAFETY: the loader passes this module's own state buffer, sized for
    // `Fat32State` and initialised by `module_new`.
    unsafe { (*(state as *const Fat32State)).selector }
}

/// Marker export: subscribe this provider to `OWNER_RELEASED`. Present because
/// the open-file table is provider-wide and stamped per owner, so a torn-down
/// consumer's slots have to be reclaimed by somebody, and this provider is the
/// only one that knows which slots those are.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(
    not(feature = "host-test"),
    link_section = ".text.module_observes_owner_release"
)]
pub extern "C" fn module_observes_owner_release() -> u32 {
    1
}

// ============================================================================
// Exported PIC Module Interface
// ============================================================================

declare_module_state_bytes!(Fat32State);

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_state_size")]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<Fat32State>() as u32
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_init")]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_new")]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<Fat32State>() {
            return -3;
        }

        let s = &mut *(state as *mut Fat32State);
        s.init(syscalls as *const SyscallTable);

        s.in_chan = in_chan;
        s.blk.bind(in_chan);

        // Parse params
        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        s.last_observe_ms = dev_millis(&*s.syscalls);

        0
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut Fat32State);
        if s.syscalls.is_null() || s.in_chan < 0 {
            return -1;
        }

        s.tick_count = s.tick_count.wrapping_add(1);
        s.call_t0 = dev_micros(&*s.syscalls);
        s.call_gen = s.call_gen.wrapping_add(1);
        s.miss = 0;
        // Settle the mount once it is mounted: the free summary, the clean
        // bit, then the rename replay, as far as the cache allows each step.
        // A call that arrives before the steps finish settles the rest (see
        // the dispatch).
        if s.rename_recovered == 0 && s.init_phase == Fat32InitPhase::Done {
            fs_pump(s);
            fs_settle_mount(s);
            fs_pump(s);
            return 0;
        }
        let now_ms = dev_millis(&*s.syscalls);
        let observe_due = now_ms.wrapping_sub(s.last_observe_ms) >= FAT32_OBSERVE_INTERVAL_MS;
        if observe_due {
            s.last_observe_ms = now_ms;
            // Module-scope telemetry: emit the current directory file count to
            // the `observe` collector (no-op when unwired). id 0 = file_count
            // per `[observability].metrics`; UpDownCounter since it's a gauge.
            if dev_telemetry_enabled(&*s.syscalls) {
                let tsys = &*s.syscalls;
                let me = dev_self_index(tsys);
                if me >= 0 {
                    dev_telemetry_metric(
                        tsys,
                        -1,
                        me as u16,
                        dev_micros(tsys),
                        abi::contracts::telemetry::METRIC_UPDOWN,
                        0,
                        s.file_count as u64,
                    );
                }
            }

            let mut msg = [0u8; 64];
            let p = msg.as_mut_ptr();
            {
                // Read path telemetry: whole-sector runs handed straight to the
                // caller, and single-sector refills through the scratch sector.
                let mut rd = [0u8; 64];
                let head = b"[fat32] rd runs=";
                rd[..head.len()].copy_from_slice(head);
                let mut rp = head.len();
                rp += fmt_u32_raw(rd.as_mut_ptr().add(rp), s.rd_runs);
                let mid = b" sectors=";
                rd[rp..rp + mid.len()].copy_from_slice(mid);
                rp += mid.len();
                rp += fmt_u32_raw(rd.as_mut_ptr().add(rp), s.rd_sectors);
                dev_log(s.sys(), 3, rd.as_ptr(), rp);
            }
            let prefix = b"[fat32] hb init=";
            core::ptr::copy_nonoverlapping(prefix.as_ptr(), p, prefix.len());
            let mut pos = prefix.len();
            let ip = s.init_phase as u8;
            *p.add(pos) = b'0' + (ip / 10);
            *p.add(pos + 1) = b'0' + (ip % 10);
            pos += 2;
            let fc_tag = b" files=";
            core::ptr::copy_nonoverlapping(fc_tag.as_ptr(), p.add(pos), fc_tag.len());
            pos += fc_tag.len();
            let fc = s.file_count.min(999);
            *p.add(pos) = b'0' + ((fc / 100) % 10) as u8;
            *p.add(pos + 1) = b'0' + ((fc / 10) % 10) as u8;
            *p.add(pos + 2) = b'0' + (fc % 10) as u8;
            pos += 3;
            // Open handles and whether the volume is currently recorded as
            // cleanly shut down — the two things about a mounted provider an
            // operator cannot see any other way.
            let fd_tag = b" fds=";
            core::ptr::copy_nonoverlapping(fd_tag.as_ptr(), p.add(pos), fd_tag.len());
            pos += fd_tag.len();
            let mut open = 0u32;
            let mut k = 0usize;
            while k < MAX_OPEN_FILES {
                if s.open_files[k].in_use == OF_OPEN {
                    open += 1;
                }
                k += 1;
            }
            pos += fmt_u32_raw(p.add(pos), open);
            let cl_tag = b" clean=";
            core::ptr::copy_nonoverlapping(cl_tag.as_ptr(), p.add(pos), cl_tag.len());
            pos += cl_tag.len();
            *p.add(pos) = b'0' + s.volume_clean;
            pos += 1;
            // Which volume this is. `expect_volume_id` is the only way to
            // authorise the destructive parameters, and this is where its
            // value is read from.
            let vol_tag = b" vol=";
            core::ptr::copy_nonoverlapping(vol_tag.as_ptr(), p.add(pos), vol_tag.len());
            pos += vol_tag.len();
            pos += fmt_volume_id(p.add(pos), s.volume_id);
            dev_log(s.sys(), 3, p, pos);
        }

        let rx_pre = s.tlm.bytes_in;
        let tx_pre = s.tlm.bytes_out;
        let bp_pre = s.tlm.bp_steps;

        let rc = step_inner(s);

        tlm_idle_if_unchanged(&mut s.tlm, rx_pre, tx_pre, bp_pre);
        // Borrow `syscalls` raw so the emit helper can hold `&mut s.tlm`
        // alongside.
        let sys = &*s.syscalls;
        let scratch_ptr = s.tlm_scratch.as_mut_ptr();
        let scratch_len = s.tlm_scratch.len();
        let tick = s.tick_count;
        if observe_due {
            dev_tlm_maybe_emit(
                sys,
                b"[fat32]",
                &mut s.tlm,
                tick,
                0,
                scratch_ptr,
                scratch_len,
            );
        }
        rc
    }
}

/// Per-tick scheduler entry. Factored out so `module_step` can wrap
/// the call with telemetry capture; every early return inside still
/// passes through the tlm emit path.
unsafe fn step_inner(s: &mut Fat32State) -> i32 {
    // Run initialization if not done
    if s.init_phase != Fat32InitPhase::Done {
        return init_step(s);
    }

    // The write-back, the operations taken and not yet decided, the
    // handles closed with write-back left, the lazy reclamation of
    // unlinked chains and the settle — every one of them bounded, none
    // waiting (see `fs_background_step`). This step is also what reaps the
    // block source's completions when no caller is asking.
    fs_background_step(s);

    // Requests are served by the FS_CONTRACT dispatch (`fat32_fs_dispatch`
    // exported below); the per-step path carries only deferred work.
    0
}

// ============================================================================
// Format
// ============================================================================
//
// Laying a fresh volume on a source that holds none (param `format`). The
// layout is the one `mkfs.vfat -F 32` and the FAT32 specification describe:
// a 32-sector reserved region carrying the boot sector (0), FSINFO (1) and
// their backups (6, 7); two FATs; the root directory in cluster 2. Cluster
// size follows the specification's table for the volume's size.
//
// The boot sector is written last, after everything else is on media behind
// a flush. It is what makes the device a volume: a format cut short leaves a
// first sector with no signature, which the next mount formats again from
// the start, rather than a boot sector describing FATs that were never
// cleared.

/// Reserved sectors a formatted volume carries. Ten or more leave room for
/// the rename intent record in the last one; 32 is what `mkfs.vfat` uses.
const FMT_RESERVED: u32 = 32;
/// FSINFO and the backup boot record, at the specification's positions.
const FMT_FSINFO: u32 = 1;
const FMT_BACKUP_BOOT: u32 = 6;
/// Clusters below which the specification calls a volume FAT16, whatever its
/// boot sector says: a reader that types the volume by its cluster count, as
/// the specification directs, would misread a smaller FAT32.
const FMT_MIN_CLUSTERS: u32 = 65_525;
/// Requests one format step issues at most while clearing, so a large
/// device spans many steps rather than holding one.
const FMT_ZERO_PER_STEP: u32 = 64;
/// Sectors per pipelined zero write in a format.
const FMT_ZERO_RUN: u32 = 8;
/// Time a format step spends clearing before it yields.
const FMT_ZERO_STEP_US: u64 = 500;
/// FAT32's largest cluster number plus one; a volume past it is not FAT32.
const FMT_MAX_CLUSTERS: u32 = 0x0FFF_FFF5;

/// A format in progress.
#[derive(Clone, Copy)]
#[repr(C)]
struct FormatPlan {
    /// Sectors the volume spans.
    total: u32,
    fat_size: u32,
    clusters: u32,
    volume_id: u32,
    /// Next sector to write: while zeroing, a sector number; while writing
    /// metadata, the index of the next record in [`format_meta_step`].
    cursor: u32,
    /// First sector past the region to zero (the end of the root cluster).
    zero_end: u32,
    spc: u8,
    _pad: [u8; 3],
}

impl FormatPlan {
    const EMPTY: Self = Self {
        total: 0,
        fat_size: 0,
        clusters: 0,
        volume_id: 0,
        cursor: 0,
        zero_end: 0,
        spc: 0,
        _pad: [0; 3],
    };
}

/// Sectors per cluster for a volume of `total` 512-byte sectors, from the
/// FAT32 specification's table.
const fn fmt_sectors_per_cluster(total: u32) -> u32 {
    if total <= 532_480 {
        1
    } else if total <= 16_777_216 {
        8
    } else if total <= 33_554_432 {
        16
    } else if total <= 67_108_864 {
        32
    } else {
        64
    }
}

/// Plan a volume of `total` sectors with `spc` sectors per cluster (0 = the
/// specification's table): `(sectors_per_cluster, fat_size, clusters)`, or
/// `None` when `spc` is not a power of two up to 128 or the volume would
/// fall outside FAT32's cluster-count range.
///
/// The FAT size is the specification's closed form, which may exceed the
/// minimum by a sector — a FAT with room to spare is valid, one short of its
/// clusters is not. Every division is 32-bit or through
/// [`div_rem_u64_by_u32`]: a PIC module has no division helpers to call.
fn fmt_plan(total: u32, spc: u32) -> Option<(u32, u32, u32)> {
    let spc = if spc == 0 {
        fmt_sectors_per_cluster(total)
    } else {
        spc
    };
    if !spc.is_power_of_two() || spc > 128 {
        return None;
    }
    if total <= FMT_RESERVED {
        return None;
    }
    let avail = total - FMT_RESERVED;
    let per = 128 * spc + 1;
    let (fat_size, _) = div_rem_u64_by_u32(u64::from(avail) + u64::from(per - 1), per);
    let fat_size = fat_size as u32;
    let meta = 2 * fat_size;
    if meta >= avail {
        return None;
    }
    let clusters = (avail - meta) / spc;
    if !(FMT_MIN_CLUSTERS..=FMT_MAX_CLUSTERS).contains(&clusters) {
        return None;
    }
    // The FAT must index every cluster plus its two reserved entries.
    if u64::from(fat_size) * 128 < u64::from(clusters) + 2 {
        return None;
    }
    Some((spc, fat_size, clusters))
}

/// Begin formatting the source, whose first sector carries no signature.
/// Returns the init step's result.
unsafe fn format_begin(s: &mut Fat32State) -> i32 {
    // The format writes through `storage.block` requests whichever way the
    // mount reads, so what it needs is a source that takes writes.
    if s.blk.caps(&*s.syscalls) != 0
        || s.blk.flags() & abi::contracts::storage::block::caps::F_WRITE == 0
        || !s.blk.is_async()
    {
        log_info(
            s,
            b"[fat32] format needs a writable, queueing storage.block source",
        );
        return -1;
    }
    if s.blk.block_size() as usize != BLOCK_SIZE {
        log_info(s, b"[fat32] format: device block size unsupported");
        return -1;
    }
    let count = s.blk.block_count();
    let total = if count > u64::from(u32::MAX) {
        u32::MAX
    } else {
        count as u32
    };
    let Some((spc, fat_size, clusters)) = fmt_plan(total, u32::from(s.format_spc)) else {
        log_info(
            s,
            b"[fat32] format: no FAT32 volume fits this source and cluster size",
        );
        return -1;
    };
    // The serial is the volume's only identity: taken from the clock and the
    // device, so two formats of one device, or one moment on two, differ.
    let sys = &*s.syscalls;
    let t = dev_micros(sys);
    let dev = s.blk.device_id();
    let mut id = (t as u32) ^ ((t >> 32) as u32) ^ (dev as u32) ^ ((dev >> 32) as u32);
    id = id.rotate_left(13) ^ total;
    if id == 0 {
        id = 1;
    }
    s.fmt = FormatPlan {
        total,
        fat_size,
        clusters,
        volume_id: id,
        cursor: 1,
        zero_end: FMT_RESERVED + 2 * fat_size + spc,
        spc: spc as u8,
        _pad: [0; 3],
    };
    s.partition_lba = 0;
    log_info(s, b"[fat32] formatting");
    s.init_phase = Fat32InitPhase::FormatZero;
    0
}

/// Zero the next run of the metadata region. Sector 0 is left for the last
/// write of the format.
///
/// The region is two whole FATs, which on a large device is most of a
/// gigabyte, so how it is cleared matters:
/// - a source whose discarded blocks read back as zeros is discarded, in
///   runs of its request size: a transform such as `crypt_block` then seals
///   each unit once rather than rewriting it for every sector;
/// - any other source is sent zero runs of `FMT_ZERO_RUN` sectors without
///   waiting, and the format goes on only once a fence over all of them is durable.
///
/// Every path stops for the step after `FMT_ZERO_STEP_US`, and nothing in it
/// waits on the device.
unsafe fn format_zero_step(s: &mut Fat32State) -> i32 {
    use abi::contracts::storage::block as blk;
    s.block_buf_lba = LBA_NONE;
    let sys = &*s.syscalls;
    let t0 = dev_micros(sys);
    let spent = |sys: &SyscallTable| dev_micros(sys).wrapping_sub(t0) >= FMT_ZERO_STEP_US;
    let mut n = 0u32;
    let zeroes = blk::caps::F_DISCARD | blk::caps::F_DISCARD_ZEROES;
    let discard = s.blk.flags() & zeroes == zeroes;
    // Every request is submitted, never waited for: the zeroes come from
    // `zero_buf`, which never changes, so a source that borrows the buffer
    // until the write lands is served as well as one that copies it.
    while s.fmt.cursor < s.fmt.zero_end && n < FMT_ZERO_PER_STEP && !spent(sys) {
        let rc = if discard {
            let run = (s.fmt.zero_end - s.fmt.cursor).min(s.blk.max_blocks().max(1));
            let rc = s.blk.submit_discard(sys, u64::from(s.fmt.cursor), run);
            if rc == 0 {
                s.fmt.cursor += run;
            }
            rc
        } else {
            let run = (s.fmt.zero_end - s.fmt.cursor)
                .min(FMT_ZERO_RUN)
                .min(ZERO_BUF_SECTORS as u32)
                .min(s.blk.max_blocks().max(1));
            let lba = fs_abs_lba(s, s.fmt.cursor);
            let rc = s.blk.submit_write(sys, lba, run, s.zero_buf.as_ptr());
            if rc == 0 {
                s.fmt.cursor += run;
            }
            rc
        };
        if rc == E_AGAIN {
            return 0;
        }
        if rc < 0 {
            log_info(s, b"[fat32] format write failed");
            return -1;
        }
        n += 1;
    }
    if s.fmt.cursor < s.fmt.zero_end {
        return 0;
    }
    // Everything submitted must have landed before the metadata that names
    // it is written: a fence, polled across steps.
    match fs_fmt_fence(s) {
        0 => {}
        1 => return 0,
        _ => {
            log_info(s, b"[fat32] format write failed");
            return -1;
        }
    }
    s.fmt.cursor = 0;
    s.init_phase = Fat32InitPhase::FormatMeta;
    0
}

/// Poll the format's flush fence, opening it on first use: 0 durable, 1
/// pending, negative failed.
unsafe fn fs_fmt_fence(s: &mut Fat32State) -> i32 {
    if s.fmt_ticket_live == 0 {
        s.fmt_ticket = s.blk.flush_submit();
        s.fmt_ticket_live = 1;
    }
    let r = s.blk.flush_poll(&*s.syscalls, s.fmt_ticket);
    if r != 1 {
        s.fmt_ticket_live = 0;
    }
    r
}

/// Build the boot sector of the planned volume in `block_buf`.
fn format_boot_sector(s: &mut Fat32State) {
    let p = s.fmt;
    let b = &mut s.block_buf;
    *b = [0; BLOCK_SIZE];
    b[0] = 0xEB;
    b[1] = 0x58;
    b[2] = 0x90;
    b[3..11].copy_from_slice(b"FLUXOR  ");
    b[11..13].copy_from_slice(&(BLOCK_SIZE as u16).to_le_bytes());
    b[13] = p.spc;
    b[14..16].copy_from_slice(&(FMT_RESERVED as u16).to_le_bytes());
    b[16] = 2; // FATs
               // 17..19 root entries, 19..21 16-bit total, 22..24 16-bit FAT size: 0.
    b[21] = 0xF8; // fixed media
    b[24..26].copy_from_slice(&63u16.to_le_bytes()); // sectors per track
    b[26..28].copy_from_slice(&255u16.to_le_bytes()); // heads
    b[32..36].copy_from_slice(&p.total.to_le_bytes());
    b[36..40].copy_from_slice(&p.fat_size.to_le_bytes());
    // 40..42 flags (both FATs mirrored), 42..44 version 0.0.
    b[44..48].copy_from_slice(&2u32.to_le_bytes()); // root cluster
    b[48..50].copy_from_slice(&(FMT_FSINFO as u16).to_le_bytes());
    b[50..52].copy_from_slice(&(FMT_BACKUP_BOOT as u16).to_le_bytes());
    b[64] = 0x80; // drive number
    b[66] = 0x29; // extended boot signature: the next three fields exist
    b[67..71].copy_from_slice(&p.volume_id.to_le_bytes());
    b[71..82].copy_from_slice(b"NO NAME    ");
    b[82..90].copy_from_slice(b"FAT32   ");
    b[510] = 0x55;
    b[511] = 0xAA;
}

/// Build the FSINFO sector of the planned volume in `block_buf`: every
/// cluster but the root's free, allocation to start after it.
fn format_fsinfo(s: &mut Fat32State) {
    let free = s.fmt.clusters - 1;
    let b = &mut s.block_buf;
    *b = [0; BLOCK_SIZE];
    b[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
    b[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
    b[FSINFO_FREE_COUNT..FSINFO_FREE_COUNT + 4].copy_from_slice(&free.to_le_bytes());
    b[FSINFO_NEXT_FREE..FSINFO_NEXT_FREE + 4].copy_from_slice(&3u32.to_le_bytes());
    b[508..512].copy_from_slice(&0xAA55_0000u32.to_le_bytes());
}

/// Build the first sector of a FAT in `block_buf`: the media entry, the
/// clean-shutdown entry, and the root directory's end of chain.
fn format_fat_head(s: &mut Fat32State) {
    let b = &mut s.block_buf;
    *b = [0; BLOCK_SIZE];
    b[0..4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes());
    b[4..8].copy_from_slice(&FAT32_TAIL.to_le_bytes());
    b[8..12].copy_from_slice(&FAT32_TAIL.to_le_bytes());
}

/// Write the volume's metadata, one record per `cursor` value, and commit it
/// with the boot sector. Resumes where an `EAGAIN` stopped it.
unsafe fn format_meta_step(s: &mut Fat32State) -> i32 {
    s.block_buf_lba = LBA_NONE;
    while s.fmt.cursor < 8 {
        // One record at a time: `block_buf` is lent to a source that
        // borrows it until the write before has landed.
        if s.fmt_seq != 0 {
            s.blk.reap(&*s.syscalls);
            let st = s.blk.write_state(s.fmt_seq);
            if st == 1 {
                return 0;
            }
            s.fmt_seq = 0;
            if st < 0 {
                log_info(s, b"[fat32] format write failed");
                return -1;
            }
        }
        let lba: u32 = match s.fmt.cursor {
            0 => {
                format_fat_head(s);
                FMT_RESERVED
            }
            1 => {
                format_fat_head(s);
                FMT_RESERVED + s.fmt.fat_size
            }
            2 => {
                format_fsinfo(s);
                FMT_FSINFO
            }
            3 => {
                format_boot_sector(s);
                FMT_BACKUP_BOOT
            }
            4 => {
                format_fsinfo(s);
                FMT_BACKUP_BOOT + FMT_FSINFO
            }
            6 => {
                format_boot_sector(s);
                0
            }
            // 5 and 7: everything before them reaches media before the
            // step after them runs.
            _ => LBA_NONE,
        };
        if lba == LBA_NONE {
            match fs_fmt_fence(s) {
                0 => {}
                1 => return 0,
                _ => {
                    log_info(s, b"[fat32] format write failed");
                    return -1;
                }
            }
        } else {
            let buf = s.block_buf.as_ptr();
            let rc = s.blk.submit_write(&*s.syscalls, u64::from(lba), 1, buf);
            if rc == E_AGAIN {
                return 0;
            }
            if rc < 0 {
                log_info(s, b"[fat32] format write failed");
                return -1;
            }
            s.fmt_seq = s.blk.last_seq();
        }
        s.fmt.cursor += 1;
    }
    log_info(s, b"[fat32] formatted");
    // Mount what was just written, through the same path as any volume. No
    // directory resolved on the old volume names anything on this one.
    s.dir_cache = [DirCacheEntry::EMPTY; DIR_CACHE];
    s.init_phase = Fat32InitPhase::Idle;
    0
}

/// Initialization state machine
unsafe fn init_step(s: &mut Fat32State) -> i32 {
    match s.init_phase {
        Fat32InitPhase::Idle => {
            s.sync_src = u8::from(writable_block_source(s));
            // Every request this provider makes is submitted and reaped; a
            // source that cannot queue would have to be waited on inside
            // the callers' steps, which the fs contract forbids.
            if s.sync_src != 0 && !s.blk.is_async() {
                log_info(s, b"[fat32] block source does not queue (no F_ASYNC)");
                return -1;
            }
            match start_read(s, 0) {
                0 => {}
                1 => return 0,
                _ => return -1,
            }
            s.init_phase = Fat32InitPhase::WaitBlock0;
            0
        }

        Fat32InitPhase::WaitBlock0 => {
            let res = try_read_block(s);
            if res < 0 {
                log_info(s, b"[fat32] blk0 read fail");
                return -1;
            }
            if res == 0 {
                // A source still attaching when the stream was sought may be
                // one that has no stream at all; once it says it takes
                // requests, mount through them.
                if s.sync_src == 0 && writable_block_source(s) {
                    s.init_phase = Fat32InitPhase::Idle;
                }
                return 0;
            }

            // Try as direct FAT32 boot sector first
            s.partition_lba = 0;
            if parse_boot_sector(s) {
                log_info(s, b"[fat32] boot ok");
                start_enumeration(s);
                s.init_phase = Fat32InitPhase::ReadRoot;
                return 2; // Burst — issue root dir seek immediately
            }

            // Try as MBR with FAT32 partition
            let lba = parse_mbr(&s.block_buf);
            if lba > 0 {
                s.partition_lba = u64::from(lba);
                s.init_phase = Fat32InitPhase::ReadBoot;
                return 2; // Burst — read boot sector immediately
            }

            // Check for GPT protective MBR (partition type 0xEE)
            let sig0 = *s.block_buf.as_ptr().add(510);
            let sig1 = *s.block_buf.as_ptr().add(511);
            if sig0 == 0x55 && sig1 == 0xAA {
                let mut i = 0u32;
                while i < 4 {
                    let ptype = *s.block_buf.as_ptr().add((446 + i * 16 + 4) as usize);
                    if ptype == 0xEE {
                        s.init_phase = Fat32InitPhase::ReadGptHeader;
                        return 2; // Burst — read GPT header
                    }
                    i += 1;
                }
            }

            if sig0 == 0x55 && sig1 == 0xAA {
                // Something wrote this device — a partition table this
                // provider does not mount from, or another filesystem.
                // `format` never overwrites it.
                log_info(s, b"[fat32] no fat32");
                return -1;
            }
            // Only a first sector that is entirely zero is blank. Filesystems
            // such as ext4 and containers such as LUKS sign nothing at
            // offset 510, so an unsigned sector with content is someone's
            // data, and `format` leaves it alone.
            if s.format == 0 || s.block_buf.iter().any(|&b| b != 0) {
                log_info(s, b"[fat32] no fat32");
                return -1;
            }
            format_begin(s)
        }

        Fat32InitPhase::ReadBoot => {
            match start_read(s, s.partition_lba) {
                0 => {}
                1 => return 0,
                _ => return -1,
            }
            s.init_phase = Fat32InitPhase::WaitBoot;
            0
        }

        Fat32InitPhase::WaitBoot => {
            let res = try_read_block(s);
            if res < 0 {
                log_info(s, b"[fat32] boot read fail");
                return -1;
            }
            if res == 0 {
                return 0;
            }

            if !parse_boot_sector(s) {
                log_info(s, b"[fat32] not fat32");
                return -1;
            }
            log_info(s, b"[fat32] boot ok");
            start_enumeration(s);
            s.init_phase = Fat32InitPhase::ReadRoot;
            2 // Burst — issue root dir seek immediately
        }

        Fat32InitPhase::ReadRoot => {
            let sector = cluster_to_sector(s, s.dir_cluster) + (s.dir_sector_in_cluster as u32);
            match start_read(s, fs_abs_lba(s, sector)) {
                0 => {}
                1 => return 0,
                _ => return -1,
            }
            s.init_phase = Fat32InitPhase::WaitRoot;
            0
        }

        Fat32InitPhase::WaitRoot => {
            let res = try_read_block(s);
            if res < 0 {
                log_info(s, b"[fat32] dir read fail");
                return -1;
            }
            if res == 0 {
                return 0;
            }

            let entries_per_sector = BLOCK_SIZE / DIR_ENTRY_SIZE;

            if s.dir_mode == 0 {
                // Path resolution: find subdirectory matching current component
                while (s.dir_entry_in_sector as usize) < entries_per_sector {
                    let offset = (s.dir_entry_in_sector as usize) * DIR_ENTRY_SIZE;
                    let entry_ptr = s.block_buf.as_ptr().add(offset);
                    let first_byte = *entry_ptr;

                    if first_byte == 0x00 {
                        log_info(s, b"[fat32] path not found");
                        return -1;
                    }

                    s.dir_entry_in_sector += 1;
                    if first_byte == 0xE5 {
                        continue;
                    }

                    let attr = *entry_ptr.add(11);
                    if attr == ATTR_LONG_NAME {
                        continue;
                    }
                    if (attr & ATTR_DIRECTORY) == 0 {
                        continue;
                    }

                    // Compare against current path component
                    let pp = s.path.as_ptr();
                    let comp_start = s.path_pos as usize;
                    let mut comp_len = 0usize;
                    while comp_start + comp_len < 63
                        && *pp.add(comp_start + comp_len) != b'/'
                        && *pp.add(comp_start + comp_len) != 0
                    {
                        comp_len += 1;
                    }

                    if matches_83(pp.add(comp_start), comp_len, entry_ptr) {
                        // Found matching subdir
                        let cluster_hi = read_u16_le(&s.block_buf, offset + 20) as u32;
                        let cluster_lo = read_u16_le(&s.block_buf, offset + 26) as u32;
                        let cluster = (cluster_hi << 16) | cluster_lo;
                        if cluster < 2 {
                            continue;
                        }

                        s.dir_cluster = cluster;
                        s.path_pos += comp_len as u8;
                        while (s.path_pos as usize) < 63 && *pp.add(s.path_pos as usize) == b'/' {
                            s.path_pos += 1;
                        }
                        if *pp.add(s.path_pos as usize) == 0 {
                            s.dir_mode = 1;
                        }
                        s.dir_sector_in_cluster = 0;
                        s.dir_entry_in_sector = 0;
                        s.init_phase = Fat32InitPhase::ReadRoot;
                        return 2; // Burst — descend into subdir immediately
                    }
                }
            } else {
                // File enumeration
                let mut end_of_dir = false;

                while (s.dir_entry_in_sector as usize) < entries_per_sector {
                    let offset = (s.dir_entry_in_sector as usize) * DIR_ENTRY_SIZE;
                    let first_byte = *s.block_buf.as_ptr().add(offset);
                    if first_byte == 0x00 {
                        end_of_dir = true;
                        break;
                    }

                    parse_dir_entry(s, offset);
                    s.dir_entry_in_sector += 1;
                }

                if end_of_dir || s.file_count >= MAX_FILES as u16 {
                    // Log file count
                    {
                        let mut lb = [0u8; 24];
                        let bp = lb.as_mut_ptr();
                        let tag = b"[fat32] files=";
                        let mut p = 0usize;
                        let mut t = 0usize;
                        while t < tag.len() {
                            *bp.add(p) = *tag.as_ptr().add(t);
                            p += 1;
                            t += 1;
                        }
                        p += fmt_u32_raw(bp.add(p), s.file_count as u32);
                        dev_log(&*s.syscalls, 3, bp, p);
                    }
                    s.init_phase = Fat32InitPhase::Done;
                    return 2; // Burst — ready for streaming
                }
            }

            // Next sector in cluster, or follow FAT chain
            s.dir_entry_in_sector = 0;
            s.dir_sector_in_cluster += 1;

            if s.dir_sector_in_cluster >= s.sectors_per_cluster {
                s.init_phase = Fat32InitPhase::ReadDirFat;
            } else {
                s.init_phase = Fat32InitPhase::ReadRoot;
            }
            2 // Burst — continue directory traversal
        }

        Fat32InitPhase::ReadDirFat => {
            let fat_sector = fat_sector_for_cluster(s, s.dir_cluster);
            match start_read(s, fs_abs_lba(s, fat_sector)) {
                0 => {}
                1 => return 0,
                _ => return -1,
            }
            s.init_phase = Fat32InitPhase::WaitDirFat;
            0
        }

        Fat32InitPhase::WaitDirFat => {
            let res = try_read_block(s);
            if res < 0 {
                if s.dir_mode == 0 {
                    log_info(s, b"[fat32] path not found");
                    return -1;
                }
                s.init_phase = Fat32InitPhase::Done;
                return 0;
            }
            if res == 0 {
                return 0;
            }

            let offset = fat_offset_for_cluster(s, s.dir_cluster);
            if offset + 4 > BLOCK_SIZE {
                if s.dir_mode == 0 {
                    log_info(s, b"[fat32] path not found");
                    return -1;
                }
                s.init_phase = Fat32InitPhase::Done;
                return 0;
            }
            let next_cluster = read_u32_le(&s.block_buf, offset) & FAT32_MASK;

            if !(2..FAT32_EOC).contains(&next_cluster) {
                if s.dir_mode == 0 {
                    log_info(s, b"[fat32] path not found");
                    return -1;
                }
                log_info(s, b"[fat32] enum done");
                s.init_phase = Fat32InitPhase::Done;
                return 0;
            }

            s.dir_cluster = next_cluster;
            s.dir_sector_in_cluster = 0;
            s.dir_entry_in_sector = 0;
            s.init_phase = Fat32InitPhase::ReadRoot;
            2 // Burst — seek next cluster immediately
        }

        Fat32InitPhase::ReadGptHeader => {
            // GPT header is at LBA 1
            match start_read(s, 1) {
                0 => {}
                1 => return 0,
                _ => return -1,
            }
            s.init_phase = Fat32InitPhase::WaitGptHeader;
            0
        }

        Fat32InitPhase::WaitGptHeader => {
            let res = try_read_block(s);
            if res < 0 {
                log_info(s, b"[fat32] gpt hdr read fail");
                return -1;
            }
            if res == 0 {
                return 0;
            }

            // Verify "EFI PART" signature at offset 0
            let buf = s.block_buf.as_ptr();
            let sig = b"EFI PART";
            let mut valid = true;
            let mut i = 0usize;
            while i < 8 {
                if *buf.add(i) != *sig.as_ptr().add(i) {
                    valid = false;
                    break;
                }
                i += 1;
            }
            if !valid {
                log_info(s, b"[fat32] bad gpt hdr");
                return -1;
            }

            // Partition entry array start LBA: the u64 at offset 72.
            s.pending_block = u64::from(read_u32_le(&s.block_buf, 72))
                | (u64::from(read_u32_le(&s.block_buf, 76)) << 32);
            s.init_phase = Fat32InitPhase::ReadGptEntry;
            2 // Burst — read partition entries
        }

        Fat32InitPhase::ReadGptEntry => {
            match start_read(s, s.pending_block) {
                0 => {}
                1 => return 0,
                _ => return -1,
            }
            s.init_phase = Fat32InitPhase::WaitGptEntry;
            0
        }

        Fat32InitPhase::WaitGptEntry => {
            let res = try_read_block(s);
            if res < 0 {
                log_info(s, b"[fat32] gpt entry read fail");
                return -1;
            }
            if res == 0 {
                return 0;
            }

            // Each GPT partition entry is 128 bytes, 4 per 512-byte sector.
            // Find first non-EFI-SP, non-empty partition with a valid FAT32 boot sector.
            // EFI System Partition GUID (mixed-endian): 28 73 2A C1 1F F8 D2 11 ...
            let buf = s.block_buf.as_ptr();
            let efi_sp_prefix: [u8; 4] = [0x28, 0x73, 0x2A, 0xC1];
            let mut i = 0u32;
            while i < 4 {
                let offset = (i * 128) as usize;
                // Check if type GUID (16 bytes at start) is all zeros = unused
                let mut empty = true;
                let mut j = 0usize;
                while j < 16 {
                    if *buf.add(offset + j) != 0 {
                        empty = false;
                        break;
                    }
                    j += 1;
                }

                if !empty {
                    // Skip EFI System Partition (check first 4 bytes of type GUID)
                    let mut is_efi = true;
                    j = 0;
                    while j < 4 {
                        if *buf.add(offset + j) != *efi_sp_prefix.as_ptr().add(j) {
                            is_efi = false;
                            break;
                        }
                        j += 1;
                    }

                    if !is_efi {
                        // Starting LBA: the u64 at offset 32 within the entry.
                        let lba = u64::from(read_u32_le(&s.block_buf, offset + 32))
                            | (u64::from(read_u32_le(&s.block_buf, offset + 36)) << 32);
                        if lba > 0 {
                            s.partition_lba = lba;
                            s.init_phase = Fat32InitPhase::ReadBoot;
                            return 2; // Burst — read boot sector
                        }
                    }
                }
                i += 1;
            }

            // Only the four entries of the first partition-entry sector are
            // scanned; a data partition listed beyond them is not found.
            log_info(s, b"[fat32] no gpt part");
            -1
        }

        Fat32InitPhase::FormatZero => format_zero_step(s),
        Fat32InitPhase::FormatMeta => format_meta_step(s),

        Fat32InitPhase::Done => 0,

        _ => -1,
    }
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");

// ============================================================================
// Host-test surface (feature = "host-test")
// ============================================================================

/// Volume serial [`test_force_ready`] installs, so a test can declare it
/// through `expect_volume_id`.
#[cfg(feature = "host-test")]
pub const TEST_VOLUME_ID: u32 = 0xF1A7_0032;

/// FS_CONTRACT opcodes, re-exported so the host-test harness can drive
/// `fat32_fs_dispatch` without re-declaring the magic numbers.
#[cfg(feature = "host-test")]
pub mod test_ops {
    pub const FS_OPEN: u32 = super::FS_OPEN;
    pub const FS_READ: u32 = super::FS_READ;
    pub const FS_CLOSE: u32 = super::FS_CLOSE;
    pub const FS_FSYNC: u32 = super::FS_FSYNC;
    pub const FS_WRITE: u32 = super::FS_WRITE;
    pub const FS_SEEK: u32 = super::FS_SEEK;
    pub const FS_OPEN_CREATE: u32 = super::FS_OPEN_CREATE;
    pub const FS_UNLINK: u32 = super::FS_UNLINK;
    pub const FS_PREALLOCATE: u32 = super::FS_PREALLOCATE;
    pub const FS_WRITE_ASYNC: u32 = super::FS_WRITE_ASYNC;
    pub const FS_FSYNC_SUBMIT: u32 = super::FS_FSYNC_SUBMIT;
    pub const FS_FSYNC_POLL: u32 = super::FS_FSYNC_POLL;
    pub const FS_FSYNC_NAME: u32 = super::FS_FSYNC_NAME;
    pub const FS_RENAME: u32 = super::FS_RENAME;
    pub const FS_CAPS: u32 = super::FS_CAPS;
    pub const FS_CAP_UNLINK: u32 = super::FS_CAP_UNLINK;
    pub const FS_CAP_FSYNC_ASYNC: u32 = super::FS_CAP_FSYNC_ASYNC;
    pub const FS_CAP_FSYNC_NAME: u32 = super::FS_CAP_FSYNC_NAME;
    pub const FS_CAP_RENAME: u32 = super::FS_CAP_RENAME;
    /// LBA of the rename-intent record on the harness geometry, so a crash
    /// test can inspect or corrupt it directly.
    pub const RENAME_INTENT_LBA: u32 = 31;
    /// FAT end-of-chain marker; the harness writes it into FAT[root] so the
    /// allocator never hands out the root-directory cluster.
    pub const FAT32_TAIL: u32 = super::FAT32_TAIL;
    pub const FS_CAP_OPEN: u32 = super::FS_CAP_OPEN;
    pub const FS_CAP_OPEN_CREATE: u32 = super::FS_CAP_OPEN_CREATE;
    pub const FS_CAP_WRITE: u32 = super::FS_CAP_WRITE;
    pub const FS_CAP_FSYNC: u32 = super::FS_CAP_FSYNC;
    pub const FS_CAP_PREALLOCATE: u32 = super::FS_CAP_PREALLOCATE;
    pub const FS_CAP_TRUNCATE: u32 = super::FS_CAP_TRUNCATE;
    pub const FS_CAP_MKDIR: u32 = super::FS_CAP_MKDIR;
    pub const FS_CAP_RMDIR: u32 = super::FS_CAP_RMDIR;
    pub const FS_MKDIR: u32 = super::FS_MKDIR;
    pub const FS_RMDIR: u32 = super::FS_RMDIR;
    pub const FS_TRUNCATE: u32 = super::FS_TRUNCATE;
    pub const FS_STAT: u32 = super::FS_STAT;
    pub const FS_OPENDIR: u32 = super::FS_OPENDIR;
    pub const FS_READDIR: u32 = super::FS_READDIR;
}

/// Host-test only: defeat the sector cache across operations, so every
/// operation pays its own reads.
///
/// Exists so a measurement can state the caching's effect rather than assume
/// it: run a workload with the cache live and again with it defeated, and
/// the difference is the number of device reads the cache removed. A cache
/// whose benefit nobody measured is a cache nobody can justify keeping.
///
/// Defeated means clean sectors are dropped after every call that decided
/// something. Within one operation the cache still has to hold what the
/// operation is gathering — its reads complete between its asks — or no
/// operation needing two sectors could ever finish.
///
/// # Safety
/// As [`test_force_ready`].
#[cfg(feature = "host-test")]
pub unsafe fn test_set_sector_cache(state: *mut u8, enabled: bool) {
    let s = &mut *(state as *mut Fat32State);
    s.cache_defeated = u8::from(!enabled);
    fs_cache_drop_clean(s);
}

/// Host-test only: run one tick of the provider's background reclamation
/// and report whether more remains.
///
/// The per-step path proper is gated on a wired block channel, which a
/// dispatch-only harness does not have. Reclamation is not optional
/// behaviour a test may skip: cluster frees are deliberately deferred out of
/// the operation that triggers them so no single `provider_call` walks an
/// N-cluster chain, so a test that measures space without draining is
/// measuring a half-finished volume.
///
/// # Safety
/// As [`test_force_ready`].
#[cfg(feature = "host-test")]
pub unsafe fn test_background_step(state: *mut u8) -> bool {
    let s = &mut *(state as *mut Fat32State);
    if s.init_phase != Fat32InitPhase::Done {
        return false;
    }
    fs_background_step(s)
}

/// Host-test only: the mounted volume's geometry, for a fixture that must
/// address the FAT, the root directory or the data region of a volume some
/// other tool formatted.
///
/// Returned as a plain tuple rather than a struct so `test_ops` stays a
/// namespace of constants and this stays the single place the harness reads
/// mount state.
///
/// `(fat_start, fat_size, num_fats, data_start, sectors_per_cluster,
///   root_cluster, reserved_sectors, count_of_clusters)`
///
/// # Safety
/// As [`test_force_ready`].
#[cfg(feature = "host-test")]
#[must_use]
pub unsafe fn test_geometry(state: *const u8) -> (u32, u32, u8, u32, u8, u32, u16, u32) {
    let s = &*(state as *const Fat32State);
    (
        s.fat_start_sector,
        s.fat_size_32,
        s.num_fats,
        s.data_start_sector,
        s.sectors_per_cluster,
        s.root_cluster,
        s.reserved_sectors,
        s.count_of_clusters,
    )
}

/// Host-test only: LBA of this volume's rename intent record, or 0 when the
/// volume's reserved region is too small to carry one.
///
/// # Safety
/// As [`test_force_ready`].
#[cfg(feature = "host-test")]
#[must_use]
pub unsafe fn test_intent_lba(state: *const u8) -> u32 {
    let s = &*(state as *const Fat32State);
    fs_rename_intent_lba(s).unwrap_or(0)
}

/// Host-test only: force an already-`module_new`'d `Fat32State` into a
/// mounted state with an explicit minimal FAT32 geometry, bypassing the
/// async init state machine (which needs the NOTIFY+channel block-source
/// protocol). The harness backs the sync block ioctls (`provider_call`
/// opcode `0x0506`) with a zeroed RAM disk; the geometry below must match
/// what the harness sizes that disk for.
///
/// Geometry: 512 B sectors, 8 sectors/cluster (4 KiB clusters),
/// 32 reserved sectors, 2 FATs of `fat_size_32` sectors each, root at
/// cluster 2, data starting right after FAT2. `next_free_hint = 3` so the
/// allocator skips the root-dir cluster (the harness marks FAT[2] = EOC).
///
/// # Safety
/// `state` must point at a live `Fat32State` of at least
/// `module_state_size()` bytes whose `syscalls` is set (i.e. `module_new`
/// has run).
#[cfg(feature = "host-test")]
pub unsafe fn test_force_ready(state: *mut u8, fat_size_32: u32, fsinfo_sector: u16) {
    let s = &mut *(state as *mut Fat32State);
    s.bytes_per_sector = 512;
    s.sectors_per_cluster = 8;
    s.reserved_sectors = 32;
    s.num_fats = 2;
    s.fat_size_32 = fat_size_32;
    s.root_cluster = 2;
    s.partition_lba = 0;
    s.fat_start_sector = 32;
    s.data_start_sector = 32 + 2 * fat_size_32;
    s.fsinfo_sector = fsinfo_sector;
    s.next_free_hint = 2; // mount default; the allocator skips FAT[2]=EOC (root)
                          // Addressable data clusters. `parse_boot_sector` derives this from the
                          // volume's total-sector count; with no boot sector to read, the FAT's own
                          // capacity is the honest ceiling for a harness disk sized to match it.
    s.count_of_clusters = fat_size_32 * (512 / 4);
    // A synthetic volume serial. Real mounts read `BS_VolID` from the boot
    // sector; a forced mount has no boot sector, and a serial of 0 would
    // make `expect_volume_id` unusable in exactly the tests that exercise
    // the destructive parameters it gates.
    s.volume_id = TEST_VOLUME_ID;
    s.init_phase = Fat32InitPhase::Done;
}

/// Host-test only: mount the volume the block source actually holds, by
/// running the real MBR / boot-sector parser over LBA 0 through the
/// synchronous block ioctls.
///
/// [`test_force_ready`] hard-codes a geometry instead, which leaves
/// `parse_mbr` and `parse_boot_sector` — the code that decides where every
/// subsequent write lands — covered by nothing. This entry point exists so
/// a fixture can be a real `mkfs.vfat` image and the provider has to agree
/// with the tool that wrote it about where the FAT, the root and the data
/// region are.
///
/// Returns `true` when a FAT32 volume was recognised.
///
/// # Safety
/// As [`test_force_ready`]: `state` must point at a live, `module_new`'d
/// `Fat32State`.
#[cfg(feature = "host-test")]
pub unsafe fn test_mount_sync(state: *mut u8) -> bool {
    let s = &mut *(state as *mut Fat32State);
    s.partition_lba = 0;
    let p0 = s.block_buf.as_mut_ptr();
    if fs_sync_read_sector(s, 0, p0) != 0 {
        return false;
    }
    if !parse_boot_sector(s) {
        // Not a bare volume — try an MBR and mount the first FAT32 slice.
        let part = parse_mbr(&s.block_buf);
        if part == 0 {
            return false;
        }
        s.partition_lba = u64::from(part);
        let pp = s.block_buf.as_mut_ptr();
        if fs_sync_read_sector(s, part, pp) != 0 {
            return false;
        }
        if !parse_boot_sector(s) {
            return false;
        }
    }
    s.next_free_hint = 2;
    s.init_phase = Fat32InitPhase::Done;
    true
}

/// Host-test only: whether the stepped mount (and any format before it) has
/// finished, so a test driving `module_step` knows when to start using the
/// volume.
///
/// # Safety
/// As [`test_force_ready`].
#[cfg(feature = "host-test")]
#[must_use]
pub unsafe fn test_mounted(state: *const u8) -> bool {
    (*(state as *const Fat32State)).init_phase == Fat32InitPhase::Done
}

/// Host-test only: the mounted volume's serial (`BS_VolID`), the identity a
/// reformat would change.
///
/// # Safety
/// As [`test_force_ready`].
#[cfg(feature = "host-test")]
#[must_use]
pub unsafe fn test_volume_id(state: *const u8) -> u32 {
    (*(state as *const Fat32State)).volume_id
}

/// Host-test only: read a writable OpenFile slot's first cluster, so a test
/// can assert which cluster the allocator handed out (e.g. that the FSINFO
/// next-free hint was honoured). `slot` is the untagged fd.
#[cfg(feature = "host-test")]
pub unsafe fn test_file_start_cluster(state: *mut u8, slot: i32) -> u32 {
    let s = &*(state as *const Fat32State);
    let idx = slot as usize;
    if idx >= MAX_OPEN_FILES {
        return 0;
    }
    s.open_files[idx].start_cluster
}
