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

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

// ============================================================================
// Constants
// ============================================================================

/// Block size (always 512 for SD/FAT32)
const BLOCK_SIZE: usize = 512;

/// Max sectors per WRITE packet. Matches `nvme::MAX_NLB` (one 4 KB PRP1
/// page of LBAs). The batcher folds up to this many contiguous data
/// sectors into a single request so the nvme driver can issue one Write
/// SQE per packet instead of one per sector. The packet itself is
/// drained downstream in 512 B chunks (see `drain_packet`) so it fits
/// any reasonable channel capacity without requiring hints.
const MAX_WRITE_NLB: u16 = 8;

/// Maximum files to enumerate
const MAX_FILES: usize = 128;

/// Maximum payload accepted for the `write_data` param. Sized to
/// span more than one cluster at common mkfs.vfat cluster sizes (up
/// to 4 KB) so the write path exercises FAT-chain-walk and cluster
/// allocation, while keeping the state-arena footprint bounded.
const WRITE_DATA_MAX: usize = 8192;

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
}

// Reads flow through the synchronous FS_CONTRACT dispatch
// (`fat32_fs_dispatch`) and the per-FD scratch in `OpenFile` — there
// is no per-step read state machine; the dispatch call walks the FAT
// chain in-line via `IOCTL_BLOCKS_READ_LBAS_SYNC`.

// ============================================================================
// Write state machine discriminants (stored in `Fat32State::write_state`).
// Kept as u8 consts instead of an enum so the heartbeat can print the
// raw value and so transitions between states never need a cast.
// ============================================================================

// Idle (no write requested or write already complete).
const WS_IDLE:              u8 = 0;
// Locate the target file by 8.3 short-name; capture dir_lba/offset.
const WS_SCAN:              u8 = 1;
// Build one sector's worth of payload into the outbuf + transition to SendPacket.
const WS_SEND_SECTOR:       u8 = 2;
// Called after SendPacket completes from WS_SEND_SECTOR — advance counters.
const WS_AFTER_SECTOR:      u8 = 3;
// Flush + seek to FAT sector containing the cur cluster; wait for read.
const WS_WALK_FAT_READ:     u8 = 4;
const WS_WALK_FAT_WAIT:     u8 = 5;
// Allocate a new cluster: iterate FAT sectors looking for a zero entry.
const WS_ALLOC_READ:        u8 = 6;
const WS_ALLOC_WAIT:        u8 = 7;
// New cluster found + patched in block_buf (EOC, and optionally prev→new).
// Emit the write for the allocation-side FAT sector.
const WS_ALLOC_WRITE:       u8 = 8;
// Link the previous cluster to the new one (separate FAT sector case).
const WS_LINK_READ:         u8 = 9;
const WS_LINK_WAIT:         u8 = 10;
const WS_LINK_WRITE:        u8 = 11;
// Write the FAT sector mirror copy (FAT2) when num_fats > 1.
const WS_MIRROR_WRITE:      u8 = 12;
// Directory-entry size patch (read-modify-write).
const WS_DIR_READ:          u8 = 13;
const WS_DIR_WAIT:          u8 = 14;
const WS_DIR_WRITE:         u8 = 15;
// Terminal: all writes successfully pushed onto the request channel.
const WS_DONE:              u8 = 16;
// Generic outbuf-drain state used by any emitter; resumes at
// `w_return_state` when the packet (REQ_HDR_SIZE + nlb*512 B) is fully sent.
const WS_SEND_PACKET:       u8 = 17;
// FSINFO sector update (read-modify-write): decrement the free-cluster
// count and bump the next-free hint after each successful allocation.
const WS_FSINFO_READ:       u8 = 18;
const WS_FSINFO_WAIT:       u8 = 19;
const WS_FSINFO_WRITE:      u8 = 20;
// ClnShutBit toggle on cluster 1's FAT entry. WS_MARK_DIRTY_* runs
// once before any data/FAT writes so a crash mid-write leaves the
// filesystem visibly dirty; WS_MARK_CLEAN_* runs last so a normal
// completion restores the clean-shutdown bit and Linux doesn't warn
// on the next mount. Both flows RMW fat_start_sector (the primary
// FAT's sector 0) and mirror to FAT2 when num_fats > 1.
const WS_MARK_DIRTY_READ:   u8 = 21;
const WS_MARK_DIRTY_WAIT:   u8 = 22;
const WS_MARK_DIRTY_WRITE:  u8 = 23;
const WS_MARK_DIRTY_MIRROR: u8 = 24;
const WS_MARK_CLEAN_READ:   u8 = 25;
const WS_MARK_CLEAN_WAIT:   u8 = 26;
const WS_MARK_CLEAN_WRITE:  u8 = 27;
const WS_MARK_CLEAN_MIRROR: u8 = 28;
// One-shot geometry query on the block_writes channel. If the consumer
// (nvme) answers, fat32 logs size+lbads and verifies a 512 B LBA; on
// ENOSYS (no handler registered, e.g. sd driver) the check is skipped.
const WS_NS_CHECK:          u8 = 29;

/// FAT32 "clean shutdown" bit in cluster 1's FAT entry. When set the
/// filesystem was properly unmounted; when cleared Linux reports
/// "Dirty bit is set. Fs was not properly unmounted". See the FAT32
/// white paper and dosfstools `FAT32_CLN_SHUT_BIT_MASK`.
const CLN_SHUT_BIT:         u32 = 0x0800_0000;

/// Geometry-query ioctl on the block_writes channel. Matches
/// `nvme::IOCTL_NVME_NS_INFO`. Arg is 13 B: in=`nsid:u32` / out=
/// `ns_size:u64 + ns_lbads:u8`. A non-nvme consumer returns ENOSYS,
/// which fat32 treats as "geometry info unavailable, proceed".
const IOCTL_NVME_NS_INFO:   u32 = 0x4E56_0001;

/// Expected LBA data-size shift. LBA size = 2^ns_lbads; fat32 only
/// supports 512 B LBAs, i.e. `ns_lbads == 9`.
const EXPECTED_LBADS:       u8 = 9;

/// Operation tag inside the 20-byte write-request header. v1 only
/// supports op=1 (single-block WRITE). Must match `nvme::pump_requests`.
const REQ_OP_WRITE:         u32 = 1;

/// Outbound write-request header size on `block_writes`:
///   op:u32 | lba:u64 | nlb:u32 | nsid:u32    (20 bytes)
/// `nsid == 0` lets the consumer use its driver-wide default namespace.
const REQ_HDR_SIZE:         usize = 20;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::Fat32State;
    use super::SCHEMA_MAX;
    use super::p_u32;

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

        // `write_file` accepts a user-friendly "name.ext" string (e.g.
        // "boot.txt"). Converted to FAT 8.3 short-name form (8 name
        // bytes + 3 extension bytes, space-padded, uppercased) so a
        // raw 11-byte compare against FileEntry.short_name finds it.
        3, write_file, str, 0
            => |s, d, len| {
                let mut name: [u8; 11] = [b' '; 11];
                let mut dot_pos = len;
                let mut i = 0usize;
                while i < len {
                    if *d.add(i) == b'.' { dot_pos = i; break; }
                    i += 1;
                }
                let n_len = if dot_pos > 8 { 8 } else { dot_pos };
                let mut j = 0usize;
                while j < n_len {
                    let b = *d.add(j);
                    name[j] = if b >= b'a' && b <= b'z' { b - 32 } else { b };
                    j += 1;
                }
                if dot_pos < len {
                    let ext_avail = len - dot_pos - 1;
                    let e_len = if ext_avail > 3 { 3 } else { ext_avail };
                    let mut k = 0usize;
                    while k < e_len {
                        let b = *d.add(dot_pos + 1 + k);
                        name[8 + k] = if b >= b'a' && b <= b'z' { b - 32 } else { b };
                        k += 1;
                    }
                }
                let dst = s.write_file.as_mut_ptr();
                let mut x = 0usize;
                while x < 11 {
                    *dst.add(x) = name[x];
                    x += 1;
                }
                // Flag the write as enabled when any bytes were given.
                s.write_file_len = if len > 0 { 11 } else { 0 };
            };

        // The tool's TLV encoder splits strings longer than 255 bytes
        // into multiple entries with the same tag, so the handler
        // appends each chunk rather than overwriting. Accumulates up
        // to WRITE_DATA_MAX.
        4, write_data, str, 0
            => |s, d, len| {
                let already = s.write_data_len as usize;
                let room = super::WRITE_DATA_MAX.saturating_sub(already);
                let n = if len > room { room } else { len };
                let dst = s.write_data.as_mut_ptr().add(already);
                let mut i = 0;
                while i < n {
                    *dst.add(i) = *d.add(i);
                    i += 1;
                }
                s.write_data_len = (already + n) as u16;
            };

        5, namespace, u32, 1
            => |s, d, len| { s.namespace = p_u32(d, len, 0, 1); };

        // When non-zero, overrides `write_data_len` as the total
        // payload length to write. Used together with `seed_pattern=1`
        // to lay down a multi-MB file from a deterministic synthesizer
        // (no inline buffer required). When `seed_pattern=0` and
        // `write_size > write_data_len`, the trailing region is
        // zero-filled by `stage_data_batch`'s existing pad path.
        6, write_size, u32, 0
            => |s, d, len| { s.write_size = p_u32(d, len, 0, 0); };

        // 0 = inline `write_data` source (used by short test fixtures).
        // 1 = synthetic pattern source (`byte_at(off) = (off & 0xFF)`),
        //     enabling multi-MB writes without inflating module state.
        //     Caller must also set `write_size` to the desired byte
        //     count; `write_data_len` is ignored.
        7, seed_pattern, u8, 0
            => |s, d, len| { s.seed_pattern = super::p_u8(d, len, 0, 0); };
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
    dir_lba:    u32,
    /// Byte offset of the 32-byte entry inside `dir_lba`.
    dir_offset: u16,
    /// Short 8.3 name as stored in the directory entry: 8 name bytes
    /// padded with spaces, then 3 extension bytes. Used by the write
    /// path to locate a file by name.
    short_name: [u8; 11],
    _pad:       u8,
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
/// HTTP serving N parallel files needs at least N slots; 8 covers
/// typical deployments (HTML + WASM + range-reads + headroom).
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
    /// Sector index within current_cluster (0..sectors_per_cluster).
    sector_in_cluster: u8,
    _pad: [u8; 2],
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
    /// Most recently fetched 512-byte sector for this FD.
    scratch_block: [u8; BLOCK_SIZE],
}

impl OpenFile {
    const fn empty() -> Self {
        Self {
            in_use: 0,
            sector_in_cluster: 0,
            _pad: [0; 2],
            current_cluster: 0,
            offset: 0,
            size: 0,
            start_cluster: 0,
            scratch_avail: 0,
            scratch_pos: 0,
            scratch_block: [0u8; BLOCK_SIZE],
        }
    }
}

// ============================================================================
// Module State
// ============================================================================

#[repr(C)]
struct Fat32State {
    syscalls: *const SyscallTable,
    /// Channel handle for the upstream block source (nvme.blocks /
    /// sd.blocks). Every sector read — init MBR/boot/dir, write-path
    /// FAT walks, FS_CONTRACT sync block reads — flows through this
    /// channel via ioctls on the producer side.
    in_chan: i32,

    // FAT32 geometry (from boot sector)
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    fat_size_32: u32,
    root_cluster: u32,
    fat_start_sector: u32,
    data_start_sector: u32,
    partition_lba: u32,
    /// Sector number of the FSINFO sector relative to `partition_lba`,
    /// from BPB_FSInfo (boot-sector offset 48). `0` or `0xFFFF` means
    /// the volume has no FSINFO sector and the free-cluster bookkeeping
    /// is skipped on alloc.
    fsinfo_sector: u16,

    // State machine
    init_phase: Fat32InitPhase,

    // File enumeration — populated at init when `path:` is non-empty
    // so the write path (`WS_SCAN`) can locate `write_file:` by 8.3
    // short name. The FS_CONTRACT read path walks the directory tree
    // on demand and does not consult `files`.
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

    // Block I/O state — single shared `block_buf` for init walks
    // and the write path's FAT/dir reads. The FS dispatch maintains
    // its own per-FD scratch in `OpenFile`.
    pending_block: u32,
    block_offset: u16,
    read_fill: u16,
    block_buf: [u8; BLOCK_SIZE],

    /// Diagnostic tick counter — drives the periodic heartbeat
    /// emitted by `module_step` so init-time state is still visible
    /// after `log_net` starts streaming.
    tick_count: u32,

    // ── Write state machine ────────────────────────────────────────
    //
    // After init completes and the target file is located (by short
    // 8.3 name), fat32 overwrites the file starting at offset 0 with
    // `write_data[..write_data_len]`. The state machine handles:
    //   * multi-sector writes within a single cluster
    //   * multi-cluster writes walking an existing FAT chain
    //   * growing the FAT chain by allocating new clusters when the
    //     existing allocation is too short
    //   * mirroring every FAT sector write to FAT2 when num_fats > 1
    //   * updating the file's dir-entry size field if the write grew
    //     the file past its previous size
    //
    // `write_file_len == 0` (empty `write_file` param) disables the
    // entire path — the module boots read-only.
    //
    // The outbound packet format matches the nvme module's `requests`
    // port: REQ_HDR_SIZE header { op:u32=1, lba:u64, nlb:u32, nsid:u32 }
    // followed by nlb * 512 B payload.
    write_out_chan:    i32,
    /// NVMe namespace id stamped into every WRITE header. `0` forwards
    /// to the consumer's driver-wide default (nvme falls back to its
    /// `namespace` param in that case).
    namespace:         u32,
    write_state:       u8,   // current WS_* discriminant
    write_file_len:    u8,   // 0 = disabled (no `write_file` param given)
    /// 0 = inline `write_data` source (default, capped at `WRITE_DATA_MAX`).
    /// 1 = synthetic pattern source for `seed_byte_at(off)`. Combined
    /// with a non-zero `write_size`, lets a single fat32 instance lay
    /// down a multi-MB file without inflating module state past
    /// `WRITE_DATA_MAX`. Verifier on the read-back side recomputes
    /// the same pattern to confirm byte-exact write fidelity.
    seed_pattern:      u8,
    _pad_w0:           u8,
    write_file:        [u8; 11],
    _pad_w1:           u8,
    write_data_len:    u16,
    _pad_w2:           u16,
    write_data:        [u8; WRITE_DATA_MAX],

    /// When > 0, the write loop walks this many bytes total instead
    /// of `write_data_len`. The bytes come from `seed_byte_at` if
    /// `seed_pattern == 1` or from `write_data` (zero-padded past
    /// `write_data_len`) otherwise. Caps at `u32::MAX`; practical
    /// values are bounded by free-cluster availability on the disk.
    write_size:        u32,

    // Target file (resolved once during WS_Scan).
    w_target_first_cluster: u32,
    w_target_old_size:      u32,
    w_target_dir_lba:       u32,
    w_target_dir_offset:    u16,
    _pad_wt:                u16,

    // Write-progress counters.
    w_bytes_written:       u32, // bytes of `write_data` already pushed
    w_current_cluster:     u32, // cluster currently being written into
    w_sector_in_cluster:   u8,  // sector offset within current_cluster
    _pad_wp:               [u8; 3],

    // Cluster-allocation scratch (used by AllocInit..LinkWait).
    w_prev_cluster:        u32, // last cluster of the existing chain (parent of the new allocation)
    w_new_cluster:         u32, // cluster just allocated (marked EOC)
    w_alloc_probe:         u32, // next cluster number to test in the linear free-cluster scan
    w_fat_sector_in_buf:   u32, // which absolute FAT LBA is currently cached in block_buf, or 0
    w_fat_copy_idx:        u8,  // 0 = primary FAT, 1 = mirror FAT (only on num_fats=2)
    w_patched_prev_inline: u8,  // 1 = prev_cluster's entry was in the same sector as new_cluster, already linked
    w_fsinfo_pending:      u8,  // 1 = an FSINFO update is owed once the post-alloc FAT writes drain
    _pad_wa:               u8,

    // Post-write size patch.
    w_new_size:            u32,

    // Outbound packet staging: REQ_HDR_SIZE request header + up to
    // MAX_WRITE_NLB sectors of payload. Filled before transitioning
    // into WS_SendPacket; drained across ticks (channel ring may take
    // several ticks to accept the full packet under backpressure).
    w_outbuf:         [u8; REQ_HDR_SIZE + MAX_WRITE_NLB as usize * BLOCK_SIZE],
    w_outbuf_sent:    u16,
    /// Total bytes in the current packet (REQ_HDR_SIZE + nlb * BLOCK_SIZE).
    /// Set by stage_header and consumed by drain_packet so the drain
    /// knows when the packet is fully on the wire.
    w_outbuf_len:     u16,
    /// NLB of the in-flight data batch. Used by ws_after_sector to
    /// advance w_bytes_written and w_sector_in_cluster by `nlb` sectors.
    w_batch_nlb:      u16,
    w_return_state:   u8,  // where to go after w_outbuf drains
    _pad_w_ret:       u8,

    /// Open-file slots backing the FS_CONTRACT dispatch path. Each
    /// slot is independent — multiple consumers can open multiple
    /// files concurrently (HTTP parallel range reads, etc.). Block
    /// I/O is shared (single nvme.blocks channel) but the FS_READ
    /// path uses `IOCTL_BLOCKS_READ_LBAS_SYNC` which is fully
    /// synchronous and serializes within each dispatch call.
    open_files: [OpenFile; MAX_OPEN_FILES],

    /// Hot-path counters emitted as `[fat32] tlm dt=… rx=… tx=… idle=… bp=…`
    /// every `FAT32_TLM_PERIOD` steps. `rx` is bytes consumed from
    /// the upstream blocks channel (init walks + write-path FAT/dir
    /// reads); `tx` and `bp` are unused on this path because reads
    /// flow through the synchronous FS_CONTRACT dispatch.
    tlm: TlmCounters,
    tlm_scratch: [u8; TLM_LINE_BUF_SIZE],
}

/// Cadence for the `[fat32] tlm` line. Matches the `hb` heartbeat
/// period so the two can be correlated by the host parser.
const FAT32_TLM_PERIOD: u32 = 5000;

impl Fat32State {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.in_chan = -1;
        self.bytes_per_sector = 512;
        self.sectors_per_cluster = 0;
        self.reserved_sectors = 0;
        self.num_fats = 0;
        self.fat_size_32 = 0;
        self.root_cluster = 0;
        self.fat_start_sector = 0;
        self.data_start_sector = 0;
        self.partition_lba = 0;
        self.fsinfo_sector = 0;
        self.init_phase = Fat32InitPhase::Idle;
        self.file_count = 0;
        self.dir_cluster = 0;
        self.dir_sector_in_cluster = 0;
        self.dir_entry_in_sector = 0;
        self.dir_mode = 0;
        self.path_pos = 0;
        self.pending_block = 0;
        self.block_offset = 0;
        self.read_fill = 0;
        self.tick_count = 0;
        self.write_out_chan = -1;
        self.namespace = 1;
        self.write_state = WS_IDLE;
        self.write_file_len = 0;
        self.write_data_len = 0;
        self.write_size = 0;
        self.seed_pattern = 0;
        self.w_target_first_cluster = 0;
        self.w_target_old_size = 0;
        self.w_target_dir_lba = 0;
        self.w_target_dir_offset = 0;
        self.w_bytes_written = 0;
        self.w_current_cluster = 0;
        self.w_sector_in_cluster = 0;
        self.w_prev_cluster = 0;
        self.w_new_cluster = 0;
        self.w_alloc_probe = 2;
        self.w_fat_sector_in_buf = 0;
        self.w_fat_copy_idx = 0;
        self.w_patched_prev_inline = 0;
        self.w_fsinfo_pending = 0;
        self.w_new_size = 0;
        self.w_outbuf_sent = 0;
        self.w_outbuf_len = 0;
        self.w_batch_nlb = 0;
        self.w_return_state = WS_DONE;
        let mut i = 0usize;
        while i < MAX_OPEN_FILES {
            self.open_files[i] = OpenFile::empty();
            i += 1;
        }
        // path, pattern, files, write_file, write_data, w_outbuf are
        // zeroed by the kernel allocator.
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

/// Convert cluster number to first sector number
#[inline(always)]
fn cluster_to_sector(s: &Fat32State, cluster: u32) -> u32 {
    s.data_start_sector + (cluster - 2) * (s.sectors_per_cluster as u32)
}

/// Get sector containing FAT entry for given cluster
/// Note: uses wrapping_div to avoid panic; bytes_per_sector is always valid after boot
#[inline(always)]
fn fat_sector_for_cluster(s: &Fat32State, cluster: u32) -> u32 {
    let bps = s.bytes_per_sector as u32;
    if bps == 0 { return s.fat_start_sector; }
    s.fat_start_sector.wrapping_add((cluster.wrapping_mul(4)).wrapping_div(bps))
}

/// Get offset within FAT sector for given cluster
/// Note: uses wrapping_rem to avoid panic; bytes_per_sector is always valid after boot
#[inline(always)]
fn fat_offset_for_cluster(s: &Fat32State, cluster: u32) -> usize {
    let bps = s.bytes_per_sector as u32;
    if bps == 0 { return 0; }
    ((cluster.wrapping_mul(4)).wrapping_rem(bps)) as usize
}

#[inline(always)]
unsafe fn log_info(s: &Fat32State, msg: &[u8]) {
    dev_log(s.sys(), 3, msg.as_ptr(), msg.len());
}

/// Request SD to seek to a block
#[inline]
unsafe fn seek_sd(s: &Fat32State, block: u32) -> i32 {
    let mut pos = block;
    let pos_ptr = &mut pos as *mut u32 as *mut u8;
    dev_channel_ioctl(s.sys(), s.in_chan, IOCTL_NOTIFY, pos_ptr)
}

/// Flush SD's output buffer (our input)
#[inline]
unsafe fn flush_input(s: &Fat32State) -> i32 {
    dev_channel_ioctl(s.sys(), s.in_chan, IOCTL_FLUSH, core::ptr::null_mut())
}

// ============================================================================
// Boot Sector Parsing
// ============================================================================

/// Parse boot sector and extract FAT32 geometry
/// Note: uses pointer arithmetic to avoid bounds check panics.
unsafe fn parse_boot_sector(s: &mut Fat32State) -> bool {
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

    // Calculate derived values (absolute sectors, including partition offset)
    s.fat_start_sector = s.partition_lba + s.reserved_sectors as u32;
    s.data_start_sector = s.fat_start_sector + (s.num_fats as u32) * s.fat_size_32;

    // Sanity checks
    if s.bytes_per_sector != 512 {
        return false;
    }
    if s.sectors_per_cluster == 0 {
        return false;
    }
    if s.root_cluster < 2 {
        return false;
    }

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
#[inline]
unsafe fn try_read_block(s: &mut Fat32State) -> i32 {
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
    if c >= b'a' && c <= b'z' { c - 32 } else { c }
}

/// Compare a name (with optional dot) against an 8.3 directory entry.
/// `name` points to name bytes, `name_len` is its length.
/// `entry` points to the 11-byte 8.3 filename field.
unsafe fn matches_83(name: *const u8, name_len: usize, entry: *const u8) -> bool {
    // Find dot position
    let mut dot = name_len;
    let mut i = 0;
    while i < name_len {
        if *name.add(i) == b'.' { dot = i; break; }
        i += 1;
    }

    // Name part (8 bytes, space-padded)
    i = 0;
    while i < 8 {
        let expected = if i < dot { to_upper(*name.add(i)) } else { b' ' };
        if *entry.add(i) != expected { return false; }
        i += 1;
    }

    // Extension part (3 bytes, space-padded)
    let ext_start = if dot < name_len { dot + 1 } else { name_len };
    let ext_len = name_len - ext_start;
    i = 0;
    while i < 3 {
        let expected = if i < ext_len { to_upper(*name.add(ext_start + i)) } else { b' ' };
        if *entry.add(8 + i) != expected { return false; }
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
        if *entry.add(8 + i) != to_upper(*pp.add(pi)) { return false; }
        i += 1;
        pi += 1;
    }
    while i < 3 {
        if *entry.add(8 + i) != b' ' { return false; }
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
        if ext_matches(pp, 2, entry) { return true; }
        // Scan for comma-separated alternatives
        let mut pi = 2usize;
        while pi < 15 && *pp.add(pi) != 0 {
            if *pp.add(pi) == b',' {
                if ext_matches(pp, pi + 1, entry) { return true; }
            }
            pi += 1;
        }
        return false;
    }

    // Exact 8.3 match
    let mut plen = 0usize;
    while plen < 15 && *pp.add(plen) != 0 { plen += 1; }
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

    s.dir_mode = if *pp.add(s.path_pos as usize) == 0 { 1 } else { 0 };
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
// `IOCTL_BLOCKS_READ_LBAS_SYNC` against whatever block source is
// wired to `s.in_chan` (nvme, sd, …). Up to MAX_OPEN_FILES concurrent
// opens; per-FD state lives in `OpenFile`. Random-access read latency
// is bounded by the producer's per-command device latency since the
// block read is fully synchronous inside the dispatch call.

// FS opcodes from the layered ABI.
const FS_OPEN:  u32 = 0x0900;
const FS_READ:  u32 = 0x0901;
const FS_SEEK:  u32 = 0x0902;
const FS_CLOSE: u32 = 0x0903;
const FS_STAT:  u32 = 0x0904;

/// Synchronously fetch a 512-byte sector at `lba` into `out`. Returns
/// 0 on success, negative errno otherwise. The block source must
/// implement `IOCTL_BLOCKS_READ_LBAS_SYNC` — nvme does; sd does not.
unsafe fn fs_sync_read_sector(s: &Fat32State, lba: u32, out: *mut u8) -> i32 {
    let mut arg = [0u8; 16];
    let lba_b = lba.to_le_bytes();
    arg[0] = lba_b[0]; arg[1] = lba_b[1]; arg[2] = lba_b[2]; arg[3] = lba_b[3];
    arg[4] = 1; arg[5] = 0; // nlb = 1
    let buf_b = (out as u64).to_le_bytes();
    let mut i = 0usize;
    while i < 8 {
        arg[8 + i] = buf_b[i];
        i += 1;
    }
    dev_channel_ioctl(
        s.sys(),
        s.in_chan,
        IOCTL_BLOCKS_READ_LBAS_SYNC,
        arg.as_mut_ptr(),
    )
}

/// Read one FAT entry synchronously; returns the next cluster
/// number (28-bit) or `FAT32_EOC` on chain end / error.
unsafe fn fs_read_fat_entry(s: &mut Fat32State, cluster: u32) -> u32 {
    let fat_lba = fat_sector_for_cluster(s, cluster);
    let mut buf = [0u8; BLOCK_SIZE];
    let rc = fs_sync_read_sector(s, fat_lba, buf.as_mut_ptr());
    if rc != 0 { return FAT32_EOC; }
    let off = fat_offset_for_cluster(s, cluster);
    if off + 4 > BLOCK_SIZE { return FAT32_EOC; }
    let raw = u32::from_le_bytes([
        buf[off], buf[off + 1], buf[off + 2], buf[off + 3],
    ]) & FAT32_MASK;
    if raw == 0 || raw >= FAT32_EOC { FAT32_EOC } else { raw }
}

/// Convert a path component to a FAT 8.3 short name (11 bytes,
/// space-padded, uppercase). Returns true on success.
fn fs_path_to_short_name(name: &[u8], out: &mut [u8; 11]) -> bool {
    *out = [b' '; 11];
    if name.is_empty() || name.len() > 12 { return false; }
    let mut dot: usize = name.len();
    let mut i = 0usize;
    while i < name.len() {
        if name[i] == b'.' { dot = i; break; }
        i += 1;
    }
    let n_len = if dot > 8 { 8 } else { dot };
    let mut j = 0usize;
    while j < n_len {
        let c = name[j];
        out[j] = if (b'a'..=b'z').contains(&c) { c - 32 } else { c };
        j += 1;
    }
    if dot < name.len() {
        let ext = &name[dot + 1..];
        let e_len = if ext.len() > 3 { 3 } else { ext.len() };
        let mut k = 0usize;
        while k < e_len {
            let c = ext[k];
            out[8 + k] = if (b'a'..=b'z').contains(&c) { c - 32 } else { c };
            k += 1;
        }
    }
    true
}

/// Result of a successful path resolution.
#[derive(Clone, Copy)]
struct ResolvedFile {
    start_cluster: u32,
    size: u32,
}

/// Search the directory rooted at `dir_first_cluster` for an entry
/// matching the 8.3 short name `want`. Walks every sector of every
/// cluster in the dir's chain, fetching synchronously via the
/// `IOCTL_BLOCKS_READ_LBAS_SYNC` block-source ioctl. Returns the
/// matched entry's (start_cluster, size, attr) — caller checks
/// `attr & ATTR_DIRECTORY` to decide whether to descend or stop.
unsafe fn fs_dir_lookup(
    s: &mut Fat32State,
    dir_first_cluster: u32,
    want: &[u8; 11],
) -> Option<(u32, u32, u8)> {
    if dir_first_cluster < 2 { return None; }
    let entries_per_sector = BLOCK_SIZE / DIR_ENTRY_SIZE;
    let spc = s.sectors_per_cluster as u32;
    if spc == 0 { return None; }
    let mut cur_cluster = dir_first_cluster;
    let mut buf = [0u8; BLOCK_SIZE];

    loop {
        let cluster_first_sector = cluster_to_sector(s, cur_cluster);
        let mut sec = 0u32;
        while sec < spc {
            let lba = cluster_first_sector + sec;
            if fs_sync_read_sector(s, lba, buf.as_mut_ptr()) != 0 {
                return None;
            }
            let mut e = 0usize;
            while e < entries_per_sector {
                let off = e * DIR_ENTRY_SIZE;
                let first = buf[off];
                if first == 0x00 {
                    // End-of-directory marker — no further entries
                    // anywhere in the chain.
                    return None;
                }
                // 0xE5 = deleted; LFN entries set attr == 0x0F; volume
                // labels carry the VOLUME_ID bit. Skip all three.
                if first != 0xE5 {
                    let attr = buf[off + 11];
                    if attr != ATTR_LONG_NAME && (attr & ATTR_VOLUME_ID) == 0 {
                        let mut name = [0u8; 11];
                        name.copy_from_slice(&buf[off..off + 11]);
                        if &name == want {
                            let cluster_hi = read_u16_le(&buf, off + 20) as u32;
                            let cluster_lo = read_u16_le(&buf, off + 26) as u32;
                            let start_cluster = (cluster_hi << 16) | cluster_lo;
                            let size = read_u32_le(&buf, off + 28);
                            return Some((start_cluster, size, attr));
                        }
                    }
                }
                e += 1;
            }
            sec += 1;
        }
        // Cluster exhausted — follow FAT chain to next cluster.
        let next = fs_read_fat_entry(s, cur_cluster);
        if next >= FAT32_EOC { return None; }
        cur_cluster = next;
    }
}

/// Resolve an absolute FAT32 path (e.g. `/web/INDEX.HTM`) to its
/// `(start_cluster, size)`. Walks each path component synchronously
/// through `fs_dir_lookup`. Returns None on ENOENT or malformed
/// path. Path components must already be in 8.3-compatible form
/// (case-folded internally by `fs_path_to_short_name`).
unsafe fn fs_resolve_path(s: &mut Fat32State, path: &[u8]) -> Option<ResolvedFile> {
    if s.init_phase != Fat32InitPhase::Done { return None; }
    if s.root_cluster < 2 { return None; }
    if path.is_empty() { return None; }
    // Walk past leading slashes.
    let mut pos = 0usize;
    while pos < path.len() && path[pos] == b'/' { pos += 1; }
    if pos >= path.len() { return None; } // bare "/"

    let mut cur_cluster = s.root_cluster;
    loop {
        // Extract the next component up to the next '/' or end-of-string.
        let start = pos;
        while pos < path.len() && path[pos] != b'/' { pos += 1; }
        let comp = &path[start..pos];
        if comp.is_empty() { return None; }
        let mut want = [b' '; 11];
        if !fs_path_to_short_name(comp, &mut want) { return None; }
        let (sc, sz, attr) = fs_dir_lookup(s, cur_cluster, &want)?;
        // Skip trailing slashes.
        while pos < path.len() && path[pos] == b'/' { pos += 1; }
        let is_final = pos >= path.len();
        if is_final {
            // The terminal component must be a regular file —
            // directories aren't openable through FS_OPEN.
            if (attr & ATTR_DIRECTORY) != 0 { return None; }
            return Some(ResolvedFile { start_cluster: sc, size: sz });
        }
        // Intermediate component must be a directory.
        if (attr & ATTR_DIRECTORY) == 0 { return None; }
        cur_cluster = sc;
    }
}

/// FS_OPEN: resolve the absolute path through the FAT32 tree
/// (`fs_resolve_path` walks the dir chain synchronously via
/// `IOCTL_BLOCKS_READ_LBAS_SYNC`), then allocate an `OpenFile` slot
/// populated with the file's `start_cluster` + `size`. Returns the
/// slot index as the FD, or a negative errno.
unsafe fn fs_op_open(s: &mut Fat32State, arg: *const u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len == 0 { return E_INVAL; }
    if s.init_phase != Fat32InitPhase::Done { return E_AGAIN; }
    let path = core::slice::from_raw_parts(arg, arg_len);
    let resolved = match fs_resolve_path(s, path) {
        Some(r) => r,
        None => return -2, // ENOENT
    };
    // Allocate slot.
    let mut slot: i32 = -1;
    let mut k = 0usize;
    while k < MAX_OPEN_FILES {
        if s.open_files[k].in_use == 0 {
            slot = k as i32;
            break;
        }
        k += 1;
    }
    if slot < 0 { return -23; } // ENFILE
    let of = &mut s.open_files[slot as usize];
    of.in_use = 1;
    of.start_cluster = resolved.start_cluster;
    of.current_cluster = resolved.start_cluster;
    of.size = resolved.size;
    of.offset = 0;
    of.sector_in_cluster = 0;
    of.scratch_avail = 0;
    of.scratch_pos = 0;
    slot
}

/// FS_READ: drain `scratch_block` first, then synchronously fetch
/// the next sector (walking the FAT chain when crossing a cluster
/// boundary). Returns bytes read on success; 0 at EOF; negative
/// errno on error.
unsafe fn fs_op_read(s: &mut Fat32State, handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len == 0 { return E_INVAL; }
    if s.init_phase != Fat32InitPhase::Done { return E_AGAIN; }
    let slot_idx = handle as usize;
    if slot_idx >= MAX_OPEN_FILES { return E_INVAL; }
    if s.open_files[slot_idx].in_use == 0 { return E_INVAL; }
    let bps = s.bytes_per_sector as u32;
    let spc = s.sectors_per_cluster as u32;
    if bps == 0 || spc == 0 { return E_AGAIN; }

    let mut written: usize = 0;
    let max = arg_len;
    while written < max {
        let of = &mut s.open_files[slot_idx];
        let remaining_in_file = of.size.saturating_sub(of.offset);
        if remaining_in_file == 0 { break; }
        if of.scratch_avail == 0 {
            // Fetch the current sector.
            let sector = cluster_to_sector(s, s.open_files[slot_idx].current_cluster)
                + (s.open_files[slot_idx].sector_in_cluster as u32);
            let buf_ptr = s.open_files[slot_idx].scratch_block.as_mut_ptr();
            let rc = fs_sync_read_sector(s, sector, buf_ptr);
            if rc != 0 { return rc; }
            let of2 = &mut s.open_files[slot_idx];
            of2.scratch_avail = bps as u16;
            of2.scratch_pos = 0;
        }
        let of3 = &mut s.open_files[slot_idx];
        let avail = of3.scratch_avail as u32;
        let want = (max - written) as u32;
        let cap = if remaining_in_file < want { remaining_in_file } else { want };
        let take = if avail < cap { avail } else { cap } as usize;
        // Copy from scratch_block into caller's buffer.
        core::ptr::copy_nonoverlapping(
            of3.scratch_block.as_ptr().add(of3.scratch_pos as usize),
            arg.add(written),
            take,
        );
        of3.scratch_pos = of3.scratch_pos.wrapping_add(take as u16);
        of3.scratch_avail = of3.scratch_avail.wrapping_sub(take as u16);
        of3.offset = of3.offset.wrapping_add(take as u32);
        written += take;
        if of3.scratch_avail == 0 {
            // Advance to the next sector / cluster.
            of3.sector_in_cluster = of3.sector_in_cluster.wrapping_add(1);
            if (of3.sector_in_cluster as u32) >= spc {
                of3.sector_in_cluster = 0;
                let cur = of3.current_cluster;
                let next = fs_read_fat_entry(s, cur);
                let of4 = &mut s.open_files[slot_idx];
                if next >= FAT32_EOC {
                    // No more clusters; file ends here. Cap offset to size
                    // and let the next iteration exit on remaining_in_file == 0.
                    of4.offset = of4.size;
                } else {
                    of4.current_cluster = next;
                }
            }
        }
    }
    written as i32
}

/// FS_SEEK: rewind to start_cluster, walk forward to the target
/// cluster, set sector + scratch position. `arg` is `[offset: i32 LE]`
/// (matching the Linux FS dispatch). Returns the resulting offset on
/// success or negative errno.
unsafe fn fs_op_seek(s: &mut Fat32State, handle: i32, arg: *const u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 4 { return E_INVAL; }
    let slot_idx = handle as usize;
    if slot_idx >= MAX_OPEN_FILES { return E_INVAL; }
    if s.open_files[slot_idx].in_use == 0 { return E_INVAL; }
    let raw = i32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
    if raw < 0 { return E_INVAL; }
    let target = raw as u32;
    let bps = s.bytes_per_sector as u32;
    let spc = s.sectors_per_cluster as u32;
    if bps == 0 || spc == 0 { return E_AGAIN; }
    let cluster_bytes = bps * spc;
    let target_cluster_idx = target / cluster_bytes;
    let target_sector = ((target % cluster_bytes) / bps) as u8;

    let start = s.open_files[slot_idx].start_cluster;
    let mut cluster = start;
    let mut walked = 0u32;
    while walked < target_cluster_idx {
        let next = fs_read_fat_entry(s, cluster);
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
    let of = &mut s.open_files[slot_idx];
    of.current_cluster = cluster;
    of.sector_in_cluster = target_sector;
    of.offset = target;
    // scratch is reset; the next FS_READ fetches the target sector.
    of.scratch_avail = 0;
    of.scratch_pos = 0;
    target as i32
}

/// FS_CLOSE: free the OpenFile slot.
unsafe fn fs_op_close(s: &mut Fat32State, handle: i32) -> i32 {
    let slot_idx = handle as usize;
    if slot_idx >= MAX_OPEN_FILES { return E_INVAL; }
    if s.open_files[slot_idx].in_use == 0 { return E_INVAL; }
    s.open_files[slot_idx] = OpenFile::empty();
    0
}

/// FS_STAT: write `[size: u32 LE, mtime: u32 LE]` (8 bytes) into
/// `arg`. mtime is reported as 0 — fat32 does not surface modification
/// times through this dispatch.
unsafe fn fs_op_stat(s: &Fat32State, handle: i32, arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < 8 { return E_INVAL; }
    let slot_idx = handle as usize;
    if slot_idx >= MAX_OPEN_FILES { return E_INVAL; }
    if s.open_files[slot_idx].in_use == 0 { return E_INVAL; }
    let size = s.open_files[slot_idx].size;
    let s_b = size.to_le_bytes();
    *arg = s_b[0];
    *arg.add(1) = s_b[1];
    *arg.add(2) = s_b[2];
    *arg.add(3) = s_b[3];
    *arg.add(4) = 0; *arg.add(5) = 0; *arg.add(6) = 0; *arg.add(7) = 0;
    0
}

#[no_mangle]
#[link_section = ".text.module_provider_dispatch"]
#[export_name = "module_provider_dispatch"]
pub unsafe extern "C" fn fat32_fs_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if state.is_null() { return E_INVAL; }
    let s = &mut *(state as *mut Fat32State);
    match opcode {
        FS_OPEN  => fs_op_open(s, arg as *const u8, arg_len),
        FS_READ  => fs_op_read(s, handle, arg, arg_len),
        FS_SEEK  => fs_op_seek(s, handle, arg as *const u8, arg_len),
        FS_CLOSE => fs_op_close(s, handle),
        FS_STAT  => fs_op_stat(s, handle, arg, arg_len),
        _ => -38, // ENOSYS
    }
}

#[no_mangle]
#[link_section = ".text.module_provides_contract"]
pub extern "C" fn module_provides_contract() -> u32 {
    0x0009 // FS
}

// ============================================================================
// Exported PIC Module Interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<Fat32State>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
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
        // `block_writes` (output port 0) carries write requests to the
        // upstream block source; the wiring stays inert when the YAML
        // doesn't connect it.
        s.write_out_chan = dev_channel_port(&*s.syscalls, 1, 0);

        // Parse params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }

        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
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
        if s.tick_count % 5000 == 0 {
            let mut msg = [0u8; 64];
            let p = msg.as_mut_ptr();
            let prefix = b"[fat32] hb init=";
            core::ptr::copy_nonoverlapping(prefix.as_ptr(), p, prefix.len());
            let mut pos = prefix.len();
            let ip = s.init_phase as u8;
            *p.add(pos)     = b'0' + (ip / 10);
            *p.add(pos + 1) = b'0' + (ip % 10);
            pos += 2;
            let fc_tag = b" files=";
            core::ptr::copy_nonoverlapping(fc_tag.as_ptr(), p.add(pos), fc_tag.len());
            pos += fc_tag.len();
            let fc = s.file_count.min(999);
            *p.add(pos)     = b'0' + ((fc / 100) % 10) as u8;
            *p.add(pos + 1) = b'0' + ((fc / 10)  % 10) as u8;
            *p.add(pos + 2) = b'0' + ( fc         % 10) as u8;
            pos += 3;
            // Write-path progress: current write_state discriminant
            // and bytes pushed so far. A stuck write is observable
            // from a frozen `ws=` / `bw=` pair across heartbeats.
            let ws_tag = b" ws=";
            core::ptr::copy_nonoverlapping(ws_tag.as_ptr(), p.add(pos), ws_tag.len());
            pos += ws_tag.len();
            let ws = s.write_state.min(99);
            *p.add(pos)     = b'0' + (ws / 10);
            *p.add(pos + 1) = b'0' + (ws % 10);
            pos += 2;
            let bw_tag = b" bw=";
            core::ptr::copy_nonoverlapping(bw_tag.as_ptr(), p.add(pos), bw_tag.len());
            pos += bw_tag.len();
            pos += fmt_u32_raw(p.add(pos), s.w_bytes_written);
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
        dev_tlm_maybe_emit(
            sys,
            b"[fat32]",
            &mut s.tlm,
            tick,
            FAT32_TLM_PERIOD,
            scratch_ptr,
            scratch_len,
        );
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

    // If a one-shot write is configured, run it before serving any
    // FS_CONTRACT reads so the write lands before downstream consumers
    // start fighting over the blocks channel. Enter the state machine
    // at WS_SCAN on first entry and stay until WS_DONE.
    if s.write_file_len > 0 && s.write_state != WS_DONE {
        if s.write_state == WS_IDLE {
            s.write_state = WS_NS_CHECK;
        }
        return write_step(s);
    }

    // Reads are served entirely by the FS_CONTRACT dispatch
    // (`fat32_fs_dispatch` exported below); the per-step path is idle
    // once init + the one-shot write are done.
    0
}

// ============================================================================
// Write-state helpers
// ============================================================================

/// Absolute LBA of the FAT sector containing a given cluster's entry,
/// for the `copy_idx`'th FAT (0 = primary, 1 = mirror on a 2-FAT vol).
#[inline]
fn fat_sector_abs(s: &Fat32State, cluster: u32, copy_idx: u8) -> u32 {
    let rel = fat_sector_for_cluster(s, cluster) - s.fat_start_sector;
    s.fat_start_sector
        .wrapping_add((copy_idx as u32).wrapping_mul(s.fat_size_32))
        .wrapping_add(rel)
}

/// Read a FAT32 entry from the in-buffer FAT sector. Caller must
/// ensure `block_buf` holds `fat_sector_abs(s, cluster, _)`.
#[inline]
unsafe fn read_fat_entry(s: &Fat32State, cluster: u32) -> u32 {
    let off = fat_offset_for_cluster(s, cluster);
    read_u32_le(&s.block_buf, off) & FAT32_MASK
}

/// Patch a FAT32 entry in the in-buffer FAT sector. Preserves the
/// top 4 reserved bits of the existing word.
#[inline]
unsafe fn patch_fat_entry(s: &mut Fat32State, cluster: u32, value: u32) {
    let off = fat_offset_for_cluster(s, cluster);
    let existing = read_u32_le(&s.block_buf, off);
    let merged = (existing & !FAT32_MASK) | (value & FAT32_MASK);
    let le = merged.to_le_bytes();
    let dst = s.block_buf.as_mut_ptr().add(off);
    *dst        = le[0];
    *dst.add(1) = le[1];
    *dst.add(2) = le[2];
    *dst.add(3) = le[3];
}

/// Write the 20-byte WRITE-request header { op, lba, nlb, nsid } at the
/// start of `w_outbuf`. Also records the full packet length
/// (REQ_HDR_SIZE + nlb * BLOCK_SIZE) so `drain_packet` knows when the
/// packet is fully on the wire.
unsafe fn stage_header(s: &mut Fat32State, lba: u32, nlb: u16) {
    let out = s.w_outbuf.as_mut_ptr();
    let op  = REQ_OP_WRITE.to_le_bytes();
    let lb  = (lba as u64).to_le_bytes();
    let nb  = (nlb as u32).to_le_bytes();
    let ns  = s.namespace.to_le_bytes();
    let mut i = 0usize;
    while i < 4 { *out.add(i)      = op[i]; i += 1; }
    i = 0;
    while i < 8 { *out.add(4 + i)  = lb[i]; i += 1; }
    i = 0;
    while i < 4 { *out.add(12 + i) = nb[i]; i += 1; }
    i = 0;
    while i < 4 { *out.add(16 + i) = ns[i]; i += 1; }
    s.w_outbuf_sent = 0;
    s.w_outbuf_len = (REQ_HDR_SIZE as u16) + (nlb as u16) * (BLOCK_SIZE as u16);
}

/// Stage a 1-sector WRITE whose payload is `payload_src[..BLOCK_SIZE]`.
/// Used for FAT / dir / FSINFO updates that always target exactly one
/// sector.
unsafe fn stage_packet(s: &mut Fat32State, lba: u32, payload_src: *const u8) {
    stage_header(s, lba, 1);
    let out = s.w_outbuf.as_mut_ptr();
    core::ptr::copy_nonoverlapping(payload_src, out.add(REQ_HDR_SIZE), BLOCK_SIZE);
}

/// Stage an N-sector WRITE whose payload starts at byte `off` of the
/// write source. Source selection:
///
///   * `seed_pattern == 1` — synthesize each byte via [`seed_byte_at`]
///     (deterministic, position-only), so the source is unbounded and
///     no inline buffer is needed for multi-MB writes.
///   * `seed_pattern == 0` — copy from `write_data[off..off+nlb*512]`,
///     zero-pad past `write_data_len` (the inline-buffer mode used by
///     short-fixture writes).
unsafe fn stage_data_batch(s: &mut Fat32State, lba: u32, nlb: u16, off: usize) {
    stage_header(s, lba, nlb);
    let out = s.w_outbuf.as_mut_ptr();
    let total = (nlb as usize) * BLOCK_SIZE;
    let dst = out.add(REQ_HDR_SIZE);

    if s.seed_pattern != 0 {
        // Synthetic pattern. Deterministic so a verifier (or fat32
        // read-back) can recompute and confirm byte-exact fidelity.
        let mut i = 0usize;
        while i < total {
            *dst.add(i) = seed_byte_at(off + i);
            i += 1;
        }
    } else {
        let wdl = s.write_data_len as usize;
        let avail = wdl.saturating_sub(off).min(total);
        if avail > 0 {
            let src = s.write_data.as_ptr().add(off);
            core::ptr::copy_nonoverlapping(src, dst, avail);
        }
        let mut z = avail;
        while z < total {
            *dst.add(z) = 0;
            z += 1;
        }
    }
}

/// Deterministic synthetic byte sequence. Encodes the byte offset
/// into both low and mid bits so a host-side verifier reading back
/// `N` bytes can recompute and compare byte-exact. Cheap (one xor +
/// shift per byte) so it doesn't dominate the write-stage path.
#[inline(always)]
const fn seed_byte_at(off: usize) -> u8 {
    ((off as u32) ^ ((off as u32) >> 8)) as u8
}

/// Total payload length for the current write — `write_size` if set,
/// else the inline `write_data` length. Used by the write state
/// machine for both the loop bound and the new-size computation.
#[inline(always)]
fn effective_write_size(s: &Fat32State) -> u32 {
    if s.write_size > 0 { s.write_size } else { s.write_data_len as u32 }
}

/// Drain `w_outbuf` through `write_out_chan`. Returns 1 when the
/// full packet (REQ_HDR_SIZE + nlb*512 B, tracked in `w_outbuf_len`)
/// is sent, 0 when partial (retry next tick), -1 on channel error
/// (non-E_AGAIN).
///
/// Writes are issued in sector-sized pieces because the kernel ring is
/// all-or-nothing per call (kernel/ringbuf.rs): a request larger than
/// the current free space is rejected with E_AGAIN outright. A one-
/// sector chunk fits inside the default 2 KB channel buffer so the
/// producer never has to know the downstream channel's capacity.
unsafe fn drain_packet(s: &mut Fat32State) -> i32 {
    const DRAIN_CHUNK: usize = BLOCK_SIZE;
    let total = s.w_outbuf_len as usize;
    let remaining = total - s.w_outbuf_sent as usize;
    let want = remaining.min(DRAIN_CHUNK);
    let src = s.w_outbuf.as_ptr().add(s.w_outbuf_sent as usize);
    let rc = (s.sys().channel_write)(s.write_out_chan, src, want);
    if rc == E_AGAIN {
        return 0;
    }
    if rc < 0 {
        return -1;
    }
    s.w_outbuf_sent += rc as u16;
    if s.w_outbuf_sent as usize >= total { 1 } else { 0 }
}

/// Log a hex-formatted 32-bit LBA with the given prefix.
unsafe fn log_lba(s: &Fat32State, prefix: &[u8], v: u32) {
    let mut msg = [0u8; 64];
    let p = msg.as_mut_ptr();
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), p, prefix.len());
    let mut pos = prefix.len();
    *p.add(pos) = b'0'; pos += 1;
    *p.add(pos) = b'x'; pos += 1;
    let mut bi = 0usize;
    while bi < 8 {
        let n = ((v >> (28 - bi * 4)) & 0xF) as u8;
        *p.add(pos) = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
        pos += 1;
        bi += 1;
    }
    dev_log(s.sys(), 3, p, pos);
}

/// Transition to `WS_SEND_PACKET`, remembering the next state to
/// resume at once the packet drains successfully.
#[inline(always)]
fn enter_send_packet(s: &mut Fat32State, resume_state: u8) {
    s.w_return_state = resume_state;
    s.write_state = WS_SEND_PACKET;
}

// ============================================================================
// Write state machine
// ============================================================================

/// Write state machine. Overwrites the contents of the named file
/// starting at offset 0 with `write_data[..write_data_len]`. Extends
/// the file when new size > old size (dir-entry size update + cluster
/// allocation to grow the FAT chain when needed).
///
/// See `WS_*` constants for state semantics. Each state does at most
/// one I/O action (seek, block-read, or packet emission) per tick.
unsafe fn write_step(s: &mut Fat32State) -> i32 {
    match s.write_state {
        WS_SCAN => ws_scan(s),
        WS_SEND_SECTOR => ws_send_sector(s),
        WS_AFTER_SECTOR => ws_after_sector(s),
        WS_WALK_FAT_READ => ws_walk_fat_read(s),
        WS_WALK_FAT_WAIT => ws_walk_fat_wait(s),
        WS_ALLOC_READ => ws_alloc_read(s),
        WS_ALLOC_WAIT => ws_alloc_wait(s),
        WS_ALLOC_WRITE => ws_alloc_write(s),
        WS_LINK_READ => ws_link_read(s),
        WS_LINK_WAIT => ws_link_wait(s),
        WS_LINK_WRITE => ws_link_write(s),
        WS_MIRROR_WRITE => ws_mirror_write(s),
        WS_DIR_READ => ws_dir_read(s),
        WS_DIR_WAIT => ws_dir_wait(s),
        WS_DIR_WRITE => ws_dir_write(s),
        WS_SEND_PACKET => ws_send_packet(s),
        WS_FSINFO_READ => ws_fsinfo_read(s),
        WS_FSINFO_WAIT => ws_fsinfo_wait(s),
        WS_FSINFO_WRITE => ws_fsinfo_write(s),
        WS_MARK_DIRTY_READ => ws_mark_fat_read(s, WS_MARK_DIRTY_WAIT),
        WS_MARK_DIRTY_WAIT => ws_mark_fat_wait(s, false),
        WS_MARK_DIRTY_WRITE => ws_mark_fat_write(s, false),
        WS_MARK_DIRTY_MIRROR => ws_mark_fat_mirror(s, false),
        WS_MARK_CLEAN_READ => ws_mark_fat_read(s, WS_MARK_CLEAN_WAIT),
        WS_MARK_CLEAN_WAIT => ws_mark_fat_wait(s, true),
        WS_MARK_CLEAN_WRITE => ws_mark_fat_write(s, true),
        WS_MARK_CLEAN_MIRROR => ws_mark_fat_mirror(s, true),
        WS_NS_CHECK => ws_ns_check(s),
        _ => 0, // WS_IDLE / WS_DONE / unknown
    }
}

/// Shared drain-then-resume step used by any state that emitted a
/// packet and needs to wait for the channel to accept the full packet.
unsafe fn ws_send_packet(s: &mut Fat32State) -> i32 {
    match drain_packet(s) {
        0 => 0, // partial — retry next tick
        1 => {
            s.write_state = s.w_return_state;
            2 // burst: advance into the resume state immediately
        }
        _ => {
            // Channel error (not E_AGAIN). Abort the write session —
            // leave downstream consumers to report the partial state.
            log_info(s, b"[fat32] write: chan err");
            s.write_state = WS_DONE;
            0
        }
    }
}

/// WS_SCAN: locate the target file by 8.3 short-name + prepare the
/// counters for the first data-sector write. Runs once.
unsafe fn ws_scan(s: &mut Fat32State) -> i32 {
    if s.write_out_chan < 0 {
        log_info(s, b"[fat32] write: no block_writes channel");
        s.write_state = WS_DONE;
        return 0;
    }

    let mut found: i32 = -1;
    let mut i = 0u16;
    while (i as usize) < s.file_count as usize {
        let fptr = s.files.as_ptr().add(i as usize);
        let mut eq = true;
        let mut k = 0usize;
        while k < 11 {
            if (*fptr).short_name[k] != s.write_file[k] { eq = false; break; }
            k += 1;
        }
        if eq { found = i as i32; break; }
        i += 1;
    }
    if found < 0 {
        log_info(s, b"[fat32] write: target file not found");
        s.write_state = WS_DONE;
        return 0;
    }

    let fptr = s.files.as_ptr().add(found as usize);
    s.w_target_first_cluster = (*fptr).start_cluster;
    s.w_target_old_size      = (*fptr).size;
    s.w_target_dir_lba       = (*fptr).dir_lba;
    s.w_target_dir_offset    = (*fptr).dir_offset;

    // POSIX-style overwrite: extend the file if the write is longer
    // than the existing size, but keep the existing tail on shorter
    // writes (no truncation). `effective_write_size` honours
    // `write_size` (synth-pattern path) over the inline buffer length.
    let old_size = s.w_target_old_size;
    let wdl      = effective_write_size(s);
    s.w_new_size = if wdl > old_size { wdl } else { old_size };

    // Initial cluster-walk state.
    s.w_bytes_written     = 0;
    s.w_current_cluster   = s.w_target_first_cluster;
    s.w_sector_in_cluster = 0;
    s.w_prev_cluster      = 0;
    s.w_new_cluster       = 0;
    s.w_alloc_probe       = 2;
    s.w_fat_sector_in_buf = 0;
    s.w_fat_copy_idx      = 0;

    // Log the LBA of the first sector that will be written so test
    // harnesses can cross-check against host-side filefrag/dd offsets.
    let first_lba = s.data_start_sector
        .wrapping_add((s.w_target_first_cluster - 2)
            * (s.sectors_per_cluster as u32));
    log_lba(s, b"[fat32] write lba=", first_lba);

    if effective_write_size(s) == 0 {
        // No payload at all — nothing to emit. (Size field would
        // already match, so dir-update is moot.)
        log_info(s, b"[fat32] write: empty payload");
        s.write_state = WS_DONE;
        return 0;
    }

    // Mark the volume dirty before any data or FAT mutation. If
    // Fluxor crashes mid-write the bit stays cleared; Linux then
    // flags the FS as "not properly unmounted" on the next mount
    // instead of silently accepting a potentially inconsistent state.
    // On a normal completion the symmetric WS_MARK_CLEAN_* flow
    // restores the bit.
    s.write_state = WS_MARK_DIRTY_READ;
    2
}

/// WS_SEND_SECTOR: stage a contiguous run of data sectors into one
/// packet and transition to the packet-drain state. The run extends
/// from `w_sector_in_cluster` up to the min of:
///   - end of current cluster (cluster walk must happen at that boundary)
///   - MAX_WRITE_NLB (driver's PRP1-only single-SQE limit)
///   - remaining payload rounded up to whole sectors
/// `w_batch_nlb` remembers the size so ws_after_sector can advance
/// counters by the correct amount.
unsafe fn ws_send_sector(s: &mut Fat32State) -> i32 {
    let lba = s.data_start_sector
        .wrapping_add((s.w_current_cluster - 2) * (s.sectors_per_cluster as u32))
        .wrapping_add(s.w_sector_in_cluster as u32);

    let off = s.w_bytes_written as usize;
    let total = effective_write_size(s) as usize;
    let remaining_bytes = total.saturating_sub(off);
    let remaining_sectors = (remaining_bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;
    let cluster_remaining = (s.sectors_per_cluster - s.w_sector_in_cluster) as usize;
    let mut nlb = remaining_sectors
        .min(cluster_remaining)
        .min(MAX_WRITE_NLB as usize);
    if nlb == 0 { nlb = 1; }
    let nlb = nlb as u16;

    stage_data_batch(s, lba, nlb, off);
    s.w_batch_nlb = nlb;
    enter_send_packet(s, WS_AFTER_SECTOR);
    2 // burst
}

/// WS_AFTER_SECTOR: advance counters by `w_batch_nlb` sectors and pick
/// the next action:
///   - more payload + current cluster has sectors left → WS_SEND_SECTOR
///   - more payload + cluster exhausted → WS_WALK_FAT_READ (walk chain
///     or, if EOC, start an allocation)
///   - all payload written → WS_DIR_READ (size-field update) or
///     WS_DONE if new_size == old_size
unsafe fn ws_after_sector(s: &mut Fat32State) -> i32 {
    let nlb = s.w_batch_nlb as u32;
    s.w_bytes_written = s.w_bytes_written.saturating_add(nlb * BLOCK_SIZE as u32);
    s.w_sector_in_cluster = s.w_sector_in_cluster.saturating_add(nlb as u8);

    let written = s.w_bytes_written;
    let total   = effective_write_size(s);

    if written >= total {
        // All payload pushed. Decide whether a dir-entry update is
        // needed (only when the write grew the file).
        if s.w_new_size != s.w_target_old_size {
            s.write_state = WS_DIR_READ;
            return 2;
        }
        log_info(s, b"[fat32] write: data done (no size change)");
        s.write_state = WS_MARK_CLEAN_READ;
        return 2;
    }

    if s.w_sector_in_cluster >= s.sectors_per_cluster {
        // Cluster exhausted — walk the FAT chain to find the next one,
        // or allocate a new cluster if this is the tail.
        s.w_sector_in_cluster = 0;
        s.write_state = WS_WALK_FAT_READ;
        return 2;
    }

    // Same cluster, next sector.
    s.write_state = WS_SEND_SECTOR;
    2
}

/// WS_WALK_FAT_READ: seek to the FAT sector holding the entry for
/// `w_current_cluster` (primary FAT).
unsafe fn ws_walk_fat_read(s: &mut Fat32State) -> i32 {
    let lba = fat_sector_abs(s, s.w_current_cluster, 0);
    flush_input(s);
    if seek_sd(s, lba) < 0 {
        log_info(s, b"[fat32] write: fat seek fail");
        s.write_state = WS_DONE;
        return 0;
    }
    s.read_fill = 0;
    s.w_fat_sector_in_buf = lba;
    s.write_state = WS_WALK_FAT_WAIT;
    0
}

/// WS_WALK_FAT_WAIT: parse the next-cluster pointer. EOC →
/// allocation; in-range cluster → advance `w_current_cluster`.
unsafe fn ws_walk_fat_wait(s: &mut Fat32State) -> i32 {
    let res = try_read_block(s);
    if res < 0 {
        log_info(s, b"[fat32] write: fat read fail");
        s.write_state = WS_DONE;
        return 0;
    }
    if res == 0 { return 0; }

    let next = read_fat_entry(s, s.w_current_cluster);
    if next >= FAT32_EOC || next < 2 {
        // Tail of the chain — need to allocate a new cluster, link
        // it in, and mirror to FAT2 if num_fats > 1.
        s.w_prev_cluster = s.w_current_cluster;
        s.w_new_cluster = 0;
        s.w_patched_prev_inline = 0;
        s.w_alloc_probe = 2;
        s.w_fat_copy_idx = 0;
        s.write_state = WS_ALLOC_READ;
        return 2;
    }

    // In-chain next cluster.
    s.w_current_cluster = next;
    s.w_sector_in_cluster = 0;
    s.write_state = WS_SEND_SECTOR;
    2
}

/// WS_ALLOC_READ: seek to the FAT sector containing `w_alloc_probe`
/// so we can scan it for a free (zero) entry.
unsafe fn ws_alloc_read(s: &mut Fat32State) -> i32 {
    let lba = fat_sector_abs(s, s.w_alloc_probe, 0);
    flush_input(s);
    if seek_sd(s, lba) < 0 {
        log_info(s, b"[fat32] write: alloc seek fail");
        s.write_state = WS_DONE;
        return 0;
    }
    s.read_fill = 0;
    s.w_fat_sector_in_buf = lba;
    s.write_state = WS_ALLOC_WAIT;
    0
}

/// WS_ALLOC_WAIT: scan the buffered FAT sector for the first zero
/// entry ≥ `w_alloc_probe`. If found, stage the writeback (EOC on the
/// new cluster, plus prev→new link if they happen to share a sector).
/// If the whole sector is full, bump `w_alloc_probe` and loop.
unsafe fn ws_alloc_wait(s: &mut Fat32State) -> i32 {
    let res = try_read_block(s);
    if res < 0 {
        log_info(s, b"[fat32] write: alloc read fail");
        s.write_state = WS_DONE;
        return 0;
    }
    if res == 0 { return 0; }

    // Scan this FAT sector for a zero entry. `entries_per_sector`
    // = bytes_per_sector / 4.
    let bps = s.bytes_per_sector as u32;
    let entries_per_sector = bps / 4;
    // Absolute cluster number of the first entry in this sector.
    let sec_rel    = s.w_fat_sector_in_buf - s.fat_start_sector;
    let first_clst = sec_rel.wrapping_mul(entries_per_sector);

    // Scan starting from max(first_clst, w_alloc_probe).
    let start_clst = if s.w_alloc_probe > first_clst {
        s.w_alloc_probe
    } else {
        first_clst
    };
    let mut c = start_clst;
    let end_clst = first_clst + entries_per_sector;
    let mut found: u32 = 0;
    while c < end_clst && c >= 2 {
        let off = ((c - first_clst) * 4) as usize;
        let v = read_u32_le(&s.block_buf, off) & FAT32_MASK;
        if v == 0 {
            found = c;
            break;
        }
        c += 1;
    }

    if found == 0 {
        // No free entry in this sector — advance probe past it.
        s.w_alloc_probe = end_clst;
        // Guard against runaway scan on tiny / bogus filesystems:
        // FAT32 caps cluster count at ~2^28. Stop after we've walked
        // the full FAT.
        let max_clst = entries_per_sector.saturating_mul(s.fat_size_32);
        if s.w_alloc_probe >= max_clst {
            log_info(s, b"[fat32] write: disk full");
            s.write_state = WS_DONE;
            return 0;
        }
        s.write_state = WS_ALLOC_READ;
        return 2;
    }

    s.w_new_cluster = found;
    s.w_fsinfo_pending = 1;
    // Mark the new cluster as EOC.
    patch_fat_entry(s, found, FAT32_TAIL);

    // If the previous cluster's entry is in this same FAT sector, we
    // can patch it in-place with a single write. This covers the
    // common case where the tail cluster is adjacent to free space.
    let prev_lba = fat_sector_abs(s, s.w_prev_cluster, 0);
    if prev_lba == s.w_fat_sector_in_buf {
        patch_fat_entry(s, s.w_prev_cluster, found);
        s.w_patched_prev_inline = 1;
    } else {
        s.w_patched_prev_inline = 0;
    }

    log_lba(s, b"[fat32] write: allocated cluster=", found);
    s.write_state = WS_ALLOC_WRITE;
    2
}

/// WS_ALLOC_WRITE: emit the write for the FAT sector containing the
/// newly allocated cluster (already patched in block_buf). Next step
/// depends on whether we also patched prev inline and whether the
/// filesystem has a mirror FAT.
unsafe fn ws_alloc_write(s: &mut Fat32State) -> i32 {
    let lba = s.w_fat_sector_in_buf;
    stage_packet(s, lba, s.block_buf.as_ptr());
    let next = next_state_after_fat_write(s, s.w_patched_prev_inline != 0);
    enter_send_packet(s, next);
    2
}

/// Pick the state to resume at after a FAT sector write completes.
///   * `links_prev`: true if the just-written sector already linked
///     the previous cluster to the new one (inline patch). When false,
///     a separate LINK read-modify-write is needed next.
///   * Mirror FAT: if num_fats > 1 and we just wrote the primary,
///     replicate the same block_buf to the mirror's corresponding
///     sector before moving on.
fn next_state_after_fat_write(s: &mut Fat32State, links_prev: bool) -> u8 {
    if s.w_fat_copy_idx == 0 && s.num_fats > 1 {
        // Still need to mirror this FAT sector.
        s.w_fat_copy_idx = 1;
        WS_MIRROR_WRITE
    } else {
        // Primary (+ mirror) for this sector done. Reset copy idx
        // for subsequent FAT operations.
        s.w_fat_copy_idx = 0;
        if links_prev {
            // The chain is fully linked. If an allocation just landed
            // and the volume has an FSINFO sector, update its
            // free-cluster bookkeeping before resuming data writes.
            if s.w_fsinfo_pending != 0
                && s.fsinfo_sector != 0
                && s.fsinfo_sector != 0xFFFF
            {
                WS_FSINFO_READ
            } else {
                s.w_current_cluster = s.w_new_cluster;
                s.w_sector_in_cluster = 0;
                WS_SEND_SECTOR
            }
        } else {
            // Need a separate LINK RMW for prev_cluster's FAT entry.
            WS_LINK_READ
        }
    }
}

/// WS_MIRROR_WRITE: write `block_buf` (unchanged) to the mirror FAT
/// sector at the same relative offset. Uses the same RMW result from
/// the primary write, so no re-read is needed.
unsafe fn ws_mirror_write(s: &mut Fat32State) -> i32 {
    let rel = s.w_fat_sector_in_buf - s.fat_start_sector;
    let lba = s.fat_start_sector
        .wrapping_add(s.fat_size_32)
        .wrapping_add(rel);
    stage_packet(s, lba, s.block_buf.as_ptr());
    let next = next_state_after_fat_write(s, s.w_patched_prev_inline != 0);
    enter_send_packet(s, next);
    2
}

/// WS_LINK_READ: seek to the FAT sector containing `w_prev_cluster`'s
/// entry so we can patch it to point at `w_new_cluster`.
unsafe fn ws_link_read(s: &mut Fat32State) -> i32 {
    let lba = fat_sector_abs(s, s.w_prev_cluster, 0);
    flush_input(s);
    if seek_sd(s, lba) < 0 {
        log_info(s, b"[fat32] write: link seek fail");
        s.write_state = WS_DONE;
        return 0;
    }
    s.read_fill = 0;
    s.w_fat_sector_in_buf = lba;
    s.write_state = WS_LINK_WAIT;
    0
}

/// WS_LINK_WAIT: patch `prev_cluster`'s entry to point at `new_cluster`,
/// then emit the FAT sector write.
unsafe fn ws_link_wait(s: &mut Fat32State) -> i32 {
    let res = try_read_block(s);
    if res < 0 {
        log_info(s, b"[fat32] write: link read fail");
        s.write_state = WS_DONE;
        return 0;
    }
    if res == 0 { return 0; }

    patch_fat_entry(s, s.w_prev_cluster, s.w_new_cluster);
    s.write_state = WS_LINK_WRITE;
    2
}

/// WS_LINK_WRITE: emit the write for the (now patched) FAT sector.
unsafe fn ws_link_write(s: &mut Fat32State) -> i32 {
    let lba = s.w_fat_sector_in_buf;
    stage_packet(s, lba, s.block_buf.as_ptr());
    // Signal that this RMW landed the prev→new link, so the
    // post-mirror transition can advance to data sectors.
    s.w_patched_prev_inline = 1;
    let next = next_state_after_fat_write(s, true);
    enter_send_packet(s, next);
    2
}

/// WS_DIR_READ: seek to the dir sector holding the target entry.
unsafe fn ws_dir_read(s: &mut Fat32State) -> i32 {
    flush_input(s);
    if seek_sd(s, s.w_target_dir_lba) < 0 {
        log_info(s, b"[fat32] write: dir seek fail");
        s.write_state = WS_DONE;
        return 0;
    }
    s.read_fill = 0;
    s.write_state = WS_DIR_WAIT;
    0
}

/// WS_DIR_WAIT: patch the 4-byte size field in the dir entry + queue
/// the writeback.
unsafe fn ws_dir_wait(s: &mut Fat32State) -> i32 {
    let res = try_read_block(s);
    if res < 0 {
        log_info(s, b"[fat32] write: dir read fail");
        s.write_state = WS_DONE;
        return 0;
    }
    if res == 0 { return 0; }

    // Per the FAT32 spec, the file-size field lives at dir_entry + 28.
    let off = s.w_target_dir_offset as usize + 28;
    let le = s.w_new_size.to_le_bytes();
    let dst = s.block_buf.as_mut_ptr().add(off);
    *dst        = le[0];
    *dst.add(1) = le[1];
    *dst.add(2) = le[2];
    *dst.add(3) = le[3];

    s.write_state = WS_DIR_WRITE;
    2
}

/// WS_DIR_WRITE: emit the patched dir sector write, then restore the
/// ClnShutBit before finalising. The FAT dirty-bit dance always runs
/// last (post-dir) so a crash between the dir write and clean-mark is
/// still visible to Linux as "dirty".
unsafe fn ws_dir_write(s: &mut Fat32State) -> i32 {
    stage_packet(s, s.w_target_dir_lba, s.block_buf.as_ptr());
    enter_send_packet(s, WS_MARK_CLEAN_READ);
    // Log on the way in so a successful write is observable even if
    // the dir writeback takes a moment to drain.
    log_info(s, b"[fat32] write: dir size patched");
    2
}

/// Drop any pending FSINFO update and resume data writes into the
/// freshly allocated cluster. FSINFO bookkeeping is best-effort —
/// fsck recomputes the free count on the next mount, so any error
/// in the read-modify-write path takes this fall-back rather than
/// abandoning the whole user write.
fn resume_after_alloc(s: &mut Fat32State) {
    s.w_fsinfo_pending = 0;
    s.w_current_cluster = s.w_new_cluster;
    s.w_sector_in_cluster = 0;
}

/// WS_FSINFO_READ: seek to the FSINFO sector so we can decrement the
/// cached free-cluster count and bump the next-free hint.
unsafe fn ws_fsinfo_read(s: &mut Fat32State) -> i32 {
    let lba = s.partition_lba.wrapping_add(s.fsinfo_sector as u32);
    flush_input(s);
    if seek_sd(s, lba) < 0 {
        log_info(s, b"[fat32] write: fsinfo seek fail");
        resume_after_alloc(s);
        s.write_state = WS_SEND_SECTOR;
        return 2;
    }
    s.read_fill = 0;
    s.w_fat_sector_in_buf = lba;
    s.write_state = WS_FSINFO_WAIT;
    0
}

/// WS_FSINFO_WAIT: validate the FSINFO signatures, decrement the
/// free-cluster count if it's a known value, and update the next-free
/// hint to one past the cluster we just allocated.
unsafe fn ws_fsinfo_wait(s: &mut Fat32State) -> i32 {
    let res = try_read_block(s);
    if res < 0 {
        log_info(s, b"[fat32] write: fsinfo read fail");
        resume_after_alloc(s);
        s.write_state = WS_SEND_SECTOR;
        return 2;
    }
    if res == 0 { return 0; }

    // FSINFO layout (FAT32 spec): lead sig at 0x000, struct sig at
    // 0x1E4, free count at 0x1E8, next-free hint at 0x1EC, trail sig
    // at 0x1FC. Reject the sector on any signature mismatch rather
    // than risk writing garbage back.
    let lead    = read_u32_le(&s.block_buf, 0x000);
    let struc   = read_u32_le(&s.block_buf, 0x1E4);
    let trailer = read_u32_le(&s.block_buf, 0x1FC);
    if lead != 0x4161_5252 || struc != 0x6141_7272 || trailer != 0xAA55_0000 {
        log_info(s, b"[fat32] write: fsinfo bad sig");
        resume_after_alloc(s);
        s.write_state = WS_SEND_SECTOR;
        return 2;
    }

    let free = read_u32_le(&s.block_buf, 0x1E8);
    if free != 0xFFFF_FFFF && free > 0 {
        let new_free = free - 1;
        let le = new_free.to_le_bytes();
        let dst = s.block_buf.as_mut_ptr().add(0x1E8);
        *dst        = le[0];
        *dst.add(1) = le[1];
        *dst.add(2) = le[2];
        *dst.add(3) = le[3];
    }

    let hint = s.w_new_cluster.wrapping_add(1).max(2);
    let le = hint.to_le_bytes();
    let dst = s.block_buf.as_mut_ptr().add(0x1EC);
    *dst        = le[0];
    *dst.add(1) = le[1];
    *dst.add(2) = le[2];
    *dst.add(3) = le[3];

    s.write_state = WS_FSINFO_WRITE;
    2
}

/// WS_FSINFO_WRITE: emit the patched FSINFO sector, then resume data
/// writes into the freshly allocated cluster.
unsafe fn ws_fsinfo_write(s: &mut Fat32State) -> i32 {
    stage_packet(s, s.w_fat_sector_in_buf, s.block_buf.as_ptr());
    resume_after_alloc(s);
    enter_send_packet(s, WS_SEND_SECTOR);
    2
}

/// Read fat_start_sector into block_buf in preparation for toggling
/// cluster 1's ClnShutBit. `wait_state` is the state to re-enter once
/// the block arrives (either WS_MARK_DIRTY_WAIT or WS_MARK_CLEAN_WAIT).
unsafe fn ws_mark_fat_read(s: &mut Fat32State, wait_state: u8) -> i32 {
    let lba = s.fat_start_sector;
    flush_input(s);
    if seek_sd(s, lba) < 0 {
        log_info(s, b"[fat32] write: clnshut seek fail");
        s.write_state = WS_DONE;
        return 0;
    }
    s.read_fill = 0;
    s.w_fat_sector_in_buf = lba;
    s.write_state = wait_state;
    0
}

/// Patch cluster 1's FAT entry in block_buf to toggle ClnShutBit.
/// `set_clean == true` sets the bit (→ clean); false clears it
/// (→ dirty). Bit 26 (HrdErrBit) is left as-is — fat32 never sets
/// that bit, so the mkfs default of "no error" is preserved across
/// normal Fluxor runs.
unsafe fn patch_clnshut_bit(buf: *mut u8, set_clean: bool) {
    let entry_ptr = buf.add(4); // cluster 1 = bytes 4..8 of FAT sector 0
    let cur = (*entry_ptr as u32)
        | ((*entry_ptr.add(1) as u32) << 8)
        | ((*entry_ptr.add(2) as u32) << 16)
        | ((*entry_ptr.add(3) as u32) << 24);
    let next = if set_clean {
        cur | CLN_SHUT_BIT
    } else {
        cur & !CLN_SHUT_BIT
    };
    let le = next.to_le_bytes();
    *entry_ptr        = le[0];
    *entry_ptr.add(1) = le[1];
    *entry_ptr.add(2) = le[2];
    *entry_ptr.add(3) = le[3];
}

/// Once the FAT sector read completes, toggle ClnShutBit and stage
/// the write. `set_clean == true` transitions via the CLEAN states;
/// false via the DIRTY states.
unsafe fn ws_mark_fat_wait(s: &mut Fat32State, set_clean: bool) -> i32 {
    let res = try_read_block(s);
    if res < 0 {
        log_info(s, b"[fat32] write: clnshut read fail");
        s.write_state = WS_DONE;
        return 0;
    }
    if res == 0 { return 0; }

    patch_clnshut_bit(s.block_buf.as_mut_ptr(), set_clean);
    s.write_state = if set_clean { WS_MARK_CLEAN_WRITE } else { WS_MARK_DIRTY_WRITE };
    2
}

/// Stage the primary-FAT-sector write with the toggled ClnShutBit.
/// On resume, go to the mirror step when num_fats > 1; otherwise
/// skip directly to the next phase (WS_SEND_SECTOR after dirty;
/// WS_DONE after clean).
unsafe fn ws_mark_fat_write(s: &mut Fat32State, set_clean: bool) -> i32 {
    let lba = s.fat_start_sector;
    stage_packet(s, lba, s.block_buf.as_ptr());
    let next = if s.num_fats > 1 {
        if set_clean { WS_MARK_CLEAN_MIRROR } else { WS_MARK_DIRTY_MIRROR }
    } else if set_clean {
        WS_DONE
    } else {
        WS_SEND_SECTOR
    };
    enter_send_packet(s, next);
    2
}

/// Mirror the primary-FAT ClnShutBit write to FAT2's sector 0. The
/// mirror FAT starts at `fat_start_sector + fat_size_32`; sector 0 of
/// the mirror is at the same relative offset (=0). block_buf already
/// holds the patched data.
unsafe fn ws_mark_fat_mirror(s: &mut Fat32State, set_clean: bool) -> i32 {
    let lba = s.fat_start_sector.wrapping_add(s.fat_size_32);
    stage_packet(s, lba, s.block_buf.as_ptr());
    let next = if set_clean { WS_DONE } else { WS_SEND_SECTOR };
    enter_send_packet(s, next);
    2
}

/// WS_NS_CHECK: one-shot geometry query over block_writes. The nvme
/// driver registers an IOCTL_NVME_NS_INFO handler on its req_in side,
/// so fat32 can sanity-check that the underlying namespace uses 512 B
/// LBAs (the only size fat32 supports today) before it stages any
/// writes. Non-nvme consumers (sd driver, etc.) don't register a
/// handler; the kernel returns ENOSYS and fat32 proceeds anyway so
/// this stays a soft check.
///
/// ns_size returned is in LBAs. For info only — fat32 doesn't cap
/// writes at ns_size because partition geometry already does.
unsafe fn ws_ns_check(s: &mut Fat32State) -> i32 {
    if s.write_out_chan < 0 {
        // No downstream wired — WS_SCAN's own guard will emit the
        // "no block_writes channel" error. Just advance.
        s.write_state = WS_SCAN;
        return 2;
    }
    // Request nsid=0 ("whatever the default is"); we don't need the
    // exact nsid, just the geometry of what fat32's writes will land
    // on. `scratch` is sized for the {ns_size:u64 + ns_lbads:u8}
    // response; the 4-byte nsid input sits in the first 4 bytes.
    let mut scratch = [0u8; 13];
    let rc = dev_channel_query(
        s.sys(),
        s.write_out_chan,
        IOCTL_NVME_NS_INFO,
        scratch.as_mut_ptr(),
        scratch.len(),
    );
    match rc {
        E_AGAIN => 0, // nvme mid-IdentifyNamespace; retry next tick
        E_NOSYS => {
            // No handler registered (sd driver, out-of-tree consumer).
            // Skip the geometry check and proceed.
            log_info(s, b"[fat32] ns_check: no nvme handler, skipping");
            s.write_state = WS_SCAN;
            2
        }
        0 => {
            let ns_size = u64::from_le_bytes([
                scratch[0], scratch[1], scratch[2], scratch[3],
                scratch[4], scratch[5], scratch[6], scratch[7],
            ]);
            let ns_lbads = scratch[8];
            emit_ns_info(s, ns_size, ns_lbads);
            if ns_lbads != EXPECTED_LBADS {
                // fat32 hard-codes 512 B sectors in stage_packet +
                // drain chunking. A 4 KiB-native SSD would silently
                // corrupt data without broader rework — refuse.
                log_info(s, b"[fat32] ns_check: unsupported lbads; writes disabled");
                s.write_state = WS_DONE;
                0
            } else {
                s.write_state = WS_SCAN;
                2
            }
        }
        _ => {
            log_info(s, b"[fat32] ns_check: ioctl err");
            s.write_state = WS_DONE;
            0
        }
    }
}

/// Emit `[fat32] ns size=NNN lbads=DD`. Helper so ws_ns_check stays
/// focused on the control flow. `ns_size` is reported as a truncated
/// u32 (LBA count); for drives up to ~2 TiB at 512 B LBAs this fits.
/// Oversized namespaces will log a wrapped value — reasonable for a
/// one-shot diagnostic line.
unsafe fn emit_ns_info(s: &Fat32State, ns_size: u64, ns_lbads: u8) {
    let mut msg = [0u8; 48];
    let p = msg.as_mut_ptr();
    let prefix = b"[fat32] ns size=";
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), p, prefix.len());
    let mut pos = prefix.len();
    pos += fmt_u32_raw(p.add(pos), ns_size as u32);
    let lb = b" lbads=";
    core::ptr::copy_nonoverlapping(lb.as_ptr(), p.add(pos), lb.len());
    pos += lb.len();
    *p.add(pos)     = b'0' + (ns_lbads / 10);
    *p.add(pos + 1) = b'0' + (ns_lbads % 10);
    pos += 2;
    dev_log(s.sys(), 3, p, pos);
}

/// Initialization state machine
unsafe fn init_step(s: &mut Fat32State) -> i32 {
    match s.init_phase {
        Fat32InitPhase::Idle => {
            flush_input(s);
            if seek_sd(s, 0) < 0 {
                return -1;
            }
            s.read_fill = 0;
            s.init_phase = Fat32InitPhase::WaitBlock0;
            0
        }

        Fat32InitPhase::WaitBlock0 => {
            let res = try_read_block(s);
            if res < 0 { log_info(s, b"[fat32] blk0 read fail"); return -1; }
            if res == 0 { return 0; }

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
                s.partition_lba = lba;
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

            log_info(s, b"[fat32] no fat32");
            -1
        }

        Fat32InitPhase::ReadBoot => {
            flush_input(s);
            if seek_sd(s, s.partition_lba) < 0 {
                return -1;
            }
            s.read_fill = 0;
            s.init_phase = Fat32InitPhase::WaitBoot;
            0
        }

        Fat32InitPhase::WaitBoot => {
            let res = try_read_block(s);
            if res < 0 { log_info(s, b"[fat32] boot read fail"); return -1; }
            if res == 0 { return 0; }

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
            let sector = cluster_to_sector(s, s.dir_cluster)
                + (s.dir_sector_in_cluster as u32);
            flush_input(s);
            if seek_sd(s, sector) < 0 {
                return -1;
            }
            s.read_fill = 0;
            s.init_phase = Fat32InitPhase::WaitRoot;
            0
        }

        Fat32InitPhase::WaitRoot => {
            let res = try_read_block(s);
            if res < 0 { log_info(s, b"[fat32] dir read fail"); return -1; }
            if res == 0 { return 0; }

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
                    if first_byte == 0xE5 { continue; }

                    let attr = *entry_ptr.add(11);
                    if attr == ATTR_LONG_NAME { continue; }
                    if (attr & ATTR_DIRECTORY) == 0 { continue; }

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
                        if cluster < 2 { continue; }

                        s.dir_cluster = cluster;
                        s.path_pos += comp_len as u8;
                        while (s.path_pos as usize) < 63
                            && *pp.add(s.path_pos as usize) == b'/'
                        {
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
                            p += 1; t += 1;
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
            flush_input(s);
            if seek_sd(s, fat_sector) < 0 {
                return -1;
            }
            s.read_fill = 0;
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
            if res == 0 { return 0; }

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

            if next_cluster >= FAT32_EOC || next_cluster < 2 {
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
            flush_input(s);
            if seek_sd(s, 1) < 0 {
                return -1;
            }
            s.read_fill = 0;
            s.init_phase = Fat32InitPhase::WaitGptHeader;
            0
        }

        Fat32InitPhase::WaitGptHeader => {
            let res = try_read_block(s);
            if res < 0 { log_info(s, b"[fat32] gpt hdr read fail"); return -1; }
            if res == 0 { return 0; }

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

            // Partition entry array start LBA at offset 72 (u64, use lower 32 bits)
            let entry_lba = read_u32_le(&s.block_buf, 72);
            s.pending_block = entry_lba;
            s.init_phase = Fat32InitPhase::ReadGptEntry;
            2 // Burst — read partition entries
        }

        Fat32InitPhase::ReadGptEntry => {
            flush_input(s);
            if seek_sd(s, s.pending_block) < 0 {
                return -1;
            }
            s.read_fill = 0;
            s.init_phase = Fat32InitPhase::WaitGptEntry;
            0
        }

        Fat32InitPhase::WaitGptEntry => {
            let res = try_read_block(s);
            if res < 0 { log_info(s, b"[fat32] gpt entry read fail"); return -1; }
            if res == 0 { return 0; }

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
                        // Starting LBA at offset 32 within entry (u64, lower 32 bits)
                        let lba = read_u32_le(&s.block_buf, offset + 32);
                        if lba > 0 {
                            s.partition_lba = lba;
                            s.init_phase = Fat32InitPhase::ReadBoot;
                            return 2; // Burst — read boot sector
                        }
                    }
                }
                i += 1;
            }

            // If we only scanned 4 entries and didn't find it, try next sector
            // For now, report failure (most SD cards have data partition in first 4)
            log_info(s, b"[fat32] no gpt part");
            -1
        }

        Fat32InitPhase::Done => 0,

        _ => -1,
    }
}


// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");
