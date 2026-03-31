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

#[path = "../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

// ============================================================================
// Constants
// ============================================================================

/// Block size (always 512 for SD/FAT32)
const BLOCK_SIZE: usize = 512;

/// Maximum files to enumerate
const MAX_FILES: usize = 128;


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

/// FAT32 file streaming phases.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum Fat32ModPhase {
    Idle = 0,
    SeekSd = 1,
    WaitSeek = 2,
    ReadBlock = 3,
    WaitBlock = 4,
    WriteData = 5,
    ReadFat = 6,
    WaitFat = 7,
}

include!("../pic_runtime.rs");
include!("../param_macro.rs");

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
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
}

impl FileEntry {
    const fn empty() -> Self {
        Self {
            start_cluster: 0,
            size: 0,
        }
    }
}

// ============================================================================
// Module State
// ============================================================================

#[repr(C)]
struct Fat32State {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,

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

    // State machine
    init_phase: Fat32InitPhase,
    mod_phase: Fat32ModPhase,

    // File enumeration
    file_count: u16,
    files: [FileEntry; MAX_FILES],

    // Configuration
    path: [u8; 64],
    pattern: [u8; 16],

    // Directory enumeration state
    dir_cluster: u32,
    dir_sector_in_cluster: u8,
    dir_entry_in_sector: u8,
    dir_mode: u8,
    path_pos: u8,

    // Current file streaming state
    current_file: u16,
    current_cluster: u32,
    current_sector_in_cluster: u8,
    file_offset: u32,
    file_size: u32,

    // Block I/O state
    pending_block: u32,
    block_offset: u16,
    read_fill: u16,
    block_buf: [u8; BLOCK_SIZE],
}

impl Fat32State {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.in_chan = -1;
        self.out_chan = -1;
        self.bytes_per_sector = 512;
        self.sectors_per_cluster = 0;
        self.reserved_sectors = 0;
        self.num_fats = 0;
        self.fat_size_32 = 0;
        self.root_cluster = 0;
        self.fat_start_sector = 0;
        self.data_start_sector = 0;
        self.partition_lba = 0;
        self.init_phase = Fat32InitPhase::Idle;
        self.mod_phase = Fat32ModPhase::Idle;
        self.file_count = 0;
        self.dir_cluster = 0;
        self.dir_sector_in_cluster = 0;
        self.dir_entry_in_sector = 0;
        self.dir_mode = 0;
        self.path_pos = 0;
        self.current_file = 0xFFFF;
        self.current_cluster = 0;
        self.current_sector_in_cluster = 0;
        self.file_offset = 0;
        self.file_size = 0;
        self.pending_block = 0;
        self.block_offset = 0;
        self.read_fill = 0;
        // path, pattern, files arrays are zeroed by kernel
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

/// Check for pending seek request from downstream
#[inline]
unsafe fn check_seek_request(s: &Fat32State) -> u32 {
    if s.out_chan < 0 {
        return u32::MAX;
    }
    let mut seek_pos: u32 = 0;
    let seek_ptr = &mut seek_pos as *mut u32 as *mut u8;
    let res = dev_channel_ioctl(s.sys(), s.out_chan, IOCTL_POLL_NOTIFY, seek_ptr);
    if res == 0 {
        seek_pos
    } else {
        u32::MAX
    }
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
    if poll <= 0 || (poll as u8 & POLL_IN) == 0 {
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
        s.file_count += 1;
    }

    true
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
    out_chan: i32,
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
        s.out_chan = out_chan;

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

        // Run initialization if not done
        if s.init_phase != Fat32InitPhase::Done {
            return init_step(s);
        }

        // Check for seek request from downstream
        if s.mod_phase == Fat32ModPhase::Idle {
            let seek_idx = check_seek_request(s);
            if seek_idx != u32::MAX && (seek_idx as u16) < s.file_count {
                // Start streaming file at index (use pointer arithmetic, no bounds check)
                let idx = seek_idx as usize;
                let file_ptr = s.files.as_ptr().add(idx);
                s.current_file = seek_idx as u16;
                s.current_cluster = (*file_ptr).start_cluster;
                s.current_sector_in_cluster = 0;
                s.file_offset = 0;
                s.file_size = (*file_ptr).size;
                s.mod_phase = Fat32ModPhase::SeekSd;
            }
        }

        // File streaming state machine
        stream_step(s)
    }
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

/// File streaming state machine
unsafe fn stream_step(s: &mut Fat32State) -> i32 {
    match s.mod_phase {
        Fat32ModPhase::Idle => 0,

        Fat32ModPhase::SeekSd => {
            let sector = cluster_to_sector(s, s.current_cluster)
                + (s.current_sector_in_cluster as u32);
            flush_input(s);
            if seek_sd(s, sector) < 0 {
                return -1;
            }
            s.read_fill = 0;
            s.mod_phase = Fat32ModPhase::WaitBlock;
            s.block_offset = 0;
            0
        }

        Fat32ModPhase::WaitBlock => {
            let res = try_read_block(s);
            if res < 0 {
                log_info(s, b"[fat32] blk read fail");
                s.mod_phase = Fat32ModPhase::Idle;
                return 0;
            }
            if res == 0 { return 0; }

            s.mod_phase = Fat32ModPhase::WriteData;
            2 // Burst — write data immediately
        }

        Fat32ModPhase::WriteData => {
            // Write block data to output, respecting file size
            let remaining_in_file = s.file_size.saturating_sub(s.file_offset);
            if remaining_in_file == 0 {
                // File complete — signal EOF to downstream
                if s.out_chan >= 0 {
                    dev_channel_ioctl(s.sys(), s.out_chan, IOCTL_EOF, core::ptr::null_mut());
                }
                s.mod_phase = Fat32ModPhase::Idle;
                s.current_file = 0xFFFF;
                return 0;
            }

            // How much of this block belongs to the file?
            let offset = s.block_offset as usize;
            let remaining_in_block = BLOCK_SIZE - offset;
            let to_write = core::cmp::min(remaining_in_block as u32, remaining_in_file) as usize;

            if s.out_chan < 0 {
                // No output channel, just advance
                s.file_offset += to_write as u32;
                s.block_offset += to_write as u16;
            } else {
                // Check if output is ready
                let poll = (s.sys().channel_poll)(s.out_chan, POLL_OUT);
                if poll <= 0 || (poll as u8 & POLL_OUT) == 0 {
                    return 0;
                }

                let src = s.block_buf.as_ptr().add(offset);
                let written = (s.sys().channel_write)(s.out_chan, src, to_write);
                if written == E_AGAIN {
                    return 0;
                }
                if written < 0 {
                    s.mod_phase = Fat32ModPhase::Idle;
                    return -1;
                }

                s.file_offset += written as u32;
                s.block_offset += written as u16;

            }

            // Check if we need more data
            if s.block_offset as usize >= BLOCK_SIZE {
                // Move to next sector
                s.block_offset = 0;
                s.current_sector_in_cluster += 1;

                if s.current_sector_in_cluster >= s.sectors_per_cluster {
                    // Need next cluster - read FAT
                    s.mod_phase = Fat32ModPhase::ReadFat;
                } else {
                    // Same cluster, next sector
                    s.mod_phase = Fat32ModPhase::SeekSd;
                }
                return 2; // Burst — seek next block immediately
            }

            0
        }

        Fat32ModPhase::ReadFat => {
            let fat_sector = fat_sector_for_cluster(s, s.current_cluster);
            flush_input(s);
            if seek_sd(s, fat_sector) < 0 {
                return -1;
            }
            s.read_fill = 0;
            s.mod_phase = Fat32ModPhase::WaitFat;
            0
        }

        Fat32ModPhase::WaitFat => {
            let res = try_read_block(s);
            if res < 0 {
                log_info(s, b"[fat32] fat read fail");
                s.mod_phase = Fat32ModPhase::Idle;
                return 0;
            }
            if res == 0 { return 0; }

            let offset = fat_offset_for_cluster(s, s.current_cluster);
            if offset + 4 > BLOCK_SIZE {
                s.mod_phase = Fat32ModPhase::Idle;
                return 0;
            }
            let next_cluster = read_u32_le(&s.block_buf, offset) & FAT32_MASK;

            if next_cluster >= FAT32_EOC {
                // End of file — signal EOF to downstream
                if s.out_chan >= 0 {
                    dev_channel_ioctl(s.sys(), s.out_chan, IOCTL_EOF, core::ptr::null_mut());
                }
                s.mod_phase = Fat32ModPhase::Idle;
                s.current_file = 0xFFFF;
                return 0;
            }

            // Continue with next cluster
            s.current_cluster = next_cluster;
            s.current_sector_in_cluster = 0;
            s.mod_phase = Fat32ModPhase::SeekSd;
            2 // Burst — seek next cluster immediately
        }

        _ => -1,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
