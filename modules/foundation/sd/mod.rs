//! SD Card PIC Module
//!
//! A reference implementation of a PIC (Position-Independent Code) module for
//! reading raw data from an SD card over SPI.
//!
//! # Architecture
//!
//! This module uses a poll-based state machine architecture suitable for
//! cooperative multitasking. All operations are non-blocking and return:
//! - `0` = pending (call again)
//! - `1` = complete
//! - `<0` = error
//!
//! # State Machine Overview
//!
//! ```text
//! INIT: CLAIMING → PRECLOCKING → CMD0 → CMD8 ─┬→ V2 path (SDHC/SDXC)
//!                                              └→ V1 path (older cards)
//!
//! V2:  CMD55 → ACMD41 (retry with timer) → CMD58 → CMD9 → CSD → CMD16 → DONE
//! V1:  CMD55 → ACMD41 (retry with timer) → CMD9 → CSD → CMD16 → DONE
//!
//! READ: Start CMD17 → Wait R1 → Wait Token → Read 512 bytes → Read CRC → Done
//! ```
//!
//! # PIC Safety
//!
//! This module is designed for position-independent execution:
//! - No panicking operations (no array indexing, no unwrap)
//! - Explicit match statements (no function pointer tables)
//! - Macro-based code reuse (compile-time expansion)
//! - All syscalls through function pointer table

#![no_std]

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

#[path = "../../../src/abi.rs"]
mod abi;
use abi::{SyscallTable, SpiOpenArgs, SpiTransferStartArgs};

// ============================================================================
// Module Parameters
// ============================================================================

/// Parameters for SD module (from YAML config).
/// Channels are passed as direct arguments to module_new.
/// Layout:
///   [0]     spi_bus: u8
///   [1]     cs_pin: u8
///   [2-3]   padding
///   [4-7]   start_block: u32
///   [8-11]  block_count: u32
#[repr(C)]
struct SdParams {
    spi_bus: u8,
    cs_pin: u8,
    _pad: [u8; 2],
    start_block: u32,
    block_count: u32,
}

include!("../../pic_runtime.rs");
include!("../../param_macro.rs");

// ============================================================================
// SD Protocol Constants
// ============================================================================

/// SPI clock during initialization (must be ≤400kHz per SD spec)
const INIT_FREQ: u32 = 400_000;

/// SPI clock during data transfer
const DATA_FREQ: u32 = 12_000_000;

/// Maximum attempts waiting for R1 response
const CMD_TIMEOUT: u32 = 100;

/// Data token indicating start of block data
const TOKEN_DATA: u8 = 0xFE;

/// Timeout for SPI bus claim
const CLAIM_TIMEOUT_MS: u64 = 50;


// SD Commands
const CMD0: u8 = 0;    // GO_IDLE_STATE
const CMD8: u8 = 8;    // SEND_IF_COND
const CMD9: u8 = 9;    // SEND_CSD
const CMD16: u8 = 16;  // SET_BLOCKLEN
const CMD17: u8 = 17;  // READ_SINGLE_BLOCK
const CMD55: u8 = 55;  // APP_CMD prefix
const ACMD41: u8 = 41; // SD_SEND_OP_COND (app command)
const CMD58: u8 = 58;  // READ_OCR

// R1 Response bits
const R1_IDLE_STATE: u8 = 1 << 0;
const R1_ILLEGAL_COMMAND: u8 = 1 << 2;

/// SD block size (always 512 bytes)
const BLOCK_SIZE: usize = 512;

// ============================================================================
// Error Codes
// ============================================================================
//
// Module-specific error codes returned by module_step().
// Negative values indicate errors; the magnitude indicates the error type.


/// Initialization failed
const E_INIT_FAILED: i32 = -20;

/// Block read failed
const E_READ_FAILED: i32 = -21;

/// Channel write failed
const E_WRITE_FAILED: i32 = -22;

// ============================================================================
// State Machine Enums
// ============================================================================

/// SPI bus transfer state.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum SpiXfer {
    Idle = 0,
    Pending = 1,
}

/// Command send state machine (send_cmd_poll).
///
// Idle → Selecting → SendingCmd → WaitingR1 → [ReadingExtra] → SendingDummy → Idle
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum CmdState {
    Idle = 0,
    Selecting = 1,
    SendingCmd = 2,
    WaitingR1 = 3,
    ReadingExtra = 4,
    SendingDummy = 5,
}

/// Data block read state machine (read_data_block_poll).
///
// Idle → Selecting → WaitingToken → ReadingData → ReadingCrc → SendingDummy → Idle
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum DataReadState {
    Idle = 0,
    Selecting = 1,
    WaitingToken = 2,
    ReadingData = 3,
    ReadingCrc = 4,
    SendingDummy = 5,
}

/// Block read state machine (read_block_poll).
///
// Idle → Selecting → SendingCmd → WaitingR1 → ReadingDataBlock → Idle
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum BlockReadState {
    Idle = 0,
    Selecting = 1,
    SendingCmd = 2,
    WaitingR1 = 3,
    ReadingDataBlock = 4,
}

/// SD card initialization state machine (SD Physical Layer Simplified Spec §4.2).
///
// ════════════════════════════════════════════════════════════════
// SD Init Phase Transitions
// ════════════════════════════════════════════════════════════════
//
// Phase               | Trigger                | Next                | Notes
// ────────────────────|────────────────────────|─────────────────────|──────────────
// Idle                | always                 | Claiming            |
// Claiming            | SPI handle acquired    | Preclocking         | 400kHz
// Preclocking         | SPI xfer started       | PreclockingWait     | ≥74 clocks
// PreclockingWait     | SPI xfer done          | Cmd0Start           |
// Cmd0Start           | send CMD0              | Cmd0Wait            |
// Cmd0Wait            | R1=0x01 (idle)         | Cmd8Start           |
// Cmd0Wait            | timeout                | Cmd0Timer → retry   | 1s timeout
// Cmd8Start           | send CMD8              | Cmd8Wait            |
// Cmd8Wait            | R1=0x01 (V2 card)      | Cmd55v2Start        |
// Cmd8Wait            | R1=0x05 (V1 card)      | Cmd55v1Start        |
// Cmd55v2Start..      | ACMD41 loop            | Cmd58Start          | ready bit set
// Cmd58Start          | send CMD58             | Cmd58Wait           | check CCS bit
// Cmd55v1Start..      | ACMD41 loop            | Cmd9Start           | ready bit set
// Cmd9Start           | send CMD9              | Cmd9Wait            |
// ReadingCsdStart     | data block read        | ReadingCsdWait      |
// Cmd16Start          | send CMD16(512)        | Cmd16Wait           | set block size
// ConfigureDataFreq   | set SPI freq           | Done                | 12MHz
// Done                | (terminal)             | —                   | card ready
//
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum SdInitPhase {
    Idle = 0,
    Claiming = 1,
    Preclocking = 2,
    PreclockingWait = 3,
    // CMD0 — reset to SPI mode
    Cmd0Start = 4,
    Cmd0Wait = 5,
    Cmd0Timer = 6,
    // CMD8 — voltage check (V1 vs V2)
    Cmd8Start = 7,
    Cmd8Wait = 8,
    // V2 path (SDHC/SDXC)
    Cmd55v2Start = 9,
    Cmd55v2Wait = 10,
    Acmd41v2Start = 11,
    Acmd41v2Wait = 12,
    Acmd41v2Timer = 13,
    Cmd58Start = 14,
    Cmd58Wait = 15,
    // V1 path (older cards)
    Cmd55v1Start = 16,
    Cmd55v1Wait = 17,
    Acmd41v1Start = 18,
    Acmd41v1Wait = 19,
    Acmd41v1Timer = 20,
    // Common final sequence
    Cmd9Start = 21,
    Cmd9Wait = 22,
    ReadingCsdStart = 23,
    ReadingCsdWait = 24,
    Cmd16Start = 25,
    Cmd16Wait = 26,
    ConfigureDataFreq = 27,
    Done = 28,
}

/// Top-level module phase.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum SdModPhase {
    Reading = 0,
    Writing = 1,
    Done = 2,
    WritingPending = 3,
}

// ============================================================================
// State Struct
// ============================================================================

#[repr(C)]
struct SdState {
    // Syscall table pointer
    syscalls: *const SyscallTable,
    spi_handle: i32,
    /// Card-dependent multiplier (1 for SDHC, 512 for older cards)
    cdv: u32,

    // SPI transfer state
    spi_state: SpiXfer,

    // Command state (send_cmd_poll)
    cmd_state: CmdState,
    cmd_release: u8,
    cmd_extra_count: u8,
    cmd_extra_idx: u8,
    cmd_buf: [u8; 6],
    cmd_response: u8,
    cmd_attempts: u8,
    cmd_start_ms_lo: u32,
    cmd_start_ms_hi: u32,
    cmd_extra: [u8; 4],
    r1_buf: [u8; 1],
    _pad1: [u8; 3],

    // Data block read state
    rd_state: DataReadState,
    rd_attempts_lo: u8,
    rd_attempts_hi: u8,
    _pad3: u8,
    rd_start_ms_lo: u32,
    rd_start_ms_hi: u32,
    crc_buf: [u8; 2],
    _pad4: [u8; 2],

    // Block read state
    rb_state: BlockReadState,
    rb_attempts: u8,
    rb_addr: u32,
    rb_start_ms_lo: u32,
    rb_start_ms_hi: u32,

    // Init state
    init_state: SdInitPhase,
    init_retry: u8,
    init_preclk_count: u8,
    _pad6: u8,
    init_start_ms_lo: u32,
    init_start_ms_hi: u32,

    // Module state
    mod_state: SdModPhase,
    /// SPI bus number (stored for TLV v2)
    spi_bus: u8,
    /// Pending write offset into block_buf
    pending_offset: u16,
    out_chan: i32,
    start_block: u32,
    block_count: u32,
    current_block: u32,
    /// CS pin number (stored for TLV v2)
    cs_pin: u8,
    _pad5: [u8; 3],
    /// Timer fd for init retry delays (fd-based timer API)
    timer_fd: i32,

    // Buffers (at end for alignment)
    block_buf: [u8; BLOCK_SIZE],
    csd_buf: [u8; BLOCK_SIZE],
}

impl SdState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.spi_handle = -1;
        self.cdv = 512;
        self.spi_state = SpiXfer::Idle;
        self.cmd_state = CmdState::Idle;
        self.cmd_release = 0;
        self.cmd_extra_count = 0;
        self.cmd_extra_idx = 0;
        self.cmd_buf = [0; 6];
        self.cmd_response = 0xFF;
        self.cmd_attempts = 0;
        self.cmd_start_ms_lo = 0;
        self.cmd_start_ms_hi = 0;
        self.cmd_extra = [0xFF; 4];
        self.r1_buf = [0xFF];
        self._pad1 = [0; 3];
        self.rd_state = DataReadState::Idle;
        self.rd_attempts_lo = 0;
        self.rd_attempts_hi = 0;
        self._pad3 = 0;
        self.rd_start_ms_lo = 0;
        self.rd_start_ms_hi = 0;
        self.crc_buf = [0xFF; 2];
        self._pad4 = [0; 2];
        self.rb_state = BlockReadState::Idle;
        self.rb_attempts = 0;
        self.rb_addr = 0;
        self.rb_start_ms_lo = 0;
        self.rb_start_ms_hi = 0;
        self.init_state = SdInitPhase::Idle;
        self.init_retry = 0;
        self.init_preclk_count = 0;
        self._pad6 = 0;
        self.init_start_ms_lo = 0;
        self.init_start_ms_hi = 0;
        self.mod_state = SdModPhase::Reading;
        self.spi_bus = 0;
        self.pending_offset = 0;
        self.cs_pin = 5; // default CS pin
        self._pad5 = [0; 3];
        self.timer_fd = -1;
        self.out_chan = -1;
        self.start_block = 0;
        self.block_count = 0;
        self.current_block = 0;
    }

    #[inline(always)]
    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::SdState;
    use super::{p_u8, p_u32};
    use super::SCHEMA_MAX;

    define_params! {
        SdState;

        1, spi_bus, u8, 0
            => |s, d, len| { s.spi_bus = p_u8(d, len, 0, 0); };

        2, cs_pin, u8, 5
            => |s, d, len| { s.cs_pin = p_u8(d, len, 0, 5); };

        3, start_block, u32, 0
            => |s, d, len| { s.start_block = p_u32(d, len, 0, 0); };

        4, block_count, u32, 0
            => |s, d, len| { s.block_count = p_u32(d, len, 0, 0); };
    }
}

// ============================================================================
// PIC-Safe Macros
// ============================================================================
//
// These macros provide code reuse without runtime dispatch. They expand to
// explicit control flow at compile time, avoiding any panic-generating code.

/// Wait for send_cmd_poll to complete.
/// On error: sets init_state to SdInitPhase::Idle and returns -1.
/// On done: executes $on_done block.
/// On pending: returns 0.
macro_rules! wait_cmd {
    ($s:expr, $on_done:expr) => {{
        let res = send_cmd_poll($s);
        if res < 0 {
            $s.init_state = SdInitPhase::Idle;
            return -1;
        }
        if res > 0 {
            $on_done
        }
        return 0;
    }};
}

/// Wait for send_cmd_poll, then transition to next state.
/// Simpler form for commands with no special handling.
macro_rules! wait_cmd_then {
    ($s:expr, $next:expr) => {{
        let res = send_cmd_poll($s);
        if res < 0 {
            $s.init_state = SdInitPhase::Idle;
            return -1;
        }
        if res > 0 {
            $s.init_state = $next;
            continue;
        }
        return 0;
    }};
}

/// Wait for SPI transfer to complete.
/// On error: sets init_state to SdInitPhase::Idle and returns -1.
/// On done: executes $on_done block.
/// On pending: returns 0.
macro_rules! wait_xfer {
    ($s:expr, $on_done:expr) => {{
        let res = spi_transfer_poll($s);
        if res < 0 {
            $s.init_state = SdInitPhase::Idle;
            return -1;
        }
        if res > 0 {
            $on_done
        }
        return 0;
    }};
}

/// Wait for timer fd, then increment retry counter and go to retry state.
macro_rules! wait_timer {
    ($s:expr, $retry_state:expr) => {{
        // fd_poll returns POLL_IN (0x01) when timer expired, 0 when pending
        if dev_fd_poll($s.sys(), $s.timer_fd, 0x01) == 0 {
            return 0;
        }
        $s.init_retry += 1;
        $s.init_state = $retry_state;
        continue;
    }};
}

/// Set timer fd delay. If successful, transition to timer state.
/// If timer_set fails, increment retry and go to retry state.
macro_rules! try_start_timer {
    ($s:expr, $delay_ms:expr, $timer_state:expr, $retry_state:expr) => {{
        let mut ms_buf = ($delay_ms as u32).to_le_bytes();
        if ($s.sys().dev_call)($s.timer_fd, 0x0605, ms_buf.as_mut_ptr(), 4) == 0 {
            $s.init_state = $timer_state;
            return 0;
        }
        $s.init_retry += 1;
        $s.init_state = $retry_state;
        continue;
    }};
}

/// Start a command and transition to wait state.
macro_rules! start_cmd {
    ($s:expr, $cmd:expr, $arg:expr, $crc:expr, $release:expr, $extra:expr, $next:expr) => {{
        send_cmd_start($s, $cmd, $arg, $crc, $release, $extra);
        $s.init_state = $next;
        continue;
    }};
}

/// Fail initialization with error.
macro_rules! fail {
    ($s:expr) => {{
        $s.init_state = SdInitPhase::Idle;
        return -1;
    }};
}

// ============================================================================
// Helper Functions
// ============================================================================

#[inline(always)]
fn store_ms(lo: &mut u32, hi: &mut u32, ms: u64) {
    *lo = ms as u32;
    *hi = (ms >> 32) as u32;
}

#[inline(always)]
fn load_ms(lo: u32, hi: u32) -> u64 {
    (lo as u64) | ((hi as u64) << 32)
}

#[inline(always)]
unsafe fn millis(s: &SdState) -> u64 {
    dev_millis(s.sys())
}

#[inline(always)]
unsafe fn deselect(s: &SdState) {
    let mut lvl = [1u8];
    (s.sys().dev_call)(s.spi_handle, 0x0204, lvl.as_mut_ptr(), 1);
}

#[inline(always)]
unsafe fn release(s: &SdState) {
    (s.sys().dev_call)(s.spi_handle, 0x0203, core::ptr::null_mut(), 0);
}

#[inline(always)]
unsafe fn log_info(s: &SdState, msg: &[u8]) {
    dev_log(s.sys(), 3, msg.as_ptr(), msg.len());
}

/// Claim SPI bus, begin transaction, and assert CS.
/// Returns: 1 = success, 0 = pending, -1 = timeout/error
unsafe fn claim_begin_select(s: &mut SdState, start_ms: u64) -> i32 {
    let mut timeout = 0u32.to_le_bytes();
    if (s.sys().dev_call)(s.spi_handle, 0x0205, timeout.as_mut_ptr(), 4) == 0 {
        if (s.sys().dev_call)(s.spi_handle, 0x0202, core::ptr::null_mut(), 0) < 0 {
            return -1;
        }
        let mut lvl = [0u8];
        (s.sys().dev_call)(s.spi_handle, 0x0204, lvl.as_mut_ptr(), 1);
        return 1;
    }
    if millis(s).wrapping_sub(start_ms) >= CLAIM_TIMEOUT_MS {
        return -1;
    }
    0
}

// ============================================================================
// SPI Transfer Layer
// ============================================================================

unsafe fn spi_transfer_start(s: &mut SdState, tx: *const u8, rx: *mut u8, len: usize) -> bool {
    let mut args = SpiTransferStartArgs {
        tx,
        rx,
        len: len as u32,
        fill: 0xFF,
        _pad: [0; 3],
    };
    if (s.sys().dev_call)(s.spi_handle, 0x0207, &mut args as *mut _ as *mut u8,
        core::mem::size_of::<SpiTransferStartArgs>()) < 0 {
        return false;
    }
    s.spi_state = SpiXfer::Pending;
    true
}

/// Poll for multi-byte SPI transfer completion.
/// Returns: 0 = pending, 1 = done, -1 = error
///
/// Includes compiler_fence(Acquire) on completion because the kernel's
/// poll syscall doesn't take the RX pointer, so the compiler can't see
/// that the buffer was modified by DMA.
unsafe fn spi_transfer_poll(s: &mut SdState) -> i32 {
    if s.spi_state == SpiXfer::Idle {
        return -1;
    }
    // Bounded tight polling
    for _ in 0..8 {
        let res = (s.sys().dev_call)(s.spi_handle, 0x0208, core::ptr::null_mut(), 0);
        if res < 0 {
            s.spi_state = SpiXfer::Idle;
            return -1;
        }
        if res > 0 {
            compiler_fence(Ordering::Acquire);
            s.spi_state = SpiXfer::Idle;
            return 1;
        }
    }
    0
}

/// Poll for single-byte SPI transfer, returning byte in result.
/// Returns: <0 = error, 0 = pending, 0x100..0x1FF = done + byte value
unsafe fn spi_poll_byte(s: &mut SdState) -> i32 {
    if s.spi_state == SpiXfer::Idle {
        return -1;
    }
    for _ in 0..8 {
        let res = (s.sys().dev_call)(s.spi_handle, 0x0209, core::ptr::null_mut(), 0);
        if res < 0 {
            s.spi_state = SpiXfer::Idle;
            return res;
        }
        if res >= 0x100 {
            s.spi_state = SpiXfer::Idle;
            return res;
        }
    }
    0
}

/// Poll if pending, otherwise start a 1-byte read.
/// Returns: <0 = error, 0 = pending, 0x100..0x1FF = done + byte value
unsafe fn poll_or_start_byte(s: &mut SdState) -> i32 {
    if s.spi_state == SpiXfer::Pending {
        return spi_poll_byte(s);
    }
    let r1_ptr = s.r1_buf.as_mut_ptr();
    if !spi_transfer_start(s, ptr::null(), r1_ptr, 1) {
        return -1;
    }
    0
}

// ============================================================================
// Command Layer (send_cmd)
// ============================================================================

unsafe fn send_cmd_start(s: &mut SdState, cmd: u8, arg: u32, crc: u8, release: bool, extra_bytes: u8) {
    s.cmd_buf = [
        0x40 | cmd,
        (arg >> 24) as u8,
        (arg >> 16) as u8,
        (arg >> 8) as u8,
        arg as u8,
        crc | 0x01,
    ];
    s.cmd_release = if release { 1 } else { 0 };
    s.cmd_extra_count = if extra_bytes > 4 { 4 } else { extra_bytes };
    s.cmd_extra_idx = 0;
    s.cmd_extra = [0xFF; 4];
    s.cmd_response = 0xFF;
    s.cmd_attempts = 0;
    let ms = millis(s);
    store_ms(&mut s.cmd_start_ms_lo, &mut s.cmd_start_ms_hi, ms);
    s.cmd_state = CmdState::Selecting;
}

/// Poll command completion.
/// Returns: 0 = pending, 1 = done (r1 in cmd_response), -1 = error
unsafe fn send_cmd_poll(s: &mut SdState) -> i32 {
    loop {
        match s.cmd_state {
            CmdState::Idle => return -1,

            CmdState::Selecting => {
                let start_ms = load_ms(s.cmd_start_ms_lo, s.cmd_start_ms_hi);
                let claim_res = claim_begin_select(s, start_ms);
                if claim_res > 0 {
                    let cmd_ptr = s.cmd_buf.as_ptr();
                    if !spi_transfer_start(s, cmd_ptr, ptr::null_mut(), 6) {
                        s.cmd_state = CmdState::Idle;
                        return -1;
                    }
                    s.cmd_state = CmdState::SendingCmd;
                    continue;
                }
                if claim_res < 0 {
                    s.cmd_state = CmdState::Idle;
                    return -1;
                }
                return 0;
            }

            CmdState::SendingCmd => {
                let res = spi_transfer_poll(s);
                if res < 0 {
                    s.cmd_state = CmdState::Idle;
                    return -1;
                }
                if res > 0 {
                    s.cmd_attempts = 0;
                    s.cmd_state = CmdState::WaitingR1;
                    continue;
                }
                return 0;
            }

            CmdState::WaitingR1 => {
                let res = poll_or_start_byte(s);
                if res < 0 {
                    s.cmd_state = CmdState::Idle;
                    return -1;
                }
                if res >= 0x100 {
                    s.cmd_response = (res & 0xFF) as u8;
                    // Valid R1 has bit 7 clear
                    if s.cmd_response & 0x80 == 0 {
                        if s.cmd_extra_count > 0 {
                            s.cmd_extra_idx = 0;
                            s.cmd_state = CmdState::ReadingExtra;
                            continue;
                        }
                        if s.cmd_release != 0 {
                            deselect(s);
                            if !spi_transfer_start(s, ptr::null(), ptr::null_mut(), 1) {
                                s.cmd_state = CmdState::Idle;
                                return -1;
                            }
                            s.cmd_state = CmdState::SendingDummy;
                            continue;
                        }
                        s.cmd_state = CmdState::Idle;
                        return 1;
                    }
                    // Still waiting for valid R1
                    if s.cmd_attempts >= CMD_TIMEOUT as u8 {
                        deselect(s);
                        release(s);
                        s.cmd_state = CmdState::Idle;
                        return -1;
                    }
                    s.cmd_attempts += 1;
                }
                return 0;
            }

            CmdState::ReadingExtra => {
                let res = poll_or_start_byte(s);
                if res < 0 {
                    s.cmd_state = CmdState::Idle;
                    return -1;
                }
                if res >= 0x100 {
                    let idx = s.cmd_extra_idx as usize;
                    if idx < 4 {
                        s.cmd_extra[idx] = (res & 0xFF) as u8;
                    }
                    s.cmd_extra_idx += 1;
                    if s.cmd_extra_idx >= s.cmd_extra_count {
                        deselect(s);
                        if !spi_transfer_start(s, ptr::null(), ptr::null_mut(), 1) {
                            s.cmd_state = CmdState::Idle;
                            return -1;
                        }
                        s.cmd_state = CmdState::SendingDummy;
                        continue;
                    }
                }
                return 0;
            }

            CmdState::SendingDummy => {
                let res = spi_transfer_poll(s);
                if res < 0 {
                    s.cmd_state = CmdState::Idle;
                    return -1;
                }
                if res > 0 {
                    release(s);
                    s.cmd_state = CmdState::Idle;
                    if s.cmd_response == 0xFF {
                        return -1;
                    }
                    return 1;
                }
                return 0;
            }

            _ => return -1,
        }
    }
}

// ============================================================================
// Data Block Layer (read_data_block)
// ============================================================================

unsafe fn read_data_block_start(s: &mut SdState, buf: *mut u8, selected: bool) {
    s.rd_start_ms_lo = buf as u32;
    s.rd_start_ms_hi = 0;
    s.rd_attempts_lo = 0;
    s.rd_attempts_hi = 0;
    if selected {
        s.rd_state = DataReadState::WaitingToken;
    } else {
        let ms = millis(s);
        s.cmd_start_ms_lo = ms as u32;
        s.cmd_start_ms_hi = (ms >> 32) as u32;
        s.rd_state = DataReadState::Selecting;
    }
}

#[inline(always)]
fn get_rd_buf(s: &SdState) -> *mut u8 {
    s.rd_start_ms_lo as *mut u8
}

#[inline(always)]
fn get_rd_attempts(s: &SdState) -> u16 {
    (s.rd_attempts_lo as u16) | ((s.rd_attempts_hi as u16) << 8)
}

#[inline(always)]
fn set_rd_attempts(s: &mut SdState, v: u16) {
    s.rd_attempts_lo = v as u8;
    s.rd_attempts_hi = (v >> 8) as u8;
}

/// Poll data block read.
/// Returns: 0 = pending, 1 = done, -1 = error
unsafe fn read_data_block_poll(s: &mut SdState) -> i32 {
    loop {
        match s.rd_state {
            DataReadState::Idle => return -1,

            DataReadState::Selecting => {
                let start_ms = load_ms(s.cmd_start_ms_lo, s.cmd_start_ms_hi);
                let claim_res = claim_begin_select(s, start_ms);
                if claim_res > 0 {
                    set_rd_attempts(s, 0);
                    s.rd_state = DataReadState::WaitingToken;
                    continue;
                }
                if claim_res < 0 {
                    s.rd_state = DataReadState::Idle;
                    return -1;
                }
                return 0;
            }

            DataReadState::WaitingToken => {
                let res = poll_or_start_byte(s);
                if res < 0 {
                    s.rd_state = DataReadState::Idle;
                    return -1;
                }
                if res >= 0x100 {
                    if (res & 0xFF) as u8 == TOKEN_DATA {
                        let buf = get_rd_buf(s);
                        if !spi_transfer_start(s, ptr::null(), buf, BLOCK_SIZE) {
                            s.rd_state = DataReadState::Idle;
                            return -1;
                        }
                        s.rd_state = DataReadState::ReadingData;
                        return 0;
                    }
                    let attempts = get_rd_attempts(s);
                    if attempts >= 1000 {
                        deselect(s);
                        release(s);
                        s.rd_state = DataReadState::Idle;
                        return -1;
                    }
                    set_rd_attempts(s, attempts + 1);
                }
                return 0;
            }

            DataReadState::ReadingData => {
                let res = spi_transfer_poll(s);
                if res < 0 {
                    s.rd_state = DataReadState::Idle;
                    return -1;
                }
                if res > 0 {
                    let crc_ptr = s.crc_buf.as_mut_ptr();
                    if !spi_transfer_start(s, ptr::null(), crc_ptr, 2) {
                        s.rd_state = DataReadState::Idle;
                        return -1;
                    }
                    s.rd_state = DataReadState::ReadingCrc;
                    return 0;
                }
                return 0;
            }

            DataReadState::ReadingCrc => {
                let res = spi_transfer_poll(s);
                if res < 0 {
                    s.rd_state = DataReadState::Idle;
                    return -1;
                }
                if res > 0 {
                    deselect(s);
                    if !spi_transfer_start(s, ptr::null(), ptr::null_mut(), 1) {
                        s.rd_state = DataReadState::Idle;
                        return -1;
                    }
                    s.rd_state = DataReadState::SendingDummy;
                    return 0;
                }
                return 0;
            }

            DataReadState::SendingDummy => {
                let res = spi_transfer_poll(s);
                if res < 0 {
                    s.rd_state = DataReadState::Idle;
                    return -1;
                }
                if res > 0 {
                    release(s);
                    s.rd_state = DataReadState::Idle;
                    return 1;
                }
                return 0;
            }

            _ => return -1,
        }
    }
}

// ============================================================================
// Block Read Layer (read_block)
// ============================================================================

unsafe fn read_block_start(s: &mut SdState, block: u32, buf: *mut u8) {
    s.rb_start_ms_lo = buf as u32;
    s.rb_start_ms_hi = 0;
    s.rb_addr = block * s.cdv;
    s.cmd_buf = [
        0x40 | CMD17,
        (s.rb_addr >> 24) as u8,
        (s.rb_addr >> 16) as u8,
        (s.rb_addr >> 8) as u8,
        s.rb_addr as u8,
        0x01,
    ];
    let ms = millis(s);
    s.cmd_start_ms_lo = ms as u32;
    s.cmd_start_ms_hi = (ms >> 32) as u32;
    s.rb_state = BlockReadState::Selecting;
}

#[inline(always)]
fn get_rb_buf(s: &SdState) -> *mut u8 {
    s.rb_start_ms_lo as *mut u8
}

/// Poll block read.
/// Returns: 0 = pending, 1 = done, negative = error
/// Error codes: -1=idle, -2=claim_xfer, -3=claim_timeout, -4=cmd_xfer,
///   -5=r1_poll, -6=r1_error(response in rb_attempts), -7=r1_timeout,
///   -8=data_block, -9=unknown
unsafe fn read_block_poll(s: &mut SdState) -> i32 {
    loop {
        match s.rb_state {
            BlockReadState::Idle => return -1,

            BlockReadState::Selecting => {
                let start_ms = load_ms(s.cmd_start_ms_lo, s.cmd_start_ms_hi);
                let claim_res = claim_begin_select(s, start_ms);
                if claim_res > 0 {
                    let cmd_ptr = s.cmd_buf.as_ptr();
                    if !spi_transfer_start(s, cmd_ptr, ptr::null_mut(), 6) {
                        s.rb_state = BlockReadState::Idle;
                        return -2; // claim ok but CMD17 transfer start failed
                    }
                    s.rb_state = BlockReadState::SendingCmd;
                    continue;
                }
                if claim_res < 0 {
                    s.rb_state = BlockReadState::Idle;
                    return -3; // SPI claim timeout
                }
                return 0;
            }

            BlockReadState::SendingCmd => {
                let res = spi_transfer_poll(s);
                if res < 0 {
                    s.rb_state = BlockReadState::Idle;
                    return -4; // CMD17 SPI transfer error
                }
                if res > 0 {
                    s.rb_attempts = 0;
                    s.rb_state = BlockReadState::WaitingR1;
                    continue;
                }
                return 0;
            }

            BlockReadState::WaitingR1 => {
                let res = poll_or_start_byte(s);
                if res < 0 {
                    s.rb_state = BlockReadState::Idle;
                    return -5; // R1 poll byte error
                }
                if res >= 0x100 {
                    s.cmd_response = (res & 0xFF) as u8;
                    if s.cmd_response & 0x80 == 0 {
                        if s.cmd_response != 0 {
                            deselect(s);
                            release(s);
                            s.rb_state = BlockReadState::Idle;
                            s.rb_attempts = s.cmd_response; // stash R1 for logging
                            return -6; // R1 error (non-zero response)
                        }
                        let buf = get_rb_buf(s);
                        read_data_block_start(s, buf, true);
                        s.rb_state = BlockReadState::ReadingDataBlock;
                        continue;
                    }
                    if s.rb_attempts >= CMD_TIMEOUT as u8 {
                        deselect(s);
                        release(s);
                        s.rb_state = BlockReadState::Idle;
                        return -7; // R1 timeout (100 attempts)
                    }
                    s.rb_attempts += 1;
                }
                return 0;
            }

            BlockReadState::ReadingDataBlock => {
                let res = read_data_block_poll(s);
                if res < 0 {
                    s.rb_state = BlockReadState::Idle;
                    return -8; // data block read error
                }
                if res > 0 {
                    s.rb_state = BlockReadState::Idle;
                    return 1;
                }
                return 0;
            }

            _ => return -9,
        }
    }
}

// ============================================================================
// Initialization State Machine
// ============================================================================

unsafe fn init_start(s: &mut SdState) {
    let ms = millis(s);
    store_ms(&mut s.init_start_ms_lo, &mut s.init_start_ms_hi, ms);
    s.init_state = SdInitPhase::Claiming;
}

/// Poll initialization.
/// Returns: 0 = pending, 1 = done, -1 = error
unsafe fn init_poll(s: &mut SdState) -> i32 {
    loop {
        match s.init_state {
            // ----------------------------------------------------------------
            // Error state
            // ----------------------------------------------------------------
            SdInitPhase::Idle => {
                return -1;
            }

            // ----------------------------------------------------------------
            // Claim SPI bus
            // ----------------------------------------------------------------
            SdInitPhase::Claiming => {
                let start_ms = load_ms(s.init_start_ms_lo, s.init_start_ms_hi);
                let mut timeout = 0u32.to_le_bytes();
                let claim_rc = (s.sys().dev_call)(s.spi_handle, 0x0205, timeout.as_mut_ptr(), 4);
                if claim_rc == 0 {
                    let begin_rc = (s.sys().dev_call)(s.spi_handle, 0x0202, core::ptr::null_mut(), 0);
                    if begin_rc < 0 {
                        log_info(s, b"[sd] spi_begin failed");
                        fail!(s);
                    }
                    deselect(s);
                    let mut cfg = [0u8; 5];
                    cfg[0..4].copy_from_slice(&INIT_FREQ.to_le_bytes());
                    cfg[4] = 0;
                    (s.sys().dev_call)(s.spi_handle, 0x0206, cfg.as_mut_ptr(), 5);
                    s.init_preclk_count = 0;
                    s.init_state = SdInitPhase::Preclocking;
                    continue;
                }
                if millis(s).wrapping_sub(start_ms) >= CLAIM_TIMEOUT_MS {
                    log_info(s, b"[sd] claim timeout");
                    fail!(s);
                }
                return 0;
            }

            // ----------------------------------------------------------------
            // Flush card with dummy clocks, CS high (SD spec: ≥74 clocks).
            // After warm reset the card may be mid-block-read, so we send
            // 16 × 64 = 1024 bytes (8192 clocks) to drain any stuck data.
            // ----------------------------------------------------------------
            SdInitPhase::Preclocking => {
                if s.init_preclk_count >= 16 {
                    s.init_retry = 0;
                    s.init_state = SdInitPhase::Cmd0Start;
                    return 0; // Yield
                }
                if !spi_transfer_start(s, ptr::null(), ptr::null_mut(), 64) {
                    fail!(s);
                }
                s.init_state = SdInitPhase::PreclockingWait;
                return 0;
            }

            SdInitPhase::PreclockingWait => {
                wait_xfer!(s, {
                    s.init_preclk_count += 1;
                    s.init_state = SdInitPhase::Preclocking;
                    continue;
                });
            }

            // ----------------------------------------------------------------
            // CMD0: Reset card to SPI mode
            // ----------------------------------------------------------------
            SdInitPhase::Cmd0Start => {
                if s.init_retry >= 5 {
                    log_info(s, b"[sd] cmd0 timeout");
                    fail!(s);
                }
                start_cmd!(s, CMD0, 0, 0x95, true, 0, SdInitPhase::Cmd0Wait);
            }

            SdInitPhase::Cmd0Wait => {
                wait_cmd!(s, {
                    if s.cmd_response == R1_IDLE_STATE {
                        s.init_state = SdInitPhase::Cmd8Start;
                        continue;
                    }
                    try_start_timer!(s, 10, SdInitPhase::Cmd0Timer, SdInitPhase::Cmd0Start);
                });
            }

            SdInitPhase::Cmd0Timer => {
                wait_timer!(s, SdInitPhase::Cmd0Start);
            }

            // ----------------------------------------------------------------
            // CMD8: Check voltage (determines V1 vs V2 card)
            // ----------------------------------------------------------------
            SdInitPhase::Cmd8Start => {
                start_cmd!(s, CMD8, 0x01AA, 0x87, true, 4, SdInitPhase::Cmd8Wait);
            }

            SdInitPhase::Cmd8Wait => {
                wait_cmd!(s, {
                    if s.cmd_response == R1_IDLE_STATE {
                        // V2 card - verify echo pattern
                        if s.cmd_extra[2] != 0x01 || s.cmd_extra[3] != 0xAA {
                            log_info(s, b"[sd] cmd8 bad echo");
                            fail!(s);
                        }
                        s.init_retry = 0;
                        s.init_state = SdInitPhase::Cmd55v2Start;
                        continue;
                    } else if s.cmd_response == (R1_IDLE_STATE | R1_ILLEGAL_COMMAND) {
                        // V1 card - CMD8 not supported
                        s.init_retry = 0;
                        s.init_state = SdInitPhase::Cmd55v1Start;
                        continue;
                    }
                    fail!(s);
                });
            }

            // ----------------------------------------------------------------
            // V2 Path: CMD55 + ACMD41 with HCS bit
            // ----------------------------------------------------------------
            SdInitPhase::Cmd55v2Start => {
                if s.init_retry >= CMD_TIMEOUT as u8 {
                    log_info(s, b"[sd] acmd41v2 timeout");
                    fail!(s);
                }
                start_cmd!(s, CMD55, 0, 0, true, 0, SdInitPhase::Cmd55v2Wait);
            }

            SdInitPhase::Cmd55v2Wait => {
                wait_cmd_then!(s, SdInitPhase::Acmd41v2Start);
            }

            SdInitPhase::Acmd41v2Start => {
                // HCS bit (0x40000000) indicates host supports SDHC
                start_cmd!(s, ACMD41, 0x4000_0000, 0, true, 0, SdInitPhase::Acmd41v2Wait);
            }

            SdInitPhase::Acmd41v2Wait => {
                wait_cmd!(s, {
                    if s.cmd_response == 0 {
                        // Card ready - check capacity
                        s.init_state = SdInitPhase::Cmd58Start;
                        continue;
                    }
                    try_start_timer!(s, 50, SdInitPhase::Acmd41v2Timer, SdInitPhase::Cmd55v2Start);
                });
            }

            SdInitPhase::Acmd41v2Timer => {
                wait_timer!(s, SdInitPhase::Cmd55v2Start);
            }

            // ----------------------------------------------------------------
            // CMD58: Read OCR to determine SDHC vs standard capacity
            // ----------------------------------------------------------------
            SdInitPhase::Cmd58Start => {
                start_cmd!(s, CMD58, 0, 0, true, 4, SdInitPhase::Cmd58Wait);
            }

            SdInitPhase::Cmd58Wait => {
                wait_cmd!(s, {
                    // CCS bit indicates SDHC (block addressing)
                    if s.cmd_extra[0] & 0x40 != 0 {
                        s.cdv = 1;  // SDHC: address in blocks
                    } else {
                        s.cdv = 512; // Standard: address in bytes
                    }
                    s.init_state = SdInitPhase::Cmd9Start;
                    continue;
                });
            }

            // ----------------------------------------------------------------
            // V1 Path: CMD55 + ACMD41 without HCS bit
            // ----------------------------------------------------------------
            SdInitPhase::Cmd55v1Start => {
                if s.init_retry >= CMD_TIMEOUT as u8 {
                    log_info(s, b"[sd] acmd41v1 timeout");
                    fail!(s);
                }
                start_cmd!(s, CMD55, 0, 0, true, 0, SdInitPhase::Cmd55v1Wait);
            }

            SdInitPhase::Cmd55v1Wait => {
                wait_cmd_then!(s, SdInitPhase::Acmd41v1Start);
            }

            SdInitPhase::Acmd41v1Start => {
                start_cmd!(s, ACMD41, 0, 0, true, 0, SdInitPhase::Acmd41v1Wait);
            }

            SdInitPhase::Acmd41v1Wait => {
                wait_cmd!(s, {
                    if s.cmd_response == 0 {
                        s.cdv = 512; // V1 cards always use byte addressing
                        s.init_state = SdInitPhase::Cmd9Start;
                        continue;
                    }
                    try_start_timer!(s, 10, SdInitPhase::Acmd41v1Timer, SdInitPhase::Cmd55v1Start);
                });
            }

            SdInitPhase::Acmd41v1Timer => {
                wait_timer!(s, SdInitPhase::Cmd55v1Start);
            }

            // ----------------------------------------------------------------
            // CMD9: Read CSD register
            // ----------------------------------------------------------------
            SdInitPhase::Cmd9Start => {
                // release=false keeps CS asserted for data read
                start_cmd!(s, CMD9, 0, 0, false, 0, SdInitPhase::Cmd9Wait);
            }

            SdInitPhase::Cmd9Wait => {
                wait_cmd!(s, {
                    if s.cmd_response != 0 {
                        log_info(s, b"[sd] cmd9 failed");
                        deselect(s);
                        release(s);
                        fail!(s);
                    }
                    s.init_state = SdInitPhase::ReadingCsdStart;
                    continue;
                });
            }

            SdInitPhase::ReadingCsdStart => {
                let csd_ptr = s.csd_buf.as_mut_ptr();
                read_data_block_start(s, csd_ptr, false);
                s.init_state = SdInitPhase::ReadingCsdWait;
                continue;
            }

            SdInitPhase::ReadingCsdWait => {
                let res = read_data_block_poll(s);
                if res < 0 {
                    log_info(s, b"[sd] csd read failed");
                    fail!(s);
                }
                if res > 0 {
                    s.init_state = SdInitPhase::Cmd16Start;
                    continue;
                }
                return 0;
            }

            // ----------------------------------------------------------------
            // CMD16: Set block length to 512 bytes
            // ----------------------------------------------------------------
            SdInitPhase::Cmd16Start => {
                start_cmd!(s, CMD16, BLOCK_SIZE as u32, 0, true, 0, SdInitPhase::Cmd16Wait);
            }

            SdInitPhase::Cmd16Wait => {
                wait_cmd!(s, {
                    if s.cmd_response != 0 {
                        log_info(s, b"[sd] cmd16 failed");
                        fail!(s);
                    }
                    s.init_state = SdInitPhase::ConfigureDataFreq;
                    continue;
                });
            }

            // ----------------------------------------------------------------
            // Switch to data transfer frequency
            // ----------------------------------------------------------------
            SdInitPhase::ConfigureDataFreq => {
                let freq_bytes = DATA_FREQ.to_le_bytes();
                let mut cfg_arg = [freq_bytes[0], freq_bytes[1], freq_bytes[2], freq_bytes[3], 0u8];
                let sys = &*s.syscalls;
                let _ = (sys.dev_call)(s.spi_handle, 0x0206, cfg_arg.as_mut_ptr(), 5);
                s.init_state = SdInitPhase::Done;
                return 1;
            }

            SdInitPhase::Done => return 1,

            _ => return -1,
        }
    }
}

// ============================================================================
// Exported PIC Module Interface
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<SdState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    _in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() { return -2; }
        if state.is_null() { return -5; }
        if state_size < core::mem::size_of::<SdState>() { return -6; }

        let s = &mut *(state as *mut SdState);
        s.init(syscalls as *const SyscallTable);

        s.out_chan = out_chan;

        // Parse params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else if !params.is_null() && params_len >= core::mem::size_of::<SdParams>() {
            let cfg = &*(params as *const SdParams);
            s.spi_bus = cfg.spi_bus;
            s.cs_pin = cfg.cs_pin;
            s.start_block = cfg.start_block;
            s.block_count = cfg.block_count;
        } else {
            params_def::set_defaults(s);
        }

        s.current_block = s.start_block;

        // Request GPIO for CS pin via dev_call
        let cs_pin = s.cs_pin;
        let mut gpio_arg = [cs_pin];
        let cs_handle = (s.sys().dev_call)(-1, 0x0106, gpio_arg.as_mut_ptr(), 1);
        if cs_handle < 0 { return -10; }
        let mut lvl = [1u8];
        (s.sys().dev_call)(cs_handle, 0x0104, lvl.as_mut_ptr(), 1);

        // Open SPI via dev_call
        let spi_bus = s.spi_bus;
        let mut spi_args = SpiOpenArgs {
            cs_handle,
            freq_hz: INIT_FREQ,
            bus: spi_bus,
            mode: 0,
            _pad: [0; 2],
        };
        s.spi_handle = (s.sys().dev_call)(-1, 0x0200,
            &mut spi_args as *mut _ as *mut u8,
            core::mem::size_of::<SpiOpenArgs>());
        if s.spi_handle < 0 { return -12; }

        // Create timer fd for init retry delays (dev_timer::CREATE = 0x0604)
        s.timer_fd = (s.sys().dev_call)(-1, 0x0604, core::ptr::null_mut(), 0);
        if s.timer_fd < 0 { return -13; }

        s.init_state = SdInitPhase::Idle;
        s.mod_state = SdModPhase::Reading;

        0
    }
}

/// Write result
enum WriteResult {
    /// All data written
    Complete,
    /// Partial write - need to retry remaining
    Partial,
    /// Channel full - retry later
    WouldBlock,
    /// Error
    Error(i32),
}

/// Try to write block buffer (or remaining portion) to output channel.
#[inline]
unsafe fn try_write_block(s: &mut SdState) -> WriteResult {
    if s.out_chan < 0 {
        return WriteResult::Complete;
    }

    let offset = s.pending_offset as usize;
    let remaining = BLOCK_SIZE - offset;

    let written = (s.sys().channel_write)(
        s.out_chan,
        s.block_buf.as_ptr().add(offset),
        remaining,
    );

    if written < 0 {
        if written == E_AGAIN {
            return WriteResult::WouldBlock;
        }
        return WriteResult::Error(E_WRITE_FAILED);
    }

    let w = written as usize;
    if w >= remaining {
        // All done
        s.pending_offset = 0;
        WriteResult::Complete
    } else if w > 0 {
        // Partial write - track remainder
        s.pending_offset += w as u16;
        WriteResult::Partial
    } else {
        WriteResult::WouldBlock
    }
}

/// Check for pending seek request on output channel.
/// Returns the seek position if one is pending, or u32::MAX if none.
#[inline]
unsafe fn check_seek_request(s: &SdState) -> u32 {
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

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() { return -1; }
        let s = &mut *(state as *mut SdState);
        if s.syscalls.is_null() { return -1; }

        // Run init if not done
        if s.init_state != SdInitPhase::Done {
            if s.init_state == SdInitPhase::Idle {
                init_start(s);
            }
            let res = init_poll(s);
            if res < 0 {
                log_info(s, b"[sd] init failed");
                return E_INIT_FAILED;
            }
            if res == 0 {
                return 0;
            }
            log_info(s, b"[sd] init done");
        }

        // Check for seek request (when not mid-SPI-read)
        if s.rb_state == BlockReadState::Idle {
            let seek_pos = check_seek_request(s);
            if seek_pos != u32::MAX {
                // Seek to the requested block — discard any pending write
                s.current_block = seek_pos;
                s.pending_offset = 0;
                s.mod_state = SdModPhase::Reading;
            }
        }

        // Read blocks
        match s.mod_state {
            SdModPhase::Reading => {
                // Check if we've read all blocks (block_count=0 means unlimited)
                if s.block_count > 0 && s.current_block >= s.start_block + s.block_count {
                    s.mod_state = SdModPhase::Done;
                    log_info(s, b"[sd] all read");
                    return 0; // Return 0 to let downstream drain
                }

                // Start a new read if idle (with backpressure check)
                if s.rb_state == BlockReadState::Idle {
                    if s.out_chan >= 0 {
                        let poll = (s.sys().channel_poll)(s.out_chan, POLL_OUT);
                        if poll <= 0 || (poll as u8 & POLL_OUT) == 0 {
                            return 0; // Channel not ready
                        }
                    }
                    let buf = s.block_buf.as_mut_ptr();
                    read_block_start(s, s.current_block, buf);
                }

                // Poll the read
                let res = read_block_poll(s);
                if res < 0 {
                    // Log: [sd] E<code> @<block>
                    let mut lb = [0u8; 40];
                    let tag = b"[sd] E";
                    let mut p = 0usize;
                    let mut t = 0usize;
                    while t < tag.len() { unsafe { *lb.as_mut_ptr().add(p) = *tag.as_ptr().add(t); } p += 1; t += 1; }
                    // Error code (negate to get positive)
                    let ecode = (0i32.wrapping_sub(res)) as u32;
                    p += unsafe { fmt_u32_raw(lb.as_mut_ptr().add(p), ecode) };
                    let at = b" @";
                    t = 0; while t < at.len() { unsafe { *lb.as_mut_ptr().add(p) = *at.as_ptr().add(t); } p += 1; t += 1; }
                    p += unsafe { fmt_u32_raw(lb.as_mut_ptr().add(p), s.current_block) };
                    if res == -6 {
                        // Also log R1 response byte
                        let r1t = b" R1=";
                        t = 0; while t < r1t.len() { unsafe { *lb.as_mut_ptr().add(p) = *r1t.as_ptr().add(t); } p += 1; t += 1; }
                        p += unsafe { fmt_u32_raw(lb.as_mut_ptr().add(p), s.rb_attempts as u32) };
                    }
                    unsafe { dev_log(s.sys(), 3, lb.as_ptr(), p); }
                    return E_READ_FAILED;
                }
                if res > 0 {
                    // Block read complete — check if a seek arrived during the read
                    let seek_pos = check_seek_request(s);
                    if seek_pos != u32::MAX {
                        // Discard this stale block — seek overrides
                        s.current_block = seek_pos;
                        s.pending_offset = 0;
                    } else {
                        // No seek — write the block normally
                        s.pending_offset = 0;
                        match try_write_block(s) {
                            WriteResult::Complete => s.current_block += 1,
                            WriteResult::Partial => s.mod_state = SdModPhase::WritingPending,
                            WriteResult::WouldBlock => s.mod_state = SdModPhase::Writing,
                            WriteResult::Error(e) => return e,
                        }
                    }
                }
                0
            }

            SdModPhase::Writing => {
                // Retry writing the full block (nothing written yet)
                match try_write_block(s) {
                    WriteResult::Complete => {
                        s.current_block += 1;
                        s.mod_state = SdModPhase::Reading;
                    }
                    WriteResult::Partial => s.mod_state = SdModPhase::WritingPending,
                    WriteResult::WouldBlock => {}
                    WriteResult::Error(e) => return e,
                }
                0
            }

            SdModPhase::WritingPending => {
                // Retry writing remaining portion of partial write
                match try_write_block(s) {
                    WriteResult::Complete => {
                        s.current_block += 1;
                        s.mod_state = SdModPhase::Reading;
                    }
                    WriteResult::Partial => {} // Still more to write
                    WriteResult::WouldBlock => {}
                    WriteResult::Error(e) => return e,
                }
                0
            }

            SdModPhase::Done => 1,

            _ => -1,
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
