//! PIO Stream Provider — PIC module replacing Embassy async PIO system
//!
//! Handles three PIO service modes via polling + kernel bridges:
//!   - **TX Stream** (mode 0): double-buffered DMA to PIO TX FIFO
//!   - **Cmd** (mode 1): bidirectional PIO transfers (gSPI-style)
//!   - **RX Stream** (mode 2): continuous DMA capture from PIO RX FIFO
//!
//! Consumers (i2s, cyw43, st7701s, mic_source) use the same dev_call
//! opcodes (0x0400-0x0427). This module registers as the PIO provider
//! (device class 0x04) and dispatches to internal slot management.
//!
//! All hardware access goes through kernel bridges:
//!   - PIO register bridge (0x0C70-0x0C7B): SM config, instruction memory
//!   - DMA FD bridge (0x0C85-0x0C89): DMA channel lifecycle + transfers
//!   - FD_POLL (0x0C41): non-blocking DMA completion check

#![no_std]

use core::ffi::c_void;

#[path = "../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../pic_runtime.rs");
include!("../param_macro.rs");

// ============================================================================
// Constants
// ============================================================================

const MAX_STREAM_SLOTS: usize = 2;
const MAX_CMD_SLOTS: usize = 2;
const MAX_RX_SLOTS: usize = 1;
const TOTAL_SLOTS: usize = MAX_STREAM_SLOTS + MAX_CMD_SLOTS + MAX_RX_SLOTS;

/// TX stream buffer size in u32 words (2048 words = 8KB per buffer)
const STREAM_BUF_WORDS: usize = 2048;
/// CMD scratch buffer size in u32 words (512 words = 2KB)
const CMD_SCRATCH_WORDS: usize = 512;
/// RX stream buffer size in u32 words (512 words = 2KB per buffer)
const RX_BUF_WORDS: usize = 512;

// Slot states
const SLOT_FREE: u8 = 0;
const SLOT_ALLOCATED: u8 = 1;
const SLOT_READY: u8 = 2;
const SLOT_BUSY: u8 = 3;

// PIO provider opcodes (from abi.rs dev_pio)
const STREAM_ALLOC: u32 = 0x0400;
const STREAM_LOAD_PROGRAM: u32 = 0x0401;
const STREAM_GET_BUFFER: u32 = 0x0402;
const STREAM_CONFIGURE: u32 = 0x0403;
const STREAM_CAN_PUSH: u32 = 0x0404;
const STREAM_PUSH: u32 = 0x0405;
const STREAM_FREE: u32 = 0x0406;
const STREAM_TIME: u32 = 0x0407;
const DIRECT_BUFFER: u32 = 0x0408;
const DIRECT_PUSH: u32 = 0x0409;
const PROGRAM_STATUS: u32 = 0x040A;
const STREAM_SET_RATE: u32 = 0x040B;

const CMD_ALLOC: u32 = 0x0410;
const CMD_LOAD_PROGRAM: u32 = 0x0411;
const CMD_CONFIGURE: u32 = 0x0412;
const CMD_TRANSFER: u32 = 0x0413;
const CMD_POLL: u32 = 0x0414;
const CMD_FREE: u32 = 0x0415;

const RX_STREAM_ALLOC: u32 = 0x0420;
const RX_STREAM_LOAD_PROGRAM: u32 = 0x0421;
const RX_STREAM_CONFIGURE: u32 = 0x0422;
const RX_STREAM_CAN_PULL: u32 = 0x0423;
const RX_STREAM_PULL: u32 = 0x0424;
const RX_STREAM_FREE: u32 = 0x0425;
const RX_STREAM_GET_BUFFER: u32 = 0x0426;
const RX_STREAM_SET_RATE: u32 = 0x0427;

// Kernel bridge opcodes
const PIO_SM_EXEC: u32 = 0x0C70;
const PIO_SM_WRITE_REG: u32 = 0x0C71;
const PIO_SM_READ_REG: u32 = 0x0C72;
const PIO_SM_ENABLE: u32 = 0x0C73;
const PIO_INSTR_ALLOC: u32 = 0x0C74;
const PIO_INSTR_WRITE: u32 = 0x0C75;
const PIO_INSTR_FREE: u32 = 0x0C76;
const PIO_PIN_SETUP: u32 = 0x0C77;
#[allow(dead_code)]
const PIO_GPIOBASE: u32 = 0x0C78;
const PIO_TXF_WRITE: u32 = 0x0C79;
const PIO_FSTAT_READ: u32 = 0x0C7A;
const PIO_SM_RESTART: u32 = 0x0C7B;

const DMA_FD_CREATE: u32 = 0x0C85;
const DMA_FD_START: u32 = 0x0C86;
const DMA_FD_RESTART: u32 = 0x0C87;
const DMA_FD_FREE: u32 = 0x0C88;
const DMA_FD_QUEUE: u32 = 0x0C89;
const FD_POLL: u32 = 0x0C41;

// DMA flags
const DMA_FLAG_INCR_READ: u8 = 0x01;
#[allow(dead_code)]
const DMA_FLAG_INCR_WRITE: u8 = 0x02;
const DMA_FLAG_SIZE_32: u8 = 0x04;

// FSTAT bit positions
const FSTAT_TXFULL_SHIFT: u32 = 16;
const FSTAT_RXEMPTY_SHIFT: u32 = 0;

// SM register indices (for PIO_SM_WRITE_REG / PIO_SM_READ_REG)
const REG_CLKDIV: u8 = 0;
const REG_EXECCTRL: u8 = 1;
const REG_SHIFTCTRL: u8 = 2;
const REG_PINCTRL: u8 = 3;

// POLL_IN defined in pic_runtime.rs

// ============================================================================
// PIO program (stored in slot, max 32 instructions)
// ============================================================================

const MAX_PIO_INSTRUCTIONS: usize = 32;

#[repr(C)]
struct PioProgram {
    instructions: [u16; MAX_PIO_INSTRUCTIONS],
    length: u8,
    wrap_target: u8,
    wrap: u8,
    sideset_bits: u8,
    sideset_optional: u8,
    sideset_pindirs: u8,
    _pad: [u8; 2],
}

// ============================================================================
// TX Stream Slot
// ============================================================================

#[repr(C)]
struct StreamSlot {
    state: u8,
    pio_num: u8,
    sm_num: u8,      // assigned at configure time via pio_num default 0
    active_buf: u8,   // 0=A is front (DMA source), 1=B is front
    dma_fd: i32,
    push_pending: u8,
    push_count: u16,  // words pending in back buffer
    _pad0: u8,
    instr_mask: u32,  // allocated instruction slots
    instr_origin: u8,
    program_loaded: u8,
    program_status: u8, // 0=none, 1=pending, 2=loaded, 3=error
    dma_active: u8,
    out_pin: u8,
    sideset_base: u8,
    shift_bits: u8,
    _pad1: u8,
    clock_div: u32,
    program: PioProgram,
    // Stream timing
    consumed_lo: u32,
    consumed_hi: u32,
    queued_units: u32,
    rate_q16: u32,
    t0_lo: u32,
    t0_hi: u32,
    // Double buffers
    buf_a: [u32; STREAM_BUF_WORDS],
    buf_b: [u32; STREAM_BUF_WORDS],
}

// ============================================================================
// CMD Slot
// ============================================================================

#[repr(C)]
struct CmdSlot {
    state: u8,
    pio_num: u8,
    sm_num: u8,
    program_loaded: u8,
    program_status: u8,
    data_pin: u8,
    clk_pin: u8,
    _pad0: u8,
    clock_div: u32,
    instr_mask: u32,
    instr_origin: u8,
    dma_ch: u8,       // raw DMA channel (not FD — cmd uses blocking)
    _pad1: [u8; 2],
    program: PioProgram,
    scratch: [u32; CMD_SCRATCH_WORDS],
}

// ============================================================================
// RX Stream Slot
// ============================================================================

#[repr(C)]
struct RxSlot {
    state: u8,
    pio_num: u8,
    sm_num: u8,
    active_buf: u8,   // which buffer DMA is filling (0=A, 1=B)
    dma_fd: i32,
    instr_mask: u32,
    instr_origin: u8,
    program_loaded: u8,
    program_status: u8,
    dma_active: u8,
    pull_ready: u8,    // 1 = readable buffer available
    pull_count: u16,   // words in readable buffer
    in_pin: u8,
    sideset_base: u8,
    shift_bits: u8,
    _pad0: u8,
    clock_div: u32,
    rate_q16: u32,
    overflow_count: u32,
    program: PioProgram,
    buf_a: [u32; RX_BUF_WORDS],
    buf_b: [u32; RX_BUF_WORDS],
}

// ============================================================================
// Module State
// ============================================================================

#[repr(C)]
struct PioState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    step_count: u32,
    streams: [StreamSlot; MAX_STREAM_SLOTS],
    cmds: [CmdSlot; MAX_CMD_SLOTS],
    rxs: [RxSlot; MAX_RX_SLOTS],
}

// ============================================================================
// Kernel bridge helpers
// ============================================================================

#[inline(always)]
unsafe fn pio_sm_exec(sys: &SyscallTable, pio_num: u8, sm: u8, instr: u16) {
    let mut buf = [0u8; 4];
    let p = buf.as_mut_ptr();
    *p = pio_num;
    *p.add(1) = sm;
    let ib = instr.to_le_bytes();
    *p.add(2) = ib[0];
    *p.add(3) = ib[1];
    (sys.dev_call)(-1, PIO_SM_EXEC, p, 4);
}

#[inline(always)]
unsafe fn pio_sm_write_reg(sys: &SyscallTable, pio_num: u8, sm: u8, reg: u8, value: u32) {
    let mut buf = [0u8; 7];
    let p = buf.as_mut_ptr();
    *p = pio_num;
    *p.add(1) = sm;
    *p.add(2) = reg;
    let vb = value.to_le_bytes();
    *p.add(3) = vb[0]; *p.add(4) = vb[1]; *p.add(5) = vb[2]; *p.add(6) = vb[3];
    (sys.dev_call)(-1, PIO_SM_WRITE_REG, p, 7);
}

#[inline(always)]
unsafe fn pio_sm_enable(sys: &SyscallTable, pio_num: u8, sm_mask: u8, enable: bool) {
    let mut buf = [pio_num, sm_mask, if enable { 1 } else { 0 }];
    (sys.dev_call)(-1, PIO_SM_ENABLE, buf.as_mut_ptr(), 3);
}

unsafe fn pio_instr_alloc(sys: &SyscallTable, pio_num: u8, count: u8) -> (i32, u32) {
    let mut buf = [0u8; 6];
    let p = buf.as_mut_ptr();
    *p = pio_num;
    *p.add(1) = count;
    let origin = (sys.dev_call)(-1, PIO_INSTR_ALLOC, p, 6);
    let mask = u32::from_le_bytes([*p.add(2), *p.add(3), *p.add(4), *p.add(5)]);
    (origin, mask)
}

unsafe fn pio_instr_write(sys: &SyscallTable, pio_num: u8, addr: u8, instr: u16) {
    let mut buf = [0u8; 4];
    let p = buf.as_mut_ptr();
    *p = pio_num;
    *p.add(1) = addr;
    let ib = instr.to_le_bytes();
    *p.add(2) = ib[0];
    *p.add(3) = ib[1];
    (sys.dev_call)(-1, PIO_INSTR_WRITE, p, 4);
}

unsafe fn pio_instr_free(sys: &SyscallTable, pio_num: u8, mask: u32) {
    let mut buf = [0u8; 5];
    let p = buf.as_mut_ptr();
    *p = pio_num;
    let mb = mask.to_le_bytes();
    *p.add(1) = mb[0]; *p.add(2) = mb[1]; *p.add(3) = mb[2]; *p.add(4) = mb[3];
    (sys.dev_call)(-1, PIO_INSTR_FREE, p, 5);
}

unsafe fn pio_pin_setup(sys: &SyscallTable, pin: u8, pio_num: u8, pull: u8) {
    let mut buf = [pin, pio_num, pull];
    (sys.dev_call)(-1, PIO_PIN_SETUP, buf.as_mut_ptr(), 3);
}

unsafe fn pio_fstat_read(sys: &SyscallTable, pio_num: u8) -> u32 {
    let mut buf = [pio_num];
    (sys.dev_call)(-1, PIO_FSTAT_READ, buf.as_mut_ptr(), 1) as u32
}

unsafe fn pio_sm_restart(sys: &SyscallTable, pio_num: u8, sm_mask: u8) {
    let mut buf = [pio_num, sm_mask];
    (sys.dev_call)(-1, PIO_SM_RESTART, buf.as_mut_ptr(), 2);
}

unsafe fn pio_txf_write(sys: &SyscallTable, pio_num: u8, sm: u8, value: u32) {
    let mut buf = [0u8; 6];
    let p = buf.as_mut_ptr();
    *p = pio_num;
    *p.add(1) = sm;
    let vb = value.to_le_bytes();
    *p.add(2) = vb[0]; *p.add(3) = vb[1]; *p.add(4) = vb[2]; *p.add(5) = vb[3];
    (sys.dev_call)(-1, PIO_TXF_WRITE, p, 6);
}

// DMA FD helpers
unsafe fn dma_fd_create(sys: &SyscallTable) -> i32 {
    (sys.dev_call)(-1, DMA_FD_CREATE, core::ptr::null_mut(), 0)
}

unsafe fn dma_fd_start(
    sys: &SyscallTable, fd: i32,
    read_addr: u32, write_addr: u32, count: u32,
    dreq: u8, flags: u8,
) -> i32 {
    let mut buf = [0u8; 14];
    let p = buf.as_mut_ptr();
    let ra = read_addr.to_le_bytes();
    *p = ra[0]; *p.add(1) = ra[1]; *p.add(2) = ra[2]; *p.add(3) = ra[3];
    let wa = write_addr.to_le_bytes();
    *p.add(4) = wa[0]; *p.add(5) = wa[1]; *p.add(6) = wa[2]; *p.add(7) = wa[3];
    let cb = count.to_le_bytes();
    *p.add(8) = cb[0]; *p.add(9) = cb[1]; *p.add(10) = cb[2]; *p.add(11) = cb[3];
    *p.add(12) = dreq;
    *p.add(13) = flags;
    (sys.dev_call)(fd, DMA_FD_START, p, 14)
}

unsafe fn dma_fd_queue(
    sys: &SyscallTable, fd: i32,
    read_addr: u32, count: u32,
) -> i32 {
    let mut buf = [0u8; 8];
    let p = buf.as_mut_ptr();
    let ra = read_addr.to_le_bytes();
    *p = ra[0]; *p.add(1) = ra[1]; *p.add(2) = ra[2]; *p.add(3) = ra[3];
    let cb = count.to_le_bytes();
    *p.add(4) = cb[0]; *p.add(5) = cb[1]; *p.add(6) = cb[2]; *p.add(7) = cb[3];
    (sys.dev_call)(fd, DMA_FD_QUEUE, p, 8)
}

unsafe fn dma_fd_free(sys: &SyscallTable, fd: i32) {
    (sys.dev_call)(fd, DMA_FD_FREE, core::ptr::null_mut(), 0);
}

unsafe fn dma_fd_poll(sys: &SyscallTable, fd: i32) -> bool {
    (sys.dev_call)(fd, FD_POLL, &POLL_IN as *const u8 as *mut u8, 1) & (POLL_IN as i32) != 0
}

// Raw DMA helpers (for CMD blocking transfers)
unsafe fn raw_dma_alloc(sys: &SyscallTable) -> i32 {
    (sys.dev_call)(-1, 0x0C80, core::ptr::null_mut(), 0)
}

unsafe fn raw_dma_free(sys: &SyscallTable, ch: u8) {
    let mut buf = [ch];
    (sys.dev_call)(-1, 0x0C81, buf.as_mut_ptr(), 1);
}

unsafe fn raw_dma_start(sys: &SyscallTable, ch: u8, read: u32, write: u32, count: u32, dreq: u8, flags: u8) -> i32 {
    let mut buf = [0u8; 15];
    let p = buf.as_mut_ptr();
    *p = ch;
    let r = read.to_le_bytes();
    *p.add(1) = r[0]; *p.add(2) = r[1]; *p.add(3) = r[2]; *p.add(4) = r[3];
    let w = write.to_le_bytes();
    *p.add(5) = w[0]; *p.add(6) = w[1]; *p.add(7) = w[2]; *p.add(8) = w[3];
    let c = count.to_le_bytes();
    *p.add(9) = c[0]; *p.add(10) = c[1]; *p.add(11) = c[2]; *p.add(12) = c[3];
    *p.add(13) = dreq;
    *p.add(14) = flags;
    (sys.dev_call)(-1, 0x0C82, p, 15)
}

unsafe fn raw_dma_busy(sys: &SyscallTable, ch: u8) -> bool {
    let mut buf = [ch];
    (sys.dev_call)(-1, 0x0C83, buf.as_mut_ptr(), 1) != 0
}

// ============================================================================
// Program loading + SM configuration
// ============================================================================

/// Load program instructions into PIO instruction memory.
/// Returns origin on success, -1 on failure.
unsafe fn load_program(
    sys: &SyscallTable,
    pio_num: u8,
    prog: &PioProgram,
    old_mask: u32,
) -> (i32, u32) {
    // Free old slots
    if old_mask != 0 {
        pio_instr_free(sys, pio_num, old_mask);
    }
    // Allocate new
    let (origin, mask) = pio_instr_alloc(sys, pio_num, prog.length);
    if origin < 0 {
        return (-1, 0);
    }
    // Write instructions
    let mut i = 0u8;
    while (i as usize) < prog.length as usize {
        let addr = ((origin as u8).wrapping_add(i)) & 31;
        let instr_ptr = prog.instructions.as_ptr().add(i as usize);
        pio_instr_write(sys, pio_num, addr, core::ptr::read_volatile(instr_ptr));
        i += 1;
    }
    (origin, mask)
}

/// Configure SM for TX streaming (autopull, MSB-first, join TX FIFO)
unsafe fn configure_stream_sm(
    sys: &SyscallTable,
    slot: &StreamSlot,
    origin: u8,
) {
    let pio_num = slot.pio_num;
    let sm = slot.sm_num;
    let sm_mask = 1u8 << sm;

    // Disable SM
    pio_sm_enable(sys, pio_num, sm_mask, false);

    // Restart SM
    pio_sm_restart(sys, pio_num, sm_mask);

    // EXECCTRL: wrap boundaries + sideset config
    let wrap_bottom = origin + slot.program.wrap_target;
    let wrap_top = origin + slot.program.wrap;
    // Build execctrl value:
    // wrap_bottom[11:7], wrap_top[16:12], side_en[30], side_pindir[29]
    let mut execctrl: u32 = 0;
    execctrl |= (wrap_bottom as u32) << 7;    // WRAP_BOTTOM
    execctrl |= (wrap_top as u32) << 12;      // WRAP_TOP
    if slot.program.sideset_optional != 0 {
        execctrl |= 1 << 30; // SIDE_EN
    }
    if slot.program.sideset_pindirs != 0 {
        execctrl |= 1 << 29; // SIDE_PINDIR
    }
    pio_sm_write_reg(sys, pio_num, sm, REG_EXECCTRL, execctrl);

    // PINCTRL: out_base, out_count=1, sideset_base, sideset_count, set_base, set_count=1
    let mut pinctrl: u32 = 0;
    pinctrl |= slot.out_pin as u32;                    // OUT_BASE [4:0]
    pinctrl |= 1 << 20;                                // OUT_COUNT [25:20] = 1
    pinctrl |= (slot.sideset_base as u32) << 10;       // SIDESET_BASE [14:10]
    pinctrl |= (slot.program.sideset_bits as u32) << 26; // SIDESET_COUNT [31:29] — actually [28:26]
    pinctrl |= (slot.out_pin as u32) << 5;             // SET_BASE [9:5]
    pinctrl |= 1 << 26;                                // SET_COUNT [28:26] = 1 — wait, overlaps with SIDESET_COUNT
    // Actually RP2350 PINCTRL layout:
    //  [4:0]   = OUT_BASE
    //  [9:5]   = SET_BASE
    //  [14:10] = SIDESET_BASE
    //  [19:15] = IN_BASE
    //  [25:20] = OUT_COUNT
    //  [28:26] = SET_COUNT
    //  [31:29] = SIDESET_COUNT
    pinctrl = 0;
    pinctrl |= slot.out_pin as u32;                         // [4:0] OUT_BASE
    pinctrl |= (slot.out_pin as u32) << 5;                  // [9:5] SET_BASE
    pinctrl |= (slot.sideset_base as u32) << 10;            // [14:10] SIDESET_BASE
    pinctrl |= 1u32 << 20;                                  // [25:20] OUT_COUNT=1
    pinctrl |= 1u32 << 26;                                  // [28:26] SET_COUNT=1
    pinctrl |= (slot.program.sideset_bits as u32) << 29;    // [31:29] SIDESET_COUNT
    pio_sm_write_reg(sys, pio_num, sm, REG_PINCTRL, pinctrl);

    // CLKDIV: integer part shifted left by 16, frac by 8
    // The kernel bridge expects the raw register value
    pio_sm_write_reg(sys, pio_num, sm, REG_CLKDIV, slot.clock_div << 8);

    // SHIFTCTRL: join TX, autopull, MSB-first, pull_thresh
    let mut shiftctrl: u32 = 0;
    shiftctrl |= 1 << 30;  // FJOIN_TX
    shiftctrl |= 1 << 17;  // AUTOPULL
    // OUT_SHIFTDIR=0 (shift left = MSB first) — bit 19
    // PULL_THRESH [24:20]
    shiftctrl |= (slot.shift_bits as u32 & 0x1F) << 20;
    pio_sm_write_reg(sys, pio_num, sm, REG_SHIFTCTRL, shiftctrl);

    // Set pin directions: force SET PINDIRS, 1
    // First set pinctrl for SET to point at out_pin
    let set_pinctrl = (slot.out_pin as u32) | ((slot.out_pin as u32) << 5) | (1u32 << 26);
    pio_sm_write_reg(sys, pio_num, sm, REG_PINCTRL, set_pinctrl);
    pio_sm_exec(sys, pio_num, sm, 0xE081); // SET PINDIRS, 1

    // SET PINS, 0 (drive low)
    pio_sm_exec(sys, pio_num, sm, 0xE000); // SET PINS, 0

    // If sideset pins differ from out, set their directions too
    if slot.sideset_base != slot.out_pin && slot.program.sideset_bits > 0 {
        let ss_pinctrl = (slot.sideset_base as u32) << 5
            | (slot.program.sideset_bits as u32) << 26;
        pio_sm_write_reg(sys, pio_num, sm, REG_PINCTRL, ss_pinctrl);
        let ss_mask = (1u16 << slot.program.sideset_bits) - 1;
        pio_sm_exec(sys, pio_num, sm, 0xE080 | ss_mask); // SET PINDIRS, mask
    }

    // Restore full pinctrl
    pio_sm_write_reg(sys, pio_num, sm, REG_PINCTRL, pinctrl);

    // Jump to entry point (wrap top)
    let entry = origin + slot.program.wrap;
    pio_sm_exec(sys, pio_num, sm, entry as u16); // JMP entry

    // Enable
    pio_sm_enable(sys, pio_num, sm_mask, true);
}

/// Configure SM for CMD mode (bidirectional: autopull+autopush, MSB-first)
unsafe fn configure_cmd_sm(
    sys: &SyscallTable,
    slot: &CmdSlot,
    origin: u8,
) {
    let pio_num = slot.pio_num;
    let sm = slot.sm_num;
    let sm_mask = 1u8 << sm;

    pio_sm_enable(sys, pio_num, sm_mask, false);
    pio_sm_restart(sys, pio_num, sm_mask);

    // EXECCTRL
    let wrap_bottom = origin + slot.program.wrap_target;
    let wrap_top = origin + slot.program.wrap;
    let mut execctrl: u32 = 0;
    execctrl |= (wrap_bottom as u32) << 7;
    execctrl |= (wrap_top as u32) << 12;
    if slot.program.sideset_optional != 0 { execctrl |= 1 << 30; }
    if slot.program.sideset_pindirs != 0 { execctrl |= 1 << 29; }
    pio_sm_write_reg(sys, pio_num, sm, REG_EXECCTRL, execctrl);

    // PINCTRL: out=data, in=data, set=data, sideset=clk
    let mut pinctrl: u32 = 0;
    pinctrl |= slot.data_pin as u32;                         // [4:0] OUT_BASE
    pinctrl |= (slot.data_pin as u32) << 5;                  // [9:5] SET_BASE
    pinctrl |= (slot.clk_pin as u32) << 10;                  // [14:10] SIDESET_BASE
    pinctrl |= (slot.data_pin as u32) << 15;                 // [19:15] IN_BASE
    pinctrl |= 1u32 << 20;                                   // [25:20] OUT_COUNT=1
    pinctrl |= 1u32 << 26;                                   // [28:26] SET_COUNT=1
    pinctrl |= (slot.program.sideset_bits as u32) << 29;     // [31:29] SIDESET_COUNT
    pio_sm_write_reg(sys, pio_num, sm, REG_PINCTRL, pinctrl);

    // CLKDIV
    pio_sm_write_reg(sys, pio_num, sm, REG_CLKDIV, slot.clock_div << 8);

    // SHIFTCTRL: autopull+autopush, MSB-first, 32-bit thresholds
    let mut shiftctrl: u32 = 0;
    shiftctrl |= 1 << 17;  // AUTOPULL
    shiftctrl |= 1 << 16;  // AUTOPUSH
    // OUT_SHIFTDIR=0, IN_SHIFTDIR=0 (MSB first)
    // PULL_THRESH=0 (=32), PUSH_THRESH=0 (=32)
    pio_sm_write_reg(sys, pio_num, sm, REG_SHIFTCTRL, shiftctrl);

    // Force data+clk pins as output LOW
    // Set data pin direction
    let set_pc = (slot.data_pin as u32) | ((slot.data_pin as u32) << 5) | (1u32 << 26);
    pio_sm_write_reg(sys, pio_num, sm, REG_PINCTRL, set_pc);
    pio_sm_exec(sys, pio_num, sm, 0xE081); // SET PINDIRS, 1
    pio_sm_exec(sys, pio_num, sm, 0xE000); // SET PINS, 0

    // Set clk pin direction
    let clk_pc = (slot.clk_pin as u32) | ((slot.clk_pin as u32) << 5) | (1u32 << 26);
    pio_sm_write_reg(sys, pio_num, sm, REG_PINCTRL, clk_pc);
    pio_sm_exec(sys, pio_num, sm, 0xE081); // SET PINDIRS, 1
    pio_sm_exec(sys, pio_num, sm, 0xE000); // SET PINS, 0

    // Restore pinctrl
    pio_sm_write_reg(sys, pio_num, sm, REG_PINCTRL, pinctrl);

    // Jump to entry point (wrap_target for cmd)
    let entry = origin + slot.program.wrap_target;
    pio_sm_exec(sys, pio_num, sm, entry as u16); // JMP entry

    // SM stays disabled — enabled per-transfer
}

/// Configure SM for RX streaming (autopush, MSB-first, join RX FIFO)
unsafe fn configure_rx_sm(
    sys: &SyscallTable,
    slot: &RxSlot,
    origin: u8,
) {
    let pio_num = slot.pio_num;
    let sm = slot.sm_num;
    let sm_mask = 1u8 << sm;

    pio_sm_enable(sys, pio_num, sm_mask, false);
    pio_sm_restart(sys, pio_num, sm_mask);

    // EXECCTRL
    let wrap_bottom = origin + slot.program.wrap_target;
    let wrap_top = origin + slot.program.wrap;
    let mut execctrl: u32 = 0;
    execctrl |= (wrap_bottom as u32) << 7;
    execctrl |= (wrap_top as u32) << 12;
    if slot.program.sideset_optional != 0 { execctrl |= 1 << 30; }
    if slot.program.sideset_pindirs != 0 { execctrl |= 1 << 29; }
    pio_sm_write_reg(sys, pio_num, sm, REG_EXECCTRL, execctrl);

    // PINCTRL: in=in_pin, sideset=sideset_base
    let mut pinctrl: u32 = 0;
    pinctrl |= (slot.in_pin as u32) << 5;                    // [9:5] SET_BASE
    pinctrl |= (slot.sideset_base as u32) << 10;             // [14:10] SIDESET_BASE
    pinctrl |= (slot.in_pin as u32) << 15;                   // [19:15] IN_BASE
    pinctrl |= 1u32 << 26;                                   // [28:26] SET_COUNT=1
    pinctrl |= (slot.program.sideset_bits as u32) << 29;     // [31:29] SIDESET_COUNT
    pio_sm_write_reg(sys, pio_num, sm, REG_PINCTRL, pinctrl);

    // CLKDIV
    pio_sm_write_reg(sys, pio_num, sm, REG_CLKDIV, slot.clock_div << 8);

    // SHIFTCTRL: join RX, autopush, MSB-first, push_thresh
    let mut shiftctrl: u32 = 0;
    shiftctrl |= 1 << 31;  // FJOIN_RX
    shiftctrl |= 1 << 16;  // AUTOPUSH
    // IN_SHIFTDIR=0 (shift left = MSB first) — bit 18
    shiftctrl |= (slot.shift_bits as u32 & 0x1F) << 20; // PUSH_THRESH [24:20]
    pio_sm_write_reg(sys, pio_num, sm, REG_SHIFTCTRL, shiftctrl);

    // Setup sideset pins as outputs
    if slot.sideset_base != slot.in_pin && slot.program.sideset_bits > 0 {
        // Setup sideset pins for PIO
        let mut ss_pin = slot.sideset_base;
        let mut n = 0u8;
        while n < slot.program.sideset_bits {
            pio_pin_setup(sys, ss_pin, pio_num, 2); // PullUp
            // Set as output
            let ss_pc = (ss_pin as u32) | ((ss_pin as u32) << 5) | (1u32 << 26);
            pio_sm_write_reg(sys, pio_num, sm, REG_PINCTRL, ss_pc);
            pio_sm_exec(sys, pio_num, sm, 0xE081); // SET PINDIRS, 1
            ss_pin = ss_pin.wrapping_add(1);
            n += 1;
        }
    }

    // Setup input pin
    pio_pin_setup(sys, slot.in_pin, pio_num, 2); // PullUp

    // Restore pinctrl
    pio_sm_write_reg(sys, pio_num, sm, REG_PINCTRL, pinctrl);

    // Jump to entry
    let entry = origin + slot.program.wrap;
    pio_sm_exec(sys, pio_num, sm, entry as u16);

    // Enable
    pio_sm_enable(sys, pio_num, sm_mask, true);
}

// ============================================================================
// Parse PioLoadProgramArgs from raw arg buffer
// ============================================================================

/// Parse load_program args: ptr to [program_ptr:u32, program_len:u32,
///   wrap_target:u8, wrap:u8, sideset_bits:u8, options:u8]
/// This matches PioLoadProgramArgs layout.
unsafe fn parse_load_program_args(arg: *const u8, arg_len: usize) -> Option<(*const u16, u8, u8, u8, u8, u8)> {
    // PioLoadProgramArgs is: *const u16 (4B on ARM), u32, u8, u8, u8, u8
    if arg_len < 12 { return None; }
    let prog_ptr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]) as *const u16;
    let prog_len = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]) as u8;
    let wrap_target = *arg.add(8);
    let wrap = *arg.add(9);
    let sideset_bits = *arg.add(10);
    let options = *arg.add(11);
    if prog_ptr.is_null() || prog_len == 0 || prog_len > 32 { return None; }
    if wrap_target >= prog_len || wrap >= prog_len { return None; }
    if sideset_bits > 5 { return None; }
    Some((prog_ptr, prog_len, wrap_target, wrap, sideset_bits, options))
}

/// Copy program from caller's pointer into slot's PioProgram struct
unsafe fn copy_program(prog: &mut PioProgram, src: *const u16, len: u8, wrap_target: u8, wrap: u8, sideset_bits: u8, options: u8) {
    prog.length = len;
    prog.wrap_target = wrap_target;
    prog.wrap = wrap;
    prog.sideset_bits = sideset_bits;
    prog.sideset_optional = if options & 0x01 != 0 { 1 } else { 0 };
    prog.sideset_pindirs = if options & 0x02 != 0 { 1 } else { 0 };
    let mut i = 0usize;
    while i < len as usize {
        let dst = prog.instructions.as_mut_ptr().add(i);
        core::ptr::write_volatile(dst, core::ptr::read_volatile(src.add(i)));
        i += 1;
    }
}

// ============================================================================
// Provider dispatch
// ============================================================================

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pio_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    let s = &mut *(state as *mut PioState);
    let sys = &*s.syscalls;

    match opcode {
        // ==== TX Stream ====
        STREAM_ALLOC => {
            // Find free stream slot
            let mut i = 0usize;
            while i < MAX_STREAM_SLOTS {
                let sp = s.streams.as_mut_ptr().add(i);
                if (*sp).state == SLOT_FREE {
                    (*sp).state = SLOT_ALLOCATED;
                    (*sp).dma_fd = -1;
                    (*sp).push_pending = 0;
                    (*sp).dma_active = 0;
                    (*sp).program_loaded = 0;
                    (*sp).program_status = 0;
                    (*sp).instr_mask = 0;
                    (*sp).active_buf = 0;
                    (*sp).consumed_lo = 0;
                    (*sp).consumed_hi = 0;
                    (*sp).queued_units = 0;
                    (*sp).rate_q16 = 0;
                    (*sp).t0_lo = 0;
                    (*sp).t0_hi = 0;
                    return i as i32;
                }
                i += 1;
            }
            -12 // ENOMEM
        }
        STREAM_LOAD_PROGRAM => {
            let idx = handle as usize;
            if idx >= MAX_STREAM_SLOTS { return -22; }
            let sp = s.streams.as_mut_ptr().add(idx);
            if (*sp).state == SLOT_FREE || (*sp).state == SLOT_BUSY { return -16; }
            let args = match parse_load_program_args(arg, arg_len) {
                Some(a) => a,
                None => return -22,
            };
            copy_program(&mut (*sp).program, args.0, args.1, args.2, args.3, args.4, args.5);
            (*sp).program_status = 1; // pending
            0
        }
        STREAM_CONFIGURE => {
            // PioConfigureArgs: clock_div:u32, data_pin:u8, clock_base:u8, shift_bits:u8, pad:u8
            if arg.is_null() || arg_len < 8 { return -22; }
            let idx = handle as usize;
            if idx >= MAX_STREAM_SLOTS { return -22; }
            let sp = s.streams.as_mut_ptr().add(idx);
            if (*sp).state == SLOT_FREE { return -5; }
            (*sp).clock_div = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            (*sp).out_pin = *arg.add(4);
            (*sp).sideset_base = *arg.add(5);
            (*sp).shift_bits = *arg.add(6);
            (*sp).pio_num = 0; // default PIO0
            (*sp).sm_num = idx as u8; // SM = slot index
            (*sp).state = SLOT_READY;
            // Try to load program now if pending
            if (*sp).program_status == 1 && (*sp).program.length > 0 {
                let (origin, mask) = load_program(sys, (*sp).pio_num, &(*sp).program, (*sp).instr_mask);
                if origin >= 0 {
                    (*sp).instr_mask = mask;
                    (*sp).instr_origin = origin as u8;
                    // Setup pin for PIO
                    pio_pin_setup(sys, (*sp).out_pin, (*sp).pio_num, 2); // PullUp
                    if (*sp).sideset_base != (*sp).out_pin {
                        pio_pin_setup(sys, (*sp).sideset_base, (*sp).pio_num, 2);
                        // Also setup second sideset pin if sideset_bits > 1
                        if (*sp).program.sideset_bits > 1 {
                            pio_pin_setup(sys, (*sp).sideset_base.wrapping_add(1), (*sp).pio_num, 2);
                        }
                    }
                    configure_stream_sm(sys, &*sp, origin as u8);
                    (*sp).program_loaded = 1;
                    (*sp).program_status = 2; // loaded
                    // Create DMA FD
                    (*sp).dma_fd = dma_fd_create(sys);
                } else {
                    (*sp).program_status = 3; // error
                }
            }
            0
        }
        STREAM_CAN_PUSH => {
            let idx = handle as usize;
            if idx >= MAX_STREAM_SLOTS { return 0; }
            let sp = s.streams.as_ptr().add(idx);
            if (*sp).state == SLOT_FREE { return 0; }
            if (*sp).push_pending != 0 { 0 } else { 1 }
        }
        STREAM_PUSH => {
            if arg.is_null() || arg_len < 4 { return -22; }
            let count = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]) as u16;
            let idx = handle as usize;
            if idx >= MAX_STREAM_SLOTS { return -22; }
            let sp = s.streams.as_mut_ptr().add(idx);
            if (*sp).state != SLOT_READY && (*sp).state != SLOT_BUSY { return -5; }
            if (*sp).push_pending != 0 { return -16; }
            if count == 0 || count as usize > STREAM_BUF_WORDS { return -22; }
            // Capture t0 on first push
            if (*sp).t0_lo == 0 && (*sp).t0_hi == 0 {
                // Get current time via system timer query
                let mut time_buf = [0u8; 4];
                let _r = (sys.dev_call)(-1, 0x0C42, time_buf.as_mut_ptr(), 4); // TIME_US_LO
                (*sp).t0_lo = u32::from_le_bytes(time_buf);
            }
            (*sp).queued_units = (*sp).queued_units.wrapping_add(count as u32);
            (*sp).push_pending = 1;
            (*sp).push_count = count;
            0
        }
        STREAM_GET_BUFFER | DIRECT_BUFFER => {
            let idx = handle as usize;
            if idx >= MAX_STREAM_SLOTS { return 0; }
            let sp = s.streams.as_ptr().add(idx);
            if (*sp).state == SLOT_FREE { return 0; }
            if (*sp).push_pending != 0 { return 0; }
            // Return pointer to back buffer
            let buf_ptr = if (*sp).active_buf == 0 {
                // A is front (DMA source), B is back (writable)
                (*sp).buf_b.as_ptr()
            } else {
                (*sp).buf_a.as_ptr()
            };
            if opcode == DIRECT_BUFFER {
                // DIRECT_BUFFER: also write capacity to arg
                if !arg.is_null() && arg_len >= 4 {
                    let cap = (STREAM_BUF_WORDS as u32).to_le_bytes();
                    *arg = cap[0]; *arg.add(1) = cap[1]; *arg.add(2) = cap[2]; *arg.add(3) = cap[3];
                }
            }
            buf_ptr as i32
        }
        DIRECT_PUSH => {
            if arg.is_null() || arg_len < 4 { return -22; }
            let words = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]) as u16;
            let idx = handle as usize;
            if idx >= MAX_STREAM_SLOTS { return -22; }
            let sp = s.streams.as_mut_ptr().add(idx);
            if (*sp).state != SLOT_READY && (*sp).state != SLOT_BUSY { return -5; }
            if (*sp).push_pending != 0 { return -16; }
            if words == 0 || words as usize > STREAM_BUF_WORDS { return -22; }
            (*sp).queued_units = (*sp).queued_units.wrapping_add(words as u32);
            (*sp).push_pending = 1;
            (*sp).push_count = words;
            0
        }
        STREAM_FREE => {
            let idx = handle as usize;
            if idx >= MAX_STREAM_SLOTS { return 0; }
            let sp = s.streams.as_mut_ptr().add(idx);
            if (*sp).state == SLOT_FREE { return 0; }
            // Stop SM
            pio_sm_enable(sys, (*sp).pio_num, 1 << (*sp).sm_num, false);
            // Free DMA FD
            if (*sp).dma_fd >= 0 {
                dma_fd_free(sys, (*sp).dma_fd);
                (*sp).dma_fd = -1;
            }
            // Free instruction memory
            if (*sp).instr_mask != 0 {
                pio_instr_free(sys, (*sp).pio_num, (*sp).instr_mask);
                (*sp).instr_mask = 0;
            }
            (*sp).state = SLOT_FREE;
            0
        }
        STREAM_TIME => {
            // Write StreamTime to arg: consumed_units:u64, queued_units:u32, rate_q16:u32, t0_micros:u64
            if arg.is_null() || arg_len < 24 { return -22; }
            let idx = handle as usize;
            if idx >= MAX_STREAM_SLOTS { return -22; }
            let sp = s.streams.as_ptr().add(idx);
            if (*sp).state == SLOT_FREE { return -5; }
            // consumed_units (u64 LE)
            let lo = (*sp).consumed_lo.to_le_bytes();
            let hi = (*sp).consumed_hi.to_le_bytes();
            *arg = lo[0]; *arg.add(1) = lo[1]; *arg.add(2) = lo[2]; *arg.add(3) = lo[3];
            *arg.add(4) = hi[0]; *arg.add(5) = hi[1]; *arg.add(6) = hi[2]; *arg.add(7) = hi[3];
            // queued_units (u32 LE)
            let qb = (*sp).queued_units.to_le_bytes();
            *arg.add(8) = qb[0]; *arg.add(9) = qb[1]; *arg.add(10) = qb[2]; *arg.add(11) = qb[3];
            // rate_q16 (u32 LE)
            let rb = (*sp).rate_q16.to_le_bytes();
            *arg.add(12) = rb[0]; *arg.add(13) = rb[1]; *arg.add(14) = rb[2]; *arg.add(15) = rb[3];
            // t0_micros (u64 LE)
            let t0l = (*sp).t0_lo.to_le_bytes();
            let t0h = (*sp).t0_hi.to_le_bytes();
            *arg.add(16) = t0l[0]; *arg.add(17) = t0l[1]; *arg.add(18) = t0l[2]; *arg.add(19) = t0l[3];
            *arg.add(20) = t0h[0]; *arg.add(21) = t0h[1]; *arg.add(22) = t0h[2]; *arg.add(23) = t0h[3];
            0
        }
        PROGRAM_STATUS => {
            // Return program status for stream or cmd based on handle range
            // Stream handles are 0..MAX_STREAM_SLOTS, cmd handles offset by that
            let idx = handle as usize;
            if idx < MAX_STREAM_SLOTS {
                let sp = s.streams.as_ptr().add(idx);
                return (*sp).program_status as i32;
            }
            // Check cmd slots (handle >= 0x100 convention)
            -22
        }
        STREAM_SET_RATE => {
            if arg.is_null() || arg_len < 4 { return -22; }
            let rate = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let idx = handle as usize;
            if idx >= MAX_STREAM_SLOTS { return -22; }
            let sp = s.streams.as_mut_ptr().add(idx);
            (*sp).rate_q16 = rate;
            0
        }

        // ==== CMD ====
        CMD_ALLOC => {
            if arg.is_null() || arg_len < 2 { return -22; }
            let pio_idx = *arg;
            let sm_idx = *arg.add(1);
            if pio_idx > 2 || sm_idx > 3 { return -22; }
            let mut i = 0usize;
            while i < MAX_CMD_SLOTS {
                let cp = s.cmds.as_mut_ptr().add(i);
                if (*cp).state == SLOT_FREE {
                    (*cp).state = SLOT_ALLOCATED;
                    (*cp).pio_num = pio_idx;
                    (*cp).sm_num = sm_idx;
                    (*cp).program_loaded = 0;
                    (*cp).program_status = 0;
                    (*cp).instr_mask = 0;
                    (*cp).dma_ch = 0xFF;
                    return i as i32;
                }
                i += 1;
            }
            -12 // ENOMEM
        }
        CMD_LOAD_PROGRAM => {
            let idx = handle as usize;
            if idx >= MAX_CMD_SLOTS { return -22; }
            let cp = s.cmds.as_mut_ptr().add(idx);
            if (*cp).state == SLOT_FREE || (*cp).state == SLOT_BUSY { return -16; }
            let args = match parse_load_program_args(arg, arg_len) {
                Some(a) => a,
                None => return -22,
            };
            copy_program(&mut (*cp).program, args.0, args.1, args.2, args.3, args.4, args.5);
            (*cp).program_status = 1;
            0
        }
        CMD_CONFIGURE => {
            // PioCmdConfigureArgs: data_pin:u8, clk_pin:u8, pad:[u8;2], clock_div:u32
            if arg.is_null() || arg_len < 8 { return -22; }
            let idx = handle as usize;
            if idx >= MAX_CMD_SLOTS { return -22; }
            let cp = s.cmds.as_mut_ptr().add(idx);
            if (*cp).state == SLOT_FREE { return -5; }
            (*cp).data_pin = *arg;
            (*cp).clk_pin = *arg.add(1);
            (*cp).clock_div = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]);
            (*cp).state = SLOT_READY;
            // Try program load
            if (*cp).program_status == 1 && (*cp).program.length > 0 {
                let (origin, mask) = load_program(sys, (*cp).pio_num, &(*cp).program, (*cp).instr_mask);
                if origin >= 0 {
                    (*cp).instr_mask = mask;
                    (*cp).instr_origin = origin as u8;
                    // Setup pins
                    pio_pin_setup(sys, (*cp).data_pin, (*cp).pio_num, 1); // PullDown for DIO
                    pio_pin_setup(sys, (*cp).clk_pin, (*cp).pio_num, 0); // None for CLK
                    configure_cmd_sm(sys, &*cp, origin as u8);
                    // Allocate raw DMA channel
                    let ch = raw_dma_alloc(sys);
                    if ch >= 0 {
                        (*cp).dma_ch = ch as u8;
                    }
                    (*cp).program_loaded = 1;
                    (*cp).program_status = 2;
                } else {
                    (*cp).program_status = 3;
                }
            }
            0
        }
        CMD_TRANSFER => {
            // PioCmdTransferArgs: tx_ptr:u32, tx_len:u32, rx_ptr:u32, rx_len:u32
            if arg.is_null() || arg_len < 16 { return -22; }
            let idx = handle as usize;
            if idx >= MAX_CMD_SLOTS { return -22; }
            let cp = s.cmds.as_mut_ptr().add(idx);
            if (*cp).state != SLOT_READY { return -16; }
            if (*cp).program_loaded == 0 { return -5; }

            let tx_ptr = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let tx_len = u32::from_le_bytes([*arg.add(4), *arg.add(5), *arg.add(6), *arg.add(7)]) as usize;
            let rx_ptr = u32::from_le_bytes([*arg.add(8), *arg.add(9), *arg.add(10), *arg.add(11)]);
            let rx_len = u32::from_le_bytes([*arg.add(12), *arg.add(13), *arg.add(14), *arg.add(15)]) as usize;

            if tx_ptr == 0 || tx_len < 8 { return -22; }

            // Read tx_words from first 4 bytes of tx buffer
            let tx_src = tx_ptr as *const u8;
            let tx_words = u32::from_le_bytes([
                core::ptr::read_volatile(tx_src),
                core::ptr::read_volatile(tx_src.add(1)),
                core::ptr::read_volatile(tx_src.add(2)),
                core::ptr::read_volatile(tx_src.add(3)),
            ]) as usize;

            // Read rx_words from offset 4 + tx_words*4
            let rw_off = 4 + tx_words * 4;
            let rx_words = if rw_off + 4 <= tx_len {
                u32::from_le_bytes([
                    core::ptr::read_volatile(tx_src.add(rw_off)),
                    core::ptr::read_volatile(tx_src.add(rw_off + 1)),
                    core::ptr::read_volatile(tx_src.add(rw_off + 2)),
                    core::ptr::read_volatile(tx_src.add(rw_off + 3)),
                ]) as usize
            } else {
                0
            };

            if tx_words > CMD_SCRATCH_WORDS { return -22; }

            // Copy TX data to aligned scratch
            let scratch = (*cp).scratch.as_mut_ptr();
            if tx_words > 0 {
                // Zero last word (partial fill)
                core::ptr::write_volatile(scratch.add(tx_words - 1), 0);
                let tx_data_bytes = tx_words << 2; // tx_words * 4
                let src = tx_src.add(4);
                let dst = scratch as *mut u8;
                let mut b = 0usize;
                while b < tx_data_bytes {
                    core::ptr::write_volatile(dst.add(b), core::ptr::read_volatile(src.add(b)));
                    b += 1;
                }
            }

            let write_bits = if tx_words > 0 { (tx_words << 5) - 1 } else { 0 }; // tx_words * 32 - 1
            let read_words = if rx_words > 0 { rx_words } else { 1 };
            let read_bits = (read_words << 5) - 1;

            let origin = (*cp).instr_origin;
            let pio_n = (*cp).pio_num;
            let sm_n = (*cp).sm_num;
            let dma_ch = (*cp).dma_ch;
            if dma_ch == 0xFF { return -5; }

            // Per-transaction SM setup
            pio_sm_enable(sys, pio_n, 1 << sm_n, false);

            // Set X = write_bits (push to TXF, force OUT X, 32)
            pio_txf_write(sys, pio_n, sm_n, write_bits as u32);
            pio_sm_exec(sys, pio_n, sm_n, 0x6020); // OUT X, 32

            // Set Y = read_bits
            pio_txf_write(sys, pio_n, sm_n, read_bits as u32);
            pio_sm_exec(sys, pio_n, sm_n, 0x6040); // OUT Y, 32

            // SET PINDIRS, 1 (output)
            pio_sm_exec(sys, pio_n, sm_n, 0xE081);

            // JMP origin
            pio_sm_exec(sys, pio_n, sm_n, origin as u16);

            pio_sm_enable(sys, pio_n, 1 << sm_n, true);

            // TX DMA: scratch → PIO TXF (blocking via raw DMA)
            let tx_dreq = (pio_n << 3) + sm_n; // pio_num * 8 + sm_num
            if tx_words > 0 {
                raw_dma_start(sys, dma_ch, scratch as u32,
                    pio_txf_addr(pio_n, sm_n), tx_words as u32,
                    tx_dreq, DMA_FLAG_INCR_READ | DMA_FLAG_SIZE_32);
                while raw_dma_busy(sys, dma_ch) {}
            }

            // RX DMA: PIO RXF → scratch (blocking)
            let rx_dreq = (pio_n << 3) + sm_n + 4;
            raw_dma_start(sys, dma_ch, pio_rxf_addr(pio_n, sm_n),
                scratch as u32, read_words as u32,
                rx_dreq, DMA_FLAG_INCR_WRITE | DMA_FLAG_SIZE_32);
            while raw_dma_busy(sys, dma_ch) {}

            // Copy RX to caller
            let mut total_bytes = tx_len as i32;
            if rx_words > 0 && rx_ptr != 0 && rx_len > 0 {
                let copy_len = if (rx_words << 2) < rx_len { rx_words << 2 } else { rx_len };
                let src = scratch as *const u8;
                let dst = rx_ptr as *mut u8;
                let mut b = 0usize;
                while b < copy_len {
                    core::ptr::write_volatile(dst.add(b), core::ptr::read_volatile(src.add(b)));
                    b += 1;
                }
                total_bytes += rx_len as i32;
            }

            total_bytes
        }
        CMD_POLL => {
            let idx = handle as usize;
            if idx >= MAX_CMD_SLOTS { return -22; }
            let cp = s.cmds.as_ptr().add(idx);
            if (*cp).state == SLOT_READY { 0 } else { -5 }
        }
        CMD_FREE => {
            let idx = handle as usize;
            if idx >= MAX_CMD_SLOTS { return 0; }
            let cp = s.cmds.as_mut_ptr().add(idx);
            if (*cp).state == SLOT_FREE { return 0; }
            pio_sm_enable(sys, (*cp).pio_num, 1 << (*cp).sm_num, false);
            if (*cp).dma_ch != 0xFF {
                raw_dma_free(sys, (*cp).dma_ch);
                (*cp).dma_ch = 0xFF;
            }
            if (*cp).instr_mask != 0 {
                pio_instr_free(sys, (*cp).pio_num, (*cp).instr_mask);
                (*cp).instr_mask = 0;
            }
            (*cp).state = SLOT_FREE;
            0
        }

        // ==== RX Stream ====
        RX_STREAM_ALLOC => {
            let mut i = 0usize;
            while i < MAX_RX_SLOTS {
                let rp = s.rxs.as_mut_ptr().add(i);
                if (*rp).state == SLOT_FREE {
                    (*rp).state = SLOT_ALLOCATED;
                    (*rp).dma_fd = -1;
                    (*rp).dma_active = 0;
                    (*rp).pull_ready = 0;
                    (*rp).program_loaded = 0;
                    (*rp).program_status = 0;
                    (*rp).instr_mask = 0;
                    (*rp).active_buf = 0;
                    (*rp).overflow_count = 0;
                    (*rp).rate_q16 = 0;
                    return i as i32;
                }
                i += 1;
            }
            -12
        }
        RX_STREAM_LOAD_PROGRAM => {
            let idx = handle as usize;
            if idx >= MAX_RX_SLOTS { return -22; }
            let rp = s.rxs.as_mut_ptr().add(idx);
            if (*rp).state == SLOT_FREE || (*rp).state == SLOT_BUSY { return -16; }
            let args = match parse_load_program_args(arg, arg_len) {
                Some(a) => a,
                None => return -22,
            };
            copy_program(&mut (*rp).program, args.0, args.1, args.2, args.3, args.4, args.5);
            (*rp).program_status = 1;
            0
        }
        RX_STREAM_CONFIGURE => {
            // PioRxConfigureArgs: clock_div:u32, in_pin:u8, sideset_base:u8, shift_bits:u8, pad:u8
            if arg.is_null() || arg_len < 8 { return -22; }
            let idx = handle as usize;
            if idx >= MAX_RX_SLOTS { return -22; }
            let rp = s.rxs.as_mut_ptr().add(idx);
            if (*rp).state == SLOT_FREE { return -5; }
            (*rp).clock_div = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            (*rp).in_pin = *arg.add(4);
            (*rp).sideset_base = *arg.add(5);
            (*rp).shift_bits = *arg.add(6);
            (*rp).pio_num = 1; // RX typically on PIO1
            (*rp).sm_num = 0;
            (*rp).state = SLOT_READY;
            // Try program load
            if (*rp).program_status == 1 && (*rp).program.length > 0 {
                let (origin, mask) = load_program(sys, (*rp).pio_num, &(*rp).program, (*rp).instr_mask);
                if origin >= 0 {
                    (*rp).instr_mask = mask;
                    (*rp).instr_origin = origin as u8;
                    configure_rx_sm(sys, &*rp, origin as u8);
                    (*rp).dma_fd = dma_fd_create(sys);
                    (*rp).program_loaded = 1;
                    (*rp).program_status = 2;
                } else {
                    (*rp).program_status = 3;
                }
            }
            0
        }
        RX_STREAM_CAN_PULL => {
            let idx = handle as usize;
            if idx >= MAX_RX_SLOTS { return 0; }
            let rp = s.rxs.as_ptr().add(idx);
            if (*rp).state == SLOT_FREE { return 0; }
            if (*rp).pull_ready != 0 { 1 } else { 0 }
        }
        RX_STREAM_PULL => {
            let idx = handle as usize;
            if idx >= MAX_RX_SLOTS { return -22; }
            let rp = s.rxs.as_mut_ptr().add(idx);
            if (*rp).pull_ready != 0 {
                (*rp).pull_ready = 0;
                (*rp).pull_count as i32
            } else {
                0
            }
        }
        RX_STREAM_GET_BUFFER => {
            if arg.is_null() || arg_len < 4 { return -22; }
            let idx = handle as usize;
            if idx >= MAX_RX_SLOTS { return 0; }
            let rp = s.rxs.as_ptr().add(idx);
            if (*rp).state == SLOT_FREE || (*rp).pull_ready == 0 { return 0; }
            // Return pointer to readable buffer (not the one DMA is filling)
            let buf_ptr = if (*rp).active_buf == 0 {
                // DMA fills A, module reads B
                (*rp).buf_b.as_ptr()
            } else {
                (*rp).buf_a.as_ptr()
            };
            // Write pointer to arg
            let pb = (buf_ptr as u32).to_le_bytes();
            *arg = pb[0]; *arg.add(1) = pb[1]; *arg.add(2) = pb[2]; *arg.add(3) = pb[3];
            RX_BUF_WORDS as i32
        }
        RX_STREAM_FREE => {
            let idx = handle as usize;
            if idx >= MAX_RX_SLOTS { return 0; }
            let rp = s.rxs.as_mut_ptr().add(idx);
            if (*rp).state == SLOT_FREE { return 0; }
            pio_sm_enable(sys, (*rp).pio_num, 1 << (*rp).sm_num, false);
            if (*rp).dma_fd >= 0 {
                dma_fd_free(sys, (*rp).dma_fd);
                (*rp).dma_fd = -1;
            }
            if (*rp).instr_mask != 0 {
                pio_instr_free(sys, (*rp).pio_num, (*rp).instr_mask);
                (*rp).instr_mask = 0;
            }
            (*rp).state = SLOT_FREE;
            0
        }
        RX_STREAM_SET_RATE => {
            if arg.is_null() || arg_len < 4 { return -22; }
            let rate = u32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let idx = handle as usize;
            if idx >= MAX_RX_SLOTS { return -22; }
            let rp = s.rxs.as_mut_ptr().add(idx);
            (*rp).rate_q16 = rate;
            0
        }

        _ => -38, // ENOSYS
    }
}

// ============================================================================
// PIO register address helpers (for DMA targets)
// ============================================================================

/// TX FIFO address for a PIO SM. PIO0 base=0x50200000, PIO1=0x50300000, PIO2=0x50400000
/// TXF0 offset = 0x010, each SM +4
#[inline(always)]
fn pio_txf_addr(pio_num: u8, sm: u8) -> u32 {
    let base: u32 = 0x5020_0000 + (pio_num as u32) * 0x0010_0000;
    base + 0x010 + (sm as u32) * 4
}

/// RX FIFO address for a PIO SM. RXF0 offset = 0x020, each SM +4
#[inline(always)]
fn pio_rxf_addr(pio_num: u8, sm: u8) -> u32 {
    let base: u32 = 0x5020_0000 + (pio_num as u32) * 0x0010_0000;
    base + 0x020 + (sm as u32) * 4
}

// ============================================================================
// Module ABI
// ============================================================================

#[unsafe(no_mangle)]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() -> u32 { 1 }

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<PioState>()
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32, out_chan: i32, ctrl_chan: i32,
    _params: *const u8, _params_len: usize,
    state: *mut u8, state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() { return -1; }
        if state_size < core::mem::size_of::<PioState>() { return -2; }

        let s = &mut *(state as *mut PioState);
        s.syscalls = syscalls as *const SyscallTable;
        s.in_chan = in_chan;
        s.out_chan = out_chan;
        s.ctrl_chan = ctrl_chan;
        s.step_count = 0;

        // Register as PIO provider (device class 0x04)
        let sys = &*s.syscalls;
        let dispatch_addr = pio_dispatch as *const () as u32;
        let mut reg_args = [0u8; 8];
        let rp = reg_args.as_mut_ptr();
        *rp = 0x04; // device_class = PIO
        *rp.add(1) = 0; *rp.add(2) = 0; *rp.add(3) = 0;
        let da = dispatch_addr.to_le_bytes();
        *rp.add(4) = da[0]; *rp.add(5) = da[1]; *rp.add(6) = da[2]; *rp.add(7) = da[3];
        (sys.dev_call)(-1, 0x0C20, rp, 8); // REGISTER_PROVIDER

        dev_log(sys, 3, b"[pio] provider registered".as_ptr(), 24);
        0
    }
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut PioState);
    let sys = &*s.syscalls;
    s.step_count = s.step_count.wrapping_add(1);
    let mut has_work = false;

    // ── TX Stream polling ──
    {
        let mut i = 0usize;
        while i < MAX_STREAM_SLOTS {
            let sp = s.streams.as_mut_ptr().add(i);

            if (*sp).state == SLOT_FREE {
                i += 1;
                continue;
            }

            // Check if DMA completed
            if (*sp).dma_active != 0 && (*sp).dma_fd >= 0 {
                if dma_fd_poll(sys, (*sp).dma_fd) {
                    // DMA done — track consumed units
                    let count = (*sp).push_count as u32;
                    let lo = (*sp).consumed_lo;
                    let hi = (*sp).consumed_hi;
                    let total = ((hi as u64) << 32) | (lo as u64);
                    let updated = total.wrapping_add(count as u64);
                    (*sp).consumed_lo = updated as u32;
                    (*sp).consumed_hi = (updated >> 32) as u32;
                    (*sp).queued_units = (*sp).queued_units.wrapping_sub(count);
                    (*sp).dma_active = 0;
                    (*sp).state = SLOT_READY;
                } else {
                    has_work = true;
                }
            }

            // Process pending push
            if (*sp).push_pending != 0 && (*sp).dma_active == 0 && (*sp).program_loaded != 0 {
                // Swap buffers: back becomes front (DMA source)
                (*sp).active_buf ^= 1;
                (*sp).push_pending = 0;

                let count = (*sp).push_count as u32;
                let buf_ptr = if (*sp).active_buf == 0 {
                    (*sp).buf_a.as_ptr()
                } else {
                    (*sp).buf_b.as_ptr()
                };

                let txf_addr = pio_txf_addr((*sp).pio_num, (*sp).sm_num);
                let tx_dreq = ((*sp).pio_num << 3) + (*sp).sm_num;

                // If DMA FD not created yet, create now
                if (*sp).dma_fd < 0 {
                    (*sp).dma_fd = dma_fd_create(sys);
                }
                if (*sp).dma_fd >= 0 {
                    let rc = dma_fd_start(
                        sys, (*sp).dma_fd,
                        buf_ptr as u32, txf_addr, count,
                        tx_dreq, DMA_FLAG_INCR_READ | DMA_FLAG_SIZE_32,
                    );
                    if rc >= 0 {
                        (*sp).dma_active = 1;
                        (*sp).state = SLOT_BUSY;
                        has_work = true;
                    }
                }
            }

            // Try program load if pending and now configured
            if (*sp).program_status == 1 && (*sp).state >= SLOT_READY && (*sp).program.length > 0 {
                let (origin, mask) = load_program(sys, (*sp).pio_num, &(*sp).program, (*sp).instr_mask);
                if origin >= 0 {
                    (*sp).instr_mask = mask;
                    (*sp).instr_origin = origin as u8;
                    pio_pin_setup(sys, (*sp).out_pin, (*sp).pio_num, 2);
                    if (*sp).sideset_base != (*sp).out_pin {
                        pio_pin_setup(sys, (*sp).sideset_base, (*sp).pio_num, 2);
                    }
                    configure_stream_sm(sys, &*sp, origin as u8);
                    (*sp).program_loaded = 1;
                    (*sp).program_status = 2;
                    if (*sp).dma_fd < 0 {
                        (*sp).dma_fd = dma_fd_create(sys);
                    }
                } else {
                    (*sp).program_status = 3;
                }
            }

            i += 1;
        }
    }

    // ── RX Stream polling ──
    {
        let mut i = 0usize;
        while i < MAX_RX_SLOTS {
            let rp = s.rxs.as_mut_ptr().add(i);

            if (*rp).state == SLOT_FREE || (*rp).program_loaded == 0 {
                i += 1;
                continue;
            }

            // Check DMA completion
            if (*rp).dma_active != 0 && (*rp).dma_fd >= 0 {
                if dma_fd_poll(sys, (*rp).dma_fd) {
                    // DMA buffer full
                    if (*rp).pull_ready != 0 {
                        // Overflow — module hasn't read previous buffer
                        (*rp).overflow_count = (*rp).overflow_count.wrapping_add(1);
                    }
                    // Swap: module can now read the completed buffer
                    (*rp).active_buf ^= 1;
                    (*rp).pull_ready = 1;
                    (*rp).pull_count = RX_BUF_WORDS as u16;
                    (*rp).dma_active = 0;
                }
            }

            // Start next DMA capture if idle
            if (*rp).dma_active == 0 && (*rp).dma_fd >= 0 {
                let fill_buf = if (*rp).active_buf == 0 {
                    (*rp).buf_a.as_mut_ptr()
                } else {
                    (*rp).buf_b.as_mut_ptr()
                };
                let rxf_addr = pio_rxf_addr((*rp).pio_num, (*rp).sm_num);
                let rx_dreq = ((*rp).pio_num << 3) + (*rp).sm_num + 4;
                let rc = dma_fd_start(
                    sys, (*rp).dma_fd,
                    rxf_addr, fill_buf as u32, RX_BUF_WORDS as u32,
                    rx_dreq, DMA_FLAG_INCR_WRITE | DMA_FLAG_SIZE_32,
                );
                if rc >= 0 {
                    (*rp).dma_active = 1;
                    (*rp).state = SLOT_BUSY;
                    has_work = true;
                }
            }

            // Try program load if pending
            if (*rp).program_status == 1 && (*rp).state >= SLOT_READY && (*rp).program.length > 0 {
                let (origin, mask) = load_program(sys, (*rp).pio_num, &(*rp).program, (*rp).instr_mask);
                if origin >= 0 {
                    (*rp).instr_mask = mask;
                    (*rp).instr_origin = origin as u8;
                    configure_rx_sm(sys, &*rp, origin as u8);
                    if (*rp).dma_fd < 0 {
                        (*rp).dma_fd = dma_fd_create(sys);
                    }
                    (*rp).program_loaded = 1;
                    (*rp).program_status = 2;
                } else {
                    (*rp).program_status = 3;
                }
            }

            i += 1;
        }
    }

    // CMD slots don't need polling (transfers are synchronous)

    if has_work { 2 } else { 0 } // 2=Burst, 0=Continue
}
