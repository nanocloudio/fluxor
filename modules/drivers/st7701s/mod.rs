//! ST7701S Display Driver PIC Module
//!
//! Board-agnostic driver for ST7701S-based RGB parallel displays.
//! All pin assignments and PIO block selection are configurable via parameters.
//!
//! # Initialization
//!
//! 1. Reset sequence: RST low 20ms → RST high 200ms
//! 2. Register init via 9-bit GPIO bit-bang SPI (27 commands)
//! 3. SLEEP_OUT + 120ms → DISPLAY_ON + 120ms
//! 4. Allocate DMA channel, configure 4 PIO SMs, start scan-out
//! 5. Enable backlight
//!
//! # Architecture
//!
//! Uses 4 autonomous PIO state machines across 2 PIO blocks:
//!   - Sync PIO (param `pio_sync`, default 1): hsync SM0 + vsync SM1
//!   - Data PIO (param `pio_data`, default 2): rgb_de SM0 + rgb SM1
//! All frame timing is handled by PIO hardware with IRQ coordination.
//! CPU only feeds pixel data via DMA to the rgb SM's TX FIFO.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

mod init_seq;
mod pio_programs;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

// ============================================================================
// Constants
// ============================================================================

/// Stripe height in display lines — must be large enough that one stripe transfer
/// outlasts the scheduler tick: at 16MHz PCLK, 60 lines ≈ 1.8ms >> 1ms tick.
const STRIPE_LINES: u16 = 60;
/// Maximum stripe buffer size (worst case: 480px wide, 60 lines, 2 bytes/pixel).
const STRIPE_BUF_SIZE: usize = 480 * 60 * 2; // 57600 bytes
/// Aligned to 4 bytes for DMA.
const STRIPE_BUF_WORDS: usize = STRIPE_BUF_SIZE / 4;

/// Maximum source rows the driver can cache (limits state size).
const MAX_CACHED_ROWS: usize = 32;

/// Maximum words per decoded line (worst case: 480px wide → 240 u32s).
const MAX_LINE_WORDS: usize = 240;
/// MAX_CACHED_ROWS × MAX_LINE_WORDS words = 7680 words = 30720 bytes (per cache).
const LINE_CACHE_WORDS: usize = MAX_CACHED_ROWS * MAX_LINE_WORDS;

/// PIO base addresses (RP2350)
const PIO0_BASE: u32 = 0x5020_0000;
const PIO1_BASE: u32 = 0x5030_0000;
const PIO2_BASE: u32 = 0x5040_0000;

/// TXF register offset from PIO base: 0x010 + sm*4
const TXF_OFFSET: u32 = 0x010;

// ============================================================================
// dev_system opcodes (raw PIO + DMA bridge)
// ============================================================================

const PIO_SM_EXEC: u32 = 0x0C70;
const PIO_SM_WRITE_REG: u32 = 0x0C71;
const PIO_SM_READ_REG: u32 = 0x0C72;
const PIO_SM_ENABLE: u32 = 0x0C73;
const PIO_INSTR_ALLOC: u32 = 0x0C74;
const PIO_INSTR_WRITE: u32 = 0x0C75;
const PIO_INSTR_FREE: u32 = 0x0C76;
const PIO_PIN_SETUP: u32 = 0x0C77;
const PIO_GPIOBASE: u32 = 0x0C78;
const PIO_TXF_WRITE: u32 = 0x0C79;
const PIO_FSTAT_READ: u32 = 0x0C7A;
const PIO_SM_RESTART: u32 = 0x0C7B;

const DMA_FD_CREATE: u32 = 0x0C85;
const DMA_FD_START: u32 = 0x0C86;
const DMA_FD_QUEUE: u32 = 0x0C89;

// 9-bit SPI bit-bang (kernel raw PAC GPIO)
const SPI9_SEND: u32 = 0x0C90;
const SPI9_RESET: u32 = 0x0C91;
const SPI9_CS_SET: u32 = 0x0C92;

// PIO SM register indices
const REG_CLKDIV: u8 = 0;
const REG_EXECCTRL: u8 = 1;
const REG_SHIFTCTRL: u8 = 2;
const REG_PINCTRL: u8 = 3;

// ============================================================================
// State machine phases
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq)]
enum Phase {
    ResetPreHigh = 0,
    ResetLow = 1,
    ResetHigh = 2,
    InitSeq = 3,
    SleepOut = 4,
    DisplayOn = 5,
    AllocDmaFd = 6,
    ConfigurePioSync = 7,
    ConfigurePioData = 8,
    StartSMs = 9,
    Running = 10,
    DmaWait = 11,
    FillStripe = 12,
    Loading = 13,
    Error = 255,
}

// ============================================================================
// Module state
// ============================================================================

#[repr(C)]
struct St7701sState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    timer_fd: i32,

    // GPIO handles
    cs_handle: i32,
    sck_handle: i32,
    sda_handle: i32,
    rst_handle: i32,
    bl_handle: i32,

    // State machine
    phase: Phase,
    init_cmd_idx: u8,

    // Config (from params)
    cs_pin: u8,
    sck_pin: u8,
    sda_pin: u8,
    rst_pin: u8,
    bl_pin: u8,
    de_pin: u8,
    hsync_pin: u8,
    vsync_pin: u8,
    pclk_pin: u8,
    data0_pin: u8,
    pio_sync: u8,  // PIO block for sync SMs (default 1)
    pio_data: u8,  // PIO block for data SMs (default 2)
    mirror_x: u8,  // 1=flip source scan direction (SDIR), panel-dependent
    _pad_cfg: u8,
    width: u16,
    height: u16,

    // DMA FD
    dma_fd: i32,

    // PIO instruction memory masks (for cleanup)
    sync_hsync_mask: u32,
    sync_vsync_mask: u32,
    data_de_mask: u32,
    data_rgb_mask: u32,

    // Program origins (needed for wrap config)
    hsync_origin: u8,
    vsync_origin: u8,
    de_origin: u8,
    rgb_origin: u8,

    // Source image info (from params)
    src_rows: u16,       // source image rows (≤MAX_CACHED_ROWS), default 32

    // Runtime geometry — computed from width/height in module_new.
    line_words: u16,     // = width >> 1  (u32 words per decoded line)
    line_bytes: u16,     // = line_words << 2 (bytes per decoded line = width*2)
    _pad_geo: u16,
    stripe_pixels: u32,  // = width * STRIPE_LINES (u16 DMA transfers per stripe; DMA is 16-bit)
    stripe_count: u8,    // stripes per frame (height / STRIPE_LINES)

    // Stripe DMA state
    current_stripe: u8,  // 0..stripe_count-1, counts DOWN
    back_is_b: u8,       // 0: back=stripe_a, 1: back=stripe_b
    frame_loaded: u8,    // 0: first frame still loading, 1: backlight on

    // Cache display state
    // row_lookup[d] → cache slot index for display line d.
    // fill_stripe_from_row_cache regenerates any stripe from the active line cache.
    has_line_cache: u8,  // 0=no cache (test pattern mode), 1=front cache valid
    active_cache_b: u8,  // 0=display from line_cache, 1=display from line_cache_back

    // Background loading state (subsequent frames load while DMA runs)
    is_loading: u8,      // 1=currently loading into line_cache_back
    back_ready: u8,      // 1=line_cache_back has a complete frame; swap at next frame boundary
    load_row: u16,       // current row being loaded (0..src_rows)
    load_row_off: u16,   // bytes received for current row (0..line_bytes)
    load_cache_off: u32, // byte offset into line_cache_back (= load_row*line_bytes + load_row_off)

    row_lookup: [u8; 480], // display line → line_cache slot index

    // Two line caches: front (active display) and back (being loaded).
    // Swapped atomically at frame boundary when back_ready=1.
    line_cache: [u32; LINE_CACHE_WORDS],
    line_cache_back: [u32; LINE_CACHE_WORDS],

    // Stripe buffers (word-aligned, at end of struct)
    stripe_a: [u32; STRIPE_BUF_WORDS],
    stripe_b: [u32; STRIPE_BUF_WORDS],
}

impl St7701sState {
    #[inline(always)]
    fn sys(&self) -> &SyscallTable {
        unsafe { &*self.syscalls }
    }

    /// Get the PIO base address for a given PIO block number.
    fn pio_base(pio_num: u8) -> u32 {
        match pio_num {
            0 => PIO0_BASE,
            1 => PIO1_BASE,
            _ => PIO2_BASE,
        }
    }

    /// Get TXF address for a given PIO block and SM.
    fn txf_addr(pio_num: u8, sm: u8) -> u32 {
        Self::pio_base(pio_num) + TXF_OFFSET + (sm as u32) * 4
    }

    /// Get pointer to the back buffer (the one being filled by CPU).
    fn back_buf_ptr(&self) -> *mut u32 {
        if self.back_is_b != 0 {
            self.stripe_b.as_ptr() as *mut u32
        } else {
            self.stripe_a.as_ptr() as *mut u32
        }
    }
}

// ============================================================================
// Parameters
// ============================================================================

mod params_def {
    use super::St7701sState;
    use super::{p_u8, p_u16};
    use super::SCHEMA_MAX;

    define_params! {
        St7701sState;

        1, cs_pin, u8, 18
            => |s, d, len| { s.cs_pin = p_u8(d, len, 0, 18); };
        2, sck_pin, u8, 2
            => |s, d, len| { s.sck_pin = p_u8(d, len, 0, 2); };
        3, sda_pin, u8, 3
            => |s, d, len| { s.sda_pin = p_u8(d, len, 0, 3); };
        4, rst_pin, u8, 19
            => |s, d, len| { s.rst_pin = p_u8(d, len, 0, 19); };
        5, bl_pin, u8, 40
            => |s, d, len| { s.bl_pin = p_u8(d, len, 0, 40); };
        6, de_pin, u8, 20
            => |s, d, len| { s.de_pin = p_u8(d, len, 0, 20); };
        7, hsync_pin, u8, 22
            => |s, d, len| { s.hsync_pin = p_u8(d, len, 0, 22); };
        8, vsync_pin, u8, 21
            => |s, d, len| { s.vsync_pin = p_u8(d, len, 0, 21); };
        9, pclk_pin, u8, 23
            => |s, d, len| { s.pclk_pin = p_u8(d, len, 0, 23); };
        10, data0_pin, u8, 24
            => |s, d, len| { s.data0_pin = p_u8(d, len, 0, 24); };
        11, width, u16, 480
            => |s, d, len| { s.width = p_u16(d, len, 0, 480); };
        12, height, u16, 480
            => |s, d, len| { s.height = p_u16(d, len, 0, 480); };
        13, pio_sync, u8, 1
            => |s, d, len| { s.pio_sync = p_u8(d, len, 0, 1); };
        14, pio_data, u8, 2
            => |s, d, len| { s.pio_data = p_u8(d, len, 0, 2); };
        15, mirror_x, u8, 1
            => |s, d, len| { s.mirror_x = p_u8(d, len, 0, 1); };
        16, source_rows, u16, 32
            => |s, d, len| {
                let v = p_u16(d, len, 0, 32);
                s.src_rows = if v < 1 { 1 } else if v > 32 { 32 } else { v };
            };
    }
}

// ============================================================================
// 9-bit SPI via kernel raw PAC GPIO (bypasses Embassy/dev_call GPIO path)
// ============================================================================

/// Send a 9-bit SPI command + data to the kernel's raw PAC GPIO SPI handler.
/// Builds arg buffer: [cs, sck, sda, cmd, data_len, data[0..N]]
unsafe fn spi9_send(s: &St7701sState, cmd: u8, data: &[u8]) {
    spi9_send_inner(s, cmd, data, false);
}

/// Send a 9-bit SPI command but hold CS LOW after (caller must raise CS via spi9_cs_set).
unsafe fn spi9_send_hold(s: &St7701sState, cmd: u8, data: &[u8]) {
    spi9_send_inner(s, cmd, data, true);
}

unsafe fn spi9_send_inner(s: &St7701sState, cmd: u8, data: &[u8], hold_cs: bool) {
    let sys = s.sys();
    // Max data per command in init_seq is 16 bytes, so 5+16+1=22 byte arg buffer suffices
    let mut arg = [0u8; 24];
    let ap = arg.as_mut_ptr();
    core::ptr::write_volatile(ap.add(0), s.cs_pin);
    core::ptr::write_volatile(ap.add(1), s.sck_pin);
    core::ptr::write_volatile(ap.add(2), s.sda_pin);
    core::ptr::write_volatile(ap.add(3), cmd);
    core::ptr::write_volatile(ap.add(4), data.len() as u8);
    let mut i = 0usize;
    while i < data.len() {
        core::ptr::write_volatile(ap.add(5 + i), *data.as_ptr().add(i));
        i += 1;
    }
    let total = 5 + data.len();
    if hold_cs {
        core::ptr::write_volatile(ap.add(total), 1);
        (sys.dev_call)(-1, SPI9_SEND, ap, total + 1);
    } else {
        (sys.dev_call)(-1, SPI9_SEND, ap, total);
    }
}

/// Trigger kernel-level 9-bit SPI reset sequence (RST high→low→high + pin init).
unsafe fn spi9_reset(s: &St7701sState) {
    let sys = s.sys();
    let mut arg = [s.rst_pin, s.cs_pin, s.sck_pin, s.sda_pin];
    (sys.dev_call)(-1, SPI9_RESET, arg.as_mut_ptr(), 4);
}

/// Send one init command from the INIT_SEQ table via kernel SPI.
unsafe fn spi9_send_init_cmd(s: &St7701sState, cmd: &init_seq::InitCmd) {
    let data = core::slice::from_raw_parts(cmd.data.as_ptr(), cmd.len as usize);
    spi9_send(s, cmd.cmd, data);
}

/// Set CS pin level explicitly (for holding CS across delays).
unsafe fn spi9_cs_set(s: &St7701sState, level: u8) {
    let sys = s.sys();
    let mut arg = [s.cs_pin, level];
    (sys.dev_call)(-1, SPI9_CS_SET, arg.as_mut_ptr(), 2);
}

// ============================================================================
// GPIO / Timer helpers
// ============================================================================

unsafe fn claim_gpio_output(sys: &SyscallTable, pin: u8) -> i32 {
    let mut arg = [pin];
    (sys.dev_call)(-1, 0x0106, arg.as_mut_ptr(), 1)
}

unsafe fn gpio_set(sys: &SyscallTable, handle: i32, level: u8) {
    let mut lvl = [level];
    (sys.dev_call)(handle, 0x0104, lvl.as_mut_ptr(), 1);
}

unsafe fn timer_set(sys: &SyscallTable, timer_fd: i32, delay_ms: u32) -> i32 {
    let mut ms_buf = delay_ms.to_le_bytes();
    (sys.dev_call)(timer_fd, 0x0605, ms_buf.as_mut_ptr(), 4)
}

unsafe fn timer_expired(sys: &SyscallTable, timer_fd: i32) -> bool {
    dev_fd_poll(sys, timer_fd, POLL_IN) & (POLL_IN as i32) != 0
}

// ============================================================================
// PIO bridge helpers
// ============================================================================

unsafe fn pio_gpiobase(sys: &SyscallTable, pio: u8, base16: u8) -> i32 {
    let mut arg = [pio, base16];
    (sys.dev_call)(-1, PIO_GPIOBASE, arg.as_mut_ptr(), 2)
}

unsafe fn pio_instr_alloc(sys: &SyscallTable, pio: u8, count: u8, mask_out: &mut u32) -> i32 {
    let mut arg = [pio, count, 0, 0, 0, 0];
    let rc = (sys.dev_call)(-1, PIO_INSTR_ALLOC, arg.as_mut_ptr(), 6);
    if rc >= 0 {
        let p = arg.as_ptr();
        *mask_out = u32::from_le_bytes([
            core::ptr::read_volatile(p.add(2)),
            core::ptr::read_volatile(p.add(3)),
            core::ptr::read_volatile(p.add(4)),
            core::ptr::read_volatile(p.add(5)),
        ]);
    }
    rc
}

unsafe fn pio_instr_write(sys: &SyscallTable, pio: u8, addr: u8, instr: u16) -> i32 {
    let bytes = instr.to_le_bytes();
    let mut arg = [pio, addr, bytes[0], bytes[1]];
    (sys.dev_call)(-1, PIO_INSTR_WRITE, arg.as_mut_ptr(), 4)
}

unsafe fn pio_sm_write_reg(sys: &SyscallTable, pio: u8, sm: u8, reg: u8, value: u32) -> i32 {
    let vb = value.to_le_bytes();
    let mut arg = [pio, sm, reg, vb[0], vb[1], vb[2], vb[3]];
    (sys.dev_call)(-1, PIO_SM_WRITE_REG, arg.as_mut_ptr(), 7)
}

unsafe fn pio_sm_enable(sys: &SyscallTable, pio: u8, mask: u8, enable: u8) -> i32 {
    let mut arg = [pio, mask, enable];
    (sys.dev_call)(-1, PIO_SM_ENABLE, arg.as_mut_ptr(), 3)
}

unsafe fn pio_sm_restart(sys: &SyscallTable, pio: u8, mask: u8) -> i32 {
    let mut arg = [pio, mask];
    (sys.dev_call)(-1, PIO_SM_RESTART, arg.as_mut_ptr(), 2)
}

unsafe fn pio_sm_exec(sys: &SyscallTable, pio: u8, sm: u8, instr: u16) -> i32 {
    let bytes = instr.to_le_bytes();
    let mut arg = [pio, sm, bytes[0], bytes[1]];
    (sys.dev_call)(-1, PIO_SM_EXEC, arg.as_mut_ptr(), 4)
}

unsafe fn pio_txf_write(sys: &SyscallTable, pio: u8, sm: u8, value: u32) -> i32 {
    let vb = value.to_le_bytes();
    let mut arg = [pio, sm, vb[0], vb[1], vb[2], vb[3]];
    (sys.dev_call)(-1, PIO_TXF_WRITE, arg.as_mut_ptr(), 6)
}

unsafe fn pio_pin_setup(sys: &SyscallTable, pin: u8, pio_num: u8, pull: u8) -> i32 {
    let mut arg = [pin, pio_num, pull];
    (sys.dev_call)(-1, PIO_PIN_SETUP, arg.as_mut_ptr(), 3)
}

// ============================================================================
// DMA FD helpers
// ============================================================================

unsafe fn dma_fd_create(sys: &SyscallTable) -> i32 {
    (sys.dev_call)(-1, DMA_FD_CREATE, core::ptr::null_mut(), 0)
}

unsafe fn dma_fd_start(sys: &SyscallTable, fd: i32, read_addr: u32, write_addr: u32, count: u32, dreq: u8, flags: u8) -> i32 {
    let ra = read_addr.to_le_bytes();
    let wa = write_addr.to_le_bytes();
    let cnt = count.to_le_bytes();
    let mut arg = [
        ra[0], ra[1], ra[2], ra[3],
        wa[0], wa[1], wa[2], wa[3],
        cnt[0], cnt[1], cnt[2], cnt[3],
        dreq, flags,
    ];
    (sys.dev_call)(fd, DMA_FD_START, arg.as_mut_ptr(), 14)
}

unsafe fn dma_fd_queue(sys: &SyscallTable, fd: i32, read_addr: u32, count: u32) -> i32 {
    let ra = read_addr.to_le_bytes();
    let cnt = count.to_le_bytes();
    let mut arg = [
        ra[0], ra[1], ra[2], ra[3],
        cnt[0], cnt[1], cnt[2], cnt[3],
    ];
    (sys.dev_call)(fd, DMA_FD_QUEUE, arg.as_mut_ptr(), 8)
}

// ============================================================================
// PIO configuration helpers
// ============================================================================

/// Relocate a PIO instruction: if it's a JMP, add `origin` to the target address.
/// PIO instruction encoding: bits [15:13] = opcode, JMP = 000, target in bits [4:0].
fn relocate_instr(instr: u16, origin: u8) -> u16 {
    let opcode = (instr >> 13) & 0x07;
    if opcode == 0 {
        // JMP instruction: relocate address in bits [4:0]
        let addr = (instr & 0x1F) + origin as u16;
        (instr & !0x1F) | (addr & 0x1F)
    } else {
        instr
    }
}

/// Load a PIO program into instruction memory and return origin.
/// Relocates JMP targets by adding the origin offset.
unsafe fn load_program(sys: &SyscallTable, pio: u8, program: &[u16], mask_out: &mut u32) -> i32 {
    let len = program.len();
    let origin = pio_instr_alloc(sys, pio, len as u8, mask_out);
    if origin < 0 { return origin; }
    let base = origin as u8;
    let mut i = 0usize;
    while i < len {
        let instr = unsafe { *program.as_ptr().add(i) };
        let relocated = relocate_instr(instr, base);
        pio_instr_write(sys, pio, base + i as u8, relocated);
        i += 1;
    }
    origin
}

/// Build EXECCTRL register value.
/// wrap_bottom and wrap_top are absolute addresses (origin + offset).
/// side_en: enable optional sideset, side_pindir: sideset affects pindirs
fn build_execctrl(wrap_bottom: u8, wrap_top: u8, side_en: bool, side_pindir: bool) -> u32 {
    // EXECCTRL register layout (RP2350):
    // [4:0]   STATUS_N
    // [5]     STATUS_SEL
    // [6]     _reserved
    // [11:7]  WRAP_BOTTOM
    // [16:12] WRAP_TOP
    // [28:24] OUT_STICKY/INLINE_OUT_EN/OUT_EN_SEL/JMP_PIN
    // [29]    SIDE_PINDIR
    // [30]    SIDE_EN
    let mut val: u32 = 0;
    val |= (wrap_bottom as u32 & 0x1F) << 7;
    val |= (wrap_top as u32 & 0x1F) << 12;
    if side_en { val |= 1 << 30; }
    if side_pindir { val |= 1 << 29; }
    val
}

/// Build PINCTRL register value.
fn build_pinctrl(
    out_base: u8, out_count: u8,
    set_base: u8, set_count: u8,
    sideset_base: u8, sideset_count: u8,
    in_base: u8,
) -> u32 {
    // PINCTRL layout:
    // [4:0]   OUT_BASE
    // [9:5]   SET_BASE
    // [14:10] SIDESET_BASE
    // [19:15] IN_BASE
    // [25:20] OUT_COUNT
    // [28:26] SET_COUNT
    // [31:29] SIDESET_COUNT
    let mut val: u32 = 0;
    val |= (out_base as u32 & 0x1F);
    val |= (set_base as u32 & 0x1F) << 5;
    val |= (sideset_base as u32 & 0x1F) << 10;
    val |= (in_base as u32 & 0x1F) << 15;
    val |= (out_count as u32 & 0x3F) << 20;
    val |= (set_count as u32 & 0x07) << 26;
    val |= (sideset_count as u32 & 0x07) << 29;
    val
}

/// Build SHIFTCTRL register value.
fn build_shiftctrl(
    autopull: bool, autopush: bool,
    pull_thresh: u8, push_thresh: u8,
    out_shiftdir: bool, in_shiftdir: bool,
    fjoin_tx: bool, fjoin_rx: bool,
) -> u32 {
    // SHIFTCTRL layout:
    // [15:0]  _reserved
    // [16]    AUTOPUSH
    // [17]    AUTOPULL
    // [18]    IN_SHIFTDIR (0=left/MSB first, 1=right/LSB first)
    // [19]    OUT_SHIFTDIR
    // [24:20] PUSH_THRESH (0 = 32)
    // [29:25] PULL_THRESH (0 = 32)
    // [30]    FJOIN_TX
    // [31]    FJOIN_RX
    let mut val: u32 = 0;
    if autopush { val |= 1 << 16; }
    if autopull { val |= 1 << 17; }
    if in_shiftdir { val |= 1 << 18; }
    if out_shiftdir { val |= 1 << 19; }
    val |= ((push_thresh as u32) & 0x1F) << 20;
    val |= ((pull_thresh as u32) & 0x1F) << 25;
    if fjoin_tx { val |= 1 << 30; }
    if fjoin_rx { val |= 1 << 31; }
    val
}

// ============================================================================
// Test pattern helpers
// ============================================================================

/// Fill a stripe buffer with 8-color vertical bars (60px each, RGB565).
/// Colors rotate by `stripe_idx & 7` positions — 32 stripes per frame, 4 per colour band,
/// creating a diagonal colour pattern across the display.
unsafe fn fill_vertical_stripes(buf: *mut u32, width: u16, stripe_idx: u8) {
    const COLORS: [u16; 8] = [
        0xF800, 0x07E0, 0x001F, 0x07FF,
        0xF81F, 0xFFE0, 0x0000, 0xFFFF,
    ];
    let rot = (stripe_idx as usize) & 7;
    let words_per_line = (width >> 1) as usize;
    let pixels_per_bar = (width >> 3) as usize;
    let words_per_bar = pixels_per_bar >> 1;

    let mut line = 0usize;
    while line < STRIPE_LINES as usize {
        let line_off = line * words_per_line;
        let mut bar = 0usize;
        while bar < 8 {
            let ci = (bar + rot) & 7;
            let color = *COLORS.as_ptr().add(ci);
            let packed = (color as u32) | ((color as u32) << 16);
            let bar_off = line_off + bar * words_per_bar;
            let mut w = 0usize;
            while w < words_per_bar {
                core::ptr::write_volatile(buf.add(bar_off + w), packed);
                w += 1;
            }
            bar += 1;
        }
        line += 1;
    }
}

/// Fill `word_count` u32 words with a solid RGB565 colour (packed as two pixels per word).
unsafe fn fill_solid(buf: *mut u32, word_count: usize, color: u16) {
    let packed = (color as u32) | ((color as u32) << 16);
    let mut w = 0usize;
    while w < word_count {
        core::ptr::write_volatile(buf.add(w), packed);
        w += 1;
    }
}

/// Compute row_lookup: maps each display line to its source cache slot.
/// Uses Bresenham DDA — no division required.
/// For a 32-row source on a 480-line display: every 15 display lines map to one source row.
unsafe fn compute_row_lookup(lookup: *mut u8, src_rows: u16, display_height: u16) {
    let mut acc = 0u32;
    let mut row = 0u8;
    let mut d = 0usize;
    while d < display_height as usize {
        core::ptr::write_volatile(lookup.add(d), row);
        acc += src_rows as u32;
        if acc >= display_height as u32 {
            acc -= display_height as u32;
            row += 1;
        }
        d += 1;
    }
}

/// Fill a stripe buffer using the row_lookup table.
/// `line_words` is the actual display width in u32 units (= width/2).
/// Panel renders last-sent line at the top of each stripe region:
///   buf[d=0] sent first (bottom), buf[STRIPE_LINES-1] sent last (top).
/// Reverse index so source row 0 appears at the top.
unsafe fn fill_stripe_from_row_cache(
    buf: *mut u32,
    row_lookup: *const u8,
    line_cache: *const u32,
    stripe_idx: u8,
    line_words: usize,
) {
    let base_line = (stripe_idx as usize) * (STRIPE_LINES as usize);
    let stripe_lines = STRIPE_LINES as usize;
    let mut d = 0usize;
    while d < stripe_lines {
        let src_row = core::ptr::read_volatile(row_lookup.add(base_line + stripe_lines - 1 - d)) as usize;
        let cache_src = line_cache.add(src_row * line_words);
        let dst = buf.add(d * line_words);
        let mut w = 0usize;
        while w < line_words {
            core::ptr::write_volatile(dst.add(w), core::ptr::read_volatile(cache_src.add(w)));
            w += 1;
        }
        d += 1;
    }
}

// ============================================================================
// Module exports
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<St7701sState>() as u32
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
    if state.is_null() || syscalls.is_null() {
        return -22;
    }
    if state_size < core::mem::size_of::<St7701sState>() {
        return -12;
    }

    let s = unsafe { &mut *(state as *mut St7701sState) };
    s.syscalls = syscalls as *const SyscallTable;

    unsafe {
        params_def::set_defaults(s);
        if !params.is_null() && params_len > 0 {
            params_def::parse_tlv(s, params, params_len);
        }
        // Compute runtime geometry from params (must be done after parse_tlv).
        s.line_words = s.width >> 1;
        s.line_bytes = s.line_words << 2;
        // DMA is 16-bit (SIZE_HALFWORD) transfers — count is in pixels, not u32 words.
        s.stripe_pixels = (s.width as u32) * (STRIPE_LINES as u32);
        s.stripe_count = match s.height {
            240 => 4,
            360 => 6,
            _   => 8, // 480 and any other value
        };
        // Build row_lookup: maps each display line to its source cache slot.
        // Must be called after params so src_rows and height are final.
        compute_row_lookup(s.row_lookup.as_mut_ptr(), s.src_rows, s.height);
    }

    s.in_chan = in_chan;
    s.timer_fd = -1;
    s.cs_handle = -1;
    s.sck_handle = -1;
    s.sda_handle = -1;
    s.rst_handle = -1;
    s.bl_handle = -1;
    s.phase = Phase::InitSeq;
    s.init_cmd_idx = 0;
    s.dma_fd = -1;
    s.current_stripe = 0;
    s.back_is_b = 0;
    s.sync_hsync_mask = 0;
    s.sync_vsync_mask = 0;
    s.data_de_mask = 0;
    s.data_rgb_mask = 0;

    unsafe {
        let sys = &*s.syscalls;

        s.timer_fd = (sys.dev_call)(-1, 0x0604, core::ptr::null_mut(), 0);
        if s.timer_fd < 0 { return -12; }

        // BL pin still needs GPIO claim (stays as SIO output after SPI init)
        s.bl_handle = claim_gpio_output(sys, s.bl_pin);
        if s.bl_handle < 0 { return s.bl_handle; }
        gpio_set(sys, s.bl_handle, 1);  // BL off (active-low)

        // Kernel-level reset: configures SIO pins + RST high→low→high (~240ms blocking)
        spi9_reset(s);

        // SPI init: send all register commands via kernel raw PAC GPIO
        let mut idx = 0usize;
        while idx < init_seq::INIT_SEQ_LEN {
            let cmd_ptr = init_seq::INIT_SEQ.as_ptr().add(idx);
            spi9_send_init_cmd(s, &*cmd_ptr);
            idx += 1;
        }

        // SDIR: source scan direction (panel-dependent, configurable via mirror_x param)
        if s.mirror_x != 0 {
            spi9_send(s, 0xFF, &[0x77, 0x01, 0x00, 0x00, 0x10]); // CMD2 Bank 0
            spi9_send(s, 0xC7, &[0x04]);                          // SDIR: mirror source
            spi9_send(s, 0xFF, &[0x77, 0x01, 0x00, 0x00, 0x00]); // back to CMD1
        }

        // SLEEP_OUT + 120ms delay (CS stays LOW during delay, matching vendor BSP)
        spi9_send_hold(s, init_seq::CMD_SLEEP_OUT, &[]);
        timer_set(sys, s.timer_fd, 120);
    }

    0
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    let s = unsafe { &mut *(state as *mut St7701sState) };
    let sys = unsafe { &*s.syscalls };

    match s.phase {
        Phase::ResetPreHigh | Phase::ResetLow | Phase::ResetHigh => {
            // These phases are no longer used (reset done in module_new)
            s.phase = Phase::InitSeq;
            2
        }

        Phase::InitSeq => {
            // SLEEP_OUT timer (set in module_new after SPI init)
            if !unsafe { timer_expired(sys, s.timer_fd) } { return 0; }
            unsafe {
                // Raise CS from SLEEP_OUT hold, then send DISPLAY_ON with CS hold
                spi9_cs_set(s, 1);
                // DISPLAY_ON + 120ms delay (CS stays LOW during delay)
                spi9_send_hold(s, init_seq::CMD_DISPLAY_ON, &[]);
                timer_set(sys, s.timer_fd, 120);
            }
            s.phase = Phase::SleepOut;
            0
        }

        Phase::SleepOut => {
            // DISPLAY_ON timer
            if !unsafe { timer_expired(sys, s.timer_fd) } { return 0; }
            unsafe {
                spi9_cs_set(s, 1);  // Raise CS from DISPLAY_ON hold
                dev_log(sys, 3, b"[lcd] display on".as_ptr(), 16);
            }
            s.phase = Phase::AllocDmaFd;
            2
        }

        Phase::DisplayOn => {
            // Unused — kept for enum completeness
            s.phase = Phase::AllocDmaFd;
            2
        }

        Phase::AllocDmaFd => {
            let fd = unsafe { dma_fd_create(sys) };
            if fd < 0 {
                unsafe { dev_log(sys, 1, b"[lcd] DMA FD alloc fail".as_ptr(), 23); }
                s.phase = Phase::Error;
                return fd;
            }
            s.dma_fd = fd;
            s.phase = Phase::ConfigurePioSync;
            2
        }

        Phase::ConfigurePioSync => {
            let pio = s.pio_sync;
            const GPIO_BASE: u8 = 16;
            let pio_hsync = s.hsync_pin - GPIO_BASE;
            let pio_vsync = s.vsync_pin - GPIO_BASE;
            // PCLK is sideset bit1 of hsync SM, base at hsync_pin
            // So sideset_base = hsync_pin (PIO-relative), which covers hsync(bit0) and pclk(bit1)
            // This requires pclk_pin = hsync_pin + 1 (which is 22+1=23, correct)

            unsafe {
                // Set GPIOBASE=16
                pio_gpiobase(sys, pio, 1);

                // Disable all SMs on this PIO
                pio_sm_enable(sys, pio, 0x0F, 0);

                // Load hsync program → SM0
                let origin = load_program(sys, pio, &pio_programs::HSYNC_PROGRAM, &mut s.sync_hsync_mask);
                if origin < 0 {
                    dev_log(sys, 1, b"[lcd] hsync load fail".as_ptr(), 21);
                    s.phase = Phase::Error;
                    return origin;
                }
                s.hsync_origin = origin as u8;

                // Load vsync program → SM1
                let origin = load_program(sys, pio, &pio_programs::VSYNC_PROGRAM, &mut s.sync_vsync_mask);
                if origin < 0 {
                    dev_log(sys, 1, b"[lcd] vsync load fail".as_ptr(), 21);
                    s.phase = Phase::Error;
                    return origin;
                }
                s.vsync_origin = origin as u8;

                // Configure SM0 (hsync): sideset 2 opt (PCLK+HSYNC)
                let h_wrap_bot = s.hsync_origin + pio_programs::HSYNC_WRAP_TARGET;
                let h_wrap_top = s.hsync_origin + pio_programs::HSYNC_WRAP;
                pio_sm_write_reg(sys, pio, 0, REG_EXECCTRL,
                    build_execctrl(h_wrap_bot, h_wrap_top, pio_programs::HSYNC_SIDESET_OPT, false));
                pio_sm_write_reg(sys, pio, 0, REG_PINCTRL,
                    build_pinctrl(0, 0, 0, 0, pio_hsync, 3, 0));
                    // sideset_count=3 for 2-bit opt sideset (2 value + 1 enable)
                    // sideset_base = hsync pin (PIO-relative), pclk = hsync+1

                // HSYNC SM clock divider: sys_clk / (pclk_freq * 2)
                // 240MHz / (16MHz * 2) = 7.5 → Q16.16 = 0x0007_8000
                let hsync_clkdiv: u32 = 0x0007_8000;

                pio_sm_write_reg(sys, pio, 0, REG_CLKDIV, hsync_clkdiv);
                pio_sm_write_reg(sys, pio, 0, REG_SHIFTCTRL,
                    build_shiftctrl(false, false, 0, 0, false, false, true, false));
                    // fjoin_tx=true for 8-deep TX FIFO

                // Configure SM1 (vsync): sideset 1 opt (VSYNC)
                let v_wrap_bot = s.vsync_origin + pio_programs::VSYNC_WRAP_TARGET;
                let v_wrap_top = s.vsync_origin + pio_programs::VSYNC_WRAP;
                pio_sm_write_reg(sys, pio, 1, REG_EXECCTRL,
                    build_execctrl(v_wrap_bot, v_wrap_top, pio_programs::VSYNC_SIDESET_OPT, false));
                pio_sm_write_reg(sys, pio, 1, REG_PINCTRL,
                    build_pinctrl(0, 0, 0, 0, pio_vsync, 2, 0));
                    // sideset_count=2 for 1-bit opt sideset (1 value + 1 enable)
                // VSYNC SM runs at full sysclk (div 1.0)
                pio_sm_write_reg(sys, pio, 1, REG_CLKDIV, 1 << 16);
                pio_sm_write_reg(sys, pio, 1, REG_SHIFTCTRL,
                    build_shiftctrl(false, false, 0, 0, false, false, true, false));

                // Setup pin funcsel for PIO
                pio_pin_setup(sys, s.hsync_pin, pio, 0);  // pull=none
                pio_pin_setup(sys, s.pclk_pin, pio, 0);
                pio_pin_setup(sys, s.vsync_pin, pio, 0);

                // Set sideset pins as outputs via SET PINDIRS
                // HSYNC SM0: 2 sideset pins (hsync, pclk)
                let set_pindirs_2 = 0xE082u16; // set pindirs, 2 (binary: 00010)...
                // Actually: set pindirs, 0b11 = set pindirs, 3 — but set only has 5 bits for data.
                // We need SET PINDIRS, with count matching sideset_count-1 pins.
                // Better approach: temporarily set SET_BASE and SET_COUNT to the sideset pins.
                // Then execute SET PINDIRS, <mask>.
                // For hsync SM: sideset pins are hsync_pin and hsync_pin+1 (pclk).
                // set_base = pio_hsync, set_count = 2, then SET PINDIRS, 0b11 (=3)
                // First save and restore pinctrl.
                pio_sm_write_reg(sys, pio, 0, REG_PINCTRL,
                    build_pinctrl(0, 0, pio_hsync, 2, pio_hsync, 3, 0));
                pio_sm_exec(sys, pio, 0, 0xE083); // set pindirs, 3 (both bits = output)

                // Restore SM0 pinctrl for normal operation
                pio_sm_write_reg(sys, pio, 0, REG_PINCTRL,
                    build_pinctrl(0, 0, 0, 0, pio_hsync, 3, 0));

                // VSYNC SM1: 1 sideset pin
                pio_sm_write_reg(sys, pio, 1, REG_PINCTRL,
                    build_pinctrl(0, 0, pio_vsync, 1, pio_vsync, 2, 0));
                pio_sm_exec(sys, pio, 1, 0xE081); // set pindirs, 1

                // Restore SM1 pinctrl
                pio_sm_write_reg(sys, pio, 1, REG_PINCTRL,
                    build_pinctrl(0, 0, 0, 0, pio_vsync, 2, 0));

                // Push initial values to TX FIFOs
                // HSYNC SM0 gets width-1 (stored in Y via bootstrap)
                pio_txf_write(sys, pio, 0, (s.width - 1) as u32);
                // VSYNC SM1 gets height-1 (stored in OSR via bootstrap)
                pio_txf_write(sys, pio, 1, (s.height - 1) as u32);

                // JMP SM0 to hsync origin, SM1 to vsync origin
                pio_sm_exec(sys, pio, 0, s.hsync_origin as u16); // JMP hsync_origin
                pio_sm_exec(sys, pio, 1, s.vsync_origin as u16); // JMP vsync_origin
            }

            s.phase = Phase::ConfigurePioData;
            2
        }

        Phase::ConfigurePioData => {
            let pio = s.pio_data;
            const GPIO_BASE: u8 = 16;
            let pio_de = s.de_pin - GPIO_BASE;
            let pio_data0 = s.data0_pin - GPIO_BASE;

            unsafe {
                // Set GPIOBASE=16
                pio_gpiobase(sys, pio, 1);

                // Disable all SMs
                pio_sm_enable(sys, pio, 0x0F, 0);

                // Load rgb_de program → SM0
                let origin = load_program(sys, pio, &pio_programs::RGB_DE_PROGRAM, &mut s.data_de_mask);
                if origin < 0 {
                    dev_log(sys, 1, b"[lcd] rgb_de load fail".as_ptr(), 22);
                    s.phase = Phase::Error;
                    return origin;
                }
                s.de_origin = origin as u8;

                // Load rgb program → SM1
                let origin = load_program(sys, pio, &pio_programs::RGB_PROGRAM, &mut s.data_rgb_mask);
                if origin < 0 {
                    dev_log(sys, 1, b"[lcd] rgb load fail".as_ptr(), 19);
                    s.phase = Phase::Error;
                    return origin;
                }
                s.rgb_origin = origin as u8;

                // Configure SM0 (rgb_de): sideset 1 opt (DE)
                let de_wrap_bot = s.de_origin + pio_programs::RGB_DE_WRAP_TARGET;
                let de_wrap_top = s.de_origin + pio_programs::RGB_DE_WRAP;
                pio_sm_write_reg(sys, pio, 0, REG_EXECCTRL,
                    build_execctrl(de_wrap_bot, de_wrap_top, pio_programs::RGB_DE_SIDESET_OPT, false));
                pio_sm_write_reg(sys, pio, 0, REG_PINCTRL,
                    build_pinctrl(0, 0, 0, 0, pio_de, 2, 0));
                    // sideset_count=2 for 1-bit opt (1 value + 1 enable), in_base=0 (wait pin N = PIO pin N)
                pio_sm_write_reg(sys, pio, 0, REG_CLKDIV, 1 << 16); // full speed
                pio_sm_write_reg(sys, pio, 0, REG_SHIFTCTRL,
                    build_shiftctrl(false, false, 0, 0, false, false, true, false));

                // Configure SM1 (rgb): no sideset, OUT 16 pins
                let rgb_wrap_bot = s.rgb_origin + pio_programs::RGB_WRAP_TARGET;
                let rgb_wrap_top = s.rgb_origin + pio_programs::RGB_WRAP;
                pio_sm_write_reg(sys, pio, 1, REG_EXECCTRL,
                    build_execctrl(rgb_wrap_bot, rgb_wrap_top, false, false));
                pio_sm_write_reg(sys, pio, 1, REG_PINCTRL,
                    build_pinctrl(pio_data0, 16, 0, 0, 0, 0, 0));
                    // out_base=data0, out_count=16, in_base=0 (wait pin N = PIO pin N)
                pio_sm_write_reg(sys, pio, 1, REG_CLKDIV, 1 << 16); // full speed
                pio_sm_write_reg(sys, pio, 1, REG_SHIFTCTRL,
                    build_shiftctrl(false, false, 0, 0, false, false, true, false));
                    // autopull=false, pull_thresh=0(default), out_shiftdir=LEFT/MSB(vendor default), fjoin_tx=true

                // Setup data pins for PIO
                let mut i = 0u8;
                while i < 16 {
                    pio_pin_setup(sys, s.data0_pin + i, pio, 2); // pull-up
                    i += 1;
                }
                // DE pin
                pio_pin_setup(sys, s.de_pin, pio, 0);

                // Set data pins as outputs via SM1 SET PINDIRS (5 pins at a time max)
                // Save pinctrl, set SET_BASE/COUNT, exec SET PINDIRS, restore
                let mut pin = pio_data0;
                let mut remaining: u8 = 16;
                while remaining > 0 {
                    let count = if remaining > 5 { 5 } else { remaining };
                    let mask = (1u8 << count) - 1;
                    pio_sm_write_reg(sys, pio, 1, REG_PINCTRL,
                        build_pinctrl(pio_data0, 16, pin, count, 0, 0, pio_de));
                    pio_sm_exec(sys, pio, 1, 0xE080 | mask as u16); // set pindirs, mask
                    pin += count;
                    remaining -= count;
                }

                // Set DE pin as output via SM0
                pio_sm_write_reg(sys, pio, 0, REG_PINCTRL,
                    build_pinctrl(0, 0, pio_de, 1, pio_de, 2, pio_de));
                pio_sm_exec(sys, pio, 0, 0xE081); // set pindirs, 1

                // Restore pinctrl for both SMs
                // in_base=0 so `wait N pin M` maps directly to PIO-relative pin M
                pio_sm_write_reg(sys, pio, 0, REG_PINCTRL,
                    build_pinctrl(0, 0, 0, 0, pio_de, 2, 0));
                pio_sm_write_reg(sys, pio, 1, REG_PINCTRL,
                    build_pinctrl(pio_data0, 16, 0, 0, 0, 0, 0));

                // Push initial values
                // rgb_de SM0 gets height-1
                pio_txf_write(sys, pio, 0, (s.height - 1) as u32);
                // rgb SM1 gets width-1
                pio_txf_write(sys, pio, 1, (s.width - 1) as u32);

                // JMP to program origins
                pio_sm_exec(sys, pio, 0, s.de_origin as u16);
                pio_sm_exec(sys, pio, 1, s.rgb_origin as u16);
            }

            s.phase = Phase::StartSMs;
            2
        }

        Phase::StartSMs => {
            if s.in_chan >= 0 {
                // Channel mode: defer PIO + DMA until first frame is cached.
                // Loading phase reads src_rows lines directly into line_cache.
                // PIO SMs start only after the first cache is fully populated.
                s.frame_loaded = 0;
                s.back_is_b = 0;
                s.load_row = 0;
                s.load_row_off = 0;
                s.load_cache_off = 0;
                s.current_stripe = 0;
                s.has_line_cache = 0;
                s.active_cache_b = 0;
                s.is_loading = 0;
                s.back_ready = 0;
                unsafe { dev_log(sys, 3, b"[lcd] loading from channel".as_ptr(), 26); }
                s.phase = Phase::Loading;
                return 2;
            }

            // Test pattern mode: start PIO + DMA immediately.
            // Descending DMA order (stripe_count-1 → 0): last transfer = stripe 0 = display top.
            let sc = s.stripe_count;
            unsafe {
                pio_sm_restart(sys, s.pio_data, 0x03);
                pio_sm_exec(sys, s.pio_data, 0, s.de_origin as u16);
                pio_sm_exec(sys, s.pio_data, 1, s.rgb_origin as u16);
                pio_sm_enable(sys, s.pio_data, 0x03, 1);

                pio_sm_restart(sys, s.pio_sync, 0x03);
                pio_sm_exec(sys, s.pio_sync, 0, s.hsync_origin as u16);
                pio_sm_exec(sys, s.pio_sync, 1, s.vsync_origin as u16);
                pio_sm_enable(sys, s.pio_sync, 0x03, 1);

                gpio_set(sys, s.bl_handle, 0);
                s.frame_loaded = 1;

                fill_vertical_stripes(s.stripe_a.as_mut_ptr(), s.width, sc - 1);
                fill_vertical_stripes(s.stripe_b.as_mut_ptr(), s.width, sc - 2);
            }

            let write_addr = St7701sState::txf_addr(s.pio_data, 1);
            let dreq = (s.pio_data * 8) + 1;

            let rc = unsafe {
                dma_fd_start(sys, s.dma_fd, s.stripe_a.as_ptr() as u32, write_addr, s.stripe_pixels, dreq, 0x01)
            };
            if rc < 0 {
                unsafe { dev_log(sys, 1, b"[lcd] DMA start fail".as_ptr(), 20); }
                s.phase = Phase::Error;
                return rc;
            }

            let rc = unsafe {
                dma_fd_queue(sys, s.dma_fd, s.stripe_b.as_ptr() as u32, s.stripe_pixels)
            };
            if rc < 0 {
                unsafe { dev_log(sys, 1, b"[lcd] DMA queue fail".as_ptr(), 20); }
                s.phase = Phase::Error;
                return rc;
            }

            s.back_is_b = 0;
            s.current_stripe = sc - 3; // stripe_count-1 and stripe_count-2 already queued
            s.phase = Phase::DmaWait;
            0
        }

        Phase::Loading => {
            // First-frame load: read src_rows lines directly into line_cache.
            // Each line is line_bytes bytes (= width * 2). img_decode must be
            // configured with height == src_rows so it emits exactly src_rows lines.
            // After all rows are cached, fill stripe_a/b and start PIO+DMA.
            let lb = s.line_bytes as usize;
            let src_rows = s.src_rows as usize;
            let dst_base = s.line_cache.as_mut_ptr() as *mut u8;

            while (s.load_row as usize) < src_rows {
                let remaining = lb - s.load_row_off as usize;
                let chan_poll = unsafe { (sys.channel_poll)(s.in_chan, POLL_IN) };
                if chan_poll & (POLL_IN as i32) == 0 {
                    return 0; // yield — wait for more data
                }
                let dst = unsafe { dst_base.add(s.load_cache_off as usize) };
                let read = unsafe { (sys.channel_read)(s.in_chan, dst, remaining) };
                if read <= 0 {
                    return 0;
                }
                let r = read as u16;
                s.load_row_off += r;
                s.load_cache_off += r as u32;
                if s.load_row_off >= s.line_bytes {
                    s.load_row += 1;
                    s.load_row_off = 0;
                }
            }

            // All src_rows cached. Reset load state for background loads.
            s.load_row = 0;
            s.load_row_off = 0;
            s.load_cache_off = 0;
            s.has_line_cache = 1;
            s.active_cache_b = 0; // display from line_cache (front)

            let sc = s.stripe_count;
            let lw = s.line_words as usize;

            // Populate stripe_a (stripe sc-1) and stripe_b (stripe sc-2) from cache.
            // DMA sends them first; descending order means sc-1 → 0, so stripe 0 is last = top.
            unsafe {
                fill_stripe_from_row_cache(s.stripe_a.as_mut_ptr(), s.row_lookup.as_ptr(), s.line_cache.as_ptr(), sc - 1, lw);
                fill_stripe_from_row_cache(s.stripe_b.as_mut_ptr(), s.row_lookup.as_ptr(), s.line_cache.as_ptr(), sc - 2, lw);
            }

            // Start all 4 PIO SMs with bootstrap values pushed into TX FIFOs.
            unsafe {
                pio_sm_enable(sys, s.pio_data, 0x03, 0);
                pio_sm_enable(sys, s.pio_sync, 0x03, 0);
                pio_sm_restart(sys, s.pio_data, 0x03);
                pio_sm_restart(sys, s.pio_sync, 0x03);

                pio_txf_write(sys, s.pio_data, 0, (s.height - 1) as u32);
                pio_txf_write(sys, s.pio_data, 1, (s.width  - 1) as u32);
                pio_txf_write(sys, s.pio_sync, 0, (s.width  - 1) as u32);
                pio_txf_write(sys, s.pio_sync, 1, (s.height - 1) as u32);

                pio_sm_exec(sys, s.pio_data, 0, s.de_origin    as u16);
                pio_sm_exec(sys, s.pio_data, 1, s.rgb_origin   as u16);
                pio_sm_exec(sys, s.pio_sync, 0, s.hsync_origin as u16);
                pio_sm_exec(sys, s.pio_sync, 1, s.vsync_origin as u16);

                pio_sm_enable(sys, s.pio_data, 0x03, 1);
                pio_sm_enable(sys, s.pio_sync, 0x03, 1);
            }

            // Start DMA chain: stripe_a first, stripe_b queued.
            let write_addr = St7701sState::txf_addr(s.pio_data, 1);
            let dreq = (s.pio_data * 8) + 1;

            let rc = unsafe {
                dma_fd_start(sys, s.dma_fd, s.stripe_a.as_ptr() as u32, write_addr, s.stripe_pixels, dreq, 0x01)
            };
            if rc < 0 {
                unsafe { dev_log(sys, 1, b"[lcd] DMA start fail".as_ptr(), 20); }
                s.phase = Phase::Error;
                return rc;
            }
            let rc = unsafe {
                dma_fd_queue(sys, s.dma_fd, s.stripe_b.as_ptr() as u32, s.stripe_pixels)
            };
            if rc < 0 {
                unsafe { dev_log(sys, 1, b"[lcd] DMA queue fail".as_ptr(), 20); }
                s.phase = Phase::Error;
                return rc;
            }

            if s.frame_loaded == 0 {
                s.frame_loaded = 1;
                unsafe { gpio_set(sys, s.bl_handle, 0); }
            }
            s.current_stripe = sc - 3; // sc-1 and sc-2 already queued; next fill is sc-3
            s.back_is_b = 0;
            unsafe { dev_log(sys, 3, b"[lcd] cached, go".as_ptr(), 16); }
            s.phase = Phase::DmaWait;
            0
        }

        Phase::FillStripe => {
            // Unused — kept for enum stability
            0
        }

        Phase::Running => {
            // Unused in current flow — kept for enum completeness
            0
        }

        Phase::DmaWait => {
            // ── Step 1: DMA ping-pong ────────────────────────────────────────
            let poll = unsafe { dev_fd_poll(sys, s.dma_fd, POLL_IN) };
            if poll & (POLL_IN as i32) != 0 {
                let lw = s.line_words as usize;

                // Select the display cache (front). No PIO restart on frame switch —
                // the swap below is atomic at the frame boundary.
                let cache_ptr = if s.active_cache_b != 0 {
                    s.line_cache_back.as_ptr()
                } else {
                    s.line_cache.as_ptr()
                };

                if s.has_line_cache != 0 {
                    unsafe { fill_stripe_from_row_cache(s.back_buf_ptr(), s.row_lookup.as_ptr(), cache_ptr, s.current_stripe, lw); }
                } else {
                    unsafe { fill_vertical_stripes(s.back_buf_ptr(), s.width, s.current_stripe); }
                }

                let rc = unsafe {
                    dma_fd_queue(sys, s.dma_fd, s.back_buf_ptr() as u32, s.stripe_pixels)
                };
                if rc < 0 {
                    unsafe { dev_log(sys, 1, b"[lcd] DMA queue fail".as_ptr(), 20); }
                    s.phase = Phase::Error;
                    return rc;
                }
                s.back_is_b ^= 1;

                // Count down; wrap at 0 → stripe_count-1 (frame boundary).
                if s.current_stripe == 0 {
                    s.current_stripe = s.stripe_count - 1;

                    // Frame boundary: atomically swap to the newly-loaded back cache.
                    if s.back_ready != 0 {
                        s.active_cache_b ^= 1;
                        s.back_ready = 0;
                        s.is_loading = 0;
                    }
                } else {
                    s.current_stripe -= 1;
                }
            }

            // ── Step 2: Background loading ───────────────────────────────────
            // Start a new background load as soon as upstream has data and no load is pending.
            if s.in_chan >= 0 && s.is_loading == 0 && s.back_ready == 0 {
                let chan_poll = unsafe { (sys.channel_poll)(s.in_chan, POLL_IN) };
                if chan_poll & (POLL_IN as i32) != 0 {
                    s.is_loading = 1;
                    s.load_row = 0;
                    s.load_row_off = 0;
                    s.load_cache_off = 0;
                }
            }

            if s.is_loading != 0 {
                let lb = s.line_bytes as usize;
                let src_rows = s.src_rows as usize;
                let dst_base = s.line_cache_back.as_mut_ptr() as *mut u8;

                // Drain as much channel data as available into the back cache.
                loop {
                    if (s.load_row as usize) >= src_rows { break; }
                    let chan_poll = unsafe { (sys.channel_poll)(s.in_chan, POLL_IN) };
                    if chan_poll & (POLL_IN as i32) == 0 { break; }
                    let remaining = lb - s.load_row_off as usize;
                    let dst = unsafe { dst_base.add(s.load_cache_off as usize) };
                    let read = unsafe { (sys.channel_read)(s.in_chan, dst, remaining) };
                    if read <= 0 { break; }
                    let r = read as u16;
                    s.load_row_off += r;
                    s.load_cache_off += r as u32;
                    if s.load_row_off >= s.line_bytes {
                        s.load_row += 1;
                        s.load_row_off = 0;
                    }
                }

                if (s.load_row as usize) >= src_rows {
                    s.back_ready = 1;
                    s.is_loading = 0;
                }
            }

            0
        }

        _ => -1,
    }
}

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [
        ChannelHint { port_type: 0, port_index: 0, buffer_size: 4096 },
    ];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

#[no_mangle]
#[link_section = ".text.module_deferred_ready"]
pub extern "C" fn module_deferred_ready() {}

// ============================================================================
// Panic handler
// ============================================================================

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
