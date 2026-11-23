//! st7701s — an ST7701S RGB-parallel panel scanned out a band at a time.
//!
//! The driver takes a `VideoDraw` stream on `draw`, retains the last
//! committed frame's records, and draws them again every refresh with the
//! reference rasteriser (`fluxor_sdk::video::raster`), a band of rows at a
//! time, into a ring of band slots the panel is scanned out from. The draw
//! list is its frame memory: a few kilobytes of records stand in for a
//! framebuffer, and a new frame takes effect whole, at the first band of
//! the first refresh after its COMMIT. `surface0` is a raster input a
//! SURFACE record places; with no `draw` edge the driver shows `surface0`
//! scaled to the panel.
//!
//! # Timing
//!
//! Four PIO state machines on two PIO blocks make the panel's timing and
//! never stop: HSYNC with the pixel clock and VSYNC on the sync block, DE
//! and the 16 data pins on the data block. The data state machine takes one
//! word a pixel from its TX FIFO, which a DMA scan list fills
//! (`platform_dma_fd` `LIST_START`): one entry a band, every entry the same
//! number of pixels, sent from a ring slot when the driver armed it and as
//! the fill colour when it did not. No software sits between the list and
//! the panel, so a band drawn late shows as fill for one refresh and is
//! counted; sync, porches and the pixel clock never move.
//!
//! The sync divider comes from the system clock and `refresh_mhz`: a line
//! is `2 × (10 + 8 + 10 + width) + 5` sync cycles (two a pixel clock, five
//! single cycles of the HSYNC program), a frame `height + 8 + 3 + 18`
//! lines.
//!
//! # A step
//!
//! Read how far the scan has run, read what the inputs hold, then do one
//! piece of drawing: draw the next band into the scratch, or convert the
//! scratch into a free ring slot and arm its entry. Nothing waits.
//!
//! A band can be armed while the scan is two or more entries short of it.
//! The renderer works ahead of the scan by up to the ring; when the scan
//! catches it, it does not chase: it resumes at the first band it can
//! still finish, and the bands between show as fill.
//!
//! The kernel answers from where the scan is, not from where the driver
//! last read it: an arm it refuses as busy is a band the scan took while
//! its slot was being filled, and goes out as fill. Around a flash write
//! the kernel returns every armed entry to fill; the driver does nothing
//! about it, since the slots it holds come free as the scan passes their
//! bands, armed or not, and the next band it draws is armed as any other.
//! The scan's position is the list's control pointer, so it counts bands
//! modulo the list across a span the kernel's interrupt was held for:
//! every band count here is used as a difference or modulo `bands`.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::contracts::video_draw as vd;
use abi::platform::rp::dma_raw::{self, fd as dma_fd};
use abi::SyscallTable;
use fluxor_abi as abi;

mod init_seq;
mod pio_programs;

use fluxor_rt::asset::{self, Asset};
use fluxor_rt::*;
use fluxor_sdk::video::raster::{
    self, Band, Entry, Event, Held, Index, Ingest, Input, Painter, Shape, Slot, Store, Surfaces,
    Texels, BAND_BPP,
};

// ============================================================================
// Limits and geometry
// ============================================================================

/// The deepest SAVE nesting and the most live rounded clips
/// (`max_depth` on the `draw` port).
const MAX_DEPTH: usize = 8;
/// Resource ids (`max_resources` on the `draw` port).
const MAX_RESOURCES: usize = 16;
/// Byte strings the instance holds in place for RES_REF records: the
/// `pack0` to `pack3` params.
const PACKS: usize = 4;
/// Bytes of a `pack` param kept: a program reference.
const PACK_PARAM: usize = 16;
/// Records of a retained frame whose rows are indexed; a frame with more
/// is drawn by walking the rest record by record.
const INDEX_RECORDS: usize = 256;
/// The widest panel: the heap figures of the manifest are per row of this.
const MAX_WIDTH: u16 = 480;
/// The most ring slots.
const MAX_SLOTS: usize = 32;
/// The fewest ring slots, and the fewest bands: one being sent, one the
/// scan may load at any moment, one to draw into.
const MIN_SLOTS: usize = 3;
// A list of the fewest bands is one the kernel starts.
const _: () = assert!(MIN_SLOTS as u16 >= dma_raw::list_start::MIN_ENTRIES);
/// The heap besides what the params size: the block header and the padding
/// between the parts (`heap_per_param.base`).
const ARENA_BASE: u32 = 128;
/// Bytes of the held byte strings hashed in one step.
const HASH_BYTES_PER_STEP: usize = 2048;
/// Bytes of `surface0` read in one step.
const INPUT_BYTES_PER_STEP: usize = 4096;
/// The frame the driver draws when `draw` is not wired: FRAME, one SURFACE
/// and COMMIT.
const OWN_FRAME_BYTES: usize = 3 * vd::HEADER + vd::FRAME_LEN + vd::SURFACE_LEN + vd::COMMIT_LEN;

/// Sync cycles a line spends outside the active pixels: two for each of
/// the 10 + 8 + 10 porch and pulse clocks, and five single cycles.
const LINE_BLANK_CYCLES: u32 = 2 * (10 + 8 + 10) + 5;
/// Lines of a frame outside the active rows: front porch, pulse, back
/// porch.
const FRAME_BLANK_LINES: u32 = 8 + 3 + 18;
/// System cycles the data state machine needs a pixel: its five-instruction
/// loop and two cycles of input synchronisation, with a cycle to spare.
const DATA_CYCLES_PER_PIXEL: u32 = 8;

/// A band can be armed while the scan is this many entries short of it:
/// the entry being sent and the one after it are the scan's.
const ARM_LEAD: i32 = 2;
/// Entries of the first refresh no renderer can arm: the list starts on
/// entry 0 with entry 1 next.
const UNARMABLE_AT_START: u32 = ARM_LEAD as u32;

/// Cookie of the ring's lend on the DMA fd.
const RING_LEND: u32 = 1;

const NO_PIN: u8 = 255;

const WIDTH_DEFAULT: u16 = 480;
const HEIGHT_DEFAULT: u16 = 480;
const REFRESH_MHZ_DEFAULT: u32 = 60_000;
const PCLK_MAX_KHZ_DEFAULT: u32 = 18_000;
const BAND_ROWS_DEFAULT: u16 = 16;
const RING_ROWS_DEFAULT: u16 = 48;
const FRAME_BYTES_DEFAULT: u32 = 8192;
const RESOURCE_BYTES_DEFAULT: u32 = 16_384;
const RECORD_BYTES_DEFAULT: u32 = 1024;

// PIO state machine register indices (`rp_raw::PIO_SM_WRITE_REG`).
const REG_CLKDIV: u8 = 0;
const REG_EXECCTRL: u8 = 1;
const REG_SHIFTCTRL: u8 = 2;
const REG_PINCTRL: u8 = 3;

/// `SHIFTCTRL` with the TX FIFO joined to eight words and every other
/// field at reset.
const SHIFTCTRL_JOIN_TX: u32 = 1 << 30;
/// A divider of one: `CLKDIV` holds 16 integer bits above 8 fraction bits
/// above 8 reserved.
const CLKDIV_ONE: u32 = 1 << 16;

/// `set pindirs, <mask>`.
const fn set_pindirs(mask: u8) -> u16 {
    0xE080 | mask as u16
}

// ============================================================================
// State
// ============================================================================

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// SLEEP_OUT has been sent; its 120 ms run.
    SleepOut,
    /// DISPLAY_ON has been sent; its 120 ms run.
    DisplayOn,
    /// Configure the state machines and start the scan.
    Start,
    Run,
    Failed,
}

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    draw: i32,
    timer_fd: i32,
    bl_handle: i32,
    dma_fd: i32,
    phase: Phase,

    // Params.
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
    pio_sync: u8,
    pio_data: u8,
    mirror_x: u8,
    status_s: u8,
    width: u16,
    height: u16,
    band_rows: u16,
    ring_rows: u16,
    underrun_rgb565: u16,
    refresh_mhz: u32,
    pclk_max_khz: u32,
    frame_bytes: u32,
    resource_bytes: u32,
    record_bytes: u32,
    surface_bytes: u32,
    pack_params: [[u8; PACK_PARAM]; PACKS],
    pack_lens: [u8; PACKS],

    // What the params come to.
    /// 0 or 16: the first GPIO of the 32-pin window the PIO blocks drive.
    gpio_base: u8,
    /// Entries of the scan list: bands of a refresh.
    bands: u16,
    /// Ring slots.
    slots: u16,
    /// Bytes of one slot.
    slot_bytes: u32,
    /// The sync divider, in 1/256.
    divider_256: u32,
    /// The refresh rate the divider gives, mHz.
    achieved_mhz: u32,
    /// The time the scan takes over one band, µs.
    band_us: u32,

    // The rasteriser.
    resources: [vd::Resource; MAX_RESOURCES],
    saves: [vd::Saved; MAX_DEPTH],
    store_slots: [Slot; MAX_RESOURCES],
    held: [Held<'static>; PACKS],
    index: [Entry; INDEX_RECORDS],
    stack: [raster::Saved; MAX_DEPTH],
    clips: [Shape; MAX_DEPTH],
    ingest: Option<Ingest<'static>>,
    painter: Option<Painter<'static>>,
    surface: Option<Input>,
    own_frame: [u8; OWN_FRAME_BYTES],
    own_frame_len: usize,
    scratch: *mut u8,
    scratch_bytes: usize,
    ring: *mut u8,

    // The scan, as `LIST_STATUS` last answered. Band counts wrap.
    /// Bands sent since the list started.
    sent: u32,
    /// `sent` within its refresh.
    sent_entry: u16,
    refreshes: u32,
    list_underruns: u32,
    /// The scan has passed the entries no renderer could arm.
    past_start: bool,

    // The renderer.
    /// The band being drawn, counted like `sent`.
    next: u32,
    /// `next` within its refresh: the list entry it is armed as.
    next_entry: u16,
    /// The ring slot the next armed band goes into.
    slot_cursor: u16,
    /// For each slot, the band count at which the band armed in it has
    /// been sent.
    slot_free_at: [u32; MAX_SLOTS],
    slot_armed: u32,
    /// The scratch holds band `next`, drawn and waiting for a slot.
    drawn: bool,
    /// Band `next` is black: nothing is retained to draw.
    black: bool,
    /// Band `next` is the first drawn of its refresh.
    first_of_refresh: bool,
    /// A frame committed and waits for the next refresh.
    frame_waiting: bool,
    /// `next` when that frame committed.
    committed_at: u32,
    late_frames: u32,
    /// µs spent on band `next` so far.
    band_cost_us: u32,
    /// µs the last finished band took.
    last_band_us: u32,
    refresh_cost_us: u32,
    refresh_bands: u32,
    render_us_per_band: u32,

    // Reporting.
    metrics_at_ms: u64,
    status_at_us: u64,
    status_sent: u32,
}

mod params_def {
    use super::*;
    fluxor_rt::define_params! {
        State;
        1, cs_pin, u8, 18 => |s, d, len| { s.cs_pin = p_u8(d, len, 0, 18); };
        2, sck_pin, u8, 2 => |s, d, len| { s.sck_pin = p_u8(d, len, 0, 2); };
        3, sda_pin, u8, 3 => |s, d, len| { s.sda_pin = p_u8(d, len, 0, 3); };
        4, rst_pin, u8, 19 => |s, d, len| { s.rst_pin = p_u8(d, len, 0, 19); };
        5, bl_pin, u8, 40 => |s, d, len| { s.bl_pin = p_u8(d, len, 0, 40); };
        6, de_pin, u8, 20 => |s, d, len| { s.de_pin = p_u8(d, len, 0, 20); };
        7, hsync_pin, u8, 22 => |s, d, len| { s.hsync_pin = p_u8(d, len, 0, 22); };
        8, vsync_pin, u8, 21 => |s, d, len| { s.vsync_pin = p_u8(d, len, 0, 21); };
        9, pclk_pin, u8, 23 => |s, d, len| { s.pclk_pin = p_u8(d, len, 0, 23); };
        10, data0_pin, u8, 24 => |s, d, len| { s.data0_pin = p_u8(d, len, 0, 24); };
        11, width, u16, WIDTH_DEFAULT
            => |s, d, len| { s.width = p_u16(d, len, 0, WIDTH_DEFAULT); };
        12, height, u16, HEIGHT_DEFAULT
            => |s, d, len| { s.height = p_u16(d, len, 0, HEIGHT_DEFAULT); };
        13, pio_sync, u8, 1 => |s, d, len| { s.pio_sync = p_u8(d, len, 0, 1); };
        14, pio_data, u8, 2 => |s, d, len| { s.pio_data = p_u8(d, len, 0, 2); };
        15, mirror_x, u8, 1 => |s, d, len| { s.mirror_x = p_u8(d, len, 0, 1); };
        16, refresh_mhz, u32, REFRESH_MHZ_DEFAULT
            => |s, d, len| { s.refresh_mhz = p_u32(d, len, 0, REFRESH_MHZ_DEFAULT); };
        17, pclk_max_khz, u32, PCLK_MAX_KHZ_DEFAULT
            => |s, d, len| { s.pclk_max_khz = p_u32(d, len, 0, PCLK_MAX_KHZ_DEFAULT); };
        18, band_rows, u16, BAND_ROWS_DEFAULT
            => |s, d, len| { s.band_rows = p_u16(d, len, 0, BAND_ROWS_DEFAULT); };
        19, ring_rows, u16, RING_ROWS_DEFAULT
            => |s, d, len| { s.ring_rows = p_u16(d, len, 0, RING_ROWS_DEFAULT); };
        20, frame_bytes, u32, FRAME_BYTES_DEFAULT
            => |s, d, len| { s.frame_bytes = p_u32(d, len, 0, FRAME_BYTES_DEFAULT); };
        21, resource_bytes, u32, RESOURCE_BYTES_DEFAULT
            => |s, d, len| { s.resource_bytes = p_u32(d, len, 0, RESOURCE_BYTES_DEFAULT); };
        22, record_bytes, u32, RECORD_BYTES_DEFAULT
            => |s, d, len| { s.record_bytes = p_u32(d, len, 0, RECORD_BYTES_DEFAULT); };
        23, surface_bytes, u32, 0 => |s, d, len| { s.surface_bytes = p_u32(d, len, 0, 0); };
        24, underrun_rgb565, u16, 0 => |s, d, len| { s.underrun_rgb565 = p_u16(d, len, 0, 0); };
        25, status_s, u8, 0 => |s, d, len| { s.status_s = p_u8(d, len, 0, 0); };
        26, pack0, str, 0 => |s, d, len| { keep_pack(s, 0, d, len); };
        27, pack1, str, 0 => |s, d, len| { keep_pack(s, 1, d, len); };
        28, pack2, str, 0 => |s, d, len| { keep_pack(s, 2, d, len); };
        29, pack3, str, 0 => |s, d, len| { keep_pack(s, 3, d, len); };
    }
}

fluxor_rt::module_facts! { state: State, arena: ARENA_BASE }

/// Keep the value of `pack<i>`. One too long to be a program reference is
/// kept as its first bytes, which `asset::open` then answers as a path:
/// `module_new` refuses it.
unsafe fn keep_pack(s: &mut State, i: usize, d: *const u8, len: usize) {
    let n = len.min(PACK_PARAM);
    let mut k = 0;
    while k < n {
        s.pack_params[i][k] = *d.add(k);
        k += 1;
    }
    s.pack_lens[i] = n as u8;
}

/// `surface0`, as SURFACE records read it.
struct Rasters<'a>(Option<&'a Input>);

impl Surfaces for Rasters<'_> {
    fn surface(&self, input: u8) -> Option<Texels<'_>> {
        if input != 0 {
            return None;
        }
        self.0?.texels()
    }
}

// ============================================================================
// Log lines
// ============================================================================

/// One log line under construction.
struct Line {
    bytes: [u8; 160],
    len: usize,
}

impl Line {
    fn new(start: &[u8]) -> Line {
        let mut line = Line {
            bytes: [0; 160],
            len: 0,
        };
        line.text(start);
        line
    }

    fn text(&mut self, text: &[u8]) -> &mut Self {
        for &b in text {
            if let Some(slot) = self.bytes.get_mut(self.len) {
                *slot = b;
                self.len += 1;
            }
        }
        self
    }

    fn number(&mut self, value: u32) -> &mut Self {
        let mut digits = [0u8; 10];
        // SAFETY: `fmt_u32_raw` writes at most ten digits.
        let n = unsafe { fmt_u32_raw(digits.as_mut_ptr(), value) };
        let n = n.min(digits.len());
        self.text(&digits[..n])
    }

    unsafe fn send(&self, sys: &SyscallTable, level: u8) {
        dev_log(sys, level, self.bytes.as_ptr(), self.len);
    }
}

unsafe fn refuse(sys: &SyscallTable, why: &[u8]) -> i32 {
    Line::new(b"[st7701s] refusing to construct: ")
        .text(why)
        .send(sys, 1);
    abi::errno::EINVAL
}

// ============================================================================
// Timing
// ============================================================================

/// The sync divider and what it gives.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Timing {
    /// The divider in 1/256, as the PIO's fractional divider steps.
    pub divider_256: u32,
    /// The refresh rate, mHz.
    pub achieved_mhz: u32,
    /// The pixel clock, Hz.
    pub pclk_hz: u32,
    /// The time the scan takes over `band_rows` lines, µs.
    pub band_us: u32,
}

/// Sync cycles of one frame of `width × height` active pixels.
pub const fn frame_cycles(width: u16, height: u16) -> u64 {
    (2 * width as u64 + LINE_BLANK_CYCLES as u64) * (height as u64 + FRAME_BLANK_LINES as u64)
}

/// The divider that brings a `sys_hz` system clock nearest `refresh_mhz`
/// for a `width × height` panel, rounded to the 1/256 step. `None` when
/// the rate is zero or the divider leaves what the PIO holds (1 to 65,535
/// and 255/256).
pub fn timing(
    sys_hz: u32,
    refresh_mhz: u32,
    width: u16,
    height: u16,
    band_rows: u16,
) -> Option<Timing> {
    let cycles = frame_cycles(width, height);
    let wanted = u64::from(refresh_mhz).checked_mul(cycles)?;
    let scaled = u64::from(sys_hz) * 256_000;
    let divider = scaled.checked_add(wanted / 2)?.checked_div(wanted)?;
    if !(256..1 << 24).contains(&divider) {
        return None;
    }
    let achieved = (scaled + divider * cycles / 2).checked_div(divider * cycles)?;
    // Two sync cycles a pixel clock.
    let pclk = (u64::from(sys_hz) * 128).checked_div(divider)?;
    let line_cycles = 2 * u64::from(width) + u64::from(LINE_BLANK_CYCLES);
    let per_us = u64::from(sys_hz) * 256;
    let band = (line_cycles * u64::from(band_rows) * divider * 1_000_000 + per_us / 2)
        .checked_div(per_us)?;
    Some(Timing {
        divider_256: divider as u32,
        achieved_mhz: achieved as u32,
        pclk_hz: pclk as u32,
        band_us: (band as u32).max(1),
    })
}

/// The first GPIO of the 32-pin window that holds the 16 data pins from
/// `data0` and the four control pins from `de`: 0 when every pin is below
/// 32, 16 when every pin is in 16 to 47. `None` when no window holds them.
pub fn gpio_window(data0: u8, de: u8) -> Option<u8> {
    let lowest = data0.min(de);
    let highest = data0.checked_add(15)?.max(de.checked_add(3)?);
    if highest < 32 {
        Some(0)
    } else if lowest >= 16 && highest < 48 {
        Some(16)
    } else {
        None
    }
}

// ============================================================================
// Panel registers: 9-bit SPI through the kernel
// ============================================================================

/// Send one command and its data. With `hold`, chip select stays low after
/// it, as the panel wants across the delay that follows SLEEP_OUT and
/// DISPLAY_ON.
unsafe fn spi9_send(s: &State, cmd: u8, data: &[u8], hold: bool) {
    let sys = &*s.syscalls;
    let mut arg = [0u8; 6 + init_seq::MAX_DATA];
    arg[0] = s.cs_pin;
    arg[1] = s.sck_pin;
    arg[2] = s.sda_pin;
    arg[3] = cmd;
    let n = data.len().min(init_seq::MAX_DATA);
    arg[4] = n as u8;
    for (dst, src) in arg[5..].iter_mut().zip(data.iter().take(n)) {
        *dst = *src;
    }
    let mut total = 5 + n;
    if hold {
        arg[total] = 1;
        total += 1;
    }
    (sys.provider_call)(
        -1,
        abi::registry::rp_raw::SPI9_SEND,
        arg.as_mut_ptr(),
        total,
        core::ptr::null_mut(),
        0,
    );
}

unsafe fn spi9_reset(s: &State) {
    let sys = &*s.syscalls;
    let mut arg = [s.rst_pin, s.cs_pin, s.sck_pin, s.sda_pin];
    (sys.provider_call)(
        -1,
        abi::registry::rp_raw::SPI9_RESET,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    );
}

unsafe fn spi9_cs(s: &State, level: u8) {
    let sys = &*s.syscalls;
    let mut arg = [s.cs_pin, level];
    (sys.provider_call)(
        -1,
        abi::registry::rp_raw::SPI9_CS_SET,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    );
}

// ============================================================================
// GPIO and timer
// ============================================================================

unsafe fn gpio_output(sys: &SyscallTable, pin: u8) -> i32 {
    let mut arg = [pin];
    (sys.provider_open)(
        abi::registry::gpio::ID as u32,
        abi::registry::gpio::SET_OUTPUT,
        arg.as_mut_ptr(),
        1,
    )
}

unsafe fn gpio_set(sys: &SyscallTable, handle: i32, level: u8) {
    let mut arg = [level];
    (sys.provider_call)(
        handle,
        abi::registry::gpio::SET_LEVEL,
        arg.as_mut_ptr(),
        1,
        core::ptr::null_mut(),
        0,
    );
}

unsafe fn timer_set(sys: &SyscallTable, timer_fd: i32, delay_ms: u32) {
    let mut ms = delay_ms.to_le_bytes();
    (sys.provider_call)(
        timer_fd,
        abi::registry::timer::SET,
        ms.as_mut_ptr(),
        4,
        core::ptr::null_mut(),
        0,
    );
}

unsafe fn timer_expired(sys: &SyscallTable, timer_fd: i32) -> bool {
    dev_fd_poll(sys, timer_fd, POLL_IN) & (POLL_IN as i32) != 0
}

// ============================================================================
// PIO
// ============================================================================

/// One call on PIO block `pio`'s raw claim.
unsafe fn pio_call(sys: &SyscallTable, pio: u8, op: u32, arg: &mut [u8]) -> i32 {
    (sys.provider_call)(
        dev_raw_claim(sys, abi::platform::rp::raw_claim::family::PIO, pio),
        op,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    )
}

unsafe fn pio_write_reg(sys: &SyscallTable, pio: u8, sm: u8, reg: u8, value: u32) {
    let v = value.to_le_bytes();
    let mut arg = [pio, sm, reg, v[0], v[1], v[2], v[3]];
    pio_call(sys, pio, abi::registry::rp_raw::PIO_SM_WRITE_REG, &mut arg);
}

unsafe fn pio_enable(sys: &SyscallTable, pio: u8, mask: u8, enable: bool) {
    let mut arg = [pio, mask, enable as u8];
    pio_call(sys, pio, abi::registry::rp_raw::PIO_SM_ENABLE, &mut arg);
}

unsafe fn pio_restart(sys: &SyscallTable, pio: u8, mask: u8) {
    let mut arg = [pio, mask];
    pio_call(sys, pio, abi::registry::rp_raw::PIO_SM_RESTART, &mut arg);
}

unsafe fn pio_exec(sys: &SyscallTable, pio: u8, sm: u8, instr: u16) {
    let i = instr.to_le_bytes();
    let mut arg = [pio, sm, i[0], i[1]];
    pio_call(sys, pio, abi::registry::rp_raw::PIO_SM_EXEC, &mut arg);
}

unsafe fn pio_push(sys: &SyscallTable, pio: u8, sm: u8, value: u32) {
    let v = value.to_le_bytes();
    let mut arg = [pio, sm, v[0], v[1], v[2], v[3]];
    pio_call(sys, pio, abi::registry::rp_raw::PIO_TXF_WRITE, &mut arg);
}

unsafe fn pio_pin(sys: &SyscallTable, pin: u8, pio: u8, pull: u8) {
    let mut arg = [pin, pio, pull];
    pio_call(sys, pio, abi::registry::rp_raw::PIO_PIN_SETUP, &mut arg);
}

/// Load `program` into block `pio`: its origin, or the kernel's errno. A
/// JMP's target (the low five bits of an instruction whose top three are
/// zero) is moved by the origin.
unsafe fn pio_load(sys: &SyscallTable, pio: u8, program: &[u16]) -> i32 {
    let mut arg = [pio, program.len() as u8, 0, 0, 0, 0];
    let origin = pio_call(sys, pio, abi::registry::rp_raw::PIO_INSTR_ALLOC, &mut arg);
    if origin < 0 {
        return origin;
    }
    for (i, instr) in program.iter().enumerate() {
        let placed = if instr >> 13 == 0 {
            (instr & !0x1F) | ((instr & 0x1F) + origin as u16) & 0x1F
        } else {
            *instr
        };
        let b = placed.to_le_bytes();
        let mut arg = [pio, origin as u8 + i as u8, b[0], b[1]];
        pio_call(sys, pio, abi::registry::rp_raw::PIO_INSTR_WRITE, &mut arg);
    }
    origin
}

/// `EXECCTRL`: the wrap addresses, with the optional side-set enable the
/// sync and DE programs use.
const fn execctrl(wrap_bottom: u8, wrap_top: u8, side_enable: bool) -> u32 {
    ((wrap_bottom as u32 & 0x1F) << 7)
        | ((wrap_top as u32 & 0x1F) << 12)
        | ((side_enable as u32) << 30)
}

/// The `PINCTRL` fields one state machine is configured with. Pins are
/// counted from the block's GPIO base.
#[derive(Clone, Copy)]
struct Pins {
    out_base: u8,
    out_count: u8,
    set_base: u8,
    set_count: u8,
    side_base: u8,
    side_count: u8,
    in_base: u8,
}

impl Pins {
    const NONE: Pins = Pins {
        out_base: 0,
        out_count: 0,
        set_base: 0,
        set_count: 0,
        side_base: 0,
        side_count: 0,
        in_base: 0,
    };

    const fn word(self) -> u32 {
        (self.out_base as u32 & 0x1F)
            | ((self.set_base as u32 & 0x1F) << 5)
            | ((self.side_base as u32 & 0x1F) << 10)
            | ((self.in_base as u32 & 0x1F) << 15)
            | ((self.out_count as u32 & 0x3F) << 20)
            | ((self.set_count as u32 & 0x07) << 26)
            | ((self.side_count as u32 & 0x07) << 29)
    }
}

/// Make `count` pins from `base` outputs of state machine `sm`, five at a
/// time (what one `set` reaches), then leave the machine with `pins`.
unsafe fn pio_outputs(sys: &SyscallTable, pio: u8, sm: u8, base: u8, count: u8, pins: Pins) {
    let mut done = 0u8;
    while done < count {
        let n = (count - done).min(5);
        let set = Pins {
            set_base: base + done,
            set_count: n,
            ..pins
        };
        pio_write_reg(sys, pio, sm, REG_PINCTRL, set.word());
        pio_exec(sys, pio, sm, set_pindirs((1u8 << n) - 1));
        done += n;
    }
    pio_write_reg(sys, pio, sm, REG_PINCTRL, pins.word());
}

/// Configure one state machine: its program's wrap, its pins, its divider.
#[allow(
    clippy::too_many_arguments,
    reason = "one state machine's whole configuration, written once for each of the four"
)]
unsafe fn pio_machine(
    sys: &SyscallTable,
    pio: u8,
    sm: u8,
    origin: u8,
    wrap: (u8, u8),
    side_enable: bool,
    pins: Pins,
    clkdiv: u32,
) {
    pio_write_reg(
        sys,
        pio,
        sm,
        REG_EXECCTRL,
        execctrl(origin + wrap.0, origin + wrap.1, side_enable),
    );
    pio_write_reg(sys, pio, sm, REG_PINCTRL, pins.word());
    pio_write_reg(sys, pio, sm, REG_CLKDIV, clkdiv);
    pio_write_reg(sys, pio, sm, REG_SHIFTCTRL, SHIFTCTRL_JOIN_TX);
}

// ============================================================================
// Construction
// ============================================================================

/// `n` rounded up to the alignment every part of the heap block starts on.
const fn aligned(n: usize) -> usize {
    (n + 7) & !7
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
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
    if syscalls.is_null() || state.is_null() {
        return abi::errno::EINVAL;
    }
    if state_size < core::mem::size_of::<State>() {
        return abi::errno::ENOMEM;
    }
    core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
    // The tables the rasteriser borrows are reached through `me`: they live
    // as long as the instance, not as long as this call's `s`.
    let me = state as *mut State;
    let s = &mut *me;
    s.syscalls = syscalls as *const SyscallTable;
    let sys = &*s.syscalls;
    if !params.is_null() && params_len > 0 {
        params_def::parse_tlv(s, params, params_len);
    } else {
        params_def::set_defaults(s);
    }
    s.draw = in_chan;
    s.timer_fd = -1;
    s.bl_handle = -1;
    s.dma_fd = -1;

    // Geometry.
    if s.width == 0 || s.width > MAX_WIDTH || s.height == 0 {
        return refuse(sys, b"width is 1 to 480 and height at least 1");
    }
    let bands = u32::from(s.height)
        .checked_div(u32::from(s.band_rows))
        .unwrap_or(0);
    if s.band_rows == 0
        || bands * u32::from(s.band_rows) != u32::from(s.height)
        || bands < MIN_SLOTS as u32
    {
        return refuse(
            sys,
            b"band_rows must divide height into three or more bands",
        );
    }
    let slots = u32::from(s.ring_rows)
        .checked_div(u32::from(s.band_rows))
        .unwrap_or(0);
    if slots * u32::from(s.band_rows) != u32::from(s.ring_rows)
        || slots < MIN_SLOTS as u32
        || slots > MAX_SLOTS as u32
        || slots > bands
    {
        return refuse(
            sys,
            b"ring_rows must be 3 to 32 bands of band_rows, and no more than height",
        );
    }
    if s.frame_bytes == 0 || (s.record_bytes as usize) < vd::HEADER + vd::BORDER_LEN {
        return refuse(
            sys,
            b"frame_bytes must be non-zero and record_bytes at least 84",
        );
    }
    s.bands = bands as u16;
    s.slots = slots as u16;
    s.slot_bytes = u32::from(s.band_rows) * u32::from(s.width) * 2;

    // Pins: 16 data pins in a row, then DE, VSYNC, HSYNC and PCLK in a
    // row, in that order, all inside one 32-pin window.
    if s.vsync_pin != s.de_pin.wrapping_add(1)
        || s.hsync_pin != s.de_pin.wrapping_add(2)
        || s.pclk_pin != s.de_pin.wrapping_add(3)
    {
        return refuse(
            sys,
            b"de_pin, vsync_pin, hsync_pin and pclk_pin must be consecutive, in that order",
        );
    }
    let Some(gpio_base) = gpio_window(s.data0_pin, s.de_pin) else {
        return refuse(
            sys,
            b"the 16 data pins and the four control pins must all lie in GPIO 0-31 or all in 16-47",
        );
    };
    let data_end = u32::from(s.data0_pin) + 16;
    if u32::from(s.de_pin) < data_end && u32::from(s.de_pin) + 4 > u32::from(s.data0_pin) {
        return refuse(sys, b"the control pins overlap the data pins");
    }
    if s.pio_sync > 2 || s.pio_data > 2 || s.pio_sync == s.pio_data {
        return refuse(
            sys,
            b"pio_sync and pio_data must be two different PIO blocks",
        );
    }
    s.gpio_base = gpio_base;

    // Timing.
    let sys_hz = dev_sys_clock_hz(sys);
    let Some(t) = timing(sys_hz, s.refresh_mhz, s.width, s.height, s.band_rows) else {
        return refuse(sys, b"refresh_mhz is outside what the sync divider reaches");
    };
    if u64::from(t.pclk_hz) > u64::from(s.pclk_max_khz) * 1000
        || t.pclk_hz > sys_hz / DATA_CYCLES_PER_PIXEL
    {
        Line::new(b"[st7701s] refusing to construct: refresh_mhz ")
            .number(s.refresh_mhz)
            .text(b" needs a pixel clock of ")
            .number(t.pclk_hz / 1000)
            .text(b" kHz, above pclk_max_khz ")
            .number(s.pclk_max_khz)
            .text(b" or an eighth of the system clock ")
            .number(sys_hz / DATA_CYCLES_PER_PIXEL / 1000)
            .text(b" kHz")
            .send(sys, 1);
        return abi::errno::EINVAL;
    }
    s.divider_256 = t.divider_256;
    s.achieved_mhz = t.achieved_mhz;
    s.band_us = t.band_us;

    // The byte strings RES_REF records resolve against: each `pack` param
    // names a program of this instance, read where the node image holds it.
    let mut held = 0usize;
    for i in 0..PACKS {
        let len = usize::from(s.pack_lens[i]);
        if len == 0 {
            continue;
        }
        let param = s.pack_params[i];
        let Ok(Asset::InPlace(bytes)) = asset::open(sys, &param[..len]) else {
            return refuse(
                sys,
                b"a `pack` param must name an asset the node image keeps readable in place",
            );
        };
        core::ptr::write(
            (&raw mut s.held).cast::<Held<'static>>().add(held),
            Held::new(bytes),
        );
        held += 1;
    }

    // One block from the heap: the read buffer, two retained frames, the
    // resource arena, the scratch band, the ring, and two buffers for
    // `surface0`.
    let scratch_bytes = usize::from(s.band_rows) * usize::from(s.width) * BAND_BPP;
    let ring_bytes = s.slot_bytes as usize * slots as usize;
    let parts = [
        s.record_bytes as usize,
        s.frame_bytes as usize,
        s.frame_bytes as usize,
        s.resource_bytes as usize,
        scratch_bytes,
        ring_bytes,
        s.surface_bytes as usize,
        s.surface_bytes as usize,
    ];
    let mut total = 0usize;
    for part in parts {
        total = total.saturating_add(aligned(part));
    }
    let Ok(total32) = u32::try_from(total) else {
        return abi::errno::ENOMEM;
    };
    let block = (sys.heap_alloc)(total32);
    if block.is_null() {
        Line::new(b"[st7701s] refusing to construct: the heap cannot hold the ")
            .number(total32)
            .text(b" bytes the params size (heap.arena_bytes below what heap_per_param sizes)")
            .send(sys, 1);
        return abi::errno::ENOMEM;
    }
    core::ptr::write_bytes(block, 0, total);
    let mut at = 0usize;
    let mut carve = |len: usize| {
        let p = block.add(at);
        at += aligned(len);
        p
    };
    let carry = carve(parts[0]);
    let frame_a = carve(parts[1]);
    let frame_b = carve(parts[2]);
    let arena = carve(parts[3]);
    s.scratch = carve(parts[4]);
    s.scratch_bytes = scratch_bytes;
    s.ring = carve(parts[5]);
    let surface_chan = dev_channel_port(sys, 0, 1);
    let cap = s.surface_bytes as usize;
    let buffers = if cap == 0 {
        [core::ptr::null_mut(); 2]
    } else {
        [carve(cap), carve(cap)]
    };
    core::ptr::write(
        &raw mut s.surface,
        Some(Input::new(surface_chan, buffers, cap)),
    );

    let limits = vd::Limits {
        ops: vd::OPS_ALL,
        pixmap_formats: (1 << vd::PIXMAP_RGBA8) | (1 << vd::PIXMAP_RGB565),
        glyph_formats: (1 << vd::GLYPH_A1) | (1 << vd::GLYPH_A8),
        max_width: s.width,
        max_height: s.height,
        max_depth: MAX_DEPTH as u8,
        max_resources: MAX_RESOURCES as u16,
        resource_bytes: s.resource_bytes,
        frame_bytes: s.frame_bytes,
        band_rows: 0,
        damage_full: true,
        surfaces: 1,
    };
    // SAFETY: each slice is a distinct part of this instance's state or
    // heap block, both of which live, unmoved, as long as the instance; the
    // state was zeroed above, and each table is filled before it is read.
    let sequence = vd::Sequence::new(limits, &mut (*me).resources, &mut (*me).saves);
    let store = Store::new(
        &mut (*me).store_slots,
        core::slice::from_raw_parts_mut(arena, parts[3]),
        core::slice::from_raw_parts_mut((&raw mut s.held).cast::<Held<'static>>(), held),
    );
    core::ptr::write(
        &raw mut s.ingest,
        Some(Ingest::new(
            sequence,
            store,
            core::slice::from_raw_parts_mut(carry, parts[0]),
            [
                core::slice::from_raw_parts_mut(frame_a, parts[1]),
                core::slice::from_raw_parts_mut(frame_b, parts[2]),
            ],
            Index::new(&mut (*me).index),
        )),
    );
    core::ptr::write(
        &raw mut s.painter,
        Some(Painter::new(&mut (*me).stack, &mut (*me).clips)),
    );
    if s.draw < 0 {
        write_own_frame(s);
    }

    // The panel: reset, registers, SLEEP_OUT.
    s.timer_fd = (sys.provider_open)(
        abi::registry::timer::ID as u32,
        abi::registry::timer::CREATE,
        core::ptr::null_mut(),
        0,
    );
    if s.timer_fd < 0 {
        return s.timer_fd;
    }
    if s.bl_pin != NO_PIN {
        s.bl_handle = gpio_output(sys, s.bl_pin);
        if s.bl_handle < 0 {
            return s.bl_handle;
        }
        // The backlight is active low: dark until the scan runs.
        gpio_set(sys, s.bl_handle, 1);
    }
    spi9_reset(s);
    for i in 0..init_seq::INIT_SEQ_LEN {
        // SAFETY: `i` is inside the table.
        let cmd = &*init_seq::INIT_SEQ.as_ptr().add(i);
        spi9_send(s, cmd.cmd, &cmd.data[..usize::from(cmd.len)], false);
    }
    if s.mirror_x != 0 {
        // Command bank 0, source scan direction reversed, command bank off.
        spi9_send(s, 0xFF, &[0x77, 0x01, 0x00, 0x00, 0x10], false);
        spi9_send(s, 0xC7, &[0x04], false);
        spi9_send(s, 0xFF, &[0x77, 0x01, 0x00, 0x00, 0x00], false);
    }
    spi9_send(s, init_seq::CMD_SLEEP_OUT, &[], true);
    timer_set(sys, s.timer_fd, 120);
    s.phase = Phase::SleepOut;
    0
}

/// The frame drawn when `draw` is not wired: `surface0`, whole, scaled to
/// the panel. A source reaching past the surface is cut to it, so the
/// largest source there is names whatever the surface's extent turns out
/// to be.
fn write_own_frame(s: &mut State) {
    let panel = vd::PRect {
        x: 0,
        y: 0,
        w: s.width,
        h: s.height,
    };
    let records = [
        vd::Record::Frame {
            generation: 0,
            revision: 1,
            damage: panel,
        },
        vd::Record::Surface {
            input: 0,
            filter: vd::FILTER_NEAREST,
            src: vd::PRect {
                x: 0,
                y: 0,
                w: u16::MAX,
                h: u16::MAX,
            },
            dst: vd::Rect {
                x: 0,
                y: 0,
                w: i32::from(s.width) * vd::FX_ONE,
                h: i32::from(s.height) * vd::FX_ONE,
            },
        },
        vd::Record::Commit { revision: 1 },
    ];
    let mut len = 0usize;
    for record in &records {
        let Some(room) = s.own_frame.get_mut(len..) else {
            break;
        };
        if let Some(n) = vd::write(room, record) {
            len += n;
        }
    }
    s.own_frame_len = len;
}

// ============================================================================
// Starting the scan
// ============================================================================

/// Configure the four state machines, start the scan list and release the
/// sync machines. The kernel's errno when a step fails.
unsafe fn start(s: &mut State) -> Result<(), i32> {
    let sys = &*s.syscalls;
    let (sync, data) = (s.pio_sync, s.pio_data);
    let rel = |pin: u8| pin - s.gpio_base;
    let (de, vsync, hsync) = (rel(s.de_pin), rel(s.vsync_pin), rel(s.hsync_pin));
    let data0 = rel(s.data0_pin);
    // The data programs wait on input pins 4 to 7 for DE, VSYNC, HSYNC and
    // PCLK: the input base sits four pins below DE, around the window.
    let in_base = (de + 32 - 4) % 32;

    // Sync block: machine 0 makes HSYNC and, one pin up, the pixel clock;
    // machine 1 makes VSYNC, counting machine 0's lines.
    let mut base = [sync, (s.gpio_base == 16) as u8];
    pio_call(sys, sync, abi::registry::rp_raw::PIO_GPIOBASE, &mut base);
    pio_enable(sys, sync, 0x0F, false);
    let hsync_origin = pio_load(sys, sync, &pio_programs::HSYNC_PROGRAM);
    let vsync_origin = pio_load(sys, sync, &pio_programs::VSYNC_PROGRAM);
    if hsync_origin < 0 || vsync_origin < 0 {
        return Err(hsync_origin.min(vsync_origin));
    }
    let (hsync_origin, vsync_origin) = (hsync_origin as u8, vsync_origin as u8);
    let hsync_pins = Pins {
        side_base: hsync,
        side_count: 3,
        ..Pins::NONE
    };
    let vsync_pins = Pins {
        side_base: vsync,
        side_count: 2,
        ..Pins::NONE
    };
    pio_machine(
        sys,
        sync,
        0,
        hsync_origin,
        (pio_programs::HSYNC_WRAP_TARGET, pio_programs::HSYNC_WRAP),
        pio_programs::HSYNC_SIDESET_OPT,
        hsync_pins,
        s.divider_256 << 8,
    );
    pio_machine(
        sys,
        sync,
        1,
        vsync_origin,
        (pio_programs::VSYNC_WRAP_TARGET, pio_programs::VSYNC_WRAP),
        pio_programs::VSYNC_SIDESET_OPT,
        vsync_pins,
        CLKDIV_ONE,
    );
    pio_pin(sys, s.hsync_pin, sync, 0);
    pio_pin(sys, s.pclk_pin, sync, 0);
    pio_pin(sys, s.vsync_pin, sync, 0);
    pio_outputs(sys, sync, 0, hsync, 2, hsync_pins);
    pio_outputs(sys, sync, 1, vsync, 1, vsync_pins);

    // Data block: machine 0 makes DE from the sync pins; machine 1 puts a
    // pixel on the 16 data pins each pixel clock DE is high.
    let mut base = [data, (s.gpio_base == 16) as u8];
    pio_call(sys, data, abi::registry::rp_raw::PIO_GPIOBASE, &mut base);
    pio_enable(sys, data, 0x0F, false);
    let de_origin = pio_load(sys, data, &pio_programs::RGB_DE_PROGRAM);
    let rgb_origin = pio_load(sys, data, &pio_programs::RGB_PROGRAM);
    if de_origin < 0 || rgb_origin < 0 {
        return Err(de_origin.min(rgb_origin));
    }
    let (de_origin, rgb_origin) = (de_origin as u8, rgb_origin as u8);
    let de_pins = Pins {
        side_base: de,
        side_count: 2,
        in_base,
        ..Pins::NONE
    };
    let rgb_pins = Pins {
        out_base: data0,
        out_count: 16,
        in_base,
        ..Pins::NONE
    };
    pio_machine(
        sys,
        data,
        0,
        de_origin,
        (pio_programs::RGB_DE_WRAP_TARGET, pio_programs::RGB_DE_WRAP),
        pio_programs::RGB_DE_SIDESET_OPT,
        de_pins,
        CLKDIV_ONE,
    );
    pio_machine(
        sys,
        data,
        1,
        rgb_origin,
        (pio_programs::RGB_WRAP_TARGET, pio_programs::RGB_WRAP),
        false,
        rgb_pins,
        CLKDIV_ONE,
    );
    for i in 0..16 {
        pio_pin(sys, s.data0_pin + i, data, 2);
    }
    pio_pin(sys, s.de_pin, data, 0);
    pio_outputs(sys, data, 1, data0, 16, rgb_pins);
    pio_outputs(sys, data, 0, de, 1, de_pins);

    // Each program begins by pulling one word: the HSYNC and pixel
    // machines the width less one, the VSYNC and DE machines the height
    // less one.
    for (pio, origins) in [
        (sync, [hsync_origin, vsync_origin]),
        (data, [de_origin, rgb_origin]),
    ] {
        pio_restart(sys, pio, 0x03);
        pio_exec(sys, pio, 0, u16::from(origins[0]));
        pio_exec(sys, pio, 1, u16::from(origins[1]));
    }
    pio_push(sys, sync, 0, u32::from(s.width) - 1);
    pio_push(sys, sync, 1, u32::from(s.height) - 1);
    pio_push(sys, data, 0, u32::from(s.height) - 1);
    pio_push(sys, data, 1, u32::from(s.width) - 1);

    // The data machines run first and take their words, so the FIFO the
    // list fills holds pixels only; then the list, every entry fill; then
    // the sync machines, whose first frame the list is waiting for.
    pio_enable(sys, data, 0x03, true);
    let fd = (sys.provider_open)(
        abi::registry::platform_dma_fd::ID as u32,
        dma_fd::CREATE,
        core::ptr::null(),
        0,
    );
    if fd < 0 {
        return Err(fd);
    }
    s.dma_fd = fd;
    let ring_bytes = s.slot_bytes as usize * usize::from(s.slots);
    let lent = dev_lend_open(sys, fd, LEND_IN, RING_LEND, s.ring, ring_bytes);
    if lent < 0 {
        return Err(lent);
    }
    // The pixel machine's TX FIFO: machine 1 of the data block.
    let dreq = data * 8 + 1;
    let mut arg = dma_raw::list_start::encode(
        RING_LEND,
        s.bands,
        dreq,
        dma_raw::flags::SIZE_HALF,
        u32::from(s.underrun_rgb565),
        s.slot_bytes / 2,
    );
    let rc = (sys.provider_call)(
        fd,
        dma_fd::LIST_START,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    );
    if rc < 0 {
        return Err(rc);
    }
    pio_enable(sys, sync, 0x03, true);
    if s.bl_handle >= 0 {
        gpio_set(sys, s.bl_handle, 0);
    }

    s.next = UNARMABLE_AT_START;
    s.next_entry = UNARMABLE_AT_START as u16;
    s.first_of_refresh = true;
    s.status_at_us = dev_micros(sys);
    Line::new(b"[st7701s] scanning ")
        .number(u32::from(s.width))
        .text(b"x")
        .number(u32::from(s.height))
        .text(b" refresh_mhz=")
        .number(s.achieved_mhz)
        .text(b" divider=")
        .number(s.divider_256 >> 8)
        .text(b"+")
        .number(s.divider_256 & 0xFF)
        .text(b"/256 bands=")
        .number(u32::from(s.bands))
        .text(b" band_us=")
        .number(s.band_us)
        .text(b" ring=")
        .number(u32::from(s.slots))
        .text(b" gpio_base=")
        .number(u32::from(s.gpio_base))
        .send(sys, 3);
    Ok(())
}

// ============================================================================
// Running
// ============================================================================

/// Read how far the scan has run.
unsafe fn read_scan(s: &mut State) {
    let sys = &*s.syscalls;
    let mut status = [0u8; dma_raw::list_status::LEN];
    let rc = (sys.provider_call)(
        s.dma_fd,
        dma_fd::LIST_STATUS,
        status.as_mut_ptr(),
        status.len(),
        core::ptr::null_mut(),
        0,
    );
    let Some((position, underruns)) = (rc >= 0)
        .then(|| dma_raw::list_status::decode(&status))
        .flatten()
    else {
        return;
    };
    let passed = position.wrapping_sub(s.sent);
    s.sent = position;
    s.list_underruns = underruns;
    if !s.past_start && s.sent >= UNARMABLE_AT_START {
        s.past_start = true;
    }
    let bands = u32::from(s.bands);
    let entry = u32::from(s.sent_entry) + passed % bands.max(1);
    s.refreshes = s
        .refreshes
        .wrapping_add(passed.checked_div(bands).unwrap_or(0))
        .wrapping_add((entry >= bands) as u32);
    s.sent_entry = (if entry >= bands { entry - bands } else { entry }) as u16;
}

/// Bands that went out as fill after a renderer could have armed them: a
/// wrapping count, as the list's is.
fn underruns(s: &State) -> u32 {
    let unarmable = if s.past_start {
        UNARMABLE_AT_START
    } else {
        s.sent.min(UNARMABLE_AT_START).min(s.list_underruns)
    };
    s.list_underruns.wrapping_sub(unarmable)
}

/// Take records from `draw` until the buffered bytes end or a frame
/// commits.
unsafe fn read_draw(s: &mut State) {
    let sys = &*s.syscalls;
    let Some(ingest) = s.ingest.as_mut() else {
        return;
    };
    // No stream is taken until every held byte string has its digest.
    if s.draw < 0 || !ingest.prepare(HASH_BYTES_PER_STEP) {
        return;
    }
    let space = ingest.space();
    if !space.is_empty() {
        let n = (sys.channel_read)(s.draw, space.as_mut_ptr(), space.len());
        if n > 0 {
            ingest.filled(n as usize);
        }
    }
    loop {
        match ingest.advance() {
            Event::NeedMore => return,
            Event::Ended | Event::Opened => {}
            Event::Faulted { fault, offset } => {
                Line::new(b"[st7701s] stream refused: ")
                    .text(raster::fault_text(fault))
                    .text(b" at byte ")
                    .number(offset.min(u64::from(u32::MAX)) as u32)
                    .send(sys, 1);
            }
            Event::Committed => {
                if !s.frame_waiting {
                    s.frame_waiting = true;
                    s.committed_at = s.next;
                }
                return;
            }
        }
    }
}

/// Move the renderer `count` bands on.
fn advance(s: &mut State, count: u32) {
    let bands = u32::from(s.bands).max(1);
    s.next = s.next.wrapping_add(count);
    let entry = u32::from(s.next_entry) + count % bands;
    if entry >= bands || count >= bands {
        s.first_of_refresh = true;
    }
    s.next_entry = (if entry >= bands { entry - bands } else { entry }) as u16;
    s.band_cost_us = 0;
}

/// What the first band of a refresh starts with: the mean cost of the
/// refresh before, the frame that committed, the raster frame that is
/// ready. A refresh shows one frame.
unsafe fn begin_refresh(s: &mut State) {
    if let Some(mean) = s.refresh_cost_us.checked_div(s.refresh_bands) {
        s.render_us_per_band = mean;
    }
    s.refresh_cost_us = 0;
    s.refresh_bands = 0;
    if s.frame_waiting {
        s.frame_waiting = false;
        if s.next.wrapping_sub(s.committed_at) > u32::from(s.bands) {
            s.late_frames = s.late_frames.wrapping_add(1);
        }
        if let (Some(ingest), Some(painter)) = (s.ingest.as_mut(), s.painter.as_mut()) {
            ingest.present(painter);
        }
    }
    if let Some(surface) = s.surface.as_mut() {
        surface.commit();
    }
}

/// Draw band `next` into the scratch.
unsafe fn draw_band(s: &mut State) {
    let region = vd::PRect {
        x: 0,
        y: s.next_entry * s.band_rows,
        w: s.width,
        h: s.band_rows,
    };
    let own = Index::new(&mut []);
    let (Some(ingest), Some(painter)) = (s.ingest.as_ref(), s.painter.as_mut()) else {
        s.black = true;
        return;
    };
    let surfaces = Rasters(s.surface.as_ref());
    let retained = if s.draw < 0 {
        // Nothing to show before the surface has a frame.
        surfaces
            .surface(0)
            .and(s.own_frame.get(..s.own_frame_len))
            .map(|frame| (frame, &own))
    } else {
        ingest.frame()
    };
    let Some((frame, index)) = retained else {
        s.black = true;
        return;
    };
    s.black = false;
    let pixels = core::slice::from_raw_parts_mut(s.scratch, s.scratch_bytes);
    let Some(mut band) = Band::new(pixels, region) else {
        s.black = true;
        return;
    };
    // A band the frame's first operation paints whole needs no black
    // under it.
    let painted = index
        .backdrop()
        .is_some_and(|d| raster::intersect(d, region) == Some(region));
    if !painted {
        band.clear();
    }
    raster::replay(frame, index, painter, &mut band, ingest.store(), &surfaces);
}

/// Convert the scratch into ring slot `slot`, or black it.
unsafe fn fill_slot(s: &mut State, slot: usize) {
    let bytes = s.slot_bytes as usize;
    let out = core::slice::from_raw_parts_mut(s.ring.add(slot * bytes), bytes);
    if s.black {
        out.fill(0);
        return;
    }
    let region = vd::PRect {
        x: 0,
        y: s.next_entry * s.band_rows,
        w: s.width,
        h: s.band_rows,
    };
    let pixels = core::slice::from_raw_parts_mut(s.scratch, s.scratch_bytes);
    let Some(band) = Band::new(pixels, region) else {
        out.fill(0);
        return;
    };
    let row_bytes = usize::from(s.width) * 2;
    for i in 0..usize::from(s.band_rows) {
        if let Some(row) = out.get_mut(i * row_bytes..(i + 1) * row_bytes) {
            band.row_rgb565(i32::from(region.y) + i as i32, row);
        }
    }
}

/// One piece of drawing: whether there may be another to do at once.
unsafe fn render(s: &mut State) -> Result<bool, i32> {
    let sys = &*s.syscalls;
    let ahead = s.next.wrapping_sub(s.sent) as i32;
    if !s.drawn {
        if ahead < ARM_LEAD {
            // The scan has caught the renderer. It does not chase: it
            // resumes at the first band it can still finish, one past the
            // nearest it could arm for each band period a band has been
            // costing.
            let lead = 1 + s.last_band_us / s.band_us.max(1);
            let lead = lead.min(u32::from(s.bands)) as i32;
            advance(s, (ARM_LEAD + lead - ahead) as u32);
        }
        if s.first_of_refresh {
            s.first_of_refresh = false;
            begin_refresh(s);
        }
        let began = dev_micros(sys);
        draw_band(s);
        s.band_cost_us = dev_micros(sys).wrapping_sub(began) as u32;
        s.drawn = true;
        return Ok(true);
    }
    if ahead < ARM_LEAD {
        // Drawn too late to arm: it goes out as fill.
        s.last_band_us = s.band_cost_us.max(s.band_us);
        s.drawn = false;
        return Ok(true);
    }
    let slot = usize::from(s.slot_cursor);
    let busy =
        s.slot_armed & (1 << slot) != 0 && (s.sent.wrapping_sub(s.slot_free_at[slot]) as i32) < 0;
    // Its entry still belongs to the band a refresh earlier until the scan
    // has sent that one.
    if busy || ahead >= i32::from(s.bands) {
        return Ok(false);
    }
    let began = dev_micros(sys);
    fill_slot(s, slot);
    let mut arg = dma_raw::list_arm::encode(s.next_entry, slot as u32 * s.slot_bytes);
    let rc = (sys.provider_call)(
        s.dma_fd,
        dma_fd::LIST_ARM,
        arg.as_mut_ptr(),
        arg.len(),
        core::ptr::null_mut(),
        0,
    );
    let cost = s
        .band_cost_us
        .wrapping_add(dev_micros(sys).wrapping_sub(began) as u32);
    if rc >= 0 {
        s.slot_armed |= 1 << slot;
        s.slot_free_at[slot] = s.next.wrapping_add(1);
        s.slot_cursor = if slot + 1 >= usize::from(s.slots) {
            0
        } else {
            slot as u16 + 1
        };
    } else if rc != abi::errno::EBUSY {
        return Err(rc);
    }
    // Refused as busy, the scan took the entry while the slot was being
    // filled: it goes out as fill, and the slot stays free.
    s.last_band_us = cost;
    s.refresh_cost_us = s.refresh_cost_us.wrapping_add(cost);
    s.refresh_bands += 1;
    s.drawn = false;
    advance(s, 1);
    Ok(true)
}

/// Emit the counters once a second, and the status line every `status_s`.
unsafe fn report(s: &mut State) {
    let sys = &*s.syscalls;
    let now_ms = dev_millis(sys);
    if now_ms.wrapping_sub(s.metrics_at_ms) >= 1000 {
        s.metrics_at_ms = now_ms;
        if dev_telemetry_enabled(sys) {
            let me = dev_self_index(sys);
            if me >= 0 {
                let (me, t) = (me as u16, dev_micros(sys));
                let counter = abi::contracts::telemetry::METRIC_COUNTER;
                let level = abi::contracts::telemetry::METRIC_UPDOWN;
                dev_telemetry_metric(sys, -1, me, t, counter, 0, u64::from(s.refreshes));
                dev_telemetry_metric(sys, -1, me, t, counter, 1, u64::from(underruns(s)));
                dev_telemetry_metric(sys, -1, me, t, counter, 2, u64::from(s.late_frames));
                dev_telemetry_metric(sys, -1, me, t, level, 3, u64::from(s.render_us_per_band));
                dev_telemetry_metric(sys, -1, me, t, level, 4, u64::from(s.achieved_mhz));
            }
        }
    }
    if s.status_s == 0 {
        return;
    }
    let now = dev_micros(sys);
    let elapsed = now.wrapping_sub(s.status_at_us);
    if elapsed < u64::from(s.status_s) * 1_000_000 {
        return;
    }
    // The rate the scan ran at since the last line, from bands sent.
    let bands = u64::from(s.sent.wrapping_sub(s.status_sent));
    let measured = (bands * 1_000_000_000)
        .checked_div(u64::from(s.bands) * elapsed)
        .unwrap_or(0);
    s.status_at_us = now;
    s.status_sent = s.sent;
    Line::new(b"[st7701s] measured_mhz=")
        .number(measured.min(u64::from(u32::MAX)) as u32)
        .text(b" refreshes=")
        .number(s.refreshes)
        .text(b" underruns=")
        .number(underruns(s))
        .text(b" late_frames=")
        .number(s.late_frames)
        .text(b" render_us_per_band=")
        .number(s.render_us_per_band)
        .text(b" band_us=")
        .number(s.band_us)
        .send(sys, 3);
}

unsafe fn fail(s: &mut State, what: &[u8], rc: i32) -> StepReturn {
    Line::new(b"[st7701s] ")
        .text(what)
        .text(b" failed: errno ")
        .number(rc.unsigned_abs())
        .send(&*s.syscalls, 1);
    s.phase = Phase::Failed;
    StepReturn::error(rc)
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
    let s = &mut *(state as *mut State);
    let sys = &*s.syscalls;
    match s.phase {
        Phase::SleepOut => {
            if timer_expired(sys, s.timer_fd) {
                spi9_cs(s, 1);
                spi9_send(s, init_seq::CMD_DISPLAY_ON, &[], true);
                timer_set(sys, s.timer_fd, 120);
                s.phase = Phase::DisplayOn;
            }
            StepReturn::Continue
        }
        Phase::DisplayOn => {
            if timer_expired(sys, s.timer_fd) {
                spi9_cs(s, 1);
                s.phase = Phase::Start;
                return StepReturn::Burst;
            }
            StepReturn::Continue
        }
        Phase::Start => match start(s) {
            Ok(()) => {
                s.phase = Phase::Run;
                StepReturn::Burst
            }
            Err(rc) if rc == abi::errno::ENOMEM => fail(
                s,
                b"starting the scan (no DMA channel is free, or the kernel's list table has no room for this many bands)",
                rc,
            ),
            Err(rc) => fail(s, b"starting the scan", rc),
        },
        Phase::Run => {
            read_scan(s);
            if let Some(surface) = s.surface.as_mut() {
                surface.pump(sys, INPUT_BYTES_PER_STEP);
            }
            read_draw(s);
            let more = match render(s) {
                Ok(more) => more,
                Err(rc) => return fail(s, b"arming a band", rc),
            };
            report(s);
            if more {
                StepReturn::Burst
            } else {
                StepReturn::Continue
            }
        }
        Phase::Failed => StepReturn::error(abi::errno::EIO),
    }
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

fluxor_rt::wasm_entry!();
