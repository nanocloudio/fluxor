//! Pre-assembled PIO instruction words for 4-SM autonomous RGB timing.
//!
//! Ported from Waveshare RP2350-Touch-LCD-4 BSP `pio_rgb.pio`.
//! Two PIO blocks required:
//!   - Sync PIO (default PIO1): hsync SM + vsync SM
//!   - Data PIO (default PIO2): rgb_de SM + rgb SM
//!
//! IRQ coordination:
//!   IRQ 0: rgb → rgb_de (row complete)
//!   IRQ 2: hsync → vsync (line heartbeat)

/// VSYNC program: .side_set 1 opt — drives VSYNC pin.
/// FrontPorch=7+1=8 lines, SyncPulse=2+1=3 lines, BackPorch=17+1=18 lines.
/// Bootstrap: pulls height-1 into OSR (run once before wrap).
pub static VSYNC_PROGRAM: [u16; 14] = [
    0x98A0, // 0: pull block side 1
    0xF827, // 1: set x, 7 side 1         [FrontPorch counter]
    0x38C2, // 2: wait 1 irq 2 side 1     [FrontPorch wait]
    0x1842, // 3: jmp x-- 2 side 1
    0xF022, // 4: set x, 2 side 0         [SyncPulse counter, VSYNC=0]
    0x30C2, // 5: wait 1 irq 2 side 0
    0x1045, // 6: jmp x-- 5 side 0
    0xF831, // 7: set x, 17 side 1        [BackPorch counter, VSYNC=1]
    0x38C2, // 8: wait 1 irq 2 side 1
    0x1848, // 9: jmp x-- 8 side 1
    0xB827, // 10: mov x, osr side 1      [x = height-1]
    0xD801, // 11: irq set 1 side 1       [signal active frame start]
    0x38C2, // 12: wait 1 irq 2 side 1    [ActiveFor wait]
    0x184C, // 13: jmp x-- 12 side 1
];
pub const VSYNC_WRAP_TARGET: u8 = 1;
pub const VSYNC_WRAP: u8 = 13;
pub const VSYNC_SIDESET_BITS: u8 = 1;
pub const VSYNC_SIDESET_OPT: bool = true;

/// HSYNC program: .side_set 2 opt — drives PCLK(bit1) + HSYNC(bit0).
/// FrontPorch=9+1=10 clocks, SyncPulse=7+1=8 clocks, BackPorch=9+1=10 clocks.
/// Bootstrap: pulls width-1 into Y (run once before wrap).
pub static HSYNC_PROGRAM: [u16; 15] = [
    0x80A0, // 0: pull block
    0xA047, // 1: mov y, osr
    0xFC29, // 2: set x, 9 side 0b11      [FP, PCLK=1 HSYNC=1]
    0xB442, // 3: nop side 0b01           [PCLK=0 HSYNC=1]
    0x1C43, // 4: jmp x-- 3 side 0b11
    0xD402, // 5: irq set 2 side 0b01     [line heartbeat, PCLK=0 HSYNC=1]
    0xF827, // 6: set x, 7 side 0b10      [pulse, PCLK=1 HSYNC=0]
    0xB042, // 7: nop side 0b00           [PCLK=0 HSYNC=0]
    0x1847, // 8: jmp x-- 7 side 0b10
    0xF429, // 9: set x, 9 side 0b01      [BP, PCLK=0 HSYNC=1]
    0xBC42, // 10: nop side 0b11          [PCLK=1 HSYNC=1]
    0x144A, // 11: jmp x-- 10 side 0b01
    0xBC22, // 12: mov x, y side 0b11     [x = width-1, active region]
    0xB442, // 13: nop side 0b01          [PCLK=0 HSYNC=1]
    0x1C4D, // 14: jmp x-- 13 side 0b11   [PCLK=1 HSYNC=1]
];
pub const HSYNC_WRAP_TARGET: u8 = 2;
pub const HSYNC_WRAP: u8 = 14;
pub const HSYNC_SIDESET_BITS: u8 = 2;
pub const HSYNC_SIDESET_OPT: bool = true;

/// RGB program: no sideset — outputs 16-bit pixel data.
/// Reads DE (pin 4 relative to GPIOBASE) and PCLK (pin 7).
/// DMA feeds TX FIFO; SM pulls one word per pixel.
/// Bootstrap: pulls width-1 into Y (run once before wrap).
pub static RGB_PROGRAM: [u16; 11] = [
    0x80A0, // 0: pull block
    0xA047, // 1: mov y, osr
    0xB022, // 2: mov x, y               [x = width-1 pixel counter]
    0x20A4, // 3: wait 1 pin 4           [wait DE high]
    0x80A0, // 4: pull block              [fetch pixel from TX FIFO]
    0x2027, // 5: wait 0 pin 7           [wait PCLK low]
    0x6010, // 6: out pins, 16           [drive pixel data]
    0x20A7, // 7: wait 1 pin 7           [wait PCLK high — latch]
    0x0044, // 8: jmp x-- 4              [next pixel]
    0xC000, // 9: irq set 0              [row complete → rgb_de]
    0xA005, // 10: mov pins, null        [clear data pins during blanking]
];
pub const RGB_WRAP_TARGET: u8 = 2;
pub const RGB_WRAP: u8 = 10;
pub const RGB_SIDESET_BITS: u8 = 0;
pub const RGB_SIDESET_OPT: bool = false;

/// RGB_DE program: .side_set 1 opt — drives DE pin.
/// Counts vsync BackPorch (T1=17+1=18 lines) and hsync BackPorch (T2=9+1=10 clocks).
/// Watches VSYNC(pin5), HSYNC(pin6), PCLK(pin7) for synchronization.
/// Bootstrap: pulls height-1 into OSR (run once before wrap).
pub static RGB_DE_PROGRAM: [u16; 17] = [
    0x90A0, // 0: pull block side 0
    0xB047, // 1: mov y, osr side 0      [y = height-1]
    0xF031, // 2: set x, 17 side 0       [vBackPorch counter]
    0x3025, // 3: wait 0 pin 5 side 0    [wait VSYNC low]
    0x30A5, // 4: wait 1 pin 5 side 0    [wait VSYNC high — rising edge]
    0x3026, // 5: wait 0 pin 6 side 0    [vBP: wait HSYNC low]
    0x30A6, // 6: wait 1 pin 6 side 0    [vBP: wait HSYNC high]
    0x1045, // 7: jmp x-- 5 side 0       [vBP: count lines]
    0x3026, // 8: wait 0 pin 6 side 0    [ActiveFor: wait HSYNC low]
    0x30A6, // 9: wait 1 pin 6 side 0    [wait HSYNC high — new line]
    0xF029, // 10: set x, 9 side 0       [hBackPorch counter]
    0x3027, // 11: wait 0 pin 7 side 0   [hBP: wait PCLK low]
    0x30A7, // 12: wait 1 pin 7 side 0   [hBP: wait PCLK high]
    0x104B, // 13: jmp x-- 11 side 0     [hBP: count clocks]
    0x30A7, // 14: wait 1 pin 7 side 0   [timing alignment]
    0x38C0, // 15: wait 1 irq 0 side 1   [DE=1! wait for rgb row-complete]
    0x1088, // 16: jmp y-- 8 side 0      [DE=0, next line]
];
pub const RGB_DE_WRAP_TARGET: u8 = 1;
pub const RGB_DE_WRAP: u8 = 16;
pub const RGB_DE_SIDESET_BITS: u8 = 1;
pub const RGB_DE_SIDESET_OPT: bool = true;
