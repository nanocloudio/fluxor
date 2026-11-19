//! RP boot configuration: the platform's hardware section (`HWRP`) of the
//! boot blob, graph flash-slot selection, and the boot-time resource planner.
//!
//! The planner reads a `HardwareConfig`, validates pin conflicts across
//! SPI/I2C/PIO/GPIO, and produces a ResourcePlan consumed by main.rs init
//! code. Pure function: no side effects, no hardware access.

use crate::kernel::boot::config::{
    FlashLayout, GpioConfig, GpioDirection, GpioLevel, GpioPull, MAX_I2C_BUSES, MAX_SPI_BUSES,
};

// ============================================================================
// Hardware section (HWRP)
// ============================================================================

/// SPI bus configuration
#[derive(Debug, Clone, Copy)]
pub struct SpiConfig {
    /// SPI bus number (0 or 1)
    pub bus: u8,
    /// MISO pin number
    pub miso: u8,
    /// MOSI pin number
    pub mosi: u8,
    /// SCK pin number
    pub sck: u8,
    /// Initial frequency in Hz
    pub freq_hz: u32,
}

/// I2C bus configuration
#[derive(Debug, Clone, Copy)]
pub struct I2cConfig {
    /// I2C bus number (0 or 1)
    pub bus: u8,
    /// SDA pin number
    pub sda: u8,
    /// SCL pin number
    pub scl: u8,
    /// Frequency in Hz
    pub freq_hz: u32,
}

/// UART bus configuration
#[derive(Debug, Clone, Copy)]
pub struct UartConfig {
    /// UART bus number (0 or 1)
    pub bus: u8,
    /// TX pin number
    pub tx_pin: u8,
    /// RX pin number
    pub rx_pin: u8,
    /// Baud rate
    pub baudrate: u32,
}

/// PIO instance configuration
///
/// Each PIO config describes one PIO instance's pin wiring.
/// - For cmd mode (bidirectional gSPI): data_pin=DIO, clk_pin=CLK, extra_pin=0xFF
/// - For stream mode (I2S): data_pin=DOUT, clk_pin=BCLK, extra_pin=LRCLK
#[derive(Debug, Clone, Copy)]
pub struct PioConfig {
    /// PIO block index (0, 1, or 2 on RP2350B)
    pub pio_idx: u8,
    /// Primary data pin
    pub data_pin: u8,
    /// Clock / sideset-base pin
    pub clk_pin: u8,
    /// Extra pin (LRCLK for I2S, 0xFF if unused)
    pub extra_pin: u8,
}

/// Maximum number of PIO instances (RP2350B has 3 PIO blocks)
pub const MAX_PIO_CONFIGS: usize = 3;
/// Maximum number of UART buses
pub const MAX_UART_BUSES: usize = 2;
/// Maximum number of GPIO pins that can be configured
pub const MAX_GPIO_CONFIGS: usize = 8;

/// The part's GPIO count when the hardware section states none (RP2350A, RP2040).
const DEFAULT_MAX_GPIO: u8 = 30;

/// Hardware configuration - describes all hardware resources
#[derive(Debug, Clone)]
pub struct HardwareConfig {
    /// SPI bus configurations
    pub spi: [Option<SpiConfig>; MAX_SPI_BUSES],
    /// I2C bus configurations
    pub i2c: [Option<I2cConfig>; MAX_I2C_BUSES],
    /// UART bus configurations
    pub uart: [Option<UartConfig>; MAX_UART_BUSES],
    /// PIO instance configurations (index 0 = cmd, index 1 = stream)
    pub pio: [Option<PioConfig>; MAX_PIO_CONFIGS],
    /// GPIO pin configurations
    pub gpio: [Option<GpioConfig>; MAX_GPIO_CONFIGS],
    /// Maximum GPIO pin count from target (e.g. 30 for RP2350A, 48 for RP2350B)
    pub max_gpio: u8,
}

impl Default for HardwareConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareConfig {
    /// Create an empty hardware configuration
    pub const fn new() -> Self {
        Self {
            spi: [None; MAX_SPI_BUSES],
            i2c: [None; MAX_I2C_BUSES],
            uart: [None; MAX_UART_BUSES],
            pio: [None; MAX_PIO_CONFIGS],
            gpio: [None; MAX_GPIO_CONFIGS],
            max_gpio: DEFAULT_MAX_GPIO,
        }
    }
}

/// Bytes of the hardware payload's counts header.
const HW_HEADER_LEN: usize = 6;
const SPI_RECORD_LEN: usize = 8;
const I2C_RECORD_LEN: usize = 8;
const UART_RECORD_LEN: usize = 8;
const GPIO_RECORD_LEN: usize = 5;
const PIO_RECORD_LEN: usize = 4;

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Decode the boot blob's `HWRP` payload. Little-endian:
///
/// ```text
/// spi_count u8 | i2c_count u8 | gpio_count u8 | pio_count u8 | max_gpio u8 | uart_count u8
/// spi  × spi_count:   bus u8 | miso u8 | mosi u8 | sck u8 | freq_hz u32
/// i2c  × i2c_count:   bus u8 | sda u8 | scl u8 | 0 u8 | freq_hz u32
/// uart × uart_count:  bus u8 | tx_pin u8 | rx_pin u8 | 0 u8 | baudrate u32
/// gpio × gpio_count:  pin u8 | flags u8 | initial u8 | owner_module_id u16
///                     flags: bit 0 direction (1 = out), bits 1-2 pull (1 up, 2 down)
///                     owner_module_id: 0xFFFF = kernel-owned
/// pio  × pio_count:   pio_idx u8 | data_pin u8 | clk_pin u8 | extra_pin u8 (0xFF unused)
/// ```
///
/// `max_gpio` 0 states the default part (30 pins). A count past its table
/// (`MAX_SPI_BUSES`, …) or a payload whose length disagrees with its counts
/// refuses the section, and with it the blob: nothing is clamped.
///
/// # Errors
/// The limit or the length rule the payload breaks.
pub fn decode_hardware(p: &[u8]) -> Result<HardwareConfig, &'static str> {
    if p.len() < HW_HEADER_LEN {
        return Err("shorter than its counts header");
    }
    let (spi_n, i2c_n, gpio_n, pio_n, max_gpio, uart_n) = (
        usize::from(p[0]),
        usize::from(p[1]),
        usize::from(p[2]),
        usize::from(p[3]),
        p[4],
        usize::from(p[5]),
    );
    if spi_n > MAX_SPI_BUSES {
        return Err("spi count exceeds MAX_SPI_BUSES");
    }
    if i2c_n > MAX_I2C_BUSES {
        return Err("i2c count exceeds MAX_I2C_BUSES");
    }
    if gpio_n > MAX_GPIO_CONFIGS {
        return Err("gpio count exceeds MAX_GPIO_CONFIGS");
    }
    if pio_n > MAX_PIO_CONFIGS {
        return Err("pio count exceeds MAX_PIO_CONFIGS");
    }
    if uart_n > MAX_UART_BUSES {
        return Err("uart count exceeds MAX_UART_BUSES");
    }
    let want = HW_HEADER_LEN
        + spi_n * SPI_RECORD_LEN
        + i2c_n * I2C_RECORD_LEN
        + uart_n * UART_RECORD_LEN
        + gpio_n * GPIO_RECORD_LEN
        + pio_n * PIO_RECORD_LEN;
    if p.len() != want {
        return Err("length disagrees with its counts");
    }

    let mut hw = HardwareConfig::new();
    if max_gpio > 0 {
        hw.max_gpio = max_gpio;
    }
    let mut records = p[HW_HEADER_LEN..].iter().as_slice();
    let mut take = |len: usize| {
        let (r, rest) = records.split_at(len);
        records = rest;
        r
    };
    for slot in hw.spi.iter_mut().take(spi_n) {
        let r = take(SPI_RECORD_LEN);
        *slot = Some(SpiConfig {
            bus: r[0],
            miso: r[1],
            mosi: r[2],
            sck: r[3],
            freq_hz: le32(r, 4),
        });
    }
    for slot in hw.i2c.iter_mut().take(i2c_n) {
        let r = take(I2C_RECORD_LEN);
        *slot = Some(I2cConfig {
            bus: r[0],
            sda: r[1],
            scl: r[2],
            freq_hz: le32(r, 4),
        });
    }
    for slot in hw.uart.iter_mut().take(uart_n) {
        let r = take(UART_RECORD_LEN);
        *slot = Some(UartConfig {
            bus: r[0],
            tx_pin: r[1],
            rx_pin: r[2],
            baudrate: le32(r, 4),
        });
    }
    for slot in hw.gpio.iter_mut().take(gpio_n) {
        let r = take(GPIO_RECORD_LEN);
        let flags = r[1];
        *slot = Some(GpioConfig {
            pin: r[0],
            direction: if flags & 0x01 != 0 {
                GpioDirection::Output
            } else {
                GpioDirection::Input
            },
            pull: match (flags >> 1) & 0x03 {
                1 => GpioPull::Up,
                2 => GpioPull::Down,
                _ => GpioPull::None,
            },
            initial: if r[2] != 0 {
                GpioLevel::High
            } else {
                GpioLevel::Low
            },
            owner_module_id: le16(r, 3),
        });
    }
    for slot in hw.pio.iter_mut().take(pio_n) {
        let r = take(PIO_RECORD_LEN);
        *slot = Some(PioConfig {
            pio_idx: r[0],
            data_pin: r[1],
            clk_pin: r[2],
            extra_pin: r[3],
        });
    }
    Ok(hw)
}

/// The hardware section of the boot blob the flash layout points at, `None`
/// when no blob decodes there. The kernel refused a blob without one, or with
/// a malformed one, before anything runs from it.
fn boot_hardware() -> Option<HardwareConfig> {
    let blob = crate::kernel::boot::config::layout_config_window()?;
    let bc = fluxor_contracts::boot_config::decode(blob).ok()?;
    decode_hardware(bc.hardware()?).ok()
}

// ============================================================================
// Graph flash slots
// ============================================================================

/// Bytes the graph image after the kernel may occupy from `at`: the flash
/// below the graph slots, or, on a flash with no room for slots, below the
/// data store.
pub fn firmware_image_window(at: u32) -> u32 {
    use crate::abi::platform::rp::flash_layout;
    let layout = crate::platform::chip::GRAPH_FLASH;
    let below = if layout.slot_size != 0 {
        layout.slot_a
    } else {
        layout.data_store
    };
    (flash_layout::XIP_BASE + below).saturating_sub(at)
}

/// The slots this boot's selector admitted, bit 0 = A, bit 1 = B: what
/// `kernel_abi::SLOT_ADMITTED` answers.
static SLOT_ADMITTED: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

/// The slots this boot's selector admitted, choosing first if boot has not.
pub fn admitted_slots() -> u8 {
    let _ = crate::kernel::boot::config::read_layout();
    SLOT_ADMITTED.load(core::sync::atomic::Ordering::Acquire)
}

/// The graph slot this boot runs: of the slots whose image is admitted
/// (`boot::graph_image::admit`), the higher epoch. `None` when the board has
/// no slots or neither is admissible, and the kernel boots the graph image
/// after itself. Called once per boot, by `boot::config::read_layout`.
pub fn choose_slot(own_pin: &[u8; 32]) -> Option<FlashLayout> {
    use crate::abi::platform::rp::flash_layout;
    let layout = crate::platform::chip::GRAPH_FLASH;
    if layout.slot_size == 0 {
        return None;
    }
    let admit = |offset: u32| {
        let base = flash_layout::XIP_BASE + offset;
        // SAFETY: the slot is this board's XIP-mapped aperture of
        // `slot_size` bytes, mapped for the life of the kernel.
        let slot = unsafe {
            core::slice::from_raw_parts(base as usize as *const u8, layout.slot_size as usize)
        };
        match crate::kernel::boot::graph_image::admit(slot, own_pin) {
            Ok(header) => Some((base, header)),
            Err(crate::kernel::boot::graph_image::Refusal::Malformed(
                crate::abi::wire::graph_image::Malformed::Magic,
            )) => None,
            Err(why) => {
                log::warn!("[boot] slot at 0x{base:08x} refused: {}", why.reason());
                None
            }
        }
    };
    let a = admit(layout.slot_a);
    let b = admit(layout.slot_b);
    SLOT_ADMITTED.store(
        u8::from(a.is_some()) | (u8::from(b.is_some()) << 1),
        core::sync::atomic::Ordering::Release,
    );
    let (base, header) = match (a, b) {
        (Some(a), Some(b)) => {
            if a.1.epoch >= b.1.epoch {
                a
            } else {
                b
            }
        }
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => return None,
    };
    Some(FlashLayout::of(base, &header))
}

// ============================================================================
// Resource planner
// ============================================================================

/// Maximum PIO plan entries (cmd + stream + rx_stream, or up to 3 independent)
pub const MAX_PIO_ENTRIES: usize = 3;

/// PIO role — what a PIO config slot is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PioRole {
    Cmd = 0,
    Stream = 1,
    RxStream = 2,
}

/// Resolved PIO assignment.
#[derive(Debug, Clone, Copy)]
pub struct PioPlanEntry {
    pub pio_idx: u8,
    pub role: PioRole,
    pub dma_ch: u8,
    pub data_pin: u8,
    pub clk_pin: u8,
    pub extra_pin: u8,
}

/// The resolved resource plan.
pub struct ResourcePlan {
    pub spi: [Option<SpiConfig>; MAX_SPI_BUSES],
    pub i2c: [Option<I2cConfig>; MAX_I2C_BUSES],
    pub pio: [Option<PioPlanEntry>; MAX_PIO_ENTRIES],
    pub gpio: [Option<GpioConfig>; MAX_GPIO_CONFIGS],
    pub pin_map: u64,
}

/// Conflict error — halts boot with a clear message.
#[derive(Debug)]
pub enum PlanError {
    PinConflict {
        pin: u8,
        first: &'static str,
        second: &'static str,
    },
    PinOutOfRange {
        pin: u8,
        max: u8,
        label: &'static str,
    },
    InvalidSpiPins {
        bus: u8,
    },
    InvalidI2cPins {
        bus: u8,
    },
    PioConflict {
        pio_idx: u8,
    },
    Pio2OnVariantA,
    DuplicateRole {
        role: u8,
    },
}

/// Per-pin owner tracking for conflict messages.
/// Index = pin number (0..47), value = peripheral label.
struct PinOwners {
    owners: [&'static str; 48],
    max_gpio: u8,
}

impl PinOwners {
    fn new(max_gpio: u8) -> Self {
        Self {
            owners: [""; 48],
            max_gpio,
        }
    }

    fn claim(&mut self, pin: u8, label: &'static str, pin_map: &mut u64) -> Result<(), PlanError> {
        let idx = pin as usize;
        if idx >= 48 {
            return Err(PlanError::PinOutOfRange {
                pin,
                max: self.max_gpio,
                label,
            });
        }
        if pin >= self.max_gpio {
            return Err(PlanError::PinOutOfRange {
                pin,
                max: self.max_gpio,
                label,
            });
        }
        let mask = 1u64 << idx;
        if *pin_map & mask != 0 {
            return Err(PlanError::PinConflict {
                pin,
                first: self.owners[idx],
                second: label,
            });
        }
        *pin_map |= mask;
        self.owners[idx] = label;
        Ok(())
    }
}

/// Valid SPI0 pin combinations (miso, mosi, sck) — all funcsel groups from RP2350 datasheet.
/// B-only pins are included; runtime max_gpio check rejects them on RP2350A.
const SPI0_VALID: &[(u8, u8, u8)] = &[
    (0, 3, 2),
    (4, 7, 6),
    (16, 19, 18),
    (20, 23, 22),
    (32, 35, 34), // B-only
    (36, 39, 38), // B-only
];

/// Valid SPI1 pin combinations (miso, mosi, sck).
const SPI1_VALID: &[(u8, u8, u8)] = &[
    (8, 11, 10),
    (12, 11, 10),
    (12, 15, 14),
    (24, 27, 26),
    (28, 31, 30), // B-only (miso=28 is A, but sck=30/mosi=31 are B)
    (40, 43, 42), // B-only
    (44, 47, 46), // B-only
];

/// Valid I2C0 pin combinations (sda, scl) — every valid funcsel pair.
const I2C0_VALID: &[(u8, u8)] = &[
    (0, 1),
    (4, 5),
    (8, 9),
    (12, 13),
    (16, 17),
    (20, 21),
    (24, 25),
    (28, 29),
    (32, 33), // B-only
    (36, 37), // B-only
    (40, 41), // B-only
    (44, 45), // B-only
];

/// Valid I2C1 pin combinations (sda, scl).
const I2C1_VALID: &[(u8, u8)] = &[
    (2, 3),
    (6, 7),
    (10, 11),
    (14, 15),
    (18, 19),
    (22, 23),
    (26, 27),
    (30, 31), // B-only
    (34, 35), // B-only
    (38, 39), // B-only
    (42, 43), // B-only
    (46, 47), // B-only
];

fn is_valid_spi_pins(bus: u8, miso: u8, mosi: u8, sck: u8) -> bool {
    let table = if bus == 0 { SPI0_VALID } else { SPI1_VALID };
    let mut i = 0;
    while i < table.len() {
        if table[i].0 == miso && table[i].1 == mosi && table[i].2 == sck {
            return true;
        }
        i += 1;
    }
    false
}

fn is_valid_i2c_pins(bus: u8, sda: u8, scl: u8) -> bool {
    let table = if bus == 0 { I2C0_VALID } else { I2C1_VALID };
    let mut i = 0;
    while i < table.len() {
        if table[i].0 == sda && table[i].1 == scl {
            return true;
        }
        i += 1;
    }
    false
}

/// Resolve a HardwareConfig into a validated ResourcePlan.
/// `max_gpio`: runtime pin limit from config target (30 for RP2350A, 48 for RP2350B).
pub fn resolve(hw: &HardwareConfig, max_gpio: u8) -> Result<ResourcePlan, PlanError> {
    let mut pin_map: u64 = 0;
    let mut owners = PinOwners::new(max_gpio);

    let mut plan = ResourcePlan {
        spi: [None; MAX_SPI_BUSES],
        i2c: [None; MAX_I2C_BUSES],
        pio: [None; MAX_PIO_ENTRIES],
        gpio: [None; MAX_GPIO_CONFIGS],
        pin_map: 0,
    };

    // --- SPI buses ---
    let mut i = 0;
    while i < MAX_SPI_BUSES {
        if let Some(spi) = &hw.spi[i] {
            if !is_valid_spi_pins(spi.bus, spi.miso, spi.mosi, spi.sck) {
                return Err(PlanError::InvalidSpiPins { bus: spi.bus });
            }
            let label = if spi.bus == 0 { "spi0" } else { "spi1" };
            owners.claim(spi.miso, label, &mut pin_map)?;
            owners.claim(spi.mosi, label, &mut pin_map)?;
            owners.claim(spi.sck, label, &mut pin_map)?;
            plan.spi[i] = Some(*spi);
        }
        i += 1;
    }

    // --- I2C buses ---
    i = 0;
    while i < MAX_I2C_BUSES {
        if let Some(i2c) = &hw.i2c[i] {
            if !is_valid_i2c_pins(i2c.bus, i2c.sda, i2c.scl) {
                return Err(PlanError::InvalidI2cPins { bus: i2c.bus });
            }
            let label = if i2c.bus == 0 { "i2c0" } else { "i2c1" };
            owners.claim(i2c.sda, label, &mut pin_map)?;
            owners.claim(i2c.scl, label, &mut pin_map)?;
            plan.i2c[i] = Some(*i2c);
        }
        i += 1;
    }

    // --- PIO configs ---
    // Fixed DMA: Cmd→CH0, Stream→CH1, RxStream→CH6
    let pio_count = hw.pio.len().min(MAX_PIO_ENTRIES);
    let mut pio_slot = 0usize;
    i = 0;
    while i < pio_count {
        if let Some(pio) = &hw.pio[i] {
            if pio.pio_idx > 2 {
                return Err(PlanError::PioConflict {
                    pio_idx: pio.pio_idx,
                });
            }
            if pio.pio_idx == 2 && max_gpio < 48 {
                return Err(PlanError::Pio2OnVariantA);
            }
            let role = match i {
                0 => PioRole::Cmd,
                1 => PioRole::Stream,
                _ => PioRole::RxStream,
            };
            let label = match role {
                PioRole::Cmd => "pio_cmd",
                PioRole::Stream => "pio_stream",
                PioRole::RxStream => "pio_rx",
            };
            let dma_ch = match role {
                PioRole::Cmd => 0u8,
                PioRole::Stream => 1u8,
                PioRole::RxStream => 6u8,
            };

            owners.claim(pio.data_pin, label, &mut pin_map)?;
            owners.claim(pio.clk_pin, label, &mut pin_map)?;
            if pio.extra_pin != 0xFF {
                owners.claim(pio.extra_pin, label, &mut pin_map)?;
            }

            plan.pio[pio_slot] = Some(PioPlanEntry {
                pio_idx: pio.pio_idx,
                role,
                dma_ch,
                data_pin: pio.data_pin,
                clk_pin: pio.clk_pin,
                extra_pin: pio.extra_pin,
            });
            pio_slot += 1;
        }
        i += 1;
    }

    // --- PIO role uniqueness ---
    // At most one Cmd and one Stream role across all PIO entries.
    let mut has_cmd = false;
    let mut has_stream = false;
    i = 0;
    while i < MAX_PIO_ENTRIES {
        if let Some(entry) = &plan.pio[i] {
            match entry.role {
                PioRole::Cmd => {
                    if has_cmd {
                        return Err(PlanError::DuplicateRole { role: 0 });
                    }
                    has_cmd = true;
                }
                PioRole::Stream => {
                    if has_stream {
                        return Err(PlanError::DuplicateRole { role: 1 });
                    }
                    has_stream = true;
                }
                PioRole::RxStream => {} // at most one per PIO block (uses SM1)
            }
        }
        i += 1;
    }

    // --- GPIO pins ---
    i = 0;
    while i < MAX_GPIO_CONFIGS {
        if let Some(gpio) = &hw.gpio[i] {
            owners.claim(gpio.pin, "gpio", &mut pin_map)?;
            plan.gpio[i] = Some(*gpio);
        }
        i += 1;
    }

    plan.pin_map = pin_map;
    Ok(plan)
}

/// Log the resolved plan for debugging.
pub fn log_plan(_plan: &ResourcePlan) {}

// ============================================================================
// Hardware Manager (Pico-flavoured defaults)
// ============================================================================
//
// `Hardware::new()` overlays the boot blob's hardware section with Pico
// 2 W defaults (SPI on GPIO 16/19/18, I2C on 20/21, PIO0/1 for cyw43
// gSPI + I2S) when a field is absent.

/// Default SPI configuration (Pico 2 W SD card pins).
pub const DEFAULT_SPI: SpiConfig = SpiConfig {
    bus: 0,
    miso: 16,
    mosi: 19,
    sck: 18,
    freq_hz: 400_000,
};

/// Default I2C configuration (Pico 2 W: I2C0 on GPIO 20/21).
pub const DEFAULT_I2C: I2cConfig = I2cConfig {
    bus: 0,
    sda: 20,
    scl: 21,
    freq_hz: 400_000,
};

/// Default PIO cmd configuration (Pico 2 W: PIO1, cyw43 gSPI DIO=24, CLK=29).
pub const DEFAULT_PIO_CMD: PioConfig = PioConfig {
    pio_idx: 1,
    data_pin: 24,
    clk_pin: 29,
    extra_pin: 0xFF,
};

/// Default PIO stream configuration (Pico 2 W: PIO0, I2S data=28, bclk=26, lrclk=27).
pub const DEFAULT_PIO_STREAM: PioConfig = PioConfig {
    pio_idx: 0,
    data_pin: 28,
    clk_pin: 26,
    extra_pin: 27,
};

/// Hardware manager — RP-platform-specific accessor that overlays the
/// parsed `HardwareConfig` with Pico defaults when no explicit
/// declaration is present. Used only by `src/platform/rp.rs`.
pub struct Hardware {
    config: HardwareConfig,
}

impl Hardware {
    /// Create hardware manager, reading the boot blob's hardware section or
    /// using Pico defaults when no config blob is present.
    pub fn new() -> Self {
        let config = match boot_hardware() {
            Some(mut hw) => {
                if hw.spi[0].is_none() && hw.spi[1].is_none() {
                    hw.spi[0] = Some(DEFAULT_SPI);
                }
                hw
            }
            None => {
                // No config blob — bare firmware boot (Pico 2 W defaults).
                let mut hw = HardwareConfig::new();
                hw.spi[0] = Some(DEFAULT_SPI);
                hw.pio[0] = Some(DEFAULT_PIO_CMD);
                hw.pio[1] = Some(DEFAULT_PIO_STREAM);
                hw
            }
        };
        Self { config }
    }

    /// Get SPI configuration.
    pub fn spi(&self) -> SpiConfig {
        self.config.spi[0]
            .or(self.config.spi[1])
            .unwrap_or(DEFAULT_SPI)
    }

    /// Get SPI bus number.
    pub fn spi_bus(&self) -> u8 {
        self.spi().bus
    }

    /// Get CS pin number (first output GPIO).
    pub fn cs_pin(&self) -> u8 {
        self.config
            .gpio
            .iter()
            .flatten()
            .find(|g| g.direction == GpioDirection::Output)
            .map(|g| g.pin)
            .unwrap_or(17)
    }

    /// Get I2C configuration (first configured bus or default).
    pub fn i2c(&self) -> I2cConfig {
        self.config.i2c[0]
            .or(self.config.i2c[1])
            .unwrap_or(DEFAULT_I2C)
    }

    /// Get PIO cmd configuration (slot 0: bidirectional gSPI for cyw43).
    pub fn pio_cmd(&self) -> PioConfig {
        self.config.pio[0].unwrap_or(DEFAULT_PIO_CMD)
    }

    /// Get PIO stream configuration (slot 1: I2S output).
    pub fn pio_stream(&self) -> PioConfig {
        self.config.pio[1].unwrap_or(DEFAULT_PIO_STREAM)
    }

    /// Get GPIO config for a specific pin.
    pub fn gpio(&self, pin: u8) -> Option<&GpioConfig> {
        self.config.gpio.iter().flatten().find(|g| g.pin == pin)
    }

    /// Get raw GPIO configs.
    pub fn gpio_configs(&self) -> &[Option<GpioConfig>; MAX_GPIO_CONFIGS] {
        &self.config.gpio
    }

    /// Get raw hardware config for the planner.
    pub fn raw_config(&self) -> &HardwareConfig {
        &self.config
    }

    /// Initialize all GPIO pins from config.
    pub fn init_gpio(&self) -> usize {
        (crate::kernel::sys::hal::init_gpio)(&self.config.gpio)
    }
}

impl Default for Hardware {
    fn default() -> Self {
        Self::new()
    }
}
