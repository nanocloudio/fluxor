//! Boot-time resource planner.
//!
//! Reads HardwareConfig, validates pin conflicts across SPI/I2C/PIO/GPIO,
//! and produces a ResourcePlan consumed by main.rs init code.
//! Pure function: no side effects, no hardware access.

use crate::kernel::config::{
    GpioConfig, HardwareConfig, I2cConfig, SpiConfig, MAX_GPIO_CONFIGS, MAX_I2C_BUSES,
    MAX_SPI_BUSES,
};

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
// `Hardware::new()` overlays the parsed `HardwareConfig` with Pico
// 2 W defaults (SPI on GPIO 16/19/18, I2C on 20/21, PIO0/1 for cyw43
// gSPI + I2S) when a field is absent. The defaults are
// RP-platform-specific and live here rather than in the kernel —
// platform-neutral parsing types (`HardwareConfig`, `SpiConfig`, …)
// stay in `kernel::config` so non-RP targets (BCM, Linux, WASM)
// never pick up RP hardware assumptions.

use crate::kernel::config::{self as kernel_config, GpioDirection, PioConfig};

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
    /// Create hardware manager, reading config from flash or using
    /// Pico defaults when no config blob is present.
    pub fn new() -> Self {
        let config = match kernel_config::read_config() {
            Some(c) => {
                let mut hw = c.hardware.clone();
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
    pub fn gpio(&self, pin: u8) -> Option<&crate::kernel::config::GpioConfig> {
        self.config.gpio.iter().flatten().find(|g| g.pin == pin)
    }

    /// Get raw GPIO configs.
    pub fn gpio_configs(&self) -> &[Option<crate::kernel::config::GpioConfig>; MAX_GPIO_CONFIGS] {
        &self.config.gpio
    }

    /// Get raw hardware config for the planner.
    pub fn raw_config(&self) -> &HardwareConfig {
        &self.config
    }

    /// Initialize all GPIO pins from config.
    pub fn init_gpio(&self) -> usize {
        (crate::kernel::hal::init_gpio)(&self.config.gpio)
    }
}

impl Default for Hardware {
    fn default() -> Self {
        Self::new()
    }
}
