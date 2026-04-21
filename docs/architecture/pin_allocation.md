# Pin and Bus Allocation

This document describes the config-driven pin and bus allocation system
for Fluxor. The goals are:

1. Represent pin and bus configuration in the graph config
2. Allow the config file to fully describe hardware resource usage
3. Validate configurations against silicon capabilities at build time
4. Initialize buses at runtime based on config, before module instantiation
5. Support SPI, I2C, GPIO, UART, ADC, PWM, PIO resources across silicon families

Hardware config and runtime context live in `src/kernel/config.rs`
(`HardwareConfig`, `HardwareContext`). Boot-time pin/bus conflict
planning lives in `src/kernel/planner.rs`. The scheduler validates
hardware requirements before graph start, and SPI bus initialization
state is tracked and enforced before module use.

The silicon capabilities themselves come from `targets/silicon/*.toml`,
which the config tool reads at validation time and the kernel build
script reads at compile time. Adding support for a new silicon target
means writing a TOML file that describes its peripherals and a HAL
backend that implements the bus primitives — see
[hal_architecture.md](hal_architecture.md).

## Resource Ownership Discipline

Hardware resource ownership is explicit and declared, not opportunistic:

- Pin and bus assignments are configuration-defined and validated before runtime.
- Runtime code does not use "grab any free pin/bus" patterns.
- Conflicts are resolved through config validation with deterministic diagnostics.
- Platform-level resource planning (pins, buses, DMA/PIO roles) remains centralized in architecture and target definitions.

## Architecture Layers

```
+-------------------------------------------------------------+
|                     Config File (TOML)                       |
|  Describes: buses, pins, module-to-resource mappings         |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                    CLI Validator                             |
|  - Validates against board definition                        |
|  - Checks for pin conflicts                                  |
|  - Checks for bus configuration conflicts                    |
|  - Generates binary config for flash                         |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                    Runtime Initializer                       |
|  - Reads config from flash                                   |
|  - Initializes buses (SPI, I2C) based on config              |
|  - Registers GPIO pins with their numbers                    |
|  - Creates resource registry for modules                     |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                        Modules                               |
|  - Request resources by name/id from config                  |
|  - Open HAL contracts via `provider_open`: GPIO/SPI/I2C/…    |
|  - No knowledge of physical pins                             |
+-------------------------------------------------------------+
```

## Silicon and Board Definitions

Silicon capabilities are declared once per chip family in
`targets/silicon/*.toml` and shared across every board that uses that
chip. Boards layer their own pin assignments and on-board peripheral
declarations on top in `targets/boards/*.toml`. The `fluxor targets`
CLI command lists every available target.

### Pico 2 W Pin Capabilities

```
GPIO 0-29: General purpose (some with special functions)

SPI Buses:
  SPI0:
    - MISO: GPIO 0, 4, 16, 20
    - MOSI: GPIO 3, 7, 19, 23
    - SCK:  GPIO 2, 6, 18, 22
    - CS:   Any GPIO (directly controlled)
  SPI1:
    - MISO: GPIO 8, 12
    - MOSI: GPIO 11, 15
    - SCK:  GPIO 10, 14
    - CS:   Any GPIO

I2C Buses:
  I2C0:
    - SDA: GPIO 0, 4, 8, 12, 16, 20
    - SCL: GPIO 1, 5, 9, 13, 17, 21
  I2C1:
    - SDA: GPIO 2, 6, 10, 14, 18, 22, 26
    - SCL: GPIO 3, 7, 11, 15, 19, 23, 27

Special Functions:
  GPIO 23: Wireless power enable (reserved)
  GPIO 24: Wireless SPI data/IRQ
  GPIO 25: Wireless SPI CS
  GPIO 29: Wireless SPI CLK / VSYS ADC

ADC Channels:
  GPIO 26: ADC0
  GPIO 27: ADC1
  GPIO 28: ADC2
  GPIO 29: ADC3 (shared with wireless)

PWM Channels: (8 slices, 2 channels each)
  GPIO 0-29 each map to a PWM slice/channel
```

### Board Definition File Format

```toml
# boards/pico2w.toml
[board]
name = "pico2w"
mcu = "rp2350"

[gpio]
count = 30
reserved = [23, 24, 25, 29]  # Wireless chip

[spi.0]
miso = [0, 4, 16, 20]
mosi = [3, 7, 19, 23]
sck = [2, 6, 18, 22]
max_freq_hz = 62_500_000

[spi.1]
miso = [8, 12]
mosi = [11, 15]
sck = [10, 14]
max_freq_hz = 62_500_000

[i2c.0]
sda = [0, 4, 8, 12, 16, 20]
scl = [1, 5, 9, 13, 17, 21]
max_freq_hz = 1_000_000

[i2c.1]
sda = [2, 6, 10, 14, 18, 22, 26]
scl = [3, 7, 11, 15, 19, 23, 27]
max_freq_hz = 1_000_000

[adc]
channels = [26, 27, 28]  # 29 reserved for wireless
```

## Config File Format

### Hardware Resources Section

```toml
[hardware]
board = "pico2w"

# SPI bus definitions
[[hardware.spi]]
bus = 0
miso = 16
mosi = 19
sck = 18
freq_hz = 400_000      # Initial frequency (can be changed by modules)

# I2C bus definitions
[[hardware.i2c]]
bus = 0
sda = 4
scl = 5
freq_hz = 100_000

# GPIO pins to make available (directly controlled, not part of a bus)
[[hardware.gpio]]
pin = 17
direction = "output"
initial = "high"
name = "sd_cs"         # Optional name for documentation

[[hardware.gpio]]
pin = 22
direction = "output"
initial = "low"
name = "led"

[[hardware.gpio]]
pin = 15
direction = "input"
pull = "up"            # "up", "down", "none"
name = "button"
```

### Module Resource Bindings

```toml
# Sources
[[sources]]
type = "sd_card"
[sources.hardware]
spi_bus = 0            # Which SPI bus to use
cs_pin = 17            # CS pin number
[sources.params]
start_block = 0
block_count = 1000
data_freq_hz = 12_000_000
init_freq_hz = 400_000

# Sinks
[[sinks]]
type = "i2s_output"
[sinks.hardware]
data_pin = 28
clock_base = 26
[sinks.params]
sample_rate = 44100

# Another SPI device on same bus
[[sources]]
type = "flash_reader"
[sources.hardware]
spi_bus = 0            # Same bus as SD card
cs_pin = 20            # Different CS pin
```

## Validation Rules

### CLI Validator Checks

1. **Board Compatibility**
   - All pins must be valid for the board (0-29 for Pico 2 W)
   - Reserved pins cannot be used (23, 24, 25, 29 for wireless)

2. **Pin Function Compatibility**
   - SPI pins must be valid for the specified bus
   - I2C pins must be valid for the specified bus
   - Cannot use same pin for multiple functions

3. **Bus Configuration Conflicts**
   - Same bus cannot be configured with different pins
   - Multiple devices on same bus must use same MISO/MOSI/SCK
   - Each device must have unique CS pin

4. **Resource Conflicts**
   - No pin used twice
   - No overlapping bus/GPIO usage
   - PWM slice conflicts if multiple PWM outputs

### Example Validation Errors

```
Error: Pin 16 conflict
  - Used as SPI0 MISO in hardware.spi[0]
  - Used as GPIO output in hardware.gpio[1]

Error: Invalid SPI0 MOSI pin
  - Pin 17 is not a valid MOSI for SPI0
  - Valid options: 3, 7, 19, 23

Error: Reserved pin usage
  - Pin 25 is reserved for wireless chip on pico2w
  - Cannot use for user GPIO

Error: SPI bus reconfiguration
  - SPI0 configured with SCK=18 in hardware.spi[0]
  - sources[1] references SPI0 but flash_reader expects SCK=22
```

## Runtime Initialization Flow

The runtime brings up hardware exactly as the binary config describes.
There are no hardcoded pin assignments anywhere in the kernel —
everything flows from the validated config blob loaded at boot.

```rust
// In runtime initializer (not main.rs)
pub struct HardwareContext {
    spi_buses: [Option<SpiBusHandle>; 2],
    i2c_buses: [Option<I2cBusHandle>; 2],
    gpio_registry: GpioRegistry,
}

impl HardwareContext {
    pub fn init_from_config(config: &HardwareConfig, peripherals: Peripherals) -> Self {
        let mut ctx = Self::default();

        // Initialize SPI buses from config
        for spi_cfg in &config.spi {
            let bus = init_spi_bus(
                &peripherals,
                spi_cfg.bus,
                spi_cfg.miso,
                spi_cfg.mosi,
                spi_cfg.sck,
                spi_cfg.freq_hz,
            );
            ctx.spi_buses[spi_cfg.bus as usize] = Some(bus);
        }

        // Initialize I2C buses from config
        for i2c_cfg in &config.i2c {
            let bus = init_i2c_bus(
                &peripherals,
                i2c_cfg.bus,
                i2c_cfg.sda,
                i2c_cfg.scl,
                i2c_cfg.freq_hz,
            );
            ctx.i2c_buses[i2c_cfg.bus as usize] = Some(bus);
        }

        // Register GPIO pins from config
        for gpio_cfg in &config.gpio {
            let pin = init_gpio_pin(&peripherals, gpio_cfg);
            ctx.gpio_registry.register(gpio_cfg.pin, pin);
        }

        ctx
    }
}
```

### main.rs Runtime Initialization

```rust
#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_rp::init(Default::default());

    // USB logger setup (always needed)
    let usb_driver = Driver::new(p.USB, Irqs);
    spawner.spawn(logger_task(usb_driver)).unwrap();

    Timer::after(Duration::from_secs(1)).await;
    log::info!("Fluxor starting");

    // Read config from flash
    let config = read_config();

    // Initialize hardware based on config
    let hw_ctx = HardwareContext::init_from_config(&config.hardware, p);

    // Register with syscalls
    syscalls::set_hardware_context(hw_ctx);
    syscalls::init_syscall_table();
    spawner.spawn(syscalls::spi_async_task()).unwrap();

    // Run pipeline (modules request resources via syscalls)
    run_from_config(config).await;
}
```

## Syscall Interface Updates

### Resource Access Contract

```rust
// Modules access GPIO/SPI/I2C via HAL contracts (contracts/hal/*.rs)
// dispatched through `provider_open` and `provider_call`.
// Runtime helpers in modules/pic_runtime.rs provide ergonomic wrappers.
//
// Examples:
// - provider_open(HAL_GPIO, gpio::SET_OUTPUT, ...)
// - provider_open(HAL_GPIO, gpio::SET_INPUT, ...)
// - provider_open(HAL_SPI, spi::OPEN, ...)
// - provider_open(HAL_I2C, i2c::OPEN, ...)
```

### Module Resource Access Pattern

```rust
// Module receives config with resource references
#[repr(C)]
pub struct SdSourceParams {
    pub spi_bus: u8,       // Which SPI bus (0 or 1)
    pub cs_pin: u8,        // CS pin number
    pub start_block: u32,
    pub block_count: u32,
    pub data_freq_hz: u32, // Optional data clock override
    pub init_freq_hz: u32, // Optional init clock override
    pub out_chan: i32,
}

// Module initialization
unsafe fn sd_init_hw(cfg: &SdSourceParams) -> i32 {
    // Request CS pin
    let mut cs_arg = [cfg.cs_pin];
    CS_HANDLE = (sys().provider_open)(-1, dev_gpio::REQUEST_OUTPUT, cs_arg.as_mut_ptr(), 1);
    if CS_HANDLE < 0 { return -10; }

    // Open SPI on the configured bus
    let mut spi = SpiOpenArgs {
        bus: cfg.spi_bus,
        cs_handle: CS_HANDLE,
        freq_hz: INIT_FREQ,
        mode: 0,
    };
    SPI_HANDLE = (sys().provider_open)(
        -1,
        dev_spi::OPEN,
        &mut spi as *mut _ as *mut u8,
        core::mem::size_of::<SpiOpenArgs>(),
    );
    if SPI_HANDLE < 0 { return -12; }

    // ... rest of init
}
```

## Binary Config Format

The CLI generates a binary config that includes:

```rust
#[repr(C)]
struct BinaryConfig {
    magic: u32,                    // 0x464C5558 "FLUX"
    version: u16,
    flags: u16,

    // Hardware section
    hw_section_offset: u16,
    hw_section_len: u16,

    // Pipeline section
    pipeline_section_offset: u16,
    pipeline_section_len: u16,

    // ... rest of config
}

#[repr(C)]
struct HardwareSection {
    spi_count: u8,
    i2c_count: u8,
    gpio_count: u8,
    _reserved: u8,

    // Variable length arrays follow
    // spi_configs: [SpiConfig; spi_count]
    // i2c_configs: [I2cConfig; i2c_count]
    // gpio_configs: [GpioConfig; gpio_count]
}

#[repr(C)]
struct SpiConfig {
    bus: u8,
    miso: u8,
    mosi: u8,
    sck: u8,
    freq_hz: u32,
}

#[repr(C)]
struct I2cConfig {
    bus: u8,
    sda: u8,
    scl: u8,
    _reserved: u8,
    freq_hz: u32,
}

#[repr(C)]
struct GpioConfig {
    pin: u8,
    flags: u8,     // bit 0: direction (0=in, 1=out), bit 1-2: pull (0=none, 1=up, 2=down)
    initial: u8,   // Initial level for outputs
    _reserved: u8,
}
```

## Validation Checklist

1. Validate all pin assignments against the selected board definition.
2. Validate bus pin tuples against legal hardware function mappings.
3. Validate per-device required resources before graph build.
4. Validate resource-count limits (bus instances, GPIO entries, channels).
5. Produce deterministic and actionable diagnostics on conflicts.

## Security Considerations

1. **Pin Validation**: CLI must validate all pins against board definition before generating config
2. **Reserved Pins**: Never allow access to wireless-reserved pins
3. **Resource Limits**: Enforce maximum bus/GPIO counts
4. **Config Integrity**: Binary config should have CRC for integrity check

## Example Complete Config

```toml
[hardware]
board = "pico2w"

# SPI bus for SD card
[[hardware.spi]]
bus = 0
miso = 16
mosi = 19
sck = 18
freq_hz = 400_000

# I2C bus for sensors
[[hardware.i2c]]
bus = 0
sda = 4
scl = 5
freq_hz = 100_000

# SD card CS pin
[[hardware.gpio]]
pin = 17
direction = "output"
initial = "high"
name = "sd_cs"

# Status LED
[[hardware.gpio]]
pin = 22
direction = "output"
initial = "low"
name = "status_led"

# Pipeline
[[sources]]
type = "sd_card"
[sources.hardware]
spi_bus = 0
cs_pin = 17
[sources.params]
start_block = 0
block_count = 1000

[[transformers]]
type = "audio_decoder"
[transformers.params]
format = "wav"

[[sinks]]
type = "i2s_output"
[sinks.hardware]
data_pin = 28
clock_base = 26
[sinks.params]
sample_rate = 44100
format = "i16_stereo"

[pipeline]
source = 0
transformers = [0]
sink = 0
```

## Appendix: Pin Quick Reference

### Pico 2 W Recommended Pin Assignments

| Function | Recommended Pins | Notes |
|----------|-----------------|-------|
| SPI0 (SD card) | MISO:16, MOSI:19, SCK:18 | Standard SD card pinout |
| SPI0 CS | 17 | Near SPI0 pins |
| SPI1 | MISO:12, MOSI:11, SCK:10 | Alternative SPI |
| I2C0 | SDA:4, SCL:5 | Standard I2C |
| I2C1 | SDA:14, SCL:15 | Alternative I2C |
| I2S | DATA:28, BCLK:26, LRCLK:27 | Audio output |
| Status LED | 22 | User LED |
| ADC | 26, 27, 28 | Analog inputs |
| Reserved | 23, 24, 25, 29 | Wireless chip |
