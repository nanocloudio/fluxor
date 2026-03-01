# HAL Architecture

This document describes the Hardware Abstraction Layer design for Fluxor.

## Design Principles

1. **HAL provides primitives** - SPI, GPIO, PIO, DMA, timers
2. **Protocols live in modules** - WS2812, I2S, e-paper drivers are PIC modules
3. **Syscalls bridge the gap** - Modules access hardware via async syscall table
4. **Onboard hardware in HAL** - BOOTSEL, status LED are RP2350-specific

## Architecture Overview

```
+---------------------------------------------------------------------+
|                         Application Layer                           |
|                    (app/, mesh/, stream/, net/)                     |
+---------------------------------------------------------------------+
|                         Module Loader                               |
|                    (module/loader.rs, table.rs)                     |
+---------------------------------------------------------------------+
|                         Syscall Table                               |
|  gpio_* | spi_async_* | flash_async_* | pio_* | timer_* | log      |
+---------------------------------------------------------------------+
|                              HAL                                    |
|          gpio | spi | pio | pio_cmd | i2c                          |
+---------------------------------------------------------------------+
|                         Embassy Runtime                             |
|                    (embassy-rp, embassy-executor)                   |
+---------------------------------------------------------------------+
|                            Hardware                                 |
|                         (RP2350/RP2040)                            |
+---------------------------------------------------------------------+
```

## Directory Structure

```
src/
+-- kernel/           # Core types, events, channels, async syscalls
+-- io/              # Hardware Abstraction Layer
|   +-- mod.rs
|   +-- gpio.rs       # Raw GPIO: set/get/configure, edge detection + event binding
|   +-- spi.rs        # SPI primitives
|   +-- pio.rs        # PIO stream: double-buffered DMA streaming (I2S, WS2812)
|   +-- pio_cmd.rs    # PIO command: bidirectional transfers (gSPI for cyw43)
|   +-- i2c.rs        # I2C bus primitives
+-- main.rs

modules/
+-- ws2812/           # WS2812/SK6812 LED protocol
+-- i2s/              # I2S audio protocol
+-- epaper/           # E-paper display protocol
+-- led_pattern/      # LED pattern algorithms
+-- dither/           # Image dithering
+-- audio_format/     # Audio format handling
+-- flash/            # BOOTSEL button + flash data: flash sideband, debounce, gesture
+-- status_led/       # Status LED: GPIO output, blink patterns, control commands
+-- ...
```

## HAL Components

### GPIO (`io/gpio.rs`)

Raw GPIO pin control with software edge detection and event binding.

```rust
pub trait GpioHal {
    fn set_pin(&mut self, pin: u8, value: bool);
    fn get_pin(&self, pin: u8) -> bool;
    fn configure_pin(&mut self, pin: u8, mode: GpioMode);
}

pub enum GpioMode {
    Input,
    InputPullUp,
    InputPullDown,
    Output,
}
```

#### Edge Detection and Event Binding

GPIO pins support software-polled edge detection via `poll_gpio_edges()`, called every scheduler tick. When an edge is detected on a pin that has an event binding, the kernel automatically signals the bound event object. This enables hardware drivers to run entirely as modules without kernel knowledge of the device.

Modules bind events to GPIO edges via `dev_call(event, dev_event::IRQ_SUBSCRIBE, [0, pin, edge], 3)`. See `architecture/events.md` for details.

### SPI (`io/spi.rs`)

SPI bus primitives. Async access is exposed via kernel syscalls.

```rust
pub trait SpiHal {
    fn write(&mut self, data: &[u8]) -> Result<()>;
    fn read(&mut self, buf: &mut [u8]) -> Result<()>;
    fn transfer(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<()>;

    /// Command/data pattern for displays (manages DC pin)
    fn cmd_data(&mut self, dc_pin: u8, cmd: u8, data: &[u8]) -> Result<()>;
}
```

### I2C

I2C is not a first-class HAL surface. Device protocols should live in modules.

### PIO (`io/pio.rs`)

**This is the key primitive for protocols like WS2812 and I2S.**

The PIO subsystem allows modules to load custom programs and push data via DMA.

```rust
/// PIO handle returned by load_program
pub type PioHandle = i32;

pub trait PioHal {
    /// Load a PIO program, returns handle
    fn load_program(&mut self, program: &[u16]) -> Result<PioHandle>;

    /// Configure a loaded program
    fn configure(
        &mut self,
        handle: PioHandle,
        pin: u8,
        clock_divider: u32,
        config: PioConfig,
    ) -> Result<()>;

    /// Push data via DMA (async, returns when complete)
    fn dma_push(&mut self, handle: PioHandle, data: &[u32]) -> Result<()>;

    /// Enable/disable state machine
    fn set_enable(&mut self, handle: PioHandle, enable: bool);

    /// Release resources
    fn unload(&mut self, handle: PioHandle);
}

pub struct PioConfig {
    pub fifo_join: FifoJoin,
    pub shift_direction: ShiftDirection,
    pub auto_pull: bool,
    pub pull_threshold: u8,
}
```

### Timer (`io/timer.rs`)

Timing operations.

```rust
pub trait TimerHal {
    fn delay_ms(&self, ms: u32);
    fn delay_us(&self, us: u32);
    fn millis(&self) -> u64;
    fn micros(&self) -> u64;
}
```

### Onboard Hardware

Onboard peripherals that can be accessed through existing syscalls (GPIO, flash sideband) are implemented as PIC modules, not HAL code:

- **BOOTSEL button** — `modules/flash/` reads via System flash sideband (`dev_call`, QSPI CS pin)
- **Status LED** — `modules/status_led/` drives via GPIO `dev_call`

### WiFi (`io/wifi.rs`)

Built-in WiFi for boards with integrated radios (e.g., Pico W with cyw43).

**Important**: External WiFi/Ethernet modules (W5500, ENC28J60, etc.) are **PIC modules**, not HAL. HAL is only for hardware that's integral to the board.

```rust
pub trait WifiHal {
    fn init(&mut self) -> Result<(), WifiError>;
    fn state(&self) -> WifiState;
    fn mac_address(&self) -> [u8; 6];
    fn scan_start(&mut self) -> Result<(), WifiError>;
    fn scan_get_results(&self, results: &mut [WifiScanEntry]) -> usize;
    fn connect(&mut self, ssid: &[u8], password: &[u8]) -> Result<(), WifiError>;
    fn disconnect(&mut self) -> Result<(), WifiError>;
    fn rssi(&self) -> Option<i8>;
}
```

See `architecture/network.md` for the full networking architecture.

## Syscall Table

The syscall table (`SyscallTable` in `src/abi.rs`) is the stable ABI between modules and the kernel. It is a `#[repr(C)]` struct of function pointers passed to each module at `module_init()`.

The table groups syscalls by subsystem:

| Group | Syscalls | Description |
|-------|----------|-------------|
| Channels | `channel_open/close/read/write/poll/ioctl/sendto/recvfrom/bind/listen/accept/port` | IPC between modules (pipes, TCP, UDP) |
| Zero-copy buffers | `buffer_acquire_write/release_write/acquire_read/release_read/acquire_inplace` | Direct buffer access without copying |
| I2C | `i2c_open/close/write/read/write_read/claim/release` | I2C bus access with handle-based locking |
| Timer | `timer_start/poll`, `millis`, `micros` | Async delays and timestamps |
| PIO Stream | `pio_stream_alloc/load_program/configure/can_push/push/free`, `stream_time`, `pio_direct_buffer/push` | Double-buffered DMA streaming (I2S, WS2812) |
| PIO Command | `pio_cmd_alloc/load_program/configure/transfer/poll/free` | Bidirectional PIO transfers (gSPI for cyw43) |
| Network | `netif_open/register_frame/register_socket/close/state/ioctl` | Network interface management |
| Sockets | `socket_open/connect/send/recv/poll/close` | TCP/UDP network connections |
| Filesystem | `fs_open/read/seek/close/stat` | VFS file access |
| Logging | `log` | Printf-style logging |
| `dev_call` | `dev_call(handle, opcode, arg, arg_len)` | Generic device dispatch (ABI v3) |
| `dev_query` | `dev_query(handle, key, out, out_len)` | Device introspection |
| Arena | `arena_get` | Module arena allocation |

### `dev_call` — Generic Device Dispatch

`dev_call` is the extensible entry point for device operations that don't warrant dedicated syscall slots. Opcodes are namespaced by device class (`class << 8 | operation`). This includes GPIO configuration, SPI control, event objects, and buffer operations.

Key device classes accessible through `dev_call`:

| Class | ID | Example opcodes |
|-------|----|----------------|
| GPIO | 0x01 | `SET_IRQ`, `POLL_IRQ` |
| SPI | 0x02 | `OPEN`, `SET_SPEED`, `TRANSFER` |
| Event | 0x0B | `CREATE`, `SIGNAL`, `POLL`, `DESTROY`, `IRQ_SUBSCRIBE`, `IRQ_UNSUBSCRIBE` |
| Buffer | 0x0A | `CREATE`, `READ`, `WRITE`, `RESIZE` |
| System | 0x0C | `RESOURCE_TRY_LOCK`, `RESOURCE_UNLOCK`, `FLASH_SIDEBAND` |

Events are the mechanism by which modules receive hardware notifications without the kernel containing any driver-specific code. See `architecture/events.md` for the full event system design.

## Module Examples

### WS2812 Module

The WS2812 module contains:
- PIO program bytes (compiled at module build time)
- Color packing functions (pure computation)
- Init/show functions that use PIO syscalls

```rust
// modules/ws2812/src/lib.rs
#![no_std]

// PIO program for WS2812 800kHz timing
static WS2812_PROGRAM: [u16; 4] = [
    0x6221, // out x, 1       side 0 [2]
    0x1123, // jmp !x do_zero side 1 [3]
    0x1400, // jmp bitloop    side 1 [14]
    0xa442, // nop            side 0 [14]
];

static mut PIO_HANDLE: i32 = -1;

#[no_mangle]
pub extern "C" fn ws2812_init(pin: u8, led_count: u16) -> i32 {
    unsafe {
        let handle = syscall!(pio_load, WS2812_PROGRAM.as_ptr(), WS2812_PROGRAM.len());
        if handle < 0 { return handle; }

        // Clock divider for 800kHz: (150MHz / 24MHz) = 6.25 in 16.16 fixed point
        let clock_div = (6 << 16) | (1 << 14); // 6.25

        // Config: TX-only FIFO, 24-bit auto-pull, left shift
        let config = (24 << 8) | 0x01; // threshold=24, flags=TX_ONLY

        let result = syscall!(pio_configure, handle, pin, clock_div, config);
        if result < 0 { return result; }

        syscall!(pio_enable, handle, 1);
        PIO_HANDLE = handle;
        0
    }
}

#[no_mangle]
pub extern "C" fn ws2812_show(colors: *const u32, count: usize) -> i32 {
    unsafe {
        if PIO_HANDLE < 0 { return -1; }
        syscall!(pio_dma_push, PIO_HANDLE, colors, count)
    }
}

/// Pack RGB to GRB format for WS2812
#[no_mangle]
pub extern "C" fn ws2812_pack_grb(r: u8, g: u8, b: u8) -> u32 {
    ((g as u32) << 16) | ((r as u32) << 8) | (b as u32)
}

/// HSV to RGB conversion
#[no_mangle]
pub extern "C" fn ws2812_hsv_to_rgb(h: u8, s: u8, v: u8, out: *mut u32) {
    // Pure computation...
}
```

### E-Paper Module

The e-paper module contains:
- SPI command sequences for init/refresh
- Framebuffer handling
- Device-specific knowledge

```rust
// modules/epaper/src/lib.rs
#![no_std]

/// Initialize e-paper display
#[no_mangle]
pub extern "C" fn epaper_init(rst_pin: u8, dc_pin: u8, busy_pin: u8) -> i32 {
    unsafe {
        // Hardware reset
        syscall!(gpio_config, rst_pin, GPIO_OUTPUT);
        syscall!(gpio_set, rst_pin, 0);
        syscall!(delay_ms, 10);
        syscall!(gpio_set, rst_pin, 1);
        syscall!(delay_ms, 10);

        // Wait for busy
        syscall!(gpio_config, busy_pin, GPIO_INPUT);
        while syscall!(gpio_get, busy_pin) == 1 {
            syscall!(delay_ms, 10);
        }

        // Send init commands via SPI
        syscall!(spi_cmd_data, dc_pin, 0x00, INIT_SEQ.as_ptr(), INIT_SEQ.len());
        // ...

        0
    }
}

/// Write framebuffer to display
#[no_mangle]
pub extern "C" fn epaper_write(dc_pin: u8, data: *const u8, len: usize) -> i32 {
    unsafe {
        syscall!(spi_cmd_data, dc_pin, 0x10, data, len)
    }
}
```

## File Locations

| Component | Location | Purpose |
|-----------|----------|---------|
| BOOTSEL button | `kernel/resource.rs` + `modules/flash/` | Flash sideband + PIC module |
| Status LED | `modules/status_led/` | PIC module (GPIO) |
| Flash storage | `io/flash.rs` | Storage primitive |
| SD card | `io/sdcard.rs` or `storage/` | Storage |
| WS2812 LEDs | `modules/ws2812/` | Protocol via PIO syscall |
| I2S audio | `modules/i2s/` | Protocol via PIO syscall |
| E-paper display | `modules/epaper/` | Device via SPI syscall |
| Device bytecode | `io/device_table.rs` | Bytecode interpreter |
| LED patterns | `modules/led_pattern/` | Pattern algorithms |

## Kernel Structure

The kernel contains no hardware protocol code and no audio-specific types. All drivers and audio handling are in PIC modules:

```
src/
+-- kernel/               # Core kernel services
|   +-- syscalls.rs       # Syscall dispatch (dev_call, channel_*, etc.)
|   +-- channel.rs        # IPC channels
|   +-- scheduler.rs      # Graph runner, main loop with select() + event wake
|   +-- event.rs          # Event objects: create/signal/poll, IRQ binding, SCHEDULER_WAKE
|   +-- resource.rs       # Resource locks, flash sideband (BOOTSEL QSPI CS read)
|   +-- loader/           # Module loading (validation, FFI, arena)
|   +-- config.rs         # Runtime configuration
|   +-- net.rs            # Network interface registry
|   +-- socket.rs         # Socket table
+-- io/                  # HAL primitives
|   +-- gpio.rs           # Raw GPIO with edge detection + event binding
|   +-- spi.rs            # SPI bus primitives
|   +-- pio.rs            # Double-buffered DMA streaming (PioStreamService)
|   +-- pio_cmd.rs        # Bidirectional PIO transfers (PioCmdService)
|   +-- i2c.rs            # I2C bus primitives

modules/
+-- ws2812/        # LED protocol: ws2812_init, ws2812_show, rainbow, hsv_to_rgb
+-- i2s/           # Audio protocol: i2s_init, i2s_write, convert_stereo_to_i2s
+-- epaper/        # E-paper protocol: device bytecode, color palettes
+-- sd/            # SD card: sd_init, sd_read_blocks, sd_get_sector_count
+-- audio_format/  # Audio types + PCM conversion: AudioFormat, SampleFormat, 8-to-16 bit
+-- dither/        # Image dithering algorithms
+-- flash/         # BOOTSEL button + flash data: flash sideband, debounce, gesture
+-- status_led/    # Status LED: GPIO output, blink patterns, control commands
```

## Zero-Footprint Drivers

If a config doesn't reference a peripheral, no code for that peripheral exists in the UF2:

| Peripheral | Config Reference | Module Loaded | Kernel Code |
|------------|------------------|---------------|-------------|
| LED Strip  | `sinks: led_strip` | `ws2812` | `Ws2812ModuleContext` only (~100 bytes) |
| I2S Audio  | `sinks: i2s` | `i2s` | `I2sModuleContext` only (~100 bytes) |
| SD Card    | `sources: sd_blocks` | `sd` | `ModuleSdSource` wrapper (~200 bytes) |
| E-Paper    | `sinks: epaper` | `epaper` | Device table interpreter |
| Audio Format | `transformers: audio_format` | `audio_format` | Zero (types only in module) |

## Benefits

1. **Clean separation** - HAL is pure Embassy/hardware, modules are portable
2. **Testable** - Modules can be tested without hardware by mocking syscalls
3. **Extensible** - New devices just need new modules, not HAL changes
4. **Small kernel** - Minimal code requires Embassy, rest is position-independent
