# Pin and Bus Allocation

Hardware resource usage — pins, buses, and their owners — is declared in
the graph config, validated against the target's silicon and board
definitions at build time, and brought up by the kernel from the packed
binary config before any module is instantiated. Modules never name
physical pins at runtime; they open HAL contracts (GPIO, SPI, I2C, UART,
ADC, PWM, PIO) through `provider_open` and receive resources the config
assigned to them.

The pieces:

- **Silicon definitions** (`targets/silicon/*.toml`) — per-chip-family
  capabilities: pin counts, valid peripheral pin combinations, and for
  RP-family chips a `[kernel]` section of chip constants that `build.rs`
  compiles into the kernel as `chip_generated.rs`
  (`src/platform/rp/chip.rs` includes it).
- **Board definitions** (`targets/boards/*.toml`) — per-board layering on
  a silicon file: usable pin range, reserved pins, default peripheral
  wiring, and platform facts.
- **Config validation** (`tools/src/board.rs`,
  `tools/src/config/validate.rs`) — checks the YAML `hardware:` section
  against the resolved target and packs the binary hardware section.
- **Runtime bring-up** (`src/kernel/boot/config.rs`) — parses the binary
  section into `HardwareConfig` and initialises buses and pins into a
  `HardwareContext` before graph start.

`fluxor inspect` lists every available target.

## Resource ownership discipline

Hardware resource ownership is explicit and declared, not opportunistic:

- Pin and bus assignments are configuration-defined and validated before
  runtime; runtime code does not use "grab any free pin/bus" patterns.
- Conflicts are resolved through config validation with deterministic
  diagnostics.
- Platform-level resource planning (pins, buses, DMA/PIO roles) stays in
  the target definitions, not in driver code.

## Board definitions

Source: `targets/boards/*.toml`, `tools/src/target.rs`.

A board file names its silicon and layers board facts on top. The shape,
abridged from `targets/boards/pico2w.toml`:

```toml
[board]
id = "pico2w"
silicon = "rp2350"
description = "Raspberry Pi Pico 2 W"

# Default PIO wiring (gSPI cmd for the wireless chip, I2S stream)
[[hardware.pio]]
pio_idx = 1
data_pin = 24
clk_pin = 29
extra_pin = 255

[gpio]
max_pin = 29
reserved_pins = [23, 24, 25, 29]

[gpio.reserved_reasons]
23 = "WL_GPIO_ON (wireless power)"

[platform.net]
phy = "wifi"
nic = "cyw43"
```

Valid peripheral pin combinations (which pins can be SPI0 MISO, I2C1 SDA,
and so on) live in the silicon file and are shared by every board on that
chip. Reserved pins carry a reason string that validation echoes in its
diagnostics.

## Config `hardware:` section

Source: `tools/src/config/validate.rs`.

The graph config (YAML) declares buses and pins under `hardware:`; module
entries then reference them by bus number and pin:

```yaml
hardware:
  spi:
    - bus: 1
      sck: 10
      mosi: 11
      miso: 12

modules:
  - name: sd
    spi_bus: 1
    cs_pin: 15
```

Recognised arrays and their fields:

| Array | Fields | Defaults |
|---|---|---|
| `spi` | `bus`, `miso`, `mosi`, `sck`, `freq_hz` | `freq_hz` 400000 |
| `i2c` | `bus`, `sda`, `scl`, `freq_hz` | `freq_hz` 100000 |
| `uart` | `bus`, `tx_pin`, `rx_pin`, `baudrate` | `baudrate` 115200 |
| `gpio` | `pin`, `direction`, `pull`, `initial`, `owner` | `direction` output, `pull` none, `initial` high |
| `pio` | `pio_idx`, `data_pin`, `clk_pin`, `extra_pin` | — |

`gpio.owner` names a module; the kernel grants the pin to that module at
instantiation (`owner_module_id` in the packed record). An unknown owner
name is a build error.

## Validation rules

Source: `tools/src/board.rs`.

Every `fluxor build` runs these checks against the resolved target:

1. **Pin range** — every pin is within the board's `max_pin`.
2. **Reserved pins** — a reserved pin is rejected, with the board's
   recorded reason.
3. **Pin function** — SPI/I2C/UART pin tuples must be a valid combination
   for the named bus per the silicon definition
   (`is_valid_spi_pins` and friends).
4. **Conflicts** — no pin is used twice across `hardware:` arrays and
   module pin references.
5. **Counts** — per-family limits on bus and pin entries (see below).

Diagnostics are deterministic and name the offending config path
(`hardware.spi[0].miso`, `modules[2].cs_pin`).

## Binary hardware section

Source: `tools/src/config/validate.rs::build_hardware_section` (encoder),
`src/kernel/boot/config.rs::parse_hardware_section` (decoder).

The validated section is packed into the binary graph config that the
kernel reads at boot:

```
header (6 bytes): spi_count, i2c_count, gpio_count, pio_count, max_gpio, uart_count
spi   × spi_count  (8 bytes): bus, miso, mosi, sck, freq_hz (u32 LE)
i2c   × i2c_count  (8 bytes): bus, sda, scl, reserved, freq_hz (u32 LE)
uart  × uart_count (8 bytes): bus, tx_pin, rx_pin, reserved, baudrate (u32 LE)
gpio  × gpio_count (5 bytes): pin, flags, initial, owner_module_id, reserved
pio   × pio_count  (4 bytes): pio_idx, data_pin, clk_pin, extra_pin
```

GPIO `flags`: bit 0 direction (0 = input, 1 = output), bits 1–2 pull
(0 = none, 1 = up, 2 = down). `owner_module_id` is the owning module's
index, `0xFF` for kernel-owned.

The kernel enforces the same count ceilings when parsing
(`src/kernel/boot/config.rs`): `MAX_SPI_BUSES = 2`, `MAX_I2C_BUSES = 2`,
`MAX_UART_BUSES = 2`, `MAX_GPIO_CONFIGS = 8`, `MAX_PIO_CONFIGS = 3`.
A section whose counts exceed them is rejected at boot.

## Runtime bring-up

Source: `src/kernel/boot/config.rs`.

`parse_hardware_section` decodes the section into `HardwareConfig`
(fixed-size `Option` arrays per bus family). Platform bring-up walks it
to initialise SPI/I2C/UART buses and register GPIO pins into a
`HardwareContext` before module instantiation, so a module's first
`provider_open` finds its bus already configured. There are no hardcoded
pin assignments in the kernel — everything flows from the validated
config blob.

Modules then access hardware exclusively through HAL contracts
(`modules/sdk/contracts/hal/`), dispatched via `provider_open` /
`provider_call`; see [abi_layers.md](abi_layers.md) for the contract
inventory and [hal_architecture.md](hal_architecture.md) for the backend
model. A module's parameters carry logical references (`spi_bus`,
`cs_pin`) from the config, not discovered hardware.
