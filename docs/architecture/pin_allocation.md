# Pin and Bus Allocation

Hardware resource usage — pins, buses, and their owners — is declared in
the graph config, validated against the target's silicon and board
definitions at build time, and brought up by the kernel from the packed
binary config before any module is instantiated. Modules never name
physical pins at runtime; they open HAL contracts (GPIO, SPI, I2C, UART,
ADC, PWM, and on RP the PIO engine) through `provider_open` and receive
resources the config assigned to them.

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
- **Runtime bring-up** (`src/platform/rp/config.rs`, `src/platform/rp.rs`)
  — decodes the binary section into `HardwareConfig`, re-checks it as a
  resource plan, and brings up pins and buses before graph start.

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
| `spi` | `bus`, `miso`, `mosi`, `sck`, `freq_hz` | `bus` 0, `miso` 16, `mosi` 19, `sck` 18, `freq_hz` 400000 |
| `i2c` | `bus`, `sda`, `scl`, `freq_hz` | `bus` 0, `sda` 4, `scl` 5, `freq_hz` 100000 |
| `uart` | `bus`, `tx_pin`, `rx_pin`, `baudrate` | `bus` 0, `tx_pin` 0, `rx_pin` 1, `baudrate` 115200 |
| `gpio` | `pin`, `direction` (`output`/`input`), `pull` (`none`/`up`/`down`), `initial` (`high`/`low`), `owner` | `direction` output, `pull` none, `initial` high |
| `pio` | `pio_idx`, `data_pin`, `clk_pin`, `extra_pin` | `extra_pin` 255 (unused) |

`gpio.owner` names a module; the kernel grants the pin to that module at
instantiation (`owner_module_id` in the packed record). An unknown owner
name is a build error.

## Validation rules

Source: `tools/src/board.rs` (`validate_config`),
`tools/src/config/validate.rs` (`build_hardware_section`).

Every `fluxor build` runs these checks against the resolved target:

1. **Bus and block exist** — an `spi`/`i2c` `bus` or a `pio` `pio_idx`
   past the silicon's count is rejected.
2. **Pin range** — every pin is within the board's `max_pin`.
3. **Reserved pins** — a reserved pin is rejected, with the board's
   recorded reason.
4. **Pin function** — SPI and I2C pin tuples must be a valid combination
   for the named bus per the silicon definition
   (`is_valid_spi_pins`, `is_valid_i2c_pins`).
5. **Conflicts** — no pin is used twice across the `hardware:` `spi`,
   `i2c` and `gpio` arrays.
6. **Counts** — per-family limits on entries (see below).

UART entries are checked for pin range only. Pins a module names in its
parameters (`cs_pin`) are not part of these checks. Diagnostics are
deterministic and name the offending entry (`hardware.spi[0]: …`).

## Binary hardware section

Source: `tools/src/config/validate.rs::build_hardware_section` (encoder),
`src/platform/rp/config.rs` (decoder).

The validated section rides the boot config as its `HWRP` section
(`fluxor_contracts::boot_config`), under the config's one checksum. It is
RP pin policy: the composer emits it for RP targets only (with zero counts
when the graph has no `hardware:`), refuses a `hardware:` that configures
anything on another target, and a non-RP kernel refuses a config that
carries one. Its payload:

```
header (6 bytes): spi_count, i2c_count, gpio_count, pio_count, max_gpio, uart_count
spi   × spi_count  (8 bytes): bus, miso, mosi, sck, freq_hz (u32 LE)
i2c   × i2c_count  (8 bytes): bus, sda, scl, reserved, freq_hz (u32 LE)
uart  × uart_count (8 bytes): bus, tx_pin, rx_pin, reserved, baudrate (u32 LE)
gpio  × gpio_count (5 bytes): pin, flags, initial, owner_module_id (u16 LE)
pio   × pio_count  (4 bytes): pio_idx, data_pin, clk_pin, extra_pin
```

GPIO `flags`: bit 0 direction (0 = input, 1 = output), bits 1–2 pull
(0 = none, 1 = up, 2 = down). `owner_module_id` is the owning module's
index, `0xFFFF` for kernel-owned. `extra_pin` `0xFF` means unused;
`max_gpio` 0 means the default part (30 pins).

The composer and the RP platform hold the same count ceilings: two SPI,
two I2C and two UART entries, eight GPIO and three PIO
(`MAX_SPI_BUSES`, `MAX_I2C_BUSES` in `src/kernel/boot/config.rs`;
`MAX_UART_BUSES`, `MAX_GPIO_CONFIGS`, `MAX_PIO_CONFIGS` in
`src/platform/rp/config.rs`). A section whose counts exceed them, or
whose length disagrees with its counts, is refused at admission, and
with it the config: nothing is clamped.

## Runtime bring-up

Source: `src/platform/rp/config.rs` (`decode_hardware`, `resolve`),
`src/platform/rp.rs` (`rp_boot_hardware`).

The RP platform decodes the section into `HardwareConfig`
(fixed-size `Option` arrays per bus family) and resolves it into a
resource plan, re-checking pin range, SPI/I2C pin combinations and pin
or PIO conflicts; a plan that fails halts boot with the conflict named.
Bring-up then walks the plan before module instantiation: SPI and I2C
buses are marked available (the bus driver module initialises the
peripheral), GPIO pins are configured, and PIO pins are routed to their
block. There are no hardcoded pin assignments in the kernel — everything
flows from the validated config.

Modules then access hardware exclusively through HAL contracts
(`crates/fluxor-abi/src/contracts/hal/`; the RP PIO engine in
`crates/fluxor-abi/src/platform/rp/pio.rs`), dispatched via `provider_open` /
`provider_call`; see [abi_layers.md](abi_layers.md) for the contract
inventory and [hal_architecture.md](hal_architecture.md) for the backend
model. A module's parameters carry logical references (`spi_bus`,
`cs_pin`) from the config, not discovered hardware.
