# cyw43 Module

Driver for the CYW43439 WiFi chip (Pico W, Pico 2 W) over gSPI on a PIO
instance. It loads the chip's firmware and CLM from the module's `.rodata`,
registers a network interface, passes Ethernet frames on `frames_tx` /
`frames_rx`, and takes `connect` / `disconnect` / `scan` commands on
`wifi_ctrl`.

## Files

- `manifest.toml`
- `mod.rs`
- `constants.rs`
- `gspi.rs`
- `wifi_ops.rs`

## Interface

| Port | Direction | Content type | |
|---|---|---|---|
| `frames_tx` | input | `EthernetFrame` |  |
| `led` | input | `FmpMessage` |  |
| `hci_tx` | input | `HciMessage` |  |
| `frames_rx` | output | `EthernetFrame` | required |
| `scan_text` | output | `OctetStream` |  |
| `scan_data` | output | `OctetStream` |  |
| `status` | output | `OctetStream` |  |
| `hci_rx` | output | `HciMessage` |  |
| `netif_state` | output | `FmpMessage` |  |
| `wifi_ctrl` | ctrl_input | `FmpMessage` |  |

Builds for: `rp2040`, `rp2350`. [manifest.toml](manifest.toml) is the declaration.

## Parameters

- `pio_idx` (enum `pio0`, `pio1`, `pio2`; default `pio1`): PIO instance.
- `dio_pin` (u8, default 24): gSPI data pin.
- `clk_pin` (u8, default 29): gSPI clock pin.
- `cs_pin` (u8, default 25): chip select.
- `pwr_pin` (u8, default 23): power control.
