# ch9120 Module

CH9120 UART-to-Ethernet Driver PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `constants.rs`

## Interface

| Port | Direction | Content type | |
|---|---|---|---|
| `net_tx` | input | `OctetStream` |  |
| `net_rx` | output | `OctetStream` | required |
| `netif_state` | output | `FmpMessage` |  |

Builds for: `rp2040`, `rp2350`. [manifest.toml](manifest.toml) is the declaration.

## Parameters

- `cfg0_pin`
- `data_baud`
- `dest_ip`
- `dest_port`
- `gateway`
- `local_ip`
- `local_port`
- `net_mode`
- `reset_pin`
- `subnet`
- `uart_bus`
- `use_dhcp`
