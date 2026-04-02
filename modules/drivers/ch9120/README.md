# ch9120 Module

CH9120 UART-to-Ethernet Driver PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `constants.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "net_tx"
direction = "input"
content_type = "OctetStream"

[[ports]]
name = "net_rx"
direction = "output"
content_type = "OctetStream"
required = true

[[resources]]
device_class = "uart"
access = "exclusive"

[[resources]]
device_class = "gpio"
access = "write"
```

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

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
