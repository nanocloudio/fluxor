# ip Module

IP Stack Service Module

## Files

- `manifest.toml`
- `mod.rs`
- `arp.rs`
- `dhcp.rs`
- `eth.rs`
- `icmp.rs`
- `ipv4.rs`
- `tcp.rs`
- `udp.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "frames_rx"
direction = "input"
content_type = "EthernetFrame"
required = true

[[ports]]
name = "frames_tx"
direction = "output"
content_type = "EthernetFrame"
required = true

[[resources]]
device_class = "netif"
access = "write"

[[resources]]
device_class = "socket"
access = "exclusive"
```

## Parameters

- `use_dhcp`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
