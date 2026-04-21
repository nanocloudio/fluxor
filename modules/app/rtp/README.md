# rtp Module

RTP PIC Module (TX + RX)

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "g711"
direction = "input"
content_type = "OctetStream"

[[ports]]
name = "packets"
direction = "output"
content_type = "OctetStream"

[[ports]]
name = "endpoint"
direction = "ctrl_input"
content_type = "OctetStream"

[[resources]]
requires_contract = "socket"
access = "write"
```

## Parameters

- `local_port`
- `peer_ip`
- `peer_port`
- `ptime`
- `ssrc`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
