# wifi Module

WiFi Connect PIC Module

## Files

- `manifest.toml`
- `mod.rs`
- `constants.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "status"
direction = "input"
content_type = "FmpMessage"

[[ports]]
name = "scan_data"
index = 1
direction = "input"
content_type = "OctetStream"

[[ports]]
name = "wifi_ctrl"
direction = "output"
content_type = "FmpMessage"

[[resources]]
device_class = "netif"
access = "write"

[commands]
accepts = ["radio_ready", "connected", "disconnected", "scan_done", "scan_result"]
emits = ["connect", "disconnect", "scan"]
```

## Parameters

- `password`
- `security`
- `ssid`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
