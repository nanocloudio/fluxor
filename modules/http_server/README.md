# http_server Module

HTTP Server PIC Module — Routing, Templating, and Proxy

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "2.0.0"
hardware_targets = ["rp2350"]

[[ports]]
name = "variables"
direction = "input"
content_type = "FmpMessage"

[[ports]]
name = "file_data"
index = 1
direction = "input"
content_type = "OctetStream"

[[ports]]
name = "file_ctrl"
direction = "output"
content_type = "OctetStream"

[[resources]]
device_class = "socket"
access = "write"

[[resources]]
device_class = "channel"
access = "read"
```

## Parameters

- `body`
- `port`
- `route_0_body`
- `route_0_handler`
- `route_0_path`
- `route_0_proxy_ip`
- `route_0_proxy_port`
- `route_0_source`
- `route_1_body`
- `route_1_handler`
- `route_1_path`
- `route_1_proxy_ip`
- `route_1_proxy_port`
- `route_1_source`
- `route_2_body`
- `route_2_handler`
- `route_2_path`
- `route_2_proxy_ip`
- `route_2_proxy_port`
- `route_2_source`
- `route_3_body`
- `route_3_handler`
- `route_3_path`
- `route_3_proxy_ip`
- `route_3_proxy_port`
- `route_3_source`

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-03-01
