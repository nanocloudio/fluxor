# wifi Module

Sequences WiFi association through the `cyw43` driver, over FMP commands
on `wifi_ctrl` and status events on `status` and `netif_state`. With an
`ssid` it sends `connect` and waits for the link; without one it sends `scan`
and logs the results from `scan_data`.

## Files

- `manifest.toml`
- `mod.rs`
- `constants.rs`

## Interface

| Port | Direction | Content type | |
|---|---|---|---|
| `status` | input | `FmpMessage` |  |
| `scan_data` | input | `OctetStream` |  |
| `netif_state` | input | `FmpMessage` |  |
| `wifi_ctrl` | output | `FmpMessage` |  |

Builds for: `rp2040`, `rp2350`. [manifest.toml](manifest.toml) is the declaration.

## Parameters

- `ssid` (str, up to 32 bytes).
- `password` (str, up to 64 bytes).
- `security` (enum `open`, `wpa`, `wpa2`, `wpa3`; default `wpa3`). `wpa` is
  sent to the driver as WPA2.
