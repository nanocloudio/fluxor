# temp_sensor Module

Temperature Sensor PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface

| Port | Direction | Content type | |
|---|---|---|---|
| `reading` | output | `SensorSample` |  |

Builds for: `rp2350`, `rp2040`. [manifest.toml](manifest.toml) is the declaration.

## Parameters

- `interval_ms` — reading period (default 5000).
- `sensor_id` — stamped on every reading, so a consumer of several sensors
  tells them apart (default 0).
