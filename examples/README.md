# `examples/` — onboarding catalog

One demo per capability, each organized into its own directory with
platform-named YAML files. Each example has a short `README.md`
that says exactly what it teaches.

## Layout

```
examples/<capability>/
  <platform>.yaml          # one per target; multiple platforms share content
  README.md                # what this teaches + how to run it
  assets/                  # demo-specific media (when needed)
```

## Capability groups

### Hello, fluxor — minimal smoke per target

| Example | Targets | Teaches |
| --- | --- | --- |
| [`hello/`](hello/) | pi5 | "Kernel boots; UART works" — the smoke test that survives without network. |
| [`web_server/`](web_server/) | linux, pi5 | Canonical HTTP / HTTPS / WS / HTTP/2 surface. |
| [`led_patterns/`](led_patterns/) | pico2w, picow | GPIO + sequencer + button input on RP boards. |
| [`midi_echo/`](midi_echo/) | linux, wasm, pico2w | MIDI input/output surface (stubs today). |

### Media

| Example | Targets | Teaches |
| --- | --- | --- |
| [`image_viewer/`](image_viewer/) | linux, wasm, pi5, waveshare-lcd4 | Codec + bank + multiple sink platforms. |
| [`audio_player/`](audio_player/) | linux, wasm, pico2w, picow, pi5 | Same shape for audio — codec-driven file playback. |

### Network

| Example | Targets | Teaches |
| --- | --- | --- |
| [`quic_loopback/`](quic_loopback/) | linux | QUIC server + client + sequencer-driven periodic data, all in one process. |
| [`dns_server/`](dns_server/) | pico2w | Authoritative DNS resolver. |
| [`mqtt_publisher/`](mqtt_publisher/) | pico2w | Sensor → MQTT publish pattern. |
| [`log_net/`](log_net/) | pi5 | Netconsole — kernel log ring over UDP, with optional monitor overlay. |

### Storage

| Example | Targets | Teaches |
| --- | --- | --- |
| [`static_server/`](static_server/) | pico2w (SD-FAT32), pi5 (NVMe-FAT32) | HTTP file serving from FAT32 storage. |

### Embedded / advanced

| Example | Targets | Teaches |
| --- | --- | --- |
| [`button_control/`](button_control/) | pico2w | GPIO button → gesture → action wiring. |
| [`synth/`](synth/) | pico2w, picow | Multi-voice tonal synthesizer; button cycles voices. |
| [`drums/`](drums/) | pico2w | TR-808-style synthesized percussion. |
| [`packet_filter/`](packet_filter/) | pi5 | L2 packet filtering with custom accept rules (rp1_gem + eth_parser + pkt_filter chain). |

> **Wasm runtime?** Any graph with `target: wasm` runs entirely in
> the browser. The scenario synthesiser auto-mounts the wasm host
> (HTML shell + JS shims + the `.wasm` bundle + scenario.json) when
> you `fluxor run examples/<capability>/wasm.yaml`; no separate
> "serve a wasm bundle" example needed. See
> [`../src/platform/wasm/host/README.md`](../src/platform/wasm/host/README.md)
> for the runtime contract.

## Running an example

```sh
# Validate without packaging
fluxor validate examples/<capability>/<platform>.yaml

# For hosted targets (linux, wasm)
fluxor run examples/<capability>/<platform>.yaml

# For embedded targets (pico2w, pi5, etc.) build + flash
make firmware TARGET=<platform>
fluxor modules build --target <silicon>
fluxor combine -o kernel8.img target/<platform>/firmware.bin examples/<capability>/<platform>.yaml
```

## Where media lives

Per-example assets live with the example: `examples/<capability>/assets/<file>`.
The asset bank, `host_asset_source`, and similar loaders all resolve
paths relative to the YAML's directory. See the root [README.md](../README.md)
for the full convention.

## What's *not* in here

The [`test_harness/`](test_harness/) sub-tree holds smoke tests, perf
probes, bringup validators, and codec coverage matrices. Those are
loaded by `make test` and the hardware rig — they're not meant to be
browsed as examples. If you find yourself looking for "the variant
of `nvme_perf` that uses 4 queues," it's almost certainly in
`test_harness/pi5/`.
