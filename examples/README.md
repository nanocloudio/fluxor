# `examples/` — onboarding catalog

One demo per capability, each in its own directory with platform-named YAML
files. Each example has a short `README.md` saying exactly what it teaches.

## Layout

```
examples/<capability>/
  <platform>.yaml          # one per target; multiple platforms share content
  README.md                # what this teaches + how to run it
  assets/                  # demo-specific media (when needed)
```

## The examples

| Example | Targets | Teaches |
| --- | --- | --- |
| [`hello/`](hello/) | linux, pi5 | "Kernel boots; UART works" — the smoke test that survives without network. `bundle/` is the same graph packaged as a workload bundle. |
| [`dns_server/`](dns_server/) | pico2w | Authoritative DNS over the datagram surface. |
| [`log_net/`](log_net/) | pi5 | Netconsole — kernel log ring over UDP, with optional monitor overlay. |
| [`owner_status/`](owner_status/) | linux | Two co-resident owners in one runtime; a fault in one terminates only that owner. |
| [`packet_filter/`](packet_filter/) | pi5 | L2 packet filtering with custom accept rules (rp1_gem + eth_parser + pkt_filter chain). |

`packet_filter/pi5.yaml` currently fails validation on an unrelated `rp1_gem`
pre-tick-drain / domain-tier conflict; the graph is still the reference for
NIC-path inspection.

## Examples that live in sibling repositories

Fluxor ships the runtime, the foundation modules and the drivers. Application
modules live alongside their own graphs: [wave](../../wave) owns the protocol
modules (`http`, `ws_stream`, `rtp`, `sip`), [spectra](../../spectra) the
codecs, [grove](../../grove) synthesis and effects.

A graph naming a module this repo does not contain cannot validate against a
clean checkout, so those examples ship where their modules do — HTTP and HTTPS
serving, WebSocket and QUIC demos, media playback, synthesis and percussion,
MQTT publishing, and the LED/button/sequencer patterns.

> **Wasm runtime?** Any graph with `target: wasm` runs entirely in the browser.
> The scenario synthesiser auto-mounts the wasm host (HTML shell + JS shims +
> the `.wasm` bundle + scenario.json) when you `fluxor run <graph>.yaml`; no
> separate "serve a wasm bundle" example is needed. See
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
The asset bank, `host_asset_source`, and similar loaders all resolve paths
relative to the YAML's directory. See the root [README.md](../README.md) for
the full convention.

## What's *not* in here

The `test_harness/` sub-tree holds smoke tests, perf probes, bringup
validators, and codec coverage matrices. Those are loaded by `make test` and
the hardware rig — they are not meant to be browsed as examples.
