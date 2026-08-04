# Example graphs

This guide cross-references the end-to-end graphs in `examples/`. Each one is a
complete, runnable configuration — `fluxor validate <yaml>` checks it and
`fluxor run <yaml>` executes it on a host target.

## Serving

| Example | Target | What it shows |
|---|---|---|
| [`examples/hello/`](../../examples/hello/) | linux | Smallest complete graph — one module, one channel |
| [`examples/web_server/`](../../examples/web_server/) | linux, pi5 | TLS 1.3 termination in front of `http` — `ip → tls → http` |
| [`examples/edge_server/`](../../examples/edge_server/) | linux | Route table with proxy and file handlers on a host TCP listener |
| [`examples/dns_server/`](../../examples/dns_server/) | linux | Authoritative DNS over the datagram surface |
| [`examples/mqtt_publisher/`](../../examples/mqtt_publisher/) | — | MQTT 3.1.1 client publishing on a cadence |
| [`examples/quic_loopback/`](../../examples/quic_loopback/) | linux | QUIC transport against a loopback peer |

## Observability

| Example | Target | What it shows |
|---|---|---|
| [`examples/observe_demo/pi5.yaml`](../../examples/observe_demo/pi5.yaml) | pi5 | `observe` rendering ring records as `MON_` console lines |
| [`examples/observe_demo/pi5_udp_export.yaml`](../../examples/observe_demo/pi5_udp_export.yaml) | pi5 | `otel → transport_buffer` exporting batches as UDP datagrams |
| [`examples/observe_demo/pi5_uart_export.yaml`](../../examples/observe_demo/pi5_uart_export.yaml) | pi5 | The network-less path — the same batches over the debug serial sink |
| [`examples/log_net/`](../../examples/log_net/) | pi5 | Log-ring forwarding to a host collector, plus adaptive-tick probes |
| [`examples/owner_status/`](../../examples/owner_status/) | — | Owner status surface and pod runtime reporting |

## Isolation and workloads

| Example | Target | What it shows |
|---|---|---|
| [`examples/iso_probe/`](../../examples/iso_probe/) | pi5 | EL0-isolated module, including fault containment under overflow |
| [`examples/iso_heap/`](../../examples/iso_heap/) | pi5 | Heap allocation from inside an isolated module |
| [`examples/iso_transform/`](../../examples/iso_transform/) | pi5 | An isolated transform stage in a live pipeline |
| [`examples/multi_graph/`](../../examples/multi_graph/) | — | Several graphs coordinated by a scenario |
| [`examples/compute_demo/`](../../examples/compute_demo/) | — | Compute-heavy module pacing |

## Surfaces and presentation

| Example | Target | What it shows |
|---|---|---|
| [`examples/surface_traits/wasm.yaml`](../../examples/surface_traits/wasm.yaml) | wasm | Browser-hosted graph with an inline `scenario:` block for the serving origin |
| [`examples/presentation/`](../../examples/presentation/) | — | Presentation surfaces and role-based rendering |
| [`examples/led_patterns/`](../../examples/led_patterns/) | rp2350 | Driver-level output with no network involved |
| [`examples/packet_filter/`](../../examples/packet_filter/) | pi5 | Packet inspection on the NIC path |
| [`examples/cli_cat/`](../../examples/cli_cat/) | linux | A CLI applet as a graph |

## Media pipelines

Audio and image playback families (`image_viewer`, `audio_player`) are built
from codec and synthesis modules, which live in the sibling repositories —
[spectra](../../../spectra) owns codecs, [grove](../../../grove) owns synthesis
and effects. Their graphs and guides ship there, built against this SDK and
loaded like any other PIC module.

## Running

Host targets (`linux`, `qemu-virt`) run directly:

```
fluxor validate examples/web_server/linux.yaml
fluxor run examples/web_server/linux.yaml
```

Embedded targets (`pi5`, `pico2w`, `waveshare-lcd4`) build a firmware image:

```
make firmware TARGET=pi5
fluxor modules build --target bcm2712
fluxor combine -o kernel8.img target/pi5/firmware.bin examples/web_server/pi5.yaml
```

A **wasm** or **split** graph needs an HTTP origin to host the browser side,
which is a separate Fluxor graph. The deployment-scenario primitive declares
that: single-graph orchestration carries a `scenario:` block inline on the graph
YAML (see `examples/surface_traits/wasm.yaml`); multi-graph harnesses use a
standalone YAML with `kind: scenario` at the top. Either form is run by
`fluxor run <yaml>`.

## Related guides

- [audio.md](audio.md) — audio pipeline architecture
- [displays.md](displays.md) — display panel drivers
- [asset_banks.md](asset_banks.md) — `bank` module navigation semantics
- [input_gestures.md](input_gestures.md) — single/double/triple click mapping to FMP verbs
