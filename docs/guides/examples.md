# Example graphs

This guide covers the end-to-end graphs in `examples/`. Each is a complete,
runnable configuration — `fluxor validate <yaml>` checks it, and on a host
target `fluxor run <yaml>` executes it.

| Example | Target | What it shows |
|---|---|---|
| [`hello/`](../../examples/hello/) | linux, pi5 | The smallest complete graph, plus the same graph as a workload bundle (`bundle/`) |
| [`dns_server/`](../../examples/dns_server/) | pico2w | Authoritative DNS over the datagram surface |
| [`log_net/`](../../examples/log_net/) | pi5 | Log-ring forwarding to a host collector over UDP |
| [`owner_status/`](../../examples/owner_status/) | linux | Two co-resident owners in one runtime; a fault in one terminates only that owner ([owner_status.md](../architecture/owner_status.md)) |
| [`packet_filter/`](../../examples/packet_filter/) | pi5 | Packet inspection on the NIC path |

Each directory carries a `README.md` with its own build-and-run recipe; the
per-target commands below are the common shape.

> `packet_filter/pi5.yaml` currently fails validation on an unrelated
> `rp1_gem` pre-tick-drain / domain-tier conflict. The graph is still the
> reference for NIC-path inspection, but expect that error until the domain
> assignment is fixed.

## Running

Host targets (`linux`, `qemu-virt`) run directly:

```
fluxor validate examples/hello/linux.yaml
fluxor run examples/hello/linux.yaml
```

Embedded targets (`pi5`, `pico2w`, `waveshare-lcd4`) build a firmware image and
combine the graph into it:

```
make firmware TARGET=pi5
fluxor modules build --target bcm2712
fluxor combine -o kernel8.img target/pi5/firmware.bin examples/log_net/pi5.yaml
```

## Graphs that live elsewhere

Fluxor ships the runtime, the kernel-adjacent foundation modules and the
drivers. Application modules live in sibling repositories — [wave](../../../wave)
owns the protocol modules (`http`, `ws_stream`, `rtp`, `sip`),
[spectra](../../../spectra) the codecs, [grove](../../../grove) synthesis and
effects — and the graphs that exercise them ship there, alongside the modules
they name. A graph naming a module this repo does not contain will not validate
against a clean checkout, which is why those examples are not here.

A **wasm** or **split** graph additionally needs an HTTP origin to host the
browser side, which is a separate Fluxor graph. The deployment-scenario
primitive declares that: single-graph orchestration carries a `scenario:` block
inline on the graph YAML; multi-graph harnesses use a standalone YAML with
`kind: scenario` at the top. Either form is run by `fluxor run <yaml>`.

## Related guides

- [audio.md](audio.md) — audio pipeline architecture
- [displays.md](displays.md) — display panel drivers
- [asset_banks.md](asset_banks.md) — `fs_bank` / `object_bank` navigation semantics
- [input_gestures.md](input_gestures.md) — single/double/triple click mapping to FMP verbs
