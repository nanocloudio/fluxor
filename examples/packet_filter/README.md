# `packet_filter/` — L2 packet filtering with custom accept rules

Frames arrive at the RP1 GEM NIC, get parsed by `eth_parser`, then
checked against per-protocol accept rules in `pkt_filter`. Accepted
frames flow to a debug sink (which logs them); rejected frames are
dropped before any downstream module sees them.

Pipeline:

```
rp1_gem → eth_parser → pkt_filter → debug
```

The example accepts TCP/80 and UDP/53; everything else is dropped.
Adjust the rules in the YAML to match what you want to forward.

## What the lesson actually is

L2 filtering before dispatch — useful for building security
middleboxes, traffic monitors, or custom protocol implementations
that don't want the overhead of a full IP stack. The `pkt_filter`
module is the only module in the tree that does protocol-level
ethernet filtering, and this is the only example exercising the
`rp1_gem + eth_parser + pkt_filter` chain.

A real consumer replaces `debug` with whatever module wants the
accepted frames — a custom protocol decoder, a traffic forwarder,
a packet logger that does something more than `dev_log`.

## Targets

- `cm5.yaml`

## Run

```sh
make firmware TARGET=cm5 && make modules TARGET=bcm2712
fluxor combine -o kernel8.img target/cm5/firmware.bin examples/packet_filter/cm5.yaml
# observe filter accept/drop counts via UART or netconsole
```

## A note on the multi-core wiring

The YAML runs the NIC pipeline on a dedicated `nic` domain (core 1,
`exec_mode: poll`). Poll-mode keeps the NIC ring from missing
frames at line rate; the dedicated core is optional — a single-
domain version would work but documents the latency-isolation
pattern less clearly. The packet-filter behaviour is the same
either way.

## Related

- The RP1 GEM driver: [`modules/drivers/rp1_gem/`](../../modules/drivers/rp1_gem/)
- For a full IP/HTTP stack on bare-metal (the *normal* network
  path, not filtering): [`web_server/cm5.yaml`](../web_server/cm5.yaml).
