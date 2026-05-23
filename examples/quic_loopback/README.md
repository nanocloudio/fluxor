# `quic_loopback/` — single-process QUIC client + server + periodic data

The fluxor QUIC demo. Two `quic` instances coexist in one graph:
the server listens on 64443, the client connects to 127.0.0.1:64443
from local port 64444. A `sequencer` ticks every 500 ms and pushes
its 8-byte output into the client's stream; the bytes traverse a
real QUIC handshake + 1-RTT data path on loopback UDP and arrive
at the server's `app_out`, where a `debug` module logs them.

```
                 sequencer (heartbeat, every 500 ms)
                          ↓
                          ▼
   debug ◄── server.app_out          server ◄── linux_net.net_out
                                              (auto-tee'd inbound)
                                       ↓
   server.net_out ─────────────────────►
            (auto-merged outbound)        linux_net.net_in
                                              ▲
                                              │
   client.net_out ────────────────────────────┘
                                              ▲
   client ◄── linux_net.net_out               │
                                              │
   heartbeat.notes ──► client.app_in ────────►(stream out)
```

What this teaches:

- **Two `quic` instances in one graph.** Both modules share
  `linux_net`; fluxor auto-tees the inbound side so each module
  sees every UDP packet and filters by destination port, and
  auto-merges the outbound side so both modules can emit through
  one NIC channel.
- **Sequencer as a generic periodic byte source.** The output is
  an audio-shaped 8-byte event, but the demo doesn't interpret it
  as audio — it's repurposed as a 2 Hz heartbeat to drive a real
  data flow over QUIC. Same module the synth + drums examples
  use; here it's the timer.
- **Real handshake + 1-RTT loopback.** The QUIC handshake completes
  end-to-end, including TLS 1.3 key derivation; subsequent stream
  writes ride the established connection.

## Targets

- `linux.yaml` — runs as a single `fluxor run` invocation.

## Setup

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes -keyout /tmp/server_key.pem -out /tmp/server_cert.pem \
  -days 365 -subj "/CN=fluxor"
openssl x509 -in /tmp/server_cert.pem -outform DER -out /tmp/server_cert.der
openssl ec  -in /tmp/server_key.pem  -outform DER -out /tmp/server_key.der
```

## Run

```sh
fluxor run examples/quic_loopback/linux.yaml
# observe debug lines every 500 ms — each carries the sequencer's
# 8-byte tick payload as received by the server side
```

## Related

- The QUIC protocol matrix (0-RTT, retry, ALPN, h3, concurrent
  streams, key checks) lives under
  [`../test_harness/linux/quic/`](../test_harness/linux/quic/) —
  each variant is a paired-client/server fixture for the
  regression suite.
- For canonical HTTP/HTTPS/h2 see [`web_server/`](../web_server/).
