# `web_server/` — canonical HTTP / HTTPS / WS / HTTP/2 demo

One graph exercising every public surface of the `http` + `tls` modules:
plain HTTP/1.1, HTTP/2 via ALPN, RFC 6455 WebSocket upgrade, TLS 1.3,
and FS-backed file serving via the unified `FS_CONTRACT` path.

Replaces the older single-feature examples (`http_server`, `http_fs`,
`http_synth`, `https_server`, `https_multilane`, `h2c_server`, `ws_echo`).
Variant probes (multi-lane, perf, scripted echo) live under
[`../test_harness/linux/web/`](../test_harness/linux/web/) and
[`../test_harness/cm5/`](../test_harness/cm5/).

## Targets

- `linux.yaml` — full kitchen sink: HTTPS on 8443 with the four
  routes documented inside.
- `cm5.yaml` — bare-metal mirror; drops `fs_path` / WebSocket routes
  (no host filesystem on bare-metal cm5) but keeps TLS + HTTP/2.

## Setup

```sh
echo -n 'hello fs_contract' > /tmp/hello.txt
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -nodes -keyout /tmp/server_key.pem -out /tmp/server_cert.pem \
  -days 365 -subj "/CN=fluxor"
openssl x509 -in /tmp/server_cert.pem -outform DER -out /tmp/server_cert.der
openssl ec  -in /tmp/server_key.pem  -outform DER -out /tmp/server_key.der
```

## Run

```sh
fluxor run examples/web_server/linux.yaml

# Probes
curl -sk  https://localhost:8443/                 # static
curl -sk  https://localhost:8443/hello.txt        # fs_path
curl -vk  --http2 https://localhost:8443/         # ALPN h2
websocat -k wss://localhost:8443/ws               # WebSocket round-trip
```

## Related

- [`static_server/`](../static_server/) — HTTP file serving from
  FAT32 storage (the storage-backed counterpart on pico2w / cm5).
- [`quic_loopback/`](../quic_loopback/) — different transport
  (QUIC instead of TCP+TLS), single-process loopback shape.
- [`log_net/`](../log_net/) — netconsole flavour of network output
  on the same cm5 platform.
