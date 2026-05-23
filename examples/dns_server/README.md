# `dns_server/` — local DNS resolver

Hybrid authoritative + recursive DNS on the pico2w's WiFi stack.
The `dns` module resolves a configured set of hostnames against an
in-memory table and forwards every other query to an upstream
resolver. Useful as a small captive-portal-style nameserver or a
LAN-local `.lan` zone.

Pipeline:

```
cyw43 (WiFi) ⇄ ip ⇄ dns
```

## Targets

- `pico2w.yaml`

## Setup

Edit the local hostname → IP table and WiFi credentials in the
YAML before flashing. The cyw43 stack must reach the upstream
resolver configured in the `dns` module's `upstream:` field.

## Run

```sh
make firmware TARGET=pico2w && make modules TARGET=rp2350
make flash CONFIG=examples/dns_server/pico2w.yaml
# Note the IP the pico reports over UART, then:
dig @<pico-ip> pico.lan         # local A record (configured table)
dig @<pico-ip> example.com      # forwarded upstream
```

## Related

- [`mqtt_publisher/`](../mqtt_publisher/) — another networked-app
  demo on the same pico2w + WiFi target.
- [`voip_call/`](../voip_call/) — SIP / RTP on the same WiFi stack.
