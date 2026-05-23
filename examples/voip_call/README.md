# `voip_call/` — SIP + RTP voice pipeline (P2P between two devices)

Point-to-point VoIP between two pico2w boards using SIP signalling
and RTP media. Each board boots the same config (with `peer_ip` set
to the other's address); pressing BOOTSEL on either side initiates
or ends a call. Audio flows mic → RTP packetizer → SIP signalling
→ WiFi, with the reverse path delivering incoming RTP to the I²S
DAC.

Plain SIP / RTP — no SRTP, no DTLS keying. See
[`docs/architecture/protocol_surfaces.md`](../../docs/architecture/protocol_surfaces.md)
for the secured-VoIP roadmap.

## Targets

- `pico2w.yaml`

## Setup

Edit `local_ip`, `peer_ip`, WiFi `ssid` + `password` in the YAML
on each device. The cyw43 WiFi stacks must reach each other on
the same L2 segment (or via a router that forwards the SIP/RTP
ports).

## Run

```sh
make firmware TARGET=pico2w && make modules TARGET=rp2350
make flash CONFIG=examples/voip_call/pico2w.yaml
# Microphone on mic_pio inputs; speaker on I²S DAC outputs.
# Flash both devices, then press BOOTSEL on one to ring the other.
```

## Related

- [`mqtt_publisher/`](../mqtt_publisher/) — another networked-app demo on the
  same WiFi target.
