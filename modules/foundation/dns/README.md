# dns Module

DNS Server PIC Module

## Files

- `manifest.toml`
- `mod.rs`

## Interface (manifest)

```toml
version = "1.0.0"
hardware_targets = ["rp2350"]

# Network transport: wired to the IP / transport stack via NetProto.
[[ports]]
name = "net_in"
direction = "input"
content_type = "NetProto"

[[ports]]
name = "net_out"
direction = "output"
content_type = "NetProto"
```

## Parameters

- `host`
- `port`
- `ttl`
- `upstream`
- `upstream_port` (destination port for forwarded queries, default 53 —
  lets a delegation listener on a non-standard port be the upstream)

## Supported profile

- Exactly one question per query (`QDCOUNT == 1`). Local answers are
  constructed from the header plus that question; nothing trailing the
  question is echoed.
- Names up to `MAX_NAME_LEN` (255) bytes, labels up to `MAX_LABEL_LEN` (63) —
  both registered in `docs/architecture/limit_register.md`.
- Forwarded queries carry a CSPRNG-drawn upstream transaction id, not the
  client's. An upstream answer is relayed only when it arrives from the
  configured upstream address and port with QR set, the expected opcode, and
  exactly the forwarded question, against a live pending slot.
- `MAX_PENDING` (8) forwarded queries may be outstanding. With every slot live,
  a new query is answered SERVFAIL; accepted work is never displaced.

## Notes

- Keep this file aligned with `manifest.toml` and parameter definitions in source.
- Last refreshed: 2026-08-20
