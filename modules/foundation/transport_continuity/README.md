# transport_continuity

`TRANSPORT_CONTINUITY` (`modules/sdk/contracts/net/transport_continuity.rs`)
over this graph's `ip` and `tls`: the provider an anchor drives to
checkpoint, import, arm and activate a live TCP+TLS connection the graph's own
stack holds. The record is sized to the TLS record, so a crash-continuous pair
keeps its protection for every record a stock peer sends: a whole record's
plaintext in is one delivery, a whole record out one delta.

## Files

- `manifest.toml`
- `mod.rs` — ports, frame reassembly, output queues
- `stack.rs` — the provider (`TcStack`): the FXTC and CT_TLS codecs, compose
  and decompose, and the operations; pure, host-tested by
  `tools/src/transport_continuity_stack.rs`

## How it works

An anchor's operations become the per-layer continuity commands `ip` and
`tls` already answer (`session_ctrl.rs` §Transport continuity). At the
primary, the checkpoint is composed from the two per-layer records the
modules export at the cut; at the standby it is decomposed into the two they
import, into silent shadows, at EMISSION_ARM. ACTIVATE checks what it can
itself (armed, a fence, a higher epoch), rebuilds the per-flow token for its
own anchor, and activates `ip` and then `tls` only on the authority's verdict.
A crash-continuous primary pairs both halves strict and, after its quiesced
checkpoint, turns every per-layer delta into deltas under the horizon gate,
acknowledging a half's transition only once the standby holds the delta
covering it; a standby takes over from the checkpoint and the deltas alone.
`TOMBSTONE` installs `ip`'s tombstone for a flow the host never held. A
KeyUpdate under a crash-continuous pair is a `KeyUpdate` delta naming the next
secret by reference; the standby's `tls` derives it at import (the CT_TLS
record carries the epochs its sealed secret set is at). `CUSTODY_ATTEST` /
`CUSTODY_WRAP` / `CUSTODY_UNWRAP` move the flow's continuity key vault to
vault: the standby's `tls` attests a fresh recipient, the authority accepts the evidence, the primary's `tls` verifies it and wraps
the key to it, the standby's unwraps it — no key is ever in a frame. The map
between the records, and what is and is not enforced, is at the head of
`stack.rs`; `docs/architecture/network.md` §`TRANSPORT_CONTINUITY` over `ip`
and `tls` has the summary.

## Wiring

```yaml
  - from: ip.cont_out
    to: tc.ip_cont
  - from: tc.ip_ctl
    to: ip.cont_in
  - from: tls.cont_out
    to: tc.tls_cont
  - from: tc.tls_ctl
    to: tls.cont_in
```

and `tc_ctl` / `tc_evt` to the anchor, `key_in` / `key_out` to the custody
path that carries the wrapped continuity object (the TLS secret set, still
sealed by `tls`'s vault), `auth_rsp` / `auth_req` to the authority (the
token check `0xC2`/`0xC3`, the custody check `0xC4`/`0xC5`). Each port
takes only its own frames. Every port carries `[type:1][len:2 LE][payload]`.

## Parameters

- `anchor_id` (str, 16 hex digits) — the anchor identity a per-flow emission
  token must name.

## Example

A graph places this module beside its `ip` (over `linux_eth` on Linux) and
`tls`, wired as above; the anchor, the custody path and the authority are the
deployment's. The same graph runs as primary on one host and standby on
another: a planned move, a crash takeover (with whole 16 KiB records under
the horizons), and a connection the client half-closed (`tls`'s
`half_close`) all move with no reset.
