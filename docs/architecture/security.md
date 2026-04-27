# Security Architecture

Fluxor's security model follows the same principle as the rest of the
runtime: explicit boundaries, composable primitives, no hidden state. The
kernel is a small root of trust; everything else is a PIC module loaded
through a verifiable path. Cryptographic operations that must be
authoritative live in the kernel; everything else is a module anyone can
audit.

This document is the authoritative reference for how those pieces fit
together. Individual mechanisms are documented alongside their
implementations; this is the map.

## Themes

The security surface decomposes into four orthogonal concerns:

1. **Resource elasticity.** Network admission and per-connection limits —
   so a single adversary cannot exhaust a single module's table.
2. **Cryptographic trust chain.** How key material, certificates, and
   module binaries are authenticated from power-on onwards.
3. **Constant-time primitives.** Side-channel resistance in the core
   crypto paths (ECDSA, ECDH, AEAD).
4. **Network stack hardening.** Reorder buffering, congestion control,
   ARP/DHCP hygiene, step-split for long crypto.

Theme 3 (constant-time primitives) is a property of the
`modules/foundation/tls/` crypto modules; its rationale is in the source.
The rest is covered below.

## Trust Root and Module Admission

Every PIC module carries a manifest section (`magic = "FXMF"`). Two
versions exist:

- **v1** — 16-byte header, ports, resources, dependencies, and an
  optional 32-byte SHA-256 integrity hash over code+data.
- **v2** — same as v1 plus a 64-byte Ed25519 signature over the integrity
  hash and a 32-byte signer public-key fingerprint.

The loader path, implemented in `src/kernel/loader.rs::validate_module`:

1. Recompute SHA-256 over the in-image code and data sections.
2. Compare against the manifest's stored hash via
   `hal::verify_integrity`. Mismatch → `IntegrityMismatch`.
3. If the manifest is v2, read the Ed25519 signature + signer
   fingerprint. Fetch the device's signing public key via
   `hal::otp_read_signing_key`. Run the kernel's hand-rolled Ed25519
   verify (`src/kernel/crypto/ed25519.rs`) against the integrity hash.
   Mismatch → `SignatureInvalid`.
4. If the `enforce_signatures` cargo feature is set and the module is
   unsigned or the device has no provisioned pubkey, reject.

The pubkey provisioning path is deliberately HAL-level. On CM5 today it
comes from the `FLUXOR_SIGNING_PUBKEY_HEX` build-time environment
variable (baked into the kernel image); future boards are expected to
read it from an on-silicon OTP bank, and the HAL keeps the loader
oblivious to which mechanism is in use.

### Signing Tool

`fluxor sign <module.fmod> --key <seed>` rewrites the `.fmod` with a v2
manifest carrying a fresh signature. The tool uses the same hand-rolled
Ed25519 code as the kernel verifier, so a kernel-rebuilt-from-source and
a tool-signed module always agree. The private key is a raw 32-byte seed
on disk (`head -c 32 /dev/urandom > key.raw`).

### Integrity hash: kernel-crate SHA-256; signature: kernel-crate
hand-rolled Ed25519/SHA-512

SHA-256 is computed via the `sha2` crate already in the kernel (it also
backs ECDSA hashing). The Ed25519 + SHA-512 verifier is hand-written
from scratch — no external crypto dependencies — because it is the root
of trust: nothing else in the image can be trusted until verify returns
true, and pulling an external crate into that path widens the supply
chain that must be reviewed. The implementation ports the 16-limb
signed-radix field arithmetic from TweetNaCl (public domain) and runs
in-tree unit tests against RFC 8032 vectors 1–3.

### Acceptance

A tamper of one byte in a signed module's code section is rejected at
boot; the loader logs `integrity mismatch`, instantiates 4-of-5
modules, and HTTPS becomes unreachable. The clean build boots and
serves HTTPS normally.

## KEY_VAULT (device class `0x10`)

A kernel-managed asymmetric-key store, mounted at device class 0x10.
Opcodes:

| Opcode | Name | Semantics |
|--------|------|-----------|
| `0x1000` | `PROBE` | Returns 1 if the vault is present. Callers detect at `module_new`. |
| `0x1001` | `STORE` | Deposit a raw P-256 scalar. Returns an opaque handle. |
| `0x1002` | `ECDH` | Compute scalar mult against a caller-supplied public key. |
| `0x1003` | `SIGN` | Deterministic ECDSA (RFC 6979 nonce). |
| `0x1004` | `VERIFY` | ECDSA verify — takes a caller-supplied public key. |
| `0x1005` | `DESTROY` | Zeroise and free the slot. |

The slot table holds 8 slots of up to 64 bytes each. `reset_all()`
zeroises every slot on scheduler reset. Slot contents are never surfaced
through any introspection API. Crypto runs against the kernel-side
`src/kernel/crypto/p256.rs` (field/group/scalar ops + HMAC-SHA256 for
the RFC 6979 nonce).

### TLS integration

At `module_new` the TLS module issues `PROBE`. If the vault is present
and an identity key is configured, it calls `STORE`, records the slot
handle, and then wipes the in-module key bytes:

```rust
if h >= 0 {
    s.key_vault_handle = h;
    // Vault is now authoritative. Wipe in-module key so CertificateVerify
    // signs only through the vault.
    let mut j = 0;
    while j < s.key_len { core::ptr::write_volatile(&mut s.key[j], 0); j += 1; }
    s.key_len = 0;
}
```

`pump_send_certificate_verify` then signs via `OP_SIGN`. The in-module
path is retained only as the explicit not-present fallback — a module
arena dump on a vault-enabled build will not reveal the identity key.

## Network Hardening

### conn_guard — TCP-SYN admission

`modules/foundation/conn_guard/` sits between the NIC driver and the IP
module on the RX path:

```
rp1_gem.frames_rx → conn_guard.frames_rx → ip.frames_rx
```

For each frame it parses Ethernet + IPv4 + TCP just enough to identify
pure SYNs (SYN set, ACK clear). A fixed-size per-source-IP counter table
(default 32 entries) tracks SYNs within a sliding `rate_window_ms` (1 s
default). When a source exceeds `rate_limit_per_ip` SYNs in a window the
SYN is dropped; everything else (non-TCP, non-SYN, within-budget
traffic) passes through unchanged. The table evicts the least-recently-
touched entry on a full insert — so a flood from one source cannot
starve unrelated peers.

The `stacks/net.toml` entry for the CM5 ethernet variant injects
`conn_guard` between `rp1_gem` and `ip` automatically — HTTP/HTTPS YAML
configs pick it up without any per-config wiring.

### IP module MAC discipline

The IP module requires drivers to announce their MAC explicitly (an
ethertype-0 frame from the driver on connect). Absent an announcement,
inbound frames are discarded rather than used to infer the MAC — a
forged ARP or misconfigured peer cannot drive the stack to adopt an
arbitrary identity.

### ARP and DHCP hardening

Documented inline in `modules/foundation/ip/{arp,dhcp}.rs`:

- ARP gratuitous-reply defence: unsolicited claims on our IP from a
  different MAC trigger a gratuitous reply asserting our binding plus a
  `MSG_ERROR` to the consumer.
- DHCP transaction-ID and lease-source validation; servers outside the
  initially-chosen one are ignored for the rest of the session.

### Reorder buffer, NewReno, dynamic receive window

TCP-side robustness: bounded reorder buffer (`modules/foundation/ip/tcp.rs`),
NewReno congestion control with fast-retransmit on triple-dup-ack, and a
rcv_wnd that tracks consumer-side read pressure. These are standard
RFC-compliant behaviour and are described at the top of `tcp.rs`.

### Step-split ECDH

The TLS module's P-256 scalar multiplication is broken into chunks so a
single handshake cannot block a second concurrent handshake for the full
duration of its ladder. `modules/sdk/p256.rs::ScalarMulState`
tracks `bit_index` and `bits_per_step`; `pump_derive_handshake_keys`
initialises on first entry, advances `bits_per_step` ladder bits per
pump tick, and finalises once the ladder completes. The `tls` module
exposes an `ecdh_bits_per_step` parameter (default 256 — full ladder in
one call, appropriate for bcm2712; drop to 64 on slower silicon).

### TLS-level retransmit retention (§1.3)

The IP module does not retain TCP segments for retransmission — that
would duplicate state between IP and TLS. Instead it signals the
consumer:

- `MSG_ACK(conn_id, acked_seq)` — advance your ACK watermark.
- `MSG_RETRANSMIT(conn_id, from_seq)` — replay data from this sequence.

The TLS module holds each emitted ciphertext record in a per-session
`retx_buf` (default 4 KB). On `MSG_ACK` the buffer is truncated up to
the absolute TCP sequence number (the first ACK anchors `retx_base_seq`
so subsequent deltas are unambiguous). On `MSG_RETRANSMIT` the tail is
re-emitted as a new `CMD_SEND` frame — no re-encryption, just re-delivery
of the ciphertext the peer is expecting.

## Horizontal Scaling and Trust Domains

Because Fluxor's scaling answer is "more modules, not more threads", a
multi-lane HTTPS deployment is:

```yaml
modules:
  - name: demux, domain: nic
  - name: ip_0, type: ip, domain: lane0
  - name: tls_0, type: tls, domain: lane0
  - name: ip_1, type: ip, domain: lane1
  - name: tls_1, type: tls, domain: lane1
```

`modules/foundation/demux/` 4-tuple-hashes inbound TCP/IPv4 frames to
one of two lanes (preserving connection affinity) and broadcasts
control-plane traffic (ARP, DHCP) to both. Each TLS instance loads its
own copy of the identity key material — key material is not shared
across lanes. See `examples/cm5/https_multilane.yaml` for a complete
config.

## Platform HAL Hooks

- `hal::otp_read_signing_key(&mut [u8; 32])` — returns the provisioned
  root-of-trust pubkey. Currently reads a compile-time constant from the
  `FLUXOR_SIGNING_PUBKEY_HEX` environment variable.
- `hal::verify_integrity(&[u8], &[u8])` — byte-compare of a computed
  hash against a stored one. Must be a real compare on every silicon
  (on bcm2712 this was briefly a stub; the loader now exercises it as
  part of every module admission).
- `kernel::dtb::read_ethernet_mac()` — reads the `local-mac-address`
  property from the firmware-provided DTB. The rp1_gem driver consults
  this first and only falls back to its locally-administered default on
  failure, so no two Pi 5s ever share an on-wire MAC.

## Operational Notes

- Test-rig DHCP: Running `dnsmasq` as a DHCP server on a shared LAN is a
  production-network hazard. The rig config ships in proxy-DHCP mode —
  dnsmasq advertises PXE/TFTP options only and never hands out leases.
  Do not add a non-proxy `dhcp-range` to any config on a shared
  interface; see the safety note in `docs/guides/pi5-bare-metal.md` (§ Dev host setup: dnsmasq).
- `sudo ip neigh` static entries are host-local and do not leak onto
  the LAN, but they will misdirect traffic on the originating host if
  the target IP is reassigned.

## Related Documentation

- `architecture/module_architecture.md` — module binary format, manifest
  layout, loader lifecycle.
- `architecture/network.md` — net_proto, IP/TLS modules, consumer
  pattern.
- `architecture/network_boot.md` — bundle signing, trust root,
  deployment flow.
- `architecture/abi_layers.md` — ABI layer boundaries, contract
  inventory, KEY_VAULT position.
- `architecture/hal_architecture.md` — HAL boundaries, OTP and DTB
  hooks.
