# Security Architecture

Fluxor's security model follows the same principle as the rest of the
runtime: explicit boundaries, composable primitives, no hidden state. The
kernel is a small root of trust; everything else is a PIC module loaded
through a verifiable path. Cryptographic operations that must be
authoritative live in the kernel; everything else is a module anyone can
audit.

This document is the map. Individual mechanisms are documented alongside
their implementations.

## Themes

The security surface decomposes into four orthogonal concerns:

1. **Resource elasticity.** Network admission and per-connection limits,
   so a single adversary cannot exhaust a single module's table.
2. **Cryptographic trust chain.** How key material, certificates, and
   module binaries are authenticated from power-on onwards.
3. **Constant-time primitives.** Side-channel resistance in the core
   crypto paths (ECDSA, ECDH, AEAD).
4. **Network stack hardening.** Reorder buffering, congestion control,
   ARP/DHCP hygiene, step-split for long crypto.

Theme 3 is a property of the `modules/sdk/crypto/` primitives used by
`modules/foundation/tls/`; its rationale is in the source. The rest is
covered below.

## Trust Root and Module Admission

Source: `src/kernel/module/loader.rs`.

Every PIC module carries a manifest section (`magic = "FXMF"`)
containing a header, ports, resources, dependencies, a 32-byte
SHA-256 integrity hash over code+data, an optional 64-byte Ed25519
signature, and an optional 32-byte signer public-key fingerprint. The
signature/fingerprint pair is filled in by `fluxor modules sign`; an unsigned
manifest has those fields zeroed.

The loader path, implemented in `validate_module`:

1. Recompute SHA-256 over the in-image code and data sections.
2. Compare against the manifest's stored hash via
   `hal::verify_integrity` (`src/kernel/sys/hal.rs`). Mismatch →
   `IntegrityMismatch`.
3. If the manifest carries a signature (non-zero), read it together
   with the signer fingerprint. Read the device's signing public key
   (see key provisioning below). Run the kernel's own Ed25519 verify
   (`src/kernel/security/crypto/ed25519.rs`) against the integrity
   hash. Mismatch → `SignatureInvalid`.
4. If the `enforce_signatures` cargo feature is set and the module is
   unsigned or the device has no provisioned pubkey, reject.

Key provisioning is build-time configuration, not a hardware mechanism:
`signing_pubkey_from_build_env` in the loader reads the
`FLUXOR_SIGNING_PUBKEY_HEX` environment variable at compile time (64 hex
chars → 32 bytes baked into the kernel image). It lives with its sole
consumer, the signature check, rather than in the generic HAL. A board
with an on-silicon OTP bank would replace this function without touching
the loader logic around it. Status: OTP-backed provisioning is a design
target, not wired.

### Load-source trust profiles

The loader records where a module table came from as a typed `LoadSource`
(`Flash` vs `Embedded`). The loader/platform combination implements these
trust profiles:

| Profile | Source | Integrity check | Signature check | Used by |
|---|---|---|---|---|
| **Trusted built-in** | Compiled-in `BuiltInModule` (e.g. `linux_net`, `wasm_browser_canvas`) | n/a — code is in the kernel image | n/a | Linux/WASM host built-ins; bypass the loader entirely |
| **Signed flash image** | RP / Pi 5 flash, packed `.fmod` table | `hal::verify_integrity` runs SHA-256 over code+data; mismatch → `IntegrityMismatch` | If signature present, Ed25519 verify; if absent and `enforce_signatures` set, reject | Production RP2350 + Pi 5 firmware images |
| **Embedded blob** | WASM `EMBEDDED_MODULES_BLOB`, Linux `mmap`'d `.fmod` file | `hal::verify_integrity` byte-compares SHA-256 on every platform | Same as flash image when present | Linux dev runs, WASM bundles |
| **Network / staged** | TFTP / OTA delivered image into a staging area then promoted | Same as flash image once promoted | Same | See [reconfigure.md](reconfigure.md) and [network_boot.md](network_boot.md) for the staged-image model |

Per-source signature policy (for example, always requiring a signature on
network-staged images) lives in the platform-side code that calls
`init_from_blob`; the loader applies the same integrity and signature
checks to every non-built-in source.

### Signing Tool

`fluxor modules sign <module.fmod> --key <seed>` rewrites the `.fmod` with a
manifest carrying a fresh signature. The tool uses the same Ed25519 code as
the kernel verifier, so a kernel rebuilt from source and a tool-signed
module always agree. The private key is a raw 32-byte seed on disk
(`head -c 32 /dev/urandom > key.raw`).

### Crypto in the admission path

Source: `src/kernel/security/crypto/`.

Both hashes and the signature check run on kernel-owned code with no
external crypto crates. SHA-256 and SHA-512 are `include!` shims over the
single-source SDK implementations in `modules/sdk/crypto/`, so the kernel
and module sides cannot drift. The Ed25519 + SHA-512 verifier is written
in-tree because it is the root of trust: nothing else in the image can be
trusted until verify returns true, and pulling an external crate into that
path widens the supply chain that must be reviewed. The field arithmetic
ports the 16-limb signed-radix representation from TweetNaCl (public
domain); the implementation conforms to RFC 8032.

## KEY_VAULT (contract id `0x0010`)

Source: `modules/sdk/contracts/key_vault.rs` (contract),
`src/kernel/security/key_vault.rs` (software backend).

A kernel-managed asymmetric-key store. Every slot names its **suite** —
P-256, Ed25519, or one of the three ML-DSA parameter sets — and the suite
decides what the key bytes mean, which operations the slot admits, and how
big each answer is. Opcodes:

| Opcode | Name | Semantics |
|--------|------|-----------|
| `0x1000` | `PROBE` | Returns 1 if a backend is present. Callers detect at `module_new`. |
| `0x1001` | `STORE` | Import a raw private key of the named suite. Returns an opaque handle. |
| `0x1002` | `ECDH` | Compute scalar mult against a caller-supplied public key. |
| `0x1003` | `SIGN` | Sign under the slot's suite, in the sign mode that suite uses. |
| `0x1004` | `VERIFY` | Verify — takes a caller-supplied public key. |
| `0x1005` | `DESTROY` | Zeroise and free the slot. |
| `0x1006` | `GENERATE` | Generate a key in-backend; the private half never exists outside it. |
| `0x1007` | `PUBLIC` | Export the public half of a slot's key. |
| `0x1008` | `TIER` | Report the backend tier (software vs hardware-backed). |
| `0x1009` | `OPEN_OR_GENERATE` | Open the slot filed under a label, generating it if absent. |
| `0x100A` | `OPEN` | Open the slot filed under a label. |
| `0x100B` | `DESTROY_BY_LABEL` | Zeroise and free the slot filed under a label. |
| `0x100C` | `DESCRIBE` | Report a slot's suite, usage mask and label. |
| `0x100D` | `SUITE_QUERY` | Report a suite's usage mask and its private, public and signature lengths. |
| `0x100E` | `SUITE_ENUM` | Enumerate the suites this backend supports. |

Sizes come from `SUITE_QUERY` rather than from a caller's assumption,
because they are no longer uniform: an ML-DSA-87 signature is 4627 bytes
where a P-256 or Ed25519 one is 64. The private length a backend reports is
what it actually holds, which is not always the algorithm's encoded private
key — the software backend holds an ML-DSA key as the 32-byte FIPS 204 seed
that reproduces it, so it reports 32 and a caller with an already-expanded
key learns from that number that it cannot import one here.

The software backend's slot table holds 8 slots of up to 64 bytes each — a
seed or a scalar, never an expanded key. `reset_all()` zeroises every slot
on scheduler reset. Slot contents are never surfaced through any
introspection API. Crypto runs against the kernel-side
`src/kernel/security/crypto/`: `p256.rs` (field/group/scalar ops plus
HMAC-SHA256 for the RFC 6979 nonce), `ed25519.rs`, and `ml_dsa.rs` over
`sha3.rs`.

ML-DSA is a per-target capability, the `pq-vault` Cargo feature. Its
polynomial scratch is a backend static dimensioned for the widest parameter
set — a signing operation needs more of it than the stack any caller
arrives on — and that is ~58 KB of kernel `.bss`, which an RP-class part
with 256 KB of SRAM does not have to spare. A kernel built without
`pq-vault` reports the ML-DSA suites as unsupported: `SUITE_QUERY` answers
`ENOSYS` and `SUITE_ENUM` omits them, so a caller discovers the absence
before it allocates rather than by storing a key the backend could not then
sign with. Every length, usage mask and enumeration flows from one gate, so
the suites cannot be half-present.

The backend is platform-overridable: the Linux platform registers a
PKCS#11 HSM backend (`src/platform/linux/hsm_key_vault.rs`) when
`FLUXOR_HSM_PKCS11_MODULE` is set at platform boot. It is compiled into
the published runtime (the `host-hsm` feature), so selecting it is a
matter of configuration; a binary built without the feature reports the
absence through `--print-features`. Registration is fail-soft — a
configured token that cannot be opened leaves the software backend live
rather than failing the boot, and `TIER` is what says which one answered.
The consumer-visible opcode surface is identical; backends differ only in
what `TIER` and `SUITE_QUERY` report. See [abi_layers.md](abi_layers.md)
for the backend rules.

### TLS integration

At `module_new` the TLS module issues `PROBE`. If the vault is present
and an identity key is configured, it calls `STORE`, records the slot
handle, and then wipes the in-module key bytes with volatile writes, so
`CertificateVerify` signs only through the vault (`SIGN`). The in-module
path is retained only as the explicit not-present fallback — a module
arena dump on a vault-enabled build does not reveal the identity key.

## Network Hardening

### conn_guard — TCP-SYN admission

Source: `modules/foundation/conn_guard/mod.rs`.

`conn_guard` sits between the NIC driver and the IP module on the RX path:

```
rp1_gem.frames_rx → conn_guard.frames_rx → ip.frames_rx
```

For each frame it parses Ethernet + IPv4 + TCP just enough to identify
pure SYNs (SYN set, ACK clear). A fixed-size per-source-IP counter table
(default 32 entries) tracks SYNs within a sliding `rate_window_ms` (1 s
default). When a source exceeds `rate_limit_per_ip` SYNs in a window
(default 16) the SYN is dropped; everything else (non-TCP, non-SYN,
within-budget traffic) passes through unchanged. The table evicts the
least-recently-touched entry on a full insert, so a flood from one source
cannot starve unrelated peers.

The `stacks/net.toml` entry for the Pi 5 ethernet variant injects
`conn_guard` between `rp1_gem` and `ip` automatically — HTTP/HTTPS YAML
configs pick it up without any per-config wiring.

### IP module MAC discipline

The IP module requires drivers to announce their MAC explicitly (an
ethertype-0 frame from the driver on connect). Absent an announcement,
inbound frames are discarded rather than used to infer the MAC — a
forged ARP or misconfigured peer cannot drive the stack to adopt an
arbitrary identity.

### ARP and DHCP hardening

Source: `modules/foundation/ip/arp.rs`, `modules/foundation/ip/dhcp.rs`.

- ARP gratuitous-reply defence: unsolicited claims on our IP from a
  different MAC trigger a gratuitous reply asserting our binding plus a
  `MSG_ERROR` to the consumer.
- DHCP transaction-ID and lease-source validation; servers outside the
  initially-chosen one are ignored for the rest of the session.

### Reorder buffer, NewReno, dynamic receive window

TCP-side resilience: bounded reorder buffer, NewReno congestion control
with fast-retransmit on triple-dup-ack, and a rcv_wnd that tracks
consumer-side read pressure. These are standard RFC-conformant behaviour
and are described at the top of `modules/foundation/ip/tcp.rs`.

### Step-split ECDH

The TLS module's P-256 scalar multiplication is broken into chunks so a
single handshake cannot block a second concurrent handshake for the full
duration of its ladder. `modules/sdk/crypto/p256.rs::ScalarMulState`
tracks the ladder position; the key-derivation pump initialises it on
first entry, advances `bits_per_step` ladder bits per pump tick, and
finalises once the ladder completes. The `tls` module exposes an
`ecdh_bits_per_step` parameter (default 256 — full ladder in one call,
appropriate for bcm2712; drop to 64 on slower silicon).

### TLS-level retransmit retention

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
  - {name: demux, domain: nic}
  - {name: ip_0, type: ip, domain: lane0}
  - {name: tls_0, type: tls, domain: lane0}
  - {name: ip_1, type: ip, domain: lane1}
  - {name: tls_1, type: tls, domain: lane1}
```

`modules/foundation/demux/` 4-tuple-hashes inbound TCP/IPv4 frames to
one of two lanes (preserving connection affinity) and broadcasts
control-plane traffic (ARP, DHCP) to both. Each TLS instance loads its
own copy of the identity key material — key material is not shared
across lanes.

## Platform Hooks

- `hal::verify_integrity(&[u8], &[u8])` (`src/kernel/sys/hal.rs`) —
  byte-compare of a computed hash against a stored one, exercised on
  every module admission on every silicon.
- `kernel::dtb::read_ethernet_mac()` (`src/kernel/boot/dtb.rs`) — reads
  the `local-mac-address` property from the firmware-provided DTB. The
  rp1_gem driver consults this first and only falls back to its
  locally-administered default on failure, so no two Pi 5s share an
  on-wire MAC.

## Operational Notes

- Netboot infrastructure on a shared LAN should run its DHCP service in
  proxy mode (advertising PXE/TFTP options only, never handing out
  leases) so it cannot disrupt the production network's address
  assignment.

## Cryptography ownership

Two crypto bodies exist by design:

- **Kernel** (`src/kernel/security/crypto/`) — the loader/key-vault
  root of trust. The loader's signature check runs *before* any PIC module
  is admitted, so this code cannot depend on modules or external crates,
  and it stays readable and portable in preference to fast (an Ed25519
  verify runs at most once per module load).
- **SDK** (`modules/sdk/crypto/`) — module-side crypto for protocol
  workloads (TLS, QUIC), NEON-accelerated where it pays.

The rule: where an implementation is identical, it has one source (kernel
`sha256.rs`, `sha512.rs`, `sha3.rs` and `ml_dsa.rs` are `include!` shims
over the SDK files — the two sides cannot drift); where the trust domain
demands divergence, the duplication is deliberate (Ed25519 and P-256
differ: the kernel versions are minimal and audit-oriented, the SDK
versions carry protocol-driven surface such as incremental ECDSA). Every
kernel primitive is load-bearing: `ed25519` backs the loader signature
verify, `p256` the key-vault ECDSA/ECDH, `sha512` the Ed25519 inner hash,
`ml_dsa` the vault's post-quantum signing and `sha3` the SHAKE stream it
expands everything from. If a kernel primitive and its SDK counterpart
converge to the same surface, they merge to one source per the rule.

ML-DSA and SHA-3 are shared rather than duplicated for a reason particular
to them: the vault signs with the same file a TLS module verifies with, so
a disagreement between signer and verifier over FIPS 204 or FIPS 202 is not
expressible. Both files derive their constants — Keccak's round constants
and rho offsets from the FIPS 202 recurrences, the NTT twiddles from
ζ = 1753 — instead of shipping the tables a reference implementation would,
because a position-independent module cannot relocate an absolute address in
`.rodata`. See `modules/sdk/crypto/p256.rs` for the same constraint solved
the same way.

## Related Documentation

- [module_architecture.md](module_architecture.md) — module binary format,
  manifest layout, loader lifecycle.
- [network.md](network.md) — net_proto, IP/TLS modules, consumer pattern.
- [network_boot.md](network_boot.md) — bundle signing, trust root,
  deployment flow.
- [abi_layers.md](abi_layers.md) — ABI layer boundaries, contract
  inventory, KEY_VAULT position.
- [hal_architecture.md](hal_architecture.md) — HAL boundaries and hooks.

## Composition Attestation and Key Custody

Source: `src/kernel/exec/scheduler/attest.rs`,
`src/kernel/security/key_vault.rs`, contract
`modules/sdk/contracts/key_vault.rs` (0x100F–0x1013).

The vault can sign what the kernel is running. `ATTEST_COMPOSITION`
builds the running-composition record from what the kernel holds — the
boot incarnation, the caller's challenge, the kernel's ABI-surface
digest, the SHA-256 of every loaded module blob with its size, every
instantiated module's name and parameter digest, every graph edge — ends
it with the vault's tier byte, and signs it with the named slot in that
suite's convention. The challenge makes an answer unreplayable; the
incarnation makes it unable to outlive the boot; the tier byte says what
the signature is worth (`DEVICE_HW`: this hardware runs exactly this
closure; `SOFTWARE`: a process that could be read does). The
**composition digest** — the record with the challenge zeroed — is the
composition's identity independent of who asked. None of this proves the
closure correct or authorised; it proves bytes and wiring.

Keys move between vaults only wrapped. `KEY_WRAP` seals a slot that
permits `usage::WRAP` for one destination: an ephemeral P-256 agreement
with the destination vault's public key, HKDF-SHA256 salted by the
destination's composition digest, ChaCha20-Poly1305 with that digest as
the associated data. `KEY_UNWRAP` on the destination recomputes its own
composition digest first and refuses when it differs — the key was
wrapped for the composition that was attested, and this is no longer it.
No surface ever carries the key in the clear.

`AEAD_SEAL` / `AEAD_OPEN` on a `suite::AEAD_KEY` slot are the vault-held
sealing primitive: a fresh CSPRNG nonce per call, the key never leaving.
The quic module's resumption tickets are its first consumer — the ticket
is the session state sealed under a labelled vault key, two generations
alternating by parity so rotation never strands a live ticket, replay
refused against a small ring of accepted digests; a fleet that shares the
labelled keys through `KEY_WRAP` opens each other's tickets. Whether
early data is admitted on a resumed handshake is a separate decision
(`enable_0rtt`); the ticket itself only ever buys a one-round-trip
resumption.

`BOOT_INCARNATION` (`kernel_abi`, 16 CSPRNG bytes per boot) is the value
any boot-bound token mixes in, so a token from a previous life of the
host is unmatchable by construction.

