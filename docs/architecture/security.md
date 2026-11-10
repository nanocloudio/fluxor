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
the loader's `MODULE_SIGNING_ROOT` is the `FLUXOR_SIGNING_PUBKEY_HEX`
environment variable, parsed at compile time (64 hex digits → 32 bytes
baked into the kernel image). A value that is not 64 hex digits fails the
build rather than producing a kernel that verifies nothing. The key lives
with its sole consumer, the signature check, rather than in the generic
HAL. No board reads it from OTP.

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
manifest carrying a fresh RFC 8032 Ed25519 signature. The private key is a
raw 32-byte seed on disk; `fluxor modules keygen --key <seed>` creates one
(mode 0600) and prints its public key, the value for
`FLUXOR_SIGNING_PUBKEY_HEX`.

### Graph-image signatures

Source: `src/kernel/security/slot_signature.rs`.

A graph image — what an RP flash slot holds and what the Pi 5 stages in RAM
— can carry an Ed25519 signature over its header, which names the payload
by its SHA-256. A kernel built with `FLUXOR_SLOT_ROOT_HEX` (a public key,
64 hex digits; any other value fails the build) boots, stages and
activates only images signed by that key whose payload matches the
digest. This root is separate from the module signing root: one vouches
for individual modules, the other for a whole graph. The image format,
the signing command and what is refused are in
[network_boot.md](network_boot.md#graph-image-signatures).

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

## KEY_VAULT (contract id `0x0005`)

Source: `modules/sdk/contracts/key_vault.rs` (contract),
`src/kernel/security/key_vault.rs` (software backend).

The kernel's opaque key custody, for asymmetric and symmetric keys alike.
Every slot names its **suite**:
- P-256, Ed25519, one of the three ML-DSA parameter sets, or RSA at 2048,
  3072 or 4096 bits;
- `AEAD_KEY` (ChaCha20-Poly1305), `AEAD_AES256_GCM`, or `HMAC_SHA256`;
- `KDF_KEY`, a derivation master whose only use is `DERIVE`.

`AEAD_AES256_GCM` is offered only where AES runs in constant time (aarch64
with the AES extension); elsewhere `SUITE_QUERY` answers `ENOSYS`.

The suite decides what the key bytes mean, which operations the slot admits,
and how big each answer is. Opcodes:

| Opcode | Name | Semantics |
|--------|------|-----------|
| `0x0500` | `PROBE` | Returns 1 if a backend is present. Callers detect at `module_new`. |
| `0x0501` | `STORE` | Import a raw private key of the named suite. Returns an opaque handle. |
| `0x0502` | `ECDH` | Compute scalar mult against a caller-supplied public key. |
| `0x0503` | `SIGN` | Sign under the slot's suite, in the sign mode that suite uses. |
| `0x0504` | `VERIFY` | Verify — takes a caller-supplied public key. |
| `0x0505` | `DESTROY` | Zeroise and free the slot. |
| `0x0506` | `GENERATE` | Generate a key in-backend; the private half never exists outside it. |
| `0x0507` | `PUBLIC` | Export the public half of a slot's key. |
| `0x0508` | `TIER` | Report the backend tier (software vs hardware-backed). |
| `0x0509` | `OPEN_OR_GENERATE` | Open the slot filed under a label, generating it if absent. |
| `0x050A` | `OPEN` | Open the slot filed under a label. |
| `0x050B` | `DESTROY_BY_LABEL` | Zeroise and free the slot filed under a label, and remove its sealed record. |
| `0x050C` | `DESCRIBE` | Report a slot's suite, usage mask, tier and whether it is persisted. |
| `0x050D` | `SUITE_QUERY` | Report a suite's usage mask and its private, public and signature lengths. |
| `0x050E` | `SUITE_ENUM` | Enumerate the suites this backend supports. |
| `0x050F` | `ATTEST_COMPOSITION` | Sign the running-composition record (§ Composition Attestation). |
| `0x0510` | `KEY_WRAP` | Wrap a slot's key for one destination composition. |
| `0x0511` | `KEY_UNWRAP` | Unwrap into a new slot, only as the composition it was wrapped for. |
| `0x0512` | `AEAD_SEAL` | Seal under an `AEAD_KEY` slot. |
| `0x0513` | `AEAD_OPEN` | Open under an `AEAD_KEY` slot. |
| `0x0514` | `DERIVE` | Make a purpose key from a `KDF_KEY`: HKDF-SHA256 over a label and context, never persisted. |
| `0x0515` | `AEAD_SEAL_UNITS` | Seal up to 32 buffers in place, each under the nonce its caller names. |
| `0x0516` | `AEAD_OPEN_UNITS` | Open up to 32 buffers in place; a buffer that fails is zeroed and reported. |
| `0x0517` | `SHARE_SPLIT` | Split a 32-byte symmetric key 2-of-3 and seal each share to its own recipient. |
| `0x0518` | `SHARE_REWRAP` | Open one share envelope and seal the share to a new recipient under a new grant. |
| `0x0519` | `SHARE_COMBINE` | Open two share envelopes and reconstruct their key into a new, never-persisted handle. |
| `0x051A` | `ATTEST_KEY` | Sign challenge-bound evidence of a key's suite, uses, owner and tier, and a commitment to it. |

`AEAD_SEAL` draws a random nonce per call, which suits a record now and then.
The unit operations take the caller's nonces, which is what a storage device
writing under one key for years needs: its nonce domain is a reserved,
monotone sequence that it owns. The key is owned by that one module, so no
other module can seal under it.

### Recovery shares

A symmetric key that must outlive any one node leaves the vault only as
shares. `SHARE_SPLIT` splits it 2-of-3 over GF(2^8) and seals each share in
an envelope to one recipient's P-256 key. The envelope authenticates:
- the recovery set, protected resource and key epoch;
- the share index, threshold and recipient thumbprint;
- the purpose, lease fence, expiry and policy digest;
- an anti-replay id.

A custodian releases its share with `SHARE_REWRAP`. This seals the share to
a new recipient under a new purpose, fence, expiry and policy. The share's
set, resource, epoch and index cannot be changed.

`SHARE_COMBINE` opens two envelopes with the caller's own recipient keys
and reconstructs the key into a handle the caller owns. That handle is
never persisted. The operation refuses:

| Refused | Answer |
| --- | --- |
| An envelope wrapped to another key | `EACCES` |
| An envelope already used (the last 32 are remembered) | `EACCES` |
| An expired envelope, or one with an expiry the platform clock cannot check | `EACCES` |
| A resource or epoch other than the one the caller asked for | `EACCES` |
| Shares of different sets, resources or epochs | `EINVAL` |
| The same index twice | `EINVAL` |

Neither a share nor the key is ever written to a caller.

`ATTEST_KEY` signs a record with one of the caller's signing keys. The
record carries:
- the caller's challenge;
- the composition digest;
- the key's backend, tier, persistence, suite, uses and owner namespace;
- a commitment to the key, HMAC-SHA256 under the key itself, so the same
  key always commits the same way and the commitment reveals nothing of it.

The envelope and record layouts are the contract's `share` and `attest_key`
modules.

### Handles, owners and labels

- **Handles.** A handle names one key for one module. It carries its slot's
  generation, bumped when the key is destroyed, so a handle to a destroyed
  key answers `ENOENT` rather than reaching the slot's next key.
- **Owners.** The slot records the module that created the key: its
  scheduler slot and that slot's occupancy. Any other module is refused
  `EACCES`, including a later module in the same slot. A module's channel
  ioctl handler runs as that module, so the handles it holds work in the
  handler as in its step.
- **Labels.** Labels live in their owner's module-type namespace within the
  owner's realm: the node's, or one workload's (its durable owner uid). No
  module reaches another type's labels, nor another realm's: two workloads
  running one module type, and a workload and the node, hold different keys
  under one label. A reopen must name the key's suite and may not widen its
  uses. A label open in another instance of the same type and realm is
  refused `EBUSY`.

### Persisted keys

A labelled key asked to persist is sealed through the platform HAL.
- **The record.** The header (namespace, label, suite and usage) is the
  seal's associated data, so a record altered at rest does not open as
  anything.
- **Durability.** On a platform with a durable store, a record that could
  not be written durably refuses the key rather than reporting it persisted.
  Linux writes a temporary file, flushes it, renames it, and flushes the
  directory.
- **Where records live.** In a graph that wires a `vault_store` module, on
  whatever `storage.block` source it is wired to: one implementation for every
  board (`modules/foundation/vault_store/README.md`, wire contract
  `abi::internal::vault_store`). The records are one `FXVS` image in kernel
  RAM; the module keeps it in two A/B slots, writing each new image to the
  slot not holding the durable one and flushing before it reports it, so a
  power cut leaves the previous image whole. Each image carries a sequence
  number and a SHA-256 over itself, and a load takes the valid image with the
  higher sequence. Without one: on Linux, one file per label under
  `FLUXOR_VAULT_DIR`, or `vault/` under `FLUXOR_STORE_DIR`; on a bare-metal
  board, nowhere — keys serve the boot that made them, and `DESCRIBE`
  reports them unpersisted. On a Pi 5 the store is a file on the board's
  FAT32 (`file_block` under the `fat32` on `nvme.blocks`); a graph with
  nothing else on `nvme.blocks` can use the first 32 KiB of the NVMe's
  External backing space instead, which every arena leaves free:
  `start_sector: 2097152`, `sector_count: 64`, `image: 16384`.
- **Waiting for the medium.** A key made with `PERSIST` through a
  `vault_store` is in the image at once and on the medium only once the module
  reports it. Until then the open that made it, and every open of it, answers
  `EAGAIN`; asked again, the same key is answered. A destroy answers `EAGAIN`
  until the medium no longer holds the record; asked again after that, the
  label names nothing and the answer is `ENOENT`. A write the medium refuses
  answers the waiting opens `ERROR`, and the module retries.
- **Sealing.** `vault_store`'s `seal` names it. `hardware` (the default):
  records are sealed through the platform HAL — ChaCha20-Poly1305 under a key
  derived from the Pi 5's OTP device key, or the RP2350's OTP seal key once
  provisioned — and a board with no such key persists nothing and says so
  once. `none`: records are kept readable under `FXVC` (`FXVR` for a
  workload's), whoever holds the medium holds the keys, and `DESCRIBE`
  reports `persisted::CLEAR` with tier `SOFTWARE` (as does `TIER`), so a
  consumer that needs a key protected at rest refuses it. A sealed store
  never takes a readable record as a key: one found there is absent.
- **Destroy.** Destroying a label removes its record, so the key does not
  come back.
- **A workload's records.** Without a vault of its own a workload's record
  is kept in the platform's store under `FXVW`, its header followed by its
  realm, so it is authenticated to that workload and opens for no other. A
  workload given a vault (`workload::vault`, on a Linux graph workload) keeps
  its records in a directory on a volume it is lent instead, under `FXVK`,
  sealed with ChaCha20-Poly1305 under the key its owner supplied: they follow
  the volume and that key, not the node, `DESCRIBE` reports them `SOFTWARE`,
  and a record there that does not open is refused `EACCES` rather than
  replaced. See [scheduler.md](scheduler.md#a-workloads-own-vault).
- **Provisioning.** `fluxor-linux vault-import --module <type>` provisions a
  shared secret into a module type's namespace (the node's realm).

Sizes come from `SUITE_QUERY` rather than from a caller's assumption,
because they are not uniform: an ML-DSA-87 signature is 4627 bytes where a
P-256 or Ed25519 one is 64. The private length a backend reports is
what it actually holds, which is not always the algorithm's encoded private
key — the software backend holds an ML-DSA key as the 32-byte FIPS 204 seed
that reproduces it, so it reports 32 and a caller with an already-expanded
key learns from that number that it cannot import one here.

The software backend's slot table holds 64 slots on aarch64 and 8 elsewhere,
of up to 64 bytes each — a seed or a scalar, never an expanded key. With no
free slot, generate, import, open, derive and unwrap are refused `ENOMEM`.
A key is zeroised by `DESTROY`, and once its owning module is gone: when the
scheduler slot it was made in holds a new occupancy (restart, replacement or
graph rebuild), the vault zeroises the key before it next allocates a slot or
looks a label up. Slot contents are never surfaced through any introspection
API. Crypto runs against the kernel-side
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

RSA is the other per-target capability, the `rsa-vault` Cargo feature,
enabled wherever `pq-vault` is. An RSA slot's key is a PKCS#1
`RSAPrivateKey` with its CRT fields, held in one of two backend entries
with the Montgomery constants of its three moduli — about 22 KB of
`.bss` for both entries and the one signing job — and a slot names the
entry it holds. `STORE` admits any DER up to the width's reported
ceiling, checks `p·q = n` and the CRT fields, and prepares the moduli;
`PUBLIC` answers the `RSAPublicKey` DER at its exact length; `GENERATE`
is `ENOSYS` — the vault imports RSA keys and never mints them. `SIGN` is
RSASSA-PSS-SHA256 over a 32-byte digest with a 32-byte salt from the
kernel's entropy, and it is the vault's one resumable operation: a private
operation is milliseconds on the fastest target and the call runs inside
the caller's step, so the first `SIGN` starts a job and answers `EAGAIN`
after a bounded number of Montgomery rows, each further `SIGN` with the
same digest advances it, and the last answers the signature; another slot
or digest meanwhile is `EBUSY`. `VERIFY` is not extended to RSA: the tls
module verifies peers in-module and nothing calls the vault with a
certificate key.

### Backends and the router

Modules call one KEY_VAULT provider, the router
(`src/kernel/security/key_vault_router.rs`). It serves the software backend
and, on Linux when `FLUXOR_HSM_PKCS11_MODULE` is set at platform boot, a
PKCS#11 backend (`src/platform/linux/hsm_key_vault.rs`) beside it. The
PKCS#11 backend is compiled into the published runtime (the `host-hsm`
feature); a binary built without it reports the absence through
`--print-features`. Registration is fail-soft: a configured token that
cannot be opened leaves the software backend alone.

| Request | Served by |
| --- | --- |
| An operation on a handle | The backend that minted it; each backend resolves only its own handles |
| `GENERATE`, `SUITE_QUERY` for a suite the token serves (P-256) | The token |
| `OPEN`, `OPEN_OR_GENERATE` for a suite the token serves | Software if it holds the label, else the token if it does; a new key is made in the token when it is asked to `PERSIST` with uses the token permits, in software otherwise. A workload's: software alone, since the token's labels name no realm |
| `DESTROY_BY_LABEL` | Both: removed wherever the label is held (a workload's: software) |
| Other labels, `STORE`, symmetric and every other suite | Software |
| `TIER` | The token when present: the backend that holds identity keys |
| `SHARE_REWRAP`, `SHARE_COMBINE`, `ATTEST_KEY` | The router, reaching each key through `ECDH`, `PUBLIC`, `SIGN` and `DESCRIBE` on its own backend |

A key's own custody is its `DESCRIBE`. A volume key reconstructed from
shares opened by a token recipient key is a software session key:
- the agreed secrets cross only bounded kernel scratch, zeroed on every
  path;
- `DESCRIBE` and `ATTEST_KEY` report it `SOFTWARE`, never the token's tier.

The token's keys come in two lifetimes. An unlabelled `GENERATE` key is a
PKCS#11 session object, gone with the process whatever its mask says: it has
no name to be reopened by. A labelled key asked to `PERSIST` is a pair of
token objects (`CKA_TOKEN=true`, the private half sensitive and never
extractable), and a later process — a new session on the same token —
reopens it by the same name with the same public key:
- the name is the token's `CKA_LABEL`, `fluxor-kv/<namespace>/<label>` with
  the caller's module type as eight hex digits and the label in hex, so
  labels are per module type exactly as in software;
- the usage mask is sealed at creation into `CKA_ID`
  (`FXVK ‖ namespace:u32 ‖ suite:u16 ‖ usage:u32`, little-endian), both
  halves created `CKA_MODIFIABLE=false`, and every reopen CHECKS it: another
  suite or a wider mask is `EACCES`, never a widened key;
- the contract's other answers are the software backend's: `ENOENT` for
  `OPEN` of an absent label, `EBUSY` for a key another instance of the type
  holds open, `ENOMEM` with no slot, `ERANGE` before anything is made;
- lookup and creation run under the backend's one session lock, so within a
  process "is it there?" and "make it" are one step. PKCS#11 offers nothing
  across processes; a name the token holds two private keys under is refused
  rather than resolved by picking one;
- `DESCRIBE` reports it persisted; `DESTROY` frees its handle and leaves it
  on the token, and `DESTROY_BY_LABEL` removes both objects.

A share opener must permit `AGREE` and `EXPORT_PUBLIC`: the router names the
recipient by its public key. A token key cannot be split (`ENOSYS`), and its
attestation carries its public thumbprint and no commitment.

The software backend reports `DEVICE_HW` only when the platform's sealing
key is device-unique and the platform actually seals with it; a board that
reads a device key but cannot seal holds every key in RAM and reports
`SOFTWARE`. See [abi_layers.md](abi_layers.md) for the backend rules.

### TLS integration

A `tls` or `quic` instance takes its certificate chain, key and trust
anchors (`cert_file`, `key_file`, `trust`) from files it reads at
runtime, through the `fs` contract, when they are given as absolute paths
(modules/foundation/tls/cred_file.rs): on the Linux host a node graph
reads the host's paths and a workload reads beneath its owner root and the
volumes lent to it, so a workload image carries no credential and takes
its identity from a volume its node lends it. PEM or DER is accepted. Until every
named file has been read and validated the instance is not ready: a server
refuses each handshake before presenting anything, a client answers a dial
`EAGAIN` on the requester's tag, and a `quic` server drops new Initials
unanswered. A file that cannot be opened is retried every second; one that
is malformed — no PEM block of its kind, base64 that does not decode, an
encrypted key, a certificate that does not parse, a key of a suite the
instance cannot sign with — is refused and reported once per content, and
taken once fixed, with no restart. On aarch64 targets the files are re-read
every ten seconds: a changed set is adopted only when two consecutive reads
of every file agree (so a volume whose files are swapped all at once is never
taken half-old, half-new), then validated whole, and
installed between handshakes (at most two seconds' wait). A new key is
deposited in the vault and the old handle destroyed; anchors replaced under
a chain walk still stepping fail that walk rather than verify it against
another key. A rotation that does not validate keeps the credentials in
use. On Cortex-M targets the files are read once (there is no memory to
stage a second set beside the first), and a change takes a restart. The
build-time form, `${file:<path>}`, embeds the file instead, for targets
with no file surface at runtime; a Linux image refuses it, and a
credential named both ways refuses to construct.

At `module_new` the TLS module issues `PROBE`. If the vault is present
and an identity key is configured, it calls `STORE`, records the slot
handle, and then wipes the in-module key bytes with volatile writes, so
`CertificateVerify` signs only through the vault (`SIGN`). A key read
from `key_file` at runtime is deposited the same way when it is read. The in-module
path is retained only as the explicit not-present fallback — a module
arena dump on a vault-enabled build does not reveal the identity key.

An identity can also be born in the vault. With `identity_label` set, the
TLS module opens a P-256 key under that label, or generates and persists it
the first time (`OPEN_OR_GENERATE`), and the private half never exists
outside the vault. The certificate cannot be part of the graph, since the
key did not exist when the graph was built, so the instance asks for one:
it writes the key's SEC1 public point on `identity_req` until a chain
arrives on `identity_cert`, and again at two thirds of the held
certificate's lifetime. A chain is taken only when its leaf certifies this
key; any other is dropped and counted. The port carries net_proto frames,
and a chain is read only once its whole frame has arrived; a frame larger
than the instance holds is dropped whole. Until one is taken, a handshake that
reaches its Certificate is refused rather than presenting nothing honest.
A label identity is refused at construction alongside `cert_file` or
`key_file`, without a vault, or with either port unwired.

An issuer that takes proof of possession, such as a device signer redeeming
a claim, needs more than the point. With `identity_request: csr` the request
is a PKCS#10 instead (`[0x5D][len][DER]`): version 0, subject
`CN=<identity_subject>` or empty, the key's SubjectPublicKeyInfo, no
attributes, signed ecdsa-with-SHA256 in the vault. The TLS module builds the
whole request from the key it holds and a name from its params, so the
vault signs one shape for it and nothing a caller supplies: no other module
reaches the key's signature, and the request asserts only what a certificate
for the key would. The alternative, a vault lending a key's signature to a
named module, would let that module sign anything under the key, which is
wider than a request needs. The request is built once per key and resent as
it is; it is public, and replaying it is useless without the key.

With `trust_issuer`, the issuer of the chain the instance is certified
with — its last certificate — is also a trust anchor, placed after the
configured ones and re-adopted on every renewal: the authority a node's
peers chain to, minted at runtime where the graph could not name it. The
chain is adopted only when it is a certification path from the leaf up to
that certificate: each certificate names the next as its issuer and
carries its signature, and every certificate above the leaf is a CA
permitted to sign certificates within its path-length constraint. Any
other chain is dropped whole, so it is neither presented nor trusted.
`trust_issuer` needs a CA profile, since a pinned profile names keys and
not an authority, and a free anchor slot: with the configured anchors
already filling the table of eight, the instance refuses to construct.
Until a chain has arrived there is no anchor, so a peer's chain fails
closed. A renewal writes the adopted anchor over its slot; a handshake
still verifying a chain against the earlier one fails that verification
cleanly rather than reading the renewed anchor's key, and the peer
retries.

Under `trust: system` the adopted issuer adds to the platform's store as
the operator's `--ca` anchors do: the platform judges each chain first,
and one it refuses for an unknown issuer — as it refuses a node's runtime
authority — is walked against the instance's own anchors, the adopted
issuer among them. A client certificate, and a peer dialled by address,
are never put to the platform; they are walked against the instance's own
anchors directly.

Under `ca_uri`, `verify_uri` is either one URI, matched byte for byte, or
a path ending in `/`, which accepts any URI strictly under it — a
cluster's replicas, each its own name, by one listener; a path segment
that is `.`, `..` or empty never matches. Both the expectation and every
presented URI must be spelled in RFC 3986 unreserved characters,
sub-delims, `:`, `@` and `/` (no percent-encoding, query or fragment, any
of which would give one identity a second spelling), shaped
`scheme://authority/path` with a non-empty authority, and at most 128
bytes, the longest principal a session reports. A presented URI longer
than that never matches, so a peer is never accepted under a name its
session could not report. The build refuses a `verify_uri` outside this
rule, and so does the module at construction. The rule applies whatever
the trust source: a chain the platform vouches for under `trust: system`
is held to it on its leaf all the same. The URI SAN that satisfied the
check is reported as the session's principal in its `peer_identity`
record, on TLS and DTLS alike, with the SAN check flag; every other
profile reports none. The validity flag is set whenever the lifetime was
enforced: under `clock_policy: require`, for both `ca_dns` and
`ca_uri`.

An RSA identity always signs through the vault: the module carries no RSA
signer of its own, so on a target whose vault holds no RSA suite the
instance refuses to construct, and the composer refuses the graph first
from the target's `vault_suites` facts. The module reads the key in either
PKCS#1 or PKCS#8 form and stores the PKCS#1 body; its CertificateVerify is
`rsa_pss_rsae_sha256`, driven across steps by the vault's `EAGAIN`
protocol with the same digest each call.

Peer verification is a stepped job in every transport (tls, dtls, quic):
the chain walk records each RSA, ECDSA or Ed25519 link it accepts on shape
and policy, and the handshake pump verifies them one at a time from the
held Certificate message, with the peer's CertificateVerify checked the
same way:

- an RSA exponentiation, `rsa_rows_per_step` Montgomery rows per step on
  one job the instance owns;
- an ECDSA verification, P-256 or P-384, `ecdh_bits_per_step` ladder bits
  per step on the session's own ladders;
- an Ed25519 verification (`modules/foundation/tls/ed25519_job.rs`) on the
  session's own job: each of the two point decodes takes a setup step and
  then its square root 32 exponent bits a step, and the joint
  `[S]B - [k]A` walk takes `ecdh_bits_per_step` bits of both scalars a
  step. Its verdict is `ed25519_verify`'s: S below the group order,
  canonical on-curve encodings, small-order keys and R refused, and the
  cofactorless equation `[S]B = R + [k]A`.

An ML-DSA link is verified whole when the chain is walked, as is the link
into an anchor that shares its subject with another anchor (so the walk can
move to the next candidate). With `ecdh_bits_per_step` at 256, its default,
each ECDSA or Ed25519 verification runs whole in one step. One handshake
per instance verifies at a time; the others wait their turn.

Every target verifies the same certificate suites — ECDSA P-256 and P-384,
Ed25519, ML-DSA-44/65/87 and RSA PKCS#1 v1.5 under SHA-256 or SHA-384 —
and offers the same `signature_algorithms`, in preference order:
`ecdsa_secp256r1_sha256`, `ecdsa_secp384r1_sha384`, `ed25519`,
`rsa_pss_rsae_sha256`, `rsa_pss_rsae_sha384`, `rsa_pkcs1_sha256`,
`rsa_pkcs1_sha384`. The PKCS#1 schemes are offered for certificate
signatures only; a CertificateVerify must use a scheme its key makes
(RFC 8446 §4.4.3), so a P-256 key answers with `ecdsa_secp256r1_sha256`, an
Ed25519 key with `ed25519`, an RSA key with RSA-PSS.

A P-384 identity signs `ecdsa_secp384r1_sha384` in the module on the same
stepped ladder; an ECDSA suite is a curve with its hash, so a P-384 key
signing under SHA-256 is refused as a signature the key does not make, and
a P-256 authority over a P-384 subject as a downgrade. A signature that
does not verify fails the session with `CERT_ERR_SIGNATURE` and a log line
naming the stage. The key exchange is stepped at the same budget: the
P-256 and X25519 ladders advance `ecdh_bits_per_step` bits per step, and
the P-256 result's affine conversion is a Fermat inversion folded in
behind the ladder rather than one call. Verification inverts only public
values and uses a binary extended Euclid for them.

The MCU-class targets run the embedded profile of the module: one session,
one DTLS peer, no continuity shadow, and P-256 as the only key-exchange
group offered (X25519 is offered on the aarch64 builds). What bounds a
handshake on such a target is its ladders and walks, which is why the step
budget is expressed in scalar bits. An RSA chain verifies faster than an
ECDSA one on that core.

## Entropy

Every random byte the kernel hands out — ISNs, tokens, the boot
incarnation, vault keys — comes from `hal::csprng_fill`. On the Pi 5 that
is the iproc-rng200 block (`src/platform/bcm2712.rs`): the generator is
enabled through `RNG_CTRL`, words are taken from its output FIFO only when
its count register says one is waiting, a master-fail lockout or a run of
zero words restarts the block through its soft resets, and a source that
yields nothing but zeros is refused. A zero word is never entropy, and a
successful return code is not either: consumers that mint identity from
randomness (the emission token, the incarnation) refuse an all-zero
result. A build check pins every register offset to the iproc-rng200 map,
and the fence rig scenario exercises the whole path on the silicon.

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

- `MSG_ACK(conn_id, acked_seq, isn)` — the peer acknowledged up to
  `acked_seq`; `isn` is the sequence number of the stream's first byte.
- `MSG_RETRANSMIT(conn_id, from_seq)` — replay data from this sequence.

The TLS module holds each emitted ciphertext record in a per-session
`retx_buf` (default 4 KB). Until the first `MSG_ACK` its base counts stream
bytes; the first one anchors `retx_base_seq` at `isn` plus that offset, so
the window is placed exactly whatever was sent before it arrived, and each
`MSG_ACK` truncates it up to the absolute TCP sequence number. On
`MSG_RETRANSMIT` up to one segment of it from `from_seq` goes back down as
`CMD_RESEND` (`[conn_id][seq][bytes]`), which `ip` sends at those sequence
numbers rather than as new data — no re-encryption, just re-delivery of the
ciphertext the peer is expecting. Because the window is the only copy, an
anchored window that cannot take the next record holds the record back
(`cipher_out` backpressure) rather than dropping bytes it retains.

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
so the definitions in the standard are what the code runs.

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
`modules/sdk/contracts/key_vault.rs` (`ATTEST_COMPOSITION`, `KEY_WRAP`,
`KEY_UNWRAP`, `AEAD_SEAL`, `AEAD_OPEN`).

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
wrapped for the composition that was attested, and this is another.
No surface ever carries the key in the clear.

`AEAD_SEAL` / `AEAD_OPEN` on a `suite::AEAD_KEY` slot are the vault-held
sealing primitive: a fresh CSPRNG nonce per call, the key never leaving.
The quic module's resumption tickets are what use it — the ticket
is the session state sealed under a labelled vault key, two generations
alternating by parity so rotation never strands a live ticket. The AAD
binds a ticket to the generation that sealed it and to the instance's
replay domain — 16 CSPRNG bytes drawn once and living exactly as long as
the RAM store that enforces single use — so it opens only in the instance
that minted it: not after a restart, and not in a re-instantiation in the
same boot, either of which starts with an empty store.
Acceptance is single-use: a claim is retained for the ticket's whole
acceptance window, and a store with no free slot refuses the resumption
rather than evicting a live claim, since evicting one would make a
captured ticket acceptable again. Whether early data is admitted on a
resumed handshake is a separate decision (`enable_0rtt`); the ticket
itself only ever buys a one-round-trip resumption.

`BOOT_INCARNATION` (`kernel_abi`, 16 CSPRNG bytes per boot) is the value
any boot-bound token mixes in, so a token from a previous life of the
host is unmatchable by construction.

