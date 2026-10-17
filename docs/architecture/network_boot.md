# Network Boot and OTA

Fluxor devices can boot a base image from the network and then pull
their application graph from an OCI registry at runtime. The delivered
unit is a **graph image**: modules, compiled configuration, and a
header that pins the graph to the kernel it runs on. The device
becomes a compute node whose behaviour is determined by what the
registry serves.

Two delivery paths exist:

- **Pi-5-class targets** netboot their boot image over TFTP, then pull
  graph images over TLS from an OCI registry and stage them in RAM
  through a kernel staging surface.
- **RP-class targets** stage graph images into on-flash A/B graph
  slots through the `ota_ingest` / `graph_slot` module pair.

## The Graph Image

Source: `tools/src/cli/commands_a.rs` (writer),
`modules/sdk/platform/rp/flash_layout.rs` (layout),
`src/kernel/module/ota_stage.rs`, `src/kernel/boot/config.rs` and
`modules/foundation/graph_slot/` (readers).

`fluxor build <config> --emit=image --output <file>` produces a graph
image: a 256-byte FXSL header; from the first 4 KiB boundary, the module
table (FXMT format, one FXMD entry per module) followed by the graph's
program section when its modules own programs (see
[module_architecture.md](module_architecture.md#programs)); and from the
next 256-byte boundary, the compiled config blob. The header fields are
little-endian:

| Offset | Field |
|--------|-------|
| 0..4 | magic `FXSL` (`0x4C53_5846`) |
| 4 | version (1) |
| 5..8 | unused (0xFF) |
| 8..16 | epoch (`u64`) |
| 16..24 | modules offset and size (the size covers the program section) |
| 24..32 | config offset and size |
| 32..64 | SHA-256 over the modules region, then the config region |
| 64..96 | ABI-surface digest of the kernel the graph was built against |
| 96..168 | signature record, or erased (0xFF) when the image is unsigned |
| 168..256 | unused (0xFF) |

The header pins kernel and graph to each other: a device refuses an
image whose ABI-surface digest does not equal the running kernel's.
The image excludes firmware; it is the only sanctioned module-delivery
path for OTA devices. An image is emitted as long as its payload, on a
whole 256-byte page: the header says where the payload ends, which is
where `ota_ingest` stops reading, so nothing is padded across the wire.
Its ceiling is the board's graph slot on an RP target (below) and 8 MiB
of RAM staging elsewhere.

### Graph-image signatures

Source: `src/kernel/security/slot_signature.rs`.

The signature record is `[magic "SIG1" (u32 LE 0x3147_4953)][key id: the
first four bytes of SHA-256 of the public key][Ed25519 signature R ‖ S:
64 bytes]`, and the signature is over header bytes 0..96: magic, version,
epoch, both regions, the payload digest and the ABI pin. The payload is
bound through its digest, so one signature vouches for every module, the
program section and the config together, and the epoch cannot be raised
without breaking it.

Signing an image takes a 32-byte Ed25519 seed:

```sh
fluxor modules keygen --key slot.key        # creates the seed, prints the public key
fluxor build graph.yaml --emit=image --output graph.img --sign-key slot.key
```

`--sign-key` is refused with any other `--emit` form, and the tool never
prints the seed. A device trusts a signer when its kernel is built with
that public key as the slot root: `FLUXOR_SLOT_ROOT_HEX`, 64 hex digits,
read at compile time. A value that is not 64 hex digits fails the kernel
build. A kernel built with a root:

- boots from a flash slot only when its header carries a record for the
  root that verifies and its payload matches the digest; otherwise it falls
  back to the other slot, then to the firmware's own graph. Verification is
  strict (S below the group order, canonical encodings, no small-order
  points) and is the same in the kernel and in `graph_slot`, so the boot
  selector and ACTIVATE agree on every image;
- stages a RAM image only when the same holds (`-EACCES` otherwise);
- tells `graph_slot` the root (`SLOT_SIGNING_ROOT`), which then activates
  a slot only when the same holds, so a successful activation is one the
  next boot honours.

A kernel built without a root checks no signature: signed and unsigned
images are admitted alike, on their structure, ABI pin, digest and epoch.
The firmware's own graph (the one in the boot image) is never
signature-checked; it is as trusted as the kernel it ships in.

## Publish and Distribution

Source: `tools/src/store_cli.rs`, `tools/src/oci_store.rs`,
`tools/src/store_remote.rs`.

Graph images and boot images are OCI artefacts in the local store:

- `fluxor publish image <file>` publishes a built graph image (media
  type `application/vnd.nanocloud.fluxor.image.v1`). By default the
  image is exploded into layers — a skeleton (header + module-table
  header), one layer per `.fmod`, the program section
  (`application/vnd.nanocloud.fluxor.programs.v1`) when there is one, and
  a config layer, each annotated with its `io.fluxor.image.offset` — so
  registries deduplicate module content and devices fetch only what
  changed. The skeleton carries the header, so a signed image stays
  signed. `--packed` keeps the
  single-blob form used by the RP flash-slot path. Epoch and ABI pin
  are mirrored from the header into the `io.fluxor.image.epoch` and
  `io.fluxor.abi-surface` annotations so a consumer can admit an image
  from the manifest alone.
- `fluxor publish firmware <file>` publishes a boot image (for
  example the Pi 5 `kernel_2712.img`) for staging hosts — TFTP roots
  and SD writers — to pull.
- `fluxor store push <ref> <host[:port]/repo:tag> [--ca <pem>]` and
  `fluxor store pull` are the only network verbs. Digests are the
  identity; tags stay mutable; blobs the registry already holds are
  skipped. Pulls digest-verify every blob, and cross-host redirects
  are refused.

Devices are targeted by tag (for example `devices/<device-id>:latest`)
on an ordinary OCI-distribution registry. The device pull is
anonymous; the registry does not authenticate devices
or select per-device content beyond the tag.

## Boot Image and Netboot

Source: `targets/boards/pi5.toml`, `memory-bcm2712.x`.

A boot image is the kernel with a module table and compiled config
appended in the platform's payload window: the base graph the device
runs before any OTA pull. On Pi 5 the board firmware netboots this
image (`kernel_2712.img`) over TFTP from standard TFTP
infrastructure; `fluxor flash` writes the SD-card alternative to
`/boot/firmware/kernel8.img`. Nothing need reside in local flash on a
netbooted Pi 5.

The base graph for an OTA device is small: the network driver, `ip`,
`tls` in client mode, and `ota_registry`. Application logic belongs in
the pulled graph.

The `tls` client needs an explicit peer-authentication profile, or it
refuses to construct — `peer_auth: ca_dns` with the deployment CA in
`trust`, or `peer_auth: pinned` with the registry's own certificate in
`trust`. Under `ca_dns` the name checked against the certificate is the
one `ota_registry` dials: its `authority` names the registry, and `tls`
reads that name off the connect record it forwards, so it is written
once. `verify_hostname` is the override for a registry reached through
a proxy or by a pinned address — set it only when the name to verify is
not the one dialled.
`trust` names its file as a source spec, `trust: "${file:pki/ca.der}"`,
never as a bare path: the build reads the file and embeds its
certificates, and a file that cannot be read or holds none fails the
build naming the file and the instance. The file may be a bundle —
concatenated DER, or PEM with several `CERTIFICATE` blocks — of up to
eight anchors, which is how a CA rotation is expressed: the outgoing and
incoming authorities side by side, and a chain signed by either verifies.
A device with no synchronised wall clock must also choose
`clock_policy: unchecked`, which states that certificate lifetimes are
not enforced on it.

On a Linux host, `fluxor run --ca <pem>` and `fluxor exec --ca <pem>`
append the PEM's certificates to the anchors of every client-mode `tls`
and `quic` instance for that run. A server instance is never widened,
whether or not it verifies its clients; there is no environment-variable
form. Under `trust: system` the operator's anchors add to the platform's
store rather than replace it: the platform judges every chain first, and
only a chain it refuses for an unknown issuer is walked against the
`--ca` anchors. Any other platform verdict (expired, revoked, name
mismatch) stands. The `tls` line that reports an accepted chain says
either that the platform verified it, or how many anchors the instance
held and where they came from (`source=deployment`,
`deployment+operator`, or `operator`).

A client identity is the operator's, not the publisher's: `fluxor exec
--identity CERT,KEY` gives a DER certificate chain and key to every
client-mode `tls` instance of the run that names no identity of its own
(no `cert_file`, no `key_file`, no `identity_label`), and without the flag
`$HOME/.config/<applet>/client.der` and `client.key.der` are used when
both exist. A published applet therefore carries no credential, and one
bundle serves every operator. Server instances are never given one. A key
longer than a `tls` instance holds (2400 bytes) is refused. The config the
run writes with the key in it is created `0600` in a directory only the
operator can enter, outside the project tree — under `$XDG_RUNTIME_DIR`
when it is set, else under a per-user directory in the system temporary
directory — and removed when the run ends; the next run removes any left
by a run that was killed.

## The Registry Puller: ota_registry

Source: `modules/foundation/ota_registry/mod.rs` and its
`manifest.toml`.

`ota_registry` is a PIC module that speaks HTTP/1.1 against the OCI
distribution API over a `net_in` / `net_out` net_proto pair, wired
through `tls`. Params (TLV tags): `authority` (10, `host[:port]`, port
5000 when omitted — the registry as dialled and as sent in the HTTP
`Host:` header), `repo` (4), `tag` (5), `poll_s` (6, 0 = pull once),
`boot_delay_ms` (7, default 2000), `chunk_bytes` (8, 0 = whole blob),
`directive_pubkey` (9, 64 hex chars of an Ed25519 public key). Tags 1,
2 and 3 are not assigned.

The pull cycle:

1. After `boot_delay_ms`, `GET /v2/<repo>/manifests/<tag>` with the
   OCI manifest media type accepted. One TCP connection per request
   (`Connection: close`), Content-Length framing only; failures back
   off exponentially from 2 s to 60 s.
2. Read `io.fluxor.image.epoch` from the manifest and compare against
   the live epoch (queried through the staging surface). An image that
   is not newer is logged as up to date and the module parks or polls.
3. Fetch each layer (or the single packed blob) with
   `GET /v2/<repo>/blobs/sha256:<hex>`, optionally in `chunk_bytes`
   Range slices, streaming the bytes into the kernel staging surface
   at the layer's annotated offset while computing an incremental
   SHA-256. A digest mismatch aborts the cycle.
4. Commit. The kernel validates and activates the staged image (next
   section).

The optional `directive` input port accepts signed retarget records:
`[0x44][counter: u64 LE][tag_len: u8][tag][Ed25519 signature: 64]`,
signature over `counter ‖ tag` under `directive_pubkey`, with a
monotonic counter for replay rejection (the counter is module state,
so it resets on rebuild or reboot). A valid directive re-points the
watched tag and forces an immediate check, so `poll_s` can be long or
zero.

## Kernel Staging Surface

Source: `src/kernel/module/ota_stage.rs`,
`modules/sdk/internal/reconfigure.rs` (opcodes).

Staging is a kernel surface reached through two `dev_system` opcodes,
available to modules with the `platform_raw` permission:

- `OTA_STAGE_WRITE` (`0x0C20`) — payload `[offset: u32 LE][bytes]`.
  Forward gaps are zero-filled; backward offsets are rejected.
- `OTA_STAGE_CTRL` (`0x0C21`) — `COMMIT` (0), `ABORT` (1), `EPOCH`
  (2, returns the live epoch).

The stage is RAM: two 8 MiB, 16 KiB-aligned static buffers used
alternately A/B. `COMMIT` validates the staged image — FXSL magic and
version, region bounds, SHA-256 over modules ‖ config against the
header, strict ABI-surface-pin equality against the running kernel
(`-EACCES` on mismatch), on a kernel built with a slot root the
header's signature (`-EACCES`), and an epoch above the live one
(`-EBUSY`) — then flips the region non-writable and executable via the
platform HAL, re-points the static loader at it, and requests a
scheduler graph rebuild. Staged code is never executed before
validation, and is loaded from the same buffer that was validated.

Failure posture: a validation failure leaves the running graph
untouched; a failure during the rebuild itself leaves the graph idle,
recoverable by power cycle back into the netboot image. Staging never
writes the boot image, so the netboot/SD image is the fallback by
construction. The live epoch is held in RAM and starts at 0 each boot:
within a boot an older or equal epoch is refused, and after a power
cycle any image with an epoch of 1 or more is accepted. Recovering an
older version means a power cycle and a re-pull, or publishing it under
a newer epoch. On targets without the RAM stage (RP, WASM) the
surface returns `ENOSYS`.

Activating a new graph image restarts the graph. For graphs holding
storage state, treat activation as reboot-class maintenance rather
than a live handoff.

## RP Flash Slots: ota_ingest and graph_slot

Source: `modules/foundation/ota_ingest/`,
`modules/foundation/graph_slot/`,
`modules/sdk/platform/rp/flash_layout.rs`.

RP2040/RP2350 targets stage into two on-flash A/B graph slots instead
of RAM.

### The flash partition

An RP board's XIP flash is partitioned by `flash_layout::graph_flash`
from two numbers: the flash the board fits (`[hardware.flash] size` in
the board TOML, the silicon's `[memory] flash_size` when a board names
none) and the flash the silicon reserves for the kernel (`[memory]
kernel_flash_reserve`). From the top: the last 4 KiB sector is the
runtime parameter store; below it lie slot B and then slot A, equal in
size; from offset 0 up to slot A lies the firmware region, the kernel
and the graph it was deployed with. Each slot is a third of what the
kernel's reserve leaves, sector-aligned, so the firmware region holds the
kernel and a graph as large as a slot: any graph a board can be deployed
with can also be sent over the air, and the reverse. A 4 MB Pico 2 W has
two 1,148 KiB slots at `0x1C1000` and `0x2E0000`; a 2 MB Pico W two of
508 KiB at `0x101000` and `0x180000`; a 16 MB board two of some 5 MiB. A
flash too small to leave two slots has none, and every OTA request on
such a board is refused.

The kernel is built for one board and computes its partition from that
board's size, so it is the one authority: `FLASH_LAYOUT` answers it to a
module as `[flash_size][slot_a][slot_b][slot_size][param_store]`, each a
`u32` LE offset from the XIP base, and `graph_slot`, `ota_ingest` and
`flash_rp` ask rather than compile a geometry in, so one module build
serves every board of a silicon. The tool computes the same partition
from the same TOMLs: it bounds the graph image it emits by the board's
slot, refuses a combined firmware image that reaches slot A, and
`fluxor inspect <config>` prints the partition (`--json`:
`config.resolved_target.flash`), which is what a bench reads to erase or
plant a slot. The CI gate holds every board's kernel image under the
silicon's reserve, since a kernel past it eats into the graph the
firmware region carries.

### The modules

`graph_slot` owns the slots and exposes an FMP channel protocol
(`gs.erase`, `gs.write`, `gs.activate`, `gs.query_active`,
`gs.query_cfg`; responses are `[req_type: u32 LE][value: i32 LE]`).
`ota_ingest` accepts a graph image as a byte stream on its `stream`
input, buffers it into 256-byte pages, and drives erase → write →
activate, reporting progress on its `status` output as 4-byte records
`[kind: u8][pad][rc: i16 LE]` with kinds `0x01` erased, `0x02` written,
`0x03` activated, `0xFF` failed. An image is as long as its header says:
the header page names where the modules and the config end, the image
is activated once that much is written, and one longer than the board's
slot is refused before anything is erased. Nothing is erased until a
whole header page has arrived, and bytes that do not begin with the
image magic (`FXSL`) — what follows an image, or the rest of one that
was refused — are dropped until an image begins. The slot content is the
packed (single-blob) graph-image form.

`graph_slot` never erases or programs the slot the kernel booted from:
module code runs in place from flash on RP, and a rebuild
re-instantiates the graph from that slot, so it is in use until reset.
It finds that slot from the address of its own code, and every erase
and write targets the other one; a second OTA before a reset replaces
the pending image, not the running one. The header page (offset 0,
which carries the magic and epoch the boot selector reads) is held in
RAM when written and programmed only by `gs.activate`, after the epoch,
the ABI pin, the SHA-256 over the rest of the slot and, on a kernel
built with a slot root, the header's signature check out (a refused
signature answers `-EACCES` and logs `[graph_slot] refused: signature`).
A slot that was half-written or failed a check therefore has no magic
and cannot be selected at boot. `gs.query_cfg` answers the running
slot's config address, which stays readable until the next reset;
`gs.query_active` answers the slot the next boot selects.

On a kernel built with a slot root, `graph_slot` counts a slot live
(for `gs.query_active`, and as the epoch an activation must beat) only
when the boot selector would admit it. Verifying a signature takes many
steps, so it does not re-verify on every query: it starts from the
slots this boot's selector admitted (`SLOT_ADMITTED`, a mask) and tracks
its own changes — a slot it erases or writes into leaves the set, a slot
it activates joins it. A higher-epoch slot planted in flash by other
means is neither booted nor counted live.

The boot selector reads a slot in place from flash: under a root it
verifies the header and hashes the payload, then runs the modules from
those same flash bytes. Nothing but `graph_slot` programs a slot while
the board runs, and it never programs the running one; an attacker who
can rewrite flash between that check and use has physical access, which
this does not defend against.

## Security Model

Content trust on the OTA path is digest pinning end to end: the
manifest names layer digests, every fetched blob is hashed as it
streams, and commit re-verifies the whole-image hash from the FXSL
header. Transport trust is TLS with the deployment CA pinned in the
base graph's `tls` module. Binding to the running kernel is the
ABI-surface pin; downgrade resistance is epoch monotonicity (within a
boot on the RAM stage; against the slot it replaces on flash).

On a kernel built with a slot root, the image's signature is what makes
a registry or transport compromise insufficient: a device boots, stages
and activates only images the root's key signed, and the signed epoch
cannot be raised to replay an old one. On a kernel built without one,
registry compromise is bounded by the TLS trust root and the
digest/ABI/epoch checks only. Module-level Ed25519 signatures are a
separate, per-module check in the loader, described in `security.md`.

## Where It Fits

The same graph image and the same store/registry model serve every
deployment shape: RP flash slots, Pi 5 RAM-staged OTA, and hosted
runs. The image format, the digest/ABI/epoch validation, and the OCI
artefact model are shared; devices differ only in where the bytes come
from and where they are staged.

## Related Documentation

- `module_architecture.md` — FXMT/FXMD module table and `.fmod` format
- `security.md` — loader trust profiles, KEY_VAULT, signing model
- `reconfigure.md` — graph rebuild and drain semantics
- `abi_surface.md` — the ABI-surface digest that pins kernel to graph
