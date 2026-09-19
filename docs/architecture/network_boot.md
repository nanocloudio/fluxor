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
`src/kernel/module/ota_stage.rs` (reader).

`fluxor build <config> --emit=image` produces a graph image: a 256-byte
FXSL header, the module table (FXMT format, one FXMD entry per
module), and the compiled config blob. The header fields are
little-endian:

| Offset | Field |
|--------|-------|
| 0..4 | magic `FXSL` (`0x4C53_5846`) |
| 4 | version (1) |
| 8..16 | epoch (`u64`) |
| 16..24 | modules offset and size |
| 24..32 | config offset and size |
| 32..64 | SHA-256 over modules ‖ config |
| 64..96 | ABI-surface digest of the kernel the graph was built against |

The header pins kernel and graph to each other: a device refuses an
image whose ABI-surface digest does not equal the running kernel's.
The image excludes firmware; it is the only sanctioned module-delivery
path for OTA devices. RP targets pad the image to the 512 KB flash
slot aperture; other targets emit it unpadded with an 8 MiB ceiling.

## Publish and Distribution

Source: `tools/src/store_cli.rs`, `tools/src/oci_store.rs`,
`tools/src/store_remote.rs`.

Graph images and boot images are OCI artefacts in the local store:

- `fluxor publish image <file>` publishes a built graph image (media
  type `application/vnd.nanocloud.fluxor.image.v1`). By default the
  image is exploded into layers — a skeleton (header + module-table
  header), one layer per `.fmod`, and a config layer, each annotated
  with its `io.fluxor.image.offset` — so registries deduplicate module
  content and devices fetch only what changed. `--packed` keeps the
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
on an ordinary OCI-distribution registry. In the current model the
device pull is anonymous; the registry does not authenticate devices
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
form. The `tls` line that reports an accepted chain says how many anchors
the instance held and where they came from (`source=deployment`,
`deployment+operator`, or `operator`).

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
2 and 3 are retired.

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
(`-EACCES` on mismatch), and epoch monotonicity (`-EBUSY`) — then
flips the region non-writable and executable via the platform HAL,
re-points the static loader at it, and requests a scheduler graph
rebuild. Staged code is never executed before validation.

Failure posture: a validation failure leaves the running graph
untouched; a failure during the rebuild itself leaves the graph idle,
recoverable by power cycle back into the netboot image. Staging never
writes the boot image, so the netboot/SD image is the fallback by
construction. Rollback to an older epoch is refused; recovering an
older version means a power cycle and a re-pull, or publishing it
under a newer epoch. On targets without the RAM stage (RP, WASM) the
surface returns `ENOSYS`.

Activating a new graph image restarts the graph. For graphs holding
storage state, treat activation as reboot-class maintenance rather
than a live handoff.

## RP Flash Slots: ota_ingest and graph_slot

Source: `modules/foundation/ota_ingest/`,
`modules/foundation/graph_slot/`,
`modules/sdk/platform/rp/flash_layout.rs`.

RP2040/RP2350 targets stage into two 512 KB on-flash A/B graph slots
instead of RAM. `graph_slot` owns the flash aperture and exposes an
FMP channel protocol (`gs.erase`, `gs.write`, `gs.activate`,
`gs.query_active`, `gs.query_cfg`; responses are
`[req_type: u32 LE][value: i32 LE]`). `ota_ingest` accepts a graph
image as a byte stream on its `stream` input, buffers it into 256-byte
pages, and drives erase → write → activate, reporting progress on its
`status` output as 4-byte records `[kind: u8][pad][rc: i16 LE]` with
kinds `0x01` erased, `0x02` written, `0x03` activated, `0xFF` failed.
The slot content is the packed (single-blob) graph-image form.

## Security Model

Content trust on the OTA path is digest pinning end to end: the
manifest names layer digests, every fetched blob is hashed as it
streams, and commit re-verifies the whole-image hash from the FXSL
header. Transport trust is TLS with the deployment CA pinned in the
base graph's `tls` module. Binding to the running kernel is the
ABI-surface pin; downgrade resistance is epoch monotonicity. Graph
images are not signature-verified on this path; module-level Ed25519
signature enforcement exists in the loader as a build-time option and
is described in `security.md`. Registry compromise is therefore
bounded by the TLS trust root and the digest/ABI/epoch checks, not by
a content signature.

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
