# Network Boot

Fluxor devices can boot their application graph entirely from the network. The
kernel and a minimal boot graph reside in local flash. The application graph —
modules, configuration, and assets — is fetched from a deployment server at
boot time. The device becomes a stateless compute node whose behaviour is
determined by what the network provides.

This is a composition of existing architectural primitives: remote channels
for transport, graph bundles for packaging, module signing for trust, live
graph reconfigure for the transition from boot graph to application graph,
and asset caching for incremental content delivery.

## How It Works

### Boot Sequence

```
Power on
    │
    ▼
Kernel boots from flash (~256 KB)
    │ Minimal: scheduler, channels, events, loader, chip HAL
    │ No application logic
    │
    ▼
Boot graph instantiates from flash
    │ Three modules:
    │   network_driver (cyw43 WiFi or eth_driver)
    │   ip_stack
    │   netboot_agent
    │
    ▼
netboot_agent connects to deployment server
    │ Server address from:
    │   - flash parameter store (configured at provisioning)
    │   - DHCP option (vendor-specific, like PXE)
    │   - mDNS discovery (find _fluxor-deploy._tcp on local network)
    │
    ▼
Server sends application graph bundle
    │ Via remote channel (TCP transport) or HTTP GET
    │ Bundle contains: graph.yaml + .fmod module binaries + manifest
    │ Signed by deployment key, verified against device trust root
    │
    ▼
netboot_agent validates bundle
    │ Signature verification (Ed25519)
    │ Module hash verification (SHA-256 per module)
    │ Graph validation (port types, resource bounds, capabilities)
    │
    ▼
netboot_agent stages bundle
    │ CM5: write to DRAM staging area (no persistent storage needed)
    │ RP2350: write to flash staging sectors
    │
    ▼
Graph reconfigure: boot graph → application graph
    │ Boot graph modules terminate
    │ Application graph modules instantiate
    │ Network driver and IP stack may survive if unchanged
    │   (same binary hash → module survival per live reconfigure RFC)
    │
    ▼
Application graph is running
    │ Device is fully operational
    │ Loaded entirely from the network
```

### The Boot Image

Network boot is a deliberate choice. The person provisioning the device
knows what network hardware it has — they're holding the board. They flash
a boot image that contains the right network driver.

The `fluxor provision` CLI tool writes a complete boot image to flash:
kernel + boot graph + the specific network driver for this board. Pre-built
boot images exist for common configurations:

```
fluxor provision --netif pico2w_cyw43 \
                 --wifi MyNetwork MyPassword \
                 --server deploy.example.com
```

This flashes a boot image containing: kernel + CYW43 driver + WiFi module +
IP stack + netboot_agent, with WiFi credentials and server URL baked into
the boot graph params. The device boots this image, connects via WiFi,
and fetches the application graph from the server.

For Ethernet boards:

```
fluxor provision --netif w5500_spi0 \
                 --server deploy.example.com
```

Different boot image — contains the W5500 SPI driver instead of CYW43.
No WiFi credentials needed (Ethernet uses DHCP).

For CM5:

```
fluxor provision --netif rp1_gbe \
                 --server deploy.example.com
```

Writes `kernel8.img` with the RP1 Gigabit Ethernet driver to the SD card.

Each boot image is small:

| Boot Image | Contents | Size |
|-----------|----------|------|
| pico2w_cyw43 | Kernel + CYW43 + WiFi + IP + netboot_agent + CYW43 firmware blob | ~450 KB |
| w5500_spi0 | Kernel + W5500 + IP + netboot_agent | ~280 KB |
| rp1_gbe | Kernel + GEM driver + IP + netboot_agent | ~300 KB |

The boot image is the device's permanent fallback. If the application
graph fails, the device reboots to the boot image. The boot image is never
updated over the network — it is flashed once at provisioning time. To
change the network interface (e.g., replacing a WiFi board with an Ethernet
board), re-provision with a different boot image.

### The netboot_agent Module

A standard PIC module (~2-3 KB compiled) with this step behaviour:

1. **Connect phase.** Open a TCP socket to the deployment server. If using
   mDNS discovery, resolve `_fluxor-deploy._tcp` first. Retry on failure
   with configurable backoff.

2. **Request phase.** Send a boot request containing: device ID (from OTP or
   flash parameter store), current application graph version (if any),
   hardware descriptor (silicon ID, available memory, peripheral set). The
   server uses this to select the appropriate graph bundle for this device.

3. **Download phase.** Receive the graph bundle. For small bundles (<100 KB,
   typical for MCU graphs), this completes in one TCP transfer. For large
   bundles (MB-scale, CM5 with many modules), the download streams in chunks
   with progress tracking.

4. **Validate phase.** Verify the bundle signature against the device's trust
   root. Verify each module's SHA-256 hash against the manifest. Run graph
   validation (port types, resource bounds, capability satisfaction). If
   validation fails, log the error, report to server, and retry (the server
   may have a corrected bundle).

5. **Stage phase.** Write the validated bundle to the staging area:
   - CM5: DRAM arena (ephemeral — lost on power cycle, re-fetched on next boot)
   - RP2350: flash staging sectors (persistent — survives power cycle)

6. **Switch phase.** Trigger graph reconfigure. The scheduler transitions
   from the boot graph to the application graph. Network modules (cyw43, ip)
   survive if they are unchanged between boot and application graph. The
   netboot_agent itself terminates — it is not part of the application graph.

7. **Fallback.** If graph reconfigure fails (instantiation error, module
   fault during first ticks), the scheduler reverts to the boot graph. The
   netboot_agent restarts and reports the failure to the server. The device
   does not brick — the boot graph is always in flash.

### Server Side

The deployment server is simple:

- Stores graph bundles keyed by (device class, version)
- Accepts boot requests, selects the appropriate bundle, sends it
- Tracks which devices have booted which version (fleet inventory)
- Can be: a Fluxor node with a registry module, a standard HTTP server with
  a REST API, or a Nanocloud controller

The protocol between netboot_agent and server is either:
- **Remote channel** (preferred for Fluxor-native servers): the server's
  deployment module has a remote channel endpoint that the netboot_agent
  connects to. The bundle flows as channel data.
- **HTTP GET** (for standard infrastructure): the netboot_agent fetches
  `https://deploy.example.com/api/v1/bundle?device=XXXX&current=v1.2`.
  The response is the signed bundle. This works with any HTTP server or CDN.

## Stateless Devices

### CM5 as a Stateless Compute Node

On CM5, the application graph loads entirely into DRAM. No local persistent
storage is required (no eMMC, no SD card). The device boots from flash
(kernel + boot graph), network-boots the application graph into DRAM, and
runs. On power cycle, the process repeats — the device re-fetches the graph
from the network.

This makes the CM5 a **stateless edge node:**

- **Hardware is fungible.** Swap a failed CM5 for a new one. It boots, fetches
  the same graph from the server, and is operational. No cloning, no imaging,
  no configuration. The server knows what this device class should run.

- **Configuration lives on the server.** The device has no local config beyond
  WiFi credentials (or Ethernet — no credentials needed) and the deployment
  server address. Everything else — the application graph, module versions,
  parameters — is determined by the server.

- **Updates are instant.** Push a new bundle to the server. Devices fetch it
  on next boot (or the server pushes a reconfigure command via remote channel
  to running devices, triggering a live update without reboot).

- **State is external.** If the application needs persistent state (KV store,
  logs, user data), it uses remote channels to a storage server — not local
  storage. The device is truly stateless.

### RP2350 with Persistent Staging

On RP2350, DRAM is too small to hold the application graph in RAM during the
boot graph's execution. The netboot_agent writes the bundle to flash staging
sectors. Subsequent boots use the staged bundle from flash (fast local boot).
The netboot_agent checks the server for updates on each boot:

1. Boot from flash (kernel + boot graph)
2. netboot_agent checks: is there a staged application graph in flash?
   - Yes, and it's valid: instantiate it immediately (fast boot, ~100 ms)
   - Yes, but server has a newer version: download new bundle, stage, switch
   - No staged graph: download from server (first boot, or after flash erase)
3. Application graph runs

This gives first-boot-from-network with subsequent-boots-from-flash. The
device is not fully stateless (it caches the graph in flash), but it is
server-authoritative — the server's version always wins on the next check.

## Hardware Discovery

The deployment server needs to know what hardware the device has — beyond
the network interface — to send the right application graph. The network
interface is already handled: the boot image contains the right driver,
flashed at provisioning time.

The remaining question is: what peripherals are on which pins? For known
boards (pico2w, cm5, flux-node-001), the server has built-in board
descriptors. For custom boards, the hardware must be described somewhere.

The default method is unchanged: a board TOML compiled into the firmware
image (local development, no network boot). Network boot adds server-side
board templates as an alternative.

### Board Templates (Server-Side)

A board template is a reusable board descriptor stored on the server:

```yaml
name: "workshop-sensor-board"
silicon: rp2350a
network_profile: pico2w_cyw43
pins:
  i2c0: { sda: 4, scl: 5 }
  spi0: { mosi: 19, miso: 16, sck: 18, cs: 17 }
  gpio:
    - { pin: 15, direction: input, pull: up, label: "user_button" }
peripherals:
  - { address: 0x3C, bus: i2c0, driver: ssd1306 }
  - { bus: spi0, driver: sd_card }
```

Templates can be created via the server's web UI (interactive pin
assignment with constraint validation against the silicon TOML), imported
from a YAML file, or exported for version control.

**Assignment rules** (evaluated in order):

1. Device has a template ID in flash config sector or OTP → use that
2. Device serial is individually mapped to a template on the server → use that
3. Server has a default template policy for the device's silicon → use that
4. No match → device status is PENDING; server UI notifies the user

For a workshop with 50 identical boards, the user sets a default template
policy: "all RP2350A devices → workshop-sensor-board" (one click). Or
flashes all boards with `fluxor provision --template workshop-sensor-board`
before deploying.

### First Boot of a New Custom Board

The user has a home-made board with peripherals on specific pins. No
EEPROM, no OTP, no special hardware. The first boot flow:

1. User provisions the minimum: WiFi credentials and server URL via USB
   (`fluxor provision --wifi MyNetwork MyPassword --server deploy.local`).
   Or: plugs in via Ethernet (no credentials needed, DHCP auto-configures).

2. Device boots the boot graph, connects to the server.

3. Server sees a new device (unknown serial, no template). Status: PENDING.

4. User opens the server's web UI in their browser. The server shows:
   "New device: RP2350A, serial E661...28. No board template. Configure?"

5. User describes the board in the browser UI:
   - Select pin assignments from constrained dropdowns (the server knows
     which pins are valid for SPI0 MOSI, I2C0 SDA, etc. — loaded from the
     silicon TOML as a JSON constraint map, validated client-side)
   - Optionally click "Probe I2C" — the server asks the device (via the
     netboot_agent's already-connected channel) to scan the I2C bus and
     report responding addresses. Results appear in the UI as suggestions.
   - Save as a new template (reusable for identical boards) or as a
     one-off device config

6. Server validates the graph against the described hardware. Sends the
   graph bundle. Device runs.

7. Every subsequent boot: device serial → template → graph bundle.
   No browser interaction needed.

The display is the user's browser, not the device. The device has no
display at this point — it just has a network connection. The server
mediates all user interaction.

### I2C Bus Probing (Opt-In)

The server can ask the device to probe its I2C bus, but only when:

- The user has already assigned I2C SDA/SCL pins in the UI (so the device
  knows which pins to probe)
- The user explicitly clicks "Probe I2C Bus" (never automatic)
- The UI warns: "Probing sends transactions on the I2C bus. Some devices
  may react to probe traffic."

The probe is a simple address scan (START + address + read 1 byte + STOP
for each address 0x08-0x77). Results are displayed as a list of responding
addresses with dropdowns of known devices at each address. The user
selects the correct device. Ambiguous addresses (0x68 could be MPU-6050
or DS1307) require the user to choose.

Probe results are suggestions, not auto-configuration. The user confirms
every assignment. Output pin assignments require explicit acknowledgement
(wrong output pins can damage hardware).

### Recovery

| Problem | Recovery Path |
|---------|--------------|
| Wrong WiFi credentials | UART console: `wifi <ssid> <pass>` then `reboot` |
| Wrong server URL | UART console: `server <url>` then `reboot` |
| Wrong network driver (wrong boot image) | Re-provision over USB: `fluxor provision --netif <correct>` |
| Wrong board template (hardware misbehaves) | Server UI: reassign template. Or UART: `template 0` then `reboot` to clear and re-register |
| Can't reach UART | Hold BOOTSEL 5+ seconds during power-on → kernel clears params, reboots to boot image defaults |
| Server offline on first boot | UART console activates after 30s timeout. User can set credentials and retry. |

The UART provisioning console is a small PIC module (~2 KB) in the boot
graph that activates when the network connection fails. It accepts 5
commands over USB serial at 115200 baud: `help`, `status`, `wifi`,
`server`, `reboot`. Plain text, no escape sequences, works with any
terminal.

Note: changing the network interface (e.g., replacing WiFi with Ethernet)
requires re-provisioning the boot image over USB — the UART console cannot
change the network driver because the driver is compiled into the boot
image. This is deliberate: the boot image is a static, known-good
configuration, not a runtime-reconfigurable system.

### Production Manufacturing (EEPROM and OTP)

For production boards where no user interaction is desired:

**I2C EEPROM at 0x50** (Pi HAT standard): stores vendor info, product ID,
and GPIO map. The kernel reads it at boot and includes the data in the
boot request. The server recognises the product ID and selects the
matching template. The board carries its own identity — works with any
server, no per-device registration needed. Programmed once during
manufacturing with `fluxor provision-board`.

**RP2350 OTP**: board template ID and network profile ID burned into OTP
rows during manufacturing. The kernel reads OTP at boot (memory-mapped,
no I2C). OTP values override the flash config sector. One-time — mistakes
cannot be corrected, but no extra hardware needed.

These are production paths, not the default developer experience. The
default is: provision WiFi + server URL over USB, describe the board
through the server web UI, done.

### What the Boot Request Contains

```
{
  serial: "E6614103E7A36D28",      // flash unique ID
  silicon: "rp2350a",              // chip registers
  template_id: 0,                  // from flash config or OTP (0=none)
  firmware_version: "1.4.2",       // boot graph version
  eeprom: { ... },                 // HAT EEPROM data, if present
  memory: { sram: 524288, psram: 8388608 }
}
```

The server uses this to look up the board template, validate the graph,
and send the bundle. For known devices (template_id > 0 or recognised
serial), the response is immediate. For unknown devices, the response is
PENDING until the user configures via the server UI.

## Fleet Management

Network boot composes with remote channels for fleet-scale management:

```
Deployment server (Nanocloud)
    │
    ├── Remote channel → Device 1 (CM5, stateless)
    │     Boot request → bundle → validate → run
    │     Telemetry ← metrics, health, version
    │
    ├── Remote channel → Device 2 (RP2350, flash-cached)
    │     Boot request → bundle → stage → run
    │     Telemetry ← metrics, health, version
    │
    ├── Remote channel → Device 3 (CM5, stateless)
    │     ...
    │
    └── Remote channel → Device N
```

The server maintains a fleet inventory: which devices exist, what they're
running, when they last booted, whether they're healthy. The remote channels
provide bidirectional communication — the server can push config changes or
reconfigure commands to running devices without waiting for a reboot cycle.

**Fleet update flow:**

1. Developer pushes new graph bundle to the deployment server
2. Server decides rollout strategy (all at once, canary, percentage-based)
3. For stateless CM5 devices: server sends reconfigure command via remote
   channel. Device live-reconfigures without reboot.
4. For RP2350 devices: server marks bundle as "update available." On next
   boot, device downloads and stages. Or: server sends reconfigure command
   and device downloads + switches while running (if live reconfigure is
   supported for this graph change).
5. Server monitors health metrics from updated devices. If failure rate
   exceeds threshold, server stops rollout and marks the bundle as bad.
   Devices that already updated can be commanded to roll back (reboot to
   previous staged graph on RP2350, or re-fetch previous version on CM5).

## Security

### Trust Root

Each device has a trust root — an Ed25519 public key surfaced through
`hal::otp_read_signing_key`:

- RP2350: OTP (one-time programmable) memory. Written once at manufacturing.
- CM5: Secure flash partition or hardware security element. Today the
  CM5 HAL reads a compile-time constant from the
  `FLUXOR_SIGNING_PUBKEY_HEX` build environment variable; production
  deployments swap this for an on-silicon OTP bank.

Each PIC module carries a v2 manifest with a 64-byte Ed25519 signature
over its SHA-256 integrity hash plus a 32-byte signer fingerprint. The
loader recomputes the hash at admission, verifies the signature
against the provisioned pubkey, and — with `enforce_signatures` set —
refuses unsigned or mismatched modules. A tampered module fails with
`IntegrityMismatch`; a bad signature fails with `SignatureInvalid`. See
`security.md` for the full admission path.

The trust root also verifies the deployment server's bundle signatures.
A bundle signed by an unknown key is rejected. A bundle with a tampered
module (hash mismatch) is rejected. The netboot_agent never executes
unverified code.

### Network Security

The connection to the deployment server should use TLS (via the TLS module
and mbedtls). The server authenticates to the device (server certificate
verified against a pinned CA or the device's trust root). The device
authenticates to the server (device certificate or pre-shared token from
provisioning).

On networks where TLS is not available (constrained MCU with no TLS
module), the bundle signature provides integrity and authenticity. The
transport may be unencrypted, but the bundle cannot be tampered with — a
modified bundle fails signature verification.

### Boot Graph Integrity

The boot graph itself is signed and verified by the kernel at boot. A
corrupted or tampered boot graph (flash bit-flip, malicious write) is
detected before instantiation. The kernel refuses to boot an invalid boot
graph and halts with a diagnostic (LED blink code or UART error).

## What This Is Not

**This is not PXE boot.** PXE loads a monolithic OS image over TFTP. Fluxor
network boot loads a validated, signed graph bundle over TCP/HTTP. The boot
graph (flash-resident) handles networking; the kernel doesn't need a network
stack.

**This is not a thin client.** The device runs the application graph locally
with full cooperative execution. It is not streaming a display from a server
(though it can — see the cloud streaming stress test). It is a full Fluxor
runtime that happens to get its graph from the network.

**This is not diskless boot.** On CM5, the device truly has no local
persistent storage for the application (DRAM only). But the kernel and boot
graph are in flash — the device is not booting from network at the firmware
level. The GPU firmware boot chain (`start4.elf`, `kernel8.img`) is local.

## Relationship to Other Architecture

| Capability | Architecture Doc |
|-----------|-----------------|
| Remote channel transport | `mesh.md` — mesh primitives, capability binding |
| Graph bundle format and signing | `capability_surface.md` — module manifests, content types |
| Live graph reconfigure | `pipeline.md` — graph runner, module lifecycle |
| Module signing and trust | `security.md` — trust root, signature path, KEY_VAULT |
| Fleet telemetry | `events.md` — observable metrics, event signalling |
| WiFi/network drivers | `network.md` — netif contract, driver/service split |
| Hardware boot (CM5) | `hal_architecture.md` — HAL boundary, boot sequence |
