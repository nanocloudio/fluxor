# `static_server/` — HTTP file serving from FAT32

HTTP server backed by a FAT32 filesystem, reading via the unified
`FS_CONTRACT` path. Same overall graph shape on both platforms;
only the storage backend and NIC differ:

```
<storage> → fat32 → http (fs_path routes) → <NIC>
```

## Targets

| File | Storage backend | NIC |
| --- | --- | --- |
| `pico2w.yaml` | SD card on SPI0 (CS GPIO17) | cyw43 WiFi |
| `cm5.yaml` | NVMe partition (via `storage: { media: nvme }`) | RP1 GEM ethernet |

## Setup

**pico2w:** format an SD card FAT32, drop files in the root (uppercase
8.3 short names — `INDEX.HTM`, `ABOUT.TXT`), slot it in.

**cm5:** format an NVMe partition FAT32, mount label `FLUXORNV`:

```sh
sudo mkfs.vfat -F 32 -s 8 -n FLUXORNV /dev/nvme0n1p1
sudo mount /dev/nvme0n1p1 /mnt/nvme
echo "<h1>Hello from NVMe FAT32</h1>" | sudo tee /mnt/nvme/INDEX.HTM
sudo umount /mnt/nvme
```

## Run

```sh
# pico2w
make firmware TARGET=pico2w && make modules TARGET=rp2350
make flash CONFIG=examples/static_server/pico2w.yaml

# cm5
make firmware TARGET=cm5 && make modules TARGET=bcm2712
fluxor combine -o kernel8.img target/cm5/firmware.bin examples/static_server/cm5.yaml

# either: files served at http://<device-ip>/<filename>
curl http://<device-ip>/
```

## Related

- The NVMe perf probe (regression fixture) lives at
  [`../test_harness/cm5/nvme_perf.yaml`](../test_harness/cm5/nvme_perf.yaml).
- For HTTP-only (without the storage backend) see
  [`web_server/`](../web_server/).
