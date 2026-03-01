# CYW43 Firmware

This directory contains firmware blobs for the CYW43 WiFi chip used on Pico W boards.

## Required Files

To use WiFi functionality, download these files from the Raspberry Pi firmware repository:

1. **43439A0.bin** - Main WiFi firmware (~230KB)
2. **43439A0_clm.bin** - Country locale matrix (~5KB)

## Download Instructions

```bash
# Download from Raspberry Pi firmware repository
curl -L -o firmware/43439A0.bin \
  https://github.com/raspberrypi/pico-sdk/raw/master/lib/cyw43-driver/firmware/43439A0.bin

curl -L -o firmware/43439A0_clm.bin \
  https://github.com/raspberrypi/pico-sdk/raw/master/lib/cyw43-driver/firmware/43439A0_clm.bin
```

Or use the alternative embassy repository:

```bash
curl -L -o firmware/43439A0.bin \
  https://github.com/embassy-rs/embassy/raw/main/cyw43-firmware/43439A0.bin

curl -L -o firmware/43439A0_clm.bin \
  https://github.com/embassy-rs/embassy/raw/main/cyw43-firmware/43439A0_clm.bin
```

## Verification

After downloading, verify the files:

```bash
ls -la firmware/
# Should show:
# -rw-r--r-- 1 user user 224190 ... 43439A0.bin
# -rw-r--r-- 1 user user   4752 ... 43439A0_clm.bin
```

## License

The CYW43 firmware is proprietary and licensed by Cypress/Infineon.
It is redistributable under the terms included in the Raspberry Pi Pico SDK.

## Building Without Firmware

If firmware files are not present, the build will fail when the `wifi` feature
is enabled. Either:
1. Download the firmware files, or
2. Build without the wifi feature: `cargo build --release`
