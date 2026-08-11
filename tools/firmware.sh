#!/bin/bash
# Build one kernel target and emit its raw boot image.
#
#   tools/firmware.sh [rp2350|rp2040|qemu-virt|pi5|wasm]
#
# The Makefile's `firmware` target calls this. It lives here rather than
# in a recipe because per-target dispatch is a conditional, and
# standards/make.md §3 puts conditionals in a `fluxor` subcommand or a
# script — never in a Makefile. The module half of the same knowledge
# (per-target rustc flags) is already in `fluxor modules build`'s
# silicon-spec table; this is the kernel half.
set -euo pipefail

TARGET="${1:-${TARGET:-rp2350}}"

case "$TARGET" in
  rp2040)    RUST_TARGET=thumbv6m-none-eabi          FEATURES=chip-rp2040  ;;
  rp2350)    RUST_TARGET=thumbv8m.main-none-eabihf   FEATURES=chip-rp2350b ;;
  qemu-virt) RUST_TARGET=aarch64-unknown-none        FEATURES=chip-bcm2712 ;;
  pi5)       RUST_TARGET=aarch64-unknown-none        FEATURES=board-pi5    ;;
  wasm)      RUST_TARGET=wasm32-unknown-unknown      FEATURES=host-wasm    ;;
  *) echo "firmware: unknown TARGET '$TARGET' (rp2350|rp2040|qemu-virt|pi5|wasm)" >&2; exit 2 ;;
esac

# Features layered on top of the target's own, for a build that differs
# only by an opt-in (`EXTRA_FEATURES=enforce_signatures`, from
# signed-image.sh) — so a variant does not fork the table above.
FEATURES="$FEATURES${EXTRA_FEATURES:+,$EXTRA_FEATURES}"

RELEASE_DIR="target/$RUST_TARGET/release"
echo "Building firmware for $TARGET ($RUST_TARGET)..."
mkdir -p "target/$TARGET"

if [[ "$TARGET" == wasm ]]; then
    cargo rustc --release --target "$RUST_TARGET" --no-default-features \
        --features "$FEATURES" --lib --crate-type=cdylib
    cp "$RELEASE_DIR/fluxor.wasm" target/wasm/firmware.wasm
    exit 0
fi

cargo build --release --target "$RUST_TARGET" --no-default-features --features "$FEATURES"

case "$TARGET" in
  qemu-virt|pi5) OBJCOPY=rust-objcopy ;;
  *)             OBJCOPY=arm-none-eabi-objcopy ;;
esac
"$OBJCOPY" -O binary "$RELEASE_DIR/fluxor" "target/$TARGET/firmware.bin"
