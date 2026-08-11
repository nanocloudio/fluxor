#!/bin/bash
# Build a boot image with module signature ENFORCEMENT on, for any
# kernel target.
#
#   tools/signed-image.sh <target> <config.yaml> <out.img>
#
# A default build is permissive: unsigned modules load. Enforcement is
# the `enforce_signatures` cargo feature, and the root of trust is a
# public key compiled into the kernel (`option_env!` in
# src/kernel/module/loader.rs). So an enforcing image is a MATCHED PAIR
# — a kernel carrying the public key, and modules signed with the
# private half — and assembling that pair correctly is what this script
# is for. Mismatch it and the board boots and rejects every module,
# which reads as a load failure rather than a key mismatch.
#
# Target, graph and output path are arguments because all three are the
# caller's to choose; add a build recipe to the project's `rig.toml`
# and the rig fills them in:
#
#   [build.pi5-signed]
#   command = ["tools/signed-image.sh", "pi5", "${scenario.config}", "target/pi5/signed.img"]
#   artifact = "target/pi5/signed.img"
#
# The private seed is the one machine-local input, so it stays an
# environment override with an XDG default — a rig profile supplies it
# through `${env:…}`. It is generated 0600 on first use and reused;
# rotate with `fluxor modules keygen -k "$SIGN_KEY" --force`. Keep it
# OUT of git.
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: tools/signed-image.sh <target> <config.yaml> <out.img>" >&2
    exit 2
fi
TARGET="$1"
CONFIG="$2"
IMG="$3"
SIGN_KEY="${SIGN_KEY:-${XDG_CONFIG_HOME:-$HOME/.config}/fluxor/signing/$TARGET.seed}"

mkdir -p "$(dirname "$SIGN_KEY")" "$(dirname "$IMG")"

echo "[signed] resolving signing pubkey ($SIGN_KEY)..."
PUBKEY="$(fluxor modules keygen -k "$SIGN_KEY")"
echo "[signed] FLUXOR_SIGNING_PUBKEY_HEX=$PUBKEY"

# The kernel build is `firmware.sh`'s, with the enforcement feature
# added on top — so each target's triple and feature set stay in one
# place.
echo "[signed] building enforce_signatures firmware for $TARGET..."
FLUXOR_SIGNING_PUBKEY_HEX="$PUBKEY" EXTRA_FEATURES=enforce_signatures \
    tools/firmware.sh "$TARGET"

# Where a target's modules live is the CLI's answer, not this script's:
# `resolve` maps a board onto its silicon's directory. `modules build`
# is the deliberate asymmetry — it takes silicon only, because building
# "for a board" is a level error — so the silicon comes back out of the
# resolved path, whose `<out>/<silicon>/modules` shape is the layout
# contract in standards/fluxor-modules.md §6.
MODULES_DIR="$(fluxor modules resolve --target "$TARGET")"
SILICON="$(basename "$(dirname "$MODULES_DIR")")"

echo "[signed] building + signing modules for $SILICON..."
fluxor modules build --target "$SILICON"
for m in "$MODULES_DIR"/*.fmod; do
    fluxor modules sign -k "$SIGN_KEY" "$m"
done

echo "[signed] combining $CONFIG -> $IMG..."
fluxor build "$CONFIG" --emit=combined \
    --firmware "target/$TARGET/firmware.bin" -o "$IMG"
echo "[signed] done: $IMG (unsigned/tampered modules will be rejected)"
