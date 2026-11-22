#!/bin/bash
# Build a boot image with module signature ENFORCEMENT on, for any
# kernel target.
#
#   tools/signed-image.sh <target> <config.yaml> <out.img>
#
# A signed image is a matched pair: modules signed by a key, and a kernel
# image carrying that key's public half as its signing root. One key gives
# both: `fluxor modules build` signs every module with `$FLUXOR_SIGNING_KEY`,
# and `fluxor build` writes its public key into the image it packs. The
# kernel is the ordinary one — a build never bakes a key in — so the root is
# a fact of the image, not of the binary. Mismatch the pair and the board
# boots and refuses every unsigned or foreign module, which reads as a load
# failure; the boot log names the root (`signing: root <id>`).
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

echo "[signed] signing key $SIGN_KEY, root $(fluxor modules keygen -k "$SIGN_KEY")"
export FLUXOR_SIGNING_KEY="$SIGN_KEY"

tools/firmware.sh "$TARGET"

# Where a target's modules live is the CLI's answer, not this script's:
# `resolve` maps a board onto its silicon's directory. `modules build`
# is the deliberate asymmetry — it takes silicon only, because building
# "for a board" is a level error — so the silicon comes back out of the
# resolved path, whose `<out>/<silicon>/modules` shape is the layout
# contract in standards/fluxor-modules.md §6.
MODULES_DIR="$(fluxor modules resolve --target "$TARGET")"
SILICON="$(basename "$(dirname "$MODULES_DIR")")"

echo "[signed] building and signing modules for $SILICON..."
fluxor modules build --target "$SILICON"

echo "[signed] combining $CONFIG -> $IMG with the key's root..."
fluxor build "$CONFIG" --emit=firmware \
    --firmware "target/$TARGET/firmware.bin" -o "$IMG"
echo "[signed] done: $IMG (unsigned/tampered modules run gated or not at all)"
