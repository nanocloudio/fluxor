#!/bin/bash
# Dependency-count ratchet.
#
# Holds each build configuration to a declared package ceiling and fails when
# one rises. Raising a ceiling is a deliberate edit to this file, in the commit
# that adds the dependency, with the reason in the commit message — so the
# count moves when someone decides it should, rather than drifting.
#
# Not a limit-register family. `standards/limit-register.md` §1 admits
# identifier widths and deliberate caps, and §3 fixes a
# `NAME | source path | right-hand side` row shape that a package count cannot
# fill; §6 names `tools/ci/` as the home for a project-local checkable claim,
# which is what this is.
set -euo pipefail
cd "$(dirname "$0")/../.."

fail=0

# Each ceiling is the measured count exactly, so every one of them binds.
# `cargo tree -e normal` counts the crate itself and in-tree path crates too.
check() {
    local label=$1 triple=$2 features=$3 ceiling=$4
    local n
    n=$(cargo tree --no-default-features --features "$features" \
            --target "$triple" -e normal --prefix none 2>/dev/null \
        | grep -v '^$' | sort -u | wc -l)
    if [[ "$n" -gt "$ceiling" ]]; then
        echo "deps: $label is $n packages, ceiling $ceiling — raise the ceiling in tools/ci/deps_budget.sh, in the commit that adds the dependency" >&2
        fail=1
    else
        printf '  %-22s %3d / %3d\n' "$label" "$n" "$ceiling"
    fi
}

echo "dependency budget:"
check "kernel rp2350"  thumbv8m.main-none-eabihf   chip-rp2350b  5
check "kernel rp2040"  thumbv6m-none-eabi          chip-rp2040   5
check "kernel bcm2712" aarch64-unknown-none        chip-bcm2712  4
check "kernel wasm"    wasm32-unknown-unknown      host-wasm     4
check "kernel linux"   aarch64-unknown-linux-gnu   host-linux    20

# The CLI is measured as a whole package graph rather than by feature.
#
# Normal dependencies only: dev-dependencies (tempfile and friends) are test
# scaffolding and do not ship, and the rig load probes are a crate of their own
# under `tools/rig-observers/`, where their async runtime stays.
#
# Measured from `tools/` rather than with `-p fluxor-tools` from the root: that
# is the resolution that actually builds the binary, and the two disagree.
n=$(cd tools && cargo tree --target aarch64-unknown-linux-gnu -e normal --prefix none 2>/dev/null \
    | grep -v '^$' | sort -u | wc -l)
ceiling=77
if [[ "$n" -gt "$ceiling" ]]; then
    echo "deps: fluxor-tools is $n packages, ceiling $ceiling — raise the ceiling in tools/ci/deps_budget.sh, in the commit that adds the dependency" >&2
    fail=1
else
    printf '  %-22s %3d / %3d\n' "fluxor-tools" "$n" "$ceiling"
fi

exit $fail
