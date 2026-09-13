#!/bin/bash
# The RP dependency trees contain exactly what they declare.
#
# This asks Cargo what each RP configuration resolves to, rather than reading
# source for imports: a crate can be in the tree with no `use` anywhere and
# still be linked, and a feature enabled transitively is easy to acquire
# without noticing. Every crate in the resolved tree must be on the list
# below, so a new dependency is a deliberate change to this file.
set -euo pipefail
cd "$(dirname "$0")/../.."

# rp2040-boot2 is a data dependency supplying a checksummed flash blob and
# contributes no control flow.
ALLOW="critical-section fluxor fluxor-contracts log portable-atomic rp2040-boot2"

fail=0
for spec in "pico2w thumbv8m.main-none-eabihf chip-rp2350b" \
            "picow thumbv6m-none-eabi chip-rp2040"; do
    set -- $spec
    board=$1 triple=$2 chip=$3
    tree="$(FLUXOR_BOARD=$board cargo tree --target "$triple" \
        --no-default-features --features "$chip" \
        --prefix none -e normal 2>/dev/null | awk '{print $1}' | sort -u)"
    [[ -n "$tree" ]] || { echo "rp-closure: could not resolve $board" >&2; exit 2; }
    for crate in $tree; do
        if ! grep -qw -- "$crate" <<<"$ALLOW"; then
            echo "rp-closure: $board resolves $crate, which is not on the list" >&2
            fail=1
        fi
    done
done
if [[ $fail -eq 0 ]]; then
    echo "rp-closure: both RP trees resolve only the declared crates"
fi
exit $fail
