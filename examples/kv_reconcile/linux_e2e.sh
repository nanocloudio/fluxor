#!/usr/bin/env bash
# Live Phase-D reconcile E2E — a control-plane reconciler as a PIC fmod driving
# the versioned keyspace provider (contract 0x17) end to end.
#
# Proves the fmod-migration Phase-D architecture on real binaries: the
# kv_reconcile module, loaded into the fluxor-linux runtime, SUBSCRIBEs an
# input prefix, and on a seeded input change GETs the input + PUTs the derived
# output — all via provider_call to the keyspace surface. Verified by parsing
# the volume-projected WAL for the reconciled output key.
#
# Usage: examples/kv_reconcile/linux_e2e.sh   (builds nothing — expects
#   `make tools linux-bin` and `fluxor modules build --target bcm2712` done)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FX="$ROOT/target/aarch64-unknown-linux-gnu/debug/fluxor"
RUNTIME="$ROOT/target/aarch64-unknown-linux-gnu/release/fluxor-linux"
MODULES_DIR="$ROOT/target/fluxor/bcm2712/modules"
GRAPH="$ROOT/examples/kv_reconcile/linux.yaml"

for f in "$FX" "$RUNTIME" "$MODULES_DIR/kv_reconcile.fmod"; do
  [ -e "$f" ] || { echo "FAIL: missing artifact $f (build first)"; exit 1; }
done

D="$(mktemp -d /tmp/kvr-e2e-XXXXXX)"
trap 'rm -rf "$D"' EXIT
fail() { echo "FAIL: $1"; tail -20 "$D/run.log" 2>/dev/null || true; exit 1; }

echo "== 1. build the config + module table =="
"$FX" generate "$GRAPH" --binary -m "$MODULES_DIR" -o "$D/config.bin" >/dev/null
"$FX" mktable-config "$GRAPH" --modules-dir "$MODULES_DIR" --output "$D/modules.bin" >/dev/null

echo "== 2. seed the input on the projected volume (WAL) =="
# A pre-existing input, as if a controller placed it: /recon/in/svc=10.0.0.1.
# WAL record: [rev:u64 LE][op:u8=PUT][key_len:u16 LE][val_len:u32 LE][key][val]
python3 - "$D/keyspace.wal" <<'PY'
import struct, sys
key, val = b"/recon/in/svc", b"10.0.0.1"
rec = struct.pack("<QBHI", 1, 1, len(key), len(val)) + key + val
open(sys.argv[1], "wb").write(rec)
PY

echo "== 3. run the reconciler in the fluxor-linux runtime =="
FLUXOR_KEYSPACE_DIR="$D" RUST_LOG=warn timeout 1 "$RUNTIME" \
  --config "$D/config.bin" --modules "$D/modules.bin" >"$D/run.log" 2>&1 || true

echo "== 4. verify the reconciled output was written to the store =="
OUT="$(python3 - "$D/keyspace.wal" <<'PY'
import struct, sys
data = open(sys.argv[1], "rb").read()
p, out = 0, None
while p + 15 <= len(data):
    rev, op, kl, vl = struct.unpack("<QBHI", data[p:p+15])
    k = data[p+15:p+15+kl]; v = data[p+15+kl:p+15+kl+vl]
    if k == b"/recon/out/svc":
        out = v
    p += 15 + kl + vl
print(out.decode() if out else "")
PY
)"
[ "$OUT" = "10.0.0.1" ] || fail "reconciler did not write /recon/out/svc=10.0.0.1 (got '$OUT')"

echo "== E2E green: reconciler wrote /recon/out/svc=$OUT via the keyspace provider =="
