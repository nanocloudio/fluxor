#!/usr/bin/env bash
# Live TCP-lease E2E — the stream-side counterpart of dns_server/linux_e2e.sh.
#
# Proves an HTTP-serving owned workload end to end on an unprivileged port,
# with real binaries and real sockets:
#   1. `fluxor build` emits the committed bundle from app.fluxor.toml
#   2. reserved-port policy refuses the bundle at admission
#   3. unreserved, the commit grants the tcp lease
#   4. the runtime binds it (declared+bound tcp/18080 in `agent status --json`)
#   5. routed paths answer from the graph (/healthz, /); unrouted are 404
#   6. `agent remove` frees the port; the host can rebind it
#
# Usage: examples/edge_server/linux_e2e.sh   (from anywhere; builds no code —
# expects `make tools linux-bin` and `fluxor modules build --target bcm2712`
# to have produced their artifacts already)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FX="$ROOT/target/aarch64-unknown-linux-gnu/debug/fluxor"
RUNTIME="$ROOT/target/aarch64-unknown-linux-gnu/release/fluxor-linux"
MODULES_DIR="$ROOT/target/fluxor/bcm2712/modules"
GRAPH="$ROOT/examples/edge_server/linux.yaml"
POD_UID="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
LISTEN_PORT=18080

for f in "$FX" "$RUNTIME" "$MODULES_DIR/http.fmod"; do
  [ -e "$f" ] || { echo "FAIL: missing artifact $f (build first)"; exit 1; }
done

D="$(mktemp -d /tmp/fluxor-edge-e2e-XXXXXX)"
RUNTIME_PID=""
cleanup() {
  [ -n "$RUNTIME_PID" ] && kill "$RUNTIME_PID" 2>/dev/null || true
  rm -rf "$D"
}
trap cleanup EXIT

fail() { echo "FAIL: $1"; echo "--- runtime.log tail ---"; tail -20 "$D/runtime.log" 2>/dev/null || true; exit 1; }

# One-shot HTTP client: GET $2 from 127.0.0.1:$1, print "<status> <body>".
http_get() {
  python3 - "$1" "$2" <<'PY'
import socket, sys
port, path = int(sys.argv[1]), sys.argv[2]
s = socket.create_connection(("127.0.0.1", port), timeout=3.0)
s.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
data = b""
try:
    while True:
        chunk = s.recv(4096)
        if not chunk: break
        data += chunk
except socket.timeout:
    pass
if not data:
    print("NORESPONSE"); sys.exit(0)
head, _, body = data.partition(b"\r\n\r\n")
status = head.split(b"\r\n")[0].split(b" ")[1].decode()
print(status, body.decode(errors="replace").strip())
PY
}

echo "== 1. source manifest emits the committed bundle =="
( cd "$ROOT" && "$FX" build examples/edge_server/app.fluxor.toml >/dev/null )
BUNDLE="$ROOT/target/fluxor/edge/linux"
[ -f "$BUNDLE/workload.json" ] || fail "emitted bundle missing at $BUNDLE"

echo "== 2. reserved port refuses admission =="
# One platform module (linux_net at compiled index 0) precedes the pod range.
"$FX" agent policy --store "$D/store" --system-modules 1 >/dev/null
"$FX" agent policy --store "$D/store" --reserved-ports "$LISTEN_PORT" >/dev/null
if "$FX" agent commit --store "$D/store" --publish "$D/current.plan" \
    --pod-uid "$POD_UID" --name edge-svc --bundle "$BUNDLE" 2>"$D/refuse.err"; then
  fail "commit succeeded despite reserved port $LISTEN_PORT"
fi
grep -q "EndpointConflict" "$D/refuse.err" || fail "refusal was not EndpointConflict: $(cat "$D/refuse.err")"

echo "== 3. unreserved, the tcp lease grants =="
"$FX" agent policy --store "$D/store" --reserved-ports "" >/dev/null
HANDLE=$("$FX" agent commit --store "$D/store" --publish "$D/current.plan" \
    --pod-uid "$POD_UID" --name edge-svc --bundle "$BUNDLE")
[ "$HANDLE" = "fluxor://$POD_UID/1" ] || fail "unexpected handle '$HANDLE'"

echo "== 4. runtime binds the leased tcp port =="
# -m matters: without it generate finds no .fmod param schema and silently
# drops every module param (routes and port would vanish).
"$FX" generate "$GRAPH" --binary -m "$MODULES_DIR" -o "$D/config.bin" >/dev/null
"$FX" mktable-config "$GRAPH" --modules-dir "$MODULES_DIR" --output "$D/modules.bin" >/dev/null
FLUXOR_PLAN="$D/current.plan" RUST_LOG=info \
  "$RUNTIME" --config "$D/config.bin" --modules "$D/modules.bin" >"$D/runtime.log" 2>&1 &
RUNTIME_PID=$!

BOUND=""
for _ in $(seq 1 40); do
  sleep 0.25
  if "$FX" agent status --store "$D/store" --json 2>/dev/null \
      | python3 -c 'import json,sys; d=json.load(sys.stdin); eps=[e for p in d["pods"] for e in p.get("endpoints",[])]; ok=any(e["protocol"]=="tcp" and e["port"]==18080 and e["bound"] and e["declared"] for e in eps); sys.exit(0 if ok else 1)'; then
    BOUND=yes; break
  fi
done
[ -n "$BOUND" ] || fail "tcp/$LISTEN_PORT never reported declared+bound"

echo "== 5. routed paths answer from the graph =="
R=$(http_get "$LISTEN_PORT" /healthz)
[ "$R" = "200 ok" ] || fail "/healthz answered '$R' (want '200 ok')"
R=$(http_get "$LISTEN_PORT" /)
case "$R" in 200*fluxor\ edge*) ;; *) fail "/ answered '$R' (want 200 + landing body)";; esac
R=$(http_get "$LISTEN_PORT" /no-such-path)
case "$R" in 404*) ;; *) fail "/no-such-path answered '$R' (want 404)";; esac

echo "== 6. remove frees the port; the host resumes it =="
"$FX" agent remove --store "$D/store" --publish "$D/current.plan" \
    --pod-uid "$POD_UID" --grace 1 >/dev/null
FREED=""
for _ in $(seq 1 40); do
  sleep 0.25
  if python3 - "$LISTEN_PORT" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("0.0.0.0", int(sys.argv[1]))); s.close()
except OSError:
    sys.exit(1)
PY
  then FREED=yes; break; fi
done
[ -n "$FREED" ] || fail "tcp/$LISTEN_PORT still held after remove"

echo "== E2E green =="
