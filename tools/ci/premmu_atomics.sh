#!/bin/bash
# No atomic read-modify-write runs on the Pi 5 before its MMU is on.
#
# With the MMU off every data access is Device-nGnRnE, and on the Cortex-A76
# a store-exclusive there never succeeds: a spinlock taken that early spins
# for ever, before the UART is up, and the board boots dark. An LSE atomic
# is refused too, as no safer on Device memory. QEMU lets those atomics
# succeed, so no QEMU boot can catch one; this check reads the pi5 kernel
# image itself instead.
#
# From `main`, it follows every path up to the call that turns the MMU on
# (`fluxor::arch::aarch64::boot_mmu::enable`, kept out of line for this),
# and every function those paths call, transitively, plus the entry stub
# that runs before `main`. A panic is not followed: one this early is a dark
# boot whatever the handler then does. Any exclusive (`ldxr`/`stxr` and
# their acquire, release, byte, half and pair forms) or LSE atomic (`cas*`,
# `swp*`, `ld<op>*`, `st<op>*`) in that set fails it, and so does anything
# it cannot follow: an indirect call, or a computed branch inside `main`
# before the switch. A missing `main`, switch symbol or call to it fails it
# too, so a renamed or inlined boundary cannot pass silently. Secondary
# cores turn their MMU on in their entry trampoline before any call
# (`platform::multicore::secondary_core_trampoline`), so the boot core's
# path is the one to check.
#
#   ELF      the pi5 kernel to read (default: built here with
#            `tools/firmware.sh pi5`, at target/pi5/firmware.elf)
#   OBJDUMP  disassembler (default: rust-objdump, which the aarch64 firmware
#            build already needs for rust-objcopy)
set -euo pipefail
[[ -n "${ELF:-}" ]] && ELF=$(realpath -- "$ELF")
cd "$(dirname "$0")/../.."

OBJDUMP=${OBJDUMP:-rust-objdump}
command -v "$OBJDUMP" >/dev/null || { echo "premmu_atomics: needs $OBJDUMP" >&2; exit 1; }
command -v python3 >/dev/null || { echo "premmu_atomics: needs python3" >&2; exit 1; }

if [[ -z "${ELF:-}" ]]; then
    tools/firmware.sh pi5 >/dev/null
    ELF=target/pi5/firmware.elf
fi
[[ -f "$ELF" ]] || { echo "premmu_atomics: no kernel at $ELF" >&2; exit 1; }

entry=$("$OBJDUMP" -f "$ELF" | awk '/start address/ { print $NF }')
"$OBJDUMP" -d --no-show-raw-insn --demangle "$ELF" | python3 -I -c '
import re, sys

entry = int(sys.argv[1], 16)
SWITCH = re.compile(r"(^|::)arch::aarch64::boot_mmu::enable(::h[0-9a-f]{16})?$")
ATOMIC = re.compile(
    r"^(ld[a]?xr[bh]?|ld[a]?xp|st[l]?xr[bh]?|st[l]?xp"
    r"|casp?(a|l|al)?[bh]?|swp(a|l|al)?[bh]?"
    r"|ld(add|clr|eor|set|smax|smin|umax|umin)(a|l|al)?[bh]?"
    r"|st(add|clr|eor|set|smax|smin|umax|umin)l?[bh]?)$"
)
# A panic this early is a dark boot whatever it then does, so the panic
# machinery (and the logging behind it) is not followed.
PANIC = re.compile(r"^(core::panicking::|rust_begin_unwind)")
BRANCH = re.compile(r"^(b(\.\w+)?|cbn?z|tbn?z)$")
FUNC = re.compile(r"^([0-9a-f]+) <(.+)>:$")
INSN = re.compile(r"^\s+([0-9a-f]+):\s+(\S+)\s*(.*)$")
TARGET = re.compile(r"(?:0x)?([0-9a-f]+)(?:\s+<[^>]*>)?\s*$")

funcs = {}   # start -> (name, [(addr, mnemonic, operands)])
cur = None
for line in sys.stdin:
    m = FUNC.match(line)
    if m:
        cur = int(m.group(1), 16)
        funcs[cur] = (m.group(2), [])
        continue
    m = INSN.match(line)
    if m and cur is not None:
        funcs[cur][1].append((int(m.group(1), 16), m.group(2), m.group(3).split("//")[0].strip()))

by_name = {name: start for start, (name, _) in funcs.items()}
starts = sorted(funcs)

def owner(addr):
    lo, hi = 0, len(starts)
    while lo < hi:
        mid = (lo + hi) // 2
        if starts[mid] <= addr:
            lo = mid + 1
        else:
            hi = mid
    return starts[lo - 1] if lo else None

def target(ops):
    m = TARGET.search(ops)
    return int(m.group(1), 16) if m else None

def fail(msg):
    print("premmu_atomics: " + msg, file=sys.stderr)
    sys.exit(1)

main = by_name.get("main")
if main is None:
    fail("no `main` in the image")
switch = [s for s, (n, _) in funcs.items() if SWITCH.search(n)]
if len(switch) != 1:
    fail("expected one out-of-line `arch::aarch64::boot_mmu::enable`, found %d" % len(switch))
switch = switch[0]

hits, why = [], {}      # why: function start -> caller chain
work = []

def reach(fn, chain):
    if fn is None:
        fail("%s: a branch leaves every known function" % " -> ".join(chain))
    if PANIC.search(funcs[fn][0]):
        return
    if fn not in why and fn != main:
        why[fn] = chain
        work.append(fn)

def check(addr, mn, ops, chain):
    if ATOMIC.match(mn):
        hits.append("%s\n    %x: %s %s" % (" -> ".join(chain), addr, mn, ops))

# `main`, path by path, up to the call that turns the MMU on.
name, body = funcs[main]
index = {a: i for i, (a, _, _) in enumerate(body)}
seen, todo, met_switch = set(), [body[0][0]], False
while todo:
    a = todo.pop()
    while a in index and a not in seen:
        seen.add(a)
        _, mn, ops = body[index[a]]
        check(a, mn, ops, ["main"])
        t = target(ops)
        if mn == "bl":
            if t == switch:
                met_switch = True
                break
            if t is None:
                fail("main: unresolved call at %x: %s" % (a, ops))
            reach(owner(t), ["main", funcs.get(owner(t), ("?",))[0]])
        elif mn in ("blr", "blraa", "blraaz", "blrab", "blrabz"):
            fail("main: indirect call at %x before the MMU is on" % a)
        elif mn in ("br", "braa", "braaz", "brab", "brabz"):
            fail("main: computed branch at %x before the MMU is on" % a)
        elif mn in ("ret", "eret") or mn.startswith("reta"):
            break
        elif BRANCH.match(mn):
            if t is None:
                fail("main: unresolved branch at %x: %s" % (a, ops))
            if owner(t) != main:
                reach(owner(t), ["main", funcs.get(owner(t), ("?",))[0]])
            else:
                todo.append(t)
            if mn == "b":
                break
        nxt = index[a] + 1
        if nxt >= len(body):
            break
        a = body[nxt][0]
if not met_switch:
    fail("no path from main reaches the call to `arch::aarch64::boot_mmu::enable`")

# The entry stub before `main`, and every function reached: whole bodies.
ent = owner(entry)
if ent is not None and ent != main:
    reach(ent, [funcs[ent][0]])
reach(switch, ["main", funcs[switch][0]])
while work:
    fn = work.pop()
    name, body = funcs[fn]
    chain = why[fn]
    for a, mn, ops in body:
        check(a, mn, ops, chain)
        if mn in ("blr", "blraa", "blraaz", "blrab", "blrabz"):
            fail("%s: indirect call at %x, reached before the MMU is on" % (" -> ".join(chain), a))
        if mn == "bl" or BRANCH.match(mn):
            t = target(ops)
            if t is None:
                fail("%s: unresolved branch at %x: %s" % (" -> ".join(chain), a, ops))
            o = owner(t)
            if o != fn:
                reach(o, chain + [funcs[o][0]])

if hits:
    fail("atomic read-modify-write before the MMU is on (it never completes on Device "
         "memory, so the boot core spins dark):\n  " + "\n  ".join(hits))
print("  premmu_atomics: %d functions before the MMU switch, no atomics" % (len(why) + 1))
' "$entry"
