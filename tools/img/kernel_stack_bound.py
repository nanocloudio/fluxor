#!/usr/bin/env python3
"""Bound the kernel's stack depth on a core from the firmware ELF.

    kernel_stack_bound.py <firmware.elf> --root <symbol> --limit <bytes>
                          [--leaf <symbol substring>]...
                          [--refuse <symbol substring>]...
                          [--reaches <caller substring>=<callee substring>]...
                          [--dispatch-from <symbol substring>]...
                          [--dispatch-table <symbol substring>]...
                          [--dispatch-depth <n>]
                          [--depth-at <symbol substring> --depth-at-limit <bytes>
                           [--entry <symbol>]...
                           [--interrupt <symbol>]... [--exception-frame <bytes>]
                           [--allowance <bytes>]]
                          [--report]

Walks the image's disassembly from `--root` along calls and reports the
deepest path. Each function's frame is the sum of its stack-pointer
decrements (pushes, `sub sp`, `vpush`); a call stacks the callee's depth on
the caller's frame; a branch to another function is a tail call, whose depth
stands alone.

Calls through registers
-----------------------

A direct call names its callee. A call through a register does not, so the
walk is told where the kernel's own tables lead:

  - `--reaches A=B`: a register call in a function whose name contains `A`
    reaches every function whose name contains `B` (the log facade and the
    kernel's logger; the formatter and the logger's writer).

  - `--dispatch-from F`, `--dispatch-table T`: a register call in a function
    whose name contains `F` (the provider table's dispatch code) reaches
    every handler registered in the kernel's provider tables. The handlers
    are read from the image, not listed by hand: they are the functions
    whose address is taken in the code of a function whose name contains `T`
    (the functions that register providers, vtables and platform
    extensions), and the functions whose address is stored in a data object
    such a function names (a contract's vtable). A `T` that matches nothing
    fails the walk: the registration moved and the caller's list is stale.

    A handler may itself dispatch (a vtable's class-routed call into the
    kernel bucket, the bucket into the platform's extension), so dispatch
    edges nest, to `--dispatch-depth` levels (default 3: vtable, bucket,
    extension). A cycle that closes only through dispatch edges ends at
    that depth; a cycle of direct calls is recursion and fails.

What neither rule covers is counted and reported (`--report` lists the
functions with register calls no rule leads out of): the platform's HAL
hooks, formatters of single values, and a module's own code, which runs on
the stack the composer admitted it against. `--allowance` is the caller's
figure for those under a module call.

The bound under a module call
-----------------------------

`--depth-at M` names the function that calls into a module. The stack the
kernel needs under a module stepped on this core is

    in use at M
    + the deepest `--entry` (the functions a module calls back: the syscall
      table's entries), walked with the rules above, so through the
      provider table into every registered handler
    + one interrupt: `--exception-frame` (default 108: the extended frame
      and its alignment word) and the deepest `--interrupt` handler
    + `--allowance`

and the walk fails when that is over `--depth-at-limit` (the target's stack
reserve). Interrupts on these cores share one priority, so one handler runs
at a time.

Failures
--------

The walk fails, naming the path, when:

  - the deepest path from the root is over `--limit`;
  - a function on a walked path sizes its frame at run time;
  - a function on a walked path is recursive (its depth has no bound);
  - a `--refuse` symbol is reachable: a function that must not run on the
    stack being bounded, whatever its depth;
  - the bound under a module call is over `--depth-at-limit`;
  - a `--dispatch-table`, `--entry` or `--interrupt` names nothing.

A `--leaf` function is counted for its own frame and not walked below: one
whose callees the caller of this script bounds separately (the panic
handler, which is a root of its own), or one that refuses to go deeper on
this stack as its first act (the kernel's `primary_stack_*` functions on a
core with a small stack).

Thumb only: the RP kernels are the ones with a stack small enough to need a
bound taken at build time.
"""
import argparse
import re
import struct
import subprocess
import sys

HEAD = re.compile(r"^([0-9a-f]{8}) <(.+)>:$")
INSN = re.compile(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$")
TARGET = re.compile(r"^([0-9a-f]+) <(.+)>$")
# Mnemonics that begin with `b` and are not branches.
NOT_BRANCH = ("bic", "bfi", "bfc", "bkpt", "bfx")


class Function:
    def __init__(self, addr, name):
        self.addr = addr
        self.name = name
        self.frame = 0
        self.calls = set()
        self.tails = set()
        self.indirect = 0
        self.dynamic = False
        # Address-sized constants the code materialises (`movw`/`movt`
        # pairs, literal-pool words): where it takes a function's address.
        self.constants = set()


def register_count(operand):
    count = 0
    for part in operand.strip("{} ").split(","):
        part = part.strip()
        if "-" in part:
            low, high = part.split("-")
            count += int(re.sub(r"\D", "", high)) - int(re.sub(r"\D", "", low)) + 1
        elif part:
            count += 1
    return count


def load(elf, objdump):
    text = subprocess.run(
        [objdump, "-d", "-C", "--no-show-raw-insn", elf],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    functions = {}
    current = None
    low_half = {}
    for line in text.splitlines():
        head = HEAD.match(line)
        if head:
            current = Function(int(head.group(1), 16), head.group(2))
            functions[current.addr] = current
            low_half = {}
            continue
        if current is None:
            continue
        insn = INSN.match(line)
        if not insn:
            continue
        op = insn.group(2)
        args = insn.group(3).split(";")[0].strip()
        base = op.split(".")[0]
        if base == "movw" and "#" in args:
            low_half[args.split(",")[0].strip()] = int(args.split("#")[1].split()[0], 0)
        elif base == "movt" and "#" in args:
            register = args.split(",")[0].strip()
            high = int(args.split("#")[1].split()[0], 0)
            current.constants.add((high << 16) | low_half.get(register, 0))
        elif base == "" and op == ".word":
            current.constants.add(int(args.split()[0], 16))
        if base == "push":
            current.frame += 4 * register_count(args)
        elif base == "stmdb" and args.startswith("sp!"):
            current.frame += 4 * register_count(args.split(",", 1)[1])
        elif base == "vpush":
            current.frame += (8 if "d" in args else 4) * register_count(args)
        elif base in ("sub", "subw", "subs") and re.match(r"sp,\s*(sp,\s*)?#", args):
            current.frame += int(args.split("#")[1].split()[0], 0)
        elif base in ("sub", "subs") and re.match(r"sp,\s*(sp,\s*)?r", args):
            current.dynamic = True
        elif base == "str" and re.search(r"\[sp,\s*#-(\d+)\]!", args):
            current.frame += int(re.search(r"\[sp,\s*#-(\d+)\]!", args).group(1))
        elif base in ("bl", "blx"):
            target = TARGET.match(args)
            if target:
                current.calls.add(int(target.group(1), 16))
            else:
                current.indirect += 1
        elif base == "bx":
            if not args.startswith("lr"):
                current.indirect += 1
        elif base.startswith("b") and not base.startswith(NOT_BRANCH):
            target = TARGET.match(args)
            # A branch inside the function names it with an offset; one to
            # another function's first instruction is a tail call.
            if target and "+0x" not in target.group(2):
                addr = int(target.group(1), 16)
                if addr != current.addr:
                    current.tails.add(addr)
    return functions


class Rules:
    """Where calls lead: the direct calls of each function, and the register
    calls the caller of this script named a destination for."""

    def __init__(self, functions, leaves, reaches, dispatch_from, handlers, dispatch_depth):
        self.functions = functions
        self.leaves = leaves
        self.reaches = [
            (caller, sorted(a for a, f in functions.items() if callee in f.name))
            for caller, callee in reaches
        ]
        self.dispatch_from = dispatch_from
        self.handlers = sorted(handlers)
        self.dispatch_depth = dispatch_depth

    def is_leaf(self, fn):
        return any(leaf in fn.name for leaf in self.leaves)

    def dispatches(self, fn):
        return fn.indirect > 0 and any(name in fn.name for name in self.dispatch_from)

    def covered(self, fn):
        """Whether a rule leads out of `fn`'s register calls."""
        return self.dispatches(fn) or any(caller in fn.name for caller, _ in self.reaches)

    def edges(self, addr, budget):
        """`(callee, callee's dispatch budget, is a tail call)` for every call
        out of `addr` walked with `budget` dispatch levels left."""
        fn = self.functions[addr]
        out = [(c, budget, False) for c in sorted(fn.calls)]
        out += [(c, budget, True) for c in sorted(fn.tails)]
        if fn.indirect:
            for caller, callees in self.reaches:
                if caller in fn.name:
                    out += [(c, budget, False) for c in callees if c != addr]
            if budget > 0 and self.dispatches(fn):
                out += [(c, budget - 1, False) for c in self.handlers]
        return out


def walk(rules, root):
    """(depth, path) of the deepest path from `root`, the depth of every
    `(function, dispatch budget)` reached, and the recursive functions."""
    functions = rules.functions
    memo = {}
    stack = []
    recursive = set()

    def depth(addr, budget):
        key = (addr, budget)
        if key in memo:
            return memo[key]
        fn = functions.get(addr)
        if fn is None:
            return (0, [])
        if key in stack:
            recursive.add(addr)
            return (0, [])
        if rules.is_leaf(fn):
            memo[key] = (fn.frame, [addr])
            return memo[key]
        stack.append(key)
        below = (0, [])
        deepest_tail = (0, [])
        for callee, left, tail in rules.edges(addr, budget):
            found = depth(callee, left)
            if tail:
                if found[0] > deepest_tail[0]:
                    deepest_tail = found
            elif found[0] > below[0]:
                below = found
        deepest = (fn.frame + below[0], [addr] + below[1])
        if deepest_tail[0] > deepest[0]:
            deepest = deepest_tail
        stack.pop()
        memo[key] = deepest
        return deepest

    result = depth(root, rules.dispatch_depth)
    return result, memo, recursive


def depth_at(rules, memo, root, goal_name):
    """The most stack in use from `root` down to and including a function
    whose name contains `goal_name`, and that function's name."""
    functions = rules.functions
    start = (root, rules.dispatch_depth)
    used = {start: functions[root].frame}
    # Longest path by relaxation; the walk has already refused cycles.
    for _ in range(len(memo) + 1):
        changed = False
        for key in list(used):
            addr, budget = key
            fn = functions[addr]
            if rules.is_leaf(fn):
                continue
            for callee, left, tail in rules.edges(addr, budget):
                if (callee, left) not in memo:
                    continue
                above = used[key] - fn.frame if tail else used[key]
                total = above + functions[callee].frame
                if total > used.get((callee, left), -1):
                    used[(callee, left)] = total
                    changed = True
        if not changed:
            break
    best = None
    for (addr, _), total in used.items():
        if goal_name in functions[addr].name and (best is None or total > best[0]):
            best = (total, functions[addr].name)
    return best


def chain_to(rules, memo, root, goal):
    """A path from `root` to `goal`, for a refusal's message."""
    start = (root, rules.dispatch_depth)
    parent = {start: None}
    queue = [start]
    found = None
    while queue:
        key = queue.pop(0)
        if key[0] == goal:
            found = key
            break
        if rules.is_leaf(rules.functions[key[0]]):
            continue
        for callee, left, _ in rules.edges(*key):
            if (callee, left) in memo and (callee, left) not in parent:
                parent[(callee, left)] = key
                queue.append((callee, left))
    path = []
    while found is not None:
        path.append(found[0])
        found = parent.get(found)
    return list(reversed(path))


def describe(functions, path):
    return "\n".join(
        "    %5d  %s" % (functions[a].frame, functions[a].name) for a in path
    )


def data_objects(elf, nm):
    """`{address: size}` of the image's named data objects."""
    listing = subprocess.run(
        [nm, "-S", "--defined-only", elf], check=True, capture_output=True, text=True
    ).stdout
    objects = {}
    for line in listing.splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4 and parts[2] in "rRdD":
            objects[int(parts[0], 16)] = int(parts[1], 16)
    return objects


def image_words(elf):
    """A reader of the little-endian word the ELF32 image holds at an
    address: `None` where no section with file contents covers it."""
    with open(elf, "rb") as handle:
        blob = handle.read()
    shoff, = struct.unpack_from("<I", blob, 0x20)
    shentsize, shnum = struct.unpack_from("<HH", blob, 0x2E)
    spans = []
    for i in range(shnum):
        kind, _, addr, offset, size = struct.unpack_from("<IIIII", blob, shoff + i * shentsize + 4)
        # SHT_PROGBITS with an address: code and initialised data.
        if kind == 1 and addr:
            spans.append((addr, size, offset))

    def word(address):
        for addr, size, offset in spans:
            if addr <= address and address + 4 <= addr + size:
                return struct.unpack_from("<I", blob, offset + address - addr)[0]
        return None

    return word


def registered_handlers(functions, objects, word, tables):
    """The functions the provider tables can hold: those whose address is
    taken in a function matching one of `tables`, or stored in a data
    object such a function names. Also the `tables` entries that match no
    function."""
    handlers = set()
    stale = []
    for pattern in tables:
        registering = [f for f in functions.values() if pattern in f.name]
        if not registering:
            stale.append(pattern)
            continue
        pending = set()
        for fn in registering:
            pending |= fn.constants
        seen = set()
        while pending:
            value = pending.pop()
            if value in seen:
                continue
            seen.add(value)
            if value & 1 and (value - 1) in functions:
                handlers.add(value - 1)
            elif value in objects:
                for at in range(value, value + objects[value] - 3, 4):
                    stored = word(at)
                    if stored is not None:
                        pending.add(stored)
    return handlers, stale


def one_function(functions, name):
    """The function named `name` exactly, else the one whose name contains
    it; `None` unless exactly one does."""
    found = [f for f in functions.values() if f.name == name] or [
        f for f in functions.values() if name in f.name
    ]
    return found[0] if len(found) == 1 else None


def pair(text):
    caller, _, callee = text.partition("=")
    if not caller or not callee:
        raise argparse.ArgumentTypeError("expected <caller>=<callee>")
    return (caller, callee)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    number = lambda v: int(v, 0)
    parser.add_argument("elf")
    parser.add_argument("--root", required=True, help="exact symbol, or a unique substring")
    parser.add_argument("--limit", required=True, type=number)
    parser.add_argument("--refuse", action="append", default=[])
    parser.add_argument("--leaf", action="append", default=[])
    parser.add_argument("--reaches", action="append", default=[], type=pair)
    parser.add_argument("--dispatch-from", action="append", default=[])
    parser.add_argument("--dispatch-table", action="append", default=[])
    parser.add_argument("--dispatch-depth", type=number, default=3)
    parser.add_argument("--depth-at")
    parser.add_argument("--depth-at-limit", type=number)
    parser.add_argument("--entry", action="append", default=[])
    parser.add_argument("--interrupt", action="append", default=[])
    parser.add_argument("--exception-frame", type=number, default=108)
    parser.add_argument("--allowance", type=number, default=0)
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--objdump", default="arm-none-eabi-objdump")
    args = parser.parse_args()

    functions = load(args.elf, args.objdump)
    root_fn = one_function(functions, args.root)
    if root_fn is None:
        print("kernel_stack_bound: --root %r names no one function" % args.root, file=sys.stderr)
        return 2
    root = root_fn.addr
    failures = []

    handlers = set()
    if args.dispatch_table:
        nm = re.sub(r"objdump$", "nm", args.objdump)
        handlers, stale = registered_handlers(
            functions, data_objects(args.elf, nm), image_words(args.elf), args.dispatch_table
        )
        for pattern in stale:
            failures.append("--dispatch-table %r names no function in the image" % pattern)
    rules = Rules(
        functions, args.leaf, args.reaches, args.dispatch_from, handlers, args.dispatch_depth
    )

    (depth, path), memo, recursive = walk(rules, root)
    reached = {addr for addr, _ in memo}

    if depth > args.limit:
        failures.append(
            "the deepest path from %s is %d B, over the %d B limit:\n%s"
            % (args.root, depth, args.limit, describe(functions, path))
        )
    for refused in args.refuse:
        for addr in sorted(reached):
            if refused in functions[addr].name:
                failures.append(
                    "%s is reachable from %s:\n%s"
                    % (
                        functions[addr].name,
                        args.root,
                        describe(functions, chain_to(rules, memo, root, addr)),
                    )
                )
                break

    # The bound under a module call: what is in use where the module is
    # called, the deepest entry it calls back, and one interrupt.
    lines = []
    if args.depth_at:
        at = depth_at(rules, memo, root, args.depth_at)
        if at is None:
            failures.append("no function matching %r is reachable from %s" % (args.depth_at, args.root))
        else:
            lines.append("%6d  in use at %s" % at)
            total = at[0]

            def deepest(names, what):
                best = (0, [])
                for name in names:
                    fn = one_function(functions, name)
                    if fn is None:
                        failures.append("--%s %r names no one function" % (what, name))
                        continue
                    found, below, cycles = walk(rules, fn.addr)
                    reached.update(addr for addr, _ in below)
                    recursive.update(cycles)
                    if found[0] > best[0]:
                        best = found
                return best

            entry = deepest(args.entry, "entry")
            if args.entry:
                lines.append("%6d  deepest entry:\n%s" % (entry[0], describe(functions, entry[1])))
                total += entry[0]
            if args.interrupt:
                handler = deepest(args.interrupt, "interrupt")
                lines.append("%6d  exception frame" % args.exception_frame)
                lines.append(
                    "%6d  deepest interrupt handler:\n%s"
                    % (handler[0], describe(functions, handler[1]))
                )
                total += args.exception_frame + handler[0]
            if args.allowance:
                lines.append("%6d  allowance for register calls no rule covers" % args.allowance)
                total += args.allowance
            lines.append("%6d  under a module call" % total)
            if args.depth_at_limit is not None and total > args.depth_at_limit:
                failures.append(
                    "the kernel needs %d B of stack under a module called from %s, over the "
                    "%d B reserve:\n%s" % (total, at[1], args.depth_at_limit, "\n".join(lines))
                )

    for addr in sorted(reached):
        if functions[addr].dynamic:
            failures.append("%s sizes its frame at run time" % functions[addr].name)
    for addr in sorted(recursive):
        failures.append("%s is recursive: its depth has no bound" % functions[addr].name)

    if args.report or failures:
        uncovered = sorted(
            functions[a].name
            for a in reached
            if functions[a].indirect and not rules.covered(functions[a])
        )
        print(
            "kernel_stack_bound: %s: %d B of %d B over %d functions; %d registered handlers; "
            "%d functions with register calls no rule covers"
            % (args.root, depth, args.limit, len(reached), len(handlers), len(uncovered))
        )
        for line in lines:
            print("kernel_stack_bound: " + line)
        if args.report:
            print(describe(functions, path))
            for addr in sorted(handlers):
                print("  handler    %s" % functions[addr].name)
            for name in uncovered:
                print("  uncovered  %s" % name)
    for failure in failures:
        print("kernel_stack_bound: " + failure, file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
