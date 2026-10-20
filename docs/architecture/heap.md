# Per-Module Heap Allocation

Source: `src/kernel/mem/heap.rs`, `modules/sdk/runtime/heap.rs`

## Overview

Fluxor provides optional per-module heap allocation. Each module may request
a bounded heap at config time, and the graph may size it per instance. Within
that cap, the module can dynamically allocate and free memory through
syscall-table entries
(`heap_alloc`, `heap_free`, `heap_realloc`). The heap is bounded, per-module,
kernel-managed, and observable. Modules that do not request a heap are
unaffected -- no code change, no overhead.

## Architecture

```
STATE_ARENA (bump-allocated by kernel)

  +----------+  +----------+  +----------+
  | Module A |  | Module B |  | Module C |   ...
  |  state   |  |  state   |  |  state   |
  |  (fixed) |  |  (fixed) |  |  (fixed) |
  +----------+  +----------+  +----------+
  +----------+  +---------------------+
  | Module A |  | Module C            |
  |  heap    |  |  heap               |
  |  arena   |  |  arena              |
  |  (4 KB)  |  |  (16 KB)           |
  +----------+  +---------------------+

  (Module B has no heap -- not affected)
```

The allocator runs inside the kernel, called through SyscallTable function
pointers. Each module's heap is independent. Its memory comes from
STATE_ARENA in one of two ways.

### Committed and elastic heaps

A heap has a **cap**: the most it may hold. How the cap is backed depends on
the module and the platform profile (`HEAP_SEGMENTS` in
`src/kernel/config.rs`):

- **Committed** — one contiguous block, the whole cap, carved at
  instantiation (the picture above). Every gated module (`protection:
  contained` or `isolated`: its heap must lie where its protection regions
  cover it) and every module on a one-segment profile (RP and wasm, whose
  small arenas are planned up front).
- **Elastic** — linux and bcm2712 (`HEAP_SEGMENTS = 8`). Nothing is carved at
  instantiation. The first allocation carves a segment of
  `cap >> 7` bytes (at least the 64 KiB quantum, at least the request); an
  allocation no segment can serve carves the next, each at least as large as
  everything committed so far, until the committed total reaches the cap.
  Eight carves always reach the cap; the last takes what is left.

```
STATE_ARENA
  +---------+ +------------+ +------------------------+
  | seg 0   | | seg 1      | | seg 2                  |  ... up to 8,
  | cap/128 | | >= seg 0   | | >= seg 0 + seg 1       |  sum <= cap
  +---------+ +------------+ +------------------------+
   carved on    carved when    carved when 0 and 1
   first alloc  seg 0 is full  cannot serve a request
```

An elastic heap costs its module only what it touches: a reader type declared
for the largest object it might ever hold commits, per instance, what that
instance actually reads.

Elastic growth follows the bare-metal rules:

- **Bounded work.** A carve is one state-arena allocation (first fit over the
  arena's bounded free list, else a bump) and zeroing exactly the bytes
  carved; the segment table is fixed. No search grows with the heap.
- **Above 1 GB on the Pi 5.** Segments come from the state arena, the linker
  region above the first GB, and are zeroed as they are handed out — never a
  region wholesale.
- **Fail loud.** Growth that cannot be satisfied (the cap reached, or the
  state arena exhausted) returns null, counts the failure (`fail_count`, and
  `grow_denied` in the kernel), logs it (rate-limited to powers of two), and
  raises a fault under `heap.alloc_failure_policy: fault`. Nothing is ever
  handed out past the cap.
- **Freed with the module.** Teardown and live remove return every segment
  with the rest of the module's memory (held back while a block source still
  has a buffer lent from it); a rebuild resets the arena wholesale.

A module that uses its arena as raw memory (`ARENA_GET`) gets the whole cap
(rounded down to the allocator's 8-byte blocks) committed as one segment on its
first call, and the same arena on every later one — provided it has not grown in
pieces through `heap_alloc` first, since there is then no contiguous arena to
hand out (the call answers no arena, and the kernel logs why).

The owner of a workload module is charged its heap's **cap** against its
`state_cap`, so admission bounds the worst case rather than a snapshot.

## Declaring Heap Needs

Modules that need heap declare it in their manifest
(`declare_module_arena_bytes!`) or export `module_arena_size() -> u32`:

```rust
#[no_mangle]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 {
    4096 // request 4 KB heap
}
```

That figure is the module TYPE's default cap. Modules without it receive no
heap, unless the graph gives an instance one (below).

### Per-instance cap: `heap.arena_bytes`

The graph may set an instance's cap, overriding its type's:

```yaml
modules:
  - name: big_reader
    type: store_big
    heap:
      arena_bytes: 2097152     # this instance reads objects up to ~2 MiB
```

A positive integer number of bytes (at least 24, at most `u32::MAX`). The
tools pack it as params tag `0xEF` (a u32 LE) beside the other per-module
kernel tags, in a base graph's module entry and a workload module's params
alike; the kernel reads it before it sizes the heap. It is not a node tag: a
workload module may set it, and its owner is charged for it.

## Syscall API

Three entries in the SyscallTable:

| Function | Signature | Description |
|----------|-----------|-------------|
| `heap_alloc` | `fn(size: u32) -> *mut u8` | Allocate `size` bytes (rounded to 16B). Returns null on failure. |
| `heap_free` | `fn(ptr: *mut u8)` | Free allocation. Null is a no-op. Invalid pointer is logged. |
| `heap_realloc` | `fn(ptr: *mut u8, new_size: u32) -> *mut u8` | Grow/shrink. Null return = failure (original unchanged). |

## SDK Helpers

In `modules/sdk/runtime/heap.rs`:

```rust
// Allocate from this module's heap
let buf = heap_alloc(sys, 256);
if buf.is_null() {
    return -12; // ENOMEM
}

// Use the buffer...

// Free when done
heap_free(sys, buf);

// Reallocate (returns null on failure, original unchanged)
let bigger = heap_realloc(sys, buf, 512);
```

## Observability

Query heap statistics via `provider_query` with key
`query_key::HEAP_STATS` (6); `handle = -1` queries the calling
module's own heap:

| Field | Type | Description |
|-------|------|-------------|
| arena_size | u32 | The heap's cap in bytes (an elastic heap commits it as used) |
| allocated | u32 | Currently allocated bytes (excluding headers) |
| alloc_count | u16 | Number of active allocations |
| total_allocs | u16 | Lifetime allocation count |
| high_water | u32 | Peak allocated bytes |
| free_blocks | u16 | Number of free blocks (fragmentation indicator) |
| largest_free | u32 | Largest allocation the heap can serve next: its largest free block, or what it can still commit |

PIC runtime helper:

```rust
let (arena_size, allocated, alloc_count, total_allocs, high_water,
     free_blocks, largest_free) = heap_stats(sys);
```

## Allocator Design

Simple freelist with first-fit and immediate coalescing on free:

- 8-byte header per block (size+flags, next pointer)
- 16-byte minimum allocation granularity
- One address-ordered free list per segment; an allocation tries the
  segments in order, then grows
- O(n) allocation in number of free blocks (bounded by cap / 16)
- Forward and backward coalescing on free to reduce fragmentation

The kernel's `[arena]` boot line reports what heaps hold beside the state
arena: `heap=<committed>/<caps> heaps=<n>`.

## Config Behaviour Keys

The heap's cap comes from the module type (manifest or
`module_arena_size()` export) or the instance's `heap.arena_bytes`. A
module's YAML entry can tune heap behaviour through the optional `heap:`
subtree, validated in `tools/src/config/builder.rs`:

```yaml
modules:
  - name: json_parser
    heap:
      arena_bytes: 65536                 # this instance's cap
      zero_on_free: true                 # scrub freed blocks
      alloc_failure_policy: return_null  # or "fault"
      canary_enabled: true               # overflow canaries
```

`alloc_failure_policy: fault` routes an exhausted heap into the module
fault machinery instead of returning null. On a committed-heap profile the
whole cap is carved at instantiation, so the sum of every module's state and
heap cap must fit the target's STATE_ARENA; on an elastic profile only what
the heaps commit has to fit, and a heap that cannot grow fails loudly.

## Rules for Module Authors

1. **Heap allocation is for setup and adaptation, not per-sample work.**
   Build data structures during `module_new()` or on infrequent configuration
   changes. The per-step work should operate on already-allocated structures.

2. **Handle allocation failure.** `heap_alloc` returns null when the arena is
   exhausted. Modules must check for null and degrade gracefully.

3. **Free what you allocate.** The heap resets on graph reconfigure, so leaks
   within a single graph lifetime are bounded. But modules that allocate and
   free during operation must free promptly to avoid fragmentation.

4. **Declare your heap budget honestly.** The type's declared arena is the
   default cap: the most any instance of it may need. A graph that knows an
   instance needs less (or more) says so with `heap.arena_bytes`. On an
   elastic profile an instance commits only what it allocates either way.

5. **Take buffers that live together as one allocation.** An elastic heap's
   segments are not contiguous and no allocation spans two, so buffers taken
   one by one can leave a segment's tail too short for the next and run out
   before a cap declared at their sum. Buffers a module holds for its whole
   life are one `heap_alloc` of their sum, carved by the module; the cap is
   that sum (plus the 4-byte canary under `canary_enabled`) rounded up to 16
   bytes, plus the 8-byte block header.

6. **Do not cast heap pointers to state pointers or vice versa.** The heap
   arena and the state block are separate allocations.

## Checklist for Heap-Using Modules

- [ ] Does the module export `module_arena_size()` with a non-zero value?
- [ ] Does `module_new()` call `heap_alloc()` and check for null?
- [ ] Is heap allocation confined to setup paths?
- [ ] Is the heap budget documented and validated against the target?
- [ ] Is the high-water mark checked under representative workloads?

## Impact on Constrained Targets

| Target | STATE_ARENA | Typical Heap Budget |
|--------|-------------|---------------------|
| RP2040 | 64 KiB | 1-4 KiB per module |
| RP2350 | 240 KiB | 4-32 KiB per module |
| BCM2712, Linux | 1 GiB | KiB to MiB per module (elastic) |
| wasm | 96 MiB | KiB to MiB per module |

The heap is opt-in and bounded. Modules that do not use it pay
nothing.
