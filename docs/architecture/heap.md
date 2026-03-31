# Per-Module Heap Allocation

## Overview

Fluxor provides optional per-module heap allocation. Each module may request
a bounded heap arena at config time. Within that arena, the module can
dynamically allocate and free memory through syscall-table entries
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

The heap arena is a contiguous block within STATE_ARENA, allocated by the
kernel at module instantiation time (alongside the state block). The allocator
runs inside the kernel, called through SyscallTable function pointers. Each
module's heap is independent.

## Declaring Heap Needs

Modules that need heap export `module_arena_size() -> u32`:

```rust
#[no_mangle]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 {
    4096 // request 4 KB heap
}
```

The kernel allocates this from STATE_ARENA during module instantiation and
initializes a freelist allocator within it. Modules without this export
receive no heap.

## Syscall API

Three new entries in the SyscallTable (appended, backward-compatible):

| Function | Signature | Description |
|----------|-----------|-------------|
| `heap_alloc` | `fn(size: u32) -> *mut u8` | Allocate `size` bytes (rounded to 16B). Returns null on failure. |
| `heap_free` | `fn(ptr: *mut u8)` | Free allocation. Null is a no-op. Invalid pointer is logged. |
| `heap_realloc` | `fn(ptr: *mut u8, new_size: u32) -> *mut u8` | Grow/shrink. Null return = failure (original unchanged). |

## PIC Runtime Helpers

In `modules/pic_runtime.rs`:

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

Query heap statistics via `dev_query` with key `HEAP_STATS` (6):

| Field | Type | Description |
|-------|------|-------------|
| arena_size | u32 | Total heap arena size in bytes |
| allocated | u32 | Currently allocated bytes (excluding headers) |
| alloc_count | u16 | Number of active allocations |
| total_allocs | u16 | Lifetime allocation count |
| high_water | u32 | Peak allocated bytes |
| free_blocks | u16 | Number of free blocks (fragmentation indicator) |
| largest_free | u16 | Largest free block in bytes |

PIC runtime helper:

```rust
let (arena_size, allocated, alloc_count, total_allocs, high_water) = heap_stats(sys);
```

## Allocator Design

Simple freelist with first-fit and immediate coalescing on free:

- 8-byte header per block (size+flags, next pointer)
- 16-byte minimum allocation granularity
- O(n) allocation in number of free blocks (bounded by arena_size / 16)
- Forward and backward coalescing on free to reduce fragmentation

## Config Validation

The `heap_arena_kb` field in module config overrides the module's
`module_arena_size()` value:

```yaml
modules:
  - name: json_parser
    heap_arena_kb: 8
```

The validation tool checks that total state + heap arena fits within the
target's STATE_ARENA:

```
sum(module_state_size[i] + heap_arena_size[i]) <= STATE_ARENA_SIZE
```

## Rules for Module Authors

1. **Heap allocation is for setup and adaptation, not per-sample work.**
   Build data structures during `module_new()` or on infrequent configuration
   changes. The per-step work should operate on already-allocated structures.

2. **Handle allocation failure.** `heap_alloc` returns null when the arena is
   exhausted. Modules must check for null and degrade gracefully.

3. **Free what you allocate.** The heap resets on graph reconfigure, so leaks
   within a single graph lifetime are bounded. But modules that allocate and
   free during operation must free promptly to avoid fragmentation.

4. **Declare your heap budget honestly.** `module_arena_size()` should return
   the maximum heap the module will ever need. The config tool validates total
   arena usage.

5. **Do not cast heap pointers to state pointers or vice versa.** The heap
   arena and the state block are separate allocations.

## Checklist for Heap-Using Modules

- [ ] Does the module export `module_arena_size()` with a non-zero value?
- [ ] Does `module_new()` call `heap_alloc()` and check for null?
- [ ] Is heap allocation confined to setup paths?
- [ ] Is the heap budget documented and validated against the target?
- [ ] Is the high-water mark tested under representative workloads?

## Impact on Constrained Targets

| Target | STATE_ARENA | Typical Heap Budget |
|--------|-------------|---------------------|
| RP2040 | 64 KB | 1-4 KB per module |
| RP2350 | 256 KB | 4-32 KB per module |
| BCM2712 | 256 KB | 4-32 KB per module |

The heap is opt-in, bounded, and zero-cost when unused. Modules that don't
use heap pay nothing. A firmware image with no heap-requesting modules is
functionally identical to pre-heap builds.
