// ============================================================================
// WASM-target syscall import surface
// ============================================================================
//
// On `wasm32-unknown-unknown` the kernel and each module live in
// separate `WebAssembly.Memory` instances, so the kernel's
// `*const SyscallTable` can't be dereferenced from inside a module.
// Each module declares the syscall surface as `extern "C"` imports
// and a static `WASM_SYSCALLS` populates `SyscallTable` with
// references to them at compile time. The host wires the imports to
// the kernel's exported syscall handlers at instantiation. Modules
// pass `&WASM_SYSCALLS` to their own `module_init` / `module_new` /
// `module_step` instead of the `*const SyscallTable` argument the
// kernel hands in, which is unused on wasm.

#[cfg(target_arch = "wasm32")]
mod wasm_syscalls {
    extern "C" {
        pub fn channel_read(handle: i32, buf: *mut u8, len: usize) -> i32;
        pub fn channel_write(handle: i32, data: *const u8, len: usize) -> i32;
        pub fn channel_poll(handle: i32, events: u32) -> i32;
        pub fn channel_peek(handle: i32, buf: *mut u8, len: usize) -> i32;
        pub fn provider_open(
            contract: u32,
            open_op: u32,
            config: *const u8,
            config_len: usize,
        ) -> i32;
        pub fn provider_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32;
        pub fn provider_query(handle: i32, key: u32, out: *mut u8, out_len: usize) -> i32;
        pub fn provider_close(handle: i32) -> i32;
    }
}

// ── Per-module heap (wasm32) ────────────────────────────────────────
//
// Each wasm module has its own linear memory. The kernel's heap sits
// in the kernel's memory and isn't reachable by module-side pointers,
// so `heap_alloc` / `heap_free` / `heap_realloc` on wasm32 run a
// module-local bump allocator whose backing storage lives in the
// module's own linear memory, grown via `memory.grow`.
//
// The arena is sized from `module_state_size + module_arena_size +
// slack`. `memory.grow` extends linear memory by enough 64 KiB pages
// to cover the budget; the returned page index is the heap base.
// Modules with `module_arena_size == 0` still get one page so the
// state struct and the init-time params blob fit.
//
// The allocator is bump-only: free is a no-op, realloc copies. Modules
// that need a free-list preallocate at init.

#[cfg(target_arch = "wasm32")]
const WASM_PAGE_BYTES: usize = 65536;

/// Slack added on top of `state_size + arena_size` to cover alignment
/// and the one-shot params blob (`MODULE_INSTANCE_PARAMS`) read in
/// `module_init_wasm`. One page covers any realistic manifest.
#[cfg(target_arch = "wasm32")]
const WASM_HEAP_INIT_SLACK_BYTES: usize = WASM_PAGE_BYTES;

#[cfg(target_arch = "wasm32")]
static mut WASM_HEAP_BASE: *mut u8 = core::ptr::null_mut();
#[cfg(target_arch = "wasm32")]
static mut WASM_HEAP_SIZE: usize = 0;
#[cfg(target_arch = "wasm32")]
static mut WASM_HEAP_USED: usize = 0;

/// Initialise the per-module heap. Idempotent. The first call grows
/// linear memory by enough pages to fit `state_size + arena_size +
/// slack`; subsequent calls return without touching memory.
///
/// `state_size` and `arena_size` come from the kernel-side wasm shim,
/// which reads the module's `module_state_size` and (optional)
/// `module_arena_size` exports before invoking `module_init_wasm`.
///
/// # Safety
/// Mutates the `WASM_HEAP_*` statics — single-threaded wasm rules out
/// concurrent access. Calls `core::arch::wasm32::memory_grow`.
#[cfg(target_arch = "wasm32")]
pub unsafe fn wasm_heap_init(state_size: usize, arena_size: usize) {
    if !WASM_HEAP_BASE.is_null() {
        return;
    }
    let total = state_size + arena_size + WASM_HEAP_INIT_SLACK_BYTES;
    let pages = total.div_ceil(WASM_PAGE_BYTES);
    let prev = core::arch::wasm32::memory_grow(0, pages);
    if prev == usize::MAX {
        return;
    }
    let base = (prev * WASM_PAGE_BYTES) as *mut u8;
    let aligned = ((base as usize + 15) & !15) as *mut u8;
    let pad = aligned as usize - base as usize;
    WASM_HEAP_BASE = aligned;
    WASM_HEAP_SIZE = pages * WASM_PAGE_BYTES - pad;
    WASM_HEAP_USED = 0;
}

#[cfg(target_arch = "wasm32")]
unsafe extern "C" fn wasm_heap_alloc(size: u32) -> *mut u8 {
    if WASM_HEAP_BASE.is_null() {
        return core::ptr::null_mut();
    }
    let size = ((size as usize) + 15) & !15;
    let used = WASM_HEAP_USED;
    if used + size > WASM_HEAP_SIZE {
        return core::ptr::null_mut();
    }
    let ptr = WASM_HEAP_BASE.add(used);
    WASM_HEAP_USED = used + size;
    ptr
}

#[cfg(target_arch = "wasm32")]
unsafe extern "C" fn wasm_heap_free(_ptr: *mut u8) {
    // Bump allocator. Memory is reclaimed when the host destroys the
    // module instance and its linear memory.
}

#[cfg(target_arch = "wasm32")]
unsafe extern "C" fn wasm_heap_realloc(ptr: *mut u8, new_size: u32) -> *mut u8 {
    let fresh = wasm_heap_alloc(new_size);
    if fresh.is_null() || ptr.is_null() {
        return fresh;
    }
    // The old block's size isn't tracked; bound the copy by the
    // distance from `ptr` to the heap end so reads can't escape the
    // heap region.
    let offset = (ptr as usize).saturating_sub(WASM_HEAP_BASE as usize);
    let max_readable = WASM_HEAP_SIZE.saturating_sub(offset);
    let copy_len = (new_size as usize).min(max_readable);
    core::ptr::copy_nonoverlapping(ptr, fresh, copy_len);
    fresh
}

/// `SyscallTable` populated at compile time with references to the
/// wasm-imported syscalls. Modules use `&WASM_SYSCALLS` in place of
/// the `*const SyscallTable` passed to `module_init` / `module_new` /
/// `module_step` — that pointer is meaningless across linear-memory
/// boundaries.
#[cfg(target_arch = "wasm32")]
#[used]
#[no_mangle]
pub static WASM_SYSCALLS: SyscallTable = SyscallTable {
    // Sourced from the ABI constant (wire.rs `ABI_VERSION`, included above) so
    // an ABI bump propagates here automatically instead of drifting at a
    // hardcoded 1. The SyscallTable layout ratchet in kernel_abi.rs forces the
    // bump on any field change; this mirror tracks it in lockstep.
    version: ABI_VERSION as u32,
    channel_read: wasm_syscalls::channel_read,
    channel_write: wasm_syscalls::channel_write,
    channel_poll: wasm_syscalls::channel_poll,
    heap_alloc: wasm_heap_alloc,
    heap_free: wasm_heap_free,
    heap_realloc: wasm_heap_realloc,
    provider_open: wasm_syscalls::provider_open,
    provider_call: wasm_syscalls::provider_call,
    provider_query: wasm_syscalls::provider_query,
    provider_close: wasm_syscalls::provider_close,
    channel_peek: wasm_syscalls::channel_peek,
};

// On wasm32 `module_init_wasm` (in `modules/sdk/runtime/wasm_entry.rs`)
// passes `&WASM_SYSCALLS` to the module's `module_new`. On native
// targets the kernel passes its own `SyscallTable` pointer. Same
// source on both targets.

