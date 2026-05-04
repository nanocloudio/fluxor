//! Generic backing-provider dispatch registry.
//!
//! A driver module that provides paged-arena backing storage (NVMe,
//! SD card, eMMC, raw flash, …) exports a dispatch function which
//! the kernel's `backing_store::backing_read/write` path calls
//! synchronously for arenas registered with `BackingType::External`.
//! Only one backing provider is active at a time — the last one to
//! register wins.
//!
//! The dispatch fn receives a page-granular `arena_base_page` from the
//! kernel (an abstract counter the kernel assigns per registered
//! arena) plus `vpage_idx` within that arena. The driver converts
//! these to its device-specific addressing however it wants (LBA,
//! sector, offset, …) — the kernel has no device-layout knowledge.

/// Op constants for the dispatch fn.
pub mod op {
    /// Read one page (PAGE_SIZE bytes) from the device into `buf`.
    ///
    /// arg layout (16 bytes, little-endian):
    ///   [arena_base_page: u32][vpage_idx: u32][buf_ptr: u64]
    pub const READ_PAGE: u32 = 0x0001;
    /// Write one page (PAGE_SIZE bytes) from `buf` to the device.
    pub const WRITE_PAGE: u32 = 0x0002;
    /// Flush the driver's in-flight writeback (no-op if synchronous).
    pub const FLUSH: u32 = 0x0003;
    /// Read N contiguous pages from the device into `buf`. Drivers
    /// that support multi-block transfers (e.g. NVMe with PRP lists)
    /// translate this to a single device command — amortizing the
    /// per-command roundtrip over many pages. `buf` covers
    /// `count * PAGE_SIZE` contiguous bytes; pages land at offsets
    /// 0, PAGE_SIZE, 2*PAGE_SIZE, ….
    ///
    /// arg layout (24 bytes, little-endian):
    ///   [arena_base_page: u32][vpage_idx_start: u32][count: u32][_pad: u32][buf_ptr: u64]
    pub const READ_PAGES: u32 = 0x0004;
    /// Write N contiguous pages from `buf` to the device. Same arg
    /// layout as `READ_PAGES`. Drivers MAY split into multiple device
    /// commands internally; the dispatch must not return until all
    /// pages have been queued (with deferred-writeback semantics)
    /// or persisted (write-through).
    pub const WRITE_PAGES: u32 = 0x0005;
}

/// Dispatch function signature: `(state, opcode, arg, arg_len) -> i32`.
/// `i32` is 0 on success, negative errno on failure.
pub type BackingProviderDispatchFn =
    unsafe extern "C" fn(state: *mut u8, opcode: u32, arg: *mut u8, arg_len: usize) -> i32;

static mut DISPATCH: Option<BackingProviderDispatchFn> = None;
static mut STATE: *mut u8 = core::ptr::null_mut();

/// Called from the provider PIC module once it's ready to serve page
/// I/O, via the `BACKING_PROVIDER_ENABLE` syscall. Records the
/// dispatch fn so `backing_store` can route pager reads/writes.
///
/// # Safety
/// `dispatch` must be a live function pointer exported by the caller's
/// module; `state` must point to the caller's state arena and stay
/// live until the graph tears down.
pub unsafe fn register(dispatch: BackingProviderDispatchFn, state: *mut u8) {
    DISPATCH = Some(dispatch);
    STATE = state;
    log::info!("[backing] provider dispatch registered");
}

/// Clear registration. `scheduler::reset` calls this between graph
/// rebuilds so a stale pointer into the previous state arena is not
/// kept alive.
pub fn unregister() {
    unsafe {
        DISPATCH = None;
        STATE = core::ptr::null_mut();
    }
}

/// Returns true once an External-backed arena can be used.
pub fn ready() -> bool {
    unsafe {
        let p = &raw const DISPATCH;
        (*p).is_some()
    }
}

/// Forward an opcode to the registered dispatch. `-ENOSYS` when no
/// module is registered. Callers in `backing_store` already check
/// `ready()` before invoking.
pub fn dispatch(opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    unsafe {
        match DISPATCH {
            Some(f) => f(STATE, opcode, arg, arg_len),
            None => crate::kernel::errno::ENOSYS,
        }
    }
}
