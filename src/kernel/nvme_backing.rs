//! NVMe backing-store dispatch registry.
//!
//! Mirrors the `blob_store` / `graph_slot` pattern: the NVMe PIC
//! driver module exports a dispatch function which the kernel's
//! `backing_store::backing_read/write` path calls synchronously when
//! an arena is registered with `BackingType::Nvme`.
//!
//! Opcodes used by the dispatch fn are declared here so the kernel
//! side and the module side agree without pulling in ABI constants.
//! The dispatch fn itself is free to use its own internal CIDs / DMA
//! buffers; the kernel just cares about the (op, arena_lba, vpage,
//! buf) → i32 contract.

/// Op constants for the dispatch fn.
pub mod op {
    /// Read one page (PAGE_SIZE bytes) from the device into `buf`.
    ///
    /// arg layout (24 bytes, little-endian):
    ///   [arena_lba_base: u64][vpage_idx: u32][buf_ptr: u64][_pad: u32]
    pub const READ_PAGE:  u32 = 0x0001;
    /// Write one page (PAGE_SIZE bytes) from `buf` to the device.
    pub const WRITE_PAGE: u32 = 0x0002;
    /// Flush the driver's in-flight writeback (no-op if synchronous).
    pub const FLUSH:      u32 = 0x0003;
}

/// Dispatch function signature: `(state, opcode, arg, arg_len) -> i32`.
/// `i32` is 0 on success, negative errno on failure.
pub type NvmeBackingDispatchFn =
    unsafe extern "C" fn(state: *mut u8, opcode: u32, arg: *mut u8, arg_len: usize) -> i32;

static mut DISPATCH: Option<NvmeBackingDispatchFn> = None;
static mut STATE: *mut u8 = core::ptr::null_mut();

/// Called from the NVMe PIC module after `Identify Namespace` has
/// completed, via the `NVME_BACKING_ENABLE` syscall. Records the
/// dispatch fn so `backing_store` can route pager reads/writes.
///
/// # Safety
/// `dispatch` must be a live function pointer exported by the caller's
/// module; `state` must point to the caller's state arena and stay
/// live until the graph tears down.
pub unsafe fn register(dispatch: NvmeBackingDispatchFn, state: *mut u8) {
    DISPATCH = Some(dispatch);
    STATE = state;
    log::info!("[nvme_backing] dispatch registered");
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

/// Returns true once an NVMe-backed arena can be used.
pub fn ready() -> bool {
    unsafe { (*(&raw const DISPATCH)).is_some() }
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
