//! Blob store dispatch registry.
//!
//! The blob_store PIC module implements the on-flash format and serves
//! PUT/GET/DELETE. The kernel only holds a dispatch-function pointer and
//! the caller's state pointer so syscall handlers can forward into the
//! module. Mirrors the runtime parameter store pattern in
//! `src/platform/rp_flash_store.rs`.

/// Dispatch function signature: `(state, opcode, arg, arg_len) -> i32`.
/// The module exports this as `blob_store_dispatch`.
pub type BlobStoreDispatchFn =
    unsafe extern "C" fn(state: *mut u8, opcode: u32, arg: *mut u8, arg_len: usize) -> i32;

/// Registered dispatch function, or `None` when the blob_store module is
/// not present in the current graph.
static mut DISPATCH: Option<BlobStoreDispatchFn> = None;

/// State pointer for the registered dispatch function.
static mut STATE: *mut u8 = core::ptr::null_mut();

/// Called by the kernel when the blob_store module invokes
/// `BLOB_STORE_ENABLE`. Records the dispatch function and the caller's
/// module state. Subsequent PUT/GET/DELETE syscalls route here.
///
/// # Safety
/// `dispatch` must be a valid function pointer with the declared
/// signature; `state` must point to the calling module's state arena
/// and remain live until the graph is torn down.
pub unsafe fn register(dispatch: BlobStoreDispatchFn, state: *mut u8) {
    DISPATCH = Some(dispatch);
    STATE = state;
}

/// Clear the registration. Called by `scheduler::reset` so a new graph
/// does not inherit a stale pointer into the previous state arena.
pub fn unregister() {
    unsafe {
        DISPATCH = None;
        STATE = core::ptr::null_mut();
    }
}

/// Forward an opcode to the registered dispatch function. Returns
/// `-ENOSYS` when no module has registered.
pub fn dispatch(opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    unsafe {
        match DISPATCH {
            Some(f) => f(STATE, opcode, arg, arg_len),
            None => crate::kernel::errno::ENOSYS,
        }
    }
}
