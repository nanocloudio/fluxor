//! Graph slot dispatch registry.
//!
//! The graph_slot PIC module owns the A/B slot format and flash writes.
//! The kernel only holds a dispatch-function pointer and state pointer
//! so the slot opcodes can be forwarded from `syscalls.rs`. Mirrors
//! the `blob_store` and runtime parameter store patterns.

/// Dispatch function signature: `(state, opcode, arg, arg_len) -> i32`.
pub type GraphSlotDispatchFn =
    unsafe extern "C" fn(state: *mut u8, opcode: u32, arg: *mut u8, arg_len: usize) -> i32;

static mut DISPATCH: Option<GraphSlotDispatchFn> = None;
static mut STATE: *mut u8 = core::ptr::null_mut();

/// Record the module's dispatch function and state pointer. Called
/// from the `GRAPH_SLOT_ENABLE` syscall handler.
///
/// # Safety
/// `dispatch` must be a valid function pointer with the declared
/// signature; `state` must point to the calling module's state arena
/// and remain live until the graph is torn down.
pub unsafe fn register(dispatch: GraphSlotDispatchFn, state: *mut u8) {
    DISPATCH = Some(dispatch);
    STATE = state;
}

/// Clear the registration, called by `scheduler::reset` so a new graph
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
