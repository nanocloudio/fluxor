// WASM module entry-point wrappers.
//
// Each module's `mod.rs` ends with
//
//     include!("../../sdk/wasm_entry.rs");
//
// after defining `module_state_size`, `module_init`, `module_new`,
// and `module_step` with the standard PIC signatures. On non-wasm
// targets this file emits nothing.
//
// On `target_arch = "wasm32"` it emits two exports the wasm kernel
// calls via `host_invoke_module`:
//
//   `module_init_wasm(in_chan, out_chan, ctrl_chan, arena_size) -> i32`
//      Initialises the per-module heap (state + arena + slack), pulls
//      the per-instance params blob via `MODULE_INSTANCE_PARAMS`,
//      allocates state, and calls the module's own `module_init` and
//      `module_new` with `&WASM_SYSCALLS` as the syscall table.
//      Returns 0 on success or a negative errno; the kernel skips
//      the module on failure.
//
//      The four args arrive as i32 LE in the kernel-side args blob.
//      `in_chan` / `out_chan` / `ctrl_chan` are the module's slot-0
//      ports (or -1 when undeclared); modules with extra ports look
//      them up inside their own `module_new` via `dev_channel_port`.
//      `arena_size` comes from the module's optional
//      `module_arena_size` export, probed by the kernel-side wasm
//      shim and passed through here.
//
//   `module_step_wasm() -> i32`
//      Reads the state pointer stashed by `module_init_wasm` and
//      delegates to the module's `module_step`.

#[cfg(target_arch = "wasm32")]
mod __wasm_entry {
    // Module handler signatures (PIC ABI):
    //   module_state_size() -> u32
    //   module_init(syscalls: *const c_void)
    //   module_new(in_chan, out_chan, ctrl_chan,
    //              params, params_len, state, state_size, syscalls) -> i32
    //   module_step(state: *mut u8) -> i32
    //
    // The state struct stashes the `syscalls` pointer at `module_new`
    // time, so `module_step` only needs the state pointer.
    use super::wasm_heap_init;
    use super::WASM_SYSCALLS;
    use super::{module_init, module_new, module_state_size, module_step, SyscallTable};

    /// MODULE_INSTANCE_PARAMS opcode; mirrors
    /// `modules/sdk/kernel_abi.rs::MODULE_INSTANCE_PARAMS`.
    const OP_MODULE_INSTANCE_PARAMS: u32 = 0x0C43;

    static mut STATE_PTR: *mut u8 = core::ptr::null_mut();

    #[no_mangle]
    pub extern "C" fn module_init_wasm(
        in_chan: i32,
        out_chan: i32,
        ctrl_chan: i32,
        arena_size: u32,
    ) -> i32 {
        let sys: &SyscallTable = unsafe { &WASM_SYSCALLS };

        // Module handlers vary between `u32` and `usize` returns and
        // between `*mut u8` / `*mut c_void` state pointers. Both
        // shapes are raw-pointer-equivalent at the wasm32 ABI level,
        // so each call below transmutes through a fn-pointer of the
        // canonical shape.
        let state_size = unsafe {
            let f: extern "C" fn() -> u32 =
                core::mem::transmute(module_state_size as *const ());
            f() as usize
        };

        unsafe {
            wasm_heap_init(state_size, arena_size as usize);
        }

        // Two-phase params fetch: query size with `out=null`, then
        // allocate and query into the real buffer. Avoids a fixed
        // truncation cap.
        let params_size = unsafe {
            (sys.provider_query)(-1, OP_MODULE_INSTANCE_PARAMS, core::ptr::null_mut(), 0)
        };
        let (params_ptr, params_len): (*const u8, usize) = if params_size > 0 {
            let n = params_size as usize;
            let buf = unsafe { (sys.heap_alloc)(params_size as u32) };
            if buf.is_null() {
                return -1;
            }
            let got =
                unsafe { (sys.provider_query)(-1, OP_MODULE_INSTANCE_PARAMS, buf, n) };
            if got < 0 || (got as usize) != n {
                return -1;
            }
            (buf as *const u8, n)
        } else {
            (core::ptr::null(), 0)
        };

        let state = unsafe { (sys.heap_alloc)(state_size as u32) };
        if state.is_null() {
            return -1;
        }

        let sys_void = sys as *const SyscallTable as *const core::ffi::c_void;
        unsafe {
            let f: extern "C" fn(*const core::ffi::c_void) =
                core::mem::transmute(module_init as *const ());
            f(sys_void);
        }
        let r = unsafe {
            let f: extern "C" fn(
                i32,
                i32,
                i32,
                *const u8,
                usize,
                *mut core::ffi::c_void,
                usize,
                *const core::ffi::c_void,
            ) -> i32 = core::mem::transmute(module_new as *const ());
            f(
                in_chan,
                out_chan,
                ctrl_chan,
                params_ptr,
                params_len,
                state as *mut core::ffi::c_void,
                state_size,
                sys_void,
            )
        };
        if r != 0 {
            return r;
        }

        unsafe {
            STATE_PTR = state;
        }
        0
    }

    #[no_mangle]
    pub extern "C" fn module_step_wasm() -> i32 {
        let state = unsafe { STATE_PTR };
        if state.is_null() {
            return -1;
        }
        let f: extern "C" fn(*mut core::ffi::c_void) -> i32 =
            unsafe { core::mem::transmute(module_step as *const ()) };
        f(state as *mut core::ffi::c_void)
    }
}
