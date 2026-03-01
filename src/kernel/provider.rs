//! Provider dispatch — registered handlers for device class operations.
//!
//! Instead of a monolithic match in `dev_call`, each device class registers
//! a dispatch function at startup. New bus/device types add a provider
//! without modifying the central dispatch logic.
//!
//! Providers can be:
//! - Kernel-internal functions (registered at startup via `register()`)
//! - PIC module exports (registered at runtime via `register_module_provider()`)
//!
//! Module providers take priority over kernel providers for the same class.

use crate::kernel::errno;

/// Function signature for a kernel-internal device class provider.
///
/// Arguments match `dev_call`: handle, opcode, arg pointer, arg length.
/// Returns: result code (0 = success, >0 = bytes/count, <0 = errno).
pub type ProviderDispatch = unsafe fn(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32;

/// Function signature for a PIC module device class provider.
///
/// First arg is the module's state pointer, remaining match `dev_call`.
/// Called synchronously from kernel context. MUST NOT block or perform async I/O.
pub type ModuleProviderDispatchFn =
    unsafe extern "C" fn(state: *mut u8, handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32;

/// Maximum device classes (matches 5-bit class field extracted from opcode).
const MAX_PROVIDERS: usize = 32;

/// Provider entry — combines kernel and module providers for a single device class.
struct ProviderEntry {
    /// Kernel-internal dispatch (None if no kernel provider).
    kernel_dispatch: Option<ProviderDispatch>,
    /// Module provider index (0xFF = none).
    module_idx: u8,
    /// Module provider dispatch function (None if no module provider).
    module_dispatch: Option<ModuleProviderDispatchFn>,
    /// Module state pointer (passed as first arg to module dispatch).
    module_state: *mut u8,
}

impl ProviderEntry {
    const fn empty() -> Self {
        Self {
            kernel_dispatch: None,
            module_idx: 0xFF,
            module_dispatch: None,
            module_state: core::ptr::null_mut(),
        }
    }
}

/// Provider table — indexed by device class number (0x00..0x1F).
static mut PROVIDERS: [ProviderEntry; MAX_PROVIDERS] = [const { ProviderEntry::empty() }; MAX_PROVIDERS];

/// Register a kernel-internal provider for a device class. Called at kernel startup.
///
/// Panics if class >= MAX_PROVIDERS (should never happen for valid classes).
pub fn register(class: u8, dispatch: ProviderDispatch) {
    let idx = class as usize;
    assert!(idx < MAX_PROVIDERS, "device class out of range");
    unsafe {
        PROVIDERS[idx].kernel_dispatch = Some(dispatch);
    }
}

/// Register a PIC module as provider for a device class.
///
/// Returns 0 on success, EINVAL if class is out of range,
/// EBUSY if a module provider is already registered for this class.
pub fn register_module_provider(
    class: u8,
    module_idx: u8,
    dispatch: ModuleProviderDispatchFn,
    state: *mut u8,
) -> i32 {
    let idx = class as usize;
    if idx >= MAX_PROVIDERS {
        return errno::EINVAL;
    }
    unsafe {
        if PROVIDERS[idx].module_dispatch.is_some() {
            return errno::EBUSY;
        }
        PROVIDERS[idx].module_idx = module_idx;
        PROVIDERS[idx].module_dispatch = Some(dispatch);
        PROVIDERS[idx].module_state = state;
    }
    0
}

/// Unregister a module provider for a device class.
///
/// Only the owning module can unregister (checked by caller).
/// Returns 0 on success, EINVAL if class out of range or no module provider.
pub fn unregister_module_provider(class: u8) -> i32 {
    let idx = class as usize;
    if idx >= MAX_PROVIDERS {
        return errno::EINVAL;
    }
    unsafe {
        if PROVIDERS[idx].module_dispatch.is_none() {
            return errno::EINVAL;
        }
        PROVIDERS[idx].module_idx = 0xFF;
        PROVIDERS[idx].module_dispatch = None;
        PROVIDERS[idx].module_state = core::ptr::null_mut();
    }
    0
}

/// Release all module providers owned by a given module index.
/// Called on module finish (Done/Error) for cleanup.
pub fn release_module_providers(module_idx: u8) {
    unsafe {
        let providers = &mut *(&raw mut PROVIDERS);
        for entry in providers.iter_mut() {
            if entry.module_idx == module_idx {
                entry.module_idx = 0xFF;
                entry.module_dispatch = None;
                entry.module_state = core::ptr::null_mut();
            }
        }
    }
}

/// Dispatch an operation to the registered provider for the given class.
///
/// Module providers take priority over kernel providers.
/// Returns E_NOSYS if no provider is registered for this class.
///
/// # Safety
/// `arg` must satisfy the aliasing and validity requirements expected by the
/// registered dispatch handler for the given `class` and `opcode`.
pub unsafe fn dispatch(class: u8, handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let idx = class as usize;
    if idx >= MAX_PROVIDERS {
        return errno::ENOSYS;
    }
    unsafe {
        let entry = &PROVIDERS[idx];

        // Try module provider first
        if let Some(dispatch_fn) = entry.module_dispatch {
            let saved = crate::kernel::scheduler::current_module_index();
            crate::kernel::scheduler::set_current_module(entry.module_idx as usize);
            let result = dispatch_fn(entry.module_state, handle, opcode, arg, arg_len);
            crate::kernel::scheduler::set_current_module(saved);
            return result;
        }

        // Fall back to kernel provider
        match entry.kernel_dispatch {
            Some(handler) => handler(handle, opcode, arg, arg_len),
            None => errno::ENOSYS,
        }
    }
}
