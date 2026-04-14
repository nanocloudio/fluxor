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
//! Module providers form a chain (stack) per device class. The top-of-chain
//! provider receives dispatch first. Middleware modules (TLS, compression)
//! can intercept calls and forward to the next layer via `CHAIN_NEXT`.

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

/// Maximum chain depth per device class (kernel + up to 3 middleware modules).
pub const MAX_CHAIN_DEPTH: usize = 3;

/// Flag ORed onto opcode to dispatch to the next provider below the caller.
pub const CHAIN_NEXT: u32 = 0x0001_0000;

/// A single layer in a provider chain.
struct ProviderLayer {
    module_idx: u8,
    dispatch: ModuleProviderDispatchFn,
    state: *mut u8,
}

/// Provider entry — combines kernel and module providers for a single device class.
struct ProviderEntry {
    /// Kernel-internal dispatch (None if no kernel provider).
    kernel_dispatch: Option<ProviderDispatch>,
    /// Module provider chain (stack). chain[depth-1] is the top.
    chain: [Option<ProviderLayer>; MAX_CHAIN_DEPTH],
    /// Number of active layers in the chain.
    depth: u8,
}

impl ProviderEntry {
    const fn empty() -> Self {
        Self {
            kernel_dispatch: None,
            chain: [const { None }; MAX_CHAIN_DEPTH],
            depth: 0,
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
/// Pushes the module onto the top of the chain. Returns 0 on success,
/// EINVAL if class is out of range or dispatch pointer is outside the
/// module's code region, EBUSY if chain is full.
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

    // Validate dispatch function pointer is within the registering module's
    // code region. Prevents a corrupted module from registering a pointer
    // into kernel memory or another module's code.
    let fn_addr = dispatch as usize;
    let (code_base, code_size) = crate::kernel::scheduler::module_code_region(module_idx as usize);
    if code_base != 0 && code_size != 0 {
        let code_end = code_base + code_size as usize;
        if fn_addr < code_base || fn_addr >= code_end {
            log::error!("[provider] module {} fn_ptr 0x{:08x} outside code region 0x{:08x}..0x{:08x}",
                module_idx, fn_addr, code_base, code_end);
            return errno::EINVAL;
        }
        // On Cortex-M (Thumb mode): verify LSB is set
        #[cfg(target_arch = "arm")]
        if fn_addr & 1 == 0 {
            log::error!("[provider] module {} fn_ptr 0x{:08x} missing Thumb bit", module_idx, fn_addr);
            return errno::EINVAL;
        }
    }

    unsafe {
        let entry = &mut PROVIDERS[idx];

        // Check same module isn't already registered for this class
        for i in 0..entry.depth as usize {
            if let Some(ref layer) = entry.chain[i] {
                if layer.module_idx == module_idx {
                    return errno::EBUSY;
                }
            }
        }

        // Check chain capacity
        if entry.depth as usize >= MAX_CHAIN_DEPTH {
            return errno::EBUSY;
        }

        // Push onto top of chain
        let d = entry.depth as usize;
        entry.chain[d] = Some(ProviderLayer {
            module_idx,
            dispatch,
            state,
        });
        entry.depth += 1;
        log::info!("[provider] module {} registered for class 0x{:02x} at depth {}", module_idx, class, entry.depth);
    }
    0
}

/// Release all module providers owned by a given module index.
/// Called on module finish (Done/Error) for cleanup.
/// Compacts chains to maintain stack ordering.
pub fn release_module_providers(module_idx: u8) {
    unsafe {
        let providers = &mut *(&raw mut PROVIDERS);
        for entry in providers.iter_mut() {
            // Compact: remove layers belonging to this module
            let mut write = 0usize;
            for read in 0..entry.depth as usize {
                let keep = match &entry.chain[read] {
                    Some(layer) => layer.module_idx != module_idx,
                    None => false,
                };
                if keep {
                    if write != read {
                        // Move layer down
                        let layer = entry.chain[read].take();
                        entry.chain[write] = layer;
                    }
                    write += 1;
                }
            }
            // Clear remaining slots
            for i in write..entry.depth as usize {
                entry.chain[i] = None;
            }
            entry.depth = write as u8;
        }
    }
}

/// Dispatch an operation to the registered provider for the given class.
///
/// Module provider chain top takes priority. Falls back to kernel provider.
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

        // Dispatch to top of chain if any module providers registered
        if entry.depth > 0 {
            let top = (entry.depth - 1) as usize;
            if let Some(ref layer) = entry.chain[top] {
                let saved = crate::kernel::scheduler::current_module_index();
                crate::kernel::scheduler::set_current_module(layer.module_idx as usize);
                let result = (layer.dispatch)(layer.state, handle, opcode, arg, arg_len);
                crate::kernel::scheduler::set_current_module(saved);
                return result;
            }
        }

        // Fall back to kernel provider
        match entry.kernel_dispatch {
            Some(handler) => handler(handle, opcode, arg, arg_len),
            None => {
                log::warn!("[provider] class 0x{:02x} op 0x{:04x}: no provider", class, opcode);
                errno::ENOSYS
            }
        }
    }
}

/// Dispatch to the next provider below the caller in the chain.
///
/// Called when a module sets the CHAIN_NEXT flag on an opcode.
/// Finds the caller's position in the chain and dispatches to the layer below.
/// If the caller is at the bottom (position 0), dispatches to the kernel provider.
///
/// # Safety
/// Same requirements as `dispatch`.
pub unsafe fn dispatch_next(
    caller_module: u8,
    class: u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    let idx = class as usize;
    if idx >= MAX_PROVIDERS {
        return errno::ENOSYS;
    }
    unsafe {
        let entry = &PROVIDERS[idx];

        // Find caller's position in the chain (search top-down)
        let mut caller_pos: Option<usize> = None;
        for i in (0..entry.depth as usize).rev() {
            if let Some(ref layer) = entry.chain[i] {
                if layer.module_idx == caller_module {
                    caller_pos = Some(i);
                    break;
                }
            }
        }

        let pos = match caller_pos {
            Some(p) => p,
            None => {
                // Caller not in chain — fall back to kernel provider
                return match entry.kernel_dispatch {
                    Some(handler) => handler(handle, opcode, arg, arg_len),
                    None => errno::ENOSYS,
                };
            }
        };

        // If caller is at bottom (position 0), dispatch to kernel provider
        if pos == 0 {
            return match entry.kernel_dispatch {
                Some(handler) => handler(handle, opcode, arg, arg_len),
                None => errno::ENOSYS,
            };
        }

        // Dispatch to layer below
        let below = pos - 1;
        if let Some(ref layer) = entry.chain[below] {
            let saved = crate::kernel::scheduler::current_module_index();
            crate::kernel::scheduler::set_current_module(layer.module_idx as usize);
            let result = (layer.dispatch)(layer.state, handle, opcode, arg, arg_len);
            crate::kernel::scheduler::set_current_module(saved);
            return result;
        }

        // Gap in chain — shouldn't happen but fall back to kernel
        match entry.kernel_dispatch {
            Some(handler) => handler(handle, opcode, arg, arg_len),
            None => errno::ENOSYS,
        }
    }
}
