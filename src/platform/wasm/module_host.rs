//! The wasm platform's module host. Module code cannot run in place in the
//! kernel's linear memory, so every module the loader resolves is a wasm
//! payload instantiated as its own wasm instance through the host
//! (`host_instantiate_module`), initialised through its `module_init_wasm`
//! export and stepped through its `module_step_wasm` export. The kernel has
//! validated the `.fmod` envelope and set the slot's grants, code region and
//! type hash before this host's constructor runs.

use super::{host_destroy_module, host_instantiate_module, host_invoke_module};
use crate::abi::wire::fmod::header::{self as fmod_header, flag};
use crate::kernel::exec::scheduler::{self, NativeInit, NativeVtable};
use crate::kernel::module::loader::{self, LoadedModule, ModuleHeader};
use crate::kernel::sys::errno;

/// Kernel-side scratch heap each hosted module gets (the profile's
/// `MODULE_HOST_SCRATCH_BYTES`).
const KERNEL_SCRATCH_BYTES: usize = crate::kernel::config::MODULE_HOST_SCRATCH_BYTES;

/// Arena state of a hosted module: its host instance and its scratch heap's
/// arena. The module keeps its own state in its own linear memory.
#[repr(C)]
struct Hosted {
    handle: i32,
    scratch: *mut u8,
}

const _: () = assert!(
    crate::kernel::config::MODULE_HOST_STATE_BYTES >= core::mem::size_of::<Hosted>(),
    "the module host's declared state holds a Hosted"
);

/// The host every loader-resolved module instantiates through. Its state is
/// the profile's `MODULE_HOST_STATE_BYTES`, the figure the build charges each
/// hosted module.
pub static WASM_MODULE_HOST: NativeVtable = NativeVtable {
    new,
    step,
    refill: None,
    flush: None,
    isr_entry: None,
    drop: Some(release),
    state_size: crate::kernel::config::MODULE_HOST_STATE_BYTES as u32,
};

/// The module whose code payload starts at `code`.
///
/// # Safety
/// `code` is the payload of a module the kernel resolved (`code_base()` of
/// its `LoadedModule`): its `.fmod` header lies immediately before it.
unsafe fn module_at(code: *const u8) -> Option<LoadedModule> {
    // SAFETY: the caller's contract: the header's bytes precede the payload.
    let base = unsafe { code.sub(fmod_header::SIZE) };
    // SAFETY: as above; `SIZE` readable bytes at `base`.
    let header =
        ModuleHeader::read(unsafe { core::slice::from_raw_parts(base, fmod_header::SIZE) })?;
    Some(LoadedModule { base, header })
}

/// # Safety
/// `state` is the instance's zeroed arena state; the current module is
/// `init.slot`.
unsafe fn new(state: *mut u8, init: &NativeInit<'_>) -> i32 {
    let slot = init.slot;
    let Some((code, code_size)) = init.code else {
        return errno::EINVAL;
    };
    // SAFETY: `init.code` is the payload of the module the kernel resolved.
    let Some(module) = (unsafe { module_at(code) }) else {
        return errno::EINVAL;
    };
    if module.header.flags & flag::WASM_PAYLOAD == 0 {
        log::error!("[wasm-kernel] module {slot}: .fmod is not a wasm payload");
        return errno::ENOEXEC;
    }

    let Ok(scratch) = loader::alloc_state(KERNEL_SCRATCH_BYTES) else {
        log::error!("[wasm-kernel] module {slot}: no state arena for its scratch heap");
        return errno::ENOMEM;
    };
    crate::kernel::mem::heap::init_module_heap(slot, scratch, KERNEL_SCRATCH_BYTES);
    // Everything after this point that refuses the module returns its
    // scratch heap.
    let refuse = |handle: i32, rc: i32| -> i32 {
        if handle >= 0 {
            // SAFETY: a wasm import; the instance just created is dropped.
            unsafe { host_destroy_module(handle) };
        }
        crate::kernel::mem::heap::reset_module_heap(slot);
        // SAFETY: the range allocated above; nothing kept a pointer into it.
        unsafe { loader::free_state_range(scratch, KERNEL_SCRATCH_BYTES) };
        rc
    };

    // SAFETY: a wasm import reading `code_size` bytes of the module's
    // payload, which the loader keeps mapped.
    let handle = unsafe { host_instantiate_module(code, code_size, core::ptr::null(), 0) };
    if handle < 0 {
        log::error!("[wasm-kernel] module {slot}: host_instantiate_module failed ({handle})");
        return refuse(-1, handle);
    }

    // Channel handles for the first port of each direction (in, out,
    // ctrl_input): `module_init_wasm` takes them as scalars. A module with
    // more ports looks the rest up through `dev_channel_port`.
    let in_chan = scheduler::get_module_port(slot, 0, 0);
    let out_chan = scheduler::get_module_port(slot, 1, 0);
    let ctrl_chan = scheduler::get_module_port(slot, 2, 0);
    log::info!(
        "[wasm-kernel] ports idx={slot} in0={in_chan} in1={} out0={out_chan} out1={} ctrl0={ctrl_chan}",
        scheduler::get_module_port(slot, 0, 1),
        scheduler::get_module_port(slot, 1, 1),
    );

    // wasm32 imports are scalar-only, so the per-instance params blob
    // cannot ride along on `module_init_wasm`: the module pulls it through
    // `MODULE_INSTANCE_PARAMS` instead.
    // SAFETY: the params borrow from the 'static embedded config blob,
    // which outlives the module's scheduler entry.
    unsafe { scheduler::set_module_params(slot, init.params.as_ptr(), init.params.len()) };

    // `module_init_wasm` is the wasm-only entry point each module exports
    // from `crates/fluxor-rt/src/wasm_entry.rs`: it owns state allocation
    // (on the module's own heap) and calls the module's `module_new`. Args
    // are four i32 LE values: in_chan, out_chan, ctrl_chan, arena_size (the
    // heap arena the module's manifest declares, 0 for none).
    let arena_size = module.manifest_arena_bytes() as u32;
    let mut args = [0u8; 16];
    args[0..4].copy_from_slice(&in_chan.to_le_bytes());
    args[4..8].copy_from_slice(&out_chan.to_le_bytes());
    args[8..12].copy_from_slice(&ctrl_chan.to_le_bytes());
    args[12..16].copy_from_slice(&arena_size.to_le_bytes());
    let export = b"module_init_wasm";
    let mut ret = [0u8; 4];
    // SAFETY: a wasm import; the export name, packed args and return
    // buffer are locals.
    let n = unsafe {
        host_invoke_module(
            handle,
            export.as_ptr(),
            export.len(),
            args.as_ptr(),
            args.len(),
            ret.as_mut_ptr(),
            ret.len(),
        )
    };
    if n < 0 {
        log::error!("[wasm-kernel] module {slot}: module_init_wasm failed ({n})");
        return refuse(handle, n);
    }
    let rc = if n >= 4 { i32::from_le_bytes(ret) } else { 0 };
    if rc != 0 {
        log::error!("[wasm-kernel] module {slot}: module_init_wasm returned {rc}");
        return refuse(handle, if rc < 0 { rc } else { errno::EINVAL });
    }

    // SAFETY: the caller's contract: `state` holds a `Hosted`, 8-byte
    // aligned.
    unsafe { core::ptr::write(state.cast::<Hosted>(), Hosted { handle, scratch }) };
    0
}

/// Invoke the module's `module_step_wasm` export: a no-argument wasm32
/// entry point that steps the module on the state it keeps in its own
/// linear memory.
///
/// # Safety
/// `state` is this module's own arena state, exclusively the step's for its
/// duration.
unsafe extern "C" fn step(state: *mut u8) -> i32 {
    // SAFETY: the state `new` filled.
    let handle = unsafe { (*state.cast::<Hosted>()).handle };
    let export = b"module_step_wasm";
    let mut ret = [0u8; 4];
    // SAFETY: a wasm import; the export name and return buffer are locals.
    let n = unsafe {
        host_invoke_module(
            handle,
            export.as_ptr(),
            export.len(),
            core::ptr::null(),
            0,
            ret.as_mut_ptr(),
            ret.len(),
        )
    };
    if n < 0 {
        return n;
    }
    if n >= 4 {
        i32::from_le_bytes(ret)
    } else {
        0
    }
}

/// # Safety
/// `state` is the arena state `new` filled; this is its one release, after
/// the module's last step.
unsafe fn release(state: *mut u8) {
    // SAFETY: the caller's contract.
    let hosted = unsafe { core::ptr::read(state.cast::<Hosted>()) };
    // SAFETY: a wasm import; the instance is never invoked again.
    unsafe { host_destroy_module(hosted.handle) };
    // SAFETY: the scratch arena `new` allocated; nothing steps on it again.
    unsafe { loader::free_state_range(hosted.scratch, KERNEL_SCRATCH_BYTES) };
}
