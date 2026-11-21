//! Native modules: modules a platform links in rather than loads, found by
//! the name hash a composed graph names them by.
//!
//! A platform registers each of its native modules once, from one table, at
//! platform init and before its first graph is prepared ([`register`]).
//! Instantiation resolves a module's name hash in the loader first and here
//! second (`splice::instantiate_batch`). A native instance is a
//! [`NativeModule`]: its vtable and a state buffer drawn from the state arena
//! like a PIC module's, charged to its owner the same way, and released
//! through the vtable's `drop` when the slot is vacated or the graph reset.
//!
//! A platform that cannot run PIC code in place (wasm, whose module code is a
//! separate wasm instance) registers one vtable that instantiates every
//! loader-resolved module ([`set_loaded_module_host`]).

use crate::kernel::module::loader::{
    ModuleIsrEntryFn, ModulePipelineRefillFn, ModulePostTickFlushFn, ModuleStepFn,
};

/// What a native module's constructor is handed.
pub struct NativeInit<'a> {
    /// The module's slot: its ports are wired and its owner stamped.
    pub slot: usize,
    /// Its params, as the composed graph carries them.
    pub params: &'a [u8],
    /// The module's code, when the loader resolved it and a
    /// [loaded-module host](set_loaded_module_host) instantiates it: its
    /// payload (`code_base`, `code_size`). `None` for a registered module.
    pub code: Option<(*const u8, usize)>,
}

/// A native module's construction: `0` once the instance is built in
/// `state`, or the negative errno that refuses it (nothing to drop then).
///
/// # Safety
/// `state` is `NativeVtable::state_size` zeroed bytes of the state arena,
/// 8-byte aligned, exclusively the constructor's.
pub type NativeNewFn = unsafe fn(state: *mut u8, init: &NativeInit<'_>) -> i32;

/// A native module's teardown: release what its constructor built in
/// `state`. Called once, on the scheduler thread, after the module's last
/// step.
///
/// # Safety
/// `state` is the buffer a successful [`NativeNewFn`] built.
pub type NativeDropFn = unsafe fn(state: *mut u8);

/// A native module: how it is built, stepped and torn down.
pub struct NativeVtable {
    /// Builds an instance in its state buffer.
    pub new: NativeNewFn,
    /// Its step, with `module_step`'s signature.
    pub step: ModuleStepFn,
    /// Its bounded input refill, if it has one.
    pub refill: Option<ModulePipelineRefillFn>,
    /// Its post-pass flush, if it has one.
    pub flush: Option<ModulePostTickFlushFn>,
    /// Its interrupt entry, if it can run in an `irq` domain.
    pub isr_entry: Option<ModuleIsrEntryFn>,
    /// Releases what `new` built. `None` when the state holds nothing to
    /// release.
    pub drop: Option<NativeDropFn>,
    /// Bytes of state an instance draws from the state arena.
    pub state_size: u32,
}

/// Native modules one node registers.
const NATIVE_MODULES: usize = 32;

static mut TABLE: [(u32, Option<&'static NativeVtable>); NATIVE_MODULES] =
    [(0, None); NATIVE_MODULES];

static mut LOADED_MODULE_HOST: Option<&'static NativeVtable> = None;

/// Register `vt` under `name_hash`, replacing what was registered there.
/// `false` when the table is full.
pub fn register(name_hash: u32, vt: &'static NativeVtable) -> bool {
    // SAFETY: written at platform init (and by a test between graphs), on the
    // scheduler thread; nothing holds a reference into the table.
    let table = unsafe { &mut *core::ptr::addr_of_mut!(TABLE) };
    let slot = table
        .iter()
        .position(|&(h, v)| v.is_some() && h == name_hash)
        .or_else(|| table.iter().position(|&(_, v)| v.is_none()));
    match slot {
        Some(i) => {
            table[i] = (name_hash, Some(vt));
            true
        }
        None => {
            log::error!("[native] table full; {name_hash:#010x} not registered");
            false
        }
    }
}

/// Register every `(name_hash, vtable)` of a platform's table.
pub fn register_all(table: &[(u32, &'static NativeVtable)]) {
    for &(h, vt) in table {
        register(h, vt);
    }
}

/// The native module registered under `name_hash`.
pub fn lookup(name_hash: u32) -> Option<&'static NativeVtable> {
    // SAFETY: as `register`; a read.
    let table = unsafe { &*core::ptr::addr_of!(TABLE) };
    table
        .iter()
        .find(|&&(h, v)| v.is_some() && h == name_hash)
        .and_then(|&(_, v)| v)
}

/// Instantiate every loader-resolved module through `vt` instead of running
/// its code in place: the platform's module host.
pub fn set_loaded_module_host(vt: &'static NativeVtable) {
    // SAFETY: as `register`.
    unsafe { *core::ptr::addr_of_mut!(LOADED_MODULE_HOST) = Some(vt) };
}

/// The platform's module host, if it has one.
pub fn loaded_module_host() -> Option<&'static NativeVtable> {
    // SAFETY: as `lookup`.
    unsafe { *core::ptr::addr_of!(LOADED_MODULE_HOST) }
}

/// A native module's instance in a slot: its vtable and its state.
pub struct NativeModule {
    vt: &'static NativeVtable,
    state: *mut u8,
}

impl NativeModule {
    /// Build an instance of `vt`: its state drawn from the state arena and
    /// handed to its constructor. The negative errno when the arena cannot
    /// seat it or the constructor refuses (the state is then freed).
    pub fn new(vt: &'static NativeVtable, init: &NativeInit<'_>) -> Result<Self, i32> {
        use crate::kernel::module::loader;
        let size = vt.state_size as usize;
        let state = loader::alloc_state(size).map_err(|_| crate::kernel::sys::errno::ENOMEM)?;
        // SAFETY: `alloc_state` returned `size` zeroed bytes for this
        // instance alone.
        let rc = unsafe { (vt.new)(state, init) };
        if rc < 0 {
            // SAFETY: the range just allocated; the constructor refused and
            // keeps nothing in it.
            unsafe { loader::free_state_range(state, size) };
            return Err(rc);
        }
        Ok(Self { vt, state })
    }

    /// The vtable the instance was built from.
    pub fn vtable(&self) -> &'static NativeVtable {
        self.vt
    }

    /// The instance's state buffer.
    pub fn state_ptr(&self) -> *mut u8 {
        self.state
    }

    /// Bytes of state the instance holds.
    pub fn state_size(&self) -> u32 {
        self.vt.state_size
    }

    /// Release what the constructor built, once.
    fn release(&mut self) {
        if self.state.is_null() {
            return;
        }
        if let Some(drop) = self.vt.drop {
            // SAFETY: `state` is the buffer `new` built; this is its one
            // release, after its last step.
            unsafe { drop(self.state) };
        }
    }

    /// Release the instance and hand back its state range, for the caller to
    /// return to the arena.
    pub fn into_state_range(mut self) -> (*mut u8, usize) {
        self.release();
        let range = (self.state, self.vt.state_size as usize);
        self.state = core::ptr::null_mut();
        range
    }
}

impl Drop for NativeModule {
    fn drop(&mut self) {
        self.release();
    }
}

impl crate::kernel::exec::step::Module for NativeModule {
    fn step(&mut self) -> Result<crate::kernel::exec::step::StepOutcome, i32> {
        // SAFETY: the step is handed the instance's own state.
        crate::kernel::exec::step::StepOutcome::from_wire(unsafe { (self.vt.step)(self.state) })
    }

    fn pipeline_refill(&mut self) -> Result<bool, i32> {
        let Some(refill) = self.vt.refill else {
            return Ok(false);
        };
        // SAFETY: as `step`.
        let rc = unsafe { refill(self.state) };
        if rc < 0 {
            Err(rc)
        } else {
            Ok(rc > 0)
        }
    }

    fn post_tick_flush(&mut self) -> Result<(), i32> {
        let Some(flush) = self.vt.flush else {
            return Ok(());
        };
        // SAFETY: as `step`.
        let rc = unsafe { flush(self.state) };
        if rc < 0 {
            Err(rc)
        } else {
            Ok(())
        }
    }

    fn name(&self) -> &'static str {
        "native"
    }

    fn stack_bytes(&self) -> usize {
        0
    }
}
