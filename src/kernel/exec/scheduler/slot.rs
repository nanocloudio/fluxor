//! The slot enum the scheduler stores instances in.
//!
//! - `Empty`                   — slot not in use.
//! - `Dynamic(DynamicModule)`  — a PIC `.fmod` loaded by `kernel::module::loader`.
//! - `Native(NativeModule)`    — a module the platform links in, built from
//!   its registered vtable (`scheduler::native`).

use super::native::NativeModule;
use crate::kernel::exec::step::Module;
use crate::kernel::module::loader::DynamicModule;

/// Module slot - holds an instantiated module
pub enum ModuleSlot {
    Empty,
    /// Dynamically loaded PIC module
    Dynamic(DynamicModule),
    /// A native module: a registered vtable and its arena state.
    Native(NativeModule),
}

impl ModuleSlot {
    /// Returns true if this slot contains a dynamically loaded PIC module
    pub fn is_dynamic(&self) -> bool {
        matches!(self, ModuleSlot::Dynamic(_))
    }

    /// Returns the module type as a string for logging
    pub fn type_name(&self) -> &'static str {
        match self {
            ModuleSlot::Empty => "empty",
            ModuleSlot::Dynamic(m) => m.name(),
            ModuleSlot::Native(m) => m.name(),
        }
    }

    /// The instance's state buffer and its size: what it was handed at
    /// construction and is stepped with.
    pub fn state(&self) -> Option<(*mut u8, u32)> {
        match self {
            ModuleSlot::Empty => None,
            ModuleSlot::Dynamic(m) => Some((m.state_ptr(), m.state_size())),
            ModuleSlot::Native(m) => Some((m.state_ptr(), m.state_size())),
        }
    }

    pub(super) fn as_module_mut(&mut self) -> Option<&mut dyn Module> {
        match self {
            ModuleSlot::Empty => None,
            ModuleSlot::Dynamic(m) => Some(m),
            ModuleSlot::Native(m) => Some(m),
        }
    }

    /// Vacate the slot: the instance is released and its state range handed
    /// back for the caller to return to the arena (`(null, 0)` when the slot
    /// held nothing).
    pub(super) fn take_state_range(&mut self) -> (*mut u8, usize) {
        match core::mem::replace(self, ModuleSlot::Empty) {
            ModuleSlot::Dynamic(m) => m.into_state_range(),
            ModuleSlot::Native(m) => m.into_state_range(),
            ModuleSlot::Empty => (core::ptr::null_mut(), 0),
        }
    }
}
