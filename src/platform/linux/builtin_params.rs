// TLV walker for built-in module params.
//
// Built-in modules receive a per-instance TLV blob via `ModuleEntry::params()`.
// Format mirrors `crates/fluxor-rt/src/params.rs::parse_tlv` and the config-tool
// packer in `tools/src/schema.rs`:
//
//   [0xFE][0x01][len_lo][len_hi]
//   [tag][len][value...] [tag][len][value...] ... [0xFF (optional end)]
//
// Each built-in walks the blob with `walk_tlv` and dispatches by tag.
// Tags are declared per parameter in the module's `manifest.toml` and are
// permanent, so the wire meaning of a field survives any reordering of the
// `[[params]]` table. Tags 0xF0..0xFF are reserved for protection / fault
// policy and are silently ignored here.

use crate::kernel::exec::scheduler::{NativeInit, NativeVtable};
use crate::kernel::module::loader::ModuleStepFn;

/// Iterate the TLV payload of a module entry, calling `f(tag, value)`
/// for each entry. No-op on a blob that lacks the magic+version
/// header (treated as "no params for this module").
pub fn walk_tlv<F: FnMut(u8, &[u8])>(blob: &[u8], f: F) {
    fluxor_contracts::params_tlv::walk_declared(blob, f);
}

/// Read a u32 TLV value (zero-extends shorter lengths so an upstream
/// u8/u16 default still decodes safely).
pub fn tlv_u32(value: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    let n = value.len().min(4);
    buf[..n].copy_from_slice(&value[..n]);
    u32::from_le_bytes(buf)
}

/// Read a u8 TLV value (zero if empty).
pub fn tlv_u8(value: &[u8]) -> u8 {
    value.first().copied().unwrap_or(0)
}

/// Decode a TLV string value as UTF-8; falls back to an empty `&str` on
/// invalid bytes so the caller can apply its own default.
pub fn tlv_str(value: &[u8]) -> &str {
    core::str::from_utf8(value).unwrap_or("")
}

/// A host native module: its instance is a host value, built from its slot
/// (ports wired, owner stamped) and its params, and dropped when the slot is
/// vacated or the graph rebuilt.
pub trait HostNative: Sized + 'static {
    /// Build the instance, or the negative errno that refuses it.
    fn build(slot: usize, params: &[u8]) -> Result<Box<Self>, i32>;
}

/// The vtable of host native `T` whose step is `step`: its arena state is
/// the instance's heap pointer, its drop the instance's.
pub const fn host_vtable<T: HostNative>(step: ModuleStepFn) -> NativeVtable {
    NativeVtable {
        new: host_new::<T>,
        step,
        refill: None,
        flush: None,
        isr_entry: None,
        drop: Some(host_drop::<T>),
        state_size: core::mem::size_of::<*mut T>() as u32,
    }
}

/// # Safety
/// `state` is the instance's arena state, `size_of::<*mut T>()` bytes.
unsafe fn host_new<T: HostNative>(state: *mut u8, init: &NativeInit<'_>) -> i32 {
    match T::build(init.slot, init.params) {
        Ok(b) => {
            // SAFETY: the arena state holds one pointer; 8-byte aligned.
            unsafe { core::ptr::write(state.cast::<*mut T>(), Box::into_raw(b)) };
            0
        }
        Err(rc) => rc,
    }
}

/// # Safety
/// `state` holds the pointer [`host_new`] wrote; this is its one release.
unsafe fn host_drop<T: HostNative>(state: *mut u8) {
    // SAFETY: the pointer `Box::into_raw` produced in `host_new`.
    drop(unsafe { Box::from_raw(core::ptr::read(state.cast::<*mut T>())) });
}

/// The instance a host native's step is handed.
///
/// # Safety
/// `state` is the arena state of a [`host_vtable::<T>`] instance, borrowed
/// exclusively for the step.
pub unsafe fn instance_state<'a, T>(state: *mut u8) -> &'a mut T {
    // SAFETY: the caller's contract: `state` holds the instance's pointer.
    unsafe { &mut *core::ptr::read(state.cast::<*mut T>()) }
}
