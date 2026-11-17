//! Kernel handles: resolving a native handle and polling any handle.
//!
//! A handle is `0 | contract | generation | index` (`abi::kernel_abi::handle`).
//! A native object — a channel, event, timer or lend — is named by its slot in
//! the kernel's own table; every other handle by a route
//! (`module::provider`). Readiness is the handle's contract's own question
//! (`ProviderVTable::poll`), so nothing here names a contract.

use crate::kernel::exec::scheduler::{ModuleId, NO_MODULE};
use crate::kernel::sys::errno;

/// What resolving a native handle reads of its slot.
pub trait Native {
    /// The slot holds an object.
    fn live(&self) -> bool;
    /// The generation a handle to the slot's object carries.
    fn generation(&self) -> u16;
    /// The module that owns the object (`NO_MODULE`: the kernel).
    fn owner(&self) -> ModuleId;
}

/// The slot of `table` (`contract`'s native table) that `h` names, with its
/// index: `EBADF` unless `h` is a handle of `contract` naming a live slot at
/// its generation that `caller` owns. The kernel (`caller == NO_MODULE`)
/// owns every object.
pub fn resolve_owned<T: Native>(
    table: &[T],
    contract: u16,
    h: i32,
    caller: ModuleId,
) -> Result<(usize, &T), i32> {
    let Some((c, generation, idx)) = crate::abi::kernel_abi::handle::decode(h) else {
        return Err(errno::EBADF);
    };
    let idx = idx as usize;
    match table.get(idx) {
        Some(slot)
            if c == contract
                && slot.live()
                && slot.generation() == generation
                && (caller == NO_MODULE || slot.owner() == caller) =>
        {
            Ok((idx, slot))
        }
        _ => Err(errno::EBADF),
    }
}

/// Non-destructive readiness of any handle: the bitmask of `events` that
/// hold, or a negative errno. `HANDLE_POLL`.
pub fn fd_poll(h: i32, events: u8) -> i32 {
    crate::kernel::module::provider::poll(h, u32::from(events))
}

/// Poll several handles in one call: the count with any event ready, and
/// each one's ready bits in `ready` (0 for none or an error).
pub fn fd_poll_multi(fds: &[i32], events: &[u8], ready: &mut [u8]) -> i32 {
    let mut count = 0i32;
    for ((&fd, &ev), r) in fds.iter().zip(events).zip(ready.iter_mut()) {
        let result = fd_poll(fd, ev);
        if result > 0 {
            *r = result as u8;
            count += 1;
        } else {
            *r = 0;
        }
    }
    count
}
