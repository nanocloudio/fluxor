//! A module's assets: the bytes a graph names by `${asset:<name>}` in one of
//! the module's params (a param its manifest marks `asset = true`).
//!
//! What the param holds depends on the target the graph is built for:
//!
//! | Value | Target | Read as |
//! |---|---|---|
//! | `program:<slot>` | a node image that carries programs | the instance's program in that slot: in place where the kernel answers an address, else through `PROGRAM_READ` |
//! | `asset://<name>` | a wasm bundle | the `fs` contract |
//! | a path | linux | the `fs` contract |
//!
//! [`open`] tells them apart. A module that wants zero copy where the
//! target offers it and correctness everywhere writes one branch for
//! [`Asset::InPlace`] and one for streamed reads.

use crate::*;
use abi::kernel_abi::{errno, program as pg, PROGRAM_INFO, PROGRAM_READ};

/// The prefix of a param value that names a program slot.
pub const PROGRAM_PREFIX: &[u8] = b"program:";

/// An asset, as the target hands it to the module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asset<'p> {
    /// A program the kernel maps: its bytes, read directly. They outlive
    /// every module of the node image that carries them.
    InPlace(&'static [u8]),
    /// A program with no address the module can read: its slot, read
    /// through [`read`].
    Program(u8),
    /// A path or `asset://<name>`: the param's own bytes, opened through
    /// the `fs` contract.
    Fs(&'p [u8]),
}

/// The slot a `program:<slot>` value names: decimal, 0 to 255, nothing
/// after it. `None` for any other value; `Some(Err(()))` for the prefix
/// with a slot that is not one.
fn program_slot(param: &[u8]) -> Option<Result<u8, ()>> {
    if param.len() < PROGRAM_PREFIX.len() {
        return None;
    }
    let mut i = 0;
    while i < PROGRAM_PREFIX.len() {
        if param[i] != PROGRAM_PREFIX[i] {
            return None;
        }
        i += 1;
    }
    if i == param.len() {
        return Some(Err(()));
    }
    let mut slot: u32 = 0;
    while i < param.len() {
        let digit = param[i].wrapping_sub(b'0');
        if digit > 9 {
            return Some(Err(()));
        }
        slot = slot * 10 + digit as u32;
        if slot > 255 {
            return Some(Err(()));
        }
        i += 1;
    }
    Some(Ok(slot as u8))
}

/// The program slot `param` names, when it is `program:<slot>`: what
/// [`read`] and [`size`] take for an asset [`open`] answered in place.
pub fn slot(param: &[u8]) -> Option<u8> {
    match program_slot(param) {
        Some(Ok(slot)) => Some(slot),
        _ => None,
    }
}

fn u32_at(info: &[u8; pg::INFO_LEN], at: usize) -> u32 {
    u32::from_le_bytes([info[at], info[at + 1], info[at + 2], info[at + 3]])
}

/// What `PROGRAM_INFO` answers for `slot`, or its errno.
unsafe fn program_info(sys: &SyscallTable, slot: u8) -> Result<[u8; pg::INFO_LEN], i32> {
    let mut info = [0u8; pg::INFO_LEN];
    info[0] = slot;
    let rc = (sys.provider_call)(
        -1,
        PROGRAM_INFO,
        info.as_mut_ptr(),
        info.len(),
        core::ptr::null_mut(),
        0,
    );
    if rc < 0 {
        return Err(rc);
    }
    Ok(info)
}

/// The asset the param value `param` names.
///
/// `program:<slot>` asks the kernel for that program of the calling
/// instance: `InPlace` over its bytes where the kernel answers an address,
/// `Program(slot)` where it answers none. The kernel's errno comes back
/// unchanged: `ENOENT` when the instance has no program in the slot, on
/// which a module refuses to construct. Any other value is `Fs`, the bytes
/// to open through the `fs` contract. An empty value, or `program:` with
/// anything but a slot after it, is `EINVAL`.
///
/// # Safety
/// `sys` is the kernel's syscall table, as the module was given it.
pub unsafe fn open<'p>(sys: &SyscallTable, param: &'p [u8]) -> Result<Asset<'p>, i32> {
    if param.is_empty() {
        return Err(errno::EINVAL);
    }
    let slot = match program_slot(param) {
        None => return Ok(Asset::Fs(param)),
        Some(Err(())) => return Err(errno::EINVAL),
        Some(Ok(slot)) => slot,
    };
    let info = program_info(sys, slot)?;
    let at = pg::info::ADDR;
    let addr = u64::from_le_bytes([
        info[at],
        info[at + 1],
        info[at + 2],
        info[at + 3],
        info[at + 4],
        info[at + 5],
        info[at + 6],
        info[at + 7],
    ]);
    if addr == 0 {
        return Ok(Asset::Program(slot));
    }
    let len = u32_at(&info, pg::info::LEN) as usize;
    // SAFETY: the kernel answers `[addr, addr + len)` as the program's
    // bytes in the node image, readable by this module and unchanged for
    // as long as the image runs.
    Ok(Asset::InPlace(core::slice::from_raw_parts(
        addr as usize as *const u8,
        len,
    )))
}

/// The size in bytes of the program in `slot`, readable in place or not.
///
/// # Safety
/// `sys` is the kernel's syscall table, as the module was given it.
pub unsafe fn size(sys: &SyscallTable, slot: u8) -> Result<u32, i32> {
    Ok(u32_at(&program_info(sys, slot)?, pg::info::SIZE))
}

/// Copy bytes of the program in `slot`, from `offset`, into `out`: how an
/// [`Asset::Program`] is read. Answers the bytes copied, 0 at the end, or
/// the kernel's errno.
///
/// # Safety
/// `sys` is the kernel's syscall table, as the module was given it.
pub unsafe fn read(sys: &SyscallTable, slot: u8, offset: u32, out: &mut [u8]) -> i32 {
    let mut req = [0u8; 8];
    req[0] = slot;
    let at = offset.to_le_bytes();
    req[4] = at[0];
    req[5] = at[1];
    req[6] = at[2];
    req[7] = at[3];
    (sys.provider_call)(
        -1,
        PROGRAM_READ,
        req.as_mut_ptr(),
        req.len(),
        out.as_mut_ptr(),
        out.len(),
    )
}
