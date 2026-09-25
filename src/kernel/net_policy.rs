//! net.policy (0x1E) — the table store every platform provider shares.
//!
//! A provider is this store plus a platform's answer to "what happens when a
//! table changes": the linux provider renders it to nftables and applies it,
//! the bare-metal provider leaves it for the in-graph packet filter to read,
//! and the wasm provider leaves it recorded and says it enforces nothing. So
//! the argument decoding, the bounds, the validation and the generation count
//! live here once, and a platform supplies only its capabilities and its hook.
//!
//! Bounded and allocation-free: kernel static memory on every target.

use crate::abi::contracts::net::policy as wire;
use crate::kernel::sys::errno;

use crate::abi::config::kernel::MAX_MODULES;

/// Tables held at once, by profile. A controller owns one (`netpolicy`,
/// `proxy`); a deployment needing more has more controllers than this platform
/// was sized for, and REPLACE says so (`ENOSPC`). The store is kernel static
/// memory, so a Cortex-M profile (no packet policy to enforce, 264 KB of RAM)
/// holds none, and wasm (records, enforces nothing) holds two small ones.
pub const MAX_TABLES: usize = if MAX_MODULES > 128 {
    8
} else if MAX_MODULES > 32 {
    2
} else {
    0
};
/// Bytes of rule records per table: on the host ~500 filter rules, or ~40
/// fully loaded services' DNAT with their backends.
pub const MAX_TABLE_BYTES: usize = if MAX_MODULES > 128 { 8192 } else { 2048 };

/// In-graph enforcers attached (`ATTACH`). A provider whose tables act only
/// through one reports ENFORCED while this is non-zero.
static mut ENFORCERS: u32 = 0;

/// Whether an in-graph enforcer has attached.
///
/// # Safety
/// Provider-dispatch context.
pub unsafe fn enforcer_attached() -> bool {
    ENFORCERS > 0
}

#[derive(Clone, Copy)]
struct Table {
    live: bool,
    name: [u8; wire::MAX_TABLE_NAME],
    name_len: u8,
    generation: u64,
    len: usize,
    rules: [u8; MAX_TABLE_BYTES],
}

impl Table {
    const fn empty() -> Self {
        Self {
            live: false,
            name: [0; wire::MAX_TABLE_NAME],
            name_len: 0,
            generation: 0,
            len: 0,
            rules: [0; MAX_TABLE_BYTES],
        }
    }
    fn is(&self, name: &[u8]) -> bool {
        self.live && &self.name[..self.name_len as usize] == name
    }
}

static mut TABLES: [Table; MAX_TABLES] = [const { Table::empty() }; MAX_TABLES];
/// Generations are store-wide and never reused, so a table deleted and
/// recreated can never present an old generation to a reader that cached it.
static mut NEXT_GENERATION: u64 = 1;

/// What a platform does with a table it accepted. `Err(errno)` refuses the
/// REPLACE and the stored table is left as it was.
pub type ApplyHook = fn(name: &[u8], rules: Option<&[u8]>) -> Result<(), i32>;

fn name_at(arg: &[u8]) -> Option<(&[u8], usize)> {
    let n = *arg.first()? as usize;
    if n == 0 || n > wire::MAX_TABLE_NAME || arg.len() < 1 + n {
        return None;
    }
    Some((&arg[1..1 + n], 1 + n))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}
fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Visit every live table's name and rules (the linux provider renders the
/// whole set when it applies one, so a table that failed never half-lands).
///
/// # Safety
/// Provider-dispatch context: the store is owned by the scheduler thread.
pub unsafe fn for_each(mut f: impl FnMut(&[u8], &[u8])) {
    let tables = &raw const TABLES;
    for t in (*tables).iter().filter(|t| t.live) {
        f(&t.name[..t.name_len as usize], &t.rules[..t.len]);
    }
}

/// The contract's dispatch, for a provider whose platform realizes `caps` and
/// runs `hook` on every change.
///
/// # Safety
/// `arg` points to `arg_len` caller-owned bytes for the call; pointers inside
/// it are caller-owned buffers of the lengths they state (the provider
/// contract).
pub unsafe fn dispatch(
    caps: u32,
    hook: Option<ApplyHook>,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if handle >= 0 {
        return errno::EINVAL;
    }
    let a: &[u8] = if arg.is_null() || arg_len == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(arg, arg_len)
    };
    match opcode {
        wire::PROBE => 1,
        wire::ATTACH => {
            ENFORCERS = ENFORCERS.saturating_add(1);
            0
        }
        wire::CAPS => {
            if arg.is_null() || arg_len < 4 {
                return errno::EINVAL;
            }
            core::slice::from_raw_parts_mut(arg, 4).copy_from_slice(&caps.to_le_bytes());
            0
        }
        wire::REPLACE => {
            let Some((name, p)) = name_at(a) else {
                return errno::EINVAL;
            };
            let (Some(rptr), Some(rlen), Some(gptr)) =
                (u64_at(a, p), u32_at(a, p + 8), u64_at(a, p + 12))
            else {
                return errno::EINVAL;
            };
            let rlen = rlen as usize;
            if rlen > MAX_TABLE_BYTES {
                return errno::ENOSPC;
            }
            let rules: &[u8] = if rlen == 0 || rptr == 0 {
                &[]
            } else {
                core::slice::from_raw_parts(rptr as *const u8, rlen)
            };
            if let Err(e) = wire::validate(rules, caps) {
                return e;
            }
            let tables = &raw mut TABLES;
            let idx = match (*tables).iter().position(|t| t.is(name)) {
                Some(i) => i,
                None => match (*tables).iter().position(|t| !t.live) {
                    Some(i) => i,
                    None => return errno::ENOSPC,
                },
            };
            // Apply BEFORE storing: a platform that refuses the table leaves
            // the old one in force and in the store, so what READ reports is
            // what is enforced.
            if let Some(h) = hook {
                if let Err(e) = h(name, Some(rules)) {
                    return e;
                }
            }
            let t = &mut (*tables)[idx];
            t.live = true;
            t.name[..name.len()].copy_from_slice(name);
            t.name_len = name.len() as u8;
            t.rules[..rlen].copy_from_slice(rules);
            t.len = rlen;
            let g = NEXT_GENERATION;
            NEXT_GENERATION += 1;
            t.generation = g;
            if gptr != 0 {
                core::ptr::copy_nonoverlapping(g.to_le_bytes().as_ptr(), gptr as *mut u8, 8);
            }
            0
        }
        wire::CLEAR => {
            let Some((name, _)) = name_at(a) else {
                return errno::EINVAL;
            };
            let tables = &raw mut TABLES;
            if let Some(i) = (*tables).iter().position(|t| t.is(name)) {
                if let Some(h) = hook {
                    if let Err(e) = h(name, None) {
                        return e;
                    }
                }
                (*tables)[i].live = false;
            }
            0
        }
        wire::READ => {
            let Some((name, p)) = name_at(a) else {
                return errno::EINVAL;
            };
            let (Some(optr), Some(ocap), Some(gptr)) =
                (u64_at(a, p), u32_at(a, p + 8), u64_at(a, p + 12))
            else {
                return errno::EINVAL;
            };
            let tables = &raw const TABLES;
            let Some(t) = (*tables).iter().find(|t| t.is(name)) else {
                return errno::ENOENT;
            };
            if gptr != 0 {
                core::ptr::copy_nonoverlapping(
                    t.generation.to_le_bytes().as_ptr(),
                    gptr as *mut u8,
                    8,
                );
            }
            if t.len > ocap as usize {
                return errno::ERANGE;
            }
            if t.len > 0 && optr != 0 {
                core::ptr::copy_nonoverlapping(t.rules.as_ptr(), optr as *mut u8, t.len);
            }
            t.len as i32
        }
        _ => errno::ENOSYS,
    }
}
