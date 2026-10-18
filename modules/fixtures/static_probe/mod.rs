//! static_probe — reads read-only tables of every shape a module declares.
//!
//! Each table is filled by a `const fn` with bytes that are not uniform, so
//! the compiler cannot answer a read from the value alone. The step sums every
//! table through `black_box`ed loads (the bytes come from memory at run time)
//! and compares the sum with the same sum taken at compile time.

#![no_std]
#![allow(
    dead_code,
    reason = "the PIC build mounts the whole of modules/sdk/* via include!, so every \
              module's compile sees the entire ABI surface while using a subset. This \
              allow is the SDK's textual mounting showing through"
)]
#![allow(
    unused_imports,
    reason = "same cause: the mounted SDK brings names this module does not reach for"
)]

use core::ffi::c_void;
use core::hint::black_box;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

const fn bytes<const N: usize>(seed: u32) -> [u8; N] {
    let mut out = [0u8; N];
    let mut x = seed;
    let mut i = 0;
    while i < N {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        out[i] = (x >> 16) as u8;
        i += 1;
    }
    out
}

const fn words<const N: usize>(seed: u32) -> [u32; N] {
    let mut out = [0u32; N];
    let mut x = seed;
    let mut i = 0;
    while i < N {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out[i] = x;
        i += 1;
    }
    out
}

const fn sum_bytes(t: &[u8]) -> u32 {
    let mut s = 0u32;
    let mut i = 0;
    while i < t.len() {
        s = s.wrapping_mul(31).wrapping_add(t[i] as u32);
        i += 1;
    }
    s
}

const fn sum_words(t: &[u32]) -> u32 {
    let mut s = 0u32;
    let mut i = 0;
    while i < t.len() {
        s = s.wrapping_mul(31).wrapping_add(t[i]);
        i += 1;
    }
    s
}

/// The shape that crashed: a large `pub static` byte table at the crate root.
pub static BIG_STATIC: [u8; 24155] = bytes(1);
/// A small one.
pub static SMALL_STATIC: [u8; 24] = bytes(2);
/// One of words.
pub static WORD_STATIC: [u32; 300] = words(3);
/// One the crate does not export.
static PRIVATE_STATIC: [u8; 5000] = bytes(4);
/// A `const` array: each use is its own anonymous constant.
pub const CONST_ARRAY: [u8; 5000] = bytes(5);
/// A `const` slice: one anonymous constant behind a reference.
pub const CONST_SLICE: &[u8] = &bytes::<5000>(6);

mod nested {
    /// Exported from a private module: not reachable from outside the crate.
    pub static NESTED_STATIC: [u8; 5000] = super::bytes(7);
}

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    done: u8,
}

unsafe fn say(s: &State, m: &[u8]) {
    dev_log(&*s.syscalls, 3, m.as_ptr(), m.len());
}

unsafe fn line(s: &State, head: &[u8], name: &[u8], sum: Option<u32>) {
    let mut buf = [0u8; 96];
    let mut n = 0;
    push(&mut buf, &mut n, b"[static_probe] ");
    push(&mut buf, &mut n, head);
    push(&mut buf, &mut n, b" ");
    push(&mut buf, &mut n, name);
    if let Some(v) = sum {
        if n < buf.len() {
            buf[n] = b' ';
            n += 1;
        }
        if n + 10 <= buf.len() {
            n += fmt_u32_raw(buf.as_mut_ptr().add(n), v);
        }
    }
    say(s, &buf[..n]);
}

fn push(buf: &mut [u8; 96], n: &mut usize, part: &[u8]) {
    for &b in part {
        if let Some(slot) = buf.get_mut(*n) {
            *slot = b;
            *n += 1;
        }
    }
}

/// Sum `t` through loads the optimiser cannot see through.
fn read_bytes(t: &[u8]) -> u32 {
    let t = black_box(t);
    let mut s = 0u32;
    for &b in t {
        s = s.wrapping_mul(31).wrapping_add(black_box(b) as u32);
    }
    s
}

fn read_words(t: &[u32]) -> u32 {
    let t = black_box(t);
    let mut s = 0u32;
    for &w in t {
        s = s.wrapping_mul(31).wrapping_add(black_box(w));
    }
    s
}

unsafe fn check(s: &State, name: &[u8], got: impl FnOnce() -> u32, want: u32) -> bool {
    line(s, b"read", name, None);
    let got = got();
    line(s, if got == want { b"ok" } else { b"BAD" }, name, Some(got));
    got == want
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes, `syscalls` the kernel's syscall table, and `params`
/// the config TLV blob of `params_len` bytes (may be null when it is empty).
#[no_mangle]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if state.is_null() || syscalls.is_null() {
        return -1;
    }
    if state_size < core::mem::size_of::<State>() {
        return -2;
    }
    unsafe {
        core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
    }
    0
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() || s.done != 0 {
            return 0;
        }
        s.done = 1;
        let mut all = true;
        all &= check(
            s,
            b"big_static",
            || read_bytes(&BIG_STATIC),
            const { sum_bytes(&BIG_STATIC) },
        );
        all &= check(
            s,
            b"small_static",
            || read_bytes(&SMALL_STATIC),
            const { sum_bytes(&SMALL_STATIC) },
        );
        all &= check(
            s,
            b"word_static",
            || read_words(&WORD_STATIC),
            const { sum_words(&WORD_STATIC) },
        );
        all &= check(
            s,
            b"private_static",
            || read_bytes(&PRIVATE_STATIC),
            const { sum_bytes(&PRIVATE_STATIC) },
        );
        all &= check(
            s,
            b"nested_static",
            || read_bytes(&nested::NESTED_STATIC),
            const { sum_bytes(&nested::NESTED_STATIC) },
        );
        all &= check(
            s,
            b"const_array",
            || read_bytes(&CONST_ARRAY),
            const { sum_bytes(&CONST_ARRAY) },
        );
        all &= check(
            s,
            b"const_slice",
            || read_bytes(CONST_SLICE),
            const { sum_bytes(CONST_SLICE) },
        );
        if all {
            say(s, b"[static_probe] done");
        }
        0
    }
}

include!("../../sdk/runtime/wasm_entry.rs");
