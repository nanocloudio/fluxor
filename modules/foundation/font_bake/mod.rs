//! font_bake — a font file in, a glyph pack out (`abi::contracts::glyph_pack`).
//!
//! A build-time module: a graph's asset names it through the `@font_baker`
//! bound name, whose stack (`packaging/stack/font_bake.yaml`) meets the
//! build-step interface. It reads the TrueType font named by `input` through
//! the FS contract, bakes it (`bake.rs`) into a pack with one strike per
//! `size × scale`, in the `format` variant, keeping the code points `chars`
//! names; writes the pack to `output`, or its errors to `diagnostics`; then
//! the exit code to `exit`, and finishes.
//!
//! Fluxor ships no fonts: the project that builds the asset supplies the
//! file.

#![cfg_attr(not(feature = "host-test"), no_std)]
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
use core::ptr;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");
include!("../../sdk/crypto/sha256.rs");

use abi::contracts::glyph_pack as gp;
use abi::contracts::storage::fs;

#[path = "bake.rs"]
mod bake;
#[path = "closure.rs"]
mod closure;
#[path = "options.rs"]
mod options;
#[path = "raster.rs"]
mod raster;
#[path = "ttf.rs"]
mod ttf;

/// The heap's cap: the font, the working buffers and the pack.
const ARENA_BYTES: u32 = 512 * 1024 * 1024;
const MAX_PATH: usize = 240;
const MAX_TEXT: usize = 256;
const READ_CHUNK: usize = 64 * 1024;
/// A channel write is whole or nothing, so it must fit the channel.
const WRITE_CHUNK: usize = 4096;
/// Points of one contour.
const POINTS: usize = 16 * 1024;
/// Accumulation cells: the largest glyph bitmap, about 2000 × 2000 pixels.
const ACC: usize = 4 * 1024 * 1024;
/// The pack buffer's first size, grown by doubling while it is too small.
const OUT_FIRST: usize = 4 * 1024 * 1024;

const PH_READ: u8 = 0;
const PH_BAKE: u8 = 1;
const PH_WRITE: u8 = 2;
const PH_EXIT: u8 = 3;
const PH_DONE: u8 = 4;

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    output: i32,
    diagnostics: i32,
    exit: i32,
    input: [u8; MAX_PATH],
    input_len: usize,
    sizes: [u8; MAX_TEXT],
    sizes_len: usize,
    scales: [u8; MAX_TEXT],
    scales_len: usize,
    format: [u8; 16],
    format_len: usize,
    chars: [u8; MAX_TEXT],
    chars_len: usize,
    phase: u8,
    code: i32,
    fd: i32,
    font: *mut u8,
    font_cap: usize,
    font_len: usize,
    out: *mut u8,
    out_len: usize,
    sent: usize,
    exit_sent: usize,
    diag: [u8; 512],
    diag_len: usize,
}

declare_module_state_bytes!(State);
declare_module_arena_bytes!(ARENA_BYTES);

fn copy_param(dst: &mut [u8], len: &mut usize, d: *const u8, n: usize) {
    if n == 0 || n > dst.len() {
        return;
    }
    for (i, b) in dst.iter_mut().enumerate().take(n) {
        *b = unsafe { *d.add(i) };
    }
    *len = n;
}

mod params_def {
    use super::*;

    define_params! {
        State;

        1, input, str, 0
            => |s, d, len| { copy_param(&mut s.input, &mut s.input_len, d, len); };
        2, sizes, str, 0
            => |s, d, len| { copy_param(&mut s.sizes, &mut s.sizes_len, d, len); };
        3, scales, str, 0
            => |s, d, len| { copy_param(&mut s.scales, &mut s.scales_len, d, len); };
        4, format, str, 0
            => |s, d, len| { copy_param(&mut s.format, &mut s.format_len, d, len); };
        5, chars, str, 0
            => |s, d, len| { copy_param(&mut s.chars, &mut s.chars_len, d, len); };
    }
}

name_table!(
    OPTION_ERRORS = [
        b"`format` is a glyph pack format: `a8` or `a1`",
        b"`sizes` lists whole pixel sizes, 1 to 1024, separated by commas",
        b"`scales` lists whole scales, 1 to 8, separated by commas",
        b"more than 64 strikes",
        b"`chars` is a unicode-range list: `U+0020-007E, U+2026`",
        b"more than 64 `chars` ranges",
    ]
);

name_table!(TABLES = [b"head", b"maxp", b"hhea", b"hmtx", b"loca", b"glyf", b"cmap"]);

fn put(s: &mut State, b: &[u8]) {
    for &c in b {
        if s.diag_len < s.diag.len() {
            s.diag[s.diag_len] = c;
            s.diag_len += 1;
        }
    }
}

/// Start a diagnostic line, `<input>: error: `; end it with `end`.
fn begin(s: &mut State) {
    let input = s.input;
    put(s, &input[..s.input_len]);
    put(s, b": error: ");
    s.code = 1;
}

fn end(s: &mut State) {
    put(s, b"\n");
}

fn error(s: &mut State, msg: &[u8]) {
    begin(s);
    put(s, msg);
    end(s);
}

fn decimal(mut v: u32, buf: &mut [u8; 10]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 || i == 0 {
            break;
        }
    }
    &buf[i..]
}

/// Read the font, growing its buffer as it comes.
fn step_read(s: &mut State) {
    let sys = unsafe { &*s.syscalls };
    if s.fd < 0 {
        if s.input_len == 0 {
            error(s, b"no input font");
            s.phase = PH_WRITE;
            return;
        }
        let mut p = [0u8; MAX_PATH + 1];
        p[..s.input_len].copy_from_slice(&s.input[..s.input_len]);
        let fd = unsafe { (sys.provider_call)(-1, fs::OPEN, p.as_mut_ptr(), s.input_len) };
        if fd < 0 {
            error(s, b"cannot open the font");
            s.phase = PH_WRITE;
            return;
        }
        s.fd = fd;
        let mut st = [0u8; 16];
        let r = unsafe { (sys.provider_call)(fd, fs::STAT, st.as_mut_ptr(), 16) };
        let size = if r >= 16 {
            u64::from_le_bytes([st[0], st[1], st[2], st[3], st[4], st[5], st[6], st[7]]) as usize
        } else {
            0
        };
        s.font_cap = size.max(READ_CHUNK) + READ_CHUNK;
        s.font = unsafe { (sys.heap_alloc)(s.font_cap as u32) };
        if s.font.is_null() {
            error(s, b"the font does not fit the baker's heap");
            s.phase = PH_WRITE;
        }
        return;
    }
    if s.font_len + READ_CHUNK > s.font_cap {
        let cap = s.font_cap * 2;
        let p = unsafe { (sys.heap_realloc)(s.font, cap as u32) };
        if p.is_null() {
            error(s, b"the font does not fit the baker's heap");
            s.phase = PH_WRITE;
            return;
        }
        s.font = p;
        s.font_cap = cap;
    }
    let r = unsafe { (sys.provider_call)(s.fd, fs::READ, s.font.add(s.font_len), READ_CHUNK) };
    if r > 0 {
        s.font_len += r as usize;
        return;
    }
    if r < 0 && r != abi::errno::EAGAIN {
        error(s, b"cannot read the font");
        s.phase = PH_WRITE;
    }
    if r == 0 {
        unsafe { (sys.provider_call)(s.fd, fs::CLOSE, ptr::null_mut(), 0) };
        s.fd = -1;
        s.phase = PH_BAKE;
    }
}

fn step_bake(s: &mut State) {
    let sys = unsafe { &*s.syscalls };
    let mut ppems = [0u16; options::MAX_PPEMS];
    let mut chars = [(0u32, 0u32); options::MAX_RANGES];
    let parsed = options::parse(
        &s.sizes[..s.sizes_len],
        &s.scales[..s.scales_len],
        &s.format[..s.format_len],
        &s.chars[..s.chars_len],
        &mut ppems,
        &mut chars,
    );
    let (format, np, nc) = match parsed {
        Ok(v) => v,
        Err(why) => {
            error(s, OPTION_ERRORS.get(why as usize));
            s.phase = PH_WRITE;
            return;
        }
    };
    let font = unsafe { core::slice::from_raw_parts(s.font, s.font_len) };
    let digest = sha256(font);
    let set_len = 8 * 1024;
    let set = unsafe { (sys.heap_alloc)(set_len as u32) };
    let points = unsafe { (sys.heap_alloc)((POINTS * core::mem::size_of::<ttf::Point>()) as u32) };
    let acc = unsafe { (sys.heap_alloc)((ACC * 4) as u32) };
    if set.is_null() || points.is_null() || acc.is_null() {
        error(s, b"the baker's working buffers do not fit its heap");
        s.phase = PH_WRITE;
        return;
    }
    let mut scratch = bake::Scratch {
        set: unsafe { core::slice::from_raw_parts_mut(set, set_len) },
        points: unsafe { core::slice::from_raw_parts_mut(points as *mut ttf::Point, POINTS) },
        acc: unsafe { core::slice::from_raw_parts_mut(acc as *mut f32, ACC) },
    };
    let o = bake::Options {
        format,
        ppems: &ppems[..np],
        chars: &chars[..nc],
    };
    let mut cap = OUT_FIRST;
    loop {
        let out = unsafe { (sys.heap_alloc)(cap as u32) };
        if out.is_null() {
            error(s, b"the pack does not fit the baker's heap");
            break;
        }
        let buf = unsafe { core::slice::from_raw_parts_mut(out, cap) };
        match bake::bake(font, &o, &digest, &mut scratch, buf) {
            Ok(n) => {
                s.out = out;
                s.out_len = n;
                break;
            }
            Err(bake::BakeError::Room) => {
                unsafe { (sys.heap_free)(out) };
                cap *= 2;
            }
            Err(e) => {
                unsafe { (sys.heap_free)(out) };
                let mut d = [0u8; 10];
                begin(s);
                match e {
                    bake::BakeError::Font(ttf::FontError::Cff) => put(
                        s,
                        b"CFF outlines (OpenType `OTTO`) are not baked yet: give a TrueType font",
                    ),
                    bake::BakeError::Font(ttf::FontError::Collection) => {
                        put(s, b"a font collection (`ttcf`): give one font")
                    }
                    bake::BakeError::Font(ttf::FontError::NotTrueType) => {
                        put(s, b"not a TrueType font")
                    }
                    bake::BakeError::Font(ttf::FontError::Malformed(t)) => {
                        put(s, b"malformed `");
                        put(s, TABLES.get(t as usize));
                        put(s, b"` table");
                    }
                    bake::BakeError::Font(ttf::FontError::Missing(t)) => {
                        put(s, b"the font has no `");
                        put(s, TABLES.get(t as usize));
                        put(s, b"` table");
                    }
                    bake::BakeError::GlyphTooLarge { glyph, ppem } => {
                        put(s, b"glyph ");
                        put(s, decimal(glyph as u32, &mut d));
                        put(s, b" is too large to rasterise at ");
                        put(s, decimal(ppem as u32, &mut d));
                        put(s, b" ppem");
                    }
                    bake::BakeError::Scratch | bake::BakeError::Room => {
                        put(s, b"the font has more glyphs than the baker holds")
                    }
                }
                end(s);
                break;
            }
        }
    }
    unsafe {
        (sys.heap_free)(acc);
        (sys.heap_free)(points);
        (sys.heap_free)(set);
    }
    s.sent = 0;
    s.phase = PH_WRITE;
}

/// Write `buf` from `*sent` to `chan`; whether all of it has gone.
fn send(sys: &SyscallTable, chan: i32, buf: &[u8], sent: &mut usize) -> bool {
    while *sent < buf.len() {
        let w = unsafe {
            (sys.channel_write)(
                chan,
                buf.as_ptr().add(*sent),
                (buf.len() - *sent).min(WRITE_CHUNK),
            )
        };
        if w <= 0 {
            return false;
        }
        *sent += w as usize;
    }
    true
}

// --- Module ABI ----------------------------------------------------------

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_state_size")]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

/// The heap arena, for a loader that asks instead of reading the manifest.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_arena_size")]
pub extern "C" fn module_arena_size() -> u32 {
    ARENA_BYTES
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_init")]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes and `syscalls` the kernel's syscall table.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_new")]
#[allow(clippy::too_many_arguments, reason = "fixed module_new ABI signature")]
pub unsafe extern "C" fn module_new(
    _in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() || state.is_null() || state_size < core::mem::size_of::<State>() {
        return -22;
    }
    ptr::write_bytes(state, 0, core::mem::size_of::<State>());
    let s = &mut *(state as *mut State);
    s.syscalls = syscalls as *const SyscallTable;
    s.output = out_chan;
    s.diagnostics = dev_channel_port(&*s.syscalls, 1, 1);
    s.exit = dev_channel_port(&*s.syscalls, 1, 2);
    s.fd = -1;
    if !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01 {
        params_def::parse_tlv(s, params, params_len);
    } else {
        params_def::set_defaults(s);
    }
    s.phase = PH_READ;
    0
}

/// # Safety
/// `state` is the block `module_new` initialised.
#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    if state.is_null() {
        return -1;
    }
    let s = &mut *(state as *mut State);
    let sys = &*s.syscalls;
    match s.phase {
        PH_READ => {
            step_read(s);
            0
        }
        PH_BAKE => {
            step_bake(s);
            0
        }
        PH_WRITE => {
            let done = if s.code == 0 {
                let pack = core::slice::from_raw_parts(s.out, s.out_len);
                s.output < 0 || send(sys, s.output, pack, &mut s.sent)
            } else if s.diagnostics >= 0 {
                let d = s.diag;
                send(sys, s.diagnostics, &d[..s.diag_len], &mut s.sent)
            } else {
                dev_log(sys, 1, s.diag.as_ptr(), s.diag_len);
                true
            };
            if done {
                s.phase = PH_EXIT;
            }
            0
        }
        PH_EXIT => {
            let code = s.code.to_le_bytes();
            if s.exit < 0 || send(sys, s.exit, &code, &mut s.exit_sent) {
                s.phase = PH_DONE;
                return 1;
            }
            0
        }
        _ => 1,
    }
}

include!("../../sdk/runtime/wasm_entry.rs");
