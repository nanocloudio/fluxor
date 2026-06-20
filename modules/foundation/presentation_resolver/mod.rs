//! On-device placement resolver — the bare-metal counterpart of the host
//! reference `tools/src/presentation_resolver.rs` (`.context/rfc_adaptive_presentation.md`
//! §10). It consumes the runtime environment plane (`input::surface_traits`
//! MSG_TRAITS records) and emits a `presentation.layout` record describing, per
//! declared control, its disposition (chrome / content / bound / hidden), plane,
//! and physical-button legend.
//!
//! The browser runs this same algorithm in JS (`browser_overlay_runtime.js`);
//! this module is how Linux-display and bare-metal-panel surfaces get an
//! adaptive layout without a host. It can't parse a config's `presentation.shell`,
//! so the tooling serializes each control's intent into the `intents` blob param
//! (encoder: `presentation_resolver::encode_intents`); the surface's non-traits
//! policy (chrome region, button count, plane capacities) comes from params too.
//! The resolve + encode logic mirrors the host reference exactly (drift-guarded
//! by tools/tests/presentation_resolver_module_drift.rs).
//!
//! Ports:
//!   in  `traits`  — input::surface_traits MSG_TRAITS (24-byte records)
//!   out `layout`  — presentation.layout records
//!
//! Params: intents (blob), physical_buttons, chrome_capacity, content_capacity,
//! chrome_region (bare-metal default: no host chrome).

#![no_std]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

use abi::contracts::input::surface_traits as st;

const MAX_CONTROLS: usize = 16;
const MAX_BTN_LEN: usize = 24;

// ── presentation.layout wire format (mirror of host presentation_resolver) ──
const MSG_LAYOUT: u8 = 0x01;
const LAYOUT_HEADER_LEN: usize = 8;

const DISP_CHROME: u8 = 0;
const DISP_CONTENT: u8 = 1;
const DISP_BOUND: u8 = 2;
const DISP_HIDDEN: u8 = 3;

const PLANE_CHROME: u8 = 0;
const PLANE_CONTENT: u8 = 1;
const PLANE_NONE: u8 = 0xFF;

const FLAG_UNPLACEABLE: u8 = 0x01;
const LEGEND_NONE: u8 = 0xFF;

// ── intent affinity codes (mirror host AFFINITY_*) ──────────────────────────
const AFFINITY_CHROME: u8 = 0; // [Chrome]
const AFFINITY_CONTENT: u8 = 1; // [Content]
const AFFINITY_CHROME_CONTENT: u8 = 2; // [Chrome, Content]
const AFFINITY_CONTENT_CHROME: u8 = 3; // [Content, Chrome]

// Priority codes (match the host `Priority` discriminant order).
const PRIO_OPTIONAL: u8 = 0;
const PRIO_STANDARD: u8 = 1;
const PRIO_ESSENTIAL: u8 = 2;

// Intent flags-byte bit (mirror host INTENT_FLAG_VIRTUAL): a virtual gameplay
// control (dpad/stick/button_cluster), suppressed on a mouse surface.
const INTENT_FLAG_VIRTUAL: u8 = 0x01;

const OUT_BUF: usize = LAYOUT_HEADER_LEN + MAX_CONTROLS * 4 + MAX_CONTROLS * (1 + MAX_BTN_LEN);

#[repr(C)]
struct State {
    syscalls: *const SyscallTable,
    traits_chan: i32,
    layout_chan: i32,
    initialized: bool,

    // Decoded intents.
    n: usize,
    aff: [u8; MAX_CONTROLS],
    prio: [u8; MAX_CONTROLS],
    min_sc: [u8; MAX_CONTROLS],
    suppress: [u16; MAX_CONTROLS],
    virtual_gp: [bool; MAX_CONTROLS],
    btn: [[u8; MAX_BTN_LEN]; MAX_CONTROLS],
    btn_len: [u8; MAX_CONTROLS],

    // Surface policy (not carried in MSG_TRAITS).
    physical_buttons: u8,
    chrome_region: bool,
    chrome_capacity: u16,
    content_capacity: u16,

    // Most-recent traits record (resolution is a pure function of the latest
    // surface state; a burst coalesces to this).
    latest: [u8; st::EVENT_SIZE],

    // Encoded layout awaiting (or mid-) delivery — the layout channel is
    // all-or-nothing, so a refused write is retried next step rather than lost.
    out: [u8; OUT_BUF],
    out_len: usize,
    pending: bool,
}

mod params_def {
    use super::p_u32;
    use super::State;
    use super::SCHEMA_MAX;
    use super::{parse_intents, MAX_BTN_LEN, MAX_CONTROLS};

    define_params! {
        State;

        // Serialized control-intent table (see host `encode_intents`).
        1, intents, blob, 0
            => |s, d, len| { parse_intents(s, d, len); };
        // Free physical buttons available to bind (board policy).
        2, physical_buttons, u32, 0
            => |s, d, len| { s.physical_buttons = p_u32(d, len, 0, 0) as u8; };
        // Plane capacities (host/board policy; bare-metal default = no chrome).
        3, chrome_capacity, u32, 0
            => |s, d, len| { s.chrome_capacity = p_u32(d, len, 0, 0) as u16; };
        4, content_capacity, u32, 8
            => |s, d, len| { s.content_capacity = p_u32(d, len, 0, 8) as u16; };
        // Does the host draw a chrome region? Bare-metal panels: no (0).
        5, chrome_region, u32, 0
            => |s, d, len| { s.chrome_region = p_u32(d, len, 0, 0) != 0; };
    }
}

/// Decode the `intents` blob param into the state's fixed arrays (mirror of host
/// `encode_intents`). Malformed/short input simply yields fewer controls.
fn parse_intents(s: &mut State, d: *const u8, len: usize) {
    s.n = 0;
    if d.is_null() || len < 1 {
        return;
    }
    let read = |off: usize| -> u8 { unsafe { *d.add(off) } };
    let count = read(0) as usize;
    let mut off = 1usize;
    let mut i = 0usize;
    while i < count && i < MAX_CONTROLS {
        // Fixed prefix: aff, prio, min_sc, suppress u16, flags u8, name_len u8
        // (7 bytes); bail on a truncated record.
        if off + 7 > len {
            break;
        }
        s.aff[i] = read(off);
        s.prio[i] = read(off + 1);
        s.min_sc[i] = read(off + 2);
        s.suppress[i] = (read(off + 3) as u16) | ((read(off + 4) as u16) << 8);
        s.virtual_gp[i] = read(off + 5) & INTENT_FLAG_VIRTUAL != 0;
        let nlen = read(off + 6) as usize;
        off += 7;
        if off + nlen > len {
            break;
        }
        let take = if nlen > MAX_BTN_LEN {
            MAX_BTN_LEN
        } else {
            nlen
        };
        let mut k = 0usize;
        while k < take {
            s.btn[i][k] = read(off + k);
            k += 1;
        }
        s.btn_len[i] = take as u8;
        off += nlen;
        i += 1;
    }
    s.n = i;
}

// ── Resolution (fixed-array port of host `resolve`) ─────────────────────────

struct Surface {
    size_class_w: u8,
    modalities: u16,
    display_count: u8,
    chrome_region: bool,
    physical_buttons: u8,
    chrome_capacity: u16,
    content_capacity: u16,
}

impl Surface {
    fn has(&self, m: u16) -> bool {
        self.modalities & m != 0
    }
    fn chrome_eligible(&self) -> bool {
        self.chrome_region && self.display_count > 0
    }
    fn content_eligible(&self) -> bool {
        self.display_count > 0
    }
}

/// Per-control resolution outputs, parallel to the intent arrays.
struct Resolution {
    disp: [u8; MAX_CONTROLS],
    plane: [u8; MAX_CONTROLS],
    bound: [bool; MAX_CONTROLS], // true → emit the control's btn name as legend
    unplaceable: [bool; MAX_CONTROLS],
}

fn resolve(s: &State, surf: &Surface) -> Resolution {
    let mut r = Resolution {
        disp: [DISP_HIDDEN; MAX_CONTROLS],
        plane: [PLANE_NONE; MAX_CONTROLS],
        bound: [false; MAX_CONTROLS],
        unplaceable: [false; MAX_CONTROLS],
    };
    let n = s.n.min(MAX_CONTROLS);
    let mut free_buttons = surf.physical_buttons;
    let mut chrome_used: u16 = 0;
    let mut content_used: u16 = 0;

    // Steps 1–3: per-control filters that don't compete for plane slots.
    let mut need_plane = [0usize; MAX_CONTROLS];
    let mut need_n = 0usize;
    for i in 0..n {
        // 1. Below the surface size class → hidden (essential falls through).
        if surf.size_class_w < s.min_sc[i] && s.prio[i] != PRIO_ESSENTIAL {
            r.disp[i] = DISP_HIDDEN;
            continue;
        }
        // 2. Physical binding wins when a button is free.
        if s.btn_len[i] > 0 && surf.has(st::MODALITY_PHYSICAL_BUTTONS) && free_buttons > 0 {
            free_buttons -= 1;
            r.disp[i] = DISP_BOUND;
            r.bound[i] = true;
            continue;
        }
        // 3. Suppressed by a present modality, or the virtual-gameplay policy
        //    (fine pointer present, no touch → a mouse surface has no use for an
        //    on-screen pad). Same rule as the host resolve + browser overlay.
        let suppressed = (s.suppress[i] != 0 && surf.has(s.suppress[i]))
            || (s.virtual_gp[i]
                && surf.has(st::MODALITY_POINTER_FINE)
                && !surf.has(st::MODALITY_TOUCH));
        if suppressed {
            r.disp[i] = DISP_HIDDEN;
            continue;
        }
        need_plane[need_n] = i;
        need_n += 1;
    }

    // Steps 4–5: plane assignment, highest-priority-first (stable by index).
    // Insertion sort on the need_plane index list.
    let mut a = 1usize;
    while a < need_n {
        let v = need_plane[a];
        let mut b = a;
        while b > 0 && better_first(s, v, need_plane[b - 1]) {
            need_plane[b] = need_plane[b - 1];
            b -= 1;
        }
        need_plane[b] = v;
        a += 1;
    }

    for idx in 0..need_n {
        let i = need_plane[idx];
        // Eligible planes in the control's preference order, auto-extending a
        // chrome-only control to content on a chrome-less-but-displayed surface.
        let mut prefs = [0u8; 2];
        let mut pref_n = 0usize;
        for &p in affinity_planes(s.aff[i]).iter() {
            let eligible = match p {
                PLANE_CHROME => surf.chrome_eligible(),
                PLANE_CONTENT => surf.content_eligible(),
                _ => false,
            };
            if eligible {
                prefs[pref_n] = p;
                pref_n += 1;
            }
        }
        if pref_n == 0
            && s.aff[i] == AFFINITY_CHROME
            && !surf.chrome_eligible()
            && surf.content_eligible()
        {
            prefs[0] = PLANE_CONTENT; // auto-extend: drawn, not dropped
            pref_n = 1;
        }

        let mut placed = false;
        for p in &prefs[..pref_n] {
            match *p {
                PLANE_CHROME if chrome_used < surf.chrome_capacity => {
                    chrome_used += 1;
                    r.disp[i] = DISP_CHROME;
                    r.plane[i] = PLANE_CHROME;
                    placed = true;
                    break;
                }
                PLANE_CONTENT if content_used < surf.content_capacity => {
                    content_used += 1;
                    r.disp[i] = DISP_CONTENT;
                    r.plane[i] = PLANE_CONTENT;
                    placed = true;
                    break;
                }
                _ => {}
            }
        }
        if !placed {
            r.disp[i] = DISP_HIDDEN;
            r.plane[i] = PLANE_NONE;
            r.unplaceable[i] = s.prio[i] == PRIO_ESSENTIAL;
        }
    }
    r
}

/// Ordered eligible-plane preference for an affinity code, as a 2-slot list
/// (second slot ignored when the affinity names one plane).
fn affinity_planes(code: u8) -> [u8; 2] {
    match code {
        AFFINITY_CONTENT => [PLANE_CONTENT, PLANE_NONE],
        AFFINITY_CHROME_CONTENT => [PLANE_CHROME, PLANE_CONTENT],
        AFFINITY_CONTENT_CHROME => [PLANE_CONTENT, PLANE_CHROME],
        _ => [PLANE_CHROME, PLANE_NONE],
    }
}

/// True if control `x` should sort before `y`: higher priority first, then
/// lower index first (stable) — mirrors the host comparator.
fn better_first(s: &State, x: usize, y: usize) -> bool {
    if s.prio[x] != s.prio[y] {
        s.prio[x] > s.prio[y]
    } else {
        x < y
    }
}

/// Encode a resolution to the `presentation.layout` wire record (mirror of host
/// `encode`). Returns the byte buffer and its used length.
fn encode_layout(s: &State, r: &Resolution, epoch: u32) -> ([u8; OUT_BUF], usize) {
    let n = s.n.min(MAX_CONTROLS);
    // Legend name table (dedup; a button drives one control).
    let mut legend = [[0u8; MAX_BTN_LEN]; MAX_CONTROLS];
    let mut legend_len = [0u8; MAX_CONTROLS];
    let mut legend_n = 0usize;

    // Entry block (legend refs assigned as names are interned).
    let mut entries = [0u8; MAX_CONTROLS * 4];
    for i in 0..n {
        let mut legend_ref = LEGEND_NONE;
        if r.disp[i] == DISP_BOUND && r.bound[i] && s.btn_len[i] > 0 {
            let bl = s.btn_len[i] as usize;
            let mut found = LEGEND_NONE;
            for j in 0..legend_n {
                if legend_len[j] as usize == bl && legend[j][..bl] == s.btn[i][..bl] {
                    found = j as u8;
                    break;
                }
            }
            if found != LEGEND_NONE {
                legend_ref = found;
            } else if legend_n < MAX_CONTROLS {
                legend[legend_n][..bl].copy_from_slice(&s.btn[i][..bl]);
                legend_len[legend_n] = bl as u8;
                legend_ref = legend_n as u8;
                legend_n += 1;
            }
        }
        let flags = if r.unplaceable[i] {
            FLAG_UNPLACEABLE
        } else {
            0
        };
        entries[i * 4] = r.disp[i];
        entries[i * 4 + 1] = r.plane[i];
        entries[i * 4 + 2] = flags;
        entries[i * 4 + 3] = legend_ref;
    }

    let mut buf = [0u8; OUT_BUF];
    let mut o = 0usize;
    let put = |b: u8, buf: &mut [u8; OUT_BUF], o: &mut usize| {
        if *o < OUT_BUF {
            buf[*o] = b;
            *o += 1;
        }
    };
    put(MSG_LAYOUT, &mut buf, &mut o);
    put(n as u8, &mut buf, &mut o);
    put(legend_n as u8, &mut buf, &mut o);
    put(0, &mut buf, &mut o);
    for b in epoch.to_le_bytes() {
        put(b, &mut buf, &mut o);
    }
    for i in 0..n * 4 {
        put(entries[i], &mut buf, &mut o);
    }
    for j in 0..legend_n {
        let l = legend_len[j] as usize;
        put(l as u8, &mut buf, &mut o);
        for k in 0..l {
            put(legend[j][k], &mut buf, &mut o);
        }
    }
    (buf, o)
}

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<State>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
#[allow(clippy::too_many_arguments, reason = "fixed module_new ABI signature")]
pub extern "C" fn module_new(
    _in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() || state.is_null() {
            return -1;
        }
        if state_size < core::mem::size_of::<State>() {
            return -2;
        }
        let s = &mut *(state as *mut State);
        s.syscalls = syscalls as *const SyscallTable;
        s.traits_chan = -1;
        s.layout_chan = -1;
        s.initialized = false;
        s.n = 0;
        s.aff = [0; MAX_CONTROLS];
        s.prio = [0; MAX_CONTROLS];
        s.min_sc = [0; MAX_CONTROLS];
        s.suppress = [0; MAX_CONTROLS];
        s.virtual_gp = [false; MAX_CONTROLS];
        s.btn = [[0; MAX_BTN_LEN]; MAX_CONTROLS];
        s.btn_len = [0; MAX_CONTROLS];
        s.physical_buttons = 0;
        s.chrome_region = false;
        s.chrome_capacity = 0;
        s.content_capacity = 8;
        s.latest = [0; st::EVENT_SIZE];
        s.out = [0; OUT_BUF];
        s.out_len = 0;
        s.pending = false;

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        0
    }
}

#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut State);
        if s.syscalls.is_null() {
            return -1;
        }
        let sys = &*s.syscalls;

        if !s.initialized {
            s.traits_chan = dev_channel_port(sys, 0, 0); // input 0: traits
            s.layout_chan = dev_channel_port(sys, 1, 0); // output 0: layout
            s.initialized = true;
        }

        // Retry an undelivered layout first (all-or-nothing channel write).
        if s.pending {
            if !try_emit(s, sys) {
                return 0;
            }
        }

        // Drain traits records; coalesce to the most recent (resolution is a
        // pure function of the latest surface state).
        if s.traits_chan >= 0 {
            let mut rec = [0u8; st::EVENT_SIZE];
            let mut have = false;
            loop {
                let nread = (sys.channel_read)(s.traits_chan, rec.as_mut_ptr(), rec.len());
                if nread < st::EVENT_SIZE as i32 {
                    break;
                }
                if rec[0] == st::MSG_TRAITS {
                    have = true;
                    s.latest = rec; // keep last (coalesce)
                }
            }
            if have {
                resolve_and_stage(s);
                s.pending = true;
                let _ = try_emit(s, sys);
            }
        }
        0
    }
}

/// Decode the latest traits record + policy into a Surface, resolve, encode the
/// layout into `s.out`.
fn resolve_and_stage(s: &mut State) {
    let rec = s.latest;
    let surf = Surface {
        size_class_w: rec[2],
        modalities: (rec[8] as u16) | ((rec[9] as u16) << 8),
        display_count: rec[21],
        chrome_region: s.chrome_region,
        physical_buttons: s.physical_buttons,
        chrome_capacity: s.chrome_capacity,
        content_capacity: s.content_capacity,
    };
    let epoch = (rec[16] as u32)
        | ((rec[17] as u32) << 8)
        | ((rec[18] as u32) << 16)
        | ((rec[19] as u32) << 24);
    let r = resolve(s, &surf);
    let (buf, len) = encode_layout(s, &r, epoch);
    s.out[..len].copy_from_slice(&buf[..len]);
    s.out_len = len;
}

/// Try to write the staged layout record. Returns true if delivered (or nothing
/// to send), false if the channel was full (retry next step).
///
/// `channel_write` on a FIFO is all-or-nothing (channel.rs): it returns `out_len`
/// (the whole record landed) or a non-positive code (EAGAIN — NOTHING written),
/// never a partial count. So retrying the full record after a non-positive
/// return cannot duplicate a prefix: there is no prefix in the ring. We treat
/// ONLY an exact `out_len` as success; anything else keeps the record pending.
fn try_emit(s: &mut State, sys: &SyscallTable) -> bool {
    if s.layout_chan < 0 || s.out_len == 0 {
        s.pending = false;
        return true;
    }
    let written = unsafe { (sys.channel_write)(s.layout_chan, s.out.as_ptr(), s.out_len) };
    if written as usize == s.out_len {
        s.pending = false;
        true
    } else {
        false // EAGAIN (nothing written) — keep pending, retry whole record
    }
}

#[no_mangle]
#[link_section = ".text.module_channel_hints"]
pub extern "C" fn module_channel_hints(out: *mut u8, max_len: usize) -> i32 {
    let hints = [
        // layout: a whole record is written atomically; size the buffer to hold
        // the largest the fixed arrays can produce (OUT_BUF), with headroom.
        ChannelHint {
            port_type: 1,
            port_index: 0,
            buffer_size: 1024,
        },
    ];
    unsafe { write_channel_hints(out, max_len, &hints) }
}

include!("../../sdk/wasm_entry.rs");
