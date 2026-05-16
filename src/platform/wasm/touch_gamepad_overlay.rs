//! `wasm_browser_touch_gamepad_overlay` built-in: transformer that
//! consumes `input::pointer::MSG_EVENT` and emits
//! `input::gamepad::MSG_STATE`. On-screen virtual gamepad — touch
//! contacts hit the configured regions and become W3C-standard
//! gamepad button presses. The corresponding visual overlay (DPAD +
//! face-button divs the user touches) is rendered by the runtime
//! shell from the same region table this module uses for
//! hit-testing — single source of truth.
//!
//! Pipeline:
//!
//! ```text
//! DOM pointer events
//!         │
//!         ▼  (Web PointerEvent push)
//! ┌─────────────────────┐
//! │  wasm_browser_pointer│   → emits PointerEvent records
//! └─────────┬───────────┘
//!           │  input::pointer::MSG_EVENT (16B)
//!           ▼
//! ┌─────────────────────────────────────┐
//! │  wasm_browser_touch_gamepad_overlay │   hit-test pointer (x,y) against
//! │                                     │   region table → button bitmask
//! │                                     │   per active pointer; OR across
//! │                                     │   pointers → composite state; emit
//! │                                     │   MSG_STATE on change
//! └─────────┬───────────────────────────┘
//!           │  input::gamepad::MSG_STATE (16B)
//!           ▼
//!   game / emulator
//! ```
//!
//! Multi-touch: each active pointer_id owns the buttons it
//! activated on DOWN. Releasing that pointer (UP/CANCEL) clears
//! only its bits, leaving other simultaneous touches intact.
//! Common case: thumb on DPAD-up + thumb on A produces
//! `button_bits = (1<<BTN_DPAD_UP) | (1<<BTN_A)`.
//!
//! For v1 the region table is hardcoded for a 960×540 canvas: DPAD
//! cross on the left, face-button diamond on the right, START /
//! SELECT centred at top. Future revs read regions from module
//! params so per-graph custom layouts (a single big steering wheel,
//! a dance-pad grid, etc.) can override.

use crate::kernel::{channel, scheduler, syscalls};

/// Input record (Pointer MSG_EVENT) — must match
/// `modules/sdk/contracts/input/pointer.rs::EVENT_SIZE`.
const POINTER_EVENT_SIZE: usize = 16;

/// Output record (Gamepad MSG_STATE) — must match
/// `modules/sdk/contracts/input/gamepad.rs::EVENT_SIZE`.
const GAMEPAD_EVENT_SIZE: usize = 16;

/// Maximum concurrent active pointers we track. 8 covers every
/// realistic multi-touch device (most browsers cap at 10 contacts
/// but practical games use 4 at most).
const MAX_ACTIVE_POINTERS: usize = 8;

/// Hardcoded button bit indices from
/// `modules/sdk/contracts/input/gamepad.rs` — must stay in sync.
mod btn {
    pub const A: u8           = 0;
    pub const B: u8           = 1;
    pub const X: u8           = 2;
    pub const Y: u8           = 3;
    pub const L1: u8          = 4;
    pub const R1: u8          = 5;
    pub const SELECT: u8      = 8;
    pub const START: u8       = 9;
    pub const DPAD_UP: u8     = 12;
    pub const DPAD_DOWN: u8   = 13;
    pub const DPAD_LEFT: u8   = 14;
    pub const DPAD_RIGHT: u8  = 15;
}

/// `(button_index, x, y, w, h)` — a single hit region.
#[derive(Clone, Copy)]
struct Region {
    btn: u8,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
}

impl Region {
    #[inline]
    fn contains(&self, px: i16, py: i16) -> bool {
        let px = px as i32;
        let py = py as i32;
        let x = self.x as i32;
        let y = self.y as i32;
        let w = self.w as i32;
        let h = self.h as i32;
        px >= x && px < x + w && py >= y && py < y + h
    }
}

/// Canonical v1 layout for a 960×540 canvas. DPAD cross at left,
/// face-button diamond at right, START / SELECT centred at top.
/// L1 / R1 are bumper strips along the top corners. These match
/// the regions runtime.html renders as DOM overlays — keep both in
/// sync (the test in `tools/tests/wasm_touch_overlay_layout.rs`
/// pins the mapping).
const REGIONS: &[Region] = &[
    // DPAD cross — left thumb. Centred at (130, 380), 60×60 cells.
    Region { btn: btn::DPAD_UP,    x: 100, y: 290, w: 60, h: 60 },
    Region { btn: btn::DPAD_LEFT,  x:  40, y: 350, w: 60, h: 60 },
    Region { btn: btn::DPAD_RIGHT, x: 160, y: 350, w: 60, h: 60 },
    Region { btn: btn::DPAD_DOWN,  x: 100, y: 410, w: 60, h: 60 },
    // Face-button diamond — right thumb. Centred at (830, 380).
    Region { btn: btn::Y,          x: 800, y: 290, w: 60, h: 60 },
    Region { btn: btn::X,          x: 740, y: 350, w: 60, h: 60 },
    Region { btn: btn::B,          x: 860, y: 350, w: 60, h: 60 },
    Region { btn: btn::A,          x: 800, y: 410, w: 60, h: 60 },
    // Bumpers along top.
    Region { btn: btn::L1,         x:   0, y:   0, w: 200, h: 40 },
    Region { btn: btn::R1,         x: 760, y:   0, w: 200, h: 40 },
    // Centre top: SELECT (left of start), START (right).
    Region { btn: btn::SELECT,     x: 380, y:  10, w:  90, h: 30 },
    Region { btn: btn::START,      x: 490, y:  10, w:  90, h: 30 },
];

/// Per-active-pointer entry. `id == -1` indicates a free slot.
#[derive(Clone, Copy)]
pub(crate) struct ActivePointer {
    id: i16,
    bits: u16,
}

#[repr(C)]
pub(crate) struct OverlayState {
    pub in_chan: i32,
    pub out_chan: i32,
    pub active: [ActivePointer; MAX_ACTIVE_POINTERS],
    /// Last-emitted composite button bits — emit a new MSG_STATE
    /// only when this changes.
    pub last_bits: u16,
    pub in_buf:  [u8; POINTER_EVENT_SIZE],
    pub out_buf: [u8; GAMEPAD_EVENT_SIZE],
}

unsafe fn alloc_state(in_chan: i32, out_chan: i32) -> *mut OverlayState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<OverlayState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut OverlayState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        OverlayState {
            in_chan,
            out_chan,
            active: [ActivePointer { id: -1, bits: 0 }; MAX_ACTIVE_POINTERS],
            last_bits: 0,
            in_buf:  [0u8; POINTER_EVENT_SIZE],
            out_buf: [0u8; GAMEPAD_EVENT_SIZE],
        },
    );
    raw
}

/// Find which W3C button bit a pointer at (x,y) lands in. Returns
/// the bitmask (single bit set), or 0 if outside every region.
#[inline]
fn region_bit(x: i16, y: i16) -> u16 {
    for r in REGIONS {
        if r.contains(x, y) {
            return 1u16 << r.btn;
        }
    }
    0
}

/// Composite the current button state across every active pointer.
#[inline]
fn composite_bits(active: &[ActivePointer; MAX_ACTIVE_POINTERS]) -> u16 {
    let mut bits = 0u16;
    for p in active.iter() {
        if p.id >= 0 {
            bits |= p.bits;
        }
    }
    bits
}

fn overlay_step(state: *mut u8) -> i32 {
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut OverlayState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.in_chan < 0 || st.out_chan < 0 {
            return 0;
        }

        // Drain every pointer event the producer has queued. The
        // wasm_browser_pointer module emits one record per DOM
        // event; many can pile up per scheduler tick during a
        // burst.
        loop {
            let n = channel::channel_read(
                st.in_chan,
                st.in_buf.as_mut_ptr(),
                st.in_buf.len(),
            );
            if n <= 0 {
                break;
            }
            if (n as usize) < POINTER_EVENT_SIZE {
                continue;
            }

            let buf = &st.in_buf;
            // Decode pointer event header.
            let pointer_id = buf[1] as i16;
            let kind = buf[2];
            // Skip the buttons / modifiers / pressure bytes (3..7).
            let x = i16::from_le_bytes([buf[8],  buf[9]]);
            let y = i16::from_le_bytes([buf[10], buf[11]]);

            // input::pointer::KIND_*
            const KIND_DOWN: u8   = 1;
            const KIND_UP: u8     = 2;
            const KIND_MOVE: u8   = 3;
            const KIND_CANCEL: u8 = 4;

            match kind {
                KIND_DOWN => {
                    let new_bits = region_bit(x, y);
                    // Claim a slot for this pointer.
                    for p in st.active.iter_mut() {
                        if p.id < 0 {
                            p.id = pointer_id;
                            p.bits = new_bits;
                            break;
                        }
                    }
                }
                KIND_MOVE => {
                    // Track-through: as a pointer drags between
                    // regions, its bit follows. Lets the user slide
                    // a thumb between DPAD-left and DPAD-up without
                    // lifting (common in dual-stick games).
                    let new_bits = region_bit(x, y);
                    for p in st.active.iter_mut() {
                        if p.id == pointer_id {
                            p.bits = new_bits;
                            break;
                        }
                    }
                }
                KIND_UP | KIND_CANCEL => {
                    for p in st.active.iter_mut() {
                        if p.id == pointer_id {
                            p.id = -1;
                            p.bits = 0;
                            break;
                        }
                    }
                }
                _ => {} // ENTER/LEAVE: not used for hit-testing.
            }
        }

        // Composite + emit on change only. Idle keepalive can be
        // added later if a consumer needs "are you still alive"
        // beats; for v1 edges are enough.
        let bits = composite_bits(&st.active);
        if bits != st.last_bits {
            st.last_bits = bits;
            // Build a MSG_STATE record (input::gamepad::MSG_STATE).
            // Layout: msg_type, pad, pad×2, gamepad_id, connected,
            // button_bits:u16, axes:i16×4.
            let out = &mut st.out_buf;
            out[0] = 0x01;            // MSG_STATE
            out[1] = 0;
            out[2] = 0; out[3] = 0;
            out[4] = 0;               // gamepad_id 0 (virtual)
            out[5] = 1;               // connected
            out[6..8].copy_from_slice(&bits.to_le_bytes());
            // No analog sticks from a touch overlay; could later
            // emit derived axes (DPAD as full-deflection axis).
            for byte in &mut out[8..16] {
                *byte = 0;
            }
            let _ = channel::channel_write(
                st.out_chan,
                out.as_ptr(),
                out.len(),
            );
        }

        0
    }
}

pub(crate) unsafe fn build(in_chan: i32, out_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new(
        "wasm_browser_touch_gamepad_overlay",
        overlay_step,
    );
    let raw = alloc_state(in_chan, out_chan);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut OverlayState, raw);
    m
}
