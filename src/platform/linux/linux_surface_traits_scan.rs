// Pure Surface Traits computation for Linux — the std-only, dependency-free
// half of the `linux_surface_traits` authority: the `/proc/bus/input/devices`
// modality scan, the size-class hysteresis, and the audio-config readback.
//
// Split out from `linux_surface_traits.rs` so this logic can be unit-tested
// standalone — `tests/harness/tests/linux_surface_traits_scan.rs` `include!`s
// THIS file directly, the same way the `fluxor-linux` bin does. Both inclusions
// land in one module scope, so the channel-wiring / step-loop half in
// `linux_surface_traits.rs` sees these items (and vice versa) with no `pub`.

use std::sync::atomic::{AtomicU32, Ordering};

/// Audio output config, published by `linux_audio` on construction. Packed
/// `(channels << 24) | (rate_hz & 0x00FF_FFFF)`; `0` = no audio sink.
pub(crate) static SURFACE_AUDIO: AtomicU32 = AtomicU32::new(0);

// Size-class thresholds — MUST match input::surface_traits.rs (drift-guarded
// by tools/tests/browser_overlay_runtime_surface.rs).
const COMPACT_ENTER_PX: u16 = 580;
const REGULAR_ENTER_PX: u16 = 600;
const EXPANDED_LEAVE_PX: u16 = 880;
const EXPANDED_ENTER_PX: u16 = 900;

const SIZE_COMPACT: u8 = 0;
const SIZE_REGULAR: u8 = 1;
const SIZE_EXPANDED: u8 = 2;

const MODALITY_KEY: u16 = 0x0001;
const MODALITY_POINTER_FINE: u16 = 0x0002;
const MODALITY_TOUCH: u16 = 0x0008;
const MODALITY_GAMEPAD: u16 = 0x0010;

/// Mirror of input::surface_traits::size_class_for (same hysteresis).
fn size_class_for(px: u16, prev: u8) -> u8 {
    match prev {
        SIZE_EXPANDED => {
            if px < EXPANDED_LEAVE_PX {
                if px < COMPACT_ENTER_PX {
                    SIZE_COMPACT
                } else {
                    SIZE_REGULAR
                }
            } else {
                SIZE_EXPANDED
            }
        }
        SIZE_COMPACT => {
            if px >= EXPANDED_ENTER_PX {
                SIZE_EXPANDED
            } else if px >= REGULAR_ENTER_PX {
                SIZE_REGULAR
            } else {
                SIZE_COMPACT
            }
        }
        _ => {
            if px >= EXPANDED_ENTER_PX {
                SIZE_EXPANDED
            } else if px < COMPACT_ENTER_PX {
                SIZE_COMPACT
            } else {
                SIZE_REGULAR
            }
        }
    }
}

/// Scan the body of `/proc/bus/input/devices` for present input modalities and
/// the attached gamepad count. Pure + unit-tested. Keys off the `H: Handlers=`
/// line (kbd / mouse / event / jsN) and the `B: ABS=` capability mask. KEY is
/// always reported — a Linux surface always has a key path.
fn scan_devices(devices: &str) -> (u16, u8) {
    let mut m = MODALITY_KEY;
    let mut pads: u8 = 0;
    for line in devices.lines() {
        let l = line.trim_start();
        if let Some(rest) = l.strip_prefix("H: Handlers=") {
            if rest.contains("mouse") {
                m |= MODALITY_POINTER_FINE;
            }
            // Each `jsN` token is one game controller.
            for tok in rest.split_whitespace() {
                if tok.starts_with("js") && tok[2..].bytes().all(|b| b.is_ascii_digit()) {
                    m |= MODALITY_GAMEPAD;
                    pads = pads.saturating_add(1);
                }
            }
        } else if let Some(rest) = l.strip_prefix("B: ABS=") {
            let mask = rest.trim();
            // A long / multi-word ABS mask indicates multitouch ABS axes.
            if mask.len() > 8 || mask.split_whitespace().count() > 1 {
                m |= MODALITY_TOUCH;
            }
        }
    }
    (m, pads)
}

fn read_audio() -> (u8, u32) {
    let a = SURFACE_AUDIO.load(Ordering::Relaxed);
    if a == 0 {
        (0, 0)
    } else {
        ((a >> 24) as u8, a & 0x00FF_FFFF)
    }
}
