//! Linux `input_event` records in, pointer records out: the decoding half
//! of the `linux_pointer` module, as a function of the bytes an evdev node
//! (or a FIFO carrying the same layout) delivers.
//!
//! Absolute touch (`ABS_X`/`ABS_Y`, `ABS_MT_POSITION_X`/`_Y` with
//! `BTN_TOUCH`) and relative mouse (`REL_X`/`REL_Y` with `BTN_LEFT`) both
//! fold into down, move and up records, scaled from the device's axis range
//! to the surface. A report closes on `SYN_REPORT`.
//!
//! WHEEL. `REL_WHEEL_HI_RES` and `REL_HWHEEL_HI_RES` are 1/120 detent, the
//! wheel record's own unit. The kernel sends the whole-detent codes
//! (`REL_WHEEL`, `REL_HWHEEL`) as well from a device that has the
//! high-resolution ones, so a whole-detent code counts only on an axis that
//! has never sent its high-resolution code; counting both would double the
//! scroll. evdev's positive `REL_WHEEL` is away from the user, which
//! scrolls toward the start, so the record's `dy` is its negation; positive
//! `REL_HWHEEL` is right, as the record's `dx`.

use super::input_queue::{RecordQueue, Wheel, QUEUE_RECORDS};
use crate::abi::contracts::input::pointer;

/// Linux `struct input_event` on a 64-bit host: a 16-byte time, then type
/// (`u16`), code (`u16`) and value (`i32`).
pub const EVENT_SIZE: usize = 24;
const OFF_TYPE: usize = 16;
const OFF_CODE: usize = 18;
const OFF_VALUE: usize = 20;

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;

pub const SYN_REPORT: u16 = 0x00;
pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const REL_HWHEEL: u16 = 0x06;
pub const REL_WHEEL: u16 = 0x08;
pub const REL_WHEEL_HI_RES: u16 = 0x0b;
pub const REL_HWHEEL_HI_RES: u16 = 0x0c;
pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;
pub const ABS_MT_POSITION_X: u16 = 0x35;
pub const ABS_MT_POSITION_Y: u16 = 0x36;
pub const BTN_LEFT: u16 = 0x110;
pub const BTN_TOUCH: u16 = 0x14a;

/// Records one report can queue: a transition and a wheel record, with
/// room for a wheel sum that continues in a further record.
const REPORT_RECORDS: usize = 4;

/// One wheel axis within a report and across them.
#[derive(Default)]
struct Axis {
    /// Whole detents and 1/120 detents received in the open report.
    detents: i32,
    hi_res: i32,
    /// Whether the device has ever sent the axis's high-resolution code.
    has_hi_res: bool,
}

impl Axis {
    /// The report's movement in 1/120 detent, clearing it.
    fn take(&mut self) -> i32 {
        let moved = if self.has_hi_res {
            self.hi_res
        } else {
            self.detents
                .saturating_mul(i32::from(pointer::WHEEL_UNITS_PER_DETENT))
        };
        self.detents = 0;
        self.hi_res = 0;
        moved
    }
}

/// The pointer an evdev stream describes.
pub struct EvdevPointer {
    width: i32,
    height: i32,
    x_max: i32,
    y_max: i32,
    cur_x: i32,
    cur_y: i32,
    down: bool,
    prev_down: bool,
    last_x: i32,
    last_y: i32,
    wheel_v: Axis,
    wheel_h: Axis,
}

/// Scale a raw axis value onto the surface. `axis_max == 0` means the value
/// is already a surface position (a mouse, or a FIFO written in surface
/// pixels).
fn scale_axis(v: i32, axis_max: i32, extent: i32) -> i16 {
    let out = if axis_max > 0 {
        (i64::from(v.max(0)) * (i64::from(extent) - 1) / i64::from(axis_max)) as i32
    } else {
        v
    };
    out.clamp(0, extent - 1) as i16
}

impl EvdevPointer {
    /// A pointer on a surface of `width` x `height`, from a device whose
    /// absolute axes reach `x_max` and `y_max` (0: already surface pixels).
    pub fn new(width: i32, height: i32, x_max: i32, y_max: i32) -> Self {
        Self {
            width: width.clamp(1, i32::from(i16::MAX)),
            height: height.clamp(1, i32::from(i16::MAX)),
            x_max,
            y_max,
            cur_x: 0,
            cur_y: 0,
            down: false,
            prev_down: false,
            last_x: -1,
            last_y: -1,
            wheel_v: Axis::default(),
            wheel_h: Axis::default(),
        }
    }

    /// Decode whole events from the front of `bytes`, queueing a report's
    /// records on `out` at its `SYN_REPORT`. Stops before a report `out`
    /// might not hold, so nothing is dropped: the caller keeps the bytes
    /// not consumed and offers them again once the queue has drained.
    /// Returns the bytes consumed.
    pub fn feed(&mut self, bytes: &[u8], out: &mut RecordQueue) -> usize {
        let mut used = 0;
        for event in bytes.chunks_exact(EVENT_SIZE) {
            if out.len() + REPORT_RECORDS > QUEUE_RECORDS {
                break;
            }
            let kind = u16::from_le_bytes([event[OFF_TYPE], event[OFF_TYPE + 1]]);
            let code = u16::from_le_bytes([event[OFF_CODE], event[OFF_CODE + 1]]);
            let value = i32::from_le_bytes([
                event[OFF_VALUE],
                event[OFF_VALUE + 1],
                event[OFF_VALUE + 2],
                event[OFF_VALUE + 3],
            ]);
            self.event(kind, code, value, out);
            used += EVENT_SIZE;
        }
        used
    }

    /// Take one event.
    pub fn event(&mut self, kind: u16, code: u16, value: i32, out: &mut RecordQueue) {
        match (kind, code) {
            (EV_ABS, ABS_X | ABS_MT_POSITION_X) => self.cur_x = value,
            (EV_ABS, ABS_Y | ABS_MT_POSITION_Y) => self.cur_y = value,
            (EV_REL, REL_X) => self.cur_x = self.cur_x.saturating_add(value),
            (EV_REL, REL_Y) => self.cur_y = self.cur_y.saturating_add(value),
            (EV_REL, REL_WHEEL) => {
                self.wheel_v.detents = self.wheel_v.detents.saturating_add(value)
            }
            (EV_REL, REL_HWHEEL) => {
                self.wheel_h.detents = self.wheel_h.detents.saturating_add(value);
            }
            (EV_REL, REL_WHEEL_HI_RES) => {
                self.wheel_v.has_hi_res = true;
                self.wheel_v.hi_res = self.wheel_v.hi_res.saturating_add(value);
            }
            (EV_REL, REL_HWHEEL_HI_RES) => {
                self.wheel_h.has_hi_res = true;
                self.wheel_h.hi_res = self.wheel_h.hi_res.saturating_add(value);
            }
            (EV_KEY, BTN_TOUCH | BTN_LEFT) => self.down = value != 0,
            (EV_SYN, SYN_REPORT) => self.report(out),
            _ => {}
        }
    }

    /// Close a report: a transition record when the report pressed,
    /// released or moved a held pointer, then its wheel movement.
    fn report(&mut self, out: &mut RecordQueue) {
        let x = scale_axis(self.cur_x, self.x_max, self.width);
        let y = scale_axis(self.cur_y, self.y_max, self.height);
        let buttons = if self.down { pointer::BTN_PRIMARY } else { 0 };
        let kind = if self.down && !self.prev_down {
            Some(pointer::KIND_DOWN)
        } else if !self.down && self.prev_down {
            Some(pointer::KIND_UP)
        } else if self.down && (self.cur_x != self.last_x || self.cur_y != self.last_y) {
            Some(pointer::KIND_MOVE)
        } else {
            None
        };
        self.prev_down = self.down;
        if let Some(kind) = kind {
            self.last_x = self.cur_x;
            self.last_y = self.cur_y;
            let event = pointer::Event {
                pointer_id: 0,
                kind,
                buttons,
                modifiers: 0,
                wheel_unit: 0,
                pressure: if self.down {
                    pointer::PRESSURE_DEFAULT
                } else {
                    0
                },
                x,
                y,
                dx: 0,
                dy: 0,
            };
            if let Some(bytes) = pointer::encode(&event) {
                out.push(&bytes);
            }
        }
        let dy = self.wheel_v.take().saturating_neg();
        let dx = self.wheel_h.take();
        out.push_wheel(&Wheel {
            pointer_id: 0,
            unit: pointer::WHEEL_DETENTS,
            buttons,
            modifiers: 0,
            x,
            y,
            dx,
            dy,
        });
    }
}
