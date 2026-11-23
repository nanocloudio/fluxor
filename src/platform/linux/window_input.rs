//! What a host window's input becomes on the wire: pointer, key and text
//! records from window events, as plain functions of the event's values.
//!
//! The window thread calls these and queues what they produce; the display
//! module's step relays the queues to its `pointer`, `keys` and `text`
//! outputs. Nothing here names the windowing library, so the mappings are
//! exercised without a window.
//!
//! Positions and pixel wheel deltas are in surface pixels: the pixels of
//! the raster the window presents, each drawn as `scale` x `scale` window
//! pixels.
//!
//! KEYS AND TEXT. A window has no text field of its own, so a key record is
//! flagged `KEY_TEXT` only when that key press produced a COMMIT here: text
//! with no control character while neither Ctrl nor Meta is held. Every
//! other key (Backspace, Enter, arrows, shortcuts) reaches the application
//! unflagged and is the application's to act on. While an input method is
//! composing it owns the keyboard: keys produce no record until the
//! composition ends.

use super::input_queue::RecordQueue;
use crate::abi::contracts::input::{key, pointer, text};

/// Wheel deltas for a window's line scroll of `(x, y)` lines, in 1/120
/// detent. A window reports the way the content moves (positive: right and
/// down); the record says where the view scrolls (positive: toward the
/// right and the end), so both axes change sign.
pub fn wheel_from_lines(x: f32, y: f32) -> (i32, i32) {
    let unit = f32::from(pointer::WHEEL_UNITS_PER_DETENT);
    ((-x * unit).round() as i32, (-y * unit).round() as i32)
}

/// Wheel deltas for a window's smooth scroll of `(x, y)` window pixels, in
/// eighths of a surface pixel. Signs as `wheel_from_lines`.
pub fn wheel_from_pixels(x: f64, y: f64, scale: u32) -> (i32, i32) {
    let unit = f64::from(pointer::WHEEL_UNITS_PER_PIXEL) / f64::from(scale.max(1));
    ((-x * unit).round() as i32, (-y * unit).round() as i32)
}

/// The surface pixel under a window position: window pixels divided by the
/// integer magnification, kept within the record's range.
pub fn surface_point(x: f64, y: f64, scale: u32) -> (i16, i16) {
    let scale = f64::from(scale.max(1));
    let cut = |v: f64| {
        (v / scale)
            .floor()
            .clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16
    };
    (cut(x), cut(y))
}

/// A pointer record other than a wheel record. Pressure is the default
/// while a button is held and zero otherwise: a mouse reports none.
pub fn pointer_record(
    kind: u8,
    pointer_id: u8,
    buttons: u8,
    modifiers: u8,
    x: i16,
    y: i16,
) -> [u8; pointer::EVENT_SIZE] {
    let event = pointer::Event {
        pointer_id,
        kind,
        buttons,
        modifiers,
        wheel_unit: 0,
        pressure: if buttons != 0 {
            pointer::PRESSURE_DEFAULT
        } else {
            0
        },
        x,
        y,
        dx: 0,
        dy: 0,
    };
    // Only wheel fields are refused, and none is set.
    pointer::encode(&event).unwrap_or([0; pointer::EVENT_SIZE])
}

/// Key codes of keys that are named, not typed: the values the key
/// contract's `key_code` carries for them.
pub mod key_codes {
    pub const BACKSPACE: u16 = 8;
    pub const TAB: u16 = 9;
    pub const ENTER: u16 = 13;
    pub const SHIFT: u16 = 16;
    pub const CONTROL: u16 = 17;
    pub const ALT: u16 = 18;
    pub const PAUSE: u16 = 19;
    pub const CAPS_LOCK: u16 = 20;
    pub const ESCAPE: u16 = 27;
    pub const SPACE: u16 = 32;
    pub const PAGE_UP: u16 = 33;
    pub const PAGE_DOWN: u16 = 34;
    pub const END: u16 = 35;
    pub const HOME: u16 = 36;
    pub const ARROW_LEFT: u16 = 37;
    pub const ARROW_UP: u16 = 38;
    pub const ARROW_RIGHT: u16 = 39;
    pub const ARROW_DOWN: u16 = 40;
    pub const PRINT_SCREEN: u16 = 44;
    pub const INSERT: u16 = 45;
    pub const DELETE: u16 = 46;
    pub const META: u16 = 91;
    pub const CONTEXT_MENU: u16 = 93;
    /// F1; F2 to F24 follow it.
    pub const F1: u16 = 112;
    pub const NUM_LOCK: u16 = 144;
    pub const SCROLL_LOCK: u16 = 145;
}

/// The key code of the key that types `c` on a US layout, or 0 for a
/// character no key code is allocated for.
pub fn key_code_for_char(c: char) -> u16 {
    let code = match c {
        'a'..='z' => c.to_ascii_uppercase() as u32,
        'A'..='Z' | '0'..='9' | ' ' => c as u32,
        ')' => '0' as u32,
        '!' => '1' as u32,
        '@' => '2' as u32,
        '#' => '3' as u32,
        '$' => '4' as u32,
        '%' => '5' as u32,
        '^' => '6' as u32,
        '&' => '7' as u32,
        '*' => '8' as u32,
        '(' => '9' as u32,
        ';' | ':' => 186,
        '=' | '+' => 187,
        ',' | '<' => 188,
        '-' | '_' => 189,
        '.' | '>' => 190,
        '/' | '?' => 191,
        '`' | '~' => 192,
        '[' | '{' => 219,
        '\\' | '|' => 220,
        ']' | '}' => 221,
        '\'' | '"' => 222,
        _ => 0,
    };
    code as u16
}

/// The text a key press commits: what the window reports for the key, when
/// it has no control character and neither Ctrl nor Meta is held. A window
/// reports Backspace, Enter and Escape as control characters; those are
/// keys.
pub fn key_text(reported: Option<&str>, modifiers: u8) -> Option<&str> {
    let reported = reported?;
    if reported.is_empty()
        || modifiers & (key::MOD_CTRL | key::MOD_META) != 0
        || reported.chars().any(char::is_control)
    {
        return None;
    }
    Some(reported)
}

/// One key transition as the window reports it.
#[derive(Clone, Copy, Debug)]
pub struct KeyInput<'a> {
    pub pressed: bool,
    pub repeat: bool,
    pub modifiers: u8,
    pub key_code: u16,
    pub scan_code: u16,
    /// The text the window says the key produced.
    pub text: Option<&'a str>,
}

/// The window's text state: whether an input method is composing.
#[derive(Default)]
pub struct TextInput {
    composing: bool,
}

impl TextInput {
    pub fn is_composing(&self) -> bool {
        self.composing
    }

    /// The records of one key transition: its text as COMMITs on `texts`
    /// (when `text_wired`), and the key record on `keys`, flagged `KEY_TEXT`
    /// when a COMMIT was sent for it. Nothing while a composition is in
    /// progress.
    pub fn key(
        &self,
        input: &KeyInput<'_>,
        text_wired: bool,
        keys: &mut RecordQueue,
        texts: &mut RecordQueue,
    ) {
        if self.composing {
            return;
        }
        let committed = input.pressed
            && text_wired
            && key_text(input.text, input.modifiers).is_some_and(|t| commit(t, texts));
        keys.push(&key::encode(&key::KeyEvent {
            kind: if input.pressed {
                key::KIND_DOWN
            } else {
                key::KIND_UP
            },
            modifiers: input.modifiers,
            repeat: input.pressed && input.repeat,
            text: committed,
            key_code: input.key_code,
            scan_code: input.scan_code,
        }));
    }

    /// The input method's preedit changed. `cursor` is its highlighted
    /// range as byte offsets into `preedit`. An empty preedit ends the
    /// composition.
    pub fn preedit(
        &mut self,
        preedit: &str,
        cursor: Option<(usize, usize)>,
        texts: &mut RecordQueue,
    ) {
        if preedit.is_empty() {
            self.end(texts);
            return;
        }
        let shown = text::prefix_within(preedit, text::TEXT_MAX);
        let count = text::scalars(shown);
        let scalar_at = |byte: usize| match preedit.get(..byte) {
            Some(head) => text::scalars(head).min(count),
            None => count,
        };
        let (hl_start, hl_end) = match cursor {
            Some((a, b)) => {
                let (a, b) = (scalar_at(a.min(b)), scalar_at(a.max(b)));
                (a as u16, b as u16)
            }
            // No highlight reported: the caret stands after the preedit.
            None => (count as u16, count as u16),
        };
        let mut record = [0u8; text::MAX_RECORD];
        if let Some(n) = text::write_compose(
            &mut record,
            text::NO_TARGET,
            !self.composing,
            false,
            hl_start,
            hl_end,
            shown,
        ) {
            texts.push(&record[..n]);
            self.composing = true;
        }
    }

    /// The input method committed `committed`: the composition in progress
    /// ends, then the text arrives as COMMITs.
    pub fn commit(&mut self, committed: &str, texts: &mut RecordQueue) {
        self.end(texts);
        commit(committed, texts);
    }

    /// The composition is over (the input method closed, or focus left).
    pub fn end(&mut self, texts: &mut RecordQueue) {
        if !self.composing {
            return;
        }
        self.composing = false;
        let mut record = [0u8; text::HEADER + 4];
        if let Some(n) = text::write_compose(&mut record, text::NO_TARGET, false, true, 0, 0, "") {
            texts.push(&record[..n]);
        }
    }
}

/// Queue `committed` as COMMIT records, split at scalar boundaries with
/// `CONTINUES` on all but the last. Whether any was queued.
fn commit(mut committed: &str, texts: &mut RecordQueue) -> bool {
    let mut any = false;
    let mut record = [0u8; text::MAX_RECORD];
    while !committed.is_empty() {
        let head = text::prefix_within(committed, text::TEXT_MAX);
        if head.is_empty() {
            break;
        }
        let rest = &committed[head.len()..];
        let Some(n) = text::write_commit(&mut record, text::NO_TARGET, !rest.is_empty(), head)
        else {
            break;
        };
        texts.push(&record[..n]);
        any = true;
        committed = rest;
    }
    any
}
