//! a11y_fixture — a small application that draws its own controls and
//! publishes them as an accessibility tree, for a host's input and
//! accessibility path under test.
//!
//! Three controls on a `WIDTH` x `HEIGHT` surface: a text field, a button
//! and a secret field. The picture leaves on `pixels` as whole frames in
//! bands; the tree leaves on `tree`. Actions, text, keys and pointer
//! records come back in and change the controls, and every change is
//! published again: the tree as the changed nodes and the focus, the
//! picture as a new frame.
//!
//! The fixture is the application side of the keys-and-text rule: text
//! arrives on `text` and is applied there; a key flagged `KEY_TEXT` is not
//! applied a second time; an unflagged editing key is the fixture's to act
//! on.

#![cfg_attr(not(feature = "host-test"), no_std)]

use core::ffi::c_void;

use abi::contracts::accessibility as tree;
use abi::contracts::input::{key, pointer, text};
use abi::contracts::video_raster as raster;
use abi::SyscallTable;
use fluxor_abi as abi;

use fluxor_rt::*;

/// The surface, in surface pixels.
const WIDTH: u16 = 240;
const HEIGHT: u16 = 128;
/// Rows in a band of the picture.
const BAND_ROWS: u16 = 8;
const ROW_BYTES: usize = WIDTH as usize * 2;

/// Node ids.
const ROOT: u32 = 1;
const FIELD: u32 = 2;
const BUTTON: u32 = 3;
const SECRET: u32 = 4;
const STATUS: u32 = 5;

/// Bytes of text a field holds.
const FIELD_BYTES: usize = 64;
/// The tree batch being sent: every node with its strings fits.
const OUT_BYTES: usize = 768;

/// Key codes the fixture acts on (`KeyboardEvent.keyCode` values).
const KEY_BACKSPACE: u16 = 8;
const KEY_TAB: u16 = 9;
const KEY_ENTER: u16 = 13;
const KEY_SPACE: u16 = 32;
const KEY_END: u16 = 35;
const KEY_HOME: u16 = 36;
const KEY_LEFT: u16 = 37;
const KEY_RIGHT: u16 = 39;
const KEY_DELETE: u16 = 46;

/// RGB565 colours.
const BACKGROUND: u16 = 0x10A2;
const INSIDE: u16 = 0x0000;
const BORDER: u16 = 0x8410;
const BORDER_FOCUSED: u16 = 0xFFE0;
const TEXT_BAR: u16 = 0xFFFF;
const SECRET_BAR: u16 = 0xF800;
const BUTTON_REST: u16 = 0x001F;
const BUTTON_PRESSED: u16 = 0x07E0;
/// Pixels of bar a scalar of text draws.
const BAR_STEP: u16 = 6;

/// A control's rectangle, in surface pixels.
#[derive(Clone, Copy)]
struct Rect {
    x: u16,
    y: u16,
    w: u16,
    h: u16,
}

impl Rect {
    fn holds(&self, x: i16, y: i16) -> bool {
        let (x, y) = (i32::from(x), i32::from(y));
        x >= i32::from(self.x)
            && x < i32::from(self.x + self.w)
            && y >= i32::from(self.y)
            && y < i32::from(self.y + self.h)
    }

    /// The rectangle as accessibility bounds: 1/64 surface pixel.
    fn bounds(&self) -> tree::Bounds {
        tree::Bounds {
            x: i32::from(self.x) * 64,
            y: i32::from(self.y) * 64,
            w: i32::from(self.w) * 64,
            h: i32::from(self.h) * 64,
        }
    }
}

const ROOT_RECT: Rect = Rect {
    x: 0,
    y: 0,
    w: WIDTH,
    h: HEIGHT,
};
const FIELD_RECT: Rect = Rect {
    x: 16,
    y: 16,
    w: 208,
    h: 24,
};
const BUTTON_RECT: Rect = Rect {
    x: 16,
    y: 52,
    w: 96,
    h: 24,
};
const STATUS_RECT: Rect = Rect {
    x: 128,
    y: 52,
    w: 96,
    h: 24,
};
const SECRET_RECT: Rect = Rect {
    x: 16,
    y: 88,
    w: 208,
    h: 24,
};

/// One text field: its text and its selection, in scalar offsets.
#[repr(C)]
struct Field {
    bytes: [u8; FIELD_BYTES],
    len: u8,
    anchor: u8,
    focus: u8,
}

impl Field {
    fn text(&self) -> &str {
        // The bytes are only ever whole scalars of text that was UTF-8.
        self.bytes
            .get(..self.len as usize)
            .and_then(abi::wire::utf8_text::text)
            .unwrap_or("")
    }

    fn scalars(&self) -> u32 {
        text::scalars(self.text()) as u32
    }

    /// The byte offset of scalar `index`, or the text's length past its end.
    fn byte_of(&self, index: u32) -> usize {
        self.text()
            .char_indices()
            .nth(index as usize)
            .map_or(self.len as usize, |(at, _)| at)
    }

    /// The selection as ordered scalar offsets within the text.
    fn selection(&self) -> (u32, u32) {
        let n = self.scalars();
        let (a, f) = (u32::from(self.anchor).min(n), u32::from(self.focus).min(n));
        (a.min(f), a.max(f))
    }

    fn select(&mut self, anchor: u32, focus: u32) {
        let n = self.scalars();
        self.anchor = anchor.min(n) as u8;
        self.focus = focus.min(n) as u8;
    }

    /// Replace scalars `lo..hi` with as much of `insert` as the field
    /// holds, cut at a scalar boundary; the caret lands after it.
    fn replace(&mut self, lo: u32, hi: u32, insert: &str) {
        let (lo_b, hi_b) = (self.byte_of(lo), self.byte_of(hi));
        let old = self.bytes;
        let head = old.get(..lo_b).unwrap_or(&[]);
        let tail = old.get(hi_b..self.len as usize).unwrap_or(&[]);
        let room = FIELD_BYTES.saturating_sub(head.len() + tail.len());
        let insert = text::prefix_within(insert, room);
        let mut len = 0u8;
        let next = head.iter().chain(insert.as_bytes()).chain(tail);
        for (slot, byte) in self.bytes.iter_mut().zip(next) {
            *slot = *byte;
            len += 1;
        }
        self.len = len;
        let caret = lo + text::scalars(insert) as u32;
        self.anchor = caret as u8;
        self.focus = caret as u8;
    }

    /// Insert at the selection, replacing it.
    fn insert(&mut self, insert: &str) {
        let (lo, hi) = self.selection();
        self.replace(lo, hi, insert);
    }

    /// Delete the selection if it is not empty, else `before` scalars
    /// before the caret and `after` after it.
    fn delete(&mut self, before: u32, after: u32) {
        let (lo, hi) = self.selection();
        if lo != hi {
            self.replace(lo, hi, "");
        } else {
            let end = hi.saturating_add(after).min(self.scalars());
            self.replace(lo.saturating_sub(before), end, "");
        }
    }
}

/// The controls: what the inputs change and the outputs publish.
#[repr(C)]
struct Ui {
    field: Field,
    secret: Field,
    focus: u32,
    presses: u32,
    /// What is owed on `tree`: the whole tree, or the changed nodes.
    owe_whole: bool,
    owe_change: bool,
    /// A frame is owed on `pixels`.
    owe_frame: bool,
}

#[repr(C)]
pub struct State {
    syscalls: *const SyscallTable,
    actions: i32,
    text: i32,
    keys: i32,
    pointer: i32,
    tree: i32,
    pixels: i32,

    ui: Ui,
    revision: u32,

    /// The batch being sent on `tree`.
    out: [u8; OUT_BYTES],
    out_len: u16,
    out_sent: u16,

    /// The frame being sent on `pixels`.
    painting: bool,
    band: u16,
    row: u16,
    header_sent: bool,

    /// The text record being read, and the composition rule.
    carry: [u8; text::MAX_RECORD],
    carry_len: u16,
    composing: text::Sequence,
    /// Records refused on any input.
    refused: u32,
}

fluxor_rt::module_facts! { state: State }

/// The field node `id` names, if it names one.
fn field_of(s: &mut Ui, id: u32) -> Option<&mut Field> {
    match id {
        FIELD => Some(&mut s.field),
        SECRET => Some(&mut s.secret),
        _ => None,
    }
}

/// A change to the controls: the tree and the picture are both owed.
fn changed(s: &mut Ui) {
    s.owe_change = true;
    s.owe_frame = true;
}

fn focus_on(s: &mut Ui, id: u32) {
    let id = match id {
        FIELD | BUTTON | SECRET => id,
        _ => tree::NO_NODE,
    };
    if s.focus != id {
        s.focus = id;
        changed(s);
    }
}

fn press(s: &mut Ui) {
    s.presses = s.presses.wrapping_add(1);
    changed(s);
}

// ── Inputs ───────────────────────────────────────────────────────────

unsafe fn read_actions(s: &mut State, sys: &SyscallTable) {
    let mut rec = [0u8; tree::ACTION_SIZE];
    while (sys.channel_read)(s.actions, rec.as_mut_ptr(), rec.len()) == rec.len() as i32 {
        match tree::decode_action(&rec) {
            Some(tree::Action::Activate { id }) if id == BUTTON => press(&mut s.ui),
            Some(tree::Action::Focus { id }) => focus_on(&mut s.ui, id),
            Some(tree::Action::Resync { .. }) => s.ui.owe_whole = true,
            Some(_) => {}
            None => s.refused = s.refused.wrapping_add(1),
        }
    }
}

fn apply_text(s: &mut Ui, record: &text::Record<'_>) {
    let target = |s: &Ui, named: u32| {
        if named == text::NO_TARGET {
            s.focus
        } else {
            named
        }
    };
    match *record {
        text::Record::Commit {
            target: named,
            text: committed,
            ..
        } => {
            let id = target(s, named);
            if let Some(f) = field_of(s, id) {
                f.insert(committed);
                changed(s);
            }
        }
        text::Record::Delete {
            target: named,
            before,
            after,
        } => {
            let id = target(s, named);
            if let Some(f) = field_of(s, id) {
                f.delete(before, after);
                changed(s);
            }
        }
        text::Record::Select {
            target: named,
            anchor,
            focus,
        } => {
            let id = target(s, named);
            if let Some(f) = field_of(s, id) {
                f.select(anchor, focus);
                s.owe_change = true;
            }
        }
        // A preedit is display only; the fixture draws none.
        text::Record::Compose { .. } => {}
    }
}

unsafe fn read_text(s: &mut State, sys: &SyscallTable) {
    loop {
        let have = (s.carry_len as usize).min(s.carry.len());
        let n = (sys.channel_read)(s.text, s.carry.as_mut_ptr().add(have), s.carry.len() - have);
        if n <= 0 {
            return;
        }
        let len = (have + n as usize).min(s.carry.len());
        let mut at = 0usize;
        loop {
            match text::parse(s.carry.get(at..len).unwrap_or(&[])) {
                text::Parse::NeedMore => break,
                text::Parse::Record { record, consumed } => {
                    if s.composing.admit(&record).is_ok() {
                        apply_text(&mut s.ui, &record);
                    } else {
                        s.composing.reset();
                        s.refused = s.refused.wrapping_add(1);
                    }
                    at += consumed;
                }
                text::Parse::Fault { skip, .. } => {
                    // A refused record goes with the composition in
                    // progress; a lost boundary takes what was read too.
                    s.composing.reset();
                    s.refused = s.refused.wrapping_add(1);
                    at = if skip == 0 { len } else { at + skip };
                }
            }
        }
        // Keep the bytes of the record still arriving at the front.
        let at = at.min(len);
        let kept = len - at;
        for i in 0..kept {
            let byte = s.carry.get(at + i).copied().unwrap_or(0);
            if let Some(slot) = s.carry.get_mut(i) {
                *slot = byte;
            }
        }
        s.carry_len = kept as u16;
    }
}

fn apply_key(s: &mut Ui, event: &key::KeyEvent) {
    if event.kind != key::KIND_DOWN {
        return;
    }
    if event.key_code == KEY_TAB {
        let back = event.modifiers & key::MOD_SHIFT != 0;
        let next = match (s.focus, back) {
            (FIELD, false) | (SECRET, true) => BUTTON,
            (BUTTON, false) | (FIELD, true) => SECRET,
            _ => FIELD,
        };
        focus_on(s, next);
        return;
    }
    if s.focus == BUTTON {
        if event.key_code == KEY_ENTER || event.key_code == KEY_SPACE {
            press(s);
        }
        return;
    }
    // The key's effect has already arrived as text.
    if event.text {
        return;
    }
    let focus = s.focus;
    let Some(f) = field_of(s, focus) else {
        return;
    };
    let caret = u32::from(f.focus);
    match event.key_code {
        KEY_BACKSPACE => f.delete(1, 0),
        KEY_DELETE => f.delete(0, 1),
        KEY_LEFT => f.select(caret.saturating_sub(1), caret.saturating_sub(1)),
        KEY_RIGHT => f.select(caret + 1, caret + 1),
        KEY_HOME => f.select(0, 0),
        KEY_END => f.select(u32::MAX, u32::MAX),
        _ => return,
    }
    changed(s);
}

unsafe fn read_keys(s: &mut State, sys: &SyscallTable) {
    let mut rec = [0u8; key::EVENT_SIZE];
    while (sys.channel_read)(s.keys, rec.as_mut_ptr(), rec.len()) == rec.len() as i32 {
        match key::decode(&rec) {
            Some(event) => apply_key(&mut s.ui, &event),
            None => s.refused = s.refused.wrapping_add(1),
        }
    }
}

unsafe fn read_pointer(s: &mut State, sys: &SyscallTable) {
    let mut rec = [0u8; pointer::EVENT_SIZE];
    while (sys.channel_read)(s.pointer, rec.as_mut_ptr(), rec.len()) == rec.len() as i32 {
        let Some(event) = pointer::decode(&rec) else {
            s.refused = s.refused.wrapping_add(1);
            continue;
        };
        if event.kind != pointer::KIND_DOWN {
            continue;
        }
        let ui = &mut s.ui;
        if FIELD_RECT.holds(event.x, event.y) {
            focus_on(ui, FIELD);
        } else if SECRET_RECT.holds(event.x, event.y) {
            focus_on(ui, SECRET);
        } else if BUTTON_RECT.holds(event.x, event.y) {
            focus_on(ui, BUTTON);
            press(ui);
        } else {
            focus_on(ui, tree::NO_NODE);
        }
    }
}

// ── The tree ─────────────────────────────────────────────────────────

/// "pressed N" into `out`; its length.
fn status_text(presses: u32, out: &mut [u8; 20]) -> usize {
    let head = *b"pressed ";
    let mut digits = [0u8; 10];
    let mut n = presses;
    let mut count = 0usize;
    loop {
        if let Some(d) = digits.get_mut(count) {
            *d = b'0' + (n % 10) as u8;
        }
        count += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let number = digits.iter().take(count).rev();
    let mut len = 0usize;
    for (slot, byte) in out.iter_mut().zip(head.iter().chain(number)) {
        *slot = *byte;
        len += 1;
    }
    len
}

fn plain_node<'a>(
    id: u32,
    parent: u32,
    order: u16,
    role: u8,
    rect: &Rect,
    name: &'a str,
) -> tree::Node<'a> {
    tree::Node {
        id,
        parent,
        order,
        role,
        live: tree::LIVE_OFF,
        states: 0,
        bounds: rect.bounds(),
        value_min: 0,
        value_max: 0,
        value_now: 0,
        sel_anchor: 0,
        sel_focus: 0,
        name,
        value: "",
        description: "",
    }
}

/// How far a batch being written has got, and whether every record so far
/// fitted.
struct Batch {
    at: usize,
    whole: bool,
}

impl Batch {
    /// The part of `out` not yet written.
    fn rest<'a>(&self, out: &'a mut [u8; OUT_BYTES]) -> &'a mut [u8] {
        out.get_mut(self.at..).unwrap_or(&mut [])
    }

    fn took(&mut self, written: Option<usize>) {
        match written {
            Some(n) => self.at += n,
            None => self.whole = false,
        }
    }
}

/// Write the batch owed into `s.out`: the whole tree, or the nodes a change
/// can touch, then the focus and APPLY.
fn stage_tree(s: &mut State, whole: bool) {
    s.revision = s.revision.wrapping_add(1);
    let mut status = [0u8; 20];
    let status_len = status_text(s.ui.presses, &mut status);
    let status_name = status
        .get(..status_len)
        .and_then(abi::wire::utf8_text::text)
        .unwrap_or("");

    let editable = tree::STATE_FOCUSABLE | tree::STATE_EDITABLE | tree::STATE_SELECTION;
    let field = tree::Node {
        states: editable,
        sel_anchor: u32::from(s.ui.field.anchor),
        sel_focus: u32::from(s.ui.field.focus),
        value: s.ui.field.text(),
        ..plain_node(FIELD, ROOT, 0, tree::ROLE_TEXTBOX, &FIELD_RECT, "Message")
    };
    let button = tree::Node {
        states: tree::STATE_FOCUSABLE,
        ..plain_node(BUTTON, ROOT, 1, tree::ROLE_BUTTON, &BUTTON_RECT, "Send")
    };
    let status_node = tree::Node {
        live: tree::LIVE_POLITE,
        ..plain_node(
            STATUS,
            ROOT,
            2,
            tree::ROLE_STATUS,
            &STATUS_RECT,
            status_name,
        )
    };
    // A secret node carries no value: its length stands in for it.
    let secret = tree::Node {
        states: editable | tree::STATE_SECRET,
        value_now: s.ui.secret.scalars() as i32,
        sel_anchor: u32::from(s.ui.secret.anchor),
        sel_focus: u32::from(s.ui.secret.focus),
        ..plain_node(
            SECRET,
            ROOT,
            3,
            tree::ROLE_TEXTBOX,
            &SECRET_RECT,
            "Passcode",
        )
    };
    let root = plain_node(
        ROOT,
        tree::NO_NODE,
        0,
        tree::ROLE_GROUP,
        &ROOT_RECT,
        "Fixture",
    );

    let out = &mut s.out;
    let mut batch = Batch { at: 0, whole: true };
    if whole {
        batch.took(tree::write_tree(batch.rest(out)));
        batch.took(tree::write_node(batch.rest(out), &root));
        batch.took(tree::write_node(batch.rest(out), &button));
    }
    batch.took(tree::write_node(batch.rest(out), &field));
    batch.took(tree::write_node(batch.rest(out), &status_node));
    batch.took(tree::write_node(batch.rest(out), &secret));
    batch.took(tree::write_focus(batch.rest(out), s.ui.focus));
    batch.took(tree::write_apply(batch.rest(out), s.revision));
    // Every node with a full field fits `OUT_BYTES`; a batch that did not
    // would be sent as nothing rather than in part.
    s.out_len = if batch.whole { batch.at as u16 } else { 0 };
    s.out_sent = 0;
}

unsafe fn send_tree(s: &mut State, sys: &SyscallTable) {
    loop {
        while s.out_sent < s.out_len {
            let room = dev_channel_writable(sys, s.tree);
            if room <= 0 {
                return;
            }
            let n = ((s.out_len - s.out_sent) as usize).min(room as usize);
            let from = s.out.as_ptr().add(s.out_sent as usize);
            if (sys.channel_write)(s.tree, from, n) != n as i32 {
                return;
            }
            s.out_sent += n as u16;
        }
        // The batch is out whole; stage what is owed next.
        if s.ui.owe_whole {
            s.ui.owe_whole = false;
            s.ui.owe_change = false;
            stage_tree(s, true);
        } else if s.ui.owe_change {
            s.ui.owe_change = false;
            stage_tree(s, false);
        } else {
            return;
        }
        if s.out_len == 0 {
            return;
        }
    }
}

// ── The picture ──────────────────────────────────────────────────────

fn fill(row: &mut [u8; ROW_BYTES], from: u16, to: u16, colour: u16) {
    let c = colour.to_le_bytes();
    let (from, to) = (from.min(WIDTH) as usize, to.min(WIDTH) as usize);
    let span = row.get_mut(from * 2..to.max(from) * 2).unwrap_or(&mut []);
    for px in span.chunks_exact_mut(2) {
        if let [lo, hi] = px {
            *lo = c[0];
            *hi = c[1];
        }
    }
}

/// One control's part of row `y`: a border, an inside, and a bar of
/// `bar` pixels in `bar_colour` across its middle rows.
fn paint_control(
    row: &mut [u8; ROW_BYTES],
    y: u16,
    r: &Rect,
    focused: bool,
    inside: u16,
    bar: u16,
    bar_colour: u16,
) {
    if y < r.y || y >= r.y + r.h {
        return;
    }
    let border = if focused { BORDER_FOCUSED } else { BORDER };
    let edge = y < r.y + 2 || y >= r.y + r.h - 2;
    fill(row, r.x, r.x + r.w, border);
    if edge {
        return;
    }
    fill(row, r.x + 2, r.x + r.w - 2, inside);
    if y >= r.y + 8 && y < r.y + r.h - 8 {
        let room = r.w - 12;
        fill(row, r.x + 6, r.x + 6 + bar.min(room), bar_colour);
    }
}

fn paint_row(s: &Ui, y: u16, row: &mut [u8; ROW_BYTES]) {
    fill(row, 0, WIDTH, BACKGROUND);
    paint_control(
        row,
        y,
        &FIELD_RECT,
        s.focus == FIELD,
        INSIDE,
        (s.field.scalars() as u16).saturating_mul(BAR_STEP),
        TEXT_BAR,
    );
    let button = if s.presses % 2 == 1 {
        BUTTON_PRESSED
    } else {
        BUTTON_REST
    };
    paint_control(row, y, &BUTTON_RECT, s.focus == BUTTON, button, 0, button);
    paint_control(
        row,
        y,
        &SECRET_RECT,
        s.focus == SECRET,
        INSIDE,
        (s.secret.scalars() as u16).saturating_mul(BAR_STEP),
        SECRET_BAR,
    );
}

/// Send the frame being painted a band at a time: a region header, then
/// the band's rows. Each write is whole or not made, and the frame resumes
/// where the channel stopped taking it.
unsafe fn send_frame(s: &mut State, sys: &SyscallTable) {
    loop {
        if !s.painting {
            if !s.ui.owe_frame {
                return;
            }
            s.ui.owe_frame = false;
            s.painting = true;
            s.band = 0;
            s.row = 0;
            s.header_sent = false;
        }
        let y0 = s.band * BAND_ROWS;
        if !s.header_sent {
            let last = y0 + BAND_ROWS >= HEIGHT;
            let header = raster::Header {
                surface_w: WIDTH,
                surface_h: HEIGHT,
                format: raster::FORMAT_RGB565,
                flags: if last { raster::FLAG_LAST } else { 0 },
                x: 0,
                y: y0,
                w: WIDTH,
                h: BAND_ROWS,
            };
            let Ok(bytes) = header.encode() else {
                s.painting = false;
                return;
            };
            if dev_channel_writable(sys, s.pixels) < bytes.len() as i32
                || (sys.channel_write)(s.pixels, bytes.as_ptr(), bytes.len()) != bytes.len() as i32
            {
                return;
            }
            s.header_sent = true;
        }
        while s.row < BAND_ROWS {
            if dev_channel_writable(sys, s.pixels) < ROW_BYTES as i32 {
                return;
            }
            let mut row = [0u8; ROW_BYTES];
            paint_row(&s.ui, y0 + s.row, &mut row);
            if (sys.channel_write)(s.pixels, row.as_ptr(), ROW_BYTES) != ROW_BYTES as i32 {
                return;
            }
            s.row += 1;
        }
        s.band += 1;
        s.row = 0;
        s.header_sent = false;
        if s.band * BAND_ROWS >= HEIGHT {
            s.painting = false;
        }
    }
}

// ── Module entry points ──────────────────────────────────────────────

/// # Safety
/// Kernel module-ABI entry point: `state` is the loader-owned instance block
/// of `state_size` bytes and `syscalls` the kernel's syscall table.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub unsafe extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    if syscalls.is_null() || state.is_null() {
        return abi::errno::EINVAL;
    }
    if state_size < core::mem::size_of::<State>() {
        return abi::errno::ENOMEM;
    }
    core::ptr::write_bytes(state, 0, core::mem::size_of::<State>());
    let s = &mut *(state as *mut State);
    s.syscalls = syscalls as *const SyscallTable;
    let sys = &*s.syscalls;
    s.actions = in_chan;
    s.text = dev_channel_port(sys, 0, 1);
    s.keys = dev_channel_port(sys, 0, 2);
    s.pointer = dev_channel_port(sys, 0, 3);
    s.tree = out_chan;
    s.pixels = dev_channel_port(sys, 1, 1);
    s.ui.focus = tree::NO_NODE;
    // The whole tree and a first frame are sent unasked.
    s.ui.owe_whole = true;
    s.ui.owe_frame = true;
    0
}

/// # Safety
/// Kernel module-ABI entry point: `state` is the instance block this module's
/// `module_new` initialised, live and exclusively this module's for the call.
#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> StepReturn {
    let s = &mut *(state as *mut State);
    let sys = &*s.syscalls;
    if s.actions >= 0 {
        read_actions(s, sys);
    }
    if s.text >= 0 {
        read_text(s, sys);
    }
    if s.keys >= 0 {
        read_keys(s, sys);
    }
    if s.pointer >= 0 {
        read_pointer(s, sys);
    }
    if s.tree >= 0 {
        send_tree(s, sys);
    }
    if s.pixels >= 0 {
        send_frame(s, sys);
    }
    StepReturn::Continue
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

fluxor_rt::wasm_entry!();
