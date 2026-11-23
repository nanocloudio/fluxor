// Contract: accessibility — the tree an application that draws its own
// controls publishes so assistive technology can reach them (the
// `AccessibilityTree` content type), and what a platform mirror sends back
// (the `AccessibilityActions` content type).
//
// Layer: contracts (public, stable).
//
// TREE RECORDS (application → platform). Every record, little-endian:
//
//   [0]     msg    MSG_*
//   [1]     flags  zero
//   [2..4]  len    u16  payload bytes
//
//   TREE      len 0          the batch replaces the whole tree
//   NODE      len 60 + n     the fixed part below, then name, value and
//                            description, UTF-8, back to back
//   REMOVE    len 4          [id u32]: the node and its subtree
//   FOCUS     len 4          [id u32]: NO_NODE when nothing is focused
//   ANNOUNCE  len 4 + n      [politeness u8][0;3] then UTF-8 text,
//                            1..=ANNOUNCE_MAX bytes
//   APPLY     len 4          [revision u32]
//
// Records between two APPLYs form one batch, applied in order and
// atomically: a mirror changes what it presents once per APPLY, or not at
// all. `revision` is the application's own counter, echoed in `RESYNC`.
//
// NODE fixed part (an upsert by `id`; a changed `parent` moves the node and
// its subtree):
//
//   [0..4]    id          u32  the application's identity for the control
//   [4..8]    parent      u32  NO_NODE for a root
//   [8..10]   order       u16  sort key among the parent's children (ties
//                              by id)
//   [10]      role        u8   ROLE_*: position in `vocabulary::ACCESS_ROLES`
//   [11]      live        u8   LIVE_OFF | LIVE_POLITE | LIVE_ASSERTIVE
//   [12..16]  states      u32  STATE_* bits
//   [16..32]  bounds      x, y, w, h: i32 each, 1/64 surface pixel
//   [32..36]  value_min   i32  valid with STATE_RANGE
//   [36..40]  value_max   i32
//   [40..44]  value_now   i32  STATE_RANGE: the value; ROLE_HEADING: the
//                              level 1..=6; STATE_SECRET: the value's
//                              length in scalar values
//   [44..48]  sel_anchor  u32  scalar offsets into value; valid with
//   [48..52]  sel_focus   u32  STATE_SELECTION
//   [52..54]  name_len    u16  at most NAME_MAX
//   [54..56]  value_len   u16  at most VALUE_MAX
//   [56..58]  desc_len    u16  at most DESC_MAX
//   [58..60]  0           u16
//
// For a range node, `value` is the spoken text of the value ("50%"). An
// editable node's value longer than VALUE_MAX is published as the window of
// it around the caret; the node's offsets, and `input::text` offsets for it,
// are into that window.
//
// SECRETS. A `STATE_SECRET` node's `value` is empty, always: the secret
// never enters the tree. Its `value_now` carries the value's length in
// scalar values, so offsets, deletion and a spoken character count work.
//
// ACTION RECORDS (platform → application). Fixed 12 bytes:
//
//   [0]      msg   ACTION_*
//   [1]      0
//   [2..4]   len   u16 = 8
//   [4..8]   id    u32
//   [8..12]  arg   i32
//
//   ACTIVATE   the node; 0. Assistive technology's "press".
//   FOCUS      the node focus moved to, or NO_NODE when it left the
//              surface; 0.
//   SET_VALUE  the node; the new `value_now`.
//   RESYNC     NO_NODE; the last applied `revision`, 0 if none. The mirror
//              has no tree it trusts: at its start, and after it rejects a
//              batch. The application answers with TREE, every node, FOCUS,
//              APPLY.
//
// KEYS ARE NEVER ACTIONS. Every keyboard key reaches the application as a
// key record; an action carries only what assistive technology or a pointer
// does to a mirrored control. Text edits arrive on `TextEvents` with the
// node as `target`.
//
// WHAT IS CHECKED HERE is each record alone: lengths, string limits, UTF-8,
// the role, state and reserved bytes, an empty secret. What needs the whole
// tree (an unknown parent at APPLY, a cycle, the node ceiling) is the
// consumer's check over a batch.

use crate::wire::utf8_text;

/// Bytes of a tree record's header (`msg`, `flags`, `len`).
pub const HEADER: usize = 4;
/// Bytes of a NODE's fixed part.
pub const NODE_FIXED: usize = 60;

/// Tree messages.
pub const MSG_TREE: u8 = 0x01;
pub const MSG_NODE: u8 = 0x02;
pub const MSG_REMOVE: u8 = 0x03;
pub const MSG_FOCUS: u8 = 0x04;
pub const MSG_ANNOUNCE: u8 = 0x05;
pub const MSG_APPLY: u8 = 0x06;

/// String limits, in bytes.
pub const NAME_MAX: usize = 1024;
pub const VALUE_MAX: usize = 16_384;
pub const DESC_MAX: usize = 1024;
pub const ANNOUNCE_MAX: usize = 1024;

/// The largest `len` of a tree record: a NODE with every string at its limit.
pub const MAX_LEN: usize = NODE_FIXED + NAME_MAX + VALUE_MAX + DESC_MAX;
/// The largest whole tree record, which is what a consumer's carry buffer
/// holds.
pub const MAX_RECORD: usize = HEADER + MAX_LEN;

/// No node: a root's `parent`, a FOCUS on nothing.
pub const NO_NODE: u32 = u32::MAX;

/// NODE fixed-part offsets, from the start of the payload.
pub const OFF_ID: usize = 0;
pub const OFF_PARENT: usize = 4;
pub const OFF_ORDER: usize = 8;
pub const OFF_ROLE: usize = 10;
pub const OFF_LIVE: usize = 11;
pub const OFF_STATES: usize = 12;
pub const OFF_BOUNDS: usize = 16;
pub const OFF_VALUE_MIN: usize = 32;
pub const OFF_VALUE_MAX: usize = 36;
pub const OFF_VALUE_NOW: usize = 40;
pub const OFF_SEL_ANCHOR: usize = 44;
pub const OFF_SEL_FOCUS: usize = 48;
pub const OFF_NAME_LEN: usize = 52;
pub const OFF_VALUE_LEN: usize = 54;
pub const OFF_DESC_LEN: usize = 56;
pub const OFF_NODE_RESERVED: usize = 58;

/// Live-region politeness (`live`, and an ANNOUNCE's `politeness`).
pub const LIVE_OFF: u8 = 0;
pub const LIVE_POLITE: u8 = 1;
pub const LIVE_ASSERTIVE: u8 = 2;

/// Roles: positions in `vocabulary::ACCESS_ROLES`, each the ARIA 1.2 role
/// of the same name.
pub const ROLE_GENERIC: u8 = 0;
pub const ROLE_BUTTON: u8 = 1;
pub const ROLE_CHECKBOX: u8 = 2;
pub const ROLE_RADIO: u8 = 3;
pub const ROLE_RADIOGROUP: u8 = 4;
pub const ROLE_SWITCH: u8 = 5;
pub const ROLE_SLIDER: u8 = 6;
pub const ROLE_SPINBUTTON: u8 = 7;
pub const ROLE_TEXTBOX: u8 = 8;
pub const ROLE_SEARCHBOX: u8 = 9;
pub const ROLE_COMBOBOX: u8 = 10;
pub const ROLE_LISTBOX: u8 = 11;
pub const ROLE_OPTION: u8 = 12;
pub const ROLE_LINK: u8 = 13;
pub const ROLE_HEADING: u8 = 14;
pub const ROLE_PARAGRAPH: u8 = 15;
pub const ROLE_LIST: u8 = 16;
pub const ROLE_LISTITEM: u8 = 17;
pub const ROLE_IMG: u8 = 18;
pub const ROLE_GROUP: u8 = 19;
pub const ROLE_REGION: u8 = 20;
pub const ROLE_DIALOG: u8 = 21;
pub const ROLE_ALERTDIALOG: u8 = 22;
pub const ROLE_ALERT: u8 = 23;
pub const ROLE_STATUS: u8 = 24;
pub const ROLE_MENU: u8 = 25;
pub const ROLE_MENUBAR: u8 = 26;
pub const ROLE_MENUITEM: u8 = 27;
pub const ROLE_MENUITEMCHECKBOX: u8 = 28;
pub const ROLE_MENUITEMRADIO: u8 = 29;
pub const ROLE_TAB: u8 = 30;
pub const ROLE_TABLIST: u8 = 31;
pub const ROLE_TABPANEL: u8 = 32;
pub const ROLE_PROGRESSBAR: u8 = 33;
pub const ROLE_METER: u8 = 34;
pub const ROLE_TOOLBAR: u8 = 35;
pub const ROLE_SEPARATOR: u8 = 36;
pub const ROLE_SCROLLBAR: u8 = 37;
pub const ROLE_TABLE: u8 = 38;
pub const ROLE_ROW: u8 = 39;
pub const ROLE_CELL: u8 = 40;
pub const ROLE_COLUMNHEADER: u8 = 41;
pub const ROLE_ROWHEADER: u8 = 42;
pub const ROLE_GRID: u8 = 43;
pub const ROLE_GRIDCELL: u8 = 44;
pub const ROLE_TREE: u8 = 45;
pub const ROLE_TREEITEM: u8 = 46;
/// Number of allocated role bytes.
pub const ROLE_COUNT: u8 = 47;

/// State bits: 0x1 for the first, doubling to 0x4_0000 for the last.
pub const STATE_FOCUSABLE: u32 = 1 << 0;
pub const STATE_DISABLED: u32 = 1 << 1;
pub const STATE_CHECKED: u32 = 1 << 2;
pub const STATE_MIXED: u32 = 1 << 3;
pub const STATE_PRESSED: u32 = 1 << 4;
pub const STATE_EXPANDED: u32 = 1 << 5;
pub const STATE_COLLAPSIBLE: u32 = 1 << 6;
pub const STATE_SELECTED: u32 = 1 << 7;
pub const STATE_READONLY: u32 = 1 << 8;
pub const STATE_REQUIRED: u32 = 1 << 9;
pub const STATE_INVALID: u32 = 1 << 10;
pub const STATE_MULTILINE: u32 = 1 << 11;
pub const STATE_BUSY: u32 = 1 << 12;
pub const STATE_MODAL: u32 = 1 << 13;
pub const STATE_SECRET: u32 = 1 << 14;
pub const STATE_EDITABLE: u32 = 1 << 15;
pub const STATE_MULTISELECTABLE: u32 = 1 << 16;
pub const STATE_RANGE: u32 = 1 << 17;
pub const STATE_SELECTION: u32 = 1 << 18;
/// Every allocated state bit.
pub const STATES_KNOWN: u32 = (1 << 19) - 1;

/// A node's bounds, 1/64 surface pixel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bounds {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

/// One NODE, borrowing its strings from the read buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node<'a> {
    pub id: u32,
    pub parent: u32,
    pub order: u16,
    pub role: u8,
    pub live: u8,
    pub states: u32,
    pub bounds: Bounds,
    pub value_min: i32,
    pub value_max: i32,
    pub value_now: i32,
    pub sel_anchor: u32,
    pub sel_focus: u32,
    pub name: &'a str,
    pub value: &'a str,
    pub description: &'a str,
}

impl Node<'_> {
    /// Whether this node is one the contract admits: an id and a parent
    /// that can name a node, a known role, politeness and state bits,
    /// strings within their limits, and no value on a secret.
    pub fn is_valid(&self) -> bool {
        self.id != NO_NODE
            && self.parent != self.id
            && self.role < ROLE_COUNT
            && self.live <= LIVE_ASSERTIVE
            && self.states & !STATES_KNOWN == 0
            && self.name.len() <= NAME_MAX
            && self.value.len() <= VALUE_MAX
            && self.description.len() <= DESC_MAX
            && (self.states & STATE_SECRET == 0 || self.value.is_empty())
    }
}

/// One tree record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Record<'a> {
    Tree,
    Node(Node<'a>),
    Remove { id: u32 },
    Focus { id: u32 },
    Announce { politeness: u8, text: &'a str },
    Apply { revision: u32 },
}

/// Why a tree record is refused. Any fault rejects the whole batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// A `msg` byte outside `MSG_*`.
    UnknownMsg,
    /// A non-zero flags or reserved byte.
    Reserved,
    /// A `len` past `MAX_LEN`: the record boundary is lost.
    Oversize,
    /// A `len` the message cannot have, or a NODE whose strings do not fill
    /// its payload exactly.
    BadLen,
    /// A string past its limit.
    StringLimit,
    /// A string that is not UTF-8.
    BadText,
    /// A role past `ROLE_COUNT`.
    BadRole,
    /// An unallocated state bit, or a politeness outside `LIVE_*`.
    BadState,
    /// A node whose id is `NO_NODE`, or that names itself as its parent;
    /// a REMOVE of `NO_NODE`.
    BadId,
    /// A `STATE_SECRET` node carrying a value.
    SecretValue,
}

/// The outcome of `parse`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parse<'a> {
    /// A whole record, and how many bytes of the buffer it occupied.
    Record { record: Record<'a>, consumed: usize },
    /// The buffer ends inside a record; read more and call again.
    NeedMore,
    /// A refused record. `skip` is its whole length; zero when the boundary
    /// is lost (`Oversize`).
    Fault { fault: Fault, skip: usize },
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn i32_at(b: &[u8], at: usize) -> i32 {
    u32_at(b, at) as i32
}

fn text(s: &[u8]) -> Result<&str, Fault> {
    utf8_text::text(s).ok_or(Fault::BadText)
}

fn parse_node(p: &[u8]) -> Result<Node<'_>, Fault> {
    if p.len() < NODE_FIXED {
        return Err(Fault::BadLen);
    }
    if u16_at(p, OFF_NODE_RESERVED) != 0 {
        return Err(Fault::Reserved);
    }
    let name_len = u16_at(p, OFF_NAME_LEN) as usize;
    let value_len = u16_at(p, OFF_VALUE_LEN) as usize;
    let desc_len = u16_at(p, OFF_DESC_LEN) as usize;
    if name_len > NAME_MAX || value_len > VALUE_MAX || desc_len > DESC_MAX {
        return Err(Fault::StringLimit);
    }
    if p.len() != NODE_FIXED + name_len + value_len + desc_len {
        return Err(Fault::BadLen);
    }
    let id = u32_at(p, OFF_ID);
    let parent = u32_at(p, OFF_PARENT);
    if id == NO_NODE || parent == id {
        return Err(Fault::BadId);
    }
    let role = p[OFF_ROLE];
    if role >= ROLE_COUNT {
        return Err(Fault::BadRole);
    }
    let live = p[OFF_LIVE];
    let states = u32_at(p, OFF_STATES);
    if live > LIVE_ASSERTIVE || states & !STATES_KNOWN != 0 {
        return Err(Fault::BadState);
    }
    if states & STATE_SECRET != 0 && value_len != 0 {
        return Err(Fault::SecretValue);
    }
    let v0 = NODE_FIXED + name_len;
    let d0 = v0 + value_len;
    Ok(Node {
        id,
        parent,
        order: u16_at(p, OFF_ORDER),
        role,
        live,
        states,
        bounds: Bounds {
            x: i32_at(p, OFF_BOUNDS),
            y: i32_at(p, OFF_BOUNDS + 4),
            w: i32_at(p, OFF_BOUNDS + 8),
            h: i32_at(p, OFF_BOUNDS + 12),
        },
        value_min: i32_at(p, OFF_VALUE_MIN),
        value_max: i32_at(p, OFF_VALUE_MAX),
        value_now: i32_at(p, OFF_VALUE_NOW),
        sel_anchor: u32_at(p, OFF_SEL_ANCHOR),
        sel_focus: u32_at(p, OFF_SEL_FOCUS),
        name: text(&p[NODE_FIXED..v0])?,
        value: text(&p[v0..d0])?,
        description: text(&p[d0..])?,
    })
}

fn parse_payload(msg: u8, p: &[u8]) -> Result<Record<'_>, Fault> {
    let fixed = |want: usize| {
        if p.len() == want {
            Ok(())
        } else {
            Err(Fault::BadLen)
        }
    };
    Ok(match msg {
        MSG_TREE => {
            fixed(0)?;
            Record::Tree
        }
        MSG_NODE => Record::Node(parse_node(p)?),
        MSG_REMOVE => {
            fixed(4)?;
            let id = u32_at(p, 0);
            if id == NO_NODE {
                return Err(Fault::BadId);
            }
            Record::Remove { id }
        }
        MSG_FOCUS => {
            fixed(4)?;
            Record::Focus { id: u32_at(p, 0) }
        }
        MSG_ANNOUNCE => {
            if p.len() <= 4 {
                return Err(Fault::BadLen);
            }
            if p.len() - 4 > ANNOUNCE_MAX {
                return Err(Fault::StringLimit);
            }
            if p[1] != 0 || p[2] != 0 || p[3] != 0 {
                return Err(Fault::Reserved);
            }
            if !matches!(p[0], LIVE_POLITE | LIVE_ASSERTIVE) {
                return Err(Fault::BadState);
            }
            Record::Announce {
                politeness: p[0],
                text: text(&p[4..])?,
            }
        }
        MSG_APPLY => {
            fixed(4)?;
            Record::Apply {
                revision: u32_at(p, 0),
            }
        }
        _ => return Err(Fault::UnknownMsg),
    })
}

/// Parse the tree record at the front of `buf`.
pub fn parse(buf: &[u8]) -> Parse<'_> {
    if buf.len() < HEADER {
        return Parse::NeedMore;
    }
    let len = u16_at(buf, 2) as usize;
    if len > MAX_LEN {
        return Parse::Fault {
            fault: Fault::Oversize,
            skip: 0,
        };
    }
    let total = HEADER + len;
    if buf.len() < total {
        return Parse::NeedMore;
    }
    if buf[1] != 0 {
        return Parse::Fault {
            fault: Fault::Reserved,
            skip: total,
        };
    }
    match parse_payload(buf[0], &buf[HEADER..total]) {
        Ok(record) => Parse::Record {
            record,
            consumed: total,
        },
        Err(fault) => Parse::Fault { fault, skip: total },
    }
}

fn write_header(out: &mut [u8], msg: u8, len: usize) {
    out[0] = msg;
    out[1] = 0;
    out[2..4].copy_from_slice(&(len as u16).to_le_bytes());
}

fn write_u32(out: &mut [u8], msg: u8, value: u32) -> Option<usize> {
    let out = out.get_mut(..HEADER + 4)?;
    write_header(out, msg, 4);
    out[HEADER..].copy_from_slice(&value.to_le_bytes());
    Some(HEADER + 4)
}

/// Write a TREE record.
pub fn write_tree(out: &mut [u8]) -> Option<usize> {
    let out = out.get_mut(..HEADER)?;
    write_header(out, MSG_TREE, 0);
    Some(HEADER)
}

/// Write a NODE. `None` when `out` is too small or the node is one
/// `Node::is_valid` refuses; never a partial record.
pub fn write_node(out: &mut [u8], node: &Node<'_>) -> Option<usize> {
    if !node.is_valid() {
        return None;
    }
    let len = NODE_FIXED + node.name.len() + node.value.len() + node.description.len();
    let total = HEADER + len;
    let out = out.get_mut(..total)?;
    write_header(out, MSG_NODE, len);
    let p = &mut out[HEADER..];
    p[OFF_ID..OFF_ID + 4].copy_from_slice(&node.id.to_le_bytes());
    p[OFF_PARENT..OFF_PARENT + 4].copy_from_slice(&node.parent.to_le_bytes());
    p[OFF_ORDER..OFF_ORDER + 2].copy_from_slice(&node.order.to_le_bytes());
    p[OFF_ROLE] = node.role;
    p[OFF_LIVE] = node.live;
    p[OFF_STATES..OFF_STATES + 4].copy_from_slice(&node.states.to_le_bytes());
    let b = node.bounds;
    for (i, v) in [b.x, b.y, b.w, b.h].into_iter().enumerate() {
        let at = OFF_BOUNDS + 4 * i;
        p[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    p[OFF_VALUE_MIN..OFF_VALUE_MIN + 4].copy_from_slice(&node.value_min.to_le_bytes());
    p[OFF_VALUE_MAX..OFF_VALUE_MAX + 4].copy_from_slice(&node.value_max.to_le_bytes());
    p[OFF_VALUE_NOW..OFF_VALUE_NOW + 4].copy_from_slice(&node.value_now.to_le_bytes());
    p[OFF_SEL_ANCHOR..OFF_SEL_ANCHOR + 4].copy_from_slice(&node.sel_anchor.to_le_bytes());
    p[OFF_SEL_FOCUS..OFF_SEL_FOCUS + 4].copy_from_slice(&node.sel_focus.to_le_bytes());
    p[OFF_NAME_LEN..OFF_NAME_LEN + 2].copy_from_slice(&(node.name.len() as u16).to_le_bytes());
    p[OFF_VALUE_LEN..OFF_VALUE_LEN + 2].copy_from_slice(&(node.value.len() as u16).to_le_bytes());
    p[OFF_DESC_LEN..OFF_DESC_LEN + 2]
        .copy_from_slice(&(node.description.len() as u16).to_le_bytes());
    p[OFF_NODE_RESERVED] = 0;
    p[OFF_NODE_RESERVED + 1] = 0;
    let v0 = NODE_FIXED + node.name.len();
    let d0 = v0 + node.value.len();
    p[NODE_FIXED..v0].copy_from_slice(node.name.as_bytes());
    p[v0..d0].copy_from_slice(node.value.as_bytes());
    p[d0..].copy_from_slice(node.description.as_bytes());
    Some(total)
}

/// Write a REMOVE. `None` for `NO_NODE`.
pub fn write_remove(out: &mut [u8], id: u32) -> Option<usize> {
    if id == NO_NODE {
        return None;
    }
    write_u32(out, MSG_REMOVE, id)
}

/// Write a FOCUS; `NO_NODE` when nothing is focused.
pub fn write_focus(out: &mut [u8], id: u32) -> Option<usize> {
    write_u32(out, MSG_FOCUS, id)
}

/// Write an ANNOUNCE. `None` when `out` is too small, the politeness is not
/// `LIVE_POLITE` or `LIVE_ASSERTIVE`, or the text is empty or past
/// `ANNOUNCE_MAX`.
pub fn write_announce(out: &mut [u8], politeness: u8, text: &str) -> Option<usize> {
    if !matches!(politeness, LIVE_POLITE | LIVE_ASSERTIVE)
        || text.is_empty()
        || text.len() > ANNOUNCE_MAX
    {
        return None;
    }
    let total = HEADER + 4 + text.len();
    let out = out.get_mut(..total)?;
    write_header(out, MSG_ANNOUNCE, 4 + text.len());
    out[HEADER] = politeness;
    out[HEADER + 1..HEADER + 4].fill(0);
    out[HEADER + 4..].copy_from_slice(text.as_bytes());
    Some(total)
}

/// Write an APPLY.
pub fn write_apply(out: &mut [u8], revision: u32) -> Option<usize> {
    write_u32(out, MSG_APPLY, revision)
}

// ── Actions ──────────────────────────────────────────────────────────

/// Bytes of one action record.
pub const ACTION_SIZE: usize = 12;
/// An action record's `len` field.
pub const ACTION_LEN: u16 = 8;

/// Action record offsets.
pub const OFF_ACTION_MSG: usize = 0;
pub const OFF_ACTION_RESERVED: usize = 1;
pub const OFF_ACTION_LEN: usize = 2;
pub const OFF_ACTION_ID: usize = 4;
pub const OFF_ACTION_ARG: usize = 8;

/// Action messages.
pub const ACTION_ACTIVATE: u8 = 0x01;
pub const ACTION_FOCUS: u8 = 0x02;
pub const ACTION_SET_VALUE: u8 = 0x03;
pub const ACTION_RESYNC: u8 = 0x04;

/// One action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Assistive technology pressed the node.
    Activate { id: u32 },
    /// Focus moved to the node, or left the surface (`NO_NODE`).
    Focus { id: u32 },
    /// Assistive technology set the node's `value_now`.
    SetValue { id: u32, value: i32 },
    /// The mirror has no tree it trusts; `revision` is the last it applied,
    /// 0 if none.
    Resync { revision: u32 },
}

/// Read an action record. `None` for an unknown message, a non-zero
/// reserved byte, a `len` other than `ACTION_LEN`, an ACTIVATE or
/// SET_VALUE naming `NO_NODE`, a non-zero `arg` on ACTIVATE or FOCUS, or a
/// RESYNC naming a node.
pub fn decode_action(b: &[u8; ACTION_SIZE]) -> Option<Action> {
    if b[OFF_ACTION_RESERVED] != 0 || u16_at(b, OFF_ACTION_LEN) != ACTION_LEN {
        return None;
    }
    let id = u32_at(b, OFF_ACTION_ID);
    let arg = i32_at(b, OFF_ACTION_ARG);
    match b[OFF_ACTION_MSG] {
        ACTION_ACTIVATE if id != NO_NODE && arg == 0 => Some(Action::Activate { id }),
        ACTION_FOCUS if arg == 0 => Some(Action::Focus { id }),
        ACTION_SET_VALUE if id != NO_NODE => Some(Action::SetValue { id, value: arg }),
        ACTION_RESYNC if id == NO_NODE => Some(Action::Resync {
            revision: arg as u32,
        }),
        _ => None,
    }
}

/// The record for `action`, or `None` for an ACTIVATE or SET_VALUE naming
/// `NO_NODE`.
pub fn encode_action(action: &Action) -> Option<[u8; ACTION_SIZE]> {
    let (msg, id, arg) = match *action {
        Action::Activate { id } if id != NO_NODE => (ACTION_ACTIVATE, id, 0),
        Action::Focus { id } => (ACTION_FOCUS, id, 0),
        Action::SetValue { id, value } if id != NO_NODE => (ACTION_SET_VALUE, id, value),
        Action::Resync { revision } => (ACTION_RESYNC, NO_NODE, revision as i32),
        _ => return None,
    };
    let mut out = [0u8; ACTION_SIZE];
    out[OFF_ACTION_MSG] = msg;
    out[OFF_ACTION_LEN..OFF_ACTION_LEN + 2].copy_from_slice(&ACTION_LEN.to_le_bytes());
    out[OFF_ACTION_ID..OFF_ACTION_ID + 4].copy_from_slice(&id.to_le_bytes());
    out[OFF_ACTION_ARG..OFF_ACTION_ARG + 4].copy_from_slice(&arg.to_le_bytes());
    Some(out)
}

const _: () = assert!(OFF_ID == 0);
const _: () = assert!(OFF_ID + 4 == OFF_PARENT);
const _: () = assert!(OFF_PARENT + 4 == OFF_ORDER);
const _: () = assert!(OFF_ORDER + 2 == OFF_ROLE);
const _: () = assert!(OFF_ROLE + 1 == OFF_LIVE);
const _: () = assert!(OFF_LIVE + 1 == OFF_STATES);
const _: () = assert!(OFF_STATES + 4 == OFF_BOUNDS);
const _: () = assert!(OFF_BOUNDS + 16 == OFF_VALUE_MIN);
const _: () = assert!(OFF_VALUE_MIN + 4 == OFF_VALUE_MAX);
const _: () = assert!(OFF_VALUE_MAX + 4 == OFF_VALUE_NOW);
const _: () = assert!(OFF_VALUE_NOW + 4 == OFF_SEL_ANCHOR);
const _: () = assert!(OFF_SEL_ANCHOR + 4 == OFF_SEL_FOCUS);
const _: () = assert!(OFF_SEL_FOCUS + 4 == OFF_NAME_LEN);
const _: () = assert!(OFF_NAME_LEN + 2 == OFF_VALUE_LEN);
const _: () = assert!(OFF_VALUE_LEN + 2 == OFF_DESC_LEN);
const _: () = assert!(OFF_DESC_LEN + 2 == OFF_NODE_RESERVED);
const _: () = assert!(OFF_NODE_RESERVED + 2 == NODE_FIXED);
const _: () = assert!(MAX_LEN == 18_492);
const _: () = assert!(MAX_LEN <= u16::MAX as usize);
const _: () = assert!(STATES_KNOWN == STATE_SELECTION * 2 - 1);
const _: () = assert!(ROLE_TREEITEM + 1 == ROLE_COUNT);
const _: () = assert!(OFF_ACTION_MSG == 0);
const _: () = assert!(OFF_ACTION_MSG + 1 == OFF_ACTION_RESERVED);
const _: () = assert!(OFF_ACTION_RESERVED + 1 == OFF_ACTION_LEN);
const _: () = assert!(OFF_ACTION_LEN + 2 == OFF_ACTION_ID);
const _: () = assert!(OFF_ACTION_ID + 4 == OFF_ACTION_ARG);
const _: () = assert!(OFF_ACTION_ARG + 4 == ACTION_SIZE);
const _: () = assert!(OFF_ACTION_ID + ACTION_LEN as usize == ACTION_SIZE);
