//! Where a host window's input method should stand: the focused node of an
//! application's accessibility tree, when that node is editable.
//!
//! A window only composes text while it allows its input method and tells
//! it where the caret is. `ImeTarget` follows an `AccessibilityTree` stream
//! (`abi::contracts::accessibility`) and answers with the focused editable
//! node's bounds in surface pixels, or nothing: with no editable node
//! focused the input method stays off, so an application's keys never feed
//! one.
//!
//! Batches stand or fall whole, by the rules every consumer of the tree
//! applies (`fluxor_sdk::accessibility::TreeCheck`): a rejected batch
//! changes nothing here, and a stream whose record boundary is lost leaves
//! the input method off until a batch that opens with `TREE` is applied.

use std::collections::HashMap;

use crate::abi::contracts::accessibility::{self as tree, Bounds, Record, NO_NODE};
use fluxor_sdk::accessibility::{Entry, Outcome, Step, TreeCheck};

/// The largest tree followed: the `max_nodes` fact of the display's `tree`
/// input.
pub const MAX_NODES: usize = 1024;

/// An editable node's place: a rectangle in surface pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Area {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    /// The node is a secret field: an input method must not learn or
    /// predict from what is typed.
    pub secret: bool,
}

/// What a batch has changed so far.
enum Change {
    Tree,
    Node {
        id: u32,
        states: u32,
        bounds: Bounds,
    },
    Focus(u32),
}

/// The follower of one tree stream.
pub struct ImeTarget {
    check: TreeCheck<'static>,
    /// Bytes read and not yet parsed into a whole record.
    carry: Vec<u8>,
    /// The applied tree's nodes: states and bounds.
    nodes: HashMap<u32, (u32, Bounds)>,
    focus: u32,
    /// The batch arriving.
    staged: Vec<Change>,
    /// Whether the applied tree is one to act on.
    trusted: bool,
    /// Whether the batch arriving began with `TREE`.
    batch_replaces: bool,
    batch_open: bool,
    rejected: u32,
}

impl Default for ImeTarget {
    fn default() -> Self {
        Self::new()
    }
}

impl ImeTarget {
    pub fn new() -> Self {
        // One pair of tables for the life of the process, as the display
        // instance that owns this follower lives.
        let live = Box::leak(vec![Entry::EMPTY; MAX_NODES].into_boxed_slice());
        let next = Box::leak(vec![Entry::EMPTY; MAX_NODES].into_boxed_slice());
        Self {
            check: TreeCheck::new(live, next),
            carry: Vec::new(),
            nodes: HashMap::new(),
            focus: NO_NODE,
            staged: Vec::new(),
            trusted: false,
            batch_replaces: false,
            batch_open: false,
            rejected: 0,
        }
    }

    /// Batches rejected, and stream boundaries lost.
    pub fn rejected(&self) -> u32 {
        self.rejected
    }

    /// The focused node's place when it is editable.
    pub fn area(&self) -> Option<Area> {
        if !self.trusted {
            return None;
        }
        let (states, bounds) = self.nodes.get(&self.focus)?;
        if states & tree::STATE_EDITABLE == 0 || states & tree::STATE_DISABLED != 0 {
            return None;
        }
        // Bounds are in 1/64 surface pixel.
        Some(Area {
            x: bounds.x >> 6,
            y: bounds.y >> 6,
            w: (bounds.w >> 6).max(1),
            h: (bounds.h >> 6).max(1),
            secret: states & tree::STATE_SECRET != 0,
        })
    }

    /// Take the next bytes of the tree stream.
    pub fn feed(&mut self, bytes: &[u8]) {
        let mut carry = std::mem::take(&mut self.carry);
        carry.extend_from_slice(bytes);
        let mut at = 0;
        loop {
            let rest = &carry[at..];
            match self.check.push(rest) {
                Step::NeedMore => break,
                Step::Lost => {
                    self.staged.clear();
                    self.batch_open = false;
                    self.trusted = false;
                    self.rejected = self.rejected.wrapping_add(1);
                    at = carry.len();
                    break;
                }
                Step::Record { consumed, outcome } => {
                    // The check keeps ids and parents; the fields the
                    // input method needs are read from the record again.
                    if let tree::Parse::Record { record, .. } = tree::parse(rest) {
                        self.stage(&record);
                    }
                    match outcome {
                        Outcome::Pending => {}
                        Outcome::Applied { .. } => self.apply(),
                        Outcome::Rejected { .. } => {
                            self.staged.clear();
                            self.batch_open = false;
                            self.rejected = self.rejected.wrapping_add(1);
                        }
                    }
                    at += consumed;
                }
            }
        }
        carry.drain(..at);
        self.carry = carry;
    }

    fn stage(&mut self, record: &Record<'_>) {
        if !self.batch_open {
            self.batch_open = true;
            self.batch_replaces = matches!(record, Record::Tree);
        }
        match record {
            Record::Tree => self.staged.push(Change::Tree),
            Record::Node(node) => self.staged.push(Change::Node {
                id: node.id,
                states: node.states,
                bounds: node.bounds,
            }),
            Record::Focus { id } => self.staged.push(Change::Focus(*id)),
            Record::Remove { .. } | Record::Announce { .. } | Record::Apply { .. } => {}
        }
    }

    fn apply(&mut self) {
        self.batch_open = false;
        // A batch that does not replace the tree only stands on a tree
        // that is itself trusted.
        if !self.trusted && !self.batch_replaces {
            self.staged.clear();
            return;
        }
        for change in self.staged.drain(..) {
            match change {
                Change::Tree => self.nodes.clear(),
                Change::Node { id, states, bounds } => {
                    self.nodes.insert(id, (states, bounds));
                }
                Change::Focus(id) => self.focus = id,
            }
        }
        // Removed nodes and their subtrees are the check's to know.
        let check = &self.check;
        self.nodes.retain(|id, _| check.contains(*id));
        self.trusted = true;
    }
}
