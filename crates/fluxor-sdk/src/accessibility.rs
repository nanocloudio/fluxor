//! The whole-tree rules of the accessibility contract
//! (`fluxor_abi::contracts::accessibility`): what a mirror checks over a
//! batch before it changes anything it presents.
//!
//! The contract's `parse` checks a record alone. `TreeCheck` holds the ids
//! and parents of the tree a mirror presents and applies each batch to a
//! working copy: at APPLY the batch stands only if every node's parent is a
//! node, no node is its own ancestor and the tree is within the mirror's
//! node ceiling. A batch that fails, or that held a record `parse` refused,
//! is rejected whole and the tree stays as the last APPLY left it.

use fluxor_abi::contracts::accessibility::{parse, Fault, Parse, Record, NO_NODE};

/// One node of a `TreeCheck` table.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    id: u32,
    parent: u32,
}

impl Entry {
    /// An empty slot, to build the tables a `TreeCheck` borrows.
    pub const EMPTY: Entry = Entry {
        id: NO_NODE,
        parent: NO_NODE,
    };
}

/// Why a batch is rejected.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// A record of the batch was refused by the contract's `parse`.
    Record(Fault),
    /// More nodes than the mirror holds.
    TooManyNodes,
    /// At APPLY, a node names a parent that is not in the tree.
    UnknownParent,
    /// At APPLY, a node is its own ancestor.
    Cycle,
}

/// What a record did.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The batch continues.
    Pending,
    /// APPLY: the batch stands and the tree is as it left it.
    Applied { revision: u32 },
    /// APPLY: the batch is rejected and the tree is as the last applied
    /// batch left it. The mirror asks for a RESYNC.
    Rejected { revision: u32, reason: Reason },
}

/// What `TreeCheck::push` found at the front of a buffer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The buffer ends inside a record: read more.
    NeedMore,
    /// A record of `consumed` bytes, and what it did.
    Record { consumed: usize, outcome: Outcome },
    /// The record boundary is lost (a length past the contract's largest):
    /// the mirror drops what it has buffered and asks for a RESYNC.
    Lost,
}

/// The tree a mirror presents, as ids and parents, and the batch arriving.
pub struct TreeCheck<'t> {
    live: &'t mut [Entry],
    next: &'t mut [Entry],
    live_len: usize,
    next_len: usize,
    failed: Option<Reason>,
    revision: Option<u32>,
}

/// Where `id` is in `table`, which is sorted by id, or where it would go.
fn find(table: &[Entry], id: u32) -> Result<usize, usize> {
    let (mut lo, mut hi) = (0usize, table.len());
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        match table.get(mid) {
            Some(e) if e.id == id => return Ok(mid),
            Some(e) if e.id < id => lo = mid + 1,
            _ => hi = mid,
        }
    }
    Err(lo)
}

impl<'t> TreeCheck<'t> {
    /// A check over two tables of the mirror's node ceiling (the shorter
    /// one's length is the ceiling). The tree starts empty.
    pub fn new(live: &'t mut [Entry], next: &'t mut [Entry]) -> Self {
        TreeCheck {
            live,
            next,
            live_len: 0,
            next_len: 0,
            failed: None,
            revision: None,
        }
    }

    /// The most nodes a tree may hold.
    pub fn max_nodes(&self) -> usize {
        self.live.len().min(self.next.len())
    }

    /// Nodes in the applied tree.
    pub fn len(&self) -> usize {
        self.live_len
    }

    pub fn is_empty(&self) -> bool {
        self.live_len == 0
    }

    /// Whether the applied tree holds node `id`.
    pub fn contains(&self, id: u32) -> bool {
        self.live
            .get(..self.live_len)
            .is_some_and(|t| find(t, id).is_ok())
    }

    /// The applied tree's parent of node `id`: `NO_NODE` for a root, `None`
    /// when the tree has no such node.
    pub fn parent(&self, id: u32) -> Option<u32> {
        let table = self.live.get(..self.live_len)?;
        let at = find(table, id).ok()?;
        table.get(at).map(|e| e.parent)
    }

    /// The revision of the last applied batch.
    pub fn revision(&self) -> Option<u32> {
        self.revision
    }

    /// Whether the batch arriving has already failed.
    pub fn failing(&self) -> bool {
        self.failed.is_some()
    }

    /// Parse the record at the front of `buf` and apply it. A record
    /// `parse` refuses fails the batch and is stepped over.
    pub fn push(&mut self, buf: &[u8]) -> Step {
        match parse(buf) {
            Parse::NeedMore => Step::NeedMore,
            Parse::Record { record, consumed } => Step::Record {
                consumed,
                outcome: self.record(&record),
            },
            Parse::Fault { skip: 0, .. } => {
                self.abandon();
                Step::Lost
            }
            Parse::Fault { fault, skip } => {
                self.refuse(fault);
                Step::Record {
                    consumed: skip,
                    outcome: Outcome::Pending,
                }
            }
        }
    }

    /// Fail the batch arriving: one of its records was refused.
    pub fn refuse(&mut self, fault: Fault) {
        self.fail(Reason::Record(fault));
    }

    /// Drop the batch arriving; the applied tree stays.
    pub fn abandon(&mut self) {
        self.failed = None;
        self.restore();
    }

    fn fail(&mut self, reason: Reason) {
        if self.failed.is_none() {
            self.failed = Some(reason);
        }
    }

    /// The working copy becomes the applied tree again.
    fn restore(&mut self) {
        let n = self.live_len.min(self.max_nodes());
        if let (Some(dst), Some(src)) = (self.next.get_mut(..n), self.live.get(..n)) {
            for (d, s) in dst.iter_mut().zip(src) {
                *d = *s;
            }
        }
        self.next_len = n;
    }

    /// Apply one parsed record to the batch arriving.
    pub fn record(&mut self, record: &Record<'_>) -> Outcome {
        match record {
            Record::Apply { revision } => return self.apply(*revision),
            _ if self.failed.is_some() => {}
            Record::Tree => self.next_len = 0,
            Record::Node(node) => {
                if node.is_valid() {
                    self.upsert(node.id, node.parent);
                } else {
                    self.fail(Reason::Record(Fault::BadId));
                }
            }
            Record::Remove { id } => self.remove(*id),
            Record::Focus { .. } | Record::Announce { .. } => {}
        }
        Outcome::Pending
    }

    fn upsert(&mut self, id: u32, parent: u32) {
        let len = self.next_len;
        let Some(table) = self.next.get_mut(..len) else {
            return;
        };
        match find(table, id) {
            Ok(at) => {
                if let Some(e) = table.get_mut(at) {
                    e.parent = parent;
                }
            }
            Err(at) => {
                if len >= self.max_nodes() {
                    self.fail(Reason::TooManyNodes);
                    return;
                }
                let mut i = len;
                while i > at {
                    self.next[i] = self.next[i - 1];
                    i -= 1;
                }
                self.next[at] = Entry { id, parent };
                self.next_len = len + 1;
            }
        }
    }

    /// Remove node `id` and every node under it. A removed node is marked
    /// by naming itself as its parent, which no node of the tree does;
    /// nodes whose parent is marked are marked until none is left, and the
    /// marked nodes are then closed over.
    fn remove(&mut self, id: u32) {
        let len = self.next_len;
        let Some(table) = self.next.get_mut(..len) else {
            return;
        };
        let Ok(at) = find(table, id) else {
            return;
        };
        table[at].parent = id;
        loop {
            let mut marked = false;
            for i in 0..len {
                let e = table[i];
                if e.parent == e.id || e.parent == NO_NODE {
                    continue;
                }
                let gone = find(table, e.parent)
                    .ok()
                    .and_then(|p| table.get(p))
                    .is_some_and(|p| p.parent == p.id);
                if gone {
                    table[i].parent = e.id;
                    marked = true;
                }
            }
            if !marked {
                break;
            }
        }
        let mut kept = 0;
        for i in 0..len {
            let e = table[i];
            if e.parent != e.id {
                table[kept] = e;
                kept += 1;
            }
        }
        self.next_len = kept;
    }

    /// The batch's verdict: every parent is a node and no node is under
    /// itself.
    fn verdict(&self) -> Option<Reason> {
        if let Some(reason) = self.failed {
            return Some(reason);
        }
        let table = self.next.get(..self.next_len)?;
        for e in table {
            // A walk to a root is shorter than the tree; a longer one is
            // going round.
            let mut parent = e.parent;
            let mut steps = 0usize;
            while parent != NO_NODE {
                let Ok(at) = find(table, parent) else {
                    return Some(Reason::UnknownParent);
                };
                steps += 1;
                if steps > table.len() {
                    return Some(Reason::Cycle);
                }
                parent = table.get(at).map_or(NO_NODE, |p| p.parent);
            }
        }
        None
    }

    fn apply(&mut self, revision: u32) -> Outcome {
        let verdict = self.verdict();
        self.failed = None;
        if let Some(reason) = verdict {
            self.restore();
            return Outcome::Rejected { revision, reason };
        }
        let n = self.next_len.min(self.max_nodes());
        if let (Some(dst), Some(src)) = (self.live.get_mut(..n), self.next.get(..n)) {
            for (d, s) in dst.iter_mut().zip(src) {
                *d = *s;
            }
        }
        self.live_len = n;
        self.revision = Some(revision);
        Outcome::Applied { revision }
    }
}
