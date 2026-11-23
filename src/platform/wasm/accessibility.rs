//! `wasm_browser_accessibility` native module: the browser mirror of an
//! application's accessibility tree, and the text field behind its drawn
//! text inputs.
//!
//! `tree` in carries `AccessibilityTree` records
//! (`abi::contracts::accessibility`). Every record is parsed and every batch
//! checked here (`fluxor_sdk::accessibility::TreeCheck`); the host is handed
//! checked records to stage and told at the batch's APPLY to apply them as
//! one change to the page, or to drop them. A rejected batch changes
//! nothing on the page; the mirror then sends `RESYNC` on `actions` and
//! passes over batches until one opens with `TREE`. It sends `RESYNC` at
//! its start too: it has no tree it trusts.
//!
//! `actions` out carries `AccessibilityActions` records: what assistive
//! technology or a pointer did to a mirrored control.
//!
//! `text` out carries `TextEvents` records (`abi::contracts::input::text`):
//! what the platform's text machinery did in the focused mirror field. The
//! host hands over each edit by field and this module writes the record.
//! With `tree` unwired the host keeps one text field over the surface and
//! its edits carry `NO_TARGET`.
//!
//! Nothing popped from the host is lost to a full channel: an action or a
//! text record the channel refuses is held and written first on the next
//! step.

use crate::abi::contracts::accessibility::{self as tree, Action};
use crate::abi::contracts::input::text;
use crate::abi::platform::native::wasm::wasm_browser_accessibility as tags;
use crate::kernel::exec::scheduler;
use crate::kernel::exec::scheduler::{NativeInit, NativeVtable};
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;
use fluxor_sdk::accessibility::{Entry, Outcome, Reason, TreeCheck};

extern "C" {
    /// The mirror exists. `tree_wired` is non-zero when the graph wires the
    /// `tree` input; zero asks the host for its text-only field.
    fn host_a11y_open(tree_wired: u32);

    /// Add one checked tree record (`ptr`/`len`, a whole record as it
    /// arrived) to the batch the host is staging.
    fn host_a11y_stage(ptr: *const u8, len: usize);

    /// End the staged batch: apply it to the page as one change (`apply`
    /// non-zero) or drop it.
    fn host_a11y_commit(apply: u32);

    /// Pop the next action the mirror raised into `buf` as one
    /// `AccessibilityActions` record. Returns its length, or 0 when none is
    /// waiting.
    fn host_a11y_action_pop(buf: *mut u8, len: usize) -> i32;

    /// Pop the next text edit into `buf`, laid out as `EDIT_*` below.
    /// Returns its length, or 0 when none is waiting.
    fn host_a11y_text_pop(buf: *mut u8, len: usize) -> i32;
}

/// The most nodes a mirrored tree holds: the `max_nodes` fact the manifest
/// declares on `tree`.
const MAX_NODES: usize = 1024;

// A text edit as the host hands it over. `kind` and `flags` take the
// contract's `MSG_*` and flag values; the text is UTF-8, at most
// `text::TEXT_MAX` bytes (the host splits a longer insert and truncates a
// longer preedit).
//
//   [0]       kind      text::MSG_*
//   [1]       flags     the message's flags
//   [2..4]    text_len  u16
//   [4..8]    target    u32
//   [8..12]   a         u32  COMPOSE hl_start, DELETE before, SELECT anchor
//   [12..16]  b         u32  COMPOSE hl_end,   DELETE after,  SELECT focus
//   [16..]    text
const EDIT_KIND: usize = 0;
const EDIT_FLAGS: usize = 1;
const EDIT_TEXT_LEN: usize = 2;
const EDIT_TARGET: usize = 4;
const EDIT_A: usize = 8;
const EDIT_B: usize = 12;
const EDIT_TEXT: usize = 16;
const EDIT_MAX: usize = EDIT_TEXT + text::TEXT_MAX;

#[repr(C)]
pub(crate) struct MirrorState {
    pub tree_chan: i32,
    pub actions_chan: i32,
    pub text_chan: i32,

    /// The whole-tree check, over two tables on the module heap.
    pub check: TreeCheck<'static>,
    /// The tree the page shows is one this mirror applied from a batch that
    /// opened with TREE. False at start and after a rejected batch.
    pub trusted: bool,
    /// What is being done with the batch arriving.
    pub batch: Batch,
    /// The host holds staged records of the batch arriving.
    pub staged: bool,
    /// A `RESYNC` is owed on `actions`.
    pub resync_owed: bool,
    /// Batches rejected.
    pub rejected: u32,
    /// Text edits the contract refuses.
    pub text_refused: u32,

    /// The action in hand; `relay_records` holds one the channel refused.
    pub action: [u8; tree::ACTION_SIZE],

    /// The composition rule for the records written on `text`.
    pub composing: text::Sequence,
    /// A text record the channel has not taken yet, and its length.
    pub text_out: [u8; text::MAX_RECORD],
    pub text_out_len: u32,
    pub edit: [u8; EDIT_MAX],

    /// Tree bytes read and not yet parsed.
    pub carry_len: u32,
    pub carry: [u8; tree::MAX_RECORD],
}

/// What the mirror is doing with the batch arriving.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Batch {
    /// Between batches: the next record opens one.
    Idle,
    /// The batch is being checked, and staged with the host while it holds.
    Checking,
    /// The batch is passed over through its APPLY: it arrived while no tree
    /// is trusted and did not open with TREE, so it names nodes the mirror
    /// cannot vouch for.
    Passing,
}

const SEAT: [u32; 6] = crate::abi::platform::native::wasm::wasm_browser_accessibility::HEAP_SEAT;
const _: () = assert!(
    SEAT[0] as usize
        >= super::heap_for::<MirrorState>() + 2 * (MAX_NODES * core::mem::size_of::<Entry>() + 32),
    "the declared heap seat holds the instance and both tables of the tree check"
);

unsafe fn alloc_table() -> Option<&'static mut [Entry]> {
    let table = syscalls::get_syscall_table();
    let bytes = (MAX_NODES * core::mem::size_of::<Entry>()) as u32;
    let raw = (table.heap_alloc)(bytes) as *mut Entry;
    if raw.is_null() {
        return None;
    }
    for i in 0..MAX_NODES {
        // SAFETY: `raw` is `MAX_NODES` entries of fresh heap, aligned by the
        // allocator for a `u32` record.
        unsafe { core::ptr::write(raw.add(i), Entry::EMPTY) };
    }
    // SAFETY: the allocation is initialised above and lives as long as the
    // module's heap, which outlives every step of the instance.
    Some(unsafe { core::slice::from_raw_parts_mut(raw, MAX_NODES) })
}

unsafe fn alloc_state(tree_chan: i32, actions_chan: i32, text_chan: i32) -> *mut MirrorState {
    let table = syscalls::get_syscall_table();
    let raw = (table.heap_alloc)(core::mem::size_of::<MirrorState>() as u32) as *mut MirrorState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    let (Some(live), Some(next)) = (alloc_table(), alloc_table()) else {
        return core::ptr::null_mut();
    };
    core::ptr::write(
        raw,
        MirrorState {
            tree_chan,
            actions_chan,
            text_chan,
            check: TreeCheck::new(live, next),
            trusted: false,
            batch: Batch::Idle,
            staged: false,
            resync_owed: true,
            rejected: 0,
            text_refused: 0,
            action: [0u8; tree::ACTION_SIZE],
            composing: text::Sequence::new(),
            text_out: [0u8; text::MAX_RECORD],
            text_out_len: 0,
            edit: [0u8; EDIT_MAX],
            carry_len: 0,
            carry: [0u8; tree::MAX_RECORD],
        },
    );
    raw
}

impl MirrorState {
    /// Tell the host to drop what it staged of the batch arriving.
    ///
    /// # Safety
    /// Calls a host import.
    unsafe fn unstage(&mut self) {
        if self.staged {
            // SAFETY: a host import with no pointer arguments.
            unsafe { host_a11y_commit(0) };
            self.staged = false;
        }
    }

    /// The batch being checked is rejected. The page keeps the tree it
    /// shows, the application is asked for the whole tree, and batches are
    /// passed over until it answers with one.
    ///
    /// # Safety
    /// Calls a host import.
    unsafe fn rejected(&mut self, reason: Option<Reason>) {
        if self.trusted || self.rejected == 0 {
            let kept = self.check.revision().unwrap_or(0);
            let why = match reason {
                Some(Reason::Record(fault)) => {
                    log::warn!("[accessibility] a tree record was refused ({fault:?})");
                    "a record the contract refuses"
                }
                Some(Reason::TooManyNodes) => "more nodes than the mirror holds",
                Some(Reason::UnknownParent) => "a node whose parent is not in the tree",
                Some(Reason::Cycle) => "a node that is its own ancestor",
                None => "a record whose length the contract does not allow",
            };
            log::warn!("[accessibility] batch rejected: {why}; the mirror keeps revision {kept}");
        }
        self.rejected = self.rejected.wrapping_add(1);
        // SAFETY: as this function's contract.
        unsafe { self.unstage() };
        self.trusted = false;
        self.resync_owed = true;
    }

    /// Decide what to do with the batch a record belongs to. A batch is
    /// checked when a tree is trusted or the batch replaces the tree, and
    /// passed over otherwise. TREE replaces the tree wherever it stands, so
    /// it also starts the checking of a batch that was being passed over:
    /// the answer to a `RESYNC` is never lost behind a batch whose APPLY
    /// was.
    fn open(&mut self, replaces_tree: bool) {
        match self.batch {
            Batch::Idle if self.trusted || replaces_tree => self.batch = Batch::Checking,
            Batch::Idle => self.batch = Batch::Passing,
            Batch::Passing if replaces_tree => self.batch = Batch::Checking,
            _ => {}
        }
    }

    /// Take one parsed record of the tree stream.
    ///
    /// # Safety
    /// `bytes` is the record's own bytes; calls host imports.
    unsafe fn take(&mut self, record: &tree::Record<'_>, bytes: &[u8]) {
        let ends_batch = matches!(record, tree::Record::Apply { .. });
        self.open(matches!(record, tree::Record::Tree));
        if self.batch == Batch::Checking {
            match self.check.record(record) {
                Outcome::Pending if self.check.failing() => {
                    // The batch has failed and is rejected at its APPLY;
                    // nothing more of it goes to the host.
                    // SAFETY: as this function's contract.
                    unsafe { self.unstage() };
                }
                Outcome::Pending => {
                    // SAFETY: `bytes` is readable for its length.
                    unsafe { host_a11y_stage(bytes.as_ptr(), bytes.len()) };
                    self.staged = true;
                }
                Outcome::Applied { .. } => {
                    // SAFETY: `bytes` is readable for its length; the commit
                    // takes no pointer.
                    unsafe {
                        host_a11y_stage(bytes.as_ptr(), bytes.len());
                        host_a11y_commit(1);
                    }
                    self.staged = false;
                    self.trusted = true;
                }
                Outcome::Rejected { reason, .. } => {
                    // SAFETY: as this function's contract.
                    unsafe { self.rejected(Some(reason)) };
                }
            }
        }
        if ends_batch {
            self.batch = Batch::Idle;
        }
    }

    /// Read and check what `tree` holds.
    ///
    /// # Safety
    /// The instance's channels are its own; calls host imports.
    unsafe fn pump_tree(&mut self) {
        loop {
            let have = self.carry_len as usize;
            // SAFETY: `carry[have..]` is writable for the length passed.
            let n = unsafe {
                channel::channel_read(
                    self.tree_chan,
                    self.carry.as_mut_ptr().add(have),
                    self.carry.len() - have,
                )
            };
            if n <= 0 {
                return;
            }
            let filled = have + n as usize;
            let mut at = 0;
            loop {
                // SAFETY: `at..filled` lies inside the carry, which nothing
                // writes until this loop ends: `take` and `rejected` touch
                // the check, the flags and the host only. The slice is
                // detached from `self` so a record borrowed from it can be
                // handed to them.
                let rest = unsafe {
                    core::slice::from_raw_parts(self.carry.as_ptr().add(at), filled - at)
                };
                match tree::parse(rest) {
                    tree::Parse::NeedMore => break,
                    tree::Parse::Record { record, consumed } => {
                        // SAFETY: the record's own bytes.
                        unsafe { self.take(&record, &rest[..consumed]) };
                        at += consumed;
                    }
                    tree::Parse::Fault { skip: 0, .. } => {
                        // The record's length is not one the contract
                        // allows, so where the next record starts is
                        // unknown: what is held is dropped, and a batch
                        // that was being checked is rejected.
                        self.check.abandon();
                        if self.batch == Batch::Checking || self.trusted {
                            // SAFETY: as this function's contract.
                            unsafe { self.rejected(None) };
                        }
                        self.batch = Batch::Idle;
                        at = filled;
                        break;
                    }
                    tree::Parse::Fault { fault, skip } => {
                        // A refused record fails its batch, which is
                        // rejected at its APPLY.
                        self.open(false);
                        if self.batch == Batch::Checking {
                            self.check.refuse(fault);
                            // SAFETY: as this function's contract.
                            unsafe { self.unstage() };
                        }
                        at += skip;
                    }
                }
            }
            self.carry.copy_within(at..filled, 0);
            self.carry_len = (filled - at) as u32;
        }
    }

    /// Move the page's actions out, then write the `RESYNC` the mirror
    /// owes: in order behind them, once no action is held.
    ///
    /// # Safety
    /// The instance's channels are its own; calls host imports.
    unsafe fn pump_actions(&mut self) {
        if self.actions_chan < 0 {
            self.resync_owed = false;
            // Nothing reads actions: drain the host's queue so it stays
            // empty.
            // SAFETY: `action` is `ACTION_SIZE` writable bytes.
            while unsafe { host_a11y_action_pop(self.action.as_mut_ptr(), tree::ACTION_SIZE) } > 0 {
            }
            self.action[0] = 0;
            return;
        }
        // SAFETY: the pop import writes at most the length it is given.
        unsafe {
            super::relay_records(
                self.actions_chan,
                &mut self.action,
                host_a11y_action_pop,
                |b| tree::decode_action(b).is_some(),
            );
        }
        if self.resync_owed && self.action[0] == 0 {
            let resync = Action::Resync {
                revision: self.check.revision().unwrap_or(0),
            };
            if let Some(record) = tree::encode_action(&resync) {
                // SAFETY: `record` is `ACTION_SIZE` readable bytes.
                let written = unsafe {
                    channel::channel_write(self.actions_chan, record.as_ptr(), record.len())
                };
                self.resync_owed = written <= 0;
            }
        }
    }

    /// The `TextEvents` record for the edit in `self.edit[..len]`, written
    /// to `text_out`. `None` for an edit the contract does not admit.
    fn encode_edit(&mut self, len: usize) -> Option<usize> {
        if len < EDIT_TEXT {
            return None;
        }
        let edit = &self.edit[..len];
        let word =
            |at: usize| u32::from_le_bytes([edit[at], edit[at + 1], edit[at + 2], edit[at + 3]]);
        let text_len = usize::from(u16::from_le_bytes([
            edit[EDIT_TEXT_LEN],
            edit[EDIT_TEXT_LEN + 1],
        ]));
        if EDIT_TEXT + text_len != len {
            return None;
        }
        let body = core::str::from_utf8(&edit[EDIT_TEXT..]).ok()?;
        let (flags, target, a, b) = (
            edit[EDIT_FLAGS],
            word(EDIT_TARGET),
            word(EDIT_A),
            word(EDIT_B),
        );
        let out = &mut self.text_out;
        match edit[EDIT_KIND] {
            text::MSG_COMMIT if flags & !text::COMMIT_CONTINUES == 0 => {
                text::write_commit(out, target, flags & text::COMMIT_CONTINUES != 0, body)
            }
            text::MSG_COMPOSE if flags & !(text::COMPOSE_START | text::COMPOSE_END) == 0 => {
                text::write_compose(
                    out,
                    target,
                    flags & text::COMPOSE_START != 0,
                    flags & text::COMPOSE_END != 0,
                    u16::try_from(a).ok()?,
                    u16::try_from(b).ok()?,
                    body,
                )
            }
            text::MSG_DELETE if flags == 0 && body.is_empty() => {
                text::write_delete(out, target, a, b)
            }
            text::MSG_SELECT if flags == 0 && body.is_empty() => {
                text::write_select(out, target, a, b)
            }
            _ => None,
        }
    }

    /// Move the host's text edits out as `TextEvents` records.
    ///
    /// # Safety
    /// The instance's channels are its own; calls host imports.
    unsafe fn pump_text(&mut self) {
        loop {
            if self.text_out_len != 0 {
                if self.text_chan < 0 {
                    self.text_out_len = 0;
                    continue;
                }
                // SAFETY: `text_out[..text_out_len]` is readable.
                let written = unsafe {
                    channel::channel_write(
                        self.text_chan,
                        self.text_out.as_ptr(),
                        self.text_out_len as usize,
                    )
                };
                if written <= 0 {
                    return;
                }
                self.text_out_len = 0;
            }
            // SAFETY: `edit` is `EDIT_MAX` writable bytes.
            let n = unsafe { host_a11y_text_pop(self.edit.as_mut_ptr(), EDIT_MAX) };
            if n <= 0 {
                return;
            }
            let admitted = self.encode_edit(n as usize).filter(|&len| {
                match text::parse(&self.text_out[..len]) {
                    text::Parse::Record { record, .. } => self.composing.admit(&record).is_ok(),
                    _ => false,
                }
            });
            match admitted {
                Some(len) => self.text_out_len = len as u32,
                None => {
                    if self.text_refused == 0 {
                        log::warn!("[accessibility] a text edit the contract refuses was dropped");
                    }
                    self.text_refused = self.text_refused.wrapping_add(1);
                    self.composing.reset();
                }
            }
        }
    }
}

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn mirror_step(state: *mut u8) -> i32 {
    // SAFETY: `state` is the kernel-provided opaque pointer to this
    // instance's heap state, allocated by the constructor.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut MirrorState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.tree_chan >= 0 {
            st.pump_tree();
        }
        st.pump_actions();
        st.pump_text();
        0
    }
}

/// The `wasm_browser_accessibility` native module.
pub static WASM_BROWSER_ACCESSIBILITY: NativeVtable = super::heap_native(
    new,
    mirror_step,
    crate::abi::platform::native::wasm::wasm_browser_accessibility::STATE_BYTES,
);

/// # Safety
/// `state` is the instance's zeroed arena state; the current module is
/// `init.slot`.
unsafe fn new(state: *mut u8, init: &NativeInit<'_>) -> i32 {
    let tree_chan = scheduler::module_port(init.slot, tags::PORT_TREE);
    let actions_chan = scheduler::module_port(init.slot, tags::PORT_ACTIONS);
    let text_chan = scheduler::module_port(init.slot, tags::PORT_TEXT);
    // SAFETY: the constructor's own contract; the instance is built on
    // the slot's heap, which the current module allocates through.
    let rc = unsafe {
        super::seat_heap_instance(
            state,
            init.slot,
            &crate::abi::platform::native::wasm::wasm_browser_accessibility::HEAP_SEAT,
            init.params,
            || alloc_state(tree_chan, actions_chan, text_chan).cast(),
        )
    };
    if rc == 0 {
        // SAFETY: a host import with no pointer arguments.
        unsafe { host_a11y_open(u32::from(tree_chan >= 0)) };
    }
    rc
}
