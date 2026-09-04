// Core: table_consumer — the normative "subscribe, don't invent a
// push contract" state machine.
//
// Layer: cores (reusable SDK implementation, `include!`d by consumers —
// NOT a wire contract, so it lives under `cores/` with `session_handoff`
// rather than `contracts/`: outside the `abi::contracts` namespace and
// the numeric ABI-surface walk, though still covered by the whole-tree
// `modules/sdk` source pin like every core).
// Arena-agnostic: the caller owns the concrete table and supplies
// scratch; this file owns only the SUBSCRIBE / apply / shadow-relist
// protocol so every table consumer (http edge, dns-records-in-graph, …)
// shares one audited implementation instead of re-deriving it.
//
// Includer contract: this file references `SyscallTable` unqualified;
// each `include!` site must bring it into scope first (module crates via
// `use crate::abi::SyscallTable;`, the harness via
// `use fluxor::abi::SyscallTable;`).
//
// ## The pattern
//
//   1. Sink wiring — the graph self-edges an output port to an input
//      port on the same module; the module passes that input channel
//      handle as the SUBSCRIBE sink. Wiring is the caller's job (two
//      manifest ports + a `storage.namespace` read grant); this helper
//      takes the already-resolved sink handle.
//   2. Init — `SUBSCRIBE (0x1305)` on the prefix for the live delta
//      stream, then a cold-start relist (§5: cold start == recovery).
//   3. Apply loop — each `namespace.change` event
//      (`Added=0`/`Modified=1`/`Deleted=2`) is applied in place.
//   4. Loss recovery with shadow swap — on LOST (or any gap) rebuild
//      via `CHANGES (0x1307)` into a SHADOW table, then swap
//      atomically, never in place — a table swapped in place is a
//      torn table for any reader mid-scan. Cold start shares this path.
//   5. Bounded admission — the arena is the caller's; overflow is the
//      caller's to surface (a reader holds no write grant, §6).
//   6. Single-writer prefix discipline — a compiler owns the prefix;
//      the consumer treats it as read-only.
//
// ## Event wire shape
//
// The SUBSCRIBE stream frames each change as the 32-byte mesh Event
// header followed by a `namespace.change` payload; `CHANGES` returns
// the same payload records back-to-back into a caller buffer. Both are
// decoded by [`parse_change_record`]. A LOST notification rides the
// SUBSCRIBE stream as the distinguished sentinel `kind=Deleted` with an
// empty key (see `src/platform/linux/store.rs::pump_subscriptions`).

// `SyscallTable` is provided by the `include!` site (see the header).

/// `storage.namespace` op — open a change subscription on a prefix.
pub const OP_SUBSCRIBE: u32 = 0x1305;
/// `storage.namespace` op — synchronous windowed change-read (relist).
pub const OP_CHANGES: u32 = 0x1307;

/// Mesh Event header prefixing every framed subscription event.
pub const EVENT_HEADER_SIZE: usize = 32;
/// Byte offset of the little-endian payload length inside the header.
pub const EVENT_LEN_OFFSET: usize = 30;

/// SUBSCRIBE flag bit0 — include the initial listing as synthesised
/// Added events. This helper leaves it CLEAR and takes the initial
/// snapshot through the shared `CHANGES(since=0)` relist instead, so
/// cold start and LOST recovery run identical shadow-swap code (§5)
/// and the initial listing is never double-applied.
pub const SUB_FLAG_INCLUDE_INITIAL: u8 = 0x01;

/// `namespace.change` kinds.
pub const KIND_ADDED: u8 = 0;
pub const KIND_MODIFIED: u8 = 1;
pub const KIND_DELETED: u8 = 2;

/// `CHANGES` response status byte.
pub const STATUS_EVENTS: u8 = 0;
pub const STATUS_LOST: u8 = 1;

/// Fence wire tags carrying a `revision` at bytes `[17..25]`
/// (`contracts/fence.rs`): `RevisionMonotone` and `ViewConsistent`.
pub const FENCE_TAG_REVISION_MONOTONE: u8 = 4;
pub const FENCE_TAG_VIEW_CONSISTENT: u8 = 5;

/// One decoded `namespace.change` record borrowed from a wire buffer.
pub struct ChangeRecord<'a> {
    pub revision: u64,
    pub kind: u8,
    pub key: &'a [u8],
    /// Empty for `Deleted`.
    pub value: &'a [u8],
}

/// The caller's table, driven by the consumer. Implementors keep a live
/// table and a shadow table; the helper fills the shadow during a
/// relist and calls [`swap_shadow`](TableSink::swap_shadow) to promote
/// it atomically. `Added`/`Modified` both map to `upsert`; `Deleted`
/// maps to `remove`.
pub trait TableSink {
    /// Insert or replace `key`'s row. `shadow` selects the rebuild
    /// shadow (`true`) or the live table (`false`).
    fn upsert(&mut self, key: &[u8], value: &[u8], shadow: bool);
    /// Remove `key`'s row from the shadow or live table.
    fn remove(&mut self, key: &[u8], shadow: bool);
    /// Empty the shadow table at the start of a relist (§2 rule 4).
    fn clear_shadow(&mut self);
    /// Atomically promote the shadow table to live.
    fn swap_shadow(&mut self);
}

/// Decode one `namespace.change` record from `rec` (the payload after
/// any mesh Event header). Returns the record plus the total bytes
/// consumed, or `None` when `rec` is short/truncated.
///
/// Record layout: `[rev:u64 LE][kind:u8][key_len:u16 LE][val_len:u32 LE][key][val]`.
pub fn parse_change_record(rec: &[u8]) -> Option<(ChangeRecord<'_>, usize)> {
    if rec.len() < 15 {
        return None;
    }
    let rev = u64::from_le_bytes([
        rec[0], rec[1], rec[2], rec[3], rec[4], rec[5], rec[6], rec[7],
    ]);
    let kind = rec[8];
    let key_len = u16::from_le_bytes([rec[9], rec[10]]) as usize;
    let val_len = u32::from_le_bytes([rec[11], rec[12], rec[13], rec[14]]) as usize;
    let key_start = 15;
    let val_start = key_start + key_len;
    let end = val_start + val_len;
    if end > rec.len() {
        return None;
    }
    Some((
        ChangeRecord {
            revision: rev,
            kind,
            key: &rec[key_start..val_start],
            value: &rec[val_start..end],
        },
        end,
    ))
}

/// True when `rec` is the LOST relist sentinel: `kind=Deleted` with an
/// empty key. Producers emit it on the SUBSCRIBE stream when a
/// subscriber's backlog overran the retained ring.
pub fn is_lost_sentinel(r: &ChangeRecord<'_>) -> bool {
    r.kind == KIND_DELETED && r.key.is_empty()
}

/// Extract the `revision` from an encoded fence, when it carries one
/// (`RevisionMonotone` / `ViewConsistent`; revision at `[17..25]`).
fn fence_revision(fence: &[u8]) -> Option<u64> {
    if fence.len() < 25 {
        return None;
    }
    match fence[0] {
        FENCE_TAG_REVISION_MONOTONE | FENCE_TAG_VIEW_CONSISTENT => Some(u64::from_le_bytes([
            fence[17], fence[18], fence[19], fence[20], fence[21], fence[22], fence[23], fence[24],
        ])),
        _ => None,
    }
}

/// The subscription's persistent bookkeeping. Embed one per consumed
/// prefix in the module's `#[repr(C)]` state. Tiny by design — the
/// table itself lives in the caller's arena.
#[repr(C)]
pub struct TableConsumer {
    /// Highest fence revision covered by the live table (the next
    /// incremental `since`; relist uses `0` for a clean full snapshot).
    pub since: u64,
    /// `0` until the SUBSCRIBE + cold-start relist have run.
    pub subscribed: u8,
    _pad: [u8; 7],
}

impl TableConsumer {
    pub const fn new() -> Self {
        Self {
            since: 0,
            subscribed: 0,
            _pad: [0; 7],
        }
    }

    /// Drive one step of the consumer against an already-resolved `sink`
    /// channel and its `prefix`. `scratch` is a caller-owned buffer for
    /// the `CHANGES` relist response — size it for the arena's worst
    /// case (a truncated relist fails closed, keeping the prior table).
    ///
    /// # Safety
    /// `sys` must be a live syscall table; `sink >= 0` a channel the
    /// store SUBSCRIBE writes to.
    pub unsafe fn step<T: TableSink>(
        &mut self,
        sys: &SyscallTable,
        sink: i32,
        prefix: &[u8],
        scratch: &mut [u8],
        table: &mut T,
    ) {
        if sink < 0 {
            return;
        }
        if self.subscribed == 0 {
            // Live delta stream from the current watermark; the initial
            // snapshot comes through the shared relist below (§5), so
            // include-initial stays clear to avoid double-applying it.
            subscribe(sys, prefix, sink, 0);
            self.subscribed = 1;
            self.resync(sys, prefix, scratch, table);
            return;
        }
        // Apply the live stream; a LOST sentinel triggers a shadow relist.
        if self.drain_live(sys, sink, table) {
            self.resync(sys, prefix, scratch, table);
        }
    }

    /// Drain and apply every pending live event off `sink`. Returns
    /// `true` when a LOST sentinel was seen (caller must relist).
    unsafe fn drain_live<T: TableSink>(
        &mut self,
        sys: &SyscallTable,
        sink: i32,
        table: &mut T,
    ) -> bool {
        // One live event's payload — a single route row, bounded well
        // under this by the value-size budget.
        let mut payload = [0u8; LIVE_EVENT_MAX];
        let mut hdr = [0u8; EVENT_HEADER_SIZE];
        let mut lost = false;
        loop {
            let n = (sys.channel_read)(sink, hdr.as_mut_ptr(), EVENT_HEADER_SIZE);
            if n != EVENT_HEADER_SIZE as i32 {
                break;
            }
            let plen =
                u16::from_le_bytes([hdr[EVENT_LEN_OFFSET], hdr[EVENT_LEN_OFFSET + 1]]) as usize;
            if plen == 0 || plen > payload.len() {
                // Oversized/empty payload: consume and skip so the
                // stream stays framed. A right-sized value never hits
                // this; a truncated read below stops the loop.
                let mut left = plen;
                let mut skip = [0u8; 256];
                while left > 0 {
                    let take = left.min(skip.len());
                    let r = (sys.channel_read)(sink, skip.as_mut_ptr(), take);
                    if r <= 0 {
                        break;
                    }
                    left -= r as usize;
                }
                continue;
            }
            let r = (sys.channel_read)(sink, payload.as_mut_ptr(), plen);
            if r != plen as i32 {
                break;
            }
            let Some((rec, _)) = parse_change_record(&payload[..plen]) else {
                continue;
            };
            if is_lost_sentinel(&rec) {
                lost = true;
                continue;
            }
            match rec.kind {
                KIND_ADDED | KIND_MODIFIED => table.upsert(rec.key, rec.value, false),
                KIND_DELETED => table.remove(rec.key, false),
                _ => {}
            }
            if rec.revision > self.since {
                self.since = rec.revision;
            }
        }
        lost
    }

    /// Rebuild the whole table from a `CHANGES(since=0)` snapshot into
    /// the shadow, then swap atomically (§2 rule 4). Shared by cold
    /// start and LOST recovery (§5). A failed/oversized relist leaves
    /// the live table untouched.
    unsafe fn resync<T: TableSink>(
        &mut self,
        sys: &SyscallTable,
        prefix: &[u8],
        scratch: &mut [u8],
        table: &mut T,
    ) {
        let mut fence = [0u8; 62];
        let n = changes(sys, prefix, 0, scratch, &mut fence);
        if n < 5 {
            return; // ENOMEM / EINVAL / empty header → keep prior table
        }
        let n = n as usize;
        if scratch[0] == STATUS_LOST {
            return; // since=0 never LOSTs; defensive
        }
        // Only mutate the table once the snapshot decoded cleanly.
        table.clear_shadow();
        let count = u32::from_le_bytes([scratch[1], scratch[2], scratch[3], scratch[4]]);
        let mut off = 5usize;
        let mut applied = 0u32;
        while applied < count {
            let Some((rec, used)) = parse_change_record(&scratch[off..n]) else {
                break;
            };
            // since=0 delivers everything as Added; honour any kind.
            match rec.kind {
                KIND_ADDED | KIND_MODIFIED => table.upsert(rec.key, rec.value, true),
                KIND_DELETED => table.remove(rec.key, true),
                _ => {}
            }
            off += used;
            applied += 1;
        }
        table.swap_shadow();
        self.since = fence_revision(&fence).unwrap_or(self.since);
    }
}

impl Default for TableConsumer {
    fn default() -> Self {
        Self::new()
    }
}

/// Upper bound on a single live event payload the drain path buffers on
/// stack. One route row (`host=…;path=…;be=…`) is far smaller; larger
/// values are skipped to keep the stream framed rather than overflow.
const LIVE_EVENT_MAX: usize = 1024;

/// Encode + issue `SUBSCRIBE (0x1305)`:
/// `[prefix_len:u16][prefix][sink_chan:u32][flags:u8]`. Returns the rc.
///
/// # Safety
/// `sys` must be a live syscall table (`provider_call` a valid entry);
/// `sink >= 0` a channel the store SUBSCRIBE writes change events to.
pub unsafe fn subscribe(sys: &SyscallTable, prefix: &[u8], sink: i32, flags: u8) -> i32 {
    let mut arg = [0u8; SUB_ARG_MAX];
    if 2 + prefix.len() + 4 + 1 > arg.len() {
        return -22; // EINVAL: prefix too long for the scratch
    }
    let mut p = 0;
    arg[p..p + 2].copy_from_slice(&(prefix.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + prefix.len()].copy_from_slice(prefix);
    p += prefix.len();
    arg[p..p + 4].copy_from_slice(&(sink as u32).to_le_bytes());
    p += 4;
    arg[p] = flags;
    p += 1;
    (sys.provider_call)(-1, OP_SUBSCRIBE, arg.as_mut_ptr(), p)
}

/// Encode + issue `CHANGES (0x1307)` into `out`, writing the encoded
/// fence into `fence` (>= `fence::WIRE_MAX_LEN`). Returns the byte
/// count written to `out`, or a negative errno. Arg layout:
/// `[prefix_len:u16][prefix][since:u64][out_buf:u64][out_cap:u32][fence_ptr:u64][fence_cap:u16]`.
///
/// # Safety
/// `sys` must be a live syscall table (`provider_call` a valid entry);
/// `out` and `fence` must remain valid for the duration of the call —
/// the store writes the change window into `out` and the covered fence
/// into `fence`.
pub unsafe fn changes(
    sys: &SyscallTable,
    prefix: &[u8],
    since: u64,
    out: &mut [u8],
    fence: &mut [u8],
) -> i32 {
    let mut arg = [0u8; SUB_ARG_MAX];
    if 2 + prefix.len() + 8 + 8 + 4 + 8 + 2 > arg.len() {
        return -22;
    }
    let mut p = 0;
    arg[p..p + 2].copy_from_slice(&(prefix.len() as u16).to_le_bytes());
    p += 2;
    arg[p..p + prefix.len()].copy_from_slice(prefix);
    p += prefix.len();
    arg[p..p + 8].copy_from_slice(&since.to_le_bytes());
    p += 8;
    arg[p..p + 8].copy_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
    p += 8;
    arg[p..p + 4].copy_from_slice(&(out.len() as u32).to_le_bytes());
    p += 4;
    arg[p..p + 8].copy_from_slice(&(fence.as_mut_ptr() as u64).to_le_bytes());
    p += 8;
    arg[p..p + 2].copy_from_slice(&(fence.len() as u16).to_le_bytes());
    p += 2;
    (sys.provider_call)(-1, OP_CHANGES, arg.as_mut_ptr(), p)
}

/// Scratch for the SUBSCRIBE / CHANGES arg encodings — prefix plus the
/// fixed header/footer fields.
const SUB_ARG_MAX: usize = 256;
