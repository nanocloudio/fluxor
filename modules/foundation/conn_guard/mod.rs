//! Stateless TCP-SYN connection-rate filter.
//!
//! Sits between the NIC driver and the IP module on the RX path:
//!
//!   rp1_gem.frames_rx → conn_guard.frames_rx → ip.frames_rx
//!
//! Frames are length-prefixed `[len:u16 LE][frame...]` on both sides, matching
//! the convention used by ip ⇄ NIC drivers.
//!
//! For each frame, parses Ethernet + IPv4 + TCP just enough to identify a
//! pure SYN (SYN set, ACK clear). For SYNs, increments a per-`(local-address,
//! source-IP)` counter; if more than `rate_limit_per_ip` SYNs arrive from the
//! same remote IP at the same local address within `rate_window_ms`, the SYN
//! is dropped. All non-TCP, non-SYN, and within-budget traffic passes through
//! unchanged.
//!
//! The rate table is a fixed-size LRU keyed by `(destination IPv4, source
//! IPv4)`. The destination (local) address is the per-workload owner axis
//!: one local address maps 1:1 to one owner in
//! v1, so partitioning the SYN budget by destination IP gives each workload
//! its own share without any owner_tag plumbing — a flood aimed at one owned
//! address cannot exhaust another owner's or the host's budget. With a single
//! local address the destination is invariant and the key collapses to the
//! source IP alone. On insertion when full,
//! the least-recently-touched entry is evicted.
//!
//! Params (TLV):
//!   tag 1: rate_table_size (u8, default 32, max 32; **0 disables the fuse
//!          entirely** — `admit_syn` short-circuits, every SYN is admitted)
//!   tag 2: rate_limit_per_ip (u8, default 16)
//!   tag 3: rate_window_ms (u16, default 1000)
//!
//! **The 16 SYN/s/IP default is sized for HOSTILE traffic.** A load probe or
//! benchmark is indistinguishable from a SYN flood by that measure, so a
//! measurement graph must widen it (or set `rate_table_size = 0`) explicitly.
//! Dropped SYNs are not visibly errors: the peer retransmits on Linux's
//! 1s/3s/7s backoff ladder, and that ladder then appears as the p90/p99 of
//! whatever is being measured. See `standards/rig.md` §6 and §7a.
//!
//! Diagnosing a suspected trip: `[guard] drop_syn` in the heartbeat is the
//! authoritative counter. Do NOT add a log line to `module_new` or to an
//! early `module_step`: it wedges this module — it stops stepping, frames
//! never reach `ip`, and the DUT boots unreachable in a way that reads as a
//! network fault. The frame buffer lives in `GuardState` rather than on the
//! stack precisely because `module_step`'s frame must stay tiny; new stack
//! buffers here are not free.

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset. unreachable_patterns: defensive `_ => Error` arms in enum state-machine matches are intentional — adding a new variant should not silently bypass the error path"
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

mod params_def;

// ============================================================================
// Constants
// ============================================================================

const MAX_FRAME: usize = 1600;
pub const MAX_TABLE: usize = 32;

const ETHERTYPE_IPV4: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;

// ============================================================================
// Rate table entry
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
struct RateEntry {
    ip: u32, // remote source IP; 0 = empty slot
    /// Local (destination) address the SYN targeted — the per-workload owner
    /// axis. In v1 one local address maps 1:1
    /// to one owner (a workload can only be reached at its own address), so the
    /// destination IP on the wire IS the owner discriminator — conn_guard needs
    /// no owner_tag plumbing to partition by it. Keying on `(dst, ip)` gives
    /// each local address its own per-remote-IP SYN budget, so a flood aimed at
    /// one workload's address exhausts that workload's share, not the host's or
    /// a neighbour's. With a single local address `dst` is constant across
    /// all entries, so the partition structure, eviction and counters are
    /// exactly those of a source-only key.
    dst: u32,
    last_ms: u32, // monotonic ms timestamp (truncated)
    /// SYNs seen from this `(dst, ip)` pair inside the current window.
    ///
    /// `u16`, NOT `u8`, deliberately. `rate_limit_per_ip` is a `u8`, so with a
    /// `u8` counter `count.saturating_add(1) <= limit` would be *always true*
    /// at `limit == 255` — the fuse would silently be a no-op at its own
    /// documented maximum. The wider counter makes 255 an ordinary limit that
    /// drops the 256th SYN.
    count: u16,
    _pad: [u8; 2],
}

impl RateEntry {
    const fn empty() -> Self {
        Self {
            ip: 0,
            dst: 0,
            last_ms: 0,
            count: 0,
            _pad: [0; 2],
        }
    }
}

// ============================================================================
// State
// ============================================================================

#[repr(C)]
pub struct GuardState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,

    rate_table_size: u8,
    rate_limit_per_ip: u8,
    rate_window_ms: u16,
    _pad: u32,

    table: [RateEntry; MAX_TABLE],

    passed: u32,
    dropped_syn: u32,
    dropped_full: u32,
    step_count: u32,

    /// Frame staging buffer (length-prefix + frame). Kept in state rather
    /// than on the stack so `module_step` has a tiny frame.
    frame_buf: [u8; 2 + MAX_FRAME],

    /// Heartbeat line buffer. In state for the same reason `frame_buf` is:
    /// a stack array in `module_step` wedges this module. 128 bytes so the
    /// full field set fits at worst-case u32 widths — the previous 96-byte
    /// stack array had ~103 bytes of worst-case content once the effective
    /// config fields were added, i.e. it could format past its own end.
    log_buf: [u8; 128],
}

const STATE_SIZE: usize = core::mem::size_of::<GuardState>();

// ============================================================================
// Frame classification
// ============================================================================

/// Returns `Some((source_ip, dest_ip))` if the frame is a pure TCP SYN (SYN
/// set, ACK clear), otherwise None. The destination IP is the local address
/// the SYN targeted — the per-owner partition axis.
unsafe fn classify_syn(frame: *const u8, len: usize) -> Option<(u32, u32)> {
    if len < 14 + 20 {
        return None;
    }

    // EtherType (offset 12-13, big-endian)
    let et = ((*frame.add(12) as u16) << 8) | (*frame.add(13) as u16);
    if et != ETHERTYPE_IPV4 {
        return None;
    }

    // IPv4 header at offset 14
    let ipv4 = frame.add(14);
    let vihl = *ipv4;
    if (vihl >> 4) != 4 {
        return None;
    }
    let ihl_words = (vihl & 0x0F) as usize;
    if ihl_words < 5 {
        return None;
    }
    let ip_hdr_len = ihl_words * 4;
    if len < 14 + ip_hdr_len + 20 {
        return None;
    }

    // Protocol (offset 9 within IPv4 header)
    if *ipv4.add(9) != IPPROTO_TCP {
        return None;
    }

    // Source IP (offset 12 within IPv4 header), big-endian on the wire.
    // Store as host-endian u32 for table key (endianness only matters for keying).
    let src_ip = ((*ipv4.add(12) as u32) << 24)
        | ((*ipv4.add(13) as u32) << 16)
        | ((*ipv4.add(14) as u32) << 8)
        | (*ipv4.add(15) as u32);

    // Destination IP (offset 16 within IPv4 header) — the local address the
    // SYN is aimed at, i.e. the owner axis. Same host-endian keying as src.
    let dst_ip = ((*ipv4.add(16) as u32) << 24)
        | ((*ipv4.add(17) as u32) << 16)
        | ((*ipv4.add(18) as u32) << 8)
        | (*ipv4.add(19) as u32);

    // TCP header starts at frame + 14 + ip_hdr_len. Flags at offset 13.
    let tcp = frame.add(14 + ip_hdr_len);
    let flags = *tcp.add(13);

    // Pure SYN = SYN set, ACK clear. Treat SYN+ACK and other combos as already
    // part of an established or in-progress connection.
    if (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0 {
        Some((src_ip, dst_ip))
    } else {
        None
    }
}

// ============================================================================
// Rate table
// ============================================================================

/// Decide whether a SYN from `src_ip` targeting local address `dst_ip` at
/// `now_ms` should be admitted. Updates the table in place. Returns true to
/// admit, false to drop.
///
/// The key is `(dst_ip, src_ip)` — the destination (local address) axis
/// partitions the per-remote-IP budget per workload: a flood aimed at one
/// owned address burns that owner's SYN share, not another owner's or the
/// host's. With a single local address `dst_ip` is invariant, so the key
/// collapses to `src_ip` alone.
unsafe fn admit_syn(s: &mut GuardState, src_ip: u32, dst_ip: u32, now_ms: u32) -> bool {
    let table_size = s.rate_table_size as usize;
    if table_size == 0 {
        return true;
    }

    let limit = s.rate_limit_per_ip;
    let window = s.rate_window_ms as u32;

    let base = s.table.as_mut_ptr();

    // 1) Look for existing entry for this (dst, src) pair.
    let mut i = 0usize;
    while i < table_size {
        let e = base.add(i);
        if (*e).ip == src_ip && (*e).dst == dst_ip && src_ip != 0 {
            let elapsed = now_ms.wrapping_sub((*e).last_ms);
            if elapsed >= window {
                // Window expired — reset counter for this pair.
                (*e).count = 1;
                (*e).last_ms = now_ms;
                return true;
            } else {
                let c = (*e).count.saturating_add(1);
                (*e).count = c;
                // Don't update last_ms inside the window — the window is
                // anchored at the first SYN of the burst.
                return c <= limit as u16;
            }
        }
        i += 1;
    }

    // 2) No entry: evict the oldest (or claim a free slot).
    let mut victim = 0usize;
    let mut victim_ms = u32::MAX;
    let mut i = 0usize;
    while i < table_size {
        let e = base.add(i);
        if (*e).ip == 0 {
            victim = i;
            break;
        }
        let age = now_ms.wrapping_sub((*e).last_ms);
        // Pick the most-aged entry. Use signed-style compare via wrapping diff.
        if age >= window || age > victim_ms {
            victim = i;
            victim_ms = age;
        }
        i += 1;
    }

    let e = base.add(victim);
    (*e).ip = src_ip;
    (*e).dst = dst_ip;
    (*e).last_ms = now_ms;
    (*e).count = 1;
    true
}

// ============================================================================
// Module ABI
// ============================================================================

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize {
    STATE_SIZE
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 {
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    out_chan: i32,
    ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    _state_size: usize,
    syscalls: *const SyscallTable,
) -> i32 {
    // SAFETY: the loader guarantees `state` points at a live allocation of at
    // least `size_of::<GuardState>()`, aligned and exclusive to this module for
    // the duration of the call.
    let s = unsafe { &mut *(state as *mut GuardState) };
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    s._ctrl_chan = ctrl_chan;

    let base = s.table.as_mut_ptr();
    let mut i = 0usize;
    while i < MAX_TABLE {
        // SAFETY: `i < MAX_TABLE` and `base` is the start of a `[RateEntry;
        // MAX_TABLE]` inside the state allocation, so the offset is in bounds.
        unsafe {
            *base.add(i) = RateEntry::empty();
        }
        i += 1;
    }

    s.passed = 0;
    s.dropped_syn = 0;
    s.dropped_full = 0;

    // SAFETY: `params` is the loader-supplied parameter blob, valid for
    // `params_len` bytes, and `parse_tlv` reads only within that bound.
    unsafe {
        // Use the generated `parse_tlv`, not a hand-rolled walk. The params
        // blob is `[0xFE][0x01][payload_len:u16 LE]` followed by the entries
        // and a `0xFF` end marker; `parse_tlv` starts at offset 4 and honours
        // that marker, and calls `set_defaults` itself.
        //
        // Starting the walk at offset 0 instead consumes that 4-byte header
        // as if it were entries, and every subsequent tag lands misaligned.
        // The damage is silent and PARTIAL, which is what makes it worth a
        // comment: walking `FE 01 0f 00 | 02 01 c8 | 03 02 64 00 | …` from 0
        // reads (tag=0xFE, len=1), then (tag=0x00, len=2), and only then
        // arrives at the real `03 02 64 00`. One parameter therefore applies
        // by coincidence while its neighbours are swallowed and keep their
        // defaults — a graph whose declared rate limits quietly are not the
        // limits in force, with nothing in the logs to say so.
        params_def::parse_tlv(s, params, params_len);
    }
    0
}

#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut GuardState);
    let sys = &*s.syscalls;

    s.step_count = s.step_count.wrapping_add(1);
    // `[guard] pass=...` heartbeat. `drop_full` non-zero ⇒ IP not draining;
    // `drop_syn` non-zero ⇒ the SYN-rate fuse is tripping. A tripping fuse
    // drops SYNs silently and the peer's retransmit ladder turns that into
    // downstream latency, so the heartbeat runs 10x faster once the fuse has
    // tripped at all.
    //
    // The heartbeat stays one buffer and one `dev_log`: a second log buffer in
    // `module_step` wedges this module — frames stop reaching `ip` and the DUT
    // boots unreachable. The frame buffer lives in `GuardState` to keep this
    // stack frame tiny; the cadence below is the only thing that varies.
    // 5_000 unconditionally: that is the cadence `ip`, `tls`, `http` and
    // `rp1_gem` all emit on, so admission decisions land in the same window
    // as the byte counts they gate. The previous 50_000 quiet-path value
    // made a clean run's `[guard] pass=` unalignable with everything else;
    // the drop path was already at 5_000 and is left as the floor.
    let cadence: u32 = 5_000;
    if s.step_count.is_multiple_of(cadence) {
        let p = s.log_buf.as_mut_ptr();
        let prefix = b"[guard] pass=";
        core::ptr::copy_nonoverlapping(prefix.as_ptr(), p, prefix.len());
        let mut pos = prefix.len();
        pos += fmt_u32_dec(s.passed, p.add(pos));
        let f2 = b" drop_syn=";
        core::ptr::copy_nonoverlapping(f2.as_ptr(), p.add(pos), f2.len());
        pos += f2.len();
        pos += fmt_u32_dec(s.dropped_syn, p.add(pos));
        let f3 = b" drop_full=";
        core::ptr::copy_nonoverlapping(f3.as_ptr(), p.add(pos), f3.len());
        pos += f3.len();
        pos += fmt_u32_dec(s.dropped_full, p.add(pos));
        // EFFECTIVE fuse config, and the clock the window is measured
        // against. Not decoration: a `drop_syn` that climbs on a benchmark
        // configured far below the fuse is only interpretable if you can see
        // whether the configured value actually reached the module and
        // whether `dev_millis` is advancing at all — a stalled clock makes
        // `elapsed >= window` permanently false, so the counter never resets
        // and the fuse trips at `limit` admissions regardless of rate.
        // These are three loads and three formats into the SAME buffer and
        // the SAME dev_log; adding a second buffer or a second log call here
        // wedges the module (see this file's step-frame note).
        let f4 = b" lim=";
        core::ptr::copy_nonoverlapping(f4.as_ptr(), p.add(pos), f4.len());
        pos += f4.len();
        pos += fmt_u32_dec(s.rate_limit_per_ip as u32, p.add(pos));
        let f5 = b" win=";
        core::ptr::copy_nonoverlapping(f5.as_ptr(), p.add(pos), f5.len());
        pos += f5.len();
        pos += fmt_u32_dec(s.rate_window_ms as u32, p.add(pos));
        let f6 = b" tsz=";
        core::ptr::copy_nonoverlapping(f6.as_ptr(), p.add(pos), f6.len());
        pos += f6.len();
        pos += fmt_u32_dec(s.rate_table_size as u32, p.add(pos));
        let f7 = b" ms=";
        core::ptr::copy_nonoverlapping(f7.as_ptr(), p.add(pos), f7.len());
        pos += f7.len();
        pos += fmt_u32_dec(dev_millis(sys) as u32, p.add(pos));
        dev_log(sys, 3, p, pos);
    }

    if s.in_chan < 0 || s.out_chan < 0 {
        return 0;
    }

    // Need at least the 2-byte length prefix to be ready.
    let poll = (sys.channel_poll)(s.in_chan, 0x01); // POLL_IN
    if poll <= 0 || (poll as u32 & 0x01) == 0 {
        return 0;
    }

    // Read the length prefix directly into the staging buffer.
    let buf = s.frame_buf.as_mut_ptr();
    let hn = (sys.channel_read)(s.in_chan, buf, 2);
    if hn < 2 {
        return 0;
    }
    let frame_len = (*buf as usize) | ((*buf.add(1) as usize) << 8);
    if frame_len == 0 || frame_len > MAX_FRAME {
        s.dropped_full = s.dropped_full.wrapping_add(1);
        return 0;
    }

    let r = (sys.channel_read)(s.in_chan, buf.add(2), frame_len);
    if r < frame_len as i32 {
        s.dropped_full = s.dropped_full.wrapping_add(1);
        return 0;
    }

    let frame_ptr = buf.add(2) as *const u8;
    let pass = if let Some((src_ip, dst_ip)) = classify_syn(frame_ptr, frame_len) {
        let now_ms = dev_millis(sys) as u32;
        let admit = admit_syn(s, src_ip, dst_ip, now_ms);
        if !admit {
            s.dropped_syn = s.dropped_syn.wrapping_add(1);
        }
        admit
    } else {
        true
    };

    if pass {
        let total = 2 + frame_len;
        let p = (sys.channel_poll)(s.out_chan, 0x02); // POLL_OUT
        if p > 0 && (p as u32 & 0x02) != 0 {
            (sys.channel_write)(s.out_chan, buf as *const u8, total);
            s.passed = s.passed.wrapping_add(1);
        } else {
            // Downstream full — drop. Higher layers (TCP, ARP) will retry.
            s.dropped_full = s.dropped_full.wrapping_add(1);
        }
    }

    2 // Burst — likely more frames pending.
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/runtime/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/runtime/wasm_entry.rs");

// ============================================================================
// Host-test API — the owner-partitioning SYN-fuse internals (`admit_syn` /
// `classify_syn`) as a minimal, `host-test`-gated public surface so the fuse
// can be exercised from `tests/harness/tests/conn_guard.rs`. Inline tests are
// banned in `modules/` (no_std → they compile away silently,
// fluxor.toml::[ci.hygiene]), so the suite lives in the harness; this keeps
// `GuardState`/`RateEntry` fields private while giving the harness a stable
// white-box entry point. Never compiled into the PIC firmware.
// ============================================================================
#[cfg(feature = "host-test")]
impl GuardState {
    /// A zeroed fuse with a full table and the given per-remote-IP limit /
    /// window — the state a bind-time `GuardState` reaches after config parse.
    pub fn new_for_test(limit: u8, window_ms: u16) -> Self {
        // SAFETY: GuardState is repr(C) POD; zeroing is a valid initial value.
        let mut s: GuardState = unsafe { core::mem::zeroed() };
        s.rate_table_size = MAX_TABLE as u8;
        s.rate_limit_per_ip = limit;
        s.rate_window_ms = window_ms;
        for e in s.table.iter_mut() {
            *e = RateEntry::empty();
        }
        s
    }

    /// Set the rate-table size (0 disables the fuse — every SYN admitted).
    pub fn set_table_size(&mut self, n: u8) {
        self.rate_table_size = n;
    }

    /// Run one SYN through the fuse against the `(dst, src)` key. Returns
    /// whether it is admitted.
    pub fn admit(&mut self, src_ip: u32, dst_ip: u32, now_ms: u32) -> bool {
        // SAFETY: touches only `self`'s POD table; no syscalls.
        unsafe { admit_syn(self, src_ip, dst_ip, now_ms) }
    }

    /// Extract `(src_ip, dst_ip)` from a raw SYN frame, or `None` if it is not
    /// a pure IPv4 TCP SYN.
    pub fn classify(frame: &[u8]) -> Option<(u32, u32)> {
        // SAFETY: `classify_syn` reads at most `frame.len()` bytes.
        unsafe { classify_syn(frame.as_ptr(), frame.len()) }
    }
}
