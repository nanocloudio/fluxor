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
//! pure SYN (SYN set, ACK clear). For SYNs, increments a per-source-IP
//! counter; if more than `rate_limit_per_ip` SYNs arrive from the same IP
//! within `rate_window_ms`, the SYN is dropped. All non-TCP, non-SYN, and
//! within-budget traffic passes through unchanged.
//!
//! The rate table is a fixed-size LRU keyed by source IPv4 address. On
//! insertion when full, the least-recently-touched entry is evicted.
//!
//! Params (TLV):
//!   tag 1: rate_table_size (u8, default 32, max 32)
//!   tag 2: rate_limit_per_ip (u8, default 16)
//!   tag 3: rate_window_ms (u16, default 1000)

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/params.rs");

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
    ip: u32,        // 0 = empty slot
    last_ms: u32,   // monotonic ms timestamp (truncated)
    count: u8,
    _pad: [u8; 3],
}

impl RateEntry {
    const fn empty() -> Self {
        Self { ip: 0, last_ms: 0, count: 0, _pad: [0; 3] }
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

    /// Frame staging buffer (length-prefix + frame). Kept in state rather
    /// than on the stack so `module_step` has a tiny frame.
    frame_buf: [u8; 2 + MAX_FRAME],
}

const STATE_SIZE: usize = core::mem::size_of::<GuardState>();

// ============================================================================
// Frame classification
// ============================================================================

/// Returns Some(source_ip) if the frame is a pure TCP SYN (SYN set, ACK clear),
/// otherwise None.
unsafe fn classify_syn(frame: *const u8, len: usize) -> Option<u32> {
    if len < 14 + 20 { return None; }

    // EtherType (offset 12-13, big-endian)
    let et = ((*frame.add(12) as u16) << 8) | (*frame.add(13) as u16);
    if et != ETHERTYPE_IPV4 { return None; }

    // IPv4 header at offset 14
    let ipv4 = frame.add(14);
    let vihl = *ipv4;
    if (vihl >> 4) != 4 { return None; }
    let ihl_words = (vihl & 0x0F) as usize;
    if ihl_words < 5 { return None; }
    let ip_hdr_len = ihl_words * 4;
    if len < 14 + ip_hdr_len + 20 { return None; }

    // Protocol (offset 9 within IPv4 header)
    if *ipv4.add(9) != IPPROTO_TCP { return None; }

    // Source IP (offset 12 within IPv4 header), big-endian on the wire.
    // Store as host-endian u32 for table key (endianness only matters for keying).
    let src_ip = ((*ipv4.add(12) as u32) << 24)
        | ((*ipv4.add(13) as u32) << 16)
        | ((*ipv4.add(14) as u32) << 8)
        | (*ipv4.add(15) as u32);

    // TCP header starts at frame + 14 + ip_hdr_len. Flags at offset 13.
    let tcp = frame.add(14 + ip_hdr_len);
    let flags = *tcp.add(13);

    // Pure SYN = SYN set, ACK clear. Treat SYN+ACK and other combos as already
    // part of an established or in-progress connection.
    if (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0 {
        Some(src_ip)
    } else {
        None
    }
}

// ============================================================================
// Rate table
// ============================================================================

/// Decide whether a SYN from `src_ip` at `now_ms` should be admitted.
/// Updates the table in place. Returns true to admit, false to drop.
unsafe fn admit_syn(s: &mut GuardState, src_ip: u32, now_ms: u32) -> bool {
    let table_size = s.rate_table_size as usize;
    if table_size == 0 { return true; }

    let limit = s.rate_limit_per_ip;
    let window = s.rate_window_ms as u32;

    let base = s.table.as_mut_ptr();

    // 1) Look for existing entry.
    let mut i = 0usize;
    while i < table_size {
        let e = base.add(i);
        if (*e).ip == src_ip && src_ip != 0 {
            let elapsed = now_ms.wrapping_sub((*e).last_ms);
            if elapsed >= window {
                // Window expired — reset counter for this IP.
                (*e).count = 1;
                (*e).last_ms = now_ms;
                return true;
            } else {
                let c = (*e).count.saturating_add(1);
                (*e).count = c;
                // Don't update last_ms inside the window — the window is
                // anchored at the first SYN of the burst.
                return c <= limit;
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
    (*e).last_ms = now_ms;
    (*e).count = 1;
    true
}

// ============================================================================
// Module ABI
// ============================================================================

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize { STATE_SIZE }

#[unsafe(no_mangle)]
#[link_section = ".text.module_arena_size"]
pub extern "C" fn module_arena_size() -> u32 { 0 }

#[unsafe(no_mangle)]
#[link_section = ".text.module_init"]
pub unsafe extern "C" fn module_init(_syscalls: *const c_void) {}

#[unsafe(no_mangle)]
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
    let s = unsafe { &mut *(state as *mut GuardState) };
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    s._ctrl_chan = ctrl_chan;

    let base = s.table.as_mut_ptr();
    let mut i = 0usize;
    while i < MAX_TABLE {
        unsafe { *base.add(i) = RateEntry::empty(); }
        i += 1;
    }

    s.passed = 0;
    s.dropped_syn = 0;
    s.dropped_full = 0;

    unsafe {
        params_def::set_defaults(s);
        if !params.is_null() && params_len > 0 {
            let mut off = 0usize;
            while off + 2 <= params_len {
                let tag = *params.add(off);
                let len = *params.add(off + 1) as usize;
                off += 2;
                if off + len > params_len { break; }
                params_def::dispatch_param(s, tag, params.add(off), len);
                off += len;
            }
        }
    }
    0
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut GuardState);
    let sys = &*s.syscalls;

    if s.in_chan < 0 || s.out_chan < 0 { return 0; }

    // Need at least the 2-byte length prefix to be ready.
    let poll = (sys.channel_poll)(s.in_chan, 0x01); // POLL_IN
    if poll <= 0 || (poll as u32 & 0x01) == 0 { return 0; }

    // Read the length prefix directly into the staging buffer.
    let buf = s.frame_buf.as_mut_ptr();
    let hn = (sys.channel_read)(s.in_chan, buf, 2);
    if hn < 2 { return 0; }
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
    let pass = if let Some(src_ip) = classify_syn(frame_ptr, frame_len) {
        let now_ms = dev_millis(sys) as u32;
        let admit = admit_syn(s, src_ip, now_ms);
        if !admit { s.dropped_syn = s.dropped_syn.wrapping_add(1); }
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
