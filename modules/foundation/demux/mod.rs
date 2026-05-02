//! RX demultiplexer for horizontal-scaled IP+TLS lanes.
//!
//! Sits between the NIC driver and two parallel IP+TLS+HTTP pipelines:
//!
//!   rp1_gem.frames_rx → demux.frames_rx
//!   demux.lane_0      → ip_0.frames_rx
//!   demux.lane_1      → ip_1.frames_rx
//!
//! For TCP/IPv4 frames the 4-tuple (src_ip, dst_ip, src_port, dst_port) is
//! hashed and the low bit selects a lane — giving stable connection
//! affinity so all segments of a TCP connection land on the same lane.
//! Everything else (ARP, DHCP, non-TCP) is broadcast to both lanes so
//! control-plane traffic still reaches each IP instance. Frames use the
//! same `[len:u16 LE][frame...]` framing as the NIC ⇄ IP byte stream.

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

const MAX_FRAME: usize = 1600;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;

#[repr(C)]
pub struct DemuxState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    lane0_chan: i32,
    lane1_chan: i32,
    _ctrl_chan: i32,
    to_lane0: u32,
    to_lane1: u32,
    broadcast: u32,
    frame_buf: [u8; 2 + MAX_FRAME],
}

const STATE_SIZE: usize = core::mem::size_of::<DemuxState>();

/// Pick a lane index (0 or 1) based on the IPv4/TCP 4-tuple, or None for
/// non-TCP/IPv4 frames.
unsafe fn classify_lane(frame: *const u8, len: usize) -> Option<u8> {
    if len < 14 + 20 { return None; }
    let et = ((*frame.add(12) as u16) << 8) | (*frame.add(13) as u16);
    if et != ETHERTYPE_IPV4 { return None; }
    let ipv4 = frame.add(14);
    let vihl = *ipv4;
    if (vihl >> 4) != 4 { return None; }
    let ihl_words = (vihl & 0x0F) as usize;
    if ihl_words < 5 { return None; }
    let ip_hdr_len = ihl_words * 4;
    if len < 14 + ip_hdr_len + 4 { return None; }
    if *ipv4.add(9) != IPPROTO_TCP { return None; }

    let src_ip = ((*ipv4.add(12) as u32) << 24)
        | ((*ipv4.add(13) as u32) << 16)
        | ((*ipv4.add(14) as u32) << 8)
        | (*ipv4.add(15) as u32);
    let dst_ip = ((*ipv4.add(16) as u32) << 24)
        | ((*ipv4.add(17) as u32) << 16)
        | ((*ipv4.add(18) as u32) << 8)
        | (*ipv4.add(19) as u32);
    let tcp = frame.add(14 + ip_hdr_len);
    let src_port = ((*tcp as u32) << 8) | (*tcp.add(1) as u32);
    let dst_port = ((*tcp.add(2) as u32) << 8) | (*tcp.add(3) as u32);

    let mut h = src_ip ^ dst_ip ^ (src_port << 16) ^ dst_port;
    // Finalise with an FNV-style mix so small perturbations in the tuple
    // reach the low bit we select on.
    h = h.wrapping_mul(0x9E3779B1);
    h ^= h >> 16;
    Some((h & 1) as u8)
}

unsafe fn write_framed(sys: &SyscallTable, chan: i32, buf: *const u8, total: usize) -> bool {
    if chan < 0 { return false; }
    let poll = (sys.channel_poll)(chan, 0x02);
    if poll <= 0 || (poll as u32 & 0x02) == 0 { return false; }
    (sys.channel_write)(chan, buf, total);
    true
}

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
    _params: *const u8,
    _params_len: usize,
    state: *mut u8,
    _state_size: usize,
    syscalls: *const SyscallTable,
) -> i32 {
    let s = unsafe { &mut *(state as *mut DemuxState) };
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.lane0_chan = out_chan;
    s.lane1_chan = -1;
    s._ctrl_chan = ctrl_chan;
    s.to_lane0 = 0;
    s.to_lane1 = 0;
    s.broadcast = 0;

    // Second output port (out[1]) is discovered via dev_channel_port.
    unsafe {
        let sys = &*s.syscalls;
        s.lane1_chan = dev_channel_port(sys, 1, 1);
    }
    0
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut DemuxState);
    let sys = &*s.syscalls;

    if s.in_chan < 0 { return 0; }

    let poll = (sys.channel_poll)(s.in_chan, 0x01);
    if poll <= 0 || (poll as u32 & 0x01) == 0 { return 0; }

    let buf = s.frame_buf.as_mut_ptr();
    let hn = (sys.channel_read)(s.in_chan, buf, 2);
    if hn < 2 { return 0; }
    let frame_len = (*buf as usize) | ((*buf.add(1) as usize) << 8);
    if frame_len == 0 || frame_len > MAX_FRAME { return 0; }

    let r = (sys.channel_read)(s.in_chan, buf.add(2), frame_len);
    if r < frame_len as i32 { return 0; }

    let total = 2 + frame_len;
    let frame_ptr = buf.add(2) as *const u8;
    match classify_lane(frame_ptr, frame_len) {
        Some(0) => {
            if write_framed(sys, s.lane0_chan, buf as *const u8, total) {
                s.to_lane0 = s.to_lane0.wrapping_add(1);
            }
        }
        Some(_) => {
            if write_framed(sys, s.lane1_chan, buf as *const u8, total) {
                s.to_lane1 = s.to_lane1.wrapping_add(1);
            }
        }
        None => {
            // Broadcast: control-plane traffic reaches both IP instances.
            let a = write_framed(sys, s.lane0_chan, buf as *const u8, total);
            let b = write_framed(sys, s.lane1_chan, buf as *const u8, total);
            if a || b { s.broadcast = s.broadcast.wrapping_add(1); }
        }
    }

    2 // Burst
}

// Wasm entry-point wrappers — no-op on non-wasm targets. See
// `modules/sdk/wasm_entry.rs` for the wasm32 module_init_wasm /
// module_step_wasm definitions.
include!("../../sdk/wasm_entry.rs");
