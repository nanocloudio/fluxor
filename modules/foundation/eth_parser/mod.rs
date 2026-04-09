//! Ethernet/IP Header Parser PIC Module
//!
//! Reads raw Ethernet frames from input channel, parses headers, and outputs
//! parsed packet metadata + payload to the output channel.
//!
//! # Channels
//!
//! - `in[0]`: Raw Ethernet frames (from NIC driver)
//! - `out[0]`: Parsed packets: 20-byte metadata header + payload
//!
//! # Output Format
//!
//! Each output message is prefixed with a 20-byte metadata header:
//! ```text
//! [0..1]   ethertype (u16 BE)
//! [2..5]   src_ip (u32 BE, 0 if not IPv4)
//! [6..9]   dst_ip (u32 BE, 0 if not IPv4)
//! [10]     ip_proto (u8, 0 if not IP)
//! [11..12] src_port (u16 BE, 0 if not TCP/UDP)
//! [13..14] dst_port (u16 BE, 0 if not TCP/UDP)
//! [15..16] payload_offset (u16 LE, offset to L4 payload in original frame)
//! [17..18] payload_len (u16 LE, length of L4 payload)
//! [19]     flags (bit 0 = IPv4, bit 1 = TCP, bit 2 = UDP, bit 3 = ICMP)
//! [20..]   original frame payload (from L3 header onward)
//! ```

#![no_std]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");

// ============================================================================
// Constants
// ============================================================================

const MAX_FRAME: usize = 1514;
const META_SIZE: usize = 20;
const ETH_HLEN: usize = 14;
const IPV4_MIN_HLEN: usize = 20;

// Ethertypes (big-endian on wire)
const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const ETH_P_IPV6: u16 = 0x86DD;

// IP protocols
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// Flags
const FLAG_IPV4: u8 = 1 << 0;
const FLAG_TCP: u8 = 1 << 1;
const FLAG_UDP: u8 = 1 << 2;
const FLAG_ICMP: u8 = 1 << 3;

const STATE_SIZE: usize = 64;

// ============================================================================
// State
// ============================================================================

#[repr(C)]
struct ParserState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    out_chan: i32,
    _ctrl_chan: i32,
    frames_parsed: u32,
    frames_dropped: u32,
}

// ============================================================================
// Parser logic
// ============================================================================

unsafe fn parse_and_forward(s: &mut ParserState, frame: *const u8, frame_len: usize) {
    if frame_len < ETH_HLEN { return; }
    let sys = &*s.syscalls;

    // Read ethertype (bytes 12-13, big-endian)
    let ethertype = ((*frame.add(12) as u16) << 8) | (*frame.add(13) as u16);

    let mut meta = [0u8; META_SIZE];
    let mp = meta.as_mut_ptr();
    // Ethertype
    *mp.add(0) = (ethertype >> 8) as u8;
    *mp.add(1) = ethertype as u8;

    let mut payload_offset: u16 = ETH_HLEN as u16;
    let mut payload_len: u16 = 0;
    let mut flags: u8 = 0;

    if ethertype == ETH_P_IPV4 && frame_len >= ETH_HLEN + IPV4_MIN_HLEN {
        flags |= FLAG_IPV4;
        let ip = frame.add(ETH_HLEN);

        // IP header length (IHL, lower nibble of byte 0, in 32-bit words)
        let ihl = ((*ip) & 0x0F) as usize;
        let ip_hlen = ihl * 4;
        if ip_hlen < IPV4_MIN_HLEN || ETH_HLEN + ip_hlen > frame_len {
            s.frames_dropped = s.frames_dropped.wrapping_add(1);
            return;
        }

        // Total length
        let ip_total = ((*ip.add(2) as u16) << 8) | (*ip.add(3) as u16);

        // Protocol
        let proto = *ip.add(9);
        *mp.add(10) = proto;

        // Source IP (bytes 12-15)
        *mp.add(2) = *ip.add(12);
        *mp.add(3) = *ip.add(13);
        *mp.add(4) = *ip.add(14);
        *mp.add(5) = *ip.add(15);

        // Dest IP (bytes 16-19)
        *mp.add(6) = *ip.add(16);
        *mp.add(7) = *ip.add(17);
        *mp.add(8) = *ip.add(18);
        *mp.add(9) = *ip.add(19);

        let l4_offset = ETH_HLEN + ip_hlen;

        match proto {
            IPPROTO_TCP => {
                flags |= FLAG_TCP;
                if frame_len >= l4_offset + 4 {
                    let l4 = frame.add(l4_offset);
                    *mp.add(11) = *l4.add(0); *mp.add(12) = *l4.add(1); // src port
                    *mp.add(13) = *l4.add(2); *mp.add(14) = *l4.add(3); // dst port
                    // TCP header length from data offset field
                    if frame_len >= l4_offset + 13 {
                        let tcp_hlen = (((*l4.add(12)) >> 4) as usize) * 4;
                        payload_offset = (l4_offset + tcp_hlen) as u16;
                        let ip_payload = ip_total as usize - ip_hlen;
                        if tcp_hlen <= ip_payload {
                            payload_len = (ip_payload - tcp_hlen) as u16;
                        }
                    }
                }
            }
            IPPROTO_UDP => {
                flags |= FLAG_UDP;
                if frame_len >= l4_offset + 4 {
                    let l4 = frame.add(l4_offset);
                    *mp.add(11) = *l4.add(0); *mp.add(12) = *l4.add(1);
                    *mp.add(13) = *l4.add(2); *mp.add(14) = *l4.add(3);
                    payload_offset = (l4_offset + 8) as u16;
                    if frame_len >= l4_offset + 8 {
                        let udp_len = ((*l4.add(4) as u16) << 8) | (*l4.add(5) as u16);
                        if udp_len >= 8 {
                            payload_len = udp_len - 8;
                        }
                    }
                }
            }
            IPPROTO_ICMP => {
                flags |= FLAG_ICMP;
                payload_offset = l4_offset as u16;
                let ip_payload = ip_total as usize - ip_hlen;
                payload_len = ip_payload as u16;
            }
            _ => {
                payload_offset = l4_offset as u16;
            }
        }
    }

    *mp.add(15) = payload_offset as u8;
    *mp.add(16) = (payload_offset >> 8) as u8;
    *mp.add(17) = payload_len as u8;
    *mp.add(18) = (payload_len >> 8) as u8;
    *mp.add(19) = flags;

    // Write metadata + L3+ payload to output
    // For zero-copy we'd use mailbox; for now use channel_write twice
    (sys.channel_write)(s.out_chan, meta.as_ptr(), META_SIZE);
    if frame_len > ETH_HLEN {
        (sys.channel_write)(s.out_chan, frame.add(ETH_HLEN), frame_len - ETH_HLEN);
    }

    s.frames_parsed = s.frames_parsed.wrapping_add(1);
}

// ============================================================================
// Module ABI
// ============================================================================

#[unsafe(no_mangle)]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> usize { STATE_SIZE }

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
    syscalls: *const SyscallTable,
) -> i32 {
    let s = unsafe { &mut *(state as *mut ParserState) };
    s.syscalls = syscalls;
    s.in_chan = in_chan;
    s.out_chan = out_chan;
    s._ctrl_chan = ctrl_chan;
    s.frames_parsed = 0;
    s.frames_dropped = 0;
    0
}

#[unsafe(no_mangle)]
#[link_section = ".text.module_step"]
pub unsafe extern "C" fn module_step(state: *mut c_void) -> i32 {
    let s = &mut *(state as *mut ParserState);
    let sys = &*s.syscalls;

    // Read frame from input channel
    let mut buf = [0u8; MAX_FRAME];
    let n = (sys.channel_read)(s.in_chan, buf.as_mut_ptr(), MAX_FRAME);
    if n > 0 {
        parse_and_forward(s, buf.as_ptr(), n as usize);
        return 2; // Burst (may have more frames)
    }

    0 // Continue
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
