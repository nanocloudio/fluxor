//! Debug PIC Module
//!
//! Diagnostic module that reads data from an input channel, computes an
//! FNV-1a hash over each 1024-byte block, and logs the result.
//!
//! Combines the former `digest` and `logger` modules into a single stage.
//!
//! **Params:**
//!   [0]: log_level (u8, default 3 = INFO)
//!
//! **Pipeline:** sd -> debug  (replaces sd -> digest -> logger)

#![no_std]

use core::ffi::c_void;

#[path = "../../src/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../pic_runtime.rs");
include!("../param_macro.rs");

// ============================================================================
// Constants
// ============================================================================

/// Input size: 2 blocks (1024 bytes) to match fluxor.test
const INPUT_SIZE: usize = 1024;

/// FNV-1a parameters
const FNV_OFFSET: u32 = 0x811c9dc5;
const FNV_PRIME: u32 = 0x01000193;

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

// ============================================================================
// Module State
// ============================================================================

#[repr(C)]
struct DebugState {
    syscalls: *const SyscallTable,
    in_chan: i32,
    /// Bytes accumulated so far
    input_accum: usize,
    /// Accumulation buffer for hashing
    input_buf: [u8; INPUT_SIZE],
    /// Block counter for log output
    block_count: u32,
    /// Log level (default 3 = INFO)
    log_level: u8,
    /// Mode: 0 = hash (default), 1 = plaintext
    mode: u8,
}

impl DebugState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.in_chan = -1;
        self.input_accum = 0;
        self.block_count = 0;
        self.log_level = 3;
        self.mode = 0;
    }

    unsafe fn sys(&self) -> &SyscallTable {
        &*self.syscalls
    }
}

// ============================================================================
// Parameter Definitions
// ============================================================================

mod params_def {
    use super::DebugState;
    use super::p_u8;
    use super::SCHEMA_MAX;

    define_params! {
        DebugState;

        1, log_level, u8, 3, enum { error=1, warn=2, info=3, debug=4, trace=5 }
            => |s, d, len| { s.log_level = p_u8(d, len, 0, 3); };

        2, mode, u8, 0, enum { hash=0, plaintext=1 }
            => |s, d, len| { s.mode = p_u8(d, len, 0, 0); };
    }
}

// ============================================================================
// FNV-1a hash
// ============================================================================

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ============================================================================
// Exported functions
// ============================================================================

#[no_mangle]
#[link_section = ".text.module_state_size"]
pub extern "C" fn module_state_size() -> u32 {
    core::mem::size_of::<DebugState>() as u32
}

#[no_mangle]
#[link_section = ".text.module_init"]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[no_mangle]
#[link_section = ".text.module_new"]
pub extern "C" fn module_new(
    in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<DebugState>() {
            return -3;
        }

        let s = &mut *(state as *mut DebugState);
        s.init(syscalls as *const SyscallTable);
        s.in_chan = in_chan;

        // Parse params
        let is_tlv = !params.is_null() && params_len >= 4
            && *params == 0xFE && *params.add(1) == 0x01;

        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else if !params.is_null() && params_len >= 1 {
            s.log_level = *params;
        } else {
            params_def::set_defaults(s);
        }

        0
    }
}

/// Step: read input, accumulate 1024 bytes, hash, log.
/// Returns: 0 = continue, 1 = done, -1 = error
#[no_mangle]
#[link_section = ".text.module_step"]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    unsafe {
        if state.is_null() {
            return -1;
        }
        let s = &mut *(state as *mut DebugState);

        if s.syscalls.is_null() || s.in_chan < 0 {
            return -1;
        }

        // Read into buffer at current accumulation offset
        let remaining = INPUT_SIZE.saturating_sub(s.input_accum);
        if remaining == 0 {
            s.input_accum = 0;
            return 0;
        }

        let dst = s.input_buf.as_mut_ptr().add(s.input_accum);
        let bytes_read = (s.sys().channel_read)(s.in_chan, dst, remaining);

        if bytes_read == E_AGAIN {
            return 0;
        }

        if bytes_read < 0 {
            return -1;
        }

        if bytes_read == 0 {
            return 1; // EOF
        }

        s.input_accum += bytes_read as usize;

        // Plaintext mode: log data as-is, no accumulation
        if s.mode == 1 {
            let start = s.input_accum - bytes_read as usize;
            dev_log(s.sys(), s.log_level, s.input_buf.as_ptr().add(start), bytes_read as usize);
            s.input_accum = 0;
            return 0;
        }

        // Compute hash and log when we have a full block
        if s.input_accum >= INPUT_SIZE {
            let data = core::slice::from_raw_parts(s.input_buf.as_ptr(), INPUT_SIZE);
            let hash = fnv1a32(data);

            // Format: "hash iter 000 hash 0x00000000"
            let mut msg: [u8; 32] = *b"hash iter 000 hash 0x00000000  \0";

            let n = s.block_count;
            msg[10] = b'0' + ((n / 100) % 10) as u8;
            msg[11] = b'0' + ((n / 10) % 10) as u8;
            msg[12] = b'0' + (n % 10) as u8;

            for i in 0..8 {
                let nibble = ((hash >> (28 - i * 4)) & 0xF) as usize;
                msg[22 + i] = HEX_CHARS[nibble];
            }

            dev_log(s.sys(), s.log_level, msg.as_ptr(), 30);

            s.block_count += 1;
            s.input_accum = 0;
        }

        0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
