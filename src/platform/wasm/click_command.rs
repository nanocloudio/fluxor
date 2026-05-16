//! `wasm_browser_click_command` built-in: pointer-event → FMP
//! command transformer.
//!
//! Drops everything except `KIND_UP` (the user lifted a contact —
//! the canonical "click" trigger that matches both mouse-up and
//! touch-end). For each KIND_UP it emits one FMP message on the
//! output channel:
//!
//!   * primary button (left-click / touch)        →  `next`
//!   * secondary button (right-click / 2-finger)  →  `prev`
//!
//! The output is the canonical bank navigation contract — the same
//! FMP wire that a hardware "next track" button would emit. Pure-
//! wasm graphs wire this directly to `bank.commands`; split graphs
//! pipe it through `wasm_browser_websocket.tx_in` so the linux /
//! cm5 producer-side bank receives the same FMP bytes over the
//! WebSocket. Single module, single contract, same shape across
//! every deployment.
//!
//! No double-click / long-press in v1 — those can be added without
//! changing the contract.

use crate::kernel::{channel, scheduler, syscalls};

/// Pointer MSG_EVENT record (16 bytes), must match
/// `modules/sdk/contracts/input/pointer.rs::EVENT_SIZE`.
const POINTER_EVENT_SIZE: usize = 16;

/// FMP message header layout used by `bank.commands`:
/// `[msg_type:u32 LE][payload_len:u16 LE]`. We always emit a 6-byte
/// command with `payload_len = 0` — same as a hardware navigation
/// button.
const FMP_HDR_SIZE: usize = 6;

/// `fnv1a32` of `"next"` — must match
/// `modules/sdk/runtime.rs::MSG_NEXT`.
const MSG_NEXT: u32 = 0x5cb68de8;
/// `fnv1a32` of `"prev"` — must match
/// `modules/sdk/runtime.rs::MSG_PREV`.
const MSG_PREV: u32 = 0xcf2ef7b0;

/// Pointer event-kind constants — mirror
/// `modules/sdk/contracts/input/pointer.rs::KIND_*`.
const KIND_UP: u8 = 2;

/// Buttons bitfield — mirror
/// `modules/sdk/contracts/input/pointer.rs::BTN_SECONDARY`.
const BTN_SECONDARY: u8 = 0x02;

#[repr(C)]
pub(crate) struct ClickCommandState {
    pub in_chan: i32,
    pub out_chan: i32,
    pub in_buf: [u8; POINTER_EVENT_SIZE],
    pub out_buf: [u8; FMP_HDR_SIZE],
}

unsafe fn alloc_state(in_chan: i32, out_chan: i32) -> *mut ClickCommandState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<ClickCommandState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut ClickCommandState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        ClickCommandState {
            in_chan,
            out_chan,
            in_buf: [0u8; POINTER_EVENT_SIZE],
            out_buf: [0u8; FMP_HDR_SIZE],
        },
    );
    raw
}

fn click_command_step(state: *mut u8) -> i32 {
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut ClickCommandState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.in_chan < 0 || st.out_chan < 0 {
            return 0;
        }

        loop {
            let n = channel::channel_read(
                st.in_chan,
                st.in_buf.as_mut_ptr(),
                st.in_buf.len(),
            );
            if n <= 0 {
                break;
            }
            if (n as usize) < POINTER_EVENT_SIZE {
                continue;
            }

            let kind = st.in_buf[2];
            let buttons = st.in_buf[3];
            // Only "click" (KIND_UP) triggers a command. Down/move/
            // cancel/enter/leave are dropped — the bank cycles on
            // release, matching the JS-shell heuristic the runtime
            // shell used to apply itself.
            if kind != KIND_UP {
                continue;
            }

            let msg_type: u32 = if (buttons & BTN_SECONDARY) != 0 {
                MSG_PREV
            } else {
                MSG_NEXT
            };

            // Build the 6-byte FMP header: [msg_type:u32 LE]
            // [payload_len:u16 LE = 0]. No payload bytes for
            // next/prev — bank's command dispatch keys off msg_type
            // alone.
            let mt = msg_type.to_le_bytes();
            st.out_buf[0] = mt[0];
            st.out_buf[1] = mt[1];
            st.out_buf[2] = mt[2];
            st.out_buf[3] = mt[3];
            st.out_buf[4] = 0;
            st.out_buf[5] = 0;
            let _ = channel::channel_write(
                st.out_chan,
                st.out_buf.as_ptr(),
                FMP_HDR_SIZE,
            );
        }
        0
    }
}

pub(crate) unsafe fn build(in_chan: i32, out_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_click_command", click_command_step);
    let raw = alloc_state(in_chan, out_chan);
    core::ptr::write(
        m.state.as_mut_ptr() as *mut *mut ClickCommandState,
        raw,
    );
    m
}
