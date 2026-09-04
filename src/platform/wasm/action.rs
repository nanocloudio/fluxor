//! `wasm_browser_action` built-in: browser-side semantic-action source.
//!
//! The presentation-shell overlay (`browser_overlay_runtime.js`) emits an
//! opaque, *application-chosen* `action` id — `next`, `toggle`, or any
//! app-specific verb — when the user activates a control. This built-in
//! is the kernel-side conduit: it drains the host action queue and emits
//! each action-id hash **unchanged** as the FMP command type. The
//! *consumer* (a `bank` selector, a player, or any app module) decides
//! what the hash means by matching it — Fluxor carries no vocabulary of
//! its own here.
//!
//! Keeping this a pure pass-through (rather than translating a fixed
//! media/transport vocabulary into FMP verbs) is the point: an app that
//! wants the generic selector verbs names its controls `next`/`prev`/
//! `toggle` — those hash to `MSG_{NEXT,PREV,TOGGLE}` that `bank` matches —
//! and an app with its own vocabulary names them whatever it likes and
//! matches the same hash on the far side. See
//! `abi::contracts::input::action` for the wire.
//!
//! Host shim contract: `host_action_pop(buf, len)` writes one 8-byte
//! record per call — `[action_hash: u32 LE][value: f32 LE]` — or returns
//! 0 when the queue is empty. `action_hash` is the FNV-1a32 of the
//! action id string, computed identically in JS (`makeHostSinks`) and
//! here, so the two sides agree without shipping the strings on the
//! wire.

use crate::kernel::exec::scheduler;
use crate::kernel::ipc::channel;
use crate::kernel::module::syscalls;

extern "C" {
    fn host_action_pop(buf: *mut u8, len: usize) -> i32;
}

/// One host action record: hash + value, little-endian.
const RECORD_LEN: usize = 8;
/// FMP message header: `[type: u32 LE][payload_len: u16 LE]` — matches
/// `modules/sdk/runtime.rs::MSG_HDR_SIZE`.
const FMP_HDR_LEN: usize = 6;

#[repr(C)]
pub(crate) struct ActionState {
    pub out_chan: i32,
    pub buf: [u8; RECORD_LEN],
    /// A translated FMP frame that was popped from the host queue but
    /// could not be written because the output channel was full. The
    /// record is already gone from the JS `actionQueue`, so we must hold
    /// it here and retry next tick — otherwise the action is silently
    /// dropped. `pending_len == 0` means nothing is held.
    pub pending: [u8; FMP_HDR_LEN],
    pub pending_len: usize,
}

unsafe fn alloc_state(out_chan: i32) -> *mut ActionState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<ActionState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut ActionState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        ActionState {
            out_chan,
            buf: [0u8; RECORD_LEN],
            pending: [0u8; FMP_HDR_LEN],
            pending_len: 0,
        },
    );
    raw
}

fn action_step(state: *mut u8) -> i32 {
    // SAFETY: `state` is the kernel-provided opaque pointer to this
    // instance's heap state, allocated by `build`.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut ActionState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.out_chan < 0 {
            return 0;
        }

        // Drain every queued action this tick. Each pop returns exactly
        // one 8-byte record; 0 means the queue is empty.
        loop {
            // A frame popped on a previous tick but not yet accepted by
            // the channel takes priority — flush it before popping more,
            // so the popped-but-unsent action isn't lost to backpressure.
            if st.pending_len > 0 {
                let written =
                    channel::channel_write(st.out_chan, st.pending.as_ptr(), st.pending_len);
                // Require the *whole* frame to land. PIPE writes are
                // all-or-nothing (`ringbuf::write` rejects a frame that
                // does not fit, returning 0), so a complete write returns
                // exactly `pending_len`; EAGAIN is 0 and errors are
                // negative. Keying on `== pending_len` rather than `> 0`
                // means a (contract-breaking) short write can never clear
                // the pending frame and leave a truncated command that
                // desyncs `msg_read` framing downstream.
                if written != st.pending_len as i32 {
                    break; // not fully accepted — keep it pending.
                }
                st.pending_len = 0;
            }
            let n = host_action_pop(st.buf.as_mut_ptr(), st.buf.len());
            if n < RECORD_LEN as i32 {
                break;
            }
            // Pass the action-id hash through unchanged as the FMP command
            // type — the consumer (bank/player/app module) matches it and
            // decides what it means. value (st.buf[4..8]) is not forwarded:
            // the FMP selector verbs (next/prev/toggle) are empty-payload,
            // and forwarding a 4-byte payload would desync their framing at
            // `bank`. A richer value-carrying consumer is a separate wire.
            // st.buf[0..4] already holds action_hash in LE.
            // Emit a zero-payload FMP frame: [action_hash: u32 LE][len=0: u16].
            let mut frame = [0u8; FMP_HDR_LEN];
            frame[0] = st.buf[0];
            frame[1] = st.buf[1];
            frame[2] = st.buf[2];
            frame[3] = st.buf[3];
            // frame[4..6] = payload_len = 0, already zeroed.
            let written = channel::channel_write(st.out_chan, frame.as_ptr(), FMP_HDR_LEN);
            if written != FMP_HDR_LEN as i32 {
                // Not fully accepted (full channel = 0, or error < 0) —
                // PIPE writes are atomic, so the frame did not partially
                // land. This record is already gone from the host queue,
                // so stash the whole frame and retry it intact next tick
                // rather than dropping the action or truncating it.
                st.pending = frame;
                st.pending_len = FMP_HDR_LEN;
                break;
            }
        }
        0
    }
}

pub(crate) unsafe fn build(out_chan: i32) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_action", action_step);
    let raw = alloc_state(out_chan);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut ActionState, raw);
    m
}
