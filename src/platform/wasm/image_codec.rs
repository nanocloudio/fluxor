//! `wasm_browser_image_codec` built-in: encoded-image → RGB565
//! transformer that delegates the actual decode to the browser via
//! `createImageBitmap` + `OffscreenCanvas`.
//!
//! Wasm-host analogue of `host_image_codec` on linux (which uses the
//! `image` crate). Same contract: `encoded` in (OctetStream),
//! `pixels` out (VideoRaster, RGB565 LE), params `width`/`height`/
//! `max_bytes`.
//!
//! State machine, per-step:
//!
//!   ```text
//!   ┌─────────────┐  POLL_HUP on in_chan      ┌─────────────┐
//!   │ Collecting  │ ───────────────────────► │  Decoding   │
//!   │ (read       │                          │ (host_image_│
//!   │  encoded)   │                          │  decode_open│
//!   └─────────────┘                          │  +_size)    │
//!                                            └──────┬──────┘
//!                                                   │ size > 0
//!                                                   ▼
//!                            ┌────────────────────────────────────┐
//!                            │           Outputting               │
//!                            │  loop:                             │
//!                            │    host_image_decode_recv → buf    │
//!                            │    channel_write(out, buf)         │
//!                            └────────────────┬───────────────────┘
//!                                             │ all bytes drained
//!                                             ▼
//!                            ┌────────────────────────────────────┐
//!                            │             Done                   │
//!                            │  IOCTL_SET_HUP on out;             │
//!                            │  host_image_decode_close           │
//!                            └────────────────────────────────────┘
//!   ```
//!
//! Synchronous-looking from the kernel side; the browser shim hides
//! `createImageBitmap`'s async-ness behind the same poll-then-pull
//! pattern as `host_browser_fetch`.

use crate::kernel::{channel, scheduler, syscalls};

extern "C" {
    /// Hand the entire encoded image to the browser shim along with
    /// the target dimensions. Returns a non-negative handle on
    /// success, or a negative error. Decode kicks off asynchronously
    /// — the kernel polls `host_image_decode_size` to wait for it
    /// to complete.
    fn host_image_decode_open(
        enc_ptr: *const u8,
        enc_len: usize,
        width: u32,
        height: u32,
    ) -> i32;

    /// Returns the decoded RGB565 buffer length once the decode
    /// has completed. While the decode is still in flight, returns
    /// `-3`. On hard failure, returns `-2`. Until commit, returns
    /// `-1` — call again next tick.
    ///
    ///   `>= 0` decoded; value is the bytes available to drain
    ///   `-1`   pending (decode promise still resolving)
    ///   `-2`   error (createImageBitmap rejected, etc.)
    ///   `-3`   handle unknown
    fn host_image_decode_size(handle: i32) -> i32;

    /// Drain bytes from the decoded RGB565 buffer into `buf`.
    /// Returns:
    ///   `> 0` bytes written;
    ///   `= 0` no bytes left to drain (frame complete);
    ///   `< 0` error.
    fn host_image_decode_recv(handle: i32, buf: *mut u8, len: usize) -> i32;

    /// Drop the host-side handle. Idempotent on unknown handles.
    fn host_image_decode_close(handle: i32) -> i32;
}

/// Per-`channel_write` chunk size — same rationale as fetch.rs's
/// `WRITE_CHUNK_BYTES`. Channel ring buffer is all-or-nothing on
/// writes; small chunks fit even in mid-drain states.
const WRITE_CHUNK_BYTES: usize = 512;

/// Per-`host_image_decode_recv` chunk size. The kernel-side scratch
/// buffer can be small because the browser holds the entire decoded
/// frame and feeds it to us in arbitrarily-sized requests.
const RX_CHUNK_BYTES: usize = 4096;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Collecting = 0,
    Decoding   = 1,
    Outputting = 2,
    Done       = 3,
    Error      = 4,
}

/// Codec state — small, fixed-size. The encoded ingest buffer is
/// heap-allocated separately (sized to `max_bytes`) so the State
/// struct can stay tiny and not blow past the per-module heap.
#[repr(C)]
pub(crate) struct ImageCodecState {
    pub in_chan:     i32,
    pub out_chan:    i32,
    pub width:       u16,
    pub height:      u16,
    pub max_bytes:   u32,

    pub phase:       u8,        // Phase
    pub _pad:        [u8; 3],

    pub handle:      i32,
    pub encoded_len: u32,

    /// Per-tick read scratch from `host_image_decode_recv`.
    pub rx:          [u8; RX_CHUNK_BYTES],
    /// Bytes pulled from the shim but not yet accepted by
    /// `channel_write` (back-pressure). `[pending_pos..pending_len)`
    /// of `rx` is queued.
    pub pending_pos: u32,
    pub pending_len: u32,

    /// Heap-allocated encoded-ingest buffer (capacity = max_bytes).
    /// Producer writes into `encoded[..encoded_len]` until HUP.
    pub encoded_ptr: *mut u8,
    pub encoded_cap: u32,
}

/// Public — used by `wasm.rs` to size the per-module heap. The
/// per-module heap must hold the State struct plus the encoded
/// buffer plus a small overhead. Allocations come out of
/// STATE_ARENA so this is the one knob the wiring code consults.
pub(crate) fn heap_size_for(max_bytes: u32) -> usize {
    core::mem::size_of::<ImageCodecState>() + max_bytes as usize + 256
}

unsafe fn alloc_state(
    in_chan: i32,
    out_chan: i32,
    width: u16,
    height: u16,
    max_bytes: u32,
) -> *mut ImageCodecState {
    let table = syscalls::get_syscall_table();
    let state_size = core::mem::size_of::<ImageCodecState>() as u32;
    let raw = (table.heap_alloc)(state_size) as *mut ImageCodecState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    let encoded = (table.heap_alloc)(max_bytes);
    if encoded.is_null() {
        // State is allocated but encoded buffer wasn't — leave the
        // State allocated (per-module heap is reset on graph swap)
        // and signal failure to caller.
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        ImageCodecState {
            in_chan,
            out_chan,
            width,
            height,
            max_bytes,
            phase: Phase::Collecting as u8,
            _pad: [0; 3],
            handle: -1,
            encoded_len: 0,
            rx: [0u8; RX_CHUNK_BYTES],
            pending_pos: 0,
            pending_len: 0,
            encoded_ptr: encoded,
            encoded_cap: max_bytes,
        },
    );
    raw
}

fn step(state: *mut u8) -> i32 {
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut ImageCodecState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;

        match st.phase {
            x if x == Phase::Collecting as u8 => collect_step(st),
            x if x == Phase::Decoding as u8   => decoding_step(st),
            x if x == Phase::Outputting as u8 => outputting_step(st),
            _ => 0,
        }
    }
}

unsafe fn collect_step(st: &mut ImageCodecState) -> i32 {
    if st.in_chan < 0 {
        return 0;
    }

    // Drain any available bytes. Cap at encoded_cap — anything past
    // that and we transition to decode with what we have rather than
    // truncate silently.
    loop {
        let cap = st.encoded_cap as usize;
        let used = st.encoded_len as usize;
        if used >= cap {
            // Buffer full but no HUP yet — decode what we have.
            transition_to_decode(st);
            return 0;
        }
        let n = channel::channel_read(
            st.in_chan,
            st.encoded_ptr.add(used),
            cap - used,
        );
        if n > 0 {
            st.encoded_len = (used + n as usize) as u32;
            continue;
        }
        // n == 0: no data this tick; check for HUP to decide whether
        // to transition.
        let poll = channel::channel_poll(st.in_chan, channel::POLL_HUP);
        if poll > 0 && (poll as u32 & channel::POLL_HUP) != 0 {
            if st.encoded_len == 0 {
                // Producer EOFed without sending anything — nothing
                // to decode. Mark done.
                st.phase = Phase::Done as u8;
                let _ = channel::channel_ioctl(
                    st.out_chan,
                    channel::IOCTL_SET_HUP,
                    core::ptr::null_mut(),
                );
                return 0;
            }
            transition_to_decode(st);
            return 0;
        }
        // No data, no HUP — wait for more.
        return 0;
    }
}

unsafe fn transition_to_decode(st: &mut ImageCodecState) {
    let h = host_image_decode_open(
        st.encoded_ptr,
        st.encoded_len as usize,
        st.width as u32,
        st.height as u32,
    );
    if h < 0 {
        st.phase = Phase::Error as u8;
        let _ = channel::channel_ioctl(
            st.out_chan,
            channel::IOCTL_SET_HUP,
            core::ptr::null_mut(),
        );
        return;
    }
    st.handle = h;
    st.phase = Phase::Decoding as u8;
}

unsafe fn decoding_step(st: &mut ImageCodecState) -> i32 {
    let size = host_image_decode_size(st.handle);
    match size {
        s if s >= 0 => {
            // Ready — start streaming out. (Size value itself isn't
            // needed: width*height*2 is the contract; we just trust
            // host_image_decode_recv to return EOF when drained.)
            st.phase = Phase::Outputting as u8;
        }
        -1 => {
            // Pending — try again next tick.
        }
        _ => {
            st.phase = Phase::Error as u8;
            let _ = host_image_decode_close(st.handle);
            st.handle = -1;
            let _ = channel::channel_ioctl(
                st.out_chan,
                channel::IOCTL_SET_HUP,
                core::ptr::null_mut(),
            );
        }
    }
    0
}

unsafe fn outputting_step(st: &mut ImageCodecState) -> i32 {
    if st.out_chan < 0 {
        return 0;
    }

    loop {
        // Phase 1: drain any pending tail from a back-pressured
        // write last tick.
        while st.pending_pos < st.pending_len {
            let start = st.pending_pos as usize;
            let remaining = (st.pending_len - st.pending_pos) as usize;
            let want = remaining.min(WRITE_CHUNK_BYTES);
            let written = channel::channel_write(
                st.out_chan,
                st.rx.as_ptr().add(start),
                want,
            );
            if written <= 0 {
                return 0;
            }
            st.pending_pos += written as u32;
        }
        st.pending_pos = 0;
        st.pending_len = 0;

        // Phase 2: pull more decoded bytes from the shim.
        let n = host_image_decode_recv(st.handle, st.rx.as_mut_ptr(), st.rx.len());
        if n == 0 {
            // Frame fully drained — release host handle, signal HUP
            // downstream, transition to Done.
            let _ = host_image_decode_close(st.handle);
            st.handle = -1;
            st.phase = Phase::Done as u8;
            let _ = channel::channel_ioctl(
                st.out_chan,
                channel::IOCTL_SET_HUP,
                core::ptr::null_mut(),
            );
            return 0;
        }
        if n < 0 {
            st.phase = Phase::Error as u8;
            let _ = host_image_decode_close(st.handle);
            st.handle = -1;
            let _ = channel::channel_ioctl(
                st.out_chan,
                channel::IOCTL_SET_HUP,
                core::ptr::null_mut(),
            );
            return 0;
        }
        let total = n as usize;
        let mut off = 0usize;
        while off < total {
            let want = (total - off).min(WRITE_CHUNK_BYTES);
            let written = channel::channel_write(
                st.out_chan,
                st.rx.as_ptr().add(off),
                want,
            );
            if written <= 0 {
                st.pending_pos = off as u32;
                st.pending_len = total as u32;
                return 0;
            }
            off += written as usize;
        }
    }
}

pub(crate) unsafe fn build(
    in_chan: i32,
    out_chan: i32,
    width: u16,
    height: u16,
    max_bytes: u32,
) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_image_codec", step);
    let raw = alloc_state(in_chan, out_chan, width, height, max_bytes);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut ImageCodecState, raw);
    m
}
