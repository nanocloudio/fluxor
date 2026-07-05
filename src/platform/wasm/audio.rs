//! `wasm_browser_audio` built-in: AudioSample sink that forwards
//! signed-16-bit PCM blocks to the host shim's `host_audio_play`
//! import, which schedules them through WebAudio.
//!
//! Block size is opportunistic: whatever bytes are available on the
//! input channel each tick are forwarded as a unit. The shim
//! buffers and schedules to maintain continuous playback.
//!
//! State: heap-allocated; the `BuiltInModule` 64-byte inline state
//! holds a `*mut AudioState` pointer.

use crate::kernel::{channel, scheduler, syscalls};

extern "C" {
    /// Play a block of signed-16-bit PCM. `ptr`/`len` is in the
    /// kernel's linear memory; the shim copies the samples and
    /// schedules them through a WebAudio AudioContext at the
    /// configured sample rate.
    fn host_audio_play(ptr: *const u8, len: usize, sample_rate: u32, channels: u32);
    /// Whether the browser renderer can consume PCM right now. Zero ring lead is
    /// ambiguous before WebAudio has been unlocked, so readiness is a separate
    /// signal rather than being inferred from `host_audio_lead_us`.
    fn host_audio_ready() -> i32;
    /// Microseconds of audio currently buffered in the AudioWorklet ring
    /// (frames buffered ÷ sample rate), or 0 until the worklet is up and the
    /// AudioContext is running. Read straight from the audio render thread's
    /// ring fill — no wall-clock estimation, so it's exact and drift-free.
    fn host_audio_lead_us() -> u64;
}

/// Per-tick read budget. Sized to a comfortable AudioWorklet quantum
/// (128 frames × 2 channels × 2 bytes = 512 bytes minimum, with
/// headroom for stereo + small jitter buffer).
const READ_BUF_BYTES: usize = 4096;

/// Target ring depth, in microseconds. The sink forwards PCM to the
/// AudioWorklet ring only until it is this full, then HOLDS — leaving
/// decoded PCM in the input channel so back-pressure propagates upstream
/// (codec → producer → fetch) and the whole pipeline is paced to the
/// audio clock.
///
/// Without this, the sink drains its input every tick and floods the ring;
/// the ring's drop-oldest overflow path then discards audio. Holding at a
/// bounded ring depth keeps the producer matched to the 44.1 kHz audio
/// clock instead of free-running at the (much faster, when visible) frame
/// rate.
///
/// The ring (host_shims.js `createAudioScheduler` / `pcm-ring`) always plays at
/// exactly the source sample rate. This target sets its normal latency: 120 ms
/// absorbs Worker/main-thread delivery jitter while remaining comfortably below
/// the 320 ms ring cap. If production misses real time the worklet emits silence
/// and reports an underflow; it must never hide the miss by changing music pitch
/// or duration.
const LEAD_TARGET_US: u64 = 120_000;

#[repr(C)]
pub(crate) struct AudioState {
    pub in_chan: i32,
    pub sample_rate: u32,
    pub channels: u32,
    pub buf: [u8; READ_BUF_BYTES],
}

unsafe fn alloc_state(in_chan: i32, sample_rate: u32, channels: u32) -> *mut AudioState {
    let table = syscalls::get_syscall_table();
    let size = core::mem::size_of::<AudioState>() as u32;
    let raw = (table.heap_alloc)(size) as *mut AudioState;
    if raw.is_null() {
        return core::ptr::null_mut();
    }
    core::ptr::write(
        raw,
        AudioState {
            in_chan,
            sample_rate,
            channels,
            buf: [0u8; READ_BUF_BYTES],
        },
    );
    raw
}

fn audio_step(state: *mut u8) -> i32 {
    // SAFETY: state is the kernel-provided opaque state pointer for
    // this module instance; we cast it back to the module-private state
    // type allocated by the new_fn and operate within that allocation.
    unsafe {
        let st_ptr = core::ptr::read(state as *const *mut AudioState);
        if st_ptr.is_null() {
            return -1;
        }
        let st = &mut *st_ptr;
        if st.in_chan < 0 {
            return 0;
        }

        // Retain PCM in Fluxor's bounded channels until the AudioContext is
        // running and its worklet is connected. Draining earlier creates an
        // unbounded JS/MessagePort backlog which is discarded when Safari finally
        // resumes the shallow render ring.
        if host_audio_ready() <= 0 {
            return 0;
        }

        loop {
            // Pace to the WebAudio clock: forward PCM only while the queue
            // is shorter than the target lead, then HOLD — leaving the rest
            // in the channel so back-pressure propagates upstream and the
            // pipeline tracks real time instead of free-running. The lead
            // is read straight from the audio clock, so transient channel
            // emptiness (the codec just hasn't written this pass) doesn't
            // perturb pacing: the queued WebAudio buffers are still there.
            if host_audio_lead_us() >= LEAD_TARGET_US {
                break;
            }
            let n = channel::channel_read(st.in_chan, st.buf.as_mut_ptr(), st.buf.len());
            if n <= 0 {
                break;
            }
            host_audio_play(st.buf.as_ptr(), n as usize, st.sample_rate, st.channels);
        }
        0
    }
}

pub(crate) unsafe fn build(
    sample_rate: u32,
    channels: u32,
    in_chan: i32,
) -> scheduler::BuiltInModule {
    let mut m = scheduler::BuiltInModule::new("wasm_browser_audio", audio_step);
    let raw = alloc_state(in_chan, sample_rate, channels);
    core::ptr::write(m.state.as_mut_ptr() as *mut *mut AudioState, raw);
    m
}
