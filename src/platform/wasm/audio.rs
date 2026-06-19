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
    /// Microseconds of audio currently queued ahead of the WebAudio
    /// playback clock (`audioSchedTime - currentTime`), or 0 until the
    /// AudioContext is running. Read straight from the audio clock — no
    /// wall-clock estimation, so it's exact and drift-free.
    fn host_audio_lead_us() -> u64;
}

/// Per-tick read budget. Sized to a comfortable AudioWorklet quantum
/// (128 frames × 2 channels × 2 bytes = 512 bytes minimum, with
/// headroom for stereo + small jitter buffer).
const READ_BUF_BYTES: usize = 4096;

/// Target amount of audio queued ahead of the real-time playback clock,
/// in microseconds. The sink forwards PCM to the WebAudio scheduler only
/// until it is this far ahead, then HOLDS — leaving decoded PCM in the
/// input channel so back-pressure propagates upstream
/// (codec → producer → fetch) and the whole pipeline is paced to the
/// audio clock.
///
/// Without this, the sink drains its input every tick and dumps every
/// block into WebAudio, whose schedule advances at the browser's frame
/// rate, NOT the 44.1 kHz audio clock. On a fast/visible tab the pipeline
/// produces many× real-time, so the schedule races ahead, the shim clamps
/// it at its `MAX_AHEAD` ceiling, and blocks overlap — audible as a fast,
/// garbled, uneven-tempo playback. Holding at a bounded lead keeps the
/// schedule between the shim's lookahead (~120 ms) and its clamp
/// (~400 ms), so it never overlaps and never underruns. 200 ms leaves a
/// comfortable jitter cushion on both sides (rAF granularity, GC pauses).
const LEAD_TARGET_US: u64 = 200_000;

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
