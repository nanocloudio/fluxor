//! wasm StreamTime provider — exposes the browser audio sink's played-frame
//! clock so `provider_query(-1, STREAM_TIME)` answers on wasm exactly as the
//! Linux/RP2350 audio sinks do (mirrors
//! `src/platform/linux/linux_audio.rs::linux_stream_time_dispatch`).
//!
//! The audio clock lives in JavaScript (`createAudioScheduler` / the `pcm-ring`
//! AudioWorklet in `host_shims.js`); the `host_stream_time` import fills the
//! 24-byte `StreamTime` snapshot from it. Registering this makes the audio sink
//! the ONE A/V clock authority that both an app's producer (via
//! `dev_stream_time`) and its presenter read, so the two share a single clock
//! rather than private ones that can drift apart and deadlock.
//!
//! Unit contract (wasm): `consumed_units` is already in emulated-60 Hz frames
//! and `units_per_sec_q16 = 60 << 16`, so a consumer's emulated-frame index is
//! `consumed_units` directly (the portable form `consumed * 60 / (rate>>16)`
//! reduces to `consumed` here). `t0_micros` is 0 until audio starts running.

use crate::kernel::sys::errno;

/// PIO-side `STREAM_TIME` opcode that the `0x0C30` (`STREAM_TIME`) syscall
/// delegates to (`src/kernel/syscalls.rs`). Kept in sync with `linux_audio.rs`.
const STREAM_CLOCK_QUERY: u32 = 0x1C00;

extern "C" {
    /// Fill a 24-byte `StreamTime { consumed_units u64, queued_units u32,
    /// units_per_sec_q16 u32, t0_micros u64 }` (little-endian) from the audio
    /// sink. Returns 1 if the clock has started, 0 otherwise (snapshot zeros).
    /// Provided by `host_shims.js` (in-process) / `fluxor-worker.js` (worker).
    fn host_stream_time(out: *mut u8) -> i32;
}

/// HAL_PIO dispatch: answer `STREAM_TIME` (handle=-1 → the single wasm audio
/// stream) with the audio sink's clock. Shape mirrors `linux_stream_time_dispatch`.
unsafe fn wasm_stream_time_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    if opcode != STREAM_CLOCK_QUERY {
        return errno::ENOSYS;
    }
    if handle >= 0 {
        // Only the "first active stream" (handle=-1) form is meaningful on wasm.
        return errno::EINVAL;
    }
    if arg.is_null() || arg_len < 24 {
        return errno::EINVAL;
    }
    // The host writes the full 24-byte StreamTime; a 0 return just means the
    // audio clock has not started yet (snapshot is zeros → the guest cold-starts).
    let _started = host_stream_time(arg);
    0
}

/// Register the audio-clock StreamTime provider. Called once from
/// `hal.rs::wasm_init_providers()` at kernel boot (mirrors
/// `linux/runtime.rs:162` `provider::register(HAL_PIO, linux_stream_time_dispatch)`).
pub fn register() {
    use crate::kernel::module::provider;
    use crate::kernel::module::provider::contract as dev_class;
    provider::register(dev_class::STREAM_CLOCK, wasm_stream_time_dispatch);
}
