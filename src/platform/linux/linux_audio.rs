// linux_audio built-in — PCM sink. Four modes:
//   wav      append to a WAV file with periodically-refreshed header
//   raw      append to a headerless little-endian PCM file
//   null     drain and discard
//   playback push samples to the host audio device via CPAL
//            (requires `host-playback` Cargo feature)
//
// Params are declared in `modules/builtin/linux/linux_audio/manifest.toml`
// and packed into the kernel's TLV stream by the config tool.

#[cfg(feature = "host-playback")]
mod playback_backend {
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    /// CPAL output stream owned by the linux_audio step. Samples are
    /// pushed into a shared queue; CPAL's data callback pulls from
    /// it. Underruns emit silence and log at most once per second.
    pub struct PlaybackBackend {
        queue: Arc<Mutex<VecDeque<i16>>>,
        // Stream must outlive its callback closure; keep it owned.
        _stream: cpal::Stream,
    }

    impl PlaybackBackend {
        pub fn spawn(sample_rate: u32, channels: u16) -> Result<Self, String> {
            let host = cpal::default_host();
            let device = host
                .default_output_device()
                .ok_or_else(|| "no default audio output device".to_string())?;
            let config = cpal::StreamConfig {
                channels,
                sample_rate: cpal::SampleRate(sample_rate),
                buffer_size: cpal::BufferSize::Default,
            };
            let queue = Arc::new(Mutex::new(VecDeque::with_capacity(
                (sample_rate as usize * channels as usize) / 4,
            )));
            let queue_for_cb = Arc::clone(&queue);
            let underrun_logged = Arc::new(std::sync::atomic::AtomicU32::new(0));
            let underrun_for_cb = Arc::clone(&underrun_logged);
            let stream = device
                .build_output_stream(
                    &config,
                    move |out: &mut [i16], _: &cpal::OutputCallbackInfo| {
                        let mut q = queue_for_cb.lock().unwrap();
                        let mut filled = 0;
                        while filled < out.len() {
                            match q.pop_front() {
                                Some(s) => {
                                    out[filled] = s;
                                    filled += 1;
                                }
                                None => break,
                            }
                        }
                        if filled < out.len() {
                            for s in &mut out[filled..] {
                                *s = 0;
                            }
                            let prev =
                                underrun_for_cb.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if prev == 0 || prev % 1000 == 0 {
                                log::warn!(
                                    "[linux_audio] underrun (silenced {} sample(s); count={})",
                                    out.len() - filled,
                                    prev + 1
                                );
                            }
                        }
                    },
                    move |e| log::warn!("[linux_audio] cpal stream error: {}", e),
                    None,
                )
                .map_err(|e| format!("cpal build_output_stream: {}", e))?;
            stream.play().map_err(|e| format!("cpal play: {}", e))?;
            log::info!(
                "[linux_audio] cpal stream started ({}Hz {}ch on '{}')",
                sample_rate,
                channels,
                device.name().unwrap_or_else(|_| "default".into())
            );
            Ok(Self {
                queue,
                _stream: stream,
            })
        }

        /// Push s16le interleaved samples (raw byte buffer) into the
        /// playback queue. Capped to keep the queue bounded — if the
        /// producer outruns the device, oldest samples are dropped.
        pub fn submit(&self, bytes: &[u8], cap_samples: usize) {
            let mut q = self.queue.lock().unwrap();
            for pair in bytes.chunks_exact(2) {
                if q.len() >= cap_samples {
                    q.pop_front();
                }
                q.push_back(i16::from_le_bytes([pair[0], pair[1]]));
            }
        }
    }
}

use std::io::{Seek, SeekFrom};

const LINUX_AUDIO_HASH: u32 = 0xF62EA500; // fnv1a32("linux_audio")
const PIO_STREAM_TIME: u32 = 0x0407;

struct LinuxAudioClock {
    started: bool,
    start_micros: u64,
    sample_rate: u32,
    channels: u16,
    bytes_written: u64,
}

static mut LINUX_AUDIO_CLOCK: LinuxAudioClock = LinuxAudioClock {
    started: false,
    start_micros: 0,
    sample_rate: 0,
    channels: 0,
    bytes_written: 0,
};

#[derive(Clone, Copy, PartialEq)]
enum AudioMode {
    Wav,
    Raw,
    Null,
    #[cfg(feature = "host-playback")]
    Playback,
}

struct LinuxAudioState {
    in_chan: i32,
    failed: bool,
    mode: AudioMode,
    file: Option<std::fs::File>,
    start_micros: u64,
    sample_rate: u32,
    channels: u16,
    bytes_written: u32,
    bytes_since_flush: u32,
    flush_interval: u32,
    #[cfg(feature = "host-playback")]
    playback: Option<playback_backend::PlaybackBackend>,
    #[cfg(feature = "host-playback")]
    playback_cap_samples: usize,
}

// Tag layout (declaration order in manifest.toml, starting at 10):
//   10: mode (enum wav=0, raw=1, null=2, playback=3)
//   11: path (str)
//   12: sample_rate (u32)
//   13: channels (u8)
const AUDIO_TAG_MODE: u8 = 10;
const AUDIO_TAG_PATH: u8 = 11;
const AUDIO_TAG_SAMPLE_RATE: u8 = 12;
const AUDIO_TAG_CHANNELS: u8 = 13;

const AUDIO_MODE_WAV: u8 = 0;
const AUDIO_MODE_RAW: u8 = 1;
const AUDIO_MODE_NULL: u8 = 2;
const AUDIO_MODE_PLAYBACK: u8 = 3;

fn resolve_audio_mode(raw: u8) -> AudioMode {
    #[cfg(feature = "host-playback")]
    {
        match raw {
            AUDIO_MODE_WAV => AudioMode::Wav,
            AUDIO_MODE_RAW => AudioMode::Raw,
            AUDIO_MODE_NULL => AudioMode::Null,
            AUDIO_MODE_PLAYBACK => AudioMode::Playback,
            _ => AudioMode::Wav,
        }
    }
    #[cfg(not(feature = "host-playback"))]
    {
        match raw {
            AUDIO_MODE_RAW => AudioMode::Raw,
            AUDIO_MODE_NULL => AudioMode::Null,
            AUDIO_MODE_PLAYBACK => {
                log::warn!(
                    "[linux_audio] mode='playback' requires --features host-playback; using wav"
                );
                AudioMode::Wav
            }
            _ => AudioMode::Wav,
        }
    }
}

fn write_wav_header(
    f: &mut std::fs::File,
    sample_rate: u32,
    channels: u16,
    data_len: u32,
) -> std::io::Result<()> {
    f.seek(SeekFrom::Start(0))?;
    let bits_per_sample: u16 = 16;
    let byte_rate = sample_rate * channels as u32 * bits_per_sample as u32 / 8;
    let block_align = channels * bits_per_sample / 8;
    f.write_all(b"RIFF")?;
    f.write_all(&(36u32 + data_len).to_le_bytes())?;
    f.write_all(b"WAVE")?;
    f.write_all(b"fmt ")?;
    f.write_all(&16u32.to_le_bytes())?; // PCM fmt chunk size
    f.write_all(&1u16.to_le_bytes())?; // PCM format
    f.write_all(&channels.to_le_bytes())?;
    f.write_all(&sample_rate.to_le_bytes())?;
    f.write_all(&byte_rate.to_le_bytes())?;
    f.write_all(&block_align.to_le_bytes())?;
    f.write_all(&bits_per_sample.to_le_bytes())?;
    f.write_all(b"data")?;
    f.write_all(&data_len.to_le_bytes())?;
    Ok(())
}

unsafe fn linux_stream_time_dispatch(
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if opcode != PIO_STREAM_TIME {
        return fluxor::kernel::errno::ENOSYS;
    }
    if handle >= 0 {
        return fluxor::kernel::errno::EINVAL;
    }
    if arg.is_null() || arg_len < 24 {
        return fluxor::kernel::errno::EINVAL;
    }

    let clock = &*(&raw const LINUX_AUDIO_CLOCK);
    if !clock.started || clock.sample_rate == 0 || clock.channels == 0 {
        return fluxor::kernel::errno::ENODEV;
    }

    let bytes_per_frame = clock.channels as u64 * 2;
    let consumed = if bytes_per_frame > 0 {
        clock.bytes_written / bytes_per_frame
    } else {
        0
    };
    let queued: u32 = 0;
    let rate_q16 = clock.sample_rate << 16;

    let out = core::slice::from_raw_parts_mut(arg, 24);
    out[0..8].copy_from_slice(&consumed.to_le_bytes());
    out[8..12].copy_from_slice(&queued.to_le_bytes());
    out[12..16].copy_from_slice(&rate_q16.to_le_bytes());
    out[16..24].copy_from_slice(&clock.start_micros.to_le_bytes());

    0
}

fn linux_audio_due_bytes(st: &LinuxAudioState) -> usize {
    let bytes_per_frame = st.channels as u64 * 2;
    let byte_rate = st.sample_rate as u64 * bytes_per_frame;
    if byte_rate == 0 || bytes_per_frame == 0 {
        return 0;
    }

    let elapsed_us = linux_now_micros().saturating_sub(st.start_micros);
    let target_bytes = elapsed_us.saturating_mul(byte_rate) / 1_000_000;
    let due = target_bytes.saturating_sub(st.bytes_written as u64);
    let aligned_due = due - (due % bytes_per_frame);
    aligned_due.min(4096) as usize
}

fn linux_audio_step(state: *mut u8) -> i32 {
    let st = unsafe { instance_state::<LinuxAudioState>(state) };

    if st.failed || st.in_chan < 0 {
        return 0;
    }

    let mut buf = [0u8; 4096];
    let max_read = match st.mode {
        AudioMode::Null => buf.len(),
        #[cfg(feature = "host-playback")]
        AudioMode::Playback => buf.len(),
        AudioMode::Raw | AudioMode::Wav => linux_audio_due_bytes(st),
    };
    if max_read == 0 {
        return 0;
    }

    let read = unsafe { channel::channel_read(st.in_chan, buf.as_mut_ptr(), max_read) };
    if read <= 0 {
        match st.mode {
            AudioMode::Raw | AudioMode::Wav => {
                buf[..max_read].fill(0);
            }
            _ => return 0,
        }
    }
    let n = match st.mode {
        AudioMode::Raw | AudioMode::Wav => {
            if read > 0 {
                read as usize
            } else {
                max_read
            }
        }
        _ => read as usize,
    };

    match st.mode {
        AudioMode::Null => {
            // discard
        }
        #[cfg(feature = "host-playback")]
        AudioMode::Playback => {
            if let Some(p) = st.playback.as_ref() {
                p.submit(&buf[..n], st.playback_cap_samples);
            }
        }
        AudioMode::Raw | AudioMode::Wav => {
            if let Some(f) = st.file.as_mut() {
                if let Err(e) = f.write_all(&buf[..n]) {
                    log::warn!("[linux_audio] write failed: {}", e);
                    st.failed = true;
                    return 0;
                }
                st.bytes_written = st.bytes_written.saturating_add(n as u32);
                unsafe {
                    let clock = &mut *(&raw mut LINUX_AUDIO_CLOCK);
                    clock.bytes_written = st.bytes_written as u64;
                }
                st.bytes_since_flush = st.bytes_since_flush.saturating_add(n as u32);
                if matches!(st.mode, AudioMode::Wav) && st.bytes_since_flush >= st.flush_interval {
                    let total = st.bytes_written;
                    let sr = st.sample_rate;
                    let ch = st.channels;
                    if let Err(e) = write_wav_header(f, sr, ch, total) {
                        log::warn!("[linux_audio] header refresh failed: {}", e);
                    }
                    let _ = f.seek(SeekFrom::End(0));
                    st.bytes_since_flush = 0;
                }
            }
        }
    }
    0
}

fn build_linux_audio(module_idx: usize, params: &[u8]) -> scheduler::BuiltInModule {
    // Manifest declares a default for every param; the tool packs them
    // all into the TLV stream so each tag matches one walker arm.
    let mut mode_raw: u8 = AUDIO_MODE_WAV;
    let mut sample_rate: u32 = 0;
    let mut channels: u16 = 0;
    let mut path = String::new();
    walk_tlv(params, |tag, value| match tag {
        AUDIO_TAG_MODE => mode_raw = tlv_u8(value),
        AUDIO_TAG_PATH => path = tlv_str(value).to_string(),
        AUDIO_TAG_SAMPLE_RATE => sample_rate = tlv_u32(value),
        AUDIO_TAG_CHANNELS => channels = tlv_u8(value) as u16,
        _ => {}
    });
    let mode = resolve_audio_mode(mode_raw);
    let start_micros = linux_now_micros();

    // Flush header roughly once per second of audio.
    let flush_interval = sample_rate * channels as u32 * 2;
    let mut failed = false;
    let mut file: Option<std::fs::File> = None;

    if matches!(mode, AudioMode::Wav | AudioMode::Raw) {
        if let Some(parent) = Path::new(&path).parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    log::warn!("[linux_audio] mkdir '{}' failed: {}", parent.display(), e);
                    failed = true;
                }
            }
        }
        match std::fs::File::create(&path) {
            Ok(mut f) => {
                if matches!(mode, AudioMode::Wav) {
                    if let Err(e) = write_wav_header(&mut f, sample_rate, channels, 0) {
                        log::warn!("[linux_audio] header write failed: {}", e);
                        failed = true;
                    }
                }
                file = Some(f);
            }
            Err(e) => {
                log::warn!("[linux_audio] open '{}' failed: {}", path, e);
                failed = true;
            }
        }
    }
    let mode_str = match mode {
        AudioMode::Wav => "wav",
        AudioMode::Raw => "raw",
        AudioMode::Null => "null",
        #[cfg(feature = "host-playback")]
        AudioMode::Playback => "playback",
    };
    log::info!(
        "[linux_audio] mode={} {}Hz {}ch path='{}'",
        mode_str,
        sample_rate,
        channels,
        path,
    );
    unsafe {
        let clock = &mut *(&raw mut LINUX_AUDIO_CLOCK);
        clock.started = true;
        clock.start_micros = start_micros;
        clock.sample_rate = sample_rate;
        clock.channels = channels;
        clock.bytes_written = 0;
    }

    #[cfg(feature = "host-playback")]
    let (playback, playback_cap_samples) = if matches!(mode, AudioMode::Playback) {
        // Cap the playback queue at ~250 ms of audio so a runaway
        // producer can't grow it without bound.
        let cap = (sample_rate as usize * channels as usize) / 4;
        match playback_backend::PlaybackBackend::spawn(sample_rate, channels) {
            Ok(p) => (Some(p), cap),
            Err(e) => {
                log::warn!("[linux_audio] playback init failed: {}; muting", e);
                failed = true;
                (None, 0)
            }
        }
    } else {
        (None, 0)
    };

    scheduler::set_current_module(module_idx);
    let in_chan = scheduler::get_module_port(module_idx, 0, 0);
    let mut m = scheduler::BuiltInModule::new("linux_audio", linux_audio_step);
    install_state(
        &mut m,
        Box::new(LinuxAudioState {
            in_chan,
            failed,
            mode,
            file,
            start_micros,
            sample_rate,
            channels,
            bytes_written: 0,
            bytes_since_flush: 0,
            flush_interval,
            #[cfg(feature = "host-playback")]
            playback,
            #[cfg(feature = "host-playback")]
            playback_cap_samples,
        }),
    );
    log::info!(
        "[inst] module {} = linux_audio (built-in) in={}",
        module_idx,
        in_chan
    );
    m
}
