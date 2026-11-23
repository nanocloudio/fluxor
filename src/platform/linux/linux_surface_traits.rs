// linux_surface_traits native module — Linux Surface Traits authority.
//
// The Linux implementation of the runtime environment plane. Emits
// `input::surface_traits::MSG_TRAITS` (24-byte) records on its output port:
// one baseline at startup, then one per change. A consumer wired to it adapts
// to the surface; an unwired graph is unaffected (purely additive).
//
// Sources of each field:
//   * geometry / orientation / size class — the live window size when a
//     `linux_display` window backend is running (host-window feature; it
//     publishes its inner size into `SURFACE_WINDOW_GEOM` on resize), else the
//     configured `width`/`height` params (headless / file mode).
//   * input modalities + gamepad count — scanned from `/proc/bus/input/devices`,
//     re-scanned periodically so device hot-plug bumps the epoch.
//   * audio channels / rate — published by `linux_audio` into `SURFACE_AUDIO`
//     when an audio sink is in the graph (0 when none).
//
// Params, declared with their TLV tags in `manifest.toml`:
//   width  (u32) — fallback geometry when no window backend
//   height (u32)

// The pure scan / size-class / audio logic + its shared consts
// (`SURFACE_AUDIO`, MODALITY_*, SIZE_*, size-class thresholds) live in the
// sibling `linux_surface_traits_scan.rs`, `include!`'d alongside this file
// into the bin so the two share one module scope.

/// Live window geometry, published by `linux_display`'s winit thread
/// (host-window) on resize. Packed `(width << 16) | height`; `0` = unset, so
/// the authority falls back to the configured size. Visible to `linux_display`
/// because every `linux/*.rs` is `include!`'d into one module. Only meaningful
/// with a window backend; headless / file-mode graphs use the configured size.
#[cfg(feature = "host-window")]
pub(crate) static SURFACE_WINDOW_GEOM: AtomicU32 = AtomicU32::new(0);


use fluxor::abi::platform::native::linux::linux_surface_traits as surface_traits_tags;
use fluxor::abi::platform::native::linux::linux_surface_traits::{
    TAG_HEIGHT as ST_TAG_HEIGHT, TAG_WIDTH as ST_TAG_WIDTH,
};

/// Re-scan modality presence every N steps so USB hot-plug is noticed without
/// scanning /proc every tick. Geometry + audio are cheap atomic loads and are
/// checked every step.
const RESCAN_TICKS: u32 = 240;

use fluxor::abi::contracts::input::surface_traits as traits_contract;

struct LinuxSurfaceTraitsState {
    out_chan: i32,
    cfg_width: u16,
    cfg_height: u16,
    prev_w_class: u8,
    prev_h_class: u8,
    // Cached modality scan (refreshed every RESCAN_TICKS).
    cached_modalities: u16,
    cached_pads: u8,
    // Last emitted change-key fields, for change detection.
    last_w: u16,
    last_h: u16,
    last_modalities: u16,
    last_pads: u8,
    last_audio: u32,
    emitted: bool,
    epoch: u32,
    ticks: u32,
}

fn read_devices() -> (u16, u8) {
    std::fs::read_to_string("/proc/bus/input/devices")
        .map(|t| scan_devices(&t))
        // Default to a keyboard path if /proc is unreadable (containers,
        // restricted mounts) — never report "no input at all".
        .unwrap_or((MODALITY_KEY, 0))
}

#[cfg(feature = "host-window")]
fn current_geom(cfg_w: u16, cfg_h: u16) -> (u16, u16) {
    let g = SURFACE_WINDOW_GEOM.load(Ordering::Relaxed);
    if g != 0 {
        ((g >> 16) as u16, (g & 0xFFFF) as u16)
    } else {
        (cfg_w, cfg_h)
    }
}

#[cfg(not(feature = "host-window"))]
fn current_geom(cfg_w: u16, cfg_h: u16) -> (u16, u16) {
    (cfg_w, cfg_h)
}

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn linux_surface_traits_step(state: *mut u8) -> i32 {
    // SAFETY: `state` is the kernel-owned per-instance arena for this module;
    // size-matched to `LinuxSurfaceTraitsState` by the loader.
    let st = unsafe { instance_state::<LinuxSurfaceTraitsState>(state) };
    if st.out_chan < 0 {
        return 0;
    }

    // Refresh the modality scan on the baseline + periodically; geometry and
    // audio are cheap atomic loads checked every step (resize is latency-
    // sensitive, /proc scanning is not).
    if !st.emitted || st.ticks % RESCAN_TICKS == 0 {
        let (m, pads) = read_devices();
        st.cached_modalities = m;
        st.cached_pads = pads;
    }
    st.ticks = st.ticks.wrapping_add(1);

    let (w, h) = current_geom(st.cfg_width, st.cfg_height);
    let (audio_ch, audio_rate) = read_audio();
    let audio_packed = ((audio_ch as u32) << 24) | (audio_rate & 0x00FF_FFFF);

    // Change detection on the raw record fields (size class is downstream of w/h
    // so a within-band resize still bumps the epoch, matching the browser
    // authority; hysteresis only prevents class *thrash*).
    if st.emitted
        && w == st.last_w
        && h == st.last_h
        && st.cached_modalities == st.last_modalities
        && st.cached_pads == st.last_pads
        && audio_packed == st.last_audio
    {
        return 0;
    }

    // Compute the candidate record WITHOUT mutating change-detection or
    // hysteresis state — those are committed only once the write is accepted, so
    // a refused write (full channel) is re-attempted on a later step rather than
    // dropped (committed state would match the unchanged fields next step and
    // skip the record).
    let w_class = size_class_for(w, st.prev_w_class);
    let h_class = size_class_for(h, st.prev_h_class);
    let epoch = st.epoch.wrapping_add(1);

    let buf = traits_contract::encode(&traits_contract::Traits {
        orientation: traits_contract::orientation_for(w, h),
        size_class_w: w_class,
        size_class_h: h_class,
        viewport_w_px: w,
        viewport_h_px: h,
        modalities: st.cached_modalities,
        gamepad_count: st.cached_pads,
        audio_channels: audio_ch,
        audio_rate_hz: audio_rate,
        epoch,
        authority: traits_contract::AUTHORITY_LINUX,
        // A Linux host presents on one display: a window or a framebuffer.
        display_count: 1,
        // The display takes a raster of the viewport's own extent and
        // magnifies it itself, so a surface pixel is a logical pixel.
        dpr_eighths: traits_contract::DPR_1X,
    });
    // SAFETY: channel_write takes (chan, *const u8, len); buf is a stack array
    // sized to its length. The kernel FIFO write is all-or-nothing, so a
    // non-full return is EAGAIN (channel full), not a partial/corrupt record.
    let written = unsafe { channel::channel_write(st.out_chan, buf.as_ptr(), buf.len()) };
    if written as usize != buf.len() {
        return 0; // not delivered — leave state uncommitted, retry next step
    }

    // Delivered: commit hysteresis + change-detection baselines + epoch.
    st.prev_w_class = w_class;
    st.prev_h_class = h_class;
    st.last_w = w;
    st.last_h = h;
    st.last_modalities = st.cached_modalities;
    st.last_pads = st.cached_pads;
    st.last_audio = audio_packed;
    st.emitted = true;
    st.epoch = epoch;
    0
}

fn build_linux_surface_traits(module_idx: usize, params: &[u8]) -> Result<Box<LinuxSurfaceTraitsState>, i32> {
    let mut width: u16 = 0;
    let mut height: u16 = 0;
    walk_tlv(params, |tag, value| match tag {
        ST_TAG_WIDTH => width = tlv_u32(value) as u16,
        ST_TAG_HEIGHT => height = tlv_u32(value) as u16,
        _ => {}
    });
    let out_chan = scheduler::module_port(module_idx, surface_traits_tags::PORT_EVENTS);
    let st = Box::new(LinuxSurfaceTraitsState {
            out_chan,
            cfg_width: width,
            cfg_height: height,
            prev_w_class: SIZE_REGULAR,
            prev_h_class: SIZE_REGULAR,
            cached_modalities: 0,
            cached_pads: 0,
            last_w: 0,
            last_h: 0,
            last_modalities: 0,
            last_pads: 0,
            last_audio: 0,
            emitted: false,
            epoch: 0,
            ticks: 0,
        });
    log::info!(
        "[linux_surface_traits] authority cfg {width}x{height} \
         (geometry: live window when host-window else config; modalities + gamepad \
         count from /proc/bus/input/devices re-scanned every {RESCAN_TICKS} ticks; \
         audio from linux_audio), out_chan={out_chan}"
    );
    Ok(st)
}

impl HostNative for LinuxSurfaceTraitsState {
    fn build(slot: usize, params: &[u8]) -> Result<Box<Self>, i32> {
        build_linux_surface_traits(slot, params)
    }
}

/// The `linux_surface_traits` native module.
pub static LINUX_SURFACE_TRAITS: NativeVtable = host_vtable::<LinuxSurfaceTraitsState>(linux_surface_traits_step, native::linux_surface_traits::STATE_BYTES);
