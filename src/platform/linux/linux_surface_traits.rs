// linux_surface_traits built-in — Linux Surface Traits authority.
//
// The Linux implementation of the runtime environment plane
// (.context/rfc_surface_traits.md). Emits `input::surface_traits::MSG_TRAITS`
// (24-byte) records on its output port: one baseline at startup, then one per
// change. A consumer wired to it adapts to the surface; an unwired graph is
// unaffected (purely additive).
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
// Params (manifest order → auto-assigned TLV tags from 10):
//   width  (tag 10, u32)   — fallback geometry when no window backend
//   height (tag 11, u32)

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

const LINUX_SURFACE_TRAITS_HASH: u32 = 0x9772_C0F3; // fnv1a32("linux_surface_traits")

const ST_TAG_WIDTH: u8 = 10;
const ST_TAG_HEIGHT: u8 = 11;

/// Re-scan modality presence every N steps so USB hot-plug is noticed without
/// scanning /proc every tick. Geometry + audio are cheap atomic loads and are
/// checked every step.
const RESCAN_TICKS: u32 = 240;

const ORIENT_PORTRAIT: u8 = 0;
const ORIENT_LANDSCAPE: u8 = 1;

const AUTHORITY_LINUX: u8 = 1;
const EVENT_RECORD: usize = 24;

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

#[allow(clippy::too_many_arguments, reason = "fixed wire-record field set")]
fn encode(
    buf: &mut [u8; EVENT_RECORD],
    orient: u8,
    size_w: u8,
    size_h: u8,
    w: u16,
    h: u16,
    modalities: u16,
    pads: u8,
    audio_ch: u8,
    audio_rate: u32,
    epoch: u32,
) {
    buf[0] = 0x01; // MSG_TRAITS
    buf[1] = orient;
    buf[2] = size_w;
    buf[3] = size_h;
    buf[4..6].copy_from_slice(&w.to_le_bytes());
    buf[6..8].copy_from_slice(&h.to_le_bytes());
    buf[8..10].copy_from_slice(&modalities.to_le_bytes());
    buf[10] = pads;
    buf[11] = audio_ch;
    buf[12..16].copy_from_slice(&audio_rate.to_le_bytes());
    buf[16..20].copy_from_slice(&epoch.to_le_bytes());
    buf[20] = AUTHORITY_LINUX;
    buf[21] = 1; // display_count — a Linux host presents on a display (window/framebuffer)
    buf[22] = 0;
    buf[23] = 0;
}

fn linux_surface_traits_step(state: *mut u8) -> i32 {
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
    let orient = if w >= h {
        ORIENT_LANDSCAPE
    } else {
        ORIENT_PORTRAIT
    };
    let epoch = st.epoch.wrapping_add(1);

    let mut buf = [0u8; EVENT_RECORD];
    encode(
        &mut buf,
        orient,
        w_class,
        h_class,
        w,
        h,
        st.cached_modalities,
        st.cached_pads,
        audio_ch,
        audio_rate,
        epoch,
    );
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

fn build_linux_surface_traits(module_idx: usize, params: &[u8]) -> scheduler::BuiltInModule {
    let mut width: u16 = 0;
    let mut height: u16 = 0;
    walk_tlv(params, |tag, value| match tag {
        ST_TAG_WIDTH => width = tlv_u32(value) as u16,
        ST_TAG_HEIGHT => height = tlv_u32(value) as u16,
        _ => {}
    });
    scheduler::set_current_module(module_idx);
    // Output port is the manifest's first output (port kind 1, ordinal 0).
    let out_chan = scheduler::get_module_port(module_idx, 1, 0);
    let mut m =
        scheduler::BuiltInModule::new("linux_surface_traits", linux_surface_traits_step);
    install_state(
        &mut m,
        Box::new(LinuxSurfaceTraitsState {
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
        }),
    );
    log::info!(
        "[linux_surface_traits] authority cfg {width}x{height} \
         (geometry: live window when host-window else config; modalities + gamepad \
         count from /proc/bus/input/devices re-scanned every {RESCAN_TICKS} ticks; \
         audio from linux_audio), out_chan={out_chan}"
    );
    m
}

