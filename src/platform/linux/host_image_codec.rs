// host_image_codec built-in — decode JPEG/PNG/BMP/GIF into RGB565
// frames sized to a target width/height. Reads encoded bytes
// incrementally on `encoded`; once the upstream stalls (channel quiet
// for ~EOF_TICKS consecutive steps), decodes the accumulated buffer,
// resizes, and emits a single frame on `pixels`.
//
// Params are declared in `modules/builtin/host/host_image_codec/manifest.toml`
// and packed into the kernel's TLV stream by the config tool.

#[cfg(feature = "host-image")]
const HOST_IMAGE_CODEC_HASH: u32 = 0xF09D5D98; // fnv1a32("host_image_codec")

#[cfg(feature = "host-image")]
const EOF_TICKS: u32 = 200;

// Channel ring writes are all-or-nothing; stay below the smallest
// default channel capacity (2 KB) so the drain loop always makes
// progress when there's any free space.
#[cfg(feature = "host-image")]
const WRITE_CHUNK: usize = 1024;

// Tag layout (declaration order in manifest.toml, starting at 10):
//   10: width (u32)
//   11: height (u32)
//   12: scale_mode (enum fit=0, stretch=1)
//   13: max_bytes (u32)
#[cfg(feature = "host-image")]
const IMG_TAG_WIDTH: u8 = 10;
#[cfg(feature = "host-image")]
const IMG_TAG_HEIGHT: u8 = 11;
#[cfg(feature = "host-image")]
const IMG_TAG_SCALE_MODE: u8 = 12;
#[cfg(feature = "host-image")]
const IMG_TAG_MAX_BYTES: u8 = 13;

#[cfg(feature = "host-image")]
const IMG_SCALE_MODE_FIT: u8 = 0;
#[cfg(feature = "host-image")]
const IMG_SCALE_MODE_STRETCH: u8 = 1;

#[cfg(feature = "host-image")]
#[derive(Clone, Copy, PartialEq)]
enum ScaleMode {
    Fit,
    Stretch,
}

#[cfg(feature = "host-image")]
struct HostImageState {
    in_chan: i32,
    out_chan: i32,
    decoded: bool,
    failed: bool,
    width: usize,
    height: usize,
    scale_mode: ScaleMode,
    max_bytes: usize,
    encoded: Vec<u8>,
    quiet_ticks: u32,
    pending: Vec<u8>,
    pending_pos: usize,
}

#[cfg(feature = "host-image")]
fn resolve_scale_mode(raw: u8) -> ScaleMode {
    match raw {
        IMG_SCALE_MODE_STRETCH => ScaleMode::Stretch,
        _ => ScaleMode::Fit,
    }
}

#[cfg(feature = "host-image")]
fn rgb888_to_rgb565_le(rgb: &[u8], dst: &mut [u8]) {
    debug_assert_eq!(rgb.len() / 3, dst.len() / 2);
    for (px, out) in rgb.chunks_exact(3).zip(dst.chunks_exact_mut(2)) {
        let r5 = (px[0] >> 3) as u16;
        let g6 = (px[1] >> 2) as u16;
        let b5 = (px[2] >> 3) as u16;
        let v = (r5 << 11) | (g6 << 5) | b5;
        out[0] = v as u8;
        out[1] = (v >> 8) as u8;
    }
}

#[cfg(feature = "host-image")]
fn decode_to_rgb565(
    encoded: &[u8],
    target_w: usize,
    target_h: usize,
    mode: ScaleMode,
) -> Result<Vec<u8>, String> {
    use image::imageops::FilterType;
    use image::GenericImageView;

    let img = image::load_from_memory(encoded)
        .map_err(|e| format!("decode failed: {}", e))?;
    let (src_w, src_h) = img.dimensions();
    log::info!(
        "[host_image] decoded {}x{} → resizing to {}x{} ({:?})",
        src_w,
        src_h,
        target_w,
        target_h,
        match mode {
            ScaleMode::Fit => "fit",
            ScaleMode::Stretch => "stretch",
        }
    );

    let mut out = vec![0u8; target_w * target_h * 2];
    match mode {
        ScaleMode::Stretch => {
            let resized = img
                .resize_exact(target_w as u32, target_h as u32, FilterType::Triangle)
                .to_rgb8();
            rgb888_to_rgb565_le(resized.as_raw(), &mut out);
        }
        ScaleMode::Fit => {
            let resized = img
                .resize(target_w as u32, target_h as u32, FilterType::Triangle)
                .to_rgb8();
            let rw = resized.width() as usize;
            let rh = resized.height() as usize;
            let off_x = (target_w - rw) / 2;
            let off_y = (target_h - rh) / 2;
            let src = resized.as_raw();
            // Letterbox onto a black canvas: encode each resized pixel
            // at (off_x+x, off_y+y); rest remains zero (RGB565 black).
            for y in 0..rh {
                for x in 0..rw {
                    let s = (y * rw + x) * 3;
                    let r5 = (src[s] >> 3) as u16;
                    let g6 = (src[s + 1] >> 2) as u16;
                    let b5 = (src[s + 2] >> 3) as u16;
                    let v = (r5 << 11) | (g6 << 5) | b5;
                    let dx = off_x + x;
                    let dy = off_y + y;
                    let d = (dy * target_w + dx) * 2;
                    out[d] = v as u8;
                    out[d + 1] = (v >> 8) as u8;
                }
            }
        }
    }
    Ok(out)
}

#[cfg(feature = "host-image")]
fn host_image_step(state: *mut u8) -> i32 {
    let st = unsafe { instance_state::<HostImageState>(state) };

    if st.failed {
        return 1;
    }

    // Drain any pending output from a prior decoded-frame partial write.
    while st.pending_pos < st.pending.len() {
        let take = (st.pending.len() - st.pending_pos).min(WRITE_CHUNK);
        let w = unsafe {
            channel::channel_write(
                st.out_chan,
                st.pending.as_ptr().add(st.pending_pos),
                take,
            )
        };
        if w > 0 {
            st.pending_pos += w as usize;
        } else {
            return 0;
        }
    }
    if st.decoded {
        // Frame already emitted in full — nothing else to do.
        st.pending.clear();
        st.pending_pos = 0;
        return 1;
    }

    let mut buf = [0u8; 4096];
    let n = unsafe { channel::channel_read(st.in_chan, buf.as_mut_ptr(), buf.len()) };
    if n > 0 {
        let n = n as usize;
        if st.encoded.len() + n > st.max_bytes {
            log::warn!(
                "[host_image] encoded payload exceeded {} bytes; discarding",
                st.max_bytes
            );
            st.failed = true;
            return 1;
        }
        st.encoded.extend_from_slice(&buf[..n]);
        st.quiet_ticks = 0;
        return 0;
    }

    // No data this tick. If we've already collected some bytes and
    // the upstream has been quiet for long enough, treat that as EOF
    // and decode.
    if !st.encoded.is_empty() {
        st.quiet_ticks = st.quiet_ticks.saturating_add(1);
        if st.quiet_ticks < EOF_TICKS {
            return 0;
        }
    } else {
        return 0;
    }

    // EOF reached — decode, resize, queue all output bytes for write.
    log::info!(
        "[host_image] eof — decoding {} bytes",
        st.encoded.len()
    );
    let frame = match decode_to_rgb565(&st.encoded, st.width, st.height, st.scale_mode) {
        Ok(f) => f,
        Err(e) => {
            log::warn!("[host_image] {}", e);
            st.failed = true;
            return 1;
        }
    };
    st.encoded.clear();
    st.encoded.shrink_to_fit();
    st.pending = frame;
    st.pending_pos = 0;
    st.decoded = true;
    0
}

#[cfg(feature = "host-image")]
fn build_host_image_codec(module_idx: usize, params: &[u8]) -> scheduler::BuiltInModule {
    // Manifest declares a default for every param; the tool packs them
    // all into the TLV stream so each tag matches one walker arm.
    let mut width: usize = 0;
    let mut height: usize = 0;
    let mut scale_raw: u8 = IMG_SCALE_MODE_FIT;
    let mut max_bytes: usize = 0;
    walk_tlv(params, |tag, value| match tag {
        IMG_TAG_WIDTH => width = tlv_u32(value) as usize,
        IMG_TAG_HEIGHT => height = tlv_u32(value) as usize,
        IMG_TAG_SCALE_MODE => scale_raw = tlv_u8(value),
        IMG_TAG_MAX_BYTES => max_bytes = tlv_u32(value) as usize,
        _ => {}
    });
    let scale_mode = resolve_scale_mode(scale_raw);

    scheduler::set_current_module(module_idx);
    let in_ch = scheduler::get_module_port(module_idx, 0, 0);
    let out_ch = scheduler::get_module_port(module_idx, 1, 0);
    let mut m = scheduler::BuiltInModule::new("host_image_codec", host_image_step);
    install_state(
        &mut m,
        Box::new(HostImageState {
            in_chan: in_ch,
            out_chan: out_ch,
            decoded: false,
            failed: false,
            width,
            height,
            scale_mode,
            max_bytes,
            encoded: Vec::with_capacity(64 * 1024),
            quiet_ticks: 0,
            pending: Vec::new(),
            pending_pos: 0,
        }),
    );
    log::info!(
        "[inst] module {} = host_image_codec (built-in) in={} out={} {}x{} mode={} max_bytes={}",
        module_idx,
        in_ch,
        out_ch,
        width,
        height,
        match scale_mode {
            ScaleMode::Fit => "fit",
            ScaleMode::Stretch => "stretch",
        },
        max_bytes,
    );
    m
}
