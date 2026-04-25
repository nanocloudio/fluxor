// linux_display built-in — RGB565 sink. Three modes:
//   file   write each frame to a PPM file on disk
//   window blit into a winit/softbuffer host window (host-window feature)
//   null   discard
//
// Params are declared in `modules/builtin/linux/linux_display/manifest.toml`
// and packed into the kernel's TLV stream by the config tool.

#[cfg(feature = "host-window")]
mod window_backend {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };
    use std::thread;
    use winit::application::ApplicationHandler;
    use winit::dpi::LogicalSize;
    use winit::event::WindowEvent;
    use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
    use winit::window::{Window, WindowAttributes, WindowId};

    /// Window backend: a dedicated thread owns the winit event loop;
    /// the linux_display step thread submits RGB565 frames into a
    /// shared latest-frame slot. Drop semantics: backend keeps
    /// running for the program lifetime.
    pub struct WindowBackend {
        latest: Arc<Mutex<Vec<u16>>>,
        wake: Arc<AtomicBool>,
    }

    impl WindowBackend {
        pub fn spawn(width: u32, height: u32, scale: u32) -> Self {
            let latest = Arc::new(Mutex::new(vec![0u16; (width * height) as usize]));
            let wake = Arc::new(AtomicBool::new(false));
            let latest_for_thread = Arc::clone(&latest);
            let wake_for_thread = Arc::clone(&wake);
            // The thread owns the EventLoop. winit insists the
            // EventLoop be created on the thread that runs it.
            thread::Builder::new()
                .name("fluxor-display".into())
                .spawn(move || {
                    let event_loop = EventLoop::new().expect("event loop");
                    event_loop.set_control_flow(ControlFlow::Poll);
                    let mut app = WindowApp {
                        width,
                        height,
                        scale,
                        window: None,
                        context: None,
                        surface: None,
                        latest: latest_for_thread,
                        wake: wake_for_thread,
                        scaled_buf: vec![0u32; (width * scale * height * scale) as usize],
                    };
                    if let Err(e) = event_loop.run_app(&mut app) {
                        log::warn!("[linux_display] event loop exited: {}", e);
                    }
                })
                .expect("spawn fluxor-display thread");
            Self { latest, wake }
        }

        pub fn submit(&self, rgb565: &[u8]) {
            let mut guard = self.latest.lock().unwrap();
            let n = guard.len().min(rgb565.len() / 2);
            for i in 0..n {
                guard[i] = u16::from_le_bytes([rgb565[2 * i], rgb565[2 * i + 1]]);
            }
            self.wake.store(true, Ordering::Release);
        }
    }

    struct WindowApp {
        width: u32,
        height: u32,
        scale: u32,
        window: Option<Arc<Window>>,
        context: Option<softbuffer::Context<Arc<Window>>>,
        surface: Option<softbuffer::Surface<Arc<Window>, Arc<Window>>>,
        latest: Arc<Mutex<Vec<u16>>>,
        wake: Arc<AtomicBool>,
        scaled_buf: Vec<u32>,
    }

    impl ApplicationHandler for WindowApp {
        fn resumed(&mut self, event_loop: &ActiveEventLoop) {
            if self.window.is_some() {
                return;
            }
            let attrs = WindowAttributes::default()
                .with_title("fluxor display")
                .with_inner_size(LogicalSize::new(
                    self.width * self.scale,
                    self.height * self.scale,
                ))
                .with_resizable(false);
            let window = match event_loop.create_window(attrs) {
                Ok(w) => Arc::new(w),
                Err(e) => {
                    log::warn!("[linux_display] create_window failed: {}", e);
                    event_loop.exit();
                    return;
                }
            };
            let context = match softbuffer::Context::new(Arc::clone(&window)) {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("[linux_display] softbuffer context: {}", e);
                    event_loop.exit();
                    return;
                }
            };
            let surface = match softbuffer::Surface::new(&context, Arc::clone(&window)) {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("[linux_display] softbuffer surface: {}", e);
                    event_loop.exit();
                    return;
                }
            };
            self.window = Some(window);
            self.context = Some(context);
            self.surface = Some(surface);
        }

        fn window_event(
            &mut self,
            event_loop: &ActiveEventLoop,
            _id: WindowId,
            event: WindowEvent,
        ) {
            match event {
                WindowEvent::CloseRequested => event_loop.exit(),
                WindowEvent::RedrawRequested => self.redraw(),
                _ => {}
            }
        }

        fn about_to_wait(&mut self, _event_loop: &ActiveEventLoop) {
            // Pull the wake flag once per loop iteration. If new pixels
            // arrived, ask the window to repaint. This couples the
            // display refresh rate to producer cadence rather than
            // free-running at 60Hz with no work to do.
            if self.wake.swap(false, Ordering::AcqRel) {
                if let Some(w) = &self.window {
                    w.request_redraw();
                }
            }
        }
    }

    impl WindowApp {
        fn redraw(&mut self) {
            let (Some(window), Some(surface)) = (self.window.as_ref(), self.surface.as_mut())
            else {
                return;
            };
            let size = window.inner_size();
            let w = match std::num::NonZeroU32::new(size.width) {
                Some(v) => v,
                None => return,
            };
            let h = match std::num::NonZeroU32::new(size.height) {
                Some(v) => v,
                None => return,
            };
            if surface.resize(w, h).is_err() {
                return;
            }
            let mut buffer = match surface.buffer_mut() {
                Ok(b) => b,
                Err(e) => {
                    log::warn!("[linux_display] surface.buffer_mut: {}", e);
                    return;
                }
            };
            // Snapshot the latest frame under the lock then convert
            // RGB565 → 0xRRGGBB, scaling each source pixel into a
            // `scale × scale` block. softbuffer expects ARGB u32.
            let scaled_w = self.width * self.scale;
            let scaled_h = self.height * self.scale;
            let needed = (scaled_w * scaled_h) as usize;
            if self.scaled_buf.len() != needed {
                self.scaled_buf.resize(needed, 0);
            }
            {
                let src = self.latest.lock().unwrap();
                let scale = self.scale as usize;
                let sw = self.width as usize;
                let sh = self.height as usize;
                for sy in 0..sh {
                    for sx in 0..sw {
                        let v = src[sy * sw + sx];
                        let r5 = ((v >> 11) & 0x1F) as u32;
                        let g6 = ((v >> 5) & 0x3F) as u32;
                        let b5 = (v & 0x1F) as u32;
                        let r = (r5 << 3) | (r5 >> 2);
                        let g = (g6 << 2) | (g6 >> 4);
                        let b = (b5 << 3) | (b5 >> 2);
                        let pixel = (r << 16) | (g << 8) | b;
                        for dy in 0..scale {
                            let row = (sy * scale + dy) * (sw * scale);
                            for dx in 0..scale {
                                self.scaled_buf[row + sx * scale + dx] = pixel;
                            }
                        }
                    }
                }
            }
            // Copy into the surface buffer, clipping to whichever is
            // smaller in case the OS resized us behind our back.
            let copy_len = buffer.len().min(self.scaled_buf.len());
            buffer[..copy_len].copy_from_slice(&self.scaled_buf[..copy_len]);
            if let Err(e) = buffer.present() {
                log::warn!("[linux_display] buffer.present: {}", e);
            }
        }
    }
}

use std::io::Write;
use std::path::Path;

const LINUX_DISPLAY_HASH: u32 = 0xEE7453F4; // fnv1a32("linux_display")

// Tag layout (declaration order in manifest.toml, starting at 10):
//   10: mode (enum file=0, null=1, window=2)
//   11: path (str)
//   12: width (u32)
//   13: height (u32)
//   14: scale (u32)
const DISPLAY_TAG_MODE: u8 = 10;
const DISPLAY_TAG_PATH: u8 = 11;
const DISPLAY_TAG_WIDTH: u8 = 12;
const DISPLAY_TAG_HEIGHT: u8 = 13;
const DISPLAY_TAG_SCALE: u8 = 14;

const DISPLAY_MODE_FILE: u8 = 0;
const DISPLAY_MODE_NULL: u8 = 1;
const DISPLAY_MODE_WINDOW: u8 = 2;

#[derive(Clone, Copy, PartialEq)]
enum DisplayMode {
    File,
    Null,
    #[cfg(feature = "host-window")]
    Window,
}

struct LinuxDisplayState {
    in_chan: i32,
    failed: bool,
    mode: DisplayMode,
    width: usize,
    height: usize,
    frame_size: usize,
    path_template: String,
    scratch: Vec<u8>,
    scratch_pos: usize,
    frame_counter: u32,
    #[cfg(feature = "host-window")]
    window: Option<window_backend::WindowBackend>,
}

fn resolve_mode(raw: u8) -> DisplayMode {
    #[cfg(feature = "host-window")]
    {
        match raw {
            DISPLAY_MODE_FILE => DisplayMode::File,
            DISPLAY_MODE_NULL => DisplayMode::Null,
            DISPLAY_MODE_WINDOW => DisplayMode::Window,
            _ => DisplayMode::File,
        }
    }
    #[cfg(not(feature = "host-window"))]
    {
        match raw {
            DISPLAY_MODE_NULL => DisplayMode::Null,
            DISPLAY_MODE_WINDOW => {
                log::warn!(
                    "[linux_display] mode='window' requires --features host-window; using file"
                );
                DisplayMode::File
            }
            _ => DisplayMode::File,
        }
    }
}

fn render_path_template(template: &str, counter: u32) -> String {
    if let Some(idx) = template.find("%04d") {
        let mut out = String::with_capacity(template.len() + 4);
        out.push_str(&template[..idx]);
        out.push_str(&format!("{:04}", counter));
        out.push_str(&template[idx + 4..]);
        out
    } else {
        template.to_string()
    }
}

fn write_ppm(path: &str, width: usize, height: usize, rgb565: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut f = std::fs::File::create(path)?;
    write!(f, "P6\n{} {}\n255\n", width, height)?;
    let mut rgb888 = Vec::with_capacity(width * height * 3);
    for pixel in rgb565.chunks_exact(2) {
        let lo = pixel[0] as u16;
        let hi = pixel[1] as u16;
        let v = (hi << 8) | lo; // little-endian RGB565
        let r5 = ((v >> 11) & 0x1F) as u8;
        let g6 = ((v >> 5) & 0x3F) as u8;
        let b5 = (v & 0x1F) as u8;
        // 5/6-bit → 8-bit with bit replication for full dynamic range.
        rgb888.push((r5 << 3) | (r5 >> 2));
        rgb888.push((g6 << 2) | (g6 >> 4));
        rgb888.push((b5 << 3) | (b5 >> 2));
    }
    f.write_all(&rgb888)?;
    Ok(())
}

fn linux_display_step(state: *mut u8) -> i32 {
    let st = unsafe { instance_state::<LinuxDisplayState>(state) };

    if st.failed || st.in_chan < 0 {
        return 0;
    }

    let mut buf = [0u8; 4096];
    let n = unsafe { channel::channel_read(st.in_chan, buf.as_mut_ptr(), buf.len()) };
    if n <= 0 {
        return 0;
    }

    let mut consumed = 0usize;
    let n = n as usize;
    while consumed < n {
        let want = st.frame_size - st.scratch_pos;
        let take = (n - consumed).min(want);
        st.scratch[st.scratch_pos..st.scratch_pos + take]
            .copy_from_slice(&buf[consumed..consumed + take]);
        st.scratch_pos += take;
        consumed += take;

        if st.scratch_pos == st.frame_size {
            match st.mode {
                DisplayMode::File => {
                    let path = render_path_template(&st.path_template, st.frame_counter);
                    if let Err(e) = write_ppm(&path, st.width, st.height, &st.scratch) {
                        log::warn!("[linux_display] write {} failed: {}", path, e);
                        st.failed = true;
                        return 0;
                    } else if st.frame_counter < 4 || st.frame_counter % 60 == 0 {
                        log::info!("[linux_display] wrote {}", path);
                    }
                }
                DisplayMode::Null => {}
                #[cfg(feature = "host-window")]
                DisplayMode::Window => {
                    if let Some(w) = st.window.as_ref() {
                        w.submit(&st.scratch);
                    }
                }
            }
            st.frame_counter = st.frame_counter.wrapping_add(1);
            st.scratch_pos = 0;
        }
    }
    0
}

fn build_linux_display(module_idx: usize, params: &[u8]) -> scheduler::BuiltInModule {
    // Manifest declares a default for every param; the tool packs them
    // all into the TLV stream so each tag matches one walker arm.
    let mut mode_raw: u8 = DISPLAY_MODE_FILE;
    let mut width: usize = 0;
    let mut height: usize = 0;
    let mut scale: usize = 1;
    let mut path = String::new();
    walk_tlv(params, |tag, value| match tag {
        DISPLAY_TAG_MODE => mode_raw = tlv_u8(value),
        DISPLAY_TAG_PATH => path = tlv_str(value).to_string(),
        DISPLAY_TAG_WIDTH => width = tlv_u32(value) as usize,
        DISPLAY_TAG_HEIGHT => height = tlv_u32(value) as usize,
        DISPLAY_TAG_SCALE => scale = (tlv_u32(value) as usize).max(1),
        _ => {}
    });
    let mode = resolve_mode(mode_raw);
    let frame_size = width * height * 2;
    let mode_str = match mode {
        DisplayMode::File => "file",
        DisplayMode::Null => "null",
        #[cfg(feature = "host-window")]
        DisplayMode::Window => "window",
    };
    log::info!(
        "[linux_display] mode={} {}x{} scale={} ({} bytes/frame) path='{}'",
        mode_str, width, height, scale, frame_size, path,
    );

    #[cfg(feature = "host-window")]
    let window = if matches!(mode, DisplayMode::Window) {
        Some(window_backend::WindowBackend::spawn(
            width as u32,
            height as u32,
            scale as u32,
        ))
    } else {
        None
    };

    scheduler::set_current_module(module_idx);
    let in_chan = scheduler::get_module_port(module_idx, 0, 0);
    let mut m = scheduler::BuiltInModule::new("linux_display", linux_display_step);
    install_state(
        &mut m,
        Box::new(LinuxDisplayState {
            in_chan,
            failed: false,
            mode,
            width,
            height,
            frame_size,
            path_template: path,
            scratch: vec![0u8; frame_size],
            scratch_pos: 0,
            frame_counter: 0,
            #[cfg(feature = "host-window")]
            window,
        }),
    );
    log::info!(
        "[inst] module {} = linux_display (built-in) in={}",
        module_idx, in_chan
    );
    m
}
