// linux_display native module — `VideoRaster` sink with frame memory.
//
// Every record on `pixels` is a region header
// (`abi::contracts::video_raster`) and that region's pixels, RGB565 or
// RGBA8 as the header says. The stream states its surface; the display
// takes surfaces up to the extent its `pixels` port declares. A frame's
// regions are shown together at its last one, and a damage frame changes
// only its regions. A record the contract refuses is counted and skipped,
// the picture stays as last presented, and the stream is scanned forward
// for the next header (`fluxor::platform::linux::display_surface`).
//
// Three modes present the picture:
//   file    each presented frame is written as a PPM file
//   window  a host window shows it, each surface pixel `scale` x `scale`
//           window pixels (host-window feature)
//   null    nothing
//
// In window mode the window is also an input source. `pointer` carries
// pointer and wheel records, `keys` key records and `text` committed text
// and input-method compositions, all as the window reports them
// (`fluxor::platform::linux::window_input`). Positions are in surface
// pixels. The optional `tree` input is the application's accessibility
// tree: while its focused node is editable the window allows its input
// method and places it at that node; otherwise the input method is off.
//
// Params are declared in `modules/platform/linux/linux_display/manifest.toml`
// and packed into the kernel's TLV stream by the config tool.

use fluxor::platform::linux::display_surface::{Picture, RasterSink};
use fluxor::platform::linux::ime_target::{Area, ImeTarget};

#[cfg(feature = "host-window")]
mod window_backend {
    use std::num::NonZeroU32;
    use std::sync::{mpsc, Arc, Mutex};
    use std::thread;

    use fluxor::abi::contracts::input::{key, pointer};
    use fluxor::platform::linux::display_surface::Picture;
    use fluxor::platform::linux::ime_target::Area;
    use fluxor::platform::linux::input_queue::{RecordQueue, Wheel};
    use fluxor::platform::linux::window_input::{
        self, key_code_for_char, key_codes, KeyInput, TextInput,
    };
    use winit::application::ApplicationHandler;
    use winit::dpi::{PhysicalPosition, PhysicalSize};
    use winit::event::{ElementState, Ime, MouseButton, MouseScrollDelta, TouchPhase, WindowEvent};
    use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
    use winit::keyboard::{Key, NamedKey};
    use winit::platform::scancode::PhysicalKeyExtScancode;
    use winit::platform::wayland::EventLoopBuilderExtWayland;
    use winit::platform::x11::EventLoopBuilderExtX11;
    use winit::window::{ImePurpose, Window, WindowAttributes, WindowId};

    /// Publish the surface's extent into the Surface Traits authority's
    /// shared slot (`super::SURFACE_WINDOW_GEOM`, packed `(w << 16) | h`).
    fn publish_surface_geom(w: u32, h: u32) {
        let packed = ((w.min(0xFFFF)) << 16) | h.min(0xFFFF);
        super::SURFACE_WINDOW_GEOM.store(packed, std::sync::atomic::Ordering::Relaxed);
    }

    /// Which of the display's input outputs the graph wired. An unwired
    /// output's records are never queued.
    #[derive(Clone, Copy)]
    pub struct Wired {
        pub pointer: bool,
        pub keys: bool,
        pub text: bool,
    }

    /// The picture to show, as the step last presented it.
    #[derive(Default)]
    struct Frame {
        width: u32,
        height: u32,
        pixels: Vec<u32>,
        fresh: bool,
    }

    /// The window's input, queued for the step.
    #[derive(Default)]
    struct Input {
        pointer: RecordQueue,
        keys: RecordQueue,
        text: RecordQueue,
    }

    /// Where the input method should stand, as the step last decided.
    #[derive(Default)]
    struct ImeRequest {
        area: Option<Area>,
        fresh: bool,
    }

    #[derive(Default)]
    struct Shared {
        frame: Mutex<Frame>,
        input: Mutex<Input>,
        ime: Mutex<ImeRequest>,
    }

    /// Window backend: a dedicated thread owns the event loop and the
    /// window; the display's step hands it pictures and input-method
    /// placement, and takes its input queues. The thread sleeps until the
    /// window system or the step wakes it, and lives as long as the
    /// program.
    pub struct WindowBackend {
        shared: Arc<Shared>,
        proxy: Option<EventLoopProxy<()>>,
    }

    impl WindowBackend {
        pub fn spawn(width: u32, height: u32, scale: u32, wired: Wired) -> Self {
            let shared = Arc::new(Shared::default());
            let for_thread = Arc::clone(&shared);
            let (proxy_tx, proxy_rx) = mpsc::channel();
            // The thread owns the event loop: the windowing library ties
            // one to the thread that created it.
            let spawned = thread::Builder::new()
                .name("fluxor-display".into())
                .spawn(move || {
                    let mut builder = EventLoop::<()>::with_user_event();
                    EventLoopBuilderExtX11::with_any_thread(&mut builder, true);
                    EventLoopBuilderExtWayland::with_any_thread(&mut builder, true);
                    let event_loop = match builder.build() {
                        Ok(event_loop) => event_loop,
                        Err(e) => {
                            log::warn!("[linux_display] no window system: {e}");
                            return;
                        }
                    };
                    event_loop.set_control_flow(ControlFlow::Wait);
                    if proxy_tx.send(event_loop.create_proxy()).is_err() {
                        return;
                    }
                    let mut app = WindowApp {
                        width,
                        height,
                        scale: scale.max(1),
                        wired,
                        window: None,
                        surface: None,
                        shared: for_thread,
                        cursor: (0, 0),
                        buttons: 0,
                        modifiers: 0,
                        text: TextInput::default(),
                    };
                    if let Err(e) = event_loop.run_app(&mut app) {
                        log::warn!("[linux_display] event loop exited: {e}");
                    }
                });
            if let Err(e) = spawned {
                log::warn!("[linux_display] window thread: {e}");
            }
            // The thread answers once its event loop exists, or drops the
            // sender when there is no window system to open one on.
            let proxy = proxy_rx.recv().ok();
            Self { shared, proxy }
        }

        fn wake(&self) {
            if let Some(proxy) = &self.proxy {
                // An error means the event loop has ended: nothing to wake.
                let _ = proxy.send_event(());
            }
        }

        /// Show `picture`.
        pub fn submit(&self, picture: Picture<'_>) {
            if let Ok(mut frame) = self.shared.frame.lock() {
                frame.width = u32::from(picture.width);
                frame.height = u32::from(picture.height);
                frame.pixels.clear();
                frame.pixels.extend_from_slice(picture.pixels);
                frame.fresh = true;
            }
            self.wake();
        }

        /// Place the input method at `area`, or turn it off.
        pub fn set_ime(&self, area: Option<Area>) {
            if let Ok(mut ime) = self.shared.ime.lock() {
                ime.area = area;
                ime.fresh = true;
            }
            self.wake();
        }

        /// Hand queued input to the three writers, each while it takes
        /// records; a refused record stays queued.
        pub fn relay(
            &self,
            pointer: impl FnMut(&[u8]) -> bool,
            keys: impl FnMut(&[u8]) -> bool,
            text: impl FnMut(&[u8]) -> bool,
        ) {
            if let Ok(mut input) = self.shared.input.lock() {
                input.pointer.relay(pointer);
                input.keys.relay(keys);
                input.text.relay(text);
            }
        }
    }

    struct WindowApp {
        /// The extent of the surface shown, in surface pixels.
        width: u32,
        height: u32,
        scale: u32,
        wired: Wired,
        window: Option<Arc<Window>>,
        surface: Option<softbuffer::Surface<Arc<Window>, Arc<Window>>>,
        shared: Arc<Shared>,
        /// The pointer's last position, in surface pixels.
        cursor: (i16, i16),
        buttons: u8,
        modifiers: u8,
        text: TextInput,
    }

    fn button_bit(button: MouseButton) -> u8 {
        match button {
            MouseButton::Left => pointer::BTN_PRIMARY,
            MouseButton::Right => pointer::BTN_SECONDARY,
            MouseButton::Middle => pointer::BTN_TERTIARY,
            MouseButton::Back => pointer::BTN_BACK,
            MouseButton::Forward => pointer::BTN_FORWARD,
            MouseButton::Other(_) => 0,
        }
    }

    /// The key contract's `key_code` for a window's logical key.
    fn key_code(key: &Key) -> u16 {
        match key {
            Key::Character(s) => s.chars().next().map_or(0, key_code_for_char),
            Key::Named(named) => match named {
                NamedKey::Backspace => key_codes::BACKSPACE,
                NamedKey::Tab => key_codes::TAB,
                NamedKey::Enter => key_codes::ENTER,
                NamedKey::Shift => key_codes::SHIFT,
                NamedKey::Control => key_codes::CONTROL,
                NamedKey::Alt | NamedKey::AltGraph => key_codes::ALT,
                NamedKey::Pause => key_codes::PAUSE,
                NamedKey::CapsLock => key_codes::CAPS_LOCK,
                NamedKey::Escape => key_codes::ESCAPE,
                NamedKey::Space => key_codes::SPACE,
                NamedKey::PageUp => key_codes::PAGE_UP,
                NamedKey::PageDown => key_codes::PAGE_DOWN,
                NamedKey::End => key_codes::END,
                NamedKey::Home => key_codes::HOME,
                NamedKey::ArrowLeft => key_codes::ARROW_LEFT,
                NamedKey::ArrowUp => key_codes::ARROW_UP,
                NamedKey::ArrowRight => key_codes::ARROW_RIGHT,
                NamedKey::ArrowDown => key_codes::ARROW_DOWN,
                NamedKey::PrintScreen => key_codes::PRINT_SCREEN,
                NamedKey::Insert => key_codes::INSERT,
                NamedKey::Delete => key_codes::DELETE,
                NamedKey::Super | NamedKey::Meta => key_codes::META,
                NamedKey::ContextMenu => key_codes::CONTEXT_MENU,
                NamedKey::NumLock => key_codes::NUM_LOCK,
                NamedKey::ScrollLock => key_codes::SCROLL_LOCK,
                NamedKey::F1 => key_codes::F1,
                NamedKey::F2 => key_codes::F1 + 1,
                NamedKey::F3 => key_codes::F1 + 2,
                NamedKey::F4 => key_codes::F1 + 3,
                NamedKey::F5 => key_codes::F1 + 4,
                NamedKey::F6 => key_codes::F1 + 5,
                NamedKey::F7 => key_codes::F1 + 6,
                NamedKey::F8 => key_codes::F1 + 7,
                NamedKey::F9 => key_codes::F1 + 8,
                NamedKey::F10 => key_codes::F1 + 9,
                NamedKey::F11 => key_codes::F1 + 10,
                NamedKey::F12 => key_codes::F1 + 11,
                _ => 0,
            },
            _ => 0,
        }
    }

    impl ApplicationHandler<()> for WindowApp {
        fn resumed(&mut self, event_loop: &ActiveEventLoop) {
            if self.window.is_some() {
                return;
            }
            // Window pixels, not points: a surface pixel is exactly
            // `scale` x `scale` of them on a display of any density.
            let attrs = WindowAttributes::default()
                .with_title("fluxor display")
                .with_inner_size(PhysicalSize::new(
                    self.width * self.scale,
                    self.height * self.scale,
                ))
                .with_resizable(false);
            let window = match event_loop.create_window(attrs) {
                Ok(w) => Arc::new(w),
                Err(e) => {
                    log::warn!("[linux_display] create_window failed: {e}");
                    event_loop.exit();
                    return;
                }
            };
            let surface = softbuffer::Context::new(Arc::clone(&window))
                .and_then(|context| softbuffer::Surface::new(&context, Arc::clone(&window)));
            let surface = match surface {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("[linux_display] window surface: {e}");
                    event_loop.exit();
                    return;
                }
            };
            window.set_ime_allowed(false);
            self.window = Some(window);
            self.surface = Some(surface);
            publish_surface_geom(self.width, self.height);
        }

        fn user_event(&mut self, _event_loop: &ActiveEventLoop, _wake: ()) {
            let Some(window) = self.window.as_ref() else {
                return;
            };
            let extent = self.shared.frame.lock().ok().and_then(|mut frame| {
                let fresh = std::mem::take(&mut frame.fresh);
                fresh.then_some((frame.width, frame.height))
            });
            if let Some((width, height)) = extent {
                if (width, height) != (self.width, self.height) {
                    self.width = width;
                    self.height = height;
                    // The answer is the window system's; the picture is
                    // drawn into whatever extent the window has.
                    let _ = window.request_inner_size(PhysicalSize::new(
                        width * self.scale,
                        height * self.scale,
                    ));
                    publish_surface_geom(width, height);
                }
                window.request_redraw();
            }
            let request = self.shared.ime.lock().ok().and_then(|mut ime| {
                let fresh = std::mem::take(&mut ime.fresh);
                fresh.then_some(ime.area)
            });
            if let Some(area) = request {
                match area {
                    Some(area) => {
                        let scale = self.scale as i32;
                        window.set_ime_purpose(if area.secret {
                            ImePurpose::Password
                        } else {
                            ImePurpose::Normal
                        });
                        window.set_ime_allowed(true);
                        window.set_ime_cursor_area(
                            PhysicalPosition::new(area.x * scale, area.y * scale),
                            PhysicalSize::new(
                                (area.w * scale).max(1) as u32,
                                (area.h * scale).max(1) as u32,
                            ),
                        );
                    }
                    None => {
                        window.set_ime_allowed(false);
                        if let Ok(mut input) = self.shared.input.lock() {
                            self.text.end(&mut input.text);
                        }
                    }
                }
            }
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
                WindowEvent::ModifiersChanged(mods) => {
                    // Key and pointer records share one modifier byte.
                    let state = mods.state();
                    let held = |down: bool, bit: u8| if down { bit } else { 0 };
                    self.modifiers = held(state.shift_key(), key::MOD_SHIFT)
                        | held(state.control_key(), key::MOD_CTRL)
                        | held(state.alt_key(), key::MOD_ALT)
                        | held(state.super_key(), key::MOD_META);
                }
                WindowEvent::CursorMoved { position, .. } => {
                    self.cursor = window_input::surface_point(position.x, position.y, self.scale);
                    self.pointer(pointer::KIND_MOVE, 0, self.buttons, self.cursor);
                }
                WindowEvent::CursorEntered { .. } => {
                    self.pointer(pointer::KIND_ENTER, 0, self.buttons, self.cursor);
                }
                WindowEvent::CursorLeft { .. } => {
                    self.pointer(pointer::KIND_LEAVE, 0, self.buttons, self.cursor);
                }
                WindowEvent::MouseInput { state, button, .. } => {
                    let bit = button_bit(button);
                    let kind = if state == ElementState::Pressed {
                        self.buttons |= bit;
                        pointer::KIND_DOWN
                    } else {
                        self.buttons &= !bit;
                        pointer::KIND_UP
                    };
                    self.pointer(kind, 0, self.buttons, self.cursor);
                }
                WindowEvent::MouseWheel { delta, .. } => {
                    let (unit, (dx, dy)) = match delta {
                        MouseScrollDelta::LineDelta(x, y) => {
                            (pointer::WHEEL_DETENTS, window_input::wheel_from_lines(x, y))
                        }
                        MouseScrollDelta::PixelDelta(by) => (
                            pointer::WHEEL_PIXELS,
                            window_input::wheel_from_pixels(by.x, by.y, self.scale),
                        ),
                    };
                    if self.wired.pointer {
                        if let Ok(mut input) = self.shared.input.lock() {
                            input.pointer.push_wheel(&Wheel {
                                pointer_id: 0,
                                unit,
                                buttons: self.buttons,
                                modifiers: self.modifiers,
                                x: self.cursor.0,
                                y: self.cursor.1,
                                dx,
                                dy,
                            });
                        }
                    }
                }
                WindowEvent::Touch(touch) => {
                    // Pointer 0 is the mouse; contacts follow it.
                    let id = (touch.id % 255) as u8 + 1;
                    let at =
                        window_input::surface_point(touch.location.x, touch.location.y, self.scale);
                    let (kind, buttons) = match touch.phase {
                        TouchPhase::Started => (pointer::KIND_DOWN, pointer::BTN_PRIMARY),
                        TouchPhase::Moved => (pointer::KIND_MOVE, pointer::BTN_PRIMARY),
                        TouchPhase::Ended => (pointer::KIND_UP, 0),
                        TouchPhase::Cancelled => (pointer::KIND_CANCEL, 0),
                    };
                    self.pointer(kind, id, buttons, at);
                }
                WindowEvent::KeyboardInput {
                    event,
                    is_synthetic: false,
                    ..
                } => {
                    if let Ok(mut input) = self.shared.input.lock() {
                        let input = &mut *input;
                        let mut unwired = RecordQueue::default();
                        let keys = if self.wired.keys {
                            &mut input.keys
                        } else {
                            &mut unwired
                        };
                        self.text.key(
                            &KeyInput {
                                pressed: event.state == ElementState::Pressed,
                                repeat: event.repeat,
                                modifiers: self.modifiers,
                                key_code: key_code(&event.logical_key),
                                scan_code: event
                                    .physical_key
                                    .to_scancode()
                                    .map_or(0, |code| code.min(u32::from(u16::MAX)) as u16),
                                text: event.text.as_deref(),
                            },
                            self.wired.text,
                            keys,
                            &mut input.text,
                        );
                    }
                }
                WindowEvent::Ime(ime) if self.wired.text => {
                    if let Ok(mut input) = self.shared.input.lock() {
                        match ime {
                            Ime::Preedit(preedit, cursor) => {
                                self.text.preedit(&preedit, cursor, &mut input.text);
                            }
                            Ime::Commit(committed) => {
                                self.text.commit(&committed, &mut input.text);
                            }
                            Ime::Disabled => self.text.end(&mut input.text),
                            Ime::Enabled => {}
                        }
                    }
                }
                WindowEvent::Focused(false) => {
                    if let Ok(mut input) = self.shared.input.lock() {
                        self.text.end(&mut input.text);
                    }
                }
                WindowEvent::Resized(size) => {
                    publish_surface_geom(size.width / self.scale, size.height / self.scale);
                }
                _ => {}
            }
        }
    }

    impl WindowApp {
        fn pointer(&mut self, kind: u8, id: u8, buttons: u8, at: (i16, i16)) {
            if !self.wired.pointer {
                return;
            }
            if let Ok(mut input) = self.shared.input.lock() {
                input.pointer.push(&window_input::pointer_record(
                    kind,
                    id,
                    buttons,
                    self.modifiers,
                    at.0,
                    at.1,
                ));
            }
        }

        /// Draw the picture into the window: each surface pixel as
        /// `scale` x `scale` window pixels from the top-left corner, black
        /// where the window reaches past the picture.
        fn redraw(&mut self) {
            let (Some(window), Some(surface)) = (self.window.as_ref(), self.surface.as_mut())
            else {
                return;
            };
            let size = window.inner_size();
            let (Some(w), Some(h)) = (NonZeroU32::new(size.width), NonZeroU32::new(size.height))
            else {
                return;
            };
            if surface.resize(w, h).is_err() {
                return;
            }
            let mut buffer = match surface.buffer_mut() {
                Ok(b) => b,
                Err(e) => {
                    log::warn!("[linux_display] surface.buffer_mut: {e}");
                    return;
                }
            };
            let Ok(frame) = self.shared.frame.lock() else {
                return;
            };
            let scale = self.scale as usize;
            let (src_w, src_h) = (frame.width as usize, frame.height as usize);
            for (y, row) in buffer.chunks_exact_mut(size.width as usize).enumerate() {
                let src_row = (y / scale < src_h)
                    .then(|| frame.pixels.get(y / scale * src_w..(y / scale + 1) * src_w))
                    .flatten();
                match src_row {
                    Some(src_row) => {
                        for (x, out) in row.iter_mut().enumerate() {
                            *out = src_row.get(x / scale).copied().unwrap_or(0);
                        }
                    }
                    None => row.fill(0),
                }
            }
            drop(frame);
            if let Err(e) = buffer.present() {
                log::warn!("[linux_display] buffer.present: {e}");
            }
        }
    }
}

use std::path::Path;

// Param TLV tags come from the module's `manifest.toml` `[[params]]` table,
// generated into `abi::platform::native`. `mode` selects file=0, null=1, window=2.
use fluxor::abi::platform::native::linux::linux_display as display_tags;
use fluxor::abi::platform::native::linux::linux_display::{
    TAG_HEIGHT as DISPLAY_TAG_HEIGHT, TAG_MODE as DISPLAY_TAG_MODE, TAG_PATH as DISPLAY_TAG_PATH,
    TAG_SCALE as DISPLAY_TAG_SCALE, TAG_WIDTH as DISPLAY_TAG_WIDTH,
};

/// The largest surface the display takes on either axis: the `width` and
/// `height` facts of its `pixels` port.
const DISPLAY_MAX_EXTENT: u16 = 4096;

/// Stream bytes one step takes from each input, so a step's work is bounded
/// whatever the producer has queued.
const DISPLAY_STEP_BYTES: usize = 256 * 1024;

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
    tree_chan: i32,
    #[cfg(feature = "host-window")]
    pointer_chan: i32,
    #[cfg(feature = "host-window")]
    keys_chan: i32,
    #[cfg(feature = "host-window")]
    text_chan: i32,
    failed: bool,
    mode: DisplayMode,
    path_template: String,
    sink: RasterSink,
    frame_counter: u32,
    /// The accessibility tree followed for the input method, when `tree`
    /// is wired, and the placement last handed to the window.
    ime: Option<ImeTarget>,
    ime_area: Option<Area>,
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
        out.push_str(&format!("{counter:04}"));
        out.push_str(&template[idx + 4..]);
        out
    } else {
        template.to_string()
    }
}

fn write_ppm(path: &str, picture: Picture<'_>) -> std::io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, picture.to_ppm())
}

/// Write `record` whole to `chan`. Whether the channel took it.
#[cfg(feature = "host-window")]
fn display_write(chan: i32, record: &[u8]) -> bool {
    // SAFETY: `record` is readable for its length; the channel copies it.
    let written = unsafe { channel::channel_write(chan, record.as_ptr(), record.len()) };
    written > 0 && written as usize == record.len()
}

impl LinuxDisplayState {
    /// Present one completed frame in the configured mode.
    fn present(&mut self, picture: Picture<'_>) {
        match self.mode {
            DisplayMode::File => {
                if self.failed {
                    return;
                }
                let path = render_path_template(&self.path_template, self.frame_counter);
                if let Err(e) = write_ppm(&path, picture) {
                    log::warn!("[linux_display] write {path} failed: {e}");
                    self.failed = true;
                } else if self.frame_counter < 4 || self.frame_counter.is_multiple_of(60) {
                    log::info!("[linux_display] wrote {path}");
                }
            }
            DisplayMode::Null => {}
            #[cfg(feature = "host-window")]
            DisplayMode::Window => {
                if let Some(w) = self.window.as_ref() {
                    w.submit(picture);
                }
            }
        }
        self.frame_counter = self.frame_counter.wrapping_add(1);
    }
}

/// # Safety
/// `state` is this module's own arena state, exclusively the
/// step's for its duration.
unsafe extern "C" fn linux_display_step(state: *mut u8) -> i32 {
    // SAFETY: kernel-owned arena sized to `LinuxDisplayState` by the loader.
    let st = unsafe { instance_state::<LinuxDisplayState>(state) };

    let mut buf = [0u8; 4096];
    if st.in_chan >= 0 {
        let mut taken = 0usize;
        while taken < DISPLAY_STEP_BYTES {
            // SAFETY: `channel_read` writes at most `buf.len()` bytes.
            let n = unsafe { channel::channel_read(st.in_chan, buf.as_mut_ptr(), buf.len()) };
            if n <= 0 {
                break;
            }
            let n = n as usize;
            taken += n;
            // The sink is lent out of the state while it calls back into
            // it to present.
            let mut sink = std::mem::replace(&mut st.sink, RasterSink::new(0, 0));
            sink.feed(
                &buf[..n],
                |picture| st.present(picture),
                |fault, refused| {
                    if refused.is_power_of_two() {
                        log::warn!(
                            "[linux_display] raster record refused ({fault:?}); {refused} refused so far"
                        );
                    }
                },
            );
            st.sink = sink;
        }
    }

    if st.tree_chan >= 0 {
        if let Some(ime) = st.ime.as_mut() {
            let mut taken = 0usize;
            while taken < DISPLAY_STEP_BYTES {
                // SAFETY: `channel_read` writes at most `buf.len()` bytes.
                let n = unsafe { channel::channel_read(st.tree_chan, buf.as_mut_ptr(), buf.len()) };
                if n <= 0 {
                    break;
                }
                taken += n as usize;
                ime.feed(&buf[..n as usize]);
            }
            let area = ime.area();
            if area != st.ime_area {
                st.ime_area = area;
                #[cfg(feature = "host-window")]
                if let Some(w) = st.window.as_ref() {
                    w.set_ime(area);
                }
            }
        }
    }

    #[cfg(feature = "host-window")]
    if let Some(w) = st.window.as_ref() {
        let (pointer, keys, text) = (st.pointer_chan, st.keys_chan, st.text_chan);
        w.relay(
            |record| display_write(pointer, record),
            |record| display_write(keys, record),
            |record| display_write(text, record),
        );
    }
    0
}

fn build_linux_display(module_idx: usize, params: &[u8]) -> Result<Box<LinuxDisplayState>, i32> {
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
    let mode_str = match mode {
        DisplayMode::File => "file",
        DisplayMode::Null => "null",
        #[cfg(feature = "host-window")]
        DisplayMode::Window => "window",
    };
    let in_chan = scheduler::module_port(module_idx, display_tags::PORT_PIXELS);
    let tree_chan = scheduler::module_port(module_idx, display_tags::PORT_TREE);
    let pointer_chan = scheduler::module_port(module_idx, display_tags::PORT_POINTER);
    let keys_chan = scheduler::module_port(module_idx, display_tags::PORT_KEYS);
    let text_chan = scheduler::module_port(module_idx, display_tags::PORT_TEXT);
    log::info!(
        "[linux_display] mode={mode_str} window {width}x{height} scale={scale} path='{path}'",
    );
    if mode_str != "window" && (pointer_chan >= 0 || keys_chan >= 0 || text_chan >= 0) {
        log::warn!(
            "[linux_display] pointer, keys and text come from the window; mode={mode_str} sends none"
        );
    }

    #[cfg(feature = "host-window")]
    let window = if matches!(mode, DisplayMode::Window) {
        Some(window_backend::WindowBackend::spawn(
            width as u32,
            height as u32,
            scale as u32,
            window_backend::Wired {
                pointer: pointer_chan >= 0,
                keys: keys_chan >= 0,
                text: text_chan >= 0,
            },
        ))
    } else {
        None
    };
    let st = Box::new(LinuxDisplayState {
        in_chan,
        tree_chan,
        #[cfg(feature = "host-window")]
        pointer_chan,
        #[cfg(feature = "host-window")]
        keys_chan,
        #[cfg(feature = "host-window")]
        text_chan,
        failed: false,
        mode,
        path_template: path,
        sink: RasterSink::new(DISPLAY_MAX_EXTENT, DISPLAY_MAX_EXTENT),
        frame_counter: 0,
        ime: (tree_chan >= 0).then(ImeTarget::new),
        ime_area: None,
        #[cfg(feature = "host-window")]
        window,
    });
    log::info!(
        "[inst] module {module_idx} = linux_display (native) in={in_chan} tree={tree_chan} \
         pointer={pointer_chan} keys={keys_chan} text={text_chan}"
    );
    Ok(st)
}

impl HostNative for LinuxDisplayState {
    fn build(slot: usize, params: &[u8]) -> Result<Box<Self>, i32> {
        build_linux_display(slot, params)
    }
}

/// The `linux_display` native module.
pub static LINUX_DISPLAY: NativeVtable =
    host_vtable::<LinuxDisplayState>(linux_display_step, native::linux_display::STATE_BYTES);
