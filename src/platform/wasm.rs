//! WASM platform entry — kernel exports + host imports.
//!
//! This file is the wasm32 analog of `src/platform/linux.rs` (process
//! `main()`) and the embedded `src/main.rs` (silicon boot path). The
//! WASM kernel does not have a `main`; instead it exposes a small set
//! of functions the host shim calls, and imports a small set of
//! functions the host provides.
//!
//! See `docs/architecture/wasm_platform.md` for the platform contract
//! and the per-host docs for what the shim looks like.

#![allow(
    unused_unsafe,
    reason = "explicit unsafe block kept for SAFETY documentation; compiler may elide the requirement"
)]

use crate::kernel::exec::scheduler;

#[path = "wasm/canvas.rs"]
mod canvas;

#[path = "wasm/camera.rs"]
mod camera;

#[path = "wasm/display_capture.rs"]
mod display_capture;

#[path = "wasm/scan_out.rs"]
mod scan_out;

#[path = "wasm/ws_source.rs"]
mod ws_source;

#[path = "wasm/dom_input.rs"]
mod dom_input;

// Per-class input modules (capability-surface model). Each emits one
// of the `crates/fluxor-abi/src/contracts/input/*` contracts; see the matching
// `stacks/{gamepad,pointer,keyboard}.toml` for how `platform.gamepad:
// {}` etc. select the right producer per-target. `dom_input` above
// multiplexes keyboard events on a single channel; a graph that wants one
// class wires the matching per-class module below via a
// `platform.<class>: {}` stack reference.
#[path = "wasm/keyboard.rs"]
mod keyboard;

#[path = "wasm/pointer.rs"]
mod pointer;

#[path = "wasm/gamepad.rs"]
mod gamepad;

// Surface Traits authority — drains coalesced environment-plane snapshots
// (viewport / orientation / size class / modality / audio) from the browser
// host shim and emits `input::surface_traits::MSG_TRAITS` records.
#[path = "wasm/surface_traits.rs"]
mod surface_traits;

// Demo consumer of the Surface Traits surface — decodes MSG_TRAITS and
// logs the fields, proving the round-trip end-to-end.
#[path = "wasm/surface_traits_probe.rs"]
mod surface_traits_probe;

// The mirror of a drawn UI: checks `AccessibilityTree` batches, hands the
// page the checked ones, and emits `AccessibilityActions` and `TextEvents`.
#[path = "wasm/accessibility.rs"]
mod accessibility;

// Browser-side BUTTON capability driver — wasm equivalent of
// `flash_rp` (rp BOOTSEL) and `modules/foundation/button` (rp GPIO).
// Emits one-byte transitions (`input::button` raw contract) drained
// from a host-side queue the runtime shell populates on canvas tap.
// Downstream `gesture` does click counting + FMP mapping, identical
// to every other platform's chain.
#[path = "wasm/button.rs"]
mod button;

#[path = "wasm/action.rs"]
mod action;

#[path = "wasm/midi.rs"]
mod midi;

// DOM terminal — kernel-log-ring scrollback rendered into the page.
// Drains via the same LOG_RING_DRAIN opcode (`diag::LOG_RING_DRAIN`) that
// `log_net` uses on bcm2712/rp; multi-consumer-safe, so wiring a
// terminal alongside `log_net` doesn't steal bytes.
#[path = "wasm/terminal.rs"]
mod terminal;

// Touch-overlay-to-gamepad transformer. Consumes pointer events,
// emits gamepad MSG_STATE based on which on-screen region each
// active pointer hits. Visual overlay (DPAD + face-button divs) is
// rendered by the runtime shell from the same canonical region
// table the module hit-tests against.
#[path = "wasm/touch_gamepad_overlay.rs"]
pub(crate) mod touch_gamepad_overlay;

#[path = "wasm/audio.rs"]
mod audio;

#[path = "wasm/gpu.rs"]
mod gpu;

// The generic GPU provider, on the page's one shared WebGPU device.
#[path = "wasm/gpu_compute.rs"]
mod gpu_compute;

#[path = "wasm/websocket.rs"]
mod websocket;

#[path = "wasm/fetch.rs"]
mod fetch;

#[path = "wasm/http.rs"]
mod http;

#[path = "wasm/ws.rs"]
mod ws;

#[path = "wasm/image_codec.rs"]
mod image_codec;

#[path = "wasm/fs.rs"]
mod fs;

#[path = "wasm/object.rs"]
mod object;

#[path = "wasm/image_decode.rs"]
mod image_decode;

#[path = "wasm/namespace.rs"]
mod namespace;

#[path = "wasm/stream_time.rs"]
mod stream_time;

#[path = "wasm/hal.rs"]
mod hal;

// The module host: every loader-resolved module is a wasm payload,
// instantiated as its own wasm instance through the host.
#[path = "wasm/module_host.rs"]
mod module_host;

/// Lightweight TLV walker for native module params. Mirrors
/// `src/platform/linux/native_params.rs::walk_tlv`. A native module
/// receives its per-instance TLV blob as `NativeInit::params`; tags
/// 10..0xEF are the manifest-declared params, tags 0xF0..0xFF are reserved.
///
/// Each tag a native module reads, and each port it binds by name through
/// `scheduler::module_port`, comes from `crate::abi::platform::native::wasm`,
/// which `fluxor abi-regen` generates from the `[[params]]` and `[[ports]]`
/// tables of the wasm native module manifests.
fn walk_tlv<F: FnMut(u8, &[u8])>(blob: &[u8], f: F) {
    fluxor_contracts::params_tlv::walk_declared(blob, f);
}

fn tlv_u32(value: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    let n = value.len().min(4);
    buf[..n].copy_from_slice(&value[..n]);
    u32::from_le_bytes(buf)
}

/// Move fixed-size input records from a host queue to `chan`: pop one with
/// `pop`, check it with `admit`, write it, repeat until the queue is empty
/// or the channel refuses a record. A refused record stays in `held` and is
/// written first on the next call, so a full channel delays input and never
/// loses it (a lost key-up is a stuck key). A record `admit` refuses is
/// dropped: it is not one the contract allows on the edge.
///
/// `held[0]` is the record's message type, which no contract allocates as
/// zero: zero there means nothing is held.
///
/// # Safety
/// `pop` is a host import that writes at most the `len` bytes it is given.
unsafe fn relay_records<const N: usize>(
    chan: i32,
    held: &mut [u8; N],
    pop: unsafe extern "C" fn(*mut u8, usize) -> i32,
    admit: fn(&[u8; N]) -> bool,
) {
    loop {
        if held[0] == 0 {
            // SAFETY: the caller's contract; `held` is N writable bytes.
            let n = unsafe { pop(held.as_mut_ptr(), N) };
            if n <= 0 {
                return;
            }
            if n as usize != N || !admit(held) {
                held[0] = 0;
                continue;
            }
        }
        // SAFETY: `held` is N readable bytes.
        let written = unsafe { crate::kernel::ipc::channel::channel_write(chan, held.as_ptr(), N) };
        if written <= 0 {
            return;
        }
        held[0] = 0;
    }
}

// ── Host imports ─────────────────────────────────────────────────────
//
// The host (browser shim, wasmtime shim, edge runtime) provides these
// functions. They are the kernel-uniform surface from
// `wasm_platform.md` §6 plus the WASM-specific module-instantiation
// imports. Browser-host native modules live in `src/platform/wasm/{...}.rs`
// and import their own per-capability host functions directly.

extern "C" {
    /// Emit a log line at `level` (0=trace, 1=debug, 2=info, 3=warn,
    /// 4=error). `ptr`/`len` is a UTF-8 slice in this module's linear
    /// memory.
    fn host_log(level: u32, ptr: *const u8, len: usize);

    /// Terminal panic. Hosts should surface the message and stop
    /// driving `kernel_step`.
    #[allow(
        dead_code,
        reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
    )]
    fn host_panic(ptr: *const u8, len: usize) -> !;

    /// Instantiate a WASM module from `bytes_ptr[..bytes_len]`.
    /// Returns a non-negative module handle on success, negative
    /// errno on failure.
    ///
    /// `imports_ptr` / `imports_len` are reserved; the kernel passes
    /// `(null, 0)`. The host wires the PIC syscall surface by name
    /// (`env.channel_read`, `channel_write`, `channel_poll`,
    /// `provider_open`, `provider_call`, `provider_query`,
    /// `provider_close`) into the import object at instantiation.
    /// Heap functions live module-side and are not imported.
    /// See `wasm_platform.md` §6 for the contract.
    fn host_instantiate_module(
        bytes_ptr: *const u8,
        bytes_len: usize,
        imports_ptr: *const u8,
        imports_len: usize,
    ) -> i32;

    /// Invoke an export of an instantiated module by name.
    /// `args_ptr[..args_len]` is a packed sequence of i32 LE values
    /// (one per parameter). The host writes the i32 return value as
    /// 4 bytes LE into `ret_ptr[..ret_cap]` and returns the number
    /// of bytes written, or negative errno.
    fn host_invoke_module(
        handle: i32,
        export_name_ptr: *const u8,
        export_name_len: usize,
        args_ptr: *const u8,
        args_len: usize,
        ret_ptr: *mut u8,
        ret_cap: usize,
    ) -> i32;

    /// Free the module instance identified by `handle`. Subsequent
    /// `host_invoke_module` calls with the same handle return an
    /// error.
    fn host_destroy_module(handle: i32) -> i32;
}

/// A 41-byte hand-encoded WASM module that exports a single
/// no-argument function `answer` returning `i32` const `42`.
/// Used to smoke-test the host_instantiate_module / host_invoke_module
/// round-trip without depending on a full PIC-module build pipeline.
///
/// Module shape (binary format):
///   magic:      00 61 73 6d
///   version:    01 00 00 00
///   type sec:   01 05 | 01 60 00 01 7f             ; () -> i32
///   func sec:   03 02 | 01 00                       ; 1 func, type 0
///   export sec: 07 0a | 01 06 a n s w e r 00 00     ; "answer" -> func 0
///   code sec:   0a 06 | 01 04 00 41 2a 0b           ; const 42, end
const MINIMAL_WASM_ANSWER: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, 0x03,
    0x02, 0x01, 0x00, 0x07, 0x0a, 0x01, 0x06, b'a', b'n', b's', b'w', b'e', b'r', 0x00, 0x00, 0x0a,
    0x06, 0x01, 0x04, 0x00, 0x41, 0x2a, 0x0b,
];

// ── Log forwarding ───────────────────────────────────────────────────
//
// Module-side `dev_log` syscalls land in the kernel's `syscall_log`,
// which calls `log::warn!`/`log::info!` — but those are no-ops without
// a registered logger. WASM_LOGGER forwards to `host_log` so the
// browser shim (or any host) sees module log lines alongside the
// kernel's direct log_str output.

struct WasmLogger;

impl log::Log for WasmLogger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        let level = match record.level() {
            log::Level::Error => 4u32,
            log::Level::Warn => 3,
            log::Level::Info => 2,
            log::Level::Debug => 1,
            log::Level::Trace => 0,
        };
        // Format message into a fixed-size stack buffer. core::fmt's
        // Write trait avoids any heap allocation.
        struct Sink<'a> {
            buf: &'a mut [u8],
            pos: usize,
        }
        impl core::fmt::Write for Sink<'_> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                let cap = self.buf.len();
                let take = bytes.len().min(cap.saturating_sub(self.pos));
                self.buf[self.pos..self.pos + take].copy_from_slice(&bytes[..take]);
                self.pos += take;
                Ok(())
            }
        }
        let mut buf = [0u8; 256];
        let mut sink = Sink {
            buf: &mut buf,
            pos: 0,
        };
        let _ = core::fmt::write(&mut sink, *record.args());
        let pos = sink.pos;
        // SAFETY: `host_log` is a wasm import; we pass `buf.as_ptr()` and
        // the byte length `pos` of the formatted message in the local buffer.
        unsafe {
            host_log(level, buf.as_ptr(), pos);
        }
    }
    fn flush(&self) {}
}

static WASM_LOGGER: WasmLogger = WasmLogger;

// ── Graph bookkeeping ────────────────────────────────────────────────
//
// `MODULE_COUNT` is what `kernel_module_count` reports: the module count of
// the graph `kernel_init` built (0 for a kernel with no bundled graph).
static mut MODULE_COUNT: usize = 0;

// ── Native modules ───────────────────────────────────────────────────
//
// Each browser-host bridge is a native module: a vtable in its own file,
// registered under its name hash from the one table below. Its instance
// lives on its own module heap, sized by its constructor; the arena state
// holds the instance pointer (where every step reads it) and that heap's
// arena, which its drop returns.

use crate::kernel::exec::scheduler::native::NativeNewFn;
use crate::kernel::exec::scheduler::{native, NativeVtable};
use crate::kernel::module::loader::{self, ModuleStepFn};

/// The wasm platform's native modules, registered once at init before the
/// graph is prepared: a graph names each by its name hash, and the splice
/// resolves it here when the loader does not.
static NATIVE_MODULES: &[(u32, &NativeVtable)] = &[
    (
        crate::abi::platform::native::wasm::wasm_browser_canvas::NAME_HASH,
        &canvas::WASM_BROWSER_CANVAS,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_camera::NAME_HASH,
        &camera::WASM_BROWSER_CAMERA,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_display_capture::NAME_HASH,
        &display_capture::WASM_BROWSER_DISPLAY_CAPTURE,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_scan_out::NAME_HASH,
        &scan_out::WASM_BROWSER_SCAN_OUT,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_dom_input::NAME_HASH,
        &dom_input::WASM_BROWSER_DOM_INPUT,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_keyboard::NAME_HASH,
        &keyboard::WASM_BROWSER_KEYBOARD,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_pointer::NAME_HASH,
        &pointer::WASM_BROWSER_POINTER,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_gamepad::NAME_HASH,
        &gamepad::WASM_BROWSER_GAMEPAD,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_surface_traits::NAME_HASH,
        &surface_traits::WASM_BROWSER_SURFACE_TRAITS,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_surface_traits_probe::NAME_HASH,
        &surface_traits_probe::WASM_BROWSER_SURFACE_TRAITS_PROBE,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_accessibility::NAME_HASH,
        &accessibility::WASM_BROWSER_ACCESSIBILITY,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_button::NAME_HASH,
        &button::WASM_BROWSER_BUTTON,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_action::NAME_HASH,
        &action::WASM_BROWSER_ACTION,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_midi_in::NAME_HASH,
        &midi::WASM_BROWSER_MIDI_IN,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_midi_out::NAME_HASH,
        &midi::WASM_BROWSER_MIDI_OUT,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_audio::NAME_HASH,
        &audio::WASM_BROWSER_AUDIO,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_websocket::NAME_HASH,
        &websocket::WASM_BROWSER_WEBSOCKET,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_ws_source::NAME_HASH,
        &ws_source::WASM_BROWSER_WS_SOURCE,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_http::NAME_HASH,
        &http::WASM_BROWSER_HTTP,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_ws::NAME_HASH,
        &ws::WASM_BROWSER_WS,
    ),
    (
        crate::abi::platform::native::wasm::host_browser_fetch::NAME_HASH,
        &fetch::HOST_BROWSER_FETCH,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_image_codec::NAME_HASH,
        &image_codec::WASM_BROWSER_IMAGE_CODEC,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_terminal::NAME_HASH,
        &terminal::WASM_BROWSER_TERMINAL,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_touch_gamepad_overlay::NAME_HASH,
        &touch_gamepad_overlay::WASM_BROWSER_TOUCH_GAMEPAD_OVERLAY,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_gpu::NAME_HASH,
        &gpu::WASM_BROWSER_GPU,
    ),
    (
        crate::abi::platform::native::wasm::wasm_browser_compute::NAME_HASH,
        &gpu_compute::WASM_BROWSER_COMPUTE,
    ),
];

/// Arena state of a native module whose instance lives on its own module
/// heap. The instance pointer comes first: every step reads it from the
/// start of its state.
#[repr(C)]
struct HeapInstance {
    instance: *mut u8,
    arena: *mut u8,
    arena_size: usize,
}

/// The vtable of a native module built by `new` on its own heap and stepped
/// by `step`. `state_bytes` is the native's declared state
/// (`abi::platform::native::wasm::<name>::STATE_BYTES`), the figure the build
/// charges it; a declaration that cannot hold a [`HeapInstance`] fails the
/// build of the static that names it.
const fn heap_native(new: NativeNewFn, step: ModuleStepFn, state_bytes: u32) -> NativeVtable {
    assert!(
        state_bytes as usize >= core::mem::size_of::<HeapInstance>(),
        "a heap native's declared state holds its instance record"
    );
    NativeVtable {
        new,
        step,
        refill: None,
        flush: None,
        isr_entry: None,
        drop: Some(release_heap_instance),
        state_size: state_bytes,
    }
}

/// Heap bytes an instance that allocates one `S` and nothing else needs: the
/// struct plus the heap's block header and alignment slack. Such a native's
/// declared heap seat (`HEAP_SEAT`) is asserted to hold it.
const fn heap_for<S>() -> usize {
    core::mem::size_of::<S>() + 32
}

/// Seat a module heap for `slot`, sized by the native's seat rule `seat`
/// (its `HEAP_SEAT`) for its `params` — the figure the build charges it
/// (`fluxor_contracts::state_arena::heap_seat_bytes`) — build the instance on
/// it with `build` (which allocates through the slot's heap and answers null
/// when it cannot), and record both in `state`. `0`, or `ENOMEM` with nothing
/// kept.
///
/// # Safety
/// `state` is the zeroed arena state of a [`heap_native`] instance, and the
/// current module is `slot` (as the constructor is called).
unsafe fn seat_heap_instance(
    state: *mut u8,
    slot: usize,
    seat: &[u32; 6],
    params: &[u8],
    build: impl FnOnce() -> *mut u8,
) -> i32 {
    let Some(heap_bytes) = fluxor_contracts::state_arena::heap_seat_bytes(seat, params) else {
        log::error!("[wasm-kernel] module {slot}: its heap seat overflows");
        return crate::kernel::sys::errno::ENOMEM;
    };
    let Ok(arena) = loader::alloc_state(heap_bytes) else {
        log::error!("[wasm-kernel] module {slot}: no state arena for a {heap_bytes}-byte heap");
        return crate::kernel::sys::errno::ENOMEM;
    };
    crate::kernel::mem::heap::init_module_heap(slot, arena, heap_bytes);
    let instance = build();
    if instance.is_null() {
        log::error!(
            "[wasm-kernel] module {slot}: instance does not fit its {heap_bytes}-byte heap"
        );
        crate::kernel::mem::heap::reset_module_heap(slot);
        // SAFETY: the range just allocated; nothing kept a pointer into it.
        unsafe { loader::free_state_range(arena, heap_bytes) };
        return crate::kernel::sys::errno::ENOMEM;
    }
    // SAFETY: the caller's contract: `state` holds a `HeapInstance`, 8-byte
    // aligned.
    unsafe {
        core::ptr::write(
            state.cast::<HeapInstance>(),
            HeapInstance {
                instance,
                arena,
                arena_size: heap_bytes,
            },
        )
    };
    0
}

/// # Safety
/// `state` is the arena state [`seat_heap_instance`] filled; this is its one
/// release, after the module's last step.
unsafe fn release_heap_instance(state: *mut u8) {
    // SAFETY: the caller's contract.
    let seated = unsafe { core::ptr::read(state.cast::<HeapInstance>()) };
    // SAFETY: the heap arena `seat_heap_instance` allocated; the instance on
    // it is never stepped again.
    unsafe { loader::free_state_range(seated.arena, seated.arena_size) };
}

/// The value of param `tag` in `params`, copied into `buf` (truncated to
/// it); empty when the params name none.
fn param_bytes<'b>(params: &[u8], tag: u8, buf: &'b mut [u8]) -> &'b [u8] {
    let mut len = 0usize;
    walk_tlv(params, |t, value| {
        if t == tag {
            let n = value.len().min(buf.len());
            buf[..n].copy_from_slice(&value[..n]);
            len = n;
        }
    });
    &buf[..len]
}

/// Bytes the bundle tool wrote into the modules and config blobs: zero for
/// an unbundled kernel (bare `firmware.wasm`).
fn embedded_lens() -> (usize, usize) {
    // SAFETY: volatile reads of the 'static placeholders the bundle tool
    // rewrites in place.
    unsafe {
        (
            core::ptr::read_volatile(&EMBEDDED_MODULES_BLOB.used_len) as usize,
            core::ptr::read_volatile(&EMBEDDED_CONFIG_BLOB.used_len) as usize,
        )
    }
}

/// Install the embedded config and modules blobs and build the graph they
/// compose: every module resolves in the loader (a wasm payload, through
/// the module host) or the native table, or the graph is refused.
///
/// The module count; 0 for an unbundled kernel or a refused graph.
///
/// # Safety
/// Single-threaded wasm boot, once, before the first `kernel_step`.
unsafe fn load_embedded_modules() -> usize {
    let (modules_used, config_used) = embedded_lens();
    if modules_used == 0 || config_used == 0 {
        return 0;
    }

    // Length-aware: `config_used` is the actual content size inside the
    // statically-allocated CONFIG_BLOB_CAPACITY-sized array. Bounded slice
    // construction makes the parser reject any section that overruns it.
    // SAFETY: `config_used` bytes of the 'static config placeholder.
    let cfg_slice =
        unsafe { core::slice::from_raw_parts(EMBEDDED_CONFIG_BLOB.data.as_ptr(), config_used) };
    let mod_ptr = EMBEDDED_MODULES_BLOB.data.as_ptr();
    // SAFETY: both blobs are 'static and outlive the graph built from them.
    let populated =
        unsafe { scheduler::populate_static_state_with_len(cfg_slice, mod_ptr, modules_used) };
    if let Err(msg) = populated {
        log_str(4, b"[wasm-kernel] populate_static_state failed:");
        log_str(4, msg.as_bytes());
        return 0;
    }
    match scheduler::build_graph() {
        Ok(n) => n,
        Err(rc) => {
            log_fmt2(
                4,
                "[wasm-kernel] graph refused rc=",
                rc as i64 as u64,
                "",
                0,
            );
            0
        }
    }
}

/// Host calls this once after instantiation. Returns 0 on success,
/// negative errno on failure.
#[no_mangle]
pub extern "C" fn kernel_init() -> i32 {
    log_str(2, b"[wasm-kernel] init");

    // Route `log::*!` macros through `host_log` so module-side
    // `dev_log` calls (`syscall_log` → `log::warn!`) reach the
    // browser console. `Info` level forwards module-side `dev_log`
    // and kernel error/warn paths without per-tick trace spam.
    let _ = log::set_logger(&WASM_LOGGER);
    log::set_max_level(log::LevelFilter::Info);

    // Register the WASM HAL ops table and bring up the SyscallTable +
    // built-in provider dispatchers (CHANNEL, TIMER, EVENT, BUFFER, …).
    // WASM is single-threaded with no flash / interrupts / step-guard
    // hardware, so most HAL ops are no-ops; time + crypto bridge to
    // host imports.
    crate::kernel::boot(&hal::WASM_HAL_OPS);

    // The native modules a graph may name, and the host every
    // loader-resolved module (a wasm payload) instantiates through.
    native::register_all(NATIVE_MODULES);
    native::set_loaded_module_host(&module_host::WASM_MODULE_HOST);

    // Build the graph the embedded blobs (rewritten in-place by the
    // bundle tool when building a `<config>.wasm`) compose. A bare
    // `firmware.wasm` carries none: it says so and idles.
    let (modules_used, config_used) = embedded_lens();
    if modules_used == 0 || config_used == 0 {
        log_str(2, b"[wasm-kernel] no bundled graph; idle");
    } else {
        // SAFETY: single-threaded wasm boot; runs once at init.
        let module_count = unsafe { load_embedded_modules() };
        // SAFETY: MODULE_COUNT mutated once at boot, single-threaded wasm.
        unsafe {
            MODULE_COUNT = module_count;
        }
        if module_count > 0 {
            log_fmt2(
                2,
                "[wasm-kernel] loaded ",
                module_count as u64,
                " bundled modules",
                0,
            );
            scheduler::log_arena_usage();
        }
    }

    // Smoke-test the host_instantiate_module / host_invoke_module
    // round-trip with a 41-byte hand-encoded WASM module exporting
    // `answer() -> i32 = 42`. Verifies the host's WASM-specific
    // import surface (`wasm_platform.md` §6) for an imports-free
    // module independent of the bundled-module path.
    // SAFETY: host_instantiate_module / host_invoke_module are wasm
    // imports; we pass static byte arrays for the module body and
    // export name, and a small local ret_buf.
    unsafe {
        let handle = host_instantiate_module(
            MINIMAL_WASM_ANSWER.as_ptr(),
            MINIMAL_WASM_ANSWER.len(),
            core::ptr::null(),
            0,
        );
        if handle < 0 {
            log_fmt2(
                3,
                "[wasm-kernel] host_instantiate_module failed handle=",
                handle as i64 as u64,
                "",
                0,
            );
        } else {
            let export_name = b"answer";
            let mut ret_buf = [0u8; 4];
            let n = host_invoke_module(
                handle,
                export_name.as_ptr(),
                export_name.len(),
                core::ptr::null(),
                0,
                ret_buf.as_mut_ptr(),
                ret_buf.len(),
            );
            if n == 4 {
                let value = i32::from_le_bytes(ret_buf);
                log_fmt2(
                    2,
                    "[wasm-kernel] minimal module answer=",
                    value as u64,
                    " (expected 42)",
                    0,
                );
            } else {
                log_fmt2(
                    3,
                    "[wasm-kernel] host_invoke_module returned bytes=",
                    n as i64 as u64,
                    "",
                    0,
                );
            }
        }
    }

    0
}

/// Drive one scheduler tick. Returns a hint (in milliseconds) for how
/// long the host can wait before the next call. 0 means run again
/// immediately.
///
/// Uses the one pass engine (`pass::tick_all`), as RP and Linux do, so
/// execution order, every `StepOutcome` (including `Burst`'s cap and
/// `Ready` propagation), fault transitions, step-period gating and
/// diagnostics are identical across platforms.
///
#[no_mangle]
pub extern "C" fn kernel_step() -> u32 {
    let _ = scheduler::pass::tick_all();
    // Heartbeat opt-out on wasm: the browser tab is a single-step
    // animation-frame loop and tab-side `console.log` already
    // surfaces liveness via the scenario shell's status updates. A
    // `log::info!` call from kernel_step on every frame thrashes
    // the host-shim console handler — leave the heartbeat off here.
    16 // ~60 Hz hint
}

/// Number of modules currently registered with the scheduler.
#[no_mangle]
pub extern "C" fn kernel_module_count() -> u32 {
    // SAFETY: MODULE_COUNT single-threaded wasm global.
    unsafe { MODULE_COUNT as u32 }
}

// ── Embedded blobs (modules.bin + config.bin) ────────────────────────
//
// The kernel's wasm binary carries two placeholder regions that the
// bundle tool rewrites in-place: one for `modules.bin`, one for
// `config.bin`. Each placeholder is a `#[no_mangle] pub static`
// struct laid out as:
//
//   [0..16]   magic — 16-byte ASCII sentinel; the bundle tool grep's
//             the wasm binary for this exact pattern to locate the
//             struct in the data section.
//   [16..20]  capacity — u32 LE; the byte capacity of `data`. Set by
//             the kernel build at compile time. The bundle tool
//             verifies its blob fits.
//   [20..24]  used_len — u32 LE; the byte length actually written.
//             Zero in the placeholder; bundle tool overwrites with
//             the real length.
//   [24..32]  reserved — eight bytes for future use; zero today.
//   [32..N]   data — capacity bytes of payload. Initially zero; bundle
//             tool overwrites the first `used_len` bytes with the real
//             blob.
//
// Reads of `used_len` go through `ptr::read_volatile` so the Rust
// optimizer cannot constant-fold them to zero based on the static
// initializer (the language treats `static` as immutable; the bundle
// tool's overwrite is invisible at compile time).
//
// Sizes can be tuned by the cargo features below as deployment
// envelopes change. Increasing the placeholder grows the kernel
// `.wasm` by the same amount because the bytes are emitted into the
// data section verbatim.

const MODULES_BLOB_MAGIC: [u8; 16] = *b"FLUXOR_MOD_BLOB\0";
const CONFIG_BLOB_MAGIC: [u8; 16] = *b"FLUXOR_CFG_BLOB\0";

/// Total placeholder size for `modules.bin`, including the 32-byte
/// header. A browser app graph runs ~520 KiB, and an app module able to
/// carry hi-DPI font atlases (truffle_shell ships 32px+48px DejaVu coverage,
/// ~235 KiB, for device-pixel supersampled text) more; a graph carrying a
/// JavaScript engine and its compiler is past 1 MiB on its own (phasor's
/// isolate is ~630 KiB as wasm, its compiler ~300 KiB). 2 MiB holds that;
/// the cost is the same again in the kernel `.wasm`'s data section, zeros
/// that compress away in transfer. Reproducible: the bundle tool fails fast
/// if the real blob exceeds capacity, with a clear "rebuild kernel with
/// larger placeholder" error.
const MODULES_BLOB_TOTAL: usize = 2 * 1024 * 1024;
const MODULES_BLOB_CAPACITY: usize = MODULES_BLOB_TOTAL - 32;

/// Total placeholder size for `config.bin`, including the 32-byte
/// header. Configs are normally a few KiB; 32 KiB is generous.
const CONFIG_BLOB_TOTAL: usize = 32 * 1024;
const CONFIG_BLOB_CAPACITY: usize = CONFIG_BLOB_TOTAL - 32;

#[repr(C)]
pub struct ModulesBlob {
    pub magic: [u8; 16],
    pub capacity: u32,
    pub used_len: u32,
    pub reserved: [u8; 8],
    pub data: [u8; MODULES_BLOB_CAPACITY],
}

#[repr(C)]
pub struct ConfigBlob {
    pub magic: [u8; 16],
    pub capacity: u32,
    pub used_len: u32,
    pub reserved: [u8; 8],
    pub data: [u8; CONFIG_BLOB_CAPACITY],
}

#[no_mangle]
pub static EMBEDDED_MODULES_BLOB: ModulesBlob = ModulesBlob {
    magic: MODULES_BLOB_MAGIC,
    capacity: MODULES_BLOB_CAPACITY as u32,
    used_len: 0,
    reserved: [0u8; 8],
    data: [0u8; MODULES_BLOB_CAPACITY],
};

#[no_mangle]
pub static EMBEDDED_CONFIG_BLOB: ConfigBlob = ConfigBlob {
    magic: CONFIG_BLOB_MAGIC,
    capacity: CONFIG_BLOB_CAPACITY as u32,
    used_len: 0,
    reserved: [0u8; 8],
    data: [0u8; CONFIG_BLOB_CAPACITY],
};

/// Linear-memory address of the first byte of the modules-blob payload
/// (i.e. `data[0]`, after the 32-byte header).
#[no_mangle]
pub extern "C" fn kernel_modules_blob_offset() -> u32 {
    EMBEDDED_MODULES_BLOB.data.as_ptr() as u32
}

/// Number of bytes the bundle tool wrote into the modules blob.
/// Returns 0 for an unbundled kernel (bare `firmware.wasm`).
#[no_mangle]
pub extern "C" fn kernel_modules_blob_len() -> u32 {
    // SAFETY: EMBEDDED_MODULES_BLOB.used_len is a `u32` field in a 'static
    // placeholder rewritten in-place by the bundle tool; volatile read.
    unsafe { core::ptr::read_volatile(&EMBEDDED_MODULES_BLOB.used_len) }
}

/// Maximum bytes the modules blob can hold (excludes header).
#[no_mangle]
pub extern "C" fn kernel_modules_blob_capacity() -> u32 {
    EMBEDDED_MODULES_BLOB.capacity
}

/// Linear-memory address of the first byte of the config-blob payload.
#[no_mangle]
pub extern "C" fn kernel_config_blob_offset() -> u32 {
    EMBEDDED_CONFIG_BLOB.data.as_ptr() as u32
}

/// Number of bytes the bundle tool wrote into the config blob.
#[no_mangle]
pub extern "C" fn kernel_config_blob_len() -> u32 {
    // SAFETY: EMBEDDED_CONFIG_BLOB.used_len is a `u32` field in a 'static
    // placeholder rewritten in-place by the bundle tool; volatile read.
    unsafe { core::ptr::read_volatile(&EMBEDDED_CONFIG_BLOB.used_len) }
}

/// Maximum bytes the config blob can hold (excludes header).
#[no_mangle]
pub extern "C" fn kernel_config_blob_capacity() -> u32 {
    EMBEDDED_CONFIG_BLOB.capacity
}

// ── Panic handler ────────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    // Surface the panic location — "[wasm-kernel] panic" alone has
    // cost real debugging time. (The payload itself needs fmt
    // machinery; file:line is enough to find the site.)
    let mut buf = [0u8; 160];
    let mut pos = 0usize;
    pos = append_str(&mut buf, pos, b"[wasm-kernel] panic at ");
    if let Some(loc) = info.location() {
        let file = loc.file().as_bytes();
        let tail = if file.len() > 80 {
            &file[file.len() - 80..]
        } else {
            file
        };
        pos = append_str(&mut buf, pos, tail);
        pos = append_str(&mut buf, pos, b":");
        pos = append_u64(&mut buf, pos, loc.line() as u64);
    }
    // SAFETY: wasm imports; we pass a stack buffer and its length.
    unsafe {
        host_log(4, buf.as_ptr(), pos);
        host_panic(buf.as_ptr(), pos)
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

fn log_str(level: u32, msg: &[u8]) {
    // SAFETY: wasm import; pass the message pointer + length.
    unsafe {
        host_log(level, msg.as_ptr(), msg.len());
    }
}

pub(crate) fn log_fmt2(level: u32, label_a: &str, value_a: u64, label_b: &str, value_b: u64) {
    let mut buf = [0u8; 128];
    let mut pos = 0usize;
    pos = append_str(&mut buf, pos, label_a.as_bytes());
    pos = append_u64(&mut buf, pos, value_a);
    pos = append_str(&mut buf, pos, label_b.as_bytes());
    pos = append_u64(&mut buf, pos, value_b);
    // SAFETY: wasm import; pass the formatted buffer pointer + populated length.
    unsafe {
        host_log(level, buf.as_ptr(), pos);
    }
}

fn append_str(buf: &mut [u8], mut pos: usize, s: &[u8]) -> usize {
    for &b in s {
        if pos < buf.len() {
            buf[pos] = b;
            pos += 1;
        }
    }
    pos
}

fn append_u64(buf: &mut [u8], mut pos: usize, value: u64) -> usize {
    let mut tmp = [0u8; 20];
    let mut tlen = 0usize;
    let mut v = value;
    if v == 0 {
        tmp[0] = b'0';
        tlen = 1;
    } else {
        while v > 0 && tlen < tmp.len() {
            tmp[tlen] = b'0' + (v % 10) as u8;
            v /= 10;
            tlen += 1;
        }
    }
    while tlen > 0 && pos < buf.len() {
        tlen -= 1;
        buf[pos] = tmp[tlen];
        pos += 1;
    }
    pos
}

// ── Syscall exports for child wasm modules ──────────────────────────
//
// Bundled wasm modules instantiated via `host_instantiate_module`
// import their syscall surface (channel_read, channel_write,
// provider_call, etc.) as `extern "C"` wasm imports. The browser /
// wasmtime / edge host shim wires those imports to JS callbacks that
// in turn invoke these kernel exports via the kernel's own
// `WebAssembly.Instance`.
//
// **Memory translation.** Each child module has its own
// `WebAssembly.Memory`. A pointer like `buf: *const u8` passed from
// the child to a syscall is meaningless in the kernel's memory. The
// host bridge is responsible for copying bytes between the child's
// memory and the kernel's at every cross-boundary call (read on the
// way in, write on the way back for output buffers). These exports
// take pointers into the **kernel's** linear memory; the bridge
// allocates a kernel-side scratch via `kernel_heap_alloc`, copies
// into it, calls the export, then copies any output back to the
// child.
//
// `kernel_heap_alloc` / `kernel_heap_free` are the bridge's
// allocator. Modules' own `heap_alloc` / `heap_free` (wired below)
// allocate from each module's per-module arena via the kernel's
// scheduler. The bridge's scratch buffers are short-lived and use
// the kernel's main heap.
//
// # Safety (applies to every export below)
//
// The wasm module's host bridge calls these. All pointer arguments
// must be in the kernel's linear memory (the host shim is
// responsible for allocating kernel scratch via `kernel_heap_alloc`
// and copying child-memory bytes there before calling). `len` must
// not exceed the allocated scratch. The kernel-internal handlers
// these delegate to validate handles and capability gates and
// return negative errno on bad input — they never trust the caller.

/// Channel read. The bridge supplies a kernel-memory `buf`; if data
/// is read, the bridge copies it back into the child's memory after.
#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn channel_read(handle: i32, buf: *mut u8, len: usize) -> i32 {
    let table = crate::kernel::module::syscalls::get_syscall_table();
    (table.channel_read)(handle, buf, len)
}

/// Channel write. Bridge has copied the child's payload into a kernel
/// scratch at `data` before calling.
#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn channel_write(handle: i32, data: *const u8, len: usize) -> i32 {
    let table = crate::kernel::module::syscalls::get_syscall_table();
    (table.channel_write)(handle, data, len)
}

#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn channel_poll(handle: i32, events: u32) -> i32 {
    let table = crate::kernel::module::syscalls::get_syscall_table();
    (table.channel_poll)(handle, events)
}

/// Channel peek. Bridge supplies a kernel-memory `buf`; the bridge
/// copies bytes back into the child's memory if peek succeeded.
#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn channel_peek(handle: i32, buf: *mut u8, len: usize) -> i32 {
    let table = crate::kernel::module::syscalls::get_syscall_table();
    (table.channel_peek)(handle, buf, len)
}

/// Channel discard: consume `len` bytes whole or none; no buffer crosses
/// the bridge.
#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn channel_discard(handle: i32, len: usize) -> i32 {
    let table = crate::kernel::module::syscalls::get_syscall_table();
    (table.channel_discard)(handle, len)
}

/// Heap alloc — child-module-scoped arenas. Each instantiated module
/// has its own arena; the kernel's scheduler tracks which module is
/// the current caller via `set_current_module` (called by the bridge
/// before each syscall) and routes `heap_alloc` to that arena.
#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn heap_alloc(size: u32) -> *mut u8 {
    let table = crate::kernel::module::syscalls::get_syscall_table();
    (table.heap_alloc)(size)
}

#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn heap_free(ptr: *mut u8) {
    let table = crate::kernel::module::syscalls::get_syscall_table();
    (table.heap_free)(ptr)
}

#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn heap_realloc(ptr: *mut u8, new_size: u32) -> *mut u8 {
    let table = crate::kernel::module::syscalls::get_syscall_table();
    (table.heap_realloc)(ptr, new_size)
}

#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn provider_open(
    contract: u32,
    open_op: u32,
    config: *const u8,
    config_len: usize,
) -> i32 {
    let table = crate::kernel::module::syscalls::get_syscall_table();
    (table.provider_open)(contract, open_op, config, config_len)
}

#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn provider_call(
    handle: i32,
    op: u32,
    arg: *mut u8,
    arg_len: usize,
    data: *mut u8,
    data_len: usize,
) -> i32 {
    let table = crate::kernel::module::syscalls::get_syscall_table();
    (table.provider_call)(handle, op, arg, arg_len, data, data_len)
}

#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn provider_query(
    handle: i32,
    key: u32,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let table = crate::kernel::module::syscalls::get_syscall_table();
    (table.provider_query)(handle, key, out, out_len)
}

#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn provider_close(handle: i32) -> i32 {
    let table = crate::kernel::module::syscalls::get_syscall_table();
    (table.provider_close)(handle)
}

/// Bridge-side scratch allocator. The host shim calls this to obtain
/// a buffer in the kernel's linear memory for cross-boundary copies
/// (child memory → kernel memory on syscall entry; kernel → child on
/// output return). Returns a pointer in the kernel's memory.
#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn kernel_heap_alloc(size: u32) -> *mut u8 {
    let table = crate::kernel::module::syscalls::get_syscall_table();
    (table.heap_alloc)(size)
}

#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn kernel_heap_free(ptr: *mut u8) {
    let table = crate::kernel::module::syscalls::get_syscall_table();
    (table.heap_free)(ptr)
}
