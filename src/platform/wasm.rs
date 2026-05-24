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

use crate::kernel::{channel, scheduler};

#[path = "wasm/canvas.rs"]
mod canvas;

#[path = "wasm/ws_source.rs"]
mod ws_source;

#[path = "wasm/dom_input.rs"]
mod dom_input;

// Per-class input modules (capability-surface model). Each emits one
// of the `modules/sdk/contracts/input/*` contracts; see the matching
// `stacks/{gamepad,pointer,keyboard}.toml` for how `platform.gamepad:
// {}` etc. select the right producer per-target. The legacy
// `dom_input` above multiplexes keyboard events on a single channel;
// new graphs wire one of the per-class modules below via a
// `platform.<class>: {}` stack reference instead.
#[path = "wasm/keyboard.rs"]
mod keyboard;

#[path = "wasm/pointer.rs"]
mod pointer;

#[path = "wasm/gamepad.rs"]
mod gamepad;

// Browser-side BUTTON capability driver — wasm equivalent of
// `flash_rp` (rp BOOTSEL) and `modules/foundation/button` (rp GPIO).
// Emits one-byte transitions (`input::button` raw contract) drained
// from a host-side queue the runtime shell populates on canvas tap.
// Downstream `gesture` does click counting + FMP mapping, identical
// to every other platform's chain.
#[path = "wasm/button.rs"]
mod button;

#[path = "wasm/midi.rs"]
mod midi;

// DOM terminal — kernel-log-ring scrollback rendered into the page.
// Drains via the same LOG_RING_DRAIN opcode (0x0C64) that
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

#[path = "wasm/websocket.rs"]
mod websocket;

#[path = "wasm/fetch.rs"]
mod fetch;

#[path = "wasm/image_codec.rs"]
mod image_codec;

#[path = "wasm/fs.rs"]
mod fs;

#[path = "wasm/hal.rs"]
mod hal;

/// Lightweight TLV walker for built-in module params. Mirrors
/// `src/platform/linux/builtin_params.rs::walk_tlv`. Built-ins receive
/// a per-instance TLV blob via `ModuleEntry::params()`; tags 10..0xEF
/// are the manifest-declared params (auto-numbered in declaration
/// order), tags 0xF0..0xFF are reserved.
fn walk_tlv<F: FnMut(u8, &[u8])>(blob: &[u8], mut f: F) {
    if blob.len() < 4 || blob[0] != 0xFE || blob[1] != 0x01 {
        return;
    }
    let payload_len = u16::from_le_bytes([blob[2], blob[3]]) as usize;
    let end = (4 + payload_len).min(blob.len());
    let mut off = 4usize;
    while off + 2 <= end {
        let tag = blob[off];
        let elen = blob[off + 1] as usize;
        off += 2;
        if tag == 0xFF || off + elen > end {
            break;
        }
        if tag < 0xF0 {
            f(tag, &blob[off..off + elen]);
        }
        off += elen;
    }
}

fn tlv_u32(value: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    let n = value.len().min(4);
    buf[..n].copy_from_slice(&value[..n]);
    u32::from_le_bytes(buf)
}

// ── Host imports ─────────────────────────────────────────────────────
//
// The host (browser shim, wasmtime shim, edge runtime) provides these
// functions. They are the kernel-uniform surface from
// `wasm_platform.md` §6 plus the WASM-specific module-instantiation
// imports. Browser-host built-ins live in `src/platform/wasm/{...}.rs`
// and import their own per-capability host functions directly.

extern "C" {
    /// Monotonic microseconds since host boot.
    fn host_now_us() -> u64;

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

    /// Probe whether a module exports a function by name. Returns 1
    /// if exported, 0 if absent, negative on bad handle. Used to
    /// check optional exports (e.g. `module_arena_size`) without
    /// invoking the host's missing-export diagnostic.
    fn host_module_export_exists(
        handle: i32,
        export_name_ptr: *const u8,
        export_name_len: usize,
    ) -> i32;

    /// Free the module instance identified by `handle`. Subsequent
    /// `host_invoke_module` calls with the same handle return an
    /// error.
    #[allow(
        dead_code,
        reason = "target-conditional or kept for diagnostic use; the cfg-gated build path doesn't always reach it"
    )]
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

// ── Loaded-module bookkeeping ────────────────────────────────────────
//
// `kernel_init` populates SCHED via `store_builtin_module` /
// `instantiate_one_module`. `MODULE_COUNT` is the upper bound
// `kernel_step` iterates over — mirrors `module_count` in
// `src/platform/linux.rs::main`.
static mut MODULE_COUNT: usize = 0;

// ── Kernel exports ───────────────────────────────────────────────────

/// In-kernel tick_source / tick_sink demo. Runs only when no bundled
/// modules are present — mainly for the bare `firmware.wasm` smoke
/// artifact. Real configs ship through `load_embedded_modules`.
fn init_tick_demo() {
    let chan = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);
    if chan < 0 {
        log_str(4, b"[wasm-kernel] channel_open failed");
        return;
    }

    let mut source = scheduler::BuiltInModule::new("wasm_tick_source", tick_source_step);
    source.state[0..4].copy_from_slice(&(chan as i32).to_le_bytes());
    scheduler::store_builtin_module(0, source);

    let mut sink = scheduler::BuiltInModule::new("wasm_tick_sink", tick_sink_step);
    sink.state[0..4].copy_from_slice(&(chan as i32).to_le_bytes());
    scheduler::store_builtin_module(1, sink);

    // SAFETY: MODULE_COUNT mutated once at boot under single-threaded
    // wasm runtime; init_tick_demo is the only writer in this path.
    unsafe {
        MODULE_COUNT = 2;
    }
    log_str(
        2,
        b"[wasm-kernel] tick demo: 2 builtins (tick_source -> tick_sink)",
    );
}

/// Bit 5 of the FXMD reserved[0] flags byte = wasm-payload module.
/// Mirrors `tools/src/modules.rs::pack_fmod_wasm` (sets reserved[0] |= 0x20).
const FLAG_WASM_PAYLOAD: u8 = 0x20;

use crate::abi::wire::fnv1a32;

const WASM_BROWSER_CANVAS_HASH: u32 = fnv1a32(b"wasm_browser_canvas");
const WASM_BROWSER_DOM_INPUT_HASH: u32 = fnv1a32(b"wasm_browser_dom_input");
const WASM_BROWSER_KEYBOARD_HASH: u32 = fnv1a32(b"wasm_browser_keyboard");
const WASM_BROWSER_POINTER_HASH: u32 = fnv1a32(b"wasm_browser_pointer");
const WASM_BROWSER_BUTTON_HASH: u32 = fnv1a32(b"wasm_browser_button");
const WASM_BROWSER_GAMEPAD_HASH: u32 = fnv1a32(b"wasm_browser_gamepad");
const WASM_BROWSER_AUDIO_HASH: u32 = fnv1a32(b"wasm_browser_audio");
const WASM_BROWSER_WEBSOCKET_HASH: u32 = fnv1a32(b"wasm_browser_websocket");
const WASM_BROWSER_WS_SOURCE_HASH: u32 = fnv1a32(b"wasm_browser_ws_source");
const HOST_BROWSER_FETCH_HASH: u32 = fnv1a32(b"host_browser_fetch");
const WASM_BROWSER_IMAGE_CODEC_HASH: u32 = fnv1a32(b"wasm_browser_image_codec");
const WASM_BROWSER_TERMINAL_HASH: u32 = fnv1a32(b"wasm_browser_terminal");
const WASM_BROWSER_TOUCH_GAMEPAD_OVERLAY_HASH: u32 = fnv1a32(b"wasm_browser_touch_gamepad_overlay");
// MIDI built-ins — STUB. See `wasm/midi.rs` for the unimplemented
// state. Registered here so configs that reference the modules
// load cleanly instead of failing at the runtime dispatch step.
const WASM_BROWSER_MIDI_IN_HASH: u32 = fnv1a32(b"wasm_browser_midi_in");
const WASM_BROWSER_MIDI_OUT_HASH: u32 = fnv1a32(b"wasm_browser_midi_out");

/// Initialise a per-module heap sized for one `State` struct plus
/// alignment slack. Each built-in's `alloc_state` makes one
/// `heap_alloc(size_of::<State>())` call, so the heap doesn't need
/// to grow. Returns false if the shared STATE_ARENA is full; caller
/// logs and skips the module.
fn init_builtin_heap<S>(module_idx: usize) -> bool {
    init_builtin_heap_sized(module_idx, core::mem::size_of::<S>() + 32)
}

/// Variant for built-ins whose runtime heap need exceeds their
/// State struct (e.g. `wasm_browser_image_codec` heap-allocs a
/// max_bytes-sized encoded buffer alongside its small State).
fn init_builtin_heap_sized(module_idx: usize, bytes: usize) -> bool {
    match crate::kernel::loader::alloc_state(bytes) {
        Ok(arena_ptr) => {
            crate::kernel::heap::init_module_heap(module_idx, arena_ptr, bytes);
            true
        }
        Err(_) => false,
    }
}

/// Walk the kernel's compiled module list (populated from
/// `EMBEDDED_CONFIG_BLOB` by `populate_static_state` + `prepare_graph`)
/// and instantiate each module — either as a kernel-side built-in
/// (for `wasm_browser_*` host bridges) or as a packed wasm payload
/// via `host_instantiate_module`.
///
/// Returns the number of modules successfully registered. Failures
/// (unsatisfied imports, missing bridges, etc.) are logged and
/// skipped so partial bring-up doesn't take down the kernel.
unsafe fn load_embedded_modules() -> usize {
    let modules_used = core::ptr::read_volatile(&EMBEDDED_MODULES_BLOB.used_len) as usize;
    let config_used = core::ptr::read_volatile(&EMBEDDED_CONFIG_BLOB.used_len) as usize;
    if modules_used == 0 || config_used == 0 {
        return 0;
    }

    // Populate the kernel's STATIC_CONFIG / STATIC_LOADER from the
    // embedded blobs and compile the graph. `prepare_graph` builds
    // the per-module port table, allocates channels, and returns the
    // resolved module list keyed by name_hash.
    // Length-aware: `config_used` is the actual content size inside the
    // statically-allocated CONFIG_BLOB_CAPACITY-sized array. Bounded slice
    // construction makes the parser reject any section that overruns it.
    let cfg_slice = core::slice::from_raw_parts(EMBEDDED_CONFIG_BLOB.data.as_ptr(), config_used);
    let mod_ptr = EMBEDDED_MODULES_BLOB.data.as_ptr();
    if let Err(msg) = scheduler::populate_static_state_with_len(cfg_slice, mod_ptr, modules_used) {
        log_str(4, b"[wasm-kernel] populate_static_state failed:");
        log_str(4, msg.as_bytes());
        return 0;
    }
    let (module_list, module_count) = match scheduler::prepare_graph() {
        Ok(v) => v,
        Err(rc) => {
            log_fmt2(
                4,
                "[wasm-kernel] prepare_graph failed rc=",
                rc as i64 as u64,
                "",
                0,
            );
            return 0;
        }
    };

    let modules_blob_len = EMBEDDED_MODULES_BLOB.data.len().min(modules_used);
    let mut registered = 0usize;

    for (module_idx, entry_opt) in module_list.iter().enumerate().take(module_count) {
        let entry = match entry_opt {
            Some(e) => e,
            None => continue,
        };
        scheduler::set_current_module(module_idx);

        // Browser-host built-ins, dispatched by name_hash. Same
        // pattern as the Linux platform (`linux_audio`,
        // `host_image_codec`).
        //
        // Each built-in's `alloc_state` calls `(table.heap_alloc)(size)`
        // for its single State struct, routing through
        // `MODULE_HEAPS[module_idx].alloc`. That heap returns null
        // until initialised; the PIC loader sets it up via
        // `module_arena_size` for compiled wasm modules, but built-ins
        // skip the loader. Each branch below sizes a heap to fit its
        // own State struct (plus alignment slack) before calling
        // `build()`.
        if entry.name_hash == WASM_BROWSER_CANVAS_HASH {
            // Width/height first — the per-module heap holds the
            // RGB565 frame buffer (width * height * 2), so heap
            // sizing depends on the params.
            let mut width = 0u16;
            let mut height = 0u16;
            walk_tlv(entry.params(), |tag, value| match tag {
                10 => width = tlv_u32(value) as u16,
                11 => height = tlv_u32(value) as u16,
                _ => {}
            });
            let heap_bytes = canvas::heap_size_for(width, height);
            if !init_builtin_heap_sized(module_idx, heap_bytes) {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    " = wasm_browser_canvas: STATE_ARENA full, skipping",
                    heap_bytes as u64,
                );
                continue;
            }
            let in_chan = scheduler::get_module_port(module_idx, 0, 0);
            let m = canvas::build(width, height, in_chan);
            scheduler::store_builtin_module(module_idx, m);
            registered += 1;
            log_fmt2(
                2,
                "[wasm-kernel] module ",
                module_idx as u64,
                " = wasm_browser_canvas (built-in)",
                0,
            );
            continue;
        }

        if entry.name_hash == WASM_BROWSER_DOM_INPUT_HASH {
            if !init_builtin_heap::<dom_input::DomInputState>(module_idx) {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    " = wasm_browser_dom_input: STATE_ARENA full, skipping",
                    0,
                );
                continue;
            }
            let out_chan = scheduler::get_module_port(module_idx, 1, 0);
            let m = dom_input::build(out_chan);
            scheduler::store_builtin_module(module_idx, m);
            registered += 1;
            log_fmt2(
                2,
                "[wasm-kernel] module ",
                module_idx as u64,
                " = wasm_browser_dom_input (built-in)",
                0,
            );
            continue;
        }

        // Per-class input modules — capability-surface partition of
        // the old dom_input. Each emits its corresponding
        // `modules/sdk/contracts/input/*` contract on its single
        // output port (port idx 0 — input modules are sources).
        if entry.name_hash == WASM_BROWSER_KEYBOARD_HASH {
            if !init_builtin_heap::<keyboard::KeyboardState>(module_idx) {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    " = wasm_browser_keyboard: STATE_ARENA full, skipping",
                    0,
                );
                continue;
            }
            let out_chan = scheduler::get_module_port(module_idx, 1, 0);
            let m = keyboard::build(out_chan);
            scheduler::store_builtin_module(module_idx, m);
            registered += 1;
            log_fmt2(
                2,
                "[wasm-kernel] module ",
                module_idx as u64,
                " = wasm_browser_keyboard (built-in)",
                0,
            );
            continue;
        }

        if entry.name_hash == WASM_BROWSER_POINTER_HASH {
            if !init_builtin_heap::<pointer::PointerState>(module_idx) {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    " = wasm_browser_pointer: STATE_ARENA full, skipping",
                    0,
                );
                continue;
            }
            let out_chan = scheduler::get_module_port(module_idx, 1, 0);
            let m = pointer::build(out_chan);
            scheduler::store_builtin_module(module_idx, m);
            registered += 1;
            log_fmt2(
                2,
                "[wasm-kernel] module ",
                module_idx as u64,
                " = wasm_browser_pointer (built-in)",
                0,
            );
            continue;
        }

        if entry.name_hash == WASM_BROWSER_GAMEPAD_HASH {
            if !init_builtin_heap::<gamepad::GamepadState>(module_idx) {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    " = wasm_browser_gamepad: STATE_ARENA full, skipping",
                    0,
                );
                continue;
            }
            let out_chan = scheduler::get_module_port(module_idx, 1, 0);
            let m = gamepad::build(out_chan);
            scheduler::store_builtin_module(module_idx, m);
            registered += 1;
            log_fmt2(
                2,
                "[wasm-kernel] module ",
                module_idx as u64,
                " = wasm_browser_gamepad (built-in)",
                0,
            );
            continue;
        }

        // BUTTON capability driver — emits raw button transitions
        // (one byte per debounced edge) on out[0]. Symmetric to
        // `flash_rp` on rp boards; same `input::button` contract,
        // same downstream `gesture` chain.
        if entry.name_hash == WASM_BROWSER_BUTTON_HASH {
            if !init_builtin_heap::<button::ButtonState>(module_idx) {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    " = wasm_browser_button: STATE_ARENA full, skipping",
                    0,
                );
                continue;
            }
            let out_chan = scheduler::get_module_port(module_idx, 1, 0);
            let m = button::build(out_chan);
            scheduler::store_builtin_module(module_idx, m);
            registered += 1;
            log_fmt2(
                2,
                "[wasm-kernel] module ",
                module_idx as u64,
                " = wasm_browser_button (built-in)",
                0,
            );
            continue;
        }

        // MIDI input/output — STUB. See `wasm/midi.rs`. Registers
        // so the module loads cleanly. `midi_out` drains its input
        // channel every step so wired producers don't backpressure.
        if entry.name_hash == WASM_BROWSER_MIDI_IN_HASH {
            if !init_builtin_heap::<midi::MidiInState>(module_idx) {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    " = wasm_browser_midi_in: STATE_ARENA full, skipping",
                    0,
                );
                continue;
            }
            let m = midi::build_in();
            scheduler::store_builtin_module(module_idx, m);
            registered += 1;
            log_fmt2(
                3,
                "[wasm-kernel] module ",
                module_idx as u64,
                " = wasm_browser_midi_in (built-in, STUB - Web MIDI not yet implemented)",
                0,
            );
            continue;
        }

        if entry.name_hash == WASM_BROWSER_MIDI_OUT_HASH {
            if !init_builtin_heap::<midi::MidiOutState>(module_idx) {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    " = wasm_browser_midi_out: STATE_ARENA full, skipping",
                    0,
                );
                continue;
            }
            let events_in = scheduler::get_module_port(module_idx, 0, 0);
            let m = midi::build_out(events_in);
            scheduler::store_builtin_module(module_idx, m);
            registered += 1;
            log_fmt2(3, "[wasm-kernel] module ", module_idx as u64,
                " = wasm_browser_midi_out (built-in, STUB - Web MIDI not yet implemented; drains input channel)", 0);
            continue;
        }

        if entry.name_hash == WASM_BROWSER_AUDIO_HASH {
            if !init_builtin_heap::<audio::AudioState>(module_idx) {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    " = wasm_browser_audio: STATE_ARENA full, skipping",
                    0,
                );
                continue;
            }
            let mut sample_rate = 0u32;
            let mut channels = 1u32;
            walk_tlv(entry.params(), |tag, value| match tag {
                10 => sample_rate = tlv_u32(value),
                11 => channels = tlv_u32(value),
                _ => {}
            });
            let in_chan = scheduler::get_module_port(module_idx, 0, 0);
            let m = audio::build(sample_rate, channels, in_chan);
            scheduler::store_builtin_module(module_idx, m);
            registered += 1;
            log_fmt2(
                2,
                "[wasm-kernel] module ",
                module_idx as u64,
                " = wasm_browser_audio (built-in)",
                0,
            );
            continue;
        }

        if entry.name_hash == WASM_BROWSER_WEBSOCKET_HASH {
            if !init_builtin_heap::<websocket::WsState>(module_idx) {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    " = wasm_browser_websocket: STATE_ARENA full, skipping",
                    0,
                );
                continue;
            }
            let mut url_buf = [0u8; 256];
            let mut url_len = 0usize;
            walk_tlv(entry.params(), |tag, value| {
                if tag == 10 {
                    let n = value.len().min(url_buf.len());
                    url_buf[..n].copy_from_slice(&value[..n]);
                    url_len = n;
                }
            });
            let in_chan = scheduler::get_module_port(module_idx, 0, 0);
            let out_chan = scheduler::get_module_port(module_idx, 1, 0);
            let m = websocket::build(&url_buf[..url_len], in_chan, out_chan);
            scheduler::store_builtin_module(module_idx, m);
            registered += 1;
            log_fmt2(
                2,
                "[wasm-kernel] module ",
                module_idx as u64,
                " = wasm_browser_websocket (built-in)",
                0,
            );
            continue;
        }

        if entry.name_hash == WASM_BROWSER_WS_SOURCE_HASH {
            if !init_builtin_heap::<ws_source::WsSourceState>(module_idx) {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    " = wasm_browser_ws_source: STATE_ARENA full, skipping",
                    0,
                );
                continue;
            }
            let mut url_buf = [0u8; 256];
            let mut url_len = 0usize;
            walk_tlv(entry.params(), |tag, value| {
                if tag == 10 {
                    let n = value.len().min(url_buf.len());
                    url_buf[..n].copy_from_slice(&value[..n]);
                    url_len = n;
                }
            });
            // RX-only: no input port. Output port `bytes` is index 0
            // on direction=1 (output) by manifest declaration order.
            let out_chan = scheduler::get_module_port(module_idx, 1, 0);
            let m = ws_source::build(&url_buf[..url_len], out_chan);
            scheduler::store_builtin_module(module_idx, m);
            registered += 1;
            log_fmt2(
                2,
                "[wasm-kernel] module ",
                module_idx as u64,
                " = wasm_browser_ws_source (built-in)",
                0,
            );
            continue;
        }

        if entry.name_hash == HOST_BROWSER_FETCH_HASH {
            if !init_builtin_heap::<fetch::FetchState>(module_idx) {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    " = host_browser_fetch: STATE_ARENA full, skipping",
                    0,
                );
                continue;
            }
            let mut url_buf = [0u8; 256];
            let mut url_len = 0usize;
            walk_tlv(entry.params(), |tag, value| {
                if tag == 10 {
                    let n = value.len().min(url_buf.len());
                    url_buf[..n].copy_from_slice(&value[..n]);
                    url_len = n;
                }
            });
            let out_chan = scheduler::get_module_port(module_idx, 1, 0);
            let m = fetch::build(&url_buf[..url_len], out_chan);
            scheduler::store_builtin_module(module_idx, m);
            registered += 1;
            log_fmt2(
                2,
                "[wasm-kernel] module ",
                module_idx as u64,
                " = host_browser_fetch (built-in)",
                0,
            );
            continue;
        }

        if entry.name_hash == WASM_BROWSER_IMAGE_CODEC_HASH {
            // Read params first — `max_bytes` determines per-module
            // heap size (State + encoded buffer + slack).
            let mut width = 0u16;
            let mut height = 0u16;
            let mut max_bytes = 8u32 * 1024 * 1024;
            walk_tlv(entry.params(), |tag, value| match tag {
                10 => width = tlv_u32(value) as u16,
                11 => height = tlv_u32(value) as u16,
                12 => max_bytes = tlv_u32(value),
                _ => {}
            });
            let heap_bytes = image_codec::heap_size_for(max_bytes);
            if !init_builtin_heap_sized(module_idx, heap_bytes) {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    " = wasm_browser_image_codec: STATE_ARENA full, skipping",
                    heap_bytes as u64,
                );
                continue;
            }
            let in_chan = scheduler::get_module_port(module_idx, 0, 0);
            let out_chan = scheduler::get_module_port(module_idx, 1, 0);
            let m = image_codec::build(in_chan, out_chan, width, height, max_bytes);
            scheduler::store_builtin_module(module_idx, m);
            registered += 1;
            log_fmt2(
                2,
                "[wasm-kernel] module ",
                module_idx as u64,
                " = wasm_browser_image_codec (built-in)",
                0,
            );
            continue;
        }

        // DOM scrollback terminal — drains the kernel log ring into
        // a `<pre>` widget in the page. No data ports; the module
        // pulls from the log ring via the diag-contract drain
        // opcode same as `log_net` on embedded.
        if entry.name_hash == WASM_BROWSER_TERMINAL_HASH {
            if !init_builtin_heap::<terminal::TerminalState>(module_idx) {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    " = wasm_browser_terminal: STATE_ARENA full, skipping",
                    0,
                );
                continue;
            }
            let m = terminal::build();
            scheduler::store_builtin_module(module_idx, m);
            registered += 1;
            log_fmt2(
                2,
                "[wasm-kernel] module ",
                module_idx as u64,
                " = wasm_browser_terminal (built-in)",
                0,
            );
            continue;
        }

        // Touch-overlay → gamepad transformer. PointerEvents in,
        // GamepadEvents out. The runtime shell renders the visual
        // overlay buttons (DPAD cross + face-button diamond) from
        // the same canonical region table the module hit-tests
        // against — see `touch_gamepad_overlay::REGIONS`.
        if entry.name_hash == WASM_BROWSER_TOUCH_GAMEPAD_OVERLAY_HASH {
            if !init_builtin_heap::<touch_gamepad_overlay::OverlayState>(module_idx) {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    " = wasm_browser_touch_gamepad_overlay: STATE_ARENA full, skipping",
                    0,
                );
                continue;
            }
            let in_chan = scheduler::get_module_port(module_idx, 0, 0);
            let out_chan = scheduler::get_module_port(module_idx, 1, 0);
            let m = touch_gamepad_overlay::build(in_chan, out_chan);
            scheduler::store_builtin_module(module_idx, m);
            registered += 1;
            log_fmt2(
                2,
                "[wasm-kernel] module ",
                module_idx as u64,
                " = wasm_browser_touch_gamepad_overlay (built-in)",
                0,
            );
            continue;
        }

        // Non-builtin: locate the .fmod in modules.bin via the static
        // loader's name-hash index, verify it's a wasm payload, and
        // hand the wasm bytes to `host_instantiate_module`.
        let _ = modules_blob_len; // (loader does its own bounds check)
        let _ = mod_ptr;
        let loader = scheduler::static_loader();
        let loaded = match loader.find_by_name_hash(entry.name_hash) {
            Ok(l) => l,
            Err(_) => {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    ": no .fmod entry for name_hash",
                    entry.name_hash as u64,
                );
                continue;
            }
        };
        let header = &loaded.header;
        if header.reserved[0] & FLAG_WASM_PAYLOAD == 0 {
            log_fmt2(
                3,
                "[wasm-kernel] module ",
                module_idx as u64,
                ": .fmod is not wasm-payload; skipping",
                0,
            );
            continue;
        }

        // Run the same admission pipeline native modules go through:
        // ABI-version, code-size, manifest-integrity, signature, and
        // `enforce_signatures` gates all apply to hosted WASM modules
        // identically to RP/BCM. The wasm payload itself goes through
        // the host's wasmtime/browser instantiation below — the
        // kernel can't verify wasm32 instructions itself — but the
        // `.fmod` envelope is verified here.
        if let Err(_e) = crate::kernel::loader::validate_module(&loaded, "wasm-child") {
            log_fmt2(
                3,
                "[wasm-kernel] module ",
                module_idx as u64,
                ": validate_module rejected the .fmod envelope",
                0,
            );
            continue;
        }

        // The wasm platform's `host_instantiate_module` loop bypasses
        // `scheduler::instantiate_one_module`, so cap metadata has to
        // be staged explicitly — otherwise `check_contract_grant`
        // rejects every non-infra contract the module declares.
        let cap_class: u8 = match header.module_type {
            5 => 3, // Protocol → CAP_FULL
            3 => 1, // Sink → CAP_SERVICE_PIO
            4 => 2, // EventHandler → CAP_SERVICE_GPIO
            _ => 0, // Source / Transformer → CAP_SERVICE
        };
        scheduler::set_module_caps(
            module_idx,
            cap_class,
            header.required_caps(),
            loaded.manifest_permissions(),
        );

        let code_size = header.code_size as usize;
        let code_ptr = loaded.code_base();

        let handle = host_instantiate_module(code_ptr, code_size, core::ptr::null(), 0);
        if handle < 0 {
            log_fmt2(
                3,
                "[wasm-kernel] module ",
                module_idx as u64,
                ": host_instantiate_module failed",
                0,
            );
            continue;
        }

        // Resolve channel handles for the module's first three port
        // slots (in[0], out[0], ctrl[0] — slot 0 of each direction).
        // Modules with more ports look the rest up internally via
        // `dev_channel_port`.
        //
        // Port direction id 2 = ctrl_input. Modules that declare a
        // `ctrl_input` port (e.g. bank.commands, voip.call) need
        // this; without it the module gets `ctrl_chan = -1` and
        // silently ignores every FMP message on its ctrl port —
        // which is exactly what was breaking the wasm audio_player
        // and image_viewer chains. Same lookup pattern bcm2712 and
        // rp2350 use in `kernel::scheduler::instantiate_one_module`.
        let in_chan = scheduler::get_module_port(module_idx, 0, 0);
        let out_chan = scheduler::get_module_port(module_idx, 1, 0);
        let ctrl_chan = scheduler::get_module_port(module_idx, 2, 0);

        // Diagnostic: log the full port table for each PIC module so
        // wiring issues are visible. Three log lines, one per
        // direction. `i1`/`o1` are the second-port handles modules
        // commonly look up via `dev_channel_port`.
        let in1 = scheduler::get_module_port(module_idx, 0, 1);
        let out1 = scheduler::get_module_port(module_idx, 1, 1);
        log_fmt3(
            2,
            "[wasm-kernel] ports idx=",
            module_idx as u64,
            " in0=",
            in_chan as i64 as u64,
            " in1=",
            in1 as i64 as u64,
        );
        log_fmt3(
            2,
            "[wasm-kernel] ports idx=",
            module_idx as u64,
            " out0=",
            out_chan as i64 as u64,
            " out1=",
            out1 as i64 as u64,
        );
        log_fmt2(
            2,
            "[wasm-kernel] ports idx=",
            module_idx as u64,
            " ctrl0=",
            ctrl_chan as i64 as u64,
        );

        // Read the optional `module_arena_size` export. Modules that
        // need a non-trivial heap export it from their `mod.rs`;
        // modules whose state fits inside the State struct skip it.
        // The export-exists probe stays quiet when the export is
        // absent.
        let arena_size: u32 = {
            let arena_export = b"module_arena_size";
            let exists =
                host_module_export_exists(handle, arena_export.as_ptr(), arena_export.len());
            if exists == 1 {
                let mut arena_ret = [0u8; 4];
                let arena_rc = host_invoke_module(
                    handle,
                    arena_export.as_ptr(),
                    arena_export.len(),
                    core::ptr::null(),
                    0,
                    arena_ret.as_mut_ptr(),
                    arena_ret.len(),
                );
                if arena_rc >= 4 {
                    u32::from_le_bytes(arena_ret)
                } else {
                    0
                }
            } else {
                0
            }
        };

        // Allocate a per-module kernel-side scratch heap. The wasm
        // host shim routes every PIC syscall that crosses linear-memory
        // boundaries (`channel_read`/`channel_write`/`provider_call`)
        // through `kernel_heap_alloc`, which reads `MODULE_HEAPS[idx]`.
        // Without this initialisation the alloc returns null and every
        // such syscall silently fails with -1. Sized at 256 KiB so a
        // single read up to 64 KiB (e.g. media_loader's snapshot poll)
        // fits even after the heap's per-block header + alignment
        // slack, and tolerates a few in-flight syscalls per step.
        const PIC_KERNEL_SCRATCH_BYTES: usize = 256 * 1024;
        match crate::kernel::loader::alloc_state(PIC_KERNEL_SCRATCH_BYTES) {
            Ok(arena_ptr) => {
                crate::kernel::heap::init_module_heap(
                    module_idx,
                    arena_ptr,
                    PIC_KERNEL_SCRATCH_BYTES,
                );
            }
            Err(_) => {
                log_fmt2(
                    3,
                    "[wasm-kernel] module ",
                    module_idx as u64,
                    ": kernel scratch arena alloc failed",
                    0,
                );
            }
        }

        // wasm32 imports are scalar-only, so the per-instance params
        // blob can't ride along on `module_init_wasm` the way it does
        // on Linux / bare metal. Register it here so the module can
        // pull it via `MODULE_INSTANCE_PARAMS` instead. The blob
        // borrows from the `'static` embedded-modules section.
        let params_slice = entry.params();
        // SAFETY: `params_slice` borrows from the 'static embedded-modules
        // section; `set_module_params` records the pointer + length for the
        // module's first init call.
        unsafe {
            scheduler::set_module_params(module_idx, params_slice.as_ptr(), params_slice.len());
        }

        // `module_init_wasm` is the wasm-only entry point each PIC
        // module exports from `modules/sdk/wasm_entry.rs`. It owns
        // state allocation (via the module's bump heap) and calls
        // the module's `module_new` with `&WASM_SYSCALLS`. Args are
        // packed as four i32 LE values: in_chan, out_chan, ctrl_chan,
        // arena_size.
        let init_export = b"module_init_wasm";
        let init_args = [
            (in_chan as u32).to_le_bytes(),
            (out_chan as u32).to_le_bytes(),
            (ctrl_chan as u32).to_le_bytes(),
            arena_size.to_le_bytes(),
        ];
        let mut init_args_packed = [0u8; 16];
        init_args_packed[0..4].copy_from_slice(&init_args[0]);
        init_args_packed[4..8].copy_from_slice(&init_args[1]);
        init_args_packed[8..12].copy_from_slice(&init_args[2]);
        init_args_packed[12..16].copy_from_slice(&init_args[3]);
        let mut init_ret = [0u8; 4];
        let init_rc = host_invoke_module(
            handle,
            init_export.as_ptr(),
            init_export.len(),
            init_args_packed.as_ptr(),
            init_args_packed.len(),
            init_ret.as_mut_ptr(),
            init_ret.len(),
        );
        if init_rc < 0 {
            log_fmt2(
                3,
                "[wasm-kernel] module ",
                module_idx as u64,
                ": module_init_wasm failed",
                init_rc as i64 as u64,
            );
            continue;
        }
        let init_value = if init_rc >= 4 {
            i32::from_le_bytes(init_ret)
        } else {
            0
        };
        if init_value != 0 {
            log_fmt2(
                3,
                "[wasm-kernel] module ",
                module_idx as u64,
                ": module_init_wasm returned non-zero",
                init_value as i64 as u64,
            );
            continue;
        }

        let mut bm = scheduler::BuiltInModule::new("wasm_module", wasm_module_step);
        bm.state[0..4].copy_from_slice(&(handle as i32).to_le_bytes());
        scheduler::store_builtin_module(module_idx, bm);
        registered += 1;
        log_fmt2(
            2,
            "[wasm-kernel] module ",
            module_idx as u64,
            " = wasm-instantiated + initialised",
            0,
        );
    }

    // Return the `prepare_graph` module count, not `registered`.
    // Modules that failed to register (e.g. STATE_ARENA full) are
    // left at their original slot index; the scheduler's
    // `step_modules` tolerates `ModuleSlot::Empty` gracefully via
    // `as_module_mut().is_some()`. Returning `registered` here would
    // shrink `MODULE_COUNT` and silently skip later,
    // successfully-registered modules at the tail.
    if registered < module_count {
        log_fmt2(
            3,
            "[wasm-kernel] partial bring-up: ",
            registered as u64,
            " of N modules registered (slots with failures will be skipped per-tick)",
            module_count as u64,
        );
    }
    module_count
}

/// BuiltInModule step function for a wasm-instantiated module. Reads
/// the host module handle from `state[0..4]` and invokes
/// `host_invoke_module(handle, "module_step_wasm", ...)`. The wasm
/// module manages its own state in its own linear memory — the
/// kernel-side state buffer is just a handle holder. Module's
/// `module_step_wasm` is a no-arg wasm32-only entry point that
/// dispatches into the module's existing `module_step(state_ptr)`
/// using its internal static state buffer.
fn wasm_module_step(state: *mut u8) -> i32 {
    // SAFETY: state is the kernel-provided opaque state pointer; the first
    // 4 bytes hold the host module handle written in load_embedded_modules.
    // `host_invoke_module` is a wasm import; we pass it the handle plus a
    // small local return buffer.
    unsafe {
        let handle = core::ptr::read_unaligned(state as *const i32);
        if handle < 0 {
            return -1;
        }
        let export = b"module_step_wasm";
        let mut ret = [0u8; 4];
        let n = host_invoke_module(
            handle,
            export.as_ptr(),
            export.len(),
            core::ptr::null(),
            0,
            ret.as_mut_ptr(),
            ret.len(),
        );
        if n < 0 {
            return n;
        }
        if n >= 4 {
            i32::from_le_bytes(ret)
        } else {
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

    // Walk the embedded modules blob (rewritten in-place by the
    // bundle tool when building a `<config>.wasm`) and instantiate
    // each entry. Returns zero for a bare `firmware.wasm` (no
    // bundled modules), in which case we fall back to the in-kernel
    // tick demo so the smoke artifact still exercises scheduler
    // dispatch and channel IPC.
    // SAFETY: walks the 'static embedded-modules section. Single-threaded
    // wasm boot; runs once at init.
    let module_count = unsafe { load_embedded_modules() };

    if module_count == 0 {
        log_str(2, b"[wasm-kernel] no bundled modules; running tick demo");
        init_tick_demo();
    } else {
        // SAFETY: MODULE_COUNT mutated once at boot, single-threaded wasm.
        unsafe {
            MODULE_COUNT = module_count;
        }
        log_fmt2(
            2,
            "[wasm-kernel] loaded ",
            module_count as u64,
            " bundled modules",
            0,
        );
        scheduler::log_arena_summary();
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
/// Uses the shared `step_modules` path — the same one RP and Linux
/// call — so topological execution order, every `StepOutcome`
/// variant (including `Burst`'s cap and `Ready` signal propagation),
/// fault transitions, step-period gating, and diagnostics are
/// identical across platforms.
///
#[no_mangle]
pub extern "C" fn kernel_step() -> u32 {
    // SAFETY: MODULE_COUNT and the scheduler globals are accessed from
    // the single-threaded wasm runtime.
    let count = unsafe { MODULE_COUNT };
    // SAFETY: as above.
    let sched = unsafe { scheduler::sched_mut() };
    let _ = scheduler::step_modules(&mut sched.modules, count);
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
/// header. 512 KiB is comfortably larger than the largest module set
/// observed today (a typical browser app graph (~7-10 modules, ~40 KiB); mainline foundation
/// stacks total ~120 KiB). Reproducible: the bundle tool fails fast if
/// the real blob exceeds capacity, with a clear "rebuild kernel with
/// larger placeholder" error.
const MODULES_BLOB_TOTAL: usize = 512 * 1024;
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

// ── tick_source / tick_sink built-ins ────────────────────────────────
//
// State layout for both modules (64-byte BuiltInModule state buffer):
//   bytes 0..4:  i32 channel handle (set by kernel_init before first step)
//   bytes 4..8:  u32 step counter
//   bytes 8..16: u64 first-tick timestamp from host_now_us (LE)

const REPORT_INTERVAL: u32 = 60;

fn tick_source_step(state: *mut u8) -> i32 {
    // SAFETY: state is the BuiltInModule's 64-byte state buffer; we read
    // the channel handle from [0..4] and the tick counter from [4..8].
    unsafe {
        let chan = core::ptr::read_unaligned(state as *const i32);
        let counter_ptr = state.add(4) as *mut u32;
        let mut ticks = core::ptr::read_unaligned(counter_ptr);
        ticks = ticks.wrapping_add(1);
        core::ptr::write_unaligned(counter_ptr, ticks);

        // Emit the tick counter as a 4-byte LE message. The sink reads
        // it back and counts received messages.
        let bytes = ticks.to_le_bytes();
        let _ = channel::channel_write(chan, bytes.as_ptr(), 4);
    }
    0
}

fn tick_sink_step(state: *mut u8) -> i32 {
    // SAFETY: state is the BuiltInModule's 64-byte state buffer; we read
    // the channel handle from [0..4], counter from [4..8], timestamp from [8..16].
    unsafe {
        let chan = core::ptr::read_unaligned(state as *const i32);
        let counter_ptr = state.add(4) as *mut u32;
        let ts_ptr = state.add(8) as *mut u64;

        // Drain any messages currently readable.
        loop {
            let mut buf = [0u8; 4];
            let n = channel::channel_read(chan, buf.as_mut_ptr(), 4);
            if n <= 0 {
                break;
            }

            let mut received = core::ptr::read_unaligned(counter_ptr);
            if received == 0 {
                core::ptr::write_unaligned(ts_ptr, host_now_us());
            }
            received = received.wrapping_add(1);
            core::ptr::write_unaligned(counter_ptr, received);

            if received.is_multiple_of(REPORT_INTERVAL) {
                let first_us = core::ptr::read_unaligned(ts_ptr);
                let now_us = host_now_us();
                let elapsed_ms = ((now_us - first_us) / 1000) as u32;
                let last_payload = u32::from_le_bytes(buf);
                log_fmt3(
                    2,
                    "[wasm_tick_sink] received=",
                    received as u64,
                    " last_payload=",
                    last_payload as u64,
                    " elapsed_ms=",
                    elapsed_ms as u64,
                );
            }
        }
    }
    0
}

// ── Panic handler ────────────────────────────────────────────────────

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    let msg = b"[wasm-kernel] panic";
    // SAFETY: wasm imports; we pass a static byte array and its length.
    unsafe {
        host_log(4, msg.as_ptr(), msg.len());
        host_panic(msg.as_ptr(), msg.len())
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

fn log_str(level: u32, msg: &[u8]) {
    // SAFETY: wasm import; pass the message pointer + length.
    unsafe {
        host_log(level, msg.as_ptr(), msg.len());
    }
}

fn log_fmt2(level: u32, label_a: &str, value_a: u64, label_b: &str, value_b: u64) {
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

fn log_fmt3(
    level: u32,
    label_a: &str,
    value_a: u64,
    label_b: &str,
    value_b: u64,
    label_c: &str,
    value_c: u64,
) {
    let mut buf = [0u8; 192];
    let mut pos = 0usize;
    pos = append_str(&mut buf, pos, label_a.as_bytes());
    pos = append_u64(&mut buf, pos, value_a);
    pos = append_str(&mut buf, pos, label_b.as_bytes());
    pos = append_u64(&mut buf, pos, value_b);
    pos = append_str(&mut buf, pos, label_c.as_bytes());
    pos = append_u64(&mut buf, pos, value_c);
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
    let table = crate::kernel::syscalls::get_syscall_table();
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
    let table = crate::kernel::syscalls::get_syscall_table();
    (table.channel_write)(handle, data, len)
}

#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn channel_poll(handle: i32, events: u32) -> i32 {
    let table = crate::kernel::syscalls::get_syscall_table();
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
    let table = crate::kernel::syscalls::get_syscall_table();
    (table.channel_peek)(handle, buf, len)
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
    let table = crate::kernel::syscalls::get_syscall_table();
    (table.heap_alloc)(size)
}

#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn heap_free(ptr: *mut u8) {
    let table = crate::kernel::syscalls::get_syscall_table();
    (table.heap_free)(ptr)
}

#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn heap_realloc(ptr: *mut u8, new_size: u32) -> *mut u8 {
    let table = crate::kernel::syscalls::get_syscall_table();
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
    let table = crate::kernel::syscalls::get_syscall_table();
    (table.provider_open)(contract, open_op, config, config_len)
}

#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn provider_call(handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    let table = crate::kernel::syscalls::get_syscall_table();
    (table.provider_call)(handle, op, arg, arg_len)
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
    let table = crate::kernel::syscalls::get_syscall_table();
    (table.provider_query)(handle, key, out, out_len)
}

#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn provider_close(handle: i32) -> i32 {
    let table = crate::kernel::syscalls::get_syscall_table();
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
    let table = crate::kernel::syscalls::get_syscall_table();
    (table.heap_alloc)(size)
}

#[allow(
    clippy::missing_safety_doc,
    reason = "low-level platform shim; safety contract documented at call site"
)]
#[no_mangle]
pub unsafe extern "C" fn kernel_heap_free(ptr: *mut u8) {
    let table = crate::kernel::syscalls::get_syscall_table();
    (table.heap_free)(ptr)
}
