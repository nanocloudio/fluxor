// Platform: Linux hosted — runs Fluxor as an aarch64 Linux userspace process.
//
// Loads real PIC .fmod modules via mmap and runs the same scheduler/graph
// model as the embedded targets. Single-domain: one thread, cooperative
// step loop with std::thread::sleep for tick timing.
//
// Usage:
//   fluxor-linux --image node.img

#![allow(
    unsafe_code,
    reason = "host kernel binary: mmap of PIC .fmod modules and raw syscall plumbing for FD passing"
)]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "host-linux kernel binary logs to stdout/stderr as user-visible process output"
)]

use std::env;
use std::fs;
use std::os::unix::io::AsRawFd;
use std::process;
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use fluxor::kernel::exec::scheduler;
use fluxor::kernel::exec::step_guard;
use fluxor::kernel::ipc::channel;
use fluxor::kernel::module::loader;
use fluxor::kernel::sys::hal::HalOps;

include!("linux/runtime.rs");

// ============================================================================
// CLI argument parsing
// ============================================================================

struct CliArgs {
    image_path: String,
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = env::args().collect();
    let mut image_path = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--image" | "-i" => {
                i += 1;
                if i < args.len() {
                    image_path = args[i].clone();
                } else {
                    eprintln!("error: --image requires a path");
                    process::exit(1);
                }
            }
            "--help" | "-h" => {
                eprintln!("Usage: fluxor-linux --image <node.img>");
                eprintln!();
                eprintln!("Options:");
                eprintln!(
                    "  -i, --image <path>    The node image `fluxor build` writes (node.img)"
                );
                eprintln!("      --print-features  Print compiled-in host-* features and exit");
                eprintln!("  -h, --help            Show this help");
                process::exit(0);
            }
            "--print-features" => {
                // Newline-separated inventory of the optional backends
                // this binary carries. `fluxor build` parses it to
                // reject a config asking for one that is absent, e.g.
                // `linux_display.mode = "window"` without
                // `--features host-window`. The list is the whole
                // inventory, not only the YAML-selectable part: a
                // backend chosen by environment rather than by config
                // is otherwise indistinguishable, from outside, from a
                // backend that was never compiled in.
                #[cfg(feature = "host-window")]
                println!("host-window");
                #[cfg(feature = "host-playback")]
                println!("host-playback");
                #[cfg(feature = "host-image")]
                println!("host-image");
                process::exit(0);
            }
            // Everything after `--` is the app's argv — cli_in reads it
            // from env::args() itself.
            "--" => break,
            other => {
                eprintln!("error: unknown argument: {other}");
                process::exit(1);
            }
        }
        i += 1;
    }

    if image_path.is_empty() {
        eprintln!("error: --image is required");
        eprintln!("Usage: fluxor-linux --image <node.img>");
        process::exit(1);
    }

    CliArgs { image_path }
}

// The platform providers (FS/proc/net registry) and the owner facts writer
// compile into the fluxor library at
// `fluxor::platform::linux::{providers, owner_facts}` so the host
// test harness can exercise them directly. Bring the binary-facing entry points
// into scope so the flat registration (`runtime.rs`) and boot/watch sites
// (`linux.rs` body) resolve them by name.
use fluxor::platform::linux::host_lane::HOST_LANE;
use fluxor::platform::linux::owner_facts::OwnerFactsWriter;
use fluxor::platform::linux::providers::linux_fs_dispatch;
// The `workload` provider (class `workload`) and its host-process backend (the
// `host_backend` namespace/cgroup mechanism) compile into the fluxor library at
// `fluxor::platform::linux::{workload, host_backend}` so the host test harness can
// exercise them directly. Bring the binary-facing entry points into scope so
// the flat provider-registration (`runtime.rs`) site resolves them by name.
use fluxor::platform::linux::workload::linux_workload_dispatch;
// TLV param walkers + per-instance state helpers, in the library so the
// library provider modules can reach them; glob-imported so the flat
// native modules here resolve them by bare name.
use fluxor::kernel::exec::scheduler::NativeVtable;
use fluxor::platform::linux::native_params::*;
include!("linux/cli_io.rs");
include!("linux/stop.rs");
include!("linux/host_asset_source.rs");
include!("linux/host_asset_index.rs");
include!("linux/linux_gpu.rs");
include!("linux/linux_display.rs");
include!("linux/linux_audio.rs");
include!("linux/host_image_codec.rs");
include!("linux/linux_alsa_midi.rs");
include!("linux/linux_surface_traits_scan.rs");
include!("linux/linux_surface_traits.rs");
include!("linux/linux_surface_traits_probe.rs");
include!("linux/linux_pointer.rs");
include!("linux/linux_eth.rs");
include!("linux/owner_log_tee.rs");

/// Runtime parameter overrides, file-backed. Its own module so its parse and
/// merge can be unit-tested without a graph.
pub mod param_store {
    use fluxor_contracts::params_tlv;
    include!("linux/param_store.rs");
}

/// The `trust` contract's Linux provider: the system store, with the
/// platform's policy applied rather than reported.
///
/// On Linux there is no OS verification API to call. `rustls-platform-verifier`
/// — the shape this contract was designed around — falls back to webpki over
/// the system roots on this platform for exactly that reason, so what happens
/// here IS the platform path and not a stand-in for one. macOS and Windows
/// have real OS calls; when those targets exist, their providers call them and
/// this file stays as it is.
///
/// What this applies that `tls`'s own verifier does not: path building through
/// intermediates it may reorder or ignore, name constraints on the issuing
/// chain, EKU for the purpose, and the full public root set as the platform
/// maintains it. What it does NOT apply is revocation — and it says so, by
/// leaving `check::REVOCATION` clear, which is the field's whole reason for
/// existing.
///
/// Its own module rather than an inlined include: it pulls a verifier's worth
/// of names into scope and none of them belong to the rest of the platform.
#[cfg(feature = "trust-system")]
pub mod trust_provider {
    include!("linux/trust.rs");
}

// ============================================================================
// Graph construction (shared by boot and live rebuild)
// ============================================================================

use fluxor::abi::platform::native::linux as native;

/// The Linux platform's native modules, registered once at boot before the
/// first graph is prepared: a graph names each by its name hash, and the
/// splice resolves it here when the loader does not.
static NATIVE_MODULES: &[(u32, &scheduler::NativeVtable)] = &[
    (native::cli_in::NAME_HASH, &CLI_IN),
    (native::cli_out::NAME_HASH, &CLI_OUT),
    (native::host_asset_source::NAME_HASH, &HOST_ASSET_SOURCE),
    (native::host_asset_index::NAME_HASH, &HOST_ASSET_INDEX),
    (native::linux_gpu::NAME_HASH, &LINUX_GPU),
    (native::linux_display::NAME_HASH, &LINUX_DISPLAY),
    (native::linux_audio::NAME_HASH, &LINUX_AUDIO),
    #[cfg(feature = "host-image")]
    (native::host_image_codec::NAME_HASH, &HOST_IMAGE_CODEC),
    (native::linux_alsa_midi::NAME_HASH, &LINUX_ALSA_MIDI),
    (
        native::linux_surface_traits::NAME_HASH,
        &LINUX_SURFACE_TRAITS,
    ),
    (
        native::linux_surface_traits_probe::NAME_HASH,
        &LINUX_SURFACE_TRAITS_PROBE,
    ),
    (native::linux_pointer::NAME_HASH, &LINUX_POINTER),
    (native::linux_eth::NAME_HASH, &LINUX_ETH),
    (native::host_lane::NAME_HASH, &HOST_LANE),
];

/// Prepare and instantiate the installed `STATIC_CONFIG`: the splice stages
/// it, the owner plan is applied, every module instantiates (a load that
/// completes later is polled within the shared budget, the thread yielding
/// between polls) and the graph is published. Shared by first boot and the
/// live-rebuild path. The module count; a graph the node refuses ends the
/// process, naming why.
fn build_graph_linux() -> usize {
    let staged = match scheduler::prepare_graph() {
        Ok(st) => st,
        Err(rc) => {
            eprintln!("error: graph refused at preparation (rc={rc})");
            process::exit(1);
        }
    };

    // Ownership must be live before any module runs: `module_new` opens
    // provider handles under the module's owner at open time, and the
    // preparation reset every module to the node owner. Also re-applies
    // the retained plan on a rebuild (an ordinary rebuild must not drop
    // isolation). Fail closed: a staged-but-invalid plan refuses the graph
    // rather than running it node-owned.
    if let Err(e) = fluxor::kernel::workload::owner_plan::apply_staged() {
        eprintln!("error: staged owner plan invalid ({e:?}); refusing to run the graph with ownership isolation disabled");
        process::exit(1);
    }

    let count = match scheduler::instantiate_graph(staged, &mut thread::yield_now, &mut |_| {}) {
        Ok(n) => n,
        Err(rc) => {
            eprintln!("error: graph refused at instantiation (rc={rc}); the log names the module");
            restore_terminal();
            process::exit(1);
        }
    };
    log::info!("[inst] {count} modules");
    scheduler::log_arena_usage();
    count
}

// ============================================================================
// Entry point
// ============================================================================

/// Modification time of the published plan file, if it exists.
fn plan_mtime(path: &str) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// The plan buffers the kernel may still read: the staged plan, and the
/// applied plan it retains (a view over the bytes staged for it).
static mut PLAN_BUFFERS: Vec<Box<[u8]>> = Vec::new();

/// Read + stage the plan blob at `path`. The staged-plan contract keeps the
/// bytes valid until the plan is applied, and the applied plan is retained
/// over the bytes it was staged from; every other buffer is freed here, so
/// at most two are held.
fn stage_plan_from(path: &str) {
    match std::fs::read(path) {
        Ok(bytes) => {
            log::info!("[owner] staging plan from {path} ({} bytes)", bytes.len());
            let bytes = bytes.into_boxed_slice();
            // SAFETY: the main thread alone stages plans; the kernel reads
            // the staged bytes on this thread too.
            unsafe {
                fluxor::kernel::workload::owner_plan::set_staged_plan(bytes.as_ptr(), bytes.len());
                let retained = fluxor::kernel::workload::owner_plan::retained_plan_bytes();
                let buffers = &mut *core::ptr::addr_of_mut!(PLAN_BUFFERS);
                buffers.retain(|b| Some(b.as_ptr()) == retained);
                buffers.push(bytes);
            }
        }
        Err(e) => log::error!("[owner] plan reload from {path} failed: {e}"),
    }
}

/// Refuse to start below the `aarch64` module ABI floor (ARMv8.0-A with
/// AES, SHA2 and NEON): every module this runtime loads is compiled for it,
/// and so is the runtime itself, so a CPU without them would fault later on
/// an instruction it does not have. Named here, once, instead.
#[cfg(target_arch = "aarch64")]
fn check_abi_floor() {
    // SAFETY: getauxval reads the process's auxiliary vector; no memory is
    // passed in.
    let hwcap = unsafe { libc::getauxval(libc::AT_HWCAP) };
    let missing: Vec<&str> = [
        (libc::HWCAP_ASIMD, "NEON"),
        (libc::HWCAP_AES, "AES"),
        (libc::HWCAP_SHA2, "SHA2"),
    ]
    .into_iter()
    .filter(|(bit, _)| hwcap & bit == 0)
    .map(|(_, name)| name)
    .collect();
    if !missing.is_empty() {
        eprintln!(
            "error: this CPU lacks {} — the aarch64 module ABI needs ARMv8.0-A with AES, SHA2 \
             and NEON",
            missing.join(", ")
        );
        process::exit(1);
    }
}

fn main() {
    #[cfg(target_arch = "aarch64")]
    check_abi_floor();

    // Initialize boot instant for monotonic clock
    // SAFETY: main runs before any other thread; first write to BOOT_INSTANT
    // happens-before any reader observes it.
    unsafe {
        BOOT_INSTANT = Some(Instant::now());
    }

    // Set up logging via the owner-log tee: identical env_logger stderr
    // formatting/filtering, plus per-owner ring routing for `fluxor agent
    // logs`. Registers this (main) thread as the scheduler thread — the only
    // thread whose records reach the rings.
    install_owner_log_tee();
    register_scheduler_thread();

    log::info!("[fluxor] linux platform boot");

    let args = parse_args();

    // The node image is mapped whole, PROT_READ | PROT_EXEC: the module
    // table holds PIC code, which a heap copy could not run. The mapping is
    // never unmapped, so the config the kernel parses borrows its module
    // params from it in place for the life of the process, as on every
    // platform. The file's length bounds the image.
    let image_file = fs::File::open(&args.image_path).unwrap_or_else(|e| {
        eprintln!("error: failed to open image {}: {}", args.image_path, e);
        process::exit(1);
    });
    let image_len = image_file.metadata().map(|m| m.len()).unwrap_or(0) as usize;
    if image_len == 0 {
        eprintln!("error: image {} is empty", args.image_path);
        process::exit(1);
    }
    // SAFETY: `mmap` with a valid fd, a non-zero length and PRIVATE|EXEC
    // flags: the kernel returns a valid mapping or MAP_FAILED (checked below).
    let image_ptr = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            image_len,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE,
            image_file.as_raw_fd(),
            0,
        )
    };
    if image_ptr == libc::MAP_FAILED {
        eprintln!("error: failed to mmap image {}", args.image_path);
        process::exit(1);
    }
    // SAFETY: the mapping above covers `image_len` bytes and is never
    // unmapped.
    let image: &'static [u8] =
        unsafe { core::slice::from_raw_parts(image_ptr as *const u8, image_len) };

    // HAL ops, syscall table, providers, then the step guard and the
    // platform's native modules.
    fluxor::kernel::boot(&LINUX_HAL_OPS);
    step_guard::init();
    scheduler::native::register_all(NATIVE_MODULES);

    // Admit the image as every target admits its graph (shape, ABI pin,
    // and, under the runtime's signing root, signature and payload digest), then
    // populate the kernel's static config + loader from its regions and
    // build the graph.
    let own_pin = fluxor::kernel::boot::node_image::own_abi_pin();
    let header = fluxor::kernel::boot::node_image::admit(image, &own_pin).unwrap_or_else(|why| {
        eprintln!(
            "error: node image {} refused: {}",
            args.image_path,
            why.reason()
        );
        process::exit(1);
    });
    log::info!(
        "[image] {} bytes from {} at {:p}: modules {} B, config {} B",
        image_len,
        args.image_path,
        image_ptr,
        header.modules_size,
        header.config_size
    );
    loader::reset_state_arena();
    let modules = header.modules(image);
    // SAFETY: both regions lie in the image mapping, which stays mapped for
    // the life of the process; `populate_static_state_with_len` bounds the
    // config by its slice and the module table by `modules.len()`.
    if let Err(msg) = unsafe {
        scheduler::populate_static_state_with_len(
            header.config(image),
            modules.as_ptr(),
            modules.len(),
        )
    } {
        eprintln!("error: {msg}");
        process::exit(1);
    }

    // SAFETY: `static_config()` returns a reference into the static config
    // arena populated by `populate_static_state_with_len` above.
    let cfg_header_tick_us = unsafe { scheduler::static_config().header.tick_us as u32 };
    let tick_us = if cfg_header_tick_us > 0 {
        cfg_header_tick_us
    } else {
        1000
    };
    log::info!("[loader] module table loaded, tick_us={tick_us}");

    // Stage an owner plan from FLUXOR_PLAN=<file> (the node agent's delivery
    // path). Re-staged on SIGHUP: the agent recommits + republishes the plan,
    // then signals us to pick up the new generation via a live rebuild.
    let plan_path = std::env::var("FLUXOR_PLAN").ok();
    let mut last_plan_mtime = None;
    let mut last_plan_check = Instant::now();
    if let Some(path) = plan_path.as_deref() {
        stage_plan_from(path);
        last_plan_mtime = plan_mtime(path);
    }
    // Node-agent mode also writes the kernel's owner facts next to the plan
    // it consumes (`owner_facts::FILE_NAME`, atomic replace) for the node
    // agent to render. Absent FLUXOR_PLAN ⇒ none written.
    let mut owner_facts = plan_path
        .as_deref()
        .map(|p| OwnerFactsWriter::new(std::path::Path::new(p)));
    // Per-owner log rings are flushed into `logs/` beside the plan, on the
    // same tick. `fluxor agent logs` resolves this directory the same way.
    let logs_dir: Option<std::path::PathBuf> = plan_path.as_deref().map(|p| {
        std::path::Path::new(p)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("logs")
    });

    // Compile + instantiate the graph (shared with the live-rebuild path).
    build_graph_linux();

    // Admit resident workloads declared in the config's `WKLD` section
    // (`workloads:` / `combine <two-graph.yaml>`) as workload owners via
    // the splice, then the domain loop multiplexes them with the node
    // graph. Boot-only (not re-run on live rebuild). No-op without workloads.
    scheduler::admit_resident_workloads_from_config();

    // Publish the initial owner facts immediately (before the first 100 ms
    // watch window) so an orchestrator polling right after activation sees
    // the runtime up rather than a stale/absent file.
    if let Some(w) = owner_facts.as_mut() {
        w.tick();
    }
    if let Some(dir) = logs_dir.as_deref() {
        flush_owner_rings(dir);
    }

    // Scheduler + HAL are up: log records may now resolve their owning module.
    enable_owner_log_attribution();

    log::info!("[sched] starting domain loop, tick_us={tick_us}");
    // The per-iteration deadline is the pass engine's (`pass::tick_all`);
    // with no adaptive flag set it is the nominal tick.
    let mut tick: u64 = 0;
    let mut stop: Option<StopDrain> = None;
    install_stop_signals();
    // FLUXOR_FORCED_PASSES=K makes the scheduler run at least K exec-order
    // passes per tick (clamped to MAX_PIPELINE_PASSES), so a reply path that
    // flows against exec order can complete within a tick without any module
    // returning Burst. Unset means 1: one pass per idle tick, the same as a
    // build without the variable. See `scheduler::FORCED_PIPELINE_PASSES`.
    if let Some(k) = std::env::var("FLUXOR_FORCED_PASSES")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
    {
        fluxor::kernel::exec::scheduler::set_forced_pipeline_passes(k);
        eprintln!("[fluxor-linux] forced pipeline passes = {k}");
    }
    // Throttle oversleep warnings to once every ~1 s of expected
    // wall-clock so a chronic oversleep doesn't flood the log.
    let mut last_oversleep_log_tick: u64 = 0;
    let oversleep_log_period_ticks: u64 = if tick_us > 0 {
        (1_000_000 / tick_us as u64).max(1)
    } else {
        u64::MAX
    };

    // Capture the runtime thread so `linux_wake_scheduler` (called via
    // `hal::wake_scheduler` from `event_signal` / `event_signal_from_isr`)
    // can `unpark()` us out of `park_timeout` between ticks. Same shape as
    // RP's wake latch: the producer records the wake and then pokes the
    // consumer, and the consumer re-checks rather than trusting the poke.
    linux_install_wake_thread();

    loop {
        let t0 = Instant::now();

        // A stop signal drains the graph, then exits; see `linux/stop.rs`.
        if stop.is_none() && stop_requested() {
            stop = Some(StopDrain::begin());
        }
        if stop.as_ref().is_some_and(StopDrain::over) {
            finish_stop(owner_facts.as_mut(), logs_dir.as_deref());
        }

        // Node-agent generation update: the agent recommits + republishes the
        // plan file; a changed mtime re-stages it and live-rebuilds ownership.
        // Time-gated to one stat() per ~100 ms regardless of tick rate (a
        // busy-loop tick would otherwise stat every spin; an idle 100
        // ms-per-iteration loop would otherwise check too rarely).
        if plan_path.is_some() && last_plan_check.elapsed() >= Duration::from_millis(100) {
            last_plan_check = Instant::now();
            // Settle drains BEFORE consuming a new plan: a drain that already
            // reached quiescence or its deadline frees its owner and records
            // the outcome first, so the plan update never races a finished
            // drain. A still-live drain is protected on the other side: the
            // delta path refuses a plan that drops a retained revocation while
            // its owner is installed. The kernel arbitrates; this clock is the
            // platform's.
            fluxor::kernel::workload::owner_plan::drain_tick(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            );
            if let Some(path) = plan_path.as_deref() {
                let mtime = plan_mtime(path);
                if mtime.is_some() && mtime != last_plan_mtime {
                    last_plan_mtime = mtime;
                    log::info!("[owner] plan file changed; reloading from {path}");
                    stage_plan_from(path);
                    // A pure-drain generation (records moved from the
                    // assignment section to the revocation section, nothing
                    // else) applies as a live delta: the departing owner flips
                    // to Draining and `drain_tick` frees it — no rebuild,
                    // co-resident owners untouched. Anything structural falls
                    // through to the rebuild.
                    if fluxor::kernel::workload::owner_plan::try_apply_drain_delta().is_none() {
                        // Structural plan: not a pure-drain delta, but it may
                        // still revoke owners. They stop admitting before the
                        // rebuild, whose apply records each forfeited.
                        fluxor::kernel::workload::owner_plan::begin_staged_revocation_drains();
                        scheduler::request_rebuild();
                    }
                }
            }
            // Same cadence as the plan watch: publish the owner facts (no-op
            // write when they are unchanged) and flush the per-owner log
            // rings to their files.
            if let Some(w) = owner_facts.as_mut() {
                w.tick();
            }
            if let Some(dir) = logs_dir.as_deref() {
                flush_owner_rings(dir);
            }
        }

        // Live rebuild. The reconfigure module triggers
        // `TRIGGER_REBUILD` -> `request_rebuild`; consume it here and rebuild
        // the graph from STATIC_CONFIG. Single-threaded, so no quiesce is
        // needed (unlike bcm2712). `prepare_graph` does the destructive reset
        // and is fail-safe on error.
        if scheduler::take_rebuild_request() {
            log::info!("[reconfigure] rebuild requested; rebuilding graph");
            let count = build_graph_linux();
            scheduler::set_reconfigure_phase(scheduler::ReconfigurePhase::Running);
            log::info!("[reconfigure] rebuilt graph: {count} modules");
            // Publish the rebuilt owners' facts now, before their modules
            // step: a reader sees the re-activation even when an owner
            // faults again within the 100 ms cadence.
            if let Some(w) = owner_facts.as_mut() {
                w.tick();
            }
            if let Some(dir) = logs_dir.as_deref() {
                flush_owner_rings(dir);
            }
            continue;
        }

        // The one pass engine, every domain in order (`pass::tick_all`): each
        // resident graph stepped independently, idle ones skipped, and the
        // merged sleep deadline returned.
        let pass = scheduler::pass::tick_all();
        let (result, sleep_us) = (pass.result, pass.deadline_us);

        // A plain run ends when every module is done, or when the CLI sink
        // has retired with its output flushed. The second is what lets an
        // applet wire a platform provider: a provider serves on request and
        // never declares itself finished, so waiting for one is waiting for
        // ever. Node-agent mode owns its own lifetime and is excluded below.
        let cli_done = CLI_RUN_COMPLETE.load(Ordering::Acquire);
        let all_done = matches!(result, fluxor::kernel::exec::scheduler::StepResult::Done);
        if stop.is_some() && all_done {
            // Stopping, and nothing is left to drain.
            log::info!("[stop] drained; exiting");
            finish_stop(owner_facts.as_mut(), logs_dir.as_deref());
        }
        if cli_done || all_done {
            // Node-agent mode (FLUXOR_PLAN set): the runtime is the node's
            // persistent substrate — workloads come and go via plan reloads, so an
            // all-done/empty graph idles awaiting SIGHUP instead of exiting.
            if plan_path.is_some() {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            // Plain-run/exec completion: report the CLI exit-code latch
            // (default 0 — non-CLI graphs are unchanged). Node-agent mode
            // never reaches here.
            let code = CLI_EXIT_CODE.load(Ordering::Acquire);
            log::info!("[sched] all modules complete, exiting (code {code})");
            // Restore the terminal if an interactive applet put it in raw mode.
            restore_terminal();
            process::exit(code);
        }

        // Wakes latched during the pass (modules signalling their own
        // events) are stepped now, each domain's from its own mask, rather
        // than waiting out the next tick.
        scheduler::pass::wake_all();

        tick += 1;

        scheduler::maybe_emit_alive(tick, None);

        // Tick pacing, against the pacer-chosen `sleep_us` (below).
        // `thread::sleep` for sub-millisecond targets has a ~50-150 µs floor
        // on Linux (timer-tick granularity + scheduler wake latency), so for
        // hot cadences we busy-spin instead and only fall back to sleep at
        // coarse settings:
        //
        //   * sleep_us == 0   → pure busy-loop, no pacing.
        //   * sleep_us <= 200 → spin until `sleep_duration` elapses,
        //                       yielding early if a wake bit fires.
        //   * sleep_us > 200  → `park_timeout` for the remainder; an
        //                       `unpark` from `linux_wake_scheduler`
        //                       returns immediately so the next
        //                       iteration's drain runs the woken module.
        // `sleep_us` was chosen above by the pass engine. With no
        // adaptive flag set it returns the domain's nominal tick, so `sleep_us == tick_us`
        // every iteration and the bands below are byte-identical to the
        // fixed-tick loop. With mechanism (a) enabled and an idle pass it returns
        // `tick_max_us`; `park_timeout` stays interruptible by `unpark` from
        // `linux_wake_scheduler`, so a wake returns immediately.
        let sleep_duration = Duration::from_micros(sleep_us as u64);
        let elapsed = t0.elapsed();
        if sleep_us == 0 {
            // Pure busy-loop — recheck immediately.
        } else if sleep_us <= 200 {
            while t0.elapsed() < sleep_duration {
                // Yield early on wake so woken modules don't wait out
                // the remainder of the spin budget. The bit stays
                // latched in EVENT_WAKE_PENDING for the next iteration.
                if fluxor::kernel::ipc::event::wake_pending_nonzero() {
                    break;
                }
                core::hint::spin_loop();
            }
        } else if elapsed < sleep_duration {
            // `park_timeout` is interruptible by `unpark()` and may
            // return spuriously; either way the next iteration drains
            // wake bits and steps. The remaining budget is the upper
            // bound, never a hard sleep. Under mechanism (a) idle this is
            // the `tick_max_us` backstop — a wake cuts it short.
            thread::park_timeout(sleep_duration - elapsed);
        }

        // Second drain after the wait: an event signalled during the park
        // (or between the first drain and the spin) is stepped before the
        // next tick.
        scheduler::pass::wake_all();

        // Detect chronic host oversleep. `thread::park_timeout`
        // contracts with the OS scheduler; under `CONFIG_HZ=100` or
        // load, the wake-up may overshoot by milliseconds. A 1.5×
        // threshold ignores small-jitter overshoot and only fires on
        // sustained drift, throttled once per ~second of expected
        // wall-clock. Operators reading this in the log can correlate
        // to RT-priority or CFS-bandwidth misconfiguration.
        // Threshold tracks the ACTUAL chosen deadline (`sleep_duration`), not
        // the nominal tick — otherwise mechanism (a)'s idle `tick_max_us`
        // sleeps would trip this every idle pass. A real oversleep is the OS
        // overshooting the deadline it was given.
        if sleep_us > 200 {
            let actual = t0.elapsed();
            let threshold = sleep_duration + sleep_duration / 2;
            if actual > threshold && tick - last_oversleep_log_tick >= oversleep_log_period_ticks {
                log::warn!(
                    "MON_HOST_OVERSLEEP tick={} requested_us={} actual_us={} threshold_us={}",
                    tick,
                    sleep_us,
                    actual.as_micros() as u64,
                    threshold.as_micros() as u64,
                );
                last_oversleep_log_tick = tick;
            }
        }
    }
}
