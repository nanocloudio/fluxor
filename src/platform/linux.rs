// Platform: Linux hosted — runs Fluxor as an aarch64 Linux userspace process.
//
// Loads real PIC .fmod modules via mmap and runs the same scheduler/graph
// model as the embedded targets. Single-domain (v1): one thread, cooperative
// step loop with std::thread::sleep for tick timing.
//
// Usage:
//   fluxor-linux --config config.bin --modules modules.bin
//   fluxor-linux config.yaml                  # (future: auto-generate bins)

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

use fluxor::kernel::channel;
use fluxor::kernel::hal::HalOps;
use fluxor::kernel::loader;
use fluxor::kernel::scheduler;
use fluxor::kernel::step_guard;

include!("linux/runtime.rs");

// ============================================================================
// CLI argument parsing
// ============================================================================

struct CliArgs {
    config_path: String,
    modules_path: String,
}

fn parse_args() -> CliArgs {
    let args: Vec<String> = env::args().collect();
    let mut config_path = String::new();
    let mut modules_path = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                i += 1;
                if i < args.len() {
                    config_path = args[i].clone();
                } else {
                    eprintln!("error: --config requires a path");
                    process::exit(1);
                }
            }
            "--modules" | "-m" => {
                i += 1;
                if i < args.len() {
                    modules_path = args[i].clone();
                } else {
                    eprintln!("error: --modules requires a path");
                    process::exit(1);
                }
            }
            "--help" | "-h" => {
                eprintln!("Usage: fluxor-linux --config <config.bin> --modules <modules.bin>");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  -c, --config <path>   Path to config.bin");
                eprintln!("  -m, --modules <path>  Path to modules.bin");
                eprintln!("      --print-features  Print compiled-in host-* features and exit");
                eprintln!("  -h, --help            Show this help");
                process::exit(0);
            }
            "--print-features" => {
                // Newline-separated feature list. The tool's `fluxor
                // run` (config.rs::validate_runtime_features) parses
                // this to reject configs that need a feature absent
                // from the binary, e.g. `linux_display.mode = "window"`
                // without `--features host-window`.
                #[cfg(feature = "host-window")]
                println!("host-window");
                #[cfg(feature = "host-playback")]
                println!("host-playback");
                #[cfg(feature = "host-image")]
                println!("host-image");
                process::exit(0);
            }
            // Everything after `--` is the app's argv — cli_in reads it
            // from env::args() itself (rfc_cli_execution.md §4.1).
            "--" => break,
            other => {
                eprintln!("error: unknown argument: {other}");
                process::exit(1);
            }
        }
        i += 1;
    }

    if config_path.is_empty() || modules_path.is_empty() {
        eprintln!("error: --config and --modules are required");
        eprintln!("Usage: fluxor-linux --config <config.bin> --modules <modules.bin>");
        process::exit(1);
    }

    CliArgs {
        config_path,
        modules_path,
    }
}

// The platform providers (FS/proc/net registry), the per-owner status writer,
// and the owner-drain driver compile into the fluxor library at
// `fluxor::platform::linux::{providers, owner_status, owner_drain}` so the host
// test harness can exercise them directly. Bring the binary-facing entry points
// into scope so the flat registration (`runtime.rs`) and boot/watch sites
// (`linux.rs` body) resolve them by name.
use fluxor::platform::linux::owner_drain::{arm_drains, drain_tick, synthesize_restart_terminals};
use fluxor::platform::linux::owner_status::OwnerStatusWriter;
use fluxor::platform::linux::providers::{
    linux_fs_dispatch, linux_net_close_all_and_clear_registry, linux_net_register_state,
    linux_net_step, linux_proc_dispatch, LinuxNetState, LINUX_NET_HASH, LINUX_NET_MAX_INBOUND,
};
include!("linux/object.rs");
include!("linux/namespace.rs");
// The `workload` provider (class 0x1A) and its host-process backend (the oci
// namespace/cgroup mechanism) compile into the fluxor library at
// `fluxor::platform::linux::{workload, oci}` so the host test harness can
// exercise them directly. Bring the binary-facing entry points into scope so
// the flat provider-registration (`runtime.rs`) and owner-drain
// (`owner_drain.rs`) sites resolve them by name. See
// `.context/fluxor_nanocloud.md`.
use fluxor::platform::linux::workload::linux_workload_dispatch;
// TLV param walkers + per-instance state helpers, in the library so the
// library provider modules can reach them; glob-imported so the flat
// built-in modules here resolve them by bare name.
use fluxor::platform::linux::builtin_params::*;
include!("linux/cli_io.rs");
include!("linux/host_asset_source.rs");
include!("linux/host_asset_index.rs");
include!("linux/linux_display.rs");
include!("linux/linux_audio.rs");
include!("linux/host_image_codec.rs");
include!("linux/linux_alsa_midi.rs");
include!("linux/linux_surface_traits_scan.rs");
include!("linux/linux_surface_traits.rs");
include!("linux/linux_surface_traits_probe.rs");
include!("linux/linux_pointer.rs");
include!("linux/owner_log_tee.rs");

// ============================================================================
// Graph construction (shared by boot and live rebuild)
// ============================================================================

/// Compile the installed `STATIC_CONFIG` and instantiate every module, including
/// the hosted built-ins (`linux_net`, asset/display/audio/etc.). Returns
/// `(compiled_count, loaded_count)`. Shared by first boot and the live-rebuild
/// path in the main loop; both call `prepare_graph()` (which does the
/// destructive arena/scheduler reset) then this.
fn build_graph_linux() -> (usize, usize) {
    // Close the previous graph's linux_net fds BEFORE the destructive reset
    // drops their state: a leaked listener fd would keep its port bound and
    // every re-issued CMD_BIND after the rebuild would die on EADDRINUSE.
    // The endpoint report shows a bounded transient bound:false across the
    // rebuild window (rfc_endpoint_lease.md §4.5); pure-drain removals never
    // rebuild, so co-residents' reports don't flap on ordinary deletes.
    linux_net_close_all_and_clear_registry();

    // linux_net drains one inbound lane per wired edge (priority by
    // wiring order) — tell graph prep not to merge its fan-in.
    scheduler::register_multi_inbound(LINUX_NET_HASH);
    let (module_list, module_count) = match scheduler::prepare_graph() {
        Ok(v) => v,
        Err(rc) => {
            eprintln!("error: prepare_graph failed (rc={rc})");
            process::exit(1);
        }
    };
    log::info!("[graph] compiled: {module_count} modules");

    // Establish plan ownership BEFORE instantiation: prepare_graph above reset
    // every module to the system owner, and module_new (in the loop below) opens
    // provider handles that are recorded under the module's owner at open time —
    // so ownership must be live first, or those handles are permanently
    // system-owned and bypass tenant isolation. Also re-applies the retained
    // plan on a rebuild (an ordinary rebuild must not drop isolation). Fail
    // closed: a staged-but-invalid plan rejects the graph rather than running it
    // system-owned (which would disable ownership isolation).
    if let Err(e) = fluxor::kernel::owner_plan::apply_staged() {
        eprintln!("error: staged owner plan invalid ({e:?}); refusing to run the graph with ownership isolation disabled");
        process::exit(1);
    }

    // SAFETY: `static_loader` returns a reference into the static loader arena.
    let loader_ref = unsafe { scheduler::static_loader() };
    // SAFETY: single-threaded; `sched_mut` exposes scheduler state during
    // instantiation, before/between worker stepping.
    let sched = unsafe { scheduler::sched_mut() };
    let mut loaded_count = 0usize;

    for (module_idx, entry) in module_list.iter().enumerate().take(module_count) {
        let entry = match entry {
            Some(e) => e,
            None => continue,
        };

        if entry.name_hash == LINUX_NET_HASH {
            scheduler::set_current_module(module_idx);
            // Collect EVERY inbound command channel (priority lanes:
            // one per `to: linux_net.net_in` edge, in wiring order), and
            // resolve each lane's COMMANDING owner from its producing edge —
            // the carried-attribution source for endpoint-lease stamps
            // (rfc_endpoint_lease.md §4.1). Owner stamps are live here: the
            // plan applied before instantiation (see apply_staged above).
            let mut net_ins = [-1i32; LINUX_NET_MAX_INBOUND];
            let mut lane_owners = [fluxor::kernel::owner::OWNER_SYSTEM; LINUX_NET_MAX_INBOUND];
            let mut lane_count = 0usize;
            for (k, slot) in net_ins.iter_mut().enumerate() {
                let ch = scheduler::get_module_port(module_idx, 0, k as u8);
                *slot = ch;
                if ch >= 0 {
                    lane_owners[k] = scheduler::channel_producer_owner(ch);
                    lane_count = k + 1;
                }
            }
            let net_out_ch = scheduler::get_module_port(module_idx, 1, 0);
            let mut m = scheduler::BuiltInModule::new("linux_net", linux_net_step);
            let state = LinuxNetState::new(net_ins, lane_owners, net_out_ch);
            // Register for the platform-side endpoint report, the owner
            // teardown hook, and the rebuild fd close-out (§4.3–§4.5).
            linux_net_register_state(&*state as *const LinuxNetState as *mut LinuxNetState);
            install_state(&mut m, state);
            scheduler::store_builtin_module(module_idx, m);
            log::info!(
                "[inst] module {module_idx} = linux_net (built-in) net_in_lanes={lane_count} net_out={net_out_ch}"
            );
            loaded_count += 1;
            continue;
        }

        if entry.name_hash == CLI_IN_HASH {
            let m = build_cli_in(module_idx);
            scheduler::store_builtin_module(module_idx, m);
            loaded_count += 1;
            continue;
        }

        if entry.name_hash == CLI_OUT_HASH {
            let m = build_cli_out(module_idx);
            scheduler::store_builtin_module(module_idx, m);
            loaded_count += 1;
            continue;
        }

        if entry.name_hash == HOST_ASSET_SOURCE_HASH {
            let m = build_host_asset_source(module_idx, entry.params());
            scheduler::store_builtin_module(module_idx, m);
            loaded_count += 1;
            continue;
        }

        if entry.name_hash == HOST_ASSET_INDEX_HASH {
            let m = build_host_asset_index(module_idx, entry.params());
            scheduler::store_builtin_module(module_idx, m);
            loaded_count += 1;
            continue;
        }

        if entry.name_hash == LINUX_DISPLAY_HASH {
            let m = build_linux_display(module_idx, entry.params());
            scheduler::store_builtin_module(module_idx, m);
            loaded_count += 1;
            continue;
        }

        if entry.name_hash == LINUX_AUDIO_HASH {
            let m = build_linux_audio(module_idx, entry.params());
            scheduler::store_builtin_module(module_idx, m);
            loaded_count += 1;
            continue;
        }

        #[cfg(feature = "host-image")]
        if entry.name_hash == HOST_IMAGE_CODEC_HASH {
            let m = build_host_image_codec(module_idx, entry.params());
            scheduler::store_builtin_module(module_idx, m);
            loaded_count += 1;
            continue;
        }

        if entry.name_hash == LINUX_ALSA_MIDI_HASH {
            let m = build_linux_alsa_midi(module_idx, entry.params());
            scheduler::store_builtin_module(module_idx, m);
            loaded_count += 1;
            continue;
        }

        if entry.name_hash == LINUX_SURFACE_TRAITS_HASH {
            let m = build_linux_surface_traits(module_idx, entry.params());
            scheduler::store_builtin_module(module_idx, m);
            loaded_count += 1;
            continue;
        }

        if entry.name_hash == LINUX_SURFACE_TRAITS_PROBE_HASH {
            let m = build_linux_surface_traits_probe(module_idx);
            scheduler::store_builtin_module(module_idx, m);
            loaded_count += 1;
            continue;
        }

        if entry.name_hash == LINUX_POINTER_HASH {
            let m = build_linux_pointer(module_idx, entry.params());
            scheduler::store_builtin_module(module_idx, m);
            loaded_count += 1;
            continue;
        }

        scheduler::set_current_module(module_idx);
        let result = scheduler::instantiate_one_module(
            loader_ref,
            entry,
            module_idx,
            module_idx,
            &mut sched.edges,
            &mut sched.modules,
            &mut sched.ports,
        );
        match result {
            scheduler::InstantiateResult::Done => {
                log::info!("[inst] module {module_idx} ready");
                loaded_count += 1;
            }
            scheduler::InstantiateResult::Pending(mut pending) => {
                let mut loaded = false;
                for _ in 0..100 {
                    thread::sleep(Duration::from_millis(10));
                    // SAFETY: `pending` is the scheduler-allocated handle from
                    // `instantiate_one_module`; `try_complete` polls the loader.
                    match unsafe { pending.try_complete() } {
                        Ok(Some(dm)) => {
                            log::info!("[inst] module {module_idx} ready (pending)");
                            scheduler::store_dynamic_module(module_idx, dm);
                            loaded_count += 1;
                            loaded = true;
                            break;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            log::error!("[inst] module {module_idx} failed: {e:?}");
                            loaded = true;
                            break;
                        }
                    }
                }
                if !loaded {
                    log::error!("[inst] module {module_idx} timeout");
                }
            }
            scheduler::InstantiateResult::Error(rc) => {
                log::error!("[inst] module {module_idx} error rc={rc}");
            }
        }
    }

    log::info!("[inst] {loaded_count} of {module_count} modules loaded");
    scheduler::log_arena_summary();
    (module_count, loaded_count)
}

// ============================================================================
// Entry point
// ============================================================================

/// Modification time of the published plan file, if it exists.
fn plan_mtime(path: &str) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Read + stage the plan blob at `path`. The bytes are intentionally leaked:
/// the staged-plan contract requires them valid until the (asynchronous)
/// apply consumes them, and reloads happen at pod-lifecycle frequency — a few
/// dozen bytes per pod churn, not a growth path.
fn stage_plan_from(path: &str) {
    match std::fs::read(path) {
        Ok(bytes) => {
            log::info!("[owner] staging plan from {path} ({} bytes)", bytes.len());
            let leaked: &'static [u8] = Box::leak(bytes.into_boxed_slice());
            // SAFETY: 'static bytes satisfy the validity contract.
            unsafe { fluxor::kernel::owner_plan::set_staged_plan(leaked.as_ptr(), leaked.len()) };
        }
        Err(e) => log::error!("[owner] plan reload from {path} failed: {e}"),
    }
}

fn main() {
    // Initialize boot instant for monotonic clock
    // SAFETY: main runs before any other thread; first write to BOOT_INSTANT
    // happens-before any reader observes it.
    unsafe {
        BOOT_INSTANT = Some(Instant::now());
    }

    // Set up logging via the owner-log tee: identical env_logger stderr
    // formatting/filtering, plus per-owner ring routing for `fluxor agent logs`
    // (rfc_owner_drain_and_logs.md Part B). Registers this (main) thread as the
    // scheduler thread — the only thread whose records reach the rings.
    install_owner_log_tee();
    register_scheduler_thread();

    log::info!("[fluxor] linux platform boot");

    let args = parse_args();

    // Read config from file (regular read — config is data, not code)
    let config_data = fs::read(&args.config_path).unwrap_or_else(|e| {
        eprintln!("error: failed to read config {}: {}", args.config_path, e);
        process::exit(1);
    });

    // mmap modules with PROT_READ | PROT_EXEC — PIC modules contain executable code.
    // Using fs::read() would place code in non-executable heap memory, causing SEGV.
    let modules_file = fs::File::open(&args.modules_path).unwrap_or_else(|e| {
        eprintln!("error: failed to open modules {}: {}", args.modules_path, e);
        process::exit(1);
    });
    let modules_len = modules_file.metadata().unwrap().len() as usize;
    // SAFETY: `mmap` with a valid fd, length, and PRIVATE|EXEC flags — the
    // kernel returns either a valid mapping or MAP_FAILED (checked below).
    let modules_ptr = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            modules_len,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE,
            modules_file.as_raw_fd(),
            0,
        )
    };
    if modules_ptr == libc::MAP_FAILED {
        eprintln!("error: failed to mmap modules file");
        process::exit(1);
    }

    log::info!(
        "[config] loaded {} bytes from {}",
        config_data.len(),
        args.config_path
    );
    log::info!(
        "[modules] mapped {} bytes from {} at {:p}",
        modules_len,
        args.modules_path,
        modules_ptr
    );

    // HAL ops, syscall table, providers, then the step guard.
    fluxor::kernel::boot(&LINUX_HAL_OPS);
    step_guard::init();

    // Populate the kernel's static config + loader from our mmap'd blobs
    // and compile the graph. `scheduler::prepare_graph` decodes edges,
    // inserts `_tee` / `_merge` for fan groups, allocates channels, and
    // populates port tables.
    loader::reset_state_arena();
    // Length-aware: pass the file's exact byte count for both blobs
    // so the parser rejects any section that would extend past the
    // actual mappings.
    // SAFETY: `config_data` is a Vec<u8>; `modules_ptr`/`modules_len` come from
    // the mmap above and cover the full file. `populate_static_state_with_len`
    // bounds-checks both blobs against the supplied lengths.
    if let Err(msg) = unsafe {
        scheduler::populate_static_state_with_len(
            &config_data,
            modules_ptr as *const u8,
            modules_len,
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
    // Node-agent mode also PUBLISHES per-owner live status next to the plan
    // it consumes (`owner_status.json`, atomic replace) so `fluxor agent
    // status` can report truthful per-pod §7.2 state. Absent file / absent
    // FLUXOR_PLAN ⇒ no runtime status surfaced.
    let mut owner_status = plan_path
        .as_deref()
        .map(|p| OwnerStatusWriter::new(std::path::Path::new(p)));
    // Per-owner log rings are flushed into `logs/` beside `owner_status.json`,
    // on the same tick. `fluxor agent logs` resolves this directory the same way.
    let logs_dir: Option<std::path::PathBuf> = plan_path.as_deref().map(|p| {
        std::path::Path::new(p)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("logs")
    });

    // Compile + instantiate the graph (shared with the live-rebuild path).
    let (mut module_count, loaded_count) = build_graph_linux();
    if loaded_count == 0 {
        log::warn!("[sched] no modules loaded, nothing to do");
        process::exit(0);
    }

    // Admit resident pods declared in the config's `[FXPD]` section (RFC
    // adaptive_tick_extra §7 — `pods:` / `combine <two-graph.yaml>`) as workload
    // owners via `apply_add`, then the multi-graph runner multiplexes them with
    // the base graph. Boot-only (not re-run on live rebuild). No-op without pods.
    scheduler::admit_resident_pods_from_config();

    // A revocation the just-applied plan still lists, naming an owner that was
    // NOT reinstalled, was mid-drain when the previous process died: the drain
    // is forfeited and recorded as drain-timeout-by-restart — unless the
    // previous process already persisted that pod's terminal outcome
    // (rfc_owner_drain_and_logs.md §3.6, §3.7 writer seeding).
    synthesize_restart_terminals(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        &owner_status
            .as_ref()
            .map(|w| w.seeded_terminated_uids())
            .unwrap_or_default(),
    );

    // Publish the initial owner status immediately (before the first 100 ms
    // watch window) so an orchestrator polling right after activation sees
    // the runtime up rather than a stale/absent file.
    if let Some(w) = owner_status.as_mut() {
        w.tick();
    }
    if let Some(dir) = logs_dir.as_deref() {
        flush_owner_rings(dir);
    }

    // Scheduler + HAL are up: log records may now resolve their owning module.
    enable_owner_log_attribution();

    log::info!("[sched] starting main loop, tick_us={tick_us}");
    // The per-iteration deadline is chosen by the adaptive-tick pacer
    // (`scheduler::pacer_next_deadline_us`) inside the loop; there is no fixed
    // `tick_duration` any more. With no adaptive flag set the pacer returns the
    // nominal tick every iteration, so pacing is byte-identical to before.
    let mut tick: u64 = 0;
    // Test hook: when FLUXOR_TEST_REBUILD_EVERY=N is set,
    // self-trigger a graph rebuild every N loop iterations to exercise the
    // live-rebuild loop without a full reconfigure graph. No-op when unset.
    let test_rebuild_every: u64 = std::env::var("FLUXOR_TEST_REBUILD_EVERY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    // Always-incrementing iteration counter (unlike `tick`, it advances even on
    // rebuild iterations that `continue` before the tick bump), so the periodic
    // trigger fires exactly once per period.
    let mut iter: u64 = 0;
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
    // can `unpark()` us out of `park_timeout` between ticks. Matches RP's
    // SIGNAL-races-Timer pattern in `embassy_futures::select`.
    linux_install_wake_thread();

    loop {
        let t0 = Instant::now();
        iter = iter.wrapping_add(1);

        // Test hook: periodic self-trigger (no-op unless FLUXOR_TEST_REBUILD_EVERY set).
        if test_rebuild_every > 0 && iter.is_multiple_of(test_rebuild_every) {
            log::info!("[test] auto-triggering rebuild at iter {iter}");
            // SAFETY: null/0 = the documented "reload current STATIC_CONFIG" sentinel.
            unsafe { scheduler::request_rebuild(core::ptr::null(), 0) };
        }

        // Node-agent generation update: the agent recommits + republishes the
        // plan file; a changed mtime re-stages it and live-rebuilds ownership
        // (rfc_k8s.md §12). Time-gated to one stat() per ~100 ms regardless of
        // tick rate (a busy-loop tick would otherwise stat every spin; an
        // idle 100 ms-per-iteration loop would otherwise check too rarely).
        if plan_path.is_some() && last_plan_check.elapsed() >= Duration::from_millis(100) {
            last_plan_check = Instant::now();
            // Settle armed drains BEFORE consuming a new plan: a drain that
            // already reached quiescence or its deadline becomes a terminal
            // record (and its owner is freed) first, so the plan update never
            // races a finished drain. A still-live drain is protected on the
            // other side: the delta path refuses a plan that drops a retained
            // revocation while its owner is installed.
            drain_tick(
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
                    // A pure-drain generation (records moved from the assignment
                    // section to the revocation section, nothing else) applies as
                    // a live delta: the departing owner flips to Draining and the
                    // drain driver takes over — no rebuild, co-resident owners
                    // untouched (rfc_owner_drain_and_logs.md §3.4). Anything
                    // structural falls through to the rebuild as before.
                    match fluxor::kernel::owner_plan::try_apply_drain_delta() {
                        Some(delta) => arm_drains(&delta),
                        None => {
                            // Structural plan: not a pure-drain delta, but it may
                            // still revoke owners. Arm their drains before the
                            // rebuild so each gets a terminal record — the rebuild's
                            // reset drops the owner from the table and the next
                            // drain_tick finalises it, instead of it vanishing
                            // untracked.
                            let drains = fluxor::kernel::owner_plan::arm_staged_revocation_drains();
                            arm_drains(&drains);
                            // SAFETY: null/0 = reload current STATIC_CONFIG sentinel.
                            unsafe { scheduler::request_rebuild(core::ptr::null(), 0) };
                        }
                    }
                }
            }
            // Same cadence as the plan watch: publish per-owner live status
            // (no-op write when the derived state is unchanged) and flush the
            // per-owner log rings to their files.
            if let Some(w) = owner_status.as_mut() {
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
        if scheduler::take_rebuild_request().is_some() {
            log::info!("[reconfigure] rebuild requested; rebuilding graph");
            let (mc, lc) = build_graph_linux();
            module_count = mc;
            scheduler::set_reconfigure_phase(scheduler::ReconfigurePhase::Running);
            log::info!("[reconfigure] rebuilt graph: {lc} of {mc} modules");
            // Observe re-activation NOW, before the rebuilt modules step: a
            // previously-terminated owner that faults again within the 100 ms
            // status cadence would otherwise re-terminate unobserved and its
            // aggregate restart (Terminated → re-activated) go uncounted.
            if let Some(w) = owner_status.as_mut() {
                w.tick();
            }
            if let Some(dir) = logs_dir.as_deref() {
                flush_owner_rings(dir);
            }
            continue;
        }

        // Use the shared scheduler stepping path — same one RP and BCM
        // (via its per-domain wrapper) call. Centralises topological
        // execution order, `StepOutcome::{Continue, Ready, Done, Burst}`,
        // burst-cap enforcement, deferred-ready gating, step-period
        // counters, fault transitions, and diagnostics.
        //
        // SAFETY: linux platform is single-threaded; the main loop is the
        // sole scheduler user after instantiation.
        let sched = unsafe { scheduler::sched_mut() };
        // Multi-graph runtime (RFC adaptive_tick_extra §7): when more than one
        // resident graph is admitted this steps each owner independently, skips
        // idle owners, and returns the §7.2 merged sleep deadline. With one
        // resident graph it is byte-identical to `step_modules` +
        // `pacer_next_deadline_us(0)` (the fast path inside the call).
        let (result, sleep_us) =
            scheduler::step_resident_graphs_flat(&mut sched.modules, module_count);

        if matches!(result, fluxor::kernel::scheduler::StepResult::Done) {
            // Node-agent mode (FLUXOR_PLAN set): the runtime is the node's
            // persistent substrate — pods come and go via plan reloads, so an
            // all-done/empty graph idles awaiting SIGHUP instead of exiting.
            if plan_path.is_some() {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            // Plain-run/exec completion: report the CLI exit-code latch
            // (default 0 — non-CLI graphs are unchanged). Node-agent mode
            // never reaches here (rfc_cli_execution.md §6).
            let code = CLI_EXIT_CODE.load(Ordering::Acquire);
            log::info!("[sched] all modules complete, exiting (code {code})");
            // Restore the terminal if an interactive applet put it in raw mode.
            restore_terminal();
            process::exit(code);
        }

        // Event-wake parity with RP: drain any wake bits that latched
        // during step_modules (modules signaling their own events) and
        // run the affected modules through the same `step_one_module`
        // body with `event_wake = true`. Without this, events signaled
        // mid-tick on Linux waited until the next full tick to run —
        // an interrupt-driven module would observe its event arbitrarily
        // late depending on `tick_us`.
        let wake = fluxor::kernel::event::take_wake_pending();
        if !wake.is_empty() {
            scheduler::step_woken_modules(&mut sched.modules, module_count, &wake);
        }

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
        // `sleep_us` was chosen above by the resident-graph runner (RFC
        // adaptive_tick §5.1 / adaptive_tick_extra §7.2). With no adaptive flag
        // set it returns the domain's nominal tick, so `sleep_us == tick_us`
        // every iteration and the bands below are byte-identical to the
        // fixed-tick loop. With mechanism (a) enabled and an idle pass it returns
        // `tick_max_us`; `park_timeout` stays interruptible by `unpark` from
        // `linux_wake_scheduler`, so a wake returns immediately. Linux is a flat
        // single-domain runner → domain 0.
        let sleep_duration = Duration::from_micros(sleep_us as u64);
        let elapsed = t0.elapsed();
        if sleep_us == 0 {
            // Pure busy-loop — recheck immediately.
        } else if sleep_us <= 200 {
            while t0.elapsed() < sleep_duration {
                // Yield early on wake so woken modules don't wait out
                // the remainder of the spin budget. The bit stays
                // latched in EVENT_WAKE_PENDING for the next iteration.
                if fluxor::kernel::event::wake_pending_nonzero() {
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

        // Second drain after the wait: an event signaled during the
        // park_timeout (or between the first drain and entering the
        // spin) reaches `step_woken_modules` before the next full
        // step pass, matching RP's two-drain wake path.
        let wake = fluxor::kernel::event::take_wake_pending();
        if !wake.is_empty() {
            // SAFETY: single-threaded linux main loop — sole scheduler user.
            let sched = unsafe { scheduler::sched_mut() };
            scheduler::step_woken_modules(&mut sched.modules, module_count, &wake);
        }

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
