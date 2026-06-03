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

include!("linux/providers.rs");
include!("linux/builtin_params.rs");
include!("linux/host_asset_source.rs");
include!("linux/host_asset_index.rs");
include!("linux/linux_display.rs");
include!("linux/linux_audio.rs");
include!("linux/host_image_codec.rs");
include!("linux/linux_alsa_midi.rs");

// ============================================================================
// Entry point
// ============================================================================

fn main() {
    // Initialize boot instant for monotonic clock
    // SAFETY: main runs before any other thread; first write to BOOT_INSTANT
    // happens-before any reader observes it.
    unsafe {
        BOOT_INSTANT = Some(Instant::now());
    }

    // Set up logging via env_logger or simple stderr
    // For now, just use log macros which will go to the default sink
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

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

    let (module_list, module_count) = match scheduler::prepare_graph() {
        Ok(v) => v,
        Err(rc) => {
            eprintln!("error: prepare_graph failed (rc={rc})");
            process::exit(1);
        }
    };
    log::info!("[graph] compiled: {module_count} modules");

    // Instantiate every module in the compiled list. `linux_net` is a
    // hosted built-in with no .fmod entry, so it's constructed directly
    // as a `BuiltInModule`; every other slot — user modules and any
    // kernel-inserted `_tee` / `_merge` — goes through the shared
    // `instantiate_one_module` path.
    // SAFETY: `static_loader` returns a reference into the static loader
    // arena populated by `populate_static_state_with_len`.
    let loader_ref = unsafe { scheduler::static_loader() };
    // SAFETY: single-threaded boot; `sched_mut` exposes the scheduler's
    // static state during module instantiation, before any worker thread
    // takes ownership.
    let sched = unsafe { scheduler::sched_mut() };
    let mut loaded_count = 0usize;

    for (module_idx, entry) in module_list.iter().enumerate().take(module_count) {
        let entry = match entry {
            Some(e) => e,
            None => continue,
        };

        if entry.name_hash == LINUX_NET_HASH {
            scheduler::set_current_module(module_idx);
            let net_in_ch = scheduler::get_module_port(module_idx, 0, 0);
            let net_out_ch = scheduler::get_module_port(module_idx, 1, 0);
            let mut m = scheduler::BuiltInModule::new("linux_net", linux_net_step);
            // `LinuxNetState::new` already returns a heap `Box<Self>`
            // (built in place to avoid a ~16 MiB stack temporary).
            install_state(&mut m, LinuxNetState::new(net_in_ch, net_out_ch));
            scheduler::store_builtin_module(module_idx, m);
            log::info!(
                "[inst] module {module_idx} = linux_net (built-in) net_in={net_in_ch} net_out={net_out_ch}"
            );
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
                    // `instantiate_one_module`; `try_complete` polls the loader
                    // state machine and is the contract-correct call here.
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
    if loaded_count == 0 {
        log::warn!("[sched] no modules loaded, nothing to do");
        process::exit(0);
    }
    scheduler::log_arena_summary();

    log::info!("[sched] starting main loop, tick_us={tick_us}");
    let tick_duration = Duration::from_micros(tick_us as u64);
    let mut tick: u64 = 0;
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

        // Use the shared scheduler stepping path — same one RP and BCM
        // (via its per-domain wrapper) call. Centralises topological
        // execution order, `StepOutcome::{Continue, Ready, Done, Burst}`,
        // burst-cap enforcement, deferred-ready gating, step-period
        // counters, fault transitions, and diagnostics. The previous
        // Linux loop only handled `Burst` and stepped in raw index order
        // — non-trivially divergent from the reference path.
        //
        // SAFETY: linux platform is single-threaded; the main loop is the
        // sole scheduler user after instantiation.
        let sched = unsafe { scheduler::sched_mut() };
        let result = scheduler::step_modules(&mut sched.modules, module_count);

        if matches!(result, fluxor::kernel::scheduler::StepResult::Done) {
            log::info!("[sched] all modules complete, exiting");
            process::exit(0);
        }

        // Event-wake parity with RP: drain any wake bits that latched
        // during step_modules (modules signaling their own events) and
        // run the affected modules through the same `step_one_module`
        // body with `event_wake = true`. Without this, events signaled
        // mid-tick on Linux waited until the next full tick to run —
        // an interrupt-driven module would observe its event arbitrarily
        // late depending on `tick_us`.
        let wake = fluxor::kernel::event::take_wake_pending();
        if wake != 0 {
            scheduler::step_woken_modules(&mut sched.modules, module_count, wake);
        }

        tick += 1;

        scheduler::maybe_emit_alive(tick, None);

        // Tick pacing. `thread::sleep` for sub-millisecond targets
        // has a ~50-150 µs floor on Linux (timer-tick granularity +
        // scheduler wake latency), so for hot cadences we busy-spin
        // instead and only fall back to sleep at coarse settings:
        //
        //   * tick_us == 0   → pure busy-loop, no pacing.
        //   * tick_us <= 200 → spin until `tick_duration` elapses,
        //                      yielding early if a wake bit fires.
        //   * tick_us > 200  → `park_timeout` for the remainder; an
        //                      `unpark` from `linux_wake_scheduler`
        //                      returns immediately so the next
        //                      iteration's drain runs the woken module.
        let elapsed = t0.elapsed();
        if tick_us == 0 {
            // Pure busy-loop — recheck immediately.
        } else if tick_us <= 200 {
            while t0.elapsed() < tick_duration {
                // Yield early on wake so woken modules don't wait out
                // the remainder of the spin budget. The bit stays
                // latched in EVENT_WAKE_PENDING for the next iteration.
                if fluxor::kernel::event::wake_pending_nonzero() {
                    break;
                }
                core::hint::spin_loop();
            }
        } else if elapsed < tick_duration {
            // `park_timeout` is interruptible by `unpark()` and may
            // return spuriously; either way the next iteration drains
            // wake bits and steps. The remaining budget is the upper
            // bound, never a hard sleep.
            thread::park_timeout(tick_duration - elapsed);
        }

        // Second drain after the wait: an event signaled during the
        // park_timeout (or between the first drain and entering the
        // spin) reaches `step_woken_modules` before the next full
        // step pass, matching RP's two-drain wake path.
        let wake = fluxor::kernel::event::take_wake_pending();
        if wake != 0 {
            // SAFETY: single-threaded linux main loop — sole scheduler user.
            let sched = unsafe { scheduler::sched_mut() };
            scheduler::step_woken_modules(&mut sched.modules, module_count, wake);
        }

        // Detect chronic host oversleep. `thread::park_timeout`
        // contracts with the OS scheduler; under `CONFIG_HZ=100` or
        // load, the wake-up may overshoot by milliseconds. A 1.5×
        // threshold ignores small-jitter overshoot and only fires on
        // sustained drift, throttled once per ~second of expected
        // wall-clock. Operators reading this in the log can correlate
        // to RT-priority or CFS-bandwidth misconfiguration.
        if tick_us > 200 {
            let actual = t0.elapsed();
            let threshold = tick_duration + tick_duration / 2;
            if actual > threshold && tick - last_oversleep_log_tick >= oversleep_log_period_ticks {
                log::warn!(
                    "MON_HOST_OVERSLEEP tick={} requested_us={} actual_us={} threshold_us={}",
                    tick,
                    tick_us,
                    actual.as_micros() as u64,
                    threshold.as_micros() as u64,
                );
                last_oversleep_log_tick = tick;
            }
        }
    }
}
