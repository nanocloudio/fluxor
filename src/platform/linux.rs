// Platform: Linux hosted — runs Fluxor as an aarch64 Linux userspace process.
//
// Loads real PIC .fmod modules via mmap and runs the same scheduler/graph
// model as the embedded targets. Single-domain (v1): one thread, cooperative
// step loop with std::thread::sleep for tick timing.
//
// Usage:
//   fluxor-linux --config config.bin --modules modules.bin
//   fluxor-linux config.yaml                  # (future: auto-generate bins)

use std::env;
use std::fs;
use std::os::unix::io::AsRawFd;
use std::process;
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
                eprintln!("error: unknown argument: {}", other);
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

// ============================================================================
// Entry point
// ============================================================================

fn main() {
    // Initialize boot instant for monotonic clock
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
    if let Err(msg) =
        unsafe { scheduler::populate_static_state(config_data.as_ptr(), modules_ptr as *const u8) }
    {
        eprintln!("error: {}", msg);
        process::exit(1);
    }

    let cfg_header_tick_us = unsafe { scheduler::static_config().header.tick_us as u32 };
    let tick_us = if cfg_header_tick_us > 0 {
        cfg_header_tick_us
    } else {
        1000
    };
    log::info!("[loader] module table loaded, tick_us={}", tick_us);

    let (module_list, module_count) = match scheduler::prepare_graph() {
        Ok(v) => v,
        Err(rc) => {
            eprintln!("error: prepare_graph failed (rc={})", rc);
            process::exit(1);
        }
    };
    log::info!("[graph] compiled: {} modules", module_count);

    // Instantiate every module in the compiled list. `linux_net` is a
    // hosted built-in with no .fmod entry, so it's constructed directly
    // as a `BuiltInModule`; every other slot — user modules and any
    // kernel-inserted `_tee` / `_merge` — goes through the shared
    // `instantiate_one_module` path.
    let loader_ref = unsafe { scheduler::static_loader() };
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
            install_state(&mut m, Box::new(LinuxNetState::new(net_in_ch, net_out_ch)));
            scheduler::store_builtin_module(module_idx, m);
            log::info!(
                "[inst] module {} = linux_net (built-in) net_in={} net_out={}",
                module_idx,
                net_in_ch,
                net_out_ch
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
                log::info!("[inst] module {} ready", module_idx);
                loaded_count += 1;
            }
            scheduler::InstantiateResult::Pending(mut pending) => {
                let mut loaded = false;
                for _ in 0..100 {
                    thread::sleep(Duration::from_millis(10));
                    match unsafe { pending.try_complete() } {
                        Ok(Some(dm)) => {
                            log::info!("[inst] module {} ready (pending)", module_idx);
                            scheduler::store_dynamic_module(module_idx, dm);
                            loaded_count += 1;
                            loaded = true;
                            break;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            log::error!("[inst] module {} failed: {:?}", module_idx, e);
                            loaded = true;
                            break;
                        }
                    }
                }
                if !loaded {
                    log::error!("[inst] module {} timeout", module_idx);
                }
            }
            scheduler::InstantiateResult::Error(rc) => {
                log::error!("[inst] module {} error rc={}", module_idx, rc);
            }
        }
    }

    log::info!("[inst] {} of {} modules loaded", loaded_count, module_count);
    if loaded_count == 0 {
        log::warn!("[sched] no modules loaded, nothing to do");
        process::exit(0);
    }
    scheduler::log_arena_summary();

    log::info!("[sched] starting main loop, tick_us={}", tick_us);
    let tick_duration = Duration::from_micros(tick_us as u64);
    let mut tick: u64 = 0;

    // Burst-step bound: matches the bcm2712 pump. A module returning
    // `StepOutcome::Burst` is asking to be re-stepped immediately
    // because it has more synchronous work to do (e.g. http's
    // `step_send_file` consumed one MSS and has more to push). The
    // cap defends against a runaway module that never returns
    // anything else.
    const MAX_BURST_STEPS: usize = 16384;

    loop {
        let t0 = Instant::now();

        for i in 0..module_count {
            scheduler::set_current_module(i);
            if let Some(Ok(fluxor::modules::StepOutcome::Burst)) =
                scheduler::step_module_outcome(i)
            {
                for _ in 0..MAX_BURST_STEPS {
                    match scheduler::step_module_outcome(i) {
                        Some(Ok(fluxor::modules::StepOutcome::Burst)) => continue,
                        _ => break,
                    }
                }
            }
        }

        tick += 1;

        if tick_us > 0 && tick.is_multiple_of(10_000_000 / tick_us as u64) {
            log::info!("[sched] alive t={} elapsed_ms={}", tick, linux_now_millis());
        }

        // Tick pacing. `thread::sleep` for sub-millisecond targets
        // has a ~50-150 µs floor on Linux (timer-tick granularity +
        // scheduler wake latency), so for hot cadences we busy-spin
        // instead and only fall back to sleep at coarse settings:
        //
        //   * tick_us == 0   → pure busy-loop, no pacing.
        //   * tick_us <= 200 → spin until `tick_duration` elapses.
        //   * tick_us > 200  → sleep for the remainder.
        let elapsed = t0.elapsed();
        if tick_us == 0 {
            // Pure busy-loop — recheck immediately.
        } else if tick_us <= 200 {
            while t0.elapsed() < tick_duration {
                core::hint::spin_loop();
            }
        } else if elapsed < tick_duration {
            thread::sleep(tick_duration - elapsed);
        }
    }
}
