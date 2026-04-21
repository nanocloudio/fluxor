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
use std::time::Instant;

use fluxor::kernel::channel;
use fluxor::kernel::config::{self, Config};
use fluxor::kernel::hal::{self, HalOps};
use fluxor::kernel::loader::{self, DynamicModule, ModuleLoader, StartNewResult};
use fluxor::kernel::scheduler;
use fluxor::kernel::step_guard;
use fluxor::kernel::syscalls;

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
                eprintln!("");
                eprintln!("Options:");
                eprintln!("  -c, --config <path>   Path to config.bin");
                eprintln!("  -m, --modules <path>  Path to modules.bin");
                eprintln!("  -h, --help            Show this help");
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

// ============================================================================
// Module storage
// ============================================================================

const MAX_MODS: usize = config::MAX_MODULES;

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

    // Initialize HAL
    hal::init(&LINUX_HAL_OPS);

    // Initialize syscall table and providers
    syscalls::init_syscall_table();
    syscalls::init_providers();
    step_guard::init();

    // Parse config from loaded data
    let mut cfg = Config::empty();
    if !config::read_config_from_ptr(config_data.as_ptr(), &mut cfg) {
        eprintln!("error: failed to parse config");
        process::exit(1);
    }

    let n_modules = cfg.module_count as usize;
    let n_edges = cfg.edge_count as usize;
    let tick_us = if cfg.header.tick_us > 0 {
        cfg.header.tick_us as u32
    } else {
        1000
    };

    log::info!(
        "[config] {} modules, {} edges, tick_us={}",
        n_modules,
        n_edges,
        tick_us
    );

    // Load module table from blob
    loader::reset_state_arena();
    let mut ldr = ModuleLoader::new();
    if ldr.init_from_blob(modules_ptr as *const u8).is_err() {
        eprintln!("error: failed to load module table");
        process::exit(1);
    }

    log::info!("[loader] module table loaded");

    // Create channels from graph edges and register ports via set_module_port.
    // Supports multi-port modules (e.g. linux_net.net_out, ip.net_in).
    // Also tracks port-0 in/out/ctrl for DynamicModule::start_new().
    let mut mod_in: [i32; MAX_MODS] = [-1; MAX_MODS];
    let mut mod_out: [i32; MAX_MODS] = [-1; MAX_MODS];
    let mut mod_ctrl: [i32; MAX_MODS] = [-1; MAX_MODS];

    for e in 0..n_edges {
        if let Some(ref edge) = cfg.graph_edges[e] {
            let from = edge.from_id as usize;
            let to = edge.to_id as usize;

            let ch = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);
            if ch < 0 {
                continue;
            }

            // Register source (output) port
            if from < MAX_MODS {
                scheduler::set_module_port(from, 1, edge.from_port_index, ch);
                if edge.from_port_index == 0 && mod_out[from] < 0 {
                    mod_out[from] = ch;
                }
            }

            // Register destination port (input or ctrl)
            if to < MAX_MODS {
                let port_type = if edge.to_port == 1 { 2u8 } else { 0u8 }; // ctrl=2, in=0
                scheduler::set_module_port(to, port_type, edge.to_port_index, ch);
                if edge.to_port == 0 && edge.to_port_index == 0 && mod_in[to] < 0 {
                    mod_in[to] = ch;
                } else if edge.to_port == 1 && edge.to_port_index == 0 && mod_ctrl[to] < 0 {
                    mod_ctrl[to] = ch;
                }
            }
        }
    }

    // Instantiate modules
    let syscall_table = syscalls::get_table_for_module_type(0);
    let mut modules: Vec<bool> = Vec::with_capacity(n_modules);

    for i in 0..n_modules {
        if let Some(ref entry) = cfg.modules[i] {
            // Check for built-in modules first
            if entry.name_hash == LINUX_NET_HASH {
                scheduler::set_current_module(i);

                // Create BuiltInModule with channel handles in state buffer
                let mut m = scheduler::BuiltInModule::new("linux_net", linux_net_step);
                let state = m.state.as_mut_ptr();
                // Read channel handles from set_module_port (input port 0, output port 0)
                let net_in_ch = scheduler::channel_port_lookup(0, 0); // input port 0
                let net_out_ch = scheduler::channel_port_lookup(1, 0); // output port 0
                unsafe {
                    core::ptr::write(state as *mut i32, net_in_ch);
                    core::ptr::write(state.add(4) as *mut i32, net_out_ch);
                }
                scheduler::store_builtin_module(i, m);
                log::info!(
                    "[inst] module {} = linux_net (built-in) net_in={} net_out={}",
                    i,
                    net_in_ch,
                    net_out_ch
                );
                modules.push(true);
                continue;
            }

            if let Ok(m) = ldr.find_by_name_hash(entry.name_hash) {
                scheduler::set_current_module(i);

                // Store export table and caps info for provider registration
                scheduler::set_module_exports(
                    i,
                    m.code_base() as usize,
                    m.export_table_ptr(),
                    m.header.export_count,
                );
                let cap_class = match m.header.module_type {
                    5 => 3,
                    3 => 1,
                    4 => 2,
                    _ => 0,
                };
                scheduler::set_module_caps(
                    i,
                    cap_class,
                    m.header.required_caps() as u32,
                    m.manifest_permissions(),
                );

                let result = unsafe {
                    DynamicModule::start_new(
                        &m,
                        syscall_table,
                        mod_in[i],
                        mod_out[i],
                        mod_ctrl[i],
                        entry.params_ptr,
                        entry.params_len,
                        "",
                    )
                };
                match result {
                    Ok(StartNewResult::Ready(dm)) => {
                        log::info!("[inst] module {} ready", i);
                        scheduler::store_dynamic_module(i, dm);
                        modules.push(true);
                    }
                    Ok(StartNewResult::Pending(mut pending)) => {
                        let mut loaded = false;
                        for _ in 0..100 {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                            match unsafe { pending.try_complete() } {
                                Ok(Some(dm)) => {
                                    log::info!("[inst] module {} ready (pending)", i);
                                    scheduler::store_dynamic_module(i, dm);
                                    modules.push(true);
                                    loaded = true;
                                    break;
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    log::error!("[inst] module {} failed: {:?}", i, e);
                                    modules.push(false);
                                    loaded = true;
                                    break;
                                }
                            }
                        }
                        if !loaded {
                            log::error!("[inst] module {} timeout", i);
                            modules.push(false);
                        }
                    }
                    Err(e) => {
                        log::error!("[inst] module {} error: {:?}", i, e);
                        modules.push(false);
                    }
                }
            } else {
                log::warn!(
                    "[inst] module {} not found (hash={:#010x})",
                    i,
                    entry.name_hash
                );
                modules.push(false);
            }
        } else {
            modules.push(false);
        }
    }

    let loaded_count = modules.iter().filter(|m| **m).count();
    log::info!("[inst] {} of {} modules loaded", loaded_count, n_modules);

    if loaded_count == 0 {
        log::warn!("[sched] no modules loaded, nothing to do");
        process::exit(0);
    }

    // Main step loop
    log::info!("[sched] starting main loop, tick_us={}", tick_us);
    let tick_duration = std::time::Duration::from_micros(tick_us as u64);
    let mut tick: u64 = 0;

    loop {
        let t0 = Instant::now();

        for i in 0..modules.len() {
            if modules[i] {
                scheduler::set_current_module(i);
                scheduler::step_module(i);
            }
        }

        tick += 1;

        // Periodic alive log every 10 seconds
        if tick_us > 0 && tick % (10_000_000 / tick_us as u64) == 0 {
            log::info!("[sched] alive t={} elapsed_ms={}", tick, linux_now_millis());
        }

        let elapsed = t0.elapsed();
        if elapsed < tick_duration {
            std::thread::sleep(tick_duration - elapsed);
        }
    }
}
