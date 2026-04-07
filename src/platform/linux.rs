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

use fluxor::kernel::hal::{self, HalOps};
use fluxor::kernel::loader::{self, DynamicModule, ModuleLoader, StartNewResult};
use fluxor::kernel::config::{self, Config};
use fluxor::kernel::channel;
use fluxor::kernel::scheduler;
use fluxor::kernel::step_guard;
use fluxor::kernel::syscalls;

// ============================================================================
// Linker symbol stub
// ============================================================================

// The config module references __end_block_addr (a linker symbol for flash
// layout trailers). On Linux we don't use flash layout — we load config from
// files directly. Provide a dummy symbol so the code links.
#[no_mangle]
#[used]
static __end_block_addr: u8 = 0;

// ============================================================================
// Monotonic clock (CLOCK_MONOTONIC via std::time)
// ============================================================================

static mut BOOT_INSTANT: Option<Instant> = None;

fn elapsed_micros() -> u64 {
    unsafe {
        let ptr = &raw const BOOT_INSTANT;
        match &*ptr {
            Some(t) => t.elapsed().as_micros() as u64,
            None => 0,
        }
    }
}

// ============================================================================
// HAL implementation
// ============================================================================

fn linux_disable_interrupts() -> u32 { 0 }
fn linux_restore_interrupts(_state: u32) {}
fn linux_wake_scheduler() {}

fn linux_now_millis() -> u64 { elapsed_micros() / 1000 }
fn linux_now_micros() -> u64 { elapsed_micros() }
fn linux_tick_count() -> u32 { scheduler::tick_count() }

fn linux_flash_base() -> usize { 0 }
fn linux_flash_end() -> usize { 0 }
fn linux_apply_code_bit(addr: usize) -> usize { addr }
fn linux_validate_fn_addr(addr: usize) -> bool { addr != 0 }
fn linux_validate_module_base(addr: usize) -> bool { addr != 0 }
fn linux_validate_fn_in_code(_addr: usize, _base: usize, _size: u32) -> bool { true }
fn linux_verify_integrity(_computed: &[u8], _expected: &[u8]) -> bool { true }
fn linux_pic_barrier() {}

fn linux_step_guard_init() {}
fn linux_step_guard_arm(_deadline_us: u32) {}
fn linux_step_guard_disarm() {}
fn linux_step_guard_post_check() {}

fn linux_read_cycle_count() -> u32 { elapsed_micros() as u32 }

fn linux_isr_tier_init() {}
fn linux_isr_tier_start(_period_us: u32) {}
fn linux_isr_tier_stop() {}
fn linux_isr_tier_poll() {}

fn linux_init_providers() {
    // Override the default stub FS provider with one backed by real libc I/O.
    // Socket provider is already registered by syscalls::init_providers();
    // we service socket slots from the main loop via linux_service_sockets().
    use fluxor::kernel::provider;
    use fluxor::abi::dev_class;
    provider::register(dev_class::FS, linux_fs_dispatch);
}
fn linux_release_module_handles(_module_idx: u8) {}
fn linux_boot_scan() {}
fn linux_merge_runtime_overrides(
    _module_id: u16, _buf: *mut u8, len: usize, _max: usize,
) -> usize {
    len
}

static LINUX_HAL_OPS: HalOps = HalOps {
    disable_interrupts: linux_disable_interrupts,
    restore_interrupts: linux_restore_interrupts,
    wake_scheduler: linux_wake_scheduler,
    now_millis: linux_now_millis,
    now_micros: linux_now_micros,
    tick_count: linux_tick_count,
    flash_base: linux_flash_base,
    flash_end: linux_flash_end,
    apply_code_bit: linux_apply_code_bit,
    validate_fn_addr: linux_validate_fn_addr,
    validate_module_base: linux_validate_module_base,
    validate_fn_in_code: linux_validate_fn_in_code,
    verify_integrity: linux_verify_integrity,
    pic_barrier: linux_pic_barrier,
    step_guard_init: linux_step_guard_init,
    step_guard_arm: linux_step_guard_arm,
    step_guard_disarm: linux_step_guard_disarm,
    step_guard_post_check: linux_step_guard_post_check,
    read_cycle_count: linux_read_cycle_count,
    isr_tier_init: linux_isr_tier_init,
    isr_tier_start: linux_isr_tier_start,
    isr_tier_stop: linux_isr_tier_stop,
    isr_tier_poll: linux_isr_tier_poll,
    init_providers: linux_init_providers,
    release_module_handles: linux_release_module_handles,
    boot_scan: linux_boot_scan,
    merge_runtime_overrides: linux_merge_runtime_overrides,
    init_gpio: |_| 0,
    csprng_fill: linux_csprng_fill,
    core_id: || 0,
    irq_bind: |_, _, _| fluxor::kernel::errno::ENOSYS,
};

fn linux_csprng_fill(buf: *mut u8, len: usize) -> i32 {
    unsafe {
        // getrandom() syscall (318 on aarch64 Linux, 318 on x86_64)
        #[cfg(target_arch = "aarch64")]
        const SYS_GETRANDOM: i64 = 278;
        #[cfg(target_arch = "x86_64")]
        const SYS_GETRANDOM: i64 = 318;
        let ret: i64;
        core::arch::asm!(
            "svc 0",
            in("x8") SYS_GETRANDOM,
            in("x0") buf as u64,
            in("x1") len as u64,
            in("x2") 0u64,  // flags: 0 = /dev/urandom
            lateout("x0") ret,
        );
        if ret < 0 || ret as usize != len {
            return -1;
        }
        0
    }
}

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

    CliArgs { config_path, modules_path }
}

// ============================================================================
// Linux Socket Service — polls SocketSlots and services via libc
// ============================================================================

/// Per-slot Linux socket state.  Maps kernel SocketSlot index to a real libc fd.
struct LinuxSocketSlot {
    /// Real libc file descriptor (-1 if not open)
    fd: i32,
    /// Is this a listening socket?
    listening: bool,
}

const MAX_LINUX_SOCKETS: usize = fluxor::kernel::socket::MAX_SOCKETS;

static mut LINUX_SOCKETS: [LinuxSocketSlot; MAX_LINUX_SOCKETS] = {
    // Cannot call const fn with struct init in array repeat, so use a const block
    const EMPTY: LinuxSocketSlot = LinuxSocketSlot { fd: -1, listening: false };
    [EMPTY; MAX_LINUX_SOCKETS]
};

/// Service all socket slots once per tick.  Mirrors what the `ip` module does
/// on bare-metal — reads SERVICE_INFO via direct SocketService access, then
/// performs libc calls for pending operations and data transfer.
unsafe fn linux_service_sockets() {
    use fluxor::kernel::socket::{SocketService, SocketOp};
    use fluxor::abi::poll as poll_flags;

    let sockets = &mut *(&raw mut LINUX_SOCKETS);

    for idx in 0..MAX_LINUX_SOCKETS {
        let slot = match SocketService::get_slot_by_index(idx) {
            Some(s) => s,
            None => continue,
        };

        if slot.is_free() {
            // Reclaim any leaked libc fd
            if sockets[idx].fd >= 0 {
                libc::close(sockets[idx].fd);
                sockets[idx].fd = -1;
                sockets[idx].listening = false;
            }
            continue;
        }

        let lsock = &mut sockets[idx];

        // Service pending operations
        let op = slot.pending_op();
        if op != SocketOp::None {
            match op {
                SocketOp::Connect => {
                    let sock_type = slot.socket_type();
                    // Ensure libc socket exists
                    if lsock.fd < 0 {
                        let ltype = if sock_type == 1 { libc::SOCK_STREAM } else { libc::SOCK_DGRAM };
                        lsock.fd = libc::socket(libc::AF_INET, ltype | libc::SOCK_NONBLOCK, 0);
                    }
                    if lsock.fd < 0 {
                        slot.complete_op(-1);
                        slot.set_state(0); // closed
                        slot.set_poll_flags(poll_flags::ERR);
                    } else {
                        let remote_ip = slot.remote_endpoint();
                        let remote_port = slot.remote_id();
                        let mut addr: libc::sockaddr_in = core::mem::zeroed();
                        addr.sin_family = libc::AF_INET as u16;
                        addr.sin_port = remote_port.to_be();
                        addr.sin_addr.s_addr = remote_ip.to_be();
                        let ret = libc::connect(
                            lsock.fd,
                            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                            core::mem::size_of::<libc::sockaddr_in>() as u32,
                        );
                        if ret == 0 {
                            slot.complete_op(0);
                            slot.set_state(4); // Connected
                            slot.set_poll_flags(poll_flags::CONN);
                        } else {
                            let err = *libc::__errno_location();
                            if err == libc::EINPROGRESS {
                                // Will complete later — leave op pending for now
                                // Actually complete it immediately to keep it simple
                                slot.complete_op(0);
                                slot.set_state(4); // Connected
                                slot.set_poll_flags(poll_flags::CONN);
                            } else {
                                slot.complete_op(-err);
                                slot.set_state(7); // Closed
                                slot.set_poll_flags(poll_flags::ERR);
                            }
                        }
                    }
                }
                SocketOp::Bind => {
                    let sock_type = slot.socket_type();
                    if lsock.fd < 0 {
                        let ltype = if sock_type == 1 { libc::SOCK_STREAM } else { libc::SOCK_DGRAM };
                        lsock.fd = libc::socket(libc::AF_INET, ltype | libc::SOCK_NONBLOCK, 0);
                    }
                    if lsock.fd < 0 {
                        slot.complete_op(-1);
                        slot.set_poll_flags(poll_flags::ERR);
                    } else {
                        // Set SO_REUSEADDR
                        let one: i32 = 1;
                        libc::setsockopt(
                            lsock.fd,
                            libc::SOL_SOCKET,
                            libc::SO_REUSEADDR,
                            &one as *const i32 as *const libc::c_void,
                            core::mem::size_of::<i32>() as u32,
                        );

                        let port = slot.local_id();
                        let mut addr: libc::sockaddr_in = core::mem::zeroed();
                        addr.sin_family = libc::AF_INET as u16;
                        addr.sin_port = port.to_be();
                        addr.sin_addr.s_addr = 0; // INADDR_ANY

                        let ret = libc::bind(
                            lsock.fd,
                            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                            core::mem::size_of::<libc::sockaddr_in>() as u32,
                        );
                        if ret == 0 {
                            slot.complete_op(0);
                            slot.set_state(1); // Allocated (bound)
                        } else {
                            let err = *libc::__errno_location();
                            slot.complete_op(-err);
                            slot.set_poll_flags(poll_flags::ERR);
                        }
                    }
                }
                SocketOp::Listen => {
                    if lsock.fd >= 0 {
                        let ret = libc::listen(lsock.fd, 8);
                        if ret == 0 {
                            lsock.listening = true;
                            slot.complete_op(0);
                            slot.set_state(5); // Listening
                        } else {
                            let err = *libc::__errno_location();
                            slot.complete_op(-err);
                            slot.set_poll_flags(poll_flags::ERR);
                        }
                    } else {
                        slot.complete_op(-22); // EINVAL
                        slot.set_poll_flags(poll_flags::ERR);
                    }
                }
                SocketOp::Accept => {
                    if lsock.fd >= 0 && lsock.listening {
                        let mut addr: libc::sockaddr_in = core::mem::zeroed();
                        let mut addrlen: u32 = core::mem::size_of::<libc::sockaddr_in>() as u32;
                        let new_fd = libc::accept4(
                            lsock.fd,
                            &mut addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
                            &mut addrlen,
                            libc::SOCK_NONBLOCK,
                        );
                        if new_fd >= 0 {
                            libc::close(lsock.fd);
                            lsock.fd = new_fd;
                            lsock.listening = false;
                            slot.set_remote(
                                u32::from_be(addr.sin_addr.s_addr),
                                u16::from_be(addr.sin_port),
                            );
                            slot.complete_op(0);
                            slot.set_state(4);
                            slot.set_poll_flags(poll_flags::CONN);
                        } else {
                            let err = *libc::__errno_location();
                            if err == libc::EAGAIN || err == libc::EWOULDBLOCK {
                                // No connection yet — leave op pending (will retry next tick)
                            } else {
                                slot.complete_op(-err);
                                slot.set_poll_flags(poll_flags::ERR);
                            }
                        }
                    } else {
                        slot.complete_op(-22); // EINVAL
                        slot.set_poll_flags(poll_flags::ERR);
                    }
                }
                SocketOp::Close => {
                    if lsock.fd >= 0 {
                        libc::close(lsock.fd);
                        lsock.fd = -1;
                        lsock.listening = false;
                    }
                    slot.complete_op(0);
                    slot.set_state(7); // Closed
                    slot.set_poll_flags(poll_flags::HUP);
                    slot.reset();
                }
                SocketOp::None => {}
            }
        }

        // Data transfer for connected sockets
        if lsock.fd >= 0 && !lsock.listening && slot.state() == 4 {
            // TX: drain kernel TX buffer → libc send()
            let mut tx_buf = [0u8; 512];
            let n = slot.tx_read(&mut tx_buf);
            if n > 0 {
                let sent = libc::send(
                    lsock.fd,
                    tx_buf.as_ptr() as *const libc::c_void,
                    n,
                    libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                );
                if sent < 0 {
                    let err = *libc::__errno_location();
                    if err != libc::EAGAIN && err != libc::EWOULDBLOCK {
                        // Connection error
                        slot.set_poll_flags(poll_flags::ERR | poll_flags::HUP);
                    }
                    // On EAGAIN, data is lost — acceptable for v1. Modules will resend.
                }
            }

            // RX: libc recv() → kernel RX buffer
            if slot.rx_space() > 0 {
                let mut rx_buf = [0u8; 512];
                let max = slot.rx_space().min(512);
                let recvd = libc::recv(
                    lsock.fd,
                    rx_buf.as_mut_ptr() as *mut libc::c_void,
                    max,
                    libc::MSG_DONTWAIT,
                );
                if recvd > 0 {
                    slot.rx_write(&rx_buf[..recvd as usize]);
                } else if recvd == 0 {
                    // Peer closed
                    slot.set_poll_flags(poll_flags::HUP);
                }
                // recvd < 0 with EAGAIN is normal for non-blocking
            }
        }
    }
}

// ============================================================================
// Linux FS Provider — real file I/O via libc
// ============================================================================

/// File handle table mapping Fluxor handles to libc fds.
const MAX_OPEN_FILES: usize = 16;

struct LinuxFileSlot {
    fd: i32,
    in_use: bool,
}

static mut LINUX_FILES: [LinuxFileSlot; MAX_OPEN_FILES] = {
    const EMPTY: LinuxFileSlot = LinuxFileSlot { fd: -1, in_use: false };
    [EMPTY; MAX_OPEN_FILES]
};

/// FS provider dispatch — handle values are direct slot indices (no FD tagging).
/// Same convention as the bare-metal sd module: OPEN returns slot index,
/// subsequent ops use that slot index as handle.
unsafe fn linux_fs_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use fluxor::abi::dev_fs;
    use fluxor::kernel::errno;

    match opcode {
        dev_fs::OPEN => {
            // arg = path bytes (not necessarily null-terminated)
            if arg.is_null() || arg_len == 0 {
                return errno::EINVAL;
            }
            // Find free slot
            let files = &mut *(&raw mut LINUX_FILES);
            let slot_idx = files.iter().position(|s| !s.in_use);
            let slot_idx = match slot_idx {
                Some(i) => i,
                None => return errno::ENOMEM,
            };

            // Build null-terminated path
            let path_bytes = core::slice::from_raw_parts(arg, arg_len);
            let mut path_buf = [0u8; 256];
            let plen = arg_len.min(255);
            path_buf[..plen].copy_from_slice(&path_bytes[..plen]);
            path_buf[plen] = 0;

            let fd_raw = libc::open(
                path_buf.as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_CREAT,
                0o644,
            );
            if fd_raw < 0 {
                // Try read-only
                let fd_raw = libc::open(
                    path_buf.as_ptr() as *const libc::c_char,
                    libc::O_RDONLY,
                    0,
                );
                if fd_raw < 0 {
                    return errno::ENODEV;
                }
                files[slot_idx].fd = fd_raw;
                files[slot_idx].in_use = true;
                return slot_idx as i32;
            }
            files[slot_idx].fd = fd_raw;
            files[slot_idx].in_use = true;
            slot_idx as i32
        }
        dev_fs::READ => {
            let slot_idx = handle as usize;
            let files = &*(&raw const LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
                return errno::EINVAL;
            }
            if arg.is_null() || arg_len == 0 {
                return errno::EINVAL;
            }
            let n = libc::read(files[slot_idx].fd, arg as *mut libc::c_void, arg_len);
            if n < 0 { errno::ERROR } else { n as i32 }
        }
        dev_fs::WRITE => {
            let slot_idx = handle as usize;
            let files = &*(&raw const LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
                return errno::EINVAL;
            }
            if arg.is_null() || arg_len == 0 {
                return errno::EINVAL;
            }
            let n = libc::write(files[slot_idx].fd, arg as *const libc::c_void, arg_len);
            if n < 0 { errno::ERROR } else { n as i32 }
        }
        dev_fs::SEEK => {
            let slot_idx = handle as usize;
            let files = &*(&raw const LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
                return errno::EINVAL;
            }
            if arg.is_null() || arg_len < 4 {
                return errno::EINVAL;
            }
            let offset = i32::from_le_bytes([*arg, *arg.add(1), *arg.add(2), *arg.add(3)]);
            let pos = libc::lseek(files[slot_idx].fd, offset as i64, libc::SEEK_SET);
            if pos < 0 { errno::ERROR } else { pos as i32 }
        }
        dev_fs::CLOSE => {
            let slot_idx = handle as usize;
            let files = &mut *(&raw mut LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
                return errno::EINVAL;
            }
            libc::close(files[slot_idx].fd);
            files[slot_idx].fd = -1;
            files[slot_idx].in_use = false;
            errno::OK
        }
        dev_fs::STAT => {
            let slot_idx = handle as usize;
            let files = &*(&raw const LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
                return errno::EINVAL;
            }
            let mut stat: libc::stat = core::mem::zeroed();
            let ret = libc::fstat(files[slot_idx].fd, &mut stat);
            if ret < 0 {
                return errno::ERROR;
            }
            // Return file size (truncated to i32)
            stat.st_size as i32
        }
        dev_fs::FSYNC => {
            let slot_idx = handle as usize;
            let files = &*(&raw const LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
                return errno::EINVAL;
            }
            let ret = libc::fsync(files[slot_idx].fd);
            if ret < 0 { errno::ERROR } else { errno::OK }
        }
        _ => errno::ENOSYS,
    }
}

// ============================================================================
// Module storage
// ============================================================================

const MAX_MODS: usize = config::MAX_MODULES;

// ============================================================================
// Entry point
// ============================================================================

fn main() {
    // Initialize boot instant for monotonic clock
    unsafe { BOOT_INSTANT = Some(Instant::now()); }

    // Set up logging via env_logger or simple stderr
    // For now, just use log macros which will go to the default sink
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).format_timestamp_millis().init();

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

    log::info!("[config] loaded {} bytes from {}", config_data.len(), args.config_path);
    log::info!("[modules] mapped {} bytes from {} at {:p}", modules_len, args.modules_path, modules_ptr);

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
    let tick_us = if cfg.header.tick_us > 0 { cfg.header.tick_us as u32 } else { 1000 };

    log::info!("[config] {} modules, {} edges, tick_us={}", n_modules, n_edges, tick_us);

    // Load module table from blob
    loader::reset_state_arena();
    let mut ldr = ModuleLoader::new();
    if ldr.init_from_blob(modules_ptr as *const u8).is_err() {
        eprintln!("error: failed to load module table");
        process::exit(1);
    }

    log::info!("[loader] module table loaded");

    // Create channels from graph edges
    let mut mod_in: [i32; MAX_MODS] = [-1; MAX_MODS];
    let mut mod_out: [i32; MAX_MODS] = [-1; MAX_MODS];
    let mut mod_ctrl: [i32; MAX_MODS] = [-1; MAX_MODS];

    for e in 0..n_edges {
        if let Some(ref edge) = cfg.graph_edges[e] {
            let from = edge.from_id as usize;
            let to = edge.to_id as usize;

            let ch = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);
            if ch >= 0 {
                if from < MAX_MODS && mod_out[from] < 0 {
                    mod_out[from] = ch;
                }
                if to < MAX_MODS {
                    if edge.to_port == 0 && mod_in[to] < 0 {
                        mod_in[to] = ch;
                    } else if edge.to_port == 1 && mod_ctrl[to] < 0 {
                        mod_ctrl[to] = ch;
                    }
                }
            }
        }
    }

    // Instantiate modules
    let syscall_table = syscalls::get_table_for_module_type(0);
    let mut modules: Vec<bool> = Vec::with_capacity(n_modules);

    for i in 0..n_modules {
        if let Some(ref entry) = cfg.modules[i] {
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
                    5 => 3, 3 => 1, 4 => 2, _ => 0,
                };
                scheduler::set_module_caps(i, cap_class, m.header.required_caps() as u32);

                let result = unsafe {
                    DynamicModule::start_new(
                        &m, syscall_table,
                        mod_in[i], mod_out[i], mod_ctrl[i],
                        entry.params_ptr, entry.params_len, "",
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
                log::warn!("[inst] module {} not found (hash={:#010x})", i, entry.name_hash);
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

        // Service socket slots — drain TX to libc, fill RX from libc, handle ops
        unsafe { linux_service_sockets(); }

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
