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
// linux_net built-in module — channel-based net_proto framing via libc sockets
// ============================================================================

/// FNV-1a hash of "linux_net"
const LINUX_NET_HASH: u32 = 0xFBCC7DC9;

// Net protocol message types (downstream: linux_net → consumer)
const MSG_ACCEPTED:  u8 = 0x01;
const MSG_DATA:      u8 = 0x02;
const MSG_CLOSED:    u8 = 0x03;
const MSG_BOUND:     u8 = 0x04;
const MSG_CONNECTED: u8 = 0x05;
const MSG_ERROR:     u8 = 0x06;

// Net protocol command types (upstream: consumer → linux_net)
const CMD_BIND:    u8 = 0x10;
const CMD_SEND:    u8 = 0x11;
const CMD_CLOSE:   u8 = 0x12;
const CMD_CONNECT: u8 = 0x13;

const LINUX_NET_MAX_CONNS: usize = 24;

#[derive(Clone, Copy)]
#[allow(dead_code)]
struct LinuxNetConn {
    fd: i32,        // libc socket fd (-1 = unused)
    conn_type: u8,  // 1=stream(TCP), 2=dgram(UDP)
    state: u8,      // 0=unused, 1=connecting, 2=connected, 3=listening
}

impl LinuxNetConn {
    const EMPTY: Self = Self { fd: -1, conn_type: 0, state: 0 };
}

struct LinuxNetState {
    net_in: i32,        // channel handle for reading CMD frames
    net_out: i32,       // channel handle for writing MSG frames
    conns: [LinuxNetConn; LINUX_NET_MAX_CONNS],
    cmd_buf: [u8; 2048],  // incoming command frame buffer
    msg_buf: [u8; 2048],  // outgoing message frame assembly
    recv_buf: [u8; 1500], // socket recv scratch
    initialized: bool,
}

static mut LINUX_NET: LinuxNetState = LinuxNetState {
    net_in: -1,
    net_out: -1,
    conns: [LinuxNetConn::EMPTY; LINUX_NET_MAX_CONNS],
    cmd_buf: [0u8; 2048],
    msg_buf: [0u8; 2048],
    recv_buf: [0u8; 1500],
    initialized: false,
};

/// Set a socket to non-blocking mode.
unsafe fn set_nonblocking(fd: i32) {
    let flags = libc::fcntl(fd, libc::F_GETFL);
    if flags >= 0 {
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

/// Find a free connection slot. Returns index or -1.
unsafe fn linux_net_alloc_conn() -> i32 {
    let st = &mut *(&raw mut LINUX_NET);
    for i in 0..LINUX_NET_MAX_CONNS {
        if st.conns[i].state == 0 {
            return i as i32;
        }
    }
    -1
}

/// Send a MSG frame on net_out.
/// Send a net_proto TLV frame: [msg_type] [len: u16 LE] [payload].
/// `msg_type` is the first byte of `data`, payload is `data[1..]`.
unsafe fn linux_net_send_msg(data: &[u8]) {
    let st = &*(&raw const LINUX_NET);
    if st.net_out < 0 || data.is_empty() { return; }
    let msg_type = data[0];
    let payload = &data[1..];
    let payload_len = payload.len() as u16;
    let mut frame = [0u8; 512];
    frame[0] = msg_type;
    frame[1] = payload_len as u8;
    frame[2] = (payload_len >> 8) as u8;
    if !payload.is_empty() {
        frame[3..3 + payload.len()].copy_from_slice(payload);
    }
    let total = 3 + payload.len();
    channel::channel_write(st.net_out, frame.as_ptr(), total);
}

/// Handle CMD_BIND: create TCP listening socket on given port.
/// Allocates a connection slot with state=3 (listening).
/// Supports multiple concurrent listeners on different ports.
unsafe fn linux_net_cmd_bind(port: u16) {
    let st = &mut *(&raw mut LINUX_NET);

    let slot = linux_net_alloc_conn();
    if slot < 0 {
        log::error!("[linux_net] no free slots for listener");
        return;
    }

    let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    if fd < 0 {
        log::error!("[linux_net] socket() failed");
        return;
    }

    // SO_REUSEADDR
    let opt: i32 = 1;
    libc::setsockopt(
        fd, libc::SOL_SOCKET, libc::SO_REUSEADDR,
        &opt as *const i32 as *const libc::c_void, 4,
    );

    let mut addr: libc::sockaddr_in = core::mem::zeroed();
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = 0; // INADDR_ANY

    if libc::bind(fd, &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                  core::mem::size_of::<libc::sockaddr_in>() as u32) < 0 {
        log::error!("[linux_net] bind() failed on port {}", port);
        libc::close(fd);
        return;
    }

    if libc::listen(fd, 8) < 0 {
        log::error!("[linux_net] listen() failed");
        libc::close(fd);
        return;
    }

    set_nonblocking(fd);
    let idx = slot as usize;
    st.conns[idx] = LinuxNetConn { fd, conn_type: 1, state: 3 };
    log::info!("[linux_net] listening on port {} (slot {})", port, idx);

    // Send MSG_BOUND
    let msg = [MSG_BOUND];
    linux_net_send_msg(&msg);
}

/// Handle CMD_CONNECT: create socket and connect to remote.
unsafe fn linux_net_cmd_connect(sock_type: u8, ip: u32, port: u16) {
    let st = &mut *(&raw mut LINUX_NET);
    let slot = linux_net_alloc_conn();
    if slot < 0 {
        log::error!("[linux_net] no free connection slots");
        return;
    }
    let idx = slot as usize;

    let libc_type = if sock_type == 2 { libc::SOCK_DGRAM } else { libc::SOCK_STREAM };
    let fd = libc::socket(libc::AF_INET, libc_type, 0);
    if fd < 0 {
        log::error!("[linux_net] socket() failed for connect");
        return;
    }

    set_nonblocking(fd);

    let mut addr: libc::sockaddr_in = core::mem::zeroed();
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = ip.to_be();

    let ret = libc::connect(fd, &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                            core::mem::size_of::<libc::sockaddr_in>() as u32);

    if ret < 0 {
        let errno = *libc::__errno_location();
        if errno != libc::EINPROGRESS {
            log::error!("[linux_net] connect() failed errno={}", errno);
            libc::close(fd);
            // Send MSG_ERROR
            let msg = [MSG_ERROR, idx as u8, errno as u8];
            linux_net_send_msg(&msg);
            return;
        }
        // EINPROGRESS: connection in progress (non-blocking)
        st.conns[idx] = LinuxNetConn { fd, conn_type: sock_type, state: 1 };
    } else {
        // Immediate connection (unlikely for TCP, normal for UDP)
        st.conns[idx] = LinuxNetConn { fd, conn_type: sock_type, state: 2 };
        let msg = [MSG_CONNECTED, idx as u8];
        linux_net_send_msg(&msg);
    }
}

/// Handle CMD_SEND: write data to a connection's socket.
unsafe fn linux_net_cmd_send(conn_id: u8, data: &[u8]) {
    let st = &*(&raw const LINUX_NET);
    let idx = conn_id as usize;
    if idx >= LINUX_NET_MAX_CONNS || st.conns[idx].state < 2 {
        return;
    }
    let fd = st.conns[idx].fd;
    if fd < 0 { return; }
    libc::send(fd, data.as_ptr() as *const libc::c_void, data.len(), libc::MSG_NOSIGNAL);
}

/// Handle CMD_CLOSE: close a connection.
unsafe fn linux_net_cmd_close(conn_id: u8) {
    let st = &mut *(&raw mut LINUX_NET);
    let idx = conn_id as usize;
    if idx >= LINUX_NET_MAX_CONNS || st.conns[idx].state == 0 {
        return;
    }
    if st.conns[idx].fd >= 0 {
        libc::close(st.conns[idx].fd);
    }
    st.conns[idx] = LinuxNetConn::EMPTY;
    let msg = [MSG_CLOSED, conn_id];
    linux_net_send_msg(&msg);
}

/// Poll all listening sockets (state=3) for new connections.
unsafe fn linux_net_poll_accept() -> bool {
    let st = &mut *(&raw mut LINUX_NET);
    let mut had_work = false;

    for li in 0..LINUX_NET_MAX_CONNS {
        if st.conns[li].state != 3 || st.conns[li].fd < 0 { continue; }

        let mut addr: libc::sockaddr_in = core::mem::zeroed();
        let mut addr_len: libc::socklen_t = core::mem::size_of::<libc::sockaddr_in>() as u32;

        let client_fd = libc::accept4(
            st.conns[li].fd,
            &mut addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut addr_len,
            libc::SOCK_NONBLOCK,
        );
        if client_fd < 0 { continue; }

        let slot = linux_net_alloc_conn();
        if slot < 0 {
            libc::close(client_fd);
            continue;
        }
        let idx = slot as usize;
        st.conns[idx] = LinuxNetConn { fd: client_fd, conn_type: 1, state: 2 };

        let msg = [MSG_ACCEPTED, idx as u8];
        linux_net_send_msg(&msg);
        log::info!("[linux_net] accepted conn_id={}", idx);
        had_work = true;
    }
    had_work
}

/// Poll all connected sockets for incoming data.
unsafe fn linux_net_poll_recv() -> bool {
    let st = &mut *(&raw mut LINUX_NET);
    let mut had_work = false;

    for i in 0..LINUX_NET_MAX_CONNS {
        if st.conns[i].state != 2 && st.conns[i].state != 1 {
            continue; // skip unused (0), listening (3) slots
        }
        if st.conns[i].fd < 0 { continue; }

        if st.conns[i].state != 2 {
            // Check connecting sockets (state=1) for completion
            if st.conns[i].state == 1 {
                let mut pfd = libc::pollfd {
                    fd: st.conns[i].fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                if libc::poll(&mut pfd, 1, 0) > 0 {
                    if pfd.revents & libc::POLLOUT != 0 {
                        // Connection completed
                        let mut err: i32 = 0;
                        let mut errlen: libc::socklen_t = 4;
                        libc::getsockopt(
                            st.conns[i].fd, libc::SOL_SOCKET, libc::SO_ERROR,
                            &mut err as *mut i32 as *mut libc::c_void, &mut errlen,
                        );
                        if err == 0 {
                            st.conns[i].state = 2;
                            let msg = [MSG_CONNECTED, i as u8];
                            linux_net_send_msg(&msg);
                            had_work = true;
                        } else {
                            libc::close(st.conns[i].fd);
                            st.conns[i] = LinuxNetConn::EMPTY;
                            let msg = [MSG_ERROR, i as u8, err as u8];
                            linux_net_send_msg(&msg);
                        }
                    }
                }
            }
            continue;
        }

        let n = libc::recv(
            st.conns[i].fd,
            st.recv_buf.as_mut_ptr() as *mut libc::c_void,
            st.recv_buf.len(),
            0,
        );
        if n > 0 {
            // Build MSG_DATA TLV frame: [MSG_DATA] [len: u16 LE] [conn_id] [data...]
            let payload_len = 1 + n as usize; // conn_id + data
            let frame_len = 3 + payload_len;
            if frame_len <= st.msg_buf.len() {
                st.msg_buf[0] = MSG_DATA;
                st.msg_buf[1] = payload_len as u8;
                st.msg_buf[2] = (payload_len >> 8) as u8;
                st.msg_buf[3] = i as u8; // conn_id
                core::ptr::copy_nonoverlapping(
                    st.recv_buf.as_ptr(),
                    st.msg_buf.as_mut_ptr().add(4),
                    n as usize,
                );
                if st.net_out >= 0 {
                    channel::channel_write(st.net_out, st.msg_buf.as_ptr(), frame_len);
                }
            }
            had_work = true;
        } else if n == 0 {
            // Connection closed by peer
            libc::close(st.conns[i].fd);
            st.conns[i] = LinuxNetConn::EMPTY;
            let msg = [MSG_CLOSED, i as u8];
            linux_net_send_msg(&msg);
            had_work = true;
        }
        // n < 0: EAGAIN/EWOULDBLOCK = no data, just continue
    }
    had_work
}

/// Step function for the linux_net built-in module.
///
/// The `state` pointer points at the BuiltInModule.state[64] buffer.
/// Bytes 0..3 = net_in channel handle (i32 LE)
/// Bytes 4..7 = net_out channel handle (i32 LE)
fn linux_net_step(state: *mut u8) -> i32 {
    unsafe {
        let st = &mut *(&raw mut LINUX_NET);

        // First call: read channel handles from BuiltIn state and store in static
        if !st.initialized {
            st.net_in = core::ptr::read(state as *const i32);
            st.net_out = core::ptr::read(state.add(4) as *const i32);
            st.initialized = true;
            log::info!("[linux_net] init net_in={} net_out={}", st.net_in, st.net_out);
        }

        let mut had_work = false;

        // Read CMD frames from net_in channel using two-step TLV reads.
        // Step 1: read 3-byte header [msg_type:u8][len:u16 LE]
        // Step 2: read exactly payload_len bytes
        // This prevents consuming multiple TLV frames in one read.
        if st.net_in >= 0 {
            loop {
                let mut hdr = [0u8; 3];
                let n = channel::channel_read(st.net_in, hdr.as_mut_ptr(), 3);
                if n < 3 { break; }
                let msg_type = hdr[0];
                let payload_len = (hdr[1] as u16 | ((hdr[2] as u16) << 8)) as usize;
                if payload_len > 0 && payload_len <= st.cmd_buf.len() {
                    let n2 = channel::channel_read(st.net_in, st.cmd_buf.as_mut_ptr(), payload_len);
                    if n2 < payload_len as i32 { break; }
                }

                // Payload is in cmd_buf[0..payload_len]
                match msg_type {
                    CMD_BIND if payload_len >= 2 => {
                        let port = u16::from_le_bytes([st.cmd_buf[0], st.cmd_buf[1]]);
                        linux_net_cmd_bind(port);
                        had_work = true;
                    }
                    CMD_CONNECT if payload_len >= 7 => {
                        let sock_type = st.cmd_buf[0];
                        let ip = u32::from_le_bytes([
                            st.cmd_buf[1], st.cmd_buf[2], st.cmd_buf[3], st.cmd_buf[4],
                        ]);
                        let port = u16::from_le_bytes([st.cmd_buf[5], st.cmd_buf[6]]);
                        linux_net_cmd_connect(sock_type, ip, port);
                        had_work = true;
                    }
                    CMD_SEND if payload_len >= 2 => {
                        // Payload: [conn_id: u8] [data...]
                        let conn_id = st.cmd_buf[0];
                        let data_len = payload_len - 1;
                        let data_slice = core::slice::from_raw_parts(
                            st.cmd_buf.as_ptr().add(1), data_len,
                        );
                        linux_net_cmd_send(conn_id, data_slice);
                        had_work = true;
                    }
                    CMD_CLOSE if payload_len >= 1 => {
                        let conn_id = st.cmd_buf[0];
                        linux_net_cmd_close(conn_id);
                        had_work = true;
                    }
                    _ => {
                        log::warn!("[linux_net] unknown cmd 0x{:02x} pl={}", msg_type, payload_len);
                    }
                }
            }
        }

        // Poll for incoming connections and data
        if linux_net_poll_accept() { had_work = true; }
        if linux_net_poll_recv() { had_work = true; }

        // Return Burst(2) when there's active work, Continue(0) otherwise
        if had_work { 2 } else { 0 }
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

    // Create channels from graph edges and register ports via set_module_port.
    // This supports multi-port modules (e.g. linux_net.net_out, ip.net_in).
    // Legacy: also track port-0 in/out/ctrl for DynamicModule::start_new().
    let mut mod_in: [i32; MAX_MODS] = [-1; MAX_MODS];
    let mut mod_out: [i32; MAX_MODS] = [-1; MAX_MODS];
    let mut mod_ctrl: [i32; MAX_MODS] = [-1; MAX_MODS];

    for e in 0..n_edges {
        if let Some(ref edge) = cfg.graph_edges[e] {
            let from = edge.from_id as usize;
            let to = edge.to_id as usize;

            let ch = channel::channel_open(channel::CHANNEL_TYPE_PIPE, core::ptr::null(), 0);
            if ch < 0 { continue; }

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
                log::info!("[inst] module {} = linux_net (built-in) net_in={} net_out={}", i, net_in_ch, net_out_ch);
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
