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
    const EMPTY: LinuxFileSlot = LinuxFileSlot {
        fd: -1,
        in_use: false,
    };
    [EMPTY; MAX_OPEN_FILES]
};

/// FS provider dispatch — handle values are direct slot indices (no FD tagging).
/// Same convention as the bare-metal sd module: OPEN returns slot index,
/// subsequent ops use that slot index as handle.
unsafe fn linux_fs_dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    use fluxor::abi::contracts::storage::fs as dev_fs;
    use fluxor::kernel::errno;

    match opcode {
        dev_fs::OPEN => {
            if arg.is_null() || arg_len == 0 {
                return errno::EINVAL;
            }
            let files = &mut *(&raw mut LINUX_FILES);
            let slot_idx = files.iter().position(|s| !s.in_use);
            let slot_idx = match slot_idx {
                Some(i) => i,
                None => return errno::ENOMEM,
            };

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
                let fd_raw =
                    libc::open(path_buf.as_ptr() as *const libc::c_char, libc::O_RDONLY, 0);
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
            if n < 0 {
                errno::ERROR
            } else {
                n as i32
            }
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
            if n < 0 {
                errno::ERROR
            } else {
                n as i32
            }
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
            if pos < 0 {
                errno::ERROR
            } else {
                pos as i32
            }
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
            if arg.is_null() || arg_len < 8 {
                return errno::EINVAL;
            }
            let mut stat: libc::stat = core::mem::zeroed();
            let ret = libc::fstat(files[slot_idx].fd, &mut stat);
            if ret < 0 {
                return errno::ERROR;
            }
            let size = (stat.st_size as u64).min(u32::MAX as u64) as u32;
            let mtime = stat.st_mtime as u32;
            let size_b = size.to_le_bytes();
            let mtime_b = mtime.to_le_bytes();
            *arg = size_b[0];
            *arg.add(1) = size_b[1];
            *arg.add(2) = size_b[2];
            *arg.add(3) = size_b[3];
            *arg.add(4) = mtime_b[0];
            *arg.add(5) = mtime_b[1];
            *arg.add(6) = mtime_b[2];
            *arg.add(7) = mtime_b[3];
            errno::OK
        }
        dev_fs::FSYNC => {
            let slot_idx = handle as usize;
            let files = &*(&raw const LINUX_FILES);
            if slot_idx >= MAX_OPEN_FILES || !files[slot_idx].in_use {
                return errno::EINVAL;
            }
            let ret = libc::fsync(files[slot_idx].fd);
            if ret < 0 {
                errno::ERROR
            } else {
                errno::OK
            }
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
const MSG_ACCEPTED: u8 = 0x01;
const MSG_DATA: u8 = 0x02;
const MSG_CLOSED: u8 = 0x03;
const MSG_BOUND: u8 = 0x04;
const MSG_CONNECTED: u8 = 0x05;
const MSG_ERROR: u8 = 0x06;

// Net protocol command types (upstream: consumer → linux_net)
const CMD_BIND: u8 = 0x10;
const CMD_SEND: u8 = 0x11;
const CMD_CLOSE: u8 = 0x12;
const CMD_CONNECT: u8 = 0x13;

const LINUX_NET_MAX_CONNS: usize = 24;

#[derive(Clone, Copy)]
#[allow(dead_code)]
struct LinuxNetConn {
    fd: i32,
    conn_type: u8,
    state: u8,
}

impl LinuxNetConn {
    const EMPTY: Self = Self {
        fd: -1,
        conn_type: 0,
        state: 0,
    };
}

/// linux_net keeps per-instance state in a `Box<LinuxNetState>` like
/// every other host built-in. Two `linux_net` modules in one graph
/// would each get their own connection table and channel handles —
/// but they would still race for OS-level listen ports and fds. That's
/// a config-time concern (don't bind two listeners on port 9000), not
/// a state-aliasing one. Per-instance ownership matches the rest of
/// the host built-in family and makes the dispatch path uniform.
struct LinuxNetState {
    net_in: i32,
    net_out: i32,
    conns: [LinuxNetConn; LINUX_NET_MAX_CONNS],
    cmd_buf: [u8; 2048],
    msg_buf: [u8; 2048],
    recv_buf: [u8; 1500],
}

impl LinuxNetState {
    fn new(net_in: i32, net_out: i32) -> Self {
        Self {
            net_in,
            net_out,
            conns: [LinuxNetConn::EMPTY; LINUX_NET_MAX_CONNS],
            cmd_buf: [0u8; 2048],
            msg_buf: [0u8; 2048],
            recv_buf: [0u8; 1500],
        }
    }
}

unsafe fn set_nonblocking(fd: i32) {
    let flags = libc::fcntl(fd, libc::F_GETFL);
    if flags >= 0 {
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

fn linux_net_alloc_conn(st: &LinuxNetState) -> i32 {
    for i in 0..LINUX_NET_MAX_CONNS {
        if st.conns[i].state == 0 {
            return i as i32;
        }
    }
    -1
}

unsafe fn linux_net_send_msg(st: &LinuxNetState, data: &[u8]) {
    if st.net_out < 0 || data.is_empty() {
        return;
    }
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

unsafe fn linux_net_cmd_bind(st: &mut LinuxNetState, port: u16) {
    let slot = linux_net_alloc_conn(st);
    if slot < 0 {
        log::error!("[linux_net] no free slots for listener");
        return;
    }

    let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    if fd < 0 {
        log::error!("[linux_net] socket() failed");
        return;
    }

    let opt: i32 = 1;
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_REUSEADDR,
        &opt as *const i32 as *const libc::c_void,
        4,
    );

    let mut addr: libc::sockaddr_in = core::mem::zeroed();
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = 0;

    if libc::bind(
        fd,
        &addr as *const libc::sockaddr_in as *const libc::sockaddr,
        core::mem::size_of::<libc::sockaddr_in>() as u32,
    ) < 0
    {
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
    st.conns[idx] = LinuxNetConn {
        fd,
        conn_type: 1,
        state: 3,
    };
    log::info!("[linux_net] listening on port {} (slot {})", port, idx);

    let msg = [MSG_BOUND];
    linux_net_send_msg(st, &msg);
}

unsafe fn linux_net_cmd_connect(st: &mut LinuxNetState, sock_type: u8, ip: u32, port: u16) {
    let slot = linux_net_alloc_conn(st);
    if slot < 0 {
        log::error!("[linux_net] no free connection slots");
        return;
    }
    let idx = slot as usize;

    let libc_type = if sock_type == 2 {
        libc::SOCK_DGRAM
    } else {
        libc::SOCK_STREAM
    };
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

    let ret = libc::connect(
        fd,
        &addr as *const libc::sockaddr_in as *const libc::sockaddr,
        core::mem::size_of::<libc::sockaddr_in>() as u32,
    );

    if ret < 0 {
        let errno = *libc::__errno_location();
        if errno != libc::EINPROGRESS {
            log::error!("[linux_net] connect() failed errno={}", errno);
            libc::close(fd);
            let msg = [MSG_ERROR, idx as u8, errno as u8];
            linux_net_send_msg(st, &msg);
            return;
        }
        st.conns[idx] = LinuxNetConn {
            fd,
            conn_type: sock_type,
            state: 1,
        };
    } else {
        st.conns[idx] = LinuxNetConn {
            fd,
            conn_type: sock_type,
            state: 2,
        };
        let msg = [MSG_CONNECTED, idx as u8];
        linux_net_send_msg(st, &msg);
    }
}

unsafe fn linux_net_cmd_send(st: &LinuxNetState, conn_id: u8, data: &[u8]) {
    let idx = conn_id as usize;
    if idx >= LINUX_NET_MAX_CONNS || st.conns[idx].state < 2 {
        return;
    }
    let fd = st.conns[idx].fd;
    if fd < 0 {
        return;
    }
    libc::send(
        fd,
        data.as_ptr() as *const libc::c_void,
        data.len(),
        libc::MSG_NOSIGNAL,
    );
}

unsafe fn linux_net_cmd_close(st: &mut LinuxNetState, conn_id: u8) {
    let idx = conn_id as usize;
    if idx >= LINUX_NET_MAX_CONNS || st.conns[idx].state == 0 {
        return;
    }
    if st.conns[idx].fd >= 0 {
        libc::close(st.conns[idx].fd);
    }
    st.conns[idx] = LinuxNetConn::EMPTY;
    let msg = [MSG_CLOSED, conn_id];
    linux_net_send_msg(st, &msg);
}

unsafe fn linux_net_poll_accept(st: &mut LinuxNetState) -> bool {
    let mut had_work = false;

    for li in 0..LINUX_NET_MAX_CONNS {
        if st.conns[li].state != 3 || st.conns[li].fd < 0 {
            continue;
        }

        let mut addr: libc::sockaddr_in = core::mem::zeroed();
        let mut addr_len: libc::socklen_t = core::mem::size_of::<libc::sockaddr_in>() as u32;

        let client_fd = libc::accept4(
            st.conns[li].fd,
            &mut addr as *mut libc::sockaddr_in as *mut libc::sockaddr,
            &mut addr_len,
            libc::SOCK_NONBLOCK,
        );
        if client_fd < 0 {
            continue;
        }

        let slot = linux_net_alloc_conn(st);
        if slot < 0 {
            libc::close(client_fd);
            continue;
        }
        let idx = slot as usize;
        st.conns[idx] = LinuxNetConn {
            fd: client_fd,
            conn_type: 1,
            state: 2,
        };

        let msg = [MSG_ACCEPTED, idx as u8];
        linux_net_send_msg(st, &msg);
        log::info!("[linux_net] accepted conn_id={}", idx);
        had_work = true;
    }
    had_work
}

unsafe fn linux_net_poll_recv(st: &mut LinuxNetState) -> bool {
    let mut had_work = false;

    for i in 0..LINUX_NET_MAX_CONNS {
        if st.conns[i].state != 2 && st.conns[i].state != 1 {
            continue;
        }
        if st.conns[i].fd < 0 {
            continue;
        }

        if st.conns[i].state != 2 {
            if st.conns[i].state == 1 {
                let mut pfd = libc::pollfd {
                    fd: st.conns[i].fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                if libc::poll(&mut pfd, 1, 0) > 0 && pfd.revents & libc::POLLOUT != 0 {
                    let mut err: i32 = 0;
                    let mut errlen: libc::socklen_t = 4;
                    libc::getsockopt(
                        st.conns[i].fd,
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        &mut err as *mut i32 as *mut libc::c_void,
                        &mut errlen,
                    );
                    if err == 0 {
                        st.conns[i].state = 2;
                        let msg = [MSG_CONNECTED, i as u8];
                        linux_net_send_msg(st, &msg);
                        had_work = true;
                    } else {
                        libc::close(st.conns[i].fd);
                        st.conns[i] = LinuxNetConn::EMPTY;
                        let msg = [MSG_ERROR, i as u8, err as u8];
                        linux_net_send_msg(st, &msg);
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
            let payload_len = 1 + n as usize;
            let frame_len = 3 + payload_len;
            if frame_len <= st.msg_buf.len() {
                st.msg_buf[0] = MSG_DATA;
                st.msg_buf[1] = payload_len as u8;
                st.msg_buf[2] = (payload_len >> 8) as u8;
                st.msg_buf[3] = i as u8;
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
            libc::close(st.conns[i].fd);
            st.conns[i] = LinuxNetConn::EMPTY;
            let msg = [MSG_CLOSED, i as u8];
            linux_net_send_msg(st, &msg);
            had_work = true;
        }
    }
    had_work
}

fn linux_net_step(state: *mut u8) -> i32 {
    unsafe {
        let st = instance_state::<LinuxNetState>(state);

        let mut had_work = false;

        if st.net_in >= 0 {
            loop {
                let mut hdr = [0u8; 3];
                let n = channel::channel_read(st.net_in, hdr.as_mut_ptr(), 3);
                if n < 3 {
                    break;
                }
                let msg_type = hdr[0];
                let payload_len = (hdr[1] as u16 | ((hdr[2] as u16) << 8)) as usize;
                if payload_len > 0 && payload_len <= st.cmd_buf.len() {
                    let n2 = channel::channel_read(st.net_in, st.cmd_buf.as_mut_ptr(), payload_len);
                    if n2 < payload_len as i32 {
                        break;
                    }
                }

                match msg_type {
                    CMD_BIND if payload_len >= 2 => {
                        let port = u16::from_le_bytes([st.cmd_buf[0], st.cmd_buf[1]]);
                        linux_net_cmd_bind(st, port);
                        had_work = true;
                    }
                    CMD_CONNECT if payload_len >= 7 => {
                        let sock_type = st.cmd_buf[0];
                        let ip = u32::from_le_bytes([
                            st.cmd_buf[1],
                            st.cmd_buf[2],
                            st.cmd_buf[3],
                            st.cmd_buf[4],
                        ]);
                        let port = u16::from_le_bytes([st.cmd_buf[5], st.cmd_buf[6]]);
                        linux_net_cmd_connect(st, sock_type, ip, port);
                        had_work = true;
                    }
                    CMD_SEND if payload_len >= 2 => {
                        let conn_id = st.cmd_buf[0];
                        let data_len = payload_len - 1;
                        let data_slice =
                            core::slice::from_raw_parts(st.cmd_buf.as_ptr().add(1), data_len);
                        linux_net_cmd_send(st, conn_id, data_slice);
                        had_work = true;
                    }
                    CMD_CLOSE if payload_len >= 1 => {
                        let conn_id = st.cmd_buf[0];
                        linux_net_cmd_close(st, conn_id);
                        had_work = true;
                    }
                    _ => {
                        log::warn!(
                            "[linux_net] unknown cmd 0x{:02x} pl={}",
                            msg_type,
                            payload_len
                        );
                    }
                }
            }
        }

        if linux_net_poll_accept(st) {
            had_work = true;
        }
        if linux_net_poll_recv(st) {
            had_work = true;
        }

        if had_work {
            2
        } else {
            0
        }
    }
}
