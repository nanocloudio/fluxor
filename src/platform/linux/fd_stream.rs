//! Blocking-tolerant whole writes and reads on a host fd: partial writes
//! resumed, EINTR retried, EAGAIN/EWOULDBLOCK waited out with poll(2), so a
//! non-blocking stdio pipe neither cuts output nor reads as end of input.
//! Shared by the cli_in/cli_out built-ins; host-tested by
//! tests/harness/tests/cli_fd_stream.rs.

/// Wait until `fd` is ready for `events`, or a bounded while has passed (the
/// caller simply tries again). Errors and hangups return too: the next
/// read/write reports them.
pub fn wait_fd(fd: i32, events: libc::c_short) {
    let mut p = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    // SAFETY: one valid pollfd on the stack.
    unsafe { libc::poll(&mut p, 1, 100) };
}

/// Write all of `buf` to `fd`. `false` when the fd refuses for good (the
/// reader has gone, or a real write error): nothing more can be delivered.
pub fn write_stream(fd: i32, buf: &[u8]) -> bool {
    let mut pos = 0usize;
    while pos < buf.len() {
        // SAFETY: pointer/length within `buf`.
        let w = unsafe { libc::write(fd, buf.as_ptr().add(pos).cast(), buf.len() - pos) };
        if w > 0 {
            pos += w as usize;
            continue;
        }
        if w == 0 {
            wait_fd(fd, libc::POLLOUT);
            continue;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EINTR) => {}
            Some(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK => wait_fd(fd, libc::POLLOUT),
            _ => return false,
        }
    }
    true
}

/// Read what `fd` has into `buf`. `None` at end of input or on a real error.
pub fn read_stream(fd: i32, buf: &mut [u8]) -> Option<usize> {
    loop {
        // SAFETY: pointer/length of `buf`.
        let r = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if r > 0 {
            return Some(r as usize);
        }
        if r == 0 {
            return None;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EINTR) => {}
            Some(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK => wait_fd(fd, libc::POLLIN),
            _ => return None,
        }
    }
}
