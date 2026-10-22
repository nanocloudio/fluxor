//! Descriptor hygiene for every process the runtime starts.
//!
//! A workload starts holding only what it was granted (`workload` contract,
//! 0x1A). Two rules realize that on Linux:
//!
//! 1. Every descriptor the runtime creates is close-on-exec from the call that
//!    creates it (`O_CLOEXEC`, `SOCK_CLOEXEC`, `EPOLL_CLOEXEC`, …). Setting it
//!    afterwards with `fcntl` leaves a window in which another thread's fork
//!    inherits the descriptor; `fluxor lint`'s Linux hygiene rule refuses a
//!    descriptor-creating call without the flag in `src/platform/linux/`.
//! 2. Every child the runtime spawns sweeps what it inherited anyway (a
//!    descriptor a library opened without the flag, one inherited from the
//!    runtime's own parent) before it executes: [`sweep_inherited`], installed
//!    on a std [`Command`] by [`sweep_on_exec`].
//!
//! The sweep MARKS every descriptor from 3 up close-on-exec rather than closing
//! it outright. The effect at exec is the same — the new program holds stdio
//! and nothing else — but std's own exec-failure report pipe, itself
//! close-on-exec, keeps working, so a program that cannot be executed still
//! fails `spawn` instead of looking like a child that exited 1.

use std::os::unix::process::CommandExt;
use std::process::Command;

/// The lowest descriptor a child keeps by number: everything below is stdio.
const FIRST_SWEPT: libc::c_uint = 3;

/// Mark every descriptor from 3 up close-on-exec in the calling process.
///
/// Async-signal-safe, so it may run between fork and exec: raw system calls
/// only, no allocation, no locks. `close_range` with `CLOSE_RANGE_CLOEXEC`
/// (Linux 5.11) does it in one call; an older kernel falls back to a loop of
/// `fcntl(F_SETFD)` up to the descriptor limit (`EBADF` on the unused numbers
/// is expected and ignored).
pub fn sweep_inherited() -> std::io::Result<()> {
    // SAFETY: close_range takes integer arguments only and touches no memory.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            FIRST_SWEPT,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, writable rlimit for the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Linux bounds RLIMIT_NOFILE by fs.nr_open, so the limit is finite; the
    // clamp only keeps the loop's type honest.
    let top = lim.rlim_cur.min(libc::c_int::MAX as libc::rlim_t) as libc::c_int;
    let mut fd = FIRST_SWEPT as libc::c_int;
    while fd < top {
        // SAFETY: F_SETFD on any integer is defined; an unused one is EBADF.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        fd += 1;
    }
    Ok(())
}

/// Install [`sweep_inherited`] on `command`, so the program it runs starts
/// with stdio and nothing else of the runtime's.
pub fn sweep_on_exec(command: &mut Command) -> &mut Command {
    // SAFETY: the hook runs between fork and exec in the child; it calls only
    // async-signal-safe system calls and allocates nothing.
    unsafe { command.pre_exec(sweep_inherited) }
}
