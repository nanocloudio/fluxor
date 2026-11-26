//! Starting a provider process.
//!
//! Every provider is forked by one long-lived spawner thread: a provider
//! asks the kernel for `SIGKILL` when its parent dies (`PR_SET_PDEATHSIG`),
//! and "parent" there means the thread that forked it, so a provider
//! forked by a short-lived thread would die with that thread.
//!
//! The child starts with the environment it is given and nothing else
//! besides [`LANE_ENV`], its stdin and stdout on `/dev/null`, its stderr the
//! runtime's, in a process group of its own, and holding exactly one
//! inherited descriptor beyond stdio: the lane's control socket, at
//! descriptor 3, which [`LANE_ENV`] names. Rings travel over that socket
//! later (`SCM_RIGHTS`); nothing else is inherited, whatever the runtime has
//! open. It holds the capabilities its [`Privilege`] names and no others
//! ([`crate::privilege`]).
//!
//! The binary is opened before the fork, with the privileges that found it,
//! and executed by that descriptor once the child has given them up: a
//! runtime running as root keeps no `CAP_DAC_READ_SEARCH` across the drop,
//! so the path itself may no longer resolve for the child (a provider
//! beside a runtime under a `0700` home).

use std::ffi::{CString, OsString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};

use crate::privilege::{self, Privilege};

/// The descriptor a provider finds its control socket at.
pub const LANE_FD: RawFd = 3;

/// The environment variable that tells a provider it was started on a lane:
/// its value is [`LANE_FD`]. A descriptor 3 that happens to be open (a
/// caller's `flock` lock, a shell redirection) is not a lane.
pub const LANE_ENV: &str = "FLUXOR_LANE_FD";

/// One process to start.
pub struct Launch {
    pub binary: PathBuf,
    /// The SHA-256 the binary must have: it is hashed through the
    /// descriptor it is then executed by, so what runs is what was checked.
    pub pin: [u8; 32],
    /// The provider's own parameter string, its one argument.
    pub args: String,
    /// The whole environment the provider starts with.
    pub env: Vec<(OsString, OsString)>,
    /// The capabilities it keeps.
    pub privilege: Privilege,
}

struct Job {
    launch: Launch,
    sock: OwnedFd,
    reply: mpsc::Sender<std::io::Result<Child>>,
}

static SPAWNER: OnceLock<Mutex<mpsc::Sender<Job>>> = OnceLock::new();

fn spawner() -> &'static Mutex<mpsc::Sender<Job>> {
    SPAWNER.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name("lane-spawner".into())
            .spawn(move || {
                for job in rx {
                    let _ = job.reply.send(start(job.launch, &job.sock));
                }
            })
            .expect("the lane spawner thread starts");
        Mutex::new(tx)
    })
}

/// Start `launch` with `sock` (the provider's end of the control socket) as
/// its descriptor 3, from the spawner thread.
pub fn spawn(launch: Launch, sock: OwnedFd) -> std::io::Result<Child> {
    let (reply, rx) = mpsc::channel();
    {
        let tx = spawner()
            .lock()
            .map_err(|_| std::io::Error::from_raw_os_error(libc::EIO))?;
        tx.send(Job {
            launch,
            sock,
            reply,
        })
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EIO))?;
    }
    rx.recv()
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EIO))?
}

fn start(launch: Launch, sock: &OwnedFd) -> std::io::Result<Child> {
    let binary = open_binary(&launch.binary)?;
    if digest_of(&binary)? != launch.pin {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the provider binary is not the one the node image pins",
        ));
    }
    start_opened(launch, &binary, sock)
}

/// The SHA-256 of the file `fd` opens, read through `fd` itself.
pub(crate) fn digest_of(fd: &OwnedFd) -> std::io::Result<[u8; 32]> {
    use std::os::unix::fs::FileExt;
    let file = std::fs::File::from(fd.try_clone()?);
    let mut h = fluxor_sdk::crypto::sha256::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut at = 0u64;
    loop {
        let n = file.read_at(&mut buf, at)?;
        if n == 0 {
            return Ok(h.finalize());
        }
        h.update(&buf[..n]);
        at += n as u64;
    }
}

/// Open `path` to be read and executed by descriptor, resolved with the
/// privileges this process holds now.
pub(crate) fn open_binary(path: &Path) -> std::io::Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: a NUL-terminated path, live for the call.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened and is owned by nothing else.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    if fd.as_raw_fd() > LANE_FD {
        return Ok(fd);
    }
    // Above the lane's descriptor, which the child places over whatever
    // holds it.
    // SAFETY: integer arguments only.
    let high = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, LANE_FD + 1) };
    if high < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `high` was just made and is owned by nothing else.
    Ok(unsafe { OwnedFd::from_raw_fd(high) })
}

/// What the child executes, built before the fork so the child allocates
/// nothing: the argument and environment vectors and the pointer arrays
/// `execveat` reads.
struct Exec {
    _argv: Vec<CString>,
    _envp: Vec<CString>,
    argv_ptrs: Vec<*const libc::c_char>,
    envp_ptrs: Vec<*const libc::c_char>,
}

// SAFETY: the pointers address the `CString`s the same value owns, which
// are never changed after it is built; only the forked child reads them.
unsafe impl Send for Exec {}
// SAFETY: as above.
unsafe impl Sync for Exec {}

impl Exec {
    fn new(launch: &Launch) -> std::io::Result<Exec> {
        let cstr =
            |b: &[u8]| CString::new(b).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL));
        let argv = vec![
            cstr(launch.binary.as_os_str().as_bytes())?,
            cstr(launch.args.as_bytes())?,
        ];
        let mut envp = Vec::with_capacity(launch.env.len() + 1);
        for (k, v) in &launch.env {
            if k.as_bytes() == LANE_ENV.as_bytes() {
                continue;
            }
            let mut kv = k.as_bytes().to_vec();
            kv.push(b'=');
            kv.extend_from_slice(v.as_bytes());
            envp.push(cstr(&kv)?);
        }
        envp.push(cstr(format!("{LANE_ENV}={LANE_FD}").as_bytes())?);
        let ptrs = |v: &[CString]| {
            v.iter()
                .map(|c| c.as_ptr())
                .chain(std::iter::once(core::ptr::null()))
                .collect::<Vec<_>>()
        };
        Ok(Exec {
            argv_ptrs: ptrs(&argv),
            envp_ptrs: ptrs(&envp),
            _argv: argv,
            _envp: envp,
        })
    }
}

/// Start `launch` from `binary`, opened by [`open_binary`], with `sock` as
/// its descriptor 3.
pub(crate) fn start_opened(
    launch: Launch,
    binary: &OwnedFd,
    sock: &OwnedFd,
) -> std::io::Result<Child> {
    let exec = Exec::new(&launch)?;
    let mut cmd = Command::new(&launch.binary);
    cmd.arg(&launch.args)
        .env_clear()
        .envs(launch.env.iter().map(|(k, v)| (k, v)))
        .env(LANE_ENV, LANE_FD.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .process_group(0);
    let sock_fd = sock.as_raw_fd();
    let bin_fd = binary.as_raw_fd();
    let grant = launch.privilege;
    // SAFETY: getpid takes no arguments.
    let parent = unsafe { libc::getpid() };
    // SAFETY: the hook runs between fork and exec in the child and calls
    // only async-signal-safe system calls; it allocates nothing.
    unsafe {
        cmd.pre_exec(move || {
            // The whole value, never its pointer fields alone.
            let exec = &exec;
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // The parent may have gone between fork and prctl.
            if libc::getppid() != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            sweep_inherited()?;
            privilege::apply_in_child(grant)?;
            if sock_fd == LANE_FD {
                if libc::fcntl(LANE_FD, libc::F_SETFD, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::dup2(sock_fd, LANE_FD) != LANE_FD {
                return Err(std::io::Error::last_os_error());
            }
            // By the descriptor opened before the fork: the path is not
            // resolved again under the dropped privileges. The descriptor is
            // close-on-exec, so the provider does not inherit it.
            libc::syscall(
                libc::SYS_execveat,
                bin_fd,
                c"".as_ptr(),
                exec.argv_ptrs.as_ptr(),
                exec.envp_ptrs.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
            Err(std::io::Error::last_os_error())
        });
    }
    cmd.spawn()
}

/// Mark every descriptor from 3 up close-on-exec, so the program starts
/// with stdio and the one descriptor placed after this. Async-signal-safe.
fn sweep_inherited() -> std::io::Result<()> {
    // SAFETY: integer arguments only.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3 as libc::c_uint,
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
    // SAFETY: `lim` is writable for the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let top = lim.rlim_cur.min(libc::c_int::MAX as libc::rlim_t) as libc::c_int;
    for fd in 3..top {
        // SAFETY: F_SETFD on any integer is defined; an unused one is EBADF.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A fresh directory holding a copy of `tool` (an ELF from the host).
    fn copy_of(tool: &str, name: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("fxspawn-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = ["/usr/bin", "/bin"]
            .iter()
            .map(|d| Path::new(d).join(tool))
            .find(|p| p.is_file())
            .unwrap_or_else(|| panic!("the host has no `{tool}`"));
        let bin = dir.join(tool);
        std::fs::copy(src, &bin).unwrap();
        (dir, bin)
    }

    fn lane_end() -> OwnedFd {
        let mut sv = [0; 2];
        // SAFETY: `sv` is writable for two descriptors.
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);
        // SAFETY: both were just made; the other end closes with the test.
        unsafe {
            drop(OwnedFd::from_raw_fd(sv[1]));
            OwnedFd::from_raw_fd(sv[0])
        }
    }

    fn launch(binary: &Path, args: &str, env: Vec<(OsString, OsString)>) -> Launch {
        Launch {
            binary: binary.to_path_buf(),
            pin: [0; 32],
            args: args.to_string(),
            env,
            privilege: Privilege::NONE,
        }
    }

    /// The binary is executed by the descriptor opened with the privileges
    /// that found it: a directory the child can no longer search does not
    /// stop it. (Run as root the directory stays searchable, and this shows
    /// only that the descriptor path starts the program.)
    #[test]
    fn a_provider_starts_from_a_directory_it_can_no_longer_search() {
        let (dir, bin) = copy_of("true", "unsearchable");
        let fd = open_binary(&bin).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        let started = start_opened(launch(&bin, "", Vec::new()), &fd, &lane_end());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let status = started.expect("the provider starts").wait().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(status.success(), "{status}");
    }

    /// The child is told its lane in [`LANE_ENV`], and only as the spawner
    /// states it: a value the given environment carries is replaced.
    #[test]
    fn the_child_is_told_its_lane() {
        let stale = vec![
            (OsString::from("KEEP"), OsString::from("1")),
            (OsString::from(LANE_ENV), OsString::from("9")),
        ];
        let exec = Exec::new(&launch(Path::new("/x"), "", stale)).unwrap();
        let env: Vec<&[u8]> = exec._envp.iter().map(|c| c.as_bytes()).collect();
        assert_eq!(env, vec![&b"KEEP=1"[..], b"FLUXOR_LANE_FD=3"]);
        // `printenv NAME` exits 0 only when NAME is set, and the child was
        // given an empty environment.
        let (dir, bin) = copy_of("printenv", "told");
        let fd = open_binary(&bin).unwrap();
        let status = start_opened(launch(&bin, LANE_ENV, Vec::new()), &fd, &lane_end())
            .expect("starts")
            .wait()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(status.success(), "{status}");
    }
}
