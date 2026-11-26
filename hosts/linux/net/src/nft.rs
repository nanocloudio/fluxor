//! The rule tool, `nft`, as this provider runs it: the one place it is
//! started. Every change is a script on its standard input (`nft -f -`),
//! so whatever a script holds is applied as one transaction or not at all.
//!
//! Exec discipline (code, not a filter): this is the only program the
//! provider executes, by name from the provider's search path, in the
//! host's network domain, holding stdio and nothing else of the
//! provider's descriptors.

use std::io::Write as _;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};

use fluxor_abi::errno;

/// Whether the tool works: 0 not yet probed, 1 works, 2 absent or refused.
static WORKS: AtomicU8 = AtomicU8::new(0);

/// Mark every descriptor from 3 up close-on-exec. Async-signal-safe: one
/// system call, no allocation, run between fork and exec.
fn sweep() -> std::io::Result<()> {
    // SAFETY: close_range takes integer arguments only and touches no memory.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The tool, holding none of the provider's descriptors.
fn command() -> Command {
    let mut c = Command::new("nft");
    // SAFETY: the hook runs between fork and exec in the child and makes
    // one async-signal-safe system call.
    unsafe { c.pre_exec(sweep) };
    c
}

/// Whether `nft` is present and may change the host's rules: a listing goes
/// through the same netlink family a transaction does, and the kernel
/// refuses every message of it without `CAP_NET_ADMIN`. Probed once, and
/// again after a transaction failed ([`apply`]).
pub fn works() -> bool {
    match WORKS.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let ok = command()
                .args(["list", "tables", "ip"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if !ok {
                log::warn!("[nft] absent or not permitted: rule tables are not applied");
            }
            WORKS.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
            ok
        }
    }
}

/// Apply `script` as one transaction. `ENOSYS` when the tool cannot be run,
/// `EACCES` when it refused the script (logged with its reason, as `what`).
pub fn apply(script: &str, what: &str) -> Result<(), i32> {
    let child = command()
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            log::warn!("[nft] cannot run nft: {e}");
            WORKS.store(0, Ordering::Relaxed);
            return Err(errno::ENOSYS);
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(script.as_bytes());
    }
    match child.wait_with_output() {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            log::warn!(
                "[nft] refused {what}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            // Re-probe: the tool may have gone, or lost its permission.
            WORKS.store(0, Ordering::Relaxed);
            Err(errno::EACCES)
        }
        Err(e) => {
            log::warn!("[nft] {what}: {e}");
            Err(errno::ERROR)
        }
    }
}

/// The names of every `ip` table on the host. Empty when there is no tool
/// (no table was ever made); `Err` when the host refused the listing,
/// without the privilege too: a process that cannot list the tables cannot
/// say none is left.
pub fn tables() -> Result<Vec<String>, i32> {
    let out = match command()
        .args(["list", "tables", "ip"])
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(errno::ERROR),
    };
    if !out.status.success() {
        log::warn!(
            "[nft] cannot list tables: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        return Err(errno::EACCES);
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.trim().strip_prefix("table ip "))
        .map(|t| t.trim().to_string())
        .collect())
}

/// Delete every `ip` table whose name starts with `prefix`, in one
/// transaction. `Ok` when there was none.
pub fn delete_prefixed(prefix: &str, what: &str) -> Result<(), i32> {
    let mut script = String::new();
    for t in tables()?.iter().filter(|t| t.starts_with(prefix)) {
        script.push_str(&format!("delete table ip {t}\n"));
    }
    if script.is_empty() {
        return Ok(());
    }
    apply(&script, what)
}
