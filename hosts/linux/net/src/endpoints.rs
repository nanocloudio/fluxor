//! The bound-endpoint report: which listeners and datagram endpoints the
//! socket engine holds, and for which owner, written for a reader outside
//! the runtime (`abi::platform::linux::bound_endpoints` has the layout).
//!
//! Written only when the runtime names the directory
//! (`bound_endpoints::DIR_ENV`: node-agent mode) and the provider serves
//! sockets; atomically replaced whenever the set changes. The head names
//! this process, so a file a provider that is gone wrote reads as nothing.
//! The file is not synced: it says what a live process holds, and after a
//! crash its writer is gone either way.

use std::path::PathBuf;

use fluxor_abi::platform::linux::bound_endpoints as file;

use crate::sockets::{Owner, Sockets};

/// The report's writer.
pub struct Report {
    path: PathBuf,
    pid: u32,
    pid_start_ticks: u64,
    /// The set last written; `None` before the first write.
    last: Option<Vec<(Owner, u8, u16)>>,
    now: Vec<(Owner, u8, u16)>,
}

impl Report {
    /// The writer for the directory the runtime named, or `None` when it
    /// named none.
    pub fn from_env() -> Option<Report> {
        let dir = std::env::var_os(file::DIR_ENV)?;
        if dir.is_empty() {
            return None;
        }
        let pid = std::process::id();
        Some(Report {
            path: PathBuf::from(dir).join(file::FILE_NAME),
            pid,
            pid_start_ticks: proc_start_ticks(pid).unwrap_or(0),
            last: None,
            now: Vec::new(),
        })
    }

    /// Read the engine's endpoints and replace the file when they changed.
    pub fn tick(&mut self, sockets: &mut Sockets) {
        sockets.bound_endpoints(&mut self.now);
        if self.last.as_ref() == Some(&self.now) {
            return;
        }
        let body = encode(self.pid, self.pid_start_ticks, &self.now);
        // A failed write is retried at the next change, not every pass:
        // nothing the sockets do waits on the report.
        if let Err(e) = write_atomic(&self.path, &body) {
            log::warn!(
                "[linux_net] bound endpoints not written to {}: {e}",
                self.path.display()
            );
        }
        self.last = Some(self.now.clone());
    }
}

/// The file's bytes for `endpoints`, written by process `pid`. A set past
/// what the head counts is cut at `u16::MAX` records.
pub fn encode(pid: u32, pid_start_ticks: u64, endpoints: &[(Owner, u8, u16)]) -> Vec<u8> {
    let n = endpoints.len().min(usize::from(u16::MAX));
    let mut body = vec![0u8; file::HEAD_LEN + n * file::RECORD_LEN];
    file::write_head(&mut body, pid, pid_start_ticks, n as u16);
    for (k, &(owner, protocol, port)) in endpoints[..n].iter().enumerate() {
        let at = file::HEAD_LEN + k * file::RECORD_LEN;
        file::Record {
            owner_slot: owner.slot,
            owner_generation: owner.generation,
            protocol,
            port,
        }
        .write(&mut body[at..]);
    }
    body
}

/// Start time of `pid` in clock ticks since boot — field 22 of
/// `/proc/<pid>/stat`, parsed from after the LAST `)` so a comm containing
/// spaces or parens cannot shift the fields.
fn proc_start_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = &stat[stat.rfind(')')? + 1..];
    // `state` is field 3; `starttime` is field 22.
    tail.split_whitespace().nth(19)?.parse().ok()
}

/// Temp write and rename: a reader never sees the file half-written.
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}
