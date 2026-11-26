// Owner facts writer — where the kernel's owner facts land on a Linux node.
//
// In node-agent mode (FLUXOR_PLAN set) the runtime writes the kernel's
// `workload::OWNERS` answer verbatim beside the plan it consumes
// (`abi::platform::linux::owner_facts` has the file's name and head),
// atomically replaced whenever the answer changes. Nothing here derives a
// phase, counts a restart or keeps a record past the kernel's: rendering,
// history and retention are the node agent's.

use crate::abi::platform::linux::owner_facts as file;

/// Writes the owner facts file next to the published plan. Created only in
/// node-agent mode; `tick()` is cheap when nothing changed (byte compare).
pub struct OwnerFactsWriter {
    path: std::path::PathBuf,
    /// This process's head: magic, pid and start ticks.
    head: [u8; file::HEAD_LEN],
    /// The last answer written; rewrite only on change.
    last: Vec<u8>,
    buf: Vec<u8>,
}

impl OwnerFactsWriter {
    /// `plan_path` is the FLUXOR_PLAN file; the facts file lives beside it.
    pub fn new(plan_path: &std::path::Path) -> Self {
        let dir = plan_path.parent().unwrap_or(std::path::Path::new("."));
        let pid = std::process::id();
        let mut head = [0u8; file::HEAD_LEN];
        head[..4].copy_from_slice(&file::MAGIC);
        head[file::PID..file::PID + 4].copy_from_slice(&pid.to_le_bytes());
        head[file::PID_START_TICKS..file::PID_START_TICKS + 8]
            .copy_from_slice(&proc_start_ticks(pid).unwrap_or(0).to_le_bytes());
        OwnerFactsWriter {
            path: dir.join(file::FILE_NAME),
            head,
            last: Vec::new(),
            buf: Vec::new(),
        }
    }

    /// Read the kernel's owner facts and atomically replace the file when
    /// they changed.
    pub fn tick(&mut self) {
        use crate::abi::contracts::workload::owners;
        let slots = crate::kernel::exec::scheduler::owners().slot_count();
        let need = owners::HEADER_LEN + slots * 2 * owners::RECORD_LEN;
        if self.buf.len() < need {
            self.buf.resize(need, 0);
        }
        let n = crate::kernel::workload::owner_plan::owners_answer(&mut self.buf);
        let Ok(n) = usize::try_from(n) else {
            log::warn!("[owner] owner facts read failed: {n}");
            return;
        };
        if self.last == self.buf[..n] {
            return;
        }
        let mut body = Vec::with_capacity(file::HEAD_LEN + n);
        body.extend_from_slice(&self.head);
        body.extend_from_slice(&self.buf[..n]);
        match write_atomic(&self.path, &body) {
            Ok(()) => {
                self.last.clear();
                self.last.extend_from_slice(&self.buf[..n]);
            }
            Err(e) => {
                // Non-fatal: the runtime keeps stepping when the volume
                // misbehaves; the next change retries.
                log::warn!(
                    "[owner] owner facts write to {} failed: {e}",
                    self.path.display()
                );
            }
        }
    }
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

/// Temp write + fsync + atomic rename + parent fsync: a reader never sees
/// the file half-written, and a reported write survives power loss.
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}
