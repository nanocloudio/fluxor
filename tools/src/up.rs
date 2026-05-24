//! Multi-replica deployment orchestrator.
//!
//! `fluxor up <template> --replicas N` is the developer-facing
//! shortcut for "render this template N times and spawn N
//! `fluxor run` processes side-by-side, tailing their stderr until
//! Ctrl+C". Designed for local Raft-style cluster bring-up; the
//! same flow lives behind `make up-3` in clustor and will be the
//! pattern Lattice / Loam adopt.
//!
//! The conventional placeholder set:
//!
//! | Placeholder      | Value                                           |
//! |------------------|-------------------------------------------------|
//! | `__SELF_ID__`    | the replica index (0..N-1)                      |
//! | `__LISTEN_PORT__`| `base_port + self_id`                           |
//! | `__PEER<i>_PORT__` | `base_port + i` for i in 0..N-1               |
//! | `__HTTP_PORT__`  | `listen_port + http_offset`                     |
//!
//! Other placeholders can be passed through `--var KEY=VAL` on the
//! command line; they're applied uniformly to every replica.

use crate::error::{Error, Result};
use crate::render_template::{parse_vars, render_file};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

// Default `http_offset` value (10 000, matching the clustor
// diagnostic-surface convention) is declared on the clap arg in
// `main.rs`; no in-module constant.

/// Spawn N replicas from one template. Returns once every child has
/// exited (Ctrl+C → SIGTERM → wait).
pub fn cmd_up(
    template_path: &Path,
    replicas: u8,
    base_port: u16,
    http_offset: u16,
    extra_vars: &[String],
    fluxor_bin: Option<&Path>,
) -> Result<()> {
    if replicas == 0 {
        return Err(Error::Config("--replicas must be at least 1".to_string()));
    }
    if replicas as u32 + base_port as u32 > u16::MAX as u32 {
        return Err(Error::Config(format!(
            "base_port + replicas overflows u16 (base_port={base_port}, replicas={replicas})"
        )));
    }

    let fluxor = resolve_fluxor_bin(fluxor_bin)?;
    let extra = parse_vars(extra_vars)?;

    let scratch = tempdir_unique("fluxor-up")?;
    eprintln!("scratch:  {}", scratch.display());
    eprintln!("template: {}", template_path.display());
    eprintln!("replicas: {replicas}");
    eprintln!(
        "ports:    {}..{}",
        base_port,
        base_port + replicas as u16 - 1
    );
    eprintln!();

    let stem = format!("up-{}", std::process::id());
    let mut spawned: Vec<Spawned> = Vec::with_capacity(replicas as usize);

    let interrupt = Arc::new(AtomicBool::new(false));
    install_signal_handler(interrupt.clone());

    for i in 0..replicas {
        let listen_port = base_port + i as u16;
        let http_port = listen_port + http_offset;

        let mut vars = vec![
            ("SELF_ID".to_string(), i.to_string()),
            ("LISTEN_PORT".to_string(), listen_port.to_string()),
            ("HTTP_PORT".to_string(), http_port.to_string()),
        ];
        for j in 0..replicas {
            vars.push((format!("PEER{j}_PORT"), (base_port + j as u16).to_string()));
        }
        vars.extend(extra.iter().cloned());

        let rendered = render_file(template_path, &vars)?;
        let yaml_path = scratch.join(format!("{stem}-n{i}.yaml"));
        std::fs::write(&yaml_path, &rendered).map_err(|e| {
            Error::Config(format!(
                "writing rendered yaml {}: {}",
                yaml_path.display(),
                e
            ))
        })?;

        let stderr_path = scratch.join(format!("n{i}.stderr"));
        let stderr_file = std::fs::File::create(&stderr_path).map_err(|e| {
            Error::Config(format!(
                "creating stderr log {}: {}",
                stderr_path.display(),
                e
            ))
        })?;
        let stdout_path = scratch.join(format!("n{i}.stdout"));
        let stdout_file = std::fs::File::create(&stdout_path).map_err(|e| {
            Error::Config(format!(
                "creating stdout log {}: {}",
                stdout_path.display(),
                e
            ))
        })?;

        let child = Command::new(&fluxor)
            .arg("run")
            .arg(&yaml_path)
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .map_err(|e| Error::Config(format!("spawning fluxor run for replica {i}: {e}")))?;

        eprintln!(
            "  node {}  pid {}  port {}  log {}",
            i,
            child.id(),
            listen_port,
            stderr_path.display()
        );

        spawned.push(Spawned {
            id: i,
            child,
            stderr_path,
        });
    }

    eprintln!();
    eprintln!("tailing all node logs (Ctrl+C to stop)...");
    eprintln!("============================================");

    // One tailer thread per replica, multiplexing onto stderr with
    // a `[n<i>]` prefix so it's clear which replica each line came
    // from. Threads exit when `interrupt` flips.
    let mut tailers = Vec::with_capacity(spawned.len());
    for s in &spawned {
        let id = s.id;
        let path = s.stderr_path.clone();
        let interrupt = interrupt.clone();
        tailers.push(thread::spawn(move || tail_loop(id, &path, interrupt)));
    }

    // Wait for either Ctrl+C or for every child to exit on its own.
    loop {
        if interrupt.load(Ordering::SeqCst) {
            break;
        }
        let mut all_done = true;
        for s in spawned.iter_mut() {
            if let Ok(None) = s.child.try_wait() {
                all_done = false;
            }
        }
        if all_done {
            break;
        }
        thread::sleep(Duration::from_millis(200));
    }

    eprintln!();
    eprintln!("shutting down...");
    for s in spawned.iter_mut() {
        // Try a graceful TERM, then escalate.
        let _ = signal_child(&s.child, libc::SIGTERM);
    }
    thread::sleep(Duration::from_millis(500));
    for s in spawned.iter_mut() {
        if let Ok(None) = s.child.try_wait() {
            let _ = signal_child(&s.child, libc::SIGKILL);
        }
        let _ = s.child.wait();
    }

    // Tailer threads exit shortly after their file stops growing
    // and `interrupt` is set.
    interrupt.store(true, Ordering::SeqCst);
    for t in tailers {
        let _ = t.join();
    }

    // Best-effort cleanup of the scratch dir. Leave the rendered
    // YAMLs and logs on disk if anything goes wrong — they're
    // useful for post-mortem.
    let _ = std::fs::remove_dir_all(&scratch);

    eprintln!("done.");
    Ok(())
}

struct Spawned {
    id: u8,
    child: Child,
    stderr_path: PathBuf,
}

fn signal_child(child: &Child, sig: libc::c_int) -> std::io::Result<()> {
    let pid = child.id() as libc::pid_t;
    // SAFETY: kill(2) with a non-negative pid is well-defined; we
    // never call it on an already-reaped pid because the caller
    // checks `try_wait` first.
    let rc = unsafe { libc::kill(pid, sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

static INTERRUPT_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();

extern "C" fn interrupt_handler(_signum: libc::c_int) {
    if let Some(flag) = INTERRUPT_FLAG.get() {
        flag.store(true, Ordering::SeqCst);
    }
}

fn install_signal_handler(flag: Arc<AtomicBool>) {
    // We can't use signal-hook without a new dependency, so set up
    // a one-shot SIGINT/SIGTERM handler via libc::signal that flips
    // the AtomicBool. Cooperative shutdown is enough — the
    // orchestrator polls `interrupt` from the main loop.
    //
    // `INTERRUPT_FLAG.set` is idempotent: subsequent calls (e.g.
    // when `cmd_up` is invoked twice in a test process) keep the
    // original flag rather than re-wiring the signal table.
    let _ = INTERRUPT_FLAG.set(flag);
    // SAFETY: libc::signal is async-signal-safe to call from main.
    // We're installing handlers before any worker thread starts.
    unsafe {
        libc::signal(libc::SIGINT, interrupt_handler as libc::sighandler_t);
        libc::signal(libc::SIGTERM, interrupt_handler as libc::sighandler_t);
    }
}

fn tail_loop(id: u8, path: &Path, interrupt: Arc<AtomicBool>) {
    // Open the stderr file for read; wait until it exists.
    let mut waited = Duration::ZERO;
    let file = loop {
        match std::fs::File::open(path) {
            Ok(f) => break f,
            Err(_) => {
                if interrupt.load(Ordering::SeqCst) || waited >= Duration::from_secs(5) {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
                waited += Duration::from_millis(50);
            }
        }
    };
    let mut reader = BufReader::new(file);
    let prefix = format!("[n{id}] ");
    let mut buf = String::new();
    loop {
        buf.clear();
        match reader.read_line(&mut buf) {
            Ok(0) => {
                // EOF — wait for more.
                if interrupt.load(Ordering::SeqCst) {
                    return;
                }
                thread::sleep(Duration::from_millis(100));
            }
            Ok(_) => {
                eprint!("{prefix}{buf}");
            }
            Err(_) => return,
        }
    }
}

fn resolve_fluxor_bin(override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        if !p.exists() {
            return Err(Error::Config(format!(
                "fluxor binary not found at {}",
                p.display()
            )));
        }
        return Ok(p.to_path_buf());
    }
    // Default: assume we're called as `fluxor up`, so re-invoke
    // `fluxor run` via the same binary on $PATH. Falling back to
    // `current_exe()` covers the in-tree development case where
    // fluxor isn't installed system-wide.
    if let Ok(exe) = std::env::current_exe() {
        return Ok(exe);
    }
    Ok(PathBuf::from("fluxor"))
}

fn tempdir_unique(prefix: &str) -> Result<PathBuf> {
    // No tempfile crate dependency — match the style used by
    // `scenario.rs` (mkdir under `std::env::temp_dir()` with a pid
    // suffix). Caller is responsible for cleanup.
    let base = std::env::temp_dir();
    let path = base.join(format!("{}-{}", prefix, std::process::id()));
    std::fs::create_dir_all(&path)
        .map_err(|e| Error::Config(format!("creating scratch dir {}: {}", path.display(), e)))?;
    Ok(path)
}
