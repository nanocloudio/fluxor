//! Resolve `fluxor/run/fluxor-<triple>:latest` in the local OCI store
//! and exec its blob. Deliberately tiny — this binary must never need
//! to change (it too can be republished through the store, but its
//! whole job is one index read + one exec).

#![allow(
    unsafe_code,
    reason = "the launcher's whole job is one `fexecve` — exec of an open descriptor has no safe wrapper"
)]
#![allow(
    clippy::print_stderr,
    reason = "user-facing diagnostics on the unhappy path; there is no logging substrate before the CLI execs"
)]

use std::os::fd::AsRawFd;
use std::path::PathBuf;

const TRIPLE: &str = env!("FLUXOR_HOST_TRIPLE");

fn store_root() -> PathBuf {
    if let Some(v) = std::env::var_os("FLUXOR_STORE") {
        return PathBuf::from(v);
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("fluxor").join("store");
        }
    }
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share/fluxor/store")
}

fn die(msg: &str) -> ! {
    eprintln!("fluxor: {msg}");
    eprintln!("        no fluxor CLI in store — run `make install` from a fluxor checkout");
    std::process::exit(127);
}

fn main() {
    let root = store_root();
    let index_path = root.join("index.json");
    let index: serde_json::Value = match std::fs::read(&index_path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => die(&format!(
                "store index unreadable ({e}) at {}",
                index_path.display()
            )),
        },
        Err(_) => die(&format!("no store at {}", root.display())),
    };
    let want = format!("fluxor/run/fluxor-{TRIPLE}:latest");
    let Some(desc) = index["manifests"].as_array().and_then(|m| {
        m.iter().find(|d| {
            d["annotations"]["org.opencontainers.image.ref.name"].as_str() == Some(want.as_str())
        })
    }) else {
        die(&format!("tag {want} not found in store"));
    };
    let digest = desc["digest"].as_str().unwrap_or_default();
    let blob = |d: &str| {
        root.join("blobs/sha256")
            .join(d.trim_start_matches("sha256:"))
    };
    let manifest: serde_json::Value = match std::fs::read(blob(digest)) {
        Ok(b) => match serde_json::from_slice(&b) {
            Ok(v) => v,
            Err(e) => die(&format!("CLI manifest blob unreadable ({e})")),
        },
        Err(e) => die(&format!("CLI manifest blob missing ({e})")),
    };
    let Some(bin_digest) = manifest["layers"][0]["digest"].as_str() else {
        die("CLI manifest has no binary layer");
    };
    let file = match std::fs::File::open(blob(bin_digest)) {
        Ok(f) => f,
        Err(e) => die(&format!("CLI blob missing ({e})")),
    };

    // fexecve: exec the open descriptor — collection of a superseded
    // blob can never race the launch, and argv[0] (busybox applet
    // dispatch) passes through untouched.
    let args: Vec<std::ffi::CString> = std::env::args_os()
        .map(|a| std::ffi::CString::new(a.into_encoded_bytes()).unwrap())
        .collect();
    let mut argv: Vec<*const libc::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    // The CLI learns where the launcher is: a busybox link an applet
    // install drops must point here, not at the blob of the moment.
    let mut env: Vec<std::ffi::CString> = std::env::vars_os()
        .filter(|(k, _)| k != "FLUXOR_LAUNCHER")
        .map(|(k, v)| {
            let mut s = k.into_encoded_bytes();
            s.push(b'=');
            s.extend(v.into_encoded_bytes());
            std::ffi::CString::new(s).unwrap()
        })
        .collect();
    if let Ok(me) = std::env::current_exe() {
        let mut s = b"FLUXOR_LAUNCHER=".to_vec();
        s.extend(me.into_os_string().into_encoded_bytes());
        if let Ok(c) = std::ffi::CString::new(s) {
            env.push(c);
        }
    }
    let mut envp: Vec<*const libc::c_char> = env.iter().map(|e| e.as_ptr()).collect();
    envp.push(std::ptr::null());
    // SAFETY: `argv` and `envp` are NUL-terminated arrays of pointers
    // into `args`/`env` CStrings that outlive this call; the fd is open.
    // On success `fexecve` never returns; on failure we fall through.
    unsafe { libc::fexecve(file.as_raw_fd(), argv.as_ptr(), envp.as_ptr()) };
    die(&format!(
        "exec of CLI blob failed ({})",
        std::io::Error::last_os_error()
    ));
}
