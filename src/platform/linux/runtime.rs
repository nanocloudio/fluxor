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
    // SAFETY: `BOOT_INSTANT` is set once at boot by the bin's main()
    // before any timer reader is alive; this reads through `&raw const`
    // to avoid materialising a long-lived reference.
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

fn linux_disable_interrupts() -> u32 {
    0
}
fn linux_restore_interrupts(_state: u32) {}

/// Main-loop thread handle, captured before stepping starts.
/// `linux_wake_scheduler` clones and unparks it so an event signaled
/// from any thread (or from an ISR-equivalent callback) can interrupt
/// the runtime's `park_timeout` and run woken modules in the same way
/// RP breaks out of `embassy_futures::select` on a SIGNAL fire.
static LINUX_MAIN_THREAD: OnceLock<thread::Thread> = OnceLock::new();

/// Capture the current thread as the wake target. Call once, before
/// the scheduler loop starts.
fn linux_install_wake_thread() {
    let _ = LINUX_MAIN_THREAD.set(thread::current());
}

fn linux_wake_scheduler() {
    // Best-effort: if the runtime thread has been captured, unpark it.
    // Spurious unparks are fine — the main loop drains wake bits each
    // iteration. Before capture (early boot) wake is a no-op; the bit
    // still latches in EVENT_WAKE_PENDING and the first scheduler tick
    // observes it.
    if let Some(t) = LINUX_MAIN_THREAD.get() {
        t.unpark();
    }
}

fn linux_now_millis() -> u64 {
    elapsed_micros() / 1000
}

fn linux_now_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
/// What the kernel knows about the wall clock, via `adjtimex(2)`.
///
/// `now_unix_millis` cannot answer this and never could: a nonzero reading
/// from a clock nobody synchronised looks exactly like a good one. The
/// kernel, however, tracks it — `STA_UNSYNC` is clear once a time protocol
/// has disciplined the clock, and `maxerror` is its own estimate of how far
/// off it may be. That is evidence, and it is the difference between a
/// provider stuck at `RTC` forever and one that can honestly report
/// `NETWORK_SYNC`.
///
/// Returns `(synchronised, max_error_us)`. `synchronised: false` is a real
/// answer — the kernel can tell, and the answer is no.
fn linux_clock_sync_status() -> Option<(bool, u64)> {
    // `struct timex` is large and its layout is arch-specific, so it is
    // zeroed and only the two fields read that are at fixed offsets across
    // every Linux ABI: `modes` (0) is written, `maxerror` and `status` are
    // read back. Rather than hand-declare it, the two values come from
    // `/proc` where the layout question does not arise.
    //
    // `adjtimex` with `modes = 0` is a pure query and needs no privilege.
    #[repr(C)]
    #[derive(Default)]
    struct Timex {
        modes: i32,
        _pad0: i32,
        offset: i64,
        freq: i64,
        maxerror: i64,
        esterror: i64,
        status: i32,
        _pad1: i32,
        constant: i64,
        precision: i64,
        tolerance: i64,
        time_sec: i64,
        time_usec: i64,
        tick: i64,
        ppsfreq: i64,
        jitter: i64,
        shift: i32,
        _pad2: i32,
        stabil: i64,
        jitcnt: i64,
        calcnt: i64,
        errcnt: i64,
        stbcnt: i64,
        tai: i32,
        _reserved: [i32; 11],
    }

    unsafe extern "C" {
        fn adjtimex(buf: *mut core::ffi::c_void) -> i32;
    }

    /// `STA_UNSYNC` — set while the clock is NOT synchronised.
    const STA_UNSYNC: i32 = 0x0040;

    let mut tx = Timex::default();
    // SAFETY: `modes = 0` makes this a read-only query, and `tx` is a
    // zeroed, correctly-sized `struct timex` owned by this frame.
    let rc = unsafe { adjtimex((&raw mut tx).cast()) };
    if rc < 0 {
        // The kernel could not answer, which is not the same as "not
        // synchronised": reporting `false` here would claim knowledge this
        // call did not obtain.
        return None;
    }
    let synchronised = (tx.status & STA_UNSYNC) == 0;
    // `maxerror` saturates at 16 seconds when unsynchronised; clamped so a
    // consumer sizing a window from it cannot get a negative or absurd one.
    let max_error_us = if tx.maxerror < 0 {
        u64::MAX
    } else {
        tx.maxerror as u64
    };
    Some((synchronised, max_error_us))
}

/// Where the Linux sealing key comes from.
///
/// `HostReadable`, and that is the honest answer rather than a placeholder.
/// The key is derived from `FLUXOR_SEAL_KEY` or a file under the store
/// directory — both readable by anything running as this user. Sealing
/// therefore protects a stored key from a compromised MODULE and not from a
/// compromised HOST, and the vault's tier stays `SOFTWARE` because of it.
///
/// A Linux box with a TPM could report `DeviceUnique` by sealing to the
/// storage root key. That is a real path and deliberately not taken here on
/// the quiet: claiming it requires actually talking to the TPM, and a
/// provenance that overstates itself is worse than no sealing at all — it
/// raises a vault's tier and, with it, what a deployment believes about
/// keys it has not actually protected.
/// Where sealed key blobs live on Linux: one file per label under
/// `$FLUXOR_VAULT_DIR`, or `$FLUXOR_STORE_DIR/vault` when only the store dir
/// is set.
///
/// Unset means NO durable vault, and the hooks below then answer `false` /
/// `None`. That is deliberate: a process that was not told where to keep
/// keys should not invent a location and start writing key material into it.
fn linux_vault_dir() -> Option<std::path::PathBuf> {
    if let Ok(d) = std::env::var("FLUXOR_VAULT_DIR") {
        return Some(std::path::PathBuf::from(d));
    }
    std::env::var("FLUXOR_STORE_DIR")
        .ok()
        .map(|d| std::path::PathBuf::from(d).join("vault"))
}

/// A label's filename: its bytes, hex-encoded.
///
/// Hex rather than the label itself, because a label is an opaque byte string
/// chosen by a module and a filename is not. `../../etc/whatever` is a
/// perfectly legal label and must not become a path.
fn linux_vault_path(label: &[u8]) -> Option<std::path::PathBuf> {
    let dir = linux_vault_dir()?;
    let mut name = String::with_capacity(label.len() * 2);
    for b in label {
        use core::fmt::Write as _;
        let _ = write!(name, "{b:02x}");
    }
    Some(dir.join(name))
}

/// Write a sealed blob so it outlives the process. See
/// [`HalOps::seal_blob_write`].
///
/// The blob arrives ALREADY SEALED — this decides where it lives, nothing
/// more. Written to a temporary and renamed, so a crash midway leaves the
/// previous key intact rather than a truncated one: a half-written key reads
/// back as a key that does not open, and the vault would then generate a new
/// one and silently invalidate every credential signed under the old.
fn linux_seal_blob_write(label: &[u8], blob: &[u8]) -> bool {
    let Some(path) = linux_vault_path(label) else {
        return false;
    };
    let Some(dir) = path.parent() else {
        return false;
    };
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, blob).is_err() {
        return false;
    }
    std::fs::rename(&tmp, &path).is_ok()
}

/// Read a sealed blob back. See [`HalOps::seal_blob_read`].
fn linux_seal_blob_read(label: &[u8], out: &mut [u8]) -> Option<usize> {
    let path = linux_vault_path(label)?;
    let data = std::fs::read(path).ok()?;
    // Too large is "no key here", not a partial read: half a sealed blob does
    // not unseal, and returning part of one invites the caller to try.
    if data.len() > out.len() {
        return None;
    }
    out[..data.len()].copy_from_slice(&data);
    Some(data.len())
}

fn linux_seal_provenance() -> fluxor::kernel::sys::hal::SealProvenance {
    if linux_seal_key().is_some() {
        fluxor::kernel::sys::hal::SealProvenance::HostReadable
    } else {
        fluxor::kernel::sys::hal::SealProvenance::None
    }
}

/// The sealing key, or `None` when this deployment configured none.
///
/// From `FLUXOR_SEAL_KEY` (64 hex characters). Absent rather than
/// defaulted: a built-in constant would make every fluxor install share one
/// sealing key, which is indistinguishable from not sealing while looking
/// like it seals.
fn linux_seal_key() -> Option<[u8; 32]> {
    let hex = std::env::var("FLUXOR_SEAL_KEY").ok()?;
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        key[i] = ((hi << 4) | lo) as u8;
    }
    Some(key)
}

/// Seal with ChaCha20-Poly1305 under the platform key.
///
/// Layout: `[nonce:12][ciphertext][tag:16]`. The nonce is fresh per seal
/// from the kernel CSPRNG — a repeated nonce under one key breaks
/// confidentiality outright for a stream cipher, so it is generated rather
/// than derived from anything the caller controls.
fn linux_seal(plain: &[u8], out: &mut [u8]) -> Option<usize> {
    let key = linux_seal_key()?;
    let total = 12 + plain.len() + 16;
    if out.len() < total {
        return None;
    }
    let mut nonce = [0u8; 12];
    getrandom_bytes(&mut nonce)?;
    out[..12].copy_from_slice(&nonce);
    out[12..12 + plain.len()].copy_from_slice(plain);
    let tag = fluxor::kernel::security::crypto::chacha20::chacha20_poly1305_encrypt(
        &key,
        &nonce,
        &[],
        &mut out[12..12 + plain.len()],
    );
    out[12 + plain.len()..total].copy_from_slice(&tag);
    Some(total)
}

fn linux_unseal(sealed: &[u8], out: &mut [u8]) -> Option<usize> {
    let key = linux_seal_key()?;
    if sealed.len() < 12 + 16 {
        return None;
    }
    let body_len = sealed.len() - 12 - 16;
    if out.len() < body_len {
        return None;
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sealed[..12]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&sealed[12 + body_len..]);
    out[..body_len].copy_from_slice(&sealed[12..12 + body_len]);
    // A tag that does not verify means the blob was altered or sealed
    // under a different key. Either way it is not a key, and `out` is
    // wiped rather than returned half-decrypted.
    if fluxor::kernel::security::crypto::chacha20::chacha20_poly1305_decrypt(
        &key,
        &nonce,
        &[],
        &mut out[..body_len],
        &tag,
    ) {
        Some(body_len)
    } else {
        for b in &mut out[..body_len] {
            // SAFETY: `b` is a live, exclusively-borrowed byte of `out`.
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        None
    }
}

fn getrandom_bytes(buf: &mut [u8]) -> Option<()> {
    // SAFETY: `buf` is a live, exclusively-borrowed slice of `buf.len()`.
    let rc = unsafe {
        libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0)
    };
    if rc as usize == buf.len() {
        Some(())
    } else {
        None
    }
}

fn linux_now_micros() -> u64 {
    elapsed_micros()
}
fn linux_tick_count() -> u32 {
    // Back the HAL `tick_count` with wall-clock milliseconds instead
    // of `DBG_TICK`. The identity
    // "1 tick == 1 ms" holds only at the fixed 1 ms default; mechanism (b)
    // varies the period and mechanism (a) stops advancing `DBG_TICK` during
    // idle, so a `DBG_TICK`-backed `tick_count` returns wrong "ms since boot"
    // under adaptive tick. Wall-clock `elapsed_micros()/1000` is correct under
    // any pacing — matching rp's `Instant`-based `rp_tick_count` (rp.rs:449).
    // The internal logical tick counter (`scheduler::tick_count()` → DBG_TICK)
    // is unchanged; only this outward HAL op is decoupled.
    (elapsed_micros() / 1000) as u32
}

/// Portable `sleep_until`. Parks the calling (scheduler) thread until
/// `deadline_us` or until `linux_wake_scheduler` unparks it — the same
/// primitive the native Linux loop uses. A spurious unpark just returns early;
/// the caller re-checks its work state.
fn linux_sleep_until(deadline_us: u64) -> u32 {
    let now = elapsed_micros();
    if deadline_us <= now {
        return fluxor::kernel::sys::hal::WOKEN_DEADLINE;
    }
    let remaining = deadline_us - now;
    std::thread::park_timeout(std::time::Duration::from_micros(remaining));
    // Distinguish deadline vs early wake by re-reading the clock.
    if elapsed_micros() >= deadline_us {
        fluxor::kernel::sys::hal::WOKEN_DEADLINE
    } else {
        fluxor::kernel::sys::hal::WOKEN_EVENT
    }
}

fn linux_flash_base() -> usize {
    0
}
fn linux_flash_end() -> usize {
    0
}
fn linux_apply_code_bit(addr: usize) -> usize {
    addr
}
fn linux_validate_fn_addr(addr: usize) -> bool {
    // Non-null + 4-byte aligned. mmap-region bounds tracking would
    // require the platform main to publish the mmap base+len to a
    // static; for now alignment is a cheap catch for ABI corruption.
    addr != 0 && (addr & 0x3) == 0
}
fn linux_validate_module_base(addr: usize) -> bool {
    // Module headers are 4-byte aligned in `.fmod` images.
    addr != 0 && (addr & 0x3) == 0
}
fn linux_validate_fn_in_code(addr: usize, base: usize, size: u32) -> bool {
    // A function pointer claimed by a module manifest must fall inside
    // the module's `[code_base, code_base + code_size)`. The
    // export-offset bounds check in `get_export_addr` already rejects
    // manifests that claim out-of-range offsets; this is the
    // platform-side belt-and-braces check.
    if base == 0 || size == 0 {
        return false;
    }
    let end = base.saturating_add(size as usize);
    addr >= base && addr < end
}
/// Linux platform integrity hook — byte-compare the computed digest
/// against the manifest-stored value, matching the RP and BCM hooks.
/// The cost is one O(n) slice compare per module load.
fn linux_verify_integrity(computed: &[u8], expected: &[u8]) -> bool {
    computed == expected
}

/// OTA staging page-permission flip: RW while staging bytes land, RX
/// once committed (W^X — the staged region is only ever writable OR
/// executable). The staging buffer is 16 KiB-aligned static BSS —
/// covering the host kernel's actual page size (Raspberry Pi OS
/// aarch64 runs 16 KiB pages), which is also what the range is
/// rounded to here; a 4 KiB assumption made `mprotect` fail EINVAL on
/// such kernels.
fn linux_ota_stage_protect(base: *mut u8, len: usize, executable: bool) -> bool {
    // SAFETY: sysconf on a valid selector; falls back defensively.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page = if page > 0 { page as usize } else { 16384 };
    let start = (base as usize) & !(page - 1);
    let end = (base as usize + len + page - 1) & !(page - 1);
    let prot = if executable {
        libc::PROT_READ | libc::PROT_EXEC
    } else {
        libc::PROT_READ | libc::PROT_WRITE
    };
    // SAFETY: whole-page range over the static staging buffer; mprotect
    // on BSS pages is well-defined.
    unsafe { libc::mprotect(start as *mut libc::c_void, end - start, prot) == 0 }
}
fn linux_pic_barrier() {}

fn linux_step_guard_init() {}
fn linux_step_guard_arm(_deadline_us: u32) {}
fn linux_step_guard_disarm() {}
fn linux_step_guard_post_check() {}

fn linux_read_cycle_count() -> u32 {
    elapsed_micros() as u32
}

fn linux_isr_tier_init() {}
fn linux_isr_tier_start(_period_us: u32) {}
fn linux_isr_tier_stop() {}
fn linux_isr_tier_poll() {}

fn linux_init_providers() {
    // Override the default stub FS provider with one backed by real
    // libc I/O. The dispatcher also answers
    // `contracts::fence::QUERY_OP`, surfacing the per-handle fence
    // through `provider_query(handle, query_key::LAST_FENCE, …)`.
    use fluxor::kernel::module::provider;
    use fluxor::kernel::module::provider::contract as dev_class;
    provider::register(dev_class::FS, linux_fs_dispatch);
    provider::register(dev_class::STREAM_CLOCK, linux_stream_time_dispatch);
    // storage.object over HTTP `Range:` — wasm peer in
    // `src/platform/wasm/object.rs`; shared windowing in
    // `abi::contracts::storage::object::range`.
    provider::register(dev_class::STORAGE_OBJECT, linux_object_dispatch);
    // storage.namespace over the real filesystem (std::fs read_dir/metadata)
    // — the directory-enumeration sibling of the FS provider; wasm peer in
    // `src/platform/wasm/namespace.rs`. Lets a scanner walk a host library on
    // Linux exactly as it walks the manifest-backed index in the browser.
    provider::register(dev_class::STORAGE_NAMESPACE, linux_namespace_dispatch);
    // Control-plane store: if FLUXOR_STORE_DIR is set, the two storage providers
    // above route to an in-runtime versioned watchable store instead of
    // HTTP/filesystem. A no-op when the env is unset.
    // SAFETY: single-threaded startup, before any provider dispatch — the
    // store singleton is initialised exactly once with no concurrent access.
    // NOT discarded. A store that was asked for and could not be opened leaves
    // every store-backed module in the graph talking to a provider that is not
    // there — and a module with no provider does not fail, it just never
    // produces anything, which from outside looks like a module with nothing
    // to do. Saying so here is the difference between a one-line diagnosis and
    // an afternoon.
    match unsafe { fluxor::platform::linux::store::store_init_from_env() } {
        fluxor::platform::linux::store::StoreInit::NotConfigured
        | fluxor::platform::linux::store::StoreInit::Opened => {}
        fluxor::platform::linux::store::StoreInit::Failed => {
            log::error!(
                "[store] FLUXOR_STORE_DIR is set but the control-plane store \
                 could not be opened; every storage.object and \
                 storage.namespace call on this node will be answered without \
                 it. Check the directory exists, is writable, and that its \
                 append log is not corrupt."
            );
        }
    }
    // The impure boundary: host process executor (sector `do`). Gated by
    // `requires_contract="proc"`; only registered on host-linux (a PIC module
    // can't fork/exec, so a "worker" is by definition a Linux node).
    provider::register(
        fluxor::abi::platform::linux::host_process::PROC_CLASS,
        linux_proc_dispatch,
    );
    provider::register_fd_tag_route(
        fluxor::abi::platform::linux::host_process::FD_TAG_PROC,
        fluxor::abi::platform::linux::host_process::PROC_CLASS,
    );
    // Platform-neutral isolated-workload surface: parses the Tier-1 spec, binds
    // to a plan-allocated owner + lease, enforces the Tier-2 options envelope
    // fail-closed, and delegates to the owner-bound host-process backend.
    // Host-linux; gated by requires_contract = "workload" + platform_raw.
    provider::register(dev_class::WORKLOAD, linux_workload_dispatch);
    provider::register(
        dev_class::HOST_PROCESS,
        fluxor::platform::linux::workload::host_process_dispatch,
    );
    // KEY_VAULT hardware override: when a PKCS#11 token is configured,
    // re-register both KEY_VAULT dispatch paths over the kernel software
    // default. Runs after the kernel-core registrations, so the override
    // wins; unconfigured or failed, the software backend stays live and
    // reports TIER=SOFTWARE.
    #[cfg(feature = "host-hsm")]
    fluxor::platform::linux::hsm_key_vault::try_register_from_env();
}
/// Platform-specific per-module cleanup for Linux host.
///
/// **Intentional no-op.** The Linux runtime relies on:
///   * The kernel-generic `syscalls::release_module_handles` which
///     already releases events, fd-based timers, and module-registered
///     provider handles (all of which record `owner_module`).
///   * Process-exit cleanup for `mmap`'d module images — the kernel
///     holds module code for the lifetime of the process.
///   * `provider::reset_handle_tracking` from `prepare_graph` on
///     each reconfigure, which strips any provider handles a
///     finalised module might have leaked.
///
/// Per-module unload of mmap'd memory before process exit would
/// require the runtime to track each `.fmod` → mmap mapping by
/// module index; v1 leaves the process model as the outer cleanup
/// boundary.
fn linux_release_module_handles(_module_idx: u8) {
    // Generic kernel cleanup in `syscalls::release_module_handles`
    // covers event/timer/provider resources; Linux mmap mappings
    // live for the process.
}
fn linux_boot_scan() {}
fn linux_merge_runtime_overrides(_module_id: u16, _buf: *mut u8, len: usize, _max: usize) -> usize {
    len
}


/// HalOps protection impls: the portable MPU facade (no-op internally on
/// non-RP silicon) and the shared direct step dispatch.
fn prot_register_module(
    module_idx: usize,
    code_base: usize,
    code_size: usize,
    state_ptr: *mut u8,
    state_size: usize,
    heap_ptr: *mut u8,
    heap_size: usize,
) {
    fluxor::platform::mpu::register_module(
        module_idx,
        code_base as u32,
        code_size as u32,
        state_ptr,
        state_size,
        heap_ptr,
        heap_size,
    );
}
fn prot_set_channel_region(module_idx: usize, base: usize, size: usize) {
    fluxor::platform::mpu::set_channel_region(module_idx, base as u32, size as u32);
}
use fluxor::kernel::sys::hal::protected_step_direct as fluxor_protected_step_direct;

static LINUX_HAL_OPS: HalOps = HalOps {
    disable_interrupts: linux_disable_interrupts,
    restore_interrupts: linux_restore_interrupts,
    wake_scheduler: linux_wake_scheduler,
    now_millis: linux_now_millis,
    now_unix_millis: linux_now_unix_millis,
    clock_sync_status: linux_clock_sync_status,
    seal_provenance: linux_seal_provenance,
    seal_blob_write: linux_seal_blob_write,
    seal_blob_read: linux_seal_blob_read,
    seal: linux_seal,
    unseal: linux_unseal,
    now_micros: linux_now_micros,
    tick_count: linux_tick_count,
    flash_base: linux_flash_base,
    flash_end: linux_flash_end,
    apply_code_bit: linux_apply_code_bit,
    validate_fn_addr: linux_validate_fn_addr,
    validate_module_base: linux_validate_module_base,
    validate_fn_in_code: linux_validate_fn_in_code,
    verify_integrity: linux_verify_integrity,
    ota_stage_protect: linux_ota_stage_protect,
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
    irq_bind: |_, _, _, _| fluxor::kernel::sys::errno::ENOSYS,
    sleep_until: linux_sleep_until,
    smp_quiesce_peers: || false,
    smp_release_peers: || {},
    smp_max_domains: || 1,
    protection_set_enabled: fluxor::platform::mpu::set_enabled,
    protection_reset: || {},
    protection_register_module: prot_register_module,
    protection_set_channel_region: prot_set_channel_region,
    protection_set_isolated_channels: |_, _, _, _| {},
    protected_step: fluxor_protected_step_direct,
    protection_map_page: |_, _, _, _| {},
    protection_unmap_page: |_, _| {},
    stack_canary_check: fluxor::platform::mpu::check_stack_canary,
    stack_canary_reinit: fluxor::platform::mpu::reinit_stack_canary,
    // Host serial sink = stderr (fd 2), unbuffered so framed telemetry bytes
    // land verbatim for a capture tool. Binary-safe (no UTF-8 filtering).
    serial_write: |b| unsafe {
        let n = libc::write(2, b.as_ptr() as *const libc::c_void, b.len());
        if n < 0 {
            0
        } else {
            n as usize
        }
    },
};

fn linux_csprng_fill(buf: *mut u8, len: usize) -> i32 {
    // `libc::SYS_getrandom` is the canonical per-arch syscall selector
    // and `libc::syscall` handles the platform-specific calling
    // convention, so this compiles correctly (or fails loudly) on any
    // architecture libc supports — no hand-rolled `svc`/asm or
    // hardcoded syscall numbers.
    // SAFETY: `libc::syscall` invoked with the per-arch SYS_getrandom
    // selector and `(buf, len, flags=0)` matches `getrandom(2)`. The
    // caller supplies `buf`/`len` from a Rust slice, so the pointer
    // is valid for writes of `len` bytes.
    let ret =
        unsafe { libc::syscall(libc::SYS_getrandom, buf as *mut libc::c_void, len, 0u32) };
    if ret < 0 || ret as usize != len {
        return -1;
    }
    0
}

// ============================================================================
