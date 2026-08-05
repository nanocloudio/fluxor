//! Mount / VFS policy module.
//!
//! Registers as the **default (unkeyed) FS provider** and routes each path
//! to a volume backend by longest-prefix match. Backends are keyed `fat32`
//! instances (each declaring a `volume:` selector); this module forwards
//! each op to the named volume via `provider_call_sel` (the kernel
//! re-resolves the backend by selector per call — no cached binding).
//!
//! Consumers keep `requires_contract = "fs"` and open plain absolute paths.
//! Only this module's `mounts:` config knows which volume a path prefix lives
//! on, so a graph can move a prefix between drives without touching any
//! consumer.
//!
//! ```text
//!  bank / fs_tap  --FS_OPEN("/data/x")-->  [mount]  --call_sel("nvme0")-->  fat32#nvme0
//!                                             |      --call_sel("sd0")----> fat32#sd0
//!                                             +-- longest-prefix table:  /data -> nvme0
//!                                                                        /boot -> sd0
//! ```
//!
//! # Handle remapping
//!
//! A backend `FS_OPEN` returns `FD_TAG_FS | backend_slot`; two volumes can
//! return the same slot, so this module allocates its OWN mount slot,
//! records `(mount_idx, backend_handle)`, and returns `FD_TAG_FS |
//! mount_slot` to the consumer. Later handle-bound ops (`FS_READ` /
//! `FS_CLOSE` / …) route by tag back to this module (the default FS
//! provider), which decodes the mount slot and forwards to the owning
//! backend. `FS_CLOSE` frees the mount slot.
//!
//! # Configuration
//!
//!   mounts: "/boot=sd0;/data=nvme0"   (prefix=volume, ';'-separated)

#![cfg_attr(not(feature = "host-test"), no_std)]
#![allow(
    dead_code,
    unused_imports,
    unreachable_patterns,
    reason = "PIC build path-mounts modules/sdk/* via include!/mod, so each module's compile sees the full ABI surface; consumers use a subset."
)]

use core::ffi::c_void;

#[path = "../../sdk/abi.rs"]
mod abi;
use abi::SyscallTable;

include!("../../sdk/runtime.rs");
include!("../../sdk/runtime/params.rs");

// ── FS contract opcodes (storage/fs.rs) ─────────────────────────────────────
const FS_OPEN: u32 = 0x0900;
const FS_READ: u32 = 0x0901;
const FS_SEEK: u32 = 0x0902;
const FS_CLOSE: u32 = 0x0903;
const FS_STAT: u32 = 0x0904;
const FS_FSYNC: u32 = 0x0905;
const FS_WRITE: u32 = 0x0906;
const FS_OPENDIR: u32 = 0x0907;
const FS_READDIR: u32 = 0x0908;
const FS_OPEN_CREATE: u32 = 0x0909;
const FS_UNLINK: u32 = 0x090A;
const FS_MKDIR: u32 = 0x090B;
const FS_CAPS: u32 = 0x09FF;
const CONTRACT_FS: u32 = 0x0009;

// errno
const EINVAL: i32 = -22;
const ENODEV: i32 = -19;
const EBADF: i32 = -9;
const ENFILE: i32 = -23;

/// Mount-table entries. Several prefixes may share one volume, so this bounds
/// prefixes, not backends. The number of DISTINCT volumes is capped lower, by
/// the kernel's per-target `MAX_CHAIN_DEPTH` (one layer for this module plus
/// one per volume): 7 on bcm2712/host, 3 on rp2350, 2 on rp2040. A volume past
/// that ceiling fails to register with `EBUSY` and its mounts resolve to
/// `ENODEV`.
const MAX_MOUNTS: usize = 8;
const MAX_OPEN: usize = 64;
const PREFIX_MAX: usize = 48;
const VOLUME_MAX: usize = 15;
const PATH_MAX: usize = 256;

// Hotplug / removable-media control. A low-rate control channel
// (in[0]) carries add/remove commands, mirroring the IP `addr_ctl` port:
// the platform backend that detects insert/remove writes one command per
// record; `module_step` drains and applies them. Detection is
// platform-specific and out of this module's scope.
const MOUNT_CMD_ADD: u8 = 1;
const MOUNT_CMD_DEL: u8 = 2;
/// `[cmd:u8][prefix_len:u8][prefix][volume_len:u8][volume]`.
const CTL_MSG_MAX: usize = 2 + PREFIX_MAX + 1 + VOLUME_MAX;

#[derive(Clone, Copy)]
struct MountEntry {
    prefix: [u8; PREFIX_MAX],
    prefix_len: u8,
    volume: [u8; VOLUME_MAX],
    volume_len: u8,
    /// `false` once the volume is unmounted (its slot is reusable by a
    /// later `MOUNT_ADD`); routing skips inactive entries.
    active: bool,
}

impl MountEntry {
    const fn empty() -> Self {
        Self {
            prefix: [0; PREFIX_MAX],
            prefix_len: 0,
            volume: [0; VOLUME_MAX],
            volume_len: 0,
            active: false,
        }
    }
}

#[derive(Clone, Copy)]
struct OpenSlot {
    in_use: bool,
    /// Set when the backing volume is unmounted; the next op on this handle
    /// fails `ENODEV` and frees the slot (the lease/revocation the storage
    /// contract specifies, enforced at the handle authority — this module).
    revoked: bool,
    mount_idx: u8,
    backend_handle: i32,
}

impl OpenSlot {
    const fn empty() -> Self {
        Self {
            in_use: false,
            revoked: false,
            mount_idx: 0,
            backend_handle: -1,
        }
    }
}

#[repr(C)]
struct MountState {
    syscalls: *const SyscallTable,
    mounts: [MountEntry; MAX_MOUNTS],
    mount_count: u8,
    /// Optional hotplug control channel (in[0]); `-1` when unwired.
    ctl_chan: i32,
    opens: [OpenSlot; MAX_OPEN],
    /// Scratch buffer for the prefix-stripped in-volume path.
    scratch: [u8; PATH_MAX],

    /// Cumulative FS ops forwarded to a volume backend (metric id 0).
    ops_routed: u64,
    /// Cumulative ops that matched no mount prefix, or whose volume had been
    /// unmounted under them — every one is an `ENODEV` the caller saw (id 1).
    /// A step in this counter is the signal that a drive went away or a mount
    /// table names a prefix nothing serves.
    route_misses: u64,
    /// Wall-clock anchor for the telemetry emit cadence.
    last_observe_ms: u64,
}

/// Telemetry emit cadence. Matches the other foundation modules; the counters
/// are cumulative, so the interval sets reporting latency, not accuracy.
const MOUNT_OBSERVE_INTERVAL_MS: u64 = 5_000;

impl MountState {
    fn init(&mut self, syscalls: *const SyscallTable) {
        self.syscalls = syscalls;
        self.ops_routed = 0;
        self.route_misses = 0;
        self.last_observe_ms = 0;
        self.mounts = [MountEntry::empty(); MAX_MOUNTS];
        self.mount_count = 0;
        self.ctl_chan = -1;
        self.opens = [OpenSlot::empty(); MAX_OPEN];
    }
}

// ── mount table parsing ─────────────────────────────────────────────────────

/// Parse the `mounts` param, a `;`-separated list of `prefix=volume` pairs.
/// Malformed entries are skipped; capacity is bounded by `MAX_MOUNTS`.
unsafe fn parse_mounts(s: &mut MountState, d: *const u8, len: usize) {
    let bytes = core::slice::from_raw_parts(d, len);
    let mut i = 0;
    while i < bytes.len() && (s.mount_count as usize) < MAX_MOUNTS {
        // one entry runs to ';' or end
        let start = i;
        while i < bytes.len() && bytes[i] != b';' {
            i += 1;
        }
        let entry = &bytes[start..i];
        if i < bytes.len() {
            i += 1; // skip ';'
        }
        // split on '='
        let mut eq = entry.len();
        let mut j = 0;
        while j < entry.len() {
            if entry[j] == b'=' {
                eq = j;
                break;
            }
            j += 1;
        }
        if eq == entry.len() {
            continue; // no '=' → skip
        }
        let prefix = &entry[..eq];
        let volume = &entry[eq + 1..];
        if prefix.is_empty() || volume.is_empty() || prefix.len() > PREFIX_MAX || volume.len() > VOLUME_MAX
        {
            continue;
        }
        let idx = s.mount_count as usize;
        let e = &mut s.mounts[idx];
        e.prefix[..prefix.len()].copy_from_slice(prefix);
        e.prefix_len = prefix.len() as u8;
        e.volume[..volume.len()].copy_from_slice(volume);
        e.volume_len = volume.len() as u8;
        e.active = true;
        s.mount_count += 1;
    }
}

// ── hotplug control (add / remove a volume at runtime) ──────────────────────

/// Mark every open handle on volume `mi` revoked, so in-flight consumers
/// get `ENODEV`; a fresh open after re-add routes to the new backend.
unsafe fn revoke_volume(s: &mut MountState, mi: usize) {
    for slot in s.opens.iter_mut() {
        if slot.in_use && slot.mount_idx as usize == mi {
            slot.revoked = true;
        }
    }
}

/// Remove the mount whose prefix exactly matches `prefix` (a media-eject
/// or explicit unmount): revoke its handles and free its table slot.
unsafe fn remove_mount(s: &mut MountState, prefix: &[u8]) {
    for i in 0..s.mount_count as usize {
        let e = &s.mounts[i];
        if e.active && e.prefix_len as usize == prefix.len() && &e.prefix[..prefix.len()] == prefix {
            revoke_volume(s, i);
            s.mounts[i].active = false;
            return;
        }
    }
}

/// Add (or re-activate) a mount at runtime (media insertion). Reuses an
/// inactive table slot; binding stays lazy (first FS_OPEN binds it).
unsafe fn add_mount(s: &mut MountState, prefix: &[u8], volume: &[u8]) {
    if prefix.is_empty()
        || volume.is_empty()
        || prefix.len() > PREFIX_MAX
        || volume.len() > VOLUME_MAX
    {
        return;
    }
    // Find a free slot: an inactive entry, or grow the table.
    let mut idx = None;
    for i in 0..s.mount_count as usize {
        if !s.mounts[i].active {
            idx = Some(i);
            break;
        }
    }
    let i = match idx {
        Some(i) => i,
        None => {
            if (s.mount_count as usize) >= MAX_MOUNTS {
                return;
            }
            let i = s.mount_count as usize;
            s.mount_count += 1;
            i
        }
    };
    let e = &mut s.mounts[i];
    e.prefix = [0; PREFIX_MAX];
    e.prefix[..prefix.len()].copy_from_slice(prefix);
    e.prefix_len = prefix.len() as u8;
    e.volume = [0; VOLUME_MAX];
    e.volume[..volume.len()].copy_from_slice(volume);
    e.volume_len = volume.len() as u8;
    e.active = true;
}

/// Parse and apply one control message
/// (`[cmd][prefix_len][prefix][volume_len][volume]`).
unsafe fn apply_ctl(s: &mut MountState, msg: &[u8]) {
    if msg.len() < 2 {
        return;
    }
    let cmd = msg[0];
    let plen = msg[1] as usize;
    if 2 + plen > msg.len() {
        return;
    }
    let prefix = &msg[2..2 + plen];
    match cmd {
        MOUNT_CMD_DEL => remove_mount(s, prefix),
        MOUNT_CMD_ADD => {
            let off = 2 + plen;
            if off >= msg.len() {
                return;
            }
            let vlen = msg[off] as usize;
            if off + 1 + vlen > msg.len() {
                return;
            }
            let volume = &msg[off + 1..off + 1 + vlen];
            // Copy out of the shared read buffer before mutating the table.
            let mut pbuf = [0u8; PREFIX_MAX];
            let mut vbuf = [0u8; VOLUME_MAX];
            if plen > PREFIX_MAX || vlen > VOLUME_MAX {
                return;
            }
            pbuf[..plen].copy_from_slice(prefix);
            vbuf[..vlen].copy_from_slice(volume);
            add_mount(s, &pbuf[..plen], &vbuf[..vlen]);
        }
        _ => {}
    }
}

/// Drain the hotplug control channel each tick (bounded), applying add /
/// remove commands. No-op when the port is unwired.
unsafe fn service_ctl(s: &mut MountState) {
    if s.ctl_chan < 0 {
        return;
    }
    let sys = &*s.syscalls;
    let mut buf = [0u8; CTL_MSG_MAX];
    // One control op per record; a full table's worth per tick is ample.
    for _ in 0..MAX_MOUNTS {
        let n = (sys.channel_read)(s.ctl_chan, buf.as_mut_ptr(), buf.len());
        if n <= 0 {
            break;
        }
        apply_ctl(s, &buf[..n as usize]);
    }
}

mod params_def {
    use super::MountState;
    use super::SCHEMA_MAX;

    define_params! {
        MountState;

        1, mounts, str, 0
            => |s, d, len| { super::parse_mounts(s, d, len); };
    }
}

// ── routing ─────────────────────────────────────────────────────────────────

/// Longest-prefix match of `path` against the mount table, respecting path
/// boundaries: a prefix matches only when it equals the path, is followed
/// by `/`, or is the root `/`. Returns the mount index, or `None`.
unsafe fn longest_prefix_match(s: &MountState, path: *const u8, path_len: usize) -> Option<usize> {
    let path = core::slice::from_raw_parts(path, path_len);
    let mut best: Option<usize> = None;
    let mut best_len = 0usize;
    for i in 0..s.mount_count as usize {
        let e = &s.mounts[i];
        if !e.active {
            continue;
        }
        let pl = e.prefix_len as usize;
        let pre = &e.prefix[..pl];
        if pl > path.len() || &path[..pl] != pre {
            continue;
        }
        // Boundary: prefix == path, or next char is '/', or prefix is "/".
        let boundary = pl == path.len() || path[pl] == b'/' || (pl == 1 && pre[0] == b'/');
        if boundary && pl >= best_len {
            best = Some(i);
            best_len = pl;
        }
    }
    best
}

/// Strip the mount prefix from `path` into `s.scratch`, yielding the
/// in-volume absolute path. Root mount (`/`) passes the path through; an
/// exact-prefix match yields `/`. Returns the rewritten length.
unsafe fn rewrite_path(s: &mut MountState, mi: usize, path: *const u8, path_len: usize) -> usize {
    let pl = s.mounts[mi].prefix_len as usize;
    let src = core::slice::from_raw_parts(path, path_len);
    // Root mount, or prefix that is just "/": pass through unchanged.
    if pl == 1 && s.mounts[mi].prefix[0] == b'/' {
        let n = core::cmp::min(path_len, PATH_MAX);
        s.scratch[..n].copy_from_slice(&src[..n]);
        return n;
    }
    // Remainder after the prefix (which had a boundary at pl).
    let rem = &src[pl..];
    if rem.is_empty() {
        s.scratch[0] = b'/';
        return 1;
    }
    // `rem` starts with '/' (the boundary char); copy it verbatim.
    let n = core::cmp::min(rem.len(), PATH_MAX);
    s.scratch[..n].copy_from_slice(&rem[..n]);
    n
}

/// Forward one op to the backend for mount `mi`, selecting the volume by
/// name each call. `provider_call_sel` re-resolves by selector, so there is
/// no cached token to go stale under live graph mutation. `op_handle` is
/// the backend's OWN handle (`-1` for open-style ops).
unsafe fn call_volume(
    s: &mut MountState,
    mi: usize,
    op_handle: i32,
    op: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    let mut vol = [0u8; VOLUME_MAX];
    let vl = s.mounts[mi].volume_len as usize;
    vol[..vl].copy_from_slice(&s.mounts[mi].volume[..vl]);
    s.ops_routed = s.ops_routed.wrapping_add(1);
    let sys = &*s.syscalls;
    dev_provider_call_sel(sys, &vol[..vl], op_handle, op, arg, arg_len)
}

unsafe fn alloc_slot(s: &mut MountState, mount_idx: u8, backend_handle: i32) -> Option<usize> {
    for (i, slot) in s.opens.iter_mut().enumerate() {
        if !slot.in_use {
            slot.in_use = true;
            slot.revoked = false;
            slot.mount_idx = mount_idx;
            slot.backend_handle = backend_handle;
            return Some(i);
        }
    }
    None
}

/// The FS provider dispatch. Routes open-family and one-shot ops by path
/// prefix; routes handle-bound ops by the mount slot recorded at open.
unsafe fn mount_dispatch(s: &mut MountState, handle: i32, op: u32, arg: *mut u8, arg_len: usize) -> i32 {
    match op {
        FS_OPEN | FS_OPENDIR | FS_OPEN_CREATE => {
            let mi = match longest_prefix_match(s, arg, arg_len) {
                Some(i) => i,
                None => {
                    s.route_misses = s.route_misses.wrapping_add(1);
                    return ENODEV;
                }
            };
            let n = rewrite_path(s, mi, arg, arg_len);
            let p = s.scratch.as_mut_ptr();
            let backend_h = call_volume(s, mi, -1, op, p, n);
            if backend_h < 0 {
                return backend_h;
            }
            match alloc_slot(s, mi as u8, backend_h) {
                Some(slot) => abi::kernel_abi::fd::tag_fd(abi::kernel_abi::fd::FD_TAG_FS, slot as i32),
                None => {
                    // No free mount slot — close the backend handle so it
                    // doesn't leak, then report the table-full error.
                    call_volume(s, mi, backend_h, FS_CLOSE, core::ptr::null_mut(), 0);
                    ENFILE
                }
            }
        }
        FS_UNLINK | FS_MKDIR => {
            let mi = match longest_prefix_match(s, arg, arg_len) {
                Some(i) => i,
                None => {
                    s.route_misses = s.route_misses.wrapping_add(1);
                    return ENODEV;
                }
            };
            let n = rewrite_path(s, mi, arg, arg_len);
            let p = s.scratch.as_mut_ptr();
            call_volume(s, mi, -1, op, p, n)
        }
        FS_CAPS => {
            // Report the first active volume's caps as representative; a
            // graph mounting heterogeneous FS providers is out of scope
            // (all backends are fat32 today).
            let mut mi = None;
            for i in 0..s.mount_count as usize {
                if s.mounts[i].active {
                    mi = Some(i);
                    break;
                }
            }
            match mi {
                Some(i) => call_volume(s, i, -1, FS_CAPS, arg, arg_len),
                None => 0,
            }
        }
        _ => {
            // Handle-bound op: decode the mount slot and forward to the
            // backend that owns it.
            if handle < 0 {
                return EINVAL;
            }
            let slot = abi::kernel_abi::fd::slot_of(handle) as usize;
            if slot >= MAX_OPEN || !s.opens[slot].in_use {
                return EBADF;
            }
            // Revoked by a volume unmount — fail the op and free the slot,
            // per the storage handle lease/revocation contract.
            if s.opens[slot].revoked {
                s.opens[slot].in_use = false;
                s.route_misses = s.route_misses.wrapping_add(1);
                return ENODEV;
            }
            let mi = s.opens[slot].mount_idx as usize;
            let bh = s.opens[slot].backend_handle;
            let rc = call_volume(s, mi, bh, op, arg, arg_len);
            if op == FS_CLOSE {
                s.opens[slot].in_use = false;
            }
            rc
        }
    }
}

// ── Exported PIC module interface ───────────────────────────────────────────

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_state_size")]
pub extern "C" fn module_state_size() -> usize {
    core::mem::size_of::<MountState>()
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_init")]
pub extern "C" fn module_init(_syscalls: *const c_void) {}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_new")]
pub extern "C" fn module_new(
    in_chan: i32,
    _out_chan: i32,
    _ctrl_chan: i32,
    params: *const u8,
    params_len: usize,
    state: *mut u8,
    state_size: usize,
    syscalls: *const c_void,
) -> i32 {
    unsafe {
        if syscalls.is_null() {
            return -2;
        }
        if state.is_null() || state_size < core::mem::size_of::<MountState>() {
            return -3;
        }
        let s = &mut *(state as *mut MountState);
        s.init(syscalls as *const SyscallTable);
        // in[0] is the optional hotplug control channel; -1 when unwired.
        s.ctl_chan = in_chan;

        let is_tlv =
            !params.is_null() && params_len >= 4 && *params == 0xFE && *params.add(1) == 0x01;
        if is_tlv {
            params_def::parse_tlv(s, params, params_len);
        } else {
            params_def::set_defaults(s);
        }
        0
    }
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_step")]
pub extern "C" fn module_step(state: *mut u8) -> i32 {
    // The FS path is served through provider calls; the only per-tick work
    // is draining the hotplug control channel (add/remove volumes).
    if state.is_null() {
        return -1;
    }
    // SAFETY: kernel passes this module's initialised state buffer.
    unsafe {
        let s = &mut *(state as *mut MountState);
        if !s.syscalls.is_null() {
            service_ctl(s);
            emit_telemetry(s);
        }
    }
    0
}

/// Emit the routing counters on a wall-clock cadence. Both are cumulative
/// COUNTERs per `[observability].metrics`: id 0 = `ops_routed`, id 1 =
/// `route_misses`. Gated on a subscribed consumer, so an uncollected graph
/// builds no records.
unsafe fn emit_telemetry(s: &mut MountState) {
    let sys = &*s.syscalls;
    let now_ms = dev_millis(sys);
    if now_ms.wrapping_sub(s.last_observe_ms) < MOUNT_OBSERVE_INTERVAL_MS {
        return;
    }
    s.last_observe_ms = now_ms;
    if !dev_telemetry_enabled(sys) {
        return;
    }
    let me = dev_self_index(sys);
    if me < 0 {
        return;
    }
    let t = dev_micros(sys);
    let counter = abi::contracts::telemetry::METRIC_COUNTER;
    dev_telemetry_metric(sys, -1, me as u16, t, counter, 0, s.ops_routed);
    dev_telemetry_metric(sys, -1, me as u16, t, counter, 1, s.route_misses);
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_provides_contract")]
pub extern "C" fn module_provides_contract() -> u32 {
    CONTRACT_FS
}

#[cfg_attr(not(feature = "host-test"), no_mangle)]
#[cfg_attr(not(feature = "host-test"), link_section = ".text.module_provider_dispatch")]
pub extern "C" fn module_provider_dispatch(
    state: *mut u8,
    handle: i32,
    op: u32,
    arg: *mut u8,
    arg_len: usize,
) -> i32 {
    if state.is_null() {
        return EINVAL;
    }
    // SAFETY: the kernel passes this module's own state buffer, sized for
    // `MountState` and initialised by `module_new`.
    unsafe {
        let s = &mut *(state as *mut MountState);
        if s.syscalls.is_null() {
            return EINVAL;
        }
        mount_dispatch(s, handle, op, arg, arg_len)
    }
}

/// Host-test hook: apply one control message directly, exactly as
/// `service_ctl` does when draining the hotplug channel. Lets tests drive
/// add/remove without standing up a mock channel + active context.
#[cfg(feature = "host-test")]
pub fn test_apply_ctl(state: *mut u8, msg: &[u8]) {
    if state.is_null() {
        return;
    }
    // SAFETY: the test passes its own `MountState` buffer.
    unsafe {
        let s = &mut *(state as *mut MountState);
        apply_ctl(s, msg);
    }
}

#[cfg(all(target_arch = "wasm32", not(feature = "host-test")))]
include!("../../sdk/runtime/wasm_entry.rs");
