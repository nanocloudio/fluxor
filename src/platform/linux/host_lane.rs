//! `host_lane` — a host provider process behind ports or contracts.
//!
//! The instance starts its provider (`runtime`, a binary beside this
//! runtime's own) when it is built and stops it when it is dropped, which
//! is before the graph's state is reset on a rebuild and when its owner is
//! released. Between the two it is a carrier:
//!
//! - **Ports.** Port pair *i* (`chN` in, `chN_rx` out) is lane channel *i*
//!   of the `channels` table. Each step takes whole records off `chN` and
//!   commits them to the provider's ring, and takes the provider's records
//!   off its ring onto `chN_rx`. A record the provider's ring cannot take is
//!   held or dropped by `overload`; a record `chN_rx` cannot take stays on
//!   the ring, so the provider sees the backpressure.
//! - **Contracts.** For each contract in `serves`, the instance is that
//!   contract's provider: a call reaches the provider with the calling
//!   module's identity filled in from the kernel's tables, and is answered
//!   by the key vault's resumable rule (`fluxor_host_lane::runtime`).
//!
//! - **Owner facts.** A provider that takes them is told each owner's host
//!   process as the host-process backend starts it — its init's pid and a
//!   `NETLINK_ROUTE` socket this runtime opens inside its network namespace
//!   — and when it is gone ([`owner_facts`]).
//! - **Dynamic lanes.** An instance with `lanes` is a lane target under the
//!   name `lane_target`: each lane attached there (`kernel::workload::lanes`),
//!   under the owner of the module writing its commands, becomes a dynamic lane of the provider's in attach order, its
//!   commands carried down and its events up whole, `tlv16`-framed, as port
//!   records are; detached and drained with its owner. A lane the provider
//!   cannot carry is closed, its events ending in error.
//! - **Gates.** For each wired input port and each dynamic lane the provider
//!   is told the owner whose commands arrive there and what that owner may
//!   claim — its admission, its authority, its grants under the committed
//!   plan — before any of its records, and again when that changes. A freed
//!   owner is told to the provider, which lets go of what it holds for it
//!   before the release completes.
//!
//! A provider keeps the capabilities [`provider_privilege`] names for it
//! and no others. A provider that exits closes the lane: calls out answer
//! `EIO`, records for it are held or dropped by `overload`, and `events`
//! says `closed`. Nothing a provider does can take the scheduler down with
//! it.

use std::ffi::OsString;
use std::time::Duration;

use fluxor_contracts::channel_table::{self, framing, Entry};
use fluxor_host_lane::control::{gate, Gate, OwnerFact};
use fluxor_host_lane::privilege::{cap, Privilege};
use fluxor_host_lane::runtime::{CallReq, Lane, SendError, Spec};

use crate::abi::platform::native::linux::host_lane as tags;
use crate::kernel::exec::scheduler::{self, ModuleId};
use crate::kernel::ipc::channel;
use crate::kernel::module::provider;
use crate::kernel::sys::errno;
use crate::kernel::workload::owner::OwnerHandle;

use super::native_params::{instance_state, tlv_str, tlv_u8, walk_tlv, HostNative};

/// Port pairs one instance carries: as many as `remote_channel`, so one
/// table describes a channel set whether its peer is a node or a process.
pub const PORT_CHANNELS: usize = 8;

/// Largest record a port channel may declare.
pub const PORT_RECORD_MAX: u32 = 16 << 20;

/// How long a contract call waits for its answer before answering `EAGAIN`.
pub const CALL_WAIT: Duration = Duration::from_millis(2);

/// How long a provider has to say `HELLO`.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an owner's release waits for the provider to let go of what it
/// held for the owner.
pub const RELEASE_WAIT: Duration = Duration::from_millis(200);

/// A dynamic lane's records: any `tlv16` record whole, as a socket lane
/// carries them.
const LANE_CHANNEL: &str = "NetProto:tlv16:65538";

/// Grant bytes one gate carries for an owner; an owner with more is gated
/// as granted nothing.
const GRANTS_MAX: usize = 512;

/// Records moved per port per step, each way.
const BURST: usize = 32;

/// `overload` values.
mod overload {
    pub const BLOCK: u8 = 0;
    pub const DROP_OLDEST: u8 = 1;
    pub const DROP_NEWEST: u8 = 2;
}

/// `events` records.
pub mod event {
    /// The lane is open.
    pub const OPENED: u8 = 1;
    /// The provider exited or broke the protocol; nothing crosses now.
    pub const CLOSED: u8 = 2;
}

/// The environment a provider is started with: the names it may read from
/// this runtime's, and nothing else. Secrets reach a provider this way and
/// never as params, which land in the node image.
fn provider_env(runtime: &str) -> &'static [&'static str] {
    match runtime {
        "fluxor-provider-hsm" => &["FLUXOR_HSM_USER_PIN", "SOFTHSM2_CONF"],
        // The search path its rule tool is found on; the instance's names on
        // its host and where the host registry and tunables live; the policy
        // dry-run directory.
        "fluxor-provider-net" => &[
            "PATH",
            "FLUXOR_STATE_DIR",
            "FLUXOR_INSTANCE",
            "FLUXOR_RUN_DIR",
            "FLUXOR_TUNABLE_DIR",
            "FLUXOR_NET_POLICY_DRYRUN",
        ],
        _ => &[],
    }
}

/// What this runtime tells a provider of its own, beside [`provider_env`]:
/// the network provider, in node-agent mode, is told the directory the
/// owner facts land in (beside the owner plan, `FLUXOR_PLAN`), and writes
/// its bound-endpoint report there
/// (`abi::platform::linux::bound_endpoints`).
fn provider_told(runtime: &str) -> Vec<(OsString, OsString)> {
    use crate::abi::platform::linux::bound_endpoints;
    if runtime != "fluxor-provider-net" {
        return Vec::new();
    }
    let Some(plan) = std::env::var_os("FLUXOR_PLAN") else {
        return Vec::new();
    };
    let plan = std::path::Path::new(&plan);
    let dir = match plan.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => std::path::Path::new("."),
    };
    match std::path::absolute(dir) {
        Ok(dir) => vec![(
            OsString::from(bound_endpoints::DIR_ENV),
            dir.into_os_string(),
        )],
        Err(e) => {
            log::warn!("[host_lane] owner facts directory unknown: {e}");
            Vec::new()
        }
    }
}

/// The capabilities a provider keeps; every other is dropped before it
/// runs. The network provider administers links, addresses, routes and the
/// node's `nft` tables (`CAP_NET_ADMIN`), sends link-layer frames of its
/// own — the forwarding probe, a held address's announcement
/// (`CAP_NET_RAW`) — and binds the host ports its graph's sockets ask for,
/// those below 1024 included (`CAP_NET_BIND_SERVICE`); it enters no
/// namespace itself — this runtime hands it a netlink socket inside each
/// owner's — so it holds no `CAP_SYS_ADMIN`.
fn provider_privilege(runtime: &str) -> Privilege {
    match runtime {
        "fluxor-provider-net" => {
            Privilege::of(&[cap::NET_ADMIN, cap::NET_RAW, cap::NET_BIND_SERVICE])
        }
        _ => Privilege::NONE,
    }
}

/// Every live instance, for [`stop_all`].
static LIVE: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

fn live() -> std::sync::MutexGuard<'static, Vec<usize>> {
    LIVE.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

extern "C" fn stop_all_at_exit() {
    stop_all();
}

/// Stop every live instance's provider: each is told `STOP` and takes down
/// what it holds on the host before it exits. The runtime's exit runs this
/// (also by `atexit`): a provider killed with its runtime instead leaves
/// its host state for its next start to reconcile.
pub fn stop_all() {
    let all = std::mem::take(&mut *live());
    for p in all {
        // SAFETY: an address in `LIVE` is a boxed instance not yet dropped
        // (its drop removes it); the process is ending, and nothing steps it
        // after this.
        let st = unsafe { &mut *(p as *mut HostLane) };
        st.lane.stop();
    }
}

/// A runtime name names one file beside this runtime, and nothing else.
fn runtime_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// A workload's lane, carried as one of the provider's dynamic lanes.
struct DynLane {
    /// The provider's key for it.
    key: u8,
    owner: OwnerHandle,
    /// The workload's own key for it (`kernel_abi::lane`).
    owner_key: u8,
    commands: i32,
    events: i32,
    staged: Option<Vec<u8>>,
    held: Option<Vec<u8>>,
    /// The gate flags last told for it.
    told: Option<u8>,
}

/// One instance.
pub struct HostLane {
    slot: usize,
    lane: Lane,
    ins: [i32; PORT_CHANNELS],
    outs: [i32; PORT_CHANNELS],
    events: i32,
    overload: u8,
    /// A record taken off `chN` that the provider's ring has not taken.
    staged: [Option<Vec<u8>>; PORT_CHANNELS],
    /// A record taken off the provider's ring that `chN_rx` has not taken.
    held: [Option<Vec<u8>>; PORT_CHANNELS],
    dropped: [u64; PORT_CHANNELS],
    malformed: [u64; PORT_CHANNELS],
    serves: Vec<u16>,
    /// Callers that hold something at the provider: told to it when they go.
    callers: Vec<(u16, u32)>,
    /// Owner facts told to the provider, and the [`owner_facts`] generation
    /// they were last compared at.
    told: Vec<(OwnerHandle, u32)>,
    facts_seen: u64,
    opened_said: bool,
    closed_said: bool,
    rx: Vec<u8>,
    /// Per wired input port, its producer's owner and the gate flags last
    /// told for it.
    port_gates: [Option<(OwnerHandle, u8)>; PORT_CHANNELS],
    /// The workload lanes this instance carries, when it is a lane target.
    lanes: Vec<DynLane>,
    lane_entry: Entry,
    lane_rx: Vec<u8>,
}

/// Parse `serves`: comma-separated registry names of contracts a lane can
/// carry.
fn parse_serves(text: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    for name in text.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let id = crate::abi::registry::contract_id(name)
            .ok_or_else(|| format!("`serves` names {name:?}, which is no contract"))?;
        if fluxor_host_lane::served::served(id).is_none() {
            return Err(format!(
                "`serves` names {name:?}, which a host lane does not carry"
            ));
        }
        if out.contains(&id) {
            return Err(format!("`serves` names {name:?} twice"));
        }
        out.push(id);
    }
    Ok(out)
}

/// The 32 bytes 64 hex digits spell; `None` for anything else.
fn digest_of_hex(hex: &str) -> Option<[u8; 32]> {
    let b = hex.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let nib = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
    }
    Some(out)
}

fn build(slot: usize, params: &[u8]) -> Result<Box<HostLane>, i32> {
    let mut runtime = String::new();
    let mut channels = String::new();
    let mut args = String::new();
    let mut overload = overload::DROP_OLDEST;
    let mut serves_text = String::new();
    let mut lane_target = String::new();
    let mut lanes_cap = 0usize;
    let mut pin_hex = String::new();
    walk_tlv(params, |tag, value| match tag {
        tags::TAG_RUNTIME => runtime = tlv_str(value).to_string(),
        tags::TAG_CHANNELS => channels = tlv_str(value).to_string(),
        tags::TAG_ARGS => args = tlv_str(value).to_string(),
        tags::TAG_OVERLOAD => overload = tlv_u8(value),
        tags::TAG_SERVES => serves_text = tlv_str(value).to_string(),
        tags::TAG_LANE_TARGET => lane_target = tlv_str(value).to_string(),
        tags::TAG_LANES => lanes_cap = usize::from(tlv_u8(value)),
        tags::TAG_RUNTIME_DIGEST => pin_hex = tlv_str(value).to_string(),
        _ => {}
    });
    let refuse = |why: &str| {
        log::error!("[inst] module {slot} = host_lane refused: {why}");
        errno::EINVAL
    };
    if !runtime_name_ok(&runtime) {
        return Err(refuse("`runtime` must name one binary beside the runtime"));
    }
    let Some(pin) = digest_of_hex(&pin_hex) else {
        return Err(refuse(
            "`runtime_digest` is not the 64 hex digits of the provider binary's SHA-256: \
             the node image pins the provider it runs",
        ));
    };
    if !matches!(
        overload,
        overload::BLOCK | overload::DROP_OLDEST | overload::DROP_NEWEST
    ) {
        return Err(refuse(
            "`overload` is not block, drop_oldest or drop_newest",
        ));
    }
    let mut table = [Entry::EMPTY; PORT_CHANNELS];
    let n_ports = if channels.trim().is_empty() {
        0
    } else {
        channel_table::parse_into(channels.as_bytes(), PORT_RECORD_MAX, &mut table)
            .map_err(|e| refuse(&format!("`channels` refused: {e:?}")))?
    };
    let serves = parse_serves(&serves_text).map_err(|why| refuse(&why))?;
    if n_ports == 0 && serves.is_empty() && lanes_cap == 0 {
        return Err(refuse(
            "neither `channels`, `serves` nor `lanes`: the lane would carry nothing",
        ));
    }
    if (lanes_cap > 0) == lane_target.is_empty() {
        return Err(refuse(
            "`lanes` and `lane_target` go together: dynamic lanes are reached by the target's name",
        ));
    }
    let mut lane_entry = [Entry::EMPTY; 1];
    channel_table::parse_into(LANE_CHANNEL.as_bytes(), PORT_RECORD_MAX, &mut lane_entry)
        .map_err(|e| refuse(&format!("the lane channel refused: {e:?}")))?;

    let mut ins = [-1i32; PORT_CHANNELS];
    let mut outs = [-1i32; PORT_CHANNELS];
    for i in 0..PORT_CHANNELS {
        ins[i] = scheduler::module_port(slot, (tags::PORT_CH0.0, tags::PORT_CH0.1 + i as u8));
        outs[i] =
            scheduler::module_port(slot, (tags::PORT_CH0_RX.0, tags::PORT_CH0_RX.1 + i as u8));
        if i >= n_ports && (ins[i] >= 0 || outs[i] >= 0) {
            return Err(refuse(&format!(
                "port pair {i} is wired but `channels` has no entry {i}"
            )));
        }
    }
    let events = scheduler::module_port(slot, tags::PORT_EVENTS);

    // Beside this runtime, where `fluxor sync` puts a project's runtimes.
    let binary = match std::env::current_exe() {
        Ok(exe) => exe.with_file_name(&runtime),
        Err(e) => return Err(refuse(&format!("this runtime's own path is unknown: {e}"))),
    };
    if !binary.is_file() {
        log::error!(
            "[inst] module {slot} = host_lane refused: no provider `{runtime}` at {}",
            binary.display()
        );
        return Err(errno::ENOENT);
    }
    let mut env: Vec<(OsString, OsString)> = provider_env(&runtime)
        .iter()
        .filter_map(|&name| std::env::var_os(name).map(|v| (OsString::from(name), v)))
        .collect();
    env.extend(provider_told(&runtime));
    let lane = Lane::open(Spec {
        binary,
        args,
        env,
        ports: table[..n_ports].to_vec(),
        contracts: serves.clone(),
        digest: crate::abi::abi_surface::ABI_SURFACE_DIGEST,
        pin,
        hello_timeout: HELLO_TIMEOUT,
        privilege: provider_privilege(&runtime),
        lanes: lanes_cap,
    })
    .map_err(|e| {
        log::error!("[inst] module {slot} = host_lane refused: `{runtime}`: {e}");
        errno::EIO
    })?;
    let max = table[..n_ports]
        .iter()
        .map(|e| e.max_record as usize)
        .max()
        .unwrap_or(0);
    let mut st = Box::new(HostLane {
        slot,
        lane,
        ins,
        outs,
        events,
        overload,
        staged: Default::default(),
        held: Default::default(),
        dropped: [0; PORT_CHANNELS],
        malformed: [0; PORT_CHANNELS],
        serves,
        callers: Vec::new(),
        told: Vec::new(),
        facts_seen: u64::MAX,
        opened_said: false,
        closed_said: false,
        rx: vec![0u8; max],
        port_gates: [None; PORT_CHANNELS],
        lanes: Vec::new(),
        lane_entry: lane_entry[0],
        lane_rx: vec![0u8; lane_entry[0].max_record as usize],
    });
    if !st.serves.is_empty() {
        let state = (&raw mut *st).cast::<u8>();
        for &c in &st.serves {
            let rc = provider::register_module_provider(
                c,
                slot as ModuleId,
                host_lane_dispatch,
                state,
                0,
                provider::LayerScope::Owner,
            );
            if rc < 0 {
                provider::release_module_providers(slot as ModuleId);
                log::error!(
                    "[inst] module {slot} = host_lane refused: contract {c:#06x} could not be \
                     registered (rc={rc})"
                );
                return Err(rc);
            }
        }
        let rc = provider::register_owner_release_observer(slot as ModuleId);
        if rc < 0 {
            provider::release_module_providers(slot as ModuleId);
            return Err(rc);
        }
    }
    if lanes_cap > 0 {
        let rc = crate::kernel::workload::lanes::declare(
            slot,
            crate::abi::wire::fnv1a32(lane_target.as_bytes()),
            lanes_cap,
        );
        if rc != 0 {
            provider::release_module_providers(slot as ModuleId);
            log::error!(
                "[inst] module {slot} = host_lane refused: lane target `{lane_target}` (rc={rc})"
            );
            return Err(rc);
        }
    }
    // Every wired input's owner, before any of its records.
    for i in 0..n_ports {
        if st.ins[i] >= 0 {
            let owner = scheduler::channel_producer_owner(st.ins[i]);
            st.tell_gate(gate::PORT, i as u8, owner);
        }
    }
    {
        static AT_EXIT: std::sync::Once = std::sync::Once::new();
        AT_EXIT.call_once(|| {
            // SAFETY: registers a plain extern "C" fn with no captured state.
            unsafe {
                libc::atexit(stop_all_at_exit);
            }
        });
        live().push((&raw mut *st) as usize);
    }
    log::info!(
        "[inst] module {slot} = host_lane (native) runtime={runtime} ports={n_ports} serves={:?} lanes={lanes_cap} pid={} incarnation={:02x?}",
        st.serves,
        st.lane.pid().unwrap_or(0),
        &st.lane.incarnation()[..4]
    );
    Ok(st)
}

impl HostNative for HostLane {
    fn build(slot: usize, params: &[u8]) -> Result<Box<Self>, i32> {
        build(slot, params)
    }
}

impl Drop for HostLane {
    /// The provider is stopped with the instance, and the contracts it
    /// served go with it.
    fn drop(&mut self) {
        let me = core::ptr::from_mut(self) as usize;
        live().retain(|&p| p != me);
        if !self.serves.is_empty() {
            provider::release_module_providers(self.slot as ModuleId);
        }
        self.lane.stop();
        log::info!(
            "[host_lane] module {} stopped; dropped {:?} malformed {:?}",
            self.slot,
            &self.dropped[..self.lane.ports()],
            &self.malformed[..self.lane.ports()]
        );
    }
}

/// The `host_lane` native module.
pub static HOST_LANE: scheduler::NativeVtable =
    super::native_params::host_vtable::<HostLane>(host_lane_step, tags::STATE_BYTES);

/// Write one `events` record, if the port is wired. `true` once written.
fn say(events: i32, ev: u8) -> bool {
    if events < 0 {
        return true;
    }
    // SAFETY: a one-byte stack record.
    unsafe { channel::channel_write(events, &ev, 1) == 1 }
}

/// The next whole record waiting on channel `ch`, framed as `e` says; a
/// record the framing cannot have counts in `malformed`.
fn take_framed(ch: i32, e: &Entry, malformed: &mut u64) -> Option<Vec<u8>> {
    {
        let max = e.max_record as usize;
        match e.framing {
            framing::MAILBOX => {
                let n = channel::channel_record_len(ch);
                if n <= 0 {
                    return None;
                }
                let mut rec = vec![0u8; n as usize];
                // SAFETY: a buffer of the record's length.
                let r = unsafe { channel::channel_read(ch, rec.as_mut_ptr(), rec.len()) };
                if r <= 0 {
                    return None;
                }
                rec.truncate(r as usize);
                if rec.len() > max {
                    *malformed += 1;
                    return None;
                }
                Some(rec)
            }
            framing::BYTES => {
                let n = channel::channel_readable_bytes(ch).min(max);
                if n == 0 {
                    return None;
                }
                let mut rec = vec![0u8; n];
                // SAFETY: a buffer of `n` bytes.
                let r = unsafe { channel::channel_read(ch, rec.as_mut_ptr(), n) };
                if r <= 0 {
                    return None;
                }
                rec.truncate(r as usize);
                Some(rec)
            }
            _ => {
                let h = e.header_len();
                let mut hdr = [0u8; channel_table::HDR_MAX];
                // SAFETY: a stack buffer of at least `h` bytes.
                if unsafe { channel::channel_peek(ch, hdr.as_mut_ptr(), h) } != h as i32 {
                    return None;
                }
                let want = e.record_len(&hdr[..h]);
                if want < h as u64 || want > max as u64 {
                    // A record this edge's framing cannot have: the stream
                    // cannot be resynchronised, so what is buffered goes.
                    channel::channel_discard(ch, channel::channel_readable_bytes(ch));
                    *malformed += 1;
                    return None;
                }
                let want = want as usize;
                if channel::channel_readable_bytes(ch) < want {
                    return None;
                }
                let mut rec = vec![0u8; want];
                // SAFETY: a buffer of `want` bytes, all of them buffered.
                let r = unsafe { channel::channel_read(ch, rec.as_mut_ptr(), want) };
                if r != want as i32 {
                    return None;
                }
                Some(rec)
            }
        }
    }
}

impl HostLane {
    /// The next whole record waiting on `chN`, framed as its entry says.
    fn take_record(&mut self, i: usize) -> Option<Vec<u8>> {
        let e = *self.lane.port_entry(i)?;
        take_framed(self.ins[i], &e, &mut self.malformed[i])
    }

    /// Port `i`, graph to provider.
    fn pump_in(&mut self, i: usize) {
        for _ in 0..BURST {
            if self.staged[i].is_none() {
                match self.take_record(i) {
                    Some(r) => self.staged[i] = Some(r),
                    None => return,
                }
            }
            let Some(rec) = self.staged[i].take() else {
                return;
            };
            match self.lane.send(i, &rec) {
                Ok(()) => continue,
                Err(SendError::TooBig | SendError::NoPort) => {
                    self.malformed[i] += 1;
                    continue;
                }
                Err(SendError::Full | SendError::Closed) => {}
            }
            match self.overload {
                overload::DROP_OLDEST => match self.take_record(i) {
                    Some(newer) => {
                        self.dropped[i] += 1;
                        self.staged[i] = Some(newer);
                    }
                    None => {
                        self.staged[i] = Some(rec);
                        return;
                    }
                },
                overload::DROP_NEWEST => {
                    self.staged[i] = Some(rec);
                    match self.take_record(i) {
                        Some(_) => self.dropped[i] += 1,
                        None => return,
                    }
                }
                _ => {
                    self.staged[i] = Some(rec);
                    return;
                }
            }
        }
    }

    /// Port `i`, provider to graph.
    fn pump_out(&mut self, i: usize) {
        let ch = self.outs[i];
        for _ in 0..BURST {
            if let Some(rec) = self.held[i].take() {
                // SAFETY: a live buffer of the record's length.
                let w = unsafe { channel::channel_write(ch, rec.as_ptr(), rec.len()) };
                if w != rec.len() as i32 {
                    self.held[i] = Some(rec);
                    return;
                }
                continue;
            }
            match self.lane.recv(i, &mut self.rx) {
                Ok(Some(n)) => self.held[i] = Some(self.rx[..n].to_vec()),
                _ => return,
            }
        }
    }

    /// Bring the provider's owner facts up to [`owner_facts`]: new owners
    /// told with a netlink socket in their network namespace, gone ones told
    /// gone.
    fn sync_owner_facts(&mut self) {
        if !self.lane.takes_owners() {
            return;
        }
        let Some((generation, facts)) = owner_facts::snapshot_if_newer(self.facts_seen) else {
            return;
        };
        self.facts_seen = generation;
        let mut k = 0;
        while k < self.told.len() {
            let (o, pid) = self.told[k];
            if facts.iter().any(|f| f.0 == o && f.1 == pid) {
                k += 1;
            } else {
                self.told.swap_remove(k);
                self.lane.owner_fact_gone(o.slot, o.generation);
            }
        }
        for &(o, pid, uid) in &facts {
            if self.told.iter().any(|t| t.0 == o) {
                continue;
            }
            let netlink = owner_facts::netlink_in(pid);
            self.lane.owner_fact(
                OwnerFact {
                    slot: o.slot,
                    generation: o.generation,
                    owner_uid: uid,
                    pid,
                },
                netlink.as_ref(),
            );
            self.told.push((o, pid));
        }
    }

    /// Tell the provider what `owner` may claim through port entry `index`
    /// (`on` = [`gate::PORT`]) or dynamic lane `index` ([`gate::LANE`]) now,
    /// and remember what was told.
    fn tell_gate(&mut self, on: u8, index: u8, owner: OwnerHandle) {
        let told = gate_flags(owner);
        let mut grants = [0u8; GRANTS_MAX];
        let mut len = 0usize;
        if !owner.is_node() {
            let mut arg = [0u8; 8];
            arg[..2].copy_from_slice(&owner.slot.to_le_bytes());
            arg[4..].copy_from_slice(&owner.generation.to_le_bytes());
            // Grants past what one gate carries are none.
            let n = crate::kernel::workload::endpoints::owner_grants(
                owner.slot,
                owner.generation,
                &mut arg,
                &mut grants,
            );
            len = usize::try_from(n).unwrap_or(0);
        }
        let g = Gate {
            on,
            index,
            owner_slot: owner.slot,
            owner_generation: owner.generation,
            flags: told,
            grants: grants[..len].to_vec(),
        };
        if let Err(rc) = self.lane.gate(&g) {
            log::warn!(
                "[host_lane] module {}: gate for owner slot {} not told (rc={rc})",
                self.slot,
                owner.slot
            );
        }
        if on == gate::PORT {
            if let Some(g) = self.port_gates.get_mut(usize::from(index)) {
                *g = Some((owner, told));
            }
        } else if let Some(l) = self.lanes.iter_mut().find(|l| l.key == index) {
            l.told = Some(told);
        }
    }

    /// Tell the provider every gate whose owner's admission or authority
    /// moved since it was last told.
    fn refresh_gates(&mut self) {
        for i in 0..PORT_CHANNELS {
            if let Some((owner, told)) = self.port_gates[i] {
                if !owner.is_node() && gate_flags(owner) != told {
                    self.tell_gate(gate::PORT, i as u8, owner);
                }
            }
        }
        for k in 0..self.lanes.len() {
            let (key, owner, told) = (self.lanes[k].key, self.lanes[k].owner, self.lanes[k].told);
            if told != Some(gate_flags(owner)) {
                self.tell_gate(gate::LANE, key, owner);
            }
        }
    }

    /// Take every lane change the kernel queued for this instance, before
    /// any lane's records move.
    fn take_lanes(&mut self) {
        use crate::abi::kernel_abi::lane;
        if self.lane.lanes_capacity() == 0 {
            return;
        }
        let mut rec = [0u8; lane::RECORD_LEN];
        while crate::kernel::workload::lanes::take(self.slot, &mut rec) == lane::RECORD_LEN as i32 {
            let owner = OwnerHandle {
                slot: u16::from_le_bytes([
                    rec[lane::OFF_OWNER_SLOT],
                    rec[lane::OFF_OWNER_SLOT + 1],
                ]),
                generation: u32::from_le_bytes([
                    rec[lane::OFF_OWNER_GEN],
                    rec[lane::OFF_OWNER_GEN + 1],
                    rec[lane::OFF_OWNER_GEN + 2],
                    rec[lane::OFF_OWNER_GEN + 3],
                ]),
            };
            let word =
                |at: usize| i32::from_le_bytes([rec[at], rec[at + 1], rec[at + 2], rec[at + 3]]);
            match rec[lane::OFF_OP] {
                lane::OP_ATTACH => {
                    self.attach(
                        owner,
                        rec[lane::OFF_KEY],
                        word(lane::OFF_COMMANDS),
                        word(lane::OFF_EVENTS),
                    );
                }
                lane::OP_DETACH => {
                    let mut k = 0;
                    while k < self.lanes.len() {
                        if self.lanes[k].owner == owner {
                            let l = self.lanes.swap_remove(k);
                            let _ = self.lane.lane_del(l.key);
                            log::info!(
                                "[host_lane] module {}: owner slot {} lane {} detached",
                                self.slot,
                                owner.slot,
                                l.owner_key
                            );
                        } else {
                            k += 1;
                        }
                    }
                }
                lane::OP_DRAIN => {
                    for k in 0..self.lanes.len() {
                        if self.lanes[k].owner == owner {
                            let key = self.lanes[k].key;
                            let _ = self.lane.lane_drain(key);
                            self.tell_gate(gate::LANE, key, owner);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Carry `(commands, events)`, lane `owner_key` of `owner`, as a dynamic
    /// lane of the provider's. A lane the provider cannot carry is closed:
    /// its events end in error and its commands are read by no one, so its
    /// module sees the refusal rather than a lane that never answers.
    fn attach(&mut self, owner: OwnerHandle, owner_key: u8, commands: i32, events: i32) {
        if commands < 0 || events < 0 || commands == events {
            log::warn!(
                "[host_lane] module {}: owner slot {} lane {owner_key} refused: its channels",
                self.slot,
                owner.slot
            );
            refuse_lane(commands, events);
            return;
        }
        let Some(key) = (0..=u8::MAX).find(|k| !self.lanes.iter().any(|l| l.key == *k)) else {
            log::warn!(
                "[host_lane] module {}: owner slot {} lane {owner_key} refused: no lane key free",
                self.slot,
                owner.slot
            );
            refuse_lane(commands, events);
            return;
        };
        let rc = self.lane.lane_add(
            key,
            owner.slot,
            owner.generation,
            self.lane_entry.max_record,
        );
        if let Err(rc) = rc {
            log::warn!(
                "[host_lane] module {}: owner slot {} lane {owner_key} not carried (rc={rc})",
                self.slot,
                owner.slot
            );
            refuse_lane(commands, events);
            return;
        }
        self.lanes.push(DynLane {
            key,
            owner,
            owner_key,
            commands,
            events,
            staged: None,
            held: None,
            told: None,
        });
        self.tell_gate(gate::LANE, key, owner);
        log::info!(
            "[host_lane] module {}: owner slot {} lane {owner_key} carried as lane {key}",
            self.slot,
            owner.slot
        );
    }

    /// Dynamic lane `k`'s records, both ways. Its commands wait on their
    /// channel while the provider's ring is full: the workload's producer
    /// sees the back-pressure.
    fn pump_lane(&mut self, k: usize) {
        let mut dropped = 0u64;
        for _ in 0..BURST {
            let l = &mut self.lanes[k];
            if l.staged.is_none() {
                l.staged = take_framed(l.commands, &self.lane_entry, &mut dropped);
            }
            let Some(rec) = l.staged.take() else {
                break;
            };
            match self.lane.lane_send(l.key, &rec) {
                Ok(()) => {}
                Err(SendError::TooBig | SendError::NoPort) => dropped += 1,
                Err(SendError::Full | SendError::Closed) => {
                    self.lanes[k].staged = Some(rec);
                    break;
                }
            }
        }
        for _ in 0..BURST {
            let l = &mut self.lanes[k];
            if let Some(rec) = l.held.take() {
                // SAFETY: a live buffer of the record's length.
                let w = unsafe { channel::channel_write(l.events, rec.as_ptr(), rec.len()) };
                if w != rec.len() as i32 {
                    l.held = Some(rec);
                    break;
                }
                continue;
            }
            let key = l.key;
            match self.lane.lane_recv(key, &mut self.lane_rx) {
                Ok(Some(n)) => self.lanes[k].held = Some(self.lane_rx[..n].to_vec()),
                _ => break,
            }
        }
        if dropped > 0 {
            log::warn!(
                "[host_lane] module {}: lane {} dropped {dropped} record(s) its framing cannot have",
                self.slot,
                self.lanes[k].owner_key
            );
        }
    }

    /// Tell the provider about callers that are gone.
    fn reap_callers(&mut self) {
        let mut k = 0;
        while k < self.callers.len() {
            let (s, g) = self.callers[k];
            if scheduler::module_slot_generation(s as usize) != g {
                self.callers.swap_remove(k);
                self.lane.caller_gone(s, g);
            } else {
                k += 1;
            }
        }
    }
}

/// Close a lane the provider does not carry: its events end in error (HUP
/// and ERR, which a module polling them reads as the lane refused), and
/// its commands are committed and dropped, so their producer never waits
/// on a reader that does not exist. The channels stay the owner's, closed
/// with its edges.
fn refuse_lane(commands: i32, events: i32) {
    if events >= 0 {
        channel::channel_producer_gone(events, true);
    }
    if commands >= 0 && commands != events {
        channel::channel_set_reader_gone(commands);
    }
}

/// # Safety
/// `state` is this instance's arena state, the step's alone.
unsafe extern "C" fn host_lane_step(state: *mut u8) -> i32 {
    // SAFETY: the kernel hands the step its own instance's state.
    let st = unsafe { instance_state::<HostLane>(state) };
    if !st.opened_said {
        st.opened_said = say(st.events, event::OPENED);
    }
    if !st.serves.is_empty() {
        st.lane
            .tick(|s, g| scheduler::module_slot_generation(s as usize) == g);
        st.reap_callers();
    } else {
        st.lane.poll_control();
    }
    st.sync_owner_facts();
    st.take_lanes();
    st.refresh_gates();
    for k in 0..st.lanes.len() {
        st.pump_lane(k);
    }
    for i in 0..st.lane.ports() {
        if st.ins[i] >= 0 {
            st.pump_in(i);
        }
        if st.outs[i] >= 0 {
            st.pump_out(i);
        }
    }
    if st.lane.is_closed() && !st.closed_said {
        st.closed_said = say(st.events, event::CLOSED);
        if st.closed_said {
            log::warn!("[host_lane] module {}: lane closed", st.slot);
        }
    }
    0
}

/// The gate flags of `owner` now: whether it admits new work.
fn gate_flags(owner: OwnerHandle) -> u8 {
    if owner.is_node() || scheduler::owners().authorize_admit(owner) {
        gate::OPEN
    } else {
        0
    }
}

/// The uid of `owner`, or zeros when it resolves to nothing.
fn uid_of(owner: OwnerHandle) -> [u8; 16] {
    scheduler::owners()
        .lookup(owner)
        .map_or([0; 16], |e| e.owner_uid)
}

/// The opaque owner key a lane files calls under.
fn owner_key(owner: OwnerHandle) -> u64 {
    (u64::from(owner.slot) << 32) | u64::from(owner.generation)
}

/// A served contract's call, made by the module the kernel names as the
/// caller.
///
/// # Safety
/// `state` is the instance this dispatch was registered with; `arg` is
/// valid for `arg_len` bytes of reads and writes for the call.
unsafe extern "C" fn host_lane_dispatch(
    state: *mut u8,
    handle: i32,
    opcode: u32,
    arg: *mut u8,
    arg_len: usize,
    data: *mut u8,
    data_len: usize,
) -> i32 {
    // SAFETY: the registered state is the boxed instance, alive while its
    // layers are.
    let st = unsafe { &mut *state.cast::<HostLane>() };
    let arg: &mut [u8] = if arg.is_null() || arg_len == 0 {
        &mut []
    } else {
        // SAFETY: the caller's contract.
        unsafe { core::slice::from_raw_parts_mut(arg, arg_len) }
    };
    if opcode == crate::abi::internal::reconfigure::OWNER_RELEASED {
        if let (Some(s), Some(g)) = (arg.get(0..2), arg.get(4..8)) {
            let owner = OwnerHandle {
                slot: u16::from_le_bytes([s[0], s[1]]),
                generation: u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
            };
            st.lane.owner_gone(owner_key(owner));
            owner_facts::ended(owner);
            if !st
                .lane
                .owner_released(owner.slot, owner.generation, RELEASE_WAIT)
            {
                log::warn!(
                    "[host_lane] module {}: the provider did not let go of owner slot {} within {:?}",
                    st.slot,
                    owner.slot,
                    RELEASE_WAIT
                );
            }
        }
        return 0;
    }
    let contract = ((opcode >> 8) & 0xFF) as u16;
    if !st.serves.contains(&contract) {
        return errno::ENOSYS;
    }
    let data: &mut [u8] = if data.is_null() || data_len == 0 {
        &mut []
    } else {
        // SAFETY: the caller's contract: `data` is the op's span, valid for
        // `data_len` bytes of reads and writes for the call.
        unsafe { core::slice::from_raw_parts_mut(data, data_len) }
    };
    let caller_idx = scheduler::caller_module_index();
    let slot = caller_idx as u16;
    let generation = scheduler::module_slot_generation(caller_idx);
    let owner = scheduler::module_owner(caller_idx);
    let authority = scheduler::owners().authority_of(owner);
    let req = CallReq {
        caller: fluxor_host_lane::frame::Caller {
            slot,
            generation,
            owner_uid: uid_of(owner),
            authority_uid: uid_of(authority),
        },
        owner: owner_key(owner),
        contract,
        opcode,
        handle,
    };
    let rc = st.lane.call_data(req, arg, data, CALL_WAIT).rc;
    if rc >= 0 && !st.callers.contains(&(slot, generation)) {
        st.callers.push((slot, generation));
    }
    rc
}

/// Owner facts: which owners run a host process, and its init's pid. The
/// host-process backend states them as it starts and ends a workload; each
/// `host_lane` whose provider takes owner facts tells its provider the
/// difference on its next step.
pub mod owner_facts {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::sync::Mutex;

    use crate::kernel::exec::scheduler;
    use crate::kernel::workload::owner::OwnerHandle;

    /// One running owner: `(owner, its init's pid, owner_uid)`.
    pub type Fact = (OwnerHandle, u32, [u8; 16]);

    /// Every running owner, and a generation that moves with every change.
    struct Facts {
        generation: u64,
        live: Vec<Fact>,
    }

    static FACTS: Mutex<Facts> = Mutex::new(Facts {
        generation: 0,
        live: Vec::new(),
    });

    fn with<R>(f: impl FnOnce(&mut Facts) -> R) -> R {
        let mut g = FACTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut g)
    }

    /// `owner`'s host process started; its init is `pid`.
    pub fn started(owner: OwnerHandle, pid: u32) {
        let uid = scheduler::owners()
            .lookup(owner)
            .map_or([0; 16], |e| e.owner_uid);
        with(|f| {
            f.live.retain(|e| e.0 != owner);
            f.live.push((owner, pid, uid));
            f.generation += 1;
        });
    }

    /// `owner`'s host process is gone (or the owner is released).
    pub fn ended(owner: OwnerHandle) {
        with(|f| {
            let before = f.live.len();
            f.live.retain(|e| e.0 != owner);
            if f.live.len() != before {
                f.generation += 1;
            }
        });
    }

    /// The owner whose host process `pid` was has ended (it exited, or was
    /// destroyed): its facts end.
    pub fn process_ended(pid: u32) {
        with(|f| {
            let before = f.live.len();
            f.live.retain(|e| e.1 != pid);
            if f.live.len() != before {
                f.generation += 1;
            }
        });
    }

    /// The facts and their generation, when it differs from `seen`.
    pub fn snapshot_if_newer(seen: u64) -> Option<(u64, Vec<Fact>)> {
        with(|f| (f.generation != seen).then(|| (f.generation, f.live.clone())))
    }

    /// A `NETLINK_ROUTE` socket inside the network namespace of process
    /// `pid`, opened on a thread of its own that enters the namespace and
    /// ends: no runtime thread changes namespace. `None` when the namespace
    /// cannot be entered (the runtime lacks the privilege, or the process
    /// is gone); the provider is then told the owner without one.
    pub fn netlink_in(pid: u32) -> Option<OwnedFd> {
        let path = format!("/proc/{pid}/ns/net");
        let ns = std::fs::File::open(path).ok()?;
        std::thread::scope(|sc| {
            sc.spawn(|| {
                use std::os::fd::AsRawFd;
                // SAFETY: `ns` is an open namespace descriptor; setns
                // changes this short-lived thread's namespace alone.
                if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
                    return None;
                }
                // SAFETY: integer arguments only.
                let fd = unsafe {
                    libc::socket(
                        libc::AF_NETLINK,
                        libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                        libc::NETLINK_ROUTE,
                    )
                };
                // SAFETY: a descriptor just returned to us, owned by nothing
                // else.
                (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
            })
            .join()
            .ok()
            .flatten()
        })
    }
}
