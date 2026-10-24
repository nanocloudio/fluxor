//! net.route (0x20) on Linux: the kernel's tables (`kernel::net_route`)
//! realized in the host's network domain.
//!
//! Everything here is keyed by this runtime's instance (`instance.rs`): its
//! tag names the host objects, its registry claims guard the prefixes and
//! gateways against other runtimes, its routing table and rule priority come
//! from the registry, and the host tunables it changes are recorded there and
//! restored when the last dependent leaves.
//!
//! | Concept | Realization |
//! |---|---|
//! | Gateway | `gateway/32` on the instance's dummy link `fx<stem>g`. |
//! | Attachment | Inside the workload's domain (`net_identity.rs`): `addr/32`, a permanent neighbour entry gateway → the host end's MAC, `default via gateway onlink`, MTU. Node side: the host end up, no address, `addr/32 dev <link> src <gateway>` in the instance table. |
//! | Rule | `from all lookup <instance table>` before main. |
//! | Anti-spoofing | In the instance's guard, per workload link: a packet arriving on it from any source but that workload's address is dropped (before routing, whatever the host's reverse-path setting). |
//! | Forwarding | On each workload link, and on each uplink (the links peers and default routes leave by) through the registry. |
//! | Forward guard | `ct state established,related accept`; `iif ∈ instance links accept`; `oif ∈ instance links, daddr ∈ cluster accept`; other traffic on instance links dropped. On an uplink whose forwarding the registry itself turned on, forwarded traffic that is neither translated nor established is dropped (the node does not become a router for its LAN); an uplink the host already forwarded on is left alone. |
//! | Redirects | `send_redirects` off globally and on each uplink, through the registry (the per-link setting is OR'd with the global one). |
//! | Peer routes | `prefix via peer` in the instance table — except a route whose prefix overlaps the connected prefix of one of the node's own uplink addresses, which is not installed and reads `refused(conflict)`; the overlap is checked again whenever the probe finds the uplink addresses changed. |
//! | Egress translated | Source translation in the guard table: segment prefix → destinations outside the cluster prefixes. |
//! | Held `announce` | `addr/32` to the dummy link in the instance table, a proxy neighbour entry on the uplink whose connected prefix covers the address, `proxy_delay = 0` there through the registry (a broadcast request is otherwise answered after up to 0.8 s), and an unsolicited announcement on arm from a raw link socket. The uplink forwards (through the registry, guarded as above). Fence withdraws the entry, the route and the tunable dependence. Requires `FORWARD`. |
//! | Held `deliver` | `addr/32` on the covering uplink, no prefix route, marked with [`HELD_ADDR_PROTO`]. |
//!
//! A held address is claimed in the registry while it is armed (another
//! live runtime holding it reads `refused(conflict)`); no covering uplink is
//! `refused(unsupported)`. A dead runtime's held addresses go first when its
//! tag is collected ([`reclaim_held`]), so it stops answering for an address
//! another node may have taken.
//!
//! **Honesty.** CAPS are set only when the realization would take effect:
//! no `FLUXOR_STATE_DIR` clears them all (entries read
//! `refused(no_state_dir)`); without `CAP_NET_ADMIN` they read
//! `refused(no_privilege)`; without the rule tool `refused(unsupported)`.
//! Forwarding is checked actively: a frame is sent through a pair of test
//! links and must come out of a second pair, forwarded by this host. A host
//! that drops it (a forward policy of drop) clears `FORWARD` and its
//! dependents and reads `refused(host_forward_drop)`; a probe that cannot
//! run (no `CAP_NET_RAW`) reads `unknown`. The probe re-runs every
//! [`PROBE_INTERVAL_SECS`], so a firewall change after start shows up.
//!
//! Teardown is by tag: held addresses and the guard first (they act for the
//! tag), then the rule, the table's routes and the links
//! (`instance::RECLAIMERS`).
//!
//! Platform-internal: nothing here crosses the portable surface.

use super::instance;
use super::net_identity as nl;
use crate::abi::contracts::net::route as wire;
use crate::kernel::net_route as store;
use crate::kernel::sys::errno;
use std::io::Write as _;
use std::sync::Mutex;

/// Seconds between forwarding probes.
pub const PROBE_INTERVAL_SECS: u64 = 30;
/// How long the forwarding probe waits for its frame to come out.
const PROBE_WAIT_MS: u64 = 300;
/// The probe's frame: from this address, on the first test pair...
const PROBE_SRC: [u8; 4] = [198, 18, 255, 1];
/// ...to this one, routed out of the second.
const PROBE_DST: [u8; 4] = [198, 18, 255, 2];
const PROBE_PORT: u16 = 9;
/// Capability bit numbers (`linux/capability.h`).
const CAP_NET_ADMIN: u32 = 12;
const CAP_NET_RAW: u32 = 13;
/// The address protocol (`IFA_PROTO`) a `deliver` address carries, so a
/// reclaim removes only addresses a runtime added.
pub const HELD_ADDR_PROTO: u8 = 0x46;
/// Repeats of the unsolicited announcement after the first, and the gap
/// before each (a lost frame is not the only chance).
const ANNOUNCE_REPEATS_MS: [u64; 2] = [100, 300];
const RTM_DELNEIGH: u16 = 29;
const RTM_GETADDR: u16 = 22;
const NDA_DST: u16 = 1;
const NTF_PROXY: u8 = 0x08;
const NUD_PERMANENT: u16 = 0x80;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;
const IFA_PROTO: u16 = 11;
const IFA_F_NOPREFIXROUTE: u32 = 0x200;
const ETH_P_ARP: u16 = 0x0806;

/// What the forwarding probe found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Forward {
    /// A frame forwarded through this host came out.
    Passes,
    /// It did not: the host drops forwarded traffic.
    Dropped,
    /// The probe could not run.
    Unknown,
}

/// What the host lets this runtime do.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Probes {
    /// `CAP_NET_ADMIN`: links, addresses, routes, rules, the rule tool.
    pub admin: bool,
    /// `CAP_NET_RAW`: the forwarding probe's raw frames.
    pub raw: bool,
    /// The forwarding and redirect tunables are writable.
    pub tunables: bool,
    /// The rule tool is present and answers.
    pub nft: bool,
    /// The forwarding probe's result.
    pub forward: Forward,
    /// The proxy-delay tunable is writable (held `announce`).
    pub proxy: bool,
}

/// One attached workload.
struct Attachment {
    link: String,
    addr: [u8; 4],
    segment: u16,
}

/// A held address as realized on the host.
#[derive(Clone, PartialEq, Eq)]
struct HeldReal {
    addr: [u8; 4],
    mode: u8,
    /// The covering uplink.
    uplink: String,
    uplink_index: i32,
}

/// A held entry's realization result.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HeldOutcome {
    Realized,
    Fenced,
    Refused(u8),
    Unknown,
}

/// Per-entry realization result beside the host-wide probes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Ok,
    Conflict,
    Failed,
    Unsupported,
}

struct State {
    probes: Option<Probes>,
    segments: Vec<wire::Segment>,
    seg_outcome: Vec<Outcome>,
    routes: Vec<wire::Route>,
    route_outcome: Vec<Outcome>,
    /// Gateways on the dummy link, as realized.
    gateways: Vec<[u8; 4]>,
    /// Peer routes in the instance table, as realized: `(prefix, len)`.
    peer_routes: Vec<([u8; 4], u8)>,
    attachments: Vec<Attachment>,
    /// Uplinks whose forwarding this registry turned on: the guard drops
    /// transit on them.
    guarded_uplinks: Vec<String>,
    /// Uplinks already depended on (forwarding, redirects).
    uplinks: Vec<String>,
    redirects_off: bool,
    rule: Option<(u32, u32)>,
    prober: bool,
    held: Vec<wire::Held>,
    held_outcome: Vec<HeldOutcome>,
    /// Held addresses on the host, as realized.
    held_real: Vec<HeldReal>,
    /// Uplinks whose proxy delay this instance depends on.
    proxy_uplinks: Vec<String>,
    /// Fence evidence per held address: `(addr, install_gen, cutoff)` — the
    /// install count when it was last installed, the fence count when it
    /// was last withdrawn.
    held_evidence: Vec<([u8; 4], u32, u64)>,
    held_installs: u32,
    held_fences: u64,
    /// The uplink prefixes the peer routes were last checked against.
    uplink_prefixes: Vec<([u8; 4], u8)>,
}

static STATE: Mutex<State> = Mutex::new(State {
    probes: None,
    segments: Vec::new(),
    seg_outcome: Vec::new(),
    routes: Vec::new(),
    route_outcome: Vec::new(),
    gateways: Vec::new(),
    peer_routes: Vec::new(),
    attachments: Vec::new(),
    guarded_uplinks: Vec::new(),
    uplinks: Vec::new(),
    redirects_off: false,
    rule: None,
    prober: false,
    held: Vec::new(),
    held_outcome: Vec::new(),
    held_real: Vec::new(),
    proxy_uplinks: Vec::new(),
    held_evidence: Vec::new(),
    held_installs: 0,
    uplink_prefixes: Vec::new(),
    held_fences: 0,
});

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

fn v4(a: &[u8; 16]) -> [u8; 4] {
    [a[0], a[1], a[2], a[3]]
}

fn dotted(a: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

fn cidr(a: [u8; 4], len: u8) -> String {
    if len == 32 {
        dotted(a)
    } else {
        format!("{}/{len}", dotted(a))
    }
}

// ---- probes -----------------------------------------------------------------

/// The tunable root (`FLUXOR_TUNABLE_DIR`, as the registry reads it).
fn tunable_root() -> std::path::PathBuf {
    std::env::var("FLUXOR_TUNABLE_DIR")
        .ok()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| instance::DEFAULT_TUNABLE_DIR.into())
        .into()
}

fn tunable_path(key: &str) -> std::path::PathBuf {
    tunable_root().join(key)
}

fn read_tunable(key: &str) -> Option<String> {
    std::fs::read_to_string(tunable_path(key))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Set a tunable of a link this instance owns (it dies with the link, so no
/// registry record is needed).
fn set_own_tunable(key: &str, value: &str) -> bool {
    std::fs::write(tunable_path(key), value).is_ok()
}

/// The effective capability set, from `/proc/self/status`.
fn effective_caps() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        })
        .unwrap_or(0)
}

fn writable(path: &std::path::Path) -> bool {
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    // SAFETY: access(2) on a NUL-terminated path we own.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

/// The rule tool, holding none of the runtime's descriptors.
fn nft() -> std::process::Command {
    let mut command = std::process::Command::new("nft");
    crate::platform::linux::descriptors::sweep_on_exec(&mut command);
    command
}

fn nft_present() -> bool {
    nft()
        .args(["list", "tables"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Run the probes now (the forwarding probe included).
pub fn probe() -> Probes {
    let caps = effective_caps();
    let admin = caps & (1 << CAP_NET_ADMIN) != 0;
    let raw = caps & (1 << CAP_NET_RAW) != 0;
    let tunables = writable(&tunable_path("net/ipv4/conf/all/send_redirects"))
        && writable(&tunable_path("net/ipv4/conf/all/forwarding"));
    let nft = admin && nft_present();
    let forward = if admin && raw && instance::state_dir().is_some() {
        forward_probe()
    } else {
        Forward::Unknown
    };
    // Per-link neighbour tunables (a network domain other than the host's
    // first has no `default` set; every one has loopback's).
    let proxy = writable(&tunable_path("net/ipv4/neigh/lo/proxy_delay"));
    Probes {
        admin,
        raw,
        tunables,
        nft,
        forward,
        proxy,
    }
}

/// The probes, run once if they have not been.
fn probes(st: &mut State) -> Probes {
    if let Some(p) = st.probes {
        return p;
    }
    let p = probe();
    st.probes = Some(p);
    p
}

/// The forwarding probe's four links: two veth pairs.
fn probe_links(tag: &str) -> [String; 4] {
    let s = instance::stem(tag);
    [
        format!("fx{s}pa"),
        format!("fx{s}pb"),
        format!("fx{s}pc"),
        format!("fx{s}pd"),
    ]
}

fn link_named(name: &str) -> Option<nl::LinkInfo> {
    nl::links().ok()?.into_iter().find(|l| l.name == name)
}

/// The instance's routing table and rule priority, the rule installed.
fn ensure_rule() -> Result<(u32, u32), i32> {
    let (table, prio) =
        instance::with_live(|l| Ok::<_, i32>((l.table_id()?, l.rule_priority()?)))??;
    let mut m = nl::msg_rule(table, prio);
    let rc = nl::nl_request(&mut m, nl::RTM_NEWRULE, nl::NLM_F_CREATE | nl::NLM_F_EXCL);
    if rc != 0 && rc != -libc::EEXIST {
        return Err(rc);
    }
    Ok((table, prio))
}

fn ip_checksum(h: &[u8]) -> u16 {
    let mut sum = 0u32;
    for c in h.chunks(2) {
        let w = if c.len() == 2 {
            u16::from_be_bytes([c[0], c[1]])
        } else {
            u16::from_be_bytes([c[0], 0])
        };
        sum += w as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// The probe's datagram: IPv4 + UDP, carrying `nonce`.
fn probe_packet(nonce: &[u8; 8]) -> Vec<u8> {
    let payload_len = 8 + nonce.len();
    let total = 20 + payload_len;
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[6] = 0x40; // don't fragment
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&PROBE_SRC);
    p[16..20].copy_from_slice(&PROBE_DST);
    let c = ip_checksum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p[20..22].copy_from_slice(&PROBE_PORT.to_be_bytes());
    p[22..24].copy_from_slice(&PROBE_PORT.to_be_bytes());
    p[24..26].copy_from_slice(&(payload_len as u16).to_be_bytes());
    p[28..].copy_from_slice(nonce);
    p
}

fn packet_socket(index: i32) -> Option<i32> {
    let proto = (libc::ETH_P_IP as u16).to_be();
    // SAFETY: plain socket call; CLOEXEC keeps it out of any child.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            proto as i32,
        )
    };
    if fd < 0 {
        return None;
    }
    // SAFETY: a zeroed sockaddr_ll is a valid starting value.
    let mut sll: libc::sockaddr_ll = unsafe { core::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = proto;
    sll.sll_ifindex = index;
    // SAFETY: binding the socket opened above to a sockaddr_ll we own.
    let rc = unsafe {
        libc::bind(
            fd,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            core::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if rc != 0 {
        // SAFETY: closing the socket opened above.
        unsafe { libc::close(fd) };
        return None;
    }
    Some(fd)
}

/// Send the probe datagram out of link `index` to hardware address `mac`.
fn send_probe(fd: i32, index: i32, mac: [u8; 6], packet: &[u8]) -> bool {
    // SAFETY: a zeroed sockaddr_ll is a valid starting value.
    let mut sll: libc::sockaddr_ll = unsafe { core::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    sll.sll_ifindex = index;
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(&mac);
    // SAFETY: `packet` and `sll` outlive the call.
    let n = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            core::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    n == packet.len() as isize
}

/// Whether a datagram carrying `nonce` arrives on `fd` before the deadline.
fn await_probe(fd: i32, nonce: &[u8; 8], deadline: std::time::Instant) -> bool {
    let mut buf = [0u8; 2048];
    while std::time::Instant::now() < deadline {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: polling one descriptor we own.
        let r = unsafe { libc::poll(&mut pfd, 1, 20) };
        if r <= 0 {
            continue;
        }
        // SAFETY: `buf` is ours for the call.
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n >= 36 && buf.get(28..36) == Some(&nonce[..]) {
            return true;
        }
    }
    false
}

/// Send a frame into this host through one test pair and wait for it to be
/// forwarded out of the other. The test links carry the instance's alias,
/// so a probe interrupted by a crash is collected with the tag.
fn forward_probe() -> Forward {
    let Ok(tag) = instance::live_tag() else {
        return Forward::Unknown;
    };
    let Ok((table, _)) = ensure_rule() else {
        return Forward::Unknown;
    };
    let [a, b, c, d] = probe_links(&tag);
    let _ = nl::delete_link(&a);
    let _ = nl::delete_link(&c);
    let result = (|| {
        if nl::create_veth_pair(&a, &b) != 0 || nl::create_veth_pair(&c, &d) != 0 {
            return Forward::Unknown;
        }
        let alias = instance::link_alias(&tag);
        let _ = nl::alias_link(&a, &alias);
        let _ = nl::alias_link(&c, &alias);
        let (Some(la), Some(lb), Some(lc), Some(ld)) = (
            link_named(&a),
            link_named(&b),
            link_named(&c),
            link_named(&d),
        ) else {
            return Forward::Unknown;
        };
        for l in [&la, &lb, &lc, &ld] {
            let mut m = nl::msg_link_up(l.index, None);
            if nl::nl_request(&mut m, nl::RTM_NEWLINK, 0) != 0 {
                return Forward::Unknown;
            }
        }
        let (Some(mac_a), Some(mac_d)) = (la.mac, ld.mac) else {
            return Forward::Unknown;
        };
        if !set_own_tunable(&format!("net/ipv4/conf/{a}/forwarding"), "1") {
            return Forward::Unknown;
        }
        let _ = set_own_tunable(&format!("net/ipv4/conf/{a}/rp_filter"), "0");
        let mut back = nl::msg_route(table, PROBE_SRC, 32, la.index, None, None, false);
        let mut out = nl::msg_route(table, PROBE_DST, 32, lc.index, None, None, false);
        let mut neigh = nl::msg_neigh(lc.index, PROBE_DST, mac_d);
        let flags = nl::NLM_F_CREATE | nl::NLM_F_REPLACE;
        if nl::nl_request(&mut back, nl::RTM_NEWROUTE, flags) != 0
            || nl::nl_request(&mut out, nl::RTM_NEWROUTE, flags) != 0
            || nl::nl_request(&mut neigh, nl::RTM_NEWNEIGH, flags) != 0
        {
            return Forward::Unknown;
        }
        let (Some(rx), Some(tx)) = (packet_socket(ld.index), packet_socket(lb.index)) else {
            return Forward::Unknown;
        };
        let mut nonce = *b"fxprobe0";
        // SAFETY: getrandom(2) into a buffer we own; a short fill keeps the
        // fixed bytes, which still identify the probe.
        unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), 0) };
        let packet = probe_packet(&nonce);
        let mut seen = false;
        let mut sent = false;
        for _ in 0..3 {
            sent |= send_probe(tx, lb.index, mac_a, &packet);
            let deadline =
                std::time::Instant::now() + std::time::Duration::from_millis(PROBE_WAIT_MS / 3);
            if await_probe(rx, &nonce, deadline) {
                seen = true;
                break;
            }
        }
        // SAFETY: closing the two sockets opened above.
        unsafe {
            libc::close(rx);
            libc::close(tx);
        }
        match (seen, sent) {
            (true, _) => Forward::Passes,
            (false, true) => Forward::Dropped,
            (false, false) => Forward::Unknown,
        }
    })();
    let _ = nl::delete_link(&a);
    let _ = nl::delete_link(&c);
    result
}

/// Re-run the probes every [`PROBE_INTERVAL_SECS`] on a thread of their own.
fn start_prober() {
    {
        let mut st = state();
        if st.prober {
            return;
        }
        st.prober = true;
    }
    let spawned = std::thread::Builder::new()
        .name("fx-net-route-probe".into())
        .spawn(|| loop {
            std::thread::sleep(std::time::Duration::from_secs(PROBE_INTERVAL_SECS));
            let p = probe();
            let mut st = state();
            if st.probes != Some(p) {
                log::info!("[net_route] host changed: {p:?}");
            }
            st.probes = Some(p);
            // The node's uplink addresses moved: the peer routes are
            // checked against them again.
            if !st.routes.is_empty() {
                if let Ok(tag) = instance::live_tag() {
                    if uplink_prefixes(&tag) != st.uplink_prefixes {
                        let n = st.routes.len();
                        st.route_outcome = vec![Outcome::Ok; n];
                        realize(&mut st);
                    }
                }
            }
        });
    if spawned.is_err() {
        log::warn!("[net_route] cannot start the periodic probe; probes are not re-run");
    }
}

/// Runtime start: probe the host once and keep re-probing. A runtime with no
/// state directory realizes nothing and probes nothing.
pub fn init() {
    if instance::state_dir().is_none() {
        return;
    }
    let p = probe();
    log::info!("[net_route] {p:?}");
    state().probes = Some(p);
    start_prober();
}

/// Re-run the probes now (the periodic thread does this on its own).
pub fn reprobe() -> Probes {
    let p = probe();
    state().probes = Some(p);
    p
}

// ---- capabilities and states ------------------------------------------------

/// What this platform realizes now.
pub fn caps() -> u32 {
    if instance::state_dir().is_none() {
        return 0;
    }
    let p = probes(&mut state());
    if !p.admin {
        return 0;
    }
    // An address on an uplink needs only the privilege.
    let mut c = wire::caps::HOLD_DELIVER;
    if !p.nft || !p.tunables {
        return c;
    }
    c |= wire::caps::SEGMENTS;
    if p.forward == Forward::Passes {
        c |= wire::caps::FORWARD | wire::caps::PEER_ROUTES | wire::caps::EGRESS_TRANSLATE;
        if p.raw && p.proxy {
            c |= wire::caps::HOLD_ANNOUNCE;
        }
    }
    c
}

/// Whether held `announce` entries can be realized now; the outcome they
/// read when not.
fn announce_gate(p: &Probes) -> Result<(), HeldOutcome> {
    use wire::reason as r;
    if !p.admin {
        return Err(HeldOutcome::Refused(r::NO_PRIVILEGE));
    }
    if !p.nft || !p.tunables || !p.proxy {
        return Err(HeldOutcome::Refused(r::UNSUPPORTED));
    }
    if !p.raw {
        return Err(HeldOutcome::Refused(r::NO_PRIVILEGE));
    }
    match p.forward {
        Forward::Passes => Ok(()),
        Forward::Dropped => Err(HeldOutcome::Refused(r::HOST_FORWARD_DROP)),
        Forward::Unknown => Err(HeldOutcome::Unknown),
    }
}

/// A held entry's state: what its realization found, against the probes
/// now (a firewall that starts dropping forwarded traffic shows up here).
fn held_state(st: &State, p: &Probes, index: usize) -> (u8, u8) {
    use wire::{reason as r, state as s};
    let mode = st.held.get(index).map(|h| h.mode);
    match st.held_outcome.get(index).copied() {
        Some(HeldOutcome::Realized) => {
            if mode == Some(wire::held::MODE_ANNOUNCE) {
                match announce_gate(p) {
                    Ok(()) => (s::REALIZED, r::NONE),
                    Err(HeldOutcome::Refused(why)) => (s::REFUSED, why),
                    Err(_) => (s::UNKNOWN, r::NONE),
                }
            } else {
                (s::REALIZED, r::NONE)
            }
        }
        Some(HeldOutcome::Fenced) => (s::FENCED, r::NONE),
        Some(HeldOutcome::Refused(why)) => (s::REFUSED, why),
        Some(HeldOutcome::Unknown) => (s::UNKNOWN, r::NONE),
        None => (s::PENDING, r::NONE),
    }
}

fn entry_state(kind: u8, index: usize) -> (u8, u8) {
    use wire::{reason as r, state as s};
    if instance::state_dir().is_none() {
        return (s::REFUSED, r::NO_STATE_DIR);
    }
    let mut st = state();
    let p = probes(&mut st);
    if !p.admin {
        return (s::REFUSED, r::NO_PRIVILEGE);
    }
    if kind == wire::entry::KIND_HELD {
        return held_state(&st, &p, index);
    }
    if !p.nft || !p.tunables {
        return (s::REFUSED, r::UNSUPPORTED);
    }
    let outcome = match kind {
        wire::entry::KIND_SEGMENT => st.seg_outcome.get(index).copied(),
        _ => st.route_outcome.get(index).copied(),
    };
    match outcome.unwrap_or(Outcome::Failed) {
        Outcome::Conflict => return (s::REFUSED, r::CONFLICT),
        Outcome::Unsupported => return (s::REFUSED, r::UNSUPPORTED),
        Outcome::Failed => return (s::UNKNOWN, r::NONE),
        Outcome::Ok => {}
    }
    match p.forward {
        Forward::Passes => (s::REALIZED, r::NONE),
        Forward::Dropped => (s::REFUSED, r::HOST_FORWARD_DROP),
        Forward::Unknown => (s::UNKNOWN, r::NONE),
    }
}

// ---- realization ------------------------------------------------------------

fn claim_of(kind: instance::ClaimKind, family: u8, addr: &[u8; 16], len: u8) -> instance::Claim {
    instance::Claim {
        kind,
        family,
        addr: *addr,
        len,
    }
}

/// Claim `items` (each a claim, and its outcome slot) in the registry: on a
/// conflict the overlapping item is marked and the rest claimed again.
fn claim_all(
    live: &instance::Live,
    kind: instance::ClaimKind,
    items: &[(instance::Claim, usize)],
    outcome: &mut [Outcome],
) {
    loop {
        let claims: Vec<instance::Claim> = items
            .iter()
            .filter(|(_, i)| outcome.get(*i) == Some(&Outcome::Ok))
            .map(|(c, _)| *c)
            .collect();
        match live.set_claims(kind, &claims) {
            Ok(()) => return,
            Err(instance::ClaimError::Conflict(c)) => {
                let Some((_, i)) = items
                    .iter()
                    .find(|(cl, i)| *cl == c.ours && outcome.get(*i) == Some(&Outcome::Ok))
                else {
                    return;
                };
                log::warn!(
                    "[net_route] {kind:?} {}/{} overlaps live instance {}: refused(conflict)",
                    dotted(v4(&c.ours.addr)),
                    c.ours.len,
                    c.tag
                );
                if let Some(o) = outcome.get_mut(*i) {
                    *o = Outcome::Conflict;
                }
            }
            Err(instance::ClaimError::Errno(e)) => {
                log::warn!("[net_route] registry refused {kind:?} claims ({e})");
                for (_, i) in items {
                    if let Some(o) = outcome.get_mut(*i) {
                        *o = Outcome::Failed;
                    }
                }
                return;
            }
        }
    }
}

/// The dummy link holding the gateways, created when absent.
fn ensure_dummy(tag: &str) -> Option<nl::LinkInfo> {
    let name = instance::gateway_link_name(tag);
    if link_named(&name).is_none() {
        let rc = nl::create_kind(&name, b"dummy");
        if rc != 0 && rc != -libc::EEXIST {
            log::warn!("[net_route] cannot create {name}: {rc}");
            return None;
        }
        let _ = nl::alias_link(&name, &instance::link_alias(tag));
    }
    let l = link_named(&name)?;
    let mut up = nl::msg_link_up(l.index, None);
    let _ = nl::nl_request(&mut up, nl::RTM_NEWLINK, 0);
    Some(l)
}

/// Depend on a host tunable through the registry.
fn depend(live: &instance::Live, key: &str, value: &str) -> bool {
    match live.depend_tunable(key, value) {
        Ok(()) => true,
        Err(e) => {
            log::warn!("[net_route] cannot set {key}={value} ({e})");
            false
        }
    }
}

/// Forward on uplink `u`, with redirects off on it and globally, through the
/// registry. An uplink whose forwarding the registry itself turned on is
/// guarded. Whether it forwards.
fn depend_uplink(live: &instance::Live, st: &mut State, u: &str) -> bool {
    if !st.redirects_off {
        st.redirects_off = depend(live, "net/ipv4/conf/all/send_redirects", "0");
    }
    if st.uplinks.iter().any(|x| x == u) {
        return true;
    }
    let key = format!("net/ipv4/conf/{u}/forwarding");
    let before = live
        .tunable_prior(&key)
        .or_else(|| read_tunable(&key))
        .unwrap_or_default();
    if !depend(live, &key, "1") {
        return false;
    }
    if before.trim() != "1" {
        st.guarded_uplinks.push(u.to_string());
    }
    let _ = depend(live, &format!("net/ipv4/conf/{u}/send_redirects"), "0");
    st.uplinks.push(u.to_string());
    true
}

/// The host links traffic to peers and default destinations leaves by,
/// instance links and loopback excepted.
fn uplink_names(tag: &str, st: &State) -> Vec<String> {
    let mut idx: Vec<i32> = nl::default_route_links();
    for r in st.routes.iter().zip(&st.route_outcome) {
        if *r.1 == Outcome::Ok && r.0.prefix.family == wire::FAM_IPV4 {
            if let Some(o) = nl::route_oif(v4(&r.0.peer)) {
                idx.push(o);
            }
        }
    }
    let stem = instance::stem(tag);
    let links = nl::links().unwrap_or_default();
    let mut names: Vec<String> = Vec::new();
    for i in idx {
        if let Some(l) = links.iter().find(|l| l.index == i) {
            let ours = l.name.starts_with(&format!("fx{stem}"))
                || l.alias.as_deref().and_then(instance::alias_tag).is_some();
            if !ours && l.name != "lo" && plain_name(&l.name) && !names.contains(&l.name) {
                names.push(l.name.clone());
            }
        }
    }
    names
}

/// Whether a host link's name can stand in a tunable path and a quoted rule
/// string as it is. The kernel admits nearly any byte in a name; one with a
/// quote, a slash or a control byte is not an uplink this realizes on.
fn plain_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'@'))
        && name != "."
        && name != ".."
}

/// Bring the host in line with the tables and attachments: claims, gateway
/// link and addresses, rule, peer routes, uplink forwarding, the guard.
fn realize(st: &mut State) {
    let p = probes(st);
    if !p.admin || !p.nft || !p.tunables {
        return;
    }
    let tag = match instance::live_tag() {
        Ok(t) => t,
        Err(e) => {
            log::warn!("[net_route] not live in the host registry ({e})");
            st.seg_outcome.iter_mut().for_each(|o| *o = Outcome::Failed);
            st.route_outcome
                .iter_mut()
                .for_each(|o| *o = Outcome::Failed);
            return;
        }
    };
    // Claims: segment prefixes and gateways, peer prefixes.
    for (o, s) in st.seg_outcome.iter_mut().zip(&st.segments) {
        if s.prefix.family != wire::FAM_IPV4 {
            *o = Outcome::Unsupported;
        }
    }
    for (o, r) in st.route_outcome.iter_mut().zip(&st.routes) {
        if r.prefix.family != wire::FAM_IPV4 {
            *o = Outcome::Unsupported;
        }
    }
    // A peer route never takes the node's own uplink.
    let ups = uplink_prefixes(&tag);
    for (o, r) in st.route_outcome.iter_mut().zip(&st.routes) {
        if *o == Outcome::Ok && covers_uplink(&r.prefix, &ups) {
            log::warn!(
                "[net_route] peer route {}/{} overlaps the node's uplink: refused(conflict)",
                dotted(v4(&r.prefix.addr)),
                r.prefix.len
            );
            *o = Outcome::Conflict;
        }
    }
    st.uplink_prefixes = ups;
    let segs: Vec<(instance::Claim, usize)> = st
        .segments
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let c = claim_of(
                instance::ClaimKind::Segment,
                s.prefix.family,
                &s.prefix.addr,
                s.prefix.len,
            );
            (c, i)
        })
        .collect();
    let gws: Vec<(instance::Claim, usize)> = st
        .segments
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let c = claim_of(
                instance::ClaimKind::Gateway,
                s.prefix.family,
                &s.gateway,
                if s.prefix.family == wire::FAM_IPV6 {
                    128
                } else {
                    32
                },
            );
            (c, i)
        })
        .collect();
    let peers: Vec<(instance::Claim, usize)> = st
        .routes
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let c = claim_of(
                instance::ClaimKind::Peer,
                r.prefix.family,
                &r.prefix.addr,
                r.prefix.len,
            );
            (c, i)
        })
        .collect();
    let mut seg_outcome = std::mem::take(&mut st.seg_outcome);
    let mut route_outcome = std::mem::take(&mut st.route_outcome);
    let alloc = instance::with_live(|live| {
        claim_all(live, instance::ClaimKind::Segment, &segs, &mut seg_outcome);
        claim_all(live, instance::ClaimKind::Gateway, &gws, &mut seg_outcome);
        claim_all(live, instance::ClaimKind::Peer, &peers, &mut route_outcome);
    });
    st.seg_outcome = seg_outcome;
    st.route_outcome = route_outcome;
    if let Err(e) = alloc {
        log::warn!("[net_route] not live in the host registry ({e})");
        st.seg_outcome.iter_mut().for_each(|o| *o = Outcome::Failed);
        st.route_outcome
            .iter_mut()
            .for_each(|o| *o = Outcome::Failed);
        return;
    }
    let (table, prio) = match ensure_rule() {
        Ok(r) => r,
        Err(e) => {
            log::warn!("[net_route] cannot install the instance rule ({e})");
            st.seg_outcome.iter_mut().for_each(|o| *o = Outcome::Failed);
            st.route_outcome
                .iter_mut()
                .for_each(|o| *o = Outcome::Failed);
            return;
        }
    };
    st.rule = Some((table, prio));
    // Gateways on the dummy link.
    let want_gw: Vec<[u8; 4]> = st
        .segments
        .iter()
        .zip(&st.seg_outcome)
        .filter(|(_, o)| **o == Outcome::Ok)
        .map(|(s, _)| v4(&s.gateway))
        .collect();
    if !want_gw.is_empty() || !st.gateways.is_empty() {
        match ensure_dummy(&tag) {
            Some(d) => {
                for g in st.gateways.clone() {
                    if !want_gw.contains(&g) {
                        let mut m = nl::msg_addr(d.index, g, 32);
                        let _ = nl::nl_request(&mut m, nl::RTM_DELADDR, 0);
                    }
                }
                let mut realized = Vec::new();
                for (s, o) in st.segments.iter().zip(st.seg_outcome.iter_mut()) {
                    if *o != Outcome::Ok {
                        continue;
                    }
                    let g = v4(&s.gateway);
                    let mut m = nl::msg_addr(d.index, g, 32);
                    let rc = nl::nl_request(
                        &mut m,
                        nl::RTM_NEWADDR,
                        nl::NLM_F_CREATE | nl::NLM_F_REPLACE,
                    );
                    if rc != 0 && rc != -libc::EEXIST {
                        log::warn!("[net_route] gateway {} not added: {rc}", dotted(g));
                        *o = Outcome::Failed;
                    } else {
                        realized.push(g);
                    }
                }
                st.gateways = realized;
            }
            None => st.seg_outcome.iter_mut().for_each(|o| *o = Outcome::Failed),
        }
    }
    // Peer routes in the instance table.
    let want_routes: Vec<([u8; 4], u8, [u8; 4])> = st
        .routes
        .iter()
        .zip(&st.route_outcome)
        .filter(|(_, o)| **o == Outcome::Ok)
        .map(|(r, _)| (v4(&r.prefix.addr), r.prefix.len, v4(&r.peer)))
        .collect();
    for (dst, len) in st.peer_routes.clone() {
        if !want_routes.iter().any(|(d, l, _)| *d == dst && *l == len) {
            let mut m = nl::msg_route_key(table, dst, len);
            let _ = nl::nl_request(&mut m, nl::RTM_DELROUTE, 0);
        }
    }
    let mut realized = Vec::new();
    for (r, o) in st.routes.iter().zip(st.route_outcome.iter_mut()) {
        if *o != Outcome::Ok {
            continue;
        }
        let (dst, len, peer) = (v4(&r.prefix.addr), r.prefix.len, v4(&r.peer));
        let mut m = nl::msg_route(table, dst, len, 0, Some(peer), None, false);
        let rc = nl::nl_request(
            &mut m,
            nl::RTM_NEWROUTE,
            nl::NLM_F_CREATE | nl::NLM_F_REPLACE,
        );
        if rc != 0 {
            log::warn!(
                "[net_route] peer route {} via {} not added: {rc}",
                cidr(dst, len),
                dotted(peer)
            );
            *o = Outcome::Failed;
        } else {
            realized.push((dst, len));
        }
    }
    st.peer_routes = realized;
    // Forwarding and redirects on the uplinks, through the registry.
    if !st.segments.is_empty() || !st.routes.is_empty() {
        let names = uplink_names(&tag, st);
        let _ = instance::with_live(|live| {
            if !st.redirects_off {
                st.redirects_off = depend(live, "net/ipv4/conf/all/send_redirects", "0");
            }
            for u in names {
                depend_uplink(live, st, &u);
            }
        });
    }
    if let Err(e) = apply_guard(&tag, st) {
        log::warn!("[net_route] guard not applied ({e})");
        st.seg_outcome.iter_mut().for_each(|o| *o = Outcome::Failed);
    }
}

// ---- the guard ----------------------------------------------------------------

/// The guard table of instance `tag`.
pub fn guard_table_name(tag: &str) -> String {
    format!("fxr_{tag}")
}

/// What the guard is rendered from.
pub struct GuardInput<'a> {
    /// `(link, workload address)` of every attachment.
    pub attachments: &'a [(String, [u8; 4])],
    /// The realized segments.
    pub segments: &'a [wire::Segment],
    /// Uplinks whose forwarding this registry turned on.
    pub guarded_uplinks: &'a [String],
    /// The forwarding probe's entry link (accepted like a workload link).
    pub probe_in: &'a str,
}

/// IPv4 prefixes with every one covered by another removed (an anonymous set
/// may not hold overlapping intervals).
fn minimal(prefixes: &[([u8; 4], u8)]) -> Vec<([u8; 4], u8)> {
    let covers = |a: &([u8; 4], u8), b: &([u8; 4], u8)| {
        let p = wire::Prefix {
            family: wire::FAM_IPV4,
            len: a.1,
            addr: {
                let mut x = [0u8; 16];
                x[..4].copy_from_slice(&a.0);
                x
            },
        };
        let mut y = [0u8; 16];
        y[..4].copy_from_slice(&b.0);
        a.1 <= b.1 && p.contains(wire::FAM_IPV4, &y)
    };
    let mut out: Vec<([u8; 4], u8)> = Vec::new();
    for (i, p) in prefixes.iter().enumerate() {
        let covered = prefixes
            .iter()
            .enumerate()
            .any(|(j, q)| j != i && covers(q, p) && (q != p || j < i));
        if !covered && !out.contains(p) {
            out.push(*p);
        }
    }
    out
}

fn set_of(items: &[String]) -> String {
    format!("{{ {} }}", items.join(", "))
}

/// The nft script that replaces instance `tag`'s guard. Public so the
/// harness can pin the rendering.
pub fn render_guard(tag: &str, g: &GuardInput<'_>) -> String {
    let t = guard_table_name(tag);
    let mut s = format!("table ip {t}\ndelete table ip {t}\ntable ip {t} {{\n");
    // Anti-spoofing: before routing, whatever the host's reverse-path check.
    s.push_str(
        "\tchain guard_in {\n\t\ttype filter hook prerouting priority -300; policy accept;\n",
    );
    for (link, addr) in g.attachments {
        s.push_str(&format!(
            "\t\tiifname \"{link}\" ip saddr != {} drop\n",
            dotted(*addr)
        ));
    }
    s.push_str("\t}\n");
    let links: Vec<String> = g
        .attachments
        .iter()
        .map(|(l, _)| format!("\"{l}\""))
        .collect();
    let v4segs: Vec<&wire::Segment> = g
        .segments
        .iter()
        .filter(|x| x.prefix.family == wire::FAM_IPV4)
        .collect();
    let mut cluster: Vec<([u8; 4], u8)> = Vec::new();
    for x in &v4segs {
        cluster.push((v4(&x.prefix.addr), x.prefix.len));
        for c in x.cluster().iter().filter(|c| c.family == wire::FAM_IPV4) {
            cluster.push((v4(&c.addr), c.len));
        }
    }
    let cluster: Vec<String> = minimal(&cluster)
        .into_iter()
        .map(|(a, l)| cidr(a, l))
        .collect();
    s.push_str("\tchain guard_fwd {\n\t\ttype filter hook forward priority -10; policy accept;\n");
    s.push_str("\t\tct state established,related accept\n");
    s.push_str(&format!("\t\tiifname \"{}\" accept\n", g.probe_in));
    if !links.is_empty() {
        let l = set_of(&links);
        s.push_str(&format!("\t\tiifname {l} accept\n"));
        if !cluster.is_empty() {
            s.push_str(&format!(
                "\t\toifname {l} ip daddr {} accept\n",
                set_of(&cluster)
            ));
        }
        s.push_str(&format!("\t\tiifname {l} drop\n"));
        s.push_str(&format!("\t\toifname {l} drop\n"));
    }
    for u in g.guarded_uplinks {
        s.push_str(&format!(
            "\t\tiifname \"{u}\" oifname != \"fx*\" ct status & dnat == 0 drop\n"
        ));
        s.push_str(&format!(
            "\t\toifname \"{u}\" iifname != \"fx*\" ct status & dnat == 0 drop\n"
        ));
    }
    s.push_str("\t}\n");
    let translated: Vec<&&wire::Segment> = v4segs
        .iter()
        .filter(|x| x.egress == wire::segment::EGRESS_TRANSLATED)
        .collect();
    if !translated.is_empty() {
        s.push_str(
            "\tchain guard_nat {\n\t\ttype nat hook postrouting priority 100; policy accept;\n",
        );
        for x in translated {
            let mut inside: Vec<([u8; 4], u8)> = vec![(v4(&x.prefix.addr), x.prefix.len)];
            for c in x.cluster().iter().filter(|c| c.family == wire::FAM_IPV4) {
                inside.push((v4(&c.addr), c.len));
            }
            let inside: Vec<String> = minimal(&inside)
                .into_iter()
                .map(|(a, l)| cidr(a, l))
                .collect();
            s.push_str(&format!(
                "\t\tip saddr {} ip daddr != {} masquerade\n",
                cidr(v4(&x.prefix.addr), x.prefix.len),
                set_of(&inside)
            ));
        }
        s.push_str("\t}\n");
    }
    s.push_str("}\n");
    s
}

fn run_nft(script: &str) -> Result<(), i32> {
    let child = nft()
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            log::warn!("[net_route] cannot run nft: {e}");
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
                "[net_route] nft refused the guard: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            Err(errno::EACCES)
        }
        Err(_) => Err(errno::ERROR),
    }
}

fn apply_guard(tag: &str, st: &State) -> Result<(), i32> {
    let attachments: Vec<(String, [u8; 4])> = st
        .attachments
        .iter()
        .map(|a| (a.link.clone(), a.addr))
        .collect();
    let segments: Vec<wire::Segment> = st
        .segments
        .iter()
        .zip(&st.seg_outcome)
        .filter(|(_, o)| **o == Outcome::Ok)
        .map(|(s, _)| *s)
        .collect();
    let [probe_in, ..] = probe_links(tag);
    run_nft(&render_guard(
        tag,
        &GuardInput {
            attachments: &attachments,
            segments: &segments,
            guarded_uplinks: &st.guarded_uplinks,
            probe_in: &probe_in,
        },
    ))
}

// ---- held addresses -------------------------------------------------------------

/// Patch the netlink header of `msg` (from `nl_begin_raw`) for a dump.
fn finish_dump(msg: &mut [u8], ty: u16) {
    let len = (msg.len() as u32).to_ne_bytes();
    let head = [
        len[0],
        len[1],
        len[2],
        len[3],
        ty.to_ne_bytes()[0],
        ty.to_ne_bytes()[1],
        (nl::NLM_F_REQUEST | nl::NLM_F_DUMP).to_ne_bytes()[0],
        (nl::NLM_F_REQUEST | nl::NLM_F_DUMP).to_ne_bytes()[1],
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    for (d, s) in msg.iter_mut().zip(head) {
        *d = s;
    }
}

/// One IPv4 address of the host's network domain.
struct HostAddr {
    index: i32,
    addr: [u8; 4],
    len: u8,
    proto: u8,
}

/// Every IPv4 address in this network domain.
fn host_addrs() -> Result<Vec<HostAddr>, i32> {
    let mut msg = nl::nl_begin_raw(&[libc::AF_INET as u8, 0, 0, 0, 0, 0, 0, 0]);
    finish_dump(&mut msg, RTM_GETADDR);
    let fd = nl::nl_socket()?;
    let mut out = Vec::new();
    let mut buf = vec![0u8; 32 * 1024];
    let result = (|| {
        nl::nl_send(fd, &msg)?;
        loop {
            let n = nl::nl_recv(fd, &mut buf);
            if n <= 0 {
                return Err(errno::ERROR);
            }
            let done = nl::walk_messages(buf.get(..n as usize).unwrap_or(&[]), |ty, m| {
                if ty != nl::RTM_NEWADDR {
                    return;
                }
                let Some(f) = m.get(16..24) else { return };
                if f[0] != libc::AF_INET as u8 {
                    return;
                }
                let mut a = HostAddr {
                    index: i32::from_ne_bytes([f[4], f[5], f[6], f[7]]),
                    addr: [0; 4],
                    len: f[1],
                    proto: 0,
                };
                let mut local = None;
                nl::walk_attrs(m, 24, |aty, d| match aty {
                    IFA_LOCAL if d.len() == 4 => local = Some([d[0], d[1], d[2], d[3]]),
                    IFA_ADDRESS if d.len() == 4 => a.addr = [d[0], d[1], d[2], d[3]],
                    IFA_PROTO if d.len() == 1 => a.proto = d[0],
                    _ => {}
                });
                if let Some(l) = local {
                    a.addr = l;
                }
                out.push(a);
            })?;
            if done {
                return Ok(());
            }
        }
    })();
    // SAFETY: closing the socket opened above.
    unsafe { libc::close(fd) };
    result.map(|()| out)
}

/// The connected prefixes of the node's own uplink addresses: every IPv4
/// address on a host link that is not an instance link (any runtime's) or
/// loopback, held addresses excepted (they are service addresses the node
/// answers for, not its link).
fn uplink_prefixes(tag: &str) -> Vec<([u8; 4], u8)> {
    let stem = instance::stem(tag);
    let links = nl::links().unwrap_or_default();
    let mut out: Vec<([u8; 4], u8)> = host_addrs()
        .unwrap_or_default()
        .iter()
        .filter(|a| a.proto != HELD_ADDR_PROTO)
        .filter_map(|a| {
            let l = links.iter().find(|l| l.index == a.index)?;
            (l.name != "lo" && !instance_link(stem, l)).then_some((a.addr, a.len))
        })
        .collect();
    out.sort_unstable();
    out
}

/// Whether peer-route prefix `p` overlaps one of the uplink prefixes `ups`.
pub fn covers_uplink(p: &wire::Prefix, ups: &[([u8; 4], u8)]) -> bool {
    ups.iter().any(|(a, len)| {
        let mut addr = [0u8; wire::ADDR_LEN];
        addr[..4].copy_from_slice(a);
        p.overlaps(&wire::Prefix {
            family: wire::FAM_IPV4,
            len: *len,
            addr,
        })
    })
}

fn v4_contains(prefix: [u8; 4], len: u8, addr: [u8; 4]) -> bool {
    let mask = if len == 0 {
        0
    } else {
        u32::MAX << (32 - len.min(32) as u32)
    };
    u32::from_be_bytes(prefix) & mask == u32::from_be_bytes(addr) & mask
}

/// Whether link `l` is one of this host's instance links (any runtime's).
fn instance_link(stem: &str, l: &nl::LinkInfo) -> bool {
    l.name.starts_with(&format!("fx{stem}"))
        || l.alias.as_deref().and_then(instance::alias_tag).is_some()
}

/// The uplink whose connected prefix covers `addr`: the most specific, never
/// an instance link or loopback.
fn covering_uplink(
    tag: &str,
    addr: [u8; 4],
    links: &[nl::LinkInfo],
    addrs: &[HostAddr],
) -> Option<(String, i32)> {
    let stem = instance::stem(tag);
    addrs
        .iter()
        .filter(|a| a.len < 32 && v4_contains(a.addr, a.len, addr))
        .filter_map(|a| {
            let l = links.iter().find(|l| l.index == a.index)?;
            (l.name != "lo" && plain_name(&l.name) && !instance_link(stem, l)).then_some((a.len, l))
        })
        .max_by_key(|(len, _)| *len)
        .map(|(_, l)| (l.name.clone(), l.index))
}

/// A proxy neighbour entry for `addr` on link `index`.
fn msg_proxy(index: i32, addr: [u8; 4]) -> Vec<u8> {
    let mut fixed = [0u8; 12];
    fixed[0] = libc::AF_INET as u8;
    fixed[4..8].copy_from_slice(&index.to_ne_bytes());
    fixed[8..10].copy_from_slice(&NUD_PERMANENT.to_ne_bytes());
    fixed[10] = NTF_PROXY;
    let mut m = nl::nl_begin_raw(&fixed);
    nl::put_attr(&mut m, NDA_DST, &addr);
    m
}

/// `addr/32` on link `index`, no prefix route, marked as a held address.
fn msg_held_addr(index: i32, addr: [u8; 4]) -> Vec<u8> {
    let mut m = nl::msg_addr(index, addr, 32);
    nl::put_attr(&mut m, IFA_FLAGS, &IFA_F_NOPREFIXROUTE.to_ne_bytes());
    nl::put_attr(&mut m, IFA_PROTO, &[HELD_ADDR_PROTO]);
    m
}

/// An unsolicited announcement of `addr` at `mac` out of link `index`: a
/// broadcast request whose sender and target are both the address.
fn announce(index: i32, mac: [u8; 6], addr: [u8; 4]) -> bool {
    let proto = ETH_P_ARP.to_be();
    // SAFETY: plain socket call; CLOEXEC keeps it out of any child.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            proto as i32,
        )
    };
    if fd < 0 {
        return false;
    }
    let mut frame = [0u8; 28];
    frame[0..2].copy_from_slice(&1u16.to_be_bytes()); // Ethernet
    frame[2..4].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
    frame[4] = 6;
    frame[5] = 4;
    frame[6..8].copy_from_slice(&1u16.to_be_bytes()); // request
    frame[8..14].copy_from_slice(&mac);
    frame[14..18].copy_from_slice(&addr);
    frame[24..28].copy_from_slice(&addr);
    // SAFETY: a zeroed sockaddr_ll is a valid starting value.
    let mut sll: libc::sockaddr_ll = unsafe { core::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = proto;
    sll.sll_ifindex = index;
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(&[0xFF; 6]);
    // SAFETY: `frame` and `sll` outlive the call; closing the socket opened
    // above.
    let n = unsafe {
        let n = libc::sendto(
            fd,
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
            &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
            core::mem::size_of::<libc::sockaddr_ll>() as u32,
        );
        libc::close(fd);
        n
    };
    n == frame.len() as isize
}

/// Announce `addr` again after each of [`ANNOUNCE_REPEATS_MS`], while it is
/// still realized on `uplink`.
fn repeat_announcements(addr: [u8; 4], uplink: String, index: i32, mac: [u8; 6]) {
    let spawned = std::thread::Builder::new()
        .name("fx-held-announce".into())
        .spawn(move || {
            for gap in ANNOUNCE_REPEATS_MS {
                std::thread::sleep(std::time::Duration::from_millis(gap));
                let still = state().held_real.iter().any(|r| {
                    r.addr == addr && r.mode == wire::held::MODE_ANNOUNCE && r.uplink == uplink
                });
                if !still {
                    return;
                }
                let _ = announce(index, mac, addr);
            }
        });
    if spawned.is_err() {
        log::warn!(
            "[net_route] cannot repeat the announcement of {}",
            dotted(addr)
        );
    }
}

/// Withdraw a realized held address: the proxy entry first (it is what
/// answers), then the route; or the address.
fn withdraw_held(r: &HeldReal, table: Option<u32>) -> bool {
    let ok = |rc: i32, gone: &[i32]| rc == 0 || gone.contains(&-rc) || gone.contains(&rc);
    if r.mode == wire::held::MODE_ANNOUNCE {
        let mut m = msg_proxy(r.uplink_index, r.addr);
        let a = ok(
            nl::nl_request(&mut m, RTM_DELNEIGH, 0),
            &[libc::ENOENT, libc::ENODEV],
        );
        let b = match table {
            Some(t) => {
                let mut m = nl::msg_route_key(t, r.addr, 32);
                ok(
                    nl::nl_request(&mut m, nl::RTM_DELROUTE, 0),
                    &[libc::ESRCH, libc::ENOENT],
                )
            }
            None => true,
        };
        a && b
    } else {
        let mut m = nl::msg_addr(r.uplink_index, r.addr, 32);
        ok(
            nl::nl_request(&mut m, nl::RTM_DELADDR, 0),
            &[libc::EADDRNOTAVAIL, libc::ENODEV],
        )
    }
}

/// Install one held address; `Err` leaves nothing of it.
fn install_held(
    live: &instance::Live,
    st: &mut State,
    tag: &str,
    r: &HeldReal,
    mac: Option<[u8; 6]>,
    table: Option<u32>,
) -> Result<(), i32> {
    if r.mode != wire::held::MODE_ANNOUNCE {
        let mut m = msg_held_addr(r.uplink_index, r.addr);
        let rc = nl::nl_request(
            &mut m,
            nl::RTM_NEWADDR,
            nl::NLM_F_CREATE | nl::NLM_F_REPLACE,
        );
        return if rc == 0 || rc == -libc::EEXIST {
            Ok(())
        } else {
            Err(rc)
        };
    }
    let table = table.ok_or(errno::ERROR)?;
    let dummy = ensure_dummy(tag).ok_or(errno::ERROR)?;
    let mut route = nl::msg_route(table, r.addr, 32, dummy.index, None, None, false);
    let rc = nl::nl_request(
        &mut route,
        nl::RTM_NEWROUTE,
        nl::NLM_F_CREATE | nl::NLM_F_REPLACE,
    );
    if rc != 0 {
        return Err(rc);
    }
    // The uplink forwards (a proxy entry is answered only there) and answers
    // a broadcast request at once.
    let delay = format!("net/ipv4/neigh/{}/proxy_delay", r.uplink);
    if !depend_uplink(live, st, &r.uplink) || !depend(live, &delay, "0") {
        let _ = withdraw_held(r, Some(table));
        return Err(errno::EACCES);
    }
    if !st.proxy_uplinks.contains(&r.uplink) {
        st.proxy_uplinks.push(r.uplink.clone());
    }
    let mut m = msg_proxy(r.uplink_index, r.addr);
    let rc = nl::nl_request(
        &mut m,
        nl::RTM_NEWNEIGH,
        nl::NLM_F_CREATE | nl::NLM_F_REPLACE,
    );
    if rc != 0 {
        let _ = withdraw_held(r, Some(table));
        return Err(rc);
    }
    match mac {
        Some(mac) if announce(r.uplink_index, mac, r.addr) => {
            repeat_announcements(r.addr, r.uplink.clone(), r.uplink_index, mac);
        }
        _ => log::warn!(
            "[net_route] {} held, but its announcement on {} was not sent",
            dotted(r.addr),
            r.uplink
        ),
    }
    Ok(())
}

/// Bring the host in line with the held-address table: classify each entry,
/// claim the armed ones, withdraw what is no longer wanted, install the
/// rest, and drop proxy-delay dependences no announced address needs.
fn realize_held(st: &mut State) {
    use wire::reason as r;
    let n = st.held.len();
    let p = probes(st);
    let tag = match instance::live_tag() {
        Ok(t) => t,
        Err(e) => {
            log::warn!("[net_route] not live in the host registry ({e})");
            st.held_outcome = vec![HeldOutcome::Unknown; n];
            return;
        }
    };
    let links = nl::links().unwrap_or_default();
    let addrs = host_addrs().unwrap_or_default();
    let mut out = vec![HeldOutcome::Unknown; n];
    let mut want: Vec<Option<HeldReal>> = vec![None; n];
    for (i, h) in st.held.iter().enumerate() {
        let a = v4(&h.addr);
        out[i] = if h.family != wire::FAM_IPV4 {
            HeldOutcome::Refused(r::UNSUPPORTED)
        } else if h.state_req == wire::held::FENCED {
            HeldOutcome::Fenced
        } else if let Err(o) = if h.mode == wire::held::MODE_ANNOUNCE {
            announce_gate(&p)
        } else if p.admin {
            Ok(())
        } else {
            Err(HeldOutcome::Refused(r::NO_PRIVILEGE))
        } {
            o
        } else if let Some((uplink, uplink_index)) = covering_uplink(&tag, a, &links, &addrs) {
            // The host holding the address itself (not as one of ours).
            let ours = st.held_real.iter().any(|x| x.addr == a);
            let taken = !ours
                && addrs.iter().any(|x| {
                    x.addr == a
                        && (h.mode == wire::held::MODE_ANNOUNCE || x.proto != HELD_ADDR_PROTO)
                });
            if taken {
                HeldOutcome::Refused(r::CONFLICT)
            } else {
                want[i] = Some(HeldReal {
                    addr: a,
                    mode: h.mode,
                    uplink,
                    uplink_index,
                });
                HeldOutcome::Realized
            }
        } else {
            HeldOutcome::Refused(r::UNSUPPORTED)
        };
    }
    // Claims: the armed entries, against every other live runtime's.
    let items: Vec<(instance::Claim, usize)> = st
        .held
        .iter()
        .enumerate()
        .filter(|(i, _)| want[*i].is_some())
        .map(|(i, h)| {
            (
                claim_of(instance::ClaimKind::Held, h.family, &h.addr, 32),
                i,
            )
        })
        .collect();
    let mut claimed: Vec<Outcome> = (0..n)
        .map(|i| {
            if want[i].is_some() {
                Outcome::Ok
            } else {
                Outcome::Unsupported
            }
        })
        .collect();
    let live_ok = instance::with_live(|live| {
        claim_all(live, instance::ClaimKind::Held, &items, &mut claimed)
    });
    for i in 0..n {
        let o = match claimed[i] {
            _ if want[i].is_none() => continue,
            _ if live_ok.is_err() => HeldOutcome::Unknown,
            Outcome::Ok => continue,
            Outcome::Conflict => HeldOutcome::Refused(r::CONFLICT),
            Outcome::Failed | Outcome::Unsupported => HeldOutcome::Unknown,
        };
        out[i] = o;
        want[i] = None;
    }
    // Withdraw what is no longer wanted.
    let table = if st.held_real.is_empty() {
        None
    } else {
        st.rule
            .map(|x| x.0)
            .or_else(|| ensure_rule().ok().map(|x| x.0))
    };
    let mut kept = Vec::new();
    for real in std::mem::take(&mut st.held_real) {
        if want.iter().flatten().any(|w| *w == real) {
            kept.push(real);
            continue;
        }
        if withdraw_held(&real, table) {
            st.held_fences += 1;
            let f = st.held_fences;
            note_evidence(st, real.addr, None, Some(f));
        } else {
            log::warn!("[net_route] held {} not withdrawn", dotted(real.addr));
            for (i, h) in st.held.iter().enumerate() {
                if v4(&h.addr) == real.addr && out[i] == HeldOutcome::Fenced {
                    out[i] = HeldOutcome::Unknown;
                }
            }
            // Kept as realized, so the next replace tries again.
            kept.push(real);
        }
    }
    st.held_real = kept;
    // Install the rest (the instance rule first: it is resolved outside the
    // registry section below, which holds the instance).
    let announcing = want
        .iter()
        .flatten()
        .any(|w| w.mode == wire::held::MODE_ANNOUNCE && !st.held_real.contains(w));
    let table = if announcing {
        match ensure_rule() {
            Ok(r) => {
                st.rule = Some(r);
                Some(r.0)
            }
            Err(e) => {
                log::warn!("[net_route] cannot install the instance rule ({e})");
                None
            }
        }
    } else {
        None
    };
    let guarded_before = st.guarded_uplinks.len();
    let _ = instance::with_live(|live| {
        for (i, w) in want.iter().enumerate() {
            let Some(w) = w else { continue };
            if st.held_real.contains(w) {
                continue;
            }
            let mac = links
                .iter()
                .find(|l| l.index == w.uplink_index)
                .and_then(|l| l.mac);
            match install_held(live, st, &tag, w, mac, table) {
                Ok(()) => {
                    st.held_real.push(w.clone());
                    st.held_installs = st.held_installs.wrapping_add(1);
                    let g = st.held_installs;
                    note_evidence(st, w.addr, Some(g), None);
                }
                Err(e) => {
                    log::warn!(
                        "[net_route] held {} on {} not realized ({e})",
                        dotted(w.addr),
                        w.uplink
                    );
                    out[i] = HeldOutcome::Unknown;
                }
            }
        }
        // Proxy delays no announced address needs any more.
        let needed: Vec<String> = st
            .held_real
            .iter()
            .filter(|x| x.mode == wire::held::MODE_ANNOUNCE)
            .map(|x| x.uplink.clone())
            .collect();
        st.proxy_uplinks.retain(|u| {
            if needed.contains(u) {
                return true;
            }
            let _ = live.release_tunable(&format!("net/ipv4/neigh/{u}/proxy_delay"));
            false
        });
    });
    if st.guarded_uplinks.len() != guarded_before {
        if let Err(e) = apply_guard(&tag, st) {
            log::warn!("[net_route] guard not redone for a held uplink ({e})");
        }
    }
    st.held_outcome = out;
}

// ---- the realizer ---------------------------------------------------------------

fn apply_segments(new: &[wire::Segment]) -> Result<(), i32> {
    let mut st = state();
    st.segments = new.to_vec();
    st.seg_outcome = vec![Outcome::Ok; new.len()];
    if instance::state_dir().is_some() {
        realize(&mut st);
    }
    Ok(())
}

fn apply_routes(new: &[wire::Route]) -> Result<(), i32> {
    let mut st = state();
    st.routes = new.to_vec();
    st.route_outcome = vec![Outcome::Ok; new.len()];
    if instance::state_dir().is_some() {
        realize(&mut st);
    }
    Ok(())
}

fn apply_held(new: &[wire::Held]) -> Result<(), i32> {
    let mut st = state();
    st.held = new.to_vec();
    st.held_outcome = vec![HeldOutcome::Unknown; new.len()];
    if instance::state_dir().is_some() {
        realize_held(&mut st);
    }
    Ok(())
}

fn segment_in_use(id: u16) -> bool {
    let st = state();
    if !st.attachments.iter().any(|a| a.segment == id) {
        return false;
    }
    let links = nl::links().unwrap_or_default();
    st.attachments
        .iter()
        .any(|a| a.segment == id && links.iter().any(|l| l.name == a.link))
}

/// Record an install (`install_gen`) or a withdrawal (`cutoff`) of `addr`.
fn note_evidence(st: &mut State, addr: [u8; 4], install: Option<u32>, fence: Option<u64>) {
    let i = match st.held_evidence.iter().position(|e| e.0 == addr) {
        Some(i) => i,
        None => {
            st.held_evidence.push((addr, 0, 0));
            st.held_evidence.len() - 1
        }
    };
    if let Some(g) = install {
        st.held_evidence[i].1 = g;
    }
    if let Some(f) = fence {
        st.held_evidence[i].2 = f;
    }
}

/// Held address `index`'s evidence: the install that realized it, and for
/// one fenced, the withdrawal that took it off the host — a boundary at the
/// host's hand-off (the kernel stops sending from it), not at the wire.
fn held_evidence(index: usize) -> (u32, u64, u8) {
    let st = state();
    let Some(h) = st.held.get(index) else {
        return (0, 0, 0);
    };
    let a = v4(&h.addr);
    let Some(&(_, ig, cut)) = st.held_evidence.iter().find(|e| e.0 == a) else {
        return (0, 0, 0);
    };
    let fenced = matches!(st.held_outcome.get(index), Some(HeldOutcome::Fenced));
    let cut = if fenced { cut } else { 0 };
    (
        ig,
        cut,
        crate::abi::contracts::net::identity::cutoff::RING_HANDOFF,
    )
}

static REALIZER: store::Realizer = store::Realizer {
    caps,
    segments: apply_segments,
    routes: apply_routes,
    held: apply_held,
    segment_in_use,
    state: entry_state,
    held_evidence,
};

/// Attach a workload's host end `link` (index `index`) holding `addr` to
/// `seg`: the address routed to the link from the gateway in the instance
/// table, the segment MTU, forwarding, and the guard redone with it.
/// Returns 0 or a negative errno; the caller removes the link on failure.
///
/// An address another live attachment holds, or a segment's gateway, is
/// `EEXIST`: the route to it would be taken from the workload that has it,
/// and the guard would let both send as it.
pub fn attach(link: &str, index: i32, addr: [u8; 4], seg: &wire::Segment) -> i32 {
    let mut st = state();
    let p = probes(&mut st);
    if !p.admin || !p.nft || !p.tunables {
        return errno::ENOSYS;
    }
    let links = nl::links().unwrap_or_default();
    let taken = st
        .attachments
        .iter()
        .any(|a| a.addr == addr && a.link != link && links.iter().any(|l| l.name == a.link))
        || st.gateways.contains(&addr);
    if taken {
        log::warn!(
            "[net_route] {} is already held on this node: not attached to {link}",
            dotted(addr)
        );
        return errno::EEXIST;
    }
    // Attachments whose link has gone (a workload whose domain went without
    // its release reaching here) no longer speak for their address.
    st.attachments
        .retain(|a| a.link == link || links.iter().any(|l| l.name == a.link));
    match st
        .segments
        .iter()
        .zip(&st.seg_outcome)
        .find(|(s, _)| s.id == seg.id)
    {
        Some((_, Outcome::Ok)) => {}
        Some((_, Outcome::Conflict)) => return errno::EEXIST,
        _ => return errno::ENOSYS,
    }
    let Ok((table, _)) = ensure_rule() else {
        return errno::ERROR;
    };
    let mtu = (seg.mtu != 0).then_some(seg.mtu as u32);
    let mut up = nl::msg_link_up(index, mtu);
    let rc = nl::nl_request(&mut up, nl::RTM_NEWLINK, 0);
    if rc != 0 {
        return rc;
    }
    if !set_own_tunable(&format!("net/ipv4/conf/{link}/forwarding"), "1") {
        return errno::EACCES;
    }
    let mut route = nl::msg_route(table, addr, 32, index, None, Some(v4(&seg.gateway)), false);
    let rc = nl::nl_request(
        &mut route,
        nl::RTM_NEWROUTE,
        nl::NLM_F_CREATE | nl::NLM_F_REPLACE,
    );
    if rc != 0 {
        log::warn!(
            "[net_route] route to {} on {link} not added: {rc}",
            dotted(addr)
        );
        return rc;
    }
    let tag = match instance::live_tag() {
        Ok(t) => t,
        Err(e) => return e,
    };
    st.attachments.retain(|a| a.link != link);
    st.attachments.push(Attachment {
        link: link.to_string(),
        addr,
        segment: seg.id,
    });
    match apply_guard(&tag, &st) {
        Ok(()) => 0,
        Err(e) => {
            // The workload does not run: its link is removed by the caller,
            // and the guard stays as it was.
            st.attachments.retain(|a| a.link != link);
            e
        }
    }
}

/// A workload holding `addr` is destroyed: its attachment leaves the guard
/// (its link and the route to it went with its domain).
pub fn detach(addr: [u8; 4]) {
    let mut st = state();
    let before = st.attachments.len();
    st.attachments.retain(|a| a.addr != addr);
    if st.attachments.len() == before {
        return;
    }
    if let Ok(tag) = instance::live_tag() {
        if let Err(e) = apply_guard(&tag, &st) {
            log::warn!("[net_route] guard not redone after a detach ({e})");
        }
    }
}

/// The provider: the shared store, realized on this host.
///
/// # Safety
/// As `crate::kernel::net_route::dispatch`.
pub unsafe fn dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    store::dispatch(Some(&REALIZER), handle, opcode, arg, arg_len)
}

// ---- reclaim ------------------------------------------------------------------

/// Reclaim hook: the tag's guard (first: it acts for the tag).
pub fn reclaim_guard(ctx: &instance::ReclaimCtx<'_>) -> Result<(), i32> {
    let t = guard_table_name(ctx.tag);
    let out = match nft()
        .args(["delete", "table", "ip", &t])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
    {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(errno::ERROR),
    };
    if out.status.success() {
        log::info!("[net_route] reclaimed guard {t}");
        return Ok(());
    }
    let why = String::from_utf8_lossy(&out.stderr);
    if why.contains("No such file") || why.contains("does not exist") {
        return Ok(());
    }
    // Without the privilege no guard was ever made by this host's runtimes.
    if why.contains("Operation not permitted") {
        return Ok(());
    }
    log::warn!("[net_route] cannot delete {t}: {}", why.trim());
    Err(errno::ERROR)
}

/// Reclaim hook: the tag's rule.
pub fn reclaim_rule(ctx: &instance::ReclaimCtx<'_>) -> Result<(), i32> {
    let (Some(table), Some(prio)) = (ctx.table, ctx.priority) else {
        return Ok(());
    };
    let mut m = nl::msg_rule(table, prio);
    match nl::nl_request(&mut m, nl::RTM_DELRULE, 0) {
        0 => Ok(()),
        rc if rc == -libc::ENOENT || rc == -libc::EPERM => Ok(()),
        rc => Err(rc),
    }
}

/// Reclaim hook: every route in the tag's table.
pub fn reclaim_routes(ctx: &instance::ReclaimCtx<'_>) -> Result<(), i32> {
    let Some(table) = ctx.table else {
        return Ok(());
    };
    let Ok(all) = nl::routes() else {
        return Ok(());
    };
    let mut result = Ok(());
    for r in all.into_iter().filter(|r| r.table == table) {
        let mut m = nl::msg_route_key(table, r.dst, r.dst_len);
        let rc = nl::nl_request(&mut m, nl::RTM_DELROUTE, 0);
        if rc != 0 && rc != -libc::ESRCH {
            result = Err(rc);
        }
    }
    result
}

/// Reclaim hook (first phase): the tag's held addresses — their proxy
/// entries on every link, their routes in the tag's table, and `deliver`
/// addresses carrying [`HELD_ADDR_PROTO`] — so a dead runtime stops
/// answering for them before anything else is collected. Only addresses no
/// live runtime holds too (`ctx.claims`).
pub fn reclaim_held(ctx: &instance::ReclaimCtx<'_>) -> Result<(), i32> {
    let held: Vec<[u8; 4]> = ctx
        .claims
        .iter()
        .filter(|c| c.kind == instance::ClaimKind::Held && c.family == wire::FAM_IPV4)
        .map(|c| v4(&c.addr))
        .collect();
    if held.is_empty() {
        return Ok(());
    }
    let links = nl::links()?;
    let addrs = host_addrs()?;
    let gone = |rc: i32, ok: &[i32]| rc == 0 || rc == -libc::EPERM || ok.contains(&-rc);
    let mut result = Ok(());
    for a in held {
        for l in &links {
            let mut m = msg_proxy(l.index, a);
            let rc = nl::nl_request(&mut m, RTM_DELNEIGH, 0);
            if !gone(rc, &[libc::ENOENT, libc::ENODEV]) {
                result = Err(rc);
            }
        }
        if let Some(t) = ctx.table {
            let mut m = nl::msg_route_key(t, a, 32);
            let rc = nl::nl_request(&mut m, nl::RTM_DELROUTE, 0);
            if !gone(rc, &[libc::ESRCH, libc::ENOENT]) {
                result = Err(rc);
            }
        }
        for x in addrs
            .iter()
            .filter(|x| x.addr == a && x.len == 32 && x.proto == HELD_ADDR_PROTO)
        {
            let mut m = nl::msg_addr(x.index, a, 32);
            let rc = nl::nl_request(&mut m, nl::RTM_DELADDR, 0);
            if !gone(rc, &[libc::EADDRNOTAVAIL, libc::ENODEV]) {
                result = Err(rc);
            }
        }
        log::info!(
            "[net_route] reclaimed held {} of tag {}",
            dotted(a),
            ctx.tag
        );
    }
    result
}
