//! net.policy (0x1E) on linux: a table becomes an nftables table and is
//! applied with `nft -f -`, atomically — the whole table is one nft
//! transaction, so a policy is never half-installed.
//!
//! `FLUXOR_NET_POLICY_DRYRUN=<dir>` writes each table's script to
//! `<dir>/<table>.nft` instead of applying it, and clears `caps::ENFORCED`:
//! the tables are accepted and nothing is claimed about the traffic.
//!
//! Rendering, per table `fx_<tag>_<name>` (family `ip`), `<tag>` this
//! runtime's instance (`instance.rs`), so two runtimes on one host keep
//! their tables apart and a dead runtime's tables are collected by tag:
//!   filter_fwd  forward hook: `ct state established,related accept` first
//!               when the table filters at all (a verdict is a flow's: a reply
//!               to a workload's own connection comes back, and a flow admitted
//!               before a policy change keeps its verdict), then ALLOW/DROP in
//!               table order, then each ISOLATE's drop, then the reject for any
//!               VIP with no backends
//!   filter_out  output hook: the same no-backend rejects, for host traffic
//!   nat_pre / nat_out   prerouting and output: one DNAT per VIP, backends
//!               balanced with `numgen random` when there are several (a
//!               backend port of 0 is the VIP's own port). A
//!               `scope = local` VIP is translated in prerouting only for
//!               traffic arriving on the instance's workload links
//!               (`fx<stem>w*`); output (the node's own dials) always
//!   nat_post    postrouting: source translation of translated flows, keyed
//!               on `ct status dnat` and the flow's original destination —
//!               `always` masquerades to the egress interface's address;
//!               `hairpin` translates only a flow whose source and
//!               translated destination are the same workload (one rule per
//!               backend, `ip saddr B ip daddr B`), to the address the packet
//!               leaves by
//!
//! Established flows keep their verdict across a policy change: connection
//! tracking translates a flow once, at its first packet, and every later
//! packet follows that entry; filtering tables accept
//! `ct state established,related` first. What a policy change must undo —
//! a flow pinned to a backend that was removed — is discarded explicitly
//! ([`ctnl`]), so its next datagram is balanced afresh.
//!
//! `hairpin` and the segment gateway: the contract translates a hairpinned
//! flow to the gateway of the `net.route` segment holding the backend
//! ([`hairpin_source`], `snat ip to <gateway>`); the node side of an attached
//! workload's link holds no address, so masquerade would have none. A
//! backend on no segment masquerades. The gateway is read when the table is
//! rendered, so the segment is written before the tables that hairpin to it;
//! a segment table that cannot be read consistently then refuses the
//! REPLACE (`EAGAIN`) rather than rendering a masquerade in its place.
use crate::abi::contracts::net::policy as wire;
use crate::kernel::net_policy as store;
use crate::kernel::sys::errno;
use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::atomic::{AtomicU8, Ordering};

/// `(proto, vip, vport)` — what a DNAT is keyed by when records merge.
type VipKey = (u8, u32, u16);

/// One merged VIP: its key, flags and backends.
struct Vip {
    key: VipKey,
    flags: u8,
    backends: Vec<(u32, u16)>,
}

fn dry_run_dir() -> Option<String> {
    std::env::var("FLUXOR_NET_POLICY_DRYRUN")
        .ok()
        .filter(|d| !d.is_empty())
}

/// The rule tool's state: 0 not yet probed, 1 works, 2 absent or refused.
static RULE_TOOL: AtomicU8 = AtomicU8::new(0);

/// Whether `nft` is present and the runtime may change the host's rules:
/// a listing goes through the same netlink family a transaction does, and
/// the kernel refuses every message of it without CAP_NET_ADMIN. Probed
/// once, and again after an apply failed.
fn rule_tool_works() -> bool {
    match RULE_TOOL.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let ok = nft()
                .args(["list", "tables", "ip"])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if !ok {
                log::warn!("[net_policy] nft absent or not permitted: tables are not enforced");
            }
            RULE_TOOL.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
            ok
        }
    }
}

/// What this platform realizes. `ENFORCED` only when the rule tool is
/// present and works, and not when it has been told to only write the
/// scripts down.
pub fn caps() -> u32 {
    let all = wire::caps::FILTER
        | wire::caps::DNAT
        | wire::caps::DNAT_LOCAL
        | wire::caps::BALANCE
        | wire::caps::EGRESS
        | wire::caps::SOURCE_TRANSLATE;
    if dry_run_dir().is_none() && rule_tool_works() {
        all | wire::caps::ENFORCED
    } else {
        all
    }
}

/// The source a hairpinned flow to `backend` is translated to: the gateway
/// of the `net.route` segment holding it (the node side of an attached
/// workload's link holds no address, so masquerade would have none to
/// pick). `None` (masquerade) for a backend on no segment.
fn hairpin_source(backend: u32) -> Option<u32> {
    hairpin_gateway(backend).ok().flatten()
}

/// The segment gateway holding `backend`; `Err(EAGAIN)` when the segment
/// table was being replaced across every bounded read.
fn hairpin_gateway(backend: u32) -> Result<Option<u32>, i32> {
    use crate::abi::contracts::net::route as nr;
    let mut a = [0u8; nr::ADDR_LEN];
    a[..4].copy_from_slice(&backend.to_be_bytes());
    let s = crate::kernel::net_route::segment_for(nr::FAM_IPV4, &a)?;
    Ok(s.map(|s| u32::from_be_bytes([s.gateway[0], s.gateway[1], s.gateway[2], s.gateway[3]])))
}

/// Whether every hairpinned backend's segment can be read now, so the
/// rendering names the gateways the segment table holds.
fn hairpin_ready(rules: &[u8]) -> Result<(), i32> {
    for v in vips(rules) {
        if v.flags & wire::rule::DNAT_XLATE_MASK == wire::rule::XLATE_HAIRPIN {
            for (b, _) in &v.backends {
                hairpin_gateway(*b)?;
            }
        }
    }
    Ok(())
}

/// Every VIP a table translates, its records merged.
fn vips(rules: &[u8]) -> Vec<Vip> {
    let mut out: Vec<Vip> = Vec::new();
    let mut at = 0;
    while let Some((kind, body, next)) = wire::next_rule(rules, at) {
        at = next;
        if kind != wire::rule::DNAT {
            continue;
        }
        let Some(d) = wire::dnat(body) else { continue };
        let key = (d.proto, d.vip, d.vport);
        let bes = (0..d.backends as usize).filter_map(|i| wire::dnat_backend(body, i));
        match out.iter_mut().find(|v| v.key == key) {
            Some(v) => v.backends.extend(bes),
            None => out.push(Vip {
                key,
                flags: d.flags,
                backends: bes.collect(),
            }),
        }
    }
    out
}

fn ip(a: u32) -> String {
    let b = a.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn net(a: u32, prefix: u8) -> String {
    if prefix == 32 {
        ip(a)
    } else {
        format!("{}/{}", ip(a), prefix)
    }
}

/// `tcp dport 80-81` / `udp dport 53` / `th dport 80` for any L4 proto, or the
/// protocol alone; empty for any proto and any port.
fn l4(proto: u8, lo: u16, hi: u16) -> String {
    let ports = if lo == 0 && hi == 0 {
        String::new()
    } else if hi == 0 || hi == lo {
        format!("{lo}")
    } else {
        format!("{lo}-{hi}")
    };
    match (proto, ports.is_empty()) {
        (wire::rule::PROTO_TCP, false) => format!(" tcp dport {ports}"),
        (wire::rule::PROTO_UDP, false) => format!(" udp dport {ports}"),
        (wire::rule::PROTO_TCP, true) => " meta l4proto tcp".into(),
        (wire::rule::PROTO_UDP, true) => " meta l4proto udp".into(),
        (wire::rule::PROTO_ICMP, _) => " meta l4proto icmp".into(),
        (_, false) => format!(" meta l4proto {{ tcp, udp }} th dport {ports}"),
        (_, true) => String::new(),
    }
}

fn valid_name(name: &[u8]) -> Option<&str> {
    let s = std::str::from_utf8(name).ok()?;
    s.bytes()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
        .then_some(s)
}

/// The nft script that replaces instance `tag`'s table `name`
/// (`fx_<tag>_<name>`) with `rules` — or deletes it (`rules = None`). Public
/// so the harness can pin the rendering.
pub fn render(tag: &str, name: &str, rules: Option<&[u8]>) -> String {
    let t = super::instance::policy_table_name(tag, name);
    // `table` then `delete table`: the create makes the delete safe when the
    // table does not exist yet, and both sit in the one transaction.
    let mut s = format!("table ip {t}\ndelete table ip {t}\n");
    let Some(rules) = rules else {
        return s;
    };
    let mut fwd = Vec::new();
    let mut isolates = Vec::new();
    let mut rejects = Vec::new();
    let mut at = 0;
    while let Some((kind, body, next)) = wire::next_rule(rules, at) {
        at = next;
        match kind {
            wire::rule::ALLOW | wire::rule::DROP => {
                let Some(f) = wire::filter(body) else {
                    continue;
                };
                let (subj, peer) = if f.dir == wire::rule::DIR_INGRESS {
                    ("daddr", "saddr")
                } else {
                    ("saddr", "daddr")
                };
                let mut r = String::new();
                if f.subject_prefix > 0 {
                    let _ = write!(r, " ip {subj} {}", net(f.subject, f.subject_prefix));
                }
                if f.peer_prefix > 0 {
                    let _ = write!(r, " ip {peer} {}", net(f.peer, f.peer_prefix));
                }
                r.push_str(&l4(f.proto, f.port_lo, f.port_hi));
                let verdict = if kind == wire::rule::ALLOW {
                    "accept"
                } else {
                    "drop"
                };
                fwd.push(format!("\t\t{} {verdict}", r.trim_start()));
            }
            wire::rule::ISOLATE => {
                let Some((dir, subject, prefix)) = wire::isolate(body) else {
                    continue;
                };
                let side = if dir == wire::rule::DIR_INGRESS {
                    "daddr"
                } else {
                    "saddr"
                };
                isolates.push(format!("\t\tip {side} {} drop", net(subject, prefix)));
            }
            _ => {}
        }
    }
    let local_links = format!("fx{}w*", super::instance::stem(tag));
    let (mut pre, mut out, mut post) = (Vec::new(), Vec::new(), Vec::new());
    for v in vips(rules) {
        let (proto, vip, vport) = v.key;
        let bes = &v.backends;
        let m = format!("ip daddr {}{}", ip(vip), l4(proto, vport, vport));
        // A backend port of 0 is the VIP's own.
        let port = |p: u16| if p == 0 { vport } else { p };
        let action = match bes.len() {
            0 => {
                rejects.push(format!("\t\t{m} reject"));
                continue;
            }
            1 if port(bes[0].1) == 0 => format!("{m} dnat to {}", ip(bes[0].0)),
            1 => format!("{m} dnat to {}:{}", ip(bes[0].0), port(bes[0].1)),
            n if bes.iter().all(|(_, p)| port(*p) == 0) => {
                let map: Vec<String> = bes
                    .iter()
                    .enumerate()
                    .map(|(i, (a, _))| format!("{i} : {}", ip(*a)))
                    .collect();
                format!(
                    "{m} dnat ip to numgen random mod {n} map {{ {} }}",
                    map.join(", ")
                )
            }
            n => {
                let map: Vec<String> = bes
                    .iter()
                    .enumerate()
                    .map(|(i, (a, p))| format!("{i} : {} . {}", ip(*a), port(*p)))
                    .collect();
                format!(
                    "{m} dnat ip to numgen random mod {n} map {{ {} }}",
                    map.join(", ")
                )
            }
        };
        if v.flags & wire::rule::DNAT_SCOPE_LOCAL != 0 {
            pre.push(format!("\t\tiifname \"{local_links}\" {action}"));
        } else {
            pre.push(format!("\t\t{action}"));
        }
        out.push(format!("\t\t{action}"));
        // The flow's original destination names the VIP after translation.
        let mut orig = format!("ct status dnat ct original ip daddr {}", ip(vip));
        let known = match proto {
            wire::rule::PROTO_TCP => Some("tcp"),
            wire::rule::PROTO_UDP => Some("udp"),
            _ => None,
        };
        if let Some(p) = known {
            let _ = write!(orig, " ct original protocol {p}");
            if vport != 0 {
                let _ = write!(orig, " ct original proto-dst {vport}");
            }
        }
        match v.flags & wire::rule::DNAT_XLATE_MASK {
            wire::rule::XLATE_ALWAYS => post.push(format!("\t\t{orig} masquerade")),
            wire::rule::XLATE_HAIRPIN => {
                let mut seen: Vec<u32> = Vec::new();
                for (b, _) in bes {
                    if seen.contains(b) {
                        continue;
                    }
                    seen.push(*b);
                    let to = match hairpin_source(*b) {
                        Some(g) => format!("snat ip to {}", ip(g)),
                        None => "masquerade".into(),
                    };
                    post.push(format!("\t\t{orig} ip saddr {0} ip daddr {0} {to}", ip(*b)));
                }
            }
            _ => {}
        }
    }
    let _ = writeln!(s, "table ip {t} {{");
    let _ = writeln!(
        s,
        "\tchain filter_fwd {{\n\t\ttype filter hook forward priority 0; policy accept;"
    );
    if !fwd.is_empty() || !isolates.is_empty() {
        s.push_str("\t\tct state established,related accept\n");
    }
    for r in fwd.iter().chain(isolates.iter()).chain(rejects.iter()) {
        let _ = writeln!(s, "{r}");
    }
    s.push_str("\t}\n");
    if !rejects.is_empty() {
        let _ = writeln!(
            s,
            "\tchain filter_out {{\n\t\ttype filter hook output priority 0; policy accept;"
        );
        for r in &rejects {
            let _ = writeln!(s, "{r}");
        }
        s.push_str("\t}\n");
    }
    for (chain, hook, prio, rs) in [
        ("nat_pre", "prerouting", -100, &pre),
        ("nat_out", "output", -100, &out),
        ("nat_post", "postrouting", 100, &post),
    ] {
        if rs.is_empty() {
            continue;
        }
        let _ = writeln!(
            s,
            "\tchain {chain} {{\n\t\ttype nat hook {hook} priority {prio}; policy accept;"
        );
        for r in rs {
            let _ = writeln!(s, "{r}");
        }
        s.push_str("\t}\n");
    }
    s.push_str("}\n");
    s
}

/// The backends `old` translated to that `new` no longer does, per VIP:
/// `(proto, vip, vport, backend, backend port)`.
pub fn removed_backends(old: &[u8], new: Option<&[u8]>) -> Vec<(u8, u32, u16, u32, u16)> {
    let now = new.map(vips).unwrap_or_default();
    let mut gone = Vec::new();
    for v in vips(old) {
        let kept = now.iter().find(|n| n.key == v.key);
        for b in &v.backends {
            if !kept.is_some_and(|n| n.backends.contains(b)) {
                gone.push((v.key.0, v.key.1, v.key.2, b.0, b.1));
            }
        }
    }
    gone
}

fn apply(name: &[u8], old: Option<&[u8]>, rules: Option<&[u8]>) -> Result<(), i32> {
    let Some(n) = valid_name(name) else {
        return Err(errno::EINVAL);
    };
    if let Some(dir) = dry_run_dir() {
        let script = render(&super::instance::tag(), n, rules);
        let path = format!("{dir}/{n}.nft");
        return std::fs::write(&path, script).map_err(|e| {
            log::warn!("[net_policy] dry run: cannot write {path}: {e}");
            errno::ERROR
        });
    }
    // A table under a tag that is not live would be collected by the next
    // instance to start.
    let tag = super::instance::live_tag()?;
    if let Some(r) = rules {
        hairpin_ready(r)?;
    }
    let script = render(&tag, n, rules);
    let mut command = nft();
    let child = command
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            log::warn!("[net_policy] cannot run nft: {e}");
            return Err(errno::ENOSYS);
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(script.as_bytes());
    }
    let r = match child.wait_with_output() {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            log::warn!(
                "[net_policy] nft refused table {n}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            Err(errno::EACCES)
        }
        Err(e) => {
            log::warn!("[net_policy] nft failed: {e}");
            Err(errno::ERROR)
        }
    };
    if r.is_err() {
        // Re-probe: the tool may have gone, or lost its permission.
        RULE_TOOL.store(0, Ordering::Relaxed);
        return r;
    }
    // A flow already pinned to a backend the table no longer names would
    // keep reaching it: discard it, so its next packet is balanced afresh.
    if let Some(old) = old {
        for (proto, vip, vport, be, bport) in removed_backends(old, rules) {
            ctnl::discard(&ctnl::Match::Backend {
                proto,
                vip,
                vport,
                backend: be,
                backend_port: bport,
            });
        }
    }
    Ok(())
}

/// Discard the connection state of a workload address that is destroyed:
/// every flow it is either end of, before or after translation. Call when
/// the address leaves the node.
pub fn discard_address_flows(addr: [u8; 4]) -> usize {
    ctnl::discard(&ctnl::Match::Address(u32::from_be_bytes(addr)))
}

/// Connection-state discard through ctnetlink, directly (no `conntrack`
/// tool dependency). Needs CAP_NET_ADMIN, probed from the effective set;
/// without it nothing is discarded and the gap is logged once.
pub mod ctnl {
    use std::sync::atomic::{AtomicBool, Ordering};

    const NETLINK_NETFILTER: i32 = 12;
    const NFNL_SUBSYS_CTNETLINK: u16 = 1;
    const IPCTNL_MSG_CT_GET: u16 = 1;
    const IPCTNL_MSG_CT_DELETE: u16 = 2;
    const NLM_F_REQUEST: u16 = 0x1;
    const NLM_F_ACK: u16 = 0x4;
    const NLM_F_DUMP: u16 = 0x300;
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    const CTA_TUPLE_ORIG: u16 = 1;
    const CTA_TUPLE_REPLY: u16 = 2;
    const CTA_ZONE: u16 = 18;
    const CTA_TUPLE_IP: u16 = 1;
    const CTA_TUPLE_PROTO: u16 = 2;
    const CTA_IP_V4_SRC: u16 = 1;
    const CTA_IP_V4_DST: u16 = 2;
    const CTA_PROTO_NUM: u16 = 1;
    const CTA_PROTO_SRC_PORT: u16 = 2;
    const CTA_PROTO_DST_PORT: u16 = 3;
    const NLA_TYPE_MASK: u16 = 0x3fff;
    const CAP_NET_ADMIN: u32 = 12;

    /// Which flows to discard.
    pub enum Match {
        /// Flows translated from `vip:vport` to `backend:backend_port`.
        Backend {
            proto: u8,
            vip: u32,
            vport: u16,
            backend: u32,
            backend_port: u16,
        },
        /// Flows `addr` is any end of.
        Address(u32),
    }

    /// One direction of a flow.
    #[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Tuple {
        pub src: u32,
        pub dst: u32,
        pub proto: u8,
        pub sport: u16,
        pub dport: u16,
    }

    impl Match {
        pub fn hits(&self, orig: &Tuple, reply: &Tuple) -> bool {
            match *self {
                Match::Backend {
                    proto,
                    vip,
                    vport,
                    backend,
                    backend_port,
                } => {
                    (proto == 0 || orig.proto == proto)
                        && orig.dst == vip
                        && (vport == 0 || orig.dport == vport)
                        && reply.src == backend
                        && (backend_port == 0 || reply.sport == backend_port)
                }
                Match::Address(a) => {
                    orig.src == a || orig.dst == a || reply.src == a || reply.dst == a
                }
            }
        }
    }

    /// Whether this runtime holds CAP_NET_ADMIN (the effective set).
    pub fn permitted() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("CapEff:"))
                    .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
            })
            .is_some_and(|c| c & (1 << CAP_NET_ADMIN) != 0)
    }

    static WARNED: AtomicBool = AtomicBool::new(false);

    fn attrs(mut b: &[u8]) -> impl Iterator<Item = (u16, &[u8], &[u8])> {
        // (type, payload, whole attribute)
        std::iter::from_fn(move || {
            if b.len() < 4 {
                return None;
            }
            let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
            let ty = u16::from_ne_bytes([b[2], b[3]]) & NLA_TYPE_MASK;
            if len < 4 || len > b.len() {
                return None;
            }
            let whole = &b[..len];
            let payload = &b[4..len];
            b = &b[((len + 3) & !3).min(b.len())..];
            Some((ty, payload, whole))
        })
    }

    fn tuple(b: &[u8]) -> Tuple {
        let mut t = Tuple::default();
        for (ty, p, _) in attrs(b) {
            match ty {
                CTA_TUPLE_IP => {
                    for (ty, p, _) in attrs(p) {
                        let v = p
                            .get(..4)
                            .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
                        match (ty, v) {
                            (CTA_IP_V4_SRC, Some(v)) => t.src = v,
                            (CTA_IP_V4_DST, Some(v)) => t.dst = v,
                            _ => {}
                        }
                    }
                }
                CTA_TUPLE_PROTO => {
                    for (ty, p, _) in attrs(p) {
                        match ty {
                            CTA_PROTO_NUM => t.proto = p.first().copied().unwrap_or(0),
                            CTA_PROTO_SRC_PORT if p.len() >= 2 => {
                                t.sport = u16::from_be_bytes([p[0], p[1]])
                            }
                            CTA_PROTO_DST_PORT if p.len() >= 2 => {
                                t.dport = u16::from_be_bytes([p[0], p[1]])
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        t
    }

    fn header(ty: u16, flags: u16, seq: u32) -> Vec<u8> {
        let mut m = Vec::with_capacity(64);
        m.extend_from_slice(&0u32.to_ne_bytes()); // length, set by `finish`
        m.extend_from_slice(&((NFNL_SUBSYS_CTNETLINK << 8) | ty).to_ne_bytes());
        m.extend_from_slice(&flags.to_ne_bytes());
        m.extend_from_slice(&seq.to_ne_bytes());
        // Port id: the kernel's.
        m.extend_from_slice(&0u32.to_ne_bytes());
        // nfgenmsg: family AF_INET, version 0, resource id 0.
        m.extend_from_slice(&[libc::AF_INET as u8, 0, 0, 0]);
        m
    }

    fn finish(m: &mut [u8]) {
        let len = (m.len() as u32).to_ne_bytes();
        for (d, s) in m.iter_mut().zip(len) {
            *d = s;
        }
    }

    struct Sock(i32);
    impl Drop for Sock {
        fn drop(&mut self) {
            // SAFETY: the descriptor is this guard's own.
            unsafe { libc::close(self.0) };
        }
    }

    fn socket() -> Option<Sock> {
        // SAFETY: plain libc socket call; CLOEXEC keeps the fd out of any child.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_NETFILTER,
            )
        };
        (fd >= 0).then_some(Sock(fd))
    }

    fn send(s: &Sock, m: &[u8]) -> bool {
        loop {
            // SAFETY: `m` outlives the call; the socket is live.
            let rc = unsafe { libc::send(s.0, m.as_ptr() as *const libc::c_void, m.len(), 0) };
            if rc >= 0 {
                return true;
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return false;
            }
        }
    }

    fn recv(s: &Sock, buf: &mut [u8]) -> isize {
        loop {
            // SAFETY: `buf` is a live, writable buffer of its own length.
            let n = unsafe { libc::recv(s.0, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return n;
            }
        }
    }

    /// Visit each netlink message in `buf[..n]`: `(type, payload)`.
    fn messages(buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
        let mut at = 0usize;
        std::iter::from_fn(move || {
            let h = buf.get(at..at + 16)?;
            let len = u32::from_ne_bytes([h[0], h[1], h[2], h[3]]) as usize;
            let ty = u16::from_ne_bytes([h[4], h[5]]);
            let body = buf.get(at + 16..at + len.max(16))?;
            at += (len.max(16) + 3) & !3;
            Some((ty, body))
        })
    }

    /// Discard every flow `m` matches; the count discarded. Nothing (and a
    /// warning, once) without CAP_NET_ADMIN.
    pub fn discard(m: &Match) -> usize {
        if !permitted() {
            if !WARNED.swap(true, Ordering::Relaxed) {
                log::warn!(
                    "[net_policy] no CAP_NET_ADMIN: connection state of removed backends is kept"
                );
            }
            return 0;
        }
        let Some(dump) = socket() else {
            return 0;
        };
        let mut req = header(IPCTNL_MSG_CT_GET, NLM_F_REQUEST | NLM_F_DUMP, 1);
        finish(&mut req);
        if !send(&dump, &req) {
            return 0;
        }
        // Collect the matching flows' original tuple (and zone) first: a
        // delete on the dumping socket would interleave with the dump.
        let mut victims: Vec<Vec<u8>> = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        'dump: loop {
            let n = recv(&dump, &mut buf);
            if n <= 0 {
                break;
            }
            for (ty, body) in messages(&buf[..n as usize]) {
                if ty == NLMSG_DONE || ty == NLMSG_ERROR {
                    break 'dump;
                }
                let Some(a) = body.get(4..) else { continue };
                let (mut orig, mut reply, mut keep) = (None, None, Vec::new());
                for (ty, p, whole) in attrs(a) {
                    match ty {
                        CTA_TUPLE_ORIG => {
                            orig = Some(tuple(p));
                            keep.extend_from_slice(whole);
                            keep.resize((keep.len() + 3) & !3, 0);
                        }
                        CTA_TUPLE_REPLY => reply = Some(tuple(p)),
                        CTA_ZONE => {
                            keep.extend_from_slice(whole);
                            keep.resize((keep.len() + 3) & !3, 0);
                        }
                        _ => {}
                    }
                }
                if let (Some(o), Some(r)) = (orig, reply) {
                    if m.hits(&o, &r) {
                        victims.push(keep);
                    }
                }
            }
        }
        drop(dump);
        let Some(del) = socket() else {
            return 0;
        };
        let mut done = 0;
        let mut ack = [0u8; 4096];
        for (i, v) in victims.iter().enumerate() {
            let mut req = header(
                IPCTNL_MSG_CT_DELETE,
                NLM_F_REQUEST | NLM_F_ACK,
                2 + i as u32,
            );
            req.extend_from_slice(v);
            finish(&mut req);
            if !send(&del, &req) {
                break;
            }
            let n = recv(&del, &mut ack);
            if n >= 20 {
                let code = i32::from_ne_bytes([ack[16], ack[17], ack[18], ack[19]]);
                // ENOENT: the flow ended meanwhile, which is what was wanted.
                if code == 0 || code == -libc::ENOENT {
                    done += 1;
                }
            }
        }
        done
    }
}

/// The rule tool, holding none of the runtime's descriptors.
fn nft() -> std::process::Command {
    let mut command = std::process::Command::new("nft");
    crate::platform::linux::descriptors::sweep_on_exec(&mut command);
    command
}

/// Reclaim hook (`instance::RECLAIMERS`): delete every table the tag left.
/// No `nft` on the host means no table was ever made.
pub fn reclaim_tables(ctx: &super::instance::ReclaimCtx<'_>) -> Result<(), i32> {
    let prefix = super::instance::policy_table_prefix(ctx.tag);
    let out = match nft()
        .args(["list", "tables", "ip"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()
    {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(errno::ERROR),
    };
    if !out.status.success() {
        log::warn!(
            "[net_policy] cannot list tables: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        return Err(errno::EACCES);
    }
    let listed = String::from_utf8_lossy(&out.stdout);
    let mut result = Ok(());
    for t in listed
        .lines()
        .filter_map(|l| l.trim().strip_prefix("table ip "))
        .map(str::trim)
        .filter(|t| t.starts_with(&prefix))
    {
        let ok = nft()
            .args(["delete", "table", "ip", t])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if ok {
            log::info!("[net_policy] reclaimed table {t} of tag {}", ctx.tag);
        } else {
            result = Err(errno::ERROR);
        }
    }
    result
}

/// The provider: the shared store, linux capabilities, nftables as the hook.
///
/// # Safety
/// As `crate::kernel::net_policy::dispatch`.
pub unsafe fn dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    store::dispatch(caps(), Some(apply), handle, opcode, arg, arg_len)
}
