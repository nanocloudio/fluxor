//! net.policy (0x1E) on linux: a table becomes an nftables table and is
//! applied with `nft -f -`, atomically — the whole table is one nft
//! transaction, so a policy is never half-installed.
//!
//! `FLUXOR_NET_POLICY_DRYRUN=<dir>` writes each table's script to
//! `<dir>/<table>.nft` instead of applying it, and clears `caps::ENFORCED`:
//! the tables are accepted and nothing is claimed about the traffic.
//!
//! Rendering, per table `nc_<name>` (family `ip`):
//!   filter_fwd  forward hook: `ct state established,related accept` first
//!               when the table isolates anything (NetworkPolicy is stateful —
//!               a reply to an isolated pod's own connection must come back),
//!               then ALLOW/DROP in table order, then each ISOLATE's drop, then
//!               the reject for any VIP with no backends
//!   filter_out  output hook: the same no-backend rejects, for host traffic
//!   nat_pre / nat_out   prerouting and output: one DNAT per VIP, backends
//!               balanced with `numgen random` when there are several
use crate::abi::contracts::net::policy as wire;
use crate::kernel::net_policy as store;
use crate::kernel::sys::errno;
use std::fmt::Write as _;
use std::io::Write as _;

/// `(proto, vip, vport)` — what a DNAT is keyed by when records merge.
type VipKey = (u8, u32, u16);

fn dry_run_dir() -> Option<String> {
    std::env::var("FLUXOR_NET_POLICY_DRYRUN")
        .ok()
        .filter(|d| !d.is_empty())
}

/// What this platform enforces: everything, unless it has been told to only
/// write the scripts down.
pub fn caps() -> u32 {
    let all = wire::caps::FILTER | wire::caps::DNAT | wire::caps::BALANCE | wire::caps::EGRESS;
    if dry_run_dir().is_some() {
        all
    } else {
        all | wire::caps::ENFORCED
    }
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

/// The nft script that replaces table `nc_<name>` with `rules` — or deletes it
/// (`rules = None`). Public so the harness can pin the rendering.
pub fn render(name: &str, rules: Option<&[u8]>) -> String {
    let t = format!("nc_{}", name.replace('-', "_"));
    // `table` then `delete table`: the create makes the delete safe when the
    // table does not exist yet, and both sit in the one transaction.
    let mut s = format!("table ip {t}\ndelete table ip {t}\n");
    let Some(rules) = rules else {
        return s;
    };
    let mut fwd = Vec::new();
    let mut isolates = Vec::new();
    let mut rejects = Vec::new();
    // (proto, vip, vport) -> backends, merged across records.
    let mut dnats: Vec<(VipKey, Vec<(u32, u16)>)> = Vec::new();
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
            wire::rule::DNAT => {
                let Some(d) = wire::dnat(body) else { continue };
                let key = (d.proto, d.vip, d.vport);
                let mut bes = Vec::new();
                for i in 0..d.backends as usize {
                    if let Some(b) = wire::dnat_backend(body, i) {
                        bes.push(b);
                    }
                }
                match dnats.iter_mut().find(|(k, _)| *k == key) {
                    Some((_, v)) => v.extend(bes),
                    None => dnats.push((key, bes)),
                }
            }
            _ => {}
        }
    }
    let mut nat = Vec::new();
    for ((proto, vip, vport), bes) in &dnats {
        let m = format!("ip daddr {}{}", ip(*vip), l4(*proto, *vport, *vport));
        match bes.len() {
            0 => rejects.push(format!("\t\t{m} reject")),
            1 => nat.push(format!("\t\t{m} dnat to {}:{}", ip(bes[0].0), bes[0].1)),
            n => {
                let map: Vec<String> = bes
                    .iter()
                    .enumerate()
                    .map(|(i, (a, p))| format!("{i} : {} . {p}", ip(*a)))
                    .collect();
                nat.push(format!(
                    "\t\t{m} dnat ip to numgen random mod {n} map {{ {} }}",
                    map.join(", ")
                ));
            }
        }
    }
    let _ = writeln!(s, "table ip {t} {{");
    let _ = writeln!(
        s,
        "\tchain filter_fwd {{\n\t\ttype filter hook forward priority 0; policy accept;"
    );
    if !isolates.is_empty() {
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
    if !nat.is_empty() {
        for (chain, hook) in [("nat_pre", "prerouting"), ("nat_out", "output")] {
            let _ = writeln!(
                s,
                "\tchain {chain} {{\n\t\ttype nat hook {hook} priority -100; policy accept;"
            );
            for r in &nat {
                let _ = writeln!(s, "{r}");
            }
            s.push_str("\t}\n");
        }
    }
    s.push_str("}\n");
    s
}

fn apply(name: &[u8], rules: Option<&[u8]>) -> Result<(), i32> {
    let Some(n) = valid_name(name) else {
        return Err(errno::EINVAL);
    };
    let script = render(n, rules);
    if let Some(dir) = dry_run_dir() {
        let path = format!("{dir}/{n}.nft");
        return std::fs::write(&path, script).map_err(|e| {
            log::warn!("[net_policy] dry run: cannot write {path}: {e}");
            errno::ERROR
        });
    }
    let child = std::process::Command::new("nft")
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
    match child.wait_with_output() {
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
    }
}

/// The provider: the shared store, linux capabilities, nftables as the hook.
///
/// # Safety
/// As `crate::kernel::net_policy::dispatch`.
pub unsafe fn dispatch(handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    store::dispatch(caps(), Some(apply), handle, opcode, arg, arg_len)
}
