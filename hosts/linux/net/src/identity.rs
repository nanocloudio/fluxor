//! Address control (`contracts/net/identity.rs`) on Linux: a workload's
//! network identity, realized as a veth pair into its own network domain.
//!
//! The writer (the node agent) sends `ADDR_ADD` on this provider's
//! `addr_ctl` port after it creates the workload; `owner_tag` names the
//! workload's owner slot. The runtime has told this provider, by owner
//! facts, the owner's host process and a `NETLINK_ROUTE` socket it opened
//! inside the process's network domain; the provider configures the inside
//! through that socket and never enters the domain itself.
//!
//! | Concept | Realization |
//! |---|---|
//! | Host end | `fx<stem>w<slot>`, aliased with the instance's tag, up, no address. |
//! | Workload end | `fxc<slot>`, made directly inside the owner's domain (by its pid), up; `lo` up. |
//! | Segment 0 | The address with its prefix on the workload end. The host end is left unattached: its plumbing is the writer's. |
//! | Segment ≥ 1 | Inside: `addr/32`, a permanent neighbour entry gateway → the host end's MAC, `default via gateway onlink`, the segment MTU. Node side: [`crate::route::attach`]. |
//!
//! Answers go on the events port: `MSG_ADDR_ADDED` with a fresh token and a
//! generation, or `MSG_ADDR_REFUSED` with the identity contract's reason:
//!
//! - `NOT_UNICAST`: not an IPv4 unicast address, or IPv6 (this provider
//!   realizes IPv4 only).
//! - `OWNER`: another owner holds the address, or the owner tag names the
//!   node (the node's own addresses are the host's; an address the node
//!   answers for is a `net_route` held address).
//! - `TABLE_FULL`: the owner already holds another address (one identity
//!   per workload).
//! - `SEGMENT`: the segment is not in the table, does not hold the
//!   address, or the address is its gateway.
//! - `ACTUATOR`: the host cannot realize it — no host process for the
//!   owner, no netlink socket into its domain, no privilege, an install
//!   that asked to start fenced (a host address has no emission gate), or a
//!   host refusal while realizing. `ADDR_ARM` and `ADDR_FENCE` are refused
//!   the same way: a host address always emits.
//! - `NOT_FOUND`: `ADDR_DEL`, `ADDR_ARM` or `ADDR_FENCE` of an address not
//!   installed.
//!
//! An `ADDR_ADD` of an address its owner already holds answers
//! `MSG_ADDR_ADDED` again with the same token and generation. `ADDR_DEL`
//! is not answered when it removes; it discards the address's connection
//! state and its attachment. An owner that is gone loses its address the
//! same way. `OWNER_RESOLVER` is the socket data plane's, not this
//! control half's, and is not acted on here.

use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant};

use fluxor_abi::contracts::net::identity as id;
use fluxor_abi::contracts::net::route as rt;
use fluxor_host_lane::control::OwnerFact;

use crate::instance;
use crate::netlink as nl;

/// How long an `ADDR_ADD` waits for its owner's facts before it is refused.
pub const OWNER_WAIT: Duration = Duration::from_secs(2);

/// An owner's host process, as the runtime told it.
struct Owner {
    slot: u16,
    generation: u32,
    pid: u32,
    netlink: Option<OwnedFd>,
}

/// One installed address.
struct Installed {
    owner: u16,
    addr: [u8; 4],
    link: String,
    token: [u8; 16],
    generation: u32,
}

/// The address-control state: owners, installed addresses, installs
/// waiting for their owner, and events owed to the writer.
#[derive(Default)]
pub struct Identity {
    owners: Vec<Owner>,
    installed: Vec<Installed>,
    waiting: Vec<(Instant, Vec<u8>)>,
    next_generation: u32,
    events: Vec<Vec<u8>>,
}

fn frame(msg: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(id::FRAME_HDR + payload.len());
    f.push(msg);
    f.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    f.extend_from_slice(payload);
    f
}

fn addr16(a: [u8; 4]) -> [u8; 16] {
    let mut x = [0u8; 16];
    x[..4].copy_from_slice(&a);
    x
}

fn unicast_v4(a: [u8; 4]) -> bool {
    a != [0; 4] && a[0] != 127 && a[0] < 224
}

/// Sixteen bytes from the kernel's entropy, or `None`.
fn fresh_token() -> Option<[u8; 16]> {
    let mut t = [0u8; 16];
    // SAFETY: `t` is writable for its length.
    let n = unsafe { libc::getrandom(t.as_mut_ptr().cast(), t.len(), 0) };
    (n == t.len() as isize).then_some(t)
}

impl Identity {
    fn refuse(&mut self, addr: &[u8], op: u8, reason: u8) {
        let mut p = [0u8; 18];
        for (d, s) in p.iter_mut().zip(addr.iter().take(16)) {
            *d = *s;
        }
        p[16] = op;
        p[17] = reason;
        self.events.push(frame(id::MSG_ADDR_REFUSED, &p));
    }

    fn added(&mut self, i: usize) {
        let Some(x) = self.installed.get(i) else {
            return;
        };
        let mut p = Vec::with_capacity(id::EVENT_PAYLOAD_MAX);
        p.extend_from_slice(&addr16(x.addr));
        p.extend_from_slice(&x.token);
        p.extend_from_slice(&x.generation.to_le_bytes());
        self.events.push(frame(id::MSG_ADDR_ADDED, &p));
    }

    /// The events owed to the writer, oldest first.
    pub fn take_events(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.events)
    }

    /// The host-end links of every installed address.
    pub fn links_in_use(&self) -> Vec<String> {
        self.installed.iter().map(|x| x.link.clone()).collect()
    }

    /// An owner's host process started (or this provider just learned of
    /// it). A slot's earlier owner, if any, loses what it held.
    pub fn owner(&mut self, fact: OwnerFact, netlink: Option<OwnedFd>) {
        let earlier: Vec<(u16, u32)> = self
            .owners
            .iter()
            .filter(|o| o.slot == fact.slot && o.generation != fact.generation)
            .map(|o| (o.slot, o.generation))
            .collect();
        for (s, g) in earlier {
            self.owner_gone(s, g);
        }
        self.owners
            .retain(|o| !(o.slot == fact.slot && o.generation == fact.generation));
        self.owners.push(Owner {
            slot: fact.slot,
            generation: fact.generation,
            pid: fact.pid,
            netlink,
        });
    }

    /// That owner's process is gone: its address leaves the node.
    pub fn owner_gone(&mut self, slot: u16, generation: u32) {
        let before = self.owners.len();
        self.owners
            .retain(|o| !(o.slot == slot && o.generation == generation));
        if self.owners.len() == before {
            return;
        }
        while let Some(i) = self.installed.iter().position(|x| x.owner == slot) {
            let x = self.installed.swap_remove(i);
            remove(&x);
        }
    }

    /// One record off `addr_ctl`.
    pub fn record(&mut self, rec: &[u8]) {
        let Some(&msg) = rec.first() else { return };
        let Some(len) = rec
            .get(1..3)
            .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
        else {
            return;
        };
        let Some(payload) = rec.get(id::FRAME_HDR..id::FRAME_HDR + len) else {
            return;
        };
        match msg {
            id::ADDR_ADD => self.add(payload.to_vec(), Instant::now() + OWNER_WAIT),
            id::ADDR_DEL => self.del(payload),
            id::ADDR_ARM | id::ADDR_FENCE => {
                let Some(a) = payload.get(..16) else { return };
                let installed = self.installed.iter().any(|x| addr16(x.addr) == *a);
                let reason = if installed {
                    id::refusal::ACTUATOR
                } else {
                    id::refusal::NOT_FOUND
                };
                self.refuse(a, msg, reason);
            }
            _ => {}
        }
    }

    /// Retry installs waiting for their owner's facts; refuse those whose
    /// wait ran out. `true` while any still waits.
    pub fn poll(&mut self) -> bool {
        for (deadline, p) in std::mem::take(&mut self.waiting) {
            self.add(p, deadline);
        }
        !self.waiting.is_empty()
    }

    fn del(&mut self, p: &[u8]) {
        let Some(a) = p.get(..16) else { return };
        match self.installed.iter().position(|x| addr16(x.addr) == *a) {
            Some(i) => {
                let x = self.installed.swap_remove(i);
                remove(&x);
            }
            None => self.refuse(a, id::ADDR_DEL, id::refusal::NOT_FOUND),
        }
    }

    fn add(&mut self, p: Vec<u8>, deadline: Instant) {
        use id::refusal as r;
        if p.len() < id::ADDR_ADD_PAYLOAD_LEN {
            return;
        }
        let a16 = &p[..16];
        let op = id::ADDR_ADD;
        let flags = p.get(id::ADD_FLAGS_OFF).copied().unwrap_or(0);
        let prefix_len = p[id::ADD_PREFIX_LEN_OFF];
        let owner = u16::from_le_bytes([p[id::ADD_OWNER_TAG_OFF], p[id::ADD_OWNER_TAG_OFF + 1]]);
        let segment = p
            .get(id::ADD_SEGMENT_OFF..id::ADD_SEGMENT_OFF + 2)
            .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]));
        let addr = [p[0], p[1], p[2], p[3]];
        if flags & id::install::FAMILY6 != 0
            || a16[4..].iter().any(|&b| b != 0)
            || !unicast_v4(addr)
            || prefix_len == 0
            || prefix_len > 32
        {
            return self.refuse(a16, op, r::NOT_UNICAST);
        }
        if owner == 0 {
            return self.refuse(a16, op, r::OWNER);
        }
        if let Some(i) = self.installed.iter().position(|x| x.addr == addr) {
            if self.installed[i].owner == owner {
                return self.added(i);
            }
            return self.refuse(a16, op, r::OWNER);
        }
        if self.installed.iter().any(|x| x.owner == owner) {
            return self.refuse(a16, op, r::TABLE_FULL);
        }
        if flags & id::install::DISARMED != 0 {
            return self.refuse(a16, op, r::ACTUATOR);
        }
        let seg = if segment == 0 {
            None
        } else {
            let mut found = None;
            let a = addr16(addr);
            let rc = crate::tables::with_segment(segment, |s| {
                found = Some(*s);
                0
            });
            match found {
                Some(s) if rc == 0 && s.prefix.contains(rt::FAM_IPV4, &a) && s.gateway != a => {
                    Some(s)
                }
                _ => return self.refuse(a16, op, r::SEGMENT),
            }
        };
        let Some(o) = self.owners.iter().position(|o| o.slot == owner) else {
            if Instant::now() < deadline {
                self.waiting.push((deadline, p));
            } else {
                self.refuse(a16, op, r::ACTUATOR);
            }
            return;
        };
        let Some(token) = fresh_token() else {
            return self.refuse(a16, op, r::NO_ENTROPY);
        };
        let o = &self.owners[o];
        let Some(netlink) = o.netlink.as_ref() else {
            log::warn!("[identity] owner slot {owner} has no netlink socket into its domain");
            return self.refuse(a16, op, r::ACTUATOR);
        };
        let link = match realize(
            owner,
            o.pid,
            netlink.as_raw_fd(),
            addr,
            prefix_len,
            seg.as_ref(),
        ) {
            Ok(l) => l,
            Err(e) => {
                log::warn!(
                    "[identity] {} for owner slot {owner} not realized ({e})",
                    dotted(addr)
                );
                return self.refuse(a16, op, r::ACTUATOR);
            }
        };
        self.next_generation = self.next_generation.wrapping_add(1).max(1);
        self.installed.push(Installed {
            owner,
            addr,
            link,
            token,
            generation: self.next_generation,
        });
        self.added(self.installed.len() - 1);
    }
}

fn dotted(a: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

/// An installed address leaves the node: its connection state, its
/// attachment, and its link (the workload end goes with it).
fn remove(x: &Installed) {
    crate::policy::discard_address_flows(x.addr);
    crate::route::detach(x.addr);
    let _ = nl::delete_link(&x.link);
}

/// The index of link `name` in the domain `fd` is a socket in.
fn index_on(fd: i32, name: &str) -> Result<i32, i32> {
    nl::links_on(fd)?
        .into_iter()
        .find(|l| l.name == name)
        .map(|l| l.index)
        .ok_or(fluxor_abi::errno::ENODEV)
}

fn ok(rc: i32) -> Result<(), i32> {
    if rc == 0 {
        Ok(())
    } else {
        Err(rc)
    }
}

/// Make the pair, configure the inside through `fd`, attach the node side.
/// `Ok(host link name)`; `Err` leaves no link behind.
fn realize(
    slot: u16,
    pid: u32,
    fd: i32,
    addr: [u8; 4],
    prefix_len: u8,
    seg: Option<&rt::Segment>,
) -> Result<String, i32> {
    // A host link under a tag that is not live would be collected by the
    // next instance to start.
    let tag = instance::live_tag()?;
    let host = instance::workload_link_name(&tag, slot);
    let peer = instance::workload_peer_name(slot);
    // A link of this name is an earlier owner's of the slot, left behind.
    let _ = nl::delete_link(&host);
    ok(nl::create_veth_into(&host, &peer, pid))?;
    let r = (|| {
        ok(nl::alias_link(&host, &instance::link_alias(&tag)))?;
        let l = nl::links()?
            .into_iter()
            .find(|l| l.name == host)
            .ok_or(fluxor_abi::errno::ENODEV)?;
        let mut up = nl::msg_link_up(l.index, None);
        ok(nl::nl_request(&mut up, nl::RTM_NEWLINK, 0))?;
        let lo = index_on(fd, "lo")?;
        let inner = index_on(fd, &peer)?;
        let mut m = nl::msg_link_up(lo, None);
        ok(nl::request_on(fd, &mut m, nl::RTM_NEWLINK, 0))?;
        let replace = nl::NLM_F_CREATE | nl::NLM_F_REPLACE;
        match seg {
            None => {
                let mut m = nl::msg_link_up(inner, None);
                ok(nl::request_on(fd, &mut m, nl::RTM_NEWLINK, 0))?;
                let mut m = nl::msg_addr(inner, addr, prefix_len);
                ok(nl::request_on(fd, &mut m, nl::RTM_NEWADDR, replace))?;
            }
            Some(s) => {
                let gw = [s.gateway[0], s.gateway[1], s.gateway[2], s.gateway[3]];
                let mac = l.mac.ok_or(fluxor_abi::errno::ENODEV)?;
                let mtu = (s.mtu != 0).then_some(u32::from(s.mtu));
                let mut m = nl::msg_link_up(inner, mtu);
                ok(nl::request_on(fd, &mut m, nl::RTM_NEWLINK, 0))?;
                let mut m = nl::msg_addr(inner, addr, 32);
                ok(nl::request_on(fd, &mut m, nl::RTM_NEWADDR, replace))?;
                let mut m = nl::msg_neigh(inner, gw, mac);
                ok(nl::request_on(fd, &mut m, nl::RTM_NEWNEIGH, replace))?;
                let mut m =
                    nl::msg_route(nl::RT_TABLE_MAIN, [0; 4], 0, inner, Some(gw), None, true);
                ok(nl::request_on(fd, &mut m, nl::RTM_NEWROUTE, replace))?;
                ok(crate::route::attach(&host, l.index, addr, s))?;
            }
        }
        Ok(())
    })();
    match r {
        Ok(()) => Ok(host),
        Err(e) => {
            let _ = nl::delete_link(&host);
            Err(e)
        }
    }
}

/// Reclaim hook (`instance::RECLAIMERS`): delete every host link the tag
/// left — by alias, and, when the context allows it, a link that lost its
/// alias (created, then its provider died before naming it) by its name.
pub fn reclaim_links(ctx: &instance::ReclaimCtx<'_>) -> Result<(), i32> {
    let stem = instance::stem(ctx.tag);
    let mut result = Ok(());
    for l in nl::links()? {
        let ours = match &l.alias {
            Some(a) => instance::alias_tag(a) == Some(ctx.tag),
            None => ctx.by_name && instance::is_link_name_of(&l.name, stem),
        };
        if !ours {
            continue;
        }
        let rc = nl::del_link(l.index);
        if rc != 0 {
            log::warn!(
                "[identity] cannot delete link {} of tag {}: {rc}",
                l.name,
                ctx.tag
            );
            result = Err(rc);
        }
    }
    result
}
