//! The lane handler: `net_route` and `net_policy` calls, the address-control
//! port, owner facts, the restart hold, and the host sockets.
//!
//! Port pair 0, the one static pair, is the identity contract's: `addr_ctl`
//! records in, the events (`MSG_ADDR_*`) out, framed `tlv16`. A call reaches
//! the stores with the caller the runtime named; `RESYNC_END` is taken here,
//! before the store, since ending a hold reads every table.
//!
//! Every socket consumer is a dynamic lane ([`crate::sockets`]), under the
//! owner of the module writing its commands, the node or a workload.

use std::os::fd::OwnedFd;

use fluxor_abi::contracts::net::policy as pol;
use fluxor_abi::contracts::net::route as rt;
use fluxor_abi::errno;
use fluxor_host_lane::control::{gate, lane, wants, Gate, OwnerFact};
use fluxor_host_lane::provider::{
    Call, Handler, Identity as LaneIdentity, Outbox, Poll, Reply, Wake,
};

use crate::identity::Identity;
use crate::sockets::{Config, Owner, Sockets};

/// The address-control port pair's table entry.
pub const ADDR_ENTRY: &str = "NetProto:tlv16:265";

/// The address-control port pair.
pub const ADDR_PORT: usize = 0;

/// The provider's argument, as the composer writes it for a graph's
/// `linux_net`. Space-separated `key=value`:
///
/// - `max_conns`, `write_buf_kib`, `listen_backlog`: the socket engine's
///   sizes (its defaults when absent);
/// - `serves=<contract>,…`: the contracts it serves, of `net_route` and
///   `net_policy` (both when absent; none when empty — a graph whose own
///   stack serves them).
#[derive(Clone, Debug)]
pub struct Args {
    pub sockets: Config,
    pub contracts: Vec<u16>,
}

impl Args {
    pub fn parse(text: &str) -> Result<Args, String> {
        let mut cfg = Config::default();
        let mut contracts = CONTRACTS.to_vec();
        for word in text.split_whitespace() {
            let (k, v) = word
                .split_once('=')
                .ok_or_else(|| format!("`{word}` is not key=value"))?;
            let num = |v: &str| {
                v.parse::<u32>()
                    .map_err(|_| format!("`{k}` is not a number: {v:?}"))
            };
            match k {
                "serves" => {
                    contracts = Vec::new();
                    for name in v.split(',').filter(|n| !n.is_empty()) {
                        let id = fluxor_abi::registry::contract_id(name)
                            .filter(|id| CONTRACTS.contains(id))
                            .ok_or_else(|| {
                                format!("`serves` names {name:?}, which it does not serve")
                            })?;
                        if contracts.contains(&id) {
                            return Err(format!("`serves` names {name:?} twice"));
                        }
                        contracts.push(id);
                    }
                }
                "max_conns" => cfg.max_conns = num(v)? as usize,
                "write_buf_kib" => cfg.write_buf_max = num(v)? as usize * 1024,
                "listen_backlog" => cfg.listen_backlog = num(v)?.min(i32::MAX as u32) as i32,
                _ => return Err(format!("unknown argument `{k}`")),
            }
        }
        Ok(Args {
            sockets: cfg,
            contracts,
        })
    }

    /// The port table this provider states: address control alone. Its
    /// sockets are reached over lanes.
    pub fn ports(&self) -> &'static str {
        ADDR_ENTRY
    }
}

/// The contracts this provider serves.
pub const CONTRACTS: [u16; 2] = [
    fluxor_abi::registry::net_route::ID,
    fluxor_abi::registry::net_policy::ID,
];

/// What this provider states in its `HELLO`: the contracts it serves and
/// the port table `ports` ([`Args::ports`]). It requires no capability: it serves without
/// `CAP_NET_ADMIN` and `CAP_NET_RAW`, and then CAPS and every entry's state
/// say what is not realized and why; a bind of a port below 1024 without
/// `CAP_NET_BIND_SERVICE` is refused as the host refuses it.
pub fn lane_identity<'a>(contracts: &'a [u16], ports: &'a str) -> LaneIdentity<'a> {
    LaneIdentity {
        contracts,
        ports,
        requires_caps: &[],
        wants: wants::OWNERS | wants::LANES,
    }
}

/// The provider's handler.
#[derive(Default)]
pub struct Net {
    identity: Identity,
    /// Events the events port has not taken yet.
    owed: Vec<Vec<u8>>,
    /// The socket engine, every lane's.
    sockets: Option<Box<Sockets>>,
    /// Its bound-endpoint report, when the runtime names where it goes.
    report: Option<crate::endpoints::Report>,
}

impl Net {
    /// A handler for `args`.
    pub fn new(args: &Args) -> Result<Net, String> {
        Ok(Net {
            sockets: Some(Sockets::new(&args.sockets)?),
            report: crate::endpoints::Report::from_env(),
            ..Net::default()
        })
    }

    /// The socket engine's lane for dynamic lane `key`.
    fn lane_of(&self, key: u8) -> Option<usize> {
        self.sockets.as_ref()?.lane_of_key(key)
    }

    /// Step the socket engine and hand on what it planned.
    fn step_sockets(&mut self, out: &mut Outbox<'_>) -> Poll {
        let Some(s) = self.sockets.as_mut() else {
            return Poll::Idle;
        };
        let p = s.step(&mut |k| out.lane_view(k));
        if let Some(r) = self.report.as_mut() {
            r.tick(s);
        }
        s.drain_out(&mut |k, rec| {
            if let Err(e) = out.lane_send(k, rec) {
                log::error!("[linux_net] a planned record was refused ({e:?}) on lane {k}");
            }
        });
        p
    }

    fn flush(&mut self, out: &mut Outbox<'_>) -> bool {
        self.owed.extend(self.identity.take_events());
        while let Some(e) = self.owed.first() {
            if out.send(ADDR_PORT, e).is_err() {
                return true;
            }
            self.owed.remove(0);
        }
        false
    }

    fn end_resync(&mut self) {
        crate::route::resync_end(&self.identity.links_in_use());
    }

    fn dispatch(&mut self, call: &Call<'_>, arg: &mut [u8], data: &mut [u8]) -> i32 {
        let caller = crate::tables::caller_of(&call.caller);
        if call.contract == fluxor_abi::registry::net_route::ID {
            if call.opcode == rt::RESYNC_END {
                if !caller.node {
                    return errno::EACCES;
                }
                self.end_resync();
                return 0;
            }
            return crate::route::dispatch(caller, call.opcode, arg, data);
        }
        crate::policy::dispatch(caller, call.opcode, arg, data)
    }
}

impl Handler for Net {
    fn call(&mut self, call: &Call<'_>, out: &mut [u8]) -> (i32, usize) {
        let rc = self.dispatch(call, out, &mut []);
        (rc, if rc >= 0 { out.len() } else { 0 })
    }

    fn call_data(&mut self, call: &Call<'_>, out: &mut [u8], data: &mut [u8]) -> Reply {
        // A span that only moves in arrives in `call.data`.
        let mut inbound;
        let span: &mut [u8] = if data.is_empty() && !call.data.is_empty() {
            inbound = call.data.to_vec();
            &mut inbound
        } else {
            data
        };
        // A policy READ answers its state over the name in `arg`.
        let need = (call.contract == fluxor_abi::registry::net_policy::ID
            && call.opcode == pol::READ)
            .then(|| rules_len(out))
            .flatten();
        let rc = self.dispatch(call, out, span);
        let out_len = out.len();
        let data_len = if rc >= 0 {
            match (call.contract, call.opcode) {
                (_, rt::READ) | (_, pol::READ) => rc as usize,
                _ => 0,
            }
        } else if rc == errno::ERANGE {
            // What a short READ leaves: the route store's generation, or
            // the length a policy table's rules need.
            match need {
                Some(n) => n,
                None => 8.min(span.len()),
            }
        } else {
            0
        };
        Reply {
            rc,
            out_len,
            data_len,
        }
    }

    fn record(&mut self, i: usize, rec: &[u8], out: &mut Outbox<'_>) {
        if i == ADDR_PORT {
            self.identity.record(rec);
            self.flush(out);
        }
    }

    fn takes(&self, i: usize) -> bool {
        i == ADDR_PORT
    }

    fn lane(&mut self, op: u8, key: u8, owner_slot: u16, owner_generation: u32) {
        let Some(s) = self.sockets.as_mut() else {
            return;
        };
        match op {
            lane::ADD => {
                let owner = Owner {
                    slot: owner_slot,
                    generation: owner_generation,
                };
                if let Err(e) = s.attach(key, owner) {
                    log::warn!("[linux_net] lane {key} not served: {e}");
                }
            }
            lane::DEL => s.detach(key),
            lane::DRAIN => s.drain(key),
            _ => {}
        }
    }

    fn lane_record(&mut self, key: u8, rec: &[u8], _out: &mut Outbox<'_>) {
        if let Some(l) = self.lane_of(key) {
            if let Some(s) = self.sockets.as_mut() {
                s.offer(l, rec);
            }
        }
    }

    fn takes_lane(&self, key: u8) -> bool {
        match (self.sockets.as_ref(), self.lane_of(key)) {
            (Some(s), Some(l)) => s.takes(l),
            _ => true,
        }
    }

    fn gate(&mut self, g: Gate) {
        let lane = match g.on {
            gate::LANE => self.lane_of(g.index),
            _ => None,
        };
        if let (Some(s), Some(l)) = (self.sockets.as_mut(), lane) {
            s.gate(l, g.flags, &g.grants);
        }
    }

    fn owner_released(&mut self, slot: u16, generation: u32) {
        if let Some(s) = self.sockets.as_mut() {
            s.close_owner_conns(Owner { slot, generation });
        }
    }

    fn wake(&self) -> Wake {
        match self.sockets.as_ref() {
            Some(s) => {
                let (fd, within) = s.wake();
                Wake { fd, within }
            }
            None => Wake::BEAT,
        }
    }

    fn released(&mut self, slot: u16, generation: u32) {
        crate::tables::released(slot, generation);
    }

    fn owner(&mut self, fact: OwnerFact, netlink: Option<OwnedFd>) {
        self.identity.owner(fact, netlink);
    }

    fn owner_gone(&mut self, slot: u16, generation: u32) {
        self.identity.owner_gone(slot, generation);
    }

    fn poll(&mut self, out: &mut Outbox<'_>) -> Poll {
        if crate::route::hold_ran_out() {
            log::warn!(
                "[serve] no RESYNC_END within {:?}: what was not pushed again goes",
                crate::route::HOLD_MAX
            );
            self.end_resync();
        }
        let waiting = self.identity.poll();
        let owed = self.flush(out);
        match self.step_sockets(out) {
            Poll::Busy => Poll::Busy,
            _ if waiting || owed => Poll::Holding,
            p => p,
        }
    }
}

/// The length of the rules of the policy table `arg` names (`[len][name]`).
fn rules_len(arg: &[u8]) -> Option<usize> {
    let n = *arg.first()? as usize;
    let name = arg.get(1..1 + n)?;
    crate::tables::policy_rules(name).map(|r| r.len())
}

/// After the lane opened: probe the host (and keep probing), and hold
/// whatever an earlier start of this instance left until the writer's
/// `RESYNC_END`.
pub fn start() {
    crate::route::init();
    if crate::instance::state_dir().is_none() {
        return;
    }
    let tag = crate::instance::tag();
    if !crate::route::earlier_start_left(&tag) {
        return;
    }
    let prior_held: Vec<[u8; 4]> = crate::instance::with_live(|l| {
        l.claims(crate::instance::ClaimKind::Held)
            .iter()
            .filter(|c| c.family == rt::FAM_IPV4)
            .map(|c| [c.addr[0], c.addr[1], c.addr[2], c.addr[3]])
            .collect()
    })
    .unwrap_or_default();
    log::info!(
        "[serve] an earlier start of {tag} left state on the host: holding it until RESYNC_END"
    );
    crate::route::hold(prior_held);
}
