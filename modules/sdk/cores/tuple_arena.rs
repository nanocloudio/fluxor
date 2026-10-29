// tuple_arena — a sharded NAT tuple arena with TCP/UDP lifetimes.
//
// The state half of a NAT44/NAT64 translator (`cores/nat.rs` is the packet
// half). Each tuple binds an inside endpoint and a remote endpoint to one
// outside endpoint (address-and-port-dependent filtering, RFC 4787 §5: a
// return packet finds its tuple only from the remote the inside endpoint
// sent to), so the return direction always names exactly one tuple.
//
// Sharding: the outside port space of each outside address is cut into
// `SHARDS` disjoint ranges and a flow's shard is a hash of its inside
// endpoint, so shards allocate without ever contending for a port and a
// shard's exhaustion is its own. A tuple lives in its shard's arena.
//
// Lifetimes (RFC 5382 REQ-5, RFC 4787 REQ-5): a TCP binding opens only on
// an outbound SYN; it idles out after `tcp_idle_ms` once both SYNs have
// passed and no FIN has, after `tcp_transitory_ms` while it is still
// opening or closing. A port held by a live tuple, or by a retiring one —
// TCP after both FINs, an RST or its idle timeout (TIME-WAIT,
// `time_wait_ms`), UDP after its idle timeout (`udp_idle_ms`, then held
// `udp_hold_ms`) — is never handed out; reuse past the horizon advances
// the port's allocation generation (one per protocol), which a tuple
// carries so a stale reference to an earlier binding of the same port
// never matches. The generation only grows, an import included, so no
// allocation issues one the port has already carried. Exhaustion refuses and names what binds (`CtBinder`):
// ports held live, ports only retiring, or the arena.
//
// `no_std`, allocation-free; the caller owns the clock (milliseconds).

/// Shards per arena; each owns `1 / CT_SHARDS` of every address's ports.
pub const CT_SHARDS: usize = 4;
/// Outside addresses one arena allocates from.
pub const CT_ADDRS_MAX: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CtEndpoint {
    pub addr: [u8; 4],
    pub port: u16,
}

pub mod ct_state {
    pub const FREE: u8 = 0;
    /// Live; TCP flags in `CtTuple::tcp` say how far it has closed.
    pub const ACTIVE: u8 = 1;
    /// Closed: the outside port is held until `retire_at`.
    pub const TIME_WAIT: u8 = 2;
    /// UDP idle: held until `retire_at`.
    pub const UDP_HOLD: u8 = 3;
}

/// TCP close progress (`CtTuple::tcp`).
pub mod ct_tcp {
    pub const SYN_OUT: u8 = 1 << 0;
    pub const SYN_IN: u8 = 1 << 1;
    pub const FIN_OUT: u8 = 1 << 2;
    pub const FIN_IN: u8 = 1 << 3;
}

/// One binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CtTuple {
    pub state: u8,
    pub proto: u8,
    pub tcp: u8,
    pub inside: CtEndpoint,
    pub outside: CtEndpoint,
    pub remote: CtEndpoint,
    /// The outside port's allocation generation this tuple holds.
    pub generation: u32,
    pub last_ms: u64,
    pub retire_at: u64,
}

/// What a refused allocation was bound by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtBinder {
    /// Every port of the shard is held by a live tuple.
    PortsLive,
    /// Ports would be free, but each is retiring (TIME-WAIT / UDP hold).
    PortsRetiring,
    /// The shard's arena has no free slot.
    Arena,
    /// The protocol is not TCP or UDP, or no address is configured.
    Config,
    /// A TCP packet other than a SYN, for which no binding exists: only an
    /// opening connection makes one.
    NotSyn,
}

/// Timers, in milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtTimers {
    /// An established TCP binding (both SYNs seen, no FIN).
    pub tcp_idle_ms: u64,
    /// A TCP binding still opening or already closing.
    pub tcp_transitory_ms: u64,
    pub time_wait_ms: u64,
    pub udp_idle_ms: u64,
    pub udp_hold_ms: u64,
}

impl CtTimers {
    /// RFC 5382 / RFC 4787 defaults: 2 h 4 min established idle, 4 min
    /// transitory idle, 4 min TIME-WAIT (2 MSL), 5 min UDP idle, held one
    /// TIME-WAIT more.
    pub const DEFAULT: CtTimers = CtTimers {
        tcp_idle_ms: 7_440_000,
        tcp_transitory_ms: 240_000,
        time_wait_ms: 240_000,
        udp_idle_ms: 300_000,
        udp_hold_ms: 240_000,
    };
}

const CT_PROTO_TCP: u8 = 6;
const CT_PROTO_UDP: u8 = 17;

/// A sharded arena of `SLOTS` tuples per shard over `PORTS` outside ports
/// per address per shard.
pub struct TupleArena<const SLOTS: usize, const PORTS: usize> {
    addrs: [[u8; 4]; CT_ADDRS_MAX],
    n_addrs: usize,
    port_lo: u16,
    timers: CtTimers,
    shards: [[CtTuple; SLOTS]; CT_SHARDS],
    /// Per protocol (TCP, UDP), shard, address and port: the port's
    /// allocation generation. TCP and UDP ports are separate spaces, so
    /// each has its own.
    gens: [[[[u32; PORTS]; CT_ADDRS_MAX]; CT_SHARDS]; 2],
    cursor: [usize; CT_SHARDS],
}

/// The generation table a protocol's ports use.
fn ct_proto_index(proto: u8) -> usize {
    usize::from(proto == CT_PROTO_UDP)
}

fn ct_hash(e: &CtEndpoint, proto: u8) -> usize {
    // FNV-1a over the inside endpoint: stable across restarts, so a
    // restored arena shards a flow where it was.
    let mut h: u32 = 0x811C_9DC5;
    for b in e
        .addr
        .iter()
        .chain(e.port.to_be_bytes().iter())
        .chain([proto].iter())
    {
        h ^= u32::from(*b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h as usize
}

impl<const SLOTS: usize, const PORTS: usize> TupleArena<SLOTS, PORTS> {
    /// An arena over `addrs` (at most `CT_ADDRS_MAX`), each shard owning
    /// `PORTS` ports from `port_lo`: shard `s` holds
    /// `port_lo + s * PORTS .. port_lo + (s + 1) * PORTS`. `None` for no
    /// slots or ports, port 0 in the range, or a range past 65535.
    pub fn new(addrs: &[[u8; 4]], port_lo: u16, timers: CtTimers) -> Option<Self> {
        if SLOTS == 0
            || PORTS == 0
            || port_lo == 0
            || addrs.is_empty()
            || addrs.len() > CT_ADDRS_MAX
            || u32::from(port_lo) + (CT_SHARDS * PORTS) as u32 > 0x1_0000
        {
            return None;
        }
        let mut a = [[0u8; 4]; CT_ADDRS_MAX];
        a[..addrs.len()].copy_from_slice(addrs);
        Some(Self {
            addrs: a,
            n_addrs: addrs.len(),
            port_lo,
            timers,
            shards: [[CtTuple::default(); SLOTS]; CT_SHARDS],
            gens: [[[[0u32; PORTS]; CT_ADDRS_MAX]; CT_SHARDS]; 2],
            cursor: [0; CT_SHARDS],
        })
    }

    /// The shard a flow's inside endpoint belongs to.
    pub fn shard_of(inside: &CtEndpoint, proto: u8) -> usize {
        ct_hash(inside, proto) % CT_SHARDS
    }

    /// The shard owning an outside port, if it is one of ours.
    fn shard_of_port(&self, port: u16) -> Option<(usize, usize)> {
        let off = usize::from(port.checked_sub(self.port_lo)?);
        let s = off / PORTS;
        (s < CT_SHARDS).then_some((s, off % PORTS))
    }

    fn addr_index(&self, a: [u8; 4]) -> Option<usize> {
        self.addrs[..self.n_addrs].iter().position(|x| *x == a)
    }

    /// Retire what is due at `now`: idle tuples begin their hold, holds
    /// past their horizon free their slot (the port stays generation-held
    /// until its horizon passed, which is now).
    pub fn expire(&mut self, now: u64) {
        let t = self.timers;
        for shard in self.shards.iter_mut() {
            for e in shard.iter_mut() {
                match e.state {
                    ct_state::ACTIVE => {
                        let established = e.tcp & (ct_tcp::SYN_OUT | ct_tcp::SYN_IN)
                            == ct_tcp::SYN_OUT | ct_tcp::SYN_IN
                            && e.tcp & (ct_tcp::FIN_OUT | ct_tcp::FIN_IN) == 0;
                        let idle = if e.proto != CT_PROTO_TCP {
                            t.udp_idle_ms
                        } else if established {
                            t.tcp_idle_ms
                        } else {
                            t.tcp_transitory_ms
                        };
                        if now.saturating_sub(e.last_ms) >= idle {
                            if e.proto == CT_PROTO_TCP {
                                e.state = ct_state::TIME_WAIT;
                                e.retire_at = now.saturating_add(t.time_wait_ms);
                            } else {
                                e.state = ct_state::UDP_HOLD;
                                e.retire_at = now.saturating_add(t.udp_hold_ms);
                            }
                        }
                    }
                    ct_state::TIME_WAIT | ct_state::UDP_HOLD if now >= e.retire_at => {
                        *e = CtTuple::default();
                    }
                    _ => {}
                }
            }
        }
    }

    fn port_holder(&self, s: usize, addr: [u8; 4], port: u16, proto: u8) -> Option<&CtTuple> {
        self.shards[s].iter().find(|e| {
            e.state != ct_state::FREE
                && e.proto == proto
                && e.outside.addr == addr
                && e.outside.port == port
        })
    }

    /// The tuple for an outbound packet from `inside` to `remote`, made if
    /// there is none. `tcp_flags` (SYN 0x02, FIN 0x01, RST 0x04) advance a
    /// TCP tuple's close.
    pub fn outbound(
        &mut self,
        proto: u8,
        inside: CtEndpoint,
        remote: CtEndpoint,
        tcp_flags: u8,
        now: u64,
    ) -> Result<CtTuple, CtBinder> {
        if proto != CT_PROTO_TCP && proto != CT_PROTO_UDP {
            return Err(CtBinder::Config);
        }
        let s = Self::shard_of(&inside, proto);
        if let Some(i) = self.shards[s].iter().position(|e| {
            e.state == ct_state::ACTIVE
                && e.proto == proto
                && e.inside == inside
                && e.remote == remote
        }) {
            let e = &mut self.shards[s][i];
            e.last_ms = now;
            Self::track(e, tcp_flags, true, now, &self.timers);
            return Ok(*e);
        }
        // A new binding: a SYN for TCP, anything for UDP.
        if proto == CT_PROTO_TCP && tcp_flags & 0x02 == 0 {
            return Err(CtBinder::NotSyn);
        }
        // Reuse the inside endpoint's existing outside endpoint where one is
        // live (endpoint-independent mapping, RFC 4787 REQ-1), so one inside
        // endpoint is one outside endpoint to every remote.
        let reuse = self.shards[s]
            .iter()
            .find(|e| e.state == ct_state::ACTIVE && e.proto == proto && e.inside == inside)
            .map(|e| (e.outside, e.generation));
        let slot = self.shards[s]
            .iter()
            .position(|e| e.state == ct_state::FREE)
            .ok_or(CtBinder::Arena)?;
        let (outside, generation) = match reuse {
            Some(r) => r,
            None => self.allocate(s, proto)?,
        };
        let mut e = CtTuple {
            state: ct_state::ACTIVE,
            proto,
            tcp: 0,
            inside,
            outside,
            remote,
            generation,
            last_ms: now,
            retire_at: 0,
        };
        Self::track(&mut e, tcp_flags, true, now, &self.timers);
        self.shards[s][slot] = e;
        Ok(e)
    }

    fn allocate(&mut self, s: usize, proto: u8) -> Result<(CtEndpoint, u32), CtBinder> {
        let total = self.n_addrs * PORTS;
        let mut retiring = false;
        for k in 0..total {
            let c = (self.cursor[s] + k) % total;
            let (ai, pi) = (c / PORTS, c % PORTS);
            let addr = self.addrs[ai];
            let port = self.port_lo + (s * PORTS + pi) as u16;
            match self.port_holder(s, addr, port, proto).map(|e| e.state) {
                Some(ct_state::ACTIVE) => continue,
                Some(_) => {
                    retiring = true;
                    continue;
                }
                None => {}
            }
            self.cursor[s] = (c + 1) % total;
            let g = &mut self.gens[ct_proto_index(proto)][s][ai][pi];
            *g = g.wrapping_add(1);
            return Ok((CtEndpoint { addr, port }, *g));
        }
        Err(if retiring {
            CtBinder::PortsRetiring
        } else {
            CtBinder::PortsLive
        })
    }

    fn track(e: &mut CtTuple, flags: u8, out: bool, now: u64, t: &CtTimers) {
        if e.proto != CT_PROTO_TCP {
            return;
        }
        if flags & 0x02 != 0 {
            e.tcp |= if out { ct_tcp::SYN_OUT } else { ct_tcp::SYN_IN };
        }
        if flags & 0x01 != 0 {
            e.tcp |= if out { ct_tcp::FIN_OUT } else { ct_tcp::FIN_IN };
        }
        let both_fin =
            e.tcp & (ct_tcp::FIN_OUT | ct_tcp::FIN_IN) == ct_tcp::FIN_OUT | ct_tcp::FIN_IN;
        if flags & 0x04 != 0 || both_fin {
            e.state = ct_state::TIME_WAIT;
            e.retire_at = now.saturating_add(t.time_wait_ms);
        }
    }

    /// The tuple a return packet from `remote` to `outside` belongs to —
    /// only the remote it was bound to, and only while live (a retiring
    /// tuple still absorbs a late TCP segment: `None` is the caller's drop).
    pub fn inbound(
        &mut self,
        proto: u8,
        outside: CtEndpoint,
        remote: CtEndpoint,
        tcp_flags: u8,
        now: u64,
    ) -> Option<CtTuple> {
        let (s, _) = self.shard_of_port(outside.port)?;
        self.addr_index(outside.addr)?;
        let t = self.timers;
        let e = self.shards[s].iter_mut().find(|e| {
            e.state == ct_state::ACTIVE
                && e.proto == proto
                && e.outside == outside
                && e.remote == remote
        })?;
        e.last_ms = now;
        Self::track(e, tcp_flags, false, now, &t);
        Some(*e)
    }

    /// Whether `t` (as returned earlier, or imported) still names a live
    /// binding: one of the same protocol and endpoints at the generation
    /// `t` carries. A binding the arena allocated holds a generation above
    /// every one its port carried before, so a reference to an earlier
    /// binding of the port never matches it; an imported binding keeps the
    /// generation its predecessor gave it, which is matched only together
    /// with its exact endpoints.
    pub fn current(&self, t: &CtTuple) -> bool {
        let Some((s, _)) = self.shard_of_port(t.outside.port) else {
            return false;
        };
        if self.addr_index(t.outside.addr).is_none() {
            return false;
        }
        self.shards[s].iter().any(|e| {
            e.state == ct_state::ACTIVE
                && e.proto == t.proto
                && e.inside == t.inside
                && e.outside == t.outside
                && e.remote == t.remote
                && e.generation == t.generation
        })
    }

    /// `(live, retiring, free slots)` across every shard.
    pub fn counts(&self) -> (usize, usize, usize) {
        let (mut l, mut r, mut f) = (0, 0, 0);
        for e in self.shards.iter().flatten() {
            match e.state {
                ct_state::ACTIVE => l += 1,
                ct_state::FREE => f += 1,
                _ => r += 1,
            }
        }
        (l, r, f)
    }

    /// Restore a tuple exported from a predecessor (continuity): it takes
    /// its exact outside endpoint and generation (`current` names it), and
    /// the port's generation becomes the larger of its own and the
    /// binding's, so a later allocation of the port issues one above both.
    /// Refused when it is not a
    /// live TCP or UDP binding, the port is not ours or not its shard's, is
    /// held by a retiring tuple, by another inside endpoint, or by the same
    /// one under another generation, the tuple is already held, its inside
    /// endpoint is live here on another outside endpoint (one inside
    /// endpoint is one outside endpoint), or the shard is full.
    pub fn import(&mut self, t: &CtTuple) -> bool {
        if t.state != ct_state::ACTIVE || (t.proto != CT_PROTO_TCP && t.proto != CT_PROTO_UDP) {
            return false;
        }
        let Some((s, pi)) = self.shard_of_port(t.outside.port) else {
            return false;
        };
        let Some(ai) = self.addr_index(t.outside.addr) else {
            return false;
        };
        if Self::shard_of(&t.inside, t.proto) != s {
            return false;
        }
        // The inside endpoint's live bindings are all in its shard; one on
        // another outside endpoint would map it twice, and the return
        // traffic of both would be let in.
        if self.shards[s].iter().any(|e| {
            e.state == ct_state::ACTIVE
                && e.proto == t.proto
                && e.inside == t.inside
                && e.outside != t.outside
        }) {
            return false;
        }
        // The port may be shared only with the same inside endpoint's other
        // remotes (endpoint-independent mapping), all under one generation.
        for h in self.shards[s]
            .iter()
            .filter(|e| e.state != ct_state::FREE && e.proto == t.proto && e.outside == t.outside)
        {
            if h.state != ct_state::ACTIVE
                || h.inside != t.inside
                || h.generation != t.generation
                || h.remote == t.remote
            {
                return false;
            }
        }
        let Some(slot) = self.shards[s]
            .iter()
            .position(|e| e.state == ct_state::FREE)
        else {
            return false;
        };
        self.shards[s][slot] = *t;
        let g = &mut self.gens[ct_proto_index(t.proto)][s][ai][pi];
        *g = (*g).max(t.generation);
        true
    }
}
