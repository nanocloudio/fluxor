// rescue_tunnel — the ingress cell's authenticated tunnel to a remote
// anchor.
//
// Upstream ECMP picks the ingress host, not the host holding a flow's
// anchor. The ingress host's director, finding the anchor elsewhere,
// disposes the packet `TUNNEL`; this carries it whole to the anchor's host
// with the decision bound to it — the service, the route generation the
// flow was placed under, the flow epoch, and the original ingress (which
// host, interface and queue saw it) — under a tag only a member of the cell
// can make. The anchor's host takes those from the verified header alone
// and hands the inner packet to its own stack, as if it had arrived there.
//
//   magic        [2]  = b"FR"
//   version      u8   = 1
//   flags        u8   0 (reserved)
//   service_id   [16]
//   route_gen    u64 BE   the generation the flow was placed under
//   flow_epoch   u32 BE
//   anchor_id    u16 BE   the anchor the ingress director chose
//   ingress_host [8]      the ingress host's identity
//   ingress_if   u8
//   rx_queue     u8
//   seq          u64 BE   per ingress host, strictly increasing, never 0
//   inner_len    u16 BE
//   inner        [inner_len]   the IP packet, untouched
//   tag          [16] HMAC-SHA256(key, everything before it), truncated
//
// The key is the cell's rescue key (a vault-held HMAC-SHA256 key, or a
// param in rigs): a host outside the cell, or the cell's previous key, makes
// nothing that verifies. Every member of the cell holds the same key, so the
// tag says "a member of the cell", not which one: `ingress_host` is the
// sender's claim, trusted as far as the cell is.
//
// A receiver keeps a 64-packet window per ingress host (`RtWindows`,
// RFC 4303 §3.4.3), so a replayed packet is refused, a reordered one inside
// the window is not, and one ingress host's sequence cannot shadow
// another's. A window is made only for a packet whose tag verified, so a
// sender outside the cell cannot fill them. The window lives as long as the
// receiver: a sender that starts again must carry on above the sequence it
// reached (the module starts from wall-clock time for that), and a receiver
// that starts again takes any sequence once more — what bounds replay
// across a receiver restart is the key's lifetime, not the window.
//
// Needs `Sha256` in scope. `no_std`, allocation-free.

pub const RT_MAGIC: [u8; 2] = *b"FR";
pub const RT_VERSION: u8 = 1;
pub const RT_HEAD: usize = 2 + 1 + 1 + 16 + 8 + 4 + 2 + 8 + 1 + 1 + 8 + 2;
pub const RT_TAG: usize = 16;
pub const RT_OVERHEAD: usize = RT_HEAD + RT_TAG;
/// The UDP port a rescue tunnel listens on.
pub const RT_PORT: u16 = 4791;
/// Ingress hosts a receiver holds windows for.
pub const RT_HOSTS: usize = 16;

/// What the tunnel authenticates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct RtContext {
    pub service_id: [u8; 16],
    pub route_generation: u64,
    pub flow_epoch: u32,
    pub anchor_id: u16,
    pub ingress_host: [u8; 8],
    pub ingress_if: u8,
    pub rx_queue: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RtWhy {
    Malformed,
    /// The tag does not verify: another cell's key, or altered.
    Tag,
    /// A sequence number already seen, or behind the window.
    Replay,
    /// No room: the output, or a new ingress host's window.
    Capacity,
}

fn rt_hmac(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    k[..32].copy_from_slice(key);
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut h = Sha256::new();
    h.update(&ipad);
    h.update(msg);
    let inner = h.finalize();
    let mut h = Sha256::new();
    h.update(&opad);
    h.update(&inner);
    let out = h.finalize();
    // The padded keys are the key: they do not outlive the tag.
    for b in k.iter_mut().chain(ipad.iter_mut()).chain(opad.iter_mut()) {
        // SAFETY: `b` is a live, exclusively borrowed byte.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    out
}

/// Seal `inner` under `key` with `ctx` and sequence `seq` into `out`; the
/// datagram's length.
pub fn rt_seal(
    key: &[u8; 32],
    ctx: &RtContext,
    seq: u64,
    inner: &[u8],
    out: &mut [u8],
) -> Result<usize, RtWhy> {
    rt_seal_mac(&mut |d| Some(rt_hmac(key, d)), ctx, seq, inner, out)
}

/// [`rt_seal`] with the tag made by `mac` — HMAC-SHA256 under the cell's
/// key, wherever that key is: a vault-held `HMAC_SHA256` slot answers it
/// (`SIGN`) without the key leaving the vault. `None` is [`RtWhy::Tag`].
pub fn rt_seal_mac<M: FnMut(&[u8]) -> Option<[u8; 32]>>(
    mac: &mut M,
    ctx: &RtContext,
    seq: u64,
    inner: &[u8],
    out: &mut [u8],
) -> Result<usize, RtWhy> {
    if inner.is_empty() || inner.len() > usize::from(u16::MAX) {
        return Err(RtWhy::Malformed);
    }
    let n = RT_OVERHEAD + inner.len();
    if out.len() < n {
        return Err(RtWhy::Capacity);
    }
    out[0..2].copy_from_slice(&RT_MAGIC);
    out[2] = RT_VERSION;
    out[3] = 0;
    out[4..20].copy_from_slice(&ctx.service_id);
    out[20..28].copy_from_slice(&ctx.route_generation.to_be_bytes());
    out[28..32].copy_from_slice(&ctx.flow_epoch.to_be_bytes());
    out[32..34].copy_from_slice(&ctx.anchor_id.to_be_bytes());
    out[34..42].copy_from_slice(&ctx.ingress_host);
    out[42] = ctx.ingress_if;
    out[43] = ctx.rx_queue;
    out[44..52].copy_from_slice(&seq.to_be_bytes());
    out[52..54].copy_from_slice(&(inner.len() as u16).to_be_bytes());
    out[RT_HEAD..RT_HEAD + inner.len()].copy_from_slice(inner);
    let tag = mac(&out[..RT_HEAD + inner.len()]).ok_or(RtWhy::Tag)?;
    out[RT_HEAD + inner.len()..n].copy_from_slice(&tag[..RT_TAG]);
    Ok(n)
}

/// A verified rescue datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtOpened<'a> {
    pub ctx: RtContext,
    pub seq: u64,
    pub inner: &'a [u8],
}

/// One ingress host's replay window.
#[derive(Clone, Copy, Debug, Default)]
pub struct RtWindow {
    pub host: [u8; 8],
    pub live: bool,
    pub top: u64,
    pub bits: u64,
}

impl RtWindow {
    fn check(&self, seq: u64) -> Result<(), RtWhy> {
        if seq == 0 {
            return Err(RtWhy::Replay);
        }
        if seq > self.top {
            return Ok(());
        }
        let back = self.top - seq;
        if back >= 64 || self.bits & (1 << back) != 0 {
            return Err(RtWhy::Replay);
        }
        Ok(())
    }

    fn mark(&mut self, seq: u64) {
        if seq > self.top {
            let shift = seq - self.top;
            self.bits = if shift >= 64 { 0 } else { self.bits << shift };
            self.bits |= 1;
            self.top = seq;
        } else {
            self.bits |= 1 << (self.top - seq);
        }
    }
}

/// The receiver's windows, one per ingress host.
#[derive(Clone, Copy, Debug)]
pub struct RtWindows {
    pub w: [RtWindow; RT_HOSTS],
}

impl RtWindows {
    pub const fn new() -> Self {
        Self {
            w: [RtWindow {
                host: [0; 8],
                live: false,
                top: 0,
                bits: 0,
            }; RT_HOSTS],
        }
    }
}

impl Default for RtWindows {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify `b` under `key` and its ingress host's window; the context and
/// inner packet only if both pass (the window advances only then).
pub fn rt_open<'a>(
    key: &[u8; 32],
    b: &'a [u8],
    win: &mut RtWindows,
) -> Result<RtOpened<'a>, RtWhy> {
    rt_open_mac(&mut |d| Some(rt_hmac(key, d)), b, win)
}

/// [`rt_open`] with the tag made by `mac` (see [`rt_seal_mac`]).
pub fn rt_open_mac<'a, M: FnMut(&[u8]) -> Option<[u8; 32]>>(
    mac: &mut M,
    b: &'a [u8],
    win: &mut RtWindows,
) -> Result<RtOpened<'a>, RtWhy> {
    if b.len() < RT_OVERHEAD + 1 || b[0..2] != RT_MAGIC || b[2] != RT_VERSION || b[3] != 0 {
        return Err(RtWhy::Malformed);
    }
    let inner_len = usize::from(u16::from_be_bytes([b[52], b[53]]));
    if b.len() != RT_OVERHEAD + inner_len || inner_len == 0 {
        return Err(RtWhy::Malformed);
    }
    let body = RT_HEAD + inner_len;
    let tag = mac(&b[..body]).ok_or(RtWhy::Tag)?;
    let mut diff = 0u8;
    for i in 0..RT_TAG {
        diff |= tag[i] ^ b[body + i];
    }
    if diff != 0 {
        return Err(RtWhy::Tag);
    }
    let mut ctx = RtContext::default();
    ctx.service_id.copy_from_slice(&b[4..20]);
    let mut g = [0u8; 8];
    g.copy_from_slice(&b[20..28]);
    ctx.route_generation = u64::from_be_bytes(g);
    ctx.flow_epoch = u32::from_be_bytes([b[28], b[29], b[30], b[31]]);
    ctx.anchor_id = u16::from_be_bytes([b[32], b[33]]);
    ctx.ingress_host.copy_from_slice(&b[34..42]);
    ctx.ingress_if = b[42];
    ctx.rx_queue = b[43];
    g.copy_from_slice(&b[44..52]);
    let seq = u64::from_be_bytes(g);
    let slot = match win
        .w
        .iter()
        .position(|w| w.live && w.host == ctx.ingress_host)
    {
        Some(i) => i,
        None => {
            let i = win.w.iter().position(|w| !w.live).ok_or(RtWhy::Capacity)?;
            win.w[i] = RtWindow {
                host: ctx.ingress_host,
                live: true,
                top: 0,
                bits: 0,
            };
            i
        }
    };
    win.w[slot].check(seq)?;
    win.w[slot].mark(seq);
    Ok(RtOpened {
        ctx,
        seq,
        inner: &b[RT_HEAD..body],
    })
}
