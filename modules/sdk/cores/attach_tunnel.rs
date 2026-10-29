// attach_tunnel — the authenticated attachment tunnel: a packet carried
// between a consumer's attachment anchor and a producer's service director
// with the attachment's context bound to it.
//
// A private attachment exposes a service, never a network: the producer
// admits a connection by the context the tunnel authenticates and by
// nothing the consumer chose (its addresses are its own). So the context —
// `(consumer_tenant, attachment_id, attachment_generation)` and the flow's
// epoch — rides every packet under a tag a forger cannot make, and the
// receiver takes it from the verified header alone.
//
//   magic       [2]  = b"FA"
//   version     u8   = 1
//   flags       u8   bit0 = producer → consumer
//   consumer    [16] consumer tenant
//   attachment  [16] attachment id
//   generation  u64 BE  attachment generation
//   flow_epoch  u32 BE
//   seq         u64 BE  per (attachment, direction), strictly increasing
//   inner_len   u16 BE
//   inner       [inner_len]   the packet, untouched
//   tag         [16] HMAC-SHA256(key, everything before it), truncated
//
// The key is the attachment's tunnel key, which both ends' vaults derive
// from the grant (`key_vault` DERIVE, label `attach/tunnel`, context the
// attachment id and generation): a revoked attachment's new generation is
// a new key, so a packet minted under the old one does not verify. The
// receiver keeps a 64-packet sliding replay window per (attachment,
// direction) (`AtReplay`, RFC 4303 §3.4.3's), so a replayed packet is
// refused and a reordered one inside the window is not. One key serves both
// directions, with the direction in the authenticated flags; a window is
// made for the direction it receives (`AtReplay::receiving`), and a packet
// of the other — one reflected back at its sender — is refused before it
// can touch the window.
//
// Needs `Sha256` in scope. `no_std`, allocation-free.

pub const AT_MAGIC: [u8; 2] = *b"FA";
pub const AT_VERSION: u8 = 1;
pub const AT_HEAD: usize = 2 + 1 + 1 + 16 + 16 + 8 + 4 + 8 + 2;
pub const AT_TAG: usize = 16;
pub const AT_OVERHEAD: usize = AT_HEAD + AT_TAG;
pub const AT_FLAG_TO_CONSUMER: u8 = 1 << 0;

/// The context the tunnel authenticates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AtContext {
    pub consumer_tenant: [u8; 16],
    pub attachment_id: [u8; 16],
    pub attachment_generation: u64,
    pub flow_epoch: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtWhy {
    Malformed,
    /// The tag does not verify: another key (attachment, generation), or
    /// altered.
    Tag,
    /// A sequence number already seen, or behind the window.
    Replay,
    /// The other direction's packet: this window receives the one it was
    /// made for, so a packet reflected back at its sender is refused.
    Direction,
    Capacity,
}

fn at_hmac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..32 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut h = Sha256::new();
    h.update(&ipad);
    h.update(data);
    let ih = h.finalize();
    let mut o = Sha256::new();
    o.update(&opad);
    o.update(&ih);
    let out = o.finalize();
    // The padded keys are the key: they do not outlive the tag.
    for b in ipad.iter_mut().chain(opad.iter_mut()) {
        // SAFETY: `b` is a live, exclusively borrowed byte.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    out
}

/// Wrap `inner` for the tunnel into `out`: its length.
pub fn at_seal(
    key: &[u8; 32],
    ctx: &AtContext,
    to_consumer: bool,
    seq: u64,
    inner: &[u8],
    out: &mut [u8],
) -> Result<usize, AtWhy> {
    at_seal_mac(
        &mut |d| Some(at_hmac(key, d)),
        ctx,
        to_consumer,
        seq,
        inner,
        out,
    )
}

/// [`at_seal`] with the tag made by `mac` — HMAC-SHA256 under the
/// attachment's key, wherever that key is: a vault-held `HMAC_SHA256` slot
/// answers it (`SIGN`) without the key ever leaving the vault. `None` (the
/// MAC could not be made) is [`AtWhy::Tag`].
pub fn at_seal_mac<M: FnMut(&[u8]) -> Option<[u8; 32]>>(
    mac: &mut M,
    ctx: &AtContext,
    to_consumer: bool,
    seq: u64,
    inner: &[u8],
    out: &mut [u8],
) -> Result<usize, AtWhy> {
    if inner.len() > usize::from(u16::MAX) {
        return Err(AtWhy::Malformed);
    }
    let n = AT_OVERHEAD + inner.len();
    if out.len() < n {
        return Err(AtWhy::Capacity);
    }
    out[0..2].copy_from_slice(&AT_MAGIC);
    out[2] = AT_VERSION;
    out[3] = if to_consumer { AT_FLAG_TO_CONSUMER } else { 0 };
    out[4..20].copy_from_slice(&ctx.consumer_tenant);
    out[20..36].copy_from_slice(&ctx.attachment_id);
    out[36..44].copy_from_slice(&ctx.attachment_generation.to_be_bytes());
    out[44..48].copy_from_slice(&ctx.flow_epoch.to_be_bytes());
    out[48..56].copy_from_slice(&seq.to_be_bytes());
    out[56..58].copy_from_slice(&(inner.len() as u16).to_be_bytes());
    out[AT_HEAD..AT_HEAD + inner.len()].copy_from_slice(inner);
    let tag = mac(&out[..AT_HEAD + inner.len()]).ok_or(AtWhy::Tag)?;
    out[AT_HEAD + inner.len()..n].copy_from_slice(&tag[..AT_TAG]);
    Ok(n)
}

/// What a tunnel packet claims before it is verified: enough to choose
/// the key (the attachment and generation) and nothing to act on.
pub fn at_peek(b: &[u8]) -> Result<AtContext, AtWhy> {
    if b.len() < AT_OVERHEAD
        || b[0..2] != AT_MAGIC
        || b[2] != AT_VERSION
        || b[3] & !AT_FLAG_TO_CONSUMER != 0
    {
        return Err(AtWhy::Malformed);
    }
    let mut c = AtContext::default();
    c.consumer_tenant.copy_from_slice(&b[4..20]);
    c.attachment_id.copy_from_slice(&b[20..36]);
    let mut g = [0u8; 8];
    g.copy_from_slice(&b[36..44]);
    c.attachment_generation = u64::from_be_bytes(g);
    c.flow_epoch = u32::from_be_bytes([b[44], b[45], b[46], b[47]]);
    Ok(c)
}

/// A verified tunnel packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtOpened<'a> {
    pub ctx: AtContext,
    pub to_consumer: bool,
    pub seq: u64,
    pub inner: &'a [u8],
}

/// Verify `b` under `key` and the replay window; the context and inner
/// packet only if both pass (the window advances only then).
pub fn at_open<'a>(
    key: &[u8; 32],
    b: &'a [u8],
    replay: &mut AtReplay,
) -> Result<AtOpened<'a>, AtWhy> {
    at_open_mac(&mut |d| Some(at_hmac(key, d)), b, replay)
}

/// [`at_open`] with the tag made by `mac` (see [`at_seal_mac`]).
pub fn at_open_mac<'a, M: FnMut(&[u8]) -> Option<[u8; 32]>>(
    mac: &mut M,
    b: &'a [u8],
    replay: &mut AtReplay,
) -> Result<AtOpened<'a>, AtWhy> {
    let ctx = at_peek(b)?;
    let inner_len = usize::from(u16::from_be_bytes([b[56], b[57]]));
    if AT_OVERHEAD + inner_len != b.len() {
        return Err(AtWhy::Malformed);
    }
    let tag = mac(&b[..AT_HEAD + inner_len]).ok_or(AtWhy::Tag)?;
    let mut diff = 0u8;
    for i in 0..AT_TAG {
        diff |= tag[i] ^ b[AT_HEAD + inner_len + i];
    }
    if diff != 0 {
        return Err(AtWhy::Tag);
    }
    let to_consumer = b[3] & AT_FLAG_TO_CONSUMER != 0;
    if to_consumer != replay.to_consumer {
        return Err(AtWhy::Direction);
    }
    let mut s = [0u8; 8];
    s.copy_from_slice(&b[48..56]);
    let seq = u64::from_be_bytes(s);
    replay.check_and_mark(seq)?;
    Ok(AtOpened {
        ctx,
        to_consumer,
        seq,
        inner: &b[AT_HEAD..AT_HEAD + inner_len],
    })
}

/// A 64-packet anti-replay window (RFC 4303 §3.4.3) for one direction of
/// one attachment. Sequence zero is never sent. A window is made for the
/// direction it receives ([`AtReplay::receiving`]): one key seals both
/// directions, so a window that took either would accept a packet
/// reflected back at its sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtReplay {
    pub highest: u64,
    pub bitmap: u64,
    /// The direction this window receives: producer → consumer when set.
    pub to_consumer: bool,
}

impl AtReplay {
    /// An empty window receiving `to_consumer`'s direction.
    pub const fn receiving(to_consumer: bool) -> Self {
        Self {
            highest: 0,
            bitmap: 0,
            to_consumer,
        }
    }

    pub fn check_and_mark(&mut self, seq: u64) -> Result<(), AtWhy> {
        if seq == 0 {
            return Err(AtWhy::Replay);
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            self.bitmap = if shift >= 64 { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.highest = seq;
            return Ok(());
        }
        let off = self.highest - seq;
        if off >= 64 || self.bitmap & (1 << off) != 0 {
            return Err(AtWhy::Replay);
        }
        self.bitmap |= 1 << off;
        Ok(())
    }
}
