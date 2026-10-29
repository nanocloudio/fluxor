// cid_route — QUIC connection IDs that carry an authenticated routing token.
//
// A portable QUIC connection must be routable by any admitted ingress host
// to the anchor generation serving it without a control-plane lookup, and
// the ID must say nothing to anyone else. A connection ID minted here is
//
//   [cfg u8]      rotation (bits 7-6, which route key) | length - 1 (bits 5-0)
//   [nonce 4]     fresh per ID
//   [route 6]     the routing token, enciphered
//   [tag 8]       its authenticator
//
// 19 bytes, inside QUIC's 20. The token is six bytes the deployment gives
// meaning to (a traffic fabric's, say: the anchor generation and anchor).
//
// The seal is a synthetic-IV construction over the AES-128 block cipher
// under the route key K, every input one block and domain-separated by its
// first byte:
//
//   tag  = AES_K(0x01 ‖ cfg ‖ nonce ‖ route ‖ 0⁴)[..8]
//   body = route ⊕ AES_K(0x02 ‖ cfg ‖ nonce ‖ tag ‖ 0²)[..6]
//
// Opening recomputes the keystream from the tag, recovers the token, and
// requires the tag again. An ID from another key (another rotation,
// another cell), or with any bit changed, does not open, and a 64-bit tag
// bounds forgery to 2⁻⁶⁴ a guess. Nothing rests on the nonce being unique:
// the keystream is derived from the tag, so a repeated nonce reveals only
// that two IDs carry the same nonce, and two IDs for one route share
// nothing a passive observer can link unless their nonces repeat too (then
// they are the same ID). Two IDs with equal tags but different routes would
// share a keystream; at 64 bits that needs on the order of 2³² IDs under
// one key, which a route key's rotation stays far below. The routing it
// gates is a hint the anchor re-checks, never an authorization.
//
// Needs `Aes128Hp` (sdk/crypto/aes_gcm.rs) in scope. `no_std`,
// allocation-free.

pub const CID_ROUTE_LEN: usize = 19;
pub const CID_ROUTE_TOKEN: usize = 6;
const CID_ROUTE_TAG: usize = 8;
const CID_DOMAIN_TAG: u8 = 0x01;
const CID_DOMAIN_STREAM: u8 = 0x02;

/// The tag over `cfg ‖ nonce ‖ route`.
fn cid_tag(
    aes: &Aes128Hp,
    cfg: u8,
    nonce: &[u8],
    route: &[u8; CID_ROUTE_TOKEN],
) -> [u8; CID_ROUTE_TAG] {
    let mut b = [0u8; 16];
    b[0] = CID_DOMAIN_TAG;
    b[1] = cfg;
    b[2..6].copy_from_slice(nonce);
    b[6..12].copy_from_slice(route);
    aes.encrypt_block(&mut b);
    let mut t = [0u8; CID_ROUTE_TAG];
    t.copy_from_slice(&b[..CID_ROUTE_TAG]);
    t
}

/// XOR the token's keystream, derived from `cfg ‖ nonce ‖ tag`, into `body`.
fn cid_stream(aes: &Aes128Hp, cfg: u8, nonce: &[u8], tag: &[u8], body: &mut [u8; CID_ROUTE_TOKEN]) {
    let mut b = [0u8; 16];
    b[0] = CID_DOMAIN_STREAM;
    b[1] = cfg;
    b[2..6].copy_from_slice(nonce);
    b[6..14].copy_from_slice(tag);
    aes.encrypt_block(&mut b);
    for (x, k) in body.iter_mut().zip(b.iter()) {
        *x ^= *k;
    }
}

/// Mint a routable connection ID for `route` under `key` (rotation
/// `rotation`, 0-3) with the fresh `nonce`.
pub fn cid_route_mint(
    key: &[u8; 16],
    rotation: u8,
    nonce: &[u8; 4],
    route: &[u8; CID_ROUTE_TOKEN],
) -> [u8; CID_ROUTE_LEN] {
    let aes = Aes128Hp::new(key);
    let mut cid = [0u8; CID_ROUTE_LEN];
    let cfg = ((rotation & 3) << 6) | (CID_ROUTE_LEN as u8 - 1);
    cid[0] = cfg;
    cid[1..5].copy_from_slice(nonce);
    let tag = cid_tag(&aes, cfg, nonce, route);
    let mut body = *route;
    cid_stream(&aes, cfg, nonce, &tag, &mut body);
    cid[5..11].copy_from_slice(&body);
    cid[11..].copy_from_slice(&tag);
    cid
}

/// The rotation an ID names (to pick its key), before it is opened.
/// `cid` may run on past the ID — a short header's destination ID has no
/// length on the wire, and the cfg byte gives it.
pub fn cid_route_rotation(cid: &[u8]) -> Option<u8> {
    (cid.len() >= CID_ROUTE_LEN && usize::from(cid[0] & 0x3F) == CID_ROUTE_LEN - 1)
        .then(|| cid[0] >> 6)
}

/// Open an ID minted under `key`: its routing token, or `None` for an ID
/// of another key, length or shape, or altered. Only the first
/// `CID_ROUTE_LEN` bytes of `cid` are read.
pub fn cid_route_open(key: &[u8; 16], cid: &[u8]) -> Option<[u8; CID_ROUTE_TOKEN]> {
    cid_route_rotation(cid)?;
    let cid = &cid[..CID_ROUTE_LEN];
    let aes = Aes128Hp::new(key);
    let (cfg, nonce, tag) = (cid[0], &cid[1..5], &cid[11..CID_ROUTE_LEN]);
    let mut route = [0u8; CID_ROUTE_TOKEN];
    route.copy_from_slice(&cid[5..11]);
    cid_stream(&aes, cfg, nonce, tag, &mut route);
    let want = cid_tag(&aes, cfg, nonce, &route);
    let mut diff = 0u8;
    for (a, b) in want.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    (diff == 0).then_some(route)
}
