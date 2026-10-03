//! `fluxor modules cap` — issue and check mesh capability chains.
//!
//! The codec, the chain rules and the verifier are the contract's
//! (`modules/sdk/contracts/mesh/capability.rs`, reached through
//! `fluxor_abi`), the same source every verifying module links, so a chain
//! issued here is accepted there by construction. Keys are the 32-byte
//! Ed25519 seeds `fluxor modules keygen` makes, held exactly as module
//! signing keys are. Signing and the `verify` check use this tool's own
//! RFC 8032 Ed25519, held to the contract's strict verifier by the golden
//! vectors.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use fluxor_abi::contracts::mesh::capability as cap;

use crate::crypto;
use crate::error::{Error, Result};

struct Tool;

impl cap::CapCrypto for Tool {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        crypto::sha256(data)
    }
    fn ed25519_verify(&self, key: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        crypto::verify(key, msg, sig)
    }
}

/// Permission names, by bit.
const PERMS: [&str; 6] = [
    "read_state",
    "subscribe",
    "send_command",
    "configure",
    "admin",
    "delegate",
];

/// Refusal names, by `Refusal as u8 - 1`.
const REFUSALS: [&str; 16] = [
    "malformed",
    "chain_too_long",
    "reserved_bits",
    "inverted_window",
    "key_id_mismatch",
    "unknown_root",
    "key_binding",
    "not_delegable",
    "permission_widened",
    "window_widened",
    "signature",
    "no_trusted_clock",
    "not_yet_valid",
    "expired",
    "object_mismatch",
    "permission_denied",
];

fn refusal(r: cap::Refusal) -> Error {
    Error::Config(format!("refused: {}", REFUSALS[r as usize - 1]))
}

fn parse_hex<const N: usize>(s: &str, what: &str) -> Result<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != 2 * N {
        return Err(Error::Config(format!("{what} is not {} hex digits", 2 * N)));
    }
    let nibble = |c: u8| {
        char::from(c)
            .to_digit(16)
            .filter(|_| c.is_ascii_hexdigit())
            .ok_or_else(|| Error::Config(format!("{what} is not hex")))
    };
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nibble(b[2 * i])? * 16 + nibble(b[2 * i + 1])?) as u8;
    }
    Ok(out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// An object id: 32 hex digits, or a UUID.
pub fn parse_object(s: &str) -> Result<cap::ObjectId> {
    let digits: String = if s.len() == 36 {
        let b = s.as_bytes();
        if [8, 13, 18, 23].iter().any(|&i| b[i] != b'-') {
            return Err(Error::Config("object is not a UUID".into()));
        }
        s.chars().filter(|c| *c != '-').collect()
    } else {
        s.to_string()
    };
    parse_hex::<16>(&digits, "object")
}

/// The object a capability over a storage scope names — the same derivation
/// a store applies to the scope a grant is presented for.
pub fn scope_object(scope: &str) -> Result<cap::ObjectId> {
    fluxor_abi::contracts::storage::object::grant::scope_object(&Tool, scope.as_bytes()).ok_or_else(
        || {
            Error::Config(format!(
                "scope '{scope}' must be a key prefix ending '/' of at most {} bytes",
                fluxor_abi::contracts::storage::object::grant::SCOPE_MAX
            ))
        },
    )
}

/// A comma list of permission names.
pub fn parse_perms(s: &str) -> Result<u16> {
    let mut p = 0u16;
    for name in s.split(',') {
        let bit = PERMS.iter().position(|n| *n == name).ok_or_else(|| {
            Error::Config(format!(
                "unknown permission '{name}' (one of {})",
                PERMS.join(", ")
            ))
        })?;
        p |= 1 << bit;
    }
    Ok(p)
}

fn perms_text(p: u16) -> String {
    let names: Vec<&str> = (0..6)
        .filter(|b| p & (1 << b) != 0)
        .map(|b| PERMS[b])
        .collect();
    if names.is_empty() {
        "none".into()
    } else {
        names.join(",")
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A time: unix seconds, `now`, `now+N` or `now-N`.
pub fn parse_time(s: &str, now: u64) -> Result<u32> {
    let bad = || Error::Config(format!("time '{s}' is not unix seconds or now[+-N]"));
    let digits = |d: &str| -> Result<u64> {
        if d.is_empty() || !d.bytes().all(|c| c.is_ascii_digit()) {
            return Err(bad());
        }
        d.parse().map_err(|_| bad())
    };
    let v = match s.strip_prefix("now") {
        Some("") => now,
        Some(rest) => match (rest.strip_prefix('+'), rest.strip_prefix('-')) {
            (Some(n), _) => now.checked_add(digits(n)?).ok_or_else(bad)?,
            (_, Some(n)) => now.checked_sub(digits(n)?).ok_or_else(bad)?,
            _ => return Err(bad()),
        },
        None => digits(s)?,
    };
    u32::try_from(v).map_err(|_| bad())
}

fn read_seed(path: &Path) -> Result<[u8; 32]> {
    let bytes = std::fs::read(path)
        .map_err(|e| Error::Config(format!("read key {}: {e}", path.display())))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Config(format!("key {} is not a 32-byte seed", path.display())))
}

fn decode_chain(text: &str) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; cap::MAX_CHAIN_BYTES];
    let n = cap::decode_text(text.trim().as_bytes(), &mut buf)
        .ok_or_else(|| Error::Config("not a chain (fxcap1.<base64url>)".into()))?;
    buf.truncate(n);
    cap::Chain::parse(&buf).map_err(refusal)?;
    Ok(buf)
}

fn encode_chain(bytes: &[u8]) -> String {
    let mut out = vec![0u8; cap::MAX_TEXT_LEN];
    let n = cap::encode_text(bytes, &mut out).unwrap_or(0);
    String::from_utf8_lossy(&out[..n]).into_owned()
}

/// What a new link grants.
pub struct Link {
    /// The object (a grant) or the subkey's object (a delegation).
    pub object: cap::ObjectId,
    pub perms: u16,
    pub not_before: u32,
    pub not_after: u32,
}

/// Sign `link` with `seed` and put it in front of `parent` — the chain that
/// authorises `seed`'s key — or start a chain when `seed` is a root. The
/// link must narrow the link that delegated to this key, so nothing is
/// issued that a verifier would refuse on those grounds.
pub fn issue(seed: &[u8; 32], link: &Link, parent: Option<&[u8]>) -> Result<Vec<u8>> {
    if link.not_before > link.not_after {
        return Err(refusal(cap::Refusal::InvertedWindow));
    }
    let public = crypto::derive_public_key(seed);
    if let Some(parent) = parent {
        let chain = cap::Chain::parse(parent).map_err(refusal)?;
        if chain.len() >= cap::MAX_CHAIN_LINKS {
            return Err(refusal(cap::Refusal::ChainTooLong));
        }
        let head = chain.token(0);
        if head.object_id != cap::key_object(&Tool, &public) {
            return Err(refusal(cap::Refusal::KeyBinding));
        }
        if head.permissions & cap::perm::DELEGATE == 0 {
            return Err(refusal(cap::Refusal::NotDelegable));
        }
        if link.perms & !head.permissions != 0 {
            return Err(refusal(cap::Refusal::PermissionWidened));
        }
        if link.not_before < head.not_before || link.not_after > head.not_after {
            return Err(refusal(cap::Refusal::WindowWidened));
        }
    }
    let mut token = cap::Token::unsigned(
        link.object,
        link.perms,
        link.not_before,
        link.not_after,
        cap::key_id(&Tool, &public),
    );
    let (_, sig) = crypto::sign(seed, &token.signed_bytes());
    token.signature = sig;
    let parent_links = match parent {
        Some(p) => cap::Chain::parse(p).map_err(refusal)?.len(),
        None => 0,
    };
    let mut out = Vec::with_capacity(cap::CHAIN_HDR + (parent_links + 1) * cap::LINK_LEN);
    out.extend_from_slice(&((parent_links + 1) as u16).to_be_bytes());
    out.extend_from_slice(&token.encode());
    out.extend_from_slice(&public);
    if let Some(p) = parent {
        out.extend_from_slice(&p[cap::CHAIN_HDR..]);
    }
    Ok(out)
}

/// `fluxor modules cap mint`.
pub fn cmd_mint(
    key: &Path,
    object: Option<&str>,
    scope: Option<&str>,
    perms: &str,
    not_before: &str,
    not_after: &str,
    chain: Option<&str>,
) -> Result<()> {
    let t = now();
    let object = match (object, scope) {
        (Some(o), None) => parse_object(o)?,
        (None, Some(sc)) => scope_object(sc)?,
        _ => {
            return Err(Error::Config(
                "give exactly one of --object and --scope".into(),
            ))
        }
    };
    let link = Link {
        object,
        perms: parse_perms(perms)?,
        not_before: parse_time(not_before, t)?,
        not_after: parse_time(not_after, t)?,
    };
    let parent = chain.map(decode_chain).transpose()?;
    let out = issue(&read_seed(key)?, &link, parent.as_deref())?;
    println!("{}", encode_chain(&out));
    Ok(())
}

/// `fluxor modules cap delegate`.
pub fn cmd_delegate(
    key: &Path,
    to: &str,
    perms: &str,
    not_before: &str,
    not_after: &str,
    chain: Option<&str>,
) -> Result<()> {
    let t = now();
    let subkey = parse_hex::<32>(to, "delegate key")?;
    let perms = parse_perms(perms)?;
    if perms & cap::perm::DELEGATE == 0 {
        return Err(Error::Config(
            "a delegation must carry the delegate permission".into(),
        ));
    }
    let link = Link {
        object: cap::key_object(&Tool, &subkey),
        perms,
        not_before: parse_time(not_before, t)?,
        not_after: parse_time(not_after, t)?,
    };
    let parent = chain.map(decode_chain).transpose()?;
    let out = issue(&read_seed(key)?, &link, parent.as_deref())?;
    println!("{}", encode_chain(&out));
    Ok(())
}

/// Verify a chain the way a device admits it, against this host's clock.
pub fn verify(
    root: &[u8; 32],
    object: cap::ObjectId,
    perms: u16,
    chain: &[u8],
    now: u64,
) -> Result<cap::Grant> {
    let clock = cap::Clock {
        now,
        uncertainty: 0,
    };
    let demand = cap::Demand {
        object_id: object,
        permissions: perms,
    };
    cap::verify(&Tool, chain, &[*root], Some(clock), Some(demand)).map_err(refusal)
}

/// `fluxor modules cap verify`. The device decides against its own trusted
/// clock; this answers against the operator's.
pub fn cmd_verify(root: &str, object: &str, perms: &str, chain: &str) -> Result<()> {
    let root = parse_hex::<32>(root, "root key")?;
    let g = verify(
        &root,
        parse_object(object)?,
        parse_perms(perms)?,
        &decode_chain(chain)?,
        now(),
    )?;
    println!(
        "granted: {} until {}",
        perms_text(g.permissions),
        g.not_after
    );
    Ok(())
}

/// `fluxor modules cap inspect`.
pub fn cmd_inspect(chain: &str) -> Result<()> {
    let bytes = decode_chain(chain)?;
    let c = cap::Chain::parse(&bytes).map_err(refusal)?;
    for i in 0..c.len() {
        let t = c.token(i);
        println!(
            "link {i}: object {} perms {} window {}..{} signer {}",
            hex(&t.object_id),
            perms_text(t.permissions),
            t.not_before,
            t.not_after,
            hex(&c.signer(i)),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fluxor_abi::contracts::mesh::capability_vectors as golden;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const T: u64 = golden::CLOCK_NOW;

    #[test]
    fn this_tools_crypto_agrees_with_the_golden_vectors() {
        let root: [u8; 32] = unhex(golden::ROOT_KEY).try_into().unwrap();
        assert_eq!(crypto::derive_public_key(&golden::ROOT_SEED), root);
        for v in golden::VECTORS {
            let clock = v
                .clock
                .map(|(now, uncertainty)| cap::Clock { now, uncertainty });
            let demand = cap::Demand {
                object_id: v.demand_object,
                permissions: v.demand_permissions,
            };
            let got = match cap::verify(&Tool, &unhex(v.chain), &[root], clock, Some(demand)) {
                Ok(_) => 0,
                Err(r) => r as u8,
            };
            assert_eq!(got, v.expect, "vector {}", v.name);
        }
    }

    /// Ed25519 is deterministic, so reissuing a root-signed golden link from
    /// its own fields must give its bytes exactly: the issuer signs what the
    /// contract verifies, domain tag included.
    #[test]
    fn the_issuer_reproduces_every_root_signed_golden_link() {
        let root: [u8; 32] = unhex(golden::ROOT_KEY).try_into().unwrap();
        let mut checked = 0;
        for v in golden::VECTORS {
            let bytes = unhex(v.chain);
            let Ok(chain) = cap::Chain::parse(&bytes) else {
                continue;
            };
            if chain.len() != 1 || chain.signer(0) != root {
                continue;
            }
            let t = chain.token(0);
            if t.flags != 0 || t.not_before > t.not_after {
                continue;
            }
            let link = Link {
                object: t.object_id,
                perms: t.permissions,
                not_before: t.not_before,
                not_after: t.not_after,
            };
            let ours = issue(&golden::ROOT_SEED, &link, None).unwrap();
            if ours != bytes {
                // A vector whose signature or key id was bent on purpose.
                assert_ne!(v.expect, 0, "vector {}", v.name);
                continue;
            }
            checked += 1;
        }
        assert!(checked >= 2, "only {checked} golden links reissued");
    }

    #[test]
    fn issued_chains_verify_and_widening_is_refused() {
        let root = [0x51u8; 32];
        let sub = [0x52u8; 32];
        let root_pub = crypto::derive_public_key(&root);
        let sub_pub = crypto::derive_public_key(&sub);
        let obj = parse_object("0b0b0b0b-0b0b-0b0b-0b0b-0b0b0b0b0b0b").unwrap();
        let t = T as u32;
        let grant = issue(
            &root,
            &Link {
                object: obj,
                perms: parse_perms("read_state,subscribe").unwrap(),
                not_before: t - 60,
                not_after: t + 60,
            },
            None,
        )
        .unwrap();
        let g = verify(&root_pub, obj, cap::perm::READ_STATE, &grant, T).unwrap();
        assert_eq!(g.not_after, t + 60);
        assert!(verify(&root_pub, obj, cap::perm::ADMIN, &grant, T).is_err());

        let auth = issue(
            &root,
            &Link {
                object: cap::key_object(&Tool, &sub_pub),
                perms: cap::perm::SEND_COMMAND | cap::perm::DELEGATE,
                not_before: t - 600,
                not_after: t + 600,
            },
            None,
        )
        .unwrap();
        let leaf = issue(
            &sub,
            &Link {
                object: obj,
                perms: cap::perm::SEND_COMMAND,
                not_before: t - 30,
                not_after: t + 30,
            },
            Some(&auth),
        )
        .unwrap();
        assert_eq!(cap::Chain::parse(&leaf).unwrap().len(), 2);
        verify(&root_pub, obj, cap::perm::SEND_COMMAND, &leaf, T).unwrap();
        assert!(verify(&sub_pub, obj, cap::perm::SEND_COMMAND, &leaf, T).is_err());

        // The issuer refuses to widen what it was given, in rights or time,
        // and refuses a chain that does not name its key.
        let widen = Link {
            object: obj,
            perms: cap::perm::ADMIN,
            not_before: t - 30,
            not_after: t + 30,
        };
        assert!(issue(&sub, &widen, Some(&auth)).is_err());
        let late = Link {
            object: obj,
            perms: cap::perm::SEND_COMMAND,
            not_before: t - 30,
            not_after: t + 900,
        };
        assert!(issue(&sub, &late, Some(&auth)).is_err());
        let other = Link {
            object: obj,
            perms: cap::perm::SEND_COMMAND,
            not_before: t - 30,
            not_after: t + 30,
        };
        assert!(issue(&[0x53u8; 32], &other, Some(&auth)).is_err());

        // Round trip through the text form.
        let text = encode_chain(&leaf);
        assert_eq!(decode_chain(&text).unwrap(), leaf);
    }

    #[test]
    fn a_malleated_signature_is_refused_like_the_contract_refuses_it() {
        let seed = [0x61u8; 32];
        let public = crypto::derive_public_key(&seed);
        let obj = [0x0bu8; 16];
        let chain = issue(
            &seed,
            &Link {
                object: obj,
                perms: cap::perm::READ_STATE,
                not_before: 10,
                not_after: 100,
            },
            None,
        )
        .unwrap();
        let clock = cap::Clock {
            now: 50,
            uncertainty: 0,
        };
        let demand = cap::Demand {
            object_id: obj,
            permissions: cap::perm::READ_STATE,
        };
        assert!(cap::verify(&Tool, &chain, &[public], Some(clock), Some(demand)).is_ok());
        // S + L is the same point equation; the strict verifier refuses it.
        let sig_at = cap::CHAIN_HDR + cap::BODY_LEN + 32;
        let order = crypto::group_order_bytes();
        let mut carry = 0u16;
        let mut bent = chain.clone();
        for i in 0..32 {
            let v = bent[sig_at + i] as u16 + order[i] as u16 + carry;
            bent[sig_at + i] = v as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0);
        assert_eq!(
            cap::verify(&Tool, &bent, &[public], Some(clock), Some(demand)),
            Err(cap::Refusal::Signature)
        );
    }

    #[test]
    fn arguments_parse_strictly() {
        assert!(parse_object("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").is_ok());
        assert!(parse_object("0b0b0b0b_0b0b-0b0b-0b0b-0b0b0b0b0b0b").is_err());
        assert!(parse_perms("read_state,writes").is_err());
        assert_eq!(parse_time("now+10", 100).unwrap(), 110);
        assert_eq!(parse_time("now-10", 100).unwrap(), 90);
        assert!(parse_time("now*10", 100).is_err());
        assert!(parse_time("5000000000", 100).is_err());
        // Signs, spaces and multi-byte text are no digits, and none panics.
        assert!(parse_time("+5", 100).is_err());
        assert!(parse_time("now++5", 100).is_err());
        assert!(parse_time("now+", 100).is_err());
        assert!(parse_time("now\u{e9}", 100).is_err());
        assert!(parse_time("now-\u{e9}", 100).is_err());
        assert!(parse_object(&"+b".repeat(16)).is_err());
        assert!(parse_object(&"\u{e9}".repeat(16)).is_err());
        assert!(parse_hex::<4>("0b0b0b0G", "key").is_err());
        assert_eq!(parse_hex::<4>("0B0b0b0F", "key").unwrap(), [11, 11, 11, 15]);
    }
}
