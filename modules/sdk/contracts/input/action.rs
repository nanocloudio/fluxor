// Contract: input::action — canonical InputAction → FMP verb mapping.
//
// Layer: contracts/input (public, stable).
//
// The presentation-shell browser overlay emits canonical `InputAction`
// ids — `action.transport.toggle`, `action.gallery.next`, … (RFC
// browser_overlay §17.4). Consumers that speak the FMP command
// vocabulary (`bank`, and any other selector/transport controller)
// expect a verb: `next` / `prev` / `toggle` / `select`. Translating one
// canonical Fluxor vocabulary into the other is canonical knowledge —
// not application meaning — so it lives here, shared by the
// `wasm_browser_action` built-in (which hashes incoming action ids) and
// any future action bridge (endpoint adapters, native shells).
//
// On the wire only the FNV-1a32 hash of the action id travels (JS hashes
// it in `makeHostSinks`, identically to `fnv1a32` here), so the action
// strings never ship.

/// Compile-time FNV-1a 32-bit hash. Kept local (as in `graph_slot.rs`)
/// so this contract compiles identically in the kernel and PIC build
/// contexts without depending on a crate-relative path to the shared
/// `wire::fnv1a32`. Byte-identical to it (offset 0x811c_9dc5, prime
/// 0x0100_0193) and to `runtime.rs::fnv1a`, so the verbs below equal
/// `MSG_NEXT` / `MSG_PREV` / `MSG_TOGGLE` that `bank` matches on.
const fn fnv1a32(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    let mut i = 0;
    while i < data.len() {
        h ^= data[i] as u32;
        h = h.wrapping_mul(0x0100_0193);
        i += 1;
    }
    h
}

/// FMP verb hashes (== `runtime.rs::MSG_{NEXT,PREV,TOGGLE}`).
pub const VERB_NEXT: u32 = fnv1a32(b"next");
pub const VERB_PREV: u32 = fnv1a32(b"prev");
pub const VERB_TOGGLE: u32 = fnv1a32(b"toggle");

// Canonical action ids the overlay emits, as FNV-1a32 hashes.
pub const ACTION_GALLERY_NEXT: u32 = fnv1a32(b"action.gallery.next");
pub const ACTION_TRANSPORT_NEXT: u32 = fnv1a32(b"action.transport.next");
pub const ACTION_GALLERY_PREV: u32 = fnv1a32(b"action.gallery.previous");
pub const ACTION_TRANSPORT_PREV: u32 = fnv1a32(b"action.transport.previous");
pub const ACTION_TRANSPORT_TOGGLE: u32 = fnv1a32(b"action.transport.toggle");

/// Map a canonical action-id hash to its FMP verb hash, or `None` for
/// actions with no command equivalent (e.g. `seek_absolute`,
/// `set_volume`, which need a richer consumer than a selector `bank`).
pub fn action_to_verb(action_hash: u32) -> Option<u32> {
    match action_hash {
        ACTION_GALLERY_NEXT | ACTION_TRANSPORT_NEXT => Some(VERB_NEXT),
        ACTION_GALLERY_PREV | ACTION_TRANSPORT_PREV => Some(VERB_PREV),
        ACTION_TRANSPORT_TOGGLE => Some(VERB_TOGGLE),
        _ => None,
    }
}
