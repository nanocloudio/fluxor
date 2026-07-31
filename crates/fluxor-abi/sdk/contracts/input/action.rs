// Contract: input::action — the semantic-action wire.
//
// Layer: contracts/input (public, stable).
//
// A presentation-shell overlay control carries an `action` id — an
// opaque string chosen by the *application* that authored the shell
// (`next`, `prev`, `toggle`, `select`, or any app-specific verb). When
// the user activates the control, the browser overlay
// (`browser_overlay_runtime.js`) hashes that id with FNV-1a32 and pushes
// `[action_hash: u32 LE][value: f32 LE]` onto the host action queue; the
// `wasm_browser_action` built-in drains the queue and emits the hash
// **unchanged** as the FMP command type.
//
// So the wire is a pure conduit: the command a control emits is
// `fnv1a32(action_id)`, and the *consumer* (a `bank` selector, a player,
// or any app module) decides what that hash means by matching it. Fluxor
// carries no vocabulary of its own — an application that wants the
// generic selector verbs names its controls `next`/`prev`/`toggle`
// (which hash to `runtime.rs::MSG_{NEXT,PREV,TOGGLE}` that `bank`
// matches); an application with its own vocabulary names them whatever it
// likes and matches the same hash on the far side. No media, gallery, or
// transport meaning lives here.
//
// On the wire only the FNV-1a32 hash travels (JS hashes it in
// `makeHostSinks`, byte-identically to `fnv1a32` here), so the action
// strings never ship and the two sides agree without a shared table.

/// Compile-time FNV-1a 32-bit hash — the single hash both the JS overlay
/// and the kernel-side consumer use to turn an action id into its wire
/// command. Kept local (as in `graph_slot.rs`) so this contract compiles
/// identically in the kernel and PIC build contexts without depending on
/// a crate-relative path to the shared `wire::fnv1a32`. Byte-identical to
/// it (offset 0x811c_9dc5, prime 0x0100_0193) and to `runtime.rs::fnv1a`,
/// so e.g. `fnv1a32(b"next") == MSG_NEXT` that `bank` matches on.
pub const fn fnv1a32(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    let mut i = 0;
    while i < data.len() {
        h ^= data[i] as u32;
        h = h.wrapping_mul(0x0100_0193);
        i += 1;
    }
    h
}
