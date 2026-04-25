// TLV walker for built-in module params.
//
// Built-in modules receive a per-instance TLV blob via `ModuleEntry::params()`.
// Format mirrors `modules/sdk/params.rs::parse_tlv` and the config-tool
// packer in `tools/src/schema.rs`:
//
//   [0xFE][0x01][len_lo][len_hi]
//   [tag][len][value...] [tag][len][value...] ... [0xFF (optional end)]
//
// Each built-in walks the blob with `walk_tlv` and dispatches by tag.
// Tags are auto-assigned in declaration order in `manifest.toml`,
// starting at 10. Tags 0xF0..0xFF are reserved for protection / fault
// policy and are silently ignored here.

const TLV_MAGIC: u8 = 0xFE;
const TLV_VERSION: u8 = 0x01;
const TLV_END: u8 = 0xFF;

/// Iterate the TLV payload of a module entry, calling `f(tag, value)`
/// for each entry. No-op on a blob that lacks the magic+version
/// header (treated as "no params for this module").
pub(crate) fn walk_tlv<F: FnMut(u8, &[u8])>(blob: &[u8], mut f: F) {
    if blob.len() < 4 || blob[0] != TLV_MAGIC || blob[1] != TLV_VERSION {
        return;
    }
    let payload_len = u16::from_le_bytes([blob[2], blob[3]]) as usize;
    let end = (4 + payload_len).min(blob.len());
    let mut off = 4usize;
    while off + 2 <= end {
        let tag = blob[off];
        let elen = blob[off + 1] as usize;
        off += 2;
        if tag == TLV_END {
            break;
        }
        if off + elen > end {
            break;
        }
        // Skip reserved protection/policy tags so each built-in only
        // sees the params it declared in [[params]].
        if tag < 0xF0 {
            f(tag, &blob[off..off + elen]);
        }
        off += elen;
    }
}

/// Read a u32 TLV value (zero-extends shorter lengths so an upstream
/// u8/u16 default still decodes safely).
pub(crate) fn tlv_u32(value: &[u8]) -> u32 {
    let mut buf = [0u8; 4];
    let n = value.len().min(4);
    buf[..n].copy_from_slice(&value[..n]);
    u32::from_le_bytes(buf)
}

/// Read a u8 TLV value (zero if empty).
pub(crate) fn tlv_u8(value: &[u8]) -> u8 {
    value.first().copied().unwrap_or(0)
}

/// Decode a TLV string value as UTF-8; falls back to an empty `&str` on
/// invalid bytes so the caller can apply its own default.
pub(crate) fn tlv_str(value: &[u8]) -> &str {
    core::str::from_utf8(value).unwrap_or("")
}

/// Per-instance built-in state: stash a `Box<T>` in the 64-byte
/// bootstrap buffer (`BuiltInModule.state`) so each instance has its
/// own heap-allocated state. The Box is intentionally leaked — module
/// teardown isn't a thing on the host harness, and the alternative
/// (resurrecting the Box on drop) would require carrying a destructor
/// pointer through the `Module` trait.
///
/// Pair with `instance_state<T>` in the step function to read the
/// pointer back.
pub(crate) fn install_state<T>(m: &mut scheduler::BuiltInModule, state: Box<T>) {
    let raw = Box::into_raw(state);
    // pointer fits — even 16-byte Box pointers leave plenty of slack
    // in the 64-byte buffer.
    debug_assert!(core::mem::size_of::<*mut T>() <= m.state.len());
    unsafe {
        core::ptr::write(m.state.as_mut_ptr() as *mut *mut T, raw);
    }
}

/// Recover the per-instance state from the bootstrap buffer. Each call
/// produces a fresh `&mut T` borrowed from the same heap slot — caller
/// must not call this twice in nested scope.
///
/// # Safety
/// `state` must point to a buffer previously initialized by
/// [`install_state`] of matching `T`. Built-in dispatch in
/// `src/platform/linux.rs` matches by `name_hash`, which encodes the
/// type uniquely.
pub(crate) unsafe fn instance_state<T>(state: *mut u8) -> &'static mut T {
    let ptr = unsafe { core::ptr::read(state as *const *mut T) };
    unsafe { &mut *ptr }
}
