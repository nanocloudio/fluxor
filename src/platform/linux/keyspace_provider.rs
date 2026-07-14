// ============================================================================
// Linux keyspace provider — the unsafe FFI adapter over the versioned store.
// ============================================================================
//
// Wraps `keyspace::KeyspaceStore::dispatch` (the slice-based wire, unit-tested
// in keyspace.rs) at the provider ABI boundary: contract class 0x17, one-shot
// ops (handle = -1, class-byte routed by `provider_call`). Every op's `arg`
// ends with an output block the caller supplies:
//
//   [ ...op-specific input... ][out_ptr:u64][out_cap:u32][fence_ptr:u64][fence_cap:u16]
//
// so the result and its `fence` land in caller-owned buffers, matching the
// storage providers' convention (linux_fs/object pass out/fence pointers in
// `arg`). The store is process-global — one control-plane store per node —
// lazily recovered from the volume dir named by `FLUXOR_KEYSPACE_DIR` (writes
// persist across restarts; in-memory if the env is unset, for dev/test).

/// Trailing output block appended to every keyspace op's `arg`:
/// `[out_ptr:u64][out_cap:u32][fence_ptr:u64][fence_cap:u16]`.
const KS_ARG_TAIL: usize = 8 + 4 + 8 + 2;

static mut LINUX_KEYSPACE: Option<keyspace::KeyspaceStore> = None;

/// Lazily open the process-global store. Recovers from the projected volume
/// directory in `FLUXOR_KEYSPACE_DIR` so writes survive restarts; falls back
/// to an in-memory store if the env is unset or recovery fails.
unsafe fn keyspace_store() -> &'static mut keyspace::KeyspaceStore {
    let p = &raw mut LINUX_KEYSPACE;
    if (*p).is_none() {
        let store = match std::env::var("FLUXOR_KEYSPACE_DIR") {
            Ok(dir) if !dir.is_empty() => {
                keyspace::KeyspaceStore::recover(Path::new(&dir), 4096, 1024)
                    .unwrap_or_else(|_| keyspace::KeyspaceStore::new())
            }
            _ => keyspace::KeyspaceStore::new(),
        };
        *p = Some(store);
    }
    (*p).as_mut().unwrap()
}

/// Dispatch entry registered for the KEYSPACE contract from
/// `linux_init_providers`. One-shot, class-byte routed; `handle` is unused.
unsafe fn linux_keyspace_dispatch(_handle: i32, opcode: u32, arg: *mut u8, arg_len: usize) -> i32 {
    if arg.is_null() || arg_len < KS_ARG_TAIL {
        return keyspace::wire::E_INVAL;
    }
    let raw = core::slice::from_raw_parts(arg, arg_len);
    let tail = arg_len - KS_ARG_TAIL;
    let out_ptr = u64::from_le_bytes(raw[tail..tail + 8].try_into().unwrap()) as *mut u8;
    let out_cap = u32::from_le_bytes(raw[tail + 8..tail + 12].try_into().unwrap()) as usize;
    let fence_ptr = u64::from_le_bytes(raw[tail + 12..tail + 20].try_into().unwrap()) as *mut u8;
    let fence_cap = u16::from_le_bytes(raw[tail + 20..tail + 22].try_into().unwrap()) as usize;

    let input = &raw[..tail];
    // out / fence are caller-owned buffers distinct from `arg` (the ABI
    // convention); empty slices when the caller passes null.
    let out: &mut [u8] = if out_ptr.is_null() {
        &mut []
    } else {
        core::slice::from_raw_parts_mut(out_ptr, out_cap)
    };
    let fence: &mut [u8] = if fence_ptr.is_null() {
        &mut []
    } else {
        core::slice::from_raw_parts_mut(fence_ptr, fence_cap)
    };
    keyspace_store().dispatch(opcode, input, out, fence)
}

#[cfg(test)]
mod keyspace_provider_tests {
    use super::keyspace;
    use super::linux_keyspace_dispatch;

    /// Append the caller-owned output block every keyspace op carries:
    /// `[out_ptr:u64][out_cap:u32][fence_ptr:u64][fence_cap:u16]`.
    fn with_out(mut input: Vec<u8>, out: &mut [u8], fence: &mut [u8]) -> Vec<u8> {
        input.extend_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
        input.extend_from_slice(&(out.len() as u32).to_le_bytes());
        input.extend_from_slice(&(fence.as_mut_ptr() as u64).to_le_bytes());
        input.extend_from_slice(&(fence.len() as u16).to_le_bytes());
        input
    }

    #[test]
    fn ffi_adapter_roundtrips_put_then_get_through_the_provider_abi() {
        let key = b"/kp-test/x";
        let val = b"v1";
        let mut out = [0u8; 64];
        let mut fence = [0u8; 62];

        // PUT (unconditional): [key_len:u16][if_match:u64][val_len:u32][key][val]
        let mut put = Vec::new();
        put.extend_from_slice(&(key.len() as u16).to_le_bytes());
        put.extend_from_slice(&u64::MAX.to_le_bytes());
        put.extend_from_slice(&(val.len() as u32).to_le_bytes());
        put.extend_from_slice(key);
        put.extend_from_slice(val);
        let mut put = with_out(put, &mut out, &mut fence);
        let n = unsafe {
            linux_keyspace_dispatch(-1, keyspace::wire::KS_PUT, put.as_mut_ptr(), put.len())
        };
        assert_eq!(n, 8, "PUT writes the new revision");
        let rev = u64::from_le_bytes(out[..8].try_into().unwrap());
        assert!(rev >= 1);
        // committed write → RevisionMonotone fence in the caller's fence buffer.
        assert_eq!(fence[0], fluxor::abi::contracts::fence::TAG_REVISION_MONOTONE);

        // GET the same key back through the adapter: [key_len:u16][key]
        let mut get = Vec::new();
        get.extend_from_slice(&(key.len() as u16).to_le_bytes());
        get.extend_from_slice(key);
        let mut get = with_out(get, &mut out, &mut fence);
        let n = unsafe {
            linux_keyspace_dispatch(-1, keyspace::wire::KS_GET, get.as_mut_ptr(), get.len())
        };
        assert_eq!(n, 8 + val.len() as i32);
        assert_eq!(u64::from_le_bytes(out[..8].try_into().unwrap()), rev);
        assert_eq!(&out[8..8 + val.len()], val);
        // read view → ViewConsistent fence.
        assert_eq!(fence[0], fluxor::abi::contracts::fence::TAG_VIEW_CONSISTENT);
    }

    #[test]
    fn ffi_adapter_rejects_a_short_arg() {
        // Shorter than the trailing output block → E_INVAL, no deref.
        let mut tiny = [0u8; 4];
        let n = unsafe {
            linux_keyspace_dispatch(-1, keyspace::wire::KS_GET, tiny.as_mut_ptr(), tiny.len())
        };
        assert_eq!(n, keyspace::wire::E_INVAL);
    }

    // ---- Reference consumer marshalling (what a reconcile fmod does) ----
    //
    // These wrap the provider ABI from the CALLER's side — building the arg
    // (op input + the trailing [out_ptr][out_cap][fence_ptr][fence_cap] block),
    // invoking the provider, and parsing the reply. The reconcile-loop test
    // below reads as a controller: subscribe inputs, recompute on change,
    // conditional-write the output. This is the shape the Phase-D endpoints
    // fmod copies.

    use keyspace::wire;

    fn call(op: u32, mut input: Vec<u8>) -> (i32, Vec<u8>) {
        let mut out = vec![0u8; 4096];
        let mut fence = vec![0u8; 62];
        input.extend_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
        input.extend_from_slice(&(out.len() as u32).to_le_bytes());
        input.extend_from_slice(&(fence.as_mut_ptr() as u64).to_le_bytes());
        input.extend_from_slice(&(fence.len() as u16).to_le_bytes());
        let rc = unsafe { linux_keyspace_dispatch(-1, op, input.as_mut_ptr(), input.len()) };
        let n = if rc > 0 { rc as usize } else { 0 };
        (rc, out[..n].to_vec())
    }

    /// PUT: returns the new revision (>= 1) on success, or a negative wire::E_*.
    fn put(key: &str, if_match: u64, val: &[u8]) -> i64 {
        let mut a = Vec::new();
        a.extend_from_slice(&(key.len() as u16).to_le_bytes());
        a.extend_from_slice(&if_match.to_le_bytes());
        a.extend_from_slice(&(val.len() as u32).to_le_bytes());
        a.extend_from_slice(key.as_bytes());
        a.extend_from_slice(val);
        let (rc, out) = call(wire::KS_PUT, a);
        if rc == 8 {
            u64::from_le_bytes(out[..8].try_into().unwrap()) as i64
        } else {
            rc as i64
        }
    }

    fn get(key: &str) -> Option<String> {
        let mut a = Vec::new();
        a.extend_from_slice(&(key.len() as u16).to_le_bytes());
        a.extend_from_slice(key.as_bytes());
        let (rc, out) = call(wire::KS_GET, a);
        (rc >= 8).then(|| String::from_utf8_lossy(&out[8..]).into_owned())
    }

    /// LIST a prefix → key-ordered values (each fetched via GET). The
    /// reconciler's "read the current input set" step.
    fn list_values(prefix: &str) -> Vec<String> {
        let mut a = Vec::new();
        a.extend_from_slice(&(prefix.len() as u16).to_le_bytes());
        a.extend_from_slice(prefix.as_bytes());
        let (rc, out) = call(wire::KS_LIST, a);
        if rc < 12 {
            return Vec::new();
        }
        let count = u32::from_le_bytes(out[8..12].try_into().unwrap()) as usize;
        let mut p = 12;
        let mut keys = Vec::new();
        for _ in 0..count {
            let klen = u16::from_le_bytes(out[p..p + 2].try_into().unwrap()) as usize;
            let key = String::from_utf8_lossy(&out[p + 10..p + 10 + klen]).into_owned();
            keys.push(key);
            p += 10 + klen;
        }
        keys.iter().filter_map(|k| get(k)).collect()
    }

    fn subscribe(prefix: &str, since: u64) -> u64 {
        let mut a = Vec::new();
        a.extend_from_slice(&since.to_le_bytes());
        a.extend_from_slice(&(prefix.len() as u16).to_le_bytes());
        a.extend_from_slice(prefix.as_bytes());
        let (rc, out) = call(wire::KS_SUBSCRIBE, a);
        assert_eq!(rc, 8);
        u64::from_le_bytes(out[..8].try_into().unwrap())
    }

    /// DRAIN → did the watch report any change (events or a LOST marker)? A
    /// level-triggered reconciler only needs "something changed → re-list".
    fn drained_changed(wid: u64) -> bool {
        let mut a = Vec::new();
        a.extend_from_slice(&wid.to_le_bytes());
        a.extend_from_slice(&0u16.to_le_bytes()); // max = 0 → all
        let (rc, out) = call(wire::KS_DRAIN, a);
        if rc < 1 {
            return false;
        }
        match out[0] {
            wire::DRAIN_LOST => true,
            wire::DRAIN_EVENTS => u32::from_le_bytes(out[1..5].try_into().unwrap()) > 0,
            _ => false,
        }
    }

    #[test]
    fn reconcile_loop_through_the_provider_end_to_end() {
        // A minimal endpoints reconciler over the keyspace provider, proving the
        // provider is reconciler-sufficient: watch inputs, recompute on change,
        // conditional-write the output, and CAS-guard concurrent writers.
        // Unique key namespace: the store is process-global across tests.
        let pods = "/recon-test/pods/default/";
        let ep = "/recon-test/endpoints/default/web";

        // The reconciler subscribes to its input prefix BEFORE anything writes.
        let w = subscribe(pods, 0);

        // Two backend pods appear (as if a scheduler placed them).
        assert!(put(&format!("{pods}web-1"), u64::MAX, b"10.0.0.1") >= 1);
        assert!(put(&format!("{pods}web-2"), u64::MAX, b"10.0.0.2") >= 1);

        // Reconcile pass 1: the watch fired → list inputs → compute → write.
        assert!(drained_changed(w), "watch delivered the pod additions");
        let desired = list_values(pods).join(",");
        assert_eq!(desired, "10.0.0.1,10.0.0.2"); // key-ordered
        let ep_rev = put(ep, u64::MAX, desired.as_bytes());
        assert!(ep_rev >= 1);
        assert_eq!(get(ep).as_deref(), Some("10.0.0.1,10.0.0.2"));

        // A third backend appears; the watch delivers it live.
        assert!(put(&format!("{pods}web-3"), u64::MAX, b"10.0.0.3") >= 1);
        assert!(drained_changed(w), "watch delivered the live update");

        // Reconcile pass 2: recompute, then conditional-write from the revision
        // we last observed — the CAS makes the read-modify-write safe.
        let desired2 = list_values(pods).join(",");
        assert_eq!(desired2, "10.0.0.1,10.0.0.2,10.0.0.3");
        let ep_rev2 = put(ep, ep_rev as u64, desired2.as_bytes());
        assert!(ep_rev2 >= 1, "CAS with the observed revision succeeds");
        assert_eq!(get(ep).as_deref(), Some("10.0.0.1,10.0.0.2,10.0.0.3"));

        // A stale writer (still holding the old revision) is refused — no lost
        // update. This is the single-writer discipline the reconciler relies on.
        assert_eq!(
            put(ep, ep_rev as u64, b"stale") as i32,
            wire::E_CONFLICT
        );
        assert_eq!(get(ep).as_deref(), Some("10.0.0.1,10.0.0.2,10.0.0.3"));
    }
}
