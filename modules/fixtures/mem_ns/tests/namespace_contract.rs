//! The `storage.namespace` claims `mem_ns` is the provider for — see
//! `harness.rs` for why this lane and what is deliberately not tested.

#[path = "../mod.rs"]
mod mem_ns;

use mem_ns::*;

const WIRE_MAX_LEN: usize = 62;

/// A live provider instance: caller-allocated state, as the kernel does it.
struct Ns {
    state: Vec<u8>,
}

impl Ns {
    fn new() -> Ns {
        let mut state = vec![0u8; module_state_size() as usize];
        // The table pointer is stored and never dereferenced; a dangling
        // non-null is exactly what proves that, and the module rejects null.
        let rc = module_new(
            -1,
            -1,
            -1,
            core::ptr::null(),
            0,
            state.as_mut_ptr(),
            state.len(),
            core::ptr::dangling::<u8>().cast(),
        );
        assert_eq!(rc, 0, "module_new");
        Ns { state }
    }

    fn call(&mut self, handle: i32, opcode: u32, arg: &mut [u8]) -> i32 {
        unsafe {
            mem_ns_dispatch(
                self.state.as_mut_ptr(),
                handle,
                opcode,
                arg.as_mut_ptr(),
                arg.len(),
            )
        }
    }

    /// `BIND` per the layout in `namespace.rs::BIND`. Returns the rc and the
    /// fence bytes the provider advertised.
    fn bind(&mut self, path: &str, kind: u8, replace: bool, target: &[u8]) -> (i32, Vec<u8>) {
        let mut fence = vec![0u8; WIRE_MAX_LEN];
        let mut a = Vec::new();
        a.extend_from_slice(&(path.len() as u16).to_le_bytes());
        a.extend_from_slice(path.as_bytes());
        a.push(kind);
        a.push(u8::from(replace));
        a.extend_from_slice(&(target.len() as u16).to_le_bytes());
        a.extend_from_slice(target);
        a.extend_from_slice(&(fence.as_mut_ptr() as u64).to_le_bytes());
        a.extend_from_slice(&(WIRE_MAX_LEN as u16).to_le_bytes());
        let rc = self.call(-1, 0x1308, &mut a);
        (rc, fence)
    }

    fn lookup(&mut self, path: &str) -> i32 {
        let mut a = path.as_bytes().to_vec();
        self.call(-1, 0x1300, &mut a)
    }

    fn delete(&mut self, path: &str) -> i32 {
        let mut fence = vec![0u8; WIRE_MAX_LEN];
        let mut a = Vec::new();
        a.extend_from_slice(&(path.len() as u16).to_le_bytes());
        a.extend_from_slice(path.as_bytes());
        a.push(0); // flags
        a.extend_from_slice(&(fence.as_mut_ptr() as u64).to_le_bytes());
        a.extend_from_slice(&(WIRE_MAX_LEN as u16).to_le_bytes());
        self.call(-1, 0x1304, &mut a)
    }
}

/// BIND mints a name LOOKUP can then find, and DELETE unmints it.
///
/// The whole reason the op exists: without it the surface is read-mostly and
/// nothing can create an entry.
#[test]
fn bind_mints_a_name_and_delete_removes_it() {
    let mut ns = Ns::new();
    assert_eq!(ns.lookup("/a"), -2, "ENOENT before BIND");

    let (rc, _) = ns.bind("/a", 0, false, b"obj-1");
    assert_eq!(rc, 0, "BIND");
    assert!(ns.lookup("/a") >= 0, "LOOKUP finds the minted name");

    assert_eq!(ns.delete("/a"), 0, "DELETE");
    assert_eq!(ns.lookup("/a"), -2, "ENOENT after DELETE");
}

/// Re-binding an existing path is `EEXIST` unless the replace flag is set.
///
/// `BIND` never implies a move — that is `RENAME`'s job — so the collision
/// has to be refused rather than silently overwritten.
#[test]
fn rebinding_needs_the_replace_flag() {
    let mut ns = Ns::new();
    assert_eq!(ns.bind("/a", 0, false, b"first").0, 0);

    assert_eq!(
        ns.bind("/a", 0, false, b"second").0,
        -17,
        "EEXIST without the replace flag"
    );
    assert_eq!(ns.bind("/a", 0, true, b"second").0, 0, "replace succeeds");
}

/// The `CAPS` bitmap and the ops agree.
///
/// A cap bit that lies is worse than no `CAPS` at all: a consumer branches on
/// it and calls an op that returns `ENOSYS`. Asserting the bitmap alone would
/// not catch that, so each claim is checked against the op's own answer.
#[test]
fn caps_bits_match_what_the_ops_actually_do() {
    let mut ns = Ns::new();
    let caps = ns.call(-1, 0x13FF, &mut []);
    assert_eq!(caps, 0b111, "BIND|RENAME|DELETE set, SUBSCRIBE|CHANGES clear");

    // Claimed → must not answer ENOSYS.
    assert_ne!(ns.bind("/a", 0, false, b"t").0, -38, "BIND claimed");
    assert_ne!(ns.delete("/a"), -38, "DELETE claimed");

    // Unclaimed → must answer ENOSYS, the read-mostly posture consumers
    // are told to expect.
    assert_eq!(ns.call(-1, 0x1305, &mut []), -38, "SUBSCRIBE unclaimed");
    assert_eq!(ns.call(-1, 0x1307, &mut []), -38, "CHANGES unclaimed");
}

/// A failed BIND leaves the table untouched.
///
/// The provider writes the fence before mutating precisely so a malformed
/// buffer cannot half-apply; this pins that ordering, which is invisible from
/// the return code alone.
#[test]
fn a_bind_that_fails_its_fence_write_does_not_bind() {
    let mut ns = Ns::new();
    let mut a = Vec::new();
    a.extend_from_slice(&2u16.to_le_bytes());
    a.extend_from_slice(b"/a");
    a.push(0); // kind
    a.push(0); // flags
    a.extend_from_slice(&0u16.to_le_bytes()); // no target
    a.extend_from_slice(&0u64.to_le_bytes()); // null fence pointer — rejected
    a.extend_from_slice(&(WIRE_MAX_LEN as u16).to_le_bytes());

    assert!(ns.call(-1, 0x1308, &mut a) < 0, "BIND rejects a null fence out");
    assert_eq!(ns.lookup("/a"), -2, "and mints nothing");
}
