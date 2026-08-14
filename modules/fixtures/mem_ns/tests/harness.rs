//! Contract proof for `mem_ns` — declared by `manifest.toml [test] harness`
//! and run by `fluxor test` (standards/fluxor-modules.md §0.2 lane 1).
//!
//! This lane rather than `tests/harness/`: the module never dereferences the
//! syscall table it is handed, so the whole provider runs on the host with no
//! mock in the loop. It also keeps the proof in the primary repo — fluxor's
//! `tests/` is shadow-tracked, and a contract proof that does not ship with
//! the contract is not one.
//!
//! Scope is the claims `storage.namespace` makes that a plausible provider
//! could satisfy wrongly. Round-tripping a getter proves nothing and is not
//! here.

// Everything lives behind `cfg(test)`: the generated module-test crate mounts
// this file as its lib too, and helpers that only tests use are dead code
// there.
#[cfg(test)]
mod namespace_contract;
