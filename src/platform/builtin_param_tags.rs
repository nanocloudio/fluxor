//! Tag and port constants for built-in modules, generated from the
//! `[[params]]` and `[[ports]]` tables of the manifests under
//! `modules/platform/<platform>/`.
//!
//! A built-in receives its configuration as a TLV blob keyed by tag, and the
//! manifest is where each tag is declared. Generating the constants here — one
//! `pub mod` per built-in, `TAG_<PARAM>` per entry — keeps the platform match
//! arms and the manifest at a single number rather than two that must be kept
//! equal by hand.
//!
//! The same holds for ports. The packer binds each declared port at a
//! `(direction, index)` by its own rule, and `PORT_<NAME>` restates that
//! binding here so a built-in asks `scheduler::module_port` for a port by
//! name rather than by a number it would otherwise have to know.
//!
//! Present only on the hosted platforms, which are the ones with built-in
//! modules; `build.rs` emits an empty table when the manifest tree is absent.

include!(concat!(env!("OUT_DIR"), "/builtin_param_tags.rs"));
