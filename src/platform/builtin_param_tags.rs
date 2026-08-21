//! TLV tag constants for built-in module parameters, generated from the
//! `[[params]]` tables of the manifests under `modules/platform/<platform>/`.
//!
//! A built-in receives its configuration as a TLV blob keyed by tag, and the
//! manifest is where each tag is declared. Generating the constants here — one
//! `pub mod` per built-in, `TAG_<PARAM>` per entry — keeps the platform match
//! arms and the manifest at a single number rather than two that must be kept
//! equal by hand.
//!
//! Present only on the hosted platforms, which are the ones with built-in
//! modules; `build.rs` emits an empty table when the manifest tree is absent.

include!(concat!(env!("OUT_DIR"), "/builtin_param_tags.rs"));
