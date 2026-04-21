# Platform Layout

Platform entrypoints stay at the top level:

- `rp.rs`
- `bcm2712.rs`
- `linux.rs`

Supporting kernel-facing modules now live in per-platform subdirectories:

- `rp/`
- `bcm2712/`
- `linux/`

Within each platform subtree, prefer concern-based files such as
`config.rs`, `flash.rs`, `io.rs`, `protection.rs`, `providers.rs`,
`memory.rs`, `multicore.rs`, `net.rs`, and `pcie.rs` rather than
large groups of prefix-named files.
