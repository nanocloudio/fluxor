# Platform Layout

Platform entrypoints stay at the top level:

- `rp.rs`
- `bcm2712.rs`
- `linux.rs`
- `uefi.rs`

Supporting kernel-facing modules now live in per-platform subdirectories:

- `rp/`
- `bcm2712/`
- `linux/`

Within each platform subtree, prefer concern-based files such as
`config.rs`, `flash.rs`, `io.rs`, `protection.rs`, `providers.rs`,
`memory.rs`, `multicore.rs`, `net.rs`, and `pcie.rs` rather than
large groups of prefix-named files.

A platform file holds what is the chip's or the board's: peripherals,
the memory map, the entry sequence, the HAL table. What is the
processor's — vectors, interrupt controller, timer, cores, firmware
interface, page-table building, isolation — is `src/arch/<arch>/`, and
a platform configures it at boot rather than copying it. The test of
which side a thing belongs on: would a second board on the same
architecture, with different addresses, want the same code? Then it is
architecture, and the addresses are parameters.
