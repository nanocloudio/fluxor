// Module state size, made readable as DATA.
//
// Every PIC module exports `module_state_size()`, a function returning
// `size_of::<ModuleState>()`, which the kernel calls at load to carve the
// module's slice of the state arena. That makes a module's resident RAM cost
// knowable only by *running* it — so nothing host-side can sum a graph's state
// before a device tries to load it, and the composer admits graphs the arena
// cannot hold. `ResourceProfile.state_bytes`, whose type is documented as
// "measured runtime demand of a workload implementation", is in practice a
// hand-typed number defaulting to 65,536 — exactly an RP2040's entire arena.
//
// `declare_module_state_bytes!` publishes the same `size_of` as a `#[used]
// static` that `pack` reads straight out of the ELF and records in the binary
// manifest, so the footprint travels with the artefact.
//
// Why data and not the function. The function body is two to four instructions
// materialising a constant, and its encoding differs per architecture:
// `mov`/`movk` on aarch64, a PC-relative literal OR a `movs`+`lsls` pair on
// thumbv6m, `movw`/`movt` on thumbv8m. A packer that disassembled it would be
// three decoders each individually easy to get quietly wrong, and a wrong state
// size is worse than an absent one — the composer would admit against it.
//
// Why this is ADDITIVE and does not emit the function too. The 468 modules in
// this workspace do not share one entry shape: `foundation/ip` returns `usize`
// under `#[cfg_attr(not(feature = "host-test"), unsafe(no_mangle))]`, others
// return `u32` under a plain `#[no_mangle]`. A macro that owned the function
// would have to reproduce every variant or force a rewrite of all of them. So a
// module keeps the function exactly as it is and adds one line beside it.
//
// The static is left MANGLED (no `#[no_mangle]`) for the same reason
// `FLUXOR_ABI_SURFACE` is: the host test harness links several module cores
// into one binary, where a fixed global symbol would collide. `pack` matches
// the mangled name by substring, operating on one module's ELF at a time.
//
// A module that has not adopted it records 0 — "unknown", not "free". The
// generated resource summary shows that gap as a measured number rather than
// letting a guess stand in for it.

#[allow(
    unused_macros,
    reason = "every module includes the SDK runtime; only those that have adopted the macro invoke it"
)]
macro_rules! declare_module_state_bytes {
    ($state:ty) => {
        /// This module's resident state size, as data for `pack` to read.
        /// Pass the SAME type the module's `module_state_size()` measures —
        /// they sit beside each other so that is checkable by eye, and the
        /// packer records what this says.
        #[used]
        pub static FLUXOR_MODULE_STATE_BYTES: u32 = ::core::mem::size_of::<$state>() as u32;
    };
}

// Module stack depth, made readable as DATA.
//
// A module steps on a stack it does not own: the kernel's MSP on a
// microcontroller, where every module steps in turn on the one stack, and a
// per-module EL0 stack on a target with an MMU. Either way the composer must
// know the deepest a module goes before a device runs it — on rp2040 there is
// no hardware guard, so an overflow silently rewrites the top of the kernel's
// statics.
//
// `declare_module_stack_bytes!` publishes the module's measured worst-case
// depth, in bytes, as a `#[used]` static that `pack` records in the manifest.
// The argument is a const expression, so it can differ per silicon from one
// site, the way state sizes do:
//
//     declare_module_stack_bytes!(if cfg!(fluxor_silicon = "bcm2712") { 16 * 1024 } else { 5 * 1024 });
//
// Mangled for the same reason as `FLUXOR_MODULE_STATE_BYTES`. A module that has
// not declared records 0, which the composer refuses on a target without an
// MMU and treats as unknown elsewhere.

#[allow(
    unused_macros,
    reason = "every module includes the SDK runtime; only those that declare a stack depth invoke it"
)]
macro_rules! declare_module_stack_bytes {
    ($bytes:expr) => {
        /// This module's worst-case stack depth in bytes, as data for `pack`
        /// to read.
        #[used]
        pub static FLUXOR_MODULE_STACK_BYTES: u32 = ($bytes) as u32;
    };
}

// `declare_module_arena_bytes!` publishes the heap arena the module asks for,
// in bytes, as data `pack` records in the manifest — the figure
// `module_arena_size` returns, which the loader then never has to call. A
// gated (contained or isolated) module's code never runs privileged, so for
// one the declaration is the only way to get a heap:
//
//     declare_module_arena_bytes!(16 * 1024);

#[allow(
    unused_macros,
    reason = "every module includes the SDK runtime; only those with a heap arena invoke it"
)]
macro_rules! declare_module_arena_bytes {
    ($bytes:expr) => {
        /// This module's heap arena in bytes, as data for `pack` to read.
        #[used]
        pub static FLUXOR_MODULE_ARENA_BYTES: u32 = ($bytes) as u32;
    };
}
