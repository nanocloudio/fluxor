// A module's measured facts, made readable as DATA.
//
// Every module states, once, what the kernel must reserve for an instance of
// it: its state, its heap arena and — where the build cannot measure it — its
// stack. `module_facts!` publishes each as a `#[used] static` that `fluxor
// modules pack` reads out of the ELF and writes into the signed manifest. The
// kernel reads the manifest; it never runs module code to learn a fact, and
// the composer sums a graph's footprint before any device sees it.
//
// Why data and not a function: the body of a function returning a constant is
// two to four instructions whose encoding differs per architecture, so a
// packer that read it would be three decoders, each easy to get quietly
// wrong; a wrong state size is worse than an absent one.
//
// The statics are left MANGLED (no `#[no_mangle]`): the host test harness
// links several modules into one binary, where a fixed global symbol would
// collide. `pack` matches the mangled names by substring, one module's ELF at
// a time.

/// State a module's facts, at its crate root:
///
/// ```ignore
/// fluxor_rt::module_facts! { state: ModuleState }
/// fluxor_rt::module_facts! { state: ModuleState, arena: 64 * 1024 }
/// fluxor_rt::module_facts! { state: ModuleState, stack: 16 * 1024 }
/// ```
///
/// - `state`: the instance state type; the kernel reserves `size_of` it.
/// - `arena`: heap-arena bytes an instance gets (0 when absent). A graph may
///   override it per instance.
/// - `stack`: a stack depth the build cannot measure (recursion, a frame
///   sized at run time). Where the build measures a depth this is a floor:
///   one below the measurement is refused at pack time.
///
/// Also defines `MODULE_STATE_BYTES` and `MODULE_ARENA_BYTES`, the same
/// figures as `const`s, for the wasm entry glue (a wasm payload carries no
/// symbols for the packer to read) and for host tests that allocate an
/// instance.
#[macro_export]
macro_rules! module_facts {
    (state: $state:ty $(, arena: $arena:expr)? $(, stack: $stack:expr)? $(,)?) => {
        /// Bytes of one instance's state.
        pub const MODULE_STATE_BYTES: usize = ::core::mem::size_of::<$state>();
        /// Heap-arena bytes one instance gets (0 for none).
        pub const MODULE_ARENA_BYTES: usize = 0 $(+ ($arena) as usize)?;
        #[used]
        pub static FLUXOR_MODULE_STATE_BYTES: u32 = MODULE_STATE_BYTES as u32;
        #[used]
        pub static FLUXOR_MODULE_ARENA_BYTES: u32 = MODULE_ARENA_BYTES as u32;
        $(
            #[used]
            pub static FLUXOR_MODULE_STACK_BYTES: u32 = ($stack) as u32;
        )?
    };
}
