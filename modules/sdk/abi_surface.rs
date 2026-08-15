// Canonical encoding of the kernel ↔ module ABI wire surface, for
// digest-pinning graph generations to the substrate they were built against
// (rfc_k8s.md §12.2 identity-by-digest, applied to the kernel/graph boundary).
//
// The surface is the set of numeric allocations a compiled `.fmod` hardcodes
// against the kernel — the same values the byte-stability net locks
// (`tests/harness/tests/abi_wire_surface.rs`, `fd_tag_wire_surface.rs`, …).
// This module folds them into one deterministic byte stream; sha256 of that
// stream is the **ABI-surface digest**. Two kernels with equal digests are
// wire-compatible for already-built modules; a generation records the digest
// it was built against, and boot selection accepts it only on equality —
// digest identity instead of version windows (latest-is-all-there-is).
//
// Fingerprint vs attestation. The digest is a genuine ATTESTATION only on the
// path where it is (a) embedded by the compiler (`runtime.rs`
// FLUXOR_ABI_SURFACE, verified at pack time), (b) covered by the module's
// Ed25519 signature, and (c) compared by the kernel loader to its own digest
// under `enforce_signatures`. All three now hold for native signed modules.
// On the unsigned/dev path (no signature, no OTP key) the field is only a
// self-asserted FINGERPRINT — a build-time honest-mistake guard, not a
// security boundary. The slot/generation pins (kernel boot selector,
// graph_slot activation) are the image-level enforcement regardless.
//
// What it does NOT cover: kernel *semantics* behind an unchanged number, and
// compiler/toolchain/build-config behavior. The manually-bumped
// `SEMANTIC_EPOCH` below is the escape hatch for the former — bump it to force
// a digest change when meaning changes but the numbers do not.
//
// Two inputs, two sensitivities. (1) The numeric walk below: only VALUES
// matter — renaming a constant or reformatting this function does not change
// the digest; changing any numeric allocation DOES. Keep the walk
// append-only so reorderings never masquerade as ABI changes. (2) The
// SDK-wide SOURCE pin folded in via `abi_surface_srcpin.rs`: this is
// deliberately broad — it hashes the canonicalized text of every
// `modules/sdk/**/*.rs` file, so renames, formatting changes, block/inline
// comments, and most refactors of ANY SDK file DO change the digest (only
// blank lines and whole-line `//` comments are ignored). That over-sensitivity
// is the safe direction: a false-positive rebuild self-heals; a missed change
// is a field failure. Net: do not describe the digest as refactor-stable — it
// tracks the SDK source, by design.
//
// `no_std`, zero-alloc: the encoder walks fixed (name, value) pairs through
// a caller-supplied sink. Shared by path-mount: host tools hash it with
// `sha2`; the kernel can fold it with its own sha256 at build/boot time.

// Assemble a private copy of the constant layers this file canonicalizes.
// `kernel_abi.rs` references `super::wire`, which resolves to the sibling
// module here exactly as it does in the real `abi.rs` assembler. The copy is
// private to this encoder; it never leaks types.
#[allow(dead_code, reason = "only the numeric constants are read")]
mod surface_src {
    pub mod wire {
        include!("wire/wire.rs");
    }
    pub mod kernel_abi {
        include!("abi/kernel_abi.rs");
    }
    pub mod srcpin {
        include!("abi_surface_srcpin.rs");
    }
    pub mod internal {
        pub mod reconfigure {
            include!("internal/reconfigure.rs");
        }
        pub mod bridge {
            include!("internal/bridge.rs");
        }
        pub mod flash {
            include!("internal/flash.rs");
        }
        pub mod diag {
            include!("internal/diag.rs");
        }
        pub mod monitor {
            include!("internal/monitor.rs");
        }
        pub mod provider_registry {
            include!("internal/provider_registry.rs");
        }
    }
}

// `self::` keeps this resolvable both as a top-level module (fluxor's own
// build) and when the SDK is include!-d inside a consumer's `mod abi`
// (edition-2018 `use` paths are crate-relative without it).
use self::surface_src::kernel_abi as ka;

/// The embeddable full-digest const (generated; see
/// `abi_surface_srcpin.rs`), surfaced here so modules and the kernel reach
/// it as `abi::abi_surface::ABI_SURFACE_DIGEST`. The host-tools mount only
/// reads it under `#[cfg(test)]` (it computes the digest fresh at runtime),
/// so allow dead_code for the non-test tools build.
#[allow(
    dead_code,
    reason = "embedded by kernel/modules; tools use it only in tests"
)]
pub const ABI_SURFACE_DIGEST: [u8; 32] = self::surface_src::srcpin::ABI_SURFACE_DIGEST;

/// Manually-bumped semantic epoch. The digest covers ABI *declarations*
/// (numbers, layouts) but not kernel *semantics* — a syscall whose meaning
/// changes while its number stays put is invisible to the walk. Bump this
/// on any such semantic-but-not-numeric ABI change to force a digest change
/// (and the rebuild/restage it implies).
pub const SEMANTIC_EPOCH: u32 = 1;

/// Visit the canonical (name, value) sequence in fixed order. The names are
/// part of the encoding (so two constants swapping values changes the
/// digest), values are widened to i64. APPEND-ONLY: never reorder or remove
/// entries; retired allocations keep their entry with the retired value.
pub fn for_each_field(f: &mut impl FnMut(&str, i64)) {
    // ── core ──
    f("SEMANTIC_EPOCH", SEMANTIC_EPOCH as i64);
    f("ABI_VERSION", ka::ABI_VERSION as i64);
    f("CHANNEL_BUFFER_SIZE", ka::CHANNEL_BUFFER_SIZE as i64);
    f(
        "CHANNEL_HINT_WIRE_BYTES",
        surface_src::wire::CHANNEL_HINT_WIRE_BYTES as i64,
    );

    // ── poll flags ──
    f("poll.IN", ka::poll::IN as i64);
    f("poll.OUT", ka::poll::OUT as i64);
    f("poll.ERR", ka::poll::ERR as i64);
    f("poll.HUP", ka::poll::HUP as i64);
    f("poll.CONN", ka::poll::CONN as i64);

    // ── errno ──
    f("errno.OK", ka::errno::OK as i64);
    f("errno.ERROR", ka::errno::ERROR as i64);
    f("errno.EACCES", ka::errno::EACCES as i64);
    f("errno.ENXIO", ka::errno::ENXIO as i64);
    f("errno.EAGAIN", ka::errno::EAGAIN as i64);
    f("errno.ENOMEM", ka::errno::ENOMEM as i64);
    f("errno.E2BIG", ka::errno::E2BIG as i64);
    f("errno.EBUSY", ka::errno::EBUSY as i64);
    f("errno.ENODEV", ka::errno::ENODEV as i64);
    f("errno.EINVAL", ka::errno::EINVAL as i64);
    f("errno.EINPROGRESS", ka::errno::EINPROGRESS as i64);
    f("errno.ENOSYS", ka::errno::ENOSYS as i64);
    f("errno.ENOTSUP", ka::errno::ENOTSUP as i64);
    f("errno.ENOTCONN", ka::errno::ENOTCONN as i64);
    f("errno.ETIMEDOUT", ka::errno::ETIMEDOUT as i64);
    f("errno.ECONNREFUSED", ka::errno::ECONNREFUSED as i64);

    // ── channel opcodes ──
    f("channel.OPEN", ka::channel::OPEN as i64);
    f("channel.CLOSE", ka::channel::CLOSE as i64);
    f("channel.CONNECT", ka::channel::CONNECT as i64);
    f("channel.READ", ka::channel::READ as i64);
    f("channel.WRITE", ka::channel::WRITE as i64);
    f("channel.POLL", ka::channel::POLL as i64);
    f("channel.IOCTL", ka::channel::IOCTL as i64);
    f("channel.REGISTER_IOCTL", ka::channel::REGISTER_IOCTL as i64);
    f("channel.BIND", ka::channel::BIND as i64);
    f("channel.LISTEN", ka::channel::LISTEN as i64);
    f("channel.ACCEPT", ka::channel::ACCEPT as i64);
    f("channel.PORT", ka::channel::PORT as i64);

    // ── timer opcodes ──
    f("timer.MILLIS", ka::timer::MILLIS as i64);
    f("timer.MICROS", ka::timer::MICROS as i64);
    f("timer.CREATE", ka::timer::CREATE as i64);
    f("timer.SET", ka::timer::SET as i64);
    f("timer.CANCEL", ka::timer::CANCEL as i64);
    f("timer.DESTROY", ka::timer::DESTROY as i64);

    // ── buffer opcodes ──
    f("buffer.ACQUIRE_WRITE", ka::buffer::ACQUIRE_WRITE as i64);
    f("buffer.RELEASE_WRITE", ka::buffer::RELEASE_WRITE as i64);
    f("buffer.ACQUIRE_READ", ka::buffer::ACQUIRE_READ as i64);
    f("buffer.RELEASE_READ", ka::buffer::RELEASE_READ as i64);
    f("buffer.ACQUIRE_INPLACE", ka::buffer::ACQUIRE_INPLACE as i64);

    // ── event opcodes ──
    f("event.CREATE", ka::event::CREATE as i64);
    f("event.SIGNAL", ka::event::SIGNAL as i64);
    f("event.POLL", ka::event::POLL as i64);
    f("event.DESTROY", ka::event::DESTROY as i64);
    f("event.BIND_IRQ", ka::event::BIND_IRQ as i64);

    // ── top-level opcodes ──
    f("LOG_WRITE", ka::LOG_WRITE as i64);
    f("HANDLE_POLL", ka::HANDLE_POLL as i64);
    f("STREAM_TIME", ka::STREAM_TIME as i64);
    f("GRAPH_SAMPLE_RATE", ka::GRAPH_SAMPLE_RATE as i64);
    f("DOWNSTREAM_LATENCY", ka::DOWNSTREAM_LATENCY as i64);
    f("REPORT_LATENCY", ka::REPORT_LATENCY as i64);
    f("REPORT_STEP_EFFECT", ka::REPORT_STEP_EFFECT as i64);
    f("ARENA_GET", ka::ARENA_GET as i64);
    f("RANDOM_FILL", ka::RANDOM_FILL as i64);
    f("SYS_CLOCK_HZ", ka::SYS_CLOCK_HZ as i64);
    f("SELF_INDEX", ka::SELF_INDEX as i64);
    f("MODULE_INSTANCE_PARAMS", ka::MODULE_INSTANCE_PARAMS as i64);
    f("OWNER_TAG", ka::OWNER_TAG as i64);
    f("NET_IDENT_PROVIDER", ka::NET_IDENT_PROVIDER as i64);
    f("GET_HW_ETHERNET_MAC", ka::GET_HW_ETHERNET_MAC as i64);
    f("PAGED_ARENA_GET", ka::PAGED_ARENA_GET as i64);
    f("PAGED_ARENA_PREFAULT", ka::PAGED_ARENA_PREFAULT as i64);

    // ── step-effect vocabulary ──
    f("step_effect.IDLE", ka::step_effect::IDLE as i64);
    f("step_effect.WAITING", ka::step_effect::WAITING as i64);
    f("step_effect.WORK_DONE", ka::step_effect::WORK_DONE as i64);
    f(
        "step_effect.RUNNABLE_BACKLOG",
        ka::step_effect::RUNNABLE_BACKLOG as i64,
    );
    f("step_effect.BURST", ka::step_effect::BURST as i64);

    // ── query keys ──
    f("query_key.CLASS", ka::query_key::CLASS as i64);
    f("query_key.NAME", ka::query_key::NAME as i64);
    f("query_key.CAPABILITIES", ka::query_key::CAPABILITIES as i64);
    f("query_key.STATE", ka::query_key::STATE as i64);
    f("query_key.ERROR_COUNT", ka::query_key::ERROR_COUNT as i64);
    f("query_key.HEAP_STATS", ka::query_key::HEAP_STATS as i64);
    f("query_key.FAULT_STATS", ka::query_key::FAULT_STATS as i64);
    f("query_key.LAST_FENCE", ka::query_key::LAST_FENCE as i64);

    // ── FD tags ──
    f("fd.FD_TAG_CHANNEL", ka::fd::FD_TAG_CHANNEL as i64);
    f("fd.FD_TAG_EVENT", ka::fd::FD_TAG_EVENT as i64);
    f("fd.FD_TAG_TIMER", ka::fd::FD_TAG_TIMER as i64);
    f("fd.FD_TAG_DMA", ka::fd::FD_TAG_DMA as i64);
    f("fd.FD_TAG_BRIDGE", ka::fd::FD_TAG_BRIDGE as i64);
    f("fd.FD_TAG_KEY_VAULT", ka::fd::FD_TAG_KEY_VAULT as i64);
    f("fd.FD_TAG_PCIE_DEVICE", ka::fd::FD_TAG_PCIE_DEVICE as i64);
    f("fd.FD_TAG_NIC_RING", ka::fd::FD_TAG_NIC_RING as i64);
    f("fd.FD_TAG_DMA_CHANNEL", ka::fd::FD_TAG_DMA_CHANNEL as i64);
    f("fd.FD_TAG_FS", ka::fd::FD_TAG_FS as i64);
    f("fd.FD_TAG_BUFFER", ka::fd::FD_TAG_BUFFER as i64);
    f("fd.FD_TAG_HAL_GPIO", ka::fd::FD_TAG_HAL_GPIO as i64);
    f("fd.FD_TAG_HAL_SPI", ka::fd::FD_TAG_HAL_SPI as i64);
    f("fd.FD_TAG_HAL_I2C", ka::fd::FD_TAG_HAL_I2C as i64);
    f("fd.FD_TAG_HAL_UART", ka::fd::FD_TAG_HAL_UART as i64);
    f("fd.FD_TAG_HAL_ADC", ka::fd::FD_TAG_HAL_ADC as i64);
    f("fd.FD_TAG_HAL_PWM", ka::fd::FD_TAG_HAL_PWM as i64);
    f("fd.FD_TAG_HAL_PIO", ka::fd::FD_TAG_HAL_PIO as i64);
    f(
        "fd.FD_TAG_STORAGE_NAMESPACE",
        ka::fd::FD_TAG_STORAGE_NAMESPACE as i64,
    );
    f(
        "fd.FD_TAG_STORAGE_OBJECT",
        ka::fd::FD_TAG_STORAGE_OBJECT as i64,
    );
    f("fd.FD_TAG_USB_HOST", ka::fd::FD_TAG_USB_HOST as i64);
    f("fd.TAG_SHIFT", ka::fd::TAG_SHIFT as i64);
    f("fd.SLOT_MASK", ka::fd::SLOT_MASK as i64);

    // ── internal syscall layers (modules/sdk/internal/*) ──
    // Modules compiled against the SDK hardcode these opcode numbers the
    // same way they hardcode kernel_abi's — a renumbering is a wire break.
    use self::surface_src::internal as int;
    f(
        "reconfigure.SELF_INDEX",
        int::reconfigure::SELF_INDEX as i64,
    );
    f("reconfigure.SET_PHASE", int::reconfigure::SET_PHASE as i64);
    f(
        "reconfigure.CALL_DRAIN",
        int::reconfigure::CALL_DRAIN as i64,
    );
    f(
        "reconfigure.MARK_FINISHED",
        int::reconfigure::MARK_FINISHED as i64,
    );
    f(
        "reconfigure.MODULE_COUNT",
        int::reconfigure::MODULE_COUNT as i64,
    );
    f(
        "reconfigure.MODULE_INFO",
        int::reconfigure::MODULE_INFO as i64,
    );
    f(
        "reconfigure.TRIGGER_REBUILD",
        int::reconfigure::TRIGGER_REBUILD as i64,
    );
    f(
        "reconfigure.MODULE_UPSTREAM",
        int::reconfigure::MODULE_UPSTREAM as i64,
    );
    f(
        "reconfigure.MODULE_DONE",
        int::reconfigure::MODULE_DONE as i64,
    );
    f("reconfigure.APPLY_ADD", int::reconfigure::APPLY_ADD as i64);
    f(
        "reconfigure.FREE_OWNER",
        int::reconfigure::FREE_OWNER as i64,
    );
    f(
        "reconfigure.OWNER_PAUSE",
        int::reconfigure::OWNER_PAUSE as i64,
    );
    f(
        "reconfigure.OWNER_RESUME",
        int::reconfigure::OWNER_RESUME as i64,
    );

    f("bridge.WRITE", int::bridge::WRITE as i64);
    f("bridge.READ", int::bridge::READ as i64);
    f("bridge.POLL", int::bridge::POLL as i64);
    f("bridge.INFO", int::bridge::INFO as i64);
    f("bridge.SELF_BRIDGES", int::bridge::SELF_BRIDGES as i64);

    f("flash.RAW_ERASE", int::flash::RAW_ERASE as i64);
    f("flash.RAW_PROGRAM", int::flash::RAW_PROGRAM as i64);
    f("flash.SIDEBAND", int::flash::SIDEBAND as i64);

    f("diag.LOG_RING_DRAIN", int::diag::LOG_RING_DRAIN as i64);
    f(
        "diag.FAN_DIAG_SNAPSHOT",
        int::diag::FAN_DIAG_SNAPSHOT as i64,
    );

    f(
        "monitor.FAULT_MONITOR_SUBSCRIBE",
        int::monitor::FAULT_MONITOR_SUBSCRIBE as i64,
    );
    f(
        "monitor.FAULT_MONITOR_POP",
        int::monitor::FAULT_MONITOR_POP as i64,
    );
    f(
        "monitor.FAULT_STATS_QUERY",
        int::monitor::FAULT_STATS_QUERY as i64,
    );
    f(
        "monitor.STEP_HISTOGRAM_QUERY",
        int::monitor::STEP_HISTOGRAM_QUERY as i64,
    );
    f("monitor.FAULT_RAISE", int::monitor::FAULT_RAISE as i64);
    f("monitor.ARENA_USAGE", int::monitor::ARENA_USAGE as i64);
    f(
        "monitor.PAGED_ARENA_STATS",
        int::monitor::PAGED_ARENA_STATS as i64,
    );
    f("monitor.ISR_METRICS", int::monitor::ISR_METRICS as i64);

    // ── appended (append-only walk; newest wire values last) ──
    f("errno.ENOSPC", ka::errno::ENOSPC as i64);

    f(
        "provider_registry.FLASH_STORE_ENABLE",
        int::provider_registry::FLASH_STORE_ENABLE as i64,
    );
    f(
        "provider_registry.BACKING_PROVIDER_ENABLE",
        int::provider_registry::BACKING_PROVIDER_ENABLE as i64,
    );
}

/// Stream the canonical bytes through `sink`: for each field,
/// `name-bytes | 0x00 | value:i64 LE`. The digest of the surface is
/// sha256 of exactly this stream.
/// Test accessor for the checked-in source pin (the drift guard in
/// `tools/src/hash.rs` compares it against a fresh recomputation).
#[allow(
    dead_code,
    reason = "consumed by the tools-lib drift test; other mounts (bin, kernel, modules) don't call it"
)]
pub fn srcpin_for_test() -> [u8; 32] {
    surface_src::srcpin::CONTRACTS_PLATFORM_SRC_HASH
}

pub fn write_surface(sink: &mut impl FnMut(&[u8])) {
    for_each_field(&mut |name, value| {
        sink(name.as_bytes());
        sink(&[0u8]);
        sink(&value.to_le_bytes());
    });
    // Contract + platform layers, folded in as the checked-in canonical
    // source hash (see `abi_surface_srcpin.rs`) — opcode name-hashes and
    // wire-struct layouts live there, beyond what a constant walk can
    // enumerate.
    sink(b"contracts_platform_src");
    sink(&[0u8]);
    sink(&surface_src::srcpin::CONTRACTS_PLATFORM_SRC_HASH);
}
