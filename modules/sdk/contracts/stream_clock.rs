// Contract: stream clock (generic audio/media clock query).
//
// Layer: contracts (portable capability vocabulary).
//
// A dedicated, hardware-independent capability for "what time is it on the
// media stream?" — the query behind the `STREAM_TIME` (0x0C30) syscall used for
// A/V sync. Hosts (linux/wasm) register a provider for this class backed by
// their audio sink's clock, so they no longer impersonate a PIO provider just
// to answer it. On bare-metal RP no provider registers here and the syscall
// falls back to the active PIO stream's own time (`platform::rp::pio`).

/// Provider class id (opcode class 0x1Cxx). Mirrors
/// `kernel::module::provider::contract::STREAM_CLOCK`.
pub const CLASS: u16 = 0x001C;

/// Query the current stream clock. handle=-1 resolves to the single/first
/// active media stream. Writes the 24-byte `StreamTime` snapshot
/// (consumed_units:u64, queued_units:u32, rate_q16:u32, t0_micros:u64) — the
/// same layout as `kernel_abi::STREAM_TIME`. Returns 0 on success.
pub const QUERY: u32 = 0x1C00;
