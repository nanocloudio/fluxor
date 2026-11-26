// Platform: where a Linux node's owner facts land for a reader outside the
// runtime.
//
// Layer: platform/linux (host-specific, unstable). In node-agent mode (the
// runtime given an owner plan file) the runtime writes the kernel's
// `workload::OWNERS` answer verbatim to [`FILE_NAME`] beside the plan,
// atomically replaced whenever the answer changes, after a [`HEAD_LEN`]-byte
// head naming the process that wrote it: `[magic:4][pid:u32]
// [pid_start_ticks:u64]`, little-endian. The start ticks are field 22 of
// `/proc/<pid>/stat`, so a reader tells the writer from a process that
// reused its pid. Rendering, history and retention are the reader's.

/// The file's name, beside the plan file.
pub const FILE_NAME: &str = "owner_records";
/// The head's magic.
pub const MAGIC: [u8; 4] = *b"FXOW";
/// Bytes of the head; the `OWNERS` answer follows.
pub const HEAD_LEN: usize = 16;
/// Head: the writing process's id, `u32`.
pub const PID: usize = 4;
/// Head: its start time in clock ticks since boot, `u64`.
pub const PID_START_TICKS: usize = 8;
