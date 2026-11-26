// Platform: where a Linux node's bound endpoints land for a reader outside the
// runtime.
//
// Layer: platform/linux (host-specific, unstable). The node's sockets are
// the network provider's (`fluxor-provider-net`), so the provider, not the
// runtime, reports which endpoints are bound and for which owner. In
// node-agent mode the runtime names the directory its owner facts land in
// (`owner_facts`) to the provider as [`DIR_ENV`], and the provider writes
// [`FILE_NAME`] there, atomically replaced whenever the set changes. A
// [`HEAD_LEN`]-byte head names the process that wrote it and the records
// that follow, little-endian:
//
//   head:   [magic:4][pid:u32][pid_start_ticks:u64][count:u16][record_len:u16][_:u32]
//   record: [owner_slot:u16][port:u16][owner_generation:u32][protocol:u8][_:3]
//
// The start ticks are field 22 of `/proc/<pid>/stat`, so a reader tells the
// writer from a process that reused its pid: a file whose writer is gone
// says nothing. `protocol` is the IP protocol number (`net_proto::grant::
// PROTO_TCP`, `PROTO_UDP`). A record is a live listener or datagram
// endpoint; the node's own (owner slot 0, generation 0) are listed too.
// Readers take `record_len` from the head. Joining a record to a workload
// (by owner slot and generation) and to what it declared is the reader's.

/// The variable naming the directory the file is written to.
pub const DIR_ENV: &str = "FLUXOR_FACTS_DIR";
/// The file's name, in that directory.
pub const FILE_NAME: &str = "bound_endpoints";
/// The head's magic.
pub const MAGIC: [u8; 4] = *b"FXBE";
/// Bytes of the head.
pub const HEAD_LEN: usize = 24;
/// Head: the writing process's id, `u32`.
pub const PID: usize = 4;
/// Head: its start time in clock ticks since boot, `u64`.
pub const PID_START_TICKS: usize = 8;
/// Head: the record count, `u16`.
pub const COUNT: usize = 16;
/// Head: the record length, `u16`.
pub const H_RECORD_LEN: usize = 18;

/// Bytes of one record.
pub const RECORD_LEN: usize = 12;
/// Record: the owner's slot, `u16`.
pub const OWNER_SLOT: usize = 0;
/// Record: the bound port, `u16`.
pub const PORT: usize = 2;
/// Record: the owner's generation, `u32`.
pub const OWNER_GENERATION: usize = 4;
/// Record: the IP protocol number, `u8`.
pub const PROTOCOL: usize = 8;

/// One bound endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub owner_slot: u16,
    pub owner_generation: u32,
    pub protocol: u8,
    pub port: u16,
}

impl Record {
    /// Write the record into `out` (at least [`RECORD_LEN`] bytes).
    pub fn write(&self, out: &mut [u8]) {
        out[..RECORD_LEN].fill(0);
        out[OWNER_SLOT..OWNER_SLOT + 2].copy_from_slice(&self.owner_slot.to_le_bytes());
        out[PORT..PORT + 2].copy_from_slice(&self.port.to_le_bytes());
        out[OWNER_GENERATION..OWNER_GENERATION + 4]
            .copy_from_slice(&self.owner_generation.to_le_bytes());
        out[PROTOCOL] = self.protocol;
    }

    /// Read a record from the start of `b`; `None` when it is short.
    pub fn read(b: &[u8]) -> Option<Record> {
        let b = b.get(..RECORD_LEN)?;
        Some(Record {
            owner_slot: u16::from_le_bytes([b[OWNER_SLOT], b[OWNER_SLOT + 1]]),
            port: u16::from_le_bytes([b[PORT], b[PORT + 1]]),
            owner_generation: u32::from_le_bytes([
                b[OWNER_GENERATION],
                b[OWNER_GENERATION + 1],
                b[OWNER_GENERATION + 2],
                b[OWNER_GENERATION + 3],
            ]),
            protocol: b[PROTOCOL],
        })
    }
}

/// Write the head for `count` records into `out` (at least [`HEAD_LEN`]
/// bytes).
pub fn write_head(out: &mut [u8], pid: u32, pid_start_ticks: u64, count: u16) {
    out[..HEAD_LEN].fill(0);
    out[..4].copy_from_slice(&MAGIC);
    out[PID..PID + 4].copy_from_slice(&pid.to_le_bytes());
    out[PID_START_TICKS..PID_START_TICKS + 8].copy_from_slice(&pid_start_ticks.to_le_bytes());
    out[COUNT..COUNT + 2].copy_from_slice(&count.to_le_bytes());
    out[H_RECORD_LEN..H_RECORD_LEN + 2].copy_from_slice(&(RECORD_LEN as u16).to_le_bytes());
}

/// Read the head: `(pid, pid_start_ticks, count, record_len)`. `None` for a
/// wrong magic, a short head, a record length below [`RECORD_LEN`] or
/// records past the end of `b`.
pub fn read_head(b: &[u8]) -> Option<(u32, u64, usize, usize)> {
    let h = b.get(..HEAD_LEN)?;
    if h[..4] != MAGIC {
        return None;
    }
    let pid = u32::from_le_bytes([h[PID], h[PID + 1], h[PID + 2], h[PID + 3]]);
    let mut t = [0u8; 8];
    t.copy_from_slice(&h[PID_START_TICKS..PID_START_TICKS + 8]);
    let count = usize::from(u16::from_le_bytes([h[COUNT], h[COUNT + 1]]));
    let len = usize::from(u16::from_le_bytes([h[H_RECORD_LEN], h[H_RECORD_LEN + 1]]));
    if len < RECORD_LEN || HEAD_LEN + count * len > b.len() {
        return None;
    }
    Some((pid, u64::from_le_bytes(t), count, len))
}
