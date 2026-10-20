//! Host-side encoder for the on-device `AddSubgraph` wire format and the
//! resident-workload config section.
//!
//! A RESIDENT WORKLOAD is a workload-owned subgraph declared in a graph YAML's
//! `workloads:` section and admitted by the kernel at boot, alongside the base
//! graph rather than inside it. Each workload gets its own owner handle, its own
//! state/buffer caps, and is scheduled as an independent resident graph — so
//! a workload can be added, paced and parked without touching the base
//! graph's wiring or its compiled body.
//!
//! The `AddSubgraph` (FLXA) blob produced here is byte-compatible with the
//! kernel decoder `kernel::exec::scheduler::live::apply_add_encoded`:
//! big-endian, fixed-width, PIC modules referenced by `name_hash` (FNV-1a of
//! the type name). The workload **section** wraps one or more FLXA blobs and
//! is appended to the config blob PAST the checksummed body, after the
//! adaptive-tick `tick_min/max` tail (`kernel::boot::config::ADAPTIVE_POST_SIZE`),
//! so the body and its CRC do not cover it. The kernel reads it in
//! `kernel::boot::config::read_config_from_slice` and admits each workload at
//! boot via `apply_add_encoded` + `finalize_resident_graphs`.
//!
//! Scope: workloads are self-contained subgraphs — intra-workload edges only
//! (`New → New`), and those edges must stay inside one domain, because a
//! cross-domain edge needs the SPSC bridge that boot provisions for base
//! edges and `apply_add` does not open. Module params are the inline TLV
//! produced by `schema::build_params_from_schema`; a workload module cannot
//! reference a `data:`-section blob.
//!
//! FLXA layout (big-endian):
//!
//! ```text
//! header  magic u32 "FLXA" | version u16 = 1 | flags u16 = 0
//!         owner_uid [16] | state_cap u32 | buffer_cap u32
//!         module_count u8 | edge_count u8
//! module  name_hash u32 | domain_id u8
//!         step_deadline_us u32 | step_deadline_burst_us u32 | fault_policy u8
//!         params_len u16 | params [params_len]
//! edge    from_kind u8 | from_idx u16 | from_port u8
//!         to_kind u8 | to_idx u16 | to_port u8 | buffer_bytes u32
//! ```
//!
//! A workload composed here is its own authority: `flags` is always 0. Its
//! one bit, `ADD_FLAG_CREATOR_AUTHORITY`, is honoured only from the
//! `APPLY_ADD` of a module acting with the node's authority, and refused on
//! both paths a blob composed here takes: a boot graph's resident workloads
//! and a workload `CREATE`.
//!
//! The module record's step budget carries the module's YAML
//! `step_deadline_us`, `step_deadline_burst_us` and `fault_policy`, as a
//! base-graph module declares them (`0` deadline = the node's default, `0`
//! burst = `deadline × BURST_MULTIPLIER`; the policy byte is numbered as the
//! params TLV's tag `0xF1`). A workload's fault tags never ride in its params:
//! the kernel takes a live-added module's budget from this record alone, and
//! admits it only within the node's ceiling and with a policy confined to the
//! module (see `config::builder::workload_step_budget`, which refuses at build
//! time what the kernel would refuse at admission).

/// Wire magic for an `AddSubgraph` blob: "FLXA". Mirrors
/// `kernel::exec::scheduler::live::ADD_MAGIC`.
pub const ADD_MAGIC: u32 = 0x464C_5841;
/// `AddSubgraph` wire version. Mirrors `kernel::exec::scheduler::live::ADD_VERSION`.
pub const ADD_VERSION: u16 = 1;
/// Bytes of a module record before its params. Mirrors
/// `kernel::exec::scheduler::live::ADD_MODULE_FIXED_BYTES`.
pub const ADD_MODULE_FIXED_BYTES: usize = 4 + 1 + 4 + 4 + 1 + 2;

/// Fault-policy wire bytes, as the kernel's `FaultPolicy::from_wire` reads
/// them (the params TLV tag `0xF1` uses the same numbering).
pub const FAULT_POLICY_SKIP: u8 = 0;
pub const FAULT_POLICY_RESTART: u8 = 1;
pub const FAULT_POLICY_RESTART_GRAPH: u8 = 2;
pub const FAULT_POLICY_TOLERATE: u8 = 3;

/// Whether a params TLV tag is a node tag — mirrors the kernel's
/// `scheduler::is_node_param_tag`: the fault tags (0xF0–0xF3, 0xF6), trust
/// tier (0xF4), protection level (0xF5), quarantine partner (0xF7), ISR
/// budget (0xFB), IRQ (0xFC) and device window (0xFD). Only the node's own
/// graph grants them; a node refuses a workload module whose params carry
/// one. The heap flags 0xF8–0xFA act on the module's own heap and are not
/// node tags.
pub const fn is_node_param_tag(tag: u8) -> bool {
    matches!(tag, 0xF0..=0xF7 | 0xFB..=0xFD)
}

/// The first node tag in a params TLV, walked as the kernel walks it
/// (`scheduler::params_node_tag`): after the `0xFE` header when present, up
/// to the `0xFF` end marker; extended entries after the marker are not read.
pub fn params_node_tag(params: &[u8]) -> Option<u8> {
    if params.len() < 4 {
        return None;
    }
    let mut pos = if params[0] == 0xFE { 4 } else { 0 };
    while pos + 2 <= params.len() {
        let tag = params[pos];
        let len = params[pos + 1] as usize;
        pos += 2;
        if tag == 0xFF {
            break;
        }
        if pos + len > params.len() {
            break;
        }
        if is_node_param_tag(tag) {
            return Some(tag);
        }
        pos += len;
    }
    None
}

/// Burst multiplier — mirrors `kernel::step_guard::BURST_MULTIPLIER`.
const BURST_MULTIPLIER: u32 = 8;
/// Default step deadline — mirrors
/// `kernel::step_guard::DEFAULT_STEP_DEADLINE_US` (hardware figure).
const DEFAULT_STEP_DEADLINE_US: u32 = 2000;

/// A workload module's step budget, as its FLXA record carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct StepBudget {
    /// `step_deadline_us`; `0` = the node's default.
    pub deadline_us: u32,
    /// `step_deadline_burst_us`; `0` = `deadline × BURST_MULTIPLIER`.
    pub burst_us: u32,
    /// `fault_policy` wire byte (`FAULT_POLICY_*`).
    pub fault_policy: u8,
}

impl StepBudget {
    /// Whether a deadline of either kind is declared. An undeclared budget
    /// runs on the node's defaults and is not measured against a ceiling.
    pub fn declares_deadline(&self) -> bool {
        self.deadline_us != 0 || self.burst_us != 0
    }

    /// The burst deadline the kernel runs the module under: the declared
    /// burst, else the declared (or default) deadline × `BURST_MULTIPLIER`.
    pub fn effective_burst_us(&self) -> u32 {
        if self.burst_us != 0 {
            return self.burst_us;
        }
        let d = if self.deadline_us != 0 {
            self.deadline_us
        } else {
            DEFAULT_STEP_DEADLINE_US
        };
        d.saturating_mul(BURST_MULTIPLIER)
    }
}
/// Resident-workload config-section magic: "FXPD". Mirrors
/// `kernel::boot::config::WORKLOAD_SECTION_MAGIC`.
pub const WORKLOAD_SECTION_MAGIC: u32 = 0x4658_5044;

/// Largest subgraph one `apply_add` admits — mirrors
/// `kernel::exec::scheduler::live::MAX_ADD_MODULES`.
pub const MAX_ADD_MODULES: usize = 64;
/// Largest edge count one `apply_add` admits — mirrors
/// `kernel::exec::scheduler::live::MAX_ADD_EDGES`.
pub const MAX_ADD_EDGES: usize = 128;
/// Largest resident-workload section the kernel will map — mirrors
/// `kernel::boot::config::MAX_WORKLOAD_SECTION_BYTES`. The encoder rejects
/// output beyond this so a config that builds always admits ALL its workloads
/// (the kernel caps the mapped section at this size and would otherwise
/// silently truncate).
pub const MAX_WORKLOAD_SECTION_BYTES: usize = 8 * 1024;

/// One PIC module in a workload. `params` is the inline TLV blob (as
/// `schema::build_params_from_schema` produces it for a base-graph module).
pub struct WorkloadModule {
    pub name_hash: u32,
    pub domain_id: u8,
    /// The module's declared step budget (FLXA module record).
    pub budget: StepBudget,
    pub params: Vec<u8>,
}

/// An end of a workload edge: one of the workload's own modules, or the
/// node's network through a lane of the workload's (FLXA endpoint kind 3,
/// the kernel's `Endpoint::Net`). A key names one lane: at most one edge into
/// it (the module's net commands) and one out of it (its net events).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkloadEnd {
    Local(u8),
    Net(u8),
}

/// One workload edge (producer → consumer).
pub struct WorkloadEdge {
    pub from: WorkloadEnd,
    pub from_port: u8,
    pub to: WorkloadEnd,
    pub to_port: u8,
    pub buffer_bytes: u32,
}

/// The kernel's lane rule (`net_keys_paired`): every net key names exactly
/// one edge into the network (from a workload module) and one out of it (to
/// a workload module); a lane joined to another lane is refused.
pub fn check_net_lanes(edges: &[WorkloadEdge]) -> Result<(), String> {
    for e in edges {
        let key = match (e.from, e.to) {
            (WorkloadEnd::Net(_), WorkloadEnd::Net(_)) => {
                return Err(
                    "a net lane connects to a module of the workload, not to another lane".into(),
                )
            }
            (WorkloadEnd::Net(k), _) | (_, WorkloadEnd::Net(k)) => k,
            _ => continue,
        };
        let into = edges
            .iter()
            .filter(|x| x.to == WorkloadEnd::Net(key))
            .count();
        let out = edges
            .iter()
            .filter(|x| x.from == WorkloadEnd::Net(key))
            .count();
        if into != 1 || out != 1 {
            return Err(format!(
                "net lane {key} has {into} edge(s) into it and {out} out of it; a lane is exactly one of each \
                 (a module's commands in, its events out)"
            ));
        }
    }
    Ok(())
}

fn encode_end(b: &mut Vec<u8>, end: WorkloadEnd) {
    let (kind, idx) = match end {
        WorkloadEnd::Local(i) => (0u8, i),
        WorkloadEnd::Net(k) => (3u8, k),
    };
    b.push(kind);
    b.extend_from_slice(&(idx as u16).to_be_bytes());
}

/// One resident workload (a workload-owner subgraph admitted via `apply_add`).
pub struct Workload {
    pub workload_uid: [u8; 16],
    pub state_cap: u32,
    pub buffer_cap: u32,
    pub modules: Vec<WorkloadModule>,
    pub edges: Vec<WorkloadEdge>,
    /// Idle-safe attestation (graph YAML `idle_safe: true` on the workload): the
    /// operator asserts every module in this workload is demand-driven — it makes
    /// progress only when an event or its own periodic schedule wakes it, and
    /// never relies on being stepped to notice anything. Carried in the FXPD
    /// per-workload flags byte. The scheduler ANDs the attestation across every
    /// module the owner holds and parks the whole graph when idle only if all
    /// of them attest; an UNATTESTED workload is fail-closed — never parked, only
    /// relaxed to a liveness step every `tick_max`.
    pub idle_safe: bool,
}

/// FXPD per-workload flags bit: workload is idle-safe attested.
pub const WORKLOAD_FLAG_IDLE_SAFE: u8 = 0x01;

/// Encode one workload as a big-endian `AddSubgraph` (FLXA) blob byte-compatible with
/// `apply_add_encoded`.
pub fn encode_add_subgraph(workload: &Workload) -> Result<Vec<u8>, String> {
    if workload.modules.len() > MAX_ADD_MODULES {
        return Err(format!(
            "workload has {} modules, exceeds MAX_ADD_MODULES ({MAX_ADD_MODULES})",
            workload.modules.len()
        ));
    }
    if workload.edges.len() > MAX_ADD_EDGES {
        return Err(format!(
            "workload has {} edges, exceeds MAX_ADD_EDGES ({MAX_ADD_EDGES})",
            workload.edges.len()
        ));
    }
    let mut b = Vec::new();
    b.extend_from_slice(&ADD_MAGIC.to_be_bytes());
    b.extend_from_slice(&ADD_VERSION.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes()); // flags: a workload's own authority
    b.extend_from_slice(&workload.workload_uid);
    b.extend_from_slice(&workload.state_cap.to_be_bytes());
    b.extend_from_slice(&workload.buffer_cap.to_be_bytes());
    b.push(workload.modules.len() as u8);
    b.push(workload.edges.len() as u8);
    for m in &workload.modules {
        let record_start = b.len();
        b.extend_from_slice(&m.name_hash.to_be_bytes());
        b.push(m.domain_id);
        b.extend_from_slice(&m.budget.deadline_us.to_be_bytes());
        b.extend_from_slice(&m.budget.burst_us.to_be_bytes());
        b.push(m.budget.fault_policy);
        if m.params.len() > u16::MAX as usize {
            return Err(format!(
                "workload module params {} bytes exceed u16",
                m.params.len()
            ));
        }
        b.extend_from_slice(&(m.params.len() as u16).to_be_bytes());
        debug_assert_eq!(b.len() - record_start, ADD_MODULE_FIXED_BYTES);
        b.extend_from_slice(&m.params);
    }
    for e in &workload.edges {
        // Endpoint kind 0 = New (workload-local), 3 = Net (a lane to the node's
        // network).
        encode_end(&mut b, e.from);
        b.push(e.from_port);
        encode_end(&mut b, e.to);
        b.push(e.to_port);
        b.extend_from_slice(&e.buffer_bytes.to_be_bytes());
    }
    Ok(b)
}

/// CRC-16-CCITT (0xFFFF init, 0x1021 poly) — byte-identical to the kernel's
/// `config::crc16_ccitt`, so the kernel can verify the workload section's integrity.
fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Encode the resident-workload config section. Layout (little-endian framing; inner
/// FLXA blobs are big-endian):
/// `[FXPD u32][section_len u32][crc16 u16][count u16]` then per workload
/// `[blob_len u32][flags u8][FLXA blob]`. The workload section rides PAST the config
/// body's CRC-16, so it carries its OWN length + CRC over the payload (`count` +
/// workloads); the kernel validates the whole section before admitting ANY workload, so
/// corruption can't change a workload's domain/wiring/params/attestation or leave a
/// prefix active. Rejects output exceeding `MAX_WORKLOAD_SECTION_BYTES` (the kernel's
/// mapped cap), so a config that builds always admits every workload.
pub fn encode_workload_section(workloads: &[Workload]) -> Result<Vec<u8>, String> {
    // Payload = count + workloads (the CRC-covered, executable content).
    let mut payload = Vec::new();
    payload.extend_from_slice(&(workloads.len() as u16).to_le_bytes());
    for p in workloads {
        let blob = encode_add_subgraph(p)?;
        let flags = if p.idle_safe {
            WORKLOAD_FLAG_IDLE_SAFE
        } else {
            0
        };
        payload.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        payload.push(flags);
        payload.extend_from_slice(&blob);
    }
    let crc = crc16_ccitt(&payload);
    let section_len = 10 + payload.len(); // header magic(4)+len(4)+crc(2) + payload
    if section_len > MAX_WORKLOAD_SECTION_BYTES {
        return Err(format!(
            "resident-workload section is {section_len} bytes, exceeding the kernel's mapped \
             cap (MAX_WORKLOAD_SECTION_BYTES = {MAX_WORKLOAD_SECTION_BYTES}); the kernel would \
             truncate it. Reduce workload count or per-workload params."
        ));
    }
    let mut s = Vec::with_capacity(section_len);
    s.extend_from_slice(&WORKLOAD_SECTION_MAGIC.to_le_bytes());
    s.extend_from_slice(&(section_len as u32).to_le_bytes());
    s.extend_from_slice(&crc.to_le_bytes());
    s.extend_from_slice(&payload);
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_subgraph_blob_matches_kernel_wire_layout() {
        let workload = Workload {
            workload_uid: [7u8; 16],
            state_cap: 0,
            buffer_cap: 0,
            modules: vec![WorkloadModule {
                name_hash: 0x1234_5678,
                domain_id: 0,
                budget: StepBudget::default(),
                params: vec![],
            }],
            edges: vec![],
            idle_safe: false,
        };
        let b = encode_add_subgraph(&workload).unwrap();
        // magic (BE), version (BE), flags.
        assert_eq!(&b[0..4], &ADD_MAGIC.to_be_bytes());
        assert_eq!(&b[4..6], &ADD_VERSION.to_be_bytes());
        assert_eq!(&b[6..8], &[0, 0]);
        assert_eq!(&b[8..24], &[7u8; 16]); // workload_uid
        assert_eq!(&b[24..28], &0u32.to_be_bytes()); // state_cap
        assert_eq!(&b[28..32], &0u32.to_be_bytes()); // buffer_cap
        assert_eq!(b[32], 1); // module_count
        assert_eq!(b[33], 0); // edge_count
                              // module 0: name_hash (BE), domain, step budget, params_len (BE) = 0
        assert_eq!(&b[34..38], &0x1234_5678u32.to_be_bytes());
        assert_eq!(b[38], 0); // domain_id
        assert_eq!(&b[39..43], &0u32.to_be_bytes()); // step_deadline_us
        assert_eq!(&b[43..47], &0u32.to_be_bytes()); // step_deadline_burst_us
        assert_eq!(b[47], FAULT_POLICY_SKIP); // fault_policy
        assert_eq!(&b[48..50], &0u16.to_be_bytes()); // params_len
        assert_eq!(b.len(), 34 + ADD_MODULE_FIXED_BYTES);
    }

    #[test]
    fn module_record_carries_its_step_budget() {
        let workload = Workload {
            workload_uid: [0u8; 16],
            state_cap: 0,
            buffer_cap: 0,
            modules: vec![WorkloadModule {
                name_hash: 0xAABB_CCDD,
                domain_id: 1,
                budget: StepBudget {
                    deadline_us: 12_000,
                    burst_us: 16_000,
                    fault_policy: FAULT_POLICY_TOLERATE,
                },
                params: vec![0xFE, 0x01],
            }],
            edges: vec![],
            idle_safe: false,
        };
        let b = encode_add_subgraph(&workload).unwrap();
        let m = &b[34..];
        assert_eq!(&m[0..4], &0xAABB_CCDDu32.to_be_bytes());
        assert_eq!(m[4], 1);
        assert_eq!(&m[5..9], &12_000u32.to_be_bytes());
        assert_eq!(&m[9..13], &16_000u32.to_be_bytes());
        assert_eq!(m[13], FAULT_POLICY_TOLERATE);
        assert_eq!(&m[14..16], &2u16.to_be_bytes());
        assert_eq!(&m[16..18], &[0xFE, 0x01]);
        assert_eq!(b.len(), 34 + ADD_MODULE_FIXED_BYTES + 2);
    }

    #[test]
    fn node_tags_are_found_where_the_kernel_reads_them() {
        let tlv = |entries: &[u8], ext: &[u8]| {
            let mut b = vec![0xFE, 0x01, 0, 0];
            b.extend_from_slice(entries);
            b.extend_from_slice(&[0xFF, 0x00]);
            b.extend_from_slice(ext);
            b
        };
        // Schema params and heap flags only.
        assert_eq!(
            params_node_tag(&tlv(&[1, 1, 7, 12, 2, 0, 0, 0xF8, 1, 1], &[])),
            None
        );
        // Each node tag, behind an ordinary entry.
        for tag in [0xF0, 0xF1, 0xF4, 0xF5, 0xF7, 0xFB, 0xFC, 0xFD] {
            assert_eq!(params_node_tag(&tlv(&[1, 1, 0, tag, 1, 0], &[])), Some(tag));
        }
        // A wrong length still counts.
        assert_eq!(params_node_tag(&tlv(&[0xFD, 1, 0], &[])), Some(0xFD));
        // Extended entries past the end marker are not node tags, whatever
        // their tag byte (tls's credentials use [tag][0][len BE]).
        assert_eq!(params_node_tag(&tlv(&[1, 1, 0], &[0xFD, 0, 0, 1, 9])), None);
        // A node tag's value bytes are skipped, not read as tags.
        assert_eq!(params_node_tag(&tlv(&[3, 2, 0xF5, 0xFD], &[])), None);
    }

    #[test]
    fn effective_burst_follows_the_kernel_rule() {
        let none = StepBudget::default();
        assert!(!none.declares_deadline());
        assert_eq!(
            none.effective_burst_us(),
            DEFAULT_STEP_DEADLINE_US * BURST_MULTIPLIER
        );
        let d = StepBudget {
            deadline_us: 1_500,
            ..StepBudget::default()
        };
        assert_eq!(d.effective_burst_us(), 12_000);
        let b = StepBudget {
            deadline_us: 1_500,
            burst_us: 4_000,
            ..StepBudget::default()
        };
        assert_eq!(b.effective_burst_us(), 4_000);
    }

    #[test]
    fn net_lane_edges_encode_as_endpoint_kind_three() {
        let workload = Workload {
            workload_uid: [0u8; 16],
            state_cap: 0,
            buffer_cap: 0,
            modules: vec![WorkloadModule {
                name_hash: 1,
                domain_id: 0,
                budget: StepBudget::default(),
                params: vec![],
            }],
            edges: vec![
                WorkloadEdge {
                    from: WorkloadEnd::Net(2),
                    from_port: 0,
                    to: WorkloadEnd::Local(0),
                    to_port: 0,
                    buffer_bytes: 0,
                },
                WorkloadEdge {
                    from: WorkloadEnd::Local(0),
                    from_port: 0,
                    to: WorkloadEnd::Net(2),
                    to_port: 0,
                    buffer_bytes: 4096,
                },
            ],
            idle_safe: false,
        };
        assert!(check_net_lanes(&workload.edges).is_ok());
        let b = encode_add_subgraph(&workload).unwrap();
        assert_eq!(b[33], 2); // edge_count
        let e = &b[34 + ADD_MODULE_FIXED_BYTES..];
        // from Net(2) port 0 -> to New(0) port 0, 0 bytes.
        assert_eq!(&e[0..12], &[3, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        // from New(0) port 0 -> to Net(2) port 0, 4096 bytes.
        assert_eq!(&e[12..24], &[0, 0, 0, 0, 3, 0, 2, 0, 0, 0, 0x10, 0]);
        // The resident section carries the same blob after its frame.
        let s = encode_workload_section(&[workload]).unwrap();
        assert_eq!(&s[17..], &b[..]);
    }

    #[test]
    fn net_lanes_are_refused_unless_paired() {
        let edge = |from, to| WorkloadEdge {
            from,
            from_port: 0,
            to,
            to_port: 0,
            buffer_bytes: 0,
        };
        // Commands in, no events out.
        let one_way = [edge(WorkloadEnd::Local(0), WorkloadEnd::Net(1))];
        assert!(check_net_lanes(&one_way)
            .unwrap_err()
            .contains("net lane 1"));
        // Two command edges into one lane.
        let doubled = [
            edge(WorkloadEnd::Local(0), WorkloadEnd::Net(1)),
            edge(WorkloadEnd::Local(1), WorkloadEnd::Net(1)),
            edge(WorkloadEnd::Net(1), WorkloadEnd::Local(0)),
        ];
        assert!(check_net_lanes(&doubled).is_err());
        // A lane into a lane.
        let net_net = [edge(WorkloadEnd::Net(1), WorkloadEnd::Net(2))];
        assert!(check_net_lanes(&net_net).is_err());
        // Two lanes, each paired.
        let two = [
            edge(WorkloadEnd::Local(0), WorkloadEnd::Net(1)),
            edge(WorkloadEnd::Net(1), WorkloadEnd::Local(0)),
            edge(WorkloadEnd::Local(1), WorkloadEnd::Net(2)),
            edge(WorkloadEnd::Net(2), WorkloadEnd::Local(1)),
        ];
        assert!(check_net_lanes(&two).is_ok());
    }

    #[test]
    fn workload_section_header_has_length_and_crc() {
        let workload = Workload {
            workload_uid: [0u8; 16],
            state_cap: 1,
            buffer_cap: 2,
            modules: vec![],
            edges: vec![],
            idle_safe: true,
        };
        let s = encode_workload_section(&[workload]).unwrap();
        // Header: magic(4) + section_len(4) + crc16(2) + count(2).
        assert_eq!(&s[0..4], &WORKLOAD_SECTION_MAGIC.to_le_bytes());
        let section_len = u32::from_le_bytes([s[4], s[5], s[6], s[7]]) as usize;
        assert_eq!(section_len, s.len());
        let crc = u16::from_le_bytes([s[8], s[9]]);
        // CRC covers the payload (count + workloads) = section[10..].
        assert_eq!(crc, crc16_ccitt(&s[10..]));
        assert_eq!(&s[10..12], &1u16.to_le_bytes()); // workload_count
        let blob_len = u32::from_le_bytes([s[12], s[13], s[14], s[15]]) as usize;
        // Per-workload frame: blob_len(4) then flags(1) then the FLXA blob.
        assert_eq!(blob_len, 34); // 0-module blob: header(8)+uid(16)+caps(8)+counts(2)
        assert_eq!(s[16], WORKLOAD_FLAG_IDLE_SAFE); // flags: idle-safe attested
        assert_eq!(s.len(), 17 + blob_len);
        // inner blob is big-endian FLXA (after the 1-byte flags).
        assert_eq!(&s[17..21], &ADD_MAGIC.to_be_bytes());
    }

    #[test]
    fn oversized_workload_section_rejected() {
        // A workload whose params push the section past the kernel's mapped cap must
        // be rejected at encode time, not silently truncated at boot.
        let big = Workload {
            workload_uid: [0u8; 16],
            state_cap: 0,
            buffer_cap: 0,
            modules: vec![WorkloadModule {
                name_hash: 1,
                domain_id: 0,
                budget: StepBudget::default(),
                params: vec![0u8; MAX_WORKLOAD_SECTION_BYTES], // > cap on its own
            }],
            edges: vec![],
            idle_safe: false,
        };
        assert!(encode_workload_section(&[big]).is_err());
    }

    #[test]
    fn too_many_modules_rejected() {
        let workload = Workload {
            workload_uid: [0u8; 16],
            state_cap: 0,
            buffer_cap: 0,
            modules: (0..(MAX_ADD_MODULES + 1))
                .map(|_| WorkloadModule {
                    name_hash: 0,
                    domain_id: 0,
                    budget: StepBudget::default(),
                    params: vec![],
                })
                .collect(),
            edges: vec![],
            idle_safe: false,
        };
        assert!(encode_add_subgraph(&workload).is_err());
    }
}
