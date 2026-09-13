//! Host-side encoder for the on-device `AddSubgraph` wire format and the
//! resident-pod config section.
//!
//! A RESIDENT POD is a workload-owned subgraph declared in a graph YAML's
//! `pods:` section and admitted by the kernel at boot, alongside the base
//! graph rather than inside it. Each pod gets its own owner handle, its own
//! state/buffer caps, and is scheduled as an independent resident graph — so
//! a workload can be added, paced and parked without touching the base
//! graph's wiring or its compiled body.
//!
//! The `AddSubgraph` (FLXA) blob produced here is byte-compatible with the
//! kernel decoder `kernel::scheduler::live::apply_add_encoded`: big-endian,
//! fixed-width, PIC modules referenced by `name_hash` (FNV-1a of the type name).
//! The pod **section** wraps one or more FLXA blobs and is appended to the config
//! blob PAST the checksummed body (the same additive post-body discipline as the
//! adaptive-tick `tick_min/max` tail — see `kernel::config::ADAPTIVE_POST_SIZE`),
//! so the body/CRC stay byte-identical and no format version is bumped. The
//! kernel reads it in `kernel::config::read_config_from_slice` and admits each
//! pod at boot via `apply_add_encoded` + `finalize_resident_graphs`.
//!
//! Scope: pods are self-contained subgraphs — intra-pod edges only
//! (`New → New`), and those edges must stay inside one domain, because a
//! cross-domain edge needs the SPSC bridge that boot provisions for base
//! edges and `apply_add` does not open. Module params are the inline TLV
//! produced by `schema::build_params_from_schema`; a pod module cannot
//! reference a `data:`-section blob.

/// Wire magic for an `AddSubgraph` blob: "FLXA". Mirrors
/// `kernel::scheduler::live::ADD_MAGIC`.
pub const ADD_MAGIC: u32 = 0x464C_5841;
/// `AddSubgraph` wire version. Mirrors `kernel::scheduler::live::ADD_VERSION`.
pub const ADD_VERSION: u16 = 1;
/// Resident-pod config-section magic: "FXPD". Mirrors
/// `kernel::config::WORKLOAD_SECTION_MAGIC`.
pub const WORKLOAD_SECTION_MAGIC: u32 = 0x4658_5044;

/// Largest subgraph one `apply_add` admits — mirrors
/// `kernel::scheduler::live::MAX_ADD_MODULES`.
pub const MAX_ADD_MODULES: usize = 16;
/// Largest edge count one `apply_add` admits — mirrors
/// `kernel::scheduler::live::MAX_ADD_EDGES`.
pub const MAX_ADD_EDGES: usize = 32;
/// Largest resident-pod section the kernel will map — mirrors
/// `kernel::config::MAX_WORKLOAD_SECTION_BYTES`. The encoder rejects output beyond
/// this so a config that builds always admits ALL its pods (the kernel caps the
/// mapped section at this size and would otherwise silently truncate).
pub const MAX_WORKLOAD_SECTION_BYTES: usize = 8 * 1024;

/// One PIC module in a pod. `params` is the inline TLV blob (as
/// `schema::build_params_from_schema` produces it for a base-graph module).
pub struct PodModule {
    pub name_hash: u32,
    pub domain_id: u8,
    pub params: Vec<u8>,
}

/// One intra-pod edge (producer → consumer, both pod-local indices).
pub struct PodEdge {
    pub from_local: u8,
    pub from_port: u8,
    pub to_local: u8,
    pub to_port: u8,
    pub buffer_bytes: u32,
}

/// One resident pod (a workload-owner subgraph admitted via `apply_add`).
pub struct Pod {
    pub pod_uid: [u8; 16],
    pub state_cap: u32,
    pub buffer_cap: u32,
    pub modules: Vec<PodModule>,
    pub edges: Vec<PodEdge>,
    /// Idle-safe attestation (graph YAML `idle_safe: true` on the pod): the
    /// operator asserts every module in this pod is demand-driven — it makes
    /// progress only when an event or its own periodic schedule wakes it, and
    /// never relies on being stepped to notice anything. Carried in the FXPD
    /// per-pod flags byte. The scheduler ANDs the attestation across every
    /// module the owner holds and parks the whole graph when idle only if all
    /// of them attest; an UNATTESTED pod is fail-closed — never parked, only
    /// relaxed to a liveness step every `tick_max`.
    pub idle_safe: bool,
}

/// FXPD per-pod flags bit: pod is idle-safe attested.
pub const POD_FLAG_IDLE_SAFE: u8 = 0x01;

/// Encode one pod as a big-endian `AddSubgraph` (FLXA) blob byte-compatible with
/// `apply_add_encoded`.
pub fn encode_add_subgraph(pod: &Pod) -> Result<Vec<u8>, String> {
    if pod.modules.len() > MAX_ADD_MODULES {
        return Err(format!(
            "pod has {} modules, exceeds MAX_ADD_MODULES ({MAX_ADD_MODULES})",
            pod.modules.len()
        ));
    }
    if pod.edges.len() > MAX_ADD_EDGES {
        return Err(format!(
            "pod has {} edges, exceeds MAX_ADD_EDGES ({MAX_ADD_EDGES})",
            pod.edges.len()
        ));
    }
    let mut b = Vec::new();
    b.extend_from_slice(&ADD_MAGIC.to_be_bytes());
    b.extend_from_slice(&ADD_VERSION.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes()); // reserved
    b.extend_from_slice(&pod.pod_uid);
    b.extend_from_slice(&pod.state_cap.to_be_bytes());
    b.extend_from_slice(&pod.buffer_cap.to_be_bytes());
    b.push(pod.modules.len() as u8);
    b.push(pod.edges.len() as u8);
    for m in &pod.modules {
        b.extend_from_slice(&m.name_hash.to_be_bytes());
        b.push(m.domain_id);
        if m.params.len() > u16::MAX as usize {
            return Err(format!(
                "pod module params {} bytes exceed u16",
                m.params.len()
            ));
        }
        b.extend_from_slice(&(m.params.len() as u16).to_be_bytes());
        b.extend_from_slice(&m.params);
    }
    for e in &pod.edges {
        // Endpoint kind 0 = New (pod-local). v1 emits intra-pod edges only.
        b.push(0);
        b.extend_from_slice(&(e.from_local as u16).to_be_bytes());
        b.push(e.from_port);
        b.push(0);
        b.extend_from_slice(&(e.to_local as u16).to_be_bytes());
        b.push(e.to_port);
        b.extend_from_slice(&e.buffer_bytes.to_be_bytes());
    }
    Ok(b)
}

/// CRC-16-CCITT (0xFFFF init, 0x1021 poly) — byte-identical to the kernel's
/// `config::crc16_ccitt`, so the kernel can verify the pod section's integrity.
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

/// Encode the resident-pod config section. Layout (little-endian framing; inner
/// FLXA blobs are big-endian):
/// `[FXPD u32][section_len u32][crc16 u16][count u16]` then per pod
/// `[blob_len u32][flags u8][FLXA blob]`. The pod section rides PAST the config
/// body's CRC-16, so it carries its OWN length + CRC over the payload (`count` +
/// pods); the kernel validates the whole section before admitting ANY pod, so
/// corruption can't change a pod's domain/wiring/params/attestation or leave a
/// prefix active. Rejects output exceeding `MAX_WORKLOAD_SECTION_BYTES` (the kernel's
/// mapped cap), so a config that builds always admits every pod.
pub fn encode_pod_section(pods: &[Pod]) -> Result<Vec<u8>, String> {
    // Payload = count + pods (the CRC-covered, executable content).
    let mut payload = Vec::new();
    payload.extend_from_slice(&(pods.len() as u16).to_le_bytes());
    for p in pods {
        let blob = encode_add_subgraph(p)?;
        let flags = if p.idle_safe { POD_FLAG_IDLE_SAFE } else { 0 };
        payload.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        payload.push(flags);
        payload.extend_from_slice(&blob);
    }
    let crc = crc16_ccitt(&payload);
    let section_len = 10 + payload.len(); // header magic(4)+len(4)+crc(2) + payload
    if section_len > MAX_WORKLOAD_SECTION_BYTES {
        return Err(format!(
            "resident-pod section is {section_len} bytes, exceeding the kernel's mapped \
             cap (MAX_WORKLOAD_SECTION_BYTES = {MAX_WORKLOAD_SECTION_BYTES}); the kernel would \
             truncate it. Reduce pod count or per-pod params."
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
        let pod = Pod {
            pod_uid: [7u8; 16],
            state_cap: 0,
            buffer_cap: 0,
            modules: vec![PodModule {
                name_hash: 0x1234_5678,
                domain_id: 0,
                params: vec![],
            }],
            edges: vec![],
            idle_safe: false,
        };
        let b = encode_add_subgraph(&pod).unwrap();
        // magic (BE), version (BE), reserved.
        assert_eq!(&b[0..4], &ADD_MAGIC.to_be_bytes());
        assert_eq!(&b[4..6], &ADD_VERSION.to_be_bytes());
        assert_eq!(&b[6..8], &[0, 0]);
        assert_eq!(&b[8..24], &[7u8; 16]); // pod_uid
        assert_eq!(&b[24..28], &0u32.to_be_bytes()); // state_cap
        assert_eq!(&b[28..32], &0u32.to_be_bytes()); // buffer_cap
        assert_eq!(b[32], 1); // module_count
        assert_eq!(b[33], 0); // edge_count
                              // module 0: name_hash (BE), domain, params_len (BE) = 0
        assert_eq!(&b[34..38], &0x1234_5678u32.to_be_bytes());
        assert_eq!(b[38], 0); // domain_id
        assert_eq!(&b[39..41], &0u16.to_be_bytes()); // params_len
        assert_eq!(b.len(), 41);
    }

    #[test]
    fn pod_section_header_has_length_and_crc() {
        let pod = Pod {
            pod_uid: [0u8; 16],
            state_cap: 1,
            buffer_cap: 2,
            modules: vec![],
            edges: vec![],
            idle_safe: true,
        };
        let s = encode_pod_section(&[pod]).unwrap();
        // Header: magic(4) + section_len(4) + crc16(2) + count(2).
        assert_eq!(&s[0..4], &WORKLOAD_SECTION_MAGIC.to_le_bytes());
        let section_len = u32::from_le_bytes([s[4], s[5], s[6], s[7]]) as usize;
        assert_eq!(section_len, s.len());
        let crc = u16::from_le_bytes([s[8], s[9]]);
        // CRC covers the payload (count + pods) = section[10..].
        assert_eq!(crc, crc16_ccitt(&s[10..]));
        assert_eq!(&s[10..12], &1u16.to_le_bytes()); // workload_count
        let blob_len = u32::from_le_bytes([s[12], s[13], s[14], s[15]]) as usize;
        // Per-pod frame: blob_len(4) then flags(1) then the FLXA blob.
        assert_eq!(blob_len, 34); // 0-module blob: header(8)+uid(16)+caps(8)+counts(2)
        assert_eq!(s[16], POD_FLAG_IDLE_SAFE); // flags: idle-safe attested
        assert_eq!(s.len(), 17 + blob_len);
        // inner blob is big-endian FLXA (after the 1-byte flags).
        assert_eq!(&s[17..21], &ADD_MAGIC.to_be_bytes());
    }

    #[test]
    fn oversized_pod_section_rejected() {
        // A pod whose params push the section past the kernel's mapped cap must
        // be rejected at encode time, not silently truncated at boot.
        let big = Pod {
            pod_uid: [0u8; 16],
            state_cap: 0,
            buffer_cap: 0,
            modules: vec![PodModule {
                name_hash: 1,
                domain_id: 0,
                params: vec![0u8; MAX_WORKLOAD_SECTION_BYTES], // > cap on its own
            }],
            edges: vec![],
            idle_safe: false,
        };
        assert!(encode_pod_section(&[big]).is_err());
    }

    #[test]
    fn too_many_modules_rejected() {
        let pod = Pod {
            pod_uid: [0u8; 16],
            state_cap: 0,
            buffer_cap: 0,
            modules: (0..(MAX_ADD_MODULES + 1))
                .map(|_| PodModule {
                    name_hash: 0,
                    domain_id: 0,
                    params: vec![],
                })
                .collect(),
            edges: vec![],
            idle_safe: false,
        };
        assert!(encode_add_subgraph(&pod).is_err());
    }
}
