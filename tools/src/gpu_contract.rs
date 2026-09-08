//! The GPU wire contract and program-pack envelope, mounted for the host
//! tools.
//!
//! Path-mounted rather than reimplemented, for the same reason `wire.rs` and
//! `genstore_wire.rs` are: the offline packer, the device that loads a pack
//! and the consumer that built it must agree byte for byte, and the only way
//! to guarantee that is one source.
#![allow(
    dead_code,
    reason = "the contract surface is shared by producers, providers and \
              tooling; the CLI uses the pack half"
)]

include!("../../modules/sdk/crypto/sha256.rs");
include!("../../modules/sdk/wire/gpu_wire.rs");
include!("../../modules/sdk/cores/gpu_pack.rs");
include!("../../modules/sdk/cores/gpu_device.rs");
include!("../../modules/sdk/cores/gpu_replay.rs");

/// The replay provider's capability record, built from the same
/// `encode_caps` the running provider answers with, over the same profile it
/// is composed with — so a pack validated against this record is validated
/// against the device a graph would actually get.
#[must_use]
pub fn replay_caps() -> [u8; CAPS_LEN] {
    let mut resources = [ResourceSlot::EMPTY; REPLAY_MAX_RESOURCES];
    let mut views = [ViewSlot::EMPTY; REPLAY_MAX_VIEWS];
    let mut programs = [ProgramSlot::EMPTY; REPLAY_MAX_PROGRAMS];
    let mut pipelines = [PipelineSlot::EMPTY; REPLAY_MAX_PIPELINES];
    let mut fences = [FenceSlot::EMPTY; REPLAY_MAX_FENCES];
    let mut surfaces = [SurfaceSlot::EMPTY; REPLAY_MAX_SURFACES];
    let mut ring = [0u8; MIN_RING_BYTES];
    let dev = GpuDevice::restore(
        GpuTables {
            resources: &mut resources,
            views: &mut views,
            programs: &mut programs,
            pipelines: &mut pipelines,
            fences: &mut fences,
            surfaces: &mut surfaces,
            outcomes: &mut ring,
        },
        replay_limits(REPLAY_ARENA_BYTES as u64),
        BACKEND_REPLAY,
        0,
        DeviceScalars::initial(),
    );
    dev.encode_caps()
}
