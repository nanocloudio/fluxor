//! Public Fluxor storage-surface contracts.
//!
//! Fluxor owns the storage-surface vocabulary and the typed `Fence`
//! enum that operations return. Downstream implementers (Loam,
//! FAT32-backed providers, etc.) depend on this crate and produce
//! honest `Fence` values out of their pipelines.
//!
//! This crate is deliberately small and dependency-free so it can be
//! pulled in by anything that needs the vocabulary without dragging in
//! the kernel, platform code, or any chip/host feature. Enable the
//! `serde` feature to get `Serialize`/`Deserialize` on every type.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Canonical content-type identifiers for the four storage surfaces
/// Fluxor publishes. Implementers expose themselves on the mesh under
/// one of these strings.
pub mod content_type {
    pub const STORAGE_BLOCK: &str = "storage.block";
    pub const FILE_DATA: &str = "file.data";
    pub const STORAGE_NAMESPACE: &str = "storage.namespace";
    pub const STORAGE_OBJECT: &str = "storage.object";
}

/// Per-operation fence: the actual guarantee a returning operation
/// achieved. Operations MUST NOT advertise a fence stronger than the
/// underlying graph produced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
pub enum Fence {
    Volatile,
    LocalDurable,
    ReplicatedDurable {
        quorum: u32,
        epoch: u64,
        witness: ClustorFenceWitness,
    },
    ContentHashed {
        algo: HashAlgo,
        digest: Vec<u8>,
    },
    RevisionMonotone {
        revision: u64,
    },
    ViewConsistent {
        view_epoch: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum HashAlgo {
    Sha256,
    Blake3,
}

/// Externally observable proof that a replicated-durable fence
/// completed. Constructed by the Clustor binding the operation went
/// through; carried on `Fence::ReplicatedDurable` so downstream
/// consumers can verify the fence was real.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ClustorFenceWitness {
    pub fence_epoch: u64,
    pub manifest_id: String,
    pub quorum: u32,
    pub acked_participants: Vec<String>,
}

impl ClustorFenceWitness {
    pub fn new(
        fence_epoch: u64,
        manifest_id: impl Into<String>,
        quorum: u32,
        acked: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let mut acked: Vec<String> = acked.into_iter().map(Into::into).collect();
        acked.sort();
        Self {
            fence_epoch,
            manifest_id: manifest_id.into(),
            quorum,
            acked_participants: acked,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.acked_participants.is_empty()
    }
}

/// A leased handle into the mesh, returned when a caller opens a
/// namespace or object.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct StorageHandle {
    pub surface: StorageSurface,
    pub content_type: &'static str,
    pub mesh_handle_id: u64,
    pub lease_epoch: u64,
}

/// Identifier for which of the four Fluxor-owned surfaces a handle or
/// descriptor refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum StorageSurface {
    Block,
    FileData,
    Namespace,
    Object,
}

impl StorageSurface {
    pub fn content_type(&self) -> &'static str {
        match self {
            Self::Block => content_type::STORAGE_BLOCK,
            Self::FileData => content_type::FILE_DATA,
            Self::Namespace => content_type::STORAGE_NAMESPACE,
            Self::Object => content_type::STORAGE_OBJECT,
        }
    }
}
