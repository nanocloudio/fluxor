//! UF2 format parsing and generation
//!
//! UF2 is the firmware format used by RP2350/RP2040 bootloaders.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

/// UF2 format constants
pub const UF2_MAGIC_START0: u32 = 0x0A324655; // "UF2\n"
pub const UF2_MAGIC_START1: u32 = 0x9E5D5157;
pub const UF2_MAGIC_END: u32 = 0x0AB16F30;
pub const UF2_BLOCK_SIZE: usize = 512;
pub const UF2_DATA_SIZE: usize = 256;
pub const UF2_FLAGS_FAMILY: u32 = 0x2000;

/// RP2350 ARM Secure family ID
pub const UF2_FAMILY_RP2350: u32 = 0xE48BFF59;

/// Parse UF2 file into memory map
pub fn parse_uf2(content: &[u8]) -> Result<BTreeMap<u32, u8>> {
    if !content.len().is_multiple_of(UF2_BLOCK_SIZE) {
        return Err(Error::Uf2(format!(
            "Invalid UF2 file size: {} (not multiple of {})",
            content.len(),
            UF2_BLOCK_SIZE
        )));
    }

    let mut memory = BTreeMap::new();
    let num_blocks = content.len() / UF2_BLOCK_SIZE;

    for i in 0..num_blocks {
        let offset = i * UF2_BLOCK_SIZE;
        let block = &content[offset..offset + UF2_BLOCK_SIZE];

        // Parse header
        let magic0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        let magic1 = u32::from_le_bytes([block[4], block[5], block[6], block[7]]);
        let _flags = u32::from_le_bytes([block[8], block[9], block[10], block[11]]);
        let target_addr = u32::from_le_bytes([block[12], block[13], block[14], block[15]]);
        let payload_size = u32::from_le_bytes([block[16], block[17], block[18], block[19]]);

        // Verify magic
        if magic0 != UF2_MAGIC_START0 || magic1 != UF2_MAGIC_START1 {
            return Err(Error::Uf2(format!("Invalid UF2 magic at block {}", i)));
        }

        // Verify end magic
        let end_magic = u32::from_le_bytes([block[508], block[509], block[510], block[511]]);
        if end_magic != UF2_MAGIC_END {
            return Err(Error::Uf2(format!("Invalid UF2 end magic at block {}", i)));
        }

        // Extract payload
        let payload = &block[32..32 + payload_size as usize];
        for (j, &byte) in payload.iter().enumerate() {
            memory.insert(target_addr + j as u32, byte);
        }
    }

    Ok(memory)
}

/// Extract contiguous region from memory map (fixed size)
pub fn extract_region(memory: &BTreeMap<u32, u8>, start: u32, size: usize) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(size);
    for i in 0..size {
        let addr = start + i as u32;
        result.push(*memory.get(&addr)?);
    }
    Some(result)
}

/// Fix only block numbering after concatenating UF2 files
///
/// Updates block numbers and total counts but preserves original family IDs.
pub fn fix_uf2_block_numbers(data: &mut [u8]) {
    if !data.len().is_multiple_of(UF2_BLOCK_SIZE) {
        return;
    }

    let total_blocks = data.len() / UF2_BLOCK_SIZE;

    for block_no in 0..total_blocks {
        let offset = block_no * UF2_BLOCK_SIZE;

        // Update block number (offset 20)
        data[offset + 20..offset + 24].copy_from_slice(&(block_no as u32).to_le_bytes());

        // Update total blocks (offset 24)
        data[offset + 24..offset + 28].copy_from_slice(&(total_blocks as u32).to_le_bytes());

        // DO NOT modify family ID - preserve original
    }
}

/// Create UF2 blocks for data at given address
pub fn create_uf2_blocks(data: &[u8], base_addr: u32, family_id: u32) -> Vec<u8> {
    let payload_size = UF2_DATA_SIZE;
    let num_blocks = data.len().div_ceil(payload_size);
    let mut blocks = Vec::with_capacity(num_blocks * UF2_BLOCK_SIZE);

    for (block_no, chunk) in data.chunks(payload_size).enumerate() {
        let mut block = vec![0u8; UF2_BLOCK_SIZE];

        // Header
        block[0..4].copy_from_slice(&UF2_MAGIC_START0.to_le_bytes());
        block[4..8].copy_from_slice(&UF2_MAGIC_START1.to_le_bytes());
        block[8..12].copy_from_slice(&UF2_FLAGS_FAMILY.to_le_bytes());
        block[12..16]
            .copy_from_slice(&(base_addr + (block_no * payload_size) as u32).to_le_bytes());
        block[16..20].copy_from_slice(&(payload_size as u32).to_le_bytes());
        block[20..24].copy_from_slice(&(block_no as u32).to_le_bytes());
        block[24..28].copy_from_slice(&(num_blocks as u32).to_le_bytes());
        block[28..32].copy_from_slice(&family_id.to_le_bytes());

        // Payload (pad with 0xFF like flash erased state)
        block[32..32 + chunk.len()].copy_from_slice(chunk);
        for b in &mut block[32 + chunk.len()..32 + payload_size] {
            *b = 0xFF;
        }

        // End magic
        block[508..512].copy_from_slice(&UF2_MAGIC_END.to_le_bytes());

        blocks.extend_from_slice(&block);
    }

    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_parse_uf2() {
        let data = vec![0x12, 0x34, 0x56, 0x78];
        let base_addr = 0x10000000;

        let uf2 = create_uf2_blocks(&data, base_addr, UF2_FAMILY_RP2350);
        let memory = parse_uf2(&uf2).unwrap();

        assert_eq!(memory.get(&0x10000000), Some(&0x12));
        assert_eq!(memory.get(&0x10000001), Some(&0x34));
        assert_eq!(memory.get(&0x10000002), Some(&0x56));
        assert_eq!(memory.get(&0x10000003), Some(&0x78));
    }
}
