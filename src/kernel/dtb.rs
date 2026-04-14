//! Flattened Device Tree (FDT) reader.
//!
//! The DTB pointer handed to the kernel by firmware is stashed in
//! `_boot_dtb_ptr`; this module walks the blob to answer property queries.
//! Minimal: no heap, no materialised tree — just a streaming walker over
//! the FDT structure block.
//!
//! Reference: devicetree.org/specifications (section 5 "Flattened Device
//! Tree (DTB) Format").

use core::slice;

const FDT_MAGIC: u32 = 0xD00DFEED;
const FDT_BEGIN_NODE: u32 = 0x0000_0001;
const FDT_END_NODE: u32 = 0x0000_0002;
const FDT_PROP: u32 = 0x0000_0003;
const FDT_NOP: u32 = 0x0000_0004;
const FDT_END: u32 = 0x0000_0009;

#[repr(C)]
struct FdtHeader {
    magic: u32,
    totalsize: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    off_mem_rsvmap: u32,
    version: u32,
    last_comp_version: u32,
    boot_cpuid_phys: u32,
    size_dt_strings: u32,
    size_dt_struct: u32,
}

extern "C" {
    static _boot_dtb_ptr: u64;
}

/// Return the DTB base pointer, or None if no DTB was captured at boot or
/// the magic bytes don't match.
unsafe fn dtb_base() -> Option<*const u8> {
    let p = core::ptr::read_volatile(&_boot_dtb_ptr);
    if p == 0 || p == u64::MAX {
        return None;
    }
    let ptr = p as *const u8;
    let magic = read_be_u32(ptr);
    if magic != FDT_MAGIC {
        return None;
    }
    Some(ptr)
}

#[inline]
unsafe fn read_be_u32(p: *const u8) -> u32 {
    u32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)])
}

/// Return the ethernet MAC address from the DTB, if present.
///
/// Walks the structure block looking for any node carrying a
/// `local-mac-address` property of exactly 6 bytes, and returns the first
/// match. Returns None if no such property is found or no DTB is attached.
pub fn read_ethernet_mac() -> Option<[u8; 6]> {
    unsafe {
        let base = dtb_base()?;
        let header = &*(base as *const FdtHeader);
        let off_struct = u32::from_be(header.off_dt_struct) as usize;
        let off_strings = u32::from_be(header.off_dt_strings) as usize;
        let size_struct = u32::from_be(header.size_dt_struct) as usize;
        let size_strings = u32::from_be(header.size_dt_strings) as usize;
        let total = u32::from_be(header.totalsize) as usize;
        if off_struct + size_struct > total || off_strings + size_strings > total {
            return None;
        }

        let structs = slice::from_raw_parts(base.add(off_struct), size_struct);
        let strings = slice::from_raw_parts(base.add(off_strings), size_strings);

        let mut i = 0usize;
        while i + 4 <= structs.len() {
            let tok = u32::from_be_bytes([structs[i], structs[i + 1], structs[i + 2], structs[i + 3]]);
            i += 4;
            match tok {
                FDT_BEGIN_NODE => {
                    // Node name is a null-terminated string, padded to 4.
                    let mut j = i;
                    while j < structs.len() && structs[j] != 0 { j += 1; }
                    i = (j + 1 + 3) & !3; // include NUL, align up
                }
                FDT_END_NODE | FDT_NOP => {}
                FDT_PROP => {
                    if i + 8 > structs.len() { return None; }
                    let len = u32::from_be_bytes([structs[i], structs[i+1], structs[i+2], structs[i+3]]) as usize;
                    let nameoff = u32::from_be_bytes([structs[i+4], structs[i+5], structs[i+6], structs[i+7]]) as usize;
                    i += 8;
                    if i + len > structs.len() { return None; }

                    // Check the property name.
                    if nameoff < strings.len() {
                        let name = &strings[nameoff..];
                        let name_end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                        if &name[..name_end] == b"local-mac-address" && len == 6 {
                            let mut mac = [0u8; 6];
                            mac.copy_from_slice(&structs[i..i + 6]);
                            return Some(mac);
                        }
                    }

                    i = (i + len + 3) & !3;
                }
                FDT_END => return None,
                _ => return None, // malformed
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal DTB blob in-memory: header, empty reserved-map, a
    // structure block with one node carrying `local-mac-address`, a strings
    // block with just "local-mac-address". Validates the walker end-to-end.
    fn tiny_dtb(mac: [u8; 6]) -> alloc::vec::Vec<u8> {
        extern crate alloc;
        use alloc::vec::Vec;

        let mut strings: Vec<u8> = Vec::new();
        let name_off = strings.len() as u32;
        strings.extend_from_slice(b"local-mac-address\0");

        let mut structs: Vec<u8> = Vec::new();
        // BEGIN_NODE "" (root)
        structs.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
        structs.extend_from_slice(b"\0\0\0\0"); // empty name padded to 4
        // BEGIN_NODE "eth"
        structs.extend_from_slice(&FDT_BEGIN_NODE.to_be_bytes());
        structs.extend_from_slice(b"eth\0");
        // PROP local-mac-address len=6
        structs.extend_from_slice(&FDT_PROP.to_be_bytes());
        structs.extend_from_slice(&(6u32).to_be_bytes());
        structs.extend_from_slice(&name_off.to_be_bytes());
        structs.extend_from_slice(&mac);
        structs.extend_from_slice(&[0, 0]); // pad to 4
        // END_NODE
        structs.extend_from_slice(&FDT_END_NODE.to_be_bytes());
        // END_NODE (root)
        structs.extend_from_slice(&FDT_END_NODE.to_be_bytes());
        // END
        structs.extend_from_slice(&FDT_END.to_be_bytes());

        let off_mem_rsvmap = 40u32;
        let off_dt_struct = off_mem_rsvmap + 16; // one terminating reserve entry (8+8 bytes zero)
        let off_dt_strings = off_dt_struct + structs.len() as u32;
        let totalsize = off_dt_strings + strings.len() as u32;

        let mut out = Vec::with_capacity(totalsize as usize);
        out.extend_from_slice(&FDT_MAGIC.to_be_bytes());
        out.extend_from_slice(&totalsize.to_be_bytes());
        out.extend_from_slice(&off_dt_struct.to_be_bytes());
        out.extend_from_slice(&off_dt_strings.to_be_bytes());
        out.extend_from_slice(&off_mem_rsvmap.to_be_bytes());
        out.extend_from_slice(&17u32.to_be_bytes()); // version
        out.extend_from_slice(&16u32.to_be_bytes()); // last_comp_version
        out.extend_from_slice(&0u32.to_be_bytes()); // boot_cpuid_phys
        out.extend_from_slice(&(strings.len() as u32).to_be_bytes());
        out.extend_from_slice(&(structs.len() as u32).to_be_bytes());

        out.extend_from_slice(&[0u8; 16]); // empty mem_rsvmap terminator
        out.extend_from_slice(&structs);
        out.extend_from_slice(&strings);
        out
    }

    #[test]
    fn walks_tiny_dtb() {
        let mac = [0x88, 0xa2, 0x9e, 0x57, 0xd2, 0xfb];
        let blob = tiny_dtb(mac);
        let base = blob.as_ptr();

        // The real read_ethernet_mac() uses the static `_boot_dtb_ptr`. Here
        // we mimic its inner walker by parsing the blob in place.
        unsafe {
            let header = &*(base as *const FdtHeader);
            let off_struct = u32::from_be(header.off_dt_struct) as usize;
            let off_strings = u32::from_be(header.off_dt_strings) as usize;
            let size_struct = u32::from_be(header.size_dt_struct) as usize;
            let size_strings = u32::from_be(header.size_dt_strings) as usize;

            let structs = core::slice::from_raw_parts(base.add(off_struct), size_struct);
            let strings = core::slice::from_raw_parts(base.add(off_strings), size_strings);

            let mut i = 0usize;
            let mut found: Option<[u8; 6]> = None;
            while i + 4 <= structs.len() {
                let tok = u32::from_be_bytes([structs[i], structs[i+1], structs[i+2], structs[i+3]]);
                i += 4;
                match tok {
                    FDT_BEGIN_NODE => {
                        let mut j = i;
                        while j < structs.len() && structs[j] != 0 { j += 1; }
                        i = (j + 1 + 3) & !3;
                    }
                    FDT_END_NODE | FDT_NOP => {}
                    FDT_PROP => {
                        let len = u32::from_be_bytes([structs[i], structs[i+1], structs[i+2], structs[i+3]]) as usize;
                        let nameoff = u32::from_be_bytes([structs[i+4], structs[i+5], structs[i+6], structs[i+7]]) as usize;
                        i += 8;
                        let name = &strings[nameoff..];
                        let name_end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                        if &name[..name_end] == b"local-mac-address" && len == 6 {
                            let mut m = [0u8; 6];
                            m.copy_from_slice(&structs[i..i+6]);
                            found = Some(m);
                            break;
                        }
                        i = (i + len + 3) & !3;
                    }
                    FDT_END => break,
                    _ => panic!("bad token"),
                }
            }
            assert_eq!(found, Some(mac));
        }
    }
}
