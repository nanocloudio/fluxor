//! Module Table Generation and Packing
//!
//! Creates the flash-resident module table from .fmod files.
//! Also provides ELF parsing to create .fmod files from compiled objects.

use std::path::Path;

use crate::error::{Error, Result};
pub use crate::hash::fnv1a_hash;
use crate::manifest::{self, Manifest};

/// Module table magic: "FXMT" (Fluxor Module Table)
pub const MODULE_TABLE_MAGIC: u32 = 0x544D5846;

/// Module magic: "FXMD" (Fluxor Module)
pub const MODULE_MAGIC: u32 = 0x444D5846;

/// Current table version
pub const TABLE_VERSION: u8 = 1;

/// Maximum modules in table
pub const MAX_TABLE_MODULES: usize = 16;

/// Module table header (16 bytes)
pub const TABLE_HEADER_SIZE: usize = 16;

/// Module entry size (16 bytes)
pub const ENTRY_SIZE: usize = 16;

/// Information about a module to embed
#[derive(Debug)]
pub struct ModuleInfo {
    pub name: String,
    pub name_hash: u32,
    pub module_type: u8,
    /// Module can safely consume from mailbox channels (header flags bit 0)
    pub mailbox_safe: bool,
    /// Module uses buffer_acquire_inplace to modify buffer (header flags bit 1)
    pub in_place_writer: bool,
    /// Module exports module_drain for live reconfigure (header flags bit 3).
    /// Used by `fluxor info` and `fluxor diff` for transition plan display.
    #[allow(dead_code)]
    pub drain_capable: bool,
    /// Raw param schema bytes (if module uses define_params! macro)
    pub schema: Option<Vec<u8>>,
    /// Module manifest (always present in ABI v2)
    pub manifest: Manifest,
    pub data: Vec<u8>,
}

impl ModuleInfo {
    /// Load module from .fmod file
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;

        if data.len() < 68 {
            return Err(Error::Module(format!(
                "Module file too small: {} bytes",
                data.len()
            )));
        }

        // Verify magic
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != MODULE_MAGIC {
            return Err(Error::Module(format!(
                "Invalid module magic: 0x{:08x}",
                magic
            )));
        }

        // Extract name from header (offset 28, 32 bytes, null-terminated)
        // Header layout: magic(4) + version(1) + abi(1) + type(1) + flags(1) +
        //                code_size(4) + data_size(4) + bss_size(4) + init_offset(4) +
        //                export_count(2) + export_offset(2) + name[32] + reserved[8]
        let name_bytes = &data[28..60];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(32);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

        // Module type at offset 6
        let module_type = data[6];

        // Capability flags at offset 60 (reserved[0] in header)
        let flags_byte = if data.len() > 60 { data[60] } else { 0 };
        let mailbox_safe = (flags_byte & 0x01) != 0;
        let in_place_writer = (flags_byte & 0x02) != 0;
        let drain_capable = (flags_byte & 0x08) != 0;

        // ABI v2 reserved layout:
        //   byte 0 (offset 60): flags (bit 0: mailbox_safe, bit 1: in_place_writer)
        //   byte 1 (offset 61): step_period_ms
        //   bytes 2-3 (offset 62-63): schema_size (u16 LE)
        //   bytes 4-5 (offset 64-65): manifest_size (u16 LE)
        //   bytes 6-7 (offset 66-67): required_caps (u16 LE)
        let schema_size = if data.len() > 63 {
            u16::from_le_bytes([data[62], data[63]]) as usize
        } else {
            0
        };
        let manifest_size = if data.len() > 65 {
            u16::from_le_bytes([data[64], data[65]]) as usize
        } else {
            0
        };

        // Compute section offsets from header fields
        let code_size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let data_section_size = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let export_count = u16::from_le_bytes([data[24], data[25]]) as usize;
        let export_table_size = export_count * 8;
        let schema_offset = MODULE_HEADER_SIZE + code_size + data_section_size + export_table_size;

        let schema = if schema_size >= 4 && schema_offset + schema_size <= data.len() {
            Some(data[schema_offset..schema_offset + schema_size].to_vec())
        } else {
            None
        };

        // Read manifest (follows schema)
        let manifest_offset = schema_offset + schema_size;
        let manifest = if manifest_size > 0 && manifest_offset + manifest_size <= data.len() {
            Manifest::from_bytes(&data[manifest_offset..manifest_offset + manifest_size])?
        } else {
            Manifest::default()
        };

        let name_hash = fnv1a_hash(name.as_bytes());

        Ok(Self {
            name,
            name_hash,
            module_type,
            mailbox_safe,
            in_place_writer,
            drain_capable,
            schema,
            manifest,
            data,
        })
    }
}

/// Build module table binary from list of modules
pub fn build_module_table(modules: &[ModuleInfo]) -> Result<Vec<u8>> {
    if modules.len() > MAX_TABLE_MODULES {
        return Err(Error::Module(format!(
            "Too many modules: {} > {}",
            modules.len(),
            MAX_TABLE_MODULES
        )));
    }

    // Calculate total size (with 4-byte alignment padding between .fmod entries)
    // ARM Thumb code requires 2-byte aligned addresses; we use 4-byte for safety.
    // Each .fmod's code_base = fmod_start + 68 (header), so if fmod_start is
    // 4-byte aligned, code_base is also 4-byte aligned (68 = 0x44).
    let entries_size = modules.len() * ENTRY_SIZE;
    let mut data_size: usize = 0;
    let mut offsets = Vec::new();
    let mut data_offset = TABLE_HEADER_SIZE + entries_size;

    for module in modules {
        // Align code start (offset + 68 bytes header) to page boundary for aarch64 ADRP.
        // The .fmod header is 68 bytes, then code follows. ADRP needs code at page boundary.
        let code_start = data_offset + 68;
        let aligned_code = (code_start + 4095) & !4095; // round up to page
        let padding = aligned_code - 68 - data_offset;
        data_offset += padding;
        data_size += padding;

        offsets.push(data_offset);
        data_offset += module.data.len();
        data_size += module.data.len();
    }

    let total_size = TABLE_HEADER_SIZE + entries_size + data_size;
    let mut result = Vec::with_capacity(total_size);

    // Header (16 bytes)
    result.extend_from_slice(&MODULE_TABLE_MAGIC.to_le_bytes());
    result.push(TABLE_VERSION);
    result.push(modules.len() as u8);
    result.extend_from_slice(&(total_size as u16).to_le_bytes());
    result.extend_from_slice(&[0u8; 8]); // reserved

    // Entries (16 bytes each)
    for (i, module) in modules.iter().enumerate() {
        result.extend_from_slice(&module.name_hash.to_le_bytes());
        result.extend_from_slice(&(offsets[i] as u32).to_le_bytes());
        result.extend_from_slice(&(module.data.len() as u32).to_le_bytes());
        result.push(module.module_type);
        result.push(0); // flags
        result.extend_from_slice(&[0u8; 2]); // reserved
    }

    // Module data (with alignment padding — code must start at page boundary)
    for (_i, module) in modules.iter().enumerate() {
        // Pad so that offset + 68 (header size) is page-aligned
        while (result.len() + 68) % 4096 != 0 {
            result.push(0);
        }
        result.extend_from_slice(&module.data);
    }

    assert_eq!(result.len(), total_size);

    Ok(result)
}

/// Parse modules from config YAML/JSON
///
/// Modules can be specified as:
///   - Just a name: `- format` (looks in modules_dir)
///   - Object with name: `- name: format`
pub fn parse_modules_from_config(
    config: &serde_json::Value,
    modules_dir: &Path,
) -> Result<Vec<ModuleInfo>> {
    let mut modules = Vec::new();

    if let Some(modules_array) = config["modules"].as_array() {
        // Track which module types we've already loaded (avoid duplicates)
        let mut loaded_types = std::collections::HashSet::new();

        for module_entry in modules_array {
            // Get module name - either string directly or from "name" field
            let module_name = if let Some(name) = module_entry.as_str() {
                // Simple form: `- format`
                name.to_string()
            } else if let Some(name) = module_entry["name"].as_str() {
                // Object form: `- name: format`
                name.to_string()
            } else {
                return Err(Error::Module(
                    "Module entry must be a name string or object with 'name' field".into(),
                ));
            };

            // Use "type" field for .fmod lookup if present, otherwise use "name"
            let module_type = module_entry["type"].as_str().unwrap_or(&module_name);

            // Skip if we've already loaded this module type
            if !loaded_types.insert(module_type.to_string()) {
                continue;
            }

            // Build path: modules_dir/<type>.fmod
            let module_path = modules_dir.join(format!("{}.fmod", module_type));

            if !module_path.exists() {
                return Err(Error::Module(format!(
                    "Module '{}' (type '{}') not found at: {}\nRun 'make pack-modules' to build modules.",
                    module_name,
                    module_type,
                    module_path.display()
                )));
            }

            let module_info = ModuleInfo::from_file(&module_path)?;
            modules.push(module_info);
        }
    } else if let Some(modules_map) = config["modules"].as_object() {
        // Track which module types we've already loaded (avoid duplicates)
        let mut loaded_types = std::collections::HashSet::new();

        for (instance_name, module_def) in modules_map {
            // Use the "type" field to find the .fmod file, falling back to instance name
            let module_type = module_def["type"]
                .as_str()
                .unwrap_or(instance_name.as_str());

            // Skip if we've already loaded this module type
            if !loaded_types.insert(module_type.to_string()) {
                continue;
            }

            let module_path = modules_dir.join(format!("{}.fmod", module_type));

            if !module_path.exists() {
                return Err(Error::Module(format!(
                    "Module '{}' (type '{}') not found at: {}\nRun 'make pack-modules' to build modules.",
                    instance_name,
                    module_type,
                    module_path.display()
                )));
            }

            let module_info = ModuleInfo::from_file(&module_path)?;
            modules.push(module_info);
        }
    }

    Ok(modules)
}

/// Resolve a module .fmod file by searching primary dir, then extra dirs in order.
fn resolve_fmod(module_type: &str, primary_dir: &Path, extra_dirs: &[&Path]) -> Option<std::path::PathBuf> {
    let filename = format!("{}.fmod", module_type);
    let p = primary_dir.join(&filename);
    if p.exists() {
        return Some(p);
    }
    for dir in extra_dirs {
        let p = dir.join(&filename);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Like `parse_modules_from_config` but searches multiple directories.
pub fn parse_modules_from_config_multi(
    config: &serde_json::Value,
    modules_dir: &Path,
    extra_dirs: &[&Path],
) -> Result<Vec<ModuleInfo>> {
    let mut modules = Vec::new();

    if let Some(modules_array) = config["modules"].as_array() {
        let mut loaded_types = std::collections::HashSet::new();

        for module_entry in modules_array {
            let module_name = if let Some(name) = module_entry.as_str() {
                name.to_string()
            } else if let Some(name) = module_entry["name"].as_str() {
                name.to_string()
            } else {
                return Err(Error::Module(
                    "Module entry must be a name string or object with 'name' field".into(),
                ));
            };

            let module_type = module_entry["type"].as_str().unwrap_or(&module_name);

            if !loaded_types.insert(module_type.to_string()) {
                continue;
            }

            let module_path = match resolve_fmod(module_type, modules_dir, extra_dirs) {
                Some(p) => p,
                None => {
                    let searched: Vec<String> = std::iter::once(modules_dir)
                        .chain(extra_dirs.iter().copied())
                        .map(|d| d.display().to_string())
                        .collect();
                    return Err(Error::Module(format!(
                        "Module '{}' (type '{}') not found in: {}\nRun 'make modules' to build modules.",
                        module_name,
                        module_type,
                        searched.join(", "),
                    )));
                }
            };

            let module_info = ModuleInfo::from_file(&module_path)?;
            modules.push(module_info);
        }
    } else if let Some(modules_map) = config["modules"].as_object() {
        let mut loaded_types = std::collections::HashSet::new();

        for (instance_name, module_def) in modules_map {
            let module_type = module_def["type"]
                .as_str()
                .unwrap_or(instance_name.as_str());

            if !loaded_types.insert(module_type.to_string()) {
                continue;
            }

            let module_path = match resolve_fmod(module_type, modules_dir, extra_dirs) {
                Some(p) => p,
                None => {
                    let searched: Vec<String> = std::iter::once(modules_dir)
                        .chain(extra_dirs.iter().copied())
                        .map(|d| d.display().to_string())
                        .collect();
                    return Err(Error::Module(format!(
                        "Module '{}' (type '{}') not found in: {}\nRun 'make modules' to build modules.",
                        instance_name,
                        module_type,
                        searched.join(", "),
                    )));
                }
            };

            let module_info = ModuleInfo::from_file(&module_path)?;
            modules.push(module_info);
        }
    }

    Ok(modules)
}

// =============================================================================
// ELF Parsing and Module Packing
// =============================================================================

/// Module header size (must match firmware's ModuleHeader::SIZE)
pub const MODULE_HEADER_SIZE: usize = 68;

///// Must match kernel's MODULE_ABI_VERSION in src/kernel/loader.rs
pub const ABI_VERSION: u8 = 1;

/// Result of packing a module
#[derive(Debug)]
pub struct PackResult {
    pub name: String,
    pub code_size: usize,
    pub data_size: usize,
    pub bss_size: usize,
    pub init_offset: u32,
    pub exports: Vec<(String, u32, u32)>, // (name, offset, hash)
    pub total_size: usize,
}

/// ELF section info
#[derive(Debug, Default)]
struct ElfSection {
    name: String,
    #[allow(dead_code)]
    sh_type: u32,
    data: Vec<u8>,
    size: usize,
}

/// ELF symbol info
#[derive(Debug)]
struct ElfSymbol {
    name: String,
    value: u32,
    #[allow(dead_code)]
    size: u32,
    bind: u8,
    sym_type: u8,
    #[allow(dead_code)]
    section_idx: u16,
}

/// Parse ELF file (32 or 64-bit) and extract sections and symbols
fn parse_elf(data: &[u8]) -> Result<(Vec<ElfSection>, Vec<ElfSymbol>)> {
    // Verify ELF magic
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return Err(Error::Module("Not a valid ELF file".into()));
    }

    let elf64 = data[4] == 2;
    if data[4] != 1 && data[4] != 2 {
        return Err(Error::Module("Unknown ELF class (expected 32 or 64)".into()));
    }

    // Little-endian check
    if data[5] != 1 {
        return Err(Error::Module("Only little-endian ELF is supported".into()));
    }

    // Read ELF header fields — offsets differ between ELF32 and ELF64
    let (e_shoff, e_shentsize, e_shnum, e_shstrndx) = if elf64 {
        let off = u64::from_le_bytes(data[40..48].try_into().unwrap()) as usize;
        let ent = u16::from_le_bytes([data[58], data[59]]) as usize;
        let num = u16::from_le_bytes([data[60], data[61]]) as usize;
        let str = u16::from_le_bytes([data[62], data[63]]) as usize;
        (off, ent, num, str)
    } else {
        let off = u32::from_le_bytes([data[32], data[33], data[34], data[35]]) as usize;
        let ent = u16::from_le_bytes([data[46], data[47]]) as usize;
        let num = u16::from_le_bytes([data[48], data[49]]) as usize;
        let str = u16::from_le_bytes([data[50], data[51]]) as usize;
        (off, ent, num, str)
    };

    if e_shoff == 0 || e_shnum == 0 {
        return Err(Error::Module("ELF file has no section headers".into()));
    }

    // Helper: read section header fields (offset and size differ for ELF32/64)
    let sh_offset_size = |sh_off: usize| -> (usize, usize) {
        if elf64 {
            let off = u64::from_le_bytes(data[sh_off+24..sh_off+32].try_into().unwrap()) as usize;
            let sz = u64::from_le_bytes(data[sh_off+32..sh_off+40].try_into().unwrap()) as usize;
            (off, sz)
        } else {
            let off = u32::from_le_bytes([data[sh_off+16], data[sh_off+17], data[sh_off+18], data[sh_off+19]]) as usize;
            let sz = u32::from_le_bytes([data[sh_off+20], data[sh_off+21], data[sh_off+22], data[sh_off+23]]) as usize;
            (off, sz)
        }
    };

    // First pass: find section header string table
    let shstrtab_hdr_off = e_shoff + e_shstrndx * e_shentsize;
    let (shstrtab_off, shstrtab_size) = sh_offset_size(shstrtab_hdr_off);
    let shstrtab = &data[shstrtab_off..shstrtab_off + shstrtab_size];

    // Second pass: read all sections
    let mut sections = Vec::new();
    let mut symtab_idx = None;
    let mut strtab_idx = None;

    for i in 0..e_shnum {
        let sh_off = e_shoff + i * e_shentsize;
        let sh_name_idx = u32::from_le_bytes([data[sh_off], data[sh_off + 1],
                                              data[sh_off + 2], data[sh_off + 3]]) as usize;
        let sh_type = u32::from_le_bytes([data[sh_off + 4], data[sh_off + 5],
                                          data[sh_off + 6], data[sh_off + 7]]);
        let (sh_offset, sh_size) = sh_offset_size(sh_off);

        // Get section name
        let name_end = shstrtab[sh_name_idx..].iter().position(|&b| b == 0).unwrap_or(0);
        let name = String::from_utf8_lossy(&shstrtab[sh_name_idx..sh_name_idx + name_end]).to_string();

        // Track symtab and strtab indices
        if sh_type == 2 {
            // SHT_SYMTAB
            symtab_idx = Some(sections.len());
        }
        if name == ".strtab" {
            strtab_idx = Some(sections.len());
        }

        // Extract section data (skip NOBITS sections like .bss)
        let section_data = if sh_type != 8 && sh_size > 0 && sh_offset + sh_size <= data.len() {
            data[sh_offset..sh_offset + sh_size].to_vec()
        } else {
            Vec::new()
        };

        sections.push(ElfSection {
            name,
            sh_type,
            data: section_data,
            size: sh_size,
        });
    }

    // Parse symbols if we have both symtab and strtab
    let mut symbols = Vec::new();
    if let (Some(symtab_i), Some(strtab_i)) = (symtab_idx, strtab_idx) {
        let symtab = &sections[symtab_i].data;
        let strtab = &sections[strtab_i].data;

        // ELF32 symbol: 16 bytes. ELF64 symbol: 24 bytes.
        let sym_size = if elf64 { 24 } else { 16 };
        for i in (0..symtab.len()).step_by(sym_size) {
            if i + sym_size > symtab.len() {
                break;
            }

            let (st_name, st_value, st_size, st_info, st_shndx) = if elf64 {
                // ELF64: name(4), info(1), other(1), shndx(2), value(8), size(8)
                let name = u32::from_le_bytes(symtab[i..i+4].try_into().unwrap()) as usize;
                let info = symtab[i + 4];
                let shndx = u16::from_le_bytes([symtab[i + 6], symtab[i + 7]]);
                let value = u64::from_le_bytes(symtab[i+8..i+16].try_into().unwrap()) as u32;
                let size = u64::from_le_bytes(symtab[i+16..i+24].try_into().unwrap()) as u32;
                (name, value, size, info, shndx)
            } else {
                // ELF32: name(4), value(4), size(4), info(1), other(1), shndx(2)
                let name = u32::from_le_bytes(symtab[i..i+4].try_into().unwrap()) as usize;
                let value = u32::from_le_bytes(symtab[i+4..i+8].try_into().unwrap());
                let size = u32::from_le_bytes(symtab[i+8..i+12].try_into().unwrap());
                let info = symtab[i + 12];
                let shndx = u16::from_le_bytes([symtab[i + 14], symtab[i + 15]]);
                (name, value, size, info, shndx)
            };

            // Get symbol name
            if st_name < strtab.len() {
                let name_end = strtab[st_name..].iter().position(|&b| b == 0).unwrap_or(0);
                let name = String::from_utf8_lossy(&strtab[st_name..st_name + name_end]).to_string();

                symbols.push(ElfSymbol {
                    name,
                    value: st_value,
                    size: st_size,
                    bind: st_info >> 4,
                    sym_type: st_info & 0xf,
                    section_idx: st_shndx,
                });
            }
        }
    }

    Ok((sections, symbols))
}

/// Find a section by name
fn find_section<'a>(sections: &'a [ElfSection], name: &str) -> Option<&'a ElfSection> {
    sections.iter().find(|s| s.name == name)
}

/// Pack ELF object into .fmod format (ABI v2 with manifest)
pub fn pack_fmod(
    input: &Path,
    output: &Path,
    name: &str,
    module_type: u8,
    manifest_path: Option<&Path>,
) -> Result<PackResult> {
    let elf_data = std::fs::read(input)?;
    let (sections, symbols) = parse_elf(&elf_data)?;

    // Extract section data
    let text_data = find_section(&sections, ".text").map(|s| &s.data[..]).unwrap_or(&[]);
    let rodata_data = find_section(&sections, ".rodata").map(|s| &s.data[..]).unwrap_or(&[]);
    let data_data = find_section(&sections, ".data").map(|s| &s.data[..]).unwrap_or(&[]);
    let bss_size = find_section(&sections, ".bss").map(|s| s.size).unwrap_or(0);

    // Extract param schema (optional — only present if module uses define_params!)
    let schema_data = find_section(&sections, ".param_schema")
        .map(|s| {
            // Trim trailing zeros from the fixed-size SCHEMA_MAX buffer
            let data = &s.data[..];
            if data.len() >= 4 && data[0] == 0x53 && data[1] == 0x50 {
                let count = data[3] as usize;
                if count > 0 {
                    // Find actual end by scanning past all entries
                    let mut pos = 4usize;
                    for _ in 0..count {
                        if pos + 6 >= data.len() { break; }
                        pos += 6; // tag + type + default(4)
                        let name_len = data[pos] as usize;
                        pos += 1 + name_len;
                        if pos >= data.len() { break; }
                        let enum_count = data[pos] as usize;
                        pos += 1;
                        for _ in 0..enum_count {
                            if pos >= data.len() { break; }
                            pos += 1; // val
                            if pos >= data.len() { break; }
                            let ename_len = data[pos] as usize;
                            pos += 1 + ename_len;
                        }
                    }
                    &data[..pos.min(data.len())]
                } else {
                    &data[..4] // header only
                }
            } else {
                &[] as &[u8]
            }
        })
        .unwrap_or(&[]);

    // Combine code sections (text + rodata)
    let mut code_data = Vec::with_capacity(text_data.len() + rodata_data.len());
    code_data.extend_from_slice(text_data);
    code_data.extend_from_slice(rodata_data);

    let code_size = code_data.len();
    let data_size = data_data.len();

    // Find module_init offset
    let init_offset = symbols
        .iter()
        .find(|s| s.name == "module_init")
        .map(|s| s.value)
        .unwrap_or(0);

    // Build export table - filter to global functions
    let export_names = [
        // Core module interface
        "module_state_size",
        "module_init",
        "module_new",
        "module_step",
        // format: conversion helpers
        "process_audio_16",
        "process_audio_bytes",
        "process_audio",
        "stereo_to_mono",
        "mono_to_stereo",
        "convert_16to8",
        "convert_stereo16_to_mono8",
        // g711_codec
        "encode_ulaw",
        "decode_ulaw",
        "encode_alaw",
        "decode_alaw",
        // wav_parser
        "parse_wav_header",
        "get_wav_format",
        // rtp_protocol
        "process_rtp",
        "create_rtp_packet",
        // button (GPIO + debounce + gesture detection)
        // oscillator
        "generate_tone",
        // audio_mixer
        "mix_audio",
        // envelope
        "apply_envelope",
        // sip_parser
        "parse_sip",
        // http_parser
        "parse_http",
        // led_pattern
        "render_pattern",
        // debug (digest + logger)
        "debug_step",
        // sd (SD card block device)
        "sd_init",
        "sd_deinit",
        "sd_read_blocks",
        "sd_get_sector_count",
        "sd_get_card_type",
        "sd_is_initialized",
        "sd_step",
        "sd_configure",
        // input_bootsel (button input with gesture detection)
        "bootsel_poll",
        "bootsel_set_bindings",
        "bootsel_set_timing",
        "bootsel_get_timing",
        "bootsel_get_state",
        "bootsel_get_hold_duration",
        // i2s (I2S audio output via PIO)
        "i2s_stream_init",
        "i2s_stream_deinit",
        "i2s_stream_write",
        "i2s_stream_write_u8_mono",
        "i2s_stream_get_handle",
        "i2s_stream_get_sample_rate",
        "i2s_get_program",
        "i2s_get_program_len",
        "i2s_calc_clock_div",
        "i2s_get_config",
        "i2s_pack_stereo",
        "i2s_pack_mono",
        "i2s_u8_to_i16",
        "i2s_convert_u8_mono",
        "i2s_convert_i16_stereo",
        "i2s_convert_i16_mono",
        "i2s_apply_gain",
        "i2s_mix",
        // channel hints (dynamic buffer sizing)
        "module_channel_hints",
        // heap arena size (per-module heap allocation)
        "module_arena_size",
        // buffer capability markers
        "module_in_place_safe",
        "module_mailbox_safe",
        // deferred ready (infrastructure modules that need init time)
        "module_deferred_ready",
        // drain support (graceful shutdown for live reconfigure)
        "module_drain",
        // ISR tier 2 module exports
        "module_isr_init",
        "module_isr_entry",
    ];

    let mut exports: Vec<(String, u32, u32)> = Vec::new();
    for sym in &symbols {
        // STB_GLOBAL = 1, STT_FUNC = 2
        if sym.bind == 1 && sym.sym_type == 2 && export_names.contains(&sym.name.as_str()) {
            let hash = fnv1a_hash(sym.name.as_bytes());
            exports.push((sym.name.clone(), sym.value, hash));
        }
    }

    // Load or create manifest
    let mut module_manifest = if let Some(mp) = manifest_path {
        Manifest::from_toml(mp)?
    } else {
        // Auto-detect: look for manifest.toml next to the input ELF
        let auto_path = input.parent().unwrap_or(Path::new(".")).join("manifest.toml");
        if auto_path.exists() {
            Manifest::from_toml(&auto_path)?
        } else {
            Manifest::default()
        }
    };

    // Compute integrity hash over code + data sections
    let mut combined_code = Vec::with_capacity(text_data.len() + rodata_data.len());
    combined_code.extend_from_slice(text_data);
    combined_code.extend_from_slice(rodata_data);
    module_manifest.integrity_hash = Some(manifest::compute_integrity(&combined_code, data_data));

    let manifest_bytes = module_manifest.to_bytes();

    // Calculate sizes
    let export_table_size = exports.len() * 8; // 4 bytes hash + 4 bytes offset
    // Export table is stored immediately after code + data in the file.
    // BSS is not stored, so it must not be included here.
    let mem_export_offset = code_size + data_size;
    let schema_size = schema_data.len();
    let manifest_size = manifest_bytes.len();
    let total_size = MODULE_HEADER_SIZE + code_size + data_size + export_table_size + schema_size + manifest_size;

    // Build header (68 bytes)
    let mut header = Vec::with_capacity(MODULE_HEADER_SIZE);

    // Magic (4 bytes)
    header.extend_from_slice(&MODULE_MAGIC.to_le_bytes());
    // Version, ABI, Type, Reserved (4 bytes)
    header.push(TABLE_VERSION);
    header.push(ABI_VERSION);
    header.push(module_type);
    header.push(0);
    // Code size (4 bytes)
    header.extend_from_slice(&(code_size as u32).to_le_bytes());
    // Data size (4 bytes)
    header.extend_from_slice(&(data_size as u32).to_le_bytes());
    // BSS size (4 bytes)
    header.extend_from_slice(&(bss_size as u32).to_le_bytes());
    // Init offset (4 bytes)
    header.extend_from_slice(&init_offset.to_le_bytes());
    // Export count (2 bytes) + export offset (2 bytes)
    // NOTE: export_offset is u16 in the header — overflows for modules > 64KB.
    // The kernel loader computes the offset from code_size + data_size instead.
    // Store 0xFFFF as sentinel when it overflows.
    let export_offset_u16 = if mem_export_offset > u16::MAX as usize {
        0xFFFFu16
    } else {
        mem_export_offset as u16
    };
    header.extend_from_slice(&(exports.len() as u16).to_le_bytes());
    header.extend_from_slice(&export_offset_u16.to_le_bytes());
    // Name (32 bytes, null-terminated)
    let mut name_bytes = [0u8; 32];
    let name_slice = name.as_bytes();
    let copy_len = name_slice.len().min(31);
    name_bytes[..copy_len].copy_from_slice(&name_slice[..copy_len]);
    header.extend_from_slice(&name_bytes);
    // Reserved (8 bytes) — ABI v2 layout:
    //   byte 0: flags (bit 0: mailbox_safe, bit 1: in_place_writer)
    //   byte 1: step_period_ms (0 = every tick; set by config, not pack)
    //   bytes 2-3: schema_size (u16 LE)
    //   bytes 4-5: manifest_size (u16 LE)
    //   bytes 6-7: required_caps (u16 LE)
    let has_in_place_safe = symbols.iter().any(|s| s.bind == 1 && s.name == "module_in_place_safe");
    let has_mailbox_safe = symbols.iter().any(|s| s.bind == 1 && s.name == "module_mailbox_safe");
    let has_deferred_ready = symbols.iter().any(|s| s.bind == 1 && s.name == "module_deferred_ready");
    let has_drain = symbols.iter().any(|s| s.bind == 1 && s.name == "module_drain");
    let mut reserved = [0u8; 8];
    if has_in_place_safe {
        reserved[0] |= 0x03; // mailbox_safe (bit 0) + in_place_writer (bit 1)
    }
    if has_mailbox_safe {
        reserved[0] |= 0x01; // mailbox_safe only (bit 0)
    }
    if has_deferred_ready {
        reserved[0] |= 0x04; // deferred_ready (bit 2)
    }
    if has_drain {
        reserved[0] |= 0x08; // drain_capable (bit 3)
    }
    let has_isr_entry = symbols.iter().any(|s| s.bind == 1 && s.name == "module_isr_entry");
    if has_isr_entry {
        reserved[0] |= 0x10; // isr_module (bit 4)
    }
    reserved[2..4].copy_from_slice(&(schema_size as u16).to_le_bytes());
    reserved[4..6].copy_from_slice(&(manifest_size as u16).to_le_bytes());
    reserved[6..8].copy_from_slice(&module_manifest.required_caps_mask().to_le_bytes());
    header.extend_from_slice(&reserved);

    assert_eq!(header.len(), MODULE_HEADER_SIZE);

    // Build export table
    let mut export_table = Vec::with_capacity(export_table_size);
    for (_, offset, hash) in &exports {
        export_table.extend_from_slice(&hash.to_le_bytes());
        export_table.extend_from_slice(&offset.to_le_bytes());
    }

    // Write output file: header + code + data + exports + schema + manifest
    let mut output_data = Vec::with_capacity(total_size);
    output_data.extend_from_slice(&header);
    output_data.extend_from_slice(&code_data);
    output_data.extend_from_slice(data_data);
    output_data.extend_from_slice(&export_table);
    output_data.extend_from_slice(schema_data);
    output_data.extend_from_slice(&manifest_bytes);

    std::fs::write(output, &output_data)?;

    Ok(PackResult {
        name: name.to_string(),
        code_size,
        data_size,
        bss_size,
        init_offset,
        exports,
        total_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv1a_hash() {
        assert_eq!(fnv1a_hash(b"format"), 0xb99d8552);
        assert_eq!(fnv1a_hash(b"set_gain"), 0xe5587e57);
    }

    #[test]
    fn test_empty_table() {
        let table = build_module_table(&[]).unwrap();
        assert_eq!(table.len(), TABLE_HEADER_SIZE);
        assert_eq!(
            u32::from_le_bytes([table[0], table[1], table[2], table[3]]),
            MODULE_TABLE_MAGIC
        );
    }
}
