//! The UEFI interfaces the stub calls, and nothing else: the system table,
//! the boot and runtime services it uses, the text console, the loaded-image
//! and file-system protocols that reach the ESP, and the RNG protocol.
//! Layouts and member order follow the UEFI 2.10 specification; a table's
//! members the stub never calls are kept as placeholders so the ones it does
//! call sit at the right offsets.

use core::ffi::c_void;

pub type Status = usize;
pub type Handle = *mut c_void;

pub const SUCCESS: Status = 0;
/// High bit set: an error.
pub const ERROR_BIT: Status = 1 << (usize::BITS - 1);
pub const INVALID_PARAMETER: Status = ERROR_BIT | 2;

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Guid(pub u32, pub u16, pub u16, pub [u8; 8]);

pub const ACPI_20_TABLE_GUID: Guid = Guid(
    0x8868_e871,
    0xe4f1,
    0x11d3,
    [0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
);
pub const LOADED_IMAGE_PROTOCOL_GUID: Guid = Guid(
    0x5b1b_31a1,
    0x9562,
    0x11d2,
    [0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
);
pub const SIMPLE_FILE_SYSTEM_PROTOCOL_GUID: Guid = Guid(
    0x964e_5b22,
    0x6459,
    0x11d2,
    [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
);
pub const RNG_PROTOCOL_GUID: Guid = Guid(
    0x3152_bca5,
    0xeade,
    0x433d,
    [0x86, 0x2e, 0xc0, 0x1c, 0xdc, 0x29, 0x1f, 0x44],
);

#[repr(C)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct SystemTable {
    pub hdr: TableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    pub console_in_handle: Handle,
    pub con_in: *mut c_void,
    pub console_out_handle: Handle,
    pub con_out: *mut SimpleTextOutput,
    pub standard_error_handle: Handle,
    pub std_err: *mut SimpleTextOutput,
    pub runtime_services: *mut RuntimeServices,
    pub boot_services: *mut BootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: *const ConfigurationTable,
}

#[repr(C)]
pub struct ConfigurationTable {
    pub vendor_guid: Guid,
    pub vendor_table: *mut c_void,
}

#[repr(C)]
pub struct SimpleTextOutput {
    pub reset: usize,
    pub output_string: unsafe extern "efiapi" fn(*mut SimpleTextOutput, *const u16) -> Status,
}

/// `EFI_ALLOCATE_TYPE`.
pub const ALLOCATE_ADDRESS: u32 = 2;
/// `EFI_MEMORY_TYPE` values the stub allocates as and reads back.
pub const LOADER_CODE: u32 = 1;
pub const LOADER_DATA: u32 = 2;
pub const BOOT_SERVICES_CODE: u32 = 3;
pub const BOOT_SERVICES_DATA: u32 = 4;
pub const RUNTIME_SERVICES_CODE: u32 = 5;
pub const RUNTIME_SERVICES_DATA: u32 = 6;
pub const CONVENTIONAL_MEMORY: u32 = 7;
pub const ACPI_RECLAIM_MEMORY: u32 = 9;
pub const ACPI_MEMORY_NVS: u32 = 10;
pub const MEMORY_MAPPED_IO: u32 = 11;
pub const MEMORY_MAPPED_IO_PORT_SPACE: u32 = 12;

#[repr(C)]
pub struct MemoryDescriptor {
    pub kind: u32,
    pub pad: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

#[repr(C)]
pub struct BootServices {
    pub hdr: TableHeader,
    pub raise_tpl: usize,
    pub restore_tpl: usize,
    pub allocate_pages: unsafe extern "efiapi" fn(u32, u32, usize, *mut u64) -> Status,
    pub free_pages: unsafe extern "efiapi" fn(u64, usize) -> Status,
    pub get_memory_map: unsafe extern "efiapi" fn(
        *mut usize,
        *mut MemoryDescriptor,
        *mut usize,
        *mut usize,
        *mut u32,
    ) -> Status,
    pub allocate_pool: unsafe extern "efiapi" fn(u32, usize, *mut *mut c_void) -> Status,
    pub free_pool: usize,
    pub create_event: usize,
    pub set_timer: usize,
    pub wait_for_event: usize,
    pub signal_event: usize,
    pub close_event: usize,
    pub check_event: usize,
    pub install_protocol_interface: usize,
    pub reinstall_protocol_interface: usize,
    pub uninstall_protocol_interface: usize,
    pub handle_protocol: unsafe extern "efiapi" fn(Handle, *const Guid, *mut *mut c_void) -> Status,
    pub reserved: usize,
    pub register_protocol_notify: usize,
    pub locate_handle: usize,
    pub locate_device_path: usize,
    pub install_configuration_table: usize,
    pub load_image: usize,
    pub start_image: usize,
    pub exit: usize,
    pub unload_image: usize,
    pub exit_boot_services: unsafe extern "efiapi" fn(Handle, usize) -> Status,
    pub get_next_monotonic_count: usize,
    pub stall: unsafe extern "efiapi" fn(usize) -> Status,
    pub set_watchdog_timer: unsafe extern "efiapi" fn(usize, u64, usize, *const u16) -> Status,
    pub connect_controller: usize,
    pub disconnect_controller: usize,
    pub open_protocol: usize,
    pub close_protocol: usize,
    pub open_protocol_information: usize,
    pub protocols_per_handle: usize,
    pub locate_handle_buffer: usize,
    pub locate_protocol:
        unsafe extern "efiapi" fn(*const Guid, *mut c_void, *mut *mut c_void) -> Status,
}

#[repr(C)]
#[derive(Default)]
pub struct Time {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub pad1: u8,
    pub nanosecond: u32,
    pub time_zone: i16,
    pub daylight: u8,
    pub pad2: u8,
}

/// `EFI_RESET_TYPE::EfiResetShutdown`.
pub const RESET_SHUTDOWN: u32 = 2;

#[repr(C)]
pub struct RuntimeServices {
    pub hdr: TableHeader,
    pub get_time: unsafe extern "efiapi" fn(*mut Time, *mut c_void) -> Status,
    pub set_time: usize,
    pub get_wakeup_time: usize,
    pub set_wakeup_time: usize,
    pub set_virtual_address_map: usize,
    pub convert_pointer: usize,
    pub get_variable: usize,
    pub get_next_variable_name: usize,
    pub set_variable: usize,
    pub get_next_high_monotonic_count: usize,
    pub reset_system: unsafe extern "efiapi" fn(u32, Status, usize, *const c_void) -> !,
}

#[repr(C)]
pub struct LoadedImage {
    pub revision: u32,
    pub parent_handle: Handle,
    pub system_table: *mut SystemTable,
    pub device_handle: Handle,
    pub file_path: *mut c_void,
    pub reserved: *mut c_void,
    pub load_options_size: u32,
    pub load_options: *mut c_void,
    pub image_base: *mut c_void,
    pub image_size: u64,
    pub image_code_type: u32,
    pub image_data_type: u32,
    pub unload: usize,
}

#[repr(C)]
pub struct SimpleFileSystem {
    pub revision: u64,
    pub open_volume: unsafe extern "efiapi" fn(*mut SimpleFileSystem, *mut *mut File) -> Status,
}

/// `EFI_FILE_MODE_READ`.
pub const FILE_MODE_READ: u64 = 0x1;

#[repr(C)]
pub struct File {
    pub revision: u64,
    pub open: unsafe extern "efiapi" fn(*mut File, *mut *mut File, *const u16, u64, u64) -> Status,
    pub close: unsafe extern "efiapi" fn(*mut File) -> Status,
    pub delete: usize,
    pub read: unsafe extern "efiapi" fn(*mut File, *mut usize, *mut c_void) -> Status,
    pub write: usize,
    pub get_position: unsafe extern "efiapi" fn(*mut File, *mut u64) -> Status,
    pub set_position: unsafe extern "efiapi" fn(*mut File, u64) -> Status,
}

#[repr(C)]
pub struct RngProtocol {
    pub get_info: usize,
    pub get_rng: unsafe extern "efiapi" fn(*mut RngProtocol, *const Guid, usize, *mut u8) -> Status,
}
