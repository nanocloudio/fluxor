// @generated
// By `fluxor abi-regen` from `registry.toml`. Edit that file and
// regenerate; never edit this one.
//
// Scalars and `match` lookups only: nothing here places an address in
// a module's `.rodata`.

/// Bumped by hand when a meaning changes without a number changing.
pub const SEMANTIC_EPOCH: u32 = 1;
/// Contract ids are below this: the `required_caps` width.
pub const MAX_CONTRACTS: usize = 64;
/// ORed onto an opcode: dispatch to the provider below the caller.
pub const CHAIN_NEXT: u32 = 0x10000;
/// Contract ids the registry assigns.
pub const CONTRACTS_ASSIGNED: usize = 41;

/// Manifest permission bits (`permissions = [..]`).
pub mod permission {
    /// Graph slot commit, boot counter, FMP routing.
    pub const RECONFIGURE: u16 = 1 << 0;
    /// Flash ERASE and PROGRAM, bounded to declared sectors.
    pub const FLASH_RAW: u16 = 1 << 1;
    /// MMIO, NIC ring create, raw peripheral register bridges, workload spawn.
    pub const PLATFORM_RAW: u16 = 1 << 2;
    /// Fault monitor BIND / WAIT / ACK / REPORT / RAISE, step histograms.
    pub const MONITOR: u16 = 1 << 3;
    /// Cross-domain / cross-core dispatch.
    pub const BRIDGE: u16 = 1 << 4;
    /// Kernel-mediated PCIe device binding (bind/config/BAR/MSI/info on a validated device handle), distinct from raw MMIO/DMA (`platform_raw`).
    pub const PCIE_DEVICE: u16 = 1 << 5;
    /// DMA-buffer allocation from the kernel's bounded DMA arena and cache maintenance on those buffers; narrower than raw register access (`platform_raw` still gates `MMIO_READ32`/`MMIO_WRITE32`).
    pub const DMA: u16 = 1 << 6;
    /// Read-only telemetry-ring drain (`TLM_SUBSCRIBE`/`DRAIN`/`STATS`); deliberately not `monitor`, which also grants `FAULT_RAISE`.
    pub const OBSERVE: u16 = 1 << 7;
    /// Kernel-mediated USB host binding on a validated controller handle; distinct from `platform_raw`, which would hand a USB driver the whole address space.
    pub const USB_HOST: u16 = 1 << 8;
    /// Keep the key vault's durable image: the holder sees every persisted record and decides what reaches the medium.
    pub const VAULT_STORE: u16 = 1 << 9;

    /// The bit a manifest permission name stands for.
    pub fn of_name(name: &str) -> Option<u16> {
        match name {
            "reconfigure" => Some(RECONFIGURE),
            "flash_raw" => Some(FLASH_RAW),
            "platform_raw" => Some(PLATFORM_RAW),
            "monitor" => Some(MONITOR),
            "bridge" => Some(BRIDGE),
            "pcie_device" => Some(PCIE_DEVICE),
            "dma" => Some(DMA),
            "observe" => Some(OBSERVE),
            "usb_host" => Some(USB_HOST),
            "vault_store" => Some(VAULT_STORE),
            _ => None,
        }
    }

    /// The manifest name of one permission bit.
    pub fn name(bit: u16) -> Option<&'static str> {
        match bit {
            RECONFIGURE => Some("reconfigure"),
            FLASH_RAW => Some("flash_raw"),
            PLATFORM_RAW => Some("platform_raw"),
            MONITOR => Some("monitor"),
            BRIDGE => Some("bridge"),
            PCIE_DEVICE => Some("pcie_device"),
            DMA => Some("dma"),
            OBSERVE => Some("observe"),
            USB_HOST => Some("usb_host"),
            VAULT_STORE => Some("vault_store"),
            _ => None,
        }
    }

    /// Every permission bit, in bit order.
    pub fn nth(i: usize) -> Option<u16> {
        match i {
            0 => Some(RECONFIGURE),
            1 => Some(FLASH_RAW),
            2 => Some(PLATFORM_RAW),
            3 => Some(MONITOR),
            4 => Some(BRIDGE),
            5 => Some(PCIE_DEVICE),
            6 => Some(DMA),
            7 => Some(OBSERVE),
            8 => Some(USB_HOST),
            9 => Some(VAULT_STORE),
            _ => None,
        }
    }
}

/// Negative return values.
pub mod errno {
    pub const OK: i32 = 0;
    pub const ERROR: i32 = -1;
    pub const EACCES: i32 = -13;
    pub const EFAULT: i32 = -14;
    pub const ENXIO: i32 = -6;
    pub const EIO: i32 = -5;
    pub const EAGAIN: i32 = -11;
    pub const ENOMEM: i32 = -12;
    pub const ENOSPC: i32 = -28;
    pub const E2BIG: i32 = -7;
    pub const EEXIST: i32 = -17;
    pub const EISDIR: i32 = -21;
    pub const EXDEV: i32 = -18;
    pub const ENOTEMPTY: i32 = -39;
    pub const ESRCH: i32 = -3;
    pub const EBUSY: i32 = -16;
    pub const ENODEV: i32 = -19;
    pub const ENOEXEC: i32 = -8;
    pub const EINVAL: i32 = -22;
    pub const EINPROGRESS: i32 = -36;
    pub const ENOSYS: i32 = -38;
    pub const ENOENT: i32 = -2;
    pub const ERANGE: i32 = -34;
    pub const EOVERFLOW: i32 = -75;
    pub const ENOTSUP: i32 = -95;
    pub const ENOTCONN: i32 = -107;
    pub const ETIMEDOUT: i32 = -110;
    pub const ECONNREFUSED: i32 = -111;
    pub const ERETAINED: i32 = -200;
}

/// Readiness bits `HANDLE_POLL` answers.
pub mod poll {
    pub const IN: u32 = 0x01;
    pub const OUT: u32 = 0x02;
    pub const ERR: u32 = 0x04;
    pub const HUP: u32 = 0x08;
    pub const WROTE: u32 = 0x20;
}

/// Channel ioctl commands the kernel serves (`channel_ioctl`'s `cmd`).
pub mod ioctl {
    pub const NOTIFY: u32 = 1;
    pub const POLL_NOTIFY: u32 = 2;
    pub const FLUSH: u32 = 3;
    pub const SET_HUP: u32 = 4;
    pub const WRITABLE: u32 = 5;
}

pub mod kernel {
    pub const ID: u16 = 0x0000;
    pub const LOG_WRITE: u32 = 0x0040;
    pub const SERIAL_WRITE: u32 = 0x0066;
    pub const HANDLE_POLL: u32 = 0x0041;
    pub const STREAM_TIME: u32 = 0x0030;
    pub const GRAPH_SAMPLE_RATE: u32 = 0x0031;
    pub const DOWNSTREAM_LATENCY: u32 = 0x0033;
    pub const REPORT_LATENCY: u32 = 0x0050;
    pub const REPORT_STEP_EFFECT: u32 = 0x0045;
    pub const ARENA_GET: u32 = 0x003a;
    pub const RANDOM_FILL: u32 = 0x003c;
    pub const SYS_CLOCK_HZ: u32 = 0x003b;
    pub const SELF_INDEX: u32 = 0x0042;
    pub const MODULE_INSTANCE_PARAMS: u32 = 0x0043;
    pub const OWNER_TAG: u32 = 0x004b;
    pub const NET_IDENT_PROVIDER: u32 = 0x004c;
    pub const BOOT_INCARNATION: u32 = 0x002f;
    pub const PROGRAM_INFO: u32 = 0x002b;
    pub const PROGRAM_READ: u32 = 0x002c;
    pub const SLOT_SIGNING_ROOT: u32 = 0x002d;
    pub const SLOT_ADMITTED: u32 = 0x002e;
    pub const FLASH_LAYOUT: u32 = 0x002a;
    pub const MODULE_FLOW_BUDGET: u32 = 0x0046;
    pub const GET_HW_ETHERNET_MAC: u32 = 0x003d;
    pub const QUERY_OP: u32 = 0x00fe;
    pub const QUERY_CLASS: u32 = 0x0001;
    pub const QUERY_NAME: u32 = 0x0002;
    pub const QUERY_CAPABILITIES: u32 = 0x0003;
    pub const QUERY_STATE: u32 = 0x0004;
    pub const QUERY_ERROR_COUNT: u32 = 0x0005;
    pub const QUERY_HEAP_STATS: u32 = 0x0006;
    pub const QUERY_LAST_FENCE: u32 = 0x0008;
    pub const QUERY_CALLER_OWNER: u32 = 0x0009;
    pub const QUERY_CALLER_MODULE: u32 = 0x000a;
    pub const QUERY_MODULE_LIVE: u32 = 0x000b;
    pub const QUERY_EVENT_OWNER: u32 = 0x000c;
    pub const SIGNAL_CORE: u32 = 0x0052;
}

pub mod channel {
    pub const ID: u16 = 0x0001;
    pub const OPEN: u32 = 0x0100;
    pub const CLOSE: u32 = 0x0101;
    pub const IOCTL: u32 = 0x0106;
    pub const REGISTER_IOCTL: u32 = 0x0107;
    pub const PORT: u32 = 0x010c;
}

pub mod timer {
    pub const ID: u16 = 0x0002;
    pub const FD_TAG: i32 = 2;
    pub const MILLIS: u32 = 0x0202;
    pub const MICROS: u32 = 0x0203;
    pub const UNIX_MILLIS: u32 = 0x0208;
    pub const TRUSTED_UNIX: u32 = 0x0209;
    pub const CREATE: u32 = 0x0204;
    pub const SET: u32 = 0x0205;
    pub const CANCEL: u32 = 0x0206;
    pub const DESTROY: u32 = 0x0207;
    pub const DISCIPLINE: u32 = 0x020a;
}

pub mod buffer {
    pub const ID: u16 = 0x0003;
    pub const ACQUIRE_WRITE: u32 = 0x0300;
    pub const RELEASE_WRITE: u32 = 0x0301;
    pub const ACQUIRE_READ: u32 = 0x0302;
    pub const RELEASE_READ: u32 = 0x0303;
    pub const ACQUIRE_INPLACE: u32 = 0x0304;
}

pub mod event {
    pub const ID: u16 = 0x0004;
    pub const FD_TAG: i32 = 4;
    pub const CREATE: u32 = 0x0400;
    pub const SIGNAL: u32 = 0x0401;
    pub const POLL: u32 = 0x0402;
    pub const DESTROY: u32 = 0x0403;
    pub const BIND_IRQ: u32 = 0x0451;
}

pub mod key_vault {
    pub const ID: u16 = 0x0005;
    pub const FD_TAG: i32 = 5;
    pub const PROBE: u32 = 0x0500;
    pub const STORE: u32 = 0x0501;
    pub const ECDH: u32 = 0x0502;
    pub const SIGN: u32 = 0x0503;
    pub const VERIFY: u32 = 0x0504;
    pub const DESTROY: u32 = 0x0505;
    pub const GENERATE: u32 = 0x0506;
    pub const PUBLIC: u32 = 0x0507;
    pub const TIER: u32 = 0x0508;
    pub const OPEN_OR_GENERATE: u32 = 0x0509;
    pub const OPEN: u32 = 0x050a;
    pub const DESTROY_BY_LABEL: u32 = 0x050b;
    pub const DESCRIBE: u32 = 0x050c;
    pub const SUITE_QUERY: u32 = 0x050d;
    pub const SUITE_ENUM: u32 = 0x050e;
    pub const ATTEST_COMPOSITION: u32 = 0x050f;
    pub const KEY_WRAP: u32 = 0x0510;
    pub const KEY_UNWRAP: u32 = 0x0511;
    pub const AEAD_SEAL: u32 = 0x0512;
    pub const AEAD_OPEN: u32 = 0x0513;
    pub const DERIVE: u32 = 0x0514;
    pub const AEAD_SEAL_UNITS: u32 = 0x0515;
    pub const AEAD_OPEN_UNITS: u32 = 0x0516;
    pub const SHARE_SPLIT: u32 = 0x0517;
    pub const SHARE_REWRAP: u32 = 0x0518;
    pub const SHARE_COMBINE: u32 = 0x0519;
    pub const ATTEST_KEY: u32 = 0x051a;
}

pub mod gpio {
    pub const ID: u16 = 0x0006;
    pub const FD_TAG: i32 = 6;
    pub const CLAIM: u32 = 0x0600;
    pub const RELEASE: u32 = 0x0601;
    pub const SET_MODE: u32 = 0x0602;
    pub const SET_PULL: u32 = 0x0603;
    pub const SET_LEVEL: u32 = 0x0604;
    pub const GET_LEVEL: u32 = 0x0605;
    pub const SET_OUTPUT: u32 = 0x0606;
    pub const SET_INPUT: u32 = 0x0607;
    pub const WATCH_EDGE: u32 = 0x060a;
}

pub mod spi {
    pub const ID: u16 = 0x0007;
    pub const FD_TAG: i32 = 7;
    pub const OPEN: u32 = 0x0700;
    pub const CLOSE: u32 = 0x0701;
    pub const BEGIN: u32 = 0x0702;
    pub const END: u32 = 0x0703;
    pub const SET_CS: u32 = 0x0704;
    pub const CLAIM: u32 = 0x0705;
    pub const CONFIGURE: u32 = 0x0706;
    pub const TRANSFER_START: u32 = 0x0707;
    pub const TRANSFER_POLL: u32 = 0x0708;
    pub const POLL_BYTE: u32 = 0x0709;
    pub const GET_CAPS: u32 = 0x070a;
}

pub mod i2c {
    pub const ID: u16 = 0x0008;
    pub const FD_TAG: i32 = 8;
    pub const OPEN: u32 = 0x0800;
    pub const CLOSE: u32 = 0x0801;
    pub const WRITE: u32 = 0x0802;
    pub const READ: u32 = 0x0803;
    pub const WRITE_READ: u32 = 0x0804;
    pub const CLAIM: u32 = 0x0805;
    pub const RELEASE: u32 = 0x0806;
    pub const GET_CAPS: u32 = 0x0807;
}

pub mod pio {
    pub const ID: u16 = 0x0009;
    pub const FD_TAG: i32 = 9;
    pub const STREAM_ALLOC: u32 = 0x0900;
    pub const STREAM_LOAD_PROGRAM: u32 = 0x0901;
    pub const STREAM_GET_BUFFER: u32 = 0x0902;
    pub const STREAM_CONFIGURE: u32 = 0x0903;
    pub const STREAM_CAN_PUSH: u32 = 0x0904;
    pub const STREAM_PUSH: u32 = 0x0905;
    pub const STREAM_FREE: u32 = 0x0906;
    pub const STREAM_TIME: u32 = 0x0907;
    pub const DIRECT_BUFFER: u32 = 0x0908;
    pub const DIRECT_PUSH: u32 = 0x0909;
    pub const PROGRAM_STATUS: u32 = 0x090a;
    pub const STREAM_SET_RATE: u32 = 0x090b;
    pub const CMD_ALLOC: u32 = 0x0910;
    pub const CMD_LOAD_PROGRAM: u32 = 0x0911;
    pub const CMD_CONFIGURE: u32 = 0x0912;
    pub const CMD_TRANSFER: u32 = 0x0913;
    pub const CMD_POLL: u32 = 0x0914;
    pub const CMD_FREE: u32 = 0x0915;
    pub const CMD_LEVEL: u32 = 0x0916;
    pub const RX_STREAM_ALLOC: u32 = 0x0920;
    pub const RX_STREAM_LOAD_PROGRAM: u32 = 0x0921;
    pub const RX_STREAM_CONFIGURE: u32 = 0x0922;
    pub const RX_STREAM_CAN_PULL: u32 = 0x0923;
    pub const RX_STREAM_PULL: u32 = 0x0924;
    pub const RX_STREAM_FREE: u32 = 0x0925;
    pub const RX_STREAM_GET_BUFFER: u32 = 0x0926;
    pub const RX_STREAM_SET_RATE: u32 = 0x0927;
}

pub mod uart {
    pub const ID: u16 = 0x000a;
    pub const FD_TAG: i32 = 10;
    pub const OPEN: u32 = 0x0a00;
    pub const CLOSE: u32 = 0x0a01;
    pub const WRITE: u32 = 0x0a02;
    pub const READ: u32 = 0x0a03;
    pub const POLL: u32 = 0x0a04;
    pub const CONFIGURE: u32 = 0x0a05;
}

pub mod adc {
    pub const ID: u16 = 0x000b;
    pub const FD_TAG: i32 = 11;
    pub const OPEN: u32 = 0x0b00;
    pub const CLOSE: u32 = 0x0b01;
    pub const READ: u32 = 0x0b02;
    pub const POLL: u32 = 0x0b03;
    pub const CONFIGURE: u32 = 0x0b04;
}

pub mod pwm {
    pub const ID: u16 = 0x000c;
    pub const FD_TAG: i32 = 12;
    pub const OPEN: u32 = 0x0c00;
    pub const CLOSE: u32 = 0x0c01;
    pub const CONFIGURE: u32 = 0x0c02;
    pub const SET_DUTY: u32 = 0x0c03;
    pub const GET_DUTY: u32 = 0x0c04;
}

pub mod fs {
    pub const ID: u16 = 0x000d;
    pub const FD_TAG: i32 = 13;
    pub const OPEN: u32 = 0x0d00;
    pub const READ: u32 = 0x0d01;
    pub const SEEK: u32 = 0x0d02;
    pub const CLOSE: u32 = 0x0d03;
    pub const STAT: u32 = 0x0d04;
    pub const FSYNC: u32 = 0x0d05;
    pub const WRITE: u32 = 0x0d06;
    pub const OPENDIR: u32 = 0x0d07;
    pub const READDIR: u32 = 0x0d08;
    pub const OPEN_CREATE: u32 = 0x0d09;
    pub const UNLINK: u32 = 0x0d0a;
    pub const MKDIR: u32 = 0x0d0b;
    pub const PREALLOCATE: u32 = 0x0d0e;
    pub const TRUNCATE: u32 = 0x0d0c;
    pub const WRITE_ASYNC: u32 = 0x0d0f;
    pub const FSYNC_SUBMIT: u32 = 0x0d10;
    pub const FSYNC_POLL: u32 = 0x0d11;
    pub const FSYNC_NAME: u32 = 0x0d12;
    pub const RMDIR: u32 = 0x0d15;
    pub const LINK: u32 = 0x0d13;
    pub const READLINK: u32 = 0x0d14;
    pub const RENAME: u32 = 0x0d0d;
    pub const CAPS: u32 = 0x0dff;
}

pub mod storage_namespace {
    pub const ID: u16 = 0x000e;
    pub const FD_TAG: i32 = 14;
    pub const LOOKUP: u32 = 0x0e00;
    pub const STAT: u32 = 0x0e01;
    pub const LIST: u32 = 0x0e02;
    pub const RENAME: u32 = 0x0e03;
    pub const DELETE: u32 = 0x0e04;
    pub const SUBSCRIBE: u32 = 0x0e05;
    pub const TAKE_RUNG: u32 = 0x0e09;
    pub const CLOSE: u32 = 0x0e06;
    pub const CHANGES: u32 = 0x0e07;
    pub const BIND: u32 = 0x0e08;
    pub const CAPS: u32 = 0x0eff;
}

pub mod storage_object {
    pub const ID: u16 = 0x000f;
    pub const FD_TAG: i32 = 15;
    pub const PUT: u32 = 0x0f20;
    pub const GET: u32 = 0x0f21;
    pub const HEAD: u32 = 0x0f22;
    pub const RANGE_GET: u32 = 0x0f23;
    pub const DELETE: u32 = 0x0f24;
    pub const CLOSE: u32 = 0x0f25;
    pub const IMG_DECODE: u32 = 0x0f30;
    pub const IMG_RECV: u32 = 0x0f31;
    pub const IMG_CLOSE: u32 = 0x0f32;
    pub const PUT_STREAMED_OPEN: u32 = 0x0f26;
    pub const PUT_STREAMED_WRITE: u32 = 0x0f27;
    pub const PUT_STREAMED_COMMIT: u32 = 0x0f28;
    pub const PUT_STREAMED_ABORT: u32 = 0x0f29;
    pub const RETAIN: u32 = 0x0f2c;
    pub const LIST: u32 = 0x0f2a;
    pub const PRESENT: u32 = 0x0f2b;
}

pub mod telemetry {
    pub const ID: u16 = 0x0010;
    pub const TLM_EMIT: u32 = 0x103e;
    pub const TLM_SUBSCRIBE: u32 = 0x104d;
    pub const TLM_DRAIN: u32 = 0x104e;
    pub const TLM_STATS: u32 = 0x104f;
}

pub mod resource {
    pub const ID: u16 = 0x0011;
    pub const ELASTIC_ALLOC: u32 = 0x113f;
    pub const POOL_SAMPLE: u32 = 0x1125;
    pub const LEDGER_DENY: u32 = 0x1124;
}

pub mod runtime_params {
    pub const ID: u16 = 0x0012;
    pub const STORE: u32 = 0x1234;
    pub const DELETE: u32 = 0x1235;
    pub const CLEAR_ALL: u32 = 0x1236;
}

pub mod stream_clock {
    pub const ID: u16 = 0x0013;
    pub const QUERY: u32 = 0x1300;
}

pub mod trust {
    pub const ID: u16 = 0x0014;
    pub const PROBE: u32 = 0x1400;
    pub const VERIFY: u32 = 0x1401;
}

pub mod net_policy {
    pub const ID: u16 = 0x0015;
    pub const PROBE: u32 = 0x1500;
    pub const CAPS: u32 = 0x1501;
    pub const REPLACE: u32 = 0x1502;
    pub const CLEAR: u32 = 0x1503;
    pub const READ: u32 = 0x1504;
    pub const ATTACH: u32 = 0x1505;
}

pub mod net_route {
    pub const ID: u16 = 0x0016;
    pub const PROBE: u32 = 0x1600;
    pub const CAPS: u32 = 0x1601;
    pub const SEGMENTS: u32 = 0x1602;
    pub const ROUTES: u32 = 0x1603;
    pub const HOLD: u32 = 0x1604;
    pub const READ: u32 = 0x1605;
    pub const REPORT: u32 = 0x1606;
    pub const TAKE: u32 = 0x1607;
}

pub mod workload {
    pub const ID: u16 = 0x0017;
    pub const FD_TAG: i32 = 23;
    pub const CREATE: u32 = 0x1700;
    pub const START: u32 = 0x1701;
    pub const WAIT: u32 = 0x1702;
    pub const SIGNAL: u32 = 0x1703;
    pub const DESTROY: u32 = 0x1704;
    pub const PAUSE: u32 = 0x170b;
    pub const RESUME: u32 = 0x170c;
    pub const LANES: u32 = 0x170d;
    pub const NET_PROVIDE: u32 = 0x170e;
    pub const NET_LANE_TAKE: u32 = 0x170f;
    pub const NET_LANE_ADMIT: u32 = 0x1710;
    pub const NET_RESOLVER: u32 = 0x1713;
    pub const CAPS: u32 = 0x17ff;
    pub const LOOKUP: u32 = 0x1712;
    pub const MODULE_DIGESTS: u32 = 0x1711;
}

pub mod host_process {
    pub const ID: u16 = 0x0018;
    pub const READ: u32 = 0x1801;
    pub const EXEC: u32 = 0x1802;
    pub const TTY_OPEN: u32 = 0x1803;
    pub const TTY_STEP: u32 = 0x1804;
    pub const TTY_RESIZE: u32 = 0x1805;
    pub const TTY_CLOSE: u32 = 0x1806;
    pub const CAPS: u32 = 0x1800;
}

pub mod host_mount {
    pub const ID: u16 = 0x0019;
    pub const PRIV: u32 = 0x1900;
    pub const MOUNT: u32 = 0x1901;
    pub const UMOUNT: u32 = 0x1902;
    pub const ROOT: u32 = 0x1903;
    pub const PROJECT: u32 = 0x1904;
    pub const REMOVE_TREE: u32 = 0x1905;
    pub const GROUP_TREE: u32 = 0x1906;
    pub const MKDIR_MODE: u32 = 0x1907;
}

pub mod proc {
    pub const ID: u16 = 0x001a;
    pub const FD_TAG: i32 = 26;
    pub const PROC_SPAWN: u32 = 0x1a00;
    pub const PROC_READ: u32 = 0x1a01;
    pub const PROC_STATUS: u32 = 0x1a02;
    pub const PROC_CLOSE: u32 = 0x1a03;
}

pub mod usb_host {
    pub const ID: u16 = 0x001b;
    pub const FD_TAG: i32 = 27;
}

pub mod pcie_device {
    pub const ID: u16 = 0x001c;
    pub const FD_TAG: i32 = 28;
    pub const BIND: u32 = 0x1ca0;
    pub const CLOSE: u32 = 0x1ca1;
    pub const CFG_READ32: u32 = 0x1ca2;
    pub const CFG_WRITE32: u32 = 0x1ca3;
    pub const BAR_MAP: u32 = 0x1ca4;
    pub const MSI_ALLOC: u32 = 0x1ca5;
    pub const INFO: u32 = 0x1ca6;
}

pub mod platform_nic_ring {
    pub const ID: u16 = 0x001d;
    pub const FD_TAG: i32 = 29;
    pub const NIC_BAR_MAP: u32 = 0x1df0;
    pub const NIC_BAR_UNMAP: u32 = 0x1df1;
    pub const NIC_RING_CREATE: u32 = 0x1df2;
    pub const NIC_RING_DESTROY: u32 = 0x1df3;
    pub const NIC_RING_INFO: u32 = 0x1df4;
}

pub mod platform_dma {
    pub const ID: u16 = 0x001e;
    pub const FD_TAG: i32 = 30;
    pub const ALLOC: u32 = 0x1e80;
    pub const FREE: u32 = 0x1e81;
    pub const START: u32 = 0x1e82;
    pub const BUSY: u32 = 0x1e83;
    pub const ABORT: u32 = 0x1e84;
}

pub mod platform_dma_fd {
    pub const ID: u16 = 0x001f;
    pub const FD_TAG: i32 = 31;
    pub const CREATE: u32 = 0x1f85;
    pub const START: u32 = 0x1f86;
    pub const RESTART: u32 = 0x1f87;
    pub const FREE: u32 = 0x1f88;
    pub const QUEUE: u32 = 0x1f89;
}

pub mod reconfigure {
    pub const ID: u16 = 0x0020;
    pub const SET_PHASE: u32 = 0x2068;
    pub const CALL_DRAIN: u32 = 0x2069;
    pub const MARK_FINISHED: u32 = 0x206a;
    pub const MODULE_COUNT: u32 = 0x206b;
    pub const MODULE_INFO: u32 = 0x206c;
    pub const TRIGGER_REBUILD: u32 = 0x206d;
    pub const MODULE_UPSTREAM: u32 = 0x206e;
    pub const MODULE_DONE: u32 = 0x206f;
    pub const SLOT_CAPACITY: u32 = 0x2023;
    pub const APPLY_ADD: u32 = 0x2047;
    pub const FREE_OWNER: u32 = 0x2048;
    pub const OWNER_PAUSE: u32 = 0x2049;
    pub const OWNER_RESUME: u32 = 0x204a;
    pub const OWNER_RELEASED: u32 = 0x2022;
    pub const OTA_STAGE_WRITE: u32 = 0x2020;
    pub const OTA_STAGE_CTRL: u32 = 0x2021;
}

pub mod monitor {
    pub const ID: u16 = 0x0021;
    pub const FAULT_MONITOR_SUBSCRIBE: u32 = 0x2152;
    pub const FAULT_MONITOR_POP: u32 = 0x2153;
    pub const FAULT_STATS_QUERY: u32 = 0x2154;
    pub const STEP_HISTOGRAM_QUERY: u32 = 0x2155;
    pub const MODULE_STATE_QUERY: u32 = 0x2157;
    pub const FAULT_RAISE: u32 = 0x2156;
    pub const ARENA_USAGE: u32 = 0x2132;
    pub const ISR_METRICS: u32 = 0x21e8;
}

pub mod bridge {
    pub const ID: u16 = 0x0022;
    pub const FD_TAG: i32 = 34;
    pub const WRITE: u32 = 0x22e0;
    pub const READ: u32 = 0x22e1;
    pub const POLL: u32 = 0x22e2;
    pub const INFO: u32 = 0x22e3;
    pub const SELF_BRIDGES: u32 = 0x2244;
}

pub mod flash {
    pub const ID: u16 = 0x0023;
    pub const RAW_ERASE: u32 = 0x2338;
    pub const RAW_PROGRAM: u32 = 0x2339;
    pub const SIDEBAND: u32 = 0x2310;
}

pub mod provider_registry {
    pub const ID: u16 = 0x0024;
    pub const FLASH_STORE_ENABLE: u32 = 0x2437;
}

pub mod diag {
    pub const ID: u16 = 0x0025;
    pub const LOG_RING_DRAIN: u32 = 0x2564;
    pub const FAN_DIAG_SNAPSHOT: u32 = 0x2565;
}

pub mod vault_store {
    pub const ID: u16 = 0x0026;
    pub const ATTACH: u32 = 0x2640;
    pub const LOAD: u32 = 0x2641;
    pub const DECIDE: u32 = 0x2642;
    pub const PENDING: u32 = 0x2643;
    pub const READ: u32 = 0x2644;
    pub const DONE: u32 = 0x2645;
}

pub mod rp_raw {
    pub const ID: u16 = 0x0027;
    pub const PWM_PIN_ENABLE: u32 = 0x2760;
    pub const PWM_PIN_DISABLE: u32 = 0x2761;
    pub const PWM_SLICE_WRITE: u32 = 0x2762;
    pub const PWM_SLICE_READ: u32 = 0x2763;
    pub const PIO_SM_EXEC: u32 = 0x2770;
    pub const PIO_SM_WRITE_REG: u32 = 0x2771;
    pub const PIO_SM_READ_REG: u32 = 0x2772;
    pub const PIO_SM_ENABLE: u32 = 0x2773;
    pub const PIO_INSTR_ALLOC: u32 = 0x2774;
    pub const PIO_INSTR_WRITE: u32 = 0x2775;
    pub const PIO_INSTR_FREE: u32 = 0x2776;
    pub const PIO_PIN_SETUP: u32 = 0x2777;
    pub const PIO_GPIOBASE: u32 = 0x2778;
    pub const PIO_TXF_WRITE: u32 = 0x2779;
    pub const PIO_FSTAT_READ: u32 = 0x277a;
    pub const PIO_SM_RESTART: u32 = 0x277b;
    pub const PIO_INPUT_SYNC_BYPASS: u32 = 0x277c;
    pub const PIO_CMD_TRANSFER: u32 = 0x277d;
    pub const PIO_CMD_POLL: u32 = 0x277e;
    pub const PIO_PIN_LEVEL: u32 = 0x277f;
    pub const SPI9_SEND: u32 = 0x2790;
    pub const SPI9_RESET: u32 = 0x2791;
    pub const SPI9_CS_SET: u32 = 0x2792;
    pub const SPI_REG_WRITE: u32 = 0x27a0;
    pub const SPI_REG_READ: u32 = 0x27a1;
    pub const SPI_BUS_INFO: u32 = 0x27a2;
    pub const SPI_PIN_INIT: u32 = 0x27a3;
    pub const SPI_SET_ENABLE: u32 = 0x27a4;
    pub const I2C_REG_WRITE: u32 = 0x27b0;
    pub const I2C_REG_READ: u32 = 0x27b1;
    pub const I2C_BUS_INFO: u32 = 0x27b2;
    pub const I2C_PIN_INIT: u32 = 0x27b3;
    pub const I2C_SET_ENABLE: u32 = 0x27b4;
    pub const UART_REG_WRITE: u32 = 0x27c0;
    pub const UART_REG_READ: u32 = 0x27c1;
    pub const UART_PIN_INIT: u32 = 0x27c2;
    pub const UART_SET_ENABLE: u32 = 0x27c3;
    pub const ADC_REG_WRITE: u32 = 0x27d0;
    pub const ADC_REG_READ: u32 = 0x27d1;
    pub const ADC_PIN_INIT: u32 = 0x27d2;
}

pub mod metal_device {
    pub const ID: u16 = 0x0028;
    pub const MMIO_READ32: u32 = 0x28e4;
    pub const MMIO_WRITE32: u32 = 0x28e5;
    pub const DMA_ALLOC_CONTIG: u32 = 0x28e6;
    pub const CACHE_FLUSH_RANGE: u32 = 0x28e7;
    pub const DMA_FLUSH: u32 = 0x28ea;
    pub const DMA_INVALIDATE: u32 = 0x28eb;
    pub const DMA_ALLOC_STREAMING: u32 = 0x28ec;
    pub const PCIE_RESCAN: u32 = 0x28f5;
    pub const PCIE_CFG_READ32: u32 = 0x28f6;
    pub const PCIE_CFG_WRITE32: u32 = 0x28f7;
}

/// The contract a manifest names (`requires_contract`, `provides`).
pub fn contract_of_name(name: &str) -> Option<u16> {
    match name {
        "channel" => Some(0x0001),
        "timer" => Some(0x0002),
        "buffer" => Some(0x0003),
        "event" => Some(0x0004),
        "gpio" => Some(0x0006),
        "spi" => Some(0x0007),
        "i2c" => Some(0x0008),
        "pio" => Some(0x0009),
        "uart" => Some(0x000a),
        "adc" => Some(0x000b),
        "pwm" => Some(0x000c),
        "fs" => Some(0x000d),
        "storage.namespace" => Some(0x000e),
        "storage.object" => Some(0x000f),
        "trust" => Some(0x0014),
        "net_policy" => Some(0x0015),
        "net_route" => Some(0x0016),
        "workload" => Some(0x0017),
        "host_mount" => Some(0x0019),
        "proc" => Some(0x001a),
        "usb_host" => Some(0x001b),
        "pcie_device" => Some(0x001c),
        "platform_nic_ring" => Some(0x001d),
        "platform_dma" => Some(0x001e),
        "platform_dma_fd" => Some(0x001f),
        "metal_device" => Some(0x0028),
        _ => None,
    }
}

/// The registry name of a contract id.
pub fn contract_name(id: u16) -> Option<&'static str> {
    match id {
        0x0000 => Some("kernel"),
        0x0001 => Some("channel"),
        0x0002 => Some("timer"),
        0x0003 => Some("buffer"),
        0x0004 => Some("event"),
        0x0005 => Some("key_vault"),
        0x0006 => Some("gpio"),
        0x0007 => Some("spi"),
        0x0008 => Some("i2c"),
        0x0009 => Some("pio"),
        0x000a => Some("uart"),
        0x000b => Some("adc"),
        0x000c => Some("pwm"),
        0x000d => Some("fs"),
        0x000e => Some("storage.namespace"),
        0x000f => Some("storage.object"),
        0x0010 => Some("telemetry"),
        0x0011 => Some("resource"),
        0x0012 => Some("runtime_params"),
        0x0013 => Some("stream_clock"),
        0x0014 => Some("trust"),
        0x0015 => Some("net_policy"),
        0x0016 => Some("net_route"),
        0x0017 => Some("workload"),
        0x0018 => Some("host_process"),
        0x0019 => Some("host_mount"),
        0x001a => Some("proc"),
        0x001b => Some("usb_host"),
        0x001c => Some("pcie_device"),
        0x001d => Some("platform_nic_ring"),
        0x001e => Some("platform_dma"),
        0x001f => Some("platform_dma_fd"),
        0x0020 => Some("reconfigure"),
        0x0021 => Some("monitor"),
        0x0022 => Some("bridge"),
        0x0023 => Some("flash"),
        0x0024 => Some("provider_registry"),
        0x0025 => Some("diag"),
        0x0026 => Some("vault_store"),
        0x0027 => Some("rp_raw"),
        0x0028 => Some("metal_device"),
        _ => None,
    }
}

/// How many contracts a manifest may name.
pub const MANIFEST_CONTRACTS: usize = 26;

/// The `i`th contract a manifest may name, in registry order.
pub fn manifest_contract(i: usize) -> Option<&'static str> {
    match i {
        0 => Some("channel"),
        1 => Some("timer"),
        2 => Some("buffer"),
        3 => Some("event"),
        4 => Some("gpio"),
        5 => Some("spi"),
        6 => Some("i2c"),
        7 => Some("pio"),
        8 => Some("uart"),
        9 => Some("adc"),
        10 => Some("pwm"),
        11 => Some("fs"),
        12 => Some("storage.namespace"),
        13 => Some("storage.object"),
        14 => Some("trust"),
        15 => Some("net_policy"),
        16 => Some("net_route"),
        17 => Some("workload"),
        18 => Some("host_mount"),
        19 => Some("proc"),
        20 => Some("usb_host"),
        21 => Some("pcie_device"),
        22 => Some("platform_nic_ring"),
        23 => Some("platform_dma"),
        24 => Some("platform_dma_fd"),
        25 => Some("metal_device"),
        _ => None,
    }
}

/// Whether an opcode goes to the kernel by its class ahead of any
/// handle: every op of a class-routed contract except those the
/// registry routes to the handle's own provider.
pub fn op_routes_to_kernel(op: u32) -> bool {
    matches!(
        (op >> 8) & 0xff,
        0x00 | 0x10
            | 0x11
            | 0x12
            | 0x1c
            | 0x1d
            | 0x1e
            | 0x1f
            | 0x20
            | 0x21
            | 0x22
            | 0x23
            | 0x24
            | 0x25
            | 0x27
    ) && !matches!(op, 0x00fe)
}

/// Whether an opcode class byte belongs to the registry: ids are dense.
pub fn class_registered(class: u32) -> bool {
    (class as usize) < CONTRACTS_ASSIGNED
}

/// Whether a contract hands out tagged handles (its id is their tag).
pub fn contract_mints(id: u16) -> bool {
    matches!(
        id,
        0x0002
            | 0x0004
            | 0x0005
            | 0x0006
            | 0x0007
            | 0x0008
            | 0x0009
            | 0x000a
            | 0x000b
            | 0x000c
            | 0x000d
            | 0x000e
            | 0x000f
            | 0x0017
            | 0x001a
            | 0x001b
            | 0x001c
            | 0x001d
            | 0x001e
            | 0x001f
            | 0x0022
    )
}

/// Handle layout: bit 31 clear, a 6-bit contract tag, then the slot.
pub mod fd {
    /// A handle with tag 0 is untagged (a channel port, a raw integer).
    pub const UNTAGGED: i32 = 0;
    pub const TAG_SHIFT: u32 = 25;
    pub const TAG_MASK: i32 = 0x3f;
    pub const SLOT_MASK: i32 = 0x1ffffff;
    /// Slot bits a provider's own index may use; the kernel owns the
    /// slot field's top bit (routed handles, the vault's hardware field).
    pub const SLOT_FIELD_BITS: u32 = 24;

    /// Encode a tag and a slot; a negative slot (an errno) passes through,
    /// and an unencodable tag is `EINVAL` rather than an alias.
    pub const fn tag_fd(tag: i32, slot: i32) -> i32 {
        if slot < 0 {
            return slot;
        }
        if tag < 0 || tag > TAG_MASK {
            return -22;
        }
        (tag << TAG_SHIFT) | (slot & SLOT_MASK)
    }

    /// Decode a handle into `(tag, slot)`.
    pub const fn untag_fd(fd: i32) -> (i32, i32) {
        ((fd >> TAG_SHIFT) & TAG_MASK, fd & SLOT_MASK)
    }

    /// The slot of a handle.
    pub const fn slot_of(fd: i32) -> i32 {
        fd & SLOT_MASK
    }
}

/// Channel message types, one module per surface.
pub mod msg {
    pub mod datagram {
        pub const CMD_DG_BIND: u8 = 0x20;
        pub const CMD_DG_SEND_TO: u8 = 0x21;
        pub const CMD_DG_CLOSE: u8 = 0x22;
        pub const MSG_DG_BOUND: u8 = 0x40;
        pub const MSG_DG_RX_FROM: u8 = 0x41;
        pub const MSG_DG_CLOSED: u8 = 0x42;
        pub const MSG_DG_ERROR: u8 = 0x43;
    }
    pub mod identity {
        pub const ADDR_ADD: u8 = 0xa0;
        pub const ADDR_DEL: u8 = 0xa1;
        pub const ADDR_ARM: u8 = 0xa2;
        pub const ADDR_FENCE: u8 = 0xa3;
        pub const MSG_ADDR_ADDED: u8 = 0xa8;
        pub const MSG_ADDR_ARMED: u8 = 0xa9;
        pub const MSG_ADDR_FENCED: u8 = 0xaa;
        pub const MSG_ADDR_REFUSED: u8 = 0xab;
        pub const MSG_ARM_AUTH_CHECK: u8 = 0xac;
        pub const ARM_AUTH_VERDICT: u8 = 0xad;
    }
    pub mod mux {
        pub const CMD_MUX_SESSION_OPEN: u8 = 0xb0;
        pub const CMD_MUX_SESSION_CLOSE: u8 = 0xb1;
        pub const CMD_MUX_STREAM_OPEN: u8 = 0xb2;
        pub const CMD_MUX_STREAM_CLOSE: u8 = 0xb3;
        pub const CMD_MUX_STREAM_SEND: u8 = 0xb4;
        pub const CMD_MUX_STREAM_ACK: u8 = 0xb5;
        pub const CMD_MUX_DATAGRAM_SEND: u8 = 0xb6;
        pub const CMD_MUX_STREAM_RESET: u8 = 0xb7;
        pub const CMD_MUX_STREAM_STOP_SENDING: u8 = 0xb8;
        pub const CMD_MUX_STREAM_OPEN_WITH: u8 = 0xb9;
        pub const MSG_MUX_SESSION_OPENED: u8 = 0xc0;
        pub const MSG_MUX_SESSION_CLOSED: u8 = 0xc1;
        pub const MSG_MUX_STREAM_OPENED: u8 = 0xc2;
        pub const MSG_MUX_STREAM_ACCEPTED: u8 = 0xc3;
        pub const MSG_MUX_STREAM_CLOSED: u8 = 0xc4;
        pub const MSG_MUX_STREAM_RX: u8 = 0xc5;
        pub const MSG_MUX_DATAGRAM_RX: u8 = 0xc7;
        pub const MSG_MUX_STREAM_RESET: u8 = 0xca;
        pub const MSG_MUX_STREAM_STOPPED: u8 = 0xcb;
        pub const MSG_MUX_SESSION_ERROR: u8 = 0xce;
        pub const MSG_MUX_STREAM_ERROR: u8 = 0xcf;
    }
    pub mod net_proto {
        pub const MSG_ACCEPTED: u8 = 0x01;
        pub const MSG_DATA: u8 = 0x02;
        pub const MSG_CLOSED: u8 = 0x03;
        pub const MSG_BOUND: u8 = 0x04;
        pub const MSG_CONNECTED: u8 = 0x05;
        pub const MSG_ERROR: u8 = 0x06;
        pub const MSG_RETRANSMIT: u8 = 0x07;
        pub const MSG_ACK: u8 = 0x08;
        pub const MSG_TRACE_CTX: u8 = 0x09;
        pub const MSG_PEER: u8 = 0x0a;
        pub const MSG_HORIZON: u8 = 0x0b;
        pub const MSG_RESUMED: u8 = 0x0c;
        pub const CMD_BIND: u8 = 0x10;
        pub const CMD_SEND: u8 = 0x11;
        pub const CMD_CLOSE: u8 = 0x12;
        pub const CMD_RESEND: u8 = 0x18;
        pub const CMD_DELIVERED: u8 = 0x19;
        pub const CMD_CONNECT: u8 = 0x13;
        pub const CMD_CONNECT_TO: u8 = 0x14;
    }
    pub mod packet {
        pub const CMD_PKT_BIND: u8 = 0x50;
        pub const CMD_PKT_TX: u8 = 0x51;
        pub const CMD_PKT_CLOSE: u8 = 0x52;
        pub const MSG_PKT_BOUND: u8 = 0x60;
        pub const MSG_PKT_RX: u8 = 0x61;
        pub const MSG_PKT_CLOSED: u8 = 0x62;
        pub const MSG_PKT_ERROR: u8 = 0x63;
        pub const CMD_PKT_DISPOSE: u8 = 0x53;
        pub const CMD_PKT_CLONE: u8 = 0x54;
        pub const MSG_PKT_DECIDE: u8 = 0x64;
        pub const MSG_PKT_FORWARD: u8 = 0x65;
        pub const MSG_PKT_CLONED: u8 = 0x66;
        pub const MSG_PKT_EXPIRED: u8 = 0x67;
        pub const MSG_PKT_MIRROR_LOST: u8 = 0x68;
        pub const MSG_PKT_DECIDE6: u8 = 0x69;
    }
    pub mod peer_identity {
        pub const MSG_PEER_IDENTITY: u8 = 0xc8;
    }
    pub mod session_ctrl {
        pub const CMD_SC_HELLO: u8 = 0x70;
        pub const CMD_SC_ATTACH: u8 = 0x71;
        pub const CMD_SC_DETACH: u8 = 0x72;
        pub const CMD_SC_DRAIN: u8 = 0x73;
        pub const CMD_SC_EXPORT_BEGIN: u8 = 0x74;
        pub const CMD_SC_EXPORT_CHUNK: u8 = 0x75;
        pub const CMD_SC_EXPORT_END: u8 = 0x76;
        pub const CMD_SC_RESUME: u8 = 0x77;
        pub const CMD_SC_EPOCH_BUMP: u8 = 0x78;
        pub const CMD_SC_RELOCATE: u8 = 0x79;
        pub const MSG_SC_HELLO_ACK: u8 = 0x90;
        pub const MSG_SC_ATTACHED: u8 = 0x91;
        pub const MSG_SC_DETACHED: u8 = 0x92;
        pub const MSG_SC_DRAINED: u8 = 0x93;
        pub const MSG_SC_IMPORT_BEGIN: u8 = 0x94;
        pub const MSG_SC_IMPORT_CHUNK: u8 = 0x95;
        pub const MSG_SC_IMPORT_END: u8 = 0x96;
        pub const MSG_SC_RESUMED: u8 = 0x97;
        pub const MSG_SC_EPOCH_CONFIRMED: u8 = 0x98;
        pub const MSG_SC_RELOCATED: u8 = 0x99;
        pub const CMD_SC_PAIR_PREPARE: u8 = 0x7a;
        pub const CMD_SC_CHECKPOINT_BEGIN: u8 = 0x7b;
        pub const CMD_SC_CHECKPOINT_NEXT: u8 = 0x7c;
        pub const CMD_SC_CHECKPOINT_COMMIT: u8 = 0x7d;
        pub const CMD_SC_DELTA_APPLY: u8 = 0x7e;
        pub const CMD_SC_DELTA_ACK: u8 = 0x7f;
        pub const CMD_SC_QUIESCE_BEGIN: u8 = 0x80;
        pub const CMD_SC_QUIESCE_STATUS: u8 = 0x81;
        pub const CMD_SC_CUT_EXPORT: u8 = 0x82;
        pub const CMD_SC_CUT_IMPORT: u8 = 0x83;
        pub const CMD_SC_EMISSION_ARM: u8 = 0x84;
        pub const CMD_SC_ACTIVATE: u8 = 0x85;
        pub const CMD_SC_RETIRE: u8 = 0x86;
        pub const CMD_SC_ABORT: u8 = 0x87;
        pub const CMD_SC_RESERVATION_GRANT: u8 = 0x88;
        pub const CMD_SC_TOMBSTONE: u8 = 0x89;
        pub const CMD_SC_CUSTODY: u8 = 0x8a;
        pub const MSG_SC_CONTINUITY: u8 = 0x9a;
        pub const MSG_SC_ERROR: u8 = 0x9f;
    }
}

/// The permission an opcode requires, if any. An opcode the registry
/// does not list requires its contract's `unlisted` permission.
pub fn op_permission(op: u32) -> Option<u16> {
    match op {
        0x0001 => None,
        0x0002 => None,
        0x0003 => None,
        0x0004 => None,
        0x0005 => None,
        0x0006 => None,
        0x0008 => None,
        0x0009 => None,
        0x000a => None,
        0x000b => None,
        0x000c => None,
        0x002a => None,
        0x002b => None,
        0x002c => None,
        0x002d => None,
        0x002e => None,
        0x002f => None,
        0x0030 => None,
        0x0031 => None,
        0x0033 => None,
        0x003a => None,
        0x003b => None,
        0x003c => None,
        0x003d => None,
        0x0040 => None,
        0x0041 => None,
        0x0042 => None,
        0x0043 => None,
        0x0045 => None,
        0x0046 => None,
        0x004b => None,
        0x004c => None,
        0x0050 => None,
        0x0052 => Some(permission::PLATFORM_RAW),
        0x0066 => Some(permission::PLATFORM_RAW),
        0x00fe => None,
        0x0100 => None,
        0x0101 => None,
        0x0106 => None,
        0x0107 => None,
        0x010c => None,
        0x0202 => None,
        0x0203 => None,
        0x0204 => None,
        0x0205 => None,
        0x0206 => None,
        0x0207 => None,
        0x0208 => None,
        0x0209 => None,
        0x020a => Some(permission::PLATFORM_RAW),
        0x0300 => None,
        0x0301 => None,
        0x0302 => None,
        0x0303 => None,
        0x0304 => None,
        0x0400 => None,
        0x0401 => None,
        0x0402 => None,
        0x0403 => None,
        0x0451 => None,
        0x0500 => None,
        0x0501 => None,
        0x0502 => None,
        0x0503 => None,
        0x0504 => None,
        0x0505 => None,
        0x0506 => None,
        0x0507 => None,
        0x0508 => None,
        0x0509 => None,
        0x050a => None,
        0x050b => None,
        0x050c => None,
        0x050d => None,
        0x050e => None,
        0x050f => None,
        0x0510 => None,
        0x0511 => None,
        0x0512 => None,
        0x0513 => None,
        0x0514 => None,
        0x0515 => None,
        0x0516 => None,
        0x0517 => None,
        0x0518 => None,
        0x0519 => None,
        0x051a => None,
        0x0600 => None,
        0x0601 => None,
        0x0602 => None,
        0x0603 => None,
        0x0604 => None,
        0x0605 => None,
        0x0606 => None,
        0x0607 => None,
        0x060a => None,
        0x0700 => None,
        0x0701 => None,
        0x0702 => None,
        0x0703 => None,
        0x0704 => None,
        0x0705 => None,
        0x0706 => None,
        0x0707 => None,
        0x0708 => None,
        0x0709 => None,
        0x070a => None,
        0x0800 => None,
        0x0801 => None,
        0x0802 => None,
        0x0803 => None,
        0x0804 => None,
        0x0805 => None,
        0x0806 => None,
        0x0807 => None,
        0x0900 => None,
        0x0901 => None,
        0x0902 => None,
        0x0903 => None,
        0x0904 => None,
        0x0905 => None,
        0x0906 => None,
        0x0907 => None,
        0x0908 => None,
        0x0909 => None,
        0x090a => None,
        0x090b => None,
        0x0910 => None,
        0x0911 => None,
        0x0912 => None,
        0x0913 => None,
        0x0914 => None,
        0x0915 => None,
        0x0916 => None,
        0x0920 => None,
        0x0921 => None,
        0x0922 => None,
        0x0923 => None,
        0x0924 => None,
        0x0925 => None,
        0x0926 => None,
        0x0927 => None,
        0x0a00 => None,
        0x0a01 => None,
        0x0a02 => None,
        0x0a03 => None,
        0x0a04 => None,
        0x0a05 => None,
        0x0b00 => None,
        0x0b01 => None,
        0x0b02 => None,
        0x0b03 => None,
        0x0b04 => None,
        0x0c00 => None,
        0x0c01 => None,
        0x0c02 => None,
        0x0c03 => None,
        0x0c04 => None,
        0x0d00 => None,
        0x0d01 => None,
        0x0d02 => None,
        0x0d03 => None,
        0x0d04 => None,
        0x0d05 => None,
        0x0d06 => None,
        0x0d07 => None,
        0x0d08 => None,
        0x0d09 => None,
        0x0d0a => None,
        0x0d0b => None,
        0x0d0c => None,
        0x0d0d => None,
        0x0d0e => None,
        0x0d0f => None,
        0x0d10 => None,
        0x0d11 => None,
        0x0d12 => None,
        0x0d13 => None,
        0x0d14 => None,
        0x0d15 => None,
        0x0dff => None,
        0x0e00 => None,
        0x0e01 => None,
        0x0e02 => None,
        0x0e03 => None,
        0x0e04 => None,
        0x0e05 => None,
        0x0e06 => None,
        0x0e07 => None,
        0x0e08 => None,
        0x0e09 => None,
        0x0eff => None,
        0x0f20 => None,
        0x0f21 => None,
        0x0f22 => None,
        0x0f23 => None,
        0x0f24 => None,
        0x0f25 => None,
        0x0f26 => None,
        0x0f27 => None,
        0x0f28 => None,
        0x0f29 => None,
        0x0f2a => None,
        0x0f2b => None,
        0x0f2c => None,
        0x0f30 => None,
        0x0f31 => None,
        0x0f32 => None,
        0x103e => None,
        0x104d => Some(permission::OBSERVE),
        0x104e => Some(permission::OBSERVE),
        0x104f => Some(permission::OBSERVE),
        0x1124 => None,
        0x1125 => Some(permission::PLATFORM_RAW),
        0x113f => None,
        0x1234 => None,
        0x1235 => None,
        0x1236 => None,
        0x1300 => None,
        0x1400 => None,
        0x1401 => None,
        0x1500 => None,
        0x1501 => None,
        0x1502 => Some(permission::PLATFORM_RAW),
        0x1503 => Some(permission::PLATFORM_RAW),
        0x1504 => None,
        0x1505 => None,
        0x1600 => None,
        0x1601 => None,
        0x1602 => Some(permission::PLATFORM_RAW),
        0x1603 => Some(permission::PLATFORM_RAW),
        0x1604 => Some(permission::PLATFORM_RAW),
        0x1605 => Some(permission::PLATFORM_RAW),
        0x1606 => None,
        0x1607 => None,
        0x1700 => Some(permission::PLATFORM_RAW),
        0x1701 => Some(permission::PLATFORM_RAW),
        0x1702 => Some(permission::PLATFORM_RAW),
        0x1703 => Some(permission::PLATFORM_RAW),
        0x1704 => Some(permission::PLATFORM_RAW),
        0x170b => Some(permission::PLATFORM_RAW),
        0x170c => Some(permission::PLATFORM_RAW),
        0x170d => Some(permission::PLATFORM_RAW),
        0x170e => None,
        0x170f => None,
        0x1710 => None,
        0x1711 => Some(permission::PLATFORM_RAW),
        0x1712 => Some(permission::PLATFORM_RAW),
        0x1713 => None,
        0x17ff => Some(permission::PLATFORM_RAW),
        0x1800 => Some(permission::PLATFORM_RAW),
        0x1801 => Some(permission::PLATFORM_RAW),
        0x1802 => Some(permission::PLATFORM_RAW),
        0x1803 => Some(permission::PLATFORM_RAW),
        0x1804 => Some(permission::PLATFORM_RAW),
        0x1805 => Some(permission::PLATFORM_RAW),
        0x1806 => Some(permission::PLATFORM_RAW),
        0x1900 => None,
        0x1901 => Some(permission::PLATFORM_RAW),
        0x1902 => Some(permission::PLATFORM_RAW),
        0x1903 => None,
        0x1904 => Some(permission::PLATFORM_RAW),
        0x1905 => Some(permission::PLATFORM_RAW),
        0x1906 => Some(permission::PLATFORM_RAW),
        0x1907 => Some(permission::PLATFORM_RAW),
        0x1a00 => None,
        0x1a01 => None,
        0x1a02 => None,
        0x1a03 => None,
        0x1ca0 => Some(permission::PCIE_DEVICE),
        0x1ca1 => Some(permission::PCIE_DEVICE),
        0x1ca2 => Some(permission::PCIE_DEVICE),
        0x1ca3 => Some(permission::PCIE_DEVICE),
        0x1ca4 => Some(permission::PCIE_DEVICE),
        0x1ca5 => Some(permission::PCIE_DEVICE),
        0x1ca6 => Some(permission::PCIE_DEVICE),
        0x1df0 => Some(permission::PLATFORM_RAW),
        0x1df1 => Some(permission::PLATFORM_RAW),
        0x1df2 => Some(permission::PLATFORM_RAW),
        0x1df3 => Some(permission::PLATFORM_RAW),
        0x1df4 => Some(permission::PLATFORM_RAW),
        0x1e80 => Some(permission::PLATFORM_RAW),
        0x1e81 => Some(permission::PLATFORM_RAW),
        0x1e82 => Some(permission::PLATFORM_RAW),
        0x1e83 => Some(permission::PLATFORM_RAW),
        0x1e84 => Some(permission::PLATFORM_RAW),
        0x1f85 => Some(permission::PLATFORM_RAW),
        0x1f86 => Some(permission::PLATFORM_RAW),
        0x1f87 => Some(permission::PLATFORM_RAW),
        0x1f88 => Some(permission::PLATFORM_RAW),
        0x1f89 => Some(permission::PLATFORM_RAW),
        0x2020 => Some(permission::PLATFORM_RAW),
        0x2021 => Some(permission::PLATFORM_RAW),
        0x2022 => Some(permission::PLATFORM_RAW),
        0x2023 => Some(permission::RECONFIGURE),
        0x2047 => Some(permission::PLATFORM_RAW),
        0x2048 => Some(permission::PLATFORM_RAW),
        0x2049 => Some(permission::PLATFORM_RAW),
        0x204a => Some(permission::PLATFORM_RAW),
        0x2068 => Some(permission::RECONFIGURE),
        0x2069 => Some(permission::RECONFIGURE),
        0x206a => Some(permission::RECONFIGURE),
        0x206b => Some(permission::RECONFIGURE),
        0x206c => Some(permission::RECONFIGURE),
        0x206d => Some(permission::RECONFIGURE),
        0x206e => Some(permission::RECONFIGURE),
        0x206f => Some(permission::RECONFIGURE),
        0x2132 => Some(permission::PLATFORM_RAW),
        0x2152 => Some(permission::MONITOR),
        0x2153 => Some(permission::MONITOR),
        0x2154 => Some(permission::MONITOR),
        0x2155 => Some(permission::MONITOR),
        0x2156 => Some(permission::MONITOR),
        0x2157 => Some(permission::MONITOR),
        0x21e8 => None,
        0x2244 => None,
        0x22e0 => Some(permission::BRIDGE),
        0x22e1 => Some(permission::BRIDGE),
        0x22e2 => Some(permission::BRIDGE),
        0x22e3 => Some(permission::BRIDGE),
        0x2310 => Some(permission::FLASH_RAW),
        0x2338 => Some(permission::FLASH_RAW),
        0x2339 => Some(permission::FLASH_RAW),
        0x2437 => Some(permission::FLASH_RAW),
        0x2564 => Some(permission::PLATFORM_RAW),
        0x2565 => None,
        0x2640 => Some(permission::VAULT_STORE),
        0x2641 => Some(permission::VAULT_STORE),
        0x2642 => Some(permission::VAULT_STORE),
        0x2643 => Some(permission::VAULT_STORE),
        0x2644 => Some(permission::VAULT_STORE),
        0x2645 => Some(permission::VAULT_STORE),
        0x2760 => Some(permission::PLATFORM_RAW),
        0x2761 => Some(permission::PLATFORM_RAW),
        0x2762 => Some(permission::PLATFORM_RAW),
        0x2763 => Some(permission::PLATFORM_RAW),
        0x2770 => Some(permission::PLATFORM_RAW),
        0x2771 => Some(permission::PLATFORM_RAW),
        0x2772 => Some(permission::PLATFORM_RAW),
        0x2773 => Some(permission::PLATFORM_RAW),
        0x2774 => Some(permission::PLATFORM_RAW),
        0x2775 => Some(permission::PLATFORM_RAW),
        0x2776 => Some(permission::PLATFORM_RAW),
        0x2777 => Some(permission::PLATFORM_RAW),
        0x2778 => Some(permission::PLATFORM_RAW),
        0x2779 => Some(permission::PLATFORM_RAW),
        0x277a => Some(permission::PLATFORM_RAW),
        0x277b => Some(permission::PLATFORM_RAW),
        0x277c => Some(permission::PLATFORM_RAW),
        0x277d => Some(permission::PLATFORM_RAW),
        0x277e => Some(permission::PLATFORM_RAW),
        0x277f => Some(permission::PLATFORM_RAW),
        0x2790 => Some(permission::PLATFORM_RAW),
        0x2791 => Some(permission::PLATFORM_RAW),
        0x2792 => Some(permission::PLATFORM_RAW),
        0x27a0 => Some(permission::PLATFORM_RAW),
        0x27a1 => Some(permission::PLATFORM_RAW),
        0x27a2 => Some(permission::PLATFORM_RAW),
        0x27a3 => Some(permission::PLATFORM_RAW),
        0x27a4 => Some(permission::PLATFORM_RAW),
        0x27b0 => Some(permission::PLATFORM_RAW),
        0x27b1 => Some(permission::PLATFORM_RAW),
        0x27b2 => Some(permission::PLATFORM_RAW),
        0x27b3 => Some(permission::PLATFORM_RAW),
        0x27b4 => Some(permission::PLATFORM_RAW),
        0x27c0 => Some(permission::PLATFORM_RAW),
        0x27c1 => Some(permission::PLATFORM_RAW),
        0x27c2 => Some(permission::PLATFORM_RAW),
        0x27c3 => Some(permission::PLATFORM_RAW),
        0x27d0 => Some(permission::PLATFORM_RAW),
        0x27d1 => Some(permission::PLATFORM_RAW),
        0x27d2 => Some(permission::PLATFORM_RAW),
        0x28e4 => Some(permission::PLATFORM_RAW),
        0x28e5 => Some(permission::PLATFORM_RAW),
        0x28e6 => Some(permission::DMA),
        0x28e7 => Some(permission::DMA),
        0x28ea => Some(permission::DMA),
        0x28eb => Some(permission::DMA),
        0x28ec => Some(permission::DMA),
        0x28f5 => Some(permission::PLATFORM_RAW),
        0x28f6 => Some(permission::PLATFORM_RAW),
        0x28f7 => Some(permission::PLATFORM_RAW),
        _ => match op >> 8 {
            0x00 => Some(permission::PLATFORM_RAW),
            0x10 => Some(permission::PLATFORM_RAW),
            0x11 => Some(permission::PLATFORM_RAW),
            0x12 => Some(permission::PLATFORM_RAW),
            0x17 => Some(permission::PLATFORM_RAW),
            0x18 => Some(permission::PLATFORM_RAW),
            0x1b => Some(permission::USB_HOST),
            0x1c => Some(permission::PLATFORM_RAW),
            0x1d => Some(permission::PLATFORM_RAW),
            0x1e => Some(permission::PLATFORM_RAW),
            0x1f => Some(permission::PLATFORM_RAW),
            0x20 => Some(permission::PLATFORM_RAW),
            0x21 => Some(permission::PLATFORM_RAW),
            0x22 => Some(permission::PLATFORM_RAW),
            0x23 => Some(permission::PLATFORM_RAW),
            0x24 => Some(permission::PLATFORM_RAW),
            0x25 => Some(permission::PLATFORM_RAW),
            0x27 => Some(permission::PLATFORM_RAW),
            0x28 => Some(permission::PLATFORM_RAW),
            _ => None,
        },
    }
}

/// Whether an opcode creates work or a held resource, and so waits on
/// the owner admission gate.
pub fn op_admits(op: u32) -> bool {
    matches!(
        op,
        0x0100 | 0x0204 | 0x0205 | 0x0400 | 0x0451 | 0x0d00 | 0x0d07 | 0x0d09
    )
}

/// What the gateway serves a gated module.
pub mod gate {
    /// What a rule lets the caller name as the handle.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum HandleUse {
        Global,
        Value,
        Channel,
        Minted,
        Mints,
        Scoped,
        ScopedMints,
    }

    /// Which way the argument buffer moves.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum ArgDir {
        None,
        In,
        Out,
        InOut,
    }

    /// How long the argument buffer may be.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Bound {
        /// At most this many bytes.
        Bytes(usize),
        /// Bounded by the caller's own region alone.
        Any,
        /// The walked-struct bound the gateway copies.
        Walk,
    }

    /// An argument struct that carries pointers, and how to find them.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Walker {
        ChannelIoctl,
        StorageDelete,
        StorageHead,
        StorageList,
        StoragePut,
        StorageRangeGet,
        StorageRetain,
    }

    /// One opcode a gated module may use.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct OpRule {
        pub handle: HandleUse,
        pub dir: ArgDir,
        pub bound: Bound,
        pub walk: Option<Walker>,
        /// The op releases the handle it names.
        pub closes: bool,
    }

    /// The rule for `op`, if gated modules may use it.
    pub fn op_rule(op: u32) -> Option<OpRule> {
        match op {
            0x002a => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::Out,
                bound: Bound::Bytes(20),
                walk: None,
                closes: false,
            }),
            0x002b => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::InOut,
                bound: Bound::Bytes(64),
                walk: None,
                closes: false,
            }),
            0x002c => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::InOut,
                bound: Bound::Any,
                walk: None,
                closes: false,
            }),
            0x002d => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::Out,
                bound: Bound::Bytes(32),
                walk: None,
                closes: false,
            }),
            0x002e => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::None,
                bound: Bound::Bytes(0),
                walk: None,
                closes: false,
            }),
            0x002f => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::Out,
                bound: Bound::Bytes(16),
                walk: None,
                closes: false,
            }),
            0x003a => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::Out,
                bound: Bound::Bytes(4),
                walk: None,
                closes: false,
            }),
            0x003c => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::Out,
                bound: Bound::Any,
                walk: None,
                closes: false,
            }),
            0x0040 => Some(OpRule {
                handle: HandleUse::Value,
                dir: ArgDir::In,
                bound: Bound::Any,
                walk: None,
                closes: false,
            }),
            0x0041 => Some(OpRule {
                handle: HandleUse::Channel,
                dir: ArgDir::InOut,
                bound: Bound::Bytes(1),
                walk: None,
                closes: false,
            }),
            0x0045 => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::In,
                bound: Bound::Bytes(1),
                walk: None,
                closes: false,
            }),
            0x0046 => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::InOut,
                bound: Bound::Any,
                walk: None,
                closes: false,
            }),
            0x0050 => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::In,
                bound: Bound::Bytes(4),
                walk: None,
                closes: false,
            }),
            0x0106 => Some(OpRule {
                handle: HandleUse::Channel,
                dir: ArgDir::InOut,
                bound: Bound::Walk,
                walk: Some(Walker::ChannelIoctl),
                closes: false,
            }),
            0x010c => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::InOut,
                bound: Bound::Bytes(2),
                walk: None,
                closes: false,
            }),
            0x0202 => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::Out,
                bound: Bound::Bytes(8),
                walk: None,
                closes: false,
            }),
            0x0203 => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::Out,
                bound: Bound::Bytes(8),
                walk: None,
                closes: false,
            }),
            0x0208 => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::Out,
                bound: Bound::Bytes(8),
                walk: None,
                closes: false,
            }),
            0x0209 => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::Out,
                bound: Bound::Bytes(36),
                walk: None,
                closes: false,
            }),
            0x020a => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::In,
                bound: Bound::Bytes(20),
                walk: None,
                closes: false,
            }),
            0x0400 => Some(OpRule {
                handle: HandleUse::Mints,
                dir: ArgDir::None,
                bound: Bound::Bytes(0),
                walk: None,
                closes: false,
            }),
            0x0401 => Some(OpRule {
                handle: HandleUse::Minted,
                dir: ArgDir::None,
                bound: Bound::Bytes(0),
                walk: None,
                closes: false,
            }),
            0x0402 => Some(OpRule {
                handle: HandleUse::Minted,
                dir: ArgDir::None,
                bound: Bound::Bytes(0),
                walk: None,
                closes: false,
            }),
            0x0403 => Some(OpRule {
                handle: HandleUse::Minted,
                dir: ArgDir::None,
                bound: Bound::Bytes(0),
                walk: None,
                closes: true,
            }),
            0x0f20 => Some(OpRule {
                handle: HandleUse::Scoped,
                dir: ArgDir::In,
                bound: Bound::Walk,
                walk: Some(Walker::StoragePut),
                closes: false,
            }),
            0x0f21 => Some(OpRule {
                handle: HandleUse::ScopedMints,
                dir: ArgDir::In,
                bound: Bound::Any,
                walk: None,
                closes: false,
            }),
            0x0f22 => Some(OpRule {
                handle: HandleUse::Scoped,
                dir: ArgDir::In,
                bound: Bound::Walk,
                walk: Some(Walker::StorageHead),
                closes: false,
            }),
            0x0f23 => Some(OpRule {
                handle: HandleUse::Minted,
                dir: ArgDir::In,
                bound: Bound::Walk,
                walk: Some(Walker::StorageRangeGet),
                closes: false,
            }),
            0x0f24 => Some(OpRule {
                handle: HandleUse::Scoped,
                dir: ArgDir::In,
                bound: Bound::Walk,
                walk: Some(Walker::StorageDelete),
                closes: false,
            }),
            0x0f25 => Some(OpRule {
                handle: HandleUse::Minted,
                dir: ArgDir::None,
                bound: Bound::Bytes(0),
                walk: None,
                closes: true,
            }),
            0x0f2a => Some(OpRule {
                handle: HandleUse::Scoped,
                dir: ArgDir::In,
                bound: Bound::Walk,
                walk: Some(Walker::StorageList),
                closes: false,
            }),
            0x0f2b => Some(OpRule {
                handle: HandleUse::Mints,
                dir: ArgDir::InOut,
                bound: Bound::Any,
                walk: None,
                closes: false,
            }),
            0x0f2c => Some(OpRule {
                handle: HandleUse::Scoped,
                dir: ArgDir::In,
                bound: Bound::Walk,
                walk: Some(Walker::StorageRetain),
                closes: false,
            }),
            0x103e => Some(OpRule {
                handle: HandleUse::Global,
                dir: ArgDir::In,
                bound: Bound::Any,
                walk: None,
                closes: false,
            }),
            _ => None,
        }
    }

    /// The bytes a `provider_query` key served to gated modules writes.
    pub fn query_max(key: u32) -> Option<usize> {
        match key {
            0x0030 => Some(24),
            0x0031 => Some(4),
            0x0033 => Some(4),
            0x003b => Some(4),
            _ => None,
        }
    }
}
