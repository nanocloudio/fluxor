// @generated
// By `fluxor abi-regen` from `registry.toml`. Edit that file and
// regenerate; never edit this one.
//
// Scalars and `match` lookups only: nothing here places an address in
// a module's `.rodata`.

/// Bumped by hand when a meaning changes without a number changing.
pub const SEMANTIC_EPOCH: u32 = 1;
/// Contract ids are below this: the width of the first grant word.
pub const MAX_CONTRACTS: usize = 64;
/// ORed onto an opcode: dispatch to the provider below the caller.
pub const CHAIN_NEXT: u32 = 0x10000;
/// Contract ids the registry assigns.
pub const CONTRACTS_ASSIGNED: usize = 45;

/// Op-level grants (`grants = [..]` in a manifest): the bits of the
/// second grant word. A contract's own grant is its id's bit in the first.
pub mod grant {
    /// Write raw bytes to the board's serial port (`SERIAL_WRITE`).
    pub const KERNEL_SERIAL: u8 = 0;
    /// Signal another core (`SIGNAL_CORE`).
    pub const KERNEL_SIGNAL_CORE: u8 = 1;
    /// Steer the kernel clock to an external time source (`DISCIPLINE`).
    pub const TIMER_DISCIPLINE: u8 = 2;
    /// Sample a provider's pool for the resource ledger (`POOL_SAMPLE`).
    pub const RESOURCE_POOL_SAMPLE: u8 = 3;
    /// Replace or clear the node's network policy (`REPLACE`, `CLEAR`).
    pub const NET_POLICY_REPLACE: u8 = 4;
    /// Read and write the node's route table and segments (`SEGMENTS`, `ROUTES`, `HOLD`, `READ`).
    pub const NET_ROUTE_TABLE: u8 = 5;
    /// Report to and take from the route table as the node's IP stack (`REPORT`, `TAKE`).
    pub const NET_ROUTE_STACK: u8 = 6;
    /// Create, run, signal and inspect workloads.
    pub const WORKLOAD_CREATE: u8 = 7;
    /// Serve workloads' network lanes as the node's IP stack (`NET_*`).
    pub const WORKLOAD_NET: u8 = 8;
    /// Run processes and terminals on the host.
    pub const HOST_PROCESS_EXEC: u8 = 9;
    /// Mount, project and remove host trees.
    pub const HOST_MOUNT_MOUNT: u8 = 10;
    /// Add a subgraph, and pause, resume or free an owner.
    pub const RECONFIGURE_OWNER: u8 = 11;
    /// Stage an OTA image (`OTA_STAGE_WRITE`, `OTA_STAGE_CTRL`).
    pub const RECONFIGURE_OTA: u8 = 12;
    /// Open a device-register aperture and read and write registers in it (`MMIO_OPEN`, `MMIO_READ32`, `MMIO_WRITE32`).
    pub const METAL_DEVICE_MMIO: u8 = 13;
    /// Rescan PCIe and read or write any device's config space.
    pub const METAL_DEVICE_PCIE: u8 = 14;
    /// Allocate DMA memory from the kernel's arena and maintain its cache.
    pub const METAL_DEVICE_DMA: u8 = 15;
    /// Keep the key vault's durable image: the holder sees every persisted record and decides what reaches the medium.
    pub const SEAL_KEY: u8 = 16;
    /// Resolve and return a span another module lent to one of this module's edges (`RESOLVE`, `RETURN`): a privileged driver doing DMA into it.
    pub const LEND_BORROW: u8 = 17;

    /// The op-level grants a gated module may not hold.
    pub const REACH_KERNEL: u64 = 0x3ffff;

    /// The bit an op-level grant's name stands for.
    pub fn of_name(name: &str) -> Option<u8> {
        match name {
            "kernel.serial" => Some(KERNEL_SERIAL),
            "kernel.signal_core" => Some(KERNEL_SIGNAL_CORE),
            "timer.discipline" => Some(TIMER_DISCIPLINE),
            "resource.pool_sample" => Some(RESOURCE_POOL_SAMPLE),
            "net_policy.replace" => Some(NET_POLICY_REPLACE),
            "net_route.table" => Some(NET_ROUTE_TABLE),
            "net_route.stack" => Some(NET_ROUTE_STACK),
            "workload.create" => Some(WORKLOAD_CREATE),
            "workload.net" => Some(WORKLOAD_NET),
            "host_process.exec" => Some(HOST_PROCESS_EXEC),
            "host_mount.mount" => Some(HOST_MOUNT_MOUNT),
            "reconfigure.owner" => Some(RECONFIGURE_OWNER),
            "reconfigure.ota" => Some(RECONFIGURE_OTA),
            "metal_device.mmio" => Some(METAL_DEVICE_MMIO),
            "metal_device.pcie" => Some(METAL_DEVICE_PCIE),
            "metal_device.dma" => Some(METAL_DEVICE_DMA),
            "seal_key" => Some(SEAL_KEY),
            "lend.borrow" => Some(LEND_BORROW),
            _ => None,
        }
    }

    /// The name of an op-level grant's bit.
    pub fn name(bit: u8) -> Option<&'static str> {
        match bit {
            KERNEL_SERIAL => Some("kernel.serial"),
            KERNEL_SIGNAL_CORE => Some("kernel.signal_core"),
            TIMER_DISCIPLINE => Some("timer.discipline"),
            RESOURCE_POOL_SAMPLE => Some("resource.pool_sample"),
            NET_POLICY_REPLACE => Some("net_policy.replace"),
            NET_ROUTE_TABLE => Some("net_route.table"),
            NET_ROUTE_STACK => Some("net_route.stack"),
            WORKLOAD_CREATE => Some("workload.create"),
            WORKLOAD_NET => Some("workload.net"),
            HOST_PROCESS_EXEC => Some("host_process.exec"),
            HOST_MOUNT_MOUNT => Some("host_mount.mount"),
            RECONFIGURE_OWNER => Some("reconfigure.owner"),
            RECONFIGURE_OTA => Some("reconfigure.ota"),
            METAL_DEVICE_MMIO => Some("metal_device.mmio"),
            METAL_DEVICE_PCIE => Some("metal_device.pcie"),
            METAL_DEVICE_DMA => Some("metal_device.dma"),
            SEAL_KEY => Some("seal_key"),
            LEND_BORROW => Some("lend.borrow"),
            _ => None,
        }
    }
}

/// The contracts whose own grant a gated module may not hold.
pub const CONTRACT_REACH_KERNEL: u64 = 0xfff9000020;

/// The functions the kernel calls in a module, by the FNV-1a hash of
/// their names: a module exports these and nothing else.
pub mod entry_point {
    /// Once per module type, before any instance: the syscall table.
    pub const MODULE_INIT: u32 = 0xfb8dc9bc;
    /// Initialise one instance's state from its ports and params.
    pub const MODULE_NEW: u32 = 0xe6d4ac90;
    /// One step of an instance; answers a step return.
    pub const MODULE_STEP: u32 = 0xc7ea2db4;
    /// Refill a pipelined instance's input between steps.
    pub const MODULE_PIPELINE_REFILL: u32 = 0xc9c83859;
    /// Flush an instance's output after every module has stepped.
    pub const MODULE_POST_TICK_FLUSH: u32 = 0x85d25b69;
    /// Drain an instance before a live reconfiguration removes it.
    pub const MODULE_DRAIN: u32 = 0xc4c5636c;
    /// The interrupt-tier entry of an ISR module.
    pub const MODULE_ISR_ENTRY: u32 = 0x56c6a743;
    /// Serve one call on a contract the manifest says the module provides.
    pub const MODULE_PROVIDER_DISPATCH: u32 = 0xc7832e76;
    /// The selector an instance-keyed provider registers under, from its config.
    pub const MODULE_PROVIDER_SELECTOR: u32 = 0xfd70b311;

    /// Every entry point, by name.
    pub const NAMES: [&str; 9] = [
        "module_init",
        "module_new",
        "module_step",
        "module_pipeline_refill",
        "module_post_tick_flush",
        "module_drain",
        "module_isr_entry",
        "module_provider_dispatch",
        "module_provider_selector",
    ];
    /// The entry points every module defines.
    pub const REQUIRED: [&str; 2] = ["module_new", "module_step"];
}

/// Negative return values.
pub mod errno {
    pub const OK: i32 = 0;
    pub const ERROR: i32 = -1;
    pub const EACCES: i32 = -13;
    pub const EFAULT: i32 = -14;
    pub const ENXIO: i32 = -6;
    pub const EBADF: i32 = -9;
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
    pub const NET_IDENT_PROVIDER: u32 = 0x004c;
    pub const BOOT_INCARNATION: u32 = 0x002f;
    pub const PROGRAM_INFO: u32 = 0x002b;
    pub const PROGRAM_READ: u32 = 0x002c;
    pub const SIGNING_ROOT: u32 = 0x002d;
    pub const SLOT_ADMITTED: u32 = 0x002e;
    pub const FLASH_LAYOUT: u32 = 0x002a;
    pub const MODULE_FLOW_BUDGET: u32 = 0x0046;
    pub const GET_HW_ETHERNET_MAC: u32 = 0x003d;
    pub const QUERY_OP: u32 = 0x00fe;
    pub const QUERY_CLASS: u32 = 0x0001;
    pub const QUERY_HEAP_STATS: u32 = 0x0006;
    pub const QUERY_LAST_FENCE: u32 = 0x0008;
    pub const QUERY_CALLER_OWNER: u32 = 0x0009;
    pub const QUERY_CALLER_MODULE: u32 = 0x000a;
    pub const QUERY_MODULE_LIVE: u32 = 0x000b;
    pub const SIGNAL_CORE: u32 = 0x0052;
    pub const BIND: u32 = 0x0053;
    pub const BIND_DOORBELL: u32 = 0x0054;
    pub const DOORBELL_RING: u32 = 0x0055;
}

pub mod channel {
    pub const ID: u16 = 0x0001;
    pub const OPEN: u32 = 0x0100;
    pub const CLOSE: u32 = 0x0101;
    pub const FLUSH: u32 = 0x0102;
    pub const SET_HUP: u32 = 0x0103;
    pub const WRITABLE: u32 = 0x0104;
    pub const RECORD_LEN: u32 = 0x0105;
    pub const FACTS: u32 = 0x0107;
    pub const PORT: u32 = 0x010c;
    pub const ACQUIRE_WRITE: u32 = 0x0110;
    pub const RELEASE_WRITE: u32 = 0x0111;
    pub const ACQUIRE_READ: u32 = 0x0112;
    pub const RELEASE_READ: u32 = 0x0113;
    pub const ACQUIRE_INPLACE: u32 = 0x0114;
}

pub mod timer {
    pub const ID: u16 = 0x0002;
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

pub mod stream_select {
    pub const ID: u16 = 0x0003;
    pub const SELECT: u32 = 0x0300;
}

pub mod event {
    pub const ID: u16 = 0x0004;
    pub const CREATE: u32 = 0x0400;
    pub const SIGNAL: u32 = 0x0401;
    pub const POLL: u32 = 0x0402;
    pub const DESTROY: u32 = 0x0403;
    pub const BIND_IRQ: u32 = 0x0451;
}

pub mod key_vault {
    pub const ID: u16 = 0x0005;
    pub const STORE: u32 = 0x0500;
    pub const ECDH: u32 = 0x0501;
    pub const SIGN: u32 = 0x0502;
    pub const VERIFY: u32 = 0x0503;
    pub const DESTROY: u32 = 0x0504;
    pub const GENERATE: u32 = 0x0505;
    pub const PUBLIC: u32 = 0x0506;
    pub const TIER: u32 = 0x0507;
    pub const OPEN_OR_GENERATE: u32 = 0x0508;
    pub const OPEN: u32 = 0x0509;
    pub const DESTROY_BY_LABEL: u32 = 0x050a;
    pub const DESCRIBE: u32 = 0x050b;
    pub const DESCRIBE_SUITE: u32 = 0x050c;
    pub const ATTEST_COMPOSITION: u32 = 0x050d;
    pub const KEY_WRAP: u32 = 0x050e;
    pub const KEY_UNWRAP: u32 = 0x050f;
    pub const AEAD_SEAL: u32 = 0x0510;
    pub const AEAD_OPEN: u32 = 0x0511;
    pub const DERIVE: u32 = 0x0512;
    pub const AEAD_SEAL_UNITS: u32 = 0x0513;
    pub const AEAD_OPEN_UNITS: u32 = 0x0514;
    pub const SHARE_SPLIT: u32 = 0x0515;
    pub const SHARE_REWRAP: u32 = 0x0516;
    pub const SHARE_COMBINE: u32 = 0x0517;
    pub const ATTEST_KEY: u32 = 0x0518;
}

pub mod gpio {
    pub const ID: u16 = 0x0006;
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
    pub const DESCRIBE: u32 = 0x070a;
    pub const CAPS: u32 = 0x07ff;
}

pub mod i2c {
    pub const ID: u16 = 0x0008;
    pub const OPEN: u32 = 0x0800;
    pub const CLOSE: u32 = 0x0801;
    pub const WRITE: u32 = 0x0802;
    pub const READ: u32 = 0x0803;
    pub const WRITE_READ: u32 = 0x0804;
    pub const CLAIM: u32 = 0x0805;
    pub const RELEASE: u32 = 0x0806;
    pub const POLL: u32 = 0x0807;
}

pub mod pio {
    pub const ID: u16 = 0x0009;
    pub const STREAM_ALLOC: u32 = 0x0900;
    pub const STREAM_LOAD_PROGRAM: u32 = 0x0901;
    pub const STREAM_CONFIGURE: u32 = 0x0903;
    pub const STREAM_CAN_PUSH: u32 = 0x0904;
    pub const STREAM_PUSH: u32 = 0x0905;
    pub const STREAM_FREE: u32 = 0x0906;
    pub const STREAM_TIME: u32 = 0x0907;
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
    pub const RX_STREAM_SET_RATE: u32 = 0x0927;
}

pub mod uart {
    pub const ID: u16 = 0x000a;
    pub const OPEN: u32 = 0x0a00;
    pub const CLOSE: u32 = 0x0a01;
    pub const WRITE: u32 = 0x0a02;
    pub const READ: u32 = 0x0a03;
    pub const POLL: u32 = 0x0a04;
    pub const CONFIGURE: u32 = 0x0a05;
}

pub mod adc {
    pub const ID: u16 = 0x000b;
    pub const OPEN: u32 = 0x0b00;
    pub const CLOSE: u32 = 0x0b01;
    pub const READ: u32 = 0x0b02;
    pub const POLL: u32 = 0x0b03;
    pub const CONFIGURE: u32 = 0x0b04;
}

pub mod pwm {
    pub const ID: u16 = 0x000c;
    pub const OPEN: u32 = 0x0c00;
    pub const CLOSE: u32 = 0x0c01;
    pub const CONFIGURE: u32 = 0x0c02;
    pub const SET_DUTY: u32 = 0x0c03;
    pub const GET_DUTY: u32 = 0x0c04;
}

pub mod fs {
    pub const ID: u16 = 0x000d;
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
    pub const LOOKUP: u32 = 0x0e00;
    pub const STAT: u32 = 0x0e01;
    pub const LIST: u32 = 0x0e02;
    pub const RENAME: u32 = 0x0e03;
    pub const DELETE: u32 = 0x0e04;
    pub const SUBSCRIBE: u32 = 0x0e05;
    pub const CLOSE: u32 = 0x0e06;
    pub const CHANGES: u32 = 0x0e07;
    pub const BIND: u32 = 0x0e08;
    pub const CAPS: u32 = 0x0eff;
}

pub mod storage_object {
    pub const ID: u16 = 0x000f;
    pub const PUT: u32 = 0x0f20;
    pub const GET: u32 = 0x0f21;
    pub const HEAD: u32 = 0x0f22;
    pub const RANGE_GET: u32 = 0x0f23;
    pub const DELETE: u32 = 0x0f24;
    pub const CLOSE: u32 = 0x0f25;
    pub const PUT_STREAMED_OPEN: u32 = 0x0f26;
    pub const PUT_STREAMED_WRITE: u32 = 0x0f27;
    pub const PUT_STREAMED_COMMIT: u32 = 0x0f28;
    pub const PUT_STREAMED_ABORT: u32 = 0x0f29;
    pub const RETAIN: u32 = 0x0f2c;
    pub const LIST: u32 = 0x0f2a;
    pub const PRESENT: u32 = 0x0f2b;
    pub const CAPS: u32 = 0x0fff;
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
    pub const VERIFY: u32 = 0x1400;
}

pub mod net_policy {
    pub const ID: u16 = 0x0015;
    pub const REPLACE: u32 = 0x1500;
    pub const CLEAR: u32 = 0x1501;
    pub const READ: u32 = 0x1502;
    pub const ATTACH: u32 = 0x1503;
    pub const CAPS: u32 = 0x15ff;
}

pub mod net_route {
    pub const ID: u16 = 0x0016;
    pub const SEGMENTS: u32 = 0x1600;
    pub const ROUTES: u32 = 0x1601;
    pub const HOLD: u32 = 0x1602;
    pub const READ: u32 = 0x1603;
    pub const REPORT: u32 = 0x1604;
    pub const TAKE: u32 = 0x1605;
    pub const CAPS: u32 = 0x16ff;
}

pub mod workload {
    pub const ID: u16 = 0x0017;
    pub const CREATE: u32 = 0x1700;
    pub const START: u32 = 0x1701;
    pub const WAIT: u32 = 0x1702;
    pub const SIGNAL: u32 = 0x1703;
    pub const DESTROY: u32 = 0x1704;
    pub const PAUSE: u32 = 0x170b;
    pub const RESUME: u32 = 0x170c;
    pub const LANE: u32 = 0x170d;
    pub const NET_PROVIDE: u32 = 0x170e;
    pub const NET_LANE_TAKE: u32 = 0x170f;
    pub const NET_LANE_ADMIT: u32 = 0x1710;
    pub const NET_RESOLVER: u32 = 0x1713;
    pub const LOOKUP: u32 = 0x1712;
    pub const MODULE_DIGESTS: u32 = 0x1711;
    pub const OPTIONS: u32 = 0x1714;
    pub const CAPS: u32 = 0x17ff;
}

pub mod host_process {
    pub const ID: u16 = 0x0018;
    pub const READ: u32 = 0x1800;
    pub const EXEC: u32 = 0x1801;
    pub const TTY_OPEN: u32 = 0x1802;
    pub const TTY_STEP: u32 = 0x1803;
    pub const TTY_RESIZE: u32 = 0x1804;
    pub const TTY_CLOSE: u32 = 0x1805;
    pub const CAPS: u32 = 0x18ff;
}

pub mod host_mount {
    pub const ID: u16 = 0x0019;
    pub const MOUNT: u32 = 0x1900;
    pub const UMOUNT: u32 = 0x1901;
    pub const ROOT: u32 = 0x1902;
    pub const PROJECT: u32 = 0x1903;
    pub const REMOVE_TREE: u32 = 0x1904;
    pub const GROUP_TREE: u32 = 0x1905;
    pub const MKDIR_MODE: u32 = 0x1906;
    pub const CAPS: u32 = 0x19ff;
}

pub mod proc {
    pub const ID: u16 = 0x001a;
    pub const PROC_SPAWN: u32 = 0x1a00;
    pub const PROC_READ: u32 = 0x1a01;
    pub const PROC_STATUS: u32 = 0x1a02;
    pub const PROC_CLOSE: u32 = 0x1a03;
}

pub mod usb_host {
    pub const ID: u16 = 0x001b;
}

pub mod pcie_device {
    pub const ID: u16 = 0x001c;
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
    pub const NIC_BAR_MAP: u32 = 0x1df0;
    pub const NIC_BAR_UNMAP: u32 = 0x1df1;
    pub const NIC_RING_CREATE: u32 = 0x1df2;
    pub const NIC_RING_DESTROY: u32 = 0x1df3;
    pub const NIC_RING_INFO: u32 = 0x1df4;
}

pub mod platform_dma {
    pub const ID: u16 = 0x001e;
    pub const ALLOC: u32 = 0x1e80;
    pub const FREE: u32 = 0x1e81;
    pub const START: u32 = 0x1e82;
    pub const BUSY: u32 = 0x1e83;
    pub const ABORT: u32 = 0x1e84;
    pub const CHANNEL: u32 = 0x1e85;
}

pub mod platform_dma_fd {
    pub const ID: u16 = 0x001f;
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
    pub const WRITE: u32 = 0x22e0;
    pub const READ: u32 = 0x22e1;
    pub const POLL: u32 = 0x22e2;
    pub const INFO: u32 = 0x22e3;
    pub const SELF_BRIDGE: u32 = 0x2244;
}

pub mod flash {
    pub const ID: u16 = 0x0023;
    pub const RAW_ERASE: u32 = 0x2338;
    pub const RAW_PROGRAM: u32 = 0x2339;
    pub const SIDEBAND: u32 = 0x2310;
}

pub mod diag {
    pub const ID: u16 = 0x0025;
    pub const LOG_RING_DRAIN: u32 = 0x2564;
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
    pub const CLAIM: u32 = 0x2750;
    pub const RELEASE: u32 = 0x2751;
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
    pub const ID: u16 = 0x0024;
    pub const MMIO_OPEN: u32 = 0x24e8;
    pub const MMIO_READ32: u32 = 0x24e4;
    pub const MMIO_WRITE32: u32 = 0x24e5;
    pub const DMA_ALLOC_CONTIG: u32 = 0x24e6;
    pub const CACHE_FLUSH_RANGE: u32 = 0x24e7;
    pub const DMA_FLUSH: u32 = 0x24ea;
    pub const DMA_INVALIDATE: u32 = 0x24eb;
    pub const DMA_ALLOC_STREAMING: u32 = 0x24ec;
    pub const PCIE_RESCAN: u32 = 0x24f5;
    pub const PCIE_CFG_READ32: u32 = 0x24f6;
    pub const PCIE_CFG_WRITE32: u32 = 0x24f7;
}

pub mod storage_custody {
    pub const ID: u16 = 0x0028;
    pub const SEAL: u32 = 0x2800;
    pub const OPEN: u32 = 0x2801;
    pub const CUSTODIAN: u32 = 0x2802;
    pub const SPLIT: u32 = 0x2803;
    pub const DRILL: u32 = 0x2804;
}

pub mod lend {
    pub const ID: u16 = 0x0029;
    pub const OPEN: u32 = 0x2900;
    pub const RESOLVE: u32 = 0x2901;
    pub const RETURN: u32 = 0x2902;
    pub const CLOSE: u32 = 0x2903;
}

pub mod storage_block {
    pub const ID: u16 = 0x002a;
    pub const DESCRIBE: u32 = 0x2a00;
    pub const SUBMIT: u32 = 0x2a01;
    pub const REAP: u32 = 0x2a02;
    pub const EXEC: u32 = 0x2a03;
    pub const READ_STREAM: u32 = 0x2a04;
}

pub mod net_tx_drain {
    pub const ID: u16 = 0x002b;
    pub const DRAINED: u32 = 0x2b00;
}

pub mod image_decode {
    pub const ID: u16 = 0x002c;
    pub const DECODE: u32 = 0x2c00;
    pub const RECV: u32 = 0x2c01;
    pub const CLOSE: u32 = 0x2c02;
}

/// The contract a manifest names (`requires_contract`, `provides`).
pub fn contract_of_name(name: &str) -> Option<u16> {
    match name {
        "channel" => Some(0x0001),
        "timer" => Some(0x0002),
        "stream_select" => Some(0x0003),
        "event" => Some(0x0004),
        "key_vault" => Some(0x0005),
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
        "metal_device" => Some(0x0024),
        "storage.custody" => Some(0x0028),
        "storage.block" => Some(0x002a),
        "net_tx_drain" => Some(0x002b),
        "image_decode" => Some(0x002c),
        _ => None,
    }
}

/// The contract a registry name stands for, whether or not a manifest
/// may claim it: a manifest's `grants` may name any contract.
pub fn contract_id(name: &str) -> Option<u16> {
    match name {
        "kernel" => Some(0x0000),
        "channel" => Some(0x0001),
        "timer" => Some(0x0002),
        "stream_select" => Some(0x0003),
        "event" => Some(0x0004),
        "key_vault" => Some(0x0005),
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
        "telemetry" => Some(0x0010),
        "resource" => Some(0x0011),
        "runtime_params" => Some(0x0012),
        "stream_clock" => Some(0x0013),
        "trust" => Some(0x0014),
        "net_policy" => Some(0x0015),
        "net_route" => Some(0x0016),
        "workload" => Some(0x0017),
        "host_process" => Some(0x0018),
        "host_mount" => Some(0x0019),
        "proc" => Some(0x001a),
        "usb_host" => Some(0x001b),
        "pcie_device" => Some(0x001c),
        "platform_nic_ring" => Some(0x001d),
        "platform_dma" => Some(0x001e),
        "platform_dma_fd" => Some(0x001f),
        "reconfigure" => Some(0x0020),
        "monitor" => Some(0x0021),
        "bridge" => Some(0x0022),
        "flash" => Some(0x0023),
        "diag" => Some(0x0025),
        "vault_store" => Some(0x0026),
        "rp_raw" => Some(0x0027),
        "metal_device" => Some(0x0024),
        "storage.custody" => Some(0x0028),
        "lend" => Some(0x0029),
        "storage.block" => Some(0x002a),
        "net_tx_drain" => Some(0x002b),
        "image_decode" => Some(0x002c),
        _ => None,
    }
}

/// The registry name of a contract id.
pub fn contract_name(id: u16) -> Option<&'static str> {
    match id {
        0x0000 => Some("kernel"),
        0x0001 => Some("channel"),
        0x0002 => Some("timer"),
        0x0003 => Some("stream_select"),
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
        0x0024 => Some("metal_device"),
        0x0025 => Some("diag"),
        0x0026 => Some("vault_store"),
        0x0027 => Some("rp_raw"),
        0x0028 => Some("storage.custody"),
        0x0029 => Some("lend"),
        0x002a => Some("storage.block"),
        0x002b => Some("net_tx_drain"),
        0x002c => Some("image_decode"),
        _ => None,
    }
}

/// Whether a module may serve the contract as a provider
/// (`provider_contracts`); the kernel registers a module for no other.
pub fn module_providable(id: u16) -> bool {
    matches!(
        id,
        0x0003
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
            | 0x0012
            | 0x0028
            | 0x002a
            | 0x002b
            | 0x002c
    )
}

/// How many contracts a manifest may name.
pub const MANIFEST_CONTRACTS: usize = 31;

/// The `i`th contract a manifest may name, in registry order.
pub fn manifest_contract(i: usize) -> Option<&'static str> {
    match i {
        0 => Some("channel"),
        1 => Some("timer"),
        2 => Some("stream_select"),
        3 => Some("event"),
        4 => Some("key_vault"),
        5 => Some("gpio"),
        6 => Some("spi"),
        7 => Some("i2c"),
        8 => Some("pio"),
        9 => Some("uart"),
        10 => Some("adc"),
        11 => Some("pwm"),
        12 => Some("fs"),
        13 => Some("storage.namespace"),
        14 => Some("storage.object"),
        15 => Some("trust"),
        16 => Some("net_policy"),
        17 => Some("net_route"),
        18 => Some("workload"),
        19 => Some("host_mount"),
        20 => Some("proc"),
        21 => Some("usb_host"),
        22 => Some("pcie_device"),
        23 => Some("platform_nic_ring"),
        24 => Some("platform_dma"),
        25 => Some("platform_dma_fd"),
        26 => Some("metal_device"),
        27 => Some("storage.custody"),
        28 => Some("storage.block"),
        29 => Some("net_tx_drain"),
        30 => Some("image_decode"),
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
            | 0x25
            | 0x27
            | 0x29
    ) && !matches!(op, 0x00fe)
}

/// Whether an opcode class byte belongs to the registry: ids are dense.
pub fn class_registered(class: u32) -> bool {
    (class as usize) < CONTRACTS_ASSIGNED
}

/// Whether a contract is served across a graph edge: by the module at
/// the other end of the caller's port, through a handle bound to it.
pub fn contract_is_edge(id: u16) -> bool {
    matches!(id, 0x0003 | 0x002a | 0x002b)
}

/// The handle word: bit 31 clear (a negative value is an errno), then
/// the contract, the generation and the index. The kernel mints every
/// handle a module holds; a provider sees only its own index.
pub mod handle {
    pub const CONTRACT_BITS: u32 = 7;
    pub const GEN_BITS: u32 = 9;
    pub const INDEX_BITS: u32 = 15;
    pub const GEN_SHIFT: u32 = INDEX_BITS;
    pub const CONTRACT_SHIFT: u32 = INDEX_BITS + GEN_BITS;
    pub const CONTRACT_MASK: u16 = (1 << CONTRACT_BITS) - 1;
    pub const GEN_MASK: u16 = (1 << GEN_BITS) - 1;
    pub const INDEX_MASK: u32 = (1 << INDEX_BITS) - 1;
    /// Slots a table whose index a handle names may hold.
    pub const INDEX_LIMIT: usize = 1 << INDEX_BITS;

    /// The handle naming slot `index` of `contract`'s table at `generation`;
    /// fields wider than theirs are truncated.
    pub const fn encode(contract: u16, generation: u16, index: u32) -> i32 {
        ((((contract & CONTRACT_MASK) as u32) << CONTRACT_SHIFT)
            | (((generation & GEN_MASK) as u32) << GEN_SHIFT)
            | (index & INDEX_MASK)) as i32
    }

    /// `(contract, generation, index)` of a handle; `None` for a negative
    /// value, which is an errno.
    pub const fn decode(h: i32) -> Option<(u16, u16, u32)> {
        if h < 0 {
            return None;
        }
        let h = h as u32;
        Some((
            ((h >> CONTRACT_SHIFT) as u16) & CONTRACT_MASK,
            ((h >> GEN_SHIFT) as u16) & GEN_MASK,
            h & INDEX_MASK,
        ))
    }

    /// The contract a handle names, if it is one.
    pub const fn contract_of(h: i32) -> Option<u16> {
        match decode(h) {
            Some((c, _, _)) => Some(c),
            None => None,
        }
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
        /// Value ranges this surface owns, each filled densely.
        pub const RANGE_COUNT: usize = 2;
        /// The `i`th range this surface owns, `(first, last)`.
        pub const fn range(i: usize) -> Option<(u8, u8)> {
            match i {
                0 => Some((0x20, 0x22)),
                1 => Some((0x40, 0x43)),
                _ => None,
            }
        }
        /// Whether this surface owns message type `v`.
        pub const fn owns(v: u8) -> bool {
            matches!(v, 0x20..=0x22 | 0x40..=0x43)
        }
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
        pub const MSG_PEER: u8 = 0x07;
        pub const CMD_BIND: u8 = 0x10;
        pub const CMD_SEND: u8 = 0x11;
        pub const CMD_CLOSE: u8 = 0x12;
        pub const CMD_CONNECT_TO: u8 = 0x13;
        /// Value ranges this surface owns, each filled densely.
        pub const RANGE_COUNT: usize = 2;
        /// The `i`th range this surface owns, `(first, last)`.
        pub const fn range(i: usize) -> Option<(u8, u8)> {
            match i {
                0 => Some((0x01, 0x07)),
                1 => Some((0x10, 0x13)),
                _ => None,
            }
        }
        /// Whether this surface owns message type `v`.
        pub const fn owns(v: u8) -> bool {
            matches!(v, 0x01..=0x07 | 0x10..=0x13)
        }
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
    pub mod stream_cursor {
        pub const MSG_CURSOR_HORIZON: u8 = 0xd4;
        pub const MSG_CURSOR_RESUMED: u8 = 0xd5;
        pub const CMD_CURSOR_DELIVERED: u8 = 0xd6;
        /// Value ranges this surface owns, each filled densely.
        pub const RANGE_COUNT: usize = 1;
        /// The `i`th range this surface owns, `(first, last)`.
        pub const fn range(i: usize) -> Option<(u8, u8)> {
            match i {
                0 => Some((0xd4, 0xd6)),
                _ => None,
            }
        }
        /// Whether this surface owns message type `v`.
        pub const fn owns(v: u8) -> bool {
            matches!(v, 0xd4..=0xd6)
        }
    }
    pub mod stream_retx {
        pub const MSG_RETX_ACK: u8 = 0xd0;
        pub const MSG_RETX_REQUEST: u8 = 0xd1;
        pub const CMD_RETX_RESEND: u8 = 0xd2;
        /// Value ranges this surface owns, each filled densely.
        pub const RANGE_COUNT: usize = 1;
        /// The `i`th range this surface owns, `(first, last)`.
        pub const fn range(i: usize) -> Option<(u8, u8)> {
            match i {
                0 => Some((0xd0, 0xd2)),
                _ => None,
            }
        }
        /// Whether this surface owns message type `v`.
        pub const fn owns(v: u8) -> bool {
            matches!(v, 0xd0..=0xd2)
        }
    }
    pub mod stream_trace {
        pub const MSG_TRACE_CTX: u8 = 0xd3;
        /// Value ranges this surface owns, each filled densely.
        pub const RANGE_COUNT: usize = 1;
        /// The `i`th range this surface owns, `(first, last)`.
        pub const fn range(i: usize) -> Option<(u8, u8)> {
            match i {
                0 => Some((0xd3, 0xd3)),
                _ => None,
            }
        }
        /// Whether this surface owns message type `v`.
        pub const fn owns(v: u8) -> bool {
            matches!(v, 0xd3..=0xd3)
        }
    }
}

/// What calling an op needs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpGrant {
    /// Nothing: every module may call it.
    Free,
    /// The contract's own grant: its id's bit in the first word.
    Contract(u16),
    /// An op-level grant: its bit in the second word.
    Grant(u8),
}

/// The grant `op` needs, or `None` when the registry does not list it:
/// an op the registry does not list does not exist.
pub fn op_grant(op: u32) -> Option<OpGrant> {
    match op {
        0x0001 => Some(OpGrant::Free),
        0x0006 => Some(OpGrant::Free),
        0x0008 => Some(OpGrant::Free),
        0x0009 => Some(OpGrant::Free),
        0x000a => Some(OpGrant::Free),
        0x000b => Some(OpGrant::Free),
        0x002a => Some(OpGrant::Free),
        0x002b => Some(OpGrant::Free),
        0x002c => Some(OpGrant::Free),
        0x002d => Some(OpGrant::Free),
        0x002e => Some(OpGrant::Free),
        0x002f => Some(OpGrant::Free),
        0x0030 => Some(OpGrant::Free),
        0x0031 => Some(OpGrant::Free),
        0x0033 => Some(OpGrant::Free),
        0x003a => Some(OpGrant::Free),
        0x003b => Some(OpGrant::Free),
        0x003c => Some(OpGrant::Free),
        0x003d => Some(OpGrant::Free),
        0x0040 => Some(OpGrant::Free),
        0x0041 => Some(OpGrant::Free),
        0x0042 => Some(OpGrant::Free),
        0x0043 => Some(OpGrant::Free),
        0x0045 => Some(OpGrant::Free),
        0x0046 => Some(OpGrant::Free),
        0x004c => Some(OpGrant::Free),
        0x0050 => Some(OpGrant::Free),
        0x0052 => Some(OpGrant::Grant(grant::KERNEL_SIGNAL_CORE)),
        0x0053 => Some(OpGrant::Free),
        0x0054 => Some(OpGrant::Free),
        0x0055 => Some(OpGrant::Free),
        0x0066 => Some(OpGrant::Grant(grant::KERNEL_SERIAL)),
        0x00fe => Some(OpGrant::Free),
        0x0100 => Some(OpGrant::Free),
        0x0101 => Some(OpGrant::Free),
        0x0102 => Some(OpGrant::Free),
        0x0103 => Some(OpGrant::Free),
        0x0104 => Some(OpGrant::Free),
        0x0105 => Some(OpGrant::Free),
        0x0107 => Some(OpGrant::Free),
        0x010c => Some(OpGrant::Free),
        0x0110 => Some(OpGrant::Free),
        0x0111 => Some(OpGrant::Free),
        0x0112 => Some(OpGrant::Free),
        0x0113 => Some(OpGrant::Free),
        0x0114 => Some(OpGrant::Free),
        0x0202 => Some(OpGrant::Free),
        0x0203 => Some(OpGrant::Free),
        0x0204 => Some(OpGrant::Free),
        0x0205 => Some(OpGrant::Free),
        0x0206 => Some(OpGrant::Free),
        0x0207 => Some(OpGrant::Free),
        0x0208 => Some(OpGrant::Free),
        0x0209 => Some(OpGrant::Free),
        0x020a => Some(OpGrant::Grant(grant::TIMER_DISCIPLINE)),
        0x0300 => Some(OpGrant::Contract(0x0003)),
        0x0400 => Some(OpGrant::Free),
        0x0401 => Some(OpGrant::Free),
        0x0402 => Some(OpGrant::Free),
        0x0403 => Some(OpGrant::Free),
        0x0451 => Some(OpGrant::Free),
        0x0500 => Some(OpGrant::Contract(0x0005)),
        0x0501 => Some(OpGrant::Contract(0x0005)),
        0x0502 => Some(OpGrant::Contract(0x0005)),
        0x0503 => Some(OpGrant::Contract(0x0005)),
        0x0504 => Some(OpGrant::Contract(0x0005)),
        0x0505 => Some(OpGrant::Contract(0x0005)),
        0x0506 => Some(OpGrant::Contract(0x0005)),
        0x0507 => Some(OpGrant::Contract(0x0005)),
        0x0508 => Some(OpGrant::Contract(0x0005)),
        0x0509 => Some(OpGrant::Contract(0x0005)),
        0x050a => Some(OpGrant::Contract(0x0005)),
        0x050b => Some(OpGrant::Contract(0x0005)),
        0x050c => Some(OpGrant::Contract(0x0005)),
        0x050d => Some(OpGrant::Contract(0x0005)),
        0x050e => Some(OpGrant::Contract(0x0005)),
        0x050f => Some(OpGrant::Contract(0x0005)),
        0x0510 => Some(OpGrant::Contract(0x0005)),
        0x0511 => Some(OpGrant::Contract(0x0005)),
        0x0512 => Some(OpGrant::Contract(0x0005)),
        0x0513 => Some(OpGrant::Contract(0x0005)),
        0x0514 => Some(OpGrant::Contract(0x0005)),
        0x0515 => Some(OpGrant::Contract(0x0005)),
        0x0516 => Some(OpGrant::Contract(0x0005)),
        0x0517 => Some(OpGrant::Contract(0x0005)),
        0x0518 => Some(OpGrant::Contract(0x0005)),
        0x0600 => Some(OpGrant::Contract(0x0006)),
        0x0601 => Some(OpGrant::Contract(0x0006)),
        0x0602 => Some(OpGrant::Contract(0x0006)),
        0x0603 => Some(OpGrant::Contract(0x0006)),
        0x0604 => Some(OpGrant::Contract(0x0006)),
        0x0605 => Some(OpGrant::Contract(0x0006)),
        0x0606 => Some(OpGrant::Contract(0x0006)),
        0x0607 => Some(OpGrant::Contract(0x0006)),
        0x060a => Some(OpGrant::Contract(0x0006)),
        0x0700 => Some(OpGrant::Contract(0x0007)),
        0x0701 => Some(OpGrant::Contract(0x0007)),
        0x0702 => Some(OpGrant::Contract(0x0007)),
        0x0703 => Some(OpGrant::Contract(0x0007)),
        0x0704 => Some(OpGrant::Contract(0x0007)),
        0x0705 => Some(OpGrant::Contract(0x0007)),
        0x0706 => Some(OpGrant::Contract(0x0007)),
        0x0707 => Some(OpGrant::Contract(0x0007)),
        0x0708 => Some(OpGrant::Contract(0x0007)),
        0x0709 => Some(OpGrant::Contract(0x0007)),
        0x070a => Some(OpGrant::Contract(0x0007)),
        0x07ff => Some(OpGrant::Contract(0x0007)),
        0x0800 => Some(OpGrant::Contract(0x0008)),
        0x0801 => Some(OpGrant::Contract(0x0008)),
        0x0802 => Some(OpGrant::Contract(0x0008)),
        0x0803 => Some(OpGrant::Contract(0x0008)),
        0x0804 => Some(OpGrant::Contract(0x0008)),
        0x0805 => Some(OpGrant::Contract(0x0008)),
        0x0806 => Some(OpGrant::Contract(0x0008)),
        0x0807 => Some(OpGrant::Contract(0x0008)),
        0x0900 => Some(OpGrant::Contract(0x0009)),
        0x0901 => Some(OpGrant::Contract(0x0009)),
        0x0903 => Some(OpGrant::Contract(0x0009)),
        0x0904 => Some(OpGrant::Contract(0x0009)),
        0x0905 => Some(OpGrant::Contract(0x0009)),
        0x0906 => Some(OpGrant::Contract(0x0009)),
        0x0907 => Some(OpGrant::Contract(0x0009)),
        0x090a => Some(OpGrant::Contract(0x0009)),
        0x090b => Some(OpGrant::Contract(0x0009)),
        0x0910 => Some(OpGrant::Contract(0x0009)),
        0x0911 => Some(OpGrant::Contract(0x0009)),
        0x0912 => Some(OpGrant::Contract(0x0009)),
        0x0913 => Some(OpGrant::Contract(0x0009)),
        0x0914 => Some(OpGrant::Contract(0x0009)),
        0x0915 => Some(OpGrant::Contract(0x0009)),
        0x0916 => Some(OpGrant::Contract(0x0009)),
        0x0920 => Some(OpGrant::Contract(0x0009)),
        0x0921 => Some(OpGrant::Contract(0x0009)),
        0x0922 => Some(OpGrant::Contract(0x0009)),
        0x0923 => Some(OpGrant::Contract(0x0009)),
        0x0924 => Some(OpGrant::Contract(0x0009)),
        0x0925 => Some(OpGrant::Contract(0x0009)),
        0x0927 => Some(OpGrant::Contract(0x0009)),
        0x0a00 => Some(OpGrant::Contract(0x000a)),
        0x0a01 => Some(OpGrant::Contract(0x000a)),
        0x0a02 => Some(OpGrant::Contract(0x000a)),
        0x0a03 => Some(OpGrant::Contract(0x000a)),
        0x0a04 => Some(OpGrant::Contract(0x000a)),
        0x0a05 => Some(OpGrant::Contract(0x000a)),
        0x0b00 => Some(OpGrant::Contract(0x000b)),
        0x0b01 => Some(OpGrant::Contract(0x000b)),
        0x0b02 => Some(OpGrant::Contract(0x000b)),
        0x0b03 => Some(OpGrant::Contract(0x000b)),
        0x0b04 => Some(OpGrant::Contract(0x000b)),
        0x0c00 => Some(OpGrant::Contract(0x000c)),
        0x0c01 => Some(OpGrant::Contract(0x000c)),
        0x0c02 => Some(OpGrant::Contract(0x000c)),
        0x0c03 => Some(OpGrant::Contract(0x000c)),
        0x0c04 => Some(OpGrant::Contract(0x000c)),
        0x0d00 => Some(OpGrant::Contract(0x000d)),
        0x0d01 => Some(OpGrant::Contract(0x000d)),
        0x0d02 => Some(OpGrant::Contract(0x000d)),
        0x0d03 => Some(OpGrant::Contract(0x000d)),
        0x0d04 => Some(OpGrant::Contract(0x000d)),
        0x0d05 => Some(OpGrant::Contract(0x000d)),
        0x0d06 => Some(OpGrant::Contract(0x000d)),
        0x0d07 => Some(OpGrant::Contract(0x000d)),
        0x0d08 => Some(OpGrant::Contract(0x000d)),
        0x0d09 => Some(OpGrant::Contract(0x000d)),
        0x0d0a => Some(OpGrant::Contract(0x000d)),
        0x0d0b => Some(OpGrant::Contract(0x000d)),
        0x0d0c => Some(OpGrant::Contract(0x000d)),
        0x0d0d => Some(OpGrant::Contract(0x000d)),
        0x0d0e => Some(OpGrant::Contract(0x000d)),
        0x0d0f => Some(OpGrant::Contract(0x000d)),
        0x0d10 => Some(OpGrant::Contract(0x000d)),
        0x0d11 => Some(OpGrant::Contract(0x000d)),
        0x0d12 => Some(OpGrant::Contract(0x000d)),
        0x0d13 => Some(OpGrant::Contract(0x000d)),
        0x0d14 => Some(OpGrant::Contract(0x000d)),
        0x0d15 => Some(OpGrant::Contract(0x000d)),
        0x0dff => Some(OpGrant::Contract(0x000d)),
        0x0e00 => Some(OpGrant::Contract(0x000e)),
        0x0e01 => Some(OpGrant::Contract(0x000e)),
        0x0e02 => Some(OpGrant::Contract(0x000e)),
        0x0e03 => Some(OpGrant::Contract(0x000e)),
        0x0e04 => Some(OpGrant::Contract(0x000e)),
        0x0e05 => Some(OpGrant::Contract(0x000e)),
        0x0e06 => Some(OpGrant::Contract(0x000e)),
        0x0e07 => Some(OpGrant::Contract(0x000e)),
        0x0e08 => Some(OpGrant::Contract(0x000e)),
        0x0eff => Some(OpGrant::Contract(0x000e)),
        0x0f20 => Some(OpGrant::Contract(0x000f)),
        0x0f21 => Some(OpGrant::Contract(0x000f)),
        0x0f22 => Some(OpGrant::Contract(0x000f)),
        0x0f23 => Some(OpGrant::Contract(0x000f)),
        0x0f24 => Some(OpGrant::Contract(0x000f)),
        0x0f25 => Some(OpGrant::Contract(0x000f)),
        0x0f26 => Some(OpGrant::Contract(0x000f)),
        0x0f27 => Some(OpGrant::Contract(0x000f)),
        0x0f28 => Some(OpGrant::Contract(0x000f)),
        0x0f29 => Some(OpGrant::Contract(0x000f)),
        0x0f2a => Some(OpGrant::Contract(0x000f)),
        0x0f2b => Some(OpGrant::Contract(0x000f)),
        0x0f2c => Some(OpGrant::Contract(0x000f)),
        0x0fff => Some(OpGrant::Contract(0x000f)),
        0x103e => Some(OpGrant::Free),
        0x104d => Some(OpGrant::Contract(0x0010)),
        0x104e => Some(OpGrant::Contract(0x0010)),
        0x104f => Some(OpGrant::Contract(0x0010)),
        0x1124 => Some(OpGrant::Free),
        0x1125 => Some(OpGrant::Grant(grant::RESOURCE_POOL_SAMPLE)),
        0x113f => Some(OpGrant::Free),
        0x1234 => Some(OpGrant::Free),
        0x1235 => Some(OpGrant::Free),
        0x1236 => Some(OpGrant::Free),
        0x1300 => Some(OpGrant::Contract(0x0013)),
        0x1400 => Some(OpGrant::Contract(0x0014)),
        0x1500 => Some(OpGrant::Grant(grant::NET_POLICY_REPLACE)),
        0x1501 => Some(OpGrant::Grant(grant::NET_POLICY_REPLACE)),
        0x1502 => Some(OpGrant::Contract(0x0015)),
        0x1503 => Some(OpGrant::Contract(0x0015)),
        0x15ff => Some(OpGrant::Contract(0x0015)),
        0x1600 => Some(OpGrant::Grant(grant::NET_ROUTE_TABLE)),
        0x1601 => Some(OpGrant::Grant(grant::NET_ROUTE_TABLE)),
        0x1602 => Some(OpGrant::Grant(grant::NET_ROUTE_TABLE)),
        0x1603 => Some(OpGrant::Grant(grant::NET_ROUTE_TABLE)),
        0x1604 => Some(OpGrant::Grant(grant::NET_ROUTE_STACK)),
        0x1605 => Some(OpGrant::Grant(grant::NET_ROUTE_STACK)),
        0x16ff => Some(OpGrant::Contract(0x0016)),
        0x1700 => Some(OpGrant::Grant(grant::WORKLOAD_CREATE)),
        0x1701 => Some(OpGrant::Grant(grant::WORKLOAD_CREATE)),
        0x1702 => Some(OpGrant::Grant(grant::WORKLOAD_CREATE)),
        0x1703 => Some(OpGrant::Grant(grant::WORKLOAD_CREATE)),
        0x1704 => Some(OpGrant::Grant(grant::WORKLOAD_CREATE)),
        0x170b => Some(OpGrant::Grant(grant::WORKLOAD_CREATE)),
        0x170c => Some(OpGrant::Grant(grant::WORKLOAD_CREATE)),
        0x170d => Some(OpGrant::Grant(grant::WORKLOAD_CREATE)),
        0x170e => Some(OpGrant::Grant(grant::WORKLOAD_NET)),
        0x170f => Some(OpGrant::Grant(grant::WORKLOAD_NET)),
        0x1710 => Some(OpGrant::Grant(grant::WORKLOAD_NET)),
        0x1711 => Some(OpGrant::Grant(grant::WORKLOAD_CREATE)),
        0x1712 => Some(OpGrant::Grant(grant::WORKLOAD_CREATE)),
        0x1713 => Some(OpGrant::Grant(grant::WORKLOAD_NET)),
        0x1714 => Some(OpGrant::Grant(grant::WORKLOAD_CREATE)),
        0x17ff => Some(OpGrant::Grant(grant::WORKLOAD_CREATE)),
        0x1800 => Some(OpGrant::Grant(grant::HOST_PROCESS_EXEC)),
        0x1801 => Some(OpGrant::Grant(grant::HOST_PROCESS_EXEC)),
        0x1802 => Some(OpGrant::Grant(grant::HOST_PROCESS_EXEC)),
        0x1803 => Some(OpGrant::Grant(grant::HOST_PROCESS_EXEC)),
        0x1804 => Some(OpGrant::Grant(grant::HOST_PROCESS_EXEC)),
        0x1805 => Some(OpGrant::Grant(grant::HOST_PROCESS_EXEC)),
        0x18ff => Some(OpGrant::Grant(grant::HOST_PROCESS_EXEC)),
        0x1900 => Some(OpGrant::Grant(grant::HOST_MOUNT_MOUNT)),
        0x1901 => Some(OpGrant::Grant(grant::HOST_MOUNT_MOUNT)),
        0x1902 => Some(OpGrant::Contract(0x0019)),
        0x1903 => Some(OpGrant::Grant(grant::HOST_MOUNT_MOUNT)),
        0x1904 => Some(OpGrant::Grant(grant::HOST_MOUNT_MOUNT)),
        0x1905 => Some(OpGrant::Grant(grant::HOST_MOUNT_MOUNT)),
        0x1906 => Some(OpGrant::Grant(grant::HOST_MOUNT_MOUNT)),
        0x19ff => Some(OpGrant::Contract(0x0019)),
        0x1a00 => Some(OpGrant::Contract(0x001a)),
        0x1a01 => Some(OpGrant::Contract(0x001a)),
        0x1a02 => Some(OpGrant::Contract(0x001a)),
        0x1a03 => Some(OpGrant::Contract(0x001a)),
        0x1ca0 => Some(OpGrant::Contract(0x001c)),
        0x1ca1 => Some(OpGrant::Contract(0x001c)),
        0x1ca2 => Some(OpGrant::Contract(0x001c)),
        0x1ca3 => Some(OpGrant::Contract(0x001c)),
        0x1ca4 => Some(OpGrant::Contract(0x001c)),
        0x1ca5 => Some(OpGrant::Contract(0x001c)),
        0x1ca6 => Some(OpGrant::Contract(0x001c)),
        0x1df0 => Some(OpGrant::Contract(0x001d)),
        0x1df1 => Some(OpGrant::Contract(0x001d)),
        0x1df2 => Some(OpGrant::Contract(0x001d)),
        0x1df3 => Some(OpGrant::Contract(0x001d)),
        0x1df4 => Some(OpGrant::Contract(0x001d)),
        0x1e80 => Some(OpGrant::Contract(0x001e)),
        0x1e81 => Some(OpGrant::Contract(0x001e)),
        0x1e82 => Some(OpGrant::Contract(0x001e)),
        0x1e83 => Some(OpGrant::Contract(0x001e)),
        0x1e84 => Some(OpGrant::Contract(0x001e)),
        0x1e85 => Some(OpGrant::Contract(0x001e)),
        0x1f85 => Some(OpGrant::Contract(0x001f)),
        0x1f86 => Some(OpGrant::Contract(0x001f)),
        0x1f87 => Some(OpGrant::Contract(0x001f)),
        0x1f88 => Some(OpGrant::Contract(0x001f)),
        0x1f89 => Some(OpGrant::Contract(0x001f)),
        0x2020 => Some(OpGrant::Grant(grant::RECONFIGURE_OTA)),
        0x2021 => Some(OpGrant::Grant(grant::RECONFIGURE_OTA)),
        0x2022 => Some(OpGrant::Grant(grant::RECONFIGURE_OWNER)),
        0x2023 => Some(OpGrant::Contract(0x0020)),
        0x2047 => Some(OpGrant::Grant(grant::RECONFIGURE_OWNER)),
        0x2048 => Some(OpGrant::Grant(grant::RECONFIGURE_OWNER)),
        0x2049 => Some(OpGrant::Grant(grant::RECONFIGURE_OWNER)),
        0x204a => Some(OpGrant::Grant(grant::RECONFIGURE_OWNER)),
        0x2068 => Some(OpGrant::Contract(0x0020)),
        0x2069 => Some(OpGrant::Contract(0x0020)),
        0x206a => Some(OpGrant::Contract(0x0020)),
        0x206b => Some(OpGrant::Contract(0x0020)),
        0x206c => Some(OpGrant::Contract(0x0020)),
        0x206d => Some(OpGrant::Contract(0x0020)),
        0x206e => Some(OpGrant::Contract(0x0020)),
        0x206f => Some(OpGrant::Contract(0x0020)),
        0x2132 => Some(OpGrant::Contract(0x0021)),
        0x2152 => Some(OpGrant::Contract(0x0021)),
        0x2153 => Some(OpGrant::Contract(0x0021)),
        0x2154 => Some(OpGrant::Contract(0x0021)),
        0x2155 => Some(OpGrant::Contract(0x0021)),
        0x2156 => Some(OpGrant::Contract(0x0021)),
        0x2157 => Some(OpGrant::Contract(0x0021)),
        0x21e8 => Some(OpGrant::Free),
        0x2244 => Some(OpGrant::Free),
        0x22e0 => Some(OpGrant::Contract(0x0022)),
        0x22e1 => Some(OpGrant::Contract(0x0022)),
        0x22e2 => Some(OpGrant::Contract(0x0022)),
        0x22e3 => Some(OpGrant::Contract(0x0022)),
        0x2310 => Some(OpGrant::Contract(0x0023)),
        0x2338 => Some(OpGrant::Contract(0x0023)),
        0x2339 => Some(OpGrant::Contract(0x0023)),
        0x24e4 => Some(OpGrant::Grant(grant::METAL_DEVICE_MMIO)),
        0x24e5 => Some(OpGrant::Grant(grant::METAL_DEVICE_MMIO)),
        0x24e6 => Some(OpGrant::Grant(grant::METAL_DEVICE_DMA)),
        0x24e7 => Some(OpGrant::Grant(grant::METAL_DEVICE_DMA)),
        0x24e8 => Some(OpGrant::Grant(grant::METAL_DEVICE_MMIO)),
        0x24ea => Some(OpGrant::Grant(grant::METAL_DEVICE_DMA)),
        0x24eb => Some(OpGrant::Grant(grant::METAL_DEVICE_DMA)),
        0x24ec => Some(OpGrant::Grant(grant::METAL_DEVICE_DMA)),
        0x24f5 => Some(OpGrant::Grant(grant::METAL_DEVICE_PCIE)),
        0x24f6 => Some(OpGrant::Grant(grant::METAL_DEVICE_PCIE)),
        0x24f7 => Some(OpGrant::Grant(grant::METAL_DEVICE_PCIE)),
        0x2564 => Some(OpGrant::Contract(0x0025)),
        0x2640 => Some(OpGrant::Grant(grant::SEAL_KEY)),
        0x2641 => Some(OpGrant::Grant(grant::SEAL_KEY)),
        0x2642 => Some(OpGrant::Grant(grant::SEAL_KEY)),
        0x2643 => Some(OpGrant::Grant(grant::SEAL_KEY)),
        0x2644 => Some(OpGrant::Grant(grant::SEAL_KEY)),
        0x2645 => Some(OpGrant::Grant(grant::SEAL_KEY)),
        0x2750 => Some(OpGrant::Contract(0x0027)),
        0x2751 => Some(OpGrant::Contract(0x0027)),
        0x2760 => Some(OpGrant::Contract(0x0027)),
        0x2761 => Some(OpGrant::Contract(0x0027)),
        0x2762 => Some(OpGrant::Contract(0x0027)),
        0x2763 => Some(OpGrant::Contract(0x0027)),
        0x2770 => Some(OpGrant::Contract(0x0027)),
        0x2771 => Some(OpGrant::Contract(0x0027)),
        0x2772 => Some(OpGrant::Contract(0x0027)),
        0x2773 => Some(OpGrant::Contract(0x0027)),
        0x2774 => Some(OpGrant::Contract(0x0027)),
        0x2775 => Some(OpGrant::Contract(0x0027)),
        0x2776 => Some(OpGrant::Contract(0x0027)),
        0x2777 => Some(OpGrant::Contract(0x0027)),
        0x2778 => Some(OpGrant::Contract(0x0027)),
        0x2779 => Some(OpGrant::Contract(0x0027)),
        0x277a => Some(OpGrant::Contract(0x0027)),
        0x277b => Some(OpGrant::Contract(0x0027)),
        0x277c => Some(OpGrant::Contract(0x0027)),
        0x277d => Some(OpGrant::Contract(0x0027)),
        0x277e => Some(OpGrant::Contract(0x0027)),
        0x277f => Some(OpGrant::Contract(0x0027)),
        0x2790 => Some(OpGrant::Contract(0x0027)),
        0x2791 => Some(OpGrant::Contract(0x0027)),
        0x2792 => Some(OpGrant::Contract(0x0027)),
        0x27a0 => Some(OpGrant::Contract(0x0027)),
        0x27a1 => Some(OpGrant::Contract(0x0027)),
        0x27a2 => Some(OpGrant::Contract(0x0027)),
        0x27a3 => Some(OpGrant::Contract(0x0027)),
        0x27a4 => Some(OpGrant::Contract(0x0027)),
        0x27b0 => Some(OpGrant::Contract(0x0027)),
        0x27b1 => Some(OpGrant::Contract(0x0027)),
        0x27b2 => Some(OpGrant::Contract(0x0027)),
        0x27b3 => Some(OpGrant::Contract(0x0027)),
        0x27b4 => Some(OpGrant::Contract(0x0027)),
        0x27c0 => Some(OpGrant::Contract(0x0027)),
        0x27c1 => Some(OpGrant::Contract(0x0027)),
        0x27c2 => Some(OpGrant::Contract(0x0027)),
        0x27c3 => Some(OpGrant::Contract(0x0027)),
        0x27d0 => Some(OpGrant::Contract(0x0027)),
        0x27d1 => Some(OpGrant::Contract(0x0027)),
        0x27d2 => Some(OpGrant::Contract(0x0027)),
        0x2800 => Some(OpGrant::Contract(0x0028)),
        0x2801 => Some(OpGrant::Contract(0x0028)),
        0x2802 => Some(OpGrant::Contract(0x0028)),
        0x2803 => Some(OpGrant::Contract(0x0028)),
        0x2804 => Some(OpGrant::Contract(0x0028)),
        0x2900 => Some(OpGrant::Free),
        0x2901 => Some(OpGrant::Grant(grant::LEND_BORROW)),
        0x2902 => Some(OpGrant::Grant(grant::LEND_BORROW)),
        0x2903 => Some(OpGrant::Free),
        0x2a00 => Some(OpGrant::Contract(0x002a)),
        0x2a01 => Some(OpGrant::Contract(0x002a)),
        0x2a02 => Some(OpGrant::Contract(0x002a)),
        0x2a03 => Some(OpGrant::Contract(0x002a)),
        0x2a04 => Some(OpGrant::Contract(0x002a)),
        0x2b00 => Some(OpGrant::Contract(0x002b)),
        0x2c00 => Some(OpGrant::Contract(0x002c)),
        0x2c01 => Some(OpGrant::Contract(0x002c)),
        0x2c02 => Some(OpGrant::Contract(0x002c)),
        _ => None,
    }
}

/// What a contract's ops need unless an op says otherwise, or `None`
/// for an id the registry does not assign.
pub fn contract_grant(id: u16) -> Option<OpGrant> {
    match id {
        0x0000 => Some(OpGrant::Free),
        0x0001 => Some(OpGrant::Free),
        0x0002 => Some(OpGrant::Free),
        0x0003 => Some(OpGrant::Contract(0x0003)),
        0x0004 => Some(OpGrant::Free),
        0x0005 => Some(OpGrant::Contract(0x0005)),
        0x0006 => Some(OpGrant::Contract(0x0006)),
        0x0007 => Some(OpGrant::Contract(0x0007)),
        0x0008 => Some(OpGrant::Contract(0x0008)),
        0x0009 => Some(OpGrant::Contract(0x0009)),
        0x000a => Some(OpGrant::Contract(0x000a)),
        0x000b => Some(OpGrant::Contract(0x000b)),
        0x000c => Some(OpGrant::Contract(0x000c)),
        0x000d => Some(OpGrant::Contract(0x000d)),
        0x000e => Some(OpGrant::Contract(0x000e)),
        0x000f => Some(OpGrant::Contract(0x000f)),
        0x0010 => Some(OpGrant::Contract(0x0010)),
        0x0011 => Some(OpGrant::Free),
        0x0012 => Some(OpGrant::Free),
        0x0013 => Some(OpGrant::Contract(0x0013)),
        0x0014 => Some(OpGrant::Contract(0x0014)),
        0x0015 => Some(OpGrant::Contract(0x0015)),
        0x0016 => Some(OpGrant::Contract(0x0016)),
        0x0017 => Some(OpGrant::Contract(0x0017)),
        0x0018 => Some(OpGrant::Grant(grant::HOST_PROCESS_EXEC)),
        0x0019 => Some(OpGrant::Contract(0x0019)),
        0x001a => Some(OpGrant::Contract(0x001a)),
        0x001b => Some(OpGrant::Contract(0x001b)),
        0x001c => Some(OpGrant::Contract(0x001c)),
        0x001d => Some(OpGrant::Contract(0x001d)),
        0x001e => Some(OpGrant::Contract(0x001e)),
        0x001f => Some(OpGrant::Contract(0x001f)),
        0x0020 => Some(OpGrant::Contract(0x0020)),
        0x0021 => Some(OpGrant::Contract(0x0021)),
        0x0022 => Some(OpGrant::Contract(0x0022)),
        0x0023 => Some(OpGrant::Contract(0x0023)),
        0x0024 => Some(OpGrant::Contract(0x0024)),
        0x0025 => Some(OpGrant::Contract(0x0025)),
        0x0026 => Some(OpGrant::Grant(grant::SEAL_KEY)),
        0x0027 => Some(OpGrant::Contract(0x0027)),
        0x0028 => Some(OpGrant::Contract(0x0028)),
        0x0029 => Some(OpGrant::Free),
        0x002a => Some(OpGrant::Contract(0x002a)),
        0x002b => Some(OpGrant::Contract(0x002b)),
        0x002c => Some(OpGrant::Contract(0x002c)),
        _ => None,
    }
}

/// Whether an opcode creates work or a held resource, and so waits on
/// the owner admission gate.
pub fn op_admits(op: u32) -> bool {
    matches!(
        op,
        0x0100 | 0x0204 | 0x0205 | 0x0400 | 0x0451 | 0x0d00 | 0x0d07 | 0x0d09 | 0x2900 | 0x2c00
    )
}

/// The shape of every call a module may make, and what the gateway serves
/// a gated module.
pub mod gate {
    /// Longest `arg` record any op takes.
    pub const ARG_MAX: usize = 1024;

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
        MintedMints,
    }

    /// Which way a buffer moves.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Dir {
        None,
        In,
        Out,
        InOut,
    }

    /// How long the `data` span may be.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Bound {
        /// At most this many bytes.
        Bytes(usize),
        /// Bounded by the caller's own region alone.
        Any,
    }

    /// One opcode's shape.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct OpRule {
        pub handle: HandleUse,
        /// Which way the flat `arg` record moves.
        pub arg: Dir,
        /// Most bytes `arg` holds (at most `ARG_MAX`).
        pub arg_max: usize,
        /// Which way the bulk `data` span moves.
        pub data: Dir,
        pub data_max: Bound,
        /// The op releases the handle it names.
        pub closes: bool,
        /// The op answers a kernel-granted address: never served gated.
        pub addr_answer: bool,
        /// The handle the op mints signals its minter through a doorbell.
        pub signals: bool,
    }

    /// The shape of `op`, if the registry declares one.
    pub fn op_rule(op: u32) -> Option<OpRule> {
        match op {
            0x002a => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::Out,
                arg_max: 20,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x002b => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::InOut,
                arg_max: 64,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: true,
                signals: false,
            }),
            0x002c => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x002d => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::Out,
                arg_max: 32,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x002e => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x002f => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::Out,
                arg_max: 16,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x003a => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::Out,
                arg_max: 12,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: true,
                signals: false,
            }),
            0x003c => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x003d => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::Out,
                arg_max: 6,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0040 => Some(OpRule {
                handle: HandleUse::Value,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0041 => Some(OpRule {
                handle: HandleUse::Channel,
                arg: Dir::InOut,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0042 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0043 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0045 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0046 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x004c => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0050 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0052 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0053 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 34,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0055 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0066 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x00fe => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 62,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0100 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0101 => Some(OpRule {
                handle: HandleUse::Channel,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0102 => Some(OpRule {
                handle: HandleUse::Channel,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0103 => Some(OpRule {
                handle: HandleUse::Channel,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0104 => Some(OpRule {
                handle: HandleUse::Channel,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0105 => Some(OpRule {
                handle: HandleUse::Channel,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0107 => Some(OpRule {
                handle: HandleUse::Channel,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x010c => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::InOut,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0110 => Some(OpRule {
                handle: HandleUse::Channel,
                arg: Dir::Out,
                arg_max: 16,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: true,
                signals: false,
            }),
            0x0111 => Some(OpRule {
                handle: HandleUse::Channel,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0112 => Some(OpRule {
                handle: HandleUse::Channel,
                arg: Dir::Out,
                arg_max: 16,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: true,
                signals: false,
            }),
            0x0113 => Some(OpRule {
                handle: HandleUse::Channel,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0114 => Some(OpRule {
                handle: HandleUse::Channel,
                arg: Dir::Out,
                arg_max: 16,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: true,
                signals: false,
            }),
            0x0202 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::Out,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0203 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::Out,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0204 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0205 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0206 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0207 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x0208 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::Out,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0209 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::Out,
                arg_max: 36,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x020a => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 20,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0300 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0400 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0401 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0402 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0403 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x0451 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 5,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0500 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 6,
                data: Dir::In,
                data_max: Bound::Bytes(4096),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0501 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::InOut,
                arg_max: 4,
                data: Dir::InOut,
                data_max: Bound::Bytes(256),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0502 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::InOut,
                arg_max: 6,
                data: Dir::InOut,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0503 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0504 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x0505 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::InOut,
                arg_max: 12,
                data: Dir::Out,
                data_max: Bound::Bytes(4096),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0506 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::Out,
                data_max: Bound::Bytes(4096),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0507 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::Out,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0508 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::InOut,
                arg_max: 76,
                data: Dir::Out,
                data_max: Bound::Bytes(4096),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0509 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::InOut,
                arg_max: 76,
                data: Dir::Out,
                data_max: Bound::Bytes(4096),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x050a => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 65,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x050b => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x050c => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::InOut,
                arg_max: 20,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x050d => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::InOut,
                arg_max: 36,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x050e => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::InOut,
                arg_max: 101,
                data: Dir::Out,
                data_max: Bound::Bytes(256),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x050f => Some(OpRule {
                handle: HandleUse::MintedMints,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Bytes(256),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0510 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::InOut,
                arg_max: 274,
                data: Dir::InOut,
                data_max: Bound::Bytes(65552),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0511 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 274,
                data: Dir::InOut,
                data_max: Bound::Bytes(65552),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0512 => Some(OpRule {
                handle: HandleUse::MintedMints,
                arg: Dir::In,
                arg_max: 202,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0513 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::InOut,
                arg_max: 158,
                data: Dir::InOut,
                data_max: Bound::Bytes(65536),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0514 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 158,
                data: Dir::InOut,
                data_max: Bound::Bytes(65536),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0515 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 283,
                data: Dir::Out,
                data_max: Bound::Bytes(780),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0516 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 153,
                data: Dir::InOut,
                data_max: Bound::Bytes(260),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0517 => Some(OpRule {
                handle: HandleUse::MintedMints,
                arg: Dir::In,
                arg_max: 28,
                data: Dir::In,
                data_max: Bound::Bytes(260),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0518 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 32,
                data: Dir::Out,
                data_max: Bound::Bytes(148),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0600 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0601 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x0602 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0603 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0604 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0605 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0606 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0607 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x060a => Some(OpRule {
                handle: HandleUse::MintedMints,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: true,
            }),
            0x0700 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0701 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x0702 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0703 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0704 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0705 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0706 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 5,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0707 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 13,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0708 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0709 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x070a => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x07ff => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0800 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 3,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0801 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x0802 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Bytes(64),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0803 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0804 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::In,
                data_max: Bound::Bytes(64),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0805 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0806 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0807 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::Out,
                data_max: Bound::Bytes(64),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0900 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0901 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::In,
                data_max: Bound::Bytes(64),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0903 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0904 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0905 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Bytes(8192),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0906 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x0907 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::Out,
                arg_max: 24,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x090a => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x090b => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0910 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0911 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::In,
                data_max: Bound::Bytes(64),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0912 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0913 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Bytes(1624),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0914 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::Out,
                data_max: Bound::Bytes(1616),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0915 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x0916 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0920 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0921 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::In,
                data_max: Bound::Bytes(64),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0922 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0923 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0924 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0925 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x0927 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0a00 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0a01 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x0a02 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0a03 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0a04 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0a05 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0b00 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0b01 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x0b02 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0b03 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0b04 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0c00 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0c01 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x0c02 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0c03 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0c04 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d00 => Some(OpRule {
                handle: HandleUse::ScopedMints,
                arg: Dir::In,
                arg_max: 255,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d01 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 1024,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d02 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d03 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x0d04 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 32,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d05 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d06 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 1024,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d07 => Some(OpRule {
                handle: HandleUse::ScopedMints,
                arg: Dir::In,
                arg_max: 255,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d08 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 1024,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d09 => Some(OpRule {
                handle: HandleUse::ScopedMints,
                arg: Dir::In,
                arg_max: 255,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d0a => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::In,
                arg_max: 255,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d0b => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::In,
                arg_max: 255,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d0c => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::In,
                arg_max: 263,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d0d => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::In,
                arg_max: 514,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d0e => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d0f => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 1024,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d10 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d11 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d12 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::In,
                arg_max: 255,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d13 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::In,
                arg_max: 514,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d14 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::InOut,
                arg_max: 1024,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0d15 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::In,
                arg_max: 255,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0dff => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0e00 => Some(OpRule {
                handle: HandleUse::ScopedMints,
                arg: Dir::In,
                arg_max: 255,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0e01 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 50,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0e02 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::InOut,
                arg_max: 578,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0e03 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::InOut,
                arg_max: 579,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0e04 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::InOut,
                arg_max: 322,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0e05 => Some(OpRule {
                handle: HandleUse::ScopedMints,
                arg: Dir::In,
                arg_max: 258,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: true,
            }),
            0x0e06 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x0e07 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::InOut,
                arg_max: 643,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0e08 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::InOut,
                arg_max: 580,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0eff => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0f20 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::InOut,
                arg_max: 908,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0f21 => Some(OpRule {
                handle: HandleUse::ScopedMints,
                arg: Dir::In,
                arg_max: 257,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0f22 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::InOut,
                arg_max: 666,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0f23 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0f24 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::InOut,
                arg_max: 578,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0f25 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x0f26 => Some(OpRule {
                handle: HandleUse::ScopedMints,
                arg: Dir::In,
                arg_max: 844,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0f27 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0f28 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 64,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0f29 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x0f2a => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::InOut,
                arg_max: 580,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0f2b => Some(OpRule {
                handle: HandleUse::ScopedMints,
                arg: Dir::InOut,
                arg_max: 258,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0f2c => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::InOut,
                arg_max: 330,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x0fff => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x103e => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 144,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x104d => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 12,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x104e => Some(OpRule {
                handle: HandleUse::Value,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x104f => Some(OpRule {
                handle: HandleUse::Value,
                arg: Dir::Out,
                arg_max: 20,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1124 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1125 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x113f => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::InOut,
                arg_max: 12,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: true,
                signals: false,
            }),
            0x1234 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 251,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1235 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1236 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1300 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::Out,
                arg_max: 24,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1400 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1500 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::InOut,
                arg_max: 33,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1501 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 33,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1502 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::InOut,
                arg_max: 33,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1503 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 1024,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x15ff => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1600 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1601 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1602 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1603 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1604 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1605 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x16ff => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1700 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 1024,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1701 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1702 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 5,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1703 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1704 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::In,
                arg_max: 16,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x170b => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x170c => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x170d => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x170e => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x170f => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::Out,
                arg_max: 20,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1710 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 12,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1711 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1712 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::InOut,
                arg_max: 16,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1713 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::Out,
                arg_max: 256,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1714 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x17ff => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1800 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 16,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1801 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::InOut,
                arg_max: 20,
                data: Dir::InOut,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1802 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 20,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1803 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::InOut,
                arg_max: 13,
                data: Dir::InOut,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1804 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1805 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x18ff => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1900 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1901 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1902 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1903 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1904 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1905 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1906 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x19ff => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1a00 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1a01 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 1024,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1a02 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1a03 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x1ca0 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 64,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1ca1 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x1ca2 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::InOut,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1ca3 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1ca4 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::InOut,
                arg_max: 12,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: true,
                signals: false,
            }),
            0x1ca5 => Some(OpRule {
                handle: HandleUse::MintedMints,
                arg: Dir::Out,
                arg_max: 20,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: true,
                signals: true,
            }),
            0x1ca6 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 32,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1df0 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::InOut,
                arg_max: 12,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: true,
                signals: false,
            }),
            0x1df1 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1df2 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1df3 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x1df4 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::InOut,
                arg_max: 16,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: true,
                signals: false,
            }),
            0x1e80 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1e81 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x1e82 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 14,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1e83 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1e84 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1e85 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1f85 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1f86 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 14,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1f87 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 12,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x1f88 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x1f89 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 12,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2020 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2021 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2022 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2023 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2047 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::Out,
                arg_max: 6,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2048 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 6,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2049 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 6,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x204a => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 6,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2068 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2069 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x206a => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x206b => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x206c => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x206d => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x206e => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::InOut,
                arg_max: 1024,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x206f => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2152 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2153 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::Out,
                arg_max: 16,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2154 => Some(OpRule {
                handle: HandleUse::Value,
                arg: Dir::Out,
                arg_max: 12,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2155 => Some(OpRule {
                handle: HandleUse::Value,
                arg: Dir::Out,
                arg_max: 32,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2156 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 3,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2157 => Some(OpRule {
                handle: HandleUse::Value,
                arg: Dir::Out,
                arg_max: 66,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x21e8 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::InOut,
                arg_max: 24,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2244 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x22e0 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x22e1 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x22e2 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x22e3 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 16,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2310 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 5,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2338 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2339 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 260,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x24e4 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::InOut,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x24e5 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x24e6 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::InOut,
                arg_max: 12,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: true,
                signals: false,
            }),
            0x24e7 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x24e8 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::InOut,
                arg_max: 12,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: true,
                signals: false,
            }),
            0x24ea => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x24eb => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x24ec => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::InOut,
                arg_max: 12,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: true,
                signals: false,
            }),
            0x24f5 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x24f6 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::InOut,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x24f7 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2564 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2640 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2641 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::In,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2642 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2643 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::Out,
                arg_max: 16,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2644 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 12,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2645 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 16,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2750 => Some(OpRule {
                handle: HandleUse::Mints,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2751 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x2760 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2761 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2762 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 6,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2763 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2770 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2771 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 7,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2772 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 3,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2773 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 3,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2774 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::InOut,
                arg_max: 6,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2775 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2776 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 5,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2777 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 3,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2778 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2779 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 6,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x277a => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x277b => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x277c => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 5,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x277d => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 32,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x277e => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x277f => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2790 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 261,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2791 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2792 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27a0 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 5,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27a1 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::InOut,
                arg_max: 5,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27a2 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27a3 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 3,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27a4 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27b0 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 5,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27b1 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::InOut,
                arg_max: 5,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27b2 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27b3 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27b4 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27c0 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 5,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27c1 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::InOut,
                arg_max: 5,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27c2 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 2,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27c3 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27d0 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 5,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27d1 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::InOut,
                arg_max: 5,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x27d2 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 1,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2800 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::InOut,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2801 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::In,
                arg_max: 4,
                data: Dir::InOut,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2802 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::InOut,
                arg_max: 69,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2803 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::InOut,
                arg_max: 975,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2804 => Some(OpRule {
                handle: HandleUse::Scoped,
                arg: Dir::In,
                arg_max: 524,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2900 => Some(OpRule {
                handle: HandleUse::MintedMints,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::InOut,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2901 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::InOut,
                arg_max: 13,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: true,
                signals: false,
            }),
            0x2902 => Some(OpRule {
                handle: HandleUse::Global,
                arg: Dir::In,
                arg_max: 8,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2903 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
            }),
            0x2a00 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 40,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2a01 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 40,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2a02 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 80,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2a03 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::InOut,
                arg_max: 120,
                data: Dir::InOut,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2a04 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::In,
                arg_max: 40,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2b00 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::Out,
                arg_max: 4,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2c00 => Some(OpRule {
                handle: HandleUse::ScopedMints,
                arg: Dir::In,
                arg_max: 274,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2c01 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::Out,
                data_max: Bound::Any,
                closes: false,
                addr_answer: false,
                signals: false,
            }),
            0x2c02 => Some(OpRule {
                handle: HandleUse::Minted,
                arg: Dir::None,
                arg_max: 0,
                data: Dir::None,
                data_max: Bound::Bytes(0),
                closes: true,
                addr_answer: false,
                signals: false,
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
