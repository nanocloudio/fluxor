# nvme — NVMe block driver (Pi 5 / CM5, PCIe1 external slot)

Polled, single-queue NVMe driver for the CM5 NVMe HAT+. Implements
NVMe 1.4 controller initialization, Identify Controller / Namespace,
and 512-byte block read/write on one admin queue + one I/O queue.

This is v1 per `.context/future/rfc_nvme_driver.md` — not optimised,
not interrupt-driven, not multi-queue. The point is correctness.

See also: `docs/guides/driver-bringup.md` for the general methodology
this module was built against, and `hw/nvme_trace/` for the userspace
trace that defines the expected controller init sequence.

---

## Log transport

Every `log::info!` in this module flows through the kernel log ring
and out over whatever transport `platform.debug.to` selects. On the
cm5 rig we use `{ to: net, monitor: true }` and consume with
`fluxor monitor --net :6666` — no UART cable required. See
`.../memory/pi5_netconsole.md` for the bus details.

The exception handler is a separate path that writes PL011 directly,
so a catastrophic MMU/SError during NVMe bring-up still prints over
UART even if the log_net module isn't running yet.

---

## References

- NVMe Base Specification 1.4: §7.6.1 (init), §3.1 (registers), §4.2
  (SQE), §4.6 (CQE), §5.15.2.1 (Identify Controller), §5.15.2.2
  (Identify Namespace).
- Reference implementations: SPDK `lib/nvme/nvme_ctrlr.c`;
  NetBSD `sys/dev/ic/nvme.c`.
- Baseline trace tool at `hw/nvme_trace/` — captures the init +
  Identify Controller sequence with ns-accurate timestamps.

---

## Device overview

- **Bus:** PCIe1 (external x1 slot on CM5). Enumerated by `pcie_scan`
  with `controller = pcie1` param; class code `0x01_08_02`.
- **BAR:** BAR0 (memory-mapped). Controller registers NVMe 1.4 §3.1.
- **DMA:** all queues + PRP data buffers come from `dev_dma_alloc`
  (kernel-owned non-cacheable arena).
- **Inputs:** `requests` channel — 16-byte block I/O requests from
  `fat32` or other consumers.
- **Outputs:** `blocks` channel — 512-byte block data, same contract
  as the `sd` module so `fat32` consumes it unchanged.

---

## State machine

```
                    ┌───────────────┐
                    │   WaitPcie    │  pcie_scan not Ready yet
                    └──────┬────────┘
                           │ Ready upstream
                           ▼
                    ┌───────────────┐
                    │   MapBars     │  NIC_BAR_MAP via pcie_scan
                    └──────┬────────┘
                           │ bar0_virt != 0
                           ▼
                    ┌───────────────┐
                    │   Reset       │  CC.EN=0, poll CSTS.RDY=0
                    └──────┬────────┘
                           ▼
                    ┌───────────────┐
                    │ ConfigQueues  │  alloc SQ/CQ, program AQA/ASQ/ACQ
                    └──────┬────────┘
                           ▼
                    ┌───────────────┐
                    │   Enable      │  CC.EN=1, poll CSTS.RDY=1
                    └──────┬────────┘
                           ▼
                    ┌───────────────────┐
                    │ IdentifyController│  admin 0x06, CNS=1
                    └──────┬────────────┘
                           ▼
                    ┌───────────────────┐
                    │ IdentifyNamespace │  admin 0x06, CNS=0
                    └──────┬────────────┘
                           ▼
                    ┌───────────────┐
                    │  CreateIoCQ   │  admin 0x05
                    └──────┬────────┘
                           ▼
                    ┌───────────────┐
                    │  CreateIoSQ   │  admin 0x01
                    └──────┬────────┘
                           │ returns Ready(3) here — unblocks fat32
                           ▼
                    ┌───────────────┐
                    │    Ready      │  serve block I/O
                    └──────┬────────┘
                           │ on error →
                           ▼
                    ┌───────────────┐
                    │  Fault(code)  │  permanent — UART logs code
                    └───────────────┘
```

Every transition is driven by a single `module_step` invocation: one
register access, one doorbell ring, or one channel op, then return.
No state blocks. States that need to poll (`Reset`, `Enable`, any
command completion) read once per step and return `Continue`.

---

## Per-state contract

### `WaitPcie`

- **Entry:** default after `module_new`.
- **Behaviour:** read `pcie_scan` `devices` channel (or check ready
  flag); find NVMe device (class `0x01_08_02`); record `dev_idx`.
- **Exit:** NVMe device found → `MapBars`.
- **Return:** `Continue` while waiting; `Continue` on transition.
- **Spec:** N/A (platform-specific).
- **Trace row:** none (pre-NVMe).
- **Timing:** depends on PCIe scan; bounded by scheduler ticks.

### `MapBars`

- **Entry:** from `WaitPcie` with `dev_idx` set.
- **Behaviour:** `provider_call(-1, NIC_BAR_MAP, [dev_idx, 0, …])` → `bar0_virt`.
- **Exit:** `bar0_virt != 0` → `Reset`; else `Fault`.
- **Spec:** N/A.
- **Trace row:** `mmap_bar0`.
- **Timing:** single syscall; < 1 ms.

### `Reset`

- **Entry:** from `MapBars` with BAR mapped.
- **Behaviour:**
    1. Read CAP at offset `0x00`. Extract `MPSMIN`, `DSTRD`, `TO`,
       `MQES`. Store in state.
    2. Read CC at `0x14`. If `CC.EN == 1`, write `CC.EN = 0` and
       anchor `reset_start_ms = dev_millis()`.
    3. Poll `CSTS` at `0x1C`. If `CSTS.RDY == 0`, advance to
       `ConfigQueues`. If `CSTS.CFS == 1`, go to `Fault`.
    4. Each step reads CSTS once and returns `Continue`.
- **Spec:** NVMe 1.4 §7.6.1 step 2; §3.1.6 CSTS.
- **Trace rows:** `w32 0x14` (CC.EN=0), `r32 0x1C` loop.
- **Timing budget:** `CAP.TO` is in 500 ms units. Typical ≈ 30 ms;
  worst case several seconds. Anchor against `dev_millis()`, not
  step count.

### `ConfigQueues`

- **Entry:** CSTS.RDY = 0.
- **Behaviour:**
    1. `dev_dma_alloc(4 KB, 4 KB)` × 3 for admin SQ, admin CQ,
       Identify buffer. Zero all three.
    2. Write `AQA = (63 << 16) | 63`.
    3. Write `ASQ` (64-bit) with SQ phys addr.
    4. Write `ACQ` (64-bit) with CQ phys addr.
- **Exit:** → `Enable`.
- **Spec:** NVMe 1.4 §7.6.1 step 3; §3.1.8/9/10 AQA/ASQ/ACQ.
- **Trace rows:** 3× `dma_alloc`, `w32 0x24`, `w64 0x28`, `w64 0x30`.
- **Timing:** micro-seconds per register write; budget 1 step per
  register.

### `Enable`

- **Entry:** admin queues programmed.
- **Behaviour:**
    1. Build CC: `EN | (CSS=NVM) | (MPS=0) | (AMS=RR) |
       (IOSQES=6) | (IOCQES=4)`.
    2. Write CC at `0x14`. Anchor `enable_start_ms`.
    3. Poll `CSTS.RDY`. When 1, → `IdentifyController`.
       If `CFS == 1` or timeout, → `Fault`.
- **Spec:** NVMe 1.4 §7.6.1 step 4–5; §3.1.5 CC.
- **Trace rows:** `w32 0x14` (CC.EN=1), `r32 0x1C` loop.
- **Timing budget:** same as `Reset` (CAP.TO).

### `IdentifyController`

- **Entry:** CSTS.RDY = 1.
- **Behaviour:**
    1. Build SQE: CDW0 = `(CID << 16) | 0x06`, PRP1 = Identify
       buffer phys, CDW10 = `CNS = 0x01`. Write to SQ[0].
    2. Increment SQ tail to 1. Write SQ0TDBL at `0x1000`.
    3. Poll CQ[0] phase bit until it flips to 1. Check status
       field (DW3[31:17]) == 0. Extract model/serial/firmware
       from Identify response (offsets per §5.15.2.1 Figure 249:
       VID@0, SSVID@2, SN@4 (20B), MN@24 (40B), FR@64 (8B)).
    4. Log model string to UART. Ring CQ0HDBL at `0x1000 + DSTRD`.
       Flip phase.
- **Exit:** → `IdentifyNamespace`.
- **Spec:** NVMe 1.4 §4.2 SQE; §4.6 CQE; §5.15 Admin Commands;
  §5.15.2.1 Identify Controller.
- **Trace rows:** `sqe`, `w32 0x1000`, `cqe`, `w32 0x1004`.
- **Timing budget:** typical < 1 ms between doorbell and completion
  for Identify; poll-once-per-step is fine.

### `IdentifyNamespace`

Same shape as `IdentifyController`, CNS = 0x00, NSID = namespace
from config param. Response (4 KB) contains NSZE (total LBAs),
LBAF[] array indicating LBA size (we assume 512 B → LBAF[n].LBADS = 9).

### `CreateIoCQ`, `CreateIoSQ`

Admin opcodes 0x05 and 0x01. Each needs another 4 KB DMA page for
the ring. See NVMe 1.4 §5.4, §5.5.

### `Ready`

Per step:
1. Try to read 16 B from `requests` channel.
2. If a request is in-flight and I/O CQ has a new phase-flipped CQE,
   deliver 512 B to `blocks` channel and clear in-flight slot.
   Return `Burst` if more CQEs are pending, else `Continue`.
3. If no request in flight and we got a new request, submit to I/O
   SQ, ring doorbell, store CID → request mapping. Return `Continue`.
4. Apply backpressure: if `blocks` channel is full, retry same CQE
   next step; do NOT ring CQ0HDBL yet.

### `Fault(code)`

Permanent state. Log code + last CSTS once. Always return
`Continue` with no effect. Future: expose fault event for a
recovery reconfigure.

---

## Channel contracts

### `requests` (input)

16-byte records:
```
offset 0  : u8  opcode     (0=read, 1=write)
offset 1  : u8  reserved
offset 2  : u16 request_id (client-chosen; echoed on completion)
offset 4  : u32 nsid       (typically 1)
offset 8  : u64 lba        (512-byte block index)
```

### `blocks` (output)

For reads: 512-byte records, one per completed read. For writes:
16-byte ack records mirroring the request shape (shape TBD; v1 may
just stream reads).

Backpressure: writes return `bytes_actually_written`. If partial,
retry on next step. State machine does NOT advance on partial writes.

---

## Parameters

| Tag | Name               | Type | Default | Notes                                     |
|-----|--------------------|------|---------|-------------------------------------------|
| 1   | controller_index   | u8   | 0       | Which PCIe device from `pcie_scan`        |
| 2   | namespace          | u32  | 1       | Namespace ID for Identify Namespace / I/O |
| 3   | queue_depth        | u16  | 32      | I/O queue depth (v1 uses 1 in-flight)     |

---

## Why this module looks the way it does

The overarching constraint is that `module_step` returns every time it
does one unit of work. That means:

- The "wait for CSTS.RDY" loops in reference drivers become explicit
  states. `while` loops only appear inside a state if they're bounded
  by a short count (e.g., draining a CQ of at most 64 entries in one
  `Burst`).
- Completion polling cannot be blocking. Each `Ready`-state step
  either sees a new CQE or it doesn't; if it doesn't, the step
  returns and the scheduler comes back.
- Backpressure on the `blocks` output channel is an explicit state
  — we can't just drop a CQE if the consumer isn't ready for the
  data.
- Queue depth > 1 (v2) means tracking one in-flight record per CID;
  doable but out of scope for v1.

See `docs/guides/driver-bringup.md` for the full model.
