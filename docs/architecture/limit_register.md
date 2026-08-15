# Limit register

The complete list of the system's *deliberate* hard ceilings
(`rfc_resource_model.md` §4, §6.3). Two families:

- **Identifier widths (R2)** — wire/ABI commitments. The rule: no id may
  bind before a memory pool (R1) does on any targeted deployment class.
  An id-shaped ceiling found in source but absent here is a bug.
- **Deliberate caps** — policy ceilings and sanity bounds that are meant
  to bind (or to catch runaway), with the reason recorded.

Every row is machine-checked against source by
`tools/tests/limit_register.rs`: the `Symbol` must exist in `Source` as a
`const` whose value matches `Value` (first occurrence — for per-profile
constants that is the aarch64/host profile). Editing either side without
the other fails the gate.

## Identifier widths (R2)

| Id | Width | Ceiling | Symbol | Source | Value | Binds instead / notes |
|---|---|---|---|---|---|---|
| TCP/HTTP `conn_id` (net-proto wire) | u16 LE | 65535 | `MAX_TCP_CONNS` | modules/sdk/abi/config.rs | 256 | Widened 2026-08-15 (`rfc_resource_model.md` §11.5): the id space no longer binds — the conn table (R1) does, and raising it is now a memory-only change |
| module index (exec_order, fault ids) | u8 | 256 | `MAX_MODULES` | modules/sdk/abi/config.rs | 128 | Deliberate keep at u8; reopen on nanocloud density evidence. Dual asserts: `boot/config.rs`, `exec/scheduler/mod.rs` |
| channel buffer slot | i16 (−1 sentinel) | 32768 | `MAX_BUFFER_SLOTS` | src/kernel/ipc/buffer_pool.rs | 256 | R1 (buffer arena) binds first by orders of magnitude |
| owner slot | u16 | 65535 | `MAX_OWNERS` | src/kernel/workload/owner.rs | 64 | R1/policy binds first; const-asserted ≤ u16::MAX |
| HTTP request path length | u16 | 65535 | `MAX_PATH` | modules/sdk/abi/config.rs | 200 | Slot field widened with the conn_id flag-day; the 200-byte budget is now pure R1 policy |
| content-type position | u8 append-only | 256 | — | contracts/src/lib.rs | — | Vocabulary discipline; parallel tables const-assert-locked (not value-checked here) |

## Deliberate caps

| Cap | Symbol | Source | Value | Reason |
|---|---|---|---|---|
| Single module code segment | `MAX_MODULE_CODE_SIZE` | modules/sdk/abi/config.rs | 1048576 | Sanity bound: catches a corrupt/runaway blob, not a budget |
| Single channel ring | `MAX_CHAN_BYTES` | src/kernel/ipc/channel.rs | 4194304 | Sanity bound on one ring's share of the buffer arena |
| QUIC endpoint connections | `MAX_CONNS` | modules/foundation/quic/mod.rs | 2 | Policy: the endpoint is point-to-point by design |
| HTTP/2 streams per conn | `MAX_STREAMS` | modules/sdk/abi/config.rs | 4 | Policy pending review (`rfc_resource_model.md` §9) |
