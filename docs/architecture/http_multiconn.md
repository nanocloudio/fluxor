# HTTP multi-connection architecture

A single `http` module instance serves many concurrent HTTP/1, HTTP/2,
and WebSocket connections within one process tick. Each in-flight
connection gets its own slot, its own phase, and a tick of work per
`step()` — comparable to Linux's per-process behaviour, with no
FIFO-induced head-of-line blocking and no idle peer starving the
queue.

## State layout

`ServerState` holds the **server-wide** configuration: channel
handles, routes, the body cache and arena, telemetry variables, the
per-connection slot table, and the step iterator's bookkeeping.
Per-connection state lives in `ConnSlot`, one entry per slot.

A `ConnSlot` carries the conn id, phase, route match, request path
buffer, recv/send buffers (heap-allocated lazily on accept and
released on close), file/template/streaming state, WebSocket
fragmentation state, and an optional `H2State` (allocated only when
the conn upgrades to HTTP/2 — h1-only conns never pay the cost).

The active slot is identified by `ServerState::cur_slot`. Phase
handlers and their helpers (`cur_slot`, `cur_slot_mut`,
`cur_send_buf_mut_ptr`, `cur_conn_id`, …) read or mutate that slot.

## Per-target sizing

| Target | `MAX_CONCURRENT_CONNS` | Memory cost (rough) |
|--------|------------------------|---------------------|
| `aarch64` (Pi 5, Linux host) | 256 | ~4 MB peak (working-set h2) |
| `wasm32` | 256 | ~4 MB peak |
| `rp2350`, `rp2040` | 1 | ~16 KB peak |

`MAX_CONCURRENT_CONNS` matches the IP module's `MAX_TCP_CONNS` on
host platforms. The slot table is the parallelism bound; idle slots
cost ~250 B because their heap allocations are released on close.
Per-slot `recv_buf` (8 KB), `send_buf` (~4 KB), and `H2State` (~3 KB,
h2 only) all live on the module heap arena.

`alloc_free_slot` allocates `recv_buf` + `send_buf` on
`MSG_ACCEPTED`; `slot_release_buffers` returns them on close.
`H2State` is allocated lazily by `ensure_h2_state()` from
`h2::enter()`. `body_pool` grows via `heap_realloc` doubling each
time `parse_route_body` would overflow; `body_offset`, `body_len`,
`body_pool_cap`, and `body_pool_used` are all u32 so the pool can
exceed 64 KB if app templates demand it.

`module_arena_size()` reports
`2 × DEFAULT_BODY_POOL_SIZE +
ARENA_WORKING_SET_CONNS × (RECV_BUF_SIZE + SEND_BUF_SIZE +
size_of::<H2State>()) + per-alloc-overhead + slack`, so the kernel
allocates the right peak envelope at module-init time. Memory
scales with **active** connections, not with the slot table size.

## Step iterator

`step()` is O(active) via a `ready_bits: [u64; N]` bitmap on
`ServerState`. `alloc_free_slot` sets the slot's bit;
`slot_release_buffers` clears it. Each tick snapshots the bitmap,
starts at `step_cursor`, walks set bits via `trailing_zeros`, and
ticks each marked slot's phase. After the tick, `step_cursor`
advances by one so no slot starves the others.

A server-level `bound: u8` flag (set on `MSG_BOUND`) gates
`demux_inbound` so it stays dormant during the bind sequence and
runs every tick afterwards — even when slot 0 is reused for a
connection after bind completes.

## Inbound demux

`demux_inbound` runs once per `step()` at the top, before any
per-slot work. It reads net_proto frames from `net_in_chan`, looks
up the target slot by `conn_id`, and routes:

- `MSG_ACCEPTED` → `alloc_free_slot(s, conn_id)` → mark phase
  `RecvRequest`. If the slot table is full, actively close the new
  conn so the IP layer doesn't leak a TCP slot waiting for our
  timeout.
- `MSG_DATA` → `find_slot_by_conn_id(s, conn_id)` → append payload
  to that slot's `recv_buf`. The frame is peeked first; if the
  target's `recv_buf` is too full to hold the payload, the frame
  is left on `net_in_chan` so the IP module's atomic-FIFO write
  rejection triggers TCP backpressure (closes `rcv_wnd` for the
  affected conn until we drain).
- `MSG_CLOSED` → set the target slot's `peer_closed` flag.
- `MSG_BOUND` → set the server-wide `bound` flag.

The demux processes up to 16 frames per tick; anything left over
rolls into the next call.

## Outbound

Per-slot phase handlers write into the active slot's `send_buf` and
call `net_send` to push CMD_SEND envelopes to `net_out_chan`.
`net_send` is atomic-FIFO: the channel either accepts the whole
envelope or rejects it, and rejection counts as backpressure rather
than partial delivery.

The h1 phase machine (`Phase::SendHeaders` → `SendBody` →
`DrainSend`) emits headers and body chunks for static, template,
file, FS, stream, and proxy handlers. h2 emits `HEADERS` + `DATA`
frames via the round-robin emitter in `step_sending_body`, capped
by per-stream and per-connection send windows.

## File-channel serialisation

`file_chan` is shared across slots — `HANDLER_FILE`,
`HANDLER_STREAM`, and `HANDLER_TEMPLATE`'s cache-fill path all
issue `IOCTL_FLUSH` + `IOCTL_NOTIFY` against it. To prevent two
concurrent slots racing on the channel state, `ServerState` carries
a `file_chan_owner: i16` slot-index lock:

- `try_acquire_file_chan` claims it. If another slot holds it,
  callers stall in `DispatchRoute` and retry on the next tick (or,
  for h2, mark the stream `Fetching` and let `drive_cache_fetch`
  retry).
- Released on transition to `DrainSend` and in
  `slot_release_buffers` (any close path).

`HANDLER_FS_FILE` (handler 7) bypasses this entirely via a per-slot
`fs_fd` through the FS_CONTRACT, and is the recommended path for
new deployments.

## Body cache retention

Cache entries carry a `retain: u8` reader refcount. A cache hit
bumps it on the way in (in `cache_try_or_fetch` and the inline h1
hit path); end-of-emission (`Phase::DrainSend` for h1, h2's
`free_slot`) decrements via `cache_release_for_route`.
`cache_alloc` refuses to evict any entry with `retain > 0`, so a
sibling cache miss can't trample the body_pool region a stream is
still rendering from. `cache_lookup` also requires `CACHE_COMPLETE`
so an in-progress fill doesn't masquerade as a hit.

## WebSocket fan-out

When a route's handler is `HANDLER_WEBSOCKET_FANOUT`, the slot's
`ws_fan_out` flag is set and outbound WS bytes flow through a pair
of typed channels:

- `ws_in` (in[3], `WsFrame`): the http server reads `WsFrame`
  envelopes here and queues them on the active slot's `send_buf`
  as wire frames.
- `ws_out` (out[2], `WsFrame`): inbound browser WS frames are
  emitted as `WsFrame` records for downstream consumers.

`ws_drain_fanout_input` routes envelopes by their `conn_id` field
to the target slot. A `u32::MAX` "unclaimed" sentinel from
`ws_stream` (used until it observes a real inbound frame) routes
to the first available fan-out slot. If the target's `send_buf`
is non-empty (or it's mid-fragmentation), the envelope is written
back to `ws_in_chan` so the next tick retries delivery.

Fragmentation: when a `WsFrame` envelope's payload exceeds
`SEND_BUF_SIZE - WS_FRAG_HDR_RESERVE`, the message is split into a
`BINARY/fin=0` first fragment + N `CONTINUATION/fin=0` fragments +
a final `CONTINUATION/fin=1` (RFC 6455 §5.4). The source payload
is heap-allocated per-slot for the duration of fragmentation and
freed when the final fragment is queued (or on slot close).

## Limitations

- **Single-conn `legacy_mode`** — the routeless file-server
  fallback (`legacy_mode == 2`) serialises all requests through
  the slot phase machine. Multi-conn parallelism applies; the file
  channel is the bottleneck.
- **`MAX_CONCURRENT_CONNS` capped at 256** — the net-protocol wire
  format carries `conn_id` as a single byte. Lifting the cap
  requires widening `conn_id` end-to-end across IP + HTTP +
  ws_stream.
- **Per-instance `H2State`** is large (`MAX_STREAMS` ×
  `StreamSlot`). On embedded targets only one slot exists, so the
  cost is bounded; on host targets it scales with `ARENA_WORKING_SET_CONNS`.
