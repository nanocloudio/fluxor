# Agent protocol

One request and its answer between a controller and a target's node agent:
which bundle a workload should run, against which revision of the target's
descriptor, under which idempotency identity, and what the target observes,
under a fence.

Source: `modules/sdk/contracts/agent.rs` (records), `tools/src/agent_protocol.rs`
(semantics), `tools/src/agent_cli.rs` (`fluxor agent serve`, `fluxor agent call`),
`packaging/stack/agent_listen.yaml`, `packaging/stack/agent_dial.yaml` and their
`_lane` forms (the remote transport).

The node agent's other verbs (`commit`, `remove`, `status`, `logs`, `policy`) are
the local command surface of an orchestrator on the same host. They are not part
of this protocol and carry no fence.

## Records

One record per message, little-endian, tightly packed, at most
`AGENT_RECORD_MAX` (8192) bytes. Decoding holds every bound and refuses a record
whole.

Request, exactly 114 bytes:

| Field | Size | Meaning |
|---|---|---|
| `op` | 1 | `APPLY` 1, `REMOVE` 2, `OBSERVE` 3 |
| `flags` | 1 | none defined; must be zero |
| `workload_uid` | 16 | zero on `APPLY` or `REMOVE` is a bad request; on `OBSERVE` it asks about the target alone |
| `desired_bundle_digest` | 32 | the workload digest (below); zero on `OBSERVE` and `REMOVE` |
| `descriptor_revision` | 32 | the sha256 of the target descriptor the controller validated against |
| `idempotency_id` | 16 | this request's identity; zero on `APPLY` or `REMOVE` is a bad request |
| `fence_epoch` | 8 | the controller's fence |
| `fence_seq` | 8 | |

Response, 188 bytes and the diagnostic:

| Field | Size | Meaning |
|---|---|---|
| `result` | 1 | below |
| `target_id` | 32 | the target's key fingerprint |
| `workload_uid` | 16 | as asked |
| `descriptor_revision` | 32 | the target's current one |
| `idempotency_id` | 16 | as asked |
| `fence_epoch` | 8 | the fence the target holds |
| `fence_seq` | 8 | |
| `observed_activation_digest` | 32 | below; zero when nothing is active |
| `desired_bundle_digest` | 32 | the workload digest as committed |
| `phase` | 1 | `ABSENT` 0, `COMMITTED` 1, `ACTIVATING` 2, `RUNNING` 3, `UNREADY` 4, `DRAINING` 5, `TERMINATED` 6 |
| `generation` | 8 | the committed generation; zero before the first |
| `diag_len` | 2 | at most `DIAG_MAX`, 8004 |
| `diag` | `diag_len` | a diagnostic, cut at a character boundary if longer; the cut loses text, never the result |

On every transport a record travels as a frame, `[peer:32][len:u32 LE][record]`.

## Rules

A request is taken in this order; the first that applies answers.

1. **Authorization.** The peer is the fingerprint the transport verified, and
   must be a configured controller. The agent's Unix socket has no fingerprint:
   its peer is local whatever a client writes in the frame, and being able to
   open the socket (mode 0600) is the authorization. A stamped all-zero peer names
   nobody. A refused peer reads, of the target, only the `target_id` its own
   handshake already showed it.
2. **Malformed record.** `BAD_REQUEST`.
3. **Fence.** The target holds one `(epoch, seq)`, durably, in its generation
   store. A request below it, compared epoch first, is refused with the held value
   and changes nothing, `OBSERVE` included. A request above it has its fence
   durably recorded before anything else is done, whatever the request then comes
   to. Every response reports the held fence, so a status a controller publishes
   carries the fence it was read under.
4. **`OBSERVE`** answers phase, generation and activation. It never refuses on
   the descriptor revision and consults no idempotency record.
5. **Idempotency** (`APPLY`, `REMOVE`). A durable record keyed by
   `(workload_uid, idempotency_id)` holds the sha256 of the whole request and the
   response. The same identity with the same bytes replays the recorded response
   with no second commit, across restarts, whatever has changed since: a replayed
   status is the one recorded at the commit, and `OBSERVE` is what reads the
   present. The same identity with different bytes, a different fence included, is
   `REFUSED_CONFLICT`: retrying means resending the same bytes. The newest 256
   records are kept; past that, an old identity is a new request. Only a commit is
   recorded: a refusal changed nothing, so the same identity is evaluated afresh.
6. **Descriptor** (`APPLY`). A revision other than the sha256 of the descriptor
   file the agent was given, read at each request, is refused with the current
   one, for the controller to validate against.
7. **Bundle** (`APPLY`). The bundle is
   `<bundles>/<hex desired_bundle_digest>/{workload.json,resources.json,graph.yaml}`.
   The digest is the workload digest: the sha256 of `workload.json`, the same value
   `fluxor agent commit --bundle` records. `workload.json` absent is
   `BUNDLE_MISSING`. A manifest that does not hash to its directory's name, one that
   fails validation, or an artifact that does not match the digest the manifest
   pins is `REFUSED_ADMISSION`, as is a composition the target's capacity or
   reserved ports refuse. `diag` is the diagnostic verbatim. Nothing changes.
8. **Commit** (`APPLY`, `REMOVE`). The agent writes its intent, commits one
   generation through the same path as `fluxor agent commit`, publishes the plan
   for the runtime, then records the response. A crash anywhere in that leaves the
   same request safe to send again: a commit that landed is found in the store and
   not repeated, a publish that did not land is done by the retry. A `REMOVE` of a
   workload neither desired nor committed answers `OK` with no commit.

## What the activation digest proves

```text
sha256("fluxor.agent.activation\0" || workload_uid || workload_digest
       || applied_plan_digest || slot:u16 LE || owner_generation:u32 LE)
```

`applied_plan_digest` is not the agent's belief. The runtime reports, in
`owner_status.json`, the sha256 over the body of the plan it decoded and applied
(`plan_digest`). The digest is non-zero only when all of these hold: the status
file's writer is the same live process that wrote it; it reports the committed
generation; its `plan_digest` equals the committed plan's; the owner it reports
under the committed workload UID, slot and owner generation has every planned
module loaded and none terminated (`RUNNING` or `UNREADY`). A commit the runtime
has not reached therefore reads zero, not the previous activation, and so does an
owner that has ended.

It proves that a live runtime applied exactly the plan this store committed for
this workload digest, and that the owner the plan names is up under it.

It does not prove what code those modules are. A plan assigns an owner its slot,
module range, caps and leases; it does not carry the workload digest, and on Linux
the graph a runtime runs is the `--config` it was started with. The workload
digest in the formula comes from the agent's committed desired state, joined to
the runtime's report by workload UID. That the running graph was built from that
bundle is what deployment of the runtime's config must ensure.

## Transports

`fluxor agent serve` takes the store, publish path, bundles directory, descriptor,
target identity and controllers, and one transport.

| Transport | `serve` | `call` | Peer |
|---|---|---|---|
| Unix socket | `--socket PATH` | `--socket PATH` | local, whatever the client sends |
| stdio | `--stdio` | a parent process | the frame's, which the parent vouches for |
| Runtime | `--runtime R --config C` | `--runtime R --config C` | the channel's verified fingerprint |

```text
fluxor agent serve --store D --publish P --bundles B --descriptor F \
    --target-id <64 hex> --controller <64 hex> ... \
    (--socket PATH | --stdio | --runtime R --config C [--modules M] [--runtime-log L]) \
    [--profile linux] [--remove-grace SECONDS]

fluxor agent call (--socket PATH | --runtime R --config C [--modules M] [--runtime-log L]) \
    --op apply|remove|observe [--workload-uid <32 hex>] [--bundle-digest <64 hex>] \
    [--descriptor-revision <64 hex>] [--idempotency-id <32 hex>] \
    [--fence-epoch N] [--fence-seq N] [--target-id <64 hex>] [--timeout-ms N]
```

`call` prints the response as JSON and exits non-zero unless the result is `OK`,
so a refusal cannot read as success. A failed call prints no JSON.

### Remote

The remote transport is `remote_channel` over mutual `tls`, with no transport code
of its own: the `agent_listen` stack on a target, `agent_dial` on a controller. The
runtime carrying it takes frames on
stdin and gives them on stdout, and the channel's `peer_tag` prefix is the frame's
peer. On the local port `[len:u32][record]` is one `len32` record, channel table
`OctetStream:len32:8196`; the prefix stands outside the framing, so a record is
delimited however stdin and stdout split it.

```text
agent serve ⇄ fluxor-linux: cli ⇄ remote_channel (listen) ⇄ tls ⇄ net
                                                                    ║ mutual TLS
agent call  ⇄ fluxor-linux: cli ⇄ remote_channel (dial)   ⇄ tls ⇄ net
```

A graph includes the stack and names its certificate, key, trust anchor and the
URI the peer must carry, as absolute paths `tls` reads where it runs:

```yaml
target: linux
tick_us: 1000
scheduler: { accept_cycles: true }
include:
  - stack: agent_listen    # agent_dial, with `authority: host:port` for `port`
    as: agent
    params:
      port: 9310
      cert_file: /etc/fluxor/agent/target.pem
      key_file: /etc/fluxor/agent/target.key
      trust: /etc/fluxor/agent/controllers-ca.pem
      peer_uri: spiffe://fabric/controller/
```

A controller or target that speaks the protocol from a module of its own, rather
than through `fluxor agent`, includes `agent_dial_lane` or `agent_listen_lane`: the
same stack, parameters included, with the channel exported as `frames_in` and
`frames_out` in place of the two stdio modules. Each port carries the same
`[peer:32][len:u32][record]` frame. A graph includes one per target, each under its
own `as:`.

The runtime carrying the transport is not the runtime carrying the workloads. A
structural plan rebuilds a runtime's graph, sockets included, so a transport under
`FLUXOR_PLAN` would lose its session to the commit it was asked for. `serve` runs
its runtime with no plan. The workload runtime is started separately on the
publish path, and it writes the `owner_status.json` beside that path which `OBSERVE`
reads.

A call's runtime holds one session, for that call, and is stopped with it. Records
are not resumed: a request or answer lost with its session is the controller's to
send again under the same identity. A listener keeps one session per verified key,
the newest replacing the older, so a controller runs one call per key at a time: a
call whose session another's has taken over gets no answer and is sent again.

## Trust

| Check | By | Refused how |
|---|---|---|
| The peer's certificate chains to `trust`, proves possession of its key and carries `peer_uri` | `tls`, both ends | no handshake; the agent never sees the peer. A controller's call times out |
| The session belongs to the key `tls` verified | `remote_channel` `require_peer` | no session |
| The fingerprint is a controller of this target | the agent | `REFUSED_UNAUTHORIZED` |
| The `target_id` a response states is the fingerprint the channel verified, and `--target-id` if given | `fluxor agent call` | the call fails; nothing is printed as an answer |

A key fingerprint is the SHA-256 of the leaf's raw subjectPublicKey
(`peer_identity::fingerprint`).

A certificate's lifetime is checked under the stack's default `clock_policy:
require`, against a clock the platform vouches for: a Linux host whose clock is not
synchronised refuses every handshake rather than judge a lifetime by a clock nobody
disciplined. `clock_policy: unchecked` drops the check, and removing a controller
from the agent's `--controller` set is then what ends its authority.

This protocol does not authenticate workload content beyond its digest and the
bundle's own checks. The agent admits whatever bundle is in its bundles directory
under the digest a controller asks for; who placed it there, and who signed the
workload, are outside it. Whole-workload authorization is a separate format and is
not built here.

## Failures

| Result | Meaning | Changed | The controller |
|---|---|---|---|
| `OK` | done, or already done under this identity | one generation at most | reads `OBSERVE` for activation |
| `REFUSED_FENCED` | below the held fence | nothing | is superseded; stops, or takes a newer fence |
| `REFUSED_UNAUTHORIZED` | not a controller here | nothing | has the wrong target or no authority |
| `REFUSED_DESCRIPTOR` | another revision | the fence | revalidates against the revision answered, then sends again |
| `REFUSED_CONFLICT` | this identity was another request | the fence | has a bug: an identity names one request |
| `BUNDLE_MISSING` | nothing at that digest | the fence | delivers the bundle and sends the same request again |
| `REFUSED_ADMISSION` | validation or composition refused | the fence | surfaces `diag`; a rejected diagnostic is never success |
| `BAD_REQUEST` | malformed | nothing | has a bug |
| `FAULT` | the target could not read or write its own state | possibly a landed commit | sends the same request again |
| no answer | no session, or one lost | unknown | sends the same request again |
