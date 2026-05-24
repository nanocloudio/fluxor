# Fluxor Vision

Fluxor organizes systems around capabilities and graphs, not around
boxes and OS processes. This page explains why that shift matters and
what it makes possible. The architecture pages under
`docs/architecture/` are the source of truth for the current
implementation; this page is the argument for the direction.

## The Core Claim

A device is where code runs.
A capability is what the rest of the system depends on.
A graph is how work gets done.
An event is how state changes.
A handle is how authority is conveyed.

From that foundation, physical packaging stops being the primary unit
of architecture. The defining unit becomes the capability-bearing
module, expressed as part of a validated graph.

## What's Wrong With Device-Centric Models

Most embedded and IoT systems start from the device:

```text
device -> exposes protocol/API -> another device controls it
```

That assumption produces standards like HID for fixed
host-peripheral roles, AirPlay for fixed sender-receiver media,
Matter for device-type-oriented control, MQTT for transport without a
system-meaning model. Each is useful, and each cements the assumption
that the device is the primary architectural unit.

That assumption is increasingly limiting. People rarely want to
control a specific device — they want a system of capabilities to
cooperate regardless of how those capabilities happen to be
physically packaged. A button is usually modeled as belonging to a
specific product. It would be more useful as a first-class
capability that several providers can implement.

## Capability-Centric Composition

In a Fluxor system:

- a button is not a GPIO pin
- a display is not an HDMI monitor or SPI panel
- a keyboard is not a Bluetooth peripheral
- a speaker is not an I2S DAC
- a temperature reading is not a specific sensor chip
- a camera stream is not a CSI lane

Those are provider details. The system cares about button-press
intent, text input, a display surface, an audio sink, a temperature
state, a video stream. The graph expresses what a module needs;
target validation and stack expansion select the concrete provider
chain.

The button example is the clearest illustration of the payoff. Today a
button is a switch on a board, a touchscreen region in an appliance, a
soft button in a phone app, a remote control, an MQTT topic, a
voice-assistant action — five categories because they arrive through
five transports. In Fluxor they're all providers of the same semantic
object. The rest of the system needs only a trustworthy handle to the
capability and the authority to use it; it doesn't care where the
button physically lives.

The same generalization applies to keyboards, displays, sensors, and
control surfaces. A maintenance technician's tablet doesn't become "the
controller" — it temporarily binds to display, input, and
acknowledgement surfaces for a time-bounded session. A keyboard on one
machine can serve as the text-input capability for another. A
screencast becomes a special case of capability rebinding between
visual, audio, and input surfaces rather than a proprietary mirroring
protocol.

## The Execution Model Scales Further Than Expected

The same execution primitives — modules, typed channels, topological
walk, stream time, bounded arenas — express workloads across a
surprisingly wide range:

- microcontroller firmware driving displays, audio, and motor I/O
- retro-computer emulation with stream-clock A/V sync
- consensus and replication pipelines for distributed state
- protocol stacks from frame to TLS to HTTP/3
- storage services with line-rate NVMe throughput
- hardware-timed control loops with ISR-tier execution
- AI inference pipelines with deterministic timing budgets
- browser-hosted bundles consuming the same module outputs

None of these required changing the graph model. Each required
building modules and, in some cases, extending the execution model
with additional tiers: hardware-timer-driven execution for hard
real-time control, poll-mode execution for throughput-bound workloads,
demand-paged memory for datasets larger than physical RAM. The core
abstraction — modules connected by typed channels, executed with
explicit timing, validated before deployment — stayed the same.

That property is what makes the capability story credible. If a
capability like audio playback must be expressible on a Pico W with
PIO-driven I2S, on a CM5 with a DSP pipeline, and on a server-class
node streaming to a network speaker, the graph model has to work
across all of them. It does. Only the modules and their wiring
change.

## Local Determinism, Larger Graphs

Fluxor's immediate execution model is local: modules step in a graph,
communicate through channels, use declared provider contracts for
privileged resources. That local determinism is the foundation
everything else depends on.

The same graph vocabulary extends across edges that cross a process,
browser, host, or network boundary. Remote channels and protocol
surfaces are extensions of the channel model, not a separate
architecture. A module does not need a new conceptual interface just
because its provider moved from local hardware to another Fluxor
graph.

That property is what lets capabilities relocate: from cloud to edge,
from edge to device, from one hardware generation to the next, without
rewriting the system above them.

## Hardware Independence Without Pretending Hardware Is Generic

Fluxor does not hide meaningful hardware differences. It makes them
explicit at the right layer:

- target and board TOML describe available hardware and constraints
- platform code owns low-level register and boot behavior
- drivers expose narrow provider contracts or typed channel surfaces
- foundation modules compose those into higher-level services
- application modules depend on capabilities and content types

This is different from pretending every target is the same. It keeps
hardware-specific code local while preserving a stable graph model
above it. A retro-emulator config that runs on a Pico W, on a CM5
bare-metal stack, and as a WASM bundle in the browser does so because
the modules above the HAL are identical — only the providers
underneath swap.

## The Operating System Boundary Matters Less

A consequence of the model is that the traditional individual
operating system becomes less central as an organizational unit. It
doesn't disappear — it becomes an implementation detail of a Fluxor
participant rather than the place where meaning lives.

What matters across the system is:

- what capabilities exist
- what events they emit
- what commands they accept
- what authority governs access
- what timing guarantees hold
- how capabilities compose into a coherent system

In that frame, whether a capability runs on bare-metal Fluxor on an
RP2040, bare-metal on a CM5, Linux hosting a bridge, a browser UI, an
industrial controller, or a server-class node becomes secondary. The
semantic architecture sits above the host boundary.

## Inference as a Capability, Not a Platform

The AI ecosystem makes the point sharply. Today capabilities like
`object_detection` or `anomaly_alert` are tightly coupled to their
execution platform — model, runtime, and hardware form an inseparable
stack. Moving inference from cloud to edge or between devices means
rebuilding integrations.

In Fluxor, those are objects. An `object_detection` capability emits
detection events and accepts configuration commands. Its
implementation is internal: a quantized classifier on a Pico, an
NPU-accelerated model on an aarch64 board, a poll-mode pipeline on a
server, a recorded stream replayed for testing. The consumer binds to
the capability and receives events with the same semantic structure
regardless of provider.

The inference pipeline on every tier is the same graph shape: sensor
→ preprocess → inference → postprocess → action. Only the inference
module and its resource budget differ.

## Why This Is Not Theoretical

Each part of the argument corresponds to something concrete in the
current tree:

- the graph runtime, scheduler, and channel model run today across
  microcontroller, application-processor bare-metal, Linux-hosted,
  and browser-hosted targets
- ISR-tier execution, cooperative tiers, and poll-mode pipelines
  coexist in the same scheduler
- the capability/manifest/stack-expansion machinery resolves
  hardware to provider chains at build time
- modules cross targets unchanged: the same audio, codec, http,
  fat32, and ip modules ship in MCU, bare-metal CM5, Linux, and
  WASM examples
- remote channels and protocol surfaces extend the channel model
  across process and network boundaries

The pieces are not predictions. They are working primitives whose
combination is what makes the broader capability-centric story
concrete rather than aspirational.

## In One Sentence

Fluxor makes embedded and distributed systems composable around
stable capability-bearing modules and deterministic event-driven
graphs, so that physical device boundaries, host environments, and
transport protocols become implementation details rather than the
primary architecture.
