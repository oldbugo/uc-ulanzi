# uc-ulanzi

UC: Ulanzi D200H dock and Dial engine for Unified Control. A separate private
repository; the common project also includes `oldbugo/unified-control` (app),
`oldbugo/coolerscreen` (cooler engine/app) and `oldbugo/ulanzi-toolkit` (existing
Studio plugins). GitHub topic: `unified-control`. No organisation is required.

## Status: step 1.1 driver implementation

`crates/ulanzi_dock` provides protocol framing, page/partial-page ZIP builders,
event parsing, a transport-independent `Dock`, a software `FakeDock`, a queued
`Session`, and explicit opt-in Windows HID transport. This is library groundwork;
Unified Control does not yet depend on this crate or control the real dock.

**Built and checked on Windows, 2026-10-30:** native transport code compiles;
30 automated tests pass using fake transports and pure byte/filter functions.
Tests cover safe ZIP chunking, partial updates preserving other displays,
partial changes in reconnect snapshots, queue order, failed continuation,
backoff, inactivity, disable, input parsing and the read-cancellation race.
No tests enumerate, open or write hardware. No installed app or plugin changed.

**Not physically verified:** native enumeration/filtering on this dock, report
sizes, shared handle opening, native cancellation/timeouts, unplug/replug,
sleep/resume, update speed, wide-area restoration or a sustained run. Earlier
protocol feasibility observations do not verify this new driver implementation.
The orchestrator and user must perform phase 1.2 acceptance before use.

## Build and quiet checks

Use the target folder and bounded command execution described in `CLAUDE.md`:

```powershell
$env:CARGO_TARGET_DIR = 'C:/Users/pc/AppData/Local/Temp/uc-ulanzi-target'
cargo test --workspace
cargo run --bin fake-dock -- <scratch-output-folder>
```

The demo builds a page, saves the fake dock's images and prints simulated events.
It has no real-device mode. Tests and the demo open no windows and play no sound.

## Connection contract

Importing the crate or creating `Session` performs no device I/O. A session calls
its caller-supplied connector only when explicitly enabled and ticked. The app
must first check that Studio has quit, obtain exclusive logical ownership of the
dock, and run work away from the UI thread. This crate does not terminate Studio
or modify drivers. The app-level coexistence guard is a later integration step.

`windows::WindowsHid::open_first(timeout)` is the explicit real-hardware entry
point. It filters HID attributes for `2207:0019`, SetupAPI hardware IDs for
interface `MI_00`, and both report capabilities for 1025 bytes. It never parses
the opaque device path or logs serial/path values. Read/write handles use shared
access, overlapped I/O and a five-second maximum per report; read calls may use
shorter deadlines. Native report ID zero is added/removed at this boundary.

Handles and preparsed descriptors have RAII cleanup. Cancellation requests are
followed by a bounded completion wait. If a driver does not retire cancelled I/O,
the transport becomes unusable and a cleanup thread retains its file, event,
buffer and OVERLAPPED until completion. A failed cleanup wait retains these
resources until process exit to avoid freeing memory still owned by the kernel.
This fallback has only been reviewed statically, not exercised on hardware.

`Session` serializes complete commands in a 32-entry queue, with an 8 MiB ZIP
limit. One tick writes at most one complete message, then reads one event. A page
write has a 30-second overall deadline checked between reports, plus at most the
current report's five-second deadline and cancellation wait. Disable therefore
waits for an active tick; it is not an interrupt. Applications must keep the
session on a worker thread/process and continue draining input between ticks.

Read/write errors or 35 seconds without valid inbound activity drop the
transport and pending writes. Reconnect uses one-to-30-second exponential retry
delays. Successfully sent full-page/partial-page images form a bounded merged
snapshot. Cached replay is off by default because images can contain expired
account readings: the app should render a new safe page after `Notice::Connected`.
`set_reconnect_restore(true)` opts into restoring static content from a new header.
It must never be enabled for account, clock, sensor or other live faces. A queued new full page takes
precedence. Failed writes are never continued. The caller must reapply brightness
and small-window data. Partial
updates sent without an earlier full page have no reconnect snapshot. These are
deterministic fake tests, not proof of recovery on the physical dock.

`set_wide_restore(Some(data))` optionally queues the reviewed small-window mode
after a wide-area press. It is off by default. Whether it defeats this firmware's
clock cycling requires hands-on acceptance. Only raw input state is preserved;
press/release comes from the action byte, not an assumed meaning of state.
Heartbeat, brightness replies and `0x010b` preserve opaque payloads.

## Protocol evidence

The reference implementation supports partial updates with the same manifest,
PNG ZIP and chunking as full pages, selecting command `0x000d`. Lock/unlock use
empty payloads. This resolves the phase-0 TODOs from primary source review;
it does not establish that these calls work on the user's D200H.

- [Bitfocus device implementation at d467064](https://github.com/bitfocus/companion-surface-ulanzi-stream-controller/blob/d467064ddab2a4508106244c05291931151b88ee/src/device.ts)
- [Bitfocus protocol](https://github.com/bitfocus/companion-surface-ulanzi-stream-controller/blob/d467064ddab2a4508106244c05291931151b88ee/src/protocol.ts)
- [Bitfocus ZIP builder](https://github.com/bitfocus/companion-surface-ulanzi-stream-controller/blob/d467064ddab2a4508106244c05291931151b88ee/src/zip-builder.ts)
- [strmdck device at 7e29ab3](https://github.com/redphx/strmdck/blob/7e29ab32d1692faed445024eda0a0cdd5c576710/src/strmdck/devices/ulanzi_d200.py)
- [Microsoft cancellation lifetime rules](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex)

No firmware, OTA, ADB or device-storage commands are implemented. No device
diagnostic is auto-run. Ported code and source licences are credited in `NOTICE`.
