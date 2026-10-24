# uc-ulanzi
UC: Ulanzi D200H dock and Dial engine for Unified Control

## Status: step 0.2, fake dock only

`crates/ulanzi_dock` is the protocol layer for the Ulanzi D200H (packet framing,
page ZIP builder with the firmware bad-byte workaround, event parsing, a
`Transport` trait and a `Dock` driver) plus a software `FakeDock`.
**There is no real HID yet** (that is step 1.1). Nothing here opens a device.

```
# use a temp target dir, as in CLAUDE.md
set CARGO_TARGET_DIR=C:/Users/pc/AppData/Local/Temp/uc-ulanzi-target
cargo test
cargo run --bin fake-dock -- <output folder>
```

Rule: never touch the real dock (USB 2207:0019) or the Ulanzi Dial from code or
tests in this repo until the real-HID step is explicitly started.

Ported code is credited in `NOTICE` (MIT).
