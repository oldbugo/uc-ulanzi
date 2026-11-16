# ulanzi_au05

Driver for the Ulanzi AU05 "Vibe Key" (three keys, a knob and a microphone, with a 2.4 GHz USB-C
receiver, USB `FFF1:00DD`). It uses only the receiver's private HID collection: interface `MI_03`,
usage page `0xFFFC`, 64-byte reports. The keyboard, mouse and microphone parts are not touched.

Unified Control uses this crate. The vault page "Ulanzi AU05 Vibe Key facts" has the protocol evidence.

## What is in it

- `tea`: the fixed-key TEA cipher (64-bit blocks, 32 rounds, ECB). The key is a vendor constant.
  Keep it in private repositories only. Never put it in the vault or in anything public.
- `protocol`: the frame (`0x55`, seven cipher blocks, seven zero bytes), the decoder for device
  messages (key and knob events, the battery status every 10 s, replies), and the command allowlist
  (`Request`). Only a `Request` can be encoded, so a command that is not on the list cannot be sent.
- `session`: the safe queue. One request in flight, and never a second write while a reply is
  outstanding. Each write has a time limit of 2 s. Nothing is sent unless the key has sent a message in
  the last 11 s, because the key sleeps. No retry: a reply that does not come in time (20 s for key
  typing, cmd 0x50, which once took 15 s; 2 s for other commands) or a write that does not finish pauses
  sending for 30 s. After three stalls in a row it stops until the app calls `resume`. A set is sent only
  when the key is quiet: 1.5 s after it woke and 1.5 s after the last key or knob event. With
  `real_key`, the session refuses commands not checked on the real key.
- `fake`: a fake AU05 that is encrypted in both directions, sleeps like the real key, keeps its
  settings and records every command. Tests use only this.
- `windows`: the opt-in Windows transport. Importing the crate does no device I/O. Only the
  orchestrator may call `WindowsAu05::open_first`, with the user present. Its `write` checks every report
  itself (`protocol::check_outgoing`): it must decrypt to exactly one allowlisted, in-range command that was
  checked on the real key. Anything else is refused before it reaches the device.

## Evidence for each command

| Command | Bytes | Real key |
| --- | --- | --- |
| Battery, standby status, standby time, power-off time, control code, key typing, light, hooks mode, mic noise reduction (gets) | see `protocol.rs` | Answered (2026-11-16) |
| Set standby time | `01 01 2c 02 <u32 s>` | Sent and read back (600 s) |
| Set key typing | `01 06 50 00 <btn> 01 <n> <entries>` | Sent and read back (K3 = F22) |
| Set power-off time, light mode, all-on brightness, mic noise reduction | from static analysis | Not sent yet |
| Set one field of a light mode record (mask 0x04 type, 0x08 time, 0x10 breathe level, 0x20 breathe brightness, 0x40 always-on brightness) | `01 0b 88 04 <mask> <rec> ..` with the value at byte `8 + 5*rec + field` | Not sent yet |
| Set hooks mode | `01 0b 89 04 <0|1>` | Not sent yet |
| Get or set key typing for the knob press (button 3) | same layout, button 3 | Not sent yet |

`Request::verified_on_hardware()` records this table; Unified Control labels the others "Untested".
Since 2026-11-16 (user request: expose every parameter so the user can test them all at once),
`Request::allowed_on_real_key()` allows every known command on the real key. The never-send list below,
the value ranges, one request in flight, the time limits, no retry and the settle after wake still apply.
When a command is confirmed on the real key, add it to `verified_on_hardware` and its test.

Never sent (no encoder exists, `Request::plain` checks, and the real transport refuses them): reboot (0x0C, 0x26), serial
number, flash ID or UUID (0x0A, 0x0B, 0x81), receiver command 0x05, firmware or OTA, keep-alive 0x23.

## Key events (2026-11-16 finding)

Not every control reports on the private channel. In all captures only K1 (index 0) and the knob turns
(index 4 and 5) sent private events; K2, K3 and the knob press never did. Apps must not depend on private
key events for actions. The working method: the key types its own unused code (K1 F20, K2 F21, K3 F22,
knob press F19) and the app claims that code with a global hotkey. `reference/scripts/au05_k3_hotkey.py`
is the listen-only prototype that proved it with K3.

## Tests

```powershell
$env:CARGO_TARGET_DIR = 'C:/Users/pc/AppData/Local/Temp/uc-ulanzi-target'
cargo test -p ulanzi_au05
```

The tests use the fake key only. They open no window, play no sound and open no device.

`reference/` keeps the scripts and logs from the first hardware study (2026-11-16). The scripts open
the real key. Do not run them. They are a record only.
