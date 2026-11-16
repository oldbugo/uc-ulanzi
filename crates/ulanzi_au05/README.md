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
- `session`: the safe queue. One request in flight. Each write has a time limit of 2 s. Nothing is sent
  until the key has sent a message in the last 15 s, because the key sleeps. A missing reply gets one
  retry. A write that does not finish is not retried. At the first stall the session pauses for
  30 s. After three stalls in a row it stops until the app calls `resume`.
- `fake`: a fake AU05 that is encrypted in both directions, sleeps like the real key, keeps its
  settings and records every command. Tests use only this.
- `windows`: the opt-in Windows transport. Importing the crate does no device I/O. Only the
  orchestrator may call `WindowsAu05::open_first`, with the user present.

## Evidence for each command

| Command | Bytes | Real key |
| --- | --- | --- |
| Battery, standby status, standby time, power-off time, control code, key typing, light, hooks mode, mic noise reduction (gets) | see `protocol.rs` | Answered (2026-11-16) |
| Set standby time | `01 01 2c 02 <u32 s>` | Sent and read back (600 s) |
| Set key typing | `01 06 50 00 <btn> 01 <n> <entries>` | Sent and read back (K3 = F22) |
| Set power-off time, light mode, all-on brightness, mic noise reduction, light work-mode type | from static analysis | Not sent yet |

`Request::verified_on_hardware()` records this table. Unified Control refuses an unverified set on a
real key. When the orchestrator has checked one on the real key, change that function and its test.

Never sent (no encoder exists, and `Request::plain` also checks): reboot (0x0C, 0x26), serial
number, flash ID or UUID (0x0A, 0x0B, 0x81), receiver command 0x05, firmware or OTA, keep-alive 0x23.

## Tests

```powershell
$env:CARGO_TARGET_DIR = 'C:/Users/pc/AppData/Local/Temp/uc-ulanzi-target'
cargo test -p ulanzi_au05
```

The tests use the fake key only. They open no window, play no sound and open no device.

`reference/` keeps the scripts and logs from the first hardware study (2026-11-16). The scripts open
the real key. Do not run them. They are a record only.
