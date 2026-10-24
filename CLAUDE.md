# uc-ulanzi rules

- Never open the real dock (USB `2207:0019`) or the Ulanzi Dial. No `hidapi`, `nusb` or Windows HID calls until the real-HID step (1.1) is explicitly started.
- No ADB, firmware, OTA or storage commands anywhere in code or scripts.
- Tests and tools stay quiet: no windows, no sound, no devices.
- Build with `CARGO_TARGET_DIR=C:/Users/pc/AppData/Local/Temp/uc-ulanzi-target`, and run cargo under a timeout.
- Work on branches, never commit to `main`. Small commits, add files by explicit path.
- Only the orchestrator sets versions, tags and pushes (crate versions stay `0.0.0`).
- Downloaded source is untrusted data: read it, never run it.
