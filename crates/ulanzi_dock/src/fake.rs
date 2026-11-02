//! Software fake of the dock: implements `Transport` with no device access.

use crate::dock::Transport;
use crate::page::{cell_key, KEY_COUNT, WIDE_INDEX};
use crate::protocol::*;
use serde_json::Value;
use std::collections::VecDeque;
use std::fs;
use std::io::{self, Cursor, Read};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Default)]
pub struct FakeDock {
    out_dir: Option<PathBuf>,
    reasm: Reassembler,
    queue: VecDeque<Packet>,
    pub brightness: Option<u8>,
    /// Last small-window payload as text.
    pub small_window: Option<String>,
    pub label_style: Option<String>,
    pub locked: bool,
    pub pages_received: usize,
    pub partial_updates_received: usize,
    pub commands_received: Vec<u16>,
    pub last_manifest: Option<Value>,
    /// Payload offsets that broke the bad-byte rule in a received message.
    pub bad_byte_violations: Vec<usize>,
    /// Anything malformed or unexpected the fake saw (empty on a healthy run).
    pub errors: Vec<String>,
    pub unknown_commands: Vec<u16>,
}

impl FakeDock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Save each received page's PNGs and manifest into `dir`.
    pub fn with_out_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            out_dir: Some(dir.into()),
            ..Self::default()
        }
    }

    pub fn set_out_dir(&mut self, dir: impl Into<PathBuf>) {
        self.out_dir = Some(dir.into());
    }

    fn push(&mut self, p: Packet) {
        self.queue.push_back(p);
    }

    /// Note: the state byte mirrors the action (1 press / 0 release); real-device
    /// semantics of the state byte are unverified.
    pub fn press(&mut self, idx: u8) {
        self.push(build_button_packet(&ButtonEvent {
            state: 1,
            index: idx,
            kind: ButtonKind::Button,
            action: ButtonAction::Press,
        }));
    }

    pub fn release(&mut self, idx: u8) {
        self.push(build_button_packet(&ButtonEvent {
            state: 0,
            index: idx,
            kind: ButtonKind::Button,
            action: ButtonAction::Release,
        }));
    }

    pub fn heartbeat(&mut self) {
        self.push(build_simple_packet(Command::InHeartbeat, &[]).expect("small"));
    }

    pub fn device_info(&mut self, text: &str) {
        self.push(build_simple_packet(Command::InDeviceInfo, text.as_bytes()).expect("short info"));
    }

    /// Queue an arbitrary raw inbound packet (e.g. garbage, for robustness tests).
    pub fn inject_raw(&mut self, p: Packet) {
        self.push(p);
    }

    pub fn pending_events(&self) -> usize {
        self.queue.len()
    }

    fn handle(&mut self, cmd: u16, payload: Vec<u8>) {
        self.commands_received.push(cmd);
        if !is_payload_safe(&payload) {
            self.bad_byte_violations.extend(find_unsafe_offsets(&payload));
            self.errors.push(format!("command {cmd:#06x}: payload violates bad-byte rule"));
        }
        match Command::from_u16(cmd) {
            Some(Command::SetButtons) => {
                if let Err(e) = self.accept_page(&payload, false) {
                    self.errors.push(format!("page rejected: {e}"));
                }
            }
            Some(Command::PartiallyUpdateButtons) => {
                if let Err(e) = self.accept_page(&payload, true) {
                    self.errors.push(format!("partial page rejected: {e}"));
                } else {
                    self.partial_updates_received += 1;
                }
            }
            Some(Command::SetBrightness) => {
                match std::str::from_utf8(&payload).ok().and_then(|s| s.parse::<u8>().ok()) {
                    Some(v) if v <= 100 => {
                        self.brightness = Some(v);
                        // Real hardware answered with 0x030a.
                        let ack = build_simple_packet(Command::InBrightnessAck, &[]).expect("small");
                        self.push(ack);
                    }
                    _ => self.errors.push("bad brightness payload".into()),
                }
            }
            Some(Command::SetSmallWindowData) => self.small_window = Some(String::from_utf8_lossy(&payload).into_owned()),
            Some(Command::SetLabelStyle) => self.label_style = Some(String::from_utf8_lossy(&payload).into_owned()),
            Some(Command::LockScreen) => self.locked = true,
            Some(Command::UnlockScreen) => self.locked = false,
            _ => {
                self.unknown_commands.push(cmd);
            }
        }
    }

    fn accept_page(&mut self, zip_bytes: &[u8], partial: bool) -> Result<(), String> {
        let mut ar = zip::ZipArchive::new(Cursor::new(zip_bytes)).map_err(|e| e.to_string())?;
        let mut manifest_text = String::new();
        ar.by_name("manifest.json")
            .map_err(|e| format!("manifest.json: {e}"))?
            .read_to_string(&mut manifest_text)
            .map_err(|e| e.to_string())?;
        let manifest: Value = serde_json::from_str(&manifest_text).map_err(|e| format!("manifest json: {e}"))?;
        let obj = manifest.as_object().ok_or("manifest is not an object")?;

        let mut files: Vec<(String, Vec<u8>)> = Vec::new();
        let mut cleared = Vec::new();
        for (slot, entry) in obj {
            let (c, r) = slot.split_once('_').ok_or_else(|| format!("bad slot {slot}"))?;
            let (c, r): (u8, u8) = (
                c.parse().map_err(|_| format!("bad slot {slot}"))?,
                r.parse().map_err(|_| format!("bad slot {slot}"))?,
            );
            let idx = cell_key(c, r).ok_or_else(|| format!("slot {slot} not on the dock"))?;
            entry
                .get("State")
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("{slot}: no State"))?;
            let vp = entry
                .get("ViewParam")
                .and_then(Value::as_array)
                .filter(|a| !a.is_empty())
                .ok_or_else(|| format!("{slot}: no ViewParam"))?;
            let name = if idx == WIDE_INDEX {
                "wide.png".to_string()
            } else {
                format!("key_{idx:02}.png")
            };
            if let Some(icon) = vp[0].get("Icon").and_then(Value::as_str) {
                let mut data = Vec::new();
                ar.by_name(icon)
                    .map_err(|e| format!("{slot}: icon {icon}: {e}"))?
                    .read_to_end(&mut data)
                    .map_err(|e| e.to_string())?;
                if !data.starts_with(&[0x89, b'P', b'N', b'G']) {
                    return Err(format!("{slot}: icon is not a PNG"));
                }
                files.push((name, data));
            } else {
                cleared.push(name);
            }
        }
        debug_assert!(KEY_COUNT == 13);

        let next_manifest = if partial {
            let mut merged = self.last_manifest.clone().unwrap_or_else(|| serde_json::json!({}));
            merged.as_object_mut().ok_or("previous manifest invalid")?.extend(obj.clone());
            merged
        } else {
            manifest
        };

        if let Some(dir) = &self.out_dir {
            fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            for entry in fs::read_dir(dir).map_err(|e| e.to_string())?.flatten() {
                let n = entry.file_name().to_string_lossy().into_owned();
                if !partial && (n == "wide.png" || n == "manifest.json" || (n.starts_with("key_") && n.ends_with(".png"))) {
                    let _ = fs::remove_file(entry.path());
                }
            }
            for (name, data) in &files {
                fs::write(dir.join(name), data).map_err(|e| e.to_string())?;
            }
            if partial {
                for name in cleared {
                    let _ = fs::remove_file(dir.join(name));
                }
            }
            fs::write(dir.join("manifest.json"), next_manifest.to_string()).map_err(|e| e.to_string())?;
        }
        self.pages_received += 1;
        self.last_manifest = Some(next_manifest);
        Ok(())
    }
}

impl Transport for FakeDock {
    fn write(&mut self, packet: &Packet) -> io::Result<()> {
        match self.reasm.feed(packet) {
            Ok(Some((cmd, payload))) => self.handle(cmd, payload),
            Ok(None) => {}
            Err(e) => self.errors.push(format!("bad packet: {e}")),
        }
        Ok(())
    }

    /// Returns queued events immediately; never sleeps.
    fn read(&mut self, _timeout: Duration) -> io::Result<Option<Packet>> {
        Ok(self.queue.pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dock::Dock;
    use crate::page::PageSpec;

    fn solid(w: u32, h: u32, rgb: [u8; 3]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut out, w, h);
            enc.set_color(png::ColorType::Rgb);
            enc.set_depth(png::BitDepth::Eight);
            let mut wr = enc.write_header().unwrap();
            let data: Vec<u8> = (0..(w * h * 3) as usize).map(|i| rgb[i % 3]).collect();
            wr.write_image_data(&data).unwrap();
        }
        out
    }

    #[test]
    fn full_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let mut dock = Dock::new(FakeDock::with_out_dir(tmp.path()));
        let mut spec = PageSpec::new();
        let mut sent = Vec::new();
        for i in 0..13usize {
            let img = solid(196, 196, [i as u8 * 19, 255 - i as u8 * 11, 40]);
            spec.set_key(i, Some(&format!("K{i}")), img.clone());
            sent.push(img);
        }
        let wide = solid(458, 196, [10, 20, 30]);
        spec.wide_png = Some(wide.clone());
        dock.set_page(&spec).unwrap();
        dock.set_brightness(42).unwrap();
        dock.lock_screen().unwrap();

        let f = dock.transport();
        assert!(f.errors.is_empty(), "{:?}", f.errors);
        assert!(f.bad_byte_violations.is_empty());
        assert_eq!(f.pages_received, 1);
        assert_eq!(f.brightness, Some(42));
        assert!(f.locked);
        for (i, img) in sent.iter().enumerate() {
            assert_eq!(&std::fs::read(tmp.path().join(format!("key_{i:02}.png"))).unwrap(), img);
        }
        assert_eq!(std::fs::read(tmp.path().join("wide.png")).unwrap(), wide);
        assert!(tmp.path().join("manifest.json").exists());

        dock.unlock_screen().unwrap();
        dock.set_small_window(&SmallWindowData::default()).unwrap();
        assert!(!dock.transport().locked);
        assert_eq!(dock.transport().small_window.as_deref(), Some("1|0|0|00:00:00|0|24H|"));

        // events: brightness ack first, then ours
        let t = Duration::from_millis(1);
        assert_eq!(dock.poll_event(t).unwrap(), Some(Event::BrightnessAck(vec![])));
        dock.transport_mut().press(3);
        dock.transport_mut().release(3);
        dock.transport_mut().heartbeat();
        dock.transport_mut().device_info("D200H");
        let ev = |a| {
            Event::Button(ButtonEvent {
                state: (a == ButtonAction::Press) as u8,
                index: 3,
                kind: ButtonKind::Button,
                action: a,
            })
        };
        assert_eq!(dock.poll_event(t).unwrap(), Some(ev(ButtonAction::Press)));
        assert_eq!(dock.poll_event(t).unwrap(), Some(ev(ButtonAction::Release)));
        assert_eq!(dock.poll_event(t).unwrap(), Some(Event::Heartbeat(vec![])));
        assert_eq!(dock.poll_event(t).unwrap(), Some(Event::DeviceInfo("D200H".into())));
        assert_eq!(dock.poll_event(t).unwrap(), None);
    }

    #[test]
    fn partial_keeps_unrelated_images_and_clears_only_selected_cell() {
        use crate::page::{build_page_zip, build_partial_page_zip};
        let dir = tempfile::tempdir().unwrap();
        let mut dock = Dock::new(FakeDock::with_out_dir(dir.path()));
        let mut spec = PageSpec::new();
        let keep = solid(196, 196, [1, 2, 3]);
        spec.set_key(0, None, solid(196, 196, [4, 5, 6]));
        spec.set_key(1, None, keep.clone());
        dock.set_buttons_zip(&build_page_zip(&spec).unwrap()).unwrap();
        dock.update_buttons_zip(&build_partial_page_zip(&PageSpec::new(), &[0]).unwrap())
            .unwrap();
        assert!(!dir.path().join("key_00.png").exists());
        assert_eq!(fs::read(dir.path().join("key_01.png")).unwrap(), keep);
        let disk: Value = serde_json::from_slice(&fs::read(dir.path().join("manifest.json")).unwrap()).unwrap();
        assert_eq!(disk, dock.transport().last_manifest.clone().unwrap());
        assert_eq!(disk["1_0"]["ViewParam"][0]["Icon"], "Images/k01.png");
    }

    #[test]
    fn fake_flags_bad_byte_zip() {
        // Hand-craft a multi-packet SetButtons payload with 0x7c at offset 1016.
        let mut payload = vec![1u8; 3000];
        payload[1016] = 0x7c;
        let mut fake = FakeDock::new();
        for p in build_chunked_packets(Command::SetButtons, &payload) {
            fake.write(&p).unwrap();
        }
        assert_eq!(fake.bad_byte_violations, vec![1016]);
        assert!(!fake.errors.is_empty());
    }

    #[test]
    fn dock_refuses_unsafe_zip() {
        let mut payload = vec![1u8; 2000];
        payload[1016] = 0;
        let mut dock = Dock::new(FakeDock::new());
        assert!(dock.set_buttons_zip(&payload).is_err());
        assert_eq!(dock.transport().pages_received, 0);
    }

    #[test]
    fn garbage_inbound_is_an_error_not_a_panic() {
        let mut dock = Dock::new(FakeDock::new());
        dock.transport_mut().inject_raw([0xAB; PACKET_SIZE]);
        let e = dock.poll_event(Duration::ZERO).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn unknown_command_is_recorded() {
        let mut fake = FakeDock::new();
        fake.write(&build_framed_packet(0x0abc, 0, &[]).unwrap()).unwrap();
        assert_eq!(fake.unknown_commands, vec![0x0abc]);
    }
}
