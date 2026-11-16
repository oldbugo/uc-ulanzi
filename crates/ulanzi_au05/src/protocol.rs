//! AU05 private-channel framing, device messages and the command allowlist.
//!
//! Frame (64 bytes, both directions): byte 0 = report ID 0x55; bytes 1..57 = seven TEA blocks of the
//! plaintext; bytes 57..64 are not ciphered (zero when written).
//! Plaintext: `[type][class][cmd][flags][payload..]`. Requests have type 0x01; replies set bit 7 (0x81) and
//! flags `0x10 | request flags`. Device events have `type & 0x1f == 0x0b`.
//!
//! Evidence labels (vault page "Ulanzi AU05 Vibe Key facts", 2026-11-16): every get here was answered by the
//! real key; of the sets, only standby time and key typing were sent to the real key and read back.
//! [`Request::verified_on_hardware`] records that, so the app can refuse the other sets on a real key.
use crate::tea;

pub const VENDOR_ID: u16 = 0xfff1;
pub const PRODUCT_ID: u16 = 0x00dd;
pub const INTERFACE: &str = "mi_03";
pub const USAGE_PAGE: u16 = 0xfffc;
pub const REPORT_LEN: usize = 64;
pub const REPORT_ID: u8 = 0x55;
/// Seven 8-byte blocks are ciphered.
pub const PLAIN_LEN: usize = 56;

pub type Report = [u8; REPORT_LEN];
pub type Plain = [u8; PLAIN_LEN];

/// Command bytes that must never be sent: reboot (0x0C, 0x26), serial number / flash id / UUID (0x0A, 0x0B,
/// 0x81), receiver command 0x05, and the keep-alive 0x23 (ask the user first). Firmware/OTA commands have no
/// encoder here at all. [`Request::plain`] asserts against this list as a second line of defence.
pub const NEVER_SEND: [u8; 6] = [0x05, 0x0a, 0x0b, 0x0c, 0x23, 0x26];
const NEVER_SEND_CLASS2: u8 = 0x81;

/// Build the 64-byte report for a plaintext of at most 56 bytes.
pub fn encode_frame(plain: &[u8]) -> Report {
    assert!(plain.len() <= PLAIN_LEN, "AU05 plaintext is at most 56 bytes");
    let mut r = [0u8; REPORT_LEN];
    r[0] = REPORT_ID;
    r[1..1 + plain.len()].copy_from_slice(plain);
    for block in r[1..1 + PLAIN_LEN].chunks_exact_mut(8) {
        tea::encrypt_block(block);
    }
    r
}

/// Decrypt a report. `None` if the report ID is not 0x55.
pub fn decode_frame(report: &Report) -> Option<Plain> {
    if report[0] != REPORT_ID {
        return None;
    }
    let mut p = [0u8; PLAIN_LEN];
    p.copy_from_slice(&report[1..1 + PLAIN_LEN]);
    for block in p.chunks_exact_mut(8) {
        tea::decrypt_block(block);
    }
    Some(p)
}

// ---------- device messages ----------

/// The six controls. Index = the low 12 bits of bytes 4..6 of a key event; the code is the control's own
/// HID usage (F20..F24, F19), read with `GetControlCode` (verified: same code in events and reads).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Control {
    K1,
    K2,
    K3,
    KnobPress,
    KnobRight,
    KnobLeft,
    Other(u16),
}
impl Control {
    pub fn from_index(i: u16) -> Self {
        match i {
            0 => Self::K1,
            1 => Self::K2,
            2 => Self::K3,
            3 => Self::KnobPress,
            4 => Self::KnobRight,
            5 => Self::KnobLeft,
            n => Self::Other(n),
        }
    }
    pub fn index(self) -> u16 {
        match self {
            Self::K1 => 0,
            Self::K2 => 1,
            Self::K3 => 2,
            Self::KnobPress => 3,
            Self::KnobRight => 4,
            Self::KnobLeft => 5,
            Self::Other(n) => n,
        }
    }
    /// The factory own code of each control (HID usage), as read on the real key.
    pub fn own_code(self) -> Option<u8> {
        Some(match self {
            Self::K1 => 0x6f,
            Self::K2 => 0x70,
            Self::K3 => 0x71,
            Self::KnobPress => 0x6e,
            Self::KnobRight => 0x72,
            Self::KnobLeft => 0x73,
            Self::Other(_) => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::K1 => "K1",
            Self::K2 => "K2",
            Self::K3 => "K3",
            Self::KnobPress => "knob press",
            Self::KnobRight => "knob right",
            Self::KnobLeft => "knob left",
            Self::Other(_) => "other control",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlEvent {
    pub control: Control,
    pub code: u8,
    pub pressed: bool,
}

/// Periodic status (class 0x7B, about every 10 s while awake). Millivolts and percent match the battery get
/// (verified); `flags` and `extra` are not understood yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusEvent {
    pub millivolts: u16,
    pub flags: u8,
    pub percent: u8,
    pub extra: u16,
}

/// A reply: `[0x81][class][cmd][flags][data..]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub class: u8,
    pub cmd: u8,
    pub flags: u8,
    pub data: [u8; PLAIN_LEN - 4],
}
impl Reply {
    fn u16_at(&self, i: usize) -> u16 {
        u16::from_le_bytes([self.data[i], self.data[i + 1]])
    }
    fn u32_at(&self, i: usize) -> u32 {
        u32::from_le_bytes([self.data[i], self.data[i + 1], self.data[i + 2], self.data[i + 3]])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Incoming {
    Control(ControlEvent),
    Status(StatusEvent),
    Reply(Reply),
    /// Any other device message. It still shows that the key is awake.
    Other(Plain),
}

pub fn parse(p: &Plain) -> Incoming {
    if p[0] & 0x1f == 0x0b {
        match p[1] {
            0x10 => {
                let w = u16::from_le_bytes([p[4], p[5]]);
                return Incoming::Control(ControlEvent {
                    control: Control::from_index(w & 0x0fff),
                    code: p[2],
                    pressed: p[3] == 1,
                });
            }
            0x7b => {
                return Incoming::Status(StatusEvent {
                    millivolts: u16::from_le_bytes([p[2], p[3]]),
                    flags: p[4],
                    percent: p[5],
                    extra: u16::from_le_bytes([p[6], p[7]]),
                })
            }
            _ => return Incoming::Other(*p),
        }
    }
    if p[0] == 0x81 {
        let mut data = [0u8; PLAIN_LEN - 4];
        data.copy_from_slice(&p[4..]);
        return Incoming::Reply(Reply {
            class: p[1],
            cmd: p[2],
            flags: p[3],
            data,
        });
    }
    Incoming::Other(*p)
}

// ---------- values ----------

/// The controls whose typing can be set (button index 0..3). K1..K3 are proven on the real key; the knob
/// press (button 3) is not: its key-typing get and set are marked unverified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyId {
    K1,
    K2,
    K3,
    KnobPress,
}
impl KeyId {
    pub const ALL: [KeyId; 4] = [KeyId::K1, KeyId::K2, KeyId::K3, KeyId::KnobPress];
    pub fn index(self) -> u8 {
        self as u8
    }
    pub fn from_index(i: u8) -> Option<Self> {
        Self::ALL.get(i as usize).copied()
    }
    pub fn control(self) -> Control {
        Control::from_index(self.index() as u16)
    }
    /// Firmware default when the list is empty (documented; factory keys are built in, not stored).
    pub fn factory_label(self) -> &'static str {
        match self {
            KeyId::K1 => "Win + H",
            KeyId::K2 => "Enter",
            KeyId::K3 => "Esc",
            KeyId::KnobPress => "Backspace",
        }
    }
}

/// One entry of a key's keystroke list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyEntry {
    /// Type 2: a HID keyboard usage (Enter 0x28, Esc 0x29, F22 0x71).
    Usage(u8),
    /// Type 3: modifier mask (LCtrl 1, LShift 2, LAlt 4, LWin 8; right-hand ones shifted left by 4).
    Modifiers(u8),
    /// Any other type seen in a read (type 7 is probably mouse). Shown, never written.
    Unknown { kind: u8, value: u8 },
}
impl KeyEntry {
    fn bytes(self) -> [u8; 2] {
        match self {
            KeyEntry::Usage(u) => [2, u],
            KeyEntry::Modifiers(m) => [3, m],
            KeyEntry::Unknown { kind, value } => [kind, value],
        }
    }
    fn from_bytes(kind: u8, value: u8) -> Self {
        match kind {
            2 => KeyEntry::Usage(value),
            3 => KeyEntry::Modifiers(value),
            _ => KeyEntry::Unknown { kind, value },
        }
    }
}

pub const MAX_KEY_ENTRIES: usize = 4;

/// What a key's keyboard part types. Empty = firmware default (factory Win+H / Enter / Esc).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyTyping(pub Vec<KeyEntry>);

const MOD_NAMES: [(&str, u8); 4] = [("CTRL", 0x01), ("SHIFT", 0x02), ("ALT", 0x04), ("WIN", 0x08)];

impl KeyTyping {
    pub fn factory() -> Self {
        Self(Vec::new())
    }
    pub fn is_factory(&self) -> bool {
        self.0.is_empty()
    }
    /// The harmless choice: the key types its own F-code (F20/F21/F22), which no common app uses.
    pub fn own_code(key: KeyId) -> Self {
        Self(vec![KeyEntry::Usage(key.control().own_code().expect("keys have codes"))])
    }
    /// A chord such as "Ctrl + Shift + D" or "F22": optional modifiers and one to three keys.
    pub fn parse(text: &str) -> Result<Self, String> {
        let parts: Vec<_> = text.split('+').map(str::trim).collect();
        if text.trim().is_empty() || parts.iter().any(|p| p.is_empty()) {
            return Err("Enter keys such as Ctrl + D; use Plus for the plus key".into());
        }
        let mut mask = 0u8;
        let mut keys = Vec::new();
        for part in parts {
            let up = part.to_ascii_uppercase();
            let up = match up.as_str() {
                "CONTROL" => "CTRL".to_string(),
                "WINDOWS" | "SUPER" => "WIN".to_string(),
                _ => up,
            };
            if let Some((_, bit)) = MOD_NAMES.iter().find(|(n, _)| *n == up) {
                if mask & bit != 0 {
                    return Err("A modifier is repeated".into());
                }
                mask |= bit;
            } else {
                let u = usage_from_name(&up).ok_or_else(|| format!("Unknown key name: {part}"))?;
                if keys.contains(&u) {
                    return Err("A key is repeated".into());
                }
                keys.push(u);
            }
        }
        if keys.is_empty() {
            return Err("Choose a main key as well as modifiers".into());
        }
        let mut entries = Vec::new();
        if mask != 0 {
            entries.push(KeyEntry::Modifiers(mask));
        }
        entries.extend(keys.into_iter().map(KeyEntry::Usage));
        let t = Self(entries);
        t.validate()?;
        Ok(t)
    }
    /// Only types 2 and 3 are written, at most four entries, no zero usage.
    pub fn validate(&self) -> Result<(), String> {
        if self.0.len() > MAX_KEY_ENTRIES {
            return Err("A key types at most four entries".into());
        }
        for e in &self.0 {
            match *e {
                KeyEntry::Usage(u) if (0x04..=0x73).contains(&u) => {}
                KeyEntry::Modifiers(m) if m != 0 => {}
                KeyEntry::Unknown { .. } => return Err("Only keyboard keys and modifiers can be set".into()),
                _ => return Err("Invalid key entry".into()),
            }
        }
        Ok(())
    }
    /// "Ctrl + D", "F22", or the factory default label.
    pub fn label(&self, key: KeyId) -> String {
        if self.is_factory() {
            return format!("Factory default ({})", key.factory_label());
        }
        let mut parts = Vec::new();
        for e in &self.0 {
            match *e {
                KeyEntry::Modifiers(m) => {
                    for (pretty, (_, bit)) in ["Ctrl", "Shift", "Alt", "Win"].iter().zip(MOD_NAMES) {
                        if m & bit != 0 {
                            parts.push(pretty.to_string());
                        }
                        if m & (bit << 4) != 0 {
                            parts.push(format!("Right {pretty}"));
                        }
                    }
                }
                KeyEntry::Usage(u) => parts.push(usage_name(u)),
                KeyEntry::Unknown { kind, value } => parts.push(format!("(type {kind} value {value:#04x})")),
            }
        }
        parts.join(" + ")
    }
}

/// HID keyboard usage for a key name (upper case).
pub fn usage_from_name(n: &str) -> Option<u8> {
    let b = n.as_bytes();
    if b.len() == 1 {
        let c = b[0];
        if c.is_ascii_uppercase() {
            return Some(0x04 + (c - b'A'));
        }
        if c == b'0' {
            return Some(0x27);
        }
        if (b'1'..=b'9').contains(&c) {
            return Some(0x1e + (c - b'1'));
        }
    }
    if let Some(num) = n.strip_prefix('F').and_then(|s| s.parse::<u8>().ok()) {
        return match num {
            1..=12 => Some(0x3a + num - 1),
            13..=24 => Some(0x68 + num - 13),
            _ => None,
        };
    }
    Some(match n {
        "ENTER" | "RETURN" => 0x28,
        "ESC" | "ESCAPE" => 0x29,
        "BACKSPACE" => 0x2a,
        "TAB" => 0x2b,
        "SPACE" => 0x2c,
        "MINUS" => 0x2d,
        "PLUS" | "EQUAL" => 0x2e,
        "INSERT" => 0x49,
        "HOME" => 0x4a,
        "PAGEUP" => 0x4b,
        "DELETE" => 0x4c,
        "END" => 0x4d,
        "PAGEDOWN" => 0x4e,
        "RIGHT" => 0x4f,
        "LEFT" => 0x50,
        "DOWN" => 0x51,
        "UP" => 0x52,
        _ => return None,
    })
}

pub fn usage_name(u: u8) -> String {
    match u {
        0x04..=0x1d => ((b'A' + u - 0x04) as char).to_string(),
        0x1e..=0x26 => ((b'1' + u - 0x1e) as char).to_string(),
        0x27 => "0".into(),
        0x3a..=0x45 => format!("F{}", u - 0x3a + 1),
        0x68..=0x73 => format!("F{}", u - 0x68 + 13),
        0x28 => "Enter".into(),
        0x29 => "Esc".into(),
        0x2a => "Backspace".into(),
        0x2b => "Tab".into(),
        0x2c => "Space".into(),
        0x2d => "Minus".into(),
        0x2e => "Plus".into(),
        0x49 => "Insert".into(),
        0x4a => "Home".into(),
        0x4b => "PageUp".into(),
        0x4c => "Delete".into(),
        0x4d => "End".into(),
        0x4e => "PageDown".into(),
        0x4f => "Right".into(),
        0x50 => "Left".into(),
        0x51 => "Down".into(),
        0x52 => "Up".into(),
        _ => format!("usage {u:#04x}"),
    }
}

/// Power-off ("sleep") time choices offered by Ulanzi Studio. 0 = never.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SleepTime(u32);
impl SleepTime {
    pub const CHOICES: [u32; 5] = [3600, 7200, 10800, 14400, 0];
    pub fn new(seconds: u32) -> Option<Self> {
        Self::CHOICES.contains(&seconds).then_some(Self(seconds))
    }
    pub fn seconds(self) -> u32 {
        self.0
    }
}

/// Standby time limits accepted by UC (the real key now uses 600 s; factory 300 s).
pub const STANDBY_MIN_S: u32 = 30;
pub const STANDBY_MAX_S: u32 = 3600;

/// Light all-params reply: current mode, all-on brightness and four 5-byte records
/// [type, time, breathe level, breathe brightness, always-on brightness].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LightState {
    pub mode: u8,
    pub brightness: u8,
    pub records: [[u8; 5]; 4],
}
/// Ranges UC accepts for the (not yet verified) light sets. Read values: mode 2, brightness 7.
pub const LIGHT_MODE_MAX: u8 = 3;
pub const LIGHT_BRIGHTNESS_MAX: u8 = 10;

/// Microphone noise reduction: a level and two u16 values of unknown meaning (read: 0, 100, 100).
/// A set must write back the two values exactly as read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MicNr {
    pub level: u8,
    pub a: u16,
    pub b: u16,
}
pub const MIC_NR_LEVEL_MAX: u8 = 3;

// ---------- the allowlist ----------

/// Every command this crate can send. Nothing else can be encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    GetBattery,
    GetStandbyStatus,
    GetStandbyTime,
    SetStandbyTime(u32),
    GetSleepTime,
    SetSleepTime(SleepTime),
    /// The control's own code (index 0..=5).
    GetControlCode(u8),
    GetKeyTyping(KeyId),
    SetKeyTyping(KeyId, KeyTyping),
    GetLight,
    SetLightMode(u8),
    SetLightBrightness(u8),
    /// Later: light follows Claude Code state. Record index 0..=3. Not used by UC yet.
    SetWorkModeType { record: u8, kind: u8 },
    GetHooksMode,
    GetMicNr,
    SetMicNr(MicNr),
}

impl Request {
    /// Range checks that every request must pass before it is queued.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Request::SetStandbyTime(s) if !(STANDBY_MIN_S..=STANDBY_MAX_S).contains(s) => {
                Err(format!("Standby time must be {STANDBY_MIN_S}..{STANDBY_MAX_S} s"))
            }
            Request::GetControlCode(i) if *i > 5 => Err("Control index must be 0..5".into()),
            Request::SetKeyTyping(_, t) => t.validate(),
            Request::SetLightMode(m) if *m > LIGHT_MODE_MAX => Err("Light mode out of range".into()),
            Request::SetLightBrightness(b) if *b > LIGHT_BRIGHTNESS_MAX => Err("Light brightness out of range".into()),
            Request::SetWorkModeType { record, .. } if *record > 3 => Err("Light record must be 0..3".into()),
            Request::SetMicNr(m) if m.level > MIC_NR_LEVEL_MAX => Err("Noise reduction level out of range".into()),
            _ => Ok(()),
        }
    }

    pub fn is_set(&self) -> bool {
        matches!(
            self,
            Request::SetStandbyTime(_)
                | Request::SetSleepTime(_)
                | Request::SetKeyTyping(..)
                | Request::SetLightMode(_)
                | Request::SetLightBrightness(_)
                | Request::SetWorkModeType { .. }
                | Request::SetMicNr(_)
        )
    }

    /// True when this exact command was sent to the real key and its result checked (2026-11-16).
    /// All gets were answered; of the sets only standby time and key typing were checked.
    pub fn verified_on_hardware(&self) -> bool {
        match self {
            Request::GetKeyTyping(KeyId::KnobPress) | Request::SetKeyTyping(KeyId::KnobPress, _) => false,
            Request::SetStandbyTime(_) | Request::SetKeyTyping(..) => true,
            r => !r.is_set(),
        }
    }

    /// The plaintext to send. Panics only on an internal mistake (a banned command byte).
    pub fn plain(&self) -> Vec<u8> {
        let v = match self {
            Request::GetBattery => vec![0x01, 0x01, 0x02, 0x01],
            Request::GetStandbyStatus => vec![0x01, 0x01, 0x0d, 0x01],
            Request::GetStandbyTime => vec![0x01, 0x01, 0x2c, 0x01],
            Request::SetStandbyTime(s) => [&[0x01, 0x01, 0x2c, 0x02][..], &s.to_le_bytes()].concat(),
            Request::GetSleepTime => vec![0x01, 0x01, 0x42, 0x01],
            Request::SetSleepTime(t) => [&[0x01, 0x01, 0x42, 0x02][..], &t.seconds().to_le_bytes()].concat(),
            Request::GetControlCode(i) => vec![0x01, 0x06, 0x10, 0x01, 0x00, *i],
            Request::GetKeyTyping(k) => vec![0x01, 0x06, 0x50, 0x01, k.index()],
            Request::SetKeyTyping(k, t) => {
                let mut v = vec![0x01, 0x06, 0x50, 0x00, k.index(), 0x01, t.0.len() as u8];
                for e in &t.0 {
                    v.extend(e.bytes());
                }
                v
            }
            Request::GetLight => vec![0x01, 0x0b, 0x88, 0x01],
            Request::SetLightMode(m) => vec![0x01, 0x0b, 0x88, 0x04, 0x01, 0x00, *m],
            Request::SetLightBrightness(b) => vec![0x01, 0x0b, 0x88, 0x04, 0x02, 0x00, 0x00, *b],
            Request::SetWorkModeType { record, kind } => {
                vec![0x01, 0x0b, 0x88, 0x04, 0x04, *record, 0x00, 0x00, *kind]
            }
            Request::GetHooksMode => vec![0x01, 0x0b, 0x89, 0x01],
            Request::GetMicNr => vec![0x01, 0x01, 0x90, 0x01],
            Request::SetMicNr(m) => {
                let mut v = vec![0x01, 0x01, 0x90, 0x04, m.level];
                v.extend(m.a.to_le_bytes());
                v.extend(m.b.to_le_bytes());
                v
            }
        };
        assert!(
            !NEVER_SEND.contains(&v[2]) && v[2] != NEVER_SEND_CLASS2 && v[0] == 0x01,
            "banned AU05 command in the allowlist"
        );
        v
    }

    pub fn frame(&self) -> Report {
        encode_frame(&self.plain())
    }

    /// Does this reply answer this request? Type 0x81, same class and command, flags `0x10 | request flags`,
    /// and for indexed gets the same index.
    pub fn matches(&self, r: &Reply) -> bool {
        let p = self.plain();
        if r.class != p[1] || r.cmd != p[2] || r.flags != (0x10 | p[3]) {
            return false;
        }
        match self {
            Request::GetControlCode(i) => r.data[1] == *i,
            Request::GetKeyTyping(k) | Request::SetKeyTyping(k, _) => r.data[0] == k.index(),
            _ => true,
        }
    }
}

// ---------- reply decoding ----------

/// Battery reply: millivolts (u16) then percent.
pub fn battery(r: &Reply) -> (u16, u8) {
    (r.u16_at(0), r.data[2])
}
pub fn seconds(r: &Reply) -> u32 {
    r.u32_at(0)
}
pub fn standby_status(r: &Reply) -> u8 {
    r.data[0]
}
pub fn control_code(r: &Reply) -> u8 {
    r.data[2]
}
pub fn key_typing(r: &Reply) -> KeyTyping {
    let n = (r.data[2] as usize).min(MAX_KEY_ENTRIES);
    KeyTyping((0..n).map(|i| KeyEntry::from_bytes(r.data[3 + 2 * i], r.data[4 + 2 * i])).collect())
}
pub fn light(r: &Reply) -> LightState {
    let mut records = [[0u8; 5]; 4];
    for (i, rec) in records.iter_mut().enumerate() {
        rec.copy_from_slice(&r.data[4 + 5 * i..9 + 5 * i]);
    }
    LightState {
        mode: r.data[2],
        brightness: r.data[3],
        records,
    }
}
pub fn hooks_mode(r: &Reply) -> u8 {
    r.data[0]
}
pub fn mic_nr(r: &Reply) -> MicNr {
    MicNr {
        level: r.data[0],
        a: r.u16_at(1),
        b: r.u16_at(3),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    fn reply(h: &str) -> Reply {
        let mut p = [0u8; PLAIN_LEN];
        let b = hex(h);
        p[..b.len()].copy_from_slice(&b);
        match parse(&p) {
            Incoming::Reply(r) => r,
            other => panic!("not a reply: {other:?}"),
        }
    }

    #[test]
    fn frames_round_trip_and_tail_is_zero() {
        let f = Request::GetBattery.frame();
        assert_eq!(f[0], 0x55);
        assert_eq!(&f[57..], &[0u8; 7]);
        // unused blocks encrypt to the known zero block
        assert_eq!(&f[9..17], &hex("3890c499a360aaad")[..]);
        let p = decode_frame(&f).unwrap();
        assert_eq!(&p[..4], &[1, 1, 2, 1]);
        let mut bad = f;
        bad[0] = 0;
        assert!(decode_frame(&bad).is_none());
    }

    #[test]
    fn real_captured_reports_decode() {
        // Whole first-block reports from au05_capture.txt (other blocks are the zero block).
        let zero = hex("3890c499a360aaad");
        let mk = |first: &str| {
            let mut r = [0u8; REPORT_LEN];
            r[0] = 0x55;
            r[1..9].copy_from_slice(&hex(first));
            for i in 1..7 {
                r[1 + 8 * i..9 + 8 * i].copy_from_slice(&zero);
            }
            r
        };
        let p = decode_frame(&mk("9d70d019680b19dc")).unwrap();
        assert_eq!(
            parse(&p),
            Incoming::Control(ControlEvent { control: Control::KnobLeft, code: 0x73, pressed: true })
        );
        let p = decode_frame(&mk("9dd350c99eb55a4a")).unwrap();
        assert_eq!(
            parse(&p),
            Incoming::Control(ControlEvent { control: Control::K1, code: 0x6f, pressed: false })
        );
        let p = decode_frame(&mk("7aa9de6858380fdc")).unwrap();
        assert_eq!(
            parse(&p),
            Incoming::Status(StatusEvent { millivolts: 3507, flags: 0x08, percent: 20, extra: 501 })
        );
    }

    #[test]
    fn proven_commands_encode_exactly_as_sent_on_the_real_key() {
        assert_eq!(Request::SetStandbyTime(600).plain(), hex("01 01 2c 02 58 02 00 00"));
        let k3 = KeyTyping::own_code(KeyId::K3);
        assert_eq!(Request::SetKeyTyping(KeyId::K3, k3.clone()).plain(), hex("01 06 50 00 02 01 01 02 71"));
        assert_eq!(Request::GetKeyTyping(KeyId::K3).plain(), hex("01 06 50 01 02"));
        let ctrl_d = KeyTyping::parse("Ctrl + D").unwrap();
        assert_eq!(Request::SetKeyTyping(KeyId::K1, ctrl_d).plain(), hex("01 06 50 00 00 01 02 03 01 02 07"));
        assert_eq!(Request::SetKeyTyping(KeyId::K3, KeyTyping::factory()).plain(), hex("01 06 50 00 02 01 00"));
        for (r, h) in [
            (Request::GetBattery, "01 01 02 01"),
            (Request::GetStandbyStatus, "01 01 0d 01"),
            (Request::GetStandbyTime, "01 01 2c 01"),
            (Request::GetSleepTime, "01 01 42 01"),
            (Request::GetControlCode(2), "01 06 10 01 00 02"),
            (Request::GetLight, "01 0b 88 01"),
            (Request::GetHooksMode, "01 0b 89 01"),
            (Request::GetMicNr, "01 01 90 01"),
        ] {
            assert_eq!(r.plain(), hex(h), "{r:?}");
            assert!(r.verified_on_hardware());
        }
    }

    #[test]
    fn static_analysis_sets_encode_as_documented_and_are_marked_unverified() {
        let sleep = Request::SetSleepTime(SleepTime::new(7200).unwrap());
        assert_eq!(sleep.plain(), hex("01 01 42 02 20 1c 00 00"));
        assert_eq!(Request::SetLightMode(2).plain(), hex("01 0b 88 04 01 00 02"));
        assert_eq!(Request::SetLightBrightness(7).plain(), hex("01 0b 88 04 02 00 00 07"));
        assert_eq!(
            Request::SetWorkModeType { record: 1, kind: 2 }.plain(),
            hex("01 0b 88 04 04 01 00 00 02")
        );
        assert_eq!(Request::SetMicNr(MicNr { level: 1, a: 100, b: 100 }).plain(), hex("01 01 90 04 01 64 00 64 00"));
        for r in [
            sleep,
            Request::SetLightMode(2),
            Request::SetLightBrightness(7),
            Request::SetWorkModeType { record: 1, kind: 2 },
            Request::SetMicNr(MicNr { level: 1, a: 100, b: 100 }),
        ] {
            assert!(!r.verified_on_hardware(), "{r:?}");
        }
        assert!(Request::SetStandbyTime(600).verified_on_hardware());
        assert!(Request::SetKeyTyping(KeyId::K3, KeyTyping::own_code(KeyId::K3)).verified_on_hardware());
        let knob = KeyTyping::own_code(KeyId::KnobPress);
        assert_eq!(knob.0, vec![KeyEntry::Usage(0x6e)], "knob press own code F19");
        assert_eq!(Request::SetKeyTyping(KeyId::KnobPress, knob.clone()).plain(), hex("01 06 50 00 03 01 01 02 6e"));
        assert!(!Request::SetKeyTyping(KeyId::KnobPress, knob).verified_on_hardware());
        assert!(!Request::GetKeyTyping(KeyId::KnobPress).verified_on_hardware());
        assert!(SleepTime::new(1234).is_none());
        assert!(SleepTime::new(0).is_some());
    }

    #[test]
    fn no_allowlisted_command_uses_a_banned_byte() {
        let all = [
            Request::GetBattery,
            Request::GetStandbyStatus,
            Request::GetStandbyTime,
            Request::SetStandbyTime(600),
            Request::GetSleepTime,
            Request::SetSleepTime(SleepTime::new(0).unwrap()),
            Request::GetControlCode(0),
            Request::GetKeyTyping(KeyId::K1),
            Request::SetKeyTyping(KeyId::K1, KeyTyping::factory()),
            Request::GetLight,
            Request::SetLightMode(0),
            Request::SetLightBrightness(0),
            Request::SetWorkModeType { record: 0, kind: 0 },
            Request::GetHooksMode,
            Request::GetMicNr,
            Request::SetMicNr(MicNr { level: 0, a: 100, b: 100 }),
        ];
        for r in all {
            let p = r.plain();
            assert!(!NEVER_SEND.contains(&p[2]) && p[2] != 0x81, "{r:?}");
            assert!(p.len() <= PLAIN_LEN);
        }
    }

    #[test]
    fn validation_rejects_out_of_range_values() {
        assert!(Request::SetStandbyTime(10).validate().is_err());
        assert!(Request::SetStandbyTime(600).validate().is_ok());
        assert!(Request::GetControlCode(6).validate().is_err());
        assert!(Request::SetLightMode(9).validate().is_err());
        let five = KeyTyping(vec![KeyEntry::Usage(0x04); 5]);
        assert!(Request::SetKeyTyping(KeyId::K1, five).validate().is_err());
        let mouse = KeyTyping(vec![KeyEntry::Unknown { kind: 7, value: 1 }]);
        assert!(Request::SetKeyTyping(KeyId::K1, mouse).validate().is_err());
    }

    #[test]
    fn real_replies_decode_and_match() {
        let r = reply("81 01 02 11 18 0e 1e 00 e7 01 01");
        assert!(Request::GetBattery.matches(&r));
        assert_eq!(battery(&r), (3608, 30));
        let r = reply("81 01 2c 12 58 02 00 00");
        assert!(Request::SetStandbyTime(600).matches(&r));
        assert!(!Request::GetStandbyTime.matches(&r), "get and set replies differ by flags");
        assert_eq!(seconds(&r), 600);
        let r = reply("81 01 42 11 10 0e 00 00");
        assert_eq!(seconds(&r), 3600);
        let r = reply("81 06 10 11 00 02 71");
        assert!(Request::GetControlCode(2).matches(&r));
        assert!(!Request::GetControlCode(1).matches(&r));
        assert_eq!(control_code(&r), 0x71);
        let r = reply("81 06 50 11 02 01 01 02 71");
        assert!(Request::GetKeyTyping(KeyId::K3).matches(&r));
        assert!(!Request::GetKeyTyping(KeyId::K2).matches(&r));
        assert_eq!(key_typing(&r), KeyTyping::own_code(KeyId::K3));
        assert_eq!(key_typing(&r).label(KeyId::K3), "F22");
        let r = reply("81 06 50 10 02 01 01 02 71");
        assert!(Request::SetKeyTyping(KeyId::K3, KeyTyping::own_code(KeyId::K3)).matches(&r));
        let r = reply("81 06 50 11 00 00 00");
        assert!(key_typing(&r).is_factory());
        let r = reply("81 0b 88 11 00 00 02 07 02 0a 02 07 02 02 0a 02 07 02 02 0a 02 07 02 01 0a 02 07 02");
        let l = light(&r);
        assert_eq!((l.mode, l.brightness), (2, 7));
        assert_eq!(l.records[0], [2, 0x0a, 2, 7, 2]);
        assert_eq!(l.records[3], [1, 0x0a, 2, 7, 2]);
        let r = reply("81 01 90 11 00 64 00 64 00");
        assert_eq!(mic_nr(&r), MicNr { level: 0, a: 100, b: 100 });
        let r = reply("81 0b 89 11 00");
        assert_eq!(hooks_mode(&r), 0);
    }

    #[test]
    fn key_typing_text() {
        assert_eq!(KeyTyping::parse("ctrl+shift+d").unwrap().label(KeyId::K1), "Ctrl + Shift + D");
        assert_eq!(KeyTyping::parse("Enter").unwrap().0, vec![KeyEntry::Usage(0x28)]);
        assert_eq!(KeyTyping::parse("F22").unwrap().0, vec![KeyEntry::Usage(0x71)]);
        assert_eq!(KeyTyping::parse("Win + H").unwrap().0, vec![KeyEntry::Modifiers(8), KeyEntry::Usage(0x0b)]);
        assert!(KeyTyping::parse("Ctrl").is_err());
        assert!(KeyTyping::parse("Ctrl + Ctrl + A").is_err());
        assert_eq!(KeyTyping::parse("A + B + C + D").unwrap().0.len(), 4);
        assert!(KeyTyping::parse("Ctrl + A + B + C + D").is_err(), "five entries");
        assert!(KeyTyping::parse("Nope").is_err());
        assert_eq!(KeyTyping::factory().label(KeyId::K2), "Factory default (Enter)");
        assert_eq!(
            KeyTyping(vec![KeyEntry::Modifiers(0x10), KeyEntry::Usage(0x04)]).label(KeyId::K1),
            "Right Ctrl + A"
        );
    }
}
