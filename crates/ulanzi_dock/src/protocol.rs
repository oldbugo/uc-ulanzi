//! Wire protocol of the Ulanzi D200/D200H deck.
//!
//! Ported from Bitfocus `companion-surface-ulanzi-stream-controller`
//! (`src/protocol.ts`, MIT, itself derived from redphx/strmdck). See `NOTICE`.
//!
//! Transport note: the real HID report is 1025 bytes = report id `0x00`
//! followed by the 1024-byte packet. Adding/stripping that report-id byte is
//! the transport's concern; everything in this crate works on 1024-byte packets.

use std::fmt;

pub const VENDOR_ID: u16 = 0x2207;
pub const PRODUCT_ID: u16 = 0x0019;

pub const PACKET_SIZE: usize = 1024;
pub const HEADER_SIZE: usize = 8;
/// Payload bytes carried by the first packet (1024 - 8).
pub const FIRST_CHUNK_DATA: usize = PACKET_SIZE - HEADER_SIZE;
pub const MAGIC: [u8; 2] = [0x7c, 0x7c];

pub type Packet = [u8; PACKET_SIZE];

/// Command ids. Out = host to dock, In = dock to host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Command {
    SetButtons = 0x0001,
    /// Same safe ZIP layout as SetButtons; only changed entries are included.
    PartiallyUpdateButtons = 0x000d,
    SetSmallWindowData = 0x0006,
    SetBrightness = 0x000a,
    /// `OUT_SET_LABEL_STYLE` in the source.
    SetLabelStyle = 0x000b,
    /// Empty payload (Bitfocus src/device.ts).
    LockScreen = 0x000f,
    /// Empty payload (Bitfocus src/device.ts).
    UnlockScreen = 0x0010,
    InButton = 0x0101,
    /// Not in the Bitfocus source; seen on hardware (about every 10 s).
    InHeartbeat = 0x0103,
    /// Not in the Bitfocus source; name and layout unknown.
    In010b = 0x010b,
    InDeviceInfo = 0x0303,
    /// Not in the Bitfocus source; brightness reply seen on hardware.
    InBrightnessAck = 0x030a,
}

impl Command {
    pub fn from_u16(v: u16) -> Option<Self> {
        use Command::*;
        Some(match v {
            0x0001 => SetButtons,
            0x000d => PartiallyUpdateButtons,
            0x0006 => SetSmallWindowData,
            0x000a => SetBrightness,
            0x000b => SetLabelStyle,
            0x000f => LockScreen,
            0x0010 => UnlockScreen,
            0x0101 => InButton,
            0x0103 => InHeartbeat,
            0x010b => In010b,
            0x0303 => InDeviceInfo,
            0x030a => InBrightnessAck,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    /// Fewer than 8 bytes.
    TooShort(usize),
    BadMagic([u8; 2]),
    /// Declared payload length does not fit in the bytes available.
    Truncated { declared: usize, available: usize },
    /// Data for this command is shorter than its layout requires.
    BadPayload(&'static str),
    /// Payload too large for a single packet.
    PayloadTooLarge(usize),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ProtocolError {}

/// Build the first framed packet: `7c 7c | cmd u16 BE | length u32 LE | data`, zero padded.
/// `length` is the total payload length (may exceed `data.len()` for chunked payloads).
pub fn build_framed_packet(command: u16, length: u32, data: &[u8]) -> Result<Packet, ProtocolError> {
    if data.len() > FIRST_CHUNK_DATA {
        return Err(ProtocolError::PayloadTooLarge(data.len()));
    }
    let mut p = [0u8; PACKET_SIZE];
    p[..2].copy_from_slice(&MAGIC);
    p[2..4].copy_from_slice(&command.to_be_bytes());
    p[4..8].copy_from_slice(&length.to_le_bytes());
    p[HEADER_SIZE..HEADER_SIZE + data.len()].copy_from_slice(data);
    Ok(p)
}

/// Single-packet command whose length equals the payload size.
pub fn build_simple_packet(command: Command, payload: &[u8]) -> Result<Packet, ProtocolError> {
    build_framed_packet(command as u16, payload.len() as u32, payload)
}

/// Split a payload into wire packets: the first carries 1016 bytes after the
/// header, follow-on packets are raw 1024-byte chunks (no header), zero padded.
pub fn build_chunked_packets(command: Command, payload: &[u8]) -> Vec<Packet> {
    let first_len = payload.len().min(FIRST_CHUNK_DATA);
    let mut out = vec![build_framed_packet(command as u16, payload.len() as u32, &payload[..first_len])
        .expect("first chunk fits")];
    for chunk in payload[first_len..].chunks(PACKET_SIZE) {
        let mut p = [0u8; PACKET_SIZE];
        p[..chunk.len()].copy_from_slice(chunk);
        out.push(p);
    }
    out
}

/// Firmware bug: the byte at payload offset 1016 + 1024*n (first byte of every
/// follow-on chunk) must not be 0x00 or 0x7c.
pub fn is_payload_safe(payload: &[u8]) -> bool {
    find_unsafe_offsets(payload).is_empty()
}

pub fn find_unsafe_offsets(payload: &[u8]) -> Vec<usize> {
    (FIRST_CHUNK_DATA..payload.len())
        .step_by(PACKET_SIZE)
        .filter(|&i| payload[i] == 0x00 || payload[i] == 0x7c)
        .collect()
}

/// Reassembles (possibly multi-packet) payloads from a stream of 1024-byte packets.
#[derive(Default)]
pub struct Reassembler {
    pending: Option<(u16, usize, Vec<u8>)>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one packet; returns `(command, payload)` when a message completes.
    /// While a message is in progress every packet is a headerless continuation.
    pub fn feed(&mut self, packet: &Packet) -> Result<Option<(u16, Vec<u8>)>, ProtocolError> {
        if let Some((cmd, total, mut buf)) = self.pending.take() {
            let take = (total - buf.len()).min(PACKET_SIZE);
            buf.extend_from_slice(&packet[..take]);
            return Ok(self.finish_or_keep(cmd, total, buf));
        }
        if packet[..2] != MAGIC {
            return Err(ProtocolError::BadMagic([packet[0], packet[1]]));
        }
        let cmd = u16::from_be_bytes([packet[2], packet[3]]);
        let total = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]) as usize;
        let take = total.min(FIRST_CHUNK_DATA);
        let buf = packet[HEADER_SIZE..HEADER_SIZE + take].to_vec();
        Ok(self.finish_or_keep(cmd, total, buf))
    }

    fn finish_or_keep(&mut self, cmd: u16, total: usize, buf: Vec<u8>) -> Option<(u16, Vec<u8>)> {
        if buf.len() >= total {
            Some((cmd, buf))
        } else {
            self.pending = Some((cmd, total, buf));
            None
        }
    }

    pub fn in_progress(&self) -> bool {
        self.pending.is_some()
    }
}

// ---------------------------------------------------------------- inbound

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonKind {
    Button,
    Encoder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonAction {
    Press,
    Release,
    Left,
    Right,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ButtonEvent {
    pub state: u8,
    pub index: u8,
    pub kind: ButtonKind,
    pub action: ButtonAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Button(ButtonEvent),
    DeviceInfo(String),
    Heartbeat(Vec<u8>),
    In010b(Vec<u8>),
    BrightnessAck(Vec<u8>),
    Unknown { cmd: u16, payload: Vec<u8> },
}

/// Parse one inbound report (1024-byte packet, or any slice of at least the header).
/// Layout of `InButton` data, as in the source: `[state, index, type(0x02=encoder), action]`
/// with action 1 press, 2 left, 3 right, anything else release.
pub fn parse_event(report: &[u8]) -> Result<Event, ProtocolError> {
    if report.len() < HEADER_SIZE {
        return Err(ProtocolError::TooShort(report.len()));
    }
    if report[..2] != MAGIC {
        return Err(ProtocolError::BadMagic([report[0], report[1]]));
    }
    let cmd = u16::from_be_bytes([report[2], report[3]]);
    let length = u32::from_le_bytes([report[4], report[5], report[6], report[7]]) as usize;
    let available = (report.len() - HEADER_SIZE).min(FIRST_CHUNK_DATA);
    if length > available {
        // Bitfocus device.ts d467064 identifies and ignores 0x010b ACKs before
        // parsing their declared payload length. This firmware reply is opaque;
        // a nonstandard length must not trigger a drop/reconnect/page loop.
        // Preserve valid ACK payloads below, but never infer or expose bytes for
        // a length we cannot validate. All other commands remain strict.
        if cmd == Command::In010b as u16 {
            return Ok(Event::In010b(Vec::new()));
        }
        return Err(ProtocolError::Truncated { declared: length, available });
    }
    let data = &report[HEADER_SIZE..HEADER_SIZE + length];
    Ok(match Command::from_u16(cmd) {
        Some(Command::InButton) => {
            if data.len() < 4 {
                return Err(ProtocolError::BadPayload("button event needs 4 bytes"));
            }
            Event::Button(ButtonEvent {
                state: data[0],
                index: data[1],
                kind: if data[2] == 0x02 { ButtonKind::Encoder } else { ButtonKind::Button },
                action: match data[3] {
                    1 => ButtonAction::Press,
                    2 => ButtonAction::Left,
                    3 => ButtonAction::Right,
                    _ => ButtonAction::Release,
                },
            })
        }
        Some(Command::InDeviceInfo) => {
            let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
            Event::DeviceInfo(data[..end].iter().map(|&b| b as char).collect())
        }
        Some(Command::InHeartbeat) => Event::Heartbeat(data.to_vec()),
        Some(Command::In010b) => Event::In010b(data.to_vec()),
        Some(Command::InBrightnessAck) => Event::BrightnessAck(data.to_vec()),
        _ => Event::Unknown { cmd, payload: data.to_vec() },
    })
}

/// Build an inbound button packet (used by the fake; layout as parsed above).
pub fn build_button_packet(ev: &ButtonEvent) -> Packet {
    let action = match ev.action {
        ButtonAction::Press => 1,
        ButtonAction::Release => 0,
        ButtonAction::Left => 2,
        ButtonAction::Right => 3,
    };
    let kind = if ev.kind == ButtonKind::Encoder { 2 } else { 0 };
    build_simple_packet(Command::InButton, &[ev.state, ev.index, kind, action]).expect("small")
}

// ---------------------------------------------------------------- outbound payloads

/// Brightness payload: ASCII decimal percent, clamped to 0..=100.
pub fn encode_brightness(percent: u8) -> Vec<u8> {
    percent.min(100).to_string().into_bytes()
}

#[derive(Clone, Debug)]
pub struct LabelStyle {
    /// "top" | "middle" | "bottom"
    pub align: String,
    /// 0xRRGGBB
    pub color: u32,
    pub font_name: String,
    pub show_title: bool,
    pub size: u32,
    pub weight: u32,
}

impl Default for LabelStyle {
    fn default() -> Self {
        Self { align: "bottom".into(), color: 0xFFFFFF, font_name: "Roboto".into(), show_title: true, size: 10, weight: 80 }
    }
}

pub fn encode_label_style(s: &LabelStyle) -> Vec<u8> {
    serde_json::json!({
        "Align": s.align, "Color": s.color, "FontName": s.font_name,
        "ShowTitle": s.show_title, "Size": s.size, "Weight": s.weight,
    })
    .to_string()
    .into_bytes()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum SmallWindowMode {
    Stats = 0,
    Dial = 1,
    Background = 2,
    DigitalDateTimeWeekday = 200,
    DigitalTimeWeekday = 201,
    DigitalTimeDate = 202,
    DigitalTime = 203,
}

#[derive(Clone, Debug)]
pub struct SmallWindowData {
    pub mode: SmallWindowMode,
    pub cpu: u32,
    pub mem: u32,
    pub gpu: u32,
    /// HH:MM:SS, 24 h. The source reads the local clock; here the caller supplies it.
    pub time: String,
    /// YYYY/MM/DD (modes 200 / 202).
    pub date: String,
    /// "Sun".."Sat" (modes 200 / 201).
    pub weekday: String,
    pub twelve_hour: bool,
}

impl Default for SmallWindowData {
    fn default() -> Self {
        Self {
            mode: SmallWindowMode::Dial,
            cpu: 0,
            mem: 0,
            gpu: 0,
            time: "00:00:00".into(),
            date: "1970/01/01".into(),
            weekday: "Thu".into(),
            twelve_hour: false,
        }
    }
}

/// `mode|cpu|mem|time|gpu|24H|suffix` (note field order: gpu after time, as in the source).
pub fn encode_small_window(d: &SmallWindowData) -> Vec<u8> {
    use SmallWindowMode::*;
    let suffix = match d.mode {
        DigitalDateTimeWeekday => format!("{} {}", d.date, d.weekday),
        DigitalTimeWeekday => d.weekday.clone(),
        DigitalTimeDate => d.date.clone(),
        _ => String::new(),
    };
    let fmt = if d.twelve_hour { "12H" } else { "24H" };
    format!("{}|{}|{}|{}|{}|{}|{}", d.mode as u16, d.cpu, d.mem, d.time, d.gpu, fmt, suffix).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_header_endianness_and_padding() {
        let p = build_simple_packet(Command::SetBrightness, b"50").unwrap();
        assert_eq!(&p[..2], &[0x7c, 0x7c]);
        assert_eq!(&p[2..4], &[0x00, 0x0a]); // BE
        assert_eq!(&p[4..8], &[2, 0, 0, 0]); // LE
        assert_eq!(&p[8..10], b"50");
        assert!(p[10..].iter().all(|&b| b == 0));
        let p = build_framed_packet(0x0102, 0x0102_0304, &[]).unwrap();
        assert_eq!(&p[2..4], &[0x01, 0x02]);
        assert_eq!(&p[4..8], &[0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn simple_packet_rejects_oversize() {
        assert!(build_simple_packet(Command::SetButtons, &[1; 1017]).is_err());
        assert!(build_simple_packet(Command::SetButtons, &[1; 1016]).is_ok());
    }

    #[test]
    fn chunking_and_reassembly() {
        for len in [0usize, 1, 1015, 1016, 1017, 2039, 2040, 2041, 5000, 20000] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8 + 1).collect();
            let packets = build_chunked_packets(Command::SetButtons, &payload);
            let expected = if len <= 1016 { 1 } else { 1 + (len - 1016).div_ceil(1024) };
            assert_eq!(packets.len(), expected, "len {len}");
            assert_eq!(u32::from_le_bytes(packets[0][4..8].try_into().unwrap()) as usize, len);
            let mut r = Reassembler::new();
            let mut done = None;
            for (i, p) in packets.iter().enumerate() {
                let res = r.feed(p).unwrap();
                if i + 1 < packets.len() {
                    assert!(res.is_none());
                } else {
                    done = res;
                }
            }
            assert_eq!(done, Some((1, payload)), "len {len}");
            assert!(!r.in_progress());
        }
    }

    #[test]
    fn reassembler_rejects_bad_magic() {
        assert!(matches!(Reassembler::new().feed(&[0u8; PACKET_SIZE]), Err(ProtocolError::BadMagic(_))));
    }

    #[test]
    fn unsafe_offsets_detected() {
        let mut v = vec![1u8; 3100];
        assert!(is_payload_safe(&v));
        v[1016] = 0x7c;
        v[2040] = 0;
        assert_eq!(find_unsafe_offsets(&v), vec![1016, 2040]);
        assert!(is_payload_safe(&[0u8; 1016])); // no follow-on chunk
    }

    fn pkt(cmd: u16, data: &[u8]) -> Packet {
        build_framed_packet(cmd, data.len() as u32, data).unwrap()
    }

    #[test]
    fn parse_press_release_encoder() {
        let ev = ButtonEvent { state: 1, index: 7, kind: ButtonKind::Button, action: ButtonAction::Press };
        assert_eq!(parse_event(&build_button_packet(&ev)).unwrap(), Event::Button(ev));
        let ev = ButtonEvent { state: 0, index: 7, kind: ButtonKind::Button, action: ButtonAction::Release };
        assert_eq!(parse_event(&build_button_packet(&ev)).unwrap(), Event::Button(ev));
        let e = parse_event(&pkt(0x0101, &[0, 1, 2, 3])).unwrap();
        assert_eq!(
            e,
            Event::Button(ButtonEvent { state: 0, index: 1, kind: ButtonKind::Encoder, action: ButtonAction::Right })
        );
    }

    #[test]
    fn parse_info_heartbeat_ack_unknown() {
        assert_eq!(parse_event(&pkt(0x0303, b"D200H v1\0junk")).unwrap(), Event::DeviceInfo("D200H v1".into()));
        assert_eq!(parse_event(&pkt(0x0103, &[])).unwrap(), Event::Heartbeat(vec![]));
        assert_eq!(parse_event(&pkt(0x030a, b"ok")).unwrap(), Event::BrightnessAck(b"ok".to_vec()));
        assert_eq!(parse_event(&pkt(0x010b, &[9])).unwrap(), Event::In010b(vec![9]));
        assert_eq!(parse_event(&pkt(0x7777, &[1, 2])).unwrap(), Event::Unknown { cmd: 0x7777, payload: vec![1, 2] });
    }

    #[test]
    fn opaque_010b_ack_length_does_not_force_reconnect() {
        for declared in [FIRST_CHUNK_DATA as u32 + 1, 65536, u32::MAX] {
            let report = build_framed_packet(Command::In010b as u16, declared, &[9]).unwrap();
            assert_eq!(parse_event(&report).unwrap(), Event::In010b(Vec::new()));
            // The exemption is for this observed ACK command only. Heartbeat,
            // button, device info and unknown messages still validate length.
            for command in [0x0103, 0x0101, 0x0303, 0x7777] {
                let report = build_framed_packet(command, declared, &[9]).unwrap();
                assert!(matches!(parse_event(&report), Err(ProtocolError::Truncated { .. })));
            }
        }
        let mut report = build_framed_packet(Command::In010b as u16, u32::MAX, &[]).unwrap();
        report[0] = 0;
        assert!(matches!(parse_event(&report), Err(ProtocolError::BadMagic(_))));
        assert!(matches!(parse_event(&[0x7c, 0x7c, 0x01, 0x0b]), Err(ProtocolError::TooShort(4))));
        // A framed ACK with a valid empty or bounded payload stays compatible.
        assert_eq!(parse_event(&pkt(0x010b, &[])).unwrap(), Event::In010b(vec![]));
        assert_eq!(parse_event(&pkt(0x010b, &[9, 10])).unwrap(), Event::In010b(vec![9, 10]));
    }

    #[test]
    fn parse_garbage_is_error_not_panic() {
        assert_eq!(parse_event(&[]), Err(ProtocolError::TooShort(0)));
        assert_eq!(parse_event(&[0x7c; 7]), Err(ProtocolError::TooShort(7)));
        assert!(matches!(parse_event(&[0u8; 1024]), Err(ProtocolError::BadMagic(_))));
        assert!(matches!(parse_event(&pkt(0x0101, &[1, 2])), Err(ProtocolError::BadPayload(_))));
        let mut p = pkt(0x0103, &[]);
        p[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(parse_event(&p), Err(ProtocolError::Truncated { .. })));
        assert!(matches!(parse_event(&p[..20]), Err(ProtocolError::Truncated { .. })));
        for n in 0..40 {
            let _ = parse_event(&p[..n]);
        }
    }

    #[test]
    fn payload_encoders() {
        assert_eq!(encode_brightness(50), b"50");
        assert_eq!(encode_brightness(250), b"100");
        let d = SmallWindowData {
            mode: SmallWindowMode::DigitalDateTimeWeekday,
            cpu: 1,
            mem: 2,
            gpu: 3,
            time: "12:34:56".into(),
            date: "2026/10/25".into(),
            weekday: "Sun".into(),
            twelve_hour: true,
        };
        assert_eq!(encode_small_window(&d), b"200|1|2|12:34:56|3|12H|2026/10/25 Sun");
        assert_eq!(encode_small_window(&SmallWindowData::default()), b"1|0|0|00:00:00|0|24H|");
        let s = String::from_utf8(encode_label_style(&LabelStyle::default())).unwrap();
        assert!(s.contains("\"Color\":16777215") && s.contains("\"FontName\":\"Roboto\""));
    }
}
