//! A fake AU05 for tests. It speaks the real encrypted framing in both directions, keeps the settings a real
//! key keeps, sleeps (a write to a sleeping fake blocks until its deadline, like the real key), and records
//! every command it receives so tests can check that nothing outside the allowlist was sent.
use crate::protocol::{
    self, Control, KeyEntry, KeyId, KeyTyping, LightState, MicNr, Report, NEVER_SEND, PLAIN_LEN,
};
use crate::session::Transport;
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct FakeState {
    pub awake: bool,
    pub disconnected: bool,
    pub millivolts: u16,
    pub percent: u8,
    pub standby_s: u32,
    pub sleep_s: u32,
    pub light: LightState,
    pub hooks_mode: u8,
    pub mic: MicNr,
    pub typing: [KeyTyping; 3],
    /// Every plaintext the fake received, in order.
    pub received: Vec<Vec<u8>>,
    /// Commands the fake does not know. A test failure if not empty.
    pub forbidden: Vec<Vec<u8>>,
    /// What the keyboard part typed on key presses ("Esc", "F22", ...).
    pub typed: Vec<String>,
    pub reply_delay: Duration,
    pub drop_replies: u32,
    pub stall_writes: bool,
    pub status_period: Option<Duration>,
    inbox: VecDeque<(Instant, Report)>,
    next_status: Option<Instant>,
}

impl Default for FakeState {
    /// Values as read from the user's key on 2026-11-16 (after the standby and K3 changes).
    fn default() -> Self {
        Self {
            awake: false,
            disconnected: false,
            millivolts: 3608,
            percent: 30,
            standby_s: 600,
            sleep_s: 3600,
            light: LightState {
                mode: 2,
                brightness: 7,
                records: [[2, 0x0a, 2, 7, 2], [2, 0x0a, 2, 7, 2], [2, 0x0a, 2, 7, 2], [1, 0x0a, 2, 7, 2]],
            },
            hooks_mode: 0,
            mic: MicNr { level: 0, a: 100, b: 100 },
            typing: [KeyTyping::factory(), KeyTyping::factory(), KeyTyping::own_code(KeyId::K3)],
            received: Vec::new(),
            forbidden: Vec::new(),
            typed: Vec::new(),
            reply_delay: Duration::from_millis(5),
            drop_replies: 0,
            stall_writes: false,
            status_period: Some(Duration::from_secs(10)),
            inbox: VecDeque::new(),
            next_status: None,
        }
    }
}

/// Shared control of a fake key while its transport is owned by a session.
#[derive(Clone, Default)]
pub struct FakeHandle(Arc<Mutex<FakeState>>);

pub struct FakeTransport(Arc<Mutex<FakeState>>);

pub fn fake_au05() -> (FakeTransport, FakeHandle) {
    let h = FakeHandle::default();
    (FakeTransport(h.0.clone()), h)
}

fn plain_report(bytes: &[u8]) -> Report {
    protocol::encode_frame(bytes)
}

impl FakeHandle {
    pub fn lock(&self) -> MutexGuard<'_, FakeState> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn transport(&self) -> FakeTransport {
        FakeTransport(self.0.clone())
    }
    /// Wake the key: it sends a status message at once.
    pub fn wake(&self) {
        let mut s = self.lock();
        s.awake = true;
        let report = status_report(&s);
        s.inbox.push_back((Instant::now(), report));
        s.next_status = s.status_period.map(|p| Instant::now() + p);
    }
    pub fn sleep(&self) {
        let mut s = self.lock();
        s.awake = false;
        s.next_status = None;
    }
    /// Press and release a control. A press wakes the key. K1..K3 also "type" their keystroke list.
    pub fn click(&self, control: Control) {
        self.wake();
        let mut s = self.lock();
        let code = control.own_code().unwrap_or(0);
        let idx = control.index();
        for pressed in [1u8, 0u8] {
            let r = plain_report(&[0x8b, 0x10, code, pressed, (idx & 0xff) as u8, (idx >> 8) as u8]);
            s.inbox.push_back((Instant::now(), r));
        }
        if let Some(k) = KeyId::from_index(idx as u8).filter(|_| idx < 3) {
            let t = s.typing[k.index() as usize].clone();
            let label = if t.is_factory() { k.factory_label().to_string() } else { t.label(k) };
            s.typed.push(label);
        }
    }
    pub fn received(&self) -> Vec<Vec<u8>> {
        self.lock().received.clone()
    }
    pub fn forbidden(&self) -> Vec<Vec<u8>> {
        self.lock().forbidden.clone()
    }
}

fn status_report(s: &FakeState) -> Report {
    let mv = s.millivolts.to_le_bytes();
    plain_report(&[0x0b, 0x7b, mv[0], mv[1], 0x08, s.percent, 0xf6, 0x01])
}

fn u32le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// The fake's answer to one plaintext command, or `None` (no reply) for unknown commands.
fn answer(s: &mut FakeState, p: &[u8; PLAIN_LEN]) -> Option<Vec<u8>> {
    if p[0] != 0x01 || NEVER_SEND.contains(&p[2]) || p[2] == 0x81 {
        return None;
    }
    let head = |flags: u8| vec![0x81, p[1], p[2], 0x10 | flags];
    let v = match (p[1], p[2], p[3]) {
        (0x01, 0x02, 0x01) => {
            let mut v = head(1);
            v.extend(s.millivolts.to_le_bytes());
            v.extend([s.percent, 0, 0xe7, 1, 1]);
            v
        }
        (0x01, 0x0d, 0x01) => [head(1), vec![0]].concat(),
        (0x01, 0x2c, 0x01) => [head(1), u32le(s.standby_s).to_vec()].concat(),
        (0x01, 0x2c, 0x02) => {
            s.standby_s = u32::from_le_bytes([p[4], p[5], p[6], p[7]]);
            [head(2), u32le(s.standby_s).to_vec()].concat()
        }
        (0x01, 0x42, 0x01) => [head(1), u32le(s.sleep_s).to_vec()].concat(),
        (0x01, 0x42, 0x02) => {
            s.sleep_s = u32::from_le_bytes([p[4], p[5], p[6], p[7]]);
            [head(2), u32le(s.sleep_s).to_vec()].concat()
        }
        (0x06, 0x10, 0x01) if p[4] == 0 && p[5] <= 5 => {
            let code = Control::from_index(p[5] as u16).own_code().unwrap_or(0);
            [head(1), vec![0, p[5], code]].concat()
        }
        (0x06, 0x50, 0x01) if p[4] <= 2 => {
            let t = &s.typing[p[4] as usize];
            let mut v = head(1);
            v.extend([p[4], u8::from(!t.is_factory()), t.0.len() as u8]);
            for e in &t.0 {
                v.extend(match *e {
                    KeyEntry::Usage(u) => [2, u],
                    KeyEntry::Modifiers(m) => [3, m],
                    KeyEntry::Unknown { kind, value } => [kind, value],
                });
            }
            v
        }
        (0x06, 0x50, 0x00) if p[4] <= 2 && p[5] == 1 && (p[6] as usize) <= protocol::MAX_KEY_ENTRIES => {
            let n = p[6] as usize;
            let entries = (0..n)
                .map(|i| match (p[7 + 2 * i], p[8 + 2 * i]) {
                    (2, u) => KeyEntry::Usage(u),
                    (3, m) => KeyEntry::Modifiers(m),
                    (kind, value) => KeyEntry::Unknown { kind, value },
                })
                .collect();
            s.typing[p[4] as usize] = KeyTyping(entries);
            [head(0), p[4..7 + 2 * n].to_vec()].concat()
        }
        (0x0b, 0x88, 0x01) => {
            let mut v = head(1);
            v.extend([0, 0, s.light.mode, s.light.brightness]);
            for r in s.light.records {
                v.extend(r);
            }
            v
        }
        (0x0b, 0x88, 0x04) => {
            match p[4] {
                1 => s.light.mode = p[6],
                2 => s.light.brightness = p[7],
                4 if p[5] <= 3 => s.light.records[p[5] as usize][0] = p[8],
                _ => return None,
            }
            [head(4), p[4..9].to_vec()].concat()
        }
        (0x0b, 0x89, 0x01) => [head(1), vec![s.hooks_mode]].concat(),
        (0x01, 0x90, 0x01) => {
            let mut v = head(1);
            v.push(s.mic.level);
            v.extend(s.mic.a.to_le_bytes());
            v.extend(s.mic.b.to_le_bytes());
            v
        }
        (0x01, 0x90, 0x04) => {
            s.mic = MicNr {
                level: p[4],
                a: u16::from_le_bytes([p[5], p[6]]),
                b: u16::from_le_bytes([p[7], p[8]]),
            };
            [head(4), p[4..9].to_vec()].concat()
        }
        _ => return None,
    };
    Some(v)
}

impl Transport for FakeTransport {
    fn write(&mut self, report: &Report, timeout: Duration) -> io::Result<()> {
        let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if s.disconnected {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "fake AU05 unplugged"));
        }
        if !s.awake || s.stall_writes {
            // Like the real key: a write to a sleeping key does not complete. Wait for the deadline.
            drop(s);
            std::thread::sleep(timeout);
            return Err(io::Error::new(io::ErrorKind::TimedOut, "fake AU05 write deadline"));
        }
        let Some(p) = protocol::decode_frame(report) else {
            s.forbidden.push(report.to_vec());
            return Ok(());
        };
        let used = p.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
        s.received.push(p[..used.max(4)].to_vec());
        match answer(&mut s, &p) {
            Some(v) if s.drop_replies > 0 => {
                let _ = v;
                s.drop_replies -= 1;
            }
            Some(v) => {
                let due = Instant::now() + s.reply_delay;
                s.inbox.push_back((due, plain_report(&v)));
            }
            None => s.forbidden.push(p[..used.max(4)].to_vec()),
        }
        Ok(())
    }

    fn read(&mut self, timeout: Duration) -> io::Result<Option<Report>> {
        let end = Instant::now() + timeout;
        loop {
            {
                let mut s = self.0.lock().unwrap_or_else(|e| e.into_inner());
                if s.disconnected {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "fake AU05 unplugged"));
                }
                let now = Instant::now();
                if s.awake {
                    if let Some(t) = s.next_status.filter(|t| now >= *t) {
                        let r = status_report(&s);
                        s.inbox.push_back((now, r));
                        s.next_status = s.status_period.map(|p| t + p);
                    }
                }
                if s.inbox.front().is_some_and(|(due, _)| *due <= now) {
                    return Ok(s.inbox.pop_front().map(|(_, r)| r));
                }
            }
            if Instant::now() >= end {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(2).min(end.saturating_duration_since(Instant::now())));
        }
    }
}
