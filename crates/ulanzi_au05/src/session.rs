//! A safe request queue over one AU05 transport.
//!
//! Rules (vault Practices item 26 and the 2026-11-16 incident, where a blocking write left the user's
//! keyboard misbehaving):
//! - Never block: every write has a time limit (2 s by default), every read a short wait.
//! - Send nothing until the key has sent a message recently (it sleeps; a write to a sleeping key blocks).
//! - One request in flight. A pause of 200 ms between commands, as in the proven scripts.
//! - A missing reply is retried once. A write that does not finish is never retried.
//! - At the first stall the session pauses (sends nothing for `stall_pause`, then only after a new message
//!   from the key). After `max_stalls` stalls in a row it is suspended until [`Session::resume`].
use crate::protocol::{self, ControlEvent, Incoming, Report, Reply, Request, StatusEvent};
use std::collections::VecDeque;
use std::io;
use std::time::{Duration, Instant};

pub trait Transport: Send {
    /// Write one report and return within `timeout`. A deadline is `io::ErrorKind::TimedOut`; whether the
    /// report reached the key is then unknown.
    fn write(&mut self, report: &Report, timeout: Duration) -> io::Result<()>;
    /// Wait at most `timeout` for one report. `Ok(None)` when nothing arrived.
    fn read(&mut self, timeout: Duration) -> io::Result<Option<Report>>;
}

impl<T: Transport + ?Sized> Transport for Box<T> {
    fn write(&mut self, report: &Report, timeout: Duration) -> io::Result<()> {
        (**self).write(report, timeout)
    }
    fn read(&mut self, timeout: Duration) -> io::Result<Option<Report>> {
        (**self).read(timeout)
    }
}

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub write_timeout: Duration,
    pub reply_timeout: Duration,
    /// A message from the key within this window means it is awake (status arrives about every 10 s).
    pub awake_window: Duration,
    pub gap: Duration,
    pub stall_pause: Duration,
    pub max_stalls: u32,
    pub queue_limit: usize,
    /// A queued request that could not be sent (key asleep) fails after this long.
    pub request_expiry: Duration,
}
impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            write_timeout: Duration::from_secs(2),
            reply_timeout: Duration::from_millis(1500),
            awake_window: Duration::from_secs(15),
            gap: Duration::from_millis(200),
            stall_pause: Duration::from_secs(30),
            max_stalls: 3,
            queue_limit: 16,
            request_expiry: Duration::from_secs(60),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// Open, but the key has not sent anything yet.
    WaitingForKey,
    Awake,
    /// The key sent messages before but not recently (probably asleep).
    Asleep,
    /// A write or reply stalled; nothing is sent for a while.
    Paused,
    /// Too many stalls in a row; nothing is sent until `resume`.
    Suspended,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    Invalid(String),
    QueueFull,
    /// The key did not wake before the request expired.
    Asleep,
    WriteTimeout,
    NoReply,
    Paused,
    Suspended,
    Closed,
}
impl Failure {
    pub fn message(&self) -> String {
        match self {
            Failure::Invalid(m) => m.clone(),
            Failure::QueueFull => "Too many requests are waiting for the key".into(),
            Failure::Asleep => "The key is asleep. Press a key or turn the knob to wake it".into(),
            Failure::WriteTimeout => "The key did not accept the command in time. Sending is paused".into(),
            Failure::NoReply => "The key did not answer. Sending is paused".into(),
            Failure::Paused => "Sending is paused after a slow reply".into(),
            Failure::Suspended => "Sending is stopped after repeated slow replies. Use Reconnect".into(),
            Failure::Closed => "The connection closed".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output {
    Control(ControlEvent),
    Status(StatusEvent),
    Done {
        ticket: u64,
        request: Request,
        result: Result<Reply, Failure>,
    },
}

struct Queued {
    ticket: u64,
    request: Request,
    at: Instant,
}
struct InFlight {
    ticket: u64,
    request: Request,
    sent: Instant,
    attempts: u8,
}

pub struct Session<T: Transport> {
    transport: T,
    cfg: SessionConfig,
    queue: VecDeque<Queued>,
    inflight: Option<InFlight>,
    last_rx: Option<Instant>,
    next_send: Instant,
    paused_until: Option<Instant>,
    stalls: u32,
    suspended: bool,
    /// Counters for diagnostics.
    pub sent: u64,
    pub stalled: u64,
}

impl<T: Transport> Session<T> {
    pub fn new(transport: T, cfg: SessionConfig) -> Self {
        Self {
            transport,
            cfg,
            queue: VecDeque::new(),
            inflight: None,
            last_rx: None,
            next_send: Instant::now(),
            paused_until: None,
            stalls: 0,
            suspended: false,
            sent: 0,
            stalled: 0,
        }
    }
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn state(&self) -> SessionState {
        let now = Instant::now();
        if self.suspended {
            SessionState::Suspended
        } else if self.paused_until.is_some_and(|t| now < t) {
            SessionState::Paused
        } else if self.last_rx.is_none() {
            SessionState::WaitingForKey
        } else if self.awake(now) {
            SessionState::Awake
        } else {
            SessionState::Asleep
        }
    }
    fn awake(&self, now: Instant) -> bool {
        self.last_rx.is_some_and(|t| now.duration_since(t) <= self.cfg.awake_window)
    }
    fn can_send(&self, now: Instant) -> bool {
        if self.suspended || !self.awake(now) || now < self.next_send {
            return false;
        }
        match self.paused_until {
            // After a pause, wait for a message that arrived after the pause ended.
            Some(until) => now >= until && self.last_rx.is_some_and(|t| t >= until),
            None => true,
        }
    }
    pub fn pending(&self) -> usize {
        self.queue.len() + usize::from(self.inflight.is_some())
    }

    /// Queue a request. It is checked against the allowlist ranges first.
    pub fn submit(&mut self, ticket: u64, request: Request) -> Result<(), Failure> {
        request.validate().map_err(Failure::Invalid)?;
        if self.suspended {
            return Err(Failure::Suspended);
        }
        if self.pending() >= self.cfg.queue_limit {
            return Err(Failure::QueueFull);
        }
        self.queue.push_back(Queued {
            ticket,
            request,
            at: Instant::now(),
        });
        Ok(())
    }

    /// Clear a pause or suspension (an explicit user action).
    pub fn resume(&mut self) {
        self.suspended = false;
        self.paused_until = None;
        self.stalls = 0;
    }

    /// Fail everything queued or in flight (on close or reconnect).
    pub fn fail_all(&mut self, why: Failure) -> Vec<Output> {
        let mut out = Vec::new();
        if let Some(f) = self.inflight.take() {
            out.push(Output::Done {
                ticket: f.ticket,
                request: f.request,
                result: Err(why.clone()),
            });
        }
        for q in self.queue.drain(..) {
            out.push(Output::Done {
                ticket: q.ticket,
                request: q.request,
                result: Err(why.clone()),
            });
        }
        out
    }

    fn stall(&mut self, now: Instant, out: &mut Vec<Output>) {
        self.stalled += 1;
        self.stalls += 1;
        if self.stalls >= self.cfg.max_stalls {
            self.suspended = true;
        } else {
            self.paused_until = Some(now + self.cfg.stall_pause);
        }
        let why = if self.suspended { Failure::Suspended } else { Failure::Paused };
        for q in self.queue.drain(..) {
            out.push(Output::Done {
                ticket: q.ticket,
                request: q.request,
                result: Err(why.clone()),
            });
        }
    }

    /// One round: read what arrived (waiting at most `wait`), handle reply deadlines, then send at most one
    /// request. An `Err` means the transport is broken: the caller closes it and reconnects later.
    pub fn tick(&mut self, wait: Duration) -> io::Result<Vec<Output>> {
        let mut out = Vec::new();
        let mut wait = wait;
        if let Some(f) = &self.inflight {
            let due = f.sent + self.cfg.reply_timeout;
            wait = wait.min(due.saturating_duration_since(Instant::now()));
        }
        for _ in 0..32 {
            let Some(report) = self.transport.read(wait)? else { break };
            wait = Duration::ZERO;
            let Some(plain) = protocol::decode_frame(&report) else { continue };
            self.last_rx = Some(Instant::now());
            match protocol::parse(&plain) {
                Incoming::Control(e) => out.push(Output::Control(e)),
                Incoming::Status(s) => out.push(Output::Status(s)),
                Incoming::Reply(r) => {
                    if self.inflight.as_ref().is_some_and(|f| f.request.matches(&r)) {
                        let f = self.inflight.take().unwrap();
                        self.stalls = 0;
                        self.paused_until = None;
                        out.push(Output::Done {
                            ticket: f.ticket,
                            request: f.request,
                            result: Ok(r),
                        });
                    } // a late or unmatched reply is dropped
                }
                Incoming::Other(_) => {}
            }
        }

        let now = Instant::now();
        if let Some(f) = &mut self.inflight {
            if now >= f.sent + self.cfg.reply_timeout {
                if f.attempts < 2 && !self.suspended {
                    // Retry once.
                    f.attempts += 1;
                    let report = f.request.frame();
                    match self.transport.write(&report, self.cfg.write_timeout) {
                        Ok(()) => {
                            self.sent += 1;
                            f.sent = Instant::now();
                        }
                        Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                            let f = self.inflight.take().unwrap();
                            out.push(Output::Done {
                                ticket: f.ticket,
                                request: f.request,
                                result: Err(Failure::WriteTimeout),
                            });
                            self.stall(now, &mut out);
                        }
                        Err(e) => return Err(e),
                    }
                } else {
                    let f = self.inflight.take().unwrap();
                    out.push(Output::Done {
                        ticket: f.ticket,
                        request: f.request,
                        result: Err(Failure::NoReply),
                    });
                    self.stall(now, &mut out);
                }
            }
        }

        // Requests that waited too long for the key to wake.
        while self
            .queue
            .front()
            .is_some_and(|q| now.duration_since(q.at) >= self.cfg.request_expiry)
        {
            let q = self.queue.pop_front().unwrap();
            out.push(Output::Done {
                ticket: q.ticket,
                request: q.request,
                result: Err(Failure::Asleep),
            });
        }

        if self.inflight.is_none() && !self.queue.is_empty() && self.can_send(now) {
            let q = self.queue.pop_front().unwrap();
            let report = q.request.frame();
            self.next_send = now + self.cfg.gap;
            match self.transport.write(&report, self.cfg.write_timeout) {
                Ok(()) => {
                    self.sent += 1;
                    self.inflight = Some(InFlight {
                        ticket: q.ticket,
                        request: q.request,
                        sent: Instant::now(),
                        attempts: 1,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    out.push(Output::Done {
                        ticket: q.ticket,
                        request: q.request,
                        result: Err(Failure::WriteTimeout),
                    });
                    self.stall(now, &mut out);
                }
                Err(e) => {
                    self.queue.push_front(q);
                    return Err(e);
                }
            }
        }
        Ok(out)
    }
}
