//! A safe request queue over one AU05 transport.
//!
//! Rules (vault Practices item 26 and the 2026-11-16 incident, where a blocking write left the user's
//! keyboard misbehaving; orchestrator review of 2026-11-16):
//! - Never block: every write has a time limit (2 s by default), every read a short wait.
//! - Send nothing until the key has sent a message recently (it sleeps; a write to a sleeping key blocks).
//! - One request in flight, and never a second write while a reply is outstanding. A 200 ms gap between
//!   commands, as in the proven scripts.
//! - No retry. A reply that does not arrive in time (20 s for key typing, cmd 0x50, which once took 15 s;
//!   2 s for others) or a write that does not finish pauses the session at once.
//! - A set is sent only when the key has been quiet: 1.5 s after it woke and 1.5 s after the last key or
//!   knob event, so a setting never lands while the user is pressing keys.
//! - At the first stall the session pauses (sends nothing for `stall_pause`, then only after a new message
//!   from the key). After `max_stalls` stalls in a row it is suspended until [`Session::resume`].
//! - With `real_key`, requests not checked on the real key (`Request::verified_on_hardware`) are refused.
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
    /// Reply wait for most commands.
    pub reply_timeout: Duration,
    /// Reply wait for key typing (cmd 0x50): one real read took 15 s.
    pub slow_reply_timeout: Duration,
    /// A message from the key within this window means it is awake (status arrives about every 10 s).
    pub awake_window: Duration,
    pub gap: Duration,
    /// Quiet time after a wake and after a key or knob event before any set is sent.
    pub settle: Duration,
    pub stall_pause: Duration,
    pub max_stalls: u32,
    pub queue_limit: usize,
    /// A queued request fails after the key has not been awake for this long.
    pub request_expiry: Duration,
    /// A real key: refuse requests that were not checked on the real key.
    pub real_key: bool,
}
impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            write_timeout: Duration::from_secs(2),
            reply_timeout: Duration::from_secs(2),
            slow_reply_timeout: Duration::from_secs(20),
            awake_window: Duration::from_secs(11),
            gap: Duration::from_millis(200),
            settle: Duration::from_millis(1500),
            stall_pause: Duration::from_secs(30),
            max_stalls: 3,
            queue_limit: 16,
            request_expiry: Duration::from_secs(60),
            real_key: true,
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
    /// Not checked on the real key, so not sent to it.
    Unverified,
    QueueFull,
    /// The key did not wake before the request expired.
    Asleep,
    WriteTimeout,
    NoReply,
    Paused,
    Suspended,
    /// Cancelled by the caller before it was sent.
    Cancelled,
    Closed,
}
impl Failure {
    pub fn message(&self) -> String {
        match self {
            Failure::Invalid(m) => m.clone(),
            Failure::Unverified => {
                "This command is not yet checked on the real Vibe Key, so it is not sent".into()
            }
            Failure::QueueFull => "Too many requests are waiting for the key".into(),
            Failure::Asleep => "The key is asleep. Press a key or turn the knob to wake it".into(),
            Failure::WriteTimeout => "The key did not accept the command in time. Sending is paused".into(),
            Failure::NoReply => "The key did not answer in time. Sending is paused".into(),
            Failure::Paused => "Sending is paused after a slow reply".into(),
            Failure::Suspended => "Sending is stopped after repeated slow replies. Use Reconnect".into(),
            Failure::Cancelled => "Cancelled".into(),
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
    due: Instant,
}

pub struct Session<T: Transport> {
    transport: T,
    cfg: SessionConfig,
    queue: VecDeque<Queued>,
    inflight: Option<InFlight>,
    last_rx: Option<Instant>,
    woke_at: Option<Instant>,
    last_control: Option<Instant>,
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
            woke_at: None,
            last_control: None,
            next_send: Instant::now(),
            paused_until: None,
            stalls: 0,
            suspended: false,
            sent: 0,
            stalled: 0,
        }
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
    fn can_send(&self, now: Instant, request: &Request) -> bool {
        if self.suspended || !self.awake(now) || now < self.next_send {
            return false;
        }
        if let Some(until) = self.paused_until {
            // After a pause, wait for a message that arrived after the pause ended.
            if now < until || self.last_rx.is_none_or(|t| t < until) {
                return false;
            }
        }
        if request.is_set() {
            let quiet = |t: Option<Instant>| t.is_none_or(|t| now.duration_since(t) >= self.cfg.settle);
            if !quiet(self.woke_at) || !quiet(self.last_control) {
                return false;
            }
        }
        true
    }
    pub fn pending(&self) -> usize {
        self.queue.len() + usize::from(self.inflight.is_some())
    }
    /// Is a request of this kind queued or in flight?
    pub fn has_pending(&self, f: impl Fn(&Request) -> bool) -> bool {
        self.inflight.as_ref().is_some_and(|i| f(&i.request)) || self.queue.iter().any(|q| f(&q.request))
    }

    fn reply_timeout(&self, request: &Request) -> Duration {
        if request.slow_reply() {
            self.cfg.slow_reply_timeout
        } else {
            self.cfg.reply_timeout
        }
    }

    /// Queue a request. It is checked against the allowlist ranges first, and on a real key against the
    /// list of commands checked on hardware.
    pub fn submit(&mut self, ticket: u64, request: Request) -> Result<(), Failure> {
        request.validate().map_err(Failure::Invalid)?;
        if self.cfg.real_key && !request.verified_on_hardware() {
            return Err(Failure::Unverified);
        }
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

    /// Remove queued (not yet sent) requests that match. A request in flight is never cancelled.
    pub fn cancel_queued(&mut self, f: impl Fn(u64, &Request) -> bool) -> Vec<Output> {
        let mut out = Vec::new();
        self.queue.retain(|q| {
            if f(q.ticket, &q.request) {
                out.push(Output::Done {
                    ticket: q.ticket,
                    request: q.request.clone(),
                    result: Err(Failure::Cancelled),
                });
                false
            } else {
                true
            }
        });
        out
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

    /// One round: read what arrived (waiting at most `wait`), handle the reply deadline, then send at most
    /// one request. An `Err` means the transport is broken: the caller closes it and reconnects later.
    pub fn tick(&mut self, wait: Duration) -> io::Result<Vec<Output>> {
        let mut out = Vec::new();
        let mut wait = wait;
        if let Some(f) = &self.inflight {
            wait = wait.min(f.due.saturating_duration_since(Instant::now()));
        }
        for _ in 0..32 {
            let Some(report) = self.transport.read(wait)? else { break };
            wait = Duration::ZERO;
            let Some(plain) = protocol::decode_frame(&report) else { continue };
            let now = Instant::now();
            if !self.awake(now) {
                self.woke_at = Some(now);
            }
            self.last_rx = Some(now);
            match protocol::parse(&plain) {
                Incoming::Control(e) => {
                    self.last_control = Some(now);
                    out.push(Output::Control(e))
                }
                Incoming::Status(s) => out.push(Output::Status(s)),
                Incoming::Reply(r) => {
                    if self.inflight.as_ref().is_some_and(|f| f.request.matches(&r)) {
                        let f = self.inflight.take().unwrap();
                        self.stalls = 0;
                        self.paused_until = None;
                        self.next_send = now + self.cfg.gap;
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
        // No retry: a missing reply pauses sending at once.
        if self.inflight.as_ref().is_some_and(|f| now >= f.due) {
            let f = self.inflight.take().unwrap();
            out.push(Output::Done {
                ticket: f.ticket,
                request: f.request,
                result: Err(Failure::NoReply),
            });
            self.stall(now, &mut out);
        }

        // Requests that waited too long for the key to wake. Waiting behind a slow reply or for the key to be
        // quiet does not count: only a key that is not awake.
        if self.awake(now) {
            for q in &mut self.queue {
                q.at = now;
            }
        } else {
            let expiry = self.cfg.request_expiry;
            out.extend(self.cancel_queued_expired(now, expiry));
        }

        if self.inflight.is_none() && self.queue.front().is_some_and(|q| self.can_send(now, &q.request)) {
            let q = self.queue.pop_front().unwrap();
            let report = q.request.frame();
            self.next_send = now + self.cfg.gap;
            match self.transport.write(&report, self.cfg.write_timeout) {
                Ok(()) => {
                    self.sent += 1;
                    let due = Instant::now() + self.reply_timeout(&q.request);
                    self.inflight = Some(InFlight {
                        ticket: q.ticket,
                        request: q.request,
                        due,
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
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    // The transport's own allowlist refused it; nothing was written.
                    out.push(Output::Done {
                        ticket: q.ticket,
                        request: q.request,
                        result: Err(Failure::Unverified),
                    });
                }
                Err(e) => {
                    self.queue.push_front(q);
                    return Err(e);
                }
            }
        }
        Ok(out)
    }

    fn cancel_queued_expired(&mut self, now: Instant, expiry: Duration) -> Vec<Output> {
        let mut out = Vec::new();
        while self.queue.front().is_some_and(|q| now.duration_since(q.at) >= expiry) {
            let q = self.queue.pop_front().unwrap();
            out.push(Output::Done {
                ticket: q.ticket,
                request: q.request,
                result: Err(Failure::Asleep),
            });
        }
        out
    }
}
