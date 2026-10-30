//! Caller-driven, single-owner write queue and reconnect policy. Construction does
//! not connect. A factory is invoked only by `tick` after explicit `enable`.
//! No worker thread or real-device factory is installed by this module.
use crate::{
    dock::{Dock, Transport},
    page::merge_page_zip,
    protocol::*,
};
use std::{collections::VecDeque, io, time::Duration};

const MAX_QUEUE: usize = 32;
const MAX_ZIP: usize = 8 * 1024 * 1024;
#[derive(Clone, Debug)]
pub enum Request {
    Page(Vec<u8>),
    Partial(Vec<u8>),
    Brightness(u8),
    SmallWindow(SmallWindowData),
    Lock,
    Unlock,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Disabled,
    Connecting,
    Connected,
    Waiting,
}
#[derive(Debug)]
pub enum Notice {
    Connected,
    Disconnected(io::ErrorKind),
    RetryFailed(io::ErrorKind),
    Event(Event),
    WideRestoreSkipped,
}
pub struct Session<T: Transport, C: FnMut() -> io::Result<T>> {
    connector: C,
    dock: Option<Dock<T>>,
    queue: VecDeque<Request>,
    state: State,
    next_attempt: Duration,
    retry_delay: Duration,
    last_activity: Duration,
    previous_tick: Duration,
    idle_timeout: Duration,
    desired_page: Option<Vec<u8>>,
    restore_on_reconnect: bool,
    wide_restore: Option<SmallWindowData>,
}
impl<T: Transport, C: FnMut() -> io::Result<T>> Session<T, C> {
    pub fn new(connector: C) -> Self {
        Self {
            connector,
            dock: None,
            queue: VecDeque::new(),
            state: State::Disabled,
            next_attempt: Duration::ZERO,
            retry_delay: Duration::from_secs(1),
            last_activity: Duration::ZERO,
            previous_tick: Duration::ZERO,
            idle_timeout: Duration::from_secs(35),
            desired_page: None,
            restore_on_reconnect: false,
            wide_restore: None,
        }
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn pending(&self) -> usize {
        self.queue.len()
    }
    /// Off by default: cached images can contain expired account readings. The
    /// app should normally render a new safe page after Notice::Connected.
    /// Enable only for static content. Never enable for account, clock, sensor
    /// or other live faces; those must be rendered again after connection.
    pub fn set_reconnect_restore(&mut self, enabled: bool) {
        self.restore_on_reconnect = enabled;
    }
    /// Enables future ticks; does not open anything itself.
    pub fn enable(&mut self) {
        if self.state == State::Disabled {
            self.state = State::Connecting;
            self.next_attempt = Duration::ZERO;
        }
    }
    /// Drops the transport and pending writes. No background reconnect survives this.
    pub fn disable(&mut self) {
        self.dock = None;
        self.queue.clear();
        self.state = State::Disabled;
        self.retry_delay = Duration::from_secs(1);
    }
    /// Proposed mitigation, off by default: re-send a reviewed small-window mode
    /// after wide-area press. Hardware behavior still requires phase 1.2 acceptance.
    pub fn set_wide_restore(&mut self, data: Option<SmallWindowData>) {
        self.wide_restore = data;
    }
    pub fn enqueue(&mut self, request: Request) -> io::Result<()> {
        if self.state == State::Disabled {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "dock disabled"));
        }
        if self.queue.len() >= MAX_QUEUE {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "dock write queue full"));
        }
        if let Request::Page(zip) | Request::Partial(zip) = &request {
            if zip.len() > MAX_ZIP || !is_payload_safe(zip) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsafe or oversized ZIP"));
            }
        }
        self.queue.push_back(request);
        Ok(())
    }
    fn disconnect(&mut self, now: Duration) {
        self.dock = None;
        self.queue.clear();
        self.state = State::Waiting;
        self.next_attempt = now.saturating_add(self.retry_delay);
        self.retry_delay = (self.retry_delay * 2).min(Duration::from_secs(30));
    }
    /// Performs at most one complete logical write, then one <=10ms read.
    /// Pass monotonic elapsed time (e.g. Instant::elapsed), not wall-clock time.
    /// On failure, pending writes are discarded. A successfully sent full page
    /// and subsequent successful partial updates form an opt-in reconnect snapshot.
    /// Brightness/small-window settings need reapply after reconnect.
    pub fn tick(&mut self, now: Duration) -> io::Result<Vec<Notice>> {
        if now < self.previous_tick {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "clock moved backwards"));
        }
        self.previous_tick = now;
        let mut notices = Vec::new();
        if self.state == State::Disabled {
            return Ok(notices);
        }
        if self.dock.is_none() {
            if now < self.next_attempt {
                return Ok(notices);
            }
            match (self.connector)() {
                Ok(transport) => {
                    self.dock = Some(Dock::new(transport));
                    self.state = State::Connected;
                    self.last_activity = now;
                    self.retry_delay = Duration::from_secs(1);
                    notices.push(Notice::Connected);
                    if self.restore_on_reconnect
                        && self.queue.len() < MAX_QUEUE
                        && !self.queue.iter().any(|r| matches!(r, Request::Page(_)))
                    {
                        if let Some(page) = self.desired_page.clone() {
                            self.queue.push_front(Request::Page(page));
                        }
                    }
                }
                Err(e) => {
                    self.disconnect(now);
                    notices.push(Notice::RetryFailed(e.kind()));
                    return Ok(notices);
                }
            }
        }
        let dock = self.dock.as_mut().expect("connected");
        if let Some(request) = self.queue.pop_front() {
            // Prepare the next snapshot before writing, so malformed merge data never
            // changes the real display. A partial without a baseline has no restore image.
            let merged = if let (Request::Partial(zip), Some(base)) = (&request, &self.desired_page) {
                Some(merge_page_zip(base, zip).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?)
            } else {
                None
            };
            let result = match &request {
                Request::Page(zip) => dock.set_buttons_zip(zip),
                Request::Partial(zip) => dock.update_buttons_zip(zip),
                Request::Brightness(v) => dock.set_brightness(*v),
                Request::SmallWindow(v) => dock.set_small_window(v),
                Request::Lock => dock.lock_screen(),
                Request::Unlock => dock.unlock_screen(),
            };
            if let Err(e) = result {
                self.disconnect(now);
                notices.push(Notice::Disconnected(e.kind()));
                return Ok(notices);
            }
            if let Request::Page(zip) = request {
                self.desired_page = Some(zip);
            } else if let Some(zip) = merged {
                self.desired_page = Some(zip);
            }
        }
        match dock.poll_event(Duration::from_millis(10)) {
            Ok(Some(event)) => {
                self.last_activity = now;
                if matches!(
                    &event,
                    Event::Button(ButtonEvent {
                        index: 13,
                        action: ButtonAction::Press,
                        ..
                    })
                ) {
                    if let Some(data) = &self.wide_restore {
                        if self.queue.len() < MAX_QUEUE {
                            self.queue.push_front(Request::SmallWindow(data.clone()));
                        } else {
                            notices.push(Notice::WideRestoreSkipped);
                        }
                    }
                }
                notices.push(Notice::Event(event));
            }
            Ok(None) => {
                if now.saturating_sub(self.last_activity) >= self.idle_timeout {
                    self.disconnect(now);
                    notices.push(Notice::Disconnected(io::ErrorKind::TimedOut));
                }
            }
            // Malformed input is reported, but does not refresh freshness or open a device.
            Err(e) => {
                self.disconnect(now);
                notices.push(Notice::Disconnected(e.kind()));
            }
        }
        Ok(notices)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        fake::FakeDock,
        page::{build_page_zip, build_partial_page_zip, PageSpec},
    };
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };
    struct Shared(Rc<RefCell<FakeDock>>, Rc<Cell<bool>>);
    impl Transport for Shared {
        fn write(&mut self, p: &Packet) -> io::Result<()> {
            if self.1.get() {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "fake unplug"))
            } else {
                self.0.borrow_mut().write(p)
            }
        }
        fn read(&mut self, t: Duration) -> io::Result<Option<Packet>> {
            if self.1.get() {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "fake unplug"))
            } else {
                self.0.borrow_mut().read(t)
            }
        }
    }
    #[test]
    fn construction_and_disable_never_connect() {
        let calls = Rc::new(Cell::new(0));
        let c = calls.clone();
        let mut s = Session::new(move || {
            c.set(c.get() + 1);
            Ok(FakeDock::new())
        });
        s.tick(Duration::ZERO).unwrap();
        assert_eq!(calls.get(), 0);
        assert!(s.enqueue(Request::Lock).is_err());
        s.enable();
        s.disable();
        s.tick(Duration::from_secs(100)).unwrap();
        assert_eq!(calls.get(), 0);
    }
    #[test]
    fn queue_keeps_whole_messages_in_order_and_applies_wide_restore() {
        let fake = Rc::new(RefCell::new(FakeDock::new()));
        let f = fake.clone();
        let mut s = Session::new(move || Ok(Shared(f.clone(), Rc::new(Cell::new(false)))));
        s.enable();
        let zip = build_page_zip(&PageSpec::new()).unwrap();
        s.enqueue(Request::Page(zip.clone())).unwrap();
        s.enqueue(Request::Brightness(31)).unwrap();
        s.enqueue(Request::Partial(zip)).unwrap();
        s.enqueue(Request::Lock).unwrap();
        s.enqueue(Request::Unlock).unwrap();
        for n in 0..5 {
            s.tick(Duration::from_secs(n)).unwrap();
        }
        assert_eq!(fake.borrow().commands_received, vec![1, 10, 13, 15, 16]);
        assert_eq!(fake.borrow().partial_updates_received, 1);
        assert!(fake.borrow().errors.is_empty());
        s.set_wide_restore(Some(SmallWindowData {
            mode: SmallWindowMode::Background,
            ..Default::default()
        }));
        fake.borrow_mut().press(13);
        s.tick(Duration::from_secs(5)).unwrap();
        assert_eq!(s.pending(), 1);
        s.tick(Duration::from_secs(6)).unwrap();
        assert!(fake.borrow().small_window.as_ref().unwrap().starts_with("2|"));
    }
    #[test]
    fn unplug_drops_pending_retries_and_restores_page_from_header() {
        let fake = Rc::new(RefCell::new(FakeDock::new()));
        let fail = Rc::new(Cell::new(false));
        let calls = Rc::new(Cell::new(0));
        let (f, e, c) = (fake.clone(), fail.clone(), calls.clone());
        let mut s = Session::new(move || {
            c.set(c.get() + 1);
            if e.get() {
                Err(io::Error::new(io::ErrorKind::NotFound, "fake absent"))
            } else {
                Ok(Shared(f.clone(), e.clone()))
            }
        });
        s.set_reconnect_restore(true);
        s.enable();
        s.enqueue(Request::Page(build_page_zip(&PageSpec::new()).unwrap())).unwrap();
        s.tick(Duration::ZERO).unwrap();
        fail.set(true);
        s.enqueue(Request::Brightness(90)).unwrap();
        s.enqueue(Request::Lock).unwrap();
        s.tick(Duration::from_secs(1)).unwrap();
        assert_eq!(s.state(), State::Waiting);
        assert_eq!(s.pending(), 0);
        s.tick(Duration::from_millis(1500)).unwrap();
        assert_eq!(calls.get(), 1);
        s.tick(Duration::from_secs(2)).unwrap();
        assert_eq!(calls.get(), 2);
        fail.set(false);
        s.tick(Duration::from_secs(3)).unwrap();
        assert_eq!(calls.get(), 2);
        s.tick(Duration::from_secs(4)).unwrap();
        assert_eq!(s.state(), State::Connected);
        assert_eq!(fake.borrow().pages_received, 2);
        assert!(!fake.borrow().locked);
    }
    #[test]
    fn missed_heartbeat_backoff_clock_and_queue_limits() {
        let mut s = Session::new(|| Ok(FakeDock::new()));
        s.enable();
        s.tick(Duration::ZERO).unwrap();
        s.tick(Duration::from_secs(34)).unwrap();
        assert_eq!(s.state(), State::Connected);
        s.tick(Duration::from_secs(35)).unwrap();
        assert_eq!(s.state(), State::Waiting);
        assert!(s.tick(Duration::from_secs(34)).is_err());
        let mut bad = vec![1; 1100];
        bad[1016] = 0;
        assert_eq!(s.enqueue(Request::Partial(bad)).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        for _ in 0..MAX_QUEUE {
            s.enqueue(Request::Lock).unwrap();
        }
        assert_eq!(s.enqueue(Request::Lock).unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }
    #[test]
    fn reconnect_does_not_replay_cached_images_by_default() {
        let fake = Rc::new(RefCell::new(FakeDock::new()));
        let fail = Rc::new(Cell::new(false));
        let (f, e) = (fake.clone(), fail.clone());
        let mut s = Session::new(move || Ok(Shared(f.clone(), e.clone())));
        s.enable();
        s.enqueue(Request::Page(build_page_zip(&PageSpec::new()).unwrap())).unwrap();
        s.tick(Duration::ZERO).unwrap();
        fail.set(true);
        s.tick(Duration::from_secs(1)).unwrap();
        fail.set(false);
        let notices = s.tick(Duration::from_secs(2)).unwrap();
        assert!(notices.iter().any(|n| matches!(n, Notice::Connected)));
        assert_eq!(s.state(), State::Connected);
        assert_eq!(fake.borrow().commands_received, vec![1]);
        // A newly rendered page is explicitly supplied by the application.
        s.enqueue(Request::Page(build_page_zip(&PageSpec::new()).unwrap())).unwrap();
        s.tick(Duration::from_secs(3)).unwrap();
        assert_eq!(fake.borrow().commands_received, vec![1, 1]);
    }

    #[test]
    fn reconnect_restores_successful_partial_changes() {
        let fake = Rc::new(RefCell::new(FakeDock::new()));
        let fail = Rc::new(Cell::new(false));
        let (f, e) = (fake.clone(), fail.clone());
        let mut s = Session::new(move || Ok(Shared(f.clone(), e.clone())));
        s.set_reconnect_restore(true);
        s.enable();
        let mut base = PageSpec::new();
        base.keys[0].name = Some("old".into());
        base.keys[1].name = Some("keep".into());
        s.enqueue(Request::Page(build_page_zip(&base).unwrap())).unwrap();
        s.tick(Duration::ZERO).unwrap();
        base.keys[0].name = Some("new".into());
        s.enqueue(Request::Partial(build_partial_page_zip(&base, &[0]).unwrap())).unwrap();
        s.tick(Duration::from_secs(1)).unwrap();
        fail.set(true);
        s.tick(Duration::from_secs(2)).unwrap();
        fail.set(false);
        s.tick(Duration::from_secs(3)).unwrap();
        let f = fake.borrow();
        let m = f.last_manifest.as_ref().unwrap();
        assert_eq!(m["0_0"]["ViewParam"][0]["Text"], "new");
        assert_eq!(m["1_0"]["ViewParam"][0]["Text"], "keep");
        assert_eq!(f.commands_received, vec![1, 13, 1]);
        assert!(f.errors.is_empty());
    }
    #[test]
    fn failed_continuation_is_not_replayed_or_followed_by_another_command() {
        struct Fault {
            written: Rc<RefCell<Vec<Packet>>>,
            calls: usize,
        }
        impl Transport for Fault {
            fn write(&mut self, p: &Packet) -> io::Result<()> {
                self.calls += 1;
                if self.calls == 2 {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "fake mid-page failure"));
                }
                self.written.borrow_mut().push(*p);
                Ok(())
            }
            fn read(&mut self, _: Duration) -> io::Result<Option<Packet>> {
                Ok(None)
            }
        }
        let written = Rc::new(RefCell::new(Vec::new()));
        let mut dock = Dock::new(Fault {
            written: written.clone(),
            calls: 0,
        });
        assert!(dock.set_buttons_zip(&vec![1; 3000]).is_err());
        assert!(dock.set_brightness(42).is_err());
        assert_eq!(written.borrow().len(), 1);
        assert_eq!(&written.borrow()[0][..4], &[0x7c, 0x7c, 0, 1]);
    }
}
