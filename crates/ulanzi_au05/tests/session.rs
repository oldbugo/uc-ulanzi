//! Session behaviour against the encrypted fake key. No hardware, no windows, no sound.
use std::time::{Duration, Instant};
use ulanzi_au05::fake::{fake_au05, FakeHandle, FakeTransport};
use ulanzi_au05::protocol::{self, Control, KeyId, KeyTyping, MicNr, Request, SleepTime};
use ulanzi_au05::{Failure, Output, Session, SessionConfig, SessionState};

fn quick() -> SessionConfig {
    SessionConfig {
        write_timeout: Duration::from_millis(60),
        reply_timeout: Duration::from_millis(80),
        slow_reply_timeout: Duration::from_millis(800),
        awake_window: Duration::from_millis(400),
        gap: Duration::from_millis(5),
        settle: Duration::from_millis(40),
        stall_pause: Duration::from_millis(150),
        max_stalls: 3,
        queue_limit: 8,
        request_expiry: Duration::from_millis(300),
        // The fake accepts every allowlisted command; real-key behaviour is tested separately.
        real_key: false,
    }
}

fn session() -> (Session<FakeTransport>, FakeHandle) {
    let (t, h) = fake_au05();
    h.lock().status_period = Some(Duration::from_millis(100));
    (Session::new(t, quick()), h)
}

/// Tick until `ticket` is done or the time runs out; returns all outputs.
fn run_until(s: &mut Session<FakeTransport>, ticket: u64, max: Duration) -> Vec<Output> {
    let end = Instant::now() + max;
    let mut all = Vec::new();
    while Instant::now() < end {
        let out = s.tick(Duration::from_millis(5)).unwrap();
        let done = out.iter().any(|o| matches!(o, Output::Done { ticket: t, .. } if *t == ticket));
        all.extend(out);
        if done {
            break;
        }
    }
    all
}
fn result(out: &[Output], ticket: u64) -> Result<protocol::Reply, Failure> {
    out.iter()
        .find_map(|o| match o {
            Output::Done { ticket: t, result, .. } if *t == ticket => Some(result.clone()),
            _ => None,
        })
        .expect("request finished")
}

#[test]
fn sends_nothing_until_the_key_has_sent_a_message() {
    let (mut s, h) = session();
    s.submit(1, Request::GetBattery).unwrap();
    for _ in 0..10 {
        s.tick(Duration::from_millis(5)).unwrap();
    }
    assert_eq!(s.state(), SessionState::WaitingForKey);
    assert!(h.received().is_empty(), "nothing is written to a key that has not spoken");
    h.wake();
    let out = run_until(&mut s, 1, Duration::from_secs(1));
    assert_eq!(protocol::battery(&result(&out, 1).unwrap()), (3608, 30));
    assert_eq!(h.received(), vec![vec![1, 1, 2, 1]]);
    assert!(h.forbidden().is_empty());
}

#[test]
fn a_request_for_a_sleeping_key_expires_without_any_write() {
    let (mut s, h) = session();
    h.wake();
    s.tick(Duration::from_millis(5)).unwrap();
    h.sleep();
    std::thread::sleep(Duration::from_millis(450)); // past the awake window
    assert_eq!(s.state(), SessionState::Asleep);
    s.submit(7, Request::GetStandbyTime).unwrap();
    let out = run_until(&mut s, 7, Duration::from_secs(1));
    assert_eq!(result(&out, 7), Err(Failure::Asleep));
    assert!(h.received().is_empty());
}

#[test]
fn events_decode_through_the_encrypted_channel() {
    let (mut s, h) = session();
    h.click(Control::K3);
    h.click(Control::KnobLeft);
    let mut events = Vec::new();
    for _ in 0..10 {
        for o in s.tick(Duration::from_millis(5)).unwrap() {
            if let Output::Control(e) = o {
                events.push((e.control, e.code, e.pressed));
            }
        }
    }
    assert_eq!(
        events,
        vec![
            (Control::K3, 0x71, true),
            (Control::K3, 0x71, false),
            (Control::KnobLeft, 0x73, true),
            (Control::KnobLeft, 0x73, false)
        ]
    );
    assert_eq!(h.lock().typed, vec!["F22".to_string(), "scroll up".to_string()], "the knob turn types its factory scroll");
}

#[test]
fn proven_sets_round_trip_and_one_request_is_in_flight() {
    let (mut s, h) = session();
    h.wake();
    s.submit(1, Request::SetStandbyTime(900)).unwrap();
    s.submit(2, Request::GetStandbyTime).unwrap();
    s.submit(3, Request::SetKeyTyping(KeyId::K1, KeyTyping::parse("Ctrl + D").unwrap())).unwrap();
    s.submit(4, Request::GetKeyTyping(KeyId::K1)).unwrap();
    h.lock().reply_delay = Duration::from_millis(30);
    let out = run_until(&mut s, 4, Duration::from_secs(3));
    assert_eq!(protocol::seconds(&result(&out, 2).unwrap()), 900);
    assert_eq!(protocol::key_typing(&result(&out, 4).unwrap()).label(KeyId::K1), "Ctrl + D");
    assert_eq!(h.lock().overlapped, 0, "never a second write while a reply is outstanding");
    h.click(Control::K1);
    assert_eq!(h.lock().typed, vec!["Ctrl + D".to_string()]);
    assert!(h.forbidden().is_empty());
}

#[test]
fn a_late_key_typing_reply_is_waited_for_and_never_overlapped() {
    let (mut s, h) = session();
    h.wake();
    // Later than the normal 80 ms reply limit, within the 800 ms key-typing limit.
    h.lock().key_typing_delay = Duration::from_millis(300);
    s.submit(1, Request::GetKeyTyping(KeyId::K3)).unwrap();
    s.submit(2, Request::GetBattery).unwrap();
    let start = Instant::now();
    let mut out = Vec::new();
    while Instant::now() - start < Duration::from_millis(250) {
        out.extend(s.tick(Duration::from_millis(5)).unwrap());
    }
    assert_eq!(h.received().len(), 1, "the battery get waits until the slow reply is in");
    out.extend(run_until(&mut s, 2, Duration::from_secs(2)));
    assert_eq!(protocol::key_typing(&result(&out, 1).unwrap()), KeyTyping::own_code(KeyId::K3));
    assert!(result(&out, 2).is_ok());
    assert_eq!(h.lock().overlapped, 0);
    assert_eq!(h.received().len(), 2, "no retry");
}

#[test]
fn a_missing_reply_is_never_retried_and_pauses_at_once() {
    let (mut s, h) = session();
    h.wake();
    h.lock().drop_replies = 1;
    s.submit(1, Request::GetBattery).unwrap();
    s.submit(2, Request::GetStandbyTime).unwrap();
    let out = run_until(&mut s, 2, Duration::from_secs(1));
    assert_eq!(result(&out, 1), Err(Failure::NoReply));
    assert_eq!(result(&out, 2), Err(Failure::Paused), "queued work fails at once, not later");
    assert_eq!(h.received().len(), 1, "one write, no retry");
    assert_eq!(s.state(), SessionState::Paused);
    s.submit(3, Request::GetBattery).unwrap();
    for _ in 0..10 {
        s.tick(Duration::from_millis(5)).unwrap();
    }
    assert_eq!(h.received().len(), 1, "nothing is sent while paused");
    // After the pause and a fresh message from the key, sending resumes.
    std::thread::sleep(Duration::from_millis(160));
    h.wake();
    let out = run_until(&mut s, 3, Duration::from_secs(1));
    assert!(result(&out, 3).is_ok());
}

#[test]
fn a_set_waits_until_the_key_is_quiet_after_waking_and_after_key_presses() {
    let (t, h) = fake_au05();
    h.lock().status_period = Some(Duration::from_millis(100));
    let mut s = Session::new(t, SessionConfig { settle: Duration::from_millis(300), ..quick() });
    h.click(Control::K1); // wakes the key with key events
    s.submit(1, Request::SetStandbyTime(700)).unwrap();
    s.submit(2, Request::GetBattery).unwrap();
    let start = Instant::now();
    let mut sent_at = None;
    while Instant::now() - start < Duration::from_secs(1) && sent_at.is_none() {
        s.tick(Duration::from_millis(5)).unwrap();
        if h.received().iter().any(|p| p[2] == 0x2c) {
            sent_at = Some(start.elapsed());
        }
        if start.elapsed() > Duration::from_millis(150) && start.elapsed() < Duration::from_millis(170) {
            h.click(Control::KnobRight); // the user is still turning the knob
        }
    }
    let sent_at = sent_at.expect("the set was sent once quiet");
    assert!(sent_at >= Duration::from_millis(450), "waited 300 ms after the last event, sent at {sent_at:?}");
    assert!(h.received().is_empty() || h.received()[0][2] == 0x2c, "the set is first in the queue");
}

#[test]
fn a_write_that_does_not_finish_is_never_retried_and_repeated_stalls_suspend() {
    let (mut s, h) = session();
    h.wake();
    h.lock().stall_writes = true;
    let started = Instant::now();
    s.submit(1, Request::GetBattery).unwrap();
    let out = run_until(&mut s, 1, Duration::from_secs(1));
    assert_eq!(result(&out, 1), Err(Failure::WriteTimeout));
    assert!(started.elapsed() < Duration::from_millis(500), "the write had a time limit");
    for ticket in [2, 3] {
        std::thread::sleep(Duration::from_millis(160));
        h.wake();
        s.submit(ticket, Request::GetBattery).unwrap();
        let out = run_until(&mut s, ticket, Duration::from_secs(1));
        assert_eq!(result(&out, ticket), Err(Failure::WriteTimeout));
    }
    assert_eq!(s.state(), SessionState::Suspended);
    assert_eq!(s.submit(9, Request::GetBattery), Err(Failure::Suspended));
    h.lock().stall_writes = false;
    s.resume();
    h.wake();
    s.submit(10, Request::GetBattery).unwrap();
    let out = run_until(&mut s, 10, Duration::from_secs(1));
    assert!(result(&out, 10).is_ok());
}

#[test]
fn a_real_key_session_accepts_every_known_command() {
    // User request 2026-11-16: every known setting may be tried on the real key (labelled "Untested").
    let (t, h) = fake_au05();
    h.lock().act_like_real = true;
    let mut s = Session::new(t, SessionConfig { real_key: true, ..quick() });
    assert!(s.submit(1, Request::SetSleepTime(SleepTime::new(0).unwrap())).is_ok());
    assert!(s.submit(2, Request::GetKeyTyping(KeyId::KnobPress)).is_ok());
    assert!(s.submit(3, Request::SetMicNr(MicNr { level: 1, a: 100, b: 100 })).is_ok());
    assert!(s.submit(5, Request::SetStandbyTime(5)).is_err(), "ranges still apply");
    s.cancel_queued(|_, _| true);
    h.wake();
    s.submit(4, Request::SetStandbyTime(600)).unwrap();
    let out = run_until(&mut s, 4, Duration::from_secs(1));
    assert!(result(&out, 4).is_ok());
}

#[test]
fn queued_requests_can_be_cancelled_and_invalid_or_too_many_are_refused() {
    let (mut s, h) = session();
    assert!(matches!(s.submit(1, Request::SetStandbyTime(5)), Err(Failure::Invalid(_))));
    for t in 0..8 {
        s.submit(t, Request::GetBattery).unwrap();
    }
    assert_eq!(s.submit(99, Request::GetBattery), Err(Failure::QueueFull));
    assert_eq!(s.cancel_queued(|t, _| t >= 4).len(), 4);
    assert!(h.received().is_empty());
    assert_eq!(s.fail_all(Failure::Closed).len(), 4);
}

#[test]
fn unplugging_is_a_transport_error() {
    let (mut s, h) = session();
    h.wake();
    s.tick(Duration::from_millis(5)).unwrap();
    h.lock().disconnected = true;
    assert!(s.tick(Duration::from_millis(5)).is_err());
}

#[test]
fn the_fake_flags_any_report_outside_the_allowlist() {
    use ulanzi_au05::Transport;
    let (mut t, h) = fake_au05();
    h.wake();
    for bad in [
        vec![0x01, 0x01, 0x0c, 0x00],       // reboot
        vec![0x01, 0x01, 0x23, 0x01],       // keep-alive
        vec![0x01, 0x06, 0x50, 0x00, 0x00, 0x01, 0x01, 0x02, 0x66], // Power key
    ] {
        t.write(&protocol::encode_frame(&bad), Duration::from_millis(50)).unwrap();
    }
    assert_eq!(h.forbidden().len(), 3);
    assert!(h.received().is_empty());
}
