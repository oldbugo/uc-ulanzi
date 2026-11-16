//! Session behaviour against the encrypted fake key. No hardware, no windows, no sound.
use std::time::{Duration, Instant};
use ulanzi_au05::fake::{fake_au05, FakeHandle};
use ulanzi_au05::protocol::{self, Control, KeyId, KeyTyping, MicNr, Request, SleepTime};
use ulanzi_au05::{Failure, Output, Session, SessionConfig, SessionState};

fn quick() -> SessionConfig {
    SessionConfig {
        write_timeout: Duration::from_millis(60),
        reply_timeout: Duration::from_millis(80),
        awake_window: Duration::from_millis(400),
        gap: Duration::from_millis(5),
        stall_pause: Duration::from_millis(150),
        max_stalls: 3,
        queue_limit: 8,
        request_expiry: Duration::from_millis(300),
    }
}

fn session() -> (Session<ulanzi_au05::fake::FakeTransport>, FakeHandle) {
    let (t, h) = fake_au05();
    h.lock().status_period = Some(Duration::from_millis(100));
    (Session::new(t, quick()), h)
}

/// Tick until `ticket` is done or the time runs out; returns all outputs.
fn run_until(s: &mut Session<ulanzi_au05::fake::FakeTransport>, ticket: u64, max: Duration) -> Vec<Output> {
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
    // the fake keyboard part typed K3's current list: F22 (harmless)
    assert_eq!(h.lock().typed, vec!["F22".to_string()]);
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
    let mut max_in_flight = 0;
    let end = Instant::now() + Duration::from_secs(2);
    let mut out = Vec::new();
    while Instant::now() < end && out.iter().filter(|o| matches!(o, Output::Done { .. })).count() < 4 {
        out.extend(s.tick(Duration::from_millis(2)).unwrap());
        // queue + in flight, minus queued = in flight; check the fake never has two unanswered
        let sent = h.received().len();
        let done = out.iter().filter(|o| matches!(o, Output::Done { .. })).count();
        max_in_flight = max_in_flight.max(sent - done);
    }
    assert_eq!(max_in_flight, 1);
    assert_eq!(protocol::seconds(&result(&out, 2).unwrap()), 900);
    assert_eq!(protocol::key_typing(&result(&out, 4).unwrap()).label(KeyId::K1), "Ctrl + D");
    h.click(Control::K1);
    assert_eq!(h.lock().typed, vec!["Ctrl + D".to_string()]);
    assert!(h.forbidden().is_empty());
}

#[test]
fn factory_default_and_unverified_sets_work_on_the_fake() {
    let (mut s, h) = session();
    h.wake();
    s.submit(1, Request::SetKeyTyping(KeyId::K3, KeyTyping::factory())).unwrap();
    s.submit(2, Request::SetSleepTime(SleepTime::new(0).unwrap())).unwrap();
    s.submit(3, Request::SetLightMode(1)).unwrap();
    s.submit(4, Request::SetLightBrightness(4)).unwrap();
    s.submit(5, Request::SetMicNr(MicNr { level: 2, a: 100, b: 100 })).unwrap();
    s.submit(6, Request::GetLight).unwrap();
    let out = run_until(&mut s, 6, Duration::from_secs(2));
    for t in 1..=6 {
        assert!(result(&out, t).is_ok(), "ticket {t}");
    }
    let l = protocol::light(&result(&out, 6).unwrap());
    assert_eq!((l.mode, l.brightness), (1, 4));
    let st = h.lock().clone();
    assert!(st.typing[2].is_factory());
    assert_eq!(st.sleep_s, 0);
    assert_eq!(st.mic, MicNr { level: 2, a: 100, b: 100 });
    h.click(Control::K3);
    assert_eq!(h.lock().typed, vec!["Esc".to_string()]);
}

#[test]
fn a_missing_reply_is_retried_once_then_sending_pauses() {
    let (mut s, h) = session();
    h.wake();
    h.lock().drop_replies = 1;
    s.submit(1, Request::GetBattery).unwrap();
    let out = run_until(&mut s, 1, Duration::from_secs(1));
    assert!(result(&out, 1).is_ok(), "the one retry got the answer");
    assert_eq!(h.received().len(), 2);

    h.lock().drop_replies = 2;
    s.submit(2, Request::GetBattery).unwrap();
    s.submit(3, Request::GetStandbyTime).unwrap();
    let out = run_until(&mut s, 3, Duration::from_secs(1));
    assert_eq!(result(&out, 2), Err(Failure::NoReply));
    assert_eq!(result(&out, 3), Err(Failure::Paused), "queued work fails at once, not later");
    assert_eq!(h.received().len(), 4, "one send and one retry, nothing more");
    assert_eq!(s.state(), SessionState::Paused);
    // While paused nothing is sent, even with the key awake.
    s.submit(4, Request::GetBattery).unwrap();
    for _ in 0..10 {
        s.tick(Duration::from_millis(5)).unwrap();
    }
    assert_eq!(h.received().len(), 4);
    // After the pause and a fresh message from the key, sending resumes.
    std::thread::sleep(Duration::from_millis(160));
    h.wake();
    let out = run_until(&mut s, 4, Duration::from_secs(1));
    assert!(result(&out, 4).is_ok());
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
    // An explicit resume (the user's Reconnect) allows sending again.
    h.lock().stall_writes = false;
    s.resume();
    h.wake();
    s.submit(10, Request::GetBattery).unwrap();
    let out = run_until(&mut s, 10, Duration::from_secs(1));
    assert!(result(&out, 10).is_ok());
}

#[test]
fn invalid_requests_and_a_full_queue_are_refused_before_sending() {
    let (mut s, h) = session();
    assert!(matches!(s.submit(1, Request::SetStandbyTime(5)), Err(Failure::Invalid(_))));
    for t in 0..8 {
        s.submit(t, Request::GetBattery).unwrap();
    }
    assert_eq!(s.submit(99, Request::GetBattery), Err(Failure::QueueFull));
    assert!(h.received().is_empty());
    let out = s.fail_all(Failure::Closed);
    assert_eq!(out.len(), 8);
}

#[test]
fn unplugging_is_a_transport_error() {
    let (mut s, h) = session();
    h.wake();
    s.tick(Duration::from_millis(5)).unwrap();
    h.lock().disconnected = true;
    assert!(s.tick(Duration::from_millis(5)).is_err());
}
