//! Ulanzi AU05 "Vibe Key" (3 keys, knob, microphone; 2.4 GHz USB-C receiver FFF1:00DD).
//!
//! This crate covers only the receiver's private HID collection (interface MI_03, usage page 0xFFFC,
//! 64-byte reports). It never touches the keyboard, mouse or microphone parts.
//!
//! - [`tea`]: the fixed-key TEA cipher used in both directions.
//! - [`protocol`]: framing, decoding of device messages, and the command allowlist ([`protocol::Request`]).
//!   Only a `Request` can be encoded, so a command that is not in the allowlist cannot be sent.
//! - [`session`]: one request in flight, every write time-limited, nothing sent until the key has sent a
//!   message (it sleeps), at most one retry, and a pause at the first stall.
//! - [`fake`]: an encrypted fake AU05 for tests.
//! - `windows`: the explicit opt-in Windows transport. Importing this crate does no device I/O.
pub mod fake;
pub mod protocol;
pub mod session;
pub mod tea;
#[cfg(windows)]
pub mod windows;

pub use protocol::{
    Control, ControlEvent, Incoming, KeyEntry, KeyId, KeyTyping, LightState, MicNr, Reply, Request,
    SleepTime, StatusEvent,
};
pub use session::{Failure, Output, Session, SessionConfig, SessionState, Transport};
