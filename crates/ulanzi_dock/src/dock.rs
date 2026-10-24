//! Transport abstraction and the `Dock` driver.
//!
//! A `Transport` moves whole 1024-byte packets. The real HID transport (step 1.1)
//! adds/strips the report-id byte (HID report = `0x00` + 1024 bytes) and plugs in
//! here without protocol changes. This crate has no real transport.

use crate::page::{build_page_zip, PageSpec};
use crate::protocol::*;
use std::io;
use std::time::Duration;

pub trait Transport {
    fn write(&mut self, packet: &Packet) -> io::Result<()>;
    /// Wait up to `timeout` for one inbound packet; `Ok(None)` on timeout.
    fn read(&mut self, timeout: Duration) -> io::Result<Option<Packet>>;
}

pub struct Dock<T: Transport> {
    transport: T,
}

fn invalid<E: std::error::Error + Send + Sync + 'static>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

impl<T: Transport> Dock<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
    pub fn transport(&self) -> &T {
        &self.transport
    }
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
    pub fn into_transport(self) -> T {
        self.transport
    }

    fn send_simple(&mut self, cmd: Command, payload: &[u8]) -> io::Result<()> {
        let p = build_simple_packet(cmd, payload).map_err(invalid)?;
        self.transport.write(&p)
    }

    /// Send an already built page ZIP (refuses payloads that break the firmware bad-byte rule).
    pub fn set_buttons_zip(&mut self, zip: &[u8]) -> io::Result<()> {
        if !is_payload_safe(zip) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "zip violates the bad-byte rule"));
        }
        for p in build_chunked_packets(Command::SetButtons, zip) {
            self.transport.write(&p)?;
        }
        Ok(())
    }

    pub fn set_page(&mut self, spec: &PageSpec) -> io::Result<()> {
        let zip = build_page_zip(spec).map_err(invalid)?;
        self.set_buttons_zip(&zip)
    }

    pub fn set_brightness(&mut self, percent: u8) -> io::Result<()> {
        self.send_simple(Command::SetBrightness, &encode_brightness(percent))
    }

    pub fn set_small_window(&mut self, data: &SmallWindowData) -> io::Result<()> {
        self.send_simple(Command::SetSmallWindowData, &encode_small_window(data))
    }

    pub fn set_label_style(&mut self, style: &LabelStyle) -> io::Result<()> {
        self.send_simple(Command::SetLabelStyle, &encode_label_style(style))
    }

    /// Payload layout unknown in the source; sent empty (TODO).
    pub fn lock_screen(&mut self) -> io::Result<()> {
        self.send_simple(Command::LockScreen, &[])
    }

    /// Payload layout unknown in the source; sent empty (TODO).
    pub fn unlock_screen(&mut self) -> io::Result<()> {
        self.send_simple(Command::UnlockScreen, &[])
    }

    /// Poll for one inbound event. Malformed packets surface as `InvalidData`.
    pub fn poll_event(&mut self, timeout: Duration) -> io::Result<Option<Event>> {
        match self.transport.read(timeout)? {
            None => Ok(None),
            Some(p) => parse_event(&p).map(Some).map_err(invalid),
        }
    }
}
