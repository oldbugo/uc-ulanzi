//! Transport abstraction and the `Dock` driver.
//!
//! A `Transport` moves whole 1024-byte packets. The real HID transport (step 1.1)
//! adds/strips the report-id byte (HID report = `0x00` + 1024 bytes) and plugs in
//! here without protocol changes. See `windows` for the explicit opt-in transport.

use crate::page::{build_page_zip, PageSpec};
use crate::protocol::*;
use std::io;
use std::time::{Duration, Instant};

pub trait Transport {
    fn write(&mut self, packet: &Packet) -> io::Result<()>;
    /// Wait up to `timeout` for one inbound packet; `Ok(None)` on timeout.
    fn read(&mut self, timeout: Duration) -> io::Result<Option<Packet>>;
}

pub struct Dock<T: Transport> {
    transport: T,
    failed: bool,
}

fn invalid<E: std::error::Error + Send + Sync + 'static>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

impl<T: Transport> Dock<T> {
    pub fn new(transport: T) -> Self {
        Self { transport, failed: false }
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
        self.write_packet(&p)
    }

    fn write_packet(&mut self, packet: &Packet) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "previous write failed; reconnect required",
            ));
        }
        if let Err(e) = self.transport.write(packet) {
            self.failed = true;
            return Err(e);
        }
        Ok(())
    }

    /// Send an already built page ZIP (refuses payloads that break the firmware bad-byte rule).
    pub fn set_buttons_zip(&mut self, zip: &[u8]) -> io::Result<()> {
        self.send_zip(Command::SetButtons, zip)
    }

    /// Same ZIP layout as a full page, sent with 0x000d. Include only changed keys.
    /// Bitfocus src/device.ts at d467064: updateKeys passes opts.partial to sendZip.
    pub fn update_buttons_zip(&mut self, zip: &[u8]) -> io::Result<()> {
        self.send_zip(Command::PartiallyUpdateButtons, zip)
    }

    fn send_zip(&mut self, command: Command, zip: &[u8]) -> io::Result<()> {
        if zip.len() > 8 * 1024 * 1024 || !is_payload_safe(zip) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsafe or oversized ZIP"));
        }
        let start = Instant::now();
        for p in build_chunked_packets(command, zip) {
            if start.elapsed() > Duration::from_secs(30) {
                self.failed = true;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "page transfer deadline; reconnect required",
                ));
            }
            self.write_packet(&p)?;
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

    /// Empty payload, as Bitfocus src/device.ts lockScreen at d467064.
    pub fn lock_screen(&mut self) -> io::Result<()> {
        self.send_simple(Command::LockScreen, &[])
    }

    /// Empty payload, as Bitfocus src/device.ts unlockScreen at d467064.
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
