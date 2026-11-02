//! Ulanzi D200H protocol, fake dock and explicit opt-in Windows HID transport.
//! Importing this crate never enumerates or opens hardware.
pub mod dock;
pub mod fake;
pub mod page;
pub mod protocol;
pub mod session;
#[cfg(windows)]
pub mod windows;
