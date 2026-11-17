//! Explicit opt-in Windows transport for the AU05 receiver's private collection. Importing this module does
//! no I/O. No serial number or device path is logged. Never call `open_first` in automated tests: only the
//! orchestrator, with the user present, may open the real key.
//!
//! Based on the reviewed D200H transport in `ulanzi_dock::windows`: overlapped I/O with a deadline on every
//! write, `CancelIoEx` on a write deadline, and kernel-owned buffers kept alive until the driver retires them.
//!
//! Reads (2026-11-17, real-key bug: the worker saw no report at all while scripts on the same PC did): one
//! overlapped read is kept pending all the time, as hidapi does. A read with a deadline waits on it and, if
//! nothing came, leaves it pending for the next call instead of cancelling it; it is re-armed after each
//! report and cancelled only when the transport is dropped. Counters and an open-time summary of every
//! matching collection are available through `Transport::diagnostics` for the app's log.
use crate::protocol::{Report, INTERFACE, PRODUCT_ID, REPORT_ID, REPORT_LEN, USAGE_PAGE, VENDOR_ID};
use crate::session::Transport;
use std::{
    io,
    mem::{size_of, zeroed},
    ptr::{null, null_mut},
    sync::Arc,
    time::Duration,
};
use windows_sys::Win32::{
    Devices::{DeviceAndDriverInstallation::*, HumanInterfaceDevice::*},
    Foundation::*,
    Storage::FileSystem::*,
    System::{Threading::*, IO::*},
};

/// The longest wait UC allows for any one transfer (Practices item 26: about 2 s).
pub const MAX_IO_WAIT: Duration = Duration::from_secs(2);
const CANCEL_WAIT_MS: u32 = 250;

struct Handle(HANDLE);
// A kernel handle can move across threads; it is closed exactly once.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct DeviceSet(HDEVINFO);
impl Drop for DeviceSet {
    fn drop(&mut self) {
        unsafe {
            SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}
struct Preparsed(PHIDP_PREPARSED_DATA);
impl Drop for Preparsed {
    fn drop(&mut self) {
        unsafe {
            HidD_FreePreparsedData(self.0);
        }
    }
}

fn interface_matches(hardware_ids: &str) -> bool {
    hardware_ids
        .split('\0')
        .any(|id| id.split('&').any(|p| p.eq_ignore_ascii_case(INTERFACE)))
}

/// Filter on HID attributes, capabilities and SetupAPI hardware IDs, never on the opaque path.
fn matches(vid: u16, pid: u16, usage_page: u16, input: u16, output: u16, hardware_ids: &str) -> bool {
    vid == VENDOR_ID
        && pid == PRODUCT_ID
        && usage_page == USAGE_PAGE
        && input as usize == REPORT_LEN
        && output as usize == REPORT_LEN
        && interface_matches(hardware_ids)
}

unsafe fn validate(handle: HANDLE, hardware_ids: &str) -> io::Result<()> {
    let mut attr: HIDD_ATTRIBUTES = unsafe { zeroed() };
    attr.Size = size_of::<HIDD_ATTRIBUTES>() as u32;
    if !unsafe { HidD_GetAttributes(handle, &mut attr) } {
        return Err(io::Error::last_os_error());
    }
    let mut data: PHIDP_PREPARSED_DATA = 0;
    if !unsafe { HidD_GetPreparsedData(handle, &mut data) } {
        return Err(io::Error::last_os_error());
    }
    let data = Preparsed(data);
    let mut caps: HIDP_CAPS = unsafe { zeroed() };
    if unsafe { HidP_GetCaps(data.0, &mut caps) } != HIDP_STATUS_SUCCESS {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "HID capabilities unavailable"));
    }
    if !matches(
        attr.VendorID,
        attr.ProductID,
        caps.UsagePage,
        caps.InputReportByteLength,
        caps.OutputReportByteLength,
        hardware_ids,
    ) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not the AU05 private collection"));
    }
    Ok(())
}

/// Read counters for the log.
#[derive(Clone, Debug, Default)]
pub struct ReadStats {
    pub armed: u64,
    pub reports: u64,
    pub waits_without_data: u64,
    pub short_reports: u64,
    /// Report IDs seen (byte 0), first eight distinct.
    pub ids: Vec<u8>,
}

/// The receiver's private collection, opened with shared read/write access and overlapped I/O.
pub struct WindowsAu05 {
    file: Arc<Handle>,
    poisoned: bool,
    /// The read kept pending between calls.
    read_op: Option<Pending>,
    stats: ReadStats,
    /// What `find` saw: the number of matching collections and each one's capabilities.
    opened: String,
}

impl WindowsAu05 {
    /// Is an AU05 receiver present? Metadata-only: opens no collection for reading or writing.
    pub fn present() -> bool {
        unsafe { find(false) }.is_ok_and(|(_, _)| true)
    }
    pub fn stats(&self) -> &ReadStats {
        &self.stats
    }

    /// Enumerate and open only FFF1:00DD, MI_03, usage page 0xFFFC, 64-byte reports.
    /// There is no auto-open, start-up hook or default constructor.
    pub fn open_first() -> io::Result<Self> {
        let (file, opened) = unsafe { find(true) }?;
        Ok(Self {
            file: Arc::new(file.expect("open requested")),
            poisoned: false,
            read_op: None,
            stats: ReadStats::default(),
            opened,
        })
    }

    /// Wait up to `timeout` for the pending read (arming one if none is pending). A read that does not
    /// complete in time stays pending for the next call: it is not cancelled.
    fn read_pending(&mut self, timeout: Duration) -> io::Result<Option<Report>> {
        if self.poisoned {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "HID cancellation incomplete; reconnect required"));
        }
        if self.read_op.is_none() {
            let mut op = Pending::new(self.file.clone())?;
            let started = unsafe {
                ReadFile(self.file.0, op.buffer.as_mut_ptr(), REPORT_LEN as u32, null_mut(), &mut *op.overlapped)
            };
            if started == 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                    return Err(err);
                }
            }
            self.stats.armed += 1;
            self.read_op = Some(op);
        }
        let op = self.read_op.as_ref().expect("armed above");
        let ms = timeout.min(MAX_IO_WAIT).as_millis() as u32;
        let wait = unsafe { WaitForSingleObject(op.event.0, ms) };
        if wait == WAIT_TIMEOUT {
            self.stats.waits_without_data += 1;
            return Ok(None); // still pending: picked up by the next call
        }
        let op = self.read_op.take().expect("armed above");
        if wait != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        let mut count = 0;
        if unsafe { GetOverlappedResult(self.file.0, &*op.overlapped, &mut count, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if count as usize != REPORT_LEN {
            self.stats.short_reports += 1;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "short HID report"));
        }
        self.stats.reports += 1;
        if self.stats.ids.len() < 8 && !self.stats.ids.contains(&op.buffer[0]) {
            self.stats.ids.push(op.buffer[0]);
        }
        Ok(Some(*op.buffer))
    }

    fn transfer(&mut self, write: Option<&Report>, timeout: Duration) -> io::Result<Option<Report>> {
        if self.poisoned {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "HID cancellation incomplete; reconnect required"));
        }
        let mut op = Pending::new(self.file.clone())?;
        if let Some(r) = write {
            op.buffer.copy_from_slice(r);
        }
        let started = unsafe {
            if write.is_some() {
                WriteFile(self.file.0, op.buffer.as_ptr(), REPORT_LEN as u32, null_mut(), &mut *op.overlapped)
            } else {
                ReadFile(self.file.0, op.buffer.as_mut_ptr(), REPORT_LEN as u32, null_mut(), &mut *op.overlapped)
            }
        };
        if started == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(err);
            }
        }
        let ms = timeout.min(MAX_IO_WAIT).as_millis() as u32;
        let wait = unsafe { WaitForSingleObject(op.event.0, ms) };
        if wait != WAIT_OBJECT_0 {
            unsafe {
                CancelIoEx(self.file.0, &*op.overlapped);
            }
            if unsafe { WaitForSingleObject(op.event.0, CANCEL_WAIT_MS) } != WAIT_OBJECT_0 {
                self.poisoned = true;
                // Keep kernel-owned storage alive until the driver retires it; never free it on a deadline.
                let pending: &'static mut Pending = Box::leak(Box::new(op));
                std::thread::spawn(move || {
                    if unsafe { WaitForSingleObject(pending.event.0, INFINITE) } == WAIT_OBJECT_0 {
                        unsafe {
                            drop(Box::from_raw(pending as *mut Pending));
                        }
                    }
                });
                return Err(io::Error::new(io::ErrorKind::TimedOut, "HID driver did not complete cancellation"));
            }
            if write.is_none() && wait == WAIT_TIMEOUT {
                // A read can win the cancellation race: deliver it rather than lose a key event.
                let mut count = 0;
                let result = if unsafe { GetOverlappedResult(self.file.0, &*op.overlapped, &mut count, 0) } != 0 {
                    Ok(count)
                } else {
                    Err(io::Error::last_os_error())
                };
                return cancelled_read_result(result, &op.buffer);
            }
            // A write that passed its deadline is uncertain; the session never replays it.
            return Err(io::Error::new(io::ErrorKind::TimedOut, "HID transfer deadline"));
        }
        let mut count = 0;
        if unsafe { GetOverlappedResult(self.file.0, &*op.overlapped, &mut count, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if count as usize != REPORT_LEN {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "short HID report"));
        }
        if write.is_some() {
            return Ok(None);
        }
        Ok(Some(*op.buffer))
    }
}

impl Transport for WindowsAu05 {
    fn write(&mut self, report: &Report, timeout: Duration) -> io::Result<()> {
        // The lowest real write enforces the allowlist itself: only checked commands reach the real key,
        // whoever built the report.
        crate::protocol::check_outgoing(report, true)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        debug_assert_eq!(report[0], REPORT_ID);
        self.transfer(Some(report), timeout).map(|_| ())
    }
    fn read(&mut self, timeout: Duration) -> io::Result<Option<Report>> {
        self.read_pending(timeout)
    }
    fn diagnostics(&self) -> Option<String> {
        let s = &self.stats;
        let ids: Vec<String> = s.ids.iter().map(|i| format!("{i:#04x}")).collect();
        Some(format!(
            "{}; reads armed {}, reports {}, waits without data {}, short {}, report ids [{}]",
            self.opened, s.armed, s.reports, s.waits_without_data, s.short_reports, ids.join(" ")
        ))
    }
}

impl Drop for WindowsAu05 {
    /// Cancel the pending read. Its buffers stay alive until the driver retires them.
    fn drop(&mut self) {
        if let Some(op) = self.read_op.take() {
            unsafe { CancelIoEx(self.file.0, &*op.overlapped) };
            if unsafe { WaitForSingleObject(op.event.0, CANCEL_WAIT_MS) } != WAIT_OBJECT_0 {
                let pending: &'static mut Pending = Box::leak(Box::new(op));
                std::thread::spawn(move || {
                    if unsafe { WaitForSingleObject(pending.event.0, INFINITE) } == WAIT_OBJECT_0 {
                        unsafe { drop(Box::from_raw(pending as *mut Pending)) };
                    }
                });
            }
        }
    }
}

/// Capabilities of a collection, for the open-time summary (no path, no serial).
unsafe fn caps_summary(handle: HANDLE) -> String {
    let mut data: PHIDP_PREPARSED_DATA = 0;
    if !unsafe { HidD_GetPreparsedData(handle, &mut data) } {
        return "caps unreadable".into();
    }
    let data = Preparsed(data);
    let mut caps: HIDP_CAPS = unsafe { zeroed() };
    if unsafe { HidP_GetCaps(data.0, &mut caps) } != HIDP_STATUS_SUCCESS {
        return "caps unreadable".into();
    }
    format!(
        "usage page {:#06x} usage {:#06x} in {} out {} feature {}",
        caps.UsagePage, caps.Usage, caps.InputReportByteLength, caps.OutputReportByteLength, caps.FeatureReportByteLength
    )
}

/// Enumerate HID interfaces. With `open`, return the opened collection (the first that matches) and a summary
/// of every collection on the interface; without, only check presence.
unsafe fn find(open: bool) -> io::Result<(Option<Handle>, String)> {
    let mut guid = unsafe { zeroed() };
    unsafe { HidD_GetHidGuid(&mut guid) };
    let set = unsafe { SetupDiGetClassDevsW(&guid, null(), null_mut(), DIGCF_PRESENT | DIGCF_DEVICEINTERFACE) };
    if set == INVALID_HANDLE_VALUE as isize {
        return Err(io::Error::last_os_error());
    }
    let set = DeviceSet(set);
    let mut chosen: Option<Handle> = None;
    let mut seen: Vec<String> = Vec::new();
    for index in 0.. {
        let mut iface: SP_DEVICE_INTERFACE_DATA = unsafe { zeroed() };
        iface.cbSize = size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
        if unsafe { SetupDiEnumDeviceInterfaces(set.0, null(), &guid, index, &mut iface) } == 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                break;
            }
            return Err(e);
        }
        let mut needed = 0;
        unsafe { SetupDiGetDeviceInterfaceDetailW(set.0, &iface, null_mut(), 0, &mut needed, null_mut()) };
        if needed < size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32 || needed > 65536 {
            continue;
        }
        let mut detail = vec![0u64; (needed as usize).div_ceil(8)];
        let ptr = detail.as_mut_ptr().cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>();
        unsafe { (*ptr).cbSize = size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32 };
        let mut info: SP_DEVINFO_DATA = unsafe { zeroed() };
        info.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
        if unsafe { SetupDiGetDeviceInterfaceDetailW(set.0, &iface, ptr, needed, null_mut(), &mut info) } == 0 {
            continue;
        }
        let mut required = 0;
        unsafe {
            SetupDiGetDeviceRegistryPropertyW(set.0, &info, SPDRP_HARDWAREID, null_mut(), null_mut(), 0, &mut required)
        };
        if required == 0 || required > 65536 {
            continue;
        }
        let mut ids = vec![0u16; (required as usize).div_ceil(2)];
        if unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                set.0,
                &info,
                SPDRP_HARDWAREID,
                null_mut(),
                ids.as_mut_ptr().cast(),
                required,
                null_mut(),
            )
        } == 0
        {
            continue;
        }
        let ids = String::from_utf16_lossy(&ids);
        if !interface_matches(&ids) {
            continue;
        }
        let path = unsafe { (*ptr).DevicePath.as_ptr() };
        // Metadata-only access first, so no other HID collection is opened for reading or writing.
        let probe = unsafe {
            CreateFileW(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, null(), OPEN_EXISTING, FILE_FLAG_OVERLAPPED, null_mut())
        };
        if probe == INVALID_HANDLE_VALUE {
            continue;
        }
        let probe = Handle(probe);
        let summary = unsafe { caps_summary(probe.0) };
        let ok = unsafe { validate(probe.0, &ids) }.is_ok();
        let collection = ids.split('\0').next().unwrap_or("").rsplit('&').next().filter(|c| c.to_ascii_lowercase().starts_with("col")).unwrap_or("");
        seen.push(format!("{}{}{}", if collection.is_empty() { String::new() } else { format!("{collection} ") }, summary, if ok { " (matches)" } else { "" }));
        if !ok || chosen.is_some() {
            continue;
        }
        if !open {
            return Ok((None, String::new()));
        }
        let file = unsafe {
            CreateFileW(
                path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                null_mut(),
            )
        };
        if file == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let file = Handle(file);
        unsafe { validate(file.0, &ids) }?;
        if let Some(last) = seen.last_mut() {
            last.push_str(" (opened)");
        }
        chosen = Some(file);
    }
    match chosen {
        Some(file) => {
            let n = seen.iter().filter(|x| x.contains("(matches)")).count();
            Ok((Some(file), format!("receiver MI_03: {} collection(s), {n} matching: {}", seen.len(), seen.join(" | "))))
        }
        None => Err(io::Error::new(io::ErrorKind::NotFound, "AU05 receiver not found")),
    }
}

struct Pending {
    _file: Arc<Handle>,
    buffer: Box<Report>,
    overlapped: Box<OVERLAPPED>,
    event: Handle,
}
// All pointed-to storage is boxed and stable; the cleanup thread only drops it after completion.
unsafe impl Send for Pending {}
impl Pending {
    fn new(file: Arc<Handle>) -> io::Result<Self> {
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut overlapped: Box<OVERLAPPED> = Box::new(unsafe { zeroed() });
        overlapped.hEvent = event;
        Ok(Self {
            _file: file,
            buffer: Box::new([0; REPORT_LEN]),
            overlapped,
            event: Handle(event),
        })
    }
}

fn cancelled_read_result(result: io::Result<u32>, report: &Report) -> io::Result<Option<Report>> {
    match result {
        Ok(count) if count as usize == REPORT_LEN => Ok(Some(*report)),
        Ok(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "short HID report")),
        Err(e) if e.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_collection_filter() {
        assert!(matches(VENDOR_ID, PRODUCT_ID, 0xfffc, 64, 64, "HID\\VID_FFF1&PID_00DD&MI_03\0"));
        for (vid, pid, page, input, output, id) in [
            (1, PRODUCT_ID, 0xfffc, 64, 64, "mi_03"),
            (VENDOR_ID, 2, 0xfffc, 64, 64, "mi_03"),
            (VENDOR_ID, PRODUCT_ID, 0x0001, 64, 64, "mi_03"), // the keyboard part
            (VENDOR_ID, PRODUCT_ID, 0x000c, 64, 64, "mi_03"), // consumer control
            (VENDOR_ID, PRODUCT_ID, 0xfffc, 65, 64, "mi_03"),
            (VENDOR_ID, PRODUCT_ID, 0xfffc, 64, 64, "mi_02"),
            (VENDOR_ID, PRODUCT_ID, 0xfffc, 64, 64, "mi_030"),
        ] {
            assert!(!matches(vid, pid, page, input, output, id));
        }
    }
    #[test]
    fn cancellation_race_keeps_a_completed_read() {
        let r = [0x55; REPORT_LEN];
        assert!(cancelled_read_result(Ok(64), &r).unwrap().is_some());
        assert!(cancelled_read_result(Err(io::Error::from_raw_os_error(ERROR_OPERATION_ABORTED as i32)), &r)
            .unwrap()
            .is_none());
        assert!(cancelled_read_result(Ok(10), &r).is_err());
    }
}
