//! Explicit opt-in Windows HID transport. Importing this module does no I/O.
//! No serial/device path is logged. Never call `open_first` in automated tests.
use crate::dock::Transport;
use crate::protocol::{Packet, PACKET_SIZE, PRODUCT_ID, VENDOR_ID};
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

pub const REPORT_SIZE: usize = PACKET_SIZE + 1;
const MAX_IO_WAIT: Duration = Duration::from_secs(5);
const CANCEL_WAIT_MS: u32 = 250;

struct Handle(HANDLE);
// A kernel handle can move across threads; ownership is closed exactly once.
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

/// Filter against HID attributes/caps and SetupAPI hardware IDs, never an opaque path.
fn matches(vid: u16, pid: u16, input: u16, output: u16, hardware_ids: &str) -> bool {
    vid == VENDOR_ID
        && pid == PRODUCT_ID
        && input as usize == REPORT_SIZE
        && output as usize == REPORT_SIZE
        && hardware_ids
            .split('\0')
            .any(|id| id.split('&').any(|p| p.eq_ignore_ascii_case("mi_00")))
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
        caps.InputReportByteLength,
        caps.OutputReportByteLength,
        hardware_ids,
    ) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not the D200H interface-0 report collection",
        ));
    }
    Ok(())
}

/// One native file, with read and write sharing. All transfers have deadlines.
pub struct WindowsHid {
    file: Arc<Handle>,
    write_timeout: Duration,
    poisoned: bool,
}
impl WindowsHid {
    /// Enumerate and open only VID 2207/PID 0019, MI_00, 1025-byte input/output.
    /// Caller must first establish that Ulanzi Studio has quit and hardware use is enabled.
    /// There is no auto-open, startup hook, diagnostic binary or default constructor.
    pub fn open_first(write_timeout: Duration) -> io::Result<Self> {
        if write_timeout.is_zero() || write_timeout > MAX_IO_WAIT {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "write timeout must be within 1ns..=5s"));
        }
        unsafe {
            let mut guid = zeroed();
            HidD_GetHidGuid(&mut guid);
            let set = SetupDiGetClassDevsW(&guid, null(), null_mut(), DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
            if set == INVALID_HANDLE_VALUE as isize {
                return Err(io::Error::last_os_error());
            }
            let set = DeviceSet(set);
            for index in 0.. {
                let mut iface: SP_DEVICE_INTERFACE_DATA = zeroed();
                iface.cbSize = size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
                if SetupDiEnumDeviceInterfaces(set.0, null(), &guid, index, &mut iface) == 0 {
                    let e = io::Error::last_os_error();
                    if e.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                        break;
                    }
                    return Err(e);
                }
                let mut needed = 0;
                SetupDiGetDeviceInterfaceDetailW(set.0, &iface, null_mut(), 0, &mut needed, null_mut());
                if needed < size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32 || needed > 65536 {
                    continue;
                }
                // u64 allocation aligns the variable-size detail structure on either target.
                let mut detail = vec![0u64; (needed as usize).div_ceil(8)];
                let ptr = detail.as_mut_ptr().cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>();
                (*ptr).cbSize = size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
                let mut info: SP_DEVINFO_DATA = zeroed();
                info.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
                if SetupDiGetDeviceInterfaceDetailW(set.0, &iface, ptr, needed, null_mut(), &mut info) == 0 {
                    continue;
                }
                let mut required = 0;
                SetupDiGetDeviceRegistryPropertyW(set.0, &info, SPDRP_HARDWAREID, null_mut(), null_mut(), 0, &mut required);
                if required == 0 || required > 65536 {
                    continue;
                }
                let mut ids = vec![0u16; (required as usize).div_ceil(2)];
                if SetupDiGetDeviceRegistryPropertyW(
                    set.0,
                    &info,
                    SPDRP_HARDWAREID,
                    null_mut(),
                    ids.as_mut_ptr().cast(),
                    required,
                    null_mut(),
                ) == 0
                {
                    continue;
                }
                let ids = String::from_utf16_lossy(&ids);
                if !ids.split('\0').any(|id| id.split('&').any(|p| p.eq_ignore_ascii_case("mi_00"))) {
                    continue;
                }
                let path = (*ptr).DevicePath.as_ptr();
                // Metadata-only access first, so we do not request read/write on other HID collections.
                let probe = CreateFileW(
                    path,
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    null_mut(),
                );
                if probe == INVALID_HANDLE_VALUE {
                    continue;
                }
                let probe = Handle(probe);
                if validate(probe.0, &ids).is_err() {
                    continue;
                }
                let file = CreateFileW(
                    path,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    null_mut(),
                );
                if file == INVALID_HANDLE_VALUE {
                    return Err(io::Error::last_os_error());
                }
                let file = Handle(file);
                validate(file.0, &ids)?;
                return Ok(Self {
                    file: Arc::new(file),
                    write_timeout,
                    poisoned: false,
                });
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, "D200H interface 0 not found"))
    }

    fn transfer(&mut self, write: bool, packet: Option<&Packet>, timeout: Duration) -> io::Result<Option<Packet>> {
        if self.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HID cancellation incomplete; reconnect required",
            ));
        }
        let mut op = Pending::new(self.file.clone())?;
        if let Some(p) = packet {
            op.buffer[1..].copy_from_slice(p);
        }
        let started = unsafe {
            if write {
                WriteFile(self.file.0, op.buffer.as_ptr(), REPORT_SIZE as u32, null_mut(), &mut *op.overlapped)
            } else {
                ReadFile(
                    self.file.0,
                    op.buffer.as_mut_ptr(),
                    REPORT_SIZE as u32,
                    null_mut(),
                    &mut *op.overlapped,
                )
            }
        };
        if started == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(err);
            }
        }
        let wait = unsafe { WaitForSingleObject(op.event.0, timeout.min(MAX_IO_WAIT).as_millis().min(u32::MAX as u128) as u32) };
        if wait != WAIT_OBJECT_0 {
            unsafe {
                CancelIoEx(self.file.0, &*op.overlapped);
            }
            if unsafe { WaitForSingleObject(op.event.0, CANCEL_WAIT_MS) } != WAIT_OBJECT_0 {
                self.poisoned = true;
                // Cancellation is asynchronous. Keep the buffer, OVERLAPPED, event and file alive
                // until the driver retires it; never free kernel-owned memory on a deadline.
                // Leak first so even failure to start the cleanup thread cannot free pending
                // storage. A failed wait also intentionally retains it until process exit.
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
            // A read can win the cancellation race. Deliver it once rather than
            // losing a physical key event at the edge of the polling deadline.
            if !write && wait == WAIT_TIMEOUT {
                let mut count = 0;
                let result = if unsafe { GetOverlappedResult(self.file.0, &*op.overlapped, &mut count, 0) } != 0 {
                    Ok(count)
                } else {
                    Err(io::Error::last_os_error())
                };
                return cancelled_read_result(result, &op.buffer);
            }
            // Output completion after a deadline is uncertain; never replay it.
            return Err(io::Error::new(io::ErrorKind::TimedOut, "HID transfer deadline"));
        }
        let mut count = 0;
        if unsafe { GetOverlappedResult(self.file.0, &*op.overlapped, &mut count, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if count as usize != REPORT_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "short HID report"));
        }
        if write {
            return Ok(None);
        }
        decode_report(&*op.buffer).map(Some)
    }
}
impl Transport for WindowsHid {
    fn write(&mut self, packet: &Packet) -> io::Result<()> {
        self.transfer(true, Some(packet), self.write_timeout).map(|_| ())
    }
    fn read(&mut self, timeout: Duration) -> io::Result<Option<Packet>> {
        self.transfer(false, None, timeout)
    }
}

struct Pending {
    _file: Arc<Handle>,
    buffer: Box<[u8; REPORT_SIZE]>,
    overlapped: Box<OVERLAPPED>,
    event: Handle,
}
// All pointed-to storage is boxed and stable. Only the kernel and the single owner touch it;
// the cleanup thread never reads the buffers and drops them only after the event completes.
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
            buffer: Box::new([0; REPORT_SIZE]),
            overlapped,
            event: Handle(event),
        })
    }
}
fn decode_report(report: &[u8; REPORT_SIZE]) -> io::Result<Packet> {
    if report[0] != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected HID report ID"));
    }
    let mut packet = [0; PACKET_SIZE];
    packet.copy_from_slice(&report[1..]);
    Ok(packet)
}

fn cancelled_read_result(result: io::Result<u32>, report: &[u8; REPORT_SIZE]) -> io::Result<Option<Packet>> {
    match result {
        Ok(count) if count as usize == REPORT_SIZE => decode_report(report).map(Some),
        Ok(_) => Err(io::Error::new(io::ErrorKind::InvalidData, "short HID report")),
        Err(e) if e.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancellation_race_keeps_successful_input_and_only_aborted_means_timeout() {
        let mut report = [0; REPORT_SIZE];
        report[1..3].copy_from_slice(&[0x7c, 0x7c]);
        assert!(cancelled_read_result(Ok(REPORT_SIZE as u32), &report).unwrap().is_some());
        assert!(
            cancelled_read_result(Err(io::Error::from_raw_os_error(ERROR_OPERATION_ABORTED as i32)), &report)
                .unwrap()
                .is_none()
        );
        assert!(cancelled_read_result(Err(io::Error::from_raw_os_error(ERROR_DEVICE_NOT_CONNECTED as i32)), &report).is_err());
        assert!(cancelled_read_result(Ok(64), &report).is_err());
    }

    #[test]
    fn exact_collection_filter() {
        assert!(matches(VENDOR_ID, PRODUCT_ID, 1025, 1025, "HID\\VID_2207&PID_0019&MI_00\0"));
        for (vid, pid, input, output, id) in [
            (1, PRODUCT_ID, 1025, 1025, "mi_00"),
            (VENDOR_ID, 2, 1025, 1025, "mi_00"),
            (VENDOR_ID, PRODUCT_ID, 65, 1025, "mi_00"),
            (VENDOR_ID, PRODUCT_ID, 1025, 65, "mi_00"),
            (VENDOR_ID, PRODUCT_ID, 1025, 1025, "mi_01"),
            (VENDOR_ID, PRODUCT_ID, 1025, 1025, "mi_000"),
        ] {
            assert!(!matches(vid, pid, input, output, id));
        }
    }
    #[test]
    fn native_report_id_is_stripped_exactly_once() {
        let mut report = [0; REPORT_SIZE];
        report[1] = 0x7c;
        report[2] = 0x7c;
        report[1024] = 42;
        let p = decode_report(&report).unwrap();
        assert_eq!(&p[..2], &[0x7c, 0x7c]);
        assert_eq!(p[1023], 42);
        report[0] = 1;
        assert!(decode_report(&report).is_err());
    }
}
