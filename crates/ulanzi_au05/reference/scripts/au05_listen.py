# AU05 listen-only test. Opens the AU05 private channel (page 0xFFFC) and the
# media-key channel for READING ONLY. It never writes to the device.
# Guided: tells you what to press. Stops by itself. Ctrl+C stops it at any time.
import ctypes, ctypes.wintypes as W, sys, threading, time, os

VID, PID = 0xFFF1, 0x00DD
LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "au05_capture.txt")
hid = ctypes.WinDLL("hid"); sa = ctypes.WinDLL("setupapi"); k32 = ctypes.WinDLL("kernel32", use_last_error=True)

class GUID(ctypes.Structure):
    _fields_ = [("a", W.DWORD), ("b", W.WORD), ("c", W.WORD), ("d", ctypes.c_ubyte * 8)]
class IFD(ctypes.Structure):
    _fields_ = [("cbSize", W.DWORD), ("guid", GUID), ("flags", W.DWORD), ("res", ctypes.c_void_p)]
class CAPS(ctypes.Structure):
    _fields_ = [("Usage", W.USHORT), ("UsagePage", W.USHORT), ("InLen", W.USHORT), ("OutLen", W.USHORT),
                ("FeatLen", W.USHORT), ("Res", W.USHORT * 27)]

k32.CreateFileW.restype = ctypes.c_void_p
sa.SetupDiGetClassDevsW.restype = ctypes.c_void_p
GENERIC_READ = 0x80000000

def find():
    g = GUID(); hid.HidD_GetHidGuid(ctypes.byref(g))
    h = sa.SetupDiGetClassDevsW(ctypes.byref(g), None, None, 0x12)
    out, i = [], 0
    while True:
        d = IFD(); d.cbSize = ctypes.sizeof(IFD)
        if not sa.SetupDiEnumDeviceInterfaces(ctypes.c_void_p(h), None, ctypes.byref(g), i, ctypes.byref(d)): break
        i += 1
        need = W.DWORD(); sa.SetupDiGetDeviceInterfaceDetailW(ctypes.c_void_p(h), ctypes.byref(d), None, 0, ctypes.byref(need), None)
        buf = ctypes.create_string_buffer(need.value); ctypes.cast(buf, ctypes.POINTER(W.DWORD))[0] = 8
        if not sa.SetupDiGetDeviceInterfaceDetailW(ctypes.c_void_p(h), ctypes.byref(d), buf, need, None, None): continue
        p = ctypes.wstring_at(ctypes.addressof(buf) + 4)
        if f"vid_{VID:04x}&pid_{PID:04x}" in p.lower(): out.append(p)
    return out

step = ["(waiting)"]
count = [0]
lock = threading.Lock()
logf = open(LOG, "w", encoding="utf-8")
t0 = time.time()

def log(line):
    with lock:
        logf.write(line + "\n"); logf.flush()

def reader(name, fh, n):
    buf = ctypes.create_string_buffer(n); got = W.DWORD()
    while True:
        ok = k32.ReadFile(ctypes.c_void_p(fh), buf, n, ctypes.byref(got), None)
        if not ok: log(f"{time.time()-t0:7.3f} {name} read stopped (error {ctypes.get_last_error()})"); return
        data = buf.raw[:got.value]
        # trim trailing zeros for readability, keep the length
        trimmed = data.rstrip(b"\x00")
        log(f"{time.time()-t0:7.3f} [{step[0]}] {name} len={got.value} {trimmed.hex(' ')}")
        count[0] += 1

opened = 0
for p in find():
    fh = k32.CreateFileW(p, GENERIC_READ, 3, None, 3, 0, None)
    if fh in (None, ctypes.c_void_p(-1).value): continue  # keyboard/mouse parts are locked by Windows: expected
    pp = ctypes.c_void_p(); caps = CAPS()
    hid.HidD_GetPreparsedData(ctypes.c_void_p(fh), ctypes.byref(pp)); hid.HidP_GetCaps(pp, ctypes.byref(caps)); hid.HidD_FreePreparsedData(pp)
    name = "PRIVATE" if caps.UsagePage == 0xFFFC else f"page{caps.UsagePage:04X}"
    log(f"opened {name} (read only) in={caps.InLen} {p}")
    threading.Thread(target=reader, args=(name, fh, caps.InLen), daemon=True).start()
    opened += 1

if not opened:
    print("Could not open any AU05 channel. Is the receiver plugged in?"); sys.exit(1)

STEPS = [
    ("start", "Get ready. Click on an empty part of the desktop (not on Claude). Do not touch the AU05 yet.", 15),
    ("idle", "Do nothing. Listening to what the AU05 sends by itself.", 6),
    ("K1", "Press K1 (voice key) ONCE. If voice typing opens, ignore it.", 6),
    ("K2", "Press K2 (confirm) ONCE.", 5),
    ("K3", "Press K3 (reject) ONCE. This also closes voice typing.", 5),
    ("knob-press", "Press the knob ONCE.", 5),
    ("knob-right", "Turn the knob RIGHT (clockwise) 3 clicks, slowly.", 7),
    ("knob-left", "Turn the knob LEFT 3 clicks, slowly.", 7),
    ("K1-hold", "Press and HOLD K1 for 2 seconds, then let go.", 7),
    ("K2-double", "Double-press K2.", 6),
    ("idle-end", "Do nothing. Almost done.", 6),
]
print(f"\nAU05 listen-only test. Opened {opened} channel(s). Nothing is sent to the device.")
print("Press Ctrl+C at any time to stop.\n")
try:
    for key, text, secs in STEPS:
        step[0] = key
        log(f"{time.time()-t0:7.3f} --- step {key}")
        print(f"\n>>> {text}")
        for s in range(secs, 0, -1):
            print(f"    {s:2d}s left   (messages saved so far: {count[0]})   ", end="\r", flush=True); time.sleep(1)
except KeyboardInterrupt:
    print("\nStopped by you.")
log(f"{time.time()-t0:7.3f} --- end")
logf.close()
print(f"\nDone. Saved to {LOG}\nYou can close this tab. Tell Claude it is finished.")
