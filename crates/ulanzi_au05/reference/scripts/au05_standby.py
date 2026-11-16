# AU05 safe read run. Sends ONLY the read-only gets listed in GETS (flags 0x01),
# one at a time. Every send has a 2 s limit; the run STOPS at the first send that
# does not finish, or a reply slower than 1.5 s / missing. Ctrl+C works at any time.
# Starts only after the AU05 shows it is awake. Log: au05_standby.txt
import ctypes, ctypes.wintypes as W, struct, threading, time, sys, os

K = struct.unpack("<4I", bytes.fromhex("cabaa5ca6d8a2abcba9e5acaca8bb89b"))
M, D = 0xFFFFFFFF, 0x9E3779B9
def enc(b):
    v0, v1 = struct.unpack("<2I", b); s = 0
    for _ in range(32):
        s = (s + D) & M
        v0 = (v0 + ((((v1 << 4) + K[0]) ^ (v1 + s) ^ ((v1 >> 5) + K[1])))) & M
        v1 = (v1 + ((((v0 << 4) + K[2]) ^ (v0 + s) ^ ((v0 >> 5) + K[3])))) & M
    return struct.pack("<2I", v0, v1)
def dec(b):
    v0, v1 = struct.unpack("<2I", b); s = 0xC6EF3720
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + K[2]) ^ (v0 + s) ^ ((v0 >> 5) + K[3]))) & M
        v0 = (v0 - (((v1 << 4) + K[0]) ^ (v1 + s) ^ ((v1 >> 5) + K[1]))) & M
        s = (s - D) & M
    return struct.pack("<2I", v0, v1)
assert enc(bytes(8)) == bytes.fromhex("3890c499a360aaad")

SECONDS = 300 if "--restore" in sys.argv else 600
STEPS = [  # (name, plaintext) - reads, plus ONE set: standby time (cmd 0x2C, flags 0x02)
    ("standby status", "01 01 0d 01"),
    ("standby time (before)", "01 01 2c 01"),
    ("SET standby time", "01 01 2c 02 " + struct.pack("<I", SECONDS).hex(" ")),
    ("standby time (after)", "01 01 2c 01"),
    ("light all", "01 0b 88 01"),
]
GETS = [(n, bytes.fromhex(h)) for n, h in STEPS]
for n, p in GETS:
    assert p[0] == 1 and p[1] in (0x01, 0x0b), n
    is_read = p[3] == 0x01 and len(p) <= 4
    is_standby_set = p[1] == 0x01 and p[2] == 0x2c and p[3] == 0x02 and len(p) == 8 and 120 <= struct.unpack_from("<I", p, 4)[0] <= 1800
    assert is_read or is_standby_set, n
    assert p[2] in (0x0d, 0x2c, 0x88), n
def frame(p):
    pt = p.ljust(56, b"\0")
    return bytes([0x55]) + b"".join(enc(pt[i:i+8]) for i in range(0, 56, 8)) + bytes(7)

hid = ctypes.WinDLL("hid"); sa = ctypes.WinDLL("setupapi"); k32 = ctypes.WinDLL("kernel32", use_last_error=True)
class GUID(ctypes.Structure): _fields_ = [("a", W.DWORD), ("b", W.WORD), ("c", W.WORD), ("d", ctypes.c_ubyte * 8)]
class IFD(ctypes.Structure): _fields_ = [("cbSize", W.DWORD), ("guid", GUID), ("flags", W.DWORD), ("res", ctypes.c_void_p)]
class OVL(ctypes.Structure): _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p), ("Offset", W.DWORD), ("OffsetHigh", W.DWORD), ("hEvent", W.HANDLE)]
k32.CreateFileW.restype = ctypes.c_void_p; sa.SetupDiGetClassDevsW.restype = ctypes.c_void_p
k32.CreateEventW.restype = W.HANDLE
g = GUID(); hid.HidD_GetHidGuid(ctypes.byref(g)); h = sa.SetupDiGetClassDevsW(ctypes.byref(g), None, None, 0x12)
path, i = None, 0
while True:
    d = IFD(); d.cbSize = ctypes.sizeof(IFD)
    if not sa.SetupDiEnumDeviceInterfaces(ctypes.c_void_p(h), None, ctypes.byref(g), i, ctypes.byref(d)): break
    i += 1; need = W.DWORD()
    sa.SetupDiGetDeviceInterfaceDetailW(ctypes.c_void_p(h), ctypes.byref(d), None, 0, ctypes.byref(need), None)
    buf = ctypes.create_string_buffer(need.value); ctypes.cast(buf, ctypes.POINTER(W.DWORD))[0] = 8
    if sa.SetupDiGetDeviceInterfaceDetailW(ctypes.c_void_p(h), ctypes.byref(d), buf, need, None, None):
        p = ctypes.wstring_at(ctypes.addressof(buf) + 4)
        if "vid_fff1&pid_00dd&mi_03" in p.lower(): path = p
if not path: print("AU05 private channel not found"); sys.exit(1)
FLAG_OVERLAPPED = 0x40000000
fh = k32.CreateFileW(path, 0xC0000000, 3, None, 3, FLAG_OVERLAPPED, None)
if fh in (None, ctypes.c_void_p(-1).value): print("open failed", ctypes.get_last_error()); sys.exit(1)
fh = ctypes.c_void_p(fh)

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "au05_standby.txt")
logf = open(LOG, "w", encoding="utf-8"); t0 = time.time()
events, replies, stop_all = [], [], threading.Event()
def out(s):
    logf.write(s + "\n"); logf.flush(); print(s, flush=True)

def reader():
    ev = k32.CreateEventW(None, True, False, None)
    b = ctypes.create_string_buffer(64); n = W.DWORD()
    while not stop_all.is_set():
        o = OVL(); o.hEvent = ev; k32.ResetEvent(ev)
        if not k32.ReadFile(fh, b, 64, None, ctypes.byref(o)) and ctypes.get_last_error() != 997: return
        while not stop_all.is_set() and k32.WaitForSingleObject(ev, 200) == 0x102: pass
        if stop_all.is_set(): k32.CancelIoEx(fh, ctypes.byref(o)); return
        if not k32.GetOverlappedResult(fh, ctypes.byref(o), ctypes.byref(n), False): return
        raw = b.raw[:n.value].ljust(64, b"\0")
        p = b"".join(dec(raw[1+8*j:9+8*j]) for j in range(7))
        if (p[0] & 0x1F) == 0x0B: events.append(p)
        else: replies.append(p); out(f"{time.time()-t0:6.2f}s  reply {p[:28].hex(' ')}")

def send(p, limit=2.0):
    ev = k32.CreateEventW(None, True, False, None); o = OVL(); o.hEvent = ev; n = W.DWORD()
    fr = ctypes.create_string_buffer(frame(p), 64)
    if not k32.WriteFile(fh, fr, 64, None, ctypes.byref(o)) and ctypes.get_last_error() != 997: return "error"
    if k32.WaitForSingleObject(ev, int(limit * 1000)) != 0:
        k32.CancelIoEx(fh, ctypes.byref(o)); return "timeout"
    return "ok" if k32.GetOverlappedResult(fh, ctypes.byref(o), ctypes.byref(n), False) else "error"

threading.Thread(target=reader, daemon=True).start()
try:
    print("Put the mouse over an empty part of the desktop, then turn the AU05 knob ONE click to wake it.")
    print("Waiting up to 60 s...  (Ctrl+C stops at any time)", flush=True)
    end = time.time() + 60
    while time.time() < end and not events: time.sleep(0.1)
    if not events: print("No message from the AU05: it is probably asleep. NOTHING was sent."); sys.exit(2)
    if "--dry" in sys.argv: out(f"dry run: AU05 awake ({len(events)} events), sending nothing"); sys.exit(0)
    time.sleep(0.5)
    for name, p in GETS:
        before = len(replies); ts = time.time()
        out(f"{ts-t0:6.2f}s  OUT  {name:15s} {p.hex(' ')}")
        r = send(p)
        if r != "ok": out(f"        send {r} - STOPPING the run"); break
        while time.time() - ts < 1.5 and len(replies) == before: time.sleep(0.02)
        if len(replies) == before: out("        no reply within 1.5 s - STOPPING the run"); break
        time.sleep(0.2)
    else:
        out("all steps answered")
except KeyboardInterrupt:
    out("stopped by Ctrl+C")
finally:
    stop_all.set(); time.sleep(0.3); out("done"); logf.close()
    # report (do not change) any modifier key that Windows thinks is still held
    u = ctypes.WinDLL("user32")
    down = [nm for vk, nm in ((0x10, "Shift"), (0x11, "Ctrl"), (0x12, "Alt"), (0x5B, "Win"), (0x5C, "Win")) if u.GetAsyncKeyState(vk) & 0x8000]
    print("Modifier keys held now:", ", ".join(down) if down else "none")
    print(f"Saved to {LOG}. Tell Claude it is done.")

