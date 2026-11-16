# Sends exactly ONE read-only "get battery" request (plaintext 01 01 02 01) to the
# AU05 private channel, then prints every reply for 4 s. It sends it only if the
# AU05 is awake (a message arrives while listening first). No other write exists here.
import ctypes, ctypes.wintypes as W, struct, threading, time, sys

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
assert enc(bytes(8)) == bytes.fromhex("3890c499a360aaad") and dec(enc(b"12345678")) == b"12345678"

GET = bytes.fromhex("01010201")            # getBattery: type 01, class 01, cmd 02, flags 01 (get)
pt = GET.ljust(56, b"\0")
frame = bytes([0x55]) + b"".join(enc(pt[i:i+8]) for i in range(0, 56, 8)) + bytes(7)
assert len(frame) == 64

hid = ctypes.WinDLL("hid"); sa = ctypes.WinDLL("setupapi"); k32 = ctypes.WinDLL("kernel32", use_last_error=True)
class GUID(ctypes.Structure): _fields_ = [("a", W.DWORD), ("b", W.WORD), ("c", W.WORD), ("d", ctypes.c_ubyte * 8)]
class IFD(ctypes.Structure): _fields_ = [("cbSize", W.DWORD), ("guid", GUID), ("flags", W.DWORD), ("res", ctypes.c_void_p)]
k32.CreateFileW.restype = ctypes.c_void_p; sa.SetupDiGetClassDevsW.restype = ctypes.c_void_p
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

fh = k32.CreateFileW(path, 0xC0000000, 3, None, 3, 0, None)   # read + write
if fh in (None, ctypes.c_void_p(-1).value): print("open failed", ctypes.get_last_error()); sys.exit(1)
t0 = time.time(); got = []
def reader():
    b = ctypes.create_string_buffer(64); n = W.DWORD()
    while k32.ReadFile(ctypes.c_void_p(fh), b, 64, ctypes.byref(n), None):
        raw = b.raw[:n.value].ljust(64, b"\0")
        p = b"".join(dec(raw[1+8*j:9+8*j]) for j in range(7))
        got.append(time.time() - t0)
        print(f"{time.time()-t0:6.2f}s  in  id=0x{raw[0]:02x}  plain: {p[:16].hex(' ')}", flush=True)
threading.Thread(target=reader, daemon=True).start()

print("Put the mouse over an empty part of the desktop, then turn the AU05 knob ONE click to wake it.")
print("Waiting up to 60 s...", flush=True)
end = time.time() + 60
while time.time() < end and not got: time.sleep(0.1)
if not got:
    print("No message from the AU05: it is probably asleep. NOTHING was sent."); sys.exit(2)
time.sleep(0.5)
print(f"{time.time()-t0:6.2f}s  OUT one get-battery  plain: {GET.hex(' ')}  frame: {frame[:12].hex(' ')} ...", flush=True)
w = W.DWORD()
ok = k32.WriteFile(ctypes.c_void_p(fh), frame, 64, ctypes.byref(w), None)
print("write ok" if ok else f"write FAILED error {ctypes.get_last_error()}", f"({w.value} bytes)", flush=True)
time.sleep(4)
print("done")
