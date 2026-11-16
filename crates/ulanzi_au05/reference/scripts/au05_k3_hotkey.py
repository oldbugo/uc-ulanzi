# Prototype, LISTEN ONLY to the AU05 (never writes to it).
# When K3 (index 2) is pressed: bring the Claude app to the front and press Ctrl+D
# (Claude's dictation). Runs 3 minutes, or until Ctrl+C. Log: au05_k3_hotkey.txt
import ctypes, ctypes.wintypes as W, struct, threading, time, sys, os

K = struct.unpack("<4I", bytes.fromhex("cabaa5ca6d8a2abcba9e5acaca8bb89b"))
M = 0xFFFFFFFF
def dec(b):
    v0, v1 = struct.unpack("<2I", b); s = 0xC6EF3720
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + K[2]) ^ (v0 + s) ^ ((v0 >> 5) + K[3]))) & M
        v0 = (v0 - (((v1 << 4) + K[0]) ^ (v1 + s) ^ ((v1 >> 5) + K[1]))) & M
        s = (s - 0x9E3779B9) & M
    return struct.pack("<2I", v0, v1)

u32 = ctypes.WinDLL("user32", use_last_error=True)
hid = ctypes.WinDLL("hid"); sa = ctypes.WinDLL("setupapi"); k32 = ctypes.WinDLL("kernel32", use_last_error=True)

# ---- find the Claude window: visible top-level window of Claude.exe titled "Claude"
psapi = ctypes.WinDLL("psapi")
EnumProc = ctypes.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
k32.OpenProcess.restype = W.HANDLE
def exe_of(hwnd):
    pid = W.DWORD(); u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    hp = k32.OpenProcess(0x1000, False, pid.value)   # query limited information
    if not hp: return ""
    buf = ctypes.create_unicode_buffer(520); n = W.DWORD(520)
    k32.QueryFullProcessImageNameW(hp, 0, buf, ctypes.byref(n)); k32.CloseHandle(hp)
    return os.path.basename(buf.value).lower()
def find_claude():
    found = []
    def cb(hwnd, _):
        if u32.IsWindowVisible(hwnd):
            t = ctypes.create_unicode_buffer(256); u32.GetWindowTextW(hwnd, t, 256)
            if t.value.startswith("Claude") and exe_of(hwnd) == "claude.exe": found.append(hwnd)
        return True
    u32.EnumWindows(EnumProc(cb), 0)
    return found[0] if found else None

# ---- keyboard input
class KI(ctypes.Structure): _fields_ = [("wVk", W.WORD), ("wScan", W.WORD), ("dwFlags", W.DWORD), ("time", W.DWORD), ("dwExtraInfo", ctypes.c_size_t)]
class MI(ctypes.Structure): _fields_ = [("dx", W.LONG), ("dy", W.LONG), ("mouseData", W.DWORD), ("dwFlags", W.DWORD), ("time", W.DWORD), ("dwExtraInfo", ctypes.c_size_t)]
class U(ctypes.Union): _fields_ = [("ki", KI), ("mi", MI)]
class INPUT(ctypes.Structure): _fields_ = [("type", W.DWORD), ("u", U)]
def keys(seq):   # seq of (vk, up)
    arr = (INPUT * len(seq))()
    for i, (vk, up) in enumerate(seq):
        arr[i].type = 1; arr[i].u.ki.wVk = vk; arr[i].u.ki.dwFlags = 2 if up else 0
    u32.SendInput(len(seq), arr, ctypes.sizeof(INPUT))
VK_CTRL, VK_ALT, VK_D = 0x11, 0x12, 0x44

def start_dictation():
    hwnd = find_claude()
    if not hwnd: return "Claude window not found"
    if u32.IsIconic(hwnd): u32.ShowWindow(hwnd, 9)        # restore if minimised
    keys([(VK_ALT, False), (VK_ALT, True)])               # lets this script move focus (Windows rule)
    u32.SetForegroundWindow(hwnd)
    for _ in range(30):                                   # wait up to 0.6 s for Claude to be in front
        if u32.GetForegroundWindow() == hwnd: break
        time.sleep(0.02)
    else: return "could not bring Claude to the front"
    time.sleep(0.12)
    keys([(VK_CTRL, False), (VK_D, False), (VK_D, True), (VK_CTRL, True)])
    return "Claude in front, Ctrl+D pressed"

# ---- open the AU05 private channel READ ONLY
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
fh = k32.CreateFileW(path, 0x80000000, 3, None, 3, 0, None)   # GENERIC_READ only
if fh in (None, ctypes.c_void_p(-1).value): print("open failed", ctypes.get_last_error()); sys.exit(1)

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "au05_k3_hotkey.txt")
logf = open(LOG, "w", encoding="utf-8"); t0 = time.time()
def out(s): logf.write(s + "\n"); logf.flush(); print(s, flush=True)
def reader():
    b = ctypes.create_string_buffer(64); n = W.DWORD()
    while k32.ReadFile(ctypes.c_void_p(fh), b, 64, ctypes.byref(n), None):
        raw = b.raw[:n.value].ljust(64, b"\0")
        p = b"".join(dec(raw[1+8*j:9+8*j]) for j in range(7))
        if (p[0] & 0x1F) == 0x0B and p[1] == 0x10:
            idx = struct.unpack_from("<H", p, 4)[0] & 0xFFF
            out(f"{time.time()-t0:6.1f}s  private event: index {idx} {'down' if p[3] else 'up'} code 0x{p[2]:02x}")
threading.Thread(target=reader, daemon=True).start()

print("Ready. For 3 minutes: go to any other app (Notepad, a browser), then press K3.")
print("Claude should come to the front and start dictation. Ctrl+C stops this.", flush=True)
print("Claude window found:", "yes" if find_claude() else "NO - open the Claude app first", flush=True)
class MSG(ctypes.Structure): _fields_ = [("hwnd", W.HWND), ("message", W.UINT), ("wParam", W.WPARAM), ("lParam", W.LPARAM), ("time", W.DWORD), ("pt", W.POINT)]
VK_F22, WM_HOTKEY, MOD_NOREPEAT = 0x85, 0x0312, 0x4000
if not u32.RegisterHotKey(None, 1, MOD_NOREPEAT, VK_F22):
    print("Could not claim F22 (error", ctypes.get_last_error(), ")"); sys.exit(1)
print("F22 claimed: K3 (which types F22) now triggers Claude dictation from any app.", flush=True)
try:
    end = time.time() + 180; msg = MSG()
    while time.time() < end:
        while u32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
            if msg.message == WM_HOTKEY and msg.wParam == 1:
                out(f"{time.time()-t0:6.1f}s  F22 (K3) -> {start_dictation()}")
        time.sleep(0.02)
except KeyboardInterrupt:
    out("stopped by Ctrl+C")
u32.UnregisterHotKey(None, 1)
out("done"); logf.close()
