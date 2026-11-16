# Independent check: plain TEA decrypt of every captured report. Reads a file only.
import struct, sys, re, collections
K = struct.unpack("<4I", bytes.fromhex("cabaa5ca6d8a2abcba9e5acaca8bb89b"))
def dec(b):
    v0, v1 = struct.unpack("<2I", b); s = 0xC6EF3720; d = 0x9E3779B9; M = 0xFFFFFFFF
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + K[2]) ^ (v0 + s) ^ ((v0 >> 5) + K[3]))) & M
        v0 = (v0 - (((v1 << 4) + K[0]) ^ (v1 + s) ^ ((v1 >> 5) + K[1]))) & M
        s = (s - d) & M
    return struct.pack("<2I", v0, v1)
step = "?"; seen = collections.Counter(); bad = 0
for line in open(sys.argv[1], encoding="utf-8"):
    m = re.search(r"--- step (\S+)", line)
    if m: step = m.group(1); print(f"===== {step}"); continue
    m = re.search(r"^\s*([\d.]+) \[\S+\] PRIVATE len=64 (.*)$", line)
    if not m: continue
    raw = bytes.fromhex(m.group(2).replace(" ", "")).ljust(64, b"\0")
    pt = b"".join(dec(raw[1 + 8*i: 9 + 8*i]) for i in range(7))
    if any(pt[8:56]): bad += 1           # blocks 2..7 should be zero
    if pt[1] == 0x10:
        idx = struct.unpack_from("<H", pt, 4)[0]
        print(f"{m.group(1):>8} KEY code=0x{pt[2]:02x} {'down' if pt[3] else 'up  '} index={idx & 0xFFF} hi={idx >> 12}")
    else:
        print(f"{m.group(1):>8} other {pt[:8].hex(' ')}")
print("reports whose later blocks were NOT zero:", bad)
