"""Ulanzi AU05 (Vibe Key) private HID channel: TEA-ECB codec + message parser.

Derived by static analysis of Ulanzi_Studio.dll 3.4.4 (TEA at RVA 0xEE30 decrypt / 0xEF10 encrypt,
key at .data RVA 0xADD78). Pure offline codec: never opens or writes any HID device.

Usage:
  python -I au05_crypto.py <hex report> [...]     decrypt + parse 64-byte input reports (byte0 = report id 0x55)
  python -I au05_crypto.py --selftest            decrypt the captured sample blocks
  python -I au05_crypto.py --build <hex plaintext>  show the 64-byte frame Studio would write (NOT sent)
"""
import struct
import sys

KEY = bytes.fromhex('cabaa5ca6d8a2abcba9e5acaca8bb89b')   # 4 little-endian uint32: k0..k3
DELTA = 0x9E3779B9
M32 = 0xFFFFFFFF
REPORT_ID = 0x55          # Studio writes caps ReportID at byte 0; inbound reports carry 0x55
REPORT_LEN = 64           # Input/OutputReportByteLength incl. report-id byte


def _k():
    return struct.unpack('<4I', KEY)


def tea_dec_block(b):
    v0, v1 = struct.unpack('<2I', b)
    k0, k1, k2, k3 = _k()
    s = (DELTA * 32) & M32          # 0xC6EF3720
    for _ in range(32):
        v1 = (v1 - ((((v0 << 4) + k2) & M32) ^ ((v0 + s) & M32) ^ (((v0 >> 5) + k3) & M32))) & M32
        v0 = (v0 - ((((v1 << 4) + k0) & M32) ^ ((v1 + s) & M32) ^ (((v1 >> 5) + k1) & M32))) & M32
        s = (s - DELTA) & M32
    return struct.pack('<2I', v0, v1)


def tea_enc_block(b):
    v0, v1 = struct.unpack('<2I', b)
    k0, k1, k2, k3 = _k()
    s = 0
    for _ in range(32):
        s = (s + DELTA) & M32
        v0 = (v0 + ((((v1 << 4) + k0) & M32) ^ ((v1 + s) & M32) ^ (((v1 >> 5) + k1) & M32))) & M32
        v1 = (v1 + ((((v0 << 4) + k2) & M32) ^ ((v0 + s) & M32) ^ (((v0 >> 5) + k3) & M32))) & M32
    return struct.pack('<2I', v0, v1)


def _ecb(data, fn):
    n = len(data) // 8 * 8                      # Studio: length>>3 blocks; tail bytes left as-is
    return b''.join(fn(data[i:i + 8]) for i in range(0, n, 8)) + data[n:]


def decrypt_report(report):
    """report = 64 bytes as read (byte0 = report id). Returns 63-byte plaintext (bytes 57..63 untouched)."""
    return _ecb(bytes(report[1:]), tea_dec_block)


def build_frame(plain, report_id=REPORT_ID):
    """What Studio's writer does: [id] + first 63 bytes of message, TEA over 63>>3 = 7 blocks."""
    body = (bytes(plain) + bytes(63))[:63]
    return bytes([report_id]) + _ecb(body, tea_enc_block)


def parse(pt):
    t = pt[0] & 0x1F
    if t == 0x0B:                                # unsolicited device event
        sub = pt[1]
        if sub == 0x10:
            w = pt[4] | pt[5] << 8
            return dict(kind='key', code=hex(pt[2]), pressed=pt[3], index=w & 0xFFF, hi=w >> 12)
        if sub == 0x7B:
            fl = pt[4]
            return dict(kind='status7B', word=pt[2] | pt[3] << 8, flags=hex(fl),
                        f_b01=fl & 3, f_b2=fl >> 2 & 1, f_b3=fl >> 3 & 1, f_b4=fl >> 4 & 1, byte5=pt[5],
                        extra=pt[6] | pt[7] << 8)
        return dict(kind='event', sub=hex(sub), raw=pt[:16].hex(' '))
    if t in (0x01, 0x06):                        # response to a request: [type][class][cmd][flags][data..]
        return dict(kind='response', type=t, cls=pt[1] & 0x0F, cmd=hex(pt[2]), flags=hex(pt[3]),
                    ack=bool(pt[3] & 0x10), data=pt[4:20].hex(' '))
    return dict(kind='unknown', raw=pt[:16].hex(' '))


SAMPLES = ['3890c499a360aaad', '2f12546e779bb7de', 'd61b8983fbb65430', '9d70d019680b19dc',
           'ea9891b35da4f5fb', '3c81720972017506', '9dd350c99eb55a4a', '23af678d687ee3b1',
           '7aa9de6858380fdc', '04720460bda30b4e', '4836212a3cecf427', 'b99ae2afd637c6f4',
           '4bed2fcf7a4b85c9']

if __name__ == '__main__':
    a = sys.argv[1:]
    if not a or a[0] == '--selftest':
        assert tea_enc_block(bytes(8)).hex() == '3890c499a360aaad'
        for h in SAMPLES:
            pt = tea_dec_block(bytes.fromhex(h))
            print(h, '->', pt.hex(' '), parse(pt + bytes(55)))
    elif a[0] == '--build':
        print(build_frame(bytes.fromhex(''.join(a[1:]))).hex(' '))
    else:
        for h in a:
            r = bytes.fromhex(h.replace(' ', ''))
            pt = decrypt_report(r)
            print(pt.hex(' '))
            print(parse(pt))
