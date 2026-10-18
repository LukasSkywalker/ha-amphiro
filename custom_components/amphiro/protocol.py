"""amphiro b1 packet crypto and parsing, see PROTOCOL.md.

No Home Assistant imports: amphiro.py uses this module too.
"""

import random
import re

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SERIAL_TX = "0d27fb90-f0d4-469d-afd3-605a6ebbdb13"  # commands (write)
SERIAL_RX = "0d27fb91-f0d4-469d-afd3-605a6ebbdb13"  # replies (notify)
SHOW_KEY = bytes([0xFF, 0x01, 0x77] + [0xB1] * 15)  # sent unencrypted
B1_NAMES = ("amphiro_b1", "amphiro b1")
LIVE = (0x11, 0x41)


def bsd(data):
    c = 0
    for b in data:
        c = ((((c >> 1) | (c << 7)) & 0xFF) + b) & 0xFF
    return c


def aes_key(code):
    """AES-128 key from the pairing code: 4 letters + 4 digits, e.g. ABCD1234.
    Short forms are padded like the app does: "585" -> AAAA0585."""
    m = re.fullmatch(r"([A-Z]{0,4})([0-9]{1,4})", code.strip().upper())
    if not m:
        raise ValueError(f"pairing code must look like ABCD1234 or 585, got {code!r}")
    code = m[1].rjust(4, "A") + m[2].rjust(4, "0")
    d = [int(x) for x in code[4:]]
    r = (d[3] * 100 + d[2] * 10 + d[1]) * 2 + d[0]
    for ch in reversed(code[:4]):
        r = r * 26 + ord(ch) - 65
    k = list(r.to_bytes(4, "little"))
    for i in range(4, 16):
        k.append(bsd(k[i - 4 : i]))
    return bytes(k)


def mac_code(mac):
    """Default code derived from the MAC, used by devices that don't require pairing."""
    m = bytes.fromhex(mac.removeprefix("0x").replace(":", ""))
    n = (int.from_bytes(m[2:6], "little") & 0x1FFFFFFF) // 26**4
    return f"AAAA{n % 2}{n // 2 % 10}{n // 20 % 10}{n // 200 % 10}"


def _aes(key, block, decrypt=False):
    c = Cipher(algorithms.AES(key), modes.ECB())
    op = c.decryptor() if decrypt else c.encryptor()
    return op.update(bytes(block)) + op.finalize()


def encrypt(key, p):
    a = _aes(key, p[:16])
    return a[:2] + _aes(key, a[2:16] + p[16:18])


def decrypt(key, p):
    """18-byte plaintext, or None when the checksum fails (wrong key)."""
    a = _aes(key, p[2:18], decrypt=True)
    t = _aes(key, p[:2] + a[:14], decrypt=True) + a[14:16]
    return t if bsd(t[3:18]) == t[2] else None


def command(key, code, args=b""):
    p = bytearray(18)
    p[0], p[1] = code, 0x01
    p[3 : 3 + len(args)] = args
    p[17] = random.randrange(256)
    p[2] = bsd(p[3:])
    return encrypt(key, bytes(p))


def parse(p):
    be = lambda a, b: int.from_bytes(p[a:b], "big")
    if p[0] in LIVE:
        # ponytail: firmware < 54.53 (old unnamed b1) has no flow byte, duration is be(14, 17)
        return dict(type="live", shower=be(3, 5), litres=be(5, 9) / 10, energy_wh=be(9, 13),
                    temp_c=p[13], flow_lpm=p[14] / 10, seconds=be(15, 17))
    if p[0] in (0x12, 0x42):
        return dict(type="history", shower=be(3, 5), litres=be(7, 9) / 10, temp_c=p[9],
                    cold_water_c=p[10], heating_eff=p[11], flow_lpm=p[12] / 10, max_break=p[13])
    if p[0] == 0x00:
        return dict(type="version", firmware=f"{p[13]}.{p[15]}")
    return dict(type=f"0x{p[0]:02x}", raw=p.hex())


def packets(manufacturer_data):
    """The b1 packets in a bleak / Home Assistant manufacturer_data dict.
    The "company ID" key is really bytes 0-1 of the encrypted packet."""
    for cid, data in manufacturer_data.items():
        raw = cid.to_bytes(2, "little") + data
        if len(raw) in (18, 20):
            yield raw


def newest_live(manufacturer_data, key, seen):
    """Parsed newest live packet among those not in `seen` (updated in place), or None.
    BlueZ and Home Assistant keep every packet of a shower in manufacturer_data,
    because the changing ciphertext looks like a new company ID each time."""
    new = [r for r in packets(manufacturer_data) if r not in seen]
    seen.update(new)
    for raw in reversed(new):
        if (p := decrypt(key, raw)) and p[0] in LIVE:
            return parse(p)
    return None
