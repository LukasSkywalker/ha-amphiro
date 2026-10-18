#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["bleak>=0.22", "cryptography>=42"]
# ///
"""Read an amphiro b1 shower meter over BLE without the app. Protocol: see PROTOCOL.md.

  uv run amphiro.py selftest
  uv run amphiro.py scan [--key ABCD1234]          # live data from advertisements
  uv run amphiro.py showkey AA:BB:CC:DD:EE:FF      # device shows its pairing code
  uv run amphiro.py history AA:BB:CC:DD:EE:FF [--key ABCD1234] 1 50

The b1 is powered by the water flow: keep the shower running for every command.
"""
import argparse
import asyncio
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "custom_components" / "amphiro"))
from protocol import (  # noqa: E402
    B1_NAMES, SERIAL_RX, SERIAL_TX, SHOW_KEY, aes_key, bsd, command, decrypt, encrypt,
    mac_code, newest_live, packets, parse,
)


async def scan(code):
    from bleak import BleakScanner

    seen = set()

    def on_adv(dev, adv):
        named = (adv.local_name or "").lower() in B1_NAMES
        # BlueZ keys manufacturer data by the first 2 bytes, which are ciphertext here,
        # so every packet of the shower piles up in this dict: only print new ones.
        for raw in packets(adv.manufacturer_data):
            if raw in seen or not (named or raw[18:20] == b"B1"):
                continue
            seen.add(raw)
            p = decrypt(aes_key(code or mac_code(dev.address)), raw)
            # a few packets per shower never decrypt; the app ignores them too
            print(dev.address, adv.rssi, parse(p) if p else f"can't decrypt {raw.hex()}")

    async with BleakScanner(on_adv):
        print("Scanning; turn the shower on. Ctrl-C to stop.")
        await asyncio.Event().wait()


async def showkey(address):
    from bleak import BleakClient

    got = asyncio.Event()
    async with BleakClient(address) as c:
        await c.start_notify(SERIAL_RX, lambda *_: got.set())
        await c.write_gatt_char(SERIAL_TX, SHOW_KEY, response=True)
        try:
            await asyncio.wait_for(got.wait(), 5)
        except TimeoutError:
            pass
    print("The display should now show the pairing code (4 letters + 4 digits).")


async def history(address, code, start, end):
    from bleak import BleakClient

    key, q = aes_key(code or mac_code(address)), asyncio.Queue()
    async with BleakClient(address) as c:
        await c.start_notify(SERIAL_RX, lambda _, d: q.put_nowait(bytes(d)))
        for s in range(start, end + 1, 9):  # the app asks old b1s for at most 9 at a time
            e = min(s + 8, end)
            await c.write_gatt_char(SERIAL_TX, command(key, 0x22, struct.pack(">HH", s, e)), response=True)
            for _ in range(e - s + 1):
                try:
                    raw = await asyncio.wait_for(q.get(), 5)
                except TimeoutError:
                    break
                p = decrypt(key, raw)
                print(parse(p) if p else f"can't decrypt {raw.hex()}")


def selftest():
    # vectors from running the app's own JS crypto (main.js webpack modules 213/214)
    assert aes_key("ABCD1234").hex() == "6a629017c4bf78abafda2b39ba7c0cdf"
    assert aes_key("ZQXW1999").hex() == "d5f878362a823345c4831c777e3050b6"
    assert mac_code("0x11:22:33:44:55:66") == "AAAA0611"
    assert aes_key("585") == aes_key("AAAA0585")
    k, plain = aes_key("ABCD1234"), bytes.fromhex("1104ff002a00000107000003e8265f012c7b")
    assert encrypt(k, plain).hex() == "2060ebd25d6a5085775a7208c408f83069a2"
    assert decrypt(k, encrypt(k, plain) + b"B1") == plain
    assert decrypt(aes_key("ABCD1235"), encrypt(k, plain)) is None
    assert bsd(SHOW_KEY[3:]) == SHOW_KEY[2]
    assert parse(plain) == dict(type="live", shower=42, litres=26.3, energy_wh=1000,
                                temp_c=38, flow_lpm=9.5, seconds=300)

    # newest_live on a BlueZ/HA-style dict that keeps every packet, keyed by its first 2 bytes
    def live(sec):
        p = bytearray(plain)
        p[15:17] = sec.to_bytes(2, "big")
        p[2] = bsd(p[3:])
        return encrypt(k, bytes(p)) + b"B1"

    md, seen = {}, set()
    for raw in (live(10), bytes(range(20)), live(20)):
        md[int.from_bytes(raw[:2], "little")] = raw[2:]
    assert newest_live(md, k, seen)["seconds"] == 20
    assert newest_live(md, k, seen) is None
    md[int.from_bytes(live(30)[:2], "little")] = live(30)[2:]
    assert newest_live(md, k, seen)["seconds"] == 30
    print("selftest ok")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("selftest")
    sub.add_parser("scan").add_argument("--key", help="pairing code; default: MAC-derived code")
    sub.add_parser("showkey").add_argument("address")
    h = sub.add_parser("history")
    h.add_argument("address")
    h.add_argument("--key", help="pairing code; default: MAC-derived code")
    h.add_argument("start", type=int)
    h.add_argument("end", type=int)
    a = ap.parse_args()
    try:
        match a.cmd:
            case "selftest": selftest()
            case "scan": asyncio.run(scan(a.key))
            case "showkey": asyncio.run(showkey(a.address))
            case "history": asyncio.run(history(a.address, a.key, a.start, a.end))
    except KeyboardInterrupt:
        pass
