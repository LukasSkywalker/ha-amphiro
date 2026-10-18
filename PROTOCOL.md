# amphiro b1 BLE protocol

Reverse-engineered from `amphiro b1 connect` 3.3.19 (Android). The app is Ionic/Cordova and
uses `cordova-plugin-ble-central`, so all of this logic is in `assets/www/build/main.js`.
These notes come from reading the code (static analysis). Everything except the study/config
commands has been confirmed on a real device: the MAC-derived code, show-key, live advertisements
and history download.

## Discovery

- New b1: advertised name `amphiro_b1` or `amphiro b1`.
- Old b1 (firmware 17.19): no name. Its 20-byte manufacturer data ends in `"B1"`.
- The manufacturer-specific AD structure (type `0xFF`) is one **encrypted 18/20-byte packet**. The 2 bytes
  that BLE stacks treat as the "company ID" are part of it (bleak: `cid.to_bytes(2, "little") + data`).
- Those first 2 bytes are ciphertext and change with every packet, so BlueZ treats each packet as a new
  "company" and keeps every one in `ManufacturerData`. Deduplicate by packet, not by device.
- The device appends `"B1"` to the 18 encrypted bytes. About 1 in 60 packets fails the checksum even
  with the right key. The app tolerates this: its pairing check needs only about ¼ of recent packets to decrypt.
- While water flows, advertisements carry **live** data (code `0x11`/`0x41`), so reading live data
  needs no connection. The device is powered by the water flow and is only active during a shower.

## GATT

| UUID | Purpose |
|---|---|
| `0D27FA90-F0D4-469D-AFD3-605A6EBBDB13` | Serial service |
| `0D27FB90-…` | tx: commands (write with response) |
| `0D27FB91-…` | rx: replies (notify) |
| `7F40A5B1-504F-4C41-5261-6D706869726F` / `7F40A501-…` | MAC address service / characteristic (read) |
| `180A` | Device Information (2A26 = firmware revision, etc.) |
| `7F40A1B1-50AF-4C41-5261-6D706869726F` | "Shower Service": `A110` volume [cl], `A111` temp [°C], `A112` duration [s], `A115` energy [10 Wh], `A116` flow [cl/min], `A117` shower ID. **The app never reads these.** They are only listed in a name table, so it's unknown whether they exist or are readable without encryption. |

## Packet format (18 bytes plaintext)

```
[0] function code   [1] status (TX: 0x01)   [2] checksum = bsd(bytes[3:18])
[3..17] payload, byte 17 is a random nonce in commands
```

`bsd` is the BSD checksum: `c = (rotr8(c, 1) + b) & 0xFF`.

### Encryption (AES-128-ECB, two overlapping blocks)

```
encrypt: A = AES(p[0:16]);           out = A[0:2] + AES(A[2:16] + p[16:18])
decrypt: A = AES⁻¹(c[2:18]);         p   = AES⁻¹(c[0:2] + A[0:14]) + A[14:16]
```

A packet is accepted only if the checksum matches, and that check is also how the app verifies a pairing code.

### Key derivation

Pairing code = 4 letters + 4 digits (`L0 L1 L2 L3 D4 D5 D6 D7`, e.g. `ABCD1234`):

```
r = L0 + 26·(L1 + 26·(L2 + 26·(L3 + 26·(D4 + 2·(D5 + 10·D6 + 100·D7)))))   (A=0, '0'=0)
key[0..3] = r little-endian;  key[i] = bsd(key[i-4..i-1]) for i = 4..15
```

- **Pairing mandatory** (status bit `0x04` clear): send the *unencrypted* packet `FF 01 77 B1×15` to
  tx. The device then shows its code on the display. The display drops leading `A`s and `0`s, so
  `AAAA0585` appears as `585`. The app pads the code back the same way.
- **Pairing not mandatory** (status bit `0x04` set): the code is `AAAA` + 4 digits derived from the MAC address
  (`n = (LE32(mac[2:6]) & 0x1FFFFFFF) // 26⁴`, digits `n%2, n/2%10, n/20%10, n/200%10`). Only 2000
  such codes exist.

## Messages

| Code | Dir | Meaning |
|---|---|---|
| `0x00` | ⇄ | Ping (`00 01 cs 00 00 00 00 01 …`). Reply has firmware = `[13].[15]` |
| `0x11`/`0x41` | ← (advert + notify) | Live: shower ID `BE16[3:5]`, volume `BE32[5:9]/10` L, energy `BE32[9:13]` Wh, temp `[13]` °C, flow `[14]/10` L/min, duration `BE16[15:17]` s. Firmware < 54.53 (unnamed b1) has no flow field, and duration is `BE24[14:17]` |
| `0x22` | → | History request: `BE16 start, BE16 end` at `[3:7]`. The device replies with one `0x12`/`0x42` per shower. The app requests at most 9 at a time from old b1s |
| `0x12`/`0x42` | ← | Stored shower: ID `BE16[3:5]`, volume `BE16[7:9]/10` L, temp `[9]`, cold water temp `[10]`, heating efficiency `[11]` (%), flow `[12]/10`, max break `[13]`. Bytes 5–6 are not parsed by the app and are always 0 on a real device, probably the top half of a 4-byte volume as in live packets. There's no duration field (≈ litres / flow). Replies come newest first. The in-progress shower comes back all zeros. Observed: cold water 12, efficiency 65, max break 120 on every shower, so these look like settings rather than measurements |
| `0x23` | → | Sent during setup. Reply `0x43` is not handled (meaning unknown) |
| `0x61` | → | Get study config (fw ≥ 54.54). Reply `0x62`: study `[3]`, group `[4]`, goal volume `[5]` |
| `0x60` / `0x33` | → | Set study config / set config1 (`[14]` = nBaselines) |
| `0xFF` | → | Show pairing code on display (unencrypted, see above) |

A pause shorter than max break (120 s) continues the same shower ID. The live `seconds` counter keeps
running through the pause (seen on the device: 182 → 292 s with no added volume).

The device keeps about 200 showers. When the app sees live shower ID N, it downloads IDs `max(1, N-220) … N-1`.
The app computes the energy of stored showers itself:
`litres · (temp − cold) · 4.182 · 0.2777 · 100 / efficiency / 1000` kWh.
