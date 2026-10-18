# amphiro b1 for Home Assistant

Live shower data from an [amphiro b1](https://amphiro.com) water meter, now that the official app is gone.
The b1 broadcasts encrypted live data over Bluetooth while water flows. This integration decrypts it,
so it works through any Home Assistant Bluetooth adapter or ESPHome Bluetooth proxy, without connecting.

## Install

1. HACS → ⋮ → Custom repositories → add this repository as an *Integration*, then install **amphiro b1**.
2. Restart Home Assistant.
3. Turn the shower on. The b1 is powered by the water flow and is silent otherwise. Home Assistant
   should discover it. If it doesn't, go to Settings → Devices & services → Add integration → amphiro b1.
4. Confirm the pairing code. The default is derived from the MAC address and works if the b1 doesn't
   require pairing. Keep the water running so the code can be checked.

If the default code is rejected, `uv run amphiro.py showkey <address>` makes the b1 show its code on
the display. Digits only, e.g. `585`, are fine.

## Sensors

| Sensor | Notes |
|---|---|
| Volume (L), Energy (Wh), Duration (s) | Current/last shower. These restart at 0 each shower and are `total_increasing`, so the water dashboard and statistics add up all showers |
| Temperature (°C), Flow rate (L/min) | Flow drops to 0 when the b1 goes silent |
| Shower number | The b1's shower counter |

A pause shorter than 2 minutes continues the same shower.

## Also in this repo

- `PROTOCOL.md`: the reverse-engineered BLE protocol (encryption, key derivation, messages).
- `amphiro.py`: command-line tool to scan live data, show the pairing code and download the
  last ~200 showers (`uv run amphiro.py --help`).
