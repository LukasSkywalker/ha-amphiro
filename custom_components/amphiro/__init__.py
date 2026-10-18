"""amphiro b1 shower meter: live data from its BLE advertisements."""

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, Platform
from homeassistant.core import HomeAssistant, callback

from .protocol import aes_key, newest_live

DOMAIN = "amphiro"
CONF_CODE = "code"


class Amphiro:
    """Decodes one b1's advertisements and tells the sensors."""

    def __init__(self, address, code):
        self.address = address
        self.key = aes_key(code)
        self.data = {}
        self._seen = set()
        self._listeners = []

    def add_listener(self, fn):
        self._listeners.append(fn)
        return lambda: self._listeners.remove(fn)

    @callback
    def on_advertisement(self, info, change):
        if live := newest_live(info.manufacturer_data, self.key, self._seen):
            self.data = live
            for fn in self._listeners:
                fn()

    @callback
    def on_unavailable(self, info):
        # The b1 is powered by the water flow: going silent means the shower is off.
        self._seen.clear()
        if self.data:
            self.data = {**self.data, "flow_lpm": 0.0}
            for fn in self._listeners:
                fn()


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    dev = entry.runtime_data = Amphiro(entry.data[CONF_ADDRESS], entry.data[CONF_CODE])
    entry.async_on_unload(
        bluetooth.async_register_callback(
            hass,
            dev.on_advertisement,
            bluetooth.BluetoothCallbackMatcher(address=dev.address, connectable=False),
            bluetooth.BluetoothScanningMode.PASSIVE,
        )
    )
    entry.async_on_unload(
        bluetooth.async_track_unavailable(hass, dev.on_unavailable, dev.address, connectable=False)
    )
    await hass.config_entries.async_forward_entry_setups(entry, [Platform.SENSOR])
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, [Platform.SENSOR])
