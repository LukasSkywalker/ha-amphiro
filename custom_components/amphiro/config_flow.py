import voluptuous as vol

from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
    async_last_service_info,
)
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_ADDRESS

from . import CONF_CODE, DOMAIN
from .protocol import B1_NAMES, LIVE, aes_key, decrypt, mac_code, packets


def _is_b1(info):
    named = (info.name or "").lower() in B1_NAMES
    return named or any(r[18:20] == b"B1" for r in packets(info.manufacturer_data))


class AmphiroConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1
    _address: str

    async def async_step_bluetooth(self, discovery_info: BluetoothServiceInfoBleak) -> ConfigFlowResult:
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        self._address = discovery_info.address
        return await self.async_step_confirm()

    async def async_step_user(self, user_input=None) -> ConfigFlowResult:
        if user_input is not None:
            self._address = user_input[CONF_ADDRESS]
            await self.async_set_unique_id(self._address)
            self._abort_if_unique_id_configured()
            return await self.async_step_confirm()
        configured = self._async_current_ids()
        found = {
            i.address: f"{i.name} ({i.address})"
            for i in async_discovered_service_info(self.hass, connectable=False)
            if i.address not in configured and _is_b1(i)
        }
        if not found:
            return self.async_abort(reason="no_devices_found")
        return self.async_show_form(step_id="user", data_schema=vol.Schema({vol.Required(CONF_ADDRESS): vol.In(found)}))

    async def async_step_confirm(self, user_input=None) -> ConfigFlowResult:
        errors = {}
        if user_input is not None:
            try:
                key = aes_key(user_input[CONF_CODE])
            except ValueError:
                errors[CONF_CODE] = "invalid_code"
            else:
                # The newest advertisements prove the code: at least one must decrypt to live data.
                info = async_last_service_info(self.hass, self._address, connectable=False)
                if info and any((p := decrypt(key, r)) and p[0] in LIVE for r in packets(info.manufacturer_data)):
                    return self.async_create_entry(
                        title=f"amphiro b1 {self._address}",
                        data={CONF_ADDRESS: self._address, CONF_CODE: user_input[CONF_CODE]},
                    )
                errors[CONF_CODE] = "wrong_code"
        return self.async_show_form(
            step_id="confirm",
            data_schema=vol.Schema({vol.Required(CONF_CODE, default=mac_code(self._address)): str}),
            description_placeholders={"address": self._address},
            errors=errors,
        )
