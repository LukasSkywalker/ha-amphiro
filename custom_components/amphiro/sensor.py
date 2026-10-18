from homeassistant.components.sensor import (
    RestoreSensor,
    SensorDeviceClass,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    UnitOfEnergy,
    UnitOfTemperature,
    UnitOfTime,
    UnitOfVolume,
    UnitOfVolumeFlowRate,
)
from homeassistant.core import callback
from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo

# Volume, energy and duration restart at 0 every shower: TOTAL_INCREASING makes
# Home Assistant add each shower to the long-term statistics (e.g. the water dashboard).
SENSORS = (
    SensorEntityDescription(
        key="litres", name="Volume", device_class=SensorDeviceClass.WATER,
        native_unit_of_measurement=UnitOfVolume.LITERS, state_class=SensorStateClass.TOTAL_INCREASING,
    ),
    SensorEntityDescription(
        key="energy_wh", name="Energy", device_class=SensorDeviceClass.ENERGY,
        native_unit_of_measurement=UnitOfEnergy.WATT_HOUR, state_class=SensorStateClass.TOTAL_INCREASING,
    ),
    SensorEntityDescription(
        key="seconds", name="Duration", device_class=SensorDeviceClass.DURATION,
        native_unit_of_measurement=UnitOfTime.SECONDS, state_class=SensorStateClass.TOTAL_INCREASING,
    ),
    SensorEntityDescription(
        key="temp_c", name="Temperature", device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS, state_class=SensorStateClass.MEASUREMENT,
    ),
    SensorEntityDescription(
        key="flow_lpm", name="Flow rate", device_class=SensorDeviceClass.VOLUME_FLOW_RATE,
        native_unit_of_measurement=UnitOfVolumeFlowRate.LITERS_PER_MINUTE,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    SensorEntityDescription(key="shower", name="Shower number", icon="mdi:shower-head"),
)


async def async_setup_entry(hass, entry, async_add_entities):
    async_add_entities(AmphiroSensor(entry.runtime_data, d) for d in SENSORS)


class AmphiroSensor(RestoreSensor):
    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, dev, description):
        self.entity_description = description
        self._dev = dev
        self._attr_unique_id = f"{dev.address}_{description.key}"
        self._attr_device_info = DeviceInfo(
            connections={(CONNECTION_BLUETOOTH, dev.address)}, name="amphiro b1", manufacturer="amphiro"
        )

    async def async_added_to_hass(self):
        await super().async_added_to_hass()
        # keep showing the last shower after a restart; the b1 is silent between showers
        if last := await self.async_get_last_sensor_data():
            self._attr_native_value = last.native_value
        self.async_on_remove(self._dev.add_listener(self._update))

    @callback
    def _update(self):
        self._attr_native_value = self._dev.data.get(self.entity_description.key)
        self.async_write_ha_state()
