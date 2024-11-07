"""Nodbit integration."""

import voluptuous as vol

from homeassistant.core import HomeAssistant
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .const import NODBIT_DOMAIN

CONF_USER_ID = "user_id"
CONF_USER_PWD = "user_pwd"
CONF_KEY = "key"

CONFIG_SCHEMA = vol.Schema(
    {
        vol.Optional(NODBIT_DOMAIN): vol.Schema(
            {
                vol.Required(CONF_USER_ID): cv.string,
                vol.Required(CONF_USER_PWD): cv.string,
                vol.Required(CONF_KEY): cv.string,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the Twilio component."""

    if NODBIT_DOMAIN not in config:
        return True

    conf = config[NODBIT_DOMAIN]
    hass.data[NODBIT_DOMAIN] = {
        "user_id": conf.get(CONF_USER_ID),
        "user_pwd": conf.get(CONF_USER_PWD),
        "key": conf.get(CONF_KEY),
    }
    return True
