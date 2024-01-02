"""Nodbit integration."""
import voluptuous as vol

from homeassistant.core import HomeAssistant
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .const import DOMAIN

CONF_USER_ID = "user_id"
CONF_AUTH_TOKEN = "auth_token"

DATA_NODBIT = DOMAIN

CONFIG_SCHEMA = vol.Schema(
    {
        vol.Optional(DOMAIN): vol.Schema(
            {
                vol.Required(CONF_USER_ID): cv.string,
                vol.Required(CONF_AUTH_TOKEN): cv.string,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the Twilio component."""
    if DOMAIN not in config:
        return True

    conf = config[DOMAIN]
    hass.data[DATA_NODBIT] = {
        "user_id": conf.get(CONF_USER_ID),
        "auth_token": conf.get(CONF_AUTH_TOKEN),
    }
    return True
