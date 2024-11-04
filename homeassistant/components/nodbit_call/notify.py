"""Nodbit Call service for notify component."""

from __future__ import annotations

import json
import logging
from typing import Any

from aiohttp import ClientTimeout

import homeassistant.components.nodbit
from homeassistant.components.nodbit import auth
from homeassistant.components.notify import ATTR_TARGET, BaseNotificationService
from homeassistant.const import CONTENT_TYPE_JSON
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.storage import Store
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType

_LOGGER = logging.getLogger(__name__)


HTTP_TIMEOUT = homeassistant.components.nodbit.const.HTTP_TIMEOUT
timeout = ClientTimeout(total=HTTP_TIMEOUT)
NODBIT_DOMAIN = homeassistant.components.nodbit.const.NODBIT_DOMAIN
SVC_URL = homeassistant.components.nodbit.const.SVC_URL
STORAGE_KEY = homeassistant.components.nodbit.const.STORAGE_KEY
STORAGE_VERSION = homeassistant.components.nodbit.const.STORAGE_VERSION


def get_service(
    hass: HomeAssistant,
    config: ConfigType,
    discovery_info: DiscoveryInfoType | None = None,
) -> NodbitCallNotificationService:
    """Get the Nodbit Call notification service."""
    return NodbitCallNotificationService(hass, hass.data[NODBIT_DOMAIN], "call")


class NodbitCallNotificationService(BaseNotificationService):
    """Implement the notification service for Nodbit Call service."""

    def __init__(self, hass: HomeAssistant, nodbit_data, alert_type) -> None:
        """Initialize the service."""

        self.user_id = nodbit_data.get("user_id")
        self.user_pwd = nodbit_data.get("user_pwd")
        self.key = nodbit_data.get("key")
        self.alert_type = alert_type
        self.session = async_get_clientsession(hass)
        self.store: Store = Store(hass, version=STORAGE_VERSION, key=STORAGE_KEY)

    async def async_send_message(self, message: str = "", **kwargs: Any) -> None:
        """Call to specified target users."""

        if not (targets := kwargs.get(ATTR_TARGET)):
            raise HomeAssistantError(
                translation_domain=NODBIT_DOMAIN,
                translation_key="missing_field",
                translation_placeholders={"field": ATTR_TARGET},
            )

        id_token = await auth.get_id_token(
            self.user_id, self.user_pwd, self.key, self.session, self.store
        )

        headers = {
            "Content-Type": CONTENT_TYPE_JSON,
            "Authorization": f"Bearer {id_token}",
        }

        data = {
            "alert_type": self.alert_type,
            "message": message,
            "targets": targets,
        }

        async with self.session.post(
            SVC_URL, headers=headers, json=data, timeout=timeout
        ) as resp:
            resp.raise_for_status()
            response_text = await resp.text()
            obj = json.loads(response_text)
            _LOGGER.info(msg=obj)
