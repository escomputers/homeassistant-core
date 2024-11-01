"""Nodbit Call service for notify component."""

from __future__ import annotations

from http import HTTPStatus
import json
import logging
from typing import Any

import requests

from homeassistant.components.nodbit import auth, const
from homeassistant.components.notify import ATTR_TARGET, BaseNotificationService
from homeassistant.const import CONTENT_TYPE_JSON
from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType

_LOGGER = logging.getLogger(__name__)


HTTP_TIMEOUT = const.HTTP_TIMEOUT
NODBIT_DOMAIN = const.NODBIT_DOMAIN
SVC_URL = const.SVC_URL


def get_service(
    hass: HomeAssistant,
    config: ConfigType,
    discovery_info: DiscoveryInfoType | None = None,
) -> NodbitCallNotificationService:
    """Get the Nodbit Call notification service."""
    return NodbitCallNotificationService(hass.data[NODBIT_DOMAIN], "call")


class NodbitCallNotificationService(BaseNotificationService):
    """Implement the notification service for Nodbit Call service."""

    def __init__(self, data, alert_type) -> None:
        """Initialize the service."""
        self.user_id = data["user_id"]
        self.user_pwd = data["user_pwd"]
        self.key = data["key"]
        self.alert_type = alert_type

    def send_message(self, message: str = "", **kwargs: Any) -> None:
        """Call to specified target users."""
        if not (targets := kwargs.get(ATTR_TARGET)):
            _LOGGER.info("At least 1 target is required")
            return

        # id_token = auth.get_id_token(self.user_id, self.user_pwd, self.key)
        id_token = auth.get_id_token()

        headers = {
            "Content-Type": CONTENT_TYPE_JSON,
            "Authorization": f"Bearer {id_token}",
        }

        data = {
            "alert_type": self.alert_type,
            "message": message,
            "targets": targets,
        }

        resp = requests.post(
            SVC_URL, headers=headers, json=json.dumps(data), timeout=HTTP_TIMEOUT
        )

        obj = json.loads(resp.text)

        response_code = obj.get("statusCode")
        response_body = obj.get("body")

        if response_code == HTTPStatus.OK:
            _LOGGER.info(msg=response_body)
            return

        _LOGGER.error("Error Code %s: %s", response_code, response_body)
