"""Nodbit Call service for notify component."""
from __future__ import annotations

from http import HTTPStatus
import json
import logging
from typing import Any

import requests

from homeassistant.components.nodbit import DATA_NODBIT
from homeassistant.components.notify import ATTR_TARGET, BaseNotificationService
from homeassistant.const import CONTENT_TYPE_JSON
from homeassistant.core import HomeAssistant
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType

_LOGGER = logging.getLogger(__name__)

BASE_URL = f"https://api.{DATA_NODBIT}.com/v1/alerts"
TIMEOUT = 10
HEADERS = {"Content-Type": CONTENT_TYPE_JSON}


def get_service(
    hass: HomeAssistant,
    config: ConfigType,
    discovery_info: DiscoveryInfoType | None = None,
) -> NodbitCallNotificationService:
    """Get the Nodbit Call notification service."""
    return NodbitCallNotificationService(hass.data[DATA_NODBIT], "call")


class NodbitCallNotificationService(BaseNotificationService):
    """Implement the notification service for Nodbit Call service."""

    def __init__(self, nodbit_client, alert_type) -> None:
        """Initialize the service."""
        self.client = nodbit_client
        self.alert_type = alert_type

    def send_message(self, message: str = "", **kwargs: Any) -> None:
        """Call to specified target users."""
        if not (targets := kwargs.get(ATTR_TARGET)):
            _LOGGER.info("At least 1 target is required")
            return

        data = {
            "auth_data": self.client,
            "alert_type": self.alert_type,
            "message": message,
            "targets": targets,
        }

        resp = requests.post(
            BASE_URL,
            data=json.dumps(data),
            headers=HEADERS,
            timeout=TIMEOUT,
        )

        obj = json.loads(resp.text)

        response_code = obj.get("statusCode")
        response_body = obj.get("body")

        if response_code == HTTPStatus.OK:
            _LOGGER.info(msg=response_body)
            return

        _LOGGER.error("Error Code %s: %s", response_code, response_body)
