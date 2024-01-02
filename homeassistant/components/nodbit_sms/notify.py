"""Nodbit SMS service for notify component."""
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

BASE_URL = "https://alerts.nodbit.com"
TIMEOUT = 10

HEADERS = {"Content-Type": CONTENT_TYPE_JSON}


def get_service(
    hass: HomeAssistant,
    config: ConfigType,
    discovery_info: DiscoveryInfoType | None = None,
) -> NodbitSMSNotificationService:
    """Get the Nodbit SMS notification service."""
    return NodbitSMSNotificationService(hass.data[DATA_NODBIT], "sms")


class NodbitSMSNotificationService(BaseNotificationService):
    """Implement the notification service for Nodbit SMS service."""

    def __init__(self, nodbit_client, alert_type) -> None:
        """Initialize the service."""
        self.client = nodbit_client
        self.alert_type = alert_type

    def send_message(self, message: str = "", **kwargs: Any) -> None:
        """Send SMS to specified target user cell."""
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

        if resp.status_code == HTTPStatus.OK:
            return

        obj = json.loads(resp.text)
        response_msg = obj.get("response_msg")
        response_code = obj.get("response_code")
        _LOGGER.error(
            "Error %s : %s (Code %s)", resp.status_code, response_msg, response_code
        )
