"""Nodbit Call service for notify component."""

from __future__ import annotations

import inspect
import json
import logging
import re
import types
from typing import Any, cast

from aiohttp import ClientError, ClientTimeout

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

    @auth.retry_with_backoff_decorator(max_tries=4, base=2, factor=1)
    async def _send_notification(self, headers: dict, data: dict) -> None:
        """Send an HTTP POST request to the Nodbit API with retry logic.

        This function sends a notification request to the Nodbit API. It uses a retry
        mechanism with exponential backoff to handle transient network errors or
        temporary API unavailability. The maximum number of attempts, backoff base,
        and scaling factor are configurable in the applied decorator.

        Args:
            headers (dict): HTTP headers for the request, including authorization.
            data (dict): JSON payload containing notification details.

        Raises:
            ConnectionError: If all retry attempts fail or the server responds with
                a non-200 HTTP status code.

        """

        func_name = cast(types.FrameType, inspect.currentframe()).f_code.co_name
        try:
            async with self.session.post(
                SVC_URL, headers=headers, json=data, timeout=timeout
            ) as resp:
                response_text = await resp.text()

                if resp.status != 200:
                    _LOGGER.error(
                        "Task: %s - HTTP %s %s - %s",
                        func_name,
                        str(resp.status),
                        str(resp.reason),
                        response_text,
                    )

                    await self.hass.services.async_call(
                        "persistent_notification",
                        "create",
                        {
                            "message": "Cannot place call. Check system logs for more details",
                            "title": "Nodbit notification",
                        },
                    )

                    raise ConnectionError

                obj = json.loads(response_text)
                _LOGGER.info(msg=obj)
        except (ClientError, TimeoutError) as e:
            _LOGGER.error("Task: %s - Cannot connect to server", func_name)
            raise ConnectionError from e

    async def async_send_message(self, message: str = "", **kwargs: Any) -> None:
        """Place a call to specified target users.

        This function sends a message to the specified target users using the Nodbit API.
        It retrieves a valid ID token for authentication, constructs the required HTTP headers
        and payload, and delegates the actual notification sending to `_send_notification`.

        Args:
            message (str): The message content to be played in the call.
            **kwargs (Any): Additional arguments, including:
                - ATTR_TARGET: List of phone numbers that will receive the notification.

        Raises:
            HomeAssistantError: If the `ATTR_TARGET` argument is missing or empty.
            ConnectionError: If the `_send_notification` function encounters issues
                with the API or network.

        """
        if not (targets_raw := kwargs.get(ATTR_TARGET)):
            raise HomeAssistantError(
                translation_domain=NODBIT_DOMAIN,
                translation_key="missing_field",
                translation_placeholders={"field": ATTR_TARGET},
            )

        targets = []
        for target in targets_raw:
            # Split numbers using comma as separator
            numbers = target.split(",")
            for num in numbers:
                num = num.strip()  # Remove spaces
                if not re.fullmatch(r"\d+", num):
                    raise HomeAssistantError(
                        translation_domain=NODBIT_DOMAIN,
                        translation_key="invalid_targets",
                        translation_placeholders={"field": ATTR_TARGET},
                    )

                targets.append(num)

        id_token = await auth.get_id_token(
            self.user_id, self.user_pwd, self.key, self.session, self.store, self.hass
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

        try:
            await self._send_notification(headers, data)
        except (ConnectionError, TimeoutError):
            # All retry attempts failed
            await self.hass.services.async_call(
                "persistent_notification",
                "create",
                {
                    "message": "Cannot connect to server after multiple attempts. Check system logs for more details.",
                    "title": NODBIT_DOMAIN.capitalize() + " " +"notification",
                },
            )
            raise
