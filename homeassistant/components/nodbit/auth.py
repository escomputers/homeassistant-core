"""Authentication for Nodbit Integration.

This module handles the authentication required to interact with the Nodbit API.
It provides functions for logging, refreshing tokens, managing token caching,
and ensuring reliable authentication during API calls. Key functionalities include:

- `login`: Authenticate with the Nodbit API and retrieve ID and Refresh tokens.
  This function is wrapped with a retry mechanism featuring exponential backoff
  to handle transient network errors or API unavailability.

- `refresh_id_token`: Refresh the ID token using the Refresh token.
  This function also uses a retry mechanism with exponential backoff to ensure
  reliability during network disruptions.

- `get_id_token`: Retrieve a valid ID token, refreshing or re-authenticating if necessary.
  It uses `login` and `refresh_id_token` internally, benefiting from their retry mechanism.

- `retry_with_backoff_decorator`: A generic decorator that retries a coroutine
  multiple times with an exponential backoff delay. This is used to wrap functions
  like `login` and `refresh_id_token` to improve resilience against temporary failures.
  The backoff mechanism includes configurable parameters:

  - **Maximum Attempts (`max_tries`)**: Specifies the total number of attempts, including the
    initial call and retries.
    For example, `max_tries=4` means one initial attempt and up to three retries.
  - **Base Multiplier (`base`)**: Defines the base for the exponential backoff calculation.
    The delay for the `n`-th retry is calculated as `base^n`, scaled by the factor.
  - **Scaling Factor (`factor`)**: Multiplies the calculated backoff delay to control
    the total delay duration. For example, a factor of `2` doubles the delay for each retry.
  - **Random Jitter**: Adds a small, random value to the backoff delay to prevent multiple
    instances from retrying at the exact same intervals.
    The jitter is implemented as a random value uniformly distributed between `0` and `1`.

  **Example Calculation**:
  Suppose the following parameters are used:
  - `max_tries=4`
  - `base=2`
  - `factor=1`

  The retry mechanism would behave as follows:
  - **Attempt 1**: No delay (initial call).
  - **Attempt 2**: Delay = `factor * (base^1)` = `1 * 2` = 2 seconds (+ jitter).
  - **Attempt 3**: Delay = `factor * (base^2)` = `1 * 4` = 4 seconds (+ jitter).
  - **Attempt 4**: Delay = `factor * (base^3)` = `1 * 8` = 8 seconds (+ jitter).

  Total delay (without jitter) = 2 + 4 + 8 = ~ 14 seconds.

  With jitter, the total delay will vary slightly, but the intervals between retries
  will remain approximately exponential.
  This ensures a balance between responsiveness and resilience in handling temporary failures.
"""

import asyncio
from collections.abc import Callable, Coroutine
import inspect
import json
import logging
import random
import time
import types
from typing import Any, TypeVar, cast

from aiohttp import ClientError, ClientSession, ClientTimeout

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .const import (
    AUTH_DOMAIN,
    HEADERS,
    HTTP_TIMEOUT,
    ID,
    IDTOKEN_LIFETIME,
    REFRESHTOKEN_LIFETIME,
)

_LOGGER = logging.getLogger(__name__)
timeout = ClientTimeout(total=HTTP_TIMEOUT)

# Creates a generic type T
T = TypeVar("T")


def retry_with_backoff_decorator(
    max_tries: int = 4,
    base: int = 2,
    factor: int = 1,
) -> Callable[
    [Callable[..., Coroutine[Any, Any, T]]], Callable[..., Coroutine[Any, Any, T]]
]:
    """Create a decorator to retry a coroutine with exponential backoff.

    Args:
        max_tries (int): Maximum number of attempts.
        base (int): Base multiplier for the backoff.
        factor (int): Factor for scaling the backoff.

    Returns:
        A decorator that retries the coroutine.

    """

    def decorator(
        coro: Callable[..., Coroutine[Any, Any, T]],
    ) -> Callable[..., Coroutine[Any, Any, T]]:
        async def wrapper(*args, **kwargs):
            for attempt in range(1, max_tries + 1):
                try:
                    return await coro(*args, **kwargs)
                except Exception as e:
                    if attempt == max_tries:
                        _LOGGER.error("Max retries reached for %s", coro.__name__)
                        raise
                    wait_time = factor * base**attempt + random.uniform(
                        0, 1
                    )  # Full jitter

                    # Try to extract a readable error message from the exception.
                    # If str(e) is empty or only whitespace (common with some exceptions),
                    # use repr(e) to ensure the log contains useful debugging information.
                    error_message = str(e) if str(e).strip() else repr(e)
                    _LOGGER.warning(
                        "Attempt %d for %s failed with error: %s. Retrying in %.2f seconds",
                        attempt,
                        coro.__name__,
                        error_message,
                        wait_time,
                    )
                    await asyncio.sleep(wait_time)
            # Explicit return to clarify intent;
            # ensures all code paths have a return value
            # even though this line is unreachable in the current implementation.
            return None

        return wrapper

    return decorator


@retry_with_backoff_decorator(max_tries=4, base=2, factor=1)
async def refresh_id_token(
    refresh_tok: str,
    secret_hash: str,
    async_session: ClientSession,
    hass_obj: HomeAssistant,
) -> tuple[str, float]:
    """Refresh the ID token using the provided Refresh token.

    This function interacts with the Nodbit API to obtain a new ID token when the
    current one has expired. It uses a retry mechanism with exponential backoff to
    handle transient network errors or API unavailability.

    Args:
        refresh_tok (str): The Refresh token retrieved during login.
        secret_hash (str): Client-specific secret hash for authentication.
        async_session (ClientSession): The session for making HTTP requests.
        hass_obj (HomeAssistant): HomeAssistant core object for sending persistent notifications.

    Returns:
        tuple[str, float]: A tuple containing:
            - The new ID token (str).
            - Its expiration time as a Unix epoch timestamp (float).

    Raises:
        ConnectionError: If all retry attempts fail, the server is unreachable, or
            the server responds with a non-200 HTTP status code.
        ValueError: If the response from the API does not contain valid token data.
        ClientError: If there is a problem with the HTTP session, such as invalid headers
            or other client-side issues.

    """

    _LOGGER.info("Refreshing ID token")
    func_name = cast(types.FrameType, inspect.currentframe()).f_code.co_name

    refresh_payload = {
        "AuthFlow": "REFRESH_TOKEN_AUTH",
        "ClientId": ID,
        "AuthParameters": {
            "REFRESH_TOKEN": refresh_tok,
            "SECRET_HASH": secret_hash,
        },
    }

    try:
        async with async_session.post(
            AUTH_DOMAIN,
            headers=HEADERS,
            json=refresh_payload,
            timeout=timeout,
        ) as response:
            response_text = await response.text()

            if response.status != 200:
                _LOGGER.error(
                    "Task: %s - HTTP %s %s - %s",
                    func_name,
                    str(response.status),
                    str(response.reason),
                    response_text,
                )

                # Send a persistent notification whenever a critical error occurs
                await hass_obj.services.async_call(
                    "persistent_notification",
                    "create",
                    {
                        "message": "Cannot refresh credentials. Check system logs for more details",
                        "title": "Nodbit notification",
                    },
                )

                raise ConnectionError

            obj = json.loads(response_text)

            id_tok = obj["AuthenticationResult"]["IdToken"]
            new_id_token_expiry_time = time.time() + IDTOKEN_LIFETIME

            _LOGGER.info("ID token successfully refreshed")
    except (ClientError, TimeoutError) as e:
        _LOGGER.error("Task: %s - Cannot connect to server", func_name)
        raise ConnectionError from e

    return id_tok, new_id_token_expiry_time


@retry_with_backoff_decorator(max_tries=5, base=2, factor=1)
async def login(
    user_id: str,
    user_pass: str,
    secret_hash: str,
    async_session: ClientSession,
    store_obj: Store,
    hass_obj: HomeAssistant,
) -> dict[str, tuple[str, float]]:
    """Authenticate with Nodbit API to retrieve new tokens.

    This function sends the user's credentials to the Nodbit API to authenticate
    and retrieve an ID token and a Refresh token, along with their expiration times.
    It uses a retry mechanism with exponential backoff to handle transient network
    errors or API unavailability.

    Args:
        user_id (str): User's login ID.
        user_pass (str): User's password.
        secret_hash (str): Client-specific secret hash for authentication.
        async_session (ClientSession): The session for making HTTP requests.
        store_obj (Store): Persistent storage object for caching tokens.
        hass_obj (HomeAssistant): HomeAssistant core object for sending persistent notifications.

    Returns:
        dict[str, tuple[str, float]]: A dictionary containing:
            - "id_token": A tuple with the ID token and its expiration time (unix epoch).
            - "refresh_token": A tuple with the Refresh token and its expiration time (unix epoch).

    Raises:
        ConnectionError: If all retry attempts fail, the server is unreachable, or
            the server responds with a non-200 HTTP status code.
        ClientError: If there is a problem with the HTTP session, such as invalid headers
            or other client-side issues.
        ValueError: If the response from the API does not contain valid authentication data.

    """

    _LOGGER.info("Trying to log in")
    func_name = cast(types.FrameType, inspect.currentframe()).f_code.co_name

    login_payload = {
        "AuthFlow": "USER_PASSWORD_AUTH",
        "ClientId": ID,
        "AuthParameters": {
            "USERNAME": user_id,
            "PASSWORD": user_pass,
            "SECRET_HASH": secret_hash,
        },
    }

    try:
        async with async_session.post(
            AUTH_DOMAIN,
            headers=HEADERS,
            json=login_payload,
            timeout=timeout,
        ) as response:
            response_text = await response.text()

            if response.status != 200:
                _LOGGER.error(
                    "Task: %s - HTTP %s %s - %s",
                    func_name,
                    str(response.status),
                    str(response.reason),
                    response_text,
                )

                # Send a persistent notification whenever a critical error occurs
                await hass_obj.services.async_call(
                    "persistent_notification",
                    "create",
                    {
                        "message": "Cannot login. Check system logs for more details",
                        "title": "Nodbit notification",
                    },
                )

                raise ConnectionError

            obj = json.loads(response_text)

        id_tok = obj["AuthenticationResult"]["IdToken"]
        refresh_tok = obj["AuthenticationResult"]["RefreshToken"]

        id_token_expiry_time = time.time() + IDTOKEN_LIFETIME
        refresh_token_expiry_time = time.time() + REFRESHTOKEN_LIFETIME

        auth_data = {
            "id_token": (id_tok, id_token_expiry_time),
            "refresh_token": (refresh_tok, refresh_token_expiry_time),
        }

        # Save tokens to persistent storage for reuse
        await store_obj.async_save(auth_data)

        _LOGGER.info("Login successful. Tokens cached")
    except (ClientError, TimeoutError) as e:
        _LOGGER.error("Task: %s - Cannot connect to server", func_name)
        raise ConnectionError from e

    return auth_data


async def get_id_token(
    usr_id: str,
    usr_pwd: str,
    scr_hash: str,
    session: ClientSession,
    store: Store,
    hass: HomeAssistant,
) -> str:
    """Retrieve a valid ID token, refreshing or re-authenticating if necessary.

    This function retrieves a valid ID token by either loading it from the cache,
    refreshing it using a refresh token, or performing a new login if necessary.
    It handles token expiration and ensures that a valid token is always returned.

    Args:
        usr_id (str): User's login ID.
        usr_pwd (str): User's password.
        scr_hash (str): Client-specific secret hash for authentication.
        session (ClientSession): The session for making HTTP requests.
        store (Store): Persistent storage object for caching tokens.
        hass (HomeAssistant): HomeAssistant core object for sending persistent notifications.

    Returns:
        str: A valid ID token for authentication with Nodbit Notification API.

    Raises:
        ValueError: If the ID token cannot be retrieved after login or token refresh.
        ConnectionError: If the server cannot be reached during login or token refresh.
        Exception: For any unexpected errors during the authentication process.

    """

    # Load cached tokens
    existing_auth_data = await store.async_load()

    if existing_auth_data is None:
        # No cached data. Perform login
        _LOGGER.info("No cache found, trying to login")
        try:
            auth_data = await login(usr_id, usr_pwd, scr_hash, session, store, hass)
        except (ClientError, TimeoutError):
            # Send a persistent notification whenever a critical error occurs
            await hass.services.async_call(
                "persistent_notification",
                "create",
                {
                    "message": "Cannot connect to server. Check system logs for more details",
                    "title": "Nodbit notification",
                },
            )
            raise

        id_token_data = auth_data.get("id_token")
        if id_token_data is not None:
            id_token, _ = id_token_data
        else:
            # ID token key exists, but its value is None
            _LOGGER.error("Cannot get ID token after login")
            raise ValueError
    else:
        # Cache exists. Check token expiration
        _LOGGER.info("Cache found, validating tokens")
        id_token, id_token_expiration = existing_auth_data.get("id_token")
        refresh_token, refresh_token_expiration = existing_auth_data.get(
            "refresh_token"
        )

        current_time = time.time()
        # Check if ID token has expired
        # Subtract 600 seconds (10 minutes) to create a buffer for ID token expiration.
        # This ensures ID token is refreshed slightly before it actually expires,
        # preventing potential failures due to slight clock differences or delays in refreshing.
        if current_time >= id_token_expiration - 600:
            # ID token expired. Check Refresh token
            if current_time >= refresh_token_expiration:
                _LOGGER.info("Both tokens expired. Re-authenticating")
                try:
                    auth_data = await login(
                        usr_id, usr_pwd, scr_hash, session, store, hass
                    )
                except (ClientError, TimeoutError):
                    # Send a persistent notification whenever a critical error occurs
                    await hass.services.async_call(
                        "persistent_notification",
                        "create",
                        {
                            "message": "Cannot connect to server. Check system logs for more details",
                            "title": "Nodbit notification",
                        },
                    )
                    raise

                id_token_data = auth_data.get("id_token")
                if id_token_data is not None:
                    id_token, _ = id_token_data
                else:
                    # ID token key exists, but its value is None
                    _LOGGER.error("Cannot get ID token after login")
                    raise ValueError
            # ID token expired, but Refresh token is valid
            else:
                _LOGGER.info("ID token is not valid. Refreshing using Refresh token")
                try:
                    id_token, new_id_token_expiration = await refresh_id_token(
                        refresh_token, scr_hash, session, hass
                    )
                except (ClientError, TimeoutError):
                    # Send a persistent notification whenever a critical error occurs
                    await hass.services.async_call(
                        "persistent_notification",
                        "create",
                        {
                            "message": "Cannot connect to server. Check system logs for more details",
                            "title": "Nodbit notification",
                        },
                    )
                    raise

                # Update cached values
                existing_auth_data["id_token"] = id_token, new_id_token_expiration

                await store.async_save(existing_auth_data)
                _LOGGER.info("Cache updated")

    _LOGGER.info("Valid ID token retrieved successfully")
    return id_token
