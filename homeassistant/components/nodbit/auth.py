"""Authentication for Nodbit Integration.

This module handles the authentication required to interact with Nodbit API.
It provides functions for logging, refreshing tokens and managing token caching
to ensure valid authentication during API calls. Key functionalities include:

- `login`: Authenticate with the Nodbit API and retrieve ID and Refresh tokens.
- `refresh_id_token`: Refresh the ID token using the Refresh token.
- `get_id_token`: Retrieve a valid ID token, refreshing or re-authenticating if necessary.
"""

import inspect
import json
import logging
import time
import types
from typing import cast

from aiohttp import ClientSession, ClientTimeout

# import backoff
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.storage import Store

from .const import (
    AUTH_DOMAIN,
    HEADERS,
    HTTP_TIMEOUT,
    ID,
    IDTOKEN_LIFETIME,
    NODBIT_DOMAIN,
    REFRESHTOKEN_LIFETIME,
)

_LOGGER = logging.getLogger(__name__)
timeout = ClientTimeout(total=HTTP_TIMEOUT)


async def refresh_id_token(
    refresh_tok: str, secret_hash: str, async_session: ClientSession
) -> tuple[str, float]:
    """Refresh ID token using the Refresh token.

    Args:
        refresh_tok (str): The refresh token retrieved during login.
        secret_hash (str): Client-specific secret hash for authentication.
        async_session (ClientSession): The session for making HTTP requests.

    Returns:
        tuple[str, float]: The new ID token and its expiration time (unix epoch).

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

    async with async_session.post(
        AUTH_DOMAIN,
        headers=HEADERS,
        json=refresh_payload,
        timeout=timeout,
    ) as response:
        if response.status != 200:
            raise HomeAssistantError(
                translation_domain=NODBIT_DOMAIN,
                translation_key="http_response_error",
                translation_placeholders={
                    "task": func_name,
                    "status_code": str(response.status),
                    "response_reason": str(response.reason),
                    "response_body": await response.text(),
                },
            )

        response_text = await response.text()
        obj = json.loads(response_text)

        id_tok = obj["AuthenticationResult"]["IdToken"]
        new_id_token_expiry_time = time.time() + IDTOKEN_LIFETIME

        _LOGGER.info("ID token successfully refreshed")
        return id_tok, new_id_token_expiry_time


# @backoff.on_exception(
#     backoff.expo,  # Backoff esponenziale
#     max_tries=4,  # Numero massimo di tentativi
#     base=2,
#     factor=1,
#     jitter=backoff.full_jitter,  # Aggiunge variazione casuale al backoff
# )
async def login(
    user_id: str,
    user_pass: str,
    secret_hash: str,
    async_session: ClientSession,
    store_obj: Store,
) -> dict[str, tuple[str, float]]:
    """Authenticate with Nodbit API to retrieve new tokens.

    Args:
        user_id (str): User's login ID.
        user_pass (str): User's password.
        secret_hash (str): Client-specific secret hash for authentication.
        async_session (ClientSession): The session for making HTTP requests.
        store_obj (Store): Persistent storage object for caching tokens.

    Returns:
        dict[str, tuple[str, float]]: ID and Refresh tokens with their expiration times (unix epoch).

    """

    _LOGGER.info("Starting login process")
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

    async with async_session.post(
        AUTH_DOMAIN,
        headers=HEADERS,
        json=login_payload,
        timeout=timeout,
    ) as response:
        if response.status != 200:
            raise HomeAssistantError(
                translation_domain=NODBIT_DOMAIN,
                translation_key="http_response_error",
                translation_placeholders={
                    "task": func_name,
                    "status_code": str(response.status),
                    "response_reason": str(response.reason),
                    "response_body": await response.text(),
                },
            )

        response_text = await response.text()
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
    return auth_data


async def get_id_token(
    usr_id: str, usr_pwd: str, scr_hash: str, session: ClientSession, store: Store
) -> str:
    """Retrieve a valid ID token, refreshing or re-authenticating if necessary.

    Args:
        usr_id (str): User's login ID.
        usr_pwd (str): User's password.
        scr_hash (str): Client-specific secret hash for authentication.
        session (ClientSession): The session for making HTTP requests.
        store (Store): Persistent storage object for caching tokens.

    Returns:
        str: A valid ID token for authentication with Nodbit Notification API.

    """
    _LOGGER.info("Starting ID token retrieval")

    # Load cached tokens
    existing_auth_data = await store.async_load()

    if existing_auth_data is None:
        # No cached data. Perform login
        _LOGGER.info("No cache found, performing login")
        auth_data = await login(usr_id, usr_pwd, scr_hash, session, store)

        id_token_data = auth_data.get("id_token")
        if id_token_data is not None:
            id_token, _ = id_token_data
        else:
            # ID token key exists, but its value is None
            raise HomeAssistantError(
                translation_domain=NODBIT_DOMAIN, translation_key="no_token_after_login"
            )
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
                auth_data = await login(usr_id, usr_pwd, scr_hash, session, store)

                id_token_data = auth_data.get("id_token")
                if id_token_data is not None:
                    id_token, _ = id_token_data
                else:
                    # ID token key exists, but its value is None
                    raise HomeAssistantError(
                        translation_domain=NODBIT_DOMAIN,
                        translation_key="no_token_after_login",
                    )
            # ID token expired, but Refresh token is valid
            else:
                _LOGGER.info("ID token is not valid. Refreshing using Refresh token")
                id_token, new_id_token_expiration = await refresh_id_token(
                    refresh_token, scr_hash, session
                )

                # Update cached values
                existing_auth_data["id_token"] = id_token, new_id_token_expiration

                await store.async_save(existing_auth_data)
                _LOGGER.info("Cache updated")

    _LOGGER.info("Valid ID token retrieved successfully")
    return id_token
