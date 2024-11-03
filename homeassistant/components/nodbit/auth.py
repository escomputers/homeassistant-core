"""Authentication for Nodbit Integration.

This module handles the authentication required to interact with Nodbit API.
It provides functions for logging, refreshing tokens and managing token caching
to ensure valid authentication during API calls. Key functionalities include:

- `login`: Authenticates users using their credentials and retrieves ID and Refresh tokens.
- `refresh_id_token`: Uses the Refresh Token to obtain a new ID Token, extending the session without re-authenticating.
- `get_id_token`: Manages the retrieval of a valid ID Token, handling re-authentication or refresh as needed.
"""

import json
import logging
import time

from aiohttp import ClientSession, ClientTimeout

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


async def refresh_id_token(
    refresh_tok: str, secret_hash: str, async_session: ClientSession
) -> tuple[str, float]:
    """Refresh ID token using the Refresh Token."""

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
        response.raise_for_status()
        response_text = await response.text()
        obj = json.loads(response_text)

        id_tok = obj["AuthenticationResult"]["IdToken"]
        new_id_token_expiry_time = time.time() + IDTOKEN_LIFETIME

        return id_tok, new_id_token_expiry_time


async def login(
    user_id: str,
    user_pass: str,
    secret_hash: str,
    async_session: ClientSession,
    store_obj: Store,
) -> dict[str, tuple[str, float]]:
    """Log in to retrieve new tokens."""

    _LOGGER.info("Logging in")
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
        response.raise_for_status()
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

    await store_obj.async_save(auth_data)

    _LOGGER.info("Successfully logged in")
    return auth_data


async def get_id_token(
    usr_id: str, usr_pwd: str, scr_hash: str, session: ClientSession, store: Store
) -> str:
    """Retrieve a valid ID Token, refresh or re-authenticate if necessary."""
    _LOGGER.info("Retrieving ID token")

    # Try to retrieve existing authentication data
    existing_auth_data = await store.async_load()

    # No persistent cache found
    if existing_auth_data is None:
        _LOGGER.info("No cache found")
        auth_data = await login(usr_id, usr_pwd, scr_hash, session, store)

        id_token_data = auth_data.get("id_token")
        if id_token_data is not None:
            id_token, _ = id_token_data
        else:
            _LOGGER.error("Cannot get tokens after login")
    # Cache found
    else:
        _LOGGER.info("Cache data found, checking tokens expiration")
        id_token, id_token_expiration = existing_auth_data.get("id_token")
        refresh_token, refresh_token_expiration = existing_auth_data.get(
            "refresh_token"
        )

        current_time = time.time()
        # Check if ID token has expired
        if current_time >= id_token_expiration - 600:
            # ID token expired, check Refresh token
            if current_time >= refresh_token_expiration:
                _LOGGER.info("Both tokens expired. Re-authenticating")
                auth_data = await login(usr_id, usr_pwd, scr_hash, session, store)

                id_token_data = auth_data.get("id_token")
                if id_token_data is not None:
                    id_token, _ = id_token_data
                else:
                    _LOGGER.error("Cannot get tokens after login")
            # ID token expired, but Refresh token is valid
            else:
                _LOGGER.info(
                    "ID Token is about to expire. Refreshing using Refresh Token"
                )
                new_id_token, new_id_token_expiration = await refresh_id_token(
                    refresh_token, scr_hash, session
                )

                # Update cached values
                existing_auth_data["id_token"] = new_id_token, new_id_token_expiration

                await store.async_save(existing_auth_data)

    _LOGGER.info("Retrieved valid ID token")
    return id_token
