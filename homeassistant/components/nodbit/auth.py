"""Authentication and Token Management for Nodbit Integration.

This module handles the authentication and token management required to interact with Nodbit API.
It provides functions for logging, refreshing tokens and managing token caching
to ensure valid authentication during API calls. Key functionalities include:

- `login`: Authenticates users using their credentials and retrieves ID and Refresh tokens.
- `refresh_id_token`: Uses the Refresh Token to obtain a new ID Token, extending the session without re-authenticating.
- `get_id_token`: Manages the retrieval of a valid ID Token, handling re-authentication or refresh as needed.
- `retry_request`: Provides a retry mechanism with exponential backoff for network stability during authentication operations.
"""

from http import HTTPStatus
import json
import logging
import time

import requests

from .const import (
    AUTH_DOMAIN,
    HEADERS,
    HTTP_TIMEOUT,
    ID,
    IDTOKEN_LIFETIME,
    INITIAL_WAIT_TIME,
    MAX_RETRIES,
    REFRESHTOKEN_LIFETIME,
)

_LOGGER = logging.getLogger(__name__)

# Token cache
id_token_cache = None
id_token_expiry_time = None
refresh_token_cache = None
refresh_token_expiry_time = None

CONF_USER_ID = "user_id"
CONF_USER_PWD = "user_pwd"
CONF_KEY = "key"


def refresh_id_token() -> None:
    """Use the Refresh Token to obtain a new ID Token.

    Update cache with exponential retry.
    """
    global id_token_cache, id_token_expiry_time

    _LOGGER.info("Refreshing ID Token")
    refresh_payload = {
        "AuthFlow": "REFRESH_TOKEN_AUTH",
        "ClientId": ID,
        "AuthParameters": {
            "REFRESH_TOKEN": refresh_token_cache,
            "SECRET_HASH": CONF_KEY,
        },
    }

    wait_time = INITIAL_WAIT_TIME
    retries = 0
    while retries < MAX_RETRIES:
        response = requests.post(
            AUTH_DOMAIN,
            headers=HEADERS,
            json=refresh_payload,
            timeout=HTTP_TIMEOUT,
        )
        obj = json.loads(response.text)

        response_code = obj.get("statusCode")

        if response_code == HTTPStatus.OK:
            refresh_result = response.json()["AuthenticationResult"]
            id_token_cache = refresh_result["IdToken"]
            id_token_expiry_time = (
                time.time() + IDTOKEN_LIFETIME
            )  # New ID Token expiry in 1 hour

            _LOGGER.info("ID Token refreshed successfully. Cache updated")
            return

        _LOGGER.info("Refresh attempt %d failed", retries + 1)
        retries += 1
        if retries < MAX_RETRIES:
            _LOGGER.info("Retrying in %d seconds", wait_time)
            time.sleep(wait_time)
            wait_time *= 2
        else:
            _LOGGER.error("Failed to refresh ID Token after all retries")
            raise ConnectionError


def login() -> None:
    """Log into Cognito to retrieve new tokens and update the cache."""
    global \
        id_token_cache, \
        id_token_expiry_time, \
        refresh_token_cache, \
        refresh_token_expiry_time

    _LOGGER.info("Logging in")
    login_payload = {
        "AuthFlow": "USER_PASSWORD_AUTH",
        "ClientId": ID,
        "AuthParameters": {
            "USERNAME": CONF_USER_ID,
            "PASSWORD": CONF_USER_PWD,
            "SECRET_HASH": CONF_KEY,
        },
    }

    wait_time = INITIAL_WAIT_TIME
    retries = 0
    while retries < MAX_RETRIES:
        response = requests.post(
            AUTH_DOMAIN,
            headers=HEADERS,
            json=login_payload,
            timeout=HTTP_TIMEOUT,
        )

        obj = json.loads(response.text)

        response_code = obj.get("statusCode")

        if response_code == HTTPStatus.OK:
            auth_result = response.json()["AuthenticationResult"]
            id_token_cache = auth_result["IdToken"]
            refresh_token_cache = auth_result["RefreshToken"]
            id_token_expiry_time = time.time() + IDTOKEN_LIFETIME
            refresh_token_expiry_time = time.time() + REFRESHTOKEN_LIFETIME

            _LOGGER.info("Logged in successfully. Tokens saved in cache")
            return

        _LOGGER.info("Refresh attempt %d failed", retries + 1)
        retries += 1
        if retries < MAX_RETRIES:
            _LOGGER.info("Retrying in %d seconds", wait_time)
            time.sleep(wait_time)
            wait_time *= 2
        else:
            _LOGGER.error("Failed to login after all retries")
            raise ConnectionError


def get_id_token() -> str:
    """Retrieve a valid ID Token, refresh or re-authenticate if necessary."""
    global \
        id_token_cache, \
        id_token_expiry_time, \
        refresh_token_cache, \
        refresh_token_expiry_time

    _LOGGER.info("Retrieving ID token")
    if not id_token_cache or not refresh_token_cache:
        _LOGGER.info("No tokens in cache")
        login()
        return id_token_cache

    current_time = time.time()
    if current_time >= id_token_expiry_time - 600:
        if current_time >= refresh_token_expiry_time:
            _LOGGER.info("Both tokens expired. Re-authenticating")
            login()
        else:
            _LOGGER.info("ID Token is about to expire. Refreshing using Refresh Token")
            refresh_id_token()

    return id_token_cache
