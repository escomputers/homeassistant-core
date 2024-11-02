"""Authentication and Token Management for Nodbit Integration.

This module handles the authentication and token management required to interact with Nodbit API.
It provides functions for logging, refreshing tokens and managing token caching
to ensure valid authentication during API calls. Key functionalities include:

- `login`: Authenticates users using their credentials and retrieves ID and Refresh tokens.
- `refresh_id_token`: Uses the Refresh Token to obtain a new ID Token, extending the session without re-authenticating.
- `get_id_token`: Manages the retrieval of a valid ID Token, handling re-authentication or refresh as needed.
- `retry_request`: Provides a retry mechanism with exponential backoff for network stability during authentication operations.
"""

import json
import logging

import requests

from .const import AUTH_DOMAIN, HEADERS, HTTP_TIMEOUT, ID

_LOGGER = logging.getLogger(__name__)


def login(user_id: str, user_pass: str, secret_hash: str) -> str:
    """Log into Cognito to retrieve new tokens."""

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

    response = requests.post(
        AUTH_DOMAIN,
        headers=HEADERS,
        json=login_payload,
        timeout=HTTP_TIMEOUT,
    )
    response.raise_for_status()
    obj = json.loads(response.text)

    id_tok = obj["AuthenticationResult"]["IdToken"]

    _LOGGER.info("Successfully logged in")
    return id_tok


def get_id_token(usr_id: str, usr_pwd: str, scr_hash: str) -> str:
    """Retrieve a valid ID Token, refresh or re-authenticate if necessary."""
    _LOGGER.info("Retrieving ID token")
    id_token = login(usr_id, usr_pwd, scr_hash)
    return id_token
