"""Constants for Nodbit."""

NODBIT_DOMAIN = "nodbit"
AUTH_DOMAIN = "https://cognito-idp.us-east-1.amazonaws.com/"
SVC_URL = "https://da2i13b7ae.execute-api.us-east-1.amazonaws.com/prod/testing"
ID = "s9rksanbi9ak9omir8ihkd6uc"
STORAGE_KEY = "nodbit_auth"
STORAGE_VERSION = 1

HEADERS = {
    "Content-Type": "application/x-amz-json-1.1",
    "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
}

# All values are in seconds, except for MAX_RETRIES
HTTP_TIMEOUT = 30
IDTOKEN_LIFETIME = 3600
REFRESHTOKEN_LIFETIME = 7200

# Exponential backoff values
MAX_RETRIES = 5  # Maximum number of retries
INITIAL_WAIT_TIME = 2  # Initial wait time in seconds
