"""Credential resolution for the iCloud MCP server.

Credentials are resolved per request, in this order:

1. HTTP headers ``X-Apple-Email`` / ``X-Apple-App-Specific-Password``
2. HTTP ``Authorization: Basic base64(email:app-specific-password)``
3. Environment variables ``ICLOUD_EMAIL`` / ``ICLOUD_APP_SPECIFIC_PASSWORD``

Outside an HTTP request (stdio transport) only the environment is consulted.
"""

import base64
import binascii
import logging

from fastmcp.server.dependencies import get_http_headers

from .config import config

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Raised when no usable iCloud credentials are available."""


def _from_basic_auth(header: str | None) -> tuple[str | None, str | None]:
    if not header:
        return None, None
    scheme, _, value = header.strip().partition(" ")
    if scheme.lower() != "basic" or not value:
        return None, None
    try:
        decoded = base64.b64decode(value.strip(), validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None, None
    email, _, password = decoded.partition(":")
    return (email or None), (password or None)


def _request_headers() -> dict:
    try:
        headers = get_http_headers(include_all=True) or {}
    except Exception:  # not inside an HTTP request
        return {}
    return {k.lower(): v for k, v in headers.items()}


def get_credentials() -> tuple[str, str]:
    """Return ``(email, app_specific_password)`` for the current request."""
    headers = _request_headers()

    email: str | None = headers.get("x-apple-email")
    password: str | None = headers.get("x-apple-app-specific-password")

    if not (email and password):
        basic_email, basic_password = _from_basic_auth(headers.get("authorization"))
        email = email or basic_email
        password = password or basic_password

    if config.ENV_CREDENTIALS_ACTIVE:
        if not email:
            email = config.FALLBACK_EMAIL
        if not password:
            password = config.FALLBACK_PASSWORD

    if not email or not password:
        raise AuthenticationError(
            "iCloud credentials are missing. Provide them via HTTP headers "
            "(X-Apple-Email, X-Apple-App-Specific-Password), HTTP Basic auth, "
            "or environment variables (ICLOUD_EMAIL, ICLOUD_APP_SPECIFIC_PASSWORD). "
            "Use an app-specific password from https://account.apple.com/account/manage, "
            "not the Apple ID password."
        )

    return email.strip(), password.strip().replace(" ", "")


def require_auth() -> tuple[str, str]:
    """Alias kept for readability at call sites."""
    return get_credentials()


def redact_secrets(text: str) -> str:
    """Remove request and configured secrets before errors or logs leave the server."""
    secrets = {config.FALLBACK_PASSWORD, config.MCP_AUTH_TOKEN}
    headers = _request_headers()
    secrets.update((headers.get("x-apple-app-specific-password"), headers.get("x-mcp-token")))
    authorization = headers.get("authorization")
    if authorization:
        secrets.add(authorization)
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() in {"basic", "bearer"}:
            secrets.add(value.strip())
        _, password = _from_basic_auth(authorization)
        secrets.add(password)
    try:
        _, password = get_credentials()
        secrets.add(password)
    except Exception:
        pass
    for secret in tuple(secrets):
        if secret:
            secrets.add(secret.strip().replace(" ", ""))
    for secret in sorted((value for value in secrets if value), key=len, reverse=True):
        text = text.replace(secret, "***")
    return text
