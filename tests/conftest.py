import os
import socket
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

# Do not load .env files or reuse exported mailbox credentials in unit tests.
_dotenv_patch = patch("dotenv.load_dotenv", return_value=False)
_dotenv_patch.start()
os.environ["ICLOUD_EMAIL"] = "tester@icloud.com"
os.environ["ICLOUD_APP_SPECIFIC_PASSWORD"] = "aaaa-bbbb-cccc-dddd"
os.environ["DEFAULT_TIMEZONE"] = "Europe/Berlin"
os.environ["MCP_AUTH_TOKEN"] = "unit-test-token"
os.environ["ICLOUD_ENABLED_CATEGORIES"] = "calendar,contacts,email"
# Existing protocol regressions intentionally exercise every tool; the safe
# default and restricted surfaces have independent tests.
os.environ["ICLOUD_ENABLED_TOOLS"] = "all"
os.environ["EMAIL_SEND_ALLOWLIST"] = ""
os.environ["CALDAV_SERVER"] = "https://caldav.icloud.com"
os.environ["CARDDAV_SERVER"] = "https://contacts.icloud.com"


@pytest.fixture(autouse=True)
def block_live_network(monkeypatch):
    """Fail even when application code catches a blocked network attempt."""
    attempts = []

    def blocked(*args, **kwargs):
        attempts.append(True)
        raise AssertionError("Tests must use mocked transports, never live network connections")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "gethostbyname", blocked)
    yield
    assert not attempts, "A test attempted to use a live network transport"


def pytest_unconfigure(config):
    _dotenv_patch.stop()
