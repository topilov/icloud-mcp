"""Safe cloud defaults, exact tool exposure, credentials, and log regressions."""

import asyncio
import base64
import importlib.util
import logging
from pathlib import Path
from unittest.mock import Mock

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from icloud_mcp import auth, server
from icloud_mcp.config import SAFE_MAIL_TOOLS, SecretRedactingFormatter, _parse_enabled_tools, config


def _restricted_server(monkeypatch, raw=None, categories=None):
    monkeypatch.setattr(config, "ENABLED_TOOLS", _parse_enabled_tools(raw))
    monkeypatch.setattr(config, "ENABLED_CATEGORIES", categories or {"email", "contacts", "calendar"})
    spec = importlib.util.spec_from_file_location("icloud_mcp._test_restricted_server", server.__file__)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tool_names(module):
    async def run():
        async with Client(module.mcp) as client:
            return {tool.name for tool in await client.list_tools()}

    return asyncio.run(run())


@pytest.mark.parametrize("raw", [None, "", " ", "safe-mail"])
def test_default_profile_exposes_only_mail_read_send_and_draft(monkeypatch, raw):
    module = _restricted_server(monkeypatch, raw)
    assert _tool_names(module) == SAFE_MAIL_TOOLS
    assert {"email_send", "email_save_draft", "email_search"} <= SAFE_MAIL_TOOLS
    assert not any("delete" in name or "move" in name for name in SAFE_MAIL_TOOLS)


def test_excluded_tool_cannot_be_called_through_protocol(monkeypatch):
    module = _restricted_server(monkeypatch)
    operation = Mock(side_effect=AssertionError("Destructive backend must be unreachable"))
    monkeypatch.setattr(module.mail_module, "delete_message", operation)

    async def run():
        async with Client(module.mcp) as client:
            return await client.call_tool("email_delete", {"message_id": "42"}, raise_on_error=False)

    assert asyncio.run(run()).is_error
    operation.assert_not_called()


def test_custom_tool_allowlist_and_category_intersection(monkeypatch):
    module = _restricted_server(
        monkeypatch, "email_search, email_save_draft,contacts_list", categories={"email"}
    )
    assert _tool_names(module) == {"email_search", "email_save_draft"}


def test_all_tools_require_explicit_opt_in(monkeypatch):
    module = _restricted_server(monkeypatch, "all")
    assert _tool_names(module) == module._declared_tools
    assert "email_delete" in _tool_names(module)


def test_unknown_tool_names_fail_closed(monkeypatch):
    with pytest.raises(ValueError, match="Unknown tools.*email_seach"):
        _restricted_server(monkeypatch, "email_seach")
    with pytest.raises(ValueError, match="at least one tool"):
        _parse_enabled_tools(" , ")


@pytest.mark.parametrize("token", [None, "", "   "])
@pytest.mark.parametrize("allow_env", [None, False, True])
def test_http_entrypoint_never_listens_without_token(monkeypatch, token, allow_env):
    run = Mock()
    monkeypatch.setattr(server.mcp, "run", run)
    monkeypatch.setattr(server, "configure_logging", Mock())
    monkeypatch.setattr(config, "MCP_AUTH_TOKEN", token)
    monkeypatch.setattr(config, "ALLOW_ENV_CREDENTIALS", allow_env)
    monkeypatch.setattr(config, "ENV_CREDENTIALS_ACTIVE", True)
    monkeypatch.setattr(config, "LOCAL_FILES", None)
    with pytest.raises(ValueError, match="MCP_AUTH_TOKEN is required"):
        server.main(["--http"])
    run.assert_not_called()
    assert config.LOCAL_FILES is False
    assert config.ENV_CREDENTIALS_ACTIVE is False


@pytest.mark.parametrize("local_files", [None, False, True])
@pytest.mark.parametrize("arguments,transport", [(["--http"], ""), ([], "http"), ([], "streamable-http")])
def test_http_entrypoint_installs_auth_and_disables_local_files(monkeypatch, arguments, transport, local_files):
    run = Mock()
    monkeypatch.setattr(server.mcp, "run", run)
    monkeypatch.setattr(server, "configure_logging", Mock())
    monkeypatch.setenv("MCP_TRANSPORT", transport)
    monkeypatch.setattr(config, "MCP_AUTH_TOKEN", "unit-test-secret")
    monkeypatch.setattr(config, "ALLOW_ENV_CREDENTIALS", None)
    monkeypatch.setattr(config, "ENV_CREDENTIALS_ACTIVE", False)
    monkeypatch.setattr(config, "LOCAL_FILES", local_files)
    server.main(arguments)
    assert config.LOCAL_FILES is False
    assert config.ENV_CREDENTIALS_ACTIVE is True
    assert run.call_args.kwargs["transport"] == "http"
    middleware = run.call_args.kwargs["middleware"]
    assert len(middleware) == 1
    assert middleware[0].cls is server.TokenAuthMiddleware
    assert middleware[0].kwargs["token"] == "unit-test-secret"


def test_stdio_preserves_local_file_default(monkeypatch):
    run = Mock()
    monkeypatch.setattr(server.mcp, "run", run)
    monkeypatch.setattr(server, "configure_logging", Mock())
    monkeypatch.setenv("MCP_TRANSPORT", "stdio")
    monkeypatch.setattr(config, "LOCAL_FILES", None)
    server.main([])
    assert config.LOCAL_FILES is True
    assert run.call_args.kwargs["transport"] == "stdio"


def test_compose_passes_recipient_allowlist_and_safe_defaults():
    # Source check requires no Docker daemon, network, or YAML expansion of secrets.
    compose = (Path(__file__).parents[1] / "docker-compose.yml").read_text()
    assert "EMAIL_SEND_ALLOWLIST: ${EMAIL_SEND_ALLOWLIST:-}" in compose
    assert "ICLOUD_MCP_ALLOW_ENV_CREDENTIALS: ${ICLOUD_MCP_ALLOW_ENV_CREDENTIALS:-true}" in compose
    assert "ICLOUD_ENABLED_TOOLS: ${ICLOUD_ENABLED_TOOLS:-safe-mail}" in compose
    assert 'ICLOUD_MCP_LOCAL_FILES: "false"' in compose
    assert '127.0.0.1:${MCP_SERVER_PORT:-8000}:8000' in compose


def test_redaction_includes_fallback_request_and_endpoint_secrets(monkeypatch):
    encoded = base64.b64encode(b"reader@icloud.com:basic-password").decode()
    monkeypatch.setattr(config, "FALLBACK_PASSWORD", "fallback-password")
    monkeypatch.setattr(config, "MCP_AUTH_TOKEN", "endpoint-token")
    monkeypatch.setattr(auth, "_request_headers", lambda: {
        "x-apple-app-specific-password": "header password",
        "x-mcp-token": "request-token",
        "authorization": f"Basic {encoded}",
    })
    text = f"fallback-password endpoint-token header password headerpassword request-token Basic {encoded} basic-password"
    redacted = auth.redact_secrets(text)
    for secret in ["fallback-password", "endpoint-token", "header password", "headerpassword", "request-token", encoded, "basic-password"]:
        assert secret not in redacted


@pytest.mark.parametrize("error_type", [ValueError, RuntimeError, auth.AuthenticationError, ToolError])
def test_tool_errors_do_not_expose_secrets_or_exception_tracebacks(monkeypatch, caplog, error_type):
    monkeypatch.setattr(config, "MCP_AUTH_TOKEN", "endpoint-secret")
    monkeypatch.setattr(config, "FALLBACK_PASSWORD", "mailbox-secret")
    monkeypatch.setattr(auth, "_request_headers", lambda: {})

    def operation():
        raise error_type("failed using mailbox-secret endpoint-secret")

    with caplog.at_level(logging.ERROR), pytest.raises(ToolError) as raised:
        server._run(operation)
    assert "mailbox-secret" not in str(raised.value)
    assert "endpoint-secret" not in str(raised.value)
    assert raised.value.__suppress_context__ is True
    assert "mailbox-secret" not in caplog.text
    assert "endpoint-secret" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


def test_authorization_error_does_not_echo_backend_message(monkeypatch):
    def operation():
        raise RuntimeError("Unauthorized: private response and secret")

    with pytest.raises(ToolError) as raised:
        server._run(operation)
    assert "private response" not in str(raised.value)


def test_log_formatter_redacts_secrets_even_inside_tracebacks(monkeypatch):
    monkeypatch.setattr(config, "MCP_AUTH_TOKEN", "endpoint-secret")
    monkeypatch.setattr(auth, "_request_headers", lambda: {})
    try:
        raise RuntimeError("endpoint-secret")
    except RuntimeError:
        import sys
        info = sys.exc_info()
    record = logging.LogRecord("test", logging.ERROR, "test.py", 1, "using %s", ("endpoint-secret",), info)
    text = SecretRedactingFormatter("%(message)s").format(record)
    assert "endpoint-secret" not in text
    assert "***" in text


@pytest.mark.parametrize("path", ["/health", "/health/"])
def test_http_rejects_mcp_path_colliding_with_public_health(monkeypatch, path):
    run = Mock()
    monkeypatch.setattr(server.mcp, "run", run)
    monkeypatch.setattr(server, "configure_logging", Mock())
    monkeypatch.setattr(config, "LOCAL_FILES", None)
    with pytest.raises(ValueError, match="public /health"):
        server.main(["--http", "--path", path])
    run.assert_not_called()


def test_actual_http_startup_keeps_framework_logs_on_redacting_sink(monkeypatch):
    import io
    import sys

    import uvicorn

    output = io.StringIO()
    logger_names = ("", "fastmcp", "uvicorn", "uvicorn.error", "uvicorn.access")
    saved = {
        name: (logging.getLogger(name).handlers[:], logging.getLogger(name).propagate, logging.getLogger(name).level)
        for name in logger_names
    }
    monkeypatch.setattr(sys, "stderr", output)
    monkeypatch.setattr(config, "MCP_AUTH_TOKEN", "runtime-endpoint-secret")
    monkeypatch.setattr(config, "FALLBACK_PASSWORD", "runtime-mailbox-secret")
    monkeypatch.setattr(config, "LOCAL_FILES", None)
    monkeypatch.setattr(config, "ENV_CREDENTIALS_ACTIVE", True)
    monkeypatch.setattr(auth, "_request_headers", lambda: {})
    called = []

    async def serve(http_server, sockets=None):
        called.append(True)
        assert http_server.config.log_config is None
        assert http_server.config.access_log is False
        for name in ("fastmcp.server.server", "uvicorn.error"):
            logging.getLogger(name).error("runtime-endpoint-secret runtime-mailbox-secret")

    monkeypatch.setattr(uvicorn.Server, "serve", serve)
    try:
        server.main(["--http"])
        assert called == [True]
        assert "runtime-endpoint-secret" not in output.getvalue()
        assert "runtime-mailbox-secret" not in output.getvalue()
        assert "*** ***" in output.getvalue()
    finally:
        for name, (handlers, propagate, level) in saved.items():
            logger = logging.getLogger(name)
            logger.handlers = handlers
            logger.propagate = propagate
            logger.setLevel(level)
