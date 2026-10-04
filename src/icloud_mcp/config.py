"""Configuration for the iCloud MCP server.

Everything is read from environment variables (a local ``.env`` file is loaded
first). The server is stateless: nothing here is mutated per request except the
transport-dependent defaults set once at startup by ``server.main()``.
"""

import logging
import os
import sys

from dotenv import load_dotenv

load_dotenv()


def _env_bool(name: str, default: bool | None = None) -> bool | None:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _local_timezone_name() -> str:
    """Best-effort IANA name of the machine's timezone (falls back to UTC)."""
    tz = os.getenv("TZ")
    if tz and "/" in tz:
        return tz
    try:
        target = os.readlink("/etc/localtime")
        marker = "zoneinfo/"
        if marker in target:
            return target.split(marker, 1)[1]
    except OSError:
        pass
    return "UTC"


ALL_CATEGORIES = frozenset({"calendar", "contacts", "email"})
SAFE_MAIL_TOOLS = frozenset({
    "email_list_folders", "email_list_messages", "email_search", "email_get_message",
    "email_get_messages", "email_get_attachment", "email_send", "email_save_draft",
})


def _parse_enabled_tools(raw: str | None) -> frozenset[str] | None:
    """Default to mail read/send/draft tools; all other access is explicit."""
    if raw is None or not raw.strip() or raw.strip().lower() == "safe-mail":
        return SAFE_MAIL_TOOLS
    if raw.strip().lower() == "all":
        return None
    names = frozenset(name.strip() for name in raw.split(",") if name.strip())
    if not names:
        raise ValueError("ICLOUD_ENABLED_TOOLS must enable at least one tool")
    return names


def _parse_categories(raw: str | None) -> frozenset[str]:
    """Parse ICLOUD_ENABLED_CATEGORIES ("calendar,contacts,email"; "mail" is an alias for email)."""
    if raw is None or not raw.strip():
        return ALL_CATEGORIES
    result = set()
    for item in raw.split(","):
        name = item.strip().lower()
        if not name:
            continue
        if name == "mail":
            name = "email"
        if name not in ALL_CATEGORIES:
            raise ValueError(
                f"Unknown category {item.strip()!r} in ICLOUD_ENABLED_CATEGORIES; "
                f"use any of {', '.join(sorted(ALL_CATEGORIES))}"
            )
        result.add(name)
    if not result:
        raise ValueError("ICLOUD_ENABLED_CATEGORIES must enable at least one category")
    return frozenset(result)


class Config:
    """Server configuration, loaded once from the environment."""

    # iCloud endpoints
    CALDAV_SERVER: str = os.getenv("CALDAV_SERVER", "https://caldav.icloud.com")
    CARDDAV_SERVER: str = os.getenv("CARDDAV_SERVER", "https://contacts.icloud.com")
    IMAP_SERVER: str = os.getenv("IMAP_SERVER", "imap.mail.me.com")
    SMTP_SERVER: str = os.getenv("SMTP_SERVER", "smtp.mail.me.com")
    IMAP_PORT: int = int(os.getenv("IMAP_PORT", "993"))
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))

    # MCP transport
    MCP_SERVER_HOST: str = os.getenv("MCP_SERVER_HOST", "0.0.0.0")
    MCP_SERVER_PORT: int = int(os.getenv("PORT", os.getenv("MCP_SERVER_PORT", "8000")))
    MCP_SERVER_PATH: str = os.getenv("MCP_SERVER_PATH", "/mcp")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

    # Mail folders (iCloud names; discovered via IMAP special-use flags when possible)
    SENT_FOLDER: str = os.getenv("SENT_FOLDER", "Sent Messages")
    TRASH_FOLDER: str = os.getenv("TRASH_FOLDER", "Deleted Messages")
    DRAFTS_FOLDER: str = os.getenv("DRAFTS_FOLDER", "Drafts")

    # Which tool groups to expose: any of calendar, contacts, email (alias: mail).
    ENABLED_CATEGORIES: frozenset[str] = _parse_categories(os.getenv("ICLOUD_ENABLED_CATEGORIES"))

    # Exact tool names, "safe-mail" (default), or "all" (explicit full access).
    # This allowlist intersects ENABLED_CATEGORIES and applies to every transport.
    ENABLED_TOOLS: frozenset[str] | None = _parse_enabled_tools(os.getenv("ICLOUD_ENABLED_TOOLS"))

    # How rich text stored in iCloud fields (event notes/location, contact notes)
    # is returned: "markdown" keeps links/emphasis/lists, "text" renders to plain
    # text, "raw" leaves it untouched.
    HTML_MODE: str = os.getenv("ICLOUD_HTML_MODE", "markdown").strip().lower()

    # HTTP requires MCP_AUTH_TOKEN on every MCP request as Authorization: Bearer
    # or X-MCP-Token. ALLOW_ENV_CREDENTIALS cannot bypass endpoint authentication.
    MCP_AUTH_TOKEN: str | None = os.getenv("MCP_AUTH_TOKEN") or None
    ALLOW_ENV_CREDENTIALS: bool | None = _env_bool("ICLOUD_MCP_ALLOW_ENV_CREDENTIALS", None)
    # Set once at startup by server.main(); HTTP startup fails without a token.
    ENV_CREDENTIALS_ACTIVE: bool = True

    # Size limits
    EMAIL_BODY_MAX_CHARS: int = int(os.getenv("EMAIL_BODY_MAX_CHARS", "20000"))
    # Outbound recipients (email_send, email_save_draft, calendar invitations) must match
    # one of these entries when set: full addresses or domains ("@example.com").
    EMAIL_SEND_ALLOWLIST: frozenset[str] = frozenset(
        x.strip().lower() for x in os.getenv("EMAIL_SEND_ALLOWLIST", "").split(",") if x.strip()
    )
    EMAIL_MAX_ATTACHMENT_BYTES: int = int(
        os.getenv("EMAIL_MAX_ATTACHMENT_BYTES", str(20 * 1024 * 1024))
    )

    # Calendar defaults
    DEFAULT_TIMEZONE: str = os.getenv("DEFAULT_TIMEZONE") or _local_timezone_name()

    # Local filesystem access for attachments (save downloaded attachments,
    # attach local files to outgoing mail). Enabled by default for local stdio;
    # HTTP always disables local-file access, even when this is explicitly true.
    LOCAL_FILES: bool | None = _env_bool("ICLOUD_MCP_LOCAL_FILES", None)
    LOCAL_FILES_ROOT: str | None = os.getenv("ICLOUD_MCP_LOCAL_FILES_ROOT") or None

    # Fallback credentials (single-user deployments / stdio mode)
    FALLBACK_EMAIL: str | None = os.getenv("ICLOUD_EMAIL") or None
    FALLBACK_PASSWORD: str | None = os.getenv("ICLOUD_APP_SPECIFIC_PASSWORD") or None


config = Config()


class SecretRedactingFormatter(logging.Formatter):
    """Redact credentials from complete log messages, including tracebacks."""

    def format(self, record: logging.LogRecord) -> str:
        from .auth import redact_secrets

        return redact_secrets(super().format(record))


def configure_logging(level: str | None = None) -> None:
    """Send all logs to stderr. stdout is reserved for the stdio MCP transport."""
    logging.basicConfig(
        level=getattr(logging, (level or config.LOG_LEVEL), logging.INFO),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        force=True,
    )
    for handler in logging.getLogger().handlers:
        handler.setFormatter(SecretRedactingFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    # Keep framework logs on the same redacting sink. The entrypoint prevents
    # FastMCP/Uvicorn from replacing these handlers during HTTP startup.
    for name in ("fastmcp", "uvicorn", "uvicorn.error", "uvicorn.access"):
        framework_logger = logging.getLogger(name)
        framework_logger.handlers.clear()
        framework_logger.propagate = True
        framework_logger.setLevel(getattr(logging, (level or config.LOG_LEVEL), logging.INFO))
    # Third-party libraries are chatty at INFO/DEBUG.
    for noisy in ("caldav", "urllib3", "niquests", "httpx", "imapclient"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
