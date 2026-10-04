"""Mail transport, deletion scope, and IMAP search input security regressions."""

import smtplib
import socket
import ssl
from datetime import date
from unittest.mock import Mock, call

import pytest

from icloud_mcp import mail, mail_utils


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Security unit tests must not open network connections")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


@pytest.fixture
def smtp_client(monkeypatch):
    client = Mock(spec=smtplib.SMTP)
    monkeypatch.setattr(mail_utils.smtplib, "SMTP", Mock(return_value=client))
    return client


@pytest.fixture
def imap_client(monkeypatch):
    client = Mock(spec=mail_utils.IMAPClient)
    client.has_capability.side_effect = lambda capability: capability in {"MOVE", "UIDPLUS"}
    client.find_special_folder.return_value = "Deleted Messages"
    client.search.return_value = []
    monkeypatch.setattr(mail, "require_auth", Mock(return_value=("unit@icloud.com", "test-password")))
    monkeypatch.setattr(mail, "get_imap_client", Mock(return_value=client))
    return client


def test_smtp_uses_default_verifying_tls_context_before_authentication(smtp_client, monkeypatch):
    context_factory = Mock(wraps=ssl.create_default_context)
    monkeypatch.setattr(mail_utils.ssl, "create_default_context", context_factory)

    assert mail_utils.get_smtp_client("unit@icloud.com", "test-password") is smtp_client

    context_factory.assert_called_once_with()
    context = smtp_client.starttls.call_args.kwargs["context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert smtp_client.method_calls == [
        call.starttls(context=context),
        call.login("unit@icloud.com", "test-password"),
    ]


@pytest.mark.parametrize(
    "error",
    [ssl.SSLCertVerificationError("untrusted certificate"), smtplib.SMTPNotSupportedError("no STARTTLS")],
)
def test_smtp_never_authenticates_if_tls_fails(smtp_client, error):
    smtp_client.starttls.side_effect = error

    with pytest.raises(type(error)) as raised:
        mail_utils.get_smtp_client("unit@icloud.com", "test-password")

    assert raised.value is error
    smtp_client.login.assert_not_called()
    smtp_client.close.assert_called_once_with()


def test_smtp_context_failure_closes_connection_before_authentication(smtp_client, monkeypatch):
    error = OSError("certificate store unavailable")
    monkeypatch.setattr(mail_utils.ssl, "create_default_context", Mock(side_effect=error))

    with pytest.raises(OSError) as raised:
        mail_utils.get_smtp_client("unit@icloud.com", "test-password")

    assert raised.value is error
    smtp_client.starttls.assert_not_called()
    smtp_client.login.assert_not_called()
    smtp_client.close.assert_called_once_with()


def test_smtp_authentication_failure_is_reported_and_connection_closed(smtp_client):
    error = smtplib.SMTPAuthenticationError(535, b"authentication failed")
    smtp_client.login.side_effect = error

    with pytest.raises(PermissionError, match="app-specific password") as raised:
        mail_utils.get_smtp_client("unit@icloud.com", "test-password")

    assert raised.value.__cause__ is error
    smtp_client.close.assert_called_once_with()


def test_smtp_cleanup_failure_does_not_hide_tls_failure(smtp_client):
    error = ssl.SSLCertVerificationError("untrusted certificate")
    smtp_client.starttls.side_effect = error
    smtp_client.close.side_effect = OSError("socket already closed")

    with pytest.raises(ssl.SSLCertVerificationError) as raised:
        mail_utils.get_smtp_client("unit@icloud.com", "test-password")

    assert raised.value is error
    smtp_client.login.assert_not_called()


@pytest.mark.parametrize("folder", ["Deleted Messages", "deleted messages", "DELETED MESSAGES"])
@pytest.mark.parametrize("options", [{}, {"permanent": False}])
def test_nonpermanent_delete_in_trash_refuses_to_mutate(imap_client, folder, options):
    with pytest.raises(ValueError, match="already in .*permanent=true"):
        mail.delete_message("42", folder=folder, **options)

    imap_client.delete_messages.assert_not_called()
    imap_client.uid_expunge.assert_not_called()
    imap_client.expunge.assert_not_called()
    imap_client.move.assert_not_called()
    imap_client.copy.assert_not_called()
    imap_client.logout.assert_called_once_with()


def test_nonpermanent_delete_moves_to_trash(imap_client):
    result = mail.delete_message("42")

    assert result["status"] == "success"
    assert "moved to Deleted Messages" in result["message"]
    imap_client.move.assert_called_once_with([42], "Deleted Messages")
    imap_client.delete_messages.assert_not_called()
    imap_client.expunge.assert_not_called()


def test_nonpermanent_delete_without_trash_does_not_delete(imap_client):
    imap_client.find_special_folder.return_value = None
    imap_client.list_folders.return_value = []

    with pytest.raises(ValueError, match="Could not find the Trash folder"):
        mail.delete_message("42")

    imap_client.delete_messages.assert_not_called()
    imap_client.uid_expunge.assert_not_called()
    imap_client.expunge.assert_not_called()
    imap_client.move.assert_not_called()


@pytest.mark.parametrize("folder", ["INBOX", "Deleted Messages"])
def test_explicit_permanent_delete_targets_only_requested_uid(imap_client, folder):
    result = mail.delete_message("42", folder=folder, permanent=True)

    assert result["status"] == "success"
    assert "permanently deleted" in result["message"]
    imap_client.delete_messages.assert_called_once_with([42])
    imap_client.uid_expunge.assert_called_once_with([42])
    imap_client.expunge.assert_not_called()
    imap_client.move.assert_not_called()
    imap_client.logout.assert_called_once_with()


@pytest.mark.parametrize("permanent", [False, True])
def test_delete_without_safe_capability_fails_before_mutation(imap_client, permanent):
    imap_client.has_capability.return_value = False
    imap_client.has_capability.side_effect = None

    with pytest.raises(RuntimeError, match="UIDPLUS"):
        mail.delete_message("42", permanent=permanent)

    imap_client.copy.assert_not_called()
    imap_client.delete_messages.assert_not_called()
    imap_client.uid_expunge.assert_not_called()
    imap_client.expunge.assert_not_called()
    imap_client.logout.assert_called_once_with()


def test_move_capability_does_not_require_uidplus(imap_client):
    imap_client.has_capability.side_effect = lambda capability: capability == "MOVE"

    mail_utils.move_messages(imap_client, [42], "Archive")

    imap_client.move.assert_called_once_with([42], "Archive")
    imap_client.copy.assert_not_called()
    imap_client.delete_messages.assert_not_called()
    imap_client.expunge.assert_not_called()


@pytest.mark.parametrize("operation", ["move", "delete"])
def test_uid_expunge_preserves_unrelated_deleted_messages(imap_client, operation):
    imap_client.has_capability.side_effect = lambda capability: capability == "UIDPLUS"
    messages = {42: set(), 43: set(), 99: {"\\Deleted"}}

    def mark_deleted(uids):
        for uid in uids:
            messages[uid].add("\\Deleted")

    def uid_expunge(uids):
        for uid in uids:
            if "\\Deleted" in messages.get(uid, set()):
                del messages[uid]

    imap_client.delete_messages.side_effect = mark_deleted
    imap_client.uid_expunge.side_effect = uid_expunge

    if operation == "move":
        mail_utils.move_messages(imap_client, [42, 43], "Archive")
        imap_client.copy.assert_called_once_with([42, 43], "Archive")
        assert imap_client.method_calls[-3:] == [
            call.copy([42, 43], "Archive"),
            call.delete_messages([42, 43]),
            call.uid_expunge([42, 43]),
        ]
    else:
        mail_utils.permanently_delete(imap_client, [42, 43])

    assert messages == {99: {"\\Deleted"}}
    imap_client.uid_expunge.assert_called_once_with([42, 43])
    imap_client.expunge.assert_not_called()


@pytest.mark.parametrize("operation", ["move", "delete"])
def test_failed_uid_expunge_never_falls_back_to_global_expunge(imap_client, operation):
    imap_client.has_capability.side_effect = lambda capability: capability == "UIDPLUS"
    imap_client.uid_expunge.side_effect = RuntimeError("UID EXPUNGE failed")

    with pytest.raises(RuntimeError, match="UID EXPUNGE failed"):
        if operation == "move":
            mail_utils.move_messages(imap_client, [42], "Archive")
        else:
            mail_utils.permanently_delete(imap_client, [42])

    imap_client.uid_expunge.assert_called_once_with([42])
    imap_client.expunge.assert_not_called()


def test_failed_copy_never_marks_or_expunges_source(imap_client):
    imap_client.has_capability.side_effect = lambda capability: capability == "UIDPLUS"
    imap_client.copy.side_effect = RuntimeError("COPY failed")

    with pytest.raises(RuntimeError, match="COPY failed"):
        mail_utils.move_messages(imap_client, [42], "Archive")

    imap_client.delete_messages.assert_not_called()
    imap_client.uid_expunge.assert_not_called()
    imap_client.expunge.assert_not_called()


@pytest.mark.parametrize("operation", ["move", "delete"])
def test_empty_uid_list_does_not_mutate_mailbox(imap_client, operation):
    if operation == "move":
        mail_utils.move_messages(imap_client, [], "Archive")
    else:
        mail_utils.permanently_delete(imap_client, [])

    assert imap_client.method_calls == []


@pytest.mark.parametrize("field", ["query", "sender", "recipient", "subject", "body", "since", "before", "folder"])
@pytest.mark.parametrize("control", ["\r", "\n", "\x00", "\r\n"])
def test_search_rejects_control_characters_before_authentication(imap_client, field, control):
    # Dates deliberately start with a valid date: validation must precede slicing.
    value = "2026-10-04" if field in {"since", "before"} else "value"
    kwargs = {field: value + control + "INJECTED", "unread_only": True}

    with pytest.raises(ValueError, match=rf"{field} must not contain CR, LF or NUL"):
        mail.search_messages(**kwargs)

    mail.require_auth.assert_not_called()
    mail.get_imap_client.assert_not_called()
    imap_client.search.assert_not_called()


def test_search_preserves_valid_unicode_and_quoted_filters(imap_client):
    value = 'Réunion "quoted" \\ value (test)'
    result = mail.search_messages(
        query=value,
        sender="sender@example.com",
        recipient="recipient@example.com",
        subject=value,
        body=value,
        since="2026-10-01",
        before="2026-10-05",
        unread_only=True,
        folder="Réunions",
    )

    assert result == []
    imap_client.select_folder.assert_called_once_with("Réunions", readonly=True)
    imap_client.search.assert_called_once_with(
        [
            ["OR", ["SUBJECT", value], ["FROM", value]],
            "FROM", "sender@example.com",
            ["OR", ["TO", "recipient@example.com"], ["CC", "recipient@example.com"]],
            "SUBJECT", value,
            "BODY", value,
            "SINCE", date(2026, 10, 1),
            "BEFORE", date(2026, 10, 5),
            "UNSEEN",
        ],
        charset="UTF-8",
    )
    imap_client.logout.assert_called_once_with()


def test_search_empty_optional_filters_preserves_unread_only(imap_client):
    assert mail.search_messages(query="", subject=None, since="", unread_only=True) == []
    imap_client.search.assert_called_once_with(["UNSEEN"], charset="UTF-8")


def test_search_still_requires_a_filter_before_authentication(imap_client):
    with pytest.raises(ValueError, match="at least one filter"):
        mail.search_messages()

    mail.require_auth.assert_not_called()
    mail.get_imap_client.assert_not_called()


def test_search_ascii_fallback_preserves_validated_criteria(imap_client):
    imap_client.search.side_effect = [RuntimeError("CHARSET unsupported"), []]

    assert mail.search_messages(subject="hello") == []
    assert imap_client.search.call_args_list == [
        call(["SUBJECT", "hello"], charset="UTF-8"),
        call(["SUBJECT", "hello"]),
    ]
