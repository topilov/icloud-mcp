"""DAV discovery, calendar notification policy and TLS regression tests.

All transports are mocked; no Apple account or live network is used.
"""

import ssl
from unittest.mock import Mock
from xml.sax.saxutils import escape

import pytest
import requests
import vobject

from icloud_mcp import calendar, contacts, mail

_SESSION_REQUEST = requests.Session.request
BASE = "https://contacts.icloud.com"
BOOK = "https://p72-contacts.icloud.com/123/carddavhome/card/"
CARD = BOOK + "one.vcf"
EVENT = "https://p72-caldav.icloud.com/123/calendar/event.ics"
VCARD = "BEGIN:VCARD\nVERSION:3.0\nFN:Jane Doe\nN:Doe;Jane;;;\nEND:VCARD\n"
ICAL = """BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Tests//EN
BEGIN:VEVENT
UID:test
DTSTAMP:20250101T000000Z
DTSTART:20250110T100000Z
DTEND:20250110T110000Z
SUMMARY:Test
ATTENDEE:mailto:friend@ok.test
END:VEVENT
END:VCALENDAR
"""


@pytest.fixture(autouse=True)
def isolated_transports(monkeypatch):
    monkeypatch.setattr(contacts.config, "CARDDAV_SERVER", BASE)
    monkeypatch.setattr(contacts.config, "CALDAV_SERVER", "https://caldav.icloud.com")
    monkeypatch.setattr(calendar.config, "EMAIL_SEND_ALLOWLIST", frozenset())

    def no_network(*args, **kwargs):
        raise AssertionError("Unexpected live transport in DAV security test")

    monkeypatch.setattr(requests.Session, "request", no_network)
    monkeypatch.setattr(calendar.smtplib, "SMTP", no_network)
    monkeypatch.setattr(mail, "_get_imap_client", no_network)


def _response(body="", status=207, **headers):
    response = requests.Response()
    response.status_code = status
    response._content = body.encode("utf-8")
    response.encoding = "utf-8"
    response.headers.update(headers)
    return response


def _xml(stage, href):
    href_xml = f"<d:href>{escape(href)}</d:href>" if href is not None else ""
    if stage == "principal":
        contents = f"<d:current-user-principal>{href_xml}</d:current-user-principal>"
    elif stage == "home":
        contents = f"<card:addressbook-home-set>{href_xml}</card:addressbook-home-set>"
    elif stage == "book":
        contents = (
            f"{href_xml}<d:propstat><d:prop><d:displayname>Contacts</d:displayname>"
            "<d:resourcetype><card:addressbook/></d:resourcetype></d:prop></d:propstat>"
        )
    else:
        contents = (
            f"{href_xml}<d:propstat><d:prop><card:address-data>{escape(VCARD)}</card:address-data>"
            '<d:getetag>"etag"</d:getetag></d:prop></d:propstat>'
        )
    return (
        '<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">'
        f"<d:response>{contents}</d:response></d:multistatus>"
    )


@pytest.mark.parametrize(
    "url",
    [
        CARD,
        "https://p12-contacts.icloud.com.cn/123/card.vcf",
        "https://contacts.me.com/card.vcf",
        "https://P72-CONTACTS.ICLOUD.COM./123/card.vcf",
    ],
)
def test_carddav_accepts_trusted_regional_hosts(url):
    assert contacts._ensure_carddav_url(url) == url


def test_carddav_accepts_only_the_configured_custom_host(monkeypatch):
    monkeypatch.setattr(contacts.config, "CARDDAV_SERVER", "https://dav.example.test/contacts")
    monkeypatch.setattr(contacts.config, "CALDAV_SERVER", "https://calendar.example.test")
    assert contacts._ensure_carddav_url("https://dav.example.test/cards/")
    for url in ("https://other.dav.example.test/cards/", "https://calendar.example.test/cards/"):
        with pytest.raises(ValueError, match="untrusted host"):
            contacts._ensure_carddav_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://attacker.test/card.vcf",
        "https://icloud.com.attacker.test/card.vcf",
        "https://evilicloud.com/card.vcf",
        "https://contacts.icloud.com.cn.attacker.test/card.vcf",
        "http://contacts.icloud.com/card.vcf",
        "ftp://contacts.icloud.com/card.vcf",
        "https://user:secret@contacts.icloud.com/card.vcf",
        "https://@contacts.icloud.com/card.vcf",
        "https://contacts.icloud.com:443/card.vcf",
        "https://contacts.icloud.com:8443/card.vcf",
        "https://contacts.icloud.com:/card.vcf",
        "https://127.0.0.1/card.vcf",
        "https://[::1]/card.vcf",
        "https://2130706433/card.vcf",
        "https://127.1/card.vcf",
        "https://contacts.icloud.com%2e.attacker.test/card.vcf",
        "https://contacts.icloud.com\\@attacker.test/card.vcf",
        "https://contacts.icloud.com\n.attacker.test/card.vcf",
        "https://-bad.icloud.com/card.vcf",
        "https://bad..icloud.com/card.vcf",
        "https://contacts.icloud.com/card.vcf#fragment",
        "//contacts.icloud.com/card.vcf",
        "",
    ],
)
def test_carddav_rejects_bad_endpoints_before_sending(url):
    session = Mock()
    with pytest.raises(ValueError):
        contacts._carddav_request(session, "GET", url)
    session.request.assert_not_called()


@pytest.mark.parametrize("server", ["https://127.0.0.1", "https://127.1", "http://dav.test", "https://dav.test:443"])
def test_carddav_configuration_cannot_allow_unsafe_endpoints(monkeypatch, server):
    monkeypatch.setattr(contacts.config, "CARDDAV_SERVER", server)
    session = Mock()
    with pytest.raises(ValueError):
        contacts._carddav_request(session, "PROPFIND", server)
    session.request.assert_not_called()


_STAGES = {
    "principal": contacts._discover_principal,
    "home": contacts._discover_addressbook_home,
    "book": contacts._list_addressbooks,
    "card": contacts._fetch_all_vcards,
}


@pytest.mark.parametrize("stage", _STAGES)
@pytest.mark.parametrize(
    "href",
    [
        "https://attacker.test/leak",
        "//attacker.test/leak",
        "http://p72-contacts.icloud.com/leak",
        "https://user:secret@contacts.icloud.com/leak",
        "https://contacts.icloud.com:8443/leak",
        "https://127.0.0.1/leak",
        "https://icloud.com.attacker.test/leak",
        "https://contacts.icloud.com\n.attacker.test/leak",
        None,
    ],
)
def test_every_discovered_href_is_validated(stage, href):
    session = Mock()
    session.request.return_value = _response(_xml(stage, href))
    with pytest.raises(ValueError):
        _STAGES[stage](session, BASE)
    session.request.assert_called_once()
    assert session.request.call_args.args[1] == BASE
    assert session.request.call_args.kwargs["allow_redirects"] is False


def test_discovery_preserves_relative_hrefs_and_regional_shards():
    principal = "https://p72-contacts.icloud.com/123/principal/"
    home = "https://p72-contacts.icloud.com/123/carddavhome/"
    regional_card = "https://p12-contacts.icloud.com.cn/123/card/one.vcf"
    session = Mock()
    session.request.side_effect = [
        _response(_xml("principal", principal)),
        _response(_xml("home", "../carddavhome/")),
        _response(_xml("book", "card/")),
        _response(_xml("card", regional_card)),
    ]
    book = contacts._default_addressbook_url(session)
    assert book == BOOK
    cards = contacts._fetch_all_vcards(session, book)
    assert cards == [{"url": regional_card, "data": VCARD, "etag": '"etag"'}]
    assert [call.args[:2] for call in session.request.call_args_list] == [
        ("PROPFIND", BASE), ("PROPFIND", principal), ("PROPFIND", home), ("REPORT", BOOK)
    ]
    assert all(call.kwargs["allow_redirects"] is False for call in session.request.call_args_list)


@pytest.mark.parametrize("method", ["PROPFIND", "REPORT", "GET", "PUT", "DELETE"])
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("target", ["https://attacker.test/leak", "http://contacts.icloud.com/leak", "/elsewhere"])
def test_carddav_never_follows_redirects(method, status, target):
    session = Mock()
    session.request.return_value = _response(status=status, Location=target)
    with pytest.raises(ValueError, match="redirects"):
        contacts._carddav_request(session, method, BASE)
    session.request.assert_called_once_with(method, BASE, timeout=contacts.TIMEOUT, allow_redirects=False)


def test_authenticated_session_does_not_replay_credentials_on_redirect(monkeypatch):
    sent = []

    class RecordingAdapter(requests.adapters.BaseAdapter):
        def send(self, request, **kwargs):
            sent.append(request)
            response = _response(status=307, Location="https://attacker.test/leak")
            response.request = request
            response.url = request.url
            return response

        def close(self):
            pass

    session = contacts._get_carddav_session("me@icloud.com", "test-password")
    session.trust_env = False
    session.mount("https://", RecordingAdapter())
    session.mount("http://", RecordingAdapter())
    monkeypatch.setattr(requests.Session, "request", _SESSION_REQUEST)
    with pytest.raises(ValueError, match="redirects"):
        contacts._carddav_request(session, "PROPFIND", BASE)
    assert len(sent) == 1
    assert sent[0].url == BASE + "/"
    assert sent[0].headers["Authorization"].startswith("Basic ")


@pytest.mark.parametrize("operation,methods", [("get", ["GET"]), ("update", ["GET", "PUT"]), ("delete", ["DELETE"]), ("create", ["PUT"])])
def test_contact_operations_use_checked_nonredirecting_transport(monkeypatch, operation, methods):
    session = Mock()
    session.request.return_value = _response(VCARD, status=200, ETag='"etag"')
    monkeypatch.setattr(contacts, "require_auth", lambda: ("me@icloud.com", "test-password"))
    monkeypatch.setattr(contacts, "_get_carddav_session", lambda *args: session)
    monkeypatch.setattr(contacts, "_default_addressbook_url", lambda session: BOOK)
    if operation == "create":
        result = contacts.create_contact("Jane Doe")
        assert result["url"].startswith(BOOK)
    elif operation == "update":
        contacts.update_contact(CARD, name="Updated")
        assert session.request.call_args.kwargs["headers"]["If-Match"] == '"etag"'
    else:
        getattr(contacts, f"{operation}_contact")(CARD)
    assert [call.args[0] for call in session.request.call_args_list] == methods
    assert all(call.kwargs["allow_redirects"] is False for call in session.request.call_args_list)


def _deletion_event(monkeypatch, attendees):
    event = Mock()
    event.vobject_instance = vobject.readOne(ICAL)
    vevent = event.vobject_instance.vevent
    for attendee in list(vevent.attendee_list):
        vevent.remove(attendee)
    for address in attendees:
        vevent.add("attendee").value = "mailto:" + address
    monkeypatch.setattr(calendar, "require_auth", lambda: ("me@icloud.com", "test-password"))
    monkeypatch.setattr(calendar, "_client_for_url", lambda *args: Mock())
    monkeypatch.setattr(calendar.caldav, "CalendarObjectResource", lambda **kwargs: event)
    return event


@pytest.mark.parametrize("blocked", ["other@blocked.test", "not-an-address"])
def test_delete_event_validates_all_stored_attendees_before_any_side_effect(monkeypatch, blocked):
    monkeypatch.setattr(calendar.config, "EMAIL_SEND_ALLOWLIST", frozenset({"@ok.test"}))
    event = _deletion_event(monkeypatch, ["friend@ok.test", blocked])
    notify = Mock()
    monkeypatch.setattr(calendar, "_notify_attendees", notify)
    with pytest.raises((PermissionError, ValueError)):
        calendar.delete_event(EVENT)
    event.load.assert_called_once()
    event.delete.assert_not_called()
    notify.assert_not_called()


def test_delete_event_notifies_allowed_attendees_after_deletion(monkeypatch):
    monkeypatch.setattr(calendar.config, "EMAIL_SEND_ALLOWLIST", frozenset({"@ok.test"}))
    event = _deletion_event(monkeypatch, ["friend@ok.test"])

    def notify(*args):
        event.delete.assert_called_once()
        assert args[2] == ["friend@ok.test"]
        assert args[-1] == "CANCEL"
        return []

    monkeypatch.setattr(calendar, "_notify_attendees", notify)
    result = calendar.delete_event(EVENT)
    assert result["status"] == "success"


def test_notify_validates_complete_recipient_set_before_first_send(monkeypatch):
    monkeypatch.setattr(calendar.config, "EMAIL_SEND_ALLOWLIST", frozenset({"@ok.test"}))
    send = Mock()
    monkeypatch.setattr(calendar, "_send_calendar_invitation", send)
    with pytest.raises(PermissionError, match="EMAIL_SEND_ALLOWLIST"):
        calendar._notify_attendees(
            "me@icloud.com", "test-password", ["friend@ok.test", "other@blocked.test"],
            ICAL, "Test", "start", "end", None, "CANCEL"
        )
    send.assert_not_called()


def test_calendar_smtp_verifies_certificate_and_hostname(monkeypatch):
    smtp = Mock()
    monkeypatch.setattr(calendar.smtplib, "SMTP", lambda *args, **kwargs: smtp)
    monkeypatch.setattr(mail, "_get_imap_client", lambda *args: Mock())
    monkeypatch.setattr(mail, "_append_to_sent", Mock())
    monkeypatch.setattr(mail, "_close_imap_client", Mock())
    calendar._send_calendar_invitation(
        "me@icloud.com", "test-password", "friend@ok.test", ICAL, "Test", "start", "end"
    )
    context = smtp.starttls.call_args.kwargs["context"]
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    smtp.login.assert_called_once_with("me@icloud.com", "test-password")
    smtp.send_message.assert_called_once()
    assert [call[0] for call in smtp.method_calls] == ["starttls", "login", "send_message", "quit"]


def test_calendar_smtp_tls_failure_never_sends_credentials_or_mail(monkeypatch):
    smtp = Mock()
    smtp.starttls.side_effect = ssl.SSLCertVerificationError("certificate verification failed")
    monkeypatch.setattr(calendar.smtplib, "SMTP", lambda *args, **kwargs: smtp)
    with pytest.raises(ssl.SSLCertVerificationError):
        calendar._send_calendar_invitation(
            "me@icloud.com", "test-password", "friend@ok.test", ICAL, "Test", "start", "end"
        )
    smtp.login.assert_not_called()
    smtp.send_message.assert_not_called()
    smtp.quit.assert_called_once()


def test_calendar_tls_context_failure_closes_socket_without_authentication(monkeypatch):
    smtp = Mock()
    smtp.quit.side_effect = OSError("connection unavailable")
    monkeypatch.setattr(calendar.smtplib, "SMTP", lambda *args, **kwargs: smtp)
    monkeypatch.setattr(calendar.ssl, "create_default_context", Mock(side_effect=OSError("no CA store")))
    with pytest.raises(OSError, match="no CA store"):
        calendar._send_calendar_invitation(
            "me@icloud.com", "test-password", "friend@ok.test", ICAL, "Test", "start", "end"
        )
    smtp.starttls.assert_not_called()
    smtp.login.assert_not_called()
    smtp.send_message.assert_not_called()
    smtp.close.assert_called_once()
