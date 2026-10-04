"""CardDAV operations for iCloud contacts (direct HTTP/WebDAV, RFC 6352)."""

import ipaddress
import logging
import re
import uuid
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests
import vobject
from defusedxml import ElementTree as ET
from requests.auth import HTTPBasicAuth

from .auth import require_auth
from .config import config
from .mail_utils import clean_rich_text

logger = logging.getLogger(__name__)

NS = {"d": "DAV:", "card": "urn:ietf:params:xml:ns:carddav"}
TIMEOUT = 30
_CARDDAV_DOMAINS = ("icloud.com", "icloud.com.cn", "me.com")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def _carddav_host(url: str) -> str:
    """Parse a credential-free HTTPS endpoint without permissive URL rewriting."""
    if not isinstance(url, str) or not url:
        raise ValueError("CardDAV URL/ID is empty")
    if any(ord(char) <= 32 or ord(char) == 127 for char in url) or "\\" in url:
        raise ValueError("CardDAV URL must not contain whitespace, controls or backslashes")
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().removesuffix(".")
    except ValueError as exc:
        raise ValueError("Invalid CardDAV URL") from exc
    if parsed.scheme.lower() != "https" or not host:
        raise ValueError("CardDAV URL must be a full https URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("CardDAV URL must not contain credentials")
    if ":" in parsed.netloc:
        raise ValueError("CardDAV URL must not contain a port or IP literal")
    if parsed.fragment:
        raise ValueError("CardDAV URL must not contain a fragment")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("CardDAV URL must not contain an IP literal")
    labels = host.split(".")
    if (
        len(host) > 253
        or not all(_DNS_LABEL.fullmatch(label) for label in labels)
        or not labels[-1][0].isalpha()
    ):
        raise ValueError("CardDAV URL must contain a valid DNS hostname")
    return host


def _ensure_carddav_url(url: str) -> str:
    """Allow the configured server and iCloud shards, including China mainland."""
    host = _carddav_host(url)
    configured_host = _carddav_host(config.CARDDAV_SERVER)
    if host != configured_host and not any(
        host == domain or host.endswith("." + domain) for domain in _CARDDAV_DOMAINS
    ):
        raise ValueError(f"Refusing CardDAV URL on untrusted host {host!r}")
    return url


def _carddav_href(base_url: str, href: str | None) -> str:
    """Resolve and validate every server-supplied href before retaining it."""
    _ensure_carddav_url(base_url)
    if not href:
        raise ValueError("CardDAV response is missing a resource href")
    # urljoin strips some control characters; reject them before resolution.
    if any(ord(char) <= 32 or ord(char) == 127 for char in href) or "\\" in href:
        raise ValueError("Invalid CardDAV resource href")
    return _ensure_carddav_url(urljoin(base_url, href))


def _carddav_request(
    session: requests.Session, method: str, url: str, **kwargs: Any
) -> requests.Response:
    """Never send Basic auth to an unchecked endpoint or follow a redirect."""
    url = _ensure_carddav_url(url)
    response = session.request(
        method, url, timeout=TIMEOUT, allow_redirects=False, **kwargs
    )
    if 300 <= response.status_code < 400:
        raise ValueError("CardDAV redirects are not allowed")
    response.raise_for_status()
    return response


def _get_carddav_session(email: str, password: str) -> requests.Session:
    session = requests.Session()
    session.auth = HTTPBasicAuth(email, password)
    session.headers.update(
        {"Content-Type": "text/xml; charset=utf-8", "User-Agent": "iCloud-MCP/0.2"}
    )
    return session


def _discover_principal(session: requests.Session, base_url: str) -> str:
    body = """<?xml version="1.0" encoding="UTF-8"?>
    <d:propfind xmlns:d="DAV:"><d:prop><d:current-user-principal/></d:prop></d:propfind>"""
    response = _carddav_request(
        session, "PROPFIND", base_url, data=body, headers={"Depth": "0"}
    )
    root = ET.fromstring(response.content)
    elem = root.find(".//d:current-user-principal/d:href", NS)
    if elem is not None and elem.text:
        return _carddav_href(base_url, elem.text)
    raise ValueError("Could not discover CardDAV principal URL")


def _discover_addressbook_home(session: requests.Session, principal_url: str) -> str:
    body = """<?xml version="1.0" encoding="UTF-8"?>
    <d:propfind xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
        <d:prop><card:addressbook-home-set/></d:prop>
    </d:propfind>"""
    response = _carddav_request(
        session, "PROPFIND", principal_url, data=body, headers={"Depth": "0"}
    )
    root = ET.fromstring(response.content)
    elem = root.find(".//card:addressbook-home-set/d:href", NS)
    if elem is not None and elem.text:
        return _carddav_href(principal_url, elem.text)
    raise ValueError("Could not discover addressbook home URL")


def _list_addressbooks(session: requests.Session, home_url: str) -> list[dict[str, str]]:
    body = """<?xml version="1.0" encoding="UTF-8"?>
    <d:propfind xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
        <d:prop><d:displayname/><d:resourcetype/><card:addressbook-description/></d:prop>
    </d:propfind>"""
    response = _carddav_request(
        session, "PROPFIND", home_url, data=body, headers={"Depth": "1"}
    )
    root = ET.fromstring(response.content)

    addressbooks = []
    for resp in root.findall(".//d:response", NS):
        href = resp.find("d:href", NS)
        rtype = resp.find(".//d:resourcetype", NS)
        if rtype is None or rtype.find("card:addressbook", NS) is None:
            continue
        name = resp.find(".//d:displayname", NS)
        addressbooks.append(
            {
                "url": _carddav_href(home_url, href.text if href is not None else None),
                "name": name.text if name is not None and name.text else "Unnamed",
            }
        )
    return addressbooks


def _default_addressbook_url(session: requests.Session) -> str:
    principal_url = _discover_principal(session, config.CARDDAV_SERVER)
    home_url = _discover_addressbook_home(session, principal_url)
    addressbooks = _list_addressbooks(session, home_url)
    if not addressbooks:
        raise ValueError("No addressbooks found for this account")
    url = addressbooks[0]["url"]
    return url if url.endswith("/") else url + "/"


def _fetch_all_vcards(session: requests.Session, addressbook_url: str) -> list[dict[str, Any]]:
    body = """<?xml version="1.0" encoding="UTF-8"?>
    <card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
        <d:prop><d:getetag/><card:address-data/></d:prop>
    </card:addressbook-query>"""
    response = _carddav_request(
        session, "REPORT", addressbook_url, data=body, headers={"Depth": "1"}
    )

    vcards = []
    root = ET.fromstring(response.content)
    for resp in root.findall(".//d:response", NS):
        href = resp.find("d:href", NS)
        data = resp.find(".//card:address-data", NS)
        etag = resp.find(".//d:getetag", NS)
        if data is not None and data.text:
            vcards.append(
                {
                    "url": _carddav_href(addressbook_url, href.text if href is not None else None),
                    "data": data.text,
                    "etag": etag.text if etag is not None else "",
                }
            )
    return vcards


def _format_address(adr: Any) -> str:
    value = getattr(adr, "value", None)
    if value is None:
        return ""
    parts = [
        getattr(value, "street", ""),
        getattr(value, "city", ""),
        getattr(value, "region", ""),
        getattr(value, "code", ""),
        getattr(value, "country", ""),
    ]
    joined = ", ".join(str(p).replace("\n", " ").strip() for p in parts if p)
    return joined or str(value).replace("\n", " ").strip()


def _vcard_to_dict(vcard: Any, url: str) -> dict[str, Any]:
    def text(attr: str) -> str:
        prop = getattr(vcard, attr, None)
        return str(prop.value) if prop is not None and prop.value else ""

    contact: dict[str, Any] = {
        "id": url,
        "url": url,
        "name": text("fn"),
        "phones": [],
        "emails": [],
        "addresses": [],
        "organization": "",
        "title": text("title"),
        "notes": clean_rich_text(text("note")),
    }
    org = getattr(vcard, "org", None)
    if org is not None and org.value:
        contact["organization"] = str(org.value[0]) if isinstance(org.value, list) else str(org.value)
    for tel in getattr(vcard, "tel_list", []) or []:
        if getattr(tel, "value", None):
            contact["phones"].append(str(tel.value))
    for em in getattr(vcard, "email_list", []) or []:
        if getattr(em, "value", None):
            contact["emails"].append(str(em.value))
    for adr in getattr(vcard, "adr_list", []) or []:
        try:
            formatted = _format_address(adr)
        except Exception:
            continue
        if formatted:
            contact["addresses"].append(formatted)
    return contact


def list_contacts(limit: int | None = None) -> list[dict[str, Any]]:
    email, password = require_auth()
    session = _get_carddav_session(email, password)
    addressbook_url = _default_addressbook_url(session)

    result = []
    for item in _fetch_all_vcards(session, addressbook_url):
        if limit and len(result) >= limit:
            break
        try:
            vcard = vobject.readOne(item["data"])
        except Exception as e:
            logger.debug("Skipping unparsable vCard (%s)", type(e).__name__)
            continue
        contact = _vcard_to_dict(vcard, item["url"])
        if contact["name"] or contact["phones"] or contact["emails"]:
            result.append(contact)
    return result


def get_contact(contact_id: str) -> dict[str, Any]:
    contact_id = _ensure_carddav_url(contact_id)
    email, password = require_auth()
    session = _get_carddav_session(email, password)
    response = _carddav_request(session, "GET", contact_id)
    return _vcard_to_dict(vobject.readOne(response.text), contact_id)


def _apply_fields(
    vcard: Any,
    phones: list[str] | None,
    emails: list[str] | None,
    addresses: list[str] | None,
    organization: str | None,
    title: str | None,
    notes: str | None = None,
) -> None:
    """Apply partial updates. List fields replace existing values; entries whose value is
    unchanged keep their original parameters (e.g. TYPE=HOME, custom iOS labels)."""
    if phones is not None:
        _replace_entries(vcard, "tel", phones, default_type="CELL")
    if emails is not None:
        _replace_entries(vcard, "email", emails, default_type="INTERNET")
    if addresses is not None:
        for adr in list(getattr(vcard, "adr_list", []) or []):
            vcard.remove(adr)
        for addr in addresses:
            adr = vcard.add("adr")
            adr.value = vobject.vcard.Address(street=addr)
    if organization is not None:
        if hasattr(vcard, "org"):
            vcard.org.value = [organization]
        else:
            vcard.add("org").value = [organization]
    if title is not None:
        if hasattr(vcard, "title"):
            vcard.title.value = title
        else:
            vcard.add("title").value = title
    if notes is not None:
        if hasattr(vcard, "note"):
            vcard.note.value = notes
        else:
            vcard.add("note").value = notes


def _normalized(value: str) -> str:
    return "".join(ch for ch in str(value).lower() if ch not in " -()\u00a0")


def _replace_entries(vcard: Any, prop: str, values: list[str], default_type: str) -> None:
    existing = list(getattr(vcard, f"{prop}_list", []) or [])
    params_by_value = {_normalized(item.value): dict(item.params) for item in existing if item.value}
    for item in existing:
        vcard.remove(item)
    for value in values:
        entry = vcard.add(prop)
        entry.value = value
        preserved = params_by_value.get(_normalized(value))
        if preserved:
            entry.params.update(preserved)
        else:
            entry.type_param = default_type


def _split_name(name: str) -> Any:
    parts = name.strip().split()
    if len(parts) >= 2:
        return vobject.vcard.Name(family=parts[-1], given=" ".join(parts[:-1]))
    return vobject.vcard.Name(family="", given=name.strip())


def create_contact(
    name: str,
    phones: list[str] | None = None,
    emails: list[str] | None = None,
    addresses: list[str] | None = None,
    organization: str | None = None,
    title: str | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    email, password = require_auth()
    session = _get_carddav_session(email, password)
    addressbook_url = _default_addressbook_url(session)

    vcard = vobject.vCard()
    vcard.add("fn").value = name
    vcard.add("n").value = _split_name(name)
    unique_id = str(uuid.uuid4())
    vcard.add("uid").value = unique_id
    _apply_fields(vcard, phones, emails, addresses, organization, title, notes)

    contact_url = f"{addressbook_url}{unique_id}.vcf"
    _carddav_request(
        session,
        "PUT",
        contact_url,
        data=vcard.serialize().encode("utf-8"),
        headers={"Content-Type": "text/vcard; charset=utf-8", "If-None-Match": "*"},
    )
    return _vcard_to_dict(vcard, contact_url)


def update_contact(
    contact_id: str,
    name: str | None = None,
    phones: list[str] | None = None,
    emails: list[str] | None = None,
    addresses: list[str] | None = None,
    organization: str | None = None,
    title: str | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    contact_id = _ensure_carddav_url(contact_id)
    email, password = require_auth()
    session = _get_carddav_session(email, password)

    response = _carddav_request(session, "GET", contact_id)
    etag = response.headers.get("ETag", "")
    vcard = vobject.readOne(response.text)

    if name:
        if hasattr(vcard, "fn"):
            vcard.fn.value = name
        else:
            vcard.add("fn").value = name
        if hasattr(vcard, "n"):
            vcard.n.value = _split_name(name)
    _apply_fields(vcard, phones, emails, addresses, organization, title, notes)

    headers = {"Content-Type": "text/vcard; charset=utf-8"}
    if etag:
        headers["If-Match"] = etag
    _carddav_request(
        session, "PUT", contact_id, data=vcard.serialize().encode("utf-8"), headers=headers
    )
    return _vcard_to_dict(vcard, contact_id)


def delete_contact(contact_id: str) -> dict[str, str]:
    contact_id = _ensure_carddav_url(contact_id)
    email, password = require_auth()
    session = _get_carddav_session(email, password)
    _carddav_request(session, "DELETE", contact_id)
    return {"status": "success", "message": f"Contact {contact_id} deleted"}


def search_contacts(query: str, limit: int | None = None) -> list[dict[str, Any]]:
    needle = query.lower().strip()
    digits = "".join(ch for ch in needle if ch.isdigit())
    matches = []
    for contact in list_contacts():
        haystack = [
            contact.get("name", ""),
            contact.get("organization", ""),
            contact.get("notes", ""),
            *contact.get("emails", []),
        ]
        phone_hit = bool(digits) and any(
            digits in "".join(ch for ch in phone if ch.isdigit()) for phone in contact.get("phones", [])
        )
        if phone_hit or any(needle in value.lower() for value in haystack if value):
            matches.append(contact)
            if limit and len(matches) >= limit:
                break
    return matches
