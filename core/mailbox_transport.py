"""Mailbox transport metadata shared by the vault and OTP readers.

The encrypted vault historically stores only two mailbox kinds (Outlook and
iCloud relay).  Password-authenticated IMAP accounts therefore use the
existing Outlook record shape with an explicit transport marker.  This keeps
old databases and exports readable while preventing an IMAP password from
being mistaken for a Microsoft refresh token.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass


IMAP_PASSWORD_CLIENT_ID = "imap-password"
NOTLETTERS_IMAP_HOST = "imap.notletters.com"
NOTLETTERS_IMAP_PORT = 993
NOTLETTERS_PROVIDER = "submail"
NOTLETTERS_DOMAINS = frozenset({
    "belettersmail.com",
    "notlettersmail.com",
    "onelettersmail.com",
})


@dataclass(frozen=True)
class ImapPasswordEndpoint:
    host: str
    port: int = 993
    provider: str = "imap"


def email_domain(email: str) -> str:
    value = str(email or "").strip().casefold()
    return value.rsplit("@", 1)[1] if value.count("@") == 1 else ""


def is_notletters_email(email: str) -> bool:
    return email_domain(email) in NOTLETTERS_DOMAINS


def imap_password_uri(host: str, port: int = 993, *, provider: str = "imap") -> str:
    normalized_host = str(host or "").strip().casefold()
    if not normalized_host or not re.fullmatch(r"[a-z0-9.-]+", normalized_host):
        raise ValueError("invalid IMAP host")
    normalized_port = int(port)
    if not 1 <= normalized_port <= 65535:
        raise ValueError("invalid IMAP port")
    query = urllib.parse.urlencode({"provider": str(provider or "imap").strip().casefold()})
    return f"imap+ssl://{normalized_host}:{normalized_port}?{query}"


def notletters_transport() -> tuple[str, str]:
    return (
        IMAP_PASSWORD_CLIENT_ID,
        imap_password_uri(
            NOTLETTERS_IMAP_HOST,
            NOTLETTERS_IMAP_PORT,
            provider=NOTLETTERS_PROVIDER,
        ),
    )


def parse_imap_password_endpoint(
    refresh_token: str,
    client_id: str = "",
) -> ImapPasswordEndpoint | None:
    value = str(refresh_token or "").strip()
    if not value.startswith("imap+ssl://") and str(client_id or "").strip() != IMAP_PASSWORD_CLIENT_ID:
        return None
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "imap+ssl" or not parsed.hostname:
        raise ValueError("invalid password IMAP transport metadata")
    try:
        port = parsed.port or 993
    except ValueError as exc:
        raise ValueError("invalid password IMAP port") from exc
    provider = urllib.parse.parse_qs(parsed.query).get("provider", ["imap"])[0]
    return ImapPasswordEndpoint(parsed.hostname.casefold(), port, provider or "imap")


def mailbox_display_kind(kind: str, client_id: str = "", refresh_token: str = "") -> str:
    try:
        endpoint = parse_imap_password_endpoint(refresh_token, client_id)
    except ValueError:
        return "imap"
    if endpoint:
        return str(endpoint.provider or "imap").casefold()
    return str(kind or "mail").casefold()


def parse_submail_shipment_line(value: str) -> tuple[str, str] | None:
    """Accept the provider's documented ``email:password:submail`` shape.

    The password portion is greedy so embedded colons remain part of the
    password.  Dashed imports are handled by the account parser itself.
    """
    match = re.fullmatch(r"\s*([^:\s]+@[^:\s]+):(.+):submail\s*", str(value or ""), re.I)
    if not match:
        return None
    return match.group(1).strip(), match.group(2).strip()
