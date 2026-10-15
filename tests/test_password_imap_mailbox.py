from __future__ import annotations

import email.utils
import pathlib
import sys
import time
from types import SimpleNamespace

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[1]
CORE = ROOT / "core"
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

import account_vault
import accounts_pool
import email_provider
from mailbox_transport import (
    IMAP_PASSWORD_CLIENT_ID,
    mailbox_display_kind,
    parse_imap_password_endpoint,
)


def test_notletters_two_field_import_is_stored_as_explicit_password_imap(tmp_path) -> None:
    vault = account_vault.AccountVault(
        data_dir=tmp_path / "vault",
        outlook_file=tmp_path / "outlook.txt",
        icloud_file=tmp_path / "icloud.txt",
    )
    result = vault.import_text("owner@belettersmail.com----mail-password")
    assert result["added"] == 1
    account = vault.get_account("owner@belettersmail.com")
    assert account.kind == "outlook"  # backward-compatible database shape
    assert account.password == "mail-password"
    assert account.client_id == IMAP_PASSWORD_CLIENT_ID
    endpoint = parse_imap_password_endpoint(account.refresh_token, account.client_id)
    assert endpoint is not None
    assert (endpoint.host, endpoint.port, endpoint.provider) == (
        "imap.notletters.com", 993, "submail"
    )
    assert mailbox_display_kind(account.kind, account.client_id, account.refresh_token) == "submail"


@pytest.mark.parametrize(
    "line",
    [
        "owner@onelettersmail.com----mail-password----submail",
        "owner@notlettersmail.com:mail:password:submail",
    ],
)
def test_notletters_documented_shipment_formats_are_accepted(line: str) -> None:
    parsed = account_vault.parse_account_line(line)
    assert parsed.email.startswith("owner@")
    assert parsed.password in {"mail-password", "mail:password"}
    assert parse_imap_password_endpoint(parsed.refresh_token, parsed.client_id)


def test_unknown_two_field_password_mailbox_remains_rejected() -> None:
    with pytest.raises(ValueError, match="must contain 4 fields"):
        account_vault.parse_account_line("owner@example.com----password")




class _FakePasswordImap:
    login_args: tuple[str, str] | None = None

    def __init__(self, host, port, **_kwargs):
        assert (host, port) == ("imap.notletters.com", 993)
        self.sock = SimpleNamespace(settimeout=lambda _seconds: None)

    def login(self, email, password):
        type(self).login_args = (email, password)
        return "OK", [b"logged in"]

    def list(self):
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"']

    def select(self, mailbox, readonly=False):
        assert mailbox == "INBOX"
        assert readonly is True
        return "OK", [b"1"]

    def search(self, *_args):
        return "OK", [b"1"]

    def response(self, _name):
        return "UIDVALIDITY", [b"1"]

    def uid(self, command, *args):
        return self.search(*args) if command == "search" else self.fetch(*args)

    def fetch(self, _message_id, _query):
        now = email.utils.formatdate(time.time(), localtime=False, usegmt=True)
        raw = (
            "From: noreply@logicc.com\r\n"
            "Subject: Your temporary Logicc verification code\r\n"
            f"Date: {now}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n\r\n"
            "Enter this temporary verification code to continue: 314159\r\n"
        ).encode()
        metadata = b'1 (UID 1 INTERNALDATE ' + email_provider.imaplib.Time2Internaldate(time.time()).encode()
        return "OK", [(metadata, raw), b")"]

    def logout(self):
        return "BYE", [b"logout"]


def test_fetch_otp_auto_routes_password_imap_without_microsoft_oauth(monkeypatch) -> None:
    monkeypatch.setattr(email_provider.imaplib, "IMAP4_SSL", _FakePasswordImap)
    code = email_provider.fetch_otp(
        "owner@belettersmail.com",
        "imap+ssl://imap.notletters.com:993?provider=submail",
        IMAP_PASSWORD_CLIENT_ID,
        method="graph",  # global default must be overridden by transport metadata
        password="mail-password",
        timeout=5,
        after_ts=time.time() - 5,
    )
    assert code == "314159"
    assert _FakePasswordImap.login_args == (
        "owner@belettersmail.com", "mail-password"
    )


def test_password_imap_account_requires_both_transport_and_password() -> None:
    missing = accounts_pool.Account(
        email="owner@belettersmail.com",
        kind="outlook",
        password="",
        client_id=IMAP_PASSWORD_CLIENT_ID,
        refresh_token="imap+ssl://imap.notletters.com:993?provider=submail",
    )
    complete = accounts_pool.Account(**{**missing.__dict__, "password": "mail-password"})
    assert missing.has_otp_creds is False
    assert complete.has_otp_creds is True




