import json
import logging
import time
from email.message import EmailMessage

import pytest

import email_provider as provider
from core import domain_mailbox
from protocol_budget import MailboxTimeout


@pytest.mark.parametrize("text,sender,expected", [
    ("Logicc verification code is 123456", "", "123456"),
    ("Your verification code: 123456", "Logicc <noreply@logicc.com>", "123456"),
    ("Your verification code: 123456", "noreply@auth.logicc.com", "123456"),
    ("Logicc verification code: 123456", "noreply@accounts.clerk.com", "123456"),
    ("AnotherApp verification code: 654321", "noreply@clerk.com", None),
    ("ChatGPT verification code: 654321", "noreply@tm.openai.com", None),
    ("OpenAI verification code: 654321", "", None),
    ("Logicc verification code: 123456", "noreply@logicc.com.attacker.invalid", None),
    ("Logicc verification code: 123456", "Logicc <noreply@unrelated.example>", None),
    ("123456", "", None),
    ("Logicc order 123456", "", None),
    ("Logicc discount code 123456", "noreply@logicc.com", None),
    ("Logicc verification code: #123456", "", None),
    ("Logicc verification code: https://tracker.example/123456", "", None),
    ("Logicc verification code: 1234567", "", None),
    ("Logicc verification code 111111\nChatGPT verification code 222222", "", None),
    ("Logicc 验证码：123456", "", "123456"),
    ("123456 ist Ihr Bestätigungscode", "noreply@logicc.com", "123456"),
    ("Logicc Bestätigungscode: 123456", "noreply@accounts.clerk.com", "123456"),
    ("123456 ist Ihr Bestätigungscode", "noreply@other.example", None),
    ("123456 ist Ihr Bestätigungscode", "noreply@clerk.com", None),
    ("Logicc <style>verification code 999999</style><p>verification code <b>123456</b></p>", "", "123456"),
])
def test_logicc_only_candidates(text, sender, expected):
    assert provider._extract_otp(text, sender=sender) == expected


class Response:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return json.dumps(self.payload).encode()

    def close(self):
        pass


def test_graph_skips_gpt_and_unbranded_shared_clerk(monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(provider, "_get_access_token_graph", lambda *a, **k: "test-token")
    messages = [
        {"from": {"emailAddress": {"address": "noreply@tm.openai.com"}},
         "subject": "ChatGPT verification code", "body": {"content": "654321"}},
        {"from": {"emailAddress": {"address": "noreply@clerk.com"}},
         "subject": "AnotherApp verification code", "body": {"content": "654321"}},
        {"from": {"emailAddress": {"address": "noreply@clerk.com"}},
         "subject": "Logicc verification code", "body": {"content": "123456"}},
    ]
    for index, message in enumerate(messages):
        message["id"] = str(index)
    monkeypatch.setattr(provider.urllib.request, "urlopen", lambda *a, **k: Response({"value": messages}))
    assert provider.fetch_otp_graph("owner@example.test", "test-refresh", "test-client", timeout=1) == "123456"
    assert all(secret not in caplog.text for secret in ("123456", "654321", "test-token", "test-refresh"))


def test_relay_rejects_gpt_and_bare_code_then_accepts_logicc(monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    messages = iter(["ChatGPT verification code 654321", "111111", "Logicc verification code 123456"])
    monkeypatch.setattr(provider, "_read_relay", lambda *a, **k: next(messages))
    assert provider.fetch_otp_relay("https://relay.example.test/logicc", timeout=1,
                                   poll_interval=0, require_fresh=False) == "123456"
    assert "123456" not in caplog.text and "654321" not in caplog.text


def test_relay_empty_snapshot_does_not_consume_first_new_code(monkeypatch):
    messages = iter(["", "ChatGPT verification code 654321", "Logicc verification code 123456"])
    monkeypatch.setattr(provider, "_read_relay", lambda *a, **k: next(messages))
    assert provider.fetch_otp_relay("https://relay.example.test/fresh", timeout=1,
                                   poll_interval=0, require_fresh=True) == "123456"


def test_relay_excludes_old_baseline_and_explicit_excluded_codes(monkeypatch):
    messages = iter(["Logicc verification code 123456", "Logicc verification code 222222",
                     "Logicc verification code 333333"])
    monkeypatch.setattr(provider, "_read_relay", lambda *a, **k: next(messages))
    assert provider.fetch_otp_relay("https://relay.example.test/baseline", timeout=1,
        poll_interval=0, require_fresh=True, excluded_otps={"222222"}) == "333333"


def test_relay_only_wrong_target_times_out(monkeypatch):
    monkeypatch.setattr(provider, "_read_relay", lambda *a, **k: "ChatGPT verification code 654321")
    assert provider.fetch_otp("owner@example.test", "https://relay.example.test/wrong",
                             method="relay", timeout=0.001) == ""


def test_domain_mailbox_filters_individual_messages_and_decodes_mime(monkeypatch):
    credential = type("Credential", (), {"provider": object(), "token": "test-token", "address": "owner@example.test"})()
    config = type("Config", (), {"parse_inbox_url": lambda self, url: credential})()
    monkeypatch.setattr(domain_mailbox, "get_domain_mailbox_config", lambda **kw: config)
    message = EmailMessage()
    message["From"] = "noreply@logicc.com"
    message["Subject"] = "Logicc verification code"
    message.set_content("Your verification code is 123456", cte="base64")
    messages = [
        {"created_at": "2026-10-15T12:02:00Z", "raw": "ChatGPT verification code 654321"},
        {"created_at": "2026-10-15T12:01:00Z", "raw": message.as_string()},
    ]
    client = type("Client", (), {"__init__": lambda self, *a, **kw: None,
                                "list_messages": lambda self, *a, **kw: messages})
    monkeypatch.setattr(domain_mailbox, "DomainMailboxClient", client)
    text = domain_mailbox.read_managed_inbox_url("https://inbox.example.test/owned")
    assert "654321" not in text
    assert provider._extract_otp(text) == "123456"


def test_domain_unrelated_message_cannot_borrow_logicc_branding(monkeypatch):
    credential = type("Credential", (), {"provider": object(), "token": "test-token", "address": "owner@example.test"})()
    config = type("Config", (), {"parse_inbox_url": lambda self, url: credential})()
    monkeypatch.setattr(domain_mailbox, "get_domain_mailbox_config", lambda **kw: config)
    messages = [{"raw": "AnotherApp verification code 654321", "created_at": "2"},
                {"raw": "Logicc newsletter, no code", "created_at": "1"}]
    client = type("Client", (), {"__init__": lambda self, *a, **kw: None,
                                "list_messages": lambda self, *a, **kw: messages})
    monkeypatch.setattr(domain_mailbox, "DomainMailboxClient", client)
    assert domain_mailbox.read_managed_inbox_url("https://inbox.example.test/owned") == ""
