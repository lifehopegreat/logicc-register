from __future__ import annotations

import json
import urllib.parse

from core import domain_mailbox


class _Response:
    def __init__(self, payload: object):
        self.payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode()

    def read(self):
        return self.payload


def _write_config(tmp_path, secret_path):
    path = tmp_path / "mailboxes.json"
    path.write_text(json.dumps({
        "schema_version": 3,
        "default_domain": "alpha.example",
        "providers": {
            "primary-vps": {
                "provider": "vps",
                "label": "Owned mailbox",
                "api_origin": "https://manage.example",
                "admin_token_file": str(secret_path),
                "admin_token_json_key": "admin_api_token",
                "domains": ["alpha.example"],
            }
        },
    }), encoding="utf-8")
    return path


def test_config_uses_secret_reference_and_parses_inbox_url(tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"admin_api_token": "admin-secret"}), encoding="utf-8")
    config = domain_mailbox.DomainMailboxConfig.load(_write_config(tmp_path, secret))
    credential = config.parse_inbox_url(
        "https://inbox.alpha.example/cf-inbox/mailbox-secret/person%40alpha.example"
    )
    assert credential is not None
    assert credential.address == "person@alpha.example"
    assert credential.token == "mailbox-secret"
    assert credential.provider.admin_token() == "admin-secret"
    assert "admin-secret" not in json.dumps(credential.provider.public_metadata())


def test_control_endpoint_accepts_safe_https_base_path(tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"admin_api_token": "admin-secret"}), encoding="utf-8")
    config_path = _write_config(tmp_path, secret)
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    payload["providers"]["primary-vps"]["api_origin"] = "https://gateway.example/domain-mailbox/"
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    config = domain_mailbox.DomainMailboxConfig.load(config_path)
    assert config.provider("primary-vps").api_origin == "https://gateway.example/domain-mailbox"


def test_gateway_host_override_is_validated_published_and_sent(tmp_path, monkeypatch):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"admin_api_token": "admin-secret"}), encoding="utf-8")
    config_path = _write_config(tmp_path, secret)
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    payload["providers"]["primary-vps"].update({
        "api_origin": "https://gateway.example",
        "host_header": "Manage.Alpha.Example.",
    })
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    calls = []

    def fake_urlopen(request, **_kwargs):
        calls.append(request)
        return _Response({"items": [], "count": 0})

    monkeypatch.setattr(domain_mailbox, "_urlopen", fake_urlopen)
    config = domain_mailbox.DomainMailboxConfig.load(config_path)
    client = domain_mailbox.DomainMailboxClient(config.provider("primary-vps"))
    assert client.list_domains() == []
    assert calls[0].full_url == "https://gateway.example/v1/domains"
    assert calls[0].get_header("Host") == "manage.alpha.example"
    assert config.provider("primary-vps").public_metadata()["host_header"] == "manage.alpha.example"


def test_gateway_host_override_rejects_header_injection():
    try:
        domain_mailbox.provider_from_runtime_settings({
            "domain_mailbox_api_origin": "https://gateway.example",
            "domain_mailbox_host_header": "manage.example\r\nX-Evil: yes",
            "domain_mailbox_default_domain": "alpha.example",
            "domain_mailbox_domains": "alpha.example",
        })
    except domain_mailbox.DomainMailboxConfigError as exc:
        assert "host_header" in str(exc)
    else:
        raise AssertionError("header injection must be rejected")


def test_read_managed_inbox_uses_mailbox_token_not_admin_token(tmp_path, monkeypatch):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"admin_api_token": "admin-secret"}), encoding="utf-8")
    config_path = _write_config(tmp_path, secret)
    monkeypatch.setenv(domain_mailbox.CONFIG_ENV, str(config_path))
    domain_mailbox._CONFIG_CACHE = None
    calls = []

    def fake_urlopen(request, **_kwargs):
        calls.append(request)
        return _Response({
            "results": [{
                "id": "m1",
                "message_id": "source-1",
                "raw": "Your Logicc verification code is 123456",
                "truncated": 0,
                "created_at": "2026-08-23T10:00:00Z",
            }],
            "count": 1,
        })

    monkeypatch.setattr(domain_mailbox, "_urlopen", fake_urlopen)
    text = domain_mailbox.read_managed_inbox_url(
        "https://inbox.alpha.example/cf-inbox/mailbox-secret/person%40alpha.example"
    )
    assert "123456" in text
    request = calls[0]
    assert request.get_header("Authorization") == "Bearer mailbox-secret"
    assert "admin-secret" not in request.full_url
    assert urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)["address"] == ["person@alpha.example"]
    assert urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)["limit"] == ["3"]


def test_provision_uses_admin_token_and_returns_import_lines(tmp_path, monkeypatch):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"admin_api_token": "admin-secret"}), encoding="utf-8")
    config_path = _write_config(tmp_path, secret)
    domain_mailbox._CONFIG_CACHE = None
    calls = []

    def fake_urlopen(request, **_kwargs):
        calls.append(request)
        return _Response({
            "items": [{
                "address": "box@alpha.example",
                "token": "mailbox-secret",
                "inbox_url": "https://inbox.alpha.example/cf-inbox/mailbox-secret/box%40alpha.example",
            }],
            "count": 1,
        })

    monkeypatch.setattr(domain_mailbox, "_urlopen", fake_urlopen)
    items = domain_mailbox.provision_mailboxes(1, config_path=config_path)
    assert items[0].account_line.startswith("box@alpha.example----https://")
    assert calls[0].get_header("Authorization") == "Bearer admin-secret"


def test_runtime_settings_emit_token_free_child_config():
    settings = {
        "domain_mailbox_label": "Owned mail",
        "domain_mailbox_api_origin": "https://manage.example",
        "domain_mailbox_host_header": "origin.manage.example",
        "domain_mailbox_default_domain": "alpha.example",
        "domain_mailbox_domains": "alpha.example, beta.example",
        "domain_mailbox_admin_token": "admin-secret",
    }

    payload = domain_mailbox.runtime_config_payload(settings)

    assert payload["default_domain"] == "alpha.example"
    assert payload["providers"]["runtime-vps"]["host_header"] == "origin.manage.example"
    assert payload["providers"]["runtime-vps"]["domains"] == [
        "alpha.example", "beta.example",
    ]
    assert "admin-secret" not in json.dumps(payload)
    assert "admin_token" not in json.dumps(payload)


def test_runtime_settings_provision_with_admin_token(monkeypatch):
    calls = []

    def fake_urlopen(request, **_kwargs):
        calls.append(request)
        return _Response({
            "items": [{
                "address": "box@alpha.example",
                "token": "mailbox-secret",
                "inbox_url": "https://inbox.alpha.example/cf-inbox/mailbox-secret/box%40alpha.example",
            }],
            "count": 1,
        })

    monkeypatch.setattr(domain_mailbox, "_urlopen", fake_urlopen)
    items = domain_mailbox.provision_from_runtime_settings({
        "domain_mailbox_label": "Owned mail",
        "domain_mailbox_api_origin": "https://manage.example",
        "domain_mailbox_default_domain": "alpha.example",
        "domain_mailbox_domains": "alpha.example",
        "domain_mailbox_admin_token": "admin-secret",
    }, 1)

    assert items[0].account_line.endswith("/box%40alpha.example")
    assert calls[0].get_header("Authorization") == "Bearer admin-secret"
    assert json.loads(calls[0].data) == {"count": 1, "domain": "alpha.example"}
