import json
from collections import Counter
from urllib.parse import urlsplit

import httpx
import pytest

import app as console
import proxy_connectivity
from logicc2api import Logicc2Api, local_base_url
from logicc_register import load_private, save_private
from test_logicc_console import client


@pytest.mark.parametrize("url", ["https://example.test", "http://127.0.0.1.evil.test:18789",
    "http://127.0.0.1:18789/path", "http://user:secret@127.0.0.1:18789", "http://127.0.0.1:bad",
    "file:///tmp/account", "http://127.0.0.1:18789?redirect=elsewhere", "http://127.0.0.1"])
def test_handoff_rejects_non_local_or_ambiguous_destination(url):
    with pytest.raises(ValueError):
        local_base_url(url)


class FakeAdapter:
    def __init__(self):
        self.accounts = []
        self.calls = Counter()
        self.lose_import = False
        self.commit = True
        self.check_fails = False

    def handle(self, request):
        path = request.url.path
        self.calls[(request.method, path)] += 1
        assert request.headers["X-Logicc-Admin"] == "1"
        if path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/api/state":
            return httpx.Response(200, json={"accounts": self.accounts,
                "service": {"upstream": "https://app.logicc.com/api"}})
        if path == "/api/accounts":
            payload = json.loads(request.content)
            assert set(payload) == {"name", "sessionId", "clientCookie", "enabled"}
            assert payload["sessionId"] == "sess_test" and payload["clientCookie"] == "private-client-cookie"
            account = {"id": "account-test", "sessionId": "sess_test", "status": "pending"}
            if self.commit:
                self.accounts.append(account)
            if self.lose_import:
                raise httpx.ReadTimeout("private-client-cookie must not be logged")
            return httpx.Response(201, json={"account": account})
        if path == "/api/accounts/account-test/check":
            if self.check_fails:
                return httpx.Response(401, json={"error": "private-client-cookie"})
            self.accounts[0]["status"] = "ready"
            return httpx.Response(200, json={"models": 20, "account": self.accounts[0]})
        raise AssertionError(path)


def confirmed_state():
    return {"registration_ok": True, "onboarding_ok": True, "email": "owner@example.test",
            "session_id": "sess_test", "config": {"password": "never-export"}, "jwt": "never-export",
            "cookies": [{"name": "__client", "domain": "clerk.logicc.com", "value": "private-client-cookie"}]}


def test_import_contract_idempotency_and_no_mail_secrets(caplog):
    api = FakeAdapter()
    c = Logicc2Api("http://127.0.0.1:18789", transport=httpx.MockTransport(api.handle))
    state = confirmed_state(); checkpoints = []
    try:
        first = c.handoff(state, lambda: checkpoints.append(json.loads(json.dumps(state))))
        assert first["integration_status"] == "ready" and first["integration_models"] == 20
        assert c.handoff(state, lambda: None)["integration_status"] == "ready"
        assert api.calls[("POST", "/api/accounts")] == 1
        assert checkpoints[0]["logicc2api"]["status"] == "sending"
        assert "private-client-cookie" not in json.dumps(first) + caplog.text
        assert "never-export" not in json.dumps(first) + caplog.text
    finally:
        c.close()


@pytest.mark.parametrize("committed", [True, False])
def test_unknown_import_reconciles_without_duplicate(committed):
    api = FakeAdapter();api.lose_import = True;api.commit = committed
    c = Logicc2Api("http://127.0.0.1:18789", transport=httpx.MockTransport(api.handle))
    state = confirmed_state()
    try:
        assert c.handoff(state, lambda: None)["integration_status"] == "unknown"
        second = c.handoff(state, lambda: None)
        assert second["integration_status"] == ("ready" if committed else "unknown")
        if not committed:
            assert second["integration_error"] == "import_not_reconciled"
        assert api.calls[("POST", "/api/accounts")] == 1
    finally:
        c.close()


def test_import_check_failure_does_not_undo_registration_or_reimport():
    api = FakeAdapter();api.check_fails = True
    c = Logicc2Api("http://127.0.0.1:18789", transport=httpx.MockTransport(api.handle))
    state = confirmed_state()
    try:
        result = c.handoff(state, lambda: None)
        assert result["integration_status"] == "check_failed" and state["registration_ok"]
        assert result["integration_error"] == "logicc2api_http_401"
        api.check_fails = False
        assert c.handoff(state, lambda: None)["integration_status"] == "ready"
        assert api.calls[("POST", "/api/accounts")] == 1
    finally:
        c.close()


def test_partial_registration_never_exports_any_secret():
    api = FakeAdapter();state = confirmed_state();state["onboarding_ok"] = False
    c = Logicc2Api("http://127.0.0.1:18789", transport=httpx.MockTransport(api.handle))
    try:
        assert c.handoff(state, lambda: None)["integration_error"] == "registration_not_confirmed"
        assert not api.calls
    finally:
        c.close()


@pytest.mark.parametrize("bad", [{"service": None, "accounts": []}, {"service": {"upstream": None}, "accounts": []},
                                {"service": {"upstream": "https://app.logicc.com/api"}, "accounts": [None]}])
def test_malformed_adapter_contract_never_exports_credentials(bad):
    writes = []
    def handle(request):
        if request.method == "POST":
            writes.append(request.url.path)
        return httpx.Response(200, json={"status": "ok"} if request.url.path == "/health" else bad)
    c = Logicc2Api("http://127.0.0.1:18789", transport=httpx.MockTransport(handle))
    try:
        result = c.handoff(confirmed_state(), lambda: None)
        assert result["integration_error"] == "logicc2api_target_mismatch" and not writes
    finally:
        c.close()


def test_logicc_connectivity_account_pool_does_not_use_gpt_plan(client):
    client.post("/api/accounts/import", json={"lines": "owner@example.test----fixture-pass----fixture-id----fixture-token"})
    registry = console.sync_pool_registry()
    console.record_logicc_connectivity(registry, [{"email": "owner@example.test", "registration_ok": True,
        "onboarding_ok": True, "integration_status": "ready", "integration_checked_at": "2026-10-15T03:00:00Z"}])
    assert registry.summary()["alive"] == 1 and registry.summary()["unchecked"] == 0
    row = client.get("/api/accounts/managed").get_json()["accounts"][0]
    assert row["connectivity_status"] == "logicc_ready" and row["connectivity_checked_at"] == "2026-10-15T03:00:00Z"
    console.record_logicc_connectivity(registry, [{"email": "owner@example.test", "registration_ok": True,
        "onboarding_ok": True, "integration_status": "check_failed", "integration_error": "logicc2api_http_401"}])
    assert registry.summary()["alive"] == 0


def test_capmonster_settings_encrypted_migrated_and_disable_preserves_key(client, monkeypatch):
    key = "b" * 32
    assert client.patch("/api/services/capmonster", json={"enabled": True}).status_code == 400
    r = client.patch("/api/services/capmonster", json={"enabled": True, "client_key": key})
    assert r.status_code == 200 and r.get_json()["configured"]
    path = console.DATA / "services/capmonster.enc"
    assert key not in path.read_bytes().decode()
    assert key not in client.get("/api/services/capmonster").get_data(as_text=True)
    assert key not in client.get("/api/settings").get_data(as_text=True)
    assert "no-store" in r.headers["Cache-Control"]
    r = client.patch("/api/services/capmonster", json={"enabled": False, "client_key": ""})
    assert not r.get_json()["enabled"] and r.get_json()["configured"]
    assert console.private_service("capmonster")["client_key"] == key
    monkeypatch.setattr(console.CapMonster, "balance", lambda self: 0.1)
    r = client.post("/api/services/capmonster/test")
    assert r.get_json()["balance"] == 0.1 and r.get_json()["paid_task_created"] is False
    console.save_service("capmonster", {"client_key": key})
    assert client.get("/api/services/capmonster").get_json()["enabled"]


@pytest.mark.parametrize("payload", [{"enabled": "false"}, {"client_key": 123}, {"client_key": "bad"}, {"endpoint": "http://evil.test"}])
def test_capmonster_rejects_bad_configuration(client, payload):
    assert client.patch("/api/services/capmonster", json=payload).status_code == 400
    assert not (console.DATA / "services/capmonster.enc").exists()


def test_integration_settings_validate_local_only(client):
    assert not client.get("/api/services/logicc2api").get_json()["enabled"]
    assert client.patch("/api/services/logicc2api", json={"enabled": True, "base_url": "https://evil.test"}).status_code == 400
    assert client.patch("/api/services/logicc2api", json={"enabled": True, "base_url": "http://127.0.0.1:18789"}).status_code == 200
    assert console.private_service("logicc2api")["enabled"]


def test_pool_proxy_import_dedupe_encryption_probe_and_run_selection(client, monkeypatch):
    line = "proxy.example.test:3010:fixture-region-US-sid-unchanged:private-password"
    r = client.post("/api/proxies/import", json={"lines": line})
    assert r.status_code == 200 and r.get_json()["added"] == 1
    pid = r.get_json()["proxies"][0]["id"]
    assert r.get_json()["proxies"][0]["region"] == "US"
    assert client.post("/api/proxies/import", json={"lines": line}).get_json()["added"] == 0
    public = client.get("/api/proxies").get_data(as_text=True)
    assert "private-password" not in public and "sid-unchanged" not in public
    assert "private-password" not in (console.DATA / "services/proxies.enc").read_bytes().decode()
    monkeypatch.setattr(console, "probe_proxy", lambda proxy: {"ok": True, "ip": "8.8.8.8"})
    assert client.post(f"/api/proxies/{pid}/test").get_json()["check"]["ok"]
    client.post("/api/accounts/import", json={"lines": "owner@example.test----fixture-pass----fixture-id----fixture-token"})
    monkeypatch.setattr(console, "pin_proxy", lambda proxy: proxy.replace("proxy.example.test", "8.8.8.8"))
    monkeypatch.setattr(console, "start_registration_job", lambda job: None)
    r = client.post("/api/runs", json={"email": "owner@example.test", "accept_terms": True, "proxy_id": pid})
    assert r.status_code == 201
    job = console.JOBS[r.get_json()["job"]["id"]]
    key = console.console_vault().key_path.read_bytes().strip()
    config = load_private(job.meta["input_path"], key)["config"]
    assert urlsplit(config["proxy"]).hostname == "8.8.8.8" and config["proxy_id"] == pid
    assert "sid-unchanged" in config["proxy"]
    assert console.console_vault().get_registration_route("owner@example.test")["proxy"] == config["proxy"]


def test_proxy_gateway_pin_preserves_credentials_and_does_not_rotate_session(monkeypatch):
    monkeypatch.setattr(proxy_connectivity.socket, "getaddrinfo", lambda *a, **kw: [(None,None,None,None,("8.8.8.8",3010))])
    original = "http://fixture-region-US-sid-exact:p%40ss@proxy.example.test:3010"
    pinned = proxy_connectivity.pin_proxy(original)
    assert pinned == original.replace("proxy.example.test", "8.8.8.8")
    with pytest.raises(ValueError):
        proxy_connectivity.pin_proxy("http://127.0.0.1:7897")


def test_fake_ip_resolves_public_gateway_without_sending_proxy_credentials_to_dns(monkeypatch):
    monkeypatch.setattr(proxy_connectivity.socket, "getaddrinfo", lambda *a, **kw: [(None,None,None,None,("198.18.0.10",3010))])
    def handle(request):
        assert request.url.host == "dns.google" and request.url.params["name"] == "proxy.example.test"
        assert "private-password" not in str(request.url) + str(request.headers) + request.content.decode()
        return httpx.Response(200, json={"Status": 0, "Answer": [{"type": 1, "data": "8.8.8.8"}]})
    original_client = httpx.Client
    monkeypatch.setattr(proxy_connectivity.httpx, "Client", lambda **kw: original_client(transport=httpx.MockTransport(handle), **kw))
    pinned = proxy_connectivity.pin_proxy("http://user:private-password@proxy.example.test:3010")
    assert pinned == "http://user:private-password@8.8.8.8:3010"


def test_proxy_probe_errors_do_not_echo_authentication(monkeypatch):
    monkeypatch.setattr(proxy_connectivity, "pin_proxy", lambda proxy: proxy)
    def handle(request):
        raise httpx.ProxyError("echo private-password should not escape")
    original_client = httpx.Client
    monkeypatch.setattr(proxy_connectivity.httpx, "Client", lambda **kw: original_client(transport=httpx.MockTransport(handle), **{k:v for k,v in kw.items() if k != "proxy"}))
    result = proxy_connectivity.probe_proxy("http://user:private-password@8.8.8.8:3010")
    assert result["ok"] is False and result["error"] == "proxy_probe_ProxyError"
    assert "private-password" not in json.dumps(result)


def test_manual_import_api_no_new_signup(client, monkeypatch):
    jid = "a" * 32;key = console.console_vault().key_path.read_bytes().strip()
    job = console.Job({"id": jid, "provider": "logicc", "email": "owner@example.test", "state": "completed",
                       "result_path": str(console.RESULT_DIR / (jid + ".jsonl"))})
    console.JOBS[jid] = job
    save_private(console.registration_state_path(jid), key, confirmed_state())
    console.console_vault()._atomic_write(job.result_path, b'{"ok":true,"registration_ok":true,"onboarding_ok":true}\n', mode=0o600)
    api = FakeAdapter()
    monkeypatch.setattr(console, "Logicc2Api", lambda url: Logicc2Api(url, transport=httpx.MockTransport(api.handle)))
    for _ in range(2):
        result = client.post(f"/api/jobs/{jid}/logicc2api")
        assert result.status_code == 200 and result.get_json()["integration_status"] == "ready"
        assert "private-client-cookie" not in result.get_data(as_text=True)
    assert api.calls[("POST", "/api/accounts")] == 1
    assert json.loads(job.result_path.read_text())["ok"] is True
