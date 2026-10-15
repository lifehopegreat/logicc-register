from __future__ import annotations

from collections import deque
from pathlib import Path
import sys

import pytest

CORE = Path(__file__).resolve().parents[1] / "core"
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

import roxy_mgr


class FakeResponse:
    def __init__(self, payload, *, status_code=200):
        self.payload = payload
        self.status_code = status_code
        self.ok = 200 <= status_code < 400

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, *responses):
        self.responses = deque(responses)
        self.calls = []
        self.trust_env = True

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.popleft()


def client_with(*responses, workspace_id=7):
    client = roxy_mgr.RoxyClient(
        port=50000,
        token="local-test-key",
        workspace_id=workspace_id,
        rate_limit=600,
    )
    client.session = FakeSession(*responses)
    client.session.trust_env = False
    return client


def ok(data=None):
    return FakeResponse({"code": 0, "data": {} if data is None else data})


def test_client_uses_localhost_token_header_and_ignores_environment_proxy():
    client = client_with(ok({"status": "ok"}))

    assert client.health() == {"status": "ok"}

    method, url, kwargs = client.session.calls[0]
    assert method == "GET"
    assert url == "http://127.0.0.1:50000/health"
    assert kwargs["headers"]["token"] == "local-test-key"
    assert client.session.trust_env is False


def test_default_timeout_allows_cold_profile_launch():
    client = roxy_mgr.RoxyClient(
        port=50000,
        token="local-test-key",
        workspace_id=7,
        rate_limit=600,
    )

    assert client.timeout == 45.0


def test_workspace_selection_is_strict_and_profile_count_is_safe():
    client = client_with(
        ok({"status": "ok"}),
        ok({"list": [{"workspaceId": 7, "workspaceName": "Main"}]}),
        ok({"list": [{"dirId": "a"}, {"dirId": "b"}]}),
    )

    summary = client.connection_summary()

    assert summary == {
        "connected": True,
        "port": 50000,
        "workspace_id": 7,
        "workspace_name": "Main",
        "profile_count": 2,
    }
    assert client.session.calls[-1][1].endswith("/browser/list_v3")
    assert client.session.calls[-1][2]["params"]["workspaceId"] == 7


def test_missing_configured_workspace_never_falls_back_to_another_workspace():
    client = client_with(ok({"list": [{"workspaceId": 8, "workspaceName": "Other"}]}))

    with pytest.raises(roxy_mgr.RoxyBrowserError, match="工作区 7 不存在"):
        client.workspace()


def test_create_profile_injects_proxy_and_ip_adaptive_fingerprint_before_open():
    client = client_with(
        ok({"list": [{"workspaceId": 7, "workspaceName": "Main"}]}),
        ok({"dirId": "profile-1"}),
    )

    result = client.create_profile("gptfree-owner@example.com", {
        "protocol": "http",
        "host": "proxy.example.test",
        "port": 3010,
        "user": "owner",
        "password": "secret",
    })

    assert result == "profile-1"
    method, url, kwargs = client.session.calls[-1]
    assert (method, url.rsplit("/", 1)[-1]) == ("POST", "create")
    payload = kwargs["json"]
    assert "coreVersion" not in payload
    assert payload["proxyInfo"] == {
        "moduleId": 0,
        "proxyMethod": "custom",
        "proxyCategory": "HTTP",
        "ipType": "IPV4",
        "protocol": "HTTP",
        "host": "proxy.example.test",
        "port": "3010",
        "proxyUserName": "owner",
        "proxyPassword": "secret",
        "checkChannel": "IPRust.io",
    }
    finger = payload["fingerInfo"]
    assert finger["isLanguageBaseIp"] is True
    assert finger["isDisplayLanguageBaseIp"] is True
    assert finger["isTimeZone"] is True
    assert finger["isPositionBaseIp"] is True
    assert finger["position"] == 1
    assert finger["webRTC"] == 0
    assert finger["randomFingerprint"] is True


def test_profile_lifecycle_uses_documented_endpoints():
    client = client_with(
        ok({"list": [{"workspaceId": 7}]}),
        ok({"http": "http://127.0.0.1:9222", "driver": "driver.exe"}),
        ok(),
        ok(),
    )

    address, driver = client.open_profile("profile-1")
    assert (address, driver) == ("127.0.0.1:9222", "driver.exe")
    assert client.close_profile("profile-1") is True
    assert client.delete_profile("profile-1") is True

    endpoints = [call[1].removeprefix("http://127.0.0.1:50000") for call in client.session.calls]
    assert endpoints == [
        "/browser/workspace",
        "/browser/open",
        "/browser/close",
        "/browser/delete",
    ]
    assert client.session.calls[-1][2]["json"] == {
        "workspaceId": 7,
        "dirIds": ["profile-1"],
        "isSoftDelete": False,
    }


def test_quota_and_secret_bearing_errors_are_user_safe():
    quota_client = client_with(FakeResponse({"code": 1, "msg": "窗口额度不足"}))
    with pytest.raises(roxy_mgr.RoxyBrowserError, match="窗口额度已满"):
        quota_client._request("POST", "/browser/create", {})

    secret_client = client_with(FakeResponse({
        "code": 1,
        "msg": "token=super-secret password=also-secret username=owner",
    }))
    with pytest.raises(roxy_mgr.RoxyBrowserError) as caught:
        secret_client._request("GET", "/health")
    message = str(caught.value)
    assert "super-secret" not in message
    assert "also-secret" not in message
    assert "owner" not in message


@pytest.mark.parametrize("payload,status_code", [
    ({"code": 1, "msg": "API rate limit reached"}, 200),
    ({"code": 1, "msg": "too many requests"}, 200),
    ({"code": 0}, 429),
])
def test_rate_limit_is_not_misreported_as_profile_quota(payload, status_code):
    client = client_with(FakeResponse(payload, status_code=status_code))

    with pytest.raises(roxy_mgr.RoxyBrowserError, match="请求频率受限") as caught:
        client._request("GET", "/health")

    assert "窗口额度" not in str(caught.value)


def test_json_and_proxy_url_secrets_are_redacted():
    client = client_with(FakeResponse({
        "code": 1,
        "msg": '\"proxyPassword\":\"proxy-secret\" url=http://owner:pass@proxy.test:3010',
    }))

    with pytest.raises(roxy_mgr.RoxyBrowserError) as caught:
        client._request("POST", "/browser/create", {})

    message = str(caught.value)
    assert "proxy-secret" not in message
    assert "owner" not in message
    assert "pass@" not in message
