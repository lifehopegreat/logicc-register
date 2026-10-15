"""RoxyBrowser local API integration.

Registration uses only the documented local API: create an isolated profile,
inject that account's proxy before opening it, attach through CDP, then close
and delete the temporary profile.

Official docs: https://roxybrowser.com/docs/api-documentation/api-endpoint.html
"""
from __future__ import annotations

from collections import deque
import logging
import re
import threading
import time
from typing import Any

import requests
from DrissionPage import ChromiumOptions, ChromiumPage

import config


log = logging.getLogger("roxy_mgr")


class RoxyBrowserError(RuntimeError):
    """A safe, user-facing Roxy API failure."""


class _RollingRateLimiter:
    """Process-wide sliding-window limiter for the local Roxy API."""

    def __init__(self, calls_per_minute: int) -> None:
        self.limit = max(1, min(int(calls_per_minute or 45), 600))
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def wait(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                while self._calls and now - self._calls[0] >= 60.0:
                    self._calls.popleft()
                if len(self._calls) < self.limit:
                    self._calls.append(now)
                    return
                delay = max(0.05, 60.0 - (now - self._calls[0]) + 0.02)
            time.sleep(delay)


def _first_text(*values: Any) -> str:
    for value in values:
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _safe_api_message(value: Any) -> str:
    text = re.sub(r"[\r\n\t]+", " ", str(value or "Roxy API 请求失败")).strip()
    text = re.sub(
        r'''(?ix)(["']?(?:token|password|username|proxyUserName|proxyPassword)["']?)
        \s*[:=]\s*["']?[^,"' }]+["']?''',
        r"\1=[已隐藏]",
        text,
    )
    text = re.sub(r"(?i)(https?://)[^/@\s:]+:[^/@\s]+@", r"\1[凭据已隐藏]@", text)
    return text[:240]


class RoxyClient:
    """Strict client for RoxyBrowser's localhost API."""

    def __init__(
        self,
        *,
        port: int | str | None = None,
        token: str | None = None,
        workspace_id: int | str | None = None,
        rate_limit: int | None = None,
        timeout: float = 45.0,
    ) -> None:
        try:
            parsed_port = int(port if port is not None else getattr(config, "ROXY_API_PORT", 50000))
        except (TypeError, ValueError) as exc:
            raise RoxyBrowserError("Roxy API 端口必须是数字") from exc
        if not 1 <= parsed_port <= 65535:
            raise RoxyBrowserError("Roxy API 端口超出范围")
        self.base_url = f"http://127.0.0.1:{parsed_port}"
        self.token = str(token if token is not None else getattr(config, "ROXY_API_TOKEN", "")).strip()
        raw_workspace = workspace_id if workspace_id is not None else getattr(config, "ROXY_WORKSPACE_ID", 0)
        try:
            self.configured_workspace_id = int(raw_workspace or 0)
        except (TypeError, ValueError) as exc:
            raise RoxyBrowserError("Roxy 工作区 ID 必须是数字") from exc
        if self.configured_workspace_id < 0:
            raise RoxyBrowserError("Roxy 工作区 ID 不能为负数")
        # A cold Roxy/Chromium start can take noticeably longer than an
        # ordinary localhost API call.  Keep one bounded timeout for the
        # whole client, but do not abort a valid first profile launch after
        # only 20 seconds (which can leave an opening profile racing cleanup).
        self.timeout = max(3.0, min(float(timeout), 90.0))
        self.session = requests.Session()
        self.session.trust_env = False
        self._workspace: dict[str, Any] | None = None
        self._limiter = _RollingRateLimiter(
            rate_limit if rate_limit is not None else getattr(config, "ROXY_API_RATE_LIMIT", 45)
        )

    def _request(self, method: str, endpoint: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.token:
            raise RoxyBrowserError("Roxy API Key 未配置")
        self._limiter.wait()
        try:
            response = self.session.request(
                method,
                f"{self.base_url}{endpoint}",
                headers={"token": self.token, "Accept": "application/json"},
                params=payload if method.upper() == "GET" else None,
                json=payload if method.upper() != "GET" else None,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise RoxyBrowserError(f"Roxy API 无法连接（{type(exc).__name__}）") from exc
        if response.status_code == 429:
            raise RoxyBrowserError("Roxy API 请求频率受限；请稍后重试或降低并发")
        if not response.ok:
            raise RoxyBrowserError(f"Roxy API HTTP {response.status_code}")
        try:
            body = response.json()
        except ValueError as exc:
            raise RoxyBrowserError("Roxy API 返回了非 JSON 响应") from exc
        if not isinstance(body, dict):
            raise RoxyBrowserError("Roxy API 响应结构错误")
        code = body.get("code")
        if code not in (0, "0"):
            message = _safe_api_message(body.get("msg") or body.get("message") or f"code={code}")
            folded = message.casefold()
            if re.search(r"(?:rate|request|api)[ _-]*limit|too many requests|频率|限流", folded):
                raise RoxyBrowserError("Roxy API 请求频率受限；请稍后重试或降低并发")
            if (
                "额度" in message
                or "quota" in folded
                or re.search(r"(?:profile|window|environment)[ _-]*(?:count[ _-]*)?limit", folded)
            ):
                raise RoxyBrowserError(
                    "Roxy 指纹窗口额度已满；请在 Roxy 中释放至少一个闲置窗口后重试"
                )
            raise RoxyBrowserError(f"Roxy API 拒绝请求：{message}")
        return body

    @staticmethod
    def _data(body: dict[str, Any]) -> Any:
        return body.get("data")

    def health(self) -> dict[str, Any]:
        data = self._data(self._request("GET", "/health"))
        return data if isinstance(data, dict) else {}

    def workspaces(self) -> list[dict[str, Any]]:
        data = self._data(self._request(
            "GET", "/browser/workspace", {"page_index": 1, "page_size": 1000}
        ))
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            for key in ("list", "rows", "records", "workspaceList"):
                rows = data.get(key)
                if isinstance(rows, list):
                    return [row for row in rows if isinstance(row, dict)]
        return []

    def profiles(self) -> list[dict[str, Any]]:
        """Return profiles in the selected workspace without exposing them to logs."""
        data = self._data(self._request(
            "GET",
            "/browser/list_v3",
            {"workspaceId": self.workspace_id(), "page_index": 1, "page_size": 1000},
        ))
        if isinstance(data, list):
            return [row for row in data if isinstance(row, dict)]
        if isinstance(data, dict):
            for key in ("list", "rows", "records", "browserList"):
                rows = data.get(key)
                if isinstance(rows, list):
                    return [row for row in rows if isinstance(row, dict)]
        return []

    @staticmethod
    def _workspace_id(row: dict[str, Any]) -> int:
        raw = row.get("workspaceId", row.get("id", 0))
        try:
            return int(raw or 0)
        except (TypeError, ValueError):
            return 0

    def workspace(self) -> dict[str, Any]:
        if self._workspace is not None:
            return self._workspace
        rows = self.workspaces()
        if self.configured_workspace_id:
            match = next((row for row in rows if self._workspace_id(row) == self.configured_workspace_id), None)
            if not match:
                raise RoxyBrowserError(f"Roxy 工作区 {self.configured_workspace_id} 不存在或无权限")
        else:
            match = next((row for row in rows if self._workspace_id(row)), None)
            if not match:
                raise RoxyBrowserError("Roxy API 未返回可用工作区")
        self._workspace = match
        return match

    def workspace_id(self) -> int:
        value = self._workspace_id(self.workspace())
        if not value:
            raise RoxyBrowserError("Roxy 工作区缺少有效 ID")
        return value

    @staticmethod
    def _proxy_info(proxy: dict[str, Any] | None) -> dict[str, Any]:
        if not proxy or not str(proxy.get("host") or "").strip():
            return {
                "moduleId": 0,
                "proxyMethod": "custom",
                "proxyCategory": "noproxy",
                "ipType": "IPV4",
            }
        protocol = str(proxy.get("proxyType") or proxy.get("protocol") or "HTTP").upper()
        if protocol == "SOCKS5H":
            protocol = "SOCKS5"
        if protocol not in {"HTTP", "HTTPS", "SOCKS5"}:
            raise RoxyBrowserError(f"Roxy 不支持代理协议 {protocol}")
        host = str(proxy.get("host") or "").strip()
        try:
            port = int(proxy.get("port") or 0)
        except (TypeError, ValueError) as exc:
            raise RoxyBrowserError("代理端口必须是数字") from exc
        if not host or not 1 <= port <= 65535:
            raise RoxyBrowserError("代理 host/port 无效")
        return {
            "moduleId": 0,
            "proxyMethod": "custom",
            "proxyCategory": protocol,
            "ipType": "IPV4",
            "protocol": protocol,
            "host": host,
            "port": str(port),
            "proxyUserName": str(proxy.get("user") or ""),
            "proxyPassword": str(proxy.get("password") or ""),
            "checkChannel": "IPRust.io",
        }

    def create_profile(self, name: str, proxy: dict[str, Any] | None = None) -> str:
        proxy_info = self._proxy_info(proxy)
        payload: dict[str, Any] = {
            "workspaceId": self.workspace_id(),
            "windowName": str(name or f"logicc-{int(time.time())}")[:80],
            "windowRemark": "logicc-register temporary profile",
            "coreType": "Chrome",
            "os": "Windows",
            "osVersion": "11",
            "proxyInfo": proxy_info,
            "fingerInfo": {
                "isLanguageBaseIp": True,
                "isDisplayLanguageBaseIp": True,
                "isTimeZone": True,
                # Allow geolocation but derive the reported position from the
                # injected proxy.  `0` means "ask" in the Roxy API and can
                # leave an automation-blocking permission prompt behind.
                "position": 1,
                "isPositionBaseIp": True,
                "randomFingerprint": True,
                "webRTC": 0,
                "canvas": True,
                "webGL": True,
                "webGLInfo": True,
                "audioContext": True,
                "clientRects": True,
                "deviceInfo": True,
                "portScanProtect": True,
                "clearCacheFile": True,
                "clearCookie": True,
                "clearLocalStorage": True,
                "forbidSavePassword": True,
                "syncCookie": False,
                "syncTab": False,
                "syncHistory": False,
                "saveFlowMode": False,
            },
        }
        data = self._data(self._request("POST", "/browser/create", payload))
        if not isinstance(data, dict):
            raise RoxyBrowserError("Roxy 创建窗口成功但未返回窗口信息")
        dir_id = _first_text(data.get("dirId"), data.get("id"), data.get("browserId"))
        if not dir_id:
            raise RoxyBrowserError("Roxy 创建窗口成功但未返回 dirId")
        route = "直连" if proxy_info.get("proxyCategory") == "noproxy" else f"{proxy_info['proxyCategory']} 代理"
        log.info("  [Roxy] 临时指纹窗口已创建；%s已在启动前注入", route)
        return dir_id

    def open_profile(self, dir_id: str) -> tuple[str, str]:
        payload = {
            "workspaceId": self.workspace_id(),
            "dirId": str(dir_id),
            "args": [],
            "forceOpen": False,
            "headless": False,
        }
        data = self._data(self._request("POST", "/browser/open", payload))
        if not isinstance(data, dict):
            raise RoxyBrowserError("Roxy 打开窗口后未返回调试地址")
        debug_address = _first_text(data.get("http"), data.get("debugAddress"), data.get("debuggerAddress"))
        if debug_address.startswith("http://"):
            debug_address = debug_address[7:]
        elif debug_address.startswith("https://"):
            debug_address = debug_address[8:]
        if not debug_address:
            ws = _first_text(data.get("ws"), data.get("webSocketDebuggerUrl"))
            match = re.search(r"ws://([^/]+)", ws)
            debug_address = match.group(1) if match else ""
        if not debug_address:
            raise RoxyBrowserError("Roxy 打开窗口成功但未返回 CDP 地址")
        return debug_address.rstrip("/"), _first_text(data.get("driver"), data.get("driverPath"))

    def close_profile(self, dir_id: str) -> bool:
        self._request("POST", "/browser/close", {"dirId": str(dir_id)})
        return True

    def delete_profile(self, dir_id: str) -> bool:
        self._request(
            "POST",
            "/browser/delete",
            {"workspaceId": self.workspace_id(), "dirIds": [str(dir_id)], "isSoftDelete": False},
        )
        return True

    def connection_summary(self) -> dict[str, Any]:
        self.health()
        workspace = self.workspace()
        profile_count = len(self.profiles())
        return {
            "connected": True,
            "port": int(self.base_url.rsplit(":", 1)[-1]),
            "workspace_id": self.workspace_id(),
            "workspace_name": _first_text(workspace.get("workspaceName"), workspace.get("name"), "默认工作区"),
            "profile_count": profile_count,
        }


_CLIENTS: dict[tuple[int, str, int, int], RoxyClient] = {}
_CLIENTS_LOCK = threading.Lock()


def get_roxy_client() -> RoxyClient:
    port = int(getattr(config, "ROXY_API_PORT", 50000))
    token = str(getattr(config, "ROXY_API_TOKEN", "")).strip()
    workspace_id = int(getattr(config, "ROXY_WORKSPACE_ID", 0) or 0)
    rate_limit = int(getattr(config, "ROXY_API_RATE_LIMIT", 45) or 45)
    key = (port, token, workspace_id, rate_limit)
    with _CLIENTS_LOCK:
        client = _CLIENTS.get(key)
        if client is None:
            client = RoxyClient(port=port, token=token, workspace_id=workspace_id, rate_limit=rate_limit)
            _CLIENTS.clear()
            _CLIENTS[key] = client
        return client


def roxy_health() -> bool:
    get_roxy_client().health()
    return True


def roxy_workspace_id() -> int:
    return get_roxy_client().workspace_id()


def roxy_create_profile(name: str, proxy: dict[str, Any] | None = None, **_: Any) -> str:
    return get_roxy_client().create_profile(name, proxy)


def roxy_open_profile(dir_id: str, **_: Any) -> tuple[str, str]:
    return get_roxy_client().open_profile(dir_id)


def roxy_close_profile(dir_id: str) -> bool:
    return get_roxy_client().close_profile(dir_id)


def roxy_delete_profile(dir_id: str, **_: Any) -> bool:
    return get_roxy_client().delete_profile(dir_id)


def roxy_delete_local_profile(_dir_id: str) -> bool:
    """Compatibility shim: unsafe direct-local profiles are no longer created."""
    return False


def open_roxy_with_url(
    url: str = "",
    name: str = "",
    proxy: dict[str, Any] | None = None,
    goto: bool = True,
    dir_id: str = "",
    force_ephemeral: bool = True,
    **_: Any,
) -> tuple[ChromiumPage, str]:
    """Create/open an API-managed profile and attach DrissionPage."""
    del force_ephemeral
    client = get_roxy_client()
    created = not bool(str(dir_id or "").strip())
    profile_id = str(dir_id or "").strip()
    page: ChromiumPage | None = None
    try:
        if created:
            profile_id = client.create_profile(name or f"logicc-{int(time.time())}", proxy)
        debug_address, _driver = client.open_profile(profile_id)
        options = ChromiumOptions()
        options.set_address(debug_address)
        page = ChromiumPage(options)
        from registration_diagnostics import attach_browser_capture
        attach_browser_capture(page)
        if goto and url:
            page.get(url)
        return page, profile_id
    except Exception:
        if page is not None:
            try:
                page.quit()
            except Exception:
                pass
        if profile_id:
            try:
                client.close_profile(profile_id)
            except Exception:
                pass
            if created:
                try:
                    client.delete_profile(profile_id)
                except Exception:
                    pass
        raise
