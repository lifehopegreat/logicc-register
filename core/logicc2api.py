"""Local API handoff only: no mailbox credentials, direct state-file edits or generation."""
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx


def local_base_url(value):
    text = str(value).strip().rstrip("/")
    parsed = urlsplit(text)
    try:
        valid = (parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
                 and parsed.port and not parsed.username and not parsed.password
                 and parsed.path in {"", "/"} and not parsed.query and not parsed.fragment)
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("logicc2api 仅支持带端口的本机 HTTP 地址")
    return text


class IntegrationError(Exception):
    pass


class Logicc2Api:
    def __init__(self, base_url, *, transport=None):
        self.base_url = local_base_url(base_url)
        self.client = httpx.Client(base_url=self.base_url, trust_env=False, follow_redirects=False,
                                   timeout=30, headers={"X-Logicc-Admin": "1"}, transport=transport)

    def close(self):
        self.client.close()

    def call(self, method, path, payload=None):
        try:
            response = self.client.request(method, path, json=payload)
            if response.status_code not in {200, 201}:
                raise IntegrationError("logicc2api_http_" + str(response.status_code))
            value = response.json()
        except (httpx.RequestError, ValueError):
            raise IntegrationError("logicc2api_response_unavailable") from None
        if not isinstance(value, dict):
            raise IntegrationError("logicc2api_invalid_response")
        return value

    def snapshot(self):
        if self.call("GET", "/health").get("status") != "ok":
            raise IntegrationError("logicc2api_health_invalid")
        value = self.call("GET", "/api/state")
        service = value.get("service")
        if (not isinstance(value.get("accounts"), list) or not all(isinstance(a, dict) for a in value["accounts"])
                or not isinstance(service, dict) or not isinstance(service.get("upstream"), str)
                or service["upstream"].rstrip("/") != "https://app.logicc.com/api"):
            raise IntegrationError("logicc2api_target_mismatch")
        return value

    def handoff(self, state, checkpoint):
        receipt = state.setdefault("logicc2api", {})
        try:
            if not state.get("registration_ok") or not state.get("onboarding_ok"):
                raise IntegrationError("registration_not_confirmed")
            sid = state.get("session_id", "")
            if not re.fullmatch(r"sess_[A-Za-z0-9_-]{1,150}", sid):
                raise IntegrationError("session_id_missing")
            cookies = [c for c in state.get("cookies", []) if c.get("name") == "__client"
                       and c.get("domain", "").lstrip(".") in {"clerk.logicc.com", "logicc.com"}]
            cookies.sort(key=lambda c: c.get("domain", "").lstrip(".") == "clerk.logicc.com", reverse=True)
            cookie = cookies[0].get("value", "") if cookies else ""
            if not re.fullmatch(r"[\w.~+/=-]{1,20000}", cookie):
                raise IntegrationError("client_cookie_missing")
            accounts = self.snapshot()["accounts"]
            matches = [a for a in accounts if a.get("sessionId") == sid]
            if len(matches) > 1:
                raise IntegrationError("duplicate_remote_sessions")
            if matches:
                account = matches[0]
            else:
                if receipt.get("status") in {"sending", "unknown"} and receipt.get("base_url") == self.base_url:
                    raise IntegrationError("import_not_reconciled")
                receipt.update(status="sending", base_url=self.base_url)
                checkpoint()
                try:
                    account = self.call("POST", "/api/accounts", {"name": state["email"],
                        "clientCookie": cookie, "sessionId": sid, "enabled": True}).get("account", {})
                except IntegrationError as exc:
                    receipt["status"] = "unknown" if str(exc) == "logicc2api_response_unavailable" else "rejected"
                    raise
            if not isinstance(account, dict):
                receipt["status"] = "unknown"
                raise IntegrationError("import_response_identity_mismatch")
            aid = account.get("id", "")
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,150}", aid) or account.get("sessionId") != sid:
                receipt["status"] = "unknown"
                raise IntegrationError("import_response_identity_mismatch")
            receipt.update(status="imported", account_id=aid, base_url=self.base_url, error="")
            checkpoint()
            checked = self.call("POST", f"/api/accounts/{aid}/check", {})
            remote = checked.get("account", {})
            if (not isinstance(remote, dict) or remote.get("id") != aid or remote.get("sessionId") != sid or remote.get("status") != "ready"
                    or type(checked.get("models")) is not int or checked["models"] <= 0):
                raise IntegrationError("imported_account_check_failed")
            receipt.update(status="ready", models=checked["models"], error="",
                           checked_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"))
        except IntegrationError as exc:
            receipt["error"] = str(exc)
            if receipt.get("status") not in {"unknown", "sending", "rejected"}:
                receipt["status"] = "check_failed" if receipt.get("account_id") else "failed"
        checkpoint()
        return self.public_receipt(state)

    @staticmethod
    def public_receipt(state):
        value = state.get("logicc2api", {})
        return {"integration_status": value.get("status", "disabled"),
                "integration_error": value.get("error", ""),
                "integration_account_id": value.get("account_id", ""),
                "integration_models": value.get("models", 0),
                "integration_checked_at": value.get("checked_at", "")}
