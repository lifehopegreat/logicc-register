"""Time-bounded, opt-in redacted HTTP diagnostics for user-initiated runs."""
from __future__ import annotations

import functools
import json
import logging
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

LEASE = Path(__file__).resolve().parents[1] / "output/private/registration-capture.enabled"
CAPTURE_DIR = LEASE.parent / "logicc-capture"
_capture = None
HOSTS = {"app.logicc.com", "clerk.logicc.com", "challenges.cloudflare.com",
         "login.microsoftonline.com", "login.live.com", "graph.microsoft.com"}
PATHS = {"/", "/login", "/register", "/onboarding", "/api/users/me",
         "/api/tenants", "/v1/client", "/v1/client/sign_ups", "/v1/me",
         "/common/oauth2/v2.0/token", "/oauth20_token.srf", "/v1.0/me/messages"}
log = logging.getLogger("registration_diagnostics")


class CaptureWriter:
    def __init__(self, deadline):
        from capture_redaction import Redactor
        self.deadline = deadline
        self.redactor = Redactor()
        self.lock = threading.RLock()
        CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
        self.path = CAPTURE_DIR / f"capture-{os.getpid()}.jsonl"

    def active(self):
        return time.time() < self.deadline and LEASE.is_file()

    def write(self, entry):
        if not self.active():
            return
        with self.lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"utc": datetime.now(timezone.utc).isoformat(), **entry}, ensure_ascii=True) + "\n")
        log.info("[capture-snapshot] %s", entry.get("event", "snapshot"))

    def request(self, method, url, headers=None, body=None, params=None):
        with self.lock:
            safe_url = self.redactor.url(url)
            self.redactor.collect(params)
            safe_headers = self.redactor.headers(headers)
            safe_body = self.redactor.body(body, (headers or {}).get("content-type", (headers or {}).get("Content-Type", "")))
            return {"method": str(method).upper(), "url": safe_url, "headers": safe_headers,
                    "body": safe_body, "params": self.redactor.value(params) if params else None}

    def response(self, url, status, headers, content=None, unavailable=None):
        with self.lock:
            safe_headers = self.redactor.headers(headers)
            mime = next((str(v) for k, v in headers.items() if str(k).lower() == "content-type"), "")
            return {"url": self.redactor.url(url), "status": int(status), "headers": safe_headers,
                    "body": {"kind": "unavailable", "reason": unavailable} if unavailable else
                    self.redactor.body(content, mime, mailbox=urlsplit(str(url)).hostname == "graph.microsoft.com")}


def attach_browser_capture(page):
    if _capture is None or not _capture.active():
        return
    try:
        from capture_browser import BrowserCapture
        recorder = BrowserCapture(page, _capture)
        recorder.start()
        page._registration_capture = recorder
        log.info("[capture-browser-ready] redacted request/response bodies enabled before navigation")
    except Exception as exc:
        log.warning("[capture-browser-unavailable] %s", type(exc).__name__)


def safe_endpoint(url):
    try:
        parsed = urlsplit(str(url))
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in HOSTS:
            return None
        return {"host": parsed.hostname, "path": parsed.path if parsed.path in PATHS else "/[other]"}
    except ValueError:
        return None


def response_metadata(headers):
    headers = {str(k).lower(): str(v) for k, v in headers.items()}
    result = {"challenge": headers.get("cf-mitigated", "").lower() == "challenge"}
    mime = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", mime):
        result["content_type"] = mime
    # Only retain a hash for correlation, never arbitrary server header values.
    request_id = headers.get("x-request-id") or headers.get("cf-ray")
    if request_id:
        import hashlib
        result["request_id_hash"] = hashlib.sha256(request_id.encode()).hexdigest()[:16]
    return result


def enable_if_requested():
    global _capture
    try:
        config = json.loads(LEASE.read_text(encoding="utf-8"))
        deadline = float(config["deadline"] if isinstance(config, dict) else config)
    except (OSError, ValueError, TypeError, KeyError):
        return
    if not time.time() < deadline <= time.time() + 3600:
        return
    from curl_cffi.requests import AsyncSession
    import requests
    full = isinstance(config, dict) and config.get("mode") == "redacted-http"
    _capture = CaptureWriter(deadline) if full else None

    def emit(method, url, started, response=None, error=None, request_data=None, stream=False):
        try:
            endpoint = safe_endpoint(url)
            if endpoint is None or time.time() >= deadline or not LEASE.is_file():
                return
            entry = {**endpoint, "method": str(method).upper() if str(method).upper() in
                     {"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"} else "OTHER",
                     "elapsed_ms": round((time.monotonic() - started) * 1000)}
            if response is not None:
                entry.update(status=int(response.status_code), **response_metadata(response.headers))
            if error is not None:
                entry["exception"] = type(error).__name__
                match = re.search(r"curl: \((\d+)\)", str(error))
                if match:
                    entry["curl_code"] = int(match[1])
            if _capture is not None and request_data is not None:
                snapshot = {"event": "http_transaction", "transport": "python", "request_ref": uuid.uuid4().hex,
                            "request": request_data, "elapsed_ms": entry["elapsed_ms"]}
                if response is not None:
                    prepared = getattr(response, "request", None)
                    if prepared is not None:
                        snapshot["request"] = _capture.request(getattr(prepared, "method", method),
                            getattr(prepared, "url", url), getattr(prepared, "headers", {}),
                            getattr(prepared, "body", None), request_data.get("params"))
                    snapshot["response"] = _capture.response(getattr(response, "url", None) or url,
                        response.status_code, response.headers, None if stream else getattr(response, "content", None),
                        unavailable="stream_not_consumed" if stream else None)
                    snapshot["redirects"] = [
                        _capture.response(h.url, h.status_code, h.headers, getattr(h, "content", None))
                        if not isinstance(h, dict) else _capture.redactor.value(h)
                        for h in getattr(response, "history", [])]
                if error is not None:
                    snapshot["error"] = {k: entry[k] for k in ("exception", "curl_code") if k in entry}
                _capture.write(snapshot)
            log.info("[capture-http] %s", json.dumps(entry, ensure_ascii=True))
        except Exception:
            pass  # Diagnostics must never change the registration outcome.

    original_async = AsyncSession.request
    original_sync = requests.Session.request

    def request_data(session, method, url, kwargs):
        try:
            if _capture is None or not _capture.active() or safe_endpoint(url) is None:
                return None
            headers = {**dict(getattr(session, "headers", {}) or {}), **dict(kwargs.get("headers") or {})}
            body = kwargs.get("json") if kwargs.get("json") is not None else kwargs.get("data")
            return _capture.request(method, url, headers, body, kwargs.get("params"))
        except Exception as exc:
            log.warning("[capture-snapshot-unavailable] %s", type(exc).__name__)
            return None

    @functools.wraps(original_async)
    async def async_request(self, method, url, *args, **kwargs):
        started = time.monotonic()
        snapshot = request_data(self, method, url, kwargs)
        try:
            response = await original_async(self, method, url, *args, **kwargs)
        except Exception as exc:
            emit(method, url, started, error=exc, request_data=snapshot)
            raise
        emit(method, url, started, response=response, request_data=snapshot, stream=bool(kwargs.get("stream")))
        return response

    @functools.wraps(original_sync)
    def sync_request(self, method, url, *args, **kwargs):
        started = time.monotonic()
        snapshot = request_data(self, method, url, kwargs)
        try:
            response = original_sync(self, method, url, *args, **kwargs)
        except Exception as exc:
            emit(method, url, started, error=exc, request_data=snapshot)
            raise
        emit(method, url, started, response=response, request_data=snapshot, stream=bool(kwargs.get("stream")))
        return response

    AsyncSession.request = async_request
    requests.Session.request = sync_request
    log.info("[capture-ready] %s", "redacted full HTTP snapshots; credentials omitted" if full else "metadata-only; credentials omitted")
