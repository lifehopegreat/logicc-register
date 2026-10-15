"""Passive, separately connected CDP recorder for project-created browser tabs."""
from __future__ import annotations

import base64
import json
import logging
import re
import threading
import time
import uuid
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener

from registration_diagnostics import safe_endpoint

log = logging.getLogger("registration_diagnostics")


class BrowserCapture(threading.Thread):
    def __init__(self, page, writer):
        super().__init__(name="redacted-http-capture", daemon=True)
        import websocket
        self.writer = writer
        self.websocket = websocket
        self.pending = {}
        self.commands = {}
        self.sequence = 1
        self.queued = []
        address = str(page.address)
        parsed = urlsplit("http://" + address)
        if parsed.hostname not in {"localhost", "127.0.0.1"} or not parsed.port:
            raise ValueError("diagnostics require a loopback CDP address")
        with build_opener(ProxyHandler({})).open(f"http://{address}/json/list", timeout=2) as response:
            target = next(t for t in json.load(response) if t.get("id") == page.tab_id)
        ws_url = target["webSocketDebuggerUrl"]
        ws_parsed = urlsplit(ws_url)
        if ws_parsed.hostname not in {"localhost", "127.0.0.1"} or ws_parsed.port != parsed.port:
            raise ValueError("unexpected CDP endpoint")
        self.ws = websocket.create_connection(ws_url, timeout=2, suppress_origin=True,
            http_no_proxy=["localhost", "127.0.0.1"])
        try:
            self.ws.send(json.dumps({"id": 1, "method": "Network.enable", "params": {
                "maxPostDataSize": 16 * 1024 * 1024, "maxResourceBufferSize": 16 * 1024 * 1024,
                "maxTotalBufferSize": 64 * 1024 * 1024}}))
            until = time.monotonic() + 3
            while time.monotonic() < until:
                message = json.loads(self.ws.recv())
                if message.get("id") == 1:
                    if "error" in message:
                        raise RuntimeError("CDP Network.enable rejected")
                    break
                self.queued.append(message)
            else:
                raise TimeoutError("CDP Network.enable not acknowledged")
            self.ws.settimeout(.2)
            self.writer.write({"event": "browser_capture_ready", "transport": "browser_cdp"})
        except Exception:
            self.ws.close()
            raise

    def command(self, method, request_id, kind):
        self.sequence += 1
        self.commands[self.sequence] = (request_id, kind, time.monotonic())
        self.ws.send(json.dumps({"id": self.sequence, "method": method,
                                "params": {"requestId": request_id}}))

    def finish(self, request_id, reason=None):
        record = self.pending.pop(request_id, None)
        if record is None:
            return
        record.pop("started", None)
        if reason:
            if "response" in record:
                if record["response"].get("body", {}).get("reason") == "awaiting_body" or "body" not in record["response"]:
                    record["response"]["body"] = {"kind": "unavailable", "reason": reason}
            else:
                record["error"] = reason
        self.writer.write(record)

    def consume(self, message):
        command = self.commands.pop(message.get("id"), None)
        if command:
            request_id, kind, _ = command
            record = self.pending.get(request_id)
            if record is None:
                return
            result = message.get("result", {})
            if kind == "request_body":
                if "postData" in result:
                    mime = record["request"]["headers"].get("content-type", "")
                    with self.writer.lock:
                        record["request"]["body"] = self.writer.redactor.body(result["postData"], mime)
                else:
                    record["request"]["body"] = {"kind": "unavailable", "reason": "cdp_post_data_unavailable"}
            else:
                if "body" in result:
                    body = base64.b64decode(result["body"], validate=True) if result.get("base64Encoded") else result["body"]
                    mime = record.get("response", {}).get("headers", {}).get("content-type", "")
                    with self.writer.lock:
                        record["response"]["body"] = self.writer.redactor.body(body, mime,
                            mailbox=record["host"] == "graph.microsoft.com")
                    self.finish(request_id)
                else:
                    self.finish(request_id, "cdp_response_body_unavailable")
            return
        params = message.get("params", {})
        request_id = params.get("requestId")
        method = message.get("method")
        if method == "Network.requestWillBeSent":
            request = params.get("request", {})
            endpoint = safe_endpoint(request.get("url", ""))
            if not endpoint:
                return
            previous_ref = None
            if request_id in self.pending:
                previous_ref = self.pending[request_id]["request_ref"]
                redirect = params.get("redirectResponse")
                if redirect:
                    self.pending[request_id]["response"] = self.writer.response(redirect.get("url", ""),
                        redirect.get("status", 0), redirect.get("headers", {}), unavailable="redirect_body_not_exposed_by_cdp")
                self.finish(request_id, "redirect_or_reused_request_id")
            record = {"event": "http_transaction", "transport": "browser_cdp", "request_ref": uuid.uuid4().hex,
                **endpoint, "started": time.monotonic(),
                "request": self.writer.request(request.get("method", "OTHER"), request.get("url", ""),
                    request.get("headers", {}), request.get("postData")), "resource_type": params.get("type", "")}
            if previous_ref:
                record["redirect_from"] = previous_ref
            self.pending[request_id] = record
            if request.get("hasPostData") and "postData" not in request:
                self.command("Network.getRequestPostData", request_id, "request_body")
        elif method == "Network.requestWillBeSentExtraInfo" and request_id in self.pending:
            with self.writer.lock:
                self.pending[request_id]["request"]["headers"].update(self.writer.redactor.headers(params.get("headers", {})))
        elif method == "Network.responseReceived" and request_id in self.pending:
            response = params.get("response", {})
            record = self.pending[request_id]
            record["elapsed_ms"] = round((time.monotonic() - record["started"]) * 1000)
            record["response"] = self.writer.response(response.get("url", ""), response.get("status", 0),
                                                     response.get("headers", {}), unavailable="awaiting_body")
            record["response"].update(protocol=response.get("protocol", ""), from_cache=bool(response.get("fromDiskCache")))
        elif method == "Network.responseReceivedExtraInfo" and request_id in self.pending:
            with self.writer.lock:
                self.pending[request_id].setdefault("response", {})["headers"] = self.writer.redactor.headers(params.get("headers", {}))
        elif method == "Network.loadingFinished" and request_id in self.pending:
            record = self.pending[request_id]
            if "response" not in record or "status" not in record["response"]:
                self.finish(request_id, "response_event_missing")
                return
            mime = record["response"]["headers"].get("content-type", "").lower()
            record["elapsed_ms"] = round((time.monotonic() - record["started"]) * 1000)
            record["encoded_bytes"] = int(params.get("encodedDataLength", 0))
            if record["response"]["status"] in {204, 304} or record["request"]["method"] == "HEAD":
                record["response"]["body"] = {"kind": "empty"}
                self.finish(request_id)
            elif mime.startswith(("image/", "audio/", "video/", "font/")):
                record["response"]["body"] = {"kind": "binary", "reason": "binary_not_persisted"}
                self.finish(request_id)
            else:
                self.command("Network.getResponseBody", request_id, "response_body")
        elif method == "Network.loadingFailed" and request_id in self.pending:
            error = params.get("errorText", "")
            self.pending[request_id]["error"] = error if re.fullmatch(r"net::ERR_[A-Z0-9_]+", error) else "network_error"
            self.finish(request_id, "network_failure")

    def run(self):
        try:
            for message in self.queued:
                self.consume(message)
            self.queued.clear()
            while self.writer.active():
                try:
                    message = json.loads(self.ws.recv())
                except self.websocket.WebSocketTimeoutException:
                    message = {}
                self.consume(message)
                for command_id, (request_id, kind, started) in list(self.commands.items()):
                    if time.monotonic() - started > 5:
                        del self.commands[command_id]
                        if kind == "response_body":
                            self.finish(request_id, "cdp_body_command_timeout")
        except Exception as exc:
            log.warning("[capture-browser-disconnected] %s", type(exc).__name__)
        finally:
            self.ws.close()
            for request_id in list(self.pending):
                self.finish(request_id, "browser_disconnected_before_body")
