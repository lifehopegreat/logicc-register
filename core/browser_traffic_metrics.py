"""Bounded, passive CDP attribution, not a proxy bill; no response bodies.

Only vacant DrissionPage callback slots are used. Attach before other listener
registration; an occupied ordinary OR immediate slot makes start() fail open.
Hashes are keyed per collector: intentionally not correlatable across runs.
"""
from __future__ import annotations

from collections import OrderedDict
from copy import deepcopy
from hashlib import blake2b
import math
import re
import secrets
from threading import RLock


class BrowserTrafficMetrics:
    MAX_PENDING = 512
    MAX_GROUPS = 256
    TOP_N = 20
    EVENTS = ("requestWillBeSent", "responseReceived", "dataReceived",
              "loadingFinished", "loadingFailed", "requestServedFromCache")
    TYPES = frozenset(("Document", "Stylesheet", "Image", "Media", "Font", "Script",
                       "TextTrack", "XHR", "Fetch", "Prefetch", "EventSource",
                       "WebSocket", "Manifest", "SignedExchange", "Ping", "CSPViolationReport", "Other"))
    STAGES = frozenset(("startup", "signup", "password_wait", "password", "login", "oauth", "mfa", "twofa", "done", "unknown"))
    COUNTERS = ("completed", "failed", "in_flight", "evicted", "redirects",
                "encoded_bytes", "partial_encoded_bytes_lower_bound")
    OVERFLOW = ("other", "Other", "overflow", "overflow")

    def __init__(self, page):
        self._page = page
        self._driver = None
        self._lock = RLock()
        self._salt = secrets.token_bytes(16)
        self._stage = "startup"
        self._pending = OrderedDict()
        self._groups = {}
        self._callbacks = {}
        self._active = False
        self._closed = False
        self._reason = "not_started"
        self._errors = 0
        self._orphans = 0
        self._overflow_hops = 0
        self._ownership_lost = False
        self._stopped_before_close = False

    def _hash(self, value):
        return blake2b(value.encode("utf-8", "replace"), key=self._salt, digest_size=12).hexdigest()

    def set_stage(self, stage: str):
        # Never echo arbitrary caller data (email, URL, token) as a stage label.
        with self._lock:
            if not self._closed:
                self._stage = stage if stage in self.STAGES else "stage#" + self._hash(str(stage)[:1024])

    def start(self) -> bool:
        with self._lock:
            if self._closed or self._active:
                return self._active
            try:
                driver = getattr(self._page, "_driver", None)
                normal = getattr(driver, "event_handlers", None)
                immediate = getattr(driver, "immediate_event_handlers", None)
            except Exception:
                self._reason = "unsupported_callbacks"
                return False
            if (not isinstance(normal, dict) or not isinstance(immediate, dict)
                    or not callable(getattr(driver, "set_callback", None))
                    or not callable(getattr(self._page, "run_cdp", None))):
                self._reason = "unsupported_callbacks"
                return False
            if any("Network." + name in normal or "Network." + name in immediate for name in self.EVENTS):
                self._reason = "callback_conflict"
                return False
            self._driver = driver
            self._active = True
            try:
                for name in self.EVENTS:
                    event = "Network." + name
                    if event in normal or event in immediate:
                        raise RuntimeError("callback_conflict")
                    callback = lambda _name=name, **params: self._event(_name, params)
                    self._callbacks[event] = callback
                    driver.set_callback(event, callback)
                # Enable notifications only. Never alter cache, SW, routing or Fetch.
                self._page.run_cdp("Network.enable")
            except Exception:
                self._active = False
                self._reason = "attach_failed"
                self._detach()
                return False
            self._reason = "attached"
            return True

    @staticmethod
    def _bytes(value):
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if math.isfinite(value) and value >= 0:
                return int(value)
        return 0

    def _key(self, params):
        url = (params.get("request") or {}).get("url", "")
        # Do not use urlsplit's global LRU: it would retain complete private URLs.
        match = re.match(r"https?://([^/?#]*)([^?#]*)", url, re.IGNORECASE) if isinstance(url, str) and len(url) <= 16384 else None
        authority, path = match.groups() if match else ("non_http_or_invalid", "/")
        host = authority.rsplit("@", 1)[-1].lower()
        kind = params.get("type", "Other")
        return (self._stage, kind if kind in self.TYPES else "Other", self._hash(host), self._hash(path or "/"))

    @staticmethod
    def _cache(item, response):
        for flag, source in (("fromServiceWorker", "service_worker"), ("fromDiskCache", "disk"),
                             ("fromPrefetchCache", "prefetch")):
            if response.get(flag):
                item["cache"] = source
                return

    def _row(self, key):
        return dict(zip(("stage", "resource_type", "host_hash", "path_hash"), key),
                    **{name: 0 for name in self.COUNTERS}, cache_sources={})

    def _add(self, rows, item, outcome, amount, partial=False):
        key = item["key"]
        if key not in rows and len(rows) >= self.MAX_GROUPS - 1:
            key = self.OVERFLOW
        row = rows.setdefault(key, self._row(key))
        row["completed" if outcome == "redirect" else outcome] += 1
        row["redirects"] += outcome == "redirect"
        row["encoded_bytes"] += amount
        if partial:
            row["partial_encoded_bytes_lower_bound"] += amount
        sources = row["cache_sources"]
        sources[item["cache"]] = sources.get(item["cache"], 0) + 1

    @staticmethod
    def _partial(item):
        # Snapshot and chunk counts may overlap; max is a conservative lower bound.
        return max(item["chunks"], item["response_bytes"])

    def _finish(self, request_id, outcome, response=None, encoded=None):
        item = self._pending.pop(request_id, None)
        if item is None:
            self._orphans += 1
            return
        if response:
            self._cache(item, response)
        partial = outcome in ("failed", "evicted") or encoded is None
        amount = self._partial(item) if partial else self._bytes(encoded)
        self._add(self._groups, item, outcome, amount, partial)

    def _event(self, name, params):
        # Driver event threads must never be terminated by instrumentation errors.
        with self._lock:
            if not self._active:
                return
            try:
                request_id = params.get("requestId")
                if not isinstance(request_id, str) or len(request_id) > 128:
                    self._errors += 1
                    return
                if name == "requestWillBeSent":
                    if params.get("redirectResponse") and request_id not in self._pending:
                        self._orphans += 1  # joined late / previous hop evicted: attribution incomplete
                    if request_id in self._pending:
                        response = params.get("redirectResponse")
                        self._finish(request_id, "redirect" if response else "evicted", response,
                                     response.get("encodedDataLength") if response else None)
                    if len(self._pending) >= self.MAX_PENDING:
                        self._finish(next(iter(self._pending)), "evicted")
                        self._overflow_hops += 1
                    self._pending[request_id] = dict(key=self._key(params), chunks=0,
                                                    response_bytes=0, cache="network_or_unknown")
                    return
                item = self._pending.get(request_id)
                if item is None:
                    self._orphans += 1
                elif name == "responseReceived":
                    response = params.get("response") or {}
                    self._cache(item, response)
                    item["response_bytes"] = self._bytes(response.get("encodedDataLength"))
                elif name == "dataReceived":
                    item["chunks"] += self._bytes(params.get("encodedDataLength"))
                elif name == "requestServedFromCache":
                    if item["cache"] == "network_or_unknown":
                        item["cache"] = "cache_unspecified"
                elif name == "loadingFinished":
                    self._finish(request_id, "completed", encoded=params.get("encodedDataLength"))
                elif name == "loadingFailed":
                    self._finish(request_id, "failed")
            except Exception:
                self._errors += 1

    def snapshot(self) -> dict:
        with self._lock:
            rows = deepcopy(self._groups)
            for item in self._pending.values():
                self._add(rows, item, "in_flight", self._partial(item), True)
            totals = {name: sum(row[name] for row in rows.values()) for name in self.COUNTERS}
            sources = {}
            for row in rows.values():
                for name, count in row["cache_sources"].items():
                    sources[name] = sources.get(name, 0) + count
            lost = bool(self._active and getattr(self._driver, "is_running", True) and any(
                self._driver.event_handlers.get(event) is not callback
                or event in self._driver.immediate_event_handlers for event, callback in self._callbacks.items()))
            self._ownership_lost |= lost
            return dict(available=self._reason == "attached", enabled=self._reason == "attached", active=self._active, reason=self._reason,
                        scope="page_target_cdp_received_bytes_not_proxy_billing", stage_attribution="request_start",
                        totals=totals, cache_sources=sources,
                        top_resources=sorted(rows.values(), key=lambda row: row["encoded_bytes"], reverse=True)[:self.TOP_N],
                        max_pending=self.MAX_PENDING, max_groups=self.MAX_GROUPS,
                        overflow_hops=self._overflow_hops, orphan_events=self._orphans,
                        callback_errors=self._errors, callback_ownership_lost=self._ownership_lost,
                        driver_stopped_before_close=self._stopped_before_close,
                        partial_bytes_are_lower_bounds=True, group_limit_reached=self.OVERFLOW in rows)

    def _detach(self):
        for event, callback in self._callbacks.items():
            try:
                if self._driver.event_handlers.get(event) is callback:
                    self._driver.set_callback(event, None)
                elif self._reason == "attached" and getattr(self._driver, "is_running", True):
                    self._ownership_lost = True
                if event in self._driver.immediate_event_handlers:
                    self._ownership_lost = True
            except Exception:
                self._errors += 1
        self._callbacks.clear()

    def close(self) -> dict:
        with self._lock:
            if not self._closed and self._driver is not None:
                # DrissionPage clears its queued notifications on disconnect.
                self._stopped_before_close = getattr(self._driver, "is_running", True) is False
            self._active = False
            self._closed = True
            self._detach()
            return self.snapshot()
