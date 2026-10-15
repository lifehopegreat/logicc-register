"""Synthetic CDP events only: no browser, account, proxy or external network."""
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from browser_traffic_metrics import BrowserTrafficMetrics


class FakeDriver:
    def __init__(self):
        self.event_handlers = {}
        self.immediate_event_handlers = {}

    def set_callback(self, event, callback, immediate=False):
        handlers = self.immediate_event_handlers if immediate else self.event_handlers
        if callback:
            handlers[event] = callback
        else:
            handlers.pop(event, None)

    def emit(self, event, **params):
        callback = self.immediate_event_handlers.get("Network." + event) or self.event_handlers.get("Network." + event)
        if callback:
            callback(**params)


class FakePage:
    def __init__(self):
        self._driver = FakeDriver()
        self.commands = []

    def run_cdp(self, method, **params):
        self.commands.append((method, params))


@pytest.fixture
def collector():
    page = FakePage()
    metrics = BrowserTrafficMetrics(page)
    assert metrics.start()
    yield page, metrics
    metrics.close()


def request(page, request_id="1", url="https://static.example.test/asset", kind="Image", **params):
    page._driver.emit("requestWillBeSent", requestId=request_id,
                      request={"url": url}, type=kind, **params)


def test_success_uses_encoded_final_once_not_decoded_or_chunks(collector):
    page, metrics = collector
    request(page)
    page._driver.emit("responseReceived", requestId="1", response={"encodedDataLength": 50})
    page._driver.emit("dataReceived", requestId="1", encodedDataLength=100, dataLength=1000)
    page._driver.emit("dataReceived", requestId="1", encodedDataLength=200, dataLength=2000)
    page._driver.emit("loadingFinished", requestId="1", encodedDataLength=350)
    result = metrics.close()
    assert result["totals"]["encoded_bytes"] == 350
    assert result["totals"]["completed"] == 1
    assert result["totals"]["partial_encoded_bytes_lower_bound"] == 0
    assert not result["active"]
    assert result["available"] is result["enabled"] is True
    assert page.commands == [("Network.enable", {})]
    assert not page._driver.event_handlers


def test_failed_and_pending_partial_bytes_are_lower_bounds(collector):
    page, metrics = collector
    request(page)
    page._driver.emit("responseReceived", requestId="1", response={"encodedDataLength": 50})
    page._driver.emit("dataReceived", requestId="1", encodedDataLength=100)
    page._driver.emit("loadingFailed", requestId="1", errorText="private-token")
    request(page, "2")
    page._driver.emit("dataReceived", requestId="2", encodedDataLength=20)
    result = metrics.close()
    assert result["totals"]["failed"] == 1
    assert result["totals"]["in_flight"] == 1
    assert result["totals"]["encoded_bytes"] == 120  # no double addition of response snapshot
    assert result["totals"]["partial_encoded_bytes_lower_bound"] == 120
    assert result["partial_bytes_are_lower_bounds"] is True
    assert "private-token" not in json.dumps(result)


def test_redirects_count_each_hop_and_preserve_start_stage(collector):
    page, metrics = collector
    request(page, url="https://example.test/first")
    page._driver.emit("dataReceived", requestId="1", encodedDataLength=15)
    metrics.set_stage("signup")
    request(page, url="https://example.test/next", redirectResponse={"encodedDataLength": 25})
    page._driver.emit("loadingFinished", requestId="1", encodedDataLength=75)
    result = metrics.snapshot()
    assert result["totals"]["completed"] == 2
    assert result["totals"]["redirects"] == 1
    assert result["totals"]["encoded_bytes"] == 100
    assert {row["stage"]: row["encoded_bytes"] for row in result["top_resources"]} == {"startup": 25, "signup": 75}


@pytest.mark.parametrize("source,flag", [("disk", "fromDiskCache"), ("service_worker", "fromServiceWorker"), ("prefetch", "fromPrefetchCache")])
def test_cache_flags_do_not_count_decoded_bytes(collector, source, flag):
    page, metrics = collector
    request(page)
    page._driver.emit("requestServedFromCache", requestId="1")
    page._driver.emit("responseReceived", requestId="1", response={flag: True})
    page._driver.emit("loadingFinished", requestId="1", encodedDataLength=0)
    result = metrics.snapshot()
    assert result["cache_sources"] == {source: 1}
    assert result["totals"]["encoded_bytes"] == 0


def test_generic_cache_event_does_not_invent_memory_cache_source(collector):
    page, metrics = collector
    request(page)
    page._driver.emit("requestServedFromCache", requestId="1")
    assert metrics.snapshot()["cache_sources"] == {"cache_unspecified": 1}


def test_password_queue_is_a_named_stage(collector):
    page, metrics = collector
    metrics.set_stage("password_wait")
    request(page)
    assert metrics.snapshot()["top_resources"][0]["stage"] == "password_wait"


def test_sensitive_url_fields_never_appear_and_query_does_not_change_group(collector):
    page, metrics = collector
    metrics.set_stage("victim@example.test")
    for index, query in enumerate(("secret=first-token", "secret=second-token")):
        request(page, str(index), f"https://user:password@private.example.test/user/victim@example.test?{query}#fragment")
        page._driver.emit("responseReceived", requestId=str(index),
                          response={"headers": {"Set-Cookie": "session=secret"}, "url": "private"})
        page._driver.emit("loadingFinished", requestId=str(index), encodedDataLength=10)
    result = metrics.snapshot()
    assert len(result["top_resources"]) == 1
    text = json.dumps(result)
    for private in ("victim", "example.test", "first-token", "second-token", "Set-Cookie", "fragment", "session=", "/user/"):
        assert private not in text
    row = result["top_resources"][0]
    assert len(row["host_hash"]) == len(row["path_hash"]) == 24
    assert row["stage"].startswith("stage#")


@pytest.mark.parametrize("immediate", [False, True])
def test_existing_callbacks_are_never_overwritten(immediate):
    page = FakePage()
    original = lambda **params: None
    page._driver.set_callback("Network.dataReceived", original, immediate=immediate)
    metrics = BrowserTrafficMetrics(page)
    assert metrics.start() is False
    assert metrics.snapshot()["reason"] == "callback_conflict"
    metrics.close()
    registry = page._driver.immediate_event_handlers if immediate else page._driver.event_handlers
    assert registry["Network.dataReceived"] is original
    assert not page.commands


def test_close_preserves_later_callback_owner_and_other_events(collector):
    page, metrics = collector
    newer = lambda **params: None
    page._driver.set_callback("Network.dataReceived", newer)
    page._driver.set_callback("Page.loadEventFired", newer)
    assert metrics.snapshot()["callback_ownership_lost"] is True
    result = metrics.close()
    assert result["callback_ownership_lost"] is True
    assert page._driver.event_handlers == {"Network.dataReceived": newer, "Page.loadEventFired": newer}
    assert metrics.close() == result


def test_framework_shutdown_before_close_is_not_false_callback_takeover(collector):
    page, metrics = collector
    request(page)
    page._driver.emit("dataReceived", requestId="1", encodedDataLength=10)
    page._driver.is_running = False
    page._driver.event_handlers.clear()  # mirrors installed Driver._stop()
    result = metrics.close()
    assert result["driver_stopped_before_close"] is True
    assert result["callback_ownership_lost"] is False
    assert result["totals"]["in_flight"] == 1
    assert result["totals"]["partial_encoded_bytes_lower_bound"] == 10


def test_unsupported_or_failed_attach_fails_open_and_cleans_own_slots():
    unsupported = BrowserTrafficMetrics(object())
    assert not unsupported.start()
    assert unsupported.close()["reason"] == "unsupported_callbacks"
    page = FakePage()
    def fail(*args, **kwargs):
        raise RuntimeError("must not persist exception details")
    page.run_cdp = fail
    metrics = BrowserTrafficMetrics(page)
    assert not metrics.start()
    assert not page._driver.event_handlers
    assert "exception details" not in json.dumps(metrics.close())


def test_disconnected_page_property_and_mid_attach_failure_fail_open():
    class Disconnected:
        @property
        def _driver(self):
            raise RuntimeError("private disconnected page details")
    metrics = BrowserTrafficMetrics(Disconnected())
    assert not metrics.start()
    assert metrics.close()["reason"] == "unsupported_callbacks"
    page = FakePage()
    original = page._driver.set_callback
    def fail_second(event, callback, **kwargs):
        if event == "Network.responseReceived" and callback:
            raise RuntimeError("synthetic failure")
        original(event, callback, **kwargs)
    page._driver.set_callback = fail_second
    metrics = BrowserTrafficMetrics(page)
    assert not metrics.start()
    assert not page._driver.event_handlers
    assert not page.commands
    assert metrics.close()["callback_ownership_lost"] is False


def test_query_only_urls_ignore_query_without_remembering_raw_url(collector):
    page, metrics = collector
    request(page, "1", "https://example.test?email=private@example.test")
    request(page, "2", "https://example.test?email=another@example.test")
    result = metrics.snapshot()
    assert len(result["top_resources"]) == 1
    assert result["totals"]["in_flight"] == 2
    assert "email" not in repr(metrics._pending)
    assert "example.test" not in repr(metrics._pending)


def test_late_join_redirect_is_marked_incomplete_not_invented(collector):
    page, metrics = collector
    request(page, redirectResponse={"encodedDataLength": 25})
    page._driver.emit("loadingFinished", requestId="1", encodedDataLength=75)
    result = metrics.snapshot()
    assert result["totals"]["encoded_bytes"] == 75
    assert result["orphan_events"] == 1


def test_pending_and_aggregate_bounds_keep_overflow_visible(monkeypatch, collector):
    page, metrics = collector
    monkeypatch.setattr(metrics, "MAX_PENDING", 2)
    monkeypatch.setattr(metrics, "MAX_GROUPS", 3)
    monkeypatch.setattr(metrics, "TOP_N", 2)
    for i in range(10):
        request(page, str(i), f"https://example.test/asset/{i}")
        page._driver.emit("dataReceived", requestId=str(i), encodedDataLength=10)
    result = metrics.snapshot()
    assert len(metrics._pending) == 2
    assert len(metrics._groups) <= 3
    assert len(result["top_resources"]) <= 2
    assert result["group_limit_reached"]
    assert result["overflow_hops"] == result["totals"]["evicted"] == 8
    assert result["totals"]["encoded_bytes"] == 100
    assert result["totals"]["in_flight"] == 2
    page._driver.emit("loadingFinished", requestId="0", encodedDataLength=1000)
    assert metrics.snapshot()["orphan_events"] == 1


def test_malformed_and_late_events_cannot_kill_driver_callback(collector):
    page, metrics = collector
    page._driver.emit("requestWillBeSent", requestId=["invalid"])
    request(page)
    page._driver.emit("dataReceived", requestId="1", encodedDataLength=float("nan"))
    page._driver.emit("dataReceived", requestId="1", encodedDataLength=-1)
    callback = page._driver.event_handlers["Network.loadingFinished"]
    result = metrics.close()
    callback(requestId="1", encodedDataLength=999)
    assert metrics.snapshot() == result
    assert result["callback_errors"] == 1
    assert result["totals"]["encoded_bytes"] == 0


def test_concurrent_callbacks_and_snapshots_are_consistent(collector):
    page, metrics = collector
    def run(index):
        request(page, str(index))
        page._driver.emit("dataReceived", requestId=str(index), encodedDataLength=5)
        metrics.snapshot()
        page._driver.emit("loadingFinished", requestId=str(index), encodedDataLength=10)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(run, range(100)))
    result = metrics.close()
    assert result["totals"]["completed"] == 100
    assert result["totals"]["encoded_bytes"] == 1000
    assert result["totals"]["in_flight"] == 0
    assert result["callback_errors"] == 0
