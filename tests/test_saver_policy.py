"""Page-local traffic policy tests; no browser, mailbox or external service."""
from pathlib import Path
import sys

import pytest

CORE = Path(__file__).resolve().parents[1] / "core"
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

import browser_mgr


class Page:
    def __init__(self):
        self.calls = []
        self.fail_command = None

    def run_cdp(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if command == self.fail_command:
            raise RuntimeError("private value must not become public policy state")
        return {}


def block_calls(page):
    return [kwargs["urls"] for command, kwargs in page.calls if command == "Network.setBlockedURLs"]


@pytest.mark.parametrize("mode", ["saver", "headless"])
def test_pause_restore_is_page_local_and_idempotent(mode):
    page, other = Page(), Page()
    count = browser_mgr.configure_registration_traffic(page, mode)
    browser_mgr.configure_registration_traffic(other, mode)
    other_before = list(other.calls)
    original_urls = block_calls(page)[0]
    assert browser_mgr.disable_registration_traffic_filter(page)
    assert browser_mgr.disable_registration_traffic_filter(page)
    paused = browser_mgr.registration_traffic_state(page)
    assert paused["paused"] and not paused["applied"]
    assert paused["blocked_count"] == 0
    assert paused["pause_count"] == 1
    assert block_calls(page) == [original_urls, []]
    assert browser_mgr.restore_registration_traffic_filter(page)
    assert not browser_mgr.restore_registration_traffic_filter(page)
    restored = browser_mgr.registration_traffic_state(page)
    assert restored["mode"] == mode
    assert restored["applied"] and not restored["paused"]
    assert restored["blocked_count"] == count
    assert restored["restore_count"] == 1
    assert block_calls(page) == [original_urls, [], original_urls]
    assert other.calls == other_before
    assert browser_mgr.registration_traffic_state(other)["pause_count"] == 0
    assert browser_mgr.disable_registration_traffic_filter(page)
    assert browser_mgr.restore_registration_traffic_filter(page)
    assert browser_mgr.registration_traffic_state(page)["restore_count"] == 2


@pytest.mark.parametrize("configure_standard", [False, True])
def test_unowned_and_standard_pages_are_not_touched(configure_standard):
    page = Page()
    if configure_standard:
        assert browser_mgr.configure_registration_traffic(page, "standard") == 0
    assert not browser_mgr.disable_registration_traffic_filter(page)
    assert not browser_mgr.restore_registration_traffic_filter(page)
    assert page.calls == []
    assert browser_mgr.registration_traffic_state(page) == {
        "mode": "standard", "applied": False, "paused": False,
        "blocked_count": 0, "pause_count": 0, "restore_count": 0, "last_error": "",
    }


def test_failed_initial_configure_does_not_claim_applied_or_allow_restore():
    page = Page()
    page.fail_command = "Network.setBlockedURLs"
    assert browser_mgr.configure_registration_traffic(page, "saver") == 0
    state = browser_mgr.registration_traffic_state(page)
    assert not state["applied"] and not state["paused"]
    assert state["blocked_count"] == 0
    assert state["last_error"] == "configure_failed"
    page.calls.clear()
    assert not browser_mgr.disable_registration_traffic_filter(page)
    assert not browser_mgr.restore_registration_traffic_filter(page)
    assert page.calls == []


def test_pause_failure_is_honest_and_can_retry():
    page = Page()
    browser_mgr.configure_registration_traffic(page, "saver")
    page.fail_command = "Network.setBlockedURLs"
    assert not browser_mgr.disable_registration_traffic_filter(page)
    state = browser_mgr.registration_traffic_state(page)
    assert state["applied"] and not state["paused"]
    assert state["pause_count"] == 0
    assert state["last_error"] == "pause_failed"
    assert not browser_mgr.restore_registration_traffic_filter(page)
    page.fail_command = None
    assert browser_mgr.disable_registration_traffic_filter(page)
    assert browser_mgr.registration_traffic_state(page)["last_error"] == ""


def test_restore_failure_stays_paused_until_success():
    page = Page()
    browser_mgr.configure_registration_traffic(page, "saver")
    assert browser_mgr.disable_registration_traffic_filter(page)
    page.fail_command = "Network.setBlockedURLs"
    assert not browser_mgr.restore_registration_traffic_filter(page)
    state = browser_mgr.registration_traffic_state(page)
    assert state["paused"] and not state["applied"]
    assert state["restore_count"] == 0
    assert state["last_error"] == "restore_failed"
    page.fail_command = None
    assert browser_mgr.restore_registration_traffic_filter(page)
    assert browser_mgr.registration_traffic_state(page)["restore_count"] == 1


def test_failed_reconfiguration_preserves_last_confirmed_policy():
    page = Page()
    browser_mgr.configure_registration_traffic(page, "saver")
    original_urls = block_calls(page)[0]
    assert browser_mgr.disable_registration_traffic_filter(page)
    page.fail_command = "Network.setBlockedURLs"
    assert browser_mgr.configure_registration_traffic(page, "headless") == 0
    assert browser_mgr.registration_traffic_state(page)["mode"] == "saver"
    assert browser_mgr.registration_traffic_state(page)["paused"]
    page.fail_command = None
    assert browser_mgr.restore_registration_traffic_filter(page)
    assert block_calls(page)[-1] == original_urls


@pytest.mark.parametrize("paused", [False, True])
def test_explicit_standard_opt_out_removes_owned_policy_without_later_restore(paused):
    page = Page()
    browser_mgr.configure_registration_traffic(page, "saver")
    if paused:
        browser_mgr.disable_registration_traffic_filter(page)
    assert browser_mgr.configure_registration_traffic(page, "standard") == 0
    assert block_calls(page)[-1] == []
    assert not browser_mgr.restore_registration_traffic_filter(page)
    assert browser_mgr.registration_traffic_state(page)["mode"] == "standard"


def test_failed_standard_opt_out_keeps_actual_applied_state():
    page = Page()
    browser_mgr.configure_registration_traffic(page, "saver")
    page.fail_command = "Network.setBlockedURLs"
    assert browser_mgr.configure_registration_traffic(page, "standard") == 0
    state = browser_mgr.registration_traffic_state(page)
    assert state["mode"] == "saver" and state["applied"]
    assert state["last_error"] == "clear_failed"


def test_restore_uses_original_snapshot_not_mutated_global_policy(monkeypatch):
    page = Page()
    browser_mgr.configure_registration_traffic(page, "saver")
    original_urls = block_calls(page)[0]
    browser_mgr.disable_registration_traffic_filter(page)
    monkeypatch.setattr(browser_mgr, "REGISTRATION_SAVER_BLOCKED_URLS", ["*://example.test/new-rule*"])
    assert browser_mgr.restore_registration_traffic_filter(page)
    assert block_calls(page)[-1] == original_urls


def test_public_state_is_a_copy_and_contains_no_url_rules():
    page = Page()
    browser_mgr.configure_registration_traffic(page, "saver")
    public = browser_mgr.registration_traffic_state(page)
    public["mode"] = "standard"
    assert "blocked_urls" not in public
    assert browser_mgr.registration_traffic_state(page)["mode"] == "saver"


def test_saver_skips_woff_fonts_but_keeps_cache_scripts_styles_and_documents():
    page = Page()
    browser_mgr.configure_registration_traffic(page, "saver")
    urls = block_calls(page)[0]
    assert "*://*/*.woff*" in urls  # Also matches .woff2.
    assert all(not any(suffix in pattern for suffix in (".css", ".js", ".html")) for pattern in urls)
    browser_mgr.disable_registration_traffic_filter(page)
    browser_mgr.restore_registration_traffic_filter(page)
    cache_calls = [kwargs for command, kwargs in page.calls if command == "Network.setCacheDisabled"]
    assert cache_calls == [{"cacheDisabled": False}]
    assert not any(command.startswith("Fetch.") for command, _ in page.calls)


def test_missing_page_storage_fails_open_without_installing_unrecoverable_filter():
    class ReadOnlyPage:
        __slots__ = ()

        def run_cdp(self, *_args, **_kwargs):
            pytest.fail("CDP must not run without page-local policy storage")

    assert browser_mgr.configure_registration_traffic(ReadOnlyPage(), "saver") == 0
