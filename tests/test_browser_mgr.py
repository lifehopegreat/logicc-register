import browser_mgr


def test_local_chromium_aligns_japan_proxy(monkeypatch):
    class Options:
        def __init__(self): self.arguments = []
        def headless(self, _value): pass
        def set_browser_path(self, _value): pass
        def auto_port(self): pass
        def set_proxy(self, _value): pass
        def set_argument(self, value): self.arguments.append(value)

    class Page:
        def __init__(self, options): self.options, self.cdp = options, []
        def run_cdp(self, command, **kwargs): self.cdp.append((command, kwargs))

    monkeypatch.setattr(browser_mgr, "ChromiumOptions", Options)
    monkeypatch.setattr(browser_mgr, "ChromiumPage", Page)
    monkeypatch.setattr(browser_mgr.config, "CHROME_PATH", "")
    monkeypatch.setattr(browser_mgr, "_resolve_default_chrome_path", lambda: "")

    page = browser_mgr.open_local_chromium(
        proxy="http://127.0.0.1:19080",
        region_hint="http://user-region-JP@proxy:3010",
    )

    assert "--lang=ja-JP" in page.options.arguments
    assert "--webrtc-ip-handling-policy=disable_non_proxied_udp" in page.options.arguments
    assert "--force-webrtc-ip-handling-policy=disable_non_proxied_udp" in page.options.arguments
    assert ("Emulation.setTimezoneOverride", {"timezoneId": "Asia/Tokyo"}) in page.cdp


def test_local_chromium_aligns_other_proxy_regions(monkeypatch):
    class Options:
        def __init__(self): self.arguments = []
        def headless(self, _value): pass
        def set_browser_path(self, _value): pass
        def auto_port(self): pass
        def set_proxy(self, _value): pass
        def set_argument(self, value): self.arguments.append(value)

    class Page:
        def __init__(self, options): self.options, self.cdp = options, []
        def run_cdp(self, command, **kwargs): self.cdp.append((command, kwargs))

    monkeypatch.setattr(browser_mgr, "ChromiumOptions", Options)
    monkeypatch.setattr(browser_mgr, "ChromiumPage", Page)
    monkeypatch.setattr(browser_mgr.config, "CHROME_PATH", "")
    monkeypatch.setattr(browser_mgr, "_resolve_default_chrome_path", lambda: "")

    page = browser_mgr.open_local_chromium(
        proxy="http://127.0.0.1:19080",
        region_hint="http://user-region-DE-sid-test@proxy:3010",
    )

    assert "--lang=de-DE" in page.options.arguments
    assert ("Emulation.setTimezoneOverride", {"timezoneId": "Europe/Berlin"}) in page.cdp
    assert ("Emulation.setLocaleOverride", {"locale": "de-DE"}) in page.cdp
    assert (
        "Network.setExtraHTTPHeaders",
        {"headers": {"Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"}},
    ) in page.cdp
    assert browser_mgr._proxy_environment("US") == (
        "US", "en-US", "America/New_York",
    )
    assert browser_mgr._proxy_environment("user-region-TR-sid-test") == (
        "TR", "tr-TR", "Europe/Istanbul",
    )
