"""Opt-in Chromium check against a loopback-only synthetic site, never accounts."""
import base64
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time

import pytest
from DrissionPage.errors import ContextLostError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from browser_mgr import (
    _resolve_default_chrome_path, configure_registration_traffic,
    disable_registration_traffic_filter, restore_registration_traffic_filter,
)
from browser_traffic_metrics import BrowserTrafficMetrics


@pytest.mark.skipif(os.environ.get("RUN_LOCAL_BROWSER_TESTS") != "1", reason="opt-in loopback Chromium test")
def test_saver_blocks_fonts_preserves_cache_and_can_restore(tmp_path):
    from DrissionPage import ChromiumOptions, ChromiumPage
    chrome = _resolve_default_chrome_path()
    font_path = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts/arial.ttf"
    if not chrome or not font_path.exists():
        pytest.skip("local Chrome/Arial test fixture unavailable")
    font = font_path.read_bytes()
    png = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jB5kAAAAASUVORK5CYII=")
    requests, byte_counts = Counter(), Counter()
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path.endswith(".woff2"):
                # Valid TTF bytes at a WOFF-named URL exercise URL filtering.
                content, mime = font, "font/ttf"
            elif path.endswith(".png"):
                content, mime = png, "image/png"
            elif path.endswith(".js"):
                content, mime = b"window.fixtureReady=true;/*" + b"x" * 4096 + b"*/", "application/javascript"
            else:
                suffix = path.replace("/", "")
                content = ("<!doctype html><meta charset=utf-8><title>Local resource fixture</title>"
                           "<script src='/asset.js'></script><style>"
                           "@font-face{font-family:FixtureWebFont;src:url('/fixture-font.woff2?v=" + suffix + "') format('truetype')}"
                           "body{font-family:FixtureWebFont,Arial,sans-serif}</style>"
                           "<h1>省流量本地测试 / 日本語 / Continue</h1><img src='/pixel.png'>"
                           "<button id='continue' onclick=\"document.querySelector('#result').textContent='完成'\">继续</button>"
                           "<p id=result></p>").encode("utf-8")
                mime = "text/html; charset=utf-8"
            with lock:
                requests[path] += 1
                byte_counts[path] += len(content)
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "public, max-age=3600" if path.endswith((".js", ".png", ".woff2")) else "no-store")
            self.end_headers()
            try: self.wfile.write(content)
            except OSError: pass

    def wait_for(predicate):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                if predicate(): return
            except ContextLostError:
                pass  # Navigation may replace the execution context before CDP settles.
            time.sleep(0.025)
        assert predicate()

    reports = []
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            for mode in ("standard", "saver"):
                with lock:
                    requests.clear(); byte_counts.clear()
                opts = ChromiumOptions().headless(True)
                opts.set_browser_path(chrome)
                opts.set_user_data_path(str(tmp_path / mode))
                with socket.socket() as port_socket:
                    port_socket.bind(("127.0.0.1", 0))
                    opts.set_local_port(port_socket.getsockname()[1])
                for arg in ("--no-first-run", "--disable-background-networking", "--disable-component-update", "--no-proxy-server"):
                    opts.set_argument(arg)
                opts.set_argument("--host-resolver-rules", "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost")
                page = ChromiumPage(opts)
                metrics = BrowserTrafficMetrics(page)
                try:
                    configure_registration_traffic(page, mode)
                    assert metrics.start()
                    metrics.set_stage("signup")
                    base = f"http://127.0.0.1:{server.server_address[1]}"
                    assert page.get(base + "/initial", retry=0, timeout=10), page.url
                    wait_for(lambda: page.run_js("return window.fixtureReady && document.fonts.status === 'loaded'"))
                    page.ele("#continue").click()
                    assert page.ele("#result").text == "完成"
                    with lock:
                        assert requests["/asset.js"] == 1
                        assert requests["/fixture-font.woff2"] == (0 if mode == "saver" else 1)
                        initial_bytes = sum(byte_counts.values())
                    # Same document URL + same JS exercises in-session HTTP cache.
                    page.get(base + "/initial", retry=0, timeout=10)
                    wait_for(lambda: page.run_js("return window.fixtureReady && document.fonts.status === 'loaded'"))
                    with lock: assert requests["/asset.js"] == 1
                    if mode == "saver":
                        assert disable_registration_traffic_filter(page)
                        page.get(base + "/temporary", retry=0, timeout=10)
                        wait_for(lambda: page.run_js("return document.fonts.status === 'loaded'"))
                        with lock: assert requests["/fixture-font.woff2"] == 1
                        assert restore_registration_traffic_filter(page)
                        page.get(base + "/restored", retry=0, timeout=10)
                        wait_for(lambda: page.run_js("return document.fonts.status === 'loaded'"))
                        with lock: assert requests["/fixture-font.woff2"] == 1
                    wait_for(lambda: metrics.snapshot()["totals"]["completed"] >= 3)
                    report = metrics.close()
                    assert report["available"] and report["callback_errors"] == 0
                    assert any(row["resource_type"] == "Script" for row in report["top_resources"])
                    if mode == "saver":
                        assert any(row["resource_type"] == "Font" and row["failed"] for row in report["top_resources"])
                    reports.append({"mode": mode, "initial_fixture_response_body_bytes": initial_bytes,
                                    "script_server_requests": requests["/asset.js"], "metrics": report})
                finally:
                    metrics.close()
                    page.quit()
        finally:
            server.shutdown()
            worker.join(timeout=3)
    assert reports[1]["initial_fixture_response_body_bytes"] < reports[0]["initial_fixture_response_body_bytes"] - len(font) + 1024
    print(json.dumps({"fixture_only_not_account_benchmark": True,
                      "standard_initial_bytes": reports[0]["initial_fixture_response_body_bytes"],
                      "saver_initial_bytes": reports[1]["initial_fixture_response_body_bytes"],
                      "cache_and_form_ok": True}, ensure_ascii=False))
