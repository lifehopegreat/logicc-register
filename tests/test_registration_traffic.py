import socket
import socketserver
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

import pytest

from paylink_proxy import ProxyChainServer
import browser_mgr


def _read_head(sock):
    result = b""
    while b"\r\n\r\n" not in result:
        data = sock.recv(4096)
        if not data:
            break
        result += data
    return result


def _connect_tunnel(chain):
    address = urlsplit(chain.url)
    client = socket.create_connection((address.hostname, address.port), timeout=2)
    client.sendall(b"CONNECT loopback.test:443 HTTP/1.1\r\nHost: loopback.test:443\r\n\r\n")
    assert _read_head(client).startswith(b"HTTP/1.1 200")
    return client


def _wait_until(predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert predicate()


@pytest.fixture
def echo_proxy():
    """Loopback-only CONNECT peer; never resolves or contacts the target."""
    class Echo(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            try:
                assert _read_head(self.request).startswith(b"CONNECT ")
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                while data := self.request.recv(65536):
                    self.request.sendall(data)
            except OSError:
                pass

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    with Server(("127.0.0.1", 0), Echo) as server:
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        worker.start()
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}"
        finally:
            server.shutdown()
            worker.join(timeout=2)


def test_proxy_budget_closes_tunnel_at_combined_limit_and_rejects_new_connections(echo_proxy):
    with ProxyChainServer(echo_proxy, "", max_bytes=11) as chain:
        with _connect_tunnel(chain) as client:
            client.sendall(b"hello")
            assert client.recv(5) == b"hello"
            _wait_until(lambda: chain.stats["total_bytes"] == 10)
            client.sendall(b"world")
            assert client.recv(5) == b""
            _wait_until(lambda: chain.stats["budget_exceeded"])
            assert chain.stats == {
                "upload_bytes": 6,
                "download_bytes": 5,
                "forwarded_download_bytes": 5,
                "total_bytes": 11,
                "connections": 1,
                "max_bytes": 11,
                "budget_exceeded": True,
            }
        address = urlsplit(chain.url)
        with socket.create_connection((address.hostname, address.port), timeout=2) as denied:
            assert _read_head(denied).startswith(b"HTTP/1.1 503")
        assert chain.stats["connections"] == 1


def test_proxy_close_ends_idle_tunnels_and_waits_for_cleanup(echo_proxy):
    with ProxyChainServer(echo_proxy, "") as chain:
        with _connect_tunnel(chain) as client:
            client.sendall(b"hello")
            assert client.recv(5) == b"hello"
            chain.close()
            assert client.recv(1) == b""
            assert not chain.active_sockets
            assert not chain.thread.is_alive()
            snapshot = chain.stats
            chain.close()
            assert chain.stats == snapshot


def test_proxy_close_interrupts_inflight_upstream_connect():
    received_connect = threading.Event()
    disconnected = threading.Event()
    upstream_sockets = []

    class Silent(socketserver.BaseRequestHandler):
        def handle(self):
            upstream_sockets.append(self.request)
            self.request.settimeout(10)
            try:
                assert _read_head(self.request).startswith(b"CONNECT ")
                received_connect.set()
                if not self.request.recv(1):
                    disconnected.set()
            except OSError:
                disconnected.set()

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    with Server(("127.0.0.1", 0), Silent) as server:
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        worker.start()
        chain = ProxyChainServer(f"http://127.0.0.1:{server.server_address[1]}", "")
        try:
            chain.__enter__()
            address = urlsplit(chain.url)
            with socket.create_connection((address.hostname, address.port), timeout=2) as client:
                client.sendall(b"CONNECT loopback.test:443 HTTP/1.1\r\n\r\n")
                assert received_connect.wait(2)
                started = time.monotonic()
                chain.close()
                assert time.monotonic() - started < 2
                assert disconnected.wait(1)
                assert not chain.active_sockets
        finally:
            for upstream in upstream_sockets:
                try:
                    upstream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                upstream.close()
            chain.close()
            server.shutdown()
            worker.join(timeout=2)


def test_proxy_budget_is_shared_across_concurrent_tunnels(echo_proxy):
    with ProxyChainServer(echo_proxy, "", max_bytes=257) as chain:
        clients = [_connect_tunnel(chain) for _ in range(6)]
        start = threading.Barrier(len(clients))

        def exchange(client):
            with client:
                start.wait(timeout=2)
                try:
                    client.sendall(b"x" * 1024)
                    while client.recv(1024):
                        pass
                except (ConnectionError, OSError):
                    pass

        with ThreadPoolExecutor(max_workers=len(clients)) as executor:
            list(executor.map(exchange, clients))
        chain.close()
        stats = chain.stats
        assert stats["total_bytes"] == 257
        assert stats["upload_bytes"] + stats["download_bytes"] == 257
        assert stats["budget_exceeded"] is True
        assert stats["connections"] == 6
        assert not chain.active_sockets


def test_proxy_budget_caps_download_and_counts_plain_request_first_bytes(echo_proxy):
    request = b"GET http://loopback.test/private?token=fake HTTP/1.1\r\nHost: loopback.test\r\n\r\n"
    forwarded = b"GET /private?token=fake HTTP/1.1\r\nHost: loopback.test\r\n\r\n"
    with ProxyChainServer(echo_proxy, "", max_bytes=len(forwarded) + 7) as chain:
        address = urlsplit(chain.url)
        with socket.create_connection((address.hostname, address.port), timeout=2) as client:
            client.sendall(request)
            received = b""
            while data := client.recv(1024):
                received += data
            assert received == forwarded[:7]
        chain.close()
        assert chain.stats["upload_bytes"] == len(forwarded)
        assert chain.stats["download_bytes"] == 7
        assert chain.stats["budget_exceeded"] is True
        assert "fake" not in str(chain.stats)


def test_proxy_default_budget_is_unlimited_and_no_proxy_remains_direct(echo_proxy):
    with ProxyChainServer("", "") as direct:
        assert direct.url == ""
        assert direct.stats["max_bytes"] == 0
    with ProxyChainServer(echo_proxy, "") as chain:
        with _connect_tunnel(chain) as client:
            for _ in range(2):
                client.sendall(b"hello")
                assert client.recv(5) == b"hello"
        chain.close()
        assert chain.stats["upload_bytes"] == 10
        assert chain.stats["download_bytes"] == 10
        assert chain.stats["max_bytes"] == 0
        assert chain.stats["budget_exceeded"] is False


@pytest.mark.parametrize("invalid", [-1, True, 1.5, "10"])
def test_proxy_rejects_invalid_budget(invalid):
    with pytest.raises(ValueError, match="max_bytes"):
        ProxyChainServer("", "", max_bytes=invalid)


def test_upstream_connect_head_does_not_consume_unmetered_tunnel_tail():
    chain = ProxyChainServer("", "", max_bytes=2)
    left, right = socket.socketpair()
    with left, right:
        left.settimeout(0.2)
        right.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\nDATA")
        chain._send_connect(left, "loopback.test:443")
        assert left.recv(4) == b"DATA"
        assert chain.stats["total_bytes"] == 0


@pytest.mark.parametrize("max_bytes, timeout", [(0, None), (100, 5)])
def test_budgeted_relay_io_wait_is_bounded_without_changing_default(max_bytes, timeout):
    chain = ProxyChainServer("", "", max_bytes=max_bytes)
    left, right = socket.socketpair()
    with left, right:
        right.shutdown(socket.SHUT_WR)
        chain._relay(left, right)
        assert left.gettimeout() == timeout


def test_budgeted_blocked_receive_does_not_hold_shared_state_or_transfer_lock():
    receiving = threading.Event()
    release = threading.Event()
    sent = threading.Event()

    class DelayedSource:
        def recv(self, size):
            receiving.set()
            assert release.wait(2)
            return b"x"

    class Destination:
        def send(self, data):
            return len(data)

    chain = ProxyChainServer("", "", max_bytes=100000)
    reader = threading.Thread(target=chain._receive_download, args=(DelayedSource(), Destination()))

    def upload():
        chain._send_data(Destination(), b"y", upload=True)
        sent.set()

    writer = threading.Thread(target=upload)
    reader.start()
    try:
        assert receiving.wait(1)
        writer.start()
        assert sent.wait(0.3)
    finally:
        release.set()
        reader.join(timeout=2)
        if writer.ident is not None:
            writer.join(timeout=2)
        chain.close()
    assert chain.stats["total_bytes"] == 2


@pytest.mark.parametrize("upload", [True, False])
def test_proxy_partial_write_failure_preserves_actual_byte_counts(upload):
    class FailingDestination:
        """Deterministic short-write seam; the receive side still uses real sockets."""
        def __init__(self):
            self.calls = 0

        def send(self, data):
            self.calls += 1
            if self.calls == 1:
                return 2
            raise ConnectionResetError("loopback fixture reset")

    chain = ProxyChainServer("", "")
    left, right = socket.socketpair()
    with left, right:
        left.sendall(b"abcdef")
        with pytest.raises(ConnectionResetError):
            if upload:
                chain._send_data(FailingDestination(), b"abcdef", upload=True)
            else:
                chain._receive_download(right, FailingDestination())
    chain.close()
    if upload:
        assert chain.stats["upload_bytes"] == 2
        assert chain.stats["total_bytes"] == 2
    else:
        assert chain.stats["download_bytes"] == 6
        assert chain.stats["forwarded_download_bytes"] == 2
        assert chain.stats["total_bytes"] == 6


def test_proxy_chain_counts_tunnel_bytes():
    chain = ProxyChainServer("", "")
    chain._record_transfer(True, 10)
    chain._record_transfer(False, 30)
    assert chain.stats == {
        "upload_bytes": 10,
        "download_bytes": 30,
        "forwarded_download_bytes": 0,
        "total_bytes": 40,
        "connections": 0,
        "max_bytes": 0,
        "budget_exceeded": False,
    }


def test_registration_saver_uses_cdp_and_standard_is_noop():
    class Page:
        def __init__(self): self.calls = []
        def run_cdp(self, command, **kwargs): self.calls.append((command, kwargs))

    standard = Page()
    assert browser_mgr.configure_registration_traffic(standard, "standard") == 0
    assert standard.calls == []

    saver = Page()
    assert browser_mgr.configure_registration_traffic(saver, "saver") > 0
    assert any(command == "Network.setBlockedURLs" for command, _ in saver.calls)

    headless = Page()
    blocked = browser_mgr.configure_registration_traffic(headless, "headless")
    urls = next(kwargs["urls"] for command, kwargs in headless.calls if command == "Network.setBlockedURLs")
    assert blocked > browser_mgr.configure_registration_traffic(saver, "saver")
    assert any(".woff" in pattern for pattern in urls)


def test_registration_saver_keeps_block_list_when_cache_command_is_unavailable():
    class Page:
        def __init__(self): self.calls = []
        def run_cdp(self, command, **kwargs):
            self.calls.append((command, kwargs))
            if command == "Network.setCacheDisabled":
                raise RuntimeError("unsupported in old Chromium")

    page = Page()
    blocked = browser_mgr.configure_registration_traffic(page, "saver")
    assert blocked > 0
    assert any(command == "Network.setBlockedURLs" for command, _ in page.calls)


def test_registration_saver_attempts_block_list_when_network_enable_is_unavailable():
    class Page:
        def __init__(self): self.calls = []
        def run_cdp(self, command, **kwargs):
            self.calls.append((command, kwargs))
            if command == "Network.enable":
                raise RuntimeError("network domain already enabled by host")

    page = Page()
    blocked = browser_mgr.configure_registration_traffic(page, "headless")
    assert blocked == len(browser_mgr.REGISTRATION_SAVER_BLOCKED_URLS) + len(
        browser_mgr.REGISTRATION_HEADLESS_EXTRA_BLOCKED_URLS
    )
    assert any(command == "Network.setBlockedURLs" for command, _ in page.calls)


def test_local_chromium_headless_switch(monkeypatch):
    class Options:
        def __init__(self): self.headless_value, self.arguments = None, []
        def headless(self, value): self.headless_value = value
        def set_browser_path(self, _value): pass
        def auto_port(self): pass
        def set_proxy(self, _value): pass
        def set_argument(self, value): self.arguments.append(value)

    class Page:
        def __init__(self, options): self.options = options
        def run_cdp(self, *_args, **_kwargs): pass

    monkeypatch.setattr(browser_mgr, "ChromiumOptions", Options)
    monkeypatch.setattr(browser_mgr, "ChromiumPage", Page)
    monkeypatch.setattr(browser_mgr.config, "CHROME_PATH", "")
    monkeypatch.setattr(browser_mgr, "_resolve_default_chrome_path", lambda: "")
    assert browser_mgr.open_local_chromium(headless=True).options.headless_value is True
