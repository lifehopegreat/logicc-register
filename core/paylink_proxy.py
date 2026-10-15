"""Local proxy transport helpers shared by the console and browser.

代理链路（跟原版 README 一致）：
    脚本/浏览器/IMAP -> 本地代理 -> 动态代理 -> 目标站点

- 本地代理：例如 Clash on ``http://127.0.0.1:7890``，所有请求先经它
- 动态代理：每行一个 sticky/rotating 代理，``username:password@host:port`` 形态
- 链式 CONNECT：本地 → 动态 → 目标，全程 HTTP CONNECT
- 三种模式：
    * 都填 → 链式 (local→dynamic→target)
    * 只填 local → local→target
    * 只填 dynamic → dynamic→target
    * 都空 → 直连

``ProxyChainServer`` 起一个本地 HTTP CONNECT proxy server，把请求转发到上游代理。
``randomize_proxy_sid()`` 把 sticky URL 里的 ``sid=xxx`` 换成新随机值（每次开新 sid）。
"""
from __future__ import annotations

import base64
import random
import re
import select
import socket
import ssl
import threading
import time
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlparse, urlsplit, urlunsplit


# ─────────────────────────────────────────────────────────────────────────
# URL helpers
# ─────────────────────────────────────────────────────────────────────────
def normalize_proxy_url(value: str, default_scheme: str = "http") -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    # 711 and several pool exporters use host:port:user:password. Convert it
    # before adding the scheme so urlsplit sees the credentials correctly.
    if "://" not in text:
        parts = text.split(":")
        if len(parts) >= 4 and parts[1].isdigit():
            host, port, username = parts[:3]
            password = ":".join(parts[3:])
            return (
                f"{default_scheme}://{quote(username, safe='')}:{quote(password, safe='')}"
                f"@{host}:{port}"
            )
    if "://" not in text:
        text = f"{default_scheme}://{text}"
    return text


def random_proxy_sid(length: int = 10) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(alphabet) for _ in range(length))


def randomize_proxy_sid(proxy_url: str) -> str:
    """如果 URL 里带 ``sid=xxx`` 或 ``sid-xxx`` 形态的 sticky session id，换成新随机值。

    支持两种常见形态：
    1. 查询参数：``...?sid=abc123``
    2. 用户名 token：``user-sid-abc123:password@host``
    """
    text = str(proxy_url or "").strip()
    if not text:
        return ""
    sid = random_proxy_sid()
    parsed = urlsplit(text)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if any(key.lower() == "sid" for key, _ in query_pairs):
        query = urlencode([(key, sid if key.lower() == "sid" else value) for key, value in query_pairs])
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))

    netloc = parsed.netloc
    if "@" in netloc:
        userinfo, host = netloc.rsplit("@", 1)
        new_userinfo = re.sub(r"(?i)(sid[-_=])([^-:@;&/?]+)",
                              lambda m: f"{m.group(1)}{sid}", userinfo, count=1)
        if new_userinfo != userinfo:
            return urlunsplit((parsed.scheme, f"{new_userinfo}@{host}",
                               parsed.path, parsed.query, parsed.fragment))

    new_text = re.sub(r"(?i)(sid[-_=])([^-:@;&/?]+)",
                      lambda m: f"{m.group(1)}{sid}", text, count=1)
    return new_text


def mask_proxy_url(proxy_url: str) -> str:
    text = str(proxy_url or "").strip()
    if not text:
        return "直连"
    try:
        parsed = urlsplit(text)
        if "@" not in parsed.netloc:
            return text
        userinfo, host = parsed.netloc.rsplit("@", 1)
        if ":" in userinfo:
            username, _ = userinfo.split(":", 1)
            userinfo = f"{username}:***"
        else:
            userinfo = "***"
        return urlunsplit((parsed.scheme, f"{userinfo}@{host}",
                           parsed.path, parsed.query, parsed.fragment))
    except Exception:
        return "***"


# ─────────────────────────────────────────────────────────────────────────
# Pool rotator
# ─────────────────────────────────────────────────────────────────────────
class DynamicProxyPool:
    """轮询动态代理池，取下一条 + 可选 sticky sid 随机化。线程安全。"""

    def __init__(self, lines: list[str], randomize_sid: bool = True):
        self._proxies = [normalize_proxy_url(line) for line in lines if str(line or "").strip()]
        self._idx = 0
        self._lock = threading.Lock()
        self._randomize = bool(randomize_sid)

    def __bool__(self) -> bool:
        return bool(self._proxies)

    def __len__(self) -> int:
        return len(self._proxies)

    def next(self) -> str:
        if not self._proxies:
            return ""
        with self._lock:
            url = self._proxies[self._idx % len(self._proxies)]
            self._idx += 1
        if self._randomize:
            url = randomize_proxy_sid(url)
        return url

    @classmethod
    def from_text(cls, text: str, randomize_sid: bool = True) -> "DynamicProxyPool":
        lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
        return cls(lines, randomize_sid=randomize_sid)


# ─────────────────────────────────────────────────────────────────────────
# ProxyChainServer — 本地 HTTP CONNECT 代理，串接 local + dynamic
# ─────────────────────────────────────────────────────────────────────────
class ProxyChainServer:
    """起一个本地代理 server，所有请求按 local→dynamic→target 链式 CONNECT 转发。

    用法（context manager）：

        with ProxyChainServer(local_proxy, dynamic_proxy, log) as chain:
            proxy_url = chain.url   # = "http://127.0.0.1:NNN"，传给 requests/curl_cffi
            ...

    退出 ``with`` 时自动关闭。两个代理都为空时不起 server，``url=""``。
    ``max_bytes=0`` 不限流；正整数限制本实例所有连接的上传发送量 + 上游读取量。
    ``download_bytes`` 包含已读取但未成功转发的字节，转发量另见
    ``forwarded_download_bytes``。包含浏览器至目标站点的 TLS 密文；不包含 CONNECT /
    代理认证控制头、TCP/IP 开销、HTTPS 上游代理外层 TLS 及未读取的系统缓冲，
    因此本地预算不是代理供应商账单的硬上限。
    """

    def __init__(self, local_proxy: str, dynamic_proxy: str, log=None, max_bytes: int = 0):
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
            raise ValueError("max_bytes must be a non-negative integer")
        self.local_proxy = normalize_proxy_url(local_proxy)
        self.dynamic_proxy = normalize_proxy_url(dynamic_proxy)
        self.log = log or (lambda _: None)
        self.lock = threading.Lock()
        # Reserve capacity under the state lock; never hold a lock during I/O.
        self._transfer_condition = threading.Condition(self.lock)
        self._reserved_bytes = 0
        self.active_sockets: set[socket.socket] = set()
        self.server: socket.socket | None = None
        self.thread: threading.Thread | None = None
        self._workers: set[threading.Thread] = set()
        self.stop_event = threading.Event()
        self.url = ""
        self.upload_bytes = 0
        self.download_bytes = 0
        self.forwarded_download_bytes = 0
        self.connection_count = 0
        self.max_bytes = max_bytes
        self.budget_exceeded = False

    @property
    def stats(self) -> dict[str, int | bool]:
        with self.lock:
            return {
                "upload_bytes": self.upload_bytes,
                "download_bytes": self.download_bytes,
                "forwarded_download_bytes": self.forwarded_download_bytes,
                "total_bytes": self.upload_bytes + self.download_bytes,
                "connections": self.connection_count,
                "max_bytes": self.max_bytes,
                "budget_exceeded": self.budget_exceeded,
            }

    def _reserve_transfer(self, size: int) -> int:
        with self._transfer_condition:
            while not self.stop_event.is_set() and not self.budget_exceeded:
                if not self.max_bytes:
                    return size
                available = self.max_bytes - self.upload_bytes - self.download_bytes - self._reserved_bytes
                if available > 0:
                    amount = min(size, available)
                    self._reserved_bytes += amount
                    return amount
                self._transfer_condition.wait(timeout=0.1)
            return 0

    def _release_transfer(self, reserved: int) -> None:
        with self._transfer_condition:
            if self.max_bytes:
                self._reserved_bytes -= reserved
            self._transfer_condition.notify_all()

    def _record_transfer(
        self, upload: bool, size: int, *, reserved: int = 0, close_on_budget: bool = True
    ) -> None:
        with self._transfer_condition:
            if self.max_bytes:
                self._reserved_bytes -= reserved
            if upload:
                self.upload_bytes += size
            else:
                self.download_bytes += size
            if self.max_bytes and self.upload_bytes + self.download_bytes >= self.max_bytes:
                self.budget_exceeded = True
            exhausted = self.budget_exceeded
            self._transfer_condition.notify_all()
        if exhausted and close_on_budget:
            self._close_active_sockets()

    def _send_data(self, dst: socket.socket, data: bytes, upload: bool) -> bool:
        """Count bytes actually sent upstream, including partial writes.

        Tunnel TLS ciphertext is included; CONNECT/auth headers, TCP/IP, and outer
        HTTPS-proxy TLS framing are not. Provider billing can therefore be larger.
        """
        offset = 0
        while offset < len(data):
            allowance = self._reserve_transfer(len(data) - offset)
            if not allowance:
                return False
            try:
                sent = dst.send(memoryview(data)[offset:offset + allowance])
            except Exception:
                self._release_transfer(allowance)
                raise
            self._record_transfer(upload, sent, reserved=allowance)
            if not sent:
                return False
            offset += sent
        return not self.budget_exceeded

    def _receive_download(self, src: socket.socket, dst: socket.socket) -> bool:
        # Count every byte returned by upstream.recv(), even if the browser closes
        # before consuming it. Limit each read, not only the forwarded slice.
        allowance = self._reserve_transfer(65536)
        if not allowance:
            return False
        try:
            data = src.recv(allowance)
        except Exception:
            self._release_transfer(allowance)
            raise
        self._record_transfer(False, len(data), reserved=allowance, close_on_budget=False)
        if not data:
            return False
        try:
            if self.budget_exceeded:
                # Do not let a browser that stopped reading delay the cutoff.
                dst.settimeout(1)
            offset = 0
            while offset < len(data) and not self.stop_event.is_set():
                sent = dst.send(memoryview(data)[offset:])
                if not sent:
                    return False
                with self.lock:
                    self.forwarded_download_bytes += sent
                offset += sent
            return not self.stop_event.is_set() and not self.budget_exceeded
        finally:
            if self.budget_exceeded:
                self._close_active_sockets()

    def __enter__(self):
        if not self.local_proxy and not self.dynamic_proxy:
            return self
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(64)
        self.server.settimeout(0.2)
        port = self.server.getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, _exc_type, _exc, _tb):
        self.close()

    def close(self) -> None:
        self.stop_event.set()
        with self._transfer_condition:
            server, self.server = self.server, None
            self._transfer_condition.notify_all()
        if server:
            self._close_socket(server)
        self._close_active_sockets()
        # Never join while holding either lock, and never join the caller itself.
        # Bound the wait in case the OS resolver is still blocked in getaddrinfo.
        deadline = time.monotonic() + 5
        current = threading.current_thread()
        if self.thread and self.thread is not current:
            self.thread.join(timeout=max(0, deadline - time.monotonic()))
        with self.lock:
            workers = list(self._workers)
        self._close_active_sockets()
        for worker in workers:
            if worker is not current:
                worker.join(timeout=max(0, deadline - time.monotonic()))

    def set_dynamic_proxy(self, dynamic_proxy: str) -> None:
        with self.lock:
            self.dynamic_proxy = normalize_proxy_url(dynamic_proxy)
        self._close_active_sockets()

    def _close_active_sockets(self) -> None:
        with self.lock:
            sockets = list(self.active_sockets)
        for sock in sockets:
            self._close_socket(sock)

    @staticmethod
    def _close_socket(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def _track_socket(self, sock: socket.socket) -> None:
        with self.lock:
            closed = self.stop_event.is_set() or self.budget_exceeded
            if not closed:
                self.active_sockets.add(sock)
        if closed:
            self._close_socket(sock)
            raise ConnectionAbortedError("Proxy bridge is closed")

    def _untrack_socket(self, sock: socket.socket) -> None:
        with self.lock:
            self.active_sockets.discard(sock)

    def _serve(self) -> None:
        server = self.server
        if server is None:
            return
        while not self.stop_event.is_set():
            try:
                client, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                if self.stop_event.is_set():
                    self._close_socket(client)
                    return
                self.active_sockets.add(client)
                worker = threading.Thread(target=self._handle_client, args=(client,), daemon=True)
                self._workers.add(worker)
                worker.start()

    def _handle_client(self, client: socket.socket) -> None:
        upstream = None
        response_started = False
        try:
            client.settimeout(30)
            with self.lock:
                exhausted = self.budget_exceeded
            if exhausted:
                client.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                return
            head = self._read_http_head(client)
            if not head:
                return
            with self.lock:
                self.connection_count += 1
            first_line = head.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
            parts = first_line.split()
            if len(parts) < 3:
                return
            method, target, version = parts[0].upper(), parts[1], parts[2]
            if method == "CONNECT":
                upstream = self._open_chain_to_target(target)
                self._track_socket(upstream)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                response_started = True
                self._relay(client, upstream)
                return
            rewritten = self._rewrite_plain_request(head, method, target, version)
            upstream = self._open_chain_to_target(self._target_from_plain_request(method, target, head))
            self._track_socket(upstream)
            if self._send_data(upstream, rewritten, upload=True):
                response_started = True
                self._relay(client, upstream)
        except Exception:
            if not response_started and not self.stop_event.is_set() and not self.budget_exceeded:
                try:
                    client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass
        finally:
            self._untrack_socket(client)
            if upstream:
                self._untrack_socket(upstream)
                self._close_socket(upstream)
            self._close_socket(client)
            with self.lock:
                self._workers.discard(threading.current_thread())

    def _read_http_head(self, client: socket.socket, *, header_only: bool = False) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            # Upstream CONNECT replies must not consume unmetered tunnel data
            # coalesced after the headers. recv(1) also works for SSL sockets.
            chunk = client.recv(1 if header_only else 4096)
            if not chunk:
                break
            data += chunk
        return data

    def _target_from_plain_request(self, method: str, target: str, head: bytes) -> str:
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            return f"{parsed.hostname}:{port}"
        host = ""
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"host:"):
                host = line.split(b":", 1)[1].strip().decode("latin1")
                break
        return host

    def _rewrite_plain_request(self, head: bytes, method: str, target: str, version: str) -> bytes:
        if not (target.startswith("http://") or target.startswith("https://")):
            return head
        parsed = urlparse(target)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        lines = head.split(b"\r\n")
        lines[0] = f"{method} {path} {version}".encode("latin1")
        return b"\r\n".join(lines)

    def _open_chain_to_target(self, target: str) -> socket.socket:
        with self.lock:
            local_proxy = self.local_proxy
            dynamic_proxy = self.dynamic_proxy
        sock = None
        try:
            if local_proxy:
                sock = self._connect_proxy(local_proxy)
                self._send_connect(sock, self._proxy_connect_target(dynamic_proxy) if dynamic_proxy else target)
                if dynamic_proxy:
                    self._send_connect(sock, target, proxy_url=dynamic_proxy)
                return sock
            if dynamic_proxy:
                sock = self._connect_proxy(dynamic_proxy)
                self._send_connect(sock, target, proxy_url=dynamic_proxy)
                return sock
            host, port = self._split_host_port(target, 80)
            return self._connect_tcp(host, port)
        except Exception:
            if sock is not None:
                self._close_socket(sock)
                self._untrack_socket(sock)
            raise

    def _connect_tcp(self, host: str, port: int) -> socket.socket:
        last_error = None
        for family, socktype, proto, _, address in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
            sock = socket.socket(family, socktype, proto)
            try:
                sock.settimeout(30)
                self._track_socket(sock)
                sock.connect(address)
                return sock
            except OSError as error:
                last_error = error
                self._close_socket(sock)
                self._untrack_socket(sock)
                if self.stop_event.is_set() or self.budget_exceeded:
                    raise
        raise OSError("Unable to connect to upstream") from last_error

    def _connect_proxy(self, proxy_url: str) -> socket.socket:
        parsed = urlparse(proxy_url)
        if parsed.scheme not in ("http", "https"):
            raise RuntimeError("链式代理当前只支持 http/https")
        host = parsed.hostname
        if not host:
            raise RuntimeError("代理地址缺少 host")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        raw = self._connect_tcp(host, port)
        if parsed.scheme == "https":
            wrapped = None
            try:
                wrapped = ssl.create_default_context().wrap_socket(
                    raw, server_hostname=host, do_handshake_on_connect=False
                )
                self._track_socket(wrapped)
                self._untrack_socket(raw)
                wrapped.do_handshake()
                return wrapped
            except Exception:
                for sock in (raw, wrapped):
                    if sock is not None:
                        self._close_socket(sock)
                        self._untrack_socket(sock)
                raise
        return raw

    def _proxy_connect_target(self, proxy_url: str) -> str:
        parsed = urlparse(proxy_url)
        if not parsed.hostname:
            raise RuntimeError("动态代理地址缺少 host")
        return f"{parsed.hostname}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"

    def _send_connect(self, sock: socket.socket, target: str, proxy_url: str = "") -> None:
        headers = [f"CONNECT {target} HTTP/1.1", f"Host: {target}", "Proxy-Connection: keep-alive"]
        auth = self._proxy_auth(proxy_url)
        if auth:
            headers.append(f"Proxy-Authorization: Basic {auth}")
        request = ("\r\n".join(headers) + "\r\n\r\n").encode("latin1")
        sock.sendall(request)
        response = self._read_http_head(sock, header_only=True)
        status = response.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
        if " 200 " not in f" {status} ":
            code = status.split()[1:2]
            safe_code = code[0] if code and code[0].isdigit() else "invalid response"
            raise RuntimeError(f"代理 CONNECT 失败: {safe_code}")

    def _proxy_auth(self, proxy_url: str) -> str:
        parsed = urlparse(proxy_url)
        if not parsed.username:
            return ""
        username = unquote(parsed.username)
        password = unquote(parsed.password or "")
        return base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")

    def _split_host_port(self, target: str, default_port: int) -> tuple[str, int]:
        if target.startswith("["):
            host, rest = target[1:].split("]", 1)
            port = int(rest[1:]) if rest.startswith(":") else default_port
            return host, port
        if ":" in target:
            host, port = target.rsplit(":", 1)
            return host, int(port)
        return target, default_port

    def _relay(self, left: socket.socket, right: socket.socket) -> None:
        sockets = [left, right]
        for sock in sockets:
            sock.settimeout(5 if self.max_bytes else None)
        try:
            while True:
                readable, _, _ = select.select(sockets, [], [], 60)
                if not readable:
                    return
                for src in readable:
                    dst = right if src is left else left
                    if src is right:
                        if not self._receive_download(src, dst):
                            return
                        continue
                    data = src.recv(65536)
                    if not data:
                        return
                    if not self._send_data(dst, data, upload=src is left):
                        return
        finally:
            try:
                right.close()
            except Exception:
                pass


__all__ = [
    "normalize_proxy_url",
    "randomize_proxy_sid",
    "random_proxy_sid",
    "mask_proxy_url",
    "DynamicProxyPool",
    "ProxyChainServer",
]
