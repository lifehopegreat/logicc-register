"""Pin a public proxy gateway once, then probe HTTPS without submitting identity."""
import ipaddress
import socket
import time
from urllib.parse import urlsplit, urlunsplit

import httpx


def pin_proxy(proxy):
    parsed = urlsplit(proxy)
    try:
        literal = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        literal = None
    if literal:
        if not literal.is_global:
            raise ValueError("注册求解代理需要公网地址，不能使用本机或私网代理")
        return proxy
    try:
        addresses = [row[4][0] for row in socket.getaddrinfo(parsed.hostname, parsed.port, type=socket.SOCK_STREAM)]
        public = [ip for ip in addresses if ipaddress.ip_address(ip).is_global]
        if not public:
            # Clash Fake-IP answers cannot be reached by the remote solver.
            with httpx.Client(trust_env=False, timeout=15, follow_redirects=False) as client:
                response = client.get("https://dns.google/resolve", params={"name": parsed.hostname, "type": "A", "edns_client_subnet": "0.0.0.0/0"})
                response.raise_for_status()
                value = response.json()
            if not isinstance(value, dict) or value.get("Status") != 0:
                raise ValueError
            public = [row["data"] for row in value.get("Answer", []) if isinstance(row, dict) and row.get("type") == 1
                      and ipaddress.ip_address(row["data"]).is_global]
        if not public:
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError, httpx.HTTPError):
        raise ValueError("代理网关无法解析为公网地址") from None
    host = public[0]
    host = "[" + host + "]" if ":" in host else host
    auth = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
    return urlunsplit((parsed.scheme, auth + host + ":" + str(parsed.port), "", "", ""))


def probe_proxy(proxy):
    start = time.monotonic()
    try:
        pinned = pin_proxy(proxy)
        with httpx.Client(proxy=pinned, timeout=20, trust_env=False, follow_redirects=False) as client:
            ip_response = client.get("https://api.ipify.org")
            ip_response.raise_for_status()
            ip = str(ipaddress.ip_address(ip_response.text.strip()))
            page = client.get("https://app.logicc.com/register")
            clerk = client.get("https://clerk.logicc.com/v1/environment",
                               params={"__clerk_api_version": "2026-05-12", "_clerk_js_version": "6.39.0"})
            value = clerk.json()
            environment = value.get("response", value) if isinstance(value, dict) else None
            valid = isinstance(environment, dict) and isinstance(environment.get("user_settings"), dict)
        return {"ok": page.status_code == 200 and clerk.status_code == 200 and valid,
                "ip": ip, "register_status": page.status_code, "clerk_status": clerk.status_code,
                "latency_ms": round((time.monotonic()-start)*1000)}
    except (ValueError, httpx.HTTPError, OSError) as exc:
        return {"ok": False, "error": "proxy_probe_" + type(exc).__name__,
                "latency_ms": round((time.monotonic()-start)*1000)}
