"""Small, side-effect-free helpers for proxy-pool input validation.

The registration runner accepts pool rows from both the UI and the CLI.  A
row may carry its country in a separate ``REGION|`` prefix or in the proxy
username (for example ``...-region-ID-...``).  Keeping this parsing in one
module prevents the UI from labelling a row as ``POOL`` while the browser
already receives an Indonesian exit.

This module deliberately does *not* probe a proxy or alter browser
fingerprints.  It only normalizes/validates input before a job is started.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit


_REGION_IN_PROXY = re.compile(
    r"(?:^|[-_:/])(?:region|country|cc)[-_]([a-z]{2})(?=[-_:@/&?]|$)",
    re.IGNORECASE,
)
_ISO_REGION = re.compile(r"^[A-Z]{2}$")
_SUPPORTED_SCHEMES = {"http", "https", "socks4", "socks5", "socks5h"}


def infer_proxy_region(label: str = "", proxy_url: str = "") -> str:
    """Return a stable two-letter region when one is present.

    An explicit ``REGION|`` label wins.  Otherwise the common ``region-XX`` /
    ``country-XX`` / ``cc-XX`` username forms are used.  Unknown labels are
    retained (normally ``POOL``) so callers can still show that the row was
    not geo-annotated instead of inventing a country.
    """
    explicit = str(label or "").strip().upper()
    if _ISO_REGION.fullmatch(explicit):
        return explicit
    match = _REGION_IN_PROXY.search(str(proxy_url or "").strip())
    if match:
        return match.group(1).upper()
    return explicit or "POOL"


def validate_proxy_url(proxy_url: str) -> None:
    """Validate a normalized proxy URL without exposing credentials.

    Raises ``ValueError`` with a row-safe message.  Callers should include the
    row number, not the original URL, in user-facing diagnostics.
    """
    text = str(proxy_url or "").strip()
    parsed = urlsplit(text)
    if parsed.scheme.lower() not in _SUPPORTED_SCHEMES:
        raise ValueError("代理协议不受支持")
    if not parsed.hostname or parsed.port is None:
        raise ValueError("代理地址缺少 host 或 port")
    if not 1 <= int(parsed.port) <= 65535:
        raise ValueError("代理端口超出范围")


def normalize_pool_rows(raw_rows: list[str], normalizer) -> list[tuple[str, str]]:
    """Normalize and validate ``REGION|proxy`` rows.

    ``normalizer`` is injected to preserve the caller's URL escaping rules
    (the web app and CLI historically used equivalent helpers).  Empty and
    comment rows are ignored.  Errors identify only the row number.
    """
    out: list[tuple[str, str]] = []
    for row_no, raw in enumerate(raw_rows, 1):
        line = str(raw or "").strip()
        if not line or line.startswith("#"):
            continue
        label, value = (line.split("|", 1) if "|" in line else ("POOL", line))
        try:
            normalized = normalizer(value.strip())
            validate_proxy_url(normalized)
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ValueError(f"代理池第 {row_no} 行无效：{exc}") from exc
        out.append((infer_proxy_region(label, normalized), normalized))
    return out


def assign_proxy_round_robin(proxies: list[tuple[str, str]], count: int) -> list[tuple[str, str] | None]:
    """Assign one proxy row to each of ``count`` slots by round-robin.

    The whole import is one flat list, so a caller that wants to spread
    ``count`` accounts over fewer gateways simply cycles back to the first
    row once the list is exhausted (``count > len(proxies)``); with an equal
    or larger pool every slot gets its own distinct row in order.

    ``None`` means "connect directly" and is only produced for an empty pool,
    so a caller can keep the historical direct-connection default instead of
    inventing a gateway.  This helper is deliberately pure: it neither probes
    a gateway nor mutates the rows it was given.
    """
    slots = max(0, int(count))
    if not proxies:
        return [None] * slots
    return [proxies[index % len(proxies)] for index in range(slots)]


__all__ = ["assign_proxy_round_robin", "infer_proxy_region", "normalize_pool_rows", "validate_proxy_url"]
