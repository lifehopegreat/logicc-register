"""Provider-backed receive-only mailbox integration.

The account vault keeps the provider-issued ``inbox_url`` as its historical
relay credential (``email----inbox_url``).  This module recognizes those URLs
from a local schema-v3 provider configuration and reads messages through the
stable control API with the *mailbox token* embedded in the URL.  The admin
token is loaded only for mailbox provisioning or lifecycle changes.

No provider, domain, control host, or secret is hard-coded here.  Replacing a
domain or moving the mailbox service only requires changing the local config.
"""
from __future__ import annotations

import json
import os
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "data" / "domain_mailbox_runtime.json"
LEGACY_CONFIG_PATH = PROJECT_ROOT / "data" / "cloudflare-mailbox.json"
CONFIG_ENV = "DOMAIN_MAILBOX_CONFIG"
_SSL_CONTEXT = ssl.create_default_context()
_CONFIG_LOCK = threading.Lock()
_CONFIG_CACHE: tuple[str, int, "DomainMailboxConfig"] | None = None


def _selected_config_path(path: str | os.PathLike[str] | None = None) -> Path:
    """Resolve UI-managed config first while retaining the old file override."""
    if path:
        return Path(path).expanduser()
    configured = os.environ.get(CONFIG_ENV, "").strip()
    if configured:
        return Path(configured).expanduser()
    if DEFAULT_CONFIG_PATH.is_file() or not LEGACY_CONFIG_PATH.is_file():
        return DEFAULT_CONFIG_PATH
    return LEGACY_CONFIG_PATH


class DomainMailboxError(RuntimeError):
    """Base error that never includes mailbox/admin bearer tokens."""


class DomainMailboxConfigError(DomainMailboxError):
    pass


class DomainMailboxApiError(DomainMailboxError):
    def __init__(self, status: int, code: str, *, operation: str = "request") -> None:
        self.status = int(status)
        self.code = str(code or "api_error")[:120]
        self.operation = operation
        super().__init__(f"domain mailbox {operation} failed: HTTP {self.status} {self.code}")


def _clean_origin(value: object) -> str:
    """Validate the HTTPS control endpoint, including an optional base path.

    The mailbox domain and the control-plane endpoint are intentionally
    independent.  A base path lets an installation expose the API behind an
    already reachable HTTPS gateway (for example ``/domain-mailbox``) without
    changing issued inbox URLs or hard-coding a provider domain in the app.
    """
    raw = str(value or "").strip().rstrip("/")
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise DomainMailboxConfigError("api_origin must be an https endpoint without credentials")
    if parsed.query or parsed.fragment:
        raise DomainMailboxConfigError("api_origin must not contain a query or fragment")
    segments = [urllib.parse.quote(urllib.parse.unquote(item), safe="-._~")
                for item in parsed.path.split("/") if item]
    base_path = "/" + "/".join(segments) if segments else ""
    host = parsed.hostname.encode("idna").decode("ascii")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port else ""
    return f"https://{host}{port}{base_path}"


def _clean_domain(value: object) -> str:
    domain = str(value or "").strip().casefold().rstrip(".")
    if not domain or "@" in domain or "/" in domain or " " in domain:
        raise DomainMailboxConfigError("invalid mailbox domain")
    return domain


def _clean_host_header(value: object) -> str:
    """Validate an optional HTTP Host override used behind an HTTPS gateway.

    Some mainland-hosted mailbox domains cannot complete a TLS handshake with
    their own SNI name.  A reachable HTTPS vhost can still terminate TLS while
    Nginx routes the request by the original control-plane Host header.  Keep
    this explicit and hostname-only so configuration can never inject headers.
    """
    raw = str(value or "").strip().casefold().rstrip(".")
    if not raw:
        return ""
    if any(char in raw for char in "\r\n/@?#"):
        raise DomainMailboxConfigError("host_header must be a hostname without scheme or path")
    try:
        host = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise DomainMailboxConfigError("host_header is not a valid hostname") from exc
    labels = host.split(".")
    if (
        len(host) > 253
        or any(not label or len(label) > 63 for label in labels)
        or any(not all(char.isalnum() or char == "-" for char in label) for label in labels)
        or any(label.startswith("-") or label.endswith("-") for label in labels)
    ):
        raise DomainMailboxConfigError("host_header is not a valid hostname")
    return host


def _setting_domains(settings: dict[str, object]) -> tuple[str, ...]:
    """Normalize the editable runtime setting into a stable domain list."""
    raw = str(settings.get("domain_mailbox_domains") or "")
    values = re_split_domains(raw)
    default = str(settings.get("domain_mailbox_default_domain") or "").strip()
    if default:
        values.insert(0, default)
    return tuple(dict.fromkeys(_clean_domain(item) for item in values if str(item).strip()))


def re_split_domains(value: str) -> list[str]:
    # Keep the module dependency-free: the setting accepts commas, semicolons
    # and newlines so operators can paste a provider's domain list directly.
    normalized = str(value or "").replace(";", ",").replace("\r", "\n")
    return [item.strip() for line in normalized.split("\n") for item in line.split(",") if item.strip()]


def provider_from_runtime_settings(
    settings: dict[str, object],
    *,
    require_admin_token: bool = False,
) -> "ProviderConfig":
    """Build a provider from the console's editable runtime settings.

    The admin token remains in the server process.  Child registration workers
    receive a token-free schema-v3 routing file because message reads use the
    per-mailbox token embedded in ``inbox_url``.
    """
    domains = _setting_domains(settings)
    if not domains:
        raise DomainMailboxConfigError("domain mailbox has no configured domains")
    default = _clean_domain(settings.get("domain_mailbox_default_domain") or domains[0])
    if default not in domains:
        raise DomainMailboxConfigError("default domain is not in the configured domain list")
    token = str(settings.get("domain_mailbox_admin_token") or "").strip()
    if require_admin_token and not token:
        raise DomainMailboxConfigError("domain mailbox admin token is not configured")
    return ProviderConfig(
        provider_id="runtime-vps",
        provider="vps",
        label=str(settings.get("domain_mailbox_label") or "自建域名邮箱").strip() or "自建域名邮箱",
        api_origin=_clean_origin(settings.get("domain_mailbox_api_origin")),
        host_header=_clean_host_header(settings.get("domain_mailbox_host_header")),
        domains=domains,
        admin_token_literal=token,
    )


def runtime_config_payload(settings: dict[str, object]) -> dict[str, object]:
    """Return a token-free schema-v3 config for registration child processes."""
    provider = provider_from_runtime_settings(settings, require_admin_token=False)
    default = _clean_domain(settings.get("domain_mailbox_default_domain") or provider.domains[0])
    return {
        "schema_version": 3,
        "default_domain": default,
        "providers": {
            provider.provider_id: {
                "provider": "vps",
                "label": provider.label,
                "api_origin": provider.api_origin,
                **({"host_header": provider.host_header} if provider.host_header else {}),
                "domains": list(provider.domains),
            }
        },
    }


def _nested_json_value(payload: object, dotted_key: str) -> object:
    current = payload
    for part in str(dotted_key or "admin_api_token").split("."):
        if not isinstance(current, dict) or part not in current:
            return ""
        current = current[part]
    return current


@dataclass(frozen=True)
class ProviderConfig:
    provider_id: str
    provider: str
    label: str
    api_origin: str
    domains: tuple[str, ...]
    host_header: str = ""
    admin_token_literal: str = ""
    admin_token_env: str = ""
    admin_token_file: str = ""
    admin_token_json_key: str = "admin_api_token"

    def admin_token(self) -> str:
        if self.admin_token_literal:
            return self.admin_token_literal
        if self.admin_token_env:
            value = os.environ.get(self.admin_token_env, "").strip()
            if value:
                return value
        if self.admin_token_file:
            path = Path(os.path.expandvars(os.path.expanduser(self.admin_token_file)))
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                raise DomainMailboxConfigError(
                    f"cannot read admin token file: {path}"
                ) from exc
            value = str(_nested_json_value(payload, self.admin_token_json_key) or "").strip()
            if value:
                return value
        raise DomainMailboxConfigError(
            f"provider {self.provider_id} has no available admin token source"
        )

    def public_metadata(self) -> dict[str, object]:
        return {
            "id": self.provider_id,
            "provider": self.provider,
            "label": self.label,
            "api_origin": self.api_origin,
            "host_header": self.host_header,
            "domains": list(self.domains),
            "admin_token_configured": bool(
                self.admin_token_literal or self.admin_token_env or self.admin_token_file
            ),
        }


@dataclass(frozen=True)
class InboxCredential:
    provider: ProviderConfig
    address: str
    token: str
    inbox_url: str


@dataclass(frozen=True)
class IssuedMailbox:
    address: str
    token: str
    inbox_url: str

    @property
    def account_line(self) -> str:
        return f"{self.address}----{self.inbox_url}"


@dataclass(frozen=True)
class DomainMailboxConfig:
    path: Path
    schema_version: int
    default_domain: str
    providers: dict[str, ProviderConfig]

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> "DomainMailboxConfig":
        selected = _selected_config_path(path)
        try:
            payload = json.loads(selected.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise DomainMailboxConfigError(f"mailbox provider config not found: {selected}") from exc
        except (OSError, ValueError) as exc:
            raise DomainMailboxConfigError(f"invalid mailbox provider config: {selected}") from exc

        if int(payload.get("schema_version") or 0) != 3:
            raise DomainMailboxConfigError("mailbox provider config schema_version must be 3")
        raw_providers = payload.get("providers")
        if not isinstance(raw_providers, dict) or not raw_providers:
            raise DomainMailboxConfigError("mailbox provider config has no providers")

        providers: dict[str, ProviderConfig] = {}
        for provider_id, raw in raw_providers.items():
            if not isinstance(raw, dict):
                raise DomainMailboxConfigError(f"provider {provider_id} must be an object")
            provider_type = str(raw.get("provider") or "").strip().casefold()
            if provider_type != "vps":
                # Schema v3 may still contain historical providers.  Keep this
                # adapter narrow and ignore entries it cannot safely service.
                continue
            domains = tuple(dict.fromkeys(_clean_domain(item) for item in raw.get("domains") or []))
            if not domains:
                raise DomainMailboxConfigError(f"provider {provider_id} has no domains")
            providers[str(provider_id)] = ProviderConfig(
                provider_id=str(provider_id),
                provider=provider_type,
                label=str(raw.get("label") or provider_id).strip(),
                api_origin=_clean_origin(raw.get("api_origin")),
                domains=domains,
                host_header=_clean_host_header(raw.get("host_header")),
                admin_token_literal=str(raw.get("admin_token") or "").strip(),
                admin_token_env=str(raw.get("admin_token_env") or "").strip(),
                admin_token_file=str(raw.get("admin_token_file") or "").strip(),
                admin_token_json_key=str(raw.get("admin_token_json_key") or "admin_api_token").strip(),
            )
        if not providers:
            raise DomainMailboxConfigError("mailbox provider config has no supported vps provider")

        default_domain = _clean_domain(payload.get("default_domain"))
        if not any(default_domain in provider.domains for provider in providers.values()):
            raise DomainMailboxConfigError("default_domain is not owned by a configured provider")
        return cls(selected.resolve(), 3, default_domain, providers)

    def provider_for_domain(self, domain: str) -> ProviderConfig | None:
        wanted = _clean_domain(domain)
        return next((p for p in self.providers.values() if wanted in p.domains), None)

    def provider(self, provider_id: str = "", domain: str = "") -> ProviderConfig:
        if provider_id:
            provider = self.providers.get(str(provider_id))
        else:
            provider = self.provider_for_domain(domain or self.default_domain)
        if not provider:
            raise DomainMailboxConfigError("mailbox provider is not configured")
        return provider

    def parse_inbox_url(self, inbox_url: str, *, expected_address: str = "") -> InboxCredential | None:
        raw = str(inbox_url or "").strip()
        try:
            parsed = urllib.parse.urlsplit(raw)
        except ValueError:
            return None
        if parsed.scheme != "https" or not parsed.hostname:
            return None
        parts = [urllib.parse.unquote(item) for item in parsed.path.split("/") if item]
        try:
            marker = parts.index("cf-inbox")
            token, address = parts[marker + 1], parts[marker + 2].strip().casefold()
        except (ValueError, IndexError):
            return None
        if not token or address.count("@") != 1:
            return None
        if expected_address and address != str(expected_address).strip().casefold():
            raise DomainMailboxConfigError("inbox URL address does not match account email")
        provider = self.provider_for_domain(address.rsplit("@", 1)[1])
        if not provider:
            return None
        return InboxCredential(provider, address, token, raw)


def get_domain_mailbox_config(
    path: str | os.PathLike[str] | None = None,
    *,
    required: bool = False,
) -> DomainMailboxConfig | None:
    """Load and mtime-cache the local schema-v3 config.

    Missing config is a normal state for installations that only use Outlook
    or generic relay links; malformed present config is always an error.
    """
    selected = _selected_config_path(path)
    try:
        mtime = selected.stat().st_mtime_ns
    except FileNotFoundError:
        if required:
            raise DomainMailboxConfigError(f"mailbox provider config not found: {selected}")
        return None
    cache_key = str(selected.resolve())
    global _CONFIG_CACHE
    with _CONFIG_LOCK:
        if _CONFIG_CACHE and _CONFIG_CACHE[:2] == (cache_key, mtime):
            return _CONFIG_CACHE[2]
        config = DomainMailboxConfig.load(selected)
        _CONFIG_CACHE = (cache_key, mtime, config)
        return config


def _urlopen(request: urllib.request.Request, *, timeout: float, direct: bool = False):
    """Open one mailbox request without ever logging its credential-bearing URL.

    Inbox polling is intentionally direct by default at the call site.  A
    registration proxy should protect the browser session, not add latency or
    couple availability to the user's owned mailbox control plane.
    """
    if direct:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=_SSL_CONTEXT),
        )
        return opener.open(request, timeout=timeout)
    return urllib.request.urlopen(request, timeout=timeout, context=_SSL_CONTEXT)


class DomainMailboxClient:
    def __init__(self, provider: ProviderConfig, *, bearer_token: str = "",
                 direct: bool = False) -> None:
        self.provider = provider
        self.bearer_token = str(bearer_token or "").strip()
        self.direct = bool(direct)

    def _request(
        self,
        method: str,
        path: str,
        *,
        token: str = "",
        query: dict[str, object] | None = None,
        payload: dict[str, object] | None = None,
        timeout: float = 15,
        operation: str = "request",
        expect_json: bool = True,
    ) -> Any:
        query_text = urllib.parse.urlencode({k: v for k, v in (query or {}).items() if v is not None})
        url = f"{self.provider.api_origin}{path}"
        if query_text:
            url += f"?{query_text}"
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
        bearer = str(token or self.bearer_token or "").strip()
        if not bearer:
            bearer = self.provider.admin_token()
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {bearer}",
            "User-Agent": "logicc-register/domain-mailbox-v1",
        }
        if self.provider.host_header:
            headers["Host"] = self.provider.host_header
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, method=method.upper(), headers=headers)
        try:
            response = _urlopen(request, timeout=timeout, direct=self.direct)
            raw = response.read() or b""
        except urllib.error.HTTPError as exc:
            try:
                error_payload = json.loads((exc.read() or b"{}").decode("utf-8", errors="replace"))
                code = str(error_payload.get("error") or error_payload.get("code") or "api_error")
            except Exception:
                code = "api_error"
            raise DomainMailboxApiError(exc.code, code, operation=operation) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # Do not include the request URL because an inbox URL can contain a token.
            raise DomainMailboxError(
                f"domain mailbox {operation} network error: {type(exc).__name__}"
            ) from exc
        if not expect_json:
            return raw.decode("utf-8", errors="replace")
        try:
            return json.loads(raw.decode("utf-8", errors="replace") or "{}")
        except ValueError as exc:
            raise DomainMailboxError(f"domain mailbox {operation} returned invalid JSON") from exc

    def list_messages(self, address: str, *, limit: int = 20, offset: int = 0, timeout: float = 15) -> list[dict[str, object]]:
        payload = self._request(
            "GET",
            "/v1/messages",
            query={"address": address, "limit": max(1, min(int(limit), 100)), "offset": max(0, int(offset))},
            timeout=timeout,
            operation="list messages",
        )
        results = payload.get("results") if isinstance(payload, dict) else None
        return [item for item in (results or []) if isinstance(item, dict)]

    def raw_message(self, message_id: str, address: str, *, timeout: float = 15) -> str:
        safe_id = urllib.parse.quote(str(message_id or ""), safe="")
        return self._request(
            "GET",
            f"/v1/messages/{safe_id}/raw",
            query={"address": address},
            timeout=timeout,
            operation="read raw message",
            expect_json=False,
        )

    def create_batch(
        self,
        count: int,
        *,
        domain: str = "",
        local_part: str = "",
        timeout: float = 30,
    ) -> list[IssuedMailbox]:
        payload: dict[str, object] = {"count": max(1, min(int(count), 500))}
        if domain:
            payload["domain"] = _clean_domain(domain)
        if local_part:
            payload["local_part"] = str(local_part).strip()
        response = self._request(
            "POST",
            "/v1/mailboxes/batch",
            payload=payload,
            timeout=timeout,
            operation="create mailboxes",
        )
        items = response.get("items") if isinstance(response, dict) else None
        issued: list[IssuedMailbox] = []
        for item in items or []:
            if not isinstance(item, dict):
                continue
            address = str(item.get("address") or "").strip().casefold()
            token = str(item.get("token") or "").strip()
            inbox_url = str(item.get("inbox_url") or "").strip()
            if address and token and inbox_url:
                issued.append(IssuedMailbox(address, token, inbox_url))
        if len(issued) != int(response.get("count") or len(issued)):
            raise DomainMailboxError("domain mailbox create response is incomplete")
        return issued

    def list_domains(self, *, timeout: float = 15) -> list[dict[str, object]]:
        response = self._request(
            "GET",
            "/v1/domains",
            timeout=timeout,
            operation="list domains",
        )
        items = response.get("items") if isinstance(response, dict) else response
        return [item for item in (items or []) if isinstance(item, dict)]

    def set_enabled(self, address: str, enabled: bool, *, timeout: float = 15) -> dict[str, object]:
        safe_address = urllib.parse.quote(str(address or "").strip().casefold(), safe="")
        response = self._request(
            "PATCH",
            f"/v1/mailboxes/{safe_address}",
            payload={"enabled": bool(enabled)},
            timeout=timeout,
            operation="update mailbox",
        )
        return response if isinstance(response, dict) else {}


def read_managed_inbox_url(inbox_url: str, *, timeout: float = 15,
                           message_limit: int = 3) -> str | None:
    """Return mailbox text for a configured VPS URL, or ``None`` if unmatched."""
    try:
        from protocol_budget import deadline_after, remaining
    except ModuleNotFoundError:
        from .protocol_budget import deadline_after, remaining
    deadline = deadline_after(timeout)
    config = get_domain_mailbox_config(required=False)
    if not config:
        return None
    credential = config.parse_inbox_url(inbox_url)
    if not credential:
        return None
    client = DomainMailboxClient(
        credential.provider,
        bearer_token=credential.token,
        direct=True,
    )
    # Inspect each message separately so another application's OTP cannot borrow
    # Logicc branding from an adjacent email.
    messages = client.list_messages(
        credential.address,
        limit=max(1, min(int(message_limit), 10)),
        timeout=remaining(deadline, timeout),
    )
    messages.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    try:
        from email_provider import _extract_otp, _imap_message_body, _message_subject
    except ModuleNotFoundError:
        from .email_provider import _extract_otp, _imap_message_body, _message_subject
    from email import message_from_string

    for index, item in enumerate(messages):
        raw = str(item.get("raw") or "")
        if int(item.get("truncated") or 0) and item.get("id"):
            raw = client.raw_message(str(item["id"]), credential.address, timeout=remaining(deadline, timeout))
        message = message_from_string(raw)
        text = f"{_message_subject(message)}\n{_imap_message_body(message)}"
        sender = str(message.get("From") or "")
        if not _extract_otp(text, sender=sender):
            continue
        return (
            "\n".join((
                str(item.get("created_at") or ""),
                str(item.get("message_id") or item.get("id") or ""),
                "Logicc",
                text,
            ))
        )
    return ""


def provision_mailboxes(
    count: int,
    *,
    provider_id: str = "",
    domain: str = "",
    local_part: str = "",
    config_path: str | os.PathLike[str] | None = None,
) -> list[IssuedMailbox]:
    config = get_domain_mailbox_config(config_path, required=True)
    assert config is not None
    provider = config.provider(provider_id, domain)
    selected_domain = _clean_domain(domain or config.default_domain)
    if selected_domain not in provider.domains:
        raise DomainMailboxConfigError("requested domain does not belong to selected provider")
    return DomainMailboxClient(provider).create_batch(
        count,
        domain=selected_domain,
        local_part=local_part,
    )


def provision_from_runtime_settings(
    settings: dict[str, object],
    count: int,
    *,
    domain: str = "",
    local_part: str = "",
    timeout: float = 30,
) -> list[IssuedMailbox]:
    provider = provider_from_runtime_settings(settings, require_admin_token=True)
    selected_domain = _clean_domain(
        domain or settings.get("domain_mailbox_default_domain") or provider.domains[0]
    )
    if selected_domain not in provider.domains:
        raise DomainMailboxConfigError("requested domain does not belong to the configured provider")
    return DomainMailboxClient(
        provider,
        bearer_token=provider.admin_token_literal,
    ).create_batch(
        count,
        domain=selected_domain,
        local_part=local_part,
        timeout=timeout,
    )
