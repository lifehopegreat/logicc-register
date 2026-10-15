"""
邮箱 OTP 拉取模块
支持 Hotmail/Outlook (Microsoft Graph API) 和 IMAP XOAUTH2
仅接收 Logicc 验证码，保留 Microsoft 与 IMAP 邮箱认证
"""
import imaplib
from email.utils import parseaddr
from email.header import decode_header, make_header
import base64
import hashlib
import html
import itertools
import json
import logging
import re
import ssl
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from html.parser import HTMLParser

try:
    from protocol_budget import DeadlineExceeded, MailboxTimeout, deadline_after, remaining
except ModuleNotFoundError:
    from .protocol_budget import DeadlineExceeded, MailboxTimeout, deadline_after, remaining

# Mailbox URLs carry OTP credentials, so certificate verification must stay on.
_SSL_CTX = ssl.create_default_context()

log = logging.getLogger("email")

GRAPH_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
GRAPH_MAIL_URL = "https://graph.microsoft.com/v1.0/me/messages"
IMAP_HOST = "outlook.office365.com"
IMAP_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access"

# Keep every mailbox transport on the same cadence.  Three seconds is quick
# enough for verification mail while avoiding excessive Graph/IMAP/relay
# requests when several registrations are running concurrently.
OTP_POLL_INTERVAL = 3.0

# Thunderbird public OAuth client_id
DEFAULT_CLIENT_ID = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"

# Relay endpoints commonly repeat their newest message until a new one lands.
_RELAY_LAST_OTP: dict[str, str] = {}
_RELAY_LAST_MESSAGE: dict[str, str] = {}
_RELAY_LAST_OTP_LOCK = threading.Lock()

# Only verification-related six-digit codes are candidates.
OTP_PATTERNS = [
    re.compile(r"(?:verification\s+code|one[-\s]*time\s+(?:code|password)|"
               r"sign[-\s]*in\s+code|login\s+code|验证码|驗證碼|Bestätigungscode)"
               r"[^\d]{0,160}(\d{6})\b", re.I | re.S),
    re.compile(r"\b(\d{6})\b[^\d]{0,80}(?:is your|ist Ihr|作为|是您的).*?"
               r"(?:verification|sign[-\s]*in|login|验证码|驗證碼|Bestätigungscode)", re.I | re.S),
]


def _logicc_sender(sender: str) -> str:
    address = parseaddr(str(sender or ""))[1].casefold()
    domain = address.rpartition("@")[2]
    if domain == "logicc.com" or domain.endswith(".logicc.com"):
        return "logicc"
    if domain in {"clerk.com", "clerk.dev"} or domain.endswith((".clerk.com", ".clerk.dev")):
        return "clerk"
    return ""


class _VisibleTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, _attrs):
        if tag in {"script", "style", "noscript"}:
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def _otp_text(text: str) -> str:
    """Use visible HTML text so CSS, trackers and mailbox sender IDs are not OTPs."""
    if not re.search(r"<!doctype\s+html|<[a-z][^>]*>", text[:2000], re.I):
        return text
    parser = _VisibleTextParser()
    try:
        parser.feed(text)
        return html.unescape(" ".join(parser.parts))
    except Exception:
        return text


def _is_hex_color_context(text: str, idx: int) -> bool:
    if idx > 0 and text[idx - 1] == "#":
        return True
    before = text[max(0, idx - 30):idx]
    return bool(
        re.search(
            r"(?:color|background|bgcolor|fill|stroke)\s*[:=]\s*[\"']?#?\s*$",
            before, re.I,
        )
    )


def _extract_otp(text: str, *, sender: str = "") -> str | None:
    """从邮件正文（含 HTML）中提取 6 位数字 OTP，跳过颜色码 / sendgrid 跟踪 ID。"""
    text = _otp_text(text)
    sender_kind = _logicc_sender(sender)
    branded = bool(re.search(r"\blogicc\b", text, re.I))
    # Shared Clerk delivery is accepted only when the message names Logicc.
    if sender and not sender_kind:
        return None
    if sender_kind != "logicc" and not branded:
        return None
    if re.search(r"\b(?:chatgpt|openai)\b", text, re.I):
        return None
    for pat in OTP_PATTERNS:
        for m in pat.finditer(text):
            idx = m.start(1)
            if _is_hex_color_context(text, idx):
                continue
            # 跳过 sendgrid 跟踪链接里的数字 (u20216706 / em7877 等)
            before = text[max(0, idx - 30):idx]
            if re.search(r"\bu\d{0,4}$|\.ct\.sendgrid\.net|/ls/click|em\d{0,4}\.tm\.", before, re.I):
                continue
            token_start = max(text.rfind(ch, 0, idx) for ch in " \t\r\n") + 1
            token_ends = [pos for ch in " \t\r\n" if (pos := text.find(ch, idx)) >= 0]
            token = text[token_start:min(token_ends, default=len(text))]
            if "@" in token or "://" in token:
                continue
            return m.group(1)
    return None


# ========== Hotmail/Outlook via Microsoft Graph API ==========


class GraphScopeMissingError(Exception):
    """refresh_token 不带 Graph scope（卡密默认 IMAP-only），自动 fallback 到 IMAP。"""
    pass


class EmailCredentialInvalidError(RuntimeError):
    """Mailbox refresh token is permanently invalid and should not be polled."""


def _refresh_access_token(
    refresh_token: str,
    client_id: str,
    scope: str,
    *,
    email: str = "",
    classify_graph_scope: bool = False,
    deadline: float | None = None,
) -> str:
    """Refresh an OAuth token and persist Microsoft RT rotation in the vault."""
    vault = None
    claim = None
    if email:
        try:
            from account_vault import (
                AccountNotFound,
                RefreshBusy,
                VaultError,
                get_account_vault,
            )

            vault = get_account_vault()
            claim = vault.claim_refresh(email)
            refresh_token = str(claim["refresh_token"])
            client_id = str(claim["client_id"] or client_id)
        except AccountNotFound:
            vault = None
            claim = None
        except RefreshBusy:
            raise
        except VaultError as exc:
            raise EmailCredentialInvalidError(
                f"邮箱 refresh_token 已失效: {email}"
            ) from exc

    body = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "scope": scope,
    }).encode()
    req = urllib.request.Request(GRAPH_TOKEN_URL, data=body)
    try:
        resp = urllib.request.urlopen(req, timeout=remaining(deadline, 15), context=_SSL_CTX)
        try:
            data = json.loads(resp.read())
        finally:
            getattr(resp, "close", lambda: None)()
        remaining(deadline)
        access_token = data.get("access_token")
        if not access_token:
            raise RuntimeError("Microsoft token refresh response omitted access_token")
        new_refresh_token = str(data.get("refresh_token") or refresh_token).strip()
        if vault is not None and claim is not None:
            if not vault.finalize_refresh(
                int(claim["account_id"]), str(claim["lease"]), new_refresh_token
            ):
                raise RuntimeError("Microsoft token refresh lease expired")
        return str(access_token)
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="replace")
        except Exception:
            err_body = ""
        err_lower = err_body.lower()
        scope_markers = (
            "invalid_scope",
            "aadsts65001",
            "aadsts70011",
            "aadsts900144",
            "scope",
            "consent",
        )
        scope_missing = (
            classify_graph_scope
            and e.code == 400
            and any(marker in err_lower for marker in scope_markers)
        )
        invalid_grant = e.code == 400 and "invalid_grant" in err_lower and not scope_missing
        if vault is not None and claim is not None:
            vault.release_refresh(
                int(claim["account_id"]), str(claim["lease"]), invalid=invalid_grant
            )
        if scope_missing:
            raise GraphScopeMissingError(
                "Graph scope missing (refresh_token only supports IMAP)"
            ) from e
        if invalid_grant:
            raise EmailCredentialInvalidError(
                f"Microsoft refresh_token invalid_grant: {email or 'unknown'}"
            ) from e
        raise RuntimeError(f"Microsoft token refresh failed: HTTP {e.code}") from e
    except BaseException:
        if vault is not None and claim is not None:
            vault.release_refresh(int(claim["account_id"]), str(claim["lease"]))
        raise


def _get_access_token_graph(refresh_token: str, client_id: str, email: str = "", *,
                            deadline: float | None = None) -> str:
    """用 refresh_token 换取 Graph API access_token

    抛 ``GraphScopeMissingError`` 表示 token 缺 ``Mail.Read`` scope（即"卡密只有
    IMAP 权限"），调用方应该自动切到 IMAP 模式。
    """
    return _refresh_access_token(
        refresh_token,
        client_id,
        "https://graph.microsoft.com/Mail.Read offline_access",
        email=email,
        classify_graph_scope=True,
        deadline=deadline,
    )


def fetch_otp_graph(email: str, refresh_token: str, client_id: str,
                    timeout: float = 120, after_ts: float = 0,
                    excluded_otps: set[str] | None = None, *,
                    deadline: float | None = None) -> str:
    """
    通过 Microsoft Graph API 拉取 OTP（适用于 Hotmail/Outlook 邮箱）。
    after_ts: 仅接受此时刻之后到达的邮件，避免命中过期 OTP。
              默认 = 调用时刻 - 30s（容错 Logicc 投递快于浏览器跳转的窗口）。
    """
    if not after_ts:
        after_ts = time.time() - 30
    excluded_otps = set(excluded_otps or ())
    deadline = deadline_after(timeout, deadline)
    seen = set()
    cached_token = ""

    log.info(f"[OTP-Graph] 监听 {email} ({timeout}s)...")

    while time.monotonic() < deadline:
        delay = OTP_POLL_INTERVAL
        try:
            if not cached_token:
                cached_token = _get_access_token_graph(refresh_token, client_id, email=email, deadline=deadline)

            # 查询最近的 Logicc 邮件
            filter_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(after_ts))
            params = urllib.parse.urlencode({
                "$filter": f"receivedDateTime ge {filter_ts}",
                "$top": "10",
                "$orderby": "receivedDateTime desc",
                "$select": "subject,from,body,receivedDateTime",
            })
            url = f"{GRAPH_MAIL_URL}?{params}"

            req = urllib.request.Request(url, headers={
                "Authorization": f"Bearer {cached_token}",
                "Accept": "application/json",
            })
            resp = urllib.request.urlopen(req, timeout=remaining(deadline, 15), context=_SSL_CTX)
            try:
                data = json.loads(resp.read())
            finally:
                getattr(resp, "close", lambda: None)()
            remaining(deadline)

            for msg in data.get("value", []):
                msg_id = msg.get("id", "")
                if msg_id in seen:
                    continue

                sender = (msg.get("from", {}).get("emailAddress", {}).get("address", "") or "").lower()
                subject = msg.get("subject", "")
                body_text = msg.get("body", {}).get("content", "")

                if not _logicc_sender(sender):
                    seen.add(msg_id)
                    continue

                # 提取 Logicc 验证码
                combined = f"{subject} {body_text}"
                otp = _extract_otp(combined, sender=sender)
                if otp and otp not in excluded_otps:
                    log.info(f"[OTP-Graph][{email}] 已获取（内容不写入日志）")
                    return otp

                seen.add(msg_id)

        except (GraphScopeMissingError, EmailCredentialInvalidError, DeadlineExceeded):
            # 卡密 token 没 Graph scope → 立刻向上抛，让 fetch_otp 自动 fallback IMAP
            raise
        except urllib.error.HTTPError as e:
            if e.code == 401:
                cached_token = ""
            elif e.code == 429:
                try:
                    delay = max(OTP_POLL_INTERVAL, float(e.headers.get("Retry-After", "3")))
                except (TypeError, ValueError):
                    delay = OTP_POLL_INTERVAL
            log.warning(f"[OTP-Graph][{email}] HTTP {e.code}")
        except Exception as e:
            log.warning(f"[OTP-Graph][{email}] 异常: {e}")

        time.sleep(min(delay, max(0.0, deadline - time.monotonic())))

    raise DeadlineExceeded("mailbox OTP deadline exceeded")


# ========== Hotmail/Outlook via IMAP XOAUTH2 ==========

def _get_access_token_imap(refresh_token: str, client_id: str, email: str = "", *,
                           deadline: float | None = None) -> str:
    """用 refresh_token 换取 IMAP access_token"""
    return _refresh_access_token(
        refresh_token,
        client_id,
        IMAP_SCOPE,
        email=email,
        deadline=deadline,
    )


def fetch_otp_imap(email: str, refresh_token: str, client_id: str,
                   timeout: float = 240, threshold_ts: float = 0,
                   excluded_otps: set[str] | None = None, *,
                   deadline: float | None = None) -> str:
    """Read fresh mail over one account-scoped XOAUTH2 connection."""
    deadline = deadline_after(timeout, deadline)
    token = ""
    token_at = 0.0

    def connect():
        nonlocal token, token_at
        if not token or time.monotonic() - token_at >= 3000:
            token = _get_access_token_imap(refresh_token, client_id, email=email, deadline=deadline)
            token_at = time.monotonic()
        connection = imaplib.IMAP4_SSL(IMAP_HOST, 993, ssl_context=_SSL_CTX,
                                      timeout=remaining(deadline, 15))
        try:
            _imap_timeout(connection, deadline)
            auth = f"user={email}\x01auth=Bearer {token}\x01\x01".encode()
            typ, _ = connection.authenticate("XOAUTH2", lambda _: auth)
            if typ != "OK":
                raise imaplib.IMAP4.error("IMAP XOAUTH2 authentication rejected")
            return connection
        except BaseException:
            token = ""
            _close_imap(connection, deadline)
            raise

    return _poll_imap_otp(connect, deadline=deadline,
                          after_ts=threshold_ts or time.time() - 30,
                          excluded_otps=excluded_otps, poll_interval=OTP_POLL_INTERVAL)


# ========== Generic password-authenticated IMAP (NotLetters, etc.) ==========

def _imap_message_body(message) -> str:
    body_parts: list[str] = []
    for part in message.walk() if message.is_multipart() else (message,):
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                payload = str(part.get_payload() or "").encode("utf-8", errors="ignore")
            charset = part.get_content_charset() or "utf-8"
            body_parts.append(payload.decode(charset, errors="ignore"))
        except Exception:
            continue
    return "\n".join(body_parts)


def _message_subject(message) -> str:
    try:
        return str(make_header(decode_header(str(message.get("Subject") or ""))))
    except (LookupError, UnicodeError, ValueError):
        return ""


def _imap_folders(connection: imaplib.IMAP4_SSL) -> list[str]:
    try:
        typ, listing = connection.list()
        if typ != "OK":
            raise RuntimeError("IMAP LIST failed")
        names: dict[str, str] = {}
        for raw in listing or []:
            text = raw.decode(errors="ignore") if isinstance(raw, bytes) else str(raw)
            match = re.search(r'"([^"]+)"\s*$', text) or re.search(r"\s(\S+)\s*$", text)
            if match:
                value = match.group(1).strip('"')
                names[value.casefold()] = value
        picked: list[str] = []
        for candidate in ("INBOX", "Junk", "Junk Email", "Spam"):
            actual = names.get(candidate.casefold())
            if actual and actual not in picked:
                picked.append(actual)
        for lowered, actual in names.items():
            if any(marker in lowered for marker in ("junk", "spam", "bulk")) and actual not in picked:
                picked.append(actual)
        if not any(folder.casefold() == "inbox" for folder in picked):
            picked.insert(0, "INBOX")
        return picked
    except Exception:
        return ["INBOX"]


def _imap_timeout(connection, deadline: float) -> None:
    timeout = remaining(deadline, 15)
    connection.sock.settimeout(timeout)


def _close_imap(connection, deadline: float) -> None:
    if connection is None:
        return
    try:
        connection.sock.settimeout(remaining(deadline, 1))
        connection.logout()
    except Exception:
        pass
    finally:
        try:
            connection.shutdown()
        except Exception:
            pass


def _poll_imap_otp(connect, *, deadline: float, after_ts: float,
                   excluded_otps: set[str] | None, poll_interval: float) -> str:
    import email as email_lib

    seen: set[tuple[str, bytes, bytes]] = set()
    excluded = set(excluded_otps or ())
    connection = None
    folders = []
    # SINCE is day-granular; the extra day covers server/client timezone boundaries.
    search_day = time.strftime("%d-%b-%Y", time.gmtime(after_ts - 86400))
    try:
        while time.monotonic() < deadline:
            try:
                if connection is None:
                    connection = connect()
                    _imap_timeout(connection, deadline)
                    folders = _imap_folders(connection)
                    log.info("[OTP-IMAP] 已连接；扫描文件夹=%s", folders)
                for folder in folders:
                    _imap_timeout(connection, deadline)
                    name = f'"{folder}"' if " " in folder else folder
                    typ, _ = connection.select(name, readonly=True)
                    if typ != "OK":
                        continue
                    _, validity = connection.response("UIDVALIDITY")
                    uidvalidity = next((v for v in validity or [] if isinstance(v, bytes)), b"")
                    if not uidvalidity:
                        raise RuntimeError("IMAP omitted UIDVALIDITY")
                    _imap_timeout(connection, deadline)
                    typ, data = connection.uid("search", None, "SINCE", search_day)
                    if typ != "OK":
                        continue
                    for uid in reversed((data[0] or b"").split()):
                        key = ("INBOX" if folder.casefold() == "inbox" else folder, uidvalidity, uid)
                        if key in seen:
                            continue
                        _imap_timeout(connection, deadline)
                        typ, payload = connection.uid("fetch", uid,
                            "(UID INTERNALDATE BODY.PEEK[HEADER.FIELDS (FROM SUBJECT CONTENT-TYPE)])")
                        if typ != "OK":
                            continue
                        part = next((p for p in payload or [] if isinstance(p, tuple)
                                     and isinstance(p[0], bytes) and isinstance(p[1], bytes)), None)
                        if part is None:
                            continue
                        received = imaplib.Internaldate2tuple(part[0])
                        # Date headers are sender-controlled; missing server timestamps fail closed.
                        if received is None:
                            continue
                        header = email_lib.message_from_bytes(part[1])
                        sender = str(header.get("From") or "").casefold()
                        # INTERNALDATE has whole-second precision, unlike the local send timestamp.
                        if time.mktime(received) < int(after_ts) or not _logicc_sender(sender):
                            seen.add(key)
                            continue
                        _imap_timeout(connection, deadline)
                        typ, payload = connection.uid("fetch", uid, "(UID BODY.PEEK[])")
                        if typ != "OK":
                            continue
                        raw = next((p[1] for p in payload or [] if isinstance(p, tuple)
                                    and isinstance(p[1], bytes)), b"")
                        if not raw:
                            continue
                        message = email_lib.message_from_bytes(raw)
                        otp = _extract_otp(f"{_message_subject(message)}\n{_imap_message_body(message)}", sender=sender)
                        remaining(deadline)
                        seen.add(key)
                        if otp and otp not in excluded:
                            log.info("[OTP-IMAP] 已获取（内容不写入日志）")
                            return otp
            except (EmailCredentialInvalidError, DeadlineExceeded):
                raise
            except Exception as exc:
                # A timed-out makefile buffer cannot safely be reused.
                log.warning("[OTP-IMAP] 连接/轮询异常，将受控重连: %s", type(exc).__name__)
                _close_imap(connection, deadline)
                connection = None
            time.sleep(min(max(0.0, poll_interval), max(0.0, deadline - time.monotonic())))
        raise DeadlineExceeded("mailbox OTP deadline exceeded")
    finally:
        _close_imap(connection, deadline)


def fetch_otp_password_imap(
    email: str, password: str, *, host: str, port: int = 993,
    timeout: float = 120, after_ts: float = 0,
    excluded_otps: set[str] | None = None,
    poll_interval: float = OTP_POLL_INTERVAL,
    deadline: float | None = None,
) -> str:
    """Use the same fresh-UID reader with password authentication and verified TLS."""
    mailbox, secret = str(email or "").strip(), str(password or "")
    if not mailbox or not secret:
        raise EmailCredentialInvalidError("password IMAP requires email and password")
    deadline = deadline_after(timeout, deadline)

    def connect():
        connection = imaplib.IMAP4_SSL(str(host), int(port), ssl_context=_SSL_CTX,
                                      timeout=remaining(deadline, 15))
        try:
            _imap_timeout(connection, deadline)
            try:
                typ, _ = connection.login(mailbox, secret)
            except imaplib.IMAP4.error as exc:
                raise EmailCredentialInvalidError("IMAP login rejected") from exc
            if typ != "OK":
                raise EmailCredentialInvalidError("IMAP login rejected")
            return connection
        except BaseException:
            _close_imap(connection, deadline)
            raise

    return _poll_imap_otp(connect, deadline=deadline,
                          after_ts=after_ts or time.time() - 30,
                          excluded_otps=excluded_otps, poll_interval=poll_interval)


# ========== 统一入口 ==========

def fetch_otp(email: str, refresh_token: str, client_id: str = "",
              method: str = "graph", timeout: int = 120,
              *, relay_require_fresh: bool = True,
              relay_change_grace: float = 0,
              relay_allow_reuse: bool = False,
              relay_reject_same_code: bool = False,
              excluded_otps: set[str] | None = None,
              after_ts: float = 0,
              password: str = "",
              imap_host: str = "",
              imap_port: int = 993,
              deadline: float | None = None) -> str:
    """
    统一 OTP 拉取入口

    method:
      - "graph"  Microsoft Graph API（Outlook / Hotmail，需 refresh_token + client_id）
      - "imap"   IMAP XOAUTH2（同上）
      - "relay"  iCloud 隐私邮箱接码 URL（GET 直接拿 OTP，refresh_token 字段填取码 URL）

    自动识别：refresh_token 看着像 http(s):// 时无视 method，强走 relay。
    配置过的自建域名邮箱 inbox_url 会在 relay 内部改走稳定 /v1 API，
    未匹配的历史接码链接仍沿用原 GET 页面逻辑。

    relay_require_fresh:
      默认 False：拉到第一封含 OTP 的邮件就返回（注册场景 Logicc 只发 1 封，
                  接码服务通常返回的就是这一封，立即用最稳）。
      True：把第一次响应当基线丢掉，必须等内容变化（新邮件）才返回。仅用于
            "已有旧邮件、必须等新邮件"的特殊场景（如登录复用同一邮箱多次）。
    """
    parent_deadline = deadline
    deadline = deadline_after(timeout, deadline)
    after_ts = after_ts or time.time() - 30
    try:
        remaining(deadline)
        rt = (refresh_token or "").strip()

        try:
            from mailbox_transport import parse_imap_password_endpoint
        except ModuleNotFoundError:
            from .mailbox_transport import parse_imap_password_endpoint
        endpoint = parse_imap_password_endpoint(rt, client_id)
        if endpoint or method == "imap_password":
            host = str(imap_host or (endpoint.host if endpoint else "")).strip()
            port = int(imap_port or (endpoint.port if endpoint else 993))
            if not host:
                raise ValueError("password IMAP host is missing")
            return fetch_otp_password_imap(
                email,
                password,
                host=host,
                port=port,
                timeout=timeout, deadline=deadline,
                after_ts=after_ts,
                excluded_otps=excluded_otps,
            )

        # 自动识别：URL 形态的 "refresh_token" 一律走 relay（兼容 icloud 行直接当 outlook 行用的情况）
        if rt.startswith(("http://", "https://")) or method == "relay":
            return fetch_otp_relay(
                rt,
                timeout=timeout, deadline=deadline,
                excluded_otps=excluded_otps,
                require_fresh=relay_require_fresh,
                change_grace=relay_change_grace,
                allow_reuse=relay_allow_reuse,
                reject_same_code=relay_reject_same_code,
            )

        if not client_id:
            client_id = DEFAULT_CLIENT_ID

        if method == "imap":
            return fetch_otp_imap(
                email, refresh_token, client_id, timeout=timeout, deadline=deadline,
                threshold_ts=after_ts, excluded_otps=excluded_otps,
            )

        # 默认 graph：失败时自动检测 scope 缺失并 fallback 到 IMAP
        try:
            return fetch_otp_graph(
                email, refresh_token, client_id, timeout=timeout, deadline=deadline,
                after_ts=after_ts, excluded_otps=excluded_otps,
            )
        except GraphScopeMissingError as e:
            log.warning(
                f"[email] {email} refresh_token 没有 Graph scope（卡密只有 IMAP 权限）"
                f"，自动切到 IMAP 模式重试。详情：{e}"
            )
            return fetch_otp_imap(
                email, refresh_token, client_id, timeout=timeout, deadline=deadline,
                threshold_ts=after_ts, excluded_otps=excluded_otps,
            )
    except DeadlineExceeded as exc:
        if parent_deadline is None or time.monotonic() < parent_deadline:
            raise MailboxTimeout("mailbox OTP deadline exceeded") from exc
        raise


# ========== iCloud / 任意 GET-URL 接码协议 ==========

_RELAY_HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
    "Cache-Control": "no-cache, no-store, max-age=0",
    "Pragma": "no-cache",
}
_RELAY_POLL_COUNTER = itertools.count()


def _relay_poll_url(relay_url: str) -> str:
    parts = urllib.parse.urlsplit(relay_url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    query.append(("_logicc_poll", f"{time.time_ns()}-{next(_RELAY_POLL_COUNTER)}"))
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(query), parts.fragment)
    )


def _relay_message_text(page_text: str, page_url: str, timeout: float) -> str:
    """Resolve mailbox dashboards that load the active message through JSON."""
    message_id = re.search(
        r'class=["\'][^"\']*\bactive\b[^"\']*["\'][^>]*data-id=["\']([^"\']+)',
        page_text, re.I,
    ) or re.search(
        r'data-id=["\']([^"\']+)["\'][^>]*class=["\'][^"\']*\bactive\b',
        page_text, re.I,
    )
    detail_base = re.search(r"detailBase\s*=\s*(['\"])(.*?)\1", page_text, re.S)
    detail_suffix = re.search(r"detailSuffix\s*=\s*(['\"])(.*?)\1", page_text, re.S)
    if not (message_id and detail_base and detail_suffix):
        return page_text

    detail_path = (
        detail_base.group(2)
        + urllib.parse.quote(message_id.group(1), safe="")
        + detail_suffix.group(2)
    )
    detail_url = urllib.parse.urljoin(page_url, detail_path)
    request = urllib.request.Request(detail_url, headers=_RELAY_HEADERS)
    response = urllib.request.urlopen(request, timeout=timeout, context=_SSL_CTX)
    try:
        payload = json.loads((response.read() or b"{}").decode("utf-8", errors="replace"))
    finally:
        getattr(response, "close", lambda: None)()
    body = str(payload.get("body") or "")
    if body.startswith("data:") and "," in body:
        header, encoded = body.split(",", 1)
        raw = base64.b64decode(encoded) if ";base64" in header.lower() else urllib.parse.unquote_to_bytes(encoded)
        body = raw.decode("utf-8", errors="ignore")
    sender = str(payload.get("from") or payload.get("sender") or "")
    text = f"{payload.get('subject') or ''}\n{body}"
    return "Logicc\n" + text if _extract_otp(text, sender=sender) else ""


def _read_relay(relay_url: str, timeout: float) -> str:
    """Bypass intermediary caches; retry the original URL for strict providers."""
    deadline = deadline_after(timeout)
    try:
        from domain_mailbox import read_managed_inbox_url
    except ModuleNotFoundError:  # package import in tools/tests
        from .domain_mailbox import read_managed_inbox_url
    managed_text = read_managed_inbox_url(relay_url, timeout=remaining(deadline, timeout))
    if managed_text is not None:
        return managed_text
    urls = (_relay_poll_url(relay_url), relay_url)
    for index, url in enumerate(urls):
        try:
            request = urllib.request.Request(url, headers=_RELAY_HEADERS)
            response = urllib.request.urlopen(request, timeout=remaining(deadline, timeout), context=_SSL_CTX)
            try:
                text = (response.read() or b"").decode("utf-8", errors="ignore")
            finally:
                getattr(response, "close", lambda: None)()
            return _relay_message_text(text, url, remaining(deadline, timeout))
        except urllib.error.HTTPError as exc:
            if index == 0 and exc.code in {400, 404, 405}:
                continue
            raise
    return ""

def mark_relay_baseline(relay_url: str, *, timeout: float = 5.0) -> bool:
    """Remember the mailbox code visible before requesting a new OTP."""
    if not relay_url.startswith(("http://", "https://")):
        return False
    try:
        text = _read_relay(relay_url, timeout)
        otp = _extract_otp(text)
    except Exception as exc:
        log.debug("  [relay] baseline snapshot failed: %s", type(exc).__name__)
        return False
    with _RELAY_LAST_OTP_LOCK:
        _RELAY_LAST_OTP[relay_url] = otp or ""
        _RELAY_LAST_MESSAGE[relay_url] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    log.info("  [relay] 已记录发码前基线（OTP 不写入日志）")
    return True

def fetch_otp_relay(relay_url: str, *, timeout: int = 120,
                    poll_interval: float = OTP_POLL_INTERVAL,
                    excluded_otps: set[str] | None = None,
                    require_fresh: bool = True,
                    change_grace: float = 0,
                    allow_reuse: bool = False,
                    reject_same_code: bool = False,
                    deadline: float | None = None) -> str:
    """从接码 URL 拉 OTP 邮件文本，抠 6 位数字。

    跟 邮箱轮询方式：周期性 GET URL，看到含 6 位码的内容就返回。
    适用：
      - iCloud 隐私邮箱卖家发货格式 `email----https://api.example/xxx`
      - 任何 "GET URL → 邮件正文（含 OTP）" 的接码服务

    Args:
        relay_url: 取码 URL
        timeout:   总等待秒数
        poll_interval: 两次 GET 间隔
        excluded_otps: 忽略这些 OTP（防止重复拿到上一次的旧码）
        require_fresh: True 时第一次响应当作"基线快照"不返回，必须等到内容变化（新邮件到达）
                       才返回新 OTP。这能避免：Logicc 还没发新邮件，我们就把上次的旧
                       OTP 提交回去导致 verification_error。
                       False 时第一次拉到内容立即返回（旧的也接受，谨慎使用）。
        allow_reuse: 仅供调用方在同一账号的连续认证事务中做一次受控复用。部分简化
                     接码 API 只返回“最后一个六位码”，没有邮件 ID/时间戳；此时无法
                     从响应判断服务端是否为新事务复用了同一码。默认关闭。
        reject_same_code: 注册场景的防陈旧保护。若发码前已记录基线，即使接码
                          页面内容指纹因动态字段变化，也不接受与基线相同的验证码；
                          新验证码仍可正常返回。受控复用（allow_reuse=True）优先。

    Returns:
        6 位 OTP 字符串；超时返回 ""。
    """
    if not relay_url:
        return ""
    excluded_otps = set(excluded_otps or set())
    end = deadline_after(timeout, deadline)
    last_text = ""
    baseline_text = ""
    baseline_otp = ""
    baseline_initialized = False
    last_otp_fp = ""
    last_candidate_marker: str | None = None
    candidate_changed_at = 0.0
    grace_used = False
    relay_host = urllib.parse.urlsplit(relay_url).hostname or "relay"
    log.info("  [relay] 拉 OTP provider=%s (require_fresh=%s)", relay_host, require_fresh)
    while True:
        now = time.monotonic()
        if now >= end:
            if (
                not grace_used and change_grace > 0 and candidate_changed_at > 0
                and now - candidate_changed_at <= change_grace
            ):
                grace_used = True
                end = deadline_after(change_grace, deadline)
                if end <= now:
                    break
                log.info("  [relay] 临近截止检测到接码内容切换，宽限 %.0fs", change_grace)
            else:
                break
        try:
            text = _read_relay(relay_url, remaining(end, 15))
            remaining(end)
        except DeadlineExceeded:
            break
        except Exception as e:
            log.debug("  [relay] poll err: %s", type(e).__name__)
            time.sleep(min(poll_interval, max(0.0, end - time.monotonic())))
            continue

        otp = _extract_otp(text)
        if require_fresh and not baseline_initialized:
            baseline_initialized = True
            with _RELAY_LAST_OTP_LOCK:
                has_claimed_code = relay_url in _RELAY_LAST_OTP
                if not has_claimed_code and otp:
                    _RELAY_LAST_OTP[relay_url] = otp
                    _RELAY_LAST_MESSAGE[relay_url] = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if not has_claimed_code:
                baseline_text = text
                baseline_otp = otp or ""
                time.sleep(min(poll_interval, max(0.0, end - time.monotonic())))
                continue
        marker = hashlib.sha256(otp.encode("ascii")).hexdigest()[:10] if otp else ""
        if last_candidate_marker is None:
            last_candidate_marker = marker
        elif marker != last_candidate_marker:
            last_candidate_marker = marker
            candidate_changed_at = time.monotonic()

        # 卖家接口常见的"暂无邮件"应答：跳过
        low = text.strip().lower()
        if not low or low.startswith(("no", "null", "wait", "empty", "{}", "[]", "false")):
            time.sleep(min(poll_interval, max(0.0, end - time.monotonic())))
            continue
        if text == last_text:
            time.sleep(min(poll_interval, max(0.0, end - time.monotonic())))
            continue
        last_text = text

        if not otp:
            time.sleep(min(poll_interval, max(0.0, end - time.monotonic())))
            continue

        otp_fp = hashlib.sha256(otp.encode("ascii")).hexdigest()[:10]
        message_fp = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if otp_fp != last_otp_fp:
            with _RELAY_LAST_OTP_LOCK:
                claimed = (
                    _RELAY_LAST_OTP.get(relay_url) == otp
                    and _RELAY_LAST_MESSAGE.get(relay_url) == message_fp
                )
            log.info("  [relay] 检测到 Logicc 候选验证码 excluded=%s claimed=%s",
                     otp in excluded_otps, claimed)
            last_otp_fp = otp_fp

        # Atomic claim prevents two concurrent flows sharing one mailbox URL
        # from submitting the same OTP.
        with _RELAY_LAST_OTP_LOCK:
            baseline_same_code = (
                bool(reject_same_code)
                and not allow_reuse
                and bool(_RELAY_LAST_OTP.get(relay_url))
                and _RELAY_LAST_OTP.get(relay_url) == otp
            )
            duplicate_claim = (not allow_reuse) and (
                otp in excluded_otps or (
                    _RELAY_LAST_OTP.get(relay_url) == otp
                    and _RELAY_LAST_MESSAGE.get(relay_url) == message_fp
                ) or baseline_same_code
            )
            if not duplicate_claim:
                _RELAY_LAST_OTP[relay_url] = otp
                _RELAY_LAST_MESSAGE[relay_url] = message_fp
        if duplicate_claim:
            log.debug("  [relay] 已用过 / 基线 OTP，等下一封")
            time.sleep(min(poll_interval, max(0.0, end - time.monotonic())))
            continue
        if allow_reuse and otp in excluded_otps:
            log.info("  [relay] 已获取受控复用 OTP（内容不写入日志）")
        else:
            log.info("  [relay] 已获取新 OTP（内容不写入日志）")
        return otp

    if baseline_otp:
        log.warning("  [relay] 等待新的 Logicc 验证码超时")
    else:
        log.warning(f"  [relay] {timeout}s 内没拿到 OTP")
    return ""
