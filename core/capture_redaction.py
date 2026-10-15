"""Redact authentication material before diagnostic HTTP snapshots touch disk."""
from __future__ import annotations

import html
import json
import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

MASK = "[REDACTED]"
SENSITIVE = re.compile(r"password|passwd|^pwd$|token|secret|cookie|authorization|api.?key|csrf|otp|email|username|phone|birth|nonce|state|ticket|sentinel|turnstile|oai.?did|device.?id|session|client.?id|login.?hint|recovery|credential|proof|^seed$|^name$", re.I)
SAFE_QUERY = {"prompt", "screen_hint", "response_type", "scope", "code_challenge_method", "locale"}


def private_field(key, value, parent=""):
    if SENSITIVE.search(str(key)):
        return True
    if str(key).lower() == "code":
        return not (parent == "error" and isinstance(value, str) and re.fullmatch(r"[a-z0-9_]{1,80}", value)) and value not in (0, 1, None)
    return False


class Redactor:
    def __init__(self):
        self.secrets = set()

    def remember(self, value):
        if isinstance(value, (dict, list, tuple)):
            for item in value.values() if isinstance(value, dict) else value:
                self.remember(item)
        if isinstance(value, (str, int)) and len(str(value)) >= 4:
            self.secrets.update({str(value), quote(str(value), safe=""), json.dumps(str(value))[1:-1]})

    def collect(self, value, parent=""):
        if isinstance(value, dict):
            for key, item in value.items():
                if private_field(key, item, parent):
                    self.remember(item)
                else:
                    self.collect(item, str(key).lower())
        elif isinstance(value, (list, tuple)):
            for item in value:
                self.collect(item, parent)

    def text(self, value):
        value = str(value)
        for secret in sorted(self.secrets.copy(), key=len, reverse=True):
            value = value.replace(secret, MASK)
        value = re.sub(r"https?://[^\s<>\"']+", lambda m: self.url(m[0]), value)
        value = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", MASK, value)
        value = re.sub(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+", MASK, value, flags=re.I)
        value = re.sub(r"(?i)(password|passwd|token|secret|csrf|otp|nonce|state|code)\s*[:=]\s*[\"']?[^\s\"'<>,;&]+", lambda m: m[1] + "=" + MASK, value)
        value = re.sub(r"\b\d{4,8}\b", MASK, value)
        value = re.sub(r"[A-Za-z0-9_.+/-]{24,}", lambda m: MASK if any(c.isdigit() or c.isupper() for c in m[0]) else m[0], value)
        return value

    def url(self, value):
        try:
            parsed = urlsplit(str(value))
            if parsed.scheme and parsed.scheme not in {"http", "https"}:
                return MASK
            host = parsed.hostname or ""
            if parsed.port:
                host += f":{parsed.port}"
            path = re.sub(r"[\w.+-]+@[\w.-]+", MASK, parsed.path)
            path = re.sub(r"(?<![a-zA-Z])\d{4,}(?![a-zA-Z])|[A-Za-z0-9_-]{24,}", MASK, path)
            query = []
            for key, item in parse_qsl(parsed.query, keep_blank_values=True):
                if key not in SAFE_QUERY:
                    self.remember(item)
                query.append((key, self.text(item) if key in SAFE_QUERY else MASK))
            return urlunsplit((parsed.scheme, host, path, urlencode(query), ""))
        except ValueError:
            return MASK

    def value(self, value, parent=""):
        if isinstance(value, dict):
            return {str(k): MASK if private_field(k, v, parent) else self.value(v, str(k).lower()) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.value(v, parent) for v in value]
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, (int, float, bool)) or value is None:
            if re.fullmatch(r"\d{4,8}", str(value)):
                return MASK
            return value
        return "[REDACTED:unsupported-object]"

    def headers(self, headers):
        headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
        for key, value in headers.items():
            if SENSITIVE.search(key):
                self.remember(value)
                if "authorization" in key and " " in value:
                    self.remember(value.split(" ", 1)[1])
                if "cookie" in key:
                    for pair in value.split(";"):
                        if "=" in pair:
                            self.remember(pair.split("=", 1)[1].strip())
        return {key: MASK if SENSITIVE.search(key) else self.url(value) if key in {"location", "referer", "content-location"}
                else self.text(value) for key, value in headers.items()}

    def body(self, content, mime="", *, mailbox=False):
        if content is None:
            return {"kind": "empty"}
        if mailbox:
            return {"kind": "redacted", "reason": "mailbox_message_contents"}
        if isinstance(content, (dict, list, tuple)):
            self.collect(content)
            return {"kind": "json", "content": self.value(content)}
        if not isinstance(content, (str, bytes, bytearray)):
            return {"kind": "unavailable", "reason": "stream_or_unsupported_body_not_consumed"}
        size = len(content.encode("utf-8")) if isinstance(content, str) else len(content)
        if size > 16 * 1024 * 1024:
            return {"kind": "omitted", "bytes": size, "reason": "body_over_16_mib"}
        try:
            text = content if isinstance(content, str) else bytes(content).decode("utf-8")
        except UnicodeDecodeError:
            return {"kind": "binary", "bytes": size, "reason": "binary_not_persisted"}
        try:
            value = json.loads(text)
        except (ValueError, TypeError):
            value = None
        if value is not None:
            self.collect(value)
            return {"kind": "json", "bytes": size, "content": self.value(value)}
        if "x-www-form-urlencoded" in mime:
            value = parse_qsl(text, keep_blank_values=True)
            for key, item in value:
                if private_field(key, item):
                    self.remember(item)
            return {"kind": "form", "bytes": size, "content": [[key, MASK if private_field(key, item) else self.text(item)] for key, item in value]}
        if "html" in mime or text.lstrip().startswith(("<!DOCTYPE", "<!doctype", "<html")):
            parser = RedactedHTML(self)
            parser.feed(text)
            parser.close()
            return {"kind": "html", "bytes": size, "content": "".join(parser.parts),
                    "redaction": "script_contents_and_input_values_removed"}
        if mime and not (mime.startswith("text/") or "json" in mime or "xml" in mime):
            return {"kind": "binary", "bytes": size, "reason": "non_text_content_type"}
        return {"kind": "text", "bytes": size, "content": self.text(text)}


class RedactedHTML(HTMLParser):
    def __init__(self, redactor):
        super().__init__(convert_charrefs=True)
        self.redactor = redactor
        self.parts = []
        self.hidden_tag = None

    def handle_starttag(self, tag, attrs):
        if self.hidden_tag:
            return
        if tag in {"script", "style"}:
            self.hidden_tag = tag
            self.parts.append(f"<{tag}>[REDACTED:inline-content]")
            return
        safe = []
        for key, value in attrs:
            if value is None:
                safe.append(key)
                continue
            value = MASK if key in {"value", "content", "style"} or key.startswith(("data-", "on")) or SENSITIVE.search(key) else self.redactor.url(value) if key in {"href", "src", "action"} else self.redactor.text(value)
            safe.append(f'{key}="{html.escape(value, quote=True)}"')
        self.parts.append("<" + tag + (" " + " ".join(safe) if safe else "") + ">")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if self.hidden_tag and self.hidden_tag != tag:
            return
        if self.hidden_tag == tag:
            self.hidden_tag = None
        self.parts.append(f"</{tag}>")

    def handle_data(self, data):
        if not self.hidden_tag:
            self.parts.append(html.escape(self.redactor.text(data)))

    def handle_decl(self, decl):
        self.parts.append("<!DOCTYPE html>")
