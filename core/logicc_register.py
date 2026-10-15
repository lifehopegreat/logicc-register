"""One-account Logicc HTTP signup, based on the workspace capture.

No browser, captured credentials, or automatic mutation retry.
Private checkpoints include the current cookies/password and are always encrypted.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.cookiejar
import json
import logging
import math
import os
import re
import secrets
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.fernet import Fernet, InvalidToken

from account_vault import AccountVault, _validate_email, get_account_vault
from email_provider import fetch_otp, mark_relay_baseline, _RELAY_LAST_OTP, _RELAY_LAST_MESSAGE
from protocol_budget import MailboxTimeout
from capmonster import CapMonster, CapMonsterError
from logicc2api import Logicc2Api

APP_ORIGIN = "https://app.logicc.com"
CLERK_ORIGIN = "https://clerk.logicc.com"
API_QUERY = {"__clerk_api_version": "2026-05-12", "_clerk_js_version": "6.39.0"}
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
WAITING = {"human_required", "code_required", "needs_check", "rate_limited", "partial"}
SAFE_REMOTE_CODES = {
    "form_identifier_exists", "form_password_pwned", "form_password_length_too_short",
    "form_code_incorrect", "form_code_expired", "verification_failed", "session_invalid",
    "form_param_format_invalid", "form_param_missing", "captcha_invalid", "captcha_expired",
    "captcha_missing", "captcha_unavailable", "captcha_invalid_token", "rate_limit_exceeded",
    "phone_verification_required", "session_task_not_completed",
}
log = logging.getLogger("logicc_protocol")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def generated_config(email, *, accept_terms, proxy="", onboard=True):
    _validate_email(email)
    if accept_terms is not True:
        raise ValueError("accept_terms must be true")
    return {
        "email": email.strip().casefold(), "accept_terms": True, "proxy": proxy,
        "first_name": secrets.choice(("Alex", "Jamie", "Taylor", "Jordan")),
        "last_name": secrets.choice(("Lee", "Chen", "Miller", "Morgan")),
        "company_name": "Workspace " + secrets.token_hex(4),
        # These two enum values were observed in the captured successful request.
        "industry": "healthcare", "size": "extra-large", "language": "de",
        "locale": "zh-CN", "timezone": "Asia/Shanghai", "onboard": bool(onboard),
        "password": "Lc!" + secrets.token_urlsafe(24) + "aA9",
        "otp_timeout": 180, "user_agent": USER_AGENT,
    }


def save_private(path, key, payload):
    encrypted = Fernet(key).encrypt(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    AccountVault._atomic_write(Path(path), encrypted, mode=0o600)


def load_private(path, key):
    try:
        payload = json.loads(Fernet(key).decrypt(Path(path).read_bytes()))
    except (InvalidToken, ValueError, OSError) as exc:
        raise ValueError("private checkpoint unavailable or invalid") from exc
    if not isinstance(payload, dict):
        raise ValueError("invalid private checkpoint")
    return payload


class ProtocolStop(Exception):
    def __init__(self, status, code, *, http_status=0, retry_after=0):
        super().__init__(code)
        self.status, self.code = status, code
        self.http_status, self.retry_after = http_status, retry_after


class LogiccRegistration:
    def __init__(self, config, *, state_path, key, vault, transport=None, captcha_solver=None):
        self.config = dict(config)
        _validate_email(self.config.get("email", ""))
        if self.config.get("accept_terms") is not True:
            raise ValueError("accept_terms must be true")
        for name in ("password", "first_name", "last_name", "company_name"):
            value = self.config.get(name)
            if not isinstance(value, str) or not value or len(value) > 256 or any(c in value for c in "\r\n"):
                raise ValueError("invalid registration profile")
        if len(self.config["password"]) < 12:
            raise ValueError("registration password too short")
        self.config["email"] = self.config["email"].casefold()
        self.state_path, self.key, self.vault = Path(state_path), key, vault
        self.captcha_solver = captcha_solver
        self.state = load_private(state_path, key) if self.state_path.exists() else {
            "email": self.config["email"], "config": self.config, "done": [],
            "created_at": utc_now(), "status": "new", "step": "new",
            "send_count": 0, "verify_count": 0, "excluded_codes": [],
        }
        if self.state.get("email") != self.config["email"] or self.state.get("config") != self.config:
            raise ValueError("checkpoint identity or profile mismatch")
        self.client = httpx.Client(
            timeout=25, follow_redirects=False, trust_env=False,
            proxy=self.config.get("proxy") or None, transport=transport,
            headers={"User-Agent": self.config["user_agent"], "Accept": "application/json",
                     "Origin": APP_ORIGIN, "Referer": APP_ORIGIN + "/"},
        )
        for cookie in self.state.get("cookies", []):
            if cookie.get("domain", "").lstrip(".") not in {"logicc.com", "app.logicc.com", "clerk.logicc.com"}:
                raise ValueError("checkpoint contains unrelated cookies")
            self.client.cookies.jar.set_cookie(http.cookiejar.Cookie(
                version=0, name=cookie["name"], value=cookie["value"],
                port=None, port_specified=False, domain=cookie["domain"],
                domain_specified=cookie.get("domain_specified", True),
                domain_initial_dot=cookie["domain"].startswith("."),
                path=cookie["path"], path_specified=True, secure=cookie["secure"],
                expires=cookie.get("expires"), discard=cookie.get("expires") is None,
                comment=None, comment_url=None, rest={}, rfc2109=False,
            ))

    def close(self):
        self.client.close()

    def checkpoint(self):
        self.state["cookies"] = [{
            "name": c.name, "value": c.value, "domain": c.domain, "path": c.path,
            "secure": c.secure, "expires": c.expires, "domain_specified": c.domain_specified,
        } for c in self.client.cookies.jar]
        save_private(self.state_path, self.key, self.state)

    def complete_step(self, step, **updates):
        self.state.update(updates)
        if step not in self.state["done"]:
            self.state["done"].append(step)
        self.state.pop("inflight", None)
        self.checkpoint()

    def request(self, step, method, path, *, clerk=True, data=None, payload=None, params=None):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("invalid endpoint path")
        origin = CLERK_ORIGIN if clerk else APP_ORIGIN
        query = {**API_QUERY, **(params or {})} if clerk else (params or {})
        headers = {}
        if not clerk and self.state.get("jwt"):
            self.ensure_token()
            headers["Authorization"] = "Bearer " + self.state["jwt"]
            headers["Referer"] = APP_ORIGIN + "/onboarding"
        self.state["step"] = step
        if method != "GET":
            self.state["inflight"] = {"step": step, "started_at": time.time()}
        self.checkpoint()
        started = time.monotonic()
        try:
            response = self.client.request(method, origin + path, params=query, data=data,
                                           json=payload, headers=headers)
        except httpx.RequestError:
            status = "needs_check" if method != "GET" else "partial"
            raise ProtocolStop(status, "network_result_unknown" if method != "GET" else "network_unavailable")
        finally:
            # IDs, queries, headers, bodies and exception messages are deliberately absent.
            safe_path = re.sub(r"/(?:sua|sess)_[^/]+", "/{id}", path)
            log.info(json.dumps({"step": step, "method": method, "path": safe_path,
                                "latency_ms": round((time.monotonic() - started) * 1000)}))
        code = response.status_code
        log.info(json.dumps({"step": step, "http_status": code}))
        try:
            value = response.json() if response.content else None
        except ValueError:
            value = None
        if 300 <= code < 400:
            raise ProtocolStop("needs_check" if method != "GET" else "human_required", "unexpected_redirect", http_status=code)
        if code == 429:
            self.state.pop("inflight", None)
            try:
                wait = max(1, min(float(response.headers.get("Retry-After", "60")), 86400))
            except ValueError:
                wait = 60
            raise ProtocolStop("rate_limited", "rate_limit_exceeded", http_status=code, retry_after=wait)
        if code >= 500:
            raise ProtocolStop("needs_check" if method != "GET" else "partial", "upstream_unavailable", http_status=code)
        if code >= 400:
            # A successful HTML challenge is not a JSON API response either.
            self.state.pop("inflight", None)
            errors = value.get("errors", []) if isinstance(value, dict) else []
            raw = errors[0].get("code") if errors and isinstance(errors[0], dict) else ""
            error = raw if raw in SAFE_REMOTE_CODES else "remote_request_rejected"
            status = "failed"
            if "captcha" in str(raw) or (code == 403 and value is None):
                status, error = "human_required", "captcha_required"
            elif error in {"form_code_incorrect", "form_code_expired", "verification_failed"}:
                status = "code_required"
            elif error in {"phone_verification_required", "session_task_not_completed"}:
                status = "human_required"
            raise ProtocolStop(status, error, http_status=code)
        if step != "open_register" and value is None and response.content and "text/html" in response.headers.get("content-type", ""):
            raise ProtocolStop("human_required", "html_challenge", http_status=code)
        return value

    @staticmethod
    def object(value):
        result = value.get("response", value) if isinstance(value, dict) else None
        if not isinstance(result, dict):
            raise ProtocolStop("needs_check", "unexpected_response_contract")
        return result

    def bootstrap(self):
        self.request("open_register", "GET", "/register", clerk=False)
        env = self.object(self.request("environment", "GET", "/v1/environment"))
        client = self.object(self.request("client", "GET", "/v1/client"))
        if client.get("sessions") or client.get("sign_up"):
            raise ProtocolStop("needs_check", "fresh_client_not_empty")
        sign_up = env.get("user_settings", {}).get("sign_up", {})
        if sign_up.get("mode") not in {None, "public"}:
            raise ProtocolStop("failed", "sign_up_not_public")
        self.complete_step("bootstrap", captcha_required=bool(sign_up.get("captcha_enabled")) and not client.get("captcha_bypass"),
                           captcha_provider=env.get("display_config", {}).get("captcha_provider"),
                           captcha_site_key=env.get("display_config", {}).get("captcha_public_key"),
                           captcha_widget_type=env.get("display_config", {}).get("captcha_widget_type", "smart"),
                           client_created=True)

    def adopt_signup(self, signup):
        identifier = signup.get("id", "")
        if not re.fullmatch(r"sua_[A-Za-z0-9]+", identifier):
            raise ProtocolStop("needs_check", "signup_id_missing")
        if str(signup.get("email_address", "")).casefold() != self.config["email"]:
            raise ProtocolStop("needs_check", "signup_identity_mismatch")
        self.state["signup_id"] = identifier
        self.state["signup_status"] = signup.get("status")
        self.state["verification_expires_at"] = signup.get("verifications", {}).get("email_address", {}) or {}
        if signup.get("missing_fields"):
            raise ProtocolStop("partial", "signup_missing_fields")
        if signup.get("status") == "complete":
            if (signup.get("verifications", {}).get("email_address") or {}).get("status") != "verified":
                raise ProtocolStop("needs_check", "email_not_verified")
            self.state["session_id"] = signup.get("created_session_id")
            self.state["clerk_user_id"] = signup.get("created_user_id")
            if not self.state["session_id"] or not self.state["clerk_user_id"]:
                raise ProtocolStop("needs_check", "completed_signup_missing_session")
            self.complete_step("verify", registration_created=True)

    def create_signup(self, captcha_token=""):
        self.state["step"] = "captcha"
        if not isinstance(captcha_token, str) or len(captcha_token) > 2048:
            raise ProtocolStop("human_required", "invalid_captcha_input")
        if self.state.get("captcha_required") and not captcha_token and self.captcha_solver:
            if self.state.get("captcha_provider") != "turnstile":
                raise ProtocolStop("human_required", "unsupported_captcha_provider")
            self.state["step"] = "solve_captcha"
            try:
                captcha_token = self.captcha_solver.solve_turnstile(
                    site_key=self.state.get("captcha_site_key"), website_url=APP_ORIGIN + "/register",
                    user_agent=self.config["user_agent"], proxy=self.config.get("proxy", ""),
                    receipt=self.state.setdefault("captcha_task", {}), checkpoint=self.checkpoint)
            except CapMonsterError as exc:
                # Re-query a known task on explicit resume; never create another automatically.
                if str(exc) not in {"capmonster_response_unavailable", "capmonster_poll_timeout"}:
                    self.state["captcha_task"]["status"] = "failed"
                raise ProtocolStop("human_required", str(exc)) from None
        if self.state.get("captcha_required") and not captcha_token:
            raise ProtocolStop("human_required", "captcha_required")
        if captcha_token:
            fingerprint = hashlib.sha256(captcha_token.encode()).hexdigest()
            if fingerprint in self.state.get("used_captcha", []):
                raise ProtocolStop("human_required", "captcha_already_consumed")
            self.state.setdefault("used_captcha", []).append(fingerprint)
        cfg = self.config
        form = {
            "email_address": cfg["email"], "password": cfg["password"],
            "first_name": cfg["first_name"], "last_name": cfg["last_name"],
            "legal_accepted": "true", "locale": cfg["locale"], "timezone": cfg["timezone"],
            "unsafe_metadata": json.dumps({"nameSource": "email_fallback", "needsNameCompletion": True,
                                          "termsAcceptedAt": utc_now()}, separators=(",", ":")),
        }
        if captcha_token:
            form.update(captcha_token=captcha_token, captcha_widget_type=self.state.get("captcha_widget_type", "smart"))
        signup = self.object(self.request("create_signup", "POST", "/v1/client/sign_ups", data=form))
        self.adopt_signup(signup)
        self.complete_step("create_signup")

    def mailbox(self):
        account = self.vault.get_account(self.config["email"])
        if not account.has_otp_creds or not account.token_valid:
            raise ProtocolStop("partial", "mailbox_credentials_unavailable")
        return account

    def send_code(self):
        if self.state["send_count"] >= 2:
            raise ProtocolStop("code_required", "resend_limit_reached")
        account = self.mailbox()
        relay = account.relay_url if account.kind == "icloud" else account.refresh_token
        if relay.startswith(("https://", "http://")):
            if not mark_relay_baseline(relay):
                raise ProtocolStop("partial", "mailbox_baseline_unavailable")
            self.state["relay_baseline"] = {"otp": _RELAY_LAST_OTP.get(relay, ""),
                                            "message": _RELAY_LAST_MESSAGE.get(relay, "")}
        self.state["sent_at"] = time.time()
        self.state["send_count"] += 1
        signup = self.object(self.request("send_code", "POST",
            f"/v1/client/sign_ups/{self.state['signup_id']}/prepare_verification", data={"strategy": "email_code"}))
        self.adopt_signup(signup)
        verification = signup.get("verifications", {}).get("email_address") or {}
        if verification.get("strategy") != "email_code":
            raise ProtocolStop("needs_check", "email_verification_not_prepared")
        self.complete_step("send_code")

    def verify(self, code=""):
        self.state["step"] = "wait_code"
        self.checkpoint()
        if self.state["verify_count"] >= 3:
            raise ProtocolStop("code_required", "verification_attempt_limit")
        if not code:
            account = self.mailbox()
            relay = account.relay_url if account.kind == "icloud" else account.refresh_token
            if self.state.get("relay_baseline"):
                baseline = self.state["relay_baseline"]
                _RELAY_LAST_OTP[relay] = baseline["otp"]
                _RELAY_LAST_MESSAGE[relay] = baseline["message"]
            try:
                code = fetch_otp(account.email, relay, account.client_id,
                    method="relay" if account.kind == "icloud" else "graph",
                    password=account.password, timeout=self.config["otp_timeout"],
                    after_ts=self.state["sent_at"], excluded_otps=set(self.state["excluded_codes"]),
                    relay_require_fresh=True, relay_reject_same_code=True)
            except MailboxTimeout:
                raise ProtocolStop("code_required", "mailbox_timeout")
            except Exception as exc:
                raise ProtocolStop("code_required", "mailbox_unavailable") from exc
        if not isinstance(code, str) or not re.fullmatch(r"\d{6}", code):
            raise ProtocolStop("code_required", "verification_code_unavailable")
        if code in self.state["excluded_codes"]:
            raise ProtocolStop("code_required", "verification_code_already_used")
        self.state["excluded_codes"].append(code)
        self.state["verify_count"] += 1
        signup = self.object(self.request("verify", "POST",
            f"/v1/client/sign_ups/{self.state['signup_id']}/attempt_verification",
            data={"strategy": "email_code", "code": code}))
        self.adopt_signup(signup)
        if signup.get("status") != "complete":
            raise ProtocolStop("partial", "signup_not_complete")
        if (signup.get("verifications", {}).get("email_address") or {}).get("status") != "verified":
            raise ProtocolStop("needs_check", "email_not_verified")
        self.complete_step("verify", registration_created=True)

    def check_session(self, session):
        if session.get("id") != self.state.get("session_id") or session.get("status") != "active":
            raise ProtocolStop("human_required", "session_not_active")
        user = session.get("user") or {}
        emails = user.get("email_addresses") or []
        if user.get("id") != self.state.get("clerk_user_id") or not any(
            str(e.get("email_address", "")).casefold() == self.config["email"]
            and (e.get("verification") or {}).get("status") == "verified" for e in emails
        ):
            raise ProtocolStop("needs_check", "session_identity_mismatch")

    def use_token(self, jwt):
        try:
            claims = json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "==="))
            if claims.get("sub") != self.state["clerk_user_id"] or claims.get("sid") != self.state["session_id"]:
                raise ValueError
            expiry = float(claims["exp"])
            if not math.isfinite(expiry) or expiry <= time.time():
                raise ValueError
        except (AttributeError, IndexError, TypeError, ValueError, KeyError):
            raise ProtocolStop("needs_check", "session_token_contract_invalid")
        # Claim checks are not signature verification; the live /me call is the oracle.
        self.state["jwt"], self.state["jwt_expires_at"] = jwt, expiry
        self.client.cookies.jar.set_cookie(http.cookiejar.Cookie(
            version=0, name="__session", value=jwt, port=None, port_specified=False,
            domain="app.logicc.com", domain_specified=True, domain_initial_dot=False,
            path="/", path_specified=True, secure=True, expires=int(expiry), discard=False,
            comment=None, comment_url=None, rest={"HttpOnly": None}, rfc2109=False,
        ))

    def touch(self, *, organization_id=""):
        session = self.object(self.request("activate_org" if organization_id else "activate_session",
            "POST", f"/v1/client/sessions/{self.state['session_id']}/touch",
            data={"active_organization_id": organization_id,
                  "intent": "select_org" if organization_id else "select_session"}))
        self.check_session(session)
        if organization_id and session.get("last_active_organization_id") != organization_id:
            raise ProtocolStop("needs_check", "organization_not_active")
        self.use_token((session.get("last_active_token") or {}).get("jwt"))
        self.complete_step("activate_org" if organization_id else "activate_session")

    def ensure_token(self):
        if float(self.state.get("jwt_expires_at", 0)) > time.time() + 10:
            return
        value = self.object(self.request("refresh_token", "POST",
            f"/v1/client/sessions/{self.state['session_id']}/tokens",
            data={"organization_id": self.state.get("organization_id", ""),
                  "tab_state": "focused", "token": self.state.get("jwt", ""), "force_origin": "true"}))
        self.use_token(value.get("jwt"))
        self.complete_step("refresh_token")

    def confirm_account(self):
        me = self.object(self.request("confirm_account", "GET", "/api/users/me", clerk=False))
        if not isinstance(me.get("userId"), str) or not me["userId"]:
            raise ProtocolStop("needs_check", "application_user_missing")
        if self.state.get("app_user_id") and self.state["app_user_id"] != me["userId"]:
            raise ProtocolStop("needs_check", "application_identity_changed")
        self.complete_step("confirm_account", app_user_id=me["userId"], registration_ok=True)

    def onboard(self):
        cfg, sid = self.config, self.state["session_id"]
        if "language" not in self.state["done"]:
            self.request("language", "PATCH", "/api/users", clerk=False, payload={"language": cfg["language"]})
            self.complete_step("language")
        if "profile" not in self.state["done"]:
            self.request("profile", "POST", "/v1/me", params={"_method": "PATCH", "_clerk_session_id": sid},
                         data={"first_name": cfg["first_name"], "last_name": cfg["last_name"]})
            self.complete_step("profile")
        if "metadata" not in self.state["done"]:
            self.request("metadata", "POST", "/v1/me/metadata", params={"_method": "PATCH", "_clerk_session_id": sid},
                         data={"unsafe_metadata": json.dumps({"nameSource": "user_input", "needsNameCompletion": False})})
            self.complete_step("metadata")
        if "create_tenant" not in self.state["done"]:
            org = self.request("create_tenant", "POST", "/api/tenants", clerk=False,
                              payload={"industry": cfg["industry"], "size": cfg["size"],
                                       "name": cfg["company_name"], "lastAdAttribution": None})
            if not isinstance(org, str) or not re.fullmatch(r"org_[A-Za-z0-9]+", org):
                raise ProtocolStop("needs_check", "tenant_response_not_organization_id")
            self.complete_step("create_tenant", organization_id=org)
        if "activate_org" not in self.state["done"]:
            memberships = self.object(self.request("memberships", "GET", "/v1/me/organization_memberships",
                params={"paginated": "true", "limit": "20", "offset": "0", "_clerk_session_id": sid}))
            if not any((m.get("organization") or {}).get("id") == self.state["organization_id"]
                       for m in memberships.get("data", [])):
                raise ProtocolStop("needs_check", "organization_membership_missing")
            self.touch(organization_id=self.state["organization_id"])
        self.ensure_token()
        me = self.object(self.request("confirm_tenant", "GET", "/api/users/me", clerk=False))
        if me.get("userId") != self.state.get("app_user_id") or not me.get("tenantId"):
            raise ProtocolStop("needs_check", "tenant_identity_unconfirmed")
        self.complete_step("confirm_tenant", tenant_id=me["tenantId"], onboarding_ok=True)

    def reconcile(self):
        """Resolve ambiguous signup/verification; never blindly resend a mutation."""
        pending = self.state.get("inflight")
        if not pending:
            return
        step = pending["step"]
        client = self.object(self.request("reconcile_client", "GET", "/v1/client"))
        if self.state.get("session_id"):
            session = next((s for s in client.get("sessions", []) if s.get("id") == self.state["session_id"]), None)
            if session is None:
                raise ProtocolStop("human_required", "session_context_unavailable")
            self.check_session(session)
        signup = client.get("sign_up") or {}
        if step in {"create_signup", "send_code", "verify"}:
            if signup and str(signup.get("email_address", "")).casefold() == self.config["email"]:
                self.adopt_signup(signup)
                if step == "create_signup":
                    self.complete_step(step)
                    return
                if step == "send_code" and (signup.get("verifications", {}).get("email_address") or {}).get("expire_at"):
                    self.complete_step(step)
                    return
                if "verify" in self.state["done"]:
                    return
            for session in client.get("sessions", []):
                user = session.get("user") or {}
                if any(str(e.get("email_address", "")).casefold() == self.config["email"]
                       and (e.get("verification") or {}).get("status") == "verified"
                       for e in user.get("email_addresses", [])):
                    self.state.update(session_id=session.get("id"), clerk_user_id=user.get("id"))
                    self.check_session(session)
                    self.complete_step("create_signup")
                    self.complete_step("verify", registration_created=True)
                    return
        elif step == "create_tenant" and self.state.get("session_id"):
            memberships = self.object(self.request("reconcile_tenant", "GET", "/v1/me/organization_memberships",
                params={"paginated": "true", "limit": "20", "offset": "0",
                        "_clerk_session_id": self.state["session_id"]}))
            matches = [m["organization"]["id"] for m in memberships.get("data", [])
                       if (m.get("organization") or {}).get("name") == self.config["company_name"]]
            if len(matches) == 1:
                self.complete_step("create_tenant", organization_id=matches[0])
                return
        elif step in {"activate_session", "activate_org", "refresh_token"}:
            for session in client.get("sessions", []):
                if session.get("id") == self.state.get("session_id"):
                    self.check_session(session)
                    if step == "activate_org" and session.get("last_active_organization_id") != self.state.get("organization_id"):
                        break
                    self.use_token((session.get("last_active_token") or {}).get("jwt"))
                    self.complete_step(step)
                    return
        raise ProtocolStop("needs_check", "mutation_not_reconciled")

    def run(self, *, captcha_token="", code="", resend=False):
        try:
            wait_until = float(self.state.get("retry_not_before", 0))
            if time.time() < wait_until:
                raise ProtocolStop("rate_limited", "cooldown_active", retry_after=wait_until-time.time())
            self.reconcile()
            if "bootstrap" not in self.state["done"]:
                self.bootstrap()
            if "create_signup" not in self.state["done"]:
                self.create_signup(captcha_token)
            if "verify" not in self.state["done"]:
                if resend:
                    if "send_code" in self.state["done"]:
                        self.state["done"].remove("send_code")
                if "send_code" not in self.state["done"]:
                    if "pending_language" not in self.state["done"]:
                        self.request("pending_language", "POST", "/api/users/pending-signup-language",
                                     clerk=False, payload={"email": self.config["email"], "language": self.config["language"]})
                        self.complete_step("pending_language")
                    self.send_code()
                self.verify(code)
            if "activate_session" not in self.state["done"]:
                self.touch()
            self.confirm_account()
            if self.config.get("onboard", True):
                self.onboard()
            self.state.update(status="success", step="confirmed", error="", confirmed_at=utc_now())
        except ProtocolStop as exc:
            status = "partial" if self.state.get("registration_ok") and exc.status == "failed" else exc.status
            self.state.update(status=status, error=exc.code, http_status=exc.http_status)
            if exc.retry_after:
                self.state["retry_not_before"] = time.time() + exc.retry_after
        except Exception:
            self.state.update(status="needs_check" if self.state.get("inflight") else "partial",
                              error="local_dependency_error")
        self.checkpoint()
        return self.public_result()

    def public_result(self):
        state = self.state
        return {
            "email": self.config["email"], "ok": state["status"] == "success", "method": "protocol",
            "status": state["status"], "step": state["step"], "error": state.get("error", ""),
            "registration_ok": bool(state.get("registration_ok")), "onboarding_ok": bool(state.get("onboarding_ok")),
            "registered_at": state.get("confirmed_at", ""), "clerk_user_id": state.get("clerk_user_id", ""),
            "app_user_id": state.get("app_user_id", ""), "organization_id": state.get("organization_id", ""),
            "tenant_id": state.get("tenant_id", ""), "captcha_provider": state.get("captcha_provider"),
            "retry_not_before": state.get("retry_not_before", 0),
            "proxy_region": self.config.get("proxy_region", "DIRECT"),
            **Logicc2Api.public_receipt(state),
        }


def main():
    parser = argparse.ArgumentParser(description="Logicc one-account pure HTTP registration")
    parser.add_argument("--email")
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--accept-terms", action="store_true")
    parser.add_argument("--input", help="Encrypted console job input")
    parser.add_argument("--out", help="Public result JSONL (no secrets)")
    parser.add_argument("--captcha-file", help="Private JSON containing a fresh legitimate captcha_token")
    parser.add_argument("--code-file", help="Private file containing one fresh six-digit Logicc code")
    parser.add_argument("--resend-code", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)
    # HTTP libraries must never log full request query/headers or mailbox payloads.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    root = Path(__file__).resolve().parent.parent
    data = Path(os.environ.get("LOGICC_CONSOLE_DATA_DIR") or root / "data").resolve()
    os.environ.setdefault("ACCOUNT_VAULT_DIR", str(data / "account_vault"))
    vault = get_account_vault()
    key = vault.key_path.read_bytes().strip()
    if args.input:
        job = load_private(Path(args.input), key)
        run_id, config = job["run_id"], job["config"]
        proof, manual_code = job.pop("captcha_token", ""), job.pop("code", "")
        resend = bool(job.pop("resend_code", False))
        # Consume handoff secrets before making any remote request.
        save_private(Path(args.input), key, job)
    else:
        run_id = args.run_id or uuid.uuid4().hex
        state_path = data / "registrations" / (run_id + ".state.enc")
        if state_path.exists():
            config = load_private(state_path, key)["config"]
            if args.email and args.email.casefold() != config["email"]:
                raise ValueError("resume email mismatch")
        else:
            if not args.email:
                parser.error("--email is required for a new run")
            config = generated_config(args.email, accept_terms=args.accept_terms)
        proof = json.loads(Path(args.captcha_file).read_text(encoding="utf-8")).get("captcha_token", "") if args.captcha_file else ""
        manual_code = Path(args.code_file).read_text(encoding="utf-8").strip() if args.code_file else ""
        resend = args.resend_code
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise ValueError("invalid run ID")
    vault.get_account(config["email"])
    service_path = data / "services" / "capmonster.enc"
    service = load_private(service_path, key) if service_path.exists() else {}
    solver = CapMonster(service["client_key"]) if service.get("enabled", True) and service.get("client_key") else None
    registration = LogiccRegistration(config, state_path=data / "registrations" / (run_id + ".state.enc"),
                                      key=key, vault=vault, captcha_solver=solver)
    try:
        result = registration.run(captcha_token=proof, code=manual_code, resend=resend)
        integration_path = data / "services" / "logicc2api.enc"
        if result["registration_ok"] and result["onboarding_ok"] and integration_path.exists():
            try:
                integration = load_private(integration_path, key)
                if integration.get("enabled") is True:
                    connector = Logicc2Api(integration["base_url"])
                    try:
                        result.update(connector.handoff(registration.state, registration.checkpoint))
                    finally:
                        connector.close()
            except (ValueError, KeyError, OSError):
                result.update(integration_status="failed", integration_error="integration_config_invalid")
            except Exception:
                # A local connector fault must not erase a remotely confirmed registration.
                result.update(integration_status="failed", integration_error="integration_local_error")
    finally:
        registration.close()
        if solver:
            solver.close()
    result["run_id"] = run_id
    if args.out:
        AccountVault._atomic_write(Path(args.out), (json.dumps(result, ensure_ascii=False) + "\n").encode(), mode=0o600)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["ok"] else 2 if result["status"] in WAITING else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print(json.dumps({"ok": False, "status": "failed", "error": "invalid_local_input"}))
        sys.exit(1)
