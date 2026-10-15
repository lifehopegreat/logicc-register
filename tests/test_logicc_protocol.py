import base64
import json
import logging
import time
from collections import Counter
from urllib.parse import parse_qs

import httpx
import pytest

import logicc_register as module
from account_vault import AccountVault


def fake_jwt(expiry=None, *, user="user_test", session="sess_test"):
    claims = {"sub": user, "sid": session, "exp": expiry or time.time() + 60}
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return "fixture." + payload + ".fixture"


class FakeAPI:
    """Synthetic contracts, not captured identities or proof of live registration."""
    def __init__(self, *, captcha=False):
        self.captcha = captcha
        self.calls = []
        self.counts = Counter()
        self.signup = None
        self.user = None
        self.org = ""
        self.active_org = ""
        self.jwt = fake_jwt()
        self.hook = None

    def session(self):
        return {"id": "sess_test", "status": "active", "last_active_organization_id": self.active_org,
                "last_active_token": {"jwt": self.jwt},
                "user": {"id": "user_test", "email_addresses": [{"email_address": "owner@example.test",
                    "verification": {"status": "verified"}}]}}

    def client(self):
        return {"sessions": [self.session()] if self.user else [],
                "sign_up": self.signup if not self.user else None, "captcha_bypass": False}

    def handle(self, request):
        path = request.url.path
        form = {k: v[0] for k, v in parse_qs(request.content.decode(), keep_blank_values=True).items()}
        if request.headers.get("content-type", "").startswith("application/json"):
            form = json.loads(request.content) if request.content else {}
        self.calls.append((request.method, path, form, request))
        self.counts[(request.method, path)] += 1
        if self.hook:
            intercepted = self.hook(request, form)
            if intercepted is not None:
                return intercepted
        if request.url.host == "clerk.logicc.com":
            assert request.url.params["__clerk_api_version"] == "2026-05-12"
            assert request.url.params["_clerk_js_version"] == "6.39.0"
            assert request.headers["Origin"] == module.APP_ORIGIN
        if path == "/register":
            return httpx.Response(200, text="<html><title>Register</title></html>",
                                  headers={"content-type": "text/html"})
        if path == "/v1/environment":
            return httpx.Response(200, json={"user_settings": {"sign_up": {"mode": "public", "captcha_enabled": self.captcha}},
                                            "display_config": {"captcha_provider": "turnstile",
                                                               "captcha_public_key": "0xfixtureSiteKey123",
                                                               "captcha_widget_type": "smart"}})
        if path == "/v1/client":
            return httpx.Response(200, json={"response": self.client()},
                                  headers={"set-cookie": "__client=private-client-cookie; Path=/; Secure; HttpOnly"})
        if path == "/v1/client/sign_ups":
            assert request.headers.get("cookie", "").find("__client=private-client-cookie") >= 0
            assert form["legal_accepted"] == "true"
            assert json.loads(form["unsafe_metadata"])["needsNameCompletion"] is True
            self.signup = {"id": "sua_test", "email_address": form["email_address"],
                           "status": "missing_requirements", "missing_fields": [],
                           "verifications": {"email_address": None}}
            return httpx.Response(200, json={"response": self.signup})
        if path.endswith("/prepare_verification"):
            assert form == {"strategy": "email_code"}
            self.signup["verifications"]["email_address"] = {"strategy": "email_code", "status": "unverified",
                                                            "expire_at": int(time.time() * 1000) + 600000}
            return httpx.Response(200, json={"response": self.signup})
        if path.endswith("/attempt_verification"):
            assert form == {"strategy": "email_code", "code": "123456"}
            self.signup.update(status="complete", created_session_id="sess_test", created_user_id="user_test",
                               verifications={"email_address": {"strategy": "email_code", "status": "verified"}})
            self.user = "user_test"
            return httpx.Response(200, json={"response": self.signup, "client": self.client()})
        if path.endswith("/touch"):
            self.active_org = form["active_organization_id"]
            assert form["intent"] == ("select_org" if self.active_org else "select_session")
            return httpx.Response(200, json={"response": self.session()})
        if path.endswith("/tokens"):
            assert form["organization_id"] == self.org
            self.jwt = fake_jwt()
            return httpx.Response(200, json={"object": "token", "jwt": self.jwt})
        if path == "/api/users/me":
            assert request.headers["Authorization"] == "Bearer " + self.jwt
            assert "__session=" in request.headers["Cookie"]
            value = {"userId": "application_test"}
            if self.active_org:
                value["tenantId"] = "tenant_test"
            return httpx.Response(200, json=value)
        if path in {"/v1/me", "/v1/me/metadata"}:
            assert request.url.params["_method"] == "PATCH"
            assert request.url.params["_clerk_session_id"] == "sess_test"
            return httpx.Response(200, json={"response": {"id": "user_test"}})
        if path == "/api/tenants":
            assert set(form) == {"industry", "size", "name", "lastAdAttribution"}
            assert form["lastAdAttribution"] is None
            self.company = form["name"]
            self.org = "org_test"
            return httpx.Response(200, json=self.org)
        if path == "/v1/me/organization_memberships":
            value = [{"organization": {"id": self.org, "name": self.company}}] if self.org else []
            return httpx.Response(200, json={"response": {"data": value}})
        if path in {"/api/users", "/api/users/pending-signup-language"}:
            return httpx.Response(204)
        raise AssertionError("Unexpected endpoint: " + path)


@pytest.fixture
def setup(tmp_path, monkeypatch):
    vault = AccountVault(data_dir=tmp_path / "vault", outlook_file=tmp_path / "outlook",
                         icloud_file=tmp_path / "relay")
    vault.import_text("owner@example.test----mail-private----client-private----refresh-private")
    config = module.generated_config("owner@example.test", accept_terms=True)
    config["password"] = "Lc!private-registration-password-aA9"
    key = vault.key_path.read_bytes().strip()
    path = tmp_path / "registration.enc"
    monkeypatch.setattr(module, "fetch_otp", lambda *a, **kw: "123456")

    def factory(api, cfg=None):
        return module.LogiccRegistration(cfg or config, state_path=path, key=key,
                                         vault=vault, transport=httpx.MockTransport(api.handle))
    return factory, path, key, config, vault


def test_complete_http_flow_and_namespace_separation(setup, caplog):
    factory, path, key, config, vault = setup
    caplog.set_level(logging.INFO)
    api = FakeAPI()
    registration = factory(api)
    result = registration.run()
    registration.close()
    assert result["ok"] and result["registration_ok"] and result["onboarding_ok"]
    assert result["clerk_user_id"] == "user_test" and result["app_user_id"] == "application_test"
    assert result["organization_id"] == "org_test" and result["tenant_id"] == "tenant_test"
    assert api.counts[("POST", "/v1/client/sign_ups")] == 1
    assert api.counts[("POST", "/api/tenants")] == 1
    text = json.dumps(result) + caplog.text + path.read_bytes().decode()
    for secret in ("123456", "mail-private", "refresh-private", config["password"], "private-client-cookie", api.jwt):
        assert secret not in text
    state = module.load_private(path, key)
    assert state["config"]["password"] == config["password"]
    assert state["cookies"] and state["jwt"] == api.jwt
    resumed = factory(api)
    assert resumed.run()["ok"]
    resumed.close()
    assert api.counts[("POST", "/v1/client/sign_ups")] == 1
    assert api.counts[("POST", "/api/tenants")] == 1


def test_required_captcha_stops_without_submitting_identity(setup):
    factory, path, key, config, vault = setup
    api = FakeAPI(captcha=True)
    registration = factory(api)
    result = registration.run()
    registration.close()
    assert result["status"] == "human_required" and not result["ok"]
    assert not any(method != "GET" for method, *_ in api.calls)
    assert result["captcha_provider"] == "turnstile"
    resumed = factory(api)
    assert resumed.run(captcha_token="legitimate-fresh-fixture")["ok"]
    resumed.close()
    assert api.calls[3][2]["captcha_token"] == "legitimate-fresh-fixture"
    assert api.calls[3][2]["captcha_widget_type"] == "smart"


@pytest.mark.parametrize("path", ["/v1/environment", "/v1/client/sign_ups"])
def test_html_challenge_never_becomes_success(setup, path):
    factory, *_ = setup
    api = FakeAPI()
    api.hook = lambda request, form: httpx.Response(403, text="<html>Challenge</html>",
        headers={"content-type": "text/html"}) if request.url.path == path else None
    registration = factory(api)
    assert registration.run()["status"] == "human_required"
    registration.close()


def test_429_honors_cooldown_without_retry(setup):
    factory, *_ = setup
    api = FakeAPI()
    api.hook = lambda request, form: httpx.Response(429, json={"errors": []}, headers={"Retry-After": "120"})
    registration = factory(api)
    result = registration.run()
    assert result["status"] == "rate_limited" and result["retry_not_before"] > time.time() + 100
    assert registration.run()["status"] == "rate_limited"
    assert len(api.calls) == 1
    registration.close()


def test_bad_otp_is_not_retried_automatically_or_logged(setup, caplog):
    factory, *_ = setup
    api = FakeAPI()
    api.hook = lambda request, form: httpx.Response(400, json={"errors": [
        {"code": "form_code_incorrect", "message": "Echo 123456 private-registration-password"}
    ]}) if request.url.path.endswith("/attempt_verification") else None
    registration = factory(api)
    result = registration.run()
    assert result["status"] == "code_required"
    assert api.counts[("POST", "/v1/client/sign_ups/sua_test/attempt_verification")] == 1
    assert "123456" not in caplog.text and "private-registration-password" not in caplog.text
    assert registration.run(code="123456")["error"] == "verification_code_already_used"
    registration.close()


def test_mailbox_timeout_resumes_same_signup_without_resending(setup, monkeypatch):
    factory, *_ = setup
    api = FakeAPI()
    monkeypatch.setattr(module, "fetch_otp", lambda *a, **kw: "")
    registration = factory(api)
    assert registration.run()["status"] == "code_required"
    registration.close()
    resumed = factory(api)
    assert resumed.run(code="123456")["ok"]
    resumed.close()
    assert api.counts[("POST", "/v1/client/sign_ups")] == 1
    assert api.counts[("POST", "/v1/client/sign_ups/sua_test/prepare_verification")] == 1


@pytest.mark.parametrize("step", ["signup", "verify", "tenant"])
def test_ambiguous_committed_mutation_is_reconciled_not_repeated(setup, step):
    factory, *_ = setup
    api = FakeAPI()
    target = {"signup": "/v1/client/sign_ups", "verify": "/v1/client/sign_ups/sua_test/attempt_verification",
              "tenant": "/api/tenants"}[step]
    intercepted = False

    def hook(request, form):
        nonlocal intercepted
        if request.url.path != target or intercepted:
            return None
        intercepted = True
        api.hook = None
        api.handle(request)  # The synthetic server commits before the response is lost.
        raise httpx.ReadTimeout("secret echo must not be logged", request=request)

    api.hook = hook
    registration = factory(api)
    first = registration.run()
    assert first["status"] == "needs_check"
    registration.close()
    count = api.counts[("POST", target)]
    resumed = factory(api)
    assert resumed.run()["ok"]
    resumed.close()
    assert api.counts[("POST", target)] == count


def test_unresolved_mutation_never_creates_another_account(setup):
    factory, *_ = setup
    api = FakeAPI()

    def hook(request, form):
        if request.url.path == "/v1/client/sign_ups":
            raise httpx.ReadTimeout("ambiguous", request=request)
    api.hook = hook
    registration = factory(api)
    assert registration.run()["status"] == "needs_check"
    assert registration.run()["error"] == "mutation_not_reconciled"
    assert api.counts[("POST", "/v1/client/sign_ups")] == 1
    registration.close()


@pytest.mark.parametrize("wrong", ["email", "sid", "user", "jwt"])
def test_wrong_session_identity_stops_before_application_mutations(setup, wrong):
    factory, *_ = setup
    api = FakeAPI()

    def hook(request, form):
        if request.url.path.endswith("/touch"):
            session = api.session()
            if wrong == "email":
                session["user"]["email_addresses"][0]["email_address"] = "other@example.test"
            if wrong == "sid":
                session["id"] = "sess_other"
            if wrong == "user":
                session["user"]["id"] = "user_other"
            if wrong == "jwt":
                session["last_active_token"]["jwt"] = fake_jwt(user="user_other")
            return httpx.Response(200, json={"response": session})
    api.hook = hook
    registration = factory(api)
    assert not registration.run()["ok"]
    assert api.counts[("POST", "/api/tenants")] == 0
    registration.close()


def test_partial_account_is_not_claimed_as_completed_onboarding(setup):
    factory, *_ = setup
    api = FakeAPI()
    api.hook = lambda request, form: httpx.Response(400, json={"errors": [{"code": "phone_verification_required"}]}) if request.url.path == "/api/tenants" else None
    registration = factory(api)
    result = registration.run()
    assert not result["ok"] and result["registration_ok"] and not result["onboarding_ok"]
    assert result["status"] == "human_required"
    assert result["error"] == "phone_verification_required"
    registration.close()


def test_resend_requires_explicit_action_and_is_bounded(setup, monkeypatch):
    factory, *_ = setup
    api = FakeAPI()
    monkeypatch.setattr(module, "fetch_otp", lambda *a, **kw: "")
    registration = factory(api)
    assert registration.run()["status"] == "code_required"
    assert registration.run()["status"] == "code_required"
    assert api.counts[("POST", "/v1/client/sign_ups/sua_test/prepare_verification")] == 1
    assert registration.run(resend=True)["status"] == "code_required"
    assert api.counts[("POST", "/v1/client/sign_ups/sua_test/prepare_verification")] == 2
    assert registration.run(resend=True)["error"] == "resend_limit_reached"
    registration.close()


def test_checkpoint_profile_changes_are_rejected(setup):
    factory, path, key, config, vault = setup
    registration = factory(FakeAPI(captcha=True))
    registration.run()
    registration.close()
    with pytest.raises(ValueError, match="identity or profile"):
        factory(FakeAPI(), {**config, "proxy": "http://different.example.test:8888"})
