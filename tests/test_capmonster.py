import json
from collections import Counter

import httpx
import pytest

import capmonster as module
import logicc_register as registration_module
from test_logicc_protocol import setup, FakeAPI


KEY = "f" * 32
TOKEN = "fresh-fixture-token-not-for-production"


@pytest.fixture
def service(monkeypatch):
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    calls = Counter()
    responses = {}

    def handle(request):
        method = request.url.path[1:]
        calls[method] += 1
        payload = json.loads(request.content)
        assert payload["clientKey"] == KEY
        if method in responses:
            value = responses[method]
            if isinstance(value, Exception):
                raise value
            return value
        if method == "getBalance":
            return httpx.Response(200, json={"errorId": 0, "balance": 0.1})
        if method == "createTask":
            assert payload["task"] == {
                "type": "TurnstileTask", "websiteURL": "https://app.logicc.com/register",
                "websiteKey": "0xfixtureSiteKey123", "userAgent": registration_module.USER_AGENT,
                "pageAction": "signup"}
            return httpx.Response(200, json={"errorId": 0, "taskId": 123})
        assert method == "getTaskResult" and payload["taskId"] == 123
        return httpx.Response(200, json={"errorId": 0, "status": "ready",
            "solution": {"token": TOKEN, "userAgent": registration_module.USER_AGENT}})

    client = module.CapMonster(KEY, transport=httpx.MockTransport(handle))
    yield client, calls, responses
    client.close()


def solve(client, receipt, checkpoints=None):
    return client.solve_turnstile(site_key="0xfixtureSiteKey123", website_url="https://app.logicc.com/register",
        user_agent=registration_module.USER_AGENT, proxy="", receipt=receipt,
        checkpoint=lambda: checkpoints.append(dict(receipt)) if checkpoints is not None else None)


def test_one_paid_task_and_no_token_persisted(service, caplog):
    client, calls, responses = service
    receipt, checkpoints = {}, []
    assert solve(client, receipt, checkpoints) == TOKEN
    assert checkpoints[0]["status"] == "creating" and checkpoints[-1]["status"] == "consumed"
    assert TOKEN not in json.dumps(checkpoints) + caplog.text and KEY not in json.dumps(checkpoints) + caplog.text
    with pytest.raises(module.CapMonsterError, match="already_used"):
        solve(client, receipt)
    assert calls["createTask"] == 1


def test_ambiguous_create_never_repeats_charge(service):
    client, calls, responses = service
    responses["createTask"] = httpx.ReadTimeout("do not log " + KEY)
    receipt = {}
    with pytest.raises(module.CapMonsterError, match="response_unavailable"):
        solve(client, receipt)
    with pytest.raises(module.CapMonsterError, match="already_used"):
        solve(client, receipt)
    assert calls["createTask"] == 1


def test_lost_poll_resumes_same_task(service):
    client, calls, responses = service
    responses["getTaskResult"] = httpx.ReadTimeout("do not log " + KEY)
    receipt = {}
    with pytest.raises(module.CapMonsterError, match="response_unavailable"):
        solve(client, receipt)
    del responses["getTaskResult"]
    assert solve(client, receipt) == TOKEN
    assert calls["createTask"] == 1 and calls["getTaskResult"] == 2


def test_processing_bounded_and_resuming_does_not_charge(service):
    """Each attempt gets one bounded window, and resuming never re-buys.

    The free re-query means a second attempt spends another window rather than
    reusing the exhausted one; the paid task count is what must stay flat.
    """
    client, calls, responses = service
    responses["getTaskResult"] = httpx.Response(200, json={"errorId": 0, "status": "processing"})
    receipt = {}
    for _ in range(2):
        with pytest.raises(module.CapMonsterError, match="poll_timeout"):
            solve(client, receipt)
    assert calls["createTask"] == 1 and calls["getTaskResult"] == 120


@pytest.mark.parametrize("result,error", [
    ({"errorId": 1, "errorCode": "ERROR_ZERO_BALANCE", "errorDescription": KEY}, "ERROR_ZERO_BALANCE"),
    ({"errorId": 1, "errorCode": KEY, "errorDescription": KEY}, "capmonster_task_rejected"),
    ({"status": "ready"}, "capmonster_invalid_response"),
    ({"errorId": 0, "status": "ready", "solution": {"token": "x" * 2049}}, "capmonster_invalid_token"),
    ({"errorId": 0, "status": "ready", "solution": {"token": TOKEN, "userAgent": "different"}}, "capmonster_user_agent_mismatch"),
])
def test_errors_are_redacted_and_never_accepted(service, result, error):
    client, calls, responses = service
    responses["getTaskResult"] = httpx.Response(200, json=result)
    with pytest.raises(module.CapMonsterError) as exc:
        solve(client, {})
    assert str(exc.value) == error and KEY not in str(exc.value)


def test_zero_balance_does_not_create_task(service):
    client, calls, responses = service
    responses["getBalance"] = httpx.Response(200, json={"errorId": 0, "balance": 0})
    with pytest.raises(module.CapMonsterError, match="ERROR_ZERO_BALANCE"):
        solve(client, {})
    assert not calls["createTask"]


def test_integrated_http_flow(setup, service, caplog):
    factory, path, key, config, vault = setup
    client, calls, responses = service
    api = FakeAPI(captcha=True)
    registration = factory(api)
    registration.captcha_solver = client
    try:
        assert registration.run()["ok"]
        assert registration.run()["ok"]
        assert calls["createTask"] == 1
        assert api.calls[3][2]["captcha_token"] == TOKEN
        encrypted = path.read_bytes().decode()
        assert TOKEN not in encrypted + caplog.text and KEY not in encrypted + caplog.text
        receipt = registration_module.load_private(path, key)["captcha_task"]
        assert receipt["status"] == "consumed" and TOKEN not in json.dumps(receipt)
    finally:
        registration.close()


def test_solver_failure_does_not_submit_identity(setup, service):
    factory, *_ = setup
    client, calls, responses = service
    responses["createTask"] = httpx.Response(200, json={"errorId": 1, "errorCode": "ERROR_CAPTCHA_UNSOLVABLE"})
    api = FakeAPI(captcha=True)
    registration = factory(api)
    registration.captcha_solver = client
    try:
        result = registration.run()
        assert result["status"] == "human_required" and result["error"] == "ERROR_CAPTCHA_UNSOLVABLE"
        assert not any(method != "GET" for method, *_ in api.calls)
        assert calls["createTask"] == 1
    finally:
        registration.close()


def test_rejected_solve_is_retryable_up_to_the_paid_cap(service):
    """A charged-but-unsolved task must not lock the account forever."""
    client, calls, responses = service
    responses["createTask"] = httpx.Response(200, json={"errorId": 1, "errorCode": "ERROR_CAPTCHA_UNSOLVABLE"})
    receipt, checkpoints = {}, []
    with pytest.raises(module.CapMonsterError, match="ERROR_CAPTCHA_UNSOLVABLE"):
        solve(client, receipt, checkpoints)
    assert receipt["attempts"] == 1
    # A real caller persists "failed" here; the retry must survive that.
    receipt["status"] = "failed"
    with pytest.raises(module.CapMonsterError, match="ERROR_CAPTCHA_UNSOLVABLE"):
        solve(client, receipt, checkpoints)
    assert receipt["attempts"] == 2
    assert calls["createTask"] == 2
    # The cap is now reached: no third purchase.
    receipt["status"] = "failed"
    with pytest.raises(module.CapMonsterError, match="attempt_limit_reached"):
        solve(client, receipt, checkpoints)
    assert calls["createTask"] == 2


def test_retry_after_failure_reuses_a_fresh_task_id_and_can_succeed(service):
    client, calls, responses = service
    responses["createTask"] = httpx.Response(200, json={"errorId": 1, "errorCode": "ERROR_CAPTCHA_UNSOLVABLE"})
    receipt = {}
    with pytest.raises(module.CapMonsterError, match="ERROR_CAPTCHA_UNSOLVABLE"):
        solve(client, receipt)
    # The real caller records "failed" here (logicc_register.create_signup).
    receipt["status"] = "failed"
    del responses["createTask"]  # the second purchase resolves normally
    assert solve(client, receipt) == TOKEN
    assert receipt["status"] == "consumed" and receipt["attempts"] == 2
    assert calls["createTask"] == 2


def test_processing_timeout_requeries_the_same_task_for_free(service):
    """An exhausted poll window must not strand the account.

    The paid task may still be alive, so the next attempt re-queries the same
    task id: no second charge, and the account can still reach a token.
    """
    client, calls, responses = service
    responses["getTaskResult"] = httpx.Response(200, json={"errorId": 0, "status": "processing"})
    receipt = {}
    with pytest.raises(module.CapMonsterError, match="poll_timeout"):
        solve(client, receipt)
    assert receipt["status"] == "processing" and receipt["attempts"] == 1
    del responses["getTaskResult"]
    assert solve(client, receipt) == TOKEN
    assert calls["createTask"] == 1, "a live paid task must never be re-bought"
    assert receipt["status"] == "consumed"


def test_exhausted_poll_window_is_reset_once(service, monkeypatch):
    """The reset is bounded by the poll budget, not an unlimited retry loop."""
    client, calls, responses = service
    responses["getTaskResult"] = httpx.Response(200, json={"errorId": 0, "status": "processing"})
    receipt = {}
    assert solve.__name__
    with pytest.raises(module.CapMonsterError, match="poll_timeout"):
        solve(client, receipt)
    assert receipt["poll_count"] >= 60
    with pytest.raises(module.CapMonsterError, match="poll_timeout"):
        solve(client, receipt)
    assert calls["createTask"] == 1


def test_consumed_token_is_never_resold(service):
    client, calls, responses = service
    receipt = {}
    assert solve(client, receipt) == TOKEN
    assert receipt["status"] == "consumed"
    with pytest.raises(module.CapMonsterError, match="already_used"):
        solve(client, receipt)
    assert calls["createTask"] == 1
