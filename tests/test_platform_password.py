import pytest

import app as console
from logicc_register import save_private
from test_logicc_console import client


@pytest.fixture
def confirmed(client):
    client.post("/api/accounts/import", json={"lines": "owner@example.test----fixture-mailbox-password----fixture-client----fixture-refresh"})
    jid = "d" * 32
    console.JOBS[jid] = console.Job({"id": jid, "provider": "logicc", "email": "owner@example.test",
        "state": "completed", "account_count": 1, "created_at": console.utc_now(),
        "log_path": str(console.JOB_DIR / (jid + ".log")), "result_path": str(console.RESULT_DIR / (jid + ".jsonl"))})
    state = {"email": "owner@example.test", "registration_ok": True,
             "config": {"email": "owner@example.test", "password": "Lc!fixture-platform-password9"},
             "jwt": "fixture-jwt-must-not-be-returned"}
    key = console.console_vault().key_path.read_bytes().strip()
    save_private(console.registration_state_path(jid), key, state)
    return jid, state, key


def test_list_masks_platform_password_and_explicit_post_reveals_only_platform_password(client, confirmed):
    public = client.get("/api/accounts/managed")
    assert public.get_json()["accounts"][0]["has_platform_password"]
    assert "fixture-platform-password" not in public.get_data(as_text=True)
    assert "fixture-mailbox-password" not in public.get_data(as_text=True)
    r = client.post("/api/accounts/owner@example.test/platform-password", json={})
    assert r.status_code == 200
    assert r.get_json() == {"ok": True, "password": "Lc!fixture-platform-password9"}
    assert "no-store" in r.headers["Cache-Control"] and r.headers["Pragma"] == "no-cache"
    assert "fixture-jwt" not in r.get_data(as_text=True) and "fixture-mailbox-password" not in r.get_data(as_text=True)


@pytest.mark.parametrize("wrong", ["unconfirmed", "state_email", "config_email", "config_type", "missing_file"])
def test_password_rejects_wrong_or_unconfirmed_identity(client, confirmed, wrong):
    jid, state, key = confirmed
    if wrong == "unconfirmed":
        state["registration_ok"] = False
    elif wrong == "state_email":
        state["email"] = "another@example.test"
    elif wrong == "config_email":
        state["config"]["email"] = "another@example.test"
    elif wrong == "config_type":
        state["config"] = ["invalid"]
    path = console.registration_state_path(jid)
    if wrong == "missing_file":
        path.unlink()
    else:
        save_private(path, key, state)
    assert not client.get("/api/accounts/managed").get_json()["accounts"][0]["has_platform_password"]
    assert client.post("/api/accounts/owner@example.test/platform-password", json={}).status_code == 404


def test_password_endpoint_requires_explicit_same_origin_json_post(client, confirmed):
    path = "/api/accounts/owner@example.test/platform-password"
    assert client.get(path).status_code == 405
    assert client.post(path).status_code == 400
    assert client.post(path, json={}, headers={"Origin": "https://other.example"}).status_code == 403
    assert client.post(path, json={}, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.post("/api/accounts/missing@example.test/platform-password", json={}).status_code == 404


def test_mailbox_view_has_only_four_columns_and_no_otp_controls(client):
    html = client.get("/").get_data(as_text=True)
    section = html.split('id="view-pool"', 1)[1].split('id="view-launch"', 1)[0]
    assert section.count("<th>") == 4 and "Logicc 平台密码" in section
    assert "收码</th>" not in section and 'id="otpDialog"' not in html
    assert html.index('id="worklogOutput"') < html.index('id="registrationTerms"')
