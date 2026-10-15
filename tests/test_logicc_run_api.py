import io
import json
import time
import os

import pytest

import app as console
import logicc_register as module
from test_logicc_console import client
from test_logicc_protocol import FakeAPI
import httpx


@pytest.fixture
def runner(client, monkeypatch):
    api = FakeAPI(captcha=True)
    monkeypatch.setattr(module, "fetch_otp", lambda *args, **kwargs: "123456")

    def start(job):
        key = console.console_vault().key_path.read_bytes().strip()
        private = module.load_private(job.meta["input_path"], key)
        captcha, code = private.pop("captcha_token", ""), private.pop("code", "")
        resend = private.pop("resend_code", False)
        module.save_private(job.meta["input_path"], key, private)
        registration = module.LogiccRegistration(private["config"], state_path=console.registration_state_path(job.id),
            key=key, vault=console.console_vault(), transport=httpx.MockTransport(api.handle))
        try:
            result = registration.run(captcha_token=captcha, code=code, resend=resend)
        finally:
            registration.close()
        console.console_vault()._atomic_write(job.result_path, (json.dumps(result) + "\n").encode(), mode=0o600)
        job.meta.update(state="completed" if result["ok"] else result["status"],
                        registration_step=result["step"], finished_at=console.utc_now())
        job.save()
        console.pool_registry().record_job_results(job.id, [result])
        console.pool_registry().record_registered_results(job.id, [result])
    monkeypatch.setattr(console, "start_registration_job", start)
    client.post("/api/accounts/import", json={"lines":
        "owner@example.test----mail-private----client-private----refresh-private"})
    return api


def create(client):
    return client.post("/api/runs", json={"email": "owner@example.test", "accept_terms": True})


def test_start_preserves_previous_log_on_resume(client, monkeypatch):
    job_id = "e" * 32
    path = console.JOB_DIR / (job_id + ".log")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("previous safe stage\n", encoding="utf-8")
    job = console.Job({"id": job_id, "log_path": str(path), "created_at": console.utc_now()})

    def cannot_spawn(handle):
        raise OSError("fixture spawn failure")

    monkeypatch.setattr(job, "_spawn", cannot_spawn)
    with pytest.raises(OSError):
        job.start(["fixture-python"], {})
    text = path.read_text(encoding="utf-8")
    assert text.startswith("previous safe stage\n") and "start/resume" in text


def test_create_single_protocol_job_without_exposing_secrets(client, runner):
    response = create(client)
    assert response.status_code == 201
    job = response.get_json()["job"]
    assert job["state"] == "human_required"
    assert job["result_error"] == "captcha_required"
    assert client.get("/api/jobs").get_json()["jobs"][0]["result_error"] == "captcha_required"
    assert job["failed_count"] == 0 and job["pending_count"] == 1
    assert job["completed_count"] == 0
    assert job["resume_available"] and job["progress"] < 100
    assert client.get("/api/accounts/managed").get_json()["accounts"][0]["state"] == "reserved"
    private = module.load_private(console.JOBS[job["id"]].meta["input_path"],
        console.console_vault().key_path.read_bytes().strip())
    text = response.get_data(as_text=True) + client.get("/api/jobs").get_data(as_text=True)
    for secret in ["mail-private", "refresh-private", "private-client-cookie", private["config"]["password"]]:
        assert secret not in text
    assert create(client).status_code == 409
    assert client.delete("/api/accounts/owner@example.test").status_code == 409


@pytest.mark.parametrize("body", [
    {"email": "owner@example.test", "accept_terms": False},
    {"email": "owner@example.test", "accept_terms": True, "method": "browser"},
    {"email": "owner@example.test", "accept_terms": True, "workers": 2},
    {"email": "missing@example.test", "accept_terms": True},
])
def test_invalid_or_bulk_launch_is_rejected(client, runner, body):
    assert client.post("/api/runs", json=body).status_code == 400
    assert not console.JOBS


def test_resume_same_encrypted_session_and_cleanup_handoff(client, runner):
    job_id = create(client).get_json()["job"]["id"]
    response = client.post("/api/jobs/" + job_id + "/resume",
                           json={"captcha_token": "new-legitimate-fixture-proof"})
    assert response.status_code == 200
    assert response.get_json()["job"]["state"] == "completed"
    assert "no-store" in response.headers["Cache-Control"]
    key = console.console_vault().key_path.read_bytes().strip()
    private = module.load_private(console.JOBS[job_id].meta["input_path"], key)
    assert "captcha_token" not in private and "code" not in private
    assert runner.counts[("POST", "/v1/client/sign_ups")] == 1
    results = client.get("/api/results").get_json()["results"]
    assert results[0]["registration_ok"] and results[0]["onboarding_ok"]
    assert client.post("/api/jobs/" + job_id + "/resume", json={}).status_code == 409
    assert create(client).status_code == 409
    assert client.delete("/api/accounts/owner@example.test").status_code == 200
    assert not console.registration_state_path(job_id).exists()
    assert not console.JOBS[job_id].result_path.read_text(encoding="utf-8").strip()


def test_stop_before_signup_releases_pool_but_does_not_delete_remote_accounts(client, runner):
    job_id = create(client).get_json()["job"]["id"]
    assert client.post("/api/jobs/" + job_id + "/stop").status_code == 200
    assert console.JOBS[job_id].meta["state"] == "cancelled"
    assert client.get("/api/accounts/managed").get_json()["accounts"][0]["state"] == "spare"
    assert runner.counts[("POST", "/v1/client/sign_ups")] == 0


def test_resume_validates_secret_fields_and_limit_cooldown(client, runner):
    job_id = create(client).get_json()["job"]["id"]
    url = "/api/jobs/" + job_id + "/resume"
    for body in [{"code": "bad"}, {"captcha_token": []}, {"resend_code": True, "code": "123456"}]:
        assert client.post(url, json=body).status_code == 400
    path = console.JOBS[job_id].result_path
    result = console.read_results(path)[0]
    result["retry_not_before"] = time.time() + 120
    path.write_text(json.dumps(result) + "\n", encoding="utf-8")
    assert client.post(url, json={}).status_code == 429


def test_worker_human_required_is_not_completed_or_failed(client):
    job_id = "a" * 32
    console.console_vault().import_text("owner@example.test----mail-private----client-private----refresh-private")
    console.sync_pool_registry().reserve(job_id, ["owner@example.test"])
    path = console.RESULT_DIR / (job_id + ".jsonl")
    path.write_text(json.dumps({"email": "owner@example.test", "ok": False,
        "status": "human_required", "step": "captcha", "error": "captcha_required"}) + "\n", encoding="utf-8")
    job = console.Job({"id": job_id, "provider": "logicc", "account_count": 1, "email": "owner@example.test",
        "state": "running", "pool_batch": True, "created_at": console.utc_now(),
        "log_path": str(console.JOB_DIR / (job_id + ".log")), "result_path": str(path)})
    job.proc = type("Process", (), {"wait": lambda self: 2, "poll": lambda self: 2})()
    job._wait(io.StringIO())
    assert job.meta["state"] == "human_required"
    assert job.snapshot()["failed_count"] == 0
    assert console.pool_registry().lookup(["owner@example.test"])["owner@example.test"]["state"] == "reserved"


@pytest.mark.skipif(os.environ.get("RUN_LOCAL_BROWSER_TESTS") != "1", reason="opt-in loopback Chrome protocol UI")
def test_registration_ui_pauses_and_resumes_without_browser_registration(client, runner, tmp_path):
    import socket
    import threading
    from werkzeug.serving import make_server
    from DrissionPage import ChromiumOptions, ChromiumPage
    from DrissionPage.errors import ContextLostError
    from browser_mgr import _resolve_default_chrome_path

    server = make_server("127.0.0.1", 0, console.app, threaded=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    options = ChromiumOptions().headless(True)
    options.set_browser_path(_resolve_default_chrome_path())
    options.set_user_data_path(str(tmp_path / "chrome"))
    with socket.socket() as port_socket:
        port_socket.bind(("127.0.0.1", 0))
        options.set_local_port(port_socket.getsockname()[1])
    for arg in ("--no-first-run", "--disable-background-networking", "--disable-component-update", "--no-proxy-server"):
        options.set_argument(arg)
    options.set_argument("--host-resolver-rules", "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE localhost")
    page = None

    def wait_for(script):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                if page.run_js(script):
                    return
            except ContextLostError:
                pass
            time.sleep(0.025)
        assert page.run_js(script)

    try:
        page = ChromiumPage(options)
        page.run_cdp("Page.addScriptToEvaluateOnNewDocument", source=(
            "window.testErrors=[]; addEventListener('error',e=>testErrors.push(e.message));"
            "addEventListener('unhandledrejection',()=>testErrors.push('promise error'));"))
        page.get(f"http://127.0.0.1:{server.server_port}/#launch", retry=0, timeout=10)
        wait_for("return document.querySelector('#batchEmails').tagName === 'TEXTAREA'")
        page.ele("#batchEmails").input("owner@example.test")
        page.ele("#registrationTerms").click()
        page.ele("#startProtocolRun").click()
        wait_for("return document.querySelector('#worklogStatus').textContent.includes('需要人工')")
        page.ele("css:[data-nav=jobs]").click()
        wait_for("return !!document.querySelector('[data-resume]')")
        assert page.run_js("return document.querySelector('#jobsTableBody').textContent.includes('需要人工')")
        page.ele("css:[data-resume]").click()
        wait_for("return document.querySelector('#resumeDialog').open")
        page.ele("#resumeCaptcha").input("new-legitimate-fixture-proof")
        page.ele("css:#resumeForm button[type=submit]").click()
        wait_for("return !document.querySelector('#resumeDialog').open")
        wait_for("return document.querySelector('#jobsTableBody').textContent.includes('已确认完成')")
        assert page.run_js("return document.querySelector('#resumeCaptcha').value === ''")
        assert page.run_js("return window.testErrors.length === 0")
        assert runner.counts[("POST", "/v1/client/sign_ups")] == 1
    finally:
        if page is not None:
            page.quit()
        server.shutdown()
        worker.join(timeout=3)
        server.server_close()
