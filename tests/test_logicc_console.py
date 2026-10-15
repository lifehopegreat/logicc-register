from pathlib import Path
import os

import pytest

import app as console
from account_vault import AccountVault, ImportValidationError


@pytest.fixture
def client(tmp_path, monkeypatch):
    for name, suffix in [("DATA", "data"), ("OUTPUT", "output"), ("JOB_DIR", "data/jobs"),
                         ("INPUT_DIR", "data/inputs"), ("RESULT_DIR", "output/results")]:
        path = tmp_path / suffix
        path.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(console, name, path)
    monkeypatch.setattr(console, "SETTINGS_FILE", tmp_path / "data/settings.json")
    monkeypatch.setattr(console, "DOMAIN_MAILBOX_RUNTIME_FILE", tmp_path / "data/mailbox.json")
    monkeypatch.setattr(console, "JOBS", {})
    return console.app.test_client()


def test_console_loads_without_gpt_and_validates_protocol_registration(client):
    health = client.get("/api/health").get_json()
    assert health["ok"] and health["otp_target"] == "logicc"
    assert health["registration_ready"] is True
    assert health["registration_mode"] == "protocol"
    for method in ["protocol", "browser"]:
        response = client.post("/api/runs", json={"method": method, "accounts": "anything"})
        assert response.status_code == 400
    assert console.JOBS == {}
    assert not list(console.INPUT_DIR.iterdir())
    assert client.get("/").status_code == 200


@pytest.mark.parametrize("route", [
    "/api/accounts/export-at", "/api/accounts/export-2fa",
    "/api/accounts/owner@example.test/auth-session", "/api/accounts/owner@example.test/login-credentials",
    "/api/accounts/owner@example.test/twofa-code", "/api/accounts/owner@example.test/twofa-link",
])
def test_gpt_endpoints_removed(client, route):
    assert client.post(route).status_code in {404, 405}
    assert not any(str(rule) == route for rule in console.app.url_map.iter_rules())


def test_mailbox_import_metadata_and_delete_still_work(client):
    line = "owner@example.test----test-password----test-client----test-refresh"
    assert client.post("/api/accounts/import", json={"lines": line}).status_code == 200
    response = client.get("/api/accounts/managed")
    row = response.get_json()["accounts"][0]
    assert row["email"] == "owner@example.test" and row["otp_ready"]
    assert not any(secret in response.get_data(as_text=True) for secret in
                   ("test-password", "test-client", "test-refresh"))
    assert client.delete("/api/accounts/owner@example.test").status_code == 200
    assert client.get("/api/accounts/managed").get_json()["accounts"] == []


def test_old_gpt_extra_fields_are_rejected_without_partial_import(client):
    lines = "owner@example.test----test-password----test-client----test-refresh----gpt-password----MFA----PLUS"
    assert client.post("/api/accounts/import", json={"lines": lines}).status_code == 400
    assert client.get("/api/accounts/managed").get_json()["accounts"] == []


def test_explicit_otp_action_is_logicc_only_and_no_store(client, monkeypatch):
    import email_provider
    client.post("/api/accounts/import", json={"lines":
        "owner@example.test----test-password----test-client----test-refresh"})
    calls = []
    monkeypatch.setattr(email_provider, "fetch_otp", lambda *a, **kw: calls.append(kw) or "123456")
    response = client.post("/api/accounts/owner@example.test/otp", json={"timeout": 10})
    assert response.status_code == 200
    assert response.get_json()["target"] == "logicc"
    assert calls[0]["relay_require_fresh"] is True and calls[0]["after_ts"] > 0
    assert "no-store" in response.headers["Cache-Control"]


def test_settings_keep_secrets_hidden(client):
    assert client.patch("/api/settings", json={"proxy_password": "test-private"}).status_code == 200
    response = client.get("/api/settings")
    assert "test-private" not in response.get_data(as_text=True)


@pytest.mark.parametrize("address", ["bad", "a@", "@example.test", "a@example", "a b@example.test"])
def test_mailbox_import_validation_rejects_invalid_addresses(tmp_path, address):
    vault = AccountVault(data_dir=tmp_path / "vault", outlook_file=tmp_path / "outlook",
                         icloud_file=tmp_path / "relay")
    with pytest.raises(ImportValidationError):
        vault.import_text(address + "----test-password----test-client----test-refresh")


def test_removed_gpt_runtime_files_cannot_be_imported():
    core = Path(console.CORE)
    for name in ["chatgpt_register.py", "pipeline.py", "unified_pipeline.py", "codex_oauth.py",
                 "sentinel_token.py", "totp_mfa.py", "scripts/run_email_proto_register.py"]:
        assert not (core / name).exists()
    assert not list((core / "gpt_trial_protocol").glob("*.py"))


@pytest.mark.skipif(os.environ.get("RUN_LOCAL_BROWSER_TESTS") != "1", reason="opt-in loopback Chrome console smoke")
def test_console_ui_without_playwright(client, tmp_path, monkeypatch):
    import threading
    import time
    import socket
    from DrissionPage import ChromiumOptions, ChromiumPage
    from DrissionPage.errors import ContextLostError
    from browser_mgr import _resolve_default_chrome_path
    from werkzeug.serving import make_server
    import email_provider

    chrome = _resolve_default_chrome_path()
    assert chrome, "Local Chrome is required for this opt-in check"
    monkeypatch.setattr(email_provider, "fetch_otp", lambda *args, **kw: "123456")
    monkeypatch.setattr(console.CapMonster, "balance", lambda self: 0.42)
    monkeypatch.setattr(console.Logicc2Api, "snapshot", lambda self: {"accounts": []})
    monkeypatch.setattr(console, "probe_proxy", lambda proxy: {"ok": True, "ip": "8.8.8.8"})
    server = make_server("127.0.0.1", 0, console.app, threaded=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    options = ChromiumOptions().headless(True)
    options.set_browser_path(chrome)
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

    from logicc_register import save_private
    jid = "f" * 32
    vault = console.console_vault()
    log_path = console.JOB_DIR / (jid + ".log")
    log_path.write_text("fixture read-only log\n", encoding="utf-8")
    result_path = console.RESULT_DIR / (jid + ".jsonl")
    result_path.write_text('{"ok":true,"status":"success"}\n', encoding="utf-8")
    console.JOBS[jid] = console.Job({"id": jid, "provider": "logicc", "email": "owner@example.test", "state": "completed",
        "account_count": 1, "created_at": console.utc_now(), "log_path": str(log_path),
        "result_path": str(console.RESULT_DIR / (jid + ".jsonl"))})
    batch_id = "e" * 32
    batch_log = console.BATCH_DIR / (batch_id + ".log")
    batch_log.write_text("[owner@example.test] fixture batching read-only log\n", encoding="utf-8")
    console.BATCHES[batch_id] = console.Batch({
        "id": batch_id, "label": "Logicc · 批量 1", "provider": "logicc", "method": "protocol",
        "account_count": 1, "worker_limit": 4, "proxy_count": 0, "emails": ["owner@example.test"],
        "regions": ["DIRECT"], "job_ids": [jid], "created_at": console.utc_now(),
        "state": "completed", "log_path": str(batch_log)})
    save_private(console.registration_state_path(jid), vault.key_path.read_bytes().strip(), {
        "email": "owner@example.test", "registration_ok": True,
        "config": {"email": "owner@example.test", "password": "Lc!fixture-platform-password9"}})

    try:
        page = ChromiumPage(options)
        page.get(f"http://127.0.0.1:{server.server_port}", retry=0, timeout=10)
        wait_for("return document.querySelector('#sideHealthText').textContent === '基础服务正常'")
        assert page.run_js("return !document.querySelector('#withPassword, #setupTwofa, #exportAtAccounts')")
        page.ele("#openImport").click()
        assert page.run_js("return document.querySelector('#importDialog').open")
        page.ele("#importLines").input("owner@example.test----test-password----test-client----test-refresh")
        page.ele("css:#importForm button[type=submit]").click()
        wait_for("return !!document.querySelector('[data-password]')")
        assert page.run_js("return document.querySelector('#importLines').value === ''")
        assert page.run_js("return document.querySelectorAll('#view-pool th').length === 4 && !document.querySelector('[data-otp], [data-delete]')")
        page.ele("css:[data-password]").click()
        wait_for("return document.querySelector('#passwordOutput').textContent === 'Lc!fixture-platform-password9'")
        page.run_js("document.documentElement.dataset.theme='light'")
        assert page.run_js("const b=document.querySelector('#passwordDialog [data-close]'),s=getComputedStyle(b);return b.getBoundingClientRect().width>=64 && s.whiteSpace==='nowrap' && s.borderTopColor==='rgb(85, 85, 85)'")
        page.ele("css:[data-close=passwordDialog]").click()
        wait_for("return !document.querySelector('#passwordDialog').open && document.querySelector('#passwordOutput').textContent === ''")
        assert page.run_js("return !Object.keys(localStorage).some(k => /token|otp|code|password/i.test(k))")
        page.ele("css:[data-nav=launch]").click()
        wait_for("return document.querySelector('#worklogOutput').textContent.includes('fixture batching read-only log')")
        assert page.run_js("return document.querySelector('#taskReadout').getAttribute('aria-label')==='已完成 1 / 总任务 1'")
        page.run_js("updateTaskReadout({account_count:12,completed_count:7})")
        wait_for("return document.querySelector('#completedReadout .rolling-strip').style.transform==='translateY(-7em)'")
        assert page.run_js("return document.querySelector('#totalReadout').dataset.value==='12'")
        page.run_js("updateTaskReadout({account_count:12,completed_count:12});updateBalanceReadout(0.1234)")
        wait_for("return document.querySelector('#completedReadout').dataset.value==='12' && document.querySelector('#balanceValue').dataset.value==='0.1234'")
        assert page.run_js("return getComputedStyle(document.querySelector('#taskReadout')).color==='rgb(22, 131, 61)' && getComputedStyle(document.querySelector('#balanceValue')).color==='rgb(118, 54, 212)' && getComputedStyle(document.querySelector('.balance-label')).color==='rgb(17, 17, 17)'")
        page.run_js("rollingNumber(document.querySelector('#balanceValue'),'--');updateBalanceReadout(10)")
        assert page.run_js("return document.querySelector('#balanceValue').dataset.value==='10.0000' && document.querySelectorAll('#balanceValue .rolling-digit').length===6")
        page.run_cdp("Emulation.setEmulatedMedia", features=[{"name":"prefers-reduced-motion","value":"reduce"}])
        page.run_js("updateBalanceReadout(0.9)")
        assert page.run_js("return getComputedStyle(document.querySelector('#balanceValue .rolling-strip')).transitionDuration==='0s'")
        page.run_cdp("Emulation.setEmulatedMedia", features=[])
        assert page.run_js("return document.querySelector('#batchEmails').value === '' && document.querySelector('#batchEmails').tagName === 'TEXTAREA'")
        assert page.run_js("return document.querySelector('#batchEmails').rows >= 5 && document.querySelector('#batchProxies').tagName === 'TEXTAREA'")
        page.run_js("document.querySelector('#batchEmails').value='a@example.test\\nb@example.test';document.querySelector('#batchEmails').dispatchEvent(new Event('input'))")
        assert page.run_js("return document.querySelector('#batchEmailCount').textContent === '2 / 100'")
        assert page.run_js("return document.querySelector('#batchAssignment').textContent.includes('直连 ×2')")
        page.run_js("document.querySelector('#batchProxies').value='proxy.example.test:3010:fixture-region-US:private-proxy';document.querySelector('#batchProxies').dispatchEvent(new Event('input'))")
        assert page.run_js("return document.querySelector('#batchProxyCount').textContent === '1 / 100'")
        assert page.run_js("return document.querySelector('#batchAssignment').textContent.includes('第 1 条代理 ×2')")
        assert page.run_js("return document.querySelector('#batchWorkers').max === '32' && document.querySelector('#batchWorkers').min === '1'")
        assert page.run_js("return !document.querySelector('#startProtocolRun').disabled && document.querySelector('#stopBatchRun').disabled")
        assert page.run_js("return document.querySelectorAll('#batchTableBody tr').length === 1")
        assert page.run_js("return document.querySelector('#batchTableBody').textContent.includes('owner@example.test')")
        assert page.run_js("return !document.querySelector('#registrationTerms').checked")
        assert len(console.JOBS) == 1
        page.ele("css:[data-nav=settings]").click()
        wait_for("return document.querySelector('[data-setting=proxy_port]').value === '10000'")
        assert page.run_js("return document.querySelector('[data-setting=proxy_password]').value === ''")
        page.ele("css:[data-setting-panel=capmonster]").click()
        page.ele("#capmonsterKey").input("c" * 32)
        page.ele("#capmonsterEnabled").click()
        page.ele("#saveCapmonster").click()
        wait_for("return document.querySelector('#capmonsterKey').value === '' && document.querySelector('#capmonsterKey').placeholder.includes('已加密配置')")
        page.ele("#testCapmonster").click()
        wait_for("return document.querySelector('#capmonsterResult').textContent.includes('0.42')")
        assert page.run_js("return document.querySelector('#balanceValue').dataset.value==='0.4200'")
        page.ele("css:[data-setting-panel=logicc2api]").click()
        page.ele("#logicc2apiEnabled").click()
        page.ele("#saveLogicc2api").click()
        wait_for("return !document.querySelector('#saveLogicc2api').disabled")
        page.ele("#testLogicc2api").click()
        wait_for("return document.querySelector('#logicc2apiResult').textContent.includes('0 个账号')")
        page.ele("css:[data-setting-panel=proxy-pool]").click()
        page.ele("#proxyLines").input("proxy.example.test:3010:fixture-region-US:private-proxy")
        page.ele("#importProxies").click()
        wait_for("return !!document.querySelector('[data-proxy-check]') && document.querySelector('#proxyLines').value === ''")
        page.ele("css:[data-proxy-check]").click()
        wait_for("return document.querySelector('#proxyTableBody').textContent.includes('8.8.8.8')")
        assert page.run_js("return !document.querySelector('#proxyTableBody').textContent.includes('private-proxy')")
        assert console.private_service("logicc2api")["enabled"]
        page.run_cdp("Emulation.setDeviceMetricsOverride", width=390, height=844, deviceScaleFactor=1, mobile=True)
        page.ele("#sidebarToggle").click()
        assert page.run_js("return document.querySelector('#sidebar').classList.contains('open')")
    finally:
        if page is not None:
            page.quit()
        server.shutdown()
        worker.join(timeout=3)
        server.server_close()
