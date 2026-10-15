"""Batched workbench: pasted lists, round-robin gateways and the worker cap.

These are local contract tests over the dispatcher.  They do not prove that a
remote Logicc account was created; the single-account runner is exercised by
``test_logicc_protocol.py`` and ``test_logicc_run_api.py``.
"""
import json

import pytest

import app as console
from logicc_register import save_private
from proxy_pool import assign_proxy_round_robin

from test_logicc_console import client  # noqa: F401  (pytest fixture reuse)

ACCOUNT_LINE = "owner{n}@example.test----mail-private----client-private----refresh-private"


class FakeProc:
    """A member that stays 'running' for a fixed number of polls."""

    def __init__(self, ticks, done):
        self.ticks = ticks
        self.done = done
        self.pid = 4242
        self.finished = False

    def poll(self):
        if self.ticks > 0:
            self.ticks -= 1
            return None
        if not self.finished:
            self.finished = True
            self.done()
        return 0


@pytest.fixture(autouse=True)
def isolated_batches():
    """Keep dispatcher globals from leaking between tests in this session."""
    saved_batches = dict(console.BATCHES)
    saved_jobs = dict(console.JOBS)
    console.BATCHES.clear()
    console.JOBS.clear()
    yield
    console.BATCHES.clear()
    console.BATCHES.update(saved_batches)
    console.JOBS.clear()
    console.JOBS.update(saved_jobs)


@pytest.fixture
def scheduler(monkeypatch):
    """Replace the child-process start with a deterministic fake member."""
    state = {"peak": 0, "live": 0, "order": [], "ticks": 2}

    def start(job):
        state["live"] += 1
        state["peak"] = max(state["peak"], state["live"])
        state["order"].append(job.meta["email"])

        def finished():
            state["live"] -= 1

        job.proc = FakeProc(state["ticks"], finished)
        # A real member writes its own STDIO log; the batch log is assembled
        # from those files, so the fake member must produce one too.
        job.log_path.write_text(
            '{"step": "confirm_account", "http_status": 200}\n', encoding="utf-8")

    monkeypatch.setattr(console, "start_registration_job", start)
    return state


def wait_for_batch(batch_id, timeout=30.0):
    """Join the dispatcher thread so its batch-log handle is released."""
    import time
    batch = console.BATCHES[batch_id]
    deadline = time.monotonic() + timeout
    while batch.thread is not None and batch.thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.02)
    if batch.thread is not None:
        batch.thread.join(timeout=5)
        assert not batch.thread.is_alive(), "batch dispatcher did not finish"
    return batch


def seed_accounts(count, *, prefix="owner"):
    lines = "\n".join(ACCOUNT_LINE.format(n=n) for n in range(count))
    if prefix != "owner":
        lines = lines.replace("owner", prefix)
    response = console.app.test_client().post("/api/accounts/import", json={"lines": lines})
    assert response.status_code == 200
    console.sync_pool_registry()
    return [f"{prefix}{n}@example.test" for n in range(count)]


def run_batch_direct(pairs, workers, *, ticks=None, scheduler=None):
    """Drive run_batch synchronously with a stubbed member starter."""
    if ticks is not None and scheduler is not None:
        scheduler["ticks"] = ticks
    vault = console.console_vault()
    key = vault.key_path.read_bytes().strip()
    batch = console.Batch({"id": "b" * 32, "label": "Logicc · 批量", "provider": "logicc",
                           "method": "protocol", "account_count": len(pairs),
                           "worker_limit": workers, "proxy_count": 0,
                           "emails": [p[0] for p in pairs], "regions": [p[2] for p in pairs],
                           "job_ids": [p[3] for p in pairs], "created_at": console.utc_now(),
                           "state": "running",
                           "log_path": str(console.BATCH_DIR / ("b" * 32 + ".log"))})
    console.BATCHES[batch.id] = batch
    console.run_batch(batch, pairs, workers, key, vault)
    return batch


# ── Pasted input parsing ────────────────────────────────────────────────────

def test_pasted_emails_accept_lines_commas_and_blanks():
    parsed = console.parse_pasted_emails("A@Example.test\n b@example.test,\n\nc@example.test; d@example.test  a@example.test")
    assert parsed == ["a@example.test", "b@example.test", "c@example.test", "d@example.test"]


def test_pasted_emails_extract_the_address_from_credential_rows():
    """The workbench box accepts a fresh shipment, not only pre-imported rows."""
    parsed = console.parse_pasted_emails(
        "new1@example.test----mail-pw----client-id----refresh-token\n"
        "new2@example.test----mail-pw----client-id----refresh-token\n"
        "already@example.test\n")
    assert parsed == ["new1@example.test", "new2@example.test", "already@example.test"]


def test_pasted_credential_rows_are_imported_and_reimportable(client):
    lines = ("fresh@example.test----mail-private----client-private----refresh-private\n"
             "other@example.test----mail-private----client-private----refresh-private\n")
    first = console.register_pasted_credentials(lines, console.console_vault())
    assert first["added"] == 2 and first["total"] == 2
    again = console.register_pasted_credentials(lines, console.console_vault())
    assert again["added"] == 0 and again["updated"] == 2
    accounts = {account.email for account in console.console_vault().list_accounts()}
    assert {"fresh@example.test", "other@example.test"} <= accounts


def test_pasted_credentials_reject_the_whole_paste_on_a_bad_row(client):
    from account_vault import ImportValidationError
    with pytest.raises(ImportValidationError):
        console.register_pasted_credentials(
            "good@example.test----mail-private----client-private----refresh-private\n"
            "broken-row-without-fields\n".replace("broken-row-without-fields", "bad@example.test----only-two"),
            console.console_vault())


@pytest.mark.parametrize("text,message", [
    ("", "至少一个"),
    ("   \n  ", "至少一个"),
    ("not-an-email", "邮箱格式错误"),
    ("a@example.test\nbroken", "邮箱格式错误"),
])
def test_pasted_emails_reject_bad_input(text, message):
    with pytest.raises(ValueError) as error:
        console.parse_pasted_emails(text)
    assert message in str(error.value)


def test_pasted_emails_cap_at_one_hundred():
    allowed = "\n".join(f"user{n}@example.test" for n in range(console.MAX_BATCH_ACCOUNTS))
    assert len(console.parse_pasted_emails(allowed)) == 100
    too_many = allowed + "\nextra@example.test"
    with pytest.raises(ValueError, match="单批最多 100"):
        console.parse_pasted_emails(too_many)


def test_pasted_proxies_accept_host_port_user_password_and_urls():
    rows = console.parse_pasted_proxies(
        "proxy.example.test:3010:fixture-region-US:private\n"
        "DE|http://user:pass@de.example.test:8080\n"
        "# comment\n\n")
    assert [region for region, _proxy in rows] == ["US", "DE"]
    assert rows[0][1] == "http://fixture-region-US:private@proxy.example.test:3010"


def test_pasted_proxies_cap_at_one_hundred():
    allowed = "\n".join(f"user:pass@host{n}.example.test:8080" for n in range(console.MAX_BATCH_PROXIES))
    assert len(console.parse_pasted_proxies(allowed)) == 100
    with pytest.raises(ValueError, match="单批最多 100"):
        console.parse_pasted_proxies(allowed + "\nuser:pass@extra.example.test:8080")


# ── Round-robin assignment ─────────────────────────────────────────────────

def test_round_robin_pairs_one_to_one_when_the_pool_is_large_enough():
    pool = [(f"R{n}", f"http://p{n}.example.test:8080") for n in range(4)]
    assert assign_proxy_round_robin(pool, 3) == pool[:3]


def test_round_robin_restarts_from_the_top_when_the_pool_is_smaller():
    pool = [("US", "http://a.example.test:8080"), ("DE", "http://b.example.test:8080")]
    assert assign_proxy_round_robin(pool, 5) == [pool[0], pool[1], pool[0], pool[1], pool[0]]


def test_round_robin_keeps_direct_connection_for_an_empty_pool():
    assert assign_proxy_round_robin([], 3) == [None, None, None]
    assert assign_proxy_round_robin([("US", "http://a.example.test:8080")], 0) == []


# ── Launch validation ──────────────────────────────────────────────────────

def test_batch_launches_straight_from_pasted_credentials(client, scheduler):
    """One paste both imports the mailbox and starts the account."""
    body = {"emails": ("pasted0@example.test----mail-private----client-private----refresh-private\n"
                       "pasted1@example.test----mail-private----client-private----refresh-private"),
            "workers": 1, "accept_terms": True}
    response = client.post("/api/batches", json=body)
    assert response.status_code == 201, response.get_data(as_text=True)
    snapshot = response.get_json()["batch"]
    assert snapshot["account_count"] == 2
    imported = {account.email for account in console.console_vault().list_accounts()}
    assert {"pasted0@example.test", "pasted1@example.test"} <= imported
    wait_for_batch(snapshot["id"])


def test_batch_rejects_out_of_range_workers(client):
    seed_accounts(2)
    for workers in (0, 33, "many"):
        response = client.post("/api/batches", json={"emails": "owner0@example.test",
                                                     "workers": workers, "accept_terms": True})
        assert response.status_code == 400
        assert "并发数" in response.get_json()["error"]


def test_batch_requires_terms_and_known_credentials(client):
    seed_accounts(2)
    assert client.post("/api/batches", json={"emails": "owner0@example.test", "workers": 1}).status_code == 400
    response = client.post("/api/batches", json={"emails": "ghost@example.test", "workers": 1,
                                                 "accept_terms": True})
    assert response.status_code == 400
    assert "尚未导入收码凭据" in response.get_json()["error"]
    assert not console.BATCHES


def test_batch_rejects_proxy_that_cannot_be_pinned(client, monkeypatch):
    seed_accounts(2)
    monkeypatch.setattr(console, "pin_proxy_cached", lambda proxy: (_ for _ in ()).throw(ValueError("unreachable")))
    response = client.post("/api/batches", json={"emails": "owner0@example.test", "workers": 1,
                                                 "accept_terms": True,
                                                 "proxies": "1.2.3.4:8080:user:pass"})
    assert response.status_code == 400
    assert "公网网关" in response.get_json()["error"]
    assert not console.BATCHES


def test_rejected_launch_does_not_import_credentials(client):
    """A bad proxy list must not leave a half-prepared batch in the vault."""
    before = {account.email for account in console.console_vault().list_accounts()}
    response = client.post("/api/batches", json={
        "emails": "ghost@example.test----mail-pw----client-id----refresh-token",
        "proxies": "definitely not a proxy", "workers": 1, "accept_terms": True})
    assert response.status_code == 400
    after = {account.email for account in console.console_vault().list_accounts()}
    assert after == before
    assert not console.BATCHES


# ── Concurrency cap and scheduling ─────────────────────────────────────────

def test_batch_never_exceeds_the_worker_cap_and_uses_round_robin(client, scheduler):
    emails = seed_accounts(6)
    pool = [("US", "http://a.example.test:8080"), ("DE", "http://b.example.test:8080")]
    slots = assign_proxy_round_robin(pool, len(emails))
    pairs = [(email, slot[1], slot[0], f"{index:032x}")
             for index, (email, slot) in enumerate(zip(emails, slots))]
    run_batch_direct(pairs, 2, ticks=6, scheduler=scheduler)
    assert scheduler["peak"] == 2, "at most two accounts may be in flight"
    assert scheduler["order"] == ["owner0@example.test", "owner1@example.test",
                                  "owner2@example.test", "owner3@example.test",
                                  "owner4@example.test", "owner5@example.test"]
    batch = console.BATCHES["b" * 32]
    assert batch.meta["state"] == "completed"
    assert batch.meta["worker_limit"] == 2


def test_batch_assigns_gateways_in_round_robin_order(client, scheduler):
    emails = seed_accounts(3)
    pool = [("US", "http://a.example.test:8080"), ("DE", "http://b.example.test:8080")]
    slots = assign_proxy_round_robin(pool, len(emails))
    pairs = [(email, slot[1], slot[0], f"{index:032x}")
             for index, (email, slot) in enumerate(zip(emails, slots))]
    run_batch_direct(pairs, 32, ticks=1, scheduler=scheduler)
    routes = [console.console_vault().get_registration_route(email) for email in emails]
    assert [route["proxy_region"] for route in routes] == ["US", "DE", "US"]


def test_batch_log_prefixes_every_member_line(client, scheduler):
    emails = seed_accounts(2)
    pairs = [(email, "", "DIRECT", f"{index:032x}") for index, email in enumerate(emails)]
    run_batch_direct(pairs, 1, ticks=1, scheduler=scheduler)
    text = (console.BATCH_DIR / ("b" * 32 + ".log")).read_text(encoding="utf-8")
    assert "=== Logicc batch" in text and "=== batch finished" in text
    assert "[owner0@example.test]" in text


# ── API surface ────────────────────────────────────────────────────────────

def test_batch_api_snapshot_reports_progress_without_secrets(client, scheduler):
    emails = seed_accounts(2)
    body = {"emails": "\n".join(emails), "workers": 1, "accept_terms": True}
    response = client.post("/api/batches", json=body)
    assert response.status_code == 201
    snapshot = response.get_json()["batch"]
    assert snapshot["account_count"] == 2
    assert snapshot["worker_limit"] == 1
    batch = wait_for_batch(snapshot["id"])
    assert batch.meta["state"] == "completed"
    listed = client.get("/api/batches").get_json()["batches"]
    assert [row["id"] for row in listed] == [snapshot["id"]]
    detail = client.get(f"/api/batches/{snapshot['id']}?tail=50").get_json()["batch"]
    assert len(detail["accounts"]) == 2
    assert {row["email"] for row in detail["accounts"]} == set(emails)
    assert detail["logs"]
    for row in detail["accounts"]:
        assert "password" not in json.dumps(row)
    assert client.get("/api/batches/" + "0" * 32).status_code == 404
    assert client.post("/api/batches/" + "0" * 32 + "/stop").status_code == 404


def test_second_launch_is_refused_while_a_batch_is_active(client, scheduler, monkeypatch):
    emails = seed_accounts(2)
    monkeypatch.setattr(console, "active_batch", lambda: console.BATCHES["b" * 32])
    console.BATCHES["b" * 32] = console.Batch({"id": "b" * 32, "state": "running",
                                               "log_path": str(console.BATCH_DIR / "b.log")})
    response = client.post("/api/batches", json={"emails": emails[0], "workers": 1, "accept_terms": True})
    assert response.status_code == 409
    assert "未完成" in response.get_json()["error"]


def test_batch_stop_marks_every_member_for_stop(client, scheduler):
    emails = seed_accounts(2)
    body = {"emails": "\n".join(emails), "workers": 1, "accept_terms": True}
    batch_id = client.post("/api/batches", json=body).get_json()["batch"]["id"]
    response = client.post(f"/api/batches/{batch_id}/stop")
    assert response.status_code == 200
    assert console.BATCHES[batch_id].meta["stop_requested"] is True
    assert response.get_json()["batch"]["stop_requested"] is True
    wait_for_batch(batch_id)
    assert console.BATCHES[batch_id].meta["state"] == "stopped"


def test_batch_members_are_reserved_under_their_own_job(client, scheduler):
    """Each account must be owned by the member that reports its result.

    A batch reserves many accounts at once, but every account is executed by
    its own child.  If the rows were stamped with the batch id, the member's
    result would match no row and the account would stay reserved forever.
    """
    emails = seed_accounts(3)
    body = {"emails": "\n".join(emails), "workers": 1, "accept_terms": True}
    snapshot = client.post("/api/batches", json=body).get_json()["batch"]
    registry = console.pool_registry()
    rows = registry.lookup(emails)
    for email, job_id in zip(emails, snapshot["job_ids"]):
        assert rows[email.casefold()]["state"] == "reserved"
        assert rows[email.casefold()]["current_job_id"] == job_id, \
            "row must be owned by its member job, not the batch"
    wait_for_batch(snapshot["id"])


def test_failed_member_updates_pool_state_instead_of_staying_reserved(client):
    """A member that ends waiting on a human must not linger as 'reserved'."""
    emails = seed_accounts(2)
    job_ids = ["4" * 32, "5" * 32]
    registry = console.sync_pool_registry()
    assert len(registry.reserve_each(dict(zip(emails, job_ids)))) == 2
    for index, job_id in enumerate(job_ids):
        registry.record_job_results(job_id, [{
            "email": emails[index], "ok": False, "status": "human_required",
            "step": "solve_captcha", "error": "ERROR_CAPTCHA_UNSOLVABLE"}])
    rows = registry.lookup(emails)
    for email in emails:
        assert rows[email.casefold()]["state"] == "reserved"
        assert rows[email.casefold()]["registration_error"] == "ERROR_CAPTCHA_UNSOLVABLE"
    assert registry.release_batch(job_ids) == 2
    rows = registry.lookup(emails)
    for email in emails:
        assert rows[email.casefold()]["state"] == "spare"
        assert rows[email.casefold()]["current_job_id"] == ""


def test_finished_batch_does_not_block_the_next_launch(client, scheduler):
    """Waiting-on-a-human accounts are finished work, not in-flight work."""
    emails = seed_accounts(2)
    body = {"emails": "\n".join(emails), "workers": 1, "accept_terms": True}
    batch_id = client.post("/api/batches", json=body).get_json()["batch"]["id"]
    wait_for_batch(batch_id)
    # Force the members into the waiting state a real captcha failure produces.
    for job_id in console.BATCHES[batch_id].meta["job_ids"]:
        console.JOBS[job_id].meta.update(state="human_required")
    console.BATCHES[batch_id].meta["state"] = "completed"
    assert console.busy_reason() == ""
    console.sync_pool_registry().release_batch(console.BATCHES[batch_id].meta["job_ids"])
    second = client.post("/api/batches", json=body)
    assert second.status_code == 201
    wait_for_batch(second.get_json()["batch"]["id"])


def test_batch_headline_reports_accounts_still_waiting_on_a_human(client):
    """A drained dispatcher must not read as a clean completion."""
    emails = seed_accounts(2)
    job_ids = ["1" * 32, "2" * 32]
    for index, job_id in enumerate(job_ids):
        result_path = console.RESULT_DIR / (job_id + ".jsonl")
        result_path.write_text(json.dumps({
            "email": emails[index], "ok": False, "status": "human_required",
            "step": "captcha", "error": "captcha_required",
            "registration_ok": False, "onboarding_ok": False}) + "\n", encoding="utf-8")
        console.JOBS[job_id] = console.Job({
            "id": job_id, "provider": "logicc", "email": emails[index], "state": "human_required",
            "account_count": 1, "created_at": console.utc_now(), "pool_batch": True,
            "log_path": str(console.JOB_DIR / (job_id + ".log")),
            "result_path": str(result_path)})
    batch = console.Batch({"id": "c" * 32, "label": "Logicc · 批量 2", "provider": "logicc",
                           "method": "protocol", "account_count": 2, "worker_limit": 2,
                           "proxy_count": 0, "emails": list(emails), "regions": ["DIRECT", "DIRECT"],
                           "job_ids": job_ids, "created_at": console.utc_now(),
                           "state": "completed", "finished_at": console.utc_now(),
                           "log_path": str(console.BATCH_DIR / ("c" * 32 + ".log"))})
    console.BATCHES[batch.id] = batch
    snapshot = console.batch_snapshot(batch)
    assert snapshot["state"] == "completed"
    assert snapshot["headline_state"] == "human_required"
    assert snapshot["waiting_count"] == 2
    assert snapshot["completed_count"] == 0
