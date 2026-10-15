from __future__ import annotations

import sqlite3

from account_registry import AccountRegistry


def _row(registry: AccountRegistry, email: str) -> dict:
    return registry.lookup([email])[email]


def test_terminal_registration_error_is_written_atomically(tmp_path) -> None:
    path = tmp_path / "pool.db"
    registry = AccountRegistry(path)
    email = "deactivated@example.test"
    registry.sync_pool({email: f"{email}----relay"})
    assert registry.reserve("job-1", [email]) == [email]

    registry.record_job_results("job-1", [{
        "email": email,
        "ok": False,
        "status": "failed",
        "error": "otp_validate_failed: account_deactivated",
    }])

    row = _row(AccountRegistry(path), email)
    assert row["health_status"] == "account_deactivated"
    assert row["last_probe_status"] == "account_deactivated"
    assert row["health_alive"] is False
    assert row["check_error"] == "registration_terminal: account_deactivated"


def test_startup_backfills_legacy_terminal_but_preserves_healthy_evidence(tmp_path) -> None:
    path = tmp_path / "pool.db"
    registry = AccountRegistry(path)
    registry.sync_pool({
        "legacy@example.test": "legacy@example.test----relay",
        "healthy@example.test": "healthy@example.test----relay",
    })
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE pool_accounts SET registration_error = ? WHERE email = ?",
            ("otp_validate_failed: account_deactivated", "legacy@example.test"),
        )
        connection.execute(
            "UPDATE pool_accounts SET registration_error = ?, health_status = 'plus', health_alive = 1 WHERE email = ?",
            ("otp_validate_failed: account_deactivated", "healthy@example.test"),
        )

    restarted = AccountRegistry(path)
    assert _row(restarted, "legacy@example.test")["health_status"] == "account_deactivated"
    assert _row(restarted, "healthy@example.test")["health_status"] == "plus"

