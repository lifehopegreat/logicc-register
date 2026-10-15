"""Lifecycle metadata for the standalone Free account pool.

Credentials stay in ``core/account_vault.py``.  This small SQLite store only
tracks operational state so a large backup pool can be safely split into
registration batches and later joined with status-poll results.
"""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from zoneinfo import ZoneInfo


POOL_STATES = {"spare", "reserved", "registered", "failed"}
HEALTHY_STATUSES = {"logicc_ready", "free", "plus", "k12", "plus_expired"}
INCONCLUSIVE_HEALTH_STATUSES = {
    "error",
    "rt_revoked",
    "no_token",
    "token_dead",
    "protocol_login_failed",
    "browser_login_failed",
    "unknown_no_creds",
}
TERMINAL_REGISTRATION_ERRORS = ("account_deactivated",)


def _is_terminal_registration_error(error: str) -> bool:
    text = str(error or "").strip().lower()
    return any(marker in text for marker in TERMINAL_REGISTRATION_ERRORS)


def _is_retryable_registration_error(error: str) -> bool:
    return not _is_terminal_registration_error(error)


def _http_auth_failure_reason(row: dict[str, Any]) -> str:
    text = " ".join(str(row.get(field) or "").lower() for field in (
        "ban_reason",
        "error",
        "probe_error",
        "refresh_error",
        "check_error",
    ))
    if "http_401" in text:
        return "http_401"
    if "http_403" in text:
        return "http_403"
    return ""


def _is_at_probe_token_failure(row: dict[str, Any]) -> bool:
    """Recognize a stale AT 401/403 without treating the account as dead."""
    source = str(row.get("deactivation_source") or "").strip().lower()
    if source in {"protocol", "protocol_login", "protocol-login"}:
        return False
    status = str(row.get("status") or row.get("health_status") or "").strip().lower()
    primary_error = str(row.get("error") or row.get("check_error") or "").lower()
    if (
        status == "account_deactivated"
        and "at_probe_failed" not in primary_error
        and ("protocol_login" in primary_error or "deleted or deactivated" in primary_error)
    ):
        return False
    if not _http_auth_failure_reason(row):
        return False
    text = " ".join(str(row.get(field) or "").lower() for field in (
        "error",
        "probe_error",
        "check_error",
        "ban_reason",
    ))
    probe_status = str(row.get("probe_status") or row.get("last_probe_status") or "").strip().lower()
    return bool(
        source in {"access_token", "at", "at_probe", "token_probe"}
        or bool(row.get("at_probe_used"))
        or "at_probe_failed" in text
        or status == "token_dead"
        or probe_status == "token_dead"
    )


def _normalize_at_probe_result(row: dict[str, Any]) -> dict[str, Any]:
    """Convert the legacy AT-only false-ban shape into ``token_dead``."""
    normalized = dict(row)
    if not _is_at_probe_token_failure(normalized):
        return normalized
    status = str(normalized.get("status") or "").strip().lower()
    probe_status = str(normalized.get("probe_status") or status).strip().lower()
    if status == "account_deactivated":
        normalized["status"] = "token_dead"
    if probe_status == "account_deactivated" or status == "account_deactivated":
        normalized["probe_status"] = "token_dead"
    for field in ("error", "probe_error"):
        if normalized.get(field):
            normalized[field] = str(normalized[field]).replace(
                "account_deactivated:", "token_dead:"
            )
    return normalized


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_time(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        # Older workbench exports used a bare Beijing local timestamp. All
        # new console writes are ISO UTC, but interpreting legacy values as
        # UTC would shift the derived duration by eight hours.
        parsed = parsed.replace(tzinfo=ZoneInfo("Asia/Shanghai"))
    return parsed.astimezone(timezone.utc)


class AccountRegistry:
    """Persistent non-secret account state with atomic batch reservations."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 15000")
        return connection

    def _init_schema(self) -> None:
        with self._lock, self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS pool_accounts (
                    email TEXT PRIMARY KEY,
                    kind TEXT NOT NULL DEFAULT '',
                    source_file TEXT NOT NULL DEFAULT '',
                    imported_at TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL DEFAULT 'spare',
                    current_job_id TEXT NOT NULL DEFAULT '',
                    last_job_id TEXT NOT NULL DEFAULT '',
                    registered_at TEXT NOT NULL DEFAULT '',
                    registration_status TEXT NOT NULL DEFAULT '',
                    registration_error TEXT NOT NULL DEFAULT '',
                    last_checked_at TEXT NOT NULL DEFAULT '',
                    last_confirmed_at TEXT NOT NULL DEFAULT '',
                    last_probe_status TEXT NOT NULL DEFAULT '',
                    health_status TEXT NOT NULL DEFAULT '',
                    health_alive INTEGER,
                    plan_type TEXT NOT NULL DEFAULT '',
                    manual_plan_type TEXT NOT NULL DEFAULT '',
                    plan_source TEXT NOT NULL DEFAULT '',
                    active_until TEXT NOT NULL DEFAULT '',
                    trial_status TEXT NOT NULL DEFAULT '',
                    manual_trial_status TEXT NOT NULL DEFAULT '',
                    trial_eligible INTEGER,
                    trial_campaign TEXT NOT NULL DEFAULT '',
                    trial_checked_at TEXT NOT NULL DEFAULT '',
                    trial_error TEXT NOT NULL DEFAULT '',
                    check_tier INTEGER NOT NULL DEFAULT 0,
                    check_error TEXT NOT NULL DEFAULT '',
                    observed_seconds INTEGER,
                    last_banned_at TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS pool_accounts_state_idx
                    ON pool_accounts(state, imported_at, email);
                CREATE INDEX IF NOT EXISTS pool_accounts_job_idx
                    ON pool_accounts(current_job_id);
                CREATE INDEX IF NOT EXISTS pool_accounts_health_idx
                    ON pool_accounts(health_status, last_checked_at);
                """
            )
            # ``CREATE TABLE IF NOT EXISTS`` does not evolve an existing
            # operator database. Keep the historical single timestamp as a
            # best-effort confirmation until its next probe supplies the two
            # distinct timestamps below.
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(pool_accounts)").fetchall()
            }
            for column, definition in (
                ("last_confirmed_at", "TEXT NOT NULL DEFAULT ''"),
                ("last_probe_status", "TEXT NOT NULL DEFAULT ''"),
                ("plan_source", "TEXT NOT NULL DEFAULT ''"),
                ("manual_plan_type", "TEXT NOT NULL DEFAULT ''"),
                ("trial_status", "TEXT NOT NULL DEFAULT ''"),
                ("manual_trial_status", "TEXT NOT NULL DEFAULT ''"),
                ("trial_eligible", "INTEGER"),
                ("trial_campaign", "TEXT NOT NULL DEFAULT ''"),
                ("trial_checked_at", "TEXT NOT NULL DEFAULT ''"),
                ("trial_error", "TEXT NOT NULL DEFAULT ''"),
            ):
                if column not in columns:
                    connection.execute(f"ALTER TABLE pool_accounts ADD COLUMN {column} {definition}")
            connection.execute(
                """
                UPDATE pool_accounts
                SET last_confirmed_at = last_checked_at
                WHERE last_confirmed_at = ''
                    AND last_probe_status = ''
                    AND health_status IN ('free', 'plus', 'k12', 'plus_expired')
                    AND last_checked_at <> ''
                """
            )
            connection.execute(
                """
                UPDATE pool_accounts
                SET last_probe_status = health_status
                WHERE last_probe_status = '' AND health_status <> ''
                """
            )
            # Versions before the standalone RT/AT poll treated a stale
            # access token's 401/403 as a deactivated account.  Repair that
            # persisted false-positive shape during startup so operators do
            # not need to wait for a later poll to clear the red status.
            connection.execute(
                """
                UPDATE pool_accounts
                SET health_status = 'token_dead',
                    health_alive = NULL,
                    last_probe_status = 'token_dead',
                    check_error = REPLACE(check_error, 'account_deactivated:', 'token_dead:'),
                    last_banned_at = ''
                WHERE health_status = 'account_deactivated'
                    AND lower(check_error) LIKE '%at_probe_failed%'
                    AND (
                        lower(check_error) LIKE '%http_401%'
                        OR lower(check_error) LIKE '%http_403%'
                    )
                """
            )
            # Registration may be the first authoritative place where the
            # server says that an account is deleted/deactivated.  Older
            # builds only persisted ``registration_error``; after a service
            # restart those rows therefore looked like unprobed accounts.
            # Run after the old AT false-positive repair and preserve later
            # Free/Plus evidence.
            connection.execute(
                """
                UPDATE pool_accounts
                SET health_status = 'account_deactivated',
                    health_alive = 0,
                    last_probe_status = 'account_deactivated',
                    check_error = 'registration_terminal: account_deactivated',
                    last_banned_at = CASE
                        WHEN last_banned_at = '' THEN COALESCE(NULLIF(updated_at, ''), ?)
                        ELSE last_banned_at
                    END
                WHERE lower(registration_error) LIKE '%account_deactivated%'
                    AND lower(COALESCE(health_status, '')) NOT IN ('free', 'plus', 'k12', 'plus_expired')
                    AND lower(COALESCE(check_error, '')) NOT LIKE '%at_probe_failed%'
                """,
                (utc_now(),),
            )
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def sync_pool(self, records: dict[str, str]) -> int:
        """Upsert credential-pool metadata without touching lifecycle state."""
        now = utc_now()
        rows: list[tuple[str, str, str, str, str]] = []
        for email, raw in records.items():
            key = str(email or "").strip().casefold()
            if not key:
                continue
            parts = str(raw or "").split("----")
            kind = "icloud" if len(parts) == 2 and parts[1].strip().startswith(("http://", "https://")) else "outlook"
            source = "icloud_accounts.txt" if kind == "icloud" else "outlook_accounts.txt"
            rows.append((key, kind, source, now, now))
        if not rows:
            return 0
        with self._lock, self._connect() as connection:
            connection.executemany(
                """
                INSERT INTO pool_accounts(email, kind, source_file, imported_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    kind = excluded.kind,
                    source_file = excluded.source_file,
                    updated_at = excluded.updated_at
                """,
                rows,
            )
        return len(rows)

    def prune_unregistered_missing_credentials(self, emails: Iterable[str]) -> int:
        """Drop obsolete spare/failed rows after a full replacement import.

        Registered rows remain as historical account inventory even if their
        original mailbox credential is intentionally removed from the backup
        pool.
        """
        present = [str(email).strip().casefold() for email in emails if str(email).strip()]
        with self._lock, self._connect() as connection:
            if present:
                placeholders = ",".join("?" for _ in present)
                cursor = connection.execute(
                    f"DELETE FROM pool_accounts WHERE state IN ('spare', 'failed') AND email NOT IN ({placeholders})",
                    present,
                )
            else:
                cursor = connection.execute("DELETE FROM pool_accounts WHERE state IN ('spare', 'failed')")
        return int(cursor.rowcount)

    def summary(self) -> dict[str, int]:
        with self._lock, self._connect() as connection:
            state_rows = connection.execute(
                "SELECT state, COUNT(*) AS count FROM pool_accounts GROUP BY state"
            ).fetchall()
            health_rows = connection.execute(
                "SELECT health_status, COUNT(*) AS count FROM pool_accounts GROUP BY health_status"
            ).fetchall()
        result = {state: 0 for state in POOL_STATES}
        result.update({str(row["state"]): int(row["count"]) for row in state_rows})
        result["total"] = sum(result[state] for state in POOL_STATES)
        result["alive"] = sum(
            int(row["count"])
            for row in health_rows
            if str(row["health_status"] or "") in HEALTHY_STATUSES
        )
        result["unchecked"] = sum(
            int(row["count"])
            for row in health_rows
            if not str(row["health_status"] or "")
        )
        return result

    def list_accounts(
        self,
        *,
        state: str = "",
        query: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        values: list[Any] = []
        if state in POOL_STATES:
            clauses.append("state = ?")
            values.append(state)
        if query.strip():
            clauses.append("email LIKE ?")
            values.append(f"%{query.strip().casefold()}%")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        safe_limit = max(1, min(int(limit or 100), 1000))
        safe_offset = max(0, int(offset or 0))
        with self._lock, self._connect() as connection:
            total = int(connection.execute(
                f"SELECT COUNT(*) AS count FROM pool_accounts {where}", values
            ).fetchone()["count"])
            rows = connection.execute(
                f"""
                SELECT * FROM pool_accounts {where}
                ORDER BY
                    CASE state WHEN 'spare' THEN 0 WHEN 'failed' THEN 1 WHEN 'reserved' THEN 2 ELSE 3 END,
                    imported_at, email
                LIMIT ? OFFSET ?
                """,
                [*values, safe_limit, safe_offset],
            ).fetchall()
        return [self._public_row(dict(row)) for row in rows], total

    def lookup(self, emails: Iterable[str]) -> dict[str, dict[str, Any]]:
        normalized = [str(email).strip().casefold() for email in emails if str(email).strip()]
        if not normalized:
            return {}
        placeholders = ",".join("?" for _ in normalized)
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM pool_accounts WHERE email IN ({placeholders})", normalized
            ).fetchall()
        return {str(row["email"]): self._public_row(dict(row)) for row in rows}

    def delete(self, email: str) -> bool:
        """Remove one local lifecycle row by normalized email."""
        key = str(email or "").strip().casefold()
        if not key:
            return False
        with self._lock, self._connect() as connection:
            cursor = connection.execute("DELETE FROM pool_accounts WHERE email = ?", (key,))
        return cursor.rowcount == 1

    def set_manual_plan(self, email: str, plan_type: str) -> None:
        key = str(email or "").strip().casefold()
        plan = str(plan_type or "").strip().lower()
        if not key or "@" not in key:
            raise ValueError("邮箱格式无效")
        if plan not in {"", "free", "plus"}:
            raise ValueError("套餐标签只能是 FREE、PLUS 或自动检测")
        now = utc_now()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO pool_accounts(email, imported_at, updated_at, manual_plan_type)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    manual_plan_type = excluded.manual_plan_type,
                    updated_at = excluded.updated_at
                """,
                (key, now, now, plan),
            )

    def set_manual_trial(self, email: str, trial_status: str) -> None:
        key = str(email or "").strip().casefold()
        status = str(trial_status or "").strip().lower()
        if not key or "@" not in key:
            raise ValueError("邮箱格式无效")
        if status not in {"", "eligible", "not_eligible"}:
            raise ValueError("试用标签只能是有资格、无资格或自动检测")
        now = utc_now()
        with self._lock, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO pool_accounts(email, imported_at, updated_at, manual_trial_status)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(email) DO UPDATE SET
                    manual_trial_status = excluded.manual_trial_status,
                    updated_at = excluded.updated_at
                """,
                (key, now, now, status),
            )

    def choose_batch(
        self,
        *,
        count: int,
        requested: Iterable[str] | None = None,
        include_failed: bool = False,
    ) -> list[str]:
        desired = max(1, min(int(count or 1), 500))
        requested_rows = [str(item).strip().casefold() for item in (requested or []) if str(item).strip()]
        allowed = ("spare", "failed") if include_failed else ("spare",)
        with self._lock, self._connect() as connection:
            if requested_rows:
                placeholders = ",".join("?" for _ in requested_rows)
                rows = connection.execute(
                    f"SELECT email, state, registration_error FROM pool_accounts WHERE email IN ({placeholders})",
                    requested_rows,
                ).fetchall()
                states = {
                    str(row["email"]): (
                        str(row["state"]),
                        _is_retryable_registration_error(str(row["registration_error"] or "")),
                    )
                    for row in rows
                }
                return [
                    email for email in requested_rows
                    if states.get(email, ("", False))[0] in allowed
                    and (states[email][0] != "failed" or states[email][1])
                ][:desired]
            placeholders = ",".join("?" for _ in allowed)
            rows = connection.execute(
                f"""
                SELECT email FROM pool_accounts
                WHERE state IN ({placeholders})
                    AND (state != 'failed' OR COALESCE(registration_error, '') NOT LIKE '%account_deactivated%')
                ORDER BY imported_at, email
                LIMIT ?
                """,
                [*allowed, desired],
            ).fetchall()
        return [str(row["email"]) for row in rows]

    def reserve_each(self, job_id_by_email: dict[str, str], *, include_failed: bool = False) -> list[str]:
        """Atomically reserve accounts while giving each row its own owner job.

        A batch reserves many accounts at once but every account is executed by
        its own child process.  Stamping the whole set with one batch id would
        leave each row waiting for a job that never owns it, so the set is
        claimed atomically here and then pointed at the member that will
        actually report the result.
        """
        pairs = [(str(email).strip().casefold(), str(job_id))
                 for email, job_id in job_id_by_email.items() if str(email).strip()]
        if not pairs:
            return []
        requested = [email for email, _job in pairs]
        owner = dict(pairs)
        allowed = ("spare", "failed") if include_failed else ("spare",)
        placeholders = ",".join("?" for _ in requested)
        allowed_placeholders = ",".join("?" for _ in allowed)
        now = utc_now()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                f"SELECT email, state, registration_error FROM pool_accounts WHERE email IN ({placeholders})", requested
            ).fetchall()
            available = {
                str(row["email"])
                for row in rows
                if str(row["state"]) in allowed
                and (
                    str(row["state"]) != "failed"
                    or _is_retryable_registration_error(str(row["registration_error"] or ""))
                )
            }
            selected = [email for email in requested if email in available]
            if selected:
                selected_placeholders = ",".join("?" for _ in selected)
                connection.executemany(
                    f"""
                    UPDATE pool_accounts
                    SET state = 'reserved', current_job_id = ?, last_job_id = ?, updated_at = ?
                    WHERE email = ? AND state IN ({allowed_placeholders})
                    """,
                    [(owner[email], owner[email], now, email, *allowed) for email in selected],
                )
            connection.commit()
        return selected

    def reserve(self, job_id: str, emails: Iterable[str], *, include_failed: bool = False) -> list[str]:
        requested = [str(email).strip().casefold() for email in emails if str(email).strip()]
        if not requested:
            return []
        allowed = ("spare", "failed") if include_failed else ("spare",)
        placeholders = ",".join("?" for _ in requested)
        allowed_placeholders = ",".join("?" for _ in allowed)
        now = utc_now()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                f"SELECT email, state, registration_error FROM pool_accounts WHERE email IN ({placeholders})", requested
            ).fetchall()
            available = {
                str(row["email"])
                for row in rows
                if str(row["state"]) in allowed
                and (
                    str(row["state"]) != "failed"
                    or _is_retryable_registration_error(str(row["registration_error"] or ""))
                )
            }
            selected = [email for email in requested if email in available]
            if selected:
                selected_placeholders = ",".join("?" for _ in selected)
                connection.execute(
                    f"""
                    UPDATE pool_accounts
                    SET state = 'reserved', current_job_id = ?, last_job_id = ?, updated_at = ?
                    WHERE email IN ({selected_placeholders}) AND state IN ({allowed_placeholders})
                    """,
                    [job_id, job_id, now, *selected, *allowed],
                )
            connection.commit()
        return selected

    def release(self, job_id: str) -> int:
        now = utc_now()
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE pool_accounts
                SET state = 'spare', current_job_id = '', updated_at = ?
                WHERE current_job_id = ? AND state = 'reserved'
                """,
                (now, job_id),
            )
        return int(cursor.rowcount)

    def release_batch(self, job_ids: Iterable[str]) -> int:
        """Release reservations owned by a set of member jobs."""
        owners = [str(job_id) for job_id in job_ids if str(job_id)]
        if not owners:
            return 0
        now = utc_now()
        placeholders = ",".join("?" for _ in owners)
        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                f"""
                UPDATE pool_accounts
                SET state = 'spare', current_job_id = '', updated_at = ?
                WHERE current_job_id IN ({placeholders}) AND state = 'reserved'
                """,
                (now, *owners),
            )
        return int(cursor.rowcount)

    def record_job_results(self, job_id: str, results: Iterable[dict[str, Any]], *, final_state: str = "completed") -> None:
        by_email = {
            str(row.get("email") or "").strip().casefold(): row
            for row in results
            if isinstance(row, dict) and str(row.get("email") or "").strip()
        }
        now = utc_now()
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            assigned = connection.execute(
                "SELECT email FROM pool_accounts WHERE current_job_id = ?", (job_id,)
            ).fetchall()
            for item in assigned:
                email = str(item["email"])
                row = by_email.get(email)
                if row is not None and (bool(row.get("ok")) or bool(row.get("registration_ok"))):
                    registered_at = str(row.get("registered_at") or now)
                    connection.execute(
                        """
                        UPDATE pool_accounts
                        SET state = 'registered', current_job_id = '', last_job_id = ?,
                            registered_at = CASE WHEN registered_at = '' THEN ? ELSE registered_at END,
                            registration_status = ?, registration_error = '', updated_at = ?
                        WHERE email = ?
                        """,
                        (job_id, registered_at, str(row.get("status") or "registered"), now, email),
                    )
                elif row is not None and row.get("status") in {"human_required", "code_required", "needs_check", "rate_limited", "partial"}:
                    connection.execute(
                        "UPDATE pool_accounts SET registration_status = ?, registration_error = ?, updated_at = ? WHERE email = ?",
                        (row["status"], str(row.get("error") or "")[:500], now, email),
                    )
                elif row is not None:
                    error = str(row.get("error") or "registration_failed")[:500]
                    if _is_terminal_registration_error(error):
                        connection.execute(
                            """
                            UPDATE pool_accounts
                            SET state = 'failed', current_job_id = '', last_job_id = ?,
                                registration_status = ?, registration_error = ?, updated_at = ?,
                                health_status = 'account_deactivated', health_alive = 0,
                                last_probe_status = 'account_deactivated',
                                check_error = 'registration_terminal: account_deactivated',
                                last_banned_at = CASE WHEN last_banned_at = '' THEN ? ELSE last_banned_at END
                            WHERE email = ?
                            """,
                            (job_id, str(row.get("status") or "failed"), error, now, now, email),
                        )
                    else:
                        connection.execute(
                            """
                            UPDATE pool_accounts
                            SET state = 'failed', current_job_id = '', last_job_id = ?,
                                registration_status = ?, registration_error = ?, updated_at = ?
                            WHERE email = ?
                            """,
                            (job_id, str(row.get("status") or "failed"), error, now, email),
                        )
                elif final_state in {"stopped", "interrupted"}:
                    connection.execute(
                        "UPDATE pool_accounts SET state = 'spare', current_job_id = '', updated_at = ? WHERE email = ?",
                        (now, email),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE pool_accounts
                        SET state = 'failed', current_job_id = '', last_job_id = ?,
                            registration_status = 'missing_result', registration_error = 'task_finished_without_result', updated_at = ?
                        WHERE email = ?
                        """,
                        (job_id, now, email),
                    )
            connection.commit()

    def record_registered_results(self, job_id: str, results: Iterable[dict[str, Any]]) -> int:
        """Archive successful registrations, including jobs started from pasted input."""
        now = utc_now()
        updated = 0
        with self._lock, self._connect() as connection:
            for row in results:
                if not isinstance(row, dict) or not (bool(row.get("ok")) or bool(row.get("registration_ok"))):
                    continue
                email = str(row.get("email") or "").strip().casefold()
                if not email:
                    continue
                registered_at = str(row.get("registered_at") or now)
                cursor = connection.execute(
                    """
                    INSERT INTO pool_accounts(
                        email, source_file, imported_at, updated_at, state,
                        current_job_id, last_job_id, registered_at,
                        registration_status, registration_error
                    ) VALUES (?, 'task_result', ?, ?, 'registered', '', ?, ?, ?, '')
                    ON CONFLICT(email) DO UPDATE SET
                        state = 'registered', current_job_id = '', last_job_id = excluded.last_job_id,
                        registered_at = CASE
                            WHEN pool_accounts.registered_at = '' THEN excluded.registered_at
                            ELSE pool_accounts.registered_at
                        END,
                        registration_status = excluded.registration_status,
                        registration_error = '', updated_at = excluded.updated_at
                    """,
                    (
                        email,
                        now,
                        now,
                        job_id,
                        registered_at,
                        str(row.get("status") or "registered"),
                    ),
                )
                updated += int(cursor.rowcount)
        self.refresh_observed_seconds()
        return updated

    def apply_health_results(self, rows: Iterable[dict[str, Any]]) -> int:
        now = utc_now()
        updated = 0
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for row in rows:
                if not isinstance(row, dict):
                    continue
                # ``run_token_only_status_poll`` normally receives the
                # normalized core result.  Keep this second guard at the
                # standalone boundary for old snapshots and mocked/legacy
                # workers that still send AT 401/403 as account_deactivated.
                row = _normalize_at_probe_result(row)
                email = str(row.get("email") or "").strip().casefold()
                if not email:
                    continue
                status = str(row.get("status") or "").strip().lower()
                probe_status = str(row.get("probe_status") or status).strip().lower()
                checked_at = str(row.get("probe_checked_at") or row.get("last_checked") or now)
                plan_type = str(row.get("plan_type") or "")
                plan_source = str(row.get("plan_source") or "")
                active_until = str(row.get("active_until") or "")
                trial_status = str(row.get("free_trial_status") or "").strip().lower()
                trial_eligible = row.get("free_trial_eligible")
                trial_eligible = None if trial_eligible is None else int(bool(trial_eligible))
                trial_campaign = str(row.get("free_trial_campaign") or "")
                trial_checked_at = str(row.get("free_trial_checked_at") or "")
                trial_error = str(row.get("free_trial_error") or "")[:500]
                check_error = str(row.get("probe_error") or row.get("error") or "")[:500]
                try:
                    check_tier = int(row.get("probe_tier") or row.get("tier") or 0)
                except (TypeError, ValueError):
                    check_tier = 0

                # The workbench keeps a confirmed plan when a later probe is
                # inconclusive. Preserve that behavior here as a second line
                # of defense for manually imported or older worker results.
                previous = connection.execute(
                    """
                    SELECT health_status, health_alive, plan_type, plan_source, active_until,
                        trial_status, trial_eligible, trial_campaign, trial_checked_at, trial_error,
                        check_tier, last_checked_at, last_confirmed_at, last_probe_status, check_error
                    FROM pool_accounts WHERE email = ?
                    """,
                    (email,),
                ).fetchone()
                previous_status = str(previous["health_status"] or "").lower() if previous else ""
                previous_is_trusted_deactivation = bool(
                    previous
                    and previous_status == "account_deactivated"
                    and not _is_at_probe_token_failure(dict(previous))
                )
                clear_stale_banned_at = bool(
                    previous
                    and previous_status == "account_deactivated"
                    and _is_at_probe_token_failure(dict(previous))
                    and status != "account_deactivated"
                )
                previous_confirmed_at = ""
                if previous and previous_status in HEALTHY_STATUSES:
                    previous_confirmed_at = str(
                        previous["last_confirmed_at"] or previous["last_checked_at"] or ""
                    )
                if status in INCONCLUSIVE_HEALTH_STATUSES and (
                    previous_status in HEALTHY_STATUSES or previous_is_trusted_deactivation
                ):
                    status = previous_status
                    plan_type = str(previous["plan_type"] or "")
                    plan_source = str(previous["plan_source"] or "")
                    active_until = str(previous["active_until"] or "")
                    check_tier = int(previous["check_tier"] or check_tier)
                if previous and trial_status not in {"eligible", "not_eligible"}:
                    trial_status = str(previous["trial_status"] or trial_status)
                    trial_eligible = previous["trial_eligible"]
                    trial_campaign = str(previous["trial_campaign"] or trial_campaign)
                    trial_checked_at = str(previous["trial_checked_at"] or trial_checked_at)

                # ``status`` is the last authoritative plan, while
                # ``probe_status`` describes this probe attempt. A merged
                # transient failure therefore keeps the historical plan but
                # must never advance its confirmation timestamp.
                if status in HEALTHY_STATUSES:
                    if probe_status in HEALTHY_STATUSES:
                        confirmed_at = str(
                            row.get("confirmed_at")
                            or row.get("last_checked")
                            or row.get("probe_checked_at")
                            or checked_at
                        )
                    elif str(row.get("status") or "").strip().lower() in HEALTHY_STATUSES:
                        # Workbench-merged rows retain the earlier confirmed
                        # plan and its original ``last_checked`` value.
                        confirmed_at = str(
                            row.get("confirmed_at")
                            or row.get("last_checked")
                            or previous_confirmed_at
                        )
                    else:
                        confirmed_at = previous_confirmed_at
                else:
                    confirmed_at = previous_confirmed_at

                if status in HEALTHY_STATUSES:
                    alive: int | None = 1
                elif status == "account_deactivated":
                    alive = 0
                else:
                    # A credential, OTP, protocol, or network failure does
                    # not establish that the account is dead.
                    alive = None
                cursor = connection.execute(
                    """
                    UPDATE pool_accounts
                    SET last_checked_at = ?, last_confirmed_at = ?, last_probe_status = ?,
                        health_status = ?, health_alive = ?,
                        plan_type = ?, plan_source = ?, active_until = ?,
                        trial_status = ?, trial_eligible = ?, trial_campaign = ?,
                        trial_checked_at = ?, trial_error = ?, check_tier = ?, check_error = ?,
                        last_banned_at = CASE
                            WHEN ? = 'account_deactivated' THEN ?
                            WHEN ? THEN ''
                            ELSE last_banned_at
                        END,
                        updated_at = ?
                    WHERE email = ?
                    """,
                    (
                        checked_at,
                        confirmed_at,
                        probe_status,
                        status,
                        alive,
                        plan_type,
                        plan_source,
                        active_until,
                        trial_status,
                        trial_eligible,
                        trial_campaign,
                        trial_checked_at,
                        trial_error,
                        check_tier,
                        check_error,
                        probe_status,
                        str(row.get("banned_at") or checked_at),
                        clear_stale_banned_at,
                        now,
                        email,
                    ),
                )
                updated += int(cursor.rowcount)
            connection.commit()
        self.refresh_observed_seconds()
        return updated

    def apply_survival_rows(self, rows: Iterable[dict[str, Any]]) -> int:
        """Import only legacy registration timestamps from the core report.

        Standalone registrations write their own result JSONL, so the core
        report is not a health source. In particular it must not overwrite
        the confirmation-bounded duration calculated below.
        """
        updated = 0
        now = utc_now()
        with self._lock, self._connect() as connection:
            for row in rows:
                if not isinstance(row, dict):
                    continue
                email = str(row.get("email") or "").strip().casefold()
                if not email:
                    continue
                cursor = connection.execute(
                    """
                    UPDATE pool_accounts
                    SET registered_at = CASE WHEN registered_at = '' THEN ? ELSE registered_at END,
                        updated_at = ?
                    WHERE email = ?
                    """,
                    (
                        str(row.get("registered_at") or ""),
                        now,
                        email,
                    ),
                )
                updated += int(cursor.rowcount)
        self.refresh_observed_seconds()
        return updated

    def refresh_observed_seconds(self) -> None:
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT email, registered_at, last_confirmed_at
                FROM pool_accounts WHERE registered_at <> ''
                """
            ).fetchall()
            for row in rows:
                registered = _parse_time(str(row["registered_at"] or ""))
                if registered is None:
                    continue
                confirmed = _parse_time(str(row["last_confirmed_at"] or ""))
                seconds = (
                    max(0, int((confirmed - registered).total_seconds()))
                    if confirmed is not None
                    else None
                )
                connection.execute(
                    "UPDATE pool_accounts SET observed_seconds = ? WHERE email = ?",
                    (seconds, str(row["email"])),
                )

    @staticmethod
    def _public_row(row: dict[str, Any]) -> dict[str, Any]:
        row["health_alive"] = None if row.get("health_alive") is None else bool(row["health_alive"])
        row["trial_eligible"] = None if row.get("trial_eligible") is None else bool(row["trial_eligible"])
        row["observed_seconds"] = None if row.get("observed_seconds") is None else int(row["observed_seconds"])
        return row
