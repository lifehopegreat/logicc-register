#!/usr/bin/env python3
"""Local Logicc console: mailbox management and retained task infrastructure."""
from __future__ import annotations

import hmac
import importlib.util
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx
from flask import Flask, Response, jsonify, render_template, request, send_file

from account_registry import AccountRegistry


ROOT = Path(__file__).resolve().parent
CORE = ROOT / "core"
DATA = Path(os.environ.get("LOGICC_CONSOLE_DATA_DIR") or ROOT / "data").resolve()
JOB_DIR = DATA / "jobs"
INPUT_DIR = DATA / "inputs"
OUTPUT = Path(os.environ.get("LOGICC_CONSOLE_OUTPUT_DIR") or ROOT / "output").resolve()
RESULT_DIR = OUTPUT / "results"
SETTINGS_FILE = DATA / "settings.json"
DOMAIN_MAILBOX_RUNTIME_FILE = DATA / "domain_mailbox_runtime.json"
_VENV_PYTHON = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
PYTHON = os.environ.get("FREE_CONSOLE_PYTHON") or str(_VENV_PYTHON if _VENV_PYTHON.exists() else Path(sys.executable))
WINDOWS_DLL_INIT_FAILED = 0xC0000142

# Keep the runner, mailbox refresh path and console on one encrypted vault.
os.environ.setdefault("ACCOUNT_VAULT_DIR", str(DATA / "account_vault"))

if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

from logicc_register import WAITING, generated_config, save_private, load_private
from account_vault import ImportValidationError, _validate_email
from capmonster import CapMonster, CapMonsterError
from logicc2api import Logicc2Api, IntegrationError, local_base_url
from proxy_connectivity import pin_proxy, probe_proxy
from proxy_pool import assign_proxy_round_robin, normalize_pool_rows, infer_proxy_region
from paylink_proxy import normalize_proxy_url

# Batch workbench limits.  These are hard caps on one pasted launch request,
# not suggestions: they bound the reserve transaction, the encrypted input
# files written per child and the number of concurrent runner processes.
MAX_BATCH_ACCOUNTS = 100
MAX_BATCH_PROXIES = 100
MAX_BATCH_WORKERS = 32

BATCH_DIR = DATA / "batches"

for directory in (DATA, JOB_DIR, INPUT_DIR, OUTPUT, RESULT_DIR, BATCH_DIR):
    directory.mkdir(parents=True, exist_ok=True)


def validate_runtime() -> None:
    if _VENV_PYTHON.exists() and Path(sys.prefix).resolve() != _VENV_PYTHON.parent.parent.resolve():
        raise SystemExit(f"请使用当前项目环境启动：{_VENV_PYTHON} app.py")


def acquire_instance_lock():
    if os.name != "nt":
        return None
    import msvcrt

    handle = (DATA / ".console.lock").open("a+b")
    if handle.seek(0, os.SEEK_END) == 0:
        handle.write(b"0")
        handle.flush()
    handle.seek(0)
    try:
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError:
        handle.close()
        raise SystemExit("当前项目服务已经运行：http://127.0.0.1:8866") from None
    return handle


INSTANCE_LOCK = None
if __name__ == "__main__":
    validate_runtime()
    INSTANCE_LOCK = acquire_instance_lock()





app = Flask(__name__, template_folder=str(ROOT / "templates"), static_folder=str(ROOT / "static"))
app.config.update(
    JSON_SORT_KEYS=False,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    SEND_FILE_MAX_AGE_DEFAULT=0,
)


DEFAULT_SETTINGS: dict[str, Any] = {
    "proxy_host": "",
    "proxy_port": "10000",
    "proxy_user": "",
    "proxy_password": "",
    "bitbrowser_api": "http://127.0.0.1:54345",
    "roxy_api_port": "50000",
    "roxy_api_token": "",
    "roxy_workspace_id": "",
    "roxy_api_rate_limit": "45",
    "chrome_path": "",
    "display_timezone": "Asia/Shanghai",
    "domain_mailbox_enabled": "0",
    "domain_mailbox_label": "自建域名邮箱",
    "domain_mailbox_api_origin": "",
    "domain_mailbox_host_header": "",
    "domain_mailbox_default_domain": "",
    "domain_mailbox_domains": "",
    "domain_mailbox_admin_token": "",
    "domain_mailbox_local_part": "",
    "domain_mailbox_request_timeout": "30",
}

SECRET_KEYS = {
    "proxy_password",
    "roxy_api_token",
    "domain_mailbox_admin_token",
}

SETTING_ENV = {
    "proxy_host": "PROXY_HOST",
    "proxy_port": "PROXY_PORT",
    "proxy_user": "PROXY_USER",
    "proxy_password": "PROXY_PASS",
    "bitbrowser_api": "BITBROWSER_API",
    "roxy_api_port": "ROXY_API_PORT",
    "roxy_api_token": "ROXY_API_TOKEN",
    "roxy_workspace_id": "ROXY_WORKSPACE_ID",
    "roxy_api_rate_limit": "ROXY_API_RATE_LIMIT",
    "chrome_path": "CHROME_PATH",
    "display_timezone": "FREE_CONSOLE_TIMEZONE",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def display_timezone_name(settings: dict[str, Any] | None = None) -> str:
    value = str((settings or load_settings()).get("display_timezone") or "Asia/Shanghai").strip()
    try:
        ZoneInfo(value)
        return value
    except ZoneInfoNotFoundError:
        return "Asia/Shanghai"


def apply_process_timezone(settings: dict[str, Any] | None = None) -> str:
    """Keep legacy runtime timestamps aligned with the console display zone."""
    name = display_timezone_name(settings)
    os.environ["TZ"] = name
    if hasattr(time, "tzset"):
        time.tzset()
    return name


def local_now(settings: dict[str, Any] | None = None) -> str:
    zone = ZoneInfo(display_timezone_name(settings))
    return datetime.now(zone).isoformat(timespec="seconds")


def atomic_json(path: Path, payload: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + f".{uuid.uuid4().hex}.tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(temp, mode)
    temp.replace(path)












def load_settings() -> dict[str, Any]:
    data = dict(DEFAULT_SETTINGS)
    stored_keys: set[str] = set()
    if SETTINGS_FILE.exists():
        try:
            stored = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            if isinstance(stored, dict):
                saved = {key: stored[key] for key in DEFAULT_SETTINGS if key in stored}
                data.update(saved)
                stored_keys.update(saved)
        except (OSError, ValueError):
            pass
    for key, env_name in SETTING_ENV.items():
        # .env seeds a fresh install. Once the UI has saved a key, its value is
        # authoritative so template defaults (for example country=12) cannot
        # silently replace the operator's choice (for example country=145).
        env_value = os.environ.get(env_name)
        if key not in stored_keys and env_value is not None and str(env_value).strip() != "":
            data[key] = env_value
    return data




def write_domain_mailbox_runtime_config(settings: dict[str, Any] | None = None) -> Path | None:
    """Publish token-free mailbox routing for child registration workers."""
    current = settings or load_settings()
    if not (
        str(current.get("domain_mailbox_api_origin") or "").strip()
        and str(current.get("domain_mailbox_default_domain") or "").strip()
    ):
        return None
    try:
        from domain_mailbox import runtime_config_payload

        payload = runtime_config_payload(current)
    except (ImportError, ValueError, RuntimeError):
        return None
    path = DATA / "domain_mailbox_runtime.json"
    atomic_json(path, payload)
    return path


def domain_mailbox_enabled(settings: dict[str, Any] | None = None) -> bool:
    value = str((settings or load_settings()).get("domain_mailbox_enabled") or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def validate_domain_mailbox_settings(
    settings: dict[str, Any],
    *,
    require_admin_token: bool = False,
) -> None:
    configured = any(str(settings.get(key) or "").strip() for key in (
        "domain_mailbox_api_origin",
        "domain_mailbox_host_header",
        "domain_mailbox_default_domain",
        "domain_mailbox_domains",
        "domain_mailbox_admin_token",
    ))
    if not configured and not require_admin_token:
        return
    from domain_mailbox import provider_from_runtime_settings

    provider_from_runtime_settings(
        settings,
        require_admin_token=require_admin_token,
    )


def health_check_proxy(settings: dict[str, Any] | None = None) -> str:
    """Build the configured proxy URL for non-browser health probes.

    The standalone health worker previously ignored the proxy configured in
    the console and connected from the local host IP directly. Keep the secret
    in the child environment rather than exposing it in a command or job log.
    """
    current = settings or load_settings()
    host = str(current.get("proxy_host") or "").strip()
    port = str(current.get("proxy_port") or "").strip()
    user = str(current.get("proxy_user") or "").strip()
    password = str(current.get("proxy_password") or "")
    if not (host and port and user):
        return ""
    try:
        parsed_port = int(port)
    except (TypeError, ValueError):
        return ""
    if not 1 <= parsed_port <= 65535:
        return ""
    credentials = urllib.parse.quote(user, safe="")
    if password:
        credentials += ":" + urllib.parse.quote(password, safe="")
    return f"http://{credentials}@{host}:{parsed_port}"


apply_process_timezone()


@app.before_request
def _auth_guard() -> Response | None:
    if request.path == "/api/health":
        return None
    expected = os.environ.get("FREE_CONSOLE_PASSWORD", "")
    if not expected:
        return None
    auth = request.authorization
    if auth and hmac.compare_digest(auth.password or "", expected):
        return None
    return Response("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="Free Console"'})


def clean_account_lines(text: str) -> list[str]:
    rows: list[str] = []
    seen: set[str] = set()
    for raw in str(text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            from mailbox_transport import parse_submail_shipment_line

            shipment = parse_submail_shipment_line(line)
        except (ImportError, ValueError):
            shipment = None
        if shipment:
            line = "----".join(shipment)
        email = line.split("----", 1)[0].strip().lower()
        if "@" not in email or email in seen:
            continue
        seen.add(email)
        rows.append(line)
    return rows


def account_pool_path(name: str) -> Path:
    return DATA / "accounts" / name


def console_vault():
    """Build the console vault against its current durable data paths."""
    from account_vault import AccountVault

    return AccountVault(
        data_dir=DATA / "account_vault",
        outlook_file=account_pool_path("outlook_accounts.txt"),
        icloud_file=account_pool_path("icloud_accounts.txt"),
    )


def _managed_account_rows() -> list[dict[str, Any]]:
    """Publish mailbox readiness and local lifecycle metadata, never credentials."""
    from mailbox_transport import mailbox_display_kind

    registry = sync_pool_registry()
    accounts = console_vault().list_accounts()
    lifecycle = registry.lookup([account.email for account in accounts])
    return [{
        "email": account.email,
        "state": lifecycle.get(account.email.casefold(), {}).get("state", "spare"),
        "mailbox_kind": mailbox_display_kind(account.kind, account.client_id, account.refresh_token),
        "otp_ready": account.has_otp_creds,
        "mail_token_valid": account.token_valid,
        "last_refresh_at": account.last_refresh_at,
        "connectivity_status": lifecycle.get(account.email.casefold(), {}).get("health_status", ""),
        "connectivity_checked_at": lifecycle.get(account.email.casefold(), {}).get("last_checked_at", ""),
        "has_platform_password": platform_password_state(account.email) is not None,
    } for account in accounts]


def platform_password_state(email):
    """Read only a confirmed same-identity checkpoint; never use mailbox passwords."""
    wanted = str(email).strip().casefold()
    jobs = sorted(list(JOBS.values()), key=lambda job: str(job.meta.get("created_at", "")), reverse=True)
    key = console_vault().key_path.read_bytes().strip()
    for job in jobs:
        if job.meta.get("provider") != "logicc" or str(job.meta.get("email", "")).casefold() != wanted:
            continue
        try:
            state = load_private(registration_state_path(job.id), key)
        except (ValueError, OSError):
            continue
        config = state.get("config") or {}
        if not isinstance(config, dict):
            continue
        password = config.get("password")
        if (state.get("registration_ok") is True and state.get("email") == wanted
                and config.get("email") == wanted and isinstance(password, str) and 12 <= len(password) <= 256):
            return state
    return None






def replace_console_vault(vault, text: str) -> dict[str, Any]:
    """Keep replacement imports available after a future core sync."""
    if hasattr(vault, "replace_text"):
        return vault.replace_text(text)
    from account_vault import parse_import_text

    # Validate before touching existing credentials. The fallback supports an
    # older workbench Vault implementation that predates replace_text().
    parse_import_text(text)
    for account in vault.list_accounts():
        vault.delete(account.id)
    return vault.import_text(text, update_existing=True)


def load_pool_records(*, include_success: bool = False) -> dict[str, str]:
    try:
        records = {
            account.email.strip().casefold(): account.raw_line
            for account in console_vault().list_accounts()
            if account.email.strip()
        }
        if records:
            return records
    except Exception:
        # Keep legacy files readable during an interrupted first-time migration.
        pass
    records: dict[str, str] = {}
    for name in ("outlook_accounts.txt", "icloud_accounts.txt"):
        path = account_pool_path(name)
        if not path.exists():
            continue
        for line in clean_account_lines(path.read_text(encoding="utf-8", errors="ignore")):
            records.setdefault(line.split("----", 1)[0].strip().lower(), line)
    if include_success:
        success = CORE / "output" / "outlook_accounts_success.txt"
        if success.exists():
            for line in clean_account_lines(success.read_text(encoding="utf-8", errors="ignore")):
                records.setdefault(line.split("----", 1)[0].strip().lower(), line)
    return records


def pool_registry() -> AccountRegistry:
    return AccountRegistry(DATA / "pool_state.db")


def sync_pool_registry() -> AccountRegistry:
    registry = pool_registry()
    registry.sync_pool(load_pool_records())
    return registry


def record_logicc_connectivity(registry, results):
    rows = []
    for result in results:
        status = result.get("integration_status")
        if result.get("registration_ok") and result.get("onboarding_ok") and status in {"ready", "check_failed"}:
            rows.append({"email": result.get("email"), "status": "logicc_ready" if status == "ready" else "logicc_check_failed",
                         "probe_checked_at": result.get("integration_checked_at") or utc_now(),
                         "error": result.get("integration_error", "")})
    registry.apply_health_results(rows)




def normalize_proxy(value: str) -> str:
    text = normalize_proxy_url(value)
    if not text:
        return ""
    try:
        parsed = urllib.parse.urlsplit(text)
        if (parsed.scheme not in {"http", "https", "socks4", "socks5", "socks5h"}
                or not parsed.hostname or not parsed.port or parsed.path not in {"", "/"}
                or parsed.query or parsed.fragment or any(c in text for c in "\r\n")):
            raise ValueError
    except ValueError:
        raise ValueError("代理地址或协议格式无效") from None
    return text


SERVICES_LOCK = threading.RLock()


def private_service(name):
    path = DATA / "services" / (name + ".enc")
    return load_private(path, console_vault().key_path.read_bytes().strip()) if path.exists() else {}


def save_service(name, payload):
    save_private(DATA / "services" / (name + ".enc"), console_vault().key_path.read_bytes().strip(), payload)


def public_proxies():
    rows = []
    for entry in private_service("proxies").get("entries", []):
        parsed = urllib.parse.urlsplit(entry["proxy"])
        rows.append({"id": entry["id"], "host": parsed.hostname, "port": parsed.port,
                     "region": entry["region"], "label": f"{entry['region']} · {parsed.hostname}:{parsed.port} · {entry['id'][:6]}",
                     "last_check": entry.get("last_check"), "checked_at": entry.get("checked_at")})
    return rows


def managed_proxy(region: str, session_id: str, settings: dict[str, Any]) -> str:
    host = str(settings.get("proxy_host") or "").strip()
    port = int(settings.get("proxy_port") or 0)
    user = str(settings.get("proxy_user") or "").strip()
    password = str(settings.get("proxy_password") or "")
    if not (host and port and user):
        raise ValueError("托管代理尚未配置 host / port / user")
    region = (region or "JP").upper()
    if "-region-" in user:
        user = re.sub(r"-region-[A-Za-z]{2}", f"-region-{region}", user)
    else:
        user = f"{user}-region-{region}"
    user = re.sub(r"-session-[A-Za-z0-9]+(?:-sessTime-\d+)?(?:-sessAuto-\d+)?", "", user)
    user = f"{user}-session-{session_id}-sessTime-10-sessAuto-1"
    return f"http://{urllib.parse.quote(user)}:{urllib.parse.quote(password)}@{host}:{port}"


def safe_tail(path: Path, limit: int = 400) -> list[str]:
    if not path.exists():
        return []
    lines = deque(path.read_bytes().splitlines(), maxlen=max(1, min(limit, 4000)))
    decoded = []
    for line in lines:
        try:
            decoded.append(line.decode("utf-8"))
        except UnicodeDecodeError:
            # ponytail: old Windows jobs mixed our UTF-8 header with a GB18030 child stream.
            decoded.append(line.decode("gb18030", errors="replace"))
    return decoded


def read_results(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return rows
    for raw in text.splitlines():
        try:
            item = json.loads(raw)
            if isinstance(item, dict):
                rows.append(item)
        except ValueError:
            continue
    return rows


class Job:
    def __init__(self, meta: dict[str, Any]):
        self.meta = meta
        self.id = str(meta["id"])
        self.proc: subprocess.Popen[str] | None = None
        self.lock = threading.Lock()
        self.command: list[str] = []
        self.child_env: dict[str, str] = {}

    @property
    def meta_path(self) -> Path:
        return JOB_DIR / f"{self.id}.json"

    @property
    def log_path(self) -> Path:
        return Path(self.meta["log_path"])

    @property
    def result_path(self) -> Path:
        return Path(self.meta["result_path"])

    def save(self) -> None:
        atomic_json(self.meta_path, self.meta)

    def start(self, command: list[str], env: dict[str, str]) -> None:
        self.meta.pop("finished_at", None)
        self.meta.pop("stop_requested", None)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        log_handle = self.log_path.open("a", encoding="utf-8", buffering=1)
        log_handle.write(f"=== Logicc Console task {self.id} · {self.meta['created_at']} · start/resume {utc_now()} ===\n")
        log_handle.write(f"=== runner python={command[0]} cwd={CORE} ===\n")
        child_env = os.environ.copy()
        child_env.update(env)
        child_env["PYTHONUNBUFFERED"] = "1"
        child_env["PYTHONUTF8"] = "1"
        child_env["PYTHONIOENCODING"] = "utf-8"
        self.command = list(command)
        self.child_env = child_env
        try:
            self.proc = self._spawn(log_handle)
        except Exception:
            # Popen can fail before the waiter thread owns the handle.  Close it
            # here so Windows can remove/rotate the failed task log and the API
            # can safely clean the plaintext input files.
            log_handle.close()
            raise
        self.meta.update({"pid": self.proc.pid, "state": "running", "started_at": utc_now()})
        self.save()
        threading.Thread(target=self._wait, args=(log_handle,), daemon=True).start()

    def _spawn(self, log_handle):
        return subprocess.Popen(
            self.command,
            cwd=str(CORE),
            env=self.child_env,
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )

    def _wait(self, log_handle) -> None:
        assert self.proc is not None
        rc = 1
        runner_error = ""
        try:
            rc = self.proc.wait()
            if (
                os.name == "nt"
                and rc & 0xFFFFFFFF == WINDOWS_DLL_INIT_FAILED
                and not self.meta.get("stop_requested")
                and not read_results(self.result_path)
            ):
                log_handle.write("=== Windows DLL initialization failed; restarting runner once ===\n")
                self.proc = self._spawn(log_handle)
                self.meta.update({"pid": self.proc.pid, "restart_count": 1})
                self.save()
                rc = self.proc.wait()
        except Exception as exc:
            runner_error = f"{type(exc).__name__}: {exc}"
            try:
                log_handle.write(f"=== runner wait/restart failed: {runner_error} ===\n")
            except (OSError, ValueError):
                pass
        finally:
            try:
                log_handle.write(f"=== process finished rc={rc} ===\n")
            except (OSError, ValueError):
                pass
            log_handle.close()
        final_state = "completed" if rc == 0 else ("stopped" if self.meta.get("stop_requested") else "failed")
        pool_sync_error = ""
        try:
            registry = pool_registry()
            task_results = read_results(self.result_path)
            if self.meta.get("provider") == "logicc" and (self.meta.get("stop_requested") or not task_results or rc not in {0, 2}):
                state_path = registration_state_path(self.id)
                if state_path.exists():
                    private = load_private(state_path, console_vault().key_path.read_bytes().strip())
                    if private.get("inflight") or private.get("signup_id"):
                        task_results = [{"email": self.meta["email"], "ok": False, "status": "needs_check",
                                         "step": private.get("step"), "error": "worker_interrupted_check_state",
                                         "registration_ok": bool(private.get("registration_ok"))}]
                        console_vault()._atomic_write(
                            self.result_path, (json.dumps(task_results[0]) + "\n").encode(), mode=0o600)
            if task_results and self.meta.get("provider") == "logicc":
                result = task_results[-1]
                if result.get("status") in WAITING:
                    final_state = result["status"]
                if self.meta.get("stop_requested"):
                    final_state = "needs_check"
                self.meta["registration_step"] = result.get("step", "")
            registry.record_registered_results(self.id, task_results)
            record_logicc_connectivity(registry, task_results)
            if self.meta.get("pool_batch"):
                registry.record_job_results(self.id, task_results, final_state=final_state)
        except Exception as exc:
            pool_sync_error = f"{type(exc).__name__}: {exc}"
        with self.lock:
            self.meta.update({
                "rc": rc,
                "state": final_state,
                "finished_at": utc_now(),
            })
            if pool_sync_error:
                self.meta["pool_sync_error"] = pool_sync_error
            if runner_error:
                self.meta["error"] = runner_error
            self.save()
        for path in self.meta.get("cleanup_paths", []):
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                pass

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.meta["stop_requested"] = True
            self.save()
            try:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(self.proc.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                else:
                    os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        elif self.meta.get("provider") == "logicc" and self.meta.get("state") in WAITING:
            key = console_vault().key_path.read_bytes().strip()
            state = load_private(registration_state_path(self.id), key)
            if not state.get("signup_id") and not state.get("inflight"):
                self.meta.update(state="cancelled", finished_at=utc_now())
                pool_registry().release(self.id)
            else:
                self.meta["state"] = "needs_check"
            self.save()

    def snapshot(self, tail: int = 0) -> dict[str, Any]:
        results = read_results(self.result_path)
        total = int(self.meta.get("account_count") or 0)
        success = sum(1 for row in results if row.get("ok"))
        failed = sum(1 for row in results if not row.get("ok") and row.get("status") not in WAITING)
        pending = sum(1 for row in results if row.get("status") in WAITING)
        state = self.meta.get("state", "queued")
        if self.proc is not None and self.proc.poll() is None:
            state = "running"
        progress = round(min(100, len(results) * 100 / total)) if total else 0
        if state == "completed":
            progress = 100
        elif self.meta.get("provider") == "logicc" and results:
            progress = {"client": 5, "captcha": 5, "create_signup": 25, "send_code": 40,
                        "wait_code": 45, "verify": 60, "activate_session": 65,
                        "confirm_account": 70, "language": 75, "profile": 80,
                        "metadata": 85, "create_tenant": 90, "activate_org": 95}.get(results[-1].get("step"), 5)
        payload = {
            **{key: value for key, value in self.meta.items() if key not in {"command"}},
            "state": state,
            "progress": progress,
            "completed_count": success + failed,
            "success_count": success,
            "failed_count": failed,
            "pending_count": pending,
            "result_error": (results[-1].get("error") or "") if results else "",
            "resume_available": self.meta.get("provider") == "logicc" and state in WAITING | {"interrupted"},
            "duration_seconds": self._duration(),
            "retry_available": False,
            "retry_count": max(0, total - success),
        }
        if tail:
            payload["logs"] = safe_tail(self.log_path, tail)
            payload["results"] = [public_result(row) for row in results]
        return payload

    def _duration(self) -> int:
        try:
            started = datetime.fromisoformat(str(self.meta.get("started_at", "")).replace("Z", "+00:00"))
        except ValueError:
            return 0
        end = datetime.now(timezone.utc)
        if self.meta.get("finished_at"):
            try:
                end = datetime.fromisoformat(str(self.meta["finished_at"]).replace("Z", "+00:00"))
            except ValueError:
                pass
        return max(0, int((end - started).total_seconds()))


JOBS: dict[str, Job] = {}
JOBS_LOCK = threading.Lock()


# ── Batched workbench ───────────────────────────────────────────────────────
# One batch = one pasted account list + one pasted proxy list + a worker count.
# Every account still runs the unchanged, already-proven single-account runner
# as its own child process; the batch only decides who starts when and which
# gateway each child is pinned to.

EMAIL_TOKEN_SPLIT = re.compile(r"[\s,;]+")
_PIN_CACHE: dict[str, str] = {}
_PIN_LOCK = threading.Lock()
BATCH_LOCK = threading.RLock()
BATCHES: dict[str, "Batch"] = {}


def parse_pasted_emails(text: str) -> list[str]:
    """Parse one pasted account list into ordered, unique, validated addresses.

    A row that carries credentials (``email----...``) contributes its address;
    a bare address row is kept as-is.  Both forms may be mixed so an operator
    can paste a fresh shipment and an already-imported address together.
    """
    raw = str(text or "")
    if len(raw.encode("utf-8")) > 256 * 1024:
        raise ValueError("账号输入过大")
    tokens: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "----" in stripped:
            tokens.append(stripped)
        else:
            tokens.extend(token for token in EMAIL_TOKEN_SPLIT.split(stripped) if token)
    if not tokens:
        raise ValueError("请粘贴至少一个注册邮箱")
    unique: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        email = token.split("----", 1)[0].strip().casefold()
        _validate_email(email)
        if email in seen:
            continue
        seen.add(email)
        unique.append(email)
    if len(unique) > MAX_BATCH_ACCOUNTS:
        raise ValueError(f"单批最多 {MAX_BATCH_ACCOUNTS} 个邮箱")
    return unique


def register_pasted_credentials(text: str, vault) -> dict[str, int]:
    """Import any credential rows found in the pasted list into the vault.

    Validation happens inside the vault before a single row is written, so a
    malformed row rejects the whole paste instead of leaving a partial import.
    Re-pasting an address that is already stored refreshes its credentials.
    """
    credential_lines = [line.strip() for line in str(text or "").splitlines()
                        if "----" in line and not line.strip().startswith("#")]
    if not credential_lines:
        return {"added": 0, "updated": 0, "dup": 0, "total": 0}
    result = vault.import_text("\n".join(credential_lines), update_existing=True)
    return {key: int(result.get(key) or 0) for key in ("added", "updated", "dup", "total")}


def parse_pasted_proxies(text: str) -> list[tuple[str, str]]:
    """Parse one pasted proxy list into ``(region, normalized_url)`` rows."""
    raw = str(text or "")
    if len(raw.encode("utf-8")) > 256 * 1024:
        raise ValueError("代理输入过大")
    rows = normalize_pool_rows(raw.splitlines(), normalize_proxy)
    if len(rows) > MAX_BATCH_PROXIES:
        raise ValueError(f"单批最多 {MAX_BATCH_PROXIES} 条代理")
    return rows


def pin_proxy_cached(proxy: str) -> str:
    """Resolve a gateway to one public address, reusing the same answer."""
    if not proxy:
        return ""
    with _PIN_LOCK:
        cached = _PIN_CACHE.get(proxy)
    if cached:
        return cached
    pinned = pin_proxy(proxy)
    with _PIN_LOCK:
        _PIN_CACHE[proxy] = pinned
    return pinned


def pin_proxies_parallel(rows: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Pin every distinct gateway before any account starts.

    A bad gateway is reported per row instead of leaving a half-started batch.
    """
    distinct: list[str] = []
    for _region, proxy in rows:
        if proxy not in distinct:
            distinct.append(proxy)
    if not distinct:
        return []
    with ThreadPoolExecutor(max_workers=min(8, len(distinct))) as pool:
        futures = {proxy: pool.submit(pin_proxy_cached, proxy) for proxy in distinct}
    failures = []
    for proxy in distinct:
        try:
            futures[proxy].result()
        except Exception:
            failures.append(proxy)
    if failures:
        raise ValueError(f"有 {len(failures)} 条代理无法解析为公网网关，请检查后重试")
    return [(region, pin_proxy_cached(proxy)) for region, proxy in rows]


def active_batch() -> "Batch | None":
    with BATCH_LOCK:
        for batch in BATCHES.values():
            if batch.meta.get("state") in {"queued", "running"}:
                return batch
    return None


def busy_reason() -> str:
    """Refuse a second launch while accounts are genuinely still mid-flow.

    A batch member that stopped at ``human_required`` is finished work that
    needs a human, not work in progress; after its batch is terminal it must
    not block the next launch.  Members of a queued/running batch still count.
    """
    batch = active_batch()
    if batch is not None:
        return "已有未完成的批量任务，请先等待结束或停止"
    with JOBS_LOCK:
        members = {job_id for row in BATCHES.values() for job_id in row.meta.get("job_ids", [])}
        for job in JOBS.values():
            if job.meta.get("state") not in WAITING | {"queued", "running", "interrupted"}:
                continue
            if job.id in members:
                continue
            return "已有未完成任务，请先继续或检查原任务，不能重复注册"
    return ""


class Batch:
    """Dispatcher state for one pasted batch; members are ordinary Jobs."""

    def __init__(self, meta: dict[str, Any]):
        self.meta = dict(meta)
        self.id = str(meta["id"])
        self.thread: threading.Thread | None = None
        self.offsets: dict[str, int] = {}

    @property
    def meta_path(self) -> Path:
        return BATCH_DIR / f"{self.id}.json"

    @property
    def log_path(self) -> Path:
        return Path(self.meta["log_path"])

    def save(self) -> None:
        atomic_json(self.meta_path, self.meta)


def _flush_member_log(job: "Job", handle: Any, offsets: dict[str, int]) -> None:
    """Append only complete new member lines to the batch log."""
    path = job.log_path
    try:
        size = path.stat().st_size
    except OSError:
        return
    start = offsets.get(job.id, 0)
    if size <= start:
        return
    try:
        with path.open("rb") as stream:
            stream.seek(start)
            chunk = stream.read(size - start)
    except OSError:
        return
    cut = chunk.rfind(b"\n")
    if cut < 0:
        return
    offsets[job.id] = start + cut + 1
    prefix = str(job.meta.get("email") or job.id)
    for line in chunk[: cut + 1].splitlines():
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError:
            text = line.decode("gb18030", errors="replace")
        handle.write(f"[{prefix}] {text}\n")


def spawn_batch_member(batch: Batch, email: str, proxy: str, region: str, job_id: str,
                       key: bytes, vault) -> "Job":
    """Start one account with the unchanged single-account runner."""
    config = generated_config(email, accept_terms=True, proxy=proxy)
    config.update(proxy_id="", proxy_region=region or ("DIRECT" if not proxy else "POOL"))
    input_path = DATA / "registrations" / (job_id + ".input.enc")
    job = Job({"id": job_id, "label": f"Logicc · {email}", "provider": "logicc",
               "method": "protocol", "account_count": 1, "email": email,
               "created_at": utc_now(), "state": "queued", "pool_batch": True,
               "batch_id": batch.id,
               "log_path": str(JOB_DIR / (job_id + ".log")),
               "result_path": str(RESULT_DIR / (job_id + ".jsonl")),
               "input_path": str(input_path)})
    with JOBS_LOCK:
        JOBS[job_id] = job
    save_private(input_path, key, {"run_id": job_id, "config": config})
    vault.save_registration_route(email, proxy=proxy, proxy_region=region)
    start_registration_job(job)
    return job


def run_batch(batch: Batch, pairs: list[tuple[str, str, str, str]], workers: int,
              key: bytes, vault) -> None:
    """Keep ``workers`` accounts in flight, never more, until the queue drains."""
    log_path = batch.log_path
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = log_path.open("a", encoding="utf-8", buffering=1)
    handle.write(f"=== Logicc batch {batch.id} · accounts={batch.meta['account_count']}"
                 f" · workers={workers} · gateways={batch.meta['proxy_count']} · {utc_now()} ===\n")
    pending = deque(pairs)
    active: list[Job] = []

    def retire() -> None:
        for job in list(active):
            try:
                _flush_member_log(job, handle, batch.offsets)
            except (OSError, ValueError):
                pass
            if job.proc is None or job.proc.poll() is not None:
                active.remove(job)

    try:
        while pending or active:
            if batch.meta.get("stop_requested"):
                pending.clear()
            while pending and len(active) < workers and not batch.meta.get("stop_requested"):
                email, proxy, region, job_id = pending.popleft()
                try:
                    active.append(spawn_batch_member(batch, email, proxy, region, job_id, key, vault))
                except Exception:
                    handle.write(f"[{email}] spawn_failed\n")
                    try:
                        pool_registry().release(job_id)
                    except Exception:
                        pass
            time.sleep(0.3)
            retire()
            if batch.meta.get("stop_requested") and not pending:
                for job in active:
                    job.stop()
        drain_deadline = time.monotonic() + 180
        while active and time.monotonic() < drain_deadline:
            for job in active:
                job.stop()
            retire()
            time.sleep(0.3)
        retire()
        # A member process can exit just before its waiter thread writes the
        # trailing "process finished" line, so sweep every member once more
        # after a short settle instead of losing the last line of the log.
        time.sleep(0.5)
        for job_id in batch.meta.get("job_ids", []):
            job = JOBS.get(job_id)
            if job is not None:
                try:
                    _flush_member_log(job, handle, batch.offsets)
                except (OSError, ValueError):
                    pass
    finally:
        handle.write(f"=== batch finished · {utc_now()} ===\n")
        handle.close()
        with BATCH_LOCK:
            batch.meta["state"] = "stopped" if batch.meta.get("stop_requested") else "completed"
            batch.meta["finished_at"] = utc_now()
            batch.save()


def batch_snapshot(batch: Batch, tail: int = 0) -> dict[str, Any]:
    """Aggregate per-account state for the workbench readout."""
    job_ids = list(batch.meta.get("job_ids", []))
    emails = list(batch.meta.get("emails", []))
    regions = list(batch.meta.get("regions", []))
    with JOBS_LOCK:
        members = {job_id: JOBS.get(job_id) for job_id in job_ids}
    success = failed = pending = queued = 0
    accounts: list[dict[str, Any]] = []
    for index, job_id in enumerate(job_ids):
        email = emails[index] if index < len(emails) else ""
        region = regions[index] if index < len(regions) else ""
        job = members.get(job_id)
        if job is None:
            queued += 1
            accounts.append({"email": email, "job_id": job_id, "state": "queued",
                             "status": "queued", "error": "", "proxy_region": region,
                             "registration_ok": False, "onboarding_ok": False})
            continue
        snap = job.snapshot()
        success += snap["success_count"]
        failed += snap["failed_count"]
        pending += snap["pending_count"]
        row = (read_results(job.result_path) or [{}])[-1]
        accounts.append({"email": email, "job_id": job_id, "state": snap["state"],
                         "status": row.get("status", ""), "step": row.get("step", ""),
                         "error": row.get("error", ""), "proxy_region": row.get("proxy_region") or region,
                         "registration_ok": bool(row.get("registration_ok")),
                         "onboarding_ok": bool(row.get("onboarding_ok")),
                         "integration_status": row.get("integration_status", "")})
    total = int(batch.meta.get("account_count") or len(job_ids))
    completed = success + failed
    batch_state = batch.meta.get("state", "queued")
    # A drained dispatcher is not the same as a finished registration: accounts
    # can still be parked on a human or a mailbox code.  Surface that instead of
    # reporting a clean "completed" while work is genuinely still waiting.
    waiting = [row["state"] for row in accounts if row["state"] in {"human_required", "code_required", "needs_check"}]
    if batch_state in {"completed", "stopped"} and waiting:
        for candidate in ("human_required", "code_required", "needs_check"):
            if candidate in waiting:
                batch_state = candidate
                break
    payload = {
        **batch.meta,
        "state": batch.meta.get("state", "queued"),
        "headline_state": batch_state,
        "waiting_count": len(waiting),
        "success_count": success,
        "failed_count": failed,
        "pending_count": pending,
        "queued_count": queued,
        "completed_count": completed,
        "progress": 100 if batch.meta.get("state") == "completed" else (
            round(min(100, completed * 100 / total)) if total else 0),
        "accounts": accounts,
        "resume_available": False,
        "retry_available": False,
    }
    if tail:
        payload["logs"] = safe_tail(batch.log_path, tail)
    return payload


def load_batches() -> None:
    for path in sorted(BATCH_DIR.glob("*.json")):
        try:
            meta = json.loads(path.read_text(encoding="utf-8"))
            if meta.get("state") in {"queued", "running"}:
                meta["state"] = "interrupted"
                meta["finished_at"] = utc_now()
                atomic_json(path, meta)
            BATCHES[str(meta["id"])] = Batch(meta)
        except (OSError, ValueError, KeyError):
            continue


def delete_job_result_rows(email: str) -> int:
    """Remove deleted accounts from archived JSONL so reconciliation cannot revive them."""
    wanted = str(email or "").strip().casefold()
    with JOBS_LOCK:
        paths = {job.result_path for job in JOBS.values() if job.meta.get("state") not in {"queued", "running"}}
    removed = 0
    for path in paths:
        if not path.is_file():
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        kept = []
        for line in lines:
            try:
                row = json.loads(line)
            except ValueError:
                kept.append(line)
                continue
            if isinstance(row, dict) and str(row.get("email") or "").strip().casefold() == wanted:
                removed += 1
            else:
                kept.append(line)
        if len(kept) != len(lines):
            temp = path.with_suffix(path.suffix + f".{uuid.uuid4().hex}.tmp")
            temp.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
            os.replace(temp, path)
    return removed


def load_jobs() -> None:
    for path in sorted(JOB_DIR.glob("*.json")):
        try:
            meta = json.loads(path.read_text(encoding="utf-8"))
            if meta.get("state") in {"queued", "running"}:
                meta["state"] = "interrupted"
                meta["finished_at"] = utc_now()
                result_value = str(meta.get("result_path") or "")
                task_results = read_results(Path(result_value)) if result_value else []
                registry = pool_registry()
                registry.record_registered_results(str(meta.get("id") or ""), task_results)
                if meta.get("pool_batch"):
                    # Reconcile completed rows before releasing only the rows
                    # that never produced a result during the interrupted run.
                    registry.record_job_results(
                        str(meta.get("id") or ""),
                        task_results,
                        final_state="interrupted",
                    )
                atomic_json(path, meta)
            JOBS[str(meta["id"])] = Job(meta)
        except (OSError, ValueError, KeyError):
            continue


def public_result(row: dict[str, Any]) -> dict[str, Any]:
    return {key: row.get(key) for key in (
        "email", "ok", "status", "method", "proxy_region", "duration_ms", "registered_at", "error",
        "step", "registration_ok", "onboarding_ok", "captcha_provider", "retry_not_before",
        "clerk_user_id", "app_user_id", "organization_id", "tenant_id",
        "integration_status", "integration_error", "integration_account_id", "integration_models",
        "integration_checked_at",
    )}


@app.post("/api/batches")
def api_create_batch():
    """Launch one pasted batch: N accounts, M gateways, K concurrent workers."""
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": "请求体必须是 JSON 对象"}), 400
    try:
        if body.get("method", "protocol") != "protocol":
            raise ValueError("当前只支持纯协议运行")
        if body.get("accept_terms") is not True:
            raise ValueError("请确认接受目标网站的注册条款")
        try:
            workers = int(body.get("workers", 1))
        except (TypeError, ValueError):
            raise ValueError("并发数必须是整数") from None
        if not 1 <= workers <= MAX_BATCH_WORKERS:
            raise ValueError(f"并发数必须在 1 到 {MAX_BATCH_WORKERS} 之间")
        emails = parse_pasted_emails(body.get("emails", ""))
        proxies = parse_pasted_proxies(body.get("proxies", ""))
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    reason = busy_reason()
    if reason:
        return jsonify({"ok": False, "error": reason}), 409
    # Resolve every gateway before importing or reserving anything, so a bad
    # proxy list cannot leave a half-prepared batch behind.
    try:
        pinned = pin_proxies_parallel(proxies)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    vault = console_vault()
    try:
        # The box accepts credential rows too, so importing a fresh shipment and
        # launching are one step; a bare address must already be imported.
        imported = register_pasted_credentials(body.get("emails", ""), vault)
        sync_pool_registry()
        known = {account.email.strip().casefold() for account in vault.list_accounts()}
        missing = [email for email in emails if email not in known]
        if missing:
            raise ValueError(f"有 {len(missing)} 个邮箱尚未导入收码凭据，请在粘贴内容中带上凭据或先在邮箱管理中导入")
        credentials = {email: vault.get_account(email) for email in emails}
        unusable = [email for email, account in credentials.items()
                    if not account.has_otp_creds or not account.token_valid]
        if unusable:
            raise ValueError(f"有 {len(unusable)} 个邮箱没有有效收码凭据")
    except ImportValidationError as exc:
        first = exc.errors[0] if exc.errors else {}
        return jsonify({"ok": False, "error": f"账号格式校验失败（第 {first.get('line', '?')} 行）：{first.get('error', '')}"}), 400
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    slots = assign_proxy_round_robin(pinned, len(emails))
    batch_id = uuid.uuid4().hex
    job_ids = [uuid.uuid4().hex for _ in emails]
    regions = [slot[0] if slot else "DIRECT" for slot in slots]
    pairs = [(email, slot[1] if slot else "", slot[0] if slot else "DIRECT", job_id)
             for email, slot, job_id in zip(emails, slots, job_ids)]
    batch = Batch({"id": batch_id, "label": f"Logicc · 批量 {len(emails)}",
                   "provider": "logicc", "method": "protocol",
                   "account_count": len(emails), "worker_limit": workers,
                   "proxy_count": len(pinned), "emails": emails, "regions": regions,
                   "job_ids": job_ids, "created_at": utc_now(), "state": "queued",
                   "log_path": str(BATCH_DIR / (batch_id + ".log"))})
    with BATCH_LOCK:
        BATCHES[batch_id] = batch
    key = vault.key_path.read_bytes().strip()
    try:
        registry = sync_pool_registry()
        # Each account is owned by its own member job, because that member is
        # what writes the result row the registry reconciles against.
        reserved = registry.reserve_each(dict(zip(emails, job_ids)), include_failed=True)
        if len(reserved) != len(emails):
            registry.release_batch(job_ids)
            raise ValueError("邮箱已注册或正被使用，请移除后重试")
        batch.save()
        batch.thread = threading.Thread(target=run_batch, args=(batch, pairs, workers, key, vault), daemon=True)
        batch.meta["state"] = "running"
        batch.meta["started_at"] = utc_now()
        batch.thread.start()
    except ValueError as exc:
        with BATCH_LOCK:
            BATCHES.pop(batch_id, None)
        return jsonify({"ok": False, "error": str(exc)}), 409
    except Exception:
        pool_registry().release_batch(job_ids)
        with BATCH_LOCK:
            BATCHES.pop(batch_id, None)
        return jsonify({"ok": False, "error": "启动批量任务失败"}), 500
    return jsonify({"ok": True, "batch": batch_snapshot(batch), "imported": imported}), 201


@app.get("/api/batches")
def api_batches():
    with BATCH_LOCK:
        rows = [batch_snapshot(batch) for batch in BATCHES.values()]
    rows.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    return jsonify({"ok": True, "batches": rows})


@app.get("/api/batches/<batch_id>")
def api_batch(batch_id: str):
    batch = BATCHES.get(batch_id)
    if not batch:
        return jsonify({"ok": False, "error": "批次不存在"}), 404
    try:
        tail = int(request.args.get("tail") or 0)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "tail 必须是整数"}), 400
    return jsonify({"ok": True, "batch": batch_snapshot(batch, tail=max(0, min(tail, 5000)))})


@app.post("/api/batches/<batch_id>/stop")
def api_stop_batch(batch_id: str):
    batch = BATCHES.get(batch_id)
    if not batch:
        return jsonify({"ok": False, "error": "批次不存在"}), 404
    with BATCH_LOCK:
        batch.meta["stop_requested"] = True
        batch.meta["stop_at"] = utc_now()
        batch.save()
    for job_id in list(batch.meta.get("job_ids", [])):
        job = JOBS.get(job_id)
        if job is not None:
            job.stop()
    return jsonify({"ok": True, "batch": batch_snapshot(batch)})


@app.get("/api/batches/<batch_id>/download/<kind>")
def api_batch_download(batch_id: str, kind: str):
    batch = BATCHES.get(batch_id)
    if not batch:
        return jsonify({"ok": False, "error": "批次不存在"}), 404
    path = batch.log_path if kind == "log" else None
    if not path or not path.exists():
        return jsonify({"ok": False, "error": "文件不存在"}), 404
    return send_file(path, as_attachment=True, download_name=path.name)


load_jobs()
load_batches()
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def api_health():
    checks = {
        "mailbox": (CORE / "email_provider.py").is_file(),
        "registration_adapter": (CORE / "logicc_register.py").is_file(),
        "writable": os.access(OUTPUT, os.W_OK),
        "httpx": importlib.util.find_spec("httpx") is not None,
        "cryptography": importlib.util.find_spec("cryptography") is not None,
    }
    return jsonify({"ok": all(checks.values()), "service": "logicc-console",
                    "version": "0.3.0", "registration_ready": checks["registration_adapter"],
                    "registration_mode": "protocol",
                    "otp_target": "logicc", "checks": checks,
                    "time": utc_now(), "local_time": local_now(), "timezone": display_timezone_name()})


@app.route("/api/settings", methods=["GET", "PATCH"])
def api_settings():
    current = load_settings()
    if request.method == "PATCH":
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            return jsonify({"ok": False, "error": "请求体必须为 JSON 对象"}), 400
        for key in DEFAULT_SETTINGS:
            if key not in body:
                continue
            value = body[key]
            if key in SECRET_KEYS and value in (None, "", "••••••••") and current.get(key):
                continue
            current[key] = str(value or "").strip()

        try:
            validate_domain_mailbox_settings(
                current,
                require_admin_token=domain_mailbox_enabled(current),
            )
        except (ValueError, RuntimeError) as exc:
            return jsonify({"ok": False, "error": f"域名邮箱配置无效：{exc}"}), 400
        atomic_json(SETTINGS_FILE, current)
        write_domain_mailbox_runtime_config(current)
        apply_process_timezone(current)
    public = dict(current)
    configured = {key: bool(public.get(key)) for key in SECRET_KEYS}
    for key in SECRET_KEYS:
        public[key] = ""
    return jsonify({"ok": True, "settings": public, "secret_configured": configured})


@app.post("/api/domain-mailbox/test")
def api_test_domain_mailbox():
    """Verify the owned mailbox control plane without creating a mailbox."""
    current = load_settings()
    try:
        from domain_mailbox import (
            DomainMailboxClient,
            DomainMailboxConfigError,
            provider_from_runtime_settings,
        )

        provider = provider_from_runtime_settings(current, require_admin_token=True)
        timeout = max(3.0, min(float(current.get("domain_mailbox_request_timeout") or 30), 60.0))
        remote_domains = DomainMailboxClient(
            provider,
            bearer_token=provider.admin_token_literal,
        ).list_domains(timeout=timeout)
    except DomainMailboxConfigError as exc:
        return jsonify({"ok": False, "error": f"域名邮箱配置错误：{exc}"}), 400
    except (ValueError, RuntimeError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502
    return jsonify({
        "ok": True,
        "label": provider.label,
        "api_origin": provider.api_origin,
        "domains": list(provider.domains),
        "remote_domain_count": len(remote_domains),
    })


@app.route("/api/services/capmonster", methods=["GET", "PATCH"])
def api_capmonster_settings():
    with SERVICES_LOCK:
        current = private_service("capmonster")
        if request.method == "PATCH":
            body = request.get_json(silent=True)
            if not isinstance(body, dict) or set(body) - {"enabled", "client_key"}:
                return jsonify({"ok": False, "error": "CapMonster 配置格式无效"}), 400
            enabled = body.get("enabled", current.get("enabled", bool(current.get("client_key"))))
            value = body.get("client_key", "")
            if not isinstance(enabled, bool) or not isinstance(value, str):
                return jsonify({"ok": False, "error": "启用状态或密钥格式无效"}), 400
            key = value.strip() or current.get("client_key", "")
            if key and not re.fullmatch(r"[a-fA-F0-9]{32}", key):
                return jsonify({"ok": False, "error": "CapMonster 密钥应为 32 位十六进制字符"}), 400
            if enabled and not key:
                return jsonify({"ok": False, "error": "请先配置 API 密钥"}), 400
            current = {"enabled": enabled, "client_key": key}
            save_service("capmonster", current)
    response = jsonify({"ok": True, "enabled": current.get("enabled", bool(current.get("client_key"))),
                        "configured": bool(current.get("client_key")), "client_key": "", "max_tasks_per_run": 1})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/services/capmonster/test")
def api_capmonster_test():
    current = private_service("capmonster")
    if not current.get("client_key"):
        return jsonify({"ok": False, "error": "尚未配置 CapMonster 密钥"}), 400
    client = CapMonster(current["client_key"])
    try:
        balance = client.balance()
    except CapMonsterError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502
    finally:
        client.close()
    response = jsonify({"ok": True, "balance": balance, "paid_task_created": False})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/services/logicc2api", methods=["GET", "PATCH"])
def api_logicc2api_settings():
    with SERVICES_LOCK:
        current = {"enabled": False, "base_url": "http://127.0.0.1:18789", **private_service("logicc2api")}
        if request.method == "PATCH":
            body = request.get_json(silent=True)
            if not isinstance(body, dict) or set(body) - {"enabled", "base_url"}:
                return jsonify({"ok": False, "error": "logicc2api 配置格式无效"}), 400
            if not isinstance(body.get("enabled", current["enabled"]), bool):
                return jsonify({"ok": False, "error": "启用状态必须为布尔值"}), 400
            try:
                current.update(enabled=body.get("enabled", current["enabled"]),
                               base_url=local_base_url(body.get("base_url", current["base_url"])))
            except ValueError as exc:
                return jsonify({"ok": False, "error": str(exc)}), 400
            save_service("logicc2api", current)
    return jsonify({"ok": True, **current})


@app.post("/api/services/logicc2api/test")
def api_logicc2api_test():
    current = private_service("logicc2api")
    client = Logicc2Api(current.get("base_url", "http://127.0.0.1:18789"))
    try:
        value = client.snapshot()
        return jsonify({"ok": True, "account_count": len(value["accounts"]), "upstream_called": False})
    except IntegrationError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 502
    finally:
        client.close()


@app.get("/api/proxies")
def api_proxy_pool():
    return jsonify({"ok": True, "proxies": public_proxies()})


@app.post("/api/proxies/import")
def api_proxy_import():
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("lines"), str):
        return jsonify({"ok": False, "error": "请填写代理行"}), 400
    if not 1 <= len(body["lines"]) <= 100000:
        return jsonify({"ok": False, "error": "代理输入为空或过大"}), 400
    try:
        incoming = normalize_pool_rows(body["lines"].splitlines(), normalize_proxy)
        if not incoming or len(incoming) > 200:
            raise ValueError("代理池单次导入 1 到 200 条")
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    with SERVICES_LOCK:
        stored = private_service("proxies")
        entries = stored.setdefault("entries", [])
        known = {row["proxy"] for row in entries}
        added = 0
        for region, proxy in incoming:
            if proxy not in known:
                entries.append({"id": uuid.uuid4().hex, "region": region, "proxy": proxy})
                known.add(proxy)
                added += 1
        if len(entries) > 200:
            return jsonify({"ok": False, "error": "固定代理池最多保留 200 条"}), 400
        save_service("proxies", stored)
    return jsonify({"ok": True, "added": added, "proxies": public_proxies()})


@app.post("/api/proxies/<proxy_id>/test")
def api_proxy_pool_test(proxy_id):
    entry = next((row for row in private_service("proxies").get("entries", []) if row["id"] == proxy_id), None)
    if not entry:
        return jsonify({"ok": False, "error": "代理不存在"}), 404
    result = probe_proxy(entry["proxy"])
    with SERVICES_LOCK:
        stored = private_service("proxies")
        for row in stored.get("entries", []):
            if row["id"] == proxy_id:
                row.update(last_check=result, checked_at=utc_now())
        save_service("proxies", stored)
    return jsonify({"ok": True, "check": result})


@app.get("/api/accounts/pool")
def api_accounts_pool():
    registry = sync_pool_registry()
    records = load_pool_records()
    emails = [line.split("----", 1)[0] for line in records.values()]
    return jsonify({
        "ok": True,
        "count": len(emails),
        "emails": emails,
        "summary": registry.summary(),
    })


@app.get("/api/accounts")
def api_accounts_list():
    try:
        limit = int(request.args.get("limit") or 100)
        offset = int(request.args.get("offset") or 0)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "limit 和 offset 必须是整数"}), 400
    registry = sync_pool_registry()
    rows, total = registry.list_accounts(
        state=str(request.args.get("state") or ""),
        query=str(request.args.get("q") or ""),
        limit=max(1, min(limit, 1000)),
        offset=max(0, offset),
    )
    return jsonify({"ok": True, "accounts": rows, "count": total, "summary": registry.summary()})


@app.get("/api/accounts/managed")
def api_managed_accounts():
    rows = _managed_account_rows()
    query = str(request.args.get("q") or "").strip().casefold()
    state = str(request.args.get("state") or "").strip()
    rows = [row for row in rows if (not query or query in row["email"].casefold())
            and (not state or row["state"] == state)]
    return jsonify({"ok": True, "accounts": rows, "count": len(rows),
                    "summary": {"total": len(rows), "otp_ready": sum(row["otp_ready"] for row in rows)}})


@app.post("/api/accounts/<path:email>/platform-password")
def api_platform_password(email):
    origin = request.headers.get("Origin")
    if (origin and origin != request.host_url.rstrip("/")) or request.headers.get("Sec-Fetch-Site") == "cross-site":
        return jsonify({"ok": False, "error": "不允许跨站读取平台密码"}), 403
    if not request.is_json or not isinstance(request.get_json(silent=True), dict):
        return jsonify({"ok": False, "error": "请通过 JSON POST 显式查看密码"}), 400
    try:
        account = console_vault().get_account(urllib.parse.unquote(email))
    except Exception:
        return jsonify({"ok": False, "error": "邮箱不存在"}), 404
    state = platform_password_state(account.email)
    if not state:
        return jsonify({"ok": False, "error": "尚无已确认账号的平台密码"}), 404
    response = jsonify({"ok": True, "password": state["config"]["password"]})
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.delete("/api/accounts/<path:email>")
def api_account_delete(email: str):
    from account_vault import AccountNotFound

    wanted = urllib.parse.unquote(email).strip().casefold()
    if not wanted or "@" not in wanted or len(wanted) > 320:
        return jsonify({"ok": False, "error": "邮箱格式无效"}), 400
    row = pool_registry().lookup([wanted]).get(wanted, {})
    matching_jobs = [job for job in JOBS.values() if str(job.meta.get("email") or "").casefold() == wanted]
    if row.get("state") == "reserved" or any(
        job.meta.get("state") in WAITING | {"running", "queued", "interrupted"} for job in matching_jobs
    ):
        return jsonify({"ok": False, "error": "运行中的账号不能删除"}), 409
    try:
        console_vault().delete(wanted)
    except AccountNotFound:
        return jsonify({"ok": False, "error": "邮箱记录不存在"}), 404
    pool_registry().delete(wanted)
    delete_job_result_rows(wanted)
    for job in matching_jobs:
        if job.meta.get("provider") == "logicc" and re.fullmatch(r"[0-9a-f]{32}", job.id):
            for suffix in (".input.enc", ".state.enc"):
                (DATA / "registrations" / (job.id + suffix)).unlink(missing_ok=True)
    return jsonify({"ok": True, "email": wanted})


















@app.post("/api/accounts/<path:email>/otp")
def api_account_otp(email: str):
    body = request.get_json(silent=True) or {}
    try:
        if not isinstance(body, dict):
            raise ValueError("JSON object required")
        timeout = max(5, min(int(body.get("timeout") or 60), 180))
        after_ts = float(body.get("after_ts") or time.time())
        if not 0 < after_ts <= time.time():
            raise ValueError("invalid after_ts")
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "timeout 必须是 5 到 180 秒"}), 400
    try:
        account = console_vault().get_account(urllib.parse.unquote(email))
    except Exception:
        return jsonify({"ok": False, "error": "账号没有可用邮箱凭据"}), 404
    try:
        from email_provider import fetch_otp

        code = fetch_otp(
            account.email,
            account.relay_url if account.kind == "icloud" else account.refresh_token,
            account.client_id,
            method="relay" if account.kind == "icloud" else "graph",
            timeout=timeout,
            relay_require_fresh=bool(body.get("fresh", True)),
            after_ts=after_ts,
            password=str(getattr(account, "password", "") or ""),
        )
    except TimeoutError:
        return jsonify({"ok": False, "error": "等待验证码超时"}), 408
    except Exception as exc:
        return jsonify({"ok": False, "error": f"收码失败（{type(exc).__name__}）"}), 502
    if not code:
        return jsonify({"ok": False, "error": "没有识别到验证码"}), 404
    response = jsonify({"ok": True, "target": "logicc", "email": account.email, "code": code, "received_at": utc_now()})
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@app.post("/api/accounts/import")
def api_accounts_import():
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": "请求体必须为 JSON 对象"}), 400
    text = str(body.get("lines") or "")
    if not text.strip():
        return jsonify({"ok": False, "error": "没有识别到有效账号行"}), 400
    replace = str(body.get("mode") or "append") == "replace"
    try:
        from account_vault import ImportValidationError

        if replace and sync_pool_registry().summary()["reserved"]:
            return jsonify({
                "ok": False,
                "error": "有账号池任务正在运行，不能替换导入；请等待任务结束后再操作",
            }), 409
        vault = console_vault()
        result = replace_console_vault(vault, text) if replace else vault.import_text(text, update_existing=True)
        registry = sync_pool_registry()
        if replace:
            registry.prune_unregistered_missing_credentials(load_pool_records().keys())
    except ImportValidationError as exc:
        return jsonify({"ok": False, "error": "账号格式校验失败", "details": exc.errors[:20]}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 500
    return jsonify({
        "ok": True,
        "imported": int(result.get("total") or 0),
        "outlook": int((result.get("added_by_kind") or {}).get("outlook", 0)) + int((result.get("updated_by_kind") or {}).get("outlook", 0)),
        "relay": int((result.get("added_by_kind") or {}).get("icloud", 0)) + int((result.get("updated_by_kind") or {}).get("icloud", 0)),
        "added": int(result.get("added") or 0),
        "updated": int(result.get("updated") or 0),
        "duplicates": int(result.get("dup") or 0),
        "summary": registry.summary(),
    })


@app.post("/api/proxy/test")
def api_proxy_test():
    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": "请求体必须为 JSON 对象"}), 400
    try:
        proxy = normalize_proxy(body.get("proxy", ""))
        if not proxy and body.get("managed_region"):
            proxy = managed_proxy(str(body["managed_region"]), f"{secrets.randbelow(100_000_000):08d}", load_settings())
    except (ValueError, TypeError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    if not proxy:
        return jsonify({"ok": False, "error": "请填写代理地址"}), 400
    result = probe_proxy(proxy)
    return jsonify(result), 200 if result["ok"] else 502


@app.post("/api/roxy/test")
def api_roxy_test():
    """Test the localhost Roxy API without returning its token."""
    current = load_settings()
    try:
        from roxy_mgr import RoxyBrowserError, RoxyClient

        client = RoxyClient(
            port=current.get("roxy_api_port") or 50000,
            token=current.get("roxy_api_token") or "",
            workspace_id=current.get("roxy_workspace_id") or 0,
            rate_limit=int(current.get("roxy_api_rate_limit") or 45),
            timeout=12,
        )
        return jsonify({"ok": True, **client.connection_summary()})
    except (RoxyBrowserError, TypeError, ValueError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Roxy API 测试失败（{type(exc).__name__}）"}), 502
@app.post("/api/runs")
def api_create_run():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": "请求体必须是 JSON 对象"}), 400
    try:
        if body.get("method", "protocol") != "protocol" or int(body.get("workers", 1)) != 1:
            raise ValueError("当前只支持单账号、纯协议运行")
        if body.get("accept_terms") is not True:
            raise ValueError("请确认接受目标网站的注册条款")
        email = str(body.get("email") or "").strip().casefold()
        vault = console_vault()
        account = vault.get_account(email)
        if not account.has_otp_creds or not account.token_valid:
            raise ValueError("所选邮箱没有有效收码凭据")
        proxy = normalize_proxy(str(body.get("proxy") or ""))
        proxy_id = str(body.get("proxy_id") or "")
        if proxy_id:
            if proxy:
                raise ValueError("固定代理与代理池条目只能选择一种")
            entry = next((row for row in private_service("proxies").get("entries", []) if row["id"] == proxy_id), None)
            if not entry:
                raise ValueError("所选代理池条目不存在")
            proxy = entry["proxy"]
        region = infer_proxy_region("", proxy) if proxy else "DIRECT"
        if proxy:
            proxy = pin_proxy(proxy)
        config = generated_config(email, accept_terms=True, proxy=proxy)
        config.update(proxy_id=proxy_id, proxy_region=region)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc) if isinstance(exc, ValueError) else "邮箱不存在或凭据不可用"}), 400
    with JOBS_LOCK:
        if any(job.meta.get("state") in WAITING | {"queued", "running", "interrupted"} for job in JOBS.values()):
            return jsonify({"ok": False, "error": "已有未完成任务，请先继续或检查原任务，不能重复注册"}), 409
        job_id = uuid.uuid4().hex
        registry = sync_pool_registry()
        if registry.reserve(job_id, [email], include_failed=True) != [email]:
            return jsonify({"ok": False, "error": "邮箱已注册或正被使用"}), 409
        input_path = DATA / "registrations" / (job_id + ".input.enc")
        job = Job({"id": job_id, "label": "Logicc · 单账号", "provider": "logicc",
                   "method": "protocol", "account_count": 1, "email": email,
                   "created_at": utc_now(), "state": "queued", "pool_batch": True,
                   "log_path": str(JOB_DIR / (job_id + ".log")),
                   "result_path": str(RESULT_DIR / (job_id + ".jsonl")),
                   "input_path": str(input_path)})
        JOBS[job_id] = job
        try:
            save_private(input_path, vault.key_path.read_bytes().strip(), {"run_id": job_id, "config": config})
            vault.save_registration_route(email, proxy=proxy, proxy_region=region)
            start_registration_job(job)
        except Exception:
            registry.release(job_id)
            job.meta.update(state="failed", error="runner_start_failed")
            job.save()
            return jsonify({"ok": False, "error": "启动协议任务失败"}), 500
    return jsonify({"ok": True, "job": job.snapshot()}), 201


def registration_state_path(job_id):
    if not re.fullmatch(r"[0-9a-f]{32}", job_id):
        raise ValueError("invalid job ID")
    return DATA / "registrations" / (job_id + ".state.enc")


def start_registration_job(job):
    runtime_config = write_domain_mailbox_runtime_config()
    env = {"ACCOUNT_VAULT_DIR": str(DATA / "account_vault"),
           "LOGICC_CONSOLE_DATA_DIR": str(DATA), "LOGICC_CONSOLE_OUTPUT_DIR": str(OUTPUT),
           "PYTHONDONTWRITEBYTECODE": "1"}
    if runtime_config:
        env["DOMAIN_MAILBOX_CONFIG"] = str(runtime_config)
    job.start([PYTHON, "-u", str(CORE / "logicc_register.py"), "--input", job.meta["input_path"],
               "--out", str(job.result_path)], env)


@app.post("/api/jobs/<job_id>/resume")
def api_resume_registration(job_id):
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"ok": False, "error": "请求体必须是 JSON 对象"}), 400
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job or job.meta.get("provider") != "logicc":
            return jsonify({"ok": False, "error": "Logicc 任务不存在"}), 404
        if job.snapshot()["state"] not in WAITING | {"interrupted"}:
            return jsonify({"ok": False, "error": "当前任务不能继续"}), 409
        result = (read_results(job.result_path) or [{}])[-1]
        if time.time() < float(result.get("retry_not_before") or 0):
            return jsonify({"ok": False, "error": "服务限流冷却时间未结束"}), 429
        captcha, code = body.get("captcha_token", ""), body.get("code", "")
        if not isinstance(captcha, str) or len(captcha) > 2048:
            return jsonify({"ok": False, "error": "人机材料格式无效"}), 400
        if not isinstance(code, str) or (code and not re.fullmatch(r"\d{6}", code)):
            return jsonify({"ok": False, "error": "验证码须为六位数字"}), 400
        resend = body.get("resend_code", False)
        if not isinstance(resend, bool) or (resend and code):
            return jsonify({"ok": False, "error": "重新发码不能同时提交旧验证码"}), 400
        try:
            key = console_vault().key_path.read_bytes().strip()
            registration = load_private(registration_state_path(job_id), key)
            if captcha and (registration.get("signup_id") or result.get("error") not in {"captcha_required", "captcha_already_consumed"}):
                return jsonify({"ok": False, "error": "该任务不是待处理的注册人机验证"}), 400
            payload = load_private(job.meta["input_path"], key)
            payload.update(captcha_token=captcha, code=code, resend_code=resend)
            save_private(job.meta["input_path"], key, payload)
            start_registration_job(job)
        except Exception:
            return jsonify({"ok": False, "error": "检查点读取或任务启动失败；请检查原任务"}), 500
    response = jsonify({"ok": True, "job": job.snapshot()})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/jobs/<job_id>/logicc2api")
def api_import_logicc2api(job_id):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job or job.meta.get("provider") != "logicc":
            return jsonify({"ok": False, "error": "Logicc 任务不存在"}), 404
        if job.meta.get("state") in {"running", "queued"}:
            return jsonify({"ok": False, "error": "请等待注册任务结束"}), 409
        key = console_vault().key_path.read_bytes().strip()
        try:
            state = load_private(registration_state_path(job_id), key)
        except (ValueError, OSError):
            return jsonify({"ok": False, "error": "该任务的私密检查点已删除或不可用"}), 409
        if (not state.get("registration_ok") or not state.get("onboarding_ok")
                or state.get("email") != job.meta.get("email")):
            return jsonify({"ok": False, "error": "账号注册和入驻尚未确认，不导出凭据"}), 409
        settings = private_service("logicc2api")
        connector = Logicc2Api(settings.get("base_url", "http://127.0.0.1:18789"))
        try:
            imported = connector.handoff(state, lambda: save_private(registration_state_path(job_id), key, state))
        finally:
            connector.close()
        result = (read_results(job.result_path) or [{}])[-1]
        result.update(imported)
        record_logicc_connectivity(pool_registry(), [result])
        atomic_jsonl = (json.dumps(result, ensure_ascii=False) + "\n").encode()
        console_vault()._atomic_write(job.result_path, atomic_jsonl, mode=0o600)
    response = jsonify({"ok": imported["integration_status"] == "ready", **imported,
                        "error": imported["integration_error"]})
    response.headers["Cache-Control"] = "no-store"
    return response, 200 if imported["integration_status"] == "ready" else 502


@app.get("/api/jobs")
def api_jobs():
    with JOBS_LOCK:
        rows = [job.snapshot() for job in JOBS.values()]
    rows.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    return jsonify({"ok": True, "jobs": rows})


@app.get("/api/jobs/<job_id>")
def api_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"ok": False, "error": "任务不存在"}), 404
    try:
        tail = int(request.args.get("tail") or 500)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "tail 必须是整数"}), 400
    return jsonify({"ok": True, "job": job.snapshot(tail=max(0, min(tail, 5000)))})


@app.post("/api/jobs/<job_id>/stop")
def api_stop_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"ok": False, "error": "任务不存在"}), 404
    job.stop()
    return jsonify({"ok": True})


@app.get("/api/results")
def api_results():
    rows: list[dict[str, Any]] = []
    with JOBS_LOCK:
        jobs = list(JOBS.values())
    registry = sync_pool_registry()
    job_rows_by_id: list[tuple[Job, list[dict[str, Any]]]] = []
    emails: list[str] = []
    for job in jobs:
        job_rows = read_results(job.result_path)
        job_rows_by_id.append((job, job_rows))
        emails.extend(str(item.get("email") or "") for item in job_rows)
    states = registry.lookup(emails)
    for job, job_rows in job_rows_by_id:
        for item in job_rows:
            public = public_result(item)
            public["job_id"] = job.id
            state = states.get(str(public.get("email") or "").casefold(), {})
            public.update({
                "pool_state": state.get("state", ""),
                "last_checked_at": state.get("last_checked_at", ""),
                "last_confirmed_at": state.get("last_confirmed_at", ""),
                "last_probe_status": state.get("last_probe_status", ""),
                "health_status": state.get("health_status", ""),
                "health_alive": state.get("health_alive"),
                "observed_seconds": state.get("observed_seconds"),
                "health_error": state.get("check_error", ""),
            })
            rows.append(public)
    rows.sort(key=lambda item: item.get("registered_at", ""), reverse=True)
    return jsonify({"ok": True, "count": len(rows), "results": rows})


@app.get("/api/jobs/<job_id>/download/<kind>")
def api_download(job_id: str, kind: str):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"ok": False, "error": "任务不存在"}), 404
    path = job.result_path if kind == "results" else job.log_path if kind == "log" else None
    if not path or not path.exists():
        return jsonify({"ok": False, "error": "文件不存在"}), 404
    return send_file(path, as_attachment=True, download_name=path.name)




if __name__ == "__main__":
    host = "127.0.0.1"
    port = int(os.environ.get("FREE_CONSOLE_PORT", "8866"))
    app.run(host=host, port=port, debug=False, threaded=True)
