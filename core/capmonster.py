"""Bounded CapMonster Turnstile client; receipts belong in encrypted checkpoints."""
import ipaddress
import re
import time
from urllib.parse import unquote, urlsplit

import httpx

# How many paid Turnstile tasks one account may ever create.  A rejected or
# unsolvable task has already charged the balance and produced no token, so a
# retry is the only way out; the cap keeps that from becoming unlimited spend.
MAX_PAID_ATTEMPTS = 2


class CapMonsterError(Exception):
    pass


class CapMonster:
    def __init__(self, client_key, *, transport=None):
        if not isinstance(client_key, str) or not re.fullmatch(r"[a-fA-F0-9]{32}", client_key):
            raise ValueError("invalid CapMonster key")
        self.key = client_key
        self.client = httpx.Client(base_url="https://api.capmonster.cloud", trust_env=False,
                                   follow_redirects=False, timeout=20, transport=transport)

    def close(self):
        self.client.close()

    def call(self, method, payload=None, *, timeout=20):
        try:
            response = self.client.post("/" + method, json={"clientKey": self.key, **(payload or {})},
                                        timeout=timeout)
            if response.status_code != 200:
                raise CapMonsterError("capmonster_http_" + str(response.status_code))
            result = response.json()
        except (httpx.RequestError, ValueError):
            raise CapMonsterError("capmonster_response_unavailable") from None
        if not isinstance(result, dict) or type(result.get("errorId")) is not int:
            raise CapMonsterError("capmonster_invalid_response")
        if result["errorId"]:
            # Never expose errorDescription: it may echo submitted secrets.
            code = result.get("errorCode")
            safe = {"ERROR_KEY_DOES_NOT_EXIST", "ERROR_ZERO_BALANCE", "ERROR_NO_SLOT_AVAILABLE",
                    "ERROR_CAPTCHA_UNSOLVABLE", "ERROR_TASK_NOT_FOUND", "ERROR_TOKEN_EXPIRED",
                    "ERROR_PROXY_CONNECT_REFUSED", "ERROR_PROXY_CONNECT_TIMEOUT", "ERROR_PROXY_BANNED",
                    "ERROR_RECAPTCHA_INVALID_SITEKEY", "ERROR_RECAPTCHA_INVALID_DOMAIN",
                    "ERROR_TASK_ABSENT", "ERROR_TASK_NOT_SUPPORTED", "ERROR_IP_NOT_ALLOWED"}
            raise CapMonsterError(code if code in safe else "capmonster_task_rejected")
        return result

    def balance(self):
        value = self.call("getBalance").get("balance")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value < 1e12:
            raise CapMonsterError("capmonster_invalid_balance")
        return value

    def solve_turnstile(self, *, site_key, website_url, user_agent, proxy, receipt, checkpoint):
        """Buy at most ``MAX_PAID_ATTEMPTS`` tasks, 60 polls/180s each, never replay a token.

        A rejected or unsolvable task has already charged the balance and left
        no token, so the account would otherwise be stuck forever. Those tasks
        may be retried, but only up to the cap. A ``creating`` receipt is still
        refused: its create response was never observed, so retrying could pay
        twice for one token.
        """
        if not isinstance(site_key, str) or not re.fullmatch(r"0x[A-Za-z0-9_-]{10,100}", site_key):
            raise CapMonsterError("capmonster_site_key_missing")
        task = {"type": "TurnstileTask", "websiteURL": website_url,
                "websiteKey": site_key, "userAgent": user_agent, "pageAction": "signup"}
        if proxy:
            parsed = urlsplit(proxy)
            try:
                address = ipaddress.ip_address(parsed.hostname)
                port = parsed.port
            except (ValueError, TypeError):
                raise CapMonsterError("capmonster_proxy_requires_public_ip") from None
            if not address.is_global or not port or parsed.scheme not in {"http", "https", "socks4", "socks5"}:
                raise CapMonsterError("capmonster_proxy_requires_public_ip")
            task.update(proxyType=parsed.scheme, proxyAddress=str(address), proxyPort=port)
            if parsed.username:
                task.update(proxyLogin=unquote(parsed.username), proxyPassword=unquote(parsed.password or ""))
        if receipt.get("status") in {"creating", "consumed"}:
            raise CapMonsterError("capmonster_attempt_already_used")
        attempts = int(receipt.get("attempts") or 0)
        if receipt.get("status") == "failed":
            # Balance was charged and no token exists; the old task id is dead.
            if attempts >= MAX_PAID_ATTEMPTS:
                raise CapMonsterError("capmonster_attempt_limit_reached")
            receipt.pop("task_id", None)
            receipt["status"] = None
            receipt["poll_count"] = 0
            checkpoint()
        if receipt.get("status") is None:
            if attempts >= MAX_PAID_ATTEMPTS:
                raise CapMonsterError("capmonster_attempt_limit_reached")
            if self.balance() <= 0:
                raise CapMonsterError("ERROR_ZERO_BALANCE")
            receipt.update(status="creating", attempts=attempts + 1,
                           started_at=time.time(), poll_count=0)
            checkpoint()  # A lost create response must not trigger another paid task.
            result = self.call("createTask", {"task": task})
            task_id = result.get("taskId")
            if type(task_id) is not int or task_id <= 0:
                raise CapMonsterError("capmonster_task_id_missing")
            receipt.update(status="processing", task_id=task_id)
            checkpoint()
        if receipt.get("status") != "processing" or type(receipt.get("task_id")) is not int:
            raise CapMonsterError("capmonster_invalid_receipt")
        if receipt.get("poll_count", 0) >= 60:
            # The previous window was exhausted while the task was still
            # processing. Re-querying the same paid task is free, so grant a
            # fresh window instead of stranding the account.
            receipt.update(started_at=time.time(), poll_count=0)
            checkpoint()
        while time.time() < receipt["started_at"] + 180 and receipt["poll_count"] < 60:
            time.sleep(3)
            remaining = receipt["started_at"] + 180 - time.time()
            if remaining <= 0:
                break
            receipt["poll_count"] += 1
            checkpoint()
            result = self.call("getTaskResult", {"taskId": receipt["task_id"]}, timeout=min(20, remaining))
            if result.get("status") == "processing":
                continue
            if result.get("status") != "ready":
                raise CapMonsterError("capmonster_invalid_task_status")
            solution = result.get("solution") or {}
            token = solution.get("token") if isinstance(solution, dict) else None
            if not isinstance(token, str) or not 1 <= len(token) <= 2048 or any(c.isspace() for c in token):
                raise CapMonsterError("capmonster_invalid_token")
            if solution.get("userAgent", user_agent) != user_agent:
                raise CapMonsterError("capmonster_user_agent_mismatch")
            receipt.update(status="consumed", finished_at=time.time())
            checkpoint()  # Token remains in memory only; an interruption needs manual review.
            return token
        raise CapMonsterError("capmonster_poll_timeout")
