# Verification — OpenAI gateway release

Date: 2026-10-15. The isolated sanitized source tree passed **273 tests**, with the opt-in local Chromium checks enabled. JavaScript syntax checks passed for `static/app.js` and `core/gateway_worker.mjs`.

The release tests use temporary credentials and a local fixture upstream; they do not register accounts, purchase CAPTCHA tasks, or call a real model service. Browser tests verify key visibility, clearing on navigation and responsive layout.

Gateway coverage includes API-key isolation, local-only management, encrypted persistence/restart, deduplication, confirmed-session synchronization, JSON/SSE, tool-result round trips, Responses history, truncated-stream errors, and a 32-request concurrency cap (request 33 returns 429). The optional sharing relay has separate tests for its key, expiry/revocation, two-request concurrency cap, request budget and route allowlist.

The working installation separately passed real model-list, Chat Completions SSE, Responses JSON and tool-result round-trip checks. Raw live-account evidence is excluded. These checks do not establish current registration availability, guarantee all clients, or verify model provenance.

For local tests, install the Python requirements and pytest, then run pytest against the absolute path to the extracted project's `tests` directory. Default CI skips optional browser checks; use `RUN_LOCAL_BROWSER_TESTS=1` to enable them and set `LOGICC_TEST_BROWSER` to the absolute path of an installed Chromium executable for the gateway UI test. Node.js 24+ is required for embedded-gateway tests.

Source, staged Git content and ZIP members are checked against known private values and scanned with Gitleaks. Runtime data, account pools, connection files, logs, captures, screenshots, keys and machine-specific instructions are excluded. SHA-256 file hashes are in `FILE_MANIFEST.sha256`.
