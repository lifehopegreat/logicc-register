# Verification

Run `python -m pytest -q -p no:cacheprovider tests` and `node --check static/app.js`.

Tests use isolated fixture data. Historical live-account evidence is excluded from this publication. Offline tests do not establish current upstream registration availability.

Publication check (2026-10-15): **256 tests passed**, including opt-in loopback Chrome UI tests; JavaScript syntax check passed. No live registration or paid solver task was run during packaging.
