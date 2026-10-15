import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "core"))
_runtime = tempfile.TemporaryDirectory(prefix="logicc-tests-")
os.environ["LOGICC_CONSOLE_DATA_DIR"] = str(Path(_runtime.name) / "data")
os.environ["LOGICC_CONSOLE_OUTPUT_DIR"] = str(Path(_runtime.name) / "output")
os.environ["ACCOUNT_VAULT_DIR"] = str(Path(_runtime.name) / "vault")
os.environ.pop("FREE_CONSOLE_PASSWORD", None)


def pytest_sessionfinish(session, exitstatus):
    _runtime.cleanup()
