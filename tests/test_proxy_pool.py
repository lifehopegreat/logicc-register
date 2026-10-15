from pathlib import Path
import sys

import pytest

from app import normalize_proxy
from core.proxy_pool import infer_proxy_region, normalize_pool_rows, validate_proxy_url

ROOT = Path(__file__).resolve().parents[1]
for _path in (ROOT / "core", ROOT / "core" / "scripts"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))




def test_infers_region_from_proxy_username_without_logging_credentials():
    proxy = "http://user-region-ID-sid-abc:secret@example.test:3010"
    assert infer_proxy_region("POOL", proxy) == "ID"
    assert infer_proxy_region("JP", proxy) == "JP"


def test_normalize_pool_rows_validates_and_preserves_region():
    rows = normalize_pool_rows(
        [
            "# comment",
            "POOL|example.test:3010:user-region-ID-sid-abc:secret",
            "JP|http://u:p@example.test:3011",
        ],
        normalize_proxy,
    )
    assert [region for region, _proxy in rows] == ["ID", "JP"]
    assert all(proxy.startswith("http://") for _region, proxy in rows)


def test_invalid_pool_row_reports_only_row_number():
    with pytest.raises(ValueError, match=r"第 1 行无效") as exc:
        normalize_pool_rows(["ID|not-a-proxy"], normalize_proxy)
    assert "not-a-proxy" not in str(exc.value)


def test_validate_proxy_url_rejects_unsupported_scheme():
    with pytest.raises(ValueError, match="不受支持"):
        validate_proxy_url("ftp://example.test:21")
