#!/usr/bin/env python3
"""Provision receive-only domain mailboxes and optionally import the account pool."""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / "core"
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))

from account_vault import get_account_vault  # noqa: E402
from domain_mailbox import provision_mailboxes  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="创建自建域名邮箱并写入本地账号池")
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--domain", default="")
    parser.add_argument("--provider", default="")
    parser.add_argument("--local-part", default="")
    parser.add_argument("--config", default="")
    parser.add_argument("--no-import", action="store_true", help="只创建并保存凭据，不导入账号池")
    args = parser.parse_args()

    items = provision_mailboxes(
        args.count,
        provider_id=args.provider,
        domain=args.domain,
        local_part=args.local_part,
        config_path=args.config or None,
    )
    if not items:
        raise SystemExit("服务端没有返回邮箱")

    output_dir = ROOT / "output" / "mailboxes"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"domain-mailboxes-{datetime.now():%Y%m%d-%H%M%S}.txt"
    output_path.write_text("\n".join(item.account_line for item in items) + "\n", encoding="utf-8")
    try:
        os.chmod(output_path, 0o600)
    except OSError:
        pass

    imported = 0
    if not args.no_import:
        result = get_account_vault().import_text(
            "\n".join(item.account_line for item in items),
            forced_kind="icloud",
            update_existing=True,
        )
        imported = int(result.get("total") or 0)

    print(f"created={len(items)} imported={imported}")
    print(f"credentials_file={output_path}")
    print("凭据文件含一次性 inbox_url，请私密保存；聊天和日志不输出 Token。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
