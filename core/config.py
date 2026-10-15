"""Shared mailbox, proxy and browser configuration for the Logicc workspace."""
import os

OUTLOOK_ACCOUNTS_FILE = "outlook_accounts.txt"  # 格式: email----password----client_id----refresh_token

OTP_TIMEOUT = 240                   # OTP 拉取超时(秒)

OTP_METHOD = "graph"                # graph = Microsoft Graph API / imap = IMAP XOAUTH2

MAX_WORKERS = 1                     # 并发线程数

THREAD_START_DELAY = 2              # 线程启动间隔(秒)

BROWSER_MODE = "local"              # local = 本地 Chrome / roxy = Roxy 指纹窗口

CHROME_PATH = os.environ.get("CHROME_PATH", "")

USER_DATA_DIR = ""                  # Chrome 用户数据目录，留空用临时目录

ROXY_API_PORT = int(os.environ.get("ROXY_API_PORT", "50000"))

ROXY_API_TOKEN = os.environ.get("ROXY_API_TOKEN", "")

ROXY_WORKSPACE_ID = int(os.environ.get("ROXY_WORKSPACE_ID", "0") or "0")

ROXY_API_RATE_LIMIT = int(os.environ.get("ROXY_API_RATE_LIMIT", "45") or "45")

BITBROWSER_API = "http://127.0.0.1:54345"

BITBROWSER_PROXY = {
    "proxyType": "socks5",
    "host": os.environ.get("PROXY_HOST", "proxy.example.invalid"),
    "port": int(os.environ.get("PROXY_PORT", "10000")),
    "user": os.environ.get("PROXY_USER", "PROXY_USER_PLACEHOLDER"),
    "password": os.environ.get("PROXY_PASS", "PROXY_PASS_PLACEHOLDER"),
}

BITBROWSER_TEMPLATE_PROFILE_ID = os.environ.get("BITBROWSER_TEMPLATE_PROFILE_ID", "")

BITBROWSER_FINGERPRINT_PROFILE = os.environ.get("BITBROWSER_FINGERPRINT_PROFILE", "auto")

PROXY_ENABLED = False               # 注册阶段是否走代理（默认不走，BitBrowser 自带代理）

PROXY_HOST = os.environ.get("PROXY_HOST", "proxy.example.invalid")

PROXY_PORT = int(os.environ.get("PROXY_PORT", "10000"))

PROXY_USER = os.environ.get("PROXY_USER", "PROXY_USER_PLACEHOLDER")

PROXY_PASS = os.environ.get("PROXY_PASS", "PROXY_PASS_PLACEHOLDER")

DEBUG = True

# 本地覆盖：如果存在 config.local.py，把里面定义的同名变量覆盖到本模块。
# config.local.py 已在 .gitignore 中，用来放真实凭据。
# ============================================================
try:
    from config_local import *  # type: ignore  # noqa: F401,F403
except ImportError:
    try:
        # 兼容文件命名 config.local.py（不是合法包名，只能动态加载）
        import importlib.util as _ilu
        import pathlib as _pl
        _local = _pl.Path(__file__).with_name("config.local.py")
        if _local.exists():
            _spec = _ilu.spec_from_file_location("_config_local", _local)
            if _spec and _spec.loader:
                _mod = _ilu.module_from_spec(_spec)
                _spec.loader.exec_module(_mod)
                for _k in dir(_mod):
                    if not _k.startswith("_"):
                        globals()[_k] = getattr(_mod, _k)
    except Exception:
        pass
