# Logicc Register · 本地控制台与 OpenAI 网关

微软邮箱好像不行了，其他自测。
需要自备打码API。
域名邮箱未进行过实际测试，还请自检。

已有平台会话、仅使用模型网关时，不需要配置邮箱或打码服务。

一个集邮箱管理、HTTP 流程任务、运行日志和 **OpenAI 兼容模型网关** 于一体的本地 Web 控制台。已有 Logicc 平台会话可直接导入本项目，在支持自定义 OpenAI Base URL 的客户端中使用模型，无需另外下载、配置或启动 logicc2api 项目。

基于 **Python + Flask + 原生 HTML / CSS / JavaScript**，网关数据面使用 **Node.js 24+**，由项目自动启动和回收；不需要 npm install 或前端构建工具链。默认仅监听本机。当前仓库为脱敏源码发布版，不附带可用账号、邮箱凭据、代理、API 密钥或历史会话。

## 当前状态，先看这里

- **微软邮箱兼容性待确认，其他邮箱请自行验证。** 保留 Outlook Graph / IMAP XOAUTH2 适配代码，不代表目前仍能正常注册或收码。
- **本次已确认可用的是内置模型网关。** 注册流程此前出现过 HTTP 403；本次发布没有重新验证注册，不能把模型对话成功当作注册问题已修复。
- 网关已完成真实模型列表、Chat Completions SSE、Responses JSON 和工具结果回传验证。本次脱敏副本 **273 项测试通过**；详情见 [验证说明](VERIFICATION.md)，不附带历史账号数据。
- 上游页面、接口、邮件格式和验证要求可能变化，历史成功记录不能代替当前验证。

## 项目提供什么

| 模块 | 说明 |
| --- | --- |
| 邮箱管理 | 管理邮箱来源与状态；兼容 Outlook、密码 IMAP、Relay 和自建域名邮箱适配 |
| 注册工作台 | HTTP 流程任务管理，显示每个账号的阶段、状态与错误原因 |
| 实时日志 | 黑底日志面板，配合任务进度、结果列表定位失败阶段 |
| 代理配置 | 代理条目管理与只读连通性检测；单个任务期间保持固定出口 |
| 服务配置 | 本地配置 CapMonster，展示余额及求解服务状态；不附赠密钥或余额 |
| 结果管理 | 区分注册确认、公司入驻和对接结果，不把暂停或待核对标记为成功 |
| 内置模型网关 | OpenAI Chat Completions / Responses、SSE、工具调用；独立 API Key，最多 32 并发 |
| 模型账号池 | 已确认平台会话同步、按 Session 去重、JWT 刷新、轮换 Cookie 保存、异常冷却、加密持久化 |
| logicc2api 对接（可选） | 对已确认账号进行本机导入和可用性检查；与注册结果分开记录 |
| 本地数据保护 | 邮箱凭据与注册检查点加密保存，列表默认不返回明文秘密 |

工作台支持明暗主题、手机布局和数字滚动效果；系统开启“减少动态效果”时会停用数字动画。

## 快速启动

建议使用 **Python 3.11 或更新版本**；内置网关另需安装 **Node.js 24+** 并加入 PATH，可通过 `LOGICC_NODE` 指定其完整可执行文件路径。以下命令以 Windows、项目解压到 `C:\Projects\logicc-register` 为例：

```powershell
python -m venv 'C:\Projects\logicc-register\.venv'
& 'C:\Projects\logicc-register\.venv\Scripts\python.exe' -m pip install -r 'C:\Projects\logicc-register\requirements.txt'
& 'C:\Projects\logicc-register\.venv\Scripts\python.exe' 'C:\Projects\logicc-register\app.py'
```

启动后访问 **http://127.0.0.1:8866**。

Linux / macOS 可使用仓库根目录的 `start.sh`。默认只绑定 `127.0.0.1`；不要直接将管理控制台暴露到公网。

> Windows 直接启动 `app.py` 不会自动加载 `.env`。如需调整端口或设置访问密码，请在启动进程前设置 `FREE_CONSOLE_PORT`、`FREE_CONSOLE_PASSWORD` 等环境变量，配置项见 `.env.example`。

## 配置与使用

1. **邮箱管理**：导入自己的邮箱资料，检查来源与状态。仅有适配代码不等于该邮箱服务当前可用。
2. **模型网关**：启用内置网关，同步本项目已确认账号或导入已有平台会话；设置独立的网关出口代理，点击检测获取真实模型列表。
3. **连接客户端**：选择 OpenAI 兼容服务，填写 `http://127.0.0.1:8866/v1`，在网关页面点击“复制密钥”；模型填写列表中的 ID。
4. **运行配置**：按需填写邮箱、代理与其他服务配置；外部 `logicc2api` 对接仅为可选兼容功能。
5. **任务工作台**：查看任务日志与阶段变化；有异常时保留原始记录，不把“继续任务”当作一定能恢复。
6. **结果确认**：分别检查注册、入驻与自动导入结果。余额读取、页面可达或离线测试通过，都不能代替账号成功确认。

邮箱提取器仅识别 Logicc 验证邮件，并检查发件人、邮件时间和重复验证码；不接收其他平台验证码。邮件模板变化可能导致收码超时。

### 状态如何理解

| 现象 | 含义 |
| --- | --- |
| `HTTP 403` / `remote_request_rejected` | 上游拒绝了请求；仅凭状态码不能判断具体原因 |
| `ERROR_CAPTCHA_UNSOLVABLE` | 本次求解服务失败，不表示再次尝试一定成功 |
| `capmonster_poll_timeout` | 本地查询预算耗尽，不等于服务端已返回最终失败 |
| `network_unavailable` / `upstream_unavailable` | 网络或上游服务异常，需要结合失败阶段判断 |
| `needs_check` / `partial` | 结果尚未完整确认，不能计为注册成功 |

程序保留收费回执与不确定写请求的保护逻辑，不把恢复任务理解为可以无限重试或反复扣费。

## 内置网关与可选外部对接

**日常使用模型不需要运行第二个项目。** 本项目内置 MIT 许可的适配核心，由 Flask 控制台监督运行，公开接口只有 OpenAI 兼容的模型列表、Chat Completions 与 Responses。工具执行、文件权限、MCP 和 Skill 仍由客户端负责，不由网关授予。

本机默认 Base URL 是 `http://127.0.0.1:8866/v1`，API Key 在本机首次使用时随机生成、加密保存。列表不返回 Key；密钥轮换后旧 Key 对新请求失效。完整用法、支持接口、账号导入格式与限制见 [模型网关说明](MODEL_GATEWAY.md)。

旧的外部 `logicc2api` 导入功能仍保留，默认目标 `http://127.0.0.1:18789`，但内置网关不依赖它。

仅在注册身份和公司入驻都确认后执行导入。注册是否成功与目标服务是否可用分别保存，导入失败不会自动触发重新注册。

接口约定、去重与结果字段见 [对接说明](INTEGRATION.md)。

## 数据与脱敏范围

- 不发布 `data/`、`output/`、日志、HAR、截图、加密数据库、Vault key 或本机调试脚本。
- 凭据列表默认隐藏；Logicc 平台密码与邮箱密码不是同一个值。
- **注意：** 为兼容邮箱工具，运行后仍可能在忽略目录 `data/accounts/` 生成明文邮箱资料；不要分享整个工作目录。
- 若配置 `logicc2api`，其会话存储保护由目标项目负责，不能将“本项目使用加密 Vault”理解为所有相关文件均已加密。
- 发布内容经过已知私密值比对、Gitleaks 扫描和压缩包复核；范围摘要见 [SANITIZATION.json](SANITIZATION.json)，文件校验值见 [FILE_MANIFEST.sha256](FILE_MANIFEST.sha256)。

## 本地验证

安装依赖及 `pytest` 后运行：

```powershell
python -m pytest -q -p no:cacheprovider 'C:\Projects\logicc-register\tests'
node --check 'C:\Projects\logicc-register\static\app.js'
```

Node.js 24+ 同时用于内置网关运行和 JavaScript 检查。可选本机浏览器测试通过 `RUN_LOCAL_BROWSER_TESTS=1` 启用；网关 Playwright 验收还需设置 `LOGICC_TEST_BROWSER` 为已安装 Chromium 浏览器的完整路径。默认跳过这些浏览器测试，不会执行真实注册。更多验证边界见 [VERIFICATION.md](VERIFICATION.md)。

## 许可证

基于原框架裁剪，保留原作者版权声明，采用 [MIT License](LICENSE)。内置适配核心来自 [JamesZhaoY/logicc2api](https://github.com/JamesZhaoY/logicc2api)，同为 MIT，保留其 [版权声明与来源](core/gateway_vendor/NOTICE.md) 和 [许可证](core/gateway_vendor/LICENSE)。
