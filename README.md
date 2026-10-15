# Logicc 本地控制台

基于原框架裁剪，原 MIT 许可证及版权声明保留于 `LICENSE`。发布内容不包含本机账号、密钥、会话、抓包或运行记录。

**当前状态：** 本仓库的离线回归不代表上游注册可用。最近本机运行在创建注册时收到 HTTP 403，具体拒绝原因未确认；发布版本未宣称已修复该问题。

## 当前能力

- 保留 Flask + HTML/CSS/JS 控制台、任务管理基础、账号池、代理及浏览器宿主工具。
- 保留加密邮箱凭据库，支持 Outlook Graph / IMAP XOAUTH2、密码 IMAP、Relay 和自建域名邮箱。
- 仅提取 **Logicc 验证邮件中的六位验证码**；不接收 GPT 验证码，也不接受来源不明的纯六位数字响应。
- 删除 GPT 注册/登录、Codex OAuth、Sentinel、2FA、手机绑定、付款、GPT 导出与旧注册 CLI。对应业务按钮、配置和测试一起移除。
- Logicc HTTP 注册（单账号与批量）：环境/客户端 → 新 Turnstile → 创建注册 → 发码/收码/验码 → 会话 → `/api/users/me` → 公司入驻/组织切换 → 最终 `/me`。不回放遥测或旧凭据，不自动重复结果不确定的写请求。
- 注册身份和公司入驻分别记录；`human_required` / `code_required` / `needs_check` 不计为成功。

## 收码筛选

Graph / IMAP 检查真实 From 地址域名：`logicc.com` 及子域；共享 Clerk 地址（`clerk.com` / `clerk.dev` 及子域）还必须在主题/正文中明确标识 Logicc。
Relay 没有可靠发件人元数据时，要求正文包含 Logicc 与验证码语义。正文混入 GPT 标识、只有裸数字、营销/订单数字均拒绝。
域名邮箱逐封筛选并解码 MIME，不拼接多个邮件后取码，避免其他应用验证码借用相邻邮件的 Logicc 标识。

已用真实德文邮件确认 `Bestätigungscode` 规则，保留发件人、时间和重复码校验；垃圾箱也参与只读扫描。上述域名集合不是完整的 Logicc 邮件发件人列表。
规则宁可超时也不接收错误平台的验证码。发件人变化时须用真实邮件确认后调整。

默认启用 Relay 新邮件基线及重复码保护。注册过程中内部自动收码；邮箱管理页已移除手动收码和删除按钮。
协议调用保留 `after_ts`、`excluded_otps`、总截止时间和 Graph scope 缺失时的 IMAP 回退。
内部验证码接口保留显式 POST 和 `Cache-Control: no-store`；验证码不写日志、结果文件或浏览器持久存储。

## 邮箱导入

- Outlook：`email----mail_password----client_id----refresh_token`
- Relay：`email----https://your-owned-relay/inbox`
- NotLetters：`email----mail_password` 或支持的卖家发货格式。

旧 GPT 密码、2FA、FREE/PLUS 附加字段不再接受。替换导入先完整验证再写入，不能删除运行中预占的邮箱。
Vault 加密保存凭据；为兼容邮箱工具，原有本机账号文本仍会生成于忽略目录 `data/accounts/`，不要外传。

## 启动与检查

```powershell
python -m pip install -r 'C:\Projects\logicc-register\requirements.txt'
python 'C:\Projects\logicc-register\app.py'
```

默认地址 `http://127.0.0.1:8866`，仅本机监听。保留 `FREE_CONSOLE_PASSWORD` / `FREE_CONSOLE_PORT` 等环境变量以兼容启动脚本；没有密码时没有 Basic Auth。
Windows 直接启动 Python 不自动加载 `.env`，可通过 PowerShell 环境变量设置。

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -m pytest -q -p no:cacheprovider 'C:\Projects\logicc-register\tests'
node --check 'C:\Projects\logicc-register\static\app.js'
```

测试运行目录与真实账号数据分离。可选纯本机 Chromium 资源测试通过 `RUN_LOCAL_BROWSER_TESTS=1` 启用；不注册账号。
本地合同测试不等于远端注册成功；真实运行以对应任务 JSONL 中的 `registration_ok` / `onboarding_ok` 为准。

## CapMonster

不增加 SDK，复用 `httpx` 调用官方 JSON API。密钥使用 Vault 同一加密密钥保存于本机忽略目录：
`C:\Projects\logicc-register\data\services\capmonster.enc`。
在“运行配置 → CapMonster”中配置密钥、启停并测试余额。旧版加密文件自动兼容；禁用只影响后续任务，保留加密密钥。读取时只返回是否已配置，空密钥保存表示保留，不暴露密钥。

- 从当前 Clerk 环境读取 sitekey/widget，不使用抓包 Token；`pageAction=signup` 与 Clerk SDK 一致。
- 每个注册任务最多创建 **1 次**付费求解，最多轮询 60 次 / 180 秒。任务凭据与回执只保存在加密检查点。
- 创建请求结果不确定时停止，不再次购买；轮询网络错误可继续查询同一个 taskId，不能无限重试。
- 求解返回 Token 后仍须由 Clerk 实际接受；服务 `ready` 不代表注册成功。拒绝、余额不足、限流、超时均明确暂停。
- 使用相同 User-Agent；代理必须为求解服务可访问的公网 IP，本机代理/私网地址不支持。
- 密钥保护依赖本机 Vault key；不要把整个 `data` 目录、邮箱兼容文本或原抓包外传。

### 错误展示与恢复边界

任务表、队列、详情和结果按具体错误显示“求解服务失败 / 求解查询超时 / 网络连接失败 / 上游服务异常 / 付费任务保护”，不再把这些原因仅展示为“需要人工”。这是展示修正：历史 JSONL、任务状态、收费回执和恢复规则均不改写。
`ERROR_CAPTCHA_UNSOLVABLE` 只说明本次求解失败，不保证重试成功；`capmonster_poll_timeout` 是本地预算耗尽，不是服务端最终失败证明。已有失败、创建结果未知或已消费的回执仍阻止新建付费任务；轮询恢复不重置原来的 60 次 / 180 秒预算。本次未增加验证码重试、批量重跑或自动解锁。

参考：[Turnstile API](https://docs.capmonster.cloud/zh/docs/captchas/turnstile-task/)、[任务结果](https://docs.capmonster.cloud/zh/docs/api/methods/get-task-result/)。


## 固定代理池与自动导入

- “运行配置 → 固定代理池”追加导入 `host:port:user:password` 或 `REGION|proxyURL`，去重后加密保存。列表不回显用户名或密码。
- 检测会读取出口 IP、Logicc 注册页、Clerk 环境，不提交注册身份。地区标签来自输入，不冒充实测地理位置。
- 注册工作台是批量入口：左侧粘贴邮箱列表（最多 100），右侧粘贴代理列表（最多 100），再设并发数（1–32）。留空代理为直连；旧 API 的 `proxy_id` 与 `/api/runs` 单账号入口保持兼容。原托管代理参数仍供兼容检测使用，不自动套入注册，不替换用户的 Session。
- 邮箱框可直接粘贴带凭据的行（`email----邮箱密码----client_id----refresh_token`、`email----relay_url` 等），启动时自动导入邮箱管理；纯地址行则必须已在邮箱管理中导入。整批校验通过后才写入，坏行不会留下半批数据。
- 代理按行轮询分配：代理数量 ≥ 账号数量时一对一；数量少时从头再轮一遍（`assign_proxy_round_robin`）。每个账号只用自己的那一条，中途不换出口。网关启动前统一解析为公网地址，任一条解析失败则整批拒绝。
- 并发由调度器限制为最多 `workers` 个在跑子进程，账号仍逐个执行原有单账号 runner；一次只允许一个批次处于未完成状态。
- 新任务先固定一个公网代理网关，注册 HTTP 与 CapMonster 使用相同地址和完整认证参数。Clash Fake-IP 不可供远程求解使用；系统只返回非公网 DNS 地址时，通过 [Google DoH JSON API](https://developers.google.com/speed/public-dns/docs/doh/json) 查询公网 A 记录。不会把代理口令发给 DNS 服务。
- “运行配置 → 自动导入”设置本机 `logicc2api` 地址和开关，当前已配置 `http://127.0.0.1:18789`。测试仅查本机健康与管理 API，不调用上游。
- 注册身份及公司入驻都确认后，自动传递 `name`、`clientCookie`（Clerk `__client` 值）、`sessionId`、`enabled`；不发送邮箱密码、邮箱 OAuth Token 或平台密码。
- 导入后检查真实模型列表；按 Session 去重。导入失败单独记录，不将成功注册改成失败。已注册任务可在详情中点击“导入/检测 logicc2api”，不会重注册或再付费求解。
- 管理 API 操作已有账号池，不直接写 `C:\Projects\logicc2api\data\state.json`，不覆盖已有账号。目标继续使用自身全局 Clash 代理，不继承逐账号注册代理。
- `logicc2api` 会在其本机状态文件明文保存会话，依赖原 Windows ACL；不要备份或分享包含会话的数据目录。API Key 只保护兼容 `/v1/*` 接口，不代替本机管理台认证。

接口、结果与实测边界见 [自动对接说明](INTEGRATION.md)。


## 当前工作台与密码查看

- 工作台用邮箱列表与代理列表输入框，不从下拉列表选择；批量执行仍复用单账号 runner。邮箱凭据既可在邮箱管理页导入，也可随批量粘贴自动导入。
- 条款上方为固定黑底实时日志框，随页面剩余高度伸缩；桌面启动按钮靠近底部，手机允许正常滚动。只轮询本机脱敏日志，不触发注册或求解。
- 邮箱管理仅显示邮箱、来源、状态和 Logicc 平台密码四列，不显示收码、删除操作。
- 密码为平台注册时自动生成的独立密码，不是邮箱密码。只对同身份、已确认注册的加密检查点提供查看。
- 列表不含明文密码；点击查看才通过同源 JSON POST 返回，响应禁止缓存。关闭、切换页面或隐藏标签页后清除显示，不写 localStorage。
- 本轮 UI 更改未新增账号，也未进行付费求解。批量并发（最高 32、单批 100 账号 / 100 代理）已接入，本轮只用固定件与本地子进程验证，未对真实目标批量注册。
- 批次读数为聚合值：绿色“已完成/总任务”按批次汇总（含失败），待人工/待收码不计为完成；账号表逐行显示邮箱、代理地区、状态、阶段与错误码。批次全部落库后若仍有账号停在待人工/待收码，标题显示该待办状态而不是“已确认完成”。
- 停止当前批次会中断未完成账号并保留已确认的注册结果；一次只允许一个未完成批次，避免同一邮箱被重复注册。

工作台右上显示当前批次的绿色“已完成/总任务”，不是历史账号累计数；已完成包含成功及失败，待人工/待验证码不计入完成。
旁边“余额：”后用紫色显示 CapMonster API 余额，页面可见时最多每 60 秒读取一次；未配置或网络失败显示 `--`，不伪造零余额。
上述数值变化使用逐位竖向滚动，系统启用减少动态效果时立即更新。查询余额复用只读余额接口，不创建付费任务。
所有凭据弹窗的关闭按钮保持横排，边框已加深；手机宽度也不换行。
