# Logicc Register · 本地控制台

微软邮箱好像不行了，其他自测。

一个围绕 Logicc 注册流程与账号管理整理的本地 Web 控制台。将邮箱管理、HTTP 注册任务、运行日志、结果查看和 `logicc2api` 对接集中在同一个工作台，方便观察每一步的执行情况，而不是只看到一个“成功 / 失败”。

基于 **Python + Flask + 原生 HTML / CSS / JavaScript**，默认仅监听本机，不需要部署前端构建工具链。当前仓库为脱敏源码发布版，不附带可用账号、邮箱凭据、代理、API 密钥或历史会话。

## 当前状态，先看这里

- **微软邮箱兼容性待确认，其他邮箱请自行验证。** 保留 Outlook Graph / IMAP XOAUTH2 适配代码，不代表目前仍能正常注册或收码。
- 最近的真实运行在创建注册请求时收到 **HTTP 403**；具体拒绝原因尚未确认，**没有宣称已修复**。
- 发布时本地回归为 **256 项通过**，另通过 JavaScript 语法检查；这是离线固定件与本机 UI 测试结果，不是线上注册成功保证。
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
| logicc2api 对接 | 对已确认账号进行本机导入和可用性检查；与注册结果分开记录 |
| 本地数据保护 | 邮箱凭据与注册检查点加密保存，列表默认不返回明文秘密 |

工作台支持明暗主题、手机布局和数字滚动效果；系统开启“减少动态效果”时会停用数字动画。

## 快速启动

建议使用 **Python 3.11 或更新版本**。以下命令以 Windows、项目解压到 `C:\Projects\logicc-register` 为例：

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
2. **运行配置**：按需填写代理、服务密钥和本机 `logicc2api` 地址。仓库中的示例值不能直接用于真实服务。
3. **任务工作台**：查看任务日志与阶段变化；有异常时保留原始记录，不把“继续任务”当作一定能恢复。
4. **结果确认**：分别检查注册、入驻与自动导入结果。余额读取、页面可达或离线测试通过，都不能代替账号成功确认。

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

## logicc2api 对接

对接对象是另行部署的本机 `logicc2api` 服务，默认地址为 `http://127.0.0.1:18789`，**本仓库不包含该服务**。

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

Node.js 用于 JavaScript 检查。可选本机 Chrome UI 测试通过 `RUN_LOCAL_BROWSER_TESTS=1` 启用；默认跳过，不会执行真实注册。更多验证边界见 [VERIFICATION.md](VERIFICATION.md)。

## 许可证

基于原框架裁剪，保留原作者版权声明，采用 [MIT License](LICENSE)。
