# logicc2api integration



依据本机 `C:\Projects\logicc2api\server.mjs` 与 `C:\Projects\logicc2api\pool.mjs`，不改目标源码或直接改其账号文件。

```http
POST http://127.0.0.1:18789/api/accounts
X-Logicc-Admin: 1
Content-Type: application/json
```

```json
{
  "name": "account@example.test",
  "clientCookie": "CLERK_CLIENT_COOKIE_VALUE",
  "sessionId": "sess_CURRENT_ACCOUNT_SESSION",
  "enabled": true
}
```

- `clientCookie` 是 `clerk.logicc.com` 的 `__client` Value，**不是** `__session` JWT，也不是完整 Cookie 请求头。
- `sessionId` 来源于本次已验证身份的 Clerk 会话；不使用原始抓包中的旧值。
- 可选 `token` 支持含 `sid` / `exp` 的 JWT，但单独 JWT 到期不能长期刷新。本对接不发送 token，优先使用可刷新组合。
- `name` 只作本机显示，使用邮箱地址；目标不需要邮箱密码、邮箱 OAuth client ID/RT、平台密码或 tenantId 作为导入字段。
- 目标管理 API 不需要 `/v1/*` 的客户端 API Key；使用本机 Host / Origin 边界和 `X-Logicc-Admin` 请求头。对接端仅允许带端口的 loopback HTTP 地址，禁止跳转或向公网目标发送 Cookie。

## 顺序与不确定结果

1. 要求注册 `registration_ok` 和 `onboarding_ok` 都为 true。
2. 读取目标 `/health` 与 `/api/state`，核对其上游仍为 Logicc。
3. 按 `sessionId` 搜索已有账号；存在则沿用，不覆盖目标已轮换的 Cookie。
4. 不存在才 POST 添加。提交前保存加密发送标记；响应丢失后只从目标状态核对，不盲目重传。
5. POST `/api/accounts/{id}/check`；真实模型数大于 0 且账号 ready，才记录 `integration_status=ready`。
6. 手工继续只处理导入/检测，不再执行注册、发码或 CapMonster。

注册是否成功与目标是否可用独立保存：

| 字段 | 含义 |
|---|---|
| `registration_ok` | Logicc 认证 `/me` 已核对 |
| `onboarding_ok` | 公司/组织与最终 tenant 已核对 |
| `integration_status` | disabled / imported / ready / check_failed / failed / unknown 等 |
| `integration_error` | 脱敏错误码，不回显远端错误正文 |
| `integration_account_id` | 目标本机账号 ID |
| `integration_models` | 实际模型列表条数 |
| `integration_checked_at` | 模型检测的 UTC 时间，不代表永久有效 |

账号池使用 `logicc_ready` 记录模型连接检测，不把 Logicc 账号标记成 GPT FREE/PLUS。检测失败不推断账号被封。

## 控制台 API

- `GET/PATCH /api/services/capmonster`：启停、保存新 key，空 key 保留旧值；GET 不回显 key。
- `POST /api/services/capmonster/test`：只查余额，不创建付费任务。
- `GET/PATCH /api/services/logicc2api`：启停自动导入、设置本机服务地址。
- `POST /api/services/logicc2api/test`：只读取本机管理状态，不调用上游。
- `GET /api/proxies`、`POST /api/proxies/import`、`POST /api/proxies/{id}/test`：固定代理加密导入、脱敏读取与 HTTPS 检测。
- `POST /api/runs`：单账号，可传 `proxy_id` 或手填 `proxy`，不能两者同时填写。
- `POST /api/jobs/{id}/logicc2api`：对已确认任务执行幂等导入/模型检测。

