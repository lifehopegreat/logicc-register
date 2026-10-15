import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';

export class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

export function claims(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url'));
    return payload && typeof payload === 'object' && !Array.isArray(payload) ? payload : {};
  }
  catch { return {}; }
}
export const fresh = token => Number(claims(token).exp) > Date.now() / 1000 + 10;
export function safeError(error) {
  return String(error?.message || error).replace(/eyJ[\w-]+\.[\w-]+\.[\w-]+/g, '[凭据已隐藏]').slice(0, 350);
}

// Clear completed request deadlines so idle Durable Objects can be evicted.
export function deadline(milliseconds) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new DOMException('Request timed out', 'TimeoutError')), milliseconds);
  timer.unref?.();
  return { signal: controller.signal, clear: () => clearTimeout(timer) };
}

function cleanSecret(value, field) {
  if (typeof value !== 'string' || value.length > 20000) throw new HttpError(400, `${field} 格式不正确`);
  const text = value.trim().replace(/^(['"])(.*)\1$/, '$2').replace(/^__client=/, '');
  if (text && !/^[\w.~+/=-]+$/.test(text)) throw new HttpError(400, `${field} 请填写凭据值，不要填写完整 Cookie 请求头`);
  return text;
}

export class AccountPool {
  constructor(file, env = process.env, store) {
    this.file = file;
    this.store = store;
    this.env = env;
    this.cursor = 0;
    this.runtime = new Map();
    this.startedAt = Date.now();
    this.data = { version: 1, accounts: [], requests: [], models: [], modelsUpdatedAt: null };
    const saved = store ? store.get('accounts') : existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : undefined;
    if (saved !== undefined) {
      this.data = saved;
      if (this.data.version !== 1 || !['accounts', 'requests', 'models'].every(k => Array.isArray(this.data[k]))) {
        throw new Error('号池数据格式不正确，请检查数据文件；原文件未被覆盖。');
      }
      if (!store) chmodSync(file, 0o600);
    }
    if (!this.data.accounts.length && (env.LOGICC_CLIENT_COOKIE || env.LOGICC_TOKEN || env.LOGICC_TOKEN_CMD || env.LOGICC_TOKEN_FILE)) {
      let token = env.LOGICC_TOKEN || '';
      try { token ||= readFileSync(env.LOGICC_TOKEN_FILE || '/tmp/logicc-token.txt', 'utf8').trim(); } catch {}
      this.data.accounts.push({
        id: randomUUID(), name: '默认账户', enabled: true, legacy: true,
        clientCookie: env.LOGICC_CLIENT_COOKIE || '', token,
        sessionId: env.LOGICC_SESSION_ID || claims(token).sid || '',
        createdAt: Date.now(), updatedAt: Date.now(), lastCheckedAt: null, lastError: null,
      });
      this.save();
    }
  }

  save() {
    if (this.store) return this.store.put('accounts', this.data);
    mkdirSync(dirname(this.file), { recursive: true, mode: 0o700 });
    const temp = `${this.file}.tmp`;
    writeFileSync(temp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
    chmodSync(temp, 0o600);
    renameSync(temp, this.file);
  }

  runtimeFor(id) {
    if (!this.runtime.has(id)) this.runtime.set(id, { inFlight: 0, refresh: null, cooldownUntil: this.data.accounts.find(a => a.id === id)?.cooldownUntil || 0 });
    return this.runtime.get(id);
  }

  account(id) {
    const account = this.data.accounts.find(a => a.id === id);
    if (!account) throw new HttpError(404, '账户不存在');
    return account;
  }

  status(account) {
    if (!account.enabled) return 'disabled';
    if (this.runtimeFor(account.id).cooldownUntil > Date.now()) return 'cooling';
    if (!fresh(account.token) && !account.clientCookie && !(account.legacy && this.env.LOGICC_TOKEN_CMD)) return 'expired';
    if (account.lastError) return 'retry';
    return account.lastCheckedAt ? 'ready' : 'pending';
  }

  publicAccount(account) {
    const runtime = this.runtimeFor(account.id);
    const records = this.data.requests.filter(r => r.accountId === account.id && r.kind === 'chat');
    const success = records.filter(r => r.status === 'success');
    return {
      id: account.id, name: account.name, enabled: account.enabled, sessionId: account.sessionId,
      hasClientCookie: Boolean(account.clientCookie), hasToken: Boolean(account.token),
      tokenExpiresAt: claims(account.token).exp ? claims(account.token).exp * 1000 : null,
      createdAt: account.createdAt, updatedAt: account.updatedAt,
      lastCheckedAt: account.lastCheckedAt, lastError: account.lastError,
      status: this.status(account), inFlight: runtime.inFlight, cooldownUntil: runtime.cooldownUntil,
      requests: records.length, successRate: records.length ? success.length / records.length * 100 : null,
      avgLatency: success.length ? success.reduce((s, r) => s + r.durationMs, 0) / success.length : null,
    };
  }

  normalize(input, existing) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw new HttpError(400, '账户必须是 JSON 对象');
    const account = existing ? { ...existing } : {
      id: randomUUID(), name: '', enabled: true, clientCookie: '', token: '', sessionId: '',
      createdAt: Date.now(), lastCheckedAt: null, lastError: null,
    };
    if ('name' in input) {
      if (typeof input.name !== 'string' || !input.name.trim() || input.name.trim().length > 80) throw new HttpError(400, '账户名称需要 1–80 个字符');
      account.name = input.name.trim();
    }
    if (!account.name) throw new HttpError(400, '请填写账户名称');
    if ('enabled' in input) {
      if (typeof input.enabled !== 'boolean') throw new HttpError(400, 'enabled 必须为布尔值');
      account.enabled = input.enabled;
    }
    for (const field of ['clientCookie', 'token']) {
      if (field in input) {
        const secret = cleanSecret(input[field], field);
        if (secret) { account[field] = secret; account.lastError = null; account.lastCheckedAt = null; }
      }
    }
    if (input.token) {
      const decoded = claims(account.token);
      if (typeof decoded.sid !== 'string' || !/^sess_[a-zA-Z0-9_-]{1,150}$/.test(decoded.sid) || !Number.isFinite(decoded.exp) || account.token.split('.').length !== 3) throw new HttpError(400, 'Session JWT 需要包含有效的 sid 和 exp');
      if (input.sessionId && input.sessionId !== decoded.sid) throw new HttpError(400, 'Session ID 与 JWT 中的 sid 不一致');
      account.sessionId = decoded.sid;
    }
    if ('sessionId' in input && input.sessionId !== '') {
      if (typeof input.sessionId !== 'string' || !/^sess_[a-zA-Z0-9_-]{1,150}$/.test(input.sessionId)) throw new HttpError(400, 'Session ID 应以 sess_ 开头');
      account.sessionId = input.sessionId;
    }
    if (existing && !input.token && (account.sessionId !== existing.sessionId || account.clientCookie !== existing.clientCookie)) {
      account.token = '';
      account.lastError = null;
      account.lastCheckedAt = null;
    }
    if (!account.clientCookie && !account.token && !(account.legacy && this.env.LOGICC_TOKEN_CMD)) throw new HttpError(400, '请填写 __client Cookie 或 Session JWT');
    if (account.clientCookie && !account.sessionId) throw new HttpError(400, '__client Cookie 需要同时填写 Session ID 或含 sid 的 Session JWT');
    account.updatedAt = Date.now();
    return account;
  }

  addMany(inputs) {
    if (!Array.isArray(inputs) || !inputs.length || inputs.length > 200 || this.data.accounts.length + inputs.length > 200) throw new HttpError(400, '号池最多 200 个账户，请导入非空数组');
    const accounts = inputs.map(input => this.normalize(input));
    const seen = new Set(this.data.accounts.map(a => a.sessionId).filter(Boolean));
    for (const account of accounts) {
      if (account.sessionId && seen.has(account.sessionId)) throw new HttpError(409, `账户「${account.name}」的 Session 已存在，整批未导入`);
      if (account.sessionId) seen.add(account.sessionId);
    }
    this.data.accounts.push(...accounts);
    this.save();
    return accounts.map(a => this.publicAccount(a));
  }

  update(id, input) {
    const current = this.account(id);
    if (this.runtimeFor(id).inFlight || this.runtimeFor(id).refresh) throw new HttpError(409, '账户正在处理请求，请完成后再修改');
    const updated = this.normalize(input, current);
    if (this.data.accounts.some(a => a.id !== id && a.sessionId && a.sessionId === updated.sessionId)) throw new HttpError(409, '此 Session 已在号池中');
    Object.assign(current, updated);
    this.runtimeFor(id).cooldownUntil = 0;
    current.cooldownUntil = 0;
    this.save();
    return this.publicAccount(current);
  }

  remove(id) {
    const account = this.account(id);
    const runtime = this.runtimeFor(id);
    if (runtime.inFlight || runtime.refresh) throw new HttpError(409, '账户正在处理请求，请完成后再删除');
    this.data.accounts.splice(this.data.accounts.indexOf(account), 1);
    this.runtime.delete(id);
    this.save();
  }

  acquire() {
    const candidates = this.data.accounts.filter(a => a.enabled && this.runtimeFor(a.id).cooldownUntil <= Date.now() &&
      (fresh(a.token) || (a.clientCookie && a.sessionId) || (a.legacy && (this.env.LOGICC_TOKEN_FILE || this.env.LOGICC_TOKEN_CMD))));
    if (!candidates.length) throw new HttpError(503, '没有可用账户，请在控制台添加、启用或检测账户');
    // ponytail: 单进程内按最低并发数轮询；多实例部署时再使用共享调度器。
    const min = Math.min(...candidates.map(a => this.runtimeFor(a.id).inFlight));
    const available = candidates.filter(a => this.runtimeFor(a.id).inFlight === min);
    const account = available[this.cursor++ % available.length];
    this.runtimeFor(account.id).inFlight++;
    return account;
  }

  release(account) { this.runtimeFor(account.id).inFlight = Math.max(0, this.runtimeFor(account.id).inFlight - 1); }

  async tokenFor(account, force = false) {
    if (!force && fresh(account.token)) return account.token;
    const runtime = this.runtimeFor(account.id);
    if (runtime.refresh) return runtime.refresh;
    runtime.refresh = this.refreshToken(account, force);
    try { return await runtime.refresh; } finally { runtime.refresh = null; }
  }

  async refreshToken(account, force) {
    const previous = account.token;
    if (account.legacy) {
      try {
        const token = readFileSync(this.env.LOGICC_TOKEN_FILE || '/tmp/logicc-token.txt', 'utf8').trim();
        if (fresh(token) && (!force || token !== previous) && (!account.sessionId || claims(token).sid === account.sessionId)) {
          account.token = token; this.save(); return token;
        }
      } catch {}
      if (this.env.LOGICC_TOKEN_CMD) {
        let stdout;
        try { ({ stdout } = await promisify(exec)(this.env.LOGICC_TOKEN_CMD, { timeout: 15000, maxBuffer: 65536 })); }
        catch { throw new HttpError(401, '外部 JWT 刷新命令执行失败，请在本机检查命令配置'); }
        const token = stdout.trim();
        if (!fresh(token) || (account.sessionId && claims(token).sid !== account.sessionId)) throw new HttpError(401, '刷新命令返回的 JWT 已过期或不属于此账户');
        account.token = token; this.save(); return token;
      }
    }
    if (!account.clientCookie || !account.sessionId) throw new HttpError(401, 'Session JWT 已过期，请更新 JWT 或配置 __client Cookie 与 Session ID');
    const base = (this.env.LOGICC_CLERK_BASE || 'https://clerk.logicc.com').replace(/\/+$/, '');
    const timeout = deadline(20000);
    try {
      const response = await fetch(`${base}/v1/client/sessions/${encodeURIComponent(account.sessionId)}/tokens`, {
        method: 'POST', headers: { Cookie: `__client=${account.clientCookie}`, Origin: 'https://app.logicc.com' },
        signal: timeout.signal, redirect: 'manual',
      });
      // Clerk 若轮换客户端凭据，保存响应中的新值，重启后仍使用新值。
      for (const cookie of response.headers.getSetCookie()) {
        const match = cookie.match(/^__client=([^;]+)/);
        if (match) { account.clientCookie = cleanSecret(match[1], '__client'); this.save(); }
      }
      if (!response.ok) throw new HttpError(response.status, `凭据刷新失败（HTTP ${response.status}），请更新 __client Cookie / Session ID`);
      const data = await response.json();
      if (!fresh(data.jwt) || claims(data.jwt).sid !== account.sessionId) throw new HttpError(401, '上游没有返回属于此账户的有效 Session JWT');
      account.token = data.jwt;
      this.save();
      return account.token;
    } finally { timeout.clear(); }
  }

  healthy(account) {
    account.lastError = null;
    account.lastCheckedAt = Date.now();
    this.runtimeFor(account.id).cooldownUntil = 0;
    account.cooldownUntil = 0;
  }

  failed(account, error) {
    account.lastError = safeError(error);
    account.lastCheckedAt = Date.now();
    const status = error.status || 502;
    if ([401, 403, 429].includes(status) || status >= 500) {
      const cooldown = status === 429 ? 60000 : [401, 403].includes(status) ? 300000 : 15000;
      this.runtimeFor(account.id).cooldownUntil = Date.now() + cooldown;
      account.cooldownUntil = this.runtimeFor(account.id).cooldownUntil;
    }
  }

  record(record) {
    this.data.requests.unshift({ id: randomUUID(), ...record });
    // ponytail: 本地控制台保留最近 2,000 条元数据，规模扩大后再换 SQLite。
    this.data.requests.length = Math.min(this.data.requests.length, 2000);
    this.save();
  }

  snapshot() {
    const now = Date.now();
    const records = this.data.requests.filter(r => r.kind === 'chat' && r.startedAt > now - 86400000);
    const success = records.filter(r => r.status === 'success');
    const firstTokens = success.filter(r => r.ttftMs != null);
    const accounts = this.data.accounts.map(a => this.publicAccount(a));
    const start = Math.floor(now / 3600000) * 3600000 - 23 * 3600000;
    const trend = Array.from({ length: 24 }, (_, i) => ({ time: start + i * 3600000, success: 0, error: 0 }));
    for (const record of records) {
      const bucket = trend[Math.floor((record.startedAt - start) / 3600000)];
      if (bucket) bucket[record.status === 'success' ? 'success' : 'error']++;
    }
    const modelStats = [...new Set(records.map(r => r.model).filter(Boolean))].map(model => {
      const requests = records.filter(r => r.model === model);
      const ok = requests.filter(r => r.status === 'success');
      const ttfts = ok.filter(r => r.ttftMs != null);
      return { model, requests: requests.length, successRate: ok.length / requests.length * 100,
        avgLatency: ok.length ? ok.reduce((sum, r) => sum + r.durationMs, 0) / ok.length : null,
        avgTtft: ttfts.length ? ttfts.reduce((sum, r) => sum + r.ttftMs, 0) / ttfts.length : null };
    }).sort((a, b) => b.requests - a.requests);
    return {
      startedAt: this.startedAt, now, accounts, trend, modelStats,
      requests: this.data.requests.slice(0, 200), models: this.data.models, modelsUpdatedAt: this.data.modelsUpdatedAt,
      stats: { requests: records.length, successes: success.length, failures: records.length - success.length,
        successRate: records.length ? success.length / records.length * 100 : null,
        avgTtft: firstTokens.length ? firstTokens.reduce((s, r) => s + r.ttftMs, 0) / firstTokens.length : null,
        avgLatency: success.length ? success.reduce((s, r) => s + r.durationMs, 0) / success.length : null,
        active: accounts.reduce((sum, a) => sum + a.inFlight, 0),
        available: accounts.filter(a => ['ready', 'pending', 'retry'].includes(a.status)).length,
        retained: this.data.requests.length,
      },
    };
  }
}
