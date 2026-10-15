// Logicc → OpenAI adapter and local account-pool console. No runtime dependencies.
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { timingSafeEqual } from 'node:crypto';
import { AccountPool, HttpError, claims, safeError, deadline } from './pool.mjs';
import { normalizeRequest, buildPrompt, parseToolOutput, ProtocolOutput, errorPayload } from './protocols.mjs';
import { AssistantPrompts } from './assistants.mjs';

const ROOT = import.meta.url ? dirname(fileURLToPath(import.meta.url)) : '/';

export async function* parseAiSdkStream(body) {
  const decoder = new TextDecoder();
  let buffer = '';
  function parse(frame) {
    const text = frame.split(/\r?\n/).filter(line => line.startsWith('data:')).map(line => line.slice(5).trimStart()).join('\n').trim();
    if (!text || text === '[DONE]') return null;
    try { return JSON.parse(text); } catch { throw new HttpError(502, '上游返回了无法解析的数据流'); }
  }
  for await (const chunk of body) {
    buffer += decoder.decode(chunk, { stream: true });
    let separator;
    while ((separator = /\r?\n\r?\n/.exec(buffer))) {
      const event = parse(buffer.slice(0, separator.index));
      buffer = buffer.slice(separator.index + separator[0].length);
      if (event) yield event;
    }
  }
  buffer += decoder.decode();
  if (buffer.trim()) { const event = parse(buffer); if (event) yield event; }
}

function readBody(req, limit = 1048576) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > limit) { reject(new HttpError(413, '请求体过大')); return; }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
    req.on('aborted', () => reject(new HttpError(400, '请求已中断')));
  });
}
async function readJson(req) {
  const text = await readBody(req);
  try { return JSON.parse(text || '{}'); } catch { throw new HttpError(400, '请求体不是有效 JSON'); }
}
function json(res, status, data) {
  if (res.destroyed || res.writableEnded) return;
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}
function usageOf(event) {
  const usage = event.totalUsage || event.usage || event.messageMetadata?.usage;
  if (!usage) return null;
  const number = value => typeof value === 'number' && Number.isFinite(value) ? value : value?.total;
  const input = number(usage.inputTokens) ?? usage.prompt_tokens;
  const output = number(usage.outputTokens) ?? usage.completion_tokens;
  if (!Number.isFinite(input) || !Number.isFinite(output)) return null;
  return { prompt_tokens: input, completion_tokens: output, total_tokens: input + output };
}

export function createAdapter({ env = process.env, dataFile = env.LOGICC_DATA_FILE || resolve(ROOT, 'data/state.json'), store } = {}) {
  const pool = new AccountPool(dataFile, env, store);
  const apiBase = (env.LOGICC_API_BASE || 'https://app.logicc.com/api').replace(/\/+$/, '');
  const assistantPrompts = new AssistantPrompts(resolve(dirname(dataFile), 'assistant-prompts.json'), upstream, store);

  async function upstream(account, path, { method = 'GET', body, stream = false, signal } = {}, retry = true) {
    const token = await pool.tokenFor(account);
    const response = await fetch(`${apiBase}/${path}`, {
      method, signal, redirect: 'manual',
      headers: { Authorization: `Bearer ${token}`, Accept: stream ? 'text/event-stream' : 'application/json',
        ...(stream ? { 'Stream-Response-Protocol': 'ai-sdk-v6' } : {}),
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (response.status === 401 && retry) {
      await response.body?.cancel();
      await pool.tokenFor(account, true);
      return upstream(account, path, { method, body, stream, signal }, false);
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new HttpError(response.status, `上游 ${path.split('?')[0].startsWith('chats/') ? '聊天' : path.split('?')[0]} 请求失败（HTTP ${response.status}）`);
    }
    return response;
  }

  async function modelsFor(account, signal) {
    const response = await upstream(account, 'models?language=en', { signal });
    const data = await response.json();
    const list = Array.isArray(data) ? data : data.models ?? data.data;
    if (!Array.isArray(list)) throw new HttpError(502, '上游模型列表格式不正确');
    const models = list.filter(m => typeof (m.id ?? m.modelId) === 'string').map(m => ({
      id: m.id ?? m.modelId, name: typeof m.name === 'string' ? m.name : m.id ?? m.modelId,
      provider: typeof m.provider === 'string' ? m.provider : typeof m.provider?.name === 'string' ? m.provider.name : 'logicc',
      isDefault: Boolean(m.isDefault),
    }));
    if (!models.length) throw new HttpError(502, '上游没有返回可用模型');
    pool.data.models = models;
    pool.data.modelsUpdatedAt = Date.now();
    return models;
  }

  async function track(req, res, kind, operation, accountId) {
    const trace = { kind, startedAt: Date.now(), model: null, ttftMs: null, status: 'success', stream: false, usage: null };
    const controller = new AbortController();
    const onClose = () => { if (!res.writableEnded) controller.abort(); };
    res.on('close', onClose);
    const timeout = deadline(180000);
    const signal = AbortSignal.any([controller.signal, timeout.signal]);
    let account;
    try {
      account = accountId ? pool.account(accountId) : pool.acquire();
      if (accountId) pool.runtimeFor(account.id).inFlight++;
      trace.accountId = account.id;
      trace.accountName = account.name;
      const result = await operation(account, trace, signal);
      pool.healthy(account);
      return result;
    } catch (error) {
      if (signal.aborted) error = new HttpError(controller.signal.aborted ? 499 : 504, controller.signal.aborted ? '客户端已取消请求' : '上游请求超时');
      trace.status = error.status === 499 ? 'cancelled' : 'error';
      trace.error = safeError(error);
      trace.httpStatus = error.status || 502;
      if (account && error.status !== 499 && !error.noAccountFailure) pool.failed(account, error);
      throw error;
    } finally {
      timeout.clear();
      res.off('close', onClose);
      trace.durationMs = Date.now() - trace.startedAt;
      if (account) pool.release(account);
      pool.record(trace);
    }
  }

  // ponytail: bounded in-memory Responses history; use a shared store for multi-process deployments.
  const responseCache = new Map();
  let cacheBytes = 0;
  function dropResponse(id) {
    const entry = responseCache.get(id);
    if (entry) { cacheBytes -= entry.bytes; responseCache.delete(id); }
  }
  function expireResponses() {
    for (const [id, entry] of responseCache) if (entry.expiresAt <= Date.now()) dropResponse(id);
  }
  function storedResponse(id) {
    expireResponses();
    const entry = responseCache.get(id);
    if (!entry) throw new HttpError(404, 'Response 不存在、未存储或已过期；请发送完整历史 input');
    return entry;
  }
  function rememberResponse(request, output, result) {
    if (request.protocol !== 'responses' || request.body.store === false) return;
    expireResponses();
    const messages = [...request.conversation, output.historyMessage()];
    const bytes = Buffer.byteLength(JSON.stringify({ messages, result }));
    while (responseCache.size && (responseCache.size >= 128 || cacheBytes + bytes > 16 * 1024 * 1024)) dropResponse(responseCache.keys().next().value);
    responseCache.set(result.id, { result, messages, bytes, expiresAt: Date.now() + 30 * 60 * 1000 });
    cacheBytes += bytes;
  }

  async function generate(req, res, protocol) {
    const body = await readJson(req);
    let previous = [];
    if (protocol === 'responses' && body?.previous_response_id != null) {
      if (typeof body.previous_response_id !== 'string') throw new HttpError(400, 'previous_response_id 必须为字符串');
      previous = storedResponse(body.previous_response_id).messages;
    }
    const request = normalizeRequest(body, protocol, previous);
    const prompt = buildPrompt(request);
    if (Buffer.byteLength(prompt) > 2 * 1024 * 1024) throw new HttpError(413, '合并后的上下文过大，请缩短历史或开始新会话');
    await track(req, res, 'chat', async (account, trace, signal) => {
      const assistant = assistantPrompts.defaultFor(account.id);
      if (!request.model || request.model === 'default') {
        if (assistant?.modelId) request.model = assistant.modelId;
        else {
          const models = await modelsFor(account, signal);
          request.model = (models.find(m => m.isDefault) || models[0]).id;
        }
      }
      trace.model = request.model;
      trace.stream = request.stream;
      trace.protocol = protocol;
      if (assistant) { trace.assistantId = assistant.id; trace.assistantName = assistant.name; }
      const chatResponse = await upstream(account, 'chats', { method: 'POST', body: assistant ? { assistantId: assistant.id } : {}, signal });
      const createdChat = await chatResponse.json();
      const chatId = typeof createdChat === 'string' ? createdChat : createdChat.id;
      if (typeof chatId !== 'string' || !chatId) throw new HttpError(502, '上游创建会话未返回 ID');
      const response = await upstream(account, `chats/${encodeURIComponent(chatId)}`, {
        method: 'POST', stream: true, signal,
        body: { modelId: request.model, prompt, isVoicePrompt: false,
          ...(request.reasoning ? { reasoningEffort: request.reasoning } : {}),
          ...(request.forcedTool ? { forcedTool: request.forcedTool } : {}) },
      });
      const output = new ProtocolOutput(res, request);
      let buffered = '', finished = false, finishReason = 'stop', generatedBytes = 0;
      const nativeCalls = new Map();
      const toolMode = request.activeTools.length > 0;
      try {
        output.start();
        for await (const event of parseAiSdkStream(response.body)) {
          if (event.type === 'error') throw new HttpError(502, `上游流错误：${safeError(event.errorText || '未知错误')}`);
          let delta = '';
          if (event.type === 'text-delta' && typeof event.delta === 'string') {
            delta = event.delta;
            if (delta) trace.ttftMs ??= Date.now() - trace.startedAt;
          } else if (event.type === 'tool-input-start' || event.type === 'tool-input-available') {
            const callId = event.toolCallId || event.id;
            const existing = nativeCalls.get(callId);
            const name = event.toolName || existing?.name;
            if (callId && request.activeTools.some(t => t.name === name)) {
              const call = existing || { name, arguments: '', executed: false };
              if (event.input !== undefined) call.arguments = event.input;
              call.executed ||= event.providerExecuted === true;
              nativeCalls.set(callId, call);
            } else if (event.type === 'tool-input-start' && request.forcedTool) delta = `\n[tool:${name || request.forcedTool}] `;
          } else if (event.type === 'tool-input-delta') {
            const call = nativeCalls.get(event.toolCallId || event.id);
            if (call && typeof call.arguments === 'string') call.arguments += event.inputTextDelta || event.delta || '';
          } else if (event.type === 'tool-output-available' || event.type === 'tool-output-error') {
            const call = nativeCalls.get(event.toolCallId || event.id);
            if (call) call.executed = true; // Never ask the client to repeat a provider-executed side effect.
          }
          if (delta) {
            generatedBytes += Buffer.byteLength(delta);
            if (generatedBytes > 1024 * 1024) throw new HttpError(502, '上游输出超过本机代理的 1 MiB 响应限制');
            if (toolMode) buffered += delta; else output.text(delta);
          }
          const usage = usageOf(event);
          if (usage) trace.usage = usage;
          if (event.type === 'finish') {
            finished = true;
            finishReason = ['stop', 'length', 'content_filter'].includes(event.finishReason) ? event.finishReason : 'stop';
          }
        }
        if (!finished) throw new HttpError(502, '上游数据流提前结束，未收到 finish 事件');
        if (toolMode) {
          const parsed = parseToolOutput(buffered, request, [...nativeCalls.values()].filter(c => !c.executed));
          output.text(parsed.text);
          for (const call of parsed.calls) output.call(call);
          trace.toolCalls = parsed.calls.length;
        }
        output.finish(trace.usage, finishReason, result => rememberResponse(request, output, result));
      } catch (error) { output.fail(error); throw error; }
      finally { output.dispose(); }
    });
  }

  const assets = { '/': ['index.html', 'text/html'], '/app.js': ['app.js', 'text/javascript'], '/style.css': ['style.css', 'text/css'], '/favicon.svg': ['favicon.svg', 'image/svg+xml'] };
  const server = createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
    try {
      const host = req.headers.host || '';
      const localPort = server.address()?.port;
      if (![ `127.0.0.1:${localPort}`, `localhost:${localPort}`, `[::1]:${localPort}` ].includes(host)) throw new HttpError(403, '仅接受本机 Host');
      const url = new URL(req.url, `http://${host}`);
      const origin = req.headers.origin;
      const bridge = url.pathname === '/__set_token' && origin === 'https://app.logicc.com';
      if (origin && origin !== `http://${host}` && !bridge) throw new HttpError(403, '不允许此网页来源访问本机控制台');
      if (req.headers['sec-fetch-site'] === 'cross-site' && !bridge) throw new HttpError(403, '不允许跨站访问');
      if (bridge) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        res.setHeader('Access-Control-Allow-Private-Network', 'true');
        res.setHeader('Vary', 'Origin');
      }
      if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
      if (assets[url.pathname] && ['GET', 'HEAD'].includes(req.method)) {
        const [file, type] = assets[url.pathname];
        res.writeHead(200, { 'Content-Type': `${type}; charset=utf-8`, 'Cache-Control': 'no-cache' });
        res.end(req.method === 'HEAD' ? undefined : readFileSync(resolve(ROOT, 'public', file)));
        return;
      }
      if (url.pathname === '/health' && req.method === 'GET') return json(res, 200, { status: 'ok', uptime: Math.floor((Date.now() - pool.startedAt) / 1000) });
      if (url.pathname.startsWith('/api/')) {
        if (req.headers['x-logicc-admin'] !== '1') throw new HttpError(403, '控制台请求缺少 X-Logicc-Admin 请求头');
        if (!['GET', 'DELETE'].includes(req.method) && !req.headers['content-type']?.startsWith('application/json')) throw new HttpError(415, '管理接口需要 application/json');
        if (url.pathname === '/api/state' && req.method === 'GET') return json(res, 200, {
          ...pool.snapshot(), assistantDefaults: assistantPrompts.data.defaults, service: { baseUrl: `http://${host}/v1`, upstream: apiBase, apiKeyRequired: Boolean(env.LOGICC_API_KEY), strategy: 'least-busy-round-robin' },
        });
        const assistantRoute = /^\/api\/accounts\/([\w-]+)\/(assistants|default-assistant)(?:\/([\w-]+))?$/.exec(url.pathname);
        if (assistantRoute) {
          const [, accountId, resource, assistantId] = assistantRoute;
          const account = pool.account(accountId);
          const timeout = deadline(60000), signal = timeout.signal;
          pool.runtimeFor(accountId).inFlight++;
          try {
            if (resource === 'default-assistant' && !assistantId && req.method === 'PUT') {
              const body = await readJson(req);
              return json(res, 200, { defaultAssistant: await assistantPrompts.selectDefault(account, body?.assistantId, signal) });
            }
            if (resource === 'assistants') {
              if (!assistantId && req.method === 'GET') return json(res, 200, await assistantPrompts.list(account, { type: url.searchParams.get('type') || 'library', cursor: url.searchParams.get('cursor'), query: url.searchParams.get('query'), signal }));
              if (!assistantId && req.method === 'POST') return json(res, 201, { assistant: await assistantPrompts.create(account, await readJson(req), signal) });
              if (assistantId && req.method === 'GET') return json(res, 200, { assistant: await assistantPrompts.read(account, assistantId, signal) });
              if (assistantId && req.method === 'PUT') return json(res, 200, { assistant: await assistantPrompts.save(account, assistantId, await readJson(req), signal) });
            }
            throw new HttpError(404, '助手管理接口不存在');
          } finally { timeout.clear(); pool.release(account); }
        }
        if (url.pathname === '/api/accounts' && req.method === 'POST') {
          const input = await readJson(req);
          return json(res, 201, { account: pool.addMany([input])[0] });
        }
        if (url.pathname === '/api/accounts/import' && req.method === 'POST') {
          const input = await readJson(req);
          return json(res, 201, { accounts: pool.addMany(Array.isArray(input) ? input : input?.accounts) });
        }
        const match = /^\/api\/accounts\/([\w-]+)(?:\/(check|refresh))?$/.exec(url.pathname);
        if (match) {
          const [, id, action] = match;
          if (req.method === 'PATCH' && !action) return json(res, 200, { account: pool.update(id, await readJson(req)) });
          if (req.method === 'DELETE' && !action) { pool.remove(id); assistantPrompts.forgetAccount(id); return json(res, 200, { ok: true }); }
          if (req.method === 'POST' && action) {
            const result = await track(req, res, 'check', async (account, trace, signal) => {
              if (action === 'refresh') await pool.tokenFor(account, true);
              const models = await modelsFor(account, signal);
              return { models: models.length };
            }, id);
            return json(res, 200, { ...result, account: pool.publicAccount(pool.account(id)) });
          }
        }
        if (url.pathname === '/api/models/refresh' && req.method === 'POST') {
          const models = await track(req, res, 'models', (account, _trace, signal) => modelsFor(account, signal));
          return json(res, 200, { models, updatedAt: pool.data.modelsUpdatedAt });
        }
        throw new HttpError(404, '管理接口不存在');
      }
      if (url.pathname === '/__set_token' && req.method === 'POST') {
        const token = (await readBody(req, 25000)).trim().replace(/^(['"])(.*)\1$/, '$2');
        const sid = claims(token).sid;
        const requested = url.searchParams.get('account_id');
        const existing = requested ? pool.account(requested) : pool.data.accounts.find(a => a.sessionId === sid);
        if (existing && existing.sessionId && existing.sessionId !== sid) throw new HttpError(400, 'JWT 不属于指定账户');
        const account = existing ? pool.update(existing.id, { token }) : pool.addMany([{ name: '浏览器账户', token }])[0];
        return json(res, 200, { ok: true, accountId: account.id, exp: claims(token).exp });
      }
      if (url.pathname.startsWith('/v1/') && env.LOGICC_API_KEY) {
        const apiKey = url.pathname.startsWith('/v1/messages') && req.headers['x-api-key'];
        const incoming = Buffer.from(req.headers.authorization || (apiKey ? `Bearer ${apiKey}` : ''));
        const expected = Buffer.from(`Bearer ${env.LOGICC_API_KEY}`);
        if (incoming.length !== expected.length || !timingSafeEqual(incoming, expected)) throw new HttpError(401, '代理 API Key 不正确');
      }
      if (url.pathname === '/v1/models' && req.method === 'GET') {
        const models = await track(req, res, 'models', (account, _trace, signal) => modelsFor(account, signal));
        return json(res, 200, { object: 'list', data: models.map(m => ({ id: m.id, object: 'model', created: 0, owned_by: m.provider })) });
      }
      if (url.pathname === '/v1/messages/count_tokens' && req.method === 'POST') {
        const request = normalizeRequest(await readJson(req), 'messages');
        res.setHeader('X-Logicc-Token-Count', 'estimated');
        return json(res, 200, { input_tokens: Math.max(1, Math.ceil(Buffer.byteLength(buildPrompt(request)) / 3)) });
      }
      const responseMatch = /^\/v1\/responses\/(resp_[a-zA-Z0-9]+)$/.exec(url.pathname);
      if (responseMatch && ['GET', 'DELETE'].includes(req.method)) {
        const entry = storedResponse(responseMatch[1]);
        if (req.method === 'GET') return json(res, 200, entry.result);
        dropResponse(responseMatch[1]);
        return json(res, 200, { id: responseMatch[1], object: 'response.deleted', deleted: true });
      }
      const protocol = { '/v1/chat/completions': 'chat', '/v1/responses': 'responses', '/v1/messages': 'messages' }[url.pathname];
      if (protocol && req.method === 'POST') return await generate(req, res, protocol);
      throw new HttpError(404, '接口不存在');
    } catch (error) {
      const message = safeError(error);
      const protocol = req.url?.split('?')[0].startsWith('/v1/messages') ? 'messages' : req.url?.split('?')[0].startsWith('/v1/responses') ? 'responses' : 'chat';
      if (res.headersSent) {
        if (!res.destroyed && !res.writableEnded) res.end(`data: ${JSON.stringify({ error: { message, type: 'adapter_error' } })}\n\ndata: [DONE]\n\n`);
      } else json(res, error.status >= 400 && error.status <= 599 ? error.status : 502, errorPayload(protocol, error));
    }
  });
  return { server, pool };
}

if (import.meta.url && process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.argv[2] || process.env.PORT || 18789);
  const host = process.env.LOGICC_HOST || '127.0.0.1';
  const { server } = createAdapter();
  server.listen(port, host, () => {
    console.log(`Logicc console: http://127.0.0.1:${server.address().port}/`);
    console.log(`OpenAI API:    http://127.0.0.1:${server.address().port}/v1`);
  });
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  });
}
