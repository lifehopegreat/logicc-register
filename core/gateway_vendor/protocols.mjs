import { randomUUID } from 'node:crypto';
import { HttpError, safeError } from './pool.mjs';

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const id = prefix => `${prefix}_${randomUUID().replaceAll('-', '')}`;
function invalid(message) { throw new HttpError(400, message); }
function requireString(value, field) {
  if (typeof value !== 'string' || !value.trim()) invalid(`${field} 必须为非空字符串`);
  return value;
}
function textContent(content) {
  if (content == null) return '';
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) invalid('content 必须为文本或内容块数组');
  return content.map(part => {
    if (['text', 'input_text', 'output_text'].includes(part?.type) && typeof part.text === 'string') return part.text;
    if (part?.type === 'refusal' && typeof part.refusal === 'string') return part.refusal;
    if (['thinking', 'redacted_thinking'].includes(part?.type)) return '';
    invalid(`暂不支持内容块 ${part?.type || 'unknown'}，当前仅支持文本`);
  }).filter(Boolean).join('\n');
}
function argumentsObject(value, field = 'function arguments') {
  let parsed = value;
  if (typeof value === 'string') {
    try { parsed = JSON.parse(value); } catch { invalid(`${field} 不是有效 JSON`); }
  }
  if (!object(parsed)) invalid(`${field} 必须为 JSON 对象`);
  return parsed;
}
function historyCall(call) {
  if (!object(call)) invalid('工具调用必须为对象');
  const fn = call.function || call;
  return { id: requireString(call.id || call.call_id, 'tool call id'), name: requireString(fn.name, 'tool name'),
    ...(call.type === 'custom_tool_call' ? { kind: 'custom', input: requireString(call.input, 'tool input') } : { kind: 'function', arguments: argumentsObject(fn.arguments ?? fn.input ?? {}) }) };
}
function fromChat(messages) {
  if (!Array.isArray(messages) || !messages.length) invalid('messages 需要非空数组');
  return messages.map(message => {
    if (!object(message) || !['system', 'developer', 'user', 'assistant', 'tool'].includes(message.role)) invalid('消息 role 不正确');
    const normalized = { role: message.role, content: textContent(message.content) };
    if (message.role === 'tool') normalized.tool_call_id = requireString(message.tool_call_id, 'tool_call_id');
    if (message.tool_calls !== undefined) {
      if (message.role !== 'assistant' || !Array.isArray(message.tool_calls)) invalid('tool_calls 必须位于 assistant 消息中');
      normalized.tool_calls = message.tool_calls.map(historyCall);
    }
    return normalized;
  });
}
function fromResponses(input) {
  if (typeof input === 'string') return [{ role: 'user', content: input }];
  if (!Array.isArray(input)) invalid('input 必须为字符串或数组');
  return input.flatMap(item => {
    if (!object(item)) invalid('input 中的每一项必须为对象');
    if (item.type === 'reasoning') return []; // Opaque provider reasoning is not portable to Logicc.
    if (item.type === 'function_call' || item.type === 'custom_tool_call') return [{ role: 'assistant', content: '', tool_calls: [historyCall({ ...item, id: item.call_id })] }];
    if (item.type === 'function_call_output' || item.type === 'custom_tool_call_output') return [{ role: 'tool', tool_call_id: requireString(item.call_id, 'call_id'), content: textContent(item.output) }];
    if ((!item.type || item.type === 'message') && item.role) return fromChat([item]);
    invalid(`暂不支持 Responses input 类型 ${item.type || 'unknown'}`);
  });
}
function fromMessages(body) {
  if (!Array.isArray(body.messages) || !body.messages.length) invalid('messages 需要非空数组');
  const result = [];
  if (body.system !== undefined) result.push({ role: 'system', content: textContent(body.system) });
  for (const message of body.messages) {
    if (!object(message) || !['user', 'assistant'].includes(message.role)) invalid('Messages role 仅支持 user / assistant');
    const parts = typeof message.content === 'string' ? [{ type: 'text', text: message.content }] : message.content;
    if (!Array.isArray(parts)) invalid('Messages content 必须为文本或数组');
    let pending = { role: message.role, content: '' };
    const flush = () => { if (pending.content || pending.tool_calls?.length) result.push(pending); pending = { role: message.role, content: '' }; };
    for (const part of parts) {
      if (part?.type === 'tool_use') {
        if (message.role !== 'assistant') invalid('tool_use 必须位于 assistant 消息');
        (pending.tool_calls ||= []).push(historyCall(part));
      } else if (part?.type === 'tool_result') {
        if (message.role !== 'user') invalid('tool_result 必须位于 user 消息');
        flush();
        result.push({ role: 'tool', tool_call_id: requireString(part.tool_use_id, 'tool_use_id'), content: textContent(part.content), is_error: Boolean(part.is_error) });
      } else pending.content += textContent([part]);
    }
    flush();
  }
  return result;
}

function normalizeTools(body, protocol) {
  if (body.tools !== undefined && !Array.isArray(body.tools)) invalid('tools 必须为数组');
  if ((body.tools?.length || 0) > 128) invalid('最多支持 128 个工具');
  const tools = [], builtins = [];
  const builtinTypes = { web_search: 'web-search', web_search_preview: 'web-search', image_generation: 'image-generation' };
  for (const tool of body.tools || []) {
    if (!object(tool)) invalid('工具定义必须为对象');
    if (Object.hasOwn(builtinTypes, tool.type)) { builtins.push({ type: tool.type, upstream: builtinTypes[tool.type] }); continue; }
    let fn, kind = 'function';
    if (protocol === 'messages' && (!tool.type || tool.type === 'custom')) fn = { ...tool, parameters: tool.input_schema };
    else if (tool.type === 'function') fn = protocol === 'chat' ? tool.function : tool;
    else if (protocol === 'responses' && tool.type === 'custom') { fn = tool; kind = 'custom'; }
    else invalid(`不支持的工具类型：${tool.type || 'unknown'}`);
    if (!object(fn) || typeof fn.name !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(fn.name)) invalid('工具名称格式不正确');
    if (tools.some(t => t.name === fn.name)) invalid('工具名称不能重复');
    if (fn.parameters !== undefined && !object(fn.parameters)) invalid('工具 parameters / input_schema 必须为对象');
    if (fn.parameters?.required !== undefined && (!Array.isArray(fn.parameters.required) || !fn.parameters.required.every(k => typeof k === 'string'))) invalid('工具 required 必须为字段名数组');
    tools.push({ name: fn.name, description: fn.description || '', kind, parameters: fn.parameters || { type: 'object', properties: {} }, ...(fn.format ? { format: fn.format } : {}) });
  }
  let choice = body.tool_choice ?? 'auto';
  if (object(choice)) {
    if (protocol === 'messages') choice = choice.type === 'tool' ? choice.name : choice.type === 'any' ? 'required' : choice.type;
    else choice = choice.type === 'function' ? choice.function?.name || choice.name : choice.type === 'custom' ? choice.name : choice.type;
  }
  if (typeof choice !== 'string' || !['auto', 'none', 'required', ...tools.map(t => t.name), ...builtins.map(t => t.type)].includes(choice)) invalid('tool_choice 不正确或引用了未定义的工具');
  if (choice === 'required' && !tools.length && !builtins.length) invalid('tool_choice=required 需要至少一个工具');
  let active = choice === 'none' ? [] : tools;
  if (tools.some(t => t.name === choice)) active = tools.filter(t => t.name === choice);
  const native = choice === 'none' || tools.some(t => t.name === choice) ? null : builtins.find(t => t.type === choice) || builtins[0];
  if (builtins.some(t => t.type === choice)) active = [];
  return { tools, activeTools: active, choice, forcedTool: native?.upstream,
    required: choice === 'required' && active.length > 0 || tools.some(t => t.name === choice),
    parallel: body.parallel_tool_calls !== false && body.tool_choice?.disable_parallel_tool_use !== true };
}

export function normalizeRequest(body, protocol, previous = []) {
  if (!object(body)) invalid('请求体必须为 JSON 对象');
  if (body.model !== undefined && (typeof body.model !== 'string' || !body.model)) invalid('model 必须为非空字符串');
  if (body.stream !== undefined && typeof body.stream !== 'boolean') invalid('stream 必须为布尔值');
  if (body.parallel_tool_calls !== undefined && typeof body.parallel_tool_calls !== 'boolean') invalid('parallel_tool_calls 必须为布尔值');
  if (body.metadata !== undefined && !object(body.metadata)) invalid('metadata 必须为对象');
  if (body.text?.format?.type && body.text.format.type !== 'text') invalid('暂不支持 Responses text.format 结构化输出；工具调用请使用 tools');
  if (protocol === 'responses' && body.store !== undefined && typeof body.store !== 'boolean') invalid('store 必须为布尔值');
  if (body.background || body.conversation) invalid('暂不支持 background / conversation，请使用同步请求或 previous_response_id');
  if (body.n !== undefined && body.n !== 1) invalid('仅支持 n=1');
  const maxTokens = body.max_output_tokens ?? body.max_completion_tokens ?? body.max_tokens;
  if (maxTokens !== undefined && (!Number.isInteger(maxTokens) || maxTokens <= 0)) invalid('输出 token 上限必须为正整数');
  let messages = protocol === 'messages' ? fromMessages(body) : protocol === 'responses' ? [...previous, ...fromResponses(body.input ?? [])] : fromChat(body.messages);
  const conversation = messages;
  if (protocol === 'responses' && body.instructions !== undefined) messages = [{ role: 'system', content: textContent(body.instructions) }, ...messages];
  if (!messages.length || !messages.some(m => m.content || m.tool_calls?.length)) invalid('请求没有有效消息');
  const callIds = new Set(), answered = new Set();
  for (const message of messages) {
    for (const call of message.tool_calls || []) {
      if (callIds.has(call.id)) invalid('重复的工具调用 ID');
      callIds.add(call.id);
    }
    if (message.role === 'tool') {
      if (!callIds.has(message.tool_call_id)) invalid('工具结果没有对应的历史调用，请传入 assistant 工具调用或 previous_response_id');
      if (answered.has(message.tool_call_id)) invalid('同一个工具调用不能重复提交结果');
      answered.add(message.tool_call_id);
    }
  }
  return { protocol, body, model: body.model, stream: body.stream === true, messages, conversation, maxTokens,
    reasoning: body.reasoning?.effort || body.reasoning_effort || body.output_config?.effort,
    ...normalizeTools(body, protocol) };
}

export function buildPrompt(request) {
  const history = request.messages.map(message => {
    if (message.tool_calls?.length) return `[Assistant]\n${message.content}\n[Tool calls]\n${JSON.stringify(message.tool_calls)}`;
    if (message.role === 'tool') return `[Tool result: ${message.tool_call_id}${message.is_error ? '; error' : ''}]\n${message.content}`;
    return message.role === 'user' ? message.content : `[${message.role}]\n${message.content}`;
  }).join('\n\n');
  const limit = request.maxTokens ? `\nKeep the response within approximately ${request.maxTokens} output tokens.` : '';
  if (!request.activeTools.length) return history + limit;
  return `Serialize the next assistant turn for a client application. The client application executes functions requested in your output; you only select a tool and produce its input. Do not execute the client functions yourself or invent their results.
Return only one JSON object, without markdown fences or explanations, using this envelope:
{"content": "text for the user or null", "tool_calls": [{"name": "a declared tool name", "arguments": {}}]}
For a function tool, arguments must be a JSON object matching its parameters. For a custom tool, use "input" with a string instead of arguments and follow its format.
If a tool is needed to fulfill the user's request, request it and stop. Use actual values from the conversation, never placeholder values. If a tool result has already been supplied, use it to continue the task and give the final answer when sufficient. For an ordinary answer, put the answer in content and set tool_calls to []. Do not say tools are unavailable: the external client executes the declared functions after receiving your JSON.
Tool choice: ${request.required ? `You MUST request ${request.choice === 'required' ? 'at least one declared client tool' : JSON.stringify(request.choice)} in this turn.` : 'Choose a tool when needed, otherwise answer the user.'}
Parallel calls: ${request.parallel ? 'allowed' : 'disabled; return at most one tool call'}.
Declared client tools:
${JSON.stringify(request.activeTools)}
Conversation (the actual task to continue):
${JSON.stringify(request.messages)}
Return the next assistant turn JSON now.${limit}`;
}

function toolError(message) {
  const error = new HttpError(502, message);
  error.code = 'tool_generation_error';
  error.noAccountFailure = true;
  throw error;
}
function parsedEnvelope(raw) {
  let text = raw.trim();
  const fenced = /^```(?:json)?\s*\n?([\s\S]*?)\n?```\s*$/i.exec(text);
  if (fenced) text = fenced[1].trim();
  try { return JSON.parse(text); } catch { return null; }
}
function checkArguments(value, schema, depth = 0) {
  if (!object(schema) || depth > 32) return;
  const types = schema.type ? [schema.type].flat() : [];
  const typeMatches = type => type === 'null' ? value === null : type === 'array' ? Array.isArray(value) : type === 'object' ? object(value) : type === 'integer' ? Number.isInteger(value) : typeof value === type;
  if (types.length && !types.some(typeMatches)) toolError('工具参数的数据类型不符合 schema');
  if (Array.isArray(schema.enum) && !schema.enum.some(item => JSON.stringify(item) === JSON.stringify(value))) toolError('工具参数不在允许的枚举值中');
  if (object(value)) {
    for (const key of Array.isArray(schema.required) ? schema.required : []) if (!Object.hasOwn(value, key)) toolError('工具参数缺少必填字段');
    for (const [key, item] of Object.entries(value)) {
      const property = object(schema.properties) && Object.hasOwn(schema.properties, key) ? schema.properties[key] : undefined;
      if (schema.additionalProperties === false && property === undefined) toolError('工具参数包含 schema 未允许的字段');
      checkArguments(item, property ?? schema.additionalProperties, depth + 1);
    }
  } else if (Array.isArray(value)) for (const item of value) checkArguments(item, schema.items, depth + 1);
}
export function validateCalls(rawCalls, request) {
  if (!Array.isArray(rawCalls) || rawCalls.length > 32) toolError('模型返回了无效的工具调用列表');
  if (!request.parallel && rawCalls.length > 1) toolError('模型返回了多个调用，但 parallel_tool_calls 已禁用');
  return rawCalls.map(raw => {
    const name = raw?.function?.name || raw?.name;
    const tool = request.activeTools.find(t => t.name === name);
    if (!tool) toolError('模型请求了未声明或 tool_choice 不允许的工具');
    if (tool.kind === 'custom') {
      if (typeof raw.input !== 'string') toolError('自定义工具输入必须为字符串');
      return { id: id('call'), kind: 'custom', name, input: raw.input };
    }
    let args = raw.function?.arguments ?? raw.arguments ?? raw.input;
    if (typeof args === 'string') { try { args = JSON.parse(args); } catch { toolError('工具参数不是有效 JSON'); } }
    if (!object(args)) toolError('工具参数必须为 JSON 对象');
    checkArguments(args, tool.parameters);
    return { id: id('call'), kind: 'function', name, arguments: args };
  });
}
export function parseToolOutput(text, request, nativeCalls = []) {
  if (nativeCalls.length) return { text, calls: validateCalls(nativeCalls, request) };
  const envelope = parsedEnvelope(text);
  const rawCalls = envelope?.tool_calls ?? (envelope?.tool_call ? [envelope.tool_call] : undefined);
  if (rawCalls !== undefined) {
    const calls = validateCalls(rawCalls, request);
    if (request.required && !calls.length) toolError('模型未按 tool_choice 返回工具调用，请更换模型或调整请求');
    if (envelope.content != null && typeof envelope.content !== 'string') toolError('工具响应中的 content 必须为字符串或 null');
    return { text: envelope.content || '', calls };
  }
  if (request.required) toolError('模型未生成有效的工具调用 JSON；没有把普通文本伪装成调用');
  // Ordinary text is a valid auto-mode answer; never interpret JSON quoted inside prose as an executable call.
  return { text, calls: [] };
}

export function errorPayload(protocol, error) {
  const status = error.status || 502;
  const type = status === 401 ? 'authentication_error' : status === 403 ? 'permission_error' : status === 404 ? 'not_found_error' : status === 429 ? 'rate_limit_error' : status < 500 ? 'invalid_request_error' : 'api_error';
  return { ...(protocol === 'messages' ? { type: 'error' } : {}), error: { type, message: safeError(error), ...(protocol !== 'messages' ? { code: error.code || 'adapter_error', param: null } : {}) } };
}

const zeroUsage = () => ({ prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 });
export class ProtocolOutput {
  constructor(res, request) {
    this.res = res;
    this.request = request;
    this.protocol = request.protocol;
    this.id = id(this.protocol === 'responses' ? 'resp' : this.protocol === 'messages' ? 'msg' : 'chatcmpl');
    this.created = Math.floor(Date.now() / 1000);
    this.items = [];
    this.sequence = 0;
    this.callIndex = 0;
    this.openText = null;
    this.usage = null;
    this.reason = 'stop';
  }
  send(type, data) {
    if (!this.request.stream || this.res.destroyed || this.res.writableEnded) return;
    if (this.protocol === 'chat') this.res.write(`data: ${JSON.stringify(data)}\n\n`);
    else this.res.write(`event: ${type}\ndata: ${JSON.stringify({ type, ...data, ...(this.protocol === 'responses' ? { sequence_number: this.sequence++ } : {}) })}\n\n`);
  }
  chunk(delta, finishReason = null) {
    return { id: this.id, object: 'chat.completion.chunk', created: this.created, model: this.request.model, choices: [{ index: 0, delta, finish_reason: finishReason }] };
  }
  start() {
    if (!this.request.stream) return;
    this.res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    this.res.flushHeaders();
    if (this.protocol === 'chat') this.send(null, this.chunk({ role: 'assistant' }));
    else if (this.protocol === 'messages') this.send('message_start', { message: { ...this.result('in_progress'), content: [] } });
    else {
      this.send('response.created', { response: this.result('in_progress') });
      this.send('response.in_progress', { response: this.result('in_progress') });
    }
    this.heartbeat = setInterval(() => {
      if (this.res.destroyed || this.res.writableEnded) return;
      if (this.protocol === 'messages') this.send('ping', {});
      else this.res.write(': keep-alive\n\n');
    }, 15000);
    this.heartbeat.unref();
  }
  text(delta) {
    if (!delta) return;
    if (!this.openText) {
      const item = { id: id('msg'), kind: 'text', text: '', index: this.items.length };
      this.items.push(item); this.openText = item;
      if (this.protocol === 'messages') this.send('content_block_start', { index: item.index, content_block: { type: 'text', text: '' } });
      else if (this.protocol === 'responses') {
        this.send('response.output_item.added', { output_index: item.index, item: { id: item.id, type: 'message', status: 'in_progress', role: 'assistant', content: [] } });
        this.send('response.content_part.added', { item_id: item.id, output_index: item.index, content_index: 0, part: { type: 'output_text', text: '', annotations: [], logprobs: [] } });
      }
    }
    const item = this.openText;
    item.text += delta;
    if (this.protocol === 'chat') this.send(null, this.chunk({ content: delta }));
    else if (this.protocol === 'messages') this.send('content_block_delta', { index: item.index, delta: { type: 'text_delta', text: delta } });
    else this.send('response.output_text.delta', { item_id: item.id, output_index: item.index, content_index: 0, delta, logprobs: [] });
  }
  closeText() {
    const item = this.openText;
    if (!item) return;
    if (this.protocol === 'messages') this.send('content_block_stop', { index: item.index });
    else if (this.protocol === 'responses') {
      this.send('response.output_text.done', { item_id: item.id, output_index: item.index, content_index: 0, text: item.text, logprobs: [] });
      this.send('response.content_part.done', { item_id: item.id, output_index: item.index, content_index: 0, part: this.responseItem(item).content[0] });
      this.send('response.output_item.done', { output_index: item.index, item: this.responseItem(item) });
    }
    this.openText = null;
  }
  call(call) {
    this.closeText();
    const item = { ...call, itemId: id(call.kind === 'custom' ? 'ctc' : 'fc'), index: this.items.length };
    this.items.push(item);
    const args = call.kind === 'custom' ? call.input : JSON.stringify(call.arguments);
    if (this.protocol === 'chat') {
      const index = this.callIndex++;
      this.send(null, this.chunk({ tool_calls: [{ index, id: call.id, type: 'function', function: { name: call.name, arguments: '' } }] }));
      this.send(null, this.chunk({ tool_calls: [{ index, function: { arguments: args } }] }));
    } else if (this.protocol === 'messages') {
      this.send('content_block_start', { index: item.index, content_block: { type: 'tool_use', id: call.id, name: call.name, input: {} } });
      this.send('content_block_delta', { index: item.index, delta: { type: 'input_json_delta', partial_json: args } });
      this.send('content_block_stop', { index: item.index });
    } else {
      const field = call.kind === 'custom' ? 'input' : 'arguments';
      const event = call.kind === 'custom' ? 'response.custom_tool_call_input' : 'response.function_call_arguments';
      this.send('response.output_item.added', { output_index: item.index, item: { ...this.responseItem(item), status: 'in_progress', [field]: '' } });
      this.send(`${event}.delta`, { item_id: item.itemId, output_index: item.index, delta: args });
      this.send(`${event}.done`, { item_id: item.itemId, output_index: item.index, [field]: args });
      this.send('response.output_item.done', { output_index: item.index, item: this.responseItem(item) });
    }
  }
  responseItem(item) {
    if (item.kind === 'text') return { id: item.id, type: 'message', status: 'completed', role: 'assistant', content: [{ type: 'output_text', text: item.text, annotations: [], logprobs: [] }] };
    return { id: item.itemId, type: item.kind === 'custom' ? 'custom_tool_call' : 'function_call', status: 'completed', call_id: item.id, name: item.name,
      ...(item.kind === 'custom' ? { input: item.input } : { arguments: JSON.stringify(item.arguments) }) };
  }
  result(status = 'completed', error = null) {
    const request = this.request, usage = this.usage || zeroUsage();
    const calls = this.items.filter(i => i.kind !== 'text');
    const text = this.items.filter(i => i.kind === 'text').map(i => i.text).join('');
    if (this.protocol === 'chat') return {
      id: this.id, object: 'chat.completion', created: this.created, model: request.model,
      choices: [{ index: 0, message: { role: 'assistant', content: text || (calls.length ? null : ''),
        ...(calls.length ? { tool_calls: calls.map(c => ({ id: c.id, type: 'function', function: { name: c.name, arguments: JSON.stringify(c.arguments) } })) } : {}) }, finish_reason: calls.length ? 'tool_calls' : this.reason }], usage,
    };
    if (this.protocol === 'messages') return {
      id: this.id, type: 'message', role: 'assistant', model: request.model,
      content: this.items.map(item => item.kind === 'text' ? { type: 'text', text: item.text } : { type: 'tool_use', id: item.id, name: item.name, input: item.arguments }),
      stop_reason: status === 'in_progress' ? null : calls.length ? 'tool_use' : this.reason === 'length' ? 'max_tokens' : 'end_turn', stop_sequence: null,
      usage: { input_tokens: usage.prompt_tokens, output_tokens: usage.completion_tokens },
    };
    return {
      id: this.id, object: 'response', created_at: this.created, completed_at: status === 'completed' ? Math.floor(Date.now() / 1000) : null,
      status, error, incomplete_details: status === 'incomplete' ? { reason: this.reason === 'length' ? 'max_output_tokens' : 'content_filter' } : null,
      model: request.model, output: this.items.map(item => this.responseItem(item)),
      instructions: request.body.instructions ?? null, max_output_tokens: request.maxTokens ?? null,
      parallel_tool_calls: request.parallel, previous_response_id: request.body.previous_response_id ?? null,
      reasoning: request.body.reasoning ?? { effort: request.reasoning ?? null, summary: null },
      store: request.body.store !== false, text: { format: { type: 'text' } },
      tool_choice: request.body.tool_choice ?? 'auto', tools: request.body.tools ?? [],
      metadata: request.body.metadata ?? {}, truncation: 'disabled',
      usage: status === 'in_progress' ? null : { input_tokens: usage.prompt_tokens, output_tokens: usage.completion_tokens, total_tokens: usage.total_tokens,
        input_tokens_details: { cached_tokens: 0 }, output_tokens_details: { reasoning_tokens: 0 } },
    };
  }
  finish(usage, reason = 'stop', beforeSend) {
    this.usage = usage; this.reason = reason;
    this.closeText();
    const status = ['length', 'content_filter'].includes(reason) ? 'incomplete' : 'completed';
    const result = this.result(status);
    beforeSend?.(result);
    if (this.request.stream) {
      if (this.protocol === 'chat') {
        this.send(null, this.chunk({}, result.choices[0].finish_reason));
        if (this.request.body.stream_options?.include_usage) this.send(null, { id: this.id, object: 'chat.completion.chunk', created: this.created, model: this.request.model, choices: [], usage: usage || zeroUsage() });
        this.res.end('data: [DONE]\n\n');
      } else if (this.protocol === 'messages') {
        this.send('message_delta', { delta: { stop_reason: result.stop_reason, stop_sequence: null }, usage: result.usage });
        this.send('message_stop', {}); this.res.end();
      } else { this.send(`response.${status}`, { response: result }); this.res.end(); }
    } else {
      this.res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
      this.res.end(JSON.stringify(result));
    }
    return result;
  }
  fail(error) {
    if (!this.res.headersSent || this.res.destroyed || this.res.writableEnded) return;
    if (this.protocol === 'responses') this.send('response.failed', { response: this.result('failed', { code: error.code || 'adapter_error', message: safeError(error) }) });
    else if (this.protocol === 'messages') this.send('error', errorPayload('messages', error));
    else this.send(null, errorPayload('chat', error));
    this.res.end(this.protocol === 'chat' ? 'data: [DONE]\n\n' : undefined);
  }
  dispose() { clearInterval(this.heartbeat); }
  historyMessage() {
    return { role: 'assistant', content: this.items.filter(i => i.kind === 'text').map(i => i.text).join(''),
      tool_calls: this.items.filter(i => i.kind !== 'text').map(({ id, kind, name, arguments: args, input }) => ({ id, kind, name, ...(kind === 'custom' ? { input } : { arguments: args }) })) };
  }
}
