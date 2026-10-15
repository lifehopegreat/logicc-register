import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';
import { HttpError } from './pool.mjs';

const validId = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,200}$/.test(value);
const editable = assistant => ['owner', 'editor'].includes(assistant.permissions);
const revision = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function requireId(value) {
  if (!validId(value)) throw new HttpError(400, '助手 ID 格式不正确');
  return value;
}
function returnedId(value) {
  const id = typeof value === 'string' ? value : value?.id;
  if (!validId(id)) throw new HttpError(502, '上游未返回有效的助手 ID');
  return id;
}
function promptValue(value) {
  if (typeof value !== 'string' || value.length > 30000) throw new HttpError(400, 'systemPrompt 必须为不超过 30,000 字符的文本');
  return value;
}
function summary(raw) {
  return { id: requireId(raw.id), name: typeof raw.name === 'string' ? raw.name : raw.localizationKey || '未命名助手',
    modelId: typeof raw.modelId === 'string' ? raw.modelId : null, permissions: raw.permissions || 'none', isDraft: Boolean(raw.isDraft),
    visibility: raw.visibility || 'private', description: typeof raw.description === 'string' ? raw.description : '' };
}

export class AssistantPrompts {
  constructor(file, upstream, store) {
    this.file = file;
    this.store = store;
    this.upstream = upstream;
    this.locks = new Set();
    this.data = { version: 1, defaults: {}, snapshots: [] };
    const saved = store ? store.get('assistant-prompts') : existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : undefined;
    if (saved !== undefined) {
      this.data = saved;
      if (this.data.version !== 1 || !Array.isArray(this.data.snapshots) || !this.data.defaults || typeof this.data.defaults !== 'object') throw new Error('助手提示词数据格式不正确，原文件未被覆盖');
      if (!store) chmodSync(file, 0o600);
    }
  }
  persist() {
    if (this.store) return this.store.put('assistant-prompts', this.data);
    mkdirSync(dirname(this.file), { recursive: true, mode: 0o700 });
    writeFileSync(this.file + '.tmp', JSON.stringify(this.data, null, 2), { mode: 0o600 });
    chmodSync(this.file + '.tmp', 0o600);
    renameSync(this.file + '.tmp', this.file);
  }
  defaultFor(accountId) { return this.data.defaults[accountId] || null; }
  async json(account, path, options = {}) {
    const response = await this.upstream(account, path, options);
    if (response.status === 204) return null;
    const text = await response.text();
    if (!text) return null;
    try { return JSON.parse(text); } catch { throw new HttpError(502, '上游助手接口返回了无效 JSON'); }
  }
  async list(account, { type = 'library', cursor, query, signal } = {}) {
    if (!['library', 'shared', 'curated'].includes(type)) throw new HttpError(400, '助手列表类型不正确');
    if (cursor) requireId(cursor);
    if (query && (typeof query !== 'string' || query.length > 200)) throw new HttpError(400, '搜索词过长');
    const data = await this.json(account, 'assistants/list', { method: 'POST', signal, body: {
      type, limit: type === 'curated' ? 100 : 20, sortType: 'alphabetically', sortDirection: 'ascending',
      ...(cursor ? { lastAssistant: cursor } : {}), ...(query ? { query } : {}) } });
    if (!Array.isArray(data?.data)) throw new HttpError(502, '上游助手列表格式不正确');
    const items = data.data.map(summary);
    return { data: items, hasMore: Boolean(data.hasMore), nextCursor: data.hasMore ? items.at(-1)?.id || null : null, defaultAssistant: this.defaultFor(account.id) };
  }
  async readRaw(account, assistantId, signal) {
    requireId(assistantId);
    const published = await this.json(account, `assistants/${assistantId}`, { signal });
    if (!published || typeof published !== 'object') throw new HttpError(502, '上游助手详情格式不正确');
    published.id ||= assistantId;
    const draftId = !published.isDraft && editable(published) && published.draftId ? requireId(published.draftId) : null;
    const current = draftId ? await this.json(account, `assistants/${draftId}`, { signal }) : published;
    if (!current || typeof current !== 'object') throw new HttpError(502, '上游草稿详情格式不正确');
    current.id ||= draftId || assistantId;
    const version = revision({ publishedId: assistantId, draftId, editId: current.id,
      systemPrompt: current.systemPrompt, name: current.name, description: current.description,
      modelId: current.modelId, features: current.features, conversationStarters: current.conversationStarters,
      updatedAt: current.updatedAt });
    return { published, current, draftId, version };
  }
  snapshot(account, raw) {
    const { published, current, draftId, version } = raw;
    const readable = typeof current.systemPrompt === 'string';
    const old = this.data.snapshots.find(s => s.accountId === account.id && s.id === published.id);
    const item = { ...summary(current), id: published.id, editId: current.id, hasDraft: Boolean(draftId),
      isDraft: Boolean(published.isDraft), canEdit: editable(published) && editable(current) && readable,
      promptReadable: readable, systemPrompt: readable ? current.systemPrompt : null,
      originalSystemPrompt: old?.originalSystemPrompt ?? (typeof published.systemPrompt === 'string' ? published.systemPrompt : readable ? current.systemPrompt : null),
      firstReadAt: old?.originalSystemPrompt != null ? old.firstReadAt : Date.now(), fetchedAt: Date.now(), revision: version, accountId: account.id,
      source: 'logicc-assistant', defaultSelected: this.defaultFor(account.id)?.id === published.id };
    this.data.snapshots = [item, ...this.data.snapshots.filter(s => !(s.accountId === account.id && s.id === published.id))].slice(0, 200);
    this.persist();
    return item;
  }
  async read(account, assistantId, signal) { return this.snapshot(account, await this.readRaw(account, assistantId, signal)); }
  async save(account, assistantId, input, signal) {
    requireId(assistantId);
    const systemPrompt = promptValue(input?.systemPrompt);
    if (typeof input?.revision !== 'string') throw new HttpError(400, '请先读取助手，再提交带 revision 的保存请求');
    const key = `${account.id}:${assistantId}`;
    if (this.locks.has(key)) throw new HttpError(409, '该助手正在保存，请稍后重试');
    this.locks.add(key);
    try {
      const raw = await this.readRaw(account, assistantId, signal);
      if (!editable(raw.published) || !editable(raw.current)) throw new HttpError(403, '当前账号没有此助手的编辑权限');
      if (raw.version !== input.revision) throw new HttpError(409, '上游助手已被修改，请重新读取并核对后再保存');
      const draftId = raw.draftId || (raw.published.isDraft ? assistantId : returnedId(await this.json(account, 'assistants', { method: 'POST', body: { parentId: assistantId }, signal })));
      // Edit only the requested field; preserve the assistant's model, files, tools and other settings.
      const patched = await this.upstream(account, `assistants/${draftId}`, { method: 'PATCH', body: { systemPrompt }, signal });
      await patched.body?.cancel();
      const publishedId = returnedId(await this.json(account, `assistants/${draftId}/save`, { method: 'POST', signal }));
      const savedRaw = await this.readRaw(account, publishedId, signal);
      if (savedRaw.current.systemPrompt !== systemPrompt) throw new HttpError(502, '保存后读取的提示词与提交内容不一致，请在上游核对');
      const saved = this.snapshot(account, savedRaw);
      if (this.defaultFor(account.id)?.id === assistantId) {
        this.data.defaults[account.id] = { id: publishedId, name: saved.name, modelId: saved.modelId };
        this.persist();
      }
      return saved;
    } finally { this.locks.delete(key); }
  }
  async create(account, input, signal) {
    if (typeof input?.name !== 'string' || !input.name.trim() || input.name.trim().length > 50) throw new HttpError(400, '助手名称需要 1–50 个字符');
    if (typeof input.modelId !== 'string' || !input.modelId || input.modelId.length > 150) throw new HttpError(400, '请选择助手模型');
    const systemPrompt = promptValue(input.systemPrompt);
    const draftId = returnedId(await this.json(account, 'assistants', { method: 'POST', body: { parentId: null }, signal }));
    const patched = await this.upstream(account, `assistants/${draftId}`, { method: 'PATCH', signal, body: {
      name: input.name.trim(), description: '', modelId: input.modelId, systemPrompt,
      conversationStarters: [], features: { 'web-search': false, 'image-generation': false } } });
    await patched.body?.cancel();
    const publishedId = returnedId(await this.json(account, `assistants/${draftId}/save`, { method: 'POST', signal }));
    return this.read(account, publishedId, signal);
  }
  async selectDefault(account, assistantId, signal) {
    if (assistantId === null) delete this.data.defaults[account.id];
    else {
      const raw = await this.readRaw(account, requireId(assistantId), signal);
      if (raw.published.isDraft) throw new HttpError(400, '请先发布草稿，再设为默认助手');
      this.data.defaults[account.id] = { id: assistantId, name: summary(raw.published).name, modelId: summary(raw.published).modelId };
    }
    this.persist();
    return this.defaultFor(account.id);
  }
  forgetAccount(accountId) {
    delete this.data.defaults[accountId];
    this.data.snapshots = this.data.snapshots.filter(s => s.accountId !== accountId);
    this.persist();
  }
}
