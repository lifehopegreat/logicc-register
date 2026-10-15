// Private, supervised data plane. Public access goes through the Flask gateway.
import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createAdapter } from './gateway_vendor/server.mjs';

const secret = process.env.LOGICC_GATEWAY_INTERNAL_KEY;
const storageKey = process.env.LOGICC_GATEWAY_STORAGE_KEY;
const file = process.env.LOGICC_DATA_FILE;
if (!secret || !storageKey || !file) throw new Error('Missing private gateway configuration');
const key = createHash('sha256').update(storageKey).digest();
let documents = {};
if (existsSync(file)) {
  const bytes = readFileSync(file);
  if (bytes.subarray(0, 4).toString() !== 'LGW1') throw new Error('Invalid encrypted gateway state');
  const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(4, 16));
  decipher.setAuthTag(bytes.subarray(16, 32));
  documents = JSON.parse(Buffer.concat([decipher.update(bytes.subarray(32)), decipher.final()]));
}
const store = {
  get: name => documents[name],
  put(name, value) {
    documents[name] = value;
    const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(documents)), cipher.final()]);
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    writeFileSync(file + '.tmp', Buffer.concat([Buffer.from('LGW1'), iv, cipher.getAuthTag(), encrypted]), { mode: 0o600 });
    renameSync(file + '.tmp', file);
  },
};
const { server } = createAdapter({ store, env: { ...process.env, LOGICC_API_KEY: secret } });
const handle = server.listeners('request')[0];
server.removeAllListeners('request');
let active = 0;
server.on('request', (req, res) => {
  const incoming = Buffer.from(req.headers['x-gateway-internal'] || ''), expected = Buffer.from(secret);
  if (incoming.length !== expected.length || !timingSafeEqual(incoming, expected)) {
    res.writeHead(403); res.end(); return;
  }
  const path = req.url?.split('?')[0];
  const allowed = path === '/health' || path === '/api/state' || path === '/api/accounts' ||
    path === '/api/accounts/import' || /^\/api\/accounts\/[\w-]+(?:\/(?:check|refresh))?$/.test(path) ||
    ['/v1/models', '/v1/chat/completions', '/v1/responses'].includes(path) || /^\/v1\/responses\/resp_[a-zA-Z0-9]+$/.test(path);
  if (!allowed) { res.writeHead(404); res.end(); return; }
  if (path.startsWith('/v1/')) {
    if (active >= 32) {
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '1' });
      res.end(JSON.stringify({ error: { type: 'rate_limit_error', message: 'Gateway concurrency limit reached', code: 'gateway_busy', param: null } }));
      return;
    }
    active++;
    res.once('close', () => active--);
  }
  void handle(req, res);
});
server.listen(0, '127.0.0.1', () => process.stdout.write(JSON.stringify({ port: server.address().port }) + '\n'));
function stop() { server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 2000).unref(); }
process.stdin.resume();
process.stdin.on('end', stop);
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
