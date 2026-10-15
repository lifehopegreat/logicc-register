"""Single-console OpenAI gateway backed by an embedded, supervised adapter."""
from __future__ import annotations

import atexit
import hmac
import ipaddress
import json
import os
import queue
import re
import secrets
import shutil
import subprocess
import threading
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from flask import Response, jsonify, request

from logicc_register import load_private, save_private
from paylink_proxy import normalize_proxy_url


class GatewayError(Exception):
    def __init__(self, message, status=503):
        super().__init__(message)
        self.status = status


class ModelGateway:
    def __init__(self, data, key_loader, *, worker_env=None):
        self.data = Path(data)
        self.key_loader = key_loader
        self.config_path = self.data / 'services' / 'model_gateway.enc'
        self.lock = threading.RLock()
        self.sync_lock = threading.Lock()
        self.process = None
        self.port = None
        self.internal_key = ''
        self.synced_signature = None
        self.worker_env = worker_env or {}
        atexit.register(self.stop)

    def settings(self):
        with self.lock:
            if not self.config_path.exists():
                value = {'enabled': False, 'api_key': 'sk-logicc-' + secrets.token_urlsafe(32), 'proxy': ''}
                save_private(self.config_path, self.key_loader(), value)
            return load_private(self.config_path, self.key_loader())

    def configure(self, body):
        if not isinstance(body, dict) or set(body) - {'enabled', 'proxy'}:
            raise GatewayError('网关配置格式无效', 400)
        with self.lock:
            value = self.settings()
            if 'enabled' in body:
                if not isinstance(body['enabled'], bool):
                    raise GatewayError('enabled 必须为布尔值', 400)
                value['enabled'] = body['enabled']
            if 'proxy' in body:
                if not isinstance(body['proxy'], str):
                    raise GatewayError('代理格式无效', 400)
                try:
                    value['proxy'] = normalize_proxy_url(body['proxy']) if body['proxy'].strip() else ''
                except ValueError:
                    raise GatewayError('代理格式无效', 400) from None
                if value['proxy'] and urlsplit(value['proxy']).scheme not in {'http', 'https'}:
                    raise GatewayError('网关出口仅支持 HTTP/HTTPS 代理', 400)
            if self.process and self.process.poll() is None:
                if self.call('GET', '/api/state')['stats']['active']:
                    raise GatewayError('网关仍有请求运行，请完成后修改配置', 409)
                self.stop()
            save_private(self.config_path, self.key_loader(), value)
            return value

    def rotate_key(self):
        with self.lock:
            value = self.settings()
            value['api_key'] = 'sk-logicc-' + secrets.token_urlsafe(32)
            save_private(self.config_path, self.key_loader(), value)
            return value['api_key']

    def start(self):
        with self.lock:
            if not self.settings()['enabled']:
                raise GatewayError('网关尚未启用')
            if self.process and self.process.poll() is None:
                return
            if self.process:
                self.stop()
            node = os.environ.get('LOGICC_NODE') or shutil.which('node')
            if not node:
                raise GatewayError('需要 Node.js 24+；可通过 LOGICC_NODE 指定可执行文件')
            flags = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
            try:
                version = subprocess.run([node, '--version'], capture_output=True, text=True, timeout=5, **flags)
                if version.returncode or int(version.stdout.strip().lstrip('v').split('.')[0]) < 24:
                    raise GatewayError('需要 Node.js 24+')
                env = {k: v for k, v in os.environ.items() if not k.startswith(('LOGICC_', 'NODE_', 'ANTHROPIC_'))
                       and k.upper() not in {'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY'}}
                self.internal_key = secrets.token_urlsafe(32)
                env.update(LOGICC_GATEWAY_INTERNAL_KEY=self.internal_key,
                           LOGICC_GATEWAY_STORAGE_KEY=self.key_loader().decode('ascii'),
                           LOGICC_DATA_FILE=str(self.data / 'gateway' / 'state.enc'))
                proxy = self.settings().get('proxy', '')
                if proxy:
                    env.update(HTTP_PROXY=proxy, HTTPS_PROXY=proxy, NODE_USE_ENV_PROXY='1', NO_PROXY='127.0.0.1,localhost')
                env.update(self.worker_env)
                self.process = subprocess.Popen([node, str(Path(__file__).with_name('gateway_worker.mjs'))],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, **flags)
                ready = queue.Queue(maxsize=1)
                pipe = self.process.stdout
                threading.Thread(target=lambda: ready.put(pipe.readline()), daemon=True).start()
                value = json.loads(ready.get(timeout=12))
                port = value.get('port')
                if type(port) is not int or not 1 <= port <= 65535:
                    raise ValueError('Invalid worker port')
                self.port = port
                self.synced_signature = None
            except (OSError, ValueError, subprocess.SubprocessError, queue.Empty):
                self.stop()
                raise GatewayError('网关核心启动失败；请检查 Node 版本及加密数据文件，原文件未覆盖') from None

    def stop(self):
        with self.lock:
            process, self.process = self.process, None
            if process:
                if process.stdin:
                    process.stdin.close()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                if process.stdout:
                    process.stdout.close()
            self.port = None

    def client(self):
        self.start()
        return httpx.Client(base_url=f'http://127.0.0.1:{self.port}', trust_env=False,
            follow_redirects=False, timeout=httpx.Timeout(200, connect=5),
            headers={'X-Gateway-Internal': self.internal_key, 'X-Logicc-Admin': '1',
                     'Authorization': 'Bearer ' + self.internal_key})

    def call(self, method, path, body=None):
        try:
            with self.client() as client:
                response = client.request(method, path, json=body)
                if response.status_code >= 400:
                    raise GatewayError(f'网关核心返回 HTTP {response.status_code}', response.status_code)
                return response.json()
        except (httpx.HTTPError, ValueError):
            raise GatewayError('网关核心连接失败') from None

    def import_accounts(self, entries):
        with self.sync_lock:
            if not isinstance(entries, list) or not 1 <= len(entries) <= 200:
                raise GatewayError('请提供 1–200 个账号', 400)
            current = {a['sessionId'] for a in self.call('GET', '/api/state')['accounts']}
            incoming, seen = [], set(current)
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) - {'name', 'sessionId', 'clientCookie', 'token', 'enabled'}:
                    raise GatewayError('账号仅接受 name/sessionId/clientCookie/token/enabled，不接收邮箱凭据', 400)
                sid = entry.get('sessionId')
                if sid is not None and not isinstance(sid, str):
                    raise GatewayError('sessionId 必须为字符串', 400)
                if sid and sid in seen:
                    continue
                incoming.append(entry)
                if sid:
                    seen.add(sid)
            if incoming:
                self.call('POST', '/api/accounts/import', {'accounts': incoming})
            return {'imported': len(incoming), 'skipped': len(entries) - len(incoming)}

    def sync_confirmed(self):
        self.start()
        paths = sorted((self.data / 'registrations').glob('*.state.enc'))
        signature = tuple((p.name, p.stat().st_mtime_ns, p.stat().st_size) for p in paths)
        if signature == self.synced_signature:
            return {'imported': 0, 'skipped': 0}
        entries = []
        for path in paths:
            state = load_private(path, self.key_loader())
            if state.get('registration_ok') is not True or state.get('onboarding_ok') is not True:
                continue
            cookies = [c for c in state.get('cookies', []) if c.get('name') == '__client' and
                       c.get('domain', '').lstrip('.') in {'clerk.logicc.com', 'logicc.com'}]
            cookies.sort(key=lambda c: c.get('domain', '').lstrip('.') == 'clerk.logicc.com', reverse=True)
            if cookies and state.get('session_id') and state.get('email'):
                entries.append({'name': state['email'], 'sessionId': state['session_id'],
                                'clientCookie': cookies[0]['value'], 'enabled': True})
        result = self.import_accounts(entries) if entries else {'imported': 0, 'skipped': 0}
        self.synced_signature = signature
        return result


def install_gateway(app, data_loader, key_loader):
    managers = {}
    lock = threading.Lock()

    def gateway():
        data = Path(data_loader()).resolve()
        with lock:
            if data not in managers:
                managers[data] = ModelGateway(data, key_loader)
            return managers[data]

    app.extensions['model_gateway'] = gateway

    def error(message, status):
        return jsonify(error={'message': message, 'type': 'authentication_error' if status == 401 else 'gateway_error',
                              'param': None, 'code': 'gateway_error'}), status

    @app.before_request
    def gateway_guard():
        if request.path.startswith('/api/gateway'):
            try:
                local = ipaddress.ip_address(request.remote_addr or '').is_loopback
            except ValueError:
                local = False
            host = urlsplit('http://' + request.host).hostname
            if (not local or host not in {'localhost', '127.0.0.1', '::1'} or
                request.headers.get('Sec-Fetch-Site') == 'cross-site' or
                (request.headers.get('Origin') and request.headers['Origin'] != request.host_url.rstrip('/'))):
                return jsonify(ok=False, error='网关管理仅限本机同源访问'), 403
        if request.path.startswith('/v1/'):
            try:
                auth = request.headers.get('Authorization', '')
                expected = 'Bearer ' + gateway().settings()['api_key']
                if not hmac.compare_digest(auth.encode(), expected.encode()):
                    return error('Invalid API key', 401)
                if not gateway().settings()['enabled']:
                    return error('Gateway disabled', 503)
            except (OSError, ValueError):
                return error('Gateway configuration unavailable', 503)

    @app.route('/api/gateway', methods=['GET', 'PATCH'])
    def gateway_status():
        try:
            manager = gateway()
            value = manager.configure(request.get_json(silent=True)) if request.method == 'PATCH' else manager.settings()
            snapshot = manager.call('GET', '/api/state') if value['enabled'] else {}
            proxy = urlsplit(value.get('proxy', ''))
            return jsonify(ok=True, enabled=value['enabled'], base_url=request.host_url.rstrip('/') + '/v1',
                           api_key_configured=True, proxy_configured=bool(value.get('proxy')),
                           proxy_host=proxy.hostname or '', accounts=snapshot.get('accounts', []),
                           stats=snapshot.get('stats', {}), models=snapshot.get('models', []),
                           requests=snapshot.get('requests', []), max_concurrency=32)
        except GatewayError as exc:
            return jsonify(ok=False, error=str(exc)), exc.status
        except (ValueError, OSError):
            return jsonify(ok=False, error='加密网关配置不可用'), 503

    @app.post('/api/gateway/key')
    def gateway_key():
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict) or set(body) - {'rotate'} or ('rotate' in body and type(body['rotate']) is not bool):
            return jsonify(ok=False, error='密钥操作格式无效'), 400
        try:
            manager = gateway()
            key = manager.rotate_key() if body.get('rotate') else manager.settings()['api_key']
        except (ValueError, OSError):
            return jsonify(ok=False, error='加密网关配置不可用'), 503
        response = jsonify(ok=True, api_key=key)
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.post('/api/gateway/sync')
    def gateway_sync():
        try:
            return jsonify(ok=True, **gateway().sync_confirmed())
        except (GatewayError, ValueError, OSError) as exc:
            return jsonify(ok=False, error=str(exc) if isinstance(exc, GatewayError) else '注册状态解密失败，未忽略原始数据'), getattr(exc, 'status', 503)

    @app.post('/api/gateway/accounts/import')
    def gateway_import():
        try:
            body = request.get_json(silent=True)
            return jsonify(ok=True, **gateway().import_accounts(body.get('accounts') if isinstance(body, dict) else None))
        except GatewayError as exc:
            return jsonify(ok=False, error=str(exc)), exc.status

    @app.route('/api/gateway/accounts/<account_id>', methods=['PATCH'])
    @app.post('/api/gateway/accounts/<account_id>/<action>')
    def gateway_account(account_id, action=None):
        if not re.fullmatch(r'[\w-]{1,150}', account_id) or action not in {None, 'check', 'refresh'}:
            return jsonify(ok=False, error='无效账号操作'), 400
        body = request.get_json(silent=True)
        if not action and (not isinstance(body, dict) or set(body) != {'enabled'} or type(body['enabled']) is not bool):
            return jsonify(ok=False, error='仅允许启用/停用账号'), 400
        try:
            path = '/api/accounts/' + account_id + ('/' + action if action else '')
            return jsonify(ok=True, **gateway().call('POST' if action else 'PATCH', path, body or {}))
        except GatewayError as exc:
            return jsonify(ok=False, error=str(exc)), exc.status

    @app.route('/v1/<path:path>', methods=['GET', 'POST', 'DELETE'])
    def gateway_proxy(path):
        allowed = (request.method == 'GET' and path == 'models' or
                   request.method == 'POST' and path in {'chat/completions', 'responses'} or
                   request.method in {'GET', 'DELETE'} and re.fullmatch(r'responses/resp_[a-zA-Z0-9]+', path))
        if not allowed:
            return error('Endpoint not supported', 404)
        if request.method == 'POST' and not request.is_json:
            return error('Content-Type must be application/json', 415)
        client = upstream = None
        try:
            manager = gateway()
            manager.sync_confirmed()
            client = manager.client()
            headers = {'Content-Type': 'application/json'} if request.method == 'POST' else {}
            upstream = client.send(client.build_request(request.method, '/v1/' + path, content=request.get_data(), headers=headers), stream=True)
            def generate():
                try:
                    yield from upstream.iter_raw()
                except httpx.HTTPError:
                    if 'text/event-stream' in upstream.headers.get('Content-Type', ''):
                        yield b'data: {"error":{"type":"gateway_error","message":"Gateway stream interrupted"}}\n\ndata: [DONE]\n\n'
                finally:
                    upstream.close()
                    client.close()
            response = Response(generate(), status=upstream.status_code,
                content_type=upstream.headers.get('Content-Type', 'application/json'))
            response.headers.update({'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no', 'X-Content-Type-Options': 'nosniff'})
            if 'Retry-After' in upstream.headers:
                response.headers['Retry-After'] = upstream.headers['Retry-After']
            response.call_on_close(upstream.close)
            response.call_on_close(client.close)
            return response
        except (GatewayError, httpx.HTTPError, ValueError, OSError) as exc:
            if upstream:
                upstream.close()
            if client:
                client.close()
            return error(str(exc) if isinstance(exc, GatewayError) else 'Gateway unavailable', getattr(exc, 'status', 503))

    return gateway
