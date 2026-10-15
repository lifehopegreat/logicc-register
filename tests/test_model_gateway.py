import base64
import json
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from cryptography.fernet import Fernet
from flask import Flask

from logicc_register import save_private
from model_gateway import ModelGateway, GatewayError, install_gateway


def jwt(sid='sess_fixture'):
    payload = base64.urlsafe_b64encode(json.dumps({'sid': sid, 'exp': time.time() + 3600}).encode()).decode().rstrip('=')
    return 'eyJhbGciOiJub25lIn0.' + payload + '.fixture'


@pytest.fixture
def gateway(tmp_path):
    if not shutil.which('node'):
        pytest.skip('Node.js 24+ required for embedded gateway integration')
    key = Fernet.generate_key()
    app = Flask('gateway-test')
    app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
    manager = install_gateway(app, lambda: tmp_path, lambda: key)()
    manager.configure({'enabled': True})
    class Calls(list):
        hold = None
    calls = Calls()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, payload):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            calls.append(self.path)
            if calls.hold is not None:
                calls.hold.wait(timeout=15)
            self.reply(200, [{'id': 'fixture-model', 'provider': 'fixture'}])

        def do_POST(self):
            calls.append(self.path)
            body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))) or '{}')
            if self.path.endswith('/tokens'):
                return self.reply(200, {'jwt': jwt()})
            if self.path == '/api/chats':
                return self.reply(200, {'id': 'chat_fixture'})
            prompt = body.get('prompt', '')
            text = 'fixture answer'
            if body.get('modelId') == 'fixture-tools':
                text = json.dumps({'content': '', 'tool_calls': [{'name': 'read_probe', 'arguments': {'label': 'fixture'}}]})
            if body.get('modelId') == 'fixture-echo':
                text = 'RESULT_RECEIVED' if 'local-result-value' in prompt else 'MISSING'
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.end_headers()
            events = [{'type': 'text-delta', 'delta': text}]
            if body.get('modelId') != 'fixture-truncated':
                events.append({'type': 'finish', 'finishReason': 'stop', 'usage': {'inputTokens': 5, 'outputTokens': 2}})
            self.wfile.write(''.join('data: ' + json.dumps(event) + '\n\n' for event in events).encode())

    class UpstreamServer(ThreadingHTTPServer):
        request_queue_size = 128
    server = UpstreamServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = 'http://127.0.0.1:' + str(server.server_port)
    manager.worker_env = {'LOGICC_API_BASE': origin + '/api', 'LOGICC_CLERK_BASE': origin}
    headers = {'Authorization': 'Bearer ' + manager.settings()['api_key']}
    try:
        yield app.test_client(), manager, headers, calls
    finally:
        manager.stop()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def account(sid='sess_fixture'):
    return {'name': 'fixture account', 'sessionId': sid, 'clientCookie': 'fixture-cookie', 'token': jwt(sid), 'enabled': True}


def test_gateway_auth_and_admin_isolation(gateway):
    client, manager, headers, calls = gateway
    assert client.get('/v1/models').status_code == 401
    assert client.get('/v1/models', headers={'Authorization': 'Bearer bad'}).status_code == 401
    assert not calls
    assert client.get('/api/gateway', headers={'Origin': 'https://evil.example'}).status_code == 403
    assert client.post('/api/gateway/key', headers={'Host': 'evil.example'}).status_code == 403
    assert client.post('/api/gateway/key', environ_overrides={'REMOTE_ADDR': '192.0.2.1'}).status_code == 403
    assert client.post('/v1/messages', headers=headers, json={}).status_code == 404
    assert client.get('/v1/../api/state', headers=headers).status_code == 404
    response = client.get('/api/gateway')
    assert response.status_code == 200 and manager.settings()['api_key'] not in response.text
    assert client.post('/api/gateway/key', json={'rotate': 'yes'}).status_code == 400
    result = client.post('/api/gateway/key')
    assert result.headers['Cache-Control'] == 'no-store'
    assert result.json['api_key'] == manager.settings()['api_key']


def test_gateway_encrypted_storage_rotation_restart_and_duplicates(gateway):
    client, manager, headers, _ = gateway
    assert manager.import_accounts([account()]) == {'imported': 1, 'skipped': 0}
    assert manager.import_accounts([account()]) == {'imported': 0, 'skipped': 1}
    snapshot = client.get('/api/gateway').json
    text = json.dumps(snapshot)
    assert 'fixture-cookie' not in text and jwt() not in text
    old = manager.settings()['api_key']
    manager.rotate_key()
    assert manager.settings()['api_key'] != old
    assert client.get('/v1/models', headers=headers).status_code == 401
    manager.stop()
    assert len(manager.call('GET', '/api/state')['accounts']) == 1
    assert b'fixture-cookie' not in (manager.data / 'gateway/state.enc').read_bytes()
    assert manager.settings()['api_key'].encode() not in manager.config_path.read_bytes()
    with httpx.Client(trust_env=False) as external:
        assert external.get(f'http://127.0.0.1:{manager.port}/api/state', headers={'X-Logicc-Admin': '1'}).status_code == 403


def test_gateway_chat_json_and_sse(gateway):
    client, manager, headers, calls = gateway
    manager.import_accounts([account()])
    models = client.get('/v1/models', headers=headers)
    assert models.status_code == 200 and models.json['data'][0]['id'] == 'fixture-model'
    body = {'model': 'fixture-model', 'messages': [{'role': 'user', 'content': 'Hello'}]}
    result = client.post('/v1/chat/completions', headers=headers, json=body)
    assert result.status_code == 200 and result.json['choices'][0]['message']['content'] == 'fixture answer'
    assert result.json['usage']['total_tokens'] == 7
    result = client.post('/v1/chat/completions', headers=headers, json={**body, 'stream': True})
    assert result.status_code == 200 and 'text/event-stream' in result.content_type
    assert 'chat.completion.chunk' in result.text and 'data: [DONE]' in result.text
    assert calls.count('/api/chats') == 2
    assert client.post('/v1/chat/completions', headers=headers, json={'messages': []}).status_code == 400
    assert client.post('/v1/chat/completions', headers=headers, data='not json').status_code == 415


def test_gateway_responses_history_and_tool_results(gateway):
    client, manager, headers, _ = gateway
    manager.import_accounts([account()])
    tool = {'type': 'function', 'function': {'name': 'read_probe', 'parameters': {'type': 'object', 'properties': {'label': {'type': 'string'}}, 'required': ['label']}}}
    first = client.post('/v1/chat/completions', headers=headers, json={'model': 'fixture-tools',
        'messages': [{'role': 'user', 'content': 'Use tool'}], 'tools': [tool], 'tool_choice': 'required'}).json
    message = first['choices'][0]['message']
    call = message['tool_calls'][0]
    assert json.loads(call['function']['arguments']) == {'label': 'fixture'}
    second = client.post('/v1/chat/completions', headers=headers, json={'model': 'fixture-echo',
        'messages': [{'role': 'user', 'content': 'Use tool'}, message,
                     {'role': 'tool', 'tool_call_id': call['id'], 'content': 'local-result-value'}], 'tools': [tool]})
    assert second.status_code == 200 and second.json['choices'][0]['message']['content'] == 'RESULT_RECEIVED'
    response = client.post('/v1/responses', headers=headers, json={'model': 'fixture-model', 'input': 'Hello'}).json
    assert response['status'] == 'completed'
    saved = client.get('/v1/responses/' + response['id'], headers=headers)
    assert saved.status_code == 200 and saved.json['id'] == response['id']
    stream = client.post('/v1/responses', headers=headers, json={'model': 'fixture-model', 'input': 'Again', 'previous_response_id': response['id'], 'stream': True})
    assert stream.status_code == 200 and 'response.completed' in stream.text
    assert client.delete('/v1/responses/' + response['id'], headers=headers).status_code == 200
    assert client.get('/v1/responses/' + response['id'], headers=headers).status_code == 404


def test_gateway_truncated_stream_is_not_success(gateway):
    client, manager, headers, _ = gateway
    manager.import_accounts([account()])
    result = client.post('/v1/chat/completions', headers=headers, json={'model': 'fixture-truncated',
        'messages': [{'role': 'user', 'content': 'Hello'}], 'stream': True})
    assert 'error' in result.text
    assert '"finish_reason":"stop"' not in result.text
    assert manager.call('GET', '/api/state')['stats']['failures'] == 1


def test_gateway_sync_only_confirmed_and_retains_rotated_credentials(gateway):
    client, manager, headers, _ = gateway
    state = {'registration_ok': True, 'onboarding_ok': True, 'email': 'owner@example.test',
        'session_id': 'sess_fixture', 'cookies': [{'name': '__client', 'domain': 'clerk.logicc.com', 'value': 'fixture-cookie'}]}
    save_private(manager.data / 'registrations/one.state.enc', manager.key_loader(), state)
    save_private(manager.data / 'registrations/two.state.enc', manager.key_loader(), {**state, 'onboarding_ok': False, 'session_id': 'sess_partial'})
    assert manager.sync_confirmed()['imported'] == 1
    assert manager.sync_confirmed()['imported'] == 0
    assert len(manager.call('GET', '/api/state')['accounts']) == 1
    assert client.get('/v1/models', headers=headers).status_code == 200


def test_gateway_disabled_and_invalid_configuration(gateway):
    client, manager, headers, calls = gateway
    for body in [{'enabled': 'yes'}, {'proxy': 'socks5://127.0.0.1:1234'}, {'upstream': 'https://evil.example'}]:
        assert client.patch('/api/gateway', json=body).status_code == 400
    assert client.post('/api/gateway/accounts/import', json={'accounts': [{'password': 'no-mail-secrets'}]}).status_code == 400
    assert client.post('/api/gateway/accounts/import', json={'accounts': [{'name': 'invalid', 'sessionId': []}]}).status_code == 400
    manager.configure({'enabled': False})
    assert client.get('/v1/models', headers=headers).status_code == 503
    assert not calls


def test_gateway_actual_32_concurrency_cap(gateway):
    _, manager, _, calls = gateway
    manager.import_accounts([account()])
    calls.hold = threading.Event()
    with manager.client() as client, ThreadPoolExecutor(max_workers=32) as executor:
        pending = [executor.submit(client.get, '/v1/models') for _ in range(32)]
        try:
            deadline = time.monotonic() + 10
            while len(calls) < 32 and time.monotonic() < deadline:
                time.sleep(.02)
            assert len(calls) == 32
            blocked = client.get('/v1/models')
            assert blocked.status_code == 429 and blocked.headers['Retry-After'] == '1'
        finally:
            calls.hold.set()
        assert all(future.result().status_code == 200 for future in pending)


def test_console_basic_password_does_not_override_gateway_auth(tmp_path, monkeypatch):
    import app as console
    monkeypatch.setattr(console, 'DATA', tmp_path)
    monkeypatch.setenv('FREE_CONSOLE_PASSWORD', 'fixture-console-password')
    client = console.app.test_client()
    assert client.get('/api/gateway').status_code == 401
    response = client.get('/v1/models')
    assert response.status_code == 401 and response.is_json
    assert 'WWW-Authenticate' not in response.headers
