"""API-only, expiring friend access; never forward the console or its primary key."""
import hmac
import json
import re
import threading
import time

import httpx
from flask import Flask, Response, jsonify, request


def tunnel_address(line):
    try:
        event = json.loads(line)
    except ValueError:
        return None
    if not isinstance(event, dict) or event.get('type') != 'v1.tcpip_forward.register.accepted':
        return None
    match = re.fullmatch(r'localhost/([a-z0-9-]+\.(?:lhr\.life|localhost\.run))', str(event.get('id', '')))
    return 'https://' + match[1] if match else None


def create_share_app(config_loader, primary_key_loader, *, target='http://127.0.0.1:8866', transport=None, clock=time.time):
    # target is supplied by the local launcher/tests, never by an HTTP client.
    if target != 'http://127.0.0.1:8866' and transport is None:
        raise ValueError('Sharing only forwards to the local console')
    app = Flask('logicc-api-share')
    app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024
    lock = threading.Lock()
    used = active = 0

    def error(message, status, retry=False):
        response = jsonify(error={'message': message, 'type': 'share_access_error', 'code': 'share_access_error', 'param': None})
        response.status_code = status
        response.headers['Cache-Control'] = 'no-store'
        if retry:
            response.headers['Retry-After'] = '2'
        return response

    @app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
    @app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
    def forward(path):
        nonlocal used, active
        allowed = request.method == 'GET' and path == 'v1/models' or request.method == 'POST' and path in {'v1/chat/completions', 'v1/responses'}
        if not allowed or request.query_string:
            return error('Endpoint not available', 404)
        try:
            config = config_loader()
            if config.get('enabled') is not True or clock() >= config['expires_at']:
                return error('Share link expired or revoked', 403)
            expected = 'Bearer ' + config['api_key']
            if not hmac.compare_digest(request.headers.get('Authorization', '').encode(), expected.encode()):
                return error('Invalid share API key', 401)
        except (ValueError, OSError, KeyError):
            return error('Share configuration unavailable', 503)
        if request.method == 'POST' and not request.is_json:
            return error('Content-Type must be application/json', 415)
        body = request.get_data()
        with lock:
            if used >= 100:
                return error('Test request limit reached; ask the owner to renew access', 429)
            if active >= 2:
                return error('At most 2 simultaneous test requests', 429, True)
            used += 1
            active += 1
        client = upstream = None
        released = False

        def close():
            nonlocal active, released
            with lock:
                if released:
                    return
                released = True
                active -= 1
            if upstream is not None:
                upstream.close()
            if client is not None:
                client.close()

        try:
            client = httpx.Client(base_url=target, trust_env=False, follow_redirects=False, transport=transport,
                timeout=httpx.Timeout(205, connect=5), headers={'Authorization': 'Bearer ' + primary_key_loader(), 'Accept-Encoding': 'identity'})
            headers = {'Content-Type': 'application/json'} if request.method == 'POST' else {}
            upstream = client.send(client.build_request(request.method, '/' + path, content=body, headers=headers), stream=True)

            def generate():
                try:
                    yield from upstream.iter_raw()
                except httpx.HTTPError:
                    if 'text/event-stream' in upstream.headers.get('Content-Type', ''):
                        yield b'data: {"error":{"message":"Share connection interrupted","type":"share_error"}}\n\ndata: [DONE]\n\n'
                finally:
                    close()
            response = Response(generate(), status=upstream.status_code,
                                content_type=upstream.headers.get('Content-Type', 'application/json'))
            response.headers.update({'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no', 'X-Content-Type-Options': 'nosniff'})
            if 'Retry-After' in upstream.headers:
                response.headers['Retry-After'] = upstream.headers['Retry-After']
            response.call_on_close(close)
            return response
        except (httpx.HTTPError, ValueError, OSError, KeyError):
            close()
            return error('Local model gateway unavailable', 503)

    return app
