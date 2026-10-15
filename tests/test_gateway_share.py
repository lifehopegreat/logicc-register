import json
import httpx
import pytest

from gateway_share import create_share_app, tunnel_address


@pytest.fixture
def shared():
    config = {'enabled': True, 'api_key': 'fixture-friend-key', 'expires_at': 200}
    calls = []
    def handle(request):
        assert request.headers['Authorization'] == 'Bearer fixture-primary-key'
        assert 'fixture-friend-key' not in str(request.headers)
        calls.append(request)
        return httpx.Response(200, headers={'Content-Type': 'text/event-stream'},
                              stream=httpx.ByteStream(b'data: {"value":"fixture"}\n\ndata: [DONE]\n\n'))
    app = create_share_app(lambda: config, lambda: 'fixture-primary-key',
                           transport=httpx.MockTransport(handle), clock=lambda: 100)
    return app.test_client(), config, calls, {'Authorization': 'Bearer fixture-friend-key'}


def test_share_never_exposes_admin_or_other_protocols(shared):
    client, _, calls, headers = shared
    for path in ['/', '/api/gateway', '/api/gateway/key', '/api/accounts', '/v1/messages',
                 '/v1/responses/resp_private', '/v1/../api/gateway', '/v1/models?redirect=/api/state']:
        result = client.get(path, headers=headers)
        assert result.status_code == 404
        assert 'fixture-primary-key' not in result.text
    assert not calls


def test_share_auth_expiration_and_revocation(shared):
    client, config, calls, headers = shared
    assert client.get('/v1/models').status_code == 401
    assert client.get('/v1/models', headers={'Authorization': 'Bearer fixture-primary-key'}).status_code == 401
    config['expires_at'] = 99
    assert client.get('/v1/models', headers=headers).status_code == 403
    config.update(expires_at=200, enabled=False)
    assert client.get('/v1/models', headers=headers).status_code == 403
    assert not calls


def test_share_rewrites_key_and_streams_response(shared):
    client, _, calls, headers = shared
    response = client.post('/v1/chat/completions', headers=headers, json={'model': 'fixture', 'stream': True})
    assert response.status_code == 200 and 'data: [DONE]' in response.text
    assert response.headers['Cache-Control'] == 'no-store'
    assert calls[0].url.path == '/v1/chat/completions'
    assert calls[0].content == b'{"model": "fixture", "stream": true}'
    assert client.post('/v1/responses', headers=headers, data='bad body').status_code == 415


def test_share_2_concurrency_and_connection_cleanup(shared):
    client, _, _, headers = shared
    first = client.get('/v1/models', headers=headers, buffered=False)
    second = client.get('/v1/models', headers=headers, buffered=False)
    try:
        third = client.get('/v1/models', headers=headers)
        assert third.status_code == 429 and third.headers['Retry-After'] == '2'
        first.close()
        fourth = client.get('/v1/models', headers=headers)
        assert fourth.status_code == 200
        fourth.get_data()
        fourth.close()
    finally:
        first.close()
        second.close()


def test_share_request_budget_and_body_limit(shared):
    client, _, calls, headers = shared
    for _ in range(100):
        response = client.get('/v1/models', headers=headers)
        assert response.status_code == 200
        response.get_data()
        response.close()
    assert client.get('/v1/models', headers=headers).status_code == 429
    assert len(calls) == 100
    assert client.post('/v1/chat/completions', headers={**headers, 'Content-Type': 'application/json'}, data=b'x' * (1024 * 1024 + 1)).status_code == 413


def test_share_does_not_echo_network_errors_or_credentials():
    def handle(request):
        raise httpx.ConnectError('fixture-primary-key secret error', request=request)
    app = create_share_app(lambda: {'enabled': True, 'expires_at': 200, 'api_key': 'friend'}, lambda: 'primary',
        transport=httpx.MockTransport(handle), clock=lambda: 100)
    result = app.test_client().get('/v1/models', headers={'Authorization': 'Bearer friend'})
    assert result.status_code == 503
    assert 'fixture-primary-key' not in result.text


def test_tunnel_address_uses_registration_event_not_banner_urls():
    assert tunnel_address('Manage tunnels at https://admin.localhost.run') is None
    assert tunnel_address('{broken') is None
    assert tunnel_address(json.dumps({'type': 'banner', 'id': 'localhost/admin.localhost.run'})) is None
    assert tunnel_address(json.dumps({'type': 'v1.tcpip_forward.register.accepted', 'id': 'localhost/probe.lhr.life', 'data': 'https://admin.localhost.run'})) == 'https://probe.lhr.life'
    assert tunnel_address(json.dumps({'type': 'v1.tcpip_forward.register.accepted', 'id': 'localhost/attacker.example'})) is None
