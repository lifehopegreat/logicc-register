import asyncio
import logging
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
import registration_diagnostics as diag
from capture_redaction import Redactor, MASK


def test_metadata_drops_all_secret_url_parts_and_headers():
    assert diag.safe_endpoint("https://user:secret@clerk.logicc.com/v1/client/sign_ups?code=secret#secret") == {
        "host": "clerk.logicc.com", "path": "/v1/client/sign_ups"}
    assert diag.safe_endpoint("https://clerk.logicc.com/secret-123456")['path'] == "/[other]"
    assert diag.safe_endpoint("https://unrelated.test/secret") is None
    result = diag.response_metadata({"Content-Type": "text/html; charset=utf-8", "CF-Mitigated": "challenge",
                                     "Set-Cookie": "secret", "X-Request-ID": "secret"})
    assert result['content_type'] == 'text/html'
    assert result['challenge'] is True
    assert 'secret' not in str(result)


@pytest.mark.parametrize('expired', [False, True])
def test_opt_in_async_hook_preserves_results_and_exceptions(tmp_path, monkeypatch, caplog, expired):
    from curl_cffi.requests import AsyncSession
    import requests
    lease = tmp_path / 'lease'
    lease.write_text(str(time.time() + (-1 if expired else 60)), encoding='utf-8')
    monkeypatch.setattr(diag, 'LEASE', lease)
    response = SimpleNamespace(status_code=403, headers={'cf-mitigated': 'challenge'})
    failure = RuntimeError('curl: (60) secret')
    calls = []

    async def original(self, method, url, **kwargs):
        calls.append(kwargs)
        if kwargs.get('fail'):
            raise failure
        return response

    monkeypatch.setattr(AsyncSession, 'request', original)
    monkeypatch.setattr(requests.Session, 'request', requests.Session.request)
    caplog.set_level(logging.INFO, logger='registration_diagnostics')
    diag.enable_if_requested()
    assert asyncio.run(AsyncSession.request(None, 'POST', 'https://clerk.logicc.com/register?secret', data='secret')) is response
    with pytest.raises(RuntimeError) as caught:
        asyncio.run(AsyncSession.request(None, 'GET', 'https://clerk.logicc.com/register', fail=True))
    assert caught.value is failure
    assert calls[0] == {'data': 'secret'}
    assert 'secret' not in caplog.text
    assert ('[capture-http]' in caplog.text) is not expired
    if not expired:
        assert '"curl_code": 60' in caplog.text


def test_redactor_preserves_contract_and_removes_credentials_and_echoes():
    import json
    r = Redactor()
    request = r.body({'email': 'person@example.test', 'password': 'simple-pass', 'code': '123456',
                      'profile': {'name': 'Private Person'}, 'screen_hint': 'login_or_signup'})
    response = r.body({'error': {'code': 'browser_challenge', 'message': 'simple-pass rejected for person@example.test'},
                       'access_token': 'short-token', 'page': {'type': 'email_verification'},
                       'continue_url': 'https://clerk.logicc.com/register?state=short-state'})
    headers = r.headers({'Set-Cookie': 'session=short-cookie; Path=/', 'Location': 'https://clerk.logicc.com/register?code=short-code',
                         'Content-Type': 'application/json', 'openai-sentinel-token': 'sentinel-private'})
    encoded = json.dumps([request, response, headers])
    for secret in ['person@example.test', 'simple-pass', '123456', 'Private Person', 'short-token',
                   'short-state', 'short-code', 'short-cookie', 'sentinel-private']:
        assert secret not in encoded
    assert response['content']['error']['code'] == 'browser_challenge'
    assert response['content']['page']['type'] == 'email_verification'
    assert headers['content-type'] == 'application/json'


def test_form_html_binary_and_mailbox_fail_closed():
    r = Redactor()
    form = r.body('password=form-secret&code=123456&prompt=login', 'application/x-www-form-urlencoded')
    assert form['content'] == [['password', MASK], ['code', MASK], ['prompt', 'login']]
    html = r.body('<html><title>Checking your browser</title><script>token="script-secret"</script>'
                  '<input value="input-secret"><!--comment-secret--><div data-state="attribute-secret">Access denied</div></html>', 'text/html')
    assert 'Checking your browser' in html['content'] and 'Access denied' in html['content']
    for secret in ['script-secret', 'input-secret', 'comment-secret', 'attribute-secret']:
        assert secret not in html['content']
    assert r.body(b'\xff\x00', 'image/png')['kind'] == 'binary'
    assert r.body({'messages': ['private-mail']}, mailbox=True)['kind'] == 'redacted'


def test_auth_session_fields_are_redacted_even_when_not_opaque_tokens():
    import json
    r = Redactor()
    body = r.body({'oai-client-auth-session': 'short-session',
                   'session': {'value': 'nested-session'}, 'page': {'type': 'email_verification'}})
    headers = r.headers({'oai-client-auth-session': 'header-session'})
    saved = json.dumps([body, headers, r.body('short-session nested-session echoed', 'text/plain')])
    for secret in ('short-session', 'nested-session', 'header-session'):
        assert secret not in saved
    assert body['content']['page']['type'] == 'email_verification'


def test_full_mode_writes_redacted_body_outside_console_logs(tmp_path, monkeypatch, caplog):
    import json
    from curl_cffi.requests import AsyncSession
    import requests
    lease = tmp_path / 'lease'
    lease.write_text(json.dumps({'deadline': time.time() + 60, 'mode': 'redacted-http'}), encoding='utf-8')
    monkeypatch.setattr(diag, 'LEASE', lease)
    monkeypatch.setattr(diag, 'CAPTURE_DIR', tmp_path)
    response = SimpleNamespace(status_code=403, headers={'content-type': 'application/json', 'cf-mitigated': 'challenge'},
        content=b'{"error":{"code":"browser_challenge","message":"body-diagnostic"},"refresh_token":"response-secret"}',
        url='https://clerk.logicc.com/register?state=redirect-secret')

    async def original(self, method, url, **kwargs):
        return response

    monkeypatch.setattr(AsyncSession, 'request', original)
    monkeypatch.setattr(requests.Session, 'request', requests.Session.request)
    caplog.set_level(logging.INFO, logger='registration_diagnostics')
    diag.enable_if_requested()
    assert asyncio.run(AsyncSession.request(None, 'POST', 'https://clerk.logicc.com/register?state=query-secret',
        json={'password': 'request-secret', 'screen_hint': 'signup'})) is response
    files = list(tmp_path.glob('capture-*.jsonl'))
    assert len(files) == 1
    saved = files[0].read_text(encoding='utf-8')
    for secret in ['response-secret', 'request-secret', 'redirect-secret', 'query-secret']:
        assert secret not in saved
    row = json.loads(saved)
    assert row['request']['body']['content']['password'] == MASK
    assert row['response']['body']['content']['error']['message'] == 'body-diagnostic'
    assert row['response']['status'] == 403
    assert 'body-diagnostic' not in caplog.text
