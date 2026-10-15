"""Opt-in real-browser acceptance; no upstream account or model calls."""
import os
import threading
from pathlib import Path

import pytest

from test_logicc_console import client


@pytest.mark.skipif(os.environ.get('RUN_LOCAL_BROWSER_TESTS') != '1', reason='opt-in local browser acceptance')
def test_gateway_ui_key_is_explicit_and_cleared_on_navigation(client):
    from playwright.sync_api import sync_playwright, expect
    from werkzeug.serving import make_server
    import app as console

    browser_path = os.environ.get('LOGICC_TEST_BROWSER', '')
    if not browser_path or not Path(browser_path).is_file():
        pytest.skip('set LOGICC_TEST_BROWSER to an installed Chromium browser executable')
    server = make_server('127.0.0.1', 0, console.app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path=browser_path, headless=True)
            context = browser.new_context(viewport={'width': 1440, 'height': 1100}, reduced_motion='reduce')
            page = context.new_page()
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            base = f'http://127.0.0.1:{server.server_port}'
            page.goto(base + '/#gateway')
            expect(page.get_by_label('OpenAI Base URL')).to_have_value(base + '/v1')
            expect(page.get_by_label('网关 API Key')).to_have_value('')
            page.get_by_role('button', name='显示密钥', exact=True).click()
            expect(page.get_by_label('网关 API Key')).to_have_value(console.model_gateway().settings()['api_key'])
            page.get_by_role('button', name='邮箱管理', exact=True).click()
            expect(page.get_by_label('网关 API Key')).to_have_value('')
            page.get_by_role('button', name='模型网关', exact=True).click()
            expect(page.get_by_role('heading', name='模型网关', exact=True)).to_be_visible()
            assert page.evaluate('Object.keys(localStorage).every(k => !/key|token|secret/i.test(k))')
            page.set_viewport_size({'width': 390, 'height': 844})
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            assert not errors
            context.close()
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
