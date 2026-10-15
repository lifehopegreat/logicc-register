#!/usr/bin/env python3
"""Temporary API-only HTTPS sharing using the installed OpenSSH client."""
import json
import logging
import os
import queue
import secrets
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'core'))
from gateway_share import create_share_app, tunnel_address
from logicc_register import load_private, save_private
from werkzeug.serving import make_server

DATA = Path(os.environ.get('LOGICC_CONSOLE_DATA_DIR') or ROOT / 'data').resolve()
SHARE = DATA / 'gateway' / 'share.enc'
KEY = DATA / 'account_vault' / 'account_vault.key'


def main():
    key = KEY.read_bytes().strip()
    if sys.argv[1:] == ['stop']:
        config = load_private(SHARE, key)
        config['enabled'] = False
        save_private(SHARE, key, config)
        print('Friend access revoked. The share relay and SSH tunnel will stop within a few seconds.')
        return
    if sys.argv[1:]:
        raise SystemExit('Usage: python <absolute-path>/share_gateway.py [stop]')
    if SHARE.exists():
        previous = load_private(SHARE, key)
        if previous.get('enabled') and previous.get('expires_at', 0) > time.time():
            raise SystemExit('Sharing is already enabled; revoke the old share before starting another.')
    ssh = shutil.which('ssh')
    if not ssh:
        raise SystemExit('OpenSSH client is required')
    config = {'enabled': True, 'expires_at': time.time() + 7200, 'api_key': 'sk-share-' + secrets.token_urlsafe(32)}
    save_private(SHARE, key, config)
    relay = create_share_app(lambda: load_private(SHARE, key),
        lambda: load_private(DATA / 'services' / 'model_gateway.enc', key)['api_key'])
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    server = make_server('127.0.0.1', 0, relay, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    known_hosts = DATA / 'gateway' / 'share_known_hosts'
    command = [ssh, '-F', 'none', '-T', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
        '-o', 'IdentityFile=none', '-o', 'IdentityAgent=none', '-o', 'PubkeyAuthentication=no',
        '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=' + str(known_hosts),
        '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=20', '-o', 'ServerAliveCountMax=3',
        '-o', 'ExitOnForwardFailure=yes', '-R', f'80:127.0.0.1:{server.server_port}',
        'nokey@localhost.run', '--', '--output', 'json']
    flags = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
    process = None
    published = False
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **flags)
        events = queue.Queue()
        def read_events():
            with (DATA / 'gateway' / 'share-tunnel.log').open('w', encoding='utf-8') as log:
                for line in process.stdout:
                    text = line.decode('utf-8', errors='replace')
                    log.write(text)
                    log.flush()
                    events.put(text)
        threading.Thread(target=read_events, daemon=True).start()
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline and process.poll() is None:
            try:
                line = events.get(timeout=1)
            except queue.Empty:
                continue
            # Accept only the provider's successful registration event, not banner/account URLs.
            url = tunnel_address(line)
            if not url:
                continue
            expires = datetime.fromtimestamp(config['expires_at'], ZoneInfo('Asia/Shanghai')).isoformat(timespec='seconds')
            info = DATA / 'gateway' / 'friend-connection.txt'
            info.write_text('Base URL: ' + url + '/v1\nAPI Key: ' + config['api_key'] +
                '\nModel: gpt-6.1-sol\nExpires (Asia/Shanghai): ' + expires +
                '\nLimits: 2 concurrent requests; 100 total requests including model-list reads.\n' +
                'Temporary third-party HTTPS tunnel. Do not send sensitive content.\n', encoding='utf-8')
            info.chmod(0o600)
            print(json.dumps({'base_url': url + '/v1', 'expires_at': expires, 'max_concurrency': 2,
                              'request_limit': 100, 'api_key_printed': False}), flush=True)
            published = True
            break
        if not published:
            raise RuntimeError('Temporary tunnel did not return a usable HTTPS address; no key was published.')
        while process.poll() is None:
            latest = load_private(SHARE, key)
            if latest.get('enabled') is not True or time.time() >= latest['expires_at']:
                break
            time.sleep(1)
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            if process.stdout:
                process.stdout.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        config['enabled'] = False
        save_private(SHARE, key, config)
        print('Share stopped; primary gateway and primary API key unchanged.', flush=True)


if __name__ == '__main__':
    main()
