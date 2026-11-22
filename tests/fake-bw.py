#!/usr/bin/python3
"""Only synthetic data. Log command names/arguments, never environment values."""
import json
import os
from pathlib import Path
import sys
root = Path(os.environ['BW_TEST_ROOT'])
args = sys.argv[1:]
with (root / 'calls').open('a') as log:
    log.write(json.dumps(args) + '\n')
mode = (root / 'mode').read_text().strip() if (root / 'mode').exists() else ''
new_profile = mode == 'logged-out' and not (root / 'login-complete').exists()
if args[0] == 'sync':
    if mode == 'offline':
        print('test network unavailable', file=sys.stderr)
        sys.exit(1)
    (root / 'synced').touch()
elif args[0] == 'status':
    if new_profile:
        configured = root / 'configured-server'
        print(json.dumps({'status': 'unauthenticated', 'serverUrl': configured.read_text() if configured.exists() else None}))
        sys.exit(0)
    print(json.dumps({'status': 'unlocked' if os.environ.get('BW_SESSION') == 'fixture-session' and mode != 'revoked' else 'locked', 'serverUrl': 'https://test.invalid', 'userEmail': 'test@example.invalid'}))
elif args[0] == 'unlock':
    assert args == ['unlock', '--raw', '--passwordenv', 'BW_PASSWORD']
    if os.environ.get('BW_PASSWORD') != 'fixture-master-password':
        print('synthetic incorrect password', file=sys.stderr)
        sys.exit(1)
    assert (root / 'synced').exists(), 'sync must precede unlock'
    print('fixture-session')
elif args[0] == 'login':
    assert args == ['login', 'test@example.invalid', '--raw', '--passwordenv', 'BW_PASSWORD']
    assert os.environ.get('BW_PASSWORD') == 'fixture-master-password'
    assert (root / 'configured-server').read_text() == 'https://test.invalid'
    (root / 'login-complete').touch()
    print('fixture-session')
elif args[:2] == ['list', 'items']:
    assert os.environ.get('BW_SESSION') == 'fixture-session'
    if mode == 'late-list-error' and args[-1] == 'beta':
        print('synthetic late provider error', file=sys.stderr)
        sys.exit(1)
    if mode == 'slow-list':
        import time
        (root / 'list-started').touch()
        deadline=time.monotonic()+20
        while not (root/'list-release').exists() and time.monotonic()<deadline: time.sleep(.05)
    if (root / 'records.json').exists():
        print((root / 'records.json').read_text())
    elif mode == 'missing-item':
        print('[]')
    else:
        fields = [] if mode == 'missing-field' else [{'name': 'token', 'value': 'fixture-token'}]
        item = {'name': 'test-app', 'fields': fields}
        print(json.dumps([item, item] if mode == 'duplicate' else [item]))
elif args[0] == '--version':
    print('test')
elif args[:2] == ['config', 'server']:
    (root / 'configured-server').write_text(args[2])
else:
    sys.exit(1)
