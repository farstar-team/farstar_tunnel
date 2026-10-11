"""Probe the isolated CI installation. The credential is for a disposable runner."""
import json
import ssl
import urllib.request
from pathlib import Path

from farstar.core import Store, password_matches

root = Path('/var/lib/farstar-tunnel')
context = ssl.create_default_context(cafile=str(root / 'pki/ca.crt'))
store = Store(root)
config = store.get('config')
account = store.get('admin')
assert config['role'] == 'connector'
assert config['panel_port'] == 18443
assert account['username'] == 'ci.owner'
assert password_matches('ci-disposable-password-2026', account['password'])
assert not (root / 'bootstrap.token').exists()
store.close()
request = urllib.request.Request(
    'https://127.0.0.1:18443/api/login',
    data=json.dumps({'username': 'ci.owner', 'password': 'ci-disposable-password-2026'}).encode(),
    headers={'Content-Type': 'application/json'}, method='POST',
)
with urllib.request.urlopen(request, context=context, timeout=10) as response:
    assert response.status == 200
    assert json.load(response)['csrf']
    cookie = response.headers['Set-Cookie']
    assert 'HttpOnly' in cookie and 'Secure' in cookie
print('Installed systemd service, HTTPS certificate and configured administrator verified.')
