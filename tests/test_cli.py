"""Exercise real CLI credential input and persistent panel configuration."""
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from farstar.app import create_app
from farstar.core import Store, free_port, password_hash, password_matches


PASSWORD = 'installer-test-password-2026'


def command(root, *arguments, password=None):
    return subprocess.run(
        [sys.executable, '-m', 'farstar.cli', '--data-dir', str(root), *arguments],
        input=password, capture_output=True, text=True, timeout=30,
    )


@pytest.fixture
def configured(tmp_path):
    store = Store(tmp_path)
    store.put('config', {'id': 'c' * 24, 'name': 'CLI test', 'role': 'hub',
                         'public_host': '127.0.0.1', 'panel_port': free_port()})
    store.put('admin', {'username': 'admin', 'password': password_hash(PASSWORD)})
    with store.db:
        store.db.execute('INSERT INTO sessions VALUES (?,?,?)', ('old-session', 'csrf', 9999999999))
    store.close()
    return tmp_path


def test_install_account_can_sign_in_without_web_setup(tmp_path, binaries):
    port = free_port()
    result = command(tmp_path, 'init', '--role', 'hub', '--host', '127.0.0.1', '--port', str(port),
                     '--username', 'owner.user', '--password-stdin', password=PASSWORD + '\n')
    assert result.returncode == 0, result.stderr
    assert PASSWORD not in result.stdout + result.stderr
    assert not (tmp_path / 'bootstrap.token').exists()
    store = Store(tmp_path)
    assert store.get('config')['panel_port'] == port
    assert store.get('bootstrap_hash') == ''
    assert password_matches(PASSWORD, store.get('admin')['password'])
    assert PASSWORD not in (tmp_path / 'state.db').read_bytes().decode(errors='ignore')
    store.close()
    with TestClient(create_app(tmp_path, binaries, secure=False)) as client:
        assert client.post('/api/login', json={'username': 'owner.user', 'password': PASSWORD}).status_code == 200
        assert client.post('/api/setup', json={'username': 'other', 'password': PASSWORD,
                                             'bootstrap_token': 'anything'}).status_code == 409


@pytest.mark.parametrize('username,password', [
    ('bad username', PASSWORD), ('a', PASSWORD), ('admin', 'short'),
    ('admin', 'a' * 129), ('admin', 'a' * 12 + '\x00'),
])
def test_invalid_install_credentials_do_not_initialize(tmp_path, username, password):
    result = command(tmp_path, 'init', '--role', 'connector', '--host', '127.0.0.1',
                     '--username', username, '--password-stdin', password=password + '\n')
    assert result.returncode != 0
    store = Store(tmp_path)
    assert store.get('config') is None
    assert store.get('admin') is None
    assert not (tmp_path / 'pki').exists()
    store.close()


def test_change_credentials_revokes_sessions_and_accepts_new_login(configured, binaries):
    new_password = 'a-different-test-password'
    result = command(configured, 'configure-panel', '--username', 'new.owner', '--password-stdin',
                     password=new_password + '\n')
    assert result.returncode == 0, result.stderr
    assert new_password not in result.stdout + result.stderr
    store = Store(configured)
    assert store.db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0] == 0
    assert password_matches(new_password, store.get('admin')['password'])
    store.close()
    with TestClient(create_app(configured, binaries, secure=False)) as client:
        assert client.post('/api/login', json={'username': 'admin', 'password': PASSWORD}).status_code == 401
        assert client.post('/api/login', json={'username': 'new.owner', 'password': new_password}).status_code == 200


def test_port_change_preserves_account_and_sessions(configured):
    port = free_port()
    result = command(configured, 'configure-panel', '--port', str(port))
    assert result.returncode == 0, result.stderr
    store = Store(configured)
    assert store.get('config')['panel_port'] == port
    assert store.get('admin')['username'] == 'admin'
    assert store.db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0] == 1
    store.close()


def test_busy_port_does_not_modify_any_settings(configured):
    import socket
    with socket.socket() as listener:
        listener.bind(('0.0.0.0', 0))
        listener.listen()
        result = command(configured, 'configure-panel', '--port', str(listener.getsockname()[1]), '--username', 'changed')
    assert result.returncode != 0
    store = Store(configured)
    assert store.get('admin')['username'] == 'admin'
    assert store.db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0] == 1
    store.close()


def test_invalid_username_keeps_requested_port_unchanged(configured):
    store = Store(configured)
    previous = store.get('config')['panel_port']
    store.close()
    result = command(configured, 'configure-panel', '--port', str(free_port()), '--username', 'bad user')
    assert result.returncode != 0
    store = Store(configured)
    assert store.get('config')['panel_port'] == previous
    assert store.db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0] == 1
    store.close()


def test_disabled_tunnel_port_remains_reserved(configured):
    port = free_port()
    store = Store(configured)
    store.put('tunnels', [{'control_port': port, 'mappings': [], 'enabled': False}])
    old_port = store.get('config')['panel_port']
    store.close()
    result = command(configured, 'configure-panel', '--port', str(port))
    assert result.returncode != 0
    store = Store(configured)
    assert store.get('config')['panel_port'] == old_port
    store.close()


def test_upstream_port_change_preserves_pairing_and_tunnels(configured):
    store = Store(configured)
    config = store.get('config') | {'role': 'connector'}
    upstream = {'url': 'https://[2001:db8::10]:8443', 'token': 'test-pairing-token', 'host': '2001:db8::10', 'name': 'hub'}
    tunnels = [{'id': 'test-persisted-tunnel'}]
    store.put('config', config)
    store.put('upstream', upstream)
    store.put('received', tunnels)
    store.close()
    result = command(configured, 'configure-upstream', '--port', '9443')
    assert result.returncode == 0, result.stderr
    store = Store(configured)
    assert store.get('upstream') == upstream | {'url': 'https://[2001:db8::10]:9443'}
    assert store.get('received') == tunnels
    assert store.get('config') == config
    store.close()
