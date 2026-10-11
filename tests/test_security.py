import base64
import json
import socket
import sys

import pytest
from pydantic import ValidationError

from farstar.core import TunnelInput, password_hash, password_matches, port_available, renew_certificate, validate_host
from cryptography import x509
from cryptography.hazmat.primitives import hashes


def test_password_storage_and_validation():
    hashed = password_hash('رمز-خیلی-طولانی-۱۲۳۴')
    assert hashed != 'رمز-خیلی-طولانی-۱۲۳۴'
    assert password_matches('رمز-خیلی-طولانی-۱۲۳۴', hashed)
    assert not password_matches('wrong', hashed)
    assert not password_matches('wrong', 'invalid')


@pytest.mark.parametrize('host', ['https://a.com', 'x;rm -rf /', 'a\n.com', 'a..com', '-invalid.com', 'x.com:8080'])
def test_rejects_invalid_host(host):
    with pytest.raises(ValueError):
        validate_host(host)


def test_occupied_port_is_never_reused():
    with socket.socket() as service:
        service.bind(('0.0.0.0', 0))
        port = service.getsockname()[1]
        assert not port_available(port)
        service.listen()
        assert not port_available(port)


@pytest.mark.skipif(sys.platform != 'linux', reason='Linux TCP TIME_WAIT behavior')
def test_stopped_tcp_port_can_restart_without_reusing_active_services():
    with socket.socket() as listener, socket.socket() as client:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
        listener.listen()
        client.connect(('127.0.0.1', port))
        accepted, _ = listener.accept()
        accepted.close()  # Active close leaves the server side in TIME_WAIT.
        assert client.recv(1) == b''
        client.close()
    assert port_available(port)
    with socket.socket() as unrelated:
        unrelated.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        unrelated.bind(('0.0.0.0', port))
        unrelated.listen()
        assert not port_available(port)
        assert unrelated.fileno() >= 0
    with socket.socket(type=socket.SOCK_DGRAM) as udp:
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp.bind(('0.0.0.0', 0))
        assert not port_available(udp.getsockname()[1], 'udp')


def test_target_is_restricted_to_local_services():
    payload = {'name': 'test', 'peer_id': 'a'*24, 'control_port': 7443,
               'mappings': [{'listen_port': 2083, 'target_host': '169.254.169.254', 'target_port': 80}]}
    with pytest.raises(ValidationError):
        TunnelInput.model_validate(payload)
    payload['mappings'][0]['target_host'] = '127.0.0.1'
    payload['mappings'][0]['listen_port'] = 22
    with pytest.raises(ValidationError):
        TunnelInput.model_validate(payload)
    payload['mappings'][0]['listen_port'] = 7443
    with pytest.raises(ValidationError):
        TunnelInput.model_validate(payload)


def test_private_api_and_csrf(admin_panel):
    client, app, root = admin_panel
    assert client.get('/api/overview').status_code == 200
    csrf = client.headers.pop('X-Farstar-CSRF')
    assert client.post('/api/invitations', json={'name': 'peer'}).status_code == 403
    client.headers['X-Farstar-CSRF'] = csrf
    assert client.post('/api/invitations', json={'name': 'peer'}, headers={'Origin': 'https://evil.example'}).status_code == 403
    assert client.post('/api/invitations', json={'name': 'peer'}, headers={'Content-Length': '70000'}).status_code == 413
    client.cookies.clear()
    assert client.get('/api/overview').status_code == 401
    assert client.get('/api/agent/desired').status_code == 401


def test_bootstrap_token_is_required_once(panel):
    client, app, root = panel
    payload = {'username': 'admin', 'password': 'long-test-password', 'bootstrap_token': 'wrong'}
    assert client.post('/api/setup', json=payload).status_code == 403
    payload['bootstrap_token'] = 'test-bootstrap-secret'
    assert client.post('/api/setup', json=payload).status_code == 200
    assert client.post('/api/setup', json=payload).status_code == 409
    assert app.state.store.get('bootstrap_hash') == ''


def test_rate_limits_login(panel):
    client, app, root = panel
    for _ in range(10):
        assert client.post('/api/login', json={'username': 'admin', 'password': 'wrong'}).status_code == 401
    assert client.post('/api/login', json={'username': 'admin', 'password': 'wrong'}).status_code == 429


def test_one_time_pairing_and_scoped_agent(admin_panel):
    client, app, root = admin_panel
    invitation = client.post('/api/invitations', json={'name': 'Destination'}).json()['invitation']
    data = json.loads(base64.urlsafe_b64decode(invitation[9:]))
    payload = {'code': data['code'], 'node_id': 'b'*24, 'name': 'Destination'}
    response = client.post('/api/agent/enroll', json=payload)
    assert response.status_code == 200
    token = response.json()['token']
    assert client.post('/api/agent/enroll', json=payload).status_code == 403
    headers = {'Authorization': 'Bearer ' + token}
    assert client.get('/api/agent/desired', headers=headers).json() == {'tunnels': []}
    public = client.get('/api/overview').json()
    assert token not in json.dumps(public)
    assert 'token_hash' not in public['peers'][0]
    assert client.delete('/api/peers/'+'b'*24).status_code == 200
    assert client.get('/api/agent/desired', headers=headers).status_code == 401


def test_expired_invitation_rejected(admin_panel):
    client, app, root = admin_panel
    code='expired-code-12345678901234567890'
    from farstar.core import digest
    app.state.store.put('invitations', [{'hash': digest(code), 'expires': 1, 'name': 'expired'}])
    assert client.post('/api/agent/enroll', json={'code': code, 'node_id': 'c'*24, 'name': 'expired'}).status_code == 403


def test_security_headers(admin_panel):
    client, app, root = admin_panel
    response = client.get('/api/overview')
    assert response.headers['Cache-Control'] == 'no-store'
    assert response.headers['X-Frame-Options'] == 'DENY'
    assert "frame-ancestors 'none'" in response.headers['Content-Security-Policy']
    assert client.get('/').status_code == 200
    assert client.get('/assets/vazirmatn.woff2').status_code == 200


def test_password_change_revokes_sessions(admin_panel):
    client, app, root = admin_panel
    assert client.post('/api/password', json={'current': 'wrong', 'password': 'new-long-test-password'}).status_code == 403
    assert client.post('/api/password', json={'current': 'test-password-very-long', 'password': 'new-long-test-password'}).status_code == 200
    assert client.get('/api/session').status_code == 401
    assert client.post('/api/login', json={'username': 'admin', 'password': 'new-long-test-password'}).status_code == 200


def test_certificate_renewal_keeps_paired_ca(panel):
    client, app, root = panel
    ca = (root / 'pki/ca.crt').read_bytes()
    old = (root / 'pki/server.crt').read_bytes()
    renew_certificate(root, '127.0.0.1')
    assert (root / 'pki/ca.crt').read_bytes() == ca
    cert = x509.load_pem_x509_certificate((root / 'pki/server.crt').read_bytes())
    assert cert.public_bytes(__import__('cryptography').hazmat.primitives.serialization.Encoding.PEM) != old


def test_settings_export_contains_no_secrets(admin_panel):
    client, app, root = admin_panel
    app.state.store.put('tunnels', [{'id': 'a'*24, 'name': 'demo', 'token': 'secret-token', 'peer_id': 'b'*24}])
    data = client.get('/api/backup').json()
    assert data['tunnels'] == [{'name': 'demo', 'peer_id': 'b'*24}]
    assert 'secret-token' not in json.dumps(data)
