import os
import secrets
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from farstar.app import create_app
from farstar.core import Store, certificates, digest, free_port, password_hash


@pytest.fixture
def binaries():
    path = Path(os.getenv('FARSTAR_TEST_BIN', Path(__file__).resolve().parents[1] / 'bin'))
    return path


def initialize(root, role='hub', port=None, name='Test node'):
    certificates(root, '127.0.0.1')
    store = Store(root)
    config = {'id': secrets.token_hex(12), 'name': name, 'role': role, 'public_host': '127.0.0.1', 'panel_port': port or free_port()}
    store.put('config', config)
    store.put('bootstrap_hash', digest('test-bootstrap-secret'))
    store.close()
    return config


@pytest.fixture
def panel(tmp_path, binaries):
    initialize(tmp_path)
    app = create_app(tmp_path, binaries, secure=False, sync_interval=3600)
    with TestClient(app) as client:
        yield client, app, tmp_path


def login(client):
    response = client.post('/api/setup', json={'bootstrap_token': 'test-bootstrap-secret', 'username': 'admin', 'password': 'test-password-very-long'})
    assert response.status_code == 200
    response = client.post('/api/login', json={'username': 'admin', 'password': 'test-password-very-long'})
    assert response.status_code == 200
    client.headers['X-Farstar-CSRF'] = response.json()['csrf']


@pytest.fixture
def admin_panel(panel):
    login(panel[0])
    return panel
