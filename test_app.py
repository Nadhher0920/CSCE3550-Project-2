"""Project 2 endpoint, persistence, and security tests."""
import sqlite3

import jwt
import pytest

import keys
from app import app


@pytest.fixture
def client():
    return app.test_client()


def test_database_schema():
    with sqlite3.connect(keys.DB_PATH) as db:
        columns = {row[1] for row in db.execute('PRAGMA table_info(keys)')}
        assert columns == {'kid', 'key', 'exp'}


def test_database_has_valid_and_expired_keys():
    assert keys.get_key() is not None
    assert keys.get_key(expired=True) is not None


def test_keys_survive_initialization():
    kid = keys.get_key()['kid']
    keys.initialize_keys()
    assert keys.get_key()['kid'] == kid


def test_jwks(client):
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    items = response.get_json()['keys']
    assert items
    assert all(item['kty'] == 'RSA' and item['alg'] == 'RS256' for item in items)
    assert keys.get_key()['kid'] in {item['kid'] for item in items}
    assert keys.get_key(expired=True)['kid'] not in {item['kid'] for item in items}


def test_valid_token(client):
    response = client.post('/auth', json={'username': 'userABC', 'password': 'password123'})
    assert response.status_code == 200
    token = response.get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    selected = keys.get_key()
    assert header['kid'] == selected['kid']
    assert jwt.decode(token, selected['public_key'], algorithms=['RS256'])['sub'] == 'fake-user'


def test_expired_token(client):
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    token = response.get_data(as_text=True)
    assert jwt.get_unverified_header(token)['kid'] == keys.get_key(expired=True)['kid']
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, keys.get_key(expired=True)['public_key'], algorithms=['RS256'])


def test_methods_and_missing_page(client):
    assert client.get('/auth').status_code == 405
    assert client.post('/.well-known/jwks.json').status_code == 405
    assert client.get('/missing').status_code == 404


def test_missing_signing_key(client, monkeypatch):
    monkeypatch.setattr(keys, 'get_key', lambda expired=False: None)
    assert client.post('/auth').status_code == 503


def test_jwk_conversion():
    selected = keys.get_key()
    jwk = keys.public_key_to_jwk(selected)
    assert jwk['kid'] == selected['kid']
    assert jwk['n'] and jwk['e']
