"""Persistent RSA keys for the JWKS service."""
import base64
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DB_PATH = os.environ.get('JWKS_DB_PATH', 'totally_not_my_privateKeys.db')


def connect():
    return sqlite3.connect(DB_PATH)


def initialize_keys():
    """Create the database and ensure one valid and one expired key exist."""
    with connect() as db:
        db.execute('''CREATE TABLE IF NOT EXISTS keys (
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )''')
        now = int(datetime.now(timezone.utc).timestamp())
        for sql, parameters, expiry in (
            ('SELECT kid FROM keys WHERE exp > ? LIMIT 1', (now,), now + 3600),
            ('SELECT kid FROM keys WHERE exp <= ? LIMIT 1', (now,), now - 3600),
        ):
            if db.execute(sql, parameters).fetchone() is None:
                private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                db.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (pem, expiry))


def get_key(expired=False):
    """Select an RSA key from SQLite using a parameterized query."""
    now = int(datetime.now(timezone.utc).timestamp())
    predicate = 'exp <= ?' if expired else 'exp > ?'
    with connect() as db:
        row = db.execute(
            f'SELECT kid, key, exp FROM keys WHERE {predicate} ORDER BY exp DESC LIMIT 1',
            (now,),
        ).fetchone()
    if row is None:
        return None
    kid, pem, exp = row
    private_key = serialization.load_pem_private_key(pem, password=None)
    return {'kid': str(kid), 'private_key': private_key,
            'public_key': private_key.public_key(), 'expires_at': exp, 'pem': pem}


def base64url_uint(value):
    byte_length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(byte_length, 'big')).rstrip(b'=').decode('ascii')


def public_key_to_jwk(key_data):
    numbers = key_data['public_key'].public_numbers()
    return {'kty': 'RSA', 'use': 'sig', 'kid': key_data['kid'], 'alg': 'RS256',
            'n': base64url_uint(numbers.n), 'e': base64url_uint(numbers.e)}


def get_valid_jwks():
    now = int(datetime.now(timezone.utc).timestamp())
    with connect() as db:
        rows = db.execute('SELECT kid, key FROM keys WHERE exp > ?', (now,)).fetchall()
    result = []
    for kid, pem in rows:
        private_key = serialization.load_pem_private_key(pem, password=None)
        result.append(public_key_to_jwk({'kid': str(kid), 'public_key': private_key.public_key()}))
    return {'keys': result}


def get_private_key_pem(key_data):
    return key_data['pem']


initialize_keys()
