"""Flask JWT signing service backed by SQLite."""
from datetime import datetime, timedelta, timezone

import jwt
from flask import Flask, jsonify, request

import keys

app = Flask(__name__)


@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    return jsonify(keys.get_valid_jwks()), 200


@app.route('/auth', methods=['POST'])
def auth():
    expired_requested = 'expired' in request.args
    selected_key = keys.get_key(expired=expired_requested)
    if selected_key is None:
        return jsonify({'error': 'No matching signing key available'}), 503

    now = datetime.now(timezone.utc)
    expiration = now - timedelta(hours=1) if expired_requested else now + timedelta(hours=1)
    payload = {'sub': 'fake-user', 'iat': now, 'exp': expiration}
    token = jwt.encode(payload, keys.get_private_key_pem(selected_key),
                       algorithm='RS256', headers={'kid': selected_key['kid'], 'typ': 'JWT'})
    return token, 200, {'Content-Type': 'text/plain'}


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not Found'}), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
