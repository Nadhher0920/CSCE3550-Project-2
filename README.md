# CSCE 3550 Project 2 — SQLite-backed JWKS Server

Flask JWKS server with RSA signing keys persisted in `totally_not_my_privateKeys.db`.

## Setup

```bash
python3 -m pip install -r requirements.txt
python3 app.py
```

## Tests

```bash
python3 -m pytest -q tests/ --cov=app --cov=keys --cov-report=term-missing
```

## API

- `POST /auth` signs a valid RS256 JWT.
- `POST /auth?expired=true` signs an expired RS256 JWT.
- `GET /.well-known/jwks.json` publishes only unexpired public keys.

The database is created in the current working directory on first import. Keep it private; do not commit it to GitHub. The project intentionally uses mock authentication, as specified in the assignment.
