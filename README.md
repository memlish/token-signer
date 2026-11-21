# token-signer

Internal service that issues short-lived signed tokens (HS256 JWTs) to other
services. A caller asks for a token for a subject and an audience; the service
fills in the registered claims, enforces the audience allow-list and the
maximum lifetime, and returns the signed token.

Callers identify themselves with the `X-Caller-Service` header, which must be
on the allow-list. The service is only reachable from the internal network.

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness check. |
| GET | `/keys` | Issuer, key ids and algorithms in use. Never returns key material. |
| POST | `/sign` | Issue a token. Requires `X-Caller-Service`. |

`POST /sign` body:

```json
{"subject": "order-42", "audience": "inventory", "ttl_seconds": 120, "claims": {"scope": "read"}}
```

`ttl_seconds` and `claims` are optional. `claims` may not set `iss`, `sub`,
`aud`, `exp`, `iat`, `nbf` or `jti`. The service adds `azp` (the calling
service). Response:

```json
{"token": "eyJ...", "token_type": "Bearer", "kid": "dev-1", "expires_at": 1767225600}
```

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `TOKEN_SIGNER_KEY` | `dev-only-change-me` | HMAC signing key. Set a real one outside development. |
| `TOKEN_SIGNER_KEY_ID` | `dev-1` | `kid` placed in the token header. |
| `TOKEN_SIGNER_ISSUER` | `token-signer.internal` | `iss` claim. |
| `TOKEN_SIGNER_ALLOWED_CALLERS` | `orders,billing,notifications` | Comma-separated caller names. |
| `TOKEN_SIGNER_ALLOWED_AUDIENCES` | `inventory,payments,mailer` | Comma-separated audiences. |
| `TOKEN_SIGNER_DEFAULT_TTL` | `300` | Lifetime in seconds when the caller gives none. |
| `TOKEN_SIGNER_MAX_TTL` | `900` | Longest lifetime a caller may ask for. |

## Running

```sh
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
PYTHONPATH=src .venv/bin/uvicorn token_signer.app:app --port 8080
```

## Tests

```sh
.venv/bin/python -m pytest tests/ -q
```
