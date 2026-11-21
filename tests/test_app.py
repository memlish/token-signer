import base64
import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from token_signer.app import app, settings

client = TestClient(app)
CALLER = {"X-Caller-Service": "orders"}


def _b64decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _split(token: str) -> tuple[dict, dict, bytes, bytes]:
    header, payload, sig = token.split(".")
    signing_input = f"{header}.{payload}".encode()
    return json.loads(_b64decode(header)), json.loads(_b64decode(payload)), signing_input, _b64decode(sig)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_keys_lists_ids_without_material():
    r = client.get("/keys")
    assert r.status_code == 200
    body = r.json()
    assert body["keys"] == [{"kid": settings.key_id, "alg": "HS256", "use": "sig"}]
    assert settings.signing_key.decode() not in r.text


def test_sign_produces_valid_hmac():
    r = client.post("/sign", headers=CALLER, json={"subject": "order-42", "audience": "inventory"})
    assert r.status_code == 200
    token = r.json()["token"]
    header, claims, signing_input, sig = _split(token)
    expected = hmac.new(settings.signing_key, signing_input, hashlib.sha256).digest()
    assert hmac.compare_digest(sig, expected)
    assert header == {"alg": "HS256", "typ": "JWT", "kid": settings.key_id}
    assert claims["sub"] == "order-42"
    assert claims["aud"] == "inventory"
    assert claims["iss"] == settings.issuer
    assert claims["azp"] == "orders"
    assert claims["exp"] - claims["iat"] == settings.default_ttl_seconds


def test_extra_claims_are_included():
    r = client.post(
        "/sign",
        headers=CALLER,
        json={"subject": "u1", "audience": "mailer", "ttl_seconds": 60, "claims": {"scope": "send"}},
    )
    assert r.status_code == 200
    _, claims, _, _ = _split(r.json()["token"])
    assert claims["scope"] == "send"
    assert claims["exp"] - claims["iat"] == 60


def test_unknown_caller_rejected():
    body = {"subject": "u1", "audience": "inventory"}
    assert client.post("/sign", json=body).status_code == 401
    assert client.post("/sign", headers={"X-Caller-Service": "intruder"}, json=body).status_code == 403


def test_audience_must_be_allowed():
    r = client.post("/sign", headers=CALLER, json={"subject": "u1", "audience": "elsewhere"})
    assert r.status_code == 400


def test_ttl_capped():
    r = client.post(
        "/sign",
        headers=CALLER,
        json={"subject": "u1", "audience": "inventory", "ttl_seconds": settings.max_ttl_seconds + 1},
    )
    assert r.status_code == 400


def test_reserved_claims_rejected():
    r = client.post(
        "/sign",
        headers=CALLER,
        json={"subject": "u1", "audience": "inventory", "claims": {"sub": "someone-else"}},
    )
    assert r.status_code == 422
