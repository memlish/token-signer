"""Token construction and signing."""
import json
import time
import uuid

from authlib.jose import JsonWebSignature

from .config import Settings

# Registered claims the service always sets itself; callers may not override them.
RESERVED_CLAIMS = frozenset({"iss", "sub", "aud", "exp", "iat", "nbf", "jti"})


class TokenSigner:
    """Builds a claim set and signs it as a compact JWS."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._jws = JsonWebSignature(algorithms=[settings.algorithm])

    def build_claims(self, subject: str, audience: str, ttl: int, extra: dict) -> dict:
        now = int(time.time())
        claims = dict(extra)
        claims.update(
            {
                "iss": self._settings.issuer,
                "sub": subject,
                "aud": audience,
                "iat": now,
                "nbf": now,
                "exp": now + ttl,
                "jti": uuid.uuid4().hex,
            }
        )
        return claims

    def sign(self, claims: dict) -> str:
        header = {
            "alg": self._settings.algorithm,
            "typ": "JWT",
            "kid": self._settings.key_id,
        }
        payload = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode()
        token = self._jws.serialize_compact(header, payload, self._settings.signing_key)
        return token.decode("ascii")
