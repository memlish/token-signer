"""Settings, read from the environment once at startup.

Every value has a development default so the service and its tests run
without any setup. Override them in each deployed environment.
"""
import os
from dataclasses import dataclass, field


def _csv(name: str, default: str) -> tuple[str, ...]:
    raw = os.environ.get(name, default)
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw else default


@dataclass(frozen=True)
class Settings:
    # HMAC key used to sign tokens. The default is for local development only.
    signing_key: bytes = field(
        default_factory=lambda: os.environ.get("TOKEN_SIGNER_KEY", "dev-only-change-me").encode()
    )
    key_id: str = field(default_factory=lambda: os.environ.get("TOKEN_SIGNER_KEY_ID", "dev-1"))
    algorithm: str = "HS256"
    issuer: str = field(
        default_factory=lambda: os.environ.get("TOKEN_SIGNER_ISSUER", "token-signer.internal")
    )
    # Services allowed to request tokens, matched against the X-Caller-Service header.
    allowed_callers: tuple[str, ...] = field(
        default_factory=lambda: _csv("TOKEN_SIGNER_ALLOWED_CALLERS", "orders,billing,notifications")
    )
    # Audiences a token may be issued for.
    allowed_audiences: tuple[str, ...] = field(
        default_factory=lambda: _csv("TOKEN_SIGNER_ALLOWED_AUDIENCES", "inventory,payments,mailer")
    )
    default_ttl_seconds: int = field(default_factory=lambda: _int("TOKEN_SIGNER_DEFAULT_TTL", 300))
    max_ttl_seconds: int = field(default_factory=lambda: _int("TOKEN_SIGNER_MAX_TTL", 900))


def load_settings() -> Settings:
    return Settings()
