"""token-signer: issues short-lived signed tokens to internal services.

Callers are other services on the internal network. They identify themselves
with the X-Caller-Service header, which must be on the configured allow-list
(the network layer restricts who can reach this service at all).
"""
import logging
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from .config import Settings, load_settings
from .signing import RESERVED_CLAIMS, TokenSigner

log = logging.getLogger("token_signer")

settings = load_settings()
signer = TokenSigner(settings)

app = FastAPI(title="token-signer", version="1.3.0")


class SignRequest(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    audience: str = Field(min_length=1, max_length=100)
    ttl_seconds: int | None = Field(default=None, gt=0)
    claims: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "forbid"}

    @field_validator("claims")
    @classmethod
    def no_reserved_claims(cls, value: dict[str, Any]) -> dict[str, Any]:
        clash = sorted(RESERVED_CLAIMS.intersection(value))
        if clash:
            raise ValueError(f"reserved claims cannot be set by callers: {', '.join(clash)}")
        return value


class SignResponse(BaseModel):
    token: str
    token_type: str = "Bearer"
    kid: str
    expires_at: int


class KeyInfo(BaseModel):
    kid: str
    alg: str
    use: str = "sig"


class KeysResponse(BaseModel):
    issuer: str
    keys: list[KeyInfo]


def get_settings() -> Settings:
    return settings


def require_caller(
    x_caller_service: str | None = Header(default=None),
    cfg: Settings = Depends(get_settings),
) -> str:
    """Resolve the calling service from its header and check the allow-list."""
    if not x_caller_service:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing X-Caller-Service header")
    if x_caller_service not in cfg.allowed_callers:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "caller not allowed")
    return x_caller_service


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/keys", response_model=KeysResponse)
def list_keys(cfg: Settings = Depends(get_settings)) -> KeysResponse:
    """Key ids and algorithms in use. Key material is never returned."""
    return KeysResponse(issuer=cfg.issuer, keys=[KeyInfo(kid=cfg.key_id, alg=cfg.algorithm)])


@app.post("/sign", response_model=SignResponse)
def sign(
    req: SignRequest,
    caller: str = Depends(require_caller),
    cfg: Settings = Depends(get_settings),
) -> SignResponse:
    """Sign a token for `subject`, valid for `audience` only."""
    if req.audience not in cfg.allowed_audiences:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"audience not allowed: {req.audience}")

    ttl = req.ttl_seconds or cfg.default_ttl_seconds
    if ttl > cfg.max_ttl_seconds:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"ttl_seconds exceeds the maximum of {cfg.max_ttl_seconds}",
        )

    claims = signer.build_claims(req.subject, req.audience, ttl, req.claims)
    claims["azp"] = caller
    token = signer.sign(claims)
    log.info("issued token jti=%s for caller=%s aud=%s", claims["jti"], caller, req.audience)
    return SignResponse(token=token, kid=cfg.key_id, expires_at=claims["exp"])
