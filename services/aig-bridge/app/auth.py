"""Authentication and request-context helpers for the AIG bridge.

The bridge is an internal sidecar, but it still sits on a network boundary in
customer deployments.  Scan endpoints therefore fail closed when production
authentication is enabled.  Liveness remains unauthenticated so orchestrators
can determine whether the process is alive without learning anything about the
upstream AIG service.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Optional

from fastapi import Depends, Header, HTTPException, Request, status


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SCOPE_RE = re.compile(r"^[A-Za-z0-9:_./-]{1,128}$")


def auth_mode() -> str:
    """Return the configured inbound authentication mode.

    ``broker`` is the only production-safe mode.  ``api_key`` is retained as
    an explicitly opt-in compatibility mode for a local, private sidecar; it
    must never be used as a tenant identity.  ``disabled`` is only suitable
    for an isolated developer process and makes readiness fail when auth is
    required.
    """

    configured = os.getenv("BRIDGE_AUTH_MODE", "broker").strip().lower()
    return configured if configured in {"broker", "api_key", "disabled"} else "broker"


def auth_is_configured() -> bool:
    """Return whether the selected authentication mode has its key material."""

    if not auth_is_required():
        return True
    mode = auth_mode()
    if mode == "disabled":
        return False
    if mode == "api_key":
        return bool(os.getenv("BRIDGE_API_KEY", "").strip())
    return _broker_auth_config() is not None


def auth_is_required() -> bool:
    """Return whether inbound authentication is required for this process."""

    return _env_bool("BRIDGE_AUTH_REQUIRED", True)


def ha_is_required() -> bool:
    return _env_bool("BRIDGE_HA_REQUIRED", True)


def tenant_is_required() -> bool:
    """Return whether callers must send an explicit tenant identifier."""

    return _env_bool("BRIDGE_TENANT_REQUIRED", True)


def _provided_api_key(request: Request) -> str:
    api_key = request.headers.get("x-api-key", "").strip()
    if api_key:
        return api_key
    authorization = request.headers.get("authorization", "")
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() == "bearer":
        return value.strip()
    return ""


def _b64url_decode(value: str) -> bytes:
    if not value or len(value) > 16_384:
        raise ValueError("invalid JWT segment")
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _parse_scopes(value: Any) -> frozenset[str]:
    if isinstance(value, str):
        values = value.split()
    elif isinstance(value, list):
        values = value
    else:
        values = []
    scopes = {str(item).strip() for item in values if str(item).strip()}
    if any(not _SCOPE_RE.fullmatch(scope) for scope in scopes):
        raise ValueError("invalid scope claim")
    return frozenset(scopes)


def _broker_auth_config() -> tuple[bytes, str, str] | None:
    secret = os.getenv("BRIDGE_JWT_SECRET", "").strip().encode("utf-8")
    issuer = os.getenv("BRIDGE_JWT_ISSUER", "").strip()
    audience = os.getenv("BRIDGE_JWT_AUDIENCE", "").strip()
    if len(secret) < 32 or not issuer or not audience:
        return None
    return secret, issuer, audience


@dataclass(frozen=True)
class BrokerClaims:
    """Verified, short-lived broker identity used for every scan request."""

    subject: str
    tenant_id: str
    scopes: frozenset[str]
    job_id: Optional[str]
    jti: str
    expires_at: int
    claims: dict[str, Any]


class ReplayStoreUnavailable(RuntimeError):
    """The configured replay store cannot make a safe atomic decision."""


class ReplayStore:
    """Replay cache with single-host SQLite or shared PostgreSQL persistence.

    Multi-replica deployments must use the shared PostgreSQL table; a durable
    local SQLite file is not shared between replicas and cannot prevent replay.
    """

    def __init__(
        self,
        path: Optional[str] = None,
        *,
        postgres_dsn: Optional[str] = None,
        postgres_connect: Optional[Callable[[], Any]] = None,
    ):
        self.path = (path or "").strip()
        self.postgres_dsn = (postgres_dsn or "").strip()
        self._postgres_connect_override = postgres_connect
        self._memory: dict[str, int] = {}
        self._lock = Lock()
        if self.postgres_dsn:
            # Do not silently fall back to a per-replica SQLite store when the
            # shared database is unavailable.
            self.path = ""
        elif self.path:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(self.path) as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS bridge_jwt_replay "
                    "(jti TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)"
                )

    def readiness(self) -> tuple[bool, str]:
        if not self.postgres_dsn and self._postgres_connect_override is None:
            return False, "shared postgres JWT replay store is not configured"
        try:
            with self._connect_postgres() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT has_table_privilege(current_user, "
                        "'public.aig_bridge_jwt_replay', 'SELECT,INSERT,DELETE')"
                    )
                    row = cursor.fetchone()
                    if row is None or not bool(row[0]):
                        return False, "postgres JWT replay role lacks required privileges"
                    cursor.execute("SELECT 1 FROM public.aig_bridge_jwt_replay LIMIT 1")
            return True, "shared postgres JWT replay store"
        except Exception:
            return False, "postgres JWT replay store is unavailable or not migrated"

    def _connect_postgres(self) -> Any:
        if self._postgres_connect_override is not None:
            return self._postgres_connect_override()
        import psycopg

        return psycopg.connect(self.postgres_dsn, connect_timeout=3)

    def _consume_postgres(self, jti: str, expires_at: int, now: int) -> bool:
        try:
            with self._connect_postgres() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM public.aig_bridge_jwt_replay WHERE expires_at <= %s",
                        (now,),
                    )
                    cursor.execute(
                        "INSERT INTO public.aig_bridge_jwt_replay (jti, expires_at) "
                        "VALUES (%s, %s) ON CONFLICT (jti) DO NOTHING RETURNING jti",
                        (jti, expires_at),
                    )
                    return cursor.fetchone() is not None
        except Exception as exc:
            raise ReplayStoreUnavailable("shared JWT replay store is unavailable") from exc

    def consume(self, jti: str, expires_at: int) -> bool:
        now = int(time.time())
        with self._lock:
            if self.postgres_dsn or self._postgres_connect_override is not None:
                return self._consume_postgres(jti, expires_at, now)
            if ha_is_required():
                raise ReplayStoreUnavailable("shared JWT replay store is not configured")
            if self.path:
                try:
                    with sqlite3.connect(self.path, timeout=5) as connection:
                        connection.execute(
                            "DELETE FROM bridge_jwt_replay WHERE expires_at <= ?", (now,)
                        )
                        connection.execute(
                            "INSERT INTO bridge_jwt_replay(jti, expires_at) VALUES (?, ?)",
                            (jti, expires_at),
                        )
                    return True
                except sqlite3.IntegrityError:
                    return False
                except sqlite3.Error as exc:
                    raise ReplayStoreUnavailable("local JWT replay store is unavailable") from exc
            self._memory = {key: value for key, value in self._memory.items() if value > now}
            if jti in self._memory:
                return False
            self._memory[jti] = expires_at
            return True


_replay_store = ReplayStore(
    os.getenv("BRIDGE_JWT_REPLAY_DB", ""),
    postgres_dsn=os.getenv("BRIDGE_TASK_POSTGRES_DSN", ""),
)


def replay_store_ready() -> bool:
    return not ha_is_required() or _replay_store.readiness()[0]


def _verify_broker_token(request: Request) -> BrokerClaims:
    config = _broker_auth_config()
    if config is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="broker authentication is not configured")
    secret, issuer, audience = config
    authorization = request.headers.get("authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="broker bearer token required")
    try:
        header_raw, payload_raw, signature_raw = token.strip().split(".")
        header = json.loads(_b64url_decode(header_raw))
        payload_bytes = _b64url_decode(payload_raw)
        signature = _b64url_decode(signature_raw)
        if not isinstance(header, dict) or header.get("alg") != "HS256" or header.get("typ", "JWT") != "JWT":
            raise ValueError("unsupported JWT algorithm")
        signed = f"{header_raw}.{payload_raw}".encode("ascii")
        expected = hmac.new(secret, signed, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("invalid JWT signature")
        payload = json.loads(payload_bytes)
        if not isinstance(payload, dict):
            raise ValueError("invalid JWT payload")
        now = int(time.time())
        skew = int(os.getenv("BRIDGE_JWT_CLOCK_SKEW_SECONDS", "30"))
        exp = int(payload.get("exp"))
        if exp <= now - skew or exp > now + 86_400:
            raise ValueError("invalid JWT expiry")
        if "nbf" in payload and int(payload["nbf"]) > now + skew:
            raise ValueError("token is not active")
        if payload.get("iss") != issuer:
            raise ValueError("invalid JWT issuer")
        actual_aud = payload.get("aud")
        audiences = actual_aud if isinstance(actual_aud, list) else [actual_aud]
        if audience not in audiences:
            raise ValueError("invalid JWT audience")
        subject = str(payload.get("sub") or "").strip()
        tenant_id = str(payload.get("tenant_id") or payload.get("tid") or "").strip()
        jti = str(payload.get("jti") or "").strip()
        if not subject or len(subject) > 256 or not _TENANT_RE.fullmatch(tenant_id) or not jti or len(jti) > 256:
            raise ValueError("JWT is missing subject, tenant or jti")
        scopes = _parse_scopes(payload.get("scope", payload.get("scopes", [])))
        job_id = payload.get("job_id") or payload.get("jobId")
        if job_id is not None and not _TENANT_RE.fullmatch(str(job_id)):
            raise ValueError("invalid job_id claim")
        if not _replay_store.consume(jti, exp + max(0, skew)):
            raise ValueError("JWT replay detected")
        return BrokerClaims(subject, tenant_id, scopes, str(job_id) if job_id else None, jti, exp, payload)
    except ReplayStoreUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="broker replay protection is unavailable",
        ) from exc
    except (ValueError, TypeError, KeyError, RecursionError, json.JSONDecodeError, UnicodeError, binascii.Error) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid broker token") from exc


async def require_bridge_api_key(request: Request) -> BrokerClaims | None:
    """FastAPI dependency enforcing broker identity (or explicit dev key).

    A missing key is a service-configuration error (503), not a client auth
    failure (401).  This makes an accidentally public production bridge fail
    closed and visible in readiness checks instead of appearing healthy.
    """

    if not auth_is_required():
        return None
    mode = auth_mode()
    if mode == "disabled":
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="bridge authentication is not configured")
    if mode == "broker":
        return _verify_broker_token(request)
    configured = os.getenv("BRIDGE_API_KEY", "").strip()
    if not configured:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="bridge authentication is not configured")
    provided = _provided_api_key(request)
    if not provided or not hmac.compare_digest(provided, configured):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid bridge API key", headers={"WWW-Authenticate": "Bearer"})
    return None


@dataclass(frozen=True)
class RequestContext:
    """Authenticated tenant context associated with a bridge request."""

    tenant_id: str
    idempotency_key: Optional[str]
    subject: str = "local"
    scopes: frozenset[str] = frozenset()
    job_id: Optional[str] = None
    jti: Optional[str] = None


async def get_request_context(
    request: Request,
    _auth: BrokerClaims | None = Depends(require_bridge_api_key),
    tenant_header: Optional[str] = Header(default=None, alias="X-AIDR-Tenant-ID"),
) -> RequestContext:
    """Resolve the tenant and idempotency key for a request.

    The tenant is deliberately carried in a header rather than accepted from
    the JSON body so clients cannot accidentally submit work for another
    tenant while reusing a payload.  Local development may opt out with
    ``BRIDGE_TENANT_REQUIRED=false``; the fallback tenant is never used when
    the production compose file enables the requirement.
    """

    if _auth is not None:
        required_scope = "aig:read" if request.method.upper() in {"GET", "HEAD"} else "aig:scan"
        if required_scope not in _auth.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"{required_scope} scope is required",
            )

    claim_tenant = _auth.tenant_id if _auth is not None else ""
    tenant_id = (tenant_header or "").strip()
    if claim_tenant:
        if tenant_id and tenant_id != claim_tenant:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant header does not match broker claim")
        tenant_id = claim_tenant
    elif not tenant_id:
        if tenant_is_required():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="X-AIDR-Tenant-ID header is required")
        tenant_id = "local"
    if not _TENANT_RE.fullmatch(tenant_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid tenant identifier",
        )

    idempotency_key = request.headers.get("idempotency-key", "").strip() or None
    if idempotency_key and len(idempotency_key) > 256:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="idempotency key is too long",
        )
    return RequestContext(
        tenant_id=tenant_id,
        idempotency_key=idempotency_key,
        subject=_auth.subject if _auth is not None else "local",
        scopes=_auth.scopes if _auth is not None else frozenset(),
        job_id=_auth.job_id if _auth is not None else None,
        jti=_auth.jti if _auth is not None else None,
    )
