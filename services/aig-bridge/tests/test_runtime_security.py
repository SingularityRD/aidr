"""Runtime hardening tests for broker auth, bounded results and task state."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import time
import zipfile

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app import auth
from app.incidents import build_incident_candidates
from app.result_adapter import adapt_infra_result
from app.redaction import bounded_redacted, redact_url
from app.task_registry import QuotaExceeded, TaskRegistry
from app.uploads import store_upload, validate_archive


def _jwt(secret: str, payload: dict[str, object]) -> str:
    def enc(value: object) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    head = enc({"alg": "HS256", "typ": "JWT"})
    body = enc(payload)
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"


def _request(headers: dict[str, str]) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/scan/infra",
            "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
            "query_string": b"",
            "scheme": "https",
            "server": ("test", 443),
            "client": ("test", 1),
        }
    )


def test_broker_claim_binds_tenant_and_rejects_replay(monkeypatch):
    secret = "unit-test-broker-secret-at-least-32-bytes"
    monkeypatch.setenv("BRIDGE_JWT_SECRET", secret)
    monkeypatch.setenv("BRIDGE_AUTH_MODE", "broker")
    monkeypatch.setenv("BRIDGE_JWT_ISSUER", "https://broker.example.test")
    monkeypatch.setenv("BRIDGE_JWT_AUDIENCE", "aidr-aig-bridge")
    monkeypatch.setattr(auth, "_replay_store", auth.ReplayStore())
    payload = {
        "sub": "broker-worker",
        "tenant_id": "tenant-a",
        "scope": "aig:scan aig:read",
        "iss": "https://broker.example.test",
        "aud": "aidr-aig-bridge",
        "jti": "runtime-test-jti",
        "exp": int(time.time()) + 120,
    }
    token = _jwt(secret, payload)
    claims = auth._verify_broker_token(_request({"Authorization": f"Bearer {token}"}))
    assert claims.tenant_id == "tenant-a"
    assert "aig:scan" in claims.scopes
    with pytest.raises(HTTPException) as replay:
        auth._verify_broker_token(_request({"Authorization": f"Bearer {token}"}))
    assert replay.value.status_code == 401


def test_broker_tenant_header_mismatch_is_forbidden(monkeypatch):
    secret = "unit-test-broker-secret-at-least-32-bytes"
    monkeypatch.setenv("BRIDGE_JWT_SECRET", secret)
    monkeypatch.setenv("BRIDGE_JWT_ISSUER", "https://broker.example.test")
    monkeypatch.setenv("BRIDGE_JWT_AUDIENCE", "aidr-aig-bridge")
    monkeypatch.setattr(auth, "_replay_store", auth.ReplayStore())
    payload = {
        "sub": "broker-worker",
        "tenant_id": "tenant-a",
        "iss": "https://broker.example.test",
        "aud": "aidr-aig-bridge",
        "jti": "runtime-test-jti-2",
        "exp": int(time.time()) + 120,
    }
    token = _jwt(secret, payload)
    claims = auth._verify_broker_token(_request({"Authorization": f"Bearer {token}"}))
    with pytest.raises(HTTPException) as mismatch:
        import asyncio

        asyncio.run(
            auth.get_request_context(
                _request(
                    {
                        "Authorization": f"Bearer {token}",
                        "X-AIDR-Tenant-ID": "tenant-b",
                    }
                ),
                claims,
                "tenant-b",
            )
        )
    assert mismatch.value.status_code == 403


def test_multi_replica_replay_store_uses_shared_postgres_and_atomic_insert(monkeypatch, tmp_path):
    monkeypatch.setenv("BRIDGE_HA_REQUIRED", "true")
    sqlite_store = auth.ReplayStore(str(tmp_path / "replay.db"))
    monkeypatch.setattr(auth, "_replay_store", sqlite_store)
    assert not auth.replay_store_ready()

    class Cursor:
        def __init__(self, seen):
            self.seen = seen
            self.row = None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, params=()):
            if "has_table_privilege" in query:
                self.row = (True,)
            elif "INSERT INTO public.aig_bridge_jwt_replay" in query:
                jti = params[0]
                if jti in self.seen:
                    self.row = None
                else:
                    self.seen.add(jti)
                    self.row = (jti,)
            elif "SELECT 1 FROM public.aig_bridge_jwt_replay" in query:
                self.row = None

        def fetchone(self):
            return self.row

    class Connection:
        def __init__(self, seen):
            self.seen = seen

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def cursor(self):
            return Cursor(self.seen)

    seen = set()
    shared_store = auth.ReplayStore(
        postgres_dsn="postgresql://bridge:test@db.example.test/aidr",
        postgres_connect=lambda: Connection(seen),
    )
    monkeypatch.setattr(auth, "_replay_store", shared_store)
    assert auth.replay_store_ready()
    assert shared_store.consume("shared-jti", int(time.time()) + 60)
    assert not shared_store.consume("shared-jti", int(time.time()) + 60)


def test_replay_store_outage_is_service_unavailable_not_auth_failure(monkeypatch):
    secret = "unit-test-broker-secret-at-least-32-bytes"
    monkeypatch.setenv("BRIDGE_JWT_SECRET", secret)
    monkeypatch.setenv("BRIDGE_JWT_ISSUER", "https://broker.example.test")
    monkeypatch.setenv("BRIDGE_JWT_AUDIENCE", "aidr-aig-bridge")

    class UnavailableStore:
        def consume(self, _jti, _expires_at):
            raise auth.ReplayStoreUnavailable("database unavailable")

    monkeypatch.setattr(auth, "_replay_store", UnavailableStore())
    token = _jwt(
        secret,
        {
            "sub": "broker-worker",
            "tenant_id": "tenant-a",
            "iss": "https://broker.example.test",
            "aud": "aidr-aig-bridge",
            "jti": "store-unavailable-jti",
            "exp": int(time.time()) + 120,
        },
    )
    with pytest.raises(HTTPException) as unavailable:
        auth._verify_broker_token(_request({"Authorization": f"Bearer {token}"}))
    assert unavailable.value.status_code == 503


def test_redaction_removes_query_credentials_and_bounds_payload():
    assert "super-secret" not in redact_url("https://example.test/a?token=super-secret&x=1")
    assert "user:password" not in redact_url("https://user:password@example.test/a")
    result = bounded_redacted({"api_key": "super-secret", "nested": "Bearer abcdefghijkl"})
    assert result["api_key"] == "[REDACTED]"
    assert "super-secret" not in json.dumps(result)


def test_registry_quota_lease_and_reclaim(tmp_path, monkeypatch):
    monkeypatch.setenv("BRIDGE_HA_REQUIRED", "false")
    registry = TaskRegistry(db_path=str(tmp_path / "tasks.db"), max_active_per_tenant=1)
    assert registry.readiness()[0]
    registry.admit("tenant-a")
    registry.register("task-1", "tenant-a", "key-1", "hash-1")
    with pytest.raises(QuotaExceeded):
        registry.admit("tenant-a")
    assert registry.acquire_lease("task-1", "tenant-a", "worker-1", ttl_seconds=1)
    registry._connect  # keep the test explicit that state is persisted
    with registry._connect() as connection:
        connection.execute("UPDATE aig_bridge_tasks SET lease_expires_at = ? WHERE task_id = 'task-1'", (time.time() - 1,))
    assert registry.reclaim_expired() == 1
    assert registry.record_for("task-1", "tenant-a").status == "queued"


def test_postgres_registry_requires_a_real_connection(monkeypatch):
    monkeypatch.delenv("BRIDGE_TASK_POSTGRES_DSN", raising=False)
    assert TaskRegistry(backend="postgres").readiness() == (
        False,
        "postgres task registry DSN is not configured",
    )


def test_content_addressed_upload_and_archive_traversal_rejection(tmp_path):
    stream = io.BytesIO(b"safe source")
    path, digest, size = store_upload(stream, root=tmp_path, tenant_id="tenant-a")
    assert size == len(b"safe source")
    assert path.name == digest
    assert path.exists()
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../escape.txt", b"no")
    with pytest.raises(HTTPException):
        validate_archive(archive)


def test_result_adapter_is_typed_and_incident_boundary_is_redacted():
    adapted = adapt_infra_result(
        "task-1",
        "tenant-a",
        {
            "status": "done",
            "findings": [
                {
                    "cve_id": "CVE-TEST",
                    "package": "demo",
                    "version": "1.0",
                    "severity": "high",
                    "description": "Authorization: Bearer secret-token",
                    "remediation": "upgrade",
                }
            ],
            "results": [{"target_url": "https://example.test/?token=secret-token"}],
        },
    )
    assert adapted["status"] == "completed"
    assert adapted["findings"][0]["description"].find("secret-token") == -1
    assert adapted["incident_candidates"][0]["tenant_id"] == "tenant-a"
    assert "secret-token" not in json.dumps(adapted)
    assert build_incident_candidates(tenant_id="t", task_id="x", scan_type="mcp", findings=[] ) == []
