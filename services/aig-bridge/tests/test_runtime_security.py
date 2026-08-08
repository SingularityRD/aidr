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
    secret = "unit-test-broker-secret"
    monkeypatch.setenv("BRIDGE_JWT_SECRET", secret)
    monkeypatch.setenv("BRIDGE_AUTH_MODE", "broker")
    monkeypatch.setattr(auth, "_replay_store", auth.ReplayStore())
    payload = {
        "sub": "broker-worker",
        "tenant_id": "tenant-a",
        "scope": "aig:scan aig:read",
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
    secret = "unit-test-broker-secret"
    monkeypatch.setenv("BRIDGE_JWT_SECRET", secret)
    monkeypatch.setattr(auth, "_replay_store", auth.ReplayStore())
    payload = {
        "sub": "broker-worker",
        "tenant_id": "tenant-a",
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
