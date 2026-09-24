"""FastAPI boundary tests for the AIG bridge."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from app.auth import RequestContext, get_request_context
from app.models.schemas import AgentScanRequest, EvalModelConfig, InfraScanRequest
from app.routers import scan as scan_router
from app.task_registry import TaskRegistry
from app.utils.aig_client import AIGClientError, AIGSubmissionAmbiguous, get_aig_client


class FakeAIG:
    """Small async double that records the bridge-to-AIG contract."""

    def __init__(self) -> None:
        self.submissions: list[tuple[str, dict[str, Any]]] = []
        self.results: dict[str, dict[str, Any]] = {}
        self.create_error: Exception | None = None
        self.health_calls = 0

    async def create_scan_task(self, *, task_type: str, content: dict[str, Any]) -> str:
        if self.create_error:
            raise self.create_error
        task_id = f"task-{len(self.submissions) + 1}"
        self.submissions.append((task_type, content))
        return task_id

    async def get_task_result(self, task_id: str) -> dict[str, Any]:
        return self.results[task_id]

    async def cancel_task(self, task_id: str, *, username: str) -> None:
        del task_id, username

    async def health_check(self) -> bool:
        self.health_calls += 1
        return True

    async def get_latest_threats(self) -> dict[str, Any]:
        return {
            "rules_version": "test",
            "cve_count": 1,
            "mcp_risk_categories": [],
            "threat_rules": [],
            "last_updated": "2026-01-01T00:00:00Z",
        }


@pytest.fixture
def bridge(monkeypatch: pytest.MonkeyPatch):
    """Install isolated dependency doubles without changing application code."""

    monkeypatch.setenv("BRIDGE_AUTH_REQUIRED", "false")
    monkeypatch.setenv("BRIDGE_TENANT_REQUIRED", "true")
    monkeypatch.setenv("BRIDGE_VALIDATE_DNS", "false")
    monkeypatch.setenv("BRIDGE_RUNTIME_EGRESS_REQUIRED", "false")
    monkeypatch.setenv("BRIDGE_ALLOW_PRIVATE_TARGETS", "false")

    from app.main import app

    fake = FakeAIG()
    registry = TaskRegistry()
    previous_overrides = app.dependency_overrides.copy()
    app.dependency_overrides[get_aig_client] = lambda: fake

    async def test_context() -> RequestContext:
        return RequestContext(tenant_id="tenant-a", idempotency_key=None)

    app.dependency_overrides[get_request_context] = test_context
    monkeypatch.setattr(scan_router, "task_registry", registry)
    yield app, fake, registry
    app.dependency_overrides.clear()
    app.dependency_overrides.update(previous_overrides)


async def request(app: Any, method: str, path: str, **kwargs: Any) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://bridge.test") as client:
        return await client.request(method, path, **kwargs)


@pytest.mark.asyncio
async def test_infra_route_forwards_only_supported_bounded_fields(bridge):
    app, aig, _registry = bridge
    secret = "model-secret-that-must-not-appear-in-the-response"
    response = await request(
        app,
        "POST",
        "/api/v1/scan/infra",
        headers={"Idempotency-Key": "infra-contract-1"},
        json={
            "targets": [" https://example.com/api?probe=1 ", "https://scanner.example.test/health"],
            "scan_type": "standard",
            "options": {
                "timeout": 15,
                "headers": {"Authorization": "Bearer upstream-secret", "X-Trace": "trace-1"},
                "model": {
                    "model": "test-model",
                    "token": secret,
                    "base_url": "https://model.example.test/v1",
                },
                "ignored": {"credentials": "must-not-be-forwarded"},
            },
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "task_id": "task-1",
        "status": "running",
        "estimated_seconds": 120,
    }
    task_type, content = aig.submissions[0]
    assert task_type == "ai_infra_scan"
    assert content["tenant_id"] == "tenant-a"
    assert content["target"] == ["https://example.com/api?probe=1", "https://scanner.example.test/health"]
    assert content["timeout"] == 15
    assert content["headers"] == {"Authorization": "Bearer upstream-secret", "X-Trace": "trace-1"}
    assert content["model"]["token"] == secret
    assert content["target_policy"] == [
        {"scheme": "https", "host": "example.com", "port": 443, "runtime_proxy_required": False},
        {"scheme": "https", "host": "scanner.example.test", "port": 443, "runtime_proxy_required": False},
    ]
    assert "ignored" not in content
    assert "scan_type" not in content
    assert "options" not in content
    assert secret not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"targets": []},
        {"targets": ["x" * 513]},
        {"targets": ["https://example.com"], "options": {"timeout": 601}},
        {"targets": ["https://example.com"], "options": {"blob": "x" * 131_100}},
    ],
)
async def test_infra_route_rejects_invalid_or_oversized_input(bridge, payload):
    app, aig, _registry = bridge
    response = await request(app, "POST", "/api/v1/scan/infra", json=payload)

    assert response.status_code == 422
    assert aig.submissions == []


@pytest.mark.asyncio
async def test_mcp_route_rejects_ssrf_target_before_upstream_submission(bridge):
    app, aig, _registry = bridge
    response = await request(
        app,
        "POST",
        "/api/v1/scan/mcp",
        json={"target_type": "url", "target": "http://127.0.0.1:8080"},
    )

    assert response.status_code == 422
    assert aig.submissions == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target",
    ["127.0.0.1", "169.254.169.254", "metadata.google.internal", "0.0.0.0/0", "package:latest"],
)
async def test_infra_route_rejects_non_url_targets(bridge, target):
    app, aig, _registry = bridge
    response = await request(app, "POST", "/api/v1/scan/infra", json={"targets": [target]})

    assert response.status_code == 422
    assert aig.submissions == []


@pytest.mark.asyncio
async def test_source_scan_resolves_upload_id_inside_authenticated_tenant(bridge, monkeypatch, tmp_path):
    app, aig, _registry = bridge
    upload_id = "b" * 64
    monkeypatch.setenv("BRIDGE_SOURCE_ROOT", str(tmp_path))
    other_tenant = tmp_path / "tenant-b"
    other_tenant.mkdir()
    (other_tenant / upload_id).write_bytes(b"other tenant source")

    denied = await request(
        app,
        "POST",
        "/api/v1/scan/mcp",
        json={"target_type": "source", "target": upload_id},
    )
    assert denied.status_code == 422
    assert aig.submissions == []

    own_tenant = tmp_path / "tenant-a"
    own_tenant.mkdir()
    own_path = own_tenant / upload_id
    own_path.write_bytes(b"own source")
    accepted = await request(
        app,
        "POST",
        "/api/v1/scan/mcp",
        json={"target_type": "source", "target": upload_id},
    )
    assert accepted.status_code == 200
    assert aig.submissions[0][1]["attachments"] == f"tenant-a/{upload_id}"


@pytest.mark.asyncio
async def test_agent_scan_fails_closed_without_runtime_egress(bridge, monkeypatch):
    app, aig, _registry = bridge
    monkeypatch.setenv("BRIDGE_RUNTIME_EGRESS_REQUIRED", "true")
    monkeypatch.delenv("BRIDGE_EGRESS_PROXY_URL", raising=False)

    response = await request(
        app,
        "POST",
        "/api/v1/scan/agent",
        json={"agent_config": {"provider": "custom", "apiBaseUrl": "https://example.com"}},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "runtime egress proxy is not configured"
    assert aig.submissions == []


def test_schemas_reject_ambiguous_agent_targets_and_empty_credentials():
    with pytest.raises(ValidationError):
        AgentScanRequest(agent_id="saved-agent", agent_config={"url": "https://example.com"})
    with pytest.raises(ValidationError):
        AgentScanRequest(agent_id="saved-agent")
    with pytest.raises(ValidationError):
        AgentScanRequest()
    with pytest.raises(ValidationError):
        EvalModelConfig(model="test", token="", base_url="https://example.com")
    with pytest.raises(ValidationError):
        InfraScanRequest(targets=["valid-target"], options={"blob": "x" * 131_100})


@pytest.mark.asyncio
async def test_result_route_is_typed_bounded_and_redacted(bridge):
    app, aig, _registry = bridge
    submit = await request(
        app,
        "POST",
        "/api/v1/scan/infra",
        headers={"Idempotency-Key": "result-contract-1"},
        json={"targets": ["https://example.com"]},
    )
    task_id = submit.json()["task_id"]
    secret = "result-secret-token"
    aig.results[task_id] = {
        "status": "done",
        "total": 1,
        "findings": [
            {
                "cve_id": "CVE-TEST-0001",
                "package": "demo",
                "version": "1.0",
                "severity": "HIGH",
                "description": f"Authorization: Bearer {secret}",
                "remediation": "upgrade",
            }
        ],
        "results": [
            {"target_url": f"https://example.com/?token={secret}", "authorization": secret},
            {"large": "x" * 600_000},
        ],
    }

    response = await request(app, "GET", f"/api/v1/scan/infra/{task_id}")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "completed"
    assert data["findings"][0]["description"] == "Authorization: [REDACTED] [REDACTED]"
    assert data["evidence"][0]["target_url"].endswith("token=%5BREDACTED%5D")
    assert data["evidence"][0]["authorization"] == "[REDACTED]"
    assert data["evidence"][1]["truncated"] is True
    assert len(data["evidence"][1]["sha256"]) == 64
    assert data["evidence"][1]["value"] == "[TRUNCATED]"
    assert secret not in response.text
    assert len(response.content) < 10_000


@pytest.mark.asyncio
async def test_upstream_credential_error_is_generic_at_route_boundary(bridge):
    app, aig, registry = bridge
    secret = "upstream-secret-from-an-error"
    aig.create_error = AIGClientError(f"authorization token={secret}")

    response = await request(
        app,
        "POST",
        "/api/v1/scan/infra",
        json={"targets": ["https://example.com"]},
    )

    assert response.status_code == 502
    assert response.json() == {
        "detail": "AIG upstream rejected or could not accept the scan request"
    }
    assert registry.active_count("tenant-a") == 0
    assert secret not in response.text


@pytest.mark.asyncio
async def test_ambiguous_upstream_submission_retains_idempotency_reservation(bridge):
    app, aig, registry = bridge
    aig.create_error = AIGSubmissionAmbiguous("response lost after submit")

    async def idempotent_context() -> RequestContext:
        return RequestContext(tenant_id="tenant-a", idempotency_key="ambiguous-submit")

    app.dependency_overrides[get_request_context] = idempotent_context
    first = await request(
        app,
        "POST",
        "/api/v1/scan/infra",
        json={"targets": ["https://example.com"]},
    )
    second = await request(
        app,
        "POST",
        "/api/v1/scan/infra",
        json={"targets": ["https://example.com"]},
    )

    assert first.status_code == 503
    assert first.json()["detail"] == (
        "AIG submission outcome is unknown; retry is blocked pending reconciliation"
    )
    assert second.status_code == 409
    assert registry.active_count("tenant-a") == 1


@pytest.mark.asyncio
async def test_idempotent_retry_does_not_submit_twice(bridge):
    app, aig, _registry = bridge

    async def idempotent_context() -> RequestContext:
        return RequestContext(tenant_id="tenant-a", idempotency_key="retry-key")

    app.dependency_overrides[get_request_context] = idempotent_context
    first = await request(
        app,
        "POST",
        "/api/v1/scan/infra",
        json={"targets": ["https://example.com"]},
    )
    second = await request(
        app,
        "POST",
        "/api/v1/scan/infra",
        json={"targets": ["https://example.com"]},
    )

    assert first.status_code == second.status_code == 200
    assert first.json()["task_id"] == second.json()["task_id"]
    assert len(aig.submissions) == 1


@pytest.mark.asyncio
async def test_task_polling_is_tenant_scoped(bridge):
    app, aig, _registry = bridge
    submit = await request(
        app,
        "POST",
        "/api/v1/scan/infra",
        headers={"Idempotency-Key": "tenant-scope-1"},
        json={"targets": ["https://example.com"]},
    )
    task_id = submit.json()["task_id"]

    async def other_tenant() -> RequestContext:
        return RequestContext(tenant_id="tenant-b", idempotency_key=None)

    from app.main import app as bridge_app

    bridge_app.dependency_overrides[get_request_context] = other_tenant
    response = await request(app, "GET", f"/api/v1/scan/infra/{task_id}")

    assert response.status_code == 404
    assert task_id not in aig.results


@pytest.mark.asyncio
async def test_api_key_auth_rejects_missing_and_wrong_credentials(bridge, monkeypatch):
    app, aig, _registry = bridge
    from app.main import app as bridge_app

    bridge_app.dependency_overrides.pop(get_request_context)
    monkeypatch.setenv("BRIDGE_AUTH_REQUIRED", "true")
    monkeypatch.setenv("BRIDGE_AUTH_MODE", "api_key")
    monkeypatch.setenv("BRIDGE_API_KEY", "correct-bridge-key")

    missing = await request(
        app,
        "POST",
        "/api/v1/scan/infra",
        headers={"X-AIDR-Tenant-ID": "tenant-a"},
        json={"targets": ["https://example.com"]},
    )
    wrong = await request(
        app,
        "POST",
        "/api/v1/scan/infra",
        headers={"X-AIDR-Tenant-ID": "tenant-a", "X-API-Key": "wrong-key"},
        json={"targets": ["https://example.com"]},
    )
    valid = await request(
        app,
        "POST",
        "/api/v1/scan/infra",
        headers={
            "X-AIDR-Tenant-ID": "tenant-a",
            "X-API-Key": "correct-bridge-key",
            "Idempotency-Key": "auth-success-1",
        },
        json={"targets": ["https://example.com"]},
    )

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert wrong.headers["www-authenticate"] == "Bearer"
    assert valid.status_code == 200
    assert len(aig.submissions) == 1


@pytest.mark.asyncio
async def test_missing_api_key_configuration_is_a_service_failure(bridge, monkeypatch):
    app, aig, _registry = bridge
    from app.main import app as bridge_app

    bridge_app.dependency_overrides.pop(get_request_context)
    monkeypatch.setenv("BRIDGE_AUTH_REQUIRED", "true")
    monkeypatch.setenv("BRIDGE_AUTH_MODE", "api_key")
    monkeypatch.delenv("BRIDGE_API_KEY", raising=False)

    response = await request(
        app,
        "POST",
        "/api/v1/scan/infra",
        headers={"X-AIDR-Tenant-ID": "tenant-a"},
        json={"targets": ["https://example.com"]},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "bridge authentication is not configured"
    assert aig.submissions == []


@pytest.mark.asyncio
async def test_liveness_is_available_without_credentials(bridge):
    app, _aig, _registry = bridge

    response = await request(app, "GET", "/api/v1/livez")

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}
