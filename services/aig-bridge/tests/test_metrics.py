"""Bearer-protected /metrics: access contract, bounded labels and series."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from prometheus_client.parser import text_string_to_metric_families

from app import metrics
from app.auth import RequestContext, get_request_context
from app.routers import scan as scan_router
from app.task_registry import TaskRegistry
from app.utils.aig_client import AIGClientError, get_aig_client

# Assembled at runtime so secret scanners do not flag a fixture credential.
TOKEN = "-".join(["metrics", "fixture", "z" * 24])


class FakeAIG:
    def __init__(self) -> None:
        self.create_error: Exception | None = None
        self.count = 0

    async def create_scan_task(self, *, task_type: str, content: dict[str, Any]) -> str:
        del task_type, content
        if self.create_error:
            raise self.create_error
        self.count += 1
        return f"task-{self.count}"

    async def get_task_result(self, task_id: str) -> dict[str, Any]:
        return {"status": "running", "task_id": task_id}


async def call(app: Any, method: str, path: str, **kwargs: Any) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://bridge.test") as client:
        return await client.request(method, path, **kwargs)


def samples(text: str) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    found = {}
    for family in text_string_to_metric_families(text):
        for sample in family.samples:
            found[(sample.name, tuple(sorted(sample.labels.items())))] = sample.value
    return found


def value(text: str, name: str, **labels: str) -> float:
    return samples(text).get((name, tuple(sorted(labels.items()))), 0.0)


@pytest.fixture
def bridge(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("BRIDGE_AUTH_REQUIRED", "false")
    monkeypatch.setenv("BRIDGE_TENANT_REQUIRED", "true")
    monkeypatch.setenv("BRIDGE_VALIDATE_DNS", "false")
    monkeypatch.setenv("BRIDGE_RUNTIME_EGRESS_REQUIRED", "false")
    monkeypatch.setenv("BRIDGE_ALLOW_PRIVATE_TARGETS", "false")
    monkeypatch.setenv("BRIDGE_METRICS_TOKEN", TOKEN)

    from app.main import app

    fake = FakeAIG()
    registry = TaskRegistry()
    previous = app.dependency_overrides.copy()
    app.dependency_overrides[get_aig_client] = lambda: fake

    async def context() -> RequestContext:
        return RequestContext(tenant_id="tenant-metrics", idempotency_key=None)

    app.dependency_overrides[get_request_context] = context
    monkeypatch.setattr(scan_router, "task_registry", registry)
    yield app, fake, registry
    app.dependency_overrides.clear()
    app.dependency_overrides.update(previous)


async def scrape(app: Any) -> str:
    response = await call(app, "GET", "/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.headers["cache-control"] == "no-store"
    return response.text


@pytest.mark.asyncio
async def test_metrics_is_disabled_without_a_token(bridge, monkeypatch):
    app, _aig, _registry = bridge
    monkeypatch.delenv("BRIDGE_METRICS_TOKEN")
    response = await call(app, "GET", "/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 404
    assert response.text == ""


@pytest.mark.asyncio
async def test_metrics_refuses_a_token_shared_with_the_api_key(bridge, monkeypatch):
    app, _aig, _registry = bridge
    monkeypatch.setenv("BRIDGE_API_KEY", TOKEN)
    response = await call(app, "GET", "/metrics", headers={"Authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 404
    assert "aig_bridge" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer wrong-token"},
        {"Authorization": f"Basic {TOKEN}"},
        {"Authorization": f"Bearer {TOKEN}x"},
        {"X-API-Key": TOKEN},
    ],
)
async def test_metrics_requires_the_exact_bearer_token(bridge, headers):
    app, _aig, _registry = bridge
    response = await call(app, "GET", "/metrics", headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == 'Bearer realm="metrics"'
    assert "aig_bridge" not in response.text


@pytest.mark.asyncio
async def test_requests_are_counted_by_route_template_never_raw_path(bridge):
    app, _aig, _registry = bridge
    before = await scrape(app)
    task_path = "/api/v1/scan/infra/task-secret-identifier-123"
    await call(app, "GET", task_path)
    await call(app, "GET", "/api/v1/livez")
    await call(app, "GET", "/no-such-route/with-secret-segment")
    after = await scrape(app)

    template = "/api/v1/scan/infra/{task_id}"
    assert any(
        name == "aig_bridge_http_requests_total" and dict(labels).get("route") == template
        for (name, labels) in samples(after)
    )
    assert value(after, "aig_bridge_http_requests_total", method="GET", route="unmatched", status="404") == (
        value(before, "aig_bridge_http_requests_total", method="GET", route="unmatched", status="404") + 1
    )
    assert "task-secret-identifier-123" not in after
    assert "with-secret-segment" not in after
    assert "tenant-metrics" not in after
    # Probe and scrape traffic is not user load.
    assert "/api/v1/livez" not in after
    assert 'route="/metrics"' not in after


@pytest.mark.asyncio
async def test_auth_rejections_are_counted(bridge, monkeypatch):
    app, _aig, _registry = bridge
    app.dependency_overrides.pop(get_request_context)
    monkeypatch.setenv("BRIDGE_AUTH_REQUIRED", "true")
    monkeypatch.setenv("BRIDGE_AUTH_MODE", "api_key")
    monkeypatch.setenv("BRIDGE_API_KEY", "-".join(["bridge", "fixture", "k" * 24]))

    before = await scrape(app)
    rejected = await call(
        app,
        "POST",
        "/api/v1/scan/infra",
        headers={"X-AIDR-Tenant-ID": "tenant-metrics", "X-API-Key": "wrong"},
        json={"targets": ["https://example.com"]},
    )
    assert rejected.status_code == 401
    after = await scrape(app)
    assert value(after, "aig_bridge_auth_rejections_total", status="401") == (
        value(before, "aig_bridge_auth_rejections_total", status="401") + 1
    )


@pytest.mark.asyncio
async def test_upstream_failures_and_active_task_depth(bridge):
    app, aig, registry = bridge
    before = await scrape(app)

    aig.create_error = AIGClientError("upstream said no: secret-target.internal")
    failed = await call(
        app, "POST", "/api/v1/scan/infra", headers={"Idempotency-Key": "m-1"}, json={"targets": ["https://example.com"]}
    )
    assert failed.status_code == 502
    aig.create_error = None
    accepted = await call(
        app, "POST", "/api/v1/scan/infra", headers={"Idempotency-Key": "m-2"}, json={"targets": ["https://example.com"]}
    )
    assert accepted.status_code == 200

    after = await scrape(app)
    assert value(after, "aig_bridge_upstream_failures_total", outcome="rejected") == (
        value(before, "aig_bridge_upstream_failures_total", outcome="rejected") + 1
    )
    assert "secret-target.internal" not in after
    assert value(after, "aig_bridge_task_registry_up") == 1
    assert value(after, "aig_bridge_active_tasks", state="queued") == 1
    assert registry.active_counts_by_status() == {"queued": 1, "reserved": 0, "running": 0}


@pytest.mark.asyncio
async def test_unreadable_registry_is_not_reported_as_empty(bridge, monkeypatch):
    app, _aig, registry = bridge

    def broken() -> dict[str, int]:
        raise RuntimeError("database at postgres://user:pw@db is down")

    monkeypatch.setattr(registry, "active_counts_by_status", broken)
    text = await scrape(app)
    assert value(text, "aig_bridge_task_registry_up") == 0
    assert "aig_bridge_active_tasks" not in text
    assert "postgres://" not in text


def test_sqlite_registry_depth_counts_active_states_only(tmp_path):
    registry = TaskRegistry(db_path=str(tmp_path / "tasks.db"))
    registry.register("t-1", "tenant-a", "infra")
    registry.register("t-2", "tenant-b", "infra")
    registry.update_status("t-2", "tenant-b", "completed")
    counts = registry.active_counts_by_status()
    assert sum(counts.values()) == 1
    assert set(counts) == {"reserved", "queued", "running"}


def test_unknown_upstream_outcome_is_refused():
    with pytest.raises(ValueError):
        metrics.record_upstream_failure("tenant-a")
