from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import yaml

from app.routers import health
from app.provenance import DatasetProvenance


REPO_ROOT = Path(__file__).resolve().parents[3]


class HealthyAIG:
    async def health_check(self) -> bool:
        return True

    async def get_runtime_readiness(self) -> dict[str, object]:
        return {
            "active_agents": 1,
            "capabilities": {
                "ai_infra_scan": 1,
                "mcp_scan": 1,
                "agent_scan": 1,
                "model_redteam_report": 1,
            },
            "dataset_provenance": {
                "verified": True,
                "bundle_id": "a" * 64,
                "source_commit": "b" * 40,
                "release_sequence": 1,
            },
        }

    async def get_latest_threats(self) -> dict[str, object]:
        return {"cve_count": 1, "mcp_risk_categories": [{"id": "mcp_ssrf"}]}


class ConfigOnlyAIG:
    async def health_check(self) -> bool:
        return True


@pytest.mark.asyncio
async def test_readiness_ignores_config_only_worker_and_dataset_claims(monkeypatch):
    for name, value in {
        "AIG_WORKER_HEALTH_REQUIRED": "false",
        "AIG_WORKER_READY": "true",
        "AIG_AGENT_COUNT": "99",
        "AIG_MIN_WORKERS": "1",
        "AIG_DATASET_READINESS_REQUIRED": "false",
        "AIG_DATASET_MANIFEST_SHA256": "a" * 64,
        "AIG_DATASET_LOADED_SHA256": "a" * 64,
    }.items():
        monkeypatch.setenv(name, value)

    monkeypatch.setattr(health, "auth_is_required", lambda: False)
    monkeypatch.setattr(health, "replay_store_ready", lambda: True)
    monkeypatch.setattr(health, "runtime_egress_ready", lambda: (True, "ready"))
    monkeypatch.setattr(health, "task_registry", SimpleNamespace(readiness=lambda: (True, "ready")))

    report = await health._readiness_report(ConfigOnlyAIG())

    assert report["ready"] is False
    assert report["aig_agent"] == "unknown"
    assert report["dataset_ready"] is False
    assert report["dataset_reason"] == "AIG knowledge registry is unavailable"
    assert report["worker_reason"] == "authenticated AIG worker registry is unavailable"
    assert not any(report["capabilities"].values())


@pytest.mark.asyncio
async def test_readiness_accepts_live_authenticated_worker_and_loaded_datasets(monkeypatch):
    monkeypatch.setenv("AIG_MIN_WORKERS", "1")
    monkeypatch.setattr(health, "auth_is_required", lambda: False)
    monkeypatch.setattr(health, "replay_store_ready", lambda: True)
    monkeypatch.setattr(health, "runtime_egress_ready", lambda: (True, "ready"))
    monkeypatch.setattr(health, "task_registry", SimpleNamespace(readiness=lambda: (True, "ready")))
    monkeypatch.setattr(
        health,
        "verify_dataset_provenance",
        lambda _threats, _upstream: DatasetProvenance(
            True,
            "verified",
            bundle_id="a" * 64,
            source_commit="b" * 40,
            release_sequence=1,
        ),
    )

    report = await health._readiness_report(HealthyAIG())

    assert report["ready"] is True
    assert report["aig_agent"] == "ready"
    assert report["dataset_ready"] is True
    assert report["dataset_bundle_id"] == "a" * 64
    assert all(report["capabilities"].values())


@pytest.mark.asyncio
async def test_readiness_rejects_unverified_dataset_provenance(monkeypatch):
    monkeypatch.setenv("AIG_MIN_WORKERS", "1")
    monkeypatch.setattr(health, "auth_is_required", lambda: False)
    monkeypatch.setattr(health, "replay_store_ready", lambda: True)
    monkeypatch.setattr(health, "runtime_egress_ready", lambda: (True, "ready"))
    monkeypatch.setattr(health, "task_registry", SimpleNamespace(readiness=lambda: (True, "ready")))
    monkeypatch.setattr(
        health,
        "verify_dataset_provenance",
        lambda _threats, _upstream: DatasetProvenance(False, "signature verification failed"),
    )

    report = await health._readiness_report(HealthyAIG())

    assert report["ready"] is False
    assert report["dataset_ready"] is False
    assert report["dataset_reason"] == "signature verification failed"


class CountingAIG(HealthyAIG):
    def __init__(self) -> None:
        self.health_calls = 0

    async def health_check(self) -> bool:
        self.health_calls += 1
        return True


class SecretLeakingAIG:
    async def health_check(self) -> bool:
        raise RuntimeError("internal error at /srv/aig/secret-path token=abc")


@pytest.fixture
def health_app(monkeypatch):
    from app.main import app
    from app.utils.aig_client import get_aig_client

    monkeypatch.setenv("AIG_MIN_WORKERS", "1")
    monkeypatch.setenv("BRIDGE_AUTH_REQUIRED", "true")
    monkeypatch.setenv("BRIDGE_AUTH_MODE", "api_key")
    monkeypatch.setenv("BRIDGE_API_KEY", "health-test-key")
    monkeypatch.setattr(health, "replay_store_ready", lambda: True)
    monkeypatch.setattr(health, "runtime_egress_ready", lambda: (True, "ready"))
    monkeypatch.setattr(health, "task_registry", SimpleNamespace(readiness=lambda: (True, "ready")))
    monkeypatch.setattr(
        health,
        "verify_dataset_provenance",
        lambda _threats, _upstream: DatasetProvenance(
            True, "verified", bundle_id="a" * 64, source_commit="b" * 40, release_sequence=1
        ),
    )
    aig = CountingAIG()
    health.reset_readiness_cache()
    previous = app.dependency_overrides.copy()
    app.dependency_overrides[get_aig_client] = lambda: aig
    yield app, aig
    app.dependency_overrides.clear()
    app.dependency_overrides.update(previous)
    health.reset_readiness_cache()


async def _get(app, path, **kwargs):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://bridge.test") as client:
        return await client.get(path, **kwargs)


@pytest.mark.asyncio
async def test_unauthenticated_readyz_is_minimal(health_app):
    app, _aig = health_app

    response = await _get(app, "/api/v1/readyz")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_unauthenticated_readyz_not_ready_hides_reasons_and_errors(health_app, monkeypatch):
    app, _aig = health_app
    from app.utils.aig_client import get_aig_client

    app.dependency_overrides[get_aig_client] = lambda: SecretLeakingAIG()

    response = await _get(app, "/api/v1/readyz")

    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}
    assert "secret" not in response.text and "token" not in response.text


@pytest.mark.asyncio
async def test_readyz_rejects_unknown_capability_without_probing(health_app):
    app, aig = health_app

    response = await _get(app, "/api/v1/readyz", params={"capability": "not-a-capability"})

    assert response.status_code == 422
    assert aig.health_calls == 0


@pytest.mark.asyncio
async def test_detailed_health_requires_bridge_authentication(health_app):
    app, aig = health_app

    missing = await _get(app, "/api/v1/health")
    wrong = await _get(app, "/api/v1/health", headers={"X-API-Key": "wrong"})
    valid = await _get(app, "/api/v1/health", headers={"X-API-Key": "health-test-key"})

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert "dataset_bundle_id" not in missing.text
    assert valid.status_code == 200
    body = valid.json()
    assert body["status"] == "ok"
    assert body["scan_ready"] is True
    assert body["dataset_bundle_id"] == "a" * 64
    assert aig.health_calls == 1


@pytest.mark.asyncio
async def test_detailed_health_fails_closed_when_auth_is_unconfigured(health_app, monkeypatch):
    app, aig = health_app
    monkeypatch.delenv("BRIDGE_API_KEY", raising=False)

    response = await _get(app, "/api/v1/health")

    assert response.status_code == 503
    assert response.json()["detail"] == "bridge authentication is not configured"
    assert aig.health_calls == 0


@pytest.mark.asyncio
async def test_detailed_health_requires_read_scope_for_broker_tokens(health_app):
    from app.auth import BrokerClaims, require_bridge_api_key

    app, _aig = health_app

    async def no_read_scope() -> BrokerClaims:
        return BrokerClaims("svc", "tenant-a", frozenset({"aig:scan"}), None, "jti-1", 0, {})

    app.dependency_overrides[require_bridge_api_key] = no_read_scope
    response = await _get(app, "/api/v1/health")

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_probe_results_are_cached_and_shared(health_app, monkeypatch):
    app, aig = health_app
    monkeypatch.setenv("BRIDGE_HEALTH_CACHE_SECONDS", "5")

    for _ in range(5):
        assert (await _get(app, "/api/v1/readyz")).status_code == 200
    assert (await _get(app, "/api/v1/health", headers={"X-API-Key": "health-test-key"})).status_code == 200
    assert aig.health_calls == 1

    # A capability-scoped probe is cached under its own key.
    assert (await _get(app, "/api/v1/readyz", params={"capability": "mcp"})).status_code == 200
    assert aig.health_calls == 2


@pytest.mark.asyncio
async def test_probe_cache_expires(health_app, monkeypatch):
    app, aig = health_app
    clock = [1000.0]
    monkeypatch.setattr(health.time, "monotonic", lambda: clock[0])
    monkeypatch.setenv("BRIDGE_HEALTH_CACHE_SECONDS", "5")

    await _get(app, "/api/v1/readyz")
    clock[0] += 4.0
    await _get(app, "/api/v1/readyz")
    assert aig.health_calls == 1
    clock[0] += 2.0
    await _get(app, "/api/v1/readyz")
    assert aig.health_calls == 2


@pytest.mark.asyncio
async def test_concurrent_probes_are_coalesced(health_app):
    import asyncio

    app, aig = health_app
    release = asyncio.Event()

    async def slow_health() -> bool:
        aig.health_calls += 1
        await release.wait()
        return True

    aig.health_check = slow_health
    calls = [asyncio.create_task(_get(app, "/api/v1/readyz")) for _ in range(10)]
    await asyncio.sleep(0.05)
    release.set()
    responses = await asyncio.gather(*calls)

    assert all(item.status_code == 200 for item in responses)
    assert aig.health_calls == 1


@pytest.mark.asyncio
async def test_livez_stays_public_and_does_not_probe(health_app):
    app, aig = health_app

    response = await _get(app, "/api/v1/livez")

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}
    assert aig.health_calls == 0


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(None, 5.0), ("0", 0.0), ("2.5", 2.5), ("999", 30.0), ("-1", 0.0), ("nan", 5.0), ("bogus", 5.0)],
)
def test_cache_seconds_is_bounded(monkeypatch, raw, expected):
    if raw is None:
        monkeypatch.delenv("BRIDGE_HEALTH_CACHE_SECONDS", raising=False)
    else:
        monkeypatch.setenv("BRIDGE_HEALTH_CACHE_SECONDS", raw)
    assert health._cache_seconds() == expected


def test_probes_use_unauthenticated_readyz_and_livez():
    dockerfile = (REPO_ROOT / "services" / "aig-bridge" / "Dockerfile").read_text(encoding="utf-8")
    helm = (REPO_ROOT / "deploy" / "helm" / "aidr" / "templates" / "posture-scanner.yaml").read_text(encoding="utf-8")

    assert "http://localhost:8099/api/v1/readyz" in dockerfile
    assert "path: /api/v1/readyz" in helm
    assert "path: /api/v1/livez" in helm
    # Probes must never depend on the authenticated detailed endpoint.
    assert "/api/v1/health" not in dockerfile
    assert "path: /api/v1/health" not in helm


def test_compose_separates_container_liveness_from_traffic_readiness():
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.posture-scanner.yml").read_text(encoding="utf-8"))
    probe = compose["services"]["aig-bridge"]["healthcheck"]["test"]

    assert probe[-1] == "http://localhost:8099/api/v1/readyz"


def test_compose_keeps_raw_aig_private_and_worker_egress_isolated():
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.posture-scanner.yml").read_text(encoding="utf-8"))
    server = compose["services"]["aig-server"]
    agent = compose["services"]["aig-agent"]

    assert "ports" not in server
    assert server["expose"] == ["8088"]
    assert compose["networks"]["aidr-aig-network"]["internal"] is True
    assert agent["read_only"] is True
    assert agent["cap_drop"] == ["ALL"]
    assert any(item.startswith("AIG_AGENT_SHARED_SECRET=") for item in agent["environment"])
    assert any(item.startswith("AIG_WORK_DIR=/work") for item in agent["environment"])


def test_compose_mounts_dataset_and_public_key_read_only():
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.posture-scanner.yml").read_text(encoding="utf-8"))
    bridge = compose["services"]["aig-bridge"]
    server = compose["services"]["aig-server"]

    provenance_environment = {
        item.split("=", 1)[0] for item in bridge["environment"] if isinstance(item, str)
    }
    assert {
        "AIG_DATA_MANIFEST_PATH",
        "AIG_SIGNING_PUBLIC_KEY_PATH",
        "AIG_TRUSTED_SIGNING_KEY_ID",
        "AIG_TRUSTED_SIGNING_PUBLIC_KEY_SHA256",
        "AIG_EXPECTED_DATA_BUNDLE_ID",
        "AIG_EXPECTED_SOURCE_COMMIT",
    } <= provenance_environment
    provenance_mounts = {
        item["target"]: item for item in bridge["volumes"] if isinstance(item, dict)
    }
    assert provenance_mounts["/app/aig-data"]["read_only"] is True
    assert provenance_mounts["/run/secrets/aig-signing-public.pem"]["read_only"] is True
    server_mounts = {
        item["target"]: item
        for item in server["volumes"]
        if isinstance(item, dict)
    }
    assert not any(
        item.endswith(":/app/data") or item.endswith(":/app/data:ro")
        for item in server["volumes"]
        if isinstance(item, str)
    )
    assert server_mounts["/app/aig-manifest"]["read_only"] is True
    assert server_mounts["/run/secrets/aig-signing-public.pem"]["read_only"] is True
