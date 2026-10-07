from pathlib import Path
from types import SimpleNamespace

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
