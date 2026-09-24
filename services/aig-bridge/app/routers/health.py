"""Fail-closed liveness/readiness endpoints for the AIG bridge."""

from __future__ import annotations

import logging
import os

from fastapi import APIRouter, Depends, Query, Response, status

from app.auth import auth_is_configured, auth_is_required, replay_store_ready
from app.provenance import DatasetProvenance, verify_dataset_provenance
from app.task_registry import task_registry
from app.utils.aig_client import AIGClient, get_aig_client
from app.validation import runtime_egress_ready

logger = logging.getLogger("aig-bridge.health")
router = APIRouter()
_CAPABILITIES = ("infra", "mcp", "agent", "jailbreak")
_UPSTREAM_CAPABILITIES = {
    "infra": "ai_infra_scan",
    "mcp": "mcp_scan",
    "agent": "agent_scan",
    "jailbreak": "model_redteam_report",
}


def _dataset_ready(
    threats: dict[str, object] | None,
    provenance: DatasetProvenance,
) -> tuple[bool, str]:
    if not threats:
        return False, "AIG knowledge registry is unavailable"
    cve_count = threats.get("cve_count")
    categories = threats.get("mcp_risk_categories")
    if not isinstance(cve_count, int) or cve_count <= 0:
        return False, "AIG vulnerability dataset is empty"
    if not isinstance(categories, list) or not categories:
        return False, "AIG MCP dataset is empty"
    return provenance.ready, provenance.reason


def _worker_ready(runtime: dict[str, object] | None) -> tuple[bool, str]:
    if not runtime:
        return False, "authenticated AIG worker registry is unavailable"
    active_agents = runtime.get("active_agents")
    try:
        minimum = max(1, int(os.getenv("AIG_MIN_WORKERS", "1")))
    except ValueError:
        return False, "AIG_MIN_WORKERS is invalid"
    if isinstance(active_agents, bool) or not isinstance(active_agents, int):
        return False, "AIG worker registry returned invalid evidence"
    if active_agents < minimum:
        return False, f"active AIG workers {active_agents}/{minimum}"
    return True, f"active AIG workers {active_agents}/{minimum}"


def _capability_ready(capability: str, runtime: dict[str, object] | None) -> tuple[bool, str]:
    if capability not in _CAPABILITIES:
        return False, "unknown capability"
    worker, reason = _worker_ready(runtime)
    if not worker:
        return False, reason
    counts = runtime.get("capabilities") if runtime else None
    upstream_name = _UPSTREAM_CAPABILITIES[capability]
    if not isinstance(counts, dict) or not isinstance(counts.get(upstream_name), int) or counts[upstream_name] < 1:
        return False, f"no live worker advertises {upstream_name}"
    return True, f"live worker advertises {upstream_name}"


async def _readiness_report(aig: AIGClient, capability: str | None = None) -> dict[str, object]:
    upstream_ready = await aig.health_check()
    runtime = None
    threats = None
    if upstream_ready:
        try:
            runtime = await aig.get_runtime_readiness()
        except Exception as exc:
            logger.warning("AIG worker readiness probe failed: %s", type(exc).__name__)
        try:
            threats = await aig.get_latest_threats()
        except Exception as exc:
            logger.warning("AIG dataset readiness probe failed: %s", type(exc).__name__)
    auth_ready = (not auth_is_required()) or auth_is_configured()
    replay_ready = replay_store_ready()
    registry_ready, registry_reason = task_registry.readiness()
    egress_ready, egress_reason = runtime_egress_ready()
    upstream_provenance = runtime.get("dataset_provenance") if runtime else None
    provenance = verify_dataset_provenance(
        threats,
        upstream_provenance if isinstance(upstream_provenance, dict) else None,
    )
    dataset_ready, dataset_reason = _dataset_ready(threats, provenance)
    worker_ready, worker_reason = _worker_ready(runtime)
    requested = [capability] if capability else list(_CAPABILITIES)
    capabilities = {name: _capability_ready(name, runtime)[0] for name in requested}
    ready = all(
        [
            upstream_ready,
            auth_ready,
            replay_ready,
            registry_ready,
            egress_ready,
            dataset_ready,
            worker_ready,
            *capabilities.values(),
        ]
    )
    return {
        "ready": ready,
        "aig_server": "connected" if upstream_ready else "disconnected",
        "aig_agent": "ready" if worker_ready else "unknown",
        "auth_configured": auth_ready,
        "jwt_replay_store_ready": replay_ready,
        "task_registry_ready": registry_ready,
        "task_registry_reason": registry_reason,
        "egress_ready": egress_ready,
        "egress_reason": egress_reason,
        "dataset_ready": dataset_ready,
        "dataset_reason": dataset_reason,
        "dataset_bundle_id": provenance.bundle_id,
        "dataset_source_commit": provenance.source_commit,
        "dataset_release_sequence": provenance.release_sequence,
        "worker_reason": worker_reason,
        "capabilities": capabilities,
        "cve_count": threats.get("cve_count") if threats else None,
        "threat_intel_ready": dataset_ready,
    }

@router.get("/health")
async def health_check(response: Response, aig: AIGClient = Depends(get_aig_client)):
    """Return dependency health without exposing upstream payloads."""

    report = await _readiness_report(aig)
    # Health is intentionally 503 when a scan dependency is not ready.  /livez
    # remains the process-only endpoint for orchestrator restart decisions.
    if not report["ready"]:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    report["status"] = "ok" if report["ready"] else "degraded"
    report["version"] = "1.0.0"
    return report


@router.get("/livez")
async def liveness():
    """Process liveness; deliberately does not contact AIG or auth stores."""

    return {"status": "alive"}


@router.get("/readyz")
async def readiness(
    response: Response,
    capability: str | None = Query(default=None),
    aig: AIGClient = Depends(get_aig_client),
):
    """Readiness with capability, worker, dataset, broker and egress gates."""

    report = await _readiness_report(aig, capability)
    if not report["ready"]:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if report["ready"] else "not_ready",
        **report,
    }
