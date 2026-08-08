"""Fail-closed liveness/readiness endpoints for the AIG bridge."""

from __future__ import annotations

import logging
import os
import re

from fastapi import APIRouter, Depends, Query, Response, status

from app.auth import auth_is_configured, auth_is_required, replay_store_ready
from app.task_registry import task_registry
from app.utils.aig_client import AIGClient, get_aig_client
from app.validation import runtime_egress_ready

logger = logging.getLogger("aig-bridge.health")
router = APIRouter()
_CAPABILITIES = ("infra", "mcp", "agent", "jailbreak")


def _env_true(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _slug(value: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", value.upper()).strip("_")


def _dataset_ready() -> tuple[bool, str]:
    if not _env_true("AIG_DATASET_READINESS_REQUIRED", False):
        return True, "dataset manifest check disabled"
    manifest = os.getenv("AIG_DATASET_MANIFEST_SHA256", "").strip().lower()
    loaded = os.getenv("AIG_DATASET_LOADED_SHA256", "").strip().lower()
    if not manifest or not loaded or len(manifest) != 64 or manifest != loaded:
        return False, "signed dataset manifest is missing or not loaded"
    return True, "signed dataset manifest loaded"


def _worker_ready() -> tuple[bool, str]:
    if not _env_true("AIG_WORKER_HEALTH_REQUIRED", True):
        return True, "worker health check disabled"
    if not _env_true("AIG_WORKER_READY", False):
        return False, "worker health/attestation is not proven"
    try:
        min_workers = max(1, int(os.getenv("AIG_MIN_WORKERS", "1")))
        configured_workers = int(os.getenv("AIG_AGENT_COUNT", "0"))
    except ValueError:
        min_workers = 1
        configured_workers = 0
    if configured_workers < min_workers:
        return False, "configured worker count is below the capability minimum"
    return True, "worker readiness asserted by the orchestrator"


def _capability_ready(capability: str) -> tuple[bool, str]:
    if capability not in _CAPABILITIES:
        return False, "unknown capability"
    name = f"AIG_CAPABILITY_{_slug(capability)}_READY"
    if os.getenv(name) is not None and not _env_true(name):
        return False, f"{capability} capability is disabled or not ready"
    worker, reason = _worker_ready()
    return worker, reason


async def _readiness_report(aig: AIGClient, capability: str | None = None) -> dict[str, object]:
    upstream_ready = await aig.health_check()
    auth_ready = (not auth_is_required()) or auth_is_configured()
    replay_ready = replay_store_ready()
    registry_ready, registry_reason = task_registry.readiness()
    egress_ready, egress_reason = runtime_egress_ready()
    dataset_ready, dataset_reason = _dataset_ready()
    worker_ready, worker_reason = _worker_ready()
    requested = [capability] if capability else list(_CAPABILITIES)
    capabilities = {name: _capability_ready(name)[0] for name in requested}
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
        "worker_reason": worker_reason,
        "capabilities": capabilities,
    }

@router.get("/health")
async def health_check(response: Response, aig: AIGClient = Depends(get_aig_client)):
    """Return dependency health without exposing upstream payloads."""

    report = await _readiness_report(aig)
    cve_count = None
    threat_intel_ready = False
    try:
        threats = await aig.get_latest_threats()
        candidate_count = threats.get("cve_count")
        categories = threats.get("mcp_risk_categories")
        if isinstance(candidate_count, int) and candidate_count > 0:
            cve_count = candidate_count
            threat_intel_ready = isinstance(categories, list) and len(categories) > 0
    except Exception as exc:
        logger.warning("AIG threat readiness probe failed: %s", type(exc).__name__)
    report.update({"cve_count": cve_count, "threat_intel_ready": threat_intel_ready})
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
