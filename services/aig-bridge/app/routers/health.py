"""Fail-closed liveness/readiness endpoints for the AIG bridge.

Exposure model:

* ``/livez`` -- public, constant, never contacts AIG or any store.
* ``/readyz`` -- public because kubelet and Docker probes cannot send
  credentials, but it only returns ``{"status": "ready"|"not_ready"}`` with
  200/503.  No versions, dataset identifiers, gate reasons or internal errors.
* ``/health`` -- the detailed gate report; requires the same bridge
  authentication as the scan routes (``aig:read`` scope for broker tokens).

``/readyz`` and ``/health`` share one short-lived probe cache
(``BRIDGE_HEALTH_CACHE_SECONDS``, default 5s, clamped to 0-30s) and coalesce
concurrent probes, so unauthenticated callers cannot amplify load onto AIG,
PostgreSQL or the dataset verifier.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import time

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from app.auth import (
    BrokerClaims,
    auth_is_configured,
    auth_is_required,
    replay_store_ready,
    require_bridge_api_key,
)
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
    try:
        upstream_ready = bool(await aig.health_check())
    except Exception as exc:
        logger.warning("AIG upstream health probe failed: %s", type(exc).__name__)
        upstream_ready = False
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

_DEFAULT_CACHE_SECONDS = 5.0
_MAX_CACHE_SECONDS = 30.0
_report_cache: dict[str | None, tuple[float, dict[str, object]]] = {}
_inflight: dict[str | None, asyncio.Future] = {}


def _cache_seconds() -> float:
    try:
        value = float(os.getenv("BRIDGE_HEALTH_CACHE_SECONDS", str(_DEFAULT_CACHE_SECONDS)))
    except ValueError:
        return _DEFAULT_CACHE_SECONDS
    if not math.isfinite(value):
        return _DEFAULT_CACHE_SECONDS
    return min(max(value, 0.0), _MAX_CACHE_SECONDS)


def reset_readiness_cache() -> None:
    """Drop cached probe results (tests and operational tooling)."""

    _report_cache.clear()
    _inflight.clear()


async def _cached_readiness_report(aig: AIGClient, capability: str | None) -> dict[str, object]:
    """Return a recent readiness report, running at most one probe at a time.

    Concurrent callers for the same capability await one shared probe task
    instead of each contacting AIG, the task registry and the replay store.
    A probe that raises is not cached.
    """

    ttl = _cache_seconds()
    cached = _report_cache.get(capability)
    if cached is not None and ttl > 0 and time.monotonic() - cached[0] < ttl:
        return dict(cached[1])

    loop = asyncio.get_running_loop()
    pending = _inflight.get(capability)
    if pending is None or pending.done() or pending.get_loop() is not loop:
        pending = asyncio.ensure_future(_readiness_report(aig, capability))
        _inflight[capability] = pending

        def _store(task: asyncio.Future, key: str | None = capability) -> None:
            if _inflight.get(key) is task:
                del _inflight[key]
            if not task.cancelled() and task.exception() is None:
                _report_cache[key] = (time.monotonic(), task.result())

        pending.add_done_callback(_store)
    # shield: a disconnecting caller must not cancel the probe other callers
    # are waiting on.
    return dict(await asyncio.shield(pending))


def _validated_capability(capability: str | None) -> str | None:
    # Unknown values are rejected before probing so arbitrary strings cannot
    # create cache entries or trigger probes.
    if capability is not None and capability not in _CAPABILITIES:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="unknown capability")
    return capability


async def _require_health_reader(
    claims: BrokerClaims | None = Depends(require_bridge_api_key),
) -> None:
    """Reuse the scan routes' authentication for the detailed report."""

    if claims is not None and "aig:read" not in claims.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="aig:read scope is required")


@router.get("/health", dependencies=[Depends(_require_health_reader)])
async def health_check(
    response: Response,
    capability: str | None = Query(default=None, max_length=32),
    aig: AIGClient = Depends(get_aig_client),
):
    """Authenticated, detailed dependency report without upstream payloads."""

    report = await _cached_readiness_report(aig, _validated_capability(capability))
    # Health is intentionally 503 when a scan dependency is not ready.  /livez
    # remains the process-only endpoint for orchestrator restart decisions.
    if not report["ready"]:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    response.headers["Cache-Control"] = "no-store"
    report["status"] = "ok" if report["ready"] else "degraded"
    # ``scan_ready`` is the field the AIDR core client gates scans on.
    report["scan_ready"] = report["ready"]
    report["version"] = "1.0.0"
    return report


@router.get("/livez")
async def liveness():
    """Process liveness; deliberately does not contact AIG or auth stores."""

    return {"status": "alive"}


@router.get("/readyz")
async def readiness(
    response: Response,
    capability: str | None = Query(default=None, max_length=32),
    aig: AIGClient = Depends(get_aig_client),
):
    """Unauthenticated probe: ``ready``/``not_ready`` only, from the shared cache.

    Orchestrator probes cannot authenticate, so this response carries no gate
    reasons, versions or dataset identifiers; operators read the
    authenticated ``/health`` endpoint for the detailed report.
    """

    report = await _cached_readiness_report(aig, _validated_capability(capability))
    response.headers["Cache-Control"] = "no-store"
    if not report["ready"]:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not_ready"}
    return {"status": "ready"}
