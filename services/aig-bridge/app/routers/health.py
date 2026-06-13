"""
Health check endpoint.

Used by AIDR to verify connectivity before issuing scan requests, and by
Docker HEALTHCHECK to monitor container liveness.
"""

import logging

from fastapi import APIRouter, Depends

from app.utils.aig_client import AIGClient, get_aig_client

logger = logging.getLogger("aig-bridge.health")

router = APIRouter()


@router.get("/health")
async def health_check(aig: AIGClient = Depends(get_aig_client)):
    """
    Health check endpoint.

    Returns the status of the bridge service and its connection to the
    upstream AIG server.
    """
    aig_status = "unknown"
    aig_agent_status = "unknown"
    cve_count = 0

    try:
        # Probe the upstream AIG server
        aig_health = await aig.health_check()
        aig_status = "connected" if aig_health else "disconnected"
    except Exception as exc:
        logger.warning("AIG server health check failed: %s", exc)
        aig_status = "disconnected"

    try:
        # Fetch CVE count via latest threats endpoint
        threats = await aig.get_latest_threats()
        cve_count = threats.get("cve_count", 0)
    except Exception:
        pass

    return {
        "status": "ok",
        "version": "1.0.0",
        "aig_server": aig_status,
        "aig_agent": aig_agent_status,
        "scan_ready": aig_status == "connected",
        "cve_count": cve_count,
    }
