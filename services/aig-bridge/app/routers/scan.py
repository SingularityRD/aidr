"""
Scan endpoints — translate AIDR scan requests into AIG's async task workflow.

All long-running scans follow the same pattern:
  1. POST to create an async task → returns a task_id
  2. GET /{task_id} to poll for results (status: running/completed/failed)
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Path

from app.models.schemas import (
    AgentScanRequest,
    AgentScanResponse,
    InfraScanRequest,
    InfraScanResponse,
    InfraScanResultResponse,
    JailbreakEvalRequest,
    JailbreakEvalResponse,
    MCPScanRequest,
    MCPScanResponse,
    MCPScanResultResponse,
    ThreatIntelResponse,
    TaskStatusResponse,
)
from app.utils.aig_client import AIGClient, get_aig_client

logger = logging.getLogger("aig-bridge.scan")
router = APIRouter()


# ═══════════════════════════════════════════════════════════════════════════
# 1. Infrastructure CVE Scan
# ═══════════════════════════════════════════════════════════════════════════

@router.post(
    "/scan/infra",
    response_model=InfraScanResponse,
    summary="Scan AI infrastructure for CVEs",
    description=(
        "Submit AI infrastructure components for CVE scanning. "
        "AIG scans the given targets against its 1300+ CVE database. "
        "Returns a task_id for result polling."
    ),
)
async def scan_infra(
    request: InfraScanRequest,
    aig: AIGClient = Depends(get_aig_client),
):
    """
    Submit an infrastructure CVE scan task.

    AIG's Go backend evaluates targets against its vulnerability fingerprints
    and returns matched CVEs with severity ratings and remediation guidance.
    """
    logger.info(
        "Infra scan requested — targets=%s, scan_type=%s",
        request.targets,
        request.scan_type,
    )

    session_id = await aig.create_scan_task(
        task_type="ai_infra_scan",
        content={
            "targets": request.targets,
            "scan_type": request.scan_type,
            "options": request.options or {},
        },
    )

    return InfraScanResponse(
        task_id=session_id,
        status="running",
        estimated_seconds=120,
    )


@router.get(
    "/scan/infra/{task_id}",
    response_model=InfraScanResultResponse,
    summary="Get infra scan results",
)
async def get_infra_scan_result(
    task_id: str = Path(..., description="Task ID from POST /scan/infra"),
    aig: AIGClient = Depends(get_aig_client),
):
    """Poll the result of an infrastructure CVE scan task."""
    result = await aig.get_task_result(task_id)
    return InfraScanResultResponse(
        task_id=task_id,
        status=result["status"],
        summary=result.get("summary", {}),
        findings=result.get("findings", []),
    )


# ═══════════════════════════════════════════════════════════════════════════
# 2. MCP Server Security Scan
# ═══════════════════════════════════════════════════════════════════════════

@router.post(
    "/scan/mcp",
    response_model=MCPScanResponse,
    summary="Scan MCP server for security risks",
    description=(
        "Scan an MCP server (remote URL or source code directory) across "
        "14 risk categories including prompt injection, data exfiltration, "
        "privilege escalation, and tool abuse. Requires an eval LLM model "
        "configuration for dynamic analysis."
    ),
)
async def scan_mcp(
    request: MCPScanRequest,
    aig: AIGClient = Depends(get_aig_client),
):
    """
    Submit an MCP server security scan task.

    Supports two target types:
    - ``url``: Remote MCP server (SSE/streamable HTTP endpoint)
    - ``source``: Local MCP source code directory (zip uploaded first)

    The eval_model configuration is forwarded to AIG's analysis pipeline
    for dynamic evaluation of tool responses and prompt handling.
    """
    logger.info(
        "MCP scan requested — target_type=%s, categories=%s",
        request.target_type,
        request.categories,
    )

    content = {
        "target_type": request.target_type,
        "target": request.target,
        "categories": request.categories or [],
        "headers": request.headers or {},
        "eval_model": request.eval_model.model_dump() if request.eval_model else None,
    }

    session_id = await aig.create_scan_task(
        task_type="mcp_scan",
        content=content,
    )

    return MCPScanResponse(task_id=session_id, status="running")


@router.get(
    "/scan/mcp/{task_id}",
    response_model=MCPScanResultResponse,
    summary="Get MCP scan results",
)
async def get_mcp_scan_result(
    task_id: str = Path(..., description="Task ID from POST /scan/mcp"),
    aig: AIGClient = Depends(get_aig_client),
):
    """Poll the result of an MCP server security scan."""
    result = await aig.get_task_result(task_id)
    return MCPScanResultResponse(
        task_id=task_id,
        status=result["status"],
        risk_score=result.get("risk_score", 0),
        category_breakdown=result.get("category_breakdown", []),
        summary=result.get("summary", ""),
    )


# ═══════════════════════════════════════════════════════════════════════════
# 3. Agent Scan
# ═══════════════════════════════════════════════════════════════════════════

@router.post(
    "/scan/agent",
    response_model=AgentScanResponse,
    summary="Run Agent-Scan on AI agent workflows",
    description=(
        "Submit an AI agent (Dify, Coze, custom HTTP) for security scanning. "
        "AIG's agent-scan framework tests for prompt injection, privilege "
        "escalation, data leakage, and other agent-specific vulnerabilities."
    ),
)
async def scan_agent(
    request: AgentScanRequest,
    aig: AIGClient = Depends(get_aig_client),
):
    """Submit an agent security scan task."""
    logger.info(
        "Agent scan requested — provider=%s",
        request.agent_config.get("provider", "unknown") if request.agent_config else "pre-saved",
    )

    content = {}
    if request.agent_id:
        content["agent_id"] = request.agent_id
    if request.agent_config:
        content["agent_config_yaml"] = _dict_to_yaml(request.agent_config)
    if request.eval_model:
        content["eval_model"] = request.eval_model.model_dump()
    content["language"] = request.language or "en"
    content["prompt"] = request.prompt or ""

    session_id = await aig.create_scan_task(
        task_type="agent_scan",
        content=content,
    )

    return AgentScanResponse(task_id=session_id, status="running")


# ═══════════════════════════════════════════════════════════════════════════
# 4. Jailbreak Evaluation
# ═══════════════════════════════════════════════════════════════════════════

@router.post(
    "/evaluate/jailbreak",
    response_model=JailbreakEvalResponse,
    summary="Test prompt jailbreak resistance",
    description=(
        "Evaluate an LLM endpoint for jailbreak vulnerability using AIG's "
        "PromptSecurity evaluation suite. Tests include direct jailbreak "
        "attempts, prompt leaks, role-play bypasses, and more."
    ),
)
async def evaluate_jailbreak(
    request: JailbreakEvalRequest,
    aig: AIGClient = Depends(get_aig_client),
):
    """Submit a jailbreak evaluation task."""
    logger.info(
        "Jailbreak eval requested — test_suites=%s, language=%s",
        request.test_suites,
        request.language,
    )

    content = {
        "model": request.model,
        "token": request.token,
        "base_url": request.base_url,
        "test_suites": request.test_suites,
        "language": request.language or "en",
    }

    session_id = await aig.create_scan_task(
        task_type="model_redteam_report",
        content=content,
    )

    return JailbreakEvalResponse(task_id=session_id, status="running")


# ═══════════════════════════════════════════════════════════════════════════
# 5. Threat Intelligence Sync
# ═══════════════════════════════════════════════════════════════════════════

@router.get(
    "/threats/latest",
    response_model=ThreatIntelResponse,
    summary="Get latest threat intelligence and rules",
    description=(
        "Returns the latest threat intelligence from AIG for AIDR to sync: "
        "CVE counts, MCP risk category definitions, and threat patterns that "
        "AIDR can encode as YAML threat rules. Called periodically by AIDR's "
        "threat sync module."
    ),
)
async def get_latest_threats(
    aig: AIGClient = Depends(get_aig_client),
):
    """Fetch latest threat definitions and rules from AIG."""
    threats = await aig.get_latest_threats()
    return ThreatIntelResponse(
        rules_version=threats.get("rules_version", ""),
        cve_count=threats.get("cve_count", 0),
        mcp_risk_categories=threats.get("mcp_risk_categories", []),
        threat_rules=threats.get("threat_rules", []),
        last_updated=threats.get("last_updated", ""),
    )


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _dict_to_yaml(d: dict) -> str:
    """Minimal dict-to-YAML conversion for simple agent configs.

    This is a placeholder that produces basic YAML. For production, install
    ``PyYAML`` and use ``yaml.dump(d, default_flow_style=False)``.
    """
    if not d:
        return ""
    lines = []
    for key, value in d.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            for k, v in value.items():
                lines.append(f"  {k}: {v}")
        else:
            lines.append(f"{key}: {value}")
    return "\n".join(lines)
