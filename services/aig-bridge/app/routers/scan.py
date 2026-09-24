"""
Scan endpoints — translate AIDR scan requests into AIG's async task workflow.

All long-running scans follow the same pattern:
  1. POST to create an async task → returns a task_id
  2. GET /{task_id} to poll for results (status: running/completed/failed)
"""

import logging
import asyncio
import hashlib
import json
import os
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Path
from tenacity import RetryError
import yaml

from app.auth import RequestContext, auth_mode, get_request_context
from app.models.schemas import (
    AgentScanRequest,
    AgentScanResponse,
    AgentScanResultResponse,
    InfraScanRequest,
    InfraScanResponse,
    InfraScanResultResponse,
    JailbreakEvalRequest,
    JailbreakEvalResponse,
    JailbreakResultResponse,
    MCPScanRequest,
    MCPScanResponse,
    MCPScanResultResponse,
    ThreatIntelResponse,
    TaskStatusResponse,
)
from app.utils.aig_client import AIGClient, AIGClientError, AIGSubmissionAmbiguous, get_aig_client
from app.task_registry import (
    QuotaExceeded,
    SubmissionInProgress,
    TaskRegistryUnavailable,
    task_registry,
)
from app.result_adapter import (
    adapt_agent_result,
    adapt_infra_result,
    adapt_jailbreak_result,
    adapt_mcp_result,
)
from app.validation import (
    assert_source_path_safe,
    runtime_egress_ready,
    validate_forward_headers,
    validate_agent_config_targets,
    validate_remote_url,
    target_policy,
)

logger = logging.getLogger("aig-bridge.scan")
router = APIRouter()
_submit_lock = asyncio.Lock()


async def _submit_task(
    *,
    aig: AIGClient,
    context: RequestContext,
    task_type: str,
    content: Dict[str, Any],
) -> str:
    """Submit once and associate the upstream task with its tenant."""

    request_hash = hashlib.sha256(
        json.dumps(
            {"task_type": task_type, "content": content},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()
    if auth_mode() == "broker" and os.getenv("BRIDGE_REQUIRE_IDEMPOTENCY", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    } and not (context.idempotency_key or context.job_id):
        raise HTTPException(status_code=400, detail="Idempotency-Key is required for broker task submission")
    async with _submit_lock:
        try:
            reservation = task_registry.reserve_submission(
                context.tenant_id,
                context.idempotency_key or context.job_id,
                request_hash,
                task_type=task_type,
            )
        except QuotaExceeded as exc:
            raise HTTPException(status_code=429, detail="tenant scan quota exceeded") from exc
        except SubmissionInProgress as exc:
            raise HTTPException(
                status_code=409,
                detail="idempotent task submission is already in progress",
                headers={"Retry-After": "1"},
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=409,
                detail="idempotency key was already used for a different request",
            ) from exc
        except TaskRegistryUnavailable as exc:
            raise HTTPException(status_code=503, detail="task registry is unavailable") from exc
        if not reservation.is_new:
            if not reservation.task_id:
                raise HTTPException(status_code=503, detail="task registry returned an invalid reservation")
            return reservation.task_id
        payload = dict(content)
        payload["tenant_id"] = context.tenant_id
        try:
            session_id = await aig.create_scan_task(task_type=task_type, content=payload)
        except AIGSubmissionAmbiguous as exc:
            # AIG has no idempotency-key contract. Retain the reservation so a
            # retry cannot create a second task after a lost/invalid response.
            raise HTTPException(
                status_code=503,
                detail="AIG submission outcome is unknown; retry is blocked pending reconciliation",
            ) from exc
        except RetryError as exc:
            last_error = exc.last_attempt.exception()
            if isinstance(last_error, AIGSubmissionAmbiguous):
                raise HTTPException(
                    status_code=503,
                    detail="AIG submission outcome is unknown; retry is blocked pending reconciliation",
                ) from exc
            try:
                task_registry.release_submission(reservation)
            except TaskRegistryUnavailable:
                logger.error("task submission reservation release failed")
            raise HTTPException(status_code=502, detail="AIG upstream is unavailable") from exc
        except AIGClientError as exc:
            try:
                task_registry.release_submission(reservation)
            except TaskRegistryUnavailable:
                logger.error("task submission reservation release failed")
            raise HTTPException(
                status_code=502,
                detail="AIG upstream rejected or could not accept the scan request",
            ) from exc
        except Exception as exc:
            # Unexpected failures after entering the client are ambiguous too.
            # Prefer an auditable stuck reservation over a duplicate scan.
            logger.error("AIG task submission failed with an unknown outcome")
            raise HTTPException(
                status_code=503,
                detail="AIG submission outcome is unknown; retry is blocked pending reconciliation",
            ) from exc
        try:
            return task_registry.finalize_submission(reservation, session_id)
        except (KeyError, TaskRegistryUnavailable) as exc:
            # Do not delete the reservation: retaining it prevents a retry
            # from creating a second upstream task after an ambiguous commit.
            raise HTTPException(status_code=503, detail="task registry is unavailable") from exc


def _assert_task_owner(task_id: str, context: RequestContext) -> None:
    try:
        task_registry.assert_owner(task_id, context.tenant_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="task not found") from exc
    except TaskRegistryUnavailable as exc:
        raise HTTPException(status_code=503, detail="task registry is unavailable") from exc


def _sync_registry_status(task_id: str, context: RequestContext, status_value: Any) -> None:
    normalized = str(status_value or "running").lower()
    state = "completed" if normalized == "completed" else "failed" if normalized in {"failed", "cancelled", "canceled"} else "running"
    try:
        task_registry.update_status(task_id, context.tenant_id, state)
    except (KeyError, TaskRegistryUnavailable, ValueError):
        logger.warning("task registry status update failed for owned task")


@router.post(
    "/tasks/{task_id}/cancel",
    response_model=TaskStatusResponse,
    summary="Cancel an owned AIG task",
)
async def cancel_task(
    task_id: str = Path(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
    aig: AIGClient = Depends(get_aig_client),
    context: RequestContext = Depends(get_request_context),
):
    """Set a durable cancellation intent before asking AIG to terminate.

    The registry intent is retained if the upstream call fails, allowing a
    reconciler/kill-switch worker to retry without giving another tenant access
    to the task.
    """

    _assert_task_owner(task_id, context)
    try:
        cancel_requested = task_registry.request_cancel(task_id, context.tenant_id)
    except TaskRegistryUnavailable as exc:
        raise HTTPException(status_code=503, detail="task registry is unavailable") from exc
    if not cancel_requested:
        return TaskStatusResponse(task_id=task_id, status="completed", error="task is already terminal")
    try:
        await aig.cancel_task(task_id, username=os.getenv("AIG_UPSTREAM_USERNAME", "api_user"))
    except Exception as exc:
        logger.warning("AIG cancellation request failed: %s", type(exc).__name__)
        return TaskStatusResponse(task_id=task_id, status="cancel_requested", error="upstream cancellation pending")
    try:
        task_registry.update_status(task_id, context.tenant_id, "cancelled")
    except TaskRegistryUnavailable as exc:
        raise HTTPException(status_code=503, detail="task registry is unavailable") from exc
    return TaskStatusResponse(task_id=task_id, status="cancelled")


# ═══════════════════════════════════════════════════════════════════════════
# 1. Infrastructure CVE Scan
# ═══════════════════════════════════════════════════════════════════════════

@router.post(
    "/scan/infra",
    response_model=InfraScanResponse,
    summary="Scan AI infrastructure for CVEs",
    description=(
        "Submit AI infrastructure components for CVE scanning. "
        "AIG scans the given targets against the configured, versioned threat dataset. "
        "Returns a task_id for result polling."
    ),
)
async def scan_infra(
    request: InfraScanRequest,
    aig: AIGClient = Depends(get_aig_client),
    context: RequestContext = Depends(get_request_context),
):
    """
    Submit an infrastructure CVE scan task.

    AIG's Go backend evaluates targets against its vulnerability fingerprints
    and returns matched CVEs with severity ratings and remediation guidance.
    """
    logger.info("Infra scan requested — target_count=%s, scan_type=%s", len(request.targets), request.scan_type)

    # The upstream treats every non-URL value as a host or CIDR and may expand
    # it before scanning. Require an explicit validated URL so bare private
    # hosts and broad CIDRs can never bypass the egress boundary.
    validated_targets = []
    target_policies = []
    for target in request.targets:
        validated_targets.append(validate_remote_url(target, field="targets"))
        target_policies.append(target_policy(target, field="targets"))

    options = request.options or {}
    upstream_content: Dict[str, Any] = {"target": validated_targets}
    if target_policies:
        upstream_content["target_policy"] = target_policies

    # AIG's v4 task contract is an allow-list, not AIDR's historical
    # `{targets, scan_type, options}` shape.  Translate only supported fields
    # so arbitrary caller data is never silently forwarded to the worker.
    raw_headers = options.get("headers")
    if raw_headers is not None:
        if not isinstance(raw_headers, dict):
            raise HTTPException(status_code=422, detail="options.headers must be an object")
        upstream_content["headers"] = validate_forward_headers(
            {str(key): str(value) for key, value in raw_headers.items()}
        )

    raw_timeout = options.get("timeout", 30)
    if isinstance(raw_timeout, bool) or not isinstance(raw_timeout, int) or not 1 <= raw_timeout <= 600:
        raise HTTPException(status_code=422, detail="options.timeout must be an integer between 1 and 600")
    upstream_content["timeout"] = raw_timeout

    raw_model = options.get("model")
    if raw_model is not None:
        if not isinstance(raw_model, dict):
            raise HTTPException(status_code=422, detail="options.model must be an object")
        model: Dict[str, str] = {}
        for key in ("model", "token", "base_url"):
            value = raw_model.get(key)
            if value is None:
                continue
            if not isinstance(value, str) or not value.strip() or len(value) > 8_192:
                raise HTTPException(status_code=422, detail=f"options.model.{key} is invalid")
            model[key] = value.strip()
        if "base_url" in model:
            model["base_url"] = validate_remote_url(model["base_url"], field="options.model.base_url")
        upstream_content["model"] = model

    session_id = await _submit_task(
        aig=aig,
        context=context,
        task_type="ai_infra_scan",
        content=upstream_content,
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
    task_id: str = Path(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
        description="Task ID from POST /scan/infra",
    ),
    aig: AIGClient = Depends(get_aig_client),
    context: RequestContext = Depends(get_request_context),
):
    """Poll the result of an infrastructure CVE scan task."""
    _assert_task_owner(task_id, context)
    result = await aig.get_task_result(task_id)
    adapted = adapt_infra_result(task_id, context.tenant_id, result)
    _sync_registry_status(task_id, context, adapted["status"])
    return InfraScanResultResponse(**adapted)


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
    context: RequestContext = Depends(get_request_context),
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

    target = request.target
    target_headers = request.headers or {}
    remote_policy = None
    if request.target_type == "url":
        target = validate_remote_url(target, field="target")
        remote_policy = target_policy(target, field="target")
        target_headers = validate_forward_headers(target_headers)
    else:
        # Source paths are shared-volume references. Re-resolve and reject
        # symlinks immediately before dispatch to close upload/scan TOCTOU.
        target = assert_source_path_safe(target, tenant_id=context.tenant_id)
        if request.headers:
            raise HTTPException(
                status_code=422,
                detail="headers are only supported for URL targets",
            )
    # Tencent AIG v4.5.1 uses the taskapi fields `prompt`, `attachments`,
    # `model`, `thread`, `language` and `headers`; it does not understand the
    # bridge's historical target_type/categories/eval_model shape. URL scans
    # put the remote MCP URL in prompt, while source scans reference the
    # validated tenant-relative upload reference as an attachment.
    prompt = target if request.target_type == "url" else "Audit the uploaded MCP source."
    if request.categories and request.target_type == "url":
        # AIG v4.5.1 derives the remote server URL directly from ``prompt``;
        # appending instructions would make the URL invalid. The upstream
        # task contract has no category allow-list field, so retain the
        # request for API compatibility and run the full AIG category set.
        logger.info(
            "AIG v4 MCP task has no category filter; scanning full set (requested=%s)",
            request.categories,
        )
    content: Dict[str, Any] = {
        "prompt": prompt,
        "thread": 4,
        "language": "en",
        "headers": target_headers,
    }
    if request.target_type == "source":
        content["attachments"] = target
    if remote_policy:
        content["target_policy"] = remote_policy
    if request.eval_model:
        validate_remote_url(request.eval_model.base_url, field="eval_model.base_url")
        content["eval_model_policy"] = target_policy(request.eval_model.base_url, field="eval_model.base_url")
        content["model"] = request.eval_model.model_dump()

    session_id = await _submit_task(
        aig=aig, context=context, task_type="mcp_scan", content=content
    )

    return MCPScanResponse(task_id=session_id, status="running")


@router.get(
    "/scan/mcp/{task_id}",
    response_model=MCPScanResultResponse,
    summary="Get MCP scan results",
)
async def get_mcp_scan_result(
    task_id: str = Path(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
        description="Task ID from POST /scan/mcp",
    ),
    aig: AIGClient = Depends(get_aig_client),
    context: RequestContext = Depends(get_request_context),
):
    """Poll the result of an MCP server security scan."""
    _assert_task_owner(task_id, context)
    result = await aig.get_task_result(task_id)
    adapted = adapt_mcp_result(task_id, context.tenant_id, result)
    _sync_registry_status(task_id, context, adapted["status"])
    return MCPScanResultResponse(**adapted)


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
    context: RequestContext = Depends(get_request_context),
):
    """Submit an agent security scan task."""
    egress_ready, egress_reason = runtime_egress_ready()
    if not egress_ready:
        raise HTTPException(status_code=503, detail=egress_reason)
    logger.info(
        "Agent scan requested — provider=%s",
        request.agent_config.get("provider", "unknown") if request.agent_config else "pre-saved",
    )

    content = {}
    if request.agent_id:
        content["agent_id"] = request.agent_id
    if request.agent_config:
        validate_agent_config_targets(request.agent_config)
        content["agent_config_yaml"] = _dict_to_yaml(request.agent_config)
    if request.eval_model:
        content["eval_model_policy"] = target_policy(
            request.eval_model.base_url, field="eval_model.base_url"
        )
        content["eval_model"] = request.eval_model.model_dump()
    if request.agent_config:
        content["agent_config"] = content.pop("agent_config_yaml")
    content["language"] = request.language or "en"
    content["prompt"] = request.prompt or ""

    session_id = await _submit_task(
        aig=aig, context=context, task_type="agent_scan", content=content
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
    context: RequestContext = Depends(get_request_context),
):
    """Submit a jailbreak evaluation task."""
    logger.info(
        "Jailbreak eval requested — test_suites=%s, language=%s",
        request.test_suites,
        request.language,
    )

    target_meta = target_policy(request.target, field="target")
    base_meta = target_policy(request.base_url, field="base_url")
    content = {
        "model": [
            {
                "model": request.model,
                "token": request.token,
                "base_url": request.base_url,
            }
        ],
        "dataset": {
            "dataFile": request.test_suites,
            "numPrompts": 100,
            "randomSeed": 42,
        },
        "techniques": [],
        "language": request.language or "en",
        "target_policy": target_meta,
        "base_url_policy": base_meta,
    }
    if request.eval_model:
        validate_remote_url(request.eval_model.base_url, field="eval_model.base_url")
        content["eval_model_policy"] = target_policy(request.eval_model.base_url, field="eval_model.base_url")
        content["eval_model"] = request.eval_model.model_dump()

    session_id = await _submit_task(
        aig=aig, context=context, task_type="model_redteam_report", content=content
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
    _context: RequestContext = Depends(get_request_context),
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

@router.get(
    "/scan/agent/{task_id}",
    summary="Get Agent-Scan results",
)
async def get_agent_scan_result(
    task_id: str = Path(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
        description="Task ID from POST /scan/agent",
    ),
    aig: AIGClient = Depends(get_aig_client),
    context: RequestContext = Depends(get_request_context),
):
    """Poll an Agent-Scan task using the same upstream result contract."""
    _assert_task_owner(task_id, context)
    result = await aig.get_task_result(task_id)
    adapted = adapt_agent_result(task_id, context.tenant_id, result)
    _sync_registry_status(task_id, context, adapted["status"])
    return AgentScanResultResponse(**adapted)


@router.get(
    "/evaluate/jailbreak/{task_id}",
    response_model=JailbreakResultResponse,
    summary="Get jailbreak evaluation results",
)
async def get_jailbreak_result(
    task_id: str = Path(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
        description="Task ID from POST /evaluate/jailbreak",
    ),
    aig: AIGClient = Depends(get_aig_client),
    context: RequestContext = Depends(get_request_context),
):
    """Poll a jailbreak evaluation using the same upstream result contract."""
    _assert_task_owner(task_id, context)
    result = await aig.get_task_result(task_id)
    adapted = adapt_jailbreak_result(task_id, context.tenant_id, result)
    _sync_registry_status(task_id, context, adapted["status"])
    return JailbreakResultResponse(**adapted)


def _dict_to_yaml(d: dict) -> str:
    """Serialize agent configuration with a real YAML implementation."""

    return yaml.safe_dump(
        d,
        default_flow_style=False,
        sort_keys=True,
        allow_unicode=True,
    )
