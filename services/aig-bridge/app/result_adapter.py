"""Typed, bounded AIG result adapters."""

from __future__ import annotations

from typing import Any

from app.incidents import build_incident_candidates
from app.redaction import bounded_redacted, safe_text


def _status(value: Any) -> str:
    """Normalize upstream state names to the public bridge contract."""

    normalized = safe_text(value or "running", max_length=32).lower()
    if normalized in {"done", "completed", "complete", "success", "succeeded"}:
        return "completed"
    if normalized in {"failed", "failure", "error", "cancelled", "canceled"}:
        return "failed"
    if normalized in {"queued", "pending", "doing", "running", "in_progress", "in-progress"}:
        return "running"
    return normalized or "running"


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _number(value: Any, default: float = 0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    return value


def _int(value: Any, default: int = 0) -> int:
    number = _number(value, default)
    try:
        return int(number)
    except (TypeError, ValueError, OverflowError):
        return default


def adapt_infra_result(task_id: str, tenant_id: str, result: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for raw in _list(result.get("findings"))[:200]:
        if not isinstance(raw, dict):
            continue
        if not isinstance(raw.get("cve_id"), str) or not isinstance(raw.get("package"), str):
            continue
        findings.append(
            {
                "cve_id": safe_text(raw.get("cve_id"), max_length=128),
                "package": safe_text(raw.get("package"), max_length=256),
                "version": safe_text(raw.get("version"), max_length=256),
                "severity": safe_text(raw.get("severity"), max_length=32).lower(),
                "description": safe_text(raw.get("description"), max_length=2_048),
                "remediation": safe_text(raw.get("remediation"), max_length=2_048),
            }
        )
    evidence = [bounded_redacted(item, max_bytes=16_384) for item in _list(result.get("results"))[:200] if isinstance(item, dict)]
    incidents = build_incident_candidates(tenant_id=tenant_id, task_id=task_id, scan_type="infra", findings=findings)
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    matched = result.get("total", len(findings))
    if isinstance(matched, bool) or not isinstance(matched, int) or matched < 0:
        matched = len(findings)
    return {
        "task_id": task_id,
        "status": _status(result.get("status")),
        "summary": {
            "total_cves": max(0, _int(summary.get("total_cves", matched), matched)),
            "matched": max(0, _int(summary.get("matched", matched), matched)),
            "critical": max(0, _int(summary.get("critical", 0))),
            "high": max(0, _int(summary.get("high", 0))),
            "medium": max(0, _int(summary.get("medium", 0))),
            "low": max(0, _int(summary.get("low", 0))),
        },
        "findings": findings,
        "evidence": evidence,
        "incident_candidates": incidents,
    }


def adapt_mcp_result(task_id: str, tenant_id: str, result: dict[str, Any]) -> dict[str, Any]:
    breakdown: list[dict[str, Any]] = []
    for raw in _list(result.get("category_breakdown"))[:200]:
        if not isinstance(raw, dict):
            continue
        breakdown.append(
            {
                "category": safe_text(raw.get("category") or raw.get("id") or "unknown", max_length=128),
                "risk": safe_text(raw.get("risk") or raw.get("severity") or "none", max_length=32).lower(),
                "findings": [safe_text(item, max_length=1_024) for item in _list(raw.get("findings"))[:50] if isinstance(item, (str, int, float))],
            }
        )
    evidence = [bounded_redacted(item, max_bytes=16_384) for item in _list(result.get("results"))[:200] if isinstance(item, dict)]
    incident_rows = [
        {**item, "severity": item.get("risk"), "category": item.get("category")}
        for item in breakdown
        if item.get("risk") in {"critical", "high", "medium"}
    ]
    return {
        "task_id": task_id,
        "status": _status(result.get("status")),
        "risk_score": max(0, min(100, _int(result.get("risk_score", result.get("score", 0))))),
        "category_breakdown": breakdown,
        "summary": safe_text(result.get("summary") or result.get("readme") or "", max_length=4_096),
        "evidence": evidence,
        "incident_candidates": build_incident_candidates(
            tenant_id=tenant_id, task_id=task_id, scan_type="mcp", findings=incident_rows
        ),
    }


def adapt_agent_result(task_id: str, tenant_id: str, result: dict[str, Any]) -> dict[str, Any]:
    raw_findings = _list(result.get("findings")) or _list(result.get("results"))
    findings = [bounded_redacted(item, max_bytes=16_384) for item in raw_findings[:200] if isinstance(item, dict)]
    return {
        "task_id": task_id,
        "status": _status(result.get("status")),
        "score": max(0, min(100, _int(result.get("score", result.get("risk_score", 0))))),
        "summary": safe_text(result.get("summary") or result.get("report") or "", max_length=4_096),
        "findings": findings,
        "evidence": [bounded_redacted(item, max_bytes=16_384) for item in _list(result.get("evidence"))[:200] if isinstance(item, dict)],
        "incident_candidates": build_incident_candidates(
            tenant_id=tenant_id, task_id=task_id, scan_type="agent", findings=findings
        ),
    }


def adapt_jailbreak_result(task_id: str, tenant_id: str, result: dict[str, Any]) -> dict[str, Any]:
    rows = _list(result.get("findings")) or _list(result.get("results"))
    findings = [bounded_redacted(item, max_bytes=16_384) for item in rows[:200] if isinstance(item, dict)]
    return {
        "task_id": task_id,
        "status": _status(result.get("status")),
        "score": max(0, min(100, _int(result.get("score", result.get("risk_score", 0))))),
        "total": max(0, _int(result.get("total"), len(findings))),
        "passed": max(0, _int(result.get("passed"))),
        "failed": max(0, _int(result.get("failed"))),
        "summary": safe_text(result.get("summary") or result.get("report") or "", max_length=4_096),
        "findings": findings,
        "evidence": [bounded_redacted(item, max_bytes=16_384) for item in _list(result.get("evidence"))[:200] if isinstance(item, dict)],
        "incident_candidates": build_incident_candidates(
            tenant_id=tenant_id, task_id=task_id, scan_type="jailbreak", findings=findings
        ),
    }
