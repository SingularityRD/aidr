"""Incident adapter boundary for AIG findings.

The bridge does not own AIDR's incident database.  It emits deterministic,
tenant-scoped candidate records only; the control plane must validate,
deduplicate and persist them in its own transactional store.
"""

from __future__ import annotations

import hashlib
from typing import Any

from app.redaction import bounded_redacted, safe_text


def _severity(value: Any) -> str:
    normalized = safe_text(value, max_length=32).lower()
    return normalized if normalized in {"critical", "high", "medium", "low", "info", "none"} else "unknown"


def build_incident_candidates(
    *,
    tenant_id: str,
    task_id: str,
    scan_type: str,
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Map only actionable findings to stable, redacted incident candidates."""

    candidates: list[dict[str, Any]] = []
    for finding in findings[:200]:
        severity = _severity(finding.get("severity") or finding.get("risk"))
        if severity not in {"critical", "high", "medium"}:
            continue
        identity = str(
            finding.get("cve_id")
            or finding.get("id")
            or finding.get("category")
            or finding.get("title")
            or "finding"
        )
        dedupe_source = f"{tenant_id}:{scan_type}:{task_id}:{identity}"
        candidates.append(
            {
                "dedupe_key": hashlib.sha256(dedupe_source.encode("utf-8")).hexdigest(),
                "tenant_id": tenant_id,
                "task_id": task_id,
                "source": f"aig:{scan_type}",
                "severity": severity,
                "title": safe_text(finding.get("title") or finding.get("cve_id") or identity, max_length=256),
                "summary": safe_text(
                    finding.get("description")
                    or finding.get("summary")
                    or finding.get("finding")
                    or finding.get("risk")
                    or "AIG reported an actionable finding",
                    max_length=1_024,
                ),
                "evidence": bounded_redacted(
                    {
                        key: finding.get(key)
                        for key in ("cve_id", "package", "version", "category", "target_url", "fingerprint")
                        if key in finding
                    },
                    max_bytes=8_192,
                ),
            }
        )
    return candidates

