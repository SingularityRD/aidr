"""
Pydantic models for AIG Bridge request/response schemas.

All models follow the AIG common response format:
{ "status": 0, "message": "...", "data": {...} }
"""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

import json

from pydantic import BaseModel, Field, field_validator, model_validator


# ── Common ──────────────────────────────────────────────────────────────────

class TaskStatusResponse(BaseModel):
    """Generic task status response."""
    task_id: str = Field(..., description="AIG task session ID")
    status: str = Field(..., description="Task status: running, completed, failed")
    error: Optional[str] = Field(None, description="Error message if failed")


class UploadResponse(BaseModel):
    """Result of a content-addressed tenant upload."""

    upload_id: str
    sha256: str
    bytes: int = Field(..., ge=0)
    source_path: str
    archive_kind: str
    archive_entries: int = Field(..., ge=0)


# ── Eval Model Configuration ────────────────────────────────────────────────

class EvalModelConfig(BaseModel):
    """LLM model configuration for evaluation/scanning."""
    model: str = Field(..., min_length=1, max_length=256, description="Model name (e.g., gpt-4, claude-3)")
    token: str = Field(..., min_length=1, max_length=8_192, description="API authentication token")
    base_url: str = Field(..., min_length=1, max_length=2_048, description="API base URL")


# ═════════════════════════════════════════════════════════════════════════════
# 1. Infrastructure CVE Scan
# ═════════════════════════════════════════════════════════════════════════════

class InfraScanRequest(BaseModel):
    """Request model for AI infrastructure CVE scan."""
    targets: List[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of infrastructure targets (URLs, IPs, image names)",
        examples=[["https://my-ml-server.com:8080", "triton-inference-server:2.30.0"]],
    )
    scan_type: Literal["quick", "standard", "full"] = Field(
        default="full",
        description="Scan depth: quick, standard, full",
    )
    options: Optional[Dict[str, Any]] = Field(
        default=None,
        description=(
            "AIG-compatible options: timeout (1-600), headers, and optional "
            "model {model, token, base_url}; unknown keys are ignored"
        ),
    )

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, value: List[str]) -> List[str]:
        normalized = [item.strip() for item in value]
        if any(not item or len(item) > 512 for item in normalized):
            raise ValueError("each target must be between 1 and 512 characters")
        return normalized

    @field_validator("options")
    @classmethod
    def limit_options(cls, value: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if value is not None and len(json.dumps(value, default=str)) > 131_072:
            raise ValueError("scan options are too large")
        return value


class InfraScanResponse(BaseModel):
    """Response after submitting an infra scan."""
    task_id: str = Field(..., description="AIG task session ID for polling")
    status: str = Field(default="running", description="Task status")
    estimated_seconds: int = Field(default=120, description="Estimated scan duration")


class CveFinding(BaseModel):
    """A single CVE finding."""
    cve_id: str = Field(..., description="CVE identifier", examples=["CVE-2024-XXXX"])
    package: str = Field(..., description="Affected package name")
    version: str = Field(..., description="Affected version")
    severity: str = Field(..., description="Severity: critical, high, medium, low")
    description: str = Field(..., description="Vulnerability description")
    remediation: str = Field(..., description="Remediation guidance")


class InfraScanSummary(BaseModel):
    """Summary statistics for infra scan results."""
    total_cves: int = Field(..., description="Total CVEs checked")
    matched: int = Field(..., description="CVEs matched against targets")
    critical: int = Field(default=0, description="Critical severity count")
    high: int = Field(default=0, description="High severity count")
    medium: int = Field(default=0, description="Medium severity count")
    low: int = Field(default=0, description="Low severity count")


class InfraScanResultResponse(BaseModel):
    """Response model for infra scan results."""
    task_id: str = Field(..., description="AIG task session ID")
    status: str = Field(..., description="Task status: running, completed, failed")
    summary: Optional[InfraScanSummary] = Field(None, description="Scan summary statistics")
    findings: List[CveFinding] = Field(default_factory=list, description="Matched CVE findings")
    evidence: List[Dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Raw, non-secret AIG fingerprint evidence (target URL, title, "
            "HTTP status, and matched fingerprint metadata)"
        ),
    )
    incident_candidates: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Redacted candidates for the AIDR incident adapter; not persisted by the bridge",
    )


# ═════════════════════════════════════════════════════════════════════════════
# 2. MCP Server Security Scan
# ═════════════════════════════════════════════════════════════════════════════

class MCPScanRequest(BaseModel):
    """Request model for MCP server security scan."""
    target_type: str = Field(
        ...,
        description="Type of target: 'url' for remote MCP, 'source' for code",
        pattern="^(url|source)$",
    )
    target: str = Field(..., min_length=1, max_length=2_048, description="MCP server URL or source path")
    headers: Optional[Dict[str, str]] = Field(
        default=None,
        description="HTTP headers for remote MCP connection",
    )
    categories: Optional[List[str]] = Field(
        default=None,
        max_length=32,
        description="Risk categories to scan (default: all 14 categories)",
        examples=[["prompt_injection", "data_exfiltration", "privilege_escalation"]],
    )
    eval_model: Optional[EvalModelConfig] = Field(
        default=None,
        description="LLM model for dynamic evaluation (required for remote MCP scan)",
    )

    @field_validator("target")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        return value.strip()

    @field_validator("categories")
    @classmethod
    def validate_categories(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return value
        normalized = [item.strip() for item in value]
        if any(not item or len(item) > 128 for item in normalized):
            raise ValueError("categories must be non-empty and at most 128 characters")
        return normalized

    @field_validator("headers")
    @classmethod
    def validate_header_values(cls, value: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        if value is not None and len(value) > 64:
            raise ValueError("too many target headers")
        return value


class MCPScanResponse(BaseModel):
    """Response after submitting an MCP scan."""
    task_id: str = Field(..., description="AIG task session ID for polling")
    status: str = Field(default="running", description="Task status")


class CategoryBreakdown(BaseModel):
    """Risk assessment for a single MCP category."""
    category: str = Field(..., description="Category identifier")
    risk: str = Field(..., description="Risk level: critical, high, medium, low, none")
    findings: List[str] = Field(default_factory=list, description="Specific findings")


class MCPScanResultResponse(BaseModel):
    """Response model for MCP scan results."""
    task_id: str = Field(..., description="AIG task session ID")
    status: str = Field(..., description="Task status: running, completed, failed")
    risk_score: int = Field(default=0, description="Overall risk score (0-100)")
    category_breakdown: List[CategoryBreakdown] = Field(
        default_factory=list,
        description="Per-category risk breakdown",
    )
    summary: str = Field(default="", description="Human-readable scan summary")
    evidence: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Non-secret raw AIG findings preserved for audit/demo evidence",
    )
    incident_candidates: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Redacted candidates for the AIDR incident adapter; not persisted by the bridge",
    )


# ═════════════════════════════════════════════════════════════════════════════
# 3. Agent Scan
# ═════════════════════════════════════════════════════════════════════════════

class AgentScanRequest(BaseModel):
    """Request model for AI agent security scan."""
    agent_id: Optional[str] = Field(
        default=None,
        description="Pre-saved agent configuration ID (mutually exclusive with agent_config)",
    )
    agent_config: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Inline agent configuration (YAML dict, mutually exclusive with agent_id)",
    )
    eval_model: Optional[EvalModelConfig] = Field(
        default=None,
        description="Evaluation model configuration (falls back to AIG default if omitted)",
    )
    language: Optional[str] = Field(default="en", max_length=16, description="Output language: zh, en")
    prompt: Optional[str] = Field(
        default="",
        max_length=16_384,
        description="Additional scan instructions/prompt",
    )

    @model_validator(mode="after")
    def validate_target(self) -> "AgentScanRequest":
        if bool(self.agent_id) == bool(self.agent_config):
            raise ValueError("provide exactly one of agent_id or agent_config")
        if self.agent_id:
            raise ValueError("pre-saved agent_id is unavailable until configs are tenant scoped")
        if self.agent_config and len(json.dumps(self.agent_config, default=str)) > 131_072:
            raise ValueError("agent_config is too large")
        return self


class AgentScanResponse(BaseModel):
    """Response after submitting an agent scan."""
    task_id: str = Field(..., description="AIG task session ID for polling")
    status: str = Field(default="running", description="Task status")


class AgentScanResultResponse(BaseModel):
    """Typed and redacted Agent-Scan result envelope."""

    task_id: str
    status: str
    score: int = Field(default=0, ge=0, le=100)
    summary: str = ""
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    incident_candidates: List[Dict[str, Any]] = Field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════════════
# 4. Jailbreak Evaluation
# ═════════════════════════════════════════════════════════════════════════════

class JailbreakEvalRequest(BaseModel):
    """Request model for jailbreak evaluation."""
    target: str = Field(
        ...,
        min_length=1,
        max_length=2_048,
        description="LLM API endpoint URL to evaluate",
        examples=["https://api.openai.com/v1/chat/completions"],
    )
    model: str = Field(..., min_length=1, max_length=256, description="Model name to test", examples=["gpt-4"])
    token: str = Field(..., min_length=1, max_length=8_192, description="API token for the target")
    base_url: str = Field(..., min_length=1, max_length=2_048, description="API base URL")
    eval_model: Optional[EvalModelConfig] = Field(
        default=None,
        description="Optional evaluator model; falls back to AIG's configured default",
    )
    test_suites: List[str] = Field(
        ...,
        description="Test suites to run",
        examples=[["jailbreak", "prompt_leak", "role_play_bypass"]],
        min_length=1,
        max_length=64,
    )
    language: Optional[str] = Field(default="en", max_length=16, description="Output language: zh, en")

    @field_validator("target", "base_url")
    @classmethod
    def normalize_urls(cls, value: str) -> str:
        return value.strip()

    @field_validator("test_suites")
    @classmethod
    def validate_suites(cls, value: List[str]) -> List[str]:
        normalized = [item.strip() for item in value]
        if any(not item or len(item) > 128 for item in normalized):
            raise ValueError("test suites must be non-empty and at most 128 characters")
        return normalized


class JailbreakEvalResponse(BaseModel):
    """Response after submitting a jailbreak evaluation."""
    task_id: str = Field(..., description="AIG task session ID for polling")
    status: str = Field(default="running", description="Task status")


class JailbreakResultResponse(BaseModel):
    """Typed and redacted jailbreak evaluation result envelope."""

    task_id: str
    status: str
    score: int = Field(default=0, ge=0, le=100)
    total: int = Field(default=0, ge=0)
    passed: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0)
    summary: str = ""
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    incident_candidates: List[Dict[str, Any]] = Field(default_factory=list)


# ═════════════════════════════════════════════════════════════════════════════
# 5. Threat Intelligence Sync
# ═════════════════════════════════════════════════════════════════════════════

class McpRiskCategory(BaseModel):
    """MCP risk category definition from AIG."""
    id: str = Field(..., description="Category identifier")
    severity: str = Field(..., description="Default severity level")
    description: str = Field(..., description="Category description")
    aig_pattern: str = Field(..., description="AIG internal pattern identifier")


class ThreatRule(BaseModel):
    """A single threat rule for AIDR to encode."""
    id: str = Field(..., description="Rule identifier")
    type: str = Field(..., description="Rule type: mcp, infra, agent")
    pattern: str = Field(..., description="Detection pattern (regex)")
    action: str = Field(..., description="Policy action: block, warn, monitor")
    severity: str = Field(..., description="Severity level")


class ThreatIntelResponse(BaseModel):
    """Response model for threat intelligence sync."""
    rules_version: str = Field(..., description="Version identifier for this rule set")
    cve_count: int = Field(..., description="Total CVE entries in AIG database")
    mcp_risk_categories: List[McpRiskCategory] = Field(
        default_factory=list,
        description="MCP risk category definitions for policy mapping",
    )
    threat_rules: List[ThreatRule] = Field(
        default_factory=list,
        description="Threat rules for AIDR to encode",
    )
    last_updated: str = Field(..., description="ISO 8601 timestamp of last update")
