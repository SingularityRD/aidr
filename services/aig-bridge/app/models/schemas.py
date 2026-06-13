"""
Pydantic models for AIG Bridge request/response schemas.

All models follow the AIG common response format:
{ "status": 0, "message": "...", "data": {...} }
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Common ──────────────────────────────────────────────────────────────────

class TaskStatusResponse(BaseModel):
    """Generic task status response."""
    task_id: str = Field(..., description="AIG task session ID")
    status: str = Field(..., description="Task status: running, completed, failed")
    error: Optional[str] = Field(None, description="Error message if failed")


# ── Eval Model Configuration ────────────────────────────────────────────────

class EvalModelConfig(BaseModel):
    """LLM model configuration for evaluation/scanning."""
    model: str = Field(..., description="Model name (e.g., gpt-4, claude-3)")
    token: str = Field(..., description="API authentication token")
    base_url: str = Field(..., description="API base URL")


# ═════════════════════════════════════════════════════════════════════════════
# 1. Infrastructure CVE Scan
# ═════════════════════════════════════════════════════════════════════════════

class InfraScanRequest(BaseModel):
    """Request model for AI infrastructure CVE scan."""
    targets: List[str] = Field(
        ...,
        description="List of infrastructure targets (URLs, IPs, image names)",
        examples=[["https://my-ml-server.com:8080", "triton-inference-server:2.30.0"]],
    )
    scan_type: str = Field(
        default="full",
        description="Scan depth: quick, standard, full",
    )
    options: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional scan options (timeout, depth, etc.)",
    )


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
    target: str = Field(..., description="MCP server URL or source path")
    headers: Optional[Dict[str, str]] = Field(
        default=None,
        description="HTTP headers for remote MCP connection",
    )
    categories: Optional[List[str]] = Field(
        default=None,
        description="Risk categories to scan (default: all 14 categories)",
        examples=[["prompt_injection", "data_exfiltration", "privilege_escalation"]],
    )
    eval_model: Optional[EvalModelConfig] = Field(
        default=None,
        description="LLM model for dynamic evaluation (required for remote MCP scan)",
    )


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
    language: Optional[str] = Field(default="en", description="Output language: zh, en")
    prompt: Optional[str] = Field(
        default="",
        description="Additional scan instructions/prompt",
    )


class AgentScanResponse(BaseModel):
    """Response after submitting an agent scan."""
    task_id: str = Field(..., description="AIG task session ID for polling")
    status: str = Field(default="running", description="Task status")


# ═════════════════════════════════════════════════════════════════════════════
# 4. Jailbreak Evaluation
# ═════════════════════════════════════════════════════════════════════════════

class JailbreakEvalRequest(BaseModel):
    """Request model for jailbreak evaluation."""
    target: str = Field(
        ...,
        description="LLM API endpoint URL to evaluate",
        examples=["https://api.openai.com/v1/chat/completions"],
    )
    model: str = Field(..., description="Model name to test", examples=["gpt-4"])
    token: str = Field(..., description="API token for the target")
    base_url: str = Field(..., description="API base URL")
    test_suites: List[str] = Field(
        ...,
        description="Test suites to run",
        examples=[["jailbreak", "prompt_leak", "role_play_bypass"]],
    )
    language: Optional[str] = Field(default="en", description="Output language: zh, en")


class JailbreakEvalResponse(BaseModel):
    """Response after submitting a jailbreak evaluation."""
    task_id: str = Field(..., description="AIG task session ID for polling")
    status: str = Field(default="running", description="Task status")


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
