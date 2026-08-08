"""
AIG Client — HTTP client for communicating with the upstream AIG Go server.

Translates bridge REST calls into AIG's internal task-based API:
  - POST /api/v1/app/taskapi/tasks     → create scan task
  - GET  /api/v1/app/taskapi/status/{id} → poll task status
  - GET  /api/v1/app/taskapi/result/{id} → fetch task results

Also supports knowledge API for agent config management and the health check.
"""

import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx
from tenacity import RetryError, retry, stop_after_attempt, wait_exponential

logger = logging.getLogger("aig-bridge.aig_client")
_TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _normalize_task_status(value: Any) -> str:
    """Translate Tencent AIG's task states into the bridge contract."""

    normalized = str(value or "").strip().lower()
    if normalized in {"done", "completed", "complete", "success", "succeeded"}:
        return "completed"
    if normalized in {
        "doing",
        "running",
        "in_progress",
        "in-progress",
        "pending",
        "queued",
    }:
        return "running"
    if normalized in {"failed", "failure", "error", "cancelled", "canceled"}:
        return "failed"
    return normalized or "running"


class AIGClientError(Exception):
    """Raised when the upstream AIG server returns an error."""


class AIGClient:
    """
    HTTP client for the upstream AIG Go server.

    Manages task creation, status polling, and result retrieval across all
    scan types. Provides a unified interface that abstracts AIG's internal
    task workflow from the bridge routers.
    """

    def __init__(
        self,
        base_url: str = "http://aig-server:8088",
        api_key: str = "",
        timeout: float = 30.0,
    ):
        normalized_url = base_url.strip().rstrip("/")
        parsed_url = urlparse(normalized_url)
        invalid_url = (
            parsed_url.scheme not in {"http", "https"}
            or not parsed_url.hostname
            or parsed_url.username
            or parsed_url.password
            or parsed_url.fragment
        )
        # Keep a malformed environment value from turning /health into a
        # framework 500.  The inert loopback endpoint is never contacted when
        # `_configuration_error` is set; callers receive a redacted bridge
        # configuration error instead.
        self._configuration_error = invalid_url
        self.base_url = normalized_url if not invalid_url else "http://127.0.0.1:1"
        self.api_key = api_key
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout),
            headers=self._default_headers(),
        )

    def _default_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    # ── Health ──────────────────────────────────────────────────────────────

    async def health_check(self) -> bool:
        """
        Check if the AIG server is reachable.

        Returns True if the server responds with HTTP 200.
        """
        if self._configuration_error:
            logger.error("AIG server URL is invalid; readiness is disabled")
            return False
        try:
            response = await self._client.get("/", timeout=5.0)
            return response.status_code == 200
        except httpx.HTTPError as exc:
            logger.warning("AIG server health check failed (%s)", type(exc).__name__)
            return False

    # ── Task Management ─────────────────────────────────────────────────────

    async def create_scan_task(
        self,
        task_type: str,
        content: Dict[str, Any],
    ) -> str:
        """
        Create a new scan task on the AIG server.

        Args:
            task_type: One of ``ai_infra_scan``, ``mcp_scan``, ``agent_scan``,
                       ``model_redteam_report``.
            content: Task-specific content dict (varies by task type).

        Returns:
            The AIG session_id (task ID) for polling.

        Raises:
            AIGClientError: If the AIG server rejects the request.
        """
        self._ensure_configured()
        payload = {
            "type": task_type,
            "content": content,
        }

        # AIG v4.5.1 has no idempotency-key contract. Retrying a POST after a
        # response loss can create a second scan, so the bridge performs one
        # submission unless a reviewed upstream version explicitly opts in.
        response = await self._client.post(
            "/api/v1/app/taskapi/tasks",
            json=payload,
        )
        data = self._parse_response(response, "create scan task")

        session_id = data.get("session_id") or (
            data.get("data", {}).get("session_id")
        )
        if not isinstance(session_id, str) or not _TASK_ID_RE.fullmatch(session_id):
            # Do not include the raw upstream body: an error response can
            # echo eval-model tokens or target Authorization headers.
            raise AIGClientError("AIG task creation returned an invalid session_id")

        logger.info("Task created — type=%s, session_id=%s", task_type, session_id)
        return session_id

    async def cancel_task(self, session_id: str, *, username: str = "api_user") -> bool:
        """Request upstream cancellation without exposing AIG's raw response."""

        self._ensure_configured()
        response = await self._client.post(
            f"/api/v1/app/tasks/{session_id}/terminate",
            headers={"username": username},
            json={},
            timeout=10.0,
        )
        body = self._parse_response(response, f"cancel task {session_id}")
        return body.get("status", 0) == 0

    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=5),
    )
    async def get_task_status(self, session_id: str) -> Dict[str, Any]:
        """
        Poll the status of an existing scan task.

        Returns the raw AIG task status response including the current
        execution status and any accumulated log output.
        """
        self._ensure_configured()
        response = await self._client.get(
            f"/api/v1/app/taskapi/status/{session_id}",
        )
        body = self._parse_response(response, f"get task status {session_id}")
        data = body.get("data") if isinstance(body.get("data"), dict) else body
        normalized = dict(data)
        normalized["status"] = _normalize_task_status(normalized.get("status"))
        return normalized

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
    )
    async def get_task_result(self, session_id: str) -> Dict[str, Any]:
        """
        Fetch the final result of a completed scan task.

        Returns the complete scan result including all findings, risk scores,
        and summary statistics. Raises ``AIGClientError`` if the task is still
        running — callers should poll ``get_task_status`` first.
        """
        self._ensure_configured()
        response = await self._client.get(
            f"/api/v1/app/taskapi/result/{session_id}",
        )
        try:
            body = self._parse_response(response, f"get task result {session_id}")
        except AIGClientError:
            # AIG answers with HTTP 200 + status=1 while the worker is still
            # producing its result. That is a normal polling state, not an
            # upstream outage and must not become a 502/500 in the bridge.
            try:
                pending_body = response.json()
            except (TypeError, ValueError):
                raise
            message = str(pending_body.get("message") or "").lower()
            if pending_body.get("status") == 1 and "not available yet" in message:
                # AIG v4 can leave the result endpoint in its generic
                # "not available yet" state even after the worker emitted a
                # terminal error event. Consult the status endpoint so the
                # bridge never leaves a failed task polling forever.
                try:
                    task_status = await self.get_task_status(session_id)
                except (AIGClientError, RetryError):
                    # A transient status failure should preserve the normal
                    # polling contract; the next request can retry it.
                    return {"status": "running"}
                normalized_status = task_status.get("status", "running")
                if normalized_status == "failed":
                    # Upstream logs may contain model prompts, target headers,
                    # or tokens. Keep the public task contract deliberately
                    # generic; operators can inspect the authenticated AIG
                    # log stream separately.
                    return {"status": "failed", "error": "AIG task failed"}
                return {"status": normalized_status}
            raise
        data = body.get("data") if isinstance(body.get("data"), dict) else body

        # v4.5.1 returns a result envelope:
        # {data: {id, result: {results, score, total}, timestamp, type}}.
        # Older deployments return the normalized task object directly. Keep
        # both shapes behind the bridge contract and never make routers know
        # about Tencent's ``done`` state or result envelope.
        if not isinstance(data, dict):
            return {"status": "running"}
        result_payload = data.get("result")
        if isinstance(result_payload, dict):
            normalized = dict(result_payload)
            normalized["status"] = "completed"
            normalized["aig_result_id"] = data.get("id")
            normalized["timestamp"] = data.get("timestamp")
            normalized["type"] = data.get("type")
            return normalized

        normalized = dict(data)
        normalized["status"] = _normalize_task_status(normalized.get("status"))
        return normalized

    # ── Threat Intelligence ─────────────────────────────────────────────────

    async def get_latest_threats(self) -> Dict[str, Any]:
        """
        Fetch the latest threat intelligence and rules from AIG.

        Returns CVE counts, MCP risk category definitions, and AIDR-compatible
        threat patterns for periodic sync.
        """
        # Tencent AIG v4.5.1 does not expose the historical
        # ``taskapi/threats/latest`` route. Its versioned knowledge API is the
        # source of truth for the vulnerability and MCP rule datasets.
        # Request metadata/counts rather than downloading all CVE documents on
        # every readiness probe.
        try:
            self._ensure_configured()
            vulnerabilities = await self._client.get(
                "/api/v1/knowledge/vulnerabilities?page=1&size=1",
                timeout=10.0,
            )
            mcp = await self._client.get(
                "/api/v1/knowledge/mcp?page=1&size=100",
                timeout=10.0,
            )
            vulnerability_body = self._parse_response(
                vulnerabilities, "get AIG vulnerability knowledge"
            )
            mcp_body = self._parse_response(mcp, "get AIG MCP knowledge")
            vulnerability_data = vulnerability_body.get("data") or {}
            mcp_data = mcp_body.get("data") or {}
            if not isinstance(vulnerability_data, dict) or not isinstance(mcp_data, dict):
                raise AIGClientError("AIG knowledge API returned an invalid data shape")

            mcp_categories = []
            for item in mcp_data.get("items", []):
                if not isinstance(item, dict):
                    continue
                info = item.get("info") if isinstance(item.get("info"), dict) else item
                category_id = str(info.get("id") or info.get("name") or "unknown")
                mcp_categories.append(
                    {
                        "id": category_id,
                        "severity": str(info.get("severity") or "info"),
                        "description": str(
                            info.get("description") or info.get("name") or category_id
                        ),
                        "aig_pattern": category_id,
                    }
                )

            return {
                "rules_version": os.getenv("AIG_SOURCE_VERSION", "unknown"),
                "cve_count": int(vulnerability_data.get("total") or 0),
                "mcp_risk_categories": mcp_categories,
                "threat_rules": [],
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as exc:
            # Do not turn an unavailable or empty upstream dataset into a
            # successful zero-CVE response. Callers can decide whether a
            # stale cache is acceptable; readiness must remain honest.
            logger.warning("Failed to fetch latest threats: %s", type(exc).__name__)
            raise

    # ── Agent Configuration ─────────────────────────────────────────────────

    async def save_agent_config(
        self,
        name: str,
        yaml_content: str,
        verify: bool = True,
    ) -> Dict[str, Any]:
        """
        Save an agent configuration (YAML) to the AIG server for reuse.

        This corresponds to AIG's ``POST /api/v1/app/knowledge/agent/:name``
        endpoint. Saved configs can be referenced by ``agent_id`` in subsequent
        agent scan requests.

        Args:
            name: Configuration name/reference ID.
            yaml_content: Agent configuration in YAML format.
            verify: If True, runs a connectivity check against the agent.

        Returns:
            The AIG server response.
        """
        url = f"/api/v1/app/knowledge/agent/{name}"
        if not verify:
            url += "?verify=false"

        self._ensure_configured()
        response = await self._client.post(
            url,
            json={"content": yaml_content},
        )
        return self._parse_response(response, f"save agent config {name}")

    # ── Internal ────────────────────────────────────────────────────────────

    def _ensure_configured(self) -> None:
        if self._configuration_error:
            raise AIGClientError("AIG upstream URL is not configured correctly")

    def _parse_response(
        self,
        response: httpx.Response,
        context: str,
    ) -> Dict[str, Any]:
        """
        Parse and validate an AIG server response.

        AIG returns ``{"status": 0, "message": "...", "data": {...}}``.
        This method raises ``AIGClientError`` for non-zero status codes.
        """
        try:
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPStatusError as exc:
            raise AIGClientError(
                f"AIG server error during {context}: HTTP {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise AIGClientError(f"AIG upstream unavailable during {context}") from exc
        except (TypeError, ValueError) as exc:
            raise AIGClientError(f"Invalid response from AIG during {context}") from exc

        # Check AIG's own status field
        if not isinstance(body, dict):
            raise AIGClientError(f"AIG returned a non-object response during {context}")

        # Check AIG's own status field.  Some AIG versions omit it on a plain
        # success response; that is accepted for compatibility, while explicit
        # non-zero values remain errors.
        if body.get("status", 0) != 0:
            raise AIGClientError(
                f"AIG returned error during {context}: "
                f"status={body.get('status')}"
            )

        return body

    async def close(self):
        """Close the underlying HTTP client session."""
        await self._client.aclose()


# ── Dependency injection ────────────────────────────────────────────────────

_client_instance: Optional[AIGClient] = None


def get_aig_client() -> AIGClient:
    """
    FastAPI dependency that returns a shared AIGClient instance.

    The client is configured from environment variables:
    - ``BRIDGE_AIG_URL``: AIG server base URL (default: http://aig-server:8088)
    - ``BRIDGE_API_KEY``: API key for authenticated requests
    """
    global _client_instance

    if _client_instance is None:
        base_url = os.getenv("BRIDGE_AIG_URL", "http://aig-server:8088")
        api_key = os.getenv("BRIDGE_API_KEY", "")
        _client_instance = AIGClient(
            base_url=base_url,
            api_key=api_key,
        )

    return _client_instance


async def close_aig_client() -> None:
    """Close the shared HTTP client during application shutdown."""

    global _client_instance
    if _client_instance is not None:
        await _client_instance.close()
        _client_instance = None
