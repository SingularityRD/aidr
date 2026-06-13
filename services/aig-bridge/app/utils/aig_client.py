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
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger("aig-bridge.aig_client")


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
        self.base_url = base_url.rstrip("/")
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
        try:
            response = await self._client.get("/", timeout=5.0)
            return response.status_code == 200
        except httpx.RequestError as exc:
            logger.warning("AIG server unreachable: %s", exc)
            return False

    # ── Task Management ─────────────────────────────────────────────────────

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
    )
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
        payload = {
            "type": task_type,
            "content": content,
        }

        response = await self._client.post(
            "/api/v1/app/taskapi/tasks",
            json=payload,
        )
        data = self._parse_response(response, "create scan task")

        session_id = data.get("session_id") or (
            data.get("data", {}).get("session_id")
        )
        if not session_id:
            raise AIGClientError(
                f"AIG task creation returned no session_id: {data}"
            )

        logger.info("Task created — type=%s, session_id=%s", task_type, session_id)
        return session_id

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
        response = await self._client.get(
            f"/api/v1/app/taskapi/status/{session_id}",
        )
        return self._parse_response(response, f"get task status {session_id}")

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
        response = await self._client.get(
            f"/api/v1/app/taskapi/result/{session_id}",
        )
        data = self._parse_response(response, f"get task result {session_id}")

        # AIG returns results under "data" key; flatten for consistent access
        if "data" in data and isinstance(data["data"], dict):
            return data["data"]
        return data

    # ── Threat Intelligence ─────────────────────────────────────────────────

    async def get_latest_threats(self) -> Dict[str, Any]:
        """
        Fetch the latest threat intelligence and rules from AIG.

        Returns CVE counts, MCP risk category definitions, and AIDR-compatible
        threat patterns for periodic sync.
        """
        try:
            response = await self._client.get(
                "/api/v1/app/taskapi/threats/latest",
                timeout=10.0,
            )
            data = self._parse_response(response, "get latest threats")
            if "data" in data and isinstance(data["data"], dict):
                return data["data"]
            return data
        except Exception as exc:
            logger.warning("Failed to fetch latest threats: %s", exc)
            return {
                "rules_version": "",
                "cve_count": 0,
                "mcp_risk_categories": [],
                "threat_rules": [],
                "last_updated": "",
            }

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

        response = await self._client.post(
            url,
            json={"content": yaml_content},
        )
        return self._parse_response(response, f"save agent config {name}")

    # ── Internal ────────────────────────────────────────────────────────────

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
        except Exception as exc:
            raise AIGClientError(
                f"Invalid response from AIG during {context}: {exc}"
            ) from exc

        # Check AIG's own status field
        if body.get("status", 0) != 0:
            raise AIGClientError(
                f"AIG returned error during {context}: "
                f"status={body.get('status')}, message={body.get('message')}"
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
