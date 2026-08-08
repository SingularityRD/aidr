"""Contract tests for the Tencent AIG v4 response adapter."""

import httpx
import pytest

from app.utils.aig_client import AIGClient, _normalize_task_status


def mock_client(handler):
    client = AIGClient(base_url="http://aig.test")
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://aig.test",
    )
    return client


def test_normalize_upstream_states():
    assert _normalize_task_status("doing") == "running"
    assert _normalize_task_status("done") == "completed"
    assert _normalize_task_status("failed") == "failed"


@pytest.mark.asyncio
async def test_result_envelope_is_flattened_and_completed():
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/result/task-1")
        return httpx.Response(
            200,
            json={
                "status": 0,
                "message": "ok",
                "data": {
                    "id": "result-1",
                    "result": {"results": [{"target_url": "https://example.com"}], "total": 0},
                    "timestamp": 123,
                    "type": "resultUpdate",
                },
            },
        )

    client = mock_client(handler)
    try:
        result = await client.get_task_result("task-1")
    finally:
        await client.close()
    assert result["status"] == "completed"
    assert result["total"] == 0
    assert result["aig_result_id"] == "result-1"


@pytest.mark.asyncio
async def test_result_not_available_is_a_running_state():
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"status": 1, "message": "task result not available yet", "data": None},
        )

    client = mock_client(handler)
    try:
        result = await client.get_task_result("task-2")
    finally:
        await client.close()
    assert result == {"status": "running"}


@pytest.mark.asyncio
async def test_result_not_available_surfaces_terminal_upstream_failure():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/result/task-3"):
            return httpx.Response(
                200,
                json={"status": 1, "message": "task result not available yet", "data": None},
            )
        assert request.url.path.endswith("/status/task-3")
        return httpx.Response(
            200,
            json={
                "status": 0,
                "data": {"session_id": "task-3", "status": "error", "log": "secret token"},
            },
        )

    client = mock_client(handler)
    try:
        result = await client.get_task_result("task-3")
    finally:
        await client.close()
    assert result == {"status": "failed", "error": "AIG task failed"}


@pytest.mark.asyncio
async def test_knowledge_api_provides_threat_counts_and_categories():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/vulnerabilities"):
            return httpx.Response(200, json={"status": 0, "data": {"total": 1891, "items": []}})
        assert request.url.path.endswith("/mcp")
        return httpx.Response(
            200,
            json={
                "status": 0,
                "data": {
                    "total": 1,
                    "items": [
                        {
                            "info": {
                                "id": "mcp_ssrf",
                                "description": "SSRF detection",
                                "severity": "high",
                            }
                        }
                    ],
                },
            },
        )

    client = mock_client(handler)
    try:
        threats = await client.get_latest_threats()
    finally:
        await client.close()
    assert threats["cve_count"] == 1891
    assert threats["mcp_risk_categories"][0]["id"] == "mcp_ssrf"
