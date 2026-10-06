"""Contract tests for the Tencent AIG v4 response adapter."""

import httpx
import pytest

from app.utils.aig_client import AIGClient, AIGClientError, AIGSubmissionAmbiguous, _normalize_task_status


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
async def test_create_task_marks_lost_response_as_ambiguous():
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("response was lost", request=request)

    client = mock_client(handler)
    with pytest.raises(AIGSubmissionAmbiguous):
        await client.create_scan_task("mcp_scan", {"prompt": "https://example.test"})
    await client.close()


@pytest.mark.asyncio
async def test_create_task_marks_invalid_success_as_ambiguous():
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": 0, "data": {}})

    client = mock_client(handler)
    with pytest.raises(AIGSubmissionAmbiguous):
        await client.create_scan_task("mcp_scan", {"prompt": "https://example.test"})
    await client.close()


@pytest.mark.asyncio
async def test_runtime_readiness_uses_worker_shared_secret(monkeypatch):
    secret = "worker-secret-" + "x" * 32
    monkeypatch.setenv("AIG_AGENT_SHARED_SECRET", secret)

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/internal/readiness"
        assert request.headers["X-AIG-Agent-Token"] == secret
        return httpx.Response(
            200,
            json={
                "status": 0,
                "active_agents": 2,
                "capabilities": {"mcp_scan": 2},
                "dataset_provenance": {
                    "verified": True,
                    "bundle_id": "a" * 64,
                    "source_commit": "b" * 40,
                    "release_sequence": 1,
                },
            },
        )

    client = mock_client(handler)
    try:
        evidence = await client.get_runtime_readiness()
    finally:
        await client.close()
    assert evidence == {
        "active_agents": 2,
        "capabilities": {"mcp_scan": 2},
        "dataset_provenance": {
            "verified": True,
            "bundle_id": "a" * 64,
            "source_commit": "b" * 40,
            "release_sequence": 1,
        },
    }


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


@pytest.mark.asyncio
async def test_polling_failure_remains_a_controlled_upstream_error():
    async def handler(request):
        raise httpx.ReadTimeout("Authorization: secret", request=request)

    client = mock_client(handler)
    try:
        with pytest.raises(AIGClientError, match="AIG upstream request failed"):
            await client.get_task_status("task-1")
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [[], {"status": 0, "data": None}])
async def test_create_task_invalid_envelopes_are_ambiguous(body):
    client = mock_client(lambda _request: httpx.Response(200, json=body))
    try:
        with pytest.raises(AIGSubmissionAmbiguous):
            await client.create_scan_task("mcp_scan", {})
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_completed_status_without_result_is_still_pending():
    def handler(request):
        if "/result/" in request.url.path:
            return httpx.Response(200, json={"status": 1, "message": "task result not available yet"})
        return httpx.Response(200, json={"status": 0, "data": {"status": "done"}})

    client = mock_client(handler)
    try:
        assert await client.get_task_result("task-1") == {"status": "running"}
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("url", ["http://[invalid", "http://example.com:invalid", "http://example.com:70000"])
async def test_malformed_upstream_configuration_fails_readiness(url):
    client = AIGClient(base_url=url)
    try:
        assert not await client.health_check()
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_non_json_task_result_is_an_upstream_error():
    client = mock_client(lambda _request: httpx.Response(200, text="not JSON"))
    try:
        with pytest.raises(AIGClientError, match="invalid task result"):
            await client.get_task_result.__wrapped__(client, "task-1")
    finally:
        await client.close()
