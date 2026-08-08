import { afterEach, describe, expect, it, vi } from "vitest";
import {
	AigBridgeError,
	getAigScanResult,
	isAigAvailable,
	triggerAigScan,
} from "../aig-scan-client.js";

const originalFetch = globalThis.fetch;
const originalBridgeUrl = process.env.AIG_BRIDGE_URL;
const originalApiKey = process.env.AIG_BRIDGE_API_KEY;
const originalTenant = process.env.AIG_TENANT_ID;

function jsonResponse(value: unknown, status = 200): Response {
	return new Response(JSON.stringify(value), {
		status,
		headers: { "content-type": "application/json" },
	});
}

afterEach(() => {
	globalThis.fetch = originalFetch;
	if (originalBridgeUrl === undefined) delete process.env.AIG_BRIDGE_URL;
	else process.env.AIG_BRIDGE_URL = originalBridgeUrl;
	if (originalApiKey === undefined) delete process.env.AIG_BRIDGE_API_KEY;
	else process.env.AIG_BRIDGE_API_KEY = originalApiKey;
	if (originalTenant === undefined) delete process.env.AIG_TENANT_ID;
	else process.env.AIG_TENANT_ID = originalTenant;
});

describe("AIG scan client contract", () => {
	it("checks bridge readiness without throwing on malformed health", async () => {
		process.env.AIG_BRIDGE_URL = "http://bridge.test/";
		globalThis.fetch = vi.fn(async () => jsonResponse({ status: "ok", scan_ready: true })) as unknown as typeof fetch;
		expect(await isAigAvailable()).toBe(true);

		(globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce(jsonResponse({ scan_ready: "yes" }));
		expect(await isAigAvailable()).toBe(false);
	});

	it("maps each scan type to the documented endpoint and validates task IDs", async () => {
		process.env.AIG_BRIDGE_URL = "http://bridge.test";
		process.env.AIG_BRIDGE_API_KEY = "bridge-secret";
		process.env.AIG_TENANT_ID = "tenant-demo";
		const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
			const path = new URL(String(input)).pathname;
			return jsonResponse({ task_id: `task-${path.split("/").at(-1)}`, status: "running" });
		});
		globalThis.fetch = fetchMock as unknown as typeof fetch;

		await triggerAigScan({ scan_type: "infra", target: "https://infra.test", options: { scan_depth: "quick" }, idempotency_key: "once" });
		await triggerAigScan({ scan_type: "mcp", target: "https://mcp.test/sse", options: { target_type: "url", categories: ["prompt_injection"] } });
		await triggerAigScan({ scan_type: "agent", options: { agent_config: { targets: [] } } });
		await triggerAigScan({ scan_type: "jailbreak", target: "https://llm.test", options: { model: "demo", token: "target-token", base_url: "https://llm.test", test_suites: ["jailbreak"] } });

		expect(fetchMock).toHaveBeenCalledTimes(4);
		const first = fetchMock.mock.calls[0];
		expect(new URL(String(first?.[0])).pathname).toBe("/api/v1/scan/infra");
		const firstInit = first?.[1] as RequestInit;
		expect(new Headers(firstInit.headers).get("Authorization")).toBe("Bearer bridge-secret");
		expect(new Headers(firstInit.headers).get("X-AIDR-Tenant-ID")).toBe("tenant-demo");
		expect(new Headers(firstInit.headers).get("Idempotency-Key")).toBe("once");
	});

	it("normalizes result status/findings and rejects path traversal IDs", async () => {
		process.env.AIG_BRIDGE_URL = "http://bridge.test";
		globalThis.fetch = vi.fn(async () => jsonResponse({
			status: "completed",
			findings: [null, { cve_id: "CVE-1", severity: "HIGH", detail: "safe" }],
			summary: { total: "bad", high: 2 },
		})).bind(null) as unknown as typeof fetch;
		const result = await getAigScanResult("task-123", "infra");
		expect(result?.status).toBe("completed");
		expect(result?.findings).toHaveLength(2);
		expect(result?.findings[1]?.severity).toBe("high");
		expect(result?.summary.total).toBe(2);
		await expect(getAigScanResult("../../etc/passwd", "infra")).rejects.toThrow("Invalid AIG task id");
	});

	it("redacts secrets in bridge error bodies and treats 404 as pending/missing", async () => {
		process.env.AIG_BRIDGE_URL = "http://bridge.test";
		const fetchMock = vi.fn()
			.mockResolvedValueOnce(jsonResponse({ error: "token=target-secret", authorization: "Bearer bridge-secret" }, 500))
			.mockResolvedValueOnce(jsonResponse({ error: "not found" }, 404));
		globalThis.fetch = fetchMock as unknown as typeof fetch;
		const error = await getAigScanResult("task-1", "mcp").catch((value: unknown) => value);
		expect(error).toBeInstanceOf(AigBridgeError);
		expect(JSON.stringify((error as AigBridgeError).body)).not.toContain("bridge-secret");
		expect(JSON.stringify((error as AigBridgeError).body)).not.toContain("target-secret");
		expect(await getAigScanResult("task-1", "mcp")).toBeNull();
	});
});
