import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FleetInventory } from "@singularityrd/aidr-core";
import { describe, expect, it, vi } from "vitest";
import {
	collectTargetInputs,
	discoveryIngestPayload,
	discoveryUploadConfig,
	fleetCollectionExitCode,
	publishDiscoveryCycle,
	publishDiscoveryInventory,
} from "../commands/collect.js";

const TENANT = "123e4567-e89b-42d3-a456-426614174000";
const DISCOVERY_URL = "https://tenant.example.test/functions/v1/discovery";
const COLLECTOR_CREDENTIAL = `aidr_dc_${"a".repeat(43)}`;

function remoteInventory(overrides: Partial<FleetInventory["items"][number]> = {}): FleetInventory {
	const base = inventory(overrides);
	return { ...base, tenantId: TENANT, items: [{ ...base.items[0]!, target: "https://agent.example.test/private/tool", ...overrides }] };
}

function fetchStub(handler: (body: Record<string, unknown>, headers: Headers) => Response): typeof fetch {
	return vi.fn(async (_input: Parameters<typeof fetch>[0], init?: RequestInit) =>
		handler(JSON.parse(String(init?.body)) as Record<string, unknown>, new Headers(init?.headers)),
	) as unknown as typeof fetch;
}

function inventory(overrides: Partial<FleetInventory["items"][number]> = {}): FleetInventory {
	return {
		schemaVersion: 1,
		tenantId: "tenant-a",
		collectorId: "collector-a",
		generatedAt: "2026-09-12T00:00:00.000Z",
		staleAfterMs: 60_000,
		items: [
			{
				id: "a".repeat(64),
				kind: "ai_infrastructure",
				target: "http://127.0.0.1:8080/",
				firstSeenAt: "2026-09-12T00:00:00.000Z",
				lastSeenAt: "2026-09-12T00:00:00.000Z",
				lastAttemptAt: "2026-09-12T00:00:00.000Z",
				freshness: "fresh",
				reachability: "reachable",
				consecutiveFailures: 0,
				attempts: 1,
				nextRetryAt: null,
				scan: {
					url: "http://127.0.0.1:8080/",
					reachable: true,
					matched: [],
					cves: [],
					error: null,
					requestsMade: 1,
				},
				...overrides,
			},
		],
	};
}

describe("fleet collector CLI helpers", () => {
	it("combines target arguments and files with canonical deduplication", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-collect-targets-"));
		try {
			const path = join(dir, "targets.txt");
			await writeFile(path, "# comment\nHTTP://LOCALHOST:80/app/\nhttp://127.0.0.1:8080\n");
			expect(collectTargetInputs({ target: ["http://localhost/app"], file: path })).toEqual([
				"http://127.0.0.1:8080/",
				"http://localhost/app",
			]);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("maps healthy, degraded, and high-severity collection states to scheduler exit codes", () => {
		expect(fleetCollectionExitCode(inventory())).toBe(0);
		expect(fleetCollectionExitCode(inventory({ freshness: "stale" }))).toBe(1);
		expect(fleetCollectionExitCode(inventory({ reachability: "unreachable" }))).toBe(1);
		const healthyScan = inventory().items[0]?.scan;
		if (!healthyScan) throw new Error("test inventory is missing its scan result");
		expect(
			fleetCollectionExitCode(
				inventory({
					scan: {
						...healthyScan,
						cves: [
							{
								cveId: "CVE-2099-0001",
								product: "test",
								severity: "high",
								cvss: 9,
								rule: "version < 2",
								ruleStatus: "active",
								evaluated: true,
							},
						],
					},
				}),
			),
		).toBe(2);
	});
});

describe("managed discovery upload", () => {
	it("requires explicit complete credentials and HTTPS except loopback", () => {
		expect(discoveryUploadConfig({})).toBeNull();
		expect(() => discoveryUploadConfig({ AIDR_DISCOVERY_URL: DISCOVERY_URL })).toThrow("discovery_upload_config_incomplete");
		expect(() => discoveryUploadConfig({
			AIDR_DISCOVERY_URL: "http://remote.example.test/functions/v1/discovery",
			AIDR_DISCOVERY_ACCESS_TOKEN: "jwt.token",
			AIDR_DISCOVERY_ANON_KEY: "anon.key",
		})).toThrow("discovery_upload_config_invalid");
		expect(() => discoveryUploadConfig({
			AIDR_DISCOVERY_URL: DISCOVERY_URL,
			AIDR_DISCOVERY_ACCESS_TOKEN: "jwt.token",
			AIDR_DISCOVERY_COLLECTOR_CREDENTIAL: COLLECTOR_CREDENTIAL,
			AIDR_DISCOVERY_ANON_KEY: "anon.key",
		})).toThrow("discovery_upload_auth_ambiguous");
		expect(discoveryUploadConfig({
			AIDR_DISCOVERY_URL: "http://127.0.0.1:8000/functions/v1/discovery",
			AIDR_DISCOVERY_COLLECTOR_CREDENTIAL: COLLECTOR_CREDENTIAL,
			AIDR_DISCOVERY_ANON_KEY: "anon.key",
		})?.mode).toBe("collector");
	});

	it("sends only origin-level reachability and bounded status", () => {
		const local = remoteInventory({
			reachability: "unreachable",
			attempts: 3,
			scan: {
				url: "https://agent.example.test/private/tool",
				reachable: false,
				matched: [], cves: [], error: "collector_exception:SecretError", requestsMade: 1,
			},
		});
		const payload = discoveryIngestPayload(local, 2);
		expect(payload).toMatchObject({
			tenant_id: TENANT, collector_id: "collector-a", sequence: 2,
			complete: true, expected_targets: 1,
			items: [{ target: "https://agent.example.test/", reachable: false, attempts: 3, error_code: "collector_exception" }],
		});
		expect(JSON.stringify(payload)).not.toContain("private/tool");
		expect(JSON.stringify(payload)).not.toContain("SecretError");
		expect(() => discoveryIngestPayload({
			...local,
			items: [local.items[0]!, { ...local.items[0]!, target: "https://agent.example.test/another" }],
		}, 2)).toThrow("discovery_upload_duplicate_origin");
	});

	it("reads the operator cursor and validates the ingest receipt", async () => {
		const config = discoveryUploadConfig({
			AIDR_DISCOVERY_URL: DISCOVERY_URL,
			AIDR_DISCOVERY_ACCESS_TOKEN: "jwt.token",
			AIDR_DISCOVERY_ANON_KEY: "anon.key",
		});
		if (!config) throw new Error("test config missing");
		const calls: Record<string, unknown>[] = [];
		const transport = fetchStub((body, headers) => {
			calls.push(body);
			expect(headers.get("authorization")).toBe("Bearer jwt.token");
			expect(headers.get("apikey")).toBe("anon.key");
			if (body.action === "read") return Response.json({ ok: true, collector: { collector_id: "collector-a", sequence: 7 } });
			return Response.json({ ok: true, cycle: { collector_id: "collector-a", sequence: 8, cycle_id: body.cycle_id } }, { status: 201 });
		});
		await publishDiscoveryInventory(remoteInventory(), config, transport);
		expect(calls.map((call) => call.action)).toEqual(["read", "ingest"]);
		expect(calls[1]?.sequence).toBe(8);
	});

	it("uses the collector-bound cursor and fails closed on revocation", async () => {
		const config = discoveryUploadConfig({
			AIDR_DISCOVERY_URL: DISCOVERY_URL,
			AIDR_DISCOVERY_COLLECTOR_CREDENTIAL: COLLECTOR_CREDENTIAL,
			AIDR_DISCOVERY_ANON_KEY: "anon.key",
		});
		if (!config) throw new Error("test config missing");
		const actions: unknown[] = [];
		const transport = fetchStub((body) => {
			actions.push(body.action);
			if (body.action === "cursor") return Response.json({ ok: true, collector_id: "collector-a", last_sequence: 9, next_sequence: 10 });
			return Response.json({ error: "invalid_collector_credential" }, { status: 401 });
		});
		await expect(publishDiscoveryInventory(remoteInventory(), config, transport)).rejects.toThrow("discovery_upload_invalid_collector_credential");
		expect(actions).toEqual(["cursor", "ingest"]);
	});
});

describe("continuous collection", () => {
	it("reports failed interval uploads while one-shot uploads still fail closed", async () => {
		const config = discoveryUploadConfig({
			AIDR_DISCOVERY_URL: DISCOVERY_URL,
			AIDR_DISCOVERY_COLLECTOR_CREDENTIAL: COLLECTOR_CREDENTIAL,
			AIDR_DISCOVERY_ANON_KEY: "anon.key",
		});
		if (!config) throw new Error("test config missing");
		const publish = vi.fn().mockRejectedValueOnce(new Error("discovery_upload_network_error"))
			.mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error("discovery_upload_network_error"));
		const error = vi.spyOn(console, "error").mockImplementation(() => {});
		try {
			await expect(publishDiscoveryCycle(remoteInventory(), config, true, publish)).resolves.toBe(false);
			expect(error.mock.calls.flat().join(" ")).toContain("discovery_upload_network_error");
			await expect(publishDiscoveryCycle(remoteInventory(), config, true, publish)).resolves.toBe(true);
			await expect(publishDiscoveryCycle(remoteInventory(), config, false, publish))
				.rejects.toThrow("discovery_upload_network_error");
			expect(publish).toHaveBeenCalledTimes(3);
		} finally {
			error.mockRestore();
		}
	});
});
