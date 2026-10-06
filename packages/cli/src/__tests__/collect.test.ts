import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FleetInventory } from "@singularityrd/aidr-core";
import * as core from "@singularityrd/aidr-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import collectCommand, {
	collectProviderConfig,
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
	return {
		...base,
		tenantId: TENANT,
		items: [{ ...base.items[0]!, target: "https://agent.example.test/private/tool", ...overrides }],
	};
}

function fetchStub(
	handler: (body: Record<string, unknown>, headers: Headers) => Response,
): typeof fetch {
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
			fleetCollectionExitCode(inventory({ scan: { ...healthyScan, error: "deadline_exceeded" } })),
		).toBe(1);
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

	it.each(["cloud", "mdm", "vendor", ""])(
		"fails closed before local target validation for unconfigured provider %s",
		async (provider) => {
			const error = vi.spyOn(console, "error").mockImplementation(() => {});
			const previousExitCode = process.exitCode;
			try {
				process.exitCode = 0;
				await collectCommand({ tenant: "tenant-a", provider, file: "does-not-exist.txt" });
				expect(process.exitCode).toBe(1);
				expect(error.mock.calls.flat().join(" ")).toContain(
					`discovery_provider_not_configured:${provider || "unknown"}`,
				);
			} finally {
				process.exitCode = previousExitCode;
				error.mockRestore();
			}
		},
	);
});

describe("cloud collector wire and real CLI selection", () => {
	const directory = "123e4567-e89b-42d3-a456-426614174001";
	const client = "123e4567-e89b-42d3-a456-426614174002";
	const device = "123e4567-e89b-42d3-a456-426614174003";
	const config = {
		schemaVersion: 1,
		provider: "intune",
		tenantId: TENANT,
		directoryTenantId: directory,
		deviceIds: [device],
		credentials: { clientId: client, clientSecret: { env: "AIDR_INTUNE_TEST_SECRET" } },
	};
	const positiveAt = "2026-10-06T12:00:00.000Z";
	function cloudInventory(): FleetInventory {
		return {
			...inventory(),
			tenantId: TENANT,
			generatedAt: positiveAt,
			items: [],
			providerEvidence: {
				provider: "intune",
				scopeHash: "a".repeat(64),
				coverage: "managed_devices",
				complete: true,
				observedAt: positiveAt,
				lastSuccessfulAt: positiveAt,
				resources: [
					{
						id: device,
						type: "mdm.managed_device",
						scope: `intune:${directory}`,
						observedAt: positiveAt,
					},
				],
			},
		};
	}
	beforeEach(() => {
		process.exitCode = 0;
		for (const variable of [
			"AIDR_DISCOVERY_URL",
			"AIDR_DISCOVERY_ACCESS_TOKEN",
			"AIDR_DISCOVERY_COLLECTOR_CREDENTIAL",
			"AIDR_DISCOVERY_ANON_KEY",
		])
			vi.stubEnv(variable, "");
		vi.stubEnv("AIDR_INTUNE_TEST_SECRET", "fixture-secret");
		vi.spyOn(console, "log").mockImplementation(() => {});
		vi.spyOn(console, "error").mockImplementation(() => {});
	});
	afterEach(() => {
		vi.restoreAllMocks();
		vi.unstubAllEnvs();
		process.exitCode = 0;
	});

	it("uploads resource-only evidence as a separate bounded DTO and keeps scheduler states honest", () => {
		const healthy = cloudInventory();
		const payload = discoveryIngestPayload(healthy, 1);
		expect(payload.items).toEqual([]);
		expect(payload.expected_targets).toBe(0);
		expect(payload.provider_resources).toEqual({
			provider: "intune",
			scope_hash: "a".repeat(64),
			coverage: "managed_devices",
			complete: true,
			observed_at: positiveAt,
			items: [
				{
					resource_id: device,
					resource_type: "mdm.managed_device",
					scope_id: `intune:${directory}`,
					region: null,
					observed_at: positiveAt,
				},
			],
		});
		expect(fleetCollectionExitCode(healthy)).toBe(0);
		const failed = {
			...healthy,
			providerEvidence: { ...healthy.providerEvidence!, complete: false },
		};
		expect(discoveryIngestPayload(failed, 2).provider_resources).toMatchObject({
			complete: false,
			items: [],
		});
		expect(fleetCollectionExitCode(failed)).toBe(1);
		expect(fleetCollectionExitCode({ ...healthy, generatedAt: "2026-10-06T12:30:00.000Z" })).toBe(
			1,
		);
	});

	it("rejects malformed/resource-replayed evidence before authenticated upload", () => {
		const base = cloudInventory();
		const evidence = base.providerEvidence!;
		expect(() =>
			discoveryIngestPayload({ ...base, providerEvidence: { ...evidence, scopeHash: "bad" } }, 1),
		).toThrow("discovery_upload_provider_evidence_invalid");
		expect(() =>
			discoveryIngestPayload(
				{
					...base,
					providerEvidence: {
						...evidence,
						resources: [evidence.resources[0]!, evidence.resources[0]!],
					},
				},
				1,
			),
		).toThrow("discovery_upload_provider_evidence_invalid");
		expect(() =>
			discoveryIngestPayload(
				{
					...base,
					providerEvidence: {
						...evidence,
						resources: [{ ...evidence.resources[0]!, scope: "aws:outside" }],
					},
				},
				1,
			),
		).toThrow("discovery_upload_provider_evidence_invalid");
	});

	it("runs the configured Intune collector from CLI without HTTP targets and persists API observations", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-cloud-cli-"));
		try {
			const path = join(dir, "scope.json");
			await writeFile(path, JSON.stringify(config));
			vi.spyOn(core, "getInstallationId").mockResolvedValue("collector-a");
			vi.spyOn(core, "loadFleetInventory").mockResolvedValue(null);
			const save = vi.spyOn(core, "saveFleetInventory").mockResolvedValue(undefined);
			const network = vi
				.spyOn(globalThis, "fetch")
				.mockImplementation(async (input) =>
					new URL(String(input)).hostname === "login.microsoftonline.com"
						? Response.json({
								access_token: "fixture-token",
								token_type: "Bearer",
								expires_in: 3600,
							})
						: Response.json({ id: device }),
				);
			await collectCommand({
				tenant: TENANT,
				provider: "intune",
				providerConfig: path,
				json: true,
			});
			expect(process.exitCode).toBe(0);
			expect(network).toHaveBeenCalledTimes(2);
			expect(save).toHaveBeenCalledWith(
				expect.any(String),
				expect.objectContaining({
					items: [],
					providerEvidence: expect.objectContaining({
						provider: "intune",
						complete: true,
						resources: [expect.objectContaining({ id: device })],
					}),
				}),
			);
			expect(console.log).toHaveBeenCalledWith(expect.stringContaining('"providerEvidence"'));
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("bounds provider config input and rejects plaintext credentials before networking", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-cloud-config-"));
		try {
			const path = join(dir, "scope.json");
			await writeFile(path, "a".repeat(65_537));
			expect(() => collectProviderConfig(path)).toThrow("discovery_provider_config_too_large");
			await writeFile(
				path,
				JSON.stringify({
					...config,
					credentials: { clientId: client, clientSecret: "never-store-this" },
				}),
			);
			const network = vi.spyOn(globalThis, "fetch");
			await collectCommand({ tenant: TENANT, provider: "intune", providerConfig: path });
			expect(process.exitCode).toBe(1);
			expect(network).not.toHaveBeenCalled();
			expect(console.error).toHaveBeenCalledWith(
				"AIDR collection failed: discovery_provider_config_invalid",
			);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});
});

describe("provider collection command", () => {
	let previousExitCode: typeof process.exitCode;
	beforeEach(() => {
		previousExitCode = process.exitCode;
		process.exitCode = 0;
		for (const name of [
			"AIDR_DISCOVERY_URL",
			"AIDR_DISCOVERY_ACCESS_TOKEN",
			"AIDR_DISCOVERY_COLLECTOR_CREDENTIAL",
			"AIDR_DISCOVERY_ANON_KEY",
		]) {
			vi.stubEnv(name, "");
		}
		vi.spyOn(core, "getInstallationId").mockResolvedValue("collector-a");
		vi.spyOn(core, "loadFleetInventory").mockResolvedValue(inventory());
		vi.spyOn(core, "saveFleetInventory").mockResolvedValue(undefined);
		vi.spyOn(console, "log").mockImplementation(() => {});
		vi.spyOn(console, "error").mockImplementation(() => {});
	});
	afterEach(() => {
		process.exitCode = previousExitCode;
		vi.restoreAllMocks();
		vi.unstubAllEnvs();
	});

	it("does not replace or publish old inventory when the provider fails", async () => {
		vi.spyOn(core.LocalDiscoveryProvider.prototype, "collect").mockResolvedValue({
			provider: "local",
			status: "unavailable",
			freshness: "unknown",
			inventory: null,
			failClosed: true,
			reason: "collection_failed",
		});
		const fetchSpy = vi.spyOn(globalThis, "fetch");
		await collectCommand({ tenant: "tenant-a", target: ["http://127.0.0.1:8080"], json: true });
		expect(process.exitCode).toBe(1);
		expect(core.saveFleetInventory).not.toHaveBeenCalled();
		expect(fetchSpy).not.toHaveBeenCalled();
		expect(console.log).not.toHaveBeenCalled();
		expect(vi.mocked(console.error).mock.calls.flat().join(" ")).toContain("collection_failed");
	});

	it("prints degraded attempt status even when retained evidence is still fresh", async () => {
		const entry = inventory().items[0];
		if (!entry) throw new Error("test inventory is missing its entry");
		const evidence = inventory({
			reachability: "unreachable",
			scan: { ...entry.scan, reachable: false, error: "timeout" },
		});
		vi.spyOn(core.LocalDiscoveryProvider.prototype, "collect").mockResolvedValue({
			provider: "local",
			status: "degraded",
			freshness: "fresh",
			inventory: evidence,
			failClosed: false,
			reason: "targets_unreachable",
		});
		await collectCommand({ tenant: "tenant-a", target: ["http://127.0.0.1:8080"], json: true });
		expect(process.exitCode).toBe(1);
		expect(core.saveFleetInventory).toHaveBeenCalledWith(expect.any(String), evidence);
		const output = JSON.parse(String(vi.mocked(console.log).mock.calls[0]?.[0]));
		expect(output).toMatchObject({
			...evidence,
			discovery: {
				provider: "local",
				status: "degraded",
				freshness: "fresh",
				reason: "targets_unreachable",
			},
		});
	});

	it("refuses a missing local target source without saving an empty inventory", async () => {
		await collectCommand({ tenant: "tenant-a", json: true });
		expect(process.exitCode).toBe(1);
		expect(core.saveFleetInventory).not.toHaveBeenCalled();
		expect(console.log).not.toHaveBeenCalled();
		expect(vi.mocked(console.error).mock.calls.flat().join(" ")).toContain(
			"collector_targets_required",
		);
	});

	it("rejects managed uploads over 100 targets before scanning", async () => {
		vi.stubEnv("AIDR_DISCOVERY_URL", DISCOVERY_URL);
		vi.stubEnv("AIDR_DISCOVERY_COLLECTOR_CREDENTIAL", COLLECTOR_CREDENTIAL);
		vi.stubEnv("AIDR_DISCOVERY_ANON_KEY", "anon.key");
		const collect = vi.spyOn(core.LocalDiscoveryProvider.prototype, "collect");

		await collectCommand({
			tenant: TENANT,
			target: Array.from({ length: 101 }, (_, index) => `https://agent-${index}.example.test/`),
		});

		expect(process.exitCode).toBe(1);
		expect(collect).not.toHaveBeenCalled();
		expect(core.saveFleetInventory).not.toHaveBeenCalled();
		expect(vi.mocked(console.error).mock.calls.flat().join(" ")).toContain(
			"managed_discovery_upload_supports_at_most_100_targets",
		);
	});
});

describe("managed discovery upload", () => {
	it("requires explicit complete credentials and HTTPS except loopback", () => {
		expect(discoveryUploadConfig({})).toBeNull();
		expect(() => discoveryUploadConfig({ AIDR_DISCOVERY_URL: DISCOVERY_URL })).toThrow(
			"discovery_upload_config_incomplete",
		);
		expect(() =>
			discoveryUploadConfig({
				AIDR_DISCOVERY_URL: "http://remote.example.test/functions/v1/discovery",
				AIDR_DISCOVERY_ACCESS_TOKEN: "jwt.token",
				AIDR_DISCOVERY_ANON_KEY: "anon.key",
			}),
		).toThrow("discovery_upload_config_invalid");
		expect(() =>
			discoveryUploadConfig({
				AIDR_DISCOVERY_URL: DISCOVERY_URL,
				AIDR_DISCOVERY_ACCESS_TOKEN: "jwt.token",
				AIDR_DISCOVERY_COLLECTOR_CREDENTIAL: COLLECTOR_CREDENTIAL,
				AIDR_DISCOVERY_ANON_KEY: "anon.key",
			}),
		).toThrow("discovery_upload_auth_ambiguous");
		expect(
			discoveryUploadConfig({
				AIDR_DISCOVERY_URL: "http://127.0.0.1:8000/functions/v1/discovery",
				AIDR_DISCOVERY_COLLECTOR_CREDENTIAL: COLLECTOR_CREDENTIAL,
				AIDR_DISCOVERY_ANON_KEY: "anon.key",
			})?.mode,
		).toBe("collector");
	});

	it("sends only origin-level reachability and bounded status", () => {
		const local = remoteInventory({
			reachability: "unreachable",
			attempts: 3,
			scan: {
				url: "https://agent.example.test/private/tool",
				reachable: false,
				matched: [],
				cves: [],
				error: "collector_exception:SecretError",
				requestsMade: 1,
			},
		});
		const payload = discoveryIngestPayload(local, 2);
		expect(payload).toMatchObject({
			tenant_id: TENANT,
			collector_id: "collector-a",
			sequence: 2,
			complete: true,
			expected_targets: 1,
			items: [
				{
					target: "https://agent.example.test/",
					reachable: false,
					attempts: 3,
					error_code: "collector_exception",
				},
			],
		});
		expect(JSON.stringify(payload)).not.toContain("private/tool");
		expect(JSON.stringify(payload)).not.toContain("SecretError");
		expect(() =>
			discoveryIngestPayload(
				{
					...local,
					items: [
						local.items[0]!,
						{ ...local.items[0]!, target: "https://agent.example.test/another" },
					],
				},
				2,
			),
		).toThrow("discovery_upload_duplicate_origin");
	});

	it("does not publish a partially scanned reachable endpoint as healthy", () => {
		const local = remoteInventory({
			scan: {
				...remoteInventory().items[0]!.scan,
				reachable: true,
				error: "deadline_exceeded",
			},
		});
		expect(discoveryIngestPayload(local, 1).items).toEqual([
			{
				target: "https://agent.example.test/",
				reachable: false,
				attempts: 1,
				error_code: "other",
			},
		]);
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
			if (body.action === "read")
				return Response.json({ ok: true, collector: { collector_id: "collector-a", sequence: 7 } });
			return Response.json(
				{ ok: true, cycle: { collector_id: "collector-a", sequence: 8, cycle_id: body.cycle_id } },
				{ status: 201 },
			);
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
			if (body.action === "cursor")
				return Response.json({
					ok: true,
					collector_id: "collector-a",
					last_sequence: 9,
					next_sequence: 10,
				});
			return Response.json({ error: "invalid_collector_credential" }, { status: 401 });
		});
		await expect(publishDiscoveryInventory(remoteInventory(), config, transport)).rejects.toThrow(
			"discovery_upload_invalid_collector_credential",
		);
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
		const publish = vi
			.fn()
			.mockRejectedValueOnce(new Error("discovery_upload_network_error"))
			.mockResolvedValueOnce(undefined)
			.mockRejectedValueOnce(new Error("discovery_upload_network_error"));
		const error = vi.spyOn(console, "error").mockImplementation(() => {});
		try {
			await expect(publishDiscoveryCycle(remoteInventory(), config, true, publish)).resolves.toBe(
				false,
			);
			expect(error.mock.calls.flat().join(" ")).toContain("discovery_upload_network_error");
			await expect(publishDiscoveryCycle(remoteInventory(), config, true, publish)).resolves.toBe(
				true,
			);
			await expect(
				publishDiscoveryCycle(remoteInventory(), config, false, publish),
			).rejects.toThrow("discovery_upload_network_error");
			expect(publish).toHaveBeenCalledTimes(3);
		} finally {
			error.mockRestore();
		}
	});
});
