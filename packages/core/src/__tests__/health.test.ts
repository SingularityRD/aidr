import { beforeEach, describe, expect, it, vi } from "vitest";

const originalEnv = { ...process.env };

type HealthMocks = {
	cacheLoad?: () => Promise<void>;
	config?: Record<string, unknown>;
	fetch?: typeof fetch;
	remoteCache?: Record<string, unknown>;
	remoteCacheError?: Error;
	statError?: Error;
	threats?: unknown[];
	threatLoaderError?: Error;
	version?: string;
};

async function importHealthWithMocks(options: HealthMocks = {}) {
	vi.resetModules();
	vi.clearAllMocks();
	process.env = { ...originalEnv };

	if (options.version !== undefined) {
		process.env.AIDR_VERSION = options.version;
	} else {
		delete process.env.AIDR_VERSION;
	}
	process.env.AIDR_THREATS_DIR = "C:/aidr-test/threats";
	process.env.AIDR_URL_CHECK_ENDPOINT = "https://health.example.test/url-check";

	globalThis.fetch =
		options.fetch ??
		(vi.fn().mockResolvedValue({ status: 204 } as Response) as unknown as typeof fetch);

	vi.doMock("node:fs", async (importOriginal) => {
		const actual = await importOriginal<typeof import("node:fs")>();
		return {
			...actual,
			statSync: vi.fn(() => {
				if (options.statError) throw options.statError;
				return {} as ReturnType<typeof actual.statSync>;
			}),
		};
	});

	vi.doMock("../cache.js", () => ({
		VerdictCache: class {
			async load() {
				if (options.cacheLoad) {
					await options.cacheLoad();
				}
			}
		},
	}));

	vi.doMock("../config.js", () => ({
		AIDR_DIR: "~/.singularity-aidr",
		loadConfig: vi.fn().mockResolvedValue(
			options.config ?? {
				auth: { api_key: "agent-token-secret" },
				control_plane: { remote_policy_cache_enabled: true },
			},
		),
		resolvePath: (path: string) => path.replace("~", "C:/aidr-test/home"),
	}));

	vi.doMock("../remote-policy.js", () => ({
		inspectRemoteRuntimePolicyCache: vi.fn().mockImplementation(async () => {
			if (options.remoteCacheError) throw options.remoteCacheError;
			return {
				enabled: true,
				path: "C:/aidr-test/runtime-policy-cache.json",
				source: "valid",
				usable: true,
				present: true,
				policyVersion: "pol_health",
				cachedAt: "2026-05-06T00:00:00.000Z",
				expiresAt: "2026-05-06T01:00:00.000Z",
				ageSeconds: 10,
				ttlSeconds: 3590,
				keyMatches: true,
				...options.remoteCache,
			};
		}),
	}));

	vi.doMock("../threat-loader.js", () => ({
		loadThreats: vi.fn().mockImplementation(async () => {
			if (options.threatLoaderError) throw options.threatLoaderError;
			return options.threats ?? [{ id: "CLT-CMD-001" }];
		}),
	}));

	vi.doMock("../engine.js", () => ({
		DecisionEngine: class {},
	}));

	vi.doMock("../heuristics.js", () => ({
		HeuristicsEngine: class {},
	}));

	return import("../health.js");
}

describe("health status reporting", () => {
	beforeEach(() => {
		vi.restoreAllMocks();
		process.env = { ...originalEnv };
	});

	it("reports healthy required checks with configured version metadata", async () => {
		const health = await importHealthWithMocks({ version: "9.8.7-test" });

		const status = await health.getHealthStatus();

		expect(status.status).toBe("healthy");
		expect(status.version).toBe("9.8.7-test");
		expect(Date.parse(status.timestamp)).not.toBeNaN();
		expect(status.checks.map((check) => check.name)).toEqual(["core", "cache", "threat_rules"]);
		expect(status.checks.every((check) => check.status === "healthy")).toBe(true);
		expect(status.checks.find((check) => check.name === "threat_rules")?.details).toMatchObject({
			rulesCount: 1,
		});
		await expect(health.isHealthy()).resolves.toBe(true);
	});

	it("degrades when no threat rules are available and preserves dependency statuses", async () => {
		const health = await importHealthWithMocks({ threats: [] });

		const status = await health.getHealthStatus();
		const result = health.toHealthResult(status);

		expect(status.status).toBe("degraded");
		expect(result).toMatchObject({
			status: "degraded",
			version: "0.6.0",
			checks: {
				core: "healthy",
				cache: "healthy",
				threat_rules: "degraded",
			},
		});
		expect(status.checks.find((check) => check.name === "threat_rules")?.message).toContain(
			"No threat rules loaded",
		);
		await expect(health.isHealthy()).resolves.toBe(false);
	});

	it("marks required health unhealthy when a required dependency fails", async () => {
		const health = await importHealthWithMocks({
			cacheLoad: async () => {
				throw new Error("cache file unreadable");
			},
		});

		const status = await health.getHealthStatus();

		expect(status.status).toBe("unhealthy");
		expect(status.checks.find((check) => check.name === "cache")).toMatchObject({
			status: "unhealthy",
			message: "cache file unreadable",
		});
	});

	it("includes extended dependency statuses and degrades on optional endpoint failures", async () => {
		const health = await importHealthWithMocks({
			fetch: vi.fn().mockResolvedValue({ status: 503 } as Response) as unknown as typeof fetch,
		});

		const status = await health.getExtendedHealthStatus();
		const byName = Object.fromEntries(status.checks.map((check) => [check.name, check]));

		expect(status.status).toBe("degraded");
		expect(Object.keys(byName)).toEqual([
			"core",
			"cache",
			"threat_rules",
			"remote_policy",
			"url_endpoint",
			"disk_space",
		]);
		expect(byName.remote_policy).toMatchObject({
			status: "healthy",
			details: {
				policyVersion: "pol_health",
				usable: true,
				keyMatches: true,
			},
		});
		expect(byName.url_endpoint).toMatchObject({
			status: "degraded",
			details: {
				status: 503,
				endpoint: "https://health.example.test/url-check",
			},
		});
		expect(byName.disk_space).toMatchObject({ status: "healthy" });
	});

	it("keeps remote policy health output privacy-safe when an agent token is configured", async () => {
		const health = await importHealthWithMocks({
			config: {
				auth: { api_key: "agent-token-secret" },
				control_plane: { remote_policy_cache_enabled: true },
			},
			remoteCache: {
				source: "mismatched",
				usable: false,
				keyMatches: false,
				message: "Cached policy belongs to a different agent.",
			},
		});

		const status = await health.getExtendedHealthStatus();
		const remotePolicy = status.checks.find((check) => check.name === "remote_policy");
		const serialized = JSON.stringify(status);

		expect(status.status).toBe("degraded");
		expect(remotePolicy).toMatchObject({
			status: "degraded",
			message: "Cached policy belongs to a different agent.",
			details: {
				keyMatches: false,
				source: "mismatched",
			},
		});
		expect(serialized).not.toContain("agent-token-secret");
	});

	it("falls back gracefully for remote policy, endpoint, and missing disk directory errors", async () => {
		const health = await importHealthWithMocks({
			fetch: vi.fn().mockRejectedValue(new Error("network offline")) as unknown as typeof fetch,
			remoteCacheError: new Error("cache metadata corrupt"),
			statError: new Error("missing directory"),
		});

		const status = await health.getExtendedHealthStatus();
		const byName = Object.fromEntries(status.checks.map((check) => [check.name, check]));

		expect(status.status).toBe("unhealthy");
		expect(byName.remote_policy).toMatchObject({
			status: "unhealthy",
			message: "cache metadata corrupt",
		});
		expect(byName.url_endpoint).toMatchObject({
			status: "degraded",
			message: "network offline",
			details: {
				note: "Optional - not critical for local operation",
			},
		});
		expect(byName.disk_space).toMatchObject({
			status: "healthy",
			details: {
				note: "Directory not yet created - will be created on first use",
			},
		});
	});

	it("formats status without losing check messages", async () => {
		const health = await importHealthWithMocks({ threats: [] });
		const formatted = health.formatHealthStatus(await health.getHealthStatus());

		expect(formatted).toContain("Status: DEGRADED");
		expect(formatted).toContain("Version: 0.6.0");
		expect(formatted).toContain("threat_rules: degraded");
		expect(formatted).toContain("No threat rules loaded");
	});
});
