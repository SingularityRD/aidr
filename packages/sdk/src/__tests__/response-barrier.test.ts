import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
	config: vi.fn(),
	state: vi.fn(),
	key: vi.fn(),
	barrier: vi.fn(),
	cacheRead: vi.fn(),
	cacheWrite: vi.fn(),
	network: vi.fn(),
	engine: vi.fn(),
}));

vi.mock("@singularityrd/aidr-core", async () => {
	const { z } = await import("zod");
	return {
		ArtifactSchema: z.object({ type: z.string(), value: z.string() }),
		DecisionEngine: class {
			decide = mocks.engine;
		},
		HeuristicsEngine: class {
			match = () => [];
		},
		UrlCheckClient: class {
			checkUrls = mocks.network;
		},
		VerdictCache: class {
			getUrl = mocks.cacheRead;
			putUrl = mocks.cacheWrite;
		},
		loadConfig: mocks.config,
		isInvalidConfig: () => false,
		loadManagedState: mocks.state,
		getEffectiveManagedApiKey: mocks.key,
		inspectResponseBarrier: mocks.barrier,
		managedStatePath: () => "fixed-installed-managed-state",
		loadThreats: vi.fn(),
		loadTrustedDomains: vi.fn(),
		nullLogger: { debug() {}, info() {}, warn() {}, error() {} },
	};
});

import { AIDRClient } from "../client.js";

const installedState = {
	api_key: "rotated-installed-api",
	entitlement: { tenant_id: "installed-tenant" },
};
const request = { action: "fetch", resource: "https://example.invalid/ordinary" };
const cachedAllow = { verdict: "allow", severity: "info", reasons: [], source: "cache" };

function client(): AIDRClient {
	const result = new AIDRClient({
		apiKey: "unrelated-remote-sdk-api",
		retries: 0,
		urlReputationEnabled: true,
	});
	(result as unknown as { initialized: boolean }).initialized = true;
	return result;
}

beforeEach(() => {
	vi.clearAllMocks();
	mocks.config.mockResolvedValue({
		control_plane: { response_worker_required: false },
		auth: { api_key: "configured-installed-api" },
		licensing: { public_keys_pem: ["fixed-installed-issuer"] },
	});
	mocks.state.mockResolvedValue(installedState);
	mocks.key.mockReturnValue("rotated-installed-api");
	mocks.barrier.mockResolvedValue({ status: "unconfigured" });
	mocks.cacheRead.mockReturnValue(cachedAllow);
	mocks.engine.mockResolvedValue({
		decision: "allow",
		confidence: 1,
		severity: "info",
		reasons: [],
		source: "heuristics",
		matchedThreatId: null,
	});
	mocks.network.mockResolvedValue([
		{ url: request.resource, isMalicious: false, findings: [], flags: [] },
	]);
});

afterEach(() => vi.restoreAllMocks());

describe("SDK installed response controls", () => {
	it("does not return or cache an allow when the operator pauses during provider I/O", async () => {
		mocks.cacheRead.mockReturnValue(undefined);
		mocks.network.mockImplementation(async () => {
			mocks.barrier.mockResolvedValue({ status: "paused", commandId: "pause-during-check" });
			return [{ url: request.resource, isMalicious: false, findings: [], flags: [] }];
		});
		const result = await client().check(request);
		expect(result).toMatchObject({
			allowed: false,
			decision: "deny",
			metadata: { responseControl: "paused" },
		});
		expect(mocks.network).toHaveBeenCalledOnce();
		expect(mocks.cacheWrite).not.toHaveBeenCalled();
	});

	it("checks authenticated pause before a previously cached allow or provider request", async () => {
		const sdk = client();
		expect((await sdk.check(request)).decision).toBe("allow");
		mocks.barrier
			.mockResolvedValueOnce({ status: "unavailable" })
			.mockResolvedValueOnce({ status: "paused", commandId: "pause-1" });
		const denied = await sdk.check(request);
		expect(denied).toMatchObject({
			allowed: false,
			decision: "deny",
			metadata: { responseControl: "paused" },
		});
		expect(mocks.cacheRead).toHaveBeenCalledTimes(1);
		expect(mocks.network).not.toHaveBeenCalled();
	});

	it("binds present local controls to the installed credential, never the remote SDK key or tool context", async () => {
		mocks.barrier.mockResolvedValue({ status: "running" });
		await client().check({
			...request,
			context: { aidrDir: "attacker-directory", apiKey: "attacker-key", required: false },
		});
		expect(mocks.state).toHaveBeenCalledWith("fixed-installed-managed-state", {
			authToken: "configured-installed-api",
			publicKeysPem: ["fixed-installed-issuer"],
		});
		expect(mocks.barrier).toHaveBeenLastCalledWith({
			required: false,
			managedState: installedState,
			apiKey: "rotated-installed-api",
			publicKeysPem: ["fixed-installed-issuer"],
		});
		expect(JSON.stringify(mocks.barrier.mock.calls)).not.toContain("unrelated-remote-sdk-api");
		expect(JSON.stringify(mocks.barrier.mock.calls)).not.toContain("attacker-directory");
	});

	it("denies missing required controls before cache without opening an unrelated vault", async () => {
		mocks.config.mockResolvedValue({
			control_plane: { response_worker_required: true },
			auth: {},
			licensing: { public_keys_pem: [] },
		});
		const result = await client().check(request);
		expect(result).toMatchObject({
			allowed: false,
			decision: "deny",
			metadata: { responseControl: "unavailable" },
		});
		expect(mocks.state).not.toHaveBeenCalled();
		expect(mocks.cacheRead).not.toHaveBeenCalled();
		expect(mocks.network).not.toHaveBeenCalled();
	});

	it("denies corrupted state, broken custody and inspection failures without leaking their errors", async () => {
		mocks.barrier.mockResolvedValue({ status: "unavailable" });
		mocks.state.mockRejectedValue(new Error("PRIVATE-CREDENTIAL-SENTINEL"));
		const result = await client().check(request);
		expect(result.decision).toBe("deny");
		expect(result.reason).not.toContain("PRIVATE-CREDENTIAL-SENTINEL");
		expect(mocks.cacheRead).not.toHaveBeenCalled();
		expect(mocks.network).not.toHaveBeenCalled();
	});

	it("keeps unconfigured remote clients working and checks the current barrier on every call", async () => {
		const sdk = client();
		expect((await sdk.check(request)).decision).toBe("allow");
		expect((await sdk.check(request)).decision).toBe("allow");
		expect(mocks.config).toHaveBeenCalledTimes(2);
		expect(mocks.barrier).toHaveBeenCalledTimes(2);
		expect(mocks.state).not.toHaveBeenCalled();
	});
});
