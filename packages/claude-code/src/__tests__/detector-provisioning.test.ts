import { generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { BehavioralBaselineStore } from "../../../core/src/behavioral-baseline-store.js";
import {
	BehavioralDetectionOrchestrator,
	type BehavioralEmbeddingModel,
} from "../../../core/src/behavioral-orchestrator.js";
import {
	provisionTenantDetectorPolicy,
	TEST_TENANT_ID,
} from "../../../core/src/__tests__/detector-provisioning-fixtures.js";

const mocked = vi.hoisted(() => ({
	loadConfig: vi.fn(),
	loadManagedState: vi.fn(),
	isEntitlementActive: vi.fn(),
	resolvePath: vi.fn(),
	createBehavioralDetectionOrchestrator: vi.fn(),
}));

// The provisioning implementation lives in core, and Claude Code consumes it
// through the package entry point. These mocks stand in for the core
// submodules that implementation reads, so the real control flow (schema,
// signature, tenant binding, expiry) runs in-process rather than being stubbed.
vi.mock("../../../core/src/config.js", async (importOriginal) => {
	const actual = (await importOriginal()) as Record<string, unknown>;
	return { ...actual, loadConfig: mocked.loadConfig, resolvePath: mocked.resolvePath };
});

vi.mock("../../../core/src/managed.js", async (importOriginal) => {
	const actual = (await importOriginal()) as Record<string, unknown>;
	return {
		...actual,
		isEntitlementActive: mocked.isEntitlementActive,
		loadManagedState: mocked.loadManagedState,
		managedStatePath: () => "managed.json",
	};
});

vi.mock("../../../core/src/behavioral-orchestrator.js", async (importOriginal) => {
	const actual = (await importOriginal()) as Record<string, unknown>;
	return {
		...actual,
		createBehavioralDetectionOrchestrator: mocked.createBehavioralDetectionOrchestrator,
	};
});

import {
	canonicalDetectorPolicyPayload,
	detectorPolicyPath,
	loadProvisionedDetectorContext,
} from "../../../core/src/detector-provisioning.js";
import {
	detectorPolicyPath as claudeCodeDetectorPolicyPath,
	loadProvisionedDetectorContext as loadClaudeCodeProvisionedDetectorContext,
} from "../detector-provisioning.js";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const tenantId = "tenant-a";
let stateDir: string;
let realHome: string | undefined;

function payload(overrides: Record<string, unknown> = {}) {
	return {
		schema_version: 1,
		tenant_id: tenantId,
		issued_at: new Date(Date.now() - 60_000).toISOString(),
		expires_at: new Date(Date.now() + 60_000).toISOString(),
		dlp: {
			enabled: true,
			policy: {
				version: 1,
				tenantId,
				labels: [
					{ id: "business-secret", tenantId, name: "Business secret", sensitivity: "restricted" },
				],
				rules: [
					{
						id: "block-secret",
						tenantId,
						labelId: "business-secret",
						name: "Block secret",
						action: "block",
						matchers: [{ type: "keyword", values: ["customer secret"] }],
					},
				],
			},
		},
		...overrides,
	};
}

async function installPolicy(value: Record<string, unknown>, signingKey = privateKey) {
	const signature = sign(
		null,
		Buffer.from(canonicalDetectorPolicyPayload(value)),
		signingKey,
	).toString("base64");
	await mkdir(dirname(detectorPolicyPath("claude-code")), { recursive: true });
	await writeFile(
		detectorPolicyPath("claude-code"),
		JSON.stringify({ alg: "ed25519", payload: value, sig_b64: signature }),
	);
}

beforeEach(async () => {
	stateDir = await mkdtemp(join(tmpdir(), "aidr-detector-provisioning-"));
	mocked.resolvePath.mockReturnValue(stateDir);
	vi.stubEnv("HOME", stateDir);
	mocked.loadConfig.mockResolvedValue({
		mode: "managed",
		licensing: { public_keys_pem: [publicKeyPem] },
	});
	mocked.loadManagedState.mockResolvedValue({
		entitlement_alg: "ed25519",
		entitlement_sig: "verified-by-core",
		entitlement: { schema_version: 2, tenant_id: tenantId, premium_modules: [] },
	});
	mocked.isEntitlementActive.mockReturnValue(true);
	mocked.createBehavioralDetectionOrchestrator.mockReturnValue({ evaluate: vi.fn() });
});

afterEach(async () => {
	vi.clearAllMocks();
	await rm(stateDir, { recursive: true, force: true });
	if (realHome) {
		await rm(realHome, { recursive: true, force: true });
		realHome = undefined;
	}
});

describe("Claude Code detector provisioning", () => {
	it("passes a signed tenant-bound DLP policy to the evaluator context", async () => {
		await installPolicy(payload());
		const context = await loadProvisionedDetectorContext("claude-code");
		expect(context.runtimeDetectors?.tenantId).toBe(tenantId);
		expect(context.runtimeDetectors?.dlp?.enabled).toBe(true);
		expect(context.runtimeDetectors?.dlp?.policy.rules[0]?.id).toBe("block-secret");
	});

	it("passes a signed feed keyring and behavioral opt-in with fixed local storage", async () => {
		await installPolicy(
			payload({
				behavioral: { enabled: true },
				reputation_feed: { feed_id: "enterprise-feed", trusted_keys: { publisher: publicKeyPem } },
			}),
		);
		const context = await loadProvisionedDetectorContext("claude-code");
		expect(context.runtimeDetectors?.behavioral?.enabled).toBe(true);
		expect(context.runtimeDetectors?.behavioral?.learningAllowed).toBe(false);
		expect(context.reputationFeed).toEqual(
			expect.objectContaining({
				feedId: "enterprise-feed",
				storeDir: join(stateDir, "reputation-feeds", "enterprise-feed"),
				trustedKeys: { publisher: publicKeyPem },
			}),
		);
	});

	it("does not let a tool or another tenant select the detector policy", async () => {
		await installPolicy(payload({ tenant_id: "tenant-b" }));
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow(
			"trust or tenant binding failed",
		);
	});

	it("rejects a DLP policy whose tenant differs from the signed bundle", async () => {
		const mixed = payload();
		(mixed.dlp.policy as Record<string, unknown>).tenantId = "tenant-b";
		await installPolicy(mixed);
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow();
	});

	it("rejects behavioral learning in a one-shot hook process", async () => {
		await installPolicy(payload({ behavioral: { enabled: true, learning_allowed: true } }));
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow("invalid");
	});

	it("rejects a signed feed configuration with an untrusted key format", async () => {
		await installPolicy(
			payload({
				reputation_feed: { feed_id: "enterprise-feed", trusted_keys: { publisher: "not-a-key" } },
			}),
		);
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow(
			"keyring is invalid",
		);
	});

	it("rejects tampered signatures and expired policies", async () => {
		const signed = payload();
		await installPolicy(signed);
		const tampered = { ...signed, tenant_id: "tenant-b" };
		await writeFile(
			detectorPolicyPath("claude-code"),
			JSON.stringify({
				alg: "ed25519",
				payload: tampered,
				sig_b64: sign(
					null,
					Buffer.from(canonicalDetectorPolicyPayload(signed)),
					privateKey,
				).toString("base64"),
			}),
		);
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow();

		await installPolicy(payload({ expires_at: new Date(Date.now() - 1000).toISOString() }));
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow(
			"trust or tenant binding failed",
		);
	});

	it("fails closed when signed entitlement requires a missing detector bundle", async () => {
		mocked.loadManagedState.mockResolvedValue({
			entitlement_alg: "ed25519",
			entitlement_sig: "verified-by-core",
			entitlement: {
				schema_version: 2,
				tenant_id: tenantId,
				premium_modules: ["runtime_detectors"],
			},
		});
		await expect(loadProvisionedDetectorContext("claude-code")).rejects.toThrow("unavailable");
	});

	it("keeps optional detectors absent when none were provisioned", async () => {
		await expect(loadProvisionedDetectorContext("claude-code")).resolves.toEqual({});
	});

	it("provisions a behavioral baseline that persists between hook processes", async () => {
		await installPolicy(payload({ behavioral: { enabled: true } }));
		const model: BehavioralEmbeddingModel = {
			load: async () => undefined,
			findSimilarThreats: async () => [],
			getStats: async () => ({
				isLoaded: true,
				threatCount: 1,
				vectorSize: 64,
				modelSizeBytes: 1280,
			}),
		};
		// Provisioning builds the real orchestrator, so a wiring regression (for
		// example dropping the store) fails this test instead of passing quietly.
		mocked.createBehavioralDetectionOrchestrator.mockImplementation(
			(config: ConstructorParameters<typeof BehavioralDetectionOrchestrator>[0], deps) =>
				new BehavioralDetectionOrchestrator(config, deps),
		);
		const event = (command: string) => ({
			tenantId,
			sessionId: "session-a",
			toolName: "Read",
			riskScore: 10,
			timestamp: Date.now(),
			command,
			learningAllowed: true,
		});

		// Hook process 1: an operator-approved baseline workflow accepts the
		// default number of observations (minBaselineSamples is 10). The caller
		// activates a threat model for the same reason it would in production:
		// the shipped local embedder has no threat corpus, and an empty corpus
		// correctly keeps every leg degraded (see the orchestrator tests).
		const first = await loadProvisionedDetectorContext("claude-code");
		const baselineStore = mocked.createBehavioralDetectionOrchestrator.mock.calls.at(-1)?.[1] as
			| { baselineStore?: BehavioralBaselineStore }
			| undefined;
		expect(baselineStore?.baselineStore).toBeDefined();
		const firstProcess = first.runtimeDetectors?.behavioral?.orchestrator;
		if (!firstProcess) throw new Error("Provisioning did not construct an orchestrator");
		await firstProcess.refreshModel(model, "test-model-v1");
		for (let index = 0; index < 10; index++) {
			await firstProcess.evaluate(event(`npm test ${index}`));
		}
		expect(firstProcess.getStats().totalBaselineSamples).toBe(10);
		expect((await baselineStore?.baselineStore?.load(tenantId, "session-a"))?.baselineSamples).toBe(
			10,
		);

		// It is persisted under the fixed AIDR state directory, keyed by tenant.
		const records = await readdir(join(stateDir, "behavioral-baseline"), { recursive: true });
		expect(records.filter((entry) => entry.endsWith(".json"))).toHaveLength(1);

		// Hook process 2: a brand-new process with no in-memory state continues
		// the baseline instead of restarting it.
		const second = await loadProvisionedDetectorContext("claude-code");
		// The signed provisioning contract still pins learning off, which is why
		// this process may only be fed by an operator-approved workflow.
		expect(second.runtimeDetectors?.behavioral?.learningAllowed).toBe(false);
		const secondProcess = second.runtimeDetectors?.behavioral?.orchestrator;
		if (!secondProcess) throw new Error("Provisioning did not construct an orchestrator");
		await secondProcess.refreshModel(model, "test-model-v1");
		const result = await secondProcess.evaluate(event("npm test 0"));

		expect(result.learning.baselineSamplesBefore).toBe(10);
		expect(result.outcome).toBe("normal");
		expect(result.explanations).toContainEqual(
			expect.objectContaining({ leg: "behavioral", status: "ready" }),
		);
		expect(result.explanations).toContainEqual(
			expect.objectContaining({ leg: "novelty", status: "ready" }),
		);
		// Another tenant can never read this tenant's baseline.
		const secondStore = mocked.createBehavioralDetectionOrchestrator.mock.calls.at(-1)?.[1] as
			| { baselineStore?: BehavioralBaselineStore }
			| undefined;
		expect(await secondStore?.baselineStore?.load("tenant-b", "session-a")).toBeNull();
	});
});

describe("Claude Code consumes the shared helper", () => {
	it("reads the core helper's claude-code policy location and applies it", async () => {
		// Real files, real signatures and the published core build: this pins the
		// façade to the one implementation instead of a Claude-only copy.
		realHome = await mkdtemp(join(tmpdir(), "aidr-claude-code-provisioning-"));
		vi.stubEnv("HOME", realHome);
		await provisionTenantDetectorPolicy({ homeDir: realHome, agentRuntime: "claude-code" });

		expect(claudeCodeDetectorPolicyPath()).toBe(
			join(realHome, ".singularity-aidr", "detectors", "claude-code.json"),
		);

		const context = await loadClaudeCodeProvisionedDetectorContext();
		expect(context.runtimeDetectors?.tenantId).toBe(TEST_TENANT_ID);
		expect(context.runtimeDetectors?.dlp?.enabled).toBe(true);
		expect(context.runtimeDetectors?.dlp?.policy.rules[0]?.id).toBe("tenant-restricted-rule");
	});
});
