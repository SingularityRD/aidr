import { generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocked = vi.hoisted(() => ({
	loadConfig: vi.fn(),
	loadManagedState: vi.fn(),
	isEntitlementActive: vi.fn(),
	resolvePath: vi.fn(),
	createBehavioralDetectionOrchestrator: vi.fn(),
}));

vi.mock("@singularityrd/aidr-core", async () => {
	const { DlpPolicySchema } = await import("../../../core/src/dlp/policy.js");
	return {
		...mocked,
		DlpPolicySchema,
		managedStatePath: () => "managed.json",
	};
});

import {
	canonicalDetectorPolicyPayload,
	detectorPolicyPath,
	loadProvisionedDetectorContext,
} from "../detector-provisioning.js";

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
const tenantId = "tenant-a";
let stateDir: string;

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
	await mkdir(dirname(detectorPolicyPath()), { recursive: true });
	await writeFile(
		detectorPolicyPath(),
		JSON.stringify({ alg: "ed25519", payload: value, sig_b64: signature }),
	);
}

beforeEach(async () => {
	stateDir = await mkdtemp(join(tmpdir(), "aidr-detector-provisioning-"));
	mocked.resolvePath.mockReturnValue(stateDir);
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
});

describe("Claude Code detector provisioning", () => {
	it("passes a signed tenant-bound DLP policy to the evaluator context", async () => {
		await installPolicy(payload());
		const context = await loadProvisionedDetectorContext();
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
		const context = await loadProvisionedDetectorContext();
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
		await expect(loadProvisionedDetectorContext()).rejects.toThrow(
			"trust or tenant binding failed",
		);
	});

	it("rejects a DLP policy whose tenant differs from the signed bundle", async () => {
		const mixed = payload();
		(mixed.dlp.policy as Record<string, unknown>).tenantId = "tenant-b";
		await installPolicy(mixed);
		await expect(loadProvisionedDetectorContext()).rejects.toThrow();
	});

	it("rejects behavioral learning in a one-shot hook process", async () => {
		await installPolicy(payload({ behavioral: { enabled: true, learning_allowed: true } }));
		await expect(loadProvisionedDetectorContext()).rejects.toThrow("invalid");
	});

	it("rejects a signed feed configuration with an untrusted key format", async () => {
		await installPolicy(
			payload({
				reputation_feed: { feed_id: "enterprise-feed", trusted_keys: { publisher: "not-a-key" } },
			}),
		);
		await expect(loadProvisionedDetectorContext()).rejects.toThrow("keyring is invalid");
	});

	it("rejects tampered signatures and expired policies", async () => {
		const signed = payload();
		await installPolicy(signed);
		const tampered = { ...signed, tenant_id: "tenant-b" };
		await writeFile(
			detectorPolicyPath(),
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
		await expect(loadProvisionedDetectorContext()).rejects.toThrow();

		await installPolicy(payload({ expires_at: new Date(Date.now() - 1000).toISOString() }));
		await expect(loadProvisionedDetectorContext()).rejects.toThrow(
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
		await expect(loadProvisionedDetectorContext()).rejects.toThrow("unavailable");
	});

	it("keeps optional detectors absent when none were provisioned", async () => {
		await expect(loadProvisionedDetectorContext()).resolves.toEqual({});
	});
});
