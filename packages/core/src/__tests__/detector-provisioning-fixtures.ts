/**
 * Shared fixtures for the signed tenant detector policy.
 *
 * Every connector test that provisions a policy needs the same three files: a
 * managed config that trusts a publisher key, a managed state carrying a
 * genuinely ed25519-signed v2 entitlement, and the signed detector bundle
 * itself. Signing them here (instead of stubbing core internals) means the
 * connector tests exercise the real verification path.
 */
import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { BehavioralDetectionInput } from "../behavioral-orchestrator.js";
import { canonicalDetectorPolicyPayload } from "../detector-provisioning.js";
import { generateEmbedding } from "../ml/embedder.js";
import type { ThreatEmbedding } from "../ml-model.js";
import type { AgentRuntime } from "../types.js";

export const TEST_TENANT_ID = "tenant-a";
export const TEST_DLP_MARKER = "TENANT-CONFIDENTIAL-MARKER";
export const TEST_SYNTHETIC_THREAT_ID = "synthetic-fixture-only";
/** Exact synthetic input, not a real threat or a production/customer corpus. */
export const TEST_SYNTHETIC_THREAT_TEXT = JSON.stringify({
	command: "aidr-synthetic-fixture-only violet zeppelin quartz marmalade",
});

export interface SyntheticThreatCorpus {
	schema_version: number;
	tenant_id: string;
	corpus_id: string;
	corpus_version: number;
	model_version: string;
	dimension: number;
	entries: ThreatEmbedding[];
	sha256: string;
}

/** Recomputes the digest after overrides, so negative tests still have a valid digest. */
export function syntheticThreatCorpus(
	tenantId: string = TEST_TENANT_ID,
	overrides: Partial<Omit<SyntheticThreatCorpus, "sha256">> = {},
): SyntheticThreatCorpus {
	const corpus = {
		schema_version: 1,
		tenant_id: tenantId,
		corpus_id: "synthetic-test-corpus",
		corpus_version: 1,
		model_version: "local-tinyhash-v1",
		dimension: 100,
		entries: [
			{
				threatId: TEST_SYNTHETIC_THREAT_ID,
				embedding: Array.from(generateEmbedding(TEST_SYNTHETIC_THREAT_TEXT)),
				metadata: {
					category: "synthetic-test-only",
					severity: "critical",
					description: "Explicitly synthetic signed corpus fixture; not a production threat",
				},
			},
		],
		...overrides,
	};
	return {
		...corpus,
		sha256: createHash("sha256").update(canonicalDetectorPolicyPayload(corpus)).digest("hex"),
	};
}

/** Signed v2 capability; callers must separately grant behavioral_learning_v1. */
export function behavioralPolicyPayload(
	tenantId: string = TEST_TENANT_ID,
	behavioralOverrides: Record<string, unknown> = {},
): Record<string, unknown> {
	return detectorPolicyPayload(tenantId, {
		schema_version: 2,
		behavioral: {
			enabled: true,
			learning_allowed: true,
			learning_capability: "durable_baseline_v1",
			threat_corpus: syntheticThreatCorpus(tenantId),
			...behavioralOverrides,
		},
	});
}

/** Ten distinct harmless fingerprints; index ten revisits a known baseline path. */
export function syntheticBehavioralInput(
	index = 0,
	overrides: Partial<BehavioralDetectionInput> = {},
): BehavioralDetectionInput {
	const path = `/synthetic-workspace/document-${index % 10}.txt`;
	return {
		tenantId: TEST_TENANT_ID,
		sessionId: "synthetic-behavioral-session",
		toolName: "Read",
		riskScore: 0,
		timestamp: Date.now(),
		path,
		classificationText: JSON.stringify({ file_path: path }),
		learningAllowed: true,
		...overrides,
	};
}

export interface ProvisioningKeys {
	publicKeyPem: string;
	privateKey: KeyObject;
}

export function generateProvisioningKeys(): ProvisioningKeys {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	return {
		publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
		privateKey,
	};
}

export function detectorPolicyPathFor(homeDir: string, agentRuntime: AgentRuntime): string {
	return join(homeDir, ".singularity-aidr", "detectors", `${agentRuntime}.json`);
}

/**
 * A synthetic tenant DLP policy. The label and rule are test data for this
 * repository — they are not a shipped customer taxonomy.
 */
export function syntheticDlpPolicy(
	tenantId: string = TEST_TENANT_ID,
	marker: string = TEST_DLP_MARKER,
): Record<string, unknown> {
	return {
		version: 1,
		tenantId,
		maxContentBytes: 4096,
		supportedFormats: ["application/json"],
		unavailableAction: "block",
		labels: [
			{
				id: "tenant-restricted",
				tenantId,
				name: "Tenant restricted value",
				sensitivity: "restricted",
			},
		],
		rules: [
			{
				id: "tenant-restricted-rule",
				tenantId,
				labelId: "tenant-restricted",
				name: "Tenant restricted value rule",
				action: "block",
				directions: ["input"],
				matchers: [{ type: "keyword", values: [marker], wholeWord: false }],
			},
		],
		exceptions: [],
	};
}

export function detectorPolicyPayload(
	tenantId: string = TEST_TENANT_ID,
	overrides: Record<string, unknown> = {},
): Record<string, unknown> {
	return {
		schema_version: 1,
		tenant_id: tenantId,
		issued_at: new Date(Date.now() - 60_000).toISOString(),
		expires_at: new Date(Date.now() + 600_000).toISOString(),
		dlp: { enabled: true, policy: syntheticDlpPolicy(tenantId) },
		...overrides,
	};
}

export interface EntitlementOptions {
	tenantId?: string;
	premiumModules?: string[];
	/** An entitlement whose whole online + grace window is already in the past. */
	expired?: boolean;
}

export function entitlementSnapshot(options: EntitlementOptions = {}): Record<string, unknown> {
	const now = Date.now();
	const expiresAt = options.expired ? now - 120_000 : now + 600_000;
	const graceUntil = options.expired ? now - 60_000 : now + 900_000;
	return {
		schema_version: 2,
		tenant_id: options.tenantId ?? TEST_TENANT_ID,
		subscription_tier: "enterprise",
		included_agents: 5,
		extra_agents: 0,
		allowed_agents: 5,
		premium_modules: options.premiumModules ?? ["runtime_detectors"],
		issued_at: new Date(now - 600_000).toISOString(),
		expires_at: new Date(expiresAt).toISOString(),
		grace_until: new Date(graceUntil).toISOString(),
		serial: "test-serial-1",
		revocation_epoch: 1,
	};
}

export interface ProvisionTenantOptions {
	homeDir: string;
	agentRuntime: AgentRuntime;
	keys?: ProvisioningKeys;
	tenantId?: string;
	/** Full signed payload; defaults to a DLP-only policy for `tenantId`. */
	payload?: Record<string, unknown>;
	/** Full signed entitlement snapshot; defaults to an active v2 snapshot. */
	entitlement?: Record<string, unknown>;
	/** Do not write the detector bundle (leaves the runtime unprovisioned). */
	skipPolicy?: boolean;
	/** Do not write managed state at all. */
	skipEntitlement?: boolean;
	/** "signature" signs the wrong bytes, "payload" edits payload after signing. */
	tamperPolicy?: "signature" | "payload";
	mode?: "local" | "managed";
}

export interface ProvisionedTenant {
	keys: ProvisioningKeys;
	tenantId: string;
	configPath: string;
	managedPath: string;
	policyPath: string;
	payload: Record<string, unknown>;
	entitlement: Record<string, unknown>;
}

/**
 * Write a fully provisioned (or deliberately broken) tenant installation under
 * `homeDir`. Returns the resolved file locations so a caller can assert against
 * them or point a child process at the same home.
 */
export async function provisionTenantDetectorPolicy(
	options: ProvisionTenantOptions,
): Promise<ProvisionedTenant> {
	const keys = options.keys ?? generateProvisioningKeys();
	const tenantId = options.tenantId ?? TEST_TENANT_ID;
	const airdrDir = join(options.homeDir, ".singularity-aidr");
	const configPath = join(airdrDir, "config.json");
	const managedPath = join(airdrDir, "managed.json");
	const policyPath = detectorPolicyPathFor(options.homeDir, options.agentRuntime);

	await mkdir(airdrDir, { recursive: true });
	await writeFile(
		configPath,
		JSON.stringify({
			mode: options.mode ?? "managed",
			control_plane: { enabled: false },
			licensing: { public_keys_pem: [keys.publicKeyPem], require_signed_entitlements: true },
			heuristics_enabled: false,
			url_check: { enabled: false },
			package_check: { enabled: false },
			cache: { enabled: false },
			logging: { enabled: false },
			allowlist: { path: join(airdrDir, "allowlist.json") },
		}),
	);

	const entitlement = options.entitlement ?? entitlementSnapshot({ tenantId });
	if (!options.skipEntitlement) {
		await writeFile(
			managedPath,
			JSON.stringify({
				entitlement,
				entitlement_alg: "ed25519",
				entitlement_key_id: "test-key",
				entitlement_sig: sign(
					null,
					Buffer.from(canonicalDetectorPolicyPayload(entitlement)),
					keys.privateKey,
				).toString("base64"),
			}),
		);
	}

	const payload = options.payload ?? detectorPolicyPayload(tenantId);
	if (!options.skipPolicy) {
		const signature = sign(
			null,
			Buffer.from(canonicalDetectorPolicyPayload(payload)),
			options.tamperPolicy === "signature"
				? generateProvisioningKeys().privateKey
				: keys.privateKey,
		).toString("base64");
		const written =
			options.tamperPolicy === "payload" ? { ...payload, tenant_id: "tenant-tampered" } : payload;
		await mkdir(dirname(policyPath), { recursive: true });
		await writeFile(
			policyPath,
			JSON.stringify({ alg: "ed25519", payload: written, sig_b64: signature }),
		);
	}

	return { keys, tenantId, configPath, managedPath, policyPath, payload, entitlement };
}
