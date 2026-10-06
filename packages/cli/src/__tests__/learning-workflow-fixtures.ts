/** CLI-owned synthetic fixtures; signatures use only the installed public core API. */
import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
	type AgentRuntime,
	canonicalDetectorPolicyPayload,
	LocalEmbeddingModel,
} from "@singularityrd/aidr-core";

const TENANT = "tenant-a";
interface FixtureKeys {
	publicKeyPem: string;
	privateKey: KeyObject;
}

export function syntheticDlpPolicy(): Record<string, unknown> {
	return {
		version: 1,
		tenantId: TENANT,
		maxContentBytes: 4096,
		supportedFormats: ["application/json"],
		unavailableAction: "block",
		labels: [
			{
				id: "fixture-restricted",
				tenantId: TENANT,
				name: "Synthetic label",
				sensitivity: "restricted",
			},
		],
		rules: [
			{
				id: "fixture-rule",
				tenantId: TENANT,
				labelId: "fixture-restricted",
				name: "Synthetic rule",
				action: "block",
				directions: ["input"],
				matchers: [{ type: "keyword", values: ["TENANT-CONFIDENTIAL-MARKER"], wholeWord: false }],
			},
		],
		exceptions: [],
	};
}

/** Test data only: not an efficacy claim or a customer threat corpus. */
export async function behavioralPolicyPayload(
	_tenant?: undefined,
	behavioralOverrides: Record<string, unknown> = {},
): Promise<Record<string, unknown>> {
	const model = new LocalEmbeddingModel({
		modelPath: "",
		vectorSize: 100,
		similarityThreshold: 0.7,
	});
	await model.load();
	const corpus = {
		schema_version: 1,
		tenant_id: TENANT,
		corpus_id: "synthetic-cli-test",
		corpus_version: 1,
		model_version: "local-tinyhash-v1",
		dimension: 100,
		entries: [
			{
				threatId: "synthetic-fixture-only",
				embedding: await model.computeEmbedding(
					JSON.stringify({
						command: "aidr-synthetic-fixture-only violet zeppelin quartz marmalade",
					}),
				),
				metadata: {
					category: "synthetic-test-only",
					severity: "critical",
					description: "Synthetic fixture, not a production threat",
				},
			},
		],
	};
	return {
		schema_version: 2,
		tenant_id: TENANT,
		issued_at: new Date(Date.now() - 60_000).toISOString(),
		expires_at: new Date(Date.now() + 600_000).toISOString(),
		behavioral: {
			enabled: true,
			learning_allowed: true,
			learning_capability: "durable_baseline_v1",
			threat_corpus: {
				...corpus,
				sha256: createHash("sha256").update(canonicalDetectorPolicyPayload(corpus)).digest("hex"),
			},
			...behavioralOverrides,
		},
	};
}

export function entitlementSnapshot(options: {
	premiumModules: string[];
}): Record<string, unknown> {
	return {
		schema_version: 2,
		tenant_id: TENANT,
		subscription_tier: "enterprise",
		included_agents: 5,
		extra_agents: 0,
		allowed_agents: 5,
		premium_modules: options.premiumModules,
		issued_at: new Date(Date.now() - 600_000).toISOString(),
		expires_at: new Date(Date.now() + 600_000).toISOString(),
		grace_until: new Date(Date.now() + 900_000).toISOString(),
		serial: "cli-test-serial-1",
		revocation_epoch: 1,
	};
}

export async function provisionTenantDetectorPolicy(options: {
	homeDir: string;
	agentRuntime: AgentRuntime;
	keys?: FixtureKeys;
	payload?: Record<string, unknown>;
	entitlement?: Record<string, unknown>;
	skipPolicy?: boolean;
	skipEntitlement?: boolean;
}): Promise<{ keys: FixtureKeys; tenantId: string }> {
	const pair = generateKeyPairSync("ed25519");
	const keys = options.keys ?? {
		privateKey: pair.privateKey,
		publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
	};
	const state = join(options.homeDir, ".singularity-aidr");
	await mkdir(state, { recursive: true });
	await writeFile(
		join(state, "config.json"),
		JSON.stringify({
			mode: "managed",
			control_plane: { enabled: false },
			licensing: { public_keys_pem: [keys.publicKeyPem], require_signed_entitlements: true },
			heuristics_enabled: false,
			url_check: { enabled: false },
			package_check: { enabled: false },
			cache: { enabled: false },
			logging: { enabled: false },
			allowlist: { path: join(state, "allowlist.json") },
		}),
	);
	if (!options.skipEntitlement) {
		const entitlement = options.entitlement;
		if (!entitlement) throw new Error("Synthetic entitlement is required.");
		await writeFile(
			join(state, "managed.json"),
			JSON.stringify({
				entitlement,
				entitlement_alg: "ed25519",
				entitlement_key_id: "cli-test-key",
				entitlement_sig: sign(
					null,
					Buffer.from(canonicalDetectorPolicyPayload(entitlement)),
					keys.privateKey,
				).toString("base64"),
			}),
		);
	}
	if (!options.skipPolicy) {
		const payload = options.payload;
		if (!payload) throw new Error("Synthetic policy is required.");
		const target = join(state, "detectors", `${options.agentRuntime}.json`);
		await mkdir(dirname(target), { recursive: true });
		await writeFile(
			target,
			JSON.stringify({
				alg: "ed25519",
				payload,
				sig_b64: sign(
					null,
					Buffer.from(canonicalDetectorPolicyPayload(payload)),
					keys.privateKey,
				).toString("base64"),
			}),
		);
	}
	return { keys, tenantId: TENANT };
}
