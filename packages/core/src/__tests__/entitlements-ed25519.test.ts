import { sign as cryptoSign, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	applyIngestResult,
	applyRevocationsToManagedState,
	type EntitlementSnapshotV1,
	type EntitlementSnapshotV2,
	isPremiumUnlocked,
	type RevocationListV1,
	verifyEd25519SignedEntitlementSnapshot,
	verifyEd25519SignedRevocationList,
} from "../managed.js";

function canonicalize(value: unknown): unknown {
	if (Array.isArray(value)) return value.map((v) => canonicalize(v));
	if (!value || typeof value !== "object") return value;
	const obj = value as Record<string, unknown>;
	const out: Record<string, unknown> = {};
	for (const key of Object.keys(obj).sort()) out[key] = canonicalize(obj[key]);
	return out;
}

function canonicalJson(value: unknown): string {
	return JSON.stringify(canonicalize(value));
}

describe("server-signed entitlements (ed25519) + revocations", () => {
	it("accepts ed25519-signed entitlement snapshot and unlocks premium", () => {
		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();

		const snapshot: EntitlementSnapshotV1 = {
			schema_version: 1,
			issued_at: new Date().toISOString(),
			expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
			free_agents: 1,
			extra_agents: 2,
			allowed_agents: 3,
			price_per_extra_agent_usd_month: 2,
		};
		const sig = cryptoSign(null, Buffer.from(canonicalJson(snapshot), "utf8"), privateKey).toString(
			"base64",
		);

		expect(
			verifyEd25519SignedEntitlementSnapshot({
				snapshot,
				sig_b64: sig,
				public_keys_pem: [publicKeyPem],
			}),
		).toBe(true);

		const next = applyIngestResult(
			{},
			{
				ok: true,
				status: 200,
				body: {
					entitlement_signed: { snapshot, sig_b64: sig, key_id: "test-k1" },
				},
			},
			72,
			{ publicKeysPem: [publicKeyPem] },
		);

		expect(next.entitlement_alg).toBe("ed25519");
		expect(next.entitlement_key_id).toBe("test-k1");
		expect(next.entitlement_sig).toBe(sig);
		expect(next.entitlement?.allowed_agents).toBe(3);
		expect(isPremiumUnlocked(next)).toBe(true);
	});

	it("applies signed revocations to disable premium and sync", () => {
		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();

		const ent: EntitlementSnapshotV2 = {
			schema_version: 2,
			tenant_id: "t-1",
			subscription_tier: "pro",
			included_agents: 1,
			extra_agents: 2,
			allowed_agents: 3,
			premium_modules: ["intel_packs", "correlation"],
			issued_at: new Date().toISOString(),
			expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
			grace_until: new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString(),
			serial: "ser-1",
			revocation_epoch: 1,
		};

		const list: RevocationListV1 = {
			schema_version: 1,
			issued_at: new Date().toISOString(),
			expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
			revocation_epoch: 2,
			revocations: {
				artifact_ids: [],
				pack_ids: [],
				key_ids: [],
				entitlement_serials: ["ser-1"],
			},
		};
		const sig = cryptoSign(null, Buffer.from(canonicalJson(list), "utf8"), privateKey).toString(
			"base64",
		);

		expect(
			verifyEd25519SignedRevocationList({ list, sig_b64: sig, public_keys_pem: [publicKeyPem] }),
		).toBe(true);

		const state = applyRevocationsToManagedState({
			state: {
				seat_status: "ok",
				entitlement: ent,
				entitlement_alg: "ed25519",
				entitlement_sig: "some-sig",
			},
			iid: "iid-1",
			revocations: list,
		});

		expect(state.sync_disabled_reason).toBe("revoked");
		expect(state.seat_status).toBe("over_limit");
		expect(state.entitlement).toBeUndefined();
		expect(isPremiumUnlocked(state)).toBe(false);
	});
});
