import { sign as cryptoSign, generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	applyIngestResult,
	applyRevocationsToManagedState,
	type EntitlementSnapshotV1,
	type EntitlementSnapshotV2,
	isPremiumUnlocked,
	loadRevocationsCache,
	parseSignedRevocationsFromControlPlaneBody,
	loadRevocationBinding,
	type RevocationBinding,
	type RevocationList,
	revocationBindingForState,
	verifyEd25519SignedEntitlementSnapshot,
	verifyEd25519SignedRevocationList,
} from "../managed.js";

const TENANT = "11111111-1111-4111-8111-111111111111";
const OTHER_TENANT = "22222222-2222-4222-8222-222222222222";
const AGENT = "33333333-3333-4333-8333-333333333333";
const OTHER_AGENT = "44444444-4444-4444-8444-444444444444";
const BINDING: RevocationBinding = { tenantId: TENANT };

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
		const issued = new Date();

		const snapshot: EntitlementSnapshotV1 = {
			schema_version: 1,
			issued_at: issued.toISOString(),
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
		expect(isPremiumUnlocked(next, new Date(issued.getTime() - 1))).toBe(false);
		expect(isPremiumUnlocked(next, issued)).toBe(true);
		expect(isPremiumUnlocked(next)).toBe(true);
	});

	it("accepts network and cached revocations only within their signed lifetime", async () => {
		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
		const issued = Date.parse("2026-01-01T00:00:00.000Z");
		const list: RevocationList = {
			schema_version: 2,
			tenant_id: TENANT,
			agent_id: null,
			issued_at: new Date(issued).toISOString(),
			expires_at: new Date(issued + 2_000).toISOString(),
			revocation_epoch: 1,
			revocations: {
				artifact_ids: [],
				pack_ids: [],
				key_ids: [],
				entitlement_serials: ["revoked-serial"],
			},
		};
		const signed = {
			alg: "ed25519",
			sig_b64: cryptoSign(null, Buffer.from(canonicalJson(list)), privateKey).toString("base64"),
			payload: list,
		};
		const directory = await mkdtemp(join(tmpdir(), "aidr-revocation-lifetime-"));
		try {
			const path = join(directory, "revocations.json");
			await writeFile(path, JSON.stringify(signed));
			for (const [offset, accepted] of [
				[-1, false],
				[0, true],
				[1_000, true],
				[2_000, false],
				[2_001, false],
			] as const) {
				const now = issued + offset;
				expect(
					parseSignedRevocationsFromControlPlaneBody(
						{ revocations_signed: signed },
						BINDING,
						now,
					) !== null,
				).toBe(accepted);
				expect((await loadRevocationsCache(path, [publicKeyPem], BINDING, now)) !== null).toBe(
					accepted,
				);
			}
		} finally {
			await rm(directory, { recursive: true, force: true });
		}
	});

	it("rejects validly signed revocation lists bound to another tenant, an unknown tenant or no tenant", async () => {
		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
		const now = Date.parse("2026-01-01T00:00:01.000Z");
		const sign = (payload: Record<string, unknown>) => ({
			alg: "ed25519",
			sig_b64: cryptoSign(null, Buffer.from(canonicalJson(payload)), privateKey).toString("base64"),
			payload,
		});
		const base = {
			issued_at: "2026-01-01T00:00:00.000Z",
			expires_at: "2026-01-02T00:00:00.000Z",
			revocation_epoch: 1,
			revocations: { artifact_ids: [], pack_ids: [], key_ids: [], entitlement_serials: [] },
		};
		const ours = sign({ schema_version: 2, tenant_id: TENANT, agent_id: AGENT, ...base });
		const theirs = sign({ schema_version: 2, tenant_id: OTHER_TENANT, agent_id: null, ...base });
		const legacyUnbound = sign({ schema_version: 1, ...base });
		const missingAgentKey = sign({ schema_version: 2, tenant_id: TENANT, ...base });
		const directory = await mkdtemp(join(tmpdir(), "aidr-revocation-binding-"));
		try {
			const path = join(directory, "revocations.json");
			const accepts = async (signed: unknown, binding: RevocationBinding) => {
				await writeFile(path, JSON.stringify(signed));
				const network = parseSignedRevocationsFromControlPlaneBody(
					{ revocations_signed: signed },
					binding,
					now,
				);
				const cached = await loadRevocationsCache(path, [publicKeyPem], binding, now);
				expect(network !== null).toBe(cached !== null);
				return cached !== null;
			};
			expect(await accepts(ours, { tenantId: TENANT })).toBe(true);
			expect(await accepts(ours, { tenantId: TENANT.toUpperCase(), agentId: AGENT })).toBe(true);
			expect(await accepts(ours, { tenantId: TENANT, agentId: OTHER_AGENT })).toBe(false);
			expect(await accepts(theirs, { tenantId: TENANT })).toBe(false);
			expect(await accepts(ours, { tenantId: OTHER_TENANT })).toBe(false);
			expect(await accepts(ours, { tenantId: null })).toBe(false);
			expect(await accepts(ours, { tenantId: undefined })).toBe(false);
			expect(await accepts(ours, { tenantId: " " })).toBe(false);
			expect(await accepts(legacyUnbound, { tenantId: TENANT })).toBe(false);
			expect(await accepts(missingAgentKey, { tenantId: TENANT })).toBe(false);
		} finally {
			await rm(directory, { recursive: true, force: true });
		}
		expect(
			revocationBindingForState({ entitlement: { schema_version: 2, tenant_id: TENANT } as never }),
		).toEqual({ tenantId: TENANT });
		expect(revocationBindingForState({})).toEqual({ tenantId: null });
		expect(revocationBindingForState(undefined)).toEqual({ tenantId: null });
	});

	it("derives the binding from managed state only after verifying the signed entitlement", async () => {
		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
		const other = generateKeyPairSync("ed25519")
			.publicKey.export({ type: "spki", format: "pem" })
			.toString();
		const entitlement: EntitlementSnapshotV2 = {
			schema_version: 2,
			tenant_id: TENANT,
			subscription_tier: "pro",
			included_agents: 1,
			extra_agents: 0,
			allowed_agents: 1,
			premium_modules: [],
			issued_at: "2026-01-01T00:00:00.000Z",
			expires_at: "2026-01-02T00:00:00.000Z",
			grace_until: "2026-01-02T00:00:00.000Z",
			serial: "ser-binding",
			revocation_epoch: 1,
		};
		const directory = await mkdtemp(join(tmpdir(), "aidr-revocation-binding-state-"));
		try {
			const path = join(directory, "managed.json");
			const sig = cryptoSign(null, Buffer.from(canonicalJson(entitlement)), privateKey).toString(
				"base64",
			);
			await writeFile(
				path,
				JSON.stringify({ entitlement, entitlement_alg: "ed25519", entitlement_sig: sig }),
			);
			expect(await loadRevocationBinding([publicKeyPem], path)).toEqual({ tenantId: TENANT });
			expect(await loadRevocationBinding([other], path)).toEqual({ tenantId: null });
			expect(await loadRevocationBinding([], path)).toEqual({ tenantId: null });
			await writeFile(
				path,
				JSON.stringify({
					entitlement: { ...entitlement, tenant_id: OTHER_TENANT },
					entitlement_alg: "ed25519",
					entitlement_sig: sig,
				}),
			);
			expect(await loadRevocationBinding([publicKeyPem], path)).toEqual({ tenantId: null });
			expect(await loadRevocationBinding([publicKeyPem], join(directory, "missing.json"))).toEqual({
				tenantId: null,
			});
		} finally {
			await rm(directory, { recursive: true, force: true });
		}
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

		const list: RevocationList = {
			schema_version: 2,
			tenant_id: TENANT,
			agent_id: null,
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
