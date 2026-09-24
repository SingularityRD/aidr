import { generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { loadIntelKeyring } from "../intel/keyring.js";
import {
	applyIngestResult,
	applyRevocationsToManagedState,
	type EntitlementSnapshotV2,
	isEntitlementActive,
	isPremiumModuleEnabled,
	loadManagedState,
	type ManagedState,
	type RevocationListV1,
	saveEntitlementKeyringFromState,
	saveManagedState,
} from "../managed.js";

function canonicalize(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(canonicalize);
	if (!value || typeof value !== "object") return value;
	return Object.fromEntries(
		Object.entries(value as Record<string, unknown>)
			.sort(([left], [right]) => left.localeCompare(right))
			.map(([key, child]) => [key, canonicalize(child)]),
	);
}

function signedState(snapshot: EntitlementSnapshotV2): {
	state: ManagedState;
	publicKeyPem: string;
} {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
	const signature = sign(
		null,
		Buffer.from(JSON.stringify(canonicalize(snapshot))),
		privateKey,
	).toString("base64");
	const state = applyIngestResult(
		{},
		{
			ok: true,
			status: 200,
			body: {
				entitlement_signed: { snapshot, sig_b64: signature, key_id: "test-key" },
			},
		},
		72,
		{ publicKeysPem: [publicKeyPem] },
	);
	return { state, publicKeyPem };
}

function snapshotAt(issued: Date, graceHours: number): EntitlementSnapshotV2 {
	const expires = new Date(issued.getTime() + 168 * 3_600_000);
	const grace = new Date(expires.getTime() + graceHours * 3_600_000);
	return {
		schema_version: 2,
		tenant_id: "tenant-grace-test",
		subscription_tier: "pro",
		included_agents: 1,
		extra_agents: 1,
		allowed_agents: 2,
		premium_modules: ["premium_intel"],
		pack_keys: [
			{
				alg: "aes-256-gcm",
				key_id: "pack-v1",
				key_b64: Buffer.alloc(32, 7).toString("base64"),
				expires_at: grace.toISOString(),
			},
		],
		issued_at: issued.toISOString(),
		expires_at: expires.toISOString(),
		grace_until: grace.toISOString(),
		serial: "serial-grace-test",
		revocation_epoch: 1,
	};
}

afterEach(() => {
	vi.useRealTimers();
});

describe("signed entitlement expiry and offline grace", () => {
	it("keeps premium available after online expiry and stops exactly at grace end", () => {
		const issued = new Date("2026-01-01T00:00:00.000Z");
		const snapshot = snapshotAt(issued, 72);
		const { state } = signedState(snapshot);
		expect(state.entitlement_alg).toBe("ed25519");
		expect(isEntitlementActive(state, new Date("2026-01-08T01:00:00.000Z"))).toBe(true);
		expect(
			isPremiumModuleEnabled(state, "premium_intel", new Date("2026-01-08T01:00:00.000Z")),
		).toBe(true);
		expect(isEntitlementActive(state, new Date(snapshot.grace_until))).toBe(false);
		expect(isPremiumModuleEnabled(state, "premium_intel", new Date(snapshot.grace_until))).toBe(
			false,
		);
	});

	it("treats zero grace as online expiry and rejects reversed signed timestamps", () => {
		const issued = new Date("2026-01-01T00:00:00.000Z");
		const zeroGrace = snapshotAt(issued, 0);
		const { state } = signedState(zeroGrace);
		expect(isEntitlementActive(state, new Date(zeroGrace.expires_at))).toBe(false);

		const reversed = { ...snapshotAt(issued, 72), grace_until: issued.toISOString() };
		expect(signedState(reversed).state.entitlement).toBeUndefined();
	});

	it("drops an old signed cache window, then accepts a refreshed signed snapshot", async () => {
		const issued = new Date("2026-01-01T00:00:00.000Z");
		const oldGrace = new Date(issued.getTime() + 72 * 3_600_000).toISOString();
		const oldSnapshot = {
			...snapshotAt(issued, 72),
			grace_until: oldGrace,
			pack_keys: [{ ...snapshotAt(issued, 72).pack_keys![0], expires_at: oldGrace }],
		};
		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
		const signSnapshot = (snapshot: EntitlementSnapshotV2) =>
			sign(null, Buffer.from(JSON.stringify(canonicalize(snapshot))), privateKey).toString("base64");
		const dir = await mkdtemp(join(tmpdir(), "aidr-old-entitlement-"));
		try {
			const path = join(dir, "managed.json");
			await writeFile(path, JSON.stringify({
				api_key: "cached-key",
				entitlement: oldSnapshot,
				entitlement_alg: "ed25519",
				entitlement_sig: signSnapshot(oldSnapshot),
			}));
			const events: string[] = [];
			const loaded = await loadManagedState(path, {
				publicKeysPem: [publicKeyPem],
				onSecurityEvent: (event) => events.push(event.code),
			});
			expect(events).toEqual(["invalid_ed25519_schema"]);
			expect(loaded.api_key).toBe("cached-key");
			expect(loaded.entitlement).toBeUndefined();
			expect(isPremiumModuleEnabled(loaded, "premium_intel", issued)).toBe(false);

			const fresh = snapshotAt(issued, 72);
			const refreshed = applyIngestResult(loaded, {
				ok: true,
				status: 200,
				body: {
					entitlement_signed: { snapshot: fresh, sig_b64: signSnapshot(fresh), key_id: "test-key" },
				},
			}, 72, { publicKeysPem: [publicKeyPem] });
			await saveManagedState(path, refreshed);
			const reloaded = await loadManagedState(path, { publicKeysPem: [publicKeyPem] });
			expect(isEntitlementActive(reloaded, new Date("2026-01-08T01:00:00.000Z"))).toBe(true);
			expect(isEntitlementActive(reloaded, new Date(fresh.grace_until))).toBe(false);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("never trusts a cached entitlement without a signature", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-unsigned-entitlement-"));
		try {
			const path = join(dir, "managed.json");
			await writeFile(path, JSON.stringify({
				api_key: "cached-key",
				entitlement: snapshotAt(new Date(), 72),
				entitlement_alg: "ed25519",
			}));
			const events: string[] = [];
			const loaded = await loadManagedState(path, {
				onSecurityEvent: (event) => events.push(event.code),
			});
			expect(events).toEqual(["missing_entitlement_signature"]);
			expect(loaded.api_key).toBe("cached-key");
			expect(loaded.entitlement).toBeUndefined();
			expect(loaded.entitlement_alg).toBeUndefined();
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("invalidates signed grace after definitive access or seat rejection but keeps it on outage", () => {
		const { state } = signedState(snapshotAt(new Date(), 72));
		const cached = { ...state, api_key: "invalid-key" };
		const outage = applyIngestResult(cached, { ok: false, status: 503 }, 72);
		expect(outage).toBe(cached);
		expect(isEntitlementActive(outage)).toBe(true);

		const rejected = applyIngestResult(cached, {
			ok: false,
			status: 401,
			error: "invalid_api_key",
			body: { error: "invalid_api_key" },
		}, 72, { authToken: "invalid-key" });
		expect(rejected.api_key).toBeUndefined();
		expect(rejected.entitlement).toBeUndefined();
		expect(rejected.entitlement_alg).toBeUndefined();
		expect(rejected.sync_disabled_reason).toBe("invalid_api_key");
		expect(isEntitlementActive(rejected)).toBe(false);
		expect(isPremiumModuleEnabled(rejected, "premium_intel")).toBe(false);

		for (const error of [
			"tenant_access_denied",
			"tenant_not_admitted",
			"entitlement_not_provisioned",
			"agent_key_mismatch",
		]) {
			const denied = applyIngestResult(cached, {
				ok: false,
				status: 403,
				body: { error },
			}, 72);
			expect(denied.api_key).toBe("invalid-key");
			expect(denied.sync_disabled_reason).toBe(error);
			expect(isEntitlementActive(denied)).toBe(false);
		}

		const before = Date.now();
		const overLimit = applyIngestResult(cached, {
			ok: false,
			status: 402,
			body: { error: "agent_limit_exceeded", allowed_agents: 1, current_agents: 2 },
		}, 72);
		expect(overLimit.seat_status).toBe("over_limit");
		expect(isEntitlementActive(overLimit)).toBe(false);
		const nextAttempt = Date.parse(overLimit.sync_disabled_until ?? "");
		expect(nextAttempt).toBeGreaterThanOrEqual(before + 300_000);
		expect(nextAttempt).toBeLessThanOrEqual(Date.now() + 301_000);
	});

	it("does not reinterpret a delivered telemetry replay as a new entitlement", () => {
		const { state } = signedState(snapshotAt(new Date(), 72));
		const replay = applyIngestResult(state, {
			ok: true,
			body: { telemetry_queue: { deliveryState: "available" } },
		}, 72, { authToken: "cached-key" });
		expect(replay).toBe(state);
		expect(replay.entitlement_alg).toBe("ed25519");
		expect(isPremiumModuleEnabled(replay, "premium_intel")).toBe(true);
	});

	it("loads an issued pack key during grace but neither after grace nor after revocation", async () => {
		const issued = new Date("2026-01-01T00:00:00.000Z");
		vi.useFakeTimers();
		vi.setSystemTime(issued);
		const dir = await mkdtemp(join(tmpdir(), "aidr-entitlement-grace-"));
		const previousHome = process.env.HOME;
		process.env.HOME = dir;
		try {
			const aidrDir = join(dir, ".singularity-aidr");
			await mkdir(join(aidrDir, "intel"), { recursive: true });
			const snapshot = snapshotAt(issued, 72);
			const { state, publicKeyPem } = signedState(snapshot);
			const managedPath = join(aidrDir, "managed.json");
			await writeFile(
				join(aidrDir, "config.json"),
				JSON.stringify({
					licensing: { public_keys_pem: [publicKeyPem] },
				}),
			);
			await saveManagedState(managedPath, state);
			await saveEntitlementKeyringFromState(state);
			await writeFile(
				join(aidrDir, "intel", "keys.json"),
				JSON.stringify({ intel_keys: { fallback: Buffer.alloc(32, 1).toString("base64") } }),
			);
			const duringGrace = new Date("2026-01-08T01:00:00.000Z");
			expect((await loadIntelKeyring({ now: duringGrace })).has("pack-v1")).toBe(true);
			expect((await loadIntelKeyring({ now: new Date(snapshot.grace_until) })).size).toBe(0);
			await saveManagedState(managedPath, { ...state, entitlement_sig: "invalid-signature" });
			expect((await loadIntelKeyring({ now: duringGrace })).size).toBe(0);
			await saveManagedState(managedPath, state);
			const admissionDenied = applyIngestResult(state, {
				ok: false,
				status: 403,
				body: { error: "tenant_access_denied" },
			}, 72);
			await saveManagedState(managedPath, admissionDenied);
			await saveEntitlementKeyringFromState(admissionDenied);
			expect((await loadIntelKeyring({ now: duringGrace })).size).toBe(0);
			await saveManagedState(managedPath, state);
			await saveEntitlementKeyringFromState(state);

			const revocations: RevocationListV1 = {
				schema_version: 1,
				issued_at: issued.toISOString(),
				expires_at: snapshot.grace_until,
				revocation_epoch: 2,
				revocations: {
					artifact_ids: [],
					pack_ids: [],
					key_ids: [],
					entitlement_serials: [snapshot.serial],
				},
			};
			const revoked = applyRevocationsToManagedState({ state, iid: "iid-1", revocations });
			await saveManagedState(managedPath, revoked);
			// Even before the derived keyring is rewritten, the revoked managed
			// state prevents stale key material from being loaded again.
			expect((await loadIntelKeyring({ now: duringGrace })).size).toBe(0);
			await saveEntitlementKeyringFromState(revoked);
			expect((await loadIntelKeyring({ now: duringGrace })).size).toBe(0);
			const keyring = JSON.parse(await readFile(join(aidrDir, "entitlement.json"), "utf8"));
			expect(keyring.intel_keys).toEqual({});
			expect(keyring.revoked).toBe(true);
			await writeFile(join(aidrDir, "entitlement.json"), "{corrupt-json");
			expect((await loadIntelKeyring({ now: duringGrace })).size).toBe(0);
		} finally {
			if (previousHome === undefined) delete process.env.HOME;
			else process.env.HOME = previousHome;
			await rm(dir, { recursive: true, force: true });
		}
	});
});
