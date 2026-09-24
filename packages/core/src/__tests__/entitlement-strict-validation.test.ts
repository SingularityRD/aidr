import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	applyIngestResult,
	type EntitlementSnapshotV1,
	type EntitlementSnapshotV2,
	loadManagedState,
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

function signer() {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
	return {
		publicKeyPem,
		signSnapshot: (snapshot: object) =>
			sign(null, Buffer.from(JSON.stringify(canonicalize(snapshot))), privateKey).toString(
				"base64",
			),
	};
}

function validV2(): EntitlementSnapshotV2 {
	return {
		schema_version: 2,
		tenant_id: "tenant-license-test",
		subscription_tier: "pro",
		included_agents: 1,
		extra_agents: 2,
		allowed_agents: 3,
		premium_modules: ["premium_intel"],
		issued_at: "2026-01-01T00:00:00.000Z",
		expires_at: "2026-01-08T00:00:00.000Z",
		grace_until: "2026-01-11T00:00:00.000Z",
		serial: "license-test-1",
		revocation_epoch: 1,
	};
}

function validV1(): EntitlementSnapshotV1 {
	return {
		schema_version: 1,
		issued_at: "2026-01-01T00:00:00.000Z",
		expires_at: "2026-02-01T00:00:00.000Z",
		free_agents: 1,
		extra_agents: 2,
		allowed_agents: 3,
		price_per_extra_agent_usd_month: 2,
	};
}

describe("signed entitlement strict validation", () => {
	it.each([
		["seat sum mismatch", { ...validV2(), allowed_agents: 99 }],
		["negative seats", { ...validV2(), extra_agents: -1 }],
		["unsafe seat count", { ...validV2(), included_agents: Number.MAX_SAFE_INTEGER + 1 }],
		["zero revocation epoch", { ...validV2(), revocation_epoch: 0 }],
		["missing revocation epoch", (({ revocation_epoch: _removed, ...rest }) => rest)(validV2())],
	])("rejects a signed v2 snapshot with %s", (_case, snapshot) => {
		const { publicKeyPem, signSnapshot } = signer();
		const result = applyIngestResult(
			{},
			{
				ok: true,
				status: 200,
				body: { entitlement_signed: { snapshot, sig_b64: signSnapshot(snapshot) } },
			},
			72,
			{ publicKeysPem: [publicKeyPem] },
		);
		expect(result.entitlement).toBeUndefined();
		expect(result.entitlement_alg).toBeUndefined();
	});

	it.each([
		["seat sum mismatch", { ...validV1(), allowed_agents: 99 }],
		["issued after expiry", { ...validV1(), issued_at: "2026-03-01T00:00:00.000Z" }],
	])("rejects a signed v1 snapshot with %s", (_case, snapshot) => {
		const { publicKeyPem, signSnapshot } = signer();
		const result = applyIngestResult(
			{},
			{
				ok: true,
				status: 200,
				body: { entitlement_signed: { snapshot, sig_b64: signSnapshot(snapshot) } },
			},
			72,
			{ publicKeysPem: [publicKeyPem] },
		);
		expect(result.entitlement).toBeUndefined();
	});

	it("drops a validly signed but malformed cached snapshot on load", async () => {
		const { publicKeyPem, signSnapshot } = signer();
		const snapshot = { ...validV2(), allowed_agents: 500 };
		const directory = await mkdtemp(join(tmpdir(), "aidr-invalid-entitlement-"));
		try {
			const events: string[] = [];
			const state = await loadManagedState(join(directory, "managed.json"), {
				publicKeysPem: [publicKeyPem],
				onSecurityEvent: (event) => events.push(event.code),
			});
			await writeFile(
				join(directory, "managed.json"),
				JSON.stringify({
					...state,
					entitlement: snapshot,
					entitlement_alg: "ed25519",
					entitlement_sig: signSnapshot(snapshot),
				}),
			);
			const loaded = await loadManagedState(join(directory, "managed.json"), {
				publicKeysPem: [publicKeyPem],
				onSecurityEvent: (event) => events.push(event.code),
			});
			expect(loaded.entitlement).toBeUndefined();
			expect(events).toEqual(["invalid_ed25519_schema"]);
		} finally {
			await rm(directory, { recursive: true, force: true });
		}
	});
});
