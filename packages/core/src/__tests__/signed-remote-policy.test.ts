import { createHash, sign as cryptoSign, generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { verifySignedPolicy } from "../policy-signature.js";
import {
	clearRemoteRuntimePolicyCacheForTests,
	inspectRemoteRuntimePolicyCache,
	syncRemoteRuntimePolicy,
} from "../remote-policy.js";
import { ConfigSchema } from "../types.js";

// Throwaway keys generated per run; nothing here is a real credential.
function newKey() {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	return { privateKey, publicPem: publicKey.export({ type: "spki", format: "pem" }).toString() };
}
const signer = newKey();
const otherSigner = newKey();

function canonicalJson(value: unknown): string {
	const sortKeys = (v: unknown): unknown => {
		if (Array.isArray(v)) return v.map(sortKeys);
		if (!v || typeof v !== "object") return v;
		return Object.fromEntries(
			Object.keys(v as object)
				.sort()
				.map((k) => [k, sortKeys((v as Record<string, unknown>)[k])]),
		);
	};
	return JSON.stringify(sortKeys(value));
}
function sha256(policy: Record<string, unknown>) {
	const canon = JSON.stringify(
		Object.fromEntries(Object.entries(policy).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))),
	);
	return createHash("sha256").update(canon).digest("hex");
}

const NOW = Date.parse("2026-10-05T12:00:00.000Z");
const POLICY = { command_default: "deny", mcp_deny_tools: ["vault.read_secret"] };

function signedBody(
	opts: {
		policy?: Record<string, unknown>;
		sequence?: number;
		key?: KeyObject;
		keyId?: string;
		issuedAt?: number;
		expiresAt?: number;
		version?: string;
		/** Governance overlay served next to the policy (absent = none). */
		governance?: { mcp_deny_servers: string[]; mcp_require_approval_servers: string[] };
		/** Whether the envelope binds governance_sha256 (current signer) or not (legacy signer). */
		bindGovernance?: boolean;
	} = {},
) {
	const policy = opts.policy ?? POLICY;
	const overlayDigest = createHash("sha256")
		.update(
			canonicalJson(opts.governance ?? { mcp_deny_servers: [], mcp_require_approval_servers: [] }),
		)
		.digest("hex");
	const keyId = opts.keyId ?? "policy-key-1";
	const envelope = {
		schema_version: 1,
		key_id: keyId,
		policy_version: opts.version ?? "pol_1",
		policy_sha256: sha256(policy),
		sequence: opts.sequence ?? 1,
		issued_at: new Date(opts.issuedAt ?? NOW - 60_000).toISOString(),
		expires_at: new Date(opts.expiresAt ?? NOW + 3_600_000).toISOString(),
		tenant_id: "tenant_1",
		...(opts.bindGovernance === false ? {} : { governance_sha256: overlayDigest }),
	};
	return {
		ok: true,
		policy_version: envelope.policy_version,
		policy_sha256: envelope.policy_sha256,
		cache_seconds: 60,
		runtime_policy: policy,
		...(opts.governance ? { governance: opts.governance, governance_sha256: overlayDigest } : {}),
		policy_signed: {
			alg: "ed25519",
			key_id: keyId,
			sig_b64: cryptoSign(
				null,
				Buffer.from(canonicalJson(envelope)),
				opts.key ?? signer.privateKey,
			).toString("base64"),
			envelope,
		},
	};
}

describe("verifySignedPolicy", () => {
	const keys = [signer.publicPem];
	const verify = (body: Record<string, unknown>, extra: object = {}) =>
		verifySignedPolicy({ body, publicKeysPem: keys, now: NOW, ...extra });

	it("accepts a correctly signed policy", () => {
		expect(verify(signedBody())).toMatchObject({ ok: true, envelope: { sequence: 1 } });
	});

	it("rejects an unsigned policy", () => {
		const { policy_signed: _drop, ...unsigned } = signedBody();
		expect(verify(unsigned)).toEqual({ ok: false, reason: "missing_signature" });
	});

	it("rejects when no trusted keys are configured", () => {
		expect(verifySignedPolicy({ body: signedBody(), publicKeysPem: [], now: NOW })).toEqual({
			ok: false,
			reason: "no_trusted_keys",
		});
	});

	it("rejects a signature from the wrong signer", () => {
		expect(verify(signedBody({ key: otherSigner.privateKey }))).toEqual({
			ok: false,
			reason: "bad_signature",
		});
	});

	it("accepts either key during rotation (old and new configured)", () => {
		const rotated = signedBody({ key: otherSigner.privateKey, keyId: "policy-key-2" });
		expect(
			verifySignedPolicy({
				body: rotated,
				publicKeysPem: keys.concat(otherSigner.publicPem),
				now: NOW,
			}).ok,
		).toBe(true);
	});

	it("rejects a tampered envelope (sequence bumped without re-signing)", () => {
		const body = signedBody();
		(body.policy_signed.envelope as { sequence: number }).sequence = 99;
		expect(verify(body)).toEqual({ ok: false, reason: "bad_signature" });
	});

	it("rejects a relabelled key id", () => {
		const body = signedBody();
		body.policy_signed.key_id = "policy-key-2";
		expect(verify(body)).toEqual({ ok: false, reason: "malformed_signature" });
	});

	it("rejects a digest or version that differs from the signed envelope", () => {
		const other = signedBody({ policy: { command_default: "allow" } });
		const swapped = { ...signedBody(), policy_sha256: other.policy_sha256 };
		expect(verify(swapped)).toEqual({ ok: false, reason: "binding_mismatch" });
		expect(verify({ ...signedBody(), policy_version: "pol_2" })).toEqual({
			ok: false,
			reason: "binding_mismatch",
		});
	});

	it("rejects expired and not-yet-valid envelopes", () => {
		expect(verify(signedBody({ expiresAt: NOW - 1 }))).toEqual({ ok: false, reason: "expired" });
		expect(verify(signedBody({ issuedAt: NOW + 3_600_000, expiresAt: NOW + 7_200_000 }))).toEqual({
			ok: false,
			reason: "not_yet_valid",
		});
	});

	it("rejects a signing key that the signed revocation feed revoked", () => {
		expect(verify(signedBody(), { revokedKeyIds: new Set(["policy-key-1"]) })).toEqual({
			ok: false,
			reason: "key_revoked",
		});
	});

	it("rejects rollback and conflicting replay at the same sequence, accepts refresh and advance", () => {
		const hw = { sequence: 5, policySha256: sha256(POLICY) };
		expect(verify(signedBody({ sequence: 4 }), { highWater: hw })).toEqual({
			ok: false,
			reason: "rollback",
		});
		expect(
			verify(signedBody({ sequence: 5, policy: { command_default: "allow" } }), { highWater: hw }),
		).toEqual({
			ok: false,
			reason: "rollback",
		});
		expect(verify(signedBody({ sequence: 5 }), { highWater: hw }).ok).toBe(true);
		expect(verify(signedBody({ sequence: 6 }), { highWater: hw }).ok).toBe(true);
	});
});

describe("syncRemoteRuntimePolicy with signed policy", () => {
	const roots: string[] = [];
	const originalFetch = globalThis.fetch;
	afterEach(async () => {
		globalThis.fetch = originalFetch;
		vi.unstubAllEnvs();
		clearRemoteRuntimePolicyCacheForTests();
		for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
	});
	async function setup(
		opts: {
			required?: boolean;
			keys?: string[];
			licensingKeys?: string[];
			revokedKeyIds?: string[];
		} = {},
	) {
		const root = await mkdtemp(join(tmpdir(), "aidr-signed-policy-"));
		roots.push(root);
		const config = ConfigSchema.parse({
			mode: "local",
			control_plane: {
				enabled: true,
				endpoint: "https://policy.example.test",
				remote_policy_required: opts.required ?? false,
				remote_policy_cache_path: join(root, "policy.json"),
				remote_policy_offline_grace_seconds: 60,
				policy_public_keys_pem: opts.keys ?? [signer.publicPem],
			},
			licensing: { public_keys_pem: opts.licensingKeys ?? [] },
			logging: { enabled: false },
			cache: { enabled: false },
		});
		return { config, root };
	}
	const serve = (body: unknown) => {
		globalThis.fetch = vi
			.fn()
			.mockResolvedValue({ ok: true, status: 200, json: async () => body } as Response);
	};
	const sync = (config: ReturnType<typeof ConfigSchema.parse>, now = NOW) =>
		syncRemoteRuntimePolicy(config, "agent-token", undefined, now);

	it("applies a valid signed policy and persists it with its signature", async () => {
		const { config } = await setup({ required: true });
		serve(signedBody());
		const applied = await sync(config);
		expect(applied.policy.runtime_defaults.command_action).toBe("block");
		const raw = await import("node:fs/promises").then((fs) =>
			fs.readFile(config.control_plane.remote_policy_cache_path, "utf8"),
		);
		expect(JSON.parse(raw).body.policy_signed.envelope.sequence).toBe(1);
	});

	it("falls back to licensing public keys when no policy keys are configured", async () => {
		const { config } = await setup({ required: true, keys: [], licensingKeys: [signer.publicPem] });
		serve(signedBody());
		expect((await sync(config)).policy.runtime_defaults.command_action).toBe("block");
		clearRemoteRuntimePolicyCacheForTests();
		await rm(config.control_plane.remote_policy_cache_path, { force: true });
		serve(signedBody({ key: otherSigner.privateKey }));
		await expect(sync(config)).rejects.toThrow("unavailable");
	});

	it("required mode fails closed on unsigned, wrong-signer, tampered and expired policies", async () => {
		const { config } = await setup({ required: true });
		const { policy_signed: _drop, ...unsigned } = signedBody();
		const tampered = signedBody();
		tampered.runtime_policy = { ...POLICY, command_default: "allow" };
		for (const body of [
			unsigned,
			signedBody({ key: otherSigner.privateKey }),
			tampered,
			signedBody({ expiresAt: NOW - 1 }),
		]) {
			serve(body);
			await expect(sync(config)).rejects.toThrow("unavailable");
		}
	});

	it("applies signed governance bans and fails closed when they are stripped or swapped", async () => {
		const governance = { mcp_deny_servers: ["shell-runner"], mcp_require_approval_servers: [] };
		const { config } = await setup({ required: true });
		serve(signedBody({ governance }));
		expect((await sync(config)).policy.mcp.deny_servers).toContain("shell-runner");

		for (const body of [
			// Bans stripped in transit: the envelope still binds them.
			(() => {
				const { governance: _g, governance_sha256: _d, ...stripped } = signedBody({ governance });
				return stripped;
			})(),
			// Bans swapped for a weaker, self-consistent overlay.
			{
				...signedBody({ governance }),
				governance: { mcp_deny_servers: [], mcp_require_approval_servers: [] },
				governance_sha256: createHash("sha256")
					.update(canonicalJson({ mcp_deny_servers: [], mcp_require_approval_servers: [] }))
					.digest("hex"),
			},
		]) {
			clearRemoteRuntimePolicyCacheForTests();
			await rm(config.control_plane.remote_policy_cache_path, { force: true });
			serve(body);
			await expect(sync(config)).rejects.toThrow("unavailable");
		}
	});

	it("still applies (and warns about) an overlay from a legacy signer that does not bind it", async () => {
		const governance = { mcp_deny_servers: ["shell-runner"], mcp_require_approval_servers: [] };
		const { config } = await setup({ required: true });
		serve(signedBody({ governance, bindGovernance: false }));
		const warnings: string[] = [];
		const logger = {
			debug() {},
			info() {},
			warn(message: string) {
				warnings.push(message);
			},
			error() {},
		};
		const applied = await syncRemoteRuntimePolicy(config, "agent-token", logger, NOW);
		expect(applied.policy.mcp.deny_servers).toContain("shell-runner");
		expect(warnings.join(" | ")).toContain("not bound by its signature");
	});

	it("optional mode ignores a bad-signature policy instead of applying it", async () => {
		const { config } = await setup({ required: false });
		serve(signedBody({ key: otherSigner.privateKey, policy: { command_default: "allow" } }));
		const result = await sync(config);
		expect(result.policy.enabled).toBe(false);
	});

	it("skips signature verification when no public keys are configured (digest-only legacy mode)", async () => {
		const { config } = await setup({ required: true, keys: [], licensingKeys: [] });
		const { policy_signed: _drop, ...unsigned } = signedBody();
		serve(unsigned);
		expect((await sync(config)).policy.runtime_defaults.command_action).toBe("block");
	});

	it("rejects a replayed older policy after a newer one was accepted, across processes", async () => {
		const { config } = await setup({ required: true });
		const v2 = signedBody({ sequence: 2, version: "pol_2", policy: { command_default: "ask" } });
		serve(v2);
		await sync(config);
		// New process: memory cache gone, only the disk cache remains.
		clearRemoteRuntimePolicyCacheForTests();
		serve(signedBody({ sequence: 1, version: "pol_1" }));
		await expect(sync(config, NOW + 120_000)).rejects.toThrow("unavailable");
		// A legitimately newer policy still applies.
		serve(signedBody({ sequence: 3, version: "pol_3", policy: { command_default: "deny" } }));
		expect((await sync(config, NOW + 120_000)).policy.runtime_defaults.command_action).toBe(
			"block",
		);
	});

	it("retains rollback protection across authority rejection, outage, and recovery", async () => {
		const { config } = await setup({ required: true });
		serve(signedBody({ sequence: 2, version: "pol_2" }));
		await sync(config);
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: false,
			status: 401,
			json: async () => ({ error: "denied" }),
		} as Response);
		await expect(sync(config, NOW + 61_000)).rejects.toThrow("unavailable");
		const rejected = JSON.parse(
			await readFile(config.control_plane.remote_policy_cache_path, "utf8"),
		);
		expect(rejected.authority_rejected).toBe(true);
		expect(rejected.body.policy_signed.envelope.sequence).toBe(2);
		expect(
			await inspectRemoteRuntimePolicyCache(config, "agent-token", NOW + 62_000),
		).toMatchObject({ source: "invalid", usable: false });
		globalThis.fetch = vi.fn().mockRejectedValue(new Error("offline"));
		await expect(sync(config, NOW + 62_000)).rejects.toThrow("unavailable");
		clearRemoteRuntimePolicyCacheForTests();
		await expect(sync(config, NOW + 62_000)).rejects.toThrow("unavailable");
		serve(signedBody({ sequence: 1, version: "pol_1" }));
		await expect(sync(config, NOW + 63_000)).rejects.toThrow("unavailable");
		serve(signedBody({ sequence: 3, version: "pol_3" }));
		expect((await sync(config, NOW + 63_000)).policy.runtime_defaults.command_action).toBe("block");
		expect(
			JSON.parse(await readFile(config.control_plane.remote_policy_cache_path, "utf8"))
				.authority_rejected,
		).toBeUndefined();
	});

	it("rejects a tampered disk cache and falls back to a fresh signed fetch", async () => {
		const { config } = await setup({ required: true });
		serve(signedBody());
		await sync(config);
		const path = config.control_plane.remote_policy_cache_path;
		const cache = JSON.parse(
			await import("node:fs/promises").then((fs) => fs.readFile(path, "utf8")),
		);
		cache.body.runtime_policy = { ...POLICY, command_default: "allow" };
		cache.body.policy_sha256 = cache.policy_sha256 = sha256(cache.body.runtime_policy);
		await writeFile(path, JSON.stringify(cache));
		clearRemoteRuntimePolicyCacheForTests();
		globalThis.fetch = vi.fn().mockRejectedValue(new Error("offline"));
		await expect(sync(config, NOW + 120_000)).rejects.toThrow("unavailable");
	});

	it("does not use a stale cached policy past its signed expiry even inside offline grace", async () => {
		const { config } = await setup({ required: true });
		serve(signedBody({ expiresAt: NOW + 90_000 }));
		await sync(config);
		clearRemoteRuntimePolicyCacheForTests();
		globalThis.fetch = vi.fn().mockRejectedValue(new Error("offline"));
		// Within cache expiry (60s) + grace (60s) but after signed expiry (90s): must fail closed.
		await expect(sync(config, NOW + 100_000)).rejects.toThrow("unavailable");
	});

	it("rejects a policy signed by a key listed in the signed revocation feed", async () => {
		const licensing = newKey();
		const { config, root } = await setup({ required: true, licensingKeys: [licensing.publicPem] });
		// The revocation feed is bound to this runtime's tenant, which comes from
		// the verified (signed) entitlement in managed state.
		const entitlement = {
			schema_version: 2,
			tenant_id: "tenant_1",
			subscription_tier: "pro",
			included_agents: 1,
			extra_agents: 0,
			allowed_agents: 1,
			premium_modules: [],
			issued_at: new Date(Date.now() - 1000).toISOString(),
			expires_at: new Date(Date.now() + 3_600_000).toISOString(),
			grace_until: new Date(Date.now() + 3_600_000).toISOString(),
			serial: "ser-policy",
			revocation_epoch: 1,
		};
		vi.stubEnv("HOME", root);
		await mkdir(join(root, ".singularity-aidr"), { recursive: true });
		await writeFile(
			join(root, ".singularity-aidr", "managed.json"),
			JSON.stringify({
				entitlement,
				entitlement_alg: "ed25519",
				entitlement_sig: cryptoSign(
					null,
					Buffer.from(canonicalJson(entitlement)),
					licensing.privateKey,
				).toString("base64"),
			}),
		);
		const list = {
			schema_version: 2,
			tenant_id: "tenant_1",
			agent_id: null,
			issued_at: new Date(Date.now() - 1000).toISOString(),
			expires_at: new Date(Date.now() + 3_600_000).toISOString(),
			revocation_epoch: 1,
			revocations: {
				artifact_ids: [],
				pack_ids: [],
				key_ids: ["policy-key-1"],
				entitlement_serials: [],
			},
		};
		const revPath = join(root, "revocations.json");
		await writeFile(
			revPath,
			JSON.stringify({
				alg: "ed25519",
				key_id: "lic",
				sig_b64: cryptoSign(null, Buffer.from(canonicalJson(list)), licensing.privateKey).toString(
					"base64",
				),
				payload: list,
			}),
		);
		config.licensing.revocations_cache_path = revPath;
		serve(signedBody());
		await expect(sync(config)).rejects.toThrow("unavailable");
		serve(signedBody({ keyId: "policy-key-2" }));
		expect((await sync(config)).policy.runtime_defaults.command_action).toBe("block");
	});
});
