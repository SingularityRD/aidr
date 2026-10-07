import { sign as cryptoSign, generateKeyPairSync, type KeyObject } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApprovalStore } from "../approval-store.js";
import { allowVerdict, evaluateToolCall } from "../evaluator.js";
import { guardToolCall } from "../guard.js";
import {
	applyIngestResult,
	type EntitlementSnapshotV2,
	isEntitlementActive,
	isPremiumModuleEnabled,
	isPremiumUnlocked,
	loadManagedState,
	loadRevocationsCache,
	parseSignedRevocationsFromControlPlaneBody,
	redactRemoteEvent,
	verifyEd25519SignedEntitlementSnapshot,
} from "../managed.js";
import { evaluatePolicy } from "../policy.js";
import { ConfigSchema } from "../types.js";

const vaultSecrets = vi.hoisted(() => new Map<string, string>());
vi.mock("../secret-store.js", async (importOriginal) => ({
	...(await importOriginal<typeof import("../secret-store.js")>()),
	resolveSecretStore: () => ({
		kind: "windows-dpapi",
		location: "os-vault",
		osProtected: true,
		isAvailable: () => true,
		put: (id: string, secret: string) => {
			vaultSecrets.set(id, secret);
		},
		get: (id: string) => vaultSecrets.get(id) ?? null,
		revoke: (id: string) => {
			vaultSecrets.delete(id);
		},
	}),
}));

const THREATS_DIR = resolve(__dirname, "..", "..", "..", "..", "threats");
const ALLOWLISTS_DIR = resolve(__dirname, "..", "..", "..", "..", "allowlists");

const originalHome = process.env.HOME;
const originalCommercial = process.env.AIDR_COMMERCIAL;

afterEach(() => {
	vaultSecrets.clear();
	if (originalHome === undefined) delete process.env.HOME;
	else process.env.HOME = originalHome;
	if (originalCommercial === undefined) delete process.env.AIDR_COMMERCIAL;
	else process.env.AIDR_COMMERCIAL = originalCommercial;
});

function canonicalize(value: unknown): unknown {
	if (Array.isArray(value)) return value.map((item) => canonicalize(item));
	if (!value || typeof value !== "object") return value;

	const objectValue = value as Record<string, unknown>;
	const sorted: Record<string, unknown> = {};
	for (const key of Object.keys(objectValue).sort()) {
		sorted[key] = canonicalize(objectValue[key]);
	}
	return sorted;
}

function signSnapshot(snapshot: EntitlementSnapshotV2, privateKey: KeyObject): string {
	return cryptoSign(
		null,
		Buffer.from(JSON.stringify(canonicalize(snapshot)), "utf8"),
		privateKey,
	).toString("base64");
}

function makeEntitlement(
	now: Date,
	expiresAt: Date,
	graceUntil = expiresAt,
): EntitlementSnapshotV2 {
	return {
		schema_version: 2,
		tenant_id: "tenant-critical-test",
		subscription_tier: "pro",
		included_agents: 1,
		extra_agents: 2,
		allowed_agents: 3,
		premium_modules: ["intel_packs", "correlation"],
		issued_at: new Date(now.getTime() - 60_000).toISOString(),
		expires_at: expiresAt.toISOString(),
		grace_until: graceUntil.toISOString(),
		serial: "critical-serial",
		revocation_epoch: 1,
	};
}

function localConfig(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		mode: "local",
		heuristics_enabled: false,
		control_plane: { enabled: false },
		url_check: { enabled: false },
		file_check: { enabled: false },
		package_check: { enabled: false },
		amsi_check: { enabled: false },
		cache: { enabled: false },
		logging: { enabled: false },
		incident: { enabled: false },
		response: { emit_incidents: false },
		...overrides,
	};
}

async function writeRuntimeConfig(dir: string, config: Record<string, unknown>): Promise<string> {
	const configPath = join(dir, "config.json");
	await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");
	return configPath;
}

async function evaluateRuntime(
	dir: string,
	config: Record<string, unknown>,
	toolName: string,
	toolInput: Record<string, unknown>,
	artifacts: Array<{
		type: "url" | "command" | "file_path" | "content";
		value: string;
		context?: string;
	}>,
) {
	const configPath = await writeRuntimeConfig(dir, {
		...localConfig({ allowlist: { path: join(dir, "allowlist.json") } }),
		...config,
	});

	return evaluateToolCall(
		{
			sessionId: "critical-runtime-test",
			toolName,
			toolInput,
			artifacts,
		},
		{
			configPath,
			threatsDir: THREATS_DIR,
			allowlistsDir: ALLOWLISTS_DIR,
		},
	);
}

describe("critical policy and runtime security branches", () => {
	it("denies a tool call even with prior approval when its centrally managed config becomes corrupt", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-critical-evaluator-"));
		try {
			const configPath = await writeRuntimeConfig(dir, {
				...localConfig(),
				control_plane: {
					enabled: true,
					remote_policy_required: true,
					endpoint: "https://control.example.test",
				},
			});
			await writeFile(configPath, "{corrupt", "utf8");
			const request = {
				sessionId: "critical-runtime-test",
				toolName: "Bash",
				toolInput: { command: "echo safe" },
				artifacts: [{ type: "command" as const, value: "echo safe" }],
			};
			const context = { configPath, threatsDir: THREATS_DIR, allowlistsDir: ALLOWLISTS_DIR };
			expect(await evaluateToolCall(request, context)).toMatchObject({
				decision: "deny",
				category: "config_invalid",
			});

			const approvals = new ApprovalStore();
			const actionId = ApprovalStore.actionId(
				request.toolName,
				request.toolInput,
				request.sessionId,
			);
			approvals.setPending(actionId, { artifacts: request.artifacts, createdAt: Date.now() });
			approvals.approve(actionId);
			expect((await guardToolCall(request, context, approvals)).verdict).toMatchObject({
				decision: "deny",
				category: "config_invalid",
			});
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("returns allow, deny, and ask through the evaluator", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-critical-evaluator-"));
		try {
			const allowed = await evaluateRuntime(
				dir,
				{ policy: { enabled: true } },
				"Bash",
				{ command: "echo safe" },
				[{ type: "command", value: "echo safe" }],
			);
			const denied = await evaluateRuntime(
				dir,
				{
					policy: {
						enabled: true,
						shell: { enabled: true, deny_patterns: ["rm\\s+-rf"], deny_action: "block" },
					},
				},
				"Bash",
				{ command: "rm -rf /tmp/data" },
				[{ type: "command", value: "rm -rf /tmp/data" }],
			);
			const asking = await evaluateRuntime(
				dir,
				{
					policy: {
						enabled: true,
						runtime_defaults: { command_action: "require_approval" },
					},
				},
				"Bash",
				{ command: "echo needs-review" },
				[{ type: "command", value: "echo needs-review" }],
			);

			expect(allowed).toMatchObject({ decision: "allow", source: "none" });
			expect(denied).toMatchObject({
				decision: "deny",
				category: "command_execution",
				matchedThreatId: "POL-SH-001",
			});
			expect(asking).toMatchObject({
				decision: "ask",
				category: "command_execution",
				matchedThreatId: "POL-DEFAULT-CMD-001",
			});
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("keeps the exported allow verdict shape stable", () => {
		expect(allowVerdict("critical-test")).toEqual({
			decision: "allow",
			category: "none",
			confidence: 1,
			severity: "info",
			source: "critical-test",
			artifacts: [],
			matchedThreatId: null,
			reasons: [],
		});
	});

	it("handles policy defaults, unknown MCP servers, and malformed inputs safely", async () => {
		const defaultPolicy = ConfigSchema.parse({
			policy: { enabled: true, mcp: { enabled: true } },
		});
		const defaultUnknown = await evaluatePolicy("mcp__unknown__query", [], defaultPolicy, {});
		expect(defaultUnknown).toMatchObject({
			decision: "ask",
			matchedThreatId: "POL-MCP-001",
		});

		const allowedUnknownButBlockedByDefault = ConfigSchema.parse({
			policy: {
				enabled: true,
				mcp: {
					enabled: true,
					unknown_server_action: "allow",
					default_action: "block",
				},
			},
		});
		const defaultBlock = await evaluatePolicy(
			"mcp__unknown__query",
			[],
			allowedUnknownButBlockedByDefault,
			{},
		);
		expect(defaultBlock).toMatchObject({
			decision: "deny",
			matchedThreatId: "POL-MCP-005",
		});

		const malformedInputConfig = ConfigSchema.parse({
			policy: {
				enabled: true,
				filesystem: { enabled: true, allowed_write_roots: ["/safe"] },
				runtime_defaults: { command_action: "unexpected-action" },
			},
		});
		const malformedInput = await evaluatePolicy(
			"Write",
			[{ type: "file_path", value: "/outside/target" }],
			malformedInputConfig,
			{ file_path: 42 } as unknown as Record<string, unknown>,
		);
		expect(malformedInput).toBeNull();

		const disabledPolicy = ConfigSchema.parse({ policy: { enabled: false } });
		expect(
			await evaluatePolicy("Bash", [{ type: "command", value: "rm -rf /" }], disabledPolicy),
		).toBe(null);
	});

	it("accepts only valid active signed entitlements for premium branches", () => {
		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
		const now = new Date();
		const snapshot = makeEntitlement(now, new Date(now.getTime() + 60 * 60 * 1000));
		const signature = signSnapshot(snapshot, privateKey);
		const state = applyIngestResult(
			{},
			{
				ok: true,
				status: 200,
				body: { entitlement_signed: { snapshot, sig_b64: signature, key_id: "critical-key" } },
			},
			72,
			{ publicKeysPem: [publicKeyPem] },
		);

		expect(
			verifyEd25519SignedEntitlementSnapshot({
				snapshot,
				sig_b64: signature,
				public_keys_pem: [publicKeyPem],
			}),
		).toBe(true);
		expect(isEntitlementActive(state, now)).toBe(true);
		expect(isPremiumUnlocked(state, now)).toBe(true);
		expect(isPremiumModuleEnabled(state, "intel_packs", now)).toBe(true);
	});

	it("rejects invalid and expired signed entitlements", () => {
		const { publicKey, privateKey } = generateKeyPairSync("ed25519");
		const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
		const now = new Date();
		const activeSnapshot = makeEntitlement(now, new Date(now.getTime() + 60 * 60 * 1000));
		const invalid = applyIngestResult(
			{},
			{
				ok: true,
				status: 200,
				body: {
					entitlement_signed: {
						snapshot: activeSnapshot,
						sig_b64: Buffer.alloc(64, 7).toString("base64"),
					},
				},
			},
			72,
			{ publicKeysPem: [publicKeyPem] },
		);
		expect(invalid.entitlement).toBeUndefined();
		expect(isPremiumUnlocked(invalid, now)).toBe(false);

		const expiredSnapshot = makeEntitlement(
			new Date(now.getTime() - 3 * 60 * 60 * 1000),
			new Date(now.getTime() - 60 * 60 * 1000),
		);
		const expired = applyIngestResult(
			{},
			{
				ok: true,
				status: 200,
				body: {
					entitlement_signed: {
						snapshot: expiredSnapshot,
						sig_b64: signSnapshot(expiredSnapshot, privateKey),
					},
				},
			},
			72,
			{ publicKeysPem: [publicKeyPem] },
		);
		expect(expired.entitlement_alg).toBe("ed25519");
		expect(isEntitlementActive(expired, now)).toBe(false);
		expect(isPremiumUnlocked(expired, now)).toBe(false);
		expect(isPremiumModuleEnabled(expired, "intel_packs", now)).toBe(false);
	});

	it("redacts credential material before hashing or sending remote events", () => {
		const secret = ["sk_live_", "abcdefgh", "ijklmnop"].join("");
		const entry = {
			tool_input_summary: `Authorization: Bearer ${secret} token=${secret}`,
			artifacts: [`https://example.test/download?token=${secret}`],
			api_key: "aidr-live-secret",
			reasons: ["secret prompt material"],
		};

		const rawMode = redactRemoteEvent(entry, "none");
		const hashedMode = redactRemoteEvent(entry, "hash");
		const fullMode = redactRemoteEvent(entry, "full");

		expect(JSON.stringify(rawMode)).not.toContain(secret);
		expect(JSON.stringify(rawMode)).not.toContain("aidr-live-secret");
		expect(hashedMode.tool_input_summary).toMatch(/^sha256:[0-9a-f]{64}$/);
		expect(hashedMode.artifacts).toEqual([expect.stringMatching(/^sha256:[0-9a-f]{64}$/)]);
		expect(hashedMode.reasons).toEqual([]);
		expect(fullMode).toMatchObject({ tool_input_summary: "", artifacts: [], reasons: [] });
	});

	it("fails closed on malformed managed state, signatures, and revocation data", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-critical-managed-"));
		try {
			const malformedStatePath = join(dir, "managed.json");
			const malformedRevocationsPath = join(dir, "revocations.json");
			await writeFile(malformedStatePath, "{not-json", "utf8");
			await writeFile(malformedRevocationsPath, "[]", "utf8");

			expect(await loadManagedState(malformedStatePath)).toEqual({});
			expect(
				await loadRevocationsCache(malformedRevocationsPath, ["not-a-public-key"], {
					tenantId: "tenant-a",
				}),
			).toBeNull();
			expect(
				parseSignedRevocationsFromControlPlaneBody(
					{
						revocations_signed: { alg: "ed25519", sig_b64: "", payload: {} },
					},
					{ tenantId: "tenant-a" },
				),
			).toBeNull();
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("gates commercial evaluation when signed entitlement verification fails", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-critical-commercial-"));
		try {
			const aidrDir = join(dir, ".singularity-aidr");
			await mkdir(aidrDir, { recursive: true });
			process.env.HOME = dir;
			process.env.AIDR_COMMERCIAL = "1";
			vaultSecrets.set("critical-token-ref", "aidr-critical-token");
			const apiKeyRef = {
				store: "windows-dpapi",
				id: "critical-token-ref",
				created_at: new Date().toISOString(),
			};

			const { publicKey } = generateKeyPairSync("ed25519");
			const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
			const now = new Date();
			const snapshot = makeEntitlement(now, new Date(now.getTime() - 60 * 60 * 1000));
			await writeFile(
				join(aidrDir, "managed.json"),
				JSON.stringify({
					api_key_ref: apiKeyRef,
					entitlement: snapshot,
					entitlement_alg: "ed25519",
					entitlement_sig: Buffer.alloc(64, 3).toString("base64"),
					sync_disabled_until: new Date(now.getTime() + 60 * 60 * 1000).toISOString(),
				}),
				"utf8",
			);

			const configPath = await writeRuntimeConfig(dir, {
				mode: "managed",
				auth: { api_key_ref: apiKeyRef },
				control_plane: { enabled: false },
				licensing: {
					require_signed_entitlements: true,
					public_keys_pem: [publicKeyPem],
					revocations_enabled: false,
				},
				heuristics_enabled: false,
				url_check: { enabled: false },
				file_check: { enabled: false },
				package_check: { enabled: false },
				amsi_check: { enabled: false },
				cache: { enabled: false },
				logging: { enabled: false },
				incident: { enabled: false },
			});

			const verdict = await evaluateToolCall(
				{
					sessionId: "critical-commercial-test",
					toolName: "Bash",
					toolInput: { command: "echo gated" },
					artifacts: [{ type: "command", value: "echo gated" }],
				},
				{ configPath, threatsDir: THREATS_DIR, allowlistsDir: ALLOWLISTS_DIR },
			);

			expect(verdict).toMatchObject({
				decision: "ask",
				category: "managed_disabled",
				source: "managed_disabled",
			});
			expect(verdict.reasons.join(" ")).toContain("invalid");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("does not expose malformed remote data as a usable entitlement", () => {
		const state = applyIngestResult(
			{},
			{ ok: true, status: 200, body: { entitlement_signed: { snapshot: [], sig_b64: 42 } } },
			72,
			{ publicKeysPem: ["not-a-public-key"] },
		);

		expect(state.entitlement).toBeUndefined();
		expect(isEntitlementActive(state)).toBe(false);
		expect(isPremiumUnlocked(state)).toBe(false);
	});

	it("keeps the original event detached while redacting it", () => {
		const entry = {
			tool_input_summary: "token=original-secret",
			artifacts: ["original-secret"],
			reasons: ["original-secret"],
		};

		const redacted = redactRemoteEvent(entry, "hash");

		expect(entry.tool_input_summary).toBe("token=original-secret");
		expect(entry.artifacts).toEqual(["original-secret"]);
		expect(redacted).not.toBe(entry);
	});

	it("keeps malformed policy paths from throwing", async () => {
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				filesystem: {
					enabled: true,
					deny_write_patterns: ["[invalid"],
				},
			},
		});

		const verdict = await evaluatePolicy(
			"Write",
			[{ type: "file_path", value: "/tmp/file" }],
			config,
			{
				file_path: "/tmp/file",
			},
		);
		expect(verdict?.category).toBe("detection_unavailable");
		expect(verdict?.confidence).toBe(0);
		expect(verdict?.reasons[0]).toMatch(/invalid/i);
	});

	it("supports reading a valid detached managed state after verification", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-critical-state-"));
		try {
			const path = join(dir, "managed.json");
			await writeFile(path, JSON.stringify({ seat_status: "ok", api_key: "aidr-test" }), "utf8");
			const loaded = await loadManagedState(path);
			expect(loaded).toEqual({ seat_status: "ok", api_key: "aidr-test" });
			expect(await readFile(path, "utf8")).toContain("aidr-test");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});
});
