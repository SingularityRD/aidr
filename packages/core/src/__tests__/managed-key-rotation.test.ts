import { createHash, sign as cryptoSign, generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ControlPlaneClient } from "../clients/control-plane.js";
import { evaluateToolCall } from "../evaluator.js";
import {
	applyIngestResult,
	type EntitlementSnapshotV2,
	getEffectiveManagedApiKey,
	loadManagedState,
	managedTelemetryQueueNamespace,
	saveManagedState,
	shouldRefreshManagedEntitlement,
} from "../managed.js";
import { clearRemoteRuntimePolicyCacheForTests } from "../remote-policy.js";
import { DurableTelemetryQueue } from "../telemetry-queue.js";
import type { ControlPlaneConfig } from "../types.js";

const NOW = Date.parse("2026-10-05T12:00:00.000Z");
const NOW_SECONDS = NOW / 1000;
const DAY = 24 * 60 * 60;
const signer = generateKeyPairSync("ed25519");
const publicKeyPem = signer.publicKey.export({ type: "spki", format: "pem" }).toString();

function token(overrides: Record<string, unknown> = {}): string {
	const claims = {
		uid: "tenant-1",
		agent_id: "agent-1",
		jti: "rotation-1",
		iat: NOW_SECONDS,
		exp: NOW_SECONDS + 7 * DAY,
		...overrides,
	};
	return [
		Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url"),
		Buffer.from(JSON.stringify(claims)).toString("base64url"),
		Buffer.alloc(32, 1).toString("base64url"),
	].join(".");
}

const previousKey = token({ jti: "previous", iat: NOW_SECONDS - 6 * DAY, exp: NOW_SECONDS + DAY });
const nextKey = token();

function signedEntitlement(overrides: Partial<EntitlementSnapshotV2> = {}) {
	const snapshot: EntitlementSnapshotV2 = {
		schema_version: 2,
		tenant_id: "tenant-1",
		subscription_tier: "pro",
		included_agents: 1,
		extra_agents: 0,
		allowed_agents: 1,
		premium_modules: [],
		issued_at: new Date(NOW - 60_000).toISOString(),
		expires_at: new Date(NOW + 3_600_000).toISOString(),
		grace_until: new Date(NOW + 7_200_000).toISOString(),
		serial: "rotation-entitlement",
		revocation_epoch: 1,
		...overrides,
	};
	const canonical = JSON.stringify(
		Object.fromEntries(Object.entries(snapshot).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))),
	);
	return {
		snapshot,
		sig_b64: cryptoSign(null, Buffer.from(canonical), signer.privateKey).toString("base64"),
		key_id: "rotation-signer",
	};
}

function responseBody(overrides: Record<string, unknown> = {}) {
	return {
		api_key: nextKey,
		agent_id: "agent-1",
		entitlement_signed: signedEntitlement(),
		...overrides,
	};
}

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(NOW);
});
afterEach(() => vi.useRealTimers());

describe("managed endpoint key rotation", () => {
	it("drains the same WAL after rotation, restart, and a late old-process enqueue", async () => {
		const root = await mkdtemp(join(tmpdir(), "aidr-rotation-backlog-"));
		const originalFetch = globalThis.fetch;
		const commercial = process.env.AIDR_COMMERCIAL;
		process.env.AIDR_COMMERCIAL = "0";
		try {
			const endpoint = "https://queue-rotation.example.test";
			const iid = "rotation-installation";
			const config = { endpoint, timeout_seconds: 1 } as ControlPlaneConfig;
			const anchor = managedTelemetryQueueNamespace(undefined, endpoint, previousKey, iid);
			const oldQueue = new DurableTelemetryQueue({ directory: join(root, anchor), batchSize: 200 });
			const ids = Array.from(
				{ length: 201 },
				(_, index) => `evt-${String(index).padStart(3, "0")}`,
			);
			expect(
				(await oldQueue.enqueue(ids.map((event_id) => ({ event_id, type: "runtime_verdict" }))))
					.acceptedEventIds,
			).toHaveLength(201);
			const batches: string[][] = [];
			let successor = nextKey;
			globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
				const payload = JSON.parse(String(init.body)) as { events: Array<{ event_id: string }> };
				const acknowledged = payload.events.map((event) => event.event_id);
				batches.push(acknowledged);
				return {
					ok: true,
					status: 200,
					json: async () => ({
						...responseBody({ api_key: successor }),
						acknowledged_event_ids: acknowledged,
					}),
				} as Response;
			});
			const options = { telemetryQueueRoot: root, telemetryQueue: { batchSize: 200 } };
			const oldClient = new ControlPlaneClient(config, previousKey, undefined, options);
			const first = await oldClient.ingest({ iid, events: [] });
			expect(first.ok).toBe(true);
			expect((await oldQueue.inspect()).metrics.pendingEvents).toBe(1);
			const state = applyIngestResult({ api_key: previousKey }, first, 72, {
				authToken: previousKey,
				publicKeysPem: [publicKeyPem],
				endpoint,
				iid,
			});
			expect(state.api_key).toBe(nextKey);
			expect(state.telemetry_queue?.anchor_namespace).toBe(anchor);
			const statePath = join(root, "managed.json");
			await saveManagedState(statePath, state);
			const loaded = await loadManagedState(statePath, { publicKeysPem: [publicKeyPem] });
			await oldQueue.enqueue([{ event_id: "evt-late", type: "runtime_verdict" }]);
			successor = token({
				jti: "second-rotation",
				iat: NOW_SECONDS + 1,
				exp: NOW_SECONDS + 7 * DAY + 1,
			});
			vi.setSystemTime(NOW + 1000);
			const rotatedClient = new ControlPlaneClient(config, nextKey, undefined, {
				...options,
				telemetryQueueBinding: loaded.telemetry_queue,
			});
			const second = await rotatedClient.ingest({ iid, events: [] });
			expect(second.ok).toBe(true);
			expect(batches[0]).toHaveLength(200);
			expect(batches[1]).toEqual(["evt-200", "evt-late"]);
			expect((await oldQueue.inspect()).metrics.pendingEvents).toBe(0);
			const twiceRotated = applyIngestResult(loaded, second, 72, {
				authToken: nextKey,
				publicKeysPem: [publicKeyPem],
				endpoint,
				iid,
			});
			expect(twiceRotated.api_key).toBe(successor);
			expect(
				managedTelemetryQueueNamespace(twiceRotated.telemetry_queue, endpoint, successor, iid),
			).toBe(anchor);
		} finally {
			globalThis.fetch = originalFetch;
			if (commercial === undefined) delete process.env.AIDR_COMMERCIAL;
			else process.env.AIDR_COMMERCIAL = commercial;
			await rm(root, { recursive: true, force: true });
		}
	});

	it("authenticates queue routing and keeps unrelated credentials, endpoints and installations separate", () => {
		const endpoint = "https://queue-rotation.example.test";
		const iid = "rotation-installation";
		const state = applyIngestResult(
			{ api_key: previousKey },
			{ ok: true, status: 200, body: responseBody() },
			72,
			{
				authToken: previousKey,
				publicKeysPem: [publicKeyPem],
				endpoint,
				iid,
			},
		);
		const binding = state.telemetry_queue;
		expect(binding).toBeDefined();
		if (!binding) throw new Error("Expected authenticated queue binding");
		const anchor = managedTelemetryQueueNamespace(binding, endpoint, nextKey, iid);
		for (const [otherEndpoint, otherKey, otherIid] of [
			["https://other-tenant.example.test", nextKey, iid],
			[endpoint, token({ uid: "tenant-2" }), iid],
			[endpoint, nextKey, "other-installation"],
		] as const) {
			expect(managedTelemetryQueueNamespace(binding, otherEndpoint, otherKey, otherIid)).toBe(
				managedTelemetryQueueNamespace(undefined, otherEndpoint, otherKey, otherIid),
			);
			expect(managedTelemetryQueueNamespace(binding, otherEndpoint, otherKey, otherIid)).not.toBe(
				anchor,
			);
		}
		expect(() =>
			managedTelemetryQueueNamespace(
				{ ...binding, anchor_namespace: "a".repeat(64) },
				endpoint,
				nextKey,
				iid,
			),
		).toThrow("Invalid managed telemetry queue binding");
		expect(() =>
			managedTelemetryQueueNamespace(
				{ ...binding, anchor_namespace: "../other-tenant" },
				endpoint,
				nextKey,
				iid,
			),
		).toThrow("Invalid managed telemetry queue binding");
	});

	it("bounds refresh attempts, renews stale sessions, and anticipates key expiry", () => {
		const entitlement = signedEntitlement({
			expires_at: new Date(NOW + 14 * DAY * 1000).toISOString(),
			grace_until: new Date(NOW + 14 * DAY * 1000).toISOString(),
		}).snapshot;
		const state = { entitlement, last_success_at: new Date(NOW).toISOString() };
		expect(shouldRefreshManagedEntitlement(state, nextKey)).toBe(false);
		expect(shouldRefreshManagedEntitlement(state, nextKey, NOW + 6 * 3_600_000)).toBe(true);
		expect(shouldRefreshManagedEntitlement(state, previousKey)).toBe(true);
		const attempted = { ...state, last_sync_attempt_at: new Date(NOW).toISOString() };
		expect(shouldRefreshManagedEntitlement(attempted, previousKey, NOW + 299_999)).toBe(false);
		expect(shouldRefreshManagedEntitlement(attempted, previousKey, NOW + 300_000)).toBe(true);
		expect(
			shouldRefreshManagedEntitlement(
				{ last_sync_attempt_at: new Date(NOW).toISOString() },
				previousKey,
			),
		).toBe(false);
		expect(
			shouldRefreshManagedEntitlement(
				{
					...state,
					last_sync_attempt_at: new Date(NOW + 60_000).toISOString(),
					last_success_at: "invalid",
				},
				nextKey,
			),
		).toBe(true);
	});

	it("renews a clean-only long-lived session before its original seven-day key expires", async () => {
		const root = await mkdtemp(join(tmpdir(), "aidr-clean-session-renewal-"));
		const previousHome = process.env.HOME;
		const previousCommercial = process.env.AIDR_COMMERCIAL;
		const previousFetch = globalThis.fetch;
		process.env.HOME = root;
		process.env.AIDR_COMMERCIAL = "0";
		try {
			const configPath = join(root, "config.json");
			await writeFile(
				configPath,
				JSON.stringify({
					mode: "managed",
					auth: { api_key: nextKey },
					licensing: { public_keys_pem: [publicKeyPem], revocations_enabled: false },
					control_plane: {
						enabled: true,
						endpoint: "https://clean-renewal.example.test",
						remote_policy_cache_enabled: false,
						send_audit_logs: false,
						send_clean_verdicts: false,
					},
					logging: { enabled: false },
					cache: { enabled: false },
					incident: { enabled: false },
				}),
			);
			const signed = signedEntitlement({
				expires_at: new Date(NOW + 14 * DAY * 1000).toISOString(),
				grace_until: new Date(NOW + 14 * DAY * 1000).toISOString(),
			});
			const { mkdir } = await import("node:fs/promises");
			await mkdir(join(root, ".singularity-aidr"));
			const managedPath = join(root, ".singularity-aidr", "managed.json");
			await writeFile(
				managedPath,
				JSON.stringify(
					applyIngestResult(
						{ api_key: nextKey },
						{ ok: true, status: 200, body: { agent_id: "agent-1", entitlement_signed: signed } },
						72,
						{ authToken: nextKey, publicKeysPem: [publicKeyPem] },
					),
				),
			);
			const ingestKeys: string[] = [];
			let renewedKey = "";
			globalThis.fetch = vi.fn().mockImplementation(async (url: string, init: RequestInit) => {
				if (!String(url).endsWith("/ingest"))
					return { ok: false, status: 503, json: async () => ({}) } as Response;
				const authKey =
					new Headers(init.headers).get("Authorization")?.replace(/^Bearer /, "") ?? "";
				ingestKeys.push(authKey);
				const claims = JSON.parse(
					Buffer.from(authKey.split(".")[1] ?? "", "base64url").toString("utf8"),
				);
				if (claims.exp * 1000 <= Date.now())
					return {
						ok: false,
						status: 401,
						json: async () => ({ error: "invalid_api_key" }),
					} as Response;
				const rotation =
					claims.exp * 1000 - Date.now() <= 48 * 3_600_000
						? {
								api_key: (renewedKey = token({
									iat: Date.now() / 1000,
									exp: Date.now() / 1000 + 7 * DAY,
									jti: "clean-session-renewal",
								})),
							}
						: {};
				return {
					ok: true,
					status: 200,
					json: async () => ({ agent_id: "agent-1", entitlement_signed: signed, ...rotation }),
				} as Response;
			});
			const request = {
				sessionId: "clean-session",
				toolName: "Bash",
				toolInput: { command: "echo safe" },
				artifacts: [],
			};
			const context = {
				configPath,
				threatsDir: resolve(__dirname, "../../../../threats"),
				allowlistsDir: resolve(__dirname, "../../../../allowlists"),
			};
			const checkAt = async (offset: number) => {
				vi.setSystemTime(NOW + offset);
				expect((await evaluateToolCall(request, context)).decision).toBe("allow");
			};
			await checkAt(0);
			expect(ingestKeys).toHaveLength(0);
			await checkAt(6 * 3_600_000);
			await checkAt(6 * 3_600_000 + 1000);
			expect(ingestKeys).toEqual([nextKey]);
			await checkAt(5 * DAY * 1000 + 3_600_000);
			expect(renewedKey).not.toBe("");
			expect(JSON.parse(await readFile(managedPath, "utf8")).api_key).toBe(renewedKey);
			await checkAt(7 * DAY * 1000 + 3_600_000);
			expect(ingestKeys).toEqual([nextKey, nextKey, renewedKey]);
			// A failed refresh still persists its attempt, preventing per-call network retries.
			globalThis.fetch = vi.fn().mockRejectedValue(new Error("offline"));
			await checkAt(7 * DAY * 1000 + 7 * 3_600_000);
			const afterFailure = vi
				.mocked(globalThis.fetch)
				.mock.calls.filter(([url]) => String(url).endsWith("/ingest")).length;
			expect(afterFailure).toBe(1);
			await checkAt(7 * DAY * 1000 + 7 * 3_600_000 + 1000);
			expect(
				vi.mocked(globalThis.fetch).mock.calls.filter(([url]) => String(url).endsWith("/ingest")),
			).toHaveLength(afterFailure);
		} finally {
			globalThis.fetch = previousFetch;
			clearRemoteRuntimePolicyCacheForTests();
			if (previousHome === undefined) delete process.env.HOME;
			else process.env.HOME = previousHome;
			if (previousCommercial === undefined) delete process.env.AIDR_COMMERCIAL;
			else process.env.AIDR_COMMERCIAL = previousCommercial;
			await rm(root, { recursive: true, force: true });
		}
	});

	it("accepts an authenticated same-installation rotation with a signed tenant entitlement", () => {
		const next = applyIngestResult(
			{ api_key: previousKey },
			{ ok: true, status: 200, body: responseBody() },
			72,
			{ authToken: previousKey, publicKeysPem: [publicKeyPem] },
		);
		expect(next.api_key).toBe(nextKey);
		expect(next.entitlement_alg).toBe("ed25519");
		expect(getEffectiveManagedApiKey(previousKey, next)).toBe(nextKey);
		// A stale configured key remains usable as an identity anchor after expiry;
		// the successor can authenticate a new entitlement heartbeat.
		expect(getEffectiveManagedApiKey(previousKey, next, NOW + 2 * DAY * 1000)).toBe(nextKey);
	});

	it.each([
		["different tenant", { api_key: token({ uid: "tenant-2" }) }],
		["different agent", { api_key: token({ agent_id: "agent-2" }) }],
		["response identity mismatch", { agent_id: "agent-2" }],
		[
			"expired replacement",
			{ api_key: token({ iat: NOW_SECONDS - 2 * DAY, exp: NOW_SECONDS - 1 }) },
		],
		["excess lifetime", { api_key: token({ exp: NOW_SECONDS + 8 * DAY }) }],
		["future replacement", { api_key: token({ iat: NOW_SECONDS + 301 }) }],
		["shorter replacement", { api_key: token({ exp: NOW_SECONDS + 60 }) }],
		["opaque replacement", { api_key: "unverified-static-key" }],
		[
			"foreign signed entitlement",
			{ entitlement_signed: signedEntitlement({ tenant_id: "tenant-2" }) },
		],
		[
			"expired signed entitlement",
			{
				entitlement_signed: signedEntitlement({
					expires_at: new Date(NOW - 30_000).toISOString(),
					grace_until: new Date(NOW - 1).toISOString(),
				}),
			},
		],
		["unsigned entitlement", { entitlement_signed: undefined }],
	])("retains the previous key for %s", (_reason, overrides) => {
		const next = applyIngestResult(
			{ api_key: previousKey },
			{ ok: true, status: 200, body: responseBody(overrides as Record<string, unknown>) },
			72,
			{
				authToken: previousKey,
				publicKeysPem: [publicKeyPem],
				endpoint: "https://queue-rotation.example.test",
				iid: "rotation-installation",
			},
		);
		expect(next.api_key).toBe(previousKey);
		expect(next.telemetry_queue).toBeUndefined();
	});

	it("requires a fresh authenticated HTTP response and never rotates from a local replay", () => {
		const state = { api_key: previousKey };
		expect(
			applyIngestResult(state, { ok: true, status: 200, body: responseBody() }, 72, {
				publicKeysPem: [publicKeyPem],
			}).api_key,
		).toBe(previousKey);
		expect(
			applyIngestResult(state, { ok: true, body: responseBody() }, 72, {
				authToken: previousKey,
				publicKeysPem: [publicKeyPem],
			}).api_key,
		).toBe(previousKey);
		expect(
			applyIngestResult(state, { ok: true, body: { ...responseBody(), telemetry_queue: {} } }, 72, {
				authToken: previousKey,
				publicKeysPem: [publicKeyPem],
			}),
		).toBe(state);
	});

	it("ignores malformed persisted credential values", () => {
		const malformed = { api_key: 42 } as unknown as import("../managed.js").ManagedState;
		expect(getEffectiveManagedApiKey(previousKey, malformed)).toBe(previousKey);
		expect(getEffectiveManagedApiKey(undefined, malformed)).toBe("");
	});

	it("uses the rotated key for current and subsequent evaluator policy requests", async () => {
		const root = await mkdtemp(join(tmpdir(), "aidr-evaluator-key-rotation-"));
		const previousHome = process.env.HOME;
		const previousCommercial = process.env.AIDR_COMMERCIAL;
		const previousFetch = globalThis.fetch;
		process.env.HOME = root;
		process.env.AIDR_COMMERCIAL = "0";
		try {
			const configPath = join(root, "config.json");
			await writeFile(
				configPath,
				JSON.stringify({
					mode: "managed",
					auth: { api_key: previousKey },
					licensing: { public_keys_pem: [publicKeyPem], revocations_enabled: false },
					control_plane: {
						enabled: true,
						endpoint: "https://rotation.example.test",
						remote_policy_required: true,
						remote_policy_cache_enabled: false,
						send_audit_logs: false,
					},
					logging: { enabled: false },
					cache: { enabled: false },
					incident: { enabled: false },
				}),
			);
			const runtimePolicy = { command_default: "allow" };
			const digest = createHash("sha256").update(JSON.stringify(runtimePolicy)).digest("hex");
			const envelope = {
				schema_version: 1,
				key_id: "rotation-signer",
				policy_version: "rotation-1",
				policy_sha256: digest,
				sequence: 1,
				issued_at: new Date(NOW - 60_000).toISOString(),
				expires_at: new Date(NOW + 3_600_000).toISOString(),
				tenant_id: "tenant-1",
			};
			const canonical = JSON.stringify(
				Object.fromEntries(
					Object.entries(envelope).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
				),
			);
			const policyBody = {
				policy_version: "rotation-1",
				policy_sha256: digest,
				runtime_policy: runtimePolicy,
				policy_signed: {
					alg: "ed25519",
					key_id: "rotation-signer",
					envelope,
					sig_b64: cryptoSign(null, Buffer.from(canonical), signer.privateKey).toString("base64"),
				},
			};
			const headers: Array<{ operation: string; authorization: string | null }> = [];
			globalThis.fetch = vi.fn().mockImplementation(async (url: string, init: RequestInit) => {
				const operation = new URL(String(url)).pathname.split("/").at(-1) ?? "";
				headers.push({ operation, authorization: new Headers(init.headers).get("Authorization") });
				return {
					ok: true,
					status: 200,
					json: async () => (operation === "ingest" ? responseBody() : policyBody),
				} as Response;
			});
			const request = {
				sessionId: "key-rotation",
				toolName: "Bash",
				toolInput: { command: "echo safe" },
				artifacts: [],
			};
			const context = {
				configPath,
				threatsDir: resolve(__dirname, "../../../../threats"),
				allowlistsDir: resolve(__dirname, "../../../../allowlists"),
			};
			expect((await evaluateToolCall(request, context)).decision).toBe("allow");
			expect(headers.filter(({ operation }) => operation === "ingest")).toEqual([
				{ operation: "ingest", authorization: `Bearer ${previousKey}` },
			]);
			expect(headers.filter(({ operation }) => operation === "policy")).toEqual([
				{ operation: "policy", authorization: `Bearer ${nextKey}` },
			]);
			const saved = JSON.parse(
				await readFile(join(root, ".singularity-aidr", "managed.json"), "utf8"),
			);
			expect(saved.api_key).toBe(nextKey);
			clearRemoteRuntimePolicyCacheForTests();
			headers.length = 0;
			expect((await evaluateToolCall(request, context)).decision).toBe("allow");
			expect(headers).toEqual([{ operation: "policy", authorization: `Bearer ${nextKey}` }]);
		} finally {
			globalThis.fetch = previousFetch;
			clearRemoteRuntimePolicyCacheForTests();
			if (previousHome === undefined) delete process.env.HOME;
			else process.env.HOME = previousHome;
			if (previousCommercial === undefined) delete process.env.AIDR_COMMERCIAL;
			else process.env.AIDR_COMMERCIAL = previousCommercial;
			await rm(root, { recursive: true, force: true });
		}
	});

	it("keeps unrelated or static configured credentials authoritative", () => {
		expect(getEffectiveManagedApiKey("static-key", { api_key: nextKey })).toBe("static-key");
		expect(getEffectiveManagedApiKey(previousKey, { api_key: token({ uid: "tenant-2" }) })).toBe(
			previousKey,
		);
		expect(
			getEffectiveManagedApiKey(previousKey, { api_key: token({ agent_id: "agent-2" }) }),
		).toBe(previousKey);
		expect(getEffectiveManagedApiKey(previousKey, { api_key: nextKey }, NOW + 7 * DAY * 1000)).toBe(
			previousKey,
		);
	});
});
