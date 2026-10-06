import { createHmac, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { chmod, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VerdictCache } from "../cache.js";
import { canonicalJson } from "../canonical-json.js";
import { UrlCheckClient } from "../clients/url-check.js";
import { hashDeviceKey } from "../device-attestation.js";
import { evaluateToolCall } from "../evaluator.js";
import type { EntitlementSnapshotV2, ManagedState } from "../managed.js";
import * as managed from "../managed.js";
import {
	inspectResponseBarrier,
	type ResponseBarrierOptions,
	ResponseControlConfigSchema,
} from "../response-barrier.js";
import type { FleetResponseSignedDelivery } from "../response-command-consumer-v6.js";
import { FleetResponseJournal } from "../response-command-journal-v6.js";
import { FleetResponseCommandWorker } from "../response-command-worker-v6.js";
import * as secretStores from "../secret-store.js";
import { windowsTargetsAreAlreadyPrivate } from "../windows-private-acl-probe.js";

const osProfile = vi.hoisted(() => ({ directory: "" }));
vi.mock("node:os", async (original) => {
	const actual = await original<typeof import("node:os")>();
	return {
		...actual,
		userInfo: vi.fn(() => ({
			...actual.userInfo(),
			homedir: osProfile.directory || actual.userInfo().homedir,
		})),
	};
});
vi.mock("../windows-private-acl-probe.js", () => ({
	windowsTargetsAreAlreadyPrivate: vi.fn(() => true),
}));

const tenantId = "11111111-1111-4111-8111-111111111111";
const agentId = "22222222-2222-4222-8222-222222222222";
const pauseId = "33333333-3333-4333-8333-333333333333";
const resumeId = "44444444-4444-4444-8444-444444444444";
const iid = "response-test-installation";
const keyRefId = `aidr-${"a".repeat(32)}`;
const now = Date.parse("2026-10-06T12:00:00.000Z");
const signing = generateKeyPairSync("ed25519");
const wrongSigner = generateKeyPairSync("ed25519");
const publicKey = signing.publicKey.export({ type: "spki", format: "pem" }).toString();
let home: string;
let aidrDir: string;
let directory: string;
let journalKey: string;
let options: ResponseBarrierOptions;
let journal: FleetResponseJournal;
let secretStore: secretStores.SecretStore;
let clock: number;

function apiKey(overrides: Record<string, unknown> = {}): string {
	return [
		Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url"),
		Buffer.from(
			JSON.stringify({
				uid: tenantId,
				agent_id: agentId,
				jti: pauseId,
				iat: Math.floor(now / 1000) - 3600,
				exp: Math.floor(now / 1000) + 3600,
				...overrides,
			}),
		).toString("base64url"),
		Buffer.alloc(32, 5).toString("base64url"),
	].join(".");
}

function enrollment(): ManagedState {
	const entitlement: EntitlementSnapshotV2 = {
		schema_version: 2,
		tenant_id: tenantId,
		subscription_tier: "enterprise",
		included_agents: 1,
		extra_agents: 0,
		allowed_agents: 1,
		premium_modules: [],
		issued_at: new Date(now - 24 * 3600_000).toISOString(),
		expires_at: new Date(now + 24 * 3600_000).toISOString(),
		grace_until: new Date(now + 72 * 3600_000).toISOString(),
		serial: "response-test",
		revocation_epoch: 1,
	};
	return {
		api_key: apiKey(),
		entitlement,
		entitlement_alg: "ed25519",
		entitlement_sig: sign(
			null,
			Buffer.from(canonicalJson(entitlement)),
			signing.privateKey,
		).toString("base64"),
	};
}

function config() {
	return {
		schema_version: 1,
		tenant_id: tenantId,
		agent_id: agentId,
		installation_id: iid,
		trusted_command_keys: { "response-current": publicKey },
		control_plane_addresses: ["127.0.0.1"],
		admin_recovery_addresses: ["192.0.2.1"],
		network_support_addresses: [],
		journal_key_ref: {
			store: "windows-dpapi",
			id: keyRefId,
			created_at: new Date(now).toISOString(),
		},
	};
}

function delivery(
	overrides: Record<string, unknown> = {},
	signer = signing,
): FleetResponseSignedDelivery {
	const payload = {
		schema_version: 1,
		purpose: "aidr.fleet-response.command",
		key_id: "response-current",
		tenant_id: tenantId,
		agent_id: agentId,
		installation_id: iid,
		key_hash: hashDeviceKey(apiKey()),
		id: pauseId,
		command_type: "agent_pause",
		payload: {},
		attempt: 1,
		rollback_of: null,
		created_at: new Date(now - 120_000).toISOString(),
		expires_at: new Date(now - 60_000).toISOString(),
		...overrides,
	};
	return {
		alg: "ed25519",
		key_id: "response-current",
		payload,
		sig_b64: sign(null, Buffer.from(canonicalJson(payload)), signer.privateKey).toString("base64"),
	};
}

async function savePause(pause = delivery()) {
	const head = await journal.load();
	return journal.save({
		...head,
		current: null,
		response_control: { status: "paused", pause_delivery: pause, resume_delivery: null },
	});
}

async function rewriteAuthenticatedHead(changes: Record<string, unknown>): Promise<void> {
	const path = join(directory, "worker-state.a");
	const envelope = JSON.parse(await readFile(path, "utf8"));
	const payload = JSON.parse(JSON.stringify({ ...envelope.payload, ...changes }));
	await writeFile(
		path,
		JSON.stringify({
			payload,
			mac: createHmac("sha256", journalKey).update(canonicalJson(payload)).digest("hex"),
		}),
	);
}

function pollingWorker(fetchImpl: typeof fetch) {
	return new FleetResponseCommandWorker({
		endpoint: "http://127.0.0.1:8000/functions",
		developmentLoopback: true,
		apiKey: apiKey(),
		identity: { tenantId, agentId },
		installationId: iid,
		trustedCommandKeys: config().trusted_command_keys,
		adapter: {
			identity: { tenantId, agentId },
			supportedCommands: ["agent_pause"],
			execute: vi.fn(async () => ({ ok: true as const })),
			verify: vi.fn(async () => ({ observed: true as const })),
		},
		statePath: join(directory, "worker-state"),
		stableJournalKey: journalKey,
		now: () => clock,
		fetchImpl,
	});
}

beforeEach(async () => {
	clock = now;
	home = await mkdtemp(join(tmpdir(), "aidr-response-barrier-"));
	aidrDir = join(home, ".singularity-aidr");
	directory = join(aidrDir, "response-control");
	await mkdir(directory, { recursive: true, mode: 0o700 });
	await chmod(directory, 0o700);
	await writeFile(join(directory, "config.json"), JSON.stringify(config()), { mode: 0o600 });
	await writeFile(join(aidrDir, "installation-id"), iid, { mode: 0o600 });
	journalKey = randomBytes(32).toString("base64");
	secretStore = {
		kind: "windows-dpapi",
		location: "os-vault",
		osProtected: true,
		isAvailable: () => true,
		put: vi.fn(),
		revoke: vi.fn(),
		get: vi.fn((id) => (id === keyRefId ? journalKey : null)),
	};
	options = {
		required: true,
		managedState: enrollment(),
		apiKey: apiKey(),
		publicKeysPem: [publicKey],
		aidrDir,
		secretStore,
		now: () => clock,
	};
	journal = new FleetResponseJournal(
		join(directory, "worker-state"),
		{ tenantId, agentId },
		apiKey(),
		iid,
		journalKey,
		() => clock,
	);
	await journal.bootstrapResponseControl();
	vi.mocked(windowsTargetsAreAlreadyPrivate).mockReturnValue(true);
});

afterEach(async () => {
	vi.restoreAllMocks();
	vi.unstubAllEnvs();
	vi.useRealTimers();
	await rm(home, { recursive: true, force: true });
});

describe("installed response barrier", () => {
	it("allows an authenticated operator-installed running checkpoint without changing files", async () => {
		const before = await readFile(join(directory, "worker-state.a"));
		expect(await inspectResponseBarrier(options)).toEqual({ status: "running" });
		expect(await readFile(join(directory, "worker-state.a"))).toEqual(before);
		expect((await readdir(directory)).sort()).toEqual(["config.json", "worker-state.a"]);
	});

	it("bounds initial running grace to 120 seconds and rebootstrap never renews it", async () => {
		const initial = await journal.inspect();
		clock += 120_000;
		expect(await inspectResponseBarrier(options)).toEqual({ status: "running" });
		clock++;
		expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
		expect((await journal.bootstrapResponseControl()).bootstrap_at).toBe(initial?.bootstrap_at);
		expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
	});

	it("only a successful authenticated poll renews running readiness", async () => {
		clock += 120_001;
		expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
		const worker = pollingWorker(
			vi.fn(async () => new Response(JSON.stringify({ ok: true, command_signed: null }))),
		);
		expect(await worker.tick()).toEqual({ status: "idle" });
		expect((await journal.inspect())?.last_successful_poll_at).toBe(new Date(clock).toISOString());
		expect(await inspectResponseBarrier(options)).toEqual({ status: "running" });
		clock += 120_001;
		expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
	});

	it("failed polling and repeatedly inspecting expired state cannot renew readiness", async () => {
		clock += 120_001;
		const before = await readFile(join(directory, "worker-state.a"));
		const worker = pollingWorker(
			vi.fn(async () => new Response(JSON.stringify({ ok: false }), { status: 500 })),
		);
		expect((await worker.tick()).status).not.toBe("idle");
		for (let attempt = 0; attempt < 3; attempt++)
			expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
		expect(await readFile(join(directory, "worker-state.a"))).toEqual(before);
		expect((await journal.inspect())?.last_successful_poll_at).toBeNull();
	});

	it.each([
		{ bootstrap_at: undefined },
		{ last_successful_poll_at: undefined },
		{ bootstrap_at: new Date(now + 1).toISOString() },
		{ last_successful_poll_at: new Date(now + 1).toISOString() },
		{
			bootstrap_at: new Date(now - 180_000).toISOString(),
			last_successful_poll_at: new Date(now - 120_001).toISOString(),
		},
	])("denies missing, future, or stale authenticated running metadata %j", async (changes) => {
		await rewriteAuthenticatedHead(changes);
		expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
	});

	it("requires explicit activation when state is absent and never creates missing state", async () => {
		await rm(directory, { recursive: true });
		expect(await inspectResponseBarrier({ ...options, required: false })).toEqual({
			status: "unconfigured",
		});
		expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
		expect(await readdir(aidrDir)).toEqual(["installation-id"]);
	});

	it.each(["config.json", "worker-state.a"])(
		"denies missing required %s without reinitializing",
		async (file) => {
			await rm(join(directory, file));
			const before = await readdir(directory);
			expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
			expect(await readdir(directory)).toEqual(before);
		},
	);

	it("detects a damaged newest or older slot instead of falling back to running", async () => {
		await savePause();
		const active = await readFile(join(directory, "worker-state.b"));
		await writeFile(join(directory, "worker-state.b"), "{}");
		expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
		await writeFile(join(directory, "worker-state.b"), active);
		await writeFile(join(directory, "worker-state.a"), "{}");
		expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
	});

	it("keeps an expired signed pause active across credential rotation", async () => {
		await savePause();
		clock += 120_001;
		expect(await inspectResponseBarrier({ ...options, apiKey: apiKey({ jti: resumeId }) })).toEqual(
			{ status: "paused", commandId: pauseId },
		);
	});

	it.each(["polled", "acknowledged", "execute_intent", "result_pending"] as const)(
		"blocks pending %s pause, including a missing newest slot",
		async (phase) => {
			const head = await journal.load();
			const pause = delivery();
			await journal.save({
				...head,
				current: {
					command: {
						id: pauseId,
						commandType: "agent_pause",
						expiresAt: String(pause.payload.expires_at),
						attempt: 1,
						rollbackOf: null,
					},
					delivery: pause,
					phase,
					resultCode: phase === "result_pending" ? "native_action_failed" : null,
				},
			});
			const before = await journal.load();
			await journal.save({
				...before,
				current: null,
				response_control: { status: "paused", pause_delivery: pause, resume_delivery: null },
			});
			await rm(join(directory, "worker-state.a"));
			clock += 120_001;
			expect(await inspectResponseBarrier(options)).toEqual({
				status: "paused",
				commandId: pauseId,
			});
		},
	);

	it("resumes only with a verified signed matching resume, even after both deliveries expire", async () => {
		const pause = delivery();
		await savePause(pause);
		const resume = delivery({
			id: resumeId,
			command_type: "agent_resume",
			rollback_of: pauseId,
			created_at: new Date(now - 90_000).toISOString(),
			expires_at: new Date(now - 30_000).toISOString(),
		});
		await journal.save({
			...(await journal.load()),
			last_successful_poll_at: new Date(clock).toISOString(),
			response_control: { status: "running", pause_delivery: pause, resume_delivery: resume },
		});
		expect(await inspectResponseBarrier(options)).toEqual({ status: "running" });
		clock += 120_001;
		expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
	});

	it("a signed resumed head cannot reuse the initial bootstrap grace without a successful poll", async () => {
		const pause = delivery();
		await savePause(pause);
		const resume = delivery({
			id: resumeId,
			command_type: "agent_resume",
			rollback_of: pauseId,
			created_at: new Date(now - 90_000).toISOString(),
		});
		await journal.save({
			...(await journal.load()),
			response_control: { status: "running", pause_delivery: pause, resume_delivery: resume },
		});
		expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
	});

	it("refuses an untrusted signature inside an otherwise authenticated journal", async () => {
		await savePause(delivery({}, wrongSigner));
		expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
	});

	it("does not allow a forged matching resume to lift pause", async () => {
		const pause = delivery();
		await savePause(pause);
		const resume = delivery(
			{ id: resumeId, command_type: "agent_resume", rollback_of: pauseId },
			wrongSigner,
		);
		await journal.save({
			...(await journal.load()),
			response_control: { status: "running", pause_delivery: pause, resume_delivery: resume },
		});
		expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
	});

	it.each([{ uid: resumeId }, { agent_id: resumeId }, { exp: Math.floor(now / 1000) - 1 }])(
		"refuses mismatched or expired current enrollment claims %j",
		async (claims) => {
			expect(await inspectResponseBarrier({ ...options, apiKey: apiKey(claims) })).toEqual({
				status: "unavailable",
			});
		},
	);

	it("requires active signed tenant enrollment and the original installation identity", async () => {
		const damaged = {
			...options.managedState,
			entitlement_sig: Buffer.alloc(64).toString("base64"),
		};
		expect(await inspectResponseBarrier({ ...options, managedState: damaged })).toEqual({
			status: "unavailable",
		});
		expect(
			await inspectResponseBarrier({
				...options,
				managedState: { ...options.managedState, sync_disabled_reason: "revoked" },
			}),
		).toEqual({ status: "unavailable" });
		await writeFile(join(aidrDir, "installation-id"), "other-installation");
		expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
	});

	it("denies a missing, altered, or non-vault stable secret", async () => {
		for (const secret of [null, randomBytes(32).toString("base64"), "invalid"])
			expect(
				await inspectResponseBarrier({
					...options,
					secretStore: { ...secretStore, get: () => secret },
				}),
			).toEqual({ status: "unavailable" });
		expect(
			await inspectResponseBarrier({
				...options,
				secretStore: { ...secretStore, kind: "file-acl", osProtected: false },
			}),
		).toEqual({ status: "unavailable" });
	});

	it("rejects a missing or oversized sealed vault blob before invoking the vault", async () => {
		const resolver = vi.spyOn(secretStores, "resolveSecretStore").mockReturnValue(secretStore);
		expect(await inspectResponseBarrier({ ...options, secretStore: undefined })).toEqual({
			status: "unavailable",
		});
		const secretsDirectory = join(aidrDir, "secrets");
		await mkdir(secretsDirectory, { mode: 0o700 });
		await writeFile(join(secretsDirectory, `${keyRefId}.dpapi`), "x".repeat(16_385), {
			mode: 0o600,
		});
		expect(await inspectResponseBarrier({ ...options, secretStore: undefined })).toEqual({
			status: "unavailable",
		});
		expect(resolver).not.toHaveBeenCalled();
	});

	it("refuses malformed or oversized configuration even when the flag was lost", async () => {
		await writeFile(
			join(directory, "config.json"),
			JSON.stringify({ ...config(), enabled: false }),
		);
		expect(await inspectResponseBarrier({ ...options, required: false })).toEqual({
			status: "unavailable",
		});
		await writeFile(join(directory, "config.json"), " ".repeat(32_769));
		expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
	});

	it("requires existing private configuration without repairing its permissions", async () => {
		if (process.platform === "win32")
			vi.mocked(windowsTargetsAreAlreadyPrivate).mockReturnValue(false);
		else await chmod(join(directory, "config.json"), 0o644);
		expect(await inspectResponseBarrier(options)).toEqual({ status: "unavailable" });
	});

	it.each(["FE80::1", "fe80::1%eth0", "::ffff:192.0.2.1", "127.00.0.1"])(
		"rejects ambiguous native firewall address %s",
		(address) => {
			expect(
				ResponseControlConfigSchema.safeParse({ ...config(), control_plane_addresses: [address] })
					.success,
			).toBe(false);
		},
	);

	it("rejects private keys in public command trust configuration", () => {
		const privateKey = signing.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
		expect(
			ResponseControlConfigSchema.safeParse({
				...config(),
				trusted_command_keys: { current: privateKey },
			}).success,
		).toBe(false);
	});

	it("enforces pause before network/cache/empty input and ignores a redirected HOME on Windows", async () => {
		osProfile.directory = home;
		vi.stubEnv("HOME", home);
		vi.stubEnv("AIDR_COMMERCIAL", "0");
		vi.stubEnv("AIDR_BUILD", "development");
		vi.stubEnv("AIDR_BUILD_FLAVOR", "development");
		vi.useFakeTimers({ toFake: ["Date"] });
		vi.setSystemTime(now);
		vi.spyOn(secretStores, "resolveSecretStore").mockReturnValue(secretStore);
		const secretsDirectory = join(aidrDir, "secrets");
		await mkdir(secretsDirectory, { mode: 0o700 });
		await writeFile(join(secretsDirectory, `${keyRefId}.dpapi`), "test-sealed-vault-blob", {
			mode: 0o600,
		});
		const fetchSpy = vi
			.spyOn(globalThis, "fetch")
			.mockRejectedValue(new Error("network must not run"));
		const provider = vi.spyOn(UrlCheckClient.prototype, "checkUrls");
		const cache = vi.spyOn(VerdictCache.prototype, "load");
		await savePause();
		await writeFile(join(aidrDir, "managed.json"), JSON.stringify(options.managedState));
		const configPath = join(aidrDir, "config.json");
		await writeFile(
			configPath,
			JSON.stringify({
				mode: "managed",
				auth: { api_key: apiKey() },
				control_plane: { response_worker_required: true, send_audit_logs: false },
				licensing: { public_keys_pem: [publicKey] },
				logging: { enabled: false },
			}),
		);
		const verdict = await evaluateToolCall(
			{ sessionId: "response-paused", toolName: "CustomTool", toolInput: {}, artifacts: [] },
			{
				configPath,
				threatsDir: join(home, "empty-threats"),
				allowlistsDir: join(home, "empty-allowlists"),
			},
		);
		expect(verdict).toMatchObject({ decision: "deny", category: "response_paused" });
		const context = {
			configPath,
			threatsDir: join(home, "empty-threats"),
			allowlistsDir: join(home, "empty-allowlists"),
		};
		expect(
			await evaluateToolCall(
				{
					sessionId: "response-url",
					toolName: "CustomTool",
					toolInput: { url: "https://public.example/" },
					artifacts: [{ type: "url", value: "https://public.example/" }],
				},
				context,
			),
		).toMatchObject({ decision: "deny", category: "response_paused" });
		vi.spyOn(managed, "loadManagedState").mockRejectedValue(new Error("test vault unavailable"));
		expect(
			await evaluateToolCall(
				{ sessionId: "response-vault-error", toolName: "CustomTool", toolInput: {}, artifacts: [] },
				context,
			),
		).toMatchObject({ decision: "deny", category: "response_control_unavailable" });
		expect(fetchSpy).not.toHaveBeenCalled();
		expect(provider).not.toHaveBeenCalled();
		expect(cache).not.toHaveBeenCalled();
		const redirectedHome = join(home, "redirected");
		await mkdir(redirectedHome);
		vi.stubEnv("HOME", redirectedHome);
		if (process.platform === "win32") {
			vi.stubEnv("USERPROFILE", redirectedHome);
			vi.stubEnv("SystemRoot", redirectedHome);
			const redirected = await evaluateToolCall(
				{ sessionId: "response-redirected", toolName: "CustomTool", toolInput: {}, artifacts: [] },
				{ threatsDir: join(home, "empty-threats"), allowlistsDir: join(home, "empty-allowlists") },
			);
			expect(redirected).toMatchObject({
				decision: "deny",
				category: "response_control_unavailable",
			});
		}
	});
});
