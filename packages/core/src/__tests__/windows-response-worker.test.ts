import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { EventEmitter } from "node:events";
import { writeFileSync } from "node:fs";
import { mkdir, mkdtemp, readdir, readFile, rm, rmdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { PassThrough, Writable } from "node:stream";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { hashDeviceKey } from "../device-attestation.js";
import {
	FleetResponseActionInterrupted,
	type FleetResponseCommand,
	type FleetResponseSignedDelivery,
} from "../response-command-consumer-v6.js";
import {
	initializeInstalledWindowsResponseWorker,
	loadInstalledWindowsResponseWorker,
	parseWindowsResponseControlConfig,
	runInstalledWindowsResponseWorker,
	validateInstalledWindowsResponseRemoval,
} from "../windows-response-worker.js";

const mocked = vi.hoisted(() => ({
	profile: "",
	keys: new Map<string, string>(),
	spawn: vi.fn(),
	lookup: vi.fn(),
	private: vi.fn(() => true),
	vaultWrites: 0,
}));
vi.mock("node:child_process", () => ({
	spawn: mocked.spawn,
	spawnSync: vi.fn(() => ({ status: 0, stdout: mocked.profile, stderr: "" })),
}));
vi.mock("node:dns/promises", () => ({ lookup: mocked.lookup }));
vi.mock("node:os", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:os")>();
	return { ...actual, userInfo: () => ({ ...actual.userInfo(), homedir: mocked.profile }) };
});
vi.mock("../windows-private-acl-probe.js", () => ({
	windowsTargetsAreAlreadyPrivate: mocked.private,
}));
vi.mock("../secret-store.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../secret-store.js")>();
	return {
		...actual,
		createWindowsDpapiStore: () => ({
			kind: "windows-dpapi",
			location: "os-vault",
			osProtected: true,
			isAvailable: () => true,
			get: (id: string) => mocked.keys.get(id) ?? null,
			put: (id: string, secret: string) => {
				mocked.vaultWrites++;
				mocked.keys.set(id, secret);
				writeFileSync(
					join(mocked.profile, ".singularity-aidr", "secrets", `${id}.dpapi`),
					"synthetic sealed fixture",
				);
			},
			revoke: (id: string) => {
				mocked.keys.delete(id);
			},
		}),
	};
});

const tenantId = "11111111-1111-4111-8111-111111111111";
const agentId = "22222222-2222-4222-8222-222222222222";
const installationId = "33333333-3333-4333-8333-333333333333";
const commandId = "44444444-4444-4444-8444-444444444444";
const otherAgentId = "55555555-5555-4555-8555-555555555555";
const keys = generateKeyPairSync("ed25519");
const publicKey = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
const originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");
if (!originalPlatform) throw new Error("process platform descriptor unavailable");
let fixtureRoot = "";

function canonical(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
	if (value && typeof value === "object")
		return `{${Object.entries(value)
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
			.map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
			.join(",")}}`;
	return JSON.stringify(value);
}

function token(overrides: Record<string, unknown> = {}): string {
	const seconds = Math.floor(Date.now() / 1000);
	return [
		Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url"),
		Buffer.from(
			JSON.stringify({
				uid: tenantId,
				agent_id: agentId,
				jti: commandId,
				iat: seconds - 120,
				exp: seconds + 3600,
				...overrides,
			}),
		).toString("base64url"),
		Buffer.alloc(32, 7).toString("base64url"),
	].join(".");
}

function seed() {
	return {
		schema_version: 1,
		tenant_id: tenantId,
		agent_id: agentId,
		installation_id: installationId,
		trusted_command_keys: { response: publicKey },
		control_plane_addresses: ["192.0.2.10"],
		admin_recovery_addresses: ["192.0.2.20"],
		network_support_addresses: [],
	};
}

function signedCommand(
	apiKey: string,
	overrides: Record<string, unknown> = {},
): FleetResponseSignedDelivery {
	const payload = {
		schema_version: 1,
		purpose: "aidr.fleet-response.command",
		key_id: "response",
		tenant_id: tenantId,
		agent_id: agentId,
		installation_id: installationId,
		key_hash: hashDeviceKey(apiKey),
		id: commandId,
		command_type: "agent_pause",
		payload: {},
		rollback_of: null,
		created_at: new Date(Date.now() - 1000).toISOString(),
		expires_at: new Date(Date.now() + 60_000).toISOString(),
		attempt: 1,
		...overrides,
	};
	return {
		alg: "ed25519",
		key_id: "response",
		sig_b64: sign(null, Buffer.from(canonical(payload)), keys.privateKey).toString("base64"),
		payload,
	};
}

function view(delivery: FleetResponseSignedDelivery): FleetResponseCommand {
	return {
		id: delivery.payload.id as string,
		commandType: delivery.payload.command_type as FleetResponseCommand["commandType"],
		expiresAt: delivery.payload.expires_at as string,
		attempt: delivery.payload.attempt as number,
		rollbackOf: delivery.payload.rollback_of as string | null,
	};
}

async function fixture() {
	mocked.keys.clear();
	mocked.vaultWrites = 0;
	mocked.lookup.mockResolvedValue([{ address: "192.0.2.10", family: 4 }]);
	mocked.private.mockReturnValue(true);
	const aidrDir = join(fixtureRoot, ".singularity-aidr");
	const artifactDir = join(fixtureRoot, "connector", "dist");
	await mkdir(join(aidrDir, "secrets"), { recursive: true });
	await mkdir(join(artifactDir, "native"), { recursive: true });
	const apiKey = token();
	const ref = {
		store: "windows-dpapi",
		id: `aidr-${"1".repeat(32)}`,
		created_at: new Date().toISOString(),
	};
	mocked.keys.set(ref.id, apiKey);
	await writeFile(join(aidrDir, "secrets", `${ref.id}.dpapi`), "synthetic sealed fixture");
	const config = {
		mode: "managed",
		auth: { api_key_ref: ref },
		control_plane: { endpoint: "https://control.example/functions", enabled: true },
		licensing: { public_keys_pem: [publicKey] },
		integrity: { public_keys_pem: [publicKey] },
	};
	await writeFile(join(aidrDir, "config.json"), JSON.stringify(config));
	const entitlement = {
		schema_version: 2,
		tenant_id: tenantId,
		subscription_tier: "enterprise",
		included_agents: 1,
		extra_agents: 0,
		allowed_agents: 1,
		premium_modules: [],
		issued_at: new Date(Date.now() - 60_000).toISOString(),
		expires_at: new Date(Date.now() + 3_600_000).toISOString(),
		grace_until: new Date(Date.now() + 7_200_000).toISOString(),
		serial: "fixture-entitlement",
		revocation_epoch: 1,
	};
	const managed = {
		entitlement,
		entitlement_alg: "ed25519",
		entitlement_sig: sign(null, Buffer.from(canonical(entitlement)), keys.privateKey).toString(
			"base64",
		),
	};
	await writeFile(join(aidrDir, "managed.json"), JSON.stringify(managed));
	await writeFile(join(aidrDir, "installation-id"), installationId);
	const shipped = [
		"response-worker.cjs",
		"native/Invoke-AidrResponseAction.ps1",
		"native/Common.ps1",
	];
	const files = [];
	for (const name of shipped) {
		const bytes = Buffer.from(`synthetic signed ${name}`);
		await writeFile(join(artifactDir, name), bytes);
		files.push({ path: name, sha256: createHash("sha256").update(bytes).digest("hex") });
	}
	const manifest = JSON.stringify({
		schema_version: 1,
		artifact_id: "claude-code/dist",
		artifact_version: "0.6.0",
		created_at: new Date().toISOString(),
		files,
	});
	await writeFile(join(artifactDir, "aidr-artifact.manifest.json"), manifest);
	await writeFile(
		join(artifactDir, "aidr-artifact.manifest.sig"),
		sign(null, Buffer.from(manifest), keys.privateKey).toString("base64"),
	);
	return {
		aidrDir,
		artifactDir,
		apiKey,
		config,
		managed,
		adapterPath: join(artifactDir, "native", "Invoke-AidrResponseAction.ps1"),
	};
}

async function installed() {
	const current = await fixture();
	await initializeInstalledWindowsResponseWorker(current.adapterPath, seed());
	return current;
}

async function snapshot(directory: string): Promise<Record<string, string>> {
	const result: Record<string, string> = {};
	async function walk(path: string) {
		for (const entry of await readdir(path, { withFileTypes: true })) {
			const child = join(path, entry.name);
			if (entry.isDirectory()) await walk(child);
			else
				result[child] = createHash("sha256")
					.update(await readFile(child))
					.digest("hex");
		}
	}
	await walk(directory);
	return result;
}

function nativeResult(result: unknown, exitCode = 0) {
	const child = Object.assign(new EventEmitter(), {
		stdout: new PassThrough(),
		stderr: new PassThrough(),
		stdin: undefined as unknown as Writable,
		kill: vi.fn(() => true),
	});
	let input = "";
	child.stdin = new Writable({
		write(chunk, _encoding, callback) {
			input += chunk.toString();
			callback();
		},
		final(callback) {
			callback();
			queueMicrotask(() => {
				child.stdout.emit("data", Buffer.from(JSON.stringify(result)));
				child.emit("close", exitCode);
			});
		},
	});
	mocked.spawn.mockReturnValueOnce(child);
	return { child, input: () => input };
}

beforeAll(async () => {
	fixtureRoot = await mkdtemp(join(tmpdir(), "aidr-windows-response-unit-"));
	mocked.profile = fixtureRoot;
	Object.defineProperty(process, "platform", { value: "win32", configurable: true });
});
afterEach(async () => {
	vi.useRealTimers();
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	mocked.spawn.mockReset();
	Object.defineProperty(process, "platform", { value: "win32", configurable: true });
	for (const name of [".singularity-aidr", "connector"]) {
		const path = resolve(fixtureRoot, name);
		if (!path.startsWith(`${resolve(fixtureRoot)}${sep}`))
			throw new Error("unsafe fixture cleanup");
		await rm(path, { recursive: true, force: true });
	}
});
afterAll(async () => {
	Object.defineProperty(process, "platform", originalPlatform);
	await rm(fixtureRoot, { recursive: true, force: true });
});

describe("installed Windows response authority (mocked vault/process/network only)", () => {
	it("activates once with a private stable vault reference and performs read-only validation", async () => {
		const current = await installed();
		const before = await snapshot(current.aidrDir);
		const writes = mocked.vaultWrites;
		vi.stubEnv("HOME", join(fixtureRoot, "impersonated-profile"));
		vi.stubEnv("USERPROFILE", join(fixtureRoot, "impersonated-profile"));
		const runtime = await loadInstalledWindowsResponseWorker(current.adapterPath, seed());
		expect(runtime.profile).toBe(fixtureRoot);
		expect(runtime.state.response_control).toEqual({
			status: "running",
			pause_delivery: null,
			resume_delivery: null,
		});
		expect(runtime.control.journal_key_ref.store).toBe("windows-dpapi");
		expect(await snapshot(current.aidrDir)).toEqual(before);
		expect(mocked.vaultWrites).toBe(writes);
		expect(mocked.spawn).not.toHaveBeenCalled();
		const stored = await readFile(join(current.aidrDir, "response-control", "config.json"), "utf8");
		expect(stored).not.toContain(runtime.apiKey);
		expect(stored).not.toContain(runtime.stableJournalKey);
		await expect(
			initializeInstalledWindowsResponseWorker(current.adapterPath, seed()),
		).rejects.toThrow("already_required");
	});

	it("rejects changed operator trust/address configuration while retaining installed state", async () => {
		const current = await installed();
		await expect(
			loadInstalledWindowsResponseWorker(current.adapterPath, {
				...seed(),
				admin_recovery_addresses: ["192.0.2.21"],
			}),
		).rejects.toThrow("requested_config_mismatch");
	});

	it.each([
		"https://control.example/functions?secret=x",
		"http://127.0.0.1/functions",
		"ftp://control.example/functions",
	])("refuses unsafe endpoint %s before activation", async (endpoint) => {
		const current = await fixture();
		await writeFile(
			join(current.aidrDir, "config.json"),
			JSON.stringify({ ...current.config, control_plane: { endpoint } }),
		);
		await expect(
			initializeInstalledWindowsResponseWorker(current.adapterPath, seed()),
		).rejects.toThrow();
		expect(mocked.vaultWrites).toBe(0);
	});

	it("requires every currently resolved endpoint IP in the explicit recovery list", async () => {
		const current = await fixture();
		mocked.lookup.mockResolvedValue([
			{ address: "192.0.2.10", family: 4 },
			{ address: "192.0.2.11", family: 4 },
		]);
		await expect(
			initializeInstalledWindowsResponseWorker(current.adapterPath, seed()),
		).rejects.toThrow("address_mismatch");
		expect(mocked.vaultWrites).toBe(0);
	});

	it.each(["192.0.2.10/24", "2001:db8::1%12", "::ffff:c000:20a", "example.com", "192.0.2.10:443"])(
		"rejects nonliteral or ambiguous recovery IP %s",
		(address) => {
			expect(() =>
				parseWindowsResponseControlConfig({ ...seed(), admin_recovery_addresses: [address] }, true),
			).toThrow();
		},
	);

	it("refuses plaintext and mismatched rotated identities without vault migration", async () => {
		const current = await fixture();
		await writeFile(
			join(current.aidrDir, "managed.json"),
			JSON.stringify({ ...current.managed, api_key: current.apiKey }),
		);
		await expect(
			initializeInstalledWindowsResponseWorker(current.adapterPath, seed()),
		).rejects.toThrow("plaintext_credential_refused");
		expect(mocked.vaultWrites).toBe(0);
		const ref = {
			store: "windows-dpapi",
			id: `aidr-${"2".repeat(32)}`,
			created_at: new Date().toISOString(),
		};
		mocked.keys.set(
			ref.id,
			token({ agent_id: otherAgentId, exp: Math.floor(Date.now() / 1000) + 7200 }),
		);
		await writeFile(
			join(current.aidrDir, "secrets", `${ref.id}.dpapi`),
			"synthetic sealed fixture",
		);
		await writeFile(
			join(current.aidrDir, "managed.json"),
			JSON.stringify({ ...current.managed, api_key_ref: ref }),
		);
		await expect(
			initializeInstalledWindowsResponseWorker(current.adapterPath, seed()),
		).rejects.toThrow("rotation_identity_mismatch");
	});

	it("refuses missing or corrupted required journals and never recreates running state", async () => {
		const current = await installed();
		const statePath = join(current.aidrDir, "response-control", "worker-state");
		await writeFile(`${statePath}.a`, "corrupt");
		await expect(loadInstalledWindowsResponseWorker(current.adapterPath)).rejects.toThrow();
		await rm(`${statePath}.a`);
		await expect(loadInstalledWindowsResponseWorker(current.adapterPath)).rejects.toThrow(
			"bootstrap_required",
		);
		await expect(
			initializeInstalledWindowsResponseWorker(current.adapterPath, seed()),
		).rejects.toThrow();
		await expect(readFile(`${statePath}.a`)).rejects.toMatchObject({ code: "ENOENT" });
	});

	it("rejects partial/concurrent initialization and mismatched installation IDs", async () => {
		const current = await fixture();
		await mkdir(join(current.aidrDir, "response-control"));
		await expect(
			initializeInstalledWindowsResponseWorker(current.adapterPath, seed()),
		).rejects.toThrow("existing_state_refused");
		await rmdir(join(current.aidrDir, "response-control"));
		await expect(
			initializeInstalledWindowsResponseWorker(current.adapterPath, {
				...seed(),
				installation_id: otherAgentId,
			}),
		).rejects.toThrow("identity_mismatch");
		expect(mocked.vaultWrites).toBe(0);
		const attempts = await Promise.allSettled([
			initializeInstalledWindowsResponseWorker(current.adapterPath, seed()),
			initializeInstalledWindowsResponseWorker(current.adapterPath, seed()),
		]);
		expect(attempts.filter((result) => result.status === "fulfilled")).toHaveLength(1);
		expect(attempts.filter((result) => result.status === "rejected")).toHaveLength(1);
		expect(mocked.vaultWrites).toBe(1);
	});

	it("rejects untrusted script bytes, weak privacy, missing vault entries and other platforms", async () => {
		const current = await installed();
		await writeFile(join(current.artifactDir, "native", "Common.ps1"), "tampered");
		await expect(loadInstalledWindowsResponseWorker(current.adapterPath)).rejects.toThrow(
			"artifact_untrusted",
		);
		mocked.private.mockReturnValue(false);
		await expect(loadInstalledWindowsResponseWorker(current.adapterPath)).rejects.toThrow(
			"state_not_private",
		);
		mocked.private.mockReturnValue(true);
		mocked.keys.clear();
		await expect(loadInstalledWindowsResponseWorker(current.adapterPath)).rejects.toThrow(
			"vault_credential_unavailable",
		);
		Object.defineProperty(process, "platform", { value: "linux", configurable: true });
		await expect(loadInstalledWindowsResponseWorker(current.adapterPath)).rejects.toThrow(
			"unsupported_platform",
		);
	});

	it("polls only the pinned HTTPS server with redirects disabled and no native effects when idle", async () => {
		const current = await installed();
		const network = vi.fn<typeof fetch>().mockResolvedValue(
			new Response(JSON.stringify({ ok: true, command_signed: null }), {
				headers: { "content-type": "application/json" },
			}),
		);
		vi.stubGlobal("fetch", network);
		expect(await runInstalledWindowsResponseWorker(current.adapterPath, { once: true })).toEqual({
			status: "idle",
		});
		expect(network.mock.calls[0]?.[1]?.redirect).toBe("error");
		expect(network.mock.calls[0]?.[1]?.headers).toMatchObject({
			Authorization: `Bearer ${current.apiKey}`,
		});
		expect(mocked.spawn).not.toHaveBeenCalled();
	});

	it("allows removal only while locked, running, without pending work and with native independent evidence", async () => {
		const current = await installed();
		nativeResult({
			ok: true,
			observed: true,
			removable: true,
			evidence: {
				tenant_id: tenantId,
				agent_id: agentId,
				installation_id: installationId,
				state: "native_inactive",
				owned_rule_count: 0,
			},
		});
		await expect(
			validateInstalledWindowsResponseRemoval(current.adapterPath),
		).resolves.toBeUndefined();
		const runtime = await loadInstalledWindowsResponseWorker(current.adapterPath);
		const delivery = signedCommand(current.apiKey);
		await runtime.journal.load();
		await runtime.journal.save({
			...runtime.state,
			current: { command: view(delivery), delivery, phase: "execute_intent", resultCode: null },
		});
		await expect(validateInstalledWindowsResponseRemoval(current.adapterPath)).rejects.toThrow(
			"pending_or_paused",
		);
	});
});

describe("Windows native adapter signed stdin protocol", () => {
	async function adapter() {
		const current = await installed();
		const runtime = await loadInstalledWindowsResponseWorker(current.adapterPath);
		return { current, runtime, delivery: signedCommand(current.apiKey) };
	}

	it("sends only scoped signed evidence over stdin and verifies in a separate native process", async () => {
		const { runtime, delivery } = await adapter();
		const execution = nativeResult({ ok: true });
		expect(await runtime.adapter.execute(view(delivery), undefined, delivery)).toEqual({
			ok: true,
		});
		const dto = JSON.parse(execution.input());
		expect(Object.keys(dto.identity)).toEqual(["tenant_id", "agent_id", "installation_id"]);
		expect(dto.command).toEqual({
			id: commandId,
			command_type: "agent_pause",
			expires_at: delivery.payload.expires_at,
			attempt: 1,
			rollback_of: null,
		});
		expect(execution.input()).not.toContain(runtime.apiKey);
		expect(JSON.stringify(mocked.spawn.mock.calls)).not.toContain(runtime.apiKey);
		expect(mocked.spawn.mock.calls[0]?.[1]).toContain("-File");
		expect(mocked.spawn.mock.calls[0]?.[2]).toMatchObject({ shell: false, windowsHide: true });
		nativeResult({ observed: true });
		expect(await runtime.adapter.verify(view(delivery), undefined, delivery)).toEqual({
			observed: true,
		});
		expect(mocked.spawn).toHaveBeenCalledTimes(2);
	});

	it("rejects unsigned, forged and wrong-key deliveries before process creation", async () => {
		const { runtime, delivery } = await adapter();
		expect(await runtime.adapter.execute(view(delivery))).toEqual({
			ok: false,
			code: "missing_signed_delivery",
		});
		expect(
			await runtime.adapter.execute(view(delivery), undefined, {
				...delivery,
				sig_b64: Buffer.alloc(64).toString("base64"),
			}),
		).toEqual({ ok: false, code: "invalid_signed_delivery" });
		expect(
			await runtime.adapter.execute(
				view(delivery),
				undefined,
				signedCommand(token({ agent_id: otherAgentId })),
			),
		).toEqual({ ok: false, code: "invalid_signed_delivery" });
		expect(mocked.spawn).not.toHaveBeenCalled();
	});

	it("accepts literal booleans only and sanitizes native failure text", async () => {
		const { runtime, delivery } = await adapter();
		nativeResult({ ok: "true", code: "private credential material" });
		expect(await runtime.adapter.execute(view(delivery), undefined, delivery)).toEqual({
			ok: false,
			code: "execution_failed",
		});
		nativeResult({ ok: true, observed: "true" });
		expect(await runtime.adapter.verify(view(delivery), undefined, delivery)).toEqual({
			observed: false,
			code: "native_action_outcome_unknown",
		});
		nativeResult({ ok: false, code: "native_action_outcome_unknown" });
		expect(await runtime.adapter.execute(view(delivery), undefined, delivery)).toEqual({
			ok: false,
			code: "native_action_outcome_unknown",
		});
	});

	it("kills a cancelled process and keeps ambiguous results interrupted", async () => {
		const { runtime, delivery } = await adapter();
		const child = Object.assign(new EventEmitter(), {
			stdin: new PassThrough(),
			stdout: new PassThrough(),
			stderr: new PassThrough(),
			kill: vi.fn(() => true),
		});
		mocked.spawn.mockReturnValueOnce(child);
		const controller = new AbortController();
		const pending = runtime.adapter.execute(view(delivery), controller.signal, delivery);
		controller.abort();
		await expect(pending).rejects.toBeInstanceOf(FleetResponseActionInterrupted);
		expect(child.kill).toHaveBeenCalledOnce();
	});

	it("retains execution intent when execute succeeds but independent observation fails", async () => {
		const { current, delivery } = await adapter();
		nativeResult({ ok: true });
		nativeResult({ ok: false, code: "response_action_not_observed" });
		const network = vi
			.fn<typeof fetch>()
			.mockResolvedValueOnce(new Response(JSON.stringify({ ok: true, command_signed: delivery })))
			.mockResolvedValueOnce(
				new Response(JSON.stringify({ ok: true, command_id: commandId, state: "acknowledged" })),
			);
		vi.stubGlobal("fetch", network);
		expect(
			await runInstalledWindowsResponseWorker(current.adapterPath, { once: true }),
		).toMatchObject({
			status: "outcome_unknown",
			stage: "result",
			reason: "execution_state_unverified",
		});
		const state = await loadInstalledWindowsResponseWorker(current.adapterPath);
		expect(state.state.current?.phase).toBe("execute_intent");
		expect(network).toHaveBeenCalledTimes(2);
	});

	it("bounds combined output and never echoes stderr", async () => {
		const { runtime, delivery } = await adapter();
		const child = Object.assign(new EventEmitter(), {
			stdin: new PassThrough(),
			stdout: new PassThrough(),
			stderr: new PassThrough(),
			kill: vi.fn(() => true),
		});
		mocked.spawn.mockReturnValueOnce(child);
		const pending = runtime.adapter.execute(view(delivery), undefined, delivery);
		child.stderr.emit("data", Buffer.alloc(16_385, 65));
		await expect(pending).rejects.toBeInstanceOf(FleetResponseActionInterrupted);
		expect(child.kill).toHaveBeenCalledOnce();
	});

	it("bounds a hung process and preserves ambiguity on timeout", async () => {
		const { runtime, delivery } = await adapter();
		vi.useFakeTimers();
		const child = Object.assign(new EventEmitter(), {
			stdin: new PassThrough(),
			stdout: new PassThrough(),
			stderr: new PassThrough(),
			kill: vi.fn(() => true),
		});
		mocked.spawn.mockReturnValueOnce(child);
		const pending = runtime.adapter.execute(view(delivery), undefined, delivery);
		const observed = expect(pending).rejects.toBeInstanceOf(FleetResponseActionInterrupted);
		await vi.advanceTimersByTimeAsync(35_001);
		await observed;
		expect(child.kill).toHaveBeenCalledOnce();
	});

	it("observes only the authenticated old execution intent after same-device key rotation", async () => {
		const { current, runtime, delivery } = await adapter();
		const rotated = token({ exp: Math.floor(Date.now() / 1000) + 7200 });
		const ref = {
			store: "windows-dpapi",
			id: `aidr-${"2".repeat(32)}`,
			created_at: new Date().toISOString(),
		};
		mocked.keys.set(ref.id, rotated);
		await writeFile(
			join(current.aidrDir, "secrets", `${ref.id}.dpapi`),
			"synthetic sealed fixture",
		);
		await writeFile(
			join(current.aidrDir, "managed.json"),
			JSON.stringify({ ...current.managed, api_key_ref: ref }),
		);
		await runtime.journal.load();
		await runtime.journal.save({
			...runtime.state,
			current: { command: view(delivery), delivery, phase: "execute_intent", resultCode: null },
		});
		const reloaded = await loadInstalledWindowsResponseWorker(current.adapterPath);
		expect(reloaded.apiKey).toBe(rotated);
		expect(reloaded.stableJournalKey).toBe(runtime.stableJournalKey);
		nativeResult({ observed: true });
		expect(await reloaded.adapter.verify(view(delivery), undefined, delivery)).toEqual({
			observed: true,
		});
		expect(await reloaded.adapter.execute(view(delivery), undefined, delivery)).toEqual({
			ok: false,
			code: "invalid_signed_delivery",
		});
	});
});
