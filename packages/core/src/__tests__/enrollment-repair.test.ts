import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ControlPlaneClient } from "../clients/control-plane.js";
import { evaluateToolCall } from "../evaluator.js";
import { extractFromBash } from "../extractors.js";
import * as managed from "../managed.js";
import { enrollManagedInstallation } from "../managed-enrollment.js";
import { runSessionStart } from "../session-start.js";
import { ConfigSchema, nullLogger } from "../types.js";

const vault = vi.hoisted(() => ({ keys: new Map<string, string>() }));
vi.mock("../secret-store.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../secret-store.js")>();
	return {
		...actual,
		resolveSecretStore: () => ({
			kind: "windows-dpapi",
			location: "os-vault",
			osProtected: true,
			isAvailable: () => true,
			get: (id: string) => vault.keys.get(id) ?? null,
			put: (id: string, key: string) => {
				vault.keys.set(id, key);
			},
			revoke: (id: string) => {
				vault.keys.delete(id);
			},
		}),
	};
});

const iid = "00000000-0000-4000-8000-000000000001";
const enrollmentToken = "aidr_enroll_synthetic-token";
const issuedKey = "aidr_live_synthetic-issued-key";
const configInput = {
	mode: "managed",
	auth: {},
	control_plane: { enabled: true, endpoint: "https://control.example.test", timeout_seconds: 0.5 },
	url_check: { enabled: false },
	file_check: { enabled: false },
	package_check: { enabled: false },
	cache: { enabled: false },
	logging: { enabled: false },
};
const config = ConfigSchema.parse(configInput);

function response(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function deferred<T>() {
	let complete!: (value: T) => void;
	const promise = new Promise<T>((done) => {
		complete = done;
	});
	return { promise, complete };
}

describe("managed enrollment repair", () => {
	let home: string;
	let directory: string;
	let managedPath: string;
	let pendingPath: string;

	beforeEach(async () => {
		home = await mkdtemp(join(tmpdir(), "aidr-enrollment-repair-"));
		directory = join(home, ".singularity-aidr");
		await mkdir(directory);
		managedPath = join(directory, "managed.json");
		pendingPath = `${managedPath}.enrollment-pending`;
		vi.stubEnv("HOME", home);
		vi.stubEnv("USERPROFILE", home);
		vi.stubEnv("AIDR_COMMERCIAL", "1");
		await writeFile(join(directory, "installation-id"), iid);
		await writeFile(join(directory, "config.json"), JSON.stringify(configInput));
	});

	afterEach(async () => {
		vi.restoreAllMocks();
		vi.unstubAllEnvs();
		vi.unstubAllGlobals();
		vault.keys.clear();
		await rm(home, { recursive: true, force: true });
	});

	function enroll() {
		return enrollManagedInstallation({
			managedPath,
			enrollmentToken,
			iid,
			config,
			logger: nullLogger,
			agentRuntime: "claude-code",
		});
	}

	function startup() {
		return runSessionStart({
			plugins: [],
			version: "test",
			agentRuntime: "claude-code",
			threatsDir: resolve("packages/claude-code/resources/threats"),
			allowlistsDir: resolve("packages/claude-code/resources/allowlists"),
		});
	}

	async function cachedDevice() {
		await writeFile(
			managedPath,
			JSON.stringify({
				device_code: "aidr_device_synthetic",
				user_code: "ABCD-EFGH",
				verification_url: "https://dashboard.example.test/verify",
				device_expires_at: new Date(Date.now() + 60_000).toISOString(),
			}),
		);
	}

	it("stops startup retries after a lost issuance response, including expiry and config changes", async () => {
		await cachedDevice();
		const fetcher = vi.fn(async (url: string | URL | Request) => {
			if (String(url).endsWith("/device-poll"))
				return response({ enrollment_token: enrollmentToken });
			throw new Error("response lost after commit");
		});
		vi.stubGlobal("fetch", fetcher);
		const first = await startup();
		expect(first.disabled_reason).toBe("enrollment_repair_required");
		expect(first.bootstrap).toBeUndefined();
		const pending = await readFile(pendingPath, "utf8");
		expect(pending).toContain(iid);
		expect(pending).not.toContain(enrollmentToken);
		expect(pending).not.toContain(issuedKey);
		await writeFile(managedPath, JSON.stringify({ device_expires_at: "2000-01-01T00:00:00Z" }));
		await writeFile(join(directory, "config.json"), JSON.stringify({ ...configInput, auth: {} }));
		const restarted = await startup();
		expect(restarted.disabled_reason).toBe("enrollment_repair_required");
		expect(restarted.bootstrap).toBeUndefined();
		expect(fetcher.mock.calls.map(([url]) => String(url).split("/").pop())).toEqual([
			"device-poll",
			"enroll",
		]);
		expect(await readFile(join(directory, "installation-id"), "utf8")).toBe(iid);
	});

	it("retries a confirmed precommit rejection and clears the journal only after durable key storage", async () => {
		const fetcher = vi
			.fn()
			.mockResolvedValueOnce(
				response({ error: "rate_limited", enrollment_outcome: "not_committed" }, 429),
			)
			.mockResolvedValueOnce(response({ api_key: issuedKey }));
		vi.stubGlobal("fetch", fetcher);
		expect(await enroll()).toEqual({ outcome: "retry" });
		await expect(readFile(pendingPath)).rejects.toMatchObject({ code: "ENOENT" });
		expect(await enroll()).toMatchObject({ outcome: "enrolled", apiKey: issuedKey });
		await expect(readFile(pendingPath)).rejects.toMatchObject({ code: "ENOENT" });
		expect((await managed.loadManagedState(managedPath, { authToken: issuedKey })).api_key).toBe(
			issuedKey,
		);
		expect(await readFile(managedPath, "utf8")).not.toContain(issuedKey);
		expect(fetcher).toHaveBeenCalledTimes(2);
	});

	it.each(["unknown", "committed"])(
		"does not retry a server %s issuance outcome",
		async (outcome) => {
			const fetcher = vi.fn().mockResolvedValue(response({ enrollment_outcome: outcome }, 503));
			vi.stubGlobal("fetch", fetcher);
			expect(await enroll()).toEqual({ outcome: "repair" });
			expect(await enroll()).toEqual({ outcome: "repair" });
			expect(fetcher).toHaveBeenCalledTimes(1);
		},
	);

	it("serializes concurrent issuance attempts with one HTTP exchange", async () => {
		const started = deferred<void>();
		const reply = deferred<Response>();
		const fetcher = vi.fn(() => {
			started.complete();
			return reply.promise;
		});
		vi.stubGlobal("fetch", fetcher);
		const first = enroll();
		await started.promise;
		expect(await enroll()).toEqual({ outcome: "repair" });
		reply.complete(response({ enrollment_outcome: "unknown" }, 503));
		expect(await first).toEqual({ outcome: "repair" });
		expect(fetcher).toHaveBeenCalledTimes(1);
	});

	it("keeps repair required when the committed key cannot be persisted", async () => {
		const fetcher = vi.fn(async () => {
			await mkdir(managedPath);
			return response({ api_key: issuedKey });
		});
		vi.stubGlobal("fetch", fetcher);
		expect(await enroll()).toEqual({ outcome: "repair" });
		expect(await enroll()).toEqual({ outcome: "repair" });
		expect(fetcher).toHaveBeenCalledTimes(1);
		expect(vault.keys.size).toBe(0);
		expect(await readFile(pendingPath, "utf8")).not.toContain(issuedKey);
	});

	it("does not let a stale issuance writer overwrite a newer credential or clear its marker", async () => {
		const started = deferred<void>();
		const reply = deferred<Response>();
		vi.stubGlobal(
			"fetch",
			vi.fn(() => {
				started.complete();
				return reply.promise;
			}),
		);
		const first = enroll();
		await started.promise;
		await writeFile(pendingPath, JSON.stringify({ attempt: "replacement-attempt", iid }));
		await managed.saveManagedState(managedPath, { api_key: "aidr_live_newer-key" });
		reply.complete(response({ api_key: issuedKey }));
		expect(await first).toEqual({ outcome: "repair" });
		expect((await managed.loadManagedState(managedPath)).api_key).toBe("aidr_live_newer-key");
		expect(await readFile(pendingPath, "utf8")).toContain("replacement-attempt");
	});

	it("does not let a delayed device-start response erase a completed enrollment", async () => {
		const delayed = deferred<Response>();
		const slowStarted = deferred<void>();
		let starts = 0;
		const fetcher = vi.fn(async (url: string | URL | Request) => {
			const endpoint = String(url).split("/").pop();
			if (endpoint === "device-start" && ++starts === 1) {
				slowStarted.complete();
				return delayed.promise;
			}
			if (endpoint === "device-start")
				return response({
					device_code: "fast-device",
					user_code: "FAST-CODE",
					verification_url: "https://dashboard.example.test/verify",
					expires_at: new Date(Date.now() + 60_000).toISOString(),
				});
			if (endpoint === "device-poll") return response({ enrollment_token: enrollmentToken });
			if (endpoint === "enroll") return response({ api_key: issuedKey });
			return response({ error: "unavailable" }, 503);
		});
		vi.stubGlobal("fetch", fetcher);
		const slow = startup();
		await slowStarted.promise;
		await startup();
		expect((await managed.loadManagedState(managedPath)).api_key).toBe(issuedKey);
		delayed.complete(
			response({
				device_code: "slow-device",
				user_code: "SLOW-CODE",
				verification_url: "https://dashboard.example.test/verify",
				expires_at: new Date(Date.now() + 60_000).toISOString(),
			}),
		);
		const result = await slow;
		expect(result.bootstrap).toBeUndefined();
		expect((await managed.loadManagedState(managedPath)).api_key).toBe(issuedKey);
		expect(vault.keys.size).toBe(1);
		expect(fetcher.mock.calls.filter(([url]) => String(url).endsWith("/enroll"))).toHaveLength(1);
		expect(fetcher.mock.calls.filter(([url]) => String(url).endsWith("/device-poll"))).toHaveLength(
			1,
		);
	});

	it("suppresses a spent code even when the final state reload fails", async () => {
		await cachedDevice();
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue(response({ error: "already_exchanged" }, 409)),
		);
		const originalLoad = managed.loadManagedState;
		vi.spyOn(managed, "loadManagedState")
			.mockImplementationOnce(originalLoad)
			.mockRejectedValueOnce(new Error("vault unavailable"));
		const result = await startup();
		expect(result.disabled_reason).toBe("enrollment_repair_required");
		expect(result.bootstrap).toBeUndefined();
		expect(await readFile(pendingPath, "utf8")).toContain(iid);
	});

	it("tool evaluation respects a pending issuance while still detecting local threats", async () => {
		vi.stubEnv("AIDR_COMMERCIAL", "0");
		await writeFile(
			join(directory, "config.json"),
			JSON.stringify({
				...configInput,
				auth: { enrollment_token: enrollmentToken },
			}),
		);
		await writeFile(pendingPath, JSON.stringify({ attempt: "unknown-prior-attempt", iid }));
		await rm(join(directory, "installation-id"));
		const fetcher = vi.fn().mockRejectedValue(new Error("unexpected network request"));
		vi.stubGlobal("fetch", fetcher);
		const verdict = await evaluateToolCall(
			{
				sessionId: "repair",
				toolName: "Bash",
				toolInput: { command: "rm -rf /" },
				artifacts: extractFromBash("rm -rf /"),
			},
			{
				configPath: join(directory, "config.json"),
				threatsDir: resolve("packages/claude-code/resources/threats"),
				allowlistsDir: resolve("packages/claude-code/resources/allowlists"),
			},
		);
		expect(verdict.decision).toBe("deny");
		expect(verdict.source).toBe("heuristic");
		expect(fetcher.mock.calls.filter(([url]) => String(url).endsWith("/enroll"))).toHaveLength(0);
		await expect(readFile(join(directory, "installation-id"))).rejects.toMatchObject({
			code: "ENOENT",
		});
	});

	it("does not generate a new installation identity during pending startup repair", async () => {
		await writeFile(pendingPath, JSON.stringify({ attempt: "crashed-prior-attempt", iid }));
		await rm(join(directory, "installation-id"));
		vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("unexpected network request")));
		expect((await startup()).disabled_reason).toBe("enrollment_repair_required");
		await expect(readFile(join(directory, "installation-id"))).rejects.toMatchObject({
			code: "ENOENT",
		});
	});

	it("client outcomes keep transport and untyped server failures uncertain", async () => {
		const client = new ControlPlaneClient(config.control_plane, enrollmentToken);
		vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("timeout")));
		expect(await client.enroll({ iid })).toMatchObject({ enrollment_outcome: "unknown" });
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue(response({ error: "invalid_or_expired_enrollment_token" }, 401)),
		);
		expect(await client.enroll({ iid })).toMatchObject({ enrollment_outcome: "unknown" });
		vi.stubGlobal(
			"fetch",
			vi.fn().mockResolvedValue(response({ enrollment_outcome: "not_committed" }, 429)),
		);
		expect(await client.enroll({ iid })).toMatchObject({ enrollment_outcome: "not_committed" });
	});
});
