/**
 * Tests for the CLI secret store (gap B5).
 *
 * ## What is and is not exercised here
 *
 * The platform backends shell out to `powershell.exe` (DPAPI), `security(1)`
 * (macOS Keychain) and `secret-tool(1)` (Linux Secret Service). This suite drives
 * every one of them through an INJECTED `CommandRunner`, so the protocol each
 * adapter speaks — which tool, which arguments, where the secret travels, what a
 * "not found" exit looks like — is asserted, and the config manager is exercised
 * end to end against a store.
 *
 * **No real OS vault was exercised.** A real DPAPI blob, a real Keychain item and
 * a real Secret Service entry cannot be created on this build host, and the suite
 * does not pretend otherwise: it never calls the default runner for a vault.
 *
 * ## The rules these cases pin
 *
 * 1. With a store selected, `config.json` holds a `secret_ref` and never the
 *    credential, and reads resolve it through the store.
 * 2. `file-acl` is refused unless it is named explicitly — an unavailable vault
 *    makes the CLI fail closed, not fall back to plaintext.
 * 3. A rotation leaves the previous secret valid until the new one is committed,
 *    and rolls the new one back if the commit fails.
 * 4. `--force` still works on the explicitly selected file fallback.
 */

import {
	existsSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	renameSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import type {
	CommandRequest,
	CommandResult,
	CommandRunner,
	SecretStore,
	SecretStoreKind,
} from "../utils/secret-store.js";

const testHome = mkdtempSync(join(tmpdir(), "aidr-secret-store-"));
const originalHome = process.env.HOME;
process.env.HOME = testHome;
vi.mock("node:os", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:os")>();
	return { ...actual, homedir: () => testHome };
});
vi.mock("@singularityrd/aidr-core", async (importOriginal) => ({
	...(await importOriginal<typeof import("@singularityrd/aidr-core")>()),
	...(await vi.importActual<Record<string, unknown>>("../../../core/src/secret-store.js")),
}));

// These cases drive the store explicitly; the ambient selection must not leak in.
delete process.env.AIDR_SECRET_STORE;

const {
	SecretStoreUnavailableError,
	createFileAclStore,
	createLinuxSecretServiceStore,
	createMacosKeychainStore,
	createWindowsDpapiStore,
	resolveSecretStore,
} = await import("../utils/secret-store.js");
const { createConfig, getConfig, replaceConfig, revokeSecret, rotateSecret } = await import(
	"../utils/config-manager.js"
);

const configDir = join(testHome, ".singularity-aidr");
const configFile = join(configDir, "config.json");
const env = {
	agent: "claude" as const,
	hasNode: true,
	nodeVersion: process.version,
	projectRoot: testHome,
};

afterEach(() => {
	delete process.env.AIDR_COMMERCIAL;
	rmSync(configDir, { recursive: true, force: true });
});
afterAll(() => {
	if (originalHome === undefined) delete process.env.HOME;
	else process.env.HOME = originalHome;
	rmSync(testHome, { recursive: true, force: true });
});

function storedDocument(): Record<string, unknown> {
	return JSON.parse(readFileSync(configFile, "utf8")) as Record<string, unknown>;
}

function storedSecretRefId(): string {
	const reference = storedDocument().secret_ref as { id?: string } | undefined;
	return reference?.id ?? "";
}

interface FakeVaultHooks {
	onPut?: (id: string) => void;
	onRevoke?: (id: string) => void;
}

/** An in-memory stand-in for a vault, so commit ordering can be observed exactly. */
function fakeVault(
	kind: SecretStoreKind,
	secrets: Map<string, string>,
	hooks: FakeVaultHooks = {},
): SecretStore {
	return {
		kind,
		location: "os-vault",
		osProtected: true,
		isAvailable: () => true,
		put: (id, secret) => {
			hooks.onPut?.(id);
			secrets.set(id, secret);
		},
		get: (id) => secrets.get(id) ?? null,
		revoke: (id) => {
			hooks.onRevoke?.(id);
			secrets.delete(id);
		},
	};
}

// ---------------------------------------------------------------------------
// Injected runners: one per platform backend
// ---------------------------------------------------------------------------

interface RecordedCall {
	command: string;
	args: string[];
	input?: string;
}

/**
 * Simulates DPAPI's Protect/Unprotect round trip. The protect script is
 * identified by decoding the `-EncodedCommand` payload, which is exactly how the
 * real host chooses the script too.
 */
function dpapiRunner(): { runner: CommandRunner; calls: RecordedCall[] } {
	const calls: RecordedCall[] = [];
	const runner: CommandRunner = (command, args, request: CommandRequest): CommandResult => {
		const index = args.indexOf("-EncodedCommand");
		const script =
			index >= 0 ? Buffer.from(args[index + 1] ?? "", "base64").toString("utf16le") : "";
		calls.push({ command, args, input: request.input });
		if (script.includes("::Unprotect(")) {
			const sealed = Buffer.from(request.input ?? "", "base64").toString("utf8");
			return {
				status: 0,
				stdout: Buffer.from(sealed.replace(/^SEALED:/, ""), "utf8").toString("base64"),
			};
		}
		if (script.includes("::Protect(")) {
			return {
				status: 0,
				stdout: Buffer.from(`SEALED:${request.input ?? ""}`, "utf8").toString("base64"),
			};
		}
		return { status: 1, stderr: "unsupported DPAPI script" };
	};
	return { runner, calls };
}

/** Simulates `security(1)`'s generic-password commands. */
function keychainRunner(): { runner: CommandRunner; calls: RecordedCall[] } {
	const items = new Map<string, { secret: string; label: string; marker: string }>();
	const calls: RecordedCall[] = [];
	const notFound = {
		status: 44,
		stderr: "security: SecKeychainSearchCopyNext: The specified item could not be found.",
	};
	const handle = (args: string[]): CommandResult => {
		const account = args[args.indexOf("-a") + 1] ?? "";
		switch (args[0]) {
			case "list-keychains":
				return { status: 0, stdout: '    "login.keychain-db"\n' };
			case "add-generic-password":
				items.set(account, {
					secret: args[args.indexOf("-w") + 1] ?? "",
					label: args[args.indexOf("-l") + 1] ?? "",
					marker: args[args.indexOf("-G") + 1] ?? "",
				});
				return { status: 0 };
			case "find-generic-password": {
				const item = args.includes("-a")
					? items.get(account)
					: [...items.values()].find(
							(value) =>
								value.label === args[args.indexOf("-l") + 1] &&
								value.marker === args[args.indexOf("-G") + 1],
						);
				return item === undefined ? notFound : { status: 0, stdout: `${item.secret}\n` };
			}
			case "delete-generic-password":
				return items.delete(account) ? { status: 0 } : notFound;
			default:
				return { status: 2, stderr: "unsupported security command" };
		}
	};
	const runner: CommandRunner = (command, args, request: CommandRequest): CommandResult => {
		calls.push({ command, args, input: request.input });
		if (command !== "/usr/bin/security") return { status: 127, error: new Error("spawn ENOENT") };
		return handle(args[0] === "-q" ? (request.input ?? "").replace(/\n$/, "").split(" ") : args);
	};
	return { runner, calls };
}

/** Simulates libsecret's `secret-tool`, which takes the secret on stdin. */
function secretToolRunner(): { runner: CommandRunner; calls: RecordedCall[] } {
	const items = new Map<string, string>();
	const calls: RecordedCall[] = [];
	const runner: CommandRunner = (command, args, request: CommandRequest): CommandResult => {
		calls.push({ command, args, input: request.input });
		if (command !== "secret-tool") return { status: 127, error: new Error("spawn ENOENT") };
		const action = args[0];
		const id = args[args.length - 1] ?? "";
		if (action === "store") {
			items.set(id, request.input ?? "");
			return { status: 0 };
		}
		if (action === "lookup") {
			const secret = items.get(id);
			return secret === undefined
				? { status: 1, stderr: "No such secret item at path" }
				: { status: 0, stdout: `${secret}\n` };
		}
		if (action === "clear") {
			items.delete(id);
			return { status: 0 };
		}
		return { status: 2, stderr: "unsupported secret-tool command" };
	};
	return { runner, calls };
}

// ---------------------------------------------------------------------------
// Platform backends
// ---------------------------------------------------------------------------

describe("platform secret-store backends (injected command runner)", () => {
	it("seals the credential with Windows DPAPI", () => {
		const directory = join(testHome, "dpapi-directory");
		const { runner, calls } = dpapiRunner();
		const store = createWindowsDpapiStore({ runner, directory });
		expect(store.kind).toBe("windows-dpapi");
		expect(store.location).toBe("os-vault");
		expect(store.isAvailable()).toBe(true);

		const secret = "aidr_dpapi_test_value";
		store.put("aidr-0000000000000001", secret);
		const blob = readFileSync(join(directory, "aidr-0000000000000001.dpapi"), "utf8");
		expect(blob).not.toContain(secret);
		expect(store.get("aidr-0000000000000001")).toBe(secret);
		expect(store.get("aidr-0000000000000002")).toBeNull();

		store.revoke("aidr-0000000000000001");
		expect(existsSync(join(directory, "aidr-0000000000000001.dpapi"))).toBe(false);

		// The plaintext travels on stdin; it is never part of a command line.
		expect(calls.some((call) => call.input === secret)).toBe(true);
		for (const call of calls) expect(call.args.join(" ")).not.toContain(secret);
		expect(calls.every((call) => call.command === "powershell.exe")).toBe(true);
	});

	it("keeps the credential in the macOS keychain", () => {
		const { runner, calls } = keychainRunner();
		const store = createMacosKeychainStore({ runner });
		expect(store.kind).toBe("macos-keychain");
		expect(store.isAvailable()).toBe(true);

		const secret = "aidr_keychain_test_value";
		store.put("aidr-0000000000000001", secret);
		expect(store.get("aidr-0000000000000001")).toBe(secret);
		expect(store.get("aidr-0000000000000002")).toBeNull();
		store.revoke("aidr-0000000000000001");
		expect(store.get("aidr-0000000000000001")).toBeNull();
		// Deleting something already gone is not an error.
		expect(() => store.revoke("aidr-0000000000000002")).not.toThrow();

		const added = calls.find((call) => call.args[0] === "-q");
		expect(added?.args).toEqual(["-q", "-i"]);
		expect(added?.input).toContain(`-w ${Buffer.from(secret).toString("base64")} -U\n`);
		for (const call of calls) expect(call.args.join(" ")).not.toContain(secret);
		expect(calls.every((call) => call.command === "/usr/bin/security")).toBe(true);
		const read = calls.find((call) => call.args[0] === "find-generic-password");
		expect(read?.args.join(" ")).not.toContain(secret);
	});

	it("keeps the credential in the Linux Secret Service", () => {
		const { runner, calls } = secretToolRunner();
		const store = createLinuxSecretServiceStore({ runner });
		expect(store.kind).toBe("linux-secret-service");
		expect(store.isAvailable()).toBe(true);

		const secret = "aidr_secret_service_value";
		store.put("aidr-0000000000000001", secret);
		expect(store.get("aidr-0000000000000001")).toBe(secret);
		store.revoke("aidr-0000000000000001");
		expect(store.get("aidr-0000000000000001")).toBeNull();

		expect(calls.every((call) => call.command === "secret-tool")).toBe(true);
		expect(calls.some((call) => call.input === secret)).toBe(true);
		for (const call of calls) expect(call.args.join(" ")).not.toContain(secret);
	});

	it("does not clear the config reference when Linux revoke fails", async () => {
		const { runner: baseRunner } = secretToolRunner();
		const store = createLinuxSecretServiceStore({
			runner: (command, args, request) =>
				args[0] === "clear"
					? { status: 1, stderr: "Cannot autolaunch D-Bus without X11 $DISPLAY" }
					: baseRunner(command, args, request),
		});
		await createConfig(env, false, { secretStore: store });
		const before = readFileSync(configFile, "utf8");

		expect(() => revokeSecret({ secretStore: store })).toThrow(/refused to delete/i);
		expect(readFileSync(configFile, "utf8")).toBe(before);
		expect(storedDocument().secret_ref).toBeDefined();
	});

	it("clears the config only when Linux revoke confirms the item is absent", async () => {
		const { runner: baseRunner } = secretToolRunner();
		const store = createLinuxSecretServiceStore({
			runner: (command, args, request) =>
				args[0] === "clear"
					? { status: 1, stderr: "No such secret item at path" }
					: baseRunner(command, args, request),
		});
		await createConfig(env, false, { secretStore: store });

		const result = revokeSecret({ secretStore: store });

		expect(result.revokedRef).toBeTruthy();
		expect(storedDocument().secret_ref).toBeUndefined();
		expect(storedDocument().apiKey).toBeUndefined();
	});

	it("reports a backend as unavailable when its tool cannot run", () => {
		const missing: CommandRunner = () => ({ status: null, error: new Error("spawn ENOENT") });
		expect(createLinuxSecretServiceStore({ runner: missing }).isAvailable()).toBe(false);
		expect(createMacosKeychainStore({ runner: missing }).isAvailable()).toBe(false);
		expect(
			createWindowsDpapiStore({
				runner: missing,
				directory: join(testHome, "missing"),
			}).isAvailable(),
		).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Selection rules
// ---------------------------------------------------------------------------

describe("secret-store selection", () => {
	it("refuses the file fallback unless it is explicitly selected", () => {
		const missing: CommandRunner = () => ({ status: null, error: new Error("spawn ENOENT") });

		// Automatic detection never returns the fallback; it throws instead.
		for (const platform of ["win32", "darwin", "linux"] as const) {
			expect(() => resolveSecretStore({ env: {}, platform, runner: missing })).toThrow(
				SecretStoreUnavailableError,
			);
		}
		let message = "";
		try {
			resolveSecretStore({ env: {}, platform: "linux", runner: missing });
		} catch (error) {
			message = (error as Error).message;
		}
		expect(message).toMatch(/file-acl/);
		expect(message).toMatch(/plaintext/i);

		// Naming it — by flag or by environment — selects it, and the adapter says
		// plainly that it does not isolate anything.
		const fallback = resolveSecretStore({ selection: "file-acl", env: {}, runner: missing });
		expect(fallback.kind).toBe("file-acl");
		expect(fallback.location).toBe("config-file");
		expect(fallback.osProtected).toBe(false);
		expect(() => fallback.put("aidr-0000000000000001", "secret")).toThrow(/config document/);
		expect(
			resolveSecretStore({
				env: { AIDR_SECRET_STORE: "file-acl" },
				platform: "linux",
				runner: missing,
			}).kind,
		).toBe("file-acl");

		expect(() => resolveSecretStore({ selection: "keytar", env: {}, runner: missing })).toThrow(
			/Unknown secret store/,
		);
	});
});

// ---------------------------------------------------------------------------
// Config manager integration
// ---------------------------------------------------------------------------

describe("config manager with a secret store", () => {
	it("never writes the credential into config.json when a secret store is selected", async () => {
		const { runner } = dpapiRunner();
		const store = createWindowsDpapiStore({ runner, directory: join(testHome, "dpapi-config") });

		expect((await createConfig(env, false, { secretStore: store })).outcome).toBe("created");

		const stored = readFileSync(configFile, "utf8");
		const document = storedDocument();
		expect(document.apiKey).toBeUndefined();
		expect(document.secret_store).toBe("windows-dpapi");
		expect(typeof storedSecretRefId()).toBe("string");
		expect(storedSecretRefId().length).toBeGreaterThan(0);

		const resolved = getConfig({ secretStore: store });
		expect(resolved?.apiKey).toMatch(/^aidr_[A-Za-z0-9_-]{40,}$/);
		expect(stored).not.toContain(resolved?.apiKey ?? "\u0000");
		expect(store.get(storedSecretRefId())).toBe(resolved?.apiKey);
		for (const entry of readdirSync(configDir)) {
			expect(readFileSync(join(configDir, entry), "utf8")).not.toContain(
				resolved?.apiKey ?? "\u0000",
			);
		}
	});

	it("fails closed when no store is available and the fallback was not selected", async () => {
		const missing: CommandRunner = () => ({ status: null, error: new Error("spawn ENOENT") });

		await expect(createConfig(env, false, { secretStoreRunner: missing })).rejects.toThrow(
			SecretStoreUnavailableError,
		);
		// Nothing was written: not a plaintext credential, not even an empty config.
		expect(existsSync(configFile)).toBe(false);

		// The refusal is about the silent fallback, not about being unable to
		// configure at all: naming the fallback works.
		expect((await createConfig(env, false, { secretStoreSelection: "file-acl" })).outcome).toBe(
			"created",
		);
		expect(typeof storedDocument().apiKey).toBe("string");
	});

	it("fails closed when the store a config points at can no longer supply it", async () => {
		const secrets = new Map<string, string>();
		const store = fakeVault("windows-dpapi", secrets);
		await createConfig(env, false, { secretStore: store });

		secrets.clear();
		expect(() => getConfig({ secretStore: store })).toThrow(
			/missing from the windows-dpapi secret store/,
		);
		// Without the injected store the reference is resolved on its own and still
		// refuses to hand back an empty or plaintext credential.
		expect(() => getConfig()).toThrow(/windows-dpapi/);
		expect(storedDocument().apiKey).toBeUndefined();
	});

	it("leaves the previous secret valid until the rotation commits", async () => {
		const secrets = new Map<string, string>();
		let simulateConcurrentWriter = false;
		let previousRefId = "";
		let previousAliveAtPut: boolean | null = null;
		let committedRefAtRevoke: string | null = null;

		const store = fakeVault("windows-dpapi", secrets, {
			onPut: (id) => {
				if (simulateConcurrentWriter) {
					// Another writer replaces config.json between the store write and
					// the config commit.
					const temporary = `${configFile}.concurrent`;
					writeFileSync(temporary, JSON.stringify({ ...storedDocument(), concurrent_edit: true }));
					renameSync(temporary, configFile);
					return;
				}
				if (id !== previousRefId) previousAliveAtPut = secrets.has(previousRefId);
			},
			onRevoke: (id) => {
				if (id === previousRefId) committedRefAtRevoke = storedSecretRefId();
			},
		});

		await createConfig(env, false, { secretStore: store });
		const originalKey = getConfig({ secretStore: store })?.apiKey;
		previousRefId = storedSecretRefId();
		expect(originalKey).toBeTruthy();
		expect(secrets.has(previousRefId)).toBe(true);

		// A rotation whose commit loses the race rolls the new secret back and
		// leaves the previous one usable.
		simulateConcurrentWriter = true;
		expect(() => rotateSecret({ secretStore: store })).toThrow(/Local config changed during/);
		simulateConcurrentWriter = false;
		expect(getConfig({ secretStore: store })?.apiKey).toBe(originalKey);
		expect(storedSecretRefId()).toBe(previousRefId);
		expect([...secrets.keys()]).toEqual([previousRefId]);

		// A rotation that commits revokes the previous secret only afterwards.
		previousAliveAtPut = null;
		const rotation = rotateSecret({ secretStore: store });
		expect(rotation.previousRef?.id).toBe(previousRefId);
		expect(rotation.ref?.id).not.toBe(previousRefId);
		// The old secret was still in the store when the new one was written...
		expect(previousAliveAtPut).toBe(true);
		// ...and the config already referenced the new one when the old was revoked.
		expect(committedRefAtRevoke).toBe(rotation.ref?.id ?? null);
		expect(secrets.has(previousRefId)).toBe(false);
		expect(getConfig({ secretStore: store })?.apiKey).not.toBe(originalKey);
		const document = storedDocument();
		expect(document.secret_ref).toMatchObject({ store: "windows-dpapi" });
		expect(typeof document.secret_rotated_at).toBe("string");
	});

	it("revokes the credential through the store and records the outcome", async () => {
		const secrets = new Map<string, string>();
		const store = fakeVault("windows-dpapi", secrets);
		await createConfig(env, false, { secretStore: store });
		const refId = storedSecretRefId();
		expect(secrets.has(refId)).toBe(true);

		const revocation = revokeSecret({ secretStore: store });
		expect(revocation.revokedRef?.id).toBe(refId);
		expect(revocation.store).toBe("windows-dpapi");
		expect(secrets.size).toBe(0);

		const document = storedDocument();
		expect(document.secret_ref).toBeUndefined();
		expect(typeof document.secret_revoked_at).toBe("string");
		expect(getConfig({ secretStore: store })?.apiKey).toBe("");

		// A revoked config has no credential to reuse, so setup mints a new one
		// rather than reporting "no changes were needed" over an empty credential.
		expect((await createConfig(env, false, { secretStore: store })).outcome).toBe("created");
	});

	it("does not misidentify the separate managed API key as the CLI setup key", async () => {
		process.env.AIDR_COMMERCIAL = "1";
		const secrets = new Map<string, string>();
		const store = fakeVault("windows-dpapi", secrets);
		await createConfig(env, false, { secretStore: store });
		const managedKey = "synthetic-managed-key";
		writeFileSync(
			configFile,
			JSON.stringify({ ...storedDocument(), auth: { api_key: managedKey } }),
		);

		rotateSecret({ secretStore: store });
		const auth = storedDocument().auth as { api_key?: string; api_key_ref: { id: string } };
		expect(auth.api_key).toBeUndefined();
		expect(store.get(auth.api_key_ref.id)).toBe(managedKey);
		revokeSecret({ secretStore: store });
		expect((storedDocument().auth as { api_key_ref: { id: string } }).api_key_ref.id).toBe(
			auth.api_key_ref.id,
		);
		expect(store.get(auth.api_key_ref.id)).toBe(managedKey);
	});

	it("keeps --force working on the explicitly selected file fallback", async () => {
		const fallback = createFileAclStore();

		expect((await createConfig(env, false, { secretStore: fallback })).outcome).toBe("created");
		const before = storedDocument();
		expect(typeof before.apiKey).toBe("string");
		expect(before.secret_store).toBe("file-acl");
		expect(before.secret_ref).toBeUndefined();

		expect((await createConfig(env, true, { secretStore: fallback })).outcome).toBe("created");
		const after = storedDocument();
		expect(after.apiKey).not.toBe(before.apiKey);

		const reusedKey = getConfig({ secretStore: fallback })?.apiKey;
		expect((await createConfig(env, false, { secretStore: fallback })).outcome).toBe("reused");
		expect(getConfig({ secretStore: fallback })?.apiKey).toBe(reusedKey);
	});

	it("migrates managed auth through a private CLI rewrite and rotates its vault reference", async () => {
		process.env.AIDR_COMMERCIAL = "1";
		const secrets = new Map<string, string>();
		const store = fakeVault("windows-dpapi", secrets);
		await createConfig(env, false, { secretStore: store });
		writeFileSync(
			configFile,
			JSON.stringify({
				...storedDocument(),
				auth: { api_key: "synthetic-managed-key", enrollment_token: "synthetic-enroll-token" },
			}),
		);
		expect((await createConfig(env, false, { secretStore: store })).outcome).toBe("reused");
		let stored = JSON.stringify(storedDocument());
		expect(stored).not.toContain("synthetic-managed-key");
		expect(stored).not.toContain("synthetic-enroll-token");
		const originalRef = (storedDocument().auth as { api_key_ref: { id: string } }).api_key_ref.id;
		expect(getConfig({ secretStore: store })?.auth?.api_key).toBe("synthetic-managed-key");
		expect(getConfig({ secretStore: store })?.auth?.enrollment_token).toBe(
			"synthetic-enroll-token",
		);
		const current = getConfig({ secretStore: store });
		if (!current) throw new Error("Expected a stored test config.");
		replaceConfig(
			{
				...current,
				auth: { ...current.auth, api_key: "synthetic-rotated-key" },
			},
			{ secretStore: store },
		);
		stored = JSON.stringify(storedDocument());
		expect(stored).not.toContain("synthetic-rotated-key");
		expect((storedDocument().auth as { api_key_ref: { id: string } }).api_key_ref.id).not.toBe(
			originalRef,
		);
		expect(secrets.has(originalRef)).toBe(false);
		expect(getConfig({ secretStore: store })?.auth?.api_key).toBe("synthetic-rotated-key");
	});
});
