/**
 * Secret-store adapters shared by CLI setup and managed runtime credentials.
 *
 * ## Why this exists
 *
 * The original `config-manager` kept the credential in `~/.singularity-aidr/config.json` with
 * nothing but an ACL (Windows) or an owner-only mode (POSIX) protecting it. That
 * protects against *other* users, not against anything that reads the file as the
 * current user: a synced folder, a backup, a support bundle, or a second process
 * running as the same user. This module puts the credential in the platform's own
 * vault where one exists, and turns the previous plaintext layout into an
 * explicitly selected, clearly-labelled fallback.
 *
 * ## Selection is never silent
 *
 * `resolveSecretStore` accepts an explicit selection (`AIDR_SECRET_STORE`,
 * `--secret-store`, or the recorded `secret_store` in `config.json`). With no
 * selection it probes the vault for the current platform; if the probe fails it
 * THROWS. It never falls back to `file-acl` on its own: the CLI fails closed with
 * a clear message instead of quietly writing a plaintext credential.
 *
 * ## How the platform backends talk to the host
 *
 * Each backend shells out to the platform's own tooling — the same pattern
 * `hardenWindowsAcl` in `config-manager.ts` already used, and deliberately not a
 * native dependency (`keytar`, `node-dpapi`, …) that would have to be compiled per
 * platform and shipped in the SEA bundle. Every command goes through an injectable
 * {@link CommandRunner}, so each backend's protocol is covered by tests without a
 * real DPAPI, Keychain or Secret Service on the build host. **No real OS vault is
 * exercised by the test suite**; see `__tests__/secret-store.test.ts`.
 */

import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { resolvePath } from "./config.js";

export type SecretStoreKind =
	| "windows-dpapi"
	| "macos-keychain"
	| "linux-secret-service"
	| "file-acl";

export const SECRET_STORE_KINDS: readonly SecretStoreKind[] = [
	"windows-dpapi",
	"macos-keychain",
	"linux-secret-service",
	"file-acl",
];

/** Environment variable that selects the store explicitly. */
export const SECRET_STORE_ENV = "AIDR_SECRET_STORE";

/** `AIDR_SECRET_STORE` value that asks for platform detection explicitly. */
export const SECRET_STORE_AUTO = "auto";

export interface CommandResult {
	status: number | null;
	stdout?: string;
	stderr?: string;
	error?: Error;
}

export interface CommandRequest {
	env?: NodeJS.ProcessEnv;
	/** Data written to the child's stdin. Preferred over argv for secret material. */
	input?: string;
	timeout?: number;
}

export type CommandRunner = (
	command: string,
	args: string[],
	request: CommandRequest,
) => CommandResult;

const defaultCommandRunner: CommandRunner = (command, args, request) => {
	const result = spawnSync(command, args, {
		env: request.env,
		input: request.input,
		encoding: "utf8",
		timeout: request.timeout ?? 30_000,
		windowsHide: true,
	});
	return {
		status: result.status,
		stdout: result.stdout ?? undefined,
		stderr: result.stderr ?? undefined,
		error: result.error ?? undefined,
	};
};

export class SecretStoreError extends Error {
	constructor(message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "SecretStoreError";
	}
}

/** No store could be selected: the caller must FAIL CLOSED, never write plaintext. */
export class SecretStoreUnavailableError extends SecretStoreError {
	constructor(message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = "SecretStoreUnavailableError";
	}
}

/** An unknown or malformed selection was supplied. */
export class SecretStoreSelectionError extends SecretStoreError {
	constructor(message: string) {
		super(message);
		this.name = "SecretStoreSelectionError";
	}
}

/**
 * A credential store.
 *
 * `location` is the honest part of the contract:
 * - `os-vault` — the credential is kept by the platform vault; `config.json` only
 *   holds a reference.
 * - `config-file` — the `file-acl` fallback; the credential lives in the
 *   ACL-hardened config document, which the config manager writes directly. Its
 *   vault methods therefore refuse rather than pretend to isolate anything.
 */
export interface SecretStore {
	readonly kind: SecretStoreKind;
	readonly location: "os-vault" | "config-file";
	/** True only for the platform vaults; false for the ACL-hardened file fallback. */
	readonly osProtected: boolean;
	isAvailable(): boolean;
	put(id: string, secret: string): void;
	get(id: string): string | null;
	revoke(id: string): void;
}

const FILE_FALLBACK_MESSAGE =
	"The file-acl fallback keeps the credential in the ACL-hardened config document itself; " +
	"it has no separate vault entry to store, read or revoke.";

/**
 * The ACL-hardened config document as a "store".
 *
 * It exists so the fallback is addressable by name (and can be pinned as
 * `secret_store` in the config), not so it can pretend to isolate a credential.
 * `config-manager` writes and reads the credential inline for this backend.
 */
export function createFileAclStore(): SecretStore {
	return {
		kind: "file-acl",
		location: "config-file",
		osProtected: false,
		isAvailable: () => true,
		put: () => {
			throw new SecretStoreError(FILE_FALLBACK_MESSAGE);
		},
		get: () => {
			throw new SecretStoreError(FILE_FALLBACK_MESSAGE);
		},
		revoke: () => {
			throw new SecretStoreError(FILE_FALLBACK_MESSAGE);
		},
	};
}

/** Ids become file names / keychain account names, so keep them boring and local. */
function assertSafeId(id: string): void {
	if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(id) || id.includes("..")) {
		throw new SecretStoreError("The secret reference is not a safe store identifier.");
	}
}

const availabilityByRunner = new WeakMap<CommandRunner, Map<string, boolean>>();

/** Probing spawns a process; do it once per runner and backend per process. */
function cachedAvailability(runner: CommandRunner, key: string, probe: () => boolean): boolean {
	let entries = availabilityByRunner.get(runner);
	if (!entries) {
		entries = new Map<string, boolean>();
		availabilityByRunner.set(runner, entries);
	}
	const cached = entries.get(key);
	if (cached !== undefined) return cached;
	const value = probe();
	entries.set(key, value);
	return value;
}

function output(result: CommandResult): string {
	return (result.stdout ?? "").trim();
}

// ---------------------------------------------------------------------------
// Windows — DPAPI (CryptProtectData) through PowerShell, as hardenWindowsAcl does
// ---------------------------------------------------------------------------

const DPAPI_PROTECT_SCRIPT = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$plain = [Console]::In.ReadToEnd()
$scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
$bytes = [System.Text.Encoding]::UTF8.GetBytes($plain)
$sealed = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, $scope)
[Console]::Out.Write([Convert]::ToBase64String($sealed))
`;

// `Unprotect` returns a byte[]. It must be base64-encoded AS BYTES: calling
// `[Text.Encoding]::UTF8.GetBytes($plain)` on the array makes PowerShell coerce it
// to the string "99 97 110 ..." first, which returns a corrupted credential. That
// was caught by a real DPAPI round trip on Windows, not by the simulated runner.
const DPAPI_UNPROTECT_SCRIPT = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$sealed = [Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())
$scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
$plain = [System.Security.Cryptography.ProtectedData]::Unprotect($sealed, $null, $scope)
[Console]::Out.Write([Convert]::ToBase64String($plain))
`;

const DPAPI_PROBE = "singularity-aidr-dpapi-probe";

function powershellArgs(script: string): string[] {
	return [
		"-NoProfile",
		"-NonInteractive",
		"-EncodedCommand",
		Buffer.from(script, "utf16le").toString("base64"),
	];
}

export interface WindowsDpapiOptions {
	runner?: CommandRunner;
	/** Where sealed blobs live; defaults under the ACL-hardened AIDR directory. */
	directory?: string;
}

/**
 * Windows DPAPI: the credential is sealed with `CryptProtectData` under the
 * current user's master key and the ciphertext is written to a private file.
 *
 * DPAPI is a crypto API rather than a vault, so the blob has to live somewhere:
 * it goes in `<config dir>/secrets`, which inherits the owner+SYSTEM+Administrators
 * ACL that `config-manager` applies to `~/.singularity-aidr`. Revoking deletes the
 * blob, which makes the ciphertext genuinely unavailable rather than merely
 * unreferenced.
 */
export function createWindowsDpapiStore(options: WindowsDpapiOptions = {}): SecretStore {
	const runner = options.runner ?? defaultCommandRunner;
	const directory = options.directory ?? resolvePath("~/.singularity-aidr/secrets");
	const pathFor = (id: string): string => {
		assertSafeId(id);
		return join(directory, `${id}.dpapi`);
	};

	const seal = (secret: string): string => {
		const result = runner("powershell.exe", powershellArgs(DPAPI_PROTECT_SCRIPT), {
			input: secret,
			timeout: 30_000,
		});
		if (result.error || result.status !== 0) {
			throw new SecretStoreError("The Windows DPAPI store could not encrypt the credential.", {
				cause: result.error,
			});
		}
		const sealed = output(result);
		if (!sealed) throw new SecretStoreError("The Windows DPAPI store returned no ciphertext.");
		return sealed;
	};

	const unseal = (sealed: string): string => {
		const result = runner("powershell.exe", powershellArgs(DPAPI_UNPROTECT_SCRIPT), {
			input: sealed,
			timeout: 30_000,
		});
		if (result.error || result.status !== 0) {
			throw new SecretStoreError("The Windows DPAPI store could not decrypt the credential.", {
				cause: result.error,
			});
		}
		return Buffer.from(output(result), "base64").toString("utf8");
	};

	return {
		kind: "windows-dpapi",
		location: "os-vault",
		osProtected: true,
		isAvailable: () =>
			cachedAvailability(runner, "windows-dpapi", () => {
				// "Available" means a real protect/open round trip works, not that
				// powershell.exe happens to be on PATH.
				try {
					return unseal(seal(DPAPI_PROBE)) === DPAPI_PROBE;
				} catch {
					return false;
				}
			}),
		put: (id, secret) => {
			const path = pathFor(id);
			mkdirSync(directory, { recursive: true, mode: 0o700 });
			writeFileSync(path, seal(secret), { encoding: "utf8", mode: 0o600 });
		},
		get: (id) => {
			const path = pathFor(id);
			let sealed: string;
			try {
				sealed = readFileSync(path, "utf8");
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
				throw error;
			}
			return unseal(sealed);
		},
		revoke: (id) => {
			const path = pathFor(id);
			try {
				// `rmSync(..., { force: true })` was observed to report success while
				// leaving the blob in place inside the ACL-hardened AIDR directory on
				// Windows: a revoke that silently no-ops is worse than one that fails,
				// so the unlink is explicit and its errors propagate.
				unlinkSync(path);
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
				throw new SecretStoreError("The Windows DPAPI store could not delete the credential.", {
					cause: error,
				});
			}
		},
	};
}

// ---------------------------------------------------------------------------
// macOS — Keychain through `security(1)`
// ---------------------------------------------------------------------------

const KEYCHAIN_SERVICE = "singularity-aidr-cli";
const KEYCHAIN_NOT_FOUND = /could not be found|The specified item could not be found/i;

export interface MacosKeychainOptions {
	runner?: CommandRunner;
}

/**
 * macOS Keychain via `security add-generic-password` / `find-generic-password` /
 * `delete-generic-password`, keyed by service + account.
 *
 * `security add-generic-password` has no stdin path for the secret (`-w` without a
 * value reads from a TTY, which a piped child does not have), so the value is
 * passed as an argument and is briefly visible to same-user processes in the
 * process list. That limitation is the tool's, not this adapter's, and it is
 * recorded here rather than hidden: the credential still never touches
 * `config.json`, and `find`/`delete` do not take it on the command line.
 */
export function createMacosKeychainStore(options: MacosKeychainOptions = {}): SecretStore {
	const runner = options.runner ?? defaultCommandRunner;

	return {
		kind: "macos-keychain",
		location: "os-vault",
		osProtected: true,
		isAvailable: () =>
			cachedAvailability(runner, "macos-keychain", () => {
				const result = runner("security", ["list-keychains"], { timeout: 15_000 });
				return !result.error && result.status === 0;
			}),
		put: (id, secret) => {
			assertSafeId(id);
			const result = runner(
				"security",
				["add-generic-password", "-a", id, "-s", KEYCHAIN_SERVICE, "-w", secret, "-U"],
				{ timeout: 30_000 },
			);
			if (result.error || result.status !== 0) {
				throw new SecretStoreError("The macOS keychain could not store the credential.", {
					cause: result.error,
				});
			}
		},
		get: (id) => {
			assertSafeId(id);
			const result = runner(
				"security",
				["find-generic-password", "-a", id, "-s", KEYCHAIN_SERVICE, "-w"],
				{ timeout: 30_000 },
			);
			if (result.error) {
				throw new SecretStoreError("The macOS keychain could not be queried.", {
					cause: result.error,
				});
			}
			if (result.status !== 0) {
				if (KEYCHAIN_NOT_FOUND.test(result.stderr ?? "")) return null;
				throw new SecretStoreError("The macOS keychain could not be queried.");
			}
			// `security -w` prints the secret followed by a single newline.
			const secret = (result.stdout ?? "").replace(/\r?\n$/, "");
			return secret.length > 0 ? secret : null;
		},
		revoke: (id) => {
			assertSafeId(id);
			const result = runner(
				"security",
				["delete-generic-password", "-a", id, "-s", KEYCHAIN_SERVICE],
				{ timeout: 30_000 },
			);
			if (result.error) {
				throw new SecretStoreError("The macOS keychain could not be updated.", {
					cause: result.error,
				});
			}
			if (result.status !== 0 && !KEYCHAIN_NOT_FOUND.test(result.stderr ?? "")) {
				throw new SecretStoreError("The macOS keychain refused to delete the credential.");
			}
		},
	};
}

// ---------------------------------------------------------------------------
// Linux — Secret Service through `secret-tool(1)` (libsecret)
// ---------------------------------------------------------------------------

const SECRET_TOOL_SERVICE = "singularity-aidr-cli";
const SECRET_TOOL_UNAVAILABLE =
	/cannot autolaunch|d-?bus|failed to unlock|could not connect|connection refused|no such file or directory/i;
const SECRET_TOOL_ITEM_NOT_FOUND =
	/no such secret item|no matching secret item|secret item .*not found/i;

export interface LinuxSecretServiceOptions {
	runner?: CommandRunner;
}

function secretToolAttributes(id: string): string[] {
	return ["service", SECRET_TOOL_SERVICE, "id", id];
}

/**
 * Linux Secret Service via libsecret's `secret-tool`, keyed by attributes. The
 * secret itself travels on stdin, so it never appears in the process list.
 */
export function createLinuxSecretServiceStore(
	options: LinuxSecretServiceOptions = {},
): SecretStore {
	const runner = options.runner ?? defaultCommandRunner;

	return {
		kind: "linux-secret-service",
		location: "os-vault",
		osProtected: true,
		isAvailable: () =>
			cachedAvailability(runner, "linux-secret-service", () => {
				const result = runner(
					"secret-tool",
					["lookup", ...secretToolAttributes("availability-probe")],
					{ timeout: 15_000 },
				);
				if (result.error) return false;
				// Exit 0 (found) and 1 (not found) both mean the tool and the keyring
				// daemon answered. Anything else — or a daemon-failure message on
				// stderr — means there is no usable Secret Service here.
				if (result.status !== 0 && result.status !== 1) return false;
				return !SECRET_TOOL_UNAVAILABLE.test(result.stderr ?? "");
			}),
		put: (id, secret) => {
			assertSafeId(id);
			const result = runner(
				"secret-tool",
				["store", "--label", "Singularity AIDR CLI credential", ...secretToolAttributes(id)],
				{ input: secret, timeout: 30_000 },
			);
			if (result.error || result.status !== 0) {
				throw new SecretStoreError("The Linux Secret Service could not store the credential.", {
					cause: result.error,
				});
			}
		},
		get: (id) => {
			assertSafeId(id);
			const result = runner("secret-tool", ["lookup", ...secretToolAttributes(id)], {
				timeout: 30_000,
			});
			if (result.error) {
				throw new SecretStoreError("The Linux Secret Service could not be queried.", {
					cause: result.error,
				});
			}
			if (result.status !== 0) {
				if (SECRET_TOOL_ITEM_NOT_FOUND.test(result.stderr ?? "")) return null;
				throw new SecretStoreError("The Linux Secret Service could not be queried.");
			}
			const secret = (result.stdout ?? "").replace(/\r?\n$/, "");
			return secret.length > 0 ? secret : null;
		},
		revoke: (id) => {
			assertSafeId(id);
			const result = runner("secret-tool", ["clear", ...secretToolAttributes(id)], {
				timeout: 30_000,
			});
			if (result.error) {
				throw new SecretStoreError("The Linux Secret Service could not be updated.", {
					cause: result.error,
				});
			}
			if (result.status !== 0 && !SECRET_TOOL_ITEM_NOT_FOUND.test(result.stderr ?? "")) {
				throw new SecretStoreError("The Linux Secret Service refused to delete the credential.");
			}
		},
	};
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

export function isSecretStoreKind(value: string): value is SecretStoreKind {
	return (SECRET_STORE_KINDS as readonly string[]).includes(value);
}

/** Store kinds that keep the credential in a platform vault. */
export type PlatformSecretStoreKind = Exclude<SecretStoreKind, "file-acl">;

export function platformSecretStoreKind(
	platform: NodeJS.Platform = process.platform,
): PlatformSecretStoreKind {
	if (platform === "win32") return "windows-dpapi";
	if (platform === "darwin") return "macos-keychain";
	return "linux-secret-service";
}

export interface ResolveSecretStoreOptions {
	/** Explicit selection: `--secret-store` value or the recorded `secret_store`. */
	selection?: string;
	env?: NodeJS.ProcessEnv;
	platform?: NodeJS.Platform;
	runner?: CommandRunner;
	/** Override for the DPAPI blob directory (tests). */
	directory?: string;
}

function createStoreForKind(
	kind: Exclude<SecretStoreKind, "file-acl">,
	options: ResolveSecretStoreOptions,
): SecretStore {
	const runner = options.runner ?? defaultCommandRunner;
	if (kind === "windows-dpapi") {
		return createWindowsDpapiStore({ runner, directory: options.directory });
	}
	if (kind === "macos-keychain") return createMacosKeychainStore({ runner });
	return createLinuxSecretServiceStore({ runner });
}

/**
 * Select the store, or throw.
 *
 * Precedence: explicit `selection` → `AIDR_SECRET_STORE` → platform detection.
 * `file-acl` is returned only when it was named explicitly; when no vault answers
 * the probe this THROWS, so the caller fails closed instead of writing plaintext.
 */
export function resolveSecretStore(options: ResolveSecretStoreOptions = {}): SecretStore {
	const env = options.env ?? process.env;
	const platform = options.platform ?? process.platform;
	const selection = (options.selection ?? env[SECRET_STORE_ENV] ?? "").trim().toLowerCase();

	if (selection === "" || selection === SECRET_STORE_AUTO) {
		const kind = platformSecretStoreKind(platform);
		const store = createStoreForKind(kind, options);
		if (store.isAvailable()) return store;
		throw new SecretStoreUnavailableError(
			`No OS credential vault is available for the AIDR credential (probed ${kind}); ` +
				"refusing to write the credential to the local config file in plaintext. " +
				"Install a vault (Windows DPAPI, macOS Keychain, or libsecret's secret-tool), or " +
				`explicitly accept the reduced-protection file fallback with ${SECRET_STORE_ENV}=file-acl ` +
				"(or --secret-store file-acl).",
		);
	}

	if (!isSecretStoreKind(selection)) {
		throw new SecretStoreSelectionError(
			`Unknown secret store "${selection}". Expected one of: ${SECRET_STORE_KINDS.join(", ")}.`,
		);
	}

	if (selection === "file-acl") return createFileAclStore();

	const store = createStoreForKind(selection, options);
	if (!store.isAvailable()) {
		throw new SecretStoreUnavailableError(
			`The selected ${selection} secret store is not available on this host; ` +
				"refusing to fall back to a plaintext credential. Select a working store or " +
				`explicitly accept the file fallback with ${SECRET_STORE_ENV}=file-acl.`,
		);
	}
	return store;
}

/**
 * Fresh, filesystem/keychain-safe reference id.
 *
 * The reference is a handle, not the credential, but it is still drawn from a
 * CSPRNG so two installations cannot be correlated by a predictable name.
 */
export function createSecretReferenceId(): string {
	return `aidr-${randomBytes(16).toString("hex")}`;
}
