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
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import {
	closeSync,
	fstatSync,
	lstatSync,
	mkdirSync,
	openSync,
	readFileSync,
	renameSync,
	unlinkSync,
	writeFileSync,
	writeSync,
} from "node:fs";
import { join } from "node:path";
import { resolvePath } from "./config.js";

export type SecretStoreKind =
	| "windows-dpapi"
	| "macos-keychain"
	| "linux-secret-service"
	| "encrypted-file"
	| "file-acl";

export const SECRET_STORE_KINDS: readonly SecretStoreKind[] = [
	"windows-dpapi",
	"macos-keychain",
	"linux-secret-service",
	"encrypted-file",
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
 * - `encrypted-file` — the headless fallback ({@link createEncryptedFileStore}):
 *   the credential is AES-256-GCM encrypted in an owner-only file under a key
 *   bound to this machine; `config.json` only holds a reference. It is NOT an OS
 *   vault (`osProtected` is false), so callers that require one still refuse it.
 * - `config-file` — the `file-acl` fallback; the credential lives in the
 *   ACL-hardened config document, which the config manager writes directly. Its
 *   vault methods therefore refuse rather than pretend to isolate anything.
 */
export interface SecretStore {
	readonly kind: SecretStoreKind;
	readonly location: "os-vault" | "encrypted-file" | "config-file";
	/** True only for the platform vaults; false for both file-based fallbacks. */
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
const KEYCHAIN_EXECUTABLE = "/usr/bin/security";
const KEYCHAIN_STORAGE_VERSION = "aidr-utf8-base64-v1";
const KEYCHAIN_LABEL_PREFIX = "aidr-secret-v1-";
// Apple's interactive reader has a 4096-byte buffer. At 4095 command bytes it
// leaves the LF unread, executing a blank command and losing the failure status.
const KEYCHAIN_MAX_COMMAND_BYTES = 4094;
const KEYCHAIN_NOT_FOUND = /could not be found|The specified item could not be found/i;

function keychainPutCommand(id: string, encoded: string): string {
	return `add-generic-password -a ${id} -s ${KEYCHAIN_SERVICE} -l ${KEYCHAIN_LABEL_PREFIX}${id} -G ${KEYCHAIN_STORAGE_VERSION} -w ${encoded} -U`;
}

function keychainItemAbsent(result: CommandResult): boolean {
	return !result.error && result.status === 44 && KEYCHAIN_NOT_FOUND.test(result.stderr ?? "");
}

function decodeKeychainSecret(id: string, output: string): string {
	const encoded = output.replace(/\n$/, "");
	if (
		encoded.length === 0 ||
		keychainPutCommand(id, encoded).length > KEYCHAIN_MAX_COMMAND_BYTES ||
		!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)
	) {
		throw new SecretStoreError("The macOS keychain credential has an invalid storage format.");
	}
	const bytes = Buffer.from(encoded, "base64");
	const secret = bytes.toString("utf8");
	if (bytes.toString("base64") !== encoded || !Buffer.from(secret, "utf8").equals(bytes)) {
		throw new SecretStoreError("The macOS keychain credential has an invalid storage format.");
	}
	return secret;
}

export interface MacosKeychainOptions {
	runner?: CommandRunner;
}

/**
 * macOS Keychain via `security add-generic-password` / `find-generic-password` /
 * `delete-generic-password`, keyed by service + account.
 *
 * Writes use one ASCII command on `security -q -i` stdin, with a marked base64
 * payload to preserve UTF-8 and control characters. No secret is in process argv.
 * The complete command is limited to 4094 bytes before LF; the secret ceiling
 * depends on the reference ID length (documented in the secrets runbook).
 * Existing unmarked ASCII credentials retain their original read/delete identity.
 */
export function createMacosKeychainStore(options: MacosKeychainOptions = {}): SecretStore {
	const runner = options.runner ?? defaultCommandRunner;
	const run = (args: string[], request: CommandRequest): CommandResult => {
		try {
			return runner(KEYCHAIN_EXECUTABLE, args, request);
		} catch {
			// Native exceptions and output can contain secret material. Never attach
			// them as error causes or return them to callers.
			return { status: null };
		}
	};
	const getMarked = (id: string): string | null => {
		// With both account and service, Apple's finder ignores all other
		// attributes. The unique versioned label makes -G an exact filter.
		const result = run(
			[
				"find-generic-password",
				"-s",
				KEYCHAIN_SERVICE,
				"-l",
				`${KEYCHAIN_LABEL_PREFIX}${id}`,
				"-G",
				KEYCHAIN_STORAGE_VERSION,
				"-w",
			],
			{ timeout: 30_000 },
		);
		if (!result.error && result.status === 0) return decodeKeychainSecret(id, result.stdout ?? "");
		if (keychainItemAbsent(result)) return null;
		throw new SecretStoreError("The macOS keychain could not be queried.");
	};

	return {
		kind: "macos-keychain",
		location: "os-vault",
		osProtected: true,
		isAvailable: () =>
			cachedAvailability(runner, "macos-keychain", () => {
				const result = run(["list-keychains"], { timeout: 15_000 });
				return !result.error && result.status === 0;
			}),
		put: (id, secret) => {
			assertSafeId(id);
			if (
				typeof secret !== "string" ||
				secret.length === 0 ||
				Buffer.byteLength(secret, "utf8") > 3072
			) {
				throw new SecretStoreError(
					"The macOS keychain credential is empty or exceeds its input limit.",
				);
			}
			const bytes = Buffer.from(secret, "utf8");
			if (bytes.toString("utf8") !== secret) {
				throw new SecretStoreError("The macOS keychain credential is not valid UTF-8.");
			}
			const command = keychainPutCommand(id, bytes.toString("base64"));
			if (command.length > KEYCHAIN_MAX_COMMAND_BYTES) {
				throw new SecretStoreError("The macOS keychain credential exceeds its input limit.");
			}
			// Exactly one command + LF + EOF: an extra blank/exit command would hide
			// the write's native exit status. Every token is restricted to ASCII.
			const result = run(["-q", "-i"], { input: `${command}\n`, timeout: 30_000 });
			if (result.error || result.status !== 0) {
				throw new SecretStoreError("The macOS keychain could not store the credential.");
			}
		},
		get: (id) => {
			assertSafeId(id);
			const marked = getMarked(id);
			if (marked !== null) return marked;
			const result = run(["find-generic-password", "-a", id, "-s", KEYCHAIN_SERVICE, "-w"], {
				timeout: 30_000,
			});
			if (result.error) throw new SecretStoreError("The macOS keychain could not be queried.");
			if (result.status !== 0) {
				if (keychainItemAbsent(result)) return null;
				throw new SecretStoreError("The macOS keychain could not be queried.");
			}
			// A concurrent update can migrate the item between the two lookups.
			// Recheck before treating the fallback's payload as unmarked plaintext.
			const migrated = getMarked(id);
			if (migrated !== null) return migrated;
			// `security -w` prints the secret followed by a single newline.
			const secret = (result.stdout ?? "").replace(/\r?\n$/, "");
			return secret.length > 0 ? secret : null;
		},
		revoke: (id) => {
			assertSafeId(id);
			const result = run(["delete-generic-password", "-a", id, "-s", KEYCHAIN_SERVICE], {
				timeout: 30_000,
			});
			if (result.error) {
				throw new SecretStoreError("The macOS keychain could not be updated.");
			}
			if (result.status !== 0 && !keychainItemAbsent(result)) {
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
// Headless fallback — machine-bound, AES-256-GCM encrypted owner-only files
// ---------------------------------------------------------------------------

/** Files that may hold this host's machine identifier, most authoritative first. */
const MACHINE_ID_PATHS = ["/etc/machine-id", "/var/lib/dbus/machine-id"];
const SEALED_FILE_VERSION = 1;
const SEALED_FILE_DOMAIN = "singularity-aidr/encrypted-file-store/v1";
const SEALED_FILE_SUFFIX = ".sealed.json";
const SALT_FILE = "store.salt";

export interface EncryptedFileStoreOptions {
	/** Where sealed files live; defaults to `~/.singularity-aidr/sealed`. */
	directory?: string;
	/**
	 * The machine-bound secret (tests). Defaults to the host's machine id
	 * (`/etc/machine-id`, then `/var/lib/dbus/machine-id`); `null` means the
	 * host has none (for example a minimal container image).
	 */
	machineId?: string | null;
	/** Numeric user id mixed into the key (tests); defaults to the current user. */
	uid?: number;
}

/** The host's machine identifier, or null when it has none. */
export function readMachineId(paths: readonly string[] = MACHINE_ID_PATHS): string | null {
	for (const path of paths) {
		try {
			const value = readFileSync(path, "utf8").trim();
			if (/^[A-Za-z0-9-]{16,128}$/.test(value)) return value;
		} catch {
			// Absent or unreadable: try the next candidate.
		}
	}
	return null;
}

function sealedFileError(message: string, cause?: unknown): SecretStoreError {
	return new SecretStoreError(`The encrypted file store ${message}`, { cause });
}

/** True for an owner-only regular file, false when absent; throws for anything else. */
function privateRegularFile(path: string): boolean {
	let info: ReturnType<typeof lstatSync>;
	try {
		info = lstatSync(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
		throw sealedFileError("could not inspect its file.", error);
	}
	if (info.isSymbolicLink() || !info.isFile()) {
		throw sealedFileError(`refuses ${path}: it is not a regular file.`);
	}
	if (process.platform !== "win32") {
		if (process.getuid && info.uid !== process.getuid()) {
			throw sealedFileError(`refuses ${path}: it is not owned by the current user.`);
		}
		if ((info.mode & 0o077) !== 0) {
			throw sealedFileError(`refuses ${path}: it is accessible to other users.`);
		}
	}
	return true;
}

function ensurePrivateDirectory(directory: string): void {
	mkdirSync(directory, { recursive: true, mode: 0o700 });
	const info = lstatSync(directory);
	if (info.isSymbolicLink() || !info.isDirectory()) {
		throw sealedFileError(`refuses ${directory}: it is not a regular directory.`);
	}
	if (process.platform !== "win32" && process.getuid && info.uid !== process.getuid()) {
		throw sealedFileError(`refuses ${directory}: it is not owned by the current user.`);
	}
}

/** Owner-only write through an exclusive temporary file and an atomic rename. */
function writePrivateAtomic(path: string, content: string, exclusive = false): void {
	if (exclusive) {
		const fd = openSync(path, "wx", 0o600);
		try {
			writeSync(fd, content);
		} finally {
			closeSync(fd);
		}
		return;
	}
	const temporary = `${path}.${randomBytes(6).toString("hex")}.tmp`;
	const fd = openSync(temporary, "wx", 0o600);
	try {
		if (process.platform !== "win32" && (fstatSync(fd).mode & 0o077) !== 0) {
			throw sealedFileError("could not create an owner-only file.");
		}
		writeSync(fd, content);
		closeSync(fd);
		renameSync(temporary, path);
	} catch (error) {
		try {
			closeSync(fd);
		} catch {
			/* Already closed. */
		}
		try {
			unlinkSync(temporary);
		} catch {
			/* Nothing left behind, or not removable; the error below is what matters. */
		}
		throw error;
	}
}

/**
 * A store for hosts with no OS credential vault: see {@link createEncryptedFileStore}.
 */
export interface EncryptedFileStore extends SecretStore {
	readonly kind: "encrypted-file";
	readonly location: "encrypted-file";
	/** False when the host has no machine id, so the files are not bound to this machine. */
	readonly machineBound: boolean;
	readonly directory: string;
}

/**
 * The fallback for hosts with no OS credential vault (headless Linux servers,
 * WSL without a keyring, containers, CI runners).
 *
 * Each secret is AES-256-GCM encrypted in its own owner-only (`0600`) file under
 * an owner-only (`0700`) directory. The per-secret key is
 * HKDF-SHA256(machine id, per-install random salt, domain ‖ uid ‖ secret id), and
 * the secret id is bound as additional authenticated data, so:
 *
 * - nothing is ever written in plaintext: a backup, a support bundle, a synced
 *   folder or a copy on another machine (different machine id) yields nothing;
 * - a file that was edited, swapped between ids or truncated fails
 *   authentication and is refused — never returned as a secret.
 *
 * Its limit is the same one libsecret has on Linux: any process running as the
 * same user on the same machine can read the machine id and the salt, and so the
 * secret. It is therefore not presented as an OS vault (`osProtected: false`).
 * On a host with no machine id the key is derived from the salt alone;
 * {@link EncryptedFileStore.machineBound} is then false and `aidr doctor` says so.
 */
export function createEncryptedFileStore(
	options: EncryptedFileStoreOptions = {},
): EncryptedFileStore {
	const directory = options.directory ?? resolvePath("~/.singularity-aidr/sealed");
	const machineId = options.machineId === undefined ? readMachineId() : options.machineId;
	const uid = options.uid ?? (process.getuid ? process.getuid() : 0);
	const pathFor = (id: string): string => {
		assertSafeId(id);
		return join(directory, `${id}${SEALED_FILE_SUFFIX}`);
	};

	const readSalt = (create: boolean): Buffer | null => {
		const path = join(directory, SALT_FILE);
		if (privateRegularFile(path)) {
			const value = Buffer.from(readFileSync(path, "utf8").trim(), "hex");
			if (value.length !== 32) throw sealedFileError("salt is corrupt; refusing to derive a key.");
			return value;
		}
		if (!create) return null;
		ensurePrivateDirectory(directory);
		const fresh = randomBytes(32);
		try {
			writePrivateAtomic(path, `${fresh.toString("hex")}\n`, true);
			return fresh;
		} catch (error) {
			// Another process created it first: use theirs.
			if ((error as NodeJS.ErrnoException).code === "EEXIST") return readSalt(false);
			throw error;
		}
	};

	const keyFor = (id: string, salt: Buffer): Buffer =>
		Buffer.from(
			hkdfSync(
				"sha256",
				Buffer.from(machineId ?? "", "utf8"),
				salt,
				Buffer.from(`${SEALED_FILE_DOMAIN}\nuid=${uid}\nid=${id}`, "utf8"),
				32,
			),
		);

	return {
		kind: "encrypted-file",
		location: "encrypted-file",
		osProtected: false,
		machineBound: machineId !== null,
		directory,
		isAvailable: () => true,
		put: (id, secret) => {
			const path = pathFor(id);
			const salt = readSalt(true) as Buffer;
			privateRegularFile(path); // refuses a planted link or a foreign file
			const iv = randomBytes(12);
			const cipher = createCipheriv("aes-256-gcm", keyFor(id, salt), iv);
			cipher.setAAD(Buffer.from(id, "utf8"));
			const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
			const document = {
				version: SEALED_FILE_VERSION,
				alg: "A256GCM",
				kdf: "HKDF-SHA256",
				machine_bound: machineId !== null,
				iv: iv.toString("base64"),
				tag: cipher.getAuthTag().toString("base64"),
				ciphertext: ciphertext.toString("base64"),
			};
			writePrivateAtomic(path, `${JSON.stringify(document)}\n`);
		},
		get: (id) => {
			const path = pathFor(id);
			if (!privateRegularFile(path)) return null;
			const salt = readSalt(false);
			if (!salt) throw sealedFileError("salt is missing; the sealed secret cannot be opened.");
			let document: Record<string, unknown>;
			try {
				document = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
			} catch (error) {
				throw sealedFileError("holds an unreadable sealed file.", error);
			}
			if (
				document?.version !== SEALED_FILE_VERSION ||
				document.alg !== "A256GCM" ||
				typeof document.iv !== "string" ||
				typeof document.tag !== "string" ||
				typeof document.ciphertext !== "string"
			) {
				throw sealedFileError("holds a sealed file in an unknown format.");
			}
			try {
				const decipher = createDecipheriv(
					"aes-256-gcm",
					keyFor(id, salt),
					Buffer.from(document.iv, "base64"),
				);
				decipher.setAAD(Buffer.from(id, "utf8"));
				decipher.setAuthTag(Buffer.from(document.tag, "base64"));
				return Buffer.concat([
					decipher.update(Buffer.from(document.ciphertext, "base64")),
					decipher.final(),
				]).toString("utf8");
			} catch (error) {
				// Another machine or user, a swapped or edited file: never a secret.
				throw sealedFileError(
					"could not authenticate a sealed secret (edited, or sealed on another machine, user or salt).",
					error,
				);
			}
		},
		revoke: (id) => {
			const path = pathFor(id);
			try {
				unlinkSync(path);
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
				throw sealedFileError("could not delete the sealed secret.", error);
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
export type PlatformSecretStoreKind = Exclude<SecretStoreKind, "file-acl" | "encrypted-file">;

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
	/** Override for the encrypted-file store directory (tests). */
	encryptedFileDirectory?: string;
	/** Machine id for the encrypted-file store (tests); see {@link EncryptedFileStoreOptions}. */
	machineId?: string | null;
}

function encryptedFileOptions(options: ResolveSecretStoreOptions): EncryptedFileStoreOptions {
	return {
		...(options.encryptedFileDirectory ? { directory: options.encryptedFileDirectory } : {}),
		...(options.machineId !== undefined ? { machineId: options.machineId } : {}),
	};
}

function createStoreForKind(
	kind: PlatformSecretStoreKind,
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
	if (selection === "encrypted-file")
		return createEncryptedFileStore(encryptedFileOptions(options));

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
 * The store for a credential that IS needed: the platform vault when one answers,
 * otherwise — on a host with no vault, and only when nothing was selected
 * explicitly — the machine-bound {@link createEncryptedFileStore}, never a
 * plaintext file. An explicit selection (including a vault that is not
 * available) behaves exactly like {@link resolveSecretStore}.
 *
 * Callers that require an OS vault (`osProtected`) must keep using
 * {@link resolveSecretStore}; this is for credentials whose only alternative on
 * a headless host would otherwise be a plaintext file or no credential at all.
 */
export function resolveCredentialStore(options: ResolveSecretStoreOptions = {}): SecretStore {
	const env = options.env ?? process.env;
	const selection = (options.selection ?? env[SECRET_STORE_ENV] ?? "").trim().toLowerCase();
	try {
		return resolveSecretStore(options);
	} catch (error) {
		const automatic = selection === "" || selection === SECRET_STORE_AUTO;
		if (!(error instanceof SecretStoreUnavailableError) || !automatic) throw error;
		return createEncryptedFileStore(encryptedFileOptions(options));
	}
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
