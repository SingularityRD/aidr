import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
	closeSync,
	constants,
	fchmodSync,
	fstatSync,
	fsyncSync,
	lstatSync,
	mkdirSync,
	openSync,
	readFileSync,
	renameSync,
	type Stats,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { isCommercialBuild, resolvePath, VERSION } from "@singularityrd/aidr-core";
import { generateApiKey } from "./crypto.js";
import {
	type CommandRunner,
	createFileAclStore,
	createSecretReferenceId,
	isSecretStoreKind,
	resolveCredentialStore,
	resolveSecretStore,
	type SecretStore,
	type SecretStoreKind,
} from "./secret-store.js";

const CONFIG_DIR = resolvePath("~/.singularity-aidr");
const CONFIG_FILE = join(CONFIG_DIR, "config.json");
const IS_POSIX = process.platform !== "win32";
const NO_FOLLOW = IS_POSIX ? constants.O_NOFOLLOW : 0;
const WINDOWS_PRIVATE_ACL = `
$ErrorActionPreference = 'Stop'
$path = [Environment]::GetEnvironmentVariable('AIDR_PRIVATE_ACL_PATH')
$directory = [Environment]::GetEnvironmentVariable('AIDR_PRIVATE_ACL_DIRECTORY') -eq '1'
$item = if ($directory) { [System.IO.DirectoryInfo]::new($path) } else { [System.IO.FileInfo]::new($path) }
$acl = $item.GetAccessControl()
$owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administrators = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$acl.SetAccessRuleProtection($true, $false)
foreach ($entry in @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) {
  $acl.PurgeAccessRules($entry.IdentityReference)
}
$inheritance = if ($directory) {
  [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
} else {
  [System.Security.AccessControl.InheritanceFlags]::None
}
foreach ($sid in @($owner, $system, $administrators)) {
  $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    $inheritance,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
  $acl.AddAccessRule($rule)
}
$item.SetAccessControl($acl)
$updated = $item.GetAccessControl()
if (-not $updated.AreAccessRulesProtected) { throw 'ACL inheritance remains enabled' }
foreach ($entry in $updated.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
  if ($entry.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
      $entry.IdentityReference.Value -notin @($owner.Value, $system.Value, $administrators.Value)) {
    throw 'ACL grants another identity access'
  }
}
`;

export interface Environment {
	/** The first host with AIDR registered, else the first host found, else "unknown". */
	agent: "claude" | "cursor" | "vscode" | "openclaw" | "opencode" | "codex" | "unknown";
	/** Every agent host found in the user's home (the same measurement as `aidr status`). */
	detectedHosts?: Array<"claude-code" | "cursor" | "vscode" | "openclaw" | "opencode" | "codex">;
	hasNode: boolean;
	nodeVersion: string;
	/**
	 * Legacy: the directory setup happened to run in. No longer written — a global
	 * config must not depend on the caller's working directory (PRD-4, PRD-14).
	 */
	projectRoot?: string;
}

export interface Config {
	apiKey: string;
	environment: Environment;
	version: string;
	createdAt: string;
	hooksInstalled: boolean;
	agentConfigured: boolean;
	/**
	 * Which store protects the credential. The file fallback is recorded
	 * explicitly so an operator can see that reduced protection is in use; an
	 * absent value means a config written before the store existed (plaintext).
	 */
	secretStore?: SecretStoreKind;
	/** Present when the credential lives in an OS vault; `apiKey` is then resolved. */
	secretRef?: SecretReference;
	/** ISO timestamp of the last rotation that committed. */
	secretRotatedAt?: string;
	/** ISO timestamp of the last revocation. */
	secretRevokedAt?: string;
	auth?: {
		api_key?: string;
		enrollment_token?: string;
		api_key_ref?: SecretReference;
		enrollment_token_ref?: SecretReference;
	};
}

/**
 * A handle to a credential held by a {@link SecretStore}. It is stored in
 * `config.json` as `secret_ref` and is not itself a credential.
 */
export interface SecretReference {
	store: SecretStoreKind;
	id: string;
	created_at: string;
}

export interface ConfigCreationResult {
	path: string;
	/** "created" wrote a new config; "reused" kept the existing one. */
	outcome: "created" | "reused";
	/**
	 * Where the CLI credential went. `none` in local mode: nothing reads one
	 * there, so setup neither mints nor stores a credential and needs no vault.
	 */
	credential?: "none" | SecretStoreKind;
	/** Set when the new credential committed but the previous one could not be revoked. */
	warning?: string;
}

export interface ConfigManagerOptions {
	/**
	 * Injected store (tests, programmatic callers). Takes precedence over any
	 * selection string and is reused for reads of a matching reference.
	 */
	secretStore?: SecretStore;
	/** Explicit `--secret-store` selection; falls back to `AIDR_SECRET_STORE`, then detection. */
	secretStoreSelection?: string;
	/** Injected command runner for the platform backends (tests). */
	secretStoreRunner?: CommandRunner;
}

export interface SecretRotationResult {
	path: string;
	/** Store the new credential was written to. */
	store: SecretStoreKind;
	rotated: true;
	/** Reference of the new credential; null for the file fallback. */
	ref: SecretReference | null;
	/** Reference that was revoked after the new credential committed. */
	previousRef: SecretReference | null;
	rotatedAt: string;
	/** Set when the previous credential could not be revoked after the commit. */
	warning?: string;
}

export interface SecretRevocationResult {
	path: string;
	store: SecretStoreKind;
	/** Reference that was revoked; null for the file fallback. */
	revokedRef: SecretReference | null;
	revokedAt: string;
}

function lstatIfPresent(path: string): Stats | null {
	try {
		return lstatSync(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
		throw error;
	}
}

function sameFile(a: Stats, b: Stats): boolean {
	return a.dev === b.dev && a.ino === b.ino;
}

function assertOwner(stats: Stats): void {
	if (IS_POSIX && process.getuid && stats.uid !== process.getuid()) {
		throw new Error("Local config is not owned by the current user.");
	}
}

function hardenWindowsAcl(path: string, before: Stats, directory: boolean): Stats {
	const result = spawnSync(
		"powershell.exe",
		[
			"-NoProfile",
			"-NonInteractive",
			"-EncodedCommand",
			Buffer.from(WINDOWS_PRIVATE_ACL, "utf16le").toString("base64"),
		],
		{
			env: {
				...process.env,
				AIDR_PRIVATE_ACL_PATH: path,
				AIDR_PRIVATE_ACL_DIRECTORY: directory ? "1" : "0",
			},
			encoding: "utf8",
			timeout: 30_000,
			windowsHide: true,
		},
	);
	if (result.error || result.status !== 0) {
		throw new Error("Local config Windows ACL could not be made private.");
	}
	const after = lstatIfPresent(path);
	if (
		!after ||
		after.isSymbolicLink() ||
		!sameFile(before, after) ||
		directory !== after.isDirectory()
	) {
		throw new Error("Local config changed during Windows ACL update.");
	}
	return after;
}

function ensureConfigDirectory(create: boolean): Stats | null {
	let before = lstatIfPresent(CONFIG_DIR);
	if (!before && create) {
		createConfigDirectory();
		before = lstatIfPresent(CONFIG_DIR);
	}
	if (!before) return null;
	if (before.isSymbolicLink() || !before.isDirectory()) {
		throw new Error("Local config directory is not a regular directory.");
	}
	assertOwner(before);
	if (IS_POSIX) return hardenPosixDirectory(before);
	return create ? hardenWindowsAcl(CONFIG_DIR, before, true) : before;
}

function createConfigDirectory(): void {
	try {
		mkdirSync(CONFIG_DIR, { mode: 0o700 });
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
	}
}

function hardenPosixDirectory(before: Stats): Stats {
	// Use a descriptor for permission repair so chmod cannot follow a swapped link.
	const fd = openSync(CONFIG_DIR, constants.O_RDONLY | constants.O_DIRECTORY | NO_FOLLOW);
	try {
		let opened = fstatSync(fd);
		if (!opened.isDirectory() || !sameFile(before, opened)) {
			throw new Error("Local config directory changed during access.");
		}
		assertOwner(opened);
		if ((opened.mode & 0o077) !== 0) fchmodSync(fd, 0o700);
		opened = fstatSync(fd);
		if ((opened.mode & 0o077) !== 0) {
			throw new Error("Local config directory permissions are unsafe.");
		}
		const after = lstatIfPresent(CONFIG_DIR);
		if (!after || after.isSymbolicLink() || !sameFile(after, opened)) {
			throw new Error("Local config directory changed during access.");
		}
		return opened;
	} finally {
		closeSync(fd);
	}
}

/**
 * Wire form of the config document.
 *
 * The credential is written as a `secret_ref` handle when a vault protects it, and
 * inline as `apiKey` only for the explicitly selected `file-acl` fallback. TS
 * fields are camelCase and the stored document is snake_case at this boundary, the
 * same convention the rest of the CLI uses for `auth.api_key` and friends.
 */
function toStoredConfig(config: Config): Record<string, unknown> {
	const { apiKey, secretRef, secretStore, secretRotatedAt, secretRevokedAt, ...rest } = config;
	const stored: Record<string, unknown> = { ...rest };
	if (secretStore !== undefined) stored.secret_store = secretStore;
	if (secretRotatedAt !== undefined) stored.secret_rotated_at = secretRotatedAt;
	if (secretRevokedAt !== undefined) stored.secret_revoked_at = secretRevokedAt;
	const reference = secretRef && secretRef.store !== "file-acl" ? secretRef : null;
	if (reference) {
		stored.secret_ref = {
			store: reference.store,
			id: reference.id,
			created_at: reference.created_at,
		};
	} else if (apiKey) {
		stored.apiKey = apiKey;
	}
	return stored;
}

function serializeConfig(config: Config): string {
	try {
		return JSON.stringify(toStoredConfig(config), null, 2);
	} catch {
		throw new Error("Local config cannot be serialized.");
	}
}

function parseSecretReference(document: Record<string, unknown>): SecretReference | null {
	const raw = document.secret_ref;
	if (raw === undefined || raw === null) return null;
	if (typeof raw !== "object" || Array.isArray(raw)) throw new Error("Local config is invalid.");
	const { store, id, created_at } = raw as Record<string, unknown>;
	if (
		typeof store !== "string" ||
		!isSecretStoreKind(store) ||
		// The file fallback keeps the credential inline; a reference to it would
		// be a config that claims isolation it does not have.
		store === "file-acl" ||
		typeof id !== "string" ||
		id.length === 0 ||
		typeof created_at !== "string"
	) {
		throw new Error("Local config is invalid.");
	}
	return { store, id, created_at };
}

function toConfig(
	document: Record<string, unknown>,
	apiKey: string,
	reference: SecretReference | null,
): Config {
	const rest: Record<string, unknown> = { ...document };
	const rotatedAt = rest.secret_rotated_at;
	const revokedAt = rest.secret_revoked_at;
	const declaredStore = rest.secret_store;
	delete rest.secret_ref;
	delete rest.secret_store;
	delete rest.secret_rotated_at;
	delete rest.secret_revoked_at;

	const config = { ...rest, apiKey } as unknown as Config;
	if (reference) config.secretRef = reference;
	if (typeof declaredStore === "string" && isSecretStoreKind(declaredStore)) {
		config.secretStore = declaredStore;
	}
	if (typeof rotatedAt === "string") config.secretRotatedAt = rotatedAt;
	if (typeof revokedAt === "string") config.secretRevokedAt = revokedAt;
	return config;
}

/**
 * Resolve the vault for a reference.
 *
 * An injected store is reused only when it is the store the reference names, so a
 * test double can never be substituted for a different backend by accident.
 */
function storeForReference(reference: SecretReference, options: ConfigManagerOptions): SecretStore {
	if (options.secretStore && options.secretStore.kind === reference.store) {
		return options.secretStore;
	}
	return resolveSecretStore({
		selection: reference.store,
		runner: options.secretStoreRunner,
	});
}

function readVaultSecret(reference: SecretReference, options: ConfigManagerOptions): string {
	let secret: string | null = null;
	try {
		secret = storeForReference(reference, options).get(reference.id);
	} catch (error) {
		// Never surface the backend's own message here: it can echo a command line.
		throw new Error(
			`The local credential could not be read from the ${reference.store} secret store.`,
			{ cause: error },
		);
	}
	if (secret === null || secret === "") {
		throw new Error(
			`The local credential is missing from the ${reference.store} secret store. ` +
				"Run 'aidr config rotate-key' to mint a new one.",
		);
	}
	return secret;
}

function mayReplaceConfig(directory: Stats, expected: Stats | null): boolean {
	const currentDirectory = ensureConfigDirectory(false);
	if (!currentDirectory || !sameFile(directory, currentDirectory)) {
		throw new Error("Local config directory changed during update.");
	}
	const current = openConfigFile();
	const currentStats = current?.stats ?? null;
	if (current) closeSync(current.fd);
	if (!expected && currentStats) return false;
	if (expected && (!currentStats || !sameFile(expected, currentStats))) {
		throw new Error("Local config changed during update.");
	}
	return true;
}

function discardTemporary(path: string): void {
	try {
		unlinkSync(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
	}
}

function openConfigFile(): { fd: number; stats: Stats } | null {
	const before = lstatIfPresent(CONFIG_FILE);
	if (!before) return null;
	if (before.isSymbolicLink() || !before.isFile() || before.nlink !== 1) {
		throw new Error("Local config is not a regular private file.");
	}
	assertOwner(before);
	const fd = openSync(CONFIG_FILE, constants.O_RDONLY | constants.O_NONBLOCK | NO_FOLLOW);
	try {
		let opened = fstatSync(fd);
		if (!opened.isFile() || opened.nlink !== 1 || !sameFile(before, opened)) {
			throw new Error("Local config changed during access.");
		}
		assertOwner(opened);
		if (IS_POSIX && (opened.mode & 0o077) !== 0) fchmodSync(fd, 0o600);
		opened = fstatSync(fd);
		if (IS_POSIX && (opened.mode & 0o077) !== 0) {
			throw new Error("Local config permissions are unsafe.");
		}
		const after = lstatIfPresent(CONFIG_FILE);
		if (!after || after.isSymbolicLink() || !sameFile(after, opened)) {
			throw new Error("Local config changed during access.");
		}
		return { fd, stats: opened };
	} catch (error) {
		closeSync(fd);
		throw error;
	}
}

/**
 * Parse an open config file.
 *
 * With `resolve` the credential is fetched through its store, so every consumer of
 * `getConfig()` sees the same `apiKey` shape it always did while the document on
 * disk only holds a reference. Mutation paths pass `resolve: false`: recovering a
 * config whose vault entry has disappeared must not require the secret that is
 * missing, and minting a replacement is exactly how that is repaired.
 */
function parseConfigDocument(
	fd: number,
	stats: Stats,
	options: ConfigManagerOptions,
	resolve: boolean,
): { config: Config; stats: Stats } {
	let parsed: unknown;
	try {
		parsed = JSON.parse(readFileSync(fd, "utf8"));
	} catch {
		// JSON.parse errors can include source snippets containing credentials.
		throw new Error("Local config is invalid.");
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw new Error("Local config is invalid.");
	}
	const document = parsed as Record<string, unknown>;
	const reference = parseSecretReference(document);
	let apiKey = "";
	if (reference) {
		if (resolve) apiKey = readVaultSecret(reference, options);
	} else if (typeof document.apiKey === "string") {
		apiKey = document.apiKey;
	}
	const config = toConfig(document, apiKey, reference);
	if (resolve && config.auth && typeof config.auth === "object") {
		for (const field of ["api_key", "enrollment_token"] as const) {
			const ref = parseSecretReference({ secret_ref: config.auth[`${field}_ref`] });
			if (ref) config.auth[field] = readVaultSecret(ref, options);
		}
	}
	return { config, stats };
}

function readConfig(options: ConfigManagerOptions = {}): { config: Config; stats: Stats } | null {
	if (!ensureConfigDirectory(false)) return null;
	const opened = openConfigFile();
	if (!opened) return null;
	try {
		return parseConfigDocument(opened.fd, opened.stats, options, true);
	} finally {
		closeSync(opened.fd);
	}
}

/** Read for mutation/rotation: never resolves the credential itself. */
function readConfigForMutation(
	options: ConfigManagerOptions = {},
): { config: Config; stats: Stats } | null {
	if (!ensureConfigDirectory(false)) return null;
	const opened = openConfigFile();
	if (!opened) return null;
	try {
		return parseConfigDocument(opened.fd, opened.stats, options, false);
	} finally {
		closeSync(opened.fd);
	}
}

function prepareCommercialAuth(
	config: Config,
	options: ConfigManagerOptions,
): {
	config: Config;
	created: Array<{ store: SecretStore; ref: SecretReference }>;
	replaced: SecretReference[];
} {
	if (!isCommercialBuild() || !config.auth) return { config, created: [], replaced: [] };
	const auth = { ...config.auth };
	const created: Array<{ store: SecretStore; ref: SecretReference }> = [];
	const replaced: SecretReference[] = [];
	try {
		for (const field of ["api_key", "enrollment_token"] as const) {
			const refField = `${field}_ref` as const;
			const old = parseSecretReference({ secret_ref: auth[refField] });
			const value = auth[field];
			if (typeof value !== "string") continue;
			if (value === "") {
				if (old) replaced.push(old);
				delete auth[refField];
				delete auth[field];
				continue;
			}
			if (old && readVaultSecret(old, options) === value) {
				delete auth[field];
				continue;
			}
			const store = selectStore(options);
			if (store.location !== "os-vault")
				throw new Error("Managed auth requires an OS credential vault.");
			const ref: SecretReference = {
				store: store.kind,
				id: createSecretReferenceId(),
				created_at: new Date().toISOString(),
			};
			store.put(ref.id, value);
			created.push({ store, ref });
			if (old) replaced.push(old);
			auth[refField] = ref;
			delete auth[field];
		}
	} catch (error) {
		for (const { store, ref } of created) {
			try {
				store.revoke(ref.id);
			} catch {
				/* Unreferenced vault entry only. */
			}
		}
		throw error;
	}
	return { config: { ...config, auth }, created, replaced };
}

function writeConfigAtomically(
	config: Config,
	expected: Stats | null,
	securedDirectory?: Stats,
	options: ConfigManagerOptions = {},
): boolean {
	const directory = securedDirectory ?? ensureConfigDirectory(true);
	if (!directory) throw new Error("Local config directory is unavailable.");
	const prepared = prepareCommercialAuth(config, options);
	const temporary = join(CONFIG_DIR, `.config-${randomBytes(16).toString("hex")}.tmp`);
	let fd: number | null = null;
	let committed = false;
	try {
		const serialized = serializeConfig(prepared.config);
		fd = openSync(
			temporary,
			constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW,
			0o600,
		);
		const created = fstatSync(fd);
		assertOwner(created);
		if (!created.isFile() || created.nlink !== 1 || (IS_POSIX && (created.mode & 0o077) !== 0)) {
			throw new Error("Local config temporary file is unsafe.");
		}
		writeFileSync(fd, serialized, "utf8");
		fsyncSync(fd);
		closeSync(fd);
		fd = null;

		if (!mayReplaceConfig(directory, expected)) return false;
		renameSync(temporary, CONFIG_FILE);
		committed = true;
		for (const old of prepared.replaced) {
			try {
				storeForReference(old, options).revoke(old.id);
			} catch {
				/* Old reference is no longer reachable from config. */
			}
		}
		return true;
	} finally {
		if (fd !== null) closeSync(fd);
		discardTemporary(temporary);
		if (!committed) {
			for (const { store, ref } of prepared.created) {
				try {
					store.revoke(ref.id);
				} catch {
					/* Unreferenced vault entry only. */
				}
			}
		}
	}
}

/**
 * The store for a credential that is actually needed: the OS vault, or — on a
 * host with none and no explicit selection — the machine-bound encrypted file
 * store, never a plaintext config entry unless `file-acl` was chosen explicitly.
 */
function selectStore(options: ConfigManagerOptions): SecretStore {
	if (options.secretStore) return options.secretStore;
	return resolveCredentialStore({
		selection: options.secretStoreSelection,
		runner: options.secretStoreRunner,
	});
}

/** The store a rotation should write into: explicit selection, else the current one. */
function resolveRotationStore(config: Config, options: ConfigManagerOptions): SecretStore {
	if (options.secretStore) return options.secretStore;
	if (options.secretStoreSelection) {
		return resolveSecretStore({ selection: options.secretStoreSelection });
	}
	const current = config.secretRef?.store ?? config.secretStore;
	if (current) return resolveSecretStore({ selection: current, runner: options.secretStoreRunner });
	return selectStore(options);
}

/** Best effort: an uncommitted secret must not be left behind in the vault. */
function discardUncommittedSecret(
	store: SecretStore | null,
	reference: SecretReference | null,
): void {
	if (!store || !reference || store.location === "config-file") return;
	try {
		store.revoke(reference.id);
	} catch {
		// The config commit already failed; a leftover handle is unreferenced and
		// is reported by the rotation warning path when it matters.
	}
}

/**
 * Invalidate the credential a committed config just replaced.
 *
 * This runs ONLY after the new credential is committed. Until that point the
 * previous secret stays valid, so a crash or a lost write leaves the user with a
 * working credential instead of none.
 */
function revokePreviousSecret(
	previous: SecretReference | null,
	current: SecretReference | null,
	store: SecretStore | null,
	options: ConfigManagerOptions,
): string | null {
	if (!previous || previous.store === "file-acl") return null;
	if (current && previous.store === current.store && previous.id === current.id) return null;
	try {
		const previousStore =
			store && previous.store === store.kind ? store : storeForReference(previous, options);
		previousStore.revoke(previous.id);
		return null;
	} catch {
		return (
			`The previous credential in the ${previous.store} store could not be revoked; ` +
			"it stays valid until it is removed from that store."
		);
	}
}

/** Read the config that already exists, without resolving its credential. */
function readPreviousConfig(
	existing: { fd: number; stats: Stats },
	options: ConfigManagerOptions,
): { config: Config; stats: Stats } {
	try {
		return parseConfigDocument(existing.fd, existing.stats, options, false);
	} finally {
		closeSync(existing.fd);
	}
}

/**
 * Whether setup must hold a CLI credential. Only a managed configuration does;
 * the default local mode reads none, so it needs neither a credential nor a vault.
 */
function requiresCliCredential(config: Partial<Config> | undefined): boolean {
	return (config as { mode?: unknown } | undefined)?.mode === "managed";
}

/** A config with no credential at all (e.g. after a revoke) has nothing to reuse. */
function hasCredential(config: Config): boolean {
	return config.secretRef !== undefined || config.apiKey !== "";
}

/**
 * Mint a credential and, for a vault, write it there first: the config document
 * only ever learns the reference after the secret is in place.
 */
function mintCredential(
	store: SecretStore,
	createdAt: string,
): { apiKey: string; reference: SecretReference | null } {
	const apiKey = generateApiKey();
	if (store.location === "config-file") return { apiKey, reference: null };
	const reference: SecretReference = {
		store: store.kind,
		id: createSecretReferenceId(),
		created_at: createdAt,
	};
	store.put(reference.id, apiKey);
	return { apiKey, reference };
}

export async function createConfig(
	env: Environment,
	force: boolean,
	options: ConfigManagerOptions = {},
): Promise<ConfigCreationResult> {
	const directory = ensureConfigDirectory(true);
	const existing = openConfigFile();
	const expected = existing?.stats ?? null;
	const previous = existing ? readPreviousConfig(existing, options) : null;

	// An explicitly chosen store (`--secret-store`, or an injected one) asks for
	// a credential too; the AIDR_SECRET_STORE variable only picks where one goes.
	const needsCredential =
		requiresCliCredential(previous?.config) ||
		options.secretStore !== undefined ||
		options.secretStoreSelection !== undefined;
	if (previous && !force && (!needsCredential || hasCredential(previous.config))) {
		if (!IS_POSIX) hardenWindowsAcl(CONFIG_FILE, previous.stats, false);
		if (isCommercialBuild() && previous.config.auth) {
			writeConfigAtomically(previous.config, previous.stats, directory ?? undefined, options);
		}
		return {
			path: CONFIG_FILE,
			outcome: "reused",
			credential: hasCredential(previous.config)
				? (previous.config.secretRef?.store ?? previous.config.secretStore ?? "file-acl")
				: "none",
		};
	}

	// Local mode (the default) evaluates every call on this machine and reads no
	// credential, so none is minted and no vault is required (PRD-4, MSC-13). A
	// managed configuration gets one, in the vault or the encrypted file store.
	const store = needsCredential ? selectStore(options) : null;
	const createdAt = new Date().toISOString();
	const { apiKey, reference } = store
		? mintCredential(store, createdAt)
		: { apiKey: "", reference: null };
	const { projectRoot: _legacyProjectRoot, ...environment } = env;
	const config: Config = {
		// The CLI and runtime share config.json. Replacing setup metadata must not
		// discard policy, mode, auth, or other runtime settings already present.
		...(previous?.config ?? {}),
		apiKey,
		environment,
		version: VERSION,
		createdAt,
		hooksInstalled: false,
		agentConfigured: false,
	};
	delete config.secretRef;
	delete config.secretRevokedAt;
	delete config.secretStore;
	if (store) config.secretStore = store.kind;
	if (reference) config.secretRef = reference;

	let written: boolean;
	try {
		written = writeConfigAtomically(config, expected, directory ?? undefined, options);
	} catch (error) {
		discardUncommittedSecret(store, reference);
		throw error;
	}
	if (!written) {
		// A concurrent writer got there first; this credential is not referenced.
		discardUncommittedSecret(store, reference);
		return { path: CONFIG_FILE, outcome: "reused" };
	}

	const warning = revokePreviousSecret(
		previous?.config.secretRef ?? null,
		reference,
		store,
		options,
	);
	return {
		path: CONFIG_FILE,
		outcome: "created",
		credential: store ? store.kind : "none",
		...(warning ? { warning } : {}),
	};
}

export function getConfig(options: ConfigManagerOptions = {}): Config | null {
	return readConfig(options)?.config ?? null;
}

export function updateConfig(updates: Partial<Config>, options: ConfigManagerOptions = {}): void {
	const existing = readConfig(options);
	if (!existing) throw new Error("Config not found. Run 'aidr setup' first.");
	writeConfigAtomically({ ...existing.config, ...updates }, existing.stats, undefined, options);
}

/** Replace the config document with a fully validated, normalized config. */
export function replaceConfig(config: Config, options: ConfigManagerOptions = {}): void {
	const existing = readConfig(options);
	if (!existing) throw new Error("Config not found. Run 'aidr setup' first.");
	if (!writeConfigAtomically(config, existing.stats, undefined, options)) {
		throw new Error("Local config changed during update; no changes were saved.");
	}
}

/**
 * Mint a replacement credential through the store and record the outcome.
 *
 * Ordering is the contract: the new secret is written to the store first, then
 * `config.json` is committed atomically, and only then is the previous secret
 * revoked. A failure before the commit rolls the new secret back and leaves the
 * previous one valid.
 */
export function rotateSecret(options: ConfigManagerOptions = {}): SecretRotationResult {
	const existing = readConfigForMutation(options);
	if (!existing) throw new Error("Config not found. Run 'aidr setup' first.");
	const { config, stats } = existing;

	const store = resolveRotationStore(config, options);
	const rotatedAt = new Date().toISOString();
	const { apiKey, reference } = mintCredential(store, rotatedAt);

	const next: Config = {
		...config,
		apiKey,
		secretStore: store.kind,
		secretRotatedAt: rotatedAt,
	};
	delete next.secretRevokedAt;
	if (reference) next.secretRef = reference;
	else delete next.secretRef;

	let written: boolean;
	try {
		written = writeConfigAtomically(next, stats, undefined, options);
	} catch (error) {
		discardUncommittedSecret(store, reference);
		throw error;
	}
	if (!written) {
		discardUncommittedSecret(store, reference);
		throw new Error(
			"Local config changed during rotation; the previous credential is still active.",
		);
	}

	const previousReference = config.secretRef ?? null;
	const warning = revokePreviousSecret(previousReference, reference, store, options);
	return {
		path: CONFIG_FILE,
		store: store.kind,
		rotated: true,
		ref: reference,
		previousRef: previousReference,
		rotatedAt,
		...(warning ? { warning } : {}),
	};
}

/**
 * Revoke the credential and record the outcome.
 *
 * The store entry is removed first: a config document that still points at a
 * revoked reference fails closed on read, which is the safer half of a partial
 * failure.
 */
export function revokeSecret(options: ConfigManagerOptions = {}): SecretRevocationResult {
	const existing = readConfigForMutation(options);
	if (!existing) throw new Error("Config not found. Run 'aidr setup' first.");
	const { config, stats } = existing;

	const reference = config.secretRef ?? null;
	let store: SecretStore;
	if (reference) {
		store = storeForReference(reference, options);
		store.revoke(reference.id);
	} else {
		// No reference means the credential (if any) is inline in the ACL-hardened
		// config document; clearing it there is the only revocation available.
		if (config.apiKey === "") throw new Error("No local credential is stored; nothing to revoke.");
		store = createFileAclStore();
	}

	const revokedAt = new Date().toISOString();
	const next: Config = {
		...config,
		apiKey: "",
		secretStore: store.kind,
		secretRevokedAt: revokedAt,
	};
	delete next.secretRef;
	delete next.secretRotatedAt;

	let written: boolean;
	try {
		written = writeConfigAtomically(next, stats);
	} catch (error) {
		throw new Error(
			"The credential was revoked, but the local config could not be updated to record it.",
			{ cause: error },
		);
	}
	if (!written) {
		throw new Error(
			"Local config changed during revocation; the credential was revoked but the config " +
				"still references it.",
		);
	}
	return { path: CONFIG_FILE, store: store.kind, revokedRef: reference, revokedAt };
}
