import { randomBytes } from "node:crypto";
import { lookup } from "node:dns/promises";
import { constants } from "node:fs";
import { lstat, mkdir, open } from "node:fs/promises";
import { isIP } from "node:net";
import { dirname, join, resolve } from "node:path";
import { isInvalidConfig, loadConfig } from "./config.js";
import { hashDeviceKey } from "./device-attestation.js";
import { atomicWriteJson } from "./file-utils.js";
import { verifyArtifactIntegrity } from "./integrity/verify.js";
import { getEffectiveManagedApiKey, isEntitlementActive, loadManagedState } from "./managed.js";
import { preparePrivateLocalDirectory, preparePrivateLocalFile } from "./private-local-file.js";
import {
	currentWindowsUserProfile,
	type ResponseControlConfig,
	ResponseControlConfigSchema,
} from "./response-barrier.js";
import {
	type FleetResponseCycleResult,
	type FleetResponseIdentity,
	verifyFleetResponseCommandDelivery,
} from "./response-command-consumer-v6.js";
import { FleetResponseJournal } from "./response-command-journal-v6.js";
import { FleetResponseCommandWorker } from "./response-command-worker-v6.js";
import { createSecretReferenceId, createWindowsDpapiStore } from "./secret-store.js";
import { windowsTargetsAreAlreadyPrivate } from "./windows-private-acl-probe.js";
import { WindowsResponseActionAdapter } from "./windows-response-adapter.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_CONFIG_BYTES = 32_768;

type VaultReference = { store: "windows-dpapi"; id: string; created_at: string };
export type WindowsResponseControlConfig = ResponseControlConfig;

function record(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reference(value: unknown): VaultReference {
	if (
		!record(value) ||
		Object.keys(value).length !== 3 ||
		value.store !== "windows-dpapi" ||
		typeof value.id !== "string" ||
		!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value.id) ||
		value.id.includes("..") ||
		typeof value.created_at !== "string" ||
		!Number.isFinite(Date.parse(value.created_at))
	) {
		throw new Error("windows_response_invalid_vault_reference");
	}
	return value as VaultReference;
}

function literalIp(value: unknown): string {
	if (typeof value !== "string" || value.trim() !== value || !isIP(value) || value.includes("%"))
		throw new Error("windows_response_invalid_recovery_address");
	return isIP(value) === 6 ? new URL(`http://[${value}]`).hostname.slice(1, -1) : value;
}

/** Closed public configuration; no bearer, executable, home or arbitrary state path. */
export function parseWindowsResponseControlConfig(
	value: unknown,
	bootstrap = false,
): WindowsResponseControlConfig {
	try {
		const parsed = (
			bootstrap
				? ResponseControlConfigSchema.omit({ journal_key_ref: true })
				: ResponseControlConfigSchema
		).parse(value);
		if (
			new Set([
				...parsed.control_plane_addresses,
				...parsed.admin_recovery_addresses,
				...parsed.network_support_addresses,
			]).size > 64
		)
			throw new Error();
		return parsed as WindowsResponseControlConfig;
	} catch {
		throw new Error("windows_response_invalid_config");
	}
}

async function regularDirectory(path: string): Promise<void> {
	const info = await lstat(path);
	if (!info.isDirectory() || info.isSymbolicLink())
		throw new Error("windows_response_unsafe_directory");
}

async function boundedFile(path: string, limit = MAX_CONFIG_BYTES): Promise<string> {
	const before = await lstat(path);
	if (!before.isFile() || before.isSymbolicLink() || before.size > limit)
		throw new Error("windows_response_unsafe_file");
	const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
	try {
		const opened = await handle.stat();
		if (opened.dev !== before.dev || opened.ino !== before.ino || !opened.isFile())
			throw new Error("windows_response_file_changed");
		const content = Buffer.alloc(limit + 1);
		const { bytesRead } = await handle.read(content, 0, content.length, 0);
		const after = await lstat(path);
		if (
			bytesRead > limit ||
			after.isSymbolicLink() ||
			after.dev !== opened.dev ||
			after.ino !== opened.ino
		)
			throw new Error("windows_response_file_changed");
		return new TextDecoder("utf8", { fatal: true })
			.decode(content.subarray(0, bytesRead))
			.replace(/^\uFEFF/, "");
	} finally {
		await handle.close();
	}
}

function privateFiles(directory: string, files: string[]): void {
	if (
		!windowsTargetsAreAlreadyPrivate([
			{ path: directory, directory: true },
			...files.map((path) => ({ path, directory: false })),
		])
	)
		throw new Error("windows_response_state_not_private");
}

/** Consistency check only; the HTTPS control plane authenticates the HS256 bearer. */
function windowsResponseTokenIdentity(token: string, allowExpired = false): FleetResponseIdentity {
	try {
		const parts = token.split(".");
		if (
			token.length > 8192 ||
			parts.length !== 3 ||
			parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part)) ||
			parts[2]?.length !== 43
		)
			throw new Error();
		const header: unknown = JSON.parse(
			Buffer.from(parts[0] as string, "base64url").toString("utf8"),
		);
		const claims: unknown = JSON.parse(
			Buffer.from(parts[1] as string, "base64url").toString("utf8"),
		);
		if (
			!record(header) ||
			header.alg !== "HS256" ||
			header.typ !== "JWT" ||
			!record(claims) ||
			![claims.uid, claims.agent_id, claims.jti].every(
				(item) => typeof item === "string" && UUID.test(item),
			) ||
			!Number.isSafeInteger(claims.iat) ||
			!Number.isSafeInteger(claims.exp) ||
			(claims.iat as number) < 0 ||
			(claims.exp as number) <= (claims.iat as number) ||
			(claims.exp as number) - (claims.iat as number) > 604_800 ||
			(claims.iat as number) > Math.floor(Date.now() / 1000) + 300 ||
			(!allowExpired && (claims.exp as number) <= Math.floor(Date.now() / 1000))
		)
			throw new Error();
		return { tenantId: claims.uid as string, agentId: claims.agent_id as string };
	} catch {
		throw new Error("windows_response_invalid_agent_credential");
	}
}

async function pinnedAddresses(endpoint: string, addresses: readonly string[]): Promise<void> {
	const url = new URL(endpoint);
	if (
		url.protocol !== "https:" ||
		url.username ||
		url.password ||
		url.search ||
		url.hash ||
		!/^\/(?:functions(?:\/v1)?|v1)?\/?$/.test(url.pathname)
	)
		throw new Error("windows_response_requires_https");
	const host = url.hostname.replace(/^\[|\]$/g, "");
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		const resolved = isIP(host)
			? [{ address: host }]
			: await Promise.race([
					lookup(host, { all: true, verbatim: true }),
					new Promise<never>((_, reject) => {
						timer = setTimeout(() => reject(new Error("windows_response_dns_unavailable")), 5000);
					}),
				]);
		if (
			resolved.length === 0 ||
			resolved.length > 64 ||
			resolved.some((entry) => !addresses.includes(literalIp(entry.address)))
		)
			throw new Error("windows_response_control_plane_address_mismatch");
	} finally {
		if (timer) clearTimeout(timer);
	}
}

// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: keep identity, vault and entitlement checks together at the installed trust boundary
async function enrollment() {
	if (process.platform !== "win32") throw new Error("windows_response_unsupported_platform");
	const profile = currentWindowsUserProfile();
	const aidrDir = join(profile, ".singularity-aidr");
	await regularDirectory(profile);
	await regularDirectory(aidrDir);
	const configPath = join(aidrDir, "config.json");
	const managedPath = join(aidrDir, "managed.json");
	const installationPath = join(aidrDir, "installation-id");
	privateFiles(aidrDir, [configPath, managedPath, installationPath]);
	const [rawConfig, rawManaged, rawId] = await Promise.all([
		boundedFile(configPath),
		boundedFile(managedPath, 262_144),
		boundedFile(installationPath, 256),
	]);
	const document: unknown = JSON.parse(rawConfig);
	const managed: unknown = JSON.parse(rawManaged);
	if (!record(document) || !record(document.auth) || !record(managed))
		throw new Error("windows_response_invalid_enrollment");
	if (
		Object.hasOwn(document.auth, "api_key") ||
		Object.hasOwn(document.auth, "enrollment_token") ||
		Object.hasOwn(managed, "api_key")
	)
		throw new Error("windows_response_plaintext_credential_refused");
	const store = createWindowsDpapiStore({ directory: join(aidrDir, "secrets") });
	await regularDirectory(join(aidrDir, "secrets"));
	const credential = async (value: unknown): Promise<string | undefined> => {
		if (value === undefined) return undefined;
		const ref = reference(value);
		const sealedPath = join(aidrDir, "secrets", `${ref.id}.dpapi`);
		privateFiles(join(aidrDir, "secrets"), [sealedPath]);
		await boundedFile(sealedPath, 16_384);
		const secret = store.get(ref.id);
		if (!secret) throw new Error("windows_response_vault_credential_unavailable");
		return secret;
	};
	const configuredKey = await credential(document.auth.api_key_ref);
	const managedKey = await credential(managed.api_key_ref);
	if (!configuredKey && !managedKey) throw new Error("windows_response_vault_credential_required");
	const config = await loadConfig(configPath, undefined, store, { raw: rawConfig });
	if (isInvalidConfig(config) || config.mode !== "managed" || !config.control_plane.enabled)
		throw new Error("windows_response_invalid_enrollment");
	const state = await loadManagedState(managedPath, {
		publicKeysPem: config.licensing.public_keys_pem,
		secretStore: store,
		source: { raw: rawManaged },
		onSecurityEvent: () => {},
	});
	if (
		state.entitlement_alg !== "ed25519" ||
		state.entitlement?.schema_version !== 2 ||
		!isEntitlementActive(state)
	)
		throw new Error("windows_response_signed_entitlement_required");
	const apiKey = getEffectiveManagedApiKey(configuredKey, { ...state, api_key: managedKey });
	const identity = windowsResponseTokenIdentity(apiKey);
	for (const key of [configuredKey, managedKey]) {
		if (!key) continue;
		const previous = windowsResponseTokenIdentity(key, true);
		if (previous.tenantId !== identity.tenantId || previous.agentId !== identity.agentId)
			throw new Error("windows_response_rotation_identity_mismatch");
	}
	const installationId = rawId.trim();
	if (
		!ResponseControlConfigSchema.shape.installation_id.safeParse(installationId).success ||
		state.entitlement.tenant_id !== identity.tenantId
	)
		throw new Error("windows_response_enrollment_identity_mismatch");
	return {
		profile,
		aidrDir,
		configPath,
		config,
		document,
		rawConfig,
		apiKey,
		identity,
		installationId,
		store,
	};
}

async function verifiedArtifact(adapterPath: string, publicKeysPem: string[]): Promise<void> {
	const artifactDir = dirname(dirname(resolve(adapterPath)));
	await regularDirectory(artifactDir);
	await regularDirectory(join(artifactDir, "native"));
	await boundedFile(adapterPath, 262_144);
	await boundedFile(join(artifactDir, "native", "Common.ps1"), 262_144);
	const result = await verifyArtifactIntegrity({
		artifactDir,
		publicKeysPem,
		verifySignatures: true,
		expectedArtifactId: "claude-code/dist",
	});
	if (
		result.status !== "ok" ||
		!result.manifest?.files.some((file) => file.path === "native/Invoke-AidrResponseAction.ps1") ||
		!result.manifest.files.some((file) => file.path === "native/Common.ps1") ||
		!result.manifest.files.some((file) => file.path === "response-worker.cjs")
	)
		throw new Error("windows_response_artifact_untrusted");
}

function sameEnrollment(
	config: WindowsResponseControlConfig,
	enrolled: Awaited<ReturnType<typeof enrollment>>,
): void {
	if (
		config.tenant_id !== enrolled.identity.tenantId ||
		config.agent_id !== enrolled.identity.agentId ||
		config.installation_id !== enrolled.installationId
	)
		throw new Error("windows_response_enrollment_identity_mismatch");
}

/** Load current-user state without migrating, repairing, creating or healing any file. */
export async function loadInstalledWindowsResponseWorker(
	adapterPath: string,
	expectedSeed?: unknown,
) {
	const enrolled = await enrollment();
	const stateRoot = join(enrolled.aidrDir, "response-control");
	await regularDirectory(stateRoot);
	const responseConfigPath = join(stateRoot, "config.json");
	privateFiles(stateRoot, [responseConfigPath]);
	const control = parseWindowsResponseControlConfig(
		JSON.parse(await boundedFile(responseConfigPath)),
	);
	if (
		expectedSeed !== undefined &&
		publicConfig(control) !== publicConfig(parseWindowsResponseControlConfig(expectedSeed, true))
	)
		throw new Error("windows_response_requested_config_mismatch");
	sameEnrollment(control, enrolled);
	if (
		!record(enrolled.document.control_plane) ||
		enrolled.document.control_plane.response_worker_required !== true
	)
		throw new Error("windows_response_activation_incomplete");
	const keyPath = join(enrolled.aidrDir, "secrets", `${control.journal_key_ref.id}.dpapi`);
	privateFiles(join(enrolled.aidrDir, "secrets"), [keyPath]);
	await boundedFile(keyPath, 16_384);
	const stableJournalKey = enrolled.store.get(control.journal_key_ref.id);
	if (
		!stableJournalKey ||
		!/^[A-Za-z0-9+/]{43}=$/.test(stableJournalKey) ||
		Buffer.from(stableJournalKey, "base64").length !== 32 ||
		Buffer.from(stableJournalKey, "base64").toString("base64") !== stableJournalKey
	)
		throw new Error("windows_response_journal_key_unavailable");
	await pinnedAddresses(enrolled.config.control_plane.endpoint, control.control_plane_addresses);
	await verifiedArtifact(adapterPath, enrolled.config.integrity.public_keys_pem);
	const statePath = join(stateRoot, "worker-state");
	const journal = new FleetResponseJournal(
		statePath,
		enrolled.identity,
		enrolled.apiKey,
		enrolled.installationId,
		stableJournalKey,
	);
	const state = await journal.inspect();
	if (!state) throw new Error("windows_response_journal_bootstrap_required");
	const adapter = new WindowsResponseActionAdapter({
		identity: enrolled.identity,
		installationId: enrolled.installationId,
		keyHash: hashDeviceKey(enrolled.apiKey),
		trustedCommandKeys: control.trusted_command_keys,
		stateRoot,
		adapterPath,
		recoveryDelivery:
			state.current?.phase === "execute_intent" ? state.current.delivery : undefined,
		recoveryAddresses: [
			...new Set([
				...control.control_plane_addresses,
				...control.admin_recovery_addresses,
				...control.network_support_addresses,
			]),
		],
	});
	return { ...enrolled, control, stateRoot, statePath, stableJournalKey, journal, state, adapter };
}

function publicConfig(control: WindowsResponseControlConfig): string {
	return JSON.stringify({
		tenant_id: control.tenant_id,
		agent_id: control.agent_id,
		installation_id: control.installation_id,
		trusted_command_keys: Object.fromEntries(
			Object.entries(control.trusted_command_keys).sort(([a], [b]) => a.localeCompare(b)),
		),
		control_plane_addresses: [...control.control_plane_addresses].sort(),
		admin_recovery_addresses: [...control.admin_recovery_addresses].sort(),
		network_support_addresses: [...control.network_support_addresses].sort(),
	});
}

/** Explicit operator activation. A partial prior activation always requires operator repair. */
export async function initializeInstalledWindowsResponseWorker(
	adapterPath: string,
	seed: unknown,
): Promise<void> {
	const control = parseWindowsResponseControlConfig(seed, true);
	const enrolled = await enrollment();
	sameEnrollment(control, enrolled);
	if (
		record(enrolled.document.control_plane) &&
		enrolled.document.control_plane.response_worker_required !== undefined &&
		enrolled.document.control_plane.response_worker_required !== false
	)
		throw new Error("windows_response_already_required");
	const stateRoot = join(enrolled.aidrDir, "response-control");
	try {
		await lstat(stateRoot);
		throw new Error("windows_response_existing_state_refused");
	} catch (error) {
		if (!record(error) || error.code !== "ENOENT") throw error;
	}
	await pinnedAddresses(enrolled.config.control_plane.endpoint, control.control_plane_addresses);
	await verifiedArtifact(adapterPath, enrolled.config.integrity.public_keys_pem);
	// Exclusive directory creation is also the first-install reservation: two
	// simultaneous initializers cannot each establish a different authority.
	await mkdir(stateRoot, { mode: 0o700 });
	preparePrivateLocalDirectory(stateRoot);
	preparePrivateLocalDirectory(join(enrolled.aidrDir, "secrets"));
	const ref: VaultReference = {
		store: "windows-dpapi",
		id: createSecretReferenceId(),
		created_at: new Date().toISOString(),
	};
	const stableJournalKey = randomBytes(32).toString("base64");
	enrolled.store.put(ref.id, stableJournalKey);
	preparePrivateLocalFile(join(enrolled.aidrDir, "secrets", `${ref.id}.dpapi`));
	if (enrolled.store.get(ref.id) !== stableJournalKey)
		throw new Error("windows_response_journal_key_persistence_failed");
	await atomicWriteJson(join(stateRoot, "config.json"), { ...control, journal_key_ref: ref });
	preparePrivateLocalFile(join(stateRoot, "config.json"));
	const journal = new FleetResponseJournal(
		join(stateRoot, "worker-state"),
		enrolled.identity,
		enrolled.apiKey,
		enrolled.installationId,
		stableJournalKey,
	);
	await journal.bootstrapResponseControl();
	// Last write activates fail-closed hooks. The original vault references and all
	// unrelated runtime settings are preserved byte-for-byte as parsed JSON values.
	if ((await boundedFile(enrolled.configPath)) !== enrolled.rawConfig)
		throw new Error("windows_response_config_changed_during_activation");
	await atomicWriteJson(enrolled.configPath, {
		...enrolled.document,
		control_plane: {
			...(record(enrolled.document.control_plane) ? enrolled.document.control_plane : {}),
			response_worker_required: true,
		},
	});
	preparePrivateLocalFile(enrolled.configPath);
}

export async function validateInstalledWindowsResponseRemoval(adapterPath: string): Promise<void> {
	const runtime = await loadInstalledWindowsResponseWorker(adapterPath);
	// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: every removal observation must stay inside the authoritative journal lock
	await runtime.journal.withLock(async () => {
		const head = await runtime.journal.inspect();
		if (!head || head.current !== null || head.response_control.status !== "running")
			throw new Error("windows_response_removal_pending_or_paused");
		for (const name of ["pause-state.json", "network-state.json"]) {
			const path = join(runtime.stateRoot, name);
			let raw: string;
			try {
				raw = await boundedFile(path);
			} catch (error) {
				if (record(error) && error.code === "ENOENT") continue;
				throw error;
			}
			privateFiles(runtime.stateRoot, [path]);
			const saved: unknown = JSON.parse(raw);
			const signed = record(saved) ? saved.command_signed : undefined;
			const payload = record(signed) ? signed.payload : undefined;
			if (
				!record(payload) ||
				typeof payload.key_hash !== "string" ||
				!/^[a-f0-9]{64}$/.test(payload.key_hash)
			)
				throw new Error("windows_response_removal_native_state_untrusted");
			const verified = verifyFleetResponseCommandDelivery(signed, {
				identity: runtime.identity,
				attestation: {
					schemaVersion: 1,
					installationId: runtime.installationId,
					keyHash: payload.key_hash,
				},
				trustedCommandKeys: runtime.control.trusted_command_keys,
				now: Date.now(),
				allowExpired: true,
			});
			if ("status" in verified) throw new Error("windows_response_removal_native_state_untrusted");
		}
		const observed = await runtime.adapter.inspectRemoval();
		if (!observed.removable) throw new Error("windows_response_removal_not_verified");
	});
}

export async function runInstalledWindowsResponseWorker(
	adapterPath: string,
	options: { once?: boolean; signal?: AbortSignal } = {},
): Promise<FleetResponseCycleResult | void> {
	const runtime = await loadInstalledWindowsResponseWorker(adapterPath);
	const fingerprint = JSON.stringify({
		endpoint: runtime.config.control_plane.endpoint,
		control: runtime.control,
		keyHash: hashDeviceKey(runtime.apiKey),
	});
	const checkCurrent = async () => {
		const current = await loadInstalledWindowsResponseWorker(adapterPath);
		if (
			JSON.stringify({
				endpoint: current.config.control_plane.endpoint,
				control: current.control,
				keyHash: hashDeviceKey(current.apiKey),
			}) !== fingerprint
		)
			throw new Error("windows_response_enrollment_changed");
	};
	const worker = new FleetResponseCommandWorker({
		endpoint: runtime.config.control_plane.endpoint,
		apiKey: runtime.apiKey,
		identity: runtime.identity,
		installationId: runtime.installationId,
		trustedCommandKeys: runtime.control.trusted_command_keys,
		adapter: runtime.adapter,
		statePath: runtime.statePath,
		stableJournalKey: runtime.stableJournalKey,
		fetchImpl: async (input, init) => {
			await checkCurrent();
			return fetch(input, { ...init, redirect: "error" });
		},
		onCycle: checkCurrent,
		actionTimeoutMs: 30_000,
	});
	if (options.once) return worker.tick(options.signal);
	if (!options.signal) throw new Error("windows_response_supervisor_signal_required");
	await worker.run(options.signal);
}
