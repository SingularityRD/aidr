import { createPublicKey } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { isIP } from "node:net";
import { userInfo } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { z } from "zod";
import { resolvePath } from "./config.js";
import type { ManagedState } from "./managed.js";
import { isEntitlementActive, verifyEd25519SignedEntitlementSnapshot } from "./managed.js";
import {
	type FleetResponseSignedDelivery,
	verifyFleetResponseCommandDelivery,
} from "./response-command-consumer-v6.js";
import { FleetResponseJournal } from "./response-command-journal-v6.js";
import { resolveSecretStore, type SecretStore } from "./secret-store.js";
import { windowsTargetsAreAlreadyPrivate } from "./windows-private-acl-probe.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KEY_HASH = /^[a-f0-9]{64}$/;
const MAX_CONFIG_BYTES = 32_768;
const IpAddresses = z
	.array(
		z.string().refine((value) => {
			const version = isIP(value);
			if (version === 4) return true;
			if (version !== 6 || value.includes("%")) return false;
			const canonical = new URL(`http://[${value}]`).hostname.slice(1, -1);
			return value === canonical && !canonical.startsWith("::ffff:");
		}),
	)
	.max(64);
const PublicCommandKey = z
	.string()
	.min(1)
	.max(8192)
	.refine((value) => {
		try {
			return (
				value.trim().startsWith("-----BEGIN PUBLIC KEY-----") &&
				createPublicKey(value).asymmetricKeyType === "ed25519"
			);
		} catch {
			return false;
		}
	});

/** Fixed installer contract; a tool call cannot select trust, a vault or a journal path. */
export const ResponseControlConfigSchema = z
	.object({
		schema_version: z.literal(1),
		tenant_id: z.string().regex(UUID),
		agent_id: z.string().regex(UUID),
		installation_id: z
			.string()
			.min(1)
			.max(128)
			.regex(/^[^\u0000-\u001f\u007f]+$/),
		trusted_command_keys: z
			.record(z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/), PublicCommandKey)
			.refine((keys) => Object.keys(keys).length > 0 && Object.keys(keys).length <= 16),
		control_plane_addresses: IpAddresses.min(1),
		admin_recovery_addresses: IpAddresses.min(1),
		network_support_addresses: IpAddresses,
		journal_key_ref: z
			.object({
				store: z.literal("windows-dpapi"),
				id: z.string().regex(/^aidr-[a-f0-9]{32}$/),
				created_at: z.string().datetime(),
			})
			.strict(),
	})
	.strict();

export type ResponseControlConfig = z.infer<typeof ResponseControlConfigSchema>;
export type ResponseBarrierInspection =
	| { status: "unconfigured" | "running" }
	| { status: "paused"; commandId: string }
	| { status: "unavailable" };

export interface ResponseBarrierOptions {
	required: boolean;
	managedState: ManagedState;
	apiKey: string;
	publicKeysPem: readonly string[];
	/** Internal installer/test override, never a field supplied by a tool request. */
	aidrDir?: string;
	secretStore?: SecretStore;
	now?: () => number;
}

/** Anchor installed control to the OS profile, never to a tool's HOME/USERPROFILE. */
export function currentWindowsUserProfile(): string {
	if (process.platform !== "win32") throw new Error("windows_response_platform_required");
	const profile = userInfo().homedir;
	if (!profile || !isAbsolute(profile) || /[\u0000-\u001f\u007f]/.test(profile))
		throw new Error("windows_response_profile_unavailable");
	return resolve(profile);
}

async function readRegularFile(path: string, maxBytes: number): Promise<Buffer> {
	const before = await lstat(path);
	if (!before.isFile() || before.isSymbolicLink() || before.size > maxBytes)
		throw new Error("invalid_response_control_file");
	const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
	try {
		const opened = await handle.stat();
		if (opened.dev !== before.dev || opened.ino !== before.ino || !opened.isFile())
			throw new Error("response_control_file_changed");
		const content = Buffer.alloc(maxBytes + 1);
		const { bytesRead } = await handle.read(content, 0, content.length, 0);
		const after = await lstat(path);
		if (
			bytesRead > maxBytes ||
			after.isSymbolicLink() ||
			after.dev !== opened.dev ||
			after.ino !== opened.ino
		)
			throw new Error("response_control_file_changed");
		return content.subarray(0, bytesRead);
	} finally {
		await handle.close();
	}
}

async function assertPrivateConfig(directory: string, configPath: string): Promise<void> {
	const directoryInfo = await lstat(directory);
	const fileInfo = await lstat(configPath);
	if (
		!directoryInfo.isDirectory() ||
		directoryInfo.isSymbolicLink() ||
		!fileInfo.isFile() ||
		fileInfo.isSymbolicLink()
	)
		throw new Error("invalid_response_control_path");
	if (process.platform === "win32") {
		if (
			!windowsTargetsAreAlreadyPrivate([
				{ path: directory, directory: true },
				{ path: configPath, directory: false },
			])
		)
			throw new Error("response_control_config_not_private");
	} else {
		const owner = process.getuid?.();
		if (
			owner === undefined ||
			directoryInfo.uid !== owner ||
			fileInfo.uid !== owner ||
			(directoryInfo.mode & 0o077) !== 0 ||
			(fileInfo.mode & 0o077) !== 0
		)
			throw new Error("response_control_config_not_private");
	}
}

/** JWT claims are only a consistency check; the signed entitlement and journal are the authority. */
function credentialMatches(apiKey: string, config: ResponseControlConfig, now: number): boolean {
	try {
		if (apiKey.length > 8192) return false;
		const parts = apiKey.split(".");
		if (
			parts.length !== 3 ||
			parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part)) ||
			parts[2]?.length !== 43
		)
			return false;
		const header = JSON.parse(Buffer.from(parts[0] as string, "base64url").toString("utf8"));
		const claims = JSON.parse(Buffer.from(parts[1] as string, "base64url").toString("utf8"));
		return (
			header?.alg === "HS256" &&
			header.typ === "JWT" &&
			claims?.uid === config.tenant_id &&
			claims.agent_id === config.agent_id &&
			typeof claims.jti === "string" &&
			UUID.test(claims.jti) &&
			Number.isSafeInteger(claims.iat) &&
			Number.isSafeInteger(claims.exp) &&
			claims.iat >= 0 &&
			claims.exp > claims.iat &&
			claims.exp - claims.iat <= 7 * 24 * 3600 &&
			claims.iat <= now / 1000 + 300 &&
			claims.exp > now / 1000
		);
	} catch {
		return false;
	}
}

function historicalCommand(
	delivery: FleetResponseSignedDelivery,
	config: ResponseControlConfig,
	now: number,
) {
	const keyHash = delivery?.payload?.key_hash;
	if (typeof keyHash !== "string" || !KEY_HASH.test(keyHash))
		throw new Error("invalid_response_control_credential_binding");
	const verified = verifyFleetResponseCommandDelivery(delivery, {
		identity: { tenantId: config.tenant_id, agentId: config.agent_id },
		attestation: { schemaVersion: 1, installationId: config.installation_id, keyHash },
		trustedCommandKeys: config.trusted_command_keys,
		now,
		// This is the authenticated history of an applied action, not a new execution.
		allowExpired: true,
	});
	if ("status" in verified) throw new Error("unverified_response_control_delivery");
	return verified;
}

function hasFreshResponseCheckpoint(timestamp: string | null, now: number): boolean {
	if (typeof timestamp !== "string") return false;
	const polledAt = Date.parse(timestamp);
	return (
		Number.isFinite(polledAt) &&
		new Date(polledAt).toISOString() === timestamp &&
		polledAt > 0 &&
		polledAt <= now &&
		now - polledAt <= 120_000
	);
}

/** Read only: missing or damaged required state never becomes a new running checkpoint. */
// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: one fail-closed enrollment and authenticated journal boundary.
export async function inspectResponseBarrier(
	options: ResponseBarrierOptions,
): Promise<ResponseBarrierInspection> {
	let aidrDir: string;
	try {
		aidrDir =
			options.aidrDir ??
			(process.platform === "win32"
				? join(currentWindowsUserProfile(), ".singularity-aidr")
				: resolvePath("~/.singularity-aidr"));
	} catch {
		return { status: "unavailable" };
	}
	const directory = join(aidrDir, "response-control");
	try {
		await lstat(directory);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT" && !options.required)
			return { status: "unconfigured" };
		return { status: "unavailable" };
	}
	try {
		const parent = await lstat(aidrDir);
		if (!parent.isDirectory() || parent.isSymbolicLink())
			throw new Error("invalid_response_control_parent");
		const configPath = join(directory, "config.json");
		await assertPrivateConfig(directory, configPath);
		const config = ResponseControlConfigSchema.parse(
			JSON.parse((await readRegularFile(configPath, MAX_CONFIG_BYTES)).toString("utf8")),
		);
		if (
			new Set([
				...config.control_plane_addresses,
				...config.admin_recovery_addresses,
				...config.network_support_addresses,
			]).size > 64
		)
			throw new Error("invalid_response_control_addresses");
		const now = options.now?.() ?? Date.now();
		const state = options.managedState;
		if (
			state.entitlement_alg !== "ed25519" ||
			state.entitlement?.schema_version !== 2 ||
			state.entitlement.tenant_id !== config.tenant_id ||
			!state.entitlement_sig ||
			!isEntitlementActive(state, new Date(now)) ||
			!verifyEd25519SignedEntitlementSnapshot({
				snapshot: state.entitlement,
				sig_b64: state.entitlement_sig,
				public_keys_pem: [...options.publicKeysPem],
			}) ||
			!credentialMatches(options.apiKey, config, now)
		)
			throw new Error("unverified_response_control_enrollment");
		const iid = (await readRegularFile(join(aidrDir, "installation-id"), 256))
			.toString("utf8")
			.trim();
		if (iid !== config.installation_id) throw new Error("response_control_installation_mismatch");
		const secretsDirectory = join(aidrDir, "secrets");
		if (!options.secretStore) {
			const blobPath = join(secretsDirectory, `${config.journal_key_ref.id}.dpapi`);
			await assertPrivateConfig(secretsDirectory, blobPath);
			await readRegularFile(blobPath, 16_384);
		}
		const store =
			options.secretStore ??
			resolveSecretStore({
				selection: config.journal_key_ref.store,
				directory: secretsDirectory,
			});
		if (store.kind !== "windows-dpapi" || store.location !== "os-vault" || !store.osProtected)
			throw new Error("response_control_vault_unavailable");
		const journalKey = store.get(config.journal_key_ref.id);
		if (
			!journalKey ||
			Buffer.from(journalKey, "base64").length !== 32 ||
			Buffer.from(journalKey, "base64").toString("base64") !== journalKey
		)
			throw new Error("response_control_vault_key_unavailable");
		const head = await new FleetResponseJournal(
			join(directory, "worker-state"),
			{
				tenantId: config.tenant_id,
				agentId: config.agent_id,
			},
			options.apiKey,
			iid,
			journalKey,
			() => now,
		).inspect();
		if (!head?.response_control) throw new Error("response_control_head_unavailable");
		if (
			head.current?.command.commandType === "agent_pause" &&
			["polled", "acknowledged", "execute_intent", "result_pending"].includes(head.current.phase)
		) {
			// A lost newest slot can leave the preceding accepted pause after its effect.
			const pending = historicalCommand(head.current.delivery, config, now);
			return { status: "paused", commandId: pending.command.id };
		}
		const control = head.response_control;
		if (
			control.pause_delivery === null &&
			control.resume_delivery === null &&
			control.status === "running"
		)
			return hasFreshResponseCheckpoint(head.last_successful_poll_at ?? head.bootstrap_at, now)
				? { status: "running" }
				: { status: "unavailable" };
		if (!control.pause_delivery) throw new Error("response_control_pause_evidence_unavailable");
		const pause = historicalCommand(control.pause_delivery, config, now);
		if (pause.command.commandType !== "agent_pause")
			throw new Error("invalid_response_control_pause");
		if (control.status === "paused" && control.resume_delivery === null)
			return { status: "paused", commandId: pause.command.id };
		if (control.status !== "running" || !control.resume_delivery)
			throw new Error("invalid_response_control_state");
		const resume = historicalCommand(control.resume_delivery, config, now);
		if (
			resume.command.commandType !== "agent_resume" ||
			resume.command.rollbackOf !== pause.command.id ||
			Date.parse(resume.delivery.payload.created_at as string) <
				Date.parse(pause.delivery.payload.created_at as string)
		)
			throw new Error("invalid_response_control_resume");
		return hasFreshResponseCheckpoint(head.last_successful_poll_at, now)
			? { status: "running" }
			: { status: "unavailable" };
	} catch {
		return { status: "unavailable" };
	}
}
