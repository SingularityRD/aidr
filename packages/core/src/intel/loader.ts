import { createHash } from "node:crypto";
import { mkdir, open, readdir, rename, unlink, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { resolvePath } from "../config.js";
import { atomicWriteJson, getFileContent, getFileContentRaw } from "../file-utils.js";
import type { Logger } from "../types.js";
import { nullLogger } from "../types.js";
import { domainFromUrlOrHost } from "./api.js";
import { decryptAes256GcmEnvelope } from "./crypto.js";
import { loadIntelKeyring } from "./keyring.js";
import { IntelPackManifestSchema, PackActivePointerSchema } from "./schema.js";
import { compareSemver } from "./semver.js";
import type { DomainRiskEntry, IntelFileKind, IntelMerged } from "./types.js";
import { emptyIntelMerged } from "./types.js";
import { verifyEd25519Signature } from "./verify.js";

const DEFAULT_INTEL_DIR = "~/.singularity-aidr/intel";
const DEFAULT_PACKS_DIR = "~/.singularity-aidr/intel/packs";
const DEFAULT_TRUSTED_KEYS_PATH = "~/.singularity-aidr/intel/trusted-keys.json";
const INTEL_VERSION_FLOOR_NAME = ".trusted-version-floor.json";
const VERSION_FLOOR_SCHEMA_VERSION = 1;

const INTEL_PACK_ACTIVE_POINTER = "active.json";
const INTEL_PACK_PREVIOUS_POINTER = "previous.json";

type IntelVerificationMode = "strict" | "grace";

export interface LoadIntelOptions {
	intelDir?: string;
	packsDir?: string;
	trustedKeysPath?: string;
	verificationMode?: IntelVerificationMode;
	/** Only used in grace mode. Default: 72h. */
	graceHours?: number;
	/**
	 * Optional revocations input (best-effort).
	 * If provided, revoked pack ids / key ids are skipped during load.
	 */
	revocations?: {
		pack_ids?: string[];
		key_ids?: string[];
	} | null;
	requireRevocations?: boolean;
}

type TrustedKeysFile = Record<string, string>;
type IntelVersionFloor = { version: string; manifest_sha256: string };
type IntelVersionFloorFile = {
	schema_version: typeof VERSION_FLOOR_SCHEMA_VERSION;
	packs: Record<string, IntelVersionFloor>;
};

function sha256Hex(data: Uint8Array): string {
	return createHash("sha256").update(data).digest("hex");
}

function setAvailability(
	merged: IntelMerged,
	availability: "available" | "unavailable",
	detail: string,
): IntelMerged {
	Object.defineProperty(merged, "availability", {
		value: availability,
		enumerable: false,
		configurable: true,
	});
	Object.defineProperty(merged, "detail", {
		value: detail,
		enumerable: false,
		configurable: true,
	});
	return merged;
}

function versionFloorPath(packsDir: string): string {
	return join(dirname(packsDir), INTEL_VERSION_FLOOR_NAME);
}

async function withVersionFloorLock<T>(path: string, work: () => Promise<T>): Promise<T> {
	const lockPath = `${path}.lock`;
	const deadline = Date.now() + 5_000;
	let handle: Awaited<ReturnType<typeof open>>;
	for (;;) {
		try {
			handle = await open(lockPath, "wx", 0o600);
			break;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST" || Date.now() >= deadline) throw error;
			await new Promise((resolve) => setTimeout(resolve, 20));
		}
	}
	try {
		await handle.writeFile(`${process.pid}\n`);
		await handle.sync();
		return await work();
	} finally {
		await handle.close();
		await unlink(lockPath).catch(() => undefined);
	}
}

async function readVersionFloor(path: string): Promise<IntelVersionFloorFile> {
	let raw: string;
	try {
		raw = await getFileContent(path, "utf8");
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") {
			return { schema_version: VERSION_FLOOR_SCHEMA_VERSION, packs: {} };
		}
		throw error;
	}
	const parsed = JSON.parse(raw) as Partial<IntelVersionFloorFile> | null;
	if (
		!parsed ||
		parsed.schema_version !== VERSION_FLOOR_SCHEMA_VERSION ||
		!parsed.packs ||
		typeof parsed.packs !== "object" ||
		Array.isArray(parsed.packs)
	) {
		throw new Error("Intel version floor is invalid");
	}
	for (const floor of Object.values(parsed.packs)) {
		if (
			!floor ||
			typeof floor.version !== "string" ||
			!floor.version ||
			typeof floor.manifest_sha256 !== "string" ||
			!/^[0-9a-f]{64}$/i.test(floor.manifest_sha256)
		) {
			throw new Error("Intel version floor is invalid");
		}
	}
	return parsed as IntelVersionFloorFile;
}

async function acceptPackVersion(
	packsDir: string,
	packId: string,
	version: string,
	manifestSha256: string,
): Promise<boolean> {
	const path = versionFloorPath(packsDir);
	return withVersionFloorLock(path, async () => {
		const floor = await readVersionFloor(path);
		const current = floor.packs[packId];
		if (current) {
			const order = compareSemver(version, current.version);
			if (order < 0 || (order === 0 && current.manifest_sha256 !== manifestSha256)) return false;
			if (order === 0) return true;
		}
		floor.packs[packId] = { version, manifest_sha256: manifestSha256 };
		await atomicWriteJson(path, floor);
		return true;
	});
}

async function loadTrustedKeys(path: string): Promise<Map<string, string>> {
	try {
		const raw = await getFileContent(path, "utf-8");
		const parsed = JSON.parse(raw) as TrustedKeysFile;
		const map = new Map<string, string>();
		for (const [keyId, pem] of Object.entries(parsed ?? {})) {
			if (typeof keyId !== "string" || typeof pem !== "string") continue;
			if (!keyId.trim() || !pem.trim()) continue;
			map.set(keyId.trim(), pem);
		}
		return map;
	} catch {
		return new Map();
	}
}

async function listDirs(path: string): Promise<string[]> {
	try {
		const ents = await readdir(path, { withFileTypes: true });
		return ents.filter((e) => e.isDirectory()).map((e) => e.name);
	} catch {
		return [];
	}
}

async function readActiveVersion(packRoot: string): Promise<string | null> {
	try {
		const raw = await getFileContent(join(packRoot, INTEL_PACK_ACTIVE_POINTER), "utf-8");
		const parsed = PackActivePointerSchema.parse(JSON.parse(raw));
		return parsed.version;
	} catch {
		return null;
	}
}

async function writeJson(path: string, obj: unknown): Promise<void> {
	const data = `${JSON.stringify(obj, null, 2)}\n`;
	const tmp = `${path}.tmp_${Math.random().toString(16).slice(2)}`;
	await writeFile(tmp, data, "utf8");
	await rename(tmp, path);
}

export async function activatePackVersion(params: {
	packId: string;
	version: string;
	packsDir?: string;
}): Promise<void> {
	const packsDir = resolvePath(params.packsDir ?? DEFAULT_PACKS_DIR);
	const packRoot = join(packsDir, params.packId);
	await mkdir(packRoot, { recursive: true });

	const activePath = join(packRoot, INTEL_PACK_ACTIVE_POINTER);
	const prevPath = join(packRoot, INTEL_PACK_PREVIOUS_POINTER);

	const current = await readActiveVersion(packRoot);
	if (current) {
		await writeJson(prevPath, { version: current });
	}
	await writeJson(activePath, { version: params.version });
}

export async function rollbackPackVersion(params: {
	packId: string;
	packsDir?: string;
}): Promise<void> {
	const packsDir = resolvePath(params.packsDir ?? DEFAULT_PACKS_DIR);
	const packRoot = join(packsDir, params.packId);
	const activePath = join(packRoot, INTEL_PACK_ACTIVE_POINTER);
	const prevPath = join(packRoot, INTEL_PACK_PREVIOUS_POINTER);

	let prev: string | null = null;
	try {
		const raw = await getFileContent(prevPath, "utf-8");
		prev = PackActivePointerSchema.parse(JSON.parse(raw)).version;
	} catch {
		prev = null;
	}
	if (!prev) return;

	const current = await readActiveVersion(packRoot);
	if (current) {
		await writeJson(prevPath, { version: current });
	}
	await writeJson(activePath, { version: prev });
}

async function pickVersion(packRoot: string): Promise<string | null> {
	const active = await readActiveVersion(packRoot);
	if (active) return active;
	const versions = await listDirs(packRoot);
	if (versions.length === 0) return null;
	versions.sort((a, b) => compareSemver(a, b));
	return versions[versions.length - 1] ?? null;
}

function normalizeDomain(s: string): string {
	return s.trim().toLowerCase().replace(/^\.+/, "").replace(/\.+$/, "");
}

function parseTextLines(raw: string): string[] {
	const out: string[] = [];
	for (const line of raw.split(/\r?\n/)) {
		const t = line.trim();
		if (!t || t.startsWith("#")) continue;
		out.push(t);
	}
	return out;
}

function parseDomainRiskJson(raw: string): DomainRiskEntry[] {
	let data: unknown;
	try {
		data = JSON.parse(raw);
	} catch {
		return [];
	}
	if (!Array.isArray(data)) return [];
	const out: DomainRiskEntry[] = [];
	for (const item of data) {
		if (!item || typeof item !== "object") continue;
		const obj = item as Record<string, unknown>;
		const domain = normalizeDomain(String(obj.domain ?? ""));
		const action = String(obj.action ?? "");
		const severity = String(obj.severity ?? "");
		const confidence = obj.confidence;
		const reason = obj.reason;
		if (!domain) continue;
		if (action !== "allow" && action !== "ask" && action !== "deny") continue;
		if (!["critical", "high", "medium", "low"].includes(severity)) continue;
		out.push({
			domain,
			action,
			severity: severity as DomainRiskEntry["severity"],
			confidence: typeof confidence === "number" ? confidence : undefined,
			reason: typeof reason === "string" ? reason : undefined,
		});
	}
	return out;
}

async function loadPackFile(
	packVersionDir: string,
	file: {
		kind: IntelFileKind;
		path: string;
		sha256?: string;
		encrypted?: boolean;
		cipher?: "aes-256-gcm";
		key_id?: string;
		ciphertext_sha256?: string;
	},
	keyring: Map<string, Uint8Array>,
	revokedKeyIds: Set<string>,
	logger: Logger,
): Promise<{ kind: IntelFileKind; raw: string } | null> {
	const fullPath = join(packVersionDir, file.path);
	let bytes: Uint8Array;
	try {
		bytes = await getFileContentRaw(fullPath);
	} catch {
		logger.debug("Intel pack file missing", { path: fullPath });
		return null;
	}

	if (file.encrypted) {
		if (!file.cipher || file.cipher !== "aes-256-gcm") {
			logger.warn("Intel pack encrypted file has unsupported cipher", { path: fullPath });
			return null;
		}
		if (!file.key_id || !file.ciphertext_sha256) {
			logger.warn("Intel pack encrypted file missing key_id/ciphertext_sha256", { path: fullPath });
			return null;
		}
		if (revokedKeyIds.has(file.key_id)) {
			logger.warn("Intel pack encrypted file key_id is revoked", {
				path: fullPath,
				keyId: file.key_id,
			});
			return null;
		}

		const cipherDigest = sha256Hex(bytes);
		if (cipherDigest.toLowerCase() !== file.ciphertext_sha256.toLowerCase()) {
			logger.warn("Intel pack ciphertext sha256 mismatch", { path: fullPath });
			return null;
		}

		const key = keyring.get(file.key_id);
		if (!key) {
			logger.warn("Intel pack encrypted file key_id not found in keyring", {
				path: fullPath,
				keyId: file.key_id,
			});
			return null;
		}

		const decrypted = decryptAes256GcmEnvelope({ key, blob: bytes });
		if (!decrypted) {
			logger.warn("Intel pack encrypted file decrypt failed", { path: fullPath });
			return null;
		}

		if (file.sha256) {
			const plainDigest = sha256Hex(decrypted);
			if (plainDigest.toLowerCase() !== file.sha256.toLowerCase()) {
				logger.warn("Intel pack plaintext sha256 mismatch", { path: fullPath });
				return null;
			}
		}

		const raw = Buffer.from(decrypted).toString("utf-8");
		return { kind: file.kind, raw };
	}

	if (!file.sha256) {
		logger.warn("Intel pack file missing sha256", { path: fullPath });
		return null;
	}

	const digest = sha256Hex(bytes);
	if (digest.toLowerCase() !== file.sha256.toLowerCase()) {
		logger.warn("Intel pack file sha256 mismatch", { path: fullPath });
		return null;
	}

	const raw = Buffer.from(bytes).toString("utf-8");
	return { kind: file.kind, raw };
}

async function loadSinglePack(
	packId: string,
	selectedVersion: string,
	packVersionDir: string,
	trustedKeys: Map<string, string>,
	keyring: Map<string, Uint8Array>,
	revokedKeyIds: Set<string>,
	options: { verificationMode: IntelVerificationMode; graceHours: number },
	logger: Logger,
): Promise<{ merged: IntelMerged; manifestSha256: string } | null> {
	const manifestPath = join(packVersionDir, "manifest.json");
	const sigPath = join(packVersionDir, "manifest.sig");

	let manifestBytes: Uint8Array;
	let sigBase64: string;
	try {
		manifestBytes = await getFileContentRaw(manifestPath);
		sigBase64 = (await getFileContent(sigPath, "utf-8")).trim();
	} catch {
		return null;
	}

	let manifestJson: unknown;
	try {
		manifestJson = JSON.parse(Buffer.from(manifestBytes).toString("utf-8"));
	} catch {
		logger.warn("Invalid intel pack manifest JSON", { packId });
		return null;
	}

	const manifest = IntelPackManifestSchema.safeParse(manifestJson);
	if (!manifest.success) {
		logger.warn("Invalid intel pack manifest schema", { packId });
		return null;
	}

	if (manifest.data.pack_id !== packId) {
		logger.warn("Intel pack id mismatch", { packId });
		return null;
	}
	if (manifest.data.version !== selectedVersion) {
		logger.warn("Intel pack version mismatch", { packId, selectedVersion, manifestVersion: manifest.data.version });
		return null;
	}

	const pem = trustedKeys.get(manifest.data.key_id);
	if (!pem) {
		logger.warn("Intel pack key_id not trusted", { packId, keyId: manifest.data.key_id });
		return null;
	}
	if (revokedKeyIds.has(manifest.data.key_id)) {
		logger.warn("Intel pack signing key_id is revoked", { packId, keyId: manifest.data.key_id });
		return null;
	}

	if (
		!verifyEd25519Signature({
			publicKeyPem: pem,
			message: manifestBytes,
			signatureBase64: sigBase64,
		})
	) {
		logger.warn("Intel pack signature verification failed", { packId });
		return null;
	}

	if (manifest.data.expires_at) {
		const exp = Date.parse(manifest.data.expires_at);
		if (Number.isFinite(exp) && Date.now() > exp) {
			if (options.verificationMode === "strict") {
				logger.warn("Intel pack expired (strict)", { packId });
				return null;
			}
			const graceMs = Math.max(0, options.graceHours) * 60 * 60 * 1000;
			if (Date.now() > exp + graceMs) {
				logger.warn("Intel pack expired beyond grace window", { packId });
				return null;
			}
		}
	}

	const merged = emptyIntelMerged();
	for (const f of manifest.data.files) {
		const loaded = await loadPackFile(packVersionDir, f, keyring, revokedKeyIds, logger);
		if (!loaded) return null;

		if (loaded.kind === "url_denylist") {
			for (const s of parseTextLines(loaded.raw)) {
				const host = domainFromUrlOrHost(s);
				if (host) merged.urlDenyHosts.add(host);
			}
		} else if (loaded.kind === "url_allowlist") {
			for (const s of parseTextLines(loaded.raw)) {
				const host = domainFromUrlOrHost(s);
				if (host) merged.urlAllowHosts.add(host);
			}
		} else if (loaded.kind === "package_name_denylist") {
			for (const s of parseTextLines(loaded.raw)) merged.packageNameDeny.add(s.trim());
		} else if (loaded.kind === "package_hash_denylist") {
			for (const s of parseTextLines(loaded.raw))
				merged.packageHashDeny.add(s.trim().toLowerCase());
		} else if (loaded.kind === "plugin_signature_denylist") {
			for (const s of parseTextLines(loaded.raw))
				merged.pluginSignatureDeny.add(s.trim().toLowerCase());
		} else if (loaded.kind === "domain_risk") {
			for (const e of parseDomainRiskJson(loaded.raw)) merged.domainRisk.set(e.domain, e);
		}
	}

	return { merged, manifestSha256: sha256Hex(manifestBytes) };
}

function mergeInto(into: IntelMerged, from: IntelMerged): void {
	for (const h of from.urlDenyHosts) into.urlDenyHosts.add(h);
	for (const h of from.urlAllowHosts) into.urlAllowHosts.add(h);
	for (const [d, e] of from.domainRisk) into.domainRisk.set(d, e);
	for (const n of from.packageNameDeny) into.packageNameDeny.add(n);
	for (const h of from.packageHashDeny) into.packageHashDeny.add(h);
	for (const s of from.pluginSignatureDeny) into.pluginSignatureDeny.add(s);
}

export async function loadMergedIntelFromDisk(
	params: LoadIntelOptions = {},
	logger: Logger = nullLogger,
): Promise<IntelMerged> {
	const intelDir = resolvePath(params.intelDir ?? DEFAULT_INTEL_DIR);
	const packsDir = resolvePath(params.packsDir ?? DEFAULT_PACKS_DIR);
	const keysPath = resolvePath(params.trustedKeysPath ?? DEFAULT_TRUSTED_KEYS_PATH);
	const verificationMode: IntelVerificationMode = params.verificationMode ?? "strict";
	const graceHours = typeof params.graceHours === "number" ? params.graceHours : 72;

	const trustedKeys = await loadTrustedKeys(keysPath);
	const keyring = await loadIntelKeyring().catch(() => new Map<string, Uint8Array>());
	const merged = emptyIntelMerged();
	if (params.requireRevocations && !params.revocations) {
		return setAvailability(merged, "unavailable", "signed intel-pack revocations are unavailable");
	}

	const revokedPackIds = new Set(
		(params.revocations?.pack_ids ?? []).filter(
			(x): x is string => typeof x === "string" && x.trim() !== "",
		),
	);
	const revokedKeyIds = new Set(
		(params.revocations?.key_ids ?? []).filter(
			(x): x is string => typeof x === "string" && x.trim() !== "",
		),
	);

	const packIds = await listDirs(packsDir);
	let loadedPackCount = 0;
	let failedPackCount = 0;
	for (const packId of packIds) {
		if (revokedPackIds.has(packId)) {
			logger.warn("Intel pack id is revoked; skipping", { packId });
			continue;
		}
		const packRoot = join(packsDir, packId);
		const version = await pickVersion(packRoot);
		if (!version) continue;

		const packVersionDir = join(packRoot, version);
		const single = await loadSinglePack(
			packId,
			version,
			packVersionDir,
			trustedKeys,
			keyring,
			revokedKeyIds,
			{ verificationMode, graceHours },
			logger,
		);
		if (!single) {
			failedPackCount += 1;
			continue;
		}
		try {
			if (!(await acceptPackVersion(packsDir, packId, version, single.manifestSha256))) {
				logger.warn("Intel pack rollback or version equivocation rejected", { packId, version });
				failedPackCount += 1;
				continue;
			}
		} catch (error) {
			logger.warn("Intel pack version floor unavailable", { packId, error: String(error) });
			failedPackCount += 1;
			continue;
		}
		loadedPackCount += 1;
		mergeInto(merged, single.merged);
	}

	// Keep the existing merged shape for consumers, while carrying measured
	// coverage state out-of-band. An empty or rejected corpus is not clean intel.
	setAvailability(
		merged,
		loadedPackCount > 0 && failedPackCount === 0 ? "available" : "unavailable",
		loadedPackCount > 0 && failedPackCount === 0
			? `loaded ${loadedPackCount} signed intel pack(s)`
			: `no complete signed intel pack was available (${loadedPackCount} loaded, ${failedPackCount} rejected)`,
	);

	// Ensure the on-disk intel dir exists path-wise (not created here; read-only).
	void intelDir;
	return merged;
}
